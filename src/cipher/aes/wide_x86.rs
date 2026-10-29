//! Multi-block AES and GHASH kernels for x86_64, written once over the vector
//! width and instantiated for three tiers:
//!
//! | tier  | register | blocks / vector | needs                                   |
//! |-------|----------|-----------------|-----------------------------------------|
//! | `Xmm` | 128-bit  | 1               | AES-NI, PCLMULQDQ, SSSE3                |
//! | `Ymm` | 256-bit  | 2               | + AVX2, VAES, VPCLMULQDQ (YMM OS state) |
//! | `Zmm` | 512-bit  | 4               | + AVX-512F/BW (opmask/ZMM OS state)     |
//!
//! The kernels (ECB, CTR with a 128- or 32-bit counter, CBC, GHASH and the
//! stitched AES-CTR + GHASH loop of GCM) are generic `#[inline(always)]`
//! functions over the [`Lanes`] trait, whose methods are thin wrappers around
//! one intrinsic each. They carry no `#[target_feature]` themselves: each tier
//! has a set of `#[target_feature]` entry points (the [`tier_entries`] macro)
//! into which the whole generic body inlines, so the intrinsics are emitted
//! with that tier's encoding. The callers pick the entry point from
//! [`tier`], which reports only what [`crate::cpu`] confirmed (including the
//! OS-enabled register state), so the `#[target_feature]` contract holds.
//!
//! Every kernel keeps eight vectors in flight (8, 16 or 32 blocks): enough
//! independent AES chains to cover the round latency on every core that has
//! the instructions. Shorter remainders go through four-, two- and
//! one-vector groups, and what is left below one vector through the 128-bit
//! forms.
//!
//! GHASH works in the POLYVAL-style ("Montgomery") form: a byte-reversed GCM
//! block is a polynomial in the natural bit order, and with the hash-key
//! powers pre-multiplied by `x` the product of the carry-less multiplier
//! needs only a multiply by `x⁻¹²⁸`, done as two folding steps by the
//! constant `x⁶³ + x⁶² + x⁵⁷` (no bit shifts across the 256-bit product).
//! Each eight-vector chunk is aggregated (Karatsuba products summed
//! unreduced) and reduced once.
//!
//! Everything here is constant-time: AES rounds and carry-less multiplies
//! are data-independent instructions, the counter arithmetic is branch-free
//! (including the 128-bit carry), and the only branches are on public
//! lengths.
#![allow(unsafe_code)]
#![allow(unused_unsafe)]

use core::arch::x86_64::*;

/// The widest kernel tier this CPU can run (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Tier {
    Xmm = 1,
    Ymm = 2,
    Zmm = 3,
}

/// Probes the hardware (cached in [`crate::cpu`]).
#[inline]
fn detect() -> Option<Tier> {
    use crate::cpu;
    if crate::ct::force_portable() {
        return None;
    }
    if !(cpu::sse2() && cpu::ssse3() && cpu::aes() && cpu::pclmulqdq()) {
        return None;
    }
    if !(cpu::avx2() && cpu::vaes() && cpu::vpclmulqdq()) {
        return Some(Tier::Xmm);
    }
    if !(cpu::avx512f() && cpu::avx512bw()) {
        return Some(Tier::Ymm);
    }
    Some(Tier::Zmm)
}

/// The kernel tier to use, `None` when even the 128-bit kernels cannot run
/// (no AES-NI/PCLMULQDQ/SSSE3, or the constant-time harness forced the
/// portable path). In unit tests, capped by [`test_cap::with`].
#[inline]
pub(crate) fn tier() -> Option<Tier> {
    let t = detect();
    #[cfg(all(test, feature = "std"))]
    let t = test_cap::apply(t);
    t
}

/// Test hook: runs a closure with the kernel tier capped, so the differential
/// tests reach every tier the host supports (and the portable fallback) in a
/// single run. Thread-local, so parallel tests do not interfere.
#[cfg(all(test, feature = "std"))]
pub(crate) mod test_cap {
    use super::Tier;
    use core::cell::Cell;

    std::thread_local! {
        static CAP: Cell<u8> = const { Cell::new(u8::MAX) };
    }

    pub(super) fn apply(t: Option<Tier>) -> Option<Tier> {
        let cap = CAP.with(Cell::get);
        match t? {
            _ if cap == 0 => None,
            t if t as u8 <= cap => Some(t),
            _ if cap == 1 => Some(Tier::Xmm),
            _ => Some(Tier::Ymm),
        }
    }

    /// Runs `f` with the tier capped at `cap` (`None`: no wide kernels).
    pub(crate) fn with<R>(cap: Option<Tier>, f: impl FnOnce() -> R) -> R {
        struct Restore(u8);
        impl Drop for Restore {
            fn drop(&mut self) {
                CAP.with(|c| c.set(self.0));
            }
        }
        let _restore = Restore(CAP.with(Cell::get));
        CAP.with(|c| c.set(cap.map_or(0, |t| t as u8)));
        f()
    }

    /// Every cap worth testing on this host: the portable path plus each
    /// tier up to the detected one. Logs which tiers run, so a log shows
    /// whether the wide kernels were actually exercised.
    pub(crate) fn caps(what: &str) -> std::vec::Vec<Option<Tier>> {
        let top = super::detect();
        let mut v = std::vec![None];
        for t in [Tier::Xmm, Tier::Ymm, Tier::Zmm] {
            if top.is_some_and(|top| t <= top) {
                std::eprintln!("{what}: RUNNING {t:?} tier vs portable");
                v.push(Some(t));
            } else {
                std::eprintln!("{what}: SKIPPED {t:?} tier (not supported by this CPU)");
            }
        }
        v
    }
}

// --- The vector abstraction ---------------------------------------------------

/// A vector of `L` AES blocks (one per 128-bit lane). Each method is one
/// intrinsic (or a short fixed sequence); the tier's entry point supplies
/// the target features.
pub(crate) trait Lanes: Copy {
    /// Blocks per vector.
    const L: usize;
    unsafe fn zero() -> Self;
    /// Unaligned load of `16 * L` bytes.
    unsafe fn load(p: *const u8) -> Self;
    /// Unaligned store of `16 * L` bytes.
    unsafe fn store(self, p: *mut u8);
    /// `b` in every lane.
    unsafe fn splat(b: __m128i) -> Self;
    /// `b` in lane 0, zero elsewhere.
    unsafe fn lane0(b: __m128i) -> Self;
    /// Lane 0.
    unsafe fn first(self) -> __m128i;
    /// XOR of all lanes.
    unsafe fn fold(self) -> __m128i;
    /// `[prev, cur₀, …, cur_{L-2}]`: the vector one block behind `cur`.
    unsafe fn shift_in(prev: __m128i, cur: Self) -> Self;
    unsafe fn xor(self, o: Self) -> Self;
    unsafe fn and(self, o: Self) -> Self;
    unsafe fn or(self, o: Self) -> Self;
    /// `!self & o`.
    unsafe fn andnot(self, o: Self) -> Self;
    unsafe fn add64(self, o: Self) -> Self;
    unsafe fn add32(self, o: Self) -> Self;
    /// `self + d` as a 128-bit integer per lane, for `d` below 2⁶⁴ (low
    /// half only): the 64-bit add plus the branch-free carry into the high
    /// half, in each tier's cheapest form.
    unsafe fn add128(self, d: Self) -> Self;
    /// Logical right shift of each 64-bit element by 63.
    unsafe fn srl63(self) -> Self;
    /// Byte shift left by 8 within each 128-bit lane.
    unsafe fn bsll8(self) -> Self;
    /// Byte reversal within each 128-bit lane.
    unsafe fn bswap(self) -> Self;
    /// Swaps the two 64-bit halves of each lane.
    unsafe fn swap64(self) -> Self;
    unsafe fn enc(self, k: Self) -> Self;
    unsafe fn enc_last(self, k: Self) -> Self;
    unsafe fn dec(self, k: Self) -> Self;
    unsafe fn dec_last(self, k: Self) -> Self;
    /// Carry-less product of the low halves of each lane.
    unsafe fn clmul00(self, o: Self) -> Self;
    /// Carry-less product of the high halves of each lane.
    unsafe fn clmul11(self, o: Self) -> Self;
}

/// The byte-reversal shuffle control (one 128-bit lane).
#[inline(always)]
unsafe fn rev_mask() -> __m128i {
    unsafe { _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15) }
}

#[derive(Clone, Copy)]
pub(crate) struct Xmm(__m128i);

impl Lanes for Xmm {
    const L: usize = 1;
    #[inline(always)]
    unsafe fn zero() -> Self {
        unsafe { Xmm(_mm_setzero_si128()) }
    }
    #[inline(always)]
    unsafe fn load(p: *const u8) -> Self {
        unsafe { Xmm(_mm_loadu_si128(p as *const __m128i)) }
    }
    #[inline(always)]
    unsafe fn store(self, p: *mut u8) {
        unsafe { _mm_storeu_si128(p as *mut __m128i, self.0) }
    }
    #[inline(always)]
    unsafe fn splat(b: __m128i) -> Self {
        Xmm(b)
    }
    #[inline(always)]
    unsafe fn lane0(b: __m128i) -> Self {
        Xmm(b)
    }
    #[inline(always)]
    unsafe fn first(self) -> __m128i {
        self.0
    }
    #[inline(always)]
    unsafe fn fold(self) -> __m128i {
        self.0
    }
    #[inline(always)]
    unsafe fn shift_in(prev: __m128i, _cur: Self) -> Self {
        Xmm(prev)
    }
    #[inline(always)]
    unsafe fn xor(self, o: Self) -> Self {
        unsafe { Xmm(_mm_xor_si128(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn and(self, o: Self) -> Self {
        unsafe { Xmm(_mm_and_si128(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn or(self, o: Self) -> Self {
        unsafe { Xmm(_mm_or_si128(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn andnot(self, o: Self) -> Self {
        unsafe { Xmm(_mm_andnot_si128(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn add64(self, o: Self) -> Self {
        unsafe { Xmm(_mm_add_epi64(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn add32(self, o: Self) -> Self {
        unsafe { Xmm(_mm_add_epi32(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn add128(self, d: Self) -> Self {
        // carry = msb((c ∧ d) ∨ ((c ∨ d) ∧ ¬s)); SSE2 has no 64-bit compare.
        unsafe {
            let s = self.add64(d);
            let carry = self.and(d).or(s.andnot(self.or(d))).srl63().bsll8();
            s.add64(carry)
        }
    }
    #[inline(always)]
    unsafe fn srl63(self) -> Self {
        unsafe { Xmm(_mm_srli_epi64::<63>(self.0)) }
    }
    #[inline(always)]
    unsafe fn bsll8(self) -> Self {
        unsafe { Xmm(_mm_slli_si128::<8>(self.0)) }
    }
    #[inline(always)]
    unsafe fn bswap(self) -> Self {
        unsafe { Xmm(_mm_shuffle_epi8(self.0, rev_mask())) }
    }
    #[inline(always)]
    unsafe fn swap64(self) -> Self {
        unsafe { Xmm(_mm_shuffle_epi32::<0x4e>(self.0)) }
    }
    #[inline(always)]
    unsafe fn enc(self, k: Self) -> Self {
        unsafe { Xmm(_mm_aesenc_si128(self.0, k.0)) }
    }
    #[inline(always)]
    unsafe fn enc_last(self, k: Self) -> Self {
        unsafe { Xmm(_mm_aesenclast_si128(self.0, k.0)) }
    }
    #[inline(always)]
    unsafe fn dec(self, k: Self) -> Self {
        unsafe { Xmm(_mm_aesdec_si128(self.0, k.0)) }
    }
    #[inline(always)]
    unsafe fn dec_last(self, k: Self) -> Self {
        unsafe { Xmm(_mm_aesdeclast_si128(self.0, k.0)) }
    }
    #[inline(always)]
    unsafe fn clmul00(self, o: Self) -> Self {
        unsafe { Xmm(_mm_clmulepi64_si128::<0x00>(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn clmul11(self, o: Self) -> Self {
        unsafe { Xmm(_mm_clmulepi64_si128::<0x11>(self.0, o.0)) }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Ymm(__m256i);

impl Lanes for Ymm {
    const L: usize = 2;
    #[inline(always)]
    unsafe fn zero() -> Self {
        unsafe { Ymm(_mm256_setzero_si256()) }
    }
    #[inline(always)]
    unsafe fn load(p: *const u8) -> Self {
        unsafe { Ymm(_mm256_loadu_si256(p as *const __m256i)) }
    }
    #[inline(always)]
    unsafe fn store(self, p: *mut u8) {
        unsafe { _mm256_storeu_si256(p as *mut __m256i, self.0) }
    }
    #[inline(always)]
    unsafe fn splat(b: __m128i) -> Self {
        unsafe { Ymm(_mm256_broadcastsi128_si256(b)) }
    }
    #[inline(always)]
    unsafe fn lane0(b: __m128i) -> Self {
        unsafe { Ymm(_mm256_zextsi128_si256(b)) }
    }
    #[inline(always)]
    unsafe fn first(self) -> __m128i {
        unsafe { _mm256_castsi256_si128(self.0) }
    }
    #[inline(always)]
    unsafe fn fold(self) -> __m128i {
        unsafe {
            _mm_xor_si128(
                _mm256_castsi256_si128(self.0),
                _mm256_extracti128_si256::<1>(self.0),
            )
        }
    }
    #[inline(always)]
    unsafe fn shift_in(prev: __m128i, cur: Self) -> Self {
        // Low lane from `prev`, high lane from `cur`'s low lane.
        unsafe {
            Ymm(_mm256_permute2x128_si256::<0x20>(
                _mm256_castsi128_si256(prev),
                cur.0,
            ))
        }
    }
    #[inline(always)]
    unsafe fn xor(self, o: Self) -> Self {
        unsafe { Ymm(_mm256_xor_si256(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn and(self, o: Self) -> Self {
        unsafe { Ymm(_mm256_and_si256(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn or(self, o: Self) -> Self {
        unsafe { Ymm(_mm256_or_si256(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn andnot(self, o: Self) -> Self {
        unsafe { Ymm(_mm256_andnot_si256(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn add64(self, o: Self) -> Self {
        unsafe { Ymm(_mm256_add_epi64(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn add32(self, o: Self) -> Self {
        unsafe { Ymm(_mm256_add_epi32(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn add128(self, d: Self) -> Self {
        // The low half carried iff s < d (unsigned): a signed compare with
        // both sides offset by 2⁶³ gives an all-ones mask, which moved to
        // the high half and subtracted adds the carry.
        unsafe {
            let s = _mm256_add_epi64(self.0, d.0);
            let bias = _mm256_set1_epi64x(i64::MIN);
            let m = _mm256_cmpgt_epi64(_mm256_xor_si256(d.0, bias), _mm256_xor_si256(s, bias));
            Ymm(_mm256_sub_epi64(s, _mm256_bslli_epi128::<8>(m)))
        }
    }
    #[inline(always)]
    unsafe fn srl63(self) -> Self {
        unsafe { Ymm(_mm256_srli_epi64::<63>(self.0)) }
    }
    #[inline(always)]
    unsafe fn bsll8(self) -> Self {
        unsafe { Ymm(_mm256_bslli_epi128::<8>(self.0)) }
    }
    #[inline(always)]
    unsafe fn bswap(self) -> Self {
        unsafe {
            Ymm(_mm256_shuffle_epi8(
                self.0,
                _mm256_broadcastsi128_si256(rev_mask()),
            ))
        }
    }
    #[inline(always)]
    unsafe fn swap64(self) -> Self {
        unsafe { Ymm(_mm256_shuffle_epi32::<0x4e>(self.0)) }
    }
    #[inline(always)]
    unsafe fn enc(self, k: Self) -> Self {
        unsafe { Ymm(_mm256_aesenc_epi128(self.0, k.0)) }
    }
    #[inline(always)]
    unsafe fn enc_last(self, k: Self) -> Self {
        unsafe { Ymm(_mm256_aesenclast_epi128(self.0, k.0)) }
    }
    #[inline(always)]
    unsafe fn dec(self, k: Self) -> Self {
        unsafe { Ymm(_mm256_aesdec_epi128(self.0, k.0)) }
    }
    #[inline(always)]
    unsafe fn dec_last(self, k: Self) -> Self {
        unsafe { Ymm(_mm256_aesdeclast_epi128(self.0, k.0)) }
    }
    #[inline(always)]
    unsafe fn clmul00(self, o: Self) -> Self {
        unsafe { Ymm(_mm256_clmulepi64_epi128::<0x00>(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn clmul11(self, o: Self) -> Self {
        unsafe { Ymm(_mm256_clmulepi64_epi128::<0x11>(self.0, o.0)) }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Zmm(__m512i);

impl Lanes for Zmm {
    const L: usize = 4;
    #[inline(always)]
    unsafe fn zero() -> Self {
        unsafe { Zmm(_mm512_setzero_si512()) }
    }
    #[inline(always)]
    unsafe fn load(p: *const u8) -> Self {
        unsafe { Zmm(_mm512_loadu_si512(p as *const _)) }
    }
    #[inline(always)]
    unsafe fn store(self, p: *mut u8) {
        unsafe { _mm512_storeu_si512(p as *mut _, self.0) }
    }
    #[inline(always)]
    unsafe fn splat(b: __m128i) -> Self {
        unsafe { Zmm(_mm512_broadcast_i32x4(b)) }
    }
    #[inline(always)]
    unsafe fn lane0(b: __m128i) -> Self {
        unsafe { Zmm(_mm512_zextsi128_si512(b)) }
    }
    #[inline(always)]
    unsafe fn first(self) -> __m128i {
        unsafe { _mm512_castsi512_si128(self.0) }
    }
    #[inline(always)]
    unsafe fn fold(self) -> __m128i {
        unsafe {
            let y = _mm256_xor_si256(
                _mm512_castsi512_si256(self.0),
                _mm512_extracti64x4_epi64::<1>(self.0),
            );
            _mm_xor_si128(_mm256_castsi256_si128(y), _mm256_extracti128_si256::<1>(y))
        }
    }
    #[inline(always)]
    unsafe fn shift_in(prev: __m128i, cur: Self) -> Self {
        // (cur : splat(prev)) >> 6 qwords = [prev, cur₀, cur₁, cur₂].
        unsafe {
            Zmm(_mm512_alignr_epi64::<6>(
                cur.0,
                _mm512_broadcast_i32x4(prev),
            ))
        }
    }
    #[inline(always)]
    unsafe fn xor(self, o: Self) -> Self {
        unsafe { Zmm(_mm512_xor_si512(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn and(self, o: Self) -> Self {
        unsafe { Zmm(_mm512_and_si512(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn or(self, o: Self) -> Self {
        unsafe { Zmm(_mm512_or_si512(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn andnot(self, o: Self) -> Self {
        unsafe { Zmm(_mm512_andnot_si512(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn add64(self, o: Self) -> Self {
        unsafe { Zmm(_mm512_add_epi64(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn add32(self, o: Self) -> Self {
        unsafe { Zmm(_mm512_add_epi32(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn add128(self, d: Self) -> Self {
        // As `Xmm` (a compare into a mask register and a masked add measured
        // slower on Zen 5; the formula becomes one VPTERNLOGQ here).
        unsafe {
            let s = self.add64(d);
            let carry = self.and(d).or(s.andnot(self.or(d))).srl63().bsll8();
            s.add64(carry)
        }
    }
    #[inline(always)]
    unsafe fn srl63(self) -> Self {
        unsafe { Zmm(_mm512_srli_epi64::<63>(self.0)) }
    }
    #[inline(always)]
    unsafe fn bsll8(self) -> Self {
        unsafe { Zmm(_mm512_bslli_epi128::<8>(self.0)) }
    }
    #[inline(always)]
    unsafe fn bswap(self) -> Self {
        unsafe {
            Zmm(_mm512_shuffle_epi8(
                self.0,
                _mm512_broadcast_i32x4(rev_mask()),
            ))
        }
    }
    #[inline(always)]
    unsafe fn swap64(self) -> Self {
        unsafe { Zmm(_mm512_shuffle_epi32::<0x4e>(self.0)) }
    }
    #[inline(always)]
    unsafe fn enc(self, k: Self) -> Self {
        unsafe { Zmm(_mm512_aesenc_epi128(self.0, k.0)) }
    }
    #[inline(always)]
    unsafe fn enc_last(self, k: Self) -> Self {
        unsafe { Zmm(_mm512_aesenclast_epi128(self.0, k.0)) }
    }
    #[inline(always)]
    unsafe fn dec(self, k: Self) -> Self {
        unsafe { Zmm(_mm512_aesdec_epi128(self.0, k.0)) }
    }
    #[inline(always)]
    unsafe fn dec_last(self, k: Self) -> Self {
        unsafe { Zmm(_mm512_aesdeclast_epi128(self.0, k.0)) }
    }
    #[inline(always)]
    unsafe fn clmul00(self, o: Self) -> Self {
        unsafe { Zmm(_mm512_clmulepi64_epi128::<0x00>(self.0, o.0)) }
    }
    #[inline(always)]
    unsafe fn clmul11(self, o: Self) -> Self {
        unsafe { Zmm(_mm512_clmulepi64_epi128::<0x11>(self.0, o.0)) }
    }
}

// --- Shared helpers -----------------------------------------------------------

/// Vectors in flight per group.
const G: usize = 8;

/// Number of entries of the GHASH key table: the powers for one full
/// eight-vector chunk of the widest tier.
pub(crate) const HTAB_LEN: usize = G * 4;

/// The GHASH key table: `htab[i] = H^(HTAB_LEN − i) · x` in the bit-reflected
/// (POLYVAL) form, so a chunk of `m` blocks multiplies block `t` by
/// `htab[HTAB_LEN − m + t]` and a vector of consecutive blocks loads its
/// powers with one load.
pub(crate) type HTable = [u128; HTAB_LEN];

/// Best-effort wipe of vector temporaries (volatile stores plus a compiler
/// fence, the contract of [`crate::zeroize::Zeroize`], which cannot take a
/// vendor vector type): round keys, keystream and hash-key powers in the
/// register spill slots.
#[inline(always)]
unsafe fn wipe<V: Lanes>(v: &mut [V]) {
    for x in v.iter_mut() {
        // SAFETY: `x` is a live exclusive reference.
        unsafe { core::ptr::write_volatile(x, V::zero()) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Loads the forward schedule (`NR + 1` round keys at `rk`), broadcast.
#[inline(always)]
unsafe fn enc_keys<V: Lanes, const NR: usize>(rk: *const u8) -> [V; 15] {
    unsafe {
        let mut k = [V::zero(); 15];
        for (i, ki) in k.iter_mut().enumerate().take(NR + 1) {
            *ki = V::splat(_mm_loadu_si128(rk.add(16 * i) as *const __m128i));
        }
        k
    }
}

/// The equivalent-inverse-cipher schedule: `rk[0]`, `imc(rk[1..NR])`,
/// `rk[NR]`, broadcast.
#[inline(always)]
unsafe fn dec_keys<V: Lanes, const NR: usize>(rk: *const u8) -> [V; 15] {
    unsafe {
        let mut k = [V::zero(); 15];
        for (i, ki) in k.iter_mut().enumerate().take(NR + 1) {
            let mut x = _mm_loadu_si128(rk.add(16 * i) as *const __m128i);
            if i != 0 && i != NR {
                x = _mm_aesimc_si128(x);
            }
            *ki = V::splat(x);
        }
        k
    }
}

/// Keeps the instruction schedule round-major. Under register pressure
/// (eight state vectors, the round keys, counter constants, GHASH operands)
/// LLVM's machine scheduler otherwise reorders the independent AES chains
/// vector by vector, leaving only two or so in flight, and hoists the
/// stitched GHASH work out of the rounds; measured on Zen 5 that costs
/// 10-25% in CTR and GCM. A compiler fence emits no instruction but splits
/// the scheduling region, so each round's AES instructions (and the GHASH
/// step placed with it) stay together.
#[inline(always)]
fn round_fence() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// The full forward cipher on `N` vectors.
#[inline(always)]
unsafe fn encrypt_n<V: Lanes, const NR: usize, const N: usize>(b: &mut [V; G], k: &[V; 15]) {
    unsafe {
        for x in b[..N].iter_mut() {
            *x = x.xor(k[0]);
        }
        for kr in &k[1..NR] {
            for x in b[..N].iter_mut() {
                *x = x.enc(*kr);
            }
            round_fence();
        }
        for x in b[..N].iter_mut() {
            *x = x.enc_last(k[NR]);
        }
    }
}

/// The full inverse cipher on `N` vectors (`k` from [`dec_keys`]).
#[inline(always)]
unsafe fn decrypt_n<V: Lanes, const NR: usize, const N: usize>(b: &mut [V; G], k: &[V; 15]) {
    unsafe {
        for x in b[..N].iter_mut() {
            *x = x.xor(k[NR]);
        }
        for r in (1..NR).rev() {
            for x in b[..N].iter_mut() {
                *x = x.dec(k[r]);
            }
            round_fence();
        }
        for x in b[..N].iter_mut() {
            *x = x.dec_last(k[0]);
        }
    }
}

/// `n` (≤ 255) in the low 64 bits of every lane: a counter increment.
#[inline(always)]
unsafe fn inc<V: Lanes>(n: usize) -> V {
    unsafe { V::splat(_mm_set_epi64x(0, n as i64)) }
}

/// `l` in lane `l`: the per-lane offsets of consecutive counters.
#[inline(always)]
unsafe fn lane_index<V: Lanes>() -> V {
    const IDX: [u64; 8] = [0, 0, 1, 0, 2, 0, 3, 0];
    unsafe { V::load(IDX.as_ptr() as *const u8) }
}

/// Counter flavours, as the const parameter of the CTR kernels. The counter
/// register always holds the counter block as a little-endian 128-bit
/// integer per lane, byte-reversed from memory for the big-endian forms.
pub(crate) const CTR128_BE: u8 = 0; // CTR mode: whole block, big-endian, mod 2¹²⁸
pub(crate) const CTR32_BE: u8 = 1; // GCM inc32: last 4 bytes, big-endian
pub(crate) const CTR32_LE: u8 = 2; // AES-GCM-SIV: first 4 bytes, little-endian

/// `c + d` per lane in the counter flavour `MODE` (`d` < 2⁶⁴ in the low
/// half). The 128-bit form propagates the carry out of the low half
/// branch-free ([`Lanes::add128`]).
#[inline(always)]
unsafe fn ctr_add<V: Lanes, const MODE: u8>(c: V, d: V) -> V {
    unsafe {
        if MODE == CTR128_BE {
            c.add128(d)
        } else {
            c.add32(d)
        }
    }
}

/// The counter register form of a counter block (see [`CTR128_BE`]).
#[inline(always)]
unsafe fn ctr_to_reg<const MODE: u8>(b: __m128i) -> __m128i {
    unsafe {
        if MODE == CTR32_LE {
            b
        } else {
            _mm_shuffle_epi8(b, rev_mask())
        }
    }
}

// --- ECB ----------------------------------------------------------------------

#[inline(always)]
unsafe fn ecb_group<V: Lanes, const NR: usize, const DEC: bool, const N: usize>(
    k: &[V; 15],
    p: *mut u8,
) {
    unsafe {
        // A local array: kept in registers, not pinned to a stack slot.
        let mut b = [V::zero(); G];
        let b = &mut b;
        for (j, x) in b[..N].iter_mut().enumerate() {
            *x = V::load(p.add(16 * V::L * j));
        }
        if DEC {
            decrypt_n::<V, NR, N>(b, k);
        } else {
            encrypt_n::<V, NR, N>(b, k);
        }
        for (j, x) in b[..N].iter().enumerate() {
            x.store(p.add(16 * V::L * j));
        }
    }
}

/// Applies the forward (or with `DEC` the inverse) cipher to the `n` blocks
/// at `p` in place, `V`-vector groups first, then single blocks.
#[inline(always)]
unsafe fn ecb_run<V: Lanes, const NR: usize, const DEC: bool>(
    rk: *const u8,
    mut p: *mut u8,
    mut n: usize,
) -> (*mut u8, usize) {
    unsafe {
        let mut k = if DEC {
            dec_keys::<V, NR>(rk)
        } else {
            enc_keys::<V, NR>(rk)
        };
        let l = V::L;
        while n >= G * l {
            ecb_group::<V, NR, DEC, G>(&k, p);
            p = p.add(16 * G * l);
            n -= G * l;
        }
        if n >= 4 * l {
            ecb_group::<V, NR, DEC, 4>(&k, p);
            p = p.add(64 * l);
            n -= 4 * l;
        }
        if n >= 2 * l {
            ecb_group::<V, NR, DEC, 2>(&k, p);
            p = p.add(32 * l);
            n -= 2 * l;
        }
        if n >= l {
            ecb_group::<V, NR, DEC, 1>(&k, p);
            p = p.add(16 * l);
            n -= l;
        }
        wipe(&mut k);
        (p, n)
    }
}

#[inline(always)]
unsafe fn ecb_kernel<V: Lanes, const NR: usize, const DEC: bool>(rk: &[u8], buf: &mut [u8]) {
    debug_assert!(rk.len() >= 16 * (NR + 1) && buf.len().is_multiple_of(16));
    unsafe {
        let (p, n) = ecb_run::<V, NR, DEC>(rk.as_ptr(), buf.as_mut_ptr(), buf.len() / 16);
        if n > 0 {
            ecb_run::<Xmm, NR, DEC>(rk.as_ptr(), p, n);
        }
    }
}

// --- CTR ----------------------------------------------------------------------

/// One group of `N` counter vectors: keystream from `c` (advanced past the
/// group), XORed into the `N · L` blocks at `p`.
#[inline(always)]
unsafe fn ctr_group<V: Lanes, const NR: usize, const MODE: u8, const N: usize>(
    k: &[V; 15],
    c: &mut V,
    p: *mut u8,
) {
    unsafe {
        // A local array: kept in registers, not pinned to a stack slot.
        let mut b = [V::zero(); G];
        let b = &mut b;
        for (j, x) in b[..N].iter_mut().enumerate() {
            *x = if j == 0 {
                *c
            } else {
                ctr_add::<V, MODE>(*c, inc(j * V::L))
            };
        }
        *c = ctr_add::<V, MODE>(*c, inc(N * V::L));
        if MODE != CTR32_LE {
            for x in b[..N].iter_mut() {
                *x = x.bswap();
            }
        }
        encrypt_n::<V, NR, N>(b, k);
        for (j, x) in b[..N].iter().enumerate() {
            let q = p.add(16 * V::L * j);
            V::load(q).xor(*x).store(q);
        }
    }
}

/// CTR over the `n` whole blocks at `p` with `V` vectors, then the 128-bit
/// form for what is left below one vector. `c` is the first counter in the
/// register form ([`ctr_to_reg`]); returns the counter after the last block.
#[inline(always)]
unsafe fn ctr_run<V: Lanes, const NR: usize, const MODE: u8>(
    rk: *const u8,
    c: __m128i,
    mut p: *mut u8,
    mut n: usize,
) -> __m128i {
    unsafe {
        let l = V::L;
        let mut next = c;
        if n >= l {
            let mut k = enc_keys::<V, NR>(rk);
            let mut cv = ctr_add::<V, MODE>(V::splat(c), lane_index());
            while n >= G * l {
                ctr_group::<V, NR, MODE, G>(&k, &mut cv, p);
                p = p.add(16 * G * l);
                n -= G * l;
            }
            if n >= 4 * l {
                ctr_group::<V, NR, MODE, 4>(&k, &mut cv, p);
                p = p.add(64 * l);
                n -= 4 * l;
            }
            if n >= 2 * l {
                ctr_group::<V, NR, MODE, 2>(&k, &mut cv, p);
                p = p.add(32 * l);
                n -= 2 * l;
            }
            if n >= l {
                ctr_group::<V, NR, MODE, 1>(&k, &mut cv, p);
                p = p.add(16 * l);
                n -= l;
            }
            next = cv.first();
            wipe(&mut k);
        }
        if n > 0 {
            // At most three blocks (`L ≤ 4`), one at a time.
            let mut k = enc_keys::<Xmm, NR>(rk);
            let mut cv = Xmm(next);
            for _ in 0..n {
                ctr_group::<Xmm, NR, MODE, 1>(&k, &mut cv, p);
                p = p.add(16);
            }
            next = cv.0;
            wipe(&mut k);
        }
        next
    }
}

/// CTR keystream XOR over the whole blocks of `buf` from the counter block
/// `ctr`, which is advanced past them.
#[inline(always)]
unsafe fn ctr_kernel<V: Lanes, const NR: usize, const MODE: u8>(
    rk: &[u8],
    ctr: &mut [u8; 16],
    buf: &mut [u8],
) {
    debug_assert!(rk.len() >= 16 * (NR + 1) && buf.len().is_multiple_of(16));
    unsafe {
        let c = ctr_to_reg::<MODE>(_mm_loadu_si128(ctr.as_ptr() as *const __m128i));
        let next = ctr_run::<V, NR, MODE>(rk.as_ptr(), c, buf.as_mut_ptr(), buf.len() / 16);
        _mm_storeu_si128(ctr.as_mut_ptr() as *mut __m128i, ctr_to_reg::<MODE>(next));
    }
}

// --- CBC ----------------------------------------------------------------------

/// CBC encryption: inherently serial (each block's input is the previous
/// block's output), so this is one dependency chain. What it saves over a
/// block-at-a-time loop is everything around the chain: the schedule stays
/// in registers, nothing is dispatched per block, and the last round of
/// block `i` is fused with the first XOR of block `i + 1`
/// (`AESENCLAST(s, k_NR ⊕ k_0 ⊕ P_{i+1})`), so the chain is exactly `NR`
/// AES instructions per block.
#[inline(always)]
unsafe fn cbc_encrypt_kernel<const NR: usize>(rk: &[u8], iv: &mut [u8; 16], buf: &mut [u8]) {
    debug_assert!(rk.len() >= 16 * (NR + 1) && buf.len().is_multiple_of(16));
    unsafe {
        let n = buf.len() / 16;
        if n == 0 {
            return;
        }
        let mut k = enc_keys::<Xmm, NR>(rk.as_ptr());
        let kx = k[NR].xor(k[0]);
        let p = buf.as_mut_ptr();
        let mut s = Xmm::load(iv.as_ptr()).xor(Xmm::load(p)).xor(k[0]);
        for i in 0..n {
            for kr in &k[1..NR] {
                s = s.enc(*kr);
            }
            let c = s.enc_last(k[NR]);
            if i + 1 < n {
                let t = kx.xor(Xmm::load(p.add(16 * (i + 1))));
                s = s.enc_last(t);
            }
            c.store(p.add(16 * i));
        }
        _mm_storeu_si128(
            iv.as_mut_ptr() as *mut __m128i,
            _mm_loadu_si128(p.add(16 * (n - 1)) as *const __m128i),
        );
        wipe(&mut k);
        let mut s = [s];
        wipe(&mut s);
    }
}

/// One CBC-decrypt group of `N` vectors at `p`; `last` is the ciphertext
/// block before the group (the IV for the first) and becomes the group's
/// last ciphertext block.
#[inline(always)]
unsafe fn cbc_dec_group<V: Lanes, const NR: usize, const N: usize>(
    k: &[V; 15],
    last: &mut __m128i,
    p: *mut u8,
) {
    unsafe {
        // A local array: kept in registers, not pinned to a stack slot.
        let mut b = [V::zero(); G];
        let b = &mut b;
        let l = V::L;
        for (j, x) in b[..N].iter_mut().enumerate() {
            *x = V::load(p.add(16 * l * j));
        }
        let prev0 = V::shift_in(*last, b[0]);
        let next_last = _mm_loadu_si128(p.add(16 * (N * l - 1)) as *const __m128i);
        decrypt_n::<V, NR, N>(b, k);
        // All chaining XORs read the (still intact) ciphertext before any
        // plaintext is stored over it.
        b[0] = b[0].xor(prev0);
        for (j, x) in b[..N].iter_mut().enumerate().skip(1) {
            *x = x.xor(V::load(p.add(16 * l * j - 16)));
        }
        for (j, x) in b[..N].iter().enumerate() {
            x.store(p.add(16 * l * j));
        }
        *last = next_last;
    }
}

#[inline(always)]
unsafe fn cbc_dec_run<V: Lanes, const NR: usize>(
    rk: *const u8,
    last: &mut __m128i,
    mut p: *mut u8,
    mut n: usize,
) -> (*mut u8, usize) {
    unsafe {
        let l = V::L;
        let mut k = dec_keys::<V, NR>(rk);
        while n >= G * l {
            cbc_dec_group::<V, NR, G>(&k, last, p);
            p = p.add(16 * G * l);
            n -= G * l;
        }
        if n >= 4 * l {
            cbc_dec_group::<V, NR, 4>(&k, last, p);
            p = p.add(64 * l);
            n -= 4 * l;
        }
        if n >= 2 * l {
            cbc_dec_group::<V, NR, 2>(&k, last, p);
            p = p.add(32 * l);
            n -= 2 * l;
        }
        if n >= l {
            cbc_dec_group::<V, NR, 1>(&k, last, p);
            p = p.add(16 * l);
            n -= l;
        }
        wipe(&mut k);
        (p, n)
    }
}

/// CBC decryption of the whole blocks of `buf` in place; `iv` is the
/// chaining block and becomes the last ciphertext block.
#[inline(always)]
unsafe fn cbc_decrypt_kernel<V: Lanes, const NR: usize>(
    rk: &[u8],
    iv: &mut [u8; 16],
    buf: &mut [u8],
) {
    debug_assert!(rk.len() >= 16 * (NR + 1) && buf.len().is_multiple_of(16));
    unsafe {
        let mut last = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
        let (p, n) = cbc_dec_run::<V, NR>(rk.as_ptr(), &mut last, buf.as_mut_ptr(), buf.len() / 16);
        if n > 0 {
            cbc_dec_run::<Xmm, NR>(rk.as_ptr(), &mut last, p, n);
        }
        _mm_storeu_si128(iv.as_mut_ptr() as *mut __m128i, last);
    }
}

// --- GHASH --------------------------------------------------------------------

/// Unreduced Karatsuba accumulator: the 256-bit sum `lo + mid·x⁶⁴ + hi·x¹²⁸`
/// per lane, with `mid` still holding `(a₀ ⊕ a₁)(b₀ ⊕ b₁)` sums (fixed up in
/// [`Acc::reduce`]).
#[derive(Clone, Copy)]
struct Acc<V> {
    lo: V,
    mid: V,
    hi: V,
}

impl<V: Lanes> Acc<V> {
    #[inline(always)]
    unsafe fn new() -> Self {
        unsafe {
            Acc {
                lo: V::zero(),
                mid: V::zero(),
                hi: V::zero(),
            }
        }
    }

    /// `+= d · h`, with `hk = h ⊕ swap64(h)` (the Karatsuba middle operand).
    #[inline(always)]
    unsafe fn mul(&mut self, d: V, h: V, hk: V) {
        unsafe {
            self.lo = self.lo.xor(d.clmul00(h));
            self.hi = self.hi.xor(d.clmul11(h));
            self.mid = self.mid.xor(d.xor(d.swap64()).clmul00(hk));
        }
    }

    /// Reduces the sum: `Σ · x⁻¹²⁸ mod (x¹²⁸ + x¹²⁷ + x¹²⁶ + x¹²¹ + 1)`, the
    /// POLYVAL product, lane-wise, then folds the lanes (the reduction is
    /// linear, so folding after it is the same as before). Two Montgomery
    /// steps, each cancelling the low 64 bits `v₀` by adding `v₀·P` and
    /// dividing by `x⁶⁴`: `v₀·P/x⁶⁴ = v₀·(x⁶³ + x⁶² + x⁵⁷) + v₀·x⁶⁴`.
    #[inline(always)]
    unsafe fn reduce(self) -> __m128i {
        unsafe {
            let poly = V::splat(_mm_set_epi64x(0, 0xc200_0000_0000_0000u64 as i64));
            let mid = self.mid.xor(self.lo).xor(self.hi);
            let w = mid.xor(self.lo.swap64()).xor(self.lo.clmul00(poly));
            self.hi.xor(w.swap64()).xor(w.clmul00(poly)).fold()
        }
    }
}

/// The `n` power vectors (and their Karatsuba halves) for a chunk of `m`
/// blocks: vector `j` holds `htab[HTAB_LEN − m + j·L ..]`.
#[inline(always)]
unsafe fn load_powers<V: Lanes>(
    htab: &HTable,
    m: usize,
    n: usize,
    hp: &mut [V; G],
    hk: &mut [V; G],
) {
    debug_assert!(m <= HTAB_LEN && n * V::L <= m && n <= G);
    unsafe {
        let base = htab.as_ptr().add(HTAB_LEN - m) as *const u8;
        for j in 0..n {
            let h = V::load(base.add(16 * V::L * j));
            hp[j] = h;
            hk[j] = h.xor(h.swap64());
        }
    }
}

/// A data vector in the reflected form: byte-reversed for big-endian GHASH
/// blocks (`REV`), as is for POLYVAL's little-endian blocks.
#[inline(always)]
unsafe fn load_data<V: Lanes, const REV: bool>(p: *const u8) -> V {
    unsafe {
        let v = V::load(p);
        if REV { v.bswap() } else { v }
    }
}

/// Folds the `n · L` blocks at `p` into `a` with one reduction, using the
/// powers in `hp`/`hk` (from [`load_powers`] for exactly `n · L` blocks).
#[inline(always)]
unsafe fn ghash_chunk<V: Lanes, const REV: bool>(
    a: __m128i,
    hp: &[V; G],
    hk: &[V; G],
    p: *const u8,
    n: usize,
) -> __m128i {
    unsafe {
        let mut acc = Acc::<V>::new();
        for j in 0..n {
            let mut d = load_data::<V, REV>(p.add(16 * V::L * j));
            if j == 0 {
                d = d.xor(V::lane0(a));
            }
            acc.mul(d, hp[j], hk[j]);
        }
        acc.reduce()
    }
}

/// GHASH/POLYVAL over the `n` blocks at `p`: full chunks of `G · L` blocks,
/// then one chunk of the whole vectors left, then (narrower `V` only) the
/// last `< L` blocks in 128-bit form.
#[inline(always)]
unsafe fn ghash_run<V: Lanes, const REV: bool>(
    htab: &HTable,
    mut a: __m128i,
    mut p: *const u8,
    mut n: usize,
) -> __m128i {
    unsafe {
        let l = V::L;
        let mut hp = [V::zero(); G];
        let mut hk = [V::zero(); G];
        if n >= G * l {
            load_powers(htab, G * l, G, &mut hp, &mut hk);
            while n >= G * l {
                a = ghash_chunk::<V, REV>(a, &hp, &hk, p, G);
                p = p.add(16 * G * l);
                n -= G * l;
            }
        }
        let v = n / l;
        if v > 0 {
            load_powers(htab, v * l, v, &mut hp, &mut hk);
            a = ghash_chunk::<V, REV>(a, &hp, &hk, p, v);
            p = p.add(16 * v * l);
            n -= v * l;
        }
        wipe(&mut hp);
        wipe(&mut hk);
        if n > 0 {
            let mut hp = [Xmm::zero(); G];
            let mut hk = [Xmm::zero(); G];
            load_powers(htab, n, n, &mut hp, &mut hk);
            a = ghash_chunk::<Xmm, REV>(a, &hp, &hk, p, n);
            wipe(&mut hp);
            wipe(&mut hk);
        }
        a
    }
}

#[inline(always)]
unsafe fn ghash_kernel<V: Lanes, const REV: bool>(htab: &HTable, x: u128, data: &[u8]) -> u128 {
    debug_assert!(data.len().is_multiple_of(16));
    unsafe {
        let a = _mm_loadu_si128(x.to_le_bytes().as_ptr() as *const __m128i);
        let a = ghash_run::<V, REV>(htab, a, data.as_ptr(), data.len() / 16);
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, a);
        u128::from_le_bytes(out)
    }
}

/// The POLYVAL product `a · b · x⁻¹²⁸` of two reflected elements.
#[inline(always)]
unsafe fn dot(a: u128, b: u128) -> u128 {
    unsafe {
        let a = Xmm::load(a.to_le_bytes().as_ptr());
        let b = Xmm::load(b.to_le_bytes().as_ptr());
        let mut acc = Acc::<Xmm>::new();
        acc.mul(a, b, b.xor(b.swap64()));
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, acc.reduce());
        u128::from_le_bytes(out)
    }
}

/// Builds the key table from the POLYVAL-form key `k1` (powers in the
/// POLYVAL sense: `k_{i+1} = dot(k_i, k1)`). (The kernels also hash
/// little-endian POLYVAL blocks with `REV = false` over such a table;
/// AES-GCM-SIV does not use them, as its key changes with every nonce and
/// a full table per message would cost more than it saves on short ones.)
#[inline(always)]
unsafe fn table_from(k1: u128) -> HTable {
    unsafe {
        let mut t = [0u128; HTAB_LEN];
        let mut k = k1;
        for i in (0..HTAB_LEN).rev() {
            t[i] = k;
            k = dot(k, k1);
        }
        crate::zeroize::Zeroize::zeroize(&mut k);
        t
    }
}

/// The GHASH key table for hash subkey `h` (a GCM block read big-endian).
///
/// Byte-reversing a GCM block gives the same 128-bit integer read
/// little-endian, which is the reflected polynomial; with `ψ(a) = rev(a)·x`
/// the GCM product satisfies `ψ(a ⊗ b) = dot(ψ(a), ψ(b))`, so the table holds
/// the POLYVAL powers of `ψ(H) = h·x` and `dot(rev(X), ψ(Hᵏ)) = rev(X ⊗ Hᵏ)`.
///
/// # Safety
/// Requires PCLMULQDQ and SSE2 (any [`Tier`]).
#[target_feature(enable = "pclmulqdq,sse2,ssse3")]
pub(crate) unsafe fn ghash_table(h: u128) -> HTable {
    // mulX in POLYVAL's field: shift, and reduce by x¹²⁸ = x¹²⁷+x¹²⁶+x¹²¹+1.
    let hx = (h << 1) ^ (0u128.wrapping_sub(h >> 127) & 0xc200_0000_0000_0000_0000_0000_0000_0001);
    unsafe { table_from(hx) }
}

// --- Stitched GCM ---------------------------------------------------------------

/// One stitched GCM group: AES-CTR keystream for the `G` vectors at `io`
/// (counters from `c`, advanced) interleaved round by round with the GHASH
/// of the `G` vectors at `hsrc` — the previous group's ciphertext when
/// encrypting, this group's when decrypting — so the AES units and the
/// carry-less multiplier work at the same time.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
unsafe fn gcm_group<V: Lanes, const NR: usize>(
    k: &[V; 15],
    c: &mut V,
    hp: &[V; G],
    hk: &[V; G],
    a: &mut __m128i,
    hsrc: *const u8,
    io: *mut u8,
) {
    unsafe {
        // A local array: kept in registers, not pinned to a stack slot.
        let mut b = [V::zero(); G];
        let b = &mut b;
        let l = V::L;
        for (j, x) in b.iter_mut().enumerate() {
            *x = if j == 0 {
                *c
            } else {
                ctr_add::<V, CTR32_BE>(*c, inc(j * l))
            };
        }
        *c = ctr_add::<V, CTR32_BE>(*c, inc(G * l));
        for x in b.iter_mut() {
            *x = x.bswap().xor(k[0]);
        }
        let mut acc = Acc::<V>::new();
        // NR − 1 ≥ 9 middle rounds: one GHASH vector after each of the
        // first G.
        for (r, kr) in k.iter().enumerate().take(NR).skip(1) {
            for x in b.iter_mut() {
                *x = x.enc(*kr);
            }
            if r <= G {
                let j = r - 1;
                let mut d = load_data::<V, true>(hsrc.add(16 * l * j));
                if j == 0 {
                    d = d.xor(V::lane0(*a));
                }
                acc.mul(d, hp[j], hk[j]);
            }
            round_fence();
        }
        for x in b.iter_mut() {
            *x = x.enc_last(k[NR]);
        }
        *a = acc.reduce();
        for (j, x) in b.iter().enumerate() {
            let q = io.add(16 * l * j);
            V::load(q).xor(*x).store(q);
        }
    }
}

/// How many groups behind its AES the stitched encryption hashes.
const LAG: usize = 2;

/// GCM bulk: CTR (`inc32`) from counter block `ctr` (a big-endian `u128`)
/// over the whole blocks of `buf` in place, and GHASH of the ciphertext into
/// `x`. Returns the new GHASH accumulator.
#[inline(always)]
unsafe fn gcm_kernel<V: Lanes, const NR: usize, const ENC: bool>(
    rk: &[u8],
    ctr: u128,
    htab: &HTable,
    x: u128,
    buf: &mut [u8],
) -> u128 {
    debug_assert!(rk.len() >= 16 * (NR + 1) && buf.len().is_multiple_of(16));
    unsafe {
        let l = V::L;
        let rkp = rk.as_ptr();
        let mut p = buf.as_mut_ptr();
        let mut n = buf.len() / 16;
        // The register form of a big-endian counter block is the integer
        // itself, little-endian.
        let mut c = _mm_loadu_si128(ctr.to_le_bytes().as_ptr() as *const __m128i);
        let mut a = _mm_loadu_si128(x.to_le_bytes().as_ptr() as *const __m128i);

        if n >= LAG * G * l + G * l || (!ENC && n >= G * l) {
            let mut k = enc_keys::<V, NR>(rkp);
            let mut hp = [V::zero(); G];
            let mut hk = [V::zero(); G];
            load_powers(htab, G * l, G, &mut hp, &mut hk);
            let mut cv = ctr_add::<V, CTR32_BE>(V::splat(c), lane_index());
            if ENC {
                // Encryption hashes the ciphertext of the group `LAG` groups
                // back, so the GHASH loads never wait on the stores that end
                // the group just before (two groups back measured a few
                // percent faster than one on Zen 5). The first `LAG` groups
                // have nothing to hash yet.
                let gb = 16 * G * l;
                for _ in 0..LAG {
                    ctr_group::<V, NR, CTR32_BE, G>(&k, &mut cv, p);
                    p = p.add(gb);
                    n -= G * l;
                }
                while n >= G * l {
                    gcm_group::<V, NR>(&k, &mut cv, &hp, &hk, &mut a, p.sub(LAG * gb), p);
                    p = p.add(gb);
                    n -= G * l;
                }
                for i in (1..=LAG).rev() {
                    a = ghash_chunk::<V, true>(a, &hp, &hk, p.sub(i * gb), G);
                }
            } else {
                // Decryption hashes the ciphertext of the group it is
                // decrypting, before the XOR overwrites it.
                let gb = 16 * G * l;
                while n >= G * l {
                    gcm_group::<V, NR>(&k, &mut cv, &hp, &hk, &mut a, p, p);
                    p = p.add(gb);
                    n -= G * l;
                }
            }
            c = cv.first();
            wipe(&mut k);
            wipe(&mut hp);
            wipe(&mut hk);
        }

        // Fewer than one stitched group left: the two halves separately,
        // hashing the ciphertext (after encrypting, before decrypting).
        if n > 0 {
            if !ENC {
                a = ghash_run::<V, true>(htab, a, p, n);
            }
            ctr_run::<V, NR, CTR32_BE>(rkp, c, p, n);
            if ENC {
                a = ghash_run::<V, true>(htab, a, p, n);
            }
        }
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, a);
        u128::from_le_bytes(out)
    }
}

// --- Per-tier entry points ------------------------------------------------------

/// Instantiates the generic kernels for one tier inside `#[target_feature]`
/// functions, which is where the generic bodies inline and get their
/// encoding.
macro_rules! tier_entries {
    ($m:ident, $V:ty, $feat:literal) => {
        mod $m {
            use super::*;

            #[target_feature(enable = $feat)]
            pub(super) unsafe fn ecb<const NR: usize, const DEC: bool>(rk: &[u8], buf: &mut [u8]) {
                unsafe { super::ecb_kernel::<$V, NR, DEC>(rk, buf) }
            }

            #[target_feature(enable = $feat)]
            pub(super) unsafe fn ctr<const NR: usize, const MODE: u8>(
                rk: &[u8],
                c: &mut [u8; 16],
                buf: &mut [u8],
            ) {
                unsafe { super::ctr_kernel::<$V, NR, MODE>(rk, c, buf) }
            }

            #[target_feature(enable = $feat)]
            pub(super) unsafe fn cbc_decrypt<const NR: usize>(
                rk: &[u8],
                iv: &mut [u8; 16],
                buf: &mut [u8],
            ) {
                unsafe { super::cbc_decrypt_kernel::<$V, NR>(rk, iv, buf) }
            }

            #[target_feature(enable = $feat)]
            pub(super) unsafe fn ghash<const REV: bool>(
                htab: &HTable,
                x: u128,
                data: &[u8],
            ) -> u128 {
                unsafe { super::ghash_kernel::<$V, REV>(htab, x, data) }
            }

            #[target_feature(enable = $feat)]
            pub(super) unsafe fn gcm<const NR: usize, const ENC: bool>(
                rk: &[u8],
                ctr: u128,
                htab: &HTable,
                x: u128,
                buf: &mut [u8],
            ) -> u128 {
                unsafe { super::gcm_kernel::<$V, NR, ENC>(rk, ctr, htab, x, buf) }
            }
        }
    };
}

tier_entries!(xmm, Xmm, "aes,pclmulqdq,sse2,ssse3");
tier_entries!(
    ymm,
    Ymm,
    "aes,pclmulqdq,sse2,ssse3,avx,avx2,vaes,vpclmulqdq"
);
tier_entries!(
    zmm,
    Zmm,
    "aes,pclmulqdq,sse2,ssse3,avx,avx2,avx512f,avx512bw,vaes,vpclmulqdq"
);

/// The CBC-encrypt chain uses only 128-bit AES-NI.
#[target_feature(enable = "aes,sse2")]
unsafe fn cbc_encrypt_xmm<const NR: usize>(rk: &[u8], iv: &mut [u8; 16], buf: &mut [u8]) {
    unsafe { cbc_encrypt_kernel::<NR>(rk, iv, buf) }
}

// --- Safe-to-call dispatchers -----------------------------------------------------
//
// Each takes the `Tier` that `tier()` returned (the proof that the CPU runs
// that tier's instructions) and a schedule of at least `16 * (NR + 1)`
// bytes; the length checks are hard asserts because the kernels read and
// write through raw pointers.

#[inline]
fn check<const NR: usize>(rk: &[u8], buf: &[u8]) {
    assert!(
        matches!(NR, 10 | 12 | 14) && rk.len() >= 16 * (NR + 1),
        "AES round-key schedule too short for the round count"
    );
    assert!(buf.len().is_multiple_of(16), "whole blocks only");
}

/// ECB in place over whole blocks (`DEC`: the inverse cipher).
#[inline]
pub(crate) fn ecb<const NR: usize, const DEC: bool>(t: Tier, rk: &[u8], buf: &mut [u8]) {
    check::<NR>(rk, buf);
    // SAFETY: `t` came from `tier()`, so the CPU has that tier's features;
    // `check` validated the schedule and the block granularity.
    unsafe {
        match t {
            Tier::Xmm => xmm::ecb::<NR, DEC>(rk, buf),
            Tier::Ymm => ymm::ecb::<NR, DEC>(rk, buf),
            Tier::Zmm => zmm::ecb::<NR, DEC>(rk, buf),
        }
    }
}

/// CTR keystream XOR over whole blocks, advancing `c` (flavour `MODE`).
#[inline]
pub(crate) fn ctr<const NR: usize, const MODE: u8>(
    t: Tier,
    rk: &[u8],
    c: &mut [u8; 16],
    buf: &mut [u8],
) {
    check::<NR>(rk, buf);
    // SAFETY: as in `ecb`.
    unsafe {
        match t {
            Tier::Xmm => xmm::ctr::<NR, MODE>(rk, c, buf),
            Tier::Ymm => ymm::ctr::<NR, MODE>(rk, c, buf),
            Tier::Zmm => zmm::ctr::<NR, MODE>(rk, c, buf),
        }
    }
}

/// CBC encryption over whole blocks; `iv` is the chaining block.
#[inline]
pub(crate) fn cbc_encrypt<const NR: usize>(_t: Tier, rk: &[u8], iv: &mut [u8; 16], buf: &mut [u8]) {
    check::<NR>(rk, buf);
    // SAFETY: every tier includes AES-NI and SSE2; `check` as in `ecb`.
    unsafe { cbc_encrypt_xmm::<NR>(rk, iv, buf) }
}

/// CBC decryption over whole blocks; `iv` is the chaining block.
#[inline]
pub(crate) fn cbc_decrypt<const NR: usize>(t: Tier, rk: &[u8], iv: &mut [u8; 16], buf: &mut [u8]) {
    check::<NR>(rk, buf);
    // SAFETY: as in `ecb`.
    unsafe {
        match t {
            Tier::Xmm => xmm::cbc_decrypt::<NR>(rk, iv, buf),
            Tier::Ymm => ymm::cbc_decrypt::<NR>(rk, iv, buf),
            Tier::Zmm => zmm::cbc_decrypt::<NR>(rk, iv, buf),
        }
    }
}

/// Folds the whole blocks of `data` into the GHASH (`REV`, big-endian
/// blocks, table from [`ghash_table`]) or POLYVAL (little-endian blocks,
/// table of POLYVAL powers) accumulator `x`.
#[inline]
pub(crate) fn hash_blocks<const REV: bool>(t: Tier, htab: &HTable, x: u128, data: &[u8]) -> u128 {
    assert!(data.len().is_multiple_of(16), "whole blocks only");
    // SAFETY: `t` came from `tier()`; the length was checked.
    unsafe {
        match t {
            Tier::Xmm => xmm::ghash::<REV>(htab, x, data),
            Tier::Ymm => ymm::ghash::<REV>(htab, x, data),
            Tier::Zmm => zmm::ghash::<REV>(htab, x, data),
        }
    }
}

/// GCM bulk over the whole blocks of `buf` (see [`gcm`]): CTR from counter
/// block `ctr` and GHASH of the ciphertext into `x`, with an AES schedule of
/// `nr ∈ {10, 12, 14}` rounds. Returns the accumulator.
#[inline]
#[allow(clippy::too_many_arguments)]
pub(crate) fn gcm_crypt(
    t: Tier,
    rk: &[u8],
    nr: usize,
    ctr: u128,
    htab: &HTable,
    x: u128,
    buf: &mut [u8],
    encrypt: bool,
) -> u128 {
    macro_rules! go {
        ($nr:literal) => {{
            check::<$nr>(rk, buf);
            // SAFETY: as in `ecb`.
            unsafe {
                match (t, encrypt) {
                    (Tier::Xmm, true) => xmm::gcm::<$nr, true>(rk, ctr, htab, x, buf),
                    (Tier::Xmm, false) => xmm::gcm::<$nr, false>(rk, ctr, htab, x, buf),
                    (Tier::Ymm, true) => ymm::gcm::<$nr, true>(rk, ctr, htab, x, buf),
                    (Tier::Ymm, false) => ymm::gcm::<$nr, false>(rk, ctr, htab, x, buf),
                    (Tier::Zmm, true) => zmm::gcm::<$nr, true>(rk, ctr, htab, x, buf),
                    (Tier::Zmm, false) => zmm::gcm::<$nr, false>(rk, ctr, htab, x, buf),
                }
            }
        }};
    }
    match nr {
        10 => go!(10),
        12 => go!(12),
        14 => go!(14),
        _ => panic!("AES round count must be 10, 12 or 14"),
    }
}

/// Differential tests of every kernel tier the host supports against the
/// portable AES (and the modes' generic loops), over every length class:
/// each block count around the group and vector boundaries, large buffers,
/// unaligned buffers and counter wrap-around. The capped tiers are
/// selected with [`test_cap::with`]; the Intel SDE CI job runs these on an
/// emulated AVX-512 CPU (look for the `RUNNING Zmm` lines).
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::test_cap;
    use crate::cipher::{Aes128, Aes192, Aes256, BlockCipher, Cbc, Ctr};
    use std::vec::Vec;

    fn fill(seed: u64, out: &mut [u8]) {
        let mut x = seed | 1;
        for b in out.iter_mut() {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            *b = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
        }
    }

    /// Block counts covering every group / vector remainder of every tier
    /// (groups are 8, 16 or 32 blocks), plus large buffers.
    fn block_counts() -> Vec<usize> {
        let mut v: Vec<usize> = (0..=80).collect();
        v.extend([
            95,
            96,
            97,
            127,
            128,
            129,
            255,
            256,
            257,
            1024 + 7,
            4096 + 13,
        ]);
        v
    }

    macro_rules! per_key {
        ($body:ident) => {{
            let mut k16 = [0u8; 16];
            let mut k24 = [0u8; 24];
            let mut k32 = [0u8; 32];
            fill(16, &mut k16);
            fill(24, &mut k24);
            fill(32, &mut k32);
            $body(&Aes128::new(&k16), &Aes128::new_software(&k16), "AES-128");
            $body(&Aes192::new(&k24), &Aes192::new_software(&k24), "AES-192");
            $body(&Aes256::new(&k32), &Aes256::new_software(&k32), "AES-256");
        }};
    }

    #[test]
    fn ecb_tiers_match_portable() {
        fn run<C: BlockCipher + Clone>(hw: &C, sw: &C, name: &str) {
            for n in block_counts() {
                // Offset 3: unaligned for every vector width.
                let mut buf = std::vec![0u8; 16 * n + 3];
                fill(n as u64, &mut buf);
                let data = buf[3..].to_vec();
                let mut a = data.clone();
                sw.encrypt_blocks(&mut a);
                hw.encrypt_blocks(&mut buf[3..]);
                assert_eq!(&buf[3..], &a[..], "{name} enc n={n}");
                hw.decrypt_blocks(&mut buf[3..]);
                assert_eq!(&buf[3..], &data[..], "{name} dec n={n}");
            }
        }
        for cap in test_cap::caps("aes ecb") {
            test_cap::with(cap, || per_key!(run));
        }
    }

    #[test]
    fn ctr_tiers_match_portable() {
        fn run<C: BlockCipher + Clone>(hw: &C, sw: &C, name: &str) {
            // Counter starts: plain, about to carry out of the low 64 bits,
            // and about to wrap the whole 128-bit block.
            let mut ivs = [[0u8; 16]; 3];
            fill(7, &mut ivs[0]);
            ivs[1] = (u128::from(u64::MAX - 5) | 0xabcd << 64).to_be_bytes();
            ivs[2] = (u128::MAX - 9).to_be_bytes();
            let mut lens: Vec<usize> = (0..=600).collect();
            lens.extend([16 * 1024 + 5, 65536 + 31]);
            for iv in &ivs {
                for &len in &lens {
                    let mut buf = std::vec![0u8; len + 1];
                    fill(len as u64 ^ 0x55, &mut buf);
                    let mut want = buf[1..].to_vec();
                    Ctr::new(sw.clone(), iv).apply_keystream(&mut want);
                    Ctr::new(hw.clone(), iv).apply_keystream(&mut buf[1..]);
                    assert_eq!(&buf[1..], &want[..], "{name} len={len} iv={iv:02x?}");
                }
                // Streaming in uneven pieces continues the counter exactly.
                let mut data = std::vec![0u8; 3000];
                fill(99, &mut data);
                let mut want = data.clone();
                Ctr::new(sw.clone(), iv).apply_keystream(&mut want);
                let mut c = Ctr::new(hw.clone(), iv);
                let mut off = 0;
                for (i, step) in [5usize, 16, 600, 1, 513, 31, 1024]
                    .iter()
                    .cycle()
                    .enumerate()
                {
                    if off >= data.len() || i > 100 {
                        break;
                    }
                    let end = (off + step).min(data.len());
                    c.apply_keystream(&mut data[off..end]);
                    off = end;
                }
                c.apply_keystream(&mut data[off..]);
                assert_eq!(data, want, "{name} streamed iv={iv:02x?}");
            }
        }
        for cap in test_cap::caps("aes ctr") {
            test_cap::with(cap, || per_key!(run));
        }
    }

    #[test]
    fn cbc_tiers_match_portable() {
        fn run<C: BlockCipher + Clone>(hw: &C, sw: &C, name: &str) {
            let mut iv = [0u8; 16];
            fill(3, &mut iv);
            for n in block_counts() {
                let mut buf = std::vec![0u8; 16 * n + 1];
                fill(n as u64 ^ 0xc0, &mut buf);
                let pt = buf[1..].to_vec();
                // Reference: the generic serial encryptor of the portable AES.
                let mut want = pt.clone();
                Cbc::new(sw.clone(), &iv).encrypt(&mut want).unwrap();
                Cbc::new(hw.clone(), &iv).encrypt(&mut buf[1..]).unwrap();
                assert_eq!(&buf[1..], &want[..], "{name} enc n={n}");
                Cbc::new(hw.clone(), &iv).decrypt(&mut buf[1..]).unwrap();
                assert_eq!(&buf[1..], &pt[..], "{name} dec n={n}");
            }
            // The chain continues across calls of uneven block counts, and
            // agrees with the portable decryptor.
            let mut data = std::vec![0u8; 16 * 300];
            fill(77, &mut data);
            let pt = data.clone();
            let mut enc = Cbc::new(hw.clone(), &iv);
            let mut dec = Cbc::new(hw.clone(), &iv);
            let mut sw_dec = Cbc::new(sw.clone(), &iv);
            let mut off = 0;
            for blocks in [1usize, 7, 33, 2, 64, 17, 100, 76] {
                let part = &mut data[off..off + 16 * blocks];
                enc.encrypt(part).unwrap();
                let mut ct = part.to_vec();
                sw_dec.decrypt(&mut ct).unwrap();
                assert_eq!(ct, &pt[off..off + 16 * blocks], "{name} sw dec {blocks}");
                dec.decrypt(part).unwrap();
                assert_eq!(part, &pt[off..off + 16 * blocks], "{name} chained {blocks}");
                off += 16 * blocks;
            }
            assert_eq!(off, data.len());
        }
        for cap in test_cap::caps("aes cbc") {
            test_cap::with(cap, || per_key!(run));
        }
    }
}
