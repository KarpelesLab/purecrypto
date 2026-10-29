//! ARMv8 AES hardware backend (aarch64).
//!
//! Uses the `aes` (FEAT_AES) Crypto Extension via `core::arch::aarch64`
//! intrinsics. The AESE/AESD instructions are data-independent (constant-time)
//! in hardware, preserving the crate's constant-time guarantee.
//!
//! Every entry point is `#[target_feature(enable = "aes")]` (NEON is baseline on
//! aarch64) and therefore `unsafe`: callers in [`super`] invoke them only after
//! a runtime `crate::cpu::aes()` check. The round keys are
//! read straight from the software-expanded FIPS-197 `rk` byte array, one
//! `vld1q` per round key per group of blocks — never copied into a stack
//! array, so there is no schedule spill to wipe and no memcpy prologue.
//!
//! The round count is a const generic (`NR` ∈ {10, 12, 14}): each `Aes*`
//! variant monomorphises its own kernels, so the round loops unroll fully and
//! the key offsets are immediates. The batch kernels are *round-major* over
//! eight independent blocks (all eight through round `r`, then round `r+1`):
//! the AESE→AESMC chains of the eight blocks interleave in the pipeline, hiding
//! the ~3-cycle latency of each pair.
//!
//! `vaeseq_u8(x, k)` computes `ShiftRows(SubBytes(x XOR k))` and `vaesmcq_u8`
//! the MixColumns, so each AESE folds one AddRoundKey with the *next* round's
//! byte/row transform — hence the off-by-one key indexing below, which matches
//! the canonical OpenSSL `aesv8` sequences. Decryption uses AESD/AESIMC over the
//! forward schedule taken in reverse (equivalent inverse cipher); the
//! InvMixColumns of the middle round keys is applied on the fly, once per key
//! per group, so no transformed schedule ever exists in memory.
#![allow(unsafe_code)]
// Compute-only NEON intrinsics are safe to call inside a `#[target_feature]` fn
// (target_feature_11), so the uniform body-level `unsafe` is redundant in the
// pointer-free helpers; keep it for consistency and silence the style lint.
#![allow(unused_unsafe)]

use core::arch::aarch64::*;

/// Loads round key `i` (the 16 bytes at `rk[i*16..]`).
#[inline]
#[target_feature(enable = "aes")]
unsafe fn rk(rk: &[u8], i: usize) -> uint8x16_t {
    debug_assert!(rk.len() >= 16 * (i + 1));
    unsafe { vld1q_u8(rk.as_ptr().add(i * 16)) }
}

/// Forward cipher over `N` independent blocks held in registers, round-major:
/// every block goes through round `r` before any goes through `r + 1`, so
/// the `N` AESE→AESMC chains overlap. `NR` is the round count; the schedule
/// holds `NR + 1` keys.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn enc_n<const NR: usize, const N: usize>(round_keys: &[u8], b: &mut [uint8x16_t; N]) {
    unsafe {
        for r in 0..NR - 1 {
            let k = rk(round_keys, r);
            for bj in b.iter_mut() {
                *bj = vaesmcq_u8(vaeseq_u8(*bj, k));
            }
        }
        let k = rk(round_keys, NR - 1);
        let last = rk(round_keys, NR);
        for bj in b.iter_mut() {
            *bj = veorq_u8(vaeseq_u8(*bj, k), last);
        }
    }
}

/// Inverse cipher over `N` independent blocks (equivalent inverse cipher with
/// the forward schedule, the canonical OpenSSL aesv8 decrypt): the first AESD
/// uses the raw last round key, each middle key is InvMixColumns-transformed
/// (`vaesimcq`, once per key per group of `N` blocks, off the blocks'
/// dependency chain) before its AESD, and the state is InvMixColumns'd between
/// rounds. `AESD(x,k) = InvSubBytes(InvShiftRows(x XOR k))`.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn dec_n<const NR: usize, const N: usize>(round_keys: &[u8], b: &mut [uint8x16_t; N]) {
    unsafe {
        let k = rk(round_keys, NR);
        for bj in b.iter_mut() {
            *bj = vaesdq_u8(*bj, k);
        }
        for r in (1..NR).rev() {
            let k = vaesimcq_u8(rk(round_keys, r));
            for bj in b.iter_mut() {
                *bj = vaesdq_u8(vaesimcq_u8(*bj), k);
            }
        }
        let k = rk(round_keys, 0);
        for bj in b.iter_mut() {
            *bj = veorq_u8(*bj, k);
        }
    }
}

/// Loads `N` consecutive blocks from `p`.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn load_n<const N: usize>(p: *const u8) -> [uint8x16_t; N] {
    unsafe {
        let mut b = [vdupq_n_u8(0); N];
        for (j, bj) in b.iter_mut().enumerate() {
            *bj = vld1q_u8(p.add(j * 16));
        }
        b
    }
}

/// Stores `N` consecutive blocks to `p`.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn store_n<const N: usize>(p: *mut u8, b: &[uint8x16_t; N]) {
    unsafe {
        for (j, bj) in b.iter().enumerate() {
            vst1q_u8(p.add(j * 16), *bj);
        }
    }
}

/// Best-effort wipe of a block group before the frame is released: a
/// **volatile** zero store per lane followed by a compiler fence, the same
/// contract as [`crate::zeroize::Zeroize`] (which cannot be used directly:
/// `uint8x16_t` is a vendor vector type, not a `DefaultIsZeroes` scalar).
/// The eight pipelined blocks normally live in registers, but if the
/// allocator spills any, the slot would otherwise keep the last group's
/// output (raw keystream when the caller is a CTR mode) on the stack.
#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn wipe(v: &mut [uint8x16_t]) {
    for x in v.iter_mut() {
        // SAFETY: `x` is a live `&mut uint8x16_t`, hence non-null, properly
        // aligned and exclusively held; a volatile store of a zero vector
        // through it is what `*x = vdupq_n_u8(0)` does, minus the optimizer's
        // licence to treat it as a dead store.
        unsafe { core::ptr::write_volatile(x, vdupq_n_u8(0)) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// One bare AES round (AESENC semantics): `MixColumns(ShiftRows(SubBytes(state)))
/// ⊕ rk`. `vaeseq_u8(x, 0)` gives `ShiftRows(SubBytes(x))` (AddRoundKey with a
/// zero key is a no-op), `vaesmcq_u8` the MixColumns, then XOR the round key.
#[target_feature(enable = "aes")]
pub(super) unsafe fn aes_round(state: [u8; 16], rk: [u8; 16]) -> [u8; 16] {
    unsafe {
        let s = vld1q_u8(state.as_ptr());
        let k = vld1q_u8(rk.as_ptr());
        let r = veorq_u8(vaesmcq_u8(vaeseq_u8(s, vdupq_n_u8(0))), k);
        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), r);
        out
    }
}

/// SubWord for the key schedule. With the word broadcast to all four columns,
/// ShiftRows only moves bytes between identical columns, so lane 0 of
/// `AESE(dup(w), 0)` is exactly `SubBytes(w)`.
#[target_feature(enable = "aes")]
pub(super) unsafe fn sub_word(w: [u8; 4]) -> [u8; 4] {
    unsafe {
        let v = vreinterpretq_u8_u32(vdupq_n_u32(u32::from_le_bytes(w)));
        let s = vaeseq_u8(v, vdupq_n_u8(0));
        vgetq_lane_u32::<0>(vreinterpretq_u32_u8(s)).to_le_bytes()
    }
}

/// Single forward block. The state stays in registers and the round keys are
/// read from the schedule, so nothing secret touches this frame.
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt_block<const NR: usize>(round_keys: &[u8], block: &mut [u8; 16]) {
    unsafe {
        let mut b = [vld1q_u8(block.as_ptr())];
        enc_n::<NR, 1>(round_keys, &mut b);
        vst1q_u8(block.as_mut_ptr(), b[0]);
    }
}

/// Single inverse block.
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt_block<const NR: usize>(round_keys: &[u8], block: &mut [u8; 16]) {
    unsafe {
        let mut b = [vld1q_u8(block.as_ptr())];
        dec_n::<NR, 1>(round_keys, &mut b);
        vst1q_u8(block.as_mut_ptr(), b[0]);
    }
}

/// Forward permutation over independent 16-byte blocks, eight at a time
/// round-major, then a four-block group and single blocks for the remainder.
/// `blocks.len()` must be a multiple of 16.
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt_blocks<const NR: usize>(round_keys: &[u8], blocks: &mut [u8]) {
    unsafe {
        let mut wide = blocks.chunks_exact_mut(16 * 8);
        // Hoisted so the wipe below covers the last group's outputs (raw
        // keystream when the caller is a CTR mode).
        let mut b = [vdupq_n_u8(0); 8];
        for c in &mut wide {
            b = load_n::<8>(c.as_ptr());
            enc_n::<NR, 8>(round_keys, &mut b);
            store_n::<8>(c.as_mut_ptr(), &b);
        }
        let mut rest = wide.into_remainder();
        if rest.len() >= 64 {
            let mut q = load_n::<4>(rest.as_ptr());
            enc_n::<NR, 4>(round_keys, &mut q);
            store_n::<4>(rest.as_mut_ptr(), &q);
            b[..4].copy_from_slice(&q);
            rest = &mut rest[64..];
        }
        for block in rest.chunks_exact_mut(16) {
            let mut s = [vld1q_u8(block.as_ptr())];
            enc_n::<NR, 1>(round_keys, &mut s);
            vst1q_u8(block.as_mut_ptr(), s[0]);
            b[0] = s[0];
        }
        wipe(&mut b);
    }
}

/// Inverse permutation over independent 16-byte blocks, eight at a time
/// round-major. `blocks.len()` must be a multiple of 16.
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt_blocks<const NR: usize>(round_keys: &[u8], blocks: &mut [u8]) {
    unsafe {
        let mut wide = blocks.chunks_exact_mut(16 * 8);
        let mut b = [vdupq_n_u8(0); 8];
        for c in &mut wide {
            b = load_n::<8>(c.as_ptr());
            dec_n::<NR, 8>(round_keys, &mut b);
            store_n::<8>(c.as_mut_ptr(), &b);
        }
        let mut rest = wide.into_remainder();
        if rest.len() >= 64 {
            let mut q = load_n::<4>(rest.as_ptr());
            dec_n::<NR, 4>(round_keys, &mut q);
            store_n::<4>(rest.as_mut_ptr(), &q);
            b[..4].copy_from_slice(&q);
            rest = &mut rest[64..];
        }
        for block in rest.chunks_exact_mut(16) {
            let mut s = [vld1q_u8(block.as_ptr())];
            dec_n::<NR, 1>(round_keys, &mut s);
            vst1q_u8(block.as_mut_ptr(), s[0]);
            b[0] = s[0];
        }
        wipe(&mut b);
    }
}

// --- Bare-round constructions (AEGIS, AEZ) ------------------------------------

use super::{AEGIS_ABSORB, AEGIS_ENC};

/// One AES round with AESENC semantics on registers:
/// `MixColumns(ShiftRows(SubBytes(a))) ⊕ b`.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn round(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    unsafe { veorq_u8(vaesmcq_u8(vaeseq_u8(a, vdupq_n_u8(0))), b) }
}

/// Loads an `N`-word byte state into registers.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn load_words<const N: usize>(s: &[[u8; 16]; N]) -> [uint8x16_t; N] {
    unsafe {
        let mut v = [vdupq_n_u8(0); N];
        for (vj, sj) in v.iter_mut().zip(s.iter()) {
            *vj = vld1q_u8(sj.as_ptr());
        }
        v
    }
}

/// Stores an `N`-word register state back to bytes.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn store_words<const N: usize>(s: &mut [[u8; 16]; N], v: &[uint8x16_t; N]) {
    unsafe {
        for (sj, vj) in s.iter_mut().zip(v.iter()) {
            vst1q_u8(sj.as_mut_ptr(), *vj);
        }
    }
}

/// Keystream/data step shared by the AEGIS kernels: with the keystream
/// block `z`, returns the block to feed the state update (the data itself
/// when absorbing or encrypting, the recovered plaintext when decrypting)
/// and writes the output block in place for the two cipher modes. `p` is
/// only written when `MODE != AEGIS_ABSORB`.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn aegis_step<const MODE: u8>(p: *mut u8, z: uint8x16_t) -> uint8x16_t {
    unsafe {
        let m = vld1q_u8(p);
        if MODE == AEGIS_ABSORB {
            return m;
        }
        let c = veorq_u8(m, z);
        vst1q_u8(p, c);
        if MODE == AEGIS_ENC { m } else { c }
    }
}

/// AEGIS-128L bulk kernel: runs `StateUpdate128L` over every 32-byte block of
/// `buf` (`len` must be a multiple of 32) with the state held in registers.
/// `buf` is read only in [`AEGIS_ABSORB`] mode, read and written in place
/// in the two cipher modes. The eight AES rounds of one update are
/// independent; the only chain is between successive updates.
#[target_feature(enable = "aes")]
pub(super) unsafe fn aegis128l<const MODE: u8>(s: &mut [[u8; 16]; 8], buf: *mut u8, len: usize) {
    unsafe {
        let mut st = load_words(s);
        let mut off = 0;
        while off + 32 <= len {
            let p = buf.add(off);
            let z0 = veorq_u8(veorq_u8(st[1], st[6]), vandq_u8(st[2], st[3]));
            let z1 = veorq_u8(veorq_u8(st[2], st[5]), vandq_u8(st[6], st[7]));
            let t0 = aegis_step::<MODE>(p, z0);
            let t1 = aegis_step::<MODE>(p.add(16), z1);
            st = [
                round(st[7], veorq_u8(st[0], t0)),
                round(st[0], st[1]),
                round(st[1], st[2]),
                round(st[2], st[3]),
                round(st[3], veorq_u8(st[4], t1)),
                round(st[4], st[5]),
                round(st[5], st[6]),
                round(st[6], st[7]),
            ];
            off += 32;
        }
        store_words(s, &st);
        // The state is key material (it yields the keystream and the tag);
        // the caller's copy is wiped on drop, scrub any register spills here.
        wipe(&mut st);
    }
}

/// AEGIS-256 bulk kernel: `StateUpdate256` over every 16-byte block of `buf`
/// (`len` a multiple of 16); see [`aegis128l`] for the buffer contract.
#[target_feature(enable = "aes")]
pub(super) unsafe fn aegis256<const MODE: u8>(s: &mut [[u8; 16]; 6], buf: *mut u8, len: usize) {
    unsafe {
        let mut st = load_words(s);
        let mut off = 0;
        while off + 16 <= len {
            let z = veorq_u8(
                veorq_u8(veorq_u8(st[1], st[4]), st[5]),
                vandq_u8(st[2], st[3]),
            );
            let t = aegis_step::<MODE>(buf.add(off), z);
            st = [
                round(st[5], veorq_u8(st[0], t)),
                round(st[0], st[1]),
                round(st[1], st[2]),
                round(st[2], st[3]),
                round(st[3], st[4]),
                round(st[4], st[5]),
            ];
            off += 16;
        }
        store_words(s, &st);
        wipe(&mut st);
    }
}

/// AEGIS-128 (the original five-word CAESAR variant) bulk kernel over every
/// 16-byte block of `buf` (`len` a multiple of 16); see [`aegis128l`].
#[cfg(feature = "legacy-ciphers")]
#[target_feature(enable = "aes")]
pub(super) unsafe fn aegis128<const MODE: u8>(s: &mut [[u8; 16]; 5], buf: *mut u8, len: usize) {
    unsafe {
        let mut st = load_words(s);
        let mut off = 0;
        while off + 16 <= len {
            let z = veorq_u8(veorq_u8(st[1], st[4]), vandq_u8(st[2], st[3]));
            let t = aegis_step::<MODE>(buf.add(off), z);
            st = [
                round(st[4], veorq_u8(st[0], t)),
                round(st[0], st[1]),
                round(st[1], st[2]),
                round(st[2], st[3]),
                round(st[3], st[4]),
            ];
            off += 16;
        }
        store_words(s, &st);
        wipe(&mut st);
    }
}

#[cfg(feature = "aez")]
/// AEZ `AES4` (`keys[0..4]`) over the first `N` of the blocks held in
/// registers, round-major so the `N` chains overlap.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn aes4_n<const N: usize>(b: &mut [uint8x16_t; AEZ_PAIRS], k: &[uint8x16_t; 4]) {
    unsafe {
        for kv in k {
            for bj in b[..N].iter_mut() {
                *bj = round(*bj, *kv);
            }
        }
    }
}

#[cfg(feature = "aez")]
/// Pairs in flight in the AEZ-core pass kernels: the three dependent `AES4`
/// stages are latency-bound below this on a wide core (32 vector registers
/// hold the eight pairs plus the keys).
const AEZ_PAIRS: usize = 8;
#[cfg(feature = "aez")]
const _: () = assert!(8 % AEZ_PAIRS == 0);

#[cfg(feature = "aez")]
/// Register-resident temporaries of the AEZ pass kernels: the two blocks of
/// each pair and the `AES4` chain. Hoisted to the kernel entry so they are
/// wiped once per call (a wipe per group would pin them to stack slots and
/// fence every group's loads behind the previous group's stores).
struct AezRegs {
    m0: [uint8x16_t; AEZ_PAIRS],
    m1: [uint8x16_t; AEZ_PAIRS],
    t: [uint8x16_t; AEZ_PAIRS],
}

#[cfg(feature = "aez")]
impl AezRegs {
    #[inline]
    #[target_feature(enable = "aes")]
    unsafe fn new() -> Self {
        AezRegs {
            m0: [vdupq_n_u8(0); AEZ_PAIRS],
            m1: [vdupq_n_u8(0); AEZ_PAIRS],
            t: [vdupq_n_u8(0); AEZ_PAIRS],
        }
    }

    #[inline]
    #[target_feature(enable = "aes")]
    unsafe fn wipe(&mut self) {
        unsafe {
            wipe(&mut self.m0);
            wipe(&mut self.m1);
            wipe(&mut self.t);
        }
    }
}

#[cfg(feature = "aez")]
/// The AEZ tweak-offset schedule of the core passes: pair `i` (from 1) uses
/// `ii ⊕ L[i mod 8]` with `ii` starting at `2I` and doubling (in GF(2¹²⁸),
/// big-endian, `0x87`) after every pair with `i ≡ 0 (mod 8)`. Walked here in
/// groups of eight pairs that share one `ii`, so the kernels form the
/// offsets in registers from `ii` and the `L` table instead of a
/// materialised offset array.
struct AezTweaks {
    /// The running `ii`, as the big-endian integer it is doubled as.
    ii: u128,
    /// `L[0..8]` table base.
    l: *const u8,
}

#[cfg(feature = "aez")]
impl AezTweaks {
    /// `L[k]` for `k = (lbase + j) mod 8`.
    #[inline]
    #[target_feature(enable = "aes")]
    unsafe fn l(&self, lbase: usize, j: usize) -> uint8x16_t {
        unsafe { vld1q_u8(self.l.add(16 * ((lbase + j) & 7))) }
    }

    /// The current `ii` as a vector (`xored` with a base, e.g. `1J`).
    #[inline]
    #[target_feature(enable = "aes")]
    unsafe fn ii_xor(&self, base: uint8x16_t) -> uint8x16_t {
        unsafe { veorq_u8(base, vld1q_u8(self.ii.to_be_bytes().as_ptr())) }
    }

    /// Advances past a full group of eight pairs: `ii ← 2·ii`, branch-free.
    #[inline]
    fn double(&mut self) {
        let v = self.ii;
        self.ii = (v << 1) ^ (0u128.wrapping_sub(v >> 127) & 0x87);
    }
}

#[cfg(feature = "aez")]
/// AEZ-core pass 1 over `N` i-block pairs at `p` with offsets
/// `jii ⊕ L[(lbase + j) mod 8]` (`jii = 1J ⊕ ii`): `o0 = m0 ⊕ E(1,i)(m1)`,
/// `o1 = m1 ⊕ E(0,0)(o0)`, `x ⊕= o1`, written back in place.
#[inline]
#[target_feature(enable = "aes")]
#[allow(clippy::too_many_arguments)]
unsafe fn aez_pass1_n<const N: usize>(
    r: &mut AezRegs,
    k: &[uint8x16_t; 4],
    i1: uint8x16_t,
    jii: uint8x16_t,
    tw: &AezTweaks,
    lbase: usize,
    p: *mut u8,
    x: &mut uint8x16_t,
) {
    unsafe {
        for j in 0..N {
            r.m0[j] = vld1q_u8(p.add(32 * j));
            r.m1[j] = vld1q_u8(p.add(32 * j + 16));
            r.t[j] = veorq_u8(veorq_u8(r.m1[j], jii), tw.l(lbase, j));
        }
        aes4_n::<N>(&mut r.t, k);
        for j in 0..N {
            r.m0[j] = veorq_u8(r.m0[j], r.t[j]);
            r.t[j] = veorq_u8(r.m0[j], i1);
        }
        aes4_n::<N>(&mut r.t, k);
        for j in 0..N {
            r.m1[j] = veorq_u8(r.m1[j], r.t[j]);
            *x = veorq_u8(*x, r.m1[j]);
            vst1q_u8(p.add(32 * j), r.m0[j]);
            vst1q_u8(p.add(32 * j + 16), r.m1[j]);
        }
    }
}

#[cfg(feature = "aez")]
/// AEZ-core pass 2 over `N` pairs: with `t = E(2,i)(S)` (input
/// `sj2 ⊕ L[..]`, `sj2 = S ⊕ 2J ⊕ ii`), `o0 = m0 ⊕ t`, `o1 = m1 ⊕ t`,
/// `y ⊕= o0`, `o0 ⊕= E(0,0)(o1)`, `o1 ⊕= E(1,i)(o0)` (offset
/// `jii ⊕ L[..]`, `jii = 1J ⊕ ii`), the pair written back swapped (`o1 ‖ o0`).
#[inline]
#[target_feature(enable = "aes")]
#[allow(clippy::too_many_arguments)]
unsafe fn aez_pass2_n<const N: usize>(
    r: &mut AezRegs,
    k: &[uint8x16_t; 4],
    i1: uint8x16_t,
    jii: uint8x16_t,
    sj2: uint8x16_t,
    tw: &AezTweaks,
    lbase: usize,
    p: *mut u8,
    y: &mut uint8x16_t,
) {
    unsafe {
        for j in 0..N {
            r.m0[j] = vld1q_u8(p.add(32 * j));
            r.m1[j] = vld1q_u8(p.add(32 * j + 16));
            r.t[j] = veorq_u8(sj2, tw.l(lbase, j));
        }
        aes4_n::<N>(&mut r.t, k);
        for j in 0..N {
            r.m0[j] = veorq_u8(r.m0[j], r.t[j]);
            r.m1[j] = veorq_u8(r.m1[j], r.t[j]);
            *y = veorq_u8(*y, r.m0[j]);
            r.t[j] = veorq_u8(r.m1[j], i1);
        }
        aes4_n::<N>(&mut r.t, k);
        for j in 0..N {
            r.m0[j] = veorq_u8(r.m0[j], r.t[j]);
            r.t[j] = veorq_u8(veorq_u8(r.m0[j], jii), tw.l(lbase, j));
        }
        aes4_n::<N>(&mut r.t, k);
        for j in 0..N {
            r.m1[j] = veorq_u8(r.m1[j], r.t[j]);
            vst1q_u8(p.add(32 * j), r.m1[j]);
            vst1q_u8(p.add(32 * j + 16), r.m0[j]);
        }
    }
}

#[cfg(feature = "aez")]
/// AEZ-core pass 1 over the `npairs` i-block pairs at `buf` (see
/// [`aez_pass1_n`]): `keys` are the `AES4` round keys, `i1`/`j1` the `1I` and
/// `1J` subkeys, `l` the `L[0..8]` table, `i2 = 2I` the initial `ii`, `x` the
/// running `X`. [`AEZ_PAIRS`] pairs in flight, then a four-group, then
/// singly. Kept out of line so the register-resident body survives
/// whole-program inlining into the scalar caller.
#[inline(never)]
#[target_feature(enable = "aes")]
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn aez_pass1(
    keys: &[[u8; 16]; 4],
    i1: &[u8; 16],
    j1: &[u8; 16],
    l: &[[u8; 16]; 8],
    i2: &[u8; 16],
    npairs: usize,
    buf: *mut u8,
    x: &mut [u8; 16],
) {
    unsafe {
        let k = load_words(keys);
        let i1v = vld1q_u8(i1.as_ptr());
        let j1v = vld1q_u8(j1.as_ptr());
        let mut xv = vld1q_u8(x.as_ptr());
        let mut r = AezRegs::new();
        let mut tw = AezTweaks {
            ii: u128::from_be_bytes(*i2),
            l: l.as_ptr() as *const u8,
        };
        let mut p = buf;
        let mut left = npairs;
        // Runs of eight pairs (`i ≡ 1..=0 (mod 8)`) share `ii` and use
        // `L[1..7], L[0]`; a run is one or two groups depending on the
        // backend's width, and `ii` doubles after each run.
        while left >= 8 {
            let jii = tw.ii_xor(j1v);
            let mut lbase = 1;
            for _ in 0..8 / AEZ_PAIRS {
                aez_pass1_n::<AEZ_PAIRS>(&mut r, &k, i1v, jii, &tw, lbase, p, &mut xv);
                p = p.add(32 * AEZ_PAIRS);
                lbase += AEZ_PAIRS;
            }
            left -= 8;
            tw.double();
        }
        // The remainder never reaches the next doubling point.
        let jii = tw.ii_xor(j1v);
        let mut lbase = 1;
        if left >= 4 {
            aez_pass1_n::<4>(&mut r, &k, i1v, jii, &tw, lbase, p, &mut xv);
            p = p.add(128);
            left -= 4;
            lbase += 4;
        }
        for _ in 0..left {
            aez_pass1_n::<1>(&mut r, &k, i1v, jii, &tw, lbase, p, &mut xv);
            p = p.add(32);
            lbase += 1;
        }
        vst1q_u8(x.as_mut_ptr(), xv);
        r.wipe();
        crate::zeroize::Zeroize::zeroize(&mut tw.ii);
    }
}

#[cfg(feature = "aez")]
/// AEZ-core pass 2 over the `npairs` pairs at `buf` (see [`aez_pass2_n`]);
/// `j2 = 2J`, `s` the `S` block, `y` the running `Y`, the rest as in
/// [`aez_pass1`].
#[inline(never)]
#[target_feature(enable = "aes")]
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn aez_pass2(
    keys: &[[u8; 16]; 4],
    i1: &[u8; 16],
    j1: &[u8; 16],
    j2: &[u8; 16],
    l: &[[u8; 16]; 8],
    i2: &[u8; 16],
    s: &[u8; 16],
    npairs: usize,
    buf: *mut u8,
    y: &mut [u8; 16],
) {
    unsafe {
        let k = load_words(keys);
        let i1v = vld1q_u8(i1.as_ptr());
        let j1v = vld1q_u8(j1.as_ptr());
        let sj2v = veorq_u8(vld1q_u8(s.as_ptr()), vld1q_u8(j2.as_ptr()));
        let mut yv = vld1q_u8(y.as_ptr());
        let mut r = AezRegs::new();
        let mut tw = AezTweaks {
            ii: u128::from_be_bytes(*i2),
            l: l.as_ptr() as *const u8,
        };
        let mut p = buf;
        let mut left = npairs;
        while left >= 8 {
            let jii = tw.ii_xor(j1v);
            let sj2 = tw.ii_xor(sj2v);
            let mut lbase = 1;
            for _ in 0..8 / AEZ_PAIRS {
                aez_pass2_n::<AEZ_PAIRS>(&mut r, &k, i1v, jii, sj2, &tw, lbase, p, &mut yv);
                p = p.add(32 * AEZ_PAIRS);
                lbase += AEZ_PAIRS;
            }
            left -= 8;
            tw.double();
        }
        let jii = tw.ii_xor(j1v);
        let sj2 = tw.ii_xor(sj2v);
        let mut lbase = 1;
        if left >= 4 {
            aez_pass2_n::<4>(&mut r, &k, i1v, jii, sj2, &tw, lbase, p, &mut yv);
            p = p.add(128);
            left -= 4;
            lbase += 4;
        }
        for _ in 0..left {
            aez_pass2_n::<1>(&mut r, &k, i1v, jii, sj2, &tw, lbase, p, &mut yv);
            p = p.add(32);
            lbase += 1;
        }
        vst1q_u8(y.as_mut_ptr(), yv);
        r.wipe();
        crate::zeroize::Zeroize::zeroize(&mut tw.ii);
    }
}
