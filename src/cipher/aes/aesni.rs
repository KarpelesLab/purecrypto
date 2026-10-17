//! AES-NI hardware backend (x86_64).
//!
//! Uses the `aes` instruction-set extension via `core::arch::x86_64` intrinsics.
//! These instructions are data-independent (constant-time) in hardware, so this
//! backend preserves the crate's constant-time guarantee while running ~50×
//! faster than the table-free software S-box.
//!
//! Every entry point is `#[target_feature(enable = "aes,sse2")]` and therefore
//! `unsafe`: callers in [`super`] invoke them only after a runtime
//! `is_x86_feature_detected!("aes")` check. AES-NI consumes the standard
//! FIPS-197 round-key schedule directly, so the round keys are read straight
//! from the software-expanded `rk` byte array; decryption derives the
//! equivalent-inverse-cipher round keys on the fly with `aesimc`.
#![allow(unsafe_code)]

use core::arch::x86_64::*;

/// Loads round key `i` (the 16 bytes at `rk[i*16..]`) into a 128-bit register.
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rk(rk: &[u8], i: usize) -> __m128i {
    unsafe { _mm_loadu_si128(rk.as_ptr().add(i * 16) as *const __m128i) }
}

/// One bare AES round (AESENC): `MixColumns(ShiftRows(SubBytes(state))) ⊕ rk`.
/// The AEGIS/AEZ round primitive.
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn aes_round(state: [u8; 16], rk: [u8; 16]) -> [u8; 16] {
    unsafe {
        let s = _mm_loadu_si128(state.as_ptr() as *const __m128i);
        let k = _mm_loadu_si128(rk.as_ptr() as *const __m128i);
        let r = _mm_aesenc_si128(s, k);
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, r);
        out
    }
}

/// SubWord for the key schedule: `AESKEYGENASSIST` with a zero round constant
/// puts `SubWord(X[1])` in lane 0 (RotWord and Rcon stay in the shared
/// software schedule, which keeps the round-constant immediate out of a
/// per-round match).
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn sub_word(w: [u8; 4]) -> [u8; 4] {
    let v = _mm_set1_epi32(i32::from_le_bytes(w));
    let s = _mm_aeskeygenassist_si128::<0>(v);
    _mm_cvtsi128_si32(s).to_le_bytes()
}

/// Single forward block via AES-NI.
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn encrypt_block(round_keys: &[u8], nr: usize, block: &mut [u8; 16]) {
    unsafe {
        let mut s = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        s = _mm_xor_si128(s, rk(round_keys, 0));
        for r in 1..nr {
            s = _mm_aesenc_si128(s, rk(round_keys, r));
        }
        s = _mm_aesenclast_si128(s, rk(round_keys, nr));
        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, s);
    }
}

/// Single inverse block via AES-NI (equivalent inverse cipher).
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn decrypt_block(round_keys: &[u8], nr: usize, block: &mut [u8; 16]) {
    unsafe {
        let mut s = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        s = _mm_xor_si128(s, rk(round_keys, nr));
        for r in (1..nr).rev() {
            s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk(round_keys, r)));
        }
        s = _mm_aesdeclast_si128(s, rk(round_keys, 0));
        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, s);
    }
}

/// Best-effort wipe of a preloaded `__m128i` schedule (or block group) before
/// the frame is released: a **volatile** zero store per lane followed by a
/// compiler fence, the same contract as [`crate::zeroize::Zeroize`] (which
/// cannot be used directly: `__m128i` is a vendor vector type, not a
/// `DefaultIsZeroes` scalar). The vectors are usually in registers, but with 15
/// keys plus 8 pipelined blocks the allocator does spill, and the spill slots
/// would otherwise keep the round keys (from which the AES key is trivially
/// recovered) alive on the stack. Same idiom as the `Aes*` round-key `Drop`.
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn wipe(v: &mut [__m128i]) {
    for x in v.iter_mut() {
        // SAFETY: `x` is a live `&mut __m128i`, hence non-null, properly
        // aligned and exclusively held; a volatile store of a zero vector
        // through it is what `*x = _mm_setzero_si128()` does, minus the
        // optimizer's licence to treat it as a dead store.
        unsafe { core::ptr::write_volatile(x, _mm_setzero_si128()) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Forward permutation over independent 16-byte blocks, pipelining 8 at a time
/// so the AESENC latency is hidden. `blocks.len()` must be a multiple of 16.
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn encrypt_blocks(round_keys: &[u8], nr: usize, blocks: &mut [u8]) {
    unsafe {
        // Preload the schedule once (≤ 15 round keys for AES-256).
        let mut ks = [_mm_setzero_si128(); 15];
        for (i, k) in ks.iter_mut().enumerate().take(nr + 1) {
            *k = rk(round_keys, i);
        }

        let mut wide = blocks.chunks_exact_mut(16 * 8);
        // Hoisted so the wipe below covers the last group's outputs (raw
        // keystream when the caller is a CTR mode).
        let mut b = [_mm_setzero_si128(); 8];
        for c in &mut wide {
            for (j, bj) in b.iter_mut().enumerate() {
                *bj = _mm_loadu_si128(c.as_ptr().add(j * 16) as *const __m128i);
            }
            for bj in b.iter_mut() {
                *bj = _mm_xor_si128(*bj, ks[0]);
            }
            for &k in ks.iter().take(nr).skip(1) {
                for bj in b.iter_mut() {
                    *bj = _mm_aesenc_si128(*bj, k);
                }
            }
            for bj in b.iter_mut() {
                *bj = _mm_aesenclast_si128(*bj, ks[nr]);
            }
            for (j, &bj) in b.iter().enumerate() {
                _mm_storeu_si128(c.as_mut_ptr().add(j * 16) as *mut __m128i, bj);
            }
        }

        for block in wide.into_remainder().chunks_exact_mut(16) {
            let mut s = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            s = _mm_xor_si128(s, ks[0]);
            for &k in ks.iter().take(nr).skip(1) {
                s = _mm_aesenc_si128(s, k);
            }
            s = _mm_aesenclast_si128(s, ks[nr]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, s);
        }
        wipe(&mut ks);
        wipe(&mut b);
    }
}

/// Inverse permutation over independent 16-byte blocks, pipelining 8 at a time.
/// `blocks.len()` must be a multiple of 16.
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn decrypt_blocks(round_keys: &[u8], nr: usize, blocks: &mut [u8]) {
    unsafe {
        // Equivalent-inverse-cipher schedule: rk[0], imc(rk[1..nr]), rk[nr].
        let mut ks = [_mm_setzero_si128(); 15];
        ks[0] = rk(round_keys, 0);
        ks[nr] = rk(round_keys, nr);
        for (i, k) in ks.iter_mut().enumerate().take(nr).skip(1) {
            *k = _mm_aesimc_si128(rk(round_keys, i));
        }

        let mut wide = blocks.chunks_exact_mut(16 * 8);
        let mut b = [_mm_setzero_si128(); 8];
        for c in &mut wide {
            for (j, bj) in b.iter_mut().enumerate() {
                *bj = _mm_loadu_si128(c.as_ptr().add(j * 16) as *const __m128i);
            }
            for bj in b.iter_mut() {
                *bj = _mm_xor_si128(*bj, ks[nr]);
            }
            for r in (1..nr).rev() {
                for bj in b.iter_mut() {
                    *bj = _mm_aesdec_si128(*bj, ks[r]);
                }
            }
            for bj in b.iter_mut() {
                *bj = _mm_aesdeclast_si128(*bj, ks[0]);
            }
            for (j, &bj) in b.iter().enumerate() {
                _mm_storeu_si128(c.as_mut_ptr().add(j * 16) as *mut __m128i, bj);
            }
        }

        for block in wide.into_remainder().chunks_exact_mut(16) {
            let mut s = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            s = _mm_xor_si128(s, ks[nr]);
            for r in (1..nr).rev() {
                s = _mm_aesdec_si128(s, ks[r]);
            }
            s = _mm_aesdeclast_si128(s, ks[0]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, s);
        }
        // This is the only copy of the AESIMC-transformed inverse schedule
        // anywhere — the cipher struct keeps just the forward keys — so its
        // spill slots are the only place it could survive.
        wipe(&mut ks);
        wipe(&mut b);
    }
}

// --- Bare-round constructions (AEGIS, AEZ) ------------------------------------

use super::{AEGIS_ABSORB, AEGIS_ENC};

/// Loads an `N`-word byte state into registers.
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn load_words<const N: usize>(s: &[[u8; 16]; N]) -> [__m128i; N] {
    unsafe {
        let mut v = [_mm_setzero_si128(); N];
        for (vj, sj) in v.iter_mut().zip(s.iter()) {
            *vj = _mm_loadu_si128(sj.as_ptr() as *const __m128i);
        }
        v
    }
}

/// Stores an `N`-word register state back to bytes.
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn store_words<const N: usize>(s: &mut [[u8; 16]; N], v: &[__m128i; N]) {
    unsafe {
        for (sj, vj) in s.iter_mut().zip(v.iter()) {
            _mm_storeu_si128(sj.as_mut_ptr() as *mut __m128i, *vj);
        }
    }
}

/// Keystream/data step shared by the AEGIS kernels: with the keystream
/// block `z`, returns the block to feed the state update (the data itself
/// when absorbing or encrypting, the recovered plaintext when decrypting)
/// and writes the output block in place for the two cipher modes. `p` is
/// only written when `MODE != AEGIS_ABSORB`.
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn aegis_step<const MODE: u8>(p: *mut u8, z: __m128i) -> __m128i {
    unsafe {
        let m = _mm_loadu_si128(p as *const __m128i);
        if MODE == AEGIS_ABSORB {
            return m;
        }
        let c = _mm_xor_si128(m, z);
        _mm_storeu_si128(p as *mut __m128i, c);
        if MODE == AEGIS_ENC { m } else { c }
    }
}

/// AEGIS-128L bulk kernel: runs `StateUpdate128L` over every 32-byte block of
/// `buf` (`len` must be a multiple of 32) with the state held in registers.
/// `buf` is read only in [`AEGIS_ABSORB`] mode, read and written in place
/// in the two cipher modes. The eight AESENCs of one update are
/// independent; the only chain is between successive updates.
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn aegis128l<const MODE: u8>(s: &mut [[u8; 16]; 8], buf: *mut u8, len: usize) {
    unsafe {
        let mut st = load_words(s);
        let mut off = 0;
        while off + 32 <= len {
            let p = buf.add(off);
            let z0 = _mm_xor_si128(_mm_xor_si128(st[1], st[6]), _mm_and_si128(st[2], st[3]));
            let z1 = _mm_xor_si128(_mm_xor_si128(st[2], st[5]), _mm_and_si128(st[6], st[7]));
            let t0 = aegis_step::<MODE>(p, z0);
            let t1 = aegis_step::<MODE>(p.add(16), z1);
            st = [
                _mm_aesenc_si128(st[7], _mm_xor_si128(st[0], t0)),
                _mm_aesenc_si128(st[0], st[1]),
                _mm_aesenc_si128(st[1], st[2]),
                _mm_aesenc_si128(st[2], st[3]),
                _mm_aesenc_si128(st[3], _mm_xor_si128(st[4], t1)),
                _mm_aesenc_si128(st[4], st[5]),
                _mm_aesenc_si128(st[5], st[6]),
                _mm_aesenc_si128(st[6], st[7]),
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
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn aegis256<const MODE: u8>(s: &mut [[u8; 16]; 6], buf: *mut u8, len: usize) {
    unsafe {
        let mut st = load_words(s);
        let mut off = 0;
        while off + 16 <= len {
            let z = _mm_xor_si128(
                _mm_xor_si128(_mm_xor_si128(st[1], st[4]), st[5]),
                _mm_and_si128(st[2], st[3]),
            );
            let t = aegis_step::<MODE>(buf.add(off), z);
            st = [
                _mm_aesenc_si128(st[5], _mm_xor_si128(st[0], t)),
                _mm_aesenc_si128(st[0], st[1]),
                _mm_aesenc_si128(st[1], st[2]),
                _mm_aesenc_si128(st[2], st[3]),
                _mm_aesenc_si128(st[3], st[4]),
                _mm_aesenc_si128(st[4], st[5]),
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
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn aegis128<const MODE: u8>(s: &mut [[u8; 16]; 5], buf: *mut u8, len: usize) {
    unsafe {
        let mut st = load_words(s);
        let mut off = 0;
        while off + 16 <= len {
            let z = _mm_xor_si128(_mm_xor_si128(st[1], st[4]), _mm_and_si128(st[2], st[3]));
            let t = aegis_step::<MODE>(buf.add(off), z);
            st = [
                _mm_aesenc_si128(st[4], _mm_xor_si128(st[0], t)),
                _mm_aesenc_si128(st[0], st[1]),
                _mm_aesenc_si128(st[1], st[2]),
                _mm_aesenc_si128(st[2], st[3]),
                _mm_aesenc_si128(st[3], st[4]),
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
#[target_feature(enable = "aes,sse2")]
unsafe fn aes4_n<const N: usize>(b: &mut [__m128i; AEZ_PAIRS], k: &[__m128i; 4]) {
    for kv in k {
        for bj in b[..N].iter_mut() {
            *bj = _mm_aesenc_si128(*bj, *kv);
        }
    }
}

#[cfg(feature = "aez")]
/// Pairs in flight in the AEZ-core pass kernels: four fills the AESENC
/// pipeline (latency 4) within the sixteen SSE registers.
const AEZ_PAIRS: usize = 4;
#[cfg(feature = "aez")]
const _: () = assert!(8 % AEZ_PAIRS == 0);

#[cfg(feature = "aez")]
/// Register-resident temporaries of the AEZ pass kernels: the two blocks of
/// each pair and the `AES4` chain. Hoisted to the kernel entry so they are
/// wiped once per call (a wipe per group would pin them to stack slots and
/// fence every group's loads behind the previous group's stores).
struct AezRegs {
    m0: [__m128i; AEZ_PAIRS],
    m1: [__m128i; AEZ_PAIRS],
    t: [__m128i; AEZ_PAIRS],
}

#[cfg(feature = "aez")]
impl AezRegs {
    #[inline]
    #[target_feature(enable = "aes,sse2")]
    unsafe fn new() -> Self {
        AezRegs {
            m0: [_mm_setzero_si128(); AEZ_PAIRS],
            m1: [_mm_setzero_si128(); AEZ_PAIRS],
            t: [_mm_setzero_si128(); AEZ_PAIRS],
        }
    }

    #[inline]
    #[target_feature(enable = "aes,sse2")]
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
    #[target_feature(enable = "aes,sse2")]
    unsafe fn l(&self, lbase: usize, j: usize) -> __m128i {
        unsafe { _mm_loadu_si128(self.l.add(16 * ((lbase + j) & 7)) as *const __m128i) }
    }

    /// The current `ii` as a vector (`xored` with a base, e.g. `1J`).
    #[inline]
    #[target_feature(enable = "aes,sse2")]
    unsafe fn ii_xor(&self, base: __m128i) -> __m128i {
        unsafe {
            _mm_xor_si128(
                base,
                _mm_loadu_si128(self.ii.to_be_bytes().as_ptr() as *const __m128i),
            )
        }
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
#[target_feature(enable = "aes,sse2")]
#[allow(clippy::too_many_arguments)]
unsafe fn aez_pass1_n<const N: usize>(
    r: &mut AezRegs,
    k: &[__m128i; 4],
    i1: __m128i,
    jii: __m128i,
    tw: &AezTweaks,
    lbase: usize,
    p: *mut u8,
    x: &mut __m128i,
) {
    unsafe {
        for j in 0..N {
            r.m0[j] = _mm_loadu_si128(p.add(32 * j) as *const __m128i);
            r.m1[j] = _mm_loadu_si128(p.add(32 * j + 16) as *const __m128i);
            r.t[j] = _mm_xor_si128(_mm_xor_si128(r.m1[j], jii), tw.l(lbase, j));
        }
        aes4_n::<N>(&mut r.t, k);
        for j in 0..N {
            r.m0[j] = _mm_xor_si128(r.m0[j], r.t[j]);
            r.t[j] = _mm_xor_si128(r.m0[j], i1);
        }
        aes4_n::<N>(&mut r.t, k);
        for j in 0..N {
            r.m1[j] = _mm_xor_si128(r.m1[j], r.t[j]);
            *x = _mm_xor_si128(*x, r.m1[j]);
            _mm_storeu_si128(p.add(32 * j) as *mut __m128i, r.m0[j]);
            _mm_storeu_si128(p.add(32 * j + 16) as *mut __m128i, r.m1[j]);
        }
    }
}

#[cfg(feature = "aez")]
/// AEZ-core pass 2 over `N` pairs: with `t = E(2,i)(S)` (input
/// `sj2 ⊕ L[..]`, `sj2 = S ⊕ 2J ⊕ ii`), `o0 = m0 ⊕ t`, `o1 = m1 ⊕ t`,
/// `y ⊕= o0`, `o0 ⊕= E(0,0)(o1)`, `o1 ⊕= E(1,i)(o0)` (offset
/// `jii ⊕ L[..]`, `jii = 1J ⊕ ii`), the pair written back swapped (`o1 ‖ o0`).
#[inline]
#[target_feature(enable = "aes,sse2")]
#[allow(clippy::too_many_arguments)]
unsafe fn aez_pass2_n<const N: usize>(
    r: &mut AezRegs,
    k: &[__m128i; 4],
    i1: __m128i,
    jii: __m128i,
    sj2: __m128i,
    tw: &AezTweaks,
    lbase: usize,
    p: *mut u8,
    y: &mut __m128i,
) {
    unsafe {
        for j in 0..N {
            r.m0[j] = _mm_loadu_si128(p.add(32 * j) as *const __m128i);
            r.m1[j] = _mm_loadu_si128(p.add(32 * j + 16) as *const __m128i);
            r.t[j] = _mm_xor_si128(sj2, tw.l(lbase, j));
        }
        aes4_n::<N>(&mut r.t, k);
        for j in 0..N {
            r.m0[j] = _mm_xor_si128(r.m0[j], r.t[j]);
            r.m1[j] = _mm_xor_si128(r.m1[j], r.t[j]);
            *y = _mm_xor_si128(*y, r.m0[j]);
            r.t[j] = _mm_xor_si128(r.m1[j], i1);
        }
        aes4_n::<N>(&mut r.t, k);
        for j in 0..N {
            r.m0[j] = _mm_xor_si128(r.m0[j], r.t[j]);
            r.t[j] = _mm_xor_si128(_mm_xor_si128(r.m0[j], jii), tw.l(lbase, j));
        }
        aes4_n::<N>(&mut r.t, k);
        for j in 0..N {
            r.m1[j] = _mm_xor_si128(r.m1[j], r.t[j]);
            _mm_storeu_si128(p.add(32 * j) as *mut __m128i, r.m1[j]);
            _mm_storeu_si128(p.add(32 * j + 16) as *mut __m128i, r.m0[j]);
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
#[target_feature(enable = "aes,sse2")]
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
        let i1v = _mm_loadu_si128(i1.as_ptr() as *const __m128i);
        let j1v = _mm_loadu_si128(j1.as_ptr() as *const __m128i);
        let mut xv = _mm_loadu_si128(x.as_ptr() as *const __m128i);
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
        _mm_storeu_si128(x.as_mut_ptr() as *mut __m128i, xv);
        r.wipe();
        crate::zeroize::Zeroize::zeroize(&mut tw.ii);
    }
}

#[cfg(feature = "aez")]
/// AEZ-core pass 2 over the `npairs` pairs at `buf` (see [`aez_pass2_n`]);
/// `j2 = 2J`, `s` the `S` block, `y` the running `Y`, the rest as in
/// [`aez_pass1`].
#[inline(never)]
#[target_feature(enable = "aes,sse2")]
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
        let i1v = _mm_loadu_si128(i1.as_ptr() as *const __m128i);
        let j1v = _mm_loadu_si128(j1.as_ptr() as *const __m128i);
        let sj2v = _mm_xor_si128(
            _mm_loadu_si128(s.as_ptr() as *const __m128i),
            _mm_loadu_si128(j2.as_ptr() as *const __m128i),
        );
        let mut yv = _mm_loadu_si128(y.as_ptr() as *const __m128i);
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
        _mm_storeu_si128(y.as_mut_ptr() as *mut __m128i, yv);
        r.wipe();
        crate::zeroize::Zeroize::zeroize(&mut tw.ii);
    }
}
