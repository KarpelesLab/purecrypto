//! The ChaCha20 stream cipher (RFC 8439 §2.4).
//!
//! ChaCha20 expands a 256-bit key, a 96-bit nonce and a 32-bit block counter
//! into a 64-byte keystream block by running 20 rounds (ten "double rounds") of
//! the quarter-round function over a 4×4 matrix of 32-bit words. The cipher is
//! inherently constant time: it is built from 32-bit add/xor/rotate with no
//! secret-dependent branches or memory indexing.
//!
//! A given (key, nonce) pair must **never** be reused with overlapping counter
//! ranges: as with any stream cipher, keystream reuse destroys confidentiality.

/// The ChaCha20 constants — the ASCII string `"expand 32-byte k"` as four
/// little-endian words (RFC 8439 §2.3).
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// Best-effort wipe of the state matrix inside [`ChaCha20::block`].
///
/// Every ChaCha20 state matrix embeds the 256-bit key, and raw keystream is
/// key-equivalent for the bytes it covers — neither should be left behind in a
/// dead stack frame for a later caller to read.
///
/// This is deliberately **not** [`crate::zeroize::Zeroize`]: `block` runs once
/// per 64 bytes on the scalar path, and volatile stores are never merged into
/// the single vector store the plain assignment compiles to — measured at ~7%
/// of that kernel's throughput. `Zeroize`'s word-at-a-time path narrows the
/// gap but cannot close it, since this is per-block rather than per-operation.
/// Per-operation wipes elsewhere in the crate (including this cipher's own
/// one-time key and Poly1305 state) do use `Zeroize`.
#[inline]
fn wipe_words(w: &mut [u32; 16]) {
    *w = [0u32; 16];
    let _ = core::hint::black_box(w);
}

/// The ChaCha20 quarter-round on four words of the state (RFC 8439 §2.1).
#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// HChaCha20 (draft-irtf-cfrg-xchacha §2.2): a keyed hash producing a 256-bit
/// subkey from a 256-bit key and a 128-bit nonce. It runs the 20-round ChaCha20
/// permutation over `constants ‖ key ‖ nonce16` and returns the first and last
/// four state words **without** the final feed-forward addition. Used to derive
/// the per-message subkey in XChaCha20-Poly1305.
pub(crate) fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let mut s = [0u32; 16];
    s[0..4].copy_from_slice(&CONSTANTS);
    for (word, chunk) in s[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for (word, chunk) in s[12..16].iter_mut().zip(nonce16.chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    for _ in 0..10 {
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }

    let mut out = [0u8; 32];
    // Output words 0..=3 followed by 12..=15 (no final add).
    for (i, &idx) in [0usize, 1, 2, 3, 12, 13, 14, 15].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[idx].to_le_bytes());
    }
    // `s[4..12]` held the input key verbatim before the permutation and the
    // rest of the matrix is the subkey; neither belongs in a dead frame.
    wipe_words(&mut s);
    out
}

/// A ChaCha20 cipher keyed with a 256-bit key.
#[derive(Clone)]
pub struct ChaCha20 {
    key: [u32; 8],
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        // The whole state *is* the 256-bit key, so without this a retired
        // ChaCha20 traffic key (TLS 1.3 `KeyUpdate`, connection close) stays in
        // freed memory — where the AES-GCM `RecordCrypter` scrubs its round
        // keys and GHASH subkey. `Zeroize` gives volatile stores plus a
        // compiler fence, so LLVM cannot elide them as dead stores.
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for ChaCha20 {}

impl ChaCha20 {
    /// Creates a ChaCha20 cipher from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut k = [0u32; 8];
        for (word, chunk) in k.iter_mut().zip(key.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        ChaCha20 { key: k }
    }

    /// Builds the initial state matrix for a nonce and block counter.
    fn state(&self, nonce: &[u8; 12], counter: u32) -> [u32; 16] {
        let mut s = [0u32; 16];
        s[0..4].copy_from_slice(&CONSTANTS);
        s[4..12].copy_from_slice(&self.key);
        s[12] = counter;
        for (word, chunk) in s[13..16].iter_mut().zip(nonce.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        s
    }

    /// Generates the 64-byte keystream block for `(nonce, counter)`.
    pub fn block(&self, nonce: &[u8; 12], counter: u32) -> [u8; 64] {
        let mut initial = self.state(nonce, counter);
        let mut s = initial;
        // 20 rounds = 10 double-rounds (column rounds then diagonal rounds).
        for _ in 0..10 {
            quarter_round(&mut s, 0, 4, 8, 12);
            quarter_round(&mut s, 1, 5, 9, 13);
            quarter_round(&mut s, 2, 6, 10, 14);
            quarter_round(&mut s, 3, 7, 11, 15);
            quarter_round(&mut s, 0, 5, 10, 15);
            quarter_round(&mut s, 1, 6, 11, 12);
            quarter_round(&mut s, 2, 7, 8, 13);
            quarter_round(&mut s, 3, 4, 9, 14);
        }

        let mut out = [0u8; 64];
        for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
            let word = s[i].wrapping_add(initial[i]);
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        // `initial[4..12]` is the key; `s` is the pre-feed-forward state
        // (key-equivalent for this block).
        wipe_words(&mut initial);
        wipe_words(&mut s);
        out
    }

    /// XORs the keystream into `buf` in place, starting at block `counter`
    /// (RFC 8439 §2.4). The counter increments per 64-byte block.
    ///
    /// # Panics
    /// Panics if the requested operation would wrap the 32-bit block counter.
    /// RFC 8439 §2.4 caps a single ChaCha20 invocation at `2^32` blocks
    /// (256 GiB), and the AEAD wrapper at `2^32 − 1` (because counter 0 is
    /// reserved for the Poly1305 OTK). Wrapping would reuse keystream and
    /// catastrophically break confidentiality — fail loud rather than
    /// silently produce a two-time pad.
    pub fn apply_keystream(&self, nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        let blocks_needed = buf.len().div_ceil(64) as u64;
        let counter_end = (counter as u64) + blocks_needed;
        assert!(
            counter_end <= u64::from(u32::MAX) + 1,
            "ChaCha20 counter would overflow 2^32 (buf too large for a single invocation)"
        );
        // On x86_64, generate the keystream many blocks at a time — ChaCha20
        // blocks are independent, so the wide layout needs no diagonal
        // shuffles. AVX-512 does sixteen blocks per pass, AVX2 eight; both are
        // byte-identical to the scalar path.
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        if simd512::supported() {
            simd512::apply_keystream(&self.key, nonce, counter, buf);
            return;
        }
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        if simd::supported() {
            simd::apply_keystream(&self.key, nonce, counter, buf);
            return;
        }
        // On aarch64 NEON is part of the baseline ISA, so the 2×4-way kernel
        // is the normal path with no runtime probe. It hands back a tail of
        // under two blocks, where a 4-wide pass would mostly compute
        // discarded blocks, to the scalar loop below — which also remains the
        // whole path for buffers that short (single-block callers such as
        // the Poly1305 OTK derivation never enter the kernel) and in the
        // constant-time harness's forced-portable mode.
        #[cfg(target_arch = "aarch64")]
        let (done, mut block_counter) = if buf.len() >= 128 && neon::supported() {
            neon::apply_keystream(&self.key, nonce, counter, buf)
        } else {
            (0, counter)
        };
        #[cfg(not(target_arch = "aarch64"))]
        let (done, mut block_counter) = (0, counter);
        for block in buf[done..].chunks_mut(64) {
            let mut ks = self.block(nonce, block_counter);
            for (b, k) in block.iter_mut().zip(ks.iter()) {
                *b ^= *k;
            }
            // Don't leave raw keystream for this key in the stack frame — this
            // runs on every ChaCha20 / ChaCha20-Poly1305 operation. Per-block
            // inner loop, so not `Zeroize` (see `wipe_words`).
            ks = [0u8; 64];
            let _ = core::hint::black_box(&ks);
            block_counter = block_counter.wrapping_add(1);
        }
    }
}

/// AVX-512 16-way ChaCha20 keystream (x86_64). Same shape as the AVX2 kernel
/// below, with each of the 16 state words held in a `__m512i` lane-per-block
/// across sixteen consecutive counters, so one pass emits 1 KiB of keystream.
///
/// Two AVX-512 instructions do real work here beyond the doubled width:
/// `vprold` rotates in one instruction where AVX2 needs a shift/shift/or trio,
/// which matters because ChaCha20 is four rotates per quarter-round and nothing
/// else. Pinned byte-for-byte against the scalar path by a differential test.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod simd512 {
    use super::CONSTANTS;
    use core::arch::x86_64::*;

    pub(super) fn supported() -> bool {
        !crate::ct::force_portable() && std::is_x86_feature_detected!("avx512f")
    }

    /// Rotate-left each 32-bit lane by `N` — a single `vprold`.
    #[inline(always)]
    unsafe fn rol<const N: i32>(x: __m512i) -> __m512i {
        unsafe { _mm512_rol_epi32::<N>(x) }
    }

    #[inline(always)]
    unsafe fn qr(v: &mut [__m512i; 16], a: usize, b: usize, c: usize, d: usize) {
        unsafe {
            v[a] = _mm512_add_epi32(v[a], v[b]);
            v[d] = rol::<16>(_mm512_xor_si512(v[d], v[a]));
            v[c] = _mm512_add_epi32(v[c], v[d]);
            v[b] = rol::<12>(_mm512_xor_si512(v[b], v[c]));
            v[a] = _mm512_add_epi32(v[a], v[b]);
            v[d] = rol::<8>(_mm512_xor_si512(v[d], v[a]));
            v[c] = _mm512_add_epi32(v[c], v[d]);
            v[b] = rol::<7>(_mm512_xor_si512(v[b], v[c]));
        }
    }

    pub(super) fn apply_keystream(key: &[u32; 8], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        // SAFETY: `supported()` (checked by the caller) confirmed AVX-512F.
        unsafe { apply_keystream_avx512(key, nonce, counter, buf) }
    }

    #[target_feature(enable = "avx512f")]
    unsafe fn apply_keystream_avx512(
        key: &[u32; 8],
        nonce: &[u8; 12],
        counter: u32,
        buf: &mut [u8],
    ) {
        unsafe {
            let n =
                |o: usize| u32::from_le_bytes([nonce[o], nonce[o + 1], nonce[o + 2], nonce[o + 3]]);
            let (n0, n1, n2) = (n(0), n(4), n(8));
            #[rustfmt::skip]
            let lanes = _mm512_setr_epi32(
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            );

            let mut ctr = counter;
            let mut off = 0usize;
            // Hoisted out of the loop so one wipe at the end covers them; they
            // are fully overwritten every pass.
            let mut words = [[0u32; 16]; 16];
            let mut ks = [0u8; 1024];
            while off < buf.len() {
                let mut v = [
                    _mm512_set1_epi32(CONSTANTS[0] as i32),
                    _mm512_set1_epi32(CONSTANTS[1] as i32),
                    _mm512_set1_epi32(CONSTANTS[2] as i32),
                    _mm512_set1_epi32(CONSTANTS[3] as i32),
                    _mm512_set1_epi32(key[0] as i32),
                    _mm512_set1_epi32(key[1] as i32),
                    _mm512_set1_epi32(key[2] as i32),
                    _mm512_set1_epi32(key[3] as i32),
                    _mm512_set1_epi32(key[4] as i32),
                    _mm512_set1_epi32(key[5] as i32),
                    _mm512_set1_epi32(key[6] as i32),
                    _mm512_set1_epi32(key[7] as i32),
                    _mm512_add_epi32(_mm512_set1_epi32(ctr as i32), lanes),
                    _mm512_set1_epi32(n0 as i32),
                    _mm512_set1_epi32(n1 as i32),
                    _mm512_set1_epi32(n2 as i32),
                ];
                let mut init = v;
                for _ in 0..10 {
                    qr(&mut v, 0, 4, 8, 12);
                    qr(&mut v, 1, 5, 9, 13);
                    qr(&mut v, 2, 6, 10, 14);
                    qr(&mut v, 3, 7, 11, 15);
                    qr(&mut v, 0, 5, 10, 15);
                    qr(&mut v, 1, 6, 11, 12);
                    qr(&mut v, 2, 7, 8, 13);
                    qr(&mut v, 3, 4, 9, 14);
                }
                for i in 0..16 {
                    let added = _mm512_add_epi32(v[i], init[i]);
                    _mm512_storeu_si512(words[i].as_mut_ptr() as *mut _, added);
                }
                // Emit up to sixteen 64-byte keystream blocks (lane = block) and
                // XOR the bytes still needed into `buf`.
                let avail = (buf.len() - off).min(1024);
                for (b, blk) in ks.chunks_exact_mut(64).enumerate() {
                    for (i, word) in blk.chunks_exact_mut(4).enumerate() {
                        word.copy_from_slice(&words[i][b].to_le_bytes());
                    }
                }
                for (dst, k) in buf[off..off + avail].iter_mut().zip(ks.iter()) {
                    *dst ^= *k;
                }
                // `init[4..12]` is the key broadcast across lanes and `v` the
                // pre-feed-forward state; both are loop-scoped, so scrub them
                // here rather than trusting the register allocator not to have
                // spilled them.
                for (a, b) in v.iter_mut().zip(init.iter_mut()) {
                    *a = _mm512_setzero_si512();
                    *b = _mm512_setzero_si512();
                }
                let _ = core::hint::black_box(&v);
                let _ = core::hint::black_box(&init);
                off += 1024;
                ctr = ctr.wrapping_add(16);
            }
            // Don't leave raw keystream for this key in the stack frame — this
            // runs on every ChaCha20 / ChaCha20-Poly1305 operation. `words`
            // and `ks` are the same 1 KiB of keystream in two layouts.
            //
            // Not `Zeroize`: that is ~2 KiB of per-byte volatile stores on
            // *every* call regardless of payload size (measured ~1% at 64 KiB,
            // proportionally far worse on small TLS/QUIC records), so this
            // bulk-cipher path keeps the vector store plus `black_box` barrier.
            words = [[0u32; 16]; 16];
            ks = [0u8; 1024];
            let _ = core::hint::black_box(&words);
            let _ = core::hint::black_box(&ks);
        }
    }
}

/// AVX2 8-way ChaCha20 keystream (x86_64). Each of the 16 state words is held in
/// a `__m256i` lane-per-block across eight consecutive block counters; the
/// quarter-round indices are identical to the scalar path (independent blocks =
/// no diagonalization). Pinned byte-for-byte by a differential test.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod simd {
    use super::CONSTANTS;
    use core::arch::x86_64::*;

    pub(super) fn supported() -> bool {
        !crate::ct::force_portable() && std::is_x86_feature_detected!("avx2")
    }

    /// Rotate-left each 32-bit lane by `N` (with `M = 32 - N`).
    #[inline(always)]
    unsafe fn rol<const N: i32, const M: i32>(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_slli_epi32::<N>(x), _mm256_srli_epi32::<M>(x)) }
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    unsafe fn qr(v: &mut [__m256i; 16], a: usize, b: usize, c: usize, d: usize) {
        unsafe {
            v[a] = _mm256_add_epi32(v[a], v[b]);
            v[d] = rol::<16, 16>(_mm256_xor_si256(v[d], v[a]));
            v[c] = _mm256_add_epi32(v[c], v[d]);
            v[b] = rol::<12, 20>(_mm256_xor_si256(v[b], v[c]));
            v[a] = _mm256_add_epi32(v[a], v[b]);
            v[d] = rol::<8, 24>(_mm256_xor_si256(v[d], v[a]));
            v[c] = _mm256_add_epi32(v[c], v[d]);
            v[b] = rol::<7, 25>(_mm256_xor_si256(v[b], v[c]));
        }
    }

    pub(super) fn apply_keystream(key: &[u32; 8], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        // SAFETY: `supported()` (checked by the caller) confirmed AVX2.
        unsafe { apply_keystream_avx2(key, nonce, counter, buf) }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn apply_keystream_avx2(key: &[u32; 8], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        unsafe {
            let n =
                |o: usize| u32::from_le_bytes([nonce[o], nonce[o + 1], nonce[o + 2], nonce[o + 3]]);
            let (n0, n1, n2) = (n(0), n(4), n(8));
            let lanes = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);

            let mut ctr = counter;
            let mut off = 0usize;
            // Hoisted out of the loop so one wipe at the end covers them; they
            // are fully overwritten every pass.
            let mut words = [[0u32; 8]; 16];
            let mut ks = [0u8; 512];
            while off < buf.len() {
                let mut v = [
                    _mm256_set1_epi32(CONSTANTS[0] as i32),
                    _mm256_set1_epi32(CONSTANTS[1] as i32),
                    _mm256_set1_epi32(CONSTANTS[2] as i32),
                    _mm256_set1_epi32(CONSTANTS[3] as i32),
                    _mm256_set1_epi32(key[0] as i32),
                    _mm256_set1_epi32(key[1] as i32),
                    _mm256_set1_epi32(key[2] as i32),
                    _mm256_set1_epi32(key[3] as i32),
                    _mm256_set1_epi32(key[4] as i32),
                    _mm256_set1_epi32(key[5] as i32),
                    _mm256_set1_epi32(key[6] as i32),
                    _mm256_set1_epi32(key[7] as i32),
                    _mm256_add_epi32(_mm256_set1_epi32(ctr as i32), lanes),
                    _mm256_set1_epi32(n0 as i32),
                    _mm256_set1_epi32(n1 as i32),
                    _mm256_set1_epi32(n2 as i32),
                ];
                let mut init = v;
                for _ in 0..10 {
                    qr(&mut v, 0, 4, 8, 12);
                    qr(&mut v, 1, 5, 9, 13);
                    qr(&mut v, 2, 6, 10, 14);
                    qr(&mut v, 3, 7, 11, 15);
                    qr(&mut v, 0, 5, 10, 15);
                    qr(&mut v, 1, 6, 11, 12);
                    qr(&mut v, 2, 7, 8, 13);
                    qr(&mut v, 3, 4, 9, 14);
                }
                for i in 0..16 {
                    let added = _mm256_add_epi32(v[i], init[i]);
                    _mm256_storeu_si256(words[i].as_mut_ptr() as *mut __m256i, added);
                }
                // Emit up to eight 64-byte keystream blocks (lane = block) and
                // XOR the bytes still needed into `buf`.
                let avail = (buf.len() - off).min(512);
                for (b, blk) in ks.chunks_exact_mut(64).enumerate() {
                    for (i, word) in blk.chunks_exact_mut(4).enumerate() {
                        word.copy_from_slice(&words[i][b].to_le_bytes());
                    }
                }
                for (dst, k) in buf[off..off + avail].iter_mut().zip(ks.iter()) {
                    *dst ^= *k;
                }
                // See the AVX-512 kernel: scrub the key-bearing vectors.
                for (a, b) in v.iter_mut().zip(init.iter_mut()) {
                    *a = _mm256_setzero_si256();
                    *b = _mm256_setzero_si256();
                }
                let _ = core::hint::black_box(&v);
                let _ = core::hint::black_box(&init);
                off += 512;
                ctr = ctr.wrapping_add(8);
            }
            // Don't leave raw keystream for this key in the stack frame — this
            // runs on every ChaCha20 / ChaCha20-Poly1305 operation. Not
            // `Zeroize`, for the per-call cost noted in the AVX-512 kernel.
            words = [[0u32; 8]; 16];
            ks = [0u8; 512];
            let _ = core::hint::black_box(&words);
            let _ = core::hint::black_box(&ks);
        }
    }
}

/// NEON 4-way ChaCha20 keystream (aarch64), two independent 4-block sets per
/// pass so one set's eight quarter-round dependency chains overlap with the
/// other's. Each of the 16 state words is a `uint32x4_t` holding one
/// consecutive block counter per lane, so the quarter-round indices are the
/// scalar ones and no diagonalisation is needed; the lane-to-block transpose
/// at the end is two `trn1`/`trn2` levels per 4-word group.
///
/// Rotations: `<<< 16` is a `rev32.16` (swap halves), `<<< 8` a byte shuffle
/// (`tbl`), and `<<< 12` / `<<< 7` a shift plus shift-right-insert (`sri`),
/// two instructions instead of the shift/shift/or trio. NEON is in the
/// aarch64 baseline, so there is no runtime feature probe and the module
/// builds for `no_std`. Pinned byte-for-byte to the scalar path by a
/// differential test over every length in `0..=1024` and beyond.
#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
mod neon {
    use super::CONSTANTS;
    use core::arch::aarch64::*;

    pub(super) fn supported() -> bool {
        !crate::ct::force_portable()
    }

    #[inline(always)]
    unsafe fn rot16(x: uint32x4_t) -> uint32x4_t {
        unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x))) }
    }

    #[inline(always)]
    unsafe fn rot12(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<20>(vshlq_n_u32::<12>(x), x) }
    }

    #[inline(always)]
    unsafe fn rot8(x: uint32x4_t, tbl: uint8x16_t) -> uint32x4_t {
        unsafe { vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), tbl)) }
    }

    #[inline(always)]
    unsafe fn rot7(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<25>(vshlq_n_u32::<7>(x), x) }
    }

    #[inline(always)]
    unsafe fn qr(
        v: &mut [uint32x4_t; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        tbl: uint8x16_t,
    ) {
        unsafe {
            v[a] = vaddq_u32(v[a], v[b]);
            v[d] = rot16(veorq_u32(v[d], v[a]));
            v[c] = vaddq_u32(v[c], v[d]);
            v[b] = rot12(veorq_u32(v[b], v[c]));
            v[a] = vaddq_u32(v[a], v[b]);
            v[d] = rot8(veorq_u32(v[d], v[a]), tbl);
            v[c] = vaddq_u32(v[c], v[d]);
            v[b] = rot7(veorq_u32(v[b], v[c]));
        }
    }

    /// One double round (column round, then diagonal round) on a 4-block set.
    #[inline(always)]
    unsafe fn double_round(v: &mut [uint32x4_t; 16], tbl: uint8x16_t) {
        unsafe {
            qr(v, 0, 4, 8, 12, tbl);
            qr(v, 1, 5, 9, 13, tbl);
            qr(v, 2, 6, 10, 14, tbl);
            qr(v, 3, 7, 11, 15, tbl);
            qr(v, 0, 5, 10, 15, tbl);
            qr(v, 1, 6, 11, 12, tbl);
            qr(v, 2, 7, 8, 13, tbl);
            qr(v, 3, 4, 9, 14, tbl);
        }
    }

    /// The initial state for blocks `ctr .. ctr + 4`, lane = block.
    #[inline(always)]
    unsafe fn init4(key: &[u32; 8], n: &[u32; 3], ctr: u32) -> [uint32x4_t; 16] {
        unsafe {
            let lanes = vld1q_u32([0u32, 1, 2, 3].as_ptr());
            [
                vdupq_n_u32(CONSTANTS[0]),
                vdupq_n_u32(CONSTANTS[1]),
                vdupq_n_u32(CONSTANTS[2]),
                vdupq_n_u32(CONSTANTS[3]),
                vdupq_n_u32(key[0]),
                vdupq_n_u32(key[1]),
                vdupq_n_u32(key[2]),
                vdupq_n_u32(key[3]),
                vdupq_n_u32(key[4]),
                vdupq_n_u32(key[5]),
                vdupq_n_u32(key[6]),
                vdupq_n_u32(key[7]),
                vaddq_u32(vdupq_n_u32(ctr), lanes),
                vdupq_n_u32(n[0]),
                vdupq_n_u32(n[1]),
                vdupq_n_u32(n[2]),
            ]
        }
    }

    /// Feed-forward, transpose lane-major into four 64-byte blocks, and either
    /// XOR them into `p` (`XOR`) or store the raw keystream there. `p` must
    /// address 256 writable bytes.
    #[inline(always)]
    unsafe fn emit4<const XOR: bool>(v: &[uint32x4_t; 16], init: &[uint32x4_t; 16], p: *mut u8) {
        unsafe {
            for g in 0..4 {
                let w0 = vaddq_u32(v[4 * g], init[4 * g]);
                let w1 = vaddq_u32(v[4 * g + 1], init[4 * g + 1]);
                let w2 = vaddq_u32(v[4 * g + 2], init[4 * g + 2]);
                let w3 = vaddq_u32(v[4 * g + 3], init[4 * g + 3]);
                // 4×4 transpose of 32-bit lanes: row i = words 4g..4g+4 of
                // block i.
                let t0 = vreinterpretq_u64_u32(vtrn1q_u32(w0, w1));
                let t1 = vreinterpretq_u64_u32(vtrn2q_u32(w0, w1));
                let t2 = vreinterpretq_u64_u32(vtrn1q_u32(w2, w3));
                let t3 = vreinterpretq_u64_u32(vtrn2q_u32(w2, w3));
                let rows = [
                    vreinterpretq_u8_u64(vtrn1q_u64(t0, t2)),
                    vreinterpretq_u8_u64(vtrn1q_u64(t1, t3)),
                    vreinterpretq_u8_u64(vtrn2q_u64(t0, t2)),
                    vreinterpretq_u8_u64(vtrn2q_u64(t1, t3)),
                ];
                for (i, r) in rows.iter().enumerate() {
                    let q = p.add(64 * i + 16 * g);
                    if XOR {
                        vst1q_u8(q, veorq_u8(vld1q_u8(q), *r));
                    } else {
                        vst1q_u8(q, *r);
                    }
                }
            }
        }
    }

    /// Scrubs a key-bearing state set: `init[4..12]` is the key broadcast
    /// across lanes and `v` the pre-feed-forward state (key-equivalent).
    #[inline(always)]
    unsafe fn wipe(v: &mut [uint32x4_t; 16], init: &mut [uint32x4_t; 16]) {
        unsafe {
            for (a, b) in v.iter_mut().zip(init.iter_mut()) {
                *a = vdupq_n_u32(0);
                *b = vdupq_n_u32(0);
            }
            let _ = core::hint::black_box(&*v);
            let _ = core::hint::black_box(&*init);
        }
    }

    /// Applies the keystream to as much of `buf` as the wide kernels cover
    /// and returns `(bytes done, next block counter)`. The remainder is
    /// under 128 bytes, left for the caller's scalar loop (for a tail that
    /// short, a 4-wide pass would mostly compute discarded blocks).
    pub(super) fn apply_keystream(
        key: &[u32; 8],
        nonce: &[u8; 12],
        counter: u32,
        buf: &mut [u8],
    ) -> (usize, u32) {
        // SAFETY: NEON is a baseline feature of every aarch64 target, and the
        // kernel's pointer arithmetic stays inside `buf` and its own scratch.
        unsafe { apply_keystream_neon(key, nonce, counter, buf) }
    }

    #[target_feature(enable = "neon")]
    unsafe fn apply_keystream_neon(
        key: &[u32; 8],
        nonce: &[u8; 12],
        counter: u32,
        buf: &mut [u8],
    ) -> (usize, u32) {
        unsafe {
            let n =
                |o: usize| u32::from_le_bytes([nonce[o], nonce[o + 1], nonce[o + 2], nonce[o + 3]]);
            let n = [n(0), n(4), n(8)];
            #[rustfmt::skip]
            let tbl = vld1q_u8([3u8, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14].as_ptr());

            let mut ctr = counter;
            let mut off = 0usize;
            let base = buf.as_mut_ptr();
            let len = buf.len();

            // The two state sets live outside the loops so that one wipe at
            // the end covers them; every pass fully overwrites them.
            let mut ia = [vdupq_n_u32(0); 16];
            let mut ib = [vdupq_n_u32(0); 16];
            let mut a = ia;
            let mut b = ib;

            // Eight blocks per pass: two independent 4-block sets whose round
            // computations interleave.
            while off + 512 <= len {
                ia = init4(key, &n, ctr);
                ib = init4(key, &n, ctr.wrapping_add(4));
                a = ia;
                b = ib;
                for _ in 0..10 {
                    double_round(&mut a, tbl);
                    double_round(&mut b, tbl);
                }
                emit4::<true>(&a, &ia, base.add(off));
                emit4::<true>(&b, &ib, base.add(off + 256));
                off += 512;
                ctr = ctr.wrapping_add(8);
            }
            // One more full 4-block set, if it fits.
            if off + 256 <= len {
                ia = init4(key, &n, ctr);
                a = ia;
                for _ in 0..10 {
                    double_round(&mut a, tbl);
                }
                emit4::<true>(&a, &ia, base.add(off));
                off += 256;
                ctr = ctr.wrapping_add(4);
            }
            // Tail of 128..256 bytes: generate a 4-block set into scratch and
            // XOR what is needed. Blocks past the end of `buf` are computed
            // and discarded, so the counter wrap they could incur is harmless.
            if off + 128 <= len {
                ia = init4(key, &n, ctr);
                a = ia;
                for _ in 0..10 {
                    double_round(&mut a, tbl);
                }
                let mut ks = [0u8; 256];
                emit4::<false>(&a, &ia, ks.as_mut_ptr());
                let used = len - off;
                for (dst, k) in buf[off..].iter_mut().zip(ks.iter()) {
                    *dst ^= *k;
                }
                // Raw keystream for this key: same `black_box` barrier as the
                // scalar path (per-call, so not `Zeroize` — see `wipe_words`).
                ks = [0u8; 256];
                let _ = core::hint::black_box(&ks);
                off = len;
                ctr = ctr.wrapping_add(used.div_ceil(64) as u32);
            }
            wipe(&mut a, &mut ia);
            // The second set is only written by the 8-way loop (a public
            // length condition).
            if len >= 512 {
                wipe(&mut b, &mut ib);
            }
            (off, ctr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// The NEON 2×4-way keystream must equal the scalar block path for every
    /// length in `0..=1024` (partial blocks, partial 4- and 8-block groups)
    /// plus larger buffers, across counter values near the 32-bit boundary.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn neon_matches_scalar() {
        use alloc::vec::Vec;
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(3));
        let c = ChaCha20::new(&key);
        for len in (0usize..=1024).chain([1500, 4096 + 7, 65536 + 33]) {
            for &ctr in &[0u32, 1, 100, u32::MAX - 20] {
                if (ctr as u64) + (len.div_ceil(64) as u64) > u64::from(u32::MAX) + 1 {
                    continue;
                }
                let base: Vec<u8> = (0..len).map(|i| (i * 31 + 9) as u8).collect();
                let mut scalar = base.clone();
                let mut bc = ctr;
                for block in scalar.chunks_mut(64) {
                    let ks = c.block(&nonce, bc);
                    for (b, k) in block.iter_mut().zip(ks.iter()) {
                        *b ^= *k;
                    }
                    bc = bc.wrapping_add(1);
                }
                // The kernel directly, with its scalar-finished tail: it must
                // report the right resume point and leave under 128 bytes.
                let mut w = base.clone();
                let (done, mut next) = super::neon::apply_keystream(&c.key, &nonce, ctr, &mut w);
                assert!(len - done < 128, "neon tail len={len} done={done}");
                assert_eq!(next, ctr.wrapping_add(done.div_ceil(64) as u32));
                for block in w[done..].chunks_mut(64) {
                    let ks = c.block(&nonce, next);
                    for (b, k) in block.iter_mut().zip(ks.iter()) {
                        *b ^= *k;
                    }
                    next = next.wrapping_add(1);
                }
                assert_eq!(w, scalar, "neon len={len} ctr={ctr}");
                let mut d = base.clone();
                c.apply_keystream(&nonce, ctr, &mut d);
                assert_eq!(d, scalar, "dispatch len={len} ctr={ctr}");
            }
        }
    }

    #[test]
    fn rfc8439_block_function() {
        // RFC 8439 §2.3.2.
        let key =
            from_hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = from_hex::<12>("000000090000004a00000000");
        let c = ChaCha20::new(&key);
        let block = c.block(&nonce, 1);
        assert_eq!(
            block,
            from_hex::<64>(
                "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
                 d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
            )
        );
    }

    #[test]
    fn xchacha_draft_hchacha20() {
        // draft-irtf-cfrg-xchacha §2.2.1 test vector.
        let key =
            from_hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = from_hex::<16>("000000090000004a0000000031415927");
        let out = hchacha20(&key, &nonce);
        assert_eq!(
            out,
            from_hex::<32>("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
        );
    }

    #[test]
    fn rfc8439_encryption() {
        // RFC 8439 §2.4.2: encrypt the sunscreen plaintext at initial counter 1.
        let key =
            from_hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = from_hex::<12>("000000000000004a00000000");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
        let mut buf = plaintext.to_vec();
        ChaCha20::new(&key).apply_keystream(&nonce, 1, &mut buf);
        let expected = from_hex::<114>(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );
        assert_eq!(buf, expected);

        // Keystream is its own inverse: re-applying recovers the plaintext.
        ChaCha20::new(&key).apply_keystream(&nonce, 1, &mut buf);
        assert_eq!(buf, plaintext);
    }

    /// The AVX2 8-way keystream must equal the scalar block path for every
    /// length, including partial blocks and partial 8-block groups, and across
    /// a counter value near the 32-bit boundary.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn simd_matches_scalar() {
        use alloc::vec::Vec;
        // Exercise *each* wide kernel against the scalar path, rather than
        // whichever one `apply_keystream` happens to select: on an AVX-512 host
        // the dispatcher never reaches the AVX2 kernel, so going through it
        // would leave the 8-wide path untested there (and vice versa).
        let mut ran_any = false;
        if super::simd::supported() {
            std::eprintln!("chacha20: RUNNING avx2 8-wide kernel vs scalar");
            ran_any = true;
        } else {
            std::eprintln!("chacha20: SKIPPED avx2 (no AVX2 on this CPU)");
        }
        if super::simd512::supported() {
            std::eprintln!("chacha20: RUNNING avx512 16-wide kernel vs scalar");
            ran_any = true;
        } else {
            std::eprintln!("chacha20: SKIPPED avx512 (no AVX-512F on this CPU)");
        }
        if !ran_any {
            return;
        }
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(3));
        let c = ChaCha20::new(&key);
        for &len in &[
            0usize,
            1,
            63,
            64,
            65,
            200,
            511,
            512,
            513,
            1024,
            1500,
            4096 + 7,
        ] {
            for &ctr in &[0u32, 1, 100, u32::MAX - 20] {
                // Skip combinations that would legitimately overflow the counter.
                if (ctr as u64) + (len.div_ceil(64) as u64) > u64::from(u32::MAX) + 1 {
                    continue;
                }
                let base: Vec<u8> = (0..len).map(|i| (i * 31 + 9) as u8).collect();
                // Scalar reference, block by block.
                let mut scalar = base.clone();
                let mut bc = ctr;
                for block in scalar.chunks_mut(64) {
                    let ks = c.block(&nonce, bc);
                    for (b, k) in block.iter_mut().zip(ks.iter()) {
                        *b ^= *k;
                    }
                    bc = bc.wrapping_add(1);
                }
                // Each wide kernel, called directly.
                if super::simd::supported() {
                    let mut w = base.clone();
                    super::simd::apply_keystream(&c.key, &nonce, ctr, &mut w);
                    assert_eq!(w, scalar, "avx2 len={len} ctr={ctr}");
                }
                if super::simd512::supported() {
                    let mut w = base.clone();
                    super::simd512::apply_keystream(&c.key, &nonce, ctr, &mut w);
                    assert_eq!(w, scalar, "avx512 len={len} ctr={ctr}");
                }
                // ...and the dispatcher, which must agree with both.
                let mut simd = base.clone();
                c.apply_keystream(&nonce, ctr, &mut simd);
                assert_eq!(simd, scalar, "dispatch len={len} ctr={ctr}");
            }
        }
    }
}
