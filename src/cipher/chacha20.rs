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
    out
}

/// A ChaCha20 cipher keyed with a 256-bit key.
#[derive(Clone)]
pub struct ChaCha20 {
    key: [u32; 8],
}

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
        let initial = self.state(nonce, counter);
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
        // On x86_64 with AVX2, generate the keystream eight blocks at a time
        // (ChaCha20 blocks are independent, so the 8-wide layout needs no
        // diagonal shuffles). Byte-identical to the scalar path.
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        if simd::supported() {
            simd::apply_keystream(&self.key, nonce, counter, buf);
            return;
        }
        let mut block_counter = counter;
        for block in buf.chunks_mut(64) {
            let ks = self.block(nonce, block_counter);
            for (b, k) in block.iter_mut().zip(ks.iter()) {
                *b ^= *k;
            }
            block_counter = block_counter.wrapping_add(1);
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
        std::is_x86_feature_detected!("avx2")
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
                let init = v;
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
                let mut words = [[0u32; 8]; 16];
                for i in 0..16 {
                    let added = _mm256_add_epi32(v[i], init[i]);
                    _mm256_storeu_si256(words[i].as_mut_ptr() as *mut __m256i, added);
                }
                // Emit up to eight 64-byte keystream blocks (lane = block) and
                // XOR the bytes still needed into `buf`.
                let avail = (buf.len() - off).min(512);
                let mut ks = [0u8; 512];
                for (b, blk) in ks.chunks_exact_mut(64).enumerate() {
                    for (i, word) in blk.chunks_exact_mut(4).enumerate() {
                        word.copy_from_slice(&words[i][b].to_le_bytes());
                    }
                }
                for (dst, k) in buf[off..off + avail].iter_mut().zip(ks.iter()) {
                    *dst ^= *k;
                }
                off += 512;
                ctr = ctr.wrapping_add(8);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

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
        if !super::simd::supported() {
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
                // SIMD path (the real apply_keystream).
                let mut simd = base.clone();
                c.apply_keystream(&nonce, ctr, &mut simd);
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
                assert_eq!(simd, scalar, "len={len} ctr={ctr}");
            }
        }
    }
}
