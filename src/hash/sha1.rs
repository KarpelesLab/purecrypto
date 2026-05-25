//! SHA-1 (FIPS 180-4).
//!
//! Cryptographically broken for collision resistance (SHAttered); provided for
//! interoperability (TLS PRF legacy, Git, HMAC-SHA1, etc.). Avoid for new
//! signature schemes.

use super::Digest;
use super::block::{MdState, words_to_bytes_be};

const IV: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (word, chunk) in w.iter_mut().take(16).zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let tmp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// The SHA-1 hash function.
#[derive(Clone)]
pub struct Sha1 {
    state: MdState<5>,
}

impl Digest for Sha1 {
    type Output = [u8; 20];
    type Block = [u8; 64];
    const OUTPUT_LEN: usize = 20;
    const BLOCK_LEN: usize = 64;

    #[inline]
    fn new() -> Self {
        Sha1 {
            state: MdState::new(IV, true, compress),
        }
    }
    #[inline]
    fn zeroed_block() -> [u8; 64] {
        [0u8; 64]
    }
    #[inline]
    fn zeroed_output() -> [u8; 20] {
        [0u8; 20]
    }
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }
    #[inline]
    fn finalize(self) -> [u8; 20] {
        words_to_bytes_be(&self.state.finalize())
    }
    #[inline]
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

/// Computes the SHA-1 digest of `data`.
#[inline]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    #[test]
    fn fips_vectors() {
        assert_eq!(
            sha1(b""),
            from_hex::<20>("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(
            sha1(b"abc"),
            from_hex::<20>("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            from_hex::<20>("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        );
    }

    #[test]
    fn one_million_a() {
        let mut h = Sha1::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            h.finalize(),
            from_hex::<20>("34aa973cd4c4daa4f61eeb2bdbad27316534016f")
        );
    }
}
