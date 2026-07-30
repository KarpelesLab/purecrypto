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

/// SHA-1 round constants, one per 20-round stage. Also used by the aarch64
/// hardware backend (the x86 `sha1rnds4` instruction embeds them itself).
pub(crate) const K1: [u32; 4] = [0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6];

/// SHA-1 compression function: folds a 64-byte block into the state.
///
/// Dispatches to the hardware SHA-1 instructions (SHA-NI on x86_64, `sha2` on
/// aarch64) when the CPU supports them, falling back to the portable software
/// path otherwise. Both produce identical state and are constant-time.
#[inline]
fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
    if super::sha_hw::sha1_supported() {
        super::sha_hw::compress_sha1(state, block);
        return;
    }
    compress_soft(state, block);
}

/// Compresses `data` (a whole number of 64-byte blocks) into the state.
///
/// Dispatches the entire run to the hardware backend in a single call when
/// available — the backend keeps the state in registers across all blocks,
/// avoiding the per-block spill/reload of repeated [`compress`] calls — and
/// otherwise loops the software compression.
#[inline]
fn compress_blocks(state: &mut [u32; 5], data: &[u8]) {
    debug_assert!(data.len().is_multiple_of(64));
    #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
    if super::sha_hw::sha1_supported() {
        super::sha_hw::compress_sha1_blocks(state, data);
        return;
    }
    for block in data.chunks_exact(64) {
        compress_soft(state, block.try_into().unwrap());
    }
}

/// Portable software SHA-1 compression (the constant-time fallback).
fn compress_soft(state: &mut [u32; 5], block: &[u8; 64]) {
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
            0..=19 => ((b & c) | (!b & d), K1[0]),
            20..=39 => (b ^ c ^ d, K1[1]),
            40..=59 => ((b & c) | (b & d) | (c & d), K1[2]),
            _ => (b ^ c ^ d, K1[3]),
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
            state: MdState::new_bulk(IV, true, compress, compress_blocks),
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

    /// The hardware SHA-1 compression must produce identical state to the
    /// software path for every block, across all initial-state / message
    /// combinations exercised here. Runs only where the extension exists.
    #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
    #[test]
    fn sha1_hardware_matches_software() {
        if !super::super::sha_hw::sha1_supported() {
            return;
        }
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..2000 {
            let mut h_sw = IV;
            for (j, v) in h_sw.iter_mut().enumerate() {
                if j % 3 == 0 {
                    *v = next() as u32;
                }
            }
            let h_hw = h_sw;
            let mut block = [0u8; 64];
            next(); // advance
            for b in block.iter_mut() {
                *b = (next() >> 24) as u8;
            }
            let mut a = h_sw;
            let mut b = h_hw;
            compress_soft(&mut a, &block);
            super::super::sha_hw::compress_sha1(&mut b, &block);
            assert_eq!(a, b, "HW/soft mismatch");
        }
        // Multi-block kernel: the register-resident `compress_sha1_blocks` over a
        // run of N blocks must equal looping `compress_soft` block-by-block, from
        // an arbitrary (non-IV) start state. Directly pins the cross-block
        // feed-forward in the multi-block path (on x86 that includes the
        // `sha1nexte`-based recovery of the carried `e`).
        for nblocks in [1usize, 2, 5, 16] {
            let mut start = IV;
            for v in start.iter_mut() {
                *v ^= next() as u32;
            }
            let mut blocks = alloc::vec![0u8; nblocks * 64];
            for b in blocks.iter_mut() {
                *b = (next() >> 24) as u8;
            }
            let mut h_hw = start;
            super::super::sha_hw::compress_sha1_blocks(&mut h_hw, &blocks);
            let mut h_sw = start;
            for chunk in blocks.chunks_exact(64) {
                compress_soft(&mut h_sw, chunk.try_into().unwrap());
            }
            assert_eq!(h_hw, h_sw, "multi-block HW/soft mismatch (n={nblocks})");
        }

        // Multi-block consistency through the public API vs a forced-software
        // recomputation: the dispatcher (HW here) must equal the soft digest.
        let data: alloc::vec::Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let hw = sha1(&data);
        // Recompute purely in software by feeding compress_soft directly.
        let mut h = IV;
        let mut buf = data.clone();
        let bitlen = (buf.len() as u64) * 8;
        buf.push(0x80);
        while buf.len() % 64 != 56 {
            buf.push(0);
        }
        buf.extend_from_slice(&bitlen.to_be_bytes());
        for chunk in buf.chunks_exact(64) {
            compress_soft(&mut h, chunk.try_into().unwrap());
        }
        let mut soft = [0u8; 20];
        for (o, w) in soft.chunks_exact_mut(4).zip(h.iter()) {
            o.copy_from_slice(&w.to_be_bytes());
        }
        assert_eq!(hw, soft, "dispatched digest must equal software digest");
    }

    /// Streaming through awkward chunk boundaries must match the one-shot digest,
    /// exercising the partial-block top-up around the bulk multi-block path.
    #[test]
    fn streaming_matches_oneshot() {
        let msg: &[u8] = b"The quick brown fox jumps over the lazy dog";
        let one = sha1(msg);
        let mut h = Sha1::new();
        for &byte in msg {
            h.update(&[byte]);
        }
        assert_eq!(h.finalize(), one);

        let big = [0x5au8; 200];
        let oneshot = sha1(&big);
        let mut h = Sha1::new();
        h.update(&big[..1]);
        h.update(&big[1..63]);
        h.update(&big[63..130]);
        h.update(&big[130..]);
        assert_eq!(h.finalize(), oneshot);
    }

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
