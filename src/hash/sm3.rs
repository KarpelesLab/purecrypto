//! SM3 (GB/T 32905-2016) — the Chinese national 256-bit hash.
//!
//! A Merkle–Damgård hash with 64-byte blocks and a big-endian length, so it
//! reuses [`block::MdState`] (8 × u32 state, like SHA-1 uses 5).

use super::Digest;
use super::block::{MdState, words_to_bytes_be};

const IV: [u32; 8] = [
    0x7380_166f,
    0x4914_b2b9,
    0x1724_42d7,
    0xda8a_0600,
    0xa96f_30bc,
    0x1631_38aa,
    0xe38d_ee4d,
    0xb0fb_0e4e,
];

#[inline]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}
#[inline]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    // Message expansion: W[0..68], W'[j] = W[j] ^ W[j+4].
    let mut w = [0u32; 68];
    for (word, chunk) in w.iter_mut().take(16).zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for j in 16..68 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
            ^ w[j - 13].rotate_left(7)
            ^ w[j - 6];
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for j in 0..64 {
        let tj: u32 = if j < 16 { 0x79cc_4519 } else { 0x7a87_9d8a };
        let a12 = a.rotate_left(12);
        let ss1 = a12
            .wrapping_add(e)
            .wrapping_add(tj.rotate_left(j as u32 % 32))
            .rotate_left(7);
        let ss2 = ss1 ^ a12;
        let (ffj, ggj) = if j < 16 {
            (a ^ b ^ c, e ^ f ^ g)
        } else {
            ((a & b) | (a & c) | (b & c), (e & f) | (!e & g))
        };
        let tt1 = ffj
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(w[j] ^ w[j + 4]);
        let tt2 = ggj.wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j]);
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

/// The SM3 hash function.
#[derive(Clone)]
pub struct Sm3 {
    state: MdState<8>,
}

impl Digest for Sm3 {
    type Output = [u8; 32];
    type Block = [u8; 64];
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;

    #[inline]
    fn new() -> Self {
        Sm3 {
            state: MdState::new(IV, true, compress),
        }
    }
    #[inline]
    fn zeroed_block() -> [u8; 64] {
        [0u8; 64]
    }
    #[inline]
    fn zeroed_output() -> [u8; 32] {
        [0u8; 32]
    }
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }
    #[inline]
    fn finalize(self) -> [u8; 32] {
        words_to_bytes_be(&self.state.finalize())
    }
    #[inline]
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

/// Computes the SM3 digest of `data`.
#[inline]
pub fn sm3(data: &[u8]) -> [u8; 32] {
    Sm3::digest(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // GB/T 32905 reference vectors (also cross-checked with `openssl dgst -sm3`).
    #[test]
    fn reference_vectors() {
        assert_eq!(
            sm3(b""),
            from_hex::<32>("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")
        );
        assert_eq!(
            sm3(b"abc"),
            from_hex::<32>("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
        );
        // 64 bytes ("abcd" × 16): forces a second padding block.
        assert_eq!(
            sm3(b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"),
            from_hex::<32>("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let msg = [0x61u8; 200];
        let oneshot = sm3(&msg);
        let mut h = Sm3::new();
        h.update(&msg[..1]);
        h.update(&msg[1..65]);
        h.update(&msg[65..]);
        assert_eq!(h.finalize(), oneshot);
    }
}
