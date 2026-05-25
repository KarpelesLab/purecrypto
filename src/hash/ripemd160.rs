//! RIPEMD-160 (Dobbertin–Bosselaers–Preneel, 1996).
//!
//! A 160-bit hash built from two parallel 80-step lines. Still used in Bitcoin
//! addresses (`HASH160 = RIPEMD160(SHA-256(x))`).

use super::Digest;
use super::block::{MdState, block_words_le, words_to_bytes_le};

const IV: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// Round constants for the left and right lines (one per 16-step round).
const KL: [u32; 5] = [
    0x0000_0000,
    0x5a82_7999,
    0x6ed9_eba1,
    0x8f1b_bcdc,
    0xa953_fd4e,
];
const KR: [u32; 5] = [
    0x50a2_8be6,
    0x5c4d_d124,
    0x6d70_3ef3,
    0x7a6d_76e9,
    0x0000_0000,
];

/// Message-word selection for the left and right lines.
#[rustfmt::skip]
const RL: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
#[rustfmt::skip]
const RR: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

/// Left/right rotation amounts.
#[rustfmt::skip]
const SL: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
#[rustfmt::skip]
const SR: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

/// The five nonlinear functions, indexed by round (0..=4).
#[inline]
fn boolfn(round: usize, x: u32, y: u32, z: u32) -> u32 {
    match round {
        0 => x ^ y ^ z,
        1 => (x & y) | (!x & z),
        2 => (x | !y) ^ z,
        3 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let x = block_words_le(block);
    let (mut al, mut bl, mut cl, mut dl, mut el) =
        (state[0], state[1], state[2], state[3], state[4]);
    let (mut ar, mut br, mut cr, mut dr, mut er) =
        (state[0], state[1], state[2], state[3], state[4]);

    for j in 0..80 {
        let round = j / 16;

        let tl = al
            .wrapping_add(boolfn(round, bl, cl, dl))
            .wrapping_add(x[RL[j]])
            .wrapping_add(KL[round])
            .rotate_left(SL[j])
            .wrapping_add(el);
        al = el;
        el = dl;
        dl = cl.rotate_left(10);
        cl = bl;
        bl = tl;

        let tr = ar
            .wrapping_add(boolfn(4 - round, br, cr, dr))
            .wrapping_add(x[RR[j]])
            .wrapping_add(KR[round])
            .rotate_left(SR[j])
            .wrapping_add(er);
        ar = er;
        er = dr;
        dr = cr.rotate_left(10);
        cr = br;
        br = tr;
    }

    let t = state[1].wrapping_add(cl).wrapping_add(dr);
    state[1] = state[2].wrapping_add(dl).wrapping_add(er);
    state[2] = state[3].wrapping_add(el).wrapping_add(ar);
    state[3] = state[4].wrapping_add(al).wrapping_add(br);
    state[4] = state[0].wrapping_add(bl).wrapping_add(cr);
    state[0] = t;
}

/// The RIPEMD-160 hash function.
#[derive(Clone)]
pub struct Ripemd160 {
    state: MdState<5>,
}

impl Digest for Ripemd160 {
    type Output = [u8; 20];
    type Block = [u8; 64];
    const OUTPUT_LEN: usize = 20;
    const BLOCK_LEN: usize = 64;

    #[inline]
    fn new() -> Self {
        Ripemd160 {
            state: MdState::new(IV, false, compress),
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
        words_to_bytes_le(&self.state.finalize())
    }
}

/// Computes the RIPEMD-160 digest of `data`.
#[inline]
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // Official RIPEMD-160 test vectors.
    #[test]
    fn reference_vectors() {
        assert_eq!(
            ripemd160(b""),
            from_hex::<20>("9c1185a5c5e9fc54612808977ee8f548b2258d31")
        );
        assert_eq!(
            ripemd160(b"abc"),
            from_hex::<20>("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        );
        assert_eq!(
            ripemd160(b"message digest"),
            from_hex::<20>("5d0689ef49d2fae572b881b123a85ffa21595f36")
        );
        assert_eq!(
            ripemd160(b"abcdefghijklmnopqrstuvwxyz"),
            from_hex::<20>("f71c27109c692c1b56bbdceb5b9d2865b3708dbc")
        );
        assert_eq!(
            ripemd160(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            from_hex::<20>("12a053384a9c0c88e405a06c27dcf49ada62eb2b")
        );
    }

    #[test]
    fn one_million_a() {
        let mut h = Ripemd160::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            h.finalize(),
            from_hex::<20>("52783243c1697bdbe16d37f97f68f08325dc1528")
        );
    }
}
