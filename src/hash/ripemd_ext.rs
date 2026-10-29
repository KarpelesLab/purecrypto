//! RIPEMD-128, RIPEMD-256 and RIPEMD-320 (Dobbertin–Bosselaers–Preneel,
//! 1996) — the less common siblings of [`Ripemd160`](super::Ripemd160).
//!
//! - RIPEMD-128 runs two parallel 64-step lines over a 128-bit state and
//!   combines them like RIPEMD-160.
//! - RIPEMD-256 and RIPEMD-320 keep the two lines of RIPEMD-128 / RIPEMD-160
//!   as separate chaining values (doubling the output) and swap one register
//!   between them after every round. They give **no more security** than
//!   RIPEMD-128 / RIPEMD-160 respectively — only a longer output.
//!
//! Legacy, behind the opt-in `legacy-hashes` feature, for interop (PHP's
//! `hash('ripemd128', …)` and friends). The compression is pure ARX, with no
//! table lookups.

use super::Digest;
use super::block::{MdState, block_words_le, words_to_bytes_le};

const IV_L: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];
const IV_R: [u32; 5] = [
    0x7654_3210,
    0xfedc_ba98,
    0x89ab_cdef,
    0x0123_4567,
    0x3c2d_1e0f,
];

/// Left-line round constants (all four RIPEMD variants).
const KL: [u32; 5] = [
    0x0000_0000,
    0x5a82_7999,
    0x6ed9_eba1,
    0x8f1b_bcdc,
    0xa953_fd4e,
];
/// Right-line round constants of the four-round (128/256-bit) variants.
const KR4: [u32; 4] = [0x50a2_8be6, 0x5c4d_d124, 0x6d70_3ef3, 0x0000_0000];
/// Right-line round constants of the five-round (160/320-bit) variants.
const KR5: [u32; 5] = [
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

/// The five nonlinear functions `f0..f4`.
#[inline(always)]
fn f(n: usize, x: u32, y: u32, z: u32) -> u32 {
    match n {
        0 => x ^ y ^ z,
        1 => (x & y) | (!x & z),
        2 => (x | !y) ^ z,
        3 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

/// One four-round line pair of RIPEMD-128/256 over `l` and `r`. With `swap`
/// set (RIPEMD-256), register `round` is exchanged between the lines after
/// each round.
#[inline(always)]
fn lines4(l: &mut [u32; 4], r: &mut [u32; 4], x: &[u32; 16], swap: bool) {
    for round in 0..4 {
        for j in round * 16..round * 16 + 16 {
            let t = l[0]
                .wrapping_add(f(round, l[1], l[2], l[3]))
                .wrapping_add(x[RL[j]])
                .wrapping_add(KL[round])
                .rotate_left(SL[j]);
            *l = [l[3], t, l[1], l[2]];
            let t = r[0]
                .wrapping_add(f(3 - round, r[1], r[2], r[3]))
                .wrapping_add(x[RR[j]])
                .wrapping_add(KR4[round])
                .rotate_left(SR[j]);
            *r = [r[3], t, r[1], r[2]];
        }
        if swap {
            core::mem::swap(&mut l[round], &mut r[round]);
        }
    }
}

/// One five-round line pair of RIPEMD-160/320 over `l` and `r`. With `swap`
/// set (RIPEMD-320), registers b, d, a, c, e (in that round order) are
/// exchanged between the lines after each round.
#[inline(always)]
fn lines5(l: &mut [u32; 5], r: &mut [u32; 5], x: &[u32; 16], swap: bool) {
    const SWAP: [usize; 5] = [1, 3, 0, 2, 4];
    for round in 0..5 {
        for j in round * 16..round * 16 + 16 {
            let t = l[0]
                .wrapping_add(f(round, l[1], l[2], l[3]))
                .wrapping_add(x[RL[j]])
                .wrapping_add(KL[round])
                .rotate_left(SL[j])
                .wrapping_add(l[4]);
            *l = [l[4], t, l[1], l[2].rotate_left(10), l[3]];
            let t = r[0]
                .wrapping_add(f(4 - round, r[1], r[2], r[3]))
                .wrapping_add(x[RR[j]])
                .wrapping_add(KR5[round])
                .rotate_left(SR[j])
                .wrapping_add(r[4]);
            *r = [r[4], t, r[1], r[2].rotate_left(10), r[3]];
        }
        if swap {
            core::mem::swap(&mut l[SWAP[round]], &mut r[SWAP[round]]);
        }
    }
}

fn compress128(state: &mut [u32; 4], block: &[u8; 64]) {
    let x = block_words_le(block);
    let mut l = *state;
    let mut r = *state;
    lines4(&mut l, &mut r, &x, false);
    let t = state[1].wrapping_add(l[2]).wrapping_add(r[3]);
    state[1] = state[2].wrapping_add(l[3]).wrapping_add(r[0]);
    state[2] = state[3].wrapping_add(l[0]).wrapping_add(r[1]);
    state[3] = state[0].wrapping_add(l[1]).wrapping_add(r[2]);
    state[0] = t;
}

fn compress256(state: &mut [u32; 8], block: &[u8; 64]) {
    let x = block_words_le(block);
    let mut l: [u32; 4] = state[..4].try_into().unwrap();
    let mut r: [u32; 4] = state[4..].try_into().unwrap();
    lines4(&mut l, &mut r, &x, true);
    for i in 0..4 {
        state[i] = state[i].wrapping_add(l[i]);
        state[i + 4] = state[i + 4].wrapping_add(r[i]);
    }
}

fn compress320(state: &mut [u32; 10], block: &[u8; 64]) {
    let x = block_words_le(block);
    let mut l: [u32; 5] = state[..5].try_into().unwrap();
    let mut r: [u32; 5] = state[5..].try_into().unwrap();
    lines5(&mut l, &mut r, &x, true);
    for i in 0..5 {
        state[i] = state[i].wrapping_add(l[i]);
        state[i + 5] = state[i + 5].wrapping_add(r[i]);
    }
}

macro_rules! ripemd {
    ($(#[$doc:meta])* $name:ident, $func:ident, $words:literal, $out:literal, $iv:expr, $compress:ident) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name {
            state: MdState<$words>,
        }

        impl Digest for $name {
            type Output = [u8; $out];
            type Block = [u8; 64];
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = 64;

            #[inline]
            fn new() -> Self {
                $name {
                    state: MdState::new($iv, false, $compress),
                }
            }
            #[inline]
            fn zeroed_block() -> [u8; 64] {
                [0u8; 64]
            }
            #[inline]
            fn zeroed_output() -> [u8; $out] {
                [0u8; $out]
            }
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.state.update(data);
            }
            #[inline]
            fn hmac_short(inner: &Self, outer: &Self, parts: &[&[u8]]) -> Option<[u8; $out]> {
                inner.state.hmac_short(&outer.state, parts)
            }
            #[inline]
            fn finalize(self) -> [u8; $out] {
                words_to_bytes_le(&self.state.finalize())
            }
            #[inline]
            fn zeroize(&mut self) {
                self.state.zeroize();
            }
        }

        #[doc = concat!("Computes the ", stringify!($name), " digest of `data`.")]
        #[inline]
        pub fn $func(data: &[u8]) -> [u8; $out] {
            $name::digest(data)
        }
    };
}

ripemd!(
    /// The RIPEMD-128 hash function (128-bit output; legacy).
    Ripemd128, ripemd128, 4, 16,
    [IV_L[0], IV_L[1], IV_L[2], IV_L[3]],
    compress128
);
ripemd!(
    /// The RIPEMD-256 hash function: RIPEMD-128's two lines kept apart for a
    /// 256-bit output, with RIPEMD-128's security level (legacy).
    Ripemd256, ripemd256, 8, 32,
    [IV_L[0], IV_L[1], IV_L[2], IV_L[3], IV_R[0], IV_R[1], IV_R[2], IV_R[3]],
    compress256
);
ripemd!(
    /// The RIPEMD-320 hash function: RIPEMD-160's two lines kept apart for a
    /// 320-bit output, with RIPEMD-160's security level (legacy).
    Ripemd320, ripemd320, 10, 40,
    [
        IV_L[0], IV_L[1], IV_L[2], IV_L[3], IV_L[4], IV_R[0], IV_R[1], IV_R[2], IV_R[3], IV_R[4],
    ],
    compress320
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // The message set of Bosselaers' RIPEMD page
    // (https://homes.esat.kuleuven.be/~bosselae/ripemd160.html), also used
    // verbatim by php-src ext/hash/tests/ripemd{128,256,320}.phpt.
    const MSGS: [&[u8]; 8] = [
        b"",
        b"a",
        b"abc",
        b"message digest",
        b"abcdefghijklmnopqrstuvwxyz",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    ];

    fn million_a<D: Digest>() -> D::Output {
        let mut h = D::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        h.finalize()
    }

    #[test]
    fn ripemd128_vectors() {
        const EXPECTED: [&str; 9] = [
            "cdf26213a150dc3ecb610f18f6b38b46",
            "86be7afa339d0fc7cfc785e72f578d33",
            "c14a12199c66e4ba84636b0f69144c77",
            "9e327b3d6e523062afc1132d7df9d1b8",
            "fd2aa607f71dc8f510714922b371834e",
            "a1aa0689d0fafa2ddc22e88b49133a06",
            "d1e959eb179c911faea4624c60c5c702",
            "3f45ef194732c2dbb2c4a2c769795fa3",
            "4a7f5723f954eba1216c9d8f6320431f",
        ];
        for (msg, want) in MSGS.iter().zip(EXPECTED) {
            assert_eq!(ripemd128(msg), from_hex::<16>(want));
        }
        assert_eq!(million_a::<Ripemd128>(), from_hex::<16>(EXPECTED[8]));
    }

    #[test]
    fn ripemd256_vectors() {
        const EXPECTED: [&str; 9] = [
            "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
            "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925",
            "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
            "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e",
            "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133",
            "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f",
            "5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8",
            "06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd",
            "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978",
        ];
        for (msg, want) in MSGS.iter().zip(EXPECTED) {
            assert_eq!(ripemd256(msg), from_hex::<32>(want));
        }
        assert_eq!(million_a::<Ripemd256>(), from_hex::<32>(EXPECTED[8]));
    }

    #[test]
    fn ripemd320_vectors() {
        const EXPECTED: [&str; 9] = [
            "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8",
            "ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d",
            "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d",
            "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197",
            "cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009",
            "d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac",
            "ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4",
            "557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42",
            "bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66",
        ];
        for (msg, want) in MSGS.iter().zip(EXPECTED) {
            assert_eq!(ripemd320(msg), from_hex::<40>(want));
        }
        assert_eq!(million_a::<Ripemd320>(), from_hex::<40>(EXPECTED[8]));
    }
}
