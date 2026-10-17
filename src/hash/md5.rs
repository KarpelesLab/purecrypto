//! MD5 (RFC 1321).
//!
//! Cryptographically broken (practical collisions exist); provided only for
//! interoperability with legacy protocols. Do not use for security.

use super::Digest;
use super::block::{MdState, block_words_le, words_to_bytes_le};

const IV: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// Per-round left-rotation amounts.
const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// `T[i] = floor(2^32 * abs(sin(i + 1)))`.
const K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// The four MD5 round functions, in the `d ^ (b & (c ^ d))` form (one fewer
/// operation than the RFC's `(b & c) | (!b & d)`, same truth table).
macro_rules! f1 {
    ($b:ident, $c:ident, $d:ident) => {
        $d ^ ($b & ($c ^ $d))
    };
}
macro_rules! f2 {
    ($b:ident, $c:ident, $d:ident) => {
        $c ^ ($d & ($b ^ $c))
    };
}
macro_rules! f3 {
    ($b:ident, $c:ident, $d:ident) => {
        $b ^ $c ^ $d
    };
}
macro_rules! f4 {
    ($b:ident, $c:ident, $d:ident) => {
        $c ^ ($b | !$d)
    };
}

fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
    let m = block_words_le(block);
    let [mut a, mut b, mut c, mut d] = *state;

    // Step `i`: `a = b + rotl(a + f(b, c, d) + K[i] + m[g], S[i])`. Instead of
    // the RFC's `a = d; d = c; c = b` register shuffle, consecutive steps are
    // called with the register names rotated `(a, b, c, d) -> (d, a, b, c)`,
    // and the whole 64-step schedule is straight-line so every `K`/`S`/`m`
    // index is a constant (the loop form with a per-step `match` on the round
    // measured 2.3x slower).
    macro_rules! step {
        ($a:ident, $b:ident, $c:ident, $d:ident, $f:ident, $i:expr, $g:expr) => {
            $a = $b.wrapping_add(
                $a.wrapping_add($f!($b, $c, $d))
                    .wrapping_add(K[$i])
                    .wrapping_add(m[$g])
                    .rotate_left(S[$i]),
            );
        };
    }
    macro_rules! r4 {
        ($f:ident, $i:expr, $g0:expr, $g1:expr, $g2:expr, $g3:expr) => {
            step!(a, b, c, d, $f, $i, $g0);
            step!(d, a, b, c, $f, $i + 1, $g1);
            step!(c, d, a, b, $f, $i + 2, $g2);
            step!(b, c, d, a, $f, $i + 3, $g3);
        };
    }
    // Round 1: g = i.
    r4!(f1, 0, 0, 1, 2, 3);
    r4!(f1, 4, 4, 5, 6, 7);
    r4!(f1, 8, 8, 9, 10, 11);
    r4!(f1, 12, 12, 13, 14, 15);
    // Round 2: g = (5i + 1) mod 16.
    r4!(f2, 16, 1, 6, 11, 0);
    r4!(f2, 20, 5, 10, 15, 4);
    r4!(f2, 24, 9, 14, 3, 8);
    r4!(f2, 28, 13, 2, 7, 12);
    // Round 3: g = (3i + 5) mod 16.
    r4!(f3, 32, 5, 8, 11, 14);
    r4!(f3, 36, 1, 4, 7, 10);
    r4!(f3, 40, 13, 0, 3, 6);
    r4!(f3, 44, 9, 12, 15, 2);
    // Round 4: g = 7i mod 16.
    r4!(f4, 48, 0, 7, 14, 5);
    r4!(f4, 52, 12, 3, 10, 1);
    r4!(f4, 56, 8, 15, 6, 13);
    r4!(f4, 60, 4, 11, 2, 9);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// The MD5 hash function.
#[derive(Clone)]
pub struct Md5 {
    state: MdState<4>,
}

impl Digest for Md5 {
    type Output = [u8; 16];
    type Block = [u8; 64];
    const OUTPUT_LEN: usize = 16;
    const BLOCK_LEN: usize = 64;

    #[inline]
    fn new() -> Self {
        Md5 {
            state: MdState::new(IV, false, compress),
        }
    }
    #[inline]
    fn zeroed_block() -> [u8; 64] {
        [0u8; 64]
    }
    #[inline]
    fn zeroed_output() -> [u8; 16] {
        [0u8; 16]
    }
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }
    #[inline]
    fn hmac_short(inner: &Self, outer: &Self, parts: &[&[u8]]) -> Option<[u8; 16]> {
        inner.state.hmac_short(&outer.state, parts)
    }
    #[inline]
    fn finalize(self) -> [u8; 16] {
        words_to_bytes_le(&self.state.finalize())
    }
    #[inline]
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

/// Computes the MD5 digest of `data`.
#[inline]
pub fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // RFC 1321, Appendix A.5 test suite.
    #[test]
    fn rfc1321_vectors() {
        assert_eq!(md5(b""), from_hex::<16>("d41d8cd98f00b204e9800998ecf8427e"));
        assert_eq!(
            md5(b"a"),
            from_hex::<16>("0cc175b9c0f1b6a831c399e269772661")
        );
        assert_eq!(
            md5(b"abc"),
            from_hex::<16>("900150983cd24fb0d6963f7d28e17f72")
        );
        assert_eq!(
            md5(b"message digest"),
            from_hex::<16>("f96b697d7cb7938d525a2f31aaf161d0")
        );
        assert_eq!(
            md5(b"abcdefghijklmnopqrstuvwxyz"),
            from_hex::<16>("c3fcd3d76192e4007dfb496cca67e13b")
        );
        assert_eq!(
            md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            from_hex::<16>("57edf4a22be3c955ac49da2e2107b67a")
        );
    }
}
