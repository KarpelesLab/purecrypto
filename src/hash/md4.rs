//! MD4 (RFC 1320).
//!
//! Cryptographically broken (collisions are trivial); provided only for
//! interoperability with legacy protocols. Do not use for security.

use super::Digest;
use super::block::{MdState, block_words_le, words_to_bytes_le};

const IV: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

#[inline]
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}
#[inline]
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}
#[inline]
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
    let x = block_words_le(block);
    let [mut a, mut b, mut c, mut d] = *state;

    macro_rules! ff {
        ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr) => {
            $a = $a
                .wrapping_add(f($b, $c, $d))
                .wrapping_add(x[$k])
                .rotate_left($s);
        };
    }
    macro_rules! gg {
        ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr) => {
            $a = $a
                .wrapping_add(g($b, $c, $d))
                .wrapping_add(x[$k])
                .wrapping_add(0x5a82_7999)
                .rotate_left($s);
        };
    }
    macro_rules! hh {
        ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr) => {
            $a = $a
                .wrapping_add(h($b, $c, $d))
                .wrapping_add(x[$k])
                .wrapping_add(0x6ed9_eba1)
                .rotate_left($s);
        };
    }

    // Round 1.
    ff!(a, b, c, d, 0, 3);
    ff!(d, a, b, c, 1, 7);
    ff!(c, d, a, b, 2, 11);
    ff!(b, c, d, a, 3, 19);
    ff!(a, b, c, d, 4, 3);
    ff!(d, a, b, c, 5, 7);
    ff!(c, d, a, b, 6, 11);
    ff!(b, c, d, a, 7, 19);
    ff!(a, b, c, d, 8, 3);
    ff!(d, a, b, c, 9, 7);
    ff!(c, d, a, b, 10, 11);
    ff!(b, c, d, a, 11, 19);
    ff!(a, b, c, d, 12, 3);
    ff!(d, a, b, c, 13, 7);
    ff!(c, d, a, b, 14, 11);
    ff!(b, c, d, a, 15, 19);

    // Round 2.
    gg!(a, b, c, d, 0, 3);
    gg!(d, a, b, c, 4, 5);
    gg!(c, d, a, b, 8, 9);
    gg!(b, c, d, a, 12, 13);
    gg!(a, b, c, d, 1, 3);
    gg!(d, a, b, c, 5, 5);
    gg!(c, d, a, b, 9, 9);
    gg!(b, c, d, a, 13, 13);
    gg!(a, b, c, d, 2, 3);
    gg!(d, a, b, c, 6, 5);
    gg!(c, d, a, b, 10, 9);
    gg!(b, c, d, a, 14, 13);
    gg!(a, b, c, d, 3, 3);
    gg!(d, a, b, c, 7, 5);
    gg!(c, d, a, b, 11, 9);
    gg!(b, c, d, a, 15, 13);

    // Round 3.
    hh!(a, b, c, d, 0, 3);
    hh!(d, a, b, c, 8, 9);
    hh!(c, d, a, b, 4, 11);
    hh!(b, c, d, a, 12, 15);
    hh!(a, b, c, d, 2, 3);
    hh!(d, a, b, c, 10, 9);
    hh!(c, d, a, b, 6, 11);
    hh!(b, c, d, a, 14, 15);
    hh!(a, b, c, d, 1, 3);
    hh!(d, a, b, c, 9, 9);
    hh!(c, d, a, b, 5, 11);
    hh!(b, c, d, a, 13, 15);
    hh!(a, b, c, d, 3, 3);
    hh!(d, a, b, c, 11, 9);
    hh!(c, d, a, b, 7, 11);
    hh!(b, c, d, a, 15, 15);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// The MD4 hash function.
#[derive(Clone)]
pub struct Md4 {
    state: MdState<4>,
}

impl Digest for Md4 {
    type Output = [u8; 16];
    type Block = [u8; 64];
    const OUTPUT_LEN: usize = 16;
    const BLOCK_LEN: usize = 64;

    #[inline]
    fn new() -> Self {
        Md4 {
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
    fn finalize(self) -> [u8; 16] {
        words_to_bytes_le(&self.state.finalize())
    }
    #[inline]
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

/// Computes the MD4 digest of `data`.
#[inline]
pub fn md4(data: &[u8]) -> [u8; 16] {
    Md4::digest(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // RFC 1320, Appendix A.5 test suite.
    #[test]
    fn rfc1320_vectors() {
        assert_eq!(md4(b""), from_hex::<16>("31d6cfe0d16ae931b73c59d7e0c089c0"));
        assert_eq!(
            md4(b"a"),
            from_hex::<16>("bde52cb31de33e46245e05fbdbd6fb24")
        );
        assert_eq!(
            md4(b"abc"),
            from_hex::<16>("a448017aaf21d8525fc10ae87aa6729d")
        );
        assert_eq!(
            md4(b"message digest"),
            from_hex::<16>("d9130a8164549fe818874806e1c7014b")
        );
        assert_eq!(
            md4(b"abcdefghijklmnopqrstuvwxyz"),
            from_hex::<16>("d79e1c308aa5bbcdeea8ed63df412da9")
        );
        assert_eq!(
            md4(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            from_hex::<16>("e33b4ddc9c38f2199c3e7b164fcc0536")
        );
    }
}
