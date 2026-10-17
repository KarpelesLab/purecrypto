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

/// The boolean functions: `FF`/`GG` are XOR for rounds 0..16 and
/// majority / choice for rounds 16..64.
macro_rules! ff0 {
    ($a:ident, $b:ident, $c:ident) => {
        $a ^ $b ^ $c
    };
}
macro_rules! ff1 {
    ($a:ident, $b:ident, $c:ident) => {
        ($a & $b) | ($a & $c) | ($b & $c)
    };
}
macro_rules! gg1 {
    ($e:ident, $f:ident, $g:ident) => {
        ($e & $f) | (!$e & $g)
    };
}

/// Round constants, rotated by `j mod 32` per round.
const T0: u32 = 0x79cc_4519;
const T1: u32 = 0x7a87_9d8a;

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

    // Round `j`. The standard's `d = c; c = rotl(b, 9); b = a; a = tt1` (and
    // likewise `h = g; g = rotl(f, 19); f = e; e = p0(tt2)`) is done by
    // writing the new `a`/`e` over the old `d`/`h`, rotating `b`/`f` in place,
    // and calling the next round with the names rotated
    // `(a, b, c, d) -> (d, a, b, c)`; four rounds bring them back round. The
    // 64 rounds are straight-line, so `T`, `w` and the round function are all
    // constants per round (the loop form with per-round `if j < 16` selects
    // measured 1.4x slower).
    macro_rules! round {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident,
         $ff:ident, $gg:ident, $t:ident, $j:expr) => {{
            const J: usize = $j;
            let a12 = $a.rotate_left(12);
            let ss1 = a12
                .wrapping_add($e)
                .wrapping_add($t.rotate_left(J as u32 % 32))
                .rotate_left(7);
            let ss2 = ss1 ^ a12;
            let tt1 = $ff!($a, $b, $c)
                .wrapping_add($d)
                .wrapping_add(ss2)
                .wrapping_add(w[J] ^ w[J + 4]);
            let tt2 = $gg!($e, $f, $g)
                .wrapping_add($h)
                .wrapping_add(ss1)
                .wrapping_add(w[J]);
            $d = tt1;
            $b = $b.rotate_left(9);
            $h = p0(tt2);
            $f = $f.rotate_left(19);
        }};
    }
    macro_rules! r4 {
        ($ff:ident, $gg:ident, $t:ident, $j:expr) => {
            round!(a, b, c, d, e, f, g, h, $ff, $gg, $t, $j);
            round!(d, a, b, c, h, e, f, g, $ff, $gg, $t, $j + 1);
            round!(c, d, a, b, g, h, e, f, $ff, $gg, $t, $j + 2);
            round!(b, c, d, a, f, g, h, e, $ff, $gg, $t, $j + 3);
        };
    }
    r4!(ff0, ff0, T0, 0);
    r4!(ff0, ff0, T0, 4);
    r4!(ff0, ff0, T0, 8);
    r4!(ff0, ff0, T0, 12);
    r4!(ff1, gg1, T1, 16);
    r4!(ff1, gg1, T1, 20);
    r4!(ff1, gg1, T1, 24);
    r4!(ff1, gg1, T1, 28);
    r4!(ff1, gg1, T1, 32);
    r4!(ff1, gg1, T1, 36);
    r4!(ff1, gg1, T1, 40);
    r4!(ff1, gg1, T1, 44);
    r4!(ff1, gg1, T1, 48);
    r4!(ff1, gg1, T1, 52);
    r4!(ff1, gg1, T1, 56);
    r4!(ff1, gg1, T1, 60);

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
    fn hmac_short(inner: &Self, outer: &Self, parts: &[&[u8]]) -> Option<[u8; 32]> {
        inner.state.hmac_short(&outer.state, parts)
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
