//! HAVAL (Zheng–Pieprzyk–Seberry, 1992): a 1024-bit-block hash with a
//! 256-bit state, run with 3, 4 or 5 passes and folded down to a 128-, 160-,
//! 192-, 224- or 256-bit output — the fifteen `havalBITS,PASSES` variants of
//! PHP's `hash()`.
//!
//! The message is padded with a `0x01` byte and zeros to 118 mod 128 bytes,
//! then a two-byte trailer (version 1, pass count, output length) and the
//! 64-bit little-endian bit length. Words are little-endian throughout.
//!
//! Legacy, behind the opt-in `legacy-hashes` feature, for interop only:
//! collisions for 3-pass HAVAL are practical (Van Rompay et al., 2003; Wang
//! et al., 2004), and the 4- and 5-pass versions have seen attacks too. The
//! compression is pure Boolean/ARX logic with no table lookups.

use super::Digest;
use super::legacy_buffer::BlockBuffer;

/// The initial chaining value: the first 256 fraction bits of π.
const IV: [u32; 8] = [
    0x243f_6a88,
    0x85a3_08d3,
    0x1319_8a2e,
    0x0370_7344,
    0xa409_3822,
    0x299f_31d0,
    0x082e_fa98,
    0xec4e_6c89,
];

/// Additive constants of passes 2..5 (the next fraction bits of π).
#[rustfmt::skip]
const K: [[u32; 32]; 4] = [
    [
        0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
        0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
        0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
        0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5,
    ],
    [
        0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
        0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94,
        0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993,
        0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
    ],
    [
        0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991,
        0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
        0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a,
        0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4,
    ],
    [
        0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4,
        0x7d84a5c3, 0x3b8b5ebe, 0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706,
        0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b,
        0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4,
    ],
];

/// Message-word order of passes 2..5 (pass 1 takes the words in order).
#[rustfmt::skip]
const ORDER: [[usize; 32]; 4] = [
    [5, 14, 26, 18, 11, 28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8,
     30, 3, 21, 9, 17, 24, 29, 6, 19, 12, 15, 13, 2, 25, 31, 27],
    [19, 9, 4, 20, 28, 17, 8, 22, 29, 14, 25, 12, 24, 30, 16, 26,
     31, 15, 7, 3, 1, 0, 18, 27, 13, 6, 21, 10, 23, 11, 5, 2],
    [24, 4, 0, 14, 2, 7, 28, 23, 26, 6, 30, 20, 18, 25, 19, 3,
     22, 11, 31, 21, 8, 27, 12, 9, 1, 29, 5, 15, 17, 10, 16, 13],
    [27, 3, 21, 26, 17, 11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10,
     5, 9, 14, 30, 18, 6, 28, 24, 2, 23, 16, 22, 4, 1, 25, 15],
];

/// The input permutation φ of each pass: for `PASSES`-pass HAVAL, pass `r`
/// evaluates `f_r(x6, …, x0)` on registers `M_k` for the `k`s listed here
/// (in `x6..x0` order), where at step `i` register `M_k` is `E[k - i mod 8]`
/// in the reference code's notation.
#[rustfmt::skip]
const PERM: [[[usize; 7]; 5]; 3] = [
    // 3 passes.
    [[1, 0, 3, 5, 6, 2, 4], [4, 2, 1, 0, 5, 3, 6], [6, 1, 2, 3, 4, 5, 0], [0; 7], [0; 7]],
    // 4 passes.
    [[2, 6, 1, 4, 5, 3, 0], [3, 5, 2, 0, 1, 6, 4], [1, 4, 3, 6, 0, 2, 5], [6, 4, 0, 5, 2, 1, 3], [0; 7]],
    // 5 passes.
    [[3, 4, 1, 0, 5, 2, 6], [6, 2, 1, 0, 3, 4, 5], [2, 6, 0, 4, 3, 1, 5], [1, 5, 3, 2, 0, 4, 6], [2, 5, 0, 6, 4, 3, 1]],
];

/// The five Boolean functions `f1..f5`, applied to `(x6, …, x0)`.
#[inline(always)]
fn boolfn(r: usize, [x6, x5, x4, x3, x2, x1, x0]: [u32; 7]) -> u32 {
    match r {
        0 => (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1) ^ x0,
        1 => {
            (x1 & x2 & x3)
                ^ (x2 & x4 & x5)
                ^ (x1 & x2)
                ^ (x1 & x4)
                ^ (x2 & x6)
                ^ (x3 & x5)
                ^ (x4 & x5)
                ^ (x0 & x2)
                ^ x0
        }
        2 => (x1 & x2 & x3) ^ (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x3) ^ x0,
        3 => {
            (x1 & x2 & x3)
                ^ (x2 & x4 & x5)
                ^ (x3 & x4 & x6)
                ^ (x1 & x4)
                ^ (x2 & x6)
                ^ (x3 & x4)
                ^ (x3 & x5)
                ^ (x3 & x6)
                ^ (x4 & x5)
                ^ (x4 & x6)
                ^ (x0 & x4)
                ^ x0
        }
        _ => (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1 & x2 & x3) ^ (x0 & x5) ^ x0,
    }
}

fn compress(state: &mut [u32; 8], block: &[u8; 128], passes: usize) {
    let mut x = [0u32; 32];
    for (w, chunk) in x.iter_mut().zip(block.chunks_exact(4)) {
        *w = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    let mut e = *state;
    for r in 0..passes {
        let perm = &PERM[passes - 3][r];
        for i in 0..32 {
            // Step `i` overwrites register `7 - i mod 8`; `reg(k)` reads the
            // reference code's `E[M_k[i]]`, register `k - i mod 8`.
            let dst = 7 - (i & 7);
            let reg = |k: usize| e[(k + 8 - (i & 7)) & 7];
            let fv = boolfn(r, perm.map(reg));
            let (w, k) = if r == 0 {
                (x[i], 0)
            } else {
                (x[ORDER[r - 1][i]], K[r - 1][i])
            };
            e[dst] = fv
                .rotate_right(7)
                .wrapping_add(e[dst].rotate_right(11))
                .wrapping_add(w)
                .wrapping_add(k);
        }
    }
    for (s, v) in state.iter_mut().zip(e) {
        *s = s.wrapping_add(v);
    }
    super::zeroize::zero_words(&mut x);
}

/// Folds the 256-bit state down to `bits` output bits (the reference
/// "tailoring" step) and serializes it little-endian into `out`.
fn fold(s: &mut [u32; 8], bits: usize, out: &mut [u8]) {
    match bits {
        128 => {
            s[3] = s[3].wrapping_add(
                (s[7] & 0xff00_0000)
                    | (s[6] & 0x00ff_0000)
                    | (s[5] & 0x0000_ff00)
                    | (s[4] & 0x0000_00ff),
            );
            s[2] = s[2].wrapping_add(
                (((s[7] & 0x00ff_0000) | (s[6] & 0x0000_ff00) | (s[5] & 0x0000_00ff)) << 8)
                    | ((s[4] & 0xff00_0000) >> 24),
            );
            s[1] = s[1].wrapping_add(
                (((s[7] & 0x0000_ff00) | (s[6] & 0x0000_00ff)) << 16)
                    | (((s[5] & 0xff00_0000) | (s[4] & 0x00ff_0000)) >> 16),
            );
            s[0] = s[0].wrapping_add(
                ((s[7] & 0x0000_00ff) << 24)
                    | (((s[6] & 0xff00_0000) | (s[5] & 0x00ff_0000) | (s[4] & 0x0000_ff00)) >> 8),
            );
        }
        160 => {
            s[4] = s[4].wrapping_add(
                ((s[7] & 0xfe00_0000) | (s[6] & 0x01f8_0000) | (s[5] & 0x0007_f000)) >> 12,
            );
            s[3] = s[3].wrapping_add(
                ((s[7] & 0x01f8_0000) | (s[6] & 0x0007_f000) | (s[5] & 0x0000_0fc0)) >> 6,
            );
            s[2] = s[2]
                .wrapping_add((s[7] & 0x0007_f000) | (s[6] & 0x0000_0fc0) | (s[5] & 0x0000_003f));
            s[1] = s[1].wrapping_add(
                ((s[7] & 0x0000_0fc0) | (s[6] & 0x0000_003f) | (s[5] & 0xfe00_0000))
                    .rotate_right(25),
            );
            s[0] = s[0].wrapping_add(
                ((s[7] & 0x0000_003f) | (s[6] & 0xfe00_0000) | (s[5] & 0x01f8_0000))
                    .rotate_right(19),
            );
        }
        192 => {
            s[5] = s[5].wrapping_add(((s[7] & 0xfc00_0000) | (s[6] & 0x03e0_0000)) >> 21);
            s[4] = s[4].wrapping_add(((s[7] & 0x03e0_0000) | (s[6] & 0x001f_0000)) >> 16);
            s[3] = s[3].wrapping_add(((s[7] & 0x001f_0000) | (s[6] & 0x0000_fc00)) >> 10);
            s[2] = s[2].wrapping_add(((s[7] & 0x0000_fc00) | (s[6] & 0x0000_03e0)) >> 5);
            s[1] = s[1].wrapping_add((s[7] & 0x0000_03e0) | (s[6] & 0x0000_001f));
            s[0] =
                s[0].wrapping_add(((s[7] & 0x0000_001f) | (s[6] & 0xfc00_0000)).rotate_right(26));
        }
        224 => {
            s[6] = s[6].wrapping_add(s[7] & 0x0f);
            s[5] = s[5].wrapping_add((s[7] >> 4) & 0x1f);
            s[4] = s[4].wrapping_add((s[7] >> 9) & 0x0f);
            s[3] = s[3].wrapping_add((s[7] >> 13) & 0x1f);
            s[2] = s[2].wrapping_add((s[7] >> 18) & 0x0f);
            s[1] = s[1].wrapping_add((s[7] >> 22) & 0x1f);
            s[0] = s[0].wrapping_add((s[7] >> 27) & 0x1f);
        }
        _ => {}
    }
    for (chunk, w) in out.chunks_exact_mut(4).zip(s.iter()) {
        chunk.copy_from_slice(&w.to_le_bytes());
    }
}

/// HAVAL with `PASSES` passes (3, 4 or 5) and an `N`-byte output (16, 20,
/// 24, 28 or 32). Name it through the aliases — [`Haval128_3`] …
/// [`Haval256_5`], after PHP's `haval128,3` … `haval256,5` — rather than
/// spelling out the parameters; other parameter values fail to compile.
///
/// Its block, the unit HMAC keys on, is 128 bytes (as in PHP's `hash_hmac`).
#[derive(Clone)]
pub struct Haval<const PASSES: usize, const N: usize> {
    h: [u32; 8],
    buf: BlockBuffer<128>,
}

impl<const PASSES: usize, const N: usize> Haval<PASSES, N> {
    const VALID: () = assert!(
        (PASSES == 3 || PASSES == 4 || PASSES == 5)
            && (N == 16 || N == 20 || N == 24 || N == 28 || N == 32),
        "HAVAL takes 3, 4 or 5 passes and a 16-, 20-, 24-, 28- or 32-byte output"
    );
}

impl<const PASSES: usize, const N: usize> Digest for Haval<PASSES, N> {
    type Output = [u8; N];
    type Block = [u8; 128];
    const OUTPUT_LEN: usize = N;
    const BLOCK_LEN: usize = 128;

    #[inline]
    fn new() -> Self {
        let () = Self::VALID;
        Haval {
            h: IV,
            buf: BlockBuffer::new(),
        }
    }
    #[inline]
    fn zeroed_block() -> [u8; 128] {
        [0u8; 128]
    }
    #[inline]
    fn zeroed_output() -> [u8; N] {
        [0u8; N]
    }
    fn update(&mut self, data: &[u8]) {
        let h = &mut self.h;
        self.buf.update(data, |block| compress(h, block, PASSES));
    }
    fn finalize(mut self) -> [u8; N] {
        let bits = self.buf.total_bits();
        let pending = self.buf.pending();
        let mut block = [0u8; 128];
        block[..pending.len()].copy_from_slice(pending);
        block[pending.len()] = 0x01;
        if pending.len() >= 118 {
            compress(&mut self.h, &block, PASSES);
            block = [0u8; 128];
        }
        // Version 1 in bits 0..3, the pass count in bits 3..6, then the
        // output length in bits across the remaining 10 bits.
        let out_bits = (N * 8) as u16;
        let trailer = 1 | ((PASSES as u16) << 3) | (out_bits << 6);
        block[118..120].copy_from_slice(&trailer.to_le_bytes());
        block[120..].copy_from_slice(&bits.to_le_bytes());
        compress(&mut self.h, &block, PASSES);

        let mut out = [0u8; N];
        fold(&mut self.h, N * 8, &mut out);
        super::zeroize::zero_bytes(&mut block);
        self.zeroize();
        out
    }
    fn zeroize(&mut self) {
        super::zeroize::zero_words(&mut self.h);
        self.buf.zeroize();
    }
}

/// Exported-state length: header, chaining words, then the buffer part.
const STATE_LEN: usize = 2 + 32 + BlockBuffer::<128>::STATE_LEN;

impl<const PASSES: usize, const N: usize> super::ExportableState for Haval<PASSES, N> {
    const STATE_LEN: usize = STATE_LEN;
    type State = [u8; STATE_LEN];

    fn export_state(&self) -> Self::State {
        let mut out = [0u8; STATE_LEN];
        let mut w = super::state::Writer::new(&mut out, Self::TAG);
        w.u32s(&self.h);
        self.buf.export_into(&mut w);
        w.finish();
        out
    }

    fn from_state(state: &[u8]) -> Result<Self, super::StateError> {
        let () = Self::VALID;
        let mut r = super::state::Reader::new(state, Self::TAG, Self::STATE_LEN)?;
        let h = r.u32s::<8>();
        let buf = BlockBuffer::import_from(&mut r)?;
        r.finish();
        Ok(Haval { h, buf })
    }
}

impl<const PASSES: usize, const N: usize> Haval<PASSES, N> {
    /// The exported-state tag: one per pass count and output length.
    const TAG: u8 = super::state::tag::HAVAL + 5 * (PASSES as u8 - 3) + (N as u8 - 16) / 4;
}

macro_rules! haval_aliases {
    ($($name:ident = $passes:literal, $bytes:literal, $php:literal;)*) => {$(
        #[doc = concat!("HAVAL, ", stringify!($passes), " passes, ", stringify!($bytes),
                        "-byte output (PHP `", $php, "`).")]
        pub type $name = Haval<$passes, $bytes>;
    )*};
}

haval_aliases! {
    Haval128_3 = 3, 16, "haval128,3";
    Haval160_3 = 3, 20, "haval160,3";
    Haval192_3 = 3, 24, "haval192,3";
    Haval224_3 = 3, 28, "haval224,3";
    Haval256_3 = 3, 32, "haval256,3";
    Haval128_4 = 4, 16, "haval128,4";
    Haval160_4 = 4, 20, "haval160,4";
    Haval192_4 = 4, 24, "haval192,4";
    Haval224_4 = 4, 28, "haval224,4";
    Haval256_4 = 4, 32, "haval256,4";
    Haval128_5 = 5, 16, "haval128,5";
    Haval160_5 = 5, 20, "haval160,5";
    Haval192_5 = 5, 24, "haval192,5";
    Haval224_5 = 5, 28, "haval224,5";
    Haval256_5 = 5, 32, "haval256,5";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// Runs `msg` through all fifteen variants, in PHP's test order
    /// (3 passes 128..256 bits, then 4, then 5), and compares with `want`.
    fn check_all(msg: &[u8], want: &[&str; 15]) {
        macro_rules! one {
            ($i:expr, $ty:ty, $n:literal) => {
                assert_eq!(
                    <$ty>::digest(msg),
                    from_hex::<$n>(want[$i]),
                    "{} on {} bytes",
                    stringify!($ty),
                    msg.len()
                );
            };
        }
        one!(0, Haval128_3, 16);
        one!(1, Haval160_3, 20);
        one!(2, Haval192_3, 24);
        one!(3, Haval224_3, 28);
        one!(4, Haval256_3, 32);
        one!(5, Haval128_4, 16);
        one!(6, Haval160_4, 20);
        one!(7, Haval192_4, 24);
        one!(8, Haval224_4, 28);
        one!(9, Haval256_4, 32);
        one!(10, Haval128_5, 16);
        one!(11, Haval160_5, 20);
        one!(12, Haval192_5, 24);
        one!(13, Haval224_5, 28);
        one!(14, Haval256_5, 32);
    }

    // php-src ext/hash/tests/haval.phpt.
    #[test]
    fn php_empty() {
        check_all(
            b"",
            &[
                "c68f39913f901f3ddf44c707357a7d70",
                "d353c3ae22a25401d257643836d7231a9a95f953",
                "e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e",
                "c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d",
                "4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17",
                "ee6bbf4d6a46a679b3a856c88538bb98",
                "1d33aae1be4146dbaaca0b6e70d7a11f10801525",
                "4a8372945afa55c7dead800311272523ca19d42ea47b72da",
                "3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e",
                "c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b",
                "184b8482a0c050dca54b59c7f05bf5dd",
                "255158cfc1eed1a7be7c55ddd64d9790415b933b",
                "4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85",
                "4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e",
                "be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330",
            ],
        );
    }

    #[test]
    fn php_abc() {
        check_all(
            b"abc",
            &[
                "9e40ed883fb63e985d299b40cda2b8f2",
                "b21e876c4d391e2a897661149d83576b5530a089",
                "a7b14c9ef3092319b0e75e3b20b957d180bf20745629e8de",
                "5bc955220ba2346a948d2848eca37bdd5eca6ecca7b594bd32923fab",
                "8699f1e3384d05b2a84b032693e2b6f46df85a13a50d93808d6874bb8fb9e86c",
                "6f2132867c9648419adcd5013e532fa2",
                "77aca22f5b12cc09010afc9c0797308638b1cb9b",
                "7e29881ed05c915903dd5e24a8e81cde5d910142ae66207c",
                "124c43d2ba4884599d013e8c872bfea4c88b0b6bf6303974cbe04e68",
                "8f409f1bb6b30c5016fdce55f652642261575bedca0b9533f32f5455459142b5",
                "d054232fe874d9c6c6dc8e6a853519ea",
                "ae646b04845e3351f00c5161d138940e1fa0c11c",
                "d12091104555b00119a8d07808a3380bf9e60018915b9025",
                "8081027a500147c512e5f1055986674d746d92af4841abeb89da64ad",
                "976cd6254c337969e5913b158392a2921af16fca51f5601d486e0a9de01156e7",
            ],
        );
    }

    // 183 bytes: one full 128-byte block plus a tail that spills the padding
    // into a second block.
    #[test]
    fn php_multi_block() {
        let part = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ0123456789";
        let msg: [u8; 183] = core::array::from_fn(|i| part[i % part.len()]);
        check_all(
            &msg,
            &[
                "ddf4304cc5ffa3db8aab60d4f8fc2a00",
                "e709559359b15917623050e41d27a306c6c3a9db",
                "51e25280ad356c06f4b913b3cdb3abaaac5879dda0a4fea4",
                "28aa2c164e10bb3076574cc8aa8584fd6d04f6d82c37ea5c21e451b3",
                "5537364e3d75174b846d21adf9b113f9d8f97e4750df64d428c01e782f9ade4d",
                "c7d981e8270e39888ba96cafe8745636",
                "3444e38cc2a132b818b554ced8f7d9592df28f57",
                "0ca58f140ed92828a27913ce5636611abcada220fccf3af7",
                "a9d0571d0857773e71363e4e9dfcca4696dba3e5019e7225e65e0cb1",
                "1858d106bdc2fc787445364a163cfc6027597a45a58a2490d14203c8b9bdd268",
                "d41e927ea041d2f0c255352b1a9f6195",
                "f3245e222e6581d0c3077bd7af322af4b4fedab7",
                "fc45dc17a7b19adfed2a6485921f7af7951d70703b9357c1",
                "29687958a6f0d54d495105df00dbda0153ee0f5708408db68a5bbea5",
                "f93421623f852ac877584d1e4bba5d9345a95f81bfd277fe36dfeed1815f83d5",
            ],
        );
    }

    // php-src ext/hash/tests/bug70312.phpt: a 64-byte message, in 5-pass
    // HAVAL at every width.
    #[test]
    fn php_bug70312() {
        let msg = b"1234567890123456789012345678901234567890123456789012345678901234";
        assert_eq!(
            Haval128_5::digest(msg),
            from_hex::<16>("f3f0d23819b87228b4b70ee350afaa9d")
        );
        assert_eq!(
            Haval160_5::digest(msg),
            from_hex::<20>("aded6485e137f11d7292212ba3fa961714df0564")
        );
        assert_eq!(
            Haval192_5::digest(msg),
            from_hex::<24>("e53da2b16269fe732e9a898a96707a9f28404d7333b02286")
        );
        assert_eq!(
            Haval224_5::digest(msg),
            from_hex::<28>("c574fb307f0817b514b9bb2e7c4bfaffb7ad667aca3c8b523fefcf10")
        );
        assert_eq!(
            Haval256_5::digest(msg),
            from_hex::<32>("fb73c19300b14d5cb393d929bf005e6c2d459a4c9c009e9813af1d2d3637ee8f")
        );
    }
}
