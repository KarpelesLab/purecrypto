//! GOST R 34.11-94 (RFC 5831), the Russian hash standard superseded by
//! Streebog (GOST R 34.11-2012, [`Streebog256`](super::Streebog256)).
//!
//! A 256-bit Merkle–Damgård hash whose compression function enciphers the
//! chaining value with four GOST 28147-89 block-cipher keys derived from the
//! message block, then mixes with a linear feedback "ψ" transform. The final
//! two compressions absorb the 256-bit message length and the 256-bit
//! running sum of all (zero-padded) message blocks.
//!
//! The S-boxes are a parameter of the standard; two sets are in common use
//! and both are provided:
//!
//! - [`Gost94`] — the "test" parameter set of GOST R 34.11-94 itself and of
//!   RFC 5831's examples (PHP `gost`, RHash `gost94`).
//! - [`Gost94CryptoPro`] — the CryptoPro set of RFC 4357
//!   (`id-GostR3411-94-CryptoProParamSet`; PHP `gost-crypto`, OpenSSL's
//!   `md_gost94`).
//!
//! Message words are read and the digest written little-endian, matching
//! PHP and RHash (RFC 5831 prints its examples as one big-endian 256-bit
//! integer, i.e. byte-reversed).
//!
//! Legacy, behind the opt-in `legacy-hashes` feature, for interop only.
//!
//! # Side channels
//!
//! The GOST 28147-89 rounds look up 1 KiB tables (the 4-bit S-boxes expanded
//! byte-wise, built at compile time) with bytes of `key + state`, so the
//! memory-access pattern depends on the data being hashed. That is harmless
//! for public input, but keyed use (HMAC-GOST) can leak key-dependent cache
//! timing; do not key it with a secret an attacker can time.

use super::Digest;
use super::legacy_buffer::BlockBuffer;

/// The eight 4-bit S-boxes `K1..K8` (K1 substitutes the lowest nibble) of the
/// GOST R 34.11-94 test parameter set.
const SBOX_TEST: [[u8; 16]; 8] = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
];

/// The CryptoPro S-boxes (RFC 4357 §11.2, `id-GostR3411-94-CryptoProParamSet`).
const SBOX_CRYPTOPRO: [[u8; 16]; 8] = [
    [10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15],
    [5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8],
    [7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13],
    [4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3],
    [7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5],
    [7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3],
    [13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11],
    [1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12],
];

/// Byte-wise expansion of the S-boxes with GOST 28147-89's 11-bit rotation
/// folded in: `t[j][x]` is the round function's contribution of byte `j` of
/// its input having value `x`.
type Tables = [[u32; 256]; 4];

const fn expand(s: &[[u8; 16]; 8]) -> Tables {
    let mut t = [[0u32; 256]; 4];
    let mut j = 0;
    while j < 4 {
        let mut x = 0;
        while x < 256 {
            let byte = ((s[2 * j + 1][x >> 4] as u32) << 4) | s[2 * j][x & 15] as u32;
            t[j][x] = (byte << (8 * j)).rotate_left(11);
            x += 1;
        }
        j += 1;
    }
    t
}

static TABLES_TEST: Tables = expand(&SBOX_TEST);
static TABLES_CRYPTOPRO: Tables = expand(&SBOX_CRYPTOPRO);

#[inline(always)]
fn f(t: &Tables, x: u32) -> u32 {
    let b = x.to_le_bytes();
    t[0][b[0] as usize] ^ t[1][b[1] as usize] ^ t[2][b[2] as usize] ^ t[3][b[3] as usize]
}

/// GOST 28147-89 encryption of the 64-bit block `(r, l)` = `(h[0], h[1])`
/// (low word first) under the eight-word `key`.
fn encrypt(t: &Tables, key: &[u32; 8], lo: u32, hi: u32) -> (u32, u32) {
    let (mut r, mut l) = (lo, hi);
    for _ in 0..3 {
        for i in (0..8).step_by(2) {
            l ^= f(t, key[i].wrapping_add(r));
            r ^= f(t, key[i + 1].wrapping_add(l));
        }
    }
    for i in (0..8).step_by(2).rev() {
        l ^= f(t, key[i + 1].wrapping_add(r));
        r ^= f(t, key[i].wrapping_add(l));
    }
    (l, r)
}

/// The A transform on a 256-bit value held as eight 32-bit words:
/// `(y4 ‖ y3 ‖ y2 ‖ y1) ↦ (y1 ⊕ y2 ‖ y4 ‖ y3 ‖ y2)` in 64-bit lanes.
#[inline]
fn a(x: &mut [u32; 8]) {
    let l = x[0] ^ x[2];
    let r = x[1] ^ x[3];
    x.copy_within(2.., 0);
    x[6] = l;
    x[7] = r;
}

/// The P transform: the byte transposition that turns `w` into a cipher key.
#[inline]
fn p(w: &[u32; 8]) -> [u32; 8] {
    let mut bytes = [0u8; 32];
    for (chunk, word) in bytes.chunks_exact_mut(4).zip(w) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    let mut key = [0u8; 32];
    // φ(i + 1 + 4(k − 1)) = 8i + k, for i = 0..3, k = 1..8.
    for i in 0..4 {
        for k in 0..8 {
            key[i + 4 * k] = bytes[8 * i + k];
        }
    }
    let mut out = [0u32; 8];
    for (word, chunk) in out.iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

/// One application of ψ to a 256-bit value as sixteen 16-bit words
/// (`y16 ‖ … ‖ y1 ↦ y1 ⊕ y2 ⊕ y3 ⊕ y4 ⊕ y13 ⊕ y16 ‖ y16 ‖ … ‖ y2`).
#[inline]
fn psi(y: &mut [u16; 16]) {
    let t = y[0] ^ y[1] ^ y[2] ^ y[3] ^ y[12] ^ y[15];
    y.copy_within(1.., 0);
    y[15] = t;
}

fn to_u16s(w: &[u32; 8]) -> [u16; 16] {
    let mut y = [0u16; 16];
    for (i, word) in w.iter().enumerate() {
        y[2 * i] = *word as u16;
        y[2 * i + 1] = (word >> 16) as u16;
    }
    y
}

fn from_u16s(y: &[u16; 16]) -> [u32; 8] {
    let mut w = [0u32; 8];
    for (i, word) in w.iter_mut().enumerate() {
        *word = y[2 * i] as u32 | ((y[2 * i + 1] as u32) << 16);
    }
    w
}

/// The step function `χ(M, H)`.
fn compress(t: &Tables, h: &mut [u32; 8], m: &[u32; 8]) {
    // Key generation (C2 = C4 = 0, C3 = 0xff00ffff000000ffff0000ff00ffff0000ff00ff00ff00ffff00ff00ff00ff00).
    const C3: [u32; 8] = [
        0xff00_ff00,
        0xff00_ff00,
        0x00ff_00ff,
        0x00ff_00ff,
        0x00ff_ff00,
        0xff00_00ff,
        0x0000_00ff,
        0xff00_ffff,
    ];
    let mut u = *h;
    let mut v = *m;
    let mut s = [0u32; 8];
    for step in 0..4 {
        if step > 0 {
            a(&mut u);
            if step == 2 {
                for (x, c) in u.iter_mut().zip(C3) {
                    *x ^= c;
                }
            }
            a(&mut v);
            a(&mut v);
        }
        let w: [u32; 8] = core::array::from_fn(|i| u[i] ^ v[i]);
        let key = p(&w);
        let (lo, hi) = encrypt(t, &key, h[2 * step], h[2 * step + 1]);
        s[2 * step] = lo;
        s[2 * step + 1] = hi;
    }

    // H' = ψ^61(H ⊕ ψ(M ⊕ ψ^12(S))).
    let mut y = to_u16s(&s);
    for _ in 0..12 {
        psi(&mut y);
    }
    let mut x = from_u16s(&y);
    for i in 0..8 {
        x[i] ^= m[i];
    }
    let mut y = to_u16s(&x);
    psi(&mut y);
    let mut x = from_u16s(&y);
    for i in 0..8 {
        x[i] ^= h[i];
    }
    let mut y = to_u16s(&x);
    for _ in 0..61 {
        psi(&mut y);
    }
    *h = from_u16s(&y);
}

fn words_le(block: &[u8; 32]) -> [u32; 8] {
    let mut m = [0u32; 8];
    for (w, chunk) in m.iter_mut().zip(block.chunks_exact(4)) {
        *w = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    m
}

/// Shared state of the two parameter sets.
#[derive(Clone)]
struct State {
    h: [u32; 8],
    /// Running sum Σ of the message blocks, mod 2^256 (little-endian words).
    sum: [u32; 8],
    buf: BlockBuffer<32>,
}

impl State {
    const fn new() -> Self {
        State {
            h: [0u32; 8],
            sum: [0u32; 8],
            buf: BlockBuffer::new(),
        }
    }

    fn absorb(t: &Tables, h: &mut [u32; 8], sum: &mut [u32; 8], block: &[u8; 32]) {
        let m = words_le(block);
        let mut carry = 0u64;
        for (s, w) in sum.iter_mut().zip(m) {
            let v = *s as u64 + w as u64 + carry;
            *s = v as u32;
            carry = v >> 32;
        }
        compress(t, h, &m);
    }

    fn update(&mut self, t: &Tables, data: &[u8]) {
        let (h, sum) = (&mut self.h, &mut self.sum);
        self.buf
            .update(data, |block| Self::absorb(t, h, sum, block));
    }

    fn finalize(mut self, t: &Tables) -> [u8; 32] {
        let bits = self.buf.total_bits();
        let pending = self.buf.pending();
        if !pending.is_empty() {
            let mut block = [0u8; 32];
            block[..pending.len()].copy_from_slice(pending);
            Self::absorb(t, &mut self.h, &mut self.sum, &block);
            super::zeroize::zero_bytes(&mut block);
        }
        let len = [bits as u32, (bits >> 32) as u32, 0, 0, 0, 0, 0, 0];
        compress(t, &mut self.h, &len);
        let sum = self.sum;
        compress(t, &mut self.h, &sum);

        let mut out = [0u8; 32];
        for (chunk, w) in out.chunks_exact_mut(4).zip(self.h) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        self.zeroize();
        out
    }

    const STATE_LEN: usize = 2 + 32 + 32 + BlockBuffer::<32>::STATE_LEN;

    fn export_state(&self, tag: u8) -> [u8; Self::STATE_LEN] {
        let mut out = [0u8; Self::STATE_LEN];
        let mut w = super::state::Writer::new(&mut out, tag);
        w.u32s(&self.h);
        w.u32s(&self.sum);
        self.buf.export_into(&mut w);
        w.finish();
        out
    }

    /// Any chaining value and block sum are possible, so only the buffer is
    /// checked.
    fn from_state(state: &[u8], tag: u8) -> Result<Self, super::StateError> {
        let mut r = super::state::Reader::new(state, tag, Self::STATE_LEN)?;
        let h = r.u32s::<8>();
        let sum = r.u32s::<8>();
        let buf = BlockBuffer::import_from(&mut r)?;
        r.finish();
        Ok(State { h, sum, buf })
    }

    fn zeroize(&mut self) {
        super::zeroize::zero_words(&mut self.h);
        super::zeroize::zero_words(&mut self.sum);
        self.buf.zeroize();
    }
}

macro_rules! gost94 {
    ($(#[$doc:meta])* $name:ident, $func:ident, $tables:ident, $tag:ident) => {
        $(#[$doc])*
        ///
        /// Its block — the unit HMAC keys on — is the 32-byte message block,
        /// matching PHP's `hash_hmac`.
        #[derive(Clone)]
        pub struct $name(State);

        impl Digest for $name {
            type Output = [u8; 32];
            type Block = [u8; 32];
            const OUTPUT_LEN: usize = 32;
            const BLOCK_LEN: usize = 32;

            #[inline]
            fn new() -> Self {
                $name(State::new())
            }
            #[inline]
            fn zeroed_block() -> [u8; 32] {
                [0u8; 32]
            }
            #[inline]
            fn zeroed_output() -> [u8; 32] {
                [0u8; 32]
            }
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.0.update(&$tables, data);
            }
            #[inline]
            fn finalize(self) -> [u8; 32] {
                self.0.finalize(&$tables)
            }
            #[inline]
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl super::ExportableState for $name {
            const STATE_LEN: usize = State::STATE_LEN;
            type State = [u8; State::STATE_LEN];

            fn export_state(&self) -> Self::State {
                self.0.export_state(super::state::tag::$tag)
            }

            fn from_state(state: &[u8]) -> Result<Self, super::StateError> {
                State::from_state(state, super::state::tag::$tag).map($name)
            }
        }

        #[doc = concat!("Computes the ", stringify!($name), " digest of `data`.")]
        #[inline]
        pub fn $func(data: &[u8]) -> [u8; 32] {
            $name::digest(data)
        }
    };
}

gost94!(
    /// GOST R 34.11-94 with the test parameter S-boxes (PHP `gost`).
    Gost94, gost94, TABLES_TEST, GOST94
);
gost94!(
    /// GOST R 34.11-94 with the CryptoPro S-boxes of RFC 4357 (PHP
    /// `gost-crypto`).
    Gost94CryptoPro, gost94_cryptopro, TABLES_CRYPTOPRO, GOST94_CRYPTOPRO
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // php-src ext/hash/tests/gost.phpt and bug73127.phpt (40 × 0xff, which
    // exercises the carry chain of the block sum, and 40 × 0x00).
    #[test]
    fn php_vectors() {
        let cases: [(&[u8], &str, &str); 8] = [
            (
                b"",
                "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d",
                "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0",
            ),
            (
                b"The quick brown fox jumps over the lazy dog",
                "77b7fa410c9ac58a25f49bca7d0468c9296529315eaca76bd1a10f376d1f4294",
                "9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76",
            ),
            (
                b"The quick brown fox jumps over the lazy cog",
                "a3ebc4daaab78b0be131dab5737a7f67e602670d543521319150d2e14eeec445",
                "a93124f5bf2c6d83c3bbf722bc55569310245ca5957541f4dbd7dfaf8137e6f2",
            ),
            (
                &[b'a'; 31],
                "03840d6348763f11e28e7b1ecc4da0cdf7f898fa555b928ef684c6c5b8f46d9f",
                "8978e06b0ecf54ea81ec51ca4e02bcb4eb390b3f04cb5f65ee8de195ffae591b",
            ),
            (
                &[b'a'; 32],
                "fd1b746d9397e78edd311baef391450434271e02816caa37680d6d7381c79d4e",
                "e121e3740ae94ca6d289e6d653ff31695783efff3dd960417a1098a0130fa720",
            ),
            (
                &[b'a'; 33],
                "715e59cdc8ebde9fdf0fe2a2e811b3bf7f48209a01505e467d2cd2aa2bbb5ecf",
                "d3e8f22d9762a148ddfc84a6043d97a608604dae7c05baee72b55f559d03dd74",
            ),
            (
                &[0xff; 40],
                "9eaf96ba62f90fae6707f1d4274d1a9d6680f5a121d4387815aa3a6ec42439c5",
                "231d8bb980d3faa30fee6ec475df5669cf6c24bbce22f46d6737470043a99f8e",
            ),
            (
                &[0x00; 40],
                "a0be0b90fea5a5b50c90c9429d07bb98fa0c06f0c30210e94c7d80c3125c67ac",
                "bbf1f3179409c853cd3e396d67b0e10a266c218a4fd19f149c39aa4f6d37a007",
            ),
        ];
        for (msg, test, cryptopro) in cases {
            assert_eq!(gost94(msg), from_hex::<32>(test));
            assert_eq!(gost94_cryptopro(msg), from_hex::<32>(cryptopro));
        }
    }

    // "abc" and 1,000,000 'a', cross-checked against RHash's gost94 and
    // gost94-cryptopro.
    #[test]
    fn rhash_vectors() {
        assert_eq!(
            gost94(b"abc"),
            from_hex::<32>("f3134348c44fb1b2a277729e2285ebb5cb5e0f29c975bc753b70497c06a4d51d")
        );
        assert_eq!(
            gost94_cryptopro(b"abc"),
            from_hex::<32>("b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c")
        );
        let mut h = Gost94::new();
        let mut c = Gost94CryptoPro::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
            c.update(&[b'a'; 1000]);
        }
        assert_eq!(
            h.finalize(),
            from_hex::<32>("5c00ccc2734cdd3332d3d4749576e3c1a7dbaf0e7ea74e9fa602413c90a129fa")
        );
        assert_eq!(
            c.finalize(),
            from_hex::<32>("8693287aa62f9478f7cb312ec0866b6c4e4a0f11160441e8f4ffcd2715dd554f")
        );
    }

    // The two worked examples of RFC 5831 §7.3 (test parameter set), in
    // the byte order PHP and RHash print (RFC 5831 writes them as
    // big-endian integers, i.e. byte-reversed).
    #[test]
    fn rfc5831_examples() {
        assert_eq!(
            gost94(b"This is message, length=32 bytes"),
            from_hex::<32>("b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa")
        );
        assert_eq!(
            gost94(b"Suppose the original message has length = 50 bytes"),
            from_hex::<32>("471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208")
        );
    }
}
