//! IDEA, the International Data Encryption Algorithm (Lai & Massey, 1991):
//! 64-bit block, 128-bit key, 8.5 rounds.
//!
//! [`Idea`] implements [`BlockCipher64`], so it composes with
//! [`Cbc64`](super::Cbc64), [`Cfb64`](super::Cfb64) and
//! [`Ofb64`](super::Ofb64) for OpenSSL's `idea-ecb` / `idea-cbc` /
//! `idea-cfb` / `idea-ofb` (and OpenPGP's IDEA, symmetric algorithm 1).
//!
//! # Constant time
//!
//! IDEA mixes three group operations on 16-bit words: XOR, addition mod
//! 2¹⁶, and multiplication mod 2¹⁶ + 1 with the all-zero word standing for
//! 2¹⁶. Many implementations (OpenSSL's included) special-case a zero
//! operand with a branch, which leaks whether a secret word is zero. Here
//! the multiplication is branch-free: the zero operand is mapped to 2¹⁶
//! with a mask, the 33-bit product is reduced as `lo − hi` (since
//! 2¹⁶ ≡ −1), and the possible borrow is corrected with another mask. The
//! decryption subkeys' multiplicative inverses are computed by a fixed
//! square-and-multiply chain (`x^(2¹⁶−1)`), so the key schedule is
//! branch-free too. There are no tables, so no secret-dependent memory
//! access. This relies on the target's 64-bit multiply being
//! data-independent, which holds on mainstream 64-bit CPUs.
//!
//! # When to use this module
//!
//! Only to read or write existing IDEA data. It has large classes of weak
//! keys, a 64-bit block subject to Sweet32-style birthday attacks, and is
//! unauthenticated. Use [`Aes256Gcm`](super::Aes256Gcm) or
//! [`ChaCha20Poly1305`](super::ChaCha20Poly1305) for new designs.
//!
//! References:
//! - X. Lai, J. Massey, "A Proposal for a New Block Encryption Standard",
//!   EUROCRYPT '90; X. Lai, "On the Design and Security of Block Ciphers",
//!   ETH Series in Information Processing, vol. 1, 1992.

use super::BlockCipher64;
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of subkeys: six per round for eight rounds, plus four for the
/// output transformation.
const SUBKEYS: usize = 52;

/// Multiplication modulo 2¹⁶ + 1, with `0` representing 2¹⁶. Branch-free.
#[inline(always)]
fn mul(a: u16, b: u16) -> u16 {
    // 0 -> 0x1_0000; any other value is unchanged.
    let widen = |x: u16| -> u64 {
        let x = u32::from(x);
        u64::from(x | (((x.wrapping_sub(1) >> 16) & 1) << 16))
    };
    let p = widen(a) * widen(b); // at most 2^32
    let lo = (p & 0xffff) as u32;
    let hi = (p >> 16) as u32; // at most 0x1_0000
    // p = hi·2^16 + lo ≡ lo − hi (mod 2^16 + 1), with lo − hi in
    // [−2^16, 2^16); add the modulus back when it went negative.
    let r = lo.wrapping_sub(hi);
    let borrow = (r >> 31).wrapping_neg();
    // The result lies in [0, 2^16]; truncation maps 2^16 back to 0.
    r.wrapping_add(borrow & 0x1_0001) as u16
}

/// Multiplicative inverse modulo 2¹⁶ + 1 (with `0` as 2¹⁶), as
/// `x^(2¹⁶ − 1)` by Fermat: a fixed chain, no branches on `x`.
#[inline]
fn mul_inv(x: u16) -> u16 {
    let mut r = x;
    // Exponent 1 -> 2e + 1 fifteen times gives 2^16 - 1.
    for _ in 0..15 {
        r = mul(mul(r, r), x);
    }
    r
}

/// The IDEA block cipher.
///
/// Branch-free and table-free (see the module-level docs), but
/// unauthenticated with a 64-bit block: legacy interop only. The subkeys
/// are wiped on drop.
#[derive(Clone)]
pub struct Idea {
    ek: [u16; SUBKEYS],
    dk: [u16; SUBKEYS],
}

impl Idea {
    /// Expands a 16-byte key.
    pub fn new(key: &[u8; 16]) -> Self {
        // Encryption subkeys: successive 16-bit words of the key, rotated
        // left by 25 bits after every eight.
        let mut k = u128::from_be_bytes(*key);
        let mut ek = [0u16; SUBKEYS];
        for (i, e) in ek.iter_mut().enumerate() {
            if i > 0 && i % 8 == 0 {
                k = k.rotate_left(25);
            }
            *e = (k >> (112 - 16 * (i % 8))) as u16;
        }
        k.zeroize();

        // Decryption subkeys: the inverses in reverse order, with the two
        // additive keys swapped in the middle rounds (whose output swap
        // they undo).
        let mut dk = [0u16; SUBKEYS];
        for r in 0..=8 {
            let src = 48 - 6 * r;
            let (a, b) = if r == 0 || r == 8 {
                (ek[src + 1], ek[src + 2])
            } else {
                (ek[src + 2], ek[src + 1])
            };
            dk[6 * r] = mul_inv(ek[src]);
            dk[6 * r + 1] = a.wrapping_neg();
            dk[6 * r + 2] = b.wrapping_neg();
            dk[6 * r + 3] = mul_inv(ek[src + 3]);
            if r < 8 {
                dk[6 * r + 4] = ek[src - 2];
                dk[6 * r + 5] = ek[src - 1];
            }
        }
        Self { ek, dk }
    }
}

/// The IDEA data path under subkeys `k` (encryption or decryption).
fn crypt(k: &[u16; SUBKEYS], block: &mut [u8; 8]) {
    let w = |i: usize| u16::from_be_bytes([block[2 * i], block[2 * i + 1]]);
    let (mut x1, mut x2, mut x3, mut x4) = (w(0), w(1), w(2), w(3));
    for r in k[..48].chunks_exact(6) {
        let a = mul(x1, r[0]);
        let b = x2.wrapping_add(r[1]);
        let c = x3.wrapping_add(r[2]);
        let d = mul(x4, r[3]);
        let e = mul(a ^ c, r[4]);
        let f = mul((b ^ d).wrapping_add(e), r[5]);
        let e = e.wrapping_add(f);
        x1 = a ^ f;
        x2 = c ^ f;
        x3 = b ^ e;
        x4 = d ^ e;
    }
    // Output transformation (undoing the last round's middle swap).
    let out = [
        mul(x1, k[48]),
        x3.wrapping_add(k[49]),
        x2.wrapping_add(k[50]),
        mul(x4, k[51]),
    ];
    for (i, v) in out.iter().enumerate() {
        block[2 * i..2 * i + 2].copy_from_slice(&v.to_be_bytes());
    }
}

impl BlockCipher64 for Idea {
    const KEY_SIZE: usize = 16;

    fn encrypt_block(&self, block: &mut [u8; 8]) {
        crypt(&self.ek, block);
    }

    fn decrypt_block(&self, block: &mut [u8; 8]) {
        crypt(&self.dk, block);
    }
}

impl Drop for Idea {
    fn drop(&mut self) {
        self.ek.zeroize();
        self.dk.zeroize();
    }
}

impl ZeroizeOnDrop for Idea {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{Cbc64, Cfb64, Ofb64};
    use crate::test_util::from_hex;

    fn block_kat(key: &str, pt: &str, ct: &str) {
        let c = Idea::new(&from_hex(key));
        let pt: [u8; 8] = from_hex(pt);
        let ct: [u8; 8] = from_hex(ct);
        let mut b = pt;
        c.encrypt_block(&mut b);
        assert_eq!(b, ct, "key {key}");
        c.decrypt_block(&mut b);
        assert_eq!(b, pt, "key {key}");
    }

    /// Exhaustive check of the branch-free multiply against the textbook
    /// definition over a grid of operands, including both zero cases.
    #[test]
    fn mul_matches_definition() {
        let full = |x: u16| if x == 0 { 0x1_0000u64 } else { u64::from(x) };
        let mut vals: alloc::vec::Vec<u16> =
            (0..=0xffffu32).step_by(251).map(|v| v as u16).collect();
        vals.extend([0, 1, 2, 0x8000, 0xfffe, 0xffff]);
        for &a in &vals {
            for &b in &vals {
                let want = (full(a) * full(b) % 0x1_0001) as u16; // 2^16 -> 0
                assert_eq!(mul(a, b), want, "{a:#x} * {b:#x}");
            }
        }
        for &a in &vals {
            assert_eq!(mul(a, mul_inv(a)), 1, "inverse of {a:#x}");
        }
    }

    /// The Lai–Massey test vector (key `0001 0002 … 0008`), reproduced in
    /// Schneier's *Applied Cryptography* and OpenSSL's `ideatest.c`.
    #[test]
    fn lai_massey_vector() {
        block_kat(
            "00010002000300040005000600070008",
            "0000000100020003",
            "11fbed2b01986de5",
        );
    }

    /// Cross-checked against OpenSSL 3.5 `IDEA_ecb_encrypt`; the all-zero
    /// key makes every multiplicative subkey 2¹⁶.
    #[test]
    fn openssl_vectors() {
        let key: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(34));
        let c = Idea::new(&key);
        let mut b: [u8; 8] = from_hex("0011223344556677");
        c.encrypt_block(&mut b);
        assert_eq!(b, from_hex::<8>("9de10b5f00c11226"));
        c.decrypt_block(&mut b);
        assert_eq!(b, from_hex::<8>("0011223344556677"));

        let zero = "00000000000000000000000000000000";
        block_kat(zero, "0011223344556677", "000c222a667b4455");
        block_kat(zero, "0000000000000000", "0001000100000000");
    }

    /// `openssl enc -idea-{ecb,cbc,cfb,ofb}` (OpenSSL 3.5) over Eric
    /// Young's "7654321 Now is the time for " message.
    #[test]
    fn modes_match_openssl() {
        let key: [u8; 16] = from_hex("0123456789abcdeff0e1d2c3b4a59687");
        let iv: [u8; 8] = from_hex("fedcba9876543210");
        let data: &[u8; 32] = b"7654321 Now is the time for \0\0\0\0";

        let mut buf = *data;
        let c = Idea::new(&key);
        for blk in buf.chunks_exact_mut(8) {
            c.encrypt_block(blk.try_into().unwrap());
        }
        assert_eq!(
            buf,
            from_hex::<32>("8c35a9e5bd0043c636fd6b108107790b22979117d173e76fba99be9a3e08c1d7")
        );

        let mut buf = *data;
        Cbc64::new(Idea::new(&key), &iv).encrypt(&mut buf).unwrap();
        assert_eq!(
            buf,
            from_hex::<32>("34775351e5077b8f77b163cc714844fcbd55de3e515a6d3c4031f59cebcb7f02")
        );
        Cbc64::new(Idea::new(&key), &iv).decrypt(&mut buf).unwrap();
        assert_eq!(&buf, data);

        let mut buf: [u8; 29] = data[..29].try_into().unwrap();
        Cfb64::new(Idea::new(&key), &iv).encrypt(&mut buf);
        assert_eq!(
            buf,
            from_hex::<29>("7ff7a989c1bf2cdd8517c76dab400948726c2208fcda64ddeda6823122")
        );
        Cfb64::new(Idea::new(&key), &iv).decrypt(&mut buf);
        assert_eq!(buf[..], data[..29]);

        let mut buf: [u8; 29] = data[..29].try_into().unwrap();
        Ofb64::new(Idea::new(&key), &iv).apply_keystream(&mut buf);
        assert_eq!(
            buf,
            from_hex::<29>("7ff7a989c1bf2cdda97cf5245a76fe6e1ecfcf00dd3b709b8bed434477")
        );
    }
}
