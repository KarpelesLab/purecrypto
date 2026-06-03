//! AES-SIV — Synthetic Initialization Vector authenticated encryption
//! (RFC 5297).
//!
//! SIV is a *nonce-reuse-resistant* / deterministic AEAD: the synthetic IV `V`
//! is derived (via the S2V construction over AES-CMAC) from the key, all the
//! associated-data headers, and the plaintext, then used as the AES-CTR IV.
//! Repeating a (key, AD, plaintext) tuple yields identical output, and a
//! repeated nonce leaks only equality of messages — never the key.
//!
//! The double-length key is split into two halves: `K1` keys the CMAC/S2V step
//! and `K2` keys CTR encryption (RFC 5297 §2.2). A 32-byte key selects AES-128
//! for both halves; a 64-byte key selects AES-256.

use alloc::vec::Vec;

use super::cmac::Cmac;
use super::ctr::Ctr;
use super::{Aes128, Aes256, TagMismatch};
use crate::ct::ConstantTimeEq;

/// Doubles a 128-bit value in GF(2¹²⁸) per RFC 5297 §2.3 (same field and
/// big-endian convention as CMAC's `dbl`).
fn dbl(block: [u8; 16]) -> [u8; 16] {
    let msb = block[0] >> 7;
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }
    out[15] ^= 0x87 & 0u8.wrapping_sub(msb);
    out
}

/// XORs `b` into the *end* of `a` (RFC 5297 §2.1 `xorend`): the last
/// `b.len()` bytes of `a` are XORed with `b`. Requires `b.len() <= a.len()`.
fn xorend(a: &mut [u8], b: &[u8]) {
    let off = a.len() - b.len();
    for (x, y) in a[off..].iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
}

/// The two block-cipher choices SIV is instantiated over, sharing the same
/// S2V / CTR logic via dynamic dispatch on the (already public) key length.
enum Cipher {
    Aes128 { mac: Aes128, ctr: Aes128 },
    Aes256 { mac: Aes256, ctr: Aes256 },
}

/// AES-SIV context (RFC 5297). Built from a double-length key with
/// [`AesSiv::new`]; [`AesSiv::seal`] / [`AesSiv::open`] perform deterministic
/// authenticated encryption.
pub struct AesSiv {
    cipher: Cipher,
}

impl AesSiv {
    /// Creates an AES-SIV context from a `2n`-byte key: the leftmost `n` bytes
    /// key the S2V/CMAC half and the rightmost `n` bytes key CTR. A 32-byte key
    /// selects AES-128-SIV; a 64-byte key selects AES-256-SIV.
    ///
    /// # Panics
    /// Panics if `key.len()` is not 32 or 64.
    pub fn new(key: &[u8]) -> Self {
        let cipher = match key.len() {
            32 => {
                let (k1, k2) = key.split_at(16);
                Cipher::Aes128 {
                    mac: Aes128::new(k1.try_into().unwrap()),
                    ctr: Aes128::new(k2.try_into().unwrap()),
                }
            }
            64 => {
                let (k1, k2) = key.split_at(32);
                Cipher::Aes256 {
                    mac: Aes256::new(k1.try_into().unwrap()),
                    ctr: Aes256::new(k2.try_into().unwrap()),
                }
            }
            _ => panic!("AES-SIV key must be 32 bytes (AES-128) or 64 bytes (AES-256)"),
        };
        AesSiv { cipher }
    }

    /// CMAC of `data` under the S2V key half.
    fn cmac(&self, data: &[u8]) -> [u8; 16] {
        match &self.cipher {
            Cipher::Aes128 { mac, .. } => {
                let mut c = Cmac::new(mac.clone());
                c.update(data);
                c.finalize()
            }
            Cipher::Aes256 { mac, .. } => {
                let mut c = Cmac::new(mac.clone());
                c.update(data);
                c.finalize()
            }
        }
    }

    /// S2V over the associated-data vector and plaintext (RFC 5297 §2.4).
    ///
    /// `ad` are the associated-data headers `S1..Sm`; the plaintext `Sn` is the
    /// final string. Returns the 16-byte synthetic IV `V`.
    fn s2v(&self, ad: &[&[u8]], plaintext: &[u8]) -> [u8; 16] {
        // D = AES-CMAC(K, <zero>) where <zero> is one zero block.
        let mut d = self.cmac(&[0u8; 16]);

        for s in ad {
            // D = dbl(D) xor AES-CMAC(K, Si)
            d = dbl(d);
            let cs = self.cmac(s);
            for i in 0..16 {
                d[i] ^= cs[i];
            }
        }

        // Final string Sn = plaintext.
        if plaintext.len() >= 16 {
            // T = Sn xorend D, then V = AES-CMAC(K, T).
            let mut t = plaintext.to_vec();
            xorend(&mut t, &d);
            self.cmac(&t)
        } else {
            // T = dbl(D) xor pad(Sn); V = AES-CMAC(K, T).
            let mut t = dbl(d);
            for (i, b) in plaintext.iter().enumerate() {
                t[i] ^= *b;
            }
            t[plaintext.len()] ^= 0x80;
            self.cmac(&t)
        }
    }

    /// Builds the CTR IV `Q` from `V` by clearing bit 31 and bit 63 of the
    /// rightmost 64-bit halves (the `& 0x7fffffff7fffffff` mask on the last 8
    /// bytes, RFC 5297 §2.5).
    fn ctr_iv(v: &[u8; 16]) -> [u8; 16] {
        let mut q = *v;
        q[8] &= 0x7f;
        q[12] &= 0x7f;
        q
    }

    /// Applies AES-CTR (with the CTR key half) over `buf` in place.
    fn ctr_xor(&self, iv: &[u8; 16], buf: &mut [u8]) {
        match &self.cipher {
            Cipher::Aes128 { ctr, .. } => Ctr::new(ctr.clone(), iv).apply_keystream(buf),
            Cipher::Aes256 { ctr, .. } => Ctr::new(ctr.clone(), iv).apply_keystream(buf),
        }
    }

    /// Deterministically encrypts `plaintext`, binding the `associated_data`
    /// headers, and returns `V ‖ ciphertext` (RFC 5297 §2.6). `V` is the
    /// 16-byte synthetic IV / tag prepended to the output.
    pub fn seal(&self, associated_data: &[&[u8]], plaintext: &[u8]) -> Vec<u8> {
        let v = self.s2v(associated_data, plaintext);
        let q = Self::ctr_iv(&v);
        let mut out = Vec::with_capacity(16 + plaintext.len());
        out.extend_from_slice(&v);
        out.extend_from_slice(plaintext);
        self.ctr_xor(&q, &mut out[16..]);
        out
    }

    /// Verifies and decrypts an `V ‖ ciphertext` blob produced by
    /// [`seal`](Self::seal) under the same `associated_data` (RFC 5297 §2.7).
    ///
    /// The synthetic IV is recomputed over the recovered plaintext and compared
    /// to the transmitted `V` in constant time; on mismatch no plaintext is
    /// returned and [`TagMismatch`] is produced.
    pub fn open(&self, associated_data: &[&[u8]], input: &[u8]) -> Result<Vec<u8>, TagMismatch> {
        if input.len() < 16 {
            return Err(TagMismatch);
        }
        let mut v = [0u8; 16];
        v.copy_from_slice(&input[..16]);
        let q = Self::ctr_iv(&v);
        let mut plaintext = input[16..].to_vec();
        self.ctr_xor(&q, &mut plaintext);

        let expected = self.s2v(associated_data, &plaintext);
        if bool::from(expected.ct_eq(&v)) {
            Ok(plaintext)
        } else {
            // Discard the unauthenticated plaintext.
            for b in plaintext.iter_mut() {
                *b = 0;
            }
            Err(TagMismatch)
        }
    }
}

// Key material is held only inside the AES halves, which zeroize their own
// round keys on drop (see `cipher/aes/mod.rs`), so `AesSiv` needs no extra
// `Drop` of its own.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{from_hex, from_hex_vec};

    // RFC 5297 Appendix A.1: deterministic authenticated encryption, one AD
    // header. Key = a-half ‖ ctr-half (each AES-128).
    #[test]
    fn rfc5297_a1() {
        let key = from_hex::<32>(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );
        let ad = from_hex::<24>("101112131415161718191a1b1c1d1e1f2021222324252627");
        let pt = from_hex::<14>("112233445566778899aabbccddee");

        let siv = AesSiv::new(&key);
        let out = siv.seal(&[&ad], &pt);
        let expected = from_hex_vec(
            "85632d07c6e8f37f950acd320a2ecc93\
             40c02b9690c4dc04daef7f6afe5c",
        );
        assert_eq!(out, expected);

        let recovered = siv.open(&[&ad], &out).unwrap();
        assert_eq!(recovered, pt.to_vec());
    }

    // RFC 5297 Appendix A.2: nonce-based authenticated encryption with multiple
    // associated-data components (the nonce is the last AD header).
    #[test]
    fn rfc5297_a2() {
        let key = from_hex::<32>(
            "7f7e7d7c7b7a79787776757473727170\
             404142434445464748494a4b4c4d4e4f",
        );
        let ad1 = from_hex_vec(
            "00112233445566778899aabbccddeeff\
             deaddadadeaddadaffeeddccbbaa9988\
             7766554433221100",
        );
        let ad2 = from_hex_vec("102030405060708090a0");
        let nonce = from_hex_vec("09f911029d74e35bd84156c5635688c0");
        let pt = from_hex_vec(
            "7468697320697320736f6d6520706c61\
             696e7465787420746f20656e63727970\
             74207573696e67205349562d414553",
        );

        let siv = AesSiv::new(&key);
        let out = siv.seal(&[&ad1, &ad2, &nonce], &pt);
        let expected = from_hex_vec(
            "7bdb6e3b432667eb06f4d14bff2fbd0f\
             cb900f2fddbe404326601965c889bf17\
             dba77ceb094fa663b7a3f748ba8af829\
             ea64ad544a272e9c485b62a3fd5c0d",
        );
        assert_eq!(out, expected);

        let recovered = siv.open(&[&ad1, &ad2, &nonce], &out).unwrap();
        assert_eq!(recovered, pt);
    }

    // A tampered V (tag) or AD is rejected and yields no plaintext.
    #[test]
    fn reject_tamper() {
        let key = from_hex::<32>(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );
        let ad = from_hex::<24>("101112131415161718191a1b1c1d1e1f2021222324252627");
        let pt = from_hex::<14>("112233445566778899aabbccddee");

        let siv = AesSiv::new(&key);
        let mut out = siv.seal(&[&ad], &pt);
        out[0] ^= 1;
        assert_eq!(siv.open(&[&ad], &out), Err(TagMismatch));

        let out = siv.seal(&[&ad], &pt);
        let mut bad_ad = ad;
        bad_ad[0] ^= 1;
        assert_eq!(siv.open(&[&bad_ad], &out), Err(TagMismatch));
    }

    // AES-256-SIV round-trip (64-byte key); empty AD vector.
    #[test]
    fn aes256_roundtrip_empty_ad() {
        let key: Vec<u8> = (0u8..64).collect();
        let siv = AesSiv::new(&key);
        let pt = b"AES-256-SIV deterministic AEAD round-trip test payload";
        let out = siv.seal(&[], pt);
        let recovered = siv.open(&[], &out).unwrap();
        assert_eq!(recovered, pt.to_vec());
    }

    // Empty plaintext seals to just V (16 bytes) and round-trips.
    #[test]
    fn empty_plaintext() {
        let key = from_hex::<32>(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );
        let siv = AesSiv::new(&key);
        let out = siv.seal(&[], &[]);
        assert_eq!(out.len(), 16);
        assert_eq!(siv.open(&[], &out).unwrap(), Vec::<u8>::new());
    }
}
