//! AES-CMAC — Cipher-based Message Authentication Code
//! (RFC 4493 / NIST SP 800-38B).
//!
//! CMAC is a CBC-MAC variant that is secure for variable-length messages: it
//! derives two subkeys `K1`, `K2` from `E_K(0¹⁶)` and XORs the appropriate one
//! into the final (possibly padded) block before the last encryption. This
//! fixes the length-extension weakness of plain CBC-MAC without any framing.
//!
//! The construction here is generic over any 128-bit [`BlockCipher`]; the
//! [`AesCmac128`] / [`AesCmac256`] aliases pin it to AES. It also implements the
//! crate [`Mac`](crate::hash::Mac) trait so the shared constant-time
//! verification applies.

use super::BlockCipher;
use crate::ct::ConstantTimeEq;

/// The GF(2¹²⁸) reduction polynomial constant for the `dbl` operation
/// (`x⁷ + x² + x + 1`, RFC 4493 §2.3).
const RB: u8 = 0x87;

/// Doubles a 128-bit value in GF(2¹²⁸) (big-endian, RFC 4493 §2.3):
/// `dbl(x) = (x << 1)` if the MSB is 0, else `(x << 1) ⊕ 0x..87`.
///
/// Implemented branchlessly so the subkey derivation leaks nothing about the
/// (secret) block-cipher output through timing.
fn dbl(block: [u8; 16]) -> [u8; 16] {
    let msb = block[0] >> 7;
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }
    // Conditionally XOR Rb when the high bit was set, without branching.
    out[15] ^= RB & 0u8.wrapping_sub(msb);
    out
}

/// AES-CMAC context, parameterized over the underlying 128-bit block cipher.
///
/// Construct with [`Cmac::new`], feed message bytes with [`Cmac::update`], then
/// produce the tag with [`Cmac::finalize`] / [`Cmac::finalize_into`], or check
/// a received tag in constant time with [`Cmac::verify`].
#[derive(Clone)]
pub struct Cmac<C: BlockCipher> {
    cipher: C,
    /// Subkey for a full final block, `K1 = dbl(E_K(0¹⁶))`.
    k1: [u8; 16],
    /// Subkey for a padded final block, `K2 = dbl(K1)`.
    k2: [u8; 16],
    /// Running CBC-MAC chaining value `X`.
    state: [u8; 16],
    /// Bytes held back until a full block is known *not* to be the last.
    pending: [u8; 16],
    /// Number of valid bytes in `pending` (0..=16).
    pending_len: usize,
}

impl<C: BlockCipher> Cmac<C> {
    /// Creates a CMAC context from a pre-keyed block cipher, deriving the two
    /// subkeys `K1`, `K2` (RFC 4493 §2.3).
    pub fn new(cipher: C) -> Self {
        let mut l = [0u8; 16];
        cipher.encrypt_block(&mut l);
        let k1 = dbl(l);
        let k2 = dbl(k1);
        Cmac {
            cipher,
            k1,
            k2,
            state: [0u8; 16],
            pending: [0u8; 16],
            pending_len: 0,
        }
    }

    /// Absorbs a completed 16-byte block into the CBC-MAC chain.
    fn absorb(&mut self, block: &[u8; 16]) {
        for (s, b) in self.state.iter_mut().zip(block.iter()) {
            *s ^= *b;
        }
        self.cipher.encrypt_block(&mut self.state);
    }

    /// Feeds message bytes. May be called any number of times.
    ///
    /// A full block is only absorbed once a *following* byte arrives, so the
    /// final block (which is treated specially) is never absorbed early.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            // If `pending` is a full block, it cannot be the last block (more
            // data follows), so absorb it now before buffering more.
            if self.pending_len == 16 {
                let block = self.pending;
                self.absorb(&block);
                self.pending_len = 0;
            }
            let n = core::cmp::min(16 - self.pending_len, data.len());
            self.pending[self.pending_len..self.pending_len + n].copy_from_slice(&data[..n]);
            self.pending_len += n;
            data = &data[n..];
        }
    }

    /// Consumes the MAC and returns the 16-byte tag (RFC 4493 §2.4).
    pub fn finalize(mut self) -> [u8; 16] {
        let mut last = self.pending;
        if self.pending_len == 16 {
            // Complete final block: XOR K1.
            for (l, k) in last.iter_mut().zip(self.k1.iter()) {
                *l ^= *k;
            }
        } else {
            // Pad with 0x80 0x00.. then XOR K2.
            last[self.pending_len] = 0x80;
            for b in last.iter_mut().skip(self.pending_len + 1) {
                *b = 0;
            }
            for (l, k) in last.iter_mut().zip(self.k2.iter()) {
                *l ^= *k;
            }
        }
        self.absorb(&last);
        self.state
    }

    /// Consumes the MAC and writes the tag into `out`, truncated to `out.len()`
    /// (which must be ≤ 16).
    pub fn finalize_into(self, out: &mut [u8]) {
        let tag = self.finalize();
        let n = out.len().min(16);
        out[..n].copy_from_slice(&tag[..n]);
    }

    /// Consumes the MAC and checks it against `expected` in constant time.
    ///
    /// Returns `true` iff the recomputed tag (truncated to `expected.len()`)
    /// equals `expected`. The comparison time depends only on the (public) tag
    /// length, not on where any mismatch occurs.
    pub fn verify(self, expected: &[u8]) -> bool {
        if expected.len() > 16 {
            return false;
        }
        let tag = self.finalize();
        bool::from(tag[..expected.len()].ct_eq(expected))
    }
}

impl<C: BlockCipher> Drop for Cmac<C> {
    fn drop(&mut self) {
        // Best-effort wipe of the secret subkeys and chaining/buffer state, the
        // same `core::hint::black_box`-guarded zeroing used by the AES round-key
        // drop in `cipher/aes/mod.rs`.
        self.k1 = [0u8; 16];
        self.k2 = [0u8; 16];
        self.state = [0u8; 16];
        self.pending = [0u8; 16];
        let _ = core::hint::black_box(&self.k1);
        let _ = core::hint::black_box(&self.k2);
        let _ = core::hint::black_box(&self.state);
        let _ = core::hint::black_box(&self.pending);
    }
}

// The `Mac` trait lives in the `hash` module, so this impl is only available
// when that module is compiled in.
#[cfg(feature = "hash")]
impl<C: BlockCipher + Clone> crate::hash::Mac for Cmac<C> {
    /// CMAC always produces a 16-byte tag, so the trait's default `verify`
    /// rejects any `expected` that is not exactly 16 bytes.
    const OUTPUT_LEN: Option<usize> = Some(16);

    fn update(&mut self, data: &[u8]) {
        Cmac::update(self, data);
    }

    fn finalize_into(self, out: &mut [u8]) {
        Cmac::finalize_into(self, out);
    }
}

/// AES-128 in CMAC mode (RFC 4493).
pub type AesCmac128 = Cmac<super::Aes128>;
/// AES-256 in CMAC mode (NIST SP 800-38B).
pub type AesCmac256 = Cmac<super::Aes256>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{Aes128, Aes256};
    use crate::test_util::from_hex;

    fn cmac128(key_hex: &str, msg: &[u8]) -> [u8; 16] {
        let mut m = AesCmac128::new(Aes128::new(&from_hex::<16>(key_hex)));
        m.update(msg);
        m.finalize()
    }

    // RFC 4493 §2.3: subkey generation for the example key.
    #[test]
    fn rfc4493_subkeys() {
        let key = from_hex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let m = AesCmac128::new(Aes128::new(&key));
        assert_eq!(m.k1, from_hex::<16>("fbeed618357133667c85e08f7236a8de"));
        assert_eq!(m.k2, from_hex::<16>("f7ddac306ae266ccf90bc11ee46d513b"));
    }

    // RFC 4493 §4 Example 1: len = 0 (empty message).
    #[test]
    fn rfc4493_example1_empty() {
        let tag = cmac128("2b7e151628aed2a6abf7158809cf4f3c", &[]);
        assert_eq!(tag, from_hex::<16>("bb1d6929e95937287fa37d129b756746"));
    }

    // RFC 4493 §4 Example 2: len = 16 (one full block).
    #[test]
    fn rfc4493_example2_one_block() {
        let msg = from_hex::<16>("6bc1bee22e409f96e93d7e117393172a");
        let tag = cmac128("2b7e151628aed2a6abf7158809cf4f3c", &msg);
        assert_eq!(tag, from_hex::<16>("070a16b46b4d4144f79bdd9dd04a287c"));
    }

    // RFC 4493 §4 Example 3: len = 40 (partial final block).
    #[test]
    fn rfc4493_example3_partial() {
        let msg = from_hex::<40>(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411",
        );
        let tag = cmac128("2b7e151628aed2a6abf7158809cf4f3c", &msg);
        assert_eq!(tag, from_hex::<16>("dfa66747de9ae63030ca32611497c827"));
    }

    // RFC 4493 §4 Example 4: len = 64 (multiple full blocks).
    #[test]
    fn rfc4493_example4_full() {
        let msg = from_hex::<64>(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let tag = cmac128("2b7e151628aed2a6abf7158809cf4f3c", &msg);
        assert_eq!(tag, from_hex::<16>("51f0bebf7e3b9d92fc49741779363cfe"));
    }

    // NIST SP 800-38B Appendix D.3 (AES-256), Example 9: empty message.
    #[test]
    fn nist_38b_aes256_empty() {
        let key = from_hex::<32>(
            "603deb1015ca71be2b73aef0857d7781\
             1f352c073b6108d72d9810a30914dff4",
        );
        let mut m = AesCmac256::new(Aes256::new(&key));
        m.update(&[]);
        assert_eq!(
            m.finalize(),
            from_hex::<16>("028962f61b7bf89efc6b551f4667d983")
        );
    }

    // NIST SP 800-38B Appendix D.3 (AES-256), Example 11: 40-byte message.
    #[test]
    fn nist_38b_aes256_partial() {
        let key = from_hex::<32>(
            "603deb1015ca71be2b73aef0857d7781\
             1f352c073b6108d72d9810a30914dff4",
        );
        let msg = from_hex::<40>(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411",
        );
        let mut m = AesCmac256::new(Aes256::new(&key));
        m.update(&msg);
        assert_eq!(
            m.finalize(),
            from_hex::<16>("aaf3d8f1de5640c232f5b169b9c911e6")
        );
    }

    // Streaming update in irregular chunks matches a one-shot tag.
    #[test]
    fn streaming_matches_oneshot() {
        let key = "2b7e151628aed2a6abf7158809cf4f3c";
        let msg = from_hex::<64>(
            "6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710",
        );
        let oneshot = cmac128(key, &msg);

        let mut m = AesCmac128::new(Aes128::new(&from_hex::<16>(key)));
        let mut start = 0;
        for len in [1usize, 15, 16, 1, 31] {
            m.update(&msg[start..start + len]);
            start += len;
        }
        assert_eq!(m.finalize(), oneshot);
    }

    // Constant-time verify accepts the right tag and rejects a wrong one.
    #[test]
    fn verify_roundtrip() {
        let key = from_hex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let msg = from_hex::<16>("6bc1bee22e409f96e93d7e117393172a");
        let make = || {
            let mut m = AesCmac128::new(Aes128::new(&key));
            m.update(&msg);
            m
        };
        let tag = make().finalize();
        assert!(make().verify(&tag));
        // Truncated tag also verifies against its prefix.
        assert!(make().verify(&tag[..8]));
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(!make().verify(&bad));
        // Over-length expected is rejected.
        assert!(!make().verify(&[0u8; 17]));
    }

    // The crate `Mac` trait routes through the same finalize and constant-time
    // verify as the inherent methods.
    #[test]
    fn mac_trait_verify() {
        use crate::hash::Mac;
        let key = from_hex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let msg = from_hex::<16>("6bc1bee22e409f96e93d7e117393172a");
        let mut m = AesCmac128::new(Aes128::new(&key));
        Mac::update(&mut m, &msg);
        let mut tag = [0u8; 16];
        Mac::finalize_into(m.clone(), &mut tag);
        assert_eq!(tag, from_hex::<16>("070a16b46b4d4144f79bdd9dd04a287c"));
        // The trait's default constant-time verify returns a `Choice`.
        assert!(bool::from(Mac::verify(m.clone(), &tag)));
        // OUTPUT_LEN = Some(16): the trait verify rejects anything that is not
        // exactly the full 16-byte tag — truncated, empty, or over-length.
        assert!(!bool::from(Mac::verify(m.clone(), &tag[..8])));
        assert!(!bool::from(Mac::verify(m.clone(), &[])));
        let mut long = [0u8; 17];
        long[..16].copy_from_slice(&tag);
        assert!(!bool::from(Mac::verify(m, &long)));
    }
}
