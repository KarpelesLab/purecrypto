//! AES-CBC-HMAC-SHA2 — the JOSE composite AEAD (RFC 7518 §5.2:
//! `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`).
//!
//! A generic encrypt-then-MAC composition of PKCS#7-padded CBC and a
//! truncated HMAC:
//!
//! ```text
//! key = MAC_KEY ‖ ENC_KEY            (two halves of equal length)
//! C   = CBC-ENC_KEY(IV, PKCS7(P))
//! T   = HMAC-MAC_KEY(A ‖ IV ‖ C ‖ AL)[..len(MAC_KEY)]
//! AL  = BE64(bit length of A)
//! ```
//!
//! [`CbcHmacSha2`] is generic over the block cipher and the hash; the three
//! RFC 7518 instantiations are the [`A128CbcHs256`], [`A192CbcHs384`] and
//! [`A256CbcHs512`] aliases, each with a `new` taking the concatenated key.
//! The JOSE layer builds on this API; it is equally usable standalone.
//!
//! # Verification order and padding
//!
//! Decryption verifies the tag (in constant time) **before** touching the
//! ciphertext, so no unauthenticated plaintext is ever produced and there is
//! nothing for a padding oracle to observe. The PKCS#7 check that follows
//! CBC decryption is still branch-free, and a padding failure — which can
//! only come from a broken encryptor, since the ciphertext has already been
//! authenticated — is reported as the same [`AeadError::TagMismatch`] as a
//! bad tag, with the plaintext buffer wiped, so the two remain
//! indistinguishable to a caller. A ciphertext whose length is not a
//! positive multiple of 16 is likewise reported as `TagMismatch`.
//!
//! The IV must be unpredictable per message (RFC 7518 §5.2.2.1 uses a random
//! 128-bit IV); reusing one leaks plaintext-block equality as in any CBC
//! mode.

use super::{AeadError, BlockCipher, Cbc};
use crate::ct::{Choice, ConstantTimeEq, ConstantTimeLess};
use crate::hash::{Digest, Hmac};
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// AES-CBC-HMAC-SHA2 composite AEAD (RFC 7518 §5.2), generic over the block
/// cipher `C` and the HMAC hash `D`.
///
/// The tag is the first `D::OUTPUT_LEN / 2` bytes of the HMAC, and the MAC
/// key has that same length.
#[derive(Clone)]
pub struct CbcHmacSha2<C: BlockCipher, D: Digest> {
    cipher: C,
    /// Keyed HMAC, cloned for every message.
    hmac: Hmac<D>,
}

impl<C: BlockCipher + Clone, D: Digest> CbcHmacSha2<C, D> {
    /// Tag length in bytes: half the HMAC output (RFC 7518 §5.2.2.1 step 5).
    pub const TAG_LEN: usize = D::OUTPUT_LEN / 2;
    /// MAC key length in bytes (equal to the tag length).
    pub const MAC_KEY_LEN: usize = D::OUTPUT_LEN / 2;
    /// IV length in bytes: one CBC block.
    pub const IV_SIZE: usize = 16;

    /// Builds the composite from a pre-keyed block cipher (the `ENC_KEY`
    /// half) and the `MAC_KEY` half.
    ///
    /// # Errors
    /// [`AeadError::InvalidKeyLength`] if `mac_key.len() != MAC_KEY_LEN`.
    pub fn from_parts(cipher: C, mac_key: &[u8]) -> Result<Self, AeadError> {
        if mac_key.len() != Self::MAC_KEY_LEN {
            return Err(AeadError::InvalidKeyLength);
        }
        Ok(CbcHmacSha2 {
            cipher,
            hmac: Hmac::new(mac_key),
        })
    }

    /// Ciphertext length for a `msg_len`-byte plaintext: PKCS#7 always adds
    /// 1..=16 bytes.
    pub const fn ciphertext_len(msg_len: usize) -> usize {
        msg_len - msg_len % 16 + 16
    }

    /// `HMAC(A ‖ IV ‖ C ‖ AL)`, full length.
    fn mac(&self, iv: &[u8; 16], aad: &[u8], ct: &[u8]) -> Result<D::Output, AeadError> {
        let al = Self::al(aad)?;
        let mut h = self.hmac.clone();
        h.update(aad);
        h.update(iv);
        h.update(ct);
        h.update(&al);
        Ok(h.finalize())
    }

    /// `AL`: the 64-bit big-endian bit length of the associated data.
    fn al(aad: &[u8]) -> Result<[u8; 8], AeadError> {
        (aad.len() as u64)
            .checked_mul(8)
            .map(u64::to_be_bytes)
            .ok_or(AeadError::InputTooLong)
    }

    /// Encrypts `msg` under `iv`, binding `aad`, writing the padded CBC
    /// ciphertext to `ct` and the truncated HMAC to `tag`.
    ///
    /// # Panics
    /// Panics if `ct.len() != ciphertext_len(msg.len())` or
    /// `tag.len() != TAG_LEN` — output sizing is the caller's contract, not
    /// attacker-controlled input.
    ///
    /// # Errors
    /// [`AeadError::InputTooLong`] if the associated data's bit length does
    /// not fit `AL`'s 64 bits; nothing is written in that case.
    pub fn encrypt_into(
        &self,
        iv: &[u8; 16],
        aad: &[u8],
        msg: &[u8],
        ct: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), AeadError> {
        assert_eq!(
            ct.len(),
            Self::ciphertext_len(msg.len()),
            "AES-CBC-HMAC-SHA2: ct must be ciphertext_len(msg.len()) bytes"
        );
        assert_eq!(
            tag.len(),
            Self::TAG_LEN,
            "AES-CBC-HMAC-SHA2: tag must be TAG_LEN bytes"
        );
        Self::al(aad)?;
        let n = msg.len();
        ct[..n].copy_from_slice(msg);
        let pad = (ct.len() - n) as u8;
        for b in &mut ct[n..] {
            *b = pad;
        }
        Cbc::new(self.cipher.clone(), iv)
            .encrypt(ct)
            .expect("padded plaintext is a whole number of blocks");
        let mut full = self.mac(iv, aad, ct)?;
        tag.copy_from_slice(&full.as_ref()[..Self::TAG_LEN]);
        // The untruncated MAC is not the tag; do not leave it in the frame.
        full.as_mut().zeroize();
        Ok(())
    }

    /// Verifies `tag` over `(aad, iv, ct)` and, only if it matches, decrypts
    /// `ct` into `out`, returning the plaintext length (`out[..len]`).
    ///
    /// # Panics
    /// Panics if `out.len() < ct.len()`.
    ///
    /// # Errors
    /// [`AeadError::TagMismatch`] if the tag does not verify (including a
    /// tag of the wrong length), if the authenticated ciphertext is not a
    /// positive multiple of 16 bytes, or if its PKCS#7 padding is malformed;
    /// `out` holds no plaintext on error. [`AeadError::InputTooLong`] if the
    /// associated data's bit length overflows `AL`.
    pub fn decrypt_into(
        &self,
        iv: &[u8; 16],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, AeadError> {
        assert!(
            out.len() >= ct.len(),
            "AES-CBC-HMAC-SHA2: out must hold at least ct.len() bytes"
        );
        let mut full = self.mac(iv, aad, ct)?;
        // A wrong-length `tag` compares unequal (never as a prefix match).
        let ok = full.as_ref()[..Self::TAG_LEN].ct_eq(tag);
        full.as_mut().zeroize();
        if !bool::from(ok) {
            return Err(AeadError::TagMismatch);
        }
        let n = ct.len();
        if n == 0 || !n.is_multiple_of(16) {
            return Err(AeadError::TagMismatch);
        }
        let out = &mut out[..n];
        out.copy_from_slice(ct);
        Cbc::new(self.cipher.clone(), iv)
            .decrypt(out)
            .expect("length checked to be whole blocks");
        let last: &[u8; 16] = out[n - 16..].try_into().unwrap();
        let (valid, pad) = pkcs7_check(last);
        if !bool::from(valid) {
            out.zeroize();
            return Err(AeadError::TagMismatch);
        }
        Ok(n - pad)
    }

    /// Encrypts `msg` and returns `(ciphertext, tag)`.
    ///
    /// # Errors
    /// [`AeadError::InputTooLong`] if the associated data's bit length
    /// overflows `AL`.
    #[cfg(feature = "alloc")]
    pub fn encrypt(
        &self,
        iv: &[u8; 16],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), AeadError> {
        let mut ct = alloc::vec![0u8; Self::ciphertext_len(msg.len())];
        let mut tag = alloc::vec![0u8; Self::TAG_LEN];
        self.encrypt_into(iv, aad, msg, &mut ct, &mut tag)?;
        Ok((ct, tag))
    }

    /// Verifies `tag` and decrypts `ct`, returning the plaintext.
    ///
    /// # Errors
    /// As [`decrypt_into`](Self::decrypt_into).
    #[cfg(feature = "alloc")]
    pub fn decrypt(
        &self,
        iv: &[u8; 16],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, AeadError> {
        let mut out = alloc::vec![0u8; ct.len()];
        match self.decrypt_into(iv, aad, ct, tag, &mut out) {
            Ok(n) => {
                // Wipe the padding bytes before shrinking; `truncate` does
                // not clear the tail.
                out[n..].zeroize();
                out.truncate(n);
                Ok(out)
            }
            Err(e) => {
                out.zeroize();
                Err(e)
            }
        }
    }
}

// Both fields wipe themselves: `Hmac`'s `Drop` clears the keyed hashers and
// the cipher's `Drop` clears its key schedule.
impl<C: BlockCipher + Clone, D: Digest> ZeroizeOnDrop for CbcHmacSha2<C, D> {}

/// Constant-time PKCS#7 check of the final plaintext block: returns whether
/// the padding is well-formed (`1 <= p <= 16`, last `p` bytes all `p`) and
/// the padding length `p`. The length is only meaningful — and only meant to
/// be branched on — when the check passed.
fn pkcs7_check(block: &[u8; 16]) -> (Choice, usize) {
    let p = block[15];
    // `1 <= p <= 16`  ⇔  `p - 1 < 16` (with `0 - 1` wrapping to 255).
    let mut ok = p.wrapping_sub(1).ct_lt(&16);
    for (i, &b) in block.iter().enumerate() {
        // Byte `i` is padding iff `i >= 16 - p`, i.e. `!(i + p < 16)`.
        let is_pad = !(i as u16 + u16::from(p)).ct_lt(&16);
        ok &= !is_pad | b.ct_eq(&p);
    }
    (ok, usize::from(p))
}

macro_rules! rfc7518_alias {
    ($(#[$doc:meta])* $alias:ident = $cipher:ident, $digest:ident, key = $klen:literal) => {
        $(#[$doc])*
        pub type $alias = CbcHmacSha2<super::$cipher, crate::hash::$digest>;

        impl CbcHmacSha2<super::$cipher, crate::hash::$digest> {
            /// Combined key length in bytes (`MAC_KEY ‖ ENC_KEY`).
            pub const KEY_SIZE: usize = $klen;

            /// Creates the composite from the RFC 7518 concatenated key
            /// `MAC_KEY ‖ ENC_KEY`.
            pub fn new(key: &[u8; $klen]) -> Self {
                let (mac_key, enc_key) = key.split_at($klen / 2);
                let cipher = super::$cipher::new(enc_key.try_into().unwrap());
                Self::from_parts(cipher, mac_key).expect("MAC key half has the fixed length")
            }

            /// Fallible [`new`](Self::new): [`AeadError::InvalidKeyLength`]
            /// unless `key.len() == KEY_SIZE`.
            pub fn try_new(key: &[u8]) -> Result<Self, AeadError> {
                let key: &[u8; $klen] = key.try_into().map_err(|_| AeadError::InvalidKeyLength)?;
                Ok(Self::new(key))
            }
        }
    };
}

rfc7518_alias! {
    /// `A128CBC-HS256` (RFC 7518 §5.2.3): AES-128-CBC with HMAC-SHA-256,
    /// 32-byte key, 16-byte tag.
    A128CbcHs256 = Aes128, Sha256, key = 32
}

rfc7518_alias! {
    /// `A192CBC-HS384` (RFC 7518 §5.2.4): AES-192-CBC with HMAC-SHA-384,
    /// 48-byte key, 24-byte tag.
    A192CbcHs384 = Aes192, Sha384, key = 48
}

rfc7518_alias! {
    /// `A256CBC-HS512` (RFC 7518 §5.2.5): AES-256-CBC with HMAC-SHA-512,
    /// 64-byte key, 32-byte tag.
    A256CbcHs512 = Aes256, Sha512, key = 64
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::test_util::from_hex_vec;

    /// RFC 7518 Appendix B.1 (`A128CBC-HS256`).
    #[test]
    fn rfc7518_appendix_b() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let aead = A128CbcHs256::new(&key);
        let iv = crate::test_util::from_hex::<16>("1af38c2dc2b96ffdd86694092341bc04");
        let aad = b"The second principle of Auguste Kerckhoffs";
        let msg = b"A cipher system must not be required to be secret, and it must be \
                    able to fall into the hands of the enemy without inconvenience";
        let expect_ct = from_hex_vec(
            "c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9\
             a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c7032336\
             09d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b\
             384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade5\
             4b8851ffb598f7f80074b9473c82e2db",
        );
        let expect_tag = from_hex_vec("652c3fa36b0a7c5b3219fab3a30bc1c4");

        let (ct, tag) = aead.encrypt(&iv, aad, msg).unwrap();
        assert_eq!(ct, expect_ct);
        assert_eq!(tag, expect_tag);
        assert_eq!(aead.decrypt(&iv, aad, &ct, &tag).unwrap(), msg);

        let mut out = [0u8; 160];
        let n = aead.decrypt_into(&iv, aad, &ct, &tag, &mut out).unwrap();
        assert_eq!(&out[..n], msg);
    }

    #[test]
    fn pkcs7_check_table() {
        let mut block = [0x41u8; 16];
        block[15] = 1;
        assert!(bool::from(pkcs7_check(&block).0));
        for p in 1..=16u8 {
            let mut b = [0x41u8; 16];
            for x in &mut b[16 - usize::from(p)..] {
                *x = p;
            }
            let (ok, n) = pkcs7_check(&b);
            assert!(bool::from(ok), "p = {p}");
            assert_eq!(n, usize::from(p));
        }
        let mut b = [0x05u8; 16];
        b[12] = 0x04;
        assert!(!bool::from(pkcs7_check(&b).0), "one wrong pad byte");
        assert!(!bool::from(pkcs7_check(&[0u8; 16]).0), "p = 0");
        assert!(!bool::from(pkcs7_check(&[17u8; 16]).0), "p = 17");
    }

    #[test]
    fn round_trip_all_three_and_rejections() {
        let key: alloc::vec::Vec<u8> = (0u8..64).collect();
        let iv = [0x1au8; 16];
        let aad = b"header";
        macro_rules! run {
            ($t:ident, $klen:literal) => {{
                let aead = $t::new(key[..$klen].try_into().unwrap());
                for len in [0usize, 1, 15, 16, 17, 47, 48] {
                    let msg: alloc::vec::Vec<u8> = (0..len as u8).collect();
                    let (ct, tag) = aead.encrypt(&iv, aad, &msg).unwrap();
                    assert_eq!(ct.len(), $t::ciphertext_len(len));
                    assert_eq!(tag.len(), $t::TAG_LEN);
                    assert_eq!(aead.decrypt(&iv, aad, &ct, &tag).unwrap(), msg);
                    let mut bad = tag.clone();
                    bad[0] ^= 1;
                    assert_eq!(
                        aead.decrypt(&iv, aad, &ct, &bad),
                        Err(AeadError::TagMismatch)
                    );
                    assert_eq!(
                        aead.decrypt(&iv, b"other", &ct, &tag),
                        Err(AeadError::TagMismatch)
                    );
                    // A truncated tag is never a prefix match.
                    assert_eq!(
                        aead.decrypt(&iv, aad, &ct, &tag[..tag.len() - 1]),
                        Err(AeadError::TagMismatch)
                    );
                }
                assert!($t::try_new(&key[..$klen - 1]).is_err());
            }};
        }
        run!(A128CbcHs256, 32);
        run!(A192CbcHs384, 48);
        run!(A256CbcHs512, 64);
    }

    /// An authenticated ciphertext with bad padding (only a broken encryptor
    /// can produce one) is rejected with the buffer wiped.
    #[test]
    fn authentic_but_malformed_padding_is_rejected() {
        let key: alloc::vec::Vec<u8> = (0u8..32).collect();
        let aead = A128CbcHs256::new(key[..].try_into().unwrap());
        let iv = [7u8; 16];
        // Forge "ciphertext" = CBC encryption of a block whose padding byte
        // is 0, then MAC it ourselves.
        let mut block = [0u8; 16];
        Cbc::new(
            super::super::Aes128::new(key[16..].try_into().unwrap()),
            &iv,
        )
        .encrypt(&mut block)
        .unwrap();
        let mut h = crate::hash::HmacSha256::new(&key[..16]);
        h.update(&iv);
        h.update(&block);
        h.update(&0u64.to_be_bytes());
        let tag = h.finalize();
        let mut out = [0xaau8; 16];
        assert_eq!(
            aead.decrypt_into(&iv, &[], &block, &tag[..16], &mut out),
            Err(AeadError::TagMismatch)
        );
        assert_eq!(out, [0u8; 16], "wiped on padding failure");
        // And a non-block-multiple length is rejected the same way.
        let mut h = crate::hash::HmacSha256::new(&key[..16]);
        h.update(&iv);
        h.update(&block[..15]);
        h.update(&0u64.to_be_bytes());
        let tag = h.finalize();
        assert_eq!(
            aead.decrypt(&iv, &[], &block[..15], &tag[..16]),
            Err(AeadError::TagMismatch)
        );
        let _ = from_hex_vec("");
    }
}
