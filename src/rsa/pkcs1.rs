//! PKCS#1 v1.5 encryption and signatures (RFC 8017).
//!
//! # Security note
//!
//! PKCS#1 v1.5 **encryption** padding is susceptible to Bleichenbacher-style
//! padding-oracle attacks; the decryption here removes padding in a
//! best-effort manner but the scheme is fundamentally fragile. Prefer OAEP for
//! new protocols. PKCS#1 v1.5 **signatures** remain in wide use and are
//! provided for interoperability.

use alloc::vec;
use alloc::vec::Vec;

use super::emsa::{self, RawPrivate, RawPublic};
use super::{Error, RsaPrivateKey, RsaPublicKey};
use crate::bignum::Uint;
use crate::hash::Digest;
use crate::rng::RngCore;

/// Big-endian `k`-byte serialization of a fixed-width `Uint`.
fn uint_to_k_bytes<const LIMBS: usize>(value: &Uint<LIMBS>) -> Vec<u8> {
    let mut buf = vec![0u8; LIMBS * 8];
    value.write_be_bytes(&mut buf);
    buf
}

impl<const LIMBS: usize> RawPublic for RsaPublicKey<LIMBS> {
    fn key_size(&self) -> usize {
        LIMBS * 8
    }
    fn modulus_bits(&self) -> usize {
        self.modulus().bit_len()
    }
    fn raw_public(&self, m: &[u8]) -> Vec<u8> {
        uint_to_k_bytes(&self.raw(&Uint::<LIMBS>::from_be_bytes(m)))
    }
}

impl<const LIMBS: usize> RawPrivate for RsaPrivateKey<LIMBS> {
    fn key_size(&self) -> usize {
        LIMBS * 8
    }
    fn modulus_bits(&self) -> usize {
        self.modulus().bit_len()
    }
    fn raw_private(&self, c: &[u8]) -> Vec<u8> {
        uint_to_k_bytes(&self.raw(&Uint::<LIMBS>::from_be_bytes(c)))
    }
    fn secret_seed(&self) -> [u8; 32] {
        self.secret_seed_bytes()
    }
}

/// A hash usable with PKCS#1 v1.5 signatures: it carries the DER-encoded
/// `DigestInfo` prefix that precedes the hash value in the signature encoding.
pub trait Pkcs1Digest: Digest {
    /// The DER `DigestInfo` prefix (algorithm identifier + OCTET STRING header)
    /// for this hash.
    const DIGEST_INFO_PREFIX: &'static [u8];
}

impl Pkcs1Digest for crate::hash::Sha1 {
    // RFC 8017 §9.2 / RFC 3447 §9.2: DigestInfo prefix for SHA-1.
    const DIGEST_INFO_PREFIX: &'static [u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
}

impl Pkcs1Digest for crate::hash::Sha256 {
    const DIGEST_INFO_PREFIX: &'static [u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
}

impl Pkcs1Digest for crate::hash::Sha384 {
    const DIGEST_INFO_PREFIX: &'static [u8] = &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
}

impl Pkcs1Digest for crate::hash::Sha512 {
    const DIGEST_INFO_PREFIX: &'static [u8] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];
}

impl Pkcs1Digest for crate::hash::Sha224 {
    const DIGEST_INFO_PREFIX: &'static [u8] = &[
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
        0x05, 0x00, 0x04, 0x1c,
    ];
}

impl<const LIMBS: usize> RsaPublicKey<LIMBS> {
    /// Encrypts `msg` with PKCS#1 v1.5 (RFC 8017 §7.2.1). Returns the
    /// `LIMBS*8`-byte ciphertext.
    ///
    /// # Errors
    /// [`Error::MessageTooLong`] if `msg.len() > k - 11`, where `k = LIMBS*8`.
    pub fn encrypt_pkcs1v15<R: RngCore>(&self, msg: &[u8], rng: &mut R) -> Result<Vec<u8>, Error> {
        emsa::encrypt_pkcs1v15(self, msg, rng)
    }

    /// Encrypts `msg` with RSAES-OAEP (RFC 8017 §7.1.1), using hash `D` for both
    /// the label hash and MGF1, and the empty label by default — pass `label`
    /// to bind context. Returns the `LIMBS*8`-byte ciphertext.
    ///
    /// # Errors
    /// [`Error::MessageTooLong`] if `msg.len() > k - 2·hLen - 2`.
    pub fn encrypt_oaep<D: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        label: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        emsa::encrypt_oaep::<D, _, _>(self, msg, label, rng)
    }

    /// Verifies a PKCS#1 v1.5 signature over `msg`, hashing with `D`.
    ///
    /// # Errors
    /// [`Error::Verification`] if the signature is invalid;
    /// [`Error::InvalidLength`] if `sig` is not `LIMBS*8` bytes.
    pub fn verify_pkcs1v15<D: Pkcs1Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        emsa::verify_pkcs1v15::<D, _>(self, msg, sig)
    }
}

impl<const LIMBS: usize> RsaPrivateKey<LIMBS> {
    /// Decrypts a PKCS#1 v1.5 ciphertext (RFC 8017 §7.2.2) and returns the
    /// recovered message bytes.
    ///
    /// # Errors
    /// [`Error::InvalidLength`] if `ct` is not `LIMBS*8` bytes;
    /// [`Error::Decryption`] if the recovered padding is malformed.
    ///
    /// # Security
    ///
    /// The padding check itself is constant-time, but the returned `Vec`'s
    /// **length** (and the success / [`Error::Decryption`] distinction)
    /// reveals the position of the PKCS#1 v1.5 separator byte. An adaptive
    /// chosen-ciphertext attacker who observes the protocol response can
    /// mount a Bleichenbacher / Marvin / ROBOT-class oracle.
    ///
    /// For TLS 1.0–1.2 RSA key transport, CMS / PKCS#7, JOSE RSA1_5, and
    /// other contexts where the plaintext length is known at the protocol
    /// layer, use [`decrypt_pkcs1v15_session`](Self::decrypt_pkcs1v15_session)
    /// instead. It returns a fixed-width, key-bound synthetic plaintext on
    /// padding failure so the failure mode is indistinguishable from
    /// success.
    ///
    /// For new code, prefer OAEP via [`decrypt_oaep`](Self::decrypt_oaep).
    pub fn decrypt_pkcs1v15(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
        emsa::decrypt_pkcs1v15(self, ct)
    }

    /// Decrypts a PKCS#1 v1.5 ciphertext with implicit rejection (RFC 8017
    /// §7.2.2 Note, the "Marvin" / TLS 1.2-style mitigation against
    /// Bleichenbacher's attack).
    ///
    /// On padding failure, returns a deterministic pseudorandom buffer of
    /// length `expected_len` derived from the ciphertext bytes and a
    /// per-key secret. The caller (and any external observer) cannot
    /// distinguish a real decryption from a synthetic one in timing, error
    /// path, or output length — the only way to defeat a Bleichenbacher
    /// oracle when the caller's downstream behavior would otherwise leak
    /// the padding outcome.
    ///
    /// On success the returned `Vec` is **truncated or padded** to
    /// `expected_len`: PKCS#1 v1.5 padding alone cannot recover the
    /// intended plaintext length, so the protocol must agree on it (e.g.
    /// TLS RSA key transport: `expected_len = 48` for the 48-byte
    /// pre-master secret).
    ///
    /// # Errors
    /// Only [`Error::InvalidLength`] when `ct.len() != LIMBS*8`. All other
    /// failure modes are folded into the synthetic plaintext.
    pub fn decrypt_pkcs1v15_session(
        &self,
        ct: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>, Error> {
        emsa::decrypt_pkcs1v15_session(self, ct, expected_len)
    }

    /// Decrypts an RSAES-OAEP ciphertext (RFC 8017 §7.1.2). Hash `D` must match
    /// the one used at encryption; `label` must match the encryptor's label
    /// (empty by default). The padding-check path is constant-time over the
    /// decrypted EM so that a bad ciphertext is not distinguishable in timing
    /// from a bad label.
    pub fn decrypt_oaep<D: Digest>(&self, ct: &[u8], label: &[u8]) -> Result<Vec<u8>, Error> {
        emsa::decrypt_oaep::<D, _>(self, ct, label)
    }

    /// Produces a PKCS#1 v1.5 signature over `msg`, hashing with `D`
    /// (RFC 8017 §8.2.1).
    ///
    /// # Errors
    /// [`Error::MessageTooLong`] if the modulus is too small for the digest.
    pub fn sign_pkcs1v15<D: Pkcs1Digest>(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        emsa::sign_pkcs1v15::<D, _>(self, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha224, Sha256};
    use crate::rng::HmacDrbg;
    use crate::test_util::rsa_test_key_a;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        // RSA-2048: k = 256, so up to 245 message bytes.
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-enc", b"nonce", &[]);

        let msg = b"hello rsa";
        let ct = pk.encrypt_pkcs1v15(msg, &mut r).unwrap();
        assert_eq!(ct.len(), 256);
        assert_ne!(&ct[..], msg);
        assert_eq!(key.decrypt_pkcs1v15(&ct).unwrap(), msg);
    }

    #[test]
    fn encrypt_rejects_overlong() {
        let pk = rsa_test_key_a().public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-enc2", b"nonce", &[]);
        // k - 11 = 245; 246 bytes must be rejected.
        assert_eq!(
            pk.encrypt_pkcs1v15(&[0u8; 246], &mut r),
            Err(Error::MessageTooLong)
        );
    }

    #[test]
    fn oaep_roundtrip_sha256() {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-oaep", b"nonce", &[]);

        // RSA-2048 + SHA-256: k - 2*hLen - 2 = 256 - 64 - 2 = 190 max message bytes.
        let msg = b"OAEP round-trip with the default empty label";
        let ct = pk.encrypt_oaep::<Sha256, _>(msg, b"", &mut r).unwrap();
        assert_eq!(ct.len(), 256);
        assert_ne!(&ct[..msg.len()], msg);
        let pt = key.decrypt_oaep::<Sha256>(&ct, b"").unwrap();
        assert_eq!(&pt[..], msg);
    }

    #[test]
    fn oaep_distinct_ciphertexts() {
        // OAEP draws a fresh random seed per encryption, so two encryptions of
        // the same message produce distinct ciphertexts.
        let pk = rsa_test_key_a().public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-oaep-rand", b"nonce", &[]);
        let msg = b"x";
        let c1 = pk.encrypt_oaep::<Sha256, _>(msg, b"", &mut r).unwrap();
        let c2 = pk.encrypt_oaep::<Sha256, _>(msg, b"", &mut r).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn oaep_label_binds() {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-oaep-label", b"nonce", &[]);
        let msg = b"context-bound";
        let ct = pk
            .encrypt_oaep::<Sha256, _>(msg, b"label-A", &mut r)
            .unwrap();
        // Same ciphertext, different label => decryption rejects.
        assert_eq!(
            key.decrypt_oaep::<Sha256>(&ct, b"label-B"),
            Err(Error::Decryption)
        );
        // Matching label succeeds.
        assert_eq!(
            &key.decrypt_oaep::<Sha256>(&ct, b"label-A").unwrap()[..],
            msg
        );
    }

    #[test]
    fn oaep_rejects_overlong() {
        let pk = rsa_test_key_a().public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-oaep-long", b"nonce", &[]);
        // RSA-2048 + SHA-256: max message = 190 bytes; 191 must be rejected.
        assert_eq!(
            pk.encrypt_oaep::<Sha256, _>(&[0u8; 191], b"", &mut r),
            Err(Error::MessageTooLong)
        );
    }

    #[test]
    fn oaep_rejects_tampered() {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-oaep-tamper", b"nonce", &[]);
        let mut ct = pk
            .encrypt_oaep::<Sha256, _>(b"to be tampered", b"", &mut r)
            .unwrap();
        ct[42] ^= 1;
        assert_eq!(key.decrypt_oaep::<Sha256>(&ct, b""), Err(Error::Decryption));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = rsa_test_key_a();
        let pk = key.public_key();

        let msg = b"sign me";
        let sig = key.sign_pkcs1v15::<Sha256>(msg).unwrap();
        assert_eq!(sig.len(), 256);
        assert!(pk.verify_pkcs1v15::<Sha256>(msg, &sig).is_ok());

        // Wrong message fails.
        assert_eq!(
            pk.verify_pkcs1v15::<Sha256>(b"other", &sig),
            Err(Error::Verification)
        );
        // Tampered signature fails.
        let mut bad = sig.clone();
        bad[40] ^= 1;
        assert_eq!(
            pk.verify_pkcs1v15::<Sha256>(msg, &bad),
            Err(Error::Verification)
        );
        // Wrong hash algorithm fails (different DigestInfo).
        assert_eq!(
            pk.verify_pkcs1v15::<Sha224>(msg, &sig),
            Err(Error::Verification)
        );
    }

    // ---- RSA-2: implicit-rejection (decrypt_pkcs1v15_session) ----

    /// Round-trip: a real PKCS#1 v1.5 ciphertext decrypts to its original
    /// plaintext when `expected_len` matches.
    #[test]
    fn session_decrypt_recovers_message_on_valid_ct() {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-session-ok", b"nonce", &[]);
        let msg = [0xa5u8; 48]; // 48-byte premaster-secret-shaped message.
        let ct = pk.encrypt_pkcs1v15(&msg, &mut r).unwrap();
        let out = key.decrypt_pkcs1v15_session(&ct, msg.len()).unwrap();
        assert_eq!(out, msg);
    }

    /// A ciphertext whose decryption yields malformed padding must not
    /// surface an error: the session API returns an `expected_len`-byte
    /// pseudorandom plaintext instead, indistinguishable in shape from
    /// success. This is the core anti-Bleichenbacher property.
    #[test]
    fn session_decrypt_returns_synthetic_on_bad_padding() {
        let key = rsa_test_key_a();
        // Any 256-byte buffer that decrypts under `key` to something
        // not starting with 0x00 0x02. The all-ones ciphertext below
        // overwhelmingly fits.
        let bogus_ct = [0x7eu8; 256];
        let out = key.decrypt_pkcs1v15_session(&bogus_ct, 48).unwrap();
        assert_eq!(out.len(), 48);
    }

    /// The synthetic plaintext is deterministic for a given (key, ct,
    /// expected_len) triple, so repeated calls under the same long-term
    /// secret produce identical output. This is what lets a protocol layer
    /// treat the failure path as "as if decryption succeeded".
    #[test]
    fn session_decrypt_is_deterministic_under_same_key() {
        let key = rsa_test_key_a();
        let bogus_ct = [0x3cu8; 256];
        let a = key.decrypt_pkcs1v15_session(&bogus_ct, 48).unwrap();
        let b = key.decrypt_pkcs1v15_session(&bogus_ct, 48).unwrap();
        assert_eq!(a, b);
    }

    /// `Error::InvalidLength` is the only failure surfaced (ciphertext
    /// length mismatch is public, not a padding-dependent secret).
    #[test]
    fn session_decrypt_rejects_wrong_length_ct() {
        let key = rsa_test_key_a();
        let short = [0u8; 255];
        assert_eq!(
            key.decrypt_pkcs1v15_session(&short, 48),
            Err(Error::InvalidLength)
        );
    }
}
