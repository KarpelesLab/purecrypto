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

use super::{Error, RsaPrivateKey, RsaPublicKey};
use crate::bignum::Uint;
use crate::ct::ConstantTimeEq;
use crate::hash::Digest;
use crate::rng::RngCore;

/// A hash usable with PKCS#1 v1.5 signatures: it carries the DER-encoded
/// `DigestInfo` prefix that precedes the hash value in the signature encoding.
pub trait Pkcs1Digest: Digest {
    /// The DER `DigestInfo` prefix (algorithm identifier + OCTET STRING header)
    /// for this hash.
    const DIGEST_INFO_PREFIX: &'static [u8];
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
        let k = LIMBS * 8;
        if msg.len() + 11 > k {
            return Err(Error::MessageTooLong);
        }
        // EM = 0x00 || 0x02 || PS || 0x00 || M, with PS >= 8 nonzero bytes.
        let ps_len = k - msg.len() - 3;
        let mut em = vec![0u8; k];
        em[1] = 0x02;
        fill_nonzero(&mut em[2..2 + ps_len], rng);
        // em[2 + ps_len] stays 0x00 (separator)
        em[k - msg.len()..].copy_from_slice(msg);

        let m = Uint::<LIMBS>::from_be_bytes(&em);
        let c = self.raw(&m);
        Ok(to_bytes(&c, k))
    }

    /// Verifies a PKCS#1 v1.5 signature over `msg`, hashing with `D`.
    ///
    /// # Errors
    /// [`Error::Verification`] if the signature is invalid;
    /// [`Error::InvalidLength`] if `sig` is not `LIMBS*8` bytes.
    pub fn verify_pkcs1v15<D: Pkcs1Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let k = LIMBS * 8;
        if sig.len() != k {
            return Err(Error::InvalidLength);
        }
        let s = Uint::<LIMBS>::from_be_bytes(sig);
        let m = self.raw(&s);
        let em = to_bytes(&m, k);

        let expected = encode_signature::<D>(msg, k)?;
        if bool::from(em.as_slice().ct_eq(expected.as_slice())) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

impl<const LIMBS: usize> RsaPrivateKey<LIMBS> {
    /// Decrypts a PKCS#1 v1.5 ciphertext (RFC 8017 §7.2.2).
    ///
    /// # Errors
    /// [`Error::InvalidLength`] if `ct` is not `LIMBS*8` bytes;
    /// [`Error::Decryption`] if the recovered padding is malformed.
    ///
    /// See the module note: this is padding-oracle sensitive.
    pub fn decrypt_pkcs1v15(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
        let k = LIMBS * 8;
        if ct.len() != k {
            return Err(Error::InvalidLength);
        }
        let c = Uint::<LIMBS>::from_be_bytes(ct);
        let m = self.raw(&c);
        let em = to_bytes(&m, k);

        // EM = 0x00 || 0x02 || PS || 0x00 || M
        if em[0] != 0x00 || em[1] != 0x02 {
            return Err(Error::Decryption);
        }
        let mut sep = None;
        for (i, &b) in em.iter().enumerate().skip(2) {
            if b == 0x00 {
                sep = Some(i);
                break;
            }
        }
        match sep {
            Some(i) if i >= 10 => Ok(em[i + 1..].to_vec()), // PS is >= 8 bytes
            _ => Err(Error::Decryption),
        }
    }

    /// Produces a PKCS#1 v1.5 signature over `msg`, hashing with `D`
    /// (RFC 8017 §8.2.1).
    ///
    /// # Errors
    /// [`Error::MessageTooLong`] if the modulus is too small for the digest.
    pub fn sign_pkcs1v15<D: Pkcs1Digest>(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let k = LIMBS * 8;
        let em = encode_signature::<D>(msg, k)?;
        let m = Uint::<LIMBS>::from_be_bytes(&em);
        let s = self.raw(&m);
        Ok(to_bytes(&s, k))
    }
}

/// Builds the EMSA-PKCS1-v1_5 encoded message:
/// `0x00 || 0x01 || PS(0xff…) || 0x00 || DigestInfo`.
fn encode_signature<D: Pkcs1Digest>(msg: &[u8], k: usize) -> Result<Vec<u8>, Error> {
    let digest = D::digest(msg);
    let t_len = D::DIGEST_INFO_PREFIX.len() + digest.as_ref().len();
    if t_len + 11 > k {
        return Err(Error::MessageTooLong);
    }
    let ps_len = k - t_len - 3;
    let mut em = vec![0u8; k];
    em[1] = 0x01;
    for b in &mut em[2..2 + ps_len] {
        *b = 0xff;
    }
    // em[2 + ps_len] stays 0x00 (separator)
    let t_start = 2 + ps_len + 1;
    em[t_start..t_start + D::DIGEST_INFO_PREFIX.len()].copy_from_slice(D::DIGEST_INFO_PREFIX);
    em[t_start + D::DIGEST_INFO_PREFIX.len()..].copy_from_slice(digest.as_ref());
    Ok(em)
}

/// Serializes `value` as a big-endian `k`-byte vector.
fn to_bytes<const LIMBS: usize>(value: &Uint<LIMBS>, k: usize) -> Vec<u8> {
    let mut buf = vec![0u8; LIMBS * 8];
    value.write_be_bytes(&mut buf);
    debug_assert_eq!(k, LIMBS * 8);
    buf
}

/// Fills `dst` with uniformly random nonzero bytes.
fn fill_nonzero<R: RngCore>(dst: &mut [u8], rng: &mut R) {
    for slot in dst.iter_mut() {
        loop {
            let mut b = [0u8; 1];
            rng.fill_bytes(&mut b);
            if b[0] != 0 {
                *slot = b[0];
                break;
            }
        }
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
}
