//! RSA-PSS signatures (RFC 8017 §8.1, EMSA-PSS with MGF1).
//!
//! The default salt length equals the digest length (the common profile, used
//! by TLS 1.3 and the X.509 PSS parameter set); the `*_with_salt_len` /
//! `*_any_salt` variants relax that for general interop. Gated on `alloc`. The
//! encoding logic lives in [`super::emsa`]; these are thin wrappers over the
//! const-generic keys.

use alloc::vec::Vec;

use super::emsa;
use super::{Error, RsaPrivateKey, RsaPublicKey};
use crate::hash::Digest;
use crate::rng::RngCore;

impl<const LIMBS: usize> RsaPrivateKey<LIMBS> {
    /// Signs `msg` with RSA-PSS, hashing with `D` and a salt of `D`'s output
    /// length (the TLS 1.3 / X.509 profile).
    pub fn sign_pss<D: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        emsa::sign_pss::<D, _, R>(self, msg, rng)
    }

    /// Signs `msg` with RSA-PSS using an explicit salt length (in octets).
    /// `salt_len == 0` is permitted; the maximum is bounded by the modulus
    /// size (`Error::MessageTooLong` otherwise).
    pub fn sign_pss_with_salt_len<D: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        salt_len: usize,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        emsa::sign_pss_with_salt_len::<D, _, R>(self, msg, salt_len, rng)
    }
}

impl<const LIMBS: usize> RsaPublicKey<LIMBS> {
    /// Verifies an RSA-PSS signature over `msg`, hashing with `D` and
    /// requiring the salt length to equal `D`'s output length (the strict
    /// TLS 1.3 / X.509 profile).
    pub fn verify_pss<D: Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        emsa::verify_pss::<D, _>(self, msg, sig)
    }

    /// Verifies an RSA-PSS signature over `msg`, requiring the salt to be
    /// exactly `salt_len` octets.
    pub fn verify_pss_with_salt_len<D: Digest>(
        &self,
        msg: &[u8],
        sig: &[u8],
        salt_len: usize,
    ) -> Result<(), Error> {
        emsa::verify_pss_with_salt_len::<D, _>(self, msg, sig, salt_len)
    }

    /// Verifies an RSA-PSS signature over `msg`, recovering the salt length
    /// from the encoded message (accepts any valid salt length). Use this for
    /// interop with signers that do not use the salt-length == digest-length
    /// profile.
    pub fn verify_pss_any_salt<D: Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        emsa::verify_pss_any_salt::<D, _>(self, msg, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::test_util::rsa_test_key_a;

    #[test]
    fn sign_verify_roundtrip() {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-pss", b"nonce", &[]);

        let sig = key.sign_pss::<Sha256, _>(b"pss message", &mut r).unwrap();
        pk.verify_pss::<Sha256>(b"pss message", &sig).unwrap();

        // Wrong message fails.
        assert_eq!(
            pk.verify_pss::<Sha256>(b"other", &sig),
            Err(Error::Verification)
        );
        // Tampered signature fails.
        let mut bad = sig.clone();
        bad[20] ^= 1;
        assert_eq!(
            pk.verify_pss::<Sha256>(b"pss message", &bad),
            Err(Error::Verification)
        );
    }

    #[test]
    fn pss_is_randomized() {
        // Two signatures over the same message differ (random salt).
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-pss-rand", b"nonce", &[]);
        let a = key.sign_pss::<Sha256, _>(b"m", &mut r).unwrap();
        let b = key.sign_pss::<Sha256, _>(b"m", &mut r).unwrap();
        assert_ne!(a, b);
        pk.verify_pss::<Sha256>(b"m", &a).unwrap();
        pk.verify_pss::<Sha256>(b"m", &b).unwrap();
    }

    #[test]
    fn explicit_salt_len_roundtrip() {
        // SHA-256 output is 32; exercise sLen = 0, 32 (default) and 56.
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-pss-salt", b"nonce", &[]);
        for &slen in &[0usize, 32, 56] {
            let sig = key
                .sign_pss_with_salt_len::<Sha256, _>(b"m", slen, &mut r)
                .unwrap();
            // Auto-recovery accepts any salt length.
            pk.verify_pss_any_salt::<Sha256>(b"m", &sig).unwrap();
            // Exact-length verify accepts only the matching length.
            pk.verify_pss_with_salt_len::<Sha256>(b"m", &sig, slen)
                .unwrap();
            assert_eq!(
                pk.verify_pss_with_salt_len::<Sha256>(b"m", &sig, slen + 1),
                Err(Error::Verification),
                "sLen={slen}: verify with wrong length must fail"
            );
        }
    }

    #[test]
    fn strict_verify_rejects_nonstandard_salt() {
        // A signature made with sLen != hLen must be rejected by the strict
        // default `verify_pss` (TLS 1.3 / X.509 mandate sLen == hLen), but
        // accepted by `verify_pss_any_salt`.
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-pss-strict", b"nonce", &[]);
        let sig = key
            .sign_pss_with_salt_len::<Sha256, _>(b"m", 16, &mut r)
            .unwrap();
        assert_eq!(
            pk.verify_pss::<Sha256>(b"m", &sig),
            Err(Error::Verification),
            "strict verify must reject sLen=16 (!= 32)"
        );
        pk.verify_pss_any_salt::<Sha256>(b"m", &sig).unwrap();

        // Conversely, the strict default still accepts a default (sLen=hLen)
        // signature, and any_salt agrees.
        let sig_std = key.sign_pss::<Sha256, _>(b"m", &mut r).unwrap();
        pk.verify_pss::<Sha256>(b"m", &sig_std).unwrap();
        pk.verify_pss_any_salt::<Sha256>(b"m", &sig_std).unwrap();
    }
}
