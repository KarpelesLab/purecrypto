//! RSA-PSS signatures (RFC 8017 §8.1, EMSA-PSS with MGF1).
//!
//! The salt length equals the digest length (the common profile, used by
//! TLS 1.3). Gated on `alloc`. The encoding logic lives in [`super::emsa`];
//! these are thin wrappers over the const-generic keys.

use alloc::vec::Vec;

use super::emsa;
use super::{Error, RsaPrivateKey, RsaPublicKey};
use crate::hash::Digest;
use crate::rng::RngCore;

impl<const LIMBS: usize> RsaPrivateKey<LIMBS> {
    /// Signs `msg` with RSA-PSS, hashing with `D` and a salt of `D`'s output
    /// length.
    pub fn sign_pss<D: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        emsa::sign_pss::<D, _, R>(self, msg, rng)
    }
}

impl<const LIMBS: usize> RsaPublicKey<LIMBS> {
    /// Verifies an RSA-PSS signature over `msg`, hashing with `D`.
    pub fn verify_pss<D: Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        emsa::verify_pss::<D, _>(self, msg, sig)
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
}
