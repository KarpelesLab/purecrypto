//! Unified [`key`](crate::key) trait impls for the SLH-DSA (FIPS 205) keys.
//!
//! The single [`PrivateKey`](super::PrivateKey) implements [`Signer`] and the
//! [`PrivateKey`] facade; [`PublicKey`](super::PublicKey) implements
//! [`Verifier`] and the [`PublicKey`] facade. Both carry their parameter set at
//! run time; every set maps to the single [`Algorithm::SlhDsa`] discriminant.
//! The facade methods just delegate to the capability impls.
//!
//! # `SignParams` usage
//!
//! SLH-DSA fixes its own hashing, so only two [`SignParams`] fields apply:
//!
//! * `context` — passed through as the FIPS 205 context string (≤ 255 bytes).
//! * `deterministic` — selects the deterministic (zero-randomness) signing
//!   variant when set; otherwise the hedged variant draws from `rng`.
//!
//! `hash`, `prehashed`, and `padding` are ignored.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{
    Algorithm, Error, PrivateKey as KeyPrivateKey, PublicKey as KeyPublicKey, SignParams, Signer,
    Verifier,
};
use crate::rng::CryptoRngCore;

use super::{PrivateKey, PublicKey};

impl Signer for PrivateKey {
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let sig = if params.deterministic {
            self.sign_deterministic(msg, params.context)
        } else {
            let mut rng = rng;
            self.sign(&mut rng, msg, params.context)
        };
        sig.map_err(|_| Error::Signature)
    }
}

impl KeyPrivateKey for PrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::SlhDsa
    }
    fn public_key(&self) -> Result<Box<dyn KeyPublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        Signer::sign(self, msg, params, rng)
    }
}

impl Verifier for PublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        if self.verify(sig, msg, params.context) {
            Ok(())
        } else {
            Err(Error::Signature)
        }
    }
}

impl KeyPublicKey for PublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::SlhDsa
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        Verifier::verify(self, msg, sig, params)
    }
}
