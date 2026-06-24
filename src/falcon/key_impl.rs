//! Unified [`key`](crate::key) trait impls for the Falcon (FN-DSA) keys.
//!
//! [`FalconPrivateKey`] implements [`Signer`] and the [`PrivateKey`] facade;
//! [`FalconPublicKey`] implements [`Verifier`] and the [`PublicKey`] facade.
//! The [`Algorithm`] is chosen from the key's [`Degree`](super::Degree):
//! Falcon-512 -> [`Algorithm::Falcon512`], Falcon-1024 ->
//! [`Algorithm::Falcon1024`]. The facade methods just delegate to the
//! capability impls.
//!
//! # `SignParams` usage
//!
//! Falcon has no context string and no deterministic variant, and fixes its
//! own hashing, so *all* [`SignParams`] fields — `hash`, `prehashed`,
//! `padding`, `context`, and `deterministic` — are ignored.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{Algorithm, Error, PrivateKey, PublicKey, SignParams, Signer, Verifier};
use crate::rng::CryptoRngCore;

use super::{Degree, FalconPrivateKey, FalconPublicKey};

fn degree_alg(degree: Degree) -> Algorithm {
    match degree {
        Degree::Falcon512 => Algorithm::Falcon512,
        Degree::Falcon1024 => Algorithm::Falcon1024,
    }
}

impl Signer for FalconPrivateKey {
    fn sign(
        &self,
        msg: &[u8],
        _params: &SignParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let mut rng = rng;
        Ok(self.sign(msg, &mut rng))
    }
}

impl PrivateKey for FalconPrivateKey {
    fn algorithm(&self) -> Algorithm {
        degree_alg(self.degree())
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
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

impl Verifier for FalconPublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8], _params: &SignParams<'_>) -> Result<(), Error> {
        match self.verify(msg, sig) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(Error::Signature),
        }
    }
}

impl PublicKey for FalconPublicKey {
    fn algorithm(&self) -> Algorithm {
        degree_alg(self.degree())
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        Verifier::verify(self, msg, sig, params)
    }
}
