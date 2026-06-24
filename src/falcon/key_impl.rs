//! Unified [`key`](crate::key) facade impls for the Falcon (FN-DSA) keys.
//!
//! [`FalconPrivateKey`]/[`FalconPublicKey`] implement the [`key`](crate::key)
//! facade directly. The [`Algorithm`] is chosen from the key's
//! [`Degree`](super::Degree): Falcon-512 -> [`Algorithm::Falcon512`],
//! Falcon-1024 -> [`Algorithm::Falcon1024`].
//!
//! # `SignParams` usage
//!
//! Falcon has no context string and no deterministic variant, and fixes its
//! own hashing, so it honours *no* [`SignParams`] fields: setting any one of
//! them is rejected loudly via the consume-tracking reader.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{Algorithm, Error, PrivateKey, PublicKey, SignParams};
use crate::rng::CryptoRngCore;

use super::{Degree, FalconPrivateKey, FalconPublicKey};

fn degree_alg(degree: Degree) -> Algorithm {
    match degree {
        Degree::Falcon512 => Algorithm::Falcon512,
        Degree::Falcon1024 => Algorithm::Falcon1024,
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
        params.reader().finish()?;
        let mut rng = rng;
        Ok(self.sign(msg, &mut rng))
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
        params.reader().finish()?;
        match self.verify(msg, sig) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(Error::Signature),
        }
    }
}
