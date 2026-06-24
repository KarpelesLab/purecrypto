//! Unified [`key`](crate::key) facade impls for the SLH-DSA (FIPS 205) keys.
//!
//! The single [`PrivateKey`](super::PrivateKey)/[`PublicKey`](super::PublicKey)
//! implement the [`key`](crate::key) facade directly. Both carry their
//! parameter set at run time; every set maps to the single
//! [`Algorithm::SlhDsa`] discriminant. Per-call parameters are read through the
//! consume-tracking [`SignParamsReader`](crate::key::SignParamsReader) so that
//! any parameter the algorithm does not honour is rejected loudly.
//!
//! # `SignParams` usage
//!
//! SLH-DSA fixes its own hashing, so only two [`SignParams`] fields apply:
//!
//! * `context` — passed through as the FIPS 205 context string (≤ 255 bytes).
//! * `deterministic` — selects the deterministic (zero-randomness) signing
//!   variant when set; otherwise the hedged variant draws from `rng`.
//!
//! Setting `hash`, `prehashed`, `padding`, or `sig_encoding` is rejected.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{
    Algorithm, Error, PrivateKey as KeyPrivateKey, PublicKey as KeyPublicKey, SignParams,
};
use crate::rng::CryptoRngCore;

use super::{PrivateKey, PublicKey};

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
        let mut p = params.reader();
        let context = p.context();
        let deterministic = p.deterministic();
        p.finish()?;
        let sig = if deterministic {
            self.sign_deterministic(msg, context)
        } else {
            let mut rng = rng;
            self.sign(&mut rng, msg, context)
        };
        sig.map_err(|_| Error::Signature)
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
        let mut p = params.reader();
        let context = p.context();
        p.finish()?;
        if self.verify(sig, msg, context) {
            Ok(())
        } else {
            Err(Error::Signature)
        }
    }
}
