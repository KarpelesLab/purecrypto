//! Unified [`key`](crate::key) facade impls for the ML-DSA (FIPS 204) keys.
//!
//! Each per-level key implements [`PrivateKey`]/[`PublicKey`] directly for the
//! operations it supports; per-call parameters are read through the
//! consume-tracking [`SignParamsReader`](crate::key::SignParamsReader) so that
//! any parameter the algorithm does not honour is rejected loudly.
//!
//! # `SignParams` usage
//!
//! ML-DSA fixes its own hashing, so only two [`SignParams`] fields apply:
//!
//! * `context` — passed through as the FIPS 204 context string (≤ 255 bytes).
//! * `deterministic` — selects the deterministic (zero-randomness) signing
//!   variant when set; otherwise the hedged variant draws from `rng`.
//!
//! Setting `hash`, `prehashed`, `padding`, or `sig_encoding` is rejected.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{Algorithm, Error, PrivateKey, PublicKey, SignParams};
use crate::rng::CryptoRngCore;

use super::{
    MlDsa44PrivateKey, MlDsa44PublicKey, MlDsa65PrivateKey, MlDsa65PublicKey, MlDsa87PrivateKey,
    MlDsa87PublicKey,
};

macro_rules! ml_dsa_key_impl {
    ($sk:ty, $pk:ty, $alg:expr) => {
        impl PrivateKey for $sk {
            fn algorithm(&self) -> Algorithm {
                $alg
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

        impl PublicKey for $pk {
            fn algorithm(&self) -> Algorithm {
                $alg
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
    };
}

ml_dsa_key_impl!(MlDsa44PrivateKey, MlDsa44PublicKey, Algorithm::MlDsa44);
ml_dsa_key_impl!(MlDsa65PrivateKey, MlDsa65PublicKey, Algorithm::MlDsa65);
ml_dsa_key_impl!(MlDsa87PrivateKey, MlDsa87PublicKey, Algorithm::MlDsa87);
