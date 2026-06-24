//! Unified [`key`](crate::key) trait impls for the ML-DSA (FIPS 204) keys.
//!
//! Each per-level private key implements [`Signer`] and the [`PrivateKey`]
//! facade; each public key implements [`Verifier`] and the [`PublicKey`]
//! facade. The facade methods just delegate to the capability impls.
//!
//! # `SignParams` usage
//!
//! ML-DSA fixes its own hashing, so only two [`SignParams`] fields apply:
//!
//! * `context` — passed through as the FIPS 204 context string (≤ 255 bytes).
//! * `deterministic` — selects the deterministic (zero-randomness) signing
//!   variant when set; otherwise the hedged variant draws from `rng`.
//!
//! `hash`, `prehashed`, and `padding` are ignored.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{Algorithm, Error, PrivateKey, PublicKey, SignParams, Signer, Verifier};
use crate::rng::CryptoRngCore;

use super::{
    MlDsa44PrivateKey, MlDsa44PublicKey, MlDsa65PrivateKey, MlDsa65PublicKey, MlDsa87PrivateKey,
    MlDsa87PublicKey,
};

macro_rules! ml_dsa_key_impl {
    ($sk:ty, $pk:ty, $alg:expr) => {
        impl Signer for $sk {
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
                Signer::sign(self, msg, params, rng)
            }
        }

        impl Verifier for $pk {
            fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
                if self.verify(sig, msg, params.context) {
                    Ok(())
                } else {
                    Err(Error::Signature)
                }
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
                Verifier::verify(self, msg, sig, params)
            }
        }
    };
}

ml_dsa_key_impl!(MlDsa44PrivateKey, MlDsa44PublicKey, Algorithm::MlDsa44);
ml_dsa_key_impl!(MlDsa65PrivateKey, MlDsa65PublicKey, Algorithm::MlDsa65);
ml_dsa_key_impl!(MlDsa87PrivateKey, MlDsa87PublicKey, Algorithm::MlDsa87);
