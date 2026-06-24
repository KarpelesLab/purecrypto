//! Unified [`key`](crate::key) trait impls for the stateful LMS / HSS keys.
//!
//! Like XMSS, these are *stateful* one-time-key signers, but their `sign`
//! additionally consumes randomness for the per-message LM-OTS randomizer, so
//! [`StatefulSigner::sign`] threads the supplied `rng` through. Each signature
//! consumes a state index that must be persisted before reuse. The private
//! keys implement [`StatefulSigner`] and the [`PrivateKey`] facade (whose
//! shared-reference `sign` returns [`Error::StatefulKey`]); the public keys
//! implement [`Verifier`] and [`PublicKey`].

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{Algorithm, Error, PrivateKey, PublicKey, SignParams, StatefulSigner, Verifier};
use crate::rng::CryptoRngCore;

use super::{HssPrivateKey, HssPublicKey, LmsPrivateKey, LmsPublicKey};

// ----------------------------------------------------------------------------
// LMS single-level
// ----------------------------------------------------------------------------

impl StatefulSigner for LmsPrivateKey {
    fn sign(&mut self, msg: &[u8], rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
        let mut rng = rng;
        self.sign(&mut rng, msg).map_err(|_| Error::Signature)
    }

    fn remaining(&self) -> u64 {
        self.remaining()
    }
}

impl PrivateKey for LmsPrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Lms
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn sign(
        &self,
        _msg: &[u8],
        _params: &SignParams<'_>,
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        // The shared-reference facade cannot advance the one-time-key state;
        // direct callers must hold `&mut self` and use `StatefulSigner::sign`.
        Err(Error::StatefulKey)
    }
}

impl Verifier for LmsPublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8], _params: &SignParams<'_>) -> Result<(), Error> {
        if self.verify(msg, sig) {
            Ok(())
        } else {
            Err(Error::Signature)
        }
    }
}

impl PublicKey for LmsPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Lms
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        Verifier::verify(self, msg, sig, params)
    }
}

// ----------------------------------------------------------------------------
// HSS hierarchical LMS
// ----------------------------------------------------------------------------

impl StatefulSigner for HssPrivateKey {
    fn sign(&mut self, msg: &[u8], rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
        let mut rng = rng;
        self.sign(&mut rng, msg).map_err(|_| Error::Signature)
    }

    fn remaining(&self) -> u64 {
        self.remaining()
    }
}

impl PrivateKey for HssPrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Hss
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn sign(
        &self,
        _msg: &[u8],
        _params: &SignParams<'_>,
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::StatefulKey)
    }
}

impl Verifier for HssPublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8], _params: &SignParams<'_>) -> Result<(), Error> {
        if self.verify(msg, sig) {
            Ok(())
        } else {
            Err(Error::Signature)
        }
    }
}

impl PublicKey for HssPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Hss
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        Verifier::verify(self, msg, sig, params)
    }
}
