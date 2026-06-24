//! Unified [`key`](crate::key) trait impls for the stateful LMS / HSS keys.
//!
//! Like XMSS, these are *stateful* one-time-key signers, but their `sign`
//! additionally consumes randomness for the per-message LM-OTS randomizer, so
//! [`StatefulSigner::sign`] threads the supplied `rng` through. Each signature
//! consumes a state index that must be persisted before reuse. The private
//! keys implement only [`StatefulSigner`] — they are deliberately **not**
//! [`PrivateKey`](crate::key::PrivateKey)s, since the facade's
//! shared-reference `sign` cannot advance the state. The public keys verify
//! fine through a shared reference and implement [`PublicKey`].

use alloc::vec::Vec;

use crate::key::{Algorithm, Error, PublicKey, SignParams, StatefulSigner};
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

impl PublicKey for LmsPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Lms
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        params.reader().finish()?;
        if self.verify(msg, sig) {
            Ok(())
        } else {
            Err(Error::Signature)
        }
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

impl PublicKey for HssPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Hss
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        params.reader().finish()?;
        if self.verify(msg, sig) {
            Ok(())
        } else {
            Err(Error::Signature)
        }
    }
}
