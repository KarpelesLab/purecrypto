//! Unified [`key`](crate::key) trait impls for the stateful XMSS / XMSS^MT keys.
//!
//! These are *stateful* one-time-key signers: each signature consumes a state
//! index that must be persisted before the key is reused. The private keys
//! therefore implement [`StatefulSigner`] (whose `sign` takes `&mut self`) and
//! the object-safe [`PrivateKey`] facade — but the facade's shared-reference
//! `sign` cannot advance the state, so it returns [`Error::StatefulKey`] to
//! point callers at [`StatefulSigner`]. The public keys implement
//! [`Verifier`] and [`PublicKey`].

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{Algorithm, Error, PrivateKey, PublicKey, SignParams, StatefulSigner, Verifier};
use crate::rng::CryptoRngCore;

use super::{XmssMtPrivateKey, XmssMtPublicKey, XmssPrivateKey, XmssPublicKey};

// ----------------------------------------------------------------------------
// XMSS single-tree
// ----------------------------------------------------------------------------

impl StatefulSigner for XmssPrivateKey {
    fn sign(&mut self, msg: &[u8], _rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
        // XMSS draws its randomizer from the secret PRF seed, not an external
        // RNG; `rng` is ignored.
        self.sign(msg).map_err(|_| Error::Signature)
    }

    fn remaining(&self) -> u64 {
        self.remaining()
    }
}

impl PrivateKey for XmssPrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Xmss
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

impl Verifier for XmssPublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8], _params: &SignParams<'_>) -> Result<(), Error> {
        if self.verify(msg, sig) {
            Ok(())
        } else {
            Err(Error::Signature)
        }
    }
}

impl PublicKey for XmssPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Xmss
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        Verifier::verify(self, msg, sig, params)
    }
}

// ----------------------------------------------------------------------------
// XMSS^MT multi-tree
// ----------------------------------------------------------------------------

impl StatefulSigner for XmssMtPrivateKey {
    fn sign(&mut self, msg: &[u8], _rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
        self.sign(msg).map_err(|_| Error::Signature)
    }

    fn remaining(&self) -> u64 {
        self.remaining()
    }
}

impl PrivateKey for XmssMtPrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::XmssMt
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

impl Verifier for XmssMtPublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8], _params: &SignParams<'_>) -> Result<(), Error> {
        if self.verify(msg, sig) {
            Ok(())
        } else {
            Err(Error::Signature)
        }
    }
}

impl PublicKey for XmssMtPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::XmssMt
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        Verifier::verify(self, msg, sig, params)
    }
}
