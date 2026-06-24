//! Unified [`key`](crate::key) trait impls for the stateful XMSS / XMSS^MT keys.
//!
//! These are *stateful* one-time-key signers: each signature consumes a state
//! index that must be persisted before the key is reused. The private keys
//! therefore implement only [`StatefulSigner`] (whose `sign` takes `&mut self`)
//! — they are deliberately **not** [`PrivateKey`](crate::key::PrivateKey)s,
//! since the facade's shared-reference `sign` cannot advance the state. The
//! public keys verify fine through a shared reference and implement
//! [`PublicKey`].

use alloc::vec::Vec;

use crate::key::{Algorithm, Error, PublicKey, SignParams, StatefulSigner};
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

impl PublicKey for XmssPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Xmss
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

impl PublicKey for XmssMtPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::XmssMt
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
