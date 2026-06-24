//! Unified [`key`](crate::key) trait impls for the finite-field DH keys.
//!
//! [`DhPrivateKey`] implements [`KeyAgreement`] plus the object-safe
//! [`PrivateKey`] facade; [`DhPublicKey`] implements the [`PublicKey`] facade.
//! Finite-field DH supports neither signing nor encryption, so those facade
//! operations fall through to the defaulted [`Error::Unsupported`](crate::key::Error).

use alloc::boxed::Box;

use crate::key::{Algorithm, Error, KeyAgreement, PrivateKey, PublicKey, Secret, downcast_peer};

use super::key::{DhPrivateKey, DhPublicKey};

impl KeyAgreement for DhPrivateKey {
    fn make_secret(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let peer = downcast_peer::<DhPublicKey>(peer, Algorithm::DhModp)?;
        let ss = self.shared_secret(peer).map_err(|_| Error::KeyAgreement)?;
        Ok(Secret::from_bytes(ss.into_bytes()))
    }
}

impl PrivateKey for DhPrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::DhModp
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn make_secret(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        KeyAgreement::make_secret(self, peer)
    }
}

impl PublicKey for DhPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::DhModp
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
