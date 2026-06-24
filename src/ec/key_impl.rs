//! Unified [`key`](crate::key) facade impls for the elliptic-curve keys.
//!
//! Each key implements [`PrivateKey`]/[`PublicKey`] directly for the operations
//! it supports; unsupported operations fall through to the facade defaults
//! ([`Error::Unsupported`](crate::key::Error)). Per-call parameters are read
//! through the consume-tracking [`SignParamsReader`](crate::key::SignParamsReader)
//! so that any parameter the algorithm does not honour is rejected loudly.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{
    Algorithm, CryptParams, Error, Hash, PrivateKey, PublicKey, Secret, SigEncoding, SignParams,
    downcast_peer,
};
use crate::rng::CryptoRngCore;

use super::ecdh::EcdhPrivateKey;
use super::ecdsa::{EcdsaPrivateKey, EcdsaPublicKey, Signature};
use super::ed448::{Ed448PrivateKey, Ed448PublicKey, Ed448Signature};
use super::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use super::sm2::{Sm2PrivateKey, Sm2PublicKey, Sm2Signature};
use super::x448::{X448PrivateKey, X448PublicKey};
use super::x25519::{X25519PrivateKey, X25519PublicKey};

/// Runs `$body` with `$d` aliased to the concrete digest named by `$h`
/// (a [`Hash`]). Bridges the runtime hash selector into the generic
/// `sign::<D>` / `verify::<D>` methods.
macro_rules! dispatch_hash {
    ($h:expr, |$d:ident| $body:block) => {
        match $h {
            Hash::Sha256 => {
                type $d = crate::hash::Sha256;
                $body
            }
            Hash::Sha384 => {
                type $d = crate::hash::Sha384;
                $body
            }
            Hash::Sha512 => {
                type $d = crate::hash::Sha512;
                $body
            }
            Hash::Sha1 => {
                type $d = crate::hash::Sha1;
                $body
            }
        }
    };
}

// ----------------------------------------------------------------------------
// Ed25519 — fixes its own hash, no params honoured
// ----------------------------------------------------------------------------

impl PrivateKey for Ed25519PrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        params.reader().finish()?;
        Ok(self.sign(msg).to_bytes().to_vec())
    }
}

impl PublicKey for Ed25519PublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        params.reader().finish()?;
        let bytes: [u8; 64] = sig.try_into().map_err(|_| Error::Signature)?;
        self.verify(msg, &Ed25519Signature::from_bytes(bytes))
            .map_err(|_| Error::Signature)
    }
}

// ----------------------------------------------------------------------------
// Ed448 — honours `context`
// ----------------------------------------------------------------------------

impl PrivateKey for Ed448PrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed448
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let mut p = params.reader();
        let context = p.context();
        p.finish()?;
        let sig = if context.is_empty() {
            self.sign(msg)
        } else {
            self.sign_ctx(msg, context)
        };
        Ok(sig.to_bytes().to_vec())
    }
}

impl PublicKey for Ed448PublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed448
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let mut p = params.reader();
        let context = p.context();
        p.finish()?;
        let bytes: [u8; 114] = sig.try_into().map_err(|_| Error::Signature)?;
        let signature = Ed448Signature::from_bytes(bytes);
        let res = if context.is_empty() {
            self.verify(msg, &signature)
        } else {
            self.verify_ctx(msg, &signature, context)
        };
        res.map_err(|_| Error::Signature)
    }
}

// ----------------------------------------------------------------------------
// ECDSA over P-256 (fixed) — honours hash, prehashed, sig_encoding
// ----------------------------------------------------------------------------

impl PrivateKey for EcdsaPrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::P256
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let mut p = params.reader();
        let hash = p.hash();
        let prehashed = p.prehashed();
        let enc = p.sig_encoding();
        p.finish()?;
        let sig = dispatch_hash!(hash, |D| {
            if prehashed {
                self.sign_prehash::<D>(msg)
            } else {
                self.sign::<D>(msg)
            }
        })
        .map_err(|_| Error::Signature)?;
        Ok(match enc {
            SigEncoding::Raw => sig.to_bytes().to_vec(),
            SigEncoding::Der => sig.to_der(),
        })
    }
}

impl PublicKey for EcdsaPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::P256
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let mut p = params.reader();
        let hash = p.hash();
        let prehashed = p.prehashed();
        let enc = p.sig_encoding();
        p.finish()?;
        let signature = match enc {
            SigEncoding::Raw => {
                let bytes: [u8; 64] = sig.try_into().map_err(|_| Error::Signature)?;
                Signature::from_bytes(&bytes)
            }
            SigEncoding::Der => Signature::from_der(sig).map_err(|_| Error::Signature)?,
        };
        if prehashed {
            self.verify_prehash(msg, &signature)
        } else {
            dispatch_hash!(hash, |D| { self.verify::<D>(msg, &signature) })
        }
        .map_err(|_| Error::Signature)
    }
}

// ----------------------------------------------------------------------------
// ECDH over P-256 (fixed)
// ----------------------------------------------------------------------------

impl PrivateKey for EcdhPrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::P256
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn agree(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let peer = downcast_peer::<EcdsaPublicKey>(peer, Algorithm::P256)?;
        let shared = self.diffie_hellman(peer).map_err(|_| Error::KeyAgreement)?;
        Ok(Secret::from_bytes(shared.to_vec()))
    }
}

// ----------------------------------------------------------------------------
// X25519
// ----------------------------------------------------------------------------

impl PrivateKey for X25519PrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::X25519
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(X25519PublicKey::from_bytes(self.public_key())))
    }
    fn agree(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let peer = downcast_peer::<X25519PublicKey>(peer, Algorithm::X25519)?;
        let shared = self
            .diffie_hellman(peer.as_bytes())
            .map_err(|_| Error::KeyAgreement)?;
        Ok(Secret::from_bytes(shared.to_vec()))
    }
}

impl PublicKey for X25519PublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::X25519
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

// ----------------------------------------------------------------------------
// X448
// ----------------------------------------------------------------------------

impl PrivateKey for X448PrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::X448
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(X448PublicKey::from_bytes(self.public_key())))
    }
    fn agree(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let peer = downcast_peer::<X448PublicKey>(peer, Algorithm::X448)?;
        let shared = self
            .diffie_hellman(peer.as_bytes())
            .map_err(|_| Error::KeyAgreement)?;
        Ok(Secret::from_bytes(shared.to_vec()))
    }
}

impl PublicKey for X448PublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::X448
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

// ----------------------------------------------------------------------------
// SM2 — honours `context` (signer ID) and `sig_encoding`
// ----------------------------------------------------------------------------

impl PrivateKey for Sm2PrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Sm2
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
        let id = sm2_id(p.context());
        let enc = p.sig_encoding();
        p.finish()?;
        let mut rng = rng;
        let sig = self.sign(msg, id, &mut rng).map_err(|_| Error::Signature)?;
        Ok(match enc {
            SigEncoding::Raw => sig.to_bytes(),
            SigEncoding::Der => sig.to_der(),
        })
    }
    fn decrypt(&self, ct: &[u8], params: &CryptParams<'_>) -> Result<Secret, Error> {
        params.reader().finish()?;
        let pt = self.decrypt(ct).map_err(|_| Error::Decryption)?;
        Ok(Secret::from_bytes(pt))
    }
}

impl PublicKey for Sm2PublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Sm2
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let mut p = params.reader();
        let id = sm2_id(p.context());
        let enc = p.sig_encoding();
        p.finish()?;
        let signature = match enc {
            SigEncoding::Raw => Sm2Signature::from_bytes(sig).map_err(|_| Error::Signature)?,
            SigEncoding::Der => Sm2Signature::from_der(sig).map_err(|_| Error::Signature)?,
        };
        self.verify(msg, &signature, id)
            .map_err(|_| Error::Signature)
    }
    fn encrypt(
        &self,
        pt: &[u8],
        params: &CryptParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        params.reader().finish()?;
        let mut rng = rng;
        self.encrypt(pt, &mut rng).map_err(|_| Error::Encryption)
    }
}

// ----------------------------------------------------------------------------
// Runtime-curve ("boxed") ECDSA / ECDH
//
// `curve_alg` maps the four supported curves to `Algorithm`; an unsupported
// curve (e.g. Brainpool or the SM2 curve carried as ECDSA) returns `None`, so
// the capability ops reject it up front while `algorithm()` falls back to P256.
// ----------------------------------------------------------------------------

use super::boxed::{
    BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, BoxedEcdsaSignature,
};
use super::curves::CurveId;
use crate::bignum::BoxedUint;

fn curve_alg(curve: CurveId) -> Option<Algorithm> {
    match curve {
        CurveId::P256 => Some(Algorithm::P256),
        CurveId::P384 => Some(Algorithm::P384),
        CurveId::P521 => Some(Algorithm::P521),
        CurveId::Secp256k1 => Some(Algorithm::Secp256k1),
        _ => None,
    }
}

impl PrivateKey for BoxedEcdsaPrivateKey {
    fn algorithm(&self) -> Algorithm {
        curve_alg(self.curve()).unwrap_or(Algorithm::P256)
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let curve = self.curve();
        curve_alg(curve).ok_or(Error::InvalidParams)?;
        let mut p = params.reader();
        let hash = p.hash();
        let prehashed = p.prehashed();
        let enc = p.sig_encoding();
        p.finish()?;
        let sig = dispatch_hash!(hash, |D| {
            if prehashed {
                self.sign_prehash::<D>(msg)
            } else {
                self.sign::<D>(msg)
            }
        })
        .map_err(|_| Error::Signature)?;
        Ok(match enc {
            SigEncoding::Raw => sig.to_bytes(curve),
            SigEncoding::Der => sig.to_der(curve),
        })
    }
}

impl PublicKey for BoxedEcdsaPublicKey {
    fn algorithm(&self) -> Algorithm {
        curve_alg(self.curve()).unwrap_or(Algorithm::P256)
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let curve = self.curve();
        curve_alg(curve).ok_or(Error::InvalidParams)?;
        let mut p = params.reader();
        let hash = p.hash();
        let prehashed = p.prehashed();
        let enc = p.sig_encoding();
        p.finish()?;
        let signature = match enc {
            // No `from_bytes` on BoxedEcdsaSignature: split raw `r||s` halves of
            // `field_len()` -> BoxedUint -> from_components.
            SigEncoding::Raw => {
                let flen = curve.field_len();
                if sig.len() != 2 * flen {
                    return Err(Error::Signature);
                }
                let r = BoxedUint::from_be_bytes(&sig[..flen]);
                let s = BoxedUint::from_be_bytes(&sig[flen..]);
                BoxedEcdsaSignature::from_components(r, s)
            }
            SigEncoding::Der => BoxedEcdsaSignature::from_der(sig).map_err(|_| Error::Signature)?,
        };
        if prehashed {
            self.verify_prehash(msg, &signature)
        } else {
            dispatch_hash!(hash, |D| { self.verify::<D>(msg, &signature) })
        }
        .map_err(|_| Error::Signature)
    }
}

impl PrivateKey for BoxedEcdhPrivateKey {
    fn algorithm(&self) -> Algorithm {
        curve_alg(self.public_key().curve()).unwrap_or(Algorithm::P256)
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn agree(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let alg = curve_alg(self.public_key().curve()).ok_or(Error::InvalidParams)?;
        let peer = downcast_peer::<BoxedEcdsaPublicKey>(peer, alg)?;
        let shared = self.diffie_hellman(peer).map_err(|_| Error::KeyAgreement)?;
        Ok(Secret::from_bytes(shared))
    }
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

/// The SM2 signer ID: the supplied context, or [`super::sm2::DEFAULT_ID`] when
/// empty.
fn sm2_id(context: &[u8]) -> &[u8] {
    if context.is_empty() {
        super::sm2::DEFAULT_ID
    } else {
        context
    }
}
