//! Unified [`key`](crate::key) trait impls for the elliptic-curve keys.
//!
//! Each key implements the fine-grained capability trait(s) it supports
//! (`Signer`/`Verifier`/`KeyAgreement`) plus the object-safe facade
//! (`PrivateKey`/`PublicKey`); the facade methods just delegate to the
//! capability impls. Operations a key cannot perform fall through to the
//! facade's defaulted [`Error::Unsupported`](crate::key::Error).

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{
    Algorithm, DecryptParams, Decryptor, EncryptParams, Encryptor, Error, Hash, KeyAgreement,
    PrivateKey, PublicKey, Secret, SignParams, Signer, Verifier, downcast_peer,
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
/// (a [`Hash`]). Used to bridge the runtime hash selector into the generic
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
// Ed25519
// ----------------------------------------------------------------------------

impl Signer for Ed25519PrivateKey {
    fn sign(
        &self,
        msg: &[u8],
        _params: &SignParams<'_>,
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        // Ed25519 is deterministic and fixes its own hash (SHA-512); it has no
        // prehash or context variant here, so `params` and `rng` are ignored.
        Ok(self.sign(msg).to_bytes().to_vec())
    }
}

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
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        Signer::sign(self, msg, params, rng)
    }
}

impl Verifier for Ed25519PublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8], _params: &SignParams<'_>) -> Result<(), Error> {
        let bytes: [u8; 64] = sig.try_into().map_err(|_| Error::Signature)?;
        self.verify(msg, &Ed25519Signature::from_bytes(bytes))
            .map_err(|_| Error::Signature)
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
        Verifier::verify(self, msg, sig, params)
    }
}

// ----------------------------------------------------------------------------
// Ed448
// ----------------------------------------------------------------------------

impl Signer for Ed448PrivateKey {
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let sig = if params.context.is_empty() {
            self.sign(msg)
        } else {
            self.sign_ctx(msg, params.context)
        };
        Ok(sig.to_bytes().to_vec())
    }
}

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
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        Signer::sign(self, msg, params, rng)
    }
}

impl Verifier for Ed448PublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let bytes: [u8; 114] = sig.try_into().map_err(|_| Error::Signature)?;
        let signature = Ed448Signature::from_bytes(bytes);
        let res = if params.context.is_empty() {
            self.verify(msg, &signature)
        } else {
            self.verify_ctx(msg, &signature, params.context)
        };
        res.map_err(|_| Error::Signature)
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
        Verifier::verify(self, msg, sig, params)
    }
}

// ----------------------------------------------------------------------------
// ECDSA over P-256 (fixed)
// ----------------------------------------------------------------------------

impl Signer for EcdsaPrivateKey {
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let sig = dispatch_hash!(params.hash, |D| {
            if params.prehashed {
                self.sign_prehash::<D>(msg)
            } else {
                self.sign::<D>(msg)
            }
        })
        .map_err(|_| Error::Signature)?;
        Ok(sig.to_bytes().to_vec())
    }
}

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
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        Signer::sign(self, msg, params, rng)
    }
}

impl Verifier for EcdsaPublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let bytes: [u8; 64] = sig.try_into().map_err(|_| Error::Signature)?;
        let signature = Signature::from_bytes(&bytes);
        if params.prehashed {
            self.verify_prehash(msg, &signature)
        } else {
            dispatch_hash!(params.hash, |D| { self.verify::<D>(msg, &signature) })
        }
        .map_err(|_| Error::Signature)
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
        Verifier::verify(self, msg, sig, params)
    }
}

// ----------------------------------------------------------------------------
// ECDH over P-256 (fixed)
// ----------------------------------------------------------------------------

impl KeyAgreement for EcdhPrivateKey {
    fn make_secret(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let peer = downcast_peer::<EcdsaPublicKey>(peer, Algorithm::P256)?;
        let shared = self.diffie_hellman(peer).map_err(|_| Error::KeyAgreement)?;
        Ok(Secret::from_bytes(shared.to_vec()))
    }
}

impl PrivateKey for EcdhPrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::P256
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn make_secret(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        KeyAgreement::make_secret(self, peer)
    }
}

// ----------------------------------------------------------------------------
// X25519
// ----------------------------------------------------------------------------

impl KeyAgreement for X25519PrivateKey {
    fn make_secret(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let peer = downcast_peer::<X25519PublicKey>(peer, Algorithm::X25519)?;
        let shared = self
            .diffie_hellman(peer.as_bytes())
            .map_err(|_| Error::KeyAgreement)?;
        Ok(Secret::from_bytes(shared.to_vec()))
    }
}

impl PrivateKey for X25519PrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::X25519
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(X25519PublicKey::from_bytes(self.public_key())))
    }
    fn make_secret(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        KeyAgreement::make_secret(self, peer)
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

impl KeyAgreement for X448PrivateKey {
    fn make_secret(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let peer = downcast_peer::<X448PublicKey>(peer, Algorithm::X448)?;
        let shared = self
            .diffie_hellman(peer.as_bytes())
            .map_err(|_| Error::KeyAgreement)?;
        Ok(Secret::from_bytes(shared.to_vec()))
    }
}

impl PrivateKey for X448PrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::X448
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(X448PublicKey::from_bytes(self.public_key())))
    }
    fn make_secret(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        KeyAgreement::make_secret(self, peer)
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
// SM2
// ----------------------------------------------------------------------------

impl Signer for Sm2PrivateKey {
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let id = sm2_id(params.context);
        let mut rng = rng;
        let sig = self.sign(msg, id, &mut rng).map_err(|_| Error::Signature)?;
        Ok(sig.to_bytes())
    }
}

impl Decryptor for Sm2PrivateKey {
    fn decrypt(&self, ct: &[u8], _params: &DecryptParams<'_>) -> Result<Secret, Error> {
        let pt = self.decrypt(ct).map_err(|_| Error::Decryption)?;
        Ok(Secret::from_bytes(pt))
    }
}

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
        Signer::sign(self, msg, params, rng)
    }
    fn decrypt(&self, ct: &[u8], params: &DecryptParams<'_>) -> Result<Secret, Error> {
        Decryptor::decrypt(self, ct, params)
    }
}

impl Verifier for Sm2PublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let signature = Sm2Signature::from_bytes(sig).map_err(|_| Error::Signature)?;
        self.verify(msg, &signature, sm2_id(params.context))
            .map_err(|_| Error::Signature)
    }
}

impl Encryptor for Sm2PublicKey {
    fn encrypt(
        &self,
        pt: &[u8],
        _params: &EncryptParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let mut rng = rng;
        self.encrypt(pt, &mut rng).map_err(|_| Error::Encryption)
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
        Verifier::verify(self, msg, sig, params)
    }
    fn encrypt(
        &self,
        pt: &[u8],
        params: &EncryptParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        Encryptor::encrypt(self, pt, params, rng)
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

// ----------------------------------------------------------------------------
// Runtime-curve ("boxed") ECDSA / ECDH
// ----------------------------------------------------------------------------
//
// The const-generic impls above are P-256 only. These cover the runtime-curve
// `Boxed*` keys, which carry their `CurveId` at runtime and serve every
// supported curve. The unified `Algorithm` enum, however, only names the four
// curves these traits target — P-256, P-384, P-521, secp256k1. `curve_alg`
// maps those four to their `Algorithm`; any other curve (SM2, Brainpool — both
// constructible as `BoxedEcdsa*` keys) returns `None`.
//
// Resolution of the "unsupported curve" question: `algorithm()` cannot fail, so
// it falls back to `Algorithm::P256` for an unmapped curve, but every capability
// op (`sign`/`verify`/`make_secret`) first calls `curve_alg(..)` and returns
// `Error::InvalidParams` when the curve has no `Algorithm`. So an SM2 or
// Brainpool boxed key never silently signs/verifies/agrees through these unified
// traits — the operation is rejected up front. (Brainpool ECDSA has a dedicated
// home via the concrete `BoxedEcdsa*` API and the `der`/x509 layers; these
// unified traits are intentionally scoped to the four `Algorithm` curves.)

use super::boxed::{
    BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, BoxedEcdsaSignature,
};
use super::curves::CurveId;
use crate::bignum::BoxedUint;

/// Maps the four curves that have a unified [`Algorithm`] discriminant; any
/// other [`CurveId`] (SM2, Brainpool) returns `None` and is rejected by the
/// capability ops below.
fn curve_alg(curve: CurveId) -> Option<Algorithm> {
    match curve {
        CurveId::P256 => Some(Algorithm::P256),
        CurveId::P384 => Some(Algorithm::P384),
        CurveId::P521 => Some(Algorithm::P521),
        CurveId::Secp256k1 => Some(Algorithm::Secp256k1),
        _ => None,
    }
}

impl Signer for BoxedEcdsaPrivateKey {
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        // Reject curves outside the unified `Algorithm` set (e.g. Brainpool):
        // their boxed keys can sign via the concrete API, but not through here.
        let curve = self.curve();
        curve_alg(curve).ok_or(Error::InvalidParams)?;
        // RFC 6979 deterministic nonce — no `rng` needed.
        let sig = dispatch_hash!(params.hash, |D| {
            if params.prehashed {
                self.sign_prehash::<D>(msg)
            } else {
                self.sign::<D>(msg)
            }
        })
        .map_err(|_| Error::Signature)?;
        Ok(sig.to_bytes(curve))
    }
}

impl PrivateKey for BoxedEcdsaPrivateKey {
    fn algorithm(&self) -> Algorithm {
        // `algorithm()` is infallible; an unmapped curve falls back to P256.
        // The capability ops above reject unmapped curves before doing work.
        curve_alg(self.curve()).unwrap_or(Algorithm::P256)
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

impl Verifier for BoxedEcdsaPublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let curve = self.curve();
        curve_alg(curve).ok_or(Error::InvalidParams)?;
        // Reconstruct the signature from the fixed-width `r || s` encoding
        // (`BoxedEcdsaSignature` has no `from_bytes`): two `field_len`-byte
        // big-endian halves -> `BoxedUint` -> `from_components`.
        let flen = curve.field_len();
        if sig.len() != 2 * flen {
            return Err(Error::Signature);
        }
        let r = BoxedUint::from_be_bytes(&sig[..flen]);
        let s = BoxedUint::from_be_bytes(&sig[flen..]);
        let signature = BoxedEcdsaSignature::from_components(r, s);
        if params.prehashed {
            self.verify_prehash(msg, &signature)
        } else {
            dispatch_hash!(params.hash, |D| { self.verify::<D>(msg, &signature) })
        }
        .map_err(|_| Error::Signature)
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
        Verifier::verify(self, msg, sig, params)
    }
}

impl KeyAgreement for BoxedEcdhPrivateKey {
    fn make_secret(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let alg = curve_alg(self.public_key().curve()).ok_or(Error::InvalidParams)?;
        let peer = downcast_peer::<BoxedEcdsaPublicKey>(peer, alg)?;
        let shared = self.diffie_hellman(peer).map_err(|_| Error::KeyAgreement)?;
        Ok(Secret::from_bytes(shared))
    }
}

impl PrivateKey for BoxedEcdhPrivateKey {
    fn algorithm(&self) -> Algorithm {
        curve_alg(self.public_key().curve()).unwrap_or(Algorithm::P256)
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn make_secret(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        KeyAgreement::make_secret(self, peer)
    }
}
