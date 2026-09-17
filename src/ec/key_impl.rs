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
    Algorithm, CryptParams, Error, PrivateKey, PublicKey, Secret, SigEncoding, SignParams,
    downcast_peer,
};
use crate::rng::CryptoRngCore;

use super::ecdh::EcdhPrivateKey;
use super::ecdsa::{EcdsaPrivateKey, EcdsaPublicKey, Signature};
use super::ed448::{Ed448PrivateKey, Ed448PublicKey, Ed448Signature};
use super::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use super::secp256k1_ecdsa::{
    Secp256k1EcdsaPrivateKey, Secp256k1EcdsaPublicKey, Secp256k1EcdsaSignature,
};
use super::sm2::{Sm2PrivateKey, Sm2PublicKey, Sm2Signature};
use super::x448::{X448PrivateKey, X448PublicKey};
use super::x25519::{X25519PrivateKey, X25519PublicKey};

// The runtime-hash -> concrete-digest bridge, and the facade's accepted-digest
// policy, live once in `key::params`.
use crate::key::dispatch_key_hash as dispatch_hash;

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
        // `try_sign_ctx` (not the panicking `sign_ctx`): a context longer
        // than 255 bytes — the `dom4` length octet — is a caller parameter
        // error, never a panic reachable through the facade.
        let sig = self
            .try_sign_ctx(msg, context)
            .map_err(|_| Error::InvalidParams)?;
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
// ECDSA over secp256k1 (fixed, no-alloc path) — honours hash, prehashed,
// sig_encoding. Same shape as the P-256 block above.
// ----------------------------------------------------------------------------

impl PrivateKey for Secp256k1EcdsaPrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Secp256k1
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

impl PublicKey for Secp256k1EcdsaPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Secp256k1
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
                Secp256k1EcdsaSignature::from_bytes(&bytes)
            }
            SigEncoding::Der => {
                Secp256k1EcdsaSignature::from_der(sig).map_err(|_| Error::Signature)?
            }
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
// `curve_alg` is total: every `CurveId` maps to a distinct `Algorithm`, so
// `algorithm()` never mislabels a curve (a caller gating on "NIST curves only"
// must be able to trust it). `ecdsa_alg` is the narrower capability gate: it
// returns `Some` for every curve the boxed ECDSA/ECDH ops support — the NIST
// curves (P-192 through P-521), the SEC 2 secp160/192/224 k1/r1/r2 curves,
// secp256k1 and the Brainpool curves, i.e. exactly the set
// `x509::CertSigner` signs with and the signature registry verifies — and
// `None` for the SM2 curve carried as plain ECDSA (SM2 keys go through
// `Sm2PrivateKey`, whose signature scheme is not ECDSA), so `sign` / `verify`
// / `agree` reject that one up front.
// ----------------------------------------------------------------------------

use super::boxed::{
    BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, BoxedEcdsaSignature,
};
use super::curves::CurveId;
use crate::bignum::BoxedUint;

/// The `Algorithm` a curve is reported as. Total by construction: a new
/// `CurveId` must be given its own `Algorithm`, never folded into another
/// curve's discriminant.
fn curve_alg(curve: CurveId) -> Algorithm {
    match curve {
        CurveId::P256 => Algorithm::P256,
        CurveId::P384 => Algorithm::P384,
        CurveId::P521 => Algorithm::P521,
        CurveId::Secp256k1 => Algorithm::Secp256k1,
        CurveId::Sm2p256v1 => Algorithm::Sm2,
        CurveId::BrainpoolP256r1 => Algorithm::BrainpoolP256r1,
        CurveId::BrainpoolP384r1 => Algorithm::BrainpoolP384r1,
        CurveId::BrainpoolP512r1 => Algorithm::BrainpoolP512r1,
        CurveId::Secp160k1 => Algorithm::Secp160k1,
        CurveId::Secp160r1 => Algorithm::Secp160r1,
        CurveId::Secp160r2 => Algorithm::Secp160r2,
        CurveId::Secp192k1 => Algorithm::Secp192k1,
        CurveId::P192 => Algorithm::P192,
        CurveId::Secp224k1 => Algorithm::Secp224k1,
        CurveId::P224 => Algorithm::P224,
        CurveId::BrainpoolP224r1 => Algorithm::BrainpoolP224r1,
        CurveId::BrainpoolP320r1 => Algorithm::BrainpoolP320r1,
    }
}

/// The curves whose boxed ECDSA / ECDH operations are supported here.
fn ecdsa_alg(curve: CurveId) -> Option<Algorithm> {
    match curve {
        CurveId::P256
        | CurveId::P384
        | CurveId::P521
        | CurveId::Secp256k1
        | CurveId::BrainpoolP256r1
        | CurveId::BrainpoolP384r1
        | CurveId::BrainpoolP512r1
        | CurveId::Secp160k1
        | CurveId::Secp160r1
        | CurveId::Secp160r2
        | CurveId::Secp192k1
        | CurveId::P192
        | CurveId::Secp224k1
        | CurveId::P224
        | CurveId::BrainpoolP224r1
        | CurveId::BrainpoolP320r1 => Some(curve_alg(curve)),
        CurveId::Sm2p256v1 => None,
    }
}

impl PrivateKey for BoxedEcdsaPrivateKey {
    fn algorithm(&self) -> Algorithm {
        curve_alg(self.curve())
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
        ecdsa_alg(curve).ok_or(Error::InvalidParams)?;
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
        curve_alg(self.curve())
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let curve = self.curve();
        ecdsa_alg(curve).ok_or(Error::InvalidParams)?;
        let mut p = params.reader();
        let hash = p.hash();
        let prehashed = p.prehashed();
        let enc = p.sig_encoding();
        p.finish()?;
        let signature = match enc {
            // No `from_bytes` on BoxedEcdsaSignature: split raw `r||s` halves of
            // `order_len()` -> BoxedUint -> from_components. The halves are
            // scalar-width, which is what `to_bytes` emits; on secp160k1/r1/r2
            // and secp224k1 that is one byte more than a coordinate.
            SigEncoding::Raw => {
                let olen = curve.order_len();
                if sig.len() != 2 * olen {
                    return Err(Error::Signature);
                }
                let r = BoxedUint::from_be_bytes(&sig[..olen]);
                let s = BoxedUint::from_be_bytes(&sig[olen..]);
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
        curve_alg(self.curve())
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn agree(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let alg = ecdsa_alg(self.curve()).ok_or(Error::InvalidParams)?;
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
