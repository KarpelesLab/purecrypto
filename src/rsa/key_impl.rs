//! Unified [`key`](crate::key) facade impls for the RSA keys.
//!
//! Each key implements [`PrivateKey`]/[`PublicKey`] directly for the operations
//! it supports; unsupported operations fall through to the facade defaults
//! ([`Error::Unsupported`](crate::key::Error)). Per-call parameters are read
//! through the consume-tracking
//! [`SignParamsReader`](crate::key::SignParamsReader) /
//! [`CryptParamsReader`](crate::key::CryptParamsReader) so that any parameter
//! the algorithm does not honour is rejected loudly.
//!
//! Both the runtime-sized [`BoxedRsaPrivateKey`]/[`BoxedRsaPublicKey`] and the
//! const-generic [`RsaPrivateKey`]/[`RsaPublicKey`] are covered; they share the
//! same dispatch logic since they expose the same PKCS#1 / PSS / OAEP method
//! surface.
//!
//! RSA honours `hash` + `padding` (a [`RsaSigPadding`]) for signing and
//! verification, and `padding` (a [`RsaEncPadding`]) + `label` for encryption
//! and decryption. It does not read `prehashed`, `context`, `deterministic`, or
//! `sig_encoding`, so the reader's `finish()` rejects them if the caller set
//! them. [`SaltLen::Max`] has no signing API here and maps to
//! [`Error::InvalidParams`].
//!
//! # PKCS#1 v1.5 decryption is implicitly rejecting
//!
//! [`RsaEncPadding::Pkcs1v15`] decryption through this facade routes to
//! `decrypt_pkcs1v15_implicit`, **not** to the plain `decrypt_pkcs1v15`: bad
//! padding yields a key-bound pseudo-random plaintext of pseudo-random length
//! rather than [`Error::Decryption`]. A `Box<dyn PrivateKey>` is handed to
//! protocol code that has no way to know the padding outcome is secret, so the
//! error-vs-success distinction would be a ready-made Bleichenbacher / ROBOT
//! oracle (the ciphertext is attacker-chosen by definition). Callers that
//! genuinely want the failure reported — and that have audited their own
//! behaviour for the oracle — can call
//! [`BoxedRsaPrivateKey::decrypt_pkcs1v15`] directly.
//!
//! OAEP honours the `mgf1` hash only when it equals the label hash (the
//! profile PKCS#1 v2.2 and every real deployment use); any other combination
//! is rejected with [`Error::UnsupportedParam`] rather than silently
//! decrypting with the wrong mask generator.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{
    Algorithm, DecryptParams, EncryptParams, Error, Hash, PrivateKey, PublicKey, RsaEncPadding,
    RsaSigPadding, SaltLen, Secret, SignParams,
};
use crate::rng::CryptoRngCore;

use super::boxed::{BoxedRsaPrivateKey, BoxedRsaPublicKey};
use super::keys::{RsaPrivateKey, RsaPublicKey};

// The runtime-hash -> concrete-digest bridge, and the facade's accepted-digest
// policy, live once in `key::params`.
use crate::key::dispatch_key_hash as dispatch_hash;

/// The RSA OAEP implementations use one digest for both the label hash and
/// MGF1. A caller asking for a different MGF1 digest must be told so rather
/// than silently getting an incompatible ciphertext / a decryption failure.
fn check_oaep_mgf1(hash: Hash, mgf1: Hash) -> Result<(), Error> {
    if hash == mgf1 {
        Ok(())
    } else {
        Err(Error::UnsupportedParam { param: "mgf1" })
    }
}

// ----------------------------------------------------------------------------
// BoxedRsaPrivateKey
// ----------------------------------------------------------------------------

impl PrivateKey for BoxedRsaPrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Rsa
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
        let hash = p.hash();
        let padding = p.padding();
        p.finish()?;
        let mut rng = rng;
        match padding {
            RsaSigPadding::Pss { salt_len } => dispatch_hash!(hash, |D| {
                match salt_len {
                    SaltLen::DigestLength => self.sign_pss::<D, _>(msg, &mut rng),
                    SaltLen::Fixed(n) => self.sign_pss_with_salt_len::<D, _>(msg, n, &mut rng),
                    SaltLen::Max => return Err(Error::InvalidParams),
                }
            })
            .map_err(|_| Error::Signature),
            RsaSigPadding::Pkcs1v15 => dispatch_hash!(hash, |D| { self.sign_pkcs1v15::<D>(msg) })
                .map_err(|_| Error::Signature),
        }
    }
    fn decrypt(&self, ct: &[u8], params: &DecryptParams<'_>) -> Result<Secret, Error> {
        let mut p = params.reader();
        let padding = p.padding();
        let label = p.label();
        p.finish()?;
        let pt = match padding {
            RsaEncPadding::Oaep { hash, mgf1 } => {
                check_oaep_mgf1(hash, mgf1)?;
                dispatch_hash!(hash, |D| { self.decrypt_oaep::<D>(ct, label) })
            }
            // Implicit rejection, never the error-reporting variant: see the
            // module docs.
            RsaEncPadding::Pkcs1v15 => self.decrypt_pkcs1v15_implicit(ct),
        }
        .map_err(|_| Error::Decryption)?;
        Ok(Secret::from_bytes(pt))
    }
}

// ----------------------------------------------------------------------------
// BoxedRsaPublicKey
// ----------------------------------------------------------------------------

impl PublicKey for BoxedRsaPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Rsa
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let mut p = params.reader();
        let hash = p.hash();
        let padding = p.padding();
        p.finish()?;
        match padding {
            RsaSigPadding::Pss { salt_len } => dispatch_hash!(hash, |D| {
                match salt_len {
                    SaltLen::DigestLength => self.verify_pss::<D>(msg, sig),
                    SaltLen::Fixed(n) => self.verify_pss_with_salt_len::<D>(msg, sig, n),
                    SaltLen::Max => return Err(Error::InvalidParams),
                }
            })
            .map_err(|_| Error::Signature),
            RsaSigPadding::Pkcs1v15 => {
                dispatch_hash!(hash, |D| { self.verify_pkcs1v15::<D>(msg, sig) })
                    .map_err(|_| Error::Signature)
            }
        }
    }
    fn encrypt(
        &self,
        pt: &[u8],
        params: &EncryptParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let mut p = params.reader();
        let padding = p.padding();
        let label = p.label();
        p.finish()?;
        let mut rng = rng;
        match padding {
            RsaEncPadding::Oaep { hash, mgf1 } => {
                check_oaep_mgf1(hash, mgf1)?;
                dispatch_hash!(hash, |D| { self.encrypt_oaep::<D, _>(pt, label, &mut rng) })
            }
            RsaEncPadding::Pkcs1v15 => self.encrypt_pkcs1v15(pt, &mut rng),
        }
        .map_err(|_| Error::Encryption)
    }
}

// ----------------------------------------------------------------------------
// RsaPrivateKey<LIMBS>
// ----------------------------------------------------------------------------

impl<const LIMBS: usize> PrivateKey for RsaPrivateKey<LIMBS> {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Rsa
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
        let hash = p.hash();
        let padding = p.padding();
        p.finish()?;
        let mut rng = rng;
        match padding {
            RsaSigPadding::Pss { salt_len } => dispatch_hash!(hash, |D| {
                match salt_len {
                    SaltLen::DigestLength => self.sign_pss::<D, _>(msg, &mut rng),
                    SaltLen::Fixed(n) => self.sign_pss_with_salt_len::<D, _>(msg, n, &mut rng),
                    SaltLen::Max => return Err(Error::InvalidParams),
                }
            })
            .map_err(|_| Error::Signature),
            RsaSigPadding::Pkcs1v15 => dispatch_hash!(hash, |D| { self.sign_pkcs1v15::<D>(msg) })
                .map_err(|_| Error::Signature),
        }
    }
    fn decrypt(&self, ct: &[u8], params: &DecryptParams<'_>) -> Result<Secret, Error> {
        let mut p = params.reader();
        let padding = p.padding();
        let label = p.label();
        p.finish()?;
        let pt = match padding {
            RsaEncPadding::Oaep { hash, mgf1 } => {
                check_oaep_mgf1(hash, mgf1)?;
                dispatch_hash!(hash, |D| { self.decrypt_oaep::<D>(ct, label) })
            }
            // Implicit rejection, never the error-reporting variant: see the
            // module docs.
            RsaEncPadding::Pkcs1v15 => self.decrypt_pkcs1v15_implicit(ct),
        }
        .map_err(|_| Error::Decryption)?;
        Ok(Secret::from_bytes(pt))
    }
}

// ----------------------------------------------------------------------------
// RsaPublicKey<LIMBS>
// ----------------------------------------------------------------------------

impl<const LIMBS: usize> PublicKey for RsaPublicKey<LIMBS> {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Rsa
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let mut p = params.reader();
        let hash = p.hash();
        let padding = p.padding();
        p.finish()?;
        match padding {
            RsaSigPadding::Pss { salt_len } => dispatch_hash!(hash, |D| {
                match salt_len {
                    SaltLen::DigestLength => self.verify_pss::<D>(msg, sig),
                    SaltLen::Fixed(n) => self.verify_pss_with_salt_len::<D>(msg, sig, n),
                    SaltLen::Max => return Err(Error::InvalidParams),
                }
            })
            .map_err(|_| Error::Signature),
            RsaSigPadding::Pkcs1v15 => {
                dispatch_hash!(hash, |D| { self.verify_pkcs1v15::<D>(msg, sig) })
                    .map_err(|_| Error::Signature)
            }
        }
    }
    fn encrypt(
        &self,
        pt: &[u8],
        params: &EncryptParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let mut p = params.reader();
        let padding = p.padding();
        let label = p.label();
        p.finish()?;
        let mut rng = rng;
        match padding {
            RsaEncPadding::Oaep { hash, mgf1 } => {
                check_oaep_mgf1(hash, mgf1)?;
                dispatch_hash!(hash, |D| { self.encrypt_oaep::<D, _>(pt, label, &mut rng) })
            }
            RsaEncPadding::Pkcs1v15 => self.encrypt_pkcs1v15(pt, &mut rng),
        }
        .map_err(|_| Error::Encryption)
    }
}
