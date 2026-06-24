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

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{
    Algorithm, DecryptParams, EncryptParams, Error, Hash, PrivateKey, PublicKey, RsaEncPadding,
    RsaSigPadding, SaltLen, Secret, SignParams,
};
use crate::rng::CryptoRngCore;

use super::boxed::{BoxedRsaPrivateKey, BoxedRsaPublicKey};
use super::keys::{RsaPrivateKey, RsaPublicKey};

/// Runs `$body` with `$d` aliased to the concrete digest named by `$h`
/// (a [`Hash`]). Used to bridge the runtime hash selector into the generic
/// `sign_pss::<D>` / `verify_pss::<D>` / OAEP methods. Every [`Hash`] variant
/// also implements [`Pkcs1Digest`](super::Pkcs1Digest), so this same macro
/// serves the PKCS#1 v1.5 paths.
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
            RsaEncPadding::Oaep { hash, .. } => {
                dispatch_hash!(hash, |D| { self.decrypt_oaep::<D>(ct, label) })
            }
            RsaEncPadding::Pkcs1v15 => self.decrypt_pkcs1v15(ct),
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
            RsaEncPadding::Oaep { hash, .. } => {
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
            RsaEncPadding::Oaep { hash, .. } => {
                dispatch_hash!(hash, |D| { self.decrypt_oaep::<D>(ct, label) })
            }
            RsaEncPadding::Pkcs1v15 => self.decrypt_pkcs1v15(ct),
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
            RsaEncPadding::Oaep { hash, .. } => {
                dispatch_hash!(hash, |D| { self.encrypt_oaep::<D, _>(pt, label, &mut rng) })
            }
            RsaEncPadding::Pkcs1v15 => self.encrypt_pkcs1v15(pt, &mut rng),
        }
        .map_err(|_| Error::Encryption)
    }
}
