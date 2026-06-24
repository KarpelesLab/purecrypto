//! Unified [`key`](crate::key) trait impls for the RSA keys.
//!
//! Each key implements the fine-grained capability trait(s) it supports
//! (`Signer`/`Verifier` for signatures, `Decryptor`/`Encryptor` for
//! public-key encryption) plus the object-safe facade
//! (`PrivateKey`/`PublicKey`); the facade methods just delegate to the
//! capability impls. Operations a key cannot perform fall through to the
//! facade's defaulted [`Error::Unsupported`](crate::key::Error).
//!
//! Both the runtime-sized [`BoxedRsaPrivateKey`]/[`BoxedRsaPublicKey`] and the
//! const-generic [`RsaPrivateKey`]/[`RsaPublicKey`] are covered; they share the
//! same dispatch logic since they expose the same PKCS#1 / PSS / OAEP method
//! surface.
//!
//! # Unsupported parameter combinations
//!
//! * `SignParams::prehashed == true` — RSA's only prehash entry points are the
//!   `tls-legacy` raw MD5‖SHA-1 helpers (no `DigestInfo`, no PSS/OAEP
//!   equivalent), not a general prehash of an arbitrary digest, so the unified
//!   facade maps prehashed RSA to [`Error::InvalidParams`].
//! * `SaltLen::Max` for PSS — there is no "maximum salt length" signing API
//!   here, so it maps to [`Error::InvalidParams`].

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{
    Algorithm, DecryptParams, Decryptor, EncryptParams, Encryptor, Error, Hash, PrivateKey,
    PublicKey, RsaEncPadding, RsaSigPadding, SaltLen, Secret, SignParams, Signer, Verifier,
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

impl Signer for BoxedRsaPrivateKey {
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        if params.prehashed {
            return Err(Error::InvalidParams);
        }
        let mut rng = rng;
        match params.padding {
            RsaSigPadding::Pss { salt_len } => dispatch_hash!(params.hash, |D| {
                match salt_len {
                    SaltLen::DigestLength => self.sign_pss::<D, _>(msg, &mut rng),
                    SaltLen::Fixed(n) => self.sign_pss_with_salt_len::<D, _>(msg, n, &mut rng),
                    SaltLen::Max => return Err(Error::InvalidParams),
                }
            })
            .map_err(|_| Error::Signature),
            RsaSigPadding::Pkcs1v15 => {
                dispatch_hash!(params.hash, |D| { self.sign_pkcs1v15::<D>(msg) })
                    .map_err(|_| Error::Signature)
            }
        }
    }
}

impl Decryptor for BoxedRsaPrivateKey {
    fn decrypt(&self, ct: &[u8], params: &DecryptParams<'_>) -> Result<Secret, Error> {
        let pt = match params.padding {
            RsaEncPadding::Oaep { hash, .. } => {
                dispatch_hash!(hash, |D| { self.decrypt_oaep::<D>(ct, params.label) })
            }
            RsaEncPadding::Pkcs1v15 => self.decrypt_pkcs1v15(ct),
        }
        .map_err(|_| Error::Decryption)?;
        Ok(Secret::from_bytes(pt))
    }
}

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
        Signer::sign(self, msg, params, rng)
    }
    fn decrypt(&self, ct: &[u8], params: &DecryptParams<'_>) -> Result<Secret, Error> {
        Decryptor::decrypt(self, ct, params)
    }
}

// ----------------------------------------------------------------------------
// BoxedRsaPublicKey
// ----------------------------------------------------------------------------

impl Verifier for BoxedRsaPublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        if params.prehashed {
            return Err(Error::InvalidParams);
        }
        match params.padding {
            RsaSigPadding::Pss { salt_len } => dispatch_hash!(params.hash, |D| {
                match salt_len {
                    SaltLen::DigestLength => self.verify_pss::<D>(msg, sig),
                    SaltLen::Fixed(n) => self.verify_pss_with_salt_len::<D>(msg, sig, n),
                    SaltLen::Max => return Err(Error::InvalidParams),
                }
            })
            .map_err(|_| Error::Signature),
            RsaSigPadding::Pkcs1v15 => {
                dispatch_hash!(params.hash, |D| { self.verify_pkcs1v15::<D>(msg, sig) })
                    .map_err(|_| Error::Signature)
            }
        }
    }
}

impl Encryptor for BoxedRsaPublicKey {
    fn encrypt(
        &self,
        pt: &[u8],
        params: &EncryptParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let mut rng = rng;
        match params.padding {
            RsaEncPadding::Oaep { hash, .. } => {
                dispatch_hash!(hash, |D| {
                    self.encrypt_oaep::<D, _>(pt, params.label, &mut rng)
                })
            }
            RsaEncPadding::Pkcs1v15 => self.encrypt_pkcs1v15(pt, &mut rng),
        }
        .map_err(|_| Error::Encryption)
    }
}

impl PublicKey for BoxedRsaPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Rsa
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
// RsaPrivateKey<LIMBS>
// ----------------------------------------------------------------------------

impl<const LIMBS: usize> Signer for RsaPrivateKey<LIMBS> {
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        if params.prehashed {
            return Err(Error::InvalidParams);
        }
        let mut rng = rng;
        match params.padding {
            RsaSigPadding::Pss { salt_len } => dispatch_hash!(params.hash, |D| {
                match salt_len {
                    SaltLen::DigestLength => self.sign_pss::<D, _>(msg, &mut rng),
                    SaltLen::Fixed(n) => self.sign_pss_with_salt_len::<D, _>(msg, n, &mut rng),
                    SaltLen::Max => return Err(Error::InvalidParams),
                }
            })
            .map_err(|_| Error::Signature),
            RsaSigPadding::Pkcs1v15 => {
                dispatch_hash!(params.hash, |D| { self.sign_pkcs1v15::<D>(msg) })
                    .map_err(|_| Error::Signature)
            }
        }
    }
}

impl<const LIMBS: usize> Decryptor for RsaPrivateKey<LIMBS> {
    fn decrypt(&self, ct: &[u8], params: &DecryptParams<'_>) -> Result<Secret, Error> {
        let pt = match params.padding {
            RsaEncPadding::Oaep { hash, .. } => {
                dispatch_hash!(hash, |D| { self.decrypt_oaep::<D>(ct, params.label) })
            }
            RsaEncPadding::Pkcs1v15 => self.decrypt_pkcs1v15(ct),
        }
        .map_err(|_| Error::Decryption)?;
        Ok(Secret::from_bytes(pt))
    }
}

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
        Signer::sign(self, msg, params, rng)
    }
    fn decrypt(&self, ct: &[u8], params: &DecryptParams<'_>) -> Result<Secret, Error> {
        Decryptor::decrypt(self, ct, params)
    }
}

// ----------------------------------------------------------------------------
// RsaPublicKey<LIMBS>
// ----------------------------------------------------------------------------

impl<const LIMBS: usize> Verifier for RsaPublicKey<LIMBS> {
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        if params.prehashed {
            return Err(Error::InvalidParams);
        }
        match params.padding {
            RsaSigPadding::Pss { salt_len } => dispatch_hash!(params.hash, |D| {
                match salt_len {
                    SaltLen::DigestLength => self.verify_pss::<D>(msg, sig),
                    SaltLen::Fixed(n) => self.verify_pss_with_salt_len::<D>(msg, sig, n),
                    SaltLen::Max => return Err(Error::InvalidParams),
                }
            })
            .map_err(|_| Error::Signature),
            RsaSigPadding::Pkcs1v15 => {
                dispatch_hash!(params.hash, |D| { self.verify_pkcs1v15::<D>(msg, sig) })
                    .map_err(|_| Error::Signature)
            }
        }
    }
}

impl<const LIMBS: usize> Encryptor for RsaPublicKey<LIMBS> {
    fn encrypt(
        &self,
        pt: &[u8],
        params: &EncryptParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let mut rng = rng;
        match params.padding {
            RsaEncPadding::Oaep { hash, .. } => {
                dispatch_hash!(hash, |D| {
                    self.encrypt_oaep::<D, _>(pt, params.label, &mut rng)
                })
            }
            RsaEncPadding::Pkcs1v15 => self.encrypt_pkcs1v15(pt, &mut rng),
        }
        .map_err(|_| Error::Encryption)
    }
}

impl<const LIMBS: usize> PublicKey for RsaPublicKey<LIMBS> {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Rsa
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
