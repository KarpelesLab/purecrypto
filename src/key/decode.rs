//! Generic key decoders: parse an encoded key of unknown algorithm into a
//! boxed unified trait object.
//!
//! These bridge the X.509 [`AnyPrivateKey`](crate::x509::AnyPrivateKey) /
//! [`AnyPublicKey`](crate::x509::AnyPublicKey) OID dispatch onto the
//! [`PrivateKey`]/[`PublicKey`] facade, so a caller can load "some key" from
//! PKCS#8 / SPKI bytes and operate on it without knowing the algorithm at
//! compile time.
//!
//! Coverage matches `AnyPrivateKey`/`AnyPublicKey`: RSA, ECDSA (P-256/384/521,
//! secp256k1), Ed25519, Ed448, ML-DSA, and SLH-DSA. Keys outside that set —
//! X25519/X448, the stateful hash-based signers, ML-KEM, and SM2 (whose keys
//! decode as ECDSA over the SM2 curve, not as the SM2 signature scheme) — are
//! not produced here; construct those through their concrete types.
//!
//! Requires the `x509` feature (for the SPKI / PKCS#8 parsers).

use alloc::boxed::Box;

use crate::key::{Error, PrivateKey, PublicKey};
use crate::x509::{AnyPrivateKey, AnyPublicKey, Pkcs8ReadOptions};

fn any_private_to_dyn(key: AnyPrivateKey) -> Result<Box<dyn PrivateKey>, Error> {
    // The wildcard arm covers feature combinations where some variants are
    // cfg'd out; with every algorithm feature on the match is already
    // exhaustive (in-crate, `#[non_exhaustive]` is inert), so the arm is then
    // unreachable — which is fine and intentional.
    #[allow(unreachable_patterns)]
    Ok(match key {
        AnyPrivateKey::Rsa(k) => Box::new(k),
        AnyPrivateKey::Ecdsa(k) => Box::new(k),
        AnyPrivateKey::Ed25519(k) => Box::new(k),
        AnyPrivateKey::Ed448(k) => Box::new(k),
        #[cfg(feature = "mldsa")]
        AnyPrivateKey::MlDsa44(k) => Box::new(k),
        #[cfg(feature = "mldsa")]
        AnyPrivateKey::MlDsa65(k) => Box::new(k),
        #[cfg(feature = "mldsa")]
        AnyPrivateKey::MlDsa87(k) => Box::new(k),
        #[cfg(feature = "slhdsa")]
        AnyPrivateKey::SlhDsa(k) => Box::new(k),
        // `AnyPrivateKey` is `#[non_exhaustive]`; any future variant the facade
        // does not yet cover is reported rather than silently mishandled.
        _ => return Err(Error::Encoding),
    })
}

fn any_public_to_dyn(key: AnyPublicKey) -> Result<Box<dyn PublicKey>, Error> {
    #[allow(unreachable_patterns)]
    Ok(match key {
        AnyPublicKey::Rsa(k) => Box::new(k),
        AnyPublicKey::Ecdsa(k) => Box::new(k),
        AnyPublicKey::Ed25519(k) => Box::new(k),
        AnyPublicKey::Ed448(k) => Box::new(k),
        #[cfg(feature = "mldsa")]
        AnyPublicKey::MlDsa44(k) => Box::new(k),
        #[cfg(feature = "mldsa")]
        AnyPublicKey::MlDsa65(k) => Box::new(k),
        #[cfg(feature = "mldsa")]
        AnyPublicKey::MlDsa87(k) => Box::new(k),
        #[cfg(feature = "slhdsa")]
        AnyPublicKey::SlhDsa(k) => Box::new(k),
        _ => return Err(Error::Encoding),
    })
}

/// Decodes a plaintext PKCS#8 (`PrivateKeyInfo`) DER document into a boxed
/// [`PrivateKey`].
pub fn private_key_from_pkcs8_der(der: &[u8]) -> Result<Box<dyn PrivateKey>, Error> {
    let any =
        AnyPrivateKey::from_pkcs8_der(der, Pkcs8ReadOptions::new()).map_err(|_| Error::Encoding)?;
    any_private_to_dyn(any)
}

/// Decodes a plaintext PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) document into
/// a boxed [`PrivateKey`].
pub fn private_key_from_pkcs8_pem(pem: &str) -> Result<Box<dyn PrivateKey>, Error> {
    let any =
        AnyPrivateKey::from_pkcs8_pem(pem, Pkcs8ReadOptions::new()).map_err(|_| Error::Encoding)?;
    any_private_to_dyn(any)
}

/// Decodes an encrypted PKCS#8 (`EncryptedPrivateKeyInfo`) DER document under
/// `password` into a boxed [`PrivateKey`].
pub fn private_key_from_pkcs8_der_encrypted(
    der: &[u8],
    password: &[u8],
) -> Result<Box<dyn PrivateKey>, Error> {
    let any = AnyPrivateKey::from_pkcs8_der(der, Pkcs8ReadOptions::new().password(password))
        .map_err(|_| Error::Encoding)?;
    any_private_to_dyn(any)
}

/// Decodes an encrypted PKCS#8 PEM (`-----BEGIN ENCRYPTED PRIVATE KEY-----`)
/// document under `password` into a boxed [`PrivateKey`].
pub fn private_key_from_pkcs8_pem_encrypted(
    pem: &str,
    password: &[u8],
) -> Result<Box<dyn PrivateKey>, Error> {
    let any = AnyPrivateKey::from_pkcs8_pem(pem, Pkcs8ReadOptions::new().password(password))
        .map_err(|_| Error::Encoding)?;
    any_private_to_dyn(any)
}

/// Decodes a `SubjectPublicKeyInfo` DER document into a boxed [`PublicKey`].
pub fn public_key_from_spki_der(der: &[u8]) -> Result<Box<dyn PublicKey>, Error> {
    let any = AnyPublicKey::from_spki_der(der).map_err(|_| Error::Encoding)?;
    any_public_to_dyn(any)
}

/// Decodes a `SubjectPublicKeyInfo` PEM (`-----BEGIN PUBLIC KEY-----`) document
/// into a boxed [`PublicKey`].
pub fn public_key_from_spki_pem(pem: &str) -> Result<Box<dyn PublicKey>, Error> {
    let any = AnyPublicKey::from_spki_pem(pem).map_err(|_| Error::Encoding)?;
    any_public_to_dyn(any)
}
