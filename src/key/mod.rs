//! Unified asymmetric-key traits.
//!
//! Every asymmetric algorithm in the crate keeps its own concrete key type with
//! full, statically-typed control (`RsaPrivateKey::sign_pss`,
//! `Ed25519PrivateKey::sign`, `X25519PrivateKey::diffie_hellman`, …). This
//! module layers a *uniform*, object-safe interface over them so a caller can
//! hold "some private key" and ask it to sign, decrypt, or derive a shared
//! secret without branching on the concrete algorithm.
//!
//! # The facade
//!
//! [`PrivateKey`] (`sign` / `decrypt` / `agree`) and [`PublicKey`] (`verify` /
//! `encrypt`) gather the shared-reference operations behind trait objects
//! (`Box<dyn PrivateKey>`). Each operation has a default returning
//! [`Error::Unsupported`]; a key overrides only what it supports, and every
//! implementor supports at least one. Asking a key to do something it cannot —
//! decrypting with an Ed25519 key, signing with an X25519 key — fails at the
//! call with a descriptive error rather than at compile time. This is the right
//! shape when the algorithm is only known at run time (parsed keys,
//! heterogeneous collections).
//!
//! # Keys that don't fit the `&self` facade
//!
//! Two key classes have contracts the facade can't honour and are reached
//! through their own traits instead:
//!
//! * **Stateful hash-based signers** (XMSS/LMS/HSS) — [`StatefulSigner`], whose
//!   `sign` takes `&mut self` because each signature consumes a one-time key.
//! * **KEMs** (ML-KEM) — [`Encapsulator`] / [`Decapsulator`]; encapsulate /
//!   decapsulate is not pairwise agreement.
//!
//! These keys are deliberately **not** `PrivateKey`s, so `Box<dyn PrivateKey>`
//! is a meaningful guarantee that a key can sign, decrypt, and/or agree.
//!
//! # Parameters
//!
//! Signing and encryption take a [`SignParams`] / [`EncryptParams`] that selects
//! the hash, padding, context, and signature encoding. The [`Default`] is always
//! valid. The structs are **consume-tracked**: setting a parameter an algorithm
//! does not honour (an RSA padding on an Ed25519 key, a digest on a scheme that
//! fixes its own) fails loudly with [`Error::UnsupportedParam`] rather than being
//! silently ignored. See the [`params`](self) docs.

mod algorithm;
#[cfg(feature = "x509")]
mod decode;
mod error;
mod params;
mod secret;

#[cfg(feature = "x509")]
pub use decode::{
    private_key_from_pkcs8_der, private_key_from_pkcs8_der_encrypted, private_key_from_pkcs8_pem,
    private_key_from_pkcs8_pem_encrypted, public_key_from_spki_der, public_key_from_spki_pem,
};

#[cfg(all(feature = "x509", feature = "mlkem"))]
pub use crate::x509::{AnyDecapsulationKey, AnyEncapsulationKey, AnyKey, AnyKeyPublic};
/// The algorithm-tagged "any key" enums and their PKCS#8 / SPKI parsers live in
/// [`x509`](crate::x509) (they are built on the PKIX OID machinery), but they
/// are the enum counterpart to the [`PrivateKey`]/[`PublicKey`] trait objects
/// and are re-exported here for discoverability. Use
/// [`AnyPrivateKey::into_dyn`](crate::x509::AnyPrivateKey::into_dyn) /
/// [`AnyPublicKey::into_dyn`](crate::x509::AnyPublicKey::into_dyn) to cross from
/// the match-on-algorithm world into the polymorphic trait world.
#[cfg(feature = "x509")]
pub use crate::x509::{AnyPrivateKey, AnyPublicKey};

#[cfg(all(
    test,
    feature = "ec",
    feature = "rsa",
    feature = "der",
    feature = "mlkem",
    feature = "mldsa",
    feature = "xmss"
))]
mod tests;

pub use algorithm::{Algorithm, Operation};
pub use error::Error;
pub use params::{
    CryptParams, CryptParamsReader, DecryptParams, EncryptParams, Hash, RsaEncPadding,
    RsaSigPadding, SaltLen, SigEncoding, SignParams, SignParamsReader,
};
pub use secret::Secret;

use crate::rng::CryptoRngCore;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// A private (secret) asymmetric key, behind an object-safe facade.
///
/// Every implementor supports at least one of [`sign`](Self::sign),
/// [`decrypt`](Self::decrypt), or [`agree`](Self::agree); the operations it does
/// not support keep their default, which returns [`Error::Unsupported`]. Asking
/// a key to do something it cannot — decrypting with an Ed25519 key, signing
/// with an X25519 key — therefore fails at the call rather than at compile time.
///
/// Keys whose contract does not fit a shared-reference operation are **not**
/// `PrivateKey`s and are reached through their own traits instead: the stateful
/// hash-based signers (XMSS/LMS, `&mut self`) via [`StatefulSigner`], and KEM
/// decapsulation keys via [`Decapsulator`].
pub trait PrivateKey {
    /// The algorithm (and curve / parameter set) of this key.
    fn algorithm(&self) -> Algorithm;

    /// Derives the matching [`PublicKey`].
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error>;

    /// Signs `msg` under `params`, drawing any hedging/salt randomness from
    /// `rng` (deterministic schemes ignore it). Default: [`Error::Unsupported`].
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let _ = (msg, params, rng);
        Err(Error::unsupported(Operation::Sign, self.algorithm()))
    }

    /// Decrypts `ct` under `params`, returning the recovered plaintext as a
    /// zeroize-on-drop [`Secret`]. Default: [`Error::Unsupported`].
    fn decrypt(&self, ct: &[u8], params: &DecryptParams<'_>) -> Result<Secret, Error> {
        let _ = (ct, params);
        Err(Error::unsupported(Operation::Decrypt, self.algorithm()))
    }

    /// Derives a Diffie-Hellman shared secret with `peer`, which must be the
    /// same algorithm/curve as this key (else [`Error::AlgorithmMismatch`]).
    /// Default: [`Error::Unsupported`].
    fn agree(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let _ = peer;
        Err(Error::unsupported(Operation::Agree, self.algorithm()))
    }
}

/// A public asymmetric key, behind an object-safe facade.
///
/// Every implementor reports its [`algorithm`](Self::algorithm) and can serve as
/// a key-agreement peer (via [`as_any`](Self::as_any)); [`verify`](Self::verify)
/// and [`encrypt`](Self::encrypt) default to [`Error::Unsupported`] for keys
/// that do not support them.
pub trait PublicKey {
    /// The algorithm (and curve / parameter set) of this key.
    fn algorithm(&self) -> Algorithm;

    /// Upcast for downcasting back to the concrete type — used by
    /// [`PrivateKey::agree`] to recover the peer's concrete key after checking
    /// [`algorithm`](Self::algorithm).
    fn as_any(&self) -> &dyn core::any::Any;

    /// Verifies `sig` over `msg` under `params`. Returns `Ok(())` on a valid
    /// signature and [`Error::Signature`] on an invalid one. Default:
    /// [`Error::Unsupported`].
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let _ = (msg, sig, params);
        Err(Error::unsupported(Operation::Verify, self.algorithm()))
    }

    /// Encrypts `pt` under `params`, drawing randomness from `rng`. Default:
    /// [`Error::Unsupported`].
    fn encrypt(
        &self,
        pt: &[u8],
        params: &EncryptParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let _ = (pt, params, rng);
        Err(Error::unsupported(Operation::Encrypt, self.algorithm()))
    }
}

/// A stateful hash-based signer (XMSS/LMS/HSS).
///
/// `sign` takes `&mut self`: each signature consumes a one-time key and advances
/// internal state that **must** be persisted before the key is used again.
/// Reusing a state index is catastrophic, which is why these keys are not
/// [`PrivateKey`]s (whose `sign` is `&self`).
pub trait StatefulSigner {
    /// Signs `msg`, advancing the one-time-key index. `rng` supplies the
    /// randomizer for schemes that need one (LMS/HSS).
    fn sign(&mut self, msg: &[u8], rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error>;

    /// The number of signatures the key can still produce before it is
    /// exhausted.
    fn remaining(&self) -> u64;
}

/// A KEM encapsulation (public) key.
pub trait Encapsulator {
    /// Generates a fresh shared secret and the ciphertext that transports it to
    /// the holder of the matching decapsulation key. Returns
    /// `(ciphertext, shared_secret)`.
    fn encapsulate(&self, rng: &mut dyn CryptoRngCore) -> Result<(Vec<u8>, Secret), Error>;
}

/// A KEM decapsulation (private) key.
pub trait Decapsulator {
    /// Recovers the shared secret from `ct`.
    fn decapsulate(&self, ct: &[u8]) -> Result<Secret, Error>;
}

/// Checks `peer.algorithm()` against `expected` and downcasts the trait object
/// to the concrete public-key type `T`.
///
/// Used by [`PrivateKey::agree`] implementations to recover the peer's concrete
/// key. Returns [`Error::AlgorithmMismatch`] if the algorithm tag does not match
/// or the concrete type is not `T`.
//
// `allow(dead_code)`: only the key-agreement impls (EC, DH) call this, so it is
// unused under feature combinations that enable `key` without any agreement
// module (e.g. `--features key,rsa`).
#[allow(dead_code)]
pub(crate) fn downcast_peer<T: PublicKey + 'static>(
    peer: &dyn PublicKey,
    expected: Algorithm,
) -> Result<&T, Error> {
    if peer.algorithm() != expected {
        return Err(Error::AlgorithmMismatch {
            expected,
            found: peer.algorithm(),
        });
    }
    peer.as_any()
        .downcast_ref::<T>()
        .ok_or(Error::AlgorithmMismatch {
            expected,
            found: peer.algorithm(),
        })
}
