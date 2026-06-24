//! Unified asymmetric-key traits.
//!
//! Every asymmetric algorithm in the crate keeps its own concrete key type with
//! full, statically-typed control (`RsaPrivateKey::sign_pss`,
//! `Ed25519PrivateKey::sign`, `X25519PrivateKey::diffie_hellman`, …). This
//! module layers a *uniform* interface over them so a caller can hold "some
//! private key" and ask it to sign, decrypt, or derive a shared secret without
//! branching on the concrete algorithm.
//!
//! # Two layers
//!
//! **Capability traits** describe a single operation and are implemented only by
//! keys that can actually perform it, so the type system rejects a misuse at
//! compile time:
//!
//! * [`Signer`] / [`Verifier`] — signatures.
//! * [`Decryptor`] / [`Encryptor`] — public-key encryption (RSA, SM2).
//! * [`KeyAgreement`] — Diffie-Hellman shared secrets (ECDH, X25519/X448, DH).
//! * [`StatefulSigner`] — the stateful hash-based signers (XMSS/LMS), whose
//!   `sign` takes `&mut self` and consumes a one-time key.
//! * [`Encapsulator`] / [`Decapsulator`] — KEMs (ML-KEM).
//!
//! **Facade traits** [`PrivateKey`] and [`PublicKey`] gather the shared-reference
//! operations behind object-safe trait objects (`Box<dyn PrivateKey>`). Every
//! operation has a default that returns [`Error::Unsupported`]; a key overrides
//! only the operations it supports. Asking a key to do something it cannot —
//! decrypting with an Ed25519 key, signing with an X25519 key — therefore fails
//! at the call with a descriptive error rather than failing to compile. This is
//! the right shape when the algorithm is only known at run time (parsed keys,
//! heterogeneous collections); reach for the capability traits when the type is
//! known and you want the compiler to check capability.
//!
//! Two operations do not fit the `&self` facade and live only as capability
//! traits: stateful signing (needs `&mut self`) and KEMs (encapsulate/decapsulate
//! is not pairwise agreement). For those keys the facade's `sign` / `make_secret`
//! return [`Error::StatefulKey`] / [`Error::Unsupported`] and point at the
//! capability trait.
//!
//! # Parameters
//!
//! Signing and encryption take a [`SignParams`] / [`EncryptParams`] that selects
//! the hash, padding, and context. The [`Default`] is always valid; each
//! algorithm reads only the fields that apply to it. See [`SignParams`] and
//! [`EncryptParams`] for the field-by-field applicability.

mod algorithm;
mod error;
mod params;
mod secret;

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
    DecryptParams, EncryptParams, Hash, RsaEncPadding, RsaSigPadding, SaltLen, SignParams,
};
pub use secret::Secret;

use crate::rng::CryptoRngCore;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// A key that can produce signatures.
pub trait Signer {
    /// Signs `msg` under `params`, drawing any hedging/salt randomness from
    /// `rng` (deterministic schemes ignore it). Returns the scheme's signature
    /// encoding.
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error>;
}

/// A key that can verify signatures.
pub trait Verifier {
    /// Verifies `sig` over `msg` under `params`. Returns `Ok(())` on a valid
    /// signature and [`Error::Signature`] on an invalid one.
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error>;
}

/// A key that can decrypt ciphertext.
pub trait Decryptor {
    /// Decrypts `ct` under `params`, returning the recovered plaintext as a
    /// zeroize-on-drop [`Secret`].
    fn decrypt(&self, ct: &[u8], params: &DecryptParams<'_>) -> Result<Secret, Error>;
}

/// A key that can encrypt plaintext.
pub trait Encryptor {
    /// Encrypts `pt` under `params`, drawing randomness from `rng`.
    fn encrypt(
        &self,
        pt: &[u8],
        params: &EncryptParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error>;
}

/// A key that can derive a shared secret with a peer public key.
pub trait KeyAgreement {
    /// Derives a Diffie-Hellman shared secret with `peer`. `peer` must be the
    /// same algorithm/curve as this key, otherwise
    /// [`Error::AlgorithmMismatch`] is returned.
    fn make_secret(&self, peer: &dyn PublicKey) -> Result<Secret, Error>;
}

/// A stateful hash-based signer (XMSS/LMS).
///
/// Unlike [`Signer`], `sign` takes `&mut self`: each signature consumes a
/// one-time key and advances internal state that **must** be persisted before
/// the key is used again. Reusing a state index is catastrophic.
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

/// A private (secret) asymmetric key, behind an object-safe facade.
///
/// Each operation defaults to [`Error::Unsupported`]; an implementor overrides
/// only what its algorithm supports. See the [module docs](crate::key) for how
/// this relates to the capability traits.
pub trait PrivateKey {
    /// The algorithm (and curve / parameter set) of this key.
    fn algorithm(&self) -> Algorithm;

    /// Derives the matching [`PublicKey`].
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error>;

    /// Signs `msg`. Default: [`Error::Unsupported`].
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let _ = (msg, params, rng);
        Err(Error::unsupported(Operation::Sign, self.algorithm()))
    }

    /// Decrypts `ct`. Default: [`Error::Unsupported`].
    fn decrypt(&self, ct: &[u8], params: &DecryptParams<'_>) -> Result<Secret, Error> {
        let _ = (ct, params);
        Err(Error::unsupported(Operation::Decrypt, self.algorithm()))
    }

    /// Derives a shared secret with `peer`. Default: [`Error::Unsupported`].
    fn make_secret(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let _ = peer;
        Err(Error::unsupported(Operation::Agree, self.algorithm()))
    }
}

/// A public asymmetric key, behind an object-safe facade.
///
/// Each operation defaults to [`Error::Unsupported`]; an implementor overrides
/// only what its algorithm supports.
pub trait PublicKey {
    /// The algorithm (and curve / parameter set) of this key.
    fn algorithm(&self) -> Algorithm;

    /// Upcast for downcasting back to the concrete type — used by
    /// [`KeyAgreement::make_secret`] to recover the peer's concrete key after
    /// checking [`algorithm`](Self::algorithm).
    fn as_any(&self) -> &dyn core::any::Any;

    /// Verifies `sig` over `msg`. Default: [`Error::Unsupported`].
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let _ = (msg, sig, params);
        Err(Error::unsupported(Operation::Verify, self.algorithm()))
    }

    /// Encrypts `pt`. Default: [`Error::Unsupported`].
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

/// Checks `peer.algorithm()` against `expected` and downcasts the trait object
/// to the concrete public-key type `T`.
///
/// Used by [`KeyAgreement::make_secret`] implementations to recover the peer's
/// concrete key. Returns [`Error::AlgorithmMismatch`] if the algorithm tag does
/// not match or the concrete type is not `T`.
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
