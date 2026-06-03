//! Elliptic-curve cryptography.
//!
//! Two ECDSA/ECDH paths, both built on the constant-time
//! [`bignum`](crate::bignum) layer with the Renes–Costello–Batina complete
//! addition formulas (branch-free, correct for all inputs including the
//! identity):
//!
//! - a fast **const-generic P-256** path ([`ecdsa`], [`ecdh`]), for callers who
//!   know the curve at compile time; and
//! - a **runtime multi-curve** path ([`boxed`]) over heap-backed `BoxedUint`,
//!   selecting P-256/P-384/P-521/secp256k1 at runtime via [`CurveId`] — used by
//!   the TLS and X.509 layers, where the peer's curve is known only at parse
//!   time.
//!
//! Also exposes X25519 ([`x25519`]) / X448 ([`x448`]) Diffie-Hellman and
//! Ed25519 ([`ed25519`]) / Ed448 ([`ed448`]) signatures.

pub mod boxed;
mod curve25519;
mod curve448;
pub mod curves;
pub mod ecdh;
pub mod ecdsa;
pub mod ed25519;
pub mod ed448;
pub mod edwards25519;
mod p256;
#[cfg(feature = "x509")]
pub(crate) mod registry;
#[cfg(feature = "ristretto255")]
pub mod ristretto255;
#[cfg(feature = "hazmat-secp256k1")]
pub mod secp256k1;
mod weierstrass;
pub mod x25519;
pub mod x448;

pub use boxed::{
    BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, BoxedEcdsaSignature,
};
pub use curves::CurveId;
pub use ed448::{Ed448PrivateKey, Ed448PublicKey, Ed448Signature};
pub use ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};

/// Errors from elliptic-curve operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A scalar or coordinate was out of range, or a point was invalid / the
    /// identity where it must not be.
    InvalidInput,
    /// A signature failed verification.
    Verification,
    /// An encoded point or signature was malformed.
    Malformed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidInput => f.write_str("invalid elliptic-curve input"),
            Error::Verification => f.write_str("ECDSA signature verification failed"),
            Error::Malformed => f.write_str("malformed elliptic-curve encoding"),
        }
    }
}

impl core::error::Error for Error {}
