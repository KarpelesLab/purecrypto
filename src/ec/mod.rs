//! Elliptic-curve cryptography over the NIST P-256 curve (secp256r1).
//!
//! Field and group arithmetic build on the constant-time
//! [`bignum`](crate::bignum) layer, using the Renes–Costello–Batina complete
//! addition formulas (for `a = -3`) so point operations are branch-free and
//! correct for all inputs, including the identity.
//!
//! Exposes ECDSA signing and verification ([`ecdsa`]).

pub mod ecdsa;
mod p256;

/// Errors from elliptic-curve operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
