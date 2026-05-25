//! RSA.
//!
//! Built on the constant-time [`bignum`](crate::bignum) layer and the
//! [`rng`](crate::rng) CSPRNG. This module currently provides the
//! number-theoretic groundwork — primality testing and prime generation; key
//! types, key generation, and PKCS#1 operations are layered on top.

mod keys;
mod prime;

#[cfg(all(feature = "der", feature = "alloc"))]
mod encoding;
#[cfg(feature = "alloc")]
mod pkcs1;
#[cfg(feature = "alloc")]
mod pss;

pub use keys::{RsaPrivateKey, RsaPublicKey};
pub use prime::{is_prime, random_prime};

#[cfg(feature = "alloc")]
pub use pkcs1::Pkcs1Digest;

/// Errors produced by RSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The message (or encoded digest) is too long for the modulus.
    MessageTooLong,
    /// A ciphertext or signature length does not match the modulus size.
    InvalidLength,
    /// Decryption failed: the recovered padding was malformed.
    Decryption,
    /// Signature verification failed.
    Verification,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Error::MessageTooLong => "message too long for RSA modulus",
            Error::InvalidLength => "ciphertext/signature length mismatch",
            Error::Decryption => "RSA decryption error",
            Error::Verification => "RSA signature verification failed",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for Error {}
