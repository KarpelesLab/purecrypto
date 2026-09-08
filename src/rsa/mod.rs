//! RSA.
//!
//! Built on the constant-time [`bignum`](crate::bignum) layer and the
//! [`rng`](crate::rng) CSPRNG. This module currently provides the
//! number-theoretic groundwork — primality testing and prime generation; key
//! types, key generation, and PKCS#1 operations are layered on top.

mod keys;
mod prime;

#[cfg(feature = "alloc")]
mod boxed;
mod digest_info;
// Allocation-free: works entirely in caller-supplied buffers.
mod emsa;
#[cfg(all(feature = "der", feature = "alloc"))]
mod encoding;
#[cfg(feature = "key")]
mod key_impl;
// Buffer-passing PKCS#1 / PSS / OAEP: available with or without `alloc`.
mod nobuf;
#[cfg(feature = "alloc")]
mod pkcs1;
#[cfg(feature = "alloc")]
mod pss;
#[cfg(all(feature = "x509", feature = "alloc"))]
pub(crate) mod registry;

#[cfg(feature = "alloc")]
pub use boxed::{BoxedRsaPrivateKey, BoxedRsaPublicKey};
pub use keys::{RsaPrivateKey, RsaPublicKey};
pub use prime::{is_prime, random_prime};

pub use digest_info::Pkcs1Digest;

/// Upper bound on the public exponent accepted by the parse paths (and by
/// key generation): `e < 2^256`, the FIPS 186-5 §A.1.1 limit. The public
/// operation costs one squaring per bit of `e`, so without a cap an SPKI or
/// certificate carrying `e ≈ n` makes every signature *verification* as
/// expensive as a private operation — a cheap CPU-exhaustion lever against
/// anything that validates attacker-supplied certificates. Real-world
/// exponents are 3, 17, or 65537; 256 bits is far above anything legitimate.
pub(crate) const MAX_RSA_EXPONENT_BITS: usize = 256;

/// Best-effort wipe of a buffer that held secret material (a decrypted
/// encoded message, a blinder, a raw private-op output) before it is
/// dropped. The `core::hint::black_box` fence keeps LLVM from eliding the
/// stores as dead — the same idiom the key types' `Drop` impls use.
#[inline]
pub(crate) fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    let _ = core::hint::black_box(&buf);
}

/// Errors produced by RSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The message (or encoded digest) is too long for the modulus.
    MessageTooLong,
    /// A ciphertext or signature length does not match the modulus size.
    InvalidLength,
    /// Decryption failed: the recovered padding was malformed.
    Decryption,
    /// Signature verification failed.
    Verification,
    /// The key's component values are not a well-formed RSA public/private key
    /// (e.g. `e = 0`, `e` even, `e ≥ n`).
    InvalidKey,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Error::MessageTooLong => "message too long for RSA modulus",
            Error::InvalidLength => "ciphertext/signature length mismatch",
            Error::Decryption => "RSA decryption error",
            Error::Verification => "RSA signature verification failed",
            Error::InvalidKey => "RSA key components are malformed",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for Error {}
