//! The error type for the unified key traits.

use crate::key::{Algorithm, Operation};

/// Errors produced by the unified [`PrivateKey`](crate::key::PrivateKey) /
/// [`PublicKey`](crate::key::PublicKey) traits and the capability traits.
///
/// Operation failures are mapped to coarse categories (`Signature`,
/// `Decryption`, …) rather than wrapping each algorithm's own error, so the
/// facade stays uniform across schemes. The structural variants
/// (`Unsupported`, `AlgorithmMismatch`, `UnsupportedParam`, `InvalidParams`)
/// describe misuse of the abstraction itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The key does not support this operation (e.g. asking an Ed25519 key to
    /// decrypt, or an X25519 key to sign).
    Unsupported {
        /// The operation that was attempted.
        operation: Operation,
        /// The algorithm of the key it was attempted on.
        algorithm: Algorithm,
    },
    /// A key-agreement (or KEM) peer key is of a different algorithm/curve than
    /// this key.
    AlgorithmMismatch {
        /// The algorithm this key requires of its peer.
        expected: Algorithm,
        /// The algorithm the supplied peer actually has.
        found: Algorithm,
    },
    /// The caller explicitly set a parameter this algorithm does not honour
    /// (e.g. an RSA padding on an Ed25519 key, or a digest on a scheme that
    /// fixes its own). `param` names the offending field.
    UnsupportedParam {
        /// The name of the parameter that is not supported.
        param: &'static str,
    },
    /// A supported parameter was set to a value this algorithm cannot honour
    /// (e.g. an unimplemented PSS salt length).
    InvalidParams,
    /// Signature generation or verification failed.
    Signature,
    /// Encryption failed (e.g. message too long for the modulus).
    Encryption,
    /// Decryption failed (e.g. malformed padding, wrong length).
    Decryption,
    /// Key agreement failed (e.g. a small-order or invalid peer point).
    KeyAgreement,
    /// KEM encapsulation failed (e.g. a malformed encapsulation key).
    Encapsulation,
    /// KEM decapsulation failed.
    Decapsulation,
    /// Serializing or deserializing the key (or deriving the public key) failed.
    Encoding,
}

impl Error {
    /// Constructs an [`Error::Unsupported`] for `operation` on `algorithm`.
    pub fn unsupported(operation: Operation, algorithm: Algorithm) -> Self {
        Error::Unsupported {
            operation,
            algorithm,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Unsupported {
                operation,
                algorithm,
            } => write!(f, "{algorithm:?} keys do not support {operation}"),
            Error::AlgorithmMismatch { expected, found } => write!(
                f,
                "key-agreement peer mismatch: expected {expected:?}, got {found:?}"
            ),
            Error::UnsupportedParam { param } => {
                write!(
                    f,
                    "the `{param}` parameter is not supported by this algorithm"
                )
            }
            Error::InvalidParams => {
                f.write_str("a parameter value is not supported by this algorithm")
            }
            Error::Signature => f.write_str("signature operation failed"),
            Error::Encryption => f.write_str("encryption failed"),
            Error::Decryption => f.write_str("decryption failed"),
            Error::KeyAgreement => f.write_str("key agreement failed"),
            Error::Encapsulation => f.write_str("KEM encapsulation failed"),
            Error::Decapsulation => f.write_str("KEM decapsulation failed"),
            Error::Encoding => f.write_str("key encoding/decoding failed"),
        }
    }
}

impl core::error::Error for Error {}
