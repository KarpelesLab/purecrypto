//! X.509 v3 certificates (RFC 5280), built on the [`der`](crate::der) and
//! [`rsa`](crate::rsa) layers.
//!
//! Supports generating self-signed certificates, issuing (signing)
//! certificates from a CA key, and parsing + signature verification, using
//! RSA with PKCS#1 v1.5 signatures.

mod cert;
mod name;
mod time;

pub use cert::Certificate;
pub use name::DistinguishedName;
pub use time::{Time, Validity};

use alloc::vec::Vec;

/// Object identifiers used in certificates, as arc sequences.
pub mod oid {
    /// `rsaEncryption` (1.2.840.113549.1.1.1).
    pub const RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
    /// `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
    pub const SHA256_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
    /// `sha384WithRSAEncryption` (1.2.840.113549.1.1.12).
    pub const SHA384_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 12];
    /// `sha512WithRSAEncryption` (1.2.840.113549.1.1.13).
    pub const SHA512_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 13];

    /// `id-at-commonName` (2.5.4.3).
    pub const COMMON_NAME: &[u64] = &[2, 5, 4, 3];
    /// `id-at-countryName` (2.5.4.6).
    pub const COUNTRY: &[u64] = &[2, 5, 4, 6];
    /// `id-at-organizationName` (2.5.4.10).
    pub const ORGANIZATION: &[u64] = &[2, 5, 4, 10];
    /// `id-at-organizationalUnitName` (2.5.4.11).
    pub const ORGANIZATIONAL_UNIT: &[u64] = &[2, 5, 4, 11];

    /// `id-ce-basicConstraints` (2.5.29.19).
    pub const BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
}

/// Errors from X.509 encoding, parsing, and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A DER/PEM decoding error.
    Der(crate::der::Error),
    /// An RSA error (e.g. signature verification failure).
    Rsa(crate::rsa::Error),
    /// The certificate uses an algorithm this implementation does not support.
    UnsupportedAlgorithm,
    /// A structural problem in the certificate.
    Malformed,
}

impl From<crate::der::Error> for Error {
    fn from(e: crate::der::Error) -> Self {
        Error::Der(e)
    }
}

impl From<crate::rsa::Error> for Error {
    fn from(e: crate::rsa::Error) -> Self {
        Error::Rsa(e)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Der(e) => write!(f, "X.509 DER error: {e}"),
            Error::Rsa(e) => write!(f, "X.509 RSA error: {e}"),
            Error::UnsupportedAlgorithm => f.write_str("unsupported X.509 algorithm"),
            Error::Malformed => f.write_str("malformed X.509 certificate"),
        }
    }
}

impl core::error::Error for Error {}

/// Encodes an `AlgorithmIdentifier`: `SEQUENCE { algorithm OID, parameters }`.
/// For the algorithms here, `parameters` is `NULL` when `null_params` is set
/// (RSA), else absent.
pub(crate) fn algorithm_identifier(algorithm: &[u64], null_params: bool) -> Vec<u8> {
    use crate::der::{encode_null, encode_sequence, oid_tlv};
    let mut body = oid_tlv(algorithm);
    if null_params {
        body.extend_from_slice(&encode_null());
    }
    encode_sequence(&body)
}
