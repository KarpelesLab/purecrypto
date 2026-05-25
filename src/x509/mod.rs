//! X.509 v3 certificates (RFC 5280), built on the [`der`](crate::der) and
//! [`rsa`](crate::rsa) layers.
//!
//! Supports generating self-signed certificates, issuing (signing)
//! certificates from a CA key, and parsing + signature verification, using
//! RSA with PKCS#1 v1.5 signatures.

mod cert;
mod csr;
mod name;
mod pubkey;
mod signer;
mod time;

pub use cert::Certificate;
pub use csr::CertificationRequest;
pub use name::DistinguishedName;
pub use pubkey::AnyPublicKey;
pub use signer::CertSigner;
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

    /// `id-ecPublicKey` (1.2.840.10045.2.1).
    pub const EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
    /// `prime256v1` / `secp256r1` (1.2.840.10045.3.1.7).
    pub const PRIME256V1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
    /// `secp384r1` (1.3.132.0.34).
    pub const SECP384R1: &[u64] = &[1, 3, 132, 0, 34];
    /// `secp521r1` (1.3.132.0.35).
    pub const SECP521R1: &[u64] = &[1, 3, 132, 0, 35];
    /// `secp256k1` (1.3.132.0.10).
    pub const SECP256K1: &[u64] = &[1, 3, 132, 0, 10];
    /// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
    pub const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
    /// `ecdsa-with-SHA384` (1.2.840.10045.4.3.3).
    pub const ECDSA_WITH_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
    /// `ecdsa-with-SHA512` (1.2.840.10045.4.3.4).
    pub const ECDSA_WITH_SHA512: &[u64] = &[1, 2, 840, 10045, 4, 3, 4];

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
    /// `id-ce-subjectAltName` (2.5.29.17).
    pub const SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
    /// `extensionRequest` PKCS#9 attribute (1.2.840.113549.1.9.14).
    pub const EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];
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
    /// A signature failed verification.
    Verification,
    /// The certificate is outside its validity period (`notBefore`/`notAfter`).
    Expired,
    /// The certificate does not match the expected host name.
    NameMismatch,
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
            Error::Verification => f.write_str("X.509 signature verification failed"),
            Error::Expired => f.write_str("X.509 certificate outside its validity period"),
            Error::NameMismatch => f.write_str("X.509 certificate host name mismatch"),
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
