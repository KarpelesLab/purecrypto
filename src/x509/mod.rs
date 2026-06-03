//! X.509 v3 certificates (RFC 5280), built on the [`der`](crate::der) and
//! [`rsa`](crate::rsa) layers.
//!
//! Supports generating self-signed certificates, issuing (signing)
//! certificates from a CA key, and parsing + signature verification, using
//! RSA with PKCS#1 v1.5 signatures.

pub(crate) mod cert;
mod crl;
mod csr;
pub mod extension;
mod name;
pub mod ocsp;
mod pubkey;
mod signer;
mod time;

pub use cert::{Certificate, NameConstraints, SanIp};
pub use crl::{CertificateRevocationList, CrlBuilder, CrlReason, RevokedCertificate};
pub use csr::CertificationRequest;
pub use extension::{Extension, GeneralName, KeyUsageBits};
pub use name::DistinguishedName;
pub use ocsp::{
    OcspCertStatus, OcspRequest, OcspRequestBuilder, OcspResponse, OcspResponseBuilder,
    OcspResponseStatus, OcspSingleResponse,
};
pub use pubkey::AnyPublicKey;
pub use signer::CertSigner;
pub use time::{Time, Validity};

use alloc::vec::Vec;

/// Object identifiers used in certificates, as arc sequences.
pub mod oid {
    /// `rsaEncryption` (1.2.840.113549.1.1.1).
    pub const RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
    /// `sha1WithRSAEncryption` (1.2.840.113549.1.1.5). Legacy; in the
    /// registry for opt-in interop, never on the default whitelist.
    pub const SHA1_WITH_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 5];
    /// `id-RSASSA-PSS` (1.2.840.113549.1.1.10). Both the key OID (for an
    /// RSA-PSS-key-restricted SPKI) and the signature OID (with PSS
    /// parameters living in the AlgorithmIdentifier).
    pub const ID_RSASSA_PSS: &[u64] = &[1, 2, 840, 113549, 1, 1, 10];
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
    /// `sm2p256v1` / `id-sm2` (1.2.156.10197.1.301) — the SM2 named curve
    /// (GB/T 32918, RFC 8998).
    pub const SM2_P256V1: &[u64] = &[1, 2, 156, 10197, 1, 301];
    /// `SM2-with-SM3` (1.2.156.10197.1.501) — the SM2 signature algorithm
    /// over SM3 (GB/T 32918.2, RFC 8998).
    pub const SM2_WITH_SM3: &[u64] = &[1, 2, 156, 10197, 1, 501];
    /// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
    pub const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
    /// `ecdsa-with-SHA384` (1.2.840.10045.4.3.3).
    pub const ECDSA_WITH_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
    /// `ecdsa-with-SHA512` (1.2.840.10045.4.3.4).
    pub const ECDSA_WITH_SHA512: &[u64] = &[1, 2, 840, 10045, 4, 3, 4];
    /// `id-Ed25519` (1.3.101.112) — both the key and signature algorithm
    /// (RFC 8410).
    pub const ID_ED25519: &[u64] = &[1, 3, 101, 112];
    /// `id-Ed448` (1.3.101.113) — both the key and signature algorithm
    /// (RFC 8410).
    pub const ID_ED448: &[u64] = &[1, 3, 101, 113];

    /// `id-ml-dsa-44` (2.16.840.1.101.3.4.3.17) — NIST FIPS 204 ML-DSA-44.
    /// Used for both the SPKI key OID and the certificate signatureAlgorithm.
    pub const ID_ML_DSA_44: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 17];
    /// `id-ml-dsa-65` (2.16.840.1.101.3.4.3.18) — NIST FIPS 204 ML-DSA-65.
    pub const ID_ML_DSA_65: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
    /// `id-ml-dsa-87` (2.16.840.1.101.3.4.3.19) — NIST FIPS 204 ML-DSA-87.
    pub const ID_ML_DSA_87: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 19];

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
    /// `id-ce-keyUsage` (2.5.29.15).
    pub const KEY_USAGE: &[u64] = &[2, 5, 29, 15];
    /// `id-ce-extKeyUsage` (2.5.29.37).
    pub const EXT_KEY_USAGE: &[u64] = &[2, 5, 29, 37];
    /// `id-kp-serverAuth` (1.3.6.1.5.5.7.3.1).
    pub const ID_KP_SERVER_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
    /// `id-kp-clientAuth` (1.3.6.1.5.5.7.3.2).
    pub const ID_KP_CLIENT_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 2];
    /// `id-ce-subjectAltName` (2.5.29.17).
    pub const SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
    /// `id-ce-subjectKeyIdentifier` (2.5.29.14).
    pub const SUBJECT_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 14];
    /// `id-ce-authorityKeyIdentifier` (2.5.29.35).
    pub const AUTHORITY_KEY_IDENTIFIER: &[u64] = &[2, 5, 29, 35];
    /// `id-ce-nameConstraints` (2.5.29.30).
    pub const NAME_CONSTRAINTS: &[u64] = &[2, 5, 29, 30];
    /// `id-ce-certificatePolicies` (2.5.29.32).
    pub const CERTIFICATE_POLICIES: &[u64] = &[2, 5, 29, 32];
    /// `id-ce-cRLDistributionPoints` (2.5.29.31).
    pub const CRL_DISTRIBUTION_POINTS: &[u64] = &[2, 5, 29, 31];
    /// `id-kp-codeSigning` (1.3.6.1.5.5.7.3.3).
    pub const ID_KP_CODE_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 3];
    /// `id-kp-emailProtection` (1.3.6.1.5.5.7.3.4).
    pub const ID_KP_EMAIL_PROTECTION: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 4];
    /// `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8).
    pub const ID_KP_TIME_STAMPING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 8];
    /// `id-kp-OCSPSigning` (1.3.6.1.5.5.7.3.9).
    pub const ID_KP_OCSP_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 9];
    /// `extensionRequest` PKCS#9 attribute (1.2.840.113549.1.9.14).
    pub const EXTENSION_REQUEST: &[u64] = &[1, 2, 840, 113549, 1, 9, 14];

    /// `id-ce-cRLReason` (2.5.29.21) — per-entry CRL extension carrying a
    /// `CRLReason ::= ENUMERATED` (RFC 5280 §5.3.1).
    pub const CRL_REASON_CODE: &[u64] = &[2, 5, 29, 21];

    /// `id-pkix-ocsp-basic` (1.3.6.1.5.5.7.48.1.1) — the `responseType` OID
    /// nested inside an `OCSPResponse.responseBytes` field carrying a
    /// `BasicOCSPResponse` (RFC 6960 §4.2.1).
    pub const ID_PKIX_OCSP_BASIC: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 1];
    /// `id-pkix-ocsp-nocheck` (1.3.6.1.5.5.7.48.1.5) — extension on a
    /// delegated OCSP responder cert telling relying parties not to attempt
    /// revocation status checks on the responder itself (RFC 6960 §4.2.2.2.1).
    pub const ID_PKIX_OCSP_NOCHECK: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 5];
    /// `id-pkix-ocsp-nonce` (1.3.6.1.5.5.7.48.1.2) — request/response
    /// extension carrying a client-chosen random value that the responder
    /// must echo verbatim. Used to defeat replay of stapled responses; the
    /// client rejects a response whose nonce differs from (or omits) the
    /// one in its request (RFC 6960 §4.4.1, §4.4.7).
    pub const ID_PKIX_OCSP_NONCE: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 2];

    /// `id-sha1` (1.3.14.3.2.26) — the AlgorithmIdentifier OID used in OCSP
    /// `CertID.hashAlgorithm` for SHA-1-based identification. Default per
    /// RFC 6960 §4.3 (the OCSP profile mandates SHA-1 support for interop
    /// even when modern responders prefer SHA-256).
    pub const ID_SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
    /// `id-sha256` (2.16.840.1.101.3.4.2.1).
    pub const ID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
    /// `id-sha384` (2.16.840.1.101.3.4.2.2).
    pub const ID_SHA384: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
    /// `id-sha512` (2.16.840.1.101.3.4.2.3).
    pub const ID_SHA512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];
}

/// Errors from X.509 encoding, parsing, and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
