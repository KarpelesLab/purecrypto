//! JOSE: JSON Web Key (RFC 7517), JSON Web Signature (RFC 7515) and JSON
//! Web Encryption (RFC 7516) with the RFC 7518 / RFC 8037 algorithms.
//!
//! # What is here
//!
//! * [`Jwk`] / [`JwkSet`] — parsing, validation and export of `oct`, `RSA`,
//!   `EC` (P-256, P-384, P-521, secp256k1) and `OKP` (Ed25519, Ed448,
//!   X25519, X448) keys, with conversions to and from the crate's key types.
//! * [`Jws`] — verification of the compact, flattened-JSON and general-JSON
//!   serializations and compact signing, for `HS256/384/512`,
//!   `RS256/384/512`, `PS256/384/512`, `ES256/384/512`, `ES256K` and `EdDSA`.
//!   `alg: none` is always rejected.
//! * [`Jwe`] — decryption of the compact, flattened-JSON and general-JSON
//!   serializations and compact encryption, with key management `dir`,
//!   `A128KW/A192KW/A256KW`, `A128GCMKW/A192GCMKW/A256GCMKW`, `RSA1_5`,
//!   `RSA-OAEP`, `RSA-OAEP-256`, `ECDH-ES`, `ECDH-ES+A128KW/A192KW/A256KW`
//!   (P-256/384/521, secp256k1, X25519, X448) and
//!   `PBES2-HS256+A128KW/HS384+A192KW/HS512+A256KW`, and content encryption
//!   `A128GCM/A192GCM/A256GCM` and `A128CBC-HS256/A192CBC-HS384/A256CBC-HS512`.
//! * [`json`] — a strict JSON parser/serializer and [`base64url`] — strict
//!   unpadded base64url, both public because callers building or inspecting
//!   headers need them.
//!
//! # Policy
//!
//! The library is deliberately strict where the RFCs leave room, following
//! the Wycheproof JOSE guidance:
//!
//! * The key decides the algorithm, never the message. A key that carries
//!   `alg` is only ever used with that algorithm (for `dir` the key's `alg`
//!   names the content encryption); `use` and `key_ops` are enforced; the
//!   key type must match the algorithm family. Any mismatch is
//!   [`Error::KeyMismatch`] and no cryptographic operation is attempted.
//!   `RSA1_5` is only used with a key that explicitly declares `alg: RSA1_5`.
//! * `jwk`, `jku`, `x5c` and `x5u` header parameters are never used to
//!   select a key. `crit` is rejected: no extension header is understood.
//! * A JWK Set is rejected when it mixes public and private/secret keys
//!   ([`Error::MixedKeySet`]) or repeats a `kid` ([`Error::DuplicateKid`]);
//!   selecting a key without a `kid` is only allowed when exactly one key
//!   fits ([`Error::Ambiguous`] otherwise).
//! * RSA keys must be at least 2048 bits, with a sane public exponent, and
//!   are checked against the ROCA (CVE-2017-15361) fingerprint. EC and OKP
//!   coordinates must have exactly the field width, points must lie on the
//!   named curve, and a private key must match its public part. HMAC keys
//!   must be at least as long as the hash output.
//! * Every JWS verification failure is [`Error::Verification`] and every
//!   JWE decryption failure after key selection is [`Error::Decryption`];
//!   in particular `RSA1_5` uses implicit rejection so a padding failure and
//!   a wrong content key end in the same AEAD failure.
//! * `zip: DEF` is supported only when the `cert-compression` feature (the
//!   crate's DEFLATE dependency) is enabled; otherwise it is
//!   [`Error::Unsupported`].
//!
//! Content-encryption keys, derived keys and shared secrets are wiped when
//! dropped.

pub mod base64url;
mod cbc_hmac;
pub mod json;
mod jwe;
mod jwk;
mod jws;

pub use jwe::{Jwe, JweRecipient, MAX_PBES2_ITERATIONS};
pub use jwk::{EcCurve, Jwk, JwkKey, JwkSet, OkpCurve, RsaPrivateParts};
pub use jws::{Jws, JwsSignature};

use crate::ec::CurveId;

/// Errors from JWK, JWS and JWE processing.
///
/// Parsing and key-selection errors describe public, attacker-visible
/// structure (a malformed segment, an unknown algorithm, a `kid` no key
/// has); every failure that depends on secret material is collapsed into
/// [`Verification`](Self::Verification) or [`Decryption`](Self::Decryption).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Malformed JSON (including duplicate member names).
    Json,
    /// Malformed base64url (padding, invalid characters, bad trailing bits).
    Base64,
    /// The structure is wrong: wrong number of segments, a missing or
    /// mistyped member, a header parameter present in two header locations,
    /// a JWK member of the wrong type or length.
    Malformed,
    /// An `alg`, `enc`, `kty` or `crv` value that is unknown or not
    /// implemented (`alg: none` included).
    UnsupportedAlgorithm,
    /// A feature that is not available in this build or implementation; the
    /// payload names it (e.g. `"zip"`, `"oth"`).
    Unsupported(&'static str),
    /// A header lists a `crit` extension parameter this implementation does
    /// not understand (RFC 7515 §4.1.11 requires rejection).
    CriticalHeader,
    /// The key failed validation (size, exponent, point not on the curve,
    /// inconsistent components, ROCA fingerprint, ...).
    InvalidKey,
    /// The selected key cannot be used for this message: its `alg`, `use`,
    /// `key_ops`, `kty` or curve does not fit the header.
    KeyMismatch,
    /// No key in the set matches the header's `kid` / algorithm.
    NoKey,
    /// Key selection is ambiguous (several keys fit and no `kid` decides).
    Ambiguous,
    /// A JWK Set contains two keys with the same `kid`.
    DuplicateKid,
    /// A JWK Set mixes public keys with private or symmetric keys.
    MixedKeySet,
    /// The signature or MAC did not verify.
    Verification,
    /// Decryption failed (key unwrap, authentication tag, padding, key
    /// derivation, plaintext inflation — all indistinguishable).
    Decryption,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Json => f.write_str("malformed JSON"),
            Error::Base64 => f.write_str("malformed base64url"),
            Error::Malformed => f.write_str("malformed JOSE structure"),
            Error::UnsupportedAlgorithm => f.write_str("unsupported JOSE algorithm"),
            Error::Unsupported(what) => write!(f, "unsupported JOSE feature: {what}"),
            Error::CriticalHeader => f.write_str("unrecognised critical header parameter"),
            Error::InvalidKey => f.write_str("invalid JWK"),
            Error::KeyMismatch => f.write_str("key is not usable with this algorithm"),
            Error::NoKey => f.write_str("no matching key"),
            Error::Ambiguous => f.write_str("ambiguous key selection"),
            Error::DuplicateKid => f.write_str("duplicate kid in JWK Set"),
            Error::MixedKeySet => f.write_str("JWK Set mixes public and private keys"),
            Error::Verification => f.write_str("JWS verification failed"),
            Error::Decryption => f.write_str("JWE decryption failed"),
        }
    }
}

impl core::error::Error for Error {}

/// A JWS signature / MAC algorithm (RFC 7518 §3, RFC 8037 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigAlg {
    /// HMAC with SHA-256.
    HS256,
    /// HMAC with SHA-384.
    HS384,
    /// HMAC with SHA-512.
    HS512,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RS512,
    /// RSASSA-PSS with SHA-256 and MGF1-SHA-256.
    PS256,
    /// RSASSA-PSS with SHA-384 and MGF1-SHA-384.
    PS384,
    /// RSASSA-PSS with SHA-512 and MGF1-SHA-512.
    PS512,
    /// ECDSA on P-256 with SHA-256.
    ES256,
    /// ECDSA on P-384 with SHA-384.
    ES384,
    /// ECDSA on P-521 with SHA-512.
    ES512,
    /// ECDSA on secp256k1 with SHA-256 (RFC 8812).
    ES256K,
    /// EdDSA (Ed25519 or Ed448, decided by the key).
    EdDSA,
}

impl SigAlg {
    /// The registered `alg` name.
    pub fn name(self) -> &'static str {
        match self {
            SigAlg::HS256 => "HS256",
            SigAlg::HS384 => "HS384",
            SigAlg::HS512 => "HS512",
            SigAlg::RS256 => "RS256",
            SigAlg::RS384 => "RS384",
            SigAlg::RS512 => "RS512",
            SigAlg::PS256 => "PS256",
            SigAlg::PS384 => "PS384",
            SigAlg::PS512 => "PS512",
            SigAlg::ES256 => "ES256",
            SigAlg::ES384 => "ES384",
            SigAlg::ES512 => "ES512",
            SigAlg::ES256K => "ES256K",
            SigAlg::EdDSA => "EdDSA",
        }
    }

    /// Parses a registered `alg` name; `None` for anything else (`none`
    /// included).
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "HS256" => SigAlg::HS256,
            "HS384" => SigAlg::HS384,
            "HS512" => SigAlg::HS512,
            "RS256" => SigAlg::RS256,
            "RS384" => SigAlg::RS384,
            "RS512" => SigAlg::RS512,
            "PS256" => SigAlg::PS256,
            "PS384" => SigAlg::PS384,
            "PS512" => SigAlg::PS512,
            "ES256" => SigAlg::ES256,
            "ES384" => SigAlg::ES384,
            "ES512" => SigAlg::ES512,
            "ES256K" => SigAlg::ES256K,
            "EdDSA" => SigAlg::EdDSA,
            _ => return None,
        })
    }

    /// The key family this algorithm needs.
    pub(crate) fn family(self) -> KeyFamily {
        match self {
            SigAlg::HS256 | SigAlg::HS384 | SigAlg::HS512 => KeyFamily::Oct,
            SigAlg::RS256
            | SigAlg::RS384
            | SigAlg::RS512
            | SigAlg::PS256
            | SigAlg::PS384
            | SigAlg::PS512 => KeyFamily::Rsa,
            SigAlg::ES256 => KeyFamily::Ec(EcCurve::P256),
            SigAlg::ES384 => KeyFamily::Ec(EcCurve::P384),
            SigAlg::ES512 => KeyFamily::Ec(EcCurve::P521),
            SigAlg::ES256K => KeyFamily::Ec(EcCurve::Secp256k1),
            SigAlg::EdDSA => KeyFamily::OkpSign,
        }
    }
}

/// A JWE key-management algorithm (RFC 7518 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyAlg {
    /// Direct use of a shared symmetric key as the CEK.
    Dir,
    /// AES-128 Key Wrap (RFC 3394).
    A128KW,
    /// AES-192 Key Wrap.
    A192KW,
    /// AES-256 Key Wrap.
    A256KW,
    /// Key wrapping with AES-128-GCM (`iv` / `tag` header parameters).
    A128GCMKW,
    /// Key wrapping with AES-192-GCM.
    A192GCMKW,
    /// Key wrapping with AES-256-GCM.
    A256GCMKW,
    /// RSAES-PKCS1-v1_5.
    RSA1_5,
    /// RSAES-OAEP with SHA-1 and MGF1-SHA-1.
    RsaOaep,
    /// RSAES-OAEP with SHA-256 and MGF1-SHA-256.
    RsaOaep256,
    /// ECDH-ES with the Concat KDF, direct key agreement.
    EcdhEs,
    /// ECDH-ES key agreement followed by AES-128 Key Wrap.
    EcdhEsA128KW,
    /// ECDH-ES key agreement followed by AES-192 Key Wrap.
    EcdhEsA192KW,
    /// ECDH-ES key agreement followed by AES-256 Key Wrap.
    EcdhEsA256KW,
    /// PBES2 with HMAC-SHA-256 and AES-128 Key Wrap.
    Pbes2Hs256A128KW,
    /// PBES2 with HMAC-SHA-384 and AES-192 Key Wrap.
    Pbes2Hs384A192KW,
    /// PBES2 with HMAC-SHA-512 and AES-256 Key Wrap.
    Pbes2Hs512A256KW,
}

impl KeyAlg {
    /// The registered `alg` name.
    pub fn name(self) -> &'static str {
        match self {
            KeyAlg::Dir => "dir",
            KeyAlg::A128KW => "A128KW",
            KeyAlg::A192KW => "A192KW",
            KeyAlg::A256KW => "A256KW",
            KeyAlg::A128GCMKW => "A128GCMKW",
            KeyAlg::A192GCMKW => "A192GCMKW",
            KeyAlg::A256GCMKW => "A256GCMKW",
            KeyAlg::RSA1_5 => "RSA1_5",
            KeyAlg::RsaOaep => "RSA-OAEP",
            KeyAlg::RsaOaep256 => "RSA-OAEP-256",
            KeyAlg::EcdhEs => "ECDH-ES",
            KeyAlg::EcdhEsA128KW => "ECDH-ES+A128KW",
            KeyAlg::EcdhEsA192KW => "ECDH-ES+A192KW",
            KeyAlg::EcdhEsA256KW => "ECDH-ES+A256KW",
            KeyAlg::Pbes2Hs256A128KW => "PBES2-HS256+A128KW",
            KeyAlg::Pbes2Hs384A192KW => "PBES2-HS384+A192KW",
            KeyAlg::Pbes2Hs512A256KW => "PBES2-HS512+A256KW",
        }
    }

    /// Parses a registered `alg` name.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "dir" => KeyAlg::Dir,
            "A128KW" => KeyAlg::A128KW,
            "A192KW" => KeyAlg::A192KW,
            "A256KW" => KeyAlg::A256KW,
            "A128GCMKW" => KeyAlg::A128GCMKW,
            "A192GCMKW" => KeyAlg::A192GCMKW,
            "A256GCMKW" => KeyAlg::A256GCMKW,
            "RSA1_5" => KeyAlg::RSA1_5,
            "RSA-OAEP" => KeyAlg::RsaOaep,
            "RSA-OAEP-256" => KeyAlg::RsaOaep256,
            "ECDH-ES" => KeyAlg::EcdhEs,
            "ECDH-ES+A128KW" => KeyAlg::EcdhEsA128KW,
            "ECDH-ES+A192KW" => KeyAlg::EcdhEsA192KW,
            "ECDH-ES+A256KW" => KeyAlg::EcdhEsA256KW,
            "PBES2-HS256+A128KW" => KeyAlg::Pbes2Hs256A128KW,
            "PBES2-HS384+A192KW" => KeyAlg::Pbes2Hs384A192KW,
            "PBES2-HS512+A256KW" => KeyAlg::Pbes2Hs512A256KW,
            _ => return None,
        })
    }

    /// The key family this algorithm needs.
    pub(crate) fn family(self) -> KeyFamily {
        match self {
            KeyAlg::Dir
            | KeyAlg::A128KW
            | KeyAlg::A192KW
            | KeyAlg::A256KW
            | KeyAlg::A128GCMKW
            | KeyAlg::A192GCMKW
            | KeyAlg::A256GCMKW
            | KeyAlg::Pbes2Hs256A128KW
            | KeyAlg::Pbes2Hs384A192KW
            | KeyAlg::Pbes2Hs512A256KW => KeyFamily::Oct,
            KeyAlg::RSA1_5 | KeyAlg::RsaOaep | KeyAlg::RsaOaep256 => KeyFamily::Rsa,
            KeyAlg::EcdhEs | KeyAlg::EcdhEsA128KW | KeyAlg::EcdhEsA192KW | KeyAlg::EcdhEsA256KW => {
                KeyFamily::Ecdh
            }
        }
    }

    /// The AES key-wrap key size in bytes for the `A*KW`, `A*GCMKW`,
    /// `ECDH-ES+A*KW` and `PBES2-*+A*KW` algorithms.
    pub(crate) fn wrap_key_len(self) -> Option<usize> {
        Some(match self {
            KeyAlg::A128KW
            | KeyAlg::A128GCMKW
            | KeyAlg::EcdhEsA128KW
            | KeyAlg::Pbes2Hs256A128KW => 16,
            KeyAlg::A192KW
            | KeyAlg::A192GCMKW
            | KeyAlg::EcdhEsA192KW
            | KeyAlg::Pbes2Hs384A192KW => 24,
            KeyAlg::A256KW
            | KeyAlg::A256GCMKW
            | KeyAlg::EcdhEsA256KW
            | KeyAlg::Pbes2Hs512A256KW => 32,
            _ => return None,
        })
    }
}

/// A JWE content encryption algorithm (RFC 7518 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Enc {
    /// AES-128-GCM.
    A128Gcm,
    /// AES-192-GCM.
    A192Gcm,
    /// AES-256-GCM.
    A256Gcm,
    /// AES-128-CBC with HMAC-SHA-256 (32-byte composite key).
    A128CbcHs256,
    /// AES-192-CBC with HMAC-SHA-384 (48-byte composite key).
    A192CbcHs384,
    /// AES-256-CBC with HMAC-SHA-512 (64-byte composite key).
    A256CbcHs512,
}

impl Enc {
    /// The registered `enc` name.
    pub fn name(self) -> &'static str {
        match self {
            Enc::A128Gcm => "A128GCM",
            Enc::A192Gcm => "A192GCM",
            Enc::A256Gcm => "A256GCM",
            Enc::A128CbcHs256 => "A128CBC-HS256",
            Enc::A192CbcHs384 => "A192CBC-HS384",
            Enc::A256CbcHs512 => "A256CBC-HS512",
        }
    }

    /// Parses a registered `enc` name.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "A128GCM" => Enc::A128Gcm,
            "A192GCM" => Enc::A192Gcm,
            "A256GCM" => Enc::A256Gcm,
            "A128CBC-HS256" => Enc::A128CbcHs256,
            "A192CBC-HS384" => Enc::A192CbcHs384,
            "A256CBC-HS512" => Enc::A256CbcHs512,
            _ => return None,
        })
    }

    /// Content-encryption key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Enc::A128Gcm => 16,
            Enc::A192Gcm => 24,
            Enc::A256Gcm => 32,
            Enc::A128CbcHs256 => 32,
            Enc::A192CbcHs384 => 48,
            Enc::A256CbcHs512 => 64,
        }
    }

    /// Initialization-vector length in bytes (96-bit for GCM, one AES
    /// block for CBC).
    pub fn iv_len(self) -> usize {
        if self.is_gcm() { 12 } else { 16 }
    }

    /// Authentication-tag length in bytes.
    pub fn tag_len(self) -> usize {
        match self {
            Enc::A128Gcm | Enc::A192Gcm | Enc::A256Gcm => 16,
            Enc::A128CbcHs256 => 16,
            Enc::A192CbcHs384 => 24,
            Enc::A256CbcHs512 => 32,
        }
    }

    /// Whether this is one of the AES-GCM variants.
    pub fn is_gcm(self) -> bool {
        matches!(self, Enc::A128Gcm | Enc::A192Gcm | Enc::A256Gcm)
    }
}

/// The kind of key an algorithm consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyFamily {
    Oct,
    Rsa,
    Ec(EcCurve),
    /// `OKP` with an Ed25519 or Ed448 curve.
    OkpSign,
    /// `EC` on any supported curve or `OKP` with X25519 / X448.
    Ecdh,
}

impl EcCurve {
    pub(crate) fn curve_id(self) -> CurveId {
        match self {
            EcCurve::P256 => CurveId::P256,
            EcCurve::P384 => CurveId::P384,
            EcCurve::P521 => CurveId::P521,
            EcCurve::Secp256k1 => CurveId::Secp256k1,
        }
    }

    pub(crate) fn field_len(self) -> usize {
        self.curve_id().field_len()
    }

    pub(crate) fn order_len(self) -> usize {
        self.curve_id().order_len()
    }
}

/// Whether `name` is any registered algorithm identifier this module
/// knows (JWS `alg`, JWE `alg` or JWE `enc`), i.e. a legal value for a
/// JWK's `alg` member.
pub(crate) fn known_alg(name: &str) -> bool {
    SigAlg::from_name(name).is_some()
        || KeyAlg::from_name(name).is_some()
        || Enc::from_name(name).is_some()
}
