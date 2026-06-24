//! Per-call parameters for signing, verification, and RSA encryption.
//!
//! A single call selects the hash, padding, and context an operation uses. Each
//! algorithm reads only the fields that apply to it and ignores the rest; the
//! [`Default`] configuration always produces a valid call (RSA-PSS/SHA-256 for
//! signatures, RSA-OAEP/SHA-256 for encryption). Passing a field that an
//! algorithm cannot honour — e.g. an RSA padding to a non-RSA key when it would
//! change behaviour — yields [`Error::InvalidParams`](crate::key::Error::InvalidParams).

/// A hash function, selected at runtime.
///
/// Used by RSA and ECDSA (which are parameterised by a digest) and as the
/// OAEP/MGF1 hash for RSA encryption. EdDSA and the post-quantum schemes fix
/// their own internal hash and ignore this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Hash {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA-1 — legacy verification and interop only; do not use for new
    /// signatures.
    Sha1,
}

impl Hash {
    /// The digest output length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
            Hash::Sha1 => 20,
        }
    }
}

/// RSA signature padding scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RsaSigPadding {
    /// RSASSA-PSS (PKCS#1 v2.1) with the given salt length.
    Pss {
        /// The PSS salt length.
        salt_len: SaltLen,
    },
    /// RSASSA-PKCS1-v1_5 (PKCS#1 v1.5).
    Pkcs1v15,
}

/// PSS salt length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SaltLen {
    /// Salt length equal to the digest output length (the common default).
    DigestLength,
    /// The maximum salt length the modulus allows.
    Max,
    /// A fixed salt length in bytes.
    Fixed(usize),
}

/// RSA encryption padding scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RsaEncPadding {
    /// RSAES-OAEP (PKCS#1 v2.1) with the given digest and MGF1 hash.
    Oaep {
        /// The OAEP label/digest hash.
        hash: Hash,
        /// The MGF1 hash (commonly the same as `hash`).
        mgf1: Hash,
    },
    /// RSAES-PKCS1-v1_5 (PKCS#1 v1.5).
    Pkcs1v15,
}

/// Parameters for a signing or verification call.
///
/// Field applicability:
///
/// * `hash`, `prehashed`, `padding` — RSA and ECDSA.
/// * `context` — Ed448, ML-DSA, SLH-DSA, and the SM2 signer ID (empty means the
///   scheme default).
/// * `deterministic` — ML-DSA / SLH-DSA (choose the deterministic variant);
///   ignored elsewhere (ECDSA is already RFC 6979-deterministic, EdDSA is
///   inherently deterministic).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct SignParams<'a> {
    /// Digest to use (RSA/ECDSA). Ignored by EdDSA and PQC schemes.
    pub hash: Hash,
    /// If true, the message argument is already the digest (sign/verify the
    /// prehash). Honoured by RSA and ECDSA.
    pub prehashed: bool,
    /// Context string (Ed448 / ML-DSA / SLH-DSA) or SM2 signer ID. Empty = none
    /// / scheme default.
    pub context: &'a [u8],
    /// RSA padding scheme. Ignored by non-RSA keys.
    pub padding: RsaSigPadding,
    /// Select the deterministic variant for schemes that offer both. Ignored
    /// where it does not apply.
    pub deterministic: bool,
    /// Wire encoding for the signatures of schemes that have a choice — ECDSA
    /// and SM2, whose `(r, s)` pair can be either a fixed-width `r || s`
    /// concatenation ([`SigEncoding::Raw`]) or an ASN.1 DER `SEQUENCE`
    /// ([`SigEncoding::Der`], the X.509 / TLS / OpenSSL form). Ignored by every
    /// other scheme (their signatures have a single defined encoding).
    pub sig_encoding: SigEncoding,
}

/// Wire encoding for ECDSA / SM2 signatures (see [`SignParams::sig_encoding`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SigEncoding {
    /// Fixed-width `r || s` (each coordinate big-endian, padded to the field
    /// width). Used by JWS/COSE and the low-level fixed-curve APIs.
    #[default]
    Raw,
    /// ASN.1 DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` — the
    /// X.509, TLS, and OpenSSL encoding.
    Der,
}

impl Default for SignParams<'_> {
    fn default() -> Self {
        SignParams {
            hash: Hash::Sha256,
            prehashed: false,
            context: &[],
            padding: RsaSigPadding::Pss {
                salt_len: SaltLen::DigestLength,
            },
            deterministic: false,
            sig_encoding: SigEncoding::Raw,
        }
    }
}

impl<'a> SignParams<'a> {
    /// Default parameters (RSA-PSS/SHA-256, no context, hedged).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the digest.
    pub fn hash(mut self, hash: Hash) -> Self {
        self.hash = hash;
        self
    }

    /// Marks the message as a prehash (already digested).
    pub fn prehashed(mut self, yes: bool) -> Self {
        self.prehashed = yes;
        self
    }

    /// Sets the context string (Ed448 / ML-DSA / SLH-DSA) or SM2 signer ID.
    pub fn context(mut self, context: &'a [u8]) -> Self {
        self.context = context;
        self
    }

    /// Sets the signature wire encoding (ECDSA / SM2).
    pub fn sig_encoding(mut self, enc: SigEncoding) -> Self {
        self.sig_encoding = enc;
        self
    }

    /// Uses RSASSA-PKCS1-v1_5 padding instead of the default PSS.
    pub fn pkcs1v15(mut self) -> Self {
        self.padding = RsaSigPadding::Pkcs1v15;
        self
    }

    /// Uses RSASSA-PSS padding with the given salt length.
    pub fn pss(mut self, salt_len: SaltLen) -> Self {
        self.padding = RsaSigPadding::Pss { salt_len };
        self
    }

    /// Selects the deterministic variant (ML-DSA / SLH-DSA).
    pub fn deterministic(mut self, yes: bool) -> Self {
        self.deterministic = yes;
        self
    }
}

/// Parameters for an encryption call (RSA / SM2).
///
/// `padding` and `label` apply to RSA only; SM2 public-key encryption ignores
/// them.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct EncryptParams<'a> {
    /// RSA padding scheme.
    pub padding: RsaEncPadding,
    /// OAEP label (RSA-OAEP only). Empty = no label.
    pub label: &'a [u8],
}

impl Default for EncryptParams<'_> {
    fn default() -> Self {
        EncryptParams {
            padding: RsaEncPadding::Oaep {
                hash: Hash::Sha256,
                mgf1: Hash::Sha256,
            },
            label: &[],
        }
    }
}

impl<'a> EncryptParams<'a> {
    /// Default parameters (RSA-OAEP/SHA-256, no label).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the RSA padding scheme.
    pub fn padding(mut self, padding: RsaEncPadding) -> Self {
        self.padding = padding;
        self
    }

    /// Sets the OAEP label.
    pub fn label(mut self, label: &'a [u8]) -> Self {
        self.label = label;
        self
    }
}

/// Parameters for a decryption call (RSA / SM2).
///
/// Same shape as [`EncryptParams`]; the padding and label must match what the
/// sender used for RSA. SM2 ignores them.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DecryptParams<'a> {
    /// RSA padding scheme.
    pub padding: RsaEncPadding,
    /// OAEP label (RSA-OAEP only). Empty = no label.
    pub label: &'a [u8],
}

impl Default for DecryptParams<'_> {
    fn default() -> Self {
        DecryptParams {
            padding: RsaEncPadding::Oaep {
                hash: Hash::Sha256,
                mgf1: Hash::Sha256,
            },
            label: &[],
        }
    }
}

impl<'a> DecryptParams<'a> {
    /// Default parameters (RSA-OAEP/SHA-256, no label).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the RSA padding scheme.
    pub fn padding(mut self, padding: RsaEncPadding) -> Self {
        self.padding = padding;
        self
    }

    /// Sets the OAEP label.
    pub fn label(mut self, label: &'a [u8]) -> Self {
        self.label = label;
        self
    }
}
