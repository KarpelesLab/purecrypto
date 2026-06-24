//! Per-call parameters for signing, verification, and RSA/SM2 encryption.
//!
//! A single call selects the hash, padding, context, and signature encoding an
//! operation uses. The [`Default`] is always valid, and each builder method
//! records that its field was *explicitly set*.
//!
//! # Loud rejection of unsupported parameters
//!
//! These structs are **consume-tracked**: an algorithm reads the fields it
//! honours through a [`SignParamsReader`] (or [`CryptParamsReader`]) and then
//! calls [`finish`](SignParamsReader::finish). `finish` fails with
//! [`Error::UnsupportedParam`](crate::key::Error::UnsupportedParam) if the
//! caller explicitly set a field the algorithm did **not** read — so setting an
//! RSA padding on an Ed25519 key, or a digest on a scheme that fixes its own,
//! is rejected rather than silently ignored. An algorithm therefore never has
//! to check for parameters it doesn't use: it just reads what it needs and the
//! reader reports the rest. (The RNG is a separate argument, not a parameter, so
//! passing one to a deterministic scheme is never an error.)

use crate::key::Error;

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

// Field bits for the consume-tracking masks.
const F_HASH: u8 = 1 << 0;
const F_PREHASHED: u8 = 1 << 1;
const F_CONTEXT: u8 = 1 << 2;
const F_PADDING: u8 = 1 << 3;
const F_DETERMINISTIC: u8 = 1 << 4;
const F_SIG_ENCODING: u8 = 1 << 5;

const F_ENC_PADDING: u8 = 1 << 0;
const F_ENC_LABEL: u8 = 1 << 1;

/// Parameters for a signing or verification call.
///
/// Built with [`SignParams::new`] (or [`Default`]) plus chained setters. Which
/// fields each algorithm honours:
///
/// * `hash`, `prehashed` — RSA and ECDSA.
/// * `padding` — RSA.
/// * `sig_encoding` — ECDSA and SM2.
/// * `context` — Ed448, ML-DSA, SLH-DSA, and the SM2 signer ID.
/// * `deterministic` — ML-DSA / SLH-DSA.
///
/// Setting a field an algorithm does not honour makes the call fail with
/// [`Error::UnsupportedParam`](crate::key::Error::UnsupportedParam); see the
/// [module docs](crate::key).
#[derive(Debug, Clone, Copy)]
pub struct SignParams<'a> {
    hash: Hash,
    prehashed: bool,
    context: &'a [u8],
    padding: RsaSigPadding,
    deterministic: bool,
    sig_encoding: SigEncoding,
    set: u8,
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
            set: 0,
        }
    }
}

impl<'a> SignParams<'a> {
    /// Default parameters: nothing explicitly set, so every algorithm accepts
    /// them (RSA defaults to PSS/SHA-256, ECDSA/SM2 to raw `r||s`, etc.).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the digest (RSA / ECDSA).
    pub fn hash(mut self, hash: Hash) -> Self {
        self.hash = hash;
        self.set |= F_HASH;
        self
    }

    /// Marks the message as a prehash, already digested (RSA / ECDSA).
    pub fn prehashed(mut self, yes: bool) -> Self {
        self.prehashed = yes;
        self.set |= F_PREHASHED;
        self
    }

    /// Sets the context string (Ed448 / ML-DSA / SLH-DSA) or SM2 signer ID.
    pub fn context(mut self, context: &'a [u8]) -> Self {
        self.context = context;
        self.set |= F_CONTEXT;
        self
    }

    /// Sets the signature wire encoding (ECDSA / SM2).
    pub fn sig_encoding(mut self, enc: SigEncoding) -> Self {
        self.sig_encoding = enc;
        self.set |= F_SIG_ENCODING;
        self
    }

    /// Uses RSASSA-PKCS1-v1_5 padding instead of the default PSS (RSA).
    pub fn pkcs1v15(mut self) -> Self {
        self.padding = RsaSigPadding::Pkcs1v15;
        self.set |= F_PADDING;
        self
    }

    /// Uses RSASSA-PSS padding with the given salt length (RSA).
    pub fn pss(mut self, salt_len: SaltLen) -> Self {
        self.padding = RsaSigPadding::Pss { salt_len };
        self.set |= F_PADDING;
        self
    }

    /// Selects the deterministic variant (ML-DSA / SLH-DSA).
    pub fn deterministic(mut self, yes: bool) -> Self {
        self.deterministic = yes;
        self.set |= F_DETERMINISTIC;
        self
    }

    /// Begins consuming the parameters. An algorithm implementation reads the
    /// fields it honours through the returned reader, then calls
    /// [`finish`](SignParamsReader::finish).
    pub fn reader(&self) -> SignParamsReader<'a> {
        SignParamsReader {
            params: *self,
            used: 0,
        }
    }
}

/// Consume-tracking reader over [`SignParams`] (see the [module docs](crate::key)).
///
/// Each accessor returns the field's value (the caller's, or the default) and
/// records that the field was honoured. [`finish`](Self::finish) then rejects
/// any field the caller explicitly set but the algorithm did not read.
#[derive(Debug)]
pub struct SignParamsReader<'a> {
    params: SignParams<'a>,
    used: u8,
}

impl<'a> SignParamsReader<'a> {
    /// The digest to use.
    pub fn hash(&mut self) -> Hash {
        self.used |= F_HASH;
        self.params.hash
    }

    /// Whether the message is a prehash.
    pub fn prehashed(&mut self) -> bool {
        self.used |= F_PREHASHED;
        self.params.prehashed
    }

    /// The context string / SM2 signer ID.
    pub fn context(&mut self) -> &'a [u8] {
        self.used |= F_CONTEXT;
        self.params.context
    }

    /// The RSA padding scheme.
    pub fn padding(&mut self) -> RsaSigPadding {
        self.used |= F_PADDING;
        self.params.padding
    }

    /// Whether to use the deterministic variant.
    pub fn deterministic(&mut self) -> bool {
        self.used |= F_DETERMINISTIC;
        self.params.deterministic
    }

    /// The signature wire encoding.
    pub fn sig_encoding(&mut self) -> SigEncoding {
        self.used |= F_SIG_ENCODING;
        self.params.sig_encoding
    }

    /// Rejects any field the caller set but the algorithm did not read.
    pub fn finish(self) -> Result<(), Error> {
        match first_unconsumed(self.params.set & !self.used, SIGN_PARAM_NAMES) {
            Some(param) => Err(Error::UnsupportedParam { param }),
            None => Ok(()),
        }
    }
}

const SIGN_PARAM_NAMES: &[(u8, &str)] = &[
    (F_HASH, "hash"),
    (F_PREHASHED, "prehashed"),
    (F_CONTEXT, "context"),
    (F_PADDING, "padding"),
    (F_DETERMINISTIC, "deterministic"),
    (F_SIG_ENCODING, "sig_encoding"),
];

const CRYPT_PARAM_NAMES: &[(u8, &str)] = &[(F_ENC_PADDING, "padding"), (F_ENC_LABEL, "label")];

fn first_unconsumed(leftover: u8, names: &[(u8, &'static str)]) -> Option<&'static str> {
    if leftover == 0 {
        return None;
    }
    for &(bit, name) in names {
        if leftover & bit != 0 {
            return Some(name);
        }
    }
    Some("parameter")
}

/// Parameters for an encryption or decryption call (RSA / SM2).
///
/// `padding` and `label` apply to **RSA** only; SM2 public-key encryption fixes
/// its own scheme and honours neither — setting them on an SM2 key fails with
/// [`Error::UnsupportedParam`](crate::key::Error::UnsupportedParam). For
/// decryption the padding and label must match what the sender used.
#[derive(Debug, Clone, Copy)]
pub struct CryptParams<'a> {
    padding: RsaEncPadding,
    label: &'a [u8],
    set: u8,
}

/// Parameters for an encryption call. See [`CryptParams`].
pub type EncryptParams<'a> = CryptParams<'a>;
/// Parameters for a decryption call. See [`CryptParams`].
pub type DecryptParams<'a> = CryptParams<'a>;

impl Default for CryptParams<'_> {
    fn default() -> Self {
        CryptParams {
            padding: RsaEncPadding::Oaep {
                hash: Hash::Sha256,
                mgf1: Hash::Sha256,
            },
            label: &[],
            set: 0,
        }
    }
}

impl<'a> CryptParams<'a> {
    /// Default parameters: nothing explicitly set (RSA defaults to OAEP/SHA-256,
    /// no label).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the RSA padding scheme.
    pub fn padding(mut self, padding: RsaEncPadding) -> Self {
        self.padding = padding;
        self.set |= F_ENC_PADDING;
        self
    }

    /// Sets the OAEP label (RSA-OAEP).
    pub fn label(mut self, label: &'a [u8]) -> Self {
        self.label = label;
        self.set |= F_ENC_LABEL;
        self
    }

    /// Begins consuming the parameters (see [`SignParams::reader`]).
    pub fn reader(&self) -> CryptParamsReader<'a> {
        CryptParamsReader {
            params: *self,
            used: 0,
        }
    }
}

/// Consume-tracking reader over [`CryptParams`] (see the [module docs](crate::key)).
#[derive(Debug)]
pub struct CryptParamsReader<'a> {
    params: CryptParams<'a>,
    used: u8,
}

impl<'a> CryptParamsReader<'a> {
    /// The RSA padding scheme.
    pub fn padding(&mut self) -> RsaEncPadding {
        self.used |= F_ENC_PADDING;
        self.params.padding
    }

    /// The OAEP label.
    pub fn label(&mut self) -> &'a [u8] {
        self.used |= F_ENC_LABEL;
        self.params.label
    }

    /// Rejects any field the caller set but the algorithm did not read.
    pub fn finish(self) -> Result<(), Error> {
        match first_unconsumed(self.params.set & !self.used, CRYPT_PARAM_NAMES) {
            Some(param) => Err(Error::UnsupportedParam { param }),
            None => Ok(()),
        }
    }
}
