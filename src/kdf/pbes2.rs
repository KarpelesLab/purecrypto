//! RFC 8018 §6.2 — PBES2 (Password-Based Encryption Scheme 2).
//!
//! Wraps PKCS#8 unencrypted private keys (RFC 5958 §2) with a
//! password-derived AEAD or CBC-AES envelope (RFC 5958 §3). Used by
//! every modern `openssl pkcs8` / `openssl rsa -aes256` invocation.
//!
//! The outer DER is:
//!
//! ```text
//! EncryptedPrivateKeyInfo ::= SEQUENCE {
//!     encryptionAlgorithm  AlgorithmIdentifier,  -- id-PBES2 + PBES2-params
//!     encryptedData        OCTET STRING          -- ciphertext over PKCS#8
//! }
//! ```
//!
//! See the module-level encrypt/decrypt entry points; the per-key-type
//! helpers (`to_pkcs8_*_encrypted` / `from_pkcs8_*_encrypted`) layered on
//! top live next to each key.

use alloc::string::String;
use alloc::vec::Vec;

use crate::cipher::{Aes256, Aes256Gcm, Cbc};
use crate::der::{
    Reader, encode_integer, encode_octet_string, encode_sequence, oid_tlv, parse_oid, pem_decode,
    pem_encode,
};
use crate::hash::{Sha256, Sha512};
use crate::kdf::pbkdf2;
use crate::rng::RngCore;

/// Choice of key-derivation function for the outer envelope. Today
/// PBKDF2 with one of the listed PRFs is the only KDF supported; the
/// enum exists so scrypt (RFC 7914) can be added later without an API
/// break.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KdfChoice {
    /// PBKDF2 with HMAC-SHA-256. Default iteration count: 600_000
    /// (matching OWASP 2023 guidance — bump as compute scales).
    Pbkdf2HmacSha256 {
        /// Iteration count fed to PBKDF2.
        iterations: u32,
    },
    /// PBKDF2 with HMAC-SHA-512.
    Pbkdf2HmacSha512 {
        /// Iteration count fed to PBKDF2.
        iterations: u32,
    },
}

/// Choice of cipher for the outer envelope.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CipherChoice {
    /// AES-256 in CBC mode with PKCS#7 padding (RFC 8018 §A.4 aes256-CBC-PAD).
    /// Most interoperable with legacy tools; no built-in authentication —
    /// the PKCS#8 structural parse on decrypt is the integrity gate.
    Aes256Cbc,
    /// AES-256 in GCM mode with 12-byte nonce + 16-byte tag (RFC 5084).
    /// Authenticated; recommended for new code.
    Aes256Gcm,
}

/// Caller-supplied envelope parameters.
#[derive(Clone, Debug)]
pub struct Pbes2Params {
    /// Choice of key-derivation function and its tuning parameters.
    pub kdf: KdfChoice,
    /// Choice of underlying cipher.
    pub cipher: CipherChoice,
    /// Salt length in bytes. RFC 8018 §A.2: 8-byte minimum, 16 is plenty.
    pub salt_len: usize,
}

impl Default for Pbes2Params {
    fn default() -> Self {
        Self {
            kdf: KdfChoice::Pbkdf2HmacSha256 {
                iterations: 600_000,
            },
            cipher: CipherChoice::Aes256Gcm,
            salt_len: 16,
        }
    }
}

/// Errors returned by [`decrypt`] / [`decrypt_pem`].
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Outer DER didn't parse as `EncryptedPrivateKeyInfo`, or the PEM
    /// label / Base64 body was malformed.
    BadEncoding,
    /// Algorithm OID we don't recognize (e.g. PBES1, scrypt, AES-128-CBC,
    /// HMAC-SHA-1).
    UnsupportedAlgorithm,
    /// AEAD authentication failed OR CBC padding was invalid OR the
    /// derived key was somehow wrong. Returned as one variant to avoid a
    /// padding oracle.
    Decryption,
    /// Iteration count below the floor we accept (currently 10_000).
    WeakKdfParameters,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::BadEncoding => f.write_str("malformed EncryptedPrivateKeyInfo"),
            Error::UnsupportedAlgorithm => f.write_str("unsupported PBES2 algorithm"),
            Error::Decryption => f.write_str("PBES2 decryption failed"),
            Error::WeakKdfParameters => f.write_str("PBES2 KDF parameters below safety floor"),
        }
    }
}

impl core::error::Error for Error {}

// ---- OID constants ------------------------------------------------------

/// `id-PBES2` (RFC 8018 §A.4).
const OID_PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
/// `id-PBKDF2` (RFC 8018 §A.2).
const OID_PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
/// `hmacWithSHA256` (RFC 8018 §B.1.2).
const OID_HMAC_WITH_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
/// `hmacWithSHA512`.
const OID_HMAC_WITH_SHA512: &[u64] = &[1, 2, 840, 113549, 2, 11];
/// `aes256-CBC-PAD` (NIST aes algorithms, RFC 8018 §A.4).
const OID_AES256_CBC_PAD: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
/// `aes256-GCM` (RFC 5084).
const OID_AES256_GCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 46];

/// PBKDF2 iteration-count floor enforced on decrypt. Anything weaker is
/// rejected as [`Error::WeakKdfParameters`]; this catches both fixture-style
/// (1) and historical OpenSSL-default (2048) inputs that we don't want to
/// silently accept.
const MIN_PBKDF2_ITERATIONS: u32 = 10_000;

/// PEM label for `EncryptedPrivateKeyInfo` (RFC 7468 §11).
const PEM_LABEL: &str = "ENCRYPTED PRIVATE KEY";

// ---- Public API ---------------------------------------------------------

/// Encrypts `pkcs8_der` with `password`. Generates random salt + IV.
/// Returns the DER-encoded `EncryptedPrivateKeyInfo`.
pub fn encrypt(
    pkcs8_der: &[u8],
    password: &[u8],
    params: &Pbes2Params,
    rng: &mut impl RngCore,
) -> Vec<u8> {
    assert!(params.salt_len >= 8, "PBES2 salt must be at least 8 bytes");

    // 1. Salt.
    let mut salt = alloc::vec![0u8; params.salt_len];
    rng.fill_bytes(&mut salt);

    // 2. Derive a 32-byte AES-256 key.
    let key = derive_key(password, &salt, &params.kdf);

    // 3. Encrypt.
    let (cipher_algid, ciphertext) = match params.cipher {
        CipherChoice::Aes256Gcm => {
            let mut iv = [0u8; 12];
            rng.fill_bytes(&mut iv);
            let gcm = Aes256Gcm::new(Aes256::new(&key));
            let mut buf = pkcs8_der.to_vec();
            let tag = gcm.encrypt(&iv, &[], &mut buf);
            buf.extend_from_slice(&tag);
            (encode_aes256_gcm_algid(&iv), buf)
        }
        CipherChoice::Aes256Cbc => {
            let mut iv = [0u8; 16];
            rng.fill_bytes(&mut iv);
            let pad_len = 16 - (pkcs8_der.len() % 16);
            let mut buf = Vec::with_capacity(pkcs8_der.len() + pad_len);
            buf.extend_from_slice(pkcs8_der);
            buf.extend(core::iter::repeat_n(pad_len as u8, pad_len));
            Cbc::new(Aes256::new(&key), &iv)
                .encrypt(&mut buf)
                .expect("CBC encrypt: padded length is a multiple of 16");
            (encode_aes256_cbc_algid(&iv), buf)
        }
    };

    // 4. PBES2-params SEQUENCE.
    let pbes2_params =
        encode_sequence(&[encode_pbkdf2_algid(&salt, &params.kdf), cipher_algid].concat());

    // 5. Outer AlgorithmIdentifier.
    let outer_algid = encode_sequence(&[oid_tlv(OID_PBES2), pbes2_params].concat());

    // 6. Final EncryptedPrivateKeyInfo.
    encode_sequence(&[outer_algid, encode_octet_string(&ciphertext)].concat())
}

/// Decrypts the encrypted-PKCS#8 envelope with `password`. Returns the
/// inner unencrypted PKCS#8 DER bytes.
pub fn decrypt(encrypted_pkcs8_der: &[u8], password: &[u8]) -> Result<Vec<u8>, Error> {
    // ---- Outer SEQUENCE ----
    let mut reader = Reader::new(encrypted_pkcs8_der);
    let mut outer = reader.read_sequence().map_err(|_| Error::BadEncoding)?;
    let mut algid = outer.read_sequence().map_err(|_| Error::BadEncoding)?;

    // ---- encryptionAlgorithm OID ----
    let oid = parse_oid(algid.read_oid().map_err(|_| Error::BadEncoding)?)
        .map_err(|_| Error::BadEncoding)?;
    if oid.as_slice() != OID_PBES2 {
        return Err(Error::UnsupportedAlgorithm);
    }

    // ---- PBES2-params: SEQUENCE { kdf, cipher } ----
    let mut pbes2_params = algid.read_sequence().map_err(|_| Error::BadEncoding)?;
    algid.finish().map_err(|_| Error::BadEncoding)?;

    let (kdf, salt) = parse_kdf_algid(&mut pbes2_params)?;
    let (cipher_kind, iv_bytes) = parse_cipher_algid(&mut pbes2_params)?;
    pbes2_params.finish().map_err(|_| Error::BadEncoding)?;

    // ---- encryptedData OCTET STRING ----
    let ciphertext = outer.read_octet_string().map_err(|_| Error::BadEncoding)?;
    outer.finish().map_err(|_| Error::BadEncoding)?;
    reader.finish().map_err(|_| Error::BadEncoding)?;

    // ---- KDF: derive a 32-byte AES-256 key ----
    let key = derive_key(password, &salt, &kdf);

    // ---- Cipher: decrypt ----
    match cipher_kind {
        CipherChoice::Aes256Gcm => {
            if iv_bytes.len() != 12 {
                return Err(Error::BadEncoding);
            }
            if ciphertext.len() < 16 {
                return Err(Error::Decryption);
            }
            let split = ciphertext.len() - 16;
            let (ct, tag) = ciphertext.split_at(split);
            let mut buf = ct.to_vec();
            let mut tag_arr = [0u8; 16];
            tag_arr.copy_from_slice(tag);
            let mut iv_arr = [0u8; 12];
            iv_arr.copy_from_slice(&iv_bytes);
            let gcm = Aes256Gcm::new(Aes256::new(&key));
            gcm.decrypt(&iv_arr, &[], &mut buf, &tag_arr)
                .map_err(|_| Error::Decryption)?;
            Ok(buf)
        }
        CipherChoice::Aes256Cbc => {
            if iv_bytes.len() != 16 {
                return Err(Error::BadEncoding);
            }
            if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
                return Err(Error::Decryption);
            }
            let mut iv_arr = [0u8; 16];
            iv_arr.copy_from_slice(&iv_bytes);
            let mut buf = ciphertext.to_vec();
            Cbc::new(Aes256::new(&key), &iv_arr)
                .decrypt(&mut buf)
                .map_err(|_| Error::Decryption)?;
            // Constant-time PKCS#7 padding validation, then strip the padding.
            let stripped = strip_pkcs7_padding(buf)?;
            Ok(stripped)
        }
    }
}

/// PEM-wrapped variant of [`encrypt`] using the RFC 7468 §11
/// `ENCRYPTED PRIVATE KEY` label.
pub fn encrypt_pem(
    pkcs8_der: &[u8],
    password: &[u8],
    params: &Pbes2Params,
    rng: &mut impl RngCore,
) -> String {
    pem_encode(PEM_LABEL, &encrypt(pkcs8_der, password, params, rng))
}

/// PEM-wrapped variant of [`decrypt`].
pub fn decrypt_pem(pem: &str, password: &[u8]) -> Result<Vec<u8>, Error> {
    let der = pem_decode(pem, PEM_LABEL).map_err(|_| Error::BadEncoding)?;
    decrypt(&der, password)
}

// ---- Internals ----------------------------------------------------------

/// Decodes a parsed KDF `AlgorithmIdentifier` from the next position of
/// `r`, returning the chosen KDF + its salt. Enforces PBKDF2 + a
/// supported PRF + iteration-count floor.
fn parse_kdf_algid(r: &mut Reader<'_>) -> Result<(KdfChoice, Vec<u8>), Error> {
    let mut kdf_seq = r.read_sequence().map_err(|_| Error::BadEncoding)?;
    let oid = parse_oid(kdf_seq.read_oid().map_err(|_| Error::BadEncoding)?)
        .map_err(|_| Error::BadEncoding)?;
    if oid.as_slice() != OID_PBKDF2 {
        return Err(Error::UnsupportedAlgorithm);
    }

    // PBKDF2-params SEQUENCE { salt OCTET STRING, iterationCount INTEGER,
    //                         keyLength INTEGER OPTIONAL,
    //                         prf AlgorithmIdentifier DEFAULT hmacWithSHA1 }
    let mut p = kdf_seq.read_sequence().map_err(|_| Error::BadEncoding)?;
    kdf_seq.finish().map_err(|_| Error::BadEncoding)?;

    let salt = p
        .read_octet_string()
        .map_err(|_| Error::BadEncoding)?
        .to_vec();
    let iter_bytes = p.read_integer_bytes().map_err(|_| Error::BadEncoding)?;
    let iterations = integer_to_u32(iter_bytes)?;
    if iterations < MIN_PBKDF2_ITERATIONS {
        return Err(Error::WeakKdfParameters);
    }

    // Optional keyLength: skip if present (we always derive 32 bytes for
    // AES-256). If declared, sanity-check it.
    if let Some(tag) = p.peek_tag()
        && tag == crate::der::tag::INTEGER
    {
        let kl_bytes = p.read_integer_bytes().map_err(|_| Error::BadEncoding)?;
        let kl = integer_to_u32(kl_bytes)?;
        if kl != 32 {
            return Err(Error::UnsupportedAlgorithm);
        }
    }

    // PRF: SEQUENCE; if absent, default is hmacWithSHA1 (which we reject).
    let prf_kdf = if p.peek_tag().is_some() {
        let mut prf = p.read_sequence().map_err(|_| Error::BadEncoding)?;
        let prf_oid = parse_oid(prf.read_oid().map_err(|_| Error::BadEncoding)?)
            .map_err(|_| Error::BadEncoding)?;
        // PRF parameters are NULL per RFC 8018 §B.1.2; accept absent too for
        // lenient parsing.
        if !prf.is_empty() {
            prf.read_null().map_err(|_| Error::BadEncoding)?;
        }
        prf.finish().map_err(|_| Error::BadEncoding)?;
        if prf_oid.as_slice() == OID_HMAC_WITH_SHA256 {
            KdfChoice::Pbkdf2HmacSha256 { iterations }
        } else if prf_oid.as_slice() == OID_HMAC_WITH_SHA512 {
            KdfChoice::Pbkdf2HmacSha512 { iterations }
        } else {
            return Err(Error::UnsupportedAlgorithm);
        }
    } else {
        // DEFAULT hmacWithSHA1 — too weak for us.
        return Err(Error::UnsupportedAlgorithm);
    };

    p.finish().map_err(|_| Error::BadEncoding)?;
    Ok((prf_kdf, salt))
}

/// Decodes the cipher `AlgorithmIdentifier`, returning the cipher choice
/// and the wire IV bytes.
fn parse_cipher_algid(r: &mut Reader<'_>) -> Result<(CipherChoice, Vec<u8>), Error> {
    let mut cipher_seq = r.read_sequence().map_err(|_| Error::BadEncoding)?;
    let oid = parse_oid(cipher_seq.read_oid().map_err(|_| Error::BadEncoding)?)
        .map_err(|_| Error::BadEncoding)?;

    if oid.as_slice() == OID_AES256_CBC_PAD {
        let iv = cipher_seq
            .read_octet_string()
            .map_err(|_| Error::BadEncoding)?
            .to_vec();
        cipher_seq.finish().map_err(|_| Error::BadEncoding)?;
        Ok((CipherChoice::Aes256Cbc, iv))
    } else if oid.as_slice() == OID_AES256_GCM {
        // GCMParameters ::= SEQUENCE { aes-nonce OCTET STRING,
        //                              aes-ICVlen INTEGER DEFAULT 12 }
        let mut gcm = cipher_seq.read_sequence().map_err(|_| Error::BadEncoding)?;
        cipher_seq.finish().map_err(|_| Error::BadEncoding)?;
        let nonce = gcm
            .read_octet_string()
            .map_err(|_| Error::BadEncoding)?
            .to_vec();
        if let Some(tag) = gcm.peek_tag()
            && tag == crate::der::tag::INTEGER
        {
            let icv = integer_to_u32(gcm.read_integer_bytes().map_err(|_| Error::BadEncoding)?)?;
            // We only support a 16-byte tag (RFC 5084 strongly recommends
            // 16; anything else opens us to truncation attacks).
            if icv != 16 {
                return Err(Error::UnsupportedAlgorithm);
            }
        }
        gcm.finish().map_err(|_| Error::BadEncoding)?;
        Ok((CipherChoice::Aes256Gcm, nonce))
    } else {
        Err(Error::UnsupportedAlgorithm)
    }
}

/// Converts a DER `INTEGER` body to `u32`, rejecting negatives, non-minimal
/// encodings, and values that don't fit.
fn integer_to_u32(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.is_empty() {
        return Err(Error::BadEncoding);
    }
    // DER INTEGERs are two's-complement: the sign lives in the high bit of
    // the FIRST content byte, before any leading 0x00 pad is stripped. A
    // value like 40_000 is encoded `00 9C 40` — the 0x00 keeps it positive
    // even though 0x9C has its high bit set.
    if bytes[0] & 0x80 != 0 {
        // Negative — reject.
        return Err(Error::BadEncoding);
    }
    // DER minimality: a leading 0x00 is only valid when the next byte would
    // otherwise flip the sign bit.
    if bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
        return Err(Error::BadEncoding);
    }
    let trimmed = if bytes[0] == 0 && bytes.len() > 1 {
        &bytes[1..]
    } else {
        bytes
    };
    if trimmed.len() > 4 {
        return Err(Error::WeakKdfParameters); // way out of range; conservative.
    }
    let mut acc: u32 = 0;
    for &b in trimmed {
        acc = (acc << 8) | b as u32;
    }
    Ok(acc)
}

/// Derives a 32-byte AES-256 key from the password + salt using the
/// requested PBKDF2 variant.
fn derive_key(password: &[u8], salt: &[u8], kdf: &KdfChoice) -> [u8; 32] {
    let mut out = [0u8; 32];
    match *kdf {
        KdfChoice::Pbkdf2HmacSha256 { iterations } => {
            pbkdf2::<Sha256>(password, salt, iterations, &mut out);
        }
        KdfChoice::Pbkdf2HmacSha512 { iterations } => {
            pbkdf2::<Sha512>(password, salt, iterations, &mut out);
        }
    }
    out
}

/// Encodes the PBKDF2 `AlgorithmIdentifier` over the chosen PRF + salt.
fn encode_pbkdf2_algid(salt: &[u8], kdf: &KdfChoice) -> Vec<u8> {
    let (iterations, prf_oid) = match *kdf {
        KdfChoice::Pbkdf2HmacSha256 { iterations } => (iterations, OID_HMAC_WITH_SHA256),
        KdfChoice::Pbkdf2HmacSha512 { iterations } => (iterations, OID_HMAC_WITH_SHA512),
    };
    // PRF: SEQUENCE { OID hmacWithSHAxxx, NULL parameters }.
    let prf = encode_sequence(&[oid_tlv(prf_oid), crate::der::encode_null()].concat());
    let iter_be = iterations.to_be_bytes();
    let params =
        encode_sequence(&[encode_octet_string(salt), encode_integer(&iter_be), prf].concat());
    encode_sequence(&[oid_tlv(OID_PBKDF2), params].concat())
}

/// Encodes the AES-256-CBC-PAD cipher AlgorithmIdentifier.
fn encode_aes256_cbc_algid(iv: &[u8; 16]) -> Vec<u8> {
    encode_sequence(&[oid_tlv(OID_AES256_CBC_PAD), encode_octet_string(iv)].concat())
}

/// Encodes the AES-256-GCM cipher AlgorithmIdentifier (RFC 5084).
fn encode_aes256_gcm_algid(nonce: &[u8; 12]) -> Vec<u8> {
    // GCMParameters SEQUENCE { nonce OCTET STRING, icvlen INTEGER }.
    // We always emit icvlen = 16 (omitting the field would mean DEFAULT
    // 12; explicit 16 is unambiguous and within our supported set).
    let icvlen_be = 16u32.to_be_bytes();
    let params =
        encode_sequence(&[encode_octet_string(nonce), encode_integer(&icvlen_be)].concat());
    encode_sequence(&[oid_tlv(OID_AES256_GCM), params].concat())
}

/// Validates PKCS#7 padding on `buf` in constant time, returning the
/// payload with padding stripped. Any padding violation returns
/// [`Error::Decryption`] without leaking which byte (or which check)
/// failed.
fn strip_pkcs7_padding(mut buf: Vec<u8>) -> Result<Vec<u8>, Error> {
    let n = buf.len();
    if n == 0 || !n.is_multiple_of(16) {
        return Err(Error::Decryption);
    }
    let last = buf[n - 1];

    // Treat `last` as the claimed padding length. Compute a constant-time
    // "valid" accumulator that combines:
    //   * `last` is in 1..=16,
    //   * the last `last` bytes all equal `last`.
    // We always inspect the trailing 16 bytes regardless of the claimed
    // `last`, so the memory-access pattern doesn't depend on the value.
    let pad_len = last as usize;

    // `range_ok` is 0xFF if 1 <= last <= 16, else 0x00.
    let range_ok = ct_in_range_1_to_16(last);

    // `bytes_ok` is 0xFF iff each of the last 16 bytes matches: positions
    // (n-16) .. (n-1-pad_len) are unconstrained; positions (n-pad_len)..n
    // must equal `pad_len`. The mask `is_pad[i]` indicates whether
    // position `i` falls in the padding region.
    let mut bytes_ok: u8 = 0xFF;
    let start = n - 16;
    for (i, b) in buf[start..].iter().enumerate() {
        let pos_from_end = 16 - i; // 16, 15, ..., 1
        // is_pad: 0xFF when `pos_from_end <= pad_len`, else 0x00.
        let is_pad = ct_le_u8(pos_from_end as u8, last);
        // diff: 0 iff *b == last
        let diff = b ^ last;
        // If is_pad and diff != 0, byte_bad = 0xFF; else 0x00.
        let any_diff = ct_nonzero_u8(diff);
        let byte_bad = is_pad & any_diff;
        bytes_ok &= !byte_bad;
    }

    let valid = range_ok & bytes_ok;
    // Convert mask to bool without branching on secret-dependent bits:
    // we then branch on `valid_bool` but only to return Err vs strip — by
    // this point the padding has already been read in fixed order, so the
    // branch direction is the only thing the caller observes.
    if valid != 0xFF {
        return Err(Error::Decryption);
    }
    buf.truncate(n - pad_len);
    Ok(buf)
}

/// Constant-time `(x <= y)` over `u8`, returning `0xFF` for true and
/// `0x00` for false.
#[inline]
fn ct_le_u8(x: u8, y: u8) -> u8 {
    // (y - x) borrow: if x > y the high bit of (y - x) as i16 is set.
    let diff = y as i16 - x as i16;
    // diff >= 0  ->  high bit of diff cleared  ->  want 0xFF.
    // diff < 0   ->  high bit set              ->  want 0x00.
    let sign = ((diff as u16) >> 15) as u8; // 1 if negative, 0 otherwise.
    sign.wrapping_sub(1) // 0 -> 0xFF; 1 -> 0x00
}

/// Constant-time "x != 0", returning `0xFF` if nonzero else `0x00`.
#[inline]
fn ct_nonzero_u8(x: u8) -> u8 {
    // Spread the OR of all bits into bit 0, then mask-extend.
    let mut v = x;
    v |= v >> 4;
    v |= v >> 2;
    v |= v >> 1;
    let bit = v & 1;
    0u8.wrapping_sub(bit)
}

/// Constant-time "1 <= x <= 16".
#[inline]
fn ct_in_range_1_to_16(x: u8) -> u8 {
    // x >= 1: NOT (x == 0); x <= 16.
    let nonzero = ct_nonzero_u8(x);
    let le_16 = ct_le_u8(x, 16);
    nonzero & le_16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    /// Test RNG seeded deterministically so failures reproduce.
    fn test_rng(seed: &[u8]) -> HmacDrbg<Sha256> {
        HmacDrbg::<Sha256>::new(seed, b"pbes2-test", &[])
    }

    /// Fake PKCS#8 payload — `decrypt` doesn't actually parse the
    /// plaintext, so any byte string round-trips.
    fn synthetic_pkcs8() -> Vec<u8> {
        let mut v = Vec::new();
        // SEQUENCE { OCTET STRING "hello PKCS#8" }
        v.extend_from_slice(&[0x30, 0x0e, 0x04, 0x0c]);
        v.extend_from_slice(b"hello PKCS#8");
        v
    }

    #[test]
    fn roundtrip_aes256_gcm() {
        let mut rng = test_rng(b"gcm-roundtrip");
        let inner = synthetic_pkcs8();
        let params = Pbes2Params {
            kdf: KdfChoice::Pbkdf2HmacSha256 { iterations: 10_000 },
            cipher: CipherChoice::Aes256Gcm,
            salt_len: 16,
        };
        let blob = encrypt(&inner, b"swordfish", &params, &mut rng);
        let out = decrypt(&blob, b"swordfish").unwrap();
        assert_eq!(out, inner);
    }

    #[test]
    fn roundtrip_aes256_cbc() {
        let mut rng = test_rng(b"cbc-roundtrip");
        let inner = synthetic_pkcs8();
        let params = Pbes2Params {
            kdf: KdfChoice::Pbkdf2HmacSha256 { iterations: 10_000 },
            cipher: CipherChoice::Aes256Cbc,
            salt_len: 16,
        };
        let blob = encrypt(&inner, b"swordfish", &params, &mut rng);
        let out = decrypt(&blob, b"swordfish").unwrap();
        assert_eq!(out, inner);
    }

    #[test]
    fn roundtrip_aes256_cbc_aligned_input() {
        // Plaintext is already a multiple of 16 — exercises the
        // "append a full pad block" branch.
        let mut rng = test_rng(b"cbc-aligned");
        let inner = alloc::vec![0xaau8; 32];
        let params = Pbes2Params {
            kdf: KdfChoice::Pbkdf2HmacSha512 { iterations: 10_000 },
            cipher: CipherChoice::Aes256Cbc,
            salt_len: 16,
        };
        let blob = encrypt(&inner, b"hunter2", &params, &mut rng);
        let out = decrypt(&blob, b"hunter2").unwrap();
        assert_eq!(out, inner);
    }

    #[test]
    fn wrong_password_rejected_gcm() {
        let mut rng = test_rng(b"wrong-pw-gcm");
        let inner = synthetic_pkcs8();
        let params = Pbes2Params {
            kdf: KdfChoice::Pbkdf2HmacSha256 { iterations: 10_000 },
            cipher: CipherChoice::Aes256Gcm,
            salt_len: 16,
        };
        let blob = encrypt(&inner, b"correct", &params, &mut rng);
        assert_eq!(decrypt(&blob, b"wrong"), Err(Error::Decryption));
    }

    #[test]
    fn wrong_password_rejected_cbc() {
        let mut rng = test_rng(b"wrong-pw-cbc");
        let inner = synthetic_pkcs8();
        let params = Pbes2Params {
            kdf: KdfChoice::Pbkdf2HmacSha256 { iterations: 10_000 },
            cipher: CipherChoice::Aes256Cbc,
            salt_len: 16,
        };
        let blob = encrypt(&inner, b"correct", &params, &mut rng);
        // CBC has no MAC; wrong password yields garbled bytes whose padding
        // is overwhelmingly likely to be invalid -> Decryption.
        assert_eq!(decrypt(&blob, b"wrong"), Err(Error::Decryption));
    }

    #[test]
    fn tampered_ciphertext_rejected_gcm() {
        let mut rng = test_rng(b"tamper-ct-gcm");
        let inner = synthetic_pkcs8();
        let params = Pbes2Params {
            kdf: KdfChoice::Pbkdf2HmacSha256 { iterations: 10_000 },
            cipher: CipherChoice::Aes256Gcm,
            salt_len: 16,
        };
        let mut blob = encrypt(&inner, b"pass", &params, &mut rng);
        // Flip a byte in the OCTET STRING payload. The OCTET STRING is the
        // last TLV in the outer SEQUENCE; the final byte is part of the
        // GCM tag, so flipping it tests the auth check directly. Flip a
        // few bytes earlier to also exercise the ciphertext path.
        let n = blob.len();
        blob[n - 20] ^= 0x01;
        assert_eq!(decrypt(&blob, b"pass"), Err(Error::Decryption));
    }

    #[test]
    fn tampered_iv_rejected_gcm() {
        let mut rng = test_rng(b"tamper-iv-gcm");
        let inner = synthetic_pkcs8();
        let params = Pbes2Params {
            kdf: KdfChoice::Pbkdf2HmacSha256 { iterations: 10_000 },
            cipher: CipherChoice::Aes256Gcm,
            salt_len: 16,
        };
        let blob = encrypt(&inner, b"pass", &params, &mut rng);
        // Re-decode the outer DER and flip a byte inside the GCM nonce
        // OCTET STRING. Easier: re-parse to locate it.
        // Quick-and-dirty: scan for the nonce OCTET STRING pattern (the
        // nonce is 12 bytes, so look for `04 0c`) inside the GCM params.
        let mut tampered = blob.clone();
        // The first `04 0c` after the AES-GCM OID identifies the nonce.
        // OID `aes256-GCM`'s last byte is 0x2e (46); search for it.
        let mut idx = 0;
        while idx + 1 < tampered.len() {
            if tampered[idx] == 0x04 && tampered[idx + 1] == 0x0c {
                // 12-byte OCTET STRING — flip the first content byte.
                tampered[idx + 2] ^= 0x01;
                break;
            }
            idx += 1;
        }
        assert_eq!(decrypt(&tampered, b"pass"), Err(Error::Decryption));
    }

    /// Handcraft an EncryptedPrivateKeyInfo with PBKDF2 iterations = 100
    /// and verify the floor rejects it.
    #[test]
    fn reject_pbkdf2_iterations_below_10k() {
        let salt = [0u8; 16];
        let prf =
            encode_sequence(&[oid_tlv(OID_HMAC_WITH_SHA256), crate::der::encode_null()].concat());
        let kdf_params = encode_sequence(
            &[
                encode_octet_string(&salt),
                encode_integer(&100u32.to_be_bytes()),
                prf,
            ]
            .concat(),
        );
        let kdf_algid = encode_sequence(&[oid_tlv(OID_PBKDF2), kdf_params].concat());
        let iv = [0u8; 16];
        let cipher_algid =
            encode_sequence(&[oid_tlv(OID_AES256_CBC_PAD), encode_octet_string(&iv)].concat());
        let pbes2_params = encode_sequence(&[kdf_algid, cipher_algid].concat());
        let outer_algid = encode_sequence(&[oid_tlv(OID_PBES2), pbes2_params].concat());
        // Bogus ciphertext block (1 AES block of zeros) — we never reach decryption.
        let ct = alloc::vec![0u8; 16];
        let blob = encode_sequence(&[outer_algid, encode_octet_string(&ct)].concat());
        assert_eq!(decrypt(&blob, b"x"), Err(Error::WeakKdfParameters));
    }

    /// Handcraft an EncryptedPrivateKeyInfo with HMAC-SHA-1 PRF — we
    /// refuse it entirely.
    #[test]
    fn reject_unsupported_prf() {
        let salt = [0u8; 16];
        // hmacWithSHA1 OID: 1.2.840.113549.2.7
        let hmac_sha1: &[u64] = &[1, 2, 840, 113549, 2, 7];
        let prf = encode_sequence(&[oid_tlv(hmac_sha1), crate::der::encode_null()].concat());
        let kdf_params = encode_sequence(
            &[
                encode_octet_string(&salt),
                encode_integer(&100_000u32.to_be_bytes()),
                prf,
            ]
            .concat(),
        );
        let kdf_algid = encode_sequence(&[oid_tlv(OID_PBKDF2), kdf_params].concat());
        let iv = [0u8; 16];
        let cipher_algid =
            encode_sequence(&[oid_tlv(OID_AES256_CBC_PAD), encode_octet_string(&iv)].concat());
        let pbes2_params = encode_sequence(&[kdf_algid, cipher_algid].concat());
        let outer_algid = encode_sequence(&[oid_tlv(OID_PBES2), pbes2_params].concat());
        let ct = alloc::vec![0u8; 16];
        let blob = encode_sequence(&[outer_algid, encode_octet_string(&ct)].concat());
        assert_eq!(decrypt(&blob, b"x"), Err(Error::UnsupportedAlgorithm));
    }

    /// Outer algorithm OID != PBES2 -> UnsupportedAlgorithm.
    #[test]
    fn reject_pbes1_outer_oid() {
        // pbeWithMD5AndDES-CBC -> 1.2.840.113549.1.5.3 (PBES1)
        let pbes1: &[u64] = &[1, 2, 840, 113549, 1, 5, 3];
        let outer_algid = encode_sequence(&[oid_tlv(pbes1), crate::der::encode_null()].concat());
        let ct = alloc::vec![0u8; 16];
        let blob = encode_sequence(&[outer_algid, encode_octet_string(&ct)].concat());
        assert_eq!(decrypt(&blob, b"x"), Err(Error::UnsupportedAlgorithm));
    }

    /// Inner cipher AES-128-CBC -> UnsupportedAlgorithm.
    #[test]
    fn reject_unsupported_cipher() {
        let aes128_cbc: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 2];
        let salt = [0u8; 16];
        let prf =
            encode_sequence(&[oid_tlv(OID_HMAC_WITH_SHA256), crate::der::encode_null()].concat());
        let kdf_params = encode_sequence(
            &[
                encode_octet_string(&salt),
                encode_integer(&100_000u32.to_be_bytes()),
                prf,
            ]
            .concat(),
        );
        let kdf_algid = encode_sequence(&[oid_tlv(OID_PBKDF2), kdf_params].concat());
        let iv = [0u8; 16];
        let cipher_algid =
            encode_sequence(&[oid_tlv(aes128_cbc), encode_octet_string(&iv)].concat());
        let pbes2_params = encode_sequence(&[kdf_algid, cipher_algid].concat());
        let outer_algid = encode_sequence(&[oid_tlv(OID_PBES2), pbes2_params].concat());
        let ct = alloc::vec![0u8; 16];
        let blob = encode_sequence(&[outer_algid, encode_octet_string(&ct)].concat());
        assert_eq!(decrypt(&blob, b"x"), Err(Error::UnsupportedAlgorithm));
    }

    #[test]
    fn pem_roundtrip() {
        let mut rng = test_rng(b"pem-roundtrip");
        let inner = synthetic_pkcs8();
        let params = Pbes2Params {
            kdf: KdfChoice::Pbkdf2HmacSha256 { iterations: 10_000 },
            cipher: CipherChoice::Aes256Gcm,
            salt_len: 16,
        };
        let pem = encrypt_pem(&inner, b"pass", &params, &mut rng);
        assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"));
        assert!(
            pem.trim_end()
                .ends_with("-----END ENCRYPTED PRIVATE KEY-----")
        );
        let out = decrypt_pem(&pem, b"pass").unwrap();
        assert_eq!(out, inner);
    }

    #[test]
    fn rejects_bad_pem() {
        // Not a PEM at all.
        assert_eq!(decrypt_pem("not pem", b"x"), Err(Error::BadEncoding));
        // Wrong label.
        let pem = "-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n";
        assert_eq!(decrypt_pem(pem, b"x"), Err(Error::BadEncoding));
    }

    /// `integer_to_u32` accepts every valid DER non-negative INTEGER body
    /// across the byte-length band boundaries — in particular the
    /// leading-0x00-then-high-bit forms (`00 9C 40` = 40_000) that the old
    /// sign check wrongly rejected — and still refuses negatives,
    /// non-minimal padding, and values beyond `u32::MAX`.
    #[test]
    fn integer_to_u32_band_boundaries() {
        // 1-byte band.
        assert_eq!(integer_to_u32(&[0x00]), Ok(0));
        assert_eq!(integer_to_u32(&[0x7F]), Ok(127));
        // 128..=255: encoded with a leading 0x00 pad.
        assert_eq!(integer_to_u32(&[0x00, 0x80]), Ok(128));
        assert_eq!(integer_to_u32(&[0x00, 0xC8]), Ok(200));
        assert_eq!(integer_to_u32(&[0x00, 0xFF]), Ok(255));
        // 2-byte band.
        assert_eq!(integer_to_u32(&[0x01, 0x00]), Ok(256));
        assert_eq!(integer_to_u32(&[0x7F, 0xFF]), Ok(32_767));
        // 32_768..=65_535: leading 0x00 pad again.
        assert_eq!(integer_to_u32(&[0x00, 0x80, 0x00]), Ok(32_768));
        assert_eq!(integer_to_u32(&[0x00, 0x9C, 0x40]), Ok(40_000));
        assert_eq!(integer_to_u32(&[0x00, 0xFF, 0xFF]), Ok(65_535));
        // 3-byte band.
        assert_eq!(integer_to_u32(&[0x01, 0x00, 0x00]), Ok(65_536));
        assert_eq!(integer_to_u32(&[0x7F, 0xFF, 0xFF]), Ok(8_388_607));
        // 8_388_608..=16_777_215: leading 0x00 pad.
        assert_eq!(integer_to_u32(&[0x00, 0x80, 0x00, 0x00]), Ok(8_388_608));
        assert_eq!(integer_to_u32(&[0x00, 0xFF, 0xFF, 0xFF]), Ok(16_777_215));
        // 4-byte band.
        assert_eq!(integer_to_u32(&[0x01, 0x00, 0x00, 0x00]), Ok(16_777_216));
        assert_eq!(integer_to_u32(&[0x7F, 0xFF, 0xFF, 0xFF]), Ok(2_147_483_647));
        // >= 2^31 needs the pad byte to stay positive.
        assert_eq!(
            integer_to_u32(&[0x00, 0x80, 0x00, 0x00, 0x00]),
            Ok(2_147_483_648)
        );
        assert_eq!(
            integer_to_u32(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF]),
            Ok(u32::MAX)
        );

        // Negatives are rejected (high bit of the FIRST byte set).
        assert_eq!(integer_to_u32(&[0x80]), Err(Error::BadEncoding));
        assert_eq!(integer_to_u32(&[0xFF, 0x7F]), Err(Error::BadEncoding));
        // Non-minimal zero padding is rejected.
        assert_eq!(integer_to_u32(&[0x00, 0x00]), Err(Error::BadEncoding));
        assert_eq!(integer_to_u32(&[0x00, 0x7F]), Err(Error::BadEncoding));
        assert_eq!(integer_to_u32(&[0x00, 0x01, 0x00]), Err(Error::BadEncoding));
        // Empty body is rejected.
        assert_eq!(integer_to_u32(&[]), Err(Error::BadEncoding));
        // Beyond u32::MAX.
        assert_eq!(
            integer_to_u32(&[0x01, 0x00, 0x00, 0x00, 0x00]),
            Err(Error::WeakKdfParameters)
        );
    }

    /// Round-trip with an iteration count whose minimal encoding carries a
    /// leading 0x00 pad (`40_000` → `00 9C 40`). The old sign check rejected
    /// this library's own output for any count in 32_768..=65_535.
    #[test]
    fn roundtrip_iterations_with_high_bit_encoding() {
        let mut rng = test_rng(b"high-bit-iter");
        let inner = synthetic_pkcs8();
        let params = Pbes2Params {
            kdf: KdfChoice::Pbkdf2HmacSha256 { iterations: 40_000 },
            cipher: CipherChoice::Aes256Gcm,
            salt_len: 16,
        };
        let blob = encrypt(&inner, b"swordfish", &params, &mut rng);
        let out = decrypt(&blob, b"swordfish").unwrap();
        assert_eq!(out, inner);
    }

    /// Constant-time helpers behave as advertised.
    #[test]
    fn ct_helpers() {
        assert_eq!(ct_nonzero_u8(0), 0x00);
        for v in 1u8..=255 {
            assert_eq!(ct_nonzero_u8(v), 0xFF, "v={v}");
        }
        assert_eq!(ct_le_u8(0, 0), 0xFF);
        assert_eq!(ct_le_u8(0, 1), 0xFF);
        assert_eq!(ct_le_u8(1, 0), 0x00);
        assert_eq!(ct_le_u8(16, 16), 0xFF);
        assert_eq!(ct_le_u8(17, 16), 0x00);
        assert_eq!(ct_in_range_1_to_16(0), 0x00);
        assert_eq!(ct_in_range_1_to_16(1), 0xFF);
        assert_eq!(ct_in_range_1_to_16(16), 0xFF);
        assert_eq!(ct_in_range_1_to_16(17), 0x00);
        assert_eq!(ct_in_range_1_to_16(255), 0x00);
    }
}
