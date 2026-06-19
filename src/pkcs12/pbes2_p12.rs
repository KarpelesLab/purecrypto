//! A PKCS#12-tolerant PBES2 (RFC 8018 §6.2) decryptor.
//!
//! The crate's main [`crate::kdf::pbes2`] enforces a 10 000-iteration PBKDF2
//! floor, which is correct for fresh PKCS#8 envelopes but rejects real-world
//! `.p12` files — OpenSSL's default content encryption uses only 2048
//! iterations. PKCS#12 archives are integrity-protected by the file MAC
//! (verified *before* any of this runs), so the per-bag PBES2 floor would be
//! redundant security at the cost of interop. This module therefore accepts
//! the realistic legacy band (still capped to bound attacker-controlled CPU)
//! and covers the AES-{128,192,256}-CBC and -GCM ciphers OpenSSL emits.

use super::Error;
use alloc::vec::Vec;

use crate::cipher::{Aes128, Aes128Gcm, Aes192, Aes256, Aes256Gcm, Cbc};
use crate::der::{Reader, parse_oid, tag};
use crate::hash::{Sha1, Sha256, Sha512};
use crate::kdf::pbkdf2;

const OID_PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
const OID_PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
const OID_HMAC_SHA1: &[u64] = &[1, 2, 840, 113549, 2, 7];
const OID_HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
const OID_HMAC_SHA512: &[u64] = &[1, 2, 840, 113549, 2, 11];

const OID_AES128_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 2];
const OID_AES192_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 22];
const OID_AES256_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
const OID_AES128_GCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 6];
const OID_AES256_GCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 46];

/// Iteration band accepted for PKCS#12 PBES2 content. The file MAC is the
/// real integrity gate; 1024 is below OpenSSL's 2048 default but rejects
/// pathological values, and the ceiling bounds a hostile file's CPU cost.
const MIN_ITER: u32 = 1024;
const MAX_ITER: u32 = 10_000_000;

enum Prf {
    Sha1,
    Sha256,
    Sha512,
}

enum CipherKind {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes256Gcm,
}

impl CipherKind {
    fn key_len(&self) -> usize {
        match self {
            CipherKind::Aes128Cbc | CipherKind::Aes128Gcm => 16,
            CipherKind::Aes192Cbc => 24,
            CipherKind::Aes256Cbc | CipherKind::Aes256Gcm => 32,
        }
    }
}

/// Decrypts a PBES2 blob given its `algorithm` AlgorithmIdentifier DER (the
/// full `SEQUENCE { OID id-PBES2, PBES2-params }`), the ciphertext, and the
/// raw (UTF-8) password.
pub(super) fn decrypt(alg: &[u8], ciphertext: &[u8], password: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(alg);
    let mut seq = r.read_sequence()?;
    let oid = parse_oid(seq.read_oid()?)?;
    if oid.as_slice() != OID_PBES2 {
        return Err(Error::UnsupportedAlgorithm);
    }
    // PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }.
    let mut params = seq.read_sequence()?;

    // --- keyDerivationFunc: PBKDF2 ---
    let mut kdf = params.read_sequence()?;
    let kdf_oid = parse_oid(kdf.read_oid()?)?;
    if kdf_oid.as_slice() != OID_PBKDF2 {
        return Err(Error::UnsupportedAlgorithm);
    }
    let mut p = kdf.read_sequence()?;
    let salt = p.read_octet_string()?.to_vec();
    let iterations = read_u32(p.read_integer_bytes()?)?;
    if !(MIN_ITER..=MAX_ITER).contains(&iterations) {
        return Err(Error::BadParameters);
    }
    // Optional keyLength INTEGER.
    let mut explicit_key_len: Option<usize> = None;
    if let Some(t) = p.peek_tag()
        && t == tag::INTEGER
    {
        explicit_key_len = Some(read_u32(p.read_integer_bytes()?)? as usize);
    }
    // Optional PRF AlgorithmIdentifier (DEFAULT hmacWithSHA1).
    let prf = if let Some(t) = p.peek_tag()
        && t == tag::SEQUENCE
    {
        let mut prf_seq = p.read_sequence()?;
        let prf_oid = parse_oid(prf_seq.read_oid()?)?;
        match prf_oid.as_slice() {
            x if x == OID_HMAC_SHA1 => Prf::Sha1,
            x if x == OID_HMAC_SHA256 => Prf::Sha256,
            x if x == OID_HMAC_SHA512 => Prf::Sha512,
            _ => return Err(Error::UnsupportedAlgorithm),
        }
    } else {
        Prf::Sha1
    };

    // --- encryptionScheme ---
    let mut enc = params.read_sequence()?;
    let enc_oid = parse_oid(enc.read_oid()?)?;
    let cipher = match enc_oid.as_slice() {
        x if x == OID_AES128_CBC => CipherKind::Aes128Cbc,
        x if x == OID_AES192_CBC => CipherKind::Aes192Cbc,
        x if x == OID_AES256_CBC => CipherKind::Aes256Cbc,
        x if x == OID_AES128_GCM => CipherKind::Aes128Gcm,
        x if x == OID_AES256_GCM => CipherKind::Aes256Gcm,
        _ => return Err(Error::UnsupportedAlgorithm),
    };

    // IV / nonce: for CBC it's an OCTET STRING; for GCM it's a
    // GCMParameters SEQUENCE { nonce OCTET STRING, icvlen INTEGER DEFAULT 12 }.
    let is_gcm = matches!(cipher, CipherKind::Aes128Gcm | CipherKind::Aes256Gcm);
    let iv = if is_gcm {
        let mut gp = enc.read_sequence()?;
        gp.read_octet_string()?.to_vec()
    } else {
        enc.read_octet_string()?.to_vec()
    };

    let key_len = explicit_key_len.unwrap_or_else(|| cipher.key_len());
    if key_len != cipher.key_len() {
        return Err(Error::UnsupportedAlgorithm);
    }

    // Derive the key.
    let mut key = alloc::vec![0u8; key_len];
    match prf {
        Prf::Sha1 => pbkdf2::<Sha1>(password, &salt, iterations, &mut key),
        Prf::Sha256 => pbkdf2::<Sha256>(password, &salt, iterations, &mut key),
        Prf::Sha512 => pbkdf2::<Sha512>(password, &salt, iterations, &mut key),
    }

    let result = decrypt_cipher(cipher, &key, &iv, ciphertext);
    for b in key.iter_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(&key);
    result
}

fn decrypt_cipher(
    cipher: CipherKind,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    match cipher {
        CipherKind::Aes128Cbc | CipherKind::Aes192Cbc | CipherKind::Aes256Cbc => {
            if iv.len() != 16 {
                return Err(Error::Malformed);
            }
            if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
                return Err(Error::Decryption);
            }
            let mut iv_arr = [0u8; 16];
            iv_arr.copy_from_slice(iv);
            let mut buf = ciphertext.to_vec();
            match cipher {
                CipherKind::Aes128Cbc => {
                    let mut k = [0u8; 16];
                    k.copy_from_slice(key);
                    Cbc::new(Aes128::new(&k), &iv_arr)
                        .decrypt(&mut buf)
                        .map_err(|_| Error::Decryption)?;
                }
                CipherKind::Aes192Cbc => {
                    let mut k = [0u8; 24];
                    k.copy_from_slice(key);
                    Cbc::new(Aes192::new(&k), &iv_arr)
                        .decrypt(&mut buf)
                        .map_err(|_| Error::Decryption)?;
                }
                CipherKind::Aes256Cbc => {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(key);
                    Cbc::new(Aes256::new(&k), &iv_arr)
                        .decrypt(&mut buf)
                        .map_err(|_| Error::Decryption)?;
                }
                _ => unreachable!(),
            }
            super::strip_pkcs7(buf, 16)
        }
        CipherKind::Aes128Gcm | CipherKind::Aes256Gcm => {
            if iv.len() != 12 {
                return Err(Error::Malformed);
            }
            if ciphertext.len() < 16 {
                return Err(Error::Decryption);
            }
            let split = ciphertext.len() - 16;
            let (ct, tag_bytes) = ciphertext.split_at(split);
            let mut buf = ct.to_vec();
            let mut tag = [0u8; 16];
            tag.copy_from_slice(tag_bytes);
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(iv);
            match cipher {
                CipherKind::Aes128Gcm => {
                    let mut k = [0u8; 16];
                    k.copy_from_slice(key);
                    Aes128Gcm::new(Aes128::new(&k))
                        .decrypt(&nonce, &[], &mut buf, &tag)
                        .map_err(|_| Error::Decryption)?;
                }
                CipherKind::Aes256Gcm => {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(key);
                    Aes256Gcm::new(Aes256::new(&k))
                        .decrypt(&nonce, &[], &mut buf, &tag)
                        .map_err(|_| Error::Decryption)?;
                }
                _ => unreachable!(),
            }
            Ok(buf)
        }
    }
}

/// Reads a non-negative DER INTEGER body as `u32`.
fn read_u32(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.is_empty() || bytes[0] & 0x80 != 0 {
        return Err(Error::Malformed);
    }
    let trimmed = if bytes.len() > 1 && bytes[0] == 0 {
        &bytes[1..]
    } else {
        bytes
    };
    if trimmed.len() > 4 {
        return Err(Error::BadParameters);
    }
    let mut acc = 0u32;
    for &b in trimmed {
        acc = (acc << 8) | b as u32;
    }
    Ok(acc)
}
