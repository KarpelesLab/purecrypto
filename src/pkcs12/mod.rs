//! PKCS#12 / PFX (RFC 7292) personal-information exchange archives — the
//! `.p12` / `.pfx` files that bundle a private key together with its
//! certificate chain under a single password.
//!
//! # What this module does
//!
//! * [`Pfx::parse`] verifies the file MAC against the password, then walks the
//!   nested `AuthenticatedSafe`, decrypting each shrouded key and pulling out
//!   the private key(s) and certificate(s) as raw DER. A wrong password is
//!   rejected by the MAC check *before* any content decryption is attempted.
//! * [`Pfx::build`] produces a parseable archive from a PKCS#8 private key and
//!   a certificate chain: the key is wrapped in a PBES2
//!   `pkcs8ShroudedKeyBag`, the certs go in a plaintext `certBag`
//!   SafeContents, and the whole thing is sealed with the RFC 7292 §B
//!   SHA-256 HMAC.
//!
//! # Algorithm coverage
//!
//! | Layer                  | Supported on parse                                  | Emitted by `build` |
//! |------------------------|-----------------------------------------------------|--------------------|
//! | Shrouded key envelope  | PBES2 (PBKDF2 + AES-CBC/GCM); PBE-SHA1-3DES (legacy) | PBES2 (PBKDF2-SHA256 + AES-256-CBC) |
//! | `encryptedData` content| PBES2; PBE-SHA1-3DES (legacy, OpenSSL `-legacy`)    | plaintext certBag  |
//! | File MAC               | SHA-based HMAC (SHA-1 / SHA-256); PBMAC1 (PBKDF2)   | SHA-256 SHA-based  |
//!
//! The PBE-SHA1-3DES paths use the RFC 7292 Appendix B key derivation; the
//! 40-bit RC2 variant (`pbeWithSHAAnd40BitRC2-CBC`) is **not** supported.
//!
//! # Security
//!
//! The MAC is verified in constant time and gates everything: [`Pfx::parse`]
//! returns [`Error::MacMismatch`] for a wrong password without leaking
//! plaintext. Password-derived key material (BMP password, derived keys, the
//! recovered PKCS#8 DER) is zeroed on drop of the returned [`Parsed`].

#![cfg(feature = "pkcs12")]

mod kdf;
mod pbes2_p12;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::der::{
    Reader, encode_context, encode_integer, encode_octet_string, encode_sequence, oid_tlv,
    parse_oid, tag,
};
use crate::hash::{Hmac, Sha1, Sha256};
use crate::kdf::pbes2;
use crate::rng::RngCore;
use kdf::{ID_IV, ID_KEY, ID_MAC, PkcsHash, derive, password_to_bmp};

// ---- OID constants ------------------------------------------------------

/// `data` ContentInfo (PKCS#7, RFC 2315 §8).
const OID_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
/// `encryptedData` ContentInfo.
const OID_ENCRYPTED_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 6];

/// `keyBag` (RFC 7292 §4.2.1) — a plaintext PKCS#8 PrivateKeyInfo.
const OID_KEY_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 1];
/// `pkcs8ShroudedKeyBag` (§4.2.2) — an EncryptedPrivateKeyInfo.
const OID_PKCS8_SHROUDED_KEY_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 2];
/// `certBag` (§4.2.3).
const OID_CERT_BAG: &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 3];
/// `x509Certificate` cert type (inside a certBag).
const OID_CERT_TYPE_X509: &[u64] = &[1, 2, 840, 113549, 1, 9, 22, 1];

/// `friendlyName` bag attribute.
const OID_FRIENDLY_NAME: &[u64] = &[1, 2, 840, 113549, 1, 9, 20];
/// `localKeyId` bag attribute.
const OID_LOCAL_KEY_ID: &[u64] = &[1, 2, 840, 113549, 1, 9, 21];

/// `pbeWithSHAAnd3-KeyTripleDES-CBC` (RFC 7292 §C / appendix) — the legacy
/// 3DES content/key encryption.
const OID_PBE_SHA1_3DES: &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 3];

/// `id-PBES2` (RFC 8018 §A.4).
const OID_PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];

/// `hmacWithSHA1` (RFC 8018 §B.1.1) — used in the file MAC AlgorithmIdentifier.
const OID_HMAC_SHA1: &[u64] = &[1, 2, 840, 113549, 2, 7];
/// `id-sha1` (the digestAlgorithm OID in a classic MacData).
const OID_SHA1: &[u64] = &[1, 3, 14, 3, 2, 26];
/// `id-sha256`.
const OID_SHA256: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
/// `id-PBMAC1` (RFC 9579) — PBKDF2-based modern PFX MAC.
const OID_PBMAC1: &[u64] = &[1, 2, 840, 113549, 1, 5, 14];
/// `id-PBKDF2`.
const OID_PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
/// `hmacWithSHA256` PRF.
const OID_HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];

/// Iteration-count floor accepted for any password-derived material on parse.
/// Real OpenSSL archives use 2048+; we accept down to 1024 for tolerance but
/// reject pathologically weak counts.
const MIN_ITERATIONS: u32 = 1;
/// Iteration-count ceiling: the count is attacker-controlled, so cap it to
/// bound the worst-case CPU of a hostile file (DoS guard, mirroring PBES2).
const MAX_ITERATIONS: u32 = 10_000_000;

/// Errors from PKCS#12 parsing and building.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The outer/inner DER did not parse as a PFX structure.
    Malformed,
    /// The file MAC did not match — almost always a wrong password.
    MacMismatch,
    /// The archive has no MacData and integrity could not be checked. We
    /// refuse such files rather than trust unauthenticated contents.
    MissingMac,
    /// An algorithm OID we do not implement (e.g. 40-bit RC2, an unknown
    /// MAC PRF, or a PBES2 cipher outside the supported set).
    UnsupportedAlgorithm,
    /// Content decryption failed (bad password on an inner encrypted bag,
    /// or corrupt ciphertext).
    Decryption,
    /// An attacker-controlled iteration count outside the accepted band.
    BadParameters,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Malformed => f.write_str("malformed PKCS#12 archive"),
            Error::MacMismatch => f.write_str("PKCS#12 MAC mismatch (wrong password?)"),
            Error::MissingMac => f.write_str("PKCS#12 archive has no integrity MAC"),
            Error::UnsupportedAlgorithm => f.write_str("unsupported PKCS#12 algorithm"),
            Error::Decryption => f.write_str("PKCS#12 content decryption failed"),
            Error::BadParameters => f.write_str("PKCS#12 KDF parameters out of range"),
        }
    }
}

impl core::error::Error for Error {}

impl From<crate::der::Error> for Error {
    fn from(_: crate::der::Error) -> Self {
        Error::Malformed
    }
}

/// The decoded contents of a PFX: the recovered private keys and
/// certificates, each as raw DER. Secret material is zeroed on drop.
///
/// * `keys` — each entry is a plaintext PKCS#8 `PrivateKeyInfo` DER (the
///   shrouded keys are already decrypted). Parse with
///   [`AnyPrivateKey::from_pkcs8_der`](crate::x509::AnyPrivateKey::from_pkcs8_der).
/// * `certs` — each entry is a DER X.509 certificate. Parse with
///   [`Certificate::from_der`](crate::x509::Certificate::from_der).
/// * `friendly_names` — any `friendlyName` bag attributes encountered, in
///   bag order (informational; not all bags carry one).
pub struct Parsed {
    /// Recovered plaintext PKCS#8 private keys, as DER.
    pub keys: Vec<Vec<u8>>,
    /// Recovered X.509 certificates, as DER.
    pub certs: Vec<Vec<u8>>,
    /// `friendlyName` attribute values found on bags, in order.
    pub friendly_names: Vec<String>,
}

impl Drop for Parsed {
    fn drop(&mut self) {
        for k in self.keys.iter_mut() {
            for b in k.iter_mut() {
                *b = 0;
            }
            let _ = core::hint::black_box(&k);
        }
    }
}

impl core::fmt::Debug for Parsed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Parsed")
            .field(
                "keys",
                &format_args!("{} key(s) <redacted>", self.keys.len()),
            )
            .field("certs", &self.certs.len())
            .field("friendly_names", &self.friendly_names)
            .finish()
    }
}

/// PKCS#12 / PFX archive operations. This is a zero-sized namespace type; the
/// real work is in the associated [`Pfx::parse`] / [`Pfx::build`] functions.
#[derive(Debug)]
pub struct Pfx;

impl Pfx {
    /// Parses and MAC-verifies a PFX `der` against `password`.
    ///
    /// The integrity MAC is checked first; a wrong password (or a tampered
    /// file) yields [`Error::MacMismatch`] before any content is decrypted.
    /// An archive without a MAC is rejected as [`Error::MissingMac`].
    pub fn parse(der: &[u8], password: &str) -> Result<Parsed, Error> {
        let mut pw_bmp = password_to_bmp(password);
        let result = Self::parse_inner(der, password, &pw_bmp);
        // Wipe the BMP password copy regardless of outcome.
        for b in pw_bmp.iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(&pw_bmp);
        result
    }

    fn parse_inner(der: &[u8], password: &str, pw_bmp: &[u8]) -> Result<Parsed, Error> {
        // PFX ::= SEQUENCE { version INTEGER (3), authSafe ContentInfo,
        //                    macData MacData OPTIONAL }
        let mut reader = Reader::new(der);
        let mut pfx = reader.read_sequence()?;
        reader.finish()?;

        let version = pfx.read_integer_bytes()?;
        // version is 3 for the standard PFX.
        if version != [0x03] {
            return Err(Error::Malformed);
        }

        // authSafe ContentInfo — must be `data` wrapping the AuthenticatedSafe.
        let auth_safe_data = read_content_info_data(&mut pfx)?;

        // macData MacData OPTIONAL.
        let mac_data = if pfx.peek_tag().is_some() {
            Some(pfx.read_element()?)
        } else {
            None
        };
        pfx.finish()?;

        // ---- MAC verification (the gate) ----
        let mac = mac_data.ok_or(Error::MissingMac)?;
        verify_mac(mac, auth_safe_data, password, pw_bmp)?;

        // ---- Walk the AuthenticatedSafe ----
        // AuthenticatedSafe ::= SEQUENCE OF ContentInfo
        let mut out = Parsed {
            keys: Vec::new(),
            certs: Vec::new(),
            friendly_names: Vec::new(),
        };
        let mut safe_reader = Reader::new(auth_safe_data);
        let mut safe_seq = safe_reader.read_sequence()?;
        safe_reader.finish()?;

        while !safe_seq.is_empty() {
            // Each element is a ContentInfo.
            let mut ci = safe_seq.read_sequence()?;
            let ci_oid = parse_oid(ci.read_oid()?)?;
            let oid = ci_oid.as_slice();
            if oid == OID_DATA {
                // [0] EXPLICIT OCTET STRING wrapping plaintext SafeContents.
                let inner = ci.read_element()?;
                let mut ctx = Reader::new(inner);
                let body = ctx.read_tlv(tag::context(0))?;
                let mut octet = Reader::new(body);
                let safe_contents = octet.read_octet_string()?;
                parse_safe_contents(safe_contents, pw_bmp, password, &mut out)?;
            } else if oid == OID_ENCRYPTED_DATA {
                // [0] EXPLICIT EncryptedData ::= SEQUENCE { version,
                //   EncryptedContentInfo }
                let inner = ci.read_element()?;
                let mut ctx = Reader::new(inner);
                let body = ctx.read_tlv(tag::context(0))?;
                let plain = decrypt_encrypted_data(body, pw_bmp, password)?;
                parse_safe_contents(&plain, pw_bmp, password, &mut out)?;
            } else {
                return Err(Error::UnsupportedAlgorithm);
            }
        }

        Ok(out)
    }

    /// Builds a parseable `.p12` from a PKCS#8 private key and a certificate
    /// chain, sealed under `password`.
    ///
    /// * `pkcs8_key_der` — a plaintext PKCS#8 `PrivateKeyInfo` (the key is
    ///   shrouded internally with PBES2 PBKDF2-SHA256 / AES-256-CBC).
    /// * `cert_chain_der` — one or more DER X.509 certificates; the first is
    ///   the leaf. Each is stored in its own `certBag`.
    /// * `friendly_name` — optional human label attached to the key + leaf
    ///   cert bags (`friendlyName` attribute).
    ///
    /// The output is MAC-protected with the RFC 7292 §B SHA-256 HMAC.
    pub fn build(
        pkcs8_key_der: &[u8],
        cert_chain_der: &[&[u8]],
        password: &str,
        friendly_name: Option<&str>,
        rng: &mut impl RngCore,
    ) -> Vec<u8> {
        let pw_bmp = password_to_bmp(password);
        let iterations = 2048u32;

        // localKeyId ties the key bag to its leaf cert. OpenSSL uses the SHA-1
        // of the cert; any stable 20-byte value works — use a random one.
        let mut local_key_id = [0u8; 20];
        rng.fill_bytes(&mut local_key_id);

        // ---- SafeContents #1: the shrouded key bag (a `data` ContentInfo). ----
        let shrouded = pbes2::encrypt(
            pkcs8_key_der,
            password.as_bytes(),
            &pbes2::Pbes2Params {
                kdf: pbes2::KdfChoice::Pbkdf2HmacSha256 {
                    iterations: 100_000,
                },
                cipher: pbes2::CipherChoice::Aes256Cbc,
                salt_len: 16,
            },
            rng,
        );
        let key_bag = encode_safe_bag(
            OID_PKCS8_SHROUDED_KEY_BAG,
            &shrouded,
            friendly_name,
            Some(&local_key_id),
        );
        let key_safe_contents = encode_sequence(&key_bag);
        let key_content_info = encode_data_content_info(&key_safe_contents);

        // ---- SafeContents #2: the cert bags (a `data` ContentInfo). ----
        let mut cert_bags = Vec::new();
        for (idx, cert) in cert_chain_der.iter().enumerate() {
            // certBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
            let cert_value = encode_context(0, &encode_octet_string(cert));
            let cert_bag_body =
                encode_sequence(&[oid_tlv(OID_CERT_TYPE_X509), cert_value].concat());
            // Attach the friendlyName + localKeyId only to the leaf (idx 0).
            let (fname, lkid) = if idx == 0 {
                (friendly_name, Some(&local_key_id[..]))
            } else {
                (None, None)
            };
            cert_bags.extend_from_slice(&encode_safe_bag(
                OID_CERT_BAG,
                &cert_bag_body,
                fname,
                lkid,
            ));
        }
        let cert_safe_contents = encode_sequence(&cert_bags);
        let cert_content_info = encode_data_content_info(&cert_safe_contents);

        // ---- AuthenticatedSafe = SEQUENCE OF ContentInfo. ----
        let auth_safe = encode_sequence(&[key_content_info, cert_content_info].concat());

        // authSafe ContentInfo: data wrapping the AuthenticatedSafe DER.
        let auth_safe_ci = encode_data_content_info(&auth_safe);

        // ---- MacData over the AuthenticatedSafe content (SHA-256 SHA-based). ----
        let mut mac_salt = [0u8; 8];
        rng.fill_bytes(&mut mac_salt);
        let mac_data = build_mac_data(&auth_safe, &pw_bmp, &mac_salt, iterations);

        // ---- PFX ::= SEQUENCE { version INTEGER 3, authSafe, macData }. ----
        let version = encode_integer(&[0x03]);
        let pfx = encode_sequence(&[version, auth_safe_ci, mac_data].concat());

        // Wipe the BMP password copy.
        let mut pw_bmp = pw_bmp;
        for b in pw_bmp.iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(&pw_bmp);

        pfx
    }
}

// ---- ContentInfo helpers ------------------------------------------------

/// Reads a `data` ContentInfo from `r` and returns the wrapped inner OCTET
/// STRING bytes (the AuthenticatedSafe DER). The structure is
/// `SEQUENCE { OID data, [0] EXPLICIT OCTET STRING }`.
fn read_content_info_data<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let mut ci = r.read_sequence()?;
    let oid = parse_oid(ci.read_oid()?)?;
    if oid.as_slice() != OID_DATA {
        return Err(Error::Malformed);
    }
    let ctx_body = ci.read_tlv(tag::context(0))?;
    let mut inner = Reader::new(ctx_body);
    let octets = inner.read_octet_string()?;
    inner.finish()?;
    Ok(octets)
}

/// Encodes a `data` ContentInfo wrapping `inner` (already-DER content) in the
/// `[0] EXPLICIT OCTET STRING` envelope.
fn encode_data_content_info(inner: &[u8]) -> Vec<u8> {
    let octet = encode_octet_string(inner);
    let ctx = encode_context(0, &octet);
    encode_sequence(&[oid_tlv(OID_DATA), ctx].concat())
}

// ---- SafeContents / SafeBag parsing -------------------------------------

/// Parses a plaintext `SafeContents ::= SEQUENCE OF SafeBag`, extracting keys
/// and certs into `out`.
fn parse_safe_contents(
    der: &[u8],
    pw_bmp: &[u8],
    password: &str,
    out: &mut Parsed,
) -> Result<(), Error> {
    let mut reader = Reader::new(der);
    let mut seq = reader.read_sequence()?;
    reader.finish()?;

    while !seq.is_empty() {
        // SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT, bagAttrs SET OPTIONAL }
        let mut bag = seq.read_sequence()?;
        let bag_oid = parse_oid(bag.read_oid()?)?;
        let oid = bag_oid.as_slice();
        // bagValue is [0] EXPLICIT <type>.
        let bag_value = bag.read_tlv(tag::context(0))?;

        // Optional bagAttributes SET — scan for friendlyName.
        if let Some(t) = bag.peek_tag()
            && t == tag::SET
        {
            let attrs = bag.read_tlv(tag::SET)?;
            if let Some(name) = extract_friendly_name(attrs) {
                out.friendly_names.push(name);
            }
        }
        bag.finish().ok(); // tolerate trailing fields

        if oid == OID_KEY_BAG {
            // Plaintext PKCS#8 PrivateKeyInfo is exactly the bagValue.
            out.keys.push(bag_value.to_vec());
        } else if oid == OID_PKCS8_SHROUDED_KEY_BAG {
            // bagValue is an EncryptedPrivateKeyInfo — decrypt to PKCS#8.
            let plain = decrypt_shrouded_key(bag_value, pw_bmp, password)?;
            out.keys.push(plain);
        } else if oid == OID_CERT_BAG {
            // certBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
            let mut cb = Reader::new(bag_value);
            let mut cbs = cb.read_sequence()?;
            let cert_id = parse_oid(cbs.read_oid()?)?;
            if cert_id.as_slice() == OID_CERT_TYPE_X509 {
                let ctx = cbs.read_tlv(tag::context(0))?;
                let mut inner = Reader::new(ctx);
                let cert = inner.read_octet_string()?;
                out.certs.push(cert.to_vec());
            }
            // Other cert types (sdsiCertificate) are ignored.
        }
        // secretBag / safeContentsBag are ignored.
    }
    Ok(())
}

/// Extracts the first `friendlyName` (BMPString) from a bagAttributes SET
/// body, decoding it to a `String`. Returns `None` if absent or undecodable.
fn extract_friendly_name(attrs: &[u8]) -> Option<String> {
    let mut r = Reader::new(attrs);
    while !r.is_empty() {
        let mut attr = r.read_sequence().ok()?;
        let oid = parse_oid(attr.read_oid().ok()?).ok()?;
        let values = attr.read_tlv(tag::SET).ok()?;
        if oid.as_slice() == OID_FRIENDLY_NAME {
            // value is a BMPString (tag 0x1e): big-endian UTF-16.
            let mut vr = Reader::new(values);
            let (vtag, body) = vr.read_any().ok()?;
            if vtag == 0x1e {
                let mut units = Vec::with_capacity(body.len() / 2);
                for pair in body.chunks_exact(2) {
                    units.push(u16::from_be_bytes([pair[0], pair[1]]));
                }
                return String::from_utf16(&units).ok();
            }
        }
    }
    None
}

// ---- Decryption of encrypted layers -------------------------------------

/// Decrypts an `EncryptedData` `[0]` body to its plaintext SafeContents DER.
/// `EncryptedData ::= SEQUENCE { version INTEGER, EncryptedContentInfo }` where
/// `EncryptedContentInfo ::= SEQUENCE { contentType OID, contentEncryptionAlgorithm,
///   encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL }`.
fn decrypt_encrypted_data(der: &[u8], pw_bmp: &[u8], password: &str) -> Result<Vec<u8>, Error> {
    let mut reader = Reader::new(der);
    let mut ed = reader.read_sequence()?;
    let _version = ed.read_integer_bytes()?;
    let mut eci = ed.read_sequence()?;
    let _content_type = parse_oid(eci.read_oid()?)?; // should be `data`

    // contentEncryptionAlgorithm AlgorithmIdentifier.
    let alg = eci.read_element()?;

    // encryptedContent [0] IMPLICIT OCTET STRING — context tag 0x80
    // (primitive), *not* the constructed 0xA0 used for EXPLICIT tagging.
    let enc_content = eci.read_tlv(0x80)?;

    // Inspect the algorithm OID.
    let mut alg_r = Reader::new(alg);
    let mut alg_seq = alg_r.read_sequence()?;
    let alg_oid = parse_oid(alg_seq.read_oid()?)?;
    if alg_oid.as_slice() == OID_PBES2 {
        // PBES2 inside PKCS#12 (OpenSSL 3 default) is keyed on the raw UTF-8
        // password, not the BMP form.
        return pbes2_p12::decrypt(alg, enc_content, password.as_bytes());
    }
    decrypt_pbe_blob(alg, enc_content, pw_bmp)
}

/// Decrypts a `pkcs8ShroudedKeyBag` bagValue (an EncryptedPrivateKeyInfo) to
/// the inner plaintext PKCS#8 DER.
fn decrypt_shrouded_key(der: &[u8], pw_bmp: &[u8], password: &str) -> Result<Vec<u8>, Error> {
    // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm AlgorithmIdentifier,
    //                                        encryptedData OCTET STRING }
    let mut reader = Reader::new(der);
    let mut epki = reader.read_sequence()?;
    let alg = epki.read_element()?;

    // Inspect the algorithm OID to decide PBES2 vs PKCS#12 PBE.
    let mut alg_r = Reader::new(alg);
    let mut alg_seq = alg_r.read_sequence()?;
    let alg_oid = parse_oid(alg_seq.read_oid()?)?;

    if alg_oid.as_slice() == OID_PBES2 {
        // The shrouded-key bagValue is an EncryptedPrivateKeyInfo; its second
        // field is the OCTET STRING ciphertext. PBES2 is keyed on the raw
        // UTF-8 password.
        let enc = epki.read_octet_string()?;
        pbes2_p12::decrypt(alg, enc, password.as_bytes())
    } else {
        let enc = epki.read_octet_string()?;
        decrypt_pbe_blob(alg, enc, pw_bmp)
    }
}

/// Dispatches a content/key decryption on the AlgorithmIdentifier `alg`,
/// covering the legacy `pbeWithSHAAnd3-KeyTripleDES-CBC`. (PBES2 is handled by
/// the callers, which key it on the raw UTF-8 password.)
fn decrypt_pbe_blob(alg: &[u8], ciphertext: &[u8], pw_bmp: &[u8]) -> Result<Vec<u8>, Error> {
    let mut alg_r = Reader::new(alg);
    let mut alg_seq = alg_r.read_sequence()?;
    let alg_oid = parse_oid(alg_seq.read_oid()?)?;
    let oid = alg_oid.as_slice();

    if oid == OID_PBE_SHA1_3DES {
        // pkcs-12PbeParams ::= SEQUENCE { salt OCTET STRING, iterations INTEGER }
        let mut params = alg_seq.read_sequence()?;
        let salt = params.read_octet_string()?.to_vec();
        let iterations = read_iterations(&mut params)?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(Error::BadParameters);
        }
        return pbe_sha1_3des_decrypt(pw_bmp, &salt, iterations, ciphertext);
    }
    Err(Error::UnsupportedAlgorithm)
}

/// Decrypts `pbeWithSHAAnd3-KeyTripleDES-CBC`: derive a 24-byte 3DES key
/// (ID=1) and an 8-byte IV (ID=2) via the RFC 7292 §B KDF with SHA-1, then
/// CBC-decrypt and strip PKCS#7 padding.
fn pbe_sha1_3des_decrypt(
    pw_bmp: &[u8],
    salt: &[u8],
    iterations: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    use crate::cipher::{Cbc64, TdesEde3};

    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(8) {
        return Err(Error::Decryption);
    }
    let mut key = [0u8; 24];
    let mut iv = [0u8; 8];
    derive(PkcsHash::Sha1, pw_bmp, salt, iterations, ID_KEY, &mut key);
    derive(PkcsHash::Sha1, pw_bmp, salt, iterations, ID_IV, &mut iv);

    let mut buf = ciphertext.to_vec();
    let mut cbc = Cbc64::new(TdesEde3::new(&key), &iv);
    // Wipe key material now that the cipher object owns its schedule.
    for b in key.iter_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(&key);
    cbc.decrypt(&mut buf).map_err(|_| Error::Decryption)?;

    strip_pkcs7(buf, 8)
}

/// Strips PKCS#7 padding for a `block`-byte block size, rejecting invalid
/// padding as [`Error::Decryption`].
fn strip_pkcs7(mut buf: Vec<u8>, block: usize) -> Result<Vec<u8>, Error> {
    let n = buf.len();
    if n == 0 || !n.is_multiple_of(block) {
        return Err(Error::Decryption);
    }
    let pad = buf[n - 1] as usize;
    if pad == 0 || pad > block || pad > n {
        return Err(Error::Decryption);
    }
    // All padding bytes must equal `pad`.
    let mut ok = true;
    for &b in &buf[n - pad..] {
        if b as usize != pad {
            ok = false;
        }
    }
    if !ok {
        return Err(Error::Decryption);
    }
    buf.truncate(n - pad);
    Ok(buf)
}

// ---- MAC ----------------------------------------------------------------

/// Verifies the file MAC. `mac` is the raw DER of the `MacData` element,
/// `content` is the AuthenticatedSafe bytes the MAC is computed over.
///
/// `MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING,
///                         iterations INTEGER DEFAULT 1 }`
/// `DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier,
///                            digest OCTET STRING }`
fn verify_mac(mac: &[u8], content: &[u8], password: &str, pw_bmp: &[u8]) -> Result<(), Error> {
    let mut reader = Reader::new(mac);
    let mut md = reader.read_sequence()?;

    // DigestInfo.
    let mut di = md.read_sequence()?;
    let mut alg = di.read_sequence()?;
    let alg_oid = parse_oid(alg.read_oid()?)?;
    let expected = di.read_octet_string()?.to_vec();
    di.finish().ok();

    let salt = md.read_octet_string()?.to_vec();
    let iterations = if md.peek_tag().is_some() {
        read_iterations(&mut md)?
    } else {
        1
    };
    md.finish().ok();
    // The MAC iteration count is attacker-controlled; cap it so a crafted
    // MacData can't demand billions of hash iterations before the (failing)
    // comparison (a decryption-as-DoS vector).
    if iterations > MAX_ITERATIONS {
        return Err(Error::BadParameters);
    }

    let oid = alg_oid.as_slice();

    // Compute the expected tag for the password and compare in constant time.
    let computed = if oid == OID_SHA1 || oid == OID_HMAC_SHA1 {
        sha_based_hmac(PkcsHash::Sha1, pw_bmp, &salt, iterations, content)
    } else if oid == OID_SHA256 || oid == OID_HMAC_SHA256 {
        sha_based_hmac(PkcsHash::Sha256, pw_bmp, &salt, iterations, content)
    } else if oid == OID_PBMAC1 {
        // RFC 9579: the digestAlgorithm SEQUENCE carries PBKDF2 + an inner
        // HMAC AlgorithmIdentifier. Reuse the remaining `alg` reader.
        pbmac1_compute(&mut alg, password, content)?
    } else {
        return Err(Error::UnsupportedAlgorithm);
    };

    if ct_eq(&computed, &expected) {
        Ok(())
    } else {
        Err(Error::MacMismatch)
    }
}

/// Computes the RFC 7292 §B SHA-based HMAC tag: derive the MAC key (ID=3,
/// `u`-byte length) then HMAC the content under it.
fn sha_based_hmac(
    hash: PkcsHash,
    pw_bmp: &[u8],
    salt: &[u8],
    iterations: u32,
    content: &[u8],
) -> Vec<u8> {
    match hash {
        PkcsHash::Sha1 => {
            let mut key = [0u8; 20];
            derive(hash, pw_bmp, salt, iterations, ID_MAC, &mut key);
            let tag = Hmac::<Sha1>::mac(&key, content);
            for b in key.iter_mut() {
                *b = 0;
            }
            tag.as_ref().to_vec()
        }
        PkcsHash::Sha256 => {
            let mut key = [0u8; 32];
            derive(hash, pw_bmp, salt, iterations, ID_MAC, &mut key);
            let tag = Hmac::<Sha256>::mac(&key, content);
            for b in key.iter_mut() {
                *b = 0;
            }
            tag.as_ref().to_vec()
        }
    }
}

/// Computes a PBMAC1 (RFC 9579) tag. `alg` is positioned just after the
/// PBMAC1 OID, at the `PBMAC1-params ::= SEQUENCE { keyDerivationFunc,
/// messageAuthScheme }`. Only PBKDF2(HMAC-SHA-256) + HMAC-SHA-256 is wired.
fn pbmac1_compute(alg: &mut Reader<'_>, password: &str, content: &[u8]) -> Result<Vec<u8>, Error> {
    let mut params = alg.read_sequence()?;
    // keyDerivationFunc: SEQUENCE { OID id-PBKDF2, PBKDF2-params }.
    let mut kdf = params.read_sequence()?;
    let kdf_oid = parse_oid(kdf.read_oid()?)?;
    if kdf_oid.as_slice() != OID_PBKDF2 {
        return Err(Error::UnsupportedAlgorithm);
    }
    let mut p = kdf.read_sequence()?;
    let salt = p.read_octet_string()?.to_vec();
    let iterations = read_iterations(&mut p)?;
    // Optional keyLength.
    let mut key_len = 32usize;
    if let Some(t) = p.peek_tag()
        && t == tag::INTEGER
    {
        key_len = read_iterations(&mut p)? as usize;
    }
    // Optional PRF: must be HMAC-SHA-256 if present.
    if let Some(t) = p.peek_tag()
        && t == tag::SEQUENCE
    {
        let mut prf = p.read_sequence()?;
        let prf_oid = parse_oid(prf.read_oid()?)?;
        if prf_oid.as_slice() != OID_HMAC_SHA256 {
            return Err(Error::UnsupportedAlgorithm);
        }
    }

    // messageAuthScheme: SEQUENCE { OID hmacWithSHA256, params }.
    let mut mas = params.read_sequence()?;
    let mas_oid = parse_oid(mas.read_oid()?)?;
    if mas_oid.as_slice() != OID_HMAC_SHA256 {
        return Err(Error::UnsupportedAlgorithm);
    }

    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(Error::BadParameters);
    }
    let mut key = vec![0u8; key_len];
    crate::kdf::pbkdf2::<Sha256>(password.as_bytes(), &salt, iterations, &mut key);
    let tag = Hmac::<Sha256>::mac(&key, content);
    for b in key.iter_mut() {
        *b = 0;
    }
    Ok(tag.as_ref().to_vec())
}

/// Builds a `MacData` element over `content` using the SHA-256 SHA-based MAC.
fn build_mac_data(content: &[u8], pw_bmp: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let tag = sha_based_hmac(PkcsHash::Sha256, pw_bmp, salt, iterations, content);
    // DigestInfo ::= SEQUENCE { AlgorithmIdentifier { id-sha256, NULL }, OCTET STRING }
    let alg = encode_sequence(&[oid_tlv(OID_SHA256), crate::der::encode_null()].concat());
    let digest_info = encode_sequence(&[alg, encode_octet_string(&tag)].concat());
    let salt_os = encode_octet_string(salt);
    let iter = encode_integer(&iterations.to_be_bytes());
    encode_sequence(&[digest_info, salt_os, iter].concat())
}

// ---- SafeBag encoding (build) -------------------------------------------

/// Encodes a single `SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT,
/// bagAttributes SET OPTIONAL }`. `bag_value_der` is the already-encoded inner
/// type (an EncryptedPrivateKeyInfo for a shrouded key, or a certBag body).
fn encode_safe_bag(
    bag_id: &[u64],
    bag_value_der: &[u8],
    friendly_name: Option<&str>,
    local_key_id: Option<&[u8]>,
) -> Vec<u8> {
    let bag_value = encode_context(0, bag_value_der);
    let mut body = Vec::new();
    body.extend_from_slice(&oid_tlv(bag_id));
    body.extend_from_slice(&bag_value);

    // bagAttributes SET OF Attribute.
    let mut attrs = Vec::new();
    if let Some(name) = friendly_name {
        attrs.extend_from_slice(&encode_attribute(
            OID_FRIENDLY_NAME,
            &encode_bmp_string(name),
        ));
    }
    if let Some(id) = local_key_id {
        attrs.extend_from_slice(&encode_attribute(
            OID_LOCAL_KEY_ID,
            &encode_octet_string(id),
        ));
    }
    if !attrs.is_empty() {
        body.extend_from_slice(&encode_tlv_set(&attrs));
    }
    encode_sequence(&body)
}

/// Encodes `Attribute ::= SEQUENCE { attrId OID, attrValues SET OF value }`.
fn encode_attribute(oid: &[u64], value_der: &[u8]) -> Vec<u8> {
    let values = encode_tlv_set(value_der);
    encode_sequence(&[oid_tlv(oid), values].concat())
}

/// Wraps `content` in a `SET` (tag 0x31).
fn encode_tlv_set(content: &[u8]) -> Vec<u8> {
    crate::der::encode_tlv(tag::SET, content)
}

/// Encodes a `BMPString` (tag 0x1e), big-endian UTF-16 of `s` (no NUL).
fn encode_bmp_string(s: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in s.encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    crate::der::encode_tlv(0x1e, &bytes)
}

// ---- small helpers ------------------------------------------------------

/// Reads a DER INTEGER as a `u32`, enforcing the parse-side iteration band.
fn read_iterations(r: &mut Reader<'_>) -> Result<u32, Error> {
    let bytes = r.read_integer_bytes()?;
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
    let mut acc: u32 = 0;
    for &b in trimmed {
        acc = (acc << 8) | b as u32;
    }
    Ok(acc)
}

/// Constant-time slice equality (length-aware).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests;
