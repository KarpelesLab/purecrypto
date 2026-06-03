//! Shared X.509 / key helpers for the CLI tools.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::die;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId, Ed25519PrivateKey};
use purecrypto::rng::{OsRng, RngCore};
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::x509::{
    AnyPublicKey, CertSigner, Certificate, DistinguishedName, Time, Validity, oid,
};

/// A loaded private key (the owner; borrow a [`CertSigner`] from it). One
/// instance per CLI invocation, so variant-size disparity is irrelevant.
#[allow(clippy::large_enum_variant)]
pub(crate) enum PrivateKey {
    Rsa(BoxedRsaPrivateKey),
    Ec(BoxedEcdsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
}

impl PrivateKey {
    /// Loads an RSA PKCS#1, EC SEC1, or Ed25519 PKCS#8 private-key PEM.
    pub(crate) fn from_pem(pem: &str) -> Option<Self> {
        if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(pem) {
            return Some(PrivateKey::Rsa(k));
        }
        if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(pem) {
            return Some(PrivateKey::Ec(k));
        }
        Ed25519PrivateKey::from_pkcs8_pem(pem)
            .ok()
            .map(PrivateKey::Ed25519)
    }

    /// Borrows a certificate/CSR signer.
    pub(crate) fn signer(&self) -> CertSigner<'_> {
        match self {
            PrivateKey::Rsa(k) => CertSigner::Rsa(k),
            PrivateKey::Ec(k) => CertSigner::Ecdsa(k),
            PrivateKey::Ed25519(k) => CertSigner::Ed25519(k),
        }
    }
}

/// Loads a private key from `path`, dying on any error.
pub(crate) fn load_key(path: &str) -> PrivateKey {
    crate::util::warn_if_world_readable_key(path);
    let raw = std::fs::read(path).unwrap_or_else(|e| die(format!("cannot read {path}: {e}")));
    let pem = core::str::from_utf8(&raw).unwrap_or_else(|_| die(format!("{path} is not PEM")));
    PrivateKey::from_pem(pem).unwrap_or_else(|| die(format!("cannot parse key in {path}")))
}

/// Parses an OpenSSL-style subject string such as `/CN=example.com/O=Acme`.
///
/// Each attribute value is screened for ASCII control characters (`< 0x20`)
/// and rejected if any are present. The CA records issued/revoked rows as
/// one JSON object per line in `issued.jsonl` / `revoked.jsonl`; a stray
/// `\n` in a CN would corrupt subsequent records, and `parse_revoked_jsonl`
/// can be tricked into reading the wrong field if `\\"` appears unescaped.
pub(crate) fn parse_subject(subj: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    for part in subj.split('/').filter(|s| !s.is_empty()) {
        let Some((k, v)) = part.split_once('=') else {
            die(format!("malformed subject component: {part}"));
        };
        if v.bytes().any(|b| b < 0x20) {
            die(format!(
                "subject attribute {} contains a control character",
                k.trim()
            ));
        }
        match k.trim().to_ascii_uppercase().as_str() {
            "CN" => dn.common_name = Some(v.into()),
            "O" => dn.organization = Some(v.into()),
            "OU" => dn.organizational_unit = Some(v.into()),
            "C" => dn.country = Some(v.into()),
            other => die(format!("unsupported subject attribute: {other}")),
        }
    }
    dn
}

/// Escapes `s` for safe embedding inside a JSON string literal (used by the
/// `issued.jsonl` / `revoked.jsonl` ledgers). Handles the six control-character
/// escapes called out in RFC 8259 §7 plus the generic `\u{XXXX}` form for the
/// remaining `0x00..0x1F` range; non-control bytes pass through verbatim
/// (we already rejected `\` paths in [`parse_subject`], but explicit `\\` and
/// `\"` escapes are emitted for defense in depth).
pub(crate) fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Renders a distinguished name like `CN=example.com, O=Acme`.
pub(crate) fn format_dn(dn: &DistinguishedName) -> String {
    let mut parts = Vec::new();
    if let Some(c) = &dn.country {
        parts.push(format!("C={c}"));
    }
    if let Some(o) = &dn.organization {
        parts.push(format!("O={o}"));
    }
    if let Some(ou) = &dn.organizational_unit {
        parts.push(format!("OU={ou}"));
    }
    if let Some(cn) = &dn.common_name {
        parts.push(format!("CN={cn}"));
    }
    parts.join(", ")
}

/// A human label for a public key's algorithm and size/curve.
pub(crate) fn describe_key(key: &AnyPublicKey) -> String {
    match key {
        AnyPublicKey::Rsa(k) => format!("RSA, {} bits", k.modulus().bit_len()),
        AnyPublicKey::Ecdsa(k) => format!(
            "ECDSA, {}",
            match k.curve() {
                CurveId::P256 => "P-256",
                CurveId::P384 => "P-384",
                CurveId::P521 => "P-521",
                CurveId::Secp256k1 => "secp256k1",
            }
        ),
        AnyPublicKey::Ed25519(_) => "Ed25519".to_string(),
        AnyPublicKey::Ed448(_) => "Ed448".to_string(),
        AnyPublicKey::MlDsa44(_) => "ML-DSA-44".to_string(),
        AnyPublicKey::MlDsa65(_) => "ML-DSA-65".to_string(),
        AnyPublicKey::MlDsa87(_) => "ML-DSA-87".to_string(),
        AnyPublicKey::SlhDsa(k) => format!("SLH-DSA ({:?})", k.parameter_set()),
    }
}

/// A validity window of `days` starting now.
pub(crate) fn validity_days(days: u64) -> Validity {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Validity::new(Time::from_unix(now), Time::from_unix(now + days * 86_400))
}

/// A random 63-bit serial number with the high bit clear (positive DER) and
/// the low bit set (non-zero). The 63 bits of entropy are below the CA/B
/// Forum's 64-bit recommendation but match the `u64` shape consumed by
/// [`Certificate::issue_general`] / [`Certificate::self_signed_general`].
/// For production CAs use the X.509 issuer APIs directly with a 16-byte
/// BoxedUint serial.
pub(crate) fn random_serial() -> u64 {
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    // Clear the top bit to keep the DER INTEGER positive (without a leading
    // 0x00 padding byte the high-bit-set case would parse negative), and set
    // the low bit so the value is non-zero.
    (u64::from_be_bytes(b) & 0x7fff_ffff_ffff_ffff) | 1
}

/// Extracts the `BIT STRING` *contents* of an `AnyPublicKey`'s SPKI — the
/// raw key-bits payload, without the outer `SubjectPublicKeyInfo` SEQUENCE
/// or the BIT STRING's unused-bits prefix byte. This is the input to method
/// 1 of RFC 5280 §4.2.1.2 for computing a subjectKeyIdentifier.
pub(crate) fn spki_bit_string_contents(key: &AnyPublicKey) -> Vec<u8> {
    let der = key.to_spki_der();
    // SPKI ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }.
    // Walk the outer SEQUENCE → AlgorithmIdentifier → BIT STRING.
    use purecrypto::der::Reader;
    let mut r = Reader::new(&der);
    let mut spki = r.read_sequence().expect("SPKI: outer SEQUENCE");
    spki.read_sequence().expect("SPKI: AlgorithmIdentifier");
    spki.read_bit_string().expect("SPKI: BIT STRING").to_vec()
}

/// Returns the issuer's subjectKeyIdentifier bytes (the keyIdentifier
/// OCTET STRING inside the SKI extension), or an empty vec if the
/// certificate has no SKI extension. Used by templates that emit an
/// authorityKeyIdentifier on the issued leaf.
pub(crate) fn issuer_ski_bytes(cert: &Certificate) -> Vec<u8> {
    let exts = cert.extensions().unwrap_or_default();
    for e in exts {
        if e.oid == oid::SUBJECT_KEY_IDENTIFIER {
            // Value is OCTET STRING { keyIdentifier }.
            use purecrypto::der::Reader;
            let mut r = Reader::new(&e.value);
            if let Ok(ki) = r.read_octet_string() {
                return ki.to_vec();
            }
        }
    }
    Vec::new()
}

/// Parses dNSName entries from `-addext "subjectAltName=DNS:a,DNS:b"` or a plain
/// comma list (`a,b`).
pub(crate) fn parse_sans(spec: &str) -> Vec<String> {
    let list = spec.strip_prefix("subjectAltName=").unwrap_or(spec);
    list.split(',')
        .map(|e| e.trim())
        .filter(|e| !e.is_empty())
        .map(|e| e.strip_prefix("DNS:").unwrap_or(e).to_string())
        .collect()
}
