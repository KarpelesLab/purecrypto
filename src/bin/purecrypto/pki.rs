//! Shared X.509 / key helpers for the CLI tools.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::die;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::rng::{OsRng, RngCore};
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::x509::{AnyPublicKey, CertSigner, DistinguishedName, Time, Validity};

/// A loaded private key (the owner; borrow a [`CertSigner`] from it).
pub(crate) enum PrivateKey {
    Rsa(BoxedRsaPrivateKey),
    Ec(BoxedEcdsaPrivateKey),
}

impl PrivateKey {
    /// Loads an RSA PKCS#1 or EC SEC1 private-key PEM.
    pub(crate) fn from_pem(pem: &str) -> Option<Self> {
        if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(pem) {
            return Some(PrivateKey::Rsa(k));
        }
        BoxedEcdsaPrivateKey::from_sec1_pem(pem)
            .ok()
            .map(PrivateKey::Ec)
    }

    /// Borrows a certificate/CSR signer.
    pub(crate) fn signer(&self) -> CertSigner<'_> {
        match self {
            PrivateKey::Rsa(k) => CertSigner::Rsa(k),
            PrivateKey::Ec(k) => CertSigner::Ecdsa(k),
        }
    }
}

/// Loads a private key from `path`, dying on any error.
pub(crate) fn load_key(path: &str) -> PrivateKey {
    let raw = std::fs::read(path).unwrap_or_else(|e| die(format!("cannot read {path}: {e}")));
    let pem = core::str::from_utf8(&raw).unwrap_or_else(|_| die(format!("{path} is not PEM")));
    PrivateKey::from_pem(pem).unwrap_or_else(|| die(format!("cannot parse key in {path}")))
}

/// Parses an OpenSSL-style subject string such as `/CN=example.com/O=Acme`.
pub(crate) fn parse_subject(subj: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    for part in subj.split('/').filter(|s| !s.is_empty()) {
        let Some((k, v)) = part.split_once('=') else {
            die(format!("malformed subject component: {part}"));
        };
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

/// A random positive 63-bit serial number.
pub(crate) fn random_serial() -> u64 {
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    (u64::from_be_bytes(b) >> 1) | 1
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
