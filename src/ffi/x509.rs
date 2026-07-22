//! C ABI for parsing and verifying X.509 certificates.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write;

use super::common::{PcStatus, guard, out_write, slice};
use crate::ec::CurveId;
use crate::x509::{AnyPublicKey, Certificate, DistinguishedName, SanIp};

/// An opaque parsed X.509 certificate.
pub struct PcCert(Certificate);

/// Returns a borrow of the underlying [`Certificate`]. Used by sibling FFI
/// modules (e.g. `crl.rs`) that need to call a method on the certificate
/// without reparsing.
pub(super) fn pc_cert_inner(c: &PcCert) -> &Certificate {
    &c.0
}

/// Parses a PEM `CERTIFICATE` document into a handle, or NULL on failure.
///
/// # Safety
/// `pem` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_cert_from_pem(pem: *const u8, len: usize) -> *mut PcCert {
    crate::ffi::common::guard_ptr(|| {
        let Some(bytes) = (unsafe { slice(pem, len) }) else {
            return core::ptr::null_mut();
        };
        let Ok(s) = core::str::from_utf8(bytes) else {
            return core::ptr::null_mut();
        };
        match Certificate::from_pem(s) {
            Ok(c) => Box::into_raw(Box::new(PcCert(c))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Parses a DER certificate into a handle, or NULL on failure.
///
/// # Safety
/// `der` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_cert_from_der(der: *const u8, len: usize) -> *mut PcCert {
    crate::ffi::common::guard_ptr(|| {
        let Some(bytes) = (unsafe { slice(der, len) }) else {
            return core::ptr::null_mut();
        };
        match Certificate::from_der(bytes.to_vec()) {
            Ok(c) => Box::into_raw(Box::new(PcCert(c))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Writes the certificate's DER encoding to `out`.
///
/// # Safety
/// `cert` valid; buffer rules for `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_cert_to_der(
    cert: *const PcCert,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if cert.is_null() {
            return PcStatus::NullPointer;
        }
        let der = unsafe { &*cert }.0.to_der();
        unsafe { out_write(der, out, out_len) }
    })
}

/// Writes the certificate subject's public key as PKIX `SubjectPublicKeyInfo`
/// (SPKI) DER to `out`.
///
/// # Safety
/// `cert` valid; buffer rules for `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_cert_public_key_spki(
    cert: *const PcCert,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if cert.is_null() {
            return PcStatus::NullPointer;
        }
        match unsafe { &*cert }.0.subject_public_key() {
            Ok(k) => unsafe { out_write(&k.to_spki_der(), out, out_len) },
            Err(_) => PcStatus::BadEncoding,
        }
    })
}

// --- certificate analysis (JSON summary) ----------------------------------

/// Minimal JSON string literal for a control-char-free string (DN values are
/// already rejected if they contain control chars; escape quotes/backslashes
/// and any stray control byte defensively).
fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// `null` or a JSON string.
fn jopt(v: &Option<String>) -> String {
    match v {
        Some(s) => jstr(s),
        None => "null".to_string(),
    }
}

/// Dotted-decimal OID string from its arcs.
fn oid_dotted(arcs: &[u64]) -> String {
    let mut s = String::new();
    for (i, a) in arcs.iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        let _ = write!(s, "{a}");
    }
    s
}

fn hexlow(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn curve_label(c: CurveId) -> &'static str {
    match c {
        CurveId::P256 => "P-256",
        CurveId::P384 => "P-384",
        CurveId::P521 => "P-521",
        CurveId::Secp256k1 => "secp256k1",
        CurveId::Sm2p256v1 => "SM2 (sm2p256v1)",
        CurveId::BrainpoolP256r1 => "brainpoolP256r1",
        CurveId::BrainpoolP384r1 => "brainpoolP384r1",
        CurveId::BrainpoolP512r1 => "brainpoolP512r1",
    }
}

fn dn_json(dn: &DistinguishedName) -> String {
    format!(
        "{{\"cn\":{},\"o\":{},\"ou\":{},\"c\":{}}}",
        jopt(&dn.common_name),
        jopt(&dn.organization),
        jopt(&dn.organizational_unit),
        jopt(&dn.country),
    )
}

fn key_json(cert: &Certificate) -> String {
    let Ok(pk) = cert.subject_public_key() else {
        return "null".to_string();
    };
    let (alg, curve, bits): (&str, Option<&str>, Option<usize>) = match &pk {
        AnyPublicKey::Rsa(k) => ("RSA", None, Some(k.modulus().bit_len())),
        AnyPublicKey::Ecdsa(k) => ("ECDSA", Some(curve_label(k.curve())), None),
        AnyPublicKey::Ed25519(_) => ("Ed25519", None, None),
        AnyPublicKey::X25519(_) => ("X25519", None, None),
        AnyPublicKey::X448(_) => ("X448", None, None),
        AnyPublicKey::Ed448(_) => ("Ed448", None, None),
        AnyPublicKey::MlDsa44(_) => ("ML-DSA-44", None, None),
        AnyPublicKey::MlDsa65(_) => ("ML-DSA-65", None, None),
        AnyPublicKey::MlDsa87(_) => ("ML-DSA-87", None, None),
        AnyPublicKey::SlhDsa(_) => ("SLH-DSA", None, None),
    };
    format!(
        "{{\"algorithm\":{},\"curve\":{},\"bits\":{}}}",
        jstr(alg),
        curve.map(jstr).unwrap_or_else(|| "null".to_string()),
        bits.map(|b| b.to_string())
            .unwrap_or_else(|| "null".to_string()),
    )
}

fn json_array<T>(items: &[T], f: impl Fn(&T) -> String) -> String {
    let parts: Vec<String> = items.iter().map(f).collect();
    format!("[{}]", parts.join(","))
}

/// Writes a JSON summary of `cert` to `out` (see the ABI's out-buffer
/// convention). Fields: subject/issuer (CN/O/OU/C), validity (Unix seconds),
/// serial (hex), key {algorithm, curve, bits}, signature algorithm OID,
/// subjectAltName DNS/IP lists, basic constraints, keyUsage bits, and extended
/// key usage OIDs. Consumed by the demo site's certificate analyzer.
///
/// # Safety
/// `cert` must come from a `pc_cert_*` constructor; `out`/`out_len` follow the
/// usual out-buffer convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_cert_analyze(
    cert: *const PcCert,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if cert.is_null() {
            return PcStatus::NullPointer;
        }
        let c = &unsafe { &*cert }.0;

        let subject = c
            .subject()
            .map(|d| dn_json(&d))
            .unwrap_or_else(|_| "null".to_string());
        let issuer = c
            .issuer()
            .map(|d| dn_json(&d))
            .unwrap_or_else(|_| "null".to_string());
        let (nb, na) = match c.validity() {
            Ok(v) => (v.not_before.to_unix(), v.not_after.to_unix()),
            Err(_) => (0, 0),
        };
        let serial = c.serial_bytes().map(hexlow).unwrap_or_default();
        let sig_oid = c
            .signature_algorithm_oid()
            .map(|o| oid_dotted(&o))
            .unwrap_or_default();
        let dns = c.subject_alt_names().unwrap_or_default();
        let ips = c.subject_alt_ips().unwrap_or_default();
        let eku = c.extended_key_usages().unwrap_or_default();
        let (is_ca, path_len) = match c.basic_constraints() {
            Ok(Some((ca, pl))) => (
                ca.to_string(),
                pl.map(|p| p.to_string())
                    .unwrap_or_else(|| "null".to_string()),
            ),
            _ => ("null".to_string(), "null".to_string()),
        };
        let key_usage = match c.key_usage() {
            Ok(Some(k)) => k.to_string(),
            _ => "null".to_string(),
        };

        let json = format!(
            concat!(
                "{{\"subject\":{},\"issuer\":{},\"not_before\":{},\"not_after\":{},",
                "\"serial\":{},\"key\":{},\"sig_alg_oid\":{},\"sans_dns\":{},",
                "\"sans_ip\":{},\"is_ca\":{},\"path_len\":{},\"key_usage\":{},\"eku\":{}}}"
            ),
            subject,
            issuer,
            nb,
            na,
            jstr(&serial),
            key_json(c),
            jstr(&sig_oid),
            json_array(&dns, |s| jstr(s)),
            json_array(&ips, |ip| match ip {
                SanIp::V4(b) => jstr(&std::net::Ipv4Addr::from(*b).to_string()),
                SanIp::V6(b) => jstr(&std::net::Ipv6Addr::from(*b).to_string()),
            }),
            is_ca,
            path_len,
            key_usage,
            json_array(&eku, |o| jstr(&oid_dotted(o))),
        );

        unsafe { out_write(json.as_bytes(), out, out_len) }
    })
}

/// Verifies that `cert`'s signature was produced by `issuer`'s public key.
/// Returns [`PcStatus::Ok`] iff valid. (This checks the signature only, not the
/// validity period or name constraints.)
///
/// # Safety
/// Both handles must come from the `pc_cert_*` constructors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_cert_verify(cert: *const PcCert, issuer: *const PcCert) -> PcStatus {
    guard(|| {
        if cert.is_null() || issuer.is_null() {
            return PcStatus::NullPointer;
        }
        let issuer_key = match unsafe { &*issuer }.0.subject_public_key() {
            Ok(k) => k,
            Err(_) => return PcStatus::BadEncoding,
        };
        match unsafe { &*cert }.0.verify_signature_with(&issuer_key) {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::Verification,
        }
    })
}

/// Frees a certificate handle. NULL is ignored.
///
/// # Safety
/// `cert` from a `pc_cert_*` constructor, not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_cert_free(cert: *mut PcCert) {
    if !cert.is_null() {
        drop(unsafe { Box::from_raw(cert) });
    }
}

/// Generates a self-signed ECDSA P-256 certificate using `key` (CN =
/// `cn`, valid for `days` days from now). Returns the certificate as a
/// `CERTIFICATE` PEM in `out`.
///
/// Convenience entry point used by the TLS/DTLS smoke tests: a single
/// call materialises both a leaf cert (via `pc_tls_cfg_set_certificate`'s
/// PEM input) and a usable trust anchor (via `pc_tls_cfg_add_root_pem`).
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ec_self_signed_pem(
    key: *const super::ec::PcEcKey,
    cn: *const core::ffi::c_char,
    days: u32,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    use crate::x509::{CertSigner, DistinguishedName, Time, Validity};
    guard(|| {
        if key.is_null() || cn.is_null() {
            return PcStatus::NullPointer;
        }
        let cs = unsafe { core::ffi::CStr::from_ptr(cn) };
        let Ok(cn) = cs.to_str() else {
            return PcStatus::BadEncoding;
        };
        let sk = super::ec::pc_ec_inner_key(unsafe { &*key });
        let signer = CertSigner::Ecdsa(sk);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1_700_000_000);
        let validity = Validity::new(
            Time::from_unix(now),
            Time::from_unix(now + (days as u64) * 86_400),
        );
        let subject = DistinguishedName::common_name(cn);
        let cert =
            match Certificate::self_signed_general(&signer, &subject, &validity, 1, false, &[cn]) {
                Ok(c) => c,
                Err(_) => return PcStatus::Internal,
            };
        let pem = crate::der::pem_encode("CERTIFICATE", cert.to_der());
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}
