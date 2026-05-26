//! C ABI for parsing and verifying X.509 certificates.

use alloc::boxed::Box;

use super::common::{PcStatus, guard, out_write, slice};
use crate::x509::Certificate;

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
}

/// Parses a DER certificate into a handle, or NULL on failure.
///
/// # Safety
/// `der` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_cert_from_der(der: *const u8, len: usize) -> *mut PcCert {
    let Some(bytes) = (unsafe { slice(der, len) }) else {
        return core::ptr::null_mut();
    };
    match Certificate::from_der(bytes.to_vec()) {
        Ok(c) => Box::into_raw(Box::new(PcCert(c))),
        Err(_) => core::ptr::null_mut(),
    }
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
