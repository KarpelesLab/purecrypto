//! C ABI for X.509 CRL (RFC 5280 §5) parse / verify / lookup.

use alloc::boxed::Box;

use super::common::{PcStatus, guard, slice};
use super::x509::PcCert;
use crate::x509::CertificateRevocationList;

/// An opaque CRL.
pub struct PcCrl(CertificateRevocationList);

/// Parses a CRL from PEM (`X509 CRL`).
///
/// # Safety
/// `pem` valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_crl_from_pem(pem: *const u8, len: usize) -> *mut PcCrl {
    crate::ffi::common::guard_ptr(|| {
        let Some(bytes) = (unsafe { slice(pem, len) }) else {
            return core::ptr::null_mut();
        };
        let Ok(s) = core::str::from_utf8(bytes) else {
            return core::ptr::null_mut();
        };
        match CertificateRevocationList::from_pem(s) {
            Ok(crl) => Box::into_raw(Box::new(PcCrl(crl))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Parses a CRL from DER.
///
/// # Safety
/// `der` valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_crl_from_der(der: *const u8, len: usize) -> *mut PcCrl {
    crate::ffi::common::guard_ptr(|| {
        let Some(bytes) = (unsafe { slice(der, len) }) else {
            return core::ptr::null_mut();
        };
        match CertificateRevocationList::from_der(bytes.to_vec()) {
            Ok(crl) => Box::into_raw(Box::new(PcCrl(crl))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Verifies that the CRL's outer signature was produced by the subject
/// public key in `issuer`. Returns [`PcStatus::Ok`] on a valid signature,
/// [`PcStatus::Verification`] otherwise.
///
/// # Safety
/// Both pointers valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_crl_verify_with(crl: *const PcCrl, issuer: *const PcCert) -> PcStatus {
    guard(|| {
        if crl.is_null() || issuer.is_null() {
            return PcStatus::NullPointer;
        }
        let cert = super::x509::pc_cert_inner(unsafe { &*issuer });
        let key = match cert.subject_public_key() {
            Ok(k) => k,
            Err(_) => return PcStatus::BadEncoding,
        };
        match unsafe { &*crl }.0.verify_signature_with(&key) {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::Verification,
        }
    })
}

/// Returns `1` if the CRL revokes the supplied big-endian serial, `0` if it
/// does not, and `-1` on a CRL parse error.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_crl_is_revoked(
    crl: *const PcCrl,
    serial_be: *const u8,
    len: usize,
) -> i32 {
    crate::ffi::common::guard_i32(-1, || {
        if crl.is_null() {
            return -1;
        }
        let Some(s) = (unsafe { slice(serial_be, len) }) else {
            return -1;
        };
        match unsafe { &*crl }.0.is_revoked(s) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -1,
        }
    })
}

/// Frees a CRL handle. NULL is ignored.
///
/// # Safety
/// `crl` from a constructor, not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_crl_free(crl: *mut PcCrl) {
    if !crl.is_null() {
        drop(unsafe { Box::from_raw(crl) });
    }
}
