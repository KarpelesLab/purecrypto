//! C ABI for X.509 CSR (PKCS#10) creation, parse, verify.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::common::{PcStatus, guard, out_write, slice};
use super::rsa::PcRsaKey;
use crate::x509::{CertSigner, CertificationRequest, DistinguishedName};

/// An opaque CSR.
pub struct PcCsr(CertificationRequest);

/// Creates a CSR signed by `rsa_key`, with `subject_cn` as the only subject
/// attribute (CN). `dns_names`/`dns_count` are optional DNS subjectAltName
/// extension requests. Returns NULL on failure.
///
/// # Safety
/// `rsa_key` valid; `subject_cn` a NUL-terminated UTF-8 string; `dns_names`
/// points to `dns_count` NUL-terminated UTF-8 C strings (or NULL when
/// `dns_count == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_csr_create_rsa(
    rsa_key: *const PcRsaKey,
    subject_cn: *const core::ffi::c_char,
    dns_names: *const *const core::ffi::c_char,
    dns_count: usize,
) -> *mut PcCsr {
    if rsa_key.is_null() || subject_cn.is_null() {
        return core::ptr::null_mut();
    }
    let cn = unsafe { core::ffi::CStr::from_ptr(subject_cn) };
    let Ok(cn) = cn.to_str() else {
        return core::ptr::null_mut();
    };
    let mut dns: Vec<&str> = Vec::with_capacity(dns_count);
    if dns_count > 0 {
        if dns_names.is_null() {
            return core::ptr::null_mut();
        }
        for i in 0..dns_count {
            let p = unsafe { *dns_names.add(i) };
            if p.is_null() {
                return core::ptr::null_mut();
            }
            let s = unsafe { core::ffi::CStr::from_ptr(p) };
            let Ok(s) = s.to_str() else {
                return core::ptr::null_mut();
            };
            dns.push(s);
        }
    }
    let subject = DistinguishedName::common_name(cn);
    // SAFETY: PcRsaKey is allocated by Box::into_raw, so we can borrow the
    // inner key through a shared reference. The internal field `key` is
    // private; expose it via a small accessor.
    let key_ref = unsafe { rsa_key_inner(&*rsa_key) };
    let signer = CertSigner::Rsa(key_ref);
    match CertificationRequest::create(&signer, &subject, &dns) {
        Ok(csr) => Box::into_raw(Box::new(PcCsr(csr))),
        Err(_) => core::ptr::null_mut(),
    }
}

/// Helper that exposes the borrow of the inner BoxedRsaPrivateKey. Defined
/// here (rather than in `rsa.rs`) so the public field need not be widened.
fn rsa_key_inner(k: &PcRsaKey) -> &crate::rsa::BoxedRsaPrivateKey {
    k.key()
}

// Provide a small accessor on PcRsaKey. Done via an inherent impl below in
// rsa.rs is awkward — instead, declare the accessor in rsa.rs's
// `impl PcRsaKey`. We forward to it here. To avoid re-declaring it twice,
// gate on a method we add to PcRsaKey via an extension trait.
trait PcRsaKeyAccess {
    fn key(&self) -> &crate::rsa::BoxedRsaPrivateKey;
}

impl PcRsaKeyAccess for PcRsaKey {
    fn key(&self) -> &crate::rsa::BoxedRsaPrivateKey {
        super::rsa::pc_rsa_inner_key(self)
    }
}

/// Parses a CSR from PEM.
///
/// # Safety
/// `pem` valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_csr_from_pem(pem: *const u8, len: usize) -> *mut PcCsr {
    let Some(bytes) = (unsafe { slice(pem, len) }) else {
        return core::ptr::null_mut();
    };
    let Ok(s) = core::str::from_utf8(bytes) else {
        return core::ptr::null_mut();
    };
    match CertificationRequest::from_pem(s) {
        Ok(csr) => Box::into_raw(Box::new(PcCsr(csr))),
        Err(_) => core::ptr::null_mut(),
    }
}

/// Writes the CSR as a `CERTIFICATE REQUEST` PEM to `out`.
///
/// # Safety
/// `csr` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_csr_to_pem(
    csr: *const PcCsr,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if csr.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = unsafe { &*csr }.0.to_pem();
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// Verifies the CSR's self-signature (the public key inside the request
/// signs its TBS contents). Returns [`PcStatus::Ok`] iff the signature is
/// valid.
///
/// # Safety
/// `csr` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_csr_verify_self_signed(csr: *const PcCsr) -> PcStatus {
    guard(|| {
        if csr.is_null() {
            return PcStatus::NullPointer;
        }
        match unsafe { &*csr }.0.verify_self_signed() {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::Verification,
        }
    })
}

/// Writes the CSR subject's CN attribute to `out` as a UTF-8 string (no NUL).
/// Returns [`PcStatus::BadEncoding`] if there is no CN.
///
/// # Safety
/// `csr` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_csr_subject_cn(
    csr: *const PcCsr,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if csr.is_null() {
            return PcStatus::NullPointer;
        }
        let subject = match unsafe { &*csr }.0.subject() {
            Ok(s) => s,
            Err(_) => return PcStatus::BadEncoding,
        };
        let Some(cn) = subject.common_name else {
            return PcStatus::BadEncoding;
        };
        unsafe { out_write(cn.as_bytes(), out, out_len) }
    })
}

/// Frees a CSR. NULL is ignored.
///
/// # Safety
/// `csr` from a constructor, not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_csr_free(csr: *mut PcCsr) {
    if !csr.is_null() {
        drop(unsafe { Box::from_raw(csr) });
    }
}
