//! C ABI for SLH-DSA (FIPS 205) keygen / sign / verify.

use alloc::boxed::Box;

use super::common::{PcStatus, guard, out_write, slice};
use crate::rng::OsRng;
use crate::slhdsa::{ParamSet, PrivateKey};
use crate::x509::AnyPublicKey;

/// SLH-DSA parameter set identifiers (mirror `PcSlhDsa` in `purecrypto.h`).
pub mod set_id {
    #![allow(missing_docs)]
    pub const SHA2_128S: i32 = 1;
    pub const SHA2_128F: i32 = 2;
    pub const SHA2_192S: i32 = 3;
    pub const SHA2_192F: i32 = 4;
    pub const SHA2_256S: i32 = 5;
    pub const SHA2_256F: i32 = 6;
    pub const SHAKE_128S: i32 = 7;
    pub const SHAKE_128F: i32 = 8;
    pub const SHAKE_192S: i32 = 9;
    pub const SHAKE_192F: i32 = 10;
    pub const SHAKE_256S: i32 = 11;
    pub const SHAKE_256F: i32 = 12;
}

fn set_from_id(set: i32) -> Option<ParamSet> {
    Some(match set {
        set_id::SHA2_128S => ParamSet::Sha2_128s,
        set_id::SHA2_128F => ParamSet::Sha2_128f,
        set_id::SHA2_192S => ParamSet::Sha2_192s,
        set_id::SHA2_192F => ParamSet::Sha2_192f,
        set_id::SHA2_256S => ParamSet::Sha2_256s,
        set_id::SHA2_256F => ParamSet::Sha2_256f,
        set_id::SHAKE_128S => ParamSet::Shake_128s,
        set_id::SHAKE_128F => ParamSet::Shake_128f,
        set_id::SHAKE_192S => ParamSet::Shake_192s,
        set_id::SHAKE_192F => ParamSet::Shake_192f,
        set_id::SHAKE_256S => ParamSet::Shake_256s,
        set_id::SHAKE_256F => ParamSet::Shake_256f,
        _ => return None,
    })
}

/// An opaque SLH-DSA private (signing) key. The parameter set lives inside
/// the boxed `PrivateKey`.
pub struct PcSlhDsa(Box<PrivateKey>);

/// Generates an SLH-DSA signing key for the parameter set.
#[unsafe(no_mangle)]
pub extern "C" fn pc_slhdsa_generate(set: i32) -> *mut PcSlhDsa {
    crate::ffi::common::guard_ptr(|| {
        let Some(ps) = set_from_id(set) else {
            return core::ptr::null_mut();
        };
        let (sk, _) = PrivateKey::generate(ps, &mut OsRng);
        Box::into_raw(Box::new(PcSlhDsa(Box::new(sk))))
    })
}

/// Parses a PKCS#8 PEM SLH-DSA private key.
///
/// # Safety
/// `pem` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_slhdsa_from_pkcs8_pem(pem: *const u8, len: usize) -> *mut PcSlhDsa {
    crate::ffi::common::guard_ptr(|| {
        let Some(bytes) = (unsafe { slice(pem, len) }) else {
            return core::ptr::null_mut();
        };
        let Ok(s) = core::str::from_utf8(bytes) else {
            return core::ptr::null_mut();
        };
        match PrivateKey::from_pkcs8_pem(s) {
            Ok(k) => Box::into_raw(Box::new(PcSlhDsa(Box::new(k)))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// PKCS#8 PEM for the private key.
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_slhdsa_private_to_pem(
    k: *const PcSlhDsa,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = unsafe { &*k }.0.to_pkcs8_pem();
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// PKIX SPKI PEM for the public verification key.
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_slhdsa_public_to_pem(
    k: *const PcSlhDsa,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = unsafe { &*k }.0.public_key().to_spki_pem();
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// Signs `msg` (hedged via OsRng), writing the signature to `out`.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_slhdsa_sign(
    k: *const PcSlhDsa,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(m) = (unsafe { slice(msg, msg_len) }) else {
            return PcStatus::NullPointer;
        };
        let sig = match unsafe { &*k }.0.sign(&mut OsRng, m, b"") {
            Ok(s) => s,
            Err(_) => return PcStatus::Internal,
        };
        unsafe { out_write(&sig, out, out_len) }
    })
}

/// Verifies an SLH-DSA signature `sig` over `msg` under the SPKI DER in `spki`.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_slhdsa_verify(
    spki: *const u8,
    spki_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> PcStatus {
    guard(|| {
        let (Some(spki), Some(m), Some(sig)) = (
            unsafe { slice(spki, spki_len) },
            unsafe { slice(msg, msg_len) },
            unsafe { slice(sig, sig_len) },
        ) else {
            return PcStatus::NullPointer;
        };
        let any = match AnyPublicKey::from_spki_der(spki) {
            Ok(k) => k,
            Err(_) => return PcStatus::BadEncoding,
        };
        let pk = match any {
            AnyPublicKey::SlhDsa(k) => k,
            _ => return PcStatus::Unsupported,
        };
        if pk.verify(sig, m, b"") {
            PcStatus::Ok
        } else {
            PcStatus::Verification
        }
    })
}

/// Frees an SLH-DSA key handle. NULL is ignored.
///
/// # Safety
/// `k` from a generator/`*_from_pem`, not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_slhdsa_free(k: *mut PcSlhDsa) {
    if !k.is_null() {
        drop(unsafe { Box::from_raw(k) });
    }
}
