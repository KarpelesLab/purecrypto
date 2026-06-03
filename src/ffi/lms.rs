//! C ABI for LMS / HSS stateful hash-based signatures (RFC 8554 / SP 800-208).
//!
//! # Stateful-key contract (READ THIS)
//!
//! LMS and HSS keys carry a one-time-key index that advances on every
//! signature. [`pc_lms_sign`] / [`pc_hss_sign`] advance the handle's
//! **in-memory** state. After every successful sign the caller MUST
//! (1) re-serialize the handle via [`pc_lms_private_to_bytes`] /
//! [`pc_hss_private_to_bytes`], and (2) durably persist those bytes
//! (overwriting the prior copy) **before** the produced signature is released
//! or used. Reusing an older serialized state to sign a different message
//! reuses a one-time key and is catastrophic (it can leak the signing key).
//! There is no in-library file persistence — the caller owns it.

use alloc::boxed::Box;

use super::common::{PcStatus, guard, out_write, slice};
use crate::lms::{HssPrivateKey, LmotsType, LmsPrivateKey, LmsType, verify_hss, verify_lms};
use crate::rng::OsRng;

/// LMS parameter-set identifiers (mirror `PcLmsType` in `purecrypto.h`).
pub mod lms_id {
    #![allow(missing_docs)]
    pub const SHA256_M32_H5: i32 = 5;
    pub const SHA256_M32_H10: i32 = 6;
    pub const SHA256_M32_H15: i32 = 7;
    pub const SHA256_M32_H20: i32 = 8;
    pub const SHA256_M32_H25: i32 = 9;
}

/// LM-OTS parameter-set identifiers (mirror `PcLmotsType` in `purecrypto.h`).
pub mod lmots_id {
    #![allow(missing_docs)]
    pub const SHA256_N32_W1: i32 = 1;
    pub const SHA256_N32_W2: i32 = 2;
    pub const SHA256_N32_W4: i32 = 3;
    pub const SHA256_N32_W8: i32 = 4;
}

fn lms_type(v: i32) -> Option<LmsType> {
    Some(match v {
        lms_id::SHA256_M32_H5 => LmsType::Sha256M32H5,
        lms_id::SHA256_M32_H10 => LmsType::Sha256M32H10,
        lms_id::SHA256_M32_H15 => LmsType::Sha256M32H15,
        lms_id::SHA256_M32_H20 => LmsType::Sha256M32H20,
        lms_id::SHA256_M32_H25 => LmsType::Sha256M32H25,
        _ => return None,
    })
}

fn lmots_type(v: i32) -> Option<LmotsType> {
    Some(match v {
        lmots_id::SHA256_N32_W1 => LmotsType::Sha256N32W1,
        lmots_id::SHA256_N32_W2 => LmotsType::Sha256N32W2,
        lmots_id::SHA256_N32_W4 => LmotsType::Sha256N32W4,
        lmots_id::SHA256_N32_W8 => LmotsType::Sha256N32W8,
        _ => return None,
    })
}

/// An opaque, mutable single-tree LMS signing key.
pub struct PcLms(Box<LmsPrivateKey>);

/// An opaque, mutable multi-level HSS signing key.
pub struct PcHss(Box<HssPrivateKey>);

// ---------------------------------------------------------------------------
// LMS
// ---------------------------------------------------------------------------

/// Generates a single-tree LMS key with the given LMS / LM-OTS parameter sets.
#[unsafe(no_mangle)]
pub extern "C" fn pc_lms_generate(lms_param: i32, lmots_param: i32) -> *mut PcLms {
    crate::ffi::common::guard_ptr(|| {
        let (Some(lms), Some(ots)) = (lms_type(lms_param), lmots_type(lmots_param)) else {
            return core::ptr::null_mut();
        };
        let sk = LmsPrivateKey::generate(lms, ots, &mut OsRng);
        Box::into_raw(Box::new(PcLms(Box::new(sk))))
    })
}

/// Parses an LMS signing key produced by [`pc_lms_private_to_bytes`], resuming
/// at the persisted one-time-key index.
///
/// # Safety
/// `bytes` valid for `len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_lms_from_bytes(bytes: *const u8, len: usize) -> *mut PcLms {
    crate::ffi::common::guard_ptr(|| {
        let Some(b) = (unsafe { slice(bytes, len) }) else {
            return core::ptr::null_mut();
        };
        match LmsPrivateKey::from_bytes(b) {
            Ok(k) => Box::into_raw(Box::new(PcLms(Box::new(k)))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Serializes the LMS signing key (INCLUDING the live one-time-key index). The
/// caller MUST persist this after every [`pc_lms_sign`] (see module docs).
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_lms_private_to_bytes(
    k: *const PcLms,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        unsafe { out_write(&(*k).0.to_bytes(), out, out_len) }
    })
}

/// Writes the raw LMS public key (self-describing: typecodes embedded).
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_lms_public_to_bytes(
    k: *const PcLms,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let pk = unsafe { &*k }.0.public_key();
        unsafe { out_write(pk.to_bytes(), out, out_len) }
    })
}

/// Signs `msg`, ADVANCING the handle's in-memory one-time-key index. After this
/// returns [`PcStatus::Ok`], the caller MUST re-serialize via
/// [`pc_lms_private_to_bytes`] and persist before releasing the signature.
/// Returns [`PcStatus::Internal`] when the key is exhausted.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_lms_sign(
    k: *mut PcLms,
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
        let sig = match unsafe { &mut *k }.0.sign(&mut OsRng, m) {
            Ok(s) => s,
            Err(_) => return PcStatus::Internal,
        };
        unsafe { out_write(&sig, out, out_len) }
    })
}

/// Verifies an LMS signature `sig` over `msg` under the raw LMS public key
/// `pubkey` (as written by [`pc_lms_public_to_bytes`]).
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_lms_verify(
    pubkey: *const u8,
    pubkey_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> PcStatus {
    guard(|| {
        let (Some(pk), Some(m), Some(s)) = (
            unsafe { slice(pubkey, pubkey_len) },
            unsafe { slice(msg, msg_len) },
            unsafe { slice(sig, sig_len) },
        ) else {
            return PcStatus::NullPointer;
        };
        if verify_lms(pk, m, s) {
            PcStatus::Ok
        } else {
            PcStatus::Verification
        }
    })
}

/// Frees an LMS key handle. NULL is ignored.
///
/// # Safety
/// `k` from a generator / `pc_lms_from_bytes`, not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_lms_free(k: *mut PcLms) {
    if !k.is_null() {
        drop(unsafe { Box::from_raw(k) });
    }
}

// ---------------------------------------------------------------------------
// HSS
// ---------------------------------------------------------------------------

/// Generates an HSS key of `levels` identical levels, each with the given LMS /
/// LM-OTS parameter sets. `levels` must be in `1..=8`.
#[unsafe(no_mangle)]
pub extern "C" fn pc_hss_generate(levels: usize, lms_param: i32, lmots_param: i32) -> *mut PcHss {
    crate::ffi::common::guard_ptr(|| {
        let (Some(lms), Some(ots)) = (lms_type(lms_param), lmots_type(lmots_param)) else {
            return core::ptr::null_mut();
        };
        if !(1..=8).contains(&levels) {
            return core::ptr::null_mut();
        }
        let params = alloc::vec![(lms, ots); levels];
        match HssPrivateKey::generate(&params, &mut OsRng) {
            Ok(sk) => Box::into_raw(Box::new(PcHss(Box::new(sk)))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Parses an HSS signing key produced by [`pc_hss_private_to_bytes`].
///
/// # Safety
/// `bytes` valid for `len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_hss_from_bytes(bytes: *const u8, len: usize) -> *mut PcHss {
    crate::ffi::common::guard_ptr(|| {
        let Some(b) = (unsafe { slice(bytes, len) }) else {
            return core::ptr::null_mut();
        };
        match HssPrivateKey::from_bytes(b) {
            Ok(k) => Box::into_raw(Box::new(PcHss(Box::new(k)))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Serializes the HSS signing key (INCLUDING live state). Persist after every
/// [`pc_hss_sign`].
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_hss_private_to_bytes(
    k: *const PcHss,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        unsafe { out_write(&(*k).0.to_bytes(), out, out_len) }
    })
}

/// Writes the raw HSS public key (self-describing).
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_hss_public_to_bytes(
    k: *const PcHss,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let pk = unsafe { &*k }.0.public_key();
        unsafe { out_write(pk.to_bytes(), out, out_len) }
    })
}

/// Signs `msg`, ADVANCING the handle's in-memory state. Persist via
/// [`pc_hss_private_to_bytes`] before releasing the signature.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_hss_sign(
    k: *mut PcHss,
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
        let sig = match unsafe { &mut *k }.0.sign(&mut OsRng, m) {
            Ok(s) => s,
            Err(_) => return PcStatus::Internal,
        };
        unsafe { out_write(&sig, out, out_len) }
    })
}

/// Verifies an HSS signature `sig` over `msg` under the raw HSS public key.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_hss_verify(
    pubkey: *const u8,
    pubkey_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> PcStatus {
    guard(|| {
        let (Some(pk), Some(m), Some(s)) = (
            unsafe { slice(pubkey, pubkey_len) },
            unsafe { slice(msg, msg_len) },
            unsafe { slice(sig, sig_len) },
        ) else {
            return PcStatus::NullPointer;
        };
        if verify_hss(pk, m, s) {
            PcStatus::Ok
        } else {
            PcStatus::Verification
        }
    })
}

/// Frees an HSS key handle. NULL is ignored.
///
/// # Safety
/// `k` from a generator / `pc_hss_from_bytes`, not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_hss_free(k: *mut PcHss) {
    if !k.is_null() {
        drop(unsafe { Box::from_raw(k) });
    }
}
