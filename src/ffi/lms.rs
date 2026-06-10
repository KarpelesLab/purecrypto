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

/// Hash output length shared by every supported LMS / LM-OTS parameter set
/// (all are SHA-256 with `n = m = 32`, RFC 8554 Tables 1 and 2).
const N: usize = 32;

/// Exact encoded length of a single-tree LMS signature for the given
/// parameter sets: `u32(q) || lmots_signature || u32(lms_type) || path[h]`
/// (RFC 8554 §5.4), where the LM-OTS signature is `4 + n*(p+1)` bytes.
/// LMS signature sizes are constant per parameter set, so the FFI sign
/// entry points can check the caller's capacity BEFORE consuming a
/// one-time key. Cross-checked against the actual encoding in tests.
fn lms_sig_len(lms: LmsType, ots: LmotsType) -> usize {
    4 + ots.sig_len() + 4 + lms.h() as usize * N
}

/// Exact encoded length of an HSS signature: `u32(Nspk)` followed by `L`
/// LMS signatures interleaved with the `L - 1` signed child public keys
/// (`24 + n` bytes each), RFC 8554 §6.2.
///
/// [`HssPrivateKey`] does not expose its per-level parameter sets, so they
/// are recovered from the self-describing private serialization
/// (`u32(L) || per level { u32(lms) || u32(ots) || I(16) || seed(32) ||
/// u32(q) }`); the copy contains the master seeds and is wiped before
/// returning. Returns `None` only on a malformed serialization (which
/// would indicate an internal bug, not user input).
fn hss_sig_len(key: &HssPrivateKey) -> Option<usize> {
    let mut ser = key.to_bytes();
    let result = hss_sig_len_from_private_bytes(&ser);
    super::common::wipe_vec(&mut ser);
    result
}

fn hss_sig_len_from_private_bytes(ser: &[u8]) -> Option<usize> {
    const LEVEL_BYTES: usize = 4 + 4 + 16 + N + 4;
    let l = u32::from_be_bytes(ser.get(..4)?.try_into().ok()?) as usize;
    if l == 0 || ser.len() != 4 + l * LEVEL_BYTES {
        return None;
    }
    let mut total = 4; // u32(Nspk)
    for i in 0..l {
        let off = 4 + i * LEVEL_BYTES;
        let lms = LmsType::from_u32(u32::from_be_bytes(ser[off..off + 4].try_into().ok()?))?;
        let ots = LmotsType::from_u32(u32::from_be_bytes(ser[off + 4..off + 8].try_into().ok()?))?;
        total += lms_sig_len(lms, ots);
        if i + 1 < l {
            total += 24 + N; // signed child LMS public key
        }
    }
    Some(total)
}

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
/// The signature size is constant per parameter set and is checked BEFORE
/// signing: a size query (`*out_len == 0`) or too-small buffer returns
/// [`PcStatus::BufferTooSmall`] with the required length in `*out_len`
/// without consuming a one-time key.
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
        if k.is_null() || out_len.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(m) = (unsafe { slice(msg, msg_len) }) else {
            return PcStatus::NullPointer;
        };
        let key = unsafe { &mut *k };
        // Capacity check BEFORE signing — sign() irreversibly burns a
        // one-time key, so a mere size query must not advance the state.
        let expected = lms_sig_len(key.0.lms_type(), key.0.ots_type());
        if unsafe { *out_len } < expected {
            unsafe { *out_len = expected };
            return PcStatus::BufferTooSmall;
        }
        let sig = match key.0.sign(&mut OsRng, m) {
            Ok(s) => s,
            Err(_) => return PcStatus::Internal,
        };
        debug_assert_eq!(sig.len(), expected);
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
/// The signature size is constant per parameter-set configuration and is
/// checked BEFORE signing: a size query (`*out_len == 0`) or too-small buffer
/// returns [`PcStatus::BufferTooSmall`] with the required length in
/// `*out_len` without consuming a one-time key.
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
        if k.is_null() || out_len.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(m) = (unsafe { slice(msg, msg_len) }) else {
            return PcStatus::NullPointer;
        };
        let key = unsafe { &mut *k };
        // Capacity check BEFORE signing — sign() irreversibly burns a
        // one-time key, so a mere size query must not advance the state.
        let Some(expected) = hss_sig_len(&key.0) else {
            return PcStatus::Internal;
        };
        if unsafe { *out_len } < expected {
            unsafe { *out_len = expected };
            return PcStatus::BufferTooSmall;
        }
        let sig = match key.0.sign(&mut OsRng, m) {
            Ok(s) => s,
            Err(_) => return PcStatus::Internal,
        };
        debug_assert_eq!(sig.len(), expected);
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
