//! C ABI for XMSS / XMSS^MT stateful hash-based signatures (RFC 8391 /
//! SP 800-208).
//!
//! # Stateful-key contract (READ THIS)
//!
//! XMSS and XMSS^MT keys carry a one-time-key index that advances on every
//! signature. [`pc_xmss_sign`] / [`pc_xmssmt_sign`] advance the handle's
//! **in-memory** state. After every successful sign the caller MUST
//! re-serialize via [`pc_xmss_private_to_bytes`] / [`pc_xmssmt_private_to_bytes`]
//! and durably persist (overwrite the prior copy) **before** the signature is
//! released or used. Signing two different messages from the same persisted
//! state reuses a one-time key and is catastrophic. The library does no file
//! persistence — the caller owns it.
//!
//! The private-key serialization is self-describing (it embeds the parameter
//! OID). The public-key serialization written by `pc_*_public_to_bytes` is
//! `oid(4, big-endian) || raw_public`, so `pc_*_verify` can recover the
//! parameter set without a separate argument.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::common::{PcStatus, guard, out_write, slice, wipe_vec};
use crate::rng::OsRng;
use crate::xmss::{
    XmssMtParamSet, XmssMtPrivateKey, XmssMtPublicKey, XmssParamSet, XmssPrivateKey, XmssPublicKey,
};

/// An opaque, mutable XMSS signing key.
pub struct PcXmss(Box<XmssPrivateKey>);

/// An opaque, mutable XMSS^MT signing key.
pub struct PcXmssMt(Box<XmssMtPrivateKey>);

/// Prepends the 4-byte big-endian parameter OID to `raw`, yielding the
/// self-describing public-key blob the verify entry points expect.
fn tag_public(oid: u32, raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + raw.len());
    out.extend_from_slice(&oid.to_be_bytes());
    out.extend_from_slice(raw);
    out
}

/// Splits a tagged public-key blob into `(oid, raw)`.
fn untag_public(blob: &[u8]) -> Option<(u32, &[u8])> {
    if blob.len() < 4 {
        return None;
    }
    let oid = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]);
    Some((oid, &blob[4..]))
}

// ---------------------------------------------------------------------------
// XMSS
// ---------------------------------------------------------------------------

/// Generates an XMSS key for the parameter set `oid` (RFC 8391 numeric OID,
/// e.g. `1` = XMSS-SHA2_10_256).
#[unsafe(no_mangle)]
pub extern "C" fn pc_xmss_generate(oid: u32) -> *mut PcXmss {
    crate::ffi::common::guard_ptr(|| {
        let Some(set) = XmssParamSet::from_oid(oid) else {
            return core::ptr::null_mut();
        };
        let sk = XmssPrivateKey::generate(set, &mut OsRng);
        Box::into_raw(Box::new(PcXmss(Box::new(sk))))
    })
}

/// Parses an XMSS signing key produced by [`pc_xmss_private_to_bytes`].
///
/// # Safety
/// `bytes` valid for `len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_xmss_from_bytes(bytes: *const u8, len: usize) -> *mut PcXmss {
    crate::ffi::common::guard_ptr(|| {
        let Some(b) = (unsafe { slice(bytes, len) }) else {
            return core::ptr::null_mut();
        };
        match XmssPrivateKey::from_bytes(b) {
            Ok(k) => Box::into_raw(Box::new(PcXmss(Box::new(k)))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Serializes the XMSS signing key (INCLUDING live state). Persist after every
/// [`pc_xmss_sign`].
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_xmss_private_to_bytes(
    k: *const PcXmss,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        // The serialization carries the live seed material; wipe the
        // temporary before its backing storage returns to the allocator.
        let mut ser = unsafe { &*k }.0.to_bytes();
        let st = unsafe { out_write(&ser, out, out_len) };
        wipe_vec(&mut ser);
        st
    })
}

/// Writes the self-describing XMSS public key (`oid || root || PUB_SEED`).
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_xmss_public_to_bytes(
    k: *const PcXmss,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let pk = unsafe { &*k }.0.public_key();
        let blob = tag_public(pk.parameter_set().oid(), pk.to_bytes());
        unsafe { out_write(&blob, out, out_len) }
    })
}

/// Signs `msg`, ADVANCING the handle's in-memory state. Persist via
/// [`pc_xmss_private_to_bytes`] before releasing the signature.
///
/// The signature size is constant per parameter set and is checked BEFORE
/// signing: a size query (`*out_len == 0`) or too-small buffer returns
/// [`PcStatus::BufferTooSmall`] with the required length in `*out_len`
/// without consuming a one-time key.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_xmss_sign(
    k: *mut PcXmss,
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
        let expected = key.0.parameter_set().params().sig_bytes();
        if unsafe { *out_len } < expected {
            unsafe { *out_len = expected };
            return PcStatus::BufferTooSmall;
        }
        let sig = match key.0.sign(m) {
            Ok(s) => s,
            Err(_) => return PcStatus::Internal,
        };
        debug_assert_eq!(sig.len(), expected);
        unsafe { out_write(&sig, out, out_len) }
    })
}

/// Verifies an XMSS signature `sig` over `msg` under the self-describing public
/// key `pubkey` (as written by [`pc_xmss_public_to_bytes`]).
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_xmss_verify(
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
        let Some((oid, raw)) = untag_public(pk) else {
            return PcStatus::BadEncoding;
        };
        let Some(set) = XmssParamSet::from_oid(oid) else {
            return PcStatus::BadEncoding;
        };
        let pub_key = match XmssPublicKey::from_bytes(set, raw) {
            Ok(k) => k,
            Err(_) => return PcStatus::BadEncoding,
        };
        if pub_key.verify(m, s) {
            PcStatus::Ok
        } else {
            PcStatus::Verification
        }
    })
}

/// Frees an XMSS key handle. NULL is ignored.
///
/// # Safety
/// `k` from a generator / `pc_xmss_from_bytes`, not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_xmss_free(k: *mut PcXmss) {
    if !k.is_null() {
        drop(unsafe { Box::from_raw(k) });
    }
}

// ---------------------------------------------------------------------------
// XMSS^MT
// ---------------------------------------------------------------------------

/// Generates an XMSS^MT key for the parameter set `oid` (RFC 8391 numeric OID).
#[unsafe(no_mangle)]
pub extern "C" fn pc_xmssmt_generate(oid: u32) -> *mut PcXmssMt {
    crate::ffi::common::guard_ptr(|| {
        let Some(set) = XmssMtParamSet::from_oid(oid) else {
            return core::ptr::null_mut();
        };
        let sk = XmssMtPrivateKey::generate(set, &mut OsRng);
        Box::into_raw(Box::new(PcXmssMt(Box::new(sk))))
    })
}

/// Parses an XMSS^MT signing key produced by [`pc_xmssmt_private_to_bytes`].
///
/// # Safety
/// `bytes` valid for `len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_xmssmt_from_bytes(bytes: *const u8, len: usize) -> *mut PcXmssMt {
    crate::ffi::common::guard_ptr(|| {
        let Some(b) = (unsafe { slice(bytes, len) }) else {
            return core::ptr::null_mut();
        };
        match XmssMtPrivateKey::from_bytes(b) {
            Ok(k) => Box::into_raw(Box::new(PcXmssMt(Box::new(k)))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Serializes the XMSS^MT signing key (INCLUDING live state). Persist after
/// every [`pc_xmssmt_sign`].
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_xmssmt_private_to_bytes(
    k: *const PcXmssMt,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        // The serialization carries the live seed material; wipe the
        // temporary before its backing storage returns to the allocator.
        let mut ser = unsafe { &*k }.0.to_bytes();
        let st = unsafe { out_write(&ser, out, out_len) };
        wipe_vec(&mut ser);
        st
    })
}

/// Writes the self-describing XMSS^MT public key (`oid || root || PUB_SEED`).
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_xmssmt_public_to_bytes(
    k: *const PcXmssMt,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let pk = unsafe { &*k }.0.public_key();
        let blob = tag_public(pk.parameter_set().oid(), pk.to_bytes());
        unsafe { out_write(&blob, out, out_len) }
    })
}

/// Signs `msg`, ADVANCING the handle's in-memory state. Persist via
/// [`pc_xmssmt_private_to_bytes`] before releasing the signature.
///
/// The signature size is constant per parameter set and is checked BEFORE
/// signing: a size query (`*out_len == 0`) or too-small buffer returns
/// [`PcStatus::BufferTooSmall`] with the required length in `*out_len`
/// without consuming a one-time key.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_xmssmt_sign(
    k: *mut PcXmssMt,
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
        let expected = key.0.parameter_set().params().sig_bytes();
        if unsafe { *out_len } < expected {
            unsafe { *out_len = expected };
            return PcStatus::BufferTooSmall;
        }
        let sig = match key.0.sign(m) {
            Ok(s) => s,
            Err(_) => return PcStatus::Internal,
        };
        debug_assert_eq!(sig.len(), expected);
        unsafe { out_write(&sig, out, out_len) }
    })
}

/// Verifies an XMSS^MT signature `sig` over `msg` under the self-describing
/// public key `pubkey`.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_xmssmt_verify(
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
        let Some((oid, raw)) = untag_public(pk) else {
            return PcStatus::BadEncoding;
        };
        let Some(set) = XmssMtParamSet::from_oid(oid) else {
            return PcStatus::BadEncoding;
        };
        let pub_key = match XmssMtPublicKey::from_bytes(set, raw) {
            Ok(k) => k,
            Err(_) => return PcStatus::BadEncoding,
        };
        if pub_key.verify(m, s) {
            PcStatus::Ok
        } else {
            PcStatus::Verification
        }
    })
}

/// Frees an XMSS^MT key handle. NULL is ignored.
///
/// # Safety
/// `k` from a generator / `pc_xmssmt_from_bytes`, not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_xmssmt_free(k: *mut PcXmssMt) {
    if !k.is_null() {
        drop(unsafe { Box::from_raw(k) });
    }
}
