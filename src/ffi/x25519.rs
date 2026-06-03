//! C ABI for X25519 / X448 (RFC 7748).

use super::common::{PcStatus, guard, slice};
use crate::ec::x448::X448PrivateKey;
use crate::ec::x25519::X25519PrivateKey;

/// Computes the X25519 shared secret `scalar * peer`, writing the 32-byte
/// u-coordinate to `out`. Returns [`PcStatus::Verification`] if the peer is
/// a small-order point (output u-coord = 0 — RFC 7748 §6.1 / RFC 8446 §7.4.2).
///
/// # Safety
/// `scalar`, `peer`, and `out` must point to 32 valid bytes each.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_x25519(scalar: *const u8, peer: *const u8, out: *mut u8) -> PcStatus {
    guard(|| {
        let (Some(s), Some(p)) = (unsafe { slice(scalar, 32) }, unsafe { slice(peer, 32) }) else {
            return PcStatus::NullPointer;
        };
        if out.is_null() {
            return PcStatus::NullPointer;
        }
        let scalar: [u8; 32] = s.try_into().unwrap();
        let peer: [u8; 32] = p.try_into().unwrap();
        let sk = X25519PrivateKey::from_bytes(scalar);
        match sk.diffie_hellman(&peer) {
            Ok(secret) => {
                unsafe { core::ptr::copy_nonoverlapping(secret.as_ptr(), out, 32) };
                PcStatus::Ok
            }
            Err(_) => PcStatus::Verification,
        }
    })
}

/// Derives the X25519 public key `scalar * G` from `scalar`. The 32-byte
/// public key (canonical encoding) is written to `out`.
///
/// # Safety
/// `scalar` and `out` must point to 32 valid bytes each.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_x25519_public(scalar: *const u8, out: *mut u8) -> PcStatus {
    guard(|| {
        let Some(s) = (unsafe { slice(scalar, 32) }) else {
            return PcStatus::NullPointer;
        };
        if out.is_null() {
            return PcStatus::NullPointer;
        }
        let scalar: [u8; 32] = s.try_into().unwrap();
        let sk = X25519PrivateKey::from_bytes(scalar);
        let pk = sk.public_key();
        unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), out, 32) };
        PcStatus::Ok
    })
}

/// Computes the X448 shared secret `scalar * peer`, writing the 56-byte
/// u-coordinate to `out`. Returns [`PcStatus::Verification`] if the peer is
/// a small-order point (output u-coord = 0 — RFC 7748 / RFC 8446 §7.4.2).
///
/// # Safety
/// `scalar`, `peer`, and `out` must point to 56 valid bytes each.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_x448(scalar: *const u8, peer: *const u8, out: *mut u8) -> PcStatus {
    guard(|| {
        let (Some(s), Some(p)) = (unsafe { slice(scalar, 56) }, unsafe { slice(peer, 56) }) else {
            return PcStatus::NullPointer;
        };
        if out.is_null() {
            return PcStatus::NullPointer;
        }
        let scalar: [u8; 56] = s.try_into().unwrap();
        let peer: [u8; 56] = p.try_into().unwrap();
        let sk = X448PrivateKey::from_bytes(scalar);
        match sk.diffie_hellman(&peer) {
            Ok(secret) => {
                unsafe { core::ptr::copy_nonoverlapping(secret.as_ptr(), out, 56) };
                PcStatus::Ok
            }
            Err(_) => PcStatus::Verification,
        }
    })
}

/// Derives the X448 public key `scalar * G` from `scalar`. The 56-byte
/// public key (canonical encoding) is written to `out`.
///
/// # Safety
/// `scalar` and `out` must point to 56 valid bytes each.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_x448_public(scalar: *const u8, out: *mut u8) -> PcStatus {
    guard(|| {
        let Some(s) = (unsafe { slice(scalar, 56) }) else {
            return PcStatus::NullPointer;
        };
        if out.is_null() {
            return PcStatus::NullPointer;
        }
        let scalar: [u8; 56] = s.try_into().unwrap();
        let sk = X448PrivateKey::from_bytes(scalar);
        let pk = sk.public_key();
        unsafe { core::ptr::copy_nonoverlapping(pk.as_ptr(), out, 56) };
        PcStatus::Ok
    })
}
