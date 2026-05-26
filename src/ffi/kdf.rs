//! C ABI for HKDF, PBKDF2, scrypt, and Argon2.

use super::common::{PcStatus, guard, slice};
use super::hash::id;
use crate::hash::{Sha256, Sha384, Sha512};
use crate::kdf::argon2::{Argon2Params, Argon2Type, argon2};
use crate::kdf::scrypt::scrypt;
use crate::kdf::{hkdf, pbkdf2};

/// Argon2 variant identifiers.
pub mod argon2_id {
    #![allow(missing_docs)]
    pub const ARGON2D: i32 = 4;
    pub const ARGON2I: i32 = 5;
    pub const ARGON2ID: i32 = 6;
}

/// HKDF (RFC 5869). `hash` is `PC_SHA{256,384,512}`. `out_len` is the desired
/// output length.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_hkdf(
    hash: i32,
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    info: *const u8,
    info_len: usize,
    out: *mut u8,
    out_len: usize,
) -> PcStatus {
    guard(|| {
        let (Some(s), Some(k), Some(i)) = (
            unsafe { slice(salt, salt_len) },
            unsafe { slice(ikm, ikm_len) },
            unsafe { slice(info, info_len) },
        ) else {
            return PcStatus::NullPointer;
        };
        if out.is_null() && out_len > 0 {
            return PcStatus::NullPointer;
        }
        let buf = if out_len == 0 {
            &mut [][..]
        } else {
            unsafe { core::slice::from_raw_parts_mut(out, out_len) }
        };
        match hash {
            id::SHA256 => hkdf::<Sha256>(s, k, i, buf),
            id::SHA384 => hkdf::<Sha384>(s, k, i, buf),
            id::SHA512 => hkdf::<Sha512>(s, k, i, buf),
            _ => return PcStatus::Unsupported,
        }
        PcStatus::Ok
    })
}

/// PBKDF2 (RFC 8018). `hash` is `PC_SHA{256,384,512}`.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_pbkdf2(
    hash: i32,
    pw: *const u8,
    pw_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    out: *mut u8,
    out_len: usize,
) -> PcStatus {
    guard(|| {
        let (Some(p), Some(s)) = (unsafe { slice(pw, pw_len) }, unsafe {
            slice(salt, salt_len)
        }) else {
            return PcStatus::NullPointer;
        };
        if out.is_null() && out_len > 0 {
            return PcStatus::NullPointer;
        }
        if iterations == 0 {
            return PcStatus::Unsupported;
        }
        let buf = if out_len == 0 {
            &mut [][..]
        } else {
            unsafe { core::slice::from_raw_parts_mut(out, out_len) }
        };
        match hash {
            id::SHA256 => pbkdf2::<Sha256>(p, s, iterations, buf),
            id::SHA384 => pbkdf2::<Sha384>(p, s, iterations, buf),
            id::SHA512 => pbkdf2::<Sha512>(p, s, iterations, buf),
            _ => return PcStatus::Unsupported,
        }
        PcStatus::Ok
    })
}

/// scrypt (RFC 7914). `n` must be a power of two.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_scrypt(
    pw: *const u8,
    pw_len: usize,
    salt: *const u8,
    salt_len: usize,
    n: u32,
    r: u32,
    p: u32,
    out: *mut u8,
    out_len: usize,
) -> PcStatus {
    guard(|| {
        let (Some(pw), Some(s)) = (unsafe { slice(pw, pw_len) }, unsafe {
            slice(salt, salt_len)
        }) else {
            return PcStatus::NullPointer;
        };
        if out.is_null() && out_len > 0 {
            return PcStatus::NullPointer;
        }
        if n == 0 || !n.is_power_of_two() {
            return PcStatus::Unsupported;
        }
        let log_n = n.trailing_zeros() as u8;
        let buf = if out_len == 0 {
            &mut [][..]
        } else {
            unsafe { core::slice::from_raw_parts_mut(out, out_len) }
        };
        match scrypt(pw, s, log_n, r, p, buf) {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::Unsupported,
        }
    })
}

/// Argon2 (RFC 9106).
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_argon2(
    variant: i32,
    pw: *const u8,
    pw_len: usize,
    salt: *const u8,
    salt_len: usize,
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    out: *mut u8,
    out_len: usize,
) -> PcStatus {
    guard(|| {
        let (Some(pw), Some(s)) = (unsafe { slice(pw, pw_len) }, unsafe {
            slice(salt, salt_len)
        }) else {
            return PcStatus::NullPointer;
        };
        if out.is_null() && out_len > 0 {
            return PcStatus::NullPointer;
        }
        let variant = match variant {
            argon2_id::ARGON2I => Argon2Type::Argon2i,
            argon2_id::ARGON2D => Argon2Type::Argon2d,
            argon2_id::ARGON2ID => Argon2Type::Argon2id,
            _ => return PcStatus::Unsupported,
        };
        let params = Argon2Params {
            t_cost,
            m_cost_kib: m_cost,
            parallelism,
            variant,
            version: 0x13,
        };
        let buf = if out_len == 0 {
            &mut [][..]
        } else {
            unsafe { core::slice::from_raw_parts_mut(out, out_len) }
        };
        match argon2(&params, pw, s, &[], &[], buf) {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::Unsupported,
        }
    })
}
