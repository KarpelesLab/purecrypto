//! C ABI for RSA key generation, signing, verification, and PEM I/O.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::common::{PcStatus, guard, out_write, slice};
use super::hash::id;
use crate::bignum::Uint;
use crate::der::{pem_decode, pem_encode};
use crate::hash::{Sha224, Sha256, Sha384, Sha512};
use crate::rng::OsRng;
use crate::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
use crate::x509::AnyPublicKey;

const PEM_LABEL: &str = "RSA PRIVATE KEY";
const E: u64 = 65537;
const ROUNDS: usize = 20;

/// An opaque RSA private key. The original PKCS#1 DER (which carries the CRT
/// primes the runtime key type drops) is retained so it can be re-emitted.
pub struct PcRsaKey {
    key: BoxedRsaPrivateKey,
    der: Vec<u8>,
}

impl PcRsaKey {
    fn from_pkcs1_der(der: Vec<u8>) -> Option<Self> {
        let key = BoxedRsaPrivateKey::from_pkcs1_der(&der).ok()?;
        Some(PcRsaKey { key, der })
    }
}

/// Generates an RSA private key of `bits` (2048, 3072, or 4096), or NULL.
#[unsafe(no_mangle)]
pub extern "C" fn pc_rsa_generate(bits: u32) -> *mut PcRsaKey {
    let der = match bits {
        2048 => RsaPrivateKey::<32>::generate(Uint::from_u64(E), &mut OsRng, ROUNDS).to_pkcs1_der(),
        3072 => RsaPrivateKey::<48>::generate(Uint::from_u64(E), &mut OsRng, ROUNDS).to_pkcs1_der(),
        4096 => RsaPrivateKey::<64>::generate(Uint::from_u64(E), &mut OsRng, ROUNDS).to_pkcs1_der(),
        _ => return core::ptr::null_mut(),
    };
    match PcRsaKey::from_pkcs1_der(der) {
        Some(k) => Box::into_raw(Box::new(k)),
        None => core::ptr::null_mut(),
    }
}

/// Parses a PKCS#1 `RSA PRIVATE KEY` PEM into a key handle, or NULL on failure.
///
/// # Safety
/// `pem` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rsa_from_pem(pem: *const u8, len: usize) -> *mut PcRsaKey {
    let Some(bytes) = (unsafe { slice(pem, len) }) else {
        return core::ptr::null_mut();
    };
    let Ok(s) = core::str::from_utf8(bytes) else {
        return core::ptr::null_mut();
    };
    let Ok(der) = pem_decode(s, PEM_LABEL) else {
        return core::ptr::null_mut();
    };
    match PcRsaKey::from_pkcs1_der(der) {
        Some(k) => Box::into_raw(Box::new(k)),
        None => core::ptr::null_mut(),
    }
}

/// Writes the key as a PKCS#1 `RSA PRIVATE KEY` PEM to `out`.
///
/// # Safety
/// `key` valid; buffer rules for `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rsa_private_to_pem(
    key: *const PcRsaKey,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if key.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = pem_encode(PEM_LABEL, &unsafe { &*key }.der);
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// Writes the public key as a PKIX `PUBLIC KEY` (SPKI) PEM to `out`.
///
/// # Safety
/// `key` valid; buffer rules for `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rsa_public_to_pem(
    key: *const PcRsaKey,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if key.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = AnyPublicKey::Rsa(unsafe { &*key }.key.public_key()).to_spki_pem();
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// Signs `msg` with PKCS#1 v1.5 under the hash `alg` (SHA-224/256/384/512),
/// writing the signature to `out`.
///
/// # Safety
/// `key` valid; `msg` valid for `msg_len`; buffer rules for `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rsa_sign_pkcs1(
    key: *const PcRsaKey,
    alg: i32,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if key.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(m) = (unsafe { slice(msg, msg_len) }) else {
            return PcStatus::NullPointer;
        };
        let k = &unsafe { &*key }.key;
        let sig = match alg {
            id::SHA224 => k.sign_pkcs1v15::<Sha224>(m),
            id::SHA256 => k.sign_pkcs1v15::<Sha256>(m),
            id::SHA384 => k.sign_pkcs1v15::<Sha384>(m),
            id::SHA512 => k.sign_pkcs1v15::<Sha512>(m),
            _ => return PcStatus::Unsupported,
        };
        match sig {
            Ok(s) => unsafe { out_write(&s, out, out_len) },
            Err(_) => PcStatus::Internal,
        }
    })
}

/// Verifies a PKCS#1 v1.5 signature `sig` over `msg` under the SPKI DER in
/// `spki`, with hash `alg`. Returns [`PcStatus::Ok`] iff valid.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rsa_verify_pkcs1(
    spki: *const u8,
    spki_len: usize,
    alg: i32,
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
        let key = match AnyPublicKey::from_spki_der(spki) {
            Ok(AnyPublicKey::Rsa(k)) => k,
            Ok(_) => return PcStatus::Unsupported,
            Err(_) => return PcStatus::BadEncoding,
        };
        let ok = match alg {
            id::SHA224 => key.verify_pkcs1v15::<Sha224>(m, sig),
            id::SHA256 => key.verify_pkcs1v15::<Sha256>(m, sig),
            id::SHA384 => key.verify_pkcs1v15::<Sha384>(m, sig),
            id::SHA512 => key.verify_pkcs1v15::<Sha512>(m, sig),
            _ => return PcStatus::Unsupported,
        };
        if ok.is_ok() {
            PcStatus::Ok
        } else {
            PcStatus::Verification
        }
    })
}

/// Frees an RSA key. NULL is ignored.
///
/// # Safety
/// `key` from [`pc_rsa_generate`]/[`pc_rsa_from_pem`], not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rsa_free(key: *mut PcRsaKey) {
    if !key.is_null() {
        drop(unsafe { Box::from_raw(key) });
    }
}
