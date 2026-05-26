//! C ABI for ML-DSA (FIPS 204) keygen / sign / verify.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::common::{PcStatus, guard, out_write, slice};
use crate::mldsa::{
    MlDsa44PrivateKey, MlDsa44PublicKey, MlDsa65PrivateKey, MlDsa65PublicKey, MlDsa87PrivateKey,
    MlDsa87PublicKey,
};
use crate::rng::OsRng;
use crate::x509::AnyPublicKey;

/// ML-DSA parameter sets (mirror `PcMlDsa` in `purecrypto.h`).
pub mod set_id {
    #![allow(missing_docs)]
    pub const ML_DSA_44: i32 = 1;
    pub const ML_DSA_65: i32 = 2;
    pub const ML_DSA_87: i32 = 3;
}

/// An opaque ML-DSA private key.
pub enum PcMlDsa {
    /// ML-DSA-44.
    L44(Box<MlDsa44PrivateKey>),
    /// ML-DSA-65.
    L65(Box<MlDsa65PrivateKey>),
    /// ML-DSA-87.
    L87(Box<MlDsa87PrivateKey>),
}

/// Generates an ML-DSA signing key for the given parameter set.
#[unsafe(no_mangle)]
pub extern "C" fn pc_mldsa_generate(set: i32) -> *mut PcMlDsa {
    let k = match set {
        set_id::ML_DSA_44 => {
            let (sk, _) = MlDsa44PrivateKey::generate(&mut OsRng);
            PcMlDsa::L44(Box::new(sk))
        }
        set_id::ML_DSA_65 => {
            let (sk, _) = MlDsa65PrivateKey::generate(&mut OsRng);
            PcMlDsa::L65(Box::new(sk))
        }
        set_id::ML_DSA_87 => {
            let (sk, _) = MlDsa87PrivateKey::generate(&mut OsRng);
            PcMlDsa::L87(Box::new(sk))
        }
        _ => return core::ptr::null_mut(),
    };
    Box::into_raw(Box::new(k))
}

/// Parses a PKCS#8 PEM ML-DSA private key into a handle. NULL on failure.
///
/// # Safety
/// `pem` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mldsa_from_pkcs8_pem(pem: *const u8, len: usize) -> *mut PcMlDsa {
    let Some(bytes) = (unsafe { slice(pem, len) }) else {
        return core::ptr::null_mut();
    };
    let Ok(s) = core::str::from_utf8(bytes) else {
        return core::ptr::null_mut();
    };
    if let Ok(k) = MlDsa65PrivateKey::from_pkcs8_pem(s) {
        return Box::into_raw(Box::new(PcMlDsa::L65(Box::new(k))));
    }
    if let Ok(k) = MlDsa44PrivateKey::from_pkcs8_pem(s) {
        return Box::into_raw(Box::new(PcMlDsa::L44(Box::new(k))));
    }
    if let Ok(k) = MlDsa87PrivateKey::from_pkcs8_pem(s) {
        return Box::into_raw(Box::new(PcMlDsa::L87(Box::new(k))));
    }
    core::ptr::null_mut()
}

/// PKCS#8 PEM for the private key.
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mldsa_private_to_pem(
    k: *const PcMlDsa,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = match unsafe { &*k } {
            PcMlDsa::L44(sk) => sk.to_pkcs8_pem(),
            PcMlDsa::L65(sk) => sk.to_pkcs8_pem(),
            PcMlDsa::L87(sk) => sk.to_pkcs8_pem(),
        };
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// PKIX SPKI PEM for the public verification key.
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mldsa_public_to_pem(
    k: *const PcMlDsa,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = match unsafe { &*k } {
            PcMlDsa::L44(sk) => sk.public_key().to_spki_pem(),
            PcMlDsa::L65(sk) => sk.public_key().to_spki_pem(),
            PcMlDsa::L87(sk) => sk.public_key().to_spki_pem(),
        };
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// Signs `msg` (hedged via OsRng), writing the signature to `out`. ML-DSA
/// signatures are variable-width within the parameter-set bound; use
/// `out_len=0` to query the maximum size first.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mldsa_sign(
    k: *const PcMlDsa,
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
        let sig: Vec<u8> = match unsafe { &*k } {
            PcMlDsa::L44(sk) => match sk.sign(&mut OsRng, m, b"") {
                Ok(s) => s,
                Err(_) => return PcStatus::Internal,
            },
            PcMlDsa::L65(sk) => match sk.sign(&mut OsRng, m, b"") {
                Ok(s) => s,
                Err(_) => return PcStatus::Internal,
            },
            PcMlDsa::L87(sk) => match sk.sign(&mut OsRng, m, b"") {
                Ok(s) => s,
                Err(_) => return PcStatus::Internal,
            },
        };
        unsafe { out_write(&sig, out, out_len) }
    })
}

/// Verifies an ML-DSA signature `sig` over `msg` under the SPKI DER in
/// `spki`. `set` selects the parameter set; pass the corresponding `PcMlDsa`
/// constant.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mldsa_verify(
    set: i32,
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
        let ok = match (set, &any) {
            (set_id::ML_DSA_44, AnyPublicKey::MlDsa44(k)) => k.verify(sig, m, b""),
            (set_id::ML_DSA_65, AnyPublicKey::MlDsa65(k)) => k.verify(sig, m, b""),
            (set_id::ML_DSA_87, AnyPublicKey::MlDsa87(k)) => k.verify(sig, m, b""),
            // Fall back: ignore `set` when the SPKI carries an unambiguous OID.
            (_, AnyPublicKey::MlDsa44(k)) => k.verify(sig, m, b""),
            (_, AnyPublicKey::MlDsa65(k)) => k.verify(sig, m, b""),
            (_, AnyPublicKey::MlDsa87(k)) => k.verify(sig, m, b""),
            _ => return PcStatus::Unsupported,
        };
        if ok {
            PcStatus::Ok
        } else {
            PcStatus::Verification
        }
    })
}

/// Frees an ML-DSA key handle. NULL is ignored.
///
/// # Safety
/// `k` valid, not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mldsa_free(k: *mut PcMlDsa) {
    if !k.is_null() {
        drop(unsafe { Box::from_raw(k) });
    }
}

// Suppress unused-type warnings if upstream changes the boxed PublicKey
// type aliases.
#[allow(dead_code)]
type _P44 = MlDsa44PublicKey;
#[allow(dead_code)]
type _P65 = MlDsa65PublicKey;
#[allow(dead_code)]
type _P87 = MlDsa87PublicKey;
