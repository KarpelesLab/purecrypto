//! C ABI for ML-KEM (FIPS 203) keygen / encaps / decaps.

use alloc::boxed::Box;

use super::common::{PcStatus, guard, out_write, slice};
use crate::mlkem::{
    MlKem512Ciphertext, MlKem512DecapsKey, MlKem512EncapsKey, MlKem768Ciphertext,
    MlKem768DecapsKey, MlKem768EncapsKey, MlKem1024Ciphertext, MlKem1024DecapsKey,
    MlKem1024EncapsKey,
};
use crate::rng::OsRng;

/// ML-KEM parameter sets (mirror `PcMlKem` in `purecrypto.h`).
pub mod set_id {
    #![allow(missing_docs)]
    pub const ML_KEM_512: i32 = 1;
    pub const ML_KEM_768: i32 = 2;
    pub const ML_KEM_1024: i32 = 3;
}

/// An opaque ML-KEM decapsulation (private) key. The parameter set is
/// encoded by the variant and remains constant for the handle's lifetime.
pub enum PcMlKem {
    /// ML-KEM-512.
    K512(Box<MlKem512DecapsKey>),
    /// ML-KEM-768.
    K768(Box<MlKem768DecapsKey>),
    /// ML-KEM-1024.
    K1024(Box<MlKem1024DecapsKey>),
}

/// Generates an ML-KEM decapsulation key for the given parameter set.
/// Returns NULL on an unknown set.
#[unsafe(no_mangle)]
pub extern "C" fn pc_mlkem_generate(set: i32) -> *mut PcMlKem {
    crate::ffi::common::guard_ptr(|| {
        let k = match set {
            set_id::ML_KEM_512 => {
                let (sk, _) = MlKem512DecapsKey::generate(&mut OsRng);
                PcMlKem::K512(Box::new(sk))
            }
            set_id::ML_KEM_768 => {
                let (sk, _) = MlKem768DecapsKey::generate(&mut OsRng);
                PcMlKem::K768(Box::new(sk))
            }
            set_id::ML_KEM_1024 => {
                let (sk, _) = MlKem1024DecapsKey::generate(&mut OsRng);
                PcMlKem::K1024(Box::new(sk))
            }
            _ => return core::ptr::null_mut(),
        };
        Box::into_raw(Box::new(k))
    })
}

/// Parses a PKCS#8 PEM ML-KEM private key into a handle, returning NULL on
/// failure (including a non-matching parameter set OID).
///
/// # Safety
/// `pem` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mlkem_from_pkcs8_pem(pem: *const u8, len: usize) -> *mut PcMlKem {
    crate::ffi::common::guard_ptr(|| {
        let Some(bytes) = (unsafe { slice(pem, len) }) else {
            return core::ptr::null_mut();
        };
        let Ok(s) = core::str::from_utf8(bytes) else {
            return core::ptr::null_mut();
        };
        if let Ok(k) = MlKem768DecapsKey::from_pkcs8_pem(s) {
            return Box::into_raw(Box::new(PcMlKem::K768(Box::new(k))));
        }
        if let Ok(k) = MlKem512DecapsKey::from_pkcs8_pem(s) {
            return Box::into_raw(Box::new(PcMlKem::K512(Box::new(k))));
        }
        if let Ok(k) = MlKem1024DecapsKey::from_pkcs8_pem(s) {
            return Box::into_raw(Box::new(PcMlKem::K1024(Box::new(k))));
        }
        core::ptr::null_mut()
    })
}

/// Writes the key as a PKCS#8 `PRIVATE KEY` PEM to `out`.
///
/// # Safety
/// `k` from [`pc_mlkem_generate`]/[`pc_mlkem_from_pkcs8_pem`]; buffer rules apply.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mlkem_private_to_pem(
    k: *const PcMlKem,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = match unsafe { &*k } {
            PcMlKem::K512(sk) => sk.to_pkcs8_pem(),
            PcMlKem::K768(sk) => sk.to_pkcs8_pem(),
            PcMlKem::K1024(sk) => sk.to_pkcs8_pem(),
        };
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// Writes the matching encapsulation key as a PKIX SPKI PEM to `out`.
///
/// # Safety
/// `k` from a generator/`*_from_pem`; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mlkem_public_to_pem(
    k: *const PcMlKem,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = match unsafe { &*k } {
            PcMlKem::K512(sk) => sk.encapsulation_key().to_spki_pem(),
            PcMlKem::K768(sk) => sk.encapsulation_key().to_spki_pem(),
            PcMlKem::K1024(sk) => sk.encapsulation_key().to_spki_pem(),
        };
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// Writes the matching encapsulation key as a PKIX SPKI DER blob to `out`.
/// Pair with [`pc_mlkem_encaps`], which (since I-6) expects DER bytes.
///
/// # Safety
/// `k` from a generator/`*_from_pem`; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mlkem_public_to_der(
    k: *const PcMlKem,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let der = match unsafe { &*k } {
            PcMlKem::K512(sk) => sk.encapsulation_key().to_spki_der(),
            PcMlKem::K768(sk) => sk.encapsulation_key().to_spki_der(),
            PcMlKem::K1024(sk) => sk.encapsulation_key().to_spki_der(),
        };
        unsafe { out_write(&der, out, out_len) }
    })
}

/// Encapsulates against an encapsulation key supplied as a PKIX SPKI DER,
/// writing the ciphertext to `ct` and the 32-byte shared secret to `ss`. The
/// EK is validated per FIPS 203 §7.2 (re-encoded round trip) before encaps,
/// surfacing as [`PcStatus::BadEncoding`] on failure (S16 audit fix).
///
/// # Safety
/// All pointers valid for their declared lengths; `ss` writable for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mlkem_encaps(
    set: i32,
    ek_spki: *const u8,
    ek_spki_len: usize,
    ct: *mut u8,
    ct_len: *mut usize,
    ss: *mut u8,
) -> PcStatus {
    guard(|| {
        let Some(spki) = (unsafe { slice(ek_spki, ek_spki_len) }) else {
            return PcStatus::NullPointer;
        };
        if ss.is_null() {
            return PcStatus::NullPointer;
        }
        // The C ABI contract is "PKIX SPKI DER". Earlier this branch
        // accepted PEM (UTF-8 BEGIN/END framing) instead, so a caller
        // passing raw DER got a `from_utf8` failure rather than a
        // successful encapsulation. Switch to the DER parser.
        let (ct_bytes, secret): (alloc::vec::Vec<u8>, [u8; 32]) = match set {
            set_id::ML_KEM_512 => {
                let k = match MlKem512EncapsKey::from_spki_der(spki) {
                    Ok(k) => k,
                    Err(_) => return PcStatus::BadEncoding,
                };
                let bytes = k.to_bytes();
                if MlKem512EncapsKey::from_bytes_validated(bytes).is_err() {
                    return PcStatus::BadEncoding;
                }
                let (c, s) = k.encapsulate(&mut OsRng);
                (c.to_bytes().to_vec(), s)
            }
            set_id::ML_KEM_768 => {
                let k = match MlKem768EncapsKey::from_spki_der(spki) {
                    Ok(k) => k,
                    Err(_) => return PcStatus::BadEncoding,
                };
                let bytes = k.to_bytes();
                if MlKem768EncapsKey::from_bytes_validated(bytes).is_err() {
                    return PcStatus::BadEncoding;
                }
                let (c, s) = k.encapsulate(&mut OsRng);
                (c.to_bytes().to_vec(), s)
            }
            set_id::ML_KEM_1024 => {
                let k = match MlKem1024EncapsKey::from_spki_der(spki) {
                    Ok(k) => k,
                    Err(_) => return PcStatus::BadEncoding,
                };
                let bytes = k.to_bytes();
                if MlKem1024EncapsKey::from_bytes_validated(bytes).is_err() {
                    return PcStatus::BadEncoding;
                }
                let (c, s) = k.encapsulate(&mut OsRng);
                (c.to_bytes().to_vec(), s)
            }
            _ => return PcStatus::Unsupported,
        };
        // Hold the shared-secret in a scoped binding so a later early-return
        // wipes it. Ciphertext is public, but the secret must not linger.
        let mut secret = secret;
        let st = unsafe { out_write(&ct_bytes, ct, ct_len) };
        if st != PcStatus::Ok {
            // `out_write` failed (e.g. BufferTooSmall) — wipe the shared
            // secret before propagating so the dropped array does not
            // return secret bytes to the allocator.
            wipe_array(&mut secret);
            return st;
        }
        unsafe { core::ptr::copy_nonoverlapping(secret.as_ptr(), ss, 32) };
        wipe_array(&mut secret);
        PcStatus::Ok
    })
}

/// Overwrites `buf` with zeros and routes the read through
/// `core::hint::black_box` so LLVM cannot eliminate the writes as dead
/// stores (same pattern as ML-DSA/ML-KEM in `src/mldsa/mod.rs` and
/// `src/mlkem/mod.rs`, avoiding a `zeroize` dep).
fn wipe_array(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(&buf);
}

/// Decapsulates `ct` under `k`, writing the 32-byte shared secret to `ss`.
/// On a bad ciphertext the library returns an implicit-rejection pseudo-random
/// secret (FIPS 203) — this function therefore always returns [`PcStatus::Ok`]
/// for well-formed inputs of the right size.
///
/// # Safety
/// All pointers valid for their declared lengths; `ss` writable for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mlkem_decaps(
    k: *const PcMlKem,
    ct: *const u8,
    ct_len: usize,
    ss: *mut u8,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(c) = (unsafe { slice(ct, ct_len) }) else {
            return PcStatus::NullPointer;
        };
        if ss.is_null() {
            return PcStatus::NullPointer;
        }
        let mut secret = match unsafe { &*k } {
            PcMlKem::K512(sk) => {
                let arr: [u8; 768] = match c.try_into() {
                    Ok(a) => a,
                    Err(_) => return PcStatus::BadEncoding,
                };
                sk.decapsulate(&MlKem512Ciphertext::from_bytes(arr))
            }
            PcMlKem::K768(sk) => {
                let arr: [u8; 1088] = match c.try_into() {
                    Ok(a) => a,
                    Err(_) => return PcStatus::BadEncoding,
                };
                sk.decapsulate(&MlKem768Ciphertext::from_bytes(arr))
            }
            PcMlKem::K1024(sk) => {
                let arr: [u8; 1568] = match c.try_into() {
                    Ok(a) => a,
                    Err(_) => return PcStatus::BadEncoding,
                };
                sk.decapsulate(&MlKem1024Ciphertext::from_bytes(arr))
            }
        };
        unsafe { core::ptr::copy_nonoverlapping(secret.as_ptr(), ss, 32) };
        // Wipe the local copy of the shared secret before its array is
        // returned to the stack frame / allocator. The caller already
        // holds an authoritative copy at `ss`.
        wipe_array(&mut secret);
        PcStatus::Ok
    })
}

/// Frees an ML-KEM key handle. NULL is ignored.
///
/// # Safety
/// `k` must come from a generator/`*_from_pem`, not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_mlkem_free(k: *mut PcMlKem) {
    if !k.is_null() {
        drop(unsafe { Box::from_raw(k) });
    }
}
