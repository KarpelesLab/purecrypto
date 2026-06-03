//! C ABI for SM2 (GB/T 32918 / RFC 8998): keygen, SM2-DSA sign/verify, and
//! SM2 hybrid PKE encrypt/decrypt.
//!
//! SM2 is deliberately NOT routed through the generic ECDSA `pc_ec_*` entry
//! points (which reject the SM2 curve); these dedicated handles use the SM2
//! signature scheme (with the `Z_A` identity) and the SM2 public-key
//! encryption scheme.

use alloc::boxed::Box;

use super::common::{PcStatus, guard, out_write, slice, wipe_vec};
use crate::ec::sm2::{DEFAULT_ID, Sm2PrivateKey, Sm2PublicKey, Sm2Signature};
use crate::rng::OsRng;

/// An opaque SM2 private key (`sm2p256v1`). Holds the secret scalar; the public
/// point is derived on demand.
pub struct PcSm2(Box<Sm2PrivateKey>);

/// Borrows the signer identity from `(id, id_len)`, or the standard default
/// `1234567812345678` when `id` is NULL / `id_len` is 0.
///
/// # Safety
/// `id` must be valid for `id_len` bytes (or NULL with `id_len == 0`).
unsafe fn id_or_default<'a>(id: *const u8, id_len: usize) -> Option<&'a [u8]> {
    if id.is_null() && id_len == 0 {
        return Some(DEFAULT_ID);
    }
    unsafe { slice(id, id_len) }
}

/// Generates a fresh SM2 signing key.
#[unsafe(no_mangle)]
pub extern "C" fn pc_sm2_generate() -> *mut PcSm2 {
    crate::ffi::common::guard_ptr(|| {
        let sk = Sm2PrivateKey::generate(&mut OsRng);
        Box::into_raw(Box::new(PcSm2(Box::new(sk))))
    })
}

/// Parses an SM2 SEC1 (`EC PRIVATE KEY`) PEM private key.
///
/// # Safety
/// `pem` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_sm2_from_pem(pem: *const u8, len: usize) -> *mut PcSm2 {
    crate::ffi::common::guard_ptr(|| {
        let Some(bytes) = (unsafe { slice(pem, len) }) else {
            return core::ptr::null_mut();
        };
        let Ok(s) = core::str::from_utf8(bytes) else {
            return core::ptr::null_mut();
        };
        match Sm2PrivateKey::from_sec1_pem(s) {
            Ok(k) => Box::into_raw(Box::new(PcSm2(Box::new(k)))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Writes the SEC1 (`EC PRIVATE KEY`) PEM for the private key.
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_sm2_private_to_pem(
    k: *const PcSm2,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = unsafe { &*k }.0.to_sec1_pem();
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// Writes the PKIX SPKI (`PUBLIC KEY`) PEM for the public key.
///
/// # Safety
/// `k` valid; buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_sm2_public_to_pem(
    k: *const PcSm2,
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

/// SM2-DSA sign: signs `msg` under identity `id` (NULL / 0 selects the default
/// `1234567812345678`), writing the DER `Ecdsa-Sig-Value` signature to `out`.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_sm2_sign(
    k: *const PcSm2,
    id: *const u8,
    id_len: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let (Some(id), Some(m)) = (unsafe { id_or_default(id, id_len) }, unsafe {
            slice(msg, msg_len)
        }) else {
            return PcStatus::NullPointer;
        };
        let sig = match unsafe { &*k }.0.sign(m, id, &mut OsRng) {
            Ok(s) => s,
            Err(_) => return PcStatus::Internal,
        };
        unsafe { out_write(&sig.to_der(), out, out_len) }
    })
}

/// SM2-DSA verify: checks the DER `Ecdsa-Sig-Value` `sig` over `msg` under the
/// SPKI DER public key in `spki` and identity `id` (NULL / 0 = default).
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_sm2_verify(
    spki: *const u8,
    spki_len: usize,
    id: *const u8,
    id_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> PcStatus {
    guard(|| {
        let (Some(spki), Some(id), Some(m), Some(sig)) = (
            unsafe { slice(spki, spki_len) },
            unsafe { id_or_default(id, id_len) },
            unsafe { slice(msg, msg_len) },
            unsafe { slice(sig, sig_len) },
        ) else {
            return PcStatus::NullPointer;
        };
        let pk = match Sm2PublicKey::from_spki_der(spki) {
            Ok(k) => k,
            Err(_) => return PcStatus::BadEncoding,
        };
        let parsed = match Sm2Signature::from_der(sig) {
            Ok(s) => s,
            Err(_) => return PcStatus::BadEncoding,
        };
        match pk.verify(m, &parsed, id) {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::Verification,
        }
    })
}

/// SM2 PKE encrypt: encrypts `pt` to the SPKI DER public key in `spki`,
/// writing the `C1 ‖ C3 ‖ C2` ciphertext to `out`.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_sm2_encrypt(
    spki: *const u8,
    spki_len: usize,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        let (Some(spki), Some(p)) = (unsafe { slice(spki, spki_len) }, unsafe {
            slice(pt, pt_len)
        }) else {
            return PcStatus::NullPointer;
        };
        let pk = match Sm2PublicKey::from_spki_der(spki) {
            Ok(k) => k,
            Err(_) => return PcStatus::BadEncoding,
        };
        let ct = match pk.encrypt(p, &mut OsRng) {
            Ok(c) => c,
            Err(_) => return PcStatus::Internal,
        };
        unsafe { out_write(&ct, out, out_len) }
    })
}

/// SM2 PKE decrypt: decrypts a `C1 ‖ C3 ‖ C2` ciphertext with the private key,
/// writing the recovered plaintext to `out`.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_sm2_decrypt(
    k: *const PcSm2,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if k.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(c) = (unsafe { slice(ct, ct_len) }) else {
            return PcStatus::NullPointer;
        };
        let mut pt = match unsafe { &*k }.0.decrypt(c) {
            Ok(p) => p,
            Err(_) => return PcStatus::Verification,
        };
        // Capture the status, then wipe the recovered plaintext before its Vec
        // is dropped so the bytes don't linger in a freed allocation. The
        // `out_write` failure path (e.g. BufferTooSmall) scrubs too. Mirrors
        // `pc_rsa_decrypt_oaep`.
        let st = unsafe { out_write(&pt, out, out_len) };
        wipe_vec(&mut pt);
        st
    })
}

/// Frees an SM2 key handle. NULL is ignored.
///
/// # Safety
/// `k` from `pc_sm2_generate` / `pc_sm2_from_pem`, not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_sm2_free(k: *mut PcSm2) {
    if !k.is_null() {
        drop(unsafe { Box::from_raw(k) });
    }
}
