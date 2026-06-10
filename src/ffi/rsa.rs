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
        let key = match BoxedRsaPrivateKey::from_pkcs1_der(&der) {
            Ok(k) => k,
            Err(_) => {
                // `der` may still hold (partial) private material from a
                // garbled key; scrub before the allocation is recycled.
                let mut der = der;
                wipe_vec(&mut der);
                return None;
            }
        };
        Some(PcRsaKey { key, der })
    }
}

impl Drop for PcRsaKey {
    fn drop(&mut self) {
        // The retained PKCS#1 DER carries the CRT primes; don't hand it back
        // to the allocator un-scrubbed on pc_rsa_free.
        wipe_vec(&mut self.der);
    }
}

/// Returns a shared borrow of the inner Rust key. Used by sibling FFI
/// modules (notably `csr.rs`) that need to pass a `CertSigner::Rsa(_)` into
/// the library without re-decoding the PKCS#1 DER.
pub(super) fn pc_rsa_inner_key(handle: &PcRsaKey) -> &BoxedRsaPrivateKey {
    &handle.key
}

/// Generates an RSA private key of `bits` (2048, 3072, or 4096), or NULL.
#[unsafe(no_mangle)]
pub extern "C" fn pc_rsa_generate(bits: u32) -> *mut PcRsaKey {
    crate::ffi::common::guard_ptr(|| {
        let der =
            match bits {
                2048 => RsaPrivateKey::<32>::generate(Uint::from_u64(E), &mut OsRng, ROUNDS)
                    .to_pkcs1_der(),
                3072 => RsaPrivateKey::<48>::generate(Uint::from_u64(E), &mut OsRng, ROUNDS)
                    .to_pkcs1_der(),
                4096 => RsaPrivateKey::<64>::generate(Uint::from_u64(E), &mut OsRng, ROUNDS)
                    .to_pkcs1_der(),
                _ => return core::ptr::null_mut(),
            };
        match PcRsaKey::from_pkcs1_der(der) {
            Some(k) => Box::into_raw(Box::new(k)),
            None => core::ptr::null_mut(),
        }
    })
}

/// Parses a PKCS#1 `RSA PRIVATE KEY` PEM into a key handle, or NULL on failure.
///
/// # Safety
/// `pem` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rsa_from_pem(pem: *const u8, len: usize) -> *mut PcRsaKey {
    crate::ffi::common::guard_ptr(|| {
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
    })
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
        // The PEM is a re-encoding of the private key; wipe the temporary
        // before its backing storage returns to the allocator.
        let mut pem = pem_encode(PEM_LABEL, &unsafe { &*key }.der).into_bytes();
        let st = unsafe { out_write(&pem, out, out_len) };
        wipe_vec(&mut pem);
        st
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

/// Signs `msg` with RSA-PSS using `alg` as the digest and the MGF1 hash,
/// writing the signature to `out`. Salt length defaults to the hash output.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rsa_sign_pss(
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
        let mut rng = crate::rng::OsRng;
        let sig = match alg {
            id::SHA256 => k.sign_pss::<Sha256, _>(m, &mut rng),
            id::SHA384 => k.sign_pss::<Sha384, _>(m, &mut rng),
            id::SHA512 => k.sign_pss::<Sha512, _>(m, &mut rng),
            _ => return PcStatus::Unsupported,
        };
        match sig {
            Ok(s) => unsafe { out_write(&s, out, out_len) },
            Err(_) => PcStatus::Internal,
        }
    })
}

/// Verifies an RSA-PSS signature `sig` over `msg` under the SPKI DER in
/// `spki`. Returns [`PcStatus::Ok`] iff valid.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rsa_verify_pss(
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
            id::SHA256 => key.verify_pss::<Sha256>(m, sig),
            id::SHA384 => key.verify_pss::<Sha384>(m, sig),
            id::SHA512 => key.verify_pss::<Sha512>(m, sig),
            _ => return PcStatus::Unsupported,
        };
        if ok.is_ok() {
            PcStatus::Ok
        } else {
            PcStatus::Verification
        }
    })
}

/// Encrypts `pt` with RSA-OAEP under the public key in `spki`, with the
/// specified hash (SHA-256/384/512) for both the EME and the MGF1, and the
/// caller-supplied `label` (may be empty). Writes the ciphertext to `out`.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rsa_encrypt_oaep(
    spki: *const u8,
    spki_len: usize,
    hash: i32,
    label: *const u8,
    label_len: usize,
    pt: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        let (Some(spki), Some(lbl), Some(pt)) = (
            unsafe { slice(spki, spki_len) },
            unsafe { slice(label, label_len) },
            unsafe { slice(pt, pt_len) },
        ) else {
            return PcStatus::NullPointer;
        };
        let key = match AnyPublicKey::from_spki_der(spki) {
            Ok(AnyPublicKey::Rsa(k)) => k,
            Ok(_) => return PcStatus::Unsupported,
            Err(_) => return PcStatus::BadEncoding,
        };
        let mut rng = crate::rng::OsRng;
        let ct = match hash {
            id::SHA256 => key.encrypt_oaep::<Sha256, _>(pt, lbl, &mut rng),
            id::SHA384 => key.encrypt_oaep::<Sha384, _>(pt, lbl, &mut rng),
            id::SHA512 => key.encrypt_oaep::<Sha512, _>(pt, lbl, &mut rng),
            _ => return PcStatus::Unsupported,
        };
        match ct {
            Ok(c) => unsafe { out_write(&c, out, out_len) },
            Err(_) => PcStatus::Internal,
        }
    })
}

/// Decrypts an RSA-OAEP ciphertext under `key`. Constant-time on
/// decryption-error paths (the library returns the same error variant for
/// any malformed ciphertext).
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rsa_decrypt_oaep(
    key: *const PcRsaKey,
    hash: i32,
    label: *const u8,
    label_len: usize,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if key.is_null() {
            return PcStatus::NullPointer;
        }
        let (Some(lbl), Some(c)) = (unsafe { slice(label, label_len) }, unsafe {
            slice(ct, ct_len)
        }) else {
            return PcStatus::NullPointer;
        };
        let k = &unsafe { &*key }.key;
        let pt = match hash {
            id::SHA256 => k.decrypt_oaep::<Sha256>(c, lbl),
            id::SHA384 => k.decrypt_oaep::<Sha384>(c, lbl),
            id::SHA512 => k.decrypt_oaep::<Sha512>(c, lbl),
            _ => return PcStatus::Unsupported,
        };
        match pt {
            Ok(mut p) => {
                let st = unsafe { out_write(&p, out, out_len) };
                // The plaintext Vec is dropped here; wipe it first so the
                // bytes don't sit in a free-list chunk for the next
                // allocation to observe. `out_write` failures (e.g.
                // BufferTooSmall) follow the same path — the caller did
                // not get the plaintext, but we still scrub.
                wipe_vec(&mut p);
                st
            }
            Err(_) => PcStatus::Verification,
        }
    })
}

/// Overwrites `buf` with zeros and routes the read through
/// `core::hint::black_box` so LLVM cannot eliminate the writes as dead
/// stores. Used to scrub plaintext / shared-secret intermediates before
/// their backing storage is returned to the allocator (same in-house
/// pattern used by ML-DSA/ML-KEM in `src/mldsa/mod.rs` and
/// `src/mlkem/mod.rs`).
fn wipe_vec(buf: &mut Vec<u8>) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(&buf);
}
