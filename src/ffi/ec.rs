//! C ABI for ECDSA key generation, signing, verification, and PEM I/O.

use alloc::boxed::Box;

use super::common::{PcStatus, guard, out_write, slice};
use crate::ec::{
    BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, BoxedEcdsaSignature, CurveId,
    Ed25519PrivateKey, Ed25519Signature,
};
use crate::hash::{Sha256, Sha384, Sha512};
use crate::rng::OsRng;
use crate::x509::AnyPublicKey;

/// Curve identifiers (mirror `PcCurve` in `purecrypto.h`).
pub mod curve {
    #![allow(missing_docs)]
    pub const P256: i32 = 1;
    pub const P384: i32 = 2;
    pub const P521: i32 = 3;
    pub const SECP256K1: i32 = 4;
}

fn curve_from_id(id: i32) -> Option<CurveId> {
    Some(match id {
        curve::P256 => CurveId::P256,
        curve::P384 => CurveId::P384,
        curve::P521 => CurveId::P521,
        curve::SECP256K1 => CurveId::Secp256k1,
        _ => return None,
    })
}

/// An opaque ECDSA private key.
pub struct PcEcKey(BoxedEcdsaPrivateKey);

/// Returns a shared borrow of the inner Rust key. Used by sibling FFI
/// modules (notably `x509.rs::pc_ec_self_signed_pem`).
pub(super) fn pc_ec_inner_key(handle: &PcEcKey) -> &BoxedEcdsaPrivateKey {
    &handle.0
}

/// Generates an ECDSA key on `curve` (see `PcCurve`), or NULL on failure.
#[unsafe(no_mangle)]
pub extern "C" fn pc_ec_generate(curve_id: i32) -> *mut PcEcKey {
    crate::ffi::common::guard_ptr(|| {
        let Some(curve) = curve_from_id(curve_id) else {
            return core::ptr::null_mut();
        };
        let key = BoxedEcdsaPrivateKey::generate(curve, &mut OsRng);
        Box::into_raw(Box::new(PcEcKey(key)))
    })
}

/// Parses a SEC1 `EC PRIVATE KEY` PEM into a key handle, or NULL on failure.
///
/// # Safety
/// `pem` must be valid UTF-8 for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ec_from_pem(pem: *const u8, len: usize) -> *mut PcEcKey {
    crate::ffi::common::guard_ptr(|| {
        let Some(bytes) = (unsafe { slice(pem, len) }) else {
            return core::ptr::null_mut();
        };
        let Ok(s) = core::str::from_utf8(bytes) else {
            return core::ptr::null_mut();
        };
        match BoxedEcdsaPrivateKey::from_sec1_pem(s) {
            Ok(k) => Box::into_raw(Box::new(PcEcKey(k))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Writes the key as a SEC1 `EC PRIVATE KEY` PEM string to `out`.
///
/// # Safety
/// `key` from [`pc_ec_generate`]/[`pc_ec_from_pem`]; buffer rules for `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ec_private_to_pem(
    key: *const PcEcKey,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if key.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = unsafe { &*key }.0.to_sec1_pem();
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// Writes the public key as a PKIX `PUBLIC KEY` (SPKI) PEM string to `out`.
///
/// # Safety
/// `key` valid; buffer rules for `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ec_public_to_pem(
    key: *const PcEcKey,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if key.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = AnyPublicKey::Ecdsa(unsafe { &*key }.0.public_key()).to_spki_pem();
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// Signs `msg` with `key`, writing a DER `Ecdsa-Sig-Value` to `out`. The digest
/// is chosen by the curve (P-256/secp256k1 → SHA-256, P-384 → SHA-384, P-521 →
/// SHA-512).
///
/// # Safety
/// `key` valid; `msg` valid for `msg_len`; buffer rules for `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ec_sign(
    key: *const PcEcKey,
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
        let sk = &unsafe { &*key }.0;
        let curve = sk.curve();
        let sig = match curve {
            CurveId::P256 | CurveId::Secp256k1 => sk.sign::<Sha256>(m),
            CurveId::P384 => sk.sign::<Sha384>(m),
            CurveId::P521 => sk.sign::<Sha512>(m),
        };
        match sig {
            Ok(s) => unsafe { out_write(&s.to_der(curve), out, out_len) },
            Err(_) => PcStatus::Internal,
        }
    })
}

/// Verifies a DER `Ecdsa-Sig-Value` `sig` over `msg` under the SPKI (PKIX
/// `PUBLIC KEY`) DER in `spki`. Returns [`PcStatus::Ok`] iff valid.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ec_verify(
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
        let key = match AnyPublicKey::from_spki_der(spki) {
            Ok(AnyPublicKey::Ecdsa(k)) => k,
            Ok(_) => return PcStatus::Unsupported,
            Err(_) => return PcStatus::BadEncoding,
        };
        let parsed = match BoxedEcdsaSignature::from_der(sig) {
            Ok(s) => s,
            Err(_) => return PcStatus::BadEncoding,
        };
        let ok = match key.curve() {
            CurveId::P256 | CurveId::Secp256k1 => key.verify::<Sha256>(m, &parsed),
            CurveId::P384 => key.verify::<Sha384>(m, &parsed),
            CurveId::P521 => key.verify::<Sha512>(m, &parsed),
        };
        if ok.is_ok() {
            PcStatus::Ok
        } else {
            PcStatus::Verification
        }
    })
}

/// Frees an ECDSA key. NULL is ignored.
///
/// # Safety
/// `key` from [`pc_ec_generate`]/[`pc_ec_from_pem`], not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ec_free(key: *mut PcEcKey) {
    if !key.is_null() {
        drop(unsafe { Box::from_raw(key) });
    }
}

/// An opaque Ed25519 private key.
pub struct PcEd25519Key(Ed25519PrivateKey);

/// Generates an Ed25519 key, or NULL on failure.
#[unsafe(no_mangle)]
pub extern "C" fn pc_ed25519_generate() -> *mut PcEd25519Key {
    crate::ffi::common::guard_ptr(|| {
        Box::into_raw(Box::new(PcEd25519Key(Ed25519PrivateKey::generate(
            &mut OsRng,
        ))))
    })
}

/// Parses a PKCS#8 `PRIVATE KEY` PEM into an Ed25519 key handle, or NULL.
///
/// # Safety
/// `pem` must be valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ed25519_from_pem(pem: *const u8, len: usize) -> *mut PcEd25519Key {
    crate::ffi::common::guard_ptr(|| {
        let Some(bytes) = (unsafe { slice(pem, len) }) else {
            return core::ptr::null_mut();
        };
        let Ok(s) = core::str::from_utf8(bytes) else {
            return core::ptr::null_mut();
        };
        match Ed25519PrivateKey::from_pkcs8_pem(s) {
            Ok(k) => Box::into_raw(Box::new(PcEd25519Key(k))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Writes the key as a PKCS#8 `PRIVATE KEY` PEM string to `out`.
///
/// # Safety
/// `key` valid; buffer rules for `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ed25519_private_to_pem(
    key: *const PcEd25519Key,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if key.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = unsafe { &*key }.0.to_pkcs8_pem();
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// Writes the public key as a PKIX `PUBLIC KEY` (SPKI) PEM string to `out`.
///
/// # Safety
/// `key` valid; buffer rules for `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ed25519_public_to_pem(
    key: *const PcEd25519Key,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if key.is_null() {
            return PcStatus::NullPointer;
        }
        let pem = AnyPublicKey::Ed25519(unsafe { &*key }.0.public_key()).to_spki_pem();
        unsafe { out_write(pem.as_bytes(), out, out_len) }
    })
}

/// Signs `msg` with `key`, writing the raw 64-byte Ed25519 signature to `out`.
///
/// # Safety
/// `key` valid; `msg` valid for `msg_len`; buffer rules for `out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ed25519_sign(
    key: *const PcEd25519Key,
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
        let sig = unsafe { &*key }.0.sign(m);
        unsafe { out_write(&sig.to_bytes(), out, out_len) }
    })
}

/// Verifies a raw 64-byte Ed25519 signature `sig` over `msg` under the SPKI
/// (PKIX `PUBLIC KEY`) DER in `spki`. Returns [`PcStatus::Ok`] iff valid.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ed25519_verify(
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
        let key = match AnyPublicKey::from_spki_der(spki) {
            Ok(AnyPublicKey::Ed25519(k)) => k,
            Ok(_) => return PcStatus::Unsupported,
            Err(_) => return PcStatus::BadEncoding,
        };
        let Ok(bytes) = <[u8; 64]>::try_from(sig) else {
            return PcStatus::BadEncoding;
        };
        if key.verify(m, &Ed25519Signature::from_bytes(bytes)).is_ok() {
            PcStatus::Ok
        } else {
            PcStatus::Verification
        }
    })
}

/// Frees an Ed25519 key. NULL is ignored.
///
/// # Safety
/// `key` from [`pc_ed25519_generate`]/[`pc_ed25519_from_pem`], not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ed25519_free(key: *mut PcEd25519Key) {
    if !key.is_null() {
        drop(unsafe { Box::from_raw(key) });
    }
}

/// Derives an ECDH shared secret using the SEC1-encoded private scalar `priv_be`
/// (big-endian, `field_len(curve)` bytes) and the peer's SPKI DER. Writes the
/// raw shared secret (the affine x-coordinate, `field_len` bytes) to `out`.
///
/// # Safety
/// All pointers valid for their declared lengths; `out_len` non-NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ecdh(
    curve_id: i32,
    priv_be: *const u8,
    priv_len: usize,
    peer_spki: *const u8,
    peer_spki_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        let Some(curve) = curve_from_id(curve_id) else {
            return PcStatus::Unsupported;
        };
        let (Some(d), Some(spki)) = (unsafe { slice(priv_be, priv_len) }, unsafe {
            slice(peer_spki, peer_spki_len)
        }) else {
            return PcStatus::NullPointer;
        };
        let sk = match BoxedEcdhPrivateKey::from_bytes(curve, d) {
            Ok(s) => s,
            Err(_) => return PcStatus::BadEncoding,
        };
        let peer: BoxedEcdsaPublicKey = match AnyPublicKey::from_spki_der(spki) {
            Ok(AnyPublicKey::Ecdsa(k)) if k.curve() == curve => k,
            Ok(AnyPublicKey::Ecdsa(_)) => return PcStatus::Unsupported,
            Ok(_) => return PcStatus::Unsupported,
            Err(_) => return PcStatus::BadEncoding,
        };
        match sk.diffie_hellman(&peer) {
            Ok(secret) => unsafe { out_write(&secret, out, out_len) },
            Err(_) => PcStatus::Verification,
        }
    })
}
