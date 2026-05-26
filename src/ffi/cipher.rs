//! C ABI for AEAD ciphers (AES-GCM, AES-CCM, ChaCha20-Poly1305) and AES key
//! wrapping (RFC 3394 / 5649).

use alloc::vec;
use alloc::vec::Vec;

use super::common::{PcStatus, guard, out_write, slice};
use crate::cipher::{
    Aes128, Aes128Ccm, Aes128Ccm8, Aes128Gcm, Aes128Kw, Aes128Kwp, Aes256, Aes256Ccm, Aes256Ccm8,
    Aes256Gcm, Aes256Kw, Aes256Kwp, ChaCha20Poly1305,
};

/// AEAD algorithm identifiers (mirror `PcAead` in `purecrypto.h`).
pub mod aead_id {
    #![allow(missing_docs)]
    pub const AES128_GCM: i32 = 1;
    pub const AES256_GCM: i32 = 2;
    pub const CHACHA20_POLY1305: i32 = 3;
    pub const AES128_CCM: i32 = 4;
    pub const AES256_CCM: i32 = 5;
    pub const AES128_CCM8: i32 = 6;
    pub const AES256_CCM8: i32 = 7;
}

fn aead_key_size(alg: i32) -> Option<usize> {
    Some(match alg {
        aead_id::AES128_GCM | aead_id::AES128_CCM | aead_id::AES128_CCM8 => 16,
        aead_id::AES256_GCM
        | aead_id::CHACHA20_POLY1305
        | aead_id::AES256_CCM
        | aead_id::AES256_CCM8 => 32,
        _ => return None,
    })
}

fn aead_tag_size(alg: i32) -> usize {
    match alg {
        aead_id::AES128_CCM8 | aead_id::AES256_CCM8 => 8,
        _ => 16,
    }
}

/// One-shot AEAD encrypt. `pt` and `ct_and_tag` MUST NOT overlap. On success,
/// `*ct_and_tag_len` is set to `pt_len + tag_size`.
///
/// # Safety
/// All pointers must be valid for their declared lengths; `ct_and_tag_len`
/// non-NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_aead_encrypt(
    alg: i32,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    pt: *const u8,
    pt_len: usize,
    ct_and_tag: *mut u8,
    ct_and_tag_len: *mut usize,
) -> PcStatus {
    guard(|| {
        let Some(expected_key) = aead_key_size(alg) else {
            return PcStatus::Unsupported;
        };
        let (Some(k), Some(n), Some(a), Some(p)) = (
            unsafe { slice(key, key_len) },
            unsafe { slice(nonce, nonce_len) },
            unsafe { slice(aad, aad_len) },
            unsafe { slice(pt, pt_len) },
        ) else {
            return PcStatus::NullPointer;
        };
        if k.len() != expected_key {
            return PcStatus::Unsupported;
        }
        let tag_size = aead_tag_size(alg);
        let mut buf: Vec<u8> = p.to_vec();
        let tag: Vec<u8> = match alg {
            aead_id::AES128_GCM => {
                let key: [u8; 16] = k.try_into().unwrap();
                Aes128Gcm::new(Aes128::new(&key))
                    .encrypt(n, a, &mut buf)
                    .to_vec()
            }
            aead_id::AES256_GCM => {
                let key: [u8; 32] = k.try_into().unwrap();
                Aes256Gcm::new(Aes256::new(&key))
                    .encrypt(n, a, &mut buf)
                    .to_vec()
            }
            aead_id::CHACHA20_POLY1305 => {
                let key: [u8; 32] = k.try_into().unwrap();
                let nonce: [u8; 12] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                ChaCha20Poly1305::new(&key)
                    .encrypt(&nonce, a, &mut buf)
                    .to_vec()
            }
            aead_id::AES128_CCM => {
                let key: [u8; 16] = k.try_into().unwrap();
                Aes128Ccm::new(Aes128::new(&key))
                    .encrypt(n, a, &mut buf)
                    .to_vec()
            }
            aead_id::AES256_CCM => {
                let key: [u8; 32] = k.try_into().unwrap();
                Aes256Ccm::new(Aes256::new(&key))
                    .encrypt(n, a, &mut buf)
                    .to_vec()
            }
            aead_id::AES128_CCM8 => {
                let key: [u8; 16] = k.try_into().unwrap();
                Aes128Ccm8::new(Aes128::new(&key))
                    .encrypt(n, a, &mut buf)
                    .to_vec()
            }
            aead_id::AES256_CCM8 => {
                let key: [u8; 32] = k.try_into().unwrap();
                Aes256Ccm8::new(Aes256::new(&key))
                    .encrypt(n, a, &mut buf)
                    .to_vec()
            }
            _ => return PcStatus::Unsupported,
        };
        debug_assert_eq!(tag.len(), tag_size);
        buf.extend_from_slice(&tag);
        unsafe { out_write(&buf, ct_and_tag, ct_and_tag_len) }
    })
}

/// One-shot AEAD decrypt with tag verification. On success, `*pt_len` is set
/// to `ct_and_tag_len - tag_size`. On tag mismatch, returns
/// [`PcStatus::Verification`] and the buffer contents are unspecified (CCM
/// wipes; GCM/ChaCha20-Poly1305 leave them).
///
/// # Safety
/// All pointers must be valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_aead_decrypt(
    alg: i32,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ct_and_tag: *const u8,
    ct_and_tag_len: usize,
    pt: *mut u8,
    pt_len: *mut usize,
) -> PcStatus {
    guard(|| {
        let Some(expected_key) = aead_key_size(alg) else {
            return PcStatus::Unsupported;
        };
        let (Some(k), Some(n), Some(a), Some(blob)) = (
            unsafe { slice(key, key_len) },
            unsafe { slice(nonce, nonce_len) },
            unsafe { slice(aad, aad_len) },
            unsafe { slice(ct_and_tag, ct_and_tag_len) },
        ) else {
            return PcStatus::NullPointer;
        };
        if k.len() != expected_key {
            return PcStatus::Unsupported;
        }
        let tag_size = aead_tag_size(alg);
        if blob.len() < tag_size {
            return PcStatus::BadEncoding;
        }
        let (ct, tag) = blob.split_at(blob.len() - tag_size);
        let mut buf: Vec<u8> = ct.to_vec();
        let ok = match alg {
            aead_id::AES128_GCM => {
                let key: [u8; 16] = k.try_into().unwrap();
                let t: [u8; 16] = tag.try_into().unwrap();
                Aes128Gcm::new(Aes128::new(&key))
                    .decrypt(n, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AES256_GCM => {
                let key: [u8; 32] = k.try_into().unwrap();
                let t: [u8; 16] = tag.try_into().unwrap();
                Aes256Gcm::new(Aes256::new(&key))
                    .decrypt(n, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::CHACHA20_POLY1305 => {
                let key: [u8; 32] = k.try_into().unwrap();
                let nonce: [u8; 12] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                let t: [u8; 16] = tag.try_into().unwrap();
                ChaCha20Poly1305::new(&key)
                    .decrypt(&nonce, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AES128_CCM => {
                let key: [u8; 16] = k.try_into().unwrap();
                let t: [u8; 16] = tag.try_into().unwrap();
                Aes128Ccm::new(Aes128::new(&key))
                    .decrypt(n, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AES256_CCM => {
                let key: [u8; 32] = k.try_into().unwrap();
                let t: [u8; 16] = tag.try_into().unwrap();
                Aes256Ccm::new(Aes256::new(&key))
                    .decrypt(n, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AES128_CCM8 => {
                let key: [u8; 16] = k.try_into().unwrap();
                let t: [u8; 8] = tag.try_into().unwrap();
                Aes128Ccm8::new(Aes128::new(&key))
                    .decrypt(n, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AES256_CCM8 => {
                let key: [u8; 32] = k.try_into().unwrap();
                let t: [u8; 8] = tag.try_into().unwrap();
                Aes256Ccm8::new(Aes256::new(&key))
                    .decrypt(n, a, &mut buf, &t)
                    .is_ok()
            }
            _ => return PcStatus::Unsupported,
        };
        if !ok {
            return PcStatus::Verification;
        }
        unsafe { out_write(&buf, pt, pt_len) }
    })
}

/// AES key wrap (RFC 3394). `key_len` must be a multiple of 8 and ≥ 16.
/// `kek_len` selects AES-128/192/256 KW; only AES-128 and AES-256 are exposed
/// via the FFI.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_aes_kw_wrap(
    kek: *const u8,
    kek_len: usize,
    key: *const u8,
    key_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        let (Some(k), Some(pt)) = (unsafe { slice(kek, kek_len) }, unsafe {
            slice(key, key_len)
        }) else {
            return PcStatus::NullPointer;
        };
        let mut wrapped = vec![0u8; pt.len() + 8];
        let res = match k.len() {
            16 => {
                let kk: [u8; 16] = k.try_into().unwrap();
                Aes128Kw::new(Aes128::new(&kk)).wrap(pt, &mut wrapped)
            }
            32 => {
                let kk: [u8; 32] = k.try_into().unwrap();
                Aes256Kw::new(Aes256::new(&kk)).wrap(pt, &mut wrapped)
            }
            _ => return PcStatus::Unsupported,
        };
        if res.is_err() {
            return PcStatus::BadEncoding;
        }
        unsafe { out_write(&wrapped, out, out_len) }
    })
}

/// AES key unwrap (RFC 3394). Verifies the integrity IV.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_aes_kw_unwrap(
    kek: *const u8,
    kek_len: usize,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        let (Some(k), Some(c)) = (unsafe { slice(kek, kek_len) }, unsafe { slice(ct, ct_len) })
        else {
            return PcStatus::NullPointer;
        };
        if c.len() < 24 {
            return PcStatus::BadEncoding;
        }
        let mut plain = vec![0u8; c.len() - 8];
        let res = match k.len() {
            16 => {
                let kk: [u8; 16] = k.try_into().unwrap();
                Aes128Kw::new(Aes128::new(&kk)).unwrap(c, &mut plain)
            }
            32 => {
                let kk: [u8; 32] = k.try_into().unwrap();
                Aes256Kw::new(Aes256::new(&kk)).unwrap(c, &mut plain)
            }
            _ => return PcStatus::Unsupported,
        };
        if res.is_err() {
            return PcStatus::Verification;
        }
        unsafe { out_write(&plain, out, out_len) }
    })
}

/// AES key wrap with padding (RFC 5649).
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_aes_kwp_wrap(
    kek: *const u8,
    kek_len: usize,
    key: *const u8,
    key_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        let (Some(k), Some(pt)) = (unsafe { slice(kek, kek_len) }, unsafe {
            slice(key, key_len)
        }) else {
            return PcStatus::NullPointer;
        };
        let padded = pt.len().div_ceil(8) * 8;
        let mut wrapped = vec![0u8; padded + 8];
        let res = match k.len() {
            16 => {
                let kk: [u8; 16] = k.try_into().unwrap();
                Aes128Kwp::new(Aes128::new(&kk)).wrap(pt, &mut wrapped)
            }
            32 => {
                let kk: [u8; 32] = k.try_into().unwrap();
                Aes256Kwp::new(Aes256::new(&kk)).wrap(pt, &mut wrapped)
            }
            _ => return PcStatus::Unsupported,
        };
        if res.is_err() {
            return PcStatus::BadEncoding;
        }
        unsafe { out_write(&wrapped, out, out_len) }
    })
}

/// AES key unwrap with padding (RFC 5649). Recovers the original plaintext
/// length from the embedded AIV.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_aes_kwp_unwrap(
    kek: *const u8,
    kek_len: usize,
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        let (Some(k), Some(c)) = (unsafe { slice(kek, kek_len) }, unsafe { slice(ct, ct_len) })
        else {
            return PcStatus::NullPointer;
        };
        if c.len() < 16 {
            return PcStatus::BadEncoding;
        }
        let mut plain = vec![0u8; c.len() - 8];
        let n = match k.len() {
            16 => {
                let kk: [u8; 16] = k.try_into().unwrap();
                Aes128Kwp::new(Aes128::new(&kk)).unwrap(c, &mut plain)
            }
            32 => {
                let kk: [u8; 32] = k.try_into().unwrap();
                Aes256Kwp::new(Aes256::new(&kk)).unwrap(c, &mut plain)
            }
            _ => return PcStatus::Unsupported,
        };
        let n = match n {
            Ok(n) => n,
            Err(_) => return PcStatus::Verification,
        };
        plain.truncate(n);
        unsafe { out_write(&plain, out, out_len) }
    })
}
