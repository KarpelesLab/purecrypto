//! C ABI for AEAD ciphers (AES-GCM, AES-CCM, ChaCha20-Poly1305) and AES key
//! wrapping (RFC 3394 / 5649).

use alloc::vec;
use alloc::vec::Vec;

use super::common::{PcStatus, guard, out_write, slice, wipe_vec};
use crate::ascon::AsconAead128;
use crate::cipher::{
    Aegis128L, Aegis256, Aes128, Aes128Ccm, Aes128Ccm8, Aes128Gcm, Aes128Kw, Aes128Kwp, Aes256,
    Aes256Ccm, Aes256Ccm8, Aes256Gcm, Aes256Kw, Aes256Kwp, AesCmac128, AesCmac256, AesGcmSiv,
    AesGmac128, AesGmac256, AesSiv, ChaCha20Poly1305, XChaCha20Poly1305,
};

/// Owns a stack copy of secret key bytes and scrubs them on drop. Each
/// one-shot AEAD / key-wrap / MAC arm copies the caller's key slice into a
/// fixed-size array to satisfy the cipher constructors' `&[u8; N]` signature;
/// the cipher keeps its own expanded schedule, so this copy is redundant once
/// constructed and must not linger in the frame. `Drop` zeroizes it behind a
/// `black_box` barrier on every exit path (including the mid-arm nonce/tag
/// `try_into` early returns), so no `key`/`kk` copy survives the call.
struct KeyBuf<const N: usize>([u8; N]);

impl<const N: usize> KeyBuf<N> {
    /// Borrows the key bytes for a cipher constructor.
    #[inline]
    fn r(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Drop for KeyBuf<N> {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(&self.0);
    }
}

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
    pub const AES128_GCM_SIV: i32 = 8;
    pub const AES256_GCM_SIV: i32 = 9;
    pub const XCHACHA20_POLY1305: i32 = 10;
    /// AES-128-SIV (RFC 5297). Single-AD form: the `nonce` argument is passed
    /// as the (one) associated-data header; the output is `V ‖ ciphertext`.
    pub const AES128_SIV: i32 = 11;
    /// AES-256-SIV (RFC 5297), 64-byte key, single-AD form.
    pub const AES256_SIV: i32 = 12;
    /// AEGIS-128L (draft-irtf-cfrg-aegis-aead). 16-byte key, 16-byte nonce.
    pub const AEGIS128L: i32 = 13;
    /// AEGIS-256 (draft-irtf-cfrg-aegis-aead). 32-byte key, 32-byte nonce.
    pub const AEGIS256: i32 = 14;
    /// Ascon-AEAD128 (NIST SP 800-232). 16-byte key, 16-byte nonce.
    pub const ASCON_AEAD128: i32 = 15;
}

fn aead_key_size(alg: i32) -> Option<usize> {
    Some(match alg {
        aead_id::AES128_GCM
        | aead_id::AES128_CCM
        | aead_id::AES128_CCM8
        | aead_id::AES128_GCM_SIV
        | aead_id::AEGIS128L
        | aead_id::ASCON_AEAD128 => 16,
        aead_id::AES256_GCM
        | aead_id::CHACHA20_POLY1305
        | aead_id::AES256_CCM
        | aead_id::AES256_CCM8
        | aead_id::AES256_GCM_SIV
        | aead_id::AEGIS256
        | aead_id::XCHACHA20_POLY1305 => 32,
        aead_id::AES128_SIV => 32,
        aead_id::AES256_SIV => 64,
        _ => return None,
    })
}

/// Whether `alg` is one of the SIV constructions, whose tag (synthetic IV) is
/// *prepended* to the output as `V ‖ ciphertext` rather than appended.
fn is_siv(alg: i32) -> bool {
    matches!(alg, aead_id::AES128_SIV | aead_id::AES256_SIV)
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
        // AES-SIV uses a single-AD form (the `nonce` argument is the AD header)
        // and emits `V ‖ ciphertext`, so it does not fit the append-tag shape.
        if is_siv(alg) {
            let out = match alg {
                aead_id::AES128_SIV | aead_id::AES256_SIV => AesSiv::new(k).seal(&[n], p),
                _ => unreachable!(),
            };
            return unsafe { out_write(&out, ct_and_tag, ct_and_tag_len) };
        }
        let tag_size = aead_tag_size(alg);
        let mut buf: Vec<u8> = p.to_vec();
        let tag: Vec<u8> = match alg {
            aead_id::AES128_GCM => {
                if n.is_empty() {
                    return PcStatus::Unsupported;
                }
                let key = KeyBuf::<16>(k.try_into().unwrap());
                Aes128Gcm::new(Aes128::new(key.r()))
                    .encrypt(n, a, &mut buf)
                    .to_vec()
            }
            aead_id::AES256_GCM => {
                if n.is_empty() {
                    return PcStatus::Unsupported;
                }
                let key = KeyBuf::<32>(k.try_into().unwrap());
                Aes256Gcm::new(Aes256::new(key.r()))
                    .encrypt(n, a, &mut buf)
                    .to_vec()
            }
            aead_id::CHACHA20_POLY1305 => {
                let key = KeyBuf::<32>(k.try_into().unwrap());
                let nonce: [u8; 12] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                ChaCha20Poly1305::new(key.r())
                    .encrypt(&nonce, a, &mut buf)
                    .to_vec()
            }
            aead_id::AES128_CCM => {
                if !(7..=13).contains(&n.len()) {
                    return PcStatus::Unsupported;
                }
                let key = KeyBuf::<16>(k.try_into().unwrap());
                Aes128Ccm::new(Aes128::new(key.r()))
                    .encrypt(n, a, &mut buf)
                    .to_vec()
            }
            aead_id::AES256_CCM => {
                if !(7..=13).contains(&n.len()) {
                    return PcStatus::Unsupported;
                }
                let key = KeyBuf::<32>(k.try_into().unwrap());
                Aes256Ccm::new(Aes256::new(key.r()))
                    .encrypt(n, a, &mut buf)
                    .to_vec()
            }
            aead_id::AES128_CCM8 => {
                if !(7..=13).contains(&n.len()) {
                    return PcStatus::Unsupported;
                }
                let key = KeyBuf::<16>(k.try_into().unwrap());
                Aes128Ccm8::new(Aes128::new(key.r()))
                    .encrypt(n, a, &mut buf)
                    .to_vec()
            }
            aead_id::AES256_CCM8 => {
                if !(7..=13).contains(&n.len()) {
                    return PcStatus::Unsupported;
                }
                let key = KeyBuf::<32>(k.try_into().unwrap());
                Aes256Ccm8::new(Aes256::new(key.r()))
                    .encrypt(n, a, &mut buf)
                    .to_vec()
            }
            aead_id::AES128_GCM_SIV | aead_id::AES256_GCM_SIV => {
                let nonce: [u8; 12] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                AesGcmSiv::new(k).encrypt(&nonce, a, &mut buf).to_vec()
            }
            aead_id::XCHACHA20_POLY1305 => {
                let key = KeyBuf::<32>(k.try_into().unwrap());
                let nonce: [u8; 24] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                XChaCha20Poly1305::new(key.r())
                    .encrypt(&nonce, a, &mut buf)
                    .to_vec()
            }
            aead_id::AEGIS128L => {
                let key = KeyBuf::<16>(k.try_into().unwrap());
                let nonce: [u8; 16] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                Aegis128L::new(key.r())
                    .encrypt(&nonce, a, &mut buf)
                    .to_vec()
            }
            aead_id::AEGIS256 => {
                let key = KeyBuf::<32>(k.try_into().unwrap());
                let nonce: [u8; 32] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                Aegis256::new(key.r()).encrypt(&nonce, a, &mut buf).to_vec()
            }
            aead_id::ASCON_AEAD128 => {
                let key = KeyBuf::<16>(k.try_into().unwrap());
                let nonce: [u8; 16] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                AsconAead128::new(key.r())
                    .encrypt(&nonce, a, &mut buf)
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
        // AES-SIV: input is `V ‖ ciphertext`; the `nonce` argument is the AD.
        if is_siv(alg) {
            let res = match alg {
                aead_id::AES128_SIV | aead_id::AES256_SIV => AesSiv::new(k).open(&[n], blob),
                _ => unreachable!(),
            };
            return match res {
                Ok(mut pt_bytes) => {
                    let st = unsafe { out_write(&pt_bytes, pt, pt_len) };
                    // Scrub the recovered plaintext before its backing
                    // storage is returned to the allocator (mirrors
                    // pc_sm2_decrypt / pc_rsa_decrypt_oaep).
                    wipe_vec(&mut pt_bytes);
                    st
                }
                Err(_) => PcStatus::Verification,
            };
        }
        let tag_size = aead_tag_size(alg);
        if blob.len() < tag_size {
            return PcStatus::BadEncoding;
        }
        let (ct, tag) = blob.split_at(blob.len() - tag_size);
        let mut buf: Vec<u8> = ct.to_vec();
        let ok = match alg {
            aead_id::AES128_GCM => {
                if n.is_empty() {
                    return PcStatus::Unsupported;
                }
                let key = KeyBuf::<16>(k.try_into().unwrap());
                let t: [u8; 16] = tag.try_into().unwrap();
                Aes128Gcm::new(Aes128::new(key.r()))
                    .decrypt(n, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AES256_GCM => {
                if n.is_empty() {
                    return PcStatus::Unsupported;
                }
                let key = KeyBuf::<32>(k.try_into().unwrap());
                let t: [u8; 16] = tag.try_into().unwrap();
                Aes256Gcm::new(Aes256::new(key.r()))
                    .decrypt(n, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::CHACHA20_POLY1305 => {
                let key = KeyBuf::<32>(k.try_into().unwrap());
                let nonce: [u8; 12] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                let t: [u8; 16] = tag.try_into().unwrap();
                ChaCha20Poly1305::new(key.r())
                    .decrypt(&nonce, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AES128_CCM => {
                if !(7..=13).contains(&n.len()) {
                    return PcStatus::Unsupported;
                }
                let key = KeyBuf::<16>(k.try_into().unwrap());
                let t: [u8; 16] = tag.try_into().unwrap();
                Aes128Ccm::new(Aes128::new(key.r()))
                    .decrypt(n, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AES256_CCM => {
                if !(7..=13).contains(&n.len()) {
                    return PcStatus::Unsupported;
                }
                let key = KeyBuf::<32>(k.try_into().unwrap());
                let t: [u8; 16] = tag.try_into().unwrap();
                Aes256Ccm::new(Aes256::new(key.r()))
                    .decrypt(n, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AES128_CCM8 => {
                if !(7..=13).contains(&n.len()) {
                    return PcStatus::Unsupported;
                }
                let key = KeyBuf::<16>(k.try_into().unwrap());
                let t: [u8; 8] = tag.try_into().unwrap();
                Aes128Ccm8::new(Aes128::new(key.r()))
                    .decrypt(n, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AES256_CCM8 => {
                if !(7..=13).contains(&n.len()) {
                    return PcStatus::Unsupported;
                }
                let key = KeyBuf::<32>(k.try_into().unwrap());
                let t: [u8; 8] = tag.try_into().unwrap();
                Aes256Ccm8::new(Aes256::new(key.r()))
                    .decrypt(n, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AES128_GCM_SIV | aead_id::AES256_GCM_SIV => {
                let nonce: [u8; 12] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                let t: [u8; 16] = tag.try_into().unwrap();
                AesGcmSiv::new(k).decrypt(&nonce, a, &mut buf, &t).is_ok()
            }
            aead_id::XCHACHA20_POLY1305 => {
                let key = KeyBuf::<32>(k.try_into().unwrap());
                let nonce: [u8; 24] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                let t: [u8; 16] = tag.try_into().unwrap();
                XChaCha20Poly1305::new(key.r())
                    .decrypt(&nonce, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AEGIS128L => {
                let key = KeyBuf::<16>(k.try_into().unwrap());
                let nonce: [u8; 16] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                let t: [u8; 16] = tag.try_into().unwrap();
                Aegis128L::new(key.r())
                    .decrypt(&nonce, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::AEGIS256 => {
                let key = KeyBuf::<32>(k.try_into().unwrap());
                let nonce: [u8; 32] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                let t: [u8; 16] = tag.try_into().unwrap();
                Aegis256::new(key.r())
                    .decrypt(&nonce, a, &mut buf, &t)
                    .is_ok()
            }
            aead_id::ASCON_AEAD128 => {
                let key = KeyBuf::<16>(k.try_into().unwrap());
                let nonce: [u8; 16] = match n.try_into() {
                    Ok(v) => v,
                    Err(_) => return PcStatus::Unsupported,
                };
                let t: [u8; 16] = tag.try_into().unwrap();
                AsconAead128::new(key.r())
                    .decrypt(&nonce, a, &mut buf, &t)
                    .is_ok()
            }
            _ => return PcStatus::Unsupported,
        };
        if !ok {
            // Some modes decrypt in place before the tag check fails, so
            // `buf` may hold (unauthenticated) plaintext — scrub it too.
            wipe_vec(&mut buf);
            return PcStatus::Verification;
        }
        let st = unsafe { out_write(&buf, pt, pt_len) };
        // Scrub the recovered plaintext before its backing storage is
        // returned to the allocator (mirrors pc_sm2_decrypt /
        // pc_rsa_decrypt_oaep).
        wipe_vec(&mut buf);
        st
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
                let kk = KeyBuf::<16>(k.try_into().unwrap());
                Aes128Kw::new(Aes128::new(kk.r())).wrap(pt, &mut wrapped)
            }
            32 => {
                let kk = KeyBuf::<32>(k.try_into().unwrap());
                Aes256Kw::new(Aes256::new(kk.r())).wrap(pt, &mut wrapped)
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
                let kk = KeyBuf::<16>(k.try_into().unwrap());
                Aes128Kw::new(Aes128::new(kk.r())).unwrap(c, &mut plain)
            }
            32 => {
                let kk = KeyBuf::<32>(k.try_into().unwrap());
                Aes256Kw::new(Aes256::new(kk.r())).unwrap(c, &mut plain)
            }
            _ => return PcStatus::Unsupported,
        };
        if res.is_err() {
            // The buffer may hold a partially unwrapped key — scrub it.
            wipe_vec(&mut plain);
            return PcStatus::Verification;
        }
        let st = unsafe { out_write(&plain, out, out_len) };
        // Scrub the unwrapped key material before its backing storage is
        // returned to the allocator.
        wipe_vec(&mut plain);
        st
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
                let kk = KeyBuf::<16>(k.try_into().unwrap());
                Aes128Kwp::new(Aes128::new(kk.r())).wrap(pt, &mut wrapped)
            }
            32 => {
                let kk = KeyBuf::<32>(k.try_into().unwrap());
                Aes256Kwp::new(Aes256::new(kk.r())).wrap(pt, &mut wrapped)
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
                let kk = KeyBuf::<16>(k.try_into().unwrap());
                Aes128Kwp::new(Aes128::new(kk.r())).unwrap(c, &mut plain)
            }
            32 => {
                let kk = KeyBuf::<32>(k.try_into().unwrap());
                Aes256Kwp::new(Aes256::new(kk.r())).unwrap(c, &mut plain)
            }
            _ => return PcStatus::Unsupported,
        };
        let n = match n {
            Ok(n) => n,
            Err(_) => {
                // The buffer may hold a partially unwrapped key — scrub it.
                wipe_vec(&mut plain);
                return PcStatus::Verification;
            }
        };
        // Deliver `plain[..n]` without truncating first: truncate() would
        // leave the padding tail beyond `n` in the allocation, out of
        // wipe_vec's reach.
        let st = unsafe { out_write(&plain[..n], out, out_len) };
        // Scrub the unwrapped key material (full buffer, padding included)
        // before its backing storage is returned to the allocator.
        wipe_vec(&mut plain);
        st
    })
}

/// Computes the AES-CMAC tag (RFC 4493 / NIST SP 800-38B) of `msg` under `key`,
/// writing the 16-byte tag to `out`. A 16-byte key selects AES-128-CMAC; a
/// 32-byte key selects AES-256-CMAC.
///
/// # Safety
/// All pointers must be valid for their lengths; `out_len` non-NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_cmac(
    key: *const u8,
    key_len: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        let (Some(k), Some(m)) = (unsafe { slice(key, key_len) }, unsafe {
            slice(msg, msg_len)
        }) else {
            return PcStatus::NullPointer;
        };
        let tag = match k.len() {
            16 => {
                let kk = KeyBuf::<16>(k.try_into().unwrap());
                let mut c = AesCmac128::new(Aes128::new(kk.r()));
                c.update(m);
                c.finalize()
            }
            32 => {
                let kk = KeyBuf::<32>(k.try_into().unwrap());
                let mut c = AesCmac256::new(Aes256::new(kk.r()));
                c.update(m);
                c.finalize()
            }
            _ => return PcStatus::Unsupported,
        };
        unsafe { out_write(&tag, out, out_len) }
    })
}

/// Computes the GMAC tag (NIST SP 800-38D) of `data` under `key` with the
/// 12-byte `nonce`, writing the 16-byte tag to `out`. A 16-byte key selects
/// AES-128-GMAC; a 32-byte key selects AES-256-GMAC. The `nonce` MUST be unique
/// per (key, message); reuse is catastrophic.
///
/// # Safety
/// All pointers must be valid for their lengths; `out_len` non-NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_gmac(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        let (Some(k), Some(n), Some(m)) = (
            unsafe { slice(key, key_len) },
            unsafe { slice(nonce, nonce_len) },
            unsafe { slice(data, data_len) },
        ) else {
            return PcStatus::NullPointer;
        };
        let nonce: [u8; 12] = match n.try_into() {
            Ok(v) => v,
            Err(_) => return PcStatus::Unsupported,
        };
        let tag = match k.len() {
            16 => {
                let kk = KeyBuf::<16>(k.try_into().unwrap());
                let mut g = AesGmac128::new(Aes128::new(kk.r()), &nonce);
                g.update(m);
                g.finalize()
            }
            32 => {
                let kk = KeyBuf::<32>(k.try_into().unwrap());
                let mut g = AesGmac256::new(Aes256::new(kk.r()), &nonce);
                g.update(m);
                g.finalize()
            }
            _ => return PcStatus::Unsupported,
        };
        unsafe { out_write(&tag, out, out_len) }
    })
}
