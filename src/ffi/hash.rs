//! C ABI for hashing (one-shot and streaming) and HMAC.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::common::{PcStatus, guard, out_write, slice};
use crate::ascon::{AsconCxof128, AsconHash256, AsconXof128};
use crate::hash::{
    Digest, ExtendableOutput, HashAlgorithm, Hasher, Hmac, HmacSha224, HmacSha256, HmacSha384,
    HmacSha512, HmacSha512_224, HmacSha512_256, Md2, Ripemd160, Sha1, Sha3_224, Sha3_256, Sha3_384,
    Sha3_512, Sm3, Streebog256, Streebog512, Whirlpool, XofReader,
};

/// Hash algorithm identifiers (mirror `PcHashId` in `purecrypto.h`).
pub mod id {
    #![allow(missing_docs)]
    pub const SHA224: i32 = 1;
    pub const SHA256: i32 = 2;
    pub const SHA384: i32 = 3;
    pub const SHA512: i32 = 4;
    pub const SHA512_224: i32 = 5;
    pub const SHA512_256: i32 = 6;
    pub const SHA3_224: i32 = 7;
    pub const SHA3_256: i32 = 8;
    pub const SHA3_384: i32 = 9;
    pub const SHA3_512: i32 = 10;
    pub const KECCAK256: i32 = 11;
    pub const BLAKE2B256: i32 = 12;
    pub const BLAKE2B512: i32 = 13;
    pub const BLAKE2S256: i32 = 14;
    pub const BLAKE3: i32 = 15;
    pub const SM3: i32 = 16;
    pub const SHA1: i32 = 17;
    pub const MD5: i32 = 18;
    pub const RIPEMD160: i32 = 19;
    pub const ASCON_HASH256: i32 = 20;
    pub const MD2: i32 = 21;
    pub const WHIRLPOOL: i32 = 22;
    pub const STREEBOG256: i32 = 23;
    pub const STREEBOG512: i32 = 24;
}

/// A runtime-selected hasher: either one of the algorithms
/// [`HashAlgorithm`] names, or Ascon-Hash256 (which lives behind the `ascon`
/// feature and so is not in that enum).
///
/// `Hasher` holds the widest hasher state inline (BLAKE3's chunk stack
/// dominates), but the context is heap-allocated once by `pc_hash_new`.
#[allow(clippy::large_enum_variant)]
enum AnyHasher {
    Alg(Hasher),
    Ascon(AsconHash256),
}

impl AnyHasher {
    /// Maps a `PcHashId` to its hasher, or `None` for an unknown id.
    fn new(alg: i32) -> Option<Self> {
        let alg = match alg {
            id::SHA224 => HashAlgorithm::Sha224,
            id::SHA256 => HashAlgorithm::Sha256,
            id::SHA384 => HashAlgorithm::Sha384,
            id::SHA512 => HashAlgorithm::Sha512,
            id::SHA512_224 => HashAlgorithm::Sha512_224,
            id::SHA512_256 => HashAlgorithm::Sha512_256,
            id::SHA3_224 => HashAlgorithm::Sha3_224,
            id::SHA3_256 => HashAlgorithm::Sha3_256,
            id::SHA3_384 => HashAlgorithm::Sha3_384,
            id::SHA3_512 => HashAlgorithm::Sha3_512,
            id::KECCAK256 => HashAlgorithm::Keccak256,
            id::BLAKE2B256 => HashAlgorithm::Blake2b256,
            id::BLAKE2B512 => HashAlgorithm::Blake2b512,
            id::BLAKE2S256 => HashAlgorithm::Blake2s256,
            id::BLAKE3 => HashAlgorithm::Blake3,
            id::SM3 => HashAlgorithm::Sm3,
            id::SHA1 => HashAlgorithm::Sha1,
            id::MD5 => HashAlgorithm::Md5,
            id::RIPEMD160 => HashAlgorithm::Ripemd160,
            id::MD2 => HashAlgorithm::Md2,
            id::WHIRLPOOL => HashAlgorithm::Whirlpool,
            id::STREEBOG256 => HashAlgorithm::Streebog256,
            id::STREEBOG512 => HashAlgorithm::Streebog512,
            id::ASCON_HASH256 => return Some(AnyHasher::Ascon(AsconHash256::new())),
            _ => return None,
        };
        Some(AnyHasher::Alg(alg.hasher()))
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            AnyHasher::Alg(h) => h.update(data),
            AnyHasher::Ascon(h) => Digest::update(h, data),
        }
    }

    /// The digest of everything absorbed so far, leaving the context usable
    /// (the C API allows `pc_hash_finish` followed by more updates).
    fn finish(&self) -> Vec<u8> {
        match self {
            AnyHasher::Alg(h) => h.clone().finalize().as_slice().to_vec(),
            AnyHasher::Ascon(h) => Digest::finalize(h.clone()).as_ref().to_vec(),
        }
    }
}

/// An opaque streaming hash context.
pub struct PcHash(AnyHasher);

/// Computes the digest of `data` under algorithm `alg` in one call, writing it
/// to `out` (see the in/out `out_len` convention).
///
/// # Safety
/// `data`/`out` must be valid for their lengths; `out_len` must be a valid
/// pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_digest(
    alg: i32,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        let Some(input) = (unsafe { slice(data, data_len) }) else {
            return PcStatus::NullPointer;
        };
        let Some(mut h) = AnyHasher::new(alg) else {
            return PcStatus::Unsupported;
        };
        h.update(input);
        unsafe { out_write(&h.finish(), out, out_len) }
    })
}

/// Creates a streaming hash context for `alg`, or NULL if `alg` is unknown.
/// Free it with [`pc_hash_free`].
#[unsafe(no_mangle)]
pub extern "C" fn pc_hash_new(alg: i32) -> *mut PcHash {
    crate::ffi::common::guard_ptr(|| match AnyHasher::new(alg) {
        Some(h) => Box::into_raw(Box::new(PcHash(h))),
        None => core::ptr::null_mut(),
    })
}

/// Feeds `len` bytes into the hash context.
///
/// # Safety
/// `h` must come from [`pc_hash_new`] and not be freed; `data` valid for `len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_hash_update(h: *mut PcHash, data: *const u8, len: usize) -> PcStatus {
    guard(|| {
        if h.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(input) = (unsafe { slice(data, len) }) else {
            return PcStatus::NullPointer;
        };
        unsafe { &mut *h }.0.update(input);
        PcStatus::Ok
    })
}

/// Writes the current digest to `out` without consuming the context (it may be
/// updated and finished again).
///
/// # Safety
/// `h` must come from [`pc_hash_new`]; `out`/`out_len` follow the buffer rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_hash_finish(
    h: *mut PcHash,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if h.is_null() {
            return PcStatus::NullPointer;
        }
        let digest = unsafe { &*h }.0.finish();
        unsafe { out_write(&digest, out, out_len) }
    })
}

/// Frees a hash context. NULL is ignored.
///
/// # Safety
/// `h` must come from [`pc_hash_new`] and not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_hash_free(h: *mut PcHash) {
    if !h.is_null() {
        drop(unsafe { Box::from_raw(h) });
    }
}

/// Computes HMAC of `msg` under `key`, with the hash selected by `alg`,
/// writing the tag to `out`. Supports the fixed-output hashes from
/// [`pc_digest`] (SHA-1, SHA-2 family, SHA-3 family, SM3, RIPEMD-160, MD2,
/// Whirlpool, Streebog-256/512).
///
/// # Safety
/// All pointers must be valid for their lengths; `out_len` non-NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_hmac(
    alg: i32,
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
        let tag = match alg {
            id::SHA1 => Hmac::<Sha1>::mac(k, m).as_ref().to_vec(),
            id::SHA224 => HmacSha224::mac(k, m).as_ref().to_vec(),
            id::SHA256 => HmacSha256::mac(k, m).as_ref().to_vec(),
            id::SHA384 => HmacSha384::mac(k, m).as_ref().to_vec(),
            id::SHA512 => HmacSha512::mac(k, m).as_ref().to_vec(),
            id::SHA512_224 => HmacSha512_224::mac(k, m).as_ref().to_vec(),
            id::SHA512_256 => HmacSha512_256::mac(k, m).as_ref().to_vec(),
            id::SHA3_224 => Hmac::<Sha3_224>::mac(k, m).as_ref().to_vec(),
            id::SHA3_256 => Hmac::<Sha3_256>::mac(k, m).as_ref().to_vec(),
            id::SHA3_384 => Hmac::<Sha3_384>::mac(k, m).as_ref().to_vec(),
            id::SHA3_512 => Hmac::<Sha3_512>::mac(k, m).as_ref().to_vec(),
            id::SM3 => Hmac::<Sm3>::mac(k, m).as_ref().to_vec(),
            id::RIPEMD160 => Hmac::<Ripemd160>::mac(k, m).as_ref().to_vec(),
            id::MD2 => Hmac::<Md2>::mac(k, m).as_ref().to_vec(),
            id::WHIRLPOOL => Hmac::<Whirlpool>::mac(k, m).as_ref().to_vec(),
            id::STREEBOG256 => Hmac::<Streebog256>::mac(k, m).as_ref().to_vec(),
            id::STREEBOG512 => Hmac::<Streebog512>::mac(k, m).as_ref().to_vec(),
            _ => return PcStatus::Unsupported,
        };
        unsafe { out_write(&tag, out, out_len) }
    })
}

/// Ascon-XOF128 (NIST SP 800-232 §5.2): squeezes exactly `out_len` bytes of
/// extendable output from `data` into `out`. Unlike the fixed-length digest
/// APIs, `out_len` is the requested length (not an in/out capacity).
///
/// # Safety
/// `data`/`out` must be valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ascon_xof(
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
) -> PcStatus {
    guard(|| {
        let Some(input) = (unsafe { slice(data, data_len) }) else {
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
        let mut x = AsconXof128::new();
        x.update(input);
        x.finalize_xof().read(buf);
        PcStatus::Ok
    })
}

/// Ascon-CXOF128 (NIST SP 800-232 §5.3): customized XOF. `custom` is the
/// customization string `Z` (at most 256 bytes; longer is rejected with
/// [`PcStatus::Unsupported`]). Squeezes exactly `out_len` bytes into `out`.
///
/// # Safety
/// All pointers must be valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_ascon_cxof(
    custom: *const u8,
    custom_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
) -> PcStatus {
    guard(|| {
        let (Some(z), Some(input)) = (unsafe { slice(custom, custom_len) }, unsafe {
            slice(data, data_len)
        }) else {
            return PcStatus::NullPointer;
        };
        if z.len() > AsconCxof128::MAX_CUSTOMIZATION_LEN {
            return PcStatus::Unsupported;
        }
        if out.is_null() && out_len > 0 {
            return PcStatus::NullPointer;
        }
        let buf = if out_len == 0 {
            &mut [][..]
        } else {
            unsafe { core::slice::from_raw_parts_mut(out, out_len) }
        };
        AsconCxof128::xof(z, input, buf);
        PcStatus::Ok
    })
}
