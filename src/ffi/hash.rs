//! C ABI for hashing (one-shot and streaming) and HMAC.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::common::{PcStatus, guard, out_write, slice};
use crate::ascon::{AsconCxof128, AsconHash256, AsconXof128};
use crate::hash::{
    Blake2b256, Blake2b512, Blake2s256, Blake3, Digest, ExtendableOutput, Hmac, HmacSha224,
    HmacSha256, HmacSha384, HmacSha512, HmacSha512_224, HmacSha512_256, Keccak256, Md2, Md5,
    Ripemd160, Sha1, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha224, Sha256, Sha384, Sha512,
    Sha512_224, Sha512_256, Sm3, Streebog256, Streebog512, Whirlpool, XofReader,
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

/// A runtime-selected hasher. (BLAKE3 carries a larger tree state than the
/// others, but the context is heap-allocated once via `pc_hash_new`.)
#[allow(clippy::large_enum_variant)]
enum AnyHasher {
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha512_224(Sha512_224),
    Sha512_256(Sha512_256),
    Sha3_224(Sha3_224),
    Sha3_256(Sha3_256),
    Sha3_384(Sha3_384),
    Sha3_512(Sha3_512),
    Keccak256(Keccak256),
    Blake2b256(Blake2b256),
    Blake2b512(Blake2b512),
    Blake2s256(Blake2s256),
    Blake3(Blake3),
    Sm3(Sm3),
    Sha1(Sha1),
    Md5(Md5),
    Ripemd160(Ripemd160),
    AsconHash256(AsconHash256),
    Md2(Md2),
    Whirlpool(Whirlpool),
    Streebog256(Streebog256),
    Streebog512(Streebog512),
}

impl AnyHasher {
    fn new(alg: i32) -> Option<Self> {
        Some(match alg {
            id::SHA224 => AnyHasher::Sha224(Sha224::new()),
            id::SHA256 => AnyHasher::Sha256(Sha256::new()),
            id::SHA384 => AnyHasher::Sha384(Sha384::new()),
            id::SHA512 => AnyHasher::Sha512(Sha512::new()),
            id::SHA512_224 => AnyHasher::Sha512_224(Sha512_224::new()),
            id::SHA512_256 => AnyHasher::Sha512_256(Sha512_256::new()),
            id::SHA3_224 => AnyHasher::Sha3_224(Sha3_224::new()),
            id::SHA3_256 => AnyHasher::Sha3_256(Sha3_256::new()),
            id::SHA3_384 => AnyHasher::Sha3_384(Sha3_384::new()),
            id::SHA3_512 => AnyHasher::Sha3_512(Sha3_512::new()),
            id::KECCAK256 => AnyHasher::Keccak256(Keccak256::new()),
            id::BLAKE2B256 => AnyHasher::Blake2b256(Blake2b256::new()),
            id::BLAKE2B512 => AnyHasher::Blake2b512(Blake2b512::new()),
            id::BLAKE2S256 => AnyHasher::Blake2s256(Blake2s256::new()),
            id::BLAKE3 => AnyHasher::Blake3(<Blake3 as Digest>::new()),
            id::SM3 => AnyHasher::Sm3(Sm3::new()),
            id::SHA1 => AnyHasher::Sha1(Sha1::new()),
            id::MD5 => AnyHasher::Md5(Md5::new()),
            id::RIPEMD160 => AnyHasher::Ripemd160(Ripemd160::new()),
            id::ASCON_HASH256 => AnyHasher::AsconHash256(AsconHash256::new()),
            id::MD2 => AnyHasher::Md2(Md2::new()),
            id::WHIRLPOOL => AnyHasher::Whirlpool(Whirlpool::new()),
            id::STREEBOG256 => AnyHasher::Streebog256(Streebog256::new()),
            id::STREEBOG512 => AnyHasher::Streebog512(Streebog512::new()),
            _ => return None,
        })
    }

    fn update(&mut self, data: &[u8]) {
        macro_rules! u {
            ($h:expr) => {
                $h.update(data)
            };
        }
        match self {
            AnyHasher::Sha224(h) => u!(h),
            AnyHasher::Sha256(h) => u!(h),
            AnyHasher::Sha384(h) => u!(h),
            AnyHasher::Sha512(h) => u!(h),
            AnyHasher::Sha512_224(h) => u!(h),
            AnyHasher::Sha512_256(h) => u!(h),
            AnyHasher::Sha3_224(h) => u!(h),
            AnyHasher::Sha3_256(h) => u!(h),
            AnyHasher::Sha3_384(h) => u!(h),
            AnyHasher::Sha3_512(h) => u!(h),
            AnyHasher::Keccak256(h) => u!(h),
            AnyHasher::Blake2b256(h) => u!(h),
            AnyHasher::Blake2b512(h) => u!(h),
            AnyHasher::Blake2s256(h) => u!(h),
            AnyHasher::Blake3(h) => Digest::update(h, data),
            AnyHasher::Sm3(h) => u!(h),
            AnyHasher::Sha1(h) => u!(h),
            AnyHasher::Md5(h) => u!(h),
            AnyHasher::Ripemd160(h) => u!(h),
            AnyHasher::AsconHash256(h) => u!(h),
            AnyHasher::Md2(h) => u!(h),
            AnyHasher::Whirlpool(h) => u!(h),
            AnyHasher::Streebog256(h) => u!(h),
            AnyHasher::Streebog512(h) => u!(h),
        }
    }

    fn finish(&self) -> Vec<u8> {
        macro_rules! f {
            ($h:expr) => {
                Digest::finalize($h.clone()).as_ref().to_vec()
            };
        }
        match self {
            AnyHasher::Sha224(h) => f!(h),
            AnyHasher::Sha256(h) => f!(h),
            AnyHasher::Sha384(h) => f!(h),
            AnyHasher::Sha512(h) => f!(h),
            AnyHasher::Sha512_224(h) => f!(h),
            AnyHasher::Sha512_256(h) => f!(h),
            AnyHasher::Sha3_224(h) => f!(h),
            AnyHasher::Sha3_256(h) => f!(h),
            AnyHasher::Sha3_384(h) => f!(h),
            AnyHasher::Sha3_512(h) => f!(h),
            AnyHasher::Keccak256(h) => f!(h),
            AnyHasher::Blake2b256(h) => f!(h),
            AnyHasher::Blake2b512(h) => f!(h),
            AnyHasher::Blake2s256(h) => f!(h),
            AnyHasher::Blake3(h) => f!(h),
            AnyHasher::Sm3(h) => f!(h),
            AnyHasher::Sha1(h) => f!(h),
            AnyHasher::Md5(h) => f!(h),
            AnyHasher::Ripemd160(h) => f!(h),
            AnyHasher::AsconHash256(h) => f!(h),
            AnyHasher::Md2(h) => f!(h),
            AnyHasher::Whirlpool(h) => f!(h),
            AnyHasher::Streebog256(h) => f!(h),
            AnyHasher::Streebog512(h) => f!(h),
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
