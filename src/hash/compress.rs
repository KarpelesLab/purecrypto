//! Raw compression functions of the block-iterated hashes — **low level**.
//!
//! Each function folds exactly one block into a chaining value and does
//! nothing else: no buffering, no padding, no length encoding. That is the
//! piece a foreign hash-context format, a length-extension computation, or a
//! custom Merkle–Damgård framing needs; for hashing a message use the
//! [`Digest`](super::Digest) types, which do the framing correctly.
//!
//! The chaining value is the algorithm's own words, as its specification
//! defines them and as [`ExportableState`](super::ExportableState) writes
//! them: e.g. `[u32; 8]` starting from the FIPS 180-4 initial value for
//! SHA-256 (big-endian message words, so `0x6a09e667` first), `[u32; 4]`
//! from RFC 1321's `A, B, C, D` for MD5 (little-endian message words). Message
//! bytes are passed as bytes; each function reads them with its algorithm's
//! byte order.
//!
//! The hardware backends are used where the plain hashers use them (SHA-NI /
//! the aarch64 SHA extensions for SHA-1, SHA-256 and SHA-512); the results
//! are identical either way.

/// One MD4 (RFC 1320) compression.
#[inline]
pub fn md4(state: &mut [u32; 4], block: &[u8; 64]) {
    super::md4::compress(state, block);
}

/// One MD5 (RFC 1321) compression.
#[inline]
pub fn md5(state: &mut [u32; 4], block: &[u8; 64]) {
    super::md5::compress(state, block);
}

/// One SHA-1 (FIPS 180-4) compression.
#[inline]
pub fn sha1(state: &mut [u32; 5], block: &[u8; 64]) {
    super::sha1::compress(state, block);
}

/// One SHA-256 compression (FIPS 180-4); also SHA-224's, which differs only
/// in its initial value and truncation.
#[inline]
pub fn sha256(state: &mut [u32; 8], block: &[u8; 64]) {
    super::sha256::compress256(state, block);
}

/// One SHA-512 compression (FIPS 180-4); also that of SHA-384, SHA-512/224
/// and SHA-512/256, which differ only in their initial values and truncation.
#[inline]
pub fn sha512(state: &mut [u64; 8], block: &[u8; 128]) {
    super::sha512::compress512(state, block);
}

/// One RIPEMD-160 compression.
#[inline]
pub fn ripemd160(state: &mut [u32; 5], block: &[u8; 64]) {
    super::ripemd160::compress(state, block);
}

/// One SM3 (GB/T 32905-2016) compression.
#[inline]
pub fn sm3(state: &mut [u32; 8], block: &[u8; 64]) {
    super::sm3::compress(state, block);
}

/// One Whirlpool (ISO/IEC 10118-3) Miyaguchi–Preneel compression; the state
/// is eight big-endian 64-bit lanes, all zero initially.
#[inline]
pub fn whirlpool(state: &mut [u64; 8], block: &[u8; 64]) {
    super::whirlpool::compress(state, block);
}
