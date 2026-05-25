//! Cryptographic hash functions.
//!
//! Every hasher implements the [`Digest`] trait, which provides a streaming
//! interface ([`new`](Digest::new) / [`update`](Digest::update) /
//! [`finalize`](Digest::finalize)) plus a one-shot [`digest`](Digest::digest)
//! convenience. Implementations are pure `no_std` and allocation-free,
//! operating on fixed-size internal buffers.
//!
//! Currently implemented: the SHA-2 family ([`Sha224`], [`Sha256`],
//! [`Sha384`], [`Sha512`], [`Sha512_224`], [`Sha512_256`]).

mod hmac;
mod sha256;
mod sha512;

pub use hmac::{
    Hmac, HmacSha224, HmacSha256, HmacSha384, HmacSha512, HmacSha512_224, HmacSha512_256,
};
pub use sha256::{Sha224, Sha256, sha224, sha256};
pub use sha512::{Sha384, Sha512, Sha512_224, Sha512_256, sha384, sha512, sha512_224, sha512_256};

/// A cryptographic hash function with an incremental (streaming) interface.
///
/// Feed data with repeated [`update`](Digest::update) calls, then consume the
/// hasher with [`finalize`](Digest::finalize) to obtain the digest. The result
/// is identical regardless of how the input is chunked across `update` calls.
pub trait Digest: Clone {
    /// The fixed-size output type, e.g. `[u8; 32]` for SHA-256.
    type Output: AsRef<[u8]> + AsMut<[u8]> + Copy;

    /// A block-sized byte buffer (`[u8; BLOCK_LEN]`), used by block-oriented
    /// constructions such as HMAC that cannot name `[u8; BLOCK_LEN]` directly
    /// in generic code on stable Rust.
    type Block: AsRef<[u8]> + AsMut<[u8]> + Copy;

    /// Digest output length, in bytes.
    const OUTPUT_LEN: usize;

    /// Internal block length, in bytes (the unit the compression function
    /// consumes).
    const BLOCK_LEN: usize;

    /// Creates a hasher in its initial state.
    fn new() -> Self;

    /// Returns a zeroed [block buffer](Digest::Block).
    fn zeroed_block() -> Self::Block;

    /// Feeds `data` into the hasher. May be called any number of times.
    fn update(&mut self, data: &[u8]);

    /// Consumes the hasher and returns the final digest.
    fn finalize(self) -> Self::Output;

    /// Hashes `data` in a single call.
    #[inline]
    fn digest(data: &[u8]) -> Self::Output {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// Decodes a hex string into a fixed-size byte array. Test-only helper shared
/// by the hash implementations' known-answer tests.
#[cfg(test)]
pub(crate) fn from_hex<const N: usize>(s: &str) -> [u8; N] {
    let bytes = s.as_bytes();
    assert_eq!(bytes.len(), 2 * N, "hex string has wrong length");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        let hi = (bytes[2 * i] as char).to_digit(16).expect("invalid hex") as u8;
        let lo = (bytes[2 * i + 1] as char).to_digit(16).expect("invalid hex") as u8;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    out
}
