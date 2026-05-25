//! Cryptographic hash functions.
//!
//! Every hasher implements the [`Digest`] trait, which provides a streaming
//! interface ([`new`](Digest::new) / [`update`](Digest::update) /
//! [`finalize`](Digest::finalize)) plus a one-shot [`digest`](Digest::digest)
//! convenience. Implementations are pure `no_std` and allocation-free,
//! operating on fixed-size internal buffers.
//!
//! Implemented:
//! - SHA-2: [`Sha224`], [`Sha256`], [`Sha384`], [`Sha512`], [`Sha512_224`],
//!   [`Sha512_256`].
//! - SHA-3 (Keccak): [`Sha3_224`], [`Sha3_256`], [`Sha3_384`], [`Sha3_512`].
//! - BLAKE2: [`Blake2b256`], [`Blake2b384`], [`Blake2b512`], [`Blake2s256`].
//! - Legacy (interop only, not collision-resistant): [`Md4`], [`Md5`],
//!   [`Sha1`], [`Ripemd160`].

mod blake2;
mod block;
mod hmac;
mod keccak;
mod md4;
mod md5;
mod ripemd160;
mod sha1;
mod sha256;
mod sha3;
mod sha512;
mod shake;
mod sm3;

pub use blake2::{
    Blake2b256, Blake2b384, Blake2b512, Blake2s256, blake2b256, blake2b384, blake2b512, blake2s256,
};
pub use hmac::{
    Hmac, HmacSha224, HmacSha256, HmacSha384, HmacSha512, HmacSha512_224, HmacSha512_256,
};
pub use keccak::KeccakReader;
pub use md4::{Md4, md4};
pub use md5::{Md5, md5};
pub use ripemd160::{Ripemd160, ripemd160};
pub use sha1::{Sha1, sha1};
pub use sha3::{
    Keccak256, Sha3_224, Sha3_256, Sha3_384, Sha3_512, keccak256, sha3_224, sha3_256, sha3_384,
    sha3_512,
};
pub use sha256::{Sha224, Sha256, sha224, sha256};
pub use sha512::{Sha384, Sha512, Sha512_224, Sha512_256, sha384, sha512, sha512_224, sha512_256};
pub use shake::{Shake128, Shake256, shake128, shake256};
pub use sm3::{Sm3, sm3};

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

    /// Returns a zeroed [output buffer](Digest::Output). Useful to seed
    /// fixed-size state generically (e.g. HMAC-DRBG's `K`/`V`).
    fn zeroed_output() -> Self::Output;

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

/// An extendable-output function (XOF): like a hash, but it produces an output
/// stream of arbitrary length.
///
/// Feed data with [`update`](ExtendableOutput::update), then call
/// [`finalize_xof`](ExtendableOutput::finalize_xof) to obtain a
/// [`XofReader`] from which any number of output bytes can be squeezed.
pub trait ExtendableOutput: Clone {
    /// The reader that squeezes output bytes after finalization.
    type Reader: XofReader;

    /// Internal block length (rate), in bytes — the unit HMAC-style
    /// constructions key on.
    const BLOCK_LEN: usize;

    /// Creates an XOF in its initial state.
    fn new() -> Self;

    /// Feeds `data` into the XOF. May be called any number of times.
    fn update(&mut self, data: &[u8]);

    /// Finalizes absorption and returns a reader for the output stream.
    fn finalize_xof(self) -> Self::Reader;

    /// Convenience: finalize and squeeze exactly `out.len()` bytes.
    #[inline]
    fn finalize_into(self, out: &mut [u8]) {
        self.finalize_xof().read(out);
    }

    /// One-shot: hash `data` and squeeze `out.len()` output bytes.
    #[inline]
    fn xof(data: &[u8], out: &mut [u8]) {
        let mut x = Self::new();
        x.update(data);
        x.finalize_into(out);
    }
}

/// A reader over an [`ExtendableOutput`] result. Successive [`read`](XofReader::read)
/// calls yield consecutive bytes of the same output stream.
pub trait XofReader {
    /// Fills `out` with the next output bytes.
    fn read(&mut self, out: &mut [u8]);
}
