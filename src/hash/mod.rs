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
//! - SHA-3 (Keccak): [`Sha3_224`], [`Sha3_256`], [`Sha3_384`], [`Sha3_512`],
//!   and [`Keccak256`] (the legacy/Ethereum variant).
//! - BLAKE2: [`Blake2b256`], [`Blake2b384`], [`Blake2b512`], [`Blake2s256`],
//!   plus the keyed MACs [`Blake2bMac`]/[`Blake2sMac`].
//! - [`Blake3`] — also an XOF, with keyed and key-derivation modes.
//! - SM3: [`Sm3`].
//! - Legacy (interop only, not collision-resistant): [`Md4`], [`Md5`],
//!   [`Sha1`], [`Ripemd160`].
//!
//! Extendable-output functions ([`ExtendableOutput`] or an inherent
//! `finalize_xof`): [`Shake128`], [`Shake256`], [`CShake128`], [`CShake256`],
//! [`Blake2xb`], [`Blake2xs`], [`Blake3`], [`KmacXof128`], [`KmacXof256`],
//! [`TupleHash128`]/[`TupleHash256`], [`ParallelHash128`]/[`ParallelHash256`],
//! [`TurboShake128`]/[`TurboShake256`], and [`KangarooTwelve`].
//!
//! Message authentication codes ([`Mac`], with constant-time
//! [`verify`](Mac::verify)): [`Hmac`], [`Kmac128`], [`Kmac256`],
//! [`Blake2bMac`], [`Blake2sMac`]. Keyed constructions wipe their key-derived
//! state on drop.

mod blake2;
mod blake3;
mod block;
mod hmac;
mod k12;
mod keccak;
mod kmac;
mod md4;
mod md5;
mod ripemd160;
mod sha1;
mod sha256;
mod sha3;
mod sha512;
mod shake;
mod sm3;
mod zeroize;

pub use blake2::{
    Blake2b256, Blake2b384, Blake2b512, Blake2bMac, Blake2s256, Blake2sMac, Blake2xb,
    Blake2xbReader, Blake2xs, Blake2xsReader, blake2b256, blake2b384, blake2b512, blake2s256,
};
pub use blake3::{Blake3, Blake3Reader, blake3};
pub use hmac::{
    Hmac, HmacSha224, HmacSha256, HmacSha384, HmacSha512, HmacSha512_224, HmacSha512_256,
};
pub use k12::{KangarooTwelve, TurboShake128, TurboShake256, k12};
pub use keccak::KeccakReader;
pub use kmac::{
    CShake128, CShake256, Kmac128, Kmac256, KmacXof128, KmacXof256, ParallelHash128,
    ParallelHash256, TupleHash128, TupleHash256,
};
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

    /// Best-effort wipe of the hasher's internal state.
    ///
    /// Defaults to a no-op; concrete hashers override it to zero their state
    /// words and buffers. Keyed constructions such as [`Hmac`] call this on
    /// drop so the key-derived state does not linger in memory.
    #[inline]
    fn zeroize(&mut self) {}
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

/// A message authentication code: a keyed function producing an
/// authentication tag, with constant-time verification.
///
/// Implemented by [`Hmac`], [`Kmac128`]/[`Kmac256`], and
/// [`Blake2bMac`]/[`Blake2sMac`]. Each is constructed by its own keyed
/// constructor; this trait unifies the post-construction interface so generic
/// code can feed data, produce a tag, and verify it.
pub trait Mac: Clone {
    /// Feeds message bytes. May be called any number of times.
    fn update(&mut self, data: &[u8]);

    /// Consumes the MAC and writes the tag into `out`.
    ///
    /// For variable-length MACs (KMAC, BLAKE2-MAC) the tag length is
    /// `out.len()`. For fixed-length MACs (HMAC) the full digest is written,
    /// truncated to `out.len()` if shorter.
    fn finalize_into(self, out: &mut [u8]);

    /// Consumes the MAC and checks the tag against `expected` in constant time.
    ///
    /// The comparison time depends only on the (public) tag length, not on
    /// where a mismatch occurs. The default implementation supports tags up to
    /// 64 bytes; for longer tags use [`finalize_into`](Mac::finalize_into) with
    /// [`ConstantTimeEq`](crate::ct::ConstantTimeEq) directly.
    fn verify(self, expected: &[u8]) -> crate::ct::Choice {
        use crate::ct::ConstantTimeEq;
        let mut buf = [0u8; 64];
        let n = expected.len().min(buf.len());
        self.finalize_into(&mut buf[..n]);
        // `ct_eq` fails closed when `n < expected.len()` (length mismatch).
        let eq = buf[..n].ct_eq(expected);
        zeroize::zero_bytes(&mut buf);
        eq
    }
}
