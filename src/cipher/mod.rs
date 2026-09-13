//! Symmetric ciphers.
//!
//! Provides the AES block cipher ([`Aes128`], [`Aes192`], [`Aes256`]) and
//! [`Sm4`] with constant-time implementations: the S-boxes are computed by
//! GF(2⁸) inversion rather than table lookup, so there are no
//! secret-dependent memory accesses and hence no cache-timing leak.
//!
//! Block ciphers expose only the raw block transform via [`BlockCipher`];
//! modes of operation (CTR, CBC, GCM, …) are layered on top separately.
//!
//! Also provides the [`ChaCha20`] stream cipher and [`Poly1305`] authenticator,
//! combined as the [`ChaCha20Poly1305`] AEAD (RFC 8439) — both inherently
//! constant time, built from 32-bit ARX and 130-bit limb arithmetic.
//!
//! # AEAD buffer contract on tag failure
//!
//! Every in-place AEAD `decrypt` in this crate returns
//! [`TagMismatch`] **without handing the caller any unauthenticated
//! plaintext**. What is left in the buffer instead differs by mode, and
//! callers must not rely on either shape:
//!
//! | mode | buffer after `Err(TagMismatch)` |
//! | --- | --- |
//! | [`Gcm`], [`ChaCha20Poly1305`], [`XChaCha20Poly1305`], [`Aegis128L`] / [`Aegis256`], `AsconAead128` | unchanged — still the ciphertext |
//! | [`Ccm`], [`AesGcmSiv`] | zeroed |
//! | [`Aez`] (`decrypt_into`) | the `out` region it wrote is zeroed; the input `c` is a separate slice and is untouched |
//! | [`AesSiv`] (`open`) | no buffer: the plaintext `Vec` is wiped and dropped |
//!
//! The only guarantee to code against is the negative one: after an error the
//! buffer holds **no plaintext**. Treat its contents as unspecified, and if
//! you need the ciphertext afterwards (for a retry, a log, a second key) keep
//! your own copy.
//!
//! Two further caveats hold across the "unchanged" modes, and are repeated on
//! the individual methods:
//!
//! * Some of those modes reach that state by decrypting in place and
//!   re-encrypting on failure ([`Gcm`]'s stitched AES-NI path, `AsconAead128`),
//!   so unauthenticated plaintext genuinely exists in the buffer *during* the
//!   call. That is invisible to a caller that owns the buffer, but it is a
//!   real leak if the buffer aliases memory another party can read
//!   concurrently (a `MAP_SHARED` mapping, an `io_uring`/DMA region), and the
//!   restoring pass does not run if a panic unwinds mid-call. Decrypt into
//!   private memory and copy out only after `Ok`.
//! * Releasing even a *verified* plaintext is the caller's decision to make
//!   once; never process a buffer twice "to see" whether the tag matches.

mod aegis;
mod aes;
#[cfg(feature = "aez")]
mod aez;
mod aria;
// Blowfish is not exposed as a cipher of its own: it exists purely as the core
// of `kdf::bcrypt_pbkdf`, which itself needs `alloc`. Outside that combination
// every item in the module is dead code.
#[cfg(all(feature = "kdf", feature = "alloc"))]
pub(crate) mod blowfish;
mod camellia;
mod cbc;
mod ccm;
mod cfb;
mod chacha20;
mod chacha20poly1305;
#[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod clmul;
mod cmac;
mod ctr;
mod des;
mod gcm;
mod gcm_siv;
mod gmac;
mod kw;
mod ofb;
mod poly1305;
// Likewise Salsa20/8: only `kdf::scrypt` (also `alloc`-gated) uses its core
// permutation.
#[cfg(all(feature = "kdf", feature = "alloc"))]
pub(crate) mod salsa20;
mod sm4;
// AES-SIV returns variable-length `Vec` output (RFC 5297), so it needs `alloc`.
#[cfg(feature = "alloc")]
mod siv;
mod xchacha20poly1305;
mod xts;

pub use aegis::{Aegis128L, Aegis256};
pub use aes::{Aes128, Aes192, Aes256};
#[cfg(feature = "aez")]
pub use aez::Aez;
pub use aria::{Aria128, Aria192, Aria256};
pub use camellia::{Camellia128, Camellia192, Camellia256};
pub use cbc::Cbc;
pub use ccm::{Aes128Ccm, Aes128Ccm8, Aes192Ccm, Aes256Ccm, Aes256Ccm8, Ccm};
pub use cfb::Cfb;
pub use chacha20::ChaCha20;
pub use chacha20poly1305::ChaCha20Poly1305;
pub use cmac::{AesCmac128, AesCmac256, Cmac};
pub use ctr::Ctr;
pub use des::{Cbc64, Des, TdesEde2, TdesEde3};
pub use gcm::{Aes128Gcm, Aes256Gcm, Gcm};
pub use gcm_siv::{Aes128GcmSiv, Aes256GcmSiv, AesGcmSiv};
pub use gmac::{AesGmac128, AesGmac256, Gmac};
pub use kw::{
    Aes128Kw, Aes128Kwp, Aes192Kw, Aes192Kwp, Aes256Kw, Aes256Kwp, AesKw, AesKwp, KwError,
    kw_ciphertext_len, kwp_ciphertext_len,
};
pub use ofb::Ofb;
pub use poly1305::Poly1305;
#[cfg(feature = "alloc")]
pub use siv::AesSiv;
pub use sm4::Sm4;
pub use xchacha20poly1305::XChaCha20Poly1305;
pub use xts::{Aes128Xts, Aes256Xts, Xts, XtsError};

/// A block cipher: a keyed, invertible permutation on fixed-size blocks.
pub trait BlockCipher {
    /// Block size in bytes.
    const BLOCK_SIZE: usize;
    /// Key size in bytes.
    const KEY_SIZE: usize;

    /// Encrypts one block in place.
    fn encrypt_block(&self, block: &mut [u8; 16]);

    /// Decrypts one block in place.
    fn decrypt_block(&self, block: &mut [u8; 16]);

    /// Applies the forward permutation to each consecutive 16-byte block of
    /// `blocks`, treating the blocks as independent (no chaining). `blocks.len()`
    /// must be a multiple of 16.
    ///
    /// The default loops over [`encrypt_block`](Self::encrypt_block); hardware
    /// backends (e.g. AES-NI / ARMv8-AES) override this to pipeline several
    /// blocks at once. This is the batched primitive that counter-style modes
    /// (CTR, GCM, GCM-SIV, OFB) build on — they prepare the counter blocks and
    /// XOR the result, so all counter arithmetic stays in the mode. Like the
    /// single-block path it is constant-time.
    fn encrypt_blocks(&self, blocks: &mut [u8]) {
        debug_assert_eq!(blocks.len() % 16, 0, "encrypt_blocks needs whole blocks");
        for chunk in blocks.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = chunk.try_into().expect("16-byte chunk");
            self.encrypt_block(block);
        }
    }

    /// Applies the inverse permutation to each consecutive 16-byte block of
    /// `blocks` independently (no chaining). `blocks.len()` must be a multiple
    /// of 16. Default loops over [`decrypt_block`](Self::decrypt_block);
    /// hardware backends override to pipeline. Constant-time.
    fn decrypt_blocks(&self, blocks: &mut [u8]) {
        debug_assert_eq!(blocks.len() % 16, 0, "decrypt_blocks needs whole blocks");
        for chunk in blocks.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = chunk.try_into().expect("16-byte chunk");
            self.decrypt_block(block);
        }
    }

    /// Internal hook for the stitched AES-CTR ⊕ GHASH bulk path in GCM: when
    /// the cipher is AES running on a hardware backend, returns the FIPS-197
    /// round-key schedule bytes and the round count so the mode can drive the
    /// AES pipeline and the carryless multiplier in a single fused loop.
    /// `None` (the default, and the only sensible answer for anything that is
    /// not hardware-backed AES) selects the generic two-pass path.
    ///
    /// The answer is *not* trusted: the mode validates that the round count is
    /// one of AES's 10/12/14 and that the slice really holds
    /// `16 * (nr + 1)` bytes, and independently re-checks that the CPU
    /// implements the AES instruction-set extension, falling back to the
    /// generic path otherwise. Overriding this with anything but a genuine
    /// FIPS-197 schedule therefore cannot cause unsoundness — it just yields
    /// wrong ciphertext, or is ignored.
    #[doc(hidden)]
    fn hw_aes_schedule(&self) -> Option<(&[u8], usize)> {
        None
    }
}

/// A 64-bit-block cipher: parallel to [`BlockCipher`] but for legacy
/// 8-byte-block primitives (DES, 3-DES). Wire this up via [`Cbc64`] for
/// CBC-mode interop; new code should use the 128-bit `BlockCipher` and
/// `Cbc` instead.
pub trait BlockCipher64 {
    /// Key size in bytes.
    const KEY_SIZE: usize;

    /// Encrypts one 8-byte block in place.
    fn encrypt_block(&self, block: &mut [u8; 8]);

    /// Decrypts one 8-byte block in place.
    fn decrypt_block(&self, block: &mut [u8; 8]);
}

/// Error returned by block-oriented modes (e.g. CBC) when the input length is
/// not a whole number of blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidLength;

impl core::fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("input length is not a multiple of the block size")
    }
}

impl core::error::Error for InvalidLength {}

/// Error returned by AEAD decryption when the authentication tag does not
/// match — the ciphertext is inauthentic and the plaintext must be discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagMismatch;

impl core::fmt::Display for TagMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AEAD authentication tag mismatch")
    }
}

impl core::error::Error for TagMismatch {}
