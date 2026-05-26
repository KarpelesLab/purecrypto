//! Symmetric ciphers.
//!
//! Provides the AES block cipher ([`Aes128`], [`Aes192`], [`Aes256`]) with a
//! constant-time implementation: the S-box is computed by GF(2⁸) inversion
//! rather than table lookup, so there are no secret-dependent memory accesses
//! and hence no cache-timing leak.
//!
//! Block ciphers expose only the raw block transform via [`BlockCipher`];
//! modes of operation (CTR, CBC, GCM, …) are layered on top separately.
//!
//! Also provides the [`ChaCha20`] stream cipher and [`Poly1305`] authenticator,
//! combined as the [`ChaCha20Poly1305`] AEAD (RFC 8439) — both inherently
//! constant time, built from 32-bit ARX and 130-bit limb arithmetic.

mod aes;
mod cbc;
mod ccm;
mod cfb;
mod chacha20;
mod chacha20poly1305;
mod ctr;
mod gcm;
mod kw;
mod ofb;
mod poly1305;
pub(crate) mod salsa20;
mod xts;

pub use aes::{Aes128, Aes192, Aes256};
pub use cbc::Cbc;
pub use ccm::{Aes128Ccm, Aes128Ccm8, Aes192Ccm, Aes256Ccm, Aes256Ccm8, Ccm};
pub use cfb::Cfb;
pub use chacha20::ChaCha20;
pub use chacha20poly1305::ChaCha20Poly1305;
pub use ctr::Ctr;
pub use gcm::{Aes128Gcm, Aes256Gcm, Gcm};
pub use kw::{
    Aes128Kw, Aes128Kwp, Aes192Kw, Aes192Kwp, Aes256Kw, Aes256Kwp, AesKw, AesKwp, KwError,
    kw_ciphertext_len, kwp_ciphertext_len,
};
pub use ofb::Ofb;
pub use poly1305::Poly1305;
pub use xts::{Aes128Xts, Aes256Xts, Xts};

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
