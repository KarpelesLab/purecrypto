//! Symmetric ciphers.
//!
//! Currently provides the AES block cipher ([`Aes128`], [`Aes192`],
//! [`Aes256`]) with a constant-time implementation: the S-box is computed by
//! GF(2⁸) inversion rather than table lookup, so there are no
//! secret-dependent memory accesses and hence no cache-timing leak.
//!
//! Block ciphers expose only the raw block transform via [`BlockCipher`];
//! modes of operation (CTR, CBC, GCM, …) are layered on top separately.

mod aes;
mod cbc;
mod cfb;
mod ctr;
mod ofb;

pub use aes::{Aes128, Aes192, Aes256};
pub use cbc::Cbc;
pub use cfb::Cfb;
pub use ctr::Ctr;
pub use ofb::Ofb;

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
