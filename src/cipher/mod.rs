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
mod ctr;

pub use aes::{Aes128, Aes192, Aes256};
pub use ctr::Ctr;

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
