//! Thin wrappers over [`crate::zeroize::Zeroize`] for the hasher states.
//!
//! Kept so the per-algorithm `Digest::zeroize` impls read as
//! `zero_words(&mut self.h); zero_bytes(&mut self.block)`; the wiping itself
//! is the volatile-store one from the public [`zeroize`](crate::zeroize)
//! module.

use crate::zeroize::Zeroize;

/// Overwrites `bytes` with zeros.
#[inline]
pub(super) fn zero_bytes(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Overwrites a slice of integer words with zeros.
#[inline]
pub(super) fn zero_words<T: Zeroize>(words: &mut [T]) {
    words.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipes() {
        let mut bytes = [0xABu8; 16];
        zero_bytes(&mut bytes);
        assert_eq!(bytes, [0u8; 16]);

        let mut words = [0xDEAD_BEEFu32; 8];
        zero_words(&mut words);
        assert_eq!(words, [0u32; 8]);
    }
}
