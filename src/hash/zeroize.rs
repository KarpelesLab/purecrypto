//! Best-effort secret wiping, without `unsafe` or external dependencies.
//!
//! The values are overwritten with zeros and then passed through
//! [`core::hint::black_box`], the same optimization barrier the
//! [`ct`](crate::ct) module relies on, to discourage the compiler from
//! eliminating the writes as a dead store. This is best-effort: a true
//! guarantee would require volatile writes, but those need `unsafe`, which this
//! crate forbids.

/// Overwrites `bytes` with zeros.
#[inline]
pub(super) fn zero_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(bytes);
}

/// Overwrites a slice of integer words with zeros.
#[inline]
pub(super) fn zero_words<T: Default + Copy>(words: &mut [T]) {
    for w in words.iter_mut() {
        *w = T::default();
    }
    let _ = core::hint::black_box(words);
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
