//! Runtime-sized unsigned big integers (heap-backed).
//!
//! [`BoxedUint`] stores its limbs in a [`Vec`], so its width is chosen at
//! runtime rather than in the type. This is used where a value's size is only
//! known at parse time — most importantly RSA public keys read from a
//! certificate, whose modulus size varies. The fixed-size [`Uint`](super::Uint)
//! remains the choice when the width is known at compile time.

use super::uint::{LIMB_BITS, Limb};
use alloc::vec;
use alloc::vec::Vec;

/// An unsigned integer of runtime-chosen width, stored as little-endian 64-bit
/// limbs (limb 0 is least significant).
#[derive(Clone, Debug)]
pub struct BoxedUint {
    pub(super) limbs: Vec<Limb>,
}

impl BoxedUint {
    /// The value zero, occupying `limbs` limbs.
    pub fn zero(limbs: usize) -> Self {
        BoxedUint {
            limbs: vec![0; limbs.max(1)],
        }
    }

    /// Creates a `BoxedUint` from a single 64-bit value.
    pub fn from_u64(v: u64) -> Self {
        BoxedUint { limbs: vec![v] }
    }

    /// Builds a value directly from little-endian limbs.
    pub fn from_limbs(limbs: Vec<Limb>) -> Self {
        BoxedUint {
            limbs: if limbs.is_empty() { vec![0] } else { limbs },
        }
    }

    /// Interprets `bytes` as a big-endian integer.
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let nlimbs = bytes.len().div_ceil(8).max(1);
        let mut limbs = vec![0 as Limb; nlimbs];
        let mut end = bytes.len();
        let mut i = 0;
        while end > 0 {
            let start = end.saturating_sub(8);
            let mut buf = [0u8; 8];
            let slice = &bytes[start..end];
            buf[8 - slice.len()..].copy_from_slice(slice);
            limbs[i] = Limb::from_be_bytes(buf);
            i += 1;
            end = start;
        }
        BoxedUint { limbs }
    }

    /// Serializes this integer big-endian into a `len`-byte vector (the value
    /// must fit).
    pub fn to_be_bytes(&self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for (i, &limb) in self.limbs.iter().enumerate() {
            let le = limb.to_le_bytes();
            for (b, &byte) in le.iter().enumerate() {
                let pos = i * 8 + b; // byte significance from the right
                if pos < len {
                    out[len - 1 - pos] = byte;
                }
            }
        }
        out
    }

    /// The number of limbs in the current representation.
    #[inline]
    pub fn limbs(&self) -> usize {
        self.limbs.len()
    }

    /// The limbs (little-endian).
    #[inline]
    pub fn as_limbs(&self) -> &[Limb] {
        &self.limbs
    }

    /// The bit length (most-significant set bit + 1); zero for zero.
    pub fn bit_len(&self) -> usize {
        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] != 0 {
                return i * LIMB_BITS + (LIMB_BITS - self.limbs[i].leading_zeros() as usize);
            }
        }
        0
    }

    /// Whether the value is odd.
    #[inline]
    pub fn is_odd(&self) -> bool {
        self.limbs.first().is_some_and(|l| l & 1 == 1)
    }

    /// Whether the value is zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    /// The number of significant (non-leading-zero) limbs, at least one.
    pub(super) fn significant_limbs(&self) -> usize {
        let mut n = self.limbs.len();
        while n > 1 && self.limbs[n - 1] == 0 {
            n -= 1;
        }
        n
    }

    /// Returns the limbs padded or truncated to exactly `n` limbs.
    pub(super) fn limbs_resized(&self, n: usize) -> Vec<Limb> {
        let mut v = vec![0 as Limb; n];
        let copy = self.limbs.len().min(n);
        v[..copy].copy_from_slice(&self.limbs[..copy]);
        v
    }
}

impl PartialEq for BoxedUint {
    fn eq(&self, other: &Self) -> bool {
        let n = self.limbs.len().max(other.limbs.len());
        (0..n).all(|i| {
            self.limbs.get(i).copied().unwrap_or(0) == other.limbs.get(i).copied().unwrap_or(0)
        })
    }
}

impl Eq for BoxedUint {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_roundtrip_and_properties() {
        let bytes = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10];
        let u = BoxedUint::from_be_bytes(&bytes);
        assert_eq!(u.to_be_bytes(9), bytes);
        // Zero-extends on a longer buffer.
        let mut padded = [0u8; 16];
        padded[7..].copy_from_slice(&bytes);
        assert_eq!(u.to_be_bytes(16), padded);

        assert_eq!(BoxedUint::from_u64(0).bit_len(), 0);
        assert_eq!(BoxedUint::from_u64(1).bit_len(), 1);
        assert_eq!(BoxedUint::from_u64(0xff).bit_len(), 8);
        assert!(BoxedUint::from_u64(3).is_odd());
        assert!(!BoxedUint::from_u64(4).is_odd());
        assert!(BoxedUint::zero(4).is_zero());
    }

    #[test]
    fn equality_ignores_leading_zero_limbs() {
        let a = BoxedUint::from_limbs(vec![5]);
        let b = BoxedUint::from_limbs(vec![5, 0, 0]);
        assert_eq!(a, b);
        assert_ne!(a, BoxedUint::from_limbs(vec![6]));
    }
}
