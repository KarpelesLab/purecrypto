//! The BLS12-381 scalar field `Fr`, `r = 0x73eda753…00000001` (255 bits),
//! the order of `G1`, `G2` and `GT`. Secret keys are elements of this field.
//!
//! Four little-endian limbs in Montgomery form (`a·2^256 mod r`); all
//! arithmetic is the fixed-schedule limb code of [`mont`](super::mont).

use super::fp::impl_field_ops;
use super::mont;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// The group order `r`.
pub(crate) const MODULUS: [u64; 4] = [
    0xffffffff00000001,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];
/// `-r^(-1) mod 2^64`.
const INV: u64 = 0xfffffffeffffffff;
/// `R = 2^256 mod r`.
const R: [u64; 4] = [
    0x00000001fffffffe,
    0x5884b7fa00034802,
    0x998c4fefecbc4ff5,
    0x1824b159acc5056f,
];
/// `R² mod r`.
const R2: [u64; 4] = [
    0xc999e990f3f29c6d,
    0x2b6cedcb87925c23,
    0x05d314967254398f,
    0x0748d9d99f59ff11,
];
/// `R³ mod r`.
const R3: [u64; 4] = [
    0xc62c1807439b73af,
    0x1b3e0d188cf06990,
    0x73d13c71c7b5f418,
    0x6e2a5bb9c8db33e9,
];

/// An element of the scalar field `GF(r)`.
///
/// Comparison and selection are constant time; the 32-byte big-endian
/// encoding ([`to_bytes`](Fr::to_bytes) / [`from_bytes`](Fr::from_bytes))
/// is canonical.
#[derive(Clone, Copy)]
pub struct Fr(pub(crate) [u64; 4]);

impl Fr {
    /// The additive identity.
    pub const ZERO: Fr = Fr([0; 4]);
    /// The multiplicative identity.
    pub const ONE: Fr = Fr(R);

    /// Constant-time zero test.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        Choice::from((mont::is_nonzero_bit(&self.0) ^ 1) as u8)
    }

    /// `self + rhs`.
    #[inline]
    pub fn add(&self, rhs: &Fr) -> Fr {
        Fr(mont::add(&self.0, &rhs.0, &MODULUS))
    }

    /// `self - rhs`.
    #[inline]
    pub fn sub(&self, rhs: &Fr) -> Fr {
        Fr(mont::sub(&self.0, &rhs.0, &MODULUS))
    }

    /// `-self`.
    #[inline]
    pub fn neg(&self) -> Fr {
        Fr(mont::neg(&self.0, &MODULUS))
    }

    /// `self · rhs`.
    #[inline]
    pub fn mul(&self, rhs: &Fr) -> Fr {
        Fr(mont::mul(&self.0, &rhs.0, &MODULUS, INV))
    }

    /// `self²`.
    #[inline]
    pub fn square(&self) -> Fr {
        Fr(mont::square(&self.0, &MODULUS, INV))
    }

    /// The canonical integer representative as little-endian limbs — the
    /// form scalar multiplication consumes.
    #[inline]
    pub(crate) fn to_canonical(self) -> [u64; 4] {
        mont::mul(&self.0, &[1, 0, 0, 0], &MODULUS, INV)
    }

    /// Builds an element from a small integer.
    #[inline]
    pub fn from_u64(v: u64) -> Fr {
        Fr(mont::mul(&[v, 0, 0, 0], &R2, &MODULUS, INV))
    }

    /// The canonical 32-byte big-endian encoding.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        mont::to_be_bytes(&self.to_canonical(), &mut out);
        out
    }

    /// Decodes a 32-byte big-endian integer, `None` unless canonical (`< r`).
    #[inline]
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Fr> {
        let limbs = mont::from_be_bytes::<4>(bytes);
        let ok = mont::lt_bit(&limbs, &MODULUS) == 1;
        ok.then(|| Fr(mont::mul(&limbs, &R2, &MODULUS, INV)))
    }

    /// Reduces a 48-byte big-endian integer modulo `r` (`OS2IP(OKM) mod r`
    /// in the BLS `KeyGen`).
    pub(crate) fn from_bytes_wide(bytes: &[u8; 48]) -> Fr {
        // value = hi·2^256 + lo, hi being the top 16 bytes.
        let lo = mont::from_be_bytes::<4>(&bytes[16..]);
        let hi2 = mont::from_be_bytes::<2>(&bytes[..16]);
        let hi = [hi2[0], hi2[1], 0, 0];
        // mont(lo, R2) = lo·R; mont(hi, R3) = hi·2^512 = (hi·2^256)·R.
        let lo_m = mont::mul(&lo, &R2, &MODULUS, INV);
        let hi_m = mont::mul(&hi, &R3, &MODULUS, INV);
        Fr(mont::add(&lo_m, &hi_m, &MODULUS))
    }
}

impl Default for Fr {
    fn default() -> Self {
        Fr::ZERO
    }
}

impl core::fmt::Debug for Fr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("0x")?;
        for b in self.to_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl ConstantTimeEq for Fr {
    #[inline]
    fn ct_eq(&self, other: &Fr) -> Choice {
        mont::ct_eq(&self.0, &other.0)
    }
}

impl ConditionallySelectable for Fr {
    #[inline]
    fn conditional_select(a: &Fr, b: &Fr, choice: Choice) -> Fr {
        Fr(mont::select(&a.0, &b.0, choice))
    }
}

impl PartialEq for Fr {
    #[inline]
    fn eq(&self, other: &Fr) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Fr {}

impl Zeroize for Fr {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl_field_ops!(Fr);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_and_arithmetic() {
        let mut r_bytes = [0u8; 32];
        mont::to_be_bytes(&MODULUS, &mut r_bytes);
        assert!(Fr::from_bytes(&r_bytes).is_none());
        let mut rm1 = r_bytes;
        rm1[31] -= 1;
        let a = Fr::from_bytes(&rm1).unwrap();
        assert_eq!(a, -Fr::ONE);
        assert_eq!(a.to_bytes(), rm1);
        assert_eq!(a + Fr::ONE, Fr::ZERO);
        assert_eq!(Fr::from_u64(6) * Fr::from_u64(7), Fr::from_u64(42));
        assert_eq!(Fr::from_u64(6).square(), Fr::from_u64(36));
        assert_eq!(Fr::from_u64(5) - Fr::from_u64(7), -Fr::from_u64(2));
        assert_eq!(Fr::from_u64(3).to_canonical(), [3, 0, 0, 0]);
        // 2^256 + 1 mod r == R (as a plain integer) + 1.
        let mut wide = [0u8; 48];
        wide[15] = 1;
        wide[47] = 1;
        let expect = Fr(mont::mul(&R, &R2, &MODULUS, INV)) + Fr::ONE;
        assert_eq!(Fr::from_bytes_wide(&wide), expect);
    }
}
