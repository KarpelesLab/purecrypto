//! The BN254 scalar field `Fr`, `r = 0x30644e72…f0000001` (254 bits), the
//! order of `G1`, `G2` and `GT`.
//!
//! Four little-endian limbs in Montgomery form (`a·2^256 mod r`); all
//! arithmetic is the fixed-schedule limb code of
//! [`pairing_common::mont`](crate::pairing_common::mont).

use super::constants::{R_INV, R_MINUS_2, R_MOD, R_R, R_R2, R_R3};
use super::fp::impl_field_ops;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crate::pairing_common::mont;
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// An element of the scalar field `GF(r)`.
///
/// Comparison and selection are constant time; the 32-byte encodings
/// ([`to_bytes`](Fr::to_bytes) big-endian, [`to_bytes_le`](Fr::to_bytes_le)
/// little-endian) are canonical. Implements [`Zeroize`]: wipe secret
/// scalars when done with them.
#[derive(Clone, Copy)]
pub struct Fr(pub(crate) [u64; 4]);

impl Fr {
    /// The additive identity.
    pub const ZERO: Fr = Fr([0; 4]);
    /// The multiplicative identity.
    pub const ONE: Fr = Fr(R_R);

    /// Constant-time zero test.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        Choice::from((mont::is_nonzero_bit(&self.0) ^ 1) as u8)
    }

    /// `self + rhs`.
    #[inline]
    pub fn add(&self, rhs: &Fr) -> Fr {
        Fr(mont::add(&self.0, &rhs.0, &R_MOD))
    }

    /// `self - rhs`.
    #[inline]
    pub fn sub(&self, rhs: &Fr) -> Fr {
        Fr(mont::sub(&self.0, &rhs.0, &R_MOD))
    }

    /// `-self`.
    #[inline]
    pub fn neg(&self) -> Fr {
        Fr(mont::neg(&self.0, &R_MOD))
    }

    /// `2·self`.
    #[inline]
    pub fn double(&self) -> Fr {
        self.add(self)
    }

    /// `self · rhs`.
    #[inline]
    pub fn mul(&self, rhs: &Fr) -> Fr {
        Fr(mont::mul(&self.0, &rhs.0, &R_MOD, R_INV))
    }

    /// `self²`.
    #[inline]
    pub fn square(&self) -> Fr {
        Fr(mont::square(&self.0, &R_MOD, R_INV))
    }

    /// `self^e` for a little-endian limb exponent (fixed schedule over every
    /// bit of `e`, constant time in both operands).
    #[inline]
    pub fn pow(&self, e: &[u64]) -> Fr {
        Fr(mont::pow(&self.0, e, &R_R, &R_MOD, R_INV))
    }

    /// Multiplicative inverse, `None` for zero (Fermat: `self^(r-2)`,
    /// constant time).
    #[inline]
    pub fn invert(&self) -> CtOption<Fr> {
        let inv = mont::pow_public_exp(self, &R_MINUS_2, &Fr::ONE, Fr::mul, Fr::square);
        CtOption::new(inv, !self.is_zero())
    }

    /// The canonical integer representative as little-endian limbs — the
    /// form scalar multiplication consumes.
    #[inline]
    pub(crate) fn to_canonical(self) -> [u64; 4] {
        mont::mul(&self.0, &[1, 0, 0, 0], &R_MOD, R_INV)
    }

    /// Builds an element from a small integer.
    #[inline]
    pub fn from_u64(v: u64) -> Fr {
        Fr(mont::mul(&[v, 0, 0, 0], &R_R2, &R_MOD, R_INV))
    }

    /// The canonical 32-byte big-endian encoding.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        mont::to_be_bytes(&self.to_canonical(), &mut out);
        out
    }

    /// The canonical 32-byte little-endian encoding.
    #[inline]
    pub fn to_bytes_le(&self) -> [u8; 32] {
        let mut out = self.to_bytes();
        out.reverse();
        out
    }

    /// Decodes a 32-byte big-endian integer, `None` unless canonical (`< r`).
    #[inline]
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Fr> {
        let limbs = mont::from_be_bytes::<4>(bytes);
        // The canonicity verdict is public: the caller sees it as `None`.
        let ok = crate::ct::declassify_value(mont::lt_bit(&limbs, &R_MOD) == 1);
        ok.then(|| Fr(mont::mul(&limbs, &R_R2, &R_MOD, R_INV)))
    }

    /// Decodes a 32-byte little-endian integer, `None` unless canonical.
    #[inline]
    pub fn from_bytes_le(bytes: &[u8; 32]) -> Option<Fr> {
        let mut be = *bytes;
        be.reverse();
        let r = Self::from_bytes(&be);
        be.zeroize();
        r
    }

    /// Reduces a 64-byte big-endian integer modulo `r`. Fed 64 uniformly
    /// random bytes this gives a scalar whose bias is below `2^-256`.
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Fr {
        // value = hi·2^256 + lo. Each half is below 2^256 and the Montgomery
        // constants below r, so each product is below 2^256·r and the
        // reductions stay canonical.
        let lo = mont::from_be_bytes::<4>(&bytes[32..]);
        let hi = mont::from_be_bytes::<4>(&bytes[..32]);
        // mont(lo, R2) = lo·R; mont(hi, R3) = hi·2^512 = (hi·2^256)·R.
        let lo_m = mont::mul(&lo, &R_R2, &R_MOD, R_INV);
        let hi_m = mont::mul(&hi, &R_R3, &R_MOD, R_INV);
        Fr(mont::add(&lo_m, &hi_m, &R_MOD))
    }

    /// A uniformly random scalar (64 bytes from `rng`, reduced).
    #[cfg(feature = "rng")]
    pub fn random<R: crate::rng::RngCore + crate::rng::CryptoRng>(rng: &mut R) -> Fr {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        let k = Self::from_bytes_wide(&wide);
        wide.zeroize();
        k
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
        mont::to_be_bytes(&R_MOD, &mut r_bytes);
        assert!(Fr::from_bytes(&r_bytes).is_none());
        let mut rm1 = r_bytes;
        rm1[31] -= 1;
        let a = Fr::from_bytes(&rm1).unwrap();
        assert_eq!(a, -Fr::ONE);
        assert_eq!(a.to_bytes(), rm1);
        let mut le = rm1;
        le.reverse();
        assert_eq!(a.to_bytes_le(), le);
        assert_eq!(Fr::from_bytes_le(&le).unwrap(), a);
        let mut r_le = r_bytes;
        r_le.reverse();
        assert!(Fr::from_bytes_le(&r_le).is_none());
        assert_eq!(a + Fr::ONE, Fr::ZERO);
        assert_eq!(Fr::from_u64(6) * Fr::from_u64(7), Fr::from_u64(42));
        assert_eq!(Fr::from_u64(6).square(), Fr::from_u64(36));
        assert_eq!(Fr::from_u64(5) - Fr::from_u64(7), -Fr::from_u64(2));
        assert_eq!(Fr::from_u64(3).to_canonical(), [3, 0, 0, 0]);
        assert_eq!(Fr::from_u64(7) * Fr::from_u64(7).invert().unwrap(), Fr::ONE);
        assert!(bool::from(Fr::ZERO.invert().is_none()));
        assert_eq!(Fr::from_u64(3).pow(&[5]), Fr::from_u64(243));
        // 2^256 + 1 mod r == R (as a plain integer) + 1.
        let mut wide = [0u8; 64];
        wide[31] = 1;
        wide[63] = 1;
        let expect = Fr(mont::mul(&R_R, &R_R2, &R_MOD, R_INV)) + Fr::ONE;
        assert_eq!(Fr::from_bytes_wide(&wide), expect);
        // (2^512 - 1) mod r = R² - 1 as plain integers.
        let all = Fr::from_bytes_wide(&[0xff; 64]);
        let r2 = Fr(mont::mul(&R_R2, &R_R2, &R_MOD, R_INV));
        assert_eq!(all + Fr::ONE, r2);
    }
}
