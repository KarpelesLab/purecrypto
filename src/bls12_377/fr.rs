//! The BLS12-377 scalar field `Fr`, `r = 0x12ab655e…0a11800000000001`
//! (253 bits), the order of `G1`, `G2` and `GT`.
//!
//! Four little-endian limbs in Montgomery form (`a·2^256 mod r`); all
//! arithmetic is the fixed-schedule limb code of [`mont`](super::mont).

use super::constants::{FR_INV, FR_MODULUS, FR_R, FR_R_MINUS_2, FR_R2, FR_R3};
use super::fp::impl_field_ops;
use super::mont;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// An element of the scalar field `GF(r)`.
///
/// Comparison and selection are constant time; the 32-byte encodings
/// (big-endian [`to_bytes`](Fr::to_bytes) / [`from_bytes`](Fr::from_bytes),
/// little-endian [`to_bytes_le`](Fr::to_bytes_le) /
/// [`from_bytes_le`](Fr::from_bytes_le)) are canonical. Scalars are secret
/// in most protocols: [`Zeroize`] wipes one.
#[derive(Clone, Copy)]
pub struct Fr(pub(crate) [u64; 4]);

impl Fr {
    /// The additive identity.
    pub const ZERO: Fr = Fr([0; 4]);
    /// The multiplicative identity.
    pub const ONE: Fr = Fr(FR_R);

    /// Constant-time zero test.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        Choice::from((mont::is_nonzero_bit(&self.0) ^ 1) as u8)
    }

    /// `self + rhs`.
    #[inline]
    pub fn add(&self, rhs: &Fr) -> Fr {
        Fr(mont::add(&self.0, &rhs.0, &FR_MODULUS))
    }

    /// `self - rhs`.
    #[inline]
    pub fn sub(&self, rhs: &Fr) -> Fr {
        Fr(mont::sub(&self.0, &rhs.0, &FR_MODULUS))
    }

    /// `-self`.
    #[inline]
    pub fn neg(&self) -> Fr {
        Fr(mont::neg(&self.0, &FR_MODULUS))
    }

    /// `self · rhs`.
    #[inline]
    pub fn mul(&self, rhs: &Fr) -> Fr {
        Fr(mont::mul(&self.0, &rhs.0, &FR_MODULUS, FR_INV))
    }

    /// `self²`.
    #[inline]
    pub fn square(&self) -> Fr {
        Fr(mont::square(&self.0, &FR_MODULUS, FR_INV))
    }

    /// Multiplicative inverse, `None` for zero (Fermat, `self^(r-2)`, with
    /// the exponent-oblivious ladder — constant time in `self`).
    pub fn invert(&self) -> CtOption<Fr> {
        let inv = Fr(mont::pow(
            &self.0,
            &FR_R_MINUS_2,
            &FR_R,
            &FR_MODULUS,
            FR_INV,
        ));
        CtOption::new(inv, !self.is_zero())
    }

    /// The canonical integer representative as little-endian limbs — the
    /// form scalar multiplication consumes.
    #[inline]
    pub(crate) fn to_canonical(self) -> [u64; 4] {
        mont::mul(&self.0, &[1, 0, 0, 0], &FR_MODULUS, FR_INV)
    }

    /// Builds an element from a small integer.
    #[inline]
    pub fn from_u64(v: u64) -> Fr {
        Fr(mont::mul(&[v, 0, 0, 0], &FR_R2, &FR_MODULUS, FR_INV))
    }

    /// The canonical 32-byte big-endian encoding.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        mont::to_be_bytes(&self.to_canonical(), &mut out);
        out
    }

    /// The canonical 32-byte little-endian encoding (arkworks' layout; the
    /// big-endian [`to_bytes`](Fr::to_bytes) is gnark-crypto's).
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
        let ok = crate::ct::declassify_value(mont::lt_bit(&limbs, &FR_MODULUS) == 1);
        ok.then(|| Fr(mont::mul(&limbs, &FR_R2, &FR_MODULUS, FR_INV)))
    }

    /// Decodes a 32-byte little-endian integer, `None` unless canonical.
    #[inline]
    pub fn from_bytes_le(bytes: &[u8; 32]) -> Option<Fr> {
        let mut be = *bytes;
        be.reverse();
        Fr::from_bytes(&be)
    }

    /// Reduces a 64-byte big-endian integer modulo `r` — the uniform way
    /// to turn 64 random or hashed bytes into a scalar (bias below
    /// `2^-259`). Constant time.
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Fr {
        // value = hi·2^256 + lo, both below 2^256. A Montgomery product of a
        // value below 2^256 with one below r ends below 2r, so the final
        // conditional subtraction makes it canonical.
        let lo = mont::from_be_bytes::<4>(&bytes[32..]);
        let hi = mont::from_be_bytes::<4>(&bytes[..32]);
        let lo_m = mont::mul(&lo, &FR_R2, &FR_MODULUS, FR_INV);
        let hi_m = mont::mul(&hi, &FR_R3, &FR_MODULUS, FR_INV);
        Fr(mont::add(&lo_m, &hi_m, &FR_MODULUS))
    }

    /// A uniformly random scalar (64 bytes from `rng`, reduced).
    #[cfg(feature = "rng")]
    pub fn random<R: crate::rng::RngCore + crate::rng::CryptoRng>(rng: &mut R) -> Fr {
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        let k = Fr::from_bytes_wide(&buf);
        buf.zeroize();
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
        mont::to_be_bytes(&FR_MODULUS, &mut r_bytes);
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
        assert_eq!(a + Fr::ONE, Fr::ZERO);
        assert_eq!(Fr::from_u64(6) * Fr::from_u64(7), Fr::from_u64(42));
        assert_eq!(Fr::from_u64(6).square(), Fr::from_u64(36));
        assert_eq!(Fr::from_u64(5) - Fr::from_u64(7), -Fr::from_u64(2));
        assert_eq!(Fr::from_u64(3).to_canonical(), [3, 0, 0, 0]);
        assert_eq!(Fr::from_u64(7) * Fr::from_u64(7).invert().unwrap(), Fr::ONE);
        assert!(bool::from(Fr::ZERO.invert().is_none()));
        // 2^256 + 1 mod r == R (as a plain integer) + 1.
        let mut wide = [0u8; 64];
        wide[31] = 1;
        wide[63] = 1;
        let expect = Fr(mont::mul(&FR_R, &FR_R2, &FR_MODULUS, FR_INV)) + Fr::ONE;
        assert_eq!(Fr::from_bytes_wide(&wide), expect);
        // (2^512 - 1) mod r = R·R_int... checked as (2^256 - 1)(2^256 + 1).
        let all = Fr::from_bytes_wide(&[0xff; 64]);
        let r_int = Fr(mont::mul(&FR_R, &FR_R2, &FR_MODULUS, FR_INV));
        assert_eq!(all, r_int * r_int - Fr::ONE);
    }
}
