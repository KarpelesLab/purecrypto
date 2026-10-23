//! The BN254 base field `GF(p)`, `p = 0x30644e72…d87cfd47` (254 bits).
//!
//! Four little-endian limbs in Montgomery form (`a·2^256 mod p`); all
//! arithmetic is the fixed-schedule limb code of
//! [`pairing_common::mont`](crate::pairing_common::mont), so it runs in
//! constant time.

use super::constants::{P, P_INV, P_MINUS_1_DIV_2, P_MINUS_2, P_PLUS_1_DIV_4, P_R, P_R2, P_R3};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crate::pairing_common::mont;
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// An element of the BN254 base field `GF(p)`.
///
/// Equality (`==`) and the [`ConstantTimeEq`] / [`ConditionallySelectable`]
/// impls are constant time. The value is stored in Montgomery form; use
/// [`to_bytes`](Fp::to_bytes) / [`from_bytes`](Fp::from_bytes) for the
/// 32-byte big-endian canonical encoding.
#[derive(Clone, Copy)]
pub struct Fp(pub(crate) [u64; 4]);

impl Fp {
    /// The additive identity.
    pub const ZERO: Fp = Fp([0; 4]);
    /// The multiplicative identity.
    pub const ONE: Fp = Fp(P_R);

    /// Constant-time zero test.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        Choice::from((mont::is_nonzero_bit(&self.0) ^ 1) as u8)
    }

    /// `self + rhs`.
    #[inline]
    pub fn add(&self, rhs: &Fp) -> Fp {
        Fp(mont::add(&self.0, &rhs.0, &P))
    }

    /// `self - rhs`.
    #[inline]
    pub fn sub(&self, rhs: &Fp) -> Fp {
        Fp(mont::sub(&self.0, &rhs.0, &P))
    }

    /// `-self`.
    #[inline]
    pub fn neg(&self) -> Fp {
        Fp(mont::neg(&self.0, &P))
    }

    /// `2·self`.
    #[inline]
    pub fn double(&self) -> Fp {
        self.add(self)
    }

    /// `self · rhs`.
    #[inline]
    pub fn mul(&self, rhs: &Fp) -> Fp {
        Fp(mont::mul(&self.0, &rhs.0, &P, P_INV))
    }

    /// `self²`.
    #[inline]
    pub fn square(&self) -> Fp {
        Fp(mont::square(&self.0, &P, P_INV))
    }

    /// `Σᵢ aᵢ·bᵢ` with one Montgomery reduction for the whole sum (see
    /// [`mont::sum_of_products`]); `M ≤ 5` since `5p < 2^256 < 6p`.
    #[inline]
    pub(crate) fn sum_of_products<const M: usize>(a: &[Fp; M], b: &[Fp; M]) -> Fp {
        const { assert!(M <= 5) };
        let mut al = [[0u64; 4]; M];
        let mut bl = [[0u64; 4]; M];
        let mut i = 0;
        while i < M {
            al[i] = a[i].0;
            bl[i] = b[i].0;
            i += 1;
        }
        Fp(mont::sum_of_products(&al, &bl, &P, P_INV))
    }

    /// `self^e` for a little-endian limb exponent. Fixed square-and-multiply
    /// schedule over every bit of `e`: the running time depends only on the
    /// exponent's limb count, so it is constant time in both `self` and `e`.
    #[inline]
    pub fn pow(&self, e: &[u64]) -> Fp {
        Fp(mont::pow(&self.0, e, &P_R, &P, P_INV))
    }

    /// `self^e` for a **public** exponent (fixed 4-bit window, see
    /// [`mont::pow_public_exp`]): constant time in `self`, not in `e`.
    #[inline]
    pub(crate) fn pow_public_exp(&self, e: &[u64]) -> Fp {
        mont::pow_public_exp(self, e, &Fp::ONE, Fp::mul, Fp::square)
    }

    /// Multiplicative inverse, `None` for zero (Fermat: `self^(p-2)`).
    #[inline]
    pub fn invert(&self) -> CtOption<Fp> {
        CtOption::new(self.pow_public_exp(&P_MINUS_2), !self.is_zero())
    }

    /// RFC 9380 `inv0`: the inverse, or zero for zero.
    #[inline]
    pub(crate) fn invert_or_zero(&self) -> Fp {
        self.pow_public_exp(&P_MINUS_2)
    }

    /// A square root, `None` when `self` is a non-residue. With
    /// `p ≡ 3 (mod 4)` the candidate is `self^((p+1)/4)`; it is verified by
    /// squaring, so the presence flag is exact.
    #[inline]
    pub fn sqrt(&self) -> CtOption<Fp> {
        let cand = self.pow_public_exp(&P_PLUS_1_DIV_4);
        CtOption::new(cand, cand.square().ct_eq(self))
    }

    /// Whether `self` is a square (zero included): Euler's criterion
    /// `self^((p-1)/2) ∈ {0, 1}`, in constant time.
    #[inline]
    pub(crate) fn is_square(&self) -> Choice {
        let l = self.pow_public_exp(&P_MINUS_1_DIV_2);
        l.ct_eq(&Fp::ONE) | self.is_zero()
    }

    /// The canonical integer representative as little-endian limbs (leaves
    /// Montgomery form by multiplying by 1).
    #[inline]
    pub(crate) fn to_canonical(self) -> [u64; 4] {
        mont::mul(&self.0, &[1, 0, 0, 0], &P, P_INV)
    }

    /// Builds an element from canonical limbs (`< p`), entering Montgomery
    /// form.
    #[inline]
    pub(crate) fn from_canonical(limbs: &[u64; 4]) -> Fp {
        Fp(mont::mul(limbs, &P_R2, &P, P_INV))
    }

    /// The canonical 32-byte big-endian encoding.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        mont::to_be_bytes(&self.to_canonical(), &mut out);
        out
    }

    /// Decodes a 32-byte big-endian integer, `None` unless it is canonical
    /// (`< p`). The returned element is meaningful only when the flag is set
    /// (a non-canonical input yields an unspecified but harmless value).
    #[inline]
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Fp> {
        let limbs = mont::from_be_bytes::<4>(bytes);
        let ok = Choice::from(mont::lt_bit(&limbs, &P) as u8);
        CtOption::new(Fp::from_canonical(&limbs), ok)
    }

    /// Reduces a 48-byte big-endian integer modulo `p` (RFC 9380
    /// `hash_to_field` with `L = 48`).
    pub(crate) fn from_bytes_wide(bytes: &[u8; 48]) -> Fp {
        // value = hi·2^256 + lo with hi the top 16 bytes. Both halves are
        // below 2^256 and the Montgomery constants below p, so each product
        // is below 2^256·p and the reductions stay canonical.
        let lo = mont::from_be_bytes::<4>(&bytes[16..]);
        let hi2 = mont::from_be_bytes::<2>(&bytes[..16]);
        let hi = [hi2[0], hi2[1], 0, 0];
        // mont(lo, R2) = lo·R; mont(hi, R3) = hi·2^512 = (hi·2^256)·R.
        let lo_m = mont::mul(&lo, &P_R2, &P, P_INV);
        let hi_m = mont::mul(&hi, &P_R3, &P, P_INV);
        Fp(mont::add(&lo_m, &hi_m, &P))
    }

    /// True when the canonical representative is greater than `(p-1)/2`,
    /// i.e. `self > -self` — the gnark-crypto "largest" flag of compressed
    /// points.
    #[inline]
    pub(crate) fn lexicographically_largest(&self) -> Choice {
        // self > (p-1)/2  <=>  !(self < (p-1)/2 + 1).
        let c = self.to_canonical();
        let mut t = P_MINUS_1_DIV_2;
        t[0] += 1;
        Choice::from((mont::lt_bit(&c, &t) ^ 1) as u8)
    }

    /// Parity of the canonical representative (RFC 9380 `sgn0` for `GF(p)`).
    #[inline]
    pub(crate) fn is_odd(&self) -> Choice {
        Choice::from((self.to_canonical()[0] & 1) as u8)
    }
}

impl Default for Fp {
    fn default() -> Self {
        Fp::ZERO
    }
}

impl core::fmt::Debug for Fp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("0x")?;
        for b in self.to_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl ConstantTimeEq for Fp {
    #[inline]
    fn ct_eq(&self, other: &Fp) -> Choice {
        mont::ct_eq(&self.0, &other.0)
    }
}

impl ConditionallySelectable for Fp {
    #[inline]
    fn conditional_select(a: &Fp, b: &Fp, choice: Choice) -> Fp {
        Fp(mont::select(&a.0, &b.0, choice))
    }
}

impl PartialEq for Fp {
    #[inline]
    fn eq(&self, other: &Fp) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Fp {}

impl Zeroize for Fp {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Implements the `core::ops` traits for owned and borrowed operands in
/// terms of the inherent `&self`/`&rhs` methods.
macro_rules! impl_field_ops {
    ($t:ty) => {
        impl<'b> Add<&'b $t> for &$t {
            type Output = $t;
            #[inline]
            fn add(self, rhs: &'b $t) -> $t {
                <$t>::add(self, rhs)
            }
        }
        impl<'b> Sub<&'b $t> for &$t {
            type Output = $t;
            #[inline]
            fn sub(self, rhs: &'b $t) -> $t {
                <$t>::sub(self, rhs)
            }
        }
        impl<'b> Mul<&'b $t> for &$t {
            type Output = $t;
            #[inline]
            fn mul(self, rhs: &'b $t) -> $t {
                <$t>::mul(self, rhs)
            }
        }
        impl Add<$t> for $t {
            type Output = $t;
            #[inline]
            fn add(self, rhs: $t) -> $t {
                <$t>::add(&self, &rhs)
            }
        }
        impl Sub<$t> for $t {
            type Output = $t;
            #[inline]
            fn sub(self, rhs: $t) -> $t {
                <$t>::sub(&self, &rhs)
            }
        }
        impl Mul<$t> for $t {
            type Output = $t;
            #[inline]
            fn mul(self, rhs: $t) -> $t {
                <$t>::mul(&self, &rhs)
            }
        }
        impl<'b> Add<&'b $t> for $t {
            type Output = $t;
            #[inline]
            fn add(self, rhs: &'b $t) -> $t {
                <$t>::add(&self, rhs)
            }
        }
        impl<'b> Sub<&'b $t> for $t {
            type Output = $t;
            #[inline]
            fn sub(self, rhs: &'b $t) -> $t {
                <$t>::sub(&self, rhs)
            }
        }
        impl<'b> Mul<&'b $t> for $t {
            type Output = $t;
            #[inline]
            fn mul(self, rhs: &'b $t) -> $t {
                <$t>::mul(&self, rhs)
            }
        }
        impl Neg for $t {
            type Output = $t;
            #[inline]
            fn neg(self) -> $t {
                <$t>::neg(&self)
            }
        }
        impl Neg for &$t {
            type Output = $t;
            #[inline]
            fn neg(self) -> $t {
                <$t>::neg(self)
            }
        }
        impl AddAssign<$t> for $t {
            #[inline]
            fn add_assign(&mut self, rhs: $t) {
                *self = <$t>::add(self, &rhs);
            }
        }
        impl SubAssign<$t> for $t {
            #[inline]
            fn sub_assign(&mut self, rhs: $t) {
                *self = <$t>::sub(self, &rhs);
            }
        }
        impl MulAssign<$t> for $t {
            #[inline]
            fn mul_assign(&mut self, rhs: $t) {
                *self = <$t>::mul(self, &rhs);
            }
        }
        impl<'b> AddAssign<&'b $t> for $t {
            #[inline]
            fn add_assign(&mut self, rhs: &'b $t) {
                *self = <$t>::add(self, rhs);
            }
        }
        impl<'b> SubAssign<&'b $t> for $t {
            #[inline]
            fn sub_assign(&mut self, rhs: &'b $t) {
                *self = <$t>::sub(self, rhs);
            }
        }
        impl<'b> MulAssign<&'b $t> for $t {
            #[inline]
            fn mul_assign(&mut self, rhs: &'b $t) {
                *self = <$t>::mul(self, rhs);
            }
        }
    };
}
pub(crate) use impl_field_ops;

impl_field_ops!(Fp);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    const P_HEX: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

    #[test]
    fn canonical_decoding() {
        assert!(bool::from(Fp::from_bytes(&from_hex(P_HEX)).is_none()));
        let mut pm1: [u8; 32] = from_hex(P_HEX);
        pm1[31] -= 1;
        let a = Fp::from_bytes(&pm1).unwrap();
        assert_eq!(a.to_bytes(), pm1);
        assert_eq!(a, -Fp::ONE);
        assert!(bool::from(Fp::from_bytes(&[0xff; 32]).is_none()));
        assert_eq!(Fp::from_bytes(&[0; 32]).unwrap(), Fp::ZERO);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(Fp::from_bytes(&one).unwrap(), Fp::ONE);
        assert_eq!(Fp::ONE.to_bytes(), one);
    }

    #[test]
    fn ring_axioms_and_inverse() {
        let mut x = Fp::from_canonical(&[0x1234_5678_9abc_def0, 7, 0xdead_beef, 0x0123_4567]);
        let y = Fp::from_canonical(&[5, 0xffff_0000_ffff_0000, 3, 0x0fed_cba9_8765_4321]);
        for _ in 0..50 {
            assert_eq!(x * y, y * x);
            assert_eq!(Fp::sum_of_products(&[x], &[y]), x * y);
            assert_eq!(Fp::sum_of_products(&[x, y], &[y, x]), (x * y).double());
            let m1 = -Fp::ONE;
            assert_eq!(
                Fp::sum_of_products(&[m1; 5], &[m1; 5]),
                Fp::from_canonical(&[5, 0, 0, 0])
            );
            assert_eq!((x + y) * (x - y), x.square() - y.square());
            assert_eq!(x * x.invert().unwrap(), Fp::ONE);
            assert_eq!(x * x.invert_or_zero(), Fp::ONE);
            assert_eq!(x.pow(&P_MINUS_2), x.invert_or_zero());
            assert_eq!(x + (-x), Fp::ZERO);
            let s = x.square();
            let r = s.sqrt().unwrap();
            assert!(r == x || r == -x);
            assert!(bool::from(s.is_square()));
            x = x * y + Fp::ONE;
        }
        assert!(bool::from(Fp::ZERO.invert().is_none()));
        assert_eq!(Fp::ZERO.invert_or_zero(), Fp::ZERO);
        assert!(bool::from(Fp::ZERO.is_square()));
        // -1 is a non-residue (p ≡ 3 mod 4).
        assert!(bool::from((-Fp::ONE).sqrt().is_none()));
        assert!(!bool::from((-Fp::ONE).is_square()));
    }

    #[test]
    fn wide_reduction_and_sign() {
        // 2^256 + 1 reduced: bytes = 00..01 (hi) || 00..01 (lo).
        let mut wide = [0u8; 48];
        wide[15] = 1;
        wide[47] = 1;
        // 2^256 mod p is the Montgomery one as a plain integer.
        let v = Fp::from_bytes_wide(&wide);
        assert_eq!(v, Fp::from_canonical(&P_R) + Fp::ONE);
        // All-ones: (2^384 - 1) mod p.
        let w = Fp::from_bytes_wide(&[0xff; 48]);
        let two128 = Fp::from_canonical(&[0, 0, 1, 0]);
        let r = Fp::from_canonical(&P_R);
        assert_eq!(w + Fp::ONE, two128 * r);
        assert!(bool::from((-Fp::ONE).lexicographically_largest()));
        assert!(!bool::from(Fp::ONE.lexicographically_largest()));
        assert!(!bool::from(Fp::ZERO.lexicographically_largest()));
        assert!(bool::from(Fp::ONE.is_odd()));
        assert!(!bool::from((-Fp::ONE).is_odd()));
    }
}
