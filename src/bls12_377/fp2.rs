//! The quadratic extension `Fp2 = Fp[u] / (u² + 5)`.
//!
//! Elements are `c0 + c1·u`. The non-residue used to build `Fp6` on top is
//! `ξ = u` ([`mul_by_nonresidue`](Fp2::mul_by_nonresidue)). Everything is
//! constant time for the same reasons as [`Fp`](super::Fp): fixed schedules
//! and masked selections only.

use super::constants::{FP2_SR_C1, FP2_SR_C3, FP2_SR_C6, FP2_SR_C7};
use super::fp::{Fp, impl_field_ops};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// An element `c0 + c1·u` of `GF(p²)`, `u² = -5`.
#[derive(Clone, Copy, Default)]
pub struct Fp2 {
    /// The `Fp` coefficient of `1`.
    pub c0: Fp,
    /// The `Fp` coefficient of `u`.
    pub c1: Fp,
}

impl Fp2 {
    /// The additive identity.
    pub const ZERO: Fp2 = Fp2 {
        c0: Fp::ZERO,
        c1: Fp::ZERO,
    };
    /// The multiplicative identity.
    pub const ONE: Fp2 = Fp2 {
        c0: Fp::ONE,
        c1: Fp::ZERO,
    };

    /// Builds `c0 + c1·u`.
    #[inline]
    pub const fn new(c0: Fp, c1: Fp) -> Fp2 {
        Fp2 { c0, c1 }
    }

    /// Constant-time zero test.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        self.c0.is_zero() & self.c1.is_zero()
    }

    /// `self + rhs`.
    #[inline]
    pub fn add(&self, rhs: &Fp2) -> Fp2 {
        Fp2 {
            c0: self.c0.add(&rhs.c0),
            c1: self.c1.add(&rhs.c1),
        }
    }

    /// `self - rhs`.
    #[inline]
    pub fn sub(&self, rhs: &Fp2) -> Fp2 {
        Fp2 {
            c0: self.c0.sub(&rhs.c0),
            c1: self.c1.sub(&rhs.c1),
        }
    }

    /// `-self`.
    #[inline]
    pub fn neg(&self) -> Fp2 {
        Fp2 {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    /// `2·self`.
    #[inline]
    pub fn double(&self) -> Fp2 {
        self.add(self)
    }

    /// `self · rhs`: each output coefficient is a two-term sum of products
    /// with a single Montgomery reduction (`c0 = a0·b0 + a1·(-5·b1)`,
    /// `c1 = a0·b1 + a1·b0`).
    #[inline]
    pub fn mul(&self, rhs: &Fp2) -> Fp2 {
        let nb1 = rhs.c1.mul_by_5().neg();
        Fp2 {
            c0: Fp::sum_of_products(&[self.c0, self.c1], &[rhs.c0, nb1]),
            c1: Fp::sum_of_products(&[self.c0, self.c1], &[rhs.c1, rhs.c0]),
        }
    }

    /// `self²` (two `Fp` multiplications).
    #[inline]
    pub fn square(&self) -> Fp2 {
        // (a + bu)² = (a² - 5b²) + 2ab·u, with a² - 5b² = (a + b)(a - 5b) + 4ab.
        let ab = self.c0.mul(&self.c1);
        let t = self.c0.add(&self.c1).mul(&self.c0.sub(&self.c1.mul_by_5()));
        let ab2 = ab.double();
        Fp2 {
            c0: t.add(&ab2.double()),
            c1: ab2,
        }
    }

    /// Multiplies by an `Fp` scalar.
    #[inline]
    pub fn mul_by_fp(&self, k: &Fp) -> Fp2 {
        Fp2 {
            c0: self.c0.mul(k),
            c1: self.c1.mul(k),
        }
    }

    /// Multiplies by the sextic non-residue `ξ = u`:
    /// `(a + bu)·u = -5b + a·u`.
    #[inline]
    pub fn mul_by_nonresidue(&self) -> Fp2 {
        Fp2 {
            c0: self.c1.mul_by_5().neg(),
            c1: self.c0,
        }
    }

    /// The conjugate `c0 - c1·u`, which is also the Frobenius map `self^p`.
    #[inline]
    pub fn conjugate(&self) -> Fp2 {
        Fp2 {
            c0: self.c0,
            c1: self.c1.neg(),
        }
    }

    /// `self^p` (equals [`conjugate`](Fp2::conjugate)).
    #[inline]
    pub fn frobenius_map(&self) -> Fp2 {
        self.conjugate()
    }

    /// The norm `c0² + 5·c1²` (in `Fp`).
    #[inline]
    pub(crate) fn norm(&self) -> Fp {
        self.c0.square().add(&self.c1.square().mul_by_5())
    }

    /// Multiplicative inverse, `None` for zero.
    #[inline]
    pub fn invert(&self) -> CtOption<Fp2> {
        // (a + bu)^(-1) = (a - bu) / (a² + 5b²).
        self.norm().invert().map(|n| Fp2 {
            c0: self.c0.mul(&n),
            c1: self.c1.neg().mul(&n),
        })
    }

    /// `self^e` for a little-endian limb exponent (fixed schedule, see
    /// [`Fp::pow`]).
    pub fn pow(&self, e: &[u64]) -> Fp2 {
        let mut acc = Fp2::ONE;
        let mut i = e.len();
        while i > 0 {
            i -= 1;
            let mut bit = 64;
            while bit > 0 {
                bit -= 1;
                acc = acc.square();
                let prod = acc.mul(self);
                let take = Choice::from(((e[i] >> bit) & 1) as u8);
                acc = Fp2::conditional_select(&prod, &acc, take);
            }
        }
        acc
    }

    /// `self^e` for a **public** exponent (fixed 4-bit window, see
    /// [`super::mont::pow_public_exp`]): constant time in `self`, not in `e`.
    #[inline]
    pub(crate) fn pow_public_exp(&self, e: &[u64]) -> Fp2 {
        super::mont::pow_public_exp(self, e, &Fp2::ONE, Fp2::mul, Fp2::square)
    }

    /// RFC 9380 `sqrt_ratio` with the G2 SSWU constant `Z = 12 + u`.
    #[inline]
    pub(crate) fn sqrt_ratio(u: &Fp2, v: &Fp2) -> (Choice, Fp2) {
        super::curve::sqrt_ratio(u, v, FP2_SR_C1, &FP2_SR_C3, &FP2_SR_C6, &FP2_SR_C7)
    }

    /// A square root, `None` when `self` is a non-residue: the
    /// fixed-schedule `sqrt_ratio(self, 1)` (`p² - 1` has 2-adicity 47),
    /// verified by squaring so the flag is exact.
    pub fn sqrt(&self) -> CtOption<Fp2> {
        let (_, cand) = Fp2::sqrt_ratio(self, &Fp2::ONE);
        CtOption::new(cand, cand.square().ct_eq(self))
    }

    /// Lexicographic "largest" test for the compressed-point sort flag
    /// (gnark-crypto and arkworks agree): `c1` largest, or `c1 == 0` and
    /// `c0` largest.
    #[inline]
    pub(crate) fn lexicographically_largest(&self) -> Choice {
        self.c1.lexicographically_largest()
            | (self.c1.is_zero() & self.c0.lexicographically_largest())
    }

    /// RFC 9380 `sgn0` for `GF(p²)`: the parity of `c0`, or of `c1` when
    /// `c0 == 0`.
    #[inline]
    pub(crate) fn sgn0(&self) -> Choice {
        self.c0.is_odd() | (self.c0.is_zero() & self.c1.is_odd())
    }
}

impl core::fmt::Debug for Fp2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?} + {:?}·u", self.c0, self.c1)
    }
}

impl ConstantTimeEq for Fp2 {
    #[inline]
    fn ct_eq(&self, other: &Fp2) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1)
    }
}

impl ConditionallySelectable for Fp2 {
    #[inline]
    fn conditional_select(a: &Fp2, b: &Fp2, choice: Choice) -> Fp2 {
        Fp2 {
            c0: Fp::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp::conditional_select(&a.c1, &b.c1, choice),
        }
    }
}

impl PartialEq for Fp2 {
    #[inline]
    fn eq(&self, other: &Fp2) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Fp2 {}

impl Zeroize for Fp2 {
    fn zeroize(&mut self) {
        self.c0.zeroize();
        self.c1.zeroize();
    }
}

impl_field_ops!(Fp2);

#[cfg(test)]
pub(crate) mod tests {
    use super::super::constants::FP_MODULUS;
    use super::*;

    pub(crate) fn sample(i: u64) -> Fp2 {
        let f = |k: u64| {
            let mut w = [0u8; 64];
            for (j, c) in w.chunks_mut(8).enumerate() {
                let v = (k + 1)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .rotate_left(j as u32 * 9)
                    ^ 0x0123_4567_89ab_cdef;
                c.copy_from_slice(&v.to_be_bytes());
            }
            Fp::from_bytes_wide(&w)
        };
        Fp2::new(f(2 * i), f(2 * i + 1))
    }

    #[test]
    fn field_axioms() {
        let u = Fp2::new(Fp::ZERO, Fp::ONE);
        let five = Fp::from_canonical(&[5, 0, 0, 0, 0, 0]);
        assert_eq!(u.square(), Fp2::new(-five, Fp::ZERO));
        for i in 0..30 {
            let a = sample(i);
            let b = sample(i + 50);
            assert_eq!(a * b, b * a);
            assert_eq!(a.square(), a * a);
            assert_eq!((a + b) * (a - b), a.square() - b.square());
            assert_eq!(a * a.invert().unwrap(), Fp2::ONE);
            assert_eq!(a.mul_by_nonresidue(), a * u);
            assert_eq!(a.conjugate() * a, Fp2::new(a.norm(), Fp::ZERO));
            assert_eq!(a.frobenius_map(), a.pow(&FP_MODULUS));
            let r = a.square().sqrt().unwrap();
            assert!(r == a || r == -a);
            let (qr, w) = Fp2::sqrt_ratio(&a, &b);
            let z = Fp2::new(Fp::from_canonical(&[12, 0, 0, 0, 0, 0]), Fp::ONE);
            if bool::from(qr) {
                assert_eq!(w.square() * b, a);
            } else {
                assert_eq!(w.square() * b, a * z);
            }
        }
        assert!(bool::from(Fp2::ZERO.invert().is_none()));
        assert_eq!(Fp2::ZERO.sqrt().unwrap(), Fp2::ZERO);
        // u is the sextic non-residue: neither a square nor (checked in
        // the tower tests) a cube.
        assert!(bool::from(u.sqrt().is_none()));
        // Subfield elements are all squares in Fp2.
        assert!(bool::from(Fp2::new(five, Fp::ZERO).sqrt().is_some()));
        assert!(bool::from(Fp2::new(-Fp::ONE, Fp::ZERO).sqrt().is_some()));
        let t = Fp2::new(Fp::ZERO, Fp::from_canonical(&[7, 0, 0, 0, 0, 0]));
        let r = t.square().sqrt().unwrap();
        assert!(r == t || r == -t);
    }

    #[test]
    fn pow_public_exp_matches_pow() {
        for i in 0..6 {
            let a = sample(i);
            for e in [
                [0u64; 6],
                [1, 0, 0, 0, 0, 0],
                [15, 0, 0, 0, 0, 0],
                [16, 0, 0, 0, 0, 0],
                [u64::MAX; 6],
                FP_MODULUS,
            ] {
                assert_eq!(a.pow_public_exp(&e), a.pow(&e));
                assert_eq!(a.c0.pow_public_exp(&e), a.c0.pow(&e));
            }
        }
    }

    #[test]
    fn sign_and_order() {
        assert!(!bool::from(Fp2::ZERO.sgn0()));
        assert!(bool::from(Fp2::ONE.sgn0()));
        assert!(bool::from(Fp2::new(Fp::ZERO, Fp::ONE).sgn0()));
        assert!(!bool::from(Fp2::new(Fp::ONE.double(), Fp::ONE).sgn0()));
        assert!(bool::from(
            Fp2::new(Fp::ZERO, -Fp::ONE).lexicographically_largest()
        ));
        assert!(bool::from(
            Fp2::new(-Fp::ONE, Fp::ZERO).lexicographically_largest()
        ));
        assert!(!bool::from(
            Fp2::new(-Fp::ONE, Fp::ONE).lexicographically_largest()
        ));
    }
}
