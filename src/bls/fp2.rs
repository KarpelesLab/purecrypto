//! The quadratic extension `Fp2 = Fp[u] / (u² + 1)`.
//!
//! Elements are `c0 + c1·u`. The non-residue used to build `Fp6` on top is
//! `ξ = 1 + u` ([`mul_by_nonresidue`](Fp2::mul_by_nonresidue)). Everything
//! is constant time for the same reasons as [`Fp`](super::Fp): fixed
//! schedules and masked selections only.

use super::fp::{Fp, impl_field_ops};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// `(p - 1) / 2` — used by the `Fp2` square root.
const P_MINUS_1_DIV_2: [u64; 6] = [
    0xdcff7fffffffd555,
    0x0f55ffff58a9ffff,
    0xb39869507b587b12,
    0xb23ba5c279c2895f,
    0x258dd3db21a5d66b,
    0x0d0088f51cbff34d,
];

/// An element `c0 + c1·u` of `GF(p²)`, `u² = -1`.
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

    /// `self · rhs` (Karatsuba: three `Fp` multiplications).
    #[inline]
    pub fn mul(&self, rhs: &Fp2) -> Fp2 {
        let aa = self.c0.mul(&rhs.c0);
        let bb = self.c1.mul(&rhs.c1);
        let sum = self.c0.add(&self.c1).mul(&rhs.c0.add(&rhs.c1));
        Fp2 {
            c0: aa.sub(&bb),
            c1: sum.sub(&aa).sub(&bb),
        }
    }

    /// `self²` (two `Fp` multiplications).
    #[inline]
    pub fn square(&self) -> Fp2 {
        // (a + bu)² = (a + b)(a - b) + 2ab·u.
        let ab = self.c0.mul(&self.c1);
        Fp2 {
            c0: self.c0.add(&self.c1).mul(&self.c0.sub(&self.c1)),
            c1: ab.double(),
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

    /// Multiplies by the sextic non-residue `ξ = 1 + u`.
    #[inline]
    pub fn mul_by_nonresidue(&self) -> Fp2 {
        // (a + bu)(1 + u) = (a - b) + (a + b)u.
        Fp2 {
            c0: self.c0.sub(&self.c1),
            c1: self.c0.add(&self.c1),
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

    /// Multiplicative inverse, `None` for zero.
    #[inline]
    pub fn invert(&self) -> CtOption<Fp2> {
        // (a + bu)^(-1) = (a - bu) / (a² + b²).
        let norm = self.c0.square().add(&self.c1.square());
        norm.invert().map(|n| Fp2 {
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

    /// A square root, `None` when `self` is a non-residue.
    ///
    /// Algorithm 9 of <https://eprint.iacr.org/2012/685> for `p ≡ 3 (mod 4)`,
    /// made constant time: both candidate roots are computed and selected by
    /// mask, and the result is verified by squaring so the flag is exact.
    pub fn sqrt(&self) -> CtOption<Fp2> {
        // a1 = self^((p-3)/4); alpha = a1²·self = self^((p-1)/2);
        // x0 = a1·self = self^((p+1)/4).
        let a1 = self.pow(&super::fp::P_MINUS_3_DIV_4);
        let alpha = a1.square().mul(self);
        let x0 = a1.mul(self);
        // alpha == -1: self is the square of a subfield element times u,
        // the root is x0·u = -x0.c1 + x0.c0·u.
        let cand_a = Fp2 {
            c0: x0.c1.neg(),
            c1: x0.c0,
        };
        // Otherwise the root is (1 + alpha)^((p-1)/2) · x0.
        let cand_b = alpha.add(&Fp2::ONE).pow(&P_MINUS_1_DIV_2).mul(&x0);
        let is_minus_one = alpha.ct_eq(&Fp2::ONE.neg());
        let cand = Fp2::conditional_select(&cand_a, &cand_b, is_minus_one);
        CtOption::new(cand, cand.square().ct_eq(self))
    }

    /// ZCash lexicographic "largest" test for the compressed-point sort flag:
    /// `c1` largest, or `c1 == 0` and `c0` largest.
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
mod tests {
    use super::*;

    fn sample() -> (Fp2, Fp2) {
        let a = Fp2::new(
            Fp::from_canonical(&[0x1234_5678, 7, 0, 0, 0, 0]),
            Fp::from_canonical(&[0xdead_beef, 0, 3, 0, 0, 0]),
        );
        let b = Fp2::new(
            Fp::from_canonical(&[5, 0, 0, 0, 9, 0]),
            Fp::from_canonical(&[0, 0, 0, 0, 0, 0x0100]),
        );
        (a, b)
    }

    #[test]
    fn field_axioms() {
        let (mut a, b) = sample();
        let u = Fp2::new(Fp::ZERO, Fp::ONE);
        assert_eq!(u.square(), -Fp2::ONE);
        for _ in 0..30 {
            assert_eq!(a * b, b * a);
            assert_eq!(a.square(), a * a);
            assert_eq!((a + b) * (a - b), a.square() - b.square());
            assert_eq!(a * a.invert().unwrap(), Fp2::ONE);
            assert_eq!(a.mul_by_nonresidue(), a * Fp2::new(Fp::ONE, Fp::ONE));
            assert_eq!(
                a.conjugate() * a,
                Fp2::new(a.c0.square() + a.c1.square(), Fp::ZERO)
            );
            assert_eq!(a.frobenius_map(), a.pow(&super::super::fp::MODULUS));
            let r = a.square().sqrt().unwrap();
            assert!(r == a || r == -a);
            a = a * b + Fp2::ONE;
        }
        assert!(bool::from(Fp2::ZERO.invert().is_none()));
        // Roots of subfield-times-u values exercise the alpha == -1 branch.
        let t = Fp2::new(Fp::ZERO, Fp::from_canonical(&[7, 0, 0, 0, 0, 0]));
        let r = t.square().sqrt().unwrap();
        assert!(r == t || r == -t);
    }

    #[test]
    fn sign_and_order() {
        let (a, _) = sample();
        // c0 = 0x12345678 + ... is even, so sgn0 is 0 regardless of c1.
        assert!(!bool::from(a.sgn0()));
        assert!(bool::from((a + Fp2::ONE).sgn0()));
        assert!(!bool::from(Fp2::ZERO.sgn0()));
        assert!(bool::from(Fp2::new(Fp::ZERO, Fp::ONE).sgn0()));
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
