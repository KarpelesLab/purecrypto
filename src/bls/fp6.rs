//! The cubic extension `Fp6 = Fp2[v] / (v³ - ξ)`, `ξ = 1 + u`.
//!
//! Elements are `c0 + c1·v + c2·v²`. Multiplication is the Karatsuba-style
//! six-`Fp2`-multiplication schedule; the sparse variants
//! ([`mul_by_1`](Fp6::mul_by_1), [`mul_by_01`](Fp6::mul_by_01)) serve the
//! pairing's line evaluations.

use super::fp::impl_field_ops;
use super::fp2::Fp2;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// An element `c0 + c1·v + c2·v²` of `GF(p⁶)`, `v³ = 1 + u`.
#[derive(Clone, Copy, Default)]
pub struct Fp6 {
    /// The coefficient of `1`.
    pub c0: Fp2,
    /// The coefficient of `v`.
    pub c1: Fp2,
    /// The coefficient of `v²`.
    pub c2: Fp2,
}

impl Fp6 {
    /// The additive identity.
    pub const ZERO: Fp6 = Fp6 {
        c0: Fp2::ZERO,
        c1: Fp2::ZERO,
        c2: Fp2::ZERO,
    };
    /// The multiplicative identity.
    pub const ONE: Fp6 = Fp6 {
        c0: Fp2::ONE,
        c1: Fp2::ZERO,
        c2: Fp2::ZERO,
    };

    /// Builds `c0 + c1·v + c2·v²`.
    #[inline]
    pub const fn new(c0: Fp2, c1: Fp2, c2: Fp2) -> Fp6 {
        Fp6 { c0, c1, c2 }
    }

    /// Constant-time zero test.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        self.c0.is_zero() & self.c1.is_zero() & self.c2.is_zero()
    }

    /// `self + rhs`.
    #[inline]
    pub fn add(&self, rhs: &Fp6) -> Fp6 {
        Fp6 {
            c0: self.c0.add(&rhs.c0),
            c1: self.c1.add(&rhs.c1),
            c2: self.c2.add(&rhs.c2),
        }
    }

    /// `self - rhs`.
    #[inline]
    pub fn sub(&self, rhs: &Fp6) -> Fp6 {
        Fp6 {
            c0: self.c0.sub(&rhs.c0),
            c1: self.c1.sub(&rhs.c1),
            c2: self.c2.sub(&rhs.c2),
        }
    }

    /// `-self`.
    #[inline]
    pub fn neg(&self) -> Fp6 {
        Fp6 {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
            c2: self.c2.neg(),
        }
    }

    /// `2·self`.
    #[inline]
    pub fn double(&self) -> Fp6 {
        self.add(self)
    }

    /// `self · rhs`.
    pub fn mul(&self, rhs: &Fp6) -> Fp6 {
        let aa = self.c0.mul(&rhs.c0);
        let bb = self.c1.mul(&rhs.c1);
        let cc = self.c2.mul(&rhs.c2);
        // c0 = aa + ξ·((a1 + a2)(b1 + b2) - bb - cc)
        let t1 = self
            .c1
            .add(&self.c2)
            .mul(&rhs.c1.add(&rhs.c2))
            .sub(&bb)
            .sub(&cc);
        let c0 = t1.mul_by_nonresidue().add(&aa);
        // c1 = (a0 + a1)(b0 + b1) - aa - bb + ξ·cc
        let t2 = self
            .c0
            .add(&self.c1)
            .mul(&rhs.c0.add(&rhs.c1))
            .sub(&aa)
            .sub(&bb);
        let c1 = t2.add(&cc.mul_by_nonresidue());
        // c2 = (a0 + a2)(b0 + b2) - aa + bb - cc
        let t3 = self
            .c0
            .add(&self.c2)
            .mul(&rhs.c0.add(&rhs.c2))
            .sub(&aa)
            .sub(&cc);
        let c2 = t3.add(&bb);
        Fp6 { c0, c1, c2 }
    }

    /// `self²` (CH-SQR2 schedule).
    pub fn square(&self) -> Fp6 {
        let s0 = self.c0.square();
        let ab = self.c0.mul(&self.c1);
        let s1 = ab.double();
        let s2 = self.c0.sub(&self.c1).add(&self.c2).square();
        let bc = self.c1.mul(&self.c2);
        let s3 = bc.double();
        let s4 = self.c2.square();
        Fp6 {
            c0: s3.mul_by_nonresidue().add(&s0),
            c1: s4.mul_by_nonresidue().add(&s1),
            c2: s1.add(&s2).add(&s3).sub(&s0).sub(&s4),
        }
    }

    /// Multiplies by `v` (the non-residue of the next extension):
    /// `(c0 + c1 v + c2 v²)·v = ξ·c2 + c0·v + c1·v²`.
    #[inline]
    pub fn mul_by_nonresidue(&self) -> Fp6 {
        Fp6 {
            c0: self.c2.mul_by_nonresidue(),
            c1: self.c0,
            c2: self.c1,
        }
    }

    /// Multiplies by an `Fp2` scalar `b0` (an element with `c1 = c2 = 0`).
    #[inline]
    pub fn mul_by_0(&self, b0: &Fp2) -> Fp6 {
        Fp6 {
            c0: self.c0.mul(b0),
            c1: self.c1.mul(b0),
            c2: self.c2.mul(b0),
        }
    }

    /// Multiplies by the sparse element `b1·v`.
    #[inline]
    pub fn mul_by_1(&self, b1: &Fp2) -> Fp6 {
        Fp6 {
            c0: self.c2.mul(b1).mul_by_nonresidue(),
            c1: self.c0.mul(b1),
            c2: self.c1.mul(b1),
        }
    }

    /// Multiplies by the sparse element `b0 + b1·v`.
    pub fn mul_by_01(&self, b0: &Fp2, b1: &Fp2) -> Fp6 {
        let aa = self.c0.mul(b0);
        let bb = self.c1.mul(b1);
        let t1 = self
            .c1
            .add(&self.c2)
            .mul(b1)
            .sub(&bb)
            .mul_by_nonresidue()
            .add(&aa);
        let t2 = self.c0.add(&self.c1).mul(&b0.add(b1)).sub(&aa).sub(&bb);
        let t3 = self.c0.add(&self.c2).mul(b0).sub(&aa).add(&bb);
        Fp6 {
            c0: t1,
            c1: t2,
            c2: t3,
        }
    }

    /// Multiplicative inverse, `None` for zero.
    pub fn invert(&self) -> CtOption<Fp6> {
        // Norm-based inversion: with
        //   c0 = a0² - ξ·a1·a2, c1 = ξ·a2² - a0·a1, c2 = a1² - a0·a2,
        // the product (a0 + a1 v + a2 v²)(c0 + c1 v + c2 v²) lies in Fp2 and
        // equals ξ·(a2·c1 + a1·c2) + a0·c0.
        let c0 = self
            .c0
            .square()
            .sub(&self.c1.mul(&self.c2).mul_by_nonresidue());
        let c1 = self
            .c2
            .square()
            .mul_by_nonresidue()
            .sub(&self.c0.mul(&self.c1));
        let c2 = self.c1.square().sub(&self.c0.mul(&self.c2));
        let t = self
            .c2
            .mul(&c1)
            .add(&self.c1.mul(&c2))
            .mul_by_nonresidue()
            .add(&self.c0.mul(&c0));
        t.invert().map(|t| Fp6 {
            c0: c0.mul(&t),
            c1: c1.mul(&t),
            c2: c2.mul(&t),
        })
    }
}

impl core::fmt::Debug for Fp6 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "({:?}) + ({:?})·v + ({:?})·v²",
            self.c0, self.c1, self.c2
        )
    }
}

impl ConstantTimeEq for Fp6 {
    #[inline]
    fn ct_eq(&self, other: &Fp6) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1) & self.c2.ct_eq(&other.c2)
    }
}

impl ConditionallySelectable for Fp6 {
    #[inline]
    fn conditional_select(a: &Fp6, b: &Fp6, choice: Choice) -> Fp6 {
        Fp6 {
            c0: Fp2::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp2::conditional_select(&a.c1, &b.c1, choice),
            c2: Fp2::conditional_select(&a.c2, &b.c2, choice),
        }
    }
}

impl PartialEq for Fp6 {
    #[inline]
    fn eq(&self, other: &Fp6) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Fp6 {}

impl_field_ops!(Fp6);

#[cfg(test)]
mod tests {
    use super::super::fp::Fp;
    use super::*;

    pub(crate) fn sample() -> (Fp6, Fp6) {
        let f = |a: u64, b: u64| {
            Fp2::new(
                Fp::from_canonical(&[a, 1, 0, 0, 0, 0]),
                Fp::from_canonical(&[b, 0, 0, 2, 0, 0]),
            )
        };
        let a = Fp6::new(f(11, 22), f(33, 44), f(55, 66));
        let b = Fp6::new(f(77, 88), f(99, 111), f(222, 333));
        (a, b)
    }

    #[test]
    fn field_axioms() {
        let (mut a, b) = sample();
        let v = Fp6::new(Fp2::ZERO, Fp2::ONE, Fp2::ZERO);
        assert_eq!(
            v * v * v,
            Fp6::new(Fp2::ONE.mul_by_nonresidue(), Fp2::ZERO, Fp2::ZERO)
        );
        for _ in 0..20 {
            assert_eq!(a * b, b * a);
            assert_eq!(a.square(), a * a);
            assert_eq!((a + b) * (a - b), a.square() - b.square());
            assert_eq!(a * a.invert().unwrap(), Fp6::ONE);
            assert_eq!(a.mul_by_nonresidue(), a * v);
            assert_eq!(a.mul_by_1(&b.c1), a * Fp6::new(Fp2::ZERO, b.c1, Fp2::ZERO));
            assert_eq!(
                a.mul_by_01(&b.c0, &b.c1),
                a * Fp6::new(b.c0, b.c1, Fp2::ZERO)
            );
            assert_eq!(a.mul_by_0(&b.c0), a * Fp6::new(b.c0, Fp2::ZERO, Fp2::ZERO));
            a = a * b + Fp6::ONE;
        }
        assert!(bool::from(Fp6::ZERO.invert().is_none()));
    }
}
