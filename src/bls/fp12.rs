//! The quadratic extension `Fp12 = Fp6[w] / (w² - v)`, the pairing's target
//! field.
//!
//! Elements are `c0 + c1·w` with `c0, c1 ∈ Fp6`. Besides the field
//! operations this provides the Frobenius map, the sparse line-function
//! multiplication used by the Miller loop, and the cyclotomic squaring /
//! exponentiation used by the final exponentiation's hard part.

use super::constants::{FROB_1, FROB_2, FROB_3, FROB_4, FROB_5};
use super::fp::impl_field_ops;
use super::fp2::Fp2;
use super::fp6::Fp6;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// An element `c0 + c1·w` of `GF(p¹²)`, `w² = v`.
#[derive(Clone, Copy, Default)]
pub struct Fp12 {
    /// The coefficient of `1`.
    pub c0: Fp6,
    /// The coefficient of `w`.
    pub c1: Fp6,
}

impl Fp12 {
    /// The additive identity.
    pub const ZERO: Fp12 = Fp12 {
        c0: Fp6::ZERO,
        c1: Fp6::ZERO,
    };
    /// The multiplicative identity.
    pub const ONE: Fp12 = Fp12 {
        c0: Fp6::ONE,
        c1: Fp6::ZERO,
    };

    /// Builds `c0 + c1·w`.
    #[inline]
    pub const fn new(c0: Fp6, c1: Fp6) -> Fp12 {
        Fp12 { c0, c1 }
    }

    /// Constant-time zero test.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        self.c0.is_zero() & self.c1.is_zero()
    }

    /// `self + rhs`.
    #[inline]
    pub fn add(&self, rhs: &Fp12) -> Fp12 {
        Fp12 {
            c0: self.c0.add(&rhs.c0),
            c1: self.c1.add(&rhs.c1),
        }
    }

    /// `self - rhs`.
    #[inline]
    pub fn sub(&self, rhs: &Fp12) -> Fp12 {
        Fp12 {
            c0: self.c0.sub(&rhs.c0),
            c1: self.c1.sub(&rhs.c1),
        }
    }

    /// `-self`.
    #[inline]
    pub fn neg(&self) -> Fp12 {
        Fp12 {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    /// `self · rhs` (Karatsuba over `Fp6`).
    pub fn mul(&self, rhs: &Fp12) -> Fp12 {
        let aa = self.c0.mul(&rhs.c0);
        let bb = self.c1.mul(&rhs.c1);
        let c1 = self
            .c1
            .add(&self.c0)
            .mul(&rhs.c0.add(&rhs.c1))
            .sub(&aa)
            .sub(&bb);
        let c0 = bb.mul_by_nonresidue().add(&aa);
        Fp12 { c0, c1 }
    }

    /// `self²`.
    pub fn square(&self) -> Fp12 {
        // (a + bw)² = (a² + b²v) + 2ab·w, computed as
        // c0 = (a + b)(a + bv) - ab - ab·v, c1 = 2ab.
        let ab = self.c0.mul(&self.c1);
        let c0c1 = self.c0.add(&self.c1);
        let c0 = self
            .c1
            .mul_by_nonresidue()
            .add(&self.c0)
            .mul(&c0c1)
            .sub(&ab)
            .sub(&ab.mul_by_nonresidue());
        Fp12 {
            c0,
            c1: ab.double(),
        }
    }

    /// Multiplicative inverse, `None` for zero.
    pub fn invert(&self) -> CtOption<Fp12> {
        // (a + bw)^(-1) = (a - bw) / (a² - b²v).
        let norm = self.c0.square().sub(&self.c1.square().mul_by_nonresidue());
        norm.invert().map(|t| Fp12 {
            c0: self.c0.mul(&t),
            c1: self.c1.mul(&t).neg(),
        })
    }

    /// The conjugate `c0 - c1·w`, which is `self^(p⁶)`; on the cyclotomic
    /// subgroup (where pairing values live) it equals the inverse.
    #[inline]
    pub fn conjugate(&self) -> Fp12 {
        Fp12 {
            c0: self.c0,
            c1: self.c1.neg(),
        }
    }

    /// The Frobenius endomorphism `self^p`.
    ///
    /// Each `Fp2` coefficient is conjugated, then the monomials `v`, `v²`,
    /// `w`, `vw`, `v²w` pick up the constants `ξ^(i(p-1)/6)` for
    /// `i = 2, 4, 1, 3, 5` respectively.
    pub fn frobenius_map(&self) -> Fp12 {
        Fp12 {
            c0: Fp6 {
                c0: self.c0.c0.conjugate(),
                c1: self.c0.c1.conjugate().mul(&FROB_2),
                c2: self.c0.c2.conjugate().mul(&FROB_4),
            },
            c1: Fp6 {
                c0: self.c1.c0.conjugate().mul(&FROB_1),
                c1: self.c1.c1.conjugate().mul(&FROB_3),
                c2: self.c1.c2.conjugate().mul(&FROB_5),
            },
        }
    }

    /// `self^(p^k)` by iterating the Frobenius map.
    pub fn frobenius_pow(&self, k: usize) -> Fp12 {
        let mut f = *self;
        for _ in 0..k {
            f = f.frobenius_map();
        }
        f
    }

    /// `self^e` for a little-endian limb exponent (fixed schedule, see
    /// [`Fp::pow`](super::Fp::pow)).
    pub fn pow(&self, e: &[u64]) -> Fp12 {
        let mut acc = Fp12::ONE;
        let mut i = e.len();
        while i > 0 {
            i -= 1;
            let mut bit = 64;
            while bit > 0 {
                bit -= 1;
                acc = acc.square();
                let prod = acc.mul(self);
                let take = Choice::from(((e[i] >> bit) & 1) as u8);
                acc = Fp12::conditional_select(&prod, &acc, take);
            }
        }
        acc
    }

    /// Multiplies by the sparse element `c0 + c3·(v·w) + c5·(v²·w)` — the
    /// shape of the pairing's line functions (`w³ = v·w`, `w⁵ = v²·w`).
    pub fn mul_by_035(&self, c0: &Fp2, c3: &Fp2, c5: &Fp2) -> Fp12 {
        // b = b0 + b1 w with b0 = (c0, 0, 0), b1 = (0, c3, c5).
        // a·b = (a0·b0 + a1·b1·v) + (a0·b1 + a1·b0)·w, and
        // a0·b1 + a1·b0 = (a0 + a1)(b0 + b1) - a0·b0 - a1·b1.
        let aa = self.c0.mul_by_0(c0);
        let bb = self.c1.mul_by_12(c3, c5);
        let sum = self.c0.add(&self.c1);
        let b01 = Fp6 {
            c0: *c0,
            c1: *c3,
            c2: *c5,
        };
        let c1 = sum.mul(&b01).sub(&aa).sub(&bb);
        Fp12 {
            c0: bb.mul_by_nonresidue().add(&aa),
            c1,
        }
    }

    /// Squaring restricted to the cyclotomic subgroup `G_{Φ₁₂}(p)` (Granger
    /// and Scott, "Faster squaring in the cyclotomic subgroup of sixth
    /// degree extensions", via Algorithm 5.5.4 of the *Guide to
    /// Pairing-Based Cryptography*). Only valid for elements that passed the
    /// easy part of the final exponentiation.
    pub fn cyclotomic_square(&self) -> Fp12 {
        let z0 = self.c0.c0;
        let z4 = self.c0.c1;
        let z3 = self.c0.c2;
        let z2 = self.c1.c0;
        let z1 = self.c1.c1;
        let z5 = self.c1.c2;

        let (t0, t1) = fp4_square(&z0, &z1);
        // A
        let z0 = t0.sub(&z0).double().add(&t0);
        let z1 = t1.add(&z1).double().add(&t1);

        let (t0, t1) = fp4_square(&z2, &z3);
        let (t2, t3) = fp4_square(&z4, &z5);
        // C
        let z4 = t0.sub(&z4).double().add(&t0);
        let z5 = t1.add(&z5).double().add(&t1);
        // B
        let t0 = t3.mul_by_nonresidue();
        let z2 = t0.add(&z2).double().add(&t0);
        let z3 = t2.sub(&z3).double().add(&t2);

        Fp12 {
            c0: Fp6 {
                c0: z0,
                c1: z4,
                c2: z3,
            },
            c1: Fp6 {
                c0: z2,
                c1: z1,
                c2: z5,
            },
        }
    }

    /// `self^e` for a public 64-bit exponent using cyclotomic squarings.
    /// Fixed schedule (every bit is processed); the multiplications are
    /// selected by mask so the pattern is exponent-independent too.
    pub fn cyclotomic_pow(&self, e: u64) -> Fp12 {
        let mut acc = Fp12::ONE;
        let mut bit = 64;
        while bit > 0 {
            bit -= 1;
            acc = acc.cyclotomic_square();
            let prod = acc.mul(self);
            let take = Choice::from(((e >> bit) & 1) as u8);
            acc = Fp12::conditional_select(&prod, &acc, take);
        }
        acc
    }
}

/// Squaring in `Fp4 = Fp2[w'] / (w'² - v)`-style pairs `(a, b)` ↦ `(a + b·s)²`
/// with `s² = ξ`: returns `(a² + ξ·b², 2ab)`.
#[inline]
fn fp4_square(a: &Fp2, b: &Fp2) -> (Fp2, Fp2) {
    let t0 = a.square();
    let t1 = b.square();
    let c0 = t1.mul_by_nonresidue().add(&t0);
    let c1 = a.add(b).square().sub(&t0).sub(&t1);
    (c0, c1)
}

impl Fp6 {
    /// Multiplies by the sparse element `b1·v + b2·v²`.
    pub(crate) fn mul_by_12(&self, b1: &Fp2, b2: &Fp2) -> Fp6 {
        // (a0 + a1 v + a2 v²)(b1 v + b2 v²)
        //   = ξ(a1 b2 + a2 b1) + (a0 b1 + ξ a2 b2) v + (a0 b2 + a1 b1) v².
        let a0b1 = self.c0.mul(b1);
        let a0b2 = self.c0.mul(b2);
        let a1b1 = self.c1.mul(b1);
        let a1b2 = self.c1.mul(b2);
        let a2b1 = self.c2.mul(b1);
        let a2b2 = self.c2.mul(b2);
        Fp6 {
            c0: a1b2.add(&a2b1).mul_by_nonresidue(),
            c1: a0b1.add(&a2b2.mul_by_nonresidue()),
            c2: a0b2.add(&a1b1),
        }
    }
}

impl core::fmt::Debug for Fp12 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{:?}] + [{:?}]·w", self.c0, self.c1)
    }
}

impl ConstantTimeEq for Fp12 {
    #[inline]
    fn ct_eq(&self, other: &Fp12) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1)
    }
}

impl ConditionallySelectable for Fp12 {
    #[inline]
    fn conditional_select(a: &Fp12, b: &Fp12, choice: Choice) -> Fp12 {
        Fp12 {
            c0: Fp6::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp6::conditional_select(&a.c1, &b.c1, choice),
        }
    }
}

impl PartialEq for Fp12 {
    #[inline]
    fn eq(&self, other: &Fp12) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Fp12 {}

impl_field_ops!(Fp12);

#[cfg(test)]
mod tests {
    use super::super::fp::{Fp, MODULUS};
    use super::*;

    pub(crate) fn sample() -> (Fp12, Fp12) {
        let f = |a: u64, b: u64| {
            Fp2::new(
                Fp::from_canonical(&[a, 3, 0, 0, 1, 0]),
                Fp::from_canonical(&[b, 0, 5, 0, 0, 0]),
            )
        };
        let a = Fp12::new(
            Fp6::new(f(1, 2), f(3, 4), f(5, 6)),
            Fp6::new(f(7, 8), f(9, 10), f(11, 12)),
        );
        let b = Fp12::new(
            Fp6::new(f(13, 14), f(15, 16), f(17, 18)),
            Fp6::new(f(19, 20), f(21, 22), f(23, 24)),
        );
        (a, b)
    }

    #[test]
    fn field_axioms_and_sparse_mul() {
        let (mut a, b) = sample();
        let w = Fp12::new(Fp6::ZERO, Fp6::ONE);
        assert_eq!(
            w * w,
            Fp12::new(Fp6::new(Fp2::ZERO, Fp2::ONE, Fp2::ZERO), Fp6::ZERO)
        );
        for _ in 0..10 {
            assert_eq!(a * b, b * a);
            assert_eq!(a.square(), a * a);
            assert_eq!((a + b) * (a - b), a.square() - b.square());
            assert_eq!(a * a.invert().unwrap(), Fp12::ONE);
            let sparse = Fp12::new(
                Fp6::new(b.c0.c0, Fp2::ZERO, Fp2::ZERO),
                Fp6::new(Fp2::ZERO, b.c1.c1, b.c1.c2),
            );
            assert_eq!(a.mul_by_035(&b.c0.c0, &b.c1.c1, &b.c1.c2), a * sparse);
            a = a * b + Fp12::ONE;
        }
        assert!(bool::from(Fp12::ZERO.invert().is_none()));
    }

    #[test]
    fn frobenius_is_p_power() {
        let (a, _) = sample();
        assert_eq!(a.frobenius_map(), a.pow(&MODULUS));
        assert_eq!(a.frobenius_pow(6), a.conjugate());
        assert_eq!(a.frobenius_pow(12), a);
        let (_, b) = sample();
        assert_eq!(
            (a * b).frobenius_map(),
            a.frobenius_map() * b.frobenius_map()
        );
    }

    #[test]
    fn cyclotomic_square_matches_square() {
        let (a, _) = sample();
        // Map into the cyclotomic subgroup: a^((p^6 - 1)(p^2 + 1)).
        let t = a.conjugate() * a.invert().unwrap();
        let c = t.frobenius_pow(2) * t;
        assert_eq!(c.cyclotomic_square(), c.square());
        assert_eq!(
            c.cyclotomic_pow(0xd201000000010000),
            c.pow(&[0xd201000000010000])
        );
        // Inverse equals conjugate on the subgroup.
        assert_eq!(c.conjugate() * c, Fp12::ONE);
    }
}
