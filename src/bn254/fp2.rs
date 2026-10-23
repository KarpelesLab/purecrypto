//! The quadratic extension `Fp2 = Fp[u] / (u² + 1)`.
//!
//! Elements are `c0 + c1·u`. The non-residue used to build `Fp6` on top is
//! `ξ = 9 + u` ([`mul_by_nonresidue`](Fp2::mul_by_nonresidue)). Everything
//! is constant time for the same reasons as [`Fp`](super::Fp): fixed
//! schedules and masked selections only.

use super::constants::{HALF, P_PLUS_1_DIV_4, P3_MINUS_5_DIV_4};
use super::fp::{Fp, impl_field_ops};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

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

    /// `self · rhs`: each output coefficient is a two-term sum of products
    /// with a single Montgomery reduction (`c0 = a0·b0 + a1·(-b1)`,
    /// `c1 = a0·b1 + a1·b0`) — the same multiply count as Karatsuba with one
    /// reduction fewer and none of its additions.
    #[inline]
    pub fn mul(&self, rhs: &Fp2) -> Fp2 {
        let nb1 = rhs.c1.neg();
        Fp2 {
            c0: Fp::sum_of_products(&[self.c0, self.c1], &[rhs.c0, nb1]),
            c1: Fp::sum_of_products(&[self.c0, self.c1], &[rhs.c1, rhs.c0]),
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

    /// Multiplies by the sextic non-residue `ξ = 9 + u`.
    #[inline]
    pub fn mul_by_nonresidue(&self) -> Fp2 {
        // (a + bu)(9 + u) = (9a - b) + (a + 9b)u, 9t = 8t + t by additions.
        let nine = |t: &Fp| t.double().double().double().add(t);
        Fp2 {
            c0: nine(&self.c0).sub(&self.c1),
            c1: nine(&self.c1).add(&self.c0),
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

    /// `self^e` for a **public** exponent (fixed 4-bit window, see
    /// `mont::pow_public_exp`): constant time in `self`, not in `e`.
    #[cfg(test)]
    pub(crate) fn pow_public_exp(&self, e: &[u64]) -> Fp2 {
        crate::pairing_common::mont::pow_public_exp(self, e, &Fp2::ONE, Fp2::mul, Fp2::square)
    }

    /// A square root, `None` when `self` is a non-residue.
    ///
    /// The norm method for `Fp2 = Fp[u]/(u² + 1)`, `p ≡ 3 (mod 4)`, in two
    /// `Fp` exponentiations and no inversion. With `a = a0 + a1·u`,
    /// `s = √(a0² + a1²)` and `δ = (a0 + s)/2`, the root is `x0 + x1·u`
    /// with `x0² ∈ {δ, δ'}` for `δ' = (a0 - s)/2 = -a1²/(4δ)` — exactly one
    /// of the two is a residue — and `2·x0·x1 = a1`. From
    /// `w = δ^((3p-5)/4) = 1/δ^((p+1)/4)`: `χ(δ) = δ·w² = ±1`,
    /// `t = χ·δ·w` squares to `δ` (residue) or `-δ` (non-residue), and
    /// `a1·w/2` is the other coordinate in both cases: the root is
    /// `t + (a1·w/2)·u` when `δ` is a residue and `(a1·w/2) + t·u`
    /// otherwise. `δ = 0` (then `a1 = 0`, `a0` a non-residue, `s = -a0`)
    /// takes `s` in place of `δ` and the second shape: `√(s)·u`.
    ///
    /// Constant time: fixed exponent schedules, both shapes computed and
    /// selected by mask; the result is verified by squaring so the flag is
    /// exact (a non-residue input yields garbage that fails the check).
    pub fn sqrt(&self) -> CtOption<Fp2> {
        let n = self.c0.square().add(&self.c1.square());
        let s = n.pow_public_exp(&P_PLUS_1_DIV_4);
        let delta = self.c0.add(&s).mul(&HALF);
        let special = delta.is_zero();
        let d = Fp::conditional_select(&s, &delta, special);
        let w = d.pow_public_exp(&P3_MINUS_5_DIV_4);
        let chi = d.mul(&w.square());
        let t = chi.mul(&d).mul(&w);
        let x1 = self.c1.mul(&w).mul(&HALF);
        let use_b = !chi.ct_eq(&Fp::ONE) | special;
        let cand_a = Fp2 { c0: t, c1: x1 };
        let cand_b = Fp2 { c0: x1, c1: t };
        let cand = Fp2::conditional_select(&cand_b, &cand_a, use_b);
        CtOption::new(cand, cand.square().ct_eq(self))
    }

    /// Whether `self` is a square (zero included): `self` is a square in
    /// `Fp2` iff its norm `c0² + c1²` is one in `Fp`. Constant time.
    #[inline]
    pub(crate) fn is_square(&self) -> Choice {
        self.c0.square().add(&self.c1.square()).is_square()
    }

    /// RFC 9380 `inv0`: the inverse, or zero for zero (constant time).
    #[inline]
    pub(crate) fn invert_or_zero(&self) -> Fp2 {
        let n = self.c0.square().add(&self.c1.square()).invert_or_zero();
        Fp2 {
            c0: self.c0.mul(&n),
            c1: self.c1.neg().mul(&n),
        }
    }

    /// The gnark-crypto lexicographic "largest" test for the compressed-point flag:
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
    use super::super::constants::{P, P_MINUS_1_DIV_2};
    use super::*;

    fn sample() -> (Fp2, Fp2) {
        let a = Fp2::new(
            Fp::from_canonical(&[0x1234_5678, 7, 0, 0]),
            Fp::from_canonical(&[0xdead_beef, 0, 3, 0]),
        );
        let b = Fp2::new(
            Fp::from_canonical(&[5, 0, 0, 9]),
            Fp::from_canonical(&[0, 0, 0x0100, 0]),
        );
        (a, b)
    }

    /// The public-exponent window against the exponent-oblivious ladder on
    /// the field's own exponents, edge exponents and pseudo-random ones.
    #[test]
    fn pow_public_exp_matches_pow() {
        let mut x = 0x0B15_0001u64;
        let mut next = || {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let mut exps: [[u64; 4]; 10] = [[0; 4]; 10];
        exps[0] = P3_MINUS_5_DIV_4;
        exps[1] = P_MINUS_1_DIV_2;
        exps[2] = [1, 0, 0, 0];
        exps[3] = [15, 0, 0, 0];
        exps[4] = [16, 0, 0, 0];
        exps[5] = [u64::MAX; 4];
        exps[6] = [0, 0, 0, 1 << 60];
        for e in &mut exps[7..] {
            *e = [next(), next(), next(), next()];
        }
        for i in 0..16 {
            let mut w = [0u8; 48];
            for c in w.chunks_mut(8) {
                c.copy_from_slice(&next().to_le_bytes());
            }
            let a = match i {
                0 => Fp::ZERO,
                1 => Fp::ONE,
                _ => Fp::from_bytes_wide(&w),
            };
            let b = Fp2::new(a, Fp::from_bytes_wide(&w).square());
            for e in &exps {
                assert_eq!(a.pow_public_exp(e), a.pow(e));
                assert_eq!(b.pow_public_exp(e), b.pow(e));
            }
        }
    }

    #[test]
    fn field_axioms() {
        let (mut a, b) = sample();
        let u = Fp2::new(Fp::ZERO, Fp::ONE);
        assert_eq!(u.square(), -Fp2::ONE);
        let xi = Fp2::new(Fp::from_canonical(&[9, 0, 0, 0]), Fp::ONE);
        for _ in 0..30 {
            assert_eq!(a * b, b * a);
            assert_eq!(a.square(), a * a);
            assert_eq!((a + b) * (a - b), a.square() - b.square());
            assert_eq!(a * a.invert().unwrap(), Fp2::ONE);
            assert_eq!(a * a.invert_or_zero(), Fp2::ONE);
            assert_eq!(a.mul_by_nonresidue(), a * xi);
            assert_eq!(a.frobenius_map(), a.pow(&P));
            let r = a.square().sqrt().unwrap();
            assert!(r == a || r == -a);
            assert!(bool::from(a.square().is_square()));
            a = a * b + Fp2::ONE;
        }
        assert!(bool::from(Fp2::ZERO.invert().is_none()));
        assert_eq!(Fp2::ZERO.invert_or_zero(), Fp2::ZERO);
        // ξ is a non-residue (it defines the sextic extension).
        assert!(!bool::from(xi.is_square()));
        assert!(bool::from(xi.sqrt().is_none()));
    }

    /// Square roots on every shape the norm method distinguishes.
    #[test]
    fn sqrt_shapes() {
        let (a, b) = sample();
        let u = Fp2::new(Fp::ZERO, Fp::ONE);
        let check = |x: Fp2| {
            let r = x.square().sqrt().unwrap();
            assert!(r == x || r == -x, "{x:?}");
        };
        assert_eq!(Fp2::ZERO.sqrt().unwrap(), Fp2::ZERO);
        assert_eq!(Fp2::ONE.sqrt().unwrap(), Fp2::ONE);
        let r = (-Fp2::ONE).sqrt().unwrap();
        assert!(r == u || r == -u);
        // A subfield non-residue (-1·4 = -4) has a root in u·Fp.
        let m4 = Fp2::new(-Fp::from_canonical(&[4, 0, 0, 0]), Fp::ZERO);
        let r = m4.sqrt().unwrap();
        assert_eq!(r.square(), m4);
        assert_eq!(r.c0, Fp::ZERO);
        check(Fp2::new(Fp::ONE.double(), Fp::ZERO));
        check(Fp2::new(Fp::ZERO, Fp::ONE.double()));
        check(u * a);
        check(a);
        check(b);
        check(a * b);
        check(a + u);
        let xi = Fp2::new(Fp::from_canonical(&[9, 0, 0, 0]), Fp::ONE);
        assert!(bool::from((xi * a.square()).sqrt().is_none()));
        assert!(!bool::from((xi * a.square()).is_square()));
    }

    #[test]
    fn sign_and_order() {
        let (a, _) = sample();
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
