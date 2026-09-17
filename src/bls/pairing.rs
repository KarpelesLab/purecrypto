//! The optimal ate pairing `e: G1 × G2 → GT`.
//!
//! `e(P, Q) = f_{x,Q}(P)^((p¹² - 1)/r)` with the BLS parameter
//! `x = -0xd201000000010000`. The Miller loop keeps the `G2` accumulator on
//! the twist in projective coordinates and evaluates the line functions
//! through the untwist `ψ(x', y') = (x'·w⁻², y'·w⁻³)` directly at `P`, so
//! each line is a sparse `Fp12` element `c0 + c3·w³ + c5·w⁵` (the scaling by
//! `Fp2` constants is absorbed by the final exponentiation). The final
//! exponentiation uses the standard easy part `(p⁶ - 1)(p² + 1)` and, for
//! the hard part `(p⁴ - p² + 1)/r`, the polynomial identity
//! `3·λ = (x - 1)²·(x + p)·(x² + p² - 1) + 3` (Hayashida, Hayasaka and
//! Teruya, <https://eprint.iacr.org/2020/875>), i.e.
//! `λ = ((x-1)/3)·(x-1)·(x+p)·(x²+p²-1) + 1` with `(x - 1)/3` integral.

use super::fp2::Fp2;
use super::fp12::Fp12;
use super::fr::Fr;
use super::g1::G1;
use super::g2::G2;
use super::{constants::B2_3, curve::Projective};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};

/// `|x|`, `|x - 1|` and `|(x - 1)/3|` for the hard part.
const X_ABS: u64 = 0xd201000000010000;
const X_MINUS_1_ABS: u64 = 0xd201000000010001;
const X_MINUS_1_DIV_3_ABS: u64 = 0x460055555555aaab;

/// An element of `GT`, the order-`r` subgroup of `Fp12*` that pairings land
/// in. The group operation is written multiplicatively ([`Gt::mul`]).
#[derive(Clone, Copy, Debug)]
pub struct Gt(pub(crate) Fp12);

impl Gt {
    /// The identity (the field element `1`).
    pub const IDENTITY: Gt = Gt(Fp12::ONE);

    /// Constant-time identity test.
    #[inline]
    pub fn is_identity(&self) -> Choice {
        self.0.ct_eq(&Fp12::ONE)
    }

    /// The group operation `self · rhs`.
    #[inline]
    pub fn mul(&self, rhs: &Gt) -> Gt {
        Gt(self.0.mul(&rhs.0))
    }

    /// The inverse (a conjugation on the cyclotomic subgroup).
    #[inline]
    pub fn inverse(&self) -> Gt {
        Gt(self.0.conjugate())
    }

    /// `self^k`, fixed schedule in `k`.
    pub fn pow(&self, k: &Fr) -> Gt {
        Gt(self.0.pow(&k.to_canonical()))
    }

    /// The underlying `Fp12` element.
    #[inline]
    pub fn as_fp12(&self) -> &Fp12 {
        &self.0
    }
}

impl ConstantTimeEq for Gt {
    #[inline]
    fn ct_eq(&self, other: &Gt) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Gt {
    #[inline]
    fn eq(&self, other: &Gt) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Gt {}

/// The pairing `e(P, Q)`; `e(𝒪, Q) = e(P, 𝒪) = 1`.
pub fn pairing(p: &G1, q: &G2) -> Gt {
    Gt(final_exponentiation(&miller_loop(p, q)))
}

/// `∏ e(Pᵢ, Qᵢ)` with a single final exponentiation — the cheap way to
/// evaluate a product-of-pairings equation such as a signature check.
pub fn multi_pairing(pairs: &[(&G1, &G2)]) -> Gt {
    let mut f = Fp12::ONE;
    for (p, q) in pairs {
        f = f.mul(&miller_loop(p, q));
    }
    Gt(final_exponentiation(&f))
}

/// The line through `T` and `2T` (before doubling), evaluated at `P`,
/// scaled by `ξ·2yT·Z³/Z`: `(ξ·2YZ·yP, Y² - 3b'Z², -3X²·xP)`.
#[inline]
fn doubling_line(t: &Projective<Fp2>, px: &super::fp::Fp, py: &super::fp::Fp) -> (Fp2, Fp2, Fp2) {
    let c0 = t.y.mul(&t.z).double().mul_by_nonresidue().mul_by_fp(py);
    let c3 = t.y.square().sub(&B2_3.mul(&t.z.square()));
    let x2 = t.x.square();
    let c5 = x2.double().add(&x2).mul_by_fp(px).neg();
    (c0, c3, c5)
}

/// The line through `T` and `Q` (affine), evaluated at `P`, scaled by
/// `ξ·(X - xQ·Z)`: `(ξ·(X - xQ·Z)·yP, xQ·Y - yQ·X, -(Y - yQ·Z)·xP)`.
#[inline]
fn addition_line(
    t: &Projective<Fp2>,
    qx: &Fp2,
    qy: &Fp2,
    px: &super::fp::Fp,
    py: &super::fp::Fp,
) -> (Fp2, Fp2, Fp2) {
    let c0 = t.x.sub(&qx.mul(&t.z)).mul_by_nonresidue().mul_by_fp(py);
    let c3 = qx.mul(&t.y).sub(&qy.mul(&t.x));
    let c5 = t.y.sub(&qy.mul(&t.z)).mul_by_fp(px).neg();
    (c0, c3, c5)
}

/// `f_{|x|,Q}(P)` conjugated (since `x < 0`), or `1` if either input is the
/// identity. Runs a fixed schedule over the public loop constant.
pub(crate) fn miller_loop(p: &G1, q: &G2) -> Fp12 {
    let (px, py, p_inf) = p.0.to_affine();
    let (qx, qy, q_inf) = q.0.to_affine();
    let q_aff = Projective::from_affine(qx, qy);
    let mut t = q_aff;
    let mut f = Fp12::ONE;
    // Bit 63 of |x| is set; start below it with f = 1, T = Q.
    for bit in (0..63).rev() {
        f = f.square();
        let (c0, c3, c5) = doubling_line(&t, &px, &py);
        f = f.mul_by_035(&c0, &c3, &c5);
        t = t.double();
        if (X_ABS >> bit) & 1 == 1 {
            let (c0, c3, c5) = addition_line(&t, &qx, &qy, &px, &py);
            f = f.mul_by_035(&c0, &c3, &c5);
            t = t.add(&q_aff);
        }
    }
    let f = f.conjugate();
    Fp12::conditional_select(&Fp12::ONE, &f, p_inf | q_inf)
}

/// `f^((p¹² - 1)/r)`.
pub(crate) fn final_exponentiation(f: &Fp12) -> Fp12 {
    // Easy part: f^((p⁶ - 1)(p² + 1)). Miller-loop outputs are nonzero;
    // a zero input maps to zero rather than panicking.
    let inv = f.invert().unwrap_or(Fp12::ZERO);
    let t = f.conjugate().mul(&inv);
    let m = t.frobenius_pow(2).mul(&t);
    // Hard part on the cyclotomic subgroup, where x^k with x < 0 is
    // cyclotomic_pow(|x|^k) followed by a conjugation (= inversion).
    // a = m^((x-1)/3)
    let a = m.cyclotomic_pow(X_MINUS_1_DIV_3_ABS).conjugate();
    // a = m^((x-1)²/3)
    let a = a.cyclotomic_pow(X_MINUS_1_ABS).conjugate();
    // b = a^(x + p)
    let b = a.cyclotomic_pow(X_ABS).conjugate().mul(&a.frobenius_map());
    // c = b^(x² + p² - 1)
    let bx2 = b.cyclotomic_pow(X_ABS).cyclotomic_pow(X_ABS);
    let c = bx2.mul(&b.frobenius_pow(2)).mul(&b.conjugate());
    // λ = (x-1)²/3 · (x+p) · (x²+p²-1) + 1
    c.mul(&m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bilinearity_and_non_degeneracy() {
        let g1 = G1::generator();
        let g2 = G2::generator();
        let e = pairing(&g1, &g2);
        assert!(!bool::from(e.is_identity()));
        // e(P, Q)^r = 1: GT has order r.
        assert_eq!(e.pow(&-Fr::ONE).mul(&e), Gt::IDENTITY);
        let a = Fr::from_u64(0x1122_3344_5566_7788);
        let b = Fr::from_u64(0x99aa_bbcc_ddee_ff01);
        let ea = pairing(&g1.mul(&a), &g2);
        let eb = pairing(&g1, &g2.mul(&b));
        assert_eq!(ea, e.pow(&a));
        assert_eq!(eb, e.pow(&b));
        assert_eq!(pairing(&g1.mul(&a), &g2.mul(&b)), e.pow(&(a * b)));
        assert_eq!(
            pairing(&g1.mul(&a), &g2.mul(&b)),
            pairing(&g1.mul(&b), &g2.mul(&a))
        );
        // e(P, Q)·e(-P, Q) = 1 and e(P, -Q) = e(P, Q)^(-1).
        assert_eq!(pairing(&-g1, &g2).mul(&e), Gt::IDENTITY);
        assert_eq!(pairing(&g1, &-g2), e.inverse());
        // Identity inputs.
        assert_eq!(pairing(&G1::IDENTITY, &g2), Gt::IDENTITY);
        assert_eq!(pairing(&g1, &G2::IDENTITY), Gt::IDENTITY);
        // Multi-pairing: e(aP, Q)·e(-P, aQ) = 1.
        let ag1 = g1.mul(&a);
        let ag2 = g2.mul(&a);
        let ng1 = -g1;
        assert!(bool::from(
            multi_pairing(&[(&ag1, &g2), (&ng1, &ag2)]).is_identity()
        ));
        assert_eq!(multi_pairing(&[(&g1, &g2), (&g1, &g2)]), e.mul(&e));
    }

    #[test]
    fn final_exponentiation_lands_in_gt() {
        let f = miller_loop(&G1::generator(), &G2::generator());
        let e = final_exponentiation(&f);
        // e^r = 1 via e^(r-1) · e.
        assert_eq!(e.pow(&(-Fr::ONE).to_canonical()).mul(&e), Fp12::ONE);
        // Frobenius acts as raising to p on GT; p ≡ ... so e^(p) = e^(p mod r).
        assert_eq!(e.frobenius_map(), e.pow(&super::super::fp::MODULUS));
    }
}
