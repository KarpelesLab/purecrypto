//! The optimal ate pairing `e: G1 × G2 → GT`.
//!
//! `e(P, Q) = f_{x,Q}(P)^((p¹² - 1)/r)` with the BLS parameter
//! `x = -0xd201000000010000`. The Miller loop keeps the `G2` accumulator on
//! the twist `E': y² = x³ + 4(1 + u)` in homogeneous projective coordinates
//! and evaluates the twist's line functions at the image of `P` under the
//! twist map `τ(x, y) = (x·w², y·w³)` (`E → E'`, since `w⁶ = 1 + u`), so
//! each line is the sparse `Fp12` element `c0 + c1·w² + c4·w³` with
//! `c0 ∈ Fp2` the line's constant term, `c1` its `xP` term and `c4` its
//! `yP` term. Lines are scaled freely by `Fp2` factors (killed by the
//! final exponentiation). The point and the line come out of one set of
//! shared intermediates per step (Costello, Lange and Naehrig,
//! <https://eprint.iacr.org/2009/615>, `a = 0`). The final
//! exponentiation uses the standard easy part `(p⁶ - 1)(p² + 1)` and, for
//! the hard part `(p⁴ - p² + 1)/r`, the polynomial identity
//! `3·λ = (x - 1)²·(x + p)·(x² + p² - 1) + 3` (Hayashida, Hayasaka and
//! Teruya, <https://eprint.iacr.org/2020/875>), i.e.
//! `λ = ((x-1)/3)·(x-1)·(x+p)·(x²+p²-1) + 1` with `(x - 1)/3` integral.

use super::curve::{CurveField, Projective};
use super::fp::Fp;
use super::fp2::Fp2;
use super::fp12::Fp12;
use super::fr::Fr;
use super::g1::G1;
use super::g2::G2;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::zeroize::Zeroize;

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

    /// `self^k`, constant time in `k` (fixed 4-bit windows with masked
    /// table gathers and cyclotomic squarings — `GT` lies in the cyclotomic
    /// subgroup, so the cheaper squaring is exact).
    pub fn pow(&self, k: &Fr) -> Gt {
        // As in `G1::mul`: the canonical limbs are the exponent in the clear.
        let mut limbs = k.to_canonical();
        let r = Gt(self.0.cyclotomic_pow_limbs(&limbs));
        limbs.zeroize();
        r
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
///
/// The Miller loops share one accumulator: `∏ fᵢ` is built in a single run
/// over the loop constant, squaring the accumulator once per step for all
/// pairs instead of once per pair, and without the per-pair `Fp12`
/// products at the end.
pub fn multi_pairing(pairs: &[(&G1, &G2)]) -> Gt {
    let mut legs: alloc::vec::Vec<Leg> = pairs.iter().map(|(p, q)| Leg::new(p, q)).collect();
    Gt(final_exponentiation(&shared_miller_loop(&mut legs)))
}

/// One pair's state in a (shared) Miller loop.
struct Leg {
    px: Fp,
    py: Fp,
    qx: Fp2,
    qy: Fp2,
    t: Projective<Fp2>,
    /// Either input is the identity: the pair contributes `1`.
    skip: Choice,
}

impl Leg {
    fn new(p: &G1, q: &G2) -> Leg {
        let (px, py, p_inf) = p.0.to_affine();
        let (qx, qy, q_inf) = q.0.to_affine();
        Leg {
            px,
            py,
            qx,
            qy,
            t: Projective::from_affine(qx, qy),
            skip: p_inf | q_inf,
        }
    }

    /// Doubles `T` and returns the tangent line at `T` evaluated at
    /// `τ(P)`, as `(c0, c1, c4)` (one set of intermediates for both):
    /// `(Y² - 3b'Z²) - 3X²·xP·w² + 2YZ·yP·w³`.
    fn doubling_step(&mut self) -> (Fp2, Fp2, Fp2) {
        let (x, y, z) = (&self.t.x, &self.t.y, &self.t.z);
        let a = x.mul(y);
        let b = y.square();
        let c = z.square();
        // e = 3b'Z², f = 9b'Z², h = (Y + Z)² - Y² - Z² = 2YZ.
        let e = c.mul_by_b3();
        let f = e.double().add(&e);
        let h = y.add(z).square().sub(&b).sub(&c);
        let x2 = x.square();
        let c0 = b.sub(&e);
        let c1 = x2.double().add(&x2).mul_by_fp(&self.px).neg();
        let c4 = h.mul_by_fp(&self.py);
        // 2T (Costello–Lange–Naehrig, scaled by 4 to avoid halvings):
        // X3 = 2·XY·(B - F), Y3 = (B + F)² - 12·E², Z3 = 4·B·H.
        let x3 = a.mul(&b.sub(&f)).double();
        let e2 = e.square();
        let e2x4 = e2.double().double();
        let y3 = b.add(&f).square().sub(&e2x4.double().add(&e2x4));
        let z3 = b.mul(&h).double().double();
        self.t = Projective {
            x: x3,
            y: y3,
            z: z3,
        };
        (c0, c1, c4)
    }

    /// Adds the affine `Q` to `T` and returns the line through them
    /// evaluated at `τ(P)`, scaled by `v = xQ·Z - X`:
    /// `(X·yQ - Y·xQ) - u·xP·w² + v·yP·w³` with `u = yQ·Z - Y`.
    ///
    /// Not complete: `T ∈ {𝒪, ±Q}` would give the wrong answer, but the
    /// loop only ever adds `Q` to `[m]Q` with `2 ≤ m < |x| < r`.
    fn addition_step(&mut self) -> (Fp2, Fp2, Fp2) {
        let (x, y, z) = (&self.t.x, &self.t.y, &self.t.z);
        let u = self.qy.mul(z).sub(y);
        let v = self.qx.mul(z).sub(x);
        let c0 = x.mul(&self.qy).sub(&y.mul(&self.qx));
        let c1 = u.mul_by_fp(&self.px).neg();
        let c4 = v.mul_by_fp(&self.py);
        // T + Q (projective mixed addition).
        let uu = u.square();
        let vv = v.square();
        let vvv = v.mul(&vv);
        let r = vv.mul(x);
        let a = uu.mul(z).sub(&vvv).sub(&r.double());
        let x3 = v.mul(&a);
        let y3 = u.mul(&r.sub(&a)).sub(&vvv.mul(y));
        let z3 = vvv.mul(z);
        self.t = Projective {
            x: x3,
            y: y3,
            z: z3,
        };
        (c0, c1, c4)
    }
}

/// Multiplies `f` by the sparse line `(c0, c1, c4)`, or leaves it alone
/// when `skip` is set (selected, so the schedule does not depend on it).
#[inline]
fn mul_line(f: &Fp12, line: (Fp2, Fp2, Fp2), skip: Choice) -> Fp12 {
    let (c0, c1, c4) = line;
    let g = f.mul_by_014(&c0, &c1, &c4);
    Fp12::conditional_select(f, &g, skip)
}

/// `∏ f_{|x|,Qᵢ}(Pᵢ)` conjugated (since `x < 0`), pairs whose input is the
/// identity contributing `1`. Runs a fixed schedule over the public loop
/// constant and the number of pairs.
fn shared_miller_loop(legs: &mut [Leg]) -> Fp12 {
    let mut f = Fp12::ONE;
    // Bit 63 of |x| is set; start below it with f = 1, T = Q.
    for bit in (0..63).rev() {
        f = f.square();
        for leg in legs.iter_mut() {
            let line = leg.doubling_step();
            f = mul_line(&f, line, leg.skip);
        }
        if (X_ABS >> bit) & 1 == 1 {
            for leg in legs.iter_mut() {
                let line = leg.addition_step();
                f = mul_line(&f, line, leg.skip);
            }
        }
    }
    f.conjugate()
}

/// `f_{|x|,Q}(P)` conjugated (since `x < 0`), or `1` if either input is the
/// identity. Runs a fixed schedule over the public loop constant.
pub(crate) fn miller_loop(p: &G1, q: &G2) -> Fp12 {
    shared_miller_loop(&mut [Leg::new(p, q)])
}

/// `f^((p¹² - 1)/r)`.
pub(crate) fn final_exponentiation(f: &Fp12) -> Fp12 {
    // Easy part: f^((p⁶ - 1)(p² + 1)). Miller-loop outputs are nonzero;
    // a zero input maps to zero rather than panicking.
    let inv = f.invert().unwrap_or(Fp12::ZERO);
    let t = f.conjugate().mul(&inv);
    let m = t.frobenius_square().mul(&t);
    // Hard part on the cyclotomic subgroup, where x^k with x < 0 is
    // cyclotomic_pow(|x|^k) followed by a conjugation (= inversion). The
    // exponents are the public curve parameters, so the sparse
    // square-and-multiply (one multiplication per set bit) is used.
    // a = m^((x-1)/3)
    let a = m.cyclotomic_pow_public_exp(X_MINUS_1_DIV_3_ABS).conjugate();
    // a = m^((x-1)²/3)
    let a = a.cyclotomic_pow_public_exp(X_MINUS_1_ABS).conjugate();
    // b = a^(x + p)
    let b = a
        .cyclotomic_pow_public_exp(X_ABS)
        .conjugate()
        .mul(&a.frobenius_map());
    // c = b^(x² + p² - 1)
    let bx2 = b
        .cyclotomic_pow_public_exp(X_ABS)
        .cyclotomic_pow_public_exp(X_ABS);
    let c = bx2.mul(&b.frobenius_square()).mul(&b.conjugate());
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

    /// The shared Miller loop equals the product of separate pairings, with
    /// identity legs (on either side) contributing 1.
    #[test]
    fn multi_pairing_matches_product_of_pairings() {
        let g1 = G1::generator();
        let g2 = G2::generator();
        let a = Fr::from_u64(0x0123_4567_89ab_cdef);
        let b = Fr::from_u64(0x0fed_cba9_8765_4321);
        let p = [g1.mul(&a), g1.mul(&b), G1::IDENTITY, g1];
        let q = [g2, g2.mul(&b), g2.mul(&a), G2::IDENTITY];
        let mut want = Gt::IDENTITY;
        for (pi, qi) in p.iter().zip(q.iter()) {
            want = want.mul(&pairing(pi, qi));
        }
        let pairs: [(&G1, &G2); 4] = [
            (&p[0], &q[0]),
            (&p[1], &q[1]),
            (&p[2], &q[2]),
            (&p[3], &q[3]),
        ];
        assert_eq!(multi_pairing(&pairs), want);
        assert_eq!(multi_pairing(&pairs[..1]), pairing(&p[0], &q[0]));
        assert_eq!(multi_pairing(&pairs[2..]), Gt::IDENTITY);
        assert_eq!(multi_pairing(&[]), Gt::IDENTITY);
        // Cross-check the shared loop against an independent product of
        // per-pair Miller loops evaluated the old way (one f per pair).
        let mut f = Fp12::ONE;
        for (pi, qi) in &pairs {
            f = f.mul(&miller_loop(pi, qi));
        }
        assert_eq!(Gt(final_exponentiation(&f)), want);
    }

    /// SHA-256 over the twelve 48-byte coefficients of a `Gt` element.
    fn digest(e: &Gt) -> [u8; 32] {
        use crate::hash::{Digest, Sha256};
        let f = e.as_fp12();
        let mut h = Sha256::new();
        for c6 in [&f.c0, &f.c1] {
            for c2 in [&c6.c0, &c6.c1, &c6.c2] {
                h.update(&c2.c0.to_bytes());
                h.update(&c2.c1.to_bytes());
            }
        }
        h.finalize()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// Pins the exact pairing values (this implementation computes
    /// `f^((p¹²-1)/r)` itself, not a multiple of the exponent), so that
    /// reformulations of the Miller loop or final exponentiation that are
    /// only correct up to a factor killed by the exponentiation — or not
    /// at all — are caught.
    #[test]
    fn pairing_values_are_pinned() {
        let g1 = G1::generator();
        let g2 = G2::generator();
        assert_eq!(
            digest(&pairing(&g1, &g2)),
            hex32("4b4c07e7d5136bb2947bab11cf26a740cd2aeef4baf3e6f773bfadb5e505f8b4"),
        );
        let a = Fr::from_u64(0x1122_3344_5566_7788);
        let b = Fr::from_u64(0x99aa_bbcc_ddee_ff01);
        assert_eq!(
            digest(&pairing(&g1.mul(&a), &g2.mul(&b))),
            hex32("e0ef4076e6489c52511ca72e5dd5dc99c4fb4da9512fe8c923e5a6531c4cf6b5"),
        );
        assert_eq!(
            digest(&multi_pairing(&[(&g1, &g2), (&g1.mul(&a), &g2.mul(&b))])),
            hex32("edde1c6a19660c05271f113b05da31b84506bf9f5186a095837376c9e042d58c"),
        );
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
