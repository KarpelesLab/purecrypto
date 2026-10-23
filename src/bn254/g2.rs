//! The group `G2 ⊂ E'(Fp2)` of BN254 on the D-type sextic twist
//! `E': y² = x³ + 3/(9 + u)`.

use super::constants::{FROB_2, FROB_3, G2_X, G2_Y, X};
use super::curve::Projective;
use super::fp2::Fp2;
use super::fr::Fr;
use super::{Error, ops_for_group};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

/// A point of `G2`, the order-`r` subgroup of the twist `E'(Fp2)` (whose
/// full order is `r·(2p − r)`), in projective coordinates.
///
/// Every constructor that takes untrusted input ([`from_compressed`],
/// [`from_uncompressed`], [`from_affine`]) validates canonicity, the curve
/// equation **and** subgroup membership, so a `G2` value is always a
/// genuine group element (possibly the identity). Group operations are
/// complete and branch-free; [`mul`] is constant time in the scalar.
///
/// [`from_compressed`]: G2::from_compressed
/// [`from_uncompressed`]: G2::from_uncompressed
/// [`from_affine`]: G2::from_affine
/// [`mul`]: G2::mul
#[derive(Clone, Copy, Debug)]
pub struct G2(pub(crate) Projective<Fp2>);

impl G2 {
    /// The identity element.
    pub const IDENTITY: G2 = G2(Projective::IDENTITY);

    /// The standard generator (the EIP-197 one).
    pub fn generator() -> G2 {
        G2(Projective::from_affine(G2_X, G2_Y))
    }

    /// The identity element.
    #[inline]
    pub fn identity() -> G2 {
        Self::IDENTITY
    }

    /// Constant-time identity test.
    #[inline]
    pub fn is_identity(&self) -> Choice {
        self.0.is_identity()
    }

    /// Whether the point satisfies the twist equation.
    #[inline]
    pub fn is_on_curve(&self) -> Choice {
        self.0.is_on_curve()
    }

    /// The endomorphism `ψ = τ⁻¹ ∘ π_p ∘ τ` (untwist, `p`-power Frobenius,
    /// twist): `(x, y) ↦ (x̄·ξ^((p−1)/3), ȳ·ξ^((p−1)/2))`. It acts on `G2` as
    /// multiplication by `p ≡ 6x² (mod r)`.
    pub(crate) fn psi(p: &Projective<Fp2>) -> Projective<Fp2> {
        Projective {
            x: p.x.conjugate().mul(&FROB_2),
            y: p.y.conjugate().mul(&FROB_3),
            z: p.z.conjugate(),
        }
    }

    /// Whether the point lies in the prime-order subgroup, by the test
    /// `ψ(Q) = [6x²]Q` (El Housni, Guillevic and Piellard,
    /// <https://eprint.iacr.org/2022/352>). It is exact on all of `E'(Fp2)`:
    /// `ψ² − tψ + p = 0` there, so a point outside `G2` could pass only if
    /// `6x²` were an eigenvalue of `ψ` modulo a prime dividing the cofactor,
    /// i.e. a prime dividing both `(6x²)² − t·6x² + p` and `2p − r`, and
    /// `tools/bn254/consts.py` checks those are coprime.
    ///
    /// Inputs are public (this runs on decoded points), but the schedule is
    /// fixed anyway: two multiplications by the public constant `x`.
    pub fn is_torsion_free(&self) -> Choice {
        let x2 = self.0.mul_by_public_u64(X).mul_by_public_u64(X);
        let x2_3 = x2.double().add(&x2);
        let six_x2 = x2_3.double();
        Self::psi(&self.0).ct_eq(&six_x2)
    }

    /// `P + Q`.
    #[inline]
    pub fn add(&self, rhs: &G2) -> G2 {
        G2(self.0.add(&rhs.0))
    }

    /// `P - Q`.
    #[inline]
    pub fn sub(&self, rhs: &G2) -> G2 {
        G2(self.0.sub(&rhs.0))
    }

    /// `2P`.
    #[inline]
    pub fn double(&self) -> G2 {
        G2(self.0.double())
    }

    /// `-P`.
    #[inline]
    pub fn neg(&self) -> G2 {
        G2(self.0.neg())
    }

    /// `k·P`, constant time in `k` (fixed 4-bit windows, masked table
    /// gathers, complete formulas).
    pub fn mul(&self, k: &Fr) -> G2 {
        let mut limbs = k.to_canonical();
        let r = G2(self.0.mul_limbs(&limbs));
        limbs.zeroize();
        r
    }

    /// Maps any point of `E'(Fp2)` into `G2` by the Fuentes-Castañeda,
    /// Knapp and Rodríguez-Henríquez formula
    /// `[x]Q + ψ([3x]Q) + ψ²([x]Q) + ψ³(Q)` (a multiple of the cofactor
    /// `2p − r` coprime to `r`), as gnark-crypto does. Fixed schedule: two
    /// multiplications by the public `x`, complete formulas throughout.
    pub(crate) fn clear_cofactor(q: &Projective<Fp2>) -> G2 {
        let xq = q.mul_by_public_u64(X);
        let x3q = xq.double().add(&xq);
        let t = xq.add(&Self::psi(&x3q));
        let t = t.add(&Self::psi(&Self::psi(&xq)));
        G2(t.add(&Self::psi(&Self::psi(&Self::psi(q)))))
    }

    /// Affine coordinates, `None` for the identity.
    pub fn to_affine(&self) -> Option<(Fp2, Fp2)> {
        let (x, y, inf) = self.0.to_affine();
        if bool::from(inf) { None } else { Some((x, y)) }
    }

    /// Builds a point from affine coordinates, checking the twist equation
    /// and subgroup membership.
    pub fn from_affine(x: Fp2, y: Fp2) -> Result<G2, Error> {
        let p = G2(Projective::from_affine(x, y));
        if !bool::from(p.is_on_curve()) {
            return Err(Error::NotOnCurve);
        }
        p.checked()
    }

    /// The 64-byte gnark-crypto compressed encoding (`x` as `c1 || c0`,
    /// flags in the top two bits).
    pub fn to_compressed(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.0.write_compressed(&mut out);
        out
    }

    /// The 128-byte uncompressed encoding `x.c1 || x.c0 || y.c1 || y.c0`
    /// (big-endian, all zeros for the identity): the EIP-197 format,
    /// identical to gnark-crypto's raw encoding.
    pub fn to_uncompressed(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        self.0.write_uncompressed(&mut out);
        out
    }

    /// Parses a 64-byte compressed encoding, validating flags, canonicity,
    /// the twist equation and subgroup membership.
    pub fn from_compressed(bytes: &[u8]) -> Result<G2, Error> {
        G2(Projective::read_compressed(bytes)?).checked()
    }

    /// Parses a 128-byte uncompressed (EIP-197) encoding with full
    /// validation, subgroup membership included.
    pub fn from_uncompressed(bytes: &[u8]) -> Result<G2, Error> {
        G2(Projective::read_uncompressed(bytes)?).checked()
    }

    fn checked(self) -> Result<G2, Error> {
        if bool::from(self.is_torsion_free()) {
            Ok(self)
        } else {
            Err(Error::NotInSubgroup)
        }
    }
}

ops_for_group!(G2);

#[cfg(test)]
pub(crate) mod tests {
    use super::super::constants::{B2, R_MOD};
    use super::super::fp::Fp;
    use super::*;

    /// A twist point outside `G2`: the first `x = k + u` with `x³ + b'` a
    /// square (cofactor clearing has not been applied).
    pub(crate) fn non_subgroup_point() -> G2 {
        for k in 1u64.. {
            let x = Fp2::new(Fp::from_canonical(&[k, 0, 0, 0]), Fp::ONE);
            if let Some(y) = x.square().mul(&x).add(&B2).sqrt().into_option() {
                return G2(Projective::from_affine(x, y));
            }
        }
        unreachable!()
    }

    #[test]
    fn generator_order_and_group_law() {
        let g = G2::generator();
        assert!(bool::from(g.is_on_curve()));
        assert!(bool::from(g.is_torsion_free()));
        assert!(bool::from(G2(g.0.mul_limbs(&R_MOD)).is_identity()));
        assert_eq!(
            G2(G2::psi(&g.0)),
            g.mul(&Fr::from_u64(X).square().mul(&Fr::from_u64(6)))
        );
        assert_eq!(g.mul(&Fr::ZERO), G2::IDENTITY);
        assert_eq!(g.mul(&Fr::ONE), g);
        assert_eq!(g.mul(&-Fr::ONE), -g);
        let a = Fr::from_u64(0x1234_5678_9abc_def0);
        let b = Fr::from_u64(0x0fed_cba9_8765_4321);
        assert_eq!(g.mul(&(a + b)), g.mul(&a) + g.mul(&b));
        assert_eq!(g.mul(&a).mul(&b), g.mul(&(a * b)));
        assert_eq!(g + G2::IDENTITY, g);
        assert_eq!(g + g, g.double());
        assert_eq!(g - g, G2::IDENTITY);
        assert_eq!(G2::IDENTITY.double(), G2::IDENTITY);
        assert!(bool::from(G2::IDENTITY.is_torsion_free()));
        use super::super::curve::CurveField;
        let (x, _) = g.to_affine().unwrap();
        assert_eq!(CurveField::mul_by_b3(&x), x * (B2 + B2 + B2));
    }

    /// The complete formulas on the full twist group (points of order
    /// dividing the odd cofactor), the membership test rejecting them, and
    /// cofactor clearing landing in `G2`.
    #[test]
    fn non_subgroup_points() {
        let q = non_subgroup_point();
        assert!(bool::from(q.is_on_curve()));
        assert!(!bool::from(q.is_torsion_free()));
        // [r]Q ≠ 𝒪, so Q has a cofactor component.
        assert!(!bool::from(G2(q.0.mul_limbs(&R_MOD)).is_identity()));
        let rq = G2(q.0.mul_limbs(&R_MOD));
        assert!(!bool::from(rq.is_torsion_free()));
        assert_eq!(q + q, q.double());
        assert_eq!(q - q, G2::IDENTITY);
        assert_eq!((q + rq) - rq, q);
        let c = G2::clear_cofactor(&q.0);
        assert!(!bool::from(c.is_identity()));
        assert!(bool::from(c.is_torsion_free()));
        assert!(bool::from(G2(c.0.mul_limbs(&R_MOD)).is_identity()));
        // Clearing a G2 point multiplies it by a fixed scalar.
        let g = G2::generator();
        let cg = G2::clear_cofactor(&g.0);
        let cg2 = G2::clear_cofactor(&g.double().0);
        assert_eq!(cg2, cg.double());
        // Decoders reject the off-subgroup point in both encodings.
        let (x, y) = q.to_affine().unwrap();
        assert_eq!(G2::from_affine(x, y), Err(Error::NotInSubgroup));
        assert_eq!(
            G2::from_uncompressed(&q.to_uncompressed()),
            Err(Error::NotInSubgroup)
        );
        assert_eq!(
            G2::from_compressed(&q.to_compressed()),
            Err(Error::NotInSubgroup)
        );
    }

    #[test]
    fn encodings_round_trip_and_reject() {
        let g = G2::generator();
        let u = g.to_uncompressed();
        assert_eq!(&u[..2], &[0x19, 0x8e]);
        assert_eq!(G2::from_uncompressed(&u).unwrap(), g);
        let c = g.to_compressed();
        assert_eq!(c[0], 0x80 | 0x19);
        assert_eq!(G2::from_compressed(&c).unwrap(), g);
        let ng = -g;
        assert_eq!(ng.to_compressed()[0], 0xc0 | 0x19);
        assert_eq!(G2::from_compressed(&ng.to_compressed()).unwrap(), ng);
        let mut inf = [0u8; 64];
        inf[0] = 0x40;
        assert_eq!(G2::IDENTITY.to_compressed(), inf);
        assert_eq!(G2::from_compressed(&inf).unwrap(), G2::IDENTITY);
        assert_eq!(G2::IDENTITY.to_uncompressed(), [0u8; 128]);
        assert_eq!(G2::from_uncompressed(&[0u8; 128]).unwrap(), G2::IDENTITY);
        let mut bad = inf;
        bad[63] = 1;
        assert_eq!(G2::from_compressed(&bad), Err(Error::InvalidFlags));
        let mut bad = c;
        bad[0] &= 0x3f;
        assert_eq!(G2::from_compressed(&bad), Err(Error::InvalidFlags));
        assert_eq!(G2::from_compressed(&c[..63]), Err(Error::InvalidLength));
        assert_eq!(G2::from_uncompressed(&u[..127]), Err(Error::InvalidLength));
        let mut bad = u;
        bad[0] |= 0x40;
        assert_eq!(G2::from_uncompressed(&bad), Err(Error::InvalidEncoding));
        let mut bad = u;
        bad[127] ^= 1;
        assert_eq!(G2::from_uncompressed(&bad), Err(Error::NotOnCurve));
        // A non-canonical c0 of x in the compressed form.
        let mut bad = c;
        bad[32..].copy_from_slice(&[0xff; 32]);
        assert_eq!(G2::from_compressed(&bad), Err(Error::InvalidEncoding));
    }
}
