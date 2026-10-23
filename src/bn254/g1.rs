//! The group `G1 = E(Fp)` of BN254, `E: y² = x³ + 3`, of prime order `r`.

use super::constants::{G1_X, G1_Y, GLV_BASIS, GLV_BETA, GLV_G, GLV_NEG};
use super::curve::{Projective, babai_decompose, sign_magnitude};
use super::fp::Fp;
use super::fr::Fr;
use super::{Error, ops_for_group};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

/// A point of `G1` (all of `E(Fp)`, which has prime order `r`), in
/// projective coordinates.
///
/// Every constructor that takes untrusted input ([`from_compressed`],
/// [`from_uncompressed`], [`from_affine`]) validates canonicity and the
/// curve equation — which, the cofactor being 1, is also subgroup
/// membership — so a `G1` value is always a genuine group element
/// (possibly the identity: reject that separately where the protocol
/// demands, see [`is_identity`]). Group operations are complete and
/// branch-free; [`mul`] is constant time in the scalar.
///
/// [`from_compressed`]: G1::from_compressed
/// [`from_uncompressed`]: G1::from_uncompressed
/// [`from_affine`]: G1::from_affine
/// [`is_identity`]: G1::is_identity
/// [`mul`]: G1::mul
#[derive(Clone, Copy, Debug)]
pub struct G1(pub(crate) Projective<Fp>);

impl G1 {
    /// The identity element.
    pub const IDENTITY: G1 = G1(Projective::IDENTITY);

    /// The standard generator `(1, 2)`.
    pub fn generator() -> G1 {
        G1(Projective::from_affine(G1_X, G1_Y))
    }

    /// The identity element.
    #[inline]
    pub fn identity() -> G1 {
        Self::IDENTITY
    }

    /// Constant-time identity test.
    #[inline]
    pub fn is_identity(&self) -> Choice {
        self.0.is_identity()
    }

    /// Whether the point satisfies the curve equation (always true for a
    /// value built through this API).
    #[inline]
    pub fn is_on_curve(&self) -> Choice {
        self.0.is_on_curve()
    }

    /// `P + Q`.
    #[inline]
    pub fn add(&self, rhs: &G1) -> G1 {
        G1(self.0.add(&rhs.0))
    }

    /// `P - Q`.
    #[inline]
    pub fn sub(&self, rhs: &G1) -> G1 {
        G1(self.0.sub(&rhs.0))
    }

    /// `2P`.
    #[inline]
    pub fn double(&self) -> G1 {
        G1(self.0.double())
    }

    /// `-P`.
    #[inline]
    pub fn neg(&self) -> G1 {
        G1(self.0.neg())
    }

    /// `k·P`, constant time in `k`.
    ///
    /// GLV: `φ(x, y) = (βx, y)` acts on `G1` as a cube root of unity `λ`,
    /// so with the Babai split `k ≡ s₀ + s₁λ (mod r)` along the short
    /// lattice basis (`|sᵢ| < 2^127`, proved by `tools/bn254/consts.py`)
    /// `k·P = |s₀|·(±P) + |s₁|·(±φ(P))`, a two-dimensional multi-scalar
    /// multiplication over 128-bit digits with the signs applied by masked
    /// negation. Complete formulas, masked table gathers, fixed schedule.
    pub fn mul(&self, k: &Fr) -> G1 {
        // The canonical limbs are the scalar in the clear; bind them so they
        // can be wiped, rather than leaving them as an unnamed temporary.
        let mut limbs = k.to_canonical();
        let mut s = babai_decompose(&limbs, &GLV_BASIS, &GLV_G, &GLV_NEG);
        let (n0, mut m0) = sign_magnitude(&s[0]);
        let (n1, mut m1) = sign_magnitude(&s[1]);
        let phi = Projective {
            x: self.0.x.mul(&GLV_BETA),
            y: self.0.y,
            z: self.0.z,
        };
        let points = [self.0.conditional_neg(n0), phi.conditional_neg(n1)];
        let mut digits = [
            m0[0] as u128 | (m0[1] as u128) << 64,
            m1[0] as u128 | (m1[1] as u128) << 64,
        ];
        let r = G1(Projective::mul_2x128(&points, &digits));
        limbs.zeroize();
        s.zeroize();
        m0.zeroize();
        m1.zeroize();
        digits.zeroize();
        r
    }

    /// Affine coordinates, `None` for the identity.
    pub fn to_affine(&self) -> Option<(Fp, Fp)> {
        let (x, y, inf) = self.0.to_affine();
        if bool::from(inf) { None } else { Some((x, y)) }
    }

    /// Builds a point from affine coordinates, checking the curve equation.
    /// (EIP-196's `(0, 0)` identity is not an affine point; use
    /// [`G1::IDENTITY`] or [`from_uncompressed`](G1::from_uncompressed).)
    pub fn from_affine(x: Fp, y: Fp) -> Result<G1, Error> {
        let p = G1(Projective::from_affine(x, y));
        if !bool::from(p.is_on_curve()) {
            return Err(Error::NotOnCurve);
        }
        Ok(p)
    }

    /// The 32-byte gnark-crypto compressed encoding.
    pub fn to_compressed(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.write_compressed(&mut out);
        out
    }

    /// The 64-byte uncompressed encoding `x || y` (big-endian, all zeros for
    /// the identity): the EIP-196 format, identical to gnark-crypto's raw
    /// encoding.
    pub fn to_uncompressed(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.0.write_uncompressed(&mut out);
        out
    }

    /// Parses a 32-byte compressed encoding, validating flags, canonicity
    /// and the curve equation.
    pub fn from_compressed(bytes: &[u8]) -> Result<G1, Error> {
        Ok(G1(Projective::read_compressed(bytes)?))
    }

    /// Parses a 64-byte uncompressed (EIP-196) encoding, validating
    /// canonicity and the curve equation.
    pub fn from_uncompressed(bytes: &[u8]) -> Result<G1, Error> {
        Ok(G1(Projective::read_uncompressed(bytes)?))
    }
}

ops_for_group!(G1);

#[cfg(test)]
mod tests {
    use super::super::constants::R_MOD;
    use super::*;

    #[test]
    fn generator_order_and_group_law() {
        let g = G1::generator();
        assert!(bool::from(g.is_on_curve()));
        assert!(!bool::from(g.is_identity()));
        assert!(bool::from(G1(g.0.mul_limbs(&R_MOD)).is_identity()));
        assert_eq!(g.mul(&Fr::ZERO), G1::IDENTITY);
        assert_eq!(g.mul(&Fr::ONE), g);
        assert_eq!(g.mul(&-Fr::ONE), -g);
        assert_eq!(g.mul(&Fr::from_u64(5)), g.double().double() + g);
        let a = Fr::from_u64(123456789);
        let b = Fr::from_u64(987654321);
        assert_eq!(g.mul(&(a + b)), g.mul(&a) + g.mul(&b));
        assert_eq!(g.mul(&a).mul(&b), g.mul(&(a * b)));
        assert_eq!(G1(g.0.mul_by_public_u64(123456789)), g.mul(&a));
        // Complete formulas through every exceptional case.
        assert_eq!(g + G1::IDENTITY, g);
        assert_eq!(G1::IDENTITY + g, g);
        assert_eq!(g + g, g.double());
        assert_eq!(g - g, G1::IDENTITY);
        assert_eq!(G1::IDENTITY.double(), G1::IDENTITY);
        assert_eq!(G1::IDENTITY + G1::IDENTITY, G1::IDENTITY);
        assert_eq!(G1::IDENTITY.mul(&a), G1::IDENTITY);
        // P + Q with equal affine points in different projective forms.
        let p = g.mul(&a);
        let (x, y) = p.to_affine().unwrap();
        let q = G1::from_affine(x, y).unwrap();
        assert_eq!(p + q, p.double());
        assert_eq!(p - q, G1::IDENTITY);
        assert!(bool::from((p + -q).is_identity()));
        // 3b·x by additions equals the product with the constant.
        use super::super::curve::CurveField;
        assert_eq!(
            CurveField::mul_by_b3(&x),
            x * Fp::from_canonical(&[9, 0, 0, 0])
        );
    }

    #[test]
    fn encodings_round_trip_and_reject() {
        let g = G1::generator();
        let c = g.to_compressed();
        let mut want = [0u8; 32];
        want[0] = 0x80;
        want[31] = 1;
        assert_eq!(c, want);
        assert_eq!(G1::from_compressed(&c).unwrap(), g);
        let u = g.to_uncompressed();
        assert_eq!(u[31], 1);
        assert_eq!(u[63], 2);
        assert_eq!(G1::from_uncompressed(&u).unwrap(), g);
        let ng = -g;
        assert_eq!(ng.to_compressed()[0], 0xc0);
        assert_eq!(G1::from_compressed(&ng.to_compressed()).unwrap(), ng);
        // Identity encodings.
        let mut inf = [0u8; 32];
        inf[0] = 0x40;
        assert_eq!(G1::IDENTITY.to_compressed(), inf);
        assert_eq!(G1::from_compressed(&inf).unwrap(), G1::IDENTITY);
        assert_eq!(G1::IDENTITY.to_uncompressed(), [0u8; 64]);
        assert_eq!(G1::from_uncompressed(&[0u8; 64]).unwrap(), G1::IDENTITY);
        // Flag errors.
        let mut bad = inf;
        bad[31] = 1;
        assert_eq!(G1::from_compressed(&bad), Err(Error::InvalidFlags));
        let mut bad = c;
        bad[0] &= 0x3f;
        assert_eq!(G1::from_compressed(&bad), Err(Error::InvalidFlags));
        assert_eq!(G1::from_compressed(&c[..31]), Err(Error::InvalidLength));
        assert_eq!(G1::from_uncompressed(&u[..63]), Err(Error::InvalidLength));
        // x >= p.
        let mut bad: [u8; 32] = crate::test_util::from_hex(
            "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
        );
        bad[0] |= 0x80;
        assert_eq!(G1::from_compressed(&bad), Err(Error::InvalidEncoding));
        let mut bad = u;
        bad[..32].copy_from_slice(&crate::test_util::from_hex::<32>(
            "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd48",
        ));
        assert_eq!(G1::from_uncompressed(&bad), Err(Error::InvalidEncoding));
        // y' = y + p is non-canonical too.
        let mut bad = u;
        bad[32..].copy_from_slice(&crate::test_util::from_hex::<32>(
            "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd49",
        ));
        assert_eq!(G1::from_uncompressed(&bad), Err(Error::InvalidEncoding));
        // Top bits set on an uncompressed coordinate are non-canonical.
        let mut bad = u;
        bad[0] |= 0x40;
        assert_eq!(G1::from_uncompressed(&bad), Err(Error::InvalidEncoding));
        // x = 0: 0 + 3 = 3 is a non-residue -> not on curve.
        let mut bad = [0u8; 32];
        bad[0] = 0x80;
        assert_eq!(G1::from_compressed(&bad), Err(Error::NotOnCurve));
        // Wrong y.
        let mut bad = u;
        bad[63] ^= 1;
        assert_eq!(G1::from_uncompressed(&bad), Err(Error::NotOnCurve));
        // (0, y) for y ≠ 0 is not the identity and not on the curve.
        let mut bad = [0u8; 64];
        bad[63] = 1;
        assert_eq!(G1::from_uncompressed(&bad), Err(Error::NotOnCurve));
        let (x, y) = g.to_affine().unwrap();
        assert_eq!(G1::from_affine(x, y).unwrap(), g);
        assert_eq!(G1::from_affine(x, x), Err(Error::NotOnCurve));
        assert_eq!(G1::from_affine(Fp::ZERO, Fp::ZERO), Err(Error::NotOnCurve));
    }
    /// The endomorphism-split multiplication against the plain windowed
    /// ladder on the generated edge scalars (Babai rounding half-way points,
    /// eigenvalues, worst-case sub-scalars) and pseudo-random ones, on the
    /// generator and on a second point.
    #[test]
    fn glv_mul_matches_ladder() {
        use super::super::constants::BABAI_EDGE_SCALARS;
        let g = G1::generator();
        let p = g.mul(&Fr::from_u64(0x0f0f_1234_5678_9abc));
        assert_eq!(p, G1(g.0.mul_limbs(&[0x0f0f_1234_5678_9abc, 0, 0, 0])));
        let mut random = [[0u64; 4]; 24];
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        for k in random.iter_mut() {
            for l in k.iter_mut() {
                s = s
                    .wrapping_mul(0x5851_F42D_4C95_7F2D)
                    .wrapping_add(0x1405_7B7E_F767_814F);
                *l = s ^ (s >> 29);
            }
            k[3] &= 0x2fff_ffff_ffff_ffff;
        }
        for k in BABAI_EDGE_SCALARS.iter().chain(random.iter()) {
            let mut be = [0u8; 32];
            crate::pairing_common::mont::to_be_bytes(k, &mut be);
            let fr = Fr::from_bytes(&be).expect("edge scalars are canonical");
            assert_eq!(p.mul(&fr), G1(p.0.mul_limbs(k)), "k = {k:x?}");
            assert_eq!(g.mul(&fr), G1(g.0.mul_limbs(k)), "k = {k:x?}");
        }
        assert_eq!(G1::IDENTITY.mul(&Fr::from_u64(7)), G1::IDENTITY);
    }
}
