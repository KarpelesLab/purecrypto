//! The group `G1 = E(Fp)[r]` of BLS12-377, `E: y² = x³ + 1`.

use super::constants::{BETA, G1_X, G1_Y, X};
use super::curve::Projective;
use super::fp::Fp;
use super::fr::Fr;
use super::{Error, ops_for_group};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

/// A point of `G1`, the prime-order subgroup of `E(Fp)`, in projective
/// coordinates.
///
/// Every constructor that takes untrusted input ([`from_compressed`],
/// [`from_uncompressed`], the arkworks forms, [`from_affine`]) validates
/// canonicity, the curve equation and subgroup membership, so a `G1` value
/// is always a genuine group element (possibly the identity — reject that
/// separately where the protocol demands, see [`is_identity`]). Group
/// operations are branch-free; [`mul`] is constant time in the scalar.
///
/// `E(Fp)` has rational 2-torsion (the cofactor is even); the subgroup
/// check is evaluated with arithmetic that stays correct on such points,
/// see the `curve` module documentation.
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

    /// The standard generator.
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

    /// Whether the point satisfies the curve equation.
    #[inline]
    pub fn is_on_curve(&self) -> Choice {
        self.0.is_on_curve()
    }

    /// Whether a point of `E(Fp)` lies in the prime-order subgroup:
    /// `φ(P) = -x²·P` with `φ(x, y) = (β·x, y)` (Scott,
    /// <https://eprint.iacr.org/2021/1130>). Sound because `φ + x²` has
    /// degree `x⁴ - x² + 1 = r`, so its kernel is exactly `G1`. The
    /// multiplications use the 2-torsion-safe addition law, since the
    /// input is not yet known to be in the subgroup.
    fn torsion_free(p: &Projective<Fp>) -> Choice {
        let phi = Projective {
            x: p.x.mul(&BETA),
            y: p.y,
            z: p.z,
        };
        let minus_x2 = p.mul_by_x_full().mul_by_x_full().neg();
        phi.ct_eq(&minus_x2)
    }

    /// Whether the point lies in the prime-order subgroup (always true for
    /// a `G1` value; exposed for symmetry with the decoding checks).
    pub fn is_torsion_free(&self) -> Choice {
        Self::torsion_free(&self.0)
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
    /// GLV: `φ(P) = -x²·P`, so with `k = e₀ + e₁·x²` (the base-`x²` digits,
    /// both below `x² < 2^128` since `k < r < x⁴`)
    /// `k·P = e₀·P + e₁·(-φ(P))`, a two-dimensional multi-scalar
    /// multiplication over 128-bit digits. The split is a constant-time
    /// division (`div_rem_ct` in the curve module).
    pub fn mul(&self, k: &Fr) -> G1 {
        const X2: u128 = (X as u128) * (X as u128);
        let mut limbs = k.to_canonical();
        let (mut e1, mut e0) = super::curve::div_rem_ct(&limbs, X2);
        let mut e1v = e1[0] as u128 | (e1[1] as u128) << 64;
        let minus_phi = Projective {
            x: self.0.x.mul(&BETA),
            y: self.0.y.neg(),
            z: self.0.z,
        };
        let r = G1(Projective::mul_2x128(&[self.0, minus_phi], &[e0, e1v]));
        limbs.zeroize();
        e0.zeroize();
        e1.zeroize();
        e1v.zeroize();
        r
    }

    /// Multiplies any point of `E(Fp)` by the effective cofactor
    /// `h_eff = 1 - x` (RFC 9380 §8.8.1), landing in `G1`. 2-torsion-safe.
    pub(crate) fn clear_cofactor(p: &Projective<Fp>) -> G1 {
        G1(p.add_full(&p.mul_by_x_full().neg()))
    }

    /// Affine coordinates, `None` for the identity.
    pub fn to_affine(&self) -> Option<(Fp, Fp)> {
        let (x, y, inf) = self.0.to_affine();
        if bool::from(inf) { None } else { Some((x, y)) }
    }

    /// Builds a point from affine coordinates, checking the curve equation
    /// and subgroup membership.
    pub fn from_affine(x: Fp, y: Fp) -> Result<G1, Error> {
        Self::checked(Projective::from_affine(x, y))
    }

    /// The 48-byte compressed encoding of gnark-crypto (the ZCash flag
    /// layout: big-endian `x`, flags `0x80` compressed, `0x40` infinity,
    /// `0x20` "y is the larger root").
    pub fn to_compressed(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        self.0.write_compressed(&mut out);
        out
    }

    /// The 96-byte uncompressed encoding of gnark-crypto (`x || y`,
    /// big-endian, `0x40` flag for the identity).
    pub fn to_uncompressed(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        self.0.write_uncompressed(&mut out);
        out
    }

    /// Parses a 48-byte compressed encoding, validating flags, canonicity,
    /// the curve equation and subgroup membership.
    pub fn from_compressed(bytes: &[u8]) -> Result<G1, Error> {
        Self::checked(Projective::read_compressed(bytes)?)
    }

    /// Parses a 96-byte uncompressed encoding with full validation.
    pub fn from_uncompressed(bytes: &[u8]) -> Result<G1, Error> {
        Self::checked(Projective::read_uncompressed(bytes)?)
    }

    /// The 48-byte arkworks compressed encoding (`CanonicalSerialize`:
    /// little-endian `x`, flags in the last byte).
    pub fn to_compressed_ark(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        self.0.write_ark_compressed(&mut out);
        out
    }

    /// The 96-byte arkworks uncompressed encoding.
    pub fn to_uncompressed_ark(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        self.0.write_ark_uncompressed(&mut out);
        out
    }

    /// Parses an arkworks compressed encoding with full validation.
    pub fn from_compressed_ark(bytes: &[u8]) -> Result<G1, Error> {
        Self::checked(Projective::read_ark_compressed(bytes)?)
    }

    /// Parses an arkworks uncompressed encoding with full validation.
    pub fn from_uncompressed_ark(bytes: &[u8]) -> Result<G1, Error> {
        Self::checked(Projective::read_ark_uncompressed(bytes)?)
    }

    /// The single gate every untrusted point passes: on the curve, then in
    /// the subgroup.
    fn checked(p: Projective<Fp>) -> Result<G1, Error> {
        if !bool::from(p.is_on_curve()) {
            return Err(Error::NotOnCurve);
        }
        if !bool::from(Self::torsion_free(&p)) {
            return Err(Error::NotInSubgroup);
        }
        Ok(G1(p))
    }
}

ops_for_group!(G1);

#[cfg(test)]
mod tests {
    use super::super::constants::FR_MODULUS;
    use super::*;

    #[test]
    fn generator_order_and_arithmetic() {
        let g = G1::generator();
        assert!(bool::from(g.is_on_curve()));
        assert!(bool::from(g.is_torsion_free()));
        assert!(!bool::from(g.is_identity()));
        assert!(bool::from(G1(g.0.mul_limbs(&FR_MODULUS)).is_identity()));
        // φ acts as -x²; the GLV split agrees with the plain ladder.
        let k = Fr::from_bytes_wide(&[0x5a; 64]);
        assert_eq!(g.mul(&k), G1(g.0.mul_limbs(&k.to_canonical())));
        assert_eq!(g.mul(&Fr::from_u64(X)), G1(g.0.mul_by_x()));
        assert_eq!(g.mul(&Fr::ZERO), G1::IDENTITY);
        assert_eq!(g.mul(&Fr::ONE), g);
        assert_eq!(g.mul(&-Fr::ONE), -g);
        let a = Fr::from_u64(123456789);
        let b = Fr::from_u64(987654321);
        assert_eq!(g.mul(&(a + b)), g.mul(&a) + g.mul(&b));
        assert_eq!(g.mul(&(a * b)), g.mul(&a).mul(&b));
        assert_eq!(g + G1::IDENTITY, g);
        assert_eq!(G1::IDENTITY + g, g);
        assert_eq!(g + g, g.double());
        assert_eq!(g - g, G1::IDENTITY);
        assert_eq!(G1::IDENTITY.double(), G1::IDENTITY);
        // The identity encodes and round-trips in every format.
        let i = G1::IDENTITY;
        assert_eq!(G1::from_compressed(&i.to_compressed()).unwrap(), i);
        assert_eq!(G1::from_uncompressed(&i.to_uncompressed()).unwrap(), i);
        assert_eq!(G1::from_compressed_ark(&i.to_compressed_ark()).unwrap(), i);
        assert_eq!(
            G1::from_uncompressed_ark(&i.to_uncompressed_ark()).unwrap(),
            i
        );
        for k in [a, b, k, -k] {
            let p = g.mul(&k);
            assert_eq!(G1::from_compressed(&p.to_compressed()).unwrap(), p);
            assert_eq!(G1::from_uncompressed(&p.to_uncompressed()).unwrap(), p);
            assert_eq!(G1::from_compressed_ark(&p.to_compressed_ark()).unwrap(), p);
            assert_eq!(
                G1::from_uncompressed_ark(&p.to_uncompressed_ark()).unwrap(),
                p
            );
        }
    }

    /// Points of `E(Fp)` outside `G1` — the 2-torsion points, `P + T`, and
    /// a point of the full group — are rejected by every decoder, and the
    /// rejection is `NotInSubgroup` (not an accidental pass through a
    /// degenerate `(0 : 0 : 0)` comparison).
    #[test]
    fn rejects_points_outside_the_subgroup() {
        let m1 = -Fp::ONE;
        let t = Projective::from_affine(m1, Fp::ZERO);
        let ts = [
            t,
            Projective::from_affine(m1 * BETA, Fp::ZERO),
            Projective::from_affine(m1 * BETA.square(), Fp::ZERO),
        ];
        let g = G1::generator().0;
        // A point of the full group with a large cofactor component: lift
        // x = 2, 3, ... until x³ + 1 is a square.
        let mut x = Fp::ONE.double();
        let lifted = loop {
            if let Some(y) = (x.square() * x + Fp::ONE).sqrt().into_option() {
                break Projective::from_affine(x, y);
            }
            x += Fp::ONE;
        };
        let bad = [
            ts[0],
            ts[1],
            ts[2],
            g.add_full(&ts[0]),
            g.add_full(&ts[1]),
            g.add_full(&ts[2]),
            lifted,
        ];
        for p in &bad {
            assert!(bool::from(p.is_on_curve()));
            assert!(!bool::from(G1::torsion_free(p)));
            let w = G1(*p);
            assert_eq!(
                G1::from_compressed(&w.to_compressed()),
                Err(Error::NotInSubgroup)
            );
            assert_eq!(
                G1::from_uncompressed(&w.to_uncompressed()),
                Err(Error::NotInSubgroup)
            );
            assert_eq!(
                G1::from_compressed_ark(&w.to_compressed_ark()),
                Err(Error::NotInSubgroup)
            );
            assert_eq!(
                G1::from_uncompressed_ark(&w.to_uncompressed_ark()),
                Err(Error::NotInSubgroup)
            );
            let (ax, ay, _) = p.to_affine();
            assert_eq!(G1::from_affine(ax, ay), Err(Error::NotInSubgroup));
        }
        // Clearing the cofactor of any of them lands in G1.
        for p in &bad {
            let c = G1::clear_cofactor(p);
            assert!(bool::from(c.is_on_curve()) && bool::from(c.is_torsion_free()));
        }
        // 2-torsion points clear to the identity (1 - x is even).
        assert!(bool::from(G1::clear_cofactor(&t).is_identity()));
    }

    #[test]
    fn rejects_malformed_encodings() {
        let g = G1::generator();
        let c = g.to_compressed();
        let u = g.to_uncompressed();
        assert_eq!(G1::from_compressed(&c[..47]), Err(Error::InvalidLength));
        assert_eq!(G1::from_uncompressed(&u[..95]), Err(Error::InvalidLength));
        // Compression flag cleared / set on the wrong form.
        let mut x = c;
        x[0] &= 0x7f;
        assert_eq!(G1::from_compressed(&x), Err(Error::InvalidFlags));
        let mut x = u;
        x[0] |= 0x80;
        assert_eq!(G1::from_uncompressed(&x), Err(Error::InvalidFlags));
        // Infinity with payload or with the sort flag.
        let mut x = G1::IDENTITY.to_compressed();
        x[47] = 1;
        assert_eq!(G1::from_compressed(&x), Err(Error::InvalidFlags));
        let mut x = G1::IDENTITY.to_compressed();
        x[0] |= 0x20;
        assert_eq!(G1::from_compressed(&x), Err(Error::InvalidFlags));
        // Non-canonical x (the spare bits below the flags, or x >= p).
        let mut x = c;
        x[0] |= 0x10;
        assert_eq!(G1::from_compressed(&x), Err(Error::InvalidEncoding));
        // An x with x³ + 1 a non-square: x = 2 works if 9 is... search one.
        let mut xv = Fp::ONE;
        let not_on = loop {
            if bool::from((xv.square() * xv + Fp::ONE).sqrt().is_none()) {
                break xv;
            }
            xv += Fp::ONE;
        };
        let mut enc = not_on.to_bytes();
        enc[0] |= 0x80;
        assert_eq!(G1::from_compressed(&enc), Err(Error::NotOnCurve));
        let mut un = [0u8; 96];
        un[..48].copy_from_slice(&g.to_affine().unwrap().0.to_bytes());
        un[48..].copy_from_slice(&(g.to_affine().unwrap().1 + Fp::ONE).to_bytes());
        assert_eq!(G1::from_uncompressed(&un), Err(Error::NotOnCurve));
        // arkworks: both flags at once; flipped sign on the uncompressed form.
        let mut x = g.to_compressed_ark();
        x[47] |= 0xc0;
        assert_eq!(G1::from_compressed_ark(&x), Err(Error::InvalidFlags));
        let mut x = g.to_uncompressed_ark();
        x[95] ^= 0x80;
        assert_eq!(G1::from_uncompressed_ark(&x), Err(Error::InvalidFlags));
        let mut x = G1::IDENTITY.to_compressed_ark();
        x[0] = 1;
        assert_eq!(G1::from_compressed_ark(&x), Err(Error::InvalidFlags));
        // Flipping the sort flag yields -P (still valid), never P.
        let mut x = c;
        x[0] ^= 0x20;
        assert_eq!(G1::from_compressed(&x).unwrap(), -g);
    }
}
