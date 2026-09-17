//! The group `G1 = E(Fp)[r]` of BLS12-381, `E: y² = x³ + 4`.

use super::constants::{BETA, G1_X, G1_Y};
use super::curve::Projective;
use super::fp::Fp;
use super::fr::Fr;
use super::{Error, ops_for_group};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use core::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

/// A point of `G1`, the prime-order subgroup of `E(Fp)`, in projective
/// coordinates.
///
/// Every constructor that takes untrusted bytes ([`from_compressed`],
/// [`from_uncompressed`], [`from_affine`]) validates the curve equation and
/// subgroup membership, so a `G1` value is always a genuine group element
/// (possibly the identity — reject that separately where the protocol
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

    /// Whether the point lies in the prime-order subgroup.
    ///
    /// Uses the GLV endomorphism `φ(x, y) = (β·x, y)`, which acts on `G1` as
    /// multiplication by `λ = -x²` (Section 6 of
    /// <https://eprint.iacr.org/2021/1130>): `P ∈ G1 ⇔ φ(P) = -x²·P`.
    pub fn is_torsion_free(&self) -> Choice {
        let phi = Projective {
            x: self.0.x.mul(&BETA),
            y: self.0.y,
            z: self.0.z,
        };
        let minus_x2 = self.0.mul_by_x().mul_by_x().neg();
        phi.ct_eq(&minus_x2)
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
    #[inline]
    pub fn mul(&self, k: &Fr) -> G1 {
        G1(self.0.mul_limbs(&k.to_canonical()))
    }

    /// Multiplies by the effective cofactor `h_eff = 1 - x` (RFC 9380
    /// §8.8.1), mapping any point of `E(Fp)` into `G1`.
    pub(crate) fn clear_cofactor(&self) -> G1 {
        G1(self.0.mul_by_x_abs().add(&self.0))
    }

    /// Affine coordinates, `None` for the identity.
    pub fn to_affine(&self) -> Option<(Fp, Fp)> {
        let (x, y, inf) = self.0.to_affine();
        if bool::from(inf) { None } else { Some((x, y)) }
    }

    /// Builds a point from affine coordinates, checking the curve equation
    /// and subgroup membership.
    pub fn from_affine(x: Fp, y: Fp) -> Result<G1, Error> {
        let p = G1(Projective::from_affine(x, y));
        if !bool::from(p.is_on_curve()) {
            return Err(Error::NotOnCurve);
        }
        if !bool::from(p.is_torsion_free()) {
            return Err(Error::NotInSubgroup);
        }
        Ok(p)
    }

    /// The 48-byte compressed ZCash encoding.
    pub fn to_compressed(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        self.0.write_compressed(&mut out);
        out
    }

    /// The 96-byte uncompressed ZCash encoding.
    pub fn to_uncompressed(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        self.0.write_uncompressed(&mut out);
        out
    }

    /// Parses a 48-byte compressed encoding, validating flags, canonicity,
    /// the curve equation and subgroup membership.
    pub fn from_compressed(bytes: &[u8]) -> Result<G1, Error> {
        Self::from_compressed_unchecked(bytes)?.checked()
    }

    /// Parses a 96-byte uncompressed encoding with full validation.
    pub fn from_uncompressed(bytes: &[u8]) -> Result<G1, Error> {
        G1(Projective::read_uncompressed(bytes)?).checked()
    }

    /// Parses a compressed encoding without the subgroup check (the point is
    /// on the curve). Only for tests and for building known-bad inputs.
    pub(crate) fn from_compressed_unchecked(bytes: &[u8]) -> Result<G1, Error> {
        Ok(G1(Projective::read_compressed(bytes)?))
    }

    fn checked(self) -> Result<G1, Error> {
        if bool::from(self.is_torsion_free()) {
            Ok(self)
        } else {
            Err(Error::NotInSubgroup)
        }
    }
}

ops_for_group!(G1);

#[cfg(test)]
mod tests {
    use super::super::fr::MODULUS as R;
    use super::*;

    fn hex48(s: &str) -> Fp {
        let mut b = [0u8; 48];
        for (i, o) in b.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        Fp::from_bytes(&b).unwrap()
    }

    #[test]
    fn generator_order_and_pins() {
        let g = G1::generator();
        assert!(bool::from(g.is_on_curve()));
        assert!(bool::from(g.is_torsion_free()));
        assert!(!bool::from(g.is_identity()));
        assert!(bool::from(G1(g.0.mul_limbs(&R)).is_identity()));
        // x·G1 (x = -0xd201000000010000), from the parameter script.
        let xg = G1(g.0.mul_by_x());
        let (x, y) = xg.to_affine().unwrap();
        assert_eq!(
            x,
            hex48(
                "0d3aff0f3b2e6f4878f15a81eabab5d8c9f765bc93ae0a2f0da5ed1941b4924bca4516661600c41a74beeb243695b52d"
            )
        );
        assert_eq!(
            y,
            hex48(
                "16ce48c345cce7cd395692cecbb8704bcb29645135c8ac366c4e5c40dead3c218814904df7d4c92cbb9aa956bbb1deab"
            )
        );
        // Windowed multiplication agrees with the double-and-add path.
        let mut k = [0u64; 4];
        k[0] = 0xd201000000010000;
        assert_eq!(
            g.mul(&Fr::from_u64(0xd201000000010000)),
            G1(g.0.mul_limbs(&k))
        );
        assert_eq!(g.mul(&Fr::from_u64(0xd201000000010000)), xg.neg());
        assert_eq!(g.mul(&Fr::ZERO), G1::IDENTITY);
        assert_eq!(g.mul(&Fr::ONE), g);
        assert_eq!(g.mul(&-Fr::ONE), -g);
        // (a + b)G = aG + bG, complete formulas through the identity.
        let a = Fr::from_u64(123456789);
        let b = Fr::from_u64(987654321);
        assert_eq!(g.mul(&(a + b)), g.mul(&a) + g.mul(&b));
        assert_eq!(g + G1::IDENTITY, g);
        assert_eq!(G1::IDENTITY + g, g);
        assert_eq!(g + g, g.double());
        assert_eq!(g - g, G1::IDENTITY);
        assert_eq!(G1::IDENTITY.double(), G1::IDENTITY);
    }

    #[test]
    fn serialization_round_trips() {
        let g = G1::generator();
        let c = g.to_compressed();
        assert_eq!(c[0] & 0xe0, 0x80 | (c[0] & 0x20));
        assert_eq!(G1::from_compressed(&c).unwrap(), g);
        let u = g.to_uncompressed();
        assert_eq!(u[0] & 0xe0, 0);
        assert_eq!(G1::from_uncompressed(&u).unwrap(), g);
        let ng = -g;
        assert_ne!(ng.to_compressed()[0] & 0x20, c[0] & 0x20);
        assert_eq!(G1::from_compressed(&ng.to_compressed()).unwrap(), ng);
        // Identity encodings.
        let mut inf = [0u8; 48];
        inf[0] = 0xc0;
        assert_eq!(G1::IDENTITY.to_compressed(), inf);
        assert_eq!(G1::from_compressed(&inf).unwrap(), G1::IDENTITY);
        let mut infu = [0u8; 96];
        infu[0] = 0x40;
        assert_eq!(G1::IDENTITY.to_uncompressed(), infu);
        assert_eq!(G1::from_uncompressed(&infu).unwrap(), G1::IDENTITY);
        // Flag errors.
        let mut bad = inf;
        bad[0] = 0xe0;
        assert_eq!(G1::from_compressed(&bad), Err(Error::InvalidFlags));
        bad[0] = 0x40;
        assert_eq!(G1::from_compressed(&bad), Err(Error::InvalidFlags));
        bad[0] = 0xc0;
        bad[47] = 1;
        assert_eq!(G1::from_compressed(&bad), Err(Error::InvalidFlags));
        let mut bad = c;
        bad[0] &= 0x7f;
        assert_eq!(G1::from_compressed(&bad), Err(Error::InvalidFlags));
        let mut bad = c;
        bad[0] |= 0x40;
        assert_eq!(G1::from_compressed(&bad), Err(Error::InvalidFlags));
        assert_eq!(G1::from_compressed(&c[..47]), Err(Error::InvalidLength));
        // x >= p.
        let mut bad = [0xffu8; 48];
        bad[0] = 0x9f;
        assert_eq!(G1::from_compressed(&bad), Err(Error::InvalidEncoding));
        // x = 1: 1 + 4 = 5 is a non-residue -> not on curve.
        let mut bad = [0u8; 48];
        bad[0] = 0x80;
        bad[47] = 1;
        assert_eq!(G1::from_compressed(&bad), Err(Error::NotOnCurve));
        // Uncompressed with the sort flag set is rejected.
        let mut bad = u;
        bad[0] |= 0x20;
        assert_eq!(G1::from_uncompressed(&bad), Err(Error::InvalidFlags));
        // Wrong y.
        let mut bad = u;
        bad[95] ^= 1;
        assert_eq!(G1::from_uncompressed(&bad), Err(Error::NotOnCurve));
        // from_affine validates.
        let (x, y) = g.to_affine().unwrap();
        assert_eq!(G1::from_affine(x, y).unwrap(), g);
        assert_eq!(G1::from_affine(x, x), Err(Error::NotOnCurve));
    }
}
