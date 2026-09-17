//! The group `G2 = E'(Fp2)[r]` of BLS12-381, `E': y² = x³ + 4(1 + u)`.

use super::constants::{G2_X, G2_Y, PSI_X, PSI_Y, PSI2_X};
use super::curve::Projective;
use super::fp2::Fp2;
use super::fr::Fr;
use super::{Error, ops_for_group};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use core::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

/// A point of `G2`, the prime-order subgroup of the twist `E'(Fp2)`, in
/// projective coordinates.
///
/// The same validation and constant-time guarantees as [`G1`](super::G1)
/// apply: bytes-taking constructors check flags, canonicity, the curve
/// equation and subgroup membership; the group law is complete; [`mul`] is
/// constant time in the scalar.
///
/// [`mul`]: G2::mul
#[derive(Clone, Copy, Debug)]
pub struct G2(pub(crate) Projective<Fp2>);

impl G2 {
    /// The identity element.
    pub const IDENTITY: G2 = G2(Projective::IDENTITY);

    /// The standard generator.
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

    /// The untwist-Frobenius-twist endomorphism `ψ` (RFC 9380 Appendix G.3):
    /// `ψ(x, y) = (c1·x̄, c2·ȳ)` with `c1 = 1/(1+u)^((p-1)/3)`,
    /// `c2 = 1/(1+u)^((p-1)/2)`. On `G2` it acts as multiplication by `x`.
    pub(crate) fn psi(&self) -> G2 {
        G2(Projective {
            x: self.0.x.conjugate().mul(&PSI_X),
            y: self.0.y.conjugate().mul(&PSI_Y),
            z: self.0.z.conjugate(),
        })
    }

    /// `ψ²(x, y) = (c·x, -y)` with `c = 1/2^((p-1)/3) ∈ Fp`.
    pub(crate) fn psi2(&self) -> G2 {
        G2(Projective {
            x: self.0.x.mul_by_fp(&PSI2_X),
            y: self.0.y.neg(),
            z: self.0.z,
        })
    }

    /// Whether the point lies in the prime-order subgroup:
    /// `P ∈ G2 ⇔ ψ(P) = x·P` (Section 4 of
    /// <https://eprint.iacr.org/2021/1130>).
    pub fn is_torsion_free(&self) -> Choice {
        self.psi().0.ct_eq(&self.0.mul_by_x())
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

    /// `k·P`, constant time in `k`.
    #[inline]
    pub fn mul(&self, k: &Fr) -> G2 {
        G2(self.0.mul_limbs(&k.to_canonical()))
    }

    /// Maps any point of `E'(Fp2)` into `G2` by multiplying by the effective
    /// cofactor `h_eff` of RFC 9380 §8.8.2, computed with the
    /// Budroni–Pintore endomorphism formula of Appendix G.3.
    pub(crate) fn clear_cofactor(&self) -> G2 {
        let p = self.0;
        let t1 = p.mul_by_x(); // x·P
        let t2 = self.psi().0; // ψ(P)
        let t3 = G2(p.double()).psi2().0; // ψ²(2P)
        let t3 = t3.sub(&t2); // ψ²(2P) - ψ(P)
        let t2 = t1.add(&t2); // x·P + ψ(P)
        let t2 = t2.mul_by_x(); // x²·P + x·ψ(P)
        let t3 = t3.add(&t2);
        let t3 = t3.sub(&t1);
        G2(t3.sub(&p))
    }

    /// Affine coordinates, `None` for the identity.
    pub fn to_affine(&self) -> Option<(Fp2, Fp2)> {
        let (x, y, inf) = self.0.to_affine();
        if bool::from(inf) { None } else { Some((x, y)) }
    }

    /// Builds a point from affine coordinates, checking the curve equation
    /// and subgroup membership.
    pub fn from_affine(x: Fp2, y: Fp2) -> Result<G2, Error> {
        let p = G2(Projective::from_affine(x, y));
        if !bool::from(p.is_on_curve()) {
            return Err(Error::NotOnCurve);
        }
        if !bool::from(p.is_torsion_free()) {
            return Err(Error::NotInSubgroup);
        }
        Ok(p)
    }

    /// The 96-byte compressed ZCash encoding (`x.c1 || x.c0` with flags).
    pub fn to_compressed(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        self.0.write_compressed(&mut out);
        out
    }

    /// The 192-byte uncompressed ZCash encoding.
    pub fn to_uncompressed(&self) -> [u8; 192] {
        let mut out = [0u8; 192];
        self.0.write_uncompressed(&mut out);
        out
    }

    /// Parses a 96-byte compressed encoding with full validation.
    pub fn from_compressed(bytes: &[u8]) -> Result<G2, Error> {
        Self::from_compressed_unchecked(bytes)?.checked()
    }

    /// Parses a 192-byte uncompressed encoding with full validation.
    pub fn from_uncompressed(bytes: &[u8]) -> Result<G2, Error> {
        G2(Projective::read_uncompressed(bytes)?).checked()
    }

    /// Parses a compressed encoding without the subgroup check.
    pub(crate) fn from_compressed_unchecked(bytes: &[u8]) -> Result<G2, Error> {
        Ok(G2(Projective::read_compressed(bytes)?))
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
mod tests {
    use super::super::constants::H_EFF_G2;
    use super::super::fp::Fp;
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
        let g = G2::generator();
        assert!(bool::from(g.is_on_curve()));
        assert!(bool::from(g.is_torsion_free()));
        assert!(bool::from(G2(g.0.mul_limbs(&R)).is_identity()));
        let xg = G2(g.0.mul_by_x());
        let (x, y) = xg.to_affine().unwrap();
        assert_eq!(
            x.c0,
            hex48(
                "149ee6d25a1c8648c86f8673946935a6c41c801f2eb23fd9171fd41f31b7ec5c4a85f5b285f02508d928c716f9c1bc67"
            )
        );
        assert_eq!(
            x.c1,
            hex48(
                "06e63a1561fa8259ba6f6e15257a5cd4ab79697e45abf5042aa7cf28b80aa054b18d535b71cf70dafd2b694040d19479"
            )
        );
        assert_eq!(
            y.c0,
            hex48(
                "0a31b0b89b2e027b5d9201054438f7fcf510fff2b163b21a46acf330708fa11d8a37a86a347b6e882852cf7b9a5760e5"
            )
        );
        assert_eq!(
            y.c1,
            hex48(
                "053fadb2c53bf0ed7ffcf6d688029bedda2d66476494fbf7f937367aacdd0189046e74945b6e77e02b5e13023c210f7c"
            )
        );
        assert_eq!(g.psi(), xg);
        assert_eq!(g.psi().psi(), g.psi2());
        let a = Fr::from_u64(0x1234_5678_9abc);
        let b = Fr::from_u64(0xfedc_ba98);
        assert_eq!(g.mul(&(a * b)), g.mul(&a).mul(&b));
        assert_eq!(g.mul(&(a + b)), g.mul(&a) + g.mul(&b));
        assert_eq!(g.mul(&-Fr::ONE), -g);
        assert_eq!(g - g, G2::IDENTITY);
    }

    #[test]
    fn cofactor_clearing_matches_h_eff() {
        // A point of E'(Fp2) outside G2: hash-free construction by taking
        // the generator's x plus a small offset and solving for y.
        let mut x = G2_X;
        let mut p = None;
        for _ in 0..64 {
            x.c0 += Fp::ONE;
            let rhs = x.square() * x + super::super::constants::B2;
            if let Some(y) = rhs.sqrt().into_option() {
                p = Some(G2(Projective::from_affine(x, y)));
                break;
            }
        }
        let p = p.expect("found a point");
        assert!(bool::from(p.is_on_curve()));
        assert!(!bool::from(p.is_torsion_free()));
        let cleared = p.clear_cofactor();
        assert!(bool::from(cleared.is_torsion_free()));
        assert_eq!(cleared, G2(p.0.mul_limbs(&H_EFF_G2)));
        assert!(!bool::from(cleared.is_identity()));
    }

    #[test]
    fn serialization_round_trips() {
        let g = G2::generator();
        let c = g.to_compressed();
        assert_eq!(G2::from_compressed(&c).unwrap(), g);
        let u = g.to_uncompressed();
        assert_eq!(G2::from_uncompressed(&u).unwrap(), g);
        assert_eq!(G2::from_compressed(&(-g).to_compressed()).unwrap(), -g);
        let mut inf = [0u8; 96];
        inf[0] = 0xc0;
        assert_eq!(G2::IDENTITY.to_compressed(), inf);
        assert_eq!(G2::from_compressed(&inf).unwrap(), G2::IDENTITY);
        let mut infu = [0u8; 192];
        infu[0] = 0x40;
        assert_eq!(G2::IDENTITY.to_uncompressed(), infu);
        assert_eq!(G2::from_uncompressed(&infu).unwrap(), G2::IDENTITY);
        let mut bad = inf;
        bad[0] = 0xe0;
        assert_eq!(G2::from_compressed(&bad), Err(Error::InvalidFlags));
        let mut bad = inf;
        bad[95] = 1;
        assert_eq!(G2::from_compressed(&bad), Err(Error::InvalidFlags));
        let mut bad = c;
        bad[0] &= 0x7f;
        assert_eq!(G2::from_compressed(&bad), Err(Error::InvalidFlags));
        assert_eq!(G2::from_compressed(&c[..95]), Err(Error::InvalidLength));
        assert_eq!(G2::from_compressed(&u), Err(Error::InvalidLength));
        // c1 >= p.
        let mut bad = c;
        bad[0] = 0x9f;
        for b in bad[1..48].iter_mut() {
            *b = 0xff;
        }
        assert_eq!(G2::from_compressed(&bad), Err(Error::InvalidEncoding));
        // Well-formed but wrong y (uncompressed).
        let mut bad = u;
        bad[191] ^= 1;
        assert_eq!(G2::from_uncompressed(&bad), Err(Error::NotOnCurve));
    }
}
