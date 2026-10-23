//! The group `G2 = E'(Fp2)[r]` of BLS12-377, on the D-type sextic twist
//! `E': y² = x³ + 1/u`.

use super::constants::{G2_X, G2_Y, PSI_X, PSI_Y, PSI2_X, X};
use super::curve::Projective;
use super::fp2::Fp2;
use super::fr::Fr;
use super::{Error, ops_for_group};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

/// A point of `G2`, the prime-order subgroup of the twist `E'(Fp2)`, in
/// projective coordinates.
///
/// The same validation and constant-time guarantees as [`G1`](super::G1)
/// apply: every constructor taking untrusted input checks canonicity, the
/// twist equation and subgroup membership; [`mul`] is constant time in the
/// scalar. `E'(Fp2)` has odd order, so the group law is complete on it.
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

    /// The untwist-Frobenius-twist endomorphism of the D-type twist:
    /// `ψ(x, y) = (x̄·u^((p-1)/3), ȳ·u^((p-1)/2))`. On `G2` it acts as
    /// multiplication by `p ≡ x (mod r)`.
    pub(crate) fn psi(p: &Projective<Fp2>) -> Projective<Fp2> {
        Projective {
            x: p.x.conjugate().mul(&PSI_X),
            y: p.y.conjugate().mul(&PSI_Y),
            z: p.z.conjugate(),
        }
    }

    /// `ψ²(x, y) = (c·x, -y)` with `c = u^((p²-1)/3) ∈ Fp`.
    pub(crate) fn psi2(p: &Projective<Fp2>) -> Projective<Fp2> {
        Projective {
            x: p.x.mul_by_fp(&PSI2_X),
            y: p.y.neg(),
            z: p.z,
        }
    }

    /// Whether a point of `E'(Fp2)` lies in the prime-order subgroup:
    /// `ψ(P) = x·P` (Scott, <https://eprint.iacr.org/2021/1130>). Sound
    /// for BLS12-377: `ψ - x` has degree `p - x = h₁·r` and
    /// `gcd(h₁, h₂) = 1`, so its rational kernel is exactly `G2` (checked
    /// by the constants script).
    fn torsion_free(p: &Projective<Fp2>) -> Choice {
        Self::psi(p).ct_eq(&p.mul_by_x())
    }

    /// Whether the point lies in the prime-order subgroup (always true for
    /// a `G2` value).
    pub fn is_torsion_free(&self) -> Choice {
        Self::torsion_free(&self.0)
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
    ///
    /// Four-dimensional GLS: `ψ` acts as multiplication by `x`, so with the
    /// base-`x` digits `k = d₀ + d₁x + d₂x² + d₃x³` (all below `x < 2^64`
    /// since `k < r < x⁴`) `k·P = d₀·P + d₁·ψ(P) + d₂·ψ²(P) + d₃·ψ³(P)`,
    /// a four-way multi-scalar multiplication over 64-bit digits. The split
    /// is three constant-time divisions (`div_rem_ct` in the curve module).
    pub fn mul(&self, k: &Fr) -> G2 {
        let mut limbs = k.to_canonical();
        let (mut q1, d0) = super::curve::div_rem_ct(&limbs, X as u128);
        let (mut q2, d1) = super::curve::div_rem_ct(&q1, X as u128);
        let (mut q3, d2) = super::curve::div_rem_ct(&q2, X as u128);
        let mut digits = [d0 as u64, d1 as u64, d2 as u64, q3[0]];
        let psi = Self::psi(&self.0);
        let psi2 = Self::psi2(&self.0);
        let points = [self.0, psi, psi2, Self::psi(&psi2)];
        let r = G2(Projective::mul_4x64(&points, &digits));
        limbs.zeroize();
        q1.zeroize();
        q2.zeroize();
        q3.zeroize();
        digits.zeroize();
        r
    }

    /// Maps any point of `E'(Fp2)` into `G2` by the Budroni–Pintore
    /// formula `[x² - x - 1]P + [x - 1]ψ(P) + ψ²(2P)` — the effective
    /// cofactor RFC 9380 uses for BLS12 curves, and what gnark-crypto
    /// computes.
    pub(crate) fn clear_cofactor(p: &Projective<Fp2>) -> G2 {
        let t1 = p.mul_by_x(); // x·P
        let t2 = Self::psi(p); // ψ(P)
        let t3 = Self::psi2(&p.double()).sub(&t2); // ψ²(2P) - ψ(P)
        let t2 = t1.add(&t2).mul_by_x(); // x²·P + x·ψ(P)
        G2(t3.add(&t2).sub(&t1).sub(p))
    }

    /// Affine coordinates, `None` for the identity.
    pub fn to_affine(&self) -> Option<(Fp2, Fp2)> {
        let (x, y, inf) = self.0.to_affine();
        if bool::from(inf) { None } else { Some((x, y)) }
    }

    /// Builds a point from affine coordinates, checking the twist equation
    /// and subgroup membership.
    pub fn from_affine(x: Fp2, y: Fp2) -> Result<G2, Error> {
        Self::checked(Projective::from_affine(x, y))
    }

    /// The 96-byte compressed encoding of gnark-crypto (`x.c1 || x.c0`,
    /// big-endian, ZCash flags).
    pub fn to_compressed(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        self.0.write_compressed(&mut out);
        out
    }

    /// The 192-byte uncompressed encoding of gnark-crypto.
    pub fn to_uncompressed(&self) -> [u8; 192] {
        let mut out = [0u8; 192];
        self.0.write_uncompressed(&mut out);
        out
    }

    /// Parses a 96-byte compressed encoding with full validation.
    pub fn from_compressed(bytes: &[u8]) -> Result<G2, Error> {
        Self::checked(Projective::read_compressed(bytes)?)
    }

    /// Parses a 192-byte uncompressed encoding with full validation.
    pub fn from_uncompressed(bytes: &[u8]) -> Result<G2, Error> {
        Self::checked(Projective::read_uncompressed(bytes)?)
    }

    /// The 96-byte arkworks compressed encoding (`x.c0 || x.c1`,
    /// little-endian, flags in the last byte).
    pub fn to_compressed_ark(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        self.0.write_ark_compressed(&mut out);
        out
    }

    /// The 192-byte arkworks uncompressed encoding.
    pub fn to_uncompressed_ark(&self) -> [u8; 192] {
        let mut out = [0u8; 192];
        self.0.write_ark_uncompressed(&mut out);
        out
    }

    /// Parses an arkworks compressed encoding with full validation.
    pub fn from_compressed_ark(bytes: &[u8]) -> Result<G2, Error> {
        Self::checked(Projective::read_ark_compressed(bytes)?)
    }

    /// Parses an arkworks uncompressed encoding with full validation.
    pub fn from_uncompressed_ark(bytes: &[u8]) -> Result<G2, Error> {
        Self::checked(Projective::read_ark_uncompressed(bytes)?)
    }

    fn checked(p: Projective<Fp2>) -> Result<G2, Error> {
        if !bool::from(p.is_on_curve()) {
            return Err(Error::NotOnCurve);
        }
        if !bool::from(Self::torsion_free(&p)) {
            return Err(Error::NotInSubgroup);
        }
        Ok(G2(p))
    }
}

ops_for_group!(G2);

#[cfg(test)]
mod tests {
    use super::super::constants::FR_MODULUS;
    use super::super::fp::Fp;
    use super::*;

    #[test]
    fn generator_order_and_arithmetic() {
        let g = G2::generator();
        assert!(bool::from(g.is_on_curve()));
        assert!(bool::from(g.is_torsion_free()));
        assert!(bool::from(G2(g.0.mul_limbs(&FR_MODULUS)).is_identity()));
        let xg = G2(g.0.mul_by_x());
        assert_eq!(G2(G2::psi(&g.0)), xg);
        assert_eq!(G2(G2::psi(&G2::psi(&g.0))), G2(G2::psi2(&g.0)));
        let k = Fr::from_bytes_wide(&[0xa5; 64]);
        assert_eq!(g.mul(&k), G2(g.0.mul_limbs(&k.to_canonical())));
        let a = Fr::from_u64(0x1234_5678_9abc);
        let b = Fr::from_u64(0xfedc_ba98);
        assert_eq!(g.mul(&(a * b)), g.mul(&a).mul(&b));
        assert_eq!(g.mul(&(a + b)), g.mul(&a) + g.mul(&b));
        assert_eq!(g.mul(&-Fr::ONE), -g);
        assert_eq!(g.mul(&Fr::ZERO), G2::IDENTITY);
        assert_eq!(g - g, G2::IDENTITY);
        // 3b'·x by the shortcut equals the product with the constant.
        use super::super::curve::CurveField;
        let (x, _) = g.to_affine().unwrap();
        let three = Fp2::new(Fp::from_canonical(&[3, 0, 0, 0, 0, 0]), Fp::ZERO);
        assert_eq!(
            CurveField::mul_by_b3(&x),
            x * three * super::super::constants::B2
        );
        for k in [a, b, k] {
            let p = g.mul(&k);
            assert_eq!(G2::from_compressed(&p.to_compressed()).unwrap(), p);
            assert_eq!(G2::from_uncompressed(&p.to_uncompressed()).unwrap(), p);
            assert_eq!(G2::from_compressed_ark(&p.to_compressed_ark()).unwrap(), p);
            assert_eq!(
                G2::from_uncompressed_ark(&p.to_uncompressed_ark()).unwrap(),
                p
            );
        }
        let i = G2::IDENTITY;
        assert_eq!(G2::from_compressed(&i.to_compressed()).unwrap(), i);
        assert_eq!(
            G2::from_uncompressed_ark(&i.to_uncompressed_ark()).unwrap(),
            i
        );
    }

    #[test]
    fn rejects_points_outside_the_subgroup() {
        // Lift x = 1, 2, ... (real coordinates) onto the twist: such points
        // have a nontrivial cofactor component with overwhelming probability.
        let mut x = Fp2::ONE;
        let mut found = 0;
        while found < 3 {
            let rhs = x.square() * x + super::super::constants::B2;
            if let Some(y) = rhs.sqrt().into_option() {
                let p = Projective::from_affine(x, y);
                assert!(bool::from(p.is_on_curve()));
                assert!(!bool::from(G2::torsion_free(&p)));
                let w = G2(p);
                assert_eq!(
                    G2::from_compressed(&w.to_compressed()),
                    Err(Error::NotInSubgroup)
                );
                assert_eq!(
                    G2::from_uncompressed(&w.to_uncompressed()),
                    Err(Error::NotInSubgroup)
                );
                assert_eq!(
                    G2::from_compressed_ark(&w.to_compressed_ark()),
                    Err(Error::NotInSubgroup)
                );
                let c = G2::clear_cofactor(&p);
                assert!(bool::from(c.is_torsion_free()) && !bool::from(c.is_identity()));
                found += 1;
            }
            x += Fp2::ONE;
        }
        // Malformed encodings.
        let g = G2::generator();
        let c = g.to_compressed();
        assert_eq!(G2::from_compressed(&c[..95]), Err(Error::InvalidLength));
        let mut z = c;
        z[0] &= 0x7f;
        assert_eq!(G2::from_compressed(&z), Err(Error::InvalidFlags));
        let mut z = c;
        z[48] |= 0x10; // non-canonical x.c0 (bit 380)
        assert_eq!(G2::from_compressed(&z), Err(Error::InvalidEncoding));
        let mut z = g.to_uncompressed();
        z[191] ^= 1;
        assert_eq!(G2::from_uncompressed(&z), Err(Error::NotOnCurve));
    }
}
