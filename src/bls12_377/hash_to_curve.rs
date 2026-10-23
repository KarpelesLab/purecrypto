//! RFC 9380 hashing to BLS12-377, matching gnark-crypto byte for byte.
//!
//! BLS12-377 has no ciphersuite in RFC 9380; these follow the RFC's
//! construction with the parameters gnark-crypto (`HashToG1/G2`,
//! `EncodeToG1/G2`) uses, which are the de facto standard
//! (`BLS12377G1_XMD:SHA-256_SSWU_RO_` and `…G2…` by the RFC's naming):
//!
//! * `expand_message_xmd` with SHA-256, `hash_to_field` with `L = 64`;
//! * the Simplified SWU map (§6.6.2, straight-line form of Appendix F.2,
//!   with the generic `sqrt_ratio` of F.2.1.1 since `p ≡ 1 (mod 4)`) onto
//!   an isogenous curve — `E'1: y² = x³ + A'x + 22` with `Z = 5` for G1,
//!   `E'2` with `Z = 12 + u` for G2;
//! * a 2-isogeny (G1) or 23-isogeny (G2) back to `E` / `E'`;
//! * cofactor clearing: `h_eff = 1 - x` on G1, Budroni–Pintore on G2.
//!
//! The isogenous curves are the design choice gnark made; they were
//! recovered from its raw `MapToCurve1/2` outputs, and the isogenies were
//! derived from them (Vélu, Kohel) by `tools/bls12_377/derive_iso2.py` and
//! `consts.py`. gnark's G1 `Z = 5` does not satisfy RFC 9380's criteria 3–4
//! (`g(x) - Z` reducible, `g(B/(Z·A))` a non-square): the one consequence is
//! that `u = 0` has no SSWU image (both candidate `g(x)` are non-squares),
//! and gnark maps it to the identity; so does this module, by mask. Every
//! other input maps to a genuine point.
//!
//! Every step is branch-free in the message-derived values: masked
//! selections and fixed exponentiations in the maps, projective isogeny
//! evaluation (a vanishing denominator selects the identity by mask), and
//! on G1 — whose curve has 2-torsion — the 2-torsion-safe addition law for
//! the sum and the cofactor clearing.

use super::constants::{
    ISO1_A, ISO1_B, ISO1_XDEN, ISO1_XNUM, ISO1_YDEN, ISO1_YNUM, ISO2_A, ISO2_B, ISO2_XDEN,
    ISO2_XNUM, ISO2_YDEN, ISO2_YNUM, SSWU_Z1, SSWU_Z2,
};
use super::curve::{CurveField, Projective};
use super::fp::Fp;
use super::fp2::Fp2;
use super::g1::G1;
use super::g2::G2;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
pub use crate::pairing_common::expand_message_xmd;
use crate::pairing_common::expand_message_xmd_parts;

/// RFC 9380 `CMOV(a, b, c)`: `b` when `c` is true, else `a`.
#[inline]
fn cmov<T: ConditionallySelectable>(a: &T, b: &T, c: Choice) -> T {
    T::conditional_select(b, a, c)
}

/// `hash_to_field` into `Fp` with `L = 64` and `N` outputs.
fn hash_to_field_fp<const N: usize>(msg: &[&[u8]], dst: &[u8]) -> [Fp; N] {
    let mut buf = [0u8; 128];
    let buf = &mut buf[..64 * N];
    expand_message_xmd_parts(msg, dst, buf);
    let mut out = [Fp::ZERO; N];
    for (i, o) in out.iter_mut().enumerate() {
        let mut e = [0u8; 64];
        e.copy_from_slice(&buf[64 * i..64 * (i + 1)]);
        *o = Fp::from_bytes_wide(&e);
    }
    out
}

/// `hash_to_field` into `Fp2` with `L = 64` and `N` outputs
/// (`u_i = e_{i,0} + e_{i,1}·u`).
fn hash_to_field_fp2<const N: usize>(msg: &[&[u8]], dst: &[u8]) -> [Fp2; N] {
    let mut buf = [0u8; 256];
    let buf = &mut buf[..128 * N];
    expand_message_xmd_parts(msg, dst, buf);
    let elem = |off: usize| {
        let mut e = [0u8; 64];
        e.copy_from_slice(&buf[off..off + 64]);
        Fp::from_bytes_wide(&e)
    };
    let mut out = [Fp2::ZERO; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = Fp2::new(elem(128 * i), elem(128 * i + 64));
    }
    out
}

/// The Simplified SWU map (RFC 9380 F.2) onto `E': y² = x³ + A'x + B'`,
/// generic over the field; returns affine coordinates on `E'` (garbage, to
/// be masked by the caller, in the one G1 exceptional case `u = 0`).
fn map_to_curve_sswu<F, S>(
    u: &F,
    a: &F,
    b: &F,
    z: &F,
    sgn0: fn(&F) -> Choice,
    sqrt_ratio: S,
) -> (F, F)
where
    F: CurveField,
    S: Fn(&F, &F) -> (Choice, F),
{
    let tv1 = u.square();
    let tv1 = z.mul(&tv1);
    let tv2 = tv1.square();
    let tv2 = tv2.add(&tv1);
    let tv3 = tv2.add(&F::ONE);
    let tv3 = b.mul(&tv3);
    let tv4 = cmov(z, &tv2.neg(), !tv2.is_zero());
    let tv4 = a.mul(&tv4);
    let tv2 = tv3.square();
    let tv6 = tv4.square();
    let tv5 = a.mul(&tv6);
    let tv2 = tv2.add(&tv5);
    let tv2 = tv2.mul(&tv3);
    let tv6 = tv6.mul(&tv4);
    let tv5 = b.mul(&tv6);
    let tv2 = tv2.add(&tv5);
    let x = tv1.mul(&tv3);
    let (is_gx1_square, y1) = sqrt_ratio(&tv2, &tv6);
    let y = tv1.mul(u);
    let y = y.mul(&y1);
    let x = cmov(&x, &tv3, is_gx1_square);
    let y = cmov(&y, &y1, is_gx1_square);
    let e1 = sgn0(u).ct_eq(&sgn0(&y));
    let y = cmov(&y.neg(), &y, e1);
    // tv4 = A·Z or -A·tv2 is never zero, so the inverse always exists.
    let x = x.mul(&tv4.invert().unwrap_or(F::ZERO));
    (x, y)
}

/// Horner evaluation of `Σ coeffs[i]·x^i`.
fn poly<F: CurveField>(coeffs: &[F], x: &F) -> F {
    let mut acc = F::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc.mul(x).add(c);
    }
    acc
}

/// Evaluates an isogeny `(x_num/x_den, y·y_num/y_den)` projectively as
/// `(x_num·y_den : y·y_num·x_den : x_den·y_den)`, selecting the identity
/// when a denominator vanishes (the kernel).
fn iso_map<F: CurveField>(
    x: &F,
    y: &F,
    kx_num: &[F],
    kx_den: &[F],
    ky_num: &[F],
    ky_den: &[F],
) -> Projective<F> {
    let xn = poly(kx_num, x);
    let xd = poly(kx_den, x);
    let yn = poly(ky_num, x);
    let yd = poly(ky_den, x);
    let z = xd.mul(&yd);
    let p = Projective {
        x: xn.mul(&yd),
        y: y.mul(&yn).mul(&xd),
        z,
    };
    Projective::conditional_select(&Projective::IDENTITY, &p, z.is_zero())
}

/// `map_to_curve` for G1: SSWU onto `E'1`, then the 2-isogeny; `u = 0`
/// (no SSWU image under gnark's `Z`) maps to the identity.
pub(crate) fn map_to_curve_g1(u: &Fp) -> Projective<Fp> {
    let (x, y) = map_to_curve_sswu(u, &ISO1_A, &ISO1_B, &SSWU_Z1, Fp::is_odd, Fp::sqrt_ratio);
    let p = iso_map(&x, &y, &ISO1_XNUM, &ISO1_XDEN, &ISO1_YNUM, &ISO1_YDEN);
    Projective::conditional_select(&Projective::IDENTITY, &p, u.is_zero())
}

/// `map_to_curve` for G2: SSWU onto `E'2`, then the 23-isogeny.
pub(crate) fn map_to_curve_g2(u: &Fp2) -> Projective<Fp2> {
    let (x, y) = map_to_curve_sswu(u, &ISO2_A, &ISO2_B, &SSWU_Z2, Fp2::sgn0, Fp2::sqrt_ratio);
    iso_map(&x, &y, &ISO2_XNUM, &ISO2_XDEN, &ISO2_YNUM, &ISO2_YDEN)
}

/// `hash_to_curve` onto G1 (random-oracle variant, gnark-crypto's
/// `HashToG1`) with the given domain separation tag, which must be
/// non-empty (panics otherwise, see [`expand_message_xmd`]).
pub fn hash_to_g1(msg: &[u8], dst: &[u8]) -> G1 {
    hash_to_g1_parts(&[msg], dst)
}

/// [`hash_to_g1`] of the concatenation of `msg` (streamed, no buffer).
pub(crate) fn hash_to_g1_parts(msg: &[&[u8]], dst: &[u8]) -> G1 {
    let [u0, u1] = hash_to_field_fp::<2>(msg, dst);
    let q = map_to_curve_g1(&u0).add_full(&map_to_curve_g1(&u1));
    G1::clear_cofactor(&q)
}

/// `encode_to_curve` onto G1 (nonuniform variant, gnark-crypto's
/// `EncodeToG1`): one field element, one map. Not a random oracle.
pub fn encode_to_g1(msg: &[u8], dst: &[u8]) -> G1 {
    let [u] = hash_to_field_fp::<1>(&[msg], dst);
    G1::clear_cofactor(&map_to_curve_g1(&u))
}

/// `hash_to_curve` onto G2 (random-oracle variant, gnark-crypto's
/// `HashToG2`); `dst` must be non-empty.
pub fn hash_to_g2(msg: &[u8], dst: &[u8]) -> G2 {
    hash_to_g2_parts(&[msg], dst)
}

/// [`hash_to_g2`] of the concatenation of `msg` (streamed, no buffer).
pub(crate) fn hash_to_g2_parts(msg: &[&[u8]], dst: &[u8]) -> G2 {
    let [u0, u1] = hash_to_field_fp2::<2>(msg, dst);
    let q = map_to_curve_g2(&u0).add(&map_to_curve_g2(&u1));
    G2::clear_cofactor(&q)
}

/// `encode_to_curve` onto G2 (nonuniform variant, gnark-crypto's
/// `EncodeToG2`). Not a random oracle.
pub fn encode_to_g2(msg: &[u8], dst: &[u8]) -> G2 {
    let [u] = hash_to_field_fp2::<1>(&[msg], dst);
    G2::clear_cofactor(&map_to_curve_g2(&u))
}

impl G1 {
    /// Hashes a message to `G1` (see [`hash_to_g1`]).
    pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> G1 {
        hash_to_g1(msg, dst)
    }
}

impl G2 {
    /// Hashes a message to `G2` (see [`hash_to_g2`]).
    pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> G2 {
        hash_to_g2(msg, dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_land_on_the_curves() {
        for i in 0..8u64 {
            let u = Fp::from_canonical(&[i * 977 + 1, 0, 0, 0, 0, 0]);
            let (x, y) =
                map_to_curve_sswu(&u, &ISO1_A, &ISO1_B, &SSWU_Z1, Fp::is_odd, Fp::sqrt_ratio);
            assert_eq!(y.square(), x.square() * x + ISO1_A * x + ISO1_B);
            assert!(bool::from(map_to_curve_g1(&u).is_on_curve()));
            let u2 = Fp2::new(u, Fp::from_canonical(&[i + 7, 0, 0, 0, 0, 0]));
            let (x, y) =
                map_to_curve_sswu(&u2, &ISO2_A, &ISO2_B, &SSWU_Z2, Fp2::sgn0, Fp2::sqrt_ratio);
            assert_eq!(y.square(), x.square() * x + ISO2_A * x + ISO2_B);
            assert!(bool::from(map_to_curve_g2(&u2).is_on_curve()));
        }
        // u = 0: identity on G1 (gnark's convention), a real point on G2.
        assert!(bool::from(map_to_curve_g1(&Fp::ZERO).is_identity()));
        let q = map_to_curve_g2(&Fp2::ZERO);
        assert!(bool::from(q.is_on_curve()) && !bool::from(q.is_identity()));
        let h = hash_to_g1(b"abc", b"DST");
        assert!(bool::from(h.is_torsion_free()) && !bool::from(h.is_identity()));
        let h = hash_to_g2(b"abc", b"DST");
        assert!(bool::from(h.is_torsion_free()) && !bool::from(h.is_identity()));
    }
}
