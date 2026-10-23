//! RFC 9380 hashing to BN254 with the Shallue–van de Woestijne map: the
//! suites `BN254G1_XMD:SHA-256_SVDW_RO_` / `_NU_` and
//! `BN254G2_XMD:SHA-256_SVDW_RO_` / `_NU_`, byte-compatible with
//! gnark-crypto's `HashToG1` / `EncodeToG1` / `HashToG2` / `EncodeToG2`.
//!
//! Pipeline (§3): `expand_message_xmd` with SHA-256 → `hash_to_field` with
//! `L = 48` → the SVDW map (§6.6.1, straight-line form of Appendix F.1;
//! BN254 has `A = 0`, which rules out Simplified SWU without an isogeny,
//! while SVDW works on the curve itself) → point addition → cofactor
//! clearing (nothing on `G1`, whose cofactor is 1; the
//! Fuentes-Castañeda–Knapp–Rodríguez-Henríquez `ψ` formula on `G2`).
//!
//! Every step is branch-free in the message-derived values: the map uses
//! masked selections (`CMOV`), fixed exponentiations for `inv0`,
//! `is_square` and `sqrt`, and the group law is complete on the whole
//! curve.

use super::constants::{
    SVDW1_C1, SVDW1_C2, SVDW1_C3, SVDW1_C4, SVDW1_Z, SVDW2_C1, SVDW2_C2, SVDW2_C3, SVDW2_C4,
    SVDW2_Z,
};
use super::curve::{CurveField, Projective};
use super::fp::Fp;
use super::fp2::Fp2;
use super::g1::G1;
use super::g2::G2;
use crate::ct::{Choice, ConditionallySelectable};
pub use crate::pairing_common::expand_message_xmd;

/// RFC 9380 `CMOV(a, b, c)`: `b` when `c` is true, else `a`.
#[inline]
fn cmov<T: ConditionallySelectable>(a: &T, b: &T, c: Choice) -> T {
    T::conditional_select(b, a, c)
}

/// The extra field operations the SVDW map needs.
trait SvdwField: CurveField {
    const Z: Self;
    const C1: Self;
    const C2: Self;
    const C3: Self;
    const C4: Self;
    fn is_square(&self) -> Choice;
    fn inv0(&self) -> Self;
    fn sgn0(&self) -> Choice;
}

impl SvdwField for Fp {
    const Z: Self = SVDW1_Z;
    const C1: Self = SVDW1_C1;
    const C2: Self = SVDW1_C2;
    const C3: Self = SVDW1_C3;
    const C4: Self = SVDW1_C4;
    fn is_square(&self) -> Choice {
        Fp::is_square(self)
    }
    fn inv0(&self) -> Self {
        self.invert_or_zero()
    }
    fn sgn0(&self) -> Choice {
        self.is_odd()
    }
}

impl SvdwField for Fp2 {
    const Z: Self = SVDW2_Z;
    const C1: Self = SVDW2_C1;
    const C2: Self = SVDW2_C2;
    const C3: Self = SVDW2_C3;
    const C4: Self = SVDW2_C4;
    fn is_square(&self) -> Choice {
        Fp2::is_square(self)
    }
    fn inv0(&self) -> Self {
        self.invert_or_zero()
    }
    fn sgn0(&self) -> Choice {
        Fp2::sgn0(self)
    }
}

/// `g(x) = x³ + B` (`A = 0`).
#[inline]
fn g<F: SvdwField>(x: &F) -> F {
    x.square().mul(x).add(&F::B)
}

/// The Shallue–van de Woestijne map (RFC 9380 Appendix F.1, `A = 0`),
/// straight-line: every branch of the specification is a masked selection.
fn map_to_curve_svdw<F: SvdwField>(u: &F) -> Projective<F> {
    let tv1 = u.square().mul(&F::C1);
    let tv2 = F::ONE.add(&tv1);
    let tv1 = F::ONE.sub(&tv1);
    let tv3 = tv1.mul(&tv2).inv0();
    let tv4 = u.mul(&tv1).mul(&tv3).mul(&F::C3);
    let x1 = F::C2.sub(&tv4);
    let e1 = g(&x1).is_square();
    let x2 = F::C2.add(&tv4);
    let e2 = g(&x2).is_square() & !e1;
    let x3 = tv2.square().mul(&tv3).square().mul(&F::C4).add(&F::Z);
    let x = cmov(&x3, &x1, e1);
    let x = cmov(&x, &x2, e2);
    // One of g(x1), g(x2), g(x3) is always a square, so the root exists;
    // the fallback value is never selected.
    let y = g(&x).sqrt().unwrap_or(F::ZERO);
    let e3 = !(u.sgn0() ^ y.sgn0());
    let y = cmov(&y.neg(), &y, e3);
    Projective::from_affine(x, y)
}

/// `hash_to_field` into `Fp` with `L = 48`, `count = N`.
fn hash_to_field_fp<const N: usize>(msg: &[u8], dst: &[u8]) -> [Fp; N] {
    let mut buf = [0u8; 96];
    let buf = &mut buf[..48 * N];
    expand_message_xmd(msg, dst, buf);
    let mut out = [Fp::ZERO; N];
    for (o, c) in out.iter_mut().zip(buf.chunks_exact(48)) {
        let mut b = [0u8; 48];
        b.copy_from_slice(c);
        *o = Fp::from_bytes_wide(&b);
    }
    out
}

/// `hash_to_field` into `Fp2` (`m = 2`) with `L = 48`, `count = N`.
fn hash_to_field_fp2<const N: usize>(msg: &[u8], dst: &[u8]) -> [Fp2; N] {
    let mut buf = [0u8; 192];
    let buf = &mut buf[..96 * N];
    expand_message_xmd(msg, dst, buf);
    let mut out = [Fp2::ZERO; N];
    for (o, c) in out.iter_mut().zip(buf.chunks_exact(96)) {
        let mut b0 = [0u8; 48];
        let mut b1 = [0u8; 48];
        b0.copy_from_slice(&c[..48]);
        b1.copy_from_slice(&c[48..]);
        *o = Fp2::new(Fp::from_bytes_wide(&b0), Fp::from_bytes_wide(&b1));
    }
    out
}

/// Hashes `msg` to `G1` (`BN254G1_XMD:SHA-256_SVDW_RO_`, a random oracle).
/// `dst` is the domain separation tag and must be non-empty (panics
/// otherwise, see [`expand_message_xmd`]).
pub fn hash_to_g1(msg: &[u8], dst: &[u8]) -> G1 {
    let [u0, u1] = hash_to_field_fp::<2>(msg, dst);
    G1(map_to_curve_svdw(&u0).add(&map_to_curve_svdw(&u1)))
}

/// Encodes `msg` to `G1` (`BN254G1_XMD:SHA-256_SVDW_NU_`): one map
/// evaluation, cheaper than [`hash_to_g1`] but not uniformly distributed —
/// not a random oracle. `dst` must be non-empty.
pub fn encode_to_g1(msg: &[u8], dst: &[u8]) -> G1 {
    let [u] = hash_to_field_fp::<1>(msg, dst);
    G1(map_to_curve_svdw(&u))
}

/// Hashes `msg` to `G2` (`BN254G2_XMD:SHA-256_SVDW_RO_`, a random oracle).
/// `dst` must be non-empty.
pub fn hash_to_g2(msg: &[u8], dst: &[u8]) -> G2 {
    let [u0, u1] = hash_to_field_fp2::<2>(msg, dst);
    G2::clear_cofactor(&map_to_curve_svdw(&u0).add(&map_to_curve_svdw(&u1)))
}

/// Encodes `msg` to `G2` (`BN254G2_XMD:SHA-256_SVDW_NU_`, not a random
/// oracle). `dst` must be non-empty.
pub fn encode_to_g2(msg: &[u8], dst: &[u8]) -> G2 {
    let [u] = hash_to_field_fp2::<1>(msg, dst);
    G2::clear_cofactor(&map_to_curve_svdw(&u))
}

impl G1 {
    /// Same as [`hash_to_g1`].
    pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> G1 {
        hash_to_g1(msg, dst)
    }

    /// Maps one field element to `G1` with the SVDW map (gnark-crypto's
    /// `MapToG1`; the cofactor is 1).
    pub fn map_to_curve(u: &Fp) -> G1 {
        G1(map_to_curve_svdw(u))
    }
}

impl G2 {
    /// Same as [`hash_to_g2`].
    pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> G2 {
        hash_to_g2(msg, dst)
    }

    /// Maps one field element to `G2`: the SVDW map then cofactor clearing
    /// (gnark-crypto's `MapToG2`).
    pub fn map_to_curve(u: &Fp2) -> G2 {
        G2::clear_cofactor(&map_to_curve_svdw(u))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The map lands on the curve for edge inputs, including the
    /// exceptional `u` where `1 ± c1·u² = 0` would divide by zero (`inv0`
    /// maps it to the `x3 = Z` branch) and `u = 0`.
    #[test]
    fn map_is_total() {
        for k in 0u64..40 {
            let u = Fp::from_canonical(&[k, 0, 0, 0]);
            for v in [u, -u] {
                let p = map_to_curve_svdw(&v);
                assert!(bool::from(p.is_on_curve()), "u = {k}");
                let u2 = Fp2::new(v, Fp::from_canonical(&[k * 3 + 1, 0, 0, 0]));
                let q = map_to_curve_svdw(&u2);
                assert!(bool::from(q.is_on_curve()), "u = {k}");
                assert!(bool::from(G2::map_to_curve(&u2).is_torsion_free()));
            }
        }
        // u with c1·u² = -1, i.e. tv2 = 0 (if such a root exists), and with
        // c1·u² = 1 (tv1 = 0).
        for target in [-Fp::ONE, Fp::ONE] {
            let u2 = target.mul(&SVDW1_C1.invert().unwrap());
            if let Some(u) = u2.sqrt().into_option() {
                let p = map_to_curve_svdw(&u);
                assert!(bool::from(p.is_on_curve()));
            }
        }
        // The sign of y follows the sign of u.
        let u = Fp::from_canonical(&[5, 0, 0, 0]);
        let (_, y, _) = map_to_curve_svdw(&u).to_affine();
        assert_eq!(bool::from(y.is_odd()), bool::from(u.is_odd()));
        let (_, y, _) = map_to_curve_svdw(&-u).to_affine();
        assert_eq!(bool::from(y.is_odd()), bool::from((-u).is_odd()));
    }
}
