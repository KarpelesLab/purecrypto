//! The optimal ate pairing `e: G1 × G2 → GT`.
//!
//! `f = f_{6x+2,Q}(P) · ℓ_{T,ψ(Q)}(P) · ℓ_{T+ψ(Q),−ψ²(Q)}(P)` with
//! `T = [6x+2]Q` (Vercauteren's optimal ate for BN curves), then
//! `e = f^(m·(p¹²−1)/r)` with `m = 2x(6x² + 3x + 1)`: the hard part of the
//! final exponentiation uses the Fuentes-Castañeda–Knapp–Rodríguez-Henríquez
//! decomposition `Σ λᵢ pⁱ = m·(p⁴ − p² + 1)/r`
//! (<https://eprint.iacr.org/2011/297>), which computes that fixed power
//! (`m` is coprime to `r`, so the result is still a non-degenerate bilinear
//! pairing). This is exactly the value gnark-crypto and arkworks return.
//!
//! The Miller loop keeps the `G2` accumulator on the D-type twist
//! `E': y² = x³ + b'` (`b' = 3/ξ`) in homogeneous projective coordinates;
//! with the untwist `(x, y) ↦ (x·w², y·w³)` each line evaluated at `P` is
//! the sparse `Fp12` element `c0 + c3·w + c4·w³` (`w³ = v·w`), scaled by
//! `Fp2` factors that the final exponentiation kills. Point and line come
//! out of one set of shared intermediates per step (Costello, Lange and
//! Naehrig, <https://eprint.iacr.org/2009/615>, `a = 0`). The loop runs
//! over the signed binary digits of the public constant `6x + 2`.
//!
//! Products of pairings share one Miller loop per chunk of
//! [`CHUNK`] pairs on the stack and a single final exponentiation overall,
//! so nothing here allocates.

use super::Error;
use super::constants::{ATE_NAF, FROB_2, FROB_3, FROB2_2, X};
use super::curve::{CurveField, Projective};
use super::fp::Fp;
use super::fp2::Fp2;
use super::fp12::Fp12;
use super::fr::Fr;
use super::g1::G1;
use super::g2::G2;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::zeroize::Zeroize;

/// Pairs per shared Miller loop. Each leg is about 0.5 KiB of stack.
const CHUNK: usize = 8;

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
        // The canonical limbs are the exponent in the clear; wipe them.
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

    /// The 384-byte gnark-crypto encoding: the twelve `Fp` coefficients
    /// big-endian, from `c1.c2.c1` (the last) down to `c0.c0.c0`.
    pub fn to_bytes(&self) -> [u8; 384] {
        let mut out = [0u8; 384];
        for (chunk, c) in out
            .chunks_exact_mut(32)
            .zip(self.coefficients().iter().rev())
        {
            chunk.copy_from_slice(&c.to_bytes());
        }
        out
    }

    /// Parses the 384-byte encoding of [`to_bytes`](Gt::to_bytes),
    /// validating every coefficient's canonicity and membership in `GT`
    /// (`f ≠ 0` and `f^r = 1`; the input is public, the check is a fixed
    /// exponentiation).
    pub fn from_bytes(bytes: &[u8]) -> Result<Gt, Error> {
        if bytes.len() != 384 {
            return Err(Error::InvalidLength);
        }
        let mut c = [Fp::ZERO; 12];
        for (ci, chunk) in c.iter_mut().rev().zip(bytes.chunks_exact(32)) {
            let mut b = [0u8; 32];
            b.copy_from_slice(chunk);
            *ci = Fp::from_bytes(&b)
                .into_option()
                .ok_or(Error::InvalidEncoding)?;
        }
        let f2 = |i: usize| Fp2::new(c[2 * i], c[2 * i + 1]);
        let f = Fp12 {
            c0: super::fp6::Fp6::new(f2(0), f2(1), f2(2)),
            c1: super::fp6::Fp6::new(f2(3), f2(4), f2(5)),
        };
        if bool::from(f.is_zero()) || !bool::from(f.pow(&super::constants::R_MOD).ct_eq(&Fp12::ONE))
        {
            return Err(Error::NotInSubgroup);
        }
        Ok(Gt(f))
    }

    /// The twelve coefficients in tower order `c0.c0.c0, c0.c0.c1, …,
    /// c1.c2.c1`.
    fn coefficients(&self) -> [Fp; 12] {
        let f = &self.0;
        let mut out = [Fp::ZERO; 12];
        for (i, c2) in [&f.c0.c0, &f.c0.c1, &f.c0.c2, &f.c1.c0, &f.c1.c1, &f.c1.c2]
            .into_iter()
            .enumerate()
        {
            out[2 * i] = c2.c0;
            out[2 * i + 1] = c2.c1;
        }
        out
    }
}

impl ConstantTimeEq for Gt {
    #[inline]
    fn ct_eq(&self, other: &Gt) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Gt {
    #[inline]
    fn conditional_select(a: &Gt, b: &Gt, choice: Choice) -> Gt {
        Gt(Fp12::conditional_select(&a.0, &b.0, choice))
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
    multi_pairing(&[(p, q)])
}

/// `∏ e(Pᵢ, Qᵢ)` with a single final exponentiation — the cheap way to
/// evaluate a product-of-pairings equation.
///
/// Chunks of up to eight pairs share one Miller loop (one accumulator
/// squaring per step for the whole chunk); the chunks' outputs are
/// multiplied and exponentiated once. Allocator-free.
pub fn multi_pairing(pairs: &[(&G1, &G2)]) -> Gt {
    let mut f = Fp12::ONE;
    for chunk in pairs.chunks(CHUNK) {
        f = f.mul(&chunk_miller_loop(chunk));
    }
    Gt(final_exponentiation(&f))
}

/// The shared Miller loop over at most `CHUNK` pairs.
fn chunk_miller_loop(chunk: &[(&G1, &G2)]) -> Fp12 {
    let mut legs = [Leg::empty(); CHUNK];
    for (leg, (p, q)) in legs.iter_mut().zip(chunk.iter()) {
        *leg = Leg::new(p, q);
    }
    normalise(&mut legs[..chunk.len()]);
    shared_miller_loop(&mut legs[..chunk.len()])
}

/// A streaming `∏ e(Pᵢ, Qᵢ)`: pairs are pushed one at a time, buffered
/// `CHUNK` deep on the stack and run through the shared Miller loop as each
/// chunk fills, with one final exponentiation in [`finish`](Self::finish).
/// Lets aggregate signature verification hash each message as it goes
/// instead of collecting the points first (allocator-free).
pub(crate) struct PairingAccumulator {
    f: Fp12,
    p: [G1; CHUNK],
    q: [G2; CHUNK],
    n: usize,
}

impl PairingAccumulator {
    pub(crate) fn new() -> Self {
        PairingAccumulator {
            f: Fp12::ONE,
            p: [G1::IDENTITY; CHUNK],
            q: [G2::IDENTITY; CHUNK],
            n: 0,
        }
    }

    pub(crate) fn push(&mut self, p: &G1, q: &G2) {
        self.p[self.n] = *p;
        self.q[self.n] = *q;
        self.n += 1;
        if self.n == CHUNK {
            self.flush();
        }
    }

    fn flush(&mut self) {
        let pairs: [(&G1, &G2); CHUNK] = core::array::from_fn(|i| (&self.p[i], &self.q[i]));
        let m = chunk_miller_loop(&pairs[..self.n]);
        self.f = self.f.mul(&m);
        self.n = 0;
    }

    pub(crate) fn finish(mut self) -> Gt {
        if self.n > 0 {
            self.flush();
        }
        Gt(final_exponentiation(&self.f))
    }
}

/// Whether `∏ e(Pᵢ, Qᵢ) = 1` — the pairing-product check of the Ethereum
/// `ecPairing` precompile (EIP-197). An empty product is `1` (true).
pub fn pairing_check(pairs: &[(&G1, &G2)]) -> bool {
    multi_pairing(pairs).is_identity().into()
}

/// The EIP-197 `ecPairing` precompile on its raw input: a concatenation of
/// 192-byte `(G1 uncompressed ‖ G2 uncompressed)` records, returning whether
/// the product of their pairings is `1` (true for empty input).
///
/// Every point is fully validated as EIP-197 requires — canonical
/// coordinates, on the curve, and for `G2` in the order-`r` subgroup — and
/// any failure is an error, never `false`. Processes the input in chunks on
/// the stack: allocator-free for any input length.
pub fn pairing_check_eip197(input: &[u8]) -> Result<bool, Error> {
    if !input.len().is_multiple_of(192) {
        return Err(Error::InvalidLength);
    }
    let mut f = Fp12::ONE;
    for chunk in input.chunks(192 * CHUNK) {
        let mut legs = [Leg::empty(); CHUNK];
        let n = chunk.len() / 192;
        for (leg, rec) in legs.iter_mut().zip(chunk.chunks_exact(192)) {
            let p = G1::from_uncompressed(&rec[..64])?;
            let q = G2::from_uncompressed(&rec[64..])?;
            *leg = Leg::new(&p, &q);
        }
        normalise(&mut legs[..n]);
        f = f.mul(&shared_miller_loop(&mut legs[..n]));
    }
    Ok(bool::from(final_exponentiation(&f).ct_eq(&Fp12::ONE)))
}

/// One pair's state in a (shared) Miller loop. Built projective by
/// [`Leg::new`], made affine by [`normalise`].
#[derive(Clone, Copy)]
struct Leg {
    px: Fp,
    py: Fp,
    /// `Z` of `P` until normalised (then unused).
    pz: Fp,
    qx: Fp2,
    qy: Fp2,
    /// `Z` of `Q` until normalised (then unused).
    qz: Fp2,
    t: Projective<Fp2>,
    /// Either input is the identity: the pair contributes `1`.
    skip: Choice,
}

impl Leg {
    /// A placeholder for unused chunk slots (never run through the loop).
    fn empty() -> Leg {
        Leg::new(&G1::IDENTITY, &G2::IDENTITY)
    }

    fn new(p: &G1, q: &G2) -> Leg {
        Leg {
            px: p.0.x,
            py: p.0.y,
            pz: p.0.z,
            qx: q.0.x,
            qy: q.0.y,
            qz: q.0.z,
            t: Projective::IDENTITY,
            skip: p.0.z.is_zero() | q.0.z.is_zero(),
        }
    }

    /// Doubles `T` and returns the tangent line at `T` evaluated at `P`, as
    /// the `(c0, c3, c4)` of [`Fp12::mul_by_034`] (one set of
    /// intermediates for both): `2YZ·yP − 3X²·xP·w + (Y² − 3b'Z²)·w³`.
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
        let l0 = h.mul_by_fp(&self.py);
        let l3 = x2.double().add(&x2).mul_by_fp(&self.px).neg();
        let l4 = b.sub(&e);
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
        (l0, l3, l4)
    }

    /// Adds the affine `(qx, qy)` to `T` and returns the line through them
    /// evaluated at `P`, scaled by `v = qx·Z − X`:
    /// `v·yP − u·xP·w + (X·qy − Y·qx)·w³` with `u = qy·Z − Y`.
    ///
    /// Not complete: `T = ±(qx, qy)` or `T = 𝒪` would give the wrong
    /// answer, but the loop only ever adds `±Q` to `[m]Q` with
    /// `2 ≤ m < 6x + 2 < r`, and the two Frobenius terms to multiples of
    /// `Q` that differ from them (checked in `tools/bn254/consts.py`).
    fn addition_step(&mut self, qx: &Fp2, qy: &Fp2) -> (Fp2, Fp2, Fp2) {
        let (x, y, z) = (&self.t.x, &self.t.y, &self.t.z);
        let u = qy.mul(z).sub(y);
        let v = qx.mul(z).sub(x);
        let l0 = v.mul_by_fp(&self.py);
        let l3 = u.mul_by_fp(&self.px).neg();
        let l4 = x.mul(qy).sub(&y.mul(qx));
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
        (l0, l3, l4)
    }
}

/// Makes every leg's `P` and `Q` affine with a single field inversion
/// (Montgomery's trick over the `G1` `Z`s and the norms of the `G2` `Z`s),
/// and sets `T = Q`. Identity inputs have their zero `Z` replaced by one
/// (their legs are masked out of the product). Pairing inputs are public;
/// the schedule is fixed anyway.
fn normalise(legs: &mut [Leg]) {
    debug_assert!(legs.len() <= CHUNK);
    let mut zs = [Fp::ONE; 2 * CHUNK];
    for (i, leg) in legs.iter().enumerate() {
        let zp = Fp::conditional_select(&Fp::ONE, &leg.pz, leg.pz.is_zero());
        let nq = leg.qz.c0.square().add(&leg.qz.c1.square());
        let nq = Fp::conditional_select(&Fp::ONE, &nq, nq.is_zero());
        zs[2 * i] = zp;
        zs[2 * i + 1] = nq;
    }
    let n = 2 * legs.len();
    let mut prefix = [Fp::ONE; 2 * CHUNK];
    let mut acc = Fp::ONE;
    for i in 0..n {
        prefix[i] = acc;
        acc = acc.mul(&zs[i]);
    }
    // Nonzero by construction (every factor is nonzero).
    let mut inv = acc.invert_or_zero();
    for i in (0..n).rev() {
        let zi = inv.mul(&prefix[i]);
        inv = inv.mul(&zs[i]);
        zs[i] = zi;
    }
    for (i, leg) in legs.iter_mut().enumerate() {
        let (zp_inv, nq_inv) = (zs[2 * i], zs[2 * i + 1]);
        let zq_inv = leg.qz.conjugate().mul_by_fp(&nq_inv);
        leg.px = leg.px.mul(&zp_inv);
        leg.py = leg.py.mul(&zp_inv);
        leg.qx = leg.qx.mul(&zq_inv);
        leg.qy = leg.qy.mul(&zq_inv);
        leg.pz = Fp::ONE;
        leg.qz = Fp2::ONE;
        leg.t = Projective::from_affine(leg.qx, leg.qy);
    }
}

/// Multiplies `f` by the sparse line `(c0, c3, c4)`, or leaves it alone
/// when `skip` is set (selected, so the schedule does not depend on it).
#[inline]
fn mul_line(f: &Fp12, line: (Fp2, Fp2, Fp2), skip: Choice) -> Fp12 {
    let (c0, c3, c4) = line;
    let g = f.mul_by_034(&c0, &c3, &c4);
    Fp12::conditional_select(f, &g, skip)
}

/// `∏ f_{6x+2,Qᵢ}(Pᵢ)·ℓ·ℓ'` over normalised legs, pairs whose input is the
/// identity contributing `1`. Runs a fixed schedule over the public loop
/// constant and the number of legs.
fn shared_miller_loop(legs: &mut [Leg]) -> Fp12 {
    let mut f = Fp12::ONE;
    // The top digit is 1: start below it with f = 1, T = Q.
    for i in (0..ATE_NAF.len() - 1).rev() {
        f = f.square();
        for leg in legs.iter_mut() {
            let line = leg.doubling_step();
            f = mul_line(&f, line, leg.skip);
        }
        let d = ATE_NAF[i];
        if d != 0 {
            for leg in legs.iter_mut() {
                let (qx, qy) = (leg.qx, leg.qy);
                let qy = if d > 0 { qy } else { qy.neg() };
                let line = leg.addition_step(&qx, &qy);
                f = mul_line(&f, line, leg.skip);
            }
        }
    }
    for leg in legs.iter_mut() {
        // Q1 = ψ(Q), and −ψ²(Q) = (x·ξ^((p²−1)/3), y) since ξ^((p²−1)/2) = −1.
        let q1x = leg.qx.conjugate().mul(&FROB_2);
        let q1y = leg.qy.conjugate().mul(&FROB_3);
        let line = leg.addition_step(&q1x, &q1y);
        f = mul_line(&f, line, leg.skip);
        let q2x = leg.qx.mul_by_fp(&FROB2_2);
        let q2y = leg.qy;
        let line = leg.addition_step(&q2x, &q2y);
        f = mul_line(&f, line, leg.skip);
    }
    f
}

/// `f^(m·(p¹² − 1)/r)` with `m = 2x(6x² + 3x + 1)` (see the module docs).
pub(crate) fn final_exponentiation(f: &Fp12) -> Fp12 {
    // Easy part: f^((p⁶ - 1)(p² + 1)). Miller-loop outputs are nonzero;
    // a zero input maps to zero rather than panicking.
    let inv = f.invert().unwrap_or(Fp12::ZERO);
    let t = f.conjugate().mul(&inv);
    let m = t.frobenius_square().mul(&t);
    // Hard part on the cyclotomic subgroup: m^(λ0 + λ1 p + λ2 p² + λ3 p³)
    // with λ0 = 1 + 6x + 12x² + 12x³, λ1 = 4x + 6x² + 12x³,
    // λ2 = 6x + 6x² + 12x³, λ3 = −1 + 4x + 6x² + 12x³. The exponents are
    // the public curve parameter, so the sparse square-and-multiply (one
    // multiplication per set bit of x) is used.
    let fx = m.cyclotomic_pow_public_exp(X);
    let f2x = fx.cyclotomic_square();
    let f4x = f2x.cyclotomic_square();
    let f6x = f4x.mul(&f2x);
    let f6x2 = f6x.cyclotomic_pow_public_exp(X);
    let f12x2 = f6x2.cyclotomic_square();
    let f12x3 = f12x2.cyclotomic_pow_public_exp(X);
    // a = m^λ2, b = m^λ1 = a·m^(−2x).
    let a = f12x3.mul(&f6x2).mul(&f6x);
    let b = a.mul(&f2x.conjugate());
    // m^λ0 = a·m^(6x² + 1), m^λ3 = b·m^(−1).
    let y0 = a.mul(&f6x2).mul(&m);
    let y3 = b.mul(&m.conjugate());
    y0.mul(&b.frobenius_map())
        .mul(&a.frobenius_square())
        .mul(&y3.frobenius_pow(3))
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
        assert_eq!(pairing(&g1.mul(&a), &g2), e.pow(&a));
        assert_eq!(pairing(&g1, &g2.mul(&b)), e.pow(&b));
        assert_eq!(pairing(&g1.mul(&a), &g2.mul(&b)), e.pow(&(a * b)));
        assert_eq!(pairing(&-g1, &g2).mul(&e), Gt::IDENTITY);
        assert_eq!(pairing(&g1, &-g2), e.inverse());
        assert_eq!(pairing(&G1::IDENTITY, &g2), Gt::IDENTITY);
        assert_eq!(pairing(&g1, &G2::IDENTITY), Gt::IDENTITY);
        assert_eq!(pairing(&G1::IDENTITY, &G2::IDENTITY), Gt::IDENTITY);
        let ag1 = g1.mul(&a);
        let ag2 = g2.mul(&a);
        let ng1 = -g1;
        assert!(pairing_check(&[(&ag1, &g2), (&ng1, &ag2)]));
        assert!(!pairing_check(&[(&ag1, &g2), (&g1, &ag2)]));
        assert!(pairing_check(&[]));
        assert_eq!(multi_pairing(&[(&g1, &g2), (&g1, &g2)]), e.mul(&e));
        // Gt encoding round trip and rejection of non-members.
        let bytes = e.to_bytes();
        assert_eq!(Gt::from_bytes(&bytes).unwrap(), e);
        assert_eq!(
            Gt::from_bytes(&Gt::IDENTITY.to_bytes()).unwrap(),
            Gt::IDENTITY
        );
        let mut bad = bytes;
        bad[383] ^= 1;
        assert_eq!(Gt::from_bytes(&bad), Err(Error::NotInSubgroup));
        assert_eq!(Gt::from_bytes(&[0u8; 384]), Err(Error::NotInSubgroup));
        assert_eq!(Gt::from_bytes(&[0xffu8; 384]), Err(Error::InvalidEncoding));
        assert_eq!(Gt::from_bytes(&bytes[..383]), Err(Error::InvalidLength));
    }

    /// Products across chunk boundaries equal the product of the separate
    /// pairings, with identity legs (on either side) contributing 1 and
    /// projective (`Z ≠ 1`) inputs normalised correctly.
    #[test]
    fn multi_pairing_matches_product_of_pairings() {
        let g1 = G1::generator();
        let g2 = G2::generator();
        let mut ps = [G1::IDENTITY; 19];
        let mut qs = [G2::IDENTITY; 19];
        let mut k = Fr::from_u64(0x0123_4567_89ab_cdef);
        for i in 0..19 {
            ps[i] = if i % 7 == 3 { G1::IDENTITY } else { g1.mul(&k) };
            k = k.square() + Fr::ONE;
            qs[i] = if i % 5 == 4 { G2::IDENTITY } else { g2.mul(&k) };
            k = k.square() + Fr::from_u64(3);
        }
        let mut want = Gt::IDENTITY;
        let mut pairs = [(&ps[0], &qs[0]); 19];
        for i in 0..19 {
            want = want.mul(&pairing(&ps[i], &qs[i]));
            pairs[i] = (&ps[i], &qs[i]);
        }
        assert_eq!(multi_pairing(&pairs), want);
        for n in [1usize, 7, 8, 9, 16, 17] {
            let mut w = Gt::IDENTITY;
            for (p, q) in &pairs[..n] {
                w = w.mul(&pairing(p, q));
            }
            assert_eq!(multi_pairing(&pairs[..n]), w, "n = {n}");
        }
        // Affine (decoded) inputs give the same values as projective ones.
        let pa = G1::from_uncompressed(&ps[0].to_uncompressed()).unwrap();
        let qa = G2::from_uncompressed(&qs[0].to_uncompressed()).unwrap();
        assert_eq!(pairing(&pa, &qa), pairing(&ps[0], &qs[0]));
    }

    #[test]
    fn eip197_precompile() {
        let g1 = G1::generator();
        let g2 = G2::generator();
        let a = Fr::from_u64(77);
        let mut buf = [0u8; 192 * 10];
        // Ten records: e(a·G1, G2)·e(−G1, a·G2) repeated five times = 1.
        for i in 0..5 {
            let r0 = &mut buf[384 * i..384 * i + 192];
            r0[..64].copy_from_slice(&g1.mul(&a).to_uncompressed());
            r0[64..].copy_from_slice(&g2.to_uncompressed());
            let r1 = &mut buf[384 * i + 192..384 * (i + 1)];
            r1[..64].copy_from_slice(&(-g1).to_uncompressed());
            r1[64..].copy_from_slice(&g2.mul(&a).to_uncompressed());
        }
        assert_eq!(pairing_check_eip197(&buf), Ok(true));
        assert_eq!(pairing_check_eip197(&buf[..192 * 9]), Ok(false));
        assert_eq!(pairing_check_eip197(&[]), Ok(true));
        assert_eq!(pairing_check_eip197(&buf[..191]), Err(Error::InvalidLength));
        // Identity records are allowed and contribute 1.
        let zeros = [0u8; 192];
        assert_eq!(pairing_check_eip197(&zeros), Ok(true));
        // A G2 point outside the subgroup is an error.
        let q = super::super::g2::tests::non_subgroup_point();
        let mut bad = [0u8; 192];
        bad[..64].copy_from_slice(&g1.to_uncompressed());
        bad[64..].copy_from_slice(&q.to_uncompressed());
        assert_eq!(pairing_check_eip197(&bad), Err(Error::NotInSubgroup));
        bad[64..].copy_from_slice(&g2.to_uncompressed());
        bad[63] ^= 1;
        assert_eq!(pairing_check_eip197(&bad), Err(Error::NotOnCurve));
    }

    #[test]
    fn final_exponentiation_lands_in_gt() {
        let e = pairing(&G1::generator(), &G2::generator());
        assert_eq!(e.0.pow(&super::super::constants::R_MOD), Fp12::ONE);
        // Frobenius acts as raising to p on GT.
        assert_eq!(e.0.frobenius_map(), e.0.pow(&super::super::constants::P));
    }
}
