//! The optimal ate pairing `e: G1 × G2 → GT`.
//!
//! `e(P, Q) = f_{x,Q}(P)^(3·(p¹² - 1)/r)` with the BLS parameter
//! `x = 0x8508c00000000001` (positive, so no final conjugation). The
//! exponent carries a factor 3 — the value gnark-crypto and arkworks
//! compute, i.e. the cube of the reduced optimal ate pairing; since
//! `gcd(3, r) = 1` it is just as bilinear and non-degenerate, and matching
//! it makes `GT` values byte-identical across the three libraries.
//!
//! The Miller loop keeps the `G2` accumulator on the D-type twist
//! `E': y² = x³ + 1/u` in homogeneous projective coordinates and evaluates
//! the lines at `P` after untwisting (`ψ⁻¹(x, y) = (x·w², y·w³)`,
//! `w⁶ = u`), which makes each line the sparse `Fp12` element
//! `yP-term + xP-term·w + c·w³`, multiplied in by
//! [`Fp12::mul_by_034`]. Lines are scaled freely by `Fp2` factors (killed
//! by the final exponentiation). The final exponentiation uses the easy
//! part `(p⁶ - 1)(p² + 1)` and, for `3·(p⁴ - p² + 1)/r`, the identity
//! `3·Φ₁₂(p)/r = (x - 1)²·(x + p)·(x² + p² - 1) + 3` (Hayashida,
//! Hayasaka and Teruya, <https://eprint.iacr.org/2020/875>), checked by the
//! constants script.
//!
//! Nothing here allocates: [`multi_pairing`] streams its input in
//! fixed-size chunks whose Miller loops share one accumulator, and runs a
//! single final exponentiation.

use super::Error;
use super::constants::X;
use super::curve::Projective;
use super::fp::Fp;
use super::fp2::Fp2;
use super::fp6::Fp6;
use super::fp12::Fp12;
use super::fr::Fr;
use super::g1::G1;
use super::g2::G2;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::zeroize::Zeroize;

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
    /// table gathers and cyclotomic squarings).
    pub fn pow(&self, k: &Fr) -> Gt {
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

    /// The twelve `Fp` coefficients in tower order
    /// `c0.c0.c0, c0.c0.c1, c0.c1.c0, …, c1.c2.c1`.
    fn coefficients(&self) -> [Fp; 12] {
        let f = &self.0;
        [
            f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1, f.c1.c0.c0,
            f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
        ]
    }

    fn from_coefficients(c: &[Fp; 12]) -> Fp12 {
        let e2 = |i: usize| Fp2::new(c[i], c[i + 1]);
        Fp12::new(
            Fp6::new(e2(0), e2(2), e2(4)),
            Fp6::new(e2(6), e2(8), e2(10)),
        )
    }

    /// The 576-byte encoding of gnark-crypto (`GT.Bytes()`): the twelve
    /// coefficients big-endian, highest tower position first
    /// (`c1.c2.c1 || c1.c2.c0 || … || c0.c0.c0`).
    pub fn to_bytes(&self) -> [u8; 576] {
        let mut out = [0u8; 576];
        for (i, c) in self.coefficients().iter().rev().enumerate() {
            out[48 * i..48 * (i + 1)].copy_from_slice(&c.to_bytes());
        }
        out
    }

    /// The 576-byte arkworks encoding (`CanonicalSerialize`): the twelve
    /// coefficients little-endian, in tower order.
    pub fn to_bytes_ark(&self) -> [u8; 576] {
        let mut out = [0u8; 576];
        for (i, c) in self.coefficients().iter().enumerate() {
            out[48 * i..48 * (i + 1)].copy_from_slice(&c.to_bytes_le());
        }
        out
    }

    /// Parses the gnark-crypto encoding, checking that every coefficient is
    /// canonical and that the element lies in `GT`.
    pub fn from_bytes(bytes: &[u8; 576]) -> Result<Gt, Error> {
        let mut c = [Fp::ZERO; 12];
        for (i, slot) in c.iter_mut().rev().enumerate() {
            let mut b = [0u8; 48];
            b.copy_from_slice(&bytes[48 * i..48 * (i + 1)]);
            *slot = Fp::from_bytes(&b)
                .into_option()
                .ok_or(Error::InvalidEncoding)?;
        }
        Self::checked(Self::from_coefficients(&c))
    }

    /// Parses the arkworks encoding with the same checks.
    pub fn from_bytes_ark(bytes: &[u8; 576]) -> Result<Gt, Error> {
        let mut c = [Fp::ZERO; 12];
        for (i, slot) in c.iter_mut().enumerate() {
            let mut b = [0u8; 48];
            b.copy_from_slice(&bytes[48 * i..48 * (i + 1)]);
            *slot = Fp::from_bytes_le(&b)
                .into_option()
                .ok_or(Error::InvalidEncoding)?;
        }
        Self::checked(Self::from_coefficients(&c))
    }

    /// `GT` membership: `f` lies in the cyclotomic subgroup
    /// (`f^(p⁴) · f = f^(p²)`, i.e. `f^Φ₁₂(p) = 1`, which also rules out
    /// zero) and `f^p = f^x` (Scott, <https://eprint.iacr.org/2021/1130>):
    /// then `f^(p - x) = 1` with `p - x = h₁·r` and `gcd(h₁, Φ₁₂(p)/r) = 1`,
    /// so `f^r = 1`.
    fn checked(f: Fp12) -> Result<Gt, Error> {
        let f2 = f.frobenius_square();
        let cyclotomic = f2.frobenius_square().mul(&f).ct_eq(&f2) & !f.is_zero();
        if !bool::from(cyclotomic) {
            return Err(Error::NotInSubgroup);
        }
        if !bool::from(f.frobenius_map().ct_eq(&f.cyclotomic_pow_public_exp(X))) {
            return Err(Error::NotInSubgroup);
        }
        Ok(Gt(f))
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

impl core::ops::Mul<Gt> for Gt {
    type Output = Gt;
    #[inline]
    fn mul(self, rhs: Gt) -> Gt {
        Gt::mul(&self, &rhs)
    }
}

impl<'b> core::ops::Mul<&'b Gt> for &Gt {
    type Output = Gt;
    #[inline]
    fn mul(self, rhs: &'b Gt) -> Gt {
        Gt::mul(self, rhs)
    }
}

/// The pairing `e(P, Q)`; `e(𝒪, Q) = e(P, 𝒪) = 1`.
pub fn pairing(p: &G1, q: &G2) -> Gt {
    multi_pairing(&[(p, q)])
}

/// How many pairs one shared Miller loop processes at once (the stack
/// budget of [`multi_pairing`]: one `Leg` per pair).
const CHUNK: usize = 8;

/// `∏ e(Pᵢ, Qᵢ)` with a single final exponentiation — the cheap way to
/// evaluate a product-of-pairings equation such as a signature check.
///
/// Allocator-free: the pairs are taken `CHUNK` at a time; within a chunk the
/// Miller loops share one accumulator (one `Fp12` squaring per step for all
/// of them), and the chunks' results are multiplied together before the
/// final exponentiation. An empty slice gives the identity.
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
    let n = legs_into(chunk, &mut legs);
    shared_miller_loop(&mut legs[..n])
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

/// Whether `∏ e(Pᵢ, Qᵢ) = 1` — the pairing-product check of
/// verification equations (the pairing operation of the EIP-2539
/// precompile). The inputs are public; the verdict is returned in the
/// clear.
pub fn pairing_check(pairs: &[(&G1, &G2)]) -> bool {
    multi_pairing(pairs).is_identity().into()
}

/// One pair's state in a (shared) Miller loop.
#[derive(Clone, Copy)]
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
    fn empty() -> Leg {
        Leg {
            px: Fp::ZERO,
            py: Fp::ZERO,
            qx: Fp2::ZERO,
            qy: Fp2::ZERO,
            t: Projective::IDENTITY,
            skip: Choice::from(1),
        }
    }

    /// Doubles `T` and returns the tangent line at `T` evaluated at the
    /// untwisted `P`, as the `(1, w, w³)` coefficients
    /// `(2YZ·yP, -3X²·xP, Y² - 3b'Z²)` (scaled by `2YZ`).
    fn doubling_step(&mut self) -> (Fp2, Fp2, Fp2) {
        use super::curve::CurveField;
        let (x, y, z) = (&self.t.x, &self.t.y, &self.t.z);
        let a = x.mul(y);
        let b = y.square();
        let c = z.square();
        // e = 3b'Z², f = 9b'Z², h = (Y + Z)² - Y² - Z² = 2YZ.
        let e = c.mul_by_b3();
        let f = e.double().add(&e);
        let h = y.add(z).square().sub(&b).sub(&c);
        let x2 = x.square();
        let l_w3 = b.sub(&e);
        let l_w = x2.double().add(&x2).mul_by_fp(&self.px).neg();
        let l_1 = h.mul_by_fp(&self.py);
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
        (l_1, l_w, l_w3)
    }

    /// Adds the affine `Q` to `T` and returns the line through them
    /// evaluated at the untwisted `P`, scaled by `v = xQ·Z - X`:
    /// `v·yP - u·xP·w + (X·yQ - Y·xQ)·w³` with `u = yQ·Z - Y`.
    ///
    /// Not complete: `T ∈ {𝒪, ±Q}` would give the wrong answer, but the
    /// loop only ever adds `Q` to `[m]Q` with `2 ≤ m < x < r`.
    fn addition_step(&mut self) -> (Fp2, Fp2, Fp2) {
        let (x, y, z) = (&self.t.x, &self.t.y, &self.t.z);
        let u = self.qy.mul(z).sub(y);
        let v = self.qx.mul(z).sub(x);
        let l_w3 = x.mul(&self.qy).sub(&y.mul(&self.qx));
        let l_w = u.mul_by_fp(&self.px).neg();
        let l_1 = v.mul_by_fp(&self.py);
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
        (l_1, l_w, l_w3)
    }
}

/// Fills `legs[..pairs.len()]` (at most `CHUNK`), normalising every input
/// to affine coordinates with a single field inversion (Montgomery's trick
/// over the `G1` `Z`s and the norms of the `G2` `Z`s) — or none at all when
/// every input is already affine (`Z = 1`) or the identity. Whether that
/// fast path is taken depends only on how the inputs were produced, never
/// on their coordinates, and pairing inputs are public data.
fn legs_into(pairs: &[(&G1, &G2)], legs: &mut [Leg; CHUNK]) -> usize {
    let n = pairs.len();
    debug_assert!(n <= CHUNK);
    let mut zs = [Fp::ONE; 2 * CHUNK];
    let mut any_projective = Choice::from(0);
    for (i, (p, q)) in pairs.iter().enumerate() {
        let zp = Fp::conditional_select(&Fp::ONE, &p.0.z, p.0.z.is_zero());
        let nq = q.0.z.norm();
        let nq = Fp::conditional_select(&Fp::ONE, &nq, nq.is_zero());
        any_projective |= !zp.ct_eq(&Fp::ONE) | !nq.ct_eq(&Fp::ONE);
        zs[2 * i] = zp;
        zs[2 * i + 1] = nq;
    }
    if bool::from(any_projective) {
        let mut prefix = [Fp::ONE; 2 * CHUNK];
        let mut acc = Fp::ONE;
        for (z, pre) in zs[..2 * n].iter().zip(prefix.iter_mut()) {
            *pre = acc;
            acc = acc.mul(z);
        }
        // Nonzero by construction (every factor is nonzero).
        let mut inv = acc.invert().unwrap_or(Fp::ZERO);
        for (z, pre) in zs[..2 * n].iter_mut().zip(prefix.iter()).rev() {
            let zi = inv.mul(pre);
            inv = inv.mul(z);
            *z = zi;
        }
    }
    for (i, (p, q)) in pairs.iter().enumerate() {
        let (zp_inv, nq_inv) = (zs[2 * i], zs[2 * i + 1]);
        let zq_inv = q.0.z.conjugate().mul_by_fp(&nq_inv);
        let (qx, qy) = (q.0.x.mul(&zq_inv), q.0.y.mul(&zq_inv));
        legs[i] = Leg {
            px: p.0.x.mul(&zp_inv),
            py: p.0.y.mul(&zp_inv),
            qx,
            qy,
            t: Projective::from_affine(qx, qy),
            skip: p.0.z.is_zero() | q.0.z.is_zero(),
        };
    }
    n
}

/// Multiplies `f` by the sparse line, or leaves it alone when `skip` is set
/// (selected, so the schedule does not depend on it).
#[inline]
fn mul_line(f: &Fp12, line: (Fp2, Fp2, Fp2), skip: Choice) -> Fp12 {
    let (l_1, l_w, l_w3) = line;
    let g = f.mul_by_034(&l_1, &l_w, &l_w3);
    Fp12::conditional_select(f, &g, skip)
}

/// `∏ f_{x,Qᵢ}(Pᵢ)`, pairs whose input is the identity contributing `1`.
/// Runs a fixed schedule over the public loop constant and the number of
/// pairs.
fn shared_miller_loop(legs: &mut [Leg]) -> Fp12 {
    let mut f = Fp12::ONE;
    // Bit 63 of x is set; start below it with f = 1, T = Q.
    for bit in (0..63).rev() {
        f = f.square();
        for leg in legs.iter_mut() {
            let line = leg.doubling_step();
            f = mul_line(&f, line, leg.skip);
        }
        if (X >> bit) & 1 == 1 {
            for leg in legs.iter_mut() {
                let line = leg.addition_step();
                f = mul_line(&f, line, leg.skip);
            }
        }
    }
    f
}

/// `f^(3·(p¹² - 1)/r)`.
pub(crate) fn final_exponentiation(f: &Fp12) -> Fp12 {
    // Easy part: f^((p⁶ - 1)(p² + 1)). Miller-loop outputs are nonzero;
    // a zero input maps to zero rather than panicking.
    let inv = f.invert().unwrap_or(Fp12::ZERO);
    let t = f.conjugate().mul(&inv);
    let m = t.frobenius_square().mul(&t);
    // Hard part on the cyclotomic subgroup, exponent
    // (x - 1)²·(x + p)·(x² + p² - 1) + 3, over the public parameters.
    let a = m
        .cyclotomic_pow_public_exp(X - 1)
        .cyclotomic_pow_public_exp(X - 1);
    // b = a^(x + p)
    let b = a.cyclotomic_pow_public_exp(X).mul(&a.frobenius_map());
    // c = b^(x² + p² - 1)
    let bx2 = b.cyclotomic_pow_public_exp(X).cyclotomic_pow_public_exp(X);
    let c = bx2.mul(&b.frobenius_square()).mul(&b.conjugate());
    // · m³
    c.mul(&m.cyclotomic_square()).mul(&m)
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
        // e^r = 1 via e^(r-1)·e.
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
        let ag1 = g1.mul(&a);
        let ag2 = g2.mul(&a);
        let ng1 = -g1;
        assert!(pairing_check(&[(&ag1, &g2), (&ng1, &ag2)]));
        assert!(!pairing_check(&[(&ag1, &g2), (&g1, &ag2)]));
        assert!(pairing_check(&[]));
        assert_eq!(multi_pairing(&[(&g1, &g2), (&g1, &g2)]), e.mul(&e));
        // Gt round-trips and membership.
        assert_eq!(Gt::from_bytes(&e.to_bytes()).unwrap(), e);
        assert_eq!(Gt::from_bytes_ark(&e.to_bytes_ark()).unwrap(), e);
        assert_eq!(
            Gt::from_bytes(&Gt::IDENTITY.to_bytes()).unwrap(),
            Gt::IDENTITY
        );
    }

    /// Chunking: products over more than `CHUNK` pairs (identity legs and
    /// projective inputs mixed in) equal the product of single pairings.
    #[test]
    fn multi_pairing_across_chunks() {
        let g1 = G1::generator();
        let g2 = G2::generator();
        let mut ps = [G1::IDENTITY; 19];
        let mut qs = [G2::IDENTITY; 19];
        let mut want = Gt::IDENTITY;
        for i in 0..19 {
            let k = Fr::from_u64(3 * i as u64 + 1);
            let l = Fr::from_u64(5 * i as u64 + 2);
            ps[i] = if i % 7 == 3 { G1::IDENTITY } else { g1.mul(&k) };
            qs[i] = if i % 5 == 4 { G2::IDENTITY } else { g2.mul(&l) };
            if i % 3 == 0 {
                // Normalised (Z = 1) inputs exercise the no-inversion path.
                ps[i] = G1::from_compressed(&ps[i].to_compressed()).unwrap();
            }
            want = want.mul(&pairing(&ps[i], &qs[i]));
        }
        let mut pairs = [(&ps[0], &qs[0]); 19];
        for i in 0..19 {
            pairs[i] = (&ps[i], &qs[i]);
        }
        assert_eq!(multi_pairing(&pairs), want);
        assert_eq!(multi_pairing(&pairs[..8]), {
            let mut w = Gt::IDENTITY;
            for (p, q) in &pairs[..8] {
                w = w.mul(&pairing(p, q));
            }
            w
        });
    }

    #[test]
    fn gt_rejects_non_members() {
        let e = pairing(&G1::generator(), &G2::generator());
        // Zero, a non-cyclotomic element, and a cyclotomic element outside GT.
        assert_eq!(Gt::from_bytes(&[0u8; 576]), Err(Error::NotInSubgroup));
        // Perturb a non-constant coefficient (adding 1 would not do: for
        // e ∈ GT, (ē + 1)/(e + 1) = e⁻¹, so e + 1 maps back into GT).
        let mut f = e.0;
        f.c1.c1.c0 += Fp::ONE;
        assert_eq!(Gt::from_bytes(&Gt(f).to_bytes()), Err(Error::NotInSubgroup));
        // m = f^((p⁶-1)(p²+1)) is cyclotomic, but of order ≠ r (with
        // overwhelming odds): only the f^p = f^x test can reject it.
        let t = f.conjugate().mul(&f.invert().unwrap());
        let m = t.frobenius_square().mul(&t);
        assert!(!bool::from(
            m.pow(&super::super::constants::FR_MODULUS)
                .ct_eq(&Fp12::ONE)
        ));
        assert_eq!(Gt::from_bytes(&Gt(m).to_bytes()), Err(Error::NotInSubgroup));
        assert_eq!(
            Gt::from_bytes_ark(&Gt(m).to_bytes_ark()),
            Err(Error::NotInSubgroup)
        );
        // Non-canonical coefficient.
        let mut b = e.to_bytes();
        b[0] = 0xff;
        assert_eq!(Gt::from_bytes(&b), Err(Error::InvalidEncoding));
    }
}
