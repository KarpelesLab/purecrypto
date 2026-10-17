//! Projective group arithmetic for secp256k1, generic over a [`FieldBackend`].
//!
//! secp256k1 is the short-Weierstrass curve `y² = x³ + 7` (so `a = 0`,
//! `b = 7`). Because `a = 0`, the `a·X·Z²` terms of the general
//! Renes–Costello–Batina complete-addition formulas vanish; this module uses
//! their specialised **Algorithm 7** (complete addition, `a = 0`),
//! **Algorithm 8** (complete mixed addition, `a = 0`) and **Algorithm 9**
//! (complete doubling, `a = 0`) from *"Complete addition formulas for prime
//! order elliptic curves"* (EUROCRYPT 2016). All are branch-free and correct
//! for all inputs, including the identity and equal points, so the
//! scalar-multiplication ladders need no special cases.
//!
//! # Constant-time scalar multiplication
//!
//! Every secret-scalar multiplication here reads its scalar as **signed odd
//! base-16 digits** taken directly from the nibbles of a prepared value `v`:
//! the nibble `u` stands for the digit `2u + 1 − 16 ∈ {±1, ±3, …, ±15}`, so
//! `Σ dᵢ·16ⁱ = 2v + 1 − 2^(4·windows)`. No digit is zero, no carry propagates
//! between windows, and a table of the eight odd multiples plus a masked
//! negation covers every digit. The preparation of `v` from the scalar is a
//! fixed sequence of modular operations (see [`glv`]).

use super::field_backend::{Fe, FieldBackend, mask_from_bit, select};
use super::glv;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::zeroize::Zeroize;

/// The curve constant `b3 = 3·b = 21` for `b = 7`.
const B3: u32 = 21;

/// Entries per table of odd multiples: `[1]P, [3]P, …, [15]P`.
const ODD_TABLE_LEN: usize = 8;

/// Windows of the constant-time GLV ladder: each split half, offset into
/// `[0, 2¹²⁹)`, is read as 33 base-16 digits (132 bits).
const GLV_WINDOWS: usize = 33;

/// An opaque all-ones mask when `a == b` (both below `2⁶³`), else zero:
/// `(a ^ b) − 1` borrows into the top bit exactly when `a ^ b == 0`.
#[inline]
pub(super) fn eq_mask(a: u64, b: u64) -> u64 {
    mask_from_bit((a ^ b).wrapping_sub(1) >> 63)
}

/// Window `w` of the signed-digit reading of `v`: for the nibble
/// `u = (v >> 4w) & 15` the digit is `d = 2u + 1 − 16`, odd and in
/// `[−15, 15]`, so `Σ_w d_w·16^w = 2v + 1 − 2^(4·windows) =: D(v)`. Returns
/// `((|d| − 1)/2, [d < 0])` — the index into a table of odd multiples and a
/// 0/1 negation bit — by arithmetic on the nibble alone (no branch, no
/// carry between windows).
#[inline]
pub(super) fn signed_window(v: &[u64; 4], w: usize) -> (u64, u64) {
    let u = (v[w / 16] >> ((w % 16) * 4)) & 0xf;
    let neg = (u >> 3) ^ 1;
    ((u & 7) ^ (neg.wrapping_neg() & 7), neg)
}

/// `(⌊k/2⌋ with bit `top` set, [k is even])`: the signed-digit preimage of a
/// scalar of public width (`k < 2^top`), see [`Point::mul_bits`].
#[inline]
pub(super) fn half_with_top(k: &[u64; 4], top: usize) -> ([u64; 4], u64) {
    let mut v = *Fe::from_limbs(*k).shr1().as_limbs();
    v[top / 64] |= 1 << (top % 64);
    (v, (k[0] & 1) ^ 1)
}

/// Constant-time gather of `table[index]`: scans every entry under one
/// opaque mask per entry, OR-accumulating the masked limbs (exactly one mask
/// is all ones). No secret-indexed memory access.
fn gather_point<const N: usize>(table: &[Point; N], index: u64) -> Point {
    let mut x = [0u64; 4];
    let mut y = [0u64; 4];
    let mut z = [0u64; 4];
    for (j, e) in table.iter().enumerate() {
        let m = eq_mask(j as u64, index);
        let (ex, ey, ez) = (e.x.as_limbs(), e.y.as_limbs(), e.z.as_limbs());
        for i in 0..4 {
            x[i] |= ex[i] & m;
            y[i] |= ey[i] & m;
            z[i] |= ez[i] & m;
        }
    }
    Point {
        x: Fe::from_limbs(x),
        y: Fe::from_limbs(y),
        z: Fe::from_limbs(z),
    }
}

/// `y` or `−y` under the opaque mask of the 0/1 bit `neg`.
#[inline]
pub(super) fn negate_masked<F: FieldBackend>(f: &F, y: &Fe, neg: u64) -> Fe {
    Fe::from_limbs(select(
        y.as_limbs(),
        f.negate(y).as_limbs(),
        mask_from_bit(neg),
    ))
}

/// A point in projective coordinates `(X : Y : Z)`. The identity is
/// `(0 : 1 : 0)`. Field coordinates are plain residues in `[0, p)`.
#[derive(Clone, Copy)]
pub(crate) struct Point {
    pub(crate) x: Fe,
    pub(crate) y: Fe,
    pub(crate) z: Fe,
}

impl ConditionallySelectable for Point {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Point {
            x: Fe::conditional_select(&a.x, &b.x, choice),
            y: Fe::conditional_select(&a.y, &b.y, choice),
            z: Fe::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl Zeroize for Point {
    /// Wipes the coordinates: a scalar-multiplication intermediate is as
    /// secret as the scalar that produced it.
    #[inline]
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}

impl Point {
    /// The identity point `(0 : 1 : 0)`.
    #[inline]
    pub(crate) fn identity<F: FieldBackend>(f: &F) -> Self {
        Point {
            x: f.zero(),
            y: f.one(),
            z: f.zero(),
        }
    }

    /// Lifts an affine `(x, y)` to projective `(x : y : 1)`.
    #[inline]
    pub(crate) fn from_affine<F: FieldBackend>(f: &F, x: &Fe, y: &Fe) -> Self {
        Point {
            x: *x,
            y: *y,
            z: f.one(),
        }
    }

    /// Returns a [`Choice`] that is true iff this is the identity (`Z = 0`).
    #[inline]
    pub(crate) fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Complete projective addition `p + q` for `a = 0` (RCB Algorithm 7).
    /// Correct for all inputs, including `p == q` and the identity.
    pub(crate) fn add<F: FieldBackend>(f: &F, p: &Point, q: &Point) -> Point {
        let mut t0 = f.mul(&p.x, &q.x);
        let mut t1 = f.mul(&p.y, &q.y);
        let mut t2 = f.mul(&p.z, &q.z);
        let mut t3 = f.add(&p.x, &p.y);
        let mut t4 = f.add(&q.x, &q.y);
        t3 = f.mul(&t3, &t4);
        t4 = f.add(&t0, &t1);
        t3 = f.sub(&t3, &t4);
        t4 = f.add(&p.y, &p.z);
        let mut x3 = f.add(&q.y, &q.z);
        t4 = f.mul(&t4, &x3);
        x3 = f.add(&t1, &t2);
        t4 = f.sub(&t4, &x3);
        x3 = f.add(&p.x, &p.z);
        let mut y3 = f.add(&q.x, &q.z);
        x3 = f.mul(&x3, &y3);
        y3 = f.add(&t0, &t2);
        y3 = f.sub(&x3, &y3);
        x3 = f.add(&t0, &t0);
        t0 = f.add(&x3, &t0);
        t2 = f.mul_small(&t2, B3);
        let mut z3 = f.add(&t1, &t2);
        t1 = f.sub(&t1, &t2);
        y3 = f.mul_small(&y3, B3);
        x3 = f.mul(&t4, &y3);
        t2 = f.mul(&t3, &t1);
        x3 = f.sub(&t2, &x3);
        y3 = f.mul(&y3, &t0);
        t1 = f.mul(&t1, &z3);
        y3 = f.add(&t1, &y3);
        t0 = f.mul(&t0, &t3);
        z3 = f.mul(&z3, &t4);
        z3 = f.add(&z3, &t0);

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Complete mixed addition `p + (x₂, y₂)` of a projective point and an
    /// affine one (`Z₂ = 1`): RCB Algorithm 8 (`a = 0`), the specialisation
    /// of [`Self::add`] that saves one multiplication and four additions.
    /// Correct for every `p`, including the identity and `p == (x₂, y₂)`;
    /// the affine operand is a finite point by construction (table entries
    /// are never the identity). Used by the fixed-base combs and the
    /// variable-time generator tables, hence only built with a table.
    #[cfg(any(feature = "secp256k1-table", test))]
    pub(crate) fn add_mixed<F: FieldBackend>(f: &F, p: &Point, x2: &Fe, y2: &Fe) -> Point {
        let mut t0 = f.mul(&p.x, x2);
        let mut t1 = f.mul(&p.y, y2);
        let mut t3 = f.add(x2, y2);
        let mut t4 = f.add(&p.x, &p.y);
        t3 = f.mul(&t3, &t4);
        t4 = f.add(&t0, &t1);
        t3 = f.sub(&t3, &t4);
        t4 = f.mul(y2, &p.z);
        t4 = f.add(&t4, &p.y);
        let mut y3 = f.mul(x2, &p.z);
        y3 = f.add(&y3, &p.x);
        let mut x3 = f.add(&t0, &t0);
        t0 = f.add(&x3, &t0);
        let mut t2 = f.mul_small(&p.z, B3);
        let mut z3 = f.add(&t1, &t2);
        t1 = f.sub(&t1, &t2);
        y3 = f.mul_small(&y3, B3);
        x3 = f.mul(&t4, &y3);
        t2 = f.mul(&t3, &t1);
        x3 = f.sub(&t2, &x3);
        y3 = f.mul(&y3, &t0);
        t1 = f.mul(&t1, &z3);
        y3 = f.add(&t1, &y3);
        t0 = f.mul(&t0, &t3);
        z3 = f.mul(&z3, &t4);
        z3 = f.add(&z3, &t0);

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Complete projective doubling `2·p` for `a = 0` (RCB Algorithm 9).
    pub(crate) fn double<F: FieldBackend>(f: &F, p: &Point) -> Point {
        let mut t0 = f.square(&p.y);
        let mut z3 = f.add(&t0, &t0);
        z3 = f.add(&z3, &z3);
        z3 = f.add(&z3, &z3);
        let mut t1 = f.mul(&p.y, &p.z);
        let mut t2 = f.square(&p.z);
        t2 = f.mul_small(&t2, B3);
        let mut x3 = f.mul(&t2, &z3);
        let mut y3 = f.add(&t0, &t2);
        z3 = f.mul(&t1, &z3);
        t1 = f.add(&t2, &t2);
        t2 = f.add(&t1, &t2);
        t0 = f.sub(&t0, &t2);
        y3 = f.mul(&t0, &y3);
        y3 = f.add(&x3, &y3);
        t1 = f.mul(&p.x, &p.y);
        x3 = f.mul(&t0, &t1);
        x3 = f.add(&x3, &x3);

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Returns `-p` (negate the `Y` coordinate).
    #[inline]
    pub(crate) fn negate<F: FieldBackend>(f: &F, p: &Point) -> Point {
        Point {
            x: p.x,
            y: f.negate(&p.y),
            z: p.z,
        }
    }

    /// Per-limb masked select: `a` when `mask == 0`, `b` when `mask` is all
    /// ones (one opaque mask for all twelve limbs).
    #[inline]
    pub(super) fn select_mask(a: &Point, b: &Point, mask: u64) -> Point {
        Point {
            x: Fe::from_limbs(select(a.x.as_limbs(), b.x.as_limbs(), mask)),
            y: Fe::from_limbs(select(a.y.as_limbs(), b.y.as_limbs(), mask)),
            z: Fe::from_limbs(select(a.z.as_limbs(), b.z.as_limbs(), mask)),
        }
    }

    /// The odd multiples `[1]P, [3]P, …, [15]P`: one doubling, seven
    /// additions, no secret-dependent control flow.
    fn odd_multiples<F: FieldBackend>(f: &F, p: &Point) -> [Point; ODD_TABLE_LEN] {
        let two_p = Point::double(f, p);
        let mut table = [*p; ODD_TABLE_LEN];
        for i in 1..ODD_TABLE_LEN {
            table[i] = Point::add(f, &table[i - 1], &two_p);
        }
        table
    }

    /// `Σₜ D(vₜ)·Tₜ` over `TERMS` signed-digit scalars `vₜ < 2^(4·windows)`
    /// and their odd-multiple tables, where `D(v) = 2v + 1 − 2^(4·windows)`
    /// (see [`signed_window`]). The core of every constant-time
    /// variable-base multiplication here: `windows` is a public width,
    /// every window costs four doublings (bar the first) and, per term, one
    /// eight-entry masked gather, one masked negation and one unconditional
    /// complete addition. No digit is ever zero, so no add is a no-op.
    fn mul_signed<F: FieldBackend, const TERMS: usize>(
        f: &F,
        v: &[[u64; 4]; TERMS],
        tables: &[[Point; ODD_TABLE_LEN]; TERMS],
        windows: usize,
    ) -> Point {
        let mut acc = Point::identity(f);
        let mut w = windows;
        while w > 0 {
            w -= 1;
            if w + 1 < windows {
                acc = Point::double(f, &acc);
                acc = Point::double(f, &acc);
                acc = Point::double(f, &acc);
                acc = Point::double(f, &acc);
            }
            for t in 0..TERMS {
                let (idx, neg) = signed_window(&v[t], w);
                let mut e = gather_point(&tables[t], idx);
                e.y = negate_masked(f, &e.y, neg);
                acc = Point::add(f, &acc, &e);
                e.zeroize();
            }
        }
        acc
    }

    /// Constant-time scalar multiplication `scalar · point` for a reduced
    /// scalar (`< n`, little-endian limbs) — the GLV method in constant time:
    ///
    /// 1. the scalar is split into two ~128-bit halves `k ≡ k₁ + k₂·λ` by a
    ///    fixed sequence of modular operations ([`glv::glv_prepare`]), each
    ///    offset into `[0, 2¹²⁹)` so no sign-dependent negation is needed;
    /// 2. each half is read as 33 signed odd base-16 digits straight from its
    ///    nibbles (no carry-propagating recoding), so the two eight-entry
    ///    tables of odd multiples `[1]P … [15]P` and `[1]φ(P) … [15]φ(P)`
    ///    (`φ(x, y) = (β·x, y)`, eight field multiplications) suffice;
    /// 3. a single ladder of 128 doublings interleaves the two halves with
    ///    one masked gather, one masked negation and one unconditional
    ///    complete addition per half per window — 66 additions in all.
    ///
    /// Every table lookup is a scan of all eight entries under one opaque
    /// mask per entry; neither the operation schedule nor any memory index
    /// depends on the scalar. This path carries the ECDSA nonce, private
    /// keys, ECDH scalars and every zkp prover's secret multipliers.
    pub(crate) fn mul<F: FieldBackend>(f: &F, scalar: &[u64; 4], point: &Point) -> Point {
        let (mut v1, mut v2) = glv::glv_prepare(&Fe::from_limbs(*scalar));
        let mut t1 = Self::odd_multiples(f, point);
        let mut t2 = t1;
        for e in &mut t2 {
            e.x = f.mul(&e.x, &glv::BETA);
        }
        let acc = Self::mul_signed(f, &[*v1.as_limbs(), *v2.as_limbs()], &[t1, t2], GLV_WINDOWS);
        // The split halves and the tables of multiples of the input point are
        // as secret as the scalar; wipe them before the frame goes away.
        v1.zeroize();
        v2.zeroize();
        t1.zeroize();
        t2.zeroize();
        acc
    }

    /// Constant-time `scalar · point` for a scalar whose **width** is public:
    /// `scalar < 2^BITS` (`BITS` a multiple of four, at most 252), e.g. the
    /// 64-bit committed values of Pedersen commitments and range proofs
    /// (libsecp256k1-zkp's `ecmult_const(…, 64)`). Same construction as
    /// [`Self::mul`] without the GLV split: `BITS/4 + 1` windows over one
    /// table of odd multiples, every window the same work, so the timing
    /// depends on `BITS` alone and not on the value.
    ///
    /// The scalar `k` is halved, `v = ⌊k/2⌋ + 2^(4·windows − 1)`, so
    /// `D(v) = k + (1 − k mod 2)`; a final masked subtraction of `P` corrects
    /// even scalars. Bits of `scalar` at or above `BITS` are the caller's to
    /// keep clear.
    pub(crate) fn mul_bits<F: FieldBackend, const BITS: usize>(
        f: &F,
        scalar: &[u64; 4],
        point: &Point,
    ) -> Point {
        const { assert!(BITS.is_multiple_of(4) && BITS > 0 && BITS <= 252) };
        let windows = BITS / 4 + 1;
        let (mut v, even) = half_with_top(scalar, 4 * windows - 1);
        let mut table = Self::odd_multiples(f, point);
        let acc = Self::mul_signed(f, &[v], &[table], windows);
        let corrected = Point::add(f, &acc, &Point::negate(f, point));
        let out = Point::select_mask(&acc, &corrected, mask_from_bit(even));
        v.zeroize();
        table.zeroize();
        out
    }

    /// The previous constant-time ladder — a fixed 4-bit window over the 16
    /// multiples `[0]P … [15]P` with 256 doublings — kept as the
    /// differential oracle for [`Self::mul`], [`Self::mul_bits`] and the
    /// fixed-base combs.
    #[cfg(test)]
    pub(crate) fn mul_reference<F: FieldBackend>(f: &F, scalar: &[u64; 4], point: &Point) -> Point {
        let mut table = [Point::identity(f); 16];
        table[1] = *point;
        for i in 2..16 {
            table[i] = Point::add(f, &table[i - 1], point);
        }
        let mut acc = Point::identity(f);
        let mut i = 4;
        while i > 0 {
            i -= 1;
            let limb = scalar[i];
            let mut shift = 64;
            while shift > 0 {
                shift -= 4;
                for _ in 0..4 {
                    acc = Point::double(f, &acc);
                }
                let digit = ((limb >> shift) & 0xf) as usize;
                let mut sel = table[0];
                for (j, entry) in table.iter().enumerate() {
                    sel = Point::conditional_select(entry, &sel, j.ct_eq(&digit));
                }
                acc = Point::add(f, &acc, &sel);
            }
        }
        acc
    }

    /// Converts to affine `(x, y)`, returning `None` for the identity. The
    /// inversion uses the constant-time safegcd inverse from the field backend.
    // Takes `&self` for consistency with the other by-reference point ops.
    #[allow(clippy::wrong_self_convention)]
    ///
    /// Whether the point is the identity is public in every in-crate caller:
    /// the group has prime order, so `[k]P` is the identity iff
    /// `k ≡ 0 (mod n)` or `P` is — a degenerate scalar or point the caller
    /// rejects as an error.
    pub(crate) fn to_affine<F: FieldBackend>(&self, f: &F) -> Option<(Fe, Fe)> {
        if self.is_identity().declassify() {
            return None;
        }
        let z_inv = f.invert(&self.z);
        let x = f.mul(&self.x, &z_inv);
        let y = f.mul(&self.y, &z_inv);
        Some((x, y))
    }

    /// Constant-time projective equality (cross-multiplied, so different
    /// representatives of the same point compare equal). Both being the
    /// identity also compares equal.
    pub(crate) fn ct_eq<F: FieldBackend>(&self, f: &F, other: &Point) -> Choice {
        // X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1.
        let x1z2 = f.mul(&self.x, &other.z);
        let x2z1 = f.mul(&other.x, &self.z);
        let y1z2 = f.mul(&self.y, &other.z);
        let y2z1 = f.mul(&other.y, &self.z);
        x1z2.ct_eq(&x2z1) & y1z2.ct_eq(&y2z1)
    }
}

#[cfg(test)]
pub(super) mod tests {
    //! Differential tests: every new multiplication path against the
    //! previous unsigned-window ladder, over edge scalars and a
    //! pseudo-random batch, on the generator, the identity, `−G` and random
    //! points.

    use super::*;
    use crate::ec::secp256k1::field_backend::Secp256k1Field;
    use crate::ec::secp256k1::{ProjectivePoint, Scalar};

    pub(crate) struct SplitMix64(pub(crate) u64);
    impl SplitMix64 {
        pub(crate) fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        pub(crate) fn scalar(&mut self) -> Fe {
            let v = Fe::from_limbs([
                self.next_u64(),
                self.next_u64(),
                self.next_u64(),
                self.next_u64(),
            ]);
            v.reduce(&Scalar::ORDER)
        }
    }

    fn pow2(e: usize) -> Fe {
        let mut l = [0u64; 4];
        l[e / 64] = 1 << (e % 64);
        Fe::from_limbs(l)
    }

    /// Scalars at the boundaries of the split, the offsets and the digit
    /// reading: 0, 1, 2, 15, 16, n − 1, n − 2, n/2, n/2 + 1, λ, −λ, 2¹²⁸ ± 1,
    /// 2¹²⁸, 2²⁵⁵, all-F nibbles.
    pub(crate) fn edge_scalars() -> [Fe; 16] {
        let n = Scalar::ORDER;
        let m = &Scalar::MODULUS;
        [
            Fe::ZERO,
            Fe::ONE,
            Fe::from_u64(2),
            Fe::from_u64(15),
            Fe::from_u64(16),
            n.wrapping_sub(&Fe::ONE),
            n.wrapping_sub(&Fe::from_u64(2)),
            n.shr1(),
            n.shr1().wrapping_add(&Fe::ONE),
            glv::LAMBDA,
            m.sub_mod(&Fe::ZERO, &glv::LAMBDA),
            pow2(128).wrapping_sub(&Fe::ONE),
            pow2(128),
            pow2(128).wrapping_add(&Fe::ONE),
            pow2(255),
            Fe::from_limbs([u64::MAX, u64::MAX, u64::MAX, 0x0FFF_FFFF_FFFF_FFFF]),
        ]
    }

    fn points(f: &Secp256k1Field, rng: &mut SplitMix64) -> [Point; 6] {
        let g = ProjectivePoint::generator().0;
        let mut pts = [g; 6];
        pts[1] = Point::identity(f);
        pts[2] = Point::negate(f, &g);
        for p in &mut pts[3..] {
            *p = Point::mul_reference(f, rng.scalar().as_limbs(), &g);
        }
        pts
    }

    /// The GLV ladder agrees with the reference ladder.
    #[test]
    fn glv_mul_matches_reference() {
        let f = Secp256k1Field::new();
        let mut rng = SplitMix64(0x6C5F_0001);
        let pts = points(&f, &mut rng);
        let check = |k: &Fe, p: &Point| {
            let want = Point::mul_reference(&f, k.as_limbs(), p);
            let got = Point::mul(&f, k.as_limbs(), p);
            assert!(bool::from(got.ct_eq(&f, &want)), "k={:x?}", k.as_limbs());
        };
        for k in &edge_scalars() {
            for p in &pts {
                check(k, p);
            }
        }
        for i in 0..400 {
            check(&rng.scalar(), &pts[i % pts.len()]);
        }
    }

    /// The public-width ladder agrees with the reference for 64-bit values,
    /// including 0, 1, odd/even and `2⁶⁴ − 1`, and for a 128-bit width.
    #[test]
    fn mul_bits_matches_reference() {
        let f = Secp256k1Field::new();
        let mut rng = SplitMix64(0x6C5F_0002);
        let pts = points(&f, &mut rng);
        let edges = [0u64, 1, 2, 3, 15, 16, 17, 1 << 63, u64::MAX - 1, u64::MAX];
        let check64 = |k: u64, p: &Point| {
            let k = Fe::from_u64(k);
            let want = Point::mul_reference(&f, k.as_limbs(), p);
            let got = Point::mul_bits::<_, 64>(&f, k.as_limbs(), p);
            assert!(bool::from(got.ct_eq(&f, &want)), "k={:x?}", k.as_limbs());
        };
        for &k in &edges {
            for p in &pts {
                check64(k, p);
            }
        }
        for i in 0..200 {
            check64(rng.next_u64(), &pts[i % pts.len()]);
        }
        for i in 0..50 {
            let k = Fe::from_limbs([rng.next_u64(), rng.next_u64(), 0, 0]);
            let want = Point::mul_reference(&f, k.as_limbs(), &pts[i % pts.len()]);
            let got = Point::mul_bits::<_, 128>(&f, k.as_limbs(), &pts[i % pts.len()]);
            assert!(bool::from(got.ct_eq(&f, &want)));
        }
    }

    /// Mixed addition agrees with the full formula, including `p` the
    /// identity, `p == q` and `p == −q`.
    #[test]
    fn add_mixed_matches_add() {
        let f = Secp256k1Field::new();
        let mut rng = SplitMix64(0x6C5F_0003);
        let pts = points(&f, &mut rng);
        for p in &pts {
            for q in &pts {
                let Some((qx, qy)) = q.to_affine(&f) else {
                    continue;
                };
                let want = Point::add(&f, p, &Point::from_affine(&f, &qx, &qy));
                let got = Point::add_mixed(&f, p, &qx, &qy);
                assert!(bool::from(got.ct_eq(&f, &want)));
                // Against the same representative with a non-trivial Z.
                let want = Point::add(&f, p, q);
                assert!(bool::from(got.ct_eq(&f, &want)));
            }
        }
    }

    /// The signed digits of `v` sum to `D(v) = 2v + 1 − 2^(4·windows)`.
    #[test]
    fn signed_window_digits_sum() {
        let mut rng = SplitMix64(0x6C5F_0004);
        for _ in 0..200 {
            let v = [rng.next_u64(), rng.next_u64(), rng.next_u64(), 0];
            // Σ d_w 16^w as a signed 256-bit value, built from the top.
            let mut acc: i128 = 0; // only the low windows fit; check low 28.
            for w in (0..28).rev() {
                let (idx, neg) = signed_window(&v, w);
                let d = (2 * idx as i128 + 1) * if neg == 1 { -1 } else { 1 };
                acc = acc * 16 + d;
            }
            let low = (v[0] as u128 | ((v[1] as u128) << 64)) & ((1u128 << 112) - 1);
            let want = 2 * low as i128 + 1 - (1i128 << 112);
            assert_eq!(acc, want);
        }
    }
}
