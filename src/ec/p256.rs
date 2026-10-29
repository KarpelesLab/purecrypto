//! NIST P-256 (secp256r1) field and group arithmetic.
//!
//! The base field runs on the native Montgomery backend
//! ([`super::p256_field`]): every coordinate below is a Montgomery residue
//! `a·R mod p`, converted once at the SEC1 boundary ([`P256::lift_affine`]
//! / [`P256::to_affine`]) so the point formulas and the precomputed
//! generator table never convert.

use super::p256_field as field;
#[cfg(feature = "p256-table")]
use super::p256_gtable::{P256_GEN_TABLE, P256_GEN_TOP};
use crate::bignum::safegcd::SafegcdModulus;
use crate::bignum::{MontModulus, Uint};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use crate::rng::RngCore;
use crate::zeroize::Zeroize;

/// Field elements and scalars are four 64-bit limbs (256 bits).
pub(crate) type Fe = Uint<4>;

/// Generates a uniformly random scalar in `[1, n-1]`.
///
/// Rejection sampling: draw 256 uniform bits and accept only if the value
/// lies in `[1, n)`. Reducing a 256-bit draw mod `n` would introduce a
/// modulo-bias of magnitude `2^256 - n ≈ 2^128` extra preimages on a small
/// residue band — vanishingly small for P-256 but a nonzero asymmetry with
/// the boxed path (`src/ec/boxed.rs`), which already rejects. Mirroring the
/// rejection collapses the bias to zero. P-256's `n` is so close to `2^256`
/// that the per-iteration acceptance probability is effectively 1.
pub(crate) fn random_scalar<R: RngCore>(rng: &mut R) -> Fe {
    let n = P256::order();
    loop {
        let mut limbs = [0u64; 4];
        for limb in &mut limbs {
            *limb = rng.next_u64();
        }
        let d = Uint::from_limbs(limbs);
        // Accept iff 1 ≤ d < n: one non-short-circuiting verdict, public
        // (FIPS 186-5 A.4.2 rejection sampling; only the retry count, which
        // is independent of the accepted scalar, is observable).
        if (!d.is_zero() & d.ct_lt(&n)).declassify() {
            return d;
        }
    }
}

// Curve parameters (hex, big-endian).
const B_HEX: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
/// The curve coefficient `b`, decoded and converted to Montgomery form at
/// compile time.
const B: Fe = field::to_mont_const(&fe_from_hex(B_HEX));
#[cfg(any(test, not(feature = "p256-table")))]
const GX_HEX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
#[cfg(any(test, not(feature = "p256-table")))]
const GY_HEX: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
/// The generator's affine coordinates in Montgomery form (compile-time
/// conversion of the FIPS 186 hex) — the same values as
/// `P256_GEN_TABLE[0][0]`.
#[cfg(any(test, not(feature = "p256-table")))]
const GX: Fe = field::to_mont_const(&fe_from_hex(GX_HEX));
#[cfg(any(test, not(feature = "p256-table")))]
const GY: Fe = field::to_mont_const(&fe_from_hex(GY_HEX));
const N_HEX: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
/// The group order `n`, decoded at compile time.
const ORDER: Fe = fe_from_hex(N_HEX);
/// The order-`n` Montgomery context, so ECDSA does not redo the `R² mod n`
/// setup on every sign / verify.
static ORDER_MODULUS: MontModulus<4> = MontModulus::new(ORDER);
/// The order-`n` safegcd inversion context, built at compile time.
static ORDER_SAFEGCD: SafegcdModulus = SafegcdModulus::new(&ORDER);

/// Width in bits of the fixed-base comb's signed windows: each window holds
/// the `2^(COMB_W − 1)` odd multiples `[1, 3, …, 2^COMB_W − 1]·B^i·G`,
/// `B = 2^COMB_W`. Wider windows mean fewer additions per `[k]G` but larger
/// windows to scan and a larger table. 5 bits (52 windows × 16 entries,
/// 52 KB) takes 12 additions off the 4-bit comb (32 KB) for ~1 µs of
/// signing on x86-64; 6 bits (88 KB) buys only ~0.6 µs more.
/// (Defined without the table too, for its generator test.)
#[cfg(any(all(test, feature = "std"), feature = "p256-table"))]
pub(crate) const COMB_W: usize = 5;
/// Entries per comb window.
#[cfg(any(all(test, feature = "std"), feature = "p256-table"))]
pub(crate) const COMB_ENTRIES: usize = 1 << (COMB_W - 1);
/// Number of comb windows: enough `COMB_W`-bit digits to cover 256 bits.
#[cfg(any(all(test, feature = "std"), feature = "p256-table"))]
pub(crate) const COMB_WINDOWS: usize = 256usize.div_ceil(COMB_W);
/// Width of the wNAF recoding of `u1` (the generator's scalar) in
/// verification: the comb's first window holds the odd multiples of `G` up
/// to `2^COMB_W − 1`, exactly a width-`COMB_W + 1` wNAF table.
#[cfg(feature = "p256-table")]
const G_NAF_W: u32 = COMB_W as u32 + 1;
#[cfg(not(feature = "p256-table"))]
const G_NAF_W: u32 = 5;

/// Decodes a 64-character hex string into a [`Fe`].
pub(crate) const fn fe_from_hex(hex: &str) -> Fe {
    super::uint_from_be_hex(hex)
}

/// A point in projective coordinates `(X : Y : Z)` with field elements held
/// in Montgomery form. The identity is `(0 : 1 : 0)`.
#[derive(Clone, Copy)]
pub(crate) struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl ConditionallySelectable for Point {
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

/// The P-256 curve context (the curve coefficient `b`; the field arithmetic
/// itself is the stateless [`super::p256_field`] backend).
pub(crate) struct P256 {
    /// The curve coefficient `b`.
    b: Fe,
}

impl P256 {
    pub(crate) fn new() -> Self {
        P256 { b: B }
    }

    /// The group order `n`.
    pub(crate) const fn order() -> Fe {
        ORDER
    }

    /// The scalar-field (order `n`) Montgomery context, built at compile time.
    #[inline]
    pub(crate) fn order_modulus() -> &'static MontModulus<4> {
        &ORDER_MODULUS
    }

    /// `a⁻¹ mod n` for a scalar `a < n` (`0 ↦ 0`), by the Bernstein–Yang
    /// safegcd: a fixed 590-divstep schedule, constant time in `a` (the
    /// ECDSA nonce on the signing path) and ~6× faster than the Montgomery
    /// Fermat ladder (`MontModulus::inv_prime`) it replaced.
    #[inline]
    pub(crate) fn invert_scalar(a: &Fe) -> Fe {
        ORDER_SAFEGCD.invert(a)
    }

    /// The field prime `p`.
    pub(crate) const fn field_modulus() -> Fe {
        field::P
    }

    /// The identity point `(0 : 1 : 0)`. The ladders no longer start from
    /// it (their recoding has no zero digit), so it is test-only.
    #[cfg(test)]
    pub(crate) fn identity(&self) -> Point {
        Point {
            x: Fe::ZERO,
            y: field::ONE,
            z: Fe::ZERO,
        }
    }

    /// The base point `G`. With the comb table, library code multiplies by
    /// `G` through [`Self::mul_generator`] and never needs the point itself.
    #[cfg(any(test, not(feature = "p256-table")))]
    pub(crate) fn generator(&self) -> Point {
        Point {
            x: GX,
            y: GY,
            z: field::ONE,
        }
    }

    /// Lifts an affine point `(x, y)` — plain residues `< p`, as SEC1
    /// decodes them — to projective form in Montgomery representation.
    pub(crate) fn lift_affine(&self, x: &Fe, y: &Fe) -> Point {
        Point {
            x: field::to_mont(x),
            y: field::to_mont(y),
            z: field::ONE,
        }
    }

    /// Converts a point to affine `(x, y)` as plain residues (the SEC1
    /// encoding's form), or `None` if it is the identity.
    ///
    /// The inversion is the fixed-schedule safegcd [`field::invert`] —
    /// constant time by construction, NOT the variable-time
    /// extended-Euclidean `inv_mod` — `z` is derived from the secret scalar
    /// on every ECDH / ECDSA hot path and a timing leak here would be
    /// exploitable.
    ///
    /// Whether the point is the identity is public in every caller: P-256
    /// has prime order, so `[k]P` is the identity iff `k ≡ 0 (mod n)` or `P`
    /// is — a degenerate scalar or peer the caller rejects as an error.
    pub(crate) fn to_affine(&self, point: &Point) -> Option<(Fe, Fe)> {
        if point.z.is_zero().declassify() {
            return None;
        }
        let z_inv = field::invert(&point.z);
        let x = field::from_mont(&field::mul(&point.x, &z_inv));
        let y = field::from_mont(&field::mul(&point.y, &z_inv));
        Some((x, y))
    }

    #[inline]
    fn mul(&self, a: &Fe, b: &Fe) -> Fe {
        field::mul(a, b)
    }
    #[inline]
    fn sqr(&self, a: &Fe) -> Fe {
        field::square(a)
    }
    #[inline]
    fn add(&self, a: &Fe, b: &Fe) -> Fe {
        field::add(a, b)
    }
    #[inline]
    fn sub(&self, a: &Fe, b: &Fe) -> Fe {
        field::sub(a, b)
    }

    /// Complete projective point addition for `a = -3`
    /// (Renes–Costello–Batina, Algorithm 4). Correct for all inputs, including
    /// equal points and the identity.
    pub(crate) fn point_add(&self, p: &Point, q: &Point) -> Point {
        let b = self.b;
        let mut t0 = self.mul(&p.x, &q.x);
        let mut t1 = self.mul(&p.y, &q.y);
        let mut t2 = self.mul(&p.z, &q.z);
        let mut t3 = self.add(&p.x, &p.y);
        let mut t4 = self.add(&q.x, &q.y);
        t3 = self.mul(&t3, &t4);
        t4 = self.add(&t0, &t1);
        t3 = self.sub(&t3, &t4);
        t4 = self.add(&p.y, &p.z);
        let mut x3 = self.add(&q.y, &q.z);
        t4 = self.mul(&t4, &x3);
        x3 = self.add(&t1, &t2);
        t4 = self.sub(&t4, &x3);
        x3 = self.add(&p.x, &p.z);
        let mut y3 = self.add(&q.x, &q.z);
        x3 = self.mul(&x3, &y3);
        y3 = self.add(&t0, &t2);
        y3 = self.sub(&x3, &y3);
        let mut z3 = self.mul(&b, &t2);
        x3 = self.sub(&y3, &z3);
        z3 = self.add(&x3, &x3);
        x3 = self.add(&x3, &z3);
        z3 = self.sub(&t1, &x3);
        x3 = self.add(&t1, &x3);
        y3 = self.mul(&b, &y3);
        t1 = self.add(&t2, &t2);
        t2 = self.add(&t1, &t2);
        y3 = self.sub(&y3, &t2);
        y3 = self.sub(&y3, &t0);
        t1 = self.add(&y3, &y3);
        y3 = self.add(&t1, &y3);
        t1 = self.add(&t0, &t0);
        t0 = self.add(&t1, &t0);
        t0 = self.sub(&t0, &t2);
        t1 = self.mul(&t4, &y3);
        t2 = self.mul(&t0, &y3);
        y3 = self.mul(&x3, &z3);
        y3 = self.add(&y3, &t2);
        x3 = self.mul(&t3, &x3);
        x3 = self.sub(&x3, &t1);
        z3 = self.mul(&t4, &z3);
        t1 = self.mul(&t3, &t0);
        z3 = self.add(&z3, &t1);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Complete projective point doubling for `a = -3`
    /// (Renes–Costello–Batina, Algorithm 6). Exception-free for all inputs,
    /// including the identity. Cheaper than `point_add(p, p)` (8M + 3S vs
    /// 12M, and the native field's dedicated squaring makes S < M).
    fn double(&self, p: &Point) -> Point {
        let b = self.b;
        let mut t0 = self.sqr(&p.x);
        let t1 = self.sqr(&p.y);
        let mut t2 = self.sqr(&p.z);
        let mut t3 = self.mul(&p.x, &p.y);
        t3 = self.add(&t3, &t3);
        let mut z3 = self.mul(&p.x, &p.z);
        z3 = self.add(&z3, &z3);
        let mut y3 = self.mul(&b, &t2);
        y3 = self.sub(&y3, &z3);
        let mut x3 = self.add(&y3, &y3);
        y3 = self.add(&x3, &y3);
        x3 = self.sub(&t1, &y3);
        y3 = self.add(&t1, &y3);
        y3 = self.mul(&x3, &y3);
        x3 = self.mul(&x3, &t3);
        t3 = self.add(&t2, &t2);
        t2 = self.add(&t2, &t3);
        z3 = self.mul(&b, &z3);
        z3 = self.sub(&z3, &t2);
        z3 = self.sub(&z3, &t0);
        t3 = self.add(&z3, &z3);
        z3 = self.add(&z3, &t3);
        t3 = self.add(&t0, &t0);
        t0 = self.add(&t3, &t0);
        t0 = self.sub(&t0, &t2);
        t0 = self.mul(&t0, &z3);
        y3 = self.add(&y3, &t0);
        t0 = self.mul(&p.y, &p.z);
        t0 = self.add(&t0, &t0);
        z3 = self.mul(&t0, &z3);
        x3 = self.sub(&x3, &z3);
        z3 = self.mul(&t0, &t1);
        z3 = self.add(&z3, &z3);
        z3 = self.add(&z3, &z3);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Complete mixed point addition `p + (x2, y2)` for `a = -3`
    /// (Renes–Costello–Batina, Algorithm 5): `q` is an affine point, never
    /// the identity (`Z2 = 1`), `p` is any projective point including the
    /// identity, and the result is correct for every such pair — equal and
    /// opposite points included. One multiplication and six additions
    /// cheaper than [`Self::point_add`] (11M + 2m_b vs 12M + 2m_b).
    fn add_mixed(&self, p: &Point, x2: &Fe, y2: &Fe) -> Point {
        let b = self.b;
        let mut t0 = self.mul(&p.x, x2);
        let mut t1 = self.mul(&p.y, y2);
        let mut t3 = self.add(x2, y2);
        let mut t4 = self.add(&p.x, &p.y);
        t3 = self.mul(&t3, &t4);
        t4 = self.add(&t0, &t1);
        t3 = self.sub(&t3, &t4);
        t4 = self.mul(y2, &p.z);
        t4 = self.add(&t4, &p.y);
        let mut y3 = self.mul(x2, &p.z);
        y3 = self.add(&y3, &p.x);
        let mut z3 = self.mul(&b, &p.z);
        let mut x3 = self.sub(&y3, &z3);
        z3 = self.add(&x3, &x3);
        x3 = self.add(&x3, &z3);
        z3 = self.sub(&t1, &x3);
        x3 = self.add(&t1, &x3);
        y3 = self.mul(&b, &y3);
        t1 = self.add(&p.z, &p.z);
        let mut t2 = self.add(&t1, &p.z);
        y3 = self.sub(&y3, &t2);
        y3 = self.sub(&y3, &t0);
        t1 = self.add(&y3, &y3);
        y3 = self.add(&t1, &y3);
        t1 = self.add(&t0, &t0);
        t0 = self.add(&t1, &t0);
        t0 = self.sub(&t0, &t2);
        t1 = self.mul(&t4, &y3);
        t2 = self.mul(&t0, &y3);
        y3 = self.mul(&x3, &z3);
        y3 = self.add(&y3, &t2);
        x3 = self.mul(&t3, &x3);
        x3 = self.sub(&x3, &t1);
        z3 = self.mul(&t4, &z3);
        t1 = self.mul(&t3, &t0);
        z3 = self.add(&z3, &t1);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Constant-time scalar multiplication `scalar * point` by a fixed
    /// signed base-16 window over the odd recoding of [`OddScalar::new`]:
    /// the accumulator starts at `[16⁶⁴]P = P` (the recoding's implicit top
    /// digit), then each of the 64 windows, most significant first, is 4
    /// doublings and one *unconditional* addition of `[dᵢ]P`, `dᵢ ∈ {±1, ±3,
    /// …, ±15}`. The operand is fetched by a masked scan of the 8 odd
    /// multiples (one opaque mask per entry, no secret-indexed memory
    /// access) and negated through a mask, so the schedule depends only on
    /// the (public) scalar width. No digit is zero, so no addition is ever a
    /// no-op.
    ///
    /// The odd multiples are normalised to affine with one inversion (the
    /// base point is public in every caller — a peer's public key, the
    /// generator — so the table is too), and the first 63 windows run in
    /// Jacobian coordinates: `dbl-2001-b` doublings (3M + 5S) and
    /// `madd-2007-bl` mixed additions (7M + 4S), against 8M + 3S and
    /// 12M + 2m_b for the complete projective formulas. Those Jacobian
    /// formulas are incomplete, but the odd recoding keeps every one of
    /// these steps away from their exceptional inputs (see
    /// [`Self::jac_madd`]); the last window, the only one that can
    /// meet `acc = ±[d₀]P` (for `k ≡ 0, ±2 mod n`), runs on the complete
    /// mixed addition [`Self::add_mixed`] after a projective conversion.
    ///
    /// Only the scalar is secret; a base point that is the identity (never
    /// produced by SEC1 decoding) maps to the identity.
    pub(crate) fn scalar_mul(&self, scalar: &Fe, point: &Point) -> Point {
        if point.z.is_zero().declassify() {
            return *point;
        }
        let table = self.odd_multiples_affine(point);
        let mut k = OddScalar::new(scalar);
        let mut acc = Jacobian {
            x: Fe::from_limbs([table[0][0], table[0][1], table[0][2], table[0][3]]),
            y: Fe::from_limbs([table[0][4], table[0][5], table[0][6], table[0][7]]),
            z: field::ONE,
        };
        let mut i = 64;
        while i > 1 {
            i -= 1;
            acc = self.jac_double(&acc);
            acc = self.jac_double(&acc);
            acc = self.jac_double(&acc);
            acc = self.jac_double(&acc);
            let (x, mut y) = gather_affine(&table, k.digit(i));
            acc = self.jac_madd(&acc, &x, &y);
            y.zeroize();
        }
        acc = self.jac_double(&acc);
        acc = self.jac_double(&acc);
        acc = self.jac_double(&acc);
        acc = self.jac_double(&acc);
        let mut out = self.finish_ladder(&mut acc, &table, k.digit(0));
        // The ladder's accumulators are as secret as the scalar.
        out.y = negate_masked(&out.y, k.negate_result);
        k.zeroize();
        out
    }

    /// The last window of both constant-time ladders: `acc` (Jacobian) is
    /// converted to projective `(X·Z : Y : Z³)` and window 0's digit is
    /// added with the complete mixed formula, which absorbs the only
    /// exceptional cases the ladders can reach (`k' = n − 2`: `acc = [d₀]P`,
    /// a doubling; `k' = n`: `acc = −[d₀]P`, the identity). Wipes `acc`.
    #[inline]
    fn finish_ladder(&self, acc: &mut Jacobian, table: &[[u64; 8]], digit: (u64, u64)) -> Point {
        let z2 = self.sqr(&acc.z);
        let proj = Point {
            x: self.mul(&acc.x, &acc.z),
            y: acc.y,
            z: self.mul(&z2, &acc.z),
        };
        acc.zeroize();
        let (x, mut y) = gather_affine(table, digit);
        let out = self.add_mixed(&proj, &x, &y);
        y.zeroize();
        out
    }

    /// Constant-time fixed-base multiplication `scalar * G` via the
    /// precomputed comb table [`P256_GEN_TABLE`]: with the odd recoding of
    /// [`OddScalar::new`] in base `B = 2^COMB_W`, `[k]G = [B^W]G +
    /// Σᵢ [dᵢ·Bⁱ]G` over `W = COMB_WINDOWS` odd digits `|dᵢ| < B`, so there
    /// are **no doublings** — just `W` unconditional mixed additions from
    /// the constant `[B^W]G` ([`P256_GEN_TOP`]), each operand fetched by a
    /// masked scan of that window's stored affine points (one opaque mask
    /// per entry, the 8 coordinate limbs only, no secret-indexed memory
    /// access — the same gather discipline as [`Self::scalar_mul`]) and
    /// negated through a mask. The schedule depends only on the (public)
    /// scalar width.
    ///
    /// The windows are added most significant first, which keeps every
    /// window but the last away from the exceptional inputs of the
    /// Jacobian `madd-2007-bl` (7M + 4S, see [`Self::jac_madd`]), used
    /// instead of the complete projective mixed addition (11M + 2m_b);
    /// window 0 goes through the complete formula ([`Self::finish_ladder`]).
    #[cfg(feature = "p256-table")]
    pub(crate) fn mul_generator(&self, scalar: &Fe) -> Point {
        let mut k = OddScalar::new(scalar);
        let mut acc = Jacobian {
            x: Fe::from_limbs([
                P256_GEN_TOP[0],
                P256_GEN_TOP[1],
                P256_GEN_TOP[2],
                P256_GEN_TOP[3],
            ]),
            y: Fe::from_limbs([
                P256_GEN_TOP[4],
                P256_GEN_TOP[5],
                P256_GEN_TOP[6],
                P256_GEN_TOP[7],
            ]),
            z: field::ONE,
        };
        let mut i = COMB_WINDOWS;
        while i > 1 {
            i -= 1;
            let (x, mut y) = gather_affine(&P256_GEN_TABLE[i], k.digit_w(COMB_W, i));
            acc = self.jac_madd(&acc, &x, &y);
            y.zeroize();
        }
        let mut out = self.finish_ladder(&mut acc, &P256_GEN_TABLE[0], k.digit_w(COMB_W, 0));
        out.y = negate_masked(&out.y, k.negate_result);
        k.zeroize();
        out
    }

    /// Constant-time fixed-base multiplication `scalar * G` without the comb
    /// table (feature `p256-table` off): the generic windowed ladder
    /// [`Self::scalar_mul`] over `G`. Same result and the same secret-scalar
    /// discipline, at the cost of ~256 doublings the table would avoid.
    #[cfg(not(feature = "p256-table"))]
    pub(crate) fn mul_generator(&self, scalar: &Fe) -> Point {
        self.scalar_mul(scalar, &self.generator())
    }

    /// **VARIABLE-TIME** double-scalar multiplication `u1·G + u2·Q`.
    ///
    /// # Warning — never call with secret scalars
    /// The execution time, branch pattern and memory-access pattern all
    /// depend on `u1`, `u2` and `q`. This is only sound when every input is
    /// public — which is exactly the ECDSA *verification* setting (signature,
    /// message digest and public key are all public). Signing, key
    /// generation and ECDH must keep using the constant-time
    /// [`Self::mul_generator`] / [`Self::scalar_mul`] paths.
    ///
    /// Strategy: Straus–Shamir interleaving of two wNAF ladders (one shared
    /// run of doublings; width 5 for `Q`, ~43 additions, and width
    /// [`G_NAF_W`] for `G`, ~37 additions with the comb table) over Jacobian
    /// coordinates — `dbl-2001-b` doublings (3M + 5S, `a = −3`) and
    /// `madd-2007-bl` mixed additions (7M + 4S) with the exceptional cases
    /// handled explicitly. Both operand tables are affine: the odd
    /// multiples of `G` come straight from the comb table's first window
    /// (or are computed without it), and the odd multiples of `Q` are
    /// batch-normalised with one inversion (Montgomery's trick). See
    /// [`Self::verify_x_vartime`] for the inversion-free ECDSA check, which
    /// is what the native ECDSA verifier uses; this projective form serves
    /// the runtime-curve router (`ec::boxed`) and public-key recovery.
    #[cfg(any(test, feature = "alloc"))]
    pub(crate) fn mul_double_vartime(&self, u1: &Fe, u2: &Fe, q: &Point) -> Point {
        let acc = self.straus_vartime(u1, u2, q);
        // Jacobian (X : Y : Z) → projective (X·Z : Y : Z³); the identity
        // (Z = 0) maps to (0 : Y : 0), a valid identity representative.
        let z2 = self.sqr(&acc.z);
        Point {
            x: self.mul(&acc.x, &acc.z),
            y: acc.y,
            z: self.mul(&z2, &acc.z),
        }
    }

    /// **VARIABLE-TIME** ECDSA verification core: whether the affine
    /// x-coordinate of `u1·G + u2·Q`, reduced mod `n`, equals `r` (with
    /// `r < n`), without the final inversion: for the Jacobian result
    /// `(X : Y : Z)`, `x = X/Z²`, so `x ≡ r (mod n)` iff `X = r·Z²` or
    /// `X = (r + n)·Z²` (the only candidates below `p`). The identity never
    /// verifies. Public inputs only — see [`Self::mul_double_vartime`].
    pub(crate) fn verify_x_vartime(&self, u1: &Fe, u2: &Fe, q: &Point, r: &Fe) -> bool {
        let acc = self.straus_vartime(u1, u2, q);
        if bool::from(acc.z.is_zero()) {
            return false;
        }
        let zz = self.sqr(&acc.z);
        if bool::from(self.mul(&field::to_mont(r), &zz).ct_eq(&acc.x)) {
            return true;
        }
        // r + n is a candidate only when it neither overflows 2²⁵⁶ (r is
        // range-checked below n, but n > 2²⁵⁵, so r + n can carry — the
        // Wycheproof "r = 2²⁵⁶ − n + 5, x = 5" vectors) nor reaches p.
        let (r_n, carry) = r.adc(&ORDER, 0);
        carry == 0
            && bool::from(r_n.ct_lt(&field::P))
            && bool::from(self.mul(&field::to_mont(&r_n), &zz).ct_eq(&acc.x))
    }

    /// The Straus–Shamir ladder behind [`Self::mul_double_vartime`], in
    /// Jacobian coordinates. **Variable-time.**
    fn straus_vartime(&self, u1: &Fe, u2: &Fe, q: &Point) -> Jacobian {
        #[cfg(feature = "p256-table")]
        let g_odd: &[[u64; 8]] = &P256_GEN_TABLE[0];
        #[cfg(not(feature = "p256-table"))]
        let g_odd: &[[u64; 8]] = &self.odd_multiples_affine(&self.generator());

        // u2·Q vanishes for the identity (and its odd multiples could not
        // be normalised); `q` is public, so the branch is sound.
        let q_identity = bool::from(q.z.is_zero());
        let q_odd = if q_identity {
            [[0u64; 8]; 8]
        } else {
            self.odd_multiples_affine(q)
        };
        let naf1 = wnaf(u1, G_NAF_W);
        let naf2 = if q_identity { [0i8; 257] } else { wnaf(u2, 5) };

        let mut acc = Jacobian::IDENTITY;
        let Some(top) = naf1
            .iter()
            .zip(naf2.iter())
            .rposition(|(&a, &b)| a != 0 || b != 0)
        else {
            return acc;
        };
        for i in (0..=top).rev() {
            acc = self.jac_double(&acc);
            if naf1[i] != 0 {
                acc = self.jac_add_naf_digit(&acc, naf1[i], g_odd);
            }
            if naf2[i] != 0 {
                acc = self.jac_add_naf_digit(&acc, naf2[i], &q_odd);
            }
        }
        acc
    }

    /// Adds the nonzero wNAF digit `d` (odd, `|d| < 2·odd.len()`) times the point
    /// whose affine odd multiples are `odd`. **Variable-time.**
    #[inline]
    fn jac_add_naf_digit(&self, acc: &Jacobian, d: i8, odd: &[[u64; 8]]) -> Jacobian {
        let entry = &odd[(d.unsigned_abs() as usize - 1) / 2];
        let x = Fe::from_limbs([entry[0], entry[1], entry[2], entry[3]]);
        let mut y = Fe::from_limbs([entry[4], entry[5], entry[6], entry[7]]);
        if d < 0 {
            y = field::negate(&y);
        }
        self.jac_add_affine(acc, &x, &y)
    }

    /// The odd multiples `[1]P, [3]P, …, [15]P` of a non-identity `P` as
    /// affine points (Montgomery form, `x‖y` limbs), built with the complete
    /// projective formulas and normalised together with a single inversion
    /// (Montgomery's trick: `3(n − 1)` multiplications replace `n − 1`
    /// inversions). Branch-free (the inversion is the constant-time
    /// safegcd), though every caller passes a public point: the
    /// verification ladder and the ECDH ladder [`Self::scalar_mul`].
    fn odd_multiples_affine(&self, point: &Point) -> [[u64; 8]; 8] {
        let two_p = self.double(point);
        let mut table = [*point; 8];
        for i in 1..8 {
            table[i] = self.point_add(&table[i - 1], &two_p);
        }
        // prefix[i] = z₀·z₁·…·zᵢ; one inversion of prefix[7], then peel.
        let mut prefix = [table[0].z; 8];
        for i in 1..8 {
            prefix[i] = self.mul(&prefix[i - 1], &table[i].z);
        }
        let mut inv = field::invert(&prefix[7]);
        let mut out = [[0u64; 8]; 8];
        for i in (0..8).rev() {
            let z_inv = if i > 0 {
                self.mul(&inv, &prefix[i - 1])
            } else {
                inv
            };
            inv = self.mul(&inv, &table[i].z);
            let x = self.mul(&table[i].x, &z_inv);
            let y = self.mul(&table[i].y, &z_inv);
            out[i][..4].copy_from_slice(x.as_limbs());
            out[i][4..].copy_from_slice(y.as_limbs());
        }
        out
    }

    /// Jacobian doubling `dbl-2001-b` for `a = −3` (3M + 5S). The identity
    /// (`Z = 0`) doubles to itself (`Z3 = 2·Y·Z = 0`), and with no point of
    /// order two on P-256 there is no other exceptional input, so the
    /// formula is complete. Branch-free: shared by the verification ladder
    /// and the constant-time [`Self::scalar_mul`].
    fn jac_double(&self, p: &Jacobian) -> Jacobian {
        let delta = self.sqr(&p.z);
        let gamma = self.sqr(&p.y);
        let beta = self.mul(&p.x, &gamma);
        // alpha = 3·(X − delta)·(X + delta)
        let t = self.mul(&self.sub(&p.x, &delta), &self.add(&p.x, &delta));
        let alpha = self.add(&self.add(&t, &t), &t);
        // X3 = alpha² − 8·beta
        let beta2 = self.add(&beta, &beta);
        let beta4 = self.add(&beta2, &beta2);
        let beta8 = self.add(&beta4, &beta4);
        let x3 = self.sub(&self.sqr(&alpha), &beta8);
        // Z3 = (Y + Z)² − gamma − delta
        let yz = self.add(&p.y, &p.z);
        let z3 = self.sub(&self.sub(&self.sqr(&yz), &gamma), &delta);
        // Y3 = alpha·(4·beta − X3) − 8·gamma²
        let gamma2 = self.sqr(&gamma);
        let g2 = self.add(&gamma2, &gamma2);
        let g4 = self.add(&g2, &g2);
        let g8 = self.add(&g4, &g4);
        let y3 = self.sub(&self.mul(&alpha, &self.sub(&beta4, &x3)), &g8);
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Mixed Jacobian + affine addition `madd-2007-bl` (7M + 4S) with the
    /// exceptional cases handled explicitly: an identity accumulator
    /// returns the affine point; `H = 0` (same x) is a doubling when the
    /// y's agree and the identity when they are opposite. **Variable-time**
    /// callers only (the branches are on the operands).
    fn jac_add_affine(&self, p: &Jacobian, x2: &Fe, y2: &Fe) -> Jacobian {
        if bool::from(p.z.is_zero()) {
            return Jacobian {
                x: *x2,
                y: *y2,
                z: field::ONE,
            };
        }
        let z1z1 = self.sqr(&p.z);
        let u2 = self.mul(x2, &z1z1);
        let s2 = self.mul(y2, &self.mul(&p.z, &z1z1));
        let h = self.sub(&u2, &p.x);
        let r = self.sub(&s2, &p.y);
        if bool::from(h.is_zero()) {
            if bool::from(r.is_zero()) {
                return self.jac_double(p);
            }
            return Jacobian::IDENTITY;
        }
        self.madd_tail(p, &z1z1, &h, &r)
    }

    /// Branch-free mixed Jacobian + affine addition `madd-2007-bl`
    /// (7M + 4S): `p + (x2, y2)`, constant time in all operands.
    ///
    /// # Preconditions
    /// `p` is not the identity and `p ≠ ±(x2, y2)`; otherwise the result is
    /// wrong (`p = −(x2, y2)` happens to give `Z3 = 0`, the identity, but
    /// `p = (x2, y2)` gives `(0 : 0 : 0)`). The constant-time ladders meet
    /// these by construction. With the odd recoding `k' ∈ [1, n]` of
    /// [`OddScalar`] in base `B = 2^w` (plain digits `eᵢ`, signed odd digits
    /// `|dᵢ| < B`), the windows above `i` sum to `Vᵢ₊₁ = Bⁱ⁺¹·qᵢ₊₁` with
    /// `qᵢ₊₁ = ⌊k'/Bⁱ⁺¹⌋ + [eᵢ₊₁ even]`, so `1 ≤ qᵢ₊₁` and
    /// `B·qᵢ₊₁ ≤ k'/Bⁱ + B`.
    ///
    /// - Comb ([`Self::mul_generator`], no doublings): window `i` adds
    ///   `[dᵢ·Bⁱ]G` to `[Bⁱ⁺¹·qᵢ₊₁]G`.
    /// - Horner ladder ([`Self::scalar_mul`], `w = 4`): window `i` adds
    ///   `[dᵢ]P` to `[B·qᵢ₊₁]P`.
    ///
    /// Both collide iff `B·qᵢ₊₁ ∓ dᵢ ≡ 0 (mod n)` (for the comb after
    /// cancelling the invertible `Bⁱ`). For `i ≥ 1`, `B·qᵢ₊₁ ∓ dᵢ` lies in
    /// `[1, n/B + 2B)` ⊂ `[1, n)`, so it never does. Likewise the
    /// accumulator `[qᵢ]` (times `Bⁱ`) is never the identity for `i ≥ 1`
    /// (`1 ≤ qᵢ < n`), and with P-256's prime order the Jacobian doublings in
    /// between are exception-free too. Only window 0 can collide
    /// (`k' = n − 2`: a doubling; `k' = n`, i.e. `k ≡ 0`: the identity), so
    /// it runs on the complete formula ([`Self::finish_ladder`]).
    #[inline]
    fn jac_madd(&self, p: &Jacobian, x2: &Fe, y2: &Fe) -> Jacobian {
        let z1z1 = self.sqr(&p.z);
        let u2 = self.mul(x2, &z1z1);
        let s2 = self.mul(y2, &self.mul(&p.z, &z1z1));
        let h = self.sub(&u2, &p.x);
        let r = self.sub(&s2, &p.y);
        self.madd_tail(p, &z1z1, &h, &r)
    }

    /// The common tail of `madd-2007-bl` once `H = U2 − X1` and
    /// `r = S2 − Y1` are known (branch-free).
    #[inline(always)]
    fn madd_tail(&self, p: &Jacobian, z1z1: &Fe, h: &Fe, r: &Fe) -> Jacobian {
        let r = self.add(r, r);
        let hh = self.sqr(h);
        let i2 = self.add(&hh, &hh);
        let i = self.add(&i2, &i2);
        let j = self.mul(h, &i);
        let v = self.mul(&p.x, &i);
        // X3 = r² − J − 2V
        let x3 = self.sub(&self.sub(&self.sqr(&r), &j), &self.add(&v, &v));
        // Y3 = r·(V − X3) − 2·Y1·J
        let y1j = self.mul(&p.y, &j);
        let y3 = self.sub(&self.mul(&r, &self.sub(&v, &x3)), &self.add(&y1j, &y1j));
        // Z3 = (Z1 + H)² − Z1Z1 − HH
        let z3 = self.sub(&self.sub(&self.sqr(&self.add(&p.z, h)), z1z1), &hh);
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Tests whether affine `(x, y)` (plain residues `< p`) satisfies the
    /// curve equation `y^2 = x^3 - 3x + b (mod p)`.
    pub(crate) fn is_on_curve(&self, x: &Fe, y: &Fe) -> bool {
        let x = field::to_mont(x);
        let y = field::to_mont(y);
        let lhs = field::square(&y);
        let x3 = field::mul(&field::square(&x), &x);
        let three_x = field::add(&field::add(&x, &x), &x);
        let rhs = field::add(&field::sub(&x3, &three_x), &self.b);
        bool::from(lhs.ct_eq(&rhs))
    }
}

/// A point in Jacobian coordinates `(X : Y : Z)` — affine `(X/Z², Y/Z³)`,
/// identity `Z = 0` — used only by the variable-time verification ladder,
/// where its cheaper doubling (3M + 5S) and mixed addition (7M + 4S) beat
/// the complete projective formulas and the exceptional cases can simply
/// be branched on.
#[derive(Clone, Copy)]
struct Jacobian {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl Zeroize for Jacobian {
    #[inline]
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}

/// A window's operand for the constant-time ladders: for the digit
/// `(index, neg)` of [`OddScalar::digit_w`], the affine entry `index` of the
/// odd-multiple table `window` fetched by a masked scan (one opaque mask per
/// entry over all 8 limbs, no secret-indexed memory access; the table length
/// is public), with `y` negated through a mask when the digit is negative.
#[inline(always)]
fn gather_affine(window: &[[u64; 8]], (index, neg): (u64, u64)) -> (Fe, Fe) {
    let mut sel = [0u64; 8];
    for (j, entry) in window.iter().enumerate() {
        let mask = mask_eq(j as u64, index);
        for (s, e) in sel.iter_mut().zip(entry) {
            *s |= e & mask;
        }
    }
    let x = Fe::from_limbs([sel[0], sel[1], sel[2], sel[3]]);
    let y = negate_masked(&Fe::from_limbs([sel[4], sel[5], sel[6], sel[7]]), neg);
    sel.zeroize();
    (x, y)
}

impl Jacobian {
    /// The identity `(1 : 1 : 0)`.
    const IDENTITY: Jacobian = Jacobian {
        x: field::ONE,
        y: field::ONE,
        z: Fe::ZERO,
    };
}

/// A scalar recoded for the constant-time ladders.
///
/// `k' = k mod n` made odd: an even `k` is replaced by `n − k` (odd, since
/// `n` is) and the result negated at the end (`[k]P = −[n − k]P`), through
/// a mask. An odd `k' < 2²⁵⁶` has the regular signed representation
/// `k' = 16⁶⁴ + Σᵢ₌₀⁶³ dᵢ·16ⁱ` with every `dᵢ ∈ {±1, ±3, …, ±15}` (no zero
/// digit): with `eᵢ` the plain base-16 digits, `dᵢ = (eᵢ + 1 − (eᵢ mod 2))
/// − 16·(1 − (eᵢ₊₁ mod 2))`, i.e. each even digit borrows one from the
/// window above and lends 16 to the one below (`e₆₄ = 0`, so `d₆₃` is
/// always negative and the implicit top digit is `+1`). Every digit is a
/// local function of two adjacent windows, so [`Self::digit`] is a few
/// masked operations with no carry chain.
///
/// Reducing mod `n` first gives the documented policy for scalars
/// `>= n` (and `>= 2²⁵⁵`): `[k]P = [k mod n]P`, and the reduction is the
/// crate's constant-time single masked subtraction ([`super::reduce_256`]).
struct OddScalar {
    /// The odd representative `k'`.
    k: Fe,
    /// All-ones iff the ladder's result must be negated (`k mod n` even).
    negate_result: u64,
}

impl OddScalar {
    fn new(scalar: &Fe) -> Self {
        let k = super::reduce_256(scalar, &ORDER);
        let even = !k.is_odd();
        let n_minus_k = ORDER.wrapping_sub(&k);
        OddScalar {
            k: Fe::conditional_select(&n_minus_k, &k, even),
            negate_result: mask_from_bit(u64::from(even.unwrap_u8())),
        }
    }

    /// Digit `i` of the base-16 recoding (window `i` of 64); see
    /// [`Self::digit_w`].
    #[inline]
    fn digit(&self, i: usize) -> (u64, u64) {
        self.digit_w(4, i)
    }

    /// Digit `i` of the recoding in base `2^w` (`2 <= w <= 8`, window `i`
    /// of `⌈256/w⌉`) as `(table index (|dᵢ| − 1) / 2, mask that is
    /// all-ones iff dᵢ < 0)`: with `eᵢ` the plain base-`2^w` digits of `k'`,
    /// `dᵢ = (eᵢ + 1 − (eᵢ mod 2)) − 2^w·(1 − (eᵢ₊₁ mod 2))`, and
    /// `k' = 2^(w·⌈256/w⌉) + Σ dᵢ·2^(w·i)` (the base-16 description on
    /// [`OddScalar`] carries over unchanged). Constant time in the scalar
    /// (`w` and `i` are public).
    #[inline]
    fn digit_w(&self, w: usize, i: usize) -> (u64, u64) {
        let e = self.bits(w * i, w);
        // Lowest bit of window i + 1 (zero above the top window).
        let next_odd = self.bits(w * (i + 1), 1);
        // Odd value in [1, 2^w − 1]; negative iff the window above is even.
        let v = e + 1 - (e & 1);
        let neg = mask_from_bit(next_odd ^ 1);
        let mag = v ^ ((v ^ ((1u64 << w) - v)) & neg);
        (mag >> 1, neg)
    }

    /// The `w` bits of `k'` starting at bit `pos` (zero above bit 255).
    /// Branches only on the public `pos` and `w`.
    #[inline(always)]
    fn bits(&self, pos: usize, w: usize) -> u64 {
        if pos >= 256 {
            return 0;
        }
        let limbs = self.k.as_limbs();
        let (idx, sh) = (pos / 64, pos % 64);
        let mut x = limbs[idx] >> sh;
        if sh + w > 64 && idx + 1 < 4 {
            x |= limbs[idx + 1] << (64 - sh);
        }
        x & ((1u64 << w) - 1)
    }
}

impl Zeroize for OddScalar {
    fn zeroize(&mut self) {
        self.k.zeroize();
        self.negate_result.zeroize();
    }
}

/// Returns an all-ones/all-zeros `u64` mask from a 0/1 bit, behind an
/// optimisation barrier so the masked selects it feeds (digit signs, the
/// final negation) cannot be lowered to a branch or conditional move on
/// the secret bit.
#[inline]
fn mask_from_bit(bit: u64) -> u64 {
    field::mask_from_bit(bit)
}

/// All-ones iff `a == b`, by arithmetic only.
#[inline]
fn mask_eq(a: u64, b: u64) -> u64 {
    let x = a ^ b;
    mask_from_bit(((x | x.wrapping_neg()) >> 63) ^ 1)
}

/// `−y` when `mask` is all-ones, `y` when it is zero (a masked select over
/// the limbs; the negation itself is always computed).
#[inline]
fn negate_masked(y: &Fe, mask: u64) -> Fe {
    let n = field::negate(y);
    let y = y.as_limbs();
    let n = n.as_limbs();
    Fe::from_limbs([
        y[0] ^ ((y[0] ^ n[0]) & mask),
        y[1] ^ ((y[1] ^ n[1]) & mask),
        y[2] ^ ((y[2] ^ n[2]) & mask),
        y[3] ^ ((y[3] ^ n[3]) & mask),
    ])
}

/// Width-`w` wNAF recoding of a 256-bit scalar (`2 <= w <= 7`): digits
/// odd with `|d| < 2^(w−1)`, or zero, with any two nonzero digits at least
/// `w` positions apart. **Variable time** in the scalar — public scalars
/// only.
fn wnaf(k: &Fe, w: u32) -> [i8; 257] {
    let mut naf = [0i8; 257];
    let mut k = *k;
    let mut i = 0;
    let full = 1i16 << w;
    while !bool::from(k.is_zero()) {
        if bool::from(k.is_odd()) {
            let low = (k.as_limbs()[0] & (full as u64 - 1)) as i16;
            let d = if low > full / 2 { low - full } else { low };
            naf[i] = d as i8;
            if d > 0 {
                k = k.wrapping_sub(&Fe::from_u64(d as u64));
            } else {
                // k < 2^256 - 63 always holds here (k only shrinks from an
                // initial value < 2^256 - 2^224), so this cannot wrap.
                k = k.wrapping_add(&Fe::from_u64((-d) as u64));
            }
        }
        k = k.shr1();
        i += 1;
    }
    naf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_on_curve() {
        let curve = P256::new();
        let (gx, gy) = curve.to_affine(&curve.generator()).unwrap();
        assert!(curve.is_on_curve(&gx, &gy));
    }

    #[test]
    fn double_and_triple_generator() {
        let curve = P256::new();
        let g = curve.generator();

        let two_g = curve.to_affine(&curve.double(&g)).unwrap();
        assert_eq!(
            two_g.0,
            fe_from_hex("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978")
        );
        assert_eq!(
            two_g.1,
            fe_from_hex("07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1")
        );

        // 3G via scalar_mul.
        let three_g = curve
            .to_affine(&curve.mul_generator(&Fe::from_u64(3)))
            .unwrap();
        assert_eq!(
            three_g.0,
            fe_from_hex("5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c")
        );
        assert!(curve.is_on_curve(&three_g.0, &three_g.1));
    }

    #[test]
    fn scalar_mul_matches_repeated_addition() {
        let curve = P256::new();
        let g = curve.generator();
        // 5*G by scalar mul vs G+G+G+G+G.
        let mut acc = g;
        for _ in 0..4 {
            acc = curve.point_add(&acc, &g);
        }
        let expected = curve.to_affine(&acc).unwrap();
        let got = curve
            .to_affine(&curve.mul_generator(&Fe::from_u64(5)))
            .unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn order_times_generator_is_identity() {
        let curve = P256::new();
        let n = P256::order();
        let result = curve.mul_generator(&n);
        assert!(
            curve.to_affine(&result).is_none(),
            "n*G must be the identity"
        );
    }

    /// The hard-coded generator limbs are the FIPS 186 `G`.
    #[test]
    fn generator_matches_hex() {
        let curve = P256::new();
        let g = curve.generator();
        let (gx, gy) = curve.to_affine(&g).unwrap();
        assert_eq!(gx, fe_from_hex(GX_HEX));
        assert_eq!(gy, fe_from_hex(GY_HEX));
        assert!(curve.is_on_curve(&gx, &gy));
    }

    /// Re-derives every entry of the embedded fixed-base table from the
    /// group law and cross-checks the constants, so `P256_GEN_TABLE` is
    /// verified on every test run rather than trusted. The check is
    /// inversion-free: the stored affine `(x, y)` matches the computed
    /// projective `(X : Y : Z)` iff `x·Z == X` and `y·Z == Y`.
    #[test]
    #[cfg(feature = "p256-table")]
    fn gen_table_matches_computed() {
        let curve = P256::new();
        let check = |entry: &[u64; 8], acc: &Point| {
            assert!(
                !bool::from(acc.z.is_zero()),
                "table entry must not be the identity"
            );
            let ex = Fe::from_limbs([entry[0], entry[1], entry[2], entry[3]]);
            let ey = Fe::from_limbs([entry[4], entry[5], entry[6], entry[7]]);
            assert_eq!(curve.mul(&ex, &acc.z), acc.x, "x mismatch");
            assert_eq!(curve.mul(&ey, &acc.z), acc.y, "y mismatch");
        };
        // base = [B^i]G; entry j of window i is [(2j + 1)·B^i]G.
        let mut base = curve.generator();
        for window in P256_GEN_TABLE.iter() {
            let two_base = curve.double(&base);
            let mut acc = base;
            for (j, entry) in window.iter().enumerate() {
                if j > 0 {
                    acc = curve.point_add(&acc, &two_base);
                }
                check(entry, &acc);
            }
            for _ in 0..COMB_W {
                base = curve.double(&base);
            }
        }
        // After every window, base = [B^W]G, the comb's starting point.
        check(&P256_GEN_TOP, &base);
    }

    /// Differential test: the fixed-base comb agrees with the generic
    /// windowed ladder for edge scalars (0, 1, 2, n−1, n, n+1, 2²⁵⁵-ish,
    /// all-ones) and a batch of random ones.
    #[test]
    fn mul_generator_matches_generic_scalar_mul() {
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;
        let curve = P256::new();
        let g = curve.generator();
        let n = P256::order();

        let check = |k: &Fe| {
            assert_eq!(
                curve.to_affine(&curve.mul_generator(k)),
                curve.to_affine(&curve.scalar_mul(k, &g)),
                "comb/ladder mismatch"
            );
        };

        let edges = [
            Fe::ZERO,
            Fe::ONE,
            Fe::from_u64(2),
            n.wrapping_sub(&Fe::ONE),
            n,
            n.wrapping_add(&Fe::ONE),
            fe_from_hex("8000000000000000000000000000000000000000000000000000000000000000"),
            Fe::from_limbs([u64::MAX; 4]),
        ];
        for k in &edges {
            check(k);
        }

        let mut rng = HmacDrbg::<Sha256>::new(b"p256-comb-differential", b"nonce", &[]);
        for _ in 0..32 {
            let mut limbs = [0u64; 4];
            for l in &mut limbs {
                *l = rng.next_u64();
            }
            check(&Fe::from_limbs(limbs));
        }
    }

    /// Differential test: the variable-time double-scalar multiplication
    /// (verify path) agrees with the constant-time comb + windowed ladder on
    /// edge scalars and a random batch, for a random non-generator base.
    #[test]
    fn mul_double_vartime_matches_constant_time() {
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;
        let curve = P256::new();
        let n = P256::order();

        let mut rng = HmacDrbg::<Sha256>::new(b"p256-vartime-differential", b"nonce", &[]);
        let rand_fe = |rng: &mut HmacDrbg<Sha256>| {
            let mut limbs = [0u64; 4];
            for l in &mut limbs {
                *l = rng.next_u64();
            }
            Fe::from_limbs(limbs)
        };

        // A "random" public point Q = t·G.
        let t = rand_fe(&mut rng).reduce(&n);
        let (qx, qy) = curve.to_affine(&curve.mul_generator(&t)).unwrap();
        let q = curve.lift_affine(&qx, &qy);

        let check = |u1: &Fe, u2: &Fe| {
            let ct = curve.point_add(&curve.mul_generator(u1), &curve.scalar_mul(u2, &q));
            let vt = curve.mul_double_vartime(u1, u2, &q);
            assert_eq!(
                curve.to_affine(&ct),
                curve.to_affine(&vt),
                "vartime/ct mismatch: u1={:x?} u2={:x?}",
                u1.as_limbs(),
                u2.as_limbs()
            );
        };

        let edges = [
            Fe::ZERO,
            Fe::ONE,
            Fe::from_u64(2),
            Fe::from_u64(15),
            Fe::from_u64(16),
            Fe::from_u64(17),
            n.wrapping_sub(&Fe::ONE),
            n.wrapping_sub(&Fe::from_u64(15)),
            fe_from_hex("8000000000000000000000000000000000000000000000000000000000000000"),
        ];
        for u1 in &edges {
            for u2 in &edges {
                check(u1, u2);
            }
        }

        for _ in 0..48 {
            let u1 = rand_fe(&mut rng).reduce(&n);
            let u2 = rand_fe(&mut rng).reduce(&n);
            check(&u1, &u2);
        }
    }

    /// Regenerates the fixed-base table source (`src/ec/p256_gtable.rs`) for
    /// the current [`COMB_W`]. Run with:
    /// `cargo test --release gen_p256_gen_table -- --ignored --nocapture`
    /// and paste the emitted `static`s between the file's header comment and
    /// EOF. The non-ignored `gen_table_matches_computed` test keeps the
    /// pasted constants honest on every test run.
    #[test]
    #[ignore = "table generator; emits Rust source on stdout"]
    #[cfg(feature = "std")]
    fn gen_p256_gen_table() {
        use std::{print, println};
        let curve = P256::new();
        // base = [B^i]G for the current window i.
        let mut base = curve.generator();
        let emit = |indent: &str, point: &Point| {
            let (x, y) = curve
                .to_affine(point)
                .expect("table entry is never identity");
            print!("{indent}[");
            for l in field::to_mont(&x).as_limbs() {
                print!("0x{l:016x}, ");
            }
            for l in field::to_mont(&y).as_limbs() {
                print!("0x{l:016x}, ");
            }
            println!("],");
        };
        println!("pub(crate) static P256_GEN_TABLE: [[[u64; 8]; COMB_ENTRIES]; COMB_WINDOWS] = [");
        for _ in 0..COMB_WINDOWS {
            println!("    [");
            let two_base = curve.double(&base);
            let mut acc = base;
            for j in 0..COMB_ENTRIES {
                if j > 0 {
                    acc = curve.point_add(&acc, &two_base);
                }
                emit("        ", &acc);
            }
            println!("    ],");
            for _ in 0..COMB_W {
                base = curve.double(&base);
            }
        }
        println!("];");
        println!();
        println!("/// `[B^W]G` (`B = 2^COMB_W`, `W = COMB_WINDOWS`), the comb's starting point.");
        print!("pub(crate) static P256_GEN_TOP: [u64; 8] = ");
        emit("", &base);
    }

    /// Plain left-to-right double-and-add over the bits of `k` with the
    /// complete formulas — the reference for the windowed ladders.
    fn reference_mul(curve: &P256, k: &Fe, p: &Point) -> Point {
        let mut acc = curve.identity();
        for i in (0..256).rev() {
            acc = curve.double(&acc);
            if (k.as_limbs()[i / 64] >> (i % 64)) & 1 == 1 {
                acc = curve.point_add(&acc, p);
            }
        }
        acc
    }

    /// The scalars that stress the odd recoding: zero and the identity
    /// multiples, even and odd values, `n ± 1`, scalars at and above
    /// `2²⁵⁵` and `n` (reduced first), all-ones, powers of 16 (every other
    /// digit even), and the all-`0xf` / alternating-nibble patterns.
    fn recoding_edge_scalars() -> [Fe; 16] {
        let n = P256::order();
        [
            Fe::ZERO,
            Fe::ONE,
            Fe::from_u64(2),
            Fe::from_u64(15),
            Fe::from_u64(16),
            Fe::from_u64(17),
            Fe::from_u64(0x8000_0000_0000_0000),
            n.wrapping_sub(&Fe::from_u64(2)),
            n.wrapping_sub(&Fe::ONE),
            n,
            n.wrapping_add(&Fe::ONE),
            n.wrapping_add(&Fe::from_u64(16)),
            fe_from_hex("8000000000000000000000000000000000000000000000000000000000000000"),
            fe_from_hex("7fffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"),
            Fe::from_limbs([u64::MAX; 4]),
            Fe::from_limbs([0xf0f0_f0f0_f0f0_f0f0; 4]),
        ]
    }

    /// Both constant-time ladders agree with double-and-add on `G` and on
    /// a random base for every edge scalar (a scalar `>= n` acts as `k mod
    /// n`, the documented policy) and a random batch.
    #[test]
    fn ladders_match_double_and_add_reference() {
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;
        let curve = P256::new();
        let n = P256::order();
        let g = curve.generator();
        let mut rng = HmacDrbg::<Sha256>::new(b"p256-ladder-reference", b"nonce", &[]);
        let mut rand_fe = || {
            let mut limbs = [0u64; 4];
            for l in &mut limbs {
                *l = rng.next_u64();
            }
            Fe::from_limbs(limbs)
        };
        let (qx, qy) = curve
            .to_affine(&curve.mul_generator(&rand_fe().reduce(&n)))
            .unwrap();
        let q = curve.lift_affine(&qx, &qy);

        let check = |k: &Fe| {
            let want_g = curve.to_affine(&reference_mul(&curve, k, &g));
            assert_eq!(
                curve.to_affine(&curve.mul_generator(k)),
                want_g,
                "mul_generator mismatch for {:x?}",
                k.as_limbs()
            );
            assert_eq!(
                curve.to_affine(&curve.scalar_mul(k, &g)),
                want_g,
                "scalar_mul(G) mismatch for {:x?}",
                k.as_limbs()
            );
            assert_eq!(
                curve.to_affine(&curve.scalar_mul(k, &q)),
                curve.to_affine(&reference_mul(&curve, k, &q)),
                "scalar_mul(Q) mismatch for {:x?}",
                k.as_limbs()
            );
        };
        for k in &recoding_edge_scalars() {
            check(k);
        }
        for _ in 0..16 {
            check(&rand_fe());
        }
        // The identity base multiplies to the identity.
        assert!(
            curve
                .to_affine(&curve.scalar_mul(&Fe::from_u64(7), &curve.identity()))
                .is_none()
        );
    }

    /// The scalars whose last window meets the Jacobian formulas'
    /// exceptional inputs (`k' = n − 2`: `acc = [d₀]P`, a doubling, for
    /// `k ≡ ±2`; `k' = n`: `acc = −[d₀]P`, the identity, for `k ≡ 0`) and
    /// their neighbours, through both constant-time ladders on `G` and on
    /// a random base, against double-and-add. Window 0 runs on the complete
    /// formula precisely so these come out right.
    #[test]
    fn ladders_final_window_exceptions() {
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;
        let curve = P256::new();
        let n = P256::order();
        let g = curve.generator();
        let mut rng = HmacDrbg::<Sha256>::new(b"p256-final-window", b"nonce", &[]);
        let mut limbs = [0u64; 4];
        for l in &mut limbs {
            *l = rng.next_u64();
        }
        let t = Fe::from_limbs(limbs).reduce(&n);
        let (qx, qy) = curve.to_affine(&curve.mul_generator(&t)).unwrap();
        let q = curve.lift_affine(&qx, &qy);
        let small = |v: u64| Fe::from_u64(v);
        let scalars = [
            Fe::ZERO,
            n,
            small(1),
            small(2),
            small(3),
            small(4),
            n.wrapping_sub(&small(1)),
            n.wrapping_sub(&small(2)),
            n.wrapping_sub(&small(3)),
            n.wrapping_sub(&small(4)),
            n.wrapping_add(&small(2)),
            n.wrapping_add(&small(1)),
        ];
        for k in &scalars {
            let want_g = curve.to_affine(&reference_mul(&curve, k, &g));
            assert_eq!(
                curve.to_affine(&curve.mul_generator(k)),
                want_g,
                "comb {k:x?}"
            );
            assert_eq!(
                curve.to_affine(&curve.scalar_mul(k, &g)),
                want_g,
                "ladder(G) {k:x?}"
            );
            assert_eq!(
                curve.to_affine(&curve.scalar_mul(k, &q)),
                curve.to_affine(&reference_mul(&curve, k, &q)),
                "ladder(Q) {k:x?}"
            );
        }
    }

    /// The base-`2^w` recoding (`w = 2..=8`, the comb's widths and beyond)
    /// reconstructs `k'`: `2^(w·W) + Σ dᵢ·2^(w·i)` over `W = ⌈256/w⌉`
    /// windows, evaluated mod `n` (the top term exceeds `2²⁵⁶` when `w ∤
    /// 256`), with every digit odd and below `2^w` in magnitude.
    #[test]
    fn odd_scalar_recoding_any_width() {
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;
        let n = P256::order();
        let fq = P256::order_modulus();
        let mut rng = HmacDrbg::<Sha256>::new(b"p256-odd-recoding-w", b"nonce", &[]);
        let mut scalars = recoding_edge_scalars().to_vec();
        for _ in 0..32 {
            let mut limbs = [0u64; 4];
            for l in &mut limbs {
                *l = rng.next_u64();
            }
            scalars.push(Fe::from_limbs(limbs));
        }
        for w in 2..=8usize {
            let windows = 256usize.div_ceil(w);
            let base = Fe::from_u64(1 << w);
            for k in &scalars {
                let odd = OddScalar::new(k);
                // Horner mod n from the implicit top digit 1.
                let mut acc = Fe::ONE;
                for i in (0..windows).rev() {
                    let (index, neg) = odd.digit_w(w, i);
                    assert!(index < (1 << (w - 1)), "index out of range");
                    assert!(neg == 0 || neg == u64::MAX);
                    let mag = Fe::from_u64(2 * index + 1);
                    acc = fq.mul_mod(&acc, &base);
                    acc = if neg == u64::MAX {
                        fq.sub_mod(&acc, &mag)
                    } else {
                        fq.add_mod(&acc, &mag)
                    };
                }
                assert_eq!(acc, odd.k.reduce(&n), "w={w} k={:x?}", k.as_limbs());
            }
        }
    }

    /// The odd recoding reconstructs `k'`: `16⁶⁴ + Σ dᵢ·16ⁱ`, evaluated
    /// as integers, equals the odd representative, every digit is odd and
    /// within `±15`, and the result-negation flag matches `k mod n`'s
    /// parity.
    #[test]
    fn odd_scalar_recoding_is_exact() {
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;
        let n = P256::order();
        let mut rng = HmacDrbg::<Sha256>::new(b"p256-odd-recoding", b"nonce", &[]);
        let check = |k: &Fe| {
            let odd = OddScalar::new(k);
            let reduced = super::super::reduce_256(k, &n);
            let even = !bool::from(reduced.is_odd());
            assert_eq!(odd.negate_result, if even { u64::MAX } else { 0 });
            let expect = if even {
                n.wrapping_sub(&reduced)
            } else {
                reduced
            };
            assert!(bool::from(odd.k.is_odd()));
            assert_eq!(odd.k, expect);
            // Horner evaluation from the implicit top digit, in wrapping
            // 256-bit arithmetic (the true value is < 2²⁵⁶, and every
            // partial sum stays within ±2²⁵⁶ so the wrap is harmless).
            let mut acc = Fe::ONE;
            for i in (0..64).rev() {
                let (index, neg) = odd.digit(i);
                assert!(index < 8, "index out of range");
                assert!(neg == 0 || neg == u64::MAX);
                let mag = Fe::from_u64(2 * index + 1);
                for _ in 0..4 {
                    acc = acc.wrapping_add(&acc);
                }
                acc = if neg == u64::MAX {
                    acc.wrapping_sub(&mag)
                } else {
                    acc.wrapping_add(&mag)
                };
            }
            assert_eq!(acc, expect, "recoding mismatch for {:x?}", k.as_limbs());
        };
        for k in &recoding_edge_scalars() {
            check(k);
        }
        for _ in 0..64 {
            let mut limbs = [0u64; 4];
            for l in &mut limbs {
                *l = rng.next_u64();
            }
            check(&Fe::from_limbs(limbs));
        }
    }

    /// The variable-time ladder against the constant-time path on the
    /// bases that trigger every exceptional branch of the Jacobian
    /// formulas: `Q = ±G` (digit collisions, `acc = ±[d]G`), `Q = [2^k]G`
    /// (aligned digit positions), with `u1`/`u2` zero, one, `n − 1`, powers
    /// of two and the recoding edges.
    #[test]
    fn mul_double_vartime_exceptional_bases() {
        let curve = P256::new();
        let n = P256::order();
        let g = curve.generator();
        let pow2 = |k: u32| {
            let mut p = g;
            for _ in 0..k {
                p = curve.double(&p);
            }
            p
        };
        let bases = [
            g,
            Point {
                x: g.x,
                y: field::negate(&g.y),
                z: g.z,
            },
            pow2(1),
            pow2(4),
            pow2(5),
            pow2(64),
            pow2(255),
        ];
        let scalars = [
            Fe::ZERO,
            Fe::ONE,
            Fe::from_u64(2),
            Fe::from_u64(3),
            Fe::from_u64(16),
            Fe::from_u64(17),
            n.wrapping_sub(&Fe::ONE),
            n.wrapping_sub(&Fe::from_u64(2)),
            fe_from_hex("8000000000000000000000000000000000000000000000000000000000000000"),
            fe_from_hex("0000000000000000000000000000000100000000000000000000000000000000"),
        ];
        for base in &bases {
            let (qx, qy) = curve.to_affine(base).unwrap();
            let q = curve.lift_affine(&qx, &qy);
            for u1 in &scalars {
                for u2 in &scalars {
                    let ct = curve.point_add(&curve.mul_generator(u1), &curve.scalar_mul(u2, &q));
                    let vt = curve.mul_double_vartime(u1, u2, &q);
                    assert_eq!(
                        curve.to_affine(&ct),
                        curve.to_affine(&vt),
                        "vartime/ct mismatch: u1={:x?} u2={:x?}",
                        u1.as_limbs(),
                        u2.as_limbs()
                    );
                }
            }
        }
        // An identity base contributes nothing.
        let id = curve.identity();
        for u1 in &scalars {
            assert_eq!(
                curve.to_affine(&curve.mul_double_vartime(u1, &Fe::from_u64(5), &id)),
                curve.to_affine(&curve.mul_generator(u1))
            );
        }
    }

    /// Each exceptional branch of the Jacobian mixed addition, directly:
    /// identity accumulator, `acc = P` (doubling) and `acc = −P` (identity),
    /// plus the generic case against the complete projective formulas.
    #[test]
    fn jacobian_add_affine_branches() {
        let curve = P256::new();
        let g = curve.generator();
        let two_g = curve.double(&g);
        let (gx, gy) = (g.x, g.y);
        let affine_of = |j: &Jacobian| {
            let z2 = curve.sqr(&j.z);
            curve.to_affine(&Point {
                x: curve.mul(&j.x, &j.z),
                y: j.y,
                z: curve.mul(&z2, &j.z),
            })
        };
        // Identity + G = G.
        let r = curve.jac_add_affine(&Jacobian::IDENTITY, &gx, &gy);
        assert_eq!(affine_of(&r), curve.to_affine(&g));
        // Non-trivially scaled G (Z ≠ 1) + G = 2G through the doubling branch.
        let lambda = field::to_mont(&Fe::from_u64(7));
        let l2 = curve.sqr(&lambda);
        let scaled = Jacobian {
            x: curve.mul(&gx, &l2),
            y: curve.mul(&gy, &curve.mul(&l2, &lambda)),
            z: lambda,
        };
        let r = curve.jac_add_affine(&scaled, &gx, &gy);
        assert_eq!(affine_of(&r), curve.to_affine(&two_g));
        // Scaled G + (−G) = identity.
        let r = curve.jac_add_affine(&scaled, &gx, &field::negate(&gy));
        assert!(bool::from(r.z.is_zero()));
        assert!(affine_of(&r).is_none());
        // Generic: 2G + G = 3G, and doubling 2G = 4G.
        let j2 = curve.jac_add_affine(
            &curve.jac_add_affine(&Jacobian::IDENTITY, &gx, &gy),
            &gx,
            &gy,
        );
        let r = curve.jac_add_affine(&j2, &gx, &gy);
        assert_eq!(affine_of(&r), curve.to_affine(&curve.point_add(&two_g, &g)));
        assert_eq!(
            affine_of(&curve.jac_double(&j2)),
            curve.to_affine(&curve.double(&two_g))
        );
        assert!(bool::from(
            curve.jac_double(&Jacobian::IDENTITY).z.is_zero()
        ));
    }

    /// The inversion-free x-check agrees with the affine computation,
    /// including on the `x ≡ r (mod n)` wrap-around candidate `r + n`.
    #[test]
    fn verify_x_vartime_matches_affine_check() {
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;
        let curve = P256::new();
        let n = P256::order();
        let mut rng = HmacDrbg::<Sha256>::new(b"p256-verify-x", b"nonce", &[]);
        let mut rand_fe = || {
            let mut limbs = [0u64; 4];
            for l in &mut limbs {
                *l = rng.next_u64();
            }
            Fe::from_limbs(limbs).reduce(&n)
        };
        let (qx, qy) = curve.to_affine(&curve.mul_generator(&rand_fe())).unwrap();
        let q = curve.lift_affine(&qx, &qy);
        for _ in 0..16 {
            let (u1, u2) = (rand_fe(), rand_fe());
            let (x, _) = curve
                .to_affine(&curve.mul_double_vartime(&u1, &u2, &q))
                .unwrap();
            let r = super::super::reduce_256(&x, &n);
            assert!(curve.verify_x_vartime(&u1, &u2, &q, &r));
            assert!(!curve.verify_x_vartime(&u1, &u2, &q, &r.wrapping_add(&Fe::ONE)));
            assert!(!curve.verify_x_vartime(&u1, &u2, &q, &Fe::ZERO));
            // The second candidate r + n (only when x >= n, never observed
            // for a random point; the branch itself is exercised with a
            // small r where r + n < p and cannot match).
            assert!(!curve.verify_x_vartime(&u1, &u2, &q, &Fe::from_u64(1)));
        }
        // The identity never verifies: u1 = u2 = 0.
        assert!(!curve.verify_x_vartime(&Fe::ZERO, &Fe::ZERO, &q, &Fe::ONE));
        // A wrapped candidate must not match: with r = 2²⁵⁶ − n + x (in
        // range, since 2²⁵⁶ − n < n), r + n wraps to x in 256-bit
        // arithmetic, which must not count as `x ≡ r (mod n)`.
        let (x, _) = curve
            .to_affine(&curve.mul_double_vartime(&Fe::ONE, &Fe::ONE, &q))
            .unwrap();
        let wrapped = Fe::ZERO.wrapping_sub(&n).wrapping_add(&x);
        assert!(bool::from(wrapped.ct_lt(&n)));
        assert!(!curve.verify_x_vartime(&Fe::ONE, &Fe::ONE, &q, &wrapped));
    }

    #[test]
    fn random_scalar_in_range() {
        // Every sampled scalar must be in `[1, n)`. The new rejection
        // sampler returns only values that satisfy `d != 0 && d < n`;
        // a draw of 256 random bits has acceptance probability extremely
        // close to 1 for P-256, so a few hundred iterations exercise the
        // happy path without flake risk.
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;
        let mut rng = HmacDrbg::<Sha256>::new(b"p256-random-scalar", b"nonce", &[]);
        let n = P256::order();
        for _ in 0..256 {
            let d = random_scalar(&mut rng);
            assert!(!bool::from(d.is_zero()), "scalar must be nonzero");
            assert!(bool::from(d.ct_lt(&n)), "scalar must be < n");
        }
    }

    /// Manual microbenchmark of the group operations and the P-256 users
    /// (`cargo test --release --all-features microbench_group_ops -- --ignored --nocapture`).
    #[test]
    #[ignore = "manual microbenchmark"]
    #[cfg(feature = "std")]
    fn microbench_group_ops() {
        use crate::ec::ecdh::EcdhPrivateKey;
        use crate::ec::ecdsa::EcdsaPrivateKey;
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;
        use core::hint::black_box;
        use std::println;
        use std::time::Instant;

        fn time<F: FnMut()>(name: &str, iters: u32, mut f: F) {
            for _ in 0..(iters / 10).max(1) {
                f();
            }
            let t = Instant::now();
            for _ in 0..iters {
                f();
            }
            let ns = t.elapsed().as_nanos() as f64 / iters as f64;
            if ns < 10_000.0 {
                println!("  {name:<36} {ns:>10.1} ns/op");
            } else {
                println!("  {name:<36} {:>10.2} us/op", ns / 1000.0);
            }
        }

        let curve = P256::new();
        let n = P256::order();
        let mut rng = HmacDrbg::<Sha256>::new(b"p256-microbench", b"nonce", &[]);
        let mut rand_fe = || {
            let mut limbs = [0u64; 4];
            for l in &mut limbs {
                *l = rng.next_u64();
            }
            Fe::from_limbs(limbs).reduce(&n)
        };
        let k1 = rand_fe();
        let k2 = rand_fe();
        let (qx, qy) = curve.to_affine(&curve.mul_generator(&k2)).unwrap();
        let qa = curve.lift_affine(&qx, &qy);
        let q = curve.mul_generator(&k2);

        let mut p = q;
        time("point_add", 500_000, || p = curve.point_add(&p, &qa));
        black_box(p);
        let mut p = q;
        time("double", 500_000, || p = curve.double(&p));
        black_box(p);
        time("to_affine", 20_000, || {
            black_box(curve.to_affine(black_box(&q)));
        });
        time("scalar_mul (CT)", 2_000, || {
            black_box(curve.scalar_mul(black_box(&k1), black_box(&qa)));
        });
        time("mul_generator (CT)", 5_000, || {
            black_box(curve.mul_generator(black_box(&k1)));
        });
        time("mul_double_vartime", 2_000, || {
            black_box(curve.mul_double_vartime(black_box(&k1), black_box(&k2), black_box(&qa)));
        });

        let mut rng = HmacDrbg::<Sha256>::new(b"p256-microbench-keys", b"nonce", &[]);
        let sk = EcdsaPrivateKey::generate(&mut rng);
        let pk = sk.public_key();
        let msg = b"hello world, this is a benchmark message of modest length";
        let sig = sk.sign::<Sha256>(msg).unwrap();
        time("ECDSA sign", 5_000, || {
            black_box(sk.sign::<Sha256>(black_box(msg)).unwrap());
        });
        time("ECDSA verify", 2_000, || {
            pk.verify::<Sha256>(black_box(msg), black_box(&sig))
                .unwrap();
        });
        let e1 = EcdhPrivateKey::generate(&mut rng);
        let p2 = EcdhPrivateKey::generate(&mut rng).public_key();
        time("ECDH public_key", 5_000, || {
            black_box(e1.public_key());
        });
        time("ECDH diffie_hellman", 2_000, || {
            black_box(e1.diffie_hellman(black_box(&p2)).unwrap());
        });
    }
}
