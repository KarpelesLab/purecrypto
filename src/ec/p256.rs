//! NIST P-256 (secp256r1) field and group arithmetic.
//!
//! The base field runs on the native Solinas backend
//! ([`super::p256_field`]): plain (non-Montgomery) residues in `[0, p)` with
//! the FIPS 186 fast reduction, so SEC1 encode/decode and the point formulas
//! share one representation with no conversions.

use super::p256_field as field;
#[cfg(feature = "p256-table")]
use super::p256_gtable::P256_GEN_TABLE;
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
const P_HEX: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const B_HEX: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
// The generator's affine coordinates, test-only: the library takes `G` from
// `G_AFFINE`, checked against these by `tests::generator_matches_hex`.
#[cfg(test)]
const GX_HEX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
#[cfg(test)]
const GY_HEX: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
/// The generator `G` as a comb-table entry: affine `x‖y`, little-endian
/// 64-bit limbs, plain residues — the same value as `P256_GEN_TABLE[0][0]`.
#[cfg(any(test, not(feature = "p256-table")))]
const G_AFFINE: [u64; 8] = [
    0xf4a13945d898c296,
    0x77037d812deb33a0,
    0xf8bce6e563a440f2,
    0x6b17d1f2e12c4247,
    0xcbb6406837bf51f5,
    0x2bce33576b315ece,
    0x8ee7eb4a7c0f9e16,
    0x4fe342e2fe1a7f9b,
];
const N_HEX: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
/// The group order `n`, decoded at compile time.
const ORDER: Fe = fe_from_hex(N_HEX);
/// The order-`n` Montgomery context, so ECDSA does not redo the `R² mod n`
/// setup on every sign / verify.
static ORDER_MODULUS: MontModulus<4> = MontModulus::new(ORDER);

/// Decodes a 64-character hex string into a [`Fe`].
pub(crate) const fn fe_from_hex(hex: &str) -> Fe {
    super::uint_from_be_hex(hex)
}

/// A point in projective coordinates `(X : Y : Z)` with field elements held
/// as plain residues in `[0, p)`. The identity is `(0 : 1 : 0)`.
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
        P256 {
            b: fe_from_hex(B_HEX),
        }
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

    /// The field prime `p`.
    pub(crate) fn field_modulus() -> Fe {
        fe_from_hex(P_HEX)
    }

    /// The identity point `(0 : 1 : 0)`.
    pub(crate) fn identity(&self) -> Point {
        Point {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ZERO,
        }
    }

    /// The base point `G`. With the comb table, library code multiplies by
    /// `G` through [`Self::mul_generator`] and never needs the point itself.
    #[cfg(any(test, not(feature = "p256-table")))]
    pub(crate) fn generator(&self) -> Point {
        let x = Fe::from_limbs([G_AFFINE[0], G_AFFINE[1], G_AFFINE[2], G_AFFINE[3]]);
        let y = Fe::from_limbs([G_AFFINE[4], G_AFFINE[5], G_AFFINE[6], G_AFFINE[7]]);
        self.lift_affine(&x, &y)
    }

    /// Lifts an affine point `(x, y)` to projective form.
    pub(crate) fn lift_affine(&self, x: &Fe, y: &Fe) -> Point {
        Point {
            x: *x,
            y: *y,
            z: Fe::ONE,
        }
    }

    /// Converts a point to affine `(x, y)`, or `None` if it is the identity.
    ///
    /// The inversion is the fixed-addition-chain Fermat exponentiation
    /// `z^{p-2} mod p` ([`field::invert`]) — constant time by construction
    /// (a fixed sequence of 255 squarings and 13 multiplies), NOT the
    /// variable-time extended-Euclidean `inv_mod` — `z` is derived from the
    /// secret scalar on every ECDH / ECDSA hot path and a timing leak here
    /// would be exploitable.
    ///
    /// Whether the point is the identity is public in every caller: P-256
    /// has prime order, so `[k]P` is the identity iff `k ≡ 0 (mod n)` or `P`
    /// is — a degenerate scalar or peer the caller rejects as an error.
    pub(crate) fn to_affine(&self, point: &Point) -> Option<(Fe, Fe)> {
        if point.z.is_zero().declassify() {
            return None;
        }
        let z_inv = field::invert(&point.z);
        let x = field::mul(&point.x, &z_inv);
        let y = field::mul(&point.y, &z_inv);
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

    /// Constant-time scalar multiplication `scalar * point` via a fixed
    /// 4-bit window: 4 doublings and one *unconditional* addition per
    /// nibble, with the window value fetched by a masked scan of all 16
    /// table entries (no secret-indexed memory access). A zero nibble adds
    /// the identity — the complete RCB formulas make that a no-op with the
    /// same operation sequence — so, like the previous
    /// double-and-add-always ladder, the schedule is a function of the
    /// (public) scalar width only.
    pub(crate) fn scalar_mul(&self, scalar: &Fe, point: &Point) -> Point {
        // table[j] = [j]P; table[0] is the identity.
        let mut table = [self.identity(); 16];
        table[1] = *point;
        for i in 2..16 {
            table[i] = self.point_add(&table[i - 1], point);
        }

        let mut acc = self.identity();
        let limbs = scalar.as_limbs();
        let mut i = 4;
        while i > 0 {
            i -= 1;
            let limb = limbs[i];
            let mut shift = 64;
            while shift > 0 {
                shift -= 4;
                acc = self.double(&acc);
                acc = self.double(&acc);
                acc = self.double(&acc);
                acc = self.double(&acc);

                let digit = ((limb >> shift) & 0xf) as usize;
                // Constant-time gather of table[digit]: the index comparison
                // goes through `ct_eq` rather than a `==` the compiler may
                // lower to a branch on the secret window digit.
                let mut sel = table[0];
                for (j, entry) in table.iter().enumerate() {
                    sel = Point::conditional_select(entry, &sel, j.ct_eq(&digit));
                }
                acc = self.point_add(&acc, &sel);
                sel.zeroize();
            }
        }
        // The table holds the multiples [j]P; with a secret scalar those are
        // secret intermediates, so do not leave them on the stack.
        table.zeroize();
        acc
    }

    /// Constant-time fixed-base multiplication `scalar * G` via the
    /// precomputed comb table [`P256_GEN_TABLE`]: `[k]G = Σᵢ [dᵢ · 16^i]G`
    /// over the 64 base-16 digits `dᵢ` of the scalar, so there are **no
    /// doublings** — just 64 unconditional additions, each operand fetched by
    /// a masked scan of that window's 15 stored points (no secret-indexed
    /// memory access, same gather discipline as [`Self::scalar_mul`]). A zero
    /// digit adds the identity, a uniform no-op under the complete RCB
    /// formulas, so the schedule depends only on the (public) scalar width.
    #[cfg(feature = "p256-table")]
    pub(crate) fn mul_generator(&self, scalar: &Fe) -> Point {
        let id = self.identity();
        let mut acc = id;
        let limbs = scalar.as_limbs();
        for (i, window) in P256_GEN_TABLE.iter().enumerate() {
            // Digit i = bits [4i, 4i+4) of the little-endian scalar.
            let digit = ((limbs[i / 16] >> ((i % 16) * 4)) & 0xf) as usize;
            // Constant-time gather: scan all 15 entries, keep entry j when
            // j + 1 == digit; a zero digit keeps the identity.
            let mut sel = id;
            for (j, entry) in window.iter().enumerate() {
                let cand = Point {
                    x: Fe::from_limbs([entry[0], entry[1], entry[2], entry[3]]),
                    y: Fe::from_limbs([entry[4], entry[5], entry[6], entry[7]]),
                    z: Fe::ONE,
                };
                sel = Point::conditional_select(&cand, &sel, (j + 1).ct_eq(&digit));
            }
            acc = self.point_add(&acc, &sel);
            sel.zeroize();
        }
        acc
    }

    /// Constant-time fixed-base multiplication `scalar * G` without the comb
    /// table (feature `p256-table` off): the generic windowed ladder
    /// [`Self::scalar_mul`] over `G`. Same result and the same secret-scalar
    /// discipline, at the cost of ~252 doublings the table would avoid.
    #[cfg(not(feature = "p256-table"))]
    pub(crate) fn mul_generator(&self, scalar: &Fe) -> Point {
        self.scalar_mul(scalar, &self.generator())
    }

    /// Point negation `(X : -Y : Z)` (the negation itself is constant time;
    /// currently only the variable-time verify path needs it).
    fn negate_point(&self, p: &Point) -> Point {
        Point {
            x: p.x,
            y: field::negate(&p.y),
            z: p.z,
        }
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
    /// Strategy: `u1·G` through the fixed-base comb with direct (public)
    /// indexing and zero-digit skipping — no doublings at all — plus `u2·Q`
    /// via width-5 wNAF (8 precomputed odd multiples, ~256 doublings and
    /// ~43 additions on average), joined by one final addition. Without the
    /// comb table (feature `p256-table` off), both wNAF ladders are
    /// interleaved (Straus) so they share one run of doublings.
    pub(crate) fn mul_double_vartime(&self, u1: &Fe, u2: &Fe, q: &Point) -> Point {
        #[cfg(feature = "p256-table")]
        {
            self.point_add(
                &self.mul_generator_vartime(u1),
                &self.scalar_mul_vartime(u2, q),
            )
        }
        #[cfg(not(feature = "p256-table"))]
        {
            let odd_g = self.odd_multiples(&self.generator());
            let odd_q = self.odd_multiples(q);
            let naf1 = wnaf5(u1);
            let naf2 = wnaf5(u2);
            let Some(top) = naf1
                .iter()
                .zip(naf2.iter())
                .rposition(|(&a, &b)| a != 0 || b != 0)
            else {
                return self.identity();
            };
            let mut acc = self.identity();
            for i in (0..=top).rev() {
                acc = self.double(&acc);
                acc = self.add_naf_digit(&acc, naf1[i], &odd_g);
                acc = self.add_naf_digit(&acc, naf2[i], &odd_q);
            }
            acc
        }
    }

    /// The odd multiples `[1]P, [3]P, …, [15]P` for the width-5 wNAF ladders.
    fn odd_multiples(&self, point: &Point) -> [Point; 8] {
        let two_p = self.double(point);
        let mut table = [*point; 8];
        for i in 1..8 {
            table[i] = self.point_add(&table[i - 1], &two_p);
        }
        table
    }

    /// Adds the wNAF digit `d` (odd, `|d| <= 15`, or zero for a no-op) times
    /// the point whose odd multiples are `odd`. **Variable-time.**
    #[inline]
    fn add_naf_digit(&self, acc: &Point, d: i8, odd: &[Point; 8]) -> Point {
        if d > 0 {
            self.point_add(acc, &odd[(d as usize - 1) / 2])
        } else if d < 0 {
            self.point_add(acc, &self.negate_point(&odd[((-d) as usize - 1) / 2]))
        } else {
            *acc
        }
    }

    /// **VARIABLE-TIME** fixed-base multiplication `k·G` (comb table with
    /// direct indexing, zero digits skipped). Public scalars only — see
    /// [`Self::mul_double_vartime`].
    #[cfg(feature = "p256-table")]
    fn mul_generator_vartime(&self, k: &Fe) -> Point {
        let mut acc = self.identity();
        let limbs = k.as_limbs();
        for (i, window) in P256_GEN_TABLE.iter().enumerate() {
            let digit = ((limbs[i / 16] >> ((i % 16) * 4)) & 0xf) as usize;
            if digit != 0 {
                let entry = &window[digit - 1];
                let cand = Point {
                    x: Fe::from_limbs([entry[0], entry[1], entry[2], entry[3]]),
                    y: Fe::from_limbs([entry[4], entry[5], entry[6], entry[7]]),
                    z: Fe::ONE,
                };
                acc = self.point_add(&acc, &cand);
            }
        }
        acc
    }

    /// **VARIABLE-TIME** scalar multiplication `k·point` via width-5 wNAF.
    /// Public scalars only — see [`Self::mul_double_vartime`].
    #[cfg(feature = "p256-table")]
    fn scalar_mul_vartime(&self, k: &Fe, point: &Point) -> Point {
        let table = self.odd_multiples(point);

        let naf = wnaf5(k);
        // Skip leading zero digits (public scalar, so this leak is fine).
        let mut i = naf.len();
        while i > 0 && naf[i - 1] == 0 {
            i -= 1;
        }
        let mut acc = self.identity();
        while i > 0 {
            i -= 1;
            acc = self.double(&acc);
            acc = self.add_naf_digit(&acc, naf[i], &table);
        }
        acc
    }

    /// Tests whether affine `(x, y)` satisfies the curve equation
    /// `y^2 = x^3 - 3x + b (mod p)`.
    pub(crate) fn is_on_curve(&self, x: &Fe, y: &Fe) -> bool {
        let three = Fe::from_u64(3);
        let lhs = field::square(y);
        let x3 = field::mul(&field::square(x), x);
        let three_x = field::mul(&three, x);
        let rhs = field::add(&field::sub(&x3, &three_x), &self.b);
        bool::from(lhs.ct_eq(&rhs))
    }
}

/// Width-5 wNAF recoding of a 256-bit scalar: digits in
/// `{0, ±1, ±3, …, ±15}` with any two nonzero digits at least 5 positions
/// apart. **Variable time** in the scalar — public scalars only.
fn wnaf5(k: &Fe) -> [i8; 257] {
    let mut naf = [0i8; 257];
    let mut k = *k;
    let mut i = 0;
    while !bool::from(k.is_zero()) {
        if bool::from(k.is_odd()) {
            let low = (k.as_limbs()[0] & 31) as i8;
            let d = if low > 16 { low - 32 } else { low };
            naf[i] = d;
            if d > 0 {
                k = k.wrapping_sub(&Fe::from_u64(d as u64));
            } else {
                // k < 2^256 - 15 always holds here (k only shrinks from an
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
        assert_eq!(g.x, fe_from_hex(GX_HEX));
        assert_eq!(g.y, fe_from_hex(GY_HEX));
        assert!(curve.is_on_curve(&g.x, &g.y));
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
        let mut base = curve.generator();
        for window in P256_GEN_TABLE.iter() {
            let mut acc = base;
            for (j, entry) in window.iter().enumerate() {
                if j > 0 {
                    acc = curve.point_add(&acc, &base);
                }
                assert!(
                    !bool::from(acc.z.is_zero()),
                    "table entry must not be the identity"
                );
                let ex = Fe::from_limbs([entry[0], entry[1], entry[2], entry[3]]);
                let ey = Fe::from_limbs([entry[4], entry[5], entry[6], entry[7]]);
                assert_eq!(curve.mul(&ex, &acc.z), acc.x, "x mismatch");
                assert_eq!(curve.mul(&ey, &acc.z), acc.y, "y mismatch");
            }
            base = curve.double(&curve.double(&curve.double(&curve.double(&base))));
        }
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

    /// Regenerates the fixed-base table source (`src/ec/p256_gtable.rs`).
    /// Run with:
    /// `cargo test --release gen_p256_gen_table -- --ignored --nocapture`
    /// and paste the emitted `static` between the file's header comment and
    /// EOF. The non-ignored `gen_table_matches_computed` test keeps the
    /// pasted constants honest on every test run.
    #[test]
    #[ignore = "table generator; emits Rust source on stdout"]
    #[cfg(feature = "std")]
    fn gen_p256_gen_table() {
        use std::{print, println};
        let curve = P256::new();
        // base = [16^i]G for the current window i.
        let mut base = curve.generator();
        println!("pub(crate) static P256_GEN_TABLE: [[[u64; 8]; 15]; 64] = [");
        for _ in 0..64 {
            println!("    [");
            let mut acc = base;
            for j in 1..=15u32 {
                if j > 1 {
                    acc = curve.point_add(&acc, &base);
                }
                let (x, y) = curve
                    .to_affine(&acc)
                    .expect("table entry is never identity");
                print!("        [");
                for l in x.as_limbs() {
                    print!("0x{l:016x}, ");
                }
                for l in y.as_limbs() {
                    print!("0x{l:016x}, ");
                }
                println!("],");
            }
            println!("    ],");
            base = curve.double(&curve.double(&curve.double(&curve.double(&base))));
        }
        println!("];");
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
}
