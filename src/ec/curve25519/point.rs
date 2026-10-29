//! Edwards25519 curve points in extended homogeneous coordinates.
//!
//! Twisted Edwards curve `−x² + y² = 1 + d·x²·y²` (`a = −1`) over
//! GF(2²⁵⁵−19), in extended coordinates `(X:Y:Z:T)` with the complete
//! Hisil–Wong–Carter–Dawson 2008 addition formulas. Scalar multiplication is a
//! constant-time fixed 4-bit window ladder; base-point multiplication uses a
//! precomputed signed radix-16 table of affine Niels points
//! (`super::base_table`, feature `ed25519-table`) with no doublings, or the
//! same ladder over the base point without it. This is the shared point
//! backend behind Ed25519, the edwards25519 hazmat surface, and ristretto255.
//!
//! Two clearly-marked `_vartime` entry points exist for **public-input**
//! workloads (Ed25519 signature verification): they take data-dependent
//! branches and perform table lookups indexed by the scalar, so they must
//! never see secret scalars or secret points.

#[cfg(feature = "ed25519-table")]
use super::base_table::{ED25519_BASE_2_256, ED25519_BASE_ODD, ED25519_BASE_TABLE};
use super::field::{Fe, Field, ScalarInt, eq_mask, mask_from_bit};
use crate::ct::{Choice, ConstantTimeLess};
use crate::zeroize::Zeroize;

/// A curve point in extended homogeneous coordinates `(X:Y:Z:T)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Point {
    pub(crate) x: Fe,
    pub(crate) y: Fe,
    pub(crate) z: Fe,
    pub(crate) t: Fe,
}

/// The base point `B` as affine `x‖y‖t` (`t = x·y`), 5 little-endian 51-bit
/// limbs each, canonical residues. Checked against the RFC 8032 encoding by
/// `tests::base_affine_matches_encoding`.
#[cfg(any(
    test,
    feature = "hazmat-edwards25519",
    feature = "ristretto255",
    not(feature = "ed25519-table")
))]
const BASE_AFFINE: [u64; 15] = [
    0x62d608f25d51a,
    0x412a4b4f6592a,
    0x75b7171a4b31d,
    0x1ff60527118fe,
    0x216936d3cd6e5,
    0x6666666666658,
    0x4cccccccccccc,
    0x1999999999999,
    0x3333333333333,
    0x6666666666666,
    0x68ab3a5b7dda3,
    0x00eea2a5eadbb,
    0x2af8df483c27e,
    0x332b375274732,
    0x67875f0fd78b7,
];

/// Lifts a stored affine point (`x‖y‖t`, 5 little-endian 51-bit limbs each,
/// canonical residues) to extended coordinates with `Z = 1`.
#[cfg(any(
    test,
    feature = "hazmat-edwards25519",
    feature = "ristretto255",
    not(feature = "ed25519-table")
))]
#[inline]
fn table_point(entry: &[u64; 15], one: Fe) -> Point {
    Point {
        x: Fe([entry[0], entry[1], entry[2], entry[3], entry[4]]),
        y: Fe([entry[5], entry[6], entry[7], entry[8], entry[9]]),
        z: one,
        t: Fe([entry[10], entry[11], entry[12], entry[13], entry[14]]),
    }
}

/// An affine point in **Niels** form `(y + x, y − x, 2·d·x·y)`: exactly the
/// three values the mixed addition [`Field::add_niels`] multiplies by, so a
/// precomputed point costs no conversion. The identity is `(1, 1, 0)`, and
/// negation swaps the first two values and negates the third.
#[cfg(feature = "ed25519-table")]
#[derive(Clone, Copy)]
pub(crate) struct Niels {
    ypx: Fe,
    ymx: Fe,
    t2d: Fe,
}

#[cfg(feature = "ed25519-table")]
impl Niels {
    /// The neutral element `(1, 1, 0)`.
    const IDENTITY: Niels = Niels {
        ypx: Fe::ONE,
        ymx: Fe::ONE,
        t2d: Fe::ZERO,
    };

    /// Loads a stored table entry (`(y+x)‖(y−x)‖(2·d·t)`, 5 little-endian
    /// 51-bit limbs each, canonical residues).
    #[inline(always)]
    fn from_entry(e: &[u64; 15]) -> Niels {
        Niels {
            ypx: Fe([e[0], e[1], e[2], e[3], e[4]]),
            ymx: Fe([e[5], e[6], e[7], e[8], e[9]]),
            t2d: Fe([e[10], e[11], e[12], e[13], e[14]]),
        }
    }

    /// `a` when `mask` is all-ones, `b` when it is zero (same mask contract
    /// as [`Fe::select`]).
    #[inline(always)]
    fn select(a: &Niels, b: &Niels, mask: u64) -> Niels {
        Niels {
            ypx: Fe::select(&a.ypx, &b.ypx, mask),
            ymx: Fe::select(&a.ymx, &b.ymx, mask),
            t2d: Fe::select(&a.t2d, &b.t2d, mask),
        }
    }

    /// Constant-time gather of the entry with magnitude `|d|` from one
    /// table window, negated when `d < 0`; `d = 0` yields the identity.
    /// Scans all 8 entries with one barriered equality mask each (no
    /// secret-indexed memory access), then applies the sign with one
    /// barriered mask (swap `y+x`/`y−x`, negate `2dt`).
    #[inline]
    fn gather(window: &[[u64; 15]; 8], d: i8) -> Niels {
        // `smask` is 0xff iff d < 0; `mag` = |d| ∈ 0..=8, both branch-free.
        let smask = (d >> 7) as u8;
        let mag = ((d as u8) ^ smask).wrapping_sub(smask) as u64;
        let mut sel = Niels::IDENTITY;
        for (j, entry) in window.iter().enumerate() {
            let cand = Niels::from_entry(entry);
            sel = Niels::select(&cand, &sel, eq_mask(j as u64 + 1, mag));
        }
        let neg = mask_from_bit((smask & 1) as u64);
        Fe::cswap(&mut sel.ypx, &mut sel.ymx, neg);
        sel.t2d = Fe::select(&sel.t2d.neg(), &sel.t2d, neg);
        sel
    }

    /// `−self` (swap `y+x` and `y−x`, negate `2dt`).
    #[cfg(any(test, feature = "ed25519-table"))]
    #[inline]
    fn negate(&self) -> Niels {
        Niels {
            ypx: self.ymx,
            ymx: self.ypx,
            t2d: self.t2d.neg(),
        }
    }
}

/// Recodes a 256-bit little-endian scalar into 65 signed radix-16 digits:
/// `d[0..64] ∈ [−8, 8)` and a carry digit `d[64] ∈ {0, 1}`, with
/// `scalar = Σ d[i]·16^i` exactly (no reduction, no assumption on the top
/// bit). Constant time: a fixed carry chain of plain arithmetic, no
/// comparisons. The digits are secret; callers wipe them.
fn radix16_signed(scalar: &[u8; 32]) -> [i8; 65] {
    let mut d = [0i8; 65];
    for (i, &b) in scalar.iter().enumerate() {
        d[2 * i] = (b & 15) as i8;
        d[2 * i + 1] = (b >> 4) as i8;
    }
    let mut carry = 0i8;
    for digit in d.iter_mut().take(64) {
        // v ∈ [0, 16]; carry out iff v ≥ 8; the digit becomes v − 16·carry.
        let v = *digit + carry;
        carry = (v + 8) >> 4;
        *digit = v - (carry << 4);
    }
    d[64] = carry;
    d
}

impl Field {
    /// The base point `B`.
    // With the comb table, library-path base multiplications never touch the
    // point itself; only the group APIs (and tests) do. Gate to avoid
    // dead_code on the default (Ed25519-only) build.
    #[cfg(any(
        test,
        feature = "hazmat-edwards25519",
        feature = "ristretto255",
        not(feature = "ed25519-table")
    ))]
    pub(crate) fn base(&self) -> Point {
        table_point(&BASE_AFFINE, self.one)
    }

    /// Decompresses a 32-byte point encoding (RFC 8032 §5.1.3), or `None` if the
    /// bytes do not encode a curve point.
    pub(crate) fn decode(&self, enc: &[u8; 32]) -> Option<Point> {
        let sign = (enc[31] >> 7) & 1;
        let mut yb = *enc;
        yb[31] &= 0x7f;
        let yval = ScalarInt::from_le_bytes(&yb);
        if !bool::from(yval.ct_lt(&self.p)) {
            return None;
        }
        let y = Fe::from_bytes(&yb);

        // x² = (y² − 1) / (d·y² + 1) = u / v.
        let yy = self.sq(y);
        let u = self.sub(yy, self.one);
        let v = self.add(self.mul(self.d, yy), self.one);

        // x = sqrt(u/v) via the shared sqrt-ratio routine. `was_square` is
        // false exactly when neither v·x² == u nor v·x² == −u, i.e. the point
        // is not on the curve.
        let (was_square, mut x) = self.sqrt_ratio_i(u, v);
        if !bool::from(was_square) {
            return None;
        }

        if bool::from(x.is_zero()) && sign == 1 {
            return None;
        }
        if x.is_negative().unwrap_u8() != sign {
            x = self.neg(x);
        }

        let t = self.mul(x, y);
        Some(Point {
            x,
            y,
            z: self.one,
            t,
        })
    }

    /// Compresses a point to its 32-byte encoding.
    pub(crate) fn encode(&self, p: &Point) -> [u8; 32] {
        let zinv = self.inv(p.z);
        let x = self.mul(p.x, zinv);
        let y = self.mul(p.y, zinv);
        let mut out = y.to_bytes();
        out[31] |= x.is_negative().unwrap_u8() << 7;
        out
    }

    /// The affine coordinates `(x, y) = (X/Z, Y/Z)` of `p`, each written as a
    /// 32-byte little-endian canonical encoding of a residue in `[0, p)`.
    ///
    /// Unlike [`encode`](Self::encode) this returns the full `x` coordinate
    /// rather than folding its sign into a bit of `y`. Group points always have
    /// an invertible `Z`, so the inversion is well defined (the identity is
    /// `(0:1:1:0)`, giving affine `(0, 1)`).
    // Used by the edwards25519::hazmat affine-coordinate accessors; gate to the
    // same features as that surface to avoid a dead-code warning on the default
    // (Ed25519-only) build.
    #[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
    pub(crate) fn to_affine_bytes(&self, p: &Point) -> ([u8; 32], [u8; 32]) {
        let zinv = self.inv(p.z);
        let x = self.mul(p.x, zinv);
        let y = self.mul(p.y, zinv);
        (x.to_bytes(), y.to_bytes())
    }

    /// The Montgomery `u`-coordinate of the birationally equivalent
    /// curve25519 point, `u = (1 + y)/(1 − y) = (Z + Y)/(Z − Y)`, as its
    /// canonical 32-byte little-endian encoding (RFC 7748 §4.1).
    ///
    /// The identity has `Z == Y`; the inversion of `0` is `0`, so it maps to
    /// `u = 0` (as do the other points the map sends to infinity). Callers
    /// that must refuse such inputs (libsodium's `pk_to_curve25519`) reject
    /// small-order points first. Constant-time.
    pub(crate) fn to_montgomery_u(&self, p: &Point) -> [u8; 32] {
        let num = self.add(p.z, p.y);
        let den = self.sub(p.z, p.y);
        self.mul(num, self.inv(den)).to_bytes()
    }

    /// The neutral element `(0:1:1:0)`.
    pub(crate) fn identity(&self) -> Point {
        Point {
            x: Fe::ZERO,
            y: self.one,
            z: self.one,
            t: Fe::ZERO,
        }
    }

    /// Point addition (add-2008-hwcd-3), complete for `a = −1` since `d` is a
    /// non-square on edwards25519.
    pub(crate) fn point_add(&self, p: &Point, q: &Point) -> Point {
        let aa = self.mul(self.sub(p.y, p.x), self.sub(q.y, q.x));
        let bb = self.mul(self.add(p.y, p.x), self.add(q.y, q.x));
        let cc = self.mul(self.mul(p.t, self.d2), q.t);
        let dd = self.mul(self.add(p.z, p.z), q.z);
        let e = self.sub(bb, aa);
        let ff = self.sub(dd, cc);
        let g = self.add(dd, cc);
        let h = self.add(bb, aa);
        Point {
            x: self.mul(e, ff),
            y: self.mul(g, h),
            t: self.mul(e, h),
            z: self.mul(ff, g),
        }
    }

    /// Point doubling (dbl-2008-hwcd) for `a = −1`.
    pub(crate) fn point_double(&self, p: &Point) -> Point {
        let a = self.sq(p.x);
        let b = self.sq(p.y);
        let zz = self.sq(p.z);
        let c = self.add(zz, zz);
        let d = self.neg(a);
        let e = self.sub(self.sub(self.sq(self.add(p.x, p.y)), a), b);
        let g = self.add(d, b);
        let ff = self.sub(g, c);
        let h = self.sub(d, b);
        Point {
            x: self.mul(e, ff),
            y: self.mul(g, h),
            t: self.mul(e, h),
            z: self.mul(ff, g),
        }
    }

    /// Negates a point: `−(X:Y:Z:T) = (−X:Y:Z:−T)`.
    pub(crate) fn point_negate(&self, p: &Point) -> Point {
        Point {
            x: self.neg(p.x),
            y: p.y,
            z: p.z,
            t: self.neg(p.t),
        }
    }

    /// Constant-time `[scalar]·p` over the 256-bit little-endian scalar, via
    /// a fixed signed 4-bit window ([`radix16_signed`], digits in `[−8, 8)`
    /// plus a carry digit in `{0, 1}` that seeds the accumulator): 4
    /// doublings and one *unconditional* addition per digit, with the
    /// operand fetched by a masked scan of the 8 table entries `[1]P..[8]P`
    /// (one barriered equality mask each, no secret-indexed memory access)
    /// followed by a masked negation (one barriered mask). A zero digit adds
    /// the identity — a no-op with the same operation sequence, since the
    /// HWCD formulas are complete — so the schedule depends only on the
    /// (public) scalar width. The scalar bytes and digits are treated as
    /// secret (the digits are wiped).
    // Ed25519 verification moved to the vartime path (its inputs are public),
    // so on the default build this constant-time generic multiplication only
    // backs the test-side differential oracles; the hazmat/ristretto group
    // APIs (secret scalars) and the table-free `mul_base` are its library
    // users. Gate accordingly to keep the default build free of dead code.
    #[cfg(any(
        test,
        feature = "hazmat-edwards25519",
        feature = "ristretto255",
        not(feature = "ed25519-table")
    ))]
    pub(crate) fn scalar_mult(&self, scalar: &[u8; 32], p: &Point) -> Point {
        // table[j] = [j + 1]P.
        let mut table = [*p; 8];
        for i in 1..8 {
            table[i] = self.point_add(&table[i - 1], p);
        }

        let mut digits = radix16_signed(scalar);
        // The carry digit (bit 256 of the recoding) seeds the accumulator
        // with [d₆₄]P ∈ {O, P}, selected by one barriered mask.
        let mut acc = point_select(p, &self.identity(), mask_from_bit(digits[64] as u64));
        for &d in digits[..64].iter().rev() {
            acc = self.point_double(&acc);
            acc = self.point_double(&acc);
            acc = self.point_double(&acc);
            acc = self.point_double(&acc);

            // `smask` is 0xff iff d < 0; `mag` = |d| ∈ 0..=8, branch-free.
            let smask = (d >> 7) as u8;
            let mag = ((d as u8) ^ smask).wrapping_sub(smask) as u64;
            // Constant-time gather of table[mag − 1]: one barriered equality
            // mask per entry (`eq_mask`, never `==`), applied across all
            // four coordinates, so the secret digit never feeds a
            // compare-and-branch the compiler could emit; mag = 0 keeps the
            // identity.
            let mut sel = self.identity();
            for (j, entry) in table.iter().enumerate() {
                sel = point_select(entry, &sel, eq_mask(j as u64 + 1, mag));
            }
            // Masked negation: −(X:Y:Z:T) = (−X:Y:Z:−T).
            let neg = mask_from_bit((smask & 1) as u64);
            sel.x = Fe::select(&sel.x.neg(), &sel.x, neg);
            sel.t = Fe::select(&sel.t.neg(), &sel.t, neg);
            acc = self.point_add(&acc, &sel);
        }
        digits.zeroize();
        acc
    }

    /// Mixed addition `p + n` of an extended point and an affine Niels point
    /// (add-2008-hwcd-3 with `Z₂ = 1` and the Niels values precomputed):
    /// 7 multiplications instead of the 9 of [`Self::point_add`]. Complete
    /// for `a = −1` like the full formula, so adding the identity Niels
    /// `(1, 1, 0)` is a uniform no-op.
    #[cfg(feature = "ed25519-table")]
    #[inline]
    pub(crate) fn add_niels(&self, p: &Point, n: &Niels) -> Point {
        let pp = self.mul(self.add(p.y, p.x), n.ypx);
        let mm = self.mul(self.sub(p.y, p.x), n.ymx);
        let tt = self.mul(p.t, n.t2d);
        let zz2 = self.add(p.z, p.z);
        let e = self.sub(pp, mm);
        let h = self.add(pp, mm);
        let ff = self.sub(zz2, tt);
        let g = self.add(zz2, tt);
        Point {
            x: self.mul(e, ff),
            y: self.mul(g, h),
            t: self.mul(e, h),
            z: self.mul(ff, g),
        }
    }

    /// Constant-time fixed-base multiplication `[scalar]·B` via the
    /// precomputed signed radix-16 table [`ED25519_BASE_TABLE`]:
    /// `[k]B = Σᵢ [dᵢ · 16^i]B + [d₆₄ · 2^256]B` over the signed digits
    /// `dᵢ ∈ [−8, 8)` of the little-endian scalar ([`radix16_signed`]), so
    /// there are **no doublings** — 65 unconditional mixed additions, each
    /// operand fetched by [`Niels::gather`] (a masked scan of the window's 8
    /// stored points plus a masked negation; no secret-indexed memory
    /// access). A zero digit adds the identity, a uniform no-op under the
    /// complete formulas, so the schedule depends only on the (public)
    /// scalar width. Any 256-bit scalar is consumed exactly (the recoding
    /// carry is the 65th digit). The scalar bytes are treated as secret.
    #[cfg(feature = "ed25519-table")]
    pub(crate) fn mul_base(&self, scalar: &[u8; 32]) -> Point {
        let mut digits = radix16_signed(scalar);
        let mut acc = self.identity();
        for (window, &d) in ED25519_BASE_TABLE.iter().zip(digits.iter()) {
            acc = self.add_niels(&acc, &Niels::gather(window, d));
        }
        // The carry digit selects [2^256]B or the identity.
        let top = Niels::select(
            &Niels::from_entry(&ED25519_BASE_2_256),
            &Niels::IDENTITY,
            mask_from_bit(digits[64] as u64),
        );
        acc = self.add_niels(&acc, &top);
        digits.zeroize();
        acc
    }

    /// Constant-time fixed-base multiplication `[scalar]·B` without the comb
    /// table (feature `ed25519-table` off): the generic windowed ladder
    /// [`Self::scalar_mult`] over `B`. Same result and the same secret-scalar
    /// discipline, at the cost of ~252 doublings the table would avoid.
    #[cfg(not(feature = "ed25519-table"))]
    pub(crate) fn mul_base(&self, scalar: &[u8; 32]) -> Point {
        self.scalar_mult(scalar, &self.base())
    }

    /// **Variable-time** `[scalar]·p` via a width-5 wNAF ladder: ~254
    /// doublings plus one addition per nonzero digit (≈ 1 in 6), against a
    /// table of the 8 odd multiples `[1]P..[15]P`.
    ///
    /// # Warning: public inputs only
    ///
    /// Both the branch pattern and the table indices leak the scalar. This
    /// must ONLY ever be called with **public** scalars and points (e.g. the
    /// challenge scalar `k` and public key `A` during Ed25519 verification).
    // Ed25519 verification goes through the interleaved
    // `double_scalar_mult_base_vartime`; this single-scalar ladder is kept
    // as a test oracle.
    #[cfg(test)]
    pub(crate) fn scalar_mult_vartime(&self, scalar: &[u8; 32], p: &Point) -> Point {
        let odd = self.odd_multiples(p);
        let naf = wnaf(scalar, 5);
        let Some(top) = naf.iter().rposition(|&d| d != 0) else {
            return self.identity();
        };

        let mut acc = self.identity();
        for i in (0..=top).rev() {
            acc = self.point_double(&acc);
            acc = self.add_naf_digit(&acc, naf[i], &odd);
        }
        acc
    }

    /// **Variable-time** `[a]·p + [b]·B`, the Ed25519 verification
    /// combination: both wNAF ladders interleaved (Straus) so they share one
    /// run of ~254 doublings. The variable point uses width 5 against its 8
    /// odd multiples computed on the fly; the base point uses width 8
    /// against the static Niels table [`ED25519_BASE_ODD`] (`[1]B, [3]B, …,
    /// [127]B`, feature `ed25519-table`; ≈ 1 mixed addition per 9 bits) or,
    /// without the table, width 5 against odd multiples of `B` computed on
    /// the fly.
    ///
    /// # Warning: public inputs only
    ///
    /// Both the branch pattern and the table indices leak the scalars. This
    /// must ONLY ever be called with **public** scalars and points.
    pub(crate) fn double_scalar_mult_base_vartime(
        &self,
        a: &[u8; 32],
        p: &Point,
        b: &[u8; 32],
    ) -> Point {
        let odd_p = self.odd_multiples(p);
        let naf_a = wnaf(a, 5);
        #[cfg(feature = "ed25519-table")]
        let naf_b = wnaf(b, 8);
        #[cfg(not(feature = "ed25519-table"))]
        let naf_b = wnaf(b, 5);
        #[cfg(not(feature = "ed25519-table"))]
        let odd_b = self.odd_multiples(&self.base());
        let Some(top) = naf_a
            .iter()
            .zip(naf_b.iter())
            .rposition(|(&x, &y)| x != 0 || y != 0)
        else {
            return self.identity();
        };

        let mut acc = self.identity();
        for i in (0..=top).rev() {
            acc = self.point_double(&acc);
            acc = self.add_naf_digit(&acc, naf_a[i], &odd_p);
            #[cfg(feature = "ed25519-table")]
            {
                let d = naf_b[i];
                if d > 0 {
                    acc =
                        self.add_niels(&acc, &Niels::from_entry(&ED25519_BASE_ODD[d as usize / 2]));
                } else if d < 0 {
                    let n = Niels::from_entry(&ED25519_BASE_ODD[(-d) as usize / 2]);
                    acc = self.add_niels(&acc, &n.negate());
                }
            }
            #[cfg(not(feature = "ed25519-table"))]
            {
                acc = self.add_naf_digit(&acc, naf_b[i], &odd_b);
            }
        }
        acc
    }

    /// The odd multiples `odd[i] = [2i+1]P` for `i in 0..8`, the lookup table
    /// of the width-5 wNAF ladders.
    fn odd_multiples(&self, p: &Point) -> [Point; 8] {
        let p2 = self.point_double(p);
        let mut odd = [*p; 8];
        for i in 1..8 {
            odd[i] = self.point_add(&odd[i - 1], &p2);
        }
        odd
    }

    /// Adds the wNAF digit `d` (odd, `|d| <= 15`, or zero for a no-op) times
    /// the point whose odd multiples are `odd`. **Variable-time.**
    #[inline]
    fn add_naf_digit(&self, acc: &Point, d: i8, odd: &[Point; 8]) -> Point {
        if d > 0 {
            self.point_add(acc, &odd[(d as usize) / 2])
        } else if d < 0 {
            self.point_add(acc, &self.point_negate(&odd[(-d as usize) / 2]))
        } else {
            *acc
        }
    }

    /// Constant-time equality of two points, comparing the affine
    /// representatives via cross-multiplication (so distinct projective
    /// representatives of the same point compare equal): `X₁·Z₂ == X₂·Z₁` and
    /// `Y₁·Z₂ == Y₂·Z₁`. Inversion-free.
    pub(crate) fn point_ct_eq(&self, p: &Point, q: &Point) -> Choice {
        let x1z2 = self.mul(p.x, q.z);
        let x2z1 = self.mul(q.x, p.z);
        let y1z2 = self.mul(p.y, q.z);
        let y2z1 = self.mul(q.y, p.z);
        self.ct_eq(x1z2, x2z1) & self.ct_eq(y1z2, y2z1)
    }
}

/// Width-`w` non-adjacent form (`w ∈ {5, 8}`) of a 256-bit little-endian
/// scalar: odd digits in `(−2^(w−1), 2^(w−1))` with at least `w − 1` zeros
/// between nonzero digits. The extra trailing positions absorb the recoding
/// carry of scalars close to `2^256` (the last window may start at bit 255
/// and the carry lands up to `w` positions later), so any 256-bit integer
/// is represented exactly. **Variable-time**; only for public scalars.
fn wnaf(scalar: &[u8; 32], w: u32) -> [i8; 264] {
    debug_assert!(w == 5 || w == 8);
    let mut naf = [0i8; 264];

    // Five u64 limbs so the window read below may index one limb past the
    // scalar's 256 bits.
    let mut x = [0u64; 5];
    for (i, limb) in x.iter_mut().take(4).enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&scalar[i * 8..i * 8 + 8]);
        *limb = u64::from_le_bytes(b);
    }

    let width = 1u64 << w;
    let window_mask = width - 1;
    let w = w as usize;

    let mut pos = 0;
    let mut carry = 0u64;
    while pos < 256 {
        let idx = pos / 64;
        let bit = pos % 64;
        let bit_buf = if bit < 64 - w {
            x[idx] >> bit
        } else {
            (x[idx] >> bit) | (x[idx + 1] << (64 - bit))
        };
        let window = carry + (bit_buf & window_mask);
        if window & 1 == 0 {
            pos += 1;
            continue;
        }
        if window < width / 2 {
            carry = 0;
            naf[pos] = window as i8;
        } else {
            carry = 1;
            naf[pos] = (window as i8).wrapping_sub(width as i8);
        }
        pos += w;
    }
    // A carry surviving past bit 255 stands for `+2^pos`; record it (pos is
    // at most 263, and the digit is always +1).
    if carry != 0 {
        naf[pos] = 1;
    }
    naf
}

/// Constant-time point selection: `a` when `mask` is all-ones, `b` when it
/// is zero. The mask comes from `field::eq_mask` / `field::mask_from_bit`
/// (one barrier per selection) and is applied limbwise to all four
/// coordinates.
// Only the constant-time `scalar_mult` gathers whole points; same gate.
#[cfg(any(
    test,
    feature = "hazmat-edwards25519",
    feature = "ristretto255",
    not(feature = "ed25519-table")
))]
#[inline]
pub(crate) fn point_select(a: &Point, b: &Point, mask: u64) -> Point {
    Point {
        x: Fe::select(&a.x, &b.x, mask),
        y: Fe::select(&a.y, &b.y, mask),
        z: Fe::select(&a.z, &b.z, mask),
        t: Fe::select(&a.t, &b.t, mask),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::Uint;

    /// Re-derives every entry of the embedded fixed-base tables from the
    /// group law and cross-checks the constants, so `ED25519_BASE_TABLE` and
    /// `ED25519_BASE_2_256` are verified on every test run rather than
    /// trusted. The check is inversion-free: the stored Niels values match
    /// the computed extended `(X : Y : Z : T)` iff `(y+x)·Z == Y + X`,
    /// `(y−x)·Z == Y − X` and `(2dt)·Z² == 2d·X·Y`; every stored limb must
    /// also be a canonical 51-bit limb.
    #[test]
    #[cfg(feature = "ed25519-table")]
    fn base_table_matches_computed() {
        let f = Field::new();
        let check = |entry: &[u64; 15], acc: &Point| {
            assert!(entry.iter().all(|&l| l < (1u64 << 51)), "limb not 51-bit");
            let n = Niels::from_entry(entry);
            let zz = f.sq(acc.z);
            assert!(
                bool::from(f.ct_eq(f.mul(n.ypx, acc.z), f.add(acc.y, acc.x))),
                "y+x mismatch"
            );
            assert!(
                bool::from(f.ct_eq(f.mul(n.ymx, acc.z), f.sub(acc.y, acc.x))),
                "y−x mismatch"
            );
            assert!(
                bool::from(f.ct_eq(f.mul(n.t2d, zz), f.mul(f.d2, f.mul(acc.x, acc.y)))),
                "2dt mismatch"
            );
            // Canonical: the limbs round-trip through the encoding.
            for v in [n.ypx, n.ymx, n.t2d] {
                assert_eq!(Fe::from_bytes(&v.to_bytes()).0, v.0, "non-canonical entry");
            }
        };
        let mut base = f.base();
        for window in ED25519_BASE_TABLE.iter() {
            let mut acc = base;
            for (j, entry) in window.iter().enumerate() {
                if j > 0 {
                    acc = f.point_add(&acc, &base);
                }
                check(entry, &acc);
            }
            base = f.point_double(&f.point_double(&f.point_double(&f.point_double(&base))));
        }
        // After 64 windows `base` is [16^64]B = [2^256]B.
        check(&ED25519_BASE_2_256, &base);
        // The wNAF-8 table: [1]B, [3]B, …, [127]B.
        let b = f.base();
        let b2 = f.point_double(&b);
        let mut acc = b;
        for (i, entry) in ED25519_BASE_ODD.iter().enumerate() {
            if i > 0 {
                acc = f.point_add(&acc, &b2);
            }
            check(entry, &acc);
        }
    }

    /// The width-5 and width-8 wNAF recodings reproduce every scalar exactly
    /// (odd digits within range, enough zeros between them), on edge and
    /// random scalars.
    #[test]
    fn wnaf_round_trips() {
        use crate::hash::Sha256;
        use crate::rng::{HmacDrbg, RngCore};
        let check = |s: &[u8; 32], w: u32| {
            let naf = wnaf(s, w);
            let half = 1i16 << (w - 1);
            let mut last_nonzero: Option<usize> = None;
            let mut acc = Uint::<5>::ZERO;
            for (i, &d) in naf.iter().enumerate().rev() {
                acc = acc.wrapping_add(&acc);
                if d != 0 {
                    assert!(d % 2 != 0 && (d as i16).abs() < half, "digit {d} at {i}");
                    if let Some(n) = last_nonzero {
                        assert!(n - i >= w as usize, "digits too close at {i}, {n}");
                    }
                    last_nonzero = Some(i);
                    if d > 0 {
                        acc = acc.wrapping_add(&Uint::<5>::from_u64(d as u64));
                    } else {
                        acc = acc.wrapping_sub(&Uint::<5>::from_u64((-d) as u64));
                    }
                }
            }
            let mut want = [0u8; 40];
            want[..32].copy_from_slice(s);
            assert_eq!(acc, Uint::<5>::from_le_bytes(&want), "wnaf{w} of {s:02x?}");
        };
        let mut rng = HmacDrbg::<Sha256>::new(b"wnaf-roundtrip", b"nonce", &[]);
        for w in [5u32, 8] {
            for s in [
                [0u8; 32],
                [0xffu8; 32],
                [0x80u8; 32],
                [0x7fu8; 32],
                [1u8; 32],
            ] {
                check(&s, w);
            }
            for _ in 0..200 {
                let mut s = [0u8; 32];
                rng.fill_bytes(&mut s);
                check(&s, w);
            }
        }
    }

    /// The signed recoding reproduces every scalar exactly, with digits in
    /// `[−8, 8)` and the carry digit in `{0, 1}` — on the edge scalars and
    /// random ones.
    #[test]
    fn radix16_signed_round_trips() {
        use crate::hash::Sha256;
        use crate::rng::{HmacDrbg, RngCore};
        let check = |s: &[u8; 32]| {
            let d = radix16_signed(s);
            assert!(d[..64].iter().all(|&x| (-8..8).contains(&x)));
            assert!(d[64] == 0 || d[64] == 1);
            // Σ d[i]·16^i as a 264-bit little-endian integer, built from the
            // top digit down (Horner), must equal the scalar.
            let mut acc = Uint::<5>::ZERO;
            for &x in d.iter().rev() {
                // acc = acc·16 + x (x may be negative: add 16 then subtract).
                let sixteen = Uint::<5>::from_u64(16);
                let (lo, _) = acc.mul_wide(&sixteen);
                acc = lo;
                if x >= 0 {
                    acc = acc.wrapping_add(&Uint::<5>::from_u64(x as u64));
                } else {
                    acc = acc.wrapping_sub(&Uint::<5>::from_u64((-x) as u64));
                }
            }
            let mut want = [0u8; 40];
            want[..32].copy_from_slice(s);
            assert_eq!(acc, Uint::<5>::from_le_bytes(&want), "recoding of {s:02x?}");
        };
        check(&[0u8; 32]);
        check(&[0xffu8; 32]);
        check(&[0x80u8; 32]);
        check(&[0x88u8; 32]);
        check(&[0x78u8; 32]);
        let mut rng = HmacDrbg::<Sha256>::new(b"radix16-signed", b"nonce", &[]);
        for _ in 0..200 {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            check(&s);
        }
    }

    /// The hard-coded affine base point is the RFC 8032 `B`, with `t = x·y`.
    #[test]
    fn base_affine_matches_encoding() {
        let f = Field::new();
        let b = f.base();
        let dec = f
            .decode(&super::super::field::BASE_ENC)
            .expect("valid base");
        assert!(bool::from(f.point_ct_eq(&b, &dec)));
        assert!(bool::from(f.ct_eq(f.mul(b.x, b.y), b.t)));
        assert_eq!(f.encode(&b), super::super::field::BASE_ENC);
    }

    /// Differential test: the fixed-base comb agrees with the generic
    /// windowed ladder for edge scalars (0, 1, 2, L−1, L, L+1, 2²⁵⁵-ish,
    /// all-ones) and a batch of random ones — and the vartime paths agree
    /// with their constant-time counterparts on every one of them.
    #[test]
    fn mul_base_matches_generic_scalar_mult() {
        use crate::hash::Sha256;
        use crate::rng::{HmacDrbg, RngCore};
        let f = Field::new();
        let b = f.base();
        // An independent point for the double-scalar check.
        let p = f.scalar_mult(&[7u8; 32], &b);

        let check = |s: &[u8; 32]| {
            let comb = f.encode(&f.mul_base(s));
            assert_eq!(
                comb,
                f.encode(&f.scalar_mult(s, &b)),
                "comb/ladder mismatch"
            );
            assert_eq!(
                comb,
                f.encode(&f.scalar_mult_vartime(s, &b)),
                "vartime wNAF mismatch"
            );
            assert_eq!(
                comb,
                f.encode(&f.double_scalar_mult_base_vartime(&[0u8; 32], &p, s)),
                "vartime double-scalar [0]P + [s]B mismatch"
            );
            // [s]P + [s']B against the constant-time ladders, with s' = s
            // byte-reversed so the two digit streams differ.
            let mut s2 = *s;
            s2.reverse();
            let want = f.point_add(&f.scalar_mult(s, &p), &f.mul_base(&s2));
            assert_eq!(
                f.encode(&want),
                f.encode(&f.double_scalar_mult_base_vartime(s, &p, &s2)),
                "vartime double-scalar mismatch"
            );
        };

        let int_bytes = |v: &ScalarInt| {
            let mut out = [0u8; 32];
            v.write_le_bytes(&mut out);
            out
        };
        let mut edges = [[0u8; 32]; 8];
        edges[1][0] = 1;
        edges[2][0] = 2;
        edges[3] = int_bytes(&f.l.wrapping_sub(&ScalarInt::ONE));
        edges[4] = int_bytes(&f.l);
        edges[5] = int_bytes(&f.l.wrapping_add(&ScalarInt::ONE));
        edges[6][31] = 0x80;
        edges[7] = [0xff; 32];
        for s in &edges {
            check(s);
        }

        let mut rng = HmacDrbg::<Sha256>::new(b"ed25519-comb-differential", b"nonce", &[]);
        for _ in 0..32 {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            check(&s);
        }
    }

    /// Regenerates the fixed-base table source
    /// (`src/ec/curve25519/base_table.rs`). Run with:
    /// `cargo test --release gen_ed25519_base_table -- --ignored --nocapture`,
    /// paste the emitted `static`s between the file's header comment and
    /// EOF, and run `cargo fmt`. The non-ignored `base_table_matches_computed`
    /// test keeps the pasted constants honest on every test run.
    #[test]
    #[ignore = "table generator; emits Rust source on stdout"]
    #[cfg(feature = "std")]
    fn gen_ed25519_base_table() {
        use std::{print, println};
        let f = Field::new();
        // Affine Niels (y+x, y−x, 2d·x·y) as canonical plain residues,
        // printed as 51-bit limbs (fully reduced via the to/from bytes
        // round-trip).
        let niels = |p: &Point| -> [u64; 15] {
            let zinv = f.inv(p.z);
            let x = Fe::from_bytes(&f.mul(p.x, zinv).to_bytes());
            let y = Fe::from_bytes(&f.mul(p.y, zinv).to_bytes());
            let ypx = Fe::from_bytes(&f.add(y, x).to_bytes());
            let ymx = Fe::from_bytes(&f.sub(y, x).to_bytes());
            let t2d = Fe::from_bytes(&f.mul(f.mul(x, y), f.d2).to_bytes());
            let mut out = [0u64; 15];
            out[..5].copy_from_slice(&ypx.0);
            out[5..10].copy_from_slice(&ymx.0);
            out[10..].copy_from_slice(&t2d.0);
            out
        };
        let print_entry = |e: &[u64; 15]| {
            print!("        [");
            for l in e {
                print!("0x{l:013x}, ");
            }
            println!("],");
        };
        // base = [16^i]B for the current window i.
        let mut base = f.base();
        println!("pub(crate) static ED25519_BASE_TABLE: [[[u64; 15]; 8]; 64] = [");
        for _ in 0..64 {
            println!("    [");
            let mut acc = base;
            for j in 1..=8u32 {
                if j > 1 {
                    acc = f.point_add(&acc, &base);
                }
                print_entry(&niels(&acc));
            }
            println!("    ],");
            base = f.point_double(&f.point_double(&f.point_double(&f.point_double(&base))));
        }
        println!("];");
        println!();
        // base is now [16^64]B = [2^256]B.
        println!("pub(crate) static ED25519_BASE_2_256: [u64; 15] = [");
        print!("    ");
        for l in &niels(&base) {
            print!("0x{l:013x}, ");
        }
        println!();
        println!("];");
        println!();
        // [1]B, [3]B, …, [127]B for the wNAF-8 verification ladder.
        println!("pub(crate) static ED25519_BASE_ODD: [[u64; 15]; 64] = [");
        let b = f.base();
        let b2 = f.point_double(&b);
        let mut acc = b;
        for i in 0..64 {
            if i > 0 {
                acc = f.point_add(&acc, &b2);
            }
            print!("    [");
            for l in &niels(&acc) {
                print!("0x{l:013x}, ");
            }
            println!("],");
        }
        println!("];");
    }
}
