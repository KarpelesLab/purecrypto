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

/// A projective point `(X:Y:Z)` (`x = X/Z`, `y = Y/Z`): an extended point
/// with `T` dropped, the input of a doubling. Coordinates are reduced
/// multiplier outputs (limbs `< 2^51 + 2^13`).
#[derive(Clone, Copy)]
pub(crate) struct Projective {
    x: Fe,
    y: Fe,
    z: Fe,
}

/// A "completed" point `((X:Z), (Y:T))` (`x = X/Z`, `y = Y/T`), the raw
/// output of the HWCD addition and doubling formulas before the final
/// multiplications. Its coordinates are **lazy** — sums and differences
/// that skipped the carry pass (limbs `< 2^54`, see [`Fe::add_lazy`]) — and
/// they are only ever consumed as multiplier inputs by
/// [`Self::to_extended`] (4M) or [`Self::to_projective`] (3M), so a run of
/// doublings never computes the `T` it would throw away.
#[derive(Clone, Copy)]
pub(crate) struct Completed {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// An extended point in **cached** form `(Y + X, Y − X, 2·Z, 2·d·T)`: the
/// four values the addition [`add_cached`] multiplies by, so a table entry
/// costs 8 multiplications per addition instead of 9. The identity is
/// `(1, 1, 2, 0)`; negation swaps the first two values and negates the
/// last. `Y ± X` and `2·Z` are lazy (limbs `< 2^53`, multiplier inputs only).
#[derive(Clone, Copy)]
pub(crate) struct Cached {
    ypx: Fe,
    ymx: Fe,
    z2: Fe,
    t2d: Fe,
}

impl Point {
    /// Drops `T`.
    #[inline(always)]
    fn to_projective(self) -> Projective {
        Projective {
            x: self.x,
            y: self.y,
            z: self.z,
        }
    }

    /// The cached form `(Y + X, Y − X, 2·Z, 2·d·T)`: one multiplication.
    #[inline(always)]
    fn to_cached(self) -> Cached {
        Cached {
            ypx: self.y.add_lazy(&self.x),
            ymx: self.y.sub_lazy(&self.x),
            z2: self.z.add_lazy(&self.z),
            t2d: self.t.mul(&Fe::D2),
        }
    }
}

impl Projective {
    /// The neutral element `(0:1:1)`.
    const IDENTITY: Projective = Projective {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
    };

    /// dbl-2008-hwcd for `a = −1`, stopping at the completed point: 4
    /// squarings, every sum and difference lazy.
    ///
    /// Bounds (inputs reduced, `< 2^51 + 2^13`): `YY + XX` and `2·ZZ` are
    /// `< 2^52 + 2^14`; `YY − XX` (2p bias) is `< 2^53`; the two outer
    /// differences take the 4p bias of [`Fe::sub_lazy_wide`] (their
    /// subtrahends are `< 2^53 − 76`) and stay `< 2^54`.
    #[inline(always)]
    fn double(&self) -> Completed {
        let xx = self.x.sq();
        let yy = self.y.sq();
        let zz = self.z.sq();
        let zz2 = zz.add_lazy(&zz);
        let xpy2 = self.x.add_lazy(&self.y).sq();
        let yy_plus_xx = yy.add_lazy(&xx);
        let yy_minus_xx = yy.sub_lazy(&xx);
        Completed {
            x: xpy2.sub_lazy_wide(&yy_plus_xx),
            y: yy_plus_xx,
            z: yy_minus_xx,
            t: zz2.sub_lazy_wide(&yy_minus_xx),
        }
    }
}

impl Completed {
    /// The neutral element as a completed point `((0:1), (1:1))`.
    const IDENTITY: Completed = Completed {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ONE,
    };

    /// `(X·T : Y·Z : Z·T : X·Y)`: 4 multiplications, reduced output.
    #[inline(always)]
    fn to_extended(self) -> Point {
        Point {
            x: self.x.mul(&self.t),
            y: self.y.mul(&self.z),
            z: self.z.mul(&self.t),
            t: self.x.mul(&self.y),
        }
    }

    /// `(X·T : Y·Z : Z·T)`: 3 multiplications, reduced output.
    #[inline(always)]
    fn to_projective(self) -> Projective {
        Projective {
            x: self.x.mul(&self.t),
            y: self.y.mul(&self.z),
            z: self.z.mul(&self.t),
        }
    }
}

impl Cached {
    /// The neutral element `(1, 1, 2, 0)`.
    #[cfg(any(
        test,
        feature = "hazmat-edwards25519",
        feature = "ristretto255",
        not(feature = "ed25519-table")
    ))]
    const IDENTITY: Cached = Cached {
        ypx: Fe::ONE,
        ymx: Fe::ONE,
        z2: Fe([2, 0, 0, 0, 0]),
        t2d: Fe::ZERO,
    };

    /// `a` when `mask` is all-ones, `b` when it is zero (same mask contract
    /// as [`Fe::select`]).
    #[cfg(any(
        test,
        feature = "hazmat-edwards25519",
        feature = "ristretto255",
        not(feature = "ed25519-table")
    ))]
    #[inline(always)]
    fn select(a: &Cached, b: &Cached, mask: u64) -> Cached {
        Cached {
            ypx: Fe::select(&a.ypx, &b.ypx, mask),
            ymx: Fe::select(&a.ymx, &b.ymx, mask),
            z2: Fe::select(&a.z2, &b.z2, mask),
            t2d: Fe::select(&a.t2d, &b.t2d, mask),
        }
    }

    /// Negates in place when `mask` is all-ones (swap `Y+X`/`Y−X`, negate
    /// `2dT`), leaves it when zero. Same mask contract as [`Fe::select`].
    #[cfg(any(
        test,
        feature = "hazmat-edwards25519",
        feature = "ristretto255",
        not(feature = "ed25519-table")
    ))]
    #[inline(always)]
    fn conditional_negate(&mut self, mask: u64) {
        Fe::cswap(&mut self.ypx, &mut self.ymx, mask);
        self.t2d = Fe::select(&self.t2d.neg(), &self.t2d, mask);
    }

    /// Wipes the limbs (table entries of a secret-scalar multiplication).
    #[cfg(any(
        test,
        feature = "hazmat-edwards25519",
        feature = "ristretto255",
        not(feature = "ed25519-table")
    ))]
    fn zeroize(&mut self) {
        self.ypx.zeroize();
        self.ymx.zeroize();
        self.z2.zeroize();
        self.t2d.zeroize();
    }
}

/// add-2008-hwcd-3 against a cached point, stopping at the completed point:
/// 4 multiplications (`(Y₁+X₁)(Y₂+X₂)`, `(Y₁−X₁)(Y₂−X₂)`, `T₁·2dT₂`,
/// `Z₁·2Z₂`). Complete for `a = −1`. The extended input is reduced; the
/// outputs are lazy sums/differences of reduced products (limbs `< 2^53`).
#[inline(always)]
fn add_cached(p: &Point, q: &Cached) -> Completed {
    let pp = p.y.add_lazy(&p.x).mul(&q.ypx);
    let mm = p.y.sub_lazy(&p.x).mul(&q.ymx);
    let tt = p.t.mul(&q.t2d);
    let zz = p.z.mul(&q.z2);
    Completed {
        x: pp.sub_lazy(&mm),
        y: pp.add_lazy(&mm),
        z: zz.add_lazy(&tt),
        t: zz.sub_lazy(&tt),
    }
}

/// `p − q` for a cached `q` (the formula of [`add_cached`] with `q`
/// negated: `Y+X`/`Y−X` exchanged and `2dT` negated, folded into the sign
/// pattern). **Variable-time callers only** pick between this and
/// [`add_cached`]; the formula itself is branch-free.
#[inline(always)]
fn sub_cached(p: &Point, q: &Cached) -> Completed {
    let pp = p.y.add_lazy(&p.x).mul(&q.ymx);
    let mm = p.y.sub_lazy(&p.x).mul(&q.ypx);
    let tt = p.t.mul(&q.t2d);
    let zz = p.z.mul(&q.z2);
    Completed {
        x: pp.sub_lazy(&mm),
        y: pp.add_lazy(&mm),
        z: zz.sub_lazy(&tt),
        t: zz.add_lazy(&tt),
    }
}

/// Mixed addition against an affine Niels point (`Z₂ = 1`): 3
/// multiplications to the completed point. Same lazy-output bounds as
/// [`add_cached`].
#[cfg(feature = "ed25519-table")]
#[inline(always)]
fn add_niels_completed(p: &Point, n: &Niels) -> Completed {
    let pp = p.y.add_lazy(&p.x).mul(&n.ypx);
    let mm = p.y.sub_lazy(&p.x).mul(&n.ymx);
    let tt = p.t.mul(&n.t2d);
    let zz2 = p.z.add_lazy(&p.z);
    Completed {
        x: pp.sub_lazy(&mm),
        y: pp.add_lazy(&mm),
        z: zz2.add_lazy(&tt),
        t: zz2.sub_lazy(&tt),
    }
}

/// The odd multiples `[1]P, [3]P, …, [15]P` in cached form, the lookup
/// table of the width-5 wNAF ladders. **Public points only** (no wiping).
fn odd_multiples(p: &Point) -> [Cached; 8] {
    let p2 = p.to_projective().double().to_extended().to_cached();
    let mut odd = [p.to_cached(); 8];
    let mut acc = *p;
    for entry in odd.iter_mut().skip(1) {
        acc = add_cached(&acc, &p2).to_extended();
        *entry = acc.to_cached();
    }
    odd
}

/// Adds the wNAF digit `d` (odd, `|d| <= 15`, or zero for a no-op) times
/// the point whose odd multiples are `odd` to the completed point `t`.
/// **Variable-time.**
#[inline]
fn add_naf_digit(t: Completed, d: i8, odd: &[Cached; 8]) -> Completed {
    if d > 0 {
        add_cached(&t.to_extended(), &odd[(d as usize) / 2])
    } else if d < 0 {
        sub_cached(&t.to_extended(), &odd[(-d as usize) / 2])
    } else {
        t
    }
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
    /// non-square on edwards25519: `q` is brought to [`Cached`] form (one
    /// multiplication) and added in 8 more.
    // The library's own ladders add cached/Niels points directly; only the
    // group APIs (and tests) add two extended points.
    #[cfg(any(test, feature = "hazmat-edwards25519", feature = "ristretto255"))]
    pub(crate) fn point_add(&self, p: &Point, q: &Point) -> Point {
        add_cached(p, &q.to_cached()).to_extended()
    }

    /// Point doubling (dbl-2008-hwcd) for `a = −1`: 4 squarings and 4
    /// multiplications.
    pub(crate) fn point_double(&self, p: &Point) -> Point {
        p.to_projective().double().to_extended()
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
    /// operand fetched by a masked scan of the 8 [`Cached`] table entries
    /// `[1]P..[8]P` (one barriered equality mask each, no secret-indexed
    /// memory access) followed by a masked negation (one barriered mask). A
    /// zero digit adds the identity — a no-op with the same operation
    /// sequence, since the HWCD formulas are complete — so the schedule
    /// depends only on the (public) scalar width. The scalar bytes and
    /// digits are treated as secret (the digits are wiped).
    ///
    /// The doublings chain through [`Projective`] / [`Completed`] points, so
    /// only the doubling that feeds the addition computes `T` (4·(4S) +
    /// 3·3M + 4M per window, then 8M for the cached addition and 3M back to
    /// projective).
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
        #[cfg(target_arch = "x86_64")]
        if super::ifma::supported() {
            let mut digits = radix16_signed(scalar);
            let out = super::ifma::scalar_mult(&digits, p);
            digits.zeroize();
            return out;
        }
        self.scalar_mult_portable(scalar, p)
    }

    /// The portable body of [`Self::scalar_mult`].
    #[cfg(any(
        test,
        feature = "hazmat-edwards25519",
        feature = "ristretto255",
        not(feature = "ed25519-table")
    ))]
    pub(crate) fn scalar_mult_portable(&self, scalar: &[u8; 32], p: &Point) -> Point {
        // table[j] = [j + 1]P, cached.
        let p_cached = p.to_cached();
        let mut table = [p_cached; 8];
        let mut multiple = *p;
        for entry in table.iter_mut().skip(1) {
            multiple = add_cached(&multiple, &p_cached).to_extended();
            *entry = multiple.to_cached();
        }

        let mut digits = radix16_signed(scalar);
        // The carry digit (bit 256 of the recoding) seeds the accumulator
        // with [d₆₄]P ∈ {O, P}, selected by one barriered mask.
        let seed = point_select(p, &self.identity(), mask_from_bit(digits[64] as u64));
        // Out-of-line copies of the formulas for this loop: with every one
        // inlined, the 64-iteration body (four doublings, the gather and the
        // addition) grows to several thousand instructions and measured
        // ~15% slower than calling one compact copy of each formula. (The
        // formulas themselves stay `inline(always)` for the vartime paths,
        // which measured the other way round.)
        #[inline(never)]
        fn dbl(r: &Projective) -> Completed {
            r.double()
        }
        #[inline(never)]
        fn to_proj(c: &Completed) -> Projective {
            c.to_projective()
        }
        #[inline(never)]
        fn to_ext(c: &Completed) -> Point {
            c.to_extended()
        }
        #[inline(never)]
        fn add(p: &Point, q: &Cached) -> Completed {
            add_cached(p, q)
        }
        // Constant-time gather of table[|d| − 1], negated when d < 0: one
        // barriered equality mask per entry (`eq_mask`, never `==`), applied
        // across all four coordinates, so the secret digit never feeds a
        // compare-and-branch the compiler could emit; d = 0 keeps the
        // identity. Then one barriered mask for the sign (swap Y+X / Y−X,
        // negate 2dT).
        let gather = |d: i8| -> Cached {
            // `smask` is 0xff iff d < 0; `mag` = |d| ∈ 0..=8, branch-free.
            let smask = (d >> 7) as u8;
            let mag = ((d as u8) ^ smask).wrapping_sub(smask) as u64;
            let mut sel = Cached::IDENTITY;
            for (j, entry) in table.iter().enumerate() {
                sel = Cached::select(entry, &sel, eq_mask(j as u64 + 1, mag));
            }
            sel.conditional_negate(mask_from_bit((smask & 1) as u64));
            sel
        };

        // Digits 63..1 leave the accumulator projective; digit 0 finishes
        // in extended coordinates.
        let mut r = seed.to_projective();
        for &d in digits[1..64].iter().rev() {
            r = to_proj(&dbl(&r));
            r = to_proj(&dbl(&r));
            r = to_proj(&dbl(&r));
            let e = to_ext(&dbl(&r));
            r = to_proj(&add(&e, &gather(d)));
        }
        r = to_proj(&dbl(&r));
        r = to_proj(&dbl(&r));
        r = to_proj(&dbl(&r));
        let e = to_ext(&dbl(&r));
        let mut last = gather(digits[0]);
        let out = to_ext(&add(&e, &last));
        last.zeroize();
        digits.zeroize();
        for entry in table.iter_mut() {
            entry.zeroize();
        }
        out
    }

    /// Mixed addition `p + n` of an extended point and an affine Niels point
    /// (add-2008-hwcd-3 with `Z₂ = 1` and the Niels values precomputed):
    /// 7 multiplications instead of the 9 of [`Self::point_add`]. Complete
    /// for `a = −1` like the full formula, so adding the identity Niels
    /// `(1, 1, 0)` is a uniform no-op.
    #[cfg(feature = "ed25519-table")]
    #[inline]
    pub(crate) fn add_niels(&self, p: &Point, n: &Niels) -> Point {
        add_niels_completed(p, n).to_extended()
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
        #[cfg(target_arch = "x86_64")]
        if super::ifma::supported() {
            let out = super::ifma::mul_base(&digits);
            digits.zeroize();
            return out;
        }
        let out = Self::mul_base_portable(&digits);
        digits.zeroize();
        out
    }

    /// The portable body of the comb [`Self::mul_base`], from the recoded
    /// (secret) digits; the caller wipes them.
    #[cfg(feature = "ed25519-table")]
    fn mul_base_portable(digits: &[i8; 65]) -> Point {
        let f = Field::new();
        let mut acc = f.identity();
        for (window, &d) in ED25519_BASE_TABLE.iter().zip(digits.iter()) {
            acc = f.add_niels(&acc, &Niels::gather(window, d));
        }
        // The carry digit selects [2^256]B or the identity.
        let top = Niels::select(
            &Niels::from_entry(&ED25519_BASE_2_256),
            &Niels::IDENTITY,
            mask_from_bit(digits[64] as u64),
        );
        acc = f.add_niels(&acc, &top);
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
        let odd = odd_multiples(p);
        let naf = wnaf(scalar, 5);
        let Some(top) = naf.iter().rposition(|&d| d != 0) else {
            return self.identity();
        };

        let mut r = Projective::IDENTITY;
        let mut t = Completed::IDENTITY;
        for i in (0..=top).rev() {
            t = r.double();
            t = add_naf_digit(t, naf[i], &odd);
            r = t.to_projective();
        }
        t.to_extended()
    }

    /// **Variable-time** `[a]·p + [b]·B`, the Ed25519 verification
    /// combination: both wNAF ladders interleaved (Straus) so they share one
    /// run of ~254 doublings. The variable point uses width 5 against its 8
    /// odd multiples computed on the fly (in [`Cached`] form); the base point
    /// uses width 8 against the static Niels table [`ED25519_BASE_ODD`]
    /// (`[1]B, [3]B, …, [127]B`, feature `ed25519-table`; ≈ 1 mixed addition
    /// per 9 bits) or, without the table, width 5 against odd multiples of
    /// `B` computed on the fly. The accumulator stays projective between
    /// doublings; `T` is only computed ahead of an addition.
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
        let naf_a = wnaf(a, 5);
        #[cfg(feature = "ed25519-table")]
        let naf_b = wnaf(b, 8);
        #[cfg(not(feature = "ed25519-table"))]
        let naf_b = wnaf(b, 5);
        let Some(top) = naf_a
            .iter()
            .zip(naf_b.iter())
            .rposition(|(&x, &y)| x != 0 || y != 0)
        else {
            return self.identity();
        };
        #[cfg(target_arch = "x86_64")]
        if super::ifma::supported() {
            #[cfg(feature = "ed25519-table")]
            let base = ();
            #[cfg(not(feature = "ed25519-table"))]
            let base = self.base();
            return super::ifma::double_scalar_mult_vartime(&naf_a, p, &naf_b, top, &base);
        }
        self.double_scalar_mult_vartime_portable(&naf_a, p, &naf_b, top)
    }

    /// The portable body of [`Self::double_scalar_mult_base_vartime`], from
    /// the recodings and their highest nonzero position. **Variable-time.**
    pub(crate) fn double_scalar_mult_vartime_portable(
        &self,
        naf_a: &[i8; 264],
        p: &Point,
        naf_b: &[i8; 264],
        top: usize,
    ) -> Point {
        let odd_p = odd_multiples(p);
        #[cfg(not(feature = "ed25519-table"))]
        let odd_b = odd_multiples(&self.base());

        let mut r = Projective::IDENTITY;
        let mut t = Completed::IDENTITY;
        for i in (0..=top).rev() {
            t = r.double();
            t = add_naf_digit(t, naf_a[i], &odd_p);
            #[cfg(feature = "ed25519-table")]
            {
                let d = naf_b[i];
                if d > 0 {
                    let n = Niels::from_entry(&ED25519_BASE_ODD[d as usize / 2]);
                    t = add_niels_completed(&t.to_extended(), &n);
                } else if d < 0 {
                    let n = Niels::from_entry(&ED25519_BASE_ODD[(-d) as usize / 2]);
                    t = add_niels_completed(&t.to_extended(), &n.negate());
                }
            }
            #[cfg(not(feature = "ed25519-table"))]
            {
                t = add_naf_digit(t, naf_b[i], &odd_b);
            }
            r = t.to_projective();
        }
        t.to_extended()
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
                bool::from(f.ct_eq(f.mul(n.t2d, zz), f.mul(Fe::D2, f.mul(acc.x, acc.y)))),
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

    /// The pre-lazy HWCD formulas — every sum and difference fully reduced,
    /// `T` computed on every doubling, no cached/completed forms — as an
    /// independent oracle for the optimized point arithmetic.
    fn ref_add(f: &Field, p: &Point, q: &Point) -> Point {
        let aa = f.mul(f.sub(p.y, p.x), f.sub(q.y, q.x));
        let bb = f.mul(f.add(p.y, p.x), f.add(q.y, q.x));
        let cc = f.mul(f.mul(p.t, Fe::D2), q.t);
        let dd = f.mul(f.add(p.z, p.z), q.z);
        let (e, ff, g, h) = (f.sub(bb, aa), f.sub(dd, cc), f.add(dd, cc), f.add(bb, aa));
        Point {
            x: f.mul(e, ff),
            y: f.mul(g, h),
            t: f.mul(e, h),
            z: f.mul(ff, g),
        }
    }

    fn ref_double(f: &Field, p: &Point) -> Point {
        let a = f.sq(p.x);
        let b = f.sq(p.y);
        let zz = f.sq(p.z);
        let c = f.add(zz, zz);
        let d = f.neg(a);
        let e = f.sub(f.sub(f.sq(f.add(p.x, p.y)), a), b);
        let (g, h) = (f.add(d, b), f.sub(d, b));
        let ff = f.sub(g, c);
        Point {
            x: f.mul(e, ff),
            y: f.mul(g, h),
            t: f.mul(e, h),
            z: f.mul(ff, g),
        }
    }

    /// MSB-first binary double-and-add over all 256 bits.
    fn ref_mul(f: &Field, s: &[u8; 32], p: &Point) -> Point {
        let mut acc = f.identity();
        for i in (0..256).rev() {
            acc = ref_double(f, &acc);
            if (s[i / 8] >> (i % 8)) & 1 == 1 {
                acc = ref_add(f, &acc, p);
            }
        }
        acc
    }

    /// Every optimized path (cached/completed formulas with lazy
    /// reductions: `point_add`, `point_double`, the constant-time window
    /// ladder, the comb, the vartime Straus ladder) against the
    /// fully-reduced reference formulas, on prime-order points, the
    /// small-order points (orders 1, 2, 4, 8), mixed-order sums, and edge
    /// plus random scalars. Equality is projective (`point_ct_eq`) and on
    /// the canonical encoding, and every output coordinate must satisfy the
    /// reduced-limb invariant.
    #[test]
    fn optimized_formulas_match_reference() {
        use crate::hash::Sha256;
        use crate::rng::{HmacDrbg, RngCore};
        let f = Field::new();
        let reduced = |p: &Point| {
            [p.x, p.y, p.z, p.t]
                .iter()
                .all(|c| c.0.iter().all(|&l| l < (1u64 << 51) + (1u64 << 13)))
        };
        let same = |a: &Point, b: &Point, what: &str| {
            assert!(reduced(a), "{what}: unreduced output limb");
            assert!(bool::from(f.point_ct_eq(a, b)), "{what}: point mismatch");
            assert_eq!(f.encode(a), f.encode(b), "{what}: encoding mismatch");
            // T·Z == X·Y (the extended-coordinate invariant).
            assert!(
                bool::from(f.ct_eq(f.mul(a.t, a.z), f.mul(a.x, a.y))),
                "{what}: T"
            );
        };

        let b = f.base();
        // Small-order points: y = −1 (order 2), y = 0 (order 4), and an
        // order-8 point; each also added to B (mixed order).
        let mut minus_one = [0xffu8; 32];
        minus_one[0] = 0xec;
        minus_one[31] = 0x7f;
        let order8 = crate::ec::uint_from_be_hex::<4>(
            "7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7",
        );
        let mut o8 = [0u8; 32];
        order8.write_le_bytes(&mut o8);
        let small = [minus_one, [0u8; 32], o8]
            .map(|enc| f.decode(&enc).expect("small-order encoding decodes"));
        let points = [
            f.identity(),
            b,
            ref_mul(&f, &[7u8; 32], &b),
            small[0],
            small[1],
            small[2],
            ref_add(&f, &b, &small[0]),
            ref_add(&f, &b, &small[1]),
            ref_add(&f, &b, &small[2]),
        ];

        let int_bytes = |v: &ScalarInt| {
            let mut out = [0u8; 32];
            v.write_le_bytes(&mut out);
            out
        };
        let mut scalars = [[0u8; 32]; 19];
        scalars[1] = [0xff; 32];
        scalars[2] = int_bytes(&f.l);
        scalars[3] = int_bytes(&f.l.wrapping_sub(&ScalarInt::ONE));
        scalars[4][0] = 1;
        scalars[5][31] = 0x80;
        scalars[6] = [0x88; 32]; // every signed radix-16 digit −8
        let mut rng = HmacDrbg::<Sha256>::new(b"ed25519-ref-formulas", b"nonce", &[]);
        for s in scalars[7..].iter_mut() {
            rng.fill_bytes(s);
        }

        for (i, p) in points.iter().enumerate() {
            same(&f.point_double(p), &ref_double(&f, p), "point_double");
            for q in &points {
                same(&f.point_add(p, q), &ref_add(&f, p, q), "point_add");
            }
            for (j, s) in scalars.iter().enumerate() {
                let want = ref_mul(&f, s, p);
                same(&f.scalar_mult(s, p), &want, "scalar_mult");
                if i == 0 {
                    same(&f.mul_base(s), &ref_mul(&f, s, &b), "mul_base");
                }
                let s2 = &scalars[(j + 5) % scalars.len()];
                same(
                    &f.double_scalar_mult_base_vartime(s, p, s2),
                    &ref_add(&f, &want, &ref_mul(&f, s2, &b)),
                    "double_scalar_mult_base_vartime",
                );
                same(&f.scalar_mult_vartime(s, p), &want, "scalar_mult_vartime");
            }
        }
    }

    /// The AVX-512 IFMA window ladder agrees with the portable one (the
    /// reference test above already pins `scalar_mult`, which dispatches to
    /// it when supported; this pins the two backends against each other
    /// directly, on edge digits and random scalars over several points).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ifma_scalar_mult_matches_portable() {
        use crate::hash::Sha256;
        use crate::rng::{HmacDrbg, RngCore};
        if !super::super::ifma::supported() {
            #[cfg(feature = "std")]
            std::eprintln!("edwards25519: SKIPPED avx512-ifma ladder (not supported here)");
            return;
        }
        #[cfg(feature = "std")]
        std::eprintln!("edwards25519: RUNNING avx512-ifma ladder vs portable");
        let f = Field::new();
        let b = f.base();
        let mut minus_one = [0xffu8; 32];
        minus_one[0] = 0xec;
        minus_one[31] = 0x7f;
        let points = [
            f.identity(),
            b,
            f.scalar_mult_portable(&[0x5au8; 32], &b),
            f.decode(&minus_one).expect("order-2 point"),
        ];
        let mut rng = HmacDrbg::<Sha256>::new(b"edwards-ifma-differential", b"nonce", &[]);
        let mut scalars = [[0u8; 32]; 24];
        scalars[1] = [0xff; 32];
        scalars[2] = [0x88; 32];
        scalars[3] = [0x77; 32];
        scalars[4][0] = 1;
        for s in scalars[5..].iter_mut() {
            rng.fill_bytes(s);
        }
        for p in &points {
            for s in &scalars {
                let mut digits = radix16_signed(s);
                let v = super::super::ifma::scalar_mult(&digits, p);
                digits.zeroize();
                let w = f.scalar_mult_portable(s, p);
                assert!(bool::from(f.point_ct_eq(&v, &w)), "ifma/portable mismatch");
                assert_eq!(f.encode(&v), f.encode(&w));
                assert!(bool::from(f.ct_eq(f.mul(v.t, v.z), f.mul(v.x, v.y))), "T");

                // The vartime Straus ladder, [s]P + [s']B.
                let mut s2 = *s;
                s2.reverse();
                let naf_a = wnaf(s, 5);
                #[cfg(feature = "ed25519-table")]
                let (naf_b, base) = (wnaf(&s2, 8), ());
                #[cfg(not(feature = "ed25519-table"))]
                let (naf_b, base) = (wnaf(&s2, 5), f.base());
                let Some(top) = naf_a
                    .iter()
                    .zip(naf_b.iter())
                    .rposition(|(&x, &y)| x != 0 || y != 0)
                else {
                    continue;
                };
                #[cfg(feature = "ed25519-table")]
                {
                    let mut digits = radix16_signed(s);
                    let v = super::super::ifma::mul_base(&digits);
                    let w = Field::mul_base_portable(&digits);
                    digits.zeroize();
                    assert_eq!(f.encode(&v), f.encode(&w), "comb ifma/portable");
                }
                let v =
                    super::super::ifma::double_scalar_mult_vartime(&naf_a, p, &naf_b, top, &base);
                let w = f.double_scalar_mult_vartime_portable(&naf_a, p, &naf_b, top);
                assert!(bool::from(f.point_ct_eq(&v, &w)), "vartime ifma/portable");
                assert_eq!(f.encode(&v), f.encode(&w));
            }
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
            let t2d = Fe::from_bytes(&f.mul(f.mul(x, y), Fe::D2).to_bytes());
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
