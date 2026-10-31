//! Edwards448 curve points in extended homogeneous coordinates.
//!
//! Untwisted Edwards curve `x² + y² = 1 + d·x²·y²` (`a = +1`,
//! `d = −39081 mod p`) over GF(2⁴⁴⁸−2²²⁴−1), in extended coordinates
//! `(X:Y:Z:T)` with the complete Hisil–Wong–Carter–Dawson 2008 addition
//! formulas for `a = +1` (single `d`, not `2d`). Because `d` is a non-square
//! the formulas are complete (no exceptional cases). Scalar multiplication is a
//! constant-time double-and-add. This is the shared point backend behind Ed448.

#[cfg(feature = "ed448-table")]
use super::base_table::{ED448_BASE_TABLE, ED448_BASE_TOP, ED448_ODD_MULTIPLES};
#[cfg(any(test, feature = "ed448-table"))]
use super::field::mask_from_bit;
use super::field::{Fe, Field, ScalarInt, eq_mask};
use crate::ct::{Choice, ConstantTimeLess};
use crate::zeroize::Zeroize;

/// A curve point in extended homogeneous coordinates `(X:Y:Z:T)` with
/// `T = X·Y/Z`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Point {
    pub(crate) x: Fe,
    pub(crate) y: Fe,
    pub(crate) z: Fe,
    pub(crate) t: Fe,
}

impl Zeroize for Point {
    /// Wipes all four coordinates: window entries and gathered multiples are
    /// as secret as the scalar digit that selected them.
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
        self.t.zeroize();
    }
}

/// A precomputed affine point in the "Niels" form of the `a = +1` mixed
/// addition: `(x, y, d·x·y)`. With `Z = 1` the HWCD sum needs `A = X1·x`,
/// `B = Y1·y`, `C = T1·(d·x·y)` and `E` from `x + y`, so a table entry adds
/// in 8 multiplications instead of 9 plus a small-constant multiply.
#[cfg(feature = "ed448-table")]
#[derive(Clone, Copy, Debug)]
struct Affine {
    x: Fe,
    y: Fe,
    dxy: Fe,
}

#[cfg(feature = "ed448-table")]
impl Zeroize for Affine {
    /// Wipes a gathered table entry (it encodes a secret digit).
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.dxy.zeroize();
    }
}

#[cfg(feature = "ed448-table")]
impl Affine {
    /// The neutral element `(0, 1, 0)`.
    const IDENTITY: Affine = Affine {
        x: Fe::ZERO,
        y: Fe::ONE,
        dxy: Fe::ZERO,
    };

    /// Lifts a stored table entry (`x‖y‖d·x·y`, eight little-endian 56-bit
    /// limbs each, canonical residues).
    #[inline]
    fn from_entry(e: &[u64; 24]) -> Affine {
        let mut x = [0u64; 8];
        let mut y = [0u64; 8];
        let mut dxy = [0u64; 8];
        x.copy_from_slice(&e[..8]);
        y.copy_from_slice(&e[8..16]);
        dxy.copy_from_slice(&e[16..]);
        Affine {
            x: Fe(x),
            y: Fe(y),
            dxy: Fe(dxy),
        }
    }

    /// `−(x, y, d·x·y) = (−x, y, −d·x·y)`.
    #[inline]
    fn neg(&self) -> Affine {
        Affine {
            x: self.x.neg(),
            y: self.y,
            dxy: self.dxy.neg(),
        }
    }

    /// `a` when `mask` is all-ones, else `b`.
    #[inline]
    fn select(a: &Affine, b: &Affine, mask: u64) -> Affine {
        Affine {
            x: Fe::select(&a.x, &b.x, mask),
            y: Fe::select(&a.y, &b.y, mask),
            dxy: Fe::select(&a.dxy, &b.dxy, mask),
        }
    }
}

/// Constant-time gather of `[digit]·base` from a window of the 8 stored
/// multiples `[1]base..[8]base`, for a signed digit in `[−8, 8)`: scan all 8
/// entries with one opaque equality mask each (no secret-indexed memory
/// access), then negate under one more mask. A zero digit yields the
/// identity. `sel` is scratch space (left holding `[|digit|]·base`); the
/// caller wipes it.
#[cfg(feature = "ed448-table")]
fn gather(window: &[[u64; 24]; 8], digit: i8, sel: &mut [u64; 24]) -> Affine {
    // |digit| and its sign without a branch: `m` is −1 for a negative digit.
    let m = digit >> 7;
    let mag = ((digit ^ m) - m) as u64;
    let neg = (m & 1) as u64;
    // The identity entry (x = 0, y = 1, d·x·y = 0), built in the caller's
    // scratch buffer so the caller can wipe the last selection once at the
    // end instead of paying a volatile wipe per digit.
    *sel = [0u64; 24];
    sel[8] = 1;
    for (j, entry) in window.iter().enumerate() {
        let mask = eq_mask(j as u64 + 1, mag);
        for (s, &e) in sel.iter_mut().zip(entry.iter()) {
            *s ^= mask & (*s ^ e);
        }
    }
    let a = Affine::from_entry(sel);
    Affine::select(&a.neg(), &a, mask_from_bit(neg))
}

/// Signed radix-16 recoding of the low 448 bits of a 57-byte little-endian
/// scalar: 112 digits in `[−8, 8)` plus a carry digit `d₁₁₂ ∈ {0, 1}`, with
/// `Σ dᵢ·16ⁱ` equal to the scalar exactly. Branch-free (the carry is
/// arithmetic), so safe on secret scalars.
#[cfg(feature = "ed448-table")]
fn radix16_signed(scalar: &[u8; 57]) -> [i8; 113] {
    let mut d = [0i8; 113];
    for (i, &byte) in scalar[..56].iter().enumerate() {
        d[2 * i] = (byte & 15) as i8;
        d[2 * i + 1] = (byte >> 4) as i8;
    }
    for i in 0..112 {
        let carry = (d[i] + 8) >> 4;
        d[i] -= carry << 4;
        d[i + 1] += carry;
    }
    d
}

impl Field {
    /// The base point `B` (precomputed at compile time).
    // With the fixed-base table, library-path base multiplications never
    // touch the point itself; only the table-free ladders and tests do.
    #[cfg(any(test, not(feature = "ed448-table")))]
    #[inline]
    pub(crate) fn base(&self) -> Point {
        self.base_point
    }

    /// Decompresses a 57-byte point encoding (RFC 8032 §5.2.3), or `None` if the
    /// bytes do not encode a curve point.
    pub(crate) fn decode(&self, enc: &[u8; 57]) -> Option<Point> {
        // sign = high bit of octet[56]; the low 7 bits of octet[56] must be 0.
        let sign = (enc[56] >> 7) & 1;
        if enc[56] & 0x7f != 0 {
            return None;
        }
        let mut yb = [0u8; 56];
        yb.copy_from_slice(&enc[..56]);
        let yval = ScalarInt::from_le_bytes(&yb);
        if !bool::from(yval.ct_lt(&self.p)) {
            return None;
        }
        let y = Fe::from_bytes(&yb);

        // x² = (1 − y²) / (1 − d·y²) = u / v.
        let yy = self.sq(y);
        let u = self.sub(self.one, yy);
        let v = self.sub(self.one, self.mul(self.d, yy));

        // x = sqrt(u/v). `is_square` is false exactly when v·x² ≠ u, i.e. the
        // candidate is not on the curve (the point is invalid).
        let (is_square, mut x) = self.sqrt_ratio(u, v);
        if !bool::from(is_square) {
            return None;
        }

        // Reject the non-canonical (0, ±1) encoding with sign bit set: x = 0
        // has no negative representative, so demanding x odd is unsatisfiable.
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

    /// Compresses a point to its 57-byte encoding (RFC 8032 §5.2.2).
    pub(crate) fn encode(&self, p: &Point) -> [u8; 57] {
        let zinv = self.inv(p.z);
        let x = self.mul(p.x, zinv);
        let y = self.mul(p.y, zinv);
        let mut out = [0u8; 57];
        out[..56].copy_from_slice(&y.to_bytes());
        out[56] = x.is_negative().unwrap_u8() << 7;
        out
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

    /// Point addition (add-2008-hwcd-4 for `a = +1`), complete on edwards448
    /// since `d` is a non-square.
    ///
    /// `A=X1·X2; B=Y1·Y2; C=d·T1·T2; D=Z1·Z2; E=(X1+Y1)·(X2+Y2)−A−B;
    ///  F=D−C; G=D+C; H=B−A; X3=E·F; Y3=G·H; T3=E·H; Z3=F·G`.
    ///
    /// `d = −39081`, so `C` is computed as the small-constant product
    /// `c = 39081·T1·T2 = −C` (a [`Fe::mul_small`] instead of a full
    /// multiply) with `F = D + c`, `G = D − c`: 9 multiplications, one
    /// small-constant multiply.
    pub(crate) fn point_add(&self, p: &Point, q: &Point) -> Point {
        let a = self.mul(p.x, q.x);
        let b = self.mul(p.y, q.y);
        let c = self.mul_small(self.mul(p.t, q.t), Fe::NEG_D_SMALL);
        let d = self.mul(p.z, q.z);
        let e = self.sub(
            self.sub(self.mul(self.add(p.x, p.y), self.add(q.x, q.y)), a),
            b,
        );
        let ff = self.add(d, c);
        let g = self.sub(d, c);
        let h = self.sub(b, a);
        Point {
            x: self.mul(e, ff),
            y: self.mul(g, h),
            t: self.mul(e, h),
            z: self.mul(ff, g),
        }
    }

    /// Point doubling for `a = +1`.
    ///
    /// `A=X1²; B=Y1²; C=2·Z1²; E=(X1+Y1)²−A−B; G=A+B; F=G−C; H=A−B;
    ///  X3=E·F; Y3=G·H; T3=E·H; Z3=F·G`.
    pub(crate) fn point_double(&self, p: &Point) -> Point {
        let a = self.sq(p.x);
        let b = self.sq(p.y);
        let zz = self.sq(p.z);
        let c = self.add(zz, zz);
        let e = self.sub(self.sub(self.sq(self.add(p.x, p.y)), a), b);
        let g = self.add(a, b);
        let ff = self.sub(g, c);
        let h = self.sub(a, b);
        Point {
            x: self.mul(e, ff),
            y: self.mul(g, h),
            t: self.mul(e, h),
            z: self.mul(ff, g),
        }
    }

    /// Constant-time `[scalar]·p` over the low 448 bits of the 57-byte
    /// little-endian scalar, via a fixed 4-bit window: 4 doublings and one
    /// *unconditional* addition per nibble (112 additions instead of the 448
    /// of a bit-at-a-time ladder), with the window value fetched by a masked
    /// scan of all 16 table entries (no secret-indexed memory access). A zero
    /// nibble adds the identity — a no-op with the same operation sequence,
    /// since the HWCD formulas are complete — so the schedule depends only on
    /// the (public) scalar width. The scalar bytes are treated as secret; the
    /// Ed448 secret scalar is pruned to fit, and `r < L < 2⁴⁴⁶`.
    ///
    /// The table is 16 points (4 KB) of stack, the same shape as the
    /// edwards25519 window; a 3-bit window would halve it but cost ~38 more
    /// additions per multiplication.
    // Ed448 only ever multiplies the base point; with the fixed-base table
    // this generic ladder has no library users.
    #[cfg(any(test, not(feature = "ed448-table")))]
    pub(crate) fn scalar_mult(&self, scalar: &[u8; 57], p: &Point) -> Point {
        // table[j] = [j]P; table[0] is the identity.
        let mut table = [self.identity(); 16];
        table[1] = *p;
        for i in 2..16 {
            table[i] = if i % 2 == 0 {
                self.point_double(&table[i / 2])
            } else {
                self.point_add(&table[i - 1], p)
            };
        }

        let mut acc = self.identity();
        let mut sel = table[0];
        let mut i = 112;
        while i > 0 {
            i -= 1;
            acc = self.point_double(&acc);
            acc = self.point_double(&acc);
            acc = self.point_double(&acc);
            acc = self.point_double(&acc);

            let byte = scalar[i / 2];
            let digit = (if i % 2 == 1 { byte >> 4 } else { byte & 0xf }) as u64;
            // Constant-time gather of table[digit]: one opaque equality mask
            // per entry (`eq_mask`, branch-free), applied across all 32
            // limbs of the candidate, so the secret digit never feeds a
            // compare-and-branch the compiler could emit.
            sel = table[0];
            for (j, entry) in table.iter().enumerate() {
                sel = point_select(&sel, entry, eq_mask(j as u64, digit));
            }
            acc = self.point_add(&acc, &sel);
        }
        // The last gathered multiple and the window are functions of the
        // secret scalar (the window together with the output pins it down
        // for a known `p`); the accumulator is moved out as the result.
        let out = acc;
        acc.zeroize();
        sel.zeroize();
        table.zeroize();
        out
    }

    /// Mixed addition `p + q` of an extended point and a stored affine point
    /// (`Z2 = 1`): the complete HWCD `a = +1` formula of [`Self::point_add`]
    /// with `D = Z1` and `C = T1·(d·x2·y2)`, 8 multiplications.
    #[cfg(feature = "ed448-table")]
    fn add_affine(&self, p: &Point, q: &Affine) -> Point {
        let a = self.mul(p.x, q.x);
        let b = self.mul(p.y, q.y);
        let c = self.mul(p.t, q.dxy);
        let d = p.z;
        let e = self.sub(
            self.sub(self.mul(self.add(p.x, p.y), self.add(q.x, q.y)), a),
            b,
        );
        let ff = self.sub(d, c);
        let g = self.add(d, c);
        let h = self.sub(b, a);
        Point {
            x: self.mul(e, ff),
            y: self.mul(g, h),
            t: self.mul(e, h),
            z: self.mul(ff, g),
        }
    }

    /// Constant-time fixed-base multiplication `[scalar]·B` (low 448 bits of
    /// the 57-byte little-endian scalar) via the precomputed table
    /// [`ED448_BASE_TABLE`]: the scalar is recoded into 112 signed radix-16
    /// digits `dᵢ ∈ [−8, 8)` plus a carry digit `d₁₁₂ ∈ {0, 1}`, and
    /// `[k]B = Σᵢ [dᵢ·16ⁱ]B` is accumulated as the odd-position digits (each
    /// gathered from the window of `[16^(i−1)]B` multiples, then scaled by
    /// four doublings), then the even-position digits, then the carry times
    /// `[2⁴⁴⁸]B` — 113 mixed additions, 4 doublings and 112 masked window
    /// scans (no secret-indexed memory access, one opaque mask per
    /// candidate). A zero digit adds the identity, a uniform no-op under the
    /// complete HWCD formulas, so the schedule depends only on the (public)
    /// scalar width. The scalar bytes are treated as secret.
    #[cfg(feature = "ed448-table")]
    pub(crate) fn mul_base(&self, scalar: &[u8; 57]) -> Point {
        // The 113 signed digits encode the secret scalar (the Ed448 nonce
        // `r` or the private scalar `s`) exactly: wiped before returning,
        // together with the last gathered entry and its scratch buffer.
        let mut digits = radix16_signed(scalar);
        let mut acc = self.identity();
        let mut scratch = [0u64; 24];
        let mut sel;
        for (j, window) in ED448_BASE_TABLE.iter().enumerate() {
            sel = gather(window, digits[2 * j + 1], &mut scratch);
            acc = self.add_affine(&acc, &sel);
        }
        acc = self.point_double(&acc);
        acc = self.point_double(&acc);
        acc = self.point_double(&acc);
        acc = self.point_double(&acc);
        for (j, window) in ED448_BASE_TABLE.iter().enumerate() {
            sel = gather(window, digits[2 * j], &mut scratch);
            acc = self.add_affine(&acc, &sel);
        }
        // d₁₁₂ ∈ {0, 1}: add [2⁴⁴⁸]B or the identity under one mask.
        sel = Affine::select(
            &Affine::from_entry(&ED448_BASE_TOP),
            &Affine::IDENTITY,
            mask_from_bit(digits[112] as u64),
        );
        let out = self.add_affine(&acc, &sel);
        digits.zeroize();
        scratch.zeroize();
        sel.zeroize();
        acc.zeroize();
        out
    }

    /// Constant-time fixed-base multiplication `[scalar]·B` without the
    /// precomputed table (feature `ed448-table` off): the generic windowed
    /// ladder [`Self::scalar_mult`] over `B`. Same result and the same
    /// secret-scalar discipline, at the cost of ~448 doublings the table
    /// would avoid.
    #[cfg(not(feature = "ed448-table"))]
    pub(crate) fn mul_base(&self, scalar: &[u8; 57]) -> Point {
        self.scalar_mult(scalar, &self.base())
    }

    /// The previous bit-at-a-time double-and-add-always ladder, kept as the
    /// differential oracle for the windowed [`Self::scalar_mult`].
    #[cfg(test)]
    pub(crate) fn scalar_mult_bitwise(&self, scalar: &[u8; 57], p: &Point) -> Point {
        let mut acc = self.identity();
        let mut i = 448;
        while i > 0 {
            i -= 1;
            acc = self.point_double(&acc);
            let bit = (scalar[i / 8] >> (i % 8)) & 1;
            let sum = self.point_add(&acc, p);
            acc = point_select(&acc, &sum, mask_from_bit(bit as u64));
        }
        acc
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

    /// **Variable-time** `[a]·p + [b]·B`, the Ed448 verification
    /// combination: two interleaved (Straus) wNAF ladders sharing one run of
    /// ~446 doublings, plus one addition per nonzero digit. The `p` side is
    /// width 5 (≈ 1 addition in 6) against the 8 odd multiples `[1]p..[15]p`
    /// computed on the fly; the base side is width 8 (≈ 1 in 9) against the
    /// 64 stored odd multiples `[1]B..[127]B` of [`ED448_ODD_MULTIPLES`],
    /// each added with the 8-multiplication mixed formula.
    ///
    /// # Warning: public inputs only
    ///
    /// Both the branch pattern and the table indices leak the scalars. This
    /// must ONLY ever be called with **public** scalars and points (the
    /// signature scalar `S`, the challenge `k` and the public key `A` during
    /// verification) — never with signing nonces or secret keys.
    #[cfg(feature = "ed448-table")]
    pub(crate) fn double_scalar_mult_base_vartime(
        &self,
        a: &[u8; 57],
        p: &Point,
        b: &[u8; 57],
    ) -> Point {
        let odd_p = self.odd_multiples(p);
        let naf_a = wnaf::<5>(a);
        let naf_b = wnaf::<8>(b);
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
            let d = naf_b[i];
            if d > 0 {
                let e = Affine::from_entry(&ED448_ODD_MULTIPLES[(d as usize) / 2]);
                acc = self.add_affine(&acc, &e);
            } else if d < 0 {
                let e = Affine::from_entry(&ED448_ODD_MULTIPLES[(-d as usize) / 2]);
                acc = self.add_affine(&acc, &e.neg());
            }
        }
        acc
    }

    /// **Variable-time** `[a]·p + [b]·B`, the Ed448 verification
    /// combination without the precomputed table (feature `ed448-table`
    /// off): two interleaved (Straus) width-5 wNAF ladders sharing one run
    /// of ~446 doublings, plus one addition per nonzero digit (≈ 1 in 6 per
    /// scalar) against the 8 odd multiples `[1]X..[15]X` of each point.
    ///
    /// # Warning: public inputs only
    ///
    /// Both the branch pattern and the table indices leak the scalars. This
    /// must ONLY ever be called with **public** scalars and points (the
    /// signature scalar `S`, the challenge `k` and the public key `A` during
    /// verification) — never with signing nonces or secret keys.
    #[cfg(not(feature = "ed448-table"))]
    pub(crate) fn double_scalar_mult_base_vartime(
        &self,
        a: &[u8; 57],
        p: &Point,
        b: &[u8; 57],
    ) -> Point {
        let odd_p = self.odd_multiples(p);
        let odd_b = self.odd_multiples(&self.base());
        let naf_a = wnaf::<5>(a);
        let naf_b = wnaf::<5>(b);
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
            acc = self.add_naf_digit(&acc, naf_b[i], &odd_b);
        }
        acc
    }

    /// The odd multiples `odd[i] = [2i+1]P` for `i in 0..8`, the lookup table
    /// of the width-5 wNAF ladder.
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
    /// representatives via cross-multiplication: `X₁·Z₂ == X₂·Z₁` and
    /// `Y₁·Z₂ == Y₂·Z₁`.
    pub(crate) fn point_ct_eq(&self, p: &Point, q: &Point) -> Choice {
        let x1z2 = self.mul(p.x, q.z);
        let x2z1 = self.mul(q.x, p.z);
        let y1z2 = self.mul(p.y, q.z);
        let y2z1 = self.mul(q.y, p.z);
        self.ct_eq(x1z2, x2z1) & self.ct_eq(y1z2, y2z1)
    }
}

/// Width-`W` non-adjacent form (`W ≤ 8`) of a 456-bit (57-byte)
/// little-endian scalar: odd digits in `(−2^(W−1), 2^(W−1))` with at least
/// `W − 1` zeros between nonzero digits. The trailing positions absorb the
/// recoding carry, so any 456-bit integer is represented exactly.
/// **Variable-time**; only for public scalars.
fn wnaf<const W: u32>(scalar: &[u8; 57]) -> [i8; 464] {
    let mut naf = [0i8; 464];

    // Nine u64 limbs (57 bytes zero-padded, plus one spare) so the window
    // read below may index one limb past the scalar's top byte.
    let mut x = [0u64; 9];
    for (i, chunk) in scalar.chunks(8).enumerate() {
        let mut b = [0u8; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        x[i] = u64::from_le_bytes(b);
    }

    let width = 1u64 << W;
    let window_mask = width - 1;
    let w = W as usize;

    let mut pos = 0;
    let mut carry = 0u64;
    while pos < 456 {
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
            naf[pos] = (window as i16 - width as i16) as i8;
        }
        pos += w;
    }
    // A carry surviving past bit 455 stands for `+2^pos` (pos <= 463).
    if carry != 0 {
        naf[pos] = 1;
    }
    naf
}

/// Constant-time point selection: `b` if `mask` is all-ones, else `a`. The
/// caller derives the single opaque mask ([`mask_from_bit`] / [`eq_mask`]);
/// it is applied to all four coordinates with plain xor/and.
#[cfg(any(test, not(feature = "ed448-table")))]
#[inline]
pub(crate) fn point_select(a: &Point, b: &Point, mask: u64) -> Point {
    Point {
        x: Fe::select(&b.x, &a.x, mask),
        y: Fe::select(&b.y, &a.y, mask),
        z: Fe::select(&b.z, &a.z, mask),
        t: Fe::select(&b.t, &a.t, mask),
    }
}

#[cfg(test)]
mod tests {
    use super::super::field::BASE_ENC;
    use super::*;

    /// The compile-time base point is exactly the decompression of the
    /// RFC 8032 encoding (`Z = 1`, `T = X·Y`).
    #[test]
    fn const_base_matches_decoded_encoding() {
        let f = Field::new();
        let dec = f.decode(&BASE_ENC).expect("valid base point");
        let b = f.base();
        assert!(bool::from(f.ct_eq(b.x, dec.x)));
        assert!(bool::from(f.ct_eq(b.y, dec.y)));
        assert!(bool::from(f.ct_eq(b.z, dec.z)));
        assert!(bool::from(f.ct_eq(b.t, dec.t)));
        assert!(bool::from(f.ct_eq(b.z, f.one)));
        assert!(bool::from(f.ct_eq(f.mul(b.x, b.y), b.t)));
        assert_eq!(f.encode(&b), BASE_ENC);
        let (x, y, t) = f.base_affine();
        assert!(bool::from(f.ct_eq(x, b.x)));
        assert!(bool::from(f.ct_eq(y, b.y)));
        assert!(bool::from(f.ct_eq(t, b.t)));
    }

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// The windowed ladder matches the bit-at-a-time one on edge scalars
    /// (zero, one, all-ones in the consumed 448 bits, single nibbles at
    /// both ends) and a random sweep, over the base point and a non-base
    /// point.
    #[test]
    fn windowed_scalar_mult_matches_bitwise() {
        let f = Field::new();
        let b = f.base();
        let p = f.point_double(&f.point_add(&b, &f.point_double(&b)));
        let mut edges = [[0u8; 57]; 6];
        edges[1][0] = 1;
        edges[2][..56].fill(0xff);
        edges[3][0] = 0x0f;
        edges[4][55] = 0xf0;
        edges[5][..56].fill(0xa5);
        let mut st = 0x5ca1;
        let random = core::iter::repeat_with(|| {
            let mut k = [0u8; 57];
            for c in k.chunks_mut(8) {
                let w = splitmix(&mut st).to_le_bytes();
                c.copy_from_slice(&w[..c.len()]);
            }
            k
        })
        .take(24);
        for k in edges.into_iter().chain(random) {
            for pt in [&b, &p] {
                let w = f.scalar_mult(&k, pt);
                let r = f.scalar_mult_bitwise(&k, pt);
                assert!(bool::from(f.point_ct_eq(&w, &r)), "mismatch for {k:02x?}");
            }
            let m = f.mul_base(&k);
            let r = f.scalar_mult_bitwise(&k, &b);
            assert!(bool::from(f.point_ct_eq(&m, &r)), "mul_base mismatch");
        }
    }

    /// Differential test: the fixed-base multiplication agrees with the
    /// generic windowed ladder for edge scalars (0, 1, 2, L−1, L, L+1, the
    /// pruned-scalar shape 2⁴⁴⁷ + …, all-ones, and the nibble patterns that
    /// make every signed radix-16 digit carry) and a batch of random ones —
    /// and the vartime double-scalar path agrees with the constant-time
    /// ladders on every one of them.
    #[test]
    fn mul_base_matches_generic_scalar_mult() {
        use crate::hash::Sha256;
        use crate::rng::{HmacDrbg, RngCore};
        let f = Field::new();
        let b = f.base();
        // An independent point for the double-scalar check.
        let p = f.scalar_mult(&[7u8; 57], &b);

        let check = |s: &[u8; 57]| {
            let fixed = f.encode(&f.mul_base(s));
            assert_eq!(
                fixed,
                f.encode(&f.scalar_mult(s, &b)),
                "fixed-base/ladder mismatch for {s:02x?}"
            );
            assert_eq!(
                fixed,
                f.encode(&f.double_scalar_mult_base_vartime(&[0u8; 57], &p, s)),
                "vartime double-scalar [0]P + [s]B mismatch"
            );
            // [s]P + [s']B against the constant-time ladders, with s' = s
            // byte-reversed (top byte cleared) so the two digit streams
            // differ.
            let mut s2 = *s;
            s2[..56].reverse();
            s2[56] = 0;
            let want = f.point_add(&f.scalar_mult(s, &p), &f.mul_base(&s2));
            assert_eq!(
                f.encode(&want),
                f.encode(&f.double_scalar_mult_base_vartime(s, &p, &s2)),
                "vartime double-scalar mismatch"
            );
        };

        let int_bytes = |v: &ScalarInt| {
            let mut out = [0u8; 57];
            v.write_le_bytes(&mut out[..56]);
            out
        };
        let mut edges = [[0u8; 57]; 12];
        edges[1][0] = 1;
        edges[2][0] = 2;
        edges[3] = int_bytes(&f.l.wrapping_sub(&ScalarInt::ONE));
        edges[4] = int_bytes(&f.l);
        edges[5] = int_bytes(&f.l.wrapping_add(&ScalarInt::ONE));
        edges[6][55] = 0x80;
        edges[6][0] = 0xfc;
        edges[7][..56].fill(0xff);
        edges[8][..56].fill(0x88);
        edges[9][..56].fill(0x78);
        edges[10][..56].fill(0xf8);
        edges[11][..56].fill(0x08);
        edges[11][55] = 0x88;
        for s in &edges {
            check(s);
        }

        let mut rng = HmacDrbg::<Sha256>::new(b"ed448-fixed-base-differential", b"nonce", &[]);
        for _ in 0..24 {
            let mut s = [0u8; 57];
            rng.fill_bytes(&mut s[..56]);
            check(&s);
        }
    }

    /// Re-derives every entry of the embedded fixed-base tables from the
    /// group law, so `base_table.rs` is verified on every test run rather
    /// than trusted. Inversion-free: the stored affine `(x, y, d·x·y)`
    /// matches the computed `(X : Y : Z : T)` iff `x·Z == X`, `y·Z == Y`
    /// and `(d·x·y)·Z == d·T`; every stored limb is also checked canonical.
    #[test]
    #[cfg(feature = "ed448-table")]
    fn base_table_matches_computed() {
        let f = Field::new();
        let check = |entry: &[u64; 24], want: &Point| {
            let e = Affine::from_entry(entry);
            assert!(
                bool::from(f.ct_eq(f.mul(e.x, want.z), want.x)),
                "x mismatch"
            );
            assert!(
                bool::from(f.ct_eq(f.mul(e.y, want.z), want.y)),
                "y mismatch"
            );
            assert!(
                bool::from(f.ct_eq(f.mul(e.dxy, want.z), f.mul(f.d, want.t))),
                "d·x·y mismatch"
            );
            for c in [e.x, e.y, e.dxy] {
                assert_eq!(Fe::from_bytes(&c.to_bytes()).0, c.0, "non-canonical limbs");
            }
        };
        // base = [16^(2j)]B for window j.
        let mut base = f.base();
        for window in ED448_BASE_TABLE.iter() {
            let mut acc = base;
            for (k, entry) in window.iter().enumerate() {
                if k > 0 {
                    acc = f.point_add(&acc, &base);
                }
                check(entry, &acc);
            }
            for _ in 0..8 {
                base = f.point_double(&base);
            }
        }
        // After 56 windows, base = [16^112]B = [2^448]B.
        check(&ED448_BASE_TOP, &base);

        let b = f.base();
        let b2 = f.point_double(&b);
        let mut acc = b;
        for (k, entry) in ED448_ODD_MULTIPLES.iter().enumerate() {
            if k > 0 {
                acc = f.point_add(&acc, &b2);
            }
            check(entry, &acc);
        }
    }

    /// Regenerates the fixed-base table source
    /// (`src/ec/curve448/base_table.rs`). Run with:
    /// `cargo test --release gen_ed448_base_table -- --ignored --nocapture`
    /// and paste the emitted statics between the file's header comment and
    /// EOF. The non-ignored `base_table_matches_computed` test keeps the
    /// pasted constants honest on every test run.
    #[test]
    #[ignore = "table generator; emits Rust source on stdout"]
    #[cfg(feature = "std")]
    fn gen_ed448_base_table() {
        use std::{print, println};
        let f = Field::new();
        // Affine (x, y, d·x·y) as canonical 56-bit limbs (fully reduced via
        // the to/from bytes round-trip).
        let affine = |p: &Point| -> [u64; 24] {
            let zinv = f.inv(p.z);
            let x = Fe::from_bytes(&f.mul(p.x, zinv).to_bytes());
            let y = Fe::from_bytes(&f.mul(p.y, zinv).to_bytes());
            let dxy = Fe::from_bytes(&f.mul(f.d, f.mul(x, y)).to_bytes());
            let mut e = [0u64; 24];
            e[..8].copy_from_slice(&x.0);
            e[8..16].copy_from_slice(&y.0);
            e[16..].copy_from_slice(&dxy.0);
            e
        };
        let entry = |e: &[u64; 24], term: &str| {
            print!("    [");
            for l in e {
                print!("0x{l:014x}, ");
            }
            println!("]{term}");
        };
        println!("pub(crate) static ED448_BASE_TABLE: [[[u64; 24]; 8]; 56] = [");
        let mut base = f.base();
        for _ in 0..56 {
            println!("    [");
            let mut acc = base;
            for k in 1..=8u32 {
                if k > 1 {
                    acc = f.point_add(&acc, &base);
                }
                entry(&affine(&acc), ",");
            }
            println!("    ],");
            for _ in 0..8 {
                base = f.point_double(&base);
            }
        }
        println!("];");
        println!();
        println!("pub(crate) static ED448_BASE_TOP: [u64; 24] =");
        entry(&affine(&base), ";");
        println!();
        println!("pub(crate) static ED448_ODD_MULTIPLES: [[u64; 24]; 64] = [");
        let b = f.base();
        let b2 = f.point_double(&b);
        let mut acc = b;
        for k in 0..64 {
            if k > 0 {
                acc = f.point_add(&acc, &b2);
            }
            entry(&affine(&acc), ",");
        }
        println!("];");
    }

    /// The vartime Straus ladder agrees with two constant-time
    /// multiplications, including all-ones scalars (maximal wNAF carry) and
    /// zero on either side.
    #[test]
    fn double_scalar_mult_vartime_matches_ct() {
        let f = Field::new();
        let b = f.base();
        let p = f.point_double(&f.point_add(&b, &f.point_double(&b)));
        let mut full = [0xffu8; 57];
        full[56] = 0;
        let mut one = [0u8; 57];
        one[0] = 1;
        let mut st = 0xd5;
        let mut rnd = || {
            let mut k = [0u8; 57];
            for c in k[..56].chunks_mut(8) {
                c.copy_from_slice(&splitmix(&mut st).to_le_bytes());
            }
            k
        };
        let mut cases = [([0u8; 57], [0u8; 57]); 21];
        cases[1] = ([0u8; 57], one);
        cases[2] = (one, [0u8; 57]);
        cases[3] = (full, full);
        cases[4] = ([0xffu8; 57], [0xffu8; 57]);
        for c in cases[5..].iter_mut() {
            *c = (rnd(), rnd());
        }
        for (ka, kb) in cases {
            let got = f.double_scalar_mult_base_vartime(&ka, &p, &kb);
            let want = f.point_add(&f.scalar_mult(&ka, &p), &f.scalar_mult(&kb, &b));
            // scalar_mult consumes only the low 448 bits; the all-0xff
            // 57-byte case is checked against bit 448..455 added explicitly.
            let want = if ka[56] != 0 || kb[56] != 0 {
                let mut hi_a = [0u8; 57];
                hi_a[0] = ka[56];
                let mut hi_b = [0u8; 57];
                hi_b[0] = kb[56];
                let shift = |x: &Point, hi: &[u8; 57]| {
                    let mut q = f.scalar_mult(hi, x);
                    for _ in 0..448 {
                        q = f.point_double(&q);
                    }
                    q
                };
                let ha = shift(&p, &hi_a);
                let hb = shift(&b, &hi_b);
                f.point_add(&want, &f.point_add(&ha, &hb))
            } else {
                want
            };
            assert!(bool::from(f.point_ct_eq(&got, &want)));
        }
    }
}
