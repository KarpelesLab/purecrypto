//! Edwards448 curve points in extended homogeneous coordinates.
//!
//! Untwisted Edwards curve `x² + y² = 1 + d·x²·y²` (`a = +1`,
//! `d = −39081 mod p`) over GF(2⁴⁴⁸−2²²⁴−1), in extended coordinates
//! `(X:Y:Z:T)` with the complete Hisil–Wong–Carter–Dawson 2008 addition
//! formulas for `a = +1` (single `d`, not `2d`). Because `d` is a non-square
//! the formulas are complete (no exceptional cases). Scalar multiplication is a
//! constant-time double-and-add. This is the shared point backend behind Ed448.

use super::field::{Fe, Field};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};

/// A curve point in extended homogeneous coordinates `(X:Y:Z:T)`, all in
/// Montgomery form, with `T = X·Y/Z`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Point {
    pub(crate) x: Fe,
    pub(crate) y: Fe,
    pub(crate) z: Fe,
    pub(crate) t: Fe,
}

impl Field {
    /// The base point `B` (precomputed at compile time).
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
        let yval = Fe::from_le_bytes(&yb);
        if !bool::from(yval.ct_lt(&self.p)) {
            return None;
        }
        let y = self.to_mont(&yval);

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

        let xplain = self.from_mont(&x);
        // Reject the non-canonical (0, ±1) encoding with sign bit set: x = 0
        // has no negative representative, so demanding x odd is unsatisfiable.
        if bool::from(xplain.ct_eq(&Fe::ZERO)) && sign == 1 {
            return None;
        }
        if xplain.is_odd().unwrap_u8() != sign {
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
        let x = self.from_mont(&self.mul(p.x, zinv));
        let y = self.from_mont(&self.mul(p.y, zinv));
        let mut out = [0u8; 57];
        let mut yb = [0u8; 56];
        y.write_le_bytes(&mut yb);
        out[..56].copy_from_slice(&yb);
        out[56] = x.is_odd().unwrap_u8() << 7;
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
    pub(crate) fn point_add(&self, p: &Point, q: &Point) -> Point {
        let a = self.mul(p.x, q.x);
        let b = self.mul(p.y, q.y);
        let c = self.mul(self.mul(self.d, p.t), q.t);
        let d = self.mul(p.z, q.z);
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
    /// The table is 16 points (3.5 KB) of stack, the same shape as the
    /// edwards25519 window; a 3-bit window would halve it but cost ~38 more
    /// additions per multiplication.
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
        let mut i = 112;
        while i > 0 {
            i -= 1;
            acc = self.point_double(&acc);
            acc = self.point_double(&acc);
            acc = self.point_double(&acc);
            acc = self.point_double(&acc);

            let byte = scalar[i / 2];
            let digit = (if i % 2 == 1 { byte >> 4 } else { byte & 0xf }) as usize;
            // Constant-time gather of table[digit]: the index comparison is
            // the branch-free `ct_eq`, not `==`, so the secret digit never
            // feeds a compare-and-branch the compiler could emit.
            let mut sel = table[0];
            for (j, entry) in table.iter().enumerate() {
                sel = point_select(&sel, entry, j.ct_eq(&digit));
            }
            acc = self.point_add(&acc, &sel);
        }
        acc
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
            acc = point_select(&acc, &sum, Choice::from(bit));
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
    /// combination: two interleaved (Straus) width-5 wNAF ladders sharing one
    /// run of ~446 doublings, plus one addition per nonzero digit (≈ 1 in 6
    /// per scalar) against the 8 odd multiples `[1]X..[15]X` of each point.
    ///
    /// # Warning: public inputs only
    ///
    /// Both the branch pattern and the table indices leak the scalars. This
    /// must ONLY ever be called with **public** scalars and points (the
    /// signature scalar `S`, the challenge `k` and the public key `A` during
    /// verification) — never with signing nonces or secret keys.
    pub(crate) fn double_scalar_mult_base_vartime(
        &self,
        a: &[u8; 57],
        p: &Point,
        b: &[u8; 57],
    ) -> Point {
        let odd_p = self.odd_multiples(p);
        let odd_b = self.odd_multiples(&self.base());
        let naf_a = wnaf5(a);
        let naf_b = wnaf5(b);
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

/// Width-5 non-adjacent form of a 456-bit (57-byte) little-endian scalar:
/// digits in `{0, ±1, ±3, …, ±15}` with at least 4 zeros between nonzero
/// digits. The trailing positions absorb the recoding carry, so any 456-bit
/// integer is represented exactly. **Variable-time**; only for public
/// scalars.
fn wnaf5(scalar: &[u8; 57]) -> [i8; 461] {
    let mut naf = [0i8; 461];

    // Nine u64 limbs (57 bytes zero-padded, plus one spare) so the window
    // read below may index one limb past the scalar's top byte.
    let mut x = [0u64; 9];
    for (i, chunk) in scalar.chunks(8).enumerate() {
        let mut b = [0u8; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        x[i] = u64::from_le_bytes(b);
    }

    let width = 1u64 << 5;
    let window_mask = width - 1;

    let mut pos = 0;
    let mut carry = 0u64;
    while pos < 456 {
        let idx = pos / 64;
        let bit = pos % 64;
        let bit_buf = if bit < 64 - 5 {
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
        pos += 5;
    }
    // A carry surviving past bit 455 stands for `+2^pos` (pos <= 460).
    if carry != 0 {
        naf[pos] = 1;
    }
    naf
}

/// Constant-time point selection: `b` if `c` is set, else `a`.
pub(crate) fn point_select(a: &Point, b: &Point, c: Choice) -> Point {
    Point {
        x: Fe::conditional_select(&b.x, &a.x, c),
        y: Fe::conditional_select(&b.y, &a.y, c),
        z: Fe::conditional_select(&b.z, &a.z, c),
        t: Fe::conditional_select(&b.t, &a.t, c),
    }
}

#[cfg(test)]
mod tests {
    use super::super::field::BASE_ENC;
    use super::*;

    /// The compile-time base point is exactly the decompression of the
    /// RFC 8032 encoding (same Montgomery-form limbs, `Z = 1`, `T = X·Y`).
    #[test]
    fn const_base_matches_decoded_encoding() {
        let f = Field::new();
        let dec = f.decode(&BASE_ENC).expect("valid base point");
        let b = f.base();
        assert_eq!(b.x, dec.x);
        assert_eq!(b.y, dec.y);
        assert_eq!(b.z, dec.z);
        assert_eq!(b.t, dec.t);
        assert_eq!(f.encode(&b), BASE_ENC);
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
        }
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
