//! Edwards448 curve points in extended homogeneous coordinates.
//!
//! Untwisted Edwards curve `x² + y² = 1 + d·x²·y²` (`a = +1`,
//! `d = −39081 mod p`) over GF(2⁴⁴⁸−2²²⁴−1), in extended coordinates
//! `(X:Y:Z:T)` with the complete Hisil–Wong–Carter–Dawson 2008 addition
//! formulas for `a = +1` (single `d`, not `2d`). Because `d` is a non-square
//! the formulas are complete (no exceptional cases). Scalar multiplication is a
//! constant-time double-and-add. This is the shared point backend behind Ed448.

use super::field::{BASE_ENC, Fe, Field};
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
    /// The base point `B`, decompressed from its standard encoding.
    pub(crate) fn base(&self) -> Point {
        self.decode(&BASE_ENC).expect("valid base point")
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
        let c = self.add(self.sq(p.z), self.sq(p.z));
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

    /// Constant-time `[scalar]·p`, scanning the (up to) 448-bit little-endian
    /// scalar from the most significant bit. The scalar bytes are treated as
    /// secret. `scalar` is 57 bytes; only the low 448 bits are consumed (the
    /// Ed448 secret scalar is pruned to fit, and `r < L < 2⁴⁴⁶`).
    pub(crate) fn scalar_mult(&self, scalar: &[u8; 57], p: &Point) -> Point {
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

/// Constant-time point selection: `b` if `c` is set, else `a`.
pub(crate) fn point_select(a: &Point, b: &Point, c: Choice) -> Point {
    Point {
        x: Fe::conditional_select(&b.x, &a.x, c),
        y: Fe::conditional_select(&b.y, &a.y, c),
        z: Fe::conditional_select(&b.z, &a.z, c),
        t: Fe::conditional_select(&b.t, &a.t, c),
    }
}
