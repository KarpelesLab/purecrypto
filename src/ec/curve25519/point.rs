//! Edwards25519 curve points in extended homogeneous coordinates.
//!
//! Twisted Edwards curve `−x² + y² = 1 + d·x²·y²` (`a = −1`) over
//! GF(2²⁵⁵−19), in extended coordinates `(X:Y:Z:T)` with the complete
//! Hisil–Wong–Carter–Dawson 2008 addition formulas. Scalar multiplication is a
//! constant-time double-and-add. This is the shared point backend behind
//! Ed25519, the edwards25519 hazmat surface, and ristretto255.

use super::field::{BASE_ENC, Fe, Field};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};

/// A curve point in extended homogeneous coordinates `(X:Y:Z:T)`, all in
/// Montgomery form.
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

    /// Decompresses a 32-byte point encoding (RFC 8032 §5.1.3), or `None` if the
    /// bytes do not encode a curve point.
    pub(crate) fn decode(&self, enc: &[u8; 32]) -> Option<Point> {
        let sign = (enc[31] >> 7) & 1;
        let mut yb = *enc;
        yb[31] &= 0x7f;
        let yval = Fe::from_le_bytes(&yb);
        if !bool::from(yval.ct_lt(&self.p)) {
            return None;
        }
        let y = self.to_mont(&yval);

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

        let xplain = self.from_mont(&x);
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

    /// Compresses a point to its 32-byte encoding.
    pub(crate) fn encode(&self, p: &Point) -> [u8; 32] {
        let zinv = self.inv(p.z);
        let x = self.from_mont(&self.mul(p.x, zinv));
        let y = self.from_mont(&self.mul(p.y, zinv));
        let mut out = [0u8; 32];
        y.write_le_bytes(&mut out);
        out[31] |= x.is_odd().unwrap_u8() << 7;
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
        let c = self.add(self.sq(p.z), self.sq(p.z));
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
    // Used only by the optional edwards25519::hazmat and ristretto255 group
    // APIs; the RFC 8032 Ed25519 path negates via scalars, not points. Gate to
    // silence a dead-code warning on the default (Ed25519-only) build.
    #[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
    pub(crate) fn point_negate(&self, p: &Point) -> Point {
        Point {
            x: self.neg(p.x),
            y: p.y,
            z: p.z,
            t: self.neg(p.t),
        }
    }

    /// Constant-time `[scalar]·p`, scanning the 256-bit little-endian scalar
    /// from the most significant bit. The scalar bytes are treated as secret.
    pub(crate) fn scalar_mult(&self, scalar: &[u8; 32], p: &Point) -> Point {
        let mut acc = self.identity();
        let mut i = 256;
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
    /// representatives via cross-multiplication (so distinct projective
    /// representatives of the same point compare equal): `X₁·Z₂ == X₂·Z₁` and
    /// `Y₁·Z₂ == Y₂·Z₁`.
    // Used only by the edwards25519::hazmat group API (point equality /
    // identity / order checks); gate to silence a dead-code warning on the
    // default build.
    #[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
    pub(crate) fn point_ct_eq(&self, p: &Point, q: &Point) -> Choice {
        let x1z2 = self.mul(p.x, q.z);
        let x2z1 = self.mul(q.x, p.z);
        let y1z2 = self.mul(p.y, q.z);
        let y2z1 = self.mul(q.y, p.z);
        self.ct_eq(x1z2, x2z1) & self.ct_eq(y1z2, y2z1)
    }
}

/// Constant-time point selection: `b` if `c` is set, else `a`. (This crate's
/// `conditional_select(x, y, c)` returns `x` when `c` is set, so the chosen
/// value goes first.)
pub(crate) fn point_select(a: &Point, b: &Point, c: Choice) -> Point {
    Point {
        x: Fe::conditional_select(&b.x, &a.x, c),
        y: Fe::conditional_select(&b.y, &a.y, c),
        z: Fe::conditional_select(&b.z, &a.z, c),
        t: Fe::conditional_select(&b.t, &a.t, c),
    }
}
