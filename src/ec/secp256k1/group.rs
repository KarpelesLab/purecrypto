//! Projective group arithmetic for secp256k1, generic over a [`FieldBackend`].
//!
//! secp256k1 is the short-Weierstrass curve `y² = x³ + 7` (so `a = 0`,
//! `b = 7`). Because `a = 0`, the `a·X·Z²` terms of the general
//! Renes–Costello–Batina complete-addition formulas vanish; this module uses
//! their specialised **Algorithm 7** (complete addition, `a = 0`) and
//! **Algorithm 9** (complete doubling, `a = 0`) from *"Complete addition
//! formulas for prime order elliptic curves"* (EUROCRYPT 2016). Both are
//! branch-free and correct for all inputs, including the identity and equal
//! points, so the scalar-multiplication ladder needs no special cases.

use super::field_backend::{Fe, FieldBackend};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};

/// The curve constant `b3 = 3·b = 21` for `b = 7`.
const B3: u64 = 21;

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
        let b3 = Fe::from_u64(B3);

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
        t2 = f.mul(&b3, &t2);
        let mut z3 = f.add(&t1, &t2);
        t1 = f.sub(&t1, &t2);
        y3 = f.mul(&b3, &y3);
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
        let b3 = Fe::from_u64(B3);

        let mut t0 = f.square(&p.y);
        let mut z3 = f.add(&t0, &t0);
        z3 = f.add(&z3, &z3);
        z3 = f.add(&z3, &z3);
        let mut t1 = f.mul(&p.y, &p.z);
        let mut t2 = f.square(&p.z);
        t2 = f.mul(&b3, &t2);
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

    /// Constant-time scalar multiplication `scalar · point` (little-endian
    /// limbs) via a fixed 4-bit window: 4 doublings and one *unconditional*
    /// addition per nibble, the window value fetched by a masked scan of all
    /// 16 table entries (no secret-indexed memory access). A zero nibble adds
    /// the identity — a no-op with the same operation sequence, since the RCB
    /// formulas are complete — so, as with the previous double-and-add-always
    /// ladder, the schedule depends only on the public scalar width.
    pub(crate) fn mul<F: FieldBackend>(f: &F, scalar: &[u64; 4], point: &Point) -> Point {
        // table[j] = [j]P; table[0] is the identity.
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
                acc = Point::double(f, &acc);
                acc = Point::double(f, &acc);
                acc = Point::double(f, &acc);
                acc = Point::double(f, &acc);

                let digit = ((limb >> shift) & 0xf) as usize;
                // Constant-time gather of table[digit].
                let mut sel = table[0];
                for (j, entry) in table.iter().enumerate() {
                    sel = Point::conditional_select(entry, &sel, Choice::from((j == digit) as u8));
                }
                acc = Point::add(f, &acc, &sel);
            }
        }
        acc
    }

    /// Converts to affine `(x, y)`, returning `None` for the identity. The
    /// inversion uses the constant-time Fermat inverse from the field backend.
    // Takes `&self` for consistency with the other by-reference point ops.
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_affine<F: FieldBackend>(&self, f: &F) -> Option<(Fe, Fe)> {
        if bool::from(self.is_identity()) {
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
