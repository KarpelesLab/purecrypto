//! Runtime short-Weierstrass curve arithmetic over [`BoxedUint`].
//!
//! A single implementation serves every supported prime-order curve: the field
//! modulus, coefficients, generator, and order are runtime values (see
//! [`curves`](super::curves)). Point addition uses the Renes–Costello–Batina
//! **complete** formula (Algorithm 1), which is correct for all inputs —
//! including the identity and equal points — and for any coefficient `a`, so
//! both `a = -3` (the NIST curves) and `a = 0` (secp256k1) share one path.

use crate::bignum::{BoxedMontModulus, BoxedUint};
use crate::ct::{Choice, ConstantTimeEq};

/// A point in projective coordinates `(X : Y : Z)`, field elements in
/// Montgomery form. The identity is `(0 : 1 : 0)`.
#[derive(Clone)]
pub(crate) struct Point {
    x: BoxedUint,
    y: BoxedUint,
    z: BoxedUint,
}

impl Point {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Point {
            x: BoxedUint::conditional_select(&a.x, &b.x, choice),
            y: BoxedUint::conditional_select(&a.y, &b.y, choice),
            z: BoxedUint::conditional_select(&a.z, &b.z, choice),
        }
    }
}

/// A prime-order short-Weierstrass curve `y² = x³ + a·x + b (mod p)` with a
/// fixed generator and group order, ready for constant-time arithmetic.
pub(crate) struct Curve {
    fp: BoxedMontModulus,
    a_mont: BoxedUint,
    b3_mont: BoxedUint,
    a_plain: BoxedUint,
    b_plain: BoxedUint,
    one_mont: BoxedUint,
    p_minus_2: BoxedUint,
    gx: BoxedUint,
    gy: BoxedUint,
    n: BoxedUint,
}

impl Curve {
    /// Builds a curve from plain (non-Montgomery) parameters: field modulus `p`,
    /// coefficients `a`/`b`, affine generator `(gx, gy)`, and group order `n`.
    pub(crate) fn new(
        p: BoxedUint,
        a: BoxedUint,
        b: BoxedUint,
        gx: BoxedUint,
        gy: BoxedUint,
        n: BoxedUint,
    ) -> Self {
        let fp = BoxedMontModulus::new(&p);
        let b3 = fp.add_mod(&fp.add_mod(&b, &b), &b); // 3b mod p
        let one = BoxedUint::from_u64(1);
        Curve {
            a_mont: fp.to_mont(&a),
            b3_mont: fp.to_mont(&b3),
            a_plain: a,
            b_plain: b,
            one_mont: fp.to_mont(&one),
            p_minus_2: p.sub(&BoxedUint::from_u64(2)),
            gx,
            gy,
            n,
            fp,
        }
    }

    /// The group order `n`.
    pub(crate) fn order(&self) -> &BoxedUint {
        &self.n
    }

    /// The curve coefficients `(a, b)` in plain (non-Montgomery) form. Used by
    /// SM2's `ZA` computation, which hashes the 32-byte big-endian `a`/`b`.
    pub(crate) fn coefficients(&self) -> (BoxedUint, BoxedUint) {
        (self.a_plain.clone(), self.b_plain.clone())
    }

    /// The identity point `(0 : 1 : 0)`.
    pub(crate) fn identity(&self) -> Point {
        Point {
            x: BoxedUint::zero(self.fp.limbs()),
            y: self.one_mont.clone(),
            z: BoxedUint::zero(self.fp.limbs()),
        }
    }

    /// Lifts an affine point `(x, y)` (plain coordinates) to projective form.
    pub(crate) fn lift_affine(&self, x: &BoxedUint, y: &BoxedUint) -> Point {
        Point {
            x: self.fp.to_mont(x),
            y: self.fp.to_mont(y),
            z: self.one_mont.clone(),
        }
    }

    /// The base point `G`.
    pub(crate) fn generator(&self) -> Point {
        self.lift_affine(&self.gx, &self.gy)
    }

    /// Converts a point to affine `(x, y)` (plain coordinates), or `None` for
    /// the identity. The `z`-inverse uses Fermat's little theorem
    /// (`z^(p-2) mod p`).
    pub(crate) fn to_affine(&self, point: &Point) -> Option<(BoxedUint, BoxedUint)> {
        if point.z.is_zero() {
            return None;
        }
        let z = self.fp.from_mont(&point.z);
        let z_inv = self.fp.pow(&z, &self.p_minus_2);
        let x = self.fp.mul_mod(&self.fp.from_mont(&point.x), &z_inv);
        let y = self.fp.mul_mod(&self.fp.from_mont(&point.y), &z_inv);
        Some((x, y))
    }

    /// Complete projective addition (Renes–Costello–Batina, Algorithm 1).
    /// Correct for all inputs and any `a`.
    pub(crate) fn point_add(&self, p: &Point, q: &Point) -> Point {
        let a = &self.a_mont;
        let b3 = &self.b3_mont;
        let m = |x: &BoxedUint, y: &BoxedUint| self.fp.mont_mul(x, y);
        let add = |x: &BoxedUint, y: &BoxedUint| self.fp.add_mod(x, y);
        let sub = |x: &BoxedUint, y: &BoxedUint| self.fp.sub_mod(x, y);

        // Renes–Costello–Batina "add-2015-rcb", transcribed verbatim.
        let t0 = m(&p.x, &q.x);
        let t1 = m(&p.y, &q.y);
        let t2 = m(&p.z, &q.z);
        let t3 = add(&p.x, &p.y);
        let t4 = add(&q.x, &q.y);
        let t3 = m(&t3, &t4);
        let t4 = add(&t0, &t1);
        let t3 = sub(&t3, &t4);
        let t4 = add(&p.x, &p.z);
        let t5 = add(&q.x, &q.z);
        let t4 = m(&t4, &t5);
        let t5 = add(&t0, &t2);
        let t4 = sub(&t4, &t5);
        let t5 = add(&p.y, &p.z);
        let x3 = add(&q.y, &q.z);
        let t5 = m(&t5, &x3);
        let x3 = add(&t1, &t2);
        let t5 = sub(&t5, &x3);
        let z3 = m(a, &t4);
        let x3 = m(b3, &t2);
        let z3 = add(&x3, &z3);
        let x3 = sub(&t1, &z3);
        let z3 = add(&t1, &z3);
        let y3 = m(&x3, &z3);
        let t1 = add(&t0, &t0);
        let t1 = add(&t1, &t0);
        let t2 = m(a, &t2);
        let t4 = m(b3, &t4);
        let t1 = add(&t1, &t2);
        let t2 = sub(&t0, &t2);
        let t2 = m(a, &t2);
        let t4 = add(&t4, &t2);
        let t0 = m(&t1, &t4);
        let y3 = add(&y3, &t0);
        let t0 = m(&t5, &t4);
        let x3 = m(&t3, &x3);
        let x3 = sub(&x3, &t0);
        let t0 = m(&t3, &t1);
        let z3 = m(&t5, &z3);
        let z3 = add(&z3, &t0);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn double(&self, p: &Point) -> Point {
        self.point_add(p, p)
    }

    /// Constant-time `scalar * point` via double-and-add-always over a fixed
    /// number of bits (the order's bit width).
    pub(crate) fn scalar_mul(&self, scalar: &BoxedUint, point: &Point) -> Point {
        let order_limbs = self.n.bit_len().div_ceil(64);
        let limbs = scalar.as_limbs();
        let mut acc = self.identity();
        let mut i = order_limbs;
        while i > 0 {
            i -= 1;
            let limb = limbs.get(i).copied().unwrap_or(0);
            let mut bit = 64;
            while bit > 0 {
                bit -= 1;
                acc = self.double(&acc);
                let sum = self.point_add(&acc, point);
                let set = Choice::from(((limb >> bit) & 1) as u8);
                acc = Point::conditional_select(&sum, &acc, set);
            }
        }
        acc
    }

    /// Convenience: `scalar * G`.
    pub(crate) fn mul_generator(&self, scalar: &BoxedUint) -> Point {
        let g = self.generator();
        self.scalar_mul(scalar, &g)
    }

    /// Whether affine `(x, y)` (plain coordinates, each `< p`) satisfies
    /// `y² = x³ + a·x + b (mod p)`.
    pub(crate) fn is_on_curve(&self, x: &BoxedUint, y: &BoxedUint) -> bool {
        let lhs = self.fp.mul_mod(y, y);
        let x2 = self.fp.mul_mod(x, x);
        let x3 = self.fp.mul_mod(&x2, x);
        let ax = self.fp.mul_mod(&self.a_plain, x);
        let rhs = self.fp.add_mod(&self.fp.add_mod(&x3, &ax), &self.b_plain);
        bool::from(lhs.ct_eq(&rhs))
    }

    /// Whether `v` is a valid field element (`v < p`).
    pub(crate) fn in_field(&self, v: &BoxedUint) -> bool {
        // v < p  ⟺  v mod p == v.
        v.reduce(&self.fp.modulus()) == *v
    }
}
