//! Runtime short-Weierstrass curve arithmetic over [`BoxedUint`].
//!
//! A single implementation serves every supported prime-order curve: the field
//! modulus, coefficients, generator, and order are runtime values (see
//! [`curves`](super::curves)). Point addition uses the Renes–Costello–Batina
//! **complete** formula (Algorithm 1), which is correct for all inputs —
//! including the identity and equal points — and for any coefficient `a`, so
//! both `a = -3` (the NIST curves) and `a = 0` (secp256k1) share one path.

use crate::bignum::{BoxedMontModulus, BoxedUint, Limb};
use crate::ct::{ConditionallySelectable, ConstantTimeEq};
use alloc::vec;
use alloc::vec::Vec;

/// A point in projective coordinates `(X : Y : Z)`, field elements in
/// Montgomery form. The identity is `(0 : 1 : 0)`.
#[derive(Clone)]
pub(crate) struct Point {
    x: BoxedUint,
    y: BoxedUint,
    z: BoxedUint,
}

impl Point {
    /// Constant-time `table[digit]` for coordinates `limbs` wide: every
    /// entry is read in a fixed order and masked into one fresh buffer per
    /// coordinate, so neither the access pattern nor the timing depends on
    /// `digit` (the index test is `ct_eq`, not a `==` the compiler may lower
    /// to a branch). Masking limbs in place costs three allocations per
    /// lookup where chaining `BoxedUint::conditional_select` cost three per
    /// entry and coordinate. Exactly one entry matches (`digit < table.len()`),
    /// so starting from zero is sound.
    fn ct_lookup(table: &[Point], digit: usize, limbs: usize) -> Point {
        let mut out = [vec![0 as Limb; limbs], vec![0; limbs], vec![0; limbs]];
        for (j, entry) in table.iter().enumerate() {
            let hit = j.ct_eq(&digit);
            for (dst, src) in out.iter_mut().zip([&entry.x, &entry.y, &entry.z]) {
                let src = src.as_limbs();
                for (i, d) in dst.iter_mut().enumerate() {
                    // The limb index is public; widths are those of the
                    // (public) field.
                    let s = src.get(i).copied().unwrap_or(0);
                    *d = Limb::conditional_select(&s, d, hit);
                }
            }
        }
        let [x, y, z] = out;
        Point {
            x: BoxedUint::from_limbs(x),
            y: BoxedUint::from_limbs(y),
            z: BoxedUint::from_limbs(z),
        }
    }

    /// Wipes the coordinates (a scalar-multiplication intermediate is as
    /// secret as the scalar that produced it).
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}

/// Which specialised Renes–Costello–Batina formulas the coefficient `a`
/// admits. Public curve data: the choice is fixed per curve.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ACoeff {
    /// `a = 0` (secp256k1, the Koblitz curves): Algorithms 7 / 9.
    Zero,
    /// `a = −3` (NIST, SM2, the SEC 2 `r` curves): Algorithms 4 / 6.
    MinusThree,
    /// Anything else (Brainpool): the general Algorithms 1 / 3.
    General,
}

/// A prime-order short-Weierstrass curve `y² = x³ + a·x + b (mod p)` with a
/// fixed generator and group order, ready for constant-time arithmetic.
pub(crate) struct Curve {
    fp: BoxedMontModulus,
    a_kind: ACoeff,
    a_mont: BoxedUint,
    b_mont: BoxedUint,
    b3_mont: BoxedUint,
    a_plain: BoxedUint,
    b_plain: BoxedUint,
    one_mont: BoxedUint,
    p_minus_2: BoxedUint,
    gx: BoxedUint,
    gy: BoxedUint,
    n: BoxedUint,
    /// Montgomery context for the group order, for the scalar arithmetic
    /// (`mod n`) of the signature schemes built on this curve.
    fq: BoxedMontModulus,
    n_minus_2: BoxedUint,
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
        let fq = BoxedMontModulus::new(&n);
        let a_kind = if a.is_zero() {
            ACoeff::Zero
        } else if a == p.sub(&BoxedUint::from_u64(3)) {
            ACoeff::MinusThree
        } else {
            ACoeff::General
        };
        Curve {
            fq,
            a_kind,
            b_mont: fp.to_mont(&b),
            n_minus_2: n.sub(&BoxedUint::from_u64(2)),
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

    /// The Montgomery context for arithmetic modulo the group order `n`.
    pub(crate) fn order_modulus(&self) -> &BoxedMontModulus {
        &self.fq
    }

    /// `a⁻¹ mod n` via Fermat (`a^(n-2)`, `n` prime): the constant-time
    /// fixed-window exponentiation, so `a` may be secret (a nonce).
    pub(crate) fn invert_scalar(&self, a: &BoxedUint) -> BoxedUint {
        self.fq.pow(a, &self.n_minus_2)
    }

    /// The field modulus `p`.
    pub(crate) fn field_modulus(&self) -> BoxedUint {
        self.fp.modulus()
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
        // `z` is secret-derived (it is the tail of a scalar multiplication),
        // so the identity test must not short-circuit on the first non-zero
        // limb the way `BoxedUint::is_zero` does: fold every limb first. The
        // verdict is public in every caller: on these prime-order curves
        // `[k]P` is the identity iff `k ≡ 0 (mod n)` or `P` is — a
        // degenerate scalar or peer the caller rejects as an error.
        if point.z.ct_is_zero().declassify() {
            return None;
        }
        let z = self.fp.from_mont(&point.z);
        let z_inv = self.fp.pow(&z, &self.p_minus_2);
        let x = self.fp.mul_mod(&self.fp.from_mont(&point.x), &z_inv);
        let y = self.fp.mul_mod(&self.fp.from_mont(&point.y), &z_inv);
        Some((x, y))
    }

    /// Recovers the affine point `(x, y)` with the requested Y parity from a
    /// compressed x-coordinate, or `None` if `x` is not on the curve.
    ///
    /// The square root of `rhs = x³ + a·x + b` is `rhs^((p+1)/4)` when
    /// `p ≡ 3 (mod 4)` (every curve but P-224 and secp224k1) and a
    /// Tonelli–Shanks root otherwise; either way the result is verified
    /// (`y² == rhs`, which also rejects an `x` that is not a valid abscissa)
    /// and the root of the requested parity is returned (`p − y` flips it).
    /// The x-coordinate of a public key is not secret, so variable-time
    /// exponentiation is fine.
    pub(crate) fn decompress(&self, x: &BoxedUint, y_odd: bool) -> Option<(BoxedUint, BoxedUint)> {
        if !self.in_field(x) {
            return None;
        }
        // rhs = x³ + a·x + b   (plain residues mod p)
        let x2 = self.fp.mul_mod(x, x);
        let x3 = self.fp.mul_mod(&x2, x);
        let ax = self.fp.mul_mod(&self.a_plain, x);
        let rhs = self.fp.add_mod(&self.fp.add_mod(&x3, &ax), &self.b_plain);
        let p = self.field_modulus();
        let y = if (p.as_limbs()[0] & 3) == 3 {
            // exp = (p + 1) / 4.
            let exp = p.add(&BoxedUint::from_u64(1)).shr_bits(2);
            self.fp.pow_public(&rhs, &exp)
        } else {
            self.sqrt_tonelli_shanks(&rhs, &p)?
        };
        // Reject non-residues / off-curve abscissae.
        if self.fp.mul_mod(&y, &y) != rhs {
            return None;
        }
        let y = if y.is_odd() == y_odd { y } else { p.sub(&y) };
        Some((x.clone(), y))
    }

    /// Tonelli–Shanks square root of `a` modulo the field prime `p`, for any
    /// odd `p` (needed for `p ≡ 1 (mod 4)`: P-224 has `p − 1 = 2⁹⁶·q`,
    /// secp224k1 `p ≡ 5 (mod 8)`). Returns `None` when `a` is a
    /// non-residue. Variable-time: the input is a public abscissa.
    fn sqrt_tonelli_shanks(&self, a: &BoxedUint, p: &BoxedUint) -> Option<BoxedUint> {
        let one = BoxedUint::from_u64(1);
        let p_minus_1 = p.sub(&one);
        if a.is_zero() {
            return Some(BoxedUint::zero(self.fp.limbs()));
        }
        // p − 1 = q · 2^s with q odd.
        let mut q = p_minus_1.clone();
        let mut s = 0usize;
        while !q.is_odd() {
            q = q.shr_bits(1);
            s += 1;
        }
        // Euler's criterion on `a` first: a^((p−1)/2) must be 1.
        let half = p_minus_1.shr_bits(1);
        if self.fp.pow_public(a, &half) != one {
            return None;
        }
        // A quadratic non-residue z (the smallest integer works; there is
        // one below 2·ln²p, so the scan is short and depends only on p).
        let mut z = BoxedUint::from_u64(2);
        while self.fp.pow_public(&z, &half) == one {
            z = z.add(&one);
        }
        let mut c = self.fp.pow_public(&z, &q);
        let mut t = self.fp.pow_public(a, &q);
        let mut r = self.fp.pow_public(a, &q.add(&one).shr_bits(1));
        let mut m = s;
        while t != one {
            // Least i in (0, m) with t^(2^i) == 1.
            let mut i = 0usize;
            let mut t2 = t.clone();
            while t2 != one {
                t2 = self.fp.mul_mod(&t2, &t2);
                i += 1;
                if i >= m {
                    return None;
                }
            }
            // b = c^(2^(m − i − 1)).
            let mut b = c;
            for _ in 0..(m - i - 1) {
                b = self.fp.mul_mod(&b, &b);
            }
            m = i;
            c = self.fp.mul_mod(&b, &b);
            t = self.fp.mul_mod(&t, &c);
            r = self.fp.mul_mod(&r, &b);
        }
        Some(r)
    }

    /// Complete projective addition `p + q`, correct for all inputs
    /// (including `p == q` and the identity), through the cheapest
    /// Renes–Costello–Batina formula the curve's `a` admits. Every branch is
    /// straight-line field arithmetic; which one runs depends only on the
    /// (public) curve.
    pub(crate) fn point_add(&self, p: &Point, q: &Point) -> Point {
        match self.a_kind {
            ACoeff::MinusThree => self.add_a_minus_3(p, q),
            ACoeff::Zero => self.add_a_zero(p, q),
            ACoeff::General => self.add_general(p, q),
        }
    }

    /// Complete projective doubling `2·p`, correct for all inputs including
    /// the identity: RCB Algorithm 6 (`a = −3`, 8M + 3S + 2·m_b),
    /// 9 (`a = 0`, 6M + 2S + m_3b) or 3 (any `a`), against the 12M + 5·m_a,b
    /// of `point_add(p, p)`.
    fn double(&self, p: &Point) -> Point {
        match self.a_kind {
            ACoeff::MinusThree => self.double_a_minus_3(p),
            ACoeff::Zero => self.double_a_zero(p),
            ACoeff::General => self.double_general(p),
        }
    }

    /// RCB Algorithm 4: complete addition for `a = −3`.
    fn add_a_minus_3(&self, p: &Point, q: &Point) -> Point {
        let b = &self.b_mont;
        let m = |x: &BoxedUint, y: &BoxedUint| self.fp.mont_mul(x, y);
        let add = |x: &BoxedUint, y: &BoxedUint| self.fp.add_mod(x, y);
        let sub = |x: &BoxedUint, y: &BoxedUint| self.fp.sub_mod(x, y);

        let t0 = m(&p.x, &q.x);
        let t1 = m(&p.y, &q.y);
        let t2 = m(&p.z, &q.z);
        let t3 = add(&p.x, &p.y);
        let t4 = add(&q.x, &q.y);
        let t3 = m(&t3, &t4);
        let t4 = add(&t0, &t1);
        let t3 = sub(&t3, &t4);
        let t4 = add(&p.y, &p.z);
        let x3 = add(&q.y, &q.z);
        let t4 = m(&t4, &x3);
        let x3 = add(&t1, &t2);
        let t4 = sub(&t4, &x3);
        let x3 = add(&p.x, &p.z);
        let y3 = add(&q.x, &q.z);
        let x3 = m(&x3, &y3);
        let y3 = add(&t0, &t2);
        let y3 = sub(&x3, &y3);
        let z3 = m(b, &t2);
        let x3 = sub(&y3, &z3);
        let z3 = add(&x3, &x3);
        let x3 = add(&x3, &z3);
        let z3 = sub(&t1, &x3);
        let x3 = add(&t1, &x3);
        let y3 = m(b, &y3);
        let t1 = add(&t2, &t2);
        let t2 = add(&t1, &t2);
        let y3 = sub(&y3, &t2);
        let y3 = sub(&y3, &t0);
        let t1 = add(&y3, &y3);
        let y3 = add(&t1, &y3);
        let t1 = add(&t0, &t0);
        let t0 = add(&t1, &t0);
        let t0 = sub(&t0, &t2);
        let t1 = m(&t4, &y3);
        let t2 = m(&t0, &y3);
        let y3 = m(&x3, &z3);
        let y3 = add(&y3, &t2);
        let x3 = m(&t3, &x3);
        let x3 = sub(&x3, &t1);
        let z3 = m(&t4, &z3);
        let t1 = m(&t3, &t0);
        let z3 = add(&z3, &t1);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// RCB Algorithm 7: complete addition for `a = 0`.
    fn add_a_zero(&self, p: &Point, q: &Point) -> Point {
        let b3 = &self.b3_mont;
        let m = |x: &BoxedUint, y: &BoxedUint| self.fp.mont_mul(x, y);
        let add = |x: &BoxedUint, y: &BoxedUint| self.fp.add_mod(x, y);
        let sub = |x: &BoxedUint, y: &BoxedUint| self.fp.sub_mod(x, y);

        let t0 = m(&p.x, &q.x);
        let t1 = m(&p.y, &q.y);
        let t2 = m(&p.z, &q.z);
        let t3 = add(&p.x, &p.y);
        let t4 = add(&q.x, &q.y);
        let t3 = m(&t3, &t4);
        let t4 = add(&t0, &t1);
        let t3 = sub(&t3, &t4);
        let t4 = add(&p.y, &p.z);
        let x3 = add(&q.y, &q.z);
        let t4 = m(&t4, &x3);
        let x3 = add(&t1, &t2);
        let t4 = sub(&t4, &x3);
        let x3 = add(&p.x, &p.z);
        let y3 = add(&q.x, &q.z);
        let x3 = m(&x3, &y3);
        let y3 = add(&t0, &t2);
        let y3 = sub(&x3, &y3);
        let x3 = add(&t0, &t0);
        let t0 = add(&x3, &t0);
        let t2 = m(b3, &t2);
        let z3 = add(&t1, &t2);
        let t1 = sub(&t1, &t2);
        let y3 = m(b3, &y3);
        let x3 = m(&t4, &y3);
        let t2 = m(&t3, &t1);
        let x3 = sub(&t2, &x3);
        let y3 = m(&y3, &t0);
        let t1 = m(&t1, &z3);
        let y3 = add(&t1, &y3);
        let t0 = m(&t0, &t3);
        let z3 = m(&z3, &t4);
        let z3 = add(&z3, &t0);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// RCB Algorithm 6: complete doubling for `a = −3`.
    fn double_a_minus_3(&self, p: &Point) -> Point {
        let b = &self.b_mont;
        let m = |x: &BoxedUint, y: &BoxedUint| self.fp.mont_mul(x, y);
        let add = |x: &BoxedUint, y: &BoxedUint| self.fp.add_mod(x, y);
        let sub = |x: &BoxedUint, y: &BoxedUint| self.fp.sub_mod(x, y);

        let t0 = m(&p.x, &p.x);
        let t1 = m(&p.y, &p.y);
        let t2 = m(&p.z, &p.z);
        let t3 = m(&p.x, &p.y);
        let t3 = add(&t3, &t3);
        let z3 = m(&p.x, &p.z);
        let z3 = add(&z3, &z3);
        let y3 = m(b, &t2);
        let y3 = sub(&y3, &z3);
        let x3 = add(&y3, &y3);
        let y3 = add(&x3, &y3);
        let x3 = sub(&t1, &y3);
        let y3 = add(&t1, &y3);
        let y3 = m(&x3, &y3);
        let x3 = m(&x3, &t3);
        let t3 = add(&t2, &t2);
        let t2 = add(&t2, &t3);
        let z3 = m(b, &z3);
        let z3 = sub(&z3, &t2);
        let z3 = sub(&z3, &t0);
        let t3 = add(&z3, &z3);
        let z3 = add(&z3, &t3);
        let t3 = add(&t0, &t0);
        let t0 = add(&t3, &t0);
        let t0 = sub(&t0, &t2);
        let t0 = m(&t0, &z3);
        let y3 = add(&y3, &t0);
        let t0 = m(&p.y, &p.z);
        let t0 = add(&t0, &t0);
        let z3 = m(&t0, &z3);
        let x3 = sub(&x3, &z3);
        let z3 = m(&t0, &t1);
        let z3 = add(&z3, &z3);
        let z3 = add(&z3, &z3);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// RCB Algorithm 9: complete doubling for `a = 0`.
    fn double_a_zero(&self, p: &Point) -> Point {
        let b3 = &self.b3_mont;
        let m = |x: &BoxedUint, y: &BoxedUint| self.fp.mont_mul(x, y);
        let add = |x: &BoxedUint, y: &BoxedUint| self.fp.add_mod(x, y);
        let sub = |x: &BoxedUint, y: &BoxedUint| self.fp.sub_mod(x, y);

        let t0 = m(&p.y, &p.y);
        let z3 = add(&t0, &t0);
        let z3 = add(&z3, &z3);
        let z3 = add(&z3, &z3);
        let t1 = m(&p.y, &p.z);
        let t2 = m(&p.z, &p.z);
        let t2 = m(b3, &t2);
        let x3 = m(&t2, &z3);
        let y3 = add(&t0, &t2);
        let z3 = m(&t1, &z3);
        let t1 = add(&t2, &t2);
        let t2 = add(&t1, &t2);
        let t0 = sub(&t0, &t2);
        let y3 = m(&t0, &y3);
        let y3 = add(&x3, &y3);
        let t1 = m(&p.x, &p.y);
        let x3 = m(&t0, &t1);
        let x3 = add(&x3, &x3);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// RCB Algorithm 3: complete doubling for any `a`.
    fn double_general(&self, p: &Point) -> Point {
        let a = &self.a_mont;
        let b3 = &self.b3_mont;
        let m = |x: &BoxedUint, y: &BoxedUint| self.fp.mont_mul(x, y);
        let add = |x: &BoxedUint, y: &BoxedUint| self.fp.add_mod(x, y);
        let sub = |x: &BoxedUint, y: &BoxedUint| self.fp.sub_mod(x, y);

        let t0 = m(&p.x, &p.x);
        let t1 = m(&p.y, &p.y);
        let t2 = m(&p.z, &p.z);
        let t3 = m(&p.x, &p.y);
        let t3 = add(&t3, &t3);
        let z3 = m(&p.x, &p.z);
        let z3 = add(&z3, &z3);
        let x3 = m(a, &z3);
        let y3 = m(b3, &t2);
        let y3 = add(&x3, &y3);
        let x3 = sub(&t1, &y3);
        let y3 = add(&t1, &y3);
        let y3 = m(&x3, &y3);
        let x3 = m(&t3, &x3);
        let z3 = m(b3, &z3);
        let t2 = m(a, &t2);
        let t3 = sub(&t0, &t2);
        let t3 = m(a, &t3);
        let t3 = add(&t3, &z3);
        let z3 = add(&t0, &t0);
        let t0 = add(&z3, &t0);
        let t0 = add(&t0, &t2);
        let t0 = m(&t0, &t3);
        let y3 = add(&y3, &t0);
        let t2 = m(&p.y, &p.z);
        let t2 = add(&t2, &t2);
        let t0 = m(&t2, &t3);
        let x3 = sub(&x3, &t0);
        let z3 = m(&t2, &t1);
        let z3 = add(&z3, &z3);
        let z3 = add(&z3, &z3);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Complete projective addition (Renes–Costello–Batina, Algorithm 1).
    /// Correct for all inputs and any `a`; also the tests' oracle for the
    /// specialised formulas.
    fn add_general(&self, p: &Point, q: &Point) -> Point {
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

    /// Constant-time `scalar * point` over a fixed number of bits (the
    /// order's bit width), via a fixed 4-bit window: 4 doublings and one
    /// *unconditional* addition per nibble, the window value fetched by a
    /// masked scan of all 16 table entries (no secret-indexed memory
    /// access). A zero nibble adds the identity — a no-op with the same
    /// operation sequence, since the RCB Algorithm 1 formulas are complete —
    /// so, as with the previous double-and-add-always ladder, the schedule
    /// depends only on the public order width.
    pub(crate) fn scalar_mul(&self, scalar: &BoxedUint, point: &Point) -> Point {
        // The ladder below iterates only over the order's limb width, so a
        // scalar wider than `n` would have its high limbs silently dropped:
        // the previous `debug_assert` caught that in debug builds only, and
        // release quietly computed `[k mod 2^(64·order_limbs)]P`. Reduce
        // unconditionally instead, making the precondition load-bearing. The
        // reduction is constant-time long division whose iteration count
        // depends only on the *allocated* limb width (never on the secret
        // value), and it also normalises the result to exactly the order's
        // limb width. All in-tree callers already pre-reduce, so this is a
        // value-preserving pass costing a few hundred limb operations next to
        // ~4·bits point operations below.
        let mut scalar = scalar.reduce(&self.n);
        // table[j] = [j]P; table[0] is the identity.
        let mut table = alloc::vec::Vec::with_capacity(16);
        table.push(self.identity());
        table.push(point.clone());
        for i in 2..16 {
            table.push(self.point_add(&table[i - 1], point));
        }

        let order_limbs = self.n.bit_len().div_ceil(64);
        let limbs = scalar.as_limbs();
        let mut acc = self.identity();
        let mut i = order_limbs;
        while i > 0 {
            i -= 1;
            let limb = limbs.get(i).copied().unwrap_or(0);
            let mut shift = 64;
            while shift > 0 {
                shift -= 4;
                acc = self.double(&acc);
                acc = self.double(&acc);
                acc = self.double(&acc);
                acc = self.double(&acc);

                let digit = ((limb >> shift) & 0xf) as usize;
                let mut sel = Point::ct_lookup(&table, digit, self.fp.limbs());
                acc = self.point_add(&acc, &sel);
                sel.zeroize();
            }
        }
        // The reduced scalar and the multiples of `P` are secret whenever the
        // scalar is; wipe them rather than leaving them in freed heap memory.
        scalar.zeroize();
        for entry in table.iter_mut() {
            entry.zeroize();
        }
        acc
    }

    /// `-p`: `(X : −Y : Z)`.
    fn negate(&self, p: &Point) -> Point {
        Point {
            x: p.x.clone(),
            y: self.fp.sub_mod(&BoxedUint::zero(1), &p.y),
            z: p.z.clone(),
        }
    }

    /// The odd multiples `[1]P, [3]P, …, [15]P` for a width-5 wNAF ladder.
    fn odd_multiples(&self, p: &Point) -> Vec<Point> {
        let two_p = self.double(p);
        let mut table = Vec::with_capacity(8);
        table.push(p.clone());
        for i in 1..8 {
            let next = self.point_add(&table[i - 1], &two_p);
            table.push(next);
        }
        table
    }

    /// **VARIABLE-TIME** `u1·G + u2·Q`: width-5 wNAF recodings of both
    /// scalars interleaved over one run of doublings (Straus–Shamir), with
    /// zero digits skipped and the table indexed directly.
    ///
    /// Only for **public** inputs — signature verification and public-key
    /// recovery, where the scalars, the point and the result are all known
    /// to (or computable by) an observer, so timing reveals nothing. Signing,
    /// key derivation and ECDH keep the constant-time [`Self::scalar_mul`].
    /// The tables are 16 points (a few KB at P-521, transient).
    pub(crate) fn mul_double_vartime(&self, u1: &BoxedUint, u2: &BoxedUint, q: &Point) -> Point {
        let naf1 = wnaf5(u1);
        let naf2 = wnaf5(u2);
        let digit = |naf: &[i8], i: usize| naf.get(i).copied().unwrap_or(0);
        let len = naf1.len().max(naf2.len());
        let Some(top) = (0..len)
            .rev()
            .find(|&i| digit(&naf1, i) != 0 || digit(&naf2, i) != 0)
        else {
            return self.identity();
        };
        let odd_g = self.odd_multiples(&self.generator());
        let odd_q = self.odd_multiples(q);
        let mut acc = self.identity();
        for i in (0..=top).rev() {
            acc = self.double(&acc);
            for (naf, odd) in [(&naf1, &odd_g), (&naf2, &odd_q)] {
                let d = digit(naf, i);
                if d > 0 {
                    acc = self.point_add(&acc, &odd[(d as usize - 1) / 2]);
                } else if d < 0 {
                    let neg = self.negate(&odd[((-d) as usize - 1) / 2]);
                    acc = self.point_add(&acc, &neg);
                }
            }
        }
        acc
    }

    /// **VARIABLE-TIME** test that `point`'s affine x-coordinate is
    /// congruent to `v` modulo the group order (`v < n`), without the field
    /// inversion of [`Self::to_affine`]: `x = X/Z ≡ v (mod n)` with `x < p <
    /// 2n` (cofactor 1, so Hasse gives `n > p/2`) means `x ∈ {v, v + n}`, and
    /// each candidate `c < p` is checked as `c·Z == X`. The identity never
    /// matches. Public inputs only (the ECDSA / SM2 verification equations).
    pub(crate) fn affine_x_eq_mod_n(&self, point: &Point, v: &BoxedUint) -> bool {
        if point.z.is_zero() {
            return false;
        }
        let p = self.field_modulus();
        let mut cand = v.clone();
        for _ in 0..2 {
            if !cand.lt(&p) {
                break;
            }
            if self.fp.mont_mul(&self.fp.to_mont(&cand), &point.z) == point.x {
                return true;
            }
            cand = cand.add(&self.n);
        }
        false
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
        // `v` is a public coordinate, so the variable-time compare is fine.
        v.lt(&self.fp.modulus())
    }
}

/// Width-5 wNAF recoding of `k`, least-significant digit first: digits in
/// `{0, ±1, ±3, …, ±15}`, any two nonzero digits at least five positions
/// apart. **Variable time** in `k` — public scalars only.
fn wnaf5(k: &BoxedUint) -> Vec<i8> {
    // One spare limb absorbs the carry of `k + 15`.
    let mut limbs = k.as_limbs().to_vec();
    limbs.push(0);
    let mut naf = Vec::with_capacity(64 * limbs.len());
    while limbs.iter().any(|&l| l != 0) {
        let mut d = 0i8;
        if limbs[0] & 1 == 1 {
            let low = (limbs[0] & 31) as i8;
            d = if low > 16 { low - 32 } else { low };
            // k -= d, making the low five bits zero.
            let (mut borrow, mut carry) = if d > 0 {
                (d as u64, 0)
            } else {
                (0, (-d) as u64)
            };
            for l in limbs.iter_mut() {
                let (v, b) = l.overflowing_sub(borrow);
                let (v, c) = v.overflowing_add(carry);
                *l = v;
                borrow = b as u64;
                carry = c as u64;
            }
        }
        naf.push(d);
        // k >>= 1
        let mut hi = 0;
        for l in limbs.iter_mut().rev() {
            let next = *l & 1;
            *l = (*l >> 1) | (hi << 63);
            hi = next;
        }
    }
    naf
}

#[cfg(test)]
// `CurveRef` is a plain reference only with `std`; without it the `&c`
// borrows below are needed.
#[allow(clippy::needless_borrow)]
mod tests {
    use super::*;
    use crate::ec::curves::CurveId;
    use alloc::vec;
    use alloc::vec::Vec;

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A random non-zero field element in Montgomery form.
    fn rand_fe(c: &Curve, st: &mut u64) -> BoxedUint {
        loop {
            let limbs = (0..c.fp.limbs()).map(|_| splitmix64(st)).collect();
            let v = BoxedUint::from_limbs(limbs).reduce(&c.field_modulus());
            if !v.is_zero() {
                return c.fp.to_mont(&v);
            }
        }
    }

    /// The same point under a random projective scaling `(λX : λY : λZ)`.
    fn rescale(c: &Curve, p: &Point, st: &mut u64) -> Point {
        let l = rand_fe(c, st);
        Point {
            x: c.fp.mont_mul(&p.x, &l),
            y: c.fp.mont_mul(&p.y, &l),
            z: c.fp.mont_mul(&p.z, &l),
        }
    }

    fn neg(c: &Curve, p: &Point) -> Point {
        Point {
            x: p.x.clone(),
            y: c.fp.sub_mod(&BoxedUint::zero(1), &p.y),
            z: p.z.clone(),
        }
    }

    /// The specialised RCB formulas (Algorithms 3/4/6/7/9) against the
    /// general complete addition (Algorithm 1), on every curve: identity,
    /// equal, opposite and unrelated points, each under random projective
    /// representatives.
    /// The masked gather returns exactly `table[digit]`, including for an
    /// entry stored narrower than the field (its missing limbs read as 0).
    #[test]
    fn ct_lookup_selects_the_entry() {
        let c = CurveId::P384.curve();
        let w = c.fp.limbs();
        let mut table = vec![Point {
            x: BoxedUint::from_u64(7),
            y: BoxedUint::from_u64(8),
            z: BoxedUint::from_u64(9),
        }];
        let mut st = 0x100c_u64;
        for _ in 1..16 {
            table.push(Point {
                x: rand_fe(&c, &mut st),
                y: rand_fe(&c, &mut st),
                z: rand_fe(&c, &mut st),
            });
        }
        for (d, e) in table.iter().enumerate() {
            let got = Point::ct_lookup(&table, d, w);
            assert_eq!(got.x.limbs(), w);
            assert!(got.x == e.x && got.y == e.y && got.z == e.z, "digit {d}");
        }
    }

    /// The variable-time double-scalar multiplication against the
    /// constant-time ladder, and the inversion-free x-coordinate test
    /// against `to_affine`, on every curve with edge and random scalars.
    #[test]
    fn vartime_double_mul_matches_constant_time() {
        let mut st = 0xd0b1_u64;
        for &id in CurveId::ALL {
            let c: &Curve = &id.curve();
            let n = c.order().clone();
            let one = BoxedUint::from_u64(1);
            let rand_scalar = |st: &mut u64| {
                let limbs = (0..n.limbs()).map(|_| splitmix64(st)).collect();
                BoxedUint::from_limbs(limbs).reduce(&n)
            };
            let q = c.scalar_mul(&rand_scalar(&mut st), &c.generator());
            let q = rescale(c, &q, &mut st);
            let mut pairs = vec![
                (BoxedUint::zero(1), BoxedUint::zero(1)),
                (one.clone(), BoxedUint::zero(1)),
                (BoxedUint::zero(1), n.sub(&one)),
                (n.sub(&one), n.sub(&one)),
            ];
            pairs.push((rand_scalar(&mut st), rand_scalar(&mut st)));
            for (u1, u2) in &pairs {
                let fast = c.mul_double_vartime(u1, u2, &q);
                let slow = c.point_add(&c.mul_generator(u1), &c.scalar_mul(u2, &q));
                let aff = c.to_affine(&slow);
                assert_eq!(c.to_affine(&fast), aff, "{id:?}");
                // x mod n against the affine value, plus a near miss.
                let p = c.field_modulus();
                for v in [BoxedUint::zero(1), one.clone(), n.sub(&one)] {
                    let want = aff.as_ref().is_some_and(|(x, _)| x.reduce(&n) == v);
                    assert_eq!(c.affine_x_eq_mod_n(&fast, &v), want, "{id:?}");
                }
                if let Some((x, _)) = &aff {
                    let v = x.reduce(&n);
                    assert!(c.affine_x_eq_mod_n(&fast, &v), "{id:?}");
                    let off = c.fp.add_mod(&v.reduce(&p), &one).reduce(&n);
                    assert!(!c.affine_x_eq_mod_n(&fast, &off), "{id:?}");
                }
            }
        }
    }

    /// wNAF digits reconstruct the scalar and respect the window rules.
    #[test]
    fn wnaf5_reconstructs() {
        let mut st = 0x7a7a_u64;
        for len in [1usize, 4, 6, 9] {
            for _ in 0..20 {
                let k = BoxedUint::from_limbs((0..len).map(|_| splitmix64(&mut st)).collect());
                let naf = wnaf5(&k);
                // Horner from the top digit: acc = 2·acc + d, tracked as
                // (positive part, negative part) to stay unsigned.
                let (mut pos, mut neg) = (BoxedUint::zero(1), BoxedUint::zero(1));
                let mut last = None;
                for (i, &d) in naf.iter().enumerate().rev() {
                    pos = pos.add(&pos);
                    neg = neg.add(&neg);
                    if d != 0 {
                        assert!(d % 2 != 0 && (-15..=15).contains(&d));
                        if let Some(j) = last {
                            assert!(j - i >= 5);
                        }
                        last = Some(i);
                        if d > 0 {
                            pos = pos.add(&BoxedUint::from_u64(d as u64));
                        } else {
                            neg = neg.add(&BoxedUint::from_u64((-d) as u64));
                        }
                    }
                }
                assert!(pos.sub(&neg) == k);
            }
        }
    }

    #[test]
    fn coefficient_classes() {
        for (id, kind) in [
            (CurveId::P256, ACoeff::MinusThree),
            (CurveId::P384, ACoeff::MinusThree),
            (CurveId::P521, ACoeff::MinusThree),
            (CurveId::Sm2p256v1, ACoeff::MinusThree),
            (CurveId::Secp256k1, ACoeff::Zero),
            (CurveId::BrainpoolP256r1, ACoeff::General),
        ] {
            assert_eq!(id.curve().a_kind, kind, "{id:?}");
        }
    }

    #[test]
    fn specialised_formulas_match_general_addition() {
        let mut st = 0xadd5_u64;
        for &id in CurveId::ALL {
            let c: &Curve = &id.curve();
            let g = c.generator();
            let mut pts = vec![c.identity(), g.clone()];
            let mut acc = g.clone();
            for _ in 0..6 {
                acc = c.add_general(&c.add_general(&acc, &acc), &g);
                pts.push(rescale(c, &acc, &mut st));
            }
            let negs: Vec<Point> = pts.iter().map(|p| neg(c, p)).collect();
            pts.extend(negs);
            let aff = |p: &Point| c.to_affine(p);
            for p in &pts {
                assert_eq!(
                    aff(&c.double(p)),
                    aff(&c.add_general(p, p)),
                    "{id:?} double"
                );
                for q in &pts {
                    let q = rescale(c, q, &mut st);
                    assert_eq!(
                        aff(&c.point_add(p, &q)),
                        aff(&c.add_general(p, &q)),
                        "{id:?} add"
                    );
                }
            }
        }
    }
}
