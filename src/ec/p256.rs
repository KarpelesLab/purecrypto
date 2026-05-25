//! NIST P-256 (secp256r1) field and group arithmetic.

use crate::bignum::{MontModulus, Uint, inv_mod};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Field elements and scalars are four 64-bit limbs (256 bits).
pub(crate) type Fe = Uint<4>;

// Curve parameters (hex, big-endian).
const P_HEX: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const B_HEX: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
const GX_HEX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const GY_HEX: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
const N_HEX: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Decodes a 64-character hex string into a [`Fe`].
pub(crate) fn fe_from_hex(hex: &str) -> Fe {
    let h = hex.as_bytes();
    let mut bytes = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        bytes[i] = (hex_nibble(h[2 * i]) << 4) | hex_nibble(h[2 * i + 1]);
        i += 1;
    }
    Fe::from_be_bytes(&bytes)
}

/// A point in projective coordinates `(X : Y : Z)` with field elements held in
/// Montgomery form. The identity is `(0 : 1 : 0)`.
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

/// The P-256 curve context: the field modulus `p` and the curve coefficient
/// `b`, both ready for Montgomery arithmetic.
pub(crate) struct P256 {
    fp: MontModulus<4>,
    /// `b` in Montgomery form.
    b: Fe,
}

impl P256 {
    pub(crate) fn new() -> Self {
        let fp = MontModulus::new(fe_from_hex(P_HEX));
        let b = fp.to_mont(&fe_from_hex(B_HEX));
        P256 { fp, b }
    }

    /// The group order `n`.
    pub(crate) fn order() -> Fe {
        fe_from_hex(N_HEX)
    }

    /// The identity point `(0 : 1 : 0)`.
    pub(crate) fn identity(&self) -> Point {
        Point {
            x: Fe::ZERO,
            y: self.fp.to_mont(&Fe::ONE),
            z: Fe::ZERO,
        }
    }

    /// The base point `G`.
    pub(crate) fn generator(&self) -> Point {
        self.lift_affine(&fe_from_hex(GX_HEX), &fe_from_hex(GY_HEX))
    }

    /// Lifts an affine point `(x, y)` (plain coordinates) to projective form.
    pub(crate) fn lift_affine(&self, x: &Fe, y: &Fe) -> Point {
        Point {
            x: self.fp.to_mont(x),
            y: self.fp.to_mont(y),
            z: self.fp.to_mont(&Fe::ONE),
        }
    }

    /// Converts a point to affine `(x, y)` (plain coordinates), or `None` if it
    /// is the identity.
    pub(crate) fn to_affine(&self, point: &Point) -> Option<(Fe, Fe)> {
        if bool::from(point.z.is_zero()) {
            return None;
        }
        let z = self.fp.from_mont(&point.z);
        let z_inv = inv_mod(&z, self.fp.modulus())?;
        let x = self.fp.mul_mod(&self.fp.from_mont(&point.x), &z_inv);
        let y = self.fp.mul_mod(&self.fp.from_mont(&point.y), &z_inv);
        Some((x, y))
    }

    #[inline]
    fn mul(&self, a: &Fe, b: &Fe) -> Fe {
        self.fp.mont_mul(a, b)
    }
    #[inline]
    fn add(&self, a: &Fe, b: &Fe) -> Fe {
        self.fp.add_mod(a, b)
    }
    #[inline]
    fn sub(&self, a: &Fe, b: &Fe) -> Fe {
        self.fp.sub_mod(a, b)
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

    #[inline]
    fn double(&self, p: &Point) -> Point {
        self.point_add(p, p)
    }

    /// Constant-time scalar multiplication `scalar * point` via
    /// double-and-add-always over all 256 bits.
    pub(crate) fn scalar_mul(&self, scalar: &Fe, point: &Point) -> Point {
        let mut acc = self.identity();
        let limbs = scalar.as_limbs();
        let mut i = 4;
        while i > 0 {
            i -= 1;
            let limb = limbs[i];
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
    pub(crate) fn mul_generator(&self, scalar: &Fe) -> Point {
        let g = self.generator();
        self.scalar_mul(scalar, &g)
    }

    /// Tests whether affine `(x, y)` (plain coordinates) satisfies the curve
    /// equation `y^2 = x^3 - 3x + b (mod p)`.
    pub(crate) fn is_on_curve(&self, x: &Fe, y: &Fe) -> bool {
        let three = Fe::from_u64(3);
        let b = self.fp.from_mont(&self.b);
        let lhs = self.fp.mul_mod(y, y);
        let x3 = self.fp.mul_mod(&self.fp.mul_mod(x, x), x);
        let three_x = self.fp.mul_mod(&three, x);
        let rhs = self.fp.add_mod(&self.fp.sub_mod(&x3, &three_x), &b);
        bool::from(lhs.ct_eq(&rhs))
    }
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
}
