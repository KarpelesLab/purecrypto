//! `Zint` validation: differential against `i128` for in-range operations,
//! big-value identities, and extended-GCD correctness.

use super::{Zint, ext_gcd};

struct Sm64(u64);
impl Sm64 {
    fn new(s: u64) -> Sm64 {
        Sm64(s)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn to_i128(z: &Zint) -> i128 {
    z.to_i128().expect("test value fits in i128")
}

fn zi(v: i128) -> Zint {
    Zint::from_i128(v)
}

#[test]
fn arithmetic_vs_i128() {
    let mut rng = Sm64::new(0x9999_1111_2222_3333);
    for _ in 0..200_000 {
        let a = (rng.next() as i64 / 2) as i128;
        let b = (rng.next() as i64 / 2) as i128;
        let za = zi(a);
        let zb = zi(b);
        assert_eq!(to_i128(&za.add(&zb)), a + b, "add {a} {b}");
        assert_eq!(to_i128(&za.sub(&zb)), a - b, "sub {a} {b}");
        assert_eq!(to_i128(&za.mul(&zb)), a * b, "mul {a} {b}");
        assert_eq!(za.cmp(&zb), a.cmp(&b), "cmp {a} {b}");
    }
}

#[test]
fn shifts() {
    let mut rng = Sm64::new(0x4444_5555_6666_7777);
    for _ in 0..50_000 {
        let a = (rng.next() as i32) as i128;
        let s = (rng.next() % 40) as usize;
        let za = zi(a);
        assert_eq!(to_i128(&za.shl(s)), a << s, "shl {a} {s}");
        // shr truncates the magnitude toward zero (not arithmetic floor).
        let mag = a.unsigned_abs() >> s;
        let want = if a < 0 { -(mag as i128) } else { mag as i128 };
        assert_eq!(to_i128(&za.shr(s)), want, "shr {a} {s}");
    }
}

#[test]
fn bitsize_rounds_to_byte() {
    assert_eq!(Zint::zero().bitsize(), 0);
    assert_eq!(Zint::from_i64(1).bitsize(), 8);
    assert_eq!(Zint::from_i64(255).bitsize(), 8);
    assert_eq!(Zint::from_i64(256).bitsize(), 16);
    assert_eq!(Zint::from_i64(-65535).bitsize(), 16);
    assert_eq!(Zint::from_i64(65536).bitsize(), 24);
}

#[test]
fn big_value_identity() {
    // (2^500) * (2^500) == 2^1000, and 2^1000 - 1 has bitsize 1000 rounded to
    // a byte multiple (1000 is already a multiple of 8).
    let two_500 = Zint::from_i64(1).shl(500);
    let two_1000 = two_500.mul(&two_500);
    assert_eq!(two_1000, Zint::from_i64(1).shl(1000));
    let m = two_1000.sub(&Zint::from_i64(1));
    assert_eq!(m.bitsize(), 1000);
    // Round-trip a shift.
    assert_eq!(two_1000.shr(500), two_500);
}

#[test]
fn ext_gcd_small() {
    let mut rng = Sm64::new(0xAAAA_BBBB_CCCC_DDDD);
    fn gcd_i128(mut a: i128, mut b: i128) -> i128 {
        a = a.abs();
        b = b.abs();
        while b != 0 {
            let t = a % b;
            a = b;
            b = t;
        }
        a
    }
    for _ in 0..20_000 {
        let a = ((rng.next() % 2_000_000) as i128) - 1_000_000;
        let b = ((rng.next() % 2_000_000) as i128) - 1_000_000;
        if a == 0 && b == 0 {
            continue;
        }
        let (g, u, v) = ext_gcd(&zi(a), &zi(b));
        let gi = to_i128(&g);
        assert_eq!(gi, gcd_i128(a, b), "gcd {a} {b}");
        // Bezout: u*a + v*b == g.
        let lhs = u.mul(&zi(a)).add(&v.mul(&zi(b)));
        assert_eq!(to_i128(&lhs), gi, "bezout {a} {b}");
    }
}

#[test]
fn ext_gcd_big_coprime() {
    // Two large coprime numbers: 2^521-1 (a Mersenne prime) and 2^500+1.
    let p = Zint::from_i64(1).shl(521).sub(&Zint::from_i64(1));
    let qv = Zint::from_i64(1).shl(500).add(&Zint::from_i64(1));
    let (g, u, v) = ext_gcd(&p, &qv);
    assert_eq!(g, Zint::from_i64(1), "coprime gcd should be 1");
    // u*p + v*qv == 1 (verified entirely in Zint arithmetic).
    let lhs = u.mul(&p).add(&v.mul(&qv));
    assert_eq!(lhs, Zint::from_i64(1), "big bezout");
}
