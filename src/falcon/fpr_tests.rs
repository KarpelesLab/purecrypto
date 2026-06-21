//! Differential validation of the emulated [`Fpr`] against the host `f64`.
//!
//! These tests run with `std` available, so they compare every emulated
//! operation bit-for-bit against a conforming hardware `f64`. The bulk test
//! draws operands as random *normal* doubles within an exponent band chosen so
//! that the results of add/sub/mul/div/sqrt stay in the normal range — there the
//! emulation must be *exactly* equal to IEEE round-to-nearest-even. Signed
//! zeros, powers of two, and integer rounding are covered by targeted cases.

use super::Fpr;

/// SplitMix64 — a tiny deterministic PRNG (no `std` rng, no `Math.random`), so
/// the test is fully reproducible.
struct Sm64(u64);
impl Sm64 {
    fn new(seed: u64) -> Sm64 {
        Sm64(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// A random *normal* `f64` with unbiased exponent uniformly in `[lo, hi]`.
fn rand_normal(rng: &mut Sm64, lo: i32, hi: i32) -> f64 {
    let r = rng.next();
    let sign = (r >> 63) & 1;
    let span = (hi - lo + 1) as u64;
    let exp_unbiased = lo + ((r >> 1) % span) as i32;
    let mantissa = rng.next() & 0x000F_FFFF_FFFF_FFFF;
    let biased = (exp_unbiased + 1023) as u64;
    f64::from_bits((sign << 63) | (biased << 52) | mantissa)
}

fn check(label: &str, a: f64, b: f64, got: Fpr, want: f64) {
    assert_eq!(
        got.0,
        want.to_bits(),
        "{label}: a={a:?} ({:#018x}) b={b:?} ({:#018x}) got {:#018x} ({:?}) want {:#018x} ({:?})",
        a.to_bits(),
        b.to_bits(),
        got.0,
        got.to_f64(),
        want.to_bits(),
        want,
    );
}

#[test]
fn diff_arithmetic_bulk() {
    let mut rng = Sm64::new(0x0FA1_C00D_EFAC_E500);
    // Exponent band keeps add/sub/mul/div/sqrt results in the normal range, so
    // the emulation must match IEEE exactly (no underflow/overflow rounding).
    let iters = 1_000_000;
    for _ in 0..iters {
        let a = rand_normal(&mut rng, -100, 100);
        let b = rand_normal(&mut rng, -100, 100);
        let fa = Fpr::from_f64(a);
        let fb = Fpr::from_f64(b);

        check("add", a, b, fa.add(fb), a + b);
        check("sub", a, b, fa.sub(fb), a - b);
        check("mul", a, b, fa.mul(fb), a * b);
        if b != 0.0 {
            check("div", a, b, fa.div(fb), a / b);
        }
        check("sqrt", a, b, fa.abs().sqrt(), a.abs().sqrt());
    }
}

#[test]
fn diff_arithmetic_wide_exponents() {
    // Larger exponent gaps stress the add alignment / sticky logic; results
    // still land in the normal range for this band.
    let mut rng = Sm64::new(0xDEAD_BEEF_1234_5678);
    for _ in 0..500_000 {
        let a = rand_normal(&mut rng, -250, 250);
        let b = rand_normal(&mut rng, -250, 250);
        let fa = Fpr::from_f64(a);
        let fb = Fpr::from_f64(b);
        // Skip cases whose IEEE result leaves the normal range (the emulation
        // deliberately flushes deep subnormals / saturates infinities, which
        // Falcon never exercises).
        for (label, got, want) in [
            ("add", fa.add(fb), a + b),
            ("sub", fa.sub(fb), a - b),
            ("mul", fa.mul(fb), a * b),
            ("div", fa.div(fb), if b != 0.0 { a / b } else { 1.0 }),
        ] {
            if want.is_finite() && (want == 0.0 || want.abs() >= f64::MIN_POSITIVE) {
                check(label, a, b, got, want);
            }
        }
    }
}

#[test]
fn rounding_to_integer() {
    let mut rng = Sm64::new(0xA5A5_5A5A_0F0F_F0F0);
    for _ in 0..500_000 {
        // Band where |value| < 2^53 so it fits an i64 and f64 rounding is exact.
        let a = rand_normal(&mut rng, -6, 50);
        let fa = Fpr::from_f64(a);
        assert_eq!(fa.rint(), a.round_ties_even() as i64, "rint {a:?}");
        assert_eq!(fa.floor(), a.floor() as i64, "floor {a:?}");
        assert_eq!(fa.trunc(), a.trunc() as i64, "trunc {a:?}");
    }
}

#[test]
fn of_i64_matches() {
    let mut rng = Sm64::new(0x1357_9BDF_2468_ACE0);
    for _ in 0..200_000 {
        let i = rng.next() as i64;
        assert_eq!(Fpr::of_i64(i).0, (i as f64).to_bits(), "of_i64 {i}");
    }
    for i in [
        0i64,
        1,
        -1,
        2,
        -2,
        i64::MAX,
        i64::MIN,
        1 << 52,
        (1 << 53) + 1,
    ] {
        assert_eq!(Fpr::of_i64(i).0, (i as f64).to_bits(), "of_i64 {i}");
    }
}

#[test]
fn comparisons_match() {
    let mut rng = Sm64::new(0xFEED_FACE_CAFE_B0BA);
    for _ in 0..500_000 {
        let a = rand_normal(&mut rng, -120, 120);
        let b = rand_normal(&mut rng, -120, 120);
        assert_eq!(
            Fpr::from_f64(a).lt(Fpr::from_f64(b)),
            a < b,
            "lt {a:?} {b:?}"
        );
        assert_eq!(
            Fpr::from_f64(a).le(Fpr::from_f64(b)),
            a <= b,
            "le {a:?} {b:?}"
        );
    }
}

#[test]
fn signed_zero_and_edges() {
    let cases: &[f64] = &[
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.5,
        -0.5,
        2.0,
        -2.0,
        1.5,
        -1.5,
        165.736_617_182_977_6,
        1.820_5,
        1.277_833_696_912_833_7,
        100.25,
        0.000_123_4,
        1e-9,
        1e9,
    ];
    for &a in cases {
        for &b in cases {
            let fa = Fpr::from_f64(a);
            let fb = Fpr::from_f64(b);
            check("add", a, b, fa.add(fb), a + b);
            check("sub", a, b, fa.sub(fb), a - b);
            check("mul", a, b, fa.mul(fb), a * b);
            if b != 0.0 {
                check("div", a, b, fa.div(fb), a / b);
            }
            // `lt` uses a total order, so -0 sorts just below +0; skip the
            // both-zero pair where that differs from IEEE's -0 == +0.
            if a != 0.0 || b != 0.0 {
                assert_eq!(fa.lt(fb), a < b, "lt {a:?} {b:?}");
            }
        }
        // neg / abs / half / double / sqrt on edges.
        let fa = Fpr::from_f64(a);
        check("neg", a, a, fa.neg(), -a);
        check("abs", a, a, fa.abs(), a.abs());
        check("half", a, a, fa.half(), a * 0.5);
        check("double", a, a, fa.double(), a + a);
        if a >= 0.0 {
            check("sqrt", a, a, fa.sqrt(), a.sqrt());
        }
    }
}

#[test]
fn is_zero_works() {
    assert!(Fpr::from_f64(0.0).is_zero());
    assert!(Fpr::from_f64(-0.0).is_zero());
    assert!(!Fpr::from_f64(1e-300).is_zero());
    assert!(!Fpr::from_f64(1.0).is_zero());
}
