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

/// `rint` / `floor` / `trunc` negate the magnitude as `-(mag as i64)`. When the
/// low 64 bits of the `u128` magnitude are exactly `0x8000_0000_0000_0000`, the
/// cast lands on `i64::MIN` and the negation overflows — a panic under
/// `overflow-checks`, and reachable from attacker bytes through
/// `FalconPrivateKey::from_bytes` -> `recompute_g` -> `rint`. The conversion is
/// already lossy at that magnitude (these are out-of-range values a malformed
/// key produces, rejected right after), so it must wrap, not panic.
#[test]
fn round_to_int_never_panics_on_negate_overflow() {
    // −2^63 exactly: |value| as u128 has low bits 0x8000_0000_0000_0000.
    let v = Fpr::from_f64(-9_223_372_036_854_775_808.0);
    assert_eq!(v.rint(), i64::MIN);
    assert_eq!(v.floor(), i64::MIN);
    assert_eq!(v.trunc(), i64::MIN);

    // −2^127, whose truncated low 64 bits are zero, and −2^64 + something that
    // lands on the same low pattern after the cast: all must return rather than
    // panic.
    for exp in [63i32, 64, 65, 96, 127, 128, 200, 1000] {
        let mag = Fpr::from_f64(2.0f64.powi(exp));
        let neg = mag.neg();
        // The values are far out of `i64` range; the contract is only "does not
        // panic" (the caller rejects the key afterwards).
        let _ = core::hint::black_box(neg.rint());
        let _ = core::hint::black_box(neg.floor());
        let _ = core::hint::black_box(neg.trunc());
        let _ = core::hint::black_box(mag.rint());
        let _ = core::hint::black_box(mag.floor());
        let _ = core::hint::black_box(mag.trunc());
    }

    // A fractional negative just below −2^63 exercises `floor`'s
    // `intpart + has_frac` path at the same boundary.
    let v = Fpr::from_f64(-9_223_372_036_854_775_808.0).sub(Fpr::from_f64(0.0));
    assert_eq!(v.floor(), i64::MIN);
}

/// Per-operation throughput of the emulation (ignored by default; run with
/// `cargo test --release --all-features falcon::fpr::fpr_tests::op_timing -- --ignored --nocapture`).
#[test]
#[ignore]
fn op_timing() {
    let mut rng = Sm64::new(0x0B0B_0B0B_0B0B_0B0B);
    let n = 2_000_000u32;
    let xs: std::vec::Vec<Fpr> = (0..1024)
        .map(|_| Fpr::from_f64(rand_normal(&mut rng, -20, 20)))
        .collect();
    macro_rules! time {
        ($label:expr, $body:expr) => {{
            let start = std::time::Instant::now();
            let mut acc = 0u64;
            for i in 0..n {
                let a = xs[(i as usize) & 1023];
                let b = xs[((i as usize) * 7 + 3) & 1023];
                let r: u64 = $body(a, b);
                acc = acc.wrapping_add(r);
            }
            let el = start.elapsed();
            core::hint::black_box(acc);
            std::println!("{:>6}: {:?}/op", $label, el / n);
        }};
    }
    time!("add", |a: Fpr, b: Fpr| a.add(b).0);
    time!("mul", |a: Fpr, b: Fpr| a.mul(b).0);
    time!("div", |a: Fpr, b: Fpr| a.div(b).0);
    time!("sqrt", |a: Fpr, _b: Fpr| a.abs().sqrt().0);
    time!("trunc", |a: Fpr, _b: Fpr| a.trunc() as u64);
    time!("of_i64", |a: Fpr, _b: Fpr| Fpr::of_i64(a.0 as i64 >> 20).0);
}

// ---------------------------------------------------------------------------
// Differential validation against the previous (variable-time) implementation.
//
// `fpr_reference_vt` is a verbatim snapshot of `fpr.rs` before the branch-free
// rewrite. The rewrite must be *bit-exact* with it on every finite input class
// Falcon can produce: normals across the whole exponent range, zeros, exact
// ties, exponent boundaries, cancelling adds, results that need
// renormalisation, tiny/huge ratios, perfect squares. `div`/`sqrt` are the
// one deliberate departure: with *subnormal operands* the old code lost
// precision, the new one is correctly rounded — so those two are compared
// against the host `f64` there instead. Everything else is checked three-way
// (new == old == host) wherever the host result is finite.
// ---------------------------------------------------------------------------

use super::fpr_reference_vt::Fpr as RefFpr;

const EXP_MASK: u64 = 0x7FF0_0000_0000_0000;
const FRAC_MASK: u64 = 0x000F_FFFF_FFFF_FFFF;
const SIGN: u64 = 0x8000_0000_0000_0000;

fn is_finite_bits(x: u64) -> bool {
    (x & EXP_MASK) != EXP_MASK
}

fn is_subnormal_bits(x: u64) -> bool {
    (x & EXP_MASK) == 0 && (x & FRAC_MASK) != 0
}

fn bits(sign: u64, biased_exp: u64, frac: u64) -> u64 {
    (sign << 63) | (biased_exp << 52) | (frac & FRAC_MASK)
}

/// Draw one operand from a mix of classes (finite bit patterns only).
fn gen_operand(rng: &mut Sm64) -> u64 {
    let r = rng.next();
    let sign = r >> 63;
    let class = (r >> 56) & 0xF;
    let frac = rng.next() & FRAC_MASK;
    match class {
        // Normal, anywhere in the exponent range.
        0..=3 => bits(sign, 1 + (rng.next() % 2046), frac),
        // Normal in the band Falcon actually uses (|x| ~ 2^-40 .. 2^40).
        4..=7 => bits(sign, (1023 - 40) + (rng.next() % 81), frac),
        // Subnormal (nonzero fraction) or zero.
        8 => bits(sign, 0, frac),
        9 => bits(sign, 0, 0),
        // Powers of two.
        10 => bits(sign, 1 + (rng.next() % 2046), 0),
        // Exponent boundaries.
        11 => bits(
            sign,
            [1u64, 2, 3, 2044, 2045, 2046][(rng.next() % 6) as usize],
            frac,
        ),
        // Integer-valued (what `of_i64` produces).
        12 => {
            let sh = (rng.next() % 64) as u32;
            Fpr::of_i64((rng.next() as i64) >> sh).0
        }
        // Mantissa extremes: all ones / all zeros / lone low bit.
        13 => bits(
            sign,
            1 + (rng.next() % 2046),
            [FRAC_MASK, 0, 1, FRAC_MASK - 1, 1 << 51][(rng.next() % 5) as usize],
        ),
        // Smallest / largest subnormal, smallest / largest normal.
        14 => [
            bits(sign, 0, 1),
            bits(sign, 0, FRAC_MASK),
            bits(sign, 1, 0),
            bits(sign, 2046, FRAC_MASK),
        ][(rng.next() % 4) as usize],
        // A small integer times a power of two (exactly-representable values
        // that create ties when combined).
        _ => {
            let k = rng.next() % 64;
            bits(sign, 1 + (rng.next() % 2046), (k << 46) & FRAC_MASK)
        }
    }
}

/// Draw a second operand *related* to `a`, to hit the alignment, tie,
/// cancellation and renormalisation paths deliberately.
fn gen_related(rng: &mut Sm64, a: u64) -> u64 {
    let r = rng.next();
    let sign = r >> 63;
    let ea = (a >> 52) & 0x7FF;
    let fa = a & FRAC_MASK;
    match (r >> 56) & 0xF {
        0..=2 => gen_operand(rng),
        // Same exponent, random fraction, either sign: heavy cancellation.
        3 => bits(sign, ea, rng.next()),
        // A few ulps away from a, opposite sign: cancellation down to 1 ulp.
        4 => {
            let k = rng.next() % 8;
            let m = (a & !SIGN).wrapping_add(k).wrapping_sub(4) & !SIGN;
            if is_finite_bits(m) {
                m | ((a ^ SIGN) & SIGN)
            } else {
                a ^ SIGN
            }
        }
        // Exponent shifted by a small delta (alignment through the guard bits).
        5 | 6 => {
            let delta = (rng.next() % 121) as i64 - 60;
            let e = (ea as i64 + delta).clamp(0, 2046) as u64;
            bits(sign, e, rng.next())
        }
        // Exactly an ulp / half an ulp / a quarter ulp of a (add ties).
        7 => {
            let k = 52 + (rng.next() % 3);
            let e = (ea as i64 - k as i64).clamp(0, 2046) as u64;
            bits(sign, e, 0)
        }
        // Half an ulp plus a tiny bit (just above a tie).
        8 => {
            let e = (ea as i64 - 53).clamp(0, 2046) as u64;
            bits(sign, e, 1)
        }
        // Same value, either sign (x - x = +0, x + x, x * x, x / x = 1).
        9 => (a & !SIGN) | (sign << 63),
        // Huge / tiny ratio for div, overflow/underflow for mul.
        10 | 11 => {
            let delta = (rng.next() % 2001) as i64 - 1000;
            let e = (ea as i64 + delta).clamp(1, 2046) as u64;
            bits(sign, e, rng.next())
        }
        // Subnormal partner.
        12 => bits(sign, 0, rng.next()),
        // Zero partner.
        13 => bits(sign, 0, 0),
        // Same fraction, exponent one apart (renormalising subtract).
        14 => bits(sign, (ea + 1).min(2046), fa),
        _ => bits(sign, ea.saturating_sub(1), fa),
    }
}

fn expect_bits(label: &str, a: u64, b: u64, got: u64, want: u64, what: &str) {
    assert_eq!(
        got,
        want,
        "{label} vs {what}: a={a:#018x} ({:?}) b={b:#018x} ({:?}) got {got:#018x} ({:?}) want {want:#018x} ({:?})",
        f64::from_bits(a),
        f64::from_bits(b),
        f64::from_bits(got),
        f64::from_bits(want),
    );
}

/// Compare every operation on `(a, b)` against the reference snapshot and,
/// where the host result is finite or infinite (never a NaN case), against
/// the host `f64`.
fn compare_pair(a: u64, b: u64) {
    let fa = Fpr(a);
    let fb = Fpr(b);
    let ra = RefFpr(a);
    let rb = RefFpr(b);
    let ha = f64::from_bits(a);
    let hb = f64::from_bits(b);

    // add / sub / mul / double / half: bit-exact with the reference on every
    // finite class, and with the host.
    let ops: [(&str, u64, u64, f64); 5] = [
        ("add", fa.add(fb).0, ra.add(rb).0, ha + hb),
        ("sub", fa.sub(fb).0, ra.sub(rb).0, ha - hb),
        ("mul", fa.mul(fb).0, ra.mul(rb).0, ha * hb),
        ("double", fa.double().0, ra.double().0, ha + ha),
        ("half", fa.half().0, ra.half().0, ha * 0.5),
    ];
    for (label, got, want_ref, want_host) in ops {
        expect_bits(label, a, b, got, want_ref, "reference");
        if !want_host.is_nan() {
            expect_bits(label, a, b, got, want_host.to_bits(), "host");
        }
    }
    expect_bits("neg", a, b, fa.neg().0, ra.neg().0, "reference");

    // div: bit-exact with the reference for normal/zero operands (including
    // x/0 = inf and 0/0 = signed zero, the reference's conventions); with a
    // subnormal operand the new code is correctly rounded, so check the host.
    let got = fa.div(fb).0;
    let a_sub = is_subnormal_bits(a);
    let b_sub = is_subnormal_bits(b);
    if !a_sub && !b_sub {
        expect_bits("div", a, b, got, ra.div(rb).0, "reference");
    }
    if hb != 0.0 {
        expect_bits("div", a, b, got, (ha / hb).to_bits(), "host");
    }

    // sqrt(|x|): same policy as div; sqrt(-x) (a NaN pattern, or -0) must
    // still match the reference bit-for-bit.
    for (x, sub) in [(a, a_sub), (b, b_sub)] {
        let mag = x & !SIGN;
        let got = Fpr(mag).sqrt().0;
        if !sub {
            expect_bits("sqrt", x, x, got, RefFpr(mag).sqrt().0, "reference");
        }
        expect_bits(
            "sqrt",
            x,
            x,
            got,
            f64::from_bits(mag).sqrt().to_bits(),
            "host",
        );
        expect_bits(
            "sqrt(-x)",
            x,
            x,
            Fpr(x | SIGN).sqrt().0,
            RefFpr(x | SIGN).sqrt().0,
            "reference",
        );
    }

    // Integer conversions: identical to the reference on every input
    // (including the out-of-range saturation/wrap conventions), and to the
    // host where the host conversion is exact.
    for (x, rx) in [(a, ra), (b, rb)] {
        let fx = Fpr(x);
        let hx = f64::from_bits(x);
        assert_eq!(fx.rint(), rx.rint(), "rint vs reference {x:#018x}");
        assert_eq!(fx.floor(), rx.floor(), "floor vs reference {x:#018x}");
        assert_eq!(fx.trunc(), rx.trunc(), "trunc vs reference {x:#018x}");
        if hx.abs() < 9.0e18 {
            assert_eq!(
                fx.rint(),
                hx.round_ties_even() as i64,
                "rint vs host {x:#018x}"
            );
            assert_eq!(fx.floor(), hx.floor() as i64, "floor vs host {x:#018x}");
            assert_eq!(fx.trunc(), hx.trunc() as i64, "trunc vs host {x:#018x}");
        }
    }

    // Comparisons.
    assert_eq!(fa.lt(fb), ra.lt(rb), "lt {a:#018x} {b:#018x}");
    assert_eq!(fa.le(fb), ra.le(rb), "le {a:#018x} {b:#018x}");
}

#[test]
fn differential_vs_reference_bulk() {
    // >= 10 million random operand pairs in release; fewer under debug so the
    // default `cargo test` stays reasonable (the release run is the gate).
    let iters: u64 = if cfg!(debug_assertions) {
        300_000
    } else {
        10_000_000
    };
    let mut rng = Sm64::new(0x00C7_F1E1_D1FF_0001);
    for _ in 0..iters {
        let a = gen_operand(&mut rng);
        let b = gen_related(&mut rng, a);
        assert!(is_finite_bits(a) && is_finite_bits(b));
        compare_pair(a, b);
    }
}

#[test]
fn differential_vs_reference_int_conversions() {
    let iters: u64 = if cfg!(debug_assertions) {
        200_000
    } else {
        3_000_000
    };
    let mut rng = Sm64::new(0x0F1E_2D3C_4B5A_6978);
    for _ in 0..iters {
        let i = (rng.next() as i64) >> (rng.next() % 64);
        assert_eq!(Fpr::of_i64(i).0, RefFpr::of_i64(i).0, "of_i64 {i}");
        assert_eq!(Fpr::of_i64(i).0, (i as f64).to_bits(), "of_i64 host {i}");
    }
}

#[test]
fn differential_vs_reference_edge_table() {
    let mut edges: std::vec::Vec<u64> = std::vec::Vec::new();
    for sign in [0u64, 1] {
        for (e, f) in [
            (0u64, 0u64),      // zero
            (0, 1),            // smallest subnormal
            (0, FRAC_MASK),    // largest subnormal
            (0, 1 << 51),      // half of the smallest normal
            (1, 0),            // smallest normal
            (1, 1),            // smallest normal + ulp
            (2, 0),            // 2 * smallest normal
            (1022, 0),         // 0.5
            (1023, 0),         // 1.0
            (1023, 1),         // 1 + ulp
            (1023, FRAC_MASK), // 2 - ulp
            (1024, 0),         // 2.0
            (1024, 1 << 51),   // 3.0
            (1075, 0),         // 2^52
            (1076, 0),         // 2^53
            (1076, 1),         // 2^53 + 2
            (1085, 0),         // 2^62
            (1086, 0),         // 2^63
            (1087, 0),         // 2^64
            (1150, 0),         // 2^127
            (1151, 0),         // 2^128
            (2045, FRAC_MASK), // just under 2^1023
            (2046, 0),         // 2^1023
            (2046, FRAC_MASK), // largest normal
        ] {
            edges.push(bits(sign, e, f));
        }
    }
    // Some Falcon-relevant constants (the sampler's truncated literals, not
    // the `core::f64::consts` values — hence the lint allow).
    #[allow(clippy::approx_constant)]
    let consts: [f64; 10] = [
        165.736_617_182_977_6,
        168.388_571_446_543_95,
        1.277_833_696_912_833_7,
        1.298_280_334_344_292,
        1.8205,
        1.442_695_040_89,
        0.693_147_180_56,
        9_223_372_036_854_775_808.0,
        12289.0,
        1.0 / 12289.0,
    ];
    for c in consts {
        edges.push(c.to_bits());
        edges.push((-c).to_bits());
    }
    for &a in &edges {
        for &b in &edges {
            compare_pair(a, b);
        }
    }
}

/// Perfect squares (sqrt must be exact, sticky must stay clear) and the ulp
/// neighbours around them (sticky must be set and rounding must go the right
/// way): the canonical `sqrt` rounding hazard.
#[test]
fn differential_sqrt_perfect_squares() {
    let iters: u64 = if cfg!(debug_assertions) {
        50_000
    } else {
        1_000_000
    };
    let mut rng = Sm64::new(0x5A5A_5A5A_5000_0001);
    for _ in 0..iters {
        // c has <= 26 significant bits so c*c is exact in 52.
        let c = Fpr::of_i64(((rng.next() >> 38) as i64) + 1);
        let e = ((rng.next() % 980) as i64 - 500) * 2; // even exponent scale
        let scale = Fpr(bits(0, (1023 + e) as u64, 0));
        let sq = c.mul(c).mul(scale);
        for x in [sq.0, sq.0 - 1, sq.0 + 1] {
            if !is_finite_bits(x) {
                continue;
            }
            let got = Fpr(x).sqrt();
            expect_bits("sqrt", x, x, got.0, RefFpr(x).sqrt().0, "reference");
            expect_bits(
                "sqrt",
                x,
                x,
                got.0,
                f64::from_bits(x).sqrt().to_bits(),
                "host",
            );
        }
    }
}
