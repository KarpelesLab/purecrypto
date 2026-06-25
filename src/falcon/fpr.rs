//! Emulated constant-time IEEE-754 binary64 (`fpr`).
//!
//! Falcon signing needs floating-point (FFT, the LDL tree, and the Gaussian
//! sampler), but this crate is `#![no_std]` with no `libm`, and `core` exposes
//! no float math (`f64::sqrt`/`exp` live in `std`/`libm`). More importantly, the
//! signing path operates on *secret* values, so the arithmetic must be
//! constant-time, and matching the official NIST KAT vectors requires bit-exact,
//! platform-independent results. Hardware `f64` gives none of these guarantees
//! (subnormal-operand timing leaks; non-reproducible rounding/FMA contraction).
//!
//! This module is the answer Falcon's reference calls *FPEMU*: an `f64`
//! implemented entirely in integer arithmetic. [`Fpr`] stores the standard
//! IEEE-754 binary64 bit pattern in a `u64`; every operation
//! (`add`/`mul`/`div`/`sqrt`/…) reproduces correctly-rounded (round-to-nearest,
//! ties-to-even) IEEE results using only integer ops and no wide-integer
//! division/`sqrt` libcalls (a manual restoring divider and bit-by-bit integer
//! sqrt run a fixed number of iterations). The point is portability and
//! reproducibility: the result is identical on every target (including no-FPU
//! `thumbv7em`) and bit-for-bit equal to a conforming hardware `f64` — exactly
//! what the `#[cfg(test)]` differential harness in `fpr_tests.rs` checks against
//! the host's real `f64` over millions of random operations.
//!
//! **Constant-time caveat.** The emulation is *best-effort* constant-time, not
//! guaranteed branch-free: `pack` and `add` branch on operand values, and
//! `mul`/`div`/`sqrt` take zero-operand early-outs — values that, on the signing
//! path, derive from secret data. So while the emulation removes the
//! subnormal-timing and FMA-contraction leaks of a hardware `f64`, it does not
//! by itself make signing strictly constant-time; a fully branchless FPEMU is
//! future work (mirroring the candid limits documented elsewhere in the crate).
//!
//! Falcon never produces NaN or infinities in normal operation and its analysis
//! shows subnormals do not arise on the hot path; those edges are still handled
//! conservatively (infinities saturate, deep underflow flushes to a signed zero)
//! so the type is well-defined, but the values that matter for Falcon — normals
//! and zero — are exact.

/// An emulated IEEE-754 binary64 value, stored as its 64-bit bit pattern.
///
/// All arithmetic is integer-only, constant-time, and correctly rounded
/// (ties-to-even). `Copy` and cheap; secrets are scrubbed by the owning key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fpr(pub(crate) u64);

/// `+0.0`.
pub(crate) const FPR_ZERO: Fpr = Fpr(0);

impl Fpr {
    /// Reinterpret a host `f64` as an [`Fpr`] (pure bit reinterpretation — no
    /// float arithmetic, so this is valid in `no_std` and on no-FPU targets).
    /// Used to define spec constants from literals and by the test harness.
    #[inline]
    pub(crate) const fn from_f64(x: f64) -> Fpr {
        Fpr(x.to_bits())
    }

    /// Reinterpret as a host `f64` (bit reinterpretation only).
    #[cfg(test)]
    #[inline]
    pub(crate) const fn to_f64(self) -> f64 {
        f64::from_bits(self.0)
    }

    /// `true` iff the value is `+0.0` or `-0.0`.
    #[cfg(test)]
    #[inline]
    pub(crate) fn is_zero(self) -> bool {
        (self.0 & 0x7FFF_FFFF_FFFF_FFFF) == 0
    }

    /// Negation: flip the sign bit (so `neg(+0) = -0`, matching IEEE).
    #[inline]
    pub(crate) fn neg(self) -> Fpr {
        Fpr(self.0 ^ 0x8000_0000_0000_0000)
    }

    /// Absolute value: clear the sign bit.
    #[cfg(test)]
    #[inline]
    pub(crate) fn abs(self) -> Fpr {
        Fpr(self.0 & 0x7FFF_FFFF_FFFF_FFFF)
    }
}

/// Decode a finite [`Fpr`] into `((-1)^sign) * mant * 2^exp`, with `mant` a
/// nonnegative integer (`0` for zero) and `exp` the binary exponent of its
/// least-significant bit.
///
/// Normal and subnormal inputs are both handled. Inf/NaN inputs (which Falcon
/// never creates) are decoded as if their stored fraction were a large mantissa;
/// callers that could see them special-case beforehand.
#[inline]
fn decode(x: Fpr) -> (u64, i32, u128) {
    let bits = x.0;
    let sign = bits >> 63;
    let eb = ((bits >> 52) & 0x7FF) as i32;
    let frac = bits & 0x000F_FFFF_FFFF_FFFF;
    if eb == 0 {
        // Subnormal (or zero): no implicit leading 1, exponent fixed at 1-1075.
        (sign, -1074, frac as u128)
    } else {
        // Normal: implicit leading 1 at bit 52.
        (sign, eb - 1075, (frac | 0x0010_0000_0000_0000) as u128)
    }
}

/// Assemble a correctly-rounded [`Fpr`] from `((-1)^sign) * m * 2^e`.
///
/// `m` is an arbitrary-width nonnegative magnitude (`u128`); any precision that
/// was already dropped below `m`'s bit 0 must be folded into bit 0 as a sticky
/// `1` by the caller (the divider and sqrt do this). Performs IEEE
/// round-to-nearest, ties-to-even, with overflow→∞ and gradual underflow.
/// Branchless on the mantissa magnitude (uses `leading_zeros` + variable shifts,
/// both single-instruction / constant-time on the supported targets); the
/// exponent-range arms are structural, not secret-dependent.
fn pack(sign: u64, e: i32, m: u128) -> Fpr {
    if m == 0 {
        return Fpr(sign << 63); // signed zero
    }

    // Normalize to a 55-bit form: significand in bits 54..2 (53 bits, bit 54
    // set), round bit at bit 1, sticky at bit 0.
    let l = 128 - m.leading_zeros() as i32; // bit length of m, >= 1
    let mm: u64;
    let big_e: i32;
    if l > 53 {
        let drop = l - 53;
        let sig = (m >> drop) as u64; // 53 bits, bit 52 set
        let round = ((m >> (drop - 1)) & 1) as u64;
        let sticky = ((m & ((1u128 << (drop - 1)) - 1)) != 0) as u64;
        mm = (sig << 2) | (round << 1) | sticky;
        big_e = e + drop - 2;
    } else {
        let up = 53 - l;
        mm = ((m as u64) << up) << 2; // 53-bit significand then two guard bits
        big_e = e - up - 2;
    }

    // Unbiased exponent of the MSB (bit 54 of mm has weight 2^(big_e+54)).
    let mut eb = big_e + 1077;
    let mut sig = mm >> 2; // 53 bits
    let round = (mm >> 1) & 1;
    let sticky = mm & 1;

    if eb >= 2047 {
        return Fpr((sign << 63) | (0x7FFu64 << 52)); // overflow -> infinity
    }
    if eb >= 1 {
        // Normal: round to 52 stored bits, ties-to-even.
        if round == 1 && (sticky == 1 || (sig & 1) == 1) {
            sig += 1;
            if sig == (1u64 << 53) {
                sig >>= 1;
                eb += 1;
                if eb >= 2047 {
                    return Fpr((sign << 63) | (0x7FFu64 << 52));
                }
            }
        }
        return Fpr((sign << 63) | ((eb as u64) << 52) | (sig & 0x000F_FFFF_FFFF_FFFF));
    }

    // Subnormal / underflow: shift right by (1 - eb) more bits, folding the
    // existing round/sticky guard bits, then round to an integer subnormal
    // mantissa. `mm` is a fixed-point value with 2 fractional guard bits.
    let sh = 1 - eb; // >= 1
    let fb = 2 + sh; // total fractional bits after the shift
    if fb >= 64 {
        // Far below the smallest subnormal: flushes to signed zero under
        // round-to-nearest (a Falcon value never reaches here).
        return Fpr(sign << 63);
    }
    let fb = fb as u32;
    let frac = mm >> fb;
    let rbit = (mm >> (fb - 1)) & 1;
    let st = (mm & ((1u64 << (fb - 1)) - 1)) != 0;
    let mut f = frac;
    if rbit == 1 && (st || (f & 1) == 1) {
        f += 1;
    }
    // If rounding carried into the implicit-bit position, this is the smallest
    // normal (exponent field 1, fraction 0).
    if f == (1u64 << 52) {
        return Fpr((sign << 63) | (1u64 << 52));
    }
    Fpr((sign << 63) | (f & 0x000F_FFFF_FFFF_FFFF))
}

/// Constant-time unsigned 128-bit division: returns `(quotient, remainder)`.
/// Restoring division, fixed 128 iterations, branchless. `den != 0` required.
fn udivmod128(num: u128, den: u128) -> (u128, u128) {
    let mut quo: u128 = 0;
    let mut rem: u128 = 0;
    let mut i: i32 = 127;
    while i >= 0 {
        rem = (rem << 1) | ((num >> i) & 1);
        let ge = (rem >= den) as u128;
        let mask = ge.wrapping_neg();
        rem -= den & mask;
        quo |= ge << i;
        i -= 1;
    }
    (quo, rem)
}

/// Constant-time floor of the integer square root of a `u128`.
/// Bit-by-bit, fixed 64 iterations, branchless.
fn isqrt128(n: u128) -> u128 {
    let mut num = n;
    let mut res: u128 = 0;
    let mut bit: u128 = 1u128 << 126;
    let mut k = 0;
    while k < 64 {
        let t = res + bit;
        let ge = (num >= t) as u128;
        let mask = ge.wrapping_neg();
        num -= t & mask;
        res = (res >> 1) + (bit & mask);
        bit >>= 2;
        k += 1;
    }
    res
}

impl Fpr {
    /// Convert a signed integer to the nearest [`Fpr`] (round-to-nearest-even).
    #[inline]
    pub(crate) fn of_i64(i: i64) -> Fpr {
        let sign = (i < 0) as u64;
        let mag = (i as i128).unsigned_abs();
        pack(sign, 0, mag)
    }

    /// `self + other`, correctly rounded.
    pub(crate) fn add(self, other: Fpr) -> Fpr {
        let (sa, ea, ma) = decode(self);
        let (sb, eb, mb) = decode(other);
        if ma == 0 && mb == 0 {
            // -0 only when both are negative zero (matches IEEE round-to-nearest).
            return Fpr((sa & sb) << 63);
        }
        if ma == 0 {
            return other;
        }
        if mb == 0 {
            return self;
        }

        // Position of each MSB (value-exponent), to order by magnitude.
        let va = ea + (127 - ma.leading_zeros() as i32);
        let vb = eb + (127 - mb.leading_zeros() as i32);
        // Make `a` the larger-magnitude operand.
        let (sa, ea, ma, sb, eb, mb) = if va >= vb {
            (sa, ea, ma, sb, eb, mb)
        } else {
            (sb, eb, mb, sa, ea, ma)
        };

        // Place a's mantissa high in a 128-bit accumulator, leaving headroom for
        // carry; align b into the same frame, folding anything below into sticky.
        let la = 128 - ma.leading_zeros() as i32;
        let shift_a = 122 - la; // a's MSB -> bit ~121, >= 0 since la <= 53
        let acc_a = ma << shift_a;
        let efr = ea - shift_a; // frame: value = ACC * 2^efr
        let shift_b = eb - efr; // where b's LSB lands in the frame
        let (acc_b, sticky) = if shift_b >= 0 {
            // b cannot exceed a in magnitude, so this shift stays in range.
            (mb << shift_b, 0u128)
        } else {
            let s = (-shift_b) as u32;
            if s >= 128 {
                (0u128, (mb != 0) as u128)
            } else {
                let lost = mb & ((1u128 << s) - 1);
                (mb >> s, (lost != 0) as u128)
            }
        };

        if sa == sb {
            let acc = (acc_a + acc_b) | sticky;
            pack(sa, efr, acc)
        } else {
            // Opposite signs: subtract the smaller from the larger magnitude.
            // Borrow from the sticky bit so the dropped low part is accounted.
            let acc_b_eff = acc_b;
            if acc_a == acc_b_eff && sticky == 0 {
                // Exact cancellation: x + (-x) = +0 under round-to-nearest.
                return FPR_ZERO;
            }
            if acc_a > acc_b_eff {
                let mut acc = acc_a - acc_b_eff;
                // If b had a sticky tail, it makes b slightly larger, i.e. we
                // subtracted a touch too little: borrow one ulp and set sticky.
                if sticky != 0 {
                    acc -= 1;
                    acc |= 1;
                }
                pack(sa, efr, acc)
            } else if acc_b_eff > acc_a {
                // b larger: result takes b's sign; b's tail already below frame.
                let acc = (acc_b_eff - acc_a) | sticky;
                pack(sb, efr, acc)
            } else {
                // Exactly equal magnitudes with a sticky tail on b: b wins by ε.
                pack(sb, efr, sticky)
            }
        }
    }

    /// `self - other`, correctly rounded.
    #[inline]
    pub(crate) fn sub(self, other: Fpr) -> Fpr {
        self.add(other.neg())
    }

    /// `self * other`, correctly rounded.
    pub(crate) fn mul(self, other: Fpr) -> Fpr {
        let (sa, ea, ma) = decode(self);
        let (sb, eb, mb) = decode(other);
        let sign = sa ^ sb;
        if ma == 0 || mb == 0 {
            return Fpr(sign << 63); // signed zero
        }
        // ma, mb each <= 53 bits, so the product fits in u128.
        let prod = ma * mb;
        pack(sign, ea + eb, prod)
    }

    /// `self / other`, correctly rounded.
    pub(crate) fn div(self, other: Fpr) -> Fpr {
        let (sa, ea, ma) = decode(self);
        let (sb, eb, mb) = decode(other);
        let sign = sa ^ sb;
        if ma == 0 {
            return Fpr(sign << 63); // 0 / x = signed zero
        }
        if mb == 0 {
            return Fpr((sign << 63) | (0x7FFu64 << 52)); // x / 0 = signed inf
        }
        // Form a quotient with ample guard bits: (ma << 64) / mb yields ~64
        // significant bits, and a nonzero remainder becomes sticky.
        let num = ma << 64;
        let (quo, rem) = udivmod128(num, mb);
        let q = quo | ((rem != 0) as u128); // fold remainder into sticky (bit 0)
        pack(sign, ea - eb - 64, q)
    }

    /// Square root, correctly rounded. `sqrt(+0) = +0`; negative inputs (which
    /// Falcon never produces) yield a NaN-pattern and are not relied upon.
    pub(crate) fn sqrt(self) -> Fpr {
        let (s, mut e, m) = decode(self);
        if m == 0 {
            return Fpr(s << 63); // sqrt(±0) = ±0
        }
        if s == 1 {
            return Fpr(0x7FF8_0000_0000_0000); // sqrt(<0) = NaN (unused by Falcon)
        }
        // Need an even exponent so 2^(e/2) is integral.
        let mut mm = m;
        if (e & 1) != 0 {
            mm <<= 1;
            e -= 1;
        }
        // Scale up by 2^56 (even) for >= 54 bits of result precision.
        let scaled = mm << 56;
        let root = isqrt128(scaled);
        let sticky = (root * root != scaled) as u128;
        pack(0, e / 2 - 28, root | sticky)
    }

    /// Multiply by `0.5` (exact: a power-of-two scaling).
    #[inline]
    pub(crate) fn half(self) -> Fpr {
        self.mul(Fpr::from_f64(0.5))
    }

    /// Multiply by `2.0` (exact).
    #[inline]
    pub(crate) fn double(self) -> Fpr {
        self.add(self)
    }

    /// Round to the nearest integer, ties-to-even, returning an `i64`.
    pub(crate) fn rint(self) -> i64 {
        let (s, e, m) = decode(self);
        if m == 0 {
            return 0;
        }
        let mag: u128 = if e >= 0 {
            // Mirror the `sh >= 128` guard below: a shift `>= 128` is UB / a
            // panic under overflow-checks, and any such magnitude is far beyond
            // `i64` range anyway. Reachable from malformed imported keys (via
            // `recompute_g`), which the caller rejects afterwards, so saturating
            // rather than panicking is the safe behavior.
            if e >= 128 {
                return if s == 1 { i64::MIN } else { i64::MAX };
            }
            m << e
        } else {
            let sh = (-e) as u32;
            if sh >= 128 {
                0
            } else {
                let intpart = m >> sh;
                let frac = m & ((1u128 << sh) - 1);
                let half = 1u128 << (sh - 1);
                if frac > half || (frac == half && (intpart & 1) == 1) {
                    intpart + 1
                } else {
                    intpart
                }
            }
        };
        if s == 1 { -(mag as i64) } else { mag as i64 }
    }

    /// Floor (round toward −∞), returning an `i64`.
    pub(crate) fn floor(self) -> i64 {
        let (s, e, m) = decode(self);
        if m == 0 {
            return 0;
        }
        if e >= 0 {
            // See `rint`: guard the `>= 128` shift to avoid a panic/UB on the
            // out-of-range exponents reachable from malformed imported keys.
            if e >= 128 {
                return if s == 1 { i64::MIN } else { i64::MAX };
            }
            let mag = m << e;
            return if s == 1 { -(mag as i64) } else { mag as i64 };
        }
        let sh = (-e) as u32;
        if sh >= 128 {
            // |value| < 1
            return if s == 1 { -1 } else { 0 };
        }
        let intpart = m >> sh;
        let has_frac = (m & ((1u128 << sh) - 1)) != 0;
        if s == 1 {
            -((intpart + has_frac as u128) as i64)
        } else {
            intpart as i64
        }
    }

    /// Truncate toward zero, returning an `i64`.
    pub(crate) fn trunc(self) -> i64 {
        let (s, e, m) = decode(self);
        if m == 0 {
            return 0;
        }
        let mag = if e >= 0 {
            // See `rint`: guard the `>= 128` shift to avoid a panic/UB on the
            // out-of-range exponents reachable from malformed imported keys.
            if e >= 128 {
                return if s == 1 { i64::MIN } else { i64::MAX };
            }
            m << e
        } else {
            let sh = (-e) as u32;
            if sh >= 128 { 0 } else { m >> sh }
        };
        if s == 1 { -(mag as i64) } else { mag as i64 }
    }

    /// Total-order key: maps the IEEE bits to a `u64` whose unsigned ordering
    /// matches numeric ordering for non-NaN values. Constant-time.
    #[inline]
    fn order_key(self) -> u64 {
        let b = self.0;
        let mask = (b >> 63).wrapping_neg() | 0x8000_0000_0000_0000;
        b ^ mask
    }

    /// `self < other` by numeric value (constant-time; `-0` and `+0` compare as
    /// adjacent but never gate Falcon's behavior on that boundary).
    #[inline]
    pub(crate) fn lt(self, other: Fpr) -> bool {
        self.order_key() < other.order_key()
    }

    /// `self <= other` by numeric value.
    #[cfg(test)]
    #[inline]
    pub(crate) fn le(self, other: Fpr) -> bool {
        self.order_key() <= other.order_key()
    }
}

#[cfg(test)]
#[path = "fpr_tests.rs"]
mod fpr_tests;
