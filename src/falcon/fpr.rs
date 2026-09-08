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
//! division/`sqrt` libcalls. The point is portability and reproducibility: the
//! result is identical on every target (including no-FPU `thumbv7em`) and
//! bit-for-bit equal to a conforming hardware `f64` — exactly what the
//! `#[cfg(test)]` differential harness in `fpr_tests.rs` checks against the
//! host's real `f64` over millions of random operations.
//!
//! # Constant-time contract
//!
//! Every arithmetic entry point (`add`/`sub`/`mul`/`div`/`sqrt`/`of_i64`/
//! `rint`/`floor`/`trunc`/`lt`/`neg`/`half`/`double`) is **branch-free by
//! construction**: the source contains no `if`/`match`/`?:`/early `return`/
//! loop bound that depends on an operand. Everything is a straight-line
//! sequence of integer operations over the `u64` bit pattern, and every
//! decision is a full-width mask (`0` or `!0`) derived arithmetically (sign
//! bits of differences, `x | -x` for nonzero tests, the classic
//! `((!a & b) | (!(a ^ b) & (a - b))) >> 63` borrow trick for unsigned
//! comparisons) and applied with `(a & m) | (b & !m)` selects. Every mask
//! derivation is routed through [`core::hint::black_box`] so the optimizer
//! cannot recognise it as a comparison and re-materialise a conditional branch
//! (`SelectOptimize`-style transforms); the same pattern the crate's `ct`
//! module uses.
//!
//! In particular:
//!
//! * **Shifts by secret amounts** never use the native variable-shift
//!   instruction. They go through masked barrel shifters ([`shl64`],
//!   [`shr128`], [`shl256`]) with a fixed number of stages (one per amount
//!   bit), so the amount only ever feeds mask derivations.
//! * **Leading-zero counts** for normalisation use a fixed-trip binary search
//!   ([`norm64`], [`norm128`]) rather than `leading_zeros()`; no reliance on
//!   `lzcnt`/`bsr`/`clz` timing.
//! * **Division** is a restoring divider with a fixed 65 iterations
//!   (`div`); **square root** is the bit-by-bit method with a fixed 55
//!   iterations (`sqrt`). Both loop counters are compile-time constants.
//! * **Rounding** (`pack`) computes the ties-to-even increment as
//!   `round & (sticky | lsb)` and lets the mantissa carry propagate into the
//!   exponent field arithmetically; exponent overflow/underflow are handled by
//!   masks that select an infinity / a signed zero after the fact.
//!
//! The remaining platform assumptions are: 64×64→128-bit multiplication
//! (`u128` product of two `u64`, used by `mul`) and 128-bit
//! add/sub/and/or/xor/*constant*-amount shifts are constant-time — true of
//! every 64-bit target this crate supports (a single `mul`/`umulh` and
//! two-word carry chains; there is no data-dependent early-out in those
//! instructions), and of the 32-bit targets' `__multi3`/carry-chain lowerings.
//! No memory access is ever indexed by a secret.
//!
//! The arithmetic entry points are `#[inline(never)]` so each is a standalone
//! symbol whose generated code can be audited as a unit (on x86-64 the release
//! build of `add`/`mul`/`of_i64`/`rint`/`floor`/`trunc` contains no
//! conditional jump at all, and `div`/`sqrt` only the `dec; jne` of their
//! fixed-count loops). The previous, variable-time implementation is kept as
//! the test-only `fpr_reference_vt` module and the differential tests in
//! `fpr_tests.rs` prove this one bit-exact with it.
//!
//! **Special values.** Falcon never produces NaN, infinities or subnormals in
//! valid operation. Normals and zeros are exact (IEEE round-to-nearest-even,
//! and bit-identical to the previous implementation — see the
//! `fpr_reference_vt` differential tests). Subnormal *operands* are handled
//! on the same branch-free path: `add`/`mul` round them exactly, `div`/`sqrt`
//! pre-normalise them (the previous implementation lost precision there, so
//! those results are now *more* accurate, i.e. correctly rounded). Results
//! that would overflow saturate to a signed infinity and results below the
//! smallest subnormal flush to a signed zero — both selected by masks, never
//! by a branch. NaN/infinity *inputs* are decoded as if they were huge normals
//! (the results are deterministic garbage, never a panic); no Falcon value can
//! reach them.

/// An emulated IEEE-754 binary64 value, stored as its 64-bit bit pattern.
///
/// All arithmetic is integer-only, branch-free (see the module docs), and
/// correctly rounded (ties-to-even). `Copy` and cheap; secrets are scrubbed by
/// the owning key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fpr(pub(crate) u64);

/// `+0.0`.
pub(crate) const FPR_ZERO: Fpr = Fpr(0);

const SIGN_BIT: u64 = 0x8000_0000_0000_0000;
const FRAC_MASK: u64 = 0x000F_FFFF_FFFF_FFFF;
const IMPLICIT_BIT: u64 = 0x0010_0000_0000_0000;
const INF_BITS: u64 = 0x7FFu64 << 52;
const NAN_BITS: u64 = 0x7FF8_0000_0000_0000;

/// Overwrite a slice of secret [`Fpr`] values with `+0.0`.
///
/// Routed through [`core::hint::black_box`] so the compiler cannot treat the
/// stores as dead and elide them (the same pattern the private-key `Drop` impls
/// use). Falcon's expanded key and the key-expansion temporaries are lossless
/// representations of the NTRU secret, so they must not be handed back to the
/// allocator in the clear.
#[inline]
pub(crate) fn wipe_fpr(v: &mut [Fpr]) {
    for x in v.iter_mut() {
        *x = FPR_ZERO;
    }
    let _ = core::hint::black_box(&*v);
}

// ---------------------------------------------------------------------------
// Mask toolkit. Every function here returns a full-width mask (`0` or `!0`)
// and is the *only* place a data-dependent decision is turned into a value.
// The `black_box` is the optimisation barrier that keeps LLVM from folding
// the arithmetic back into `icmp`+`select` (and from there into a branch).
// ---------------------------------------------------------------------------

/// The optimisation barrier behind every mask derivation.
///
/// On x86-64 and AArch64 this is an empty `asm!` block that names the value
/// as a read/write register operand: it emits no instruction, but the
/// optimizer must treat the output as unknown, so it can no longer prove the
/// mask is a comparison result and rewrite the select arithmetic into a
/// conditional branch. Elsewhere it falls back to [`core::hint::black_box`],
/// which achieves the same through a memory round-trip (measurably slower on
/// the serial dependency chains here, hence the `asm!` fast path). The
/// `#![allow(unsafe_code)]` scope is local to this module, matching the
/// crate's `unsafe_code = "deny"` policy of scoped opt-ins.
mod barrier {
    #![allow(unsafe_code)]

    /// Return `x` as a value the optimizer knows nothing about.
    #[inline(always)]
    pub(super) fn opaque(x: u64) -> u64 {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let mut v = x;
            // SAFETY: the template is a comment only; it executes nothing,
            // names `v` as its sole (register) operand, and touches no memory.
            unsafe {
                core::arch::asm!(
                    "/* {0} */",
                    inout(reg) v,
                    options(pure, nomem, nostack, preserves_flags)
                );
            }
            v
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            core::hint::black_box(x)
        }
    }
}

/// Optimisation barrier for a 64-bit mask (see [`barrier`]).
#[inline(always)]
fn bb64(x: u64) -> u64 {
    barrier::opaque(x)
}

/// Optimisation barrier for a 128-bit mask (see [`bb64`]).
#[inline(always)]
fn bb128(x: u128) -> u128 {
    let lo = bb64(x as u64);
    let hi = bb64((x >> 64) as u64);
    ((hi as u128) << 64) | lo as u128
}

/// `!0` iff `x != 0`.
#[inline(always)]
fn nz64(x: u64) -> u64 {
    bb64(((x | x.wrapping_neg()) >> 63).wrapping_neg())
}

/// `!0` iff `x != 0`.
#[inline(always)]
fn nz128(x: u128) -> u128 {
    bb128(((x | x.wrapping_neg()) >> 127).wrapping_neg())
}

/// `!0` iff `a < b` (unsigned), via the borrow of `a - b`.
#[inline(always)]
fn lt64(a: u64, b: u64) -> u64 {
    bb64((((!a & b) | (!(a ^ b) & a.wrapping_sub(b))) >> 63).wrapping_neg())
}

/// `!0` iff `a < b` (unsigned), via the borrow of `a - b`.
#[inline(always)]
fn lt128(a: u128, b: u128) -> u128 {
    bb128((((!a & b) | (!(a ^ b) & a.wrapping_sub(b))) >> 127).wrapping_neg())
}

/// `!0` iff `x < 0` (sign bit of a signed value, replicated).
#[inline(always)]
fn neg64(x: i64) -> u64 {
    bb64((x >> 63) as u64)
}

/// `!0` iff the low bit of `x` is set (mask from a 0/1 value).
#[inline(always)]
fn bit64(x: u64) -> u64 {
    bb64((x & 1).wrapping_neg())
}

/// `a` if `m == !0`, `b` if `m == 0`.
#[inline(always)]
fn sel64(a: u64, b: u64, m: u64) -> u64 {
    (a & m) | (b & !m)
}

/// `a` if `m == !0`, `b` if `m == 0`.
#[inline(always)]
fn sel128(a: u128, b: u128, m: u128) -> u128 {
    (a & m) | (b & !m)
}

/// `a` if `m == !0`, `b` if `m == 0` (signed values, same mask type).
#[inline(always)]
fn seli(a: i64, b: i64, m: u64) -> i64 {
    sel64(a as u64, b as u64, m) as i64
}

/// Widen a 64-bit mask (`0` or `!0`) to a 128-bit mask.
#[inline(always)]
fn wide(m: u64) -> u128 {
    let m = m as u128;
    m | (m << 64)
}

/// `max(x, 0)` for a signed value, branch-free.
#[inline(always)]
fn clamp_nonneg(x: i64) -> i64 {
    x & !(neg64(x) as i64)
}

// ---------------------------------------------------------------------------
// Fixed-trip normalisation (leading-zero count + left shift) and masked
// barrel shifters. Each stage tests / shifts by a compile-time constant; the
// secret only ever selects between the shifted and unshifted candidate.
// ---------------------------------------------------------------------------

/// Normalise `x` so its most significant set bit is bit 63: returns
/// `(x << lz, lz)` with `lz = x.leading_zeros()` (`(0, 64)` for `x == 0`).
/// Seven fixed stages (32, 16, 8, 4, 2, 1, plus the final zero check).
#[inline(always)]
fn norm64(x: u64) -> (u64, u64) {
    let mut v = x;
    let mut lz = 0u64;
    macro_rules! stage {
        ($k:expr) => {{
            let z = !nz64(v >> (64 - $k)); // top $k bits all clear?
            v = sel64(v << $k, v, z);
            lz += ($k as u64) & z;
        }};
    }
    stage!(32);
    stage!(16);
    stage!(8);
    stage!(4);
    stage!(2);
    stage!(1);
    // After the stages bit 63 is set unless `x == 0`; account for that case so
    // the count is exactly 64 there (and the bit length `64 - lz` is 0).
    let z = !nz64(v >> 63);
    lz += 1 & z;
    (v, lz)
}

/// Normalise `x` so its most significant set bit is bit 127: returns
/// `(x << lz, lz)` with `lz = x.leading_zeros()` (`(0, 128)` for `x == 0`).
/// Eight fixed stages.
#[inline(always)]
fn norm128(x: u128) -> (u128, u64) {
    let mut v = x;
    let mut lz = 0u64;
    macro_rules! stage {
        ($k:expr) => {{
            let z = !nz128(v >> (128 - $k));
            v = sel128(v << $k, v, z);
            lz += ($k as u64) & (z as u64);
        }};
    }
    stage!(64);
    stage!(32);
    stage!(16);
    stage!(8);
    stage!(4);
    stage!(2);
    stage!(1);
    let z = !nz128(v >> 127);
    lz += 1 & (z as u64);
    (v, lz)
}

/// `x << amt` for a secret `amt` in `0..=63` (six masked stages). Bits of
/// `amt` above bit 5 are ignored.
#[inline(always)]
fn shl64(x: u64, amt: u64) -> u64 {
    let mut v = x;
    macro_rules! stage {
        ($i:expr) => {{
            let m = bit64(amt >> $i);
            v = sel64(v << (1u32 << $i), v, m);
        }};
    }
    stage!(0);
    stage!(1);
    stage!(2);
    stage!(3);
    stage!(4);
    stage!(5);
    v
}

/// `x >> amt` for a secret `amt` in `0..=63` (six masked stages). Bits of
/// `amt` above bit 5 are ignored.
#[inline(always)]
fn shr128(x: u128, amt: u64) -> u128 {
    let mut v = x;
    macro_rules! stage {
        ($i:expr) => {{
            let m = wide(bit64(amt >> $i));
            v = sel128(v >> (1u32 << $i), v, m);
        }};
    }
    stage!(0);
    stage!(1);
    stage!(2);
    stage!(3);
    stage!(4);
    stage!(5);
    v
}

/// `(x as u256) << amt` for a secret `amt` in `0..=255`, returned as
/// `(high 128 bits, low 128 bits)`. Eight masked stages (1 … 128).
#[inline(always)]
fn shl256(x: u128, amt: u64) -> (u128, u128) {
    let mut hi = 0u128;
    let mut lo = x;
    macro_rules! stage {
        ($i:expr) => {{
            let k = 1u32 << $i; // 1 ..= 64
            let m = wide(bit64(amt >> $i));
            let nhi = (hi << k) | (lo >> (128 - k));
            let nlo = lo << k;
            hi = sel128(nhi, hi, m);
            lo = sel128(nlo, lo, m);
        }};
    }
    stage!(0);
    stage!(1);
    stage!(2);
    stage!(3);
    stage!(4);
    stage!(5);
    stage!(6);
    // Stage 128: the whole low word moves up.
    let m = wide(bit64(amt >> 7));
    hi = sel128(lo, hi, m);
    lo &= !m;
    (hi, lo)
}

// ---------------------------------------------------------------------------
// Decode / encode.
// ---------------------------------------------------------------------------

/// Decode an [`Fpr`] into `((-1)^sign) * mant * 2^exp`, with `mant` a
/// nonnegative integer (`0` for zero, at most 53 bits) and `exp` the binary
/// exponent of its least-significant bit.
///
/// Normal and subnormal inputs are both handled, branch-free. Inf/NaN inputs
/// (which Falcon never creates) decode as if their stored fraction were a
/// normal mantissa with the maximum exponent.
#[inline(always)]
fn decode(x: Fpr) -> (u64, i64, u64) {
    let bits = x.0;
    let sign = bits >> 63;
    let ebf = (bits >> 52) & 0x7FF;
    let frac = bits & FRAC_MASK;
    let normal = nz64(ebf);
    let mant = frac | (IMPLICIT_BIT & normal);
    // Normal: e = ebf - 1075 (implicit bit at 52). Subnormal/zero: fixed -1074.
    let e = (ebf as i64) - 1075 + ((!normal) & 1) as i64;
    (sign, e, mant)
}

/// Assemble a correctly-rounded [`Fpr`] from `((-1)^sign) * m * 2^e`.
///
/// `m` is an arbitrary-width nonnegative magnitude (`u128`); any precision that
/// was already dropped below `m`'s bit 0 must be folded into bit 0 as a sticky
/// `1` by the caller (the divider and sqrt do this). Performs IEEE
/// round-to-nearest, ties-to-even, with overflow→∞ and gradual underflow
/// (flushing to a signed zero far below the smallest subnormal). Entirely
/// branch-free: normalisation, the denormalising shift, the rounding
/// increment and the special-case selections are all mask arithmetic.
#[inline(always)]
fn pack(sign: u64, e: i64, m: u128) -> Fpr {
    let szero = sign << 63;
    let zero = !nz128(m) as u64;

    // Normalise so the leading bit sits at bit 127, then take the 55-bit form
    // `mm`: significand in bits 54..2 (bit 54 set), round bit at bit 1, and the
    // OR of everything below folded into the sticky bit 0. Values with fewer
    // than 53 bits get zero round/sticky bits, exactly as a left shift would.
    let (mn, lz) = norm128(m);
    let below = nz128(mn & ((1u128 << 73) - 1)) as u64 & 1;
    let mm = ((mn >> 73) as u64) | below;

    // Biased exponent of the leading bit: `e + (128 - lz) - 55 + 1077`.
    let eb: i64 = e + 1150 - lz as i64;

    // A normal result drops the two guard bits (shift 2). A result whose
    // biased exponent is `eb <= 0` is subnormal and must be shifted right by
    // `1 - eb` more, re-folding the dropped bits into round/sticky. A total
    // shift of 64 or more leaves nothing: it is a signed zero.
    let d = clamp_nonneg(1 - eb);
    let t = 2 + d;
    let under = neg64(61 - d); // t >= 64
    let shifted = shr128((mm as u128) << 64, (t as u64) & 63);
    let ip = (shifted >> 64) as u64; // integer part (<= 53 bits)
    let lo = shifted as u64; // dropped bits: round at 63, sticky below
    let rbit = lo >> 63;
    let sticky = nz64(lo & !SIGN_BIT) & 1;
    // Round-to-nearest, ties-to-even. A carry out of bit 52 (52 for
    // subnormals) lands in the exponent field arithmetically below.
    let f = ip + (rbit & (sticky | (ip & 1)));

    // Exponent field = max(eb, 1) - 1 + (f >> 52): for a normal result `f`
    // has bit 52 (or, after a carry, bit 53) set; for a subnormal the field
    // is 0 unless rounding carried into bit 52 (the smallest normal).
    let ebm1 = clamp_nonneg(eb - 1);
    let expf = ebm1 + (f >> 52) as i64;
    let ovf = neg64(2046 - expf); // expf >= 2047
    let finite = szero | ((expf as u64) << 52) | (f & FRAC_MASK);
    let r = sel64(szero | INF_BITS, finite, ovf);
    Fpr(sel64(szero, r, under | zero))
}

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
        (self.0 & !SIGN_BIT) == 0
    }

    /// Negation: flip the sign bit (so `neg(+0) = -0`, matching IEEE).
    #[inline]
    pub(crate) fn neg(self) -> Fpr {
        Fpr(self.0 ^ SIGN_BIT)
    }

    /// Absolute value: clear the sign bit.
    #[cfg(test)]
    #[inline]
    pub(crate) fn abs(self) -> Fpr {
        Fpr(self.0 & !SIGN_BIT)
    }

    /// Convert a signed integer to the nearest [`Fpr`] (round-to-nearest-even).
    #[inline(never)]
    pub(crate) fn of_i64(i: i64) -> Fpr {
        let sm = neg64(i);
        let mag = ((i as u64) ^ sm).wrapping_sub(sm); // |i|, 2^63 for i64::MIN
        pack(sm & 1, 0, mag as u128)
    }

    /// `self + other`, correctly rounded.
    #[inline(never)]
    pub(crate) fn add(self, other: Fpr) -> Fpr {
        let (sa, ea, ma) = decode(self);
        let (sb, eb, mb) = decode(other);

        // Order by magnitude so `x` is the larger operand (ties keep `self`).
        // The IEEE encoding is monotonic in |value| for finite inputs, so a
        // single unsigned compare of the sign-cleared bit patterns decides.
        let swap = lt64(self.0 & !SIGN_BIT, other.0 & !SIGN_BIT);
        let sx = sel64(sb, sa, swap);
        let sy = sel64(sa, sb, swap);
        let ex = seli(eb, ea, swap);
        let ey = seli(ea, eb, swap);
        let mx = sel64(mb, ma, swap);
        let my = sel64(ma, mb, swap);

        // Frame: a 128-bit accumulator with x's MSB at bit 121 (headroom for
        // the carry) and value = ACC * 2^efr. y is placed by its LSB in a
        // 256-bit frame `(hi, lo)` at the same scale: `hi` is its in-frame
        // part and any nonzero `lo` is the part below the frame (the sticky
        // tail). Being no larger than x, y never reaches above bit 121.
        let (nx, lzx) = norm64(mx);
        let acc_x = (nx as u128) << 58;
        let efr = ex - 58 - lzx as i64;
        let amt = clamp_nonneg(ey - efr + 128);
        let (acc_y, tail) = shl256(my as u128, amt as u64);
        let sticky = nz128(tail) & 1;

        // Same signs: magnitudes add (the tail only ever contributes sticky).
        let sum = (acc_x + acc_y) | sticky;

        // Opposite signs: |acc_x - acc_y|, taking the larger one's sign. A
        // sticky tail belongs to y and can only exist when y is strictly
        // smaller, so it borrows one unit from the difference and stays
        // sticky. Exact cancellation gives +0 (round-to-nearest).
        let d0 = acc_x.wrapping_sub(acc_y);
        let ltm = lt128(acc_x, acc_y);
        let eqm = !nz128(d0);
        let gtm = !(ltm | eqm);
        let mag = (d0 ^ ltm).wrapping_sub(ltm);
        let diff = mag.wrapping_sub(sticky & gtm) | sticky;
        let cancel = (eqm as u64) & !(nz128(sticky) as u64);
        let sdiff = sel64(sx, sy, gtm as u64) & !cancel;

        let same = !nz64(sx ^ sy);
        let acc = sel128(sum, diff, wide(same));
        let sign = sel64(sx, sdiff, same);
        pack(sign, efr, acc)
    }

    /// `self - other`, correctly rounded.
    #[inline]
    pub(crate) fn sub(self, other: Fpr) -> Fpr {
        self.add(other.neg())
    }

    /// `self * other`, correctly rounded.
    ///
    /// Relies on the 64×64→128-bit multiply being constant-time (a single
    /// `mul`/`umulh` pair on 64-bit targets; see the module docs).
    #[inline(never)]
    pub(crate) fn mul(self, other: Fpr) -> Fpr {
        let (sa, ea, ma) = decode(self);
        let (sb, eb, mb) = decode(other);
        // Each mantissa is <= 53 bits, so the product fits in 106 bits. A zero
        // operand gives a zero product, which `pack` turns into a signed zero.
        let prod = (ma as u128) * (mb as u128);
        pack(sa ^ sb, ea + eb, prod)
    }

    /// `self / other`, correctly rounded. `0 / x = ±0` (also for `x = 0`),
    /// `x / 0 = ±∞` for nonzero `x` (neither arises in Falcon).
    #[inline(never)]
    pub(crate) fn div(self, other: Fpr) -> Fpr {
        let (sa, ea, ma) = decode(self);
        let (sb, eb, mb) = decode(other);
        let sign = sa ^ sb;
        let za = !nz64(ma);
        let zb = !nz64(mb);

        // Normalise both mantissas to bit 52 (a no-op for normal operands, and
        // what makes the quotient width fixed for subnormal ones).
        let (na, lza) = norm64(ma);
        let (nb, lzb) = norm64(mb);
        let man = na >> 11;
        let mbn = nb >> 11;
        let e = (ea - (lza as i64 - 11)) - (eb - (lzb as i64 - 11)) - 64;

        // Restoring division of `man << 64` by `mbn`. With both in
        // [2^52, 2^53) the quotient lies in (2^63, 2^65): 65 quotient bits,
        // produced MSB-first, and the partial remainder never exceeds 54 bits.
        // Quotient bits above 64 would all be zero, so the loop starts with
        // the partial remainder already equal to `man`.
        let mut rem = man;
        let mut quo: u128 = 0;
        let mut i = 0;
        while i < 65 {
            let t = rem.wrapping_sub(mbn);
            let borrow = neg64(t as i64); // rem < mbn
            rem = sel64(rem, t, borrow) << 1;
            quo = (quo << 1) | ((!borrow) & 1) as u128;
            i += 1;
        }
        // A nonzero remainder means the quotient was truncated: sticky.
        let q = (quo | (nz64(rem) & 1) as u128) & !wide(za);
        let r = pack(sign, e, q);
        Fpr(sel64((sign << 63) | INF_BITS, r.0, zb & !za))
    }

    /// Square root, correctly rounded. `sqrt(±0) = ±0`; negative inputs (which
    /// Falcon never produces) yield a NaN-pattern and are not relied upon.
    #[inline(never)]
    pub(crate) fn sqrt(self) -> Fpr {
        let (s, e, m) = decode(self);
        let zero = !nz64(m);
        let negm = nz64(s);

        // Normalise to bit 52 (no-op for normals), then make the exponent
        // even so 2^(e/2) is integral, moving the parity into the mantissa.
        let (nm, lz) = norm64(m);
        let mn = nm >> 11;
        let en = e - (lz as i64 - 11);
        let odd = (en & 1) as u64;
        let mm = sel64(mn << 1, mn, bit64(odd));
        let e2 = en - odd as i64;

        // Scale by 2^56 (even) so the root carries 55 significant bits (53 +
        // round + a bit for sticky), then take the integer square root
        // bit-by-bit from 2^108 (the scaled value is below 2^110).
        let scaled = (mm as u128) << 56;
        let mut num = scaled;
        let mut res: u128 = 0;
        let mut bit: u128 = 1u128 << 108;
        let mut k = 0;
        while k < 55 {
            let t = res + bit;
            let ge = !lt128(num, t);
            num = num.wrapping_sub(t & ge);
            res = (res >> 1) + (bit & ge);
            bit >>= 2;
            k += 1;
        }
        // `num` is now `scaled - res^2`; nonzero means an inexact root.
        let sticky = nz128(num) & 1;
        let r = pack(0, (e2 >> 1) - 28, res | sticky);
        let r = sel64(NAN_BITS, r.0, negm);
        Fpr(sel64(s << 63, r, zero))
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

    /// Shared body of `rint`/`floor`/`trunc`: `mode` is a compile-time constant
    /// (0 = nearest-even, 1 = floor, 2 = truncate), so the dispatch on it is
    /// public, not secret-dependent.
    ///
    /// Out-of-range magnitudes keep the previous semantics, which only
    /// malformed imported keys can reach (the caller rejects them afterwards):
    /// a value-exponent of 128 or more saturates to `i64::MIN`/`i64::MAX`, and
    /// below that the conversion wraps like an `as i64` cast.
    #[inline(never)]
    fn to_int<const MODE: u8>(self) -> i64 {
        let (s, e, m) = decode(self);
        let sm = nz64(s);
        let epos = !neg64(e); // e >= 0: the value is an integer
        let sat = neg64(127 - e); // e >= 128
        let big = neg64(63 - e); // 64 <= e: no bits survive the wrap

        // e >= 0: integer `m << e`, low 64 bits.
        let lsh = shl64(m, (e as u64) & 63) & !big;

        // e < 0: split at the binary point. Shifts of 63 or more behave like
        // any larger shift (m has 53 bits), so the amount is clamped there.
        let sh0 = -e;
        let sh = seli(63, sh0, neg64(63 - sh0)) as u64;
        let r = shr128((m as u128) << 64, sh & 63);
        let ip = (r >> 64) as u64;
        let lo = r as u64;
        let rbit = lo >> 63;
        let st = nz64(lo & !SIGN_BIT) & 1;
        let inc = match MODE {
            0 => rbit & (st | (ip & 1)), // nearest, ties-to-even
            1 => (rbit | st) & s,        // floor: away from zero when negative
            _ => 0,                      // trunc
        };
        let rsh = ip + inc;

        let mag = sel64(lsh, rsh, epos);
        let v = (mag ^ sm).wrapping_sub(sm); // negate if s
        let satv = sel64(i64::MIN as u64, i64::MAX as u64, sm);
        sel64(satv, v, sat) as i64
    }

    /// Round to the nearest integer, ties-to-even, returning an `i64`.
    pub(crate) fn rint(self) -> i64 {
        self.to_int::<0>()
    }

    /// Floor (round toward −∞), returning an `i64`.
    pub(crate) fn floor(self) -> i64 {
        self.to_int::<1>()
    }

    /// Truncate toward zero, returning an `i64`.
    pub(crate) fn trunc(self) -> i64 {
        self.to_int::<2>()
    }

    /// Total-order key: maps the IEEE bits to a `u64` whose unsigned ordering
    /// matches numeric ordering for non-NaN values. Constant-time.
    #[inline]
    fn order_key(self) -> u64 {
        let b = self.0;
        let mask = (b >> 63).wrapping_neg() | SIGN_BIT;
        b ^ mask
    }

    /// `self < other` by numeric value (constant-time; `-0` and `+0` compare as
    /// adjacent but never gate Falcon's behavior on that boundary).
    #[inline]
    pub(crate) fn lt(self, other: Fpr) -> bool {
        (lt64(self.order_key(), other.order_key()) & 1) != 0
    }

    /// `self <= other` by numeric value.
    #[cfg(test)]
    #[inline]
    pub(crate) fn le(self, other: Fpr) -> bool {
        (lt64(other.order_key(), self.order_key()) & 1) == 0
    }
}

#[cfg(test)]
#[path = "fpr_reference_vt.rs"]
mod fpr_reference_vt;

#[cfg(test)]
#[path = "fpr_tests.rs"]
mod fpr_tests;
