//! Constant-time discrete Gaussian sampler over the integers — `SamplerZ`.
//!
//! This is the security-critical heart of Falcon signing: it samples
//! `z ← D_{ℤ, μ, σ'}` (a discrete Gaussian centered at a *secret* `μ` with a
//! per-leaf `σ' ∈ [σ_min, σ_max]`) without leaking `μ`, `σ'`, or `z` through
//! timing. The algorithm and every constant follow the Falcon specification
//! (§3.9) and the `tprest/falcon.py` reference `samplerz.py`:
//!
//! * [`base_sampler`] — a half-Gaussian over `{0,…,18}` at `σ_max = 1.8205`,
//!   via the 18-entry reverse cumulative distribution table [`RCDT`]; reads 9
//!   bytes (72 bits).
//! * [`approx_exp`] — a fixed-point polynomial approximation of
//!   `2⁶³·ccs·exp(−x)` using the 13 FACCT coefficients [`C`] (all shifts `>>63`).
//! * [`ber_exp`] — a Bernoulli trial accepting with probability `ccs·exp(−x)`,
//!   reading one byte per comparison step (MSB-first), up to 8.
//! * [`sampler_z`] — the outer rejection loop: `base_sampler`, a sign byte, the
//!   rejection exponent, then `ber_exp`.
//!
//! All floating-point work is done in the emulated constant-time [`Fpr`], so the
//! sampler is data-oblivious and bit-reproducible. Validated against the
//! reference `samplerz` KAT vectors in `sampler_tests.rs`, which pin both the
//! output distribution and the exact random-byte consumption.

#![allow(dead_code)] // consumed by the tree/sign phases

use super::fpr::Fpr;

/// A random-byte source for the sampler, mirroring the reference's
/// `randombytes(k)` interface (the sampler requests fixed-size chunks: 9 bytes
/// for the base sampler, 1 byte for the sign and each `ber_exp` step). In
/// signing this is a SHAKE-256 stream seeded per signature; in tests it is the
/// KAT's fixed random-byte string.
pub(crate) trait SamplerRng {
    /// Fill `buf` with the next `buf.len()` random bytes.
    fn next_bytes(&mut self, buf: &mut [u8]);
}

/// Reverse cumulative distribution table for the half-Gaussian at
/// `σ_max = 1.8205`, 72-bit entries (spec §3.9 / reference `samplerz.py`).
const RCDT: [u128; 18] = [
    3024686241123004913666,
    1564742784480091954050,
    636254429462080897535,
    199560484645026482916,
    47667343854657281903,
    8595902006365044063,
    1163297957344668388,
    117656387352093658,
    8867391802663976,
    496969357462633,
    20680885154299,
    638331848991,
    14602316184,
    247426747,
    3104126,
    28824,
    198,
    1,
];

/// Polynomial coefficients for [`approx_exp`] (FACCT; spec §3.9).
const C: [u64; 13] = [
    0x0000_0004_7411_83A3,
    0x0000_0036_548C_FC06,
    0x0000_024F_DCBF_140A,
    0x0000_171D_939D_E045,
    0x0000_D00C_F58F_6F84,
    0x0006_8068_1CF7_96E3,
    0x002D_82D8_305B_0FEA,
    0x0111_1111_0E06_6FD0,
    0x0555_5555_5507_0F00,
    0x1555_5555_5581_FF00,
    0x4000_0000_0002_B400,
    0x7FFF_FFFF_FFFF_4800,
    0x8000_0000_0000_0000,
];

// These deliberately use the reference's *truncated* decimal literals, not the
// full-precision `core::f64::consts` values: the sampler KATs depend on the
// exact IEEE rounding of these specific constants, so swapping in `LN_2` would
// change the bits and break bit-exact agreement.
/// `1 / ln 2`, exactly as the reference rounds the literal `1.44269504089`.
#[allow(clippy::approx_constant)]
const ILN2: Fpr = Fpr::from_f64(1.442_695_040_89);
/// `ln 2`, exactly as the reference rounds the literal `0.69314718056`.
#[allow(clippy::approx_constant)]
const LN2: Fpr = Fpr::from_f64(0.693_147_180_56);
/// `2⁶³` as a double (exactly representable).
const TWO63: Fpr = Fpr::from_f64(9_223_372_036_854_775_808.0);
/// `σ_max = 1.8205`.
const MAX_SIGMA: Fpr = Fpr::from_f64(1.8205);

/// `1 / (2·σ_max²)`, computed in `Fpr` to match the reference's double exactly.
#[inline]
fn inv_2sigma2() -> Fpr {
    // Reference: `1 / (2 * (MAX_SIGMA ** 2))`. Under a correctly-rounded libm,
    // `x ** 2 == x * x`, so `(2*σ)*σ` reproduces it.
    Fpr::from_f64(1.0).div(MAX_SIGMA.double().mul(MAX_SIGMA))
}

/// Half-Gaussian base sampler at `σ_max`: reads 9 bytes little-endian as a
/// 72-bit integer `u`, returns the count of `RCDT` entries strictly above `u`
/// (a value in `0..=18`).
fn base_sampler<R: SamplerRng>(rng: &mut R) -> i64 {
    let mut buf = [0u8; 9];
    rng.next_bytes(&mut buf); // RCDT_PREC >> 3 = 9 bytes
    let mut u: u128 = 0;
    for (i, &byte) in buf.iter().enumerate() {
        u |= (byte as u128) << (8 * i); // little-endian (reference `int.from_bytes`)
    }
    let mut z0: i64 = 0;
    for &elt in &RCDT {
        z0 += (u < elt) as i64;
    }
    z0
}

/// Fixed-point approximation of `2⁶³ · ccs · exp(−x)` for `x ∈ [0, ln 2)` and
/// `ccs ∈ [0, 1]`. Integer Horner evaluation over [`C`]; all shifts are `>>63`.
fn approx_exp(x: Fpr, ccs: Fpr) -> u64 {
    let z = x.mul(TWO63).trunc() as u64; // int(x · 2⁶³)
    let mut y = C[0];
    for &elt in &C[1..] {
        y = elt.wrapping_sub((((z as u128) * (y as u128)) >> 63) as u64);
    }
    let z2 = ((ccs.mul(TWO63).trunc() as u64) << 1) as u128; // int(ccs · 2⁶³) << 1
    (((z2) * (y as u128)) >> 63) as u64
}

/// Bernoulli trial returning `true` with probability `ccs · exp(−x)`
/// (`x ≥ 0`). Reads one byte per MSB-first comparison step, up to 8.
fn ber_exp<R: SamplerRng>(x: Fpr, ccs: Fpr, rng: &mut R) -> bool {
    // s = ⌊x / ln 2⌋ (unclamped for the residual r), then clamp for the shift.
    // For every valid call `x ≥ 0`, so `s_full ∈ [0, 63]` and the lower clamp is
    // a no-op (the sampler KATs are unaffected); the `0` floor only guards the
    // shift against a negative `x` from a pathological out-of-range σ.
    let s_full = x.mul(ILN2).trunc();
    let r = x.sub(Fpr::of_i64(s_full).mul(LN2));
    let s = s_full.clamp(0, 63) as u32;
    // z ≈ 2⁶³ · ccs · exp(−x), scaled down to a 64-bit acceptance threshold.
    let z = approx_exp(r, ccs).wrapping_sub(1) >> s;
    let mut i: i32 = 56;
    while i >= 0 {
        let mut b = [0u8; 1];
        rng.next_bytes(&mut b);
        let w = (b[0] as i32) - (((z >> i) & 0xFF) as i32);
        if w != 0 {
            return w < 0;
        }
        i -= 8;
    }
    false
}

/// Sample `z ← D_{ℤ, μ, σ'}` with `σ' = sigma ∈ [sigmin, σ_max]`.
///
/// Consumes random bytes from `rng` in the reference order: per iteration,
/// 9 bytes (base sampler), 1 byte (sign), then `ber_exp`'s bytes.
pub(crate) fn sampler_z<R: SamplerRng>(mu: Fpr, sigma: Fpr, sigmin: Fpr, rng: &mut R) -> i64 {
    let s = mu.floor();
    let r = mu.sub(Fpr::of_i64(s));
    // dss = 1 / (2·σ²); reference writes `2 * sigma * sigma` = (2σ)·σ.
    let dss = Fpr::from_f64(1.0).div(sigma.double().mul(sigma));
    let ccs = sigmin.div(sigma);
    let inv2s2 = inv_2sigma2();
    loop {
        let z0 = base_sampler(rng);
        let mut sign = [0u8; 1];
        rng.next_bytes(&mut sign);
        let b = (sign[0] & 1) as i64;
        let z = b + (2 * b - 1) * z0;
        // x = (z−r)²·dss − z0²·(1/(2σ_max²)).
        let zr = Fpr::of_i64(z).sub(r);
        let x = zr.mul(zr).mul(dss).sub(Fpr::of_i64(z0 * z0).mul(inv2s2));
        if ber_exp(x, ccs, rng) {
            return z + s;
        }
    }
}

#[cfg(test)]
#[path = "sampler_tests.rs"]
mod sampler_tests;
