//! Low-level ML-DSA (FIPS 204) building blocks — **hazmat**.
//!
//! # Hazmat
//!
//! This module exposes the raw, parameter-set-independent internals of the
//! ML-DSA implementation — the NTT, the [`Poly`] ring type and field
//! arithmetic, coefficient sampling, bit-packing, and the rounding/hint
//! helpers — so downstream threshold-signature libraries (e.g. `mldsa-tss`)
//! can combine partial ML-DSA signatures.
//!
//! **There is no semver-stability guarantee for anything in this module.** The
//! shapes of [`Poly`], [`Params`], and every function here may change in any
//! release. The high-level [`crate::mldsa`] key types are the stable surface.
//!
//! These are raw FIPS 204 primitives with no misuse resistance. **The caller
//! owns correctness and constant-time discipline:** feeding secret-derived
//! values through these functions, ordering operations correctly, and keeping
//! data-dependent branching out of the caller's own code are all the caller's
//! responsibility. Misuse can silently break security.
//!
//! The per-level information needed to drive the primitives (the [`Params`]
//! bundle plus the module dimensions `K`/`L`, which are *not* part of
//! [`Params`]) is exposed as [`ML_DSA_44`], [`ML_DSA_65`], and [`ML_DSA_87`].

// The `unpack_eta{2,4}` raw decoders return `Result<Poly, ()>`: the underlying
// codec carries no richer error than "malformed encoding", and this raw shape
// is preserved deliberately on the hazmat surface rather than wrapped in a new
// error type. Scope the lint allowance to this module.
#![allow(clippy::result_unit_err)]

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub use super::Params;
pub use super::field::Poly;

/// Number of coefficients in a polynomial (`N = 256`).
pub const N: usize = super::field::N;
/// The ML-DSA modulus `q = 2²³ − 2¹³ + 1`.
pub const Q: u32 = super::field::Q;
/// The number of low-order bits dropped by [`power2_round`] (`d = 13`).
pub const D: u32 = super::field::D;

/// A complete ML-DSA security level: the per-level [`Params`] bundle plus the
/// module dimensions `k` (rows) and `l` (columns), which threshold callers need
/// for partial-signature combination but which are *not* stored in [`Params`].
#[derive(Clone, Copy)]
pub struct MlDsaLevel {
    /// The per-level parameter bundle.
    pub params: Params,
    /// `K`, the number of rows in the public matrix `A` (and `t`/`s2` length).
    pub k: usize,
    /// `L`, the number of columns in `A` (and `s1`/`z` length).
    pub l: usize,
}

/// ML-DSA-44 (security level 2): `K = L = 4`.
pub const ML_DSA_44: MlDsaLevel = MlDsaLevel {
    params: super::P44,
    k: 4,
    l: 4,
};
/// ML-DSA-65 (security level 3): `K = 6`, `L = 5`.
pub const ML_DSA_65: MlDsaLevel = MlDsaLevel {
    params: super::P65,
    k: 6,
    l: 5,
};
/// ML-DSA-87 (security level 5): `K = 8`, `L = 7`.
pub const ML_DSA_87: MlDsaLevel = MlDsaLevel {
    params: super::P87,
    k: 8,
    l: 7,
};

// --- field arithmetic over coefficients in `[0, q)` ---

/// Reduces a value in `[0, 2q)` to `[0, q)`.
pub fn reduce_once(a: u32) -> u32 {
    super::field::reduce_once(a)
}

/// `(a + b) mod q` for `a, b < q`.
pub fn add(a: u32, b: u32) -> u32 {
    super::field::add(a, b)
}

/// `(a − b) mod q` for `a, b < q`.
pub fn sub(a: u32, b: u32) -> u32 {
    super::field::sub(a, b)
}

/// Montgomery multiplication; with a Montgomery-domain operand this yields the
/// ordinary-domain product (see [`zeta`]).
pub fn mul(a: u32, b: u32) -> u32 {
    super::field::mul(a, b)
}

/// Component-wise product of two NTT-domain polynomials (`a[i]·b[i]·R⁻¹`).
pub fn ntt_mul(a: &Poly, b: &Poly) -> Poly {
    super::field::ntt_mul(a, b)
}

/// Read-only accessor for the `i`-th NTT twiddle factor (Montgomery form), for
/// callers doing manual NTT-domain work. Panics if `i >= N`.
pub fn zeta(i: usize) -> u32 {
    super::field::zeta(i)
}

// --- rounding, decomposition, and hint helpers (FIPS 204 §7.4) ---

/// `γ₂ = (q − 1) / 32` (ML-DSA-65 / ML-DSA-87).
pub const GAMMA2_32: u32 = super::reduce::GAMMA2_32;
/// `γ₂ = (q − 1) / 88` (ML-DSA-44).
pub const GAMMA2_88: u32 = super::reduce::GAMMA2_88;

/// Power2Round (Algorithm 35): splits `r` into `(r1, r0)` with `r = r1·2ᵈ + r0`
/// and centered `r0`, both returned in field (`[0, q)`) form.
pub fn power2_round(r: u32) -> (u32, u32) {
    super::reduce::power2_round(r)
}

/// Panics unless `gamma2` is one of the two standardized values.
///
/// The rounding helpers are written as `if gamma2 == GAMMA2_32 { … } else { … }`
/// with the `else` arm hard-coded to the `γ₂ = (q−1)/88` constants, so any other
/// value would silently compute a *different* function rather than fail — for
/// `make_hint`/`use_hint` that is a signature-validity bug, not just a wrong
/// number. The check lives here, on the public boundary, and not inside the
/// per-coefficient helpers themselves, which run in the hot signing loop.
#[inline]
fn check_gamma2(gamma2: u32) {
    assert!(
        gamma2 == GAMMA2_32 || gamma2 == GAMMA2_88,
        "ML-DSA gamma2 must be GAMMA2_32 or GAMMA2_88 (FIPS 204 Table 1)"
    );
}

/// HighBits (Algorithm 37) for the given `γ₂`.
///
/// # Panics
///
/// If `gamma2` is neither [`GAMMA2_32`] nor [`GAMMA2_88`].
pub fn high_bits(r: u32, gamma2: u32) -> u32 {
    check_gamma2(gamma2);
    super::reduce::high_bits(r, gamma2)
}

/// Decompose (Algorithm 36): `(HighBits(r), LowBits(r))`, with signed low part.
///
/// # Panics
///
/// If `gamma2` is neither [`GAMMA2_32`] nor [`GAMMA2_88`].
pub fn decompose(r: u32, gamma2: u32) -> (u32, i32) {
    check_gamma2(gamma2);
    super::reduce::decompose(r, gamma2)
}

/// MakeHint (Algorithm 39): `1` iff adding `z` changes the high bits of `r`.
///
/// # Panics
///
/// If `gamma2` is neither [`GAMMA2_32`] nor [`GAMMA2_88`].
pub fn make_hint(z: u32, r: u32, gamma2: u32) -> u32 {
    check_gamma2(gamma2);
    super::reduce::make_hint(z, r, gamma2)
}

/// UseHint (Algorithm 40): recovers the corrected high bits from `hint` and `r`.
///
/// # Panics
///
/// If `gamma2` is neither [`GAMMA2_32`] nor [`GAMMA2_88`].
pub fn use_hint(hint: u32, r: u32, gamma2: u32) -> u32 {
    check_gamma2(gamma2);
    super::reduce::use_hint(hint, r, gamma2)
}

/// Infinity norm of a single coefficient: `min(a, q − a)`.
pub fn inf_norm(a: u32) -> u32 {
    super::reduce::inf_norm(a)
}

// --- rejection / expansion sampling from SHAKE (FIPS 204 §7.1, §7.3) ---

/// RejNTTPoly / ExpandA (Algorithm 30): a uniform NTT-domain polynomial from
/// `SHAKE128(rho ‖ s ‖ r)`.
pub fn sample_ntt_poly(rho: &[u8], s: u8, r: u8) -> Poly {
    super::sample::sample_ntt_poly(rho, s, r)
}

/// RejBoundedPoly / ExpandS (Algorithm 31): coefficients in `[−η, η]` from
/// `SHAKE256(seed ‖ nonce)`.
///
/// # Panics
///
/// If `eta` is neither 2 nor 4 — the only values FIPS 204 defines. Any other
/// value would otherwise silently sample the `η = 4` distribution.
pub fn sample_bounded_poly(seed: &[u8], eta: u32, nonce: u16) -> Poly {
    super::sample::sample_bounded_poly(seed, eta, nonce)
}

/// SampleInBall (Algorithm 29): a challenge with `tau` coefficients in `{−1, 1}`.
///
/// # Panics
///
/// If `tau > N`. The sampler fills positions `N − tau ..< N`, so a larger `tau`
/// would underflow that subtraction and — in a release build, where the
/// underflow wraps rather than panicking — return the all-zero polynomial as
/// the "challenge", which every `z` satisfies. `tau` is a public parameter, so
/// the check leaks nothing.
pub fn sample_challenge(seed: &[u8], tau: usize) -> Poly {
    super::sample::sample_challenge(seed, tau)
}

/// ExpandMask (Algorithm 34): the masking-vector polynomial from
/// `SHAKE256(seed)`, with `gamma1_bits` of 17 or 19.
///
/// # Panics
///
/// If `gamma1_bits` is neither 17 nor 19; any other width would silently
/// produce the `γ₁ = 2¹⁹` encoding.
pub fn expand_mask(seed: &[u8], gamma1_bits: u32) -> Poly {
    super::sample::expand_mask(seed, gamma1_bits)
}

// --- bit-packing of polynomials and the hint (FIPS 204 §7.2–§7.3) ---

/// Packs `t1` with 10 bits per coefficient (320 bytes).
#[cfg(feature = "alloc")]
pub fn pack_t1(f: &Poly) -> Vec<u8> {
    let mut v = alloc::vec![0u8; N * 10 / 8];
    super::encode::pack_t1(f, &mut v);
    v
}

/// The exact byte length [`unpack_t1`] consumes (320).
pub const T1_LEN: usize = N * 10 / 8;
/// The exact byte length [`unpack_t0`] consumes (416).
pub const T0_LEN: usize = N * 13 / 8;
/// The exact byte length [`unpack_eta2`] consumes (96).
pub const ETA2_LEN: usize = N * 3 / 8;
/// The exact byte length [`unpack_eta4`] consumes (128).
pub const ETA4_LEN: usize = N * 4 / 8;
/// The exact byte length [`unpack_z17`] consumes (576).
pub const Z17_LEN: usize = N * 18 / 8;
/// The exact byte length [`unpack_z19`] consumes (640).
pub const Z19_LEN: usize = N * 20 / 8;

/// Unpacks `t1` (10 bits per coefficient).
///
/// Returns `None` unless `b` is exactly [`T1_LEN`] bytes. The decoders index
/// fixed offsets, so a short slice would panic; the rest of the crate always
/// length-checks before calling, but this is a public surface reachable with
/// any slice.
pub fn unpack_t1(b: &[u8]) -> Option<Poly> {
    if b.len() != T1_LEN {
        return None;
    }
    Some(super::encode::unpack_t1(b))
}

/// Packs `t0` with 13 bits per signed coefficient (416 bytes).
#[cfg(feature = "alloc")]
pub fn pack_t0(f: &Poly) -> Vec<u8> {
    let mut v = alloc::vec![0u8; N * 13 / 8];
    super::encode::pack_t0(f, &mut v);
    v
}

/// Unpacks `t0` (13 bits per signed coefficient). Returns `None` unless `b` is
/// exactly [`T0_LEN`] bytes.
pub fn unpack_t0(b: &[u8]) -> Option<Poly> {
    if b.len() != T0_LEN {
        return None;
    }
    Some(super::encode::unpack_t0(b))
}

/// Packs an `η = 2` secret coefficient vector (3 bits each, 96 bytes).
///
/// **Precondition:** every coefficient is a valid `η = 2` value, i.e. lies in
/// `{q−2, q−1, 0, 1, 2}` (what [`sample_bounded_poly`] and [`unpack_eta2`]
/// produce). The packer writes 3-bit fields with no range check, so a
/// coefficient outside that set overflows into its neighbours.
#[cfg(feature = "alloc")]
pub fn pack_eta2(f: &Poly) -> Vec<u8> {
    let mut v = alloc::vec![0u8; N * 3 / 8];
    super::encode::pack_eta2(f, &mut v);
    v
}

/// Unpacks an `η = 2` vector, validating each 3-bit group is ≤ 4. `Err(())`
/// signals only "malformed encoding" — including `b` not being exactly
/// [`ETA2_LEN`] bytes.
pub fn unpack_eta2(b: &[u8]) -> Result<Poly, ()> {
    if b.len() != ETA2_LEN {
        return Err(());
    }
    super::encode::unpack_eta2(b)
}

/// Packs an `η = 4` secret coefficient vector (4 bits each, 128 bytes).
///
/// **Precondition:** every coefficient is a valid `η = 4` value, i.e. lies in
/// `{q−4, …, q−1, 0, …, 4}`. The packer writes 4-bit fields with no range
/// check, so a coefficient outside that set overflows into its neighbours.
#[cfg(feature = "alloc")]
pub fn pack_eta4(f: &Poly) -> Vec<u8> {
    let mut v = alloc::vec![0u8; N * 4 / 8];
    super::encode::pack_eta4(f, &mut v);
    v
}

/// Unpacks an `η = 4` vector, validating each nibble is ≤ 8. `Err(())` signals
/// only "malformed encoding" — including `b` not being exactly [`ETA4_LEN`]
/// bytes.
pub fn unpack_eta4(b: &[u8]) -> Result<Poly, ()> {
    if b.len() != ETA4_LEN {
        return Err(());
    }
    super::encode::unpack_eta4(b)
}

/// Packs `z` with `γ₁ = 2¹⁷` (18 bits each, 576 bytes).
#[cfg(feature = "alloc")]
pub fn pack_z17(f: &Poly) -> Vec<u8> {
    let mut v = alloc::vec![0u8; N * 18 / 8];
    super::encode::pack_z17(f, &mut v);
    v
}

/// Packs `z` with `γ₁ = 2¹⁹` (20 bits each, 640 bytes).
#[cfg(feature = "alloc")]
pub fn pack_z19(f: &Poly) -> Vec<u8> {
    let mut v = alloc::vec![0u8; N * 20 / 8];
    super::encode::pack_z19(f, &mut v);
    v
}

/// Unpacks `z` with `γ₁ = 2¹⁷` (18 bits each). Returns `None` unless `b` is
/// exactly [`Z17_LEN`] bytes.
pub fn unpack_z17(b: &[u8]) -> Option<Poly> {
    if b.len() != Z17_LEN {
        return None;
    }
    Some(super::encode::unpack_z17(b))
}

/// Unpacks `z` with `γ₁ = 2¹⁹` (20 bits each). Returns `None` unless `b` is
/// exactly [`Z19_LEN`] bytes.
pub fn unpack_z19(b: &[u8]) -> Option<Poly> {
    if b.len() != Z19_LEN {
        return None;
    }
    Some(super::encode::unpack_z19(b))
}

/// Packs `w1` with 4 bits per coefficient (ML-DSA-65/87, 128 bytes).
///
/// **Precondition:** every coefficient is in `0..16` (the range [`high_bits`]
/// and [`use_hint`] return for `γ₂ = GAMMA2_32`). The packer writes 4-bit
/// fields with no range check, so a larger value overflows into its neighbour.
#[cfg(feature = "alloc")]
pub fn pack_w1_4(f: &Poly) -> Vec<u8> {
    let mut v = alloc::vec![0u8; N * 4 / 8];
    super::encode::pack_w1_4(f, &mut v);
    v
}

/// Packs `w1` with 6 bits per coefficient (ML-DSA-44, 192 bytes).
///
/// **Precondition:** every coefficient is in `0..44` (the range [`high_bits`]
/// and [`use_hint`] return for `γ₂ = GAMMA2_88`). The packer writes 6-bit
/// fields with no range check, so a larger value overflows into its neighbour.
#[cfg(feature = "alloc")]
pub fn pack_w1_6(f: &Poly) -> Vec<u8> {
    let mut v = alloc::vec![0u8; N * 6 / 8];
    super::encode::pack_w1_6(f, &mut v);
    v
}

/// Packs the hint: per-polynomial set-bit positions followed by running counts
/// (`omega + k` bytes, where `k = hints.len()`).
///
/// Returns `None` if the hints carry more than `omega` set coefficients in
/// total. The underlying packer writes positions into the first `omega` bytes
/// without checking, so an over-full hint would corrupt the running-count
/// region and then panic past the end of the buffer.
///
/// Also returns `None` for `omega > 255`: the running counts are single bytes,
/// so a larger `ω` would truncate them and produce an encoding that decodes to
/// a different hint. Every standardized level uses `ω ≤ 75`.
#[cfg(feature = "alloc")]
pub fn pack_hint(hints: &[Poly], omega: usize) -> Option<Vec<u8>> {
    if omega > 255 {
        return None;
    }
    let total: usize = hints
        .iter()
        .map(|h| h.c.iter().filter(|&&c| c != 0).count())
        .sum();
    if total > omega {
        return None;
    }
    let mut v = alloc::vec![0u8; omega + hints.len()];
    super::encode::pack_hint(hints, omega, &mut v);
    Some(v)
}

/// Unpacks the hint into `hints`, rejecting malformed encodings (non-increasing
/// positions, out-of-range counts, or non-zero padding). Returns `false` on a
/// malformed input — including a `b` shorter than the `omega + hints.len()`
/// bytes the encoding occupies, which the underlying decoder would index past.
pub fn unpack_hint(b: &[u8], hints: &mut [Poly], omega: usize) -> bool {
    match omega.checked_add(hints.len()) {
        Some(need) if b.len() >= need => super::encode::unpack_hint(b, hints, omega),
        _ => false,
    }
}

// --- Params-dispatched packing helpers ---

/// Panics unless `p.eta` is one of the two standardized values.
///
/// Every `η`-dispatched routine is an `if p.eta == 2 { … } else { … }` whose
/// `else` arm is the `η = 4` encoding, so an out-of-range `η` in a caller-built
/// [`Params`] silently selects the wrong one instead of failing.
#[inline]
fn check_eta(p: &Params) {
    assert!(
        p.eta == 2 || p.eta == 4,
        "ML-DSA eta must be 2 or 4 (FIPS 204 Table 1)"
    );
}

/// Panics unless `p.gamma1_bits` is 17 or 19 (same reasoning as [`check_eta`]).
#[inline]
fn check_gamma1(p: &Params) {
    assert!(
        p.gamma1_bits == 17 || p.gamma1_bits == 19,
        "ML-DSA gamma1 bit width must be 17 or 19 (FIPS 204 Table 1)"
    );
}

/// Packs the secret coefficient vector `f` with the `η` width selected by `p`.
///
/// Every coefficient must already be a valid `η`-bounded value — that is, in
/// `{q−η, …, q−1} ∪ {0, …, η}` — which is what [`sample_bounded_poly`] and
/// [`unpack_eta`] produce. The packer writes fixed-width fields without
/// checking, so an out-of-range coefficient corrupts its neighbours in the
/// output rather than being reported.
///
/// # Panics
///
/// If `p.eta` is neither 2 nor 4.
#[cfg(feature = "alloc")]
pub fn pack_eta(f: &Poly, p: &Params) -> Vec<u8> {
    check_eta(p);
    let mut v = alloc::vec![0u8; if p.eta == 2 { N * 3 / 8 } else { N * 4 / 8 }];
    super::pack_eta(f, p, &mut v);
    v
}

/// Unpacks an `η`-encoded coefficient vector for the level described by `p`,
/// returning [`super::Error::Malformed`] on an out-of-range encoding or a `b`
/// whose length is not the [`ETA2_LEN`] / [`ETA4_LEN`] the level requires.
///
/// # Panics
///
/// If `p.eta` is neither 2 nor 4.
pub fn unpack_eta(b: &[u8], p: &Params) -> Result<Poly, super::Error> {
    check_eta(p);
    let need = if p.eta == 2 { ETA2_LEN } else { ETA4_LEN };
    if b.len() != need {
        return Err(super::Error::Malformed);
    }
    super::unpack_eta(b, p)
}

/// Packs `z` with the `γ₁` width selected by `p`.
///
/// # Panics
///
/// If `p.gamma1_bits` is neither 17 nor 19.
#[cfg(feature = "alloc")]
pub fn pack_z(f: &Poly, p: &Params) -> Vec<u8> {
    check_gamma1(p);
    let mut v = alloc::vec![0u8; if p.gamma1_bits == 17 { N * 18 / 8 } else { N * 20 / 8 }];
    super::pack_z(f, p, &mut v);
    v
}

/// Unpacks a `z`-encoded coefficient vector for the level described by `p`.
///
/// Returns `None` unless `b` is exactly the [`Z17_LEN`] / [`Z19_LEN`] the
/// level's `γ₁` requires.
///
/// # Panics
///
/// If `p.gamma1_bits` is neither 17 nor 19.
pub fn unpack_z(b: &[u8], p: &Params) -> Option<Poly> {
    check_gamma1(p);
    let need = if p.gamma1_bits == 17 {
        Z17_LEN
    } else {
        Z19_LEN
    };
    if b.len() != need {
        return None;
    }
    Some(super::unpack_z(b, p))
}

/// Packs `w1` with the width selected by `p`.
///
/// Every coefficient must already be a valid `w1` high-bits value for this
/// level — `0..16` for `γ₂ = GAMMA2_32`, `0..44` for `GAMMA2_88`, which is what
/// [`high_bits`] and [`use_hint`] return. The packer writes fixed-width fields
/// without checking, so a larger coefficient corrupts its neighbours in the
/// output rather than being reported.
///
/// # Panics
///
/// If `p.gamma2` is neither [`GAMMA2_32`] nor [`GAMMA2_88`].
#[cfg(feature = "alloc")]
pub fn pack_w1(f: &Poly, p: &Params) -> Vec<u8> {
    check_gamma2(p.gamma2);
    let mut v = alloc::vec![0u8; if p.gamma2 == super::GAMMA2_88 { N * 6 / 8 } else { N * 4 / 8 }];
    super::pack_w1(f, p, &mut v);
    v
}

// The packing round-trips below go through the `Vec`-returning `pack_*`
// wrappers, which only exist with `alloc`.
#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    /// A fixed, deterministic-ish polynomial with all coefficients in `[0, q)`.
    fn sample_poly() -> Poly {
        let mut p = Poly::zero();
        for i in 0..N {
            p.c[i] = ((i as u32).wrapping_mul(2_654_435_761)) % Q;
        }
        p
    }

    /// Schoolbook negacyclic product `a·b mod (xⁿ + 1, q)`, the reference the
    /// NTT pipeline (`ntt` → `ntt_mul` → `inv_ntt`) must reproduce. Each `acc`
    /// entry is bounded by `N · q²`, well within `i128`, so the single final
    /// reduction is exact.
    fn negacyclic_mul(a: &Poly, b: &Poly) -> Poly {
        let mut acc = [0i128; N];
        for (i, &ai) in a.c.iter().enumerate() {
            for (j, &bj) in b.c.iter().enumerate() {
                let prod = (ai as i128) * (bj as i128);
                let k = i + j;
                if k < N {
                    acc[k] += prod;
                } else {
                    // xⁿ = −1, so the wrapped term is subtracted.
                    acc[k - N] -= prod;
                }
            }
        }
        let mut r = Poly::zero();
        for (dst, &a) in r.c.iter_mut().zip(acc.iter()) {
            *dst = a.rem_euclid(Q as i128) as u32;
        }
        r
    }

    /// The NTT pipeline (`ntt` → `ntt_mul` → `inv_ntt`) must reproduce the
    /// negacyclic ring product, pinning `ntt`, `ntt_mul`, and `inv_ntt`
    /// together exactly as the sign/verify hot paths chain them.
    #[test]
    fn ntt_multiply_matches_schoolbook() {
        let a = sample_poly();
        let mut b = Poly::zero();
        for i in 0..N {
            b.c[i] = ((i as u32).wrapping_mul(40_503).wrapping_add(7)) % Q;
        }
        let want = negacyclic_mul(&a, &b);

        let mut a_ntt = a;
        a_ntt.ntt();
        let mut b_ntt = b;
        b_ntt.ntt();
        let mut got = ntt_mul(&a_ntt, &b_ntt);
        got.inv_ntt();

        assert_eq!(got, want, "NTT product != schoolbook negacyclic product");
    }

    /// Pointwise NTT-domain multiplication is commutative — the property the
    /// matrix·vector products in sign/verify rely on.
    #[test]
    fn ntt_mul_commutes() {
        let mut a = sample_poly();
        a.ntt();
        let mut b = Poly::zero();
        for i in 0..N {
            b.c[i] = ((i as u32).wrapping_mul(40_503).wrapping_add(7)) % Q;
        }
        b.ntt();
        assert_eq!(
            ntt_mul(&a, &b),
            ntt_mul(&b, &a),
            "ntt_mul is not commutative"
        );
    }

    /// `pack_t1` / `unpack_t1` round-trips on values in the 10-bit range.
    #[test]
    fn pack_unpack_t1_roundtrip() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.c[i] = (i as u32) & 0x3ff;
        }
        let bytes = pack_t1(&p);
        assert_eq!(bytes.len(), N * 10 / 8);
        assert_eq!(unpack_t1(&bytes), Some(p));
    }

    /// `pack_z` / `unpack_z` round-trips through both `γ₁` widths.
    #[test]
    fn pack_unpack_z_roundtrip() {
        let mut p = Poly::zero();
        for i in 0..N {
            // Centered values within [-γ₁, γ₁]; sub(γ₁, k) maps into [0, q).
            p.c[i] = sub(ML_DSA_44.params.gamma1, (i as u32) % 7);
        }
        let b44 = pack_z(&p, &ML_DSA_44.params);
        assert_eq!(unpack_z(&b44, &ML_DSA_44.params), Some(p));

        let mut p2 = Poly::zero();
        for i in 0..N {
            p2.c[i] = sub(ML_DSA_65.params.gamma1, (i as u32) % 11);
        }
        let b65 = pack_z(&p2, &ML_DSA_65.params);
        assert_eq!(unpack_z(&b65, &ML_DSA_65.params), Some(p2));
    }

    /// `sample_ntt_poly` is deterministic in its `(rho, s, r)` inputs.
    #[test]
    fn sample_ntt_poly_deterministic() {
        let rho = [7u8; 32];
        let a = sample_ntt_poly(&rho, 1, 2);
        let b = sample_ntt_poly(&rho, 1, 2);
        assert_eq!(a, b, "sample_ntt_poly is not deterministic");
        // A different domain separator yields a different polynomial.
        let c = sample_ntt_poly(&rho, 2, 1);
        assert_ne!(a, c, "domain separation had no effect");
    }

    /// The exposed level table carries the correct `(K, L)` per level.
    #[test]
    fn level_dimensions() {
        assert_eq!((ML_DSA_44.k, ML_DSA_44.l), (4, 4));
        assert_eq!((ML_DSA_65.k, ML_DSA_65.l), (6, 5));
        assert_eq!((ML_DSA_87.k, ML_DSA_87.l), (8, 7));
    }

    /// The decoders index fixed offsets into `b`. The rest of the crate always
    /// length-checks first, but this is a public surface that takes any slice,
    /// so every short (and over-long) input must be refused rather than panic.
    #[test]
    fn decoders_reject_short_input_instead_of_panicking() {
        for len in [0usize, 1, 95, 96, 127, 320, 415, 416, 575, 639, 641, 1024] {
            let b = alloc::vec![0u8; len];
            assert_eq!(unpack_t1(&b).is_some(), len == T1_LEN, "t1 len={len}");
            assert_eq!(unpack_t0(&b).is_some(), len == T0_LEN, "t0 len={len}");
            assert_eq!(unpack_z17(&b).is_some(), len == Z17_LEN, "z17 len={len}");
            assert_eq!(unpack_z19(&b).is_some(), len == Z19_LEN, "z19 len={len}");
            // The all-zero encodings are in range, so a correct length is the
            // only thing that can make these succeed.
            assert_eq!(unpack_eta2(&b).is_ok(), len == ETA2_LEN, "eta2 len={len}");
            assert_eq!(unpack_eta4(&b).is_ok(), len == ETA4_LEN, "eta4 len={len}");

            for level in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
                let p = &level.params;
                let eta_need = if p.eta == 2 { ETA2_LEN } else { ETA4_LEN };
                assert_eq!(unpack_eta(&b, p).is_ok(), len == eta_need, "eta len={len}");
                let z_need = if p.gamma1_bits == 17 {
                    Z17_LEN
                } else {
                    Z19_LEN
                };
                assert_eq!(unpack_z(&b, p).is_some(), len == z_need, "z len={len}");
            }
        }
    }

    /// `unpack_hint` indexed `b[omega + i]` unchecked, so a buffer shorter than
    /// `omega + k` panicked.
    #[test]
    fn unpack_hint_rejects_short_input() {
        let omega = ML_DSA_44.params.omega;
        let k = ML_DSA_44.k;
        for len in 0..(omega + k) {
            let b = alloc::vec![0u8; len];
            let mut hints = alloc::vec![Poly::zero(); k];
            assert!(!unpack_hint(&b, &mut hints, omega), "len={len}");
        }
        // At the exact length an all-zero (empty) hint decodes fine.
        let b = alloc::vec![0u8; omega + k];
        let mut hints = alloc::vec![Poly::zero(); k];
        assert!(unpack_hint(&b, &mut hints, omega));
    }

    /// `pack_hint` wrote positions into the first `omega` bytes without
    /// checking: more than `omega` set coefficients corrupted the running-count
    /// region and then panicked past the end of the buffer.
    #[test]
    fn pack_hint_rejects_more_than_omega_set_bits() {
        let omega = ML_DSA_44.params.omega;
        let k = ML_DSA_44.k;

        // Exactly `omega` set bits, spread over the k polynomials: accepted.
        let mut hints = alloc::vec![Poly::zero(); k];
        for i in 0..omega {
            hints[i % k].c[i] = 1;
        }
        let packed = pack_hint(&hints, omega).expect("exactly omega set bits fits");
        assert_eq!(packed.len(), omega + k);
        let mut back = alloc::vec![Poly::zero(); k];
        assert!(unpack_hint(&packed, &mut back, omega));

        // One more: refused instead of corrupting the buffer.
        let mut over = alloc::vec![Poly::zero(); k];
        for i in 0..=omega {
            over[i % k].c[i] = 1;
        }
        assert!(pack_hint(&over, omega).is_none());

        // The running counts are single bytes, so omega > 255 would truncate.
        assert!(pack_hint(&alloc::vec![Poly::zero(); k], 256).is_none());
    }

    /// `unpack_hint` used to OR into the caller's polynomials, so decoding into
    /// a reused buffer produced the union of the old and new hints — extra
    /// `use_hint` corrections the signature never authorized.
    #[test]
    fn unpack_hint_overwrites_the_caller_buffer() {
        let omega = ML_DSA_44.params.omega;
        let k = ML_DSA_44.k;

        let mut hints = alloc::vec![Poly::zero(); k];
        hints[0].c[5] = 1;
        hints[1].c[200] = 1;
        let packed = pack_hint(&hints, omega).expect("fits");

        // Decode into a buffer that is dirty in positions the encoding does not
        // mention; they must be gone afterwards.
        let mut dirty = alloc::vec![Poly::zero(); k];
        dirty[0].c[9] = 1;
        dirty[2].c[77] = 1;
        assert!(unpack_hint(&packed, &mut dirty, omega));
        assert_eq!(dirty, hints, "decode must overwrite, never OR");
    }

    /// `tau > N` underflowed `N - tau`; in release the wrap made the fill loop
    /// empty and silently returned the ZERO challenge, which every `z`
    /// satisfies. It must panic instead.
    #[test]
    #[should_panic(expected = "tau must not exceed")]
    fn sample_challenge_rejects_oversized_tau() {
        let _ = sample_challenge(&[0u8; 32], N + 1);
    }

    /// `tau == N` is the largest legal value and must still work.
    #[test]
    fn sample_challenge_accepts_tau_up_to_n() {
        let c = sample_challenge(&[3u8; 32], N);
        assert!(c.c.iter().any(|&x| x != 0), "challenge must not be zero");
    }

    /// Out-of-range `eta` / `gamma1_bits` / `gamma2` select the *other* branch
    /// of a two-way dispatch rather than failing, so each entry point asserts.
    // `catch_unwind` needs `std`; the assertions themselves are unconditional.
    #[cfg(feature = "std")]
    #[test]
    fn parameter_dispatch_rejects_undefined_values() {
        fn panics(f: impl FnOnce() + core::panic::UnwindSafe) -> bool {
            std::panic::catch_unwind(f).is_err()
        }
        let hook = std::panic::take_hook();
        std::panic::set_hook(alloc::boxed::Box::new(|_| {}));

        assert!(panics(|| {
            let _ = sample_bounded_poly(&[0u8; 64], 3, 0);
        }));
        assert!(panics(|| {
            let _ = expand_mask(&[0u8; 66], 18);
        }));
        assert!(panics(|| {
            let _ = high_bits(0, 12345);
        }));
        assert!(panics(|| {
            let _ = decompose(0, 12345);
        }));
        assert!(panics(|| {
            let _ = make_hint(0, 0, 12345);
        }));
        assert!(panics(|| {
            let _ = use_hint(1, 0, 12345);
        }));

        let mut bad = ML_DSA_44.params;
        bad.eta = 3;
        assert!(panics(move || {
            let _ = pack_eta(&Poly::zero(), &bad);
        }));
        assert!(panics(move || {
            let _ = unpack_eta(&[0u8; ETA2_LEN], &bad);
        }));
        let mut bad_g1 = ML_DSA_44.params;
        bad_g1.gamma1_bits = 18;
        assert!(panics(move || {
            let _ = pack_z(&Poly::zero(), &bad_g1);
        }));
        assert!(panics(move || {
            let _ = unpack_z(&[0u8; Z17_LEN], &bad_g1);
        }));
        let mut bad_g2 = ML_DSA_44.params;
        bad_g2.gamma2 = 7;
        assert!(panics(move || {
            let _ = pack_w1(&Poly::zero(), &bad_g2);
        }));

        std::panic::set_hook(hook);
    }
}
