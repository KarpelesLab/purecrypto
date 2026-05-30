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

/// HighBits (Algorithm 37) for the given `γ₂`.
pub fn high_bits(r: u32, gamma2: u32) -> u32 {
    super::reduce::high_bits(r, gamma2)
}

/// Decompose (Algorithm 36): `(HighBits(r), LowBits(r))`, with signed low part.
pub fn decompose(r: u32, gamma2: u32) -> (u32, i32) {
    super::reduce::decompose(r, gamma2)
}

/// MakeHint (Algorithm 39): `1` iff adding `z` changes the high bits of `r`.
pub fn make_hint(z: u32, r: u32, gamma2: u32) -> u32 {
    super::reduce::make_hint(z, r, gamma2)
}

/// UseHint (Algorithm 40): recovers the corrected high bits from `hint` and `r`.
pub fn use_hint(hint: u32, r: u32, gamma2: u32) -> u32 {
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
pub fn sample_bounded_poly(seed: &[u8], eta: u32, nonce: u16) -> Poly {
    super::sample::sample_bounded_poly(seed, eta, nonce)
}

/// SampleInBall (Algorithm 29): a challenge with `tau` coefficients in `{−1, 1}`.
pub fn sample_challenge(seed: &[u8], tau: usize) -> Poly {
    super::sample::sample_challenge(seed, tau)
}

/// ExpandMask (Algorithm 34): the masking-vector polynomial from
/// `SHAKE256(seed)`, with `gamma1_bits` of 17 or 19.
pub fn expand_mask(seed: &[u8], gamma1_bits: u32) -> Poly {
    super::sample::expand_mask(seed, gamma1_bits)
}

// --- bit-packing of polynomials and the hint (FIPS 204 §7.2–§7.3) ---

/// Packs `t1` with 10 bits per coefficient (320 bytes).
pub fn pack_t1(f: &Poly) -> Vec<u8> {
    super::encode::pack_t1(f)
}

/// Unpacks `t1` (10 bits per coefficient).
pub fn unpack_t1(b: &[u8]) -> Poly {
    super::encode::unpack_t1(b)
}

/// Packs `t0` with 13 bits per signed coefficient (416 bytes).
pub fn pack_t0(f: &Poly) -> Vec<u8> {
    super::encode::pack_t0(f)
}

/// Unpacks `t0` (13 bits per signed coefficient).
pub fn unpack_t0(b: &[u8]) -> Poly {
    super::encode::unpack_t0(b)
}

/// Packs an `η = 2` secret coefficient vector (3 bits each, 96 bytes).
pub fn pack_eta2(f: &Poly) -> Vec<u8> {
    super::encode::pack_eta2(f)
}

/// Unpacks an `η = 2` vector, validating each 3-bit group is ≤ 4. `Err(())`
/// signals only "malformed encoding".
pub fn unpack_eta2(b: &[u8]) -> Result<Poly, ()> {
    super::encode::unpack_eta2(b)
}

/// Packs an `η = 4` secret coefficient vector (4 bits each, 128 bytes).
pub fn pack_eta4(f: &Poly) -> Vec<u8> {
    super::encode::pack_eta4(f)
}

/// Unpacks an `η = 4` vector, validating each nibble is ≤ 8. `Err(())` signals
/// only "malformed encoding".
pub fn unpack_eta4(b: &[u8]) -> Result<Poly, ()> {
    super::encode::unpack_eta4(b)
}

/// Packs `z` with `γ₁ = 2¹⁷` (18 bits each, 576 bytes).
pub fn pack_z17(f: &Poly) -> Vec<u8> {
    super::encode::pack_z17(f)
}

/// Packs `z` with `γ₁ = 2¹⁹` (20 bits each, 640 bytes).
pub fn pack_z19(f: &Poly) -> Vec<u8> {
    super::encode::pack_z19(f)
}

/// Unpacks `z` with `γ₁ = 2¹⁷` (18 bits each).
pub fn unpack_z17(b: &[u8]) -> Poly {
    super::encode::unpack_z17(b)
}

/// Unpacks `z` with `γ₁ = 2¹⁹` (20 bits each).
pub fn unpack_z19(b: &[u8]) -> Poly {
    super::encode::unpack_z19(b)
}

/// Packs `w1` with 4 bits per coefficient (ML-DSA-65/87, 128 bytes).
pub fn pack_w1_4(f: &Poly) -> Vec<u8> {
    super::encode::pack_w1_4(f)
}

/// Packs `w1` with 6 bits per coefficient (ML-DSA-44, 192 bytes).
pub fn pack_w1_6(f: &Poly) -> Vec<u8> {
    super::encode::pack_w1_6(f)
}

/// Packs the hint: per-polynomial set-bit positions followed by running counts
/// (`omega + k` bytes, where `k = hints.len()`).
pub fn pack_hint(hints: &[Poly], omega: usize) -> Vec<u8> {
    super::encode::pack_hint(hints, omega)
}

/// Unpacks the hint into `hints`, rejecting malformed encodings (non-increasing
/// positions, out-of-range counts, or non-zero padding). Returns `false` on a
/// malformed input.
pub fn unpack_hint(b: &[u8], hints: &mut [Poly], omega: usize) -> bool {
    super::encode::unpack_hint(b, hints, omega)
}

// --- Params-dispatched packing helpers ---

/// Packs the secret coefficient vector `f` with the `η` width selected by `p`.
pub fn pack_eta(f: &Poly, p: &Params) -> Vec<u8> {
    super::pack_eta(f, p)
}

/// Unpacks an `η`-encoded coefficient vector for the level described by `p`,
/// returning [`super::Error::Malformed`] on an out-of-range encoding.
pub fn unpack_eta(b: &[u8], p: &Params) -> Result<Poly, super::Error> {
    super::unpack_eta(b, p)
}

/// Packs `z` with the `γ₁` width selected by `p`.
pub fn pack_z(f: &Poly, p: &Params) -> Vec<u8> {
    super::pack_z(f, p)
}

/// Unpacks a `z`-encoded coefficient vector for the level described by `p`.
pub fn unpack_z(b: &[u8], p: &Params) -> Poly {
    super::unpack_z(b, p)
}

/// Packs `w1` with the width selected by `p`.
pub fn pack_w1(f: &Poly, p: &Params) -> Vec<u8> {
    super::pack_w1(f, p)
}

#[cfg(test)]
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
        assert_eq!(unpack_t1(&bytes), p);
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
        assert_eq!(unpack_z(&b44, &ML_DSA_44.params), p);

        let mut p2 = Poly::zero();
        for i in 0..N {
            p2.c[i] = sub(ML_DSA_65.params.gamma1, (i as u32) % 11);
        }
        let b65 = pack_z(&p2, &ML_DSA_65.params);
        assert_eq!(unpack_z(&b65, &ML_DSA_65.params), p2);
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
}
