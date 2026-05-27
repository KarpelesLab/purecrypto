//! Rounding, decomposition, and hint helpers (FIPS 204 §7.4).

use super::field::{Q, Q_MINUS_1_DIV2, add};

/// `γ₂ = (q − 1) / 32` (ML-DSA-65 / ML-DSA-87).
pub(crate) const GAMMA2_32: u32 = (Q - 1) / 32;
/// `γ₂ = (q − 1) / 88` (ML-DSA-44).
pub(crate) const GAMMA2_88: u32 = (Q - 1) / 88;

const D: u32 = super::field::D;

/// Power2Round (Algorithm 35): `r = r1·2ᵈ + r0` with centered `r0`. Both halves
/// are returned in field (`[0, q)`) form.
///
/// The conditional centering branch (`if r0 > HALF`) is rewritten as
/// arithmetic so the per-coefficient running time does not depend on the
/// low bits of `r`. `r = A·s₁ + s₂` is secret-derived during signing, so a
/// data-dependent branch here is a per-coefficient timing channel into
/// `s₁`/`s₂`. The branchless form below matches the reference output
/// bit-for-bit (verified by the ML-DSA KAT suite); on each `r ∈ [0, q)`
/// the values produced are identical.
pub(crate) fn power2_round(r: u32) -> (u32, u32) {
    const HALF: u32 = 1 << (D - 1);
    const POW_D: u32 = 1 << D;
    let r1 = r >> D;
    let r0 = r - (r1 << D); // r0 in [0, 2^D)

    // gt is all-ones (0xFFFF_FFFF) when r0 > HALF, else 0. Computed without
    // a branch: (HALF - r0) wraps negative iff r0 > HALF; its sign bit
    // (i32 >> 31) propagates 1s.
    let gt = ((HALF as i32).wrapping_sub(r0 as i32) >> 31) as u32;

    // When gt = -1: r1' = r1 + 1; r0' = r0 - 2^D mod q = r0 + (q - 2^D)
    //   (the existing branch did `sub(r0, 1<<D)` = `reduce_once(r0 + q - 2^D)`;
    //    r0 < 2^D ≤ q so r0 + q - 2^D < q, i.e. reduce_once is a no-op).
    // When gt = 0: both halves are unchanged.
    let r1_adj = r1.wrapping_add(gt & 1);
    let r0_adj = r0.wrapping_add(gt & (Q - POW_D));
    (r1_adj, r0_adj)
}

/// HighBits (Algorithm 37).
pub(crate) fn high_bits(r: u32, gamma2: u32) -> u32 {
    let mut r1 = ((r + 127) >> 7) as i32;
    if gamma2 == GAMMA2_32 {
        r1 = (r1 * 1025 + (1 << 21)) >> 22;
        (r1 & 15) as u32
    } else {
        r1 = (r1 * 11275 + (1 << 23)) >> 24;
        r1 ^= ((43 - r1) >> 31) & r1;
        r1 as u32
    }
}

/// Decompose (Algorithm 36): `r1 = HighBits(r)`, `r0 = LowBits(r)` (signed).
pub(crate) fn decompose(r: u32, gamma2: u32) -> (u32, i32) {
    let r1 = high_bits(r, gamma2);
    let mut r0 = r as i32 - (r1 as i32) * (gamma2 as i32) * 2;
    r0 -= ((Q_MINUS_1_DIV2 as i32 - r0) >> 31) & (Q as i32);
    (r1, r0)
}

/// MakeHint (Algorithm 39): 1 iff adding `z` changes the high bits of `r`.
pub(crate) fn make_hint(z: u32, r: u32, gamma2: u32) -> u32 {
    let r0 = add(r, z);
    u32::from(high_bits(r0, gamma2) != high_bits(r, gamma2))
}

/// UseHint (Algorithm 40): recovers the corrected high bits.
pub(crate) fn use_hint(hint: u32, r: u32, gamma2: u32) -> u32 {
    let (r1, r0) = decompose(r, gamma2);
    if hint == 0 {
        return r1;
    }
    if gamma2 == GAMMA2_32 {
        if r0 > 0 {
            (r1 + 1) & 15
        } else {
            r1.wrapping_sub(1) & 15
        }
    } else if r0 > 0 {
        if r1 == 43 { 0 } else { r1 + 1 }
    } else if r1 == 0 {
        43
    } else {
        r1 - 1
    }
}

/// Infinity norm of a single coefficient: `min(a, q − a)`.
pub(crate) fn inf_norm(a: u32) -> u32 {
    if a <= Q_MINUS_1_DIV2 { a } else { Q - a }
}
