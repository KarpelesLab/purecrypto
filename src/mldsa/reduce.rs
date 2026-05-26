//! Rounding, decomposition, and hint helpers (FIPS 204 §7.4).

use super::field::{Q, Q_MINUS_1_DIV2, add, sub};

/// `γ₂ = (q − 1) / 32` (ML-DSA-65 / ML-DSA-87).
pub(crate) const GAMMA2_32: u32 = (Q - 1) / 32;
/// `γ₂ = (q − 1) / 88` (ML-DSA-44).
pub(crate) const GAMMA2_88: u32 = (Q - 1) / 88;

const D: u32 = super::field::D;

/// Power2Round (Algorithm 35): `r = r1·2ᵈ + r0` with centered `r0`. Both halves
/// are returned in field (`[0, q)`) form.
pub(crate) fn power2_round(r: u32) -> (u32, u32) {
    let mut r1 = r >> D;
    let mut r0 = r - (r1 << D);
    const HALF: u32 = 1 << (D - 1);
    if r0 > HALF {
        r0 = sub(r0, 1 << D);
        r1 += 1;
    }
    (r1, r0)
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
