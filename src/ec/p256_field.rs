//! Native base-field arithmetic for NIST P-256, specialised to the Solinas
//! prime `p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1`.
//!
//! This replaces the generic saturated-Montgomery [`MontModulus`] CIOS core on
//! the P-256 hot path, mirroring the structure of the secp256k1 native backend
//! (`src/ec/secp256k1/field_backend.rs`): field elements are plain
//! (non-Montgomery) residues in `[0, p)`, stored as four little-endian `u64`
//! limbs — the exact representation the SEC1 codec serialises, so boundary
//! conversions vanish. Multiplication is a schoolbook 256×256→512 product
//! followed by the FIPS 186 / Solinas fast reduction: the 512-bit product's
//! sixteen 32-bit words are folded through nine fixed signed word
//! combinations (`s₁ + 2s₂ + 2s₃ + s₄ + s₅ − s₆ − s₇ − s₈ − s₉`), an `8p`
//! offset keeps the running value non-negative, and the small (≤ 4-bit)
//! overflow past 2²⁵⁶ is folded back through `2²⁵⁶ ≡ 2²²⁴ − 2¹⁹² − 2⁹⁶ + 1`.
//!
//! Everything is constant time in the element values: all loop bounds are
//! fixed, folds run a fixed number of times, and the final canonicalisation
//! uses mask-based conditional subtractions. Inversion is a fixed
//! addition-chain Fermat exponentiation (255 squarings + 13 multiplies), so
//! it is constant time by construction.
//!
//! The generic-Montgomery path is retained under `#[cfg(test)]` as a
//! differential oracle: every operation is cross-checked against
//! [`MontModulus`] over edge values and large deterministic random batches.
//!
//! [`MontModulus`]: crate::bignum::MontModulus

use crate::bignum::Uint;

/// A 256-bit base-field element, four little-endian 64-bit limbs, in `[0, p)`.
pub(crate) type Fe = Uint<4>;

/// The prime `p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1` as little-endian 64-bit limbs.
pub(crate) const P_LIMBS: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// The folding constant `K = 2²⁵⁶ − p = 2²²⁴ − 2¹⁹² − 2⁹⁶ + 1`, so that
/// `2²⁵⁶ ≡ K (mod p)`: overflow past 256 bits is folded back by multiplying
/// it by `K` and adding it in (`K < 2²²⁵`, so a ≤ 4-bit overflow folds to
/// `< 2²²⁹`, leaving at most a single carry bit for the final reduction).
const K_LIMBS: [u64; 4] = [
    0x0000_0000_0000_0001,
    0xFFFF_FFFF_0000_0000,
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFE,
];

/// Returns an all-ones/all-zeros `u64` mask from a 0/1 bit.
#[inline]
fn mask_from_bit(bit: u64) -> u64 {
    0u64.wrapping_sub(bit & 1)
}

/// Computes `r - p` over four limbs plus an incoming high bit `hi` (so the
/// operand is `hi·2²⁵⁶ + r`, `hi ∈ {0, 1}`), returning the difference limbs
/// and a `0/0xFFFF…FF` mask that is all-ones iff `hi·2²⁵⁶ + r >= p` (i.e. the
/// subtraction did not underflow).
#[inline]
fn sub_p_mask(r: &[u64; 4], hi: u64) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut borrow: u128 = 0;
    let mut i = 0;
    while i < 4 {
        // r[i] - P_LIMBS[i] - borrow, in two's-complement over 128 bits.
        let tmp = (r[i] as u128).wrapping_sub(P_LIMBS[i] as u128 + borrow);
        out[i] = tmp as u64;
        borrow = (tmp >> 64) & 1;
        i += 1;
    }
    // The value is >= p iff there is a high bit, or no final borrow.
    let mask = mask_from_bit(hi | (borrow as u64 ^ 1));
    (out, mask)
}

/// Selects `a` when `mask == 0` and `b` when `mask == 0xFFFF…FF`, per limb.
#[inline]
fn select(a: &[u64; 4], b: &[u64; 4], mask: u64) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        out[i] = (a[i] & !mask) | (b[i] & mask);
        i += 1;
    }
    out
}

/// Reduces `(r, hi)` — a value `hi·2²⁵⁶ + r` with `hi <= 1` and `r < 2²⁵⁶`,
/// known to be `< 2p` — into canonical `[0, p)` form via one mask-based
/// conditional subtraction of `p` (a value `< 2p` needs at most one). The
/// subtraction runs unconditionally and selects via a mask, so there is no
/// secret-dependent branch.
#[inline]
fn reduce_once(r: [u64; 4], hi: u64) -> [u64; 4] {
    let (diff, mask) = sub_p_mask(&r, hi);
    select(&r, &diff, mask)
}

/// Adds `m·K` into the four limbs `r`, returning the new limbs and the 0/1
/// carry out of the top limb (`m <= 14`, so `m·K < 2²²⁹` and the carry out is
/// at most one).
#[inline]
fn add_mul_k(r: &[u64; 4], m: u64) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut carry: u128 = 0;
    let mut i = 0;
    while i < 4 {
        let acc = (r[i] as u128) + (m as u128) * (K_LIMBS[i] as u128) + carry;
        out[i] = acc as u64;
        carry = acc >> 64;
        i += 1;
    }
    (out, carry as u64)
}

/// Folds a 512-bit product (eight little-endian limbs) down to canonical
/// `[0, p)` via the FIPS 186 / Solinas fast reduction for P-256.
///
/// With `A₀..A₁₅` the sixteen little-endian 32-bit words of the product, the
/// reduction is `s₁ + 2s₂ + 2s₃ + s₄ + s₅ − s₆ − s₇ − s₈ − s₉ (mod p)` for the
/// nine fixed word recombinations of FIPS 186-4 §D.2.3. Each output word's
/// signed coefficient sum is accumulated in an `i128` together with the
/// matching word of a global `+8p` offset (the negative terms total
/// `> −4·2²⁵⁶ > −8p`, so the offset keeps the final value non-negative;
/// the positive terms total `< 7·2²⁵⁶`, so the offset value stays
/// `< 15·2²⁵⁶`). Carries between words use arithmetic shifts (fixed
/// schedule). The resulting ≤ 4-bit overflow `hi` past 2²⁵⁶ is folded back
/// through `2²⁵⁶ ≡ K`, and the final masked subtraction canonicalises.
#[inline]
fn reduce512(t: &[u64; 8]) -> [u64; 4] {
    // Split into sixteen 32-bit words held as i64 (every value < 2³², and
    // each per-word signed sum below stays within ±2³⁵, far inside i64).
    let a0 = (t[0] & 0xFFFF_FFFF) as i64;
    let a1 = (t[0] >> 32) as i64;
    let a2 = (t[1] & 0xFFFF_FFFF) as i64;
    let a3 = (t[1] >> 32) as i64;
    let a4 = (t[2] & 0xFFFF_FFFF) as i64;
    let a5 = (t[2] >> 32) as i64;
    let a6 = (t[3] & 0xFFFF_FFFF) as i64;
    let a7 = (t[3] >> 32) as i64;
    let a8 = (t[4] & 0xFFFF_FFFF) as i64;
    let a9 = (t[4] >> 32) as i64;
    let a10 = (t[5] & 0xFFFF_FFFF) as i64;
    let a11 = (t[5] >> 32) as i64;
    let a12 = (t[6] & 0xFFFF_FFFF) as i64;
    let a13 = (t[6] >> 32) as i64;
    let a14 = (t[7] & 0xFFFF_FFFF) as i64;
    let a15 = (t[7] >> 32) as i64;

    // Per-word signed coefficient sums of s₁ + 2s₂ + 2s₃ + s₄ + s₅ − s₆ − s₇
    // − s₈ − s₉ (FIPS 186-4 §D.2.3), little-endian word order.
    let w0 = a0 + a8 + a9 - a11 - a12 - a13 - a14;
    let w1 = a1 + a9 + a10 - a12 - a13 - a14 - a15;
    let w2 = a2 + a10 + a11 - a13 - a14 - a15;
    let w3 = a3 + 2 * (a11 + a12) + a13 - a15 - a8 - a9;
    let w4 = a4 + 2 * (a12 + a13) + a14 - a9 - a10;
    let w5 = a5 + 2 * (a13 + a14) + a15 - a10 - a11;
    let w6 = a6 + a13 + 3 * a14 + 2 * a15 - a8 - a9;
    let w7 = a7 + a8 + 3 * a15 - a10 - a11 - a12 - a13;

    // Add the +8p offset and propagate carries at 64-bit limb granularity
    // (each limb pairs two words: w_{2k} + w_{2k+1}·2³², |w_j| < 2³⁵, so the
    // i128 accumulator stays within ±2⁶⁹ plus carries). Arithmetic shifts
    // give signed carries; the fixed 4-step schedule is data-independent.
    // 8p = 7·2²⁵⁶ + [0xFFFF_FFFF_FFFF_FFF8, 0x0000_0007_FFFF_FFFF, 0,
    //                0xFFFF_FFF8_0000_0008].
    const P8: [u64; 4] = [
        0xFFFF_FFFF_FFFF_FFF8,
        0x0000_0007_FFFF_FFFF,
        0,
        0xFFFF_FFF8_0000_0008,
    ];
    const P8_TOP: u64 = 7;

    let mut r = [0u64; 4];
    let acc = (w0 as i128) + ((w1 as i128) << 32) + (P8[0] as i128);
    r[0] = acc as u64;
    let acc = (w2 as i128) + ((w3 as i128) << 32) + (P8[1] as i128) + (acc >> 64);
    r[1] = acc as u64;
    let acc = (w4 as i128) + ((w5 as i128) << 32) + (P8[2] as i128) + (acc >> 64);
    r[2] = acc as u64;
    let acc = (w6 as i128) + ((w7 as i128) << 32) + (P8[3] as i128) + (acc >> 64);
    r[3] = acc as u64;
    // The offset value is in [0, 15·2²⁵⁶), so the top carry is in [0, 14].
    let hi = ((acc >> 64) as u64).wrapping_add(P8_TOP);

    // Fold the overflow through 2²⁵⁶ ≡ K once: the result `c1·2²⁵⁶ + r` has
    // `c1 <= 1` and is < 2²⁵⁶ + 14·K < 2p, which is exactly reduce_once's
    // precondition — its masked `−p` absorbs the carry bit and canonicalises
    // (when c1 = 1 the low part is < 2²²⁹, so the subtraction lands in
    // [0, K + 2²²⁹) ⊂ [0, p); when c1 = 0 the value is < 2²⁵⁶ < 2p).
    let (r, c1) = add_mul_k(&r, hi);
    reduce_once(r, c1)
}

/// Schoolbook 256×256→512 multiply of two little-endian 4-limb operands.
#[inline]
fn mul_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut t = [0u64; 8];
    let mut i = 0;
    while i < 4 {
        let mut carry: u128 = 0;
        let mut j = 0;
        while j < 4 {
            let acc = (t[i + j] as u128) + (a[i] as u128) * (b[j] as u128) + carry;
            t[i + j] = acc as u64;
            carry = acc >> 64;
            j += 1;
        }
        t[i + 4] = carry as u64;
        i += 1;
    }
    t
}

/// Dedicated 256-bit squaring: the six cross products are computed once and
/// doubled (the cross sum is `< 2⁵¹¹`, so the shift cannot overflow), then the
/// four diagonal squares are added in. Saves six of the sixteen schoolbook
/// word multiplies versus `mul_wide(a, a)`.
#[inline]
fn sqr_wide(a: &[u64; 4]) -> [u64; 8] {
    let mut t = [0u64; 8];

    // Cross products a[i]·a[j] for i < j, accumulated at position i + j.
    let mut carry: u128 = 0;
    let mut j = 1;
    while j < 4 {
        let acc = (t[j] as u128) + (a[0] as u128) * (a[j] as u128) + carry;
        t[j] = acc as u64;
        carry = acc >> 64;
        j += 1;
    }
    t[4] = carry as u64;
    carry = 0;
    let mut j = 2;
    while j < 4 {
        let acc = (t[1 + j] as u128) + (a[1] as u128) * (a[j] as u128) + carry;
        t[1 + j] = acc as u64;
        carry = acc >> 64;
        j += 1;
    }
    t[5] = carry as u64;
    let acc = (t[5] as u128) + (a[2] as u128) * (a[3] as u128);
    t[5] = acc as u64;
    t[6] = (acc >> 64) as u64;

    // Double the cross-product sum (top bit provably clear).
    let mut top = 0u64;
    let mut i = 0;
    while i < 8 {
        let v = t[i];
        t[i] = (v << 1) | top;
        top = v >> 63;
        i += 1;
    }

    // Add the diagonal squares a[i]² at position 2i.
    let mut carry: u128 = 0;
    let mut i = 0;
    while i < 4 {
        let sq = (a[i] as u128) * (a[i] as u128);
        let acc = (t[2 * i] as u128) + (sq & 0xFFFF_FFFF_FFFF_FFFF) + carry;
        t[2 * i] = acc as u64;
        carry = acc >> 64;
        let acc = (t[2 * i + 1] as u128) + (sq >> 64) + carry;
        t[2 * i + 1] = acc as u64;
        carry = acc >> 64;
        i += 1;
    }
    t
}

/// Returns `(a + b) mod p`. Operands must be in `[0, p)`.
#[inline]
pub(crate) fn add(a: &Fe, b: &Fe) -> Fe {
    let a = a.as_limbs();
    let b = b.as_limbs();
    let mut r = [0u64; 4];
    let mut carry: u128 = 0;
    let mut i = 0;
    while i < 4 {
        let acc = (a[i] as u128) + (b[i] as u128) + carry;
        r[i] = acc as u64;
        carry = acc >> 64;
        i += 1;
    }
    // Sum < 2p < 2·2²⁵⁶; reduce_once's two masked −p restore [0, p).
    Fe::from_limbs(reduce_once(r, carry as u64))
}

/// Returns `(a - b) mod p`. Operands must be in `[0, p)`.
#[inline]
pub(crate) fn sub(a: &Fe, b: &Fe) -> Fe {
    let a = a.as_limbs();
    let b = b.as_limbs();
    let mut r = [0u64; 4];
    let mut borrow: u128 = 0;
    let mut i = 0;
    while i < 4 {
        let tmp = (a[i] as u128).wrapping_sub(b[i] as u128 + borrow);
        r[i] = tmp as u64;
        borrow = (tmp >> 64) & 1;
        i += 1;
    }
    // On underflow, add p back (constant-time, mask-driven).
    let mask = mask_from_bit(borrow as u64);
    let mut out = [0u64; 4];
    let mut carry: u128 = 0;
    let mut j = 0;
    while j < 4 {
        let acc = (r[j] as u128) + ((P_LIMBS[j] & mask) as u128) + carry;
        out[j] = acc as u64;
        carry = acc >> 64;
        j += 1;
    }
    Fe::from_limbs(out)
}

/// Returns `(-a) mod p`. The operand must be in `[0, p)`.
#[inline]
pub(crate) fn negate(a: &Fe) -> Fe {
    let a = a.as_limbs();
    // p - a, then select 0 when a == 0 (since p - 0 == p is non-canonical).
    let mut r = [0u64; 4];
    let mut borrow: u128 = 0;
    let mut i = 0;
    while i < 4 {
        let tmp = (P_LIMBS[i] as u128).wrapping_sub(a[i] as u128 + borrow);
        r[i] = tmp as u64;
        borrow = (tmp >> 64) & 1;
        i += 1;
    }
    // Branch-free zero test: OR the limbs, fold to a 0/1 bit, build a mask.
    let or = a[0] | a[1] | a[2] | a[3];
    let nonzero_bit = (or | or.wrapping_neg()) >> 63;
    let zero_mask = mask_from_bit(nonzero_bit ^ 1);
    Fe::from_limbs(select(&r, &[0u64; 4], zero_mask))
}

/// Returns `(a * b) mod p`. Operands must be in `[0, p)`.
#[inline]
pub(crate) fn mul(a: &Fe, b: &Fe) -> Fe {
    Fe::from_limbs(reduce512(&mul_wide(a.as_limbs(), b.as_limbs())))
}

/// Returns `a² mod p`. The operand must be in `[0, p)`.
#[inline]
pub(crate) fn square(a: &Fe) -> Fe {
    Fe::from_limbs(reduce512(&sqr_wide(a.as_limbs())))
}

/// Squares `a` a fixed `n` times.
#[inline]
fn sqn(a: &Fe, n: u32) -> Fe {
    let mut acc = *a;
    let mut i = 0;
    while i < n {
        acc = square(&acc);
        i += 1;
    }
    acc
}

/// Returns the modular inverse `a⁻¹ = a^(p−2) mod p` via a fixed Fermat
/// addition chain (255 squarings + 13 multiplies). The inverse of `0` is `0`.
///
/// Constant time by construction: the chain is a fixed sequence of squarings
/// and multiplies derived from the public exponent
/// `p − 2 = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 3`, whose binary expansion (MSB→LSB)
/// is `[1×32][0×31][1][0×96][1×94][0][1]`. With `xₖ = a^(2ᵏ−1)` built by
/// doubling (`x₁, x₂, x₄, x₈, x₁₆, x₃₂`), the exponent is assembled as
///
/// ```text
/// acc = x32                      // 1×32
/// acc = acc·2³² · x1             // ‖ 0×31 ‖ 1
/// acc = acc·2¹²⁸ · x32           // ‖ 0×96 ‖ 1×32
/// acc = acc·2³² · x32            // ‖ 1×32   (1×64 total)
/// acc = acc·2¹⁶ · x16            // ‖ 1×16   (1×80)
/// acc = acc·2⁸  · x8             // ‖ 1×8    (1×88)
/// acc = acc·2⁴  · x4             // ‖ 1×4    (1×92)
/// acc = acc·2²  · x2             // ‖ 1×2    (1×94)
/// acc = acc·2²  · x1             // ‖ 0 ‖ 1
/// ```
pub(crate) fn invert(a: &Fe) -> Fe {
    let x1 = *a;
    let x2 = mul(&square(&x1), &x1);
    let x4 = mul(&sqn(&x2, 2), &x2);
    let x8 = mul(&sqn(&x4, 4), &x4);
    let x16 = mul(&sqn(&x8, 8), &x8);
    let x32 = mul(&sqn(&x16, 16), &x16);

    let mut acc = sqn(&x32, 32);
    acc = mul(&acc, &x1);
    acc = mul(&sqn(&acc, 128), &x32);
    acc = mul(&sqn(&acc, 32), &x32);
    acc = mul(&sqn(&acc, 16), &x16);
    acc = mul(&sqn(&acc, 8), &x8);
    acc = mul(&sqn(&acc, 4), &x4);
    acc = mul(&sqn(&acc, 2), &x2);
    mul(&sqn(&acc, 2), &x1)
}

#[cfg(test)]
mod tests {
    //! Differential tests: the native Solinas backend must agree
    //! byte-for-byte with the generic Montgomery oracle ([`MontModulus`], the
    //! numeric core the P-256 layer previously ran on) on every field
    //! operation, across edge cases and large deterministic random batches.

    use super::*;
    use crate::bignum::MontModulus;

    /// The prime `p` as a [`Fe`].
    fn p() -> Fe {
        Fe::from_limbs(P_LIMBS)
    }

    /// Generic-Montgomery differential oracle over the same prime.
    struct Oracle {
        fp: MontModulus<4>,
    }

    impl Oracle {
        fn new() -> Self {
            Oracle {
                fp: MontModulus::new(p()),
            }
        }
        fn add(&self, a: &Fe, b: &Fe) -> Fe {
            self.fp.add_mod(a, b)
        }
        fn sub(&self, a: &Fe, b: &Fe) -> Fe {
            self.fp.sub_mod(a, b)
        }
        fn mul(&self, a: &Fe, b: &Fe) -> Fe {
            self.fp.mul_mod(a, b)
        }
        fn negate(&self, a: &Fe) -> Fe {
            self.fp.sub_mod(&Fe::ZERO, a)
        }
        fn invert(&self, a: &Fe) -> Fe {
            let p_minus_2 = p().wrapping_sub(&Fe::from_u64(2));
            self.fp.pow(a, &p_minus_2)
        }
    }

    /// Deterministic SplitMix64 PRNG seeded from a literal — reproducible, no
    /// system randomness, so a failure always reprints the same offending case.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    /// A pseudo-random 256-bit value reduced into `[0, p)`.
    fn rand_fe(rng: &mut SplitMix64) -> Fe {
        let limbs = [
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
        ];
        Fe::from_limbs(limbs).reduce(&p())
    }

    /// Field elements at and around the dangerous boundaries, all in `[0, p)`.
    /// P-256's Solinas reduction is driven by 32-bit word patterns, so the
    /// power-of-two words (2⁹⁶, 2¹⁹², 2²²⁴) and saturated-word values stress
    /// the signed per-word sums hardest.
    fn edge_cases() -> [Fe; 14] {
        let prime = p();
        let p_minus_1 = prime.wrapping_sub(&Fe::ONE);
        let p_minus_2 = prime.wrapping_sub(&Fe::from_u64(2));
        // 2²⁵⁶ − 1 reduced mod p (== K − 1, the largest near-2²⁵⁶ pattern).
        let all_ones = Fe::from_limbs([u64::MAX; 4]).reduce(&prime);
        [
            Fe::ZERO,
            Fe::ONE,
            Fe::from_u64(2),
            Fe::from_u64(7),
            p_minus_1,
            p_minus_2,
            all_ones,
            // 2⁹⁶, 2¹⁹², 2²²⁴ — the prime's own power-of-two terms.
            Fe::from_limbs([0, 1 << 32, 0, 0]),
            Fe::from_limbs([0, 0, 0, 1]),
            Fe::from_limbs([0, 0, 0, 1 << 32]),
            // K = 2²⁵⁶ mod p and K − 1.
            Fe::from_limbs(K_LIMBS),
            Fe::from_limbs([0, K_LIMBS[1], K_LIMBS[2], K_LIMBS[3]]),
            // Alternating saturated 32-bit words.
            Fe::from_limbs([0xFFFF_FFFF, 0xFFFF_FFFF_0000_0000, 0xFFFF_FFFF, 0]),
            // High half saturated, low half zero.
            Fe::from_limbs([0, 0, u64::MAX, 0xFFFF_FFFF]),
        ]
    }

    fn bytes(a: &Fe) -> [u8; 32] {
        let mut out = [0u8; 32];
        a.write_be_bytes(&mut out);
        out
    }

    fn check_pair(g: &Oracle, a: &Fe, b: &Fe) {
        assert_eq!(
            bytes(&g.add(a, b)),
            bytes(&add(a, b)),
            "add mismatch: a={:x?} b={:x?}",
            a.as_limbs(),
            b.as_limbs()
        );
        assert_eq!(
            bytes(&g.sub(a, b)),
            bytes(&sub(a, b)),
            "sub mismatch: a={:x?} b={:x?}",
            a.as_limbs(),
            b.as_limbs()
        );
        assert_eq!(
            bytes(&g.mul(a, b)),
            bytes(&mul(a, b)),
            "mul mismatch: a={:x?} b={:x?}",
            a.as_limbs(),
            b.as_limbs()
        );
    }

    fn check_unary(g: &Oracle, a: &Fe) {
        assert_eq!(
            bytes(&g.mul(a, a)),
            bytes(&square(a)),
            "square mismatch: a={:x?}",
            a.as_limbs()
        );
        assert_eq!(
            bytes(&g.negate(a)),
            bytes(&negate(a)),
            "negate mismatch: a={:x?}",
            a.as_limbs()
        );
        assert_eq!(
            bytes(&g.invert(a)),
            bytes(&invert(a)),
            "invert mismatch: a={:x?}",
            a.as_limbs()
        );
    }

    #[test]
    fn native_matches_generic_edge_cases() {
        let g = Oracle::new();
        let cases = edge_cases();
        for a in &cases {
            check_unary(&g, a);
            for b in &cases {
                check_pair(&g, a, b);
            }
        }
    }

    #[test]
    fn native_matches_generic_random_batch() {
        let g = Oracle::new();
        let mut rng = SplitMix64(0x0123_4567_89AB_CDEF);
        // 100k random operands; each iteration exercises every binary op
        // plus the dedicated squaring.
        for _ in 0..100_000 {
            let a = rand_fe(&mut rng);
            let b = rand_fe(&mut rng);
            check_pair(&g, &a, &b);
            assert_eq!(bytes(&g.mul(&a, &a)), bytes(&square(&a)));
        }
    }

    #[test]
    fn native_matches_generic_random_unary() {
        let g = Oracle::new();
        let mut rng = SplitMix64(0xDEAD_BEEF_CAFE_F00D);
        // Inversion is the expensive one; a smaller but still large batch.
        for _ in 0..2_000 {
            let a = rand_fe(&mut rng);
            check_unary(&g, &a);
        }
    }

    #[test]
    fn invert_roundtrips_and_handles_zero() {
        let mut rng = SplitMix64(0xA5A5_5A5A_F0F0_0F0F);
        for _ in 0..1_000 {
            let a = rand_fe(&mut rng);
            if bool::from(a.is_zero()) {
                continue;
            }
            assert_eq!(bytes(&mul(&a, &invert(&a))), bytes(&Fe::ONE));
        }
        assert_eq!(bytes(&invert(&Fe::ZERO)), bytes(&Fe::ZERO));
    }

    #[test]
    #[ignore = "manual microbenchmark"]
    #[cfg(feature = "std")]
    fn microbench_field_ops() {
        use std::println;
        use std::time::Instant;
        let g = Oracle::new();
        let mut rng = SplitMix64(42);
        let mut a = rand_fe(&mut rng);
        let b = rand_fe(&mut rng);
        let am = g.fp.to_mont(&a);
        let bm = g.fp.to_mont(&b);
        const N: u32 = 2_000_000;

        let t = Instant::now();
        let mut x = a;
        for _ in 0..N {
            x = mul(&x, &b);
        }
        core::hint::black_box(&x);
        println!("native mul:   {:?}/op", t.elapsed() / N);

        let t = Instant::now();
        let mut x = am;
        for _ in 0..N {
            x = g.fp.mont_mul(&x, &bm);
        }
        core::hint::black_box(&x);
        println!("mont_mul:     {:?}/op", t.elapsed() / N);

        let t = Instant::now();
        let mut x = a;
        for _ in 0..N {
            x = square(&x);
        }
        core::hint::black_box(&x);
        println!("native sqr:   {:?}/op", t.elapsed() / N);

        let t = Instant::now();
        let mut x = am;
        for _ in 0..N {
            x = g.fp.mont_sqr(&x);
        }
        core::hint::black_box(&x);
        println!("mont_sqr:     {:?}/op", t.elapsed() / N);

        let t = Instant::now();
        let mut x = a;
        for _ in 0..N {
            x = add(&x, &b);
        }
        core::hint::black_box(&x);
        println!("native add:   {:?}/op", t.elapsed() / N);

        let t = Instant::now();
        let mut x = a;
        for _ in 0..N {
            x = g.fp.add_mod(&x, &b);
        }
        core::hint::black_box(&x);
        println!("generic add:  {:?}/op", t.elapsed() / N);

        let t = Instant::now();
        let mut w = mul_wide(a.as_limbs(), b.as_limbs());
        for _ in 0..N {
            w = mul_wide(&[w[0], w[1], w[2], w[3]], &[w[4], w[5], w[6], w[7]]);
        }
        core::hint::black_box(&w);
        println!("mul_wide:     {:?}/op", t.elapsed() / N);

        let t = Instant::now();
        let mut r = *a.as_limbs();
        for _ in 0..N {
            r = reduce512(&[r[0], r[1], r[2], r[3], r[0], r[1], r[2], r[3]]);
        }
        core::hint::black_box(&r);
        println!("reduce512:    {:?}/op", t.elapsed() / N);

        let t = Instant::now();
        for _ in 0..2000 {
            a = invert(&a);
        }
        core::hint::black_box(&a);
        println!("native inv:   {:?}/op", t.elapsed() / 2000);

        let t = Instant::now();
        for _ in 0..2000 {
            a = g.invert(&a);
        }
        core::hint::black_box(&a);
        println!("generic inv:  {:?}/op", t.elapsed() / 2000);
    }

    /// Random-word (not pre-reduced) products stress the Solinas word sums:
    /// feed the reducer edge-shaped *operands* whose wide products exercise
    /// extreme positive and negative per-word coefficient sums.
    #[test]
    fn solinas_extreme_word_patterns() {
        let g = Oracle::new();
        let prime = p();
        let patterns = [
            Fe::from_limbs([u64::MAX, 0, u64::MAX, 0]).reduce(&prime),
            Fe::from_limbs([0, u64::MAX, 0, u64::MAX]).reduce(&prime),
            Fe::from_limbs([
                0xFFFF_FFFF_0000_0000,
                0xFFFF_FFFF,
                0xFFFF_FFFF_0000_0000,
                0xFFFF_FFFF,
            ])
            .reduce(&prime),
            prime.wrapping_sub(&Fe::ONE),
            Fe::from_limbs([u64::MAX; 4]).reduce(&prime),
        ];
        for a in &patterns {
            for b in &patterns {
                check_pair(&g, a, b);
            }
            check_unary(&g, a);
        }
    }
}
