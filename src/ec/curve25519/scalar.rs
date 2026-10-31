//! Arithmetic modulo the edwards25519 group order
//! `L = 2²⁵² + 27742317777372353535851937790883648493`.
//!
//! These are the low-level scalar helpers shared by Ed25519 and the public
//! `Scalar` newtype in [`crate::ec::edwards25519::hazmat`] /
//! [`crate::ec::ristretto255`]. Every product and hash output is reduced by
//! [`reduce512`], a constant-time Barrett reduction specialised to `L`.

use crate::bignum::Uint;
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
use crate::bignum::safegcd::SafegcdModulus;
use crate::ct::{Choice, ConditionallySelectable};
use crate::zeroize::Zeroize;

use super::field::ScalarInt;

/// `L` as five 64-bit limbs (little-endian), the Barrett working width.
const L5: Uint<5> = Uint::from_limbs([
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
    0,
]);

/// The Barrett constant `μ = ⌊2⁵¹²/L⌋` (260 bits), little-endian limbs.
/// Checked against a long division by the `barrett_mu_is_floor_2_512_div_l`
/// test.
const MU: Uint<5> = Uint::from_limbs([
    0xed9c_e5a3_0a2c_131b,
    0x2106_215d_0863_29a7,
    0xffff_ffff_ffff_ffeb,
    0xffff_ffff_ffff_ffff,
    0x0000_0000_0000_000f,
]);

/// Subtracts `L` from `r` iff `r ≥ L`, without branching on `r`.
#[inline]
fn sub_l_if_ge(r: &Uint<5>) -> Uint<5> {
    let (d, borrow) = r.sbb(&L5, 0);
    Uint::conditional_select(&d, r, Choice::from((borrow ^ 1) as u8))
}

/// Reduces any 512-bit integer modulo `L` (Barrett, HAC Algorithm 14.42 with
/// `b = 2⁶⁴`, `k = 4`).
///
/// Constant time: a fixed sequence of limb multiplies and adds, then exactly
/// two masked conditional subtractions. HAC 14.42 bounds the remainder
/// estimate by `r < 3L`, so two always suffice. There is no data-dependent
/// branch or early exit.
///
/// The input is often secret (a nonce hash, or `r + k·a` with a secret `a`),
/// so every intermediate — the quotient estimate, the partial remainders
/// and the dropped product halves — is wiped before returning.
fn reduce512(x: &Uint<8>) -> ScalarInt {
    let x = x.as_limbs();
    // q1 = ⌊x / b^(k−1)⌋ = x >> 192, five limbs.
    let mut q1 = Uint::<5>::from_limbs([x[3], x[4], x[5], x[6], x[7]]);
    // q3 = ⌊q1·μ / b^(k+1)⌋: the high half of the ten-limb product.
    let (mut q2, mut q3) = q1.mul_wide(&MU);
    // r = (x − q3·L) mod b^(k+1); the true value is in [0, 3L).
    let mut r1 = Uint::<5>::from_limbs([x[0], x[1], x[2], x[3], x[4]]);
    let (mut r2, mut r2_hi) = q3.mul_wide(&L5);
    let mut r3 = r1.wrapping_sub(&r2);
    let mut r4 = sub_l_if_ge(&r3);
    let mut r = sub_l_if_ge(&r4);
    let l = r.as_limbs();
    // r < L < 2²⁵³, so the top limb is zero.
    let out = Uint::from_limbs([l[0], l[1], l[2], l[3]]);
    q1.zeroize();
    q2.zeroize();
    q3.zeroize();
    r1.zeroize();
    r2.zeroize();
    r2_hi.zeroize();
    r3.zeroize();
    r4.zeroize();
    r.zeroize();
    out
}

/// Joins low/high 256-bit halves into a 512-bit integer.
fn join(lo: &ScalarInt, hi: &ScalarInt) -> Uint<8> {
    let a = lo.as_limbs();
    let b = hi.as_limbs();
    Uint::from_limbs([a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]])
}

/// Zero-extends a 256-bit integer to 512 bits.
fn widen(a: &ScalarInt) -> Uint<8> {
    let l = a.as_limbs();
    Uint::from_limbs([l[0], l[1], l[2], l[3], 0, 0, 0, 0])
}

/// Reduces a 64-byte little-endian integer modulo `L`.
pub(crate) fn scalar_reduce_wide(bytes: &[u8; 64]) -> ScalarInt {
    reduce512(&Uint::<8>::from_le_bytes(bytes))
}

/// Computes `(r + k·a) mod L`.
///
/// In Ed25519 signing `k` is the public challenge while `r` (the nonce) and
/// `a` (the secret scalar) are secret, so `k·a` and the 512-bit sum reveal
/// `a`: they are wiped before returning (as is everything inside
/// [`reduce512`]).
pub(crate) fn scalar_muladd(r: &ScalarInt, k: &ScalarInt, a: &ScalarInt) -> ScalarInt {
    // k, a < 2²⁵⁶ and r < 2²⁵⁶, so k·a + r < 2⁵¹²: the carry out is zero.
    let (mut lo, mut hi) = k.mul_wide(a);
    let mut prod = join(&lo, &hi);
    let mut wide_r = widen(r);
    let (mut sum, _) = prod.adc(&wide_r, 0);
    let out = reduce512(&sum);
    lo.zeroize();
    hi.zeroize();
    prod.zeroize();
    wide_r.zeroize();
    sum.zeroize();
    out
}

/// Computes `(a · b) mod L` for `a, b < L`.
// The order-`L` field arithmetic below (mul/add/sub/negate/invert) is exercised
// only by the optional `edwards25519::hazmat` group API (which also backs
// `ristretto255`); the RFC 8032 Ed25519 path uses `scalar_reduce_wide` /
// `scalar_muladd` instead. Gate to silence dead-code warnings on the default
// (Ed25519-only) build. `scalar_mul` additionally feeds `scalar_invert`, which
// shares the same gate, so the internal call vanishes together with the export.
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub(crate) fn scalar_mul(a: &ScalarInt, b: &ScalarInt) -> ScalarInt {
    let (lo, hi) = a.mul_wide(b);
    reduce512(&join(&lo, &hi))
}

/// Computes `(a + b) mod L` for `a, b < L`.
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub(crate) fn scalar_add(a: &ScalarInt, b: &ScalarInt, l: &ScalarInt) -> ScalarInt {
    // a, b < L < 2²⁵³, so the sum fits in 256 bits with no carry out; one
    // conditional subtraction of L canonicalises it.
    let (sum, _) = a.adc(b, 0);
    let (reduced, borrow) = sum.sbb(l, 0);
    ScalarInt::conditional_select(&reduced, &sum, Choice::from((borrow ^ 1) as u8))
}

/// Computes `(a − b) mod L` for `a, b < L`.
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub(crate) fn scalar_sub(a: &ScalarInt, b: &ScalarInt, l: &ScalarInt) -> ScalarInt {
    let (diff, borrow) = a.sbb(b, 0);
    let (wrapped, _) = diff.adc(l, 0);
    ScalarInt::conditional_select(&wrapped, &diff, Choice::from(borrow as u8))
}

/// Computes `(−a) mod L` for `a < L`.
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub(crate) fn scalar_negate(a: &ScalarInt, l: &ScalarInt) -> ScalarInt {
    scalar_sub(&ScalarInt::ZERO, a, l)
}

/// `L` prepared for constant-time safegcd inversion ([`scalar_invert`]).
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
const SAFEGCD_L: SafegcdModulus = SafegcdModulus::new(&super::field::L_INT);

/// Computes the modular inverse `a⁻¹ mod L`, constant time in the value of
/// `a`, by the Bernstein–Yang safegcd divstep machine ([`SafegcdModulus`]:
/// a fixed 590-divstep schedule with barriered masks). The input is first
/// canonicalised with one masked subtraction of `L`, so any `a < 2L`
/// (every canonical scalar, plus the non-canonical encodings in `[L, 2L)`
/// a caller might hand through) is accepted. `L` is prime, so this is
/// well-defined for every nonzero `a`; the inverse of `0` is `0`.
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub(crate) fn scalar_invert(a: &ScalarInt, l: &ScalarInt) -> ScalarInt {
    let (reduced, borrow) = a.sbb(l, 0);
    let a = ScalarInt::conditional_select(&reduced, a, Choice::from((borrow ^ 1) as u8));
    SAFEGCD_L.invert(&a)
}

/// The Fermat ladder `a^(L−2) mod L` the safegcd path replaced: a fixed
/// 256-step square-and-masked-multiply, kept as the test oracle.
#[cfg(all(test, any(feature = "hazmat-edwards25519", feature = "ristretto255")))]
pub(crate) fn scalar_invert_fermat(a: &ScalarInt, l: &ScalarInt) -> ScalarInt {
    // exponent = L − 2
    let exp = l.wrapping_sub(&ScalarInt::from_u64(2));
    let mut r = ScalarInt::ONE;
    let limbs = exp.as_limbs();
    let mut i = 256;
    while i > 0 {
        i -= 1;
        r = scalar_mul(&r, &r);
        let bit = ((limbs[i / 64] >> (i % 64)) & 1) as u8;
        let prod = scalar_mul(&r, a);
        r = ScalarInt::conditional_select(&prod, &r, Choice::from(bit));
    }
    r
}

/// Clamps the lower half of the seed hash into the secret scalar (RFC 8032).
pub(crate) fn clamp(b: &mut [u8; 32]) {
    b[0] &= 248;
    b[31] &= 127;
    b[31] |= 64;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bit-serial constant-time long division the Barrett path replaced,
    /// kept as the oracle.
    fn reduce512_ref(x: &Uint<8>) -> ScalarInt {
        let l = L5.as_limbs();
        let l8 = Uint::<8>::from_limbs([l[0], l[1], l[2], l[3], 0, 0, 0, 0]);
        let r = x.reduce(&l8);
        let r = r.as_limbs();
        Uint::from_limbs([r[0], r[1], r[2], r[3]])
    }

    /// splitmix64: a dependency-free deterministic stream for the
    /// differential test.
    fn next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// The safegcd inverse agrees with the Fermat ladder on edge scalars
    /// (0 ↦ 0, 1, 2, L − 1, L − 2, and the non-canonical L, L + 1, 2L − 1
    /// which the masked pre-subtraction folds into `[0, L)`) and on random
    /// scalars; and `a · a⁻¹ ≡ 1`.
    #[test]
    #[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
    fn scalar_invert_matches_fermat() {
        let l = super::super::field::L_INT;
        let ll = l.as_limbs();
        let (two_l, _) = l.adc(&l, 0);
        let edges = [
            ScalarInt::ZERO,
            ScalarInt::ONE,
            ScalarInt::from_u64(2),
            ScalarInt::from_limbs([ll[0] - 1, ll[1], ll[2], ll[3]]),
            ScalarInt::from_limbs([ll[0] - 2, ll[1], ll[2], ll[3]]),
            l,
            ScalarInt::from_limbs([ll[0] + 1, ll[1], ll[2], ll[3]]),
            two_l.wrapping_sub(&ScalarInt::ONE),
        ];
        let check = |a: &ScalarInt| {
            let (reduced, borrow) = a.sbb(&l, 0);
            let canon = if borrow == 1 { *a } else { reduced };
            let inv = scalar_invert(a, &l);
            assert_eq!(inv, scalar_invert_fermat(&canon, &l), "input {a:?}");
            if canon != ScalarInt::ZERO {
                assert_eq!(scalar_mul(&canon, &inv), ScalarInt::ONE, "a·a⁻¹ for {a:?}");
            } else {
                assert_eq!(inv, ScalarInt::ZERO);
            }
        };
        for a in &edges {
            check(a);
        }
        let mut st = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..200 {
            let mut w = [0u64; 4];
            for limb in &mut w {
                *limb = next(&mut st);
            }
            w[3] &= 0x0fff_ffff_ffff_ffff; // < 2^252 < L
            check(&ScalarInt::from_limbs(w));
        }
    }

    #[test]
    fn barrett_mu_is_floor_2_512_div_l() {
        // μ·L ≤ 2⁵¹² < (μ + 1)·L, checked in 640-bit arithmetic as
        // 2⁵¹² − μ·L ∈ [0, L).
        let (lo, hi) = MU.mul_wide(&L5);
        let mut ml = [0u64; 10];
        ml[..5].copy_from_slice(lo.as_limbs());
        ml[5..].copy_from_slice(hi.as_limbs());
        let mut two512 = [0u64; 10];
        two512[8] = 1;
        let (diff, borrow) = Uint::<10>::from_limbs(two512).sbb(&Uint::from_limbs(ml), 0);
        assert_eq!(borrow, 0, "μ·L exceeds 2⁵¹²");
        let d = diff.as_limbs();
        assert!(d[5..].iter().all(|&w| w == 0));
        let d5 = Uint::<5>::from_limbs([d[0], d[1], d[2], d[3], d[4]]);
        assert_eq!(d5.sbb(&L5, 0).1, 1, "2⁵¹² − μ·L ≥ L");
    }

    #[test]
    fn reduce512_matches_long_division() {
        let l = L5.as_limbs();
        // (L−1)², the largest scalar_mul input, and (2²⁵⁶−1)·(L−1).
        let lm1 = ScalarInt::from_limbs([l[0] - 1, l[1], l[2], l[3]]);
        let (lo, hi) = lm1.mul_wide(&lm1);
        let lm1_sq = join(&lo, &hi);
        let (lo, hi) = ScalarInt::from_limbs([u64::MAX; 4]).mul_wide(&lm1);
        let big_mul = join(&lo, &hi);
        let edges: [Uint<8>; 8] = [
            Uint::ZERO,
            Uint::ONE,
            Uint::from_limbs([u64::MAX; 8]),
            Uint::from_limbs([l[0], l[1], l[2], l[3], 0, 0, 0, 0]),
            Uint::from_limbs([l[0] - 1, l[1], l[2], l[3], 0, 0, 0, 0]),
            Uint::from_limbs([l[0] + 1, l[1], l[2], l[3], 0, 0, 0, 0]),
            lm1_sq,
            big_mul,
        ];
        for x in &edges {
            assert_eq!(reduce512(x), reduce512_ref(x), "edge {x:?}");
        }

        let mut st = 0x2545_f491_4f6c_dd1d;
        for _ in 0..20_000 {
            let mut w = [0u64; 8];
            for limb in &mut w {
                *limb = next(&mut st);
            }
            // Also hit sparse top limbs (short hash-like inputs, products).
            let top = (next(&mut st) % 9) as usize;
            for limb in &mut w[top..] {
                *limb = 0;
            }
            let x = Uint::<8>::from_limbs(w);
            assert_eq!(reduce512(&x), reduce512_ref(&x), "input {x:?}");
        }
    }
}
