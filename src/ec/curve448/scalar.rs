//! Arithmetic modulo the edwards448 group order
//! `L = 2⁴⁴⁶ − 13818066809895115352007386748515426880336692474882178609894547503885`.
//!
//! These are the low-level scalar helpers used by Ed448. The Ed448 nonce and
//! challenge are SHAKE256 outputs of 114 bytes (912 bits), so the wide
//! integers here are fifteen limbs (960 bits) to hold them without
//! truncation; [`reduce960`] is a constant-time Barrett reduction of those
//! modulo `L`.

use crate::bignum::Uint;
use crate::ct::{Choice, ConditionallySelectable};

use super::field::Fe;

/// `L` as nine 64-bit limbs (little-endian), the Barrett working width.
const L9: Uint<9> = Uint::from_limbs([
    0x2378_c292_ab58_44f3,
    0x216c_c272_8dc5_8f55,
    0xc44e_db49_aed6_3690,
    0xffff_ffff_7cca_23e9,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x3fff_ffff_ffff_ffff,
    0,
    0,
]);

/// The Barrett constant `μ = ⌊2⁹⁶⁰/L⌋` (515 bits), little-endian limbs.
/// Checked against a long division by the `barrett_mu_is_floor_2_960_div_l`
/// test.
const MU: Uint<9> = Uint::from_limbs([
    0xd00a_a4e7_e08e_dca4,
    0xc873_d6d5_4a7b_b0e0,
    0xe933_d8d7_23a7_0aad,
    0xbb12_4b65_129c_96fd,
    0x0000_0008_335d_c163,
    0,
    0,
    0,
    0x0000_0000_0000_0004,
]);

/// Subtracts `L` from `r` iff `r ≥ L`, without branching on `r`.
#[inline]
fn sub_l_if_ge(r: &Uint<9>) -> Uint<9> {
    let (d, borrow) = r.sbb(&L9, 0);
    Uint::conditional_select(&d, r, Choice::from((borrow ^ 1) as u8))
}

/// Reduces any 960-bit integer modulo `L` (Barrett).
///
/// With `x = 2³⁸⁴·x₁ + x₀`, the quotient estimate `q = ⌊x₁·μ / 2⁵⁷⁶⌋`
/// undershoots `⌊x/L⌋` by `x₀/L + x₁·(2⁹⁶⁰/L − μ)/2⁵⁷⁶ + 1 < 3`, i.e. by at
/// most 2, so `x − q·L < 3L` and two conditional subtractions canonicalise
/// it. Every input this module produces is below 2⁹¹², where the bound
/// tightens to one, but the second subtraction keeps the function total over
/// `Uint<15>`.
///
/// Constant time: a fixed sequence of limb multiplies and adds, then exactly
/// two masked conditional subtractions, with no data-dependent branch.
fn reduce960(x: &Uint<15>) -> Fe {
    let x = x.as_limbs();
    // x₁ = x >> 384, nine limbs.
    let q1 = Uint::<9>::from_limbs([x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14]]);
    // q = ⌊x₁·μ / 2⁵⁷⁶⌋: the high half of the eighteen-limb product.
    let (_, q) = q1.mul_wide(&MU);
    // r = (x − q·L) mod 2⁵⁷⁶; the true value is in [0, 3L).
    let r1 = Uint::<9>::from_limbs([x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8]]);
    let (r2, _) = q.mul_wide(&L9);
    let r = r1.wrapping_sub(&r2);
    let r = sub_l_if_ge(&sub_l_if_ge(&r));
    let r = r.as_limbs();
    // r < L < 2⁴⁴⁶, so the top two limbs are zero.
    Uint::from_limbs([r[0], r[1], r[2], r[3], r[4], r[5], r[6]])
}

/// Zero-extends a seven-limb integer to fifteen limbs.
fn widen(a: &Fe) -> Uint<15> {
    let l = a.as_limbs();
    Uint::from_limbs([
        l[0], l[1], l[2], l[3], l[4], l[5], l[6], 0, 0, 0, 0, 0, 0, 0, 0,
    ])
}

/// Reduces a 114-byte little-endian integer modulo `L`.
pub(crate) fn scalar_reduce_wide(bytes: &[u8; 114]) -> Fe {
    // 114 bytes fit in fifteen 64-bit limbs (120 bytes); the top six bytes are
    // zero-padded by `from_le_bytes`.
    reduce960(&Uint::<15>::from_le_bytes(bytes))
}

/// Computes `(r + k·a) mod L` for `r, k, a < L`.
pub(crate) fn scalar_muladd(r: &Fe, k: &Fe, a: &Fe) -> Fe {
    // k·a is the full 14-limb product; widen both operands to 15 limbs so the
    // sum with r cannot carry out of the representation.
    let (lo, hi) = k.mul_wide(a); // each seven limbs
    let lo = lo.as_limbs();
    let hi = hi.as_limbs();
    let prod = Uint::<15>::from_limbs([
        lo[0], lo[1], lo[2], lo[3], lo[4], lo[5], lo[6], hi[0], hi[1], hi[2], hi[3], hi[4], hi[5],
        hi[6], 0,
    ]);
    let (sum, _) = prod.adc(&widen(r), 0);
    reduce960(&sum)
}

/// Prunes the lower 57 bytes of the seed hash into the secret scalar
/// (RFC 8032 §5.2.5): clear the bottom two bits, set bit 447, clear the top
/// byte. The result `s` is read little-endian from `b[0..57]`.
pub(crate) fn prune(b: &mut [u8; 57]) {
    b[0] &= 0xFC;
    b[55] |= 0x80;
    b[56] = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bit-serial constant-time long division the Barrett path replaced,
    /// kept as the oracle.
    fn reduce960_ref(x: &Uint<15>) -> Fe {
        let l = L9.as_limbs();
        let l15 = Uint::<15>::from_limbs([
            l[0], l[1], l[2], l[3], l[4], l[5], l[6], 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let r = x.reduce(&l15);
        let r = r.as_limbs();
        Uint::from_limbs([r[0], r[1], r[2], r[3], r[4], r[5], r[6]])
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

    #[test]
    fn barrett_mu_is_floor_2_960_div_l() {
        // μ·L ≤ 2⁹⁶⁰ < (μ + 1)·L, checked in 1152-bit arithmetic as
        // 2⁹⁶⁰ − μ·L ∈ [0, L).
        let (lo, hi) = MU.mul_wide(&L9);
        let mut ml = [0u64; 18];
        ml[..9].copy_from_slice(lo.as_limbs());
        ml[9..].copy_from_slice(hi.as_limbs());
        let mut two960 = [0u64; 18];
        two960[15] = 1;
        let (diff, borrow) = Uint::<18>::from_limbs(two960).sbb(&Uint::from_limbs(ml), 0);
        assert_eq!(borrow, 0, "μ·L exceeds 2⁹⁶⁰");
        let d = diff.as_limbs();
        assert!(d[9..].iter().all(|&w| w == 0));
        let d9 = Uint::<9>::from_limbs([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8]]);
        assert_eq!(d9.sbb(&L9, 0).1, 1, "2⁹⁶⁰ − μ·L ≥ L");
    }

    #[test]
    fn reduce960_matches_long_division() {
        let l = L9.as_limbs();
        let lm1 = Fe::from_limbs([l[0] - 1, l[1], l[2], l[3], l[4], l[5], l[6]]);
        let wide = |a: &Fe, b: &Fe| {
            let (lo, hi) = a.mul_wide(b);
            let (lo, hi) = (lo.as_limbs(), hi.as_limbs());
            Uint::<15>::from_limbs([
                lo[0], lo[1], lo[2], lo[3], lo[4], lo[5], lo[6], hi[0], hi[1], hi[2], hi[3], hi[4],
                hi[5], hi[6], 0,
            ])
        };
        let mut top912 = [u64::MAX; 15];
        top912[14] = 0xffff; // 2⁹¹² − 1, the largest SHAKE256 output
        let edges: [Uint<15>; 9] = [
            Uint::ZERO,
            Uint::ONE,
            Uint::from_limbs([u64::MAX; 15]),
            Uint::from_limbs(top912),
            widen(&Fe::from_limbs([l[0], l[1], l[2], l[3], l[4], l[5], l[6]])),
            widen(&lm1),
            widen(&Fe::from_limbs([
                l[0] + 1,
                l[1],
                l[2],
                l[3],
                l[4],
                l[5],
                l[6],
            ])),
            // (L−1)², the largest muladd product, and (2⁴⁴⁸−1)·(L−1).
            wide(&lm1, &lm1),
            wide(&Fe::from_limbs([u64::MAX; 7]), &lm1),
        ];
        for x in &edges {
            assert_eq!(reduce960(x), reduce960_ref(x), "edge {x:?}");
        }

        let mut st = 0x2545_f491_4f6c_dd1d;
        for _ in 0..5_000 {
            let mut w = [0u64; 15];
            for limb in &mut w {
                *limb = next(&mut st);
            }
            // Also hit sparse top limbs (912-bit hashes, products).
            let top = (next(&mut st) % 16) as usize;
            for limb in &mut w[top..] {
                *limb = 0;
            }
            let x = Uint::<15>::from_limbs(w);
            assert_eq!(reduce960(&x), reduce960_ref(&x), "input {x:?}");
        }
    }
}
