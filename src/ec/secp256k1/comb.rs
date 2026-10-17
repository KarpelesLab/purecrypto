//! Constant-time fixed-base multiplication over a precomputed comb table.
//!
//! A comb table of a base point `B` stores the affine points
//! `[j·16ⁱ]B` for `i in 0..64`, `j in 1..=15` (the layout of
//! [`super::gtable::SECP256K1_GEN_TABLE`]), so `[k]B = Σᵢ [dᵢ·16ⁱ]B` over the
//! base-16 digits `dᵢ` of `k` costs 64 additions and **no doublings**. The
//! digits are read in the signed odd form of [`super::group`] (so only the
//! odd entries of each window are gathered, eight per window, and no digit
//! is zero), each operand fetched by a masked scan under one opaque mask per
//! entry and added with the complete mixed formula. The schedule depends on
//! the (public) number of windows alone.

use super::field_backend::{Fe, FieldBackend};
use super::glv;
use super::group::{Point, eq_mask, negate_masked, signed_window};
use crate::zeroize::Zeroize;

/// Windows of a full-width comb: 64 base-16 digits.
pub(crate) const COMB_WINDOWS: usize = 64;

/// An affine table entry: `[x₀, x₁, x₂, x₃, y₀, y₁, y₂, y₃]`, little-endian
/// 64-bit limbs of the coordinates as plain residues in `[0, p)`.
pub(crate) type AffineEntry = [u64; 8];

/// A fixed-base comb table: `table[i][j − 1] = [j·16ⁱ]B` for `i in 0..64`,
/// `j in 1..=15`.
pub(crate) type CombTable = [[AffineEntry; 15]; COMB_WINDOWS];

/// Splits an affine entry into its coordinates.
#[inline]
pub(crate) fn affine_entry(e: &AffineEntry) -> (Fe, Fe) {
    (
        Fe::from_limbs([e[0], e[1], e[2], e[3]]),
        Fe::from_limbs([e[4], e[5], e[6], e[7]]),
    )
}

/// Constant-time gather of the odd entry `window[2·index]` (`[2·index + 1]B`
/// of a comb window storing `[1]B … [15]B`): scans the eight odd entries
/// under one opaque mask each, OR-accumulating the masked limbs. No
/// secret-indexed memory access.
fn gather_odd_affine(window: &[AffineEntry; 15], index: u64) -> (Fe, Fe) {
    let mut out = [0u64; 8];
    for (j, e) in window.iter().step_by(2).enumerate() {
        let m = eq_mask(j as u64, index);
        for i in 0..8 {
            out[i] |= e[i] & m;
        }
    }
    affine_entry(&out)
}

impl Point {
    /// `D(v)·B` over a comb table of `B` (only the odd entries are read),
    /// where `D(v) = 2v + 1 − 2^(4·windows)` as in `signed_window`: one
    /// window per base-16 digit of `v`, each an eight-entry masked gather of
    /// an affine entry, a masked negation and one unconditional complete
    /// mixed addition. The digit is never zero, so there is no identity
    /// operand to special-case. `windows <= 64` is public.
    fn comb_signed<F: FieldBackend>(
        f: &F,
        v: &[u64; 4],
        table: &CombTable,
        windows: usize,
    ) -> Point {
        let mut acc = Point::identity(f);
        for (w, window) in table.iter().enumerate().take(windows) {
            let (idx, neg) = signed_window(v, w);
            let (mut x, mut y) = gather_odd_affine(window, idx);
            y = negate_masked(f, &y, neg);
            acc = Point::add_mixed(f, &acc, &x, &y);
            x.zeroize();
            y.zeroize();
        }
        acc
    }

    /// Constant-time fixed-base multiplication `scalar · B` (`scalar < n`)
    /// over the comb table of `B`: the scalar is first mapped to
    /// `v = (k + 2²⁵⁶ − 1)·2⁻¹ mod n` so that `D(v) ≡ k`, then all 64
    /// windows run, each the same work.
    pub(crate) fn mul_comb<F: FieldBackend>(f: &F, scalar: &[u64; 4], table: &CombTable) -> Point {
        let mut v = glv::comb_prepare(&Fe::from_limbs(*scalar));
        let acc = Self::comb_signed(f, v.as_limbs(), table, COMB_WINDOWS);
        v.zeroize();
        acc
    }

    /// Constant-time fixed-base `scalar · B` for a scalar of public width
    /// `BITS` (as [`Point::mul_bits`]) over the comb table of `B`: only
    /// `BITS/4 + 1` of the 64 windows run, then a masked subtraction of `B`
    /// corrects even scalars.
    #[cfg(test)]
    pub(crate) fn mul_comb_bits<F: FieldBackend, const BITS: usize>(
        f: &F,
        scalar: &[u64; 4],
        table: &CombTable,
    ) -> Point {
        use super::field_backend::mask_from_bit;
        use super::group::half_with_top;
        const { assert!(BITS.is_multiple_of(4) && BITS > 0 && BITS <= 252) };
        let windows = BITS / 4 + 1;
        let (mut v, even) = half_with_top(scalar, 4 * windows - 1);
        let acc = Self::comb_signed(f, &v, table, windows);
        let (bx, by) = affine_entry(&table[0][0]);
        let corrected = Point::add_mixed(f, &acc, &bx, &f.negate(&by));
        let out = Point::select_mask(&acc, &corrected, mask_from_bit(even));
        v.zeroize();
        out
    }

    /// Constant-time fixed-base multiplication `scalar · G` via the
    /// precomputed comb table [`SECP256K1_GEN_TABLE`]: [`Self::mul_comb`]
    /// over the generator's table.
    ///
    /// [`SECP256K1_GEN_TABLE`]: super::gtable::SECP256K1_GEN_TABLE
    pub(crate) fn mul_generator_table<F: FieldBackend>(f: &F, scalar: &[u64; 4]) -> Point {
        Self::mul_comb(f, scalar, &super::gtable::SECP256K1_GEN_TABLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::secp256k1::ProjectivePoint;
    use crate::ec::secp256k1::field_backend::Secp256k1Field;
    use crate::ec::secp256k1::group::tests::{SplitMix64, edge_scalars};
    use crate::ec::secp256k1::gtable::SECP256K1_GEN_TABLE;

    /// The fixed-base combs agree with the reference ladder over `G`.
    #[test]
    fn comb_matches_reference() {
        let f = Secp256k1Field::new();
        let g = ProjectivePoint::generator().0;
        let mut rng = SplitMix64(0x6C5F_0005);
        let check = |k: &Fe| {
            let want = Point::mul_reference(&f, k.as_limbs(), &g);
            let got = Point::mul_comb(&f, k.as_limbs(), &SECP256K1_GEN_TABLE);
            assert!(bool::from(got.ct_eq(&f, &want)), "k={:x?}", k.as_limbs());
        };
        for k in &edge_scalars() {
            check(k);
        }
        for _ in 0..200 {
            check(&rng.scalar());
        }
        let edges = [0u64, 1, 2, 3, 15, 16, 17, 1 << 63, u64::MAX - 1, u64::MAX];
        let check64 = |k: u64| {
            let k = Fe::from_u64(k);
            let want = Point::mul_reference(&f, k.as_limbs(), &g);
            let got = Point::mul_comb_bits::<_, 64>(&f, k.as_limbs(), &SECP256K1_GEN_TABLE);
            assert!(bool::from(got.ct_eq(&f, &want)), "k={:x?}", k.as_limbs());
        };
        for &k in &edges {
            check64(k);
        }
        for _ in 0..200 {
            check64(rng.next_u64());
        }
    }
}
