//! Constant-time multiplication for [`Uint`].
//!
//! The widening product of two `LIMBS`-limb integers needs `2 * LIMBS` limbs,
//! which cannot be named in a return type on stable Rust. It is therefore
//! returned as `(low, high)` halves.

use super::Uint;
use super::uint::Limb;

/// Computes `a + b * c + carry`, returning `(low, carry_out)`.
///
/// The result always fits: `(2⁶⁴−1) + (2⁶⁴−1)² + (2⁶⁴−1) < 2¹²⁸`.
#[inline]
pub(crate) const fn mac(a: Limb, b: Limb, c: Limb, carry: Limb) -> (Limb, Limb) {
    let ret = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (ret as Limb, (ret >> 64) as Limb)
}

impl<const LIMBS: usize> Uint<LIMBS> {
    /// Computes the full `2 * LIMBS`-limb product `self * rhs`, returned as
    /// `(low, high)` halves (each `LIMBS` limbs, little-endian).
    pub fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        let a = self.as_limbs();
        let b = rhs.as_limbs();
        let mut lo = [0 as Limb; LIMBS];
        let mut hi = [0 as Limb; LIMBS];

        let mut i = 0;
        while i < LIMBS {
            let mut carry = 0;
            let mut j = 0;
            while j < LIMBS {
                let p = i + j;
                if p < LIMBS {
                    let (v, c) = mac(lo[p], a[i], b[j], carry);
                    lo[p] = v;
                    carry = c;
                } else {
                    let idx = p - LIMBS;
                    let (v, c) = mac(hi[idx], a[i], b[j], carry);
                    hi[idx] = v;
                    carry = c;
                }
                j += 1;
            }
            // Final carry lands at position i + LIMBS (== hi[i]), untouched so far.
            hi[i] = carry;
            i += 1;
        }

        (Uint::from_limbs(lo), Uint::from_limbs(hi))
    }

    /// Multiplies modulo `2^(64*LIMBS)`, returning only the low half.
    #[inline]
    pub fn wrapping_mul(&self, rhs: &Self) -> Self {
        self.mul_wide(rhs).0
    }

    /// Computes the full `2 * LIMBS`-limb square, returned as `(low, high)`.
    #[inline]
    pub fn square_wide(&self) -> (Self, Self) {
        self.mul_wide(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_wide_u64() {
        // 64-bit * 64-bit fits exactly in (lo, hi) checked against u128.
        let cases: [u64; 6] = [0, 1, 2, u64::MAX, u64::MAX - 1, 0x0123_4567_89ab_cdef];
        for &a in &cases {
            for &b in &cases {
                let (lo, hi) = Uint::<1>::from_u64(a).mul_wide(&Uint::<1>::from_u64(b));
                let expected = (a as u128) * (b as u128);
                let got = (lo.as_limbs()[0] as u128) | ((hi.as_limbs()[0] as u128) << 64);
                assert_eq!(got, expected, "{a} * {b}");
            }
        }
    }

    #[test]
    fn wrapping_mul_matches_u128() {
        fn u(v: u128) -> Uint<2> {
            Uint::from_limbs([v as u64, (v >> 64) as u64])
        }
        let cases: [u128; 5] = [0, 1, u64::MAX as u128, (1u128 << 64) + 7, u128::MAX];
        for &a in &cases {
            for &b in &cases {
                let prod = u(a).wrapping_mul(&u(b));
                let got = (prod.as_limbs()[0] as u128) | ((prod.as_limbs()[1] as u128) << 64);
                assert_eq!(got, a.wrapping_mul(b), "{a} * {b}");
            }
        }
    }

    #[test]
    fn mul_wide_256bit_max_square() {
        // (2^128 - 1)^2 = 2^256 - 2^129 + 1  =>  high = 2^128 - 2, low = 1.
        let max = Uint::<2>::from_limbs([u64::MAX, u64::MAX]);
        let (lo, hi) = max.square_wide();
        assert_eq!(lo, Uint::<2>::ONE);
        assert_eq!(hi, Uint::<2>::from_limbs([u64::MAX - 1, u64::MAX]));
    }
}
