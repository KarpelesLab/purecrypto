//! Fixed-size unsigned big integers.

use crate::ct::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
};

/// A single limb of a [`Uint`].
pub type Limb = u64;

/// Number of bits in a [`Limb`].
pub const LIMB_BITS: usize = 64;

/// An unsigned integer of `LIMBS * 64` bits, stored little-endian (limb 0 is
/// least significant).
///
/// `==` and the derived comparisons are **not** constant time; use the
/// [`ConstantTimeEq`] / [`ConstantTimeGreater`] / [`ConstantTimeLess`] methods
/// when comparing secret values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uint<const LIMBS: usize> {
    limbs: [Limb; LIMBS],
}

/// Adds `a + b + carry`, returning `(sum, carry_out)`.
#[inline]
pub(crate) const fn adc(a: Limb, b: Limb, carry: Limb) -> (Limb, Limb) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as Limb, (ret >> LIMB_BITS) as Limb)
}

/// Computes `a - b - borrow`, returning `(diff, borrow_out)` where `borrow_out`
/// is `1` on underflow and `0` otherwise.
#[inline]
pub(crate) const fn sbb(a: Limb, b: Limb, borrow: Limb) -> (Limb, Limb) {
    let ret = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (ret as Limb, ((ret >> LIMB_BITS) as Limb) & 1)
}

impl<const LIMBS: usize> Uint<LIMBS> {
    /// The number of limbs.
    pub const LIMBS: usize = LIMBS;

    /// The zero value.
    pub const ZERO: Self = Uint { limbs: [0; LIMBS] };

    /// The value one.
    pub const ONE: Self = Self::from_u64(1);

    /// Creates a `Uint` from a single 64-bit value.
    pub const fn from_u64(v: u64) -> Self {
        let mut limbs = [0; LIMBS];
        limbs[0] = v;
        Uint { limbs }
    }

    /// Returns the limbs (little-endian).
    #[inline]
    pub const fn as_limbs(&self) -> &[Limb; LIMBS] {
        &self.limbs
    }

    /// Builds a `Uint` directly from little-endian limbs.
    #[inline]
    pub const fn from_limbs(limbs: [Limb; LIMBS]) -> Self {
        Uint { limbs }
    }

    /// Interprets `bytes` as a big-endian integer (most-significant byte
    /// first). Shorter inputs are zero-extended.
    ///
    /// # Panics
    /// Panics if `bytes` is longer than the integer can hold (`LIMBS * 8`).
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() <= LIMBS * 8, "input too large for Uint");
        let mut limbs = [0; LIMBS];
        let mut end = bytes.len();
        let mut i = 0;
        while end > 0 {
            let start = end.saturating_sub(8);
            let mut buf = [0u8; 8];
            let slice = &bytes[start..end];
            buf[8 - slice.len()..].copy_from_slice(slice);
            limbs[i] = Limb::from_be_bytes(buf);
            i += 1;
            end = start;
        }
        Uint { limbs }
    }

    /// Writes this integer big-endian into `out`, which must be exactly
    /// `LIMBS * 8` bytes.
    ///
    /// # Panics
    /// Panics if `out.len() != LIMBS * 8`.
    pub fn write_be_bytes(&self, out: &mut [u8]) {
        assert_eq!(out.len(), LIMBS * 8, "output buffer has wrong length");
        for i in 0..LIMBS {
            let limb = self.limbs[LIMBS - 1 - i];
            out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
        }
    }

    /// Interprets `bytes` as a little-endian integer (least-significant byte
    /// first). Shorter inputs are zero-extended.
    ///
    /// # Panics
    /// Panics if `bytes` is longer than the integer can hold (`LIMBS * 8`).
    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() <= LIMBS * 8, "input too large for Uint");
        let mut limbs = [0; LIMBS];
        let mut i = 0;
        while i * 8 < bytes.len() {
            let end = (i * 8 + 8).min(bytes.len());
            let mut buf = [0u8; 8];
            buf[..end - i * 8].copy_from_slice(&bytes[i * 8..end]);
            limbs[i] = Limb::from_le_bytes(buf);
            i += 1;
        }
        Uint { limbs }
    }

    /// Writes this integer little-endian into `out`, which must be exactly
    /// `LIMBS * 8` bytes.
    ///
    /// # Panics
    /// Panics if `out.len() != LIMBS * 8`.
    pub fn write_le_bytes(&self, out: &mut [u8]) {
        assert_eq!(out.len(), LIMBS * 8, "output buffer has wrong length");
        for i in 0..LIMBS {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.limbs[i].to_le_bytes());
        }
    }

    /// Adds `self + rhs + carry`, returning the sum and the carry out of the
    /// most significant limb.
    pub fn adc(&self, rhs: &Self, carry: Limb) -> (Self, Limb) {
        let mut limbs = [0; LIMBS];
        let mut c = carry;
        let mut i = 0;
        while i < LIMBS {
            let (s, co) = adc(self.limbs[i], rhs.limbs[i], c);
            limbs[i] = s;
            c = co;
            i += 1;
        }
        (Uint { limbs }, c)
    }

    /// Subtracts `self - rhs - borrow`, returning the difference and the borrow
    /// out (`1` if the true result was negative).
    pub fn sbb(&self, rhs: &Self, borrow: Limb) -> (Self, Limb) {
        let mut limbs = [0; LIMBS];
        let mut b = borrow;
        let mut i = 0;
        while i < LIMBS {
            let (d, bo) = sbb(self.limbs[i], rhs.limbs[i], b);
            limbs[i] = d;
            b = bo;
            i += 1;
        }
        (Uint { limbs }, b)
    }

    /// Adds modulo `2^(64*LIMBS)`, discarding the final carry.
    #[inline]
    pub fn wrapping_add(&self, rhs: &Self) -> Self {
        self.adc(rhs, 0).0
    }

    /// Subtracts modulo `2^(64*LIMBS)`, discarding the final borrow.
    #[inline]
    pub fn wrapping_sub(&self, rhs: &Self) -> Self {
        self.sbb(rhs, 0).0
    }

    /// Returns a [`Choice`] that is true iff this value is zero.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Self::ZERO)
    }

    /// Returns a [`Choice`] that is true iff this value is odd.
    #[inline]
    pub fn is_odd(&self) -> Choice {
        Choice::from((self.limbs[0] & 1) as u8)
    }

    /// Returns the bit length (position of the most significant set bit plus
    /// one); zero for a zero value. Not constant time — depends on the value.
    pub fn bit_len(&self) -> usize {
        let mut i = LIMBS;
        while i > 0 {
            i -= 1;
            if self.limbs[i] != 0 {
                return i * LIMB_BITS + (LIMB_BITS - self.limbs[i].leading_zeros() as usize);
            }
        }
        0
    }

    /// Returns `self >> 1` (one-bit logical right shift).
    pub fn shr1(&self) -> Self {
        let mut limbs = self.limbs;
        let mut carry = 0;
        let mut i = LIMBS;
        while i > 0 {
            i -= 1;
            let next_carry = limbs[i] & 1;
            limbs[i] = (limbs[i] >> 1) | (carry << (LIMB_BITS - 1));
            carry = next_carry;
        }
        Uint { limbs }
    }

    /// Reduces `self` modulo `modulus` via bitwise long division.
    ///
    /// Constant time in the values (the schedule depends only on the bit
    /// width). `modulus` must be nonzero.
    ///
    /// # Panics
    /// Panics if `modulus` is zero. (Long division by zero would silently
    /// produce a meaningless result — every iteration "subtracts" because
    /// the borrow never fires — so the precondition is checked rather than
    /// returning garbage.)
    pub fn reduce(&self, modulus: &Self) -> Self {
        assert!(
            !bool::from(modulus.is_zero()),
            "Uint::reduce: modulus must be nonzero"
        );
        let mut r = Self::ZERO;
        let mut i = LIMBS;
        while i > 0 {
            i -= 1;
            let mut bit = LIMB_BITS;
            while bit > 0 {
                bit -= 1;
                // r = (r << 1) | next bit of self
                let (mut shifted, carry) = r.adc(&r, 0);
                shifted.limbs[0] |= (self.limbs[i] >> bit) & 1;
                // Subtract modulus when shifted overflowed or shifted >= modulus.
                let (diff, borrow) = shifted.sbb(modulus, 0);
                let ge = Choice::from((carry | (borrow ^ 1)) as u8);
                r = Self::conditional_select(&diff, &shifted, ge);
            }
        }
        r
    }

    /// Returns `(quotient, remainder)` for `self / divisor` via bitwise long
    /// division. Constant time in the values; `divisor` must be nonzero.
    ///
    /// # Panics
    /// Panics if `divisor` is zero. (See [`Uint::reduce`] for why this is
    /// checked rather than returning a meaningless result.)
    pub fn divrem(&self, divisor: &Self) -> (Self, Self) {
        assert!(
            !bool::from(divisor.is_zero()),
            "Uint::divrem: divisor must be nonzero"
        );
        let mut q = Self::ZERO;
        let mut r = Self::ZERO;
        let mut i = LIMBS;
        while i > 0 {
            i -= 1;
            let mut bit = LIMB_BITS;
            while bit > 0 {
                bit -= 1;
                // r = (r << 1) | next bit of self
                let (mut shifted, carry) = r.adc(&r, 0);
                shifted.limbs[0] |= (self.limbs[i] >> bit) & 1;
                let (mut q_shifted, _) = q.adc(&q, 0); // q <<= 1
                let (diff, borrow) = shifted.sbb(divisor, 0);
                let ge = Choice::from((carry | (borrow ^ 1)) as u8);
                r = Self::conditional_select(&diff, &shifted, ge);
                q_shifted.limbs[0] |= ge.unwrap_u8() as u64; // quotient bit
                q = q_shifted;
            }
        }
        (q, r)
    }
}

impl<const LIMBS: usize> Default for Uint<LIMBS> {
    #[inline]
    fn default() -> Self {
        Self::ZERO
    }
}

impl<const LIMBS: usize> ConstantTimeEq for Uint<LIMBS> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.limbs.ct_eq(&other.limbs)
    }
}

impl<const LIMBS: usize> ConstantTimeGreater for Uint<LIMBS> {
    #[inline]
    fn ct_gt(&self, other: &Self) -> Choice {
        // self > other iff (other - self) borrows.
        let (_, borrow) = other.sbb(self, 0);
        Choice::from(borrow as u8)
    }
}

// ct_lt is provided by the default impl: `self < other` ⇔ `other > self`.
impl<const LIMBS: usize> ConstantTimeLess for Uint<LIMBS> {}

impl<const LIMBS: usize> ConditionallySelectable for Uint<LIMBS> {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0; LIMBS];
        let mut i = 0;
        while i < LIMBS {
            limbs[i] = Limb::conditional_select(&a.limbs[i], &b.limbs[i], choice);
            i += 1;
        }
        Uint { limbs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type U128 = Uint<2>;

    fn from_u128(v: u128) -> U128 {
        Uint::from_limbs([v as u64, (v >> 64) as u64])
    }

    fn to_u128(u: &U128) -> u128 {
        (u.as_limbs()[0] as u128) | ((u.as_limbs()[1] as u128) << 64)
    }

    const CASES: &[u128] = &[
        0,
        1,
        2,
        u64::MAX as u128,
        (u64::MAX as u128) + 1,
        u128::MAX,
        u128::MAX - 1,
        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
        1 << 64,
        1 << 127,
    ];

    #[test]
    fn add_sub_match_u128() {
        for &a in CASES {
            for &b in CASES {
                let (sum, carry) = from_u128(a).adc(&from_u128(b), 0);
                assert_eq!(to_u128(&sum), a.wrapping_add(b));
                assert_eq!(carry == 1, a.checked_add(b).is_none());

                let (diff, borrow) = from_u128(a).sbb(&from_u128(b), 0);
                assert_eq!(to_u128(&diff), a.wrapping_sub(b));
                assert_eq!(borrow == 1, a < b);
            }
        }
    }

    #[test]
    fn ct_compare_matches_u128() {
        for &a in CASES {
            for &b in CASES {
                let (x, y) = (from_u128(a), from_u128(b));
                assert_eq!(bool::from(x.ct_eq(&y)), a == b);
                assert_eq!(bool::from(x.ct_gt(&y)), a > b);
                assert_eq!(bool::from(x.ct_lt(&y)), a < b);
            }
        }
        assert!(bool::from(U128::ZERO.is_zero()));
        assert!(!bool::from(U128::ONE.is_zero()));
    }

    #[test]
    fn conditional_select_picks_correctly() {
        let a = from_u128(0xaaaa_aaaa_aaaa_aaaa);
        let b = from_u128(0x5555_5555_5555_5555);
        assert_eq!(U128::conditional_select(&a, &b, Choice::from(1)), a);
        assert_eq!(U128::conditional_select(&a, &b, Choice::from(0)), b);
    }

    #[test]
    fn be_bytes_roundtrip() {
        let v = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128;
        let u = from_u128(v);
        let mut buf = [0u8; 16];
        u.write_be_bytes(&mut buf);
        assert_eq!(buf, v.to_be_bytes());
        assert_eq!(U128::from_be_bytes(&buf), u);

        // Short, zero-extended input.
        assert_eq!(U128::from_be_bytes(&[0x01, 0x00]), from_u128(0x100));
        assert_eq!(U128::from_be_bytes(&[]), U128::ZERO);
    }

    #[test]
    fn larger_widths_compile_and_work() {
        // 4096-bit: exercises LIMBS > 32 (where derived array Default wouldn't
        // exist) and confirms the const-generic surface scales.
        let mut a = Uint::<64>::ONE;
        a = a.wrapping_add(&Uint::<64>::ONE);
        assert_eq!(a.as_limbs()[0], 2);
        assert!(bool::from(Uint::<64>::default().is_zero()));
    }

    #[test]
    #[should_panic(expected = "modulus must be nonzero")]
    fn reduce_zero_modulus_panics() {
        // Long division by zero would silently "subtract" forever; the
        // precondition is now checked instead of returning garbage.
        let _ = Uint::<2>::from_u64(7).reduce(&Uint::<2>::ZERO);
    }

    #[test]
    #[should_panic(expected = "divisor must be nonzero")]
    fn divrem_zero_divisor_panics() {
        let _ = Uint::<2>::from_u64(7).divrem(&Uint::<2>::ZERO);
    }
}
