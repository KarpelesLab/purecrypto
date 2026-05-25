//! Constant-time ordering for unsigned integers.
//!
//! These are the comparisons needed by constant-time bignum arithmetic (e.g.
//! deciding a conditional subtraction). They are defined for unsigned types
//! only; signed ordering needs separate handling of the sign bit.

use super::Choice;

/// Greater-than comparison that runs in time independent of the values.
pub trait ConstantTimeGreater {
    /// Returns a [`Choice`] that is true iff `self > other`.
    fn ct_gt(&self, other: &Self) -> Choice;
}

/// Less-than comparison that runs in time independent of the values.
pub trait ConstantTimeLess: ConstantTimeGreater {
    /// Returns a [`Choice`] that is true iff `self < other`.
    #[inline]
    fn ct_lt(&self, other: &Self) -> Choice {
        other.ct_gt(self)
    }
}

macro_rules! impl_ct_ord_uint {
    ($($t:ty),+ $(,)?) => {$(
        impl ConstantTimeGreater for $t {
            #[inline]
            fn ct_gt(&self, other: &$t) -> Choice {
                let bits = <$t>::BITS;
                // Bits where self is greater (1) / less (0) than other.
                let gtb = self & !other;
                let mut ltb = !self & other;
                // Smear each "less" bit downward, so position i is set iff some
                // "less" bit exists at position >= i.
                let mut pow = 1;
                while pow < bits {
                    ltb |= ltb >> pow;
                    pow <<= 1;
                }
                // Keep only "greater" bits with no "less" bit at or above them,
                // i.e. self > other iff the highest differing bit is a gt bit.
                let mut bit = gtb & !ltb;
                // Fold the surviving bit down to the LSB.
                let mut pow = 1;
                while pow < bits {
                    bit |= bit >> pow;
                    pow <<= 1;
                }
                Choice::from(core::hint::black_box((bit & 1) as u8))
            }
        }

        impl ConstantTimeLess for $t {}
    )+};
}

impl_ct_ord_uint!(u8, u16, u32, u64, u128, usize);

#[cfg(test)]
mod tests {
    use super::*;

    fn b(c: Choice) -> bool {
        c.into()
    }

    #[test]
    fn u8_exhaustive() {
        for a in 0u8..=u8::MAX {
            for c in 0u8..=u8::MAX {
                assert_eq!(b(a.ct_gt(&c)), a > c);
                assert_eq!(b(a.ct_lt(&c)), a < c);
            }
        }
    }

    #[test]
    fn wide_edges() {
        assert!(b(1u64.ct_gt(&0)));
        assert!(!b(0u64.ct_gt(&0)));
        assert!(!b(0u64.ct_gt(&1)));
        assert!(b(u64::MAX.ct_gt(&(u64::MAX - 1))));
        assert!(b((u64::MAX - 1).ct_lt(&u64::MAX)));
        assert!(!b(u64::MAX.ct_lt(&u64::MAX)));

        assert!(b((1u128 << 100).ct_gt(&(1u128 << 99))));
        assert!(b(0u128.ct_lt(&u128::MAX)));

        assert!(b(200u8.ct_gt(&100)));
        assert!(!b(100u8.ct_gt(&200)));
    }
}
