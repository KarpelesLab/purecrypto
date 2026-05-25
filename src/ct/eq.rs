//! Constant-time equality.

use super::Choice;

/// Equality testing that runs in time independent of the values compared.
pub trait ConstantTimeEq {
    /// Returns a [`Choice`] that is true iff `self` and `other` are equal.
    fn ct_eq(&self, other: &Self) -> Choice;

    /// Returns a [`Choice`] that is true iff `self` and `other` differ.
    #[inline]
    fn ct_ne(&self, other: &Self) -> Choice {
        !self.ct_eq(other)
    }
}

macro_rules! impl_ct_eq_uint {
    ($($t:ty),+ $(,)?) => {$(
        impl ConstantTimeEq for $t {
            #[inline]
            fn ct_eq(&self, other: &$t) -> Choice {
                // `x` is zero iff the inputs are equal.
                let x = self ^ other;
                // The top bit of `x | -x` is 1 iff `x != 0`; shifting it down
                // yields 1 for "different" and 0 for "equal".
                let differ = (x | x.wrapping_neg()) >> (<$t>::BITS - 1);
                // Flip to the "equal" sense and barrier the result.
                Choice::from(core::hint::black_box((differ as u8) ^ 1) & 1)
            }
        }
    )+};
}

impl_ct_eq_uint!(u8, u16, u32, u64, u128, usize);

macro_rules! impl_ct_eq_int {
    ($($t:ty => $u:ty),+ $(,)?) => {$(
        impl ConstantTimeEq for $t {
            #[inline]
            fn ct_eq(&self, other: &$t) -> Choice {
                // Equality of signed values is bit-pattern equality.
                (*self as $u).ct_eq(&(*other as $u))
            }
        }
    )+};
}

impl_ct_eq_int!(i8 => u8, i16 => u16, i32 => u32, i64 => u64, i128 => u128, isize => usize);

impl ConstantTimeEq for bool {
    #[inline]
    fn ct_eq(&self, other: &bool) -> Choice {
        (*self as u8).ct_eq(&(*other as u8))
    }
}

impl<T: ConstantTimeEq> ConstantTimeEq for [T] {
    /// Compares two slices element-by-element.
    ///
    /// The length comparison is *not* secret: unequal-length slices return
    /// false immediately. For equal lengths, every element is always compared,
    /// so the running time depends only on the (public) length.
    #[inline]
    fn ct_eq(&self, other: &[T]) -> Choice {
        if self.len() != other.len() {
            return Choice::from(0);
        }
        let mut acc = Choice::from(1);
        for (a, b) in self.iter().zip(other.iter()) {
            acc &= a.ct_eq(b);
        }
        acc
    }
}

impl<T: ConstantTimeEq, const N: usize> ConstantTimeEq for [T; N] {
    #[inline]
    fn ct_eq(&self, other: &[T; N]) -> Choice {
        self[..].ct_eq(&other[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eq(c: Choice) -> bool {
        c.into()
    }

    #[test]
    fn u8_exhaustive() {
        for a in 0u8..=u8::MAX {
            for b in 0u8..=u8::MAX {
                assert_eq!(eq(a.ct_eq(&b)), a == b);
                assert_eq!(eq(a.ct_ne(&b)), a != b);
            }
        }
    }

    #[test]
    fn i8_exhaustive() {
        for a in i8::MIN..=i8::MAX {
            for b in i8::MIN..=i8::MAX {
                assert_eq!(eq(a.ct_eq(&b)), a == b);
            }
        }
    }

    #[test]
    fn wide_edges() {
        assert!(eq(0u32.ct_eq(&0)));
        assert!(eq(u32::MAX.ct_eq(&u32::MAX)));
        assert!(!eq(0u32.ct_eq(&1)));
        assert!(!eq(u32::MAX.ct_eq(&(u32::MAX - 1))));

        assert!(eq(u64::MAX.ct_eq(&u64::MAX)));
        assert!(!eq(1u64.ct_eq(&(1u64 << 63))));

        assert!(eq(u128::MAX.ct_eq(&u128::MAX)));
        assert!(!eq(0u128.ct_eq(&(1u128 << 100))));

        assert!(eq(true.ct_eq(&true)));
        assert!(!eq(true.ct_eq(&false)));
    }

    #[test]
    fn slices_and_arrays() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        assert!(eq(a.ct_eq(&b)));
        assert!(!eq(a.ct_eq(&c)));
        assert!(eq(a[..].ct_eq(&b[..])));
        // Differing lengths compare unequal.
        assert!(!eq(a[..].ct_eq(&a[..3])));
        // Empty slices are equal.
        assert!(eq((&[] as &[u8]).ct_eq(&[])));
    }
}
