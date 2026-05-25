//! Constant-time conditional selection.

use super::Choice;

/// Types that can be chosen between in constant time, without branching on the
/// deciding [`Choice`].
pub trait ConditionallySelectable: Copy {
    /// Returns `a` if `choice` is true, otherwise `b`, without a
    /// secret-dependent branch.
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self;

    /// Sets `self` to `other` if `choice` is true, otherwise leaves it
    /// unchanged.
    #[inline]
    fn conditional_assign(&mut self, other: &Self, choice: Choice) {
        // Pick `other` when choice is true, keep `self` otherwise.
        *self = Self::conditional_select(other, self, choice);
    }

    /// Swaps `a` and `b` if `choice` is true, otherwise leaves them unchanged.
    #[inline]
    fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        let t = *a;
        a.conditional_assign(b, choice);
        b.conditional_assign(&t, choice);
    }
}

macro_rules! impl_cond_select_uint {
    ($($t:ty),+ $(,)?) => {$(
        impl ConditionallySelectable for $t {
            #[inline]
            fn conditional_select(a: &$t, b: &$t, choice: Choice) -> $t {
                // `mask` is all-ones when choice is true, all-zeros otherwise.
                let mask = core::hint::black_box((choice.unwrap_u8() as $t).wrapping_neg());
                // choice => b ^ (a ^ b) = a; !choice => b ^ 0 = b.
                b ^ (mask & (a ^ b))
            }
        }
    )+};
}

impl_cond_select_uint!(u8, u16, u32, u64, u128, usize);

macro_rules! impl_cond_select_int {
    ($($t:ty => $u:ty),+ $(,)?) => {$(
        impl ConditionallySelectable for $t {
            #[inline]
            fn conditional_select(a: &$t, b: &$t, choice: Choice) -> $t {
                <$u>::conditional_select(&(*a as $u), &(*b as $u), choice) as $t
            }
        }
    )+};
}

impl_cond_select_int!(i8 => u8, i16 => u16, i32 => u32, i64 => u64, i128 => u128, isize => usize);

impl<T: ConditionallySelectable, const N: usize> ConditionallySelectable for [T; N] {
    #[inline]
    fn conditional_select(a: &[T; N], b: &[T; N], choice: Choice) -> [T; N] {
        let mut out = *a;
        for i in 0..N {
            out[i] = T::conditional_select(&a[i], &b[i], choice);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> Choice {
        Choice::from(1)
    }
    fn f() -> Choice {
        Choice::from(0)
    }

    #[test]
    fn u8_exhaustive() {
        for a in 0u8..=u8::MAX {
            for b in 0u8..=u8::MAX {
                assert_eq!(u8::conditional_select(&a, &b, t()), a);
                assert_eq!(u8::conditional_select(&a, &b, f()), b);
            }
        }
    }

    #[test]
    fn wide_and_signed() {
        assert_eq!(u64::conditional_select(&7, &9, t()), 7);
        assert_eq!(u64::conditional_select(&7, &9, f()), 9);
        assert_eq!(u128::conditional_select(&u128::MAX, &0, t()), u128::MAX);
        assert_eq!(i32::conditional_select(&-5, &5, t()), -5);
        assert_eq!(i32::conditional_select(&-5, &5, f()), 5);
    }

    #[test]
    fn assign_and_swap() {
        let mut x = 10u32;
        x.conditional_assign(&20, f());
        assert_eq!(x, 10);
        x.conditional_assign(&20, t());
        assert_eq!(x, 20);

        let (mut a, mut b) = (1u16, 2u16);
        u16::conditional_swap(&mut a, &mut b, f());
        assert_eq!((a, b), (1, 2));
        u16::conditional_swap(&mut a, &mut b, t());
        assert_eq!((a, b), (2, 1));
    }

    #[test]
    fn arrays() {
        let a = [1u8, 2, 3];
        let b = [4u8, 5, 6];
        assert_eq!(<[u8; 3]>::conditional_select(&a, &b, t()), a);
        assert_eq!(<[u8; 3]>::conditional_select(&a, &b, f()), b);
    }
}
