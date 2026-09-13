//! Constant-time conditional selection.

use super::Choice;

/// Types that can be chosen between in constant time, without branching on the
/// deciding [`Choice`].
///
/// # Selection convention
///
/// This trait's [`conditional_select`](Self::conditional_select) returns
/// **`a` when `choice` is true** — the opposite of the `subtle` crate, whose
/// `conditional_select(a, b, choice)` returns `b` when `choice` is true. The
/// two conventions side by side:
///
/// | call | `choice` true | `choice` false |
/// | --- | --- | --- |
/// | `purecrypto` [`conditional_select(a, b, c)`](Self::conditional_select) | `a` | `b` |
/// | `subtle` `conditional_select(a, b, c)` | `b` | `a` |
/// | `purecrypto` [`conditional_select_b_if_true(a, b, c)`](Self::conditional_select_b_if_true) | `b` | `a` |
///
/// Code ported from `subtle` should call
/// [`conditional_select_b_if_true`](Self::conditional_select_b_if_true), which
/// has exactly `subtle`'s semantics. [`conditional_assign`](Self::conditional_assign)
/// and [`conditional_swap`](Self::conditional_swap) mean the same thing in both
/// crates.
pub trait ConditionallySelectable: Copy {
    /// Returns `a` if `choice` is true, otherwise `b`, without a
    /// secret-dependent branch.
    ///
    /// **Note the argument order:** this returns `a` when `choice` is true,
    /// which is the *opposite* of the `subtle` crate. Use
    /// [`conditional_select_b_if_true`](Self::conditional_select_b_if_true)
    /// for `subtle`-compatible semantics.
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self;

    /// Returns `b` if `choice` is true, otherwise `a` — the `subtle` crate's
    /// `conditional_select` convention, for code ported from it.
    ///
    /// Same constant-time guarantees as
    /// [`conditional_select`](Self::conditional_select), of which this is a
    /// plain argument swap.
    #[inline]
    fn conditional_select_b_if_true(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::conditional_select(b, a, choice)
    }

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
    fn b_if_true_all_widths() {
        macro_rules! check {
            ($($t:ty),+ $(,)?) => {$(
                let a: $t = 3;
                let b: $t = 5;
                assert_eq!(<$t>::conditional_select_b_if_true(&a, &b, t()), b);
                assert_eq!(<$t>::conditional_select_b_if_true(&a, &b, f()), a);
                // Exactly the mirror image of `conditional_select`.
                assert_eq!(
                    <$t>::conditional_select_b_if_true(&a, &b, t()),
                    <$t>::conditional_select(&b, &a, t())
                );
                let (lo, hi) = (<$t>::MIN, <$t>::MAX);
                assert_eq!(<$t>::conditional_select_b_if_true(&lo, &hi, t()), hi);
                assert_eq!(<$t>::conditional_select_b_if_true(&lo, &hi, f()), lo);
            )+};
        }
        check!(
            u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
        );

        let a = [1u8, 2, 3];
        let b = [4u8, 5, 6];
        assert_eq!(<[u8; 3]>::conditional_select_b_if_true(&a, &b, t()), b);
        assert_eq!(<[u8; 3]>::conditional_select_b_if_true(&a, &b, f()), a);
        let a = [u64::MAX; 4];
        let b = [0u64; 4];
        assert_eq!(<[u64; 4]>::conditional_select_b_if_true(&a, &b, t()), b);
        assert_eq!(<[u64; 4]>::conditional_select_b_if_true(&a, &b, f()), a);

        let c = Choice::from(1);
        let d = Choice::from(0);
        assert_eq!(
            Choice::conditional_select_b_if_true(&c, &d, t()).unwrap_u8(),
            0
        );
        assert_eq!(
            Choice::conditional_select_b_if_true(&c, &d, f()).unwrap_u8(),
            1
        );
    }

    #[test]
    fn u8_b_if_true_exhaustive() {
        for a in 0u8..=u8::MAX {
            for b in 0u8..=u8::MAX {
                assert_eq!(u8::conditional_select_b_if_true(&a, &b, t()), b);
                assert_eq!(u8::conditional_select_b_if_true(&a, &b, f()), a);
            }
        }
    }

    #[test]
    fn arrays() {
        let a = [1u8, 2, 3];
        let b = [4u8, 5, 6];
        assert_eq!(<[u8; 3]>::conditional_select(&a, &b, t()), a);
        assert_eq!(<[u8; 3]>::conditional_select(&a, &b, f()), b);
    }
}
