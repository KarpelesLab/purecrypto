//! Constant-time conditional negation.

use super::{Choice, ConditionallySelectable};

/// Types that can be negated in constant time, without branching on the
/// deciding [`Choice`].
///
/// Implemented here for the primitive signed integers (two's-complement
/// wrapping negation, so `MIN` maps to itself without panicking). Field-element
/// and curve-point types implement it themselves with their own arithmetic.
pub trait ConditionallyNegatable {
    /// Replaces `self` with `-self` if `choice` is true, otherwise leaves it
    /// unchanged, without a secret-dependent branch.
    fn conditional_negate(&mut self, choice: Choice);
}

macro_rules! impl_cond_negate_int {
    ($($t:ty),+ $(,)?) => {$(
        impl ConditionallyNegatable for $t {
            #[inline]
            fn conditional_negate(&mut self, choice: Choice) {
                // Both candidates are computed unconditionally; the select is
                // the branch-free mask operation from `ConditionallySelectable`.
                let negated = self.wrapping_neg();
                self.conditional_assign(&negated, choice);
            }
        }
    )+};
}

impl_cond_negate_int!(i8, i16, i32, i64, i128, isize);

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
    fn i8_exhaustive() {
        for v in i8::MIN..=i8::MAX {
            let mut x = v;
            x.conditional_negate(f());
            assert_eq!(x, v);
            x.conditional_negate(t());
            assert_eq!(x, v.wrapping_neg());
            // Negating twice is the identity, including for `MIN`.
            x.conditional_negate(t());
            assert_eq!(x, v);
        }
    }

    #[test]
    fn edge_values() {
        macro_rules! check {
            ($($t:ty),+ $(,)?) => {$(
                for v in [0, 1, -1, 7, -7, <$t>::MAX, <$t>::MIN, <$t>::MIN + 1] {
                    let mut x: $t = v;
                    x.conditional_negate(f());
                    assert_eq!(x, v);
                    x.conditional_negate(t());
                    assert_eq!(x, v.wrapping_neg());
                }
                // `MIN` has no positive counterpart: it must map to itself
                // rather than overflow.
                let mut m = <$t>::MIN;
                m.conditional_negate(t());
                assert_eq!(m, <$t>::MIN);
                let mut one: $t = 1;
                one.conditional_negate(t());
                assert_eq!(one, -1);
            )+};
        }
        check!(i16, i32, i64, i128, isize);
    }
}
