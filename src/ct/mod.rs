//! Constant-time primitives.
//!
//! This module is the foundation of `purecrypto`: every operation here runs in
//! time independent of the secret values it touches, so higher layers (MAC
//! comparison, conditional field arithmetic, scalar selection, ...) can be
//! built without secret-dependent branches or memory accesses.
//!
//! The API follows the well-established [`Choice`] / [`ConstantTimeEq`] /
//! [`ConditionallySelectable`] pattern, reimplemented from scratch with no
//! external dependencies.
//!
//! # What "constant time" means here
//!
//! These routines avoid secret-dependent branches and table indexing at the
//! source level, and apply [`core::hint::black_box`] as an optimization
//! barrier to discourage the compiler from reintroducing them. This is
//! best-effort: genuine constant-time behavior also depends on the target CPU
//! and the emitted machine code, and should be validated with timing-analysis
//! tooling (e.g. dudect-style measurements) for security-critical use.
//!
//! Converting a [`Choice`] into a plain [`bool`] is the one deliberately
//! *variable-time* operation — do it only once a value is no longer secret.

mod eq;
mod ord;
mod select;

pub use eq::ConstantTimeEq;
pub use ord::{ConstantTimeGreater, ConstantTimeLess};
pub use select::ConditionallySelectable;

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

/// A boolean that can be combined and consumed without secret-dependent
/// branching.
///
/// Internally a `u8` that is always `0` (false) or `1` (true). Combine choices
/// with the bitwise operators (`&`, `|`, `^`, `!`); turn one *into* a real
/// [`bool`] only at the end of a computation, once the result is public —
/// that conversion is **not** constant time.
#[derive(Clone, Copy, Debug, Default)]
pub struct Choice(u8);

impl Choice {
    /// Returns the inner `0`/`1` byte.
    #[inline]
    pub fn unwrap_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for Choice {
    /// Wraps a byte as a [`Choice`] using `!= 0` semantics.
    ///
    /// Debug builds assert the input is already `0` or `1`. In every build the
    /// normalization is **branchless and constant time**: any nonzero byte maps
    /// to `Choice(1)` and only `0` maps to `Choice(0)`. This avoids the old
    /// `value & 1` foot-gun where a full `0xFF`/`0xFE` mask byte (the natural
    /// output of constant-time mask computations) would be silently truncated
    /// to its low bit — turning a `0xFE` "true" mask into `Choice(0)`.
    /// (Internal callers should still keep the bit clean; the normalization is
    /// a safety net, not a license to pass arbitrary bytes.)
    #[inline]
    fn from(value: u8) -> Self {
        debug_assert!(value == 0 || value == 1, "Choice must be 0 or 1");
        // Branchless byte-nonzero: `(x | -x) >> 7` is 1 for any nonzero `x`
        // and 0 for `x == 0`, with no data-dependent branch on `value`.
        Choice(((value | value.wrapping_neg()) >> 7) & 1)
    }
}

impl From<Choice> for bool {
    /// Converts to a plain [`bool`]. **Not constant time** — use only on values
    /// that are no longer secret.
    #[inline]
    fn from(choice: Choice) -> Self {
        choice.0 != 0
    }
}

impl BitAnd for Choice {
    type Output = Choice;
    #[inline]
    fn bitand(self, rhs: Choice) -> Choice {
        Choice(self.0 & rhs.0)
    }
}

impl BitAndAssign for Choice {
    #[inline]
    fn bitand_assign(&mut self, rhs: Choice) {
        self.0 &= rhs.0;
    }
}

impl BitOr for Choice {
    type Output = Choice;
    #[inline]
    fn bitor(self, rhs: Choice) -> Choice {
        Choice(self.0 | rhs.0)
    }
}

impl BitOrAssign for Choice {
    #[inline]
    fn bitor_assign(&mut self, rhs: Choice) {
        self.0 |= rhs.0;
    }
}

impl BitXor for Choice {
    type Output = Choice;
    #[inline]
    fn bitxor(self, rhs: Choice) -> Choice {
        Choice(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for Choice {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Choice) {
        self.0 ^= rhs.0;
    }
}

impl Not for Choice {
    type Output = Choice;
    #[inline]
    fn not(self) -> Choice {
        // self.0 is 0 or 1, so xor with 1 flips it.
        Choice(self.0 ^ 1)
    }
}

impl ConstantTimeEq for Choice {
    #[inline]
    fn ct_eq(&self, other: &Choice) -> Choice {
        // Equal -> 0 after xor -> 1 after xor with 1.
        Choice((self.0 ^ other.0) ^ 1)
    }
}

impl ConditionallySelectable for Choice {
    #[inline]
    fn conditional_select(a: &Choice, b: &Choice, choice: Choice) -> Choice {
        Choice(u8::conditional_select(&a.0, &b.0, choice))
    }
}

/// An [`Option`]-like container whose presence flag is a [`Choice`], so that
/// fallible results can be threaded through constant-time code without
/// branching on whether a value is present.
///
/// The wrapped value is always materialized (even when "none"); it simply must
/// not be observed unless [`is_some`](CtOption::is_some) is true. Combinators
/// such as [`map`](CtOption::map) therefore always run their closure.
#[derive(Clone, Copy, Debug, Default)]
pub struct CtOption<T> {
    value: T,
    is_some: Choice,
}

impl<T> CtOption<T> {
    /// Creates a new `CtOption` carrying `value`, present iff `is_some` is true.
    #[inline]
    pub fn new(value: T, is_some: Choice) -> Self {
        CtOption { value, is_some }
    }

    /// Returns a [`Choice`] that is true iff a value is present.
    #[inline]
    pub fn is_some(&self) -> Choice {
        self.is_some
    }

    /// Returns a [`Choice`] that is true iff no value is present.
    #[inline]
    pub fn is_none(&self) -> Choice {
        !self.is_some
    }

    /// Applies `f` to the wrapped value, preserving the presence flag.
    ///
    /// `f` runs unconditionally (including in the "none" case), keeping the
    /// operation constant time.
    #[inline]
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> CtOption<U> {
        CtOption::new(f(self.value), self.is_some)
    }
}

impl<T: ConditionallySelectable> CtOption<T> {
    /// Returns the contained value if present, otherwise `default`, selecting
    /// between them in constant time.
    #[inline]
    pub fn unwrap_or(self, default: T) -> T {
        // Pick the contained value when present, the default otherwise.
        T::conditional_select(&self.value, &default, self.is_some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn truthy(c: Choice) -> bool {
        c.into()
    }

    #[test]
    fn choice_logic() {
        let t = Choice::from(1);
        let f = Choice::from(0);
        assert!(truthy(t) && !truthy(f));
        assert!(truthy(t & t) && !truthy(t & f));
        assert!(truthy(t | f) && !truthy(f | f));
        assert!(truthy(t ^ f) && !truthy(t ^ t));
        assert!(truthy(!f) && !truthy(!t));
    }

    // `Choice::from` normalizes with `!= 0` semantics, so any nonzero byte —
    // including a full `0xFF`/`0xFE` mask — maps to a truthy `Choice` and only
    // `0` maps to a falsy one. We exercise the branchless normalization formula
    // directly here because `Choice::from` debug-asserts a clean 0/1 input, and
    // the unit tests build in debug mode.
    #[test]
    fn choice_from_nonzero_normalization() {
        let normalize = |value: u8| ((value | value.wrapping_neg()) >> 7) & 1;
        assert_eq!(normalize(0x00), 0);
        for v in 1u16..=255 {
            let v = v as u8;
            assert_eq!(normalize(v), 1, "byte {v:#04x} must normalize to 1");
        }
        // The clean-input path still agrees with `Choice::from`.
        assert!(truthy(Choice::from(1)));
        assert!(!truthy(Choice::from(0)));
    }

    #[test]
    fn choice_assign_ops() {
        let mut c = Choice::from(1);
        c &= Choice::from(0);
        assert!(!truthy(c));
        c |= Choice::from(1);
        assert!(truthy(c));
        c ^= Choice::from(1);
        assert!(!truthy(c));
    }

    #[test]
    fn choice_eq_and_select() {
        assert!(truthy(Choice::from(1).ct_eq(&Choice::from(1))));
        assert!(!truthy(Choice::from(1).ct_eq(&Choice::from(0))));
        let a = Choice::from(1);
        let b = Choice::from(0);
        assert!(truthy(Choice::conditional_select(&a, &b, Choice::from(1))));
        assert!(!truthy(Choice::conditional_select(&a, &b, Choice::from(0))));
    }

    #[test]
    fn ct_option_basics() {
        let some = CtOption::new(7u32, Choice::from(1));
        let none = CtOption::new(7u32, Choice::from(0));
        assert!(truthy(some.is_some()) && !truthy(some.is_none()));
        assert!(!truthy(none.is_some()) && truthy(none.is_none()));
        assert_eq!(some.unwrap_or(99), 7);
        assert_eq!(none.unwrap_or(99), 99);
        assert_eq!(some.map(|v| v + 1).unwrap_or(0), 8);
    }
}
