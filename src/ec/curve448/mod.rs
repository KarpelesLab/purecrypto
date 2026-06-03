//! Shared curve448 backend: GF(2⁴⁴⁸−2²²⁴−1) field, edwards448 points, and
//! order-`L` scalar arithmetic.
//!
//! This `pub(crate)` backend is the single arithmetic core consumed by the
//! higher-level [`crate::ec::ed448`] (RFC 8032 signing/verification) path. The
//! [`crate::ec::x448`] X448 Diffie-Hellman primitive shares the same field
//! prime but runs its own Montgomery ladder, so it consumes only the
//! [`MontModulus`](crate::bignum::MontModulus) directly rather than this
//! Edwards point backend.
//!
//! The edwards448 curve here is the *untwisted* Edwards curve `x² + y² =
//! 1 + d·x²·y²` with `a = +1` and `d = −39081 mod p`, so its complete
//! Hisil–Wong–Carter–Dawson addition formulas use a single `d` (not the `2d`
//! of the `a = −1` edwards25519 set). Cofactor 4; `d` is a non-square, so the
//! formulas have no exceptional cases.

pub(crate) mod field;
pub(crate) mod point;
pub(crate) mod scalar;
