//! Shared curve25519 backend: GF(2²⁵⁵−19) field, edwards25519 points, and
//! order-`L` scalar arithmetic.
//!
//! This `pub(crate)` backend is the single arithmetic core consumed by three
//! higher layers, so they share one audited implementation:
//!
//! - [`crate::ec::ed25519`] — the RFC 8032 signing/verification path;
//! - [`crate::ec::edwards25519::hazmat`] — low-level group/scalar exposure
//!   (feature `hazmat-edwards25519`);
//! - [`crate::ec::ristretto255`] — the RFC 9496 prime-order group
//!   (feature `ristretto255`).
//!
//! The field/point/scalar internals were extracted verbatim from the original
//! private `ed25519.rs` implementation; Ed25519 signing output is unchanged.

pub(crate) mod field;
pub(crate) mod point;
pub(crate) mod scalar;
