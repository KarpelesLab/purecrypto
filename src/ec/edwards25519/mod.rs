//! Edwards25519 group, low-level exposure.
//!
//! The audited RFC 8032 signing API lives in [`crate::ec::ed25519`]. This
//! module instead exposes the raw edwards25519 group and order-`L` scalar
//! arithmetic for callers building higher-level protocols (threshold
//! signatures, verifiable secret sharing, FROST, …) on top of the same
//! constant-time `curve25519` backend.
//!
//! The exposure is gated behind the `hazmat-edwards25519` feature and lives in
//! the [`hazmat`] submodule; see its module documentation for the stability
//! and constant-time contract.

// The hazmat surface is available when either the edwards25519 hazmat feature
// is requested directly, or when `ristretto255` is enabled (it re-exports the
// shared `Scalar` from here).
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub mod hazmat;
