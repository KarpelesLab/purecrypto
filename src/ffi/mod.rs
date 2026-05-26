//! C ABI for `purecrypto` (the `ffi` feature).
//!
//! This is the only module permitted to use `unsafe` (the crate sets
//! `unsafe_code = "deny"`, not `forbid`, for exactly this purpose). It exposes
//! `extern "C"` entry points — hashing, HMAC, randomness, RSA/ECDSA keys and
//! signatures, and X.509 parsing/verification — declared in
//! `include/purecrypto.h`.
//!
//! ## Conventions
//! - Functions return [`PcStatus`] (`0` = success, negative = error). Fallible
//!   constructors instead return an opaque pointer that is NULL on failure.
//! - Variable-length output uses the in/out length convention: pass a buffer and
//!   a `*out_len` holding its capacity; on return `*out_len` is the actual (or,
//!   on [`PcStatus::BufferTooSmall`], the required) length. Call with a zero
//!   capacity to query the length first.
//! - Opaque handles (`PcHash`, `PcRsaKey`, `PcEcKey`, `PcCert`) are created and
//!   freed by the library; every `*_new`/`*_generate`/`*_from_*` is paired with
//!   a `*_free`.
//! - Every entry point catches panics, so a Rust panic surfaces as
//!   [`PcStatus::Internal`] rather than unwinding across the boundary.
//!
//! Build a C library with, e.g.:
//! `cargo rustc --release --features ffi --crate-type staticlib`
//! (or `--crate-type cdylib`).
#![allow(unsafe_code)]
#![allow(unreachable_pub)]

mod cipher;
mod common;
mod crl;
mod csr;
mod ec;
mod hash;
mod kdf;
mod mldsa;
mod mlkem;
mod rng;
mod rsa;
mod slhdsa;
mod tls;
mod x25519;
mod x509;

pub use common::PcStatus;

#[cfg(test)]
mod tests;
