//! Standalone message authentication codes.
//!
//! The [`hash`](crate::hash) module already ships HMAC; this module collects
//! MAC primitives that don't fit there because they are built on a block
//! cipher rather than a hash function.
//!
//! Currently exposes the UMAC family from RFC 4418:
//!
//! - [`Umac64`] — 8-byte tag (`UMAC-AES-128`, `iter = 2`).
//! - [`Umac128`] — 16-byte tag (`UMAC-AES-128`, `iter = 4`).
//!
//! Both are keyed with a 16-byte AES key and accept an 8-, 12- or 16-byte
//! nonce; messages are authenticated as a single value or in streaming
//! chunks.

mod umac;

pub use umac::{Umac64, Umac128};
