//! Standalone message authentication codes.
//!
//! The [`hash`][crate::hash] module already ships HMAC, KMAC and the other
//! hash-derived MACs; this module collects the MAC primitives that are not
//! built on a hash function (universal-hash constructions over a block
//! cipher, and the SipHash ARX PRF).
//!
//! - The UMAC family from RFC 4418: [`Umac64`] (8-byte tag, `iter = 2`)
//!   and [`Umac128`] (16-byte tag, `iter = 4`). Both are keyed with a
//!   16-byte AES key and accept a nonce of 1 to 16 bytes (RFC 4418 §3.3.1;
//!   8 bytes is the conventional choice).
//! - VMAC from draft-krovetz-vmac-01 (opt-in, behind the `vmac` feature):
//!   [`Vmac64`] and [`Vmac128`], AES-128 by default (any 128-bit block
//!   cipher via `with_cipher`), with a nonce of at most 127 bits (a longer
//!   one is an [`InvalidNonce`] error).
//! - SipHash-c-d (Aumasson–Bernstein): [`SipHash13`], [`SipHash24`],
//!   [`SipHash48`] with a 64-bit output, and the 128-bit-output
//!   [`SipHashX24`] / [`SipHashX48`]; all keyed with 16 bytes, no nonce.
//!
//! Every MAC here authenticates messages as a single value or in streaming
//! chunks, and offers a length-strict constant-time `verify`.
#![cfg_attr(not(feature = "hash"), doc = "", doc = "[crate::hash]: crate")]
#![cfg_attr(
    not(feature = "vmac"),
    doc = "",
    doc = "[`Vmac64`]: crate",
    doc = "[`Vmac128`]: crate",
    doc = "[`InvalidNonce`]: crate"
)]

mod siphash;
mod umac;
#[cfg(feature = "vmac")]
mod vmac;

pub use siphash::{SipHash, SipHash13, SipHash24, SipHash48, SipHashX, SipHashX24, SipHashX48};
pub use umac::{Umac64, Umac128};
#[cfg(feature = "vmac")]
pub use vmac::{InvalidNonce, Vmac64, Vmac128};
