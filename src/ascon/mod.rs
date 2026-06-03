//! Ascon lightweight cryptography (NIST SP 800-232).
//!
//! Implements the four functions standardized in NIST SP 800-232 ("Ascon-Based
//! Lightweight Cryptography Standards for Constrained Devices"), all built on a
//! single 320-bit permutation:
//!
//! - [`AsconAead128`] — the Ascon-AEAD128 authenticated-encryption scheme
//!   (128-bit key, nonce, and tag; 128-bit security strength).
//! - [`AsconHash256`] — the Ascon-Hash256 hash function (256-bit digest).
//! - [`AsconXof128`] — the Ascon-XOF128 extendable-output function.
//! - [`AsconCxof128`] — the Ascon-CXOF128 customized XOF, which absorbs a
//!   customization string for domain separation.
//!
//! # Standard, not the v1.2 submission
//!
//! These are the **final SP 800-232** parameters, which differ from the earlier
//! Ascon v1.2 / NIST-LWC submission: the initialization values were changed,
//! the byte order is little-endian, Ascon-AEAD128 uses a 128-bit rate, and
//! Ascon-CXOF128 was added. Implementations and test vectors validated against
//! the v1.2 spec will **not** match this module.
//!
//! Correctness is checked against the official NIST SP 800-232 known-answer
//! tests (from the Ascon reference repository) for every function.

mod aead;
mod hash;
mod permutation;

pub use aead::AsconAead128;
pub use hash::{AsconCxof128, AsconHash256, AsconXof128, AsconXofReader};
