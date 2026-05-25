//! Key-derivation functions.
//!
//! Currently provides [`pbkdf2`], the password-based KDF of RFC 8018, generic
//! over any HMAC PRF.

mod hkdf;
mod pbkdf2;

pub use hkdf::{hkdf, hkdf_expand, hkdf_extract};
pub use pbkdf2::pbkdf2;
