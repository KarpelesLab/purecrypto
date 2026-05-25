//! Key-derivation functions.
//!
//! Currently provides [`pbkdf2`], the password-based KDF of RFC 8018, generic
//! over any HMAC PRF.

mod pbkdf2;

pub use pbkdf2::pbkdf2;
