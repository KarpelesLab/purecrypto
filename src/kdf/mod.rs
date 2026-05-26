//! Key-derivation functions.
//!
//!  - [`pbkdf2`] — RFC 8018, generic over any HMAC PRF.
//!  - [`hkdf`]   — RFC 5869, extract / expand / one-shot.
//!  - [`scrypt`] — RFC 7914, memory-hard PBKDF (requires `alloc`).

mod hkdf;
mod pbkdf2;
#[cfg(feature = "alloc")]
pub mod scrypt;

pub use hkdf::{hkdf, hkdf_expand, hkdf_extract};
pub use pbkdf2::pbkdf2;
