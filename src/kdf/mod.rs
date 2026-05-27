//! Key-derivation functions.
//!
//!  - [`pbkdf2`] — RFC 8018, generic over any HMAC PRF.
//!  - [`hkdf`]   — RFC 5869, extract / expand / one-shot.
//!  - [`scrypt`] — RFC 7914, memory-hard PBKDF (requires `alloc`).
//!  - [`bcrypt_pbkdf`] — OpenSSH's PBKDF over Blowfish, used to protect
//!    new-format SSH private keys (requires `alloc`).

#[cfg(feature = "alloc")]
pub mod argon2;
// The bcrypt_pbkdf module is kept private so the natural `kdf::bcrypt_pbkdf`
// path resolves to the function below rather than the module (otherwise the
// module name shadows the fn at call sites). Error type re-exported as
// BcryptPbkdfError.
#[cfg(feature = "alloc")]
mod bcrypt_pbkdf;
mod hkdf;
#[cfg(all(feature = "alloc", feature = "der"))]
pub mod pbes2;
mod pbkdf2;
#[cfg(feature = "alloc")]
pub mod scrypt;

pub use hkdf::{hkdf, hkdf_expand, hkdf_extract};
pub use pbkdf2::pbkdf2;
#[cfg(feature = "alloc")]
pub use bcrypt_pbkdf::{Error as BcryptPbkdfError, bcrypt_pbkdf};
