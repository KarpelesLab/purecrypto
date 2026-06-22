//! Key-derivation functions.
//!
//!  - [`pbkdf2`] — RFC 8018, generic over any HMAC PRF.
//!  - [`hkdf`]   — RFC 5869, extract / expand / one-shot.
//!  - [`kbkdf_counter`] / [`kbkdf_feedback`] — NIST SP 800-108r1 key-based KDF,
//!    counter and feedback modes, over an HMAC or AES-CMAC [`Prf`].
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
mod kbkdf;
#[cfg(all(feature = "alloc", feature = "der"))]
pub mod pbes2;
mod pbkdf2;
#[cfg(feature = "alloc")]
pub mod scrypt;

#[cfg(feature = "alloc")]
pub use bcrypt_pbkdf::{Error as BcryptPbkdfError, bcrypt_pbkdf};
pub use hkdf::{Error as HkdfError, hkdf, hkdf_expand, hkdf_extract, try_hkdf_expand};
pub use kbkdf::{
    CmacAes128Prf, CmacAes256Prf, Error as KbkdfError, HmacPrf, HmacSha256Prf, HmacSha384Prf,
    HmacSha512Prf, Prf, kbkdf_counter, kbkdf_counter_fixed, kbkdf_feedback, kbkdf_feedback_fixed,
};
pub use pbkdf2::pbkdf2;
