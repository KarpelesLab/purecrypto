//! Key-derivation functions.
//!
//!  - [`pbkdf2`] — RFC 8018, generic over any HMAC PRF.
//!  - [`hkdf`]   — RFC 5869, extract / expand / one-shot.
//!  - [`kbkdf_counter`] / [`kbkdf_feedback`] — NIST SP 800-108r1 key-based KDF,
//!    counter and feedback modes, over an HMAC or AES-CMAC [`Prf`].
//!  - [`scrypt`] — RFC 7914, memory-hard PBKDF (requires `alloc`).
//!  - [`bcrypt_pbkdf`] — OpenSSH's PBKDF over Blowfish, used to protect
//!    new-format SSH private keys (requires `alloc`).
//!  - [`concat_kdf`] — NIST SP 800-56A §5.8.1 single-step (Concatenation)
//!    KDF, used by JOSE `ECDH-ES`.
#![cfg_attr(
    not(feature = "alloc"),
    doc = "",
    doc = "[`scrypt`]: crate#no_std",
    doc = "[`bcrypt_pbkdf`]: crate#no_std"
)]

#[cfg(feature = "alloc")]
pub mod argon2;
// The bcrypt_pbkdf module is kept private so the natural `kdf::bcrypt_pbkdf`
// path resolves to the function below rather than the module (otherwise the
// module name shadows the fn at call sites). Error type re-exported as
// BcryptPbkdfError.
#[cfg(feature = "alloc")]
mod bcrypt_pbkdf;
mod concat;
mod hkdf;
mod kbkdf;
#[cfg(all(feature = "alloc", feature = "der", feature = "rng"))]
pub mod pbes2;
mod pbkdf2;
#[cfg(feature = "alloc")]
pub mod scrypt;

#[cfg(feature = "alloc")]
pub use bcrypt_pbkdf::{Error as BcryptPbkdfError, bcrypt_pbkdf};
pub use concat::{Error as ConcatKdfError, concat_kdf};
pub use hkdf::{
    Error as HkdfError, hkdf, hkdf_expand, hkdf_extract, hkdf_extract_parts, try_hkdf,
    try_hkdf_expand, try_hkdf_expand_parts,
};
pub use kbkdf::{
    CmacAes128Prf, CmacAes256Prf, Error as KbkdfError, HmacPrf, HmacSha256Prf, HmacSha384Prf,
    HmacSha512Prf, Prf, kbkdf_counter, kbkdf_counter_fixed, kbkdf_feedback, kbkdf_feedback_fixed,
};
pub use pbkdf2::{Error as Pbkdf2Error, pbkdf2, try_pbkdf2};

/// Best-effort wipe of a secret buffer via [`crate::zeroize::Zeroize`]
/// (volatile stores plus a compiler fence, so the writes are not elided as
/// dead stores).
#[inline]
pub(crate) fn wipe(buf: &mut [u8]) {
    crate::zeroize::Zeroize::zeroize(buf);
}
