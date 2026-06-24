//! Finite-field Diffie-Hellman over RFC 3526 MODP safe-prime groups,
//! and RFC 4419 group-exchange (caller-supplied custom group).
//!
//! For interop with SSH (`diffie-hellman-group14-sha256`,
//! `diffie-hellman-group16-sha512`, `diffie-hellman-group-exchange-sha256`),
//! legacy TLS (ciphersuites with `DHE_RSA` / `DHE_DSS`), and IKE peers that
//! don't speak ECDH. For new code, prefer the elliptic-curve DH API in
//! [`crate::ec`] — finite-field DH is here for compatibility, not because
//! the security margin is better.
//!
//! # Quick start
//!
//! ```ignore
//! use purecrypto::dh::{DhPrivateKey, group14};
//! use purecrypto::rng::OsRng;
//!
//! let mut rng = OsRng;
//! let alice = DhPrivateKey::generate(group14(), &mut rng);
//! let alice_pub = alice.public_key();
//! // ... send alice_pub.to_bytes() to Bob, receive bob_pub_bytes back ...
//! # let bob = DhPrivateKey::generate(group14(), &mut rng);
//! # let bob_pub_bytes = bob.public_key().to_bytes();
//! let bob_pub = purecrypto::dh::DhPublicKey::from_bytes(
//!     purecrypto::dh::group14(),
//!     &bob_pub_bytes,
//! )?;
//! let shared = alice.shared_secret(&bob_pub)?;
//! // Hash `shared.as_bytes()` (SHA-256 for group14, SHA-512 for group16+).
//! # Ok::<_, purecrypto::dh::Error>(())
//! ```
//!
//! # Validation
//!
//! [`DhPublicKey::from_bytes`] and [`DhPrivateKey::shared_secret`] both
//! enforce the standard subgroup-confinement check `2 ≤ y < p - 1`, and
//! the shared secret is screened against the contributory-failure values
//! `0` and `1` (NIST SP 800-56A §5.6.2.3).

pub mod groups;
mod key;
#[cfg(feature = "key")]
mod key_impl;

pub use groups::{DhGroup, group14, group15, group16, group17, group18};
pub use key::{DhPrivateKey, DhPublicKey, Error, SharedSecret};
