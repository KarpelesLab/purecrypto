//! RSA.
//!
//! Built on the constant-time [`bignum`](crate::bignum) layer and the
//! [`rng`](crate::rng) CSPRNG. This module currently provides the
//! number-theoretic groundwork — primality testing and prime generation; key
//! types, key generation, and PKCS#1 operations are layered on top.

mod keys;
mod prime;

pub use keys::{RsaPrivateKey, RsaPublicKey};
pub use prime::{is_prime, random_prime};
