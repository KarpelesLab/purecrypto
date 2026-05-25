//! `purecrypto` — a cryptography toolkit written entirely in Rust, depending on
//! no foreign code.
//!
//! The crate is built in layers, from the bottom up:
//!
//! 1. **Constant-time primitives** ([`ct`]) — branchless boolean logic,
//!    equality, selection and ordering. Everything secret-dependent rests on
//!    this layer.
//! 2. Hashing, symmetric ciphers, constant-time bignum arithmetic, asymmetric
//!    keys (RSA, ECDSA, Ed25519, ML-KEM), ASN.1, X.509, and TLS/DTLS — added
//!    on top as the project grows.
//!
//! `purecrypto` is usable as a Rust library, a C library, and a standalone
//! command-line tool.
//!
//! # `no_std`
//!
//! The crate is `#![no_std]` at its core. The `alloc` feature pulls in the
//! `alloc` crate for heap-backed types, and the `std` feature (enabled by
//! default, implies `alloc`) adds the pieces that genuinely need the operating
//! system, such as file I/O, the CLI, and system randomness. Build with
//! `--no-default-features` for a bare `no_std` target.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod ct;

#[cfg(feature = "cipher")]
pub mod cipher;

#[cfg(feature = "hash")]
pub mod hash;

/// Shared test-only helpers.
#[cfg(test)]
pub(crate) mod test_util {
    /// Decodes a hex string into a fixed-size byte array.
    pub(crate) fn from_hex<const N: usize>(s: &str) -> [u8; N] {
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 2 * N, "hex string has wrong length");
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            let hi = (bytes[2 * i] as char).to_digit(16).expect("invalid hex") as u8;
            let lo = (bytes[2 * i + 1] as char).to_digit(16).expect("invalid hex") as u8;
            out[i] = (hi << 4) | lo;
            i += 1;
        }
        out
    }
}
