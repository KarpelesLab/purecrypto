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

#[cfg(feature = "bignum")]
pub mod bignum;

#[cfg(feature = "cipher")]
pub mod cipher;

#[cfg(feature = "der")]
pub mod der;

#[cfg(feature = "ec")]
pub mod ec;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "hash")]
pub mod hash;

#[cfg(feature = "kdf")]
pub mod kdf;

#[cfg(feature = "mlkem")]
pub mod mlkem;

#[cfg(feature = "rng")]
pub mod rng;

#[cfg(feature = "rsa")]
pub mod rsa;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "x509")]
pub mod x509;

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
            let lo = (bytes[2 * i + 1] as char)
                .to_digit(16)
                .expect("invalid hex") as u8;
            out[i] = (hi << 4) | lo;
            i += 1;
        }
        out
    }

    /// Decodes a hex string (ignoring ASCII whitespace) into a byte vector,
    /// for variable-length fixtures such as the RFC 8448 record traces.
    #[cfg(feature = "alloc")]
    pub(crate) fn from_hex_vec(s: &str) -> alloc::vec::Vec<u8> {
        let digits: alloc::vec::Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        assert_eq!(digits.len() % 2, 0, "hex string has odd length");
        digits
            .chunks(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).expect("invalid hex") as u8;
                let lo = (pair[1] as char).to_digit(16).expect("invalid hex") as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    /// A fixed 2048-bit RSA test key (32 limbs), parsed from an embedded
    /// PKCS#1 PEM fixture. Avoids per-test key generation while keeping tests
    /// at a realistic key size.
    #[cfg(all(feature = "rsa", feature = "der", feature = "alloc"))]
    pub(crate) fn rsa_test_key_a() -> crate::rsa::RsaPrivateKey<32> {
        crate::rsa::RsaPrivateKey::from_pkcs1_pem(include_str!("../testdata/rsa2048_test_a.pem"))
            .expect("parse RSA-2048 test key A")
    }

    /// A second, distinct 2048-bit RSA test key.
    #[cfg(all(feature = "rsa", feature = "der", feature = "alloc"))]
    pub(crate) fn rsa_test_key_b() -> crate::rsa::RsaPrivateKey<32> {
        crate::rsa::RsaPrivateKey::from_pkcs1_pem(include_str!("../testdata/rsa2048_test_b.pem"))
            .expect("parse RSA-2048 test key B")
    }
}
