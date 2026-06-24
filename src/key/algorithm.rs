//! Algorithm and operation discriminants for the unified key traits.

/// Identifies the algorithm (and, where it matters, the curve / parameter set)
/// behind a [`PrivateKey`](crate::key::PrivateKey) or
/// [`PublicKey`](crate::key::PublicKey).
///
/// Used for introspection and to check compatibility before a key-agreement —
/// `make_secret` rejects a peer whose `Algorithm` does not match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// RSA (any modulus size).
    Rsa,
    /// ECDSA / ECDH over NIST P-256 (secp256r1).
    P256,
    /// ECDSA / ECDH over NIST P-384 (secp384r1).
    P384,
    /// ECDSA / ECDH over NIST P-521 (secp521r1).
    P521,
    /// ECDSA / ECDH over secp256k1.
    Secp256k1,
    /// Ed25519 (RFC 8032).
    Ed25519,
    /// Ed448 (RFC 8032).
    Ed448,
    /// X25519 key agreement (RFC 7748).
    X25519,
    /// X448 key agreement (RFC 7748).
    X448,
    /// SM2 (GB/T 32918) signatures and public-key encryption.
    Sm2,
    /// Finite-field Diffie-Hellman over an RFC 3526 MODP group.
    DhModp,
    /// ML-DSA-44 (FIPS 204).
    MlDsa44,
    /// ML-DSA-65 (FIPS 204).
    MlDsa65,
    /// ML-DSA-87 (FIPS 204).
    MlDsa87,
    /// SLH-DSA (FIPS 205), any parameter set.
    SlhDsa,
    /// Falcon-512 (FN-DSA, FIPS 206 draft).
    Falcon512,
    /// Falcon-1024 (FN-DSA, FIPS 206 draft).
    Falcon1024,
    /// XMSS single-tree (RFC 8391).
    Xmss,
    /// XMSS^MT multi-tree (RFC 8391).
    XmssMt,
    /// LMS (RFC 8554).
    Lms,
    /// HSS hierarchical LMS (RFC 8554).
    Hss,
    /// ML-KEM-512 (FIPS 203).
    MlKem512,
    /// ML-KEM-768 (FIPS 203).
    MlKem768,
    /// ML-KEM-1024 (FIPS 203).
    MlKem1024,
}

/// The asymmetric operation a key was asked to perform.
///
/// Carried by [`Error::Unsupported`](crate::key::Error::Unsupported) to say
/// which operation a key does not support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Operation {
    /// Produce a signature.
    Sign,
    /// Verify a signature.
    Verify,
    /// Decrypt a ciphertext.
    Decrypt,
    /// Encrypt a plaintext.
    Encrypt,
    /// Derive a shared secret with a peer public key.
    Agree,
    /// KEM encapsulation.
    Encapsulate,
    /// KEM decapsulation.
    Decapsulate,
}

impl core::fmt::Display for Operation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Operation::Sign => "sign",
            Operation::Verify => "verify",
            Operation::Decrypt => "decrypt",
            Operation::Encrypt => "encrypt",
            Operation::Agree => "key-agreement",
            Operation::Encapsulate => "encapsulate",
            Operation::Decapsulate => "decapsulate",
        };
        f.write_str(s)
    }
}
