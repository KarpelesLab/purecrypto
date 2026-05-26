//! A registry of digital-signature algorithms.
//!
//! `purecrypto`'s X.509 chain validation and TLS 1.3 `CertificateVerify` paths
//! used to each carry a hand-rolled `match` on the algorithm identifier (an
//! OID for X.509, a `SignatureScheme` code point for TLS). The two switches
//! duplicated dispatch logic and only handled the subset they were wired for.
//!
//! This module replaces both with a single static table — [`ALGORITHMS`] — of
//! [`SignatureAlgorithm`] trait objects. Each entry knows
//!   * a stable string id (e.g. `"ecdsa-secp256r1-sha256"`) for policy
//!     whitelisting,
//!   * the X.509 `AlgorithmIdentifier` OIDs it matches (a single algorithm
//!     may match several),
//!   * the TLS 1.3 `SignatureScheme` code points it implements (often empty),
//!   * a `verify(spki, message, signature)` method that parses the
//!     `SubjectPublicKeyInfo` DER, recovers the key, and verifies.
//!
//! The slice is small (≈10–20 entries) and linear scans cost a few nanoseconds
//! — dwarfed by the actual asymmetric verification. There is no `HashMap`, no
//! `OnceLock`, no init order: the registry is `&'static` and works in
//! `no_std`.
//!
//! A future commit layers a whitelist [`SignaturePolicy`](unspecified) on top.
//! Today this module is only the dispatch surface; the default acceptance set
//! is preserved by the call sites that route through it (today, exactly the
//! pre-registry set).

use crate::x509::Error;

// The module is gated behind `x509` at the crate root: it returns
// `x509::Error` and the per-primitive impls re-use the SPKI parsers in
// `src/x509/pubkey.rs`. Without `x509`, none of these types exist.

/// A signature algorithm purecrypto can verify.
///
/// Implementors are zero-sized types in `src/{rsa,ec,mldsa,slhdsa}/registry.rs`
/// that delegate to the primitive's existing `verify` method after parsing the
/// `SubjectPublicKeyInfo` to recover the key.
pub trait SignatureAlgorithm: Sync + 'static {
    /// Stable identifier for whitelisting (e.g. `"ecdsa-secp256r1-sha256"`).
    fn id(&self) -> &'static str;

    /// X.509 signature `AlgorithmIdentifier` OIDs that map to this entry. A
    /// single algorithm may match multiple OIDs (legacy aliases); the slice
    /// is non-empty for any algorithm reachable from an X.509 chain.
    fn x509_oids(&self) -> &'static [&'static [u64]];

    /// TLS 1.3 `SignatureScheme` code points (RFC 8446 §4.2.3) for this
    /// entry. May be empty (e.g. SLH-DSA, only useful in chains).
    fn tls_schemes(&self) -> &'static [u16];

    /// Verifies `signature` over `message` under `spki` (the full
    /// `SubjectPublicKeyInfo` DER, so curve / key parameters travel with the
    /// key).
    fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error>;

    /// For policy decisions: RSA modulus length in bits. `None` for non-RSA
    /// algorithms.
    fn rsa_modulus_bits(&self, _spki: &[u8]) -> Option<u32> {
        None
    }
}

/// All signature algorithms purecrypto knows. Lookups are linear; the slice
/// is small so this is cheap.
pub static ALGORITHMS: &[&'static dyn SignatureAlgorithm] = &[
    #[cfg(all(feature = "rsa", feature = "alloc"))]
    &crate::rsa::registry::Pkcs1Sha256,
    #[cfg(all(feature = "rsa", feature = "alloc"))]
    &crate::rsa::registry::Pkcs1Sha384,
    #[cfg(all(feature = "rsa", feature = "alloc"))]
    &crate::rsa::registry::Pkcs1Sha512,
    #[cfg(all(feature = "rsa", feature = "alloc"))]
    &crate::rsa::registry::PssRsaeSha256,
    #[cfg(all(feature = "rsa", feature = "alloc"))]
    &crate::rsa::registry::PssRsaeSha384,
    #[cfg(all(feature = "rsa", feature = "alloc"))]
    &crate::rsa::registry::PssRsaeSha512,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaP256Sha256,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaP384Sha384,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaP521Sha512,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::Ed25519,
];

/// Looks up a registry entry by X.509 `AlgorithmIdentifier` OID arcs.
pub fn find_by_oid(oid: &[u64]) -> Option<&'static dyn SignatureAlgorithm> {
    for algo in ALGORITHMS {
        for entry in algo.x509_oids() {
            if *entry == oid {
                return Some(*algo);
            }
        }
    }
    None
}

/// Looks up a registry entry by TLS 1.3 `SignatureScheme` code point.
pub fn find_by_tls_scheme(scheme: u16) -> Option<&'static dyn SignatureAlgorithm> {
    for algo in ALGORITHMS {
        for entry in algo.tls_schemes() {
            if *entry == scheme {
                return Some(*algo);
            }
        }
    }
    None
}

/// Looks up a registry entry by its stable identifier.
pub fn find_by_id(id: &str) -> Option<&'static dyn SignatureAlgorithm> {
    for algo in ALGORITHMS {
        if algo.id() == id {
            return Some(*algo);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "rsa", feature = "ec", feature = "alloc"))]
    #[test]
    fn registry_has_modern_entries() {
        assert!(find_by_id("rsa-pkcs1-sha256").is_some());
        assert!(find_by_id("rsa-pss-rsae-sha256").is_some());
        assert!(find_by_id("ecdsa-secp256r1-sha256").is_some());
        assert!(find_by_id("ecdsa-secp384r1-sha384").is_some());
        assert!(find_by_id("ecdsa-secp521r1-sha512").is_some());
        assert!(find_by_id("ed25519").is_some());
    }

    #[cfg(all(feature = "rsa", feature = "ec", feature = "alloc"))]
    #[test]
    fn lookup_by_oid_and_scheme() {
        // X.509 OID for ecdsa-with-SHA256.
        let algo = find_by_oid(&[1, 2, 840, 10045, 4, 3, 2]).expect("ecdsa-with-SHA256");
        assert_eq!(algo.id(), "ecdsa-secp256r1-sha256");
        // TLS scheme for rsa_pss_rsae_sha256.
        let algo = find_by_tls_scheme(0x0804).expect("rsa_pss_rsae_sha256");
        assert_eq!(algo.id(), "rsa-pss-rsae-sha256");
    }
}
