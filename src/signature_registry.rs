//! A registry of digital-signature algorithms, and a whitelist policy
//! controlling which algorithms a verifier accepts.
//!
//! `purecrypto`'s X.509 chain validation and TLS 1.3 `CertificateVerify` paths
//! used to each carry a hand-rolled `match` on the algorithm identifier (an
//! OID for X.509, a `SignatureScheme` code point for TLS). The two switches
//! duplicated dispatch logic and only handled the subset they were wired for.
//!
//! This module replaces both with a single static table — `ALGORITHMS` — of
//! `SignatureAlgorithm` trait objects. Each entry knows
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
//! # Whitelist policy
//!
//! `SignaturePolicy` (requires `alloc`) enforces a strict **whitelist**:
//! adding an algorithm to `ALGORITHMS` does NOT auto-permit it; the caller
//! has to add the id explicitly. The shipped default
//! `SignaturePolicy::modern` permits the modern IANA-blessed set —
//! RSA-PSS-RSAE / RSA-PKCS1 with SHA-256/384, ECDSA, Ed25519/Ed448, and
//! ML-DSA — with RSA keys ≥ 2048 bits. For ECDSA the two dispatch paths
//! differ: X.509 chain signatures are keyed by the signature OID
//! (`ecdsa-with-sha256/384/512`), which does not pin a curve, so any
//! supported curve (P-256 / P-384 / P-521 / secp256k1) is accepted with the
//! OID's hash; the matched-curve / matched-hash restriction over
//! P-256/P-384/P-521 applies to TLS 1.3 `CertificateVerify` scheme dispatch.

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
    // Legacy SHA-1 / RSA — opt-in only.
    #[cfg(all(feature = "rsa", feature = "alloc"))]
    &crate::rsa::registry::Pkcs1Sha1,
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
    // RSA-PSS with a PSS-key-restricted SPKI (`id-RSASSA-PSS`).
    #[cfg(all(feature = "rsa", feature = "alloc"))]
    &crate::rsa::registry::PssPssSha256,
    // OID-keyed ECDSA entries (X.509 chain dispatch).
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaSha256AnyCurve,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaSha384AnyCurve,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaSha512AnyCurve,
    // Strict curve/hash-pair ECDSA entries (TLS scheme dispatch, fine-grained
    // policy whitelisting). Matched-pair entries carry an IANA TLS scheme;
    // cross-hash and secp256k1 entries have none and are policy-only.
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaP256Sha256,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaP384Sha384,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaP521Sha512,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaP256Sha384,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaP256Sha512,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaP384Sha256,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaP384Sha512,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaP521Sha256,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaP521Sha384,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaSecp256k1Sha256,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaSecp256k1Sha384,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaSecp256k1Sha512,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::Ed25519,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::Ed448,
    // SM2 (GB/T 32918.2, RFC 8998) — not on modern(); explicit opt-in.
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::Sm2WithSm3,
    #[cfg(all(feature = "mldsa", feature = "alloc"))]
    &crate::mldsa::registry::MlDsa44,
    #[cfg(all(feature = "mldsa", feature = "alloc"))]
    &crate::mldsa::registry::MlDsa65,
    #[cfg(all(feature = "mldsa", feature = "alloc"))]
    &crate::mldsa::registry::MlDsa87,
    // SLH-DSA (FIPS 205) × 12 parameter sets. None are on `modern()`;
    // explicit opt-in (signatures are 7–50 KB).
    #[cfg(all(feature = "slhdsa", feature = "alloc"))]
    &crate::slhdsa::registry::SlhDsaSha2128s,
    #[cfg(all(feature = "slhdsa", feature = "alloc"))]
    &crate::slhdsa::registry::SlhDsaSha2128f,
    #[cfg(all(feature = "slhdsa", feature = "alloc"))]
    &crate::slhdsa::registry::SlhDsaSha2192s,
    #[cfg(all(feature = "slhdsa", feature = "alloc"))]
    &crate::slhdsa::registry::SlhDsaSha2192f,
    #[cfg(all(feature = "slhdsa", feature = "alloc"))]
    &crate::slhdsa::registry::SlhDsaSha2256s,
    #[cfg(all(feature = "slhdsa", feature = "alloc"))]
    &crate::slhdsa::registry::SlhDsaSha2256f,
    #[cfg(all(feature = "slhdsa", feature = "alloc"))]
    &crate::slhdsa::registry::SlhDsaShake128s,
    #[cfg(all(feature = "slhdsa", feature = "alloc"))]
    &crate::slhdsa::registry::SlhDsaShake128f,
    #[cfg(all(feature = "slhdsa", feature = "alloc"))]
    &crate::slhdsa::registry::SlhDsaShake192s,
    #[cfg(all(feature = "slhdsa", feature = "alloc"))]
    &crate::slhdsa::registry::SlhDsaShake192f,
    #[cfg(all(feature = "slhdsa", feature = "alloc"))]
    &crate::slhdsa::registry::SlhDsaShake256s,
    #[cfg(all(feature = "slhdsa", feature = "alloc"))]
    &crate::slhdsa::registry::SlhDsaShake256f,
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

#[cfg(feature = "alloc")]
mod policy {
    use super::{SignatureAlgorithm, find_by_id};
    use alloc::vec::Vec;

    /// Compares two `&dyn SignatureAlgorithm` references for logical equality.
    /// Pointer-identity is unreliable here: every registry entry is a
    /// zero-sized type, and Rust does not guarantee distinct ZSTs have
    /// distinct data-pointers. Using `id()` (a stable, unique string) is
    /// both portable and matches the user-visible whitelist key.
    fn algo_eq(a: &dyn SignatureAlgorithm, b: &dyn SignatureAlgorithm) -> bool {
        a.id() == b.id()
    }

    /// Whitelist policy controlling which signature algorithms a verifier
    /// accepts. Adding an algorithm to [`super::ALGORITHMS`] does NOT
    /// auto-permit it; the caller must explicitly add it here with
    /// [`Self::permit`].
    ///
    /// The shipped default — [`SignaturePolicy::modern`] — accepts exactly the
    /// modern IANA-blessed set: RSA-PKCS1 / RSA-PSS-RSAE with SHA-256/384/512,
    /// ECDSA (any supported curve for X.509 chain signatures; matched
    /// curve/hash pairs over P-256/P-384/P-521 for TLS 1.3
    /// `CertificateVerify`), Ed25519, and Ed448. RSA keys must be at least
    /// 2048 bits.
    #[derive(Clone)]
    pub struct SignaturePolicy {
        permitted: Vec<&'static dyn SignatureAlgorithm>,
        /// Minimum acceptable RSA modulus length, in bits.
        pub min_rsa_bits: u32,
    }

    impl SignaturePolicy {
        /// The shipped default whitelist: modern IANA-blessed signature
        /// algorithms, RSA ≥ 2048 bits.
        ///
        /// Permitted ids:
        ///   * `rsa-pkcs1-sha256`, `rsa-pkcs1-sha384`
        ///   * `rsa-pss-rsae-sha256`, `rsa-pss-rsae-sha384`, `rsa-pss-rsae-sha512`
        ///   * `ecdsa-with-sha256`, `ecdsa-with-sha384`, `ecdsa-with-sha512`
        ///     — the OID-keyed X.509 chain-dispatch entries. The
        ///     `ecdsa-with-SHA-N` OID does not pin a curve, so these accept
        ///     **any supported curve** (P-256, P-384, P-521, or secp256k1)
        ///     with the OID's hash.
        ///   * `ecdsa-secp256r1-sha256`, `ecdsa-secp384r1-sha384`,
        ///     `ecdsa-secp521r1-sha512` — the TLS 1.3 `CertificateVerify`
        ///     scheme-dispatch entries; this is where the matched-curve /
        ///     matched-hash restriction applies.
        ///   * `ed25519`, `ed448`
        ///   * `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` (NIST FIPS 204)
        ///
        /// Note the asymmetry for ECDSA: an X.509 chain signature over
        /// secp256k1 (or any supported-curve / SHA-256-384-512 combination)
        /// verifies under this policy via the OID-keyed entries; only the
        /// TLS 1.3 `CertificateVerify` path is limited to the matched pairs
        /// above.
        ///
        /// Everything else in [`super::ALGORITHMS`] (SHA-1 RSA, the
        /// scheme-less secp256k1 / cross-hash ECDSA pair entries, SLH-DSA,
        /// …) is one-line opt-in via [`Self::permit`].
        pub fn modern() -> Self {
            let permitted_ids = [
                "rsa-pkcs1-sha256",
                "rsa-pkcs1-sha384",
                "rsa-pss-rsae-sha256",
                "rsa-pss-rsae-sha384",
                "rsa-pss-rsae-sha512",
                // X.509-chain dispatch entries (OID-keyed; any supported curve).
                // The matched-pair entries below pin the curve for TLS 1.3
                // CertificateVerify (one per IANA scheme code point).
                "ecdsa-with-sha256",
                "ecdsa-with-sha384",
                "ecdsa-with-sha512",
                "ecdsa-secp256r1-sha256",
                "ecdsa-secp384r1-sha384",
                "ecdsa-secp521r1-sha512",
                "ed25519",
                "ed448",
                "ml-dsa-44",
                "ml-dsa-65",
                "ml-dsa-87",
            ];
            let mut permitted = Vec::new();
            for id in permitted_ids {
                if let Some(algo) = find_by_id(id) {
                    permitted.push(algo);
                }
            }
            SignaturePolicy {
                permitted,
                min_rsa_bits: 2048,
            }
        }

        /// An empty policy — accepts nothing. Build it up by chaining
        /// [`SignaturePolicy::permit`].
        pub fn empty() -> Self {
            SignaturePolicy {
                permitted: Vec::new(),
                min_rsa_bits: 2048,
            }
        }

        /// Adds an algorithm by id, looking it up in [`super::ALGORITHMS`].
        /// Ignores unknown ids and duplicates.
        pub fn permit(mut self, id: &str) -> Self {
            if let Some(algo) = find_by_id(id)
                && !self.permitted.iter().any(|a| algo_eq(*a, algo))
            {
                self.permitted.push(algo);
            }
            self
        }

        /// Overrides the RSA-modulus-bit floor.
        pub fn with_min_rsa_bits(mut self, bits: u32) -> Self {
            self.min_rsa_bits = bits;
            self
        }

        /// `true` if `algo` is on the whitelist and `spki`'s parameters meet
        /// any extra constraints (today only the `min_rsa_bits` check).
        pub fn permits(&self, algo: &dyn SignatureAlgorithm, spki: &[u8]) -> bool {
            if !self.permitted.iter().any(|a| algo_eq(*a, algo)) {
                return false;
            }
            if let Some(bits) = algo.rsa_modulus_bits(spki)
                && bits < self.min_rsa_bits
            {
                return false;
            }
            true
        }
    }

    impl Default for SignaturePolicy {
        fn default() -> Self {
            Self::modern()
        }
    }
}

#[cfg(feature = "alloc")]
pub use policy::SignaturePolicy;

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
        // X.509 OID for ecdsa-with-SHA256 dispatches through the OID-keyed
        // any-curve entry (the strict pair entries have no X.509 OIDs).
        let algo = find_by_oid(&[1, 2, 840, 10045, 4, 3, 2]).expect("ecdsa-with-SHA256");
        assert_eq!(algo.id(), "ecdsa-with-sha256");
        // TLS scheme for ecdsa_secp256r1_sha256 dispatches through the strict
        // pair entry.
        let algo = find_by_tls_scheme(0x0403).expect("ecdsa_secp256r1_sha256");
        assert_eq!(algo.id(), "ecdsa-secp256r1-sha256");
        // TLS scheme for rsa_pss_rsae_sha256.
        let algo = find_by_tls_scheme(0x0804).expect("rsa_pss_rsae_sha256");
        assert_eq!(algo.id(), "rsa-pss-rsae-sha256");
    }

    #[cfg(all(feature = "rsa", feature = "ec", feature = "alloc"))]
    #[test]
    fn modern_policy_permits_default_set() {
        let policy = SignaturePolicy::modern();
        for id in [
            "rsa-pkcs1-sha256",
            "rsa-pkcs1-sha384",
            "rsa-pss-rsae-sha256",
            "rsa-pss-rsae-sha384",
            "rsa-pss-rsae-sha512",
            "ecdsa-secp256r1-sha256",
            "ecdsa-secp384r1-sha384",
            "ecdsa-secp521r1-sha512",
            "ed25519",
        ] {
            let algo = find_by_id(id).unwrap();
            assert!(policy.permits(algo, &[]), "modern() should permit {id}");
        }
    }

    #[cfg(all(feature = "ec", feature = "alloc"))]
    #[test]
    fn empty_policy_permits_nothing_until_opt_in() {
        let algo = find_by_id("ed25519").unwrap();
        let policy = SignaturePolicy::empty();
        assert!(!policy.permits(algo, &[]));
        let policy = policy.permit("ed25519");
        assert!(policy.permits(algo, &[]));
    }

    #[cfg(all(feature = "rsa", feature = "alloc"))]
    #[test]
    fn min_rsa_bits_floor_rejects_small_keys() {
        use crate::x509::AnyPublicKey;
        let key = crate::test_util::rsa_test_key_a();
        let pk = key.public_key();
        let mut n = [0u8; 256];
        pk.modulus().write_be_bytes(&mut n);
        let mut e = [0u8; 256];
        pk.exponent().write_be_bytes(&mut e);
        let boxed = crate::rsa::BoxedRsaPublicKey::new(
            crate::bignum::BoxedUint::from_be_bytes(&n),
            crate::bignum::BoxedUint::from_be_bytes(&e),
        );
        let spki = AnyPublicKey::Rsa(boxed).to_spki_der();

        let algo = find_by_id("rsa-pkcs1-sha256").unwrap();
        // 2048-bit key permitted under default min.
        assert!(SignaturePolicy::modern().permits(algo, &spki));
        // Asking for ≥ 4096 bits rejects a 2048-bit key.
        let strict = SignaturePolicy::modern().with_min_rsa_bits(4096);
        assert!(!strict.permits(algo, &spki));
    }
}
