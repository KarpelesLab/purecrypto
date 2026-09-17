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
//! RSA-PSS-RSAE / RSA-PSS-PSS / RSA-PKCS1 with SHA-256/384, ECDSA,
//! Ed25519/Ed448, and ML-DSA — with RSA keys ≥ 2048 bits. For ECDSA the two dispatch paths
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
    /// key), with the entry's default parameters — for the RSA-PSS entries,
    /// the TLS 1.3 profile (MGF1 over the entry's digest, salt as long as
    /// the digest).
    fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error>;

    /// Like [`verify`](Self::verify), but with the parameters an X.509
    /// signature `AlgorithmIdentifier` carried
    /// ([`SignatureParams`](crate::x509::SignatureParams)).
    ///
    /// Only RSASSA-PSS has parameters that matter (RFC 4055 §3.1): the
    /// `rsa-pss-*` entries verify with the signature's MGF1 digest (any
    /// SHA-2, equal to the message digest or not — RFC 8017 §8.1) and salt
    /// length, after checking that its message digest is the entry's and
    /// its trailer field is 1. Every other entry accepts
    /// [`SignatureParams::None`](crate::x509::SignatureParams::None) only
    /// (the default implementation), and every entry refuses parameters
    /// meant for another algorithm with [`Error::UnsupportedAlgorithm`].
    fn verify_with_params(
        &self,
        spki: &[u8],
        message: &[u8],
        signature: &[u8],
        params: crate::x509::SignatureParams,
    ) -> Result<(), Error> {
        match params {
            crate::x509::SignatureParams::None => self.verify(spki, message, signature),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }

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
    // RSA-PSS with a PSS-key-restricted SPKI (`id-RSASSA-PSS`), one entry
    // per SHA-2 digest. None carries an X.509 OID: `id-RSASSA-PSS` does not
    // name a digest by itself, so `AnyPublicKey::signature_algorithm` routes
    // an `id-RSASSA-PSS` signature to the entry for the digest its
    // `RSASSA-PSS-params` name.
    #[cfg(all(feature = "rsa", feature = "alloc"))]
    &crate::rsa::registry::PssPssSha256,
    #[cfg(all(feature = "rsa", feature = "alloc"))]
    &crate::rsa::registry::PssPssSha384,
    #[cfg(all(feature = "rsa", feature = "alloc"))]
    &crate::rsa::registry::PssPssSha512,
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
    // Brainpool (RFC 5639) matched curve/hash pairs — policy-only, no TLS scheme.
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaBrainpoolP256r1Sha256,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaBrainpoolP384r1Sha384,
    #[cfg(all(feature = "ec", feature = "alloc"))]
    &crate::ec::registry::EcdsaBrainpoolP512r1Sha512,
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
    use super::{Error, SignatureAlgorithm, find_by_id};
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
        ///   * `rsa-pss-pss-sha256`, `rsa-pss-pss-sha384`, `rsa-pss-pss-sha512`
        ///     — `id-RSASSA-PSS` chain signatures (RFC 4055), including
        ///     under a PSS-key-restricted issuer key
        ///     ([`AnyPublicKey::RsaPss`](crate::x509::AnyPublicKey::RsaPss)),
        ///     and the TLS 1.3 `rsa_pss_pss_*` `CertificateVerify` schemes
        ///     (RFC 8446 §4.2.3; only under an `id-RSASSA-PSS` SPKI)
        ///   * `ecdsa-with-sha256`, `ecdsa-with-sha384`, `ecdsa-with-sha512`
        ///     — the OID-keyed X.509 chain-dispatch entries. The
        ///     `ecdsa-with-SHA-N` OID does not pin a curve, so these accept
        ///     **any supported curve** (P-256, P-384, P-521, or secp256k1)
        ///     with the OID's hash.
        ///   * `ecdsa-secp256r1-sha256`, `ecdsa-secp384r1-sha384`,
        ///     `ecdsa-secp521r1-sha512`, and the RFC 8734 Brainpool pairs
        ///     `ecdsa-brainpoolP256r1-sha256`, `ecdsa-brainpoolP384r1-sha384`,
        ///     `ecdsa-brainpoolP512r1-sha512` — the TLS 1.3
        ///     `CertificateVerify` scheme-dispatch entries; this is where the
        ///     matched-curve / matched-hash restriction applies.
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
                "rsa-pss-pss-sha256",
                "rsa-pss-pss-sha384",
                "rsa-pss-pss-sha512",
                // X.509-chain dispatch entries (OID-keyed; any supported curve).
                // The matched-pair entries below pin the curve for TLS 1.3
                // CertificateVerify (one per IANA scheme code point).
                "ecdsa-with-sha256",
                "ecdsa-with-sha384",
                "ecdsa-with-sha512",
                "ecdsa-secp256r1-sha256",
                "ecdsa-secp384r1-sha384",
                "ecdsa-secp521r1-sha512",
                // RFC 8734: the Brainpool matched pairs have TLS 1.3 code
                // points of their own, so they are permitted like the NIST
                // pairs (chain signatures over Brainpool already were, via
                // the OID-keyed entries).
                "ecdsa-brainpoolP256r1-sha256",
                "ecdsa-brainpoolP384r1-sha384",
                "ecdsa-brainpoolP512r1-sha512",
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
        ///
        /// Because an unknown id is silently dropped, a typo in a hand-written
        /// allow-list (`"ecdsa-secp256r1-sha255"`) leaves the policy quietly
        /// narrower than intended. Use [`try_permit`](Self::try_permit) —
        /// which fails on an unknown id — whenever the id comes from
        /// configuration or user input rather than a literal in the source.
        pub fn permit(mut self, id: &str) -> Self {
            if let Some(algo) = find_by_id(id)
                && !self.permitted.iter().any(|a| algo_eq(*a, algo))
            {
                self.permitted.push(algo);
            }
            self
        }

        /// [`permit`](Self::permit) that rejects an unknown id with
        /// [`Error::UnsupportedAlgorithm`] instead of ignoring it, so a typo
        /// in an allow-list is an error rather than an invisible narrowing of
        /// the policy. Duplicates are still ignored. Prefer this for ids that
        /// come from configuration files, CLI flags, or any other user input.
        pub fn try_permit(self, id: &str) -> Result<Self, Error> {
            if find_by_id(id).is_none() {
                return Err(Error::UnsupportedAlgorithm);
            }
            Ok(self.permit(id))
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

    /// The lookups are first-match linear scans over `ALGORITHMS`, so a
    /// duplicated id, X.509 OID, or TLS scheme code point would make
    /// dispatch depend on slice order — the exact bug the PSS-RSAE entries
    /// once had when they also listed the PKCS#1 `sha*WithRSAEncryption`
    /// OIDs. Every key must be unique across the whole table, and looking an
    /// entry up by each of its own keys must return that entry.
    #[cfg(feature = "alloc")]
    #[test]
    fn registry_keys_are_unique_and_round_trip() {
        use alloc::vec::Vec;
        let mut ids: Vec<&str> = Vec::new();
        let mut oids: Vec<&[u64]> = Vec::new();
        let mut schemes: Vec<u16> = Vec::new();
        for algo in ALGORITHMS {
            let id = algo.id();
            assert!(!id.is_empty(), "empty id");
            assert!(!ids.contains(&id), "duplicate id {id}");
            ids.push(id);
            assert_eq!(find_by_id(id).unwrap().id(), id);
            for oid in algo.x509_oids() {
                assert!(!oids.contains(oid), "{id}: duplicate OID {oid:?}");
                oids.push(oid);
                assert_eq!(find_by_oid(oid).unwrap().id(), id, "OID {oid:?}");
            }
            for &scheme in algo.tls_schemes() {
                assert!(
                    !schemes.contains(&scheme),
                    "{id}: duplicate TLS scheme {scheme:#06x}"
                );
                schemes.push(scheme);
                assert_eq!(
                    find_by_tls_scheme(scheme).unwrap().id(),
                    id,
                    "scheme {scheme:#06x}"
                );
            }
        }
        // Unknown keys resolve to nothing rather than to a neighbour.
        assert!(find_by_id("").is_none());
        assert!(find_by_oid(&[]).is_none());
        assert!(find_by_oid(&[1, 2, 840, 113549, 1, 1]).is_none());
        assert!(find_by_tls_scheme(0x0000).is_none());
    }

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
        // TLS scheme for rsa_pss_pss_sha384.
        let algo = find_by_tls_scheme(0x080A).expect("rsa_pss_pss_sha384");
        assert_eq!(algo.id(), "rsa-pss-pss-sha384");
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

    /// `permit` drops an unknown id on the floor (so a typo'd allow-list is
    /// silently narrower than intended); `try_permit` reports it. Known ids
    /// behave identically on both, duplicates included.
    #[cfg(all(feature = "ec", feature = "alloc"))]
    #[test]
    fn try_permit_rejects_unknown_id() {
        let algo = find_by_id("ed25519").unwrap();
        // The silent form: the typo is invisible, the policy stays empty.
        assert!(
            !SignaturePolicy::empty()
                .permit("ed25519-typo")
                .permits(algo, &[])
        );
        assert!(matches!(
            SignaturePolicy::empty().try_permit("ed25519-typo"),
            Err(Error::UnsupportedAlgorithm)
        ));
        assert!(matches!(
            SignaturePolicy::empty().try_permit(""),
            Err(Error::UnsupportedAlgorithm)
        ));
        let policy = SignaturePolicy::empty()
            .try_permit("ed25519")
            .unwrap()
            .try_permit("ed25519")
            .unwrap();
        assert!(policy.permits(algo, &[]));
        assert!(!policy.permits(find_by_id("ed448").unwrap(), &[]));
    }

    /// Every `x509::CertSigner` variant issues a self-signed certificate
    /// whose `signatureAlgorithm` OID resolves to a registry entry that
    /// verifies the certificate under its own subject key (for
    /// `id-RSASSA-PSS`, the entry the signature's parameters select), and
    /// the default `modern()` policy's verdict on that entry is the
    /// documented one:
    /// every NIST/Ed/ML-DSA signer is permitted, secp256k1 and Brainpool
    /// chain signatures ride the OID-keyed `ecdsa-with-sha*` entries (so
    /// they are permitted too), and SLH-DSA is opt-in only.
    #[cfg(all(feature = "rsa", feature = "ec", feature = "alloc"))]
    #[test]
    fn every_cert_signer_verifies_through_registry_and_policy() {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId, Ed448PrivateKey, Ed25519PrivateKey};
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;
        use crate::rsa::BoxedRsaPrivateKey;
        use crate::x509::{CertSigner, Certificate, DistinguishedName, PssHash, Time, Validity};

        let mut rng = HmacDrbg::<Sha256>::new(b"registry-all-signers", b"nonce", &[]);
        let name = DistinguishedName::common_name("registry.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let policy = SignaturePolicy::modern();

        let rsa = crate::test_util::rsa_test_key_a();
        let rsa = BoxedRsaPrivateKey::from_pkcs1_der(&rsa.to_pkcs1_der()).unwrap();
        let ec: alloc::vec::Vec<BoxedEcdsaPrivateKey> = [
            CurveId::P256,
            CurveId::P384,
            CurveId::P521,
            CurveId::Secp256k1,
            CurveId::BrainpoolP256r1,
            CurveId::BrainpoolP384r1,
            CurveId::BrainpoolP512r1,
        ]
        .into_iter()
        .map(|c| BoxedEcdsaPrivateKey::generate(c, &mut rng))
        .collect();
        let ed25519 = Ed25519PrivateKey::generate(&mut rng);
        let ed448 = Ed448PrivateKey::generate(&mut rng);
        #[cfg(feature = "mldsa")]
        let (ml44, _) = crate::mldsa::MlDsa44PrivateKey::generate(&mut rng);
        #[cfg(feature = "mldsa")]
        let (ml65, _) = crate::mldsa::MlDsa65PrivateKey::generate(&mut rng);
        #[cfg(feature = "mldsa")]
        let (ml87, _) = crate::mldsa::MlDsa87PrivateKey::generate(&mut rng);
        #[cfg(feature = "slhdsa")]
        let (slh, _) =
            crate::slhdsa::PrivateKey::generate(crate::slhdsa::ParamSet::Sha2_128f, &mut rng);

        // (signer, registry id the signature AlgorithmIdentifier must resolve
        // to under the subject key, permitted by modern()).
        // Only pushed to under `mldsa` / `slhdsa`.
        #[allow(unused_mut)]
        let mut cases: alloc::vec::Vec<(CertSigner<'_>, &str, bool)> = alloc::vec![
            (CertSigner::Rsa(&rsa), "rsa-pkcs1-sha256", true),
            (
                CertSigner::RsaPss(&rsa, PssHash::Sha256),
                "rsa-pss-pss-sha256",
                true
            ),
            (
                CertSigner::RsaPss(&rsa, PssHash::Sha384),
                "rsa-pss-pss-sha384",
                true
            ),
            (
                CertSigner::RsaPss(&rsa, PssHash::Sha512),
                "rsa-pss-pss-sha512",
                true
            ),
            (CertSigner::Ecdsa(&ec[0]), "ecdsa-with-sha256", true),
            (CertSigner::Ecdsa(&ec[1]), "ecdsa-with-sha384", true),
            (CertSigner::Ecdsa(&ec[2]), "ecdsa-with-sha512", true),
            (CertSigner::Ecdsa(&ec[3]), "ecdsa-with-sha256", true),
            (CertSigner::Ecdsa(&ec[4]), "ecdsa-with-sha256", true),
            (CertSigner::Ecdsa(&ec[5]), "ecdsa-with-sha384", true),
            (CertSigner::Ecdsa(&ec[6]), "ecdsa-with-sha512", true),
            (CertSigner::Ed25519(&ed25519), "ed25519", true),
            (CertSigner::Ed448(&ed448), "ed448", true),
        ];
        #[cfg(feature = "mldsa")]
        {
            cases.push((CertSigner::MlDsa44(&ml44), "ml-dsa-44", true));
            cases.push((CertSigner::MlDsa65(&ml65), "ml-dsa-65", true));
            cases.push((CertSigner::MlDsa87(&ml87), "ml-dsa-87", true));
        }
        #[cfg(feature = "slhdsa")]
        cases.push((CertSigner::SlhDsa(&slh), "slh-dsa-sha2-128f", false));

        for (signer, id, permitted) in &cases {
            let cert =
                Certificate::self_signed_general(signer, &name, &validity, 1, false, &[]).unwrap();
            let subject = cert.subject_public_key().unwrap();
            // The subject key the certificate carries is the signer's key.
            assert_eq!(
                subject.to_spki_der(),
                signer.public_key().to_spki_der(),
                "{id}"
            );
            cert.verify_signature_with(&subject)
                .unwrap_or_else(|e| panic!("{id}: {e:?}"));
            let alg = cert.signature_algorithm().unwrap();
            let algo = subject
                .signature_algorithm(&alg)
                .unwrap_or_else(|| panic!("{id}: signature algorithm not in registry"));
            assert_eq!(algo.id(), *id);
            // Every OID but `id-RSASSA-PSS` (whose digest lives in the
            // parameters) also resolves by bare OID lookup.
            if alg.oid() != crate::x509::oid::ID_RSASSA_PSS {
                assert_eq!(find_by_oid(alg.oid()).unwrap().id(), *id);
            } else {
                assert!(find_by_oid(alg.oid()).is_none());
            }
            assert_eq!(
                policy.permits(algo, &subject.to_spki_der()),
                *permitted,
                "modern() verdict for {id}"
            );
            // Tampering with the TBS breaks verification through the same path.
            let mut der = cert.to_der().to_vec();
            let flip = der.len() / 2;
            der[flip] ^= 0x01;
            if let Ok(bad) = Certificate::from_der(der) {
                assert!(bad.verify_signature_with(&subject).is_err(), "{id}");
            }
        }
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
