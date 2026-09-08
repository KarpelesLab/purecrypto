//! Stapled-OCSP validation against a *verified* chain (RFC 6066 §8 /
//! RFC 8446 §4.4.2.1 / RFC 6960).
//!
//! A stapled `OCSPResponse` speaks about the end-entity certificate and is
//! signed by (or delegated from) the certificate that *issued* it. The
//! chain verifier ([`super::verify`]) closes the path at the first
//! certificate anchored by the store and discards whatever the peer sent
//! above it, so the leaf's issuer is NOT simply `chain[1]`: when the leaf
//! anchors directly on a stored root, `chain[1]` — if present — is an
//! arbitrary peer-chosen certificate nobody validated. Evaluating the staple
//! against it would let a peer holding a revoked leaf append a self-signed
//! "issuer" and staple a self-signed `good` for it (and, less dramatically,
//! break stapling whenever `chain[1]` is a cross-certificate rather than the
//! anchor). [`check_stapled_ocsp`] resolves the issuer the way the verifier
//! does — the matched trust anchor, or the in-chain certificate that actually
//! signed the leaf — and evaluates the response against that.

use super::store::RootCertStore;
use super::verify::leaf_issuer;
use crate::signature_registry::SignaturePolicy;
use crate::tls::Error;
use crate::x509::{Certificate, OcspCertStatus, OcspCheckOptions, OcspResponse, Time};
use alloc::vec::Vec;

/// Validates the stapled OCSP response `ocsp_der` for `leaf` (= `chain[0]`,
/// already parsed by the caller) against the leaf's actual issuer within
/// `chain` as anchored by `store`.
///
/// Callers MUST have verified `chain` against `store` first (this function
/// only re-resolves the leaf → issuer link; it does not validate the path).
///
/// Outcome mapping, unchanged from the previous inline checks in the TLS
/// clients: a `good` status returns `Ok(())`; `revoked` returns
/// [`Error::CertificateRevoked`]; `unknown`, a response that fails to parse,
/// whose signature does not verify under the issuer (or a properly delegated
/// responder), that carries no row for the leaf, or that is stale, all return
/// [`Error::OcspResponseInvalid`]. A chain whose leaf cannot be linked to an
/// issuer returns [`Error::BadCertificate`].
pub(crate) fn check_stapled_ocsp(
    store: &RootCertStore,
    chain: &[Vec<u8>],
    leaf: &Certificate,
    ocsp_der: &[u8],
    policy: &SignaturePolicy,
    now: Option<&Time>,
) -> Result<(), Error> {
    let issuer = leaf_issuer(store, chain, policy)?;
    let resp = OcspResponse::from_der(ocsp_der.to_vec()).map_err(|_| Error::OcspResponseInvalid)?;
    match resp
        .check_for_cert_with_issuer_info(
            leaf,
            &issuer.name_der,
            &issuer.spki_der,
            &OcspCheckOptions::new(policy).with_time(now),
        )
        .map_err(|_| Error::OcspResponseInvalid)?
    {
        OcspCertStatus::Good => Ok(()),
        OcspCertStatus::Revoked { .. } => Err(Error::CertificateRevoked),
        OcspCertStatus::Unknown => Err(Error::OcspResponseInvalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::BoxedRsaPrivateKey;
    use crate::test_util::{rsa_test_key_a, rsa_test_key_b};
    use crate::tls::pki::CrlStore;
    use crate::tls::pki::verify::{LeafIssuer, verify_chain_with_crls_verified};
    use crate::x509::{
        AnyPublicKey, CertSigner, DistinguishedName, OcspResponseBuilder, Validity, extension,
    };
    use alloc::vec;

    fn validity() -> Validity {
        Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        )
    }

    fn boxed(k: &crate::rsa::RsaPrivateKey<32>) -> BoxedRsaPrivateKey {
        BoxedRsaPrivateKey::from_pkcs1_der(&k.to_pkcs1_der()).unwrap()
    }

    fn now() -> Time {
        Time::utc(2026, 5, 1, 0, 0, 0)
    }

    /// A `good` staple for `leaf`, with the `CertID` computed over `issuer`
    /// and signed by `signer`.
    fn good_staple(leaf: &Certificate, issuer: &Certificate, signer: &CertSigner<'_>) -> Vec<u8> {
        OcspResponseBuilder::good(
            leaf,
            issuer,
            Time::utc(2026, 4, 1, 0, 0, 0),
            Some(Time::utc(2026, 6, 1, 0, 0, 0)),
        )
        .unwrap()
        .sign(signer)
        .unwrap()
        .to_der()
        .to_vec()
    }

    /// A `revoked` staple for `leaf`, over `issuer`, signed by `signer`.
    fn revoked_staple(
        leaf: &Certificate,
        issuer: &Certificate,
        signer: &CertSigner<'_>,
    ) -> Vec<u8> {
        OcspResponseBuilder::revoked(
            leaf,
            issuer,
            Time::utc(2026, 4, 1, 0, 0, 0),
            Some(Time::utc(2026, 6, 1, 0, 0, 0)),
            Time::utc(2026, 3, 1, 0, 0, 0),
            None,
        )
        .unwrap()
        .sign(signer)
        .unwrap()
        .to_der()
        .to_vec()
    }

    struct Pki {
        store: RootCertStore,
        root: Certificate,
        root_key: BoxedRsaPrivateKey,
        /// Leaf issued DIRECTLY by `root`.
        leaf: Certificate,
        /// An unrelated self-signed CA that never signed anything in the
        /// trust path — the "bogus" certificate a malicious peer appends.
        bogus: Certificate,
        bogus_key: BoxedRsaPrivateKey,
    }

    fn pki() -> Pki {
        let root_key = boxed(&rsa_test_key_a());
        let bogus_key = boxed(&rsa_test_key_b());
        let root_name = DistinguishedName::common_name("Stapling Root");
        let bogus_name = DistinguishedName::common_name("Bogus CA");
        let leaf_name = DistinguishedName::common_name("leaf.example");

        let root =
            Certificate::self_signed(&rsa_test_key_a(), &root_name, &validity(), 1, true).unwrap();
        let bogus =
            Certificate::self_signed(&rsa_test_key_b(), &bogus_name, &validity(), 1, true).unwrap();
        // The leaf reuses key B (only the *issuer* identity matters here).
        let leaf = Certificate::issue_with_extensions(
            &CertSigner::Rsa(&root_key),
            &root_name,
            &leaf_name,
            &AnyPublicKey::Rsa(bogus_key.public_key()),
            &validity(),
            7,
            &[
                extension::basic_constraints(false, None),
                extension::subject_alt_name(&[crate::x509::GeneralName::Dns(
                    "leaf.example".into(),
                )]),
            ],
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        Pki {
            store,
            root,
            root_key,
            leaf,
            bogus,
            bogus_key,
        }
    }

    fn der(c: &Certificate) -> Vec<u8> {
        c.to_der().to_vec()
    }

    /// PKI-1: a leaf issued by a stored root is sent as `[leaf, bogus]` with
    /// a `good` staple signed by `bogus` and a `CertID` over `bogus`. The
    /// chain verifies (the leaf anchors directly; `bogus` is discarded), and
    /// the staple must be evaluated against the ROOT — under which `bogus`'s
    /// signature does not verify — not against `chain[1]`.
    #[test]
    fn staple_from_unvalidated_chain_1_is_rejected() {
        let p = pki();
        let chain = vec![der(&p.leaf), der(&p.bogus)];
        let policy = SignaturePolicy::modern();
        // The chain itself is fine: the leaf anchors directly.
        verify_chain_with_crls_verified(&p.store, &CrlStore::new(), &chain, Some(&now()), &policy)
            .unwrap();

        let staple = good_staple(&p.leaf, &p.bogus, &CertSigner::Rsa(&p.bogus_key));
        let r = check_stapled_ocsp(&p.store, &chain, &p.leaf, &staple, &policy, Some(&now()));
        assert_eq!(r, Err(Error::OcspResponseInvalid));

        // Same forged issuer, but a `revoked` row from the real CA is what
        // the attacker is hiding: the genuine staple is still honoured when
        // presented.
        let staple = revoked_staple(&p.leaf, &p.root, &CertSigner::Rsa(&p.root_key));
        let r = check_stapled_ocsp(&p.store, &chain, &p.leaf, &staple, &policy, Some(&now()));
        assert_eq!(r, Err(Error::CertificateRevoked));
    }

    /// `[leaf, root]` with a root-signed staple → `Good`; and `[leaf]` alone
    /// (the root supplied only by the store) is validated the same way —
    /// previously the staple was silently skipped whenever the chain had a
    /// single certificate.
    #[test]
    fn staple_against_direct_anchor_is_accepted() {
        let p = pki();
        let policy = SignaturePolicy::modern();
        let staple = good_staple(&p.leaf, &p.root, &CertSigner::Rsa(&p.root_key));
        for chain in [vec![der(&p.leaf), der(&p.root)], vec![der(&p.leaf)]] {
            check_stapled_ocsp(&p.store, &chain, &p.leaf, &staple, &policy, Some(&now())).unwrap();
        }
        // ...and a `revoked` root-signed staple is honoured on the
        // single-cert chain too.
        let staple = revoked_staple(&p.leaf, &p.root, &CertSigner::Rsa(&p.root_key));
        let r = check_stapled_ocsp(
            &p.store,
            &[der(&p.leaf)],
            &p.leaf,
            &staple,
            &policy,
            Some(&now()),
        );
        assert_eq!(r, Err(Error::CertificateRevoked));
    }

    /// `[leaf, intermediate, ...]`: the in-chain intermediate is the issuer
    /// (unchanged behaviour). A staple over the root instead of the
    /// intermediate does not match the leaf and is rejected.
    #[test]
    fn staple_against_in_chain_intermediate() {
        let p = pki();
        let policy = SignaturePolicy::modern();
        let int_key = boxed(&rsa_test_key_b());
        let root_name = DistinguishedName::common_name("Stapling Root");
        let int_name = DistinguishedName::common_name("Stapling Intermediate");
        let intermediate = Certificate::issue_with_extensions(
            &CertSigner::Rsa(&p.root_key),
            &root_name,
            &int_name,
            &AnyPublicKey::Rsa(int_key.public_key()),
            &validity(),
            2,
            &[extension::basic_constraints(true, None)],
        )
        .unwrap();
        let leaf = Certificate::issue_with_extensions(
            &CertSigner::Rsa(&int_key),
            &int_name,
            &DistinguishedName::common_name("leaf.example"),
            &AnyPublicKey::Rsa(int_key.public_key()),
            &validity(),
            9,
            &[
                extension::basic_constraints(false, None),
                extension::subject_alt_name(&[crate::x509::GeneralName::Dns(
                    "leaf.example".into(),
                )]),
            ],
        )
        .unwrap();
        let chain = vec![der(&leaf), der(&intermediate), der(&p.root)];
        let verified = verify_chain_with_crls_verified(
            &p.store,
            &CrlStore::new(),
            &chain,
            Some(&now()),
            &policy,
        )
        .unwrap();
        assert_eq!(
            verified.leaf_issuer,
            LeafIssuer {
                name_der: intermediate.subject_der().unwrap().to_vec(),
                spki_der: intermediate.spki_der().unwrap().to_vec(),
            }
        );

        let staple = good_staple(&leaf, &intermediate, &CertSigner::Rsa(&int_key));
        check_stapled_ocsp(&p.store, &chain, &leaf, &staple, &policy, Some(&now())).unwrap();

        let staple = good_staple(&leaf, &p.root, &CertSigner::Rsa(&p.root_key));
        let r = check_stapled_ocsp(&p.store, &chain, &leaf, &staple, &policy, Some(&now()));
        assert_eq!(r, Err(Error::OcspResponseInvalid));
    }

    /// The standalone resolver agrees with what the verifier recorded, for
    /// every chain shape, and the anchor identity is byte-exact with the
    /// root certificate's own Name / SPKI.
    #[test]
    fn leaf_issuer_matches_verifier() {
        let p = pki();
        let policy = SignaturePolicy::modern();
        let expected = LeafIssuer {
            name_der: p.root.subject_der().unwrap().to_vec(),
            spki_der: p.root.spki_der().unwrap().to_vec(),
        };
        for chain in [
            vec![der(&p.leaf)],
            vec![der(&p.leaf), der(&p.root)],
            vec![der(&p.leaf), der(&p.bogus)],
        ] {
            let verified = verify_chain_with_crls_verified(
                &p.store,
                &CrlStore::new(),
                &chain,
                Some(&now()),
                &policy,
            )
            .unwrap();
            assert_eq!(verified.leaf_issuer, expected);
            assert_eq!(leaf_issuer(&p.store, &chain, &policy).unwrap(), expected);
        }
        // A leaf that is neither anchored nor signed by chain[1] has no
        // issuer.
        let empty = RootCertStore::new();
        assert_eq!(
            leaf_issuer(&empty, &[der(&p.leaf), der(&p.bogus)], &policy),
            Err(Error::BadCertificate)
        );
        assert_eq!(
            leaf_issuer(&empty, &[der(&p.leaf)], &policy),
            Err(Error::BadCertificate)
        );
    }
}
