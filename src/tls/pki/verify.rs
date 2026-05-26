//! Certificate-chain verification against a [`RootCertStore`].
//!
//! Given the peer's certificate chain (end-entity first, as sent in the TLS
//! `Certificate` message), each certificate is checked to be signed by the
//! next, names are matched issuer-to-subject, the topmost certificate is
//! anchored to a trusted root, and (when a verification time is supplied) every
//! certificate is checked to be within its validity period.
//!
//! Per RFC 5280:
//!   * every non-leaf certificate must carry `basicConstraints.cA = true`
//!     (or it cannot issue subordinates),
//!   * `pathLenConstraint`, when present on a non-leaf, bounds the number
//!     of intermediates that may follow it,
//!   * if the leaf carries a `keyUsage` extension it must include
//!     `digitalSignature` (TLS 1.3 servers authenticate with a signature),
//!   * if the leaf carries an `extKeyUsage` extension it must include
//!     `id-kp-serverAuth`.
//!
//! [`verify_hostname`] separately matches the end-entity certificate against
//! the expected host name (subjectAltName dNSNames, falling back to the subject
//! common name).

use super::store::RootCertStore;
use crate::signature_registry::{SignaturePolicy, find_by_oid};
use crate::tls::Error;
use crate::x509::{AnyPublicKey, Certificate, Time, oid};
use alloc::vec::Vec;

/// `keyUsage` bit-0 `digitalSignature` (RFC 5280 §4.2.1.3).
const KU_DIGITAL_SIGNATURE: u16 = 0x80; // bit 0 in BIT STRING wire order = MSB of byte 0

/// Verifies a certificate `chain` (end-entity first) against `store` and, on
/// success, returns the end-entity (leaf) public key — the key whose possession
/// the peer proves in its `CertificateVerify`.
///
/// When `now` is `Some`, every certificate in the chain must be within its
/// validity period at that time; pass `None` to skip the expiry check.
///
/// `policy` is consulted for every signature in the chain (including the
/// anchor signature on the topmost certificate). A chain whose certificate
/// signatures use an algorithm not on the whitelist is rejected with
/// `BadCertificate`, regardless of whether the signature would otherwise
/// verify.
pub(crate) fn verify_chain(
    store: &RootCertStore,
    chain: &[Vec<u8>],
    now: Option<&Time>,
    policy: &SignaturePolicy,
) -> Result<AnyPublicKey, Error> {
    if chain.is_empty() {
        return Err(Error::BadCertificate);
    }

    let certs: Vec<Certificate> = chain
        .iter()
        .map(|der| Certificate::from_der(der.clone()))
        .collect::<Result<_, _>>()
        .map_err(|_| Error::BadCertificate)?;

    // Each certificate must currently be within its validity period.
    if let Some(now) = now {
        for cert in &certs {
            let validity = cert.validity().map_err(|_| Error::BadCertificate)?;
            if !validity.accepts(now) {
                return Err(Error::BadCertificate);
            }
        }
    }

    // Each certificate must be signed by the next, with matching names.
    for pair in certs.windows(2) {
        let (cert, issuer) = (&pair[0], &pair[1]);
        let issuer_key = issuer
            .subject_public_key()
            .map_err(|_| Error::BadCertificate)?;
        verify_cert_against_issuer(cert, &issuer_key, policy)?;
        if names_differ(cert, issuer)? {
            return Err(Error::BadCertificate);
        }
    }

    // Anchor the top of the chain to a trusted root sharing its issuer name.
    let top = certs.last().expect("chain is non-empty");
    let top_issuer = top.issuer().map_err(|_| Error::BadCertificate)?;
    let anchor = store
        .find_issuer(&top_issuer)
        .ok_or(Error::BadCertificate)?;
    verify_cert_against_issuer(top, &anchor.key, policy)?;

    // RFC 5280 §4.2.1.9 / §4.2.1.3 / §4.2.1.12 enforcement.
    enforce_constraints(&certs)?;

    certs[0]
        .subject_public_key()
        .map_err(|_| Error::BadCertificate)
}

/// Verifies the signature on `cert` under `issuer_key`, gating on `policy`.
///
/// Looks up the certificate's `signatureAlgorithm` OID in the registry,
/// rejects any algorithm not on the whitelist (with `BadCertificate`), and
/// only then delegates to the issuer key's verifier.
fn verify_cert_against_issuer(
    cert: &Certificate,
    issuer_key: &AnyPublicKey,
    policy: &SignaturePolicy,
) -> Result<(), Error> {
    let sig_alg = cert
        .signature_algorithm_oid()
        .map_err(|_| Error::BadCertificate)?;
    let algo = find_by_oid(&sig_alg).ok_or(Error::BadCertificate)?;
    let issuer_spki = issuer_key.to_spki_der();
    if !policy.permits(algo, &issuer_spki) {
        return Err(Error::BadCertificate);
    }
    cert.verify_signature_with(issuer_key)
        .map_err(|_| Error::BadCertificate)
}

/// Per-position chain constraints:
///   * every non-leaf must have `basicConstraints.cA = true`;
///   * `pathLenConstraint` on a non-leaf bounds the number of intermediates
///     between it and the leaf;
///   * if the leaf carries `keyUsage`, `digitalSignature` (bit 0) must be set;
///   * if the leaf carries `extKeyUsage`, it must include `id-kp-serverAuth`.
fn enforce_constraints(certs: &[Certificate]) -> Result<(), Error> {
    // `certs[0]` is the leaf, `certs[last]` is the topmost supplied
    // certificate (its issuer is the trust anchor in the store).
    for (i, cert) in certs.iter().enumerate().skip(1) {
        // Every non-leaf in the supplied chain signs the cert below it, so it
        // MUST be a CA per RFC 5280 §4.2.1.9.
        let bc = cert
            .basic_constraints()
            .map_err(|_| Error::BadCertificate)?
            .ok_or(Error::BadCertificate)?;
        if !bc.0 {
            return Err(Error::BadCertificate);
        }
        // `pathLenConstraint = N` permits at most N intermediate certificates
        // between this CA and any leaf. For the cert at position `i` (i > 0),
        // intermediates between it and the leaf live at positions 1..=i-1,
        // i.e. `i - 1` certs. So require `path_len >= i - 1`.
        if let Some(plc) = bc.1 {
            let intermediates_below = i.saturating_sub(1);
            if (plc as usize) < intermediates_below {
                return Err(Error::BadCertificate);
            }
        }
    }

    // Leaf: keyUsage (if present) must include digitalSignature; EKU (if
    // present) must include id-kp-serverAuth.
    let leaf = &certs[0];
    if let Some(mask) = leaf.key_usage().map_err(|_| Error::BadCertificate)?
        && (mask & KU_DIGITAL_SIGNATURE) == 0
    {
        return Err(Error::BadCertificate);
    }
    let ekus = leaf
        .extended_key_usages()
        .map_err(|_| Error::BadCertificate)?;
    if !ekus.is_empty() && !ekus.iter().any(|o| o.as_slice() == oid::ID_KP_SERVER_AUTH) {
        return Err(Error::BadCertificate);
    }
    Ok(())
}

/// Whether `cert.issuer != issuer.subject`.
fn names_differ(cert: &Certificate, issuer: &Certificate) -> Result<bool, Error> {
    let cert_issuer = cert.issuer().map_err(|_| Error::BadCertificate)?;
    let issuer_subject = issuer.subject().map_err(|_| Error::BadCertificate)?;
    Ok(cert_issuer != issuer_subject)
}

/// Checks that the end-entity certificate identifies `host`. Prefers the
/// `subjectAltName` dNSName entries (RFC 6125); if there are none, falls back
/// to the subject common name.
pub(crate) fn verify_hostname(cert: &Certificate, host: &str) -> Result<(), Error> {
    let sans = cert
        .subject_alt_names()
        .map_err(|_| Error::BadCertificate)?;
    let matched = if !sans.is_empty() {
        sans.iter().any(|pattern| dns_name_matches(pattern, host))
    } else {
        cert.subject()
            .map_err(|_| Error::BadCertificate)?
            .common_name
            .as_deref()
            .map(|cn| dns_name_matches(cn, host))
            .unwrap_or(false)
    };
    if matched {
        Ok(())
    } else {
        Err(Error::BadCertificate)
    }
}

/// Matches a certificate dNSName `pattern` against `host`, case-insensitively,
/// allowing a single leftmost-label `*` wildcard (`*.example.com` matches
/// `a.example.com` but not `example.com` or `a.b.example.com`).
fn dns_name_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        match host.split_once('.') {
            Some((label, rest)) => {
                !label.is_empty() && !rest.is_empty() && rest.eq_ignore_ascii_case(suffix)
            }
            None => false,
        }
    } else {
        !pattern.is_empty() && pattern.eq_ignore_ascii_case(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{from_hex_vec, rsa_test_key_a, rsa_test_key_b};
    use crate::x509::{Certificate, DistinguishedName, Time, Validity};

    fn validity() -> Validity {
        Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        )
    }

    /// The shipped default policy.
    fn policy() -> SignaturePolicy {
        SignaturePolicy::modern()
    }

    #[test]
    fn rfc8448_self_signed_anchor() {
        // The RFC 8448 server certificate is self-signed ("rsa" -> "rsa"); its
        // key is RSA-1024, so a default-policy verify would refuse it on the
        // min_rsa_bits check. Lower the floor for this single legacy fixture.
        let flight = from_hex_vec(include_str!(
            "../../../testdata/rfc8448_server_flight_payload.hex"
        ));
        let cert_der = flight[51..483].to_vec();

        let mut store = RootCertStore::new();
        store.add_der(cert_der.clone()).unwrap();

        let relaxed = SignaturePolicy::modern().with_min_rsa_bits(1024);
        let leaf_key = verify_chain(&store, &[cert_der], None, &relaxed).unwrap();
        assert!(matches!(leaf_key, AnyPublicKey::Rsa(_)));
    }

    #[test]
    fn two_cert_chain_to_root() {
        let ca_key = rsa_test_key_a();
        let leaf_key = rsa_test_key_b();
        let ca_name = DistinguishedName::common_name("purecrypto Root");
        let leaf_name = DistinguishedName::common_name("leaf.example");

        let root = Certificate::self_signed(&ca_key, &ca_name, &validity(), 1, true).unwrap();
        let leaf = Certificate::issue(
            &ca_key,
            &ca_name,
            &leaf_name,
            &leaf_key.public_key(),
            &validity(),
            2,
            false,
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();

        // Within the validity window (exercises the expiry check positively).
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        let policy = policy();
        // Chain with the leaf alone (root supplied by the store).
        verify_chain(&store, &[leaf.to_der().to_vec()], Some(&now), &policy).unwrap();
        // Chain that also carries the root certificate.
        verify_chain(
            &store,
            &[leaf.to_der().to_vec(), root.to_der().to_vec()],
            Some(&now),
            &policy,
        )
        .unwrap();
    }

    #[test]
    fn rejects_untrusted_and_empty() {
        let ca_key = rsa_test_key_a();
        let ca_name = DistinguishedName::common_name("Untrusted Root");
        let root = Certificate::self_signed(&ca_key, &ca_name, &validity(), 1, true).unwrap();

        // Empty store -> no anchor.
        let empty = RootCertStore::new();
        let policy = policy();
        assert!(matches!(
            verify_chain(&empty, &[root.to_der().to_vec()], None, &policy),
            Err(Error::BadCertificate)
        ));

        // Empty chain.
        assert!(matches!(
            verify_chain(&empty, &[], None, &policy),
            Err(Error::BadCertificate)
        ));
    }

    #[test]
    fn rejects_broken_signature() {
        let ca_key = rsa_test_key_a();
        let leaf_key = rsa_test_key_b();
        let ca_name = DistinguishedName::common_name("purecrypto Root");
        let leaf_name = DistinguishedName::common_name("leaf.example");

        let root = Certificate::self_signed(&ca_key, &ca_name, &validity(), 1, true).unwrap();
        // Leaf "signed" by the leaf's own key, not the CA -> chain to root fails.
        let bogus = Certificate::issue(
            &leaf_key,
            &ca_name,
            &leaf_name,
            &leaf_key.public_key(),
            &validity(),
            3,
            false,
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        assert!(matches!(
            verify_chain(&store, &[bogus.to_der().to_vec()], None, &policy()),
            Err(Error::BadCertificate)
        ));
    }

    /// An "intermediate" that lacks `basicConstraints.cA = true` cannot sign
    /// the leaf — chain validation rejects.
    #[test]
    fn rejects_non_ca_as_intermediate() {
        let ca_key = rsa_test_key_a();
        let leaf_key = rsa_test_key_b();
        let ca_name = DistinguishedName::common_name("purecrypto Root");
        let leaf_name = DistinguishedName::common_name("leaf.example");

        let root = Certificate::self_signed(&ca_key, &ca_name, &validity(), 1, true).unwrap();
        // The "intermediate" is signed by the root but is itself marked as
        // a non-CA (is_ca = false). It still issues a leaf — a forged path.
        let bad_int = Certificate::issue(
            &ca_key,
            &ca_name,
            &DistinguishedName::common_name("fake-intermediate"),
            &leaf_key.public_key(),
            &validity(),
            2,
            false,
        )
        .unwrap();
        let leaf = Certificate::issue(
            &leaf_key,
            &DistinguishedName::common_name("fake-intermediate"),
            &leaf_name,
            &leaf_key.public_key(),
            &validity(),
            3,
            false,
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let chain = alloc::vec![leaf.to_der().to_vec(), bad_int.to_der().to_vec()];
        assert!(matches!(
            verify_chain(&store, &chain, None, &policy()),
            Err(Error::BadCertificate)
        ));
    }

    #[test]
    fn rejects_expired_certificate() {
        let ca_key = rsa_test_key_a();
        let name = DistinguishedName::common_name("expired.example");
        let past = Validity::new(
            Time::utc(2020, 1, 1, 0, 0, 0),
            Time::utc(2021, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed(&ca_key, &name, &past, 1, true).unwrap();

        let mut store = RootCertStore::new();
        store.add_der(cert.to_der().to_vec()).unwrap();

        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        let policy = policy();
        // Expired at `now`.
        assert!(matches!(
            verify_chain(&store, &[cert.to_der().to_vec()], Some(&now), &policy),
            Err(Error::BadCertificate)
        ));
        // Accepted when no clock is supplied (expiry skipped).
        verify_chain(&store, &[cert.to_der().to_vec()], None, &policy).unwrap();
    }

    #[test]
    fn hostname_san_and_cn() {
        let key = rsa_test_key_a();
        // SAN cert: matches SAN entries (incl. wildcard), ignores CN.
        let san_cert = Certificate::self_signed_with_sans(
            &key,
            &DistinguishedName::common_name("ignored"),
            &validity(),
            1,
            false,
            &["example.com", "*.svc.example.com"],
        )
        .unwrap();
        verify_hostname(&san_cert, "example.com").unwrap();
        verify_hostname(&san_cert, "api.svc.example.com").unwrap();
        assert!(verify_hostname(&san_cert, "ignored").is_err()); // CN not consulted
        assert!(verify_hostname(&san_cert, "other.com").is_err());
        assert!(verify_hostname(&san_cert, "svc.example.com").is_err()); // wildcard needs a label
        assert!(verify_hostname(&san_cert, "a.b.svc.example.com").is_err()); // one label only

        // No SAN: falls back to the subject common name.
        let cn_cert = Certificate::self_signed(
            &key,
            &DistinguishedName::common_name("host.example"),
            &validity(),
            2,
            false,
        )
        .unwrap();
        verify_hostname(&cn_cert, "HOST.example").unwrap(); // case-insensitive
        assert!(verify_hostname(&cn_cert, "wrong.example").is_err());
    }

    /// Issuing and validating a self-signed ML-DSA-65 certificate through
    /// the full `verify_chain` path. ML-DSA is on the default whitelist as
    /// of commit 3, so no policy tuning is needed.
    #[test]
    fn mldsa_self_signed_chain() {
        use crate::hash::Sha256;
        use crate::mldsa::MlDsa65PrivateKey;
        use crate::rng::HmacDrbg;
        use crate::x509::CertSigner;
        let mut rng = HmacDrbg::<Sha256>::new(b"verify-mldsa65", b"n", &[]);
        let (sk, _pk) = MlDsa65PrivateKey::generate(&mut rng);
        let signer = CertSigner::MlDsa65(&sk);
        let name = DistinguishedName::common_name("pqc.example");
        let cert =
            Certificate::self_signed_general(&signer, &name, &validity(), 1, true, &[]).unwrap();

        let mut store = RootCertStore::new();
        store.add_der(cert.to_der().to_vec()).unwrap();
        let leaf_key = verify_chain(&store, &[cert.to_der().to_vec()], None, &policy()).unwrap();
        assert!(matches!(leaf_key, AnyPublicKey::MlDsa65(_)));
    }

    /// A chain whose leaf is signed with secp256k1 verifies only when the
    /// policy explicitly permits the algorithm; the default `modern()`
    /// policy refuses (secp256k1 is in the registry but not on the
    /// whitelist).
    #[test]
    fn secp256k1_chain_under_extended_policy() {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;
        use crate::x509::CertSigner;
        let mut rng = HmacDrbg::<Sha256>::new(b"verify-k1", b"n", &[]);
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::Secp256k1, &mut rng);
        let signer = CertSigner::Ecdsa(&sk);
        let name = DistinguishedName::common_name("k1.example");
        let cert =
            Certificate::self_signed_general(&signer, &name, &validity(), 1, true, &[]).unwrap();

        let mut store = RootCertStore::new();
        store.add_der(cert.to_der().to_vec()).unwrap();

        // Cert's signatureAlgorithm is `ecdsa-with-SHA256`. The default policy
        // permits the `ecdsa-with-sha256` OID-keyed entry — which accepts any
        // supported curve — so the chain validates without opt-in. (secp256k1
        // is in the registry; the policy gates the OID-keyed entry, not the
        // strict secp256k1 entry.)
        verify_chain(&store, &[cert.to_der().to_vec()], None, &policy()).unwrap();

        // To assert the strict-pair entry is opt-in only, build a policy that
        // permits only Ed25519 — secp256k1 + ECDSA-SHA256 must be refused.
        let restrictive = SignaturePolicy::empty().permit("ed25519");
        assert!(matches!(
            verify_chain(&store, &[cert.to_der().to_vec()], None, &restrictive),
            Err(Error::BadCertificate)
        ));
    }

    /// A self-signed SLH-DSA-SHA2-128f cert validates only under a policy
    /// that explicitly permits SLH-DSA (the default `modern()` does not).
    #[test]
    fn slhdsa_chain_under_extended_policy() {
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;
        use crate::slhdsa::{ParamSet, PrivateKey};
        use crate::x509::CertSigner;
        let mut rng = HmacDrbg::<Sha256>::new(b"verify-slhdsa", b"n", &[]);
        let (sk, _pk) = PrivateKey::generate(ParamSet::Sha2_128f, &mut rng);
        let signer = CertSigner::SlhDsa(&sk);
        let name = DistinguishedName::common_name("slhdsa.example");
        let cert =
            Certificate::self_signed_general(&signer, &name, &validity(), 1, true, &[]).unwrap();

        let mut store = RootCertStore::new();
        store.add_der(cert.to_der().to_vec()).unwrap();

        // Default policy refuses.
        assert!(matches!(
            verify_chain(&store, &[cert.to_der().to_vec()], None, &policy()),
            Err(Error::BadCertificate)
        ));
        // Extended policy accepts.
        let extended = SignaturePolicy::modern().permit("slh-dsa-sha2-128f");
        verify_chain(&store, &[cert.to_der().to_vec()], None, &extended).unwrap();
    }

    /// A chain whose signature algorithm is in the registry but not on the
    /// whitelist is rejected (with `BadCertificate`), even when the signature
    /// itself would verify.
    #[test]
    fn rejects_unpermitted_algorithm() {
        let key = rsa_test_key_a();
        let cert = Certificate::self_signed(
            &key,
            &DistinguishedName::common_name("rsa.example"),
            &validity(),
            1,
            true,
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(cert.to_der().to_vec()).unwrap();

        // The cert is `sha256WithRSAEncryption`. A policy that permits only
        // ed25519 must reject it; the default policy must accept it.
        let ed_only = SignaturePolicy::empty().permit("ed25519");
        assert!(matches!(
            verify_chain(&store, &[cert.to_der().to_vec()], None, &ed_only),
            Err(Error::BadCertificate)
        ));
        verify_chain(&store, &[cert.to_der().to_vec()], None, &policy()).unwrap();
    }
}
