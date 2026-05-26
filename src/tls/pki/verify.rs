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
pub(crate) fn verify_chain(
    store: &RootCertStore,
    chain: &[Vec<u8>],
    now: Option<&Time>,
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
        cert.verify_signature_with(&issuer_key)
            .map_err(|_| Error::BadCertificate)?;
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
    top.verify_signature_with(&anchor.key)
        .map_err(|_| Error::BadCertificate)?;

    // RFC 5280 §4.2.1.9 / §4.2.1.3 / §4.2.1.12 enforcement.
    enforce_constraints(&certs)?;

    certs[0]
        .subject_public_key()
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

    #[test]
    fn rfc8448_self_signed_anchor() {
        // The RFC 8448 server certificate is self-signed ("rsa" -> "rsa").
        let flight = from_hex_vec(include_str!(
            "../../../testdata/rfc8448_server_flight_payload.hex"
        ));
        let cert_der = flight[51..483].to_vec();

        let mut store = RootCertStore::new();
        store.add_der(cert_der.clone()).unwrap();

        let leaf_key = verify_chain(&store, &[cert_der], None).unwrap();
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
        // Chain with the leaf alone (root supplied by the store).
        verify_chain(&store, &[leaf.to_der().to_vec()], Some(&now)).unwrap();
        // Chain that also carries the root certificate.
        verify_chain(
            &store,
            &[leaf.to_der().to_vec(), root.to_der().to_vec()],
            Some(&now),
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
        assert!(matches!(
            verify_chain(&empty, &[root.to_der().to_vec()], None),
            Err(Error::BadCertificate)
        ));

        // Empty chain.
        assert!(matches!(
            verify_chain(&empty, &[], None),
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
            verify_chain(&store, &[bogus.to_der().to_vec()], None),
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
            verify_chain(&store, &chain, None),
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
        // Expired at `now`.
        assert!(matches!(
            verify_chain(&store, &[cert.to_der().to_vec()], Some(&now)),
            Err(Error::BadCertificate)
        ));
        // Accepted when no clock is supplied (expiry skipped).
        verify_chain(&store, &[cert.to_der().to_vec()], None).unwrap();
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
}
