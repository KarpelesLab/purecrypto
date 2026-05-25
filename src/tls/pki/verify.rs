//! Certificate-chain verification against a [`RootCertStore`].
//!
//! Given the peer's certificate chain (end-entity first, as sent in the TLS
//! `Certificate` message), each certificate is checked to be signed by the
//! next, names are matched issuer-to-subject, and the topmost certificate is
//! anchored to a trusted root.
//!
//! **Not yet performed:** validity-period (`notBefore`/`notAfter`), basic
//! constraints, key-usage/EKU, and name-constraint checks. The connection layer
//! is expected to supply a verification time and hostname check in a later
//! revision; for now this establishes the cryptographic chain of trust only.

use super::store::RootCertStore;
use crate::tls::Error;
use crate::x509::{AnyPublicKey, Certificate};
use alloc::vec::Vec;

/// Verifies a certificate `chain` (end-entity first) against `store` and, on
/// success, returns the end-entity (leaf) public key — the key whose possession
/// the peer proves in its `CertificateVerify`.
pub(crate) fn verify_chain(
    store: &RootCertStore,
    chain: &[Vec<u8>],
) -> Result<AnyPublicKey, Error> {
    if chain.is_empty() {
        return Err(Error::BadCertificate);
    }

    let certs: Vec<Certificate> = chain
        .iter()
        .map(|der| Certificate::from_der(der.clone()))
        .collect::<Result<_, _>>()
        .map_err(|_| Error::BadCertificate)?;

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

    certs[0]
        .subject_public_key()
        .map_err(|_| Error::BadCertificate)
}

/// Whether `cert.issuer != issuer.subject`.
fn names_differ(cert: &Certificate, issuer: &Certificate) -> Result<bool, Error> {
    let cert_issuer = cert.issuer().map_err(|_| Error::BadCertificate)?;
    let issuer_subject = issuer.subject().map_err(|_| Error::BadCertificate)?;
    Ok(cert_issuer != issuer_subject)
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

        let leaf_key = verify_chain(&store, &[cert_der]).unwrap();
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

        // Chain with the leaf alone (root supplied by the store).
        verify_chain(&store, &[leaf.to_der().to_vec()]).unwrap();
        // Chain that also carries the root certificate.
        verify_chain(&store, &[leaf.to_der().to_vec(), root.to_der().to_vec()]).unwrap();
    }

    #[test]
    fn rejects_untrusted_and_empty() {
        let ca_key = rsa_test_key_a();
        let ca_name = DistinguishedName::common_name("Untrusted Root");
        let root = Certificate::self_signed(&ca_key, &ca_name, &validity(), 1, true).unwrap();

        // Empty store -> no anchor.
        let empty = RootCertStore::new();
        assert!(matches!(
            verify_chain(&empty, &[root.to_der().to_vec()]),
            Err(Error::BadCertificate)
        ));

        // Empty chain.
        assert!(matches!(
            verify_chain(&empty, &[]),
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
            verify_chain(&store, &[bogus.to_der().to_vec()]),
            Err(Error::BadCertificate)
        ));
    }
}
