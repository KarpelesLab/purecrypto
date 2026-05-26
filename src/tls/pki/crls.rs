//! A store of CRLs the chain validator consults for revocation lookups.
//!
//! `CrlStore` is the counterpart to [`super::store::RootCertStore`]: it
//! holds CRLs as parsed [`CertificateRevocationList`] objects, indexed by
//! their issuer name (raw DER, RFC 5280 §7.1 byte-exact comparison).
//!
//! Revocation checking is **opt-in advisory** by default:
//!   * If the store has no CRL covering a cert's issuer, the cert is not
//!     considered revoked (i.e. the lack of a CRL is not failure).
//!   * If a CRL covering the issuer is present and signed by the issuer
//!     key (verified at chain-validation time), the cert is rejected
//!     iff [`CertificateRevocationList::is_revoked`] returns `true`.
//!   * CRLs from the store whose signature does *not* verify against the
//!     issuer chain are silently ignored (an attacker cannot poison the
//!     store with a forged CRL to deny service).
//!
//! A stricter "every cert MUST be covered" mode is not currently
//! plumbed; the design space is left open for a future `policy.require_crl`
//! field.

use alloc::vec::Vec;

use crate::tls::Error;
use crate::x509::CertificateRevocationList;

/// A set of CRLs against which peer certificate chains may be checked.
#[derive(Clone, Default)]
pub struct CrlStore {
    crls: Vec<CertificateRevocationList>,
}

impl CrlStore {
    /// An empty store.
    pub fn new() -> Self {
        CrlStore { crls: Vec::new() }
    }

    /// Adds a CRL from its DER encoding. The CRL's signature is **not**
    /// verified at this point — verification happens during chain
    /// validation, where the issuer key is known. Only the wire-format
    /// well-formedness is checked here (single SEQUENCE, parsable issuer,
    /// internal algid consistency).
    pub fn add_der(&mut self, der: Vec<u8>) -> Result<(), Error> {
        let crl = CertificateRevocationList::from_der(der).map_err(|_| Error::BadCertificate)?;
        crl.check_signature_algid_consistent()
            .map_err(|_| Error::BadCertificate)?;
        // Cheap sanity: issuer must parse and entries must decode.
        crl.issuer().map_err(|_| Error::BadCertificate)?;
        crl.entries().map_err(|_| Error::BadCertificate)?;
        self.crls.push(crl);
        Ok(())
    }

    /// Adds a CRL from its PEM encoding (RFC 7468 `X509 CRL` label).
    pub fn add_pem(&mut self, pem: &str) -> Result<(), Error> {
        let crl = CertificateRevocationList::from_pem(pem).map_err(|_| Error::BadCertificate)?;
        self.add_der(crl.to_der().to_vec())
    }

    /// The number of CRLs held.
    pub fn len(&self) -> usize {
        self.crls.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.crls.is_empty()
    }

    /// Clone the entire store (compatibility shim for the unified
    /// [`crate::tls::Config`] builder).
    pub fn clone_store(&self) -> Self {
        self.clone()
    }

    /// Iterates every CRL whose issuer `Name` DER matches `name_der`.
    pub(crate) fn crls_with_issuer<'a>(
        &'a self,
        name_der: &'a [u8],
    ) -> impl Iterator<Item = &'a CertificateRevocationList> + 'a {
        self.crls
            .iter()
            .filter(move |crl| crl.issuer_der().map(|d| d == name_der).unwrap_or(false))
    }

    /// Builds a new store containing every CRL from `self` followed by every
    /// CRL from `other`. Used to unite the connection-config CRLs with
    /// per-connection stapled CRLs at verify time.
    pub(crate) fn merged_with(&self, other: &CrlStore) -> CrlStore {
        let mut out = CrlStore {
            crls: Vec::with_capacity(self.crls.len() + other.crls.len()),
        };
        out.crls.extend(self.crls.iter().cloned());
        out.crls.extend(other.crls.iter().cloned());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::BoxedRsaPrivateKey;
    use crate::x509::{CertSigner, CrlBuilder, DistinguishedName, Time};

    fn rsa_a() -> BoxedRsaPrivateKey {
        BoxedRsaPrivateKey::from_pkcs1_pem(include_str!("../../../testdata/rsa2048_test_a.pem"))
            .expect("rsa key A")
    }

    #[test]
    fn add_der_and_lookup_by_issuer() {
        let key = rsa_a();
        let dn = DistinguishedName::common_name("crl-store-test");
        let mut b = CrlBuilder::new(&dn, Time::utc(2026, 1, 1, 0, 0, 0), None);
        b.revoke(&[0x42], Time::utc(2026, 1, 2, 0, 0, 0), None);
        let crl = b.sign(&CertSigner::Rsa(&key)).unwrap();

        let mut store = CrlStore::new();
        assert!(store.is_empty());
        store.add_der(crl.to_der().to_vec()).unwrap();
        assert_eq!(store.len(), 1);

        let dn_der = dn.to_der();
        let found: Vec<_> = store.crls_with_issuer(&dn_der).collect();
        assert_eq!(found.len(), 1);
        // The CRL we get back is the one we stored (matches by signature).
        assert!(
            found[0]
                .verify_signature_with(&CertSigner::Rsa(&key).public_key())
                .is_ok()
        );

        // Lookups against a *different* DN find nothing.
        let other = DistinguishedName::common_name("nope").to_der();
        assert_eq!(store.crls_with_issuer(&other).count(), 0);
    }

    #[test]
    fn add_der_rejects_garbage() {
        let mut store = CrlStore::new();
        // Plain garbage.
        assert!(store.add_der(alloc::vec![0u8; 4]).is_err());
        // Valid SEQUENCE but not a CRL: a tiny SEQUENCE { }.
        let bogus = alloc::vec![0x30, 0x00];
        assert!(store.add_der(bogus).is_err());
    }
}
