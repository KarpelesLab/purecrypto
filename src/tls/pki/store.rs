//! A store of trusted root certificates (trust anchors).

use crate::tls::Error;
use crate::x509::{AnyPublicKey, Certificate};
use alloc::vec::Vec;

/// A trust anchor: a root certificate's subject name (raw DER) and its
/// public key, the minimum needed to terminate a chain. We store the raw
/// DER of the subject `Name` so chain-building uses RFC 5280 §7.1
/// byte-exact equality, immune to encoding differences (PrintableString
/// vs UTF8String, extra attributes, multi-valued RDNs).
#[derive(Clone)]
pub(crate) struct TrustAnchor {
    pub(crate) subject_der: Vec<u8>,
    pub(crate) key: AnyPublicKey,
}

/// A set of trusted root certificates against which peer chains are verified.
#[derive(Clone, Default)]
pub struct RootCertStore {
    anchors: Vec<TrustAnchor>,
}

impl RootCertStore {
    /// An empty store.
    pub fn new() -> Self {
        RootCertStore {
            anchors: Vec::new(),
        }
    }

    /// Adds a trust anchor from a DER-encoded root certificate, recording its
    /// subject name and public key.
    pub fn add_der(&mut self, der: Vec<u8>) -> Result<(), Error> {
        let cert = Certificate::from_der(der).map_err(|_| Error::BadCertificate)?;
        let subject_der = cert
            .subject_der()
            .map_err(|_| Error::BadCertificate)?
            .to_vec();
        let key = cert
            .subject_public_key()
            .map_err(|_| Error::BadCertificate)?;
        self.anchors.push(TrustAnchor { subject_der, key });
        Ok(())
    }

    /// Adds a trust anchor from a PEM-encoded root certificate.
    pub fn add_pem(&mut self, pem: &str) -> Result<(), Error> {
        let cert = Certificate::from_pem(pem).map_err(|_| Error::BadCertificate)?;
        self.add_der(cert.to_der().to_vec())
    }

    /// The number of trust anchors held.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the store has no trust anchors.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// Builds a store pre-seeded with the embedded root-CA bundle from the
    /// first-party [`cacrt`](https://crates.io/crates/cacrt) crate (the
    /// Mozilla CA set, parsed into static DER at `cacrt` build time).
    ///
    /// This is the zero-configuration trust store: it requires no filesystem
    /// access, so it behaves identically across Linux, macOS, Windows, and
    /// `no_std`-with-alloc targets — unlike reading an OS bundle such as
    /// `/etc/ssl/certs/ca-certificates.crt`. Requires the `embedded-roots`
    /// feature.
    #[cfg(feature = "embedded-roots")]
    pub fn with_embedded_roots() -> Self {
        let mut store = RootCertStore::new();
        store.add_embedded_roots();
        store
    }

    /// Adds every certificate from the embedded [`cacrt`] bundle as a trust
    /// anchor, returning the number successfully added. Requires the
    /// `embedded-roots` feature.
    ///
    /// [`cacrt`]: https://crates.io/crates/cacrt
    #[cfg(feature = "embedded-roots")]
    pub fn add_embedded_roots(&mut self) -> usize {
        let mut added = 0;
        for ca in cacrt::all() {
            if self.add_der(ca.der().to_vec()).is_ok() {
                added += 1;
            }
        }
        added
    }

    /// Clone the entire store (compatibility shim for the unified
    /// [`crate::tls::Config`] builder, which holds a single
    /// [`RootCertStore`] used to seed both client trust anchors and
    /// server-side mTLS trust anchors).
    pub fn clone_store(&self) -> Self {
        self.clone()
    }

    /// Iterates over every trust anchor whose subject `Name` DER matches
    /// `name_der`. Multiple anchors may share a name (cross-signed renewal
    /// scenarios), so callers should try them all rather than stopping at
    /// the first hit.
    pub(crate) fn anchors_with_subject<'a>(
        &'a self,
        name_der: &'a [u8],
    ) -> impl Iterator<Item = &'a TrustAnchor> + 'a {
        self.anchors
            .iter()
            .filter(move |a| a.subject_der.as_slice() == name_der)
    }
}

#[cfg(all(test, feature = "embedded-roots"))]
mod embedded_roots_tests {
    use super::RootCertStore;

    #[test]
    fn with_embedded_roots_is_populated() {
        let store = RootCertStore::with_embedded_roots();
        // The cacrt bundle carries the full Mozilla CA set; sanity-check that a
        // substantial number of anchors loaded (not just a handful).
        assert!(
            store.len() > 50,
            "embedded root store unexpectedly small: {}",
            store.len()
        );
        assert!(!store.is_empty());
    }

    #[test]
    fn add_embedded_roots_reports_count() {
        let mut store = RootCertStore::new();
        let added = store.add_embedded_roots();
        assert_eq!(added, store.len());
        assert!(added > 50);
    }
}
