//! A store of trusted root certificates (trust anchors).

use crate::tls::Error;
use crate::x509::{AnyPublicKey, Certificate};
use alloc::vec::Vec;

/// A trust anchor: a root certificate's subject name (raw DER) and its
/// public key, the minimum needed to terminate a chain. We store the raw
/// DER of the subject `Name` so chain-building uses RFC 5280 §7.1
/// byte-exact equality, immune to encoding differences (PrintableString
/// vs UTF8String, extra attributes, multi-valued RDNs).
pub(crate) struct TrustAnchor {
    pub(crate) subject_der: Vec<u8>,
    pub(crate) key: AnyPublicKey,
}

/// A set of trusted root certificates against which peer chains are verified.
#[derive(Default)]
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
