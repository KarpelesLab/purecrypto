//! A store of trusted root certificates (trust anchors).

use crate::tls::Error;
use crate::x509::{AnyPublicKey, Certificate, DistinguishedName};
use alloc::vec::Vec;

/// A trust anchor: a root certificate's subject name and its public key, the
/// minimum needed to terminate a chain.
pub(crate) struct TrustAnchor {
    pub(crate) subject: DistinguishedName,
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
        let subject = cert.subject().map_err(|_| Error::BadCertificate)?;
        let key = cert
            .subject_public_key()
            .map_err(|_| Error::BadCertificate)?;
        self.anchors.push(TrustAnchor { subject, key });
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

    /// Finds a trust anchor whose subject name matches `name` (a chain top's
    /// issuer).
    pub(crate) fn find_issuer(&self, name: &DistinguishedName) -> Option<&TrustAnchor> {
        self.anchors.iter().find(|a| &a.subject == name)
    }
}
