//! A store of trusted root certificates (trust anchors).

use crate::tls::Error;
use crate::x509::{AnyPublicKey, Certificate, NameConstraints};
use alloc::vec::Vec;

/// A trust anchor: a root certificate's subject name (raw DER), its public
/// key, and any `nameConstraints` the root declared. The name + key are the
/// minimum needed to terminate a chain. We store the raw DER of the subject
/// `Name` so chain-building uses RFC 5280 §7.1 byte-exact equality, immune
/// to encoding differences (PrintableString vs UTF8String, extra attributes,
/// multi-valued RDNs). The anchor's `nameConstraints` (parsed once, at
/// [`RootCertStore::add_der`] time) are seeded into the RFC 5280 §6.1.4
/// constraint state so a deliberately constrained root (e.g. a corporate
/// root limited to `.corp.example`) governs every certificate in the
/// validated path, exactly as an in-chain CA's constraints would.
#[derive(Clone)]
pub(crate) struct TrustAnchor {
    pub(crate) subject_der: Vec<u8>,
    pub(crate) key: AnyPublicKey,
    /// The anchor's `SubjectPublicKeyInfo` exactly as encoded in the root
    /// certificate (full TLV). Retained so a leaf that anchors *directly* on
    /// this root can be checked against an OCSP `CertID` — whose
    /// `issuerKeyHash` is computed over the on-the-wire `subjectPublicKey`
    /// BIT STRING (RFC 6960 §4.1.1), not over a re-encoding of `key`.
    pub(crate) spki_der: Vec<u8>,
    pub(crate) name_constraints: Option<NameConstraints>,
    /// The anchor's own `basicConstraints.pathLenConstraint`, when it declared
    /// one. RFC 5280 §6.1 does not process the anchor's certificate at all,
    /// but RFC 5937 ("Using Trust Anchor Constraints during Certification Path
    /// Processing") allows a relying party to honour constraints the anchor
    /// carries — and OpenSSL does. Enforced only when actually present, so
    /// anchors without the field behave exactly as before.
    pub(crate) path_len_constraint: Option<u32>,
    /// The anchor's own `extKeyUsage` OIDs, empty when it declared none. Like
    /// `path_len_constraint`, enforced only when non-empty (RFC 5937): an
    /// EKU-scoped root must permit the purpose the chain is being validated
    /// for, the same rule in-chain CAs obey.
    pub(crate) extended_key_usages: Vec<Vec<u64>>,
}

/// A set of trusted root certificates against which peer chains are verified.
///
/// Roots that declare a `nameConstraints` extension keep it: the constraints
/// are enforced over every chain that anchors at that root (RFC 5280 §6.1.4),
/// the same way constraints declared by in-chain intermediate CAs are. See
/// [`RootCertStore::add_der`] for the fail-closed handling of constraint
/// shapes the validator cannot evaluate.
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
    /// subject name, public key, and any `nameConstraints` it declares.
    ///
    /// A `nameConstraints` extension on the root is retained and enforced
    /// over every chain that anchors at it (RFC 5280 §6.1.4), exactly as an
    /// in-chain CA's constraints would be. Because an admin installing a
    /// constrained root does so deliberately, this fails closed: a root
    /// whose `nameConstraints` extension does not parse, or whose subtrees
    /// reference a GeneralName variant the validator cannot evaluate
    /// (anything other than dNSName / iPAddress), is rejected rather than
    /// added with its constraints silently ignored.
    pub fn add_der(&mut self, der: Vec<u8>) -> Result<(), Error> {
        let cert = Certificate::from_der(der).map_err(|_| Error::BadCertificate)?;
        let subject_der = cert
            .subject_der()
            .map_err(|_| Error::BadCertificate)?
            .to_vec();
        let key = cert
            .subject_public_key()
            .map_err(|_| Error::BadCertificate)?;
        let spki_der = cert.spki_der().map_err(|_| Error::BadCertificate)?.to_vec();
        let name_constraints = cert.name_constraints().map_err(|_| Error::BadCertificate)?;
        if let Some(nc) = &name_constraints
            && (nc.has_unenforceable_permitted || nc.has_unenforceable_excluded)
        {
            return Err(Error::BadCertificate);
        }
        // RFC 5937 anchor constraints: keep the anchor's own
        // `pathLenConstraint` and `extKeyUsage`, when it declares them, so the
        // validator can honour them (see [`TrustAnchor`]). Both are optional
        // fields; an anchor that carries neither is unconstrained exactly as
        // before. A malformed extension is fail-closed like nameConstraints.
        let path_len_constraint = cert
            .basic_constraints()
            .map_err(|_| Error::BadCertificate)?
            .and_then(|(is_ca, plc)| if is_ca { plc } else { None });
        let extended_key_usages = cert
            .extended_key_usages()
            .map_err(|_| Error::BadCertificate)?;
        self.anchors.push(TrustAnchor {
            subject_der,
            key,
            spki_der,
            name_constraints,
            path_len_constraint,
            extended_key_usages,
        });
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
    /// first-party [`cacrt`](https://crates.io/crates/cacrt) crate — a
    /// curated root store built from the Mozilla root program and others,
    /// following CA/Browser Forum rules, parsed into static DER at `cacrt`
    /// build time.
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
    pub(crate) fn anchors_with_subject<'a, 'n>(
        &'a self,
        name_der: &'n [u8],
    ) -> impl Iterator<Item = &'a TrustAnchor> + use<'a, 'n> {
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
        // The cacrt bundle carries a full curated root set; sanity-check that
        // a substantial number of anchors loaded (not just a handful).
        assert!(
            store.len() > 50,
            "embedded root store unexpectedly small: {}",
            store.len()
        );
        assert!(!store.is_empty());
    }

    /// RFC 5937 anchor constraints are enforced only when the anchor declares
    /// them, so they must not disturb the embedded bundle: no embedded root
    /// carries an `extKeyUsage`, and the handful that carry a
    /// `pathLenConstraint` all leave room for at least one intermediate.
    #[test]
    fn embedded_roots_carry_no_blocking_self_constraints() {
        let store = RootCertStore::with_embedded_roots();
        for anchor in &store.anchors {
            assert!(
                anchor.extended_key_usages.is_empty(),
                "an embedded root declares an EKU; revisit RFC 5937 enforcement"
            );
            if let Some(plc) = anchor.path_len_constraint {
                assert!(plc >= 1, "an embedded root declares pathlen:0");
            }
        }
    }

    #[test]
    fn add_embedded_roots_reports_count() {
        let mut store = RootCertStore::new();
        let added = store.add_embedded_roots();
        assert_eq!(added, store.len());
        assert!(added > 50);
    }
}
