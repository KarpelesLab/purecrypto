//! A store of trusted root certificates (trust anchors).

use crate::tls::Error;
use crate::x509::{AnyPublicKey, Certificate, NameConstraints};
use alloc::sync::Arc;
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
    /// The anchor's own `basicConstraints.cA` flag, `None` when the
    /// certificate carries no `basicConstraints` extension (v1 roots, and a
    /// few old v3 ones). A trust anchor is normally "a name and a key" (RFC
    /// 5280 §6.1), but the pinning pattern — adding a server's own
    /// *end-entity* certificate to the store so it anchors itself — puts
    /// `CA:FALSE` certificates in here too. Such an anchor must be able to
    /// vouch for itself and nothing else: without this flag the pinned
    /// key could sign a certificate for any name and the result would
    /// validate (OpenSSL: `X509_V_ERR_INVALID_CA`). Only consulted when the
    /// anchor issues a certificate *other than itself*.
    pub(crate) is_ca: Option<bool>,
    /// The anchor's own `keyUsage` bit mask (wire order, bit 0 = MSB), `None`
    /// when the extension is absent. Like `is_ca`, consulted only when the
    /// anchor issues a certificate other than itself: an anchor that carries
    /// `keyUsage` without `keyCertSign` — again the pinned end-entity case,
    /// typically `digitalSignature` only — may not issue certificates (RFC
    /// 5280 §4.2.1.3; OpenSSL: `X509_V_ERR_KEYUSAGE_NO_CERTSIGN`).
    pub(crate) key_usage: Option<u16>,
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
/// [`RootCertStore::add_der`] for the handling of constraint forms the
/// validator cannot evaluate.
///
/// A store can also carry a *distrust list*: public keys and certificates
/// that must never be accepted, wherever they appear in a chain (a
/// compromised intermediate, a disabled root reached through a cross-sign).
/// See [`RootCertStore::distrust_spki_sha256`]. The embedded bundle
/// (`RootCertStore::with_embedded_roots`, feature `embedded-roots`) loads `cacrt`'s blocklist into it.
///
/// Cloning a store is cheap: the anchors are shared behind a reference
/// count (every connection built from a [`crate::tls::Config`] takes its own
/// copy of the store, and a full embedded root bundle is hundreds of parsed
/// keys and names), and are copied only when a shared store is added to.
#[derive(Clone, Default)]
pub struct RootCertStore {
    anchors: Arc<Vec<TrustAnchor>>,
    distrusted: Arc<Distrust>,
}

/// The distrust list of a [`RootCertStore`]: SHA-256 hashes of refused
/// `SubjectPublicKeyInfo`s and of refused whole certificates (DER).
#[derive(Clone, Default)]
struct Distrust {
    spki_sha256: Vec<[u8; 32]>,
    cert_sha256: Vec<[u8; 32]>,
}

impl Distrust {
    fn is_empty(&self) -> bool {
        self.spki_sha256.is_empty() && self.cert_sha256.is_empty()
    }
}

impl RootCertStore {
    /// An empty store.
    pub fn new() -> Self {
        RootCertStore {
            anchors: Arc::new(Vec::new()),
            distrusted: Arc::new(Distrust::default()),
        }
    }

    /// Adds a trust anchor from a DER-encoded root certificate, recording its
    /// subject name, public key, and any `nameConstraints` it declares.
    ///
    /// A `nameConstraints` extension on the root is retained and enforced
    /// over every chain that anchors at it (RFC 5280 §6.1.4), exactly as an
    /// in-chain CA's constraints would be — every subtree form the
    /// validator evaluates (dNSName, iPAddress, rfc822Name, URI,
    /// directoryName) and, for the forms it cannot (otherName, x400Address,
    /// ediPartyName, registeredID), the same fail-closed rule as for an
    /// in-chain CA: a subordinate certificate presenting a name of such a
    /// form is refused. Because an admin installing a constrained root does
    /// so deliberately, a root whose `nameConstraints` extension does not
    /// parse is rejected rather than added with its constraints silently
    /// ignored.
    pub fn add_der(&mut self, der: Vec<u8>) -> Result<(), Error> {
        let cert = Certificate::from_der(der).map_err(|_| Error::BadCertificate)?;
        let subject_der = cert
            .subject_der()
            .map_err(|_| Error::BadCertificate)?
            .to_vec();
        // Parsed with the insecure RSA floor (256 bits): an anchor key is
        // only ever used behind `SignaturePolicy::permits`, whose own
        // `min_rsa_bits` (2048 by default) decides whether a small root
        // can anchor anything. A sub-1024-bit root therefore loads but
        // verifies nothing until the policy is lowered explicitly.
        let key = cert
            .subject_public_key_insecure()
            .map_err(|_| Error::BadCertificate)?;
        let spki_der = cert.spki_der().map_err(|_| Error::BadCertificate)?.to_vec();
        let name_constraints = cert.name_constraints().map_err(|_| Error::BadCertificate)?;
        // RFC 5937 anchor constraints: keep the anchor's own
        // `pathLenConstraint` and `extKeyUsage`, when it declares them, so the
        // validator can honour them (see [`TrustAnchor`]). Both are optional
        // fields; an anchor that carries neither is unconstrained exactly as
        // before. A malformed extension is fail-closed like nameConstraints.
        let basic_constraints = cert
            .basic_constraints()
            .map_err(|_| Error::BadCertificate)?;
        let path_len_constraint =
            basic_constraints.and_then(|(is_ca, plc)| if is_ca { plc } else { None });
        // Whether the anchor may issue certificates at all (see
        // [`TrustAnchor::is_ca`] / [`TrustAnchor::key_usage`]): a pinned
        // end-entity certificate anchors itself and nothing else.
        let is_ca = basic_constraints.map(|(is_ca, _)| is_ca);
        let key_usage = cert.key_usage().map_err(|_| Error::BadCertificate)?;
        let extended_key_usages = cert
            .extended_key_usages()
            .map_err(|_| Error::BadCertificate)?;
        Arc::make_mut(&mut self.anchors).push(TrustAnchor {
            subject_der,
            key,
            spki_der,
            name_constraints,
            path_len_constraint,
            is_ca,
            key_usage,
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
    ///
    /// The store also carries `cacrt`'s blocklist (see
    /// [`Self::add_embedded_blocklist`]), so a compromised intermediate or a
    /// disabled root is refused even when a peer presents it.
    #[cfg(feature = "embedded-roots")]
    pub fn with_embedded_roots() -> Self {
        let mut store = RootCertStore::new();
        store.add_embedded_roots();
        store
    }

    /// Adds every certificate from the embedded [`cacrt`] bundle as a trust
    /// anchor, returning the number successfully added. Also loads `cacrt`'s
    /// blocklist (see [`Self::add_embedded_blocklist`]): the bundle and its
    /// blocklist are curated together, and the roots alone would still
    /// accept a compromised intermediate they issued. Requires the
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
        self.add_embedded_blocklist();
        added
    }

    /// Adds `cacrt`'s blocklist to this store's distrust list, returning the
    /// number of entries. It names disabled roots and compromised
    /// intermediates. Each entry distrusts its public key (so a re-issued or
    /// cross-signed certificate for the same key is refused too) and its
    /// exact certificate.
    ///
    /// [`Self::with_embedded_roots`] and [`Self::add_embedded_roots`] call
    /// this already; call it directly to apply the blocklist to a store
    /// built from another bundle (an OS `ca-certificates.crt`, say).
    /// Requires the `embedded-roots` feature.
    #[cfg(feature = "embedded-roots")]
    pub fn add_embedded_blocklist(&mut self) -> usize {
        let blocked = cacrt::blocked();
        for b in blocked {
            self.distrust_spki_sha256(*b.spki_sha256());
            self.distrust_cert_sha256(*b.cert_sha256());
        }
        blocked.len()
    }

    /// Distrusts every certificate whose `SubjectPublicKeyInfo` (DER) has
    /// this SHA-256 hash — the same value as an HPKP / `openssl x509
    /// -pubkey | openssl pkey -pubin -outform der | sha256sum` pin. Chain
    /// verification refuses such a certificate anywhere in the validated
    /// path, and refuses a trust anchor carrying that key.
    pub fn distrust_spki_sha256(&mut self, spki_sha256: [u8; 32]) {
        let d = Arc::make_mut(&mut self.distrusted);
        if !d.spki_sha256.contains(&spki_sha256) {
            d.spki_sha256.push(spki_sha256);
        }
    }

    /// Distrusts the one certificate whose DER encoding has this SHA-256
    /// hash (its usual fingerprint). Chain verification refuses it anywhere
    /// in the validated path. Prefer
    /// [`distrust_spki_sha256`](Self::distrust_spki_sha256) when the key
    /// itself is compromised: it also catches re-issued certificates.
    pub fn distrust_cert_sha256(&mut self, cert_sha256: [u8; 32]) {
        let d = Arc::make_mut(&mut self.distrusted);
        if !d.cert_sha256.contains(&cert_sha256) {
            d.cert_sha256.push(cert_sha256);
        }
    }

    /// Whether the DER certificate `cert_der` is on this store's distrust
    /// list, by its own fingerprint or by its public key. A certificate that
    /// does not parse is reported as not distrusted (verification refuses
    /// it anyway).
    pub fn is_distrusted(&self, cert_der: &[u8]) -> bool {
        if self.distrusted.is_empty() {
            return false;
        }
        match Certificate::from_der(cert_der.to_vec()) {
            Ok(cert) => self.check_distrust(&cert).is_err(),
            Err(_) => false,
        }
    }

    /// Refuses `cert` when its fingerprint or its public key is distrusted.
    pub(crate) fn check_distrust(&self, cert: &Certificate) -> Result<(), Error> {
        if self.distrusted.is_empty() {
            return Ok(());
        }
        let spki = cert.spki_der().map_err(|_| Error::BadCertificate)?;
        self.check_distrust_spki(spki)?;
        let fp = crate::hash::sha256(cert.to_der());
        if self.distrusted.cert_sha256.contains(&fp) {
            return Err(Error::BadCertificate);
        }
        Ok(())
    }

    /// Refuses a public key (`SubjectPublicKeyInfo` DER) that is distrusted.
    pub(crate) fn check_distrust_spki(&self, spki_der: &[u8]) -> Result<(), Error> {
        if self.distrusted.spki_sha256.is_empty() {
            return Ok(());
        }
        if self
            .distrusted
            .spki_sha256
            .contains(&crate::hash::sha256(spki_der))
        {
            return Err(Error::BadCertificate);
        }
        Ok(())
    }

    /// The distrust list as `(tag, hash)` pairs (`0` = public key, `1` =
    /// certificate), in insertion order. Folded into session-ticket bindings
    /// next to [`anchor_identities`](Self::anchor_identities).
    pub(crate) fn distrust_identities(&self) -> impl Iterator<Item = (u8, &[u8; 32])> {
        self.distrusted
            .spki_sha256
            .iter()
            .map(|h| (0u8, h))
            .chain(self.distrusted.cert_sha256.iter().map(|h| (1u8, h)))
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

    /// Identity material for each trust anchor, in insertion order: the
    /// anchor's subject `Name` DER and its `SubjectPublicKeyInfo` DER.
    ///
    /// Used to derive a stable digest of "which roots does this store
    /// trust" — e.g. to bind a session ticket to the exact client-auth
    /// trust configuration of the listener that issued it, so a listener
    /// with different roots cannot resume it.
    pub(crate) fn anchor_identities(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.anchors
            .iter()
            .map(|a| (a.subject_der.as_slice(), a.spki_der.as_slice()))
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
    /// carries an `extKeyUsage`, the handful that carry a
    /// `pathLenConstraint` all leave room for at least one intermediate, and
    /// none says `CA:FALSE` or carries a `keyUsage` without `keyCertSign`
    /// (either would stop the root issuing anything).
    #[test]
    fn embedded_roots_carry_no_blocking_self_constraints() {
        let store = RootCertStore::with_embedded_roots();
        for anchor in store.anchors.iter() {
            assert!(
                anchor.extended_key_usages.is_empty(),
                "an embedded root declares an EKU; revisit RFC 5937 enforcement"
            );
            if let Some(plc) = anchor.path_len_constraint {
                assert!(plc >= 1, "an embedded root declares pathlen:0");
            }
            assert_ne!(
                anchor.is_ca,
                Some(false),
                "an embedded root declares CA:FALSE"
            );
            if let Some(ku) = anchor.key_usage {
                // keyCertSign is bit 5, i.e. `0x04` in the MSB-first mask
                // `Certificate::key_usage` returns.
                assert!(
                    ku & 0x04 != 0,
                    "an embedded root declares keyUsage without keyCertSign"
                );
            }
        }
    }

    /// `cacrt`'s blocklist is loaded with the bundle, and none of the
    /// bundled roots is itself on it (that would silently distrust a root
    /// the bundle ships).
    #[test]
    fn embedded_roots_load_the_blocklist() {
        let store = RootCertStore::with_embedded_roots();
        let blocked = cacrt::blocked();
        assert!(!blocked.is_empty(), "cacrt ships an empty blocklist");
        let spkis = store.distrust_identities().filter(|(t, _)| *t == 0).count();
        let certs = store.distrust_identities().filter(|(t, _)| *t == 1).count();
        assert!(spkis >= 1 && spkis <= blocked.len());
        assert_eq!(certs, blocked.len());
        for ca in cacrt::all() {
            assert!(
                !store.is_distrusted(ca.der()),
                "embedded root {} is on the blocklist",
                ca.label()
            );
        }

        let mut custom = RootCertStore::new();
        assert_eq!(custom.add_embedded_blocklist(), blocked.len());
        assert!(custom.is_empty());
    }

    #[test]
    fn add_embedded_roots_reports_count() {
        let mut store = RootCertStore::new();
        let added = store.add_embedded_roots();
        assert_eq!(added, store.len());
        assert!(added > 50);
    }
}
