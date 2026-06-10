//! Certificate-chain verification against a [`RootCertStore`].
//!
//! Given the peer's certificate chain (end-entity first, as sent in the TLS
//! `Certificate` message), each certificate is checked to be signed by the
//! next and names are matched issuer-to-subject, walking upward until a
//! certificate issued by a trusted root in the store is reached. That first
//! anchorable certificate terminates the path: any further certificates the
//! peer supplied above it (e.g. a redundant or cross-signed root) are
//! discarded. When a verification time is supplied, every certificate in the
//! validated path — but not the trust anchor itself — is checked to be within
//! its validity period.
//!
//! Per RFC 5280:
//!   * every non-leaf certificate must carry `basicConstraints.cA = true`
//!     (or it cannot issue subordinates),
//!   * `pathLenConstraint`, when present on a non-leaf, bounds the number
//!     of intermediates that may follow it,
//!   * the inner `signature` AlgorithmIdentifier inside `TBSCertificate`
//!     MUST equal the outer `signatureAlgorithm` (RFC 5280 §4.1.1.2 /
//!     §4.1.2.3),
//!   * any `critical` extension we don't understand MUST cause rejection
//!     (RFC 5280 §4.2),
//!   * every non-leaf MUST have `keyUsage.keyCertSign` when it carries a
//!     `keyUsage` extension (RFC 5280 §4.2.1.3),
//!   * if the leaf carries a `keyUsage` extension it must include
//!     `digitalSignature` (TLS 1.3 servers authenticate with a signature),
//!   * if the leaf carries an `extKeyUsage` extension it must include
//!     `id-kp-serverAuth`.
//!
//! [`verify_hostname`] separately matches the end-entity certificate against
//! the expected host name (subjectAltName dNSNames, falling back to the subject
//! common name).

use super::crls::CrlStore;
use super::store::{RootCertStore, TrustAnchor};
use crate::signature_registry::{SignaturePolicy, find_by_oid};
use crate::tls::Error;
use crate::x509::{AnyPublicKey, Certificate, Time, Validity, oid};
use alloc::vec::Vec;

/// `keyUsage` bit-0 `digitalSignature` (RFC 5280 §4.2.1.3).
const KU_DIGITAL_SIGNATURE: u16 = 0x80; // bit 0 in BIT STRING wire order = MSB of byte 0
/// `keyUsage` bit-5 `keyCertSign`.
const KU_KEY_CERT_SIGN: u16 = 0x04;

/// Upper bound on the length of a peer-supplied certificate chain. Each cert
/// triggers a signature verification (RSA / ECDSA / PQ) plus repeated DN
/// parsing; an unbounded chain is a DoS vector during TLS handshake. The
/// value is generous — production CAs rarely exceed 4 — but caps the worst
/// case at a few milliseconds of verification work.
const MAX_CHAIN_LEN: usize = 10;

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
///
/// Equivalent to [`verify_chain_for_purpose`] with [`ChainPurpose::Server`]
/// (the most common case). Use the explicit form for client-cert
/// verification in mTLS.
#[allow(dead_code)] // useful for tests / future internal callers
pub(crate) fn verify_chain(
    store: &RootCertStore,
    chain: &[Vec<u8>],
    now: Option<&Time>,
    policy: &SignaturePolicy,
) -> Result<AnyPublicKey, Error> {
    verify_chain_for_purpose(store, chain, now, policy, ChainPurpose::Server)
}

/// Like [`verify_chain`], but additionally consults `crls` for revocation
/// after the regular signature/anchoring checks succeed.
///
/// CRL coverage is **opt-in advisory**: a chain is rejected only when a CRL
/// from `crls` whose issuer matches and whose signature verifies under the
/// chain issuer's key contains the cert's serial. CRLs signed by an unknown
/// key, or whose issuer name does not appear in the chain, are silently
/// ignored.
pub(crate) fn verify_chain_with_crls(
    store: &RootCertStore,
    crls: &CrlStore,
    chain: &[Vec<u8>],
    now: Option<&Time>,
    policy: &SignaturePolicy,
) -> Result<AnyPublicKey, Error> {
    verify_chain_with_crls_for_purpose(store, crls, chain, now, policy, ChainPurpose::Server)
}

/// Whether the leaf is the *server* (verified by a TLS client) or the
/// *client* (verified by a TLS server in mTLS). The distinction matters for
/// the leaf's `extKeyUsage`: server certs need `id-kp-serverAuth`, client
/// certs need `id-kp-clientAuth` (RFC 5280 §4.2.1.12). Conflating the two
/// would let a server cert authenticate as a client (or vice versa).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChainPurpose {
    /// The leaf is a TLS server certificate. Requires `id-kp-serverAuth`
    /// EKU when an EKU extension is present.
    Server,
    /// The leaf is a TLS client certificate (mTLS). Requires
    /// `id-kp-clientAuth` EKU when an EKU extension is present.
    Client,
}

#[allow(dead_code)] // useful for tests / future internal callers
pub(crate) fn verify_chain_for_purpose(
    store: &RootCertStore,
    chain: &[Vec<u8>],
    now: Option<&Time>,
    policy: &SignaturePolicy,
    purpose: ChainPurpose,
) -> Result<AnyPublicKey, Error> {
    let empty = CrlStore::new();
    verify_chain_with_crls_for_purpose(store, &empty, chain, now, policy, purpose)
}

pub(crate) fn verify_chain_with_crls_for_purpose(
    store: &RootCertStore,
    crls: &CrlStore,
    chain: &[Vec<u8>],
    now: Option<&Time>,
    policy: &SignaturePolicy,
    purpose: ChainPurpose,
) -> Result<AnyPublicKey, Error> {
    if chain.is_empty() {
        return Err(Error::BadCertificate);
    }
    // Cap the chain length to bound verification cost (DoS protection).
    if chain.len() > MAX_CHAIN_LEN {
        return Err(Error::BadCertificate);
    }

    let certs: Vec<Certificate> = chain
        .iter()
        .map(|der| Certificate::from_der(der.clone()))
        .collect::<Result<_, _>>()
        .map_err(|_| Error::BadCertificate)?;

    // Build and verify the trust path. Walk the supplied chain from the leaf
    // (index 0) upward: each certificate must either be issued by a trusted
    // anchor in `store` — at which point the path terminates — or be signed by
    // the next certificate in the chain (which must itself be a CA, enforced
    // below). The FIRST certificate whose issuer is a trusted anchor closes the
    // path; any certificates the peer supplied ABOVE that point are discarded.
    //
    // Stopping at the first trusted anchor (rather than only anchoring the
    // topmost supplied cert) is required, not merely lenient:
    //   * a trust anchor may legitimately be reached below the top of the
    //     presented chain — e.g. a server sends `[leaf, intermediate, transit
    //     CA, cross-signed root]` where the *transit CA* is issued by a root we
    //     already trust, and the final cross-signed root is anchored to some
    //     other CA we don't carry; and
    //   * a peer may append an expired or cross-signed copy of the root (e.g.
    //     the 2021 "DST Root CA X3" cross-sign of ISRG Root X1).
    // In both cases we trust the in-store anchor directly and never look above
    // it. Consequently the validity, algorithm-identifier, critical-extension,
    // and name/CA-constraint checks run over the validated path ONLY — never
    // over the discarded tail (RFC 5280 §6.1: validation stops at a trust
    // anchor, and the anchor itself is not validity-checked).
    let mut anchor_at: Option<usize> = None;
    let mut matched_anchor: Option<&TrustAnchor> = None;
    for i in 0..certs.len() {
        // (a) Is certs[i] issued directly by a trusted anchor? Anchors match by
        //     byte-exact issuer/subject Name equality (RFC 5280 §7.1); several
        //     anchors may share a Name (cross-signed renewal), so accept the
        //     first whose key verifies certs[i]'s signature under `policy`.
        let issuer_der = certs[i].issuer_der().map_err(|_| Error::BadCertificate)?;
        let mut anchored: Option<&TrustAnchor> = None;
        for anchor in store.anchors_with_subject(issuer_der) {
            if verify_cert_against_issuer(&certs[i], &anchor.key, policy).is_ok() {
                anchored = Some(anchor);
                break;
            }
        }
        if let Some(anchor) = anchored {
            // Path closes here: certs[0..=i] is the validated path. certs[i]
            // may still be revoked by a CRL signed by the anchor.
            check_revocation(&certs[i], &anchor.key, crls, now, policy)?;
            anchor_at = Some(i + 1);
            matched_anchor = Some(anchor);
            break;
        }

        // (b) Not anchored: certs[i] must be signed by the next supplied cert.
        //     Running off the top of the chain without reaching an anchor means
        //     the chain does not lead to a trusted root — reject.
        let Some(issuer) = certs.get(i + 1) else {
            return Err(Error::BadCertificate);
        };
        let issuer_key = issuer
            .subject_public_key()
            .map_err(|_| Error::BadCertificate)?;
        verify_cert_against_issuer(&certs[i], &issuer_key, policy)?;
        if names_differ(&certs[i], issuer)? {
            return Err(Error::BadCertificate);
        }
        check_revocation(&certs[i], &issuer_key, crls, now, policy)?;
    }

    // `anchor_at` is set whenever control reaches here: the loop either records
    // the anchor and breaks, or returns BadCertificate on the no-anchor path.
    let anchor_at = anchor_at.ok_or(Error::BadCertificate)?;
    let path = &certs[..anchor_at];

    // The remaining per-certificate checks apply to the validated path only.
    for cert in path {
        // RFC 5280 §4.1.1.2 / §4.1.2.3: inner `signature` AlgorithmIdentifier
        // in TBSCertificate MUST equal the outer `signatureAlgorithm`.
        cert.check_signature_algid_consistent()
            .map_err(|_| Error::BadCertificate)?;
        // RFC 5280 §4.2: a `critical` extension whose OID we don't understand
        // requires rejection.
        check_critical_extensions_recognized(cert)?;
    }

    // Each certificate in the path must currently be within its validity
    // period. The trust anchor itself is NOT validity-checked (RFC 5280 §6.1),
    // which is exactly why a supplied-but-expired root above the anchor is
    // harmless.
    if let Some(now) = now {
        for cert in path {
            let validity = cert.validity().map_err(|_| Error::BadCertificate)?;
            if !validity.accepts(now) {
                return Err(Error::BadCertificate);
            }
        }
    }

    // RFC 5280 §6.1.4 — nameConstraints accumulated across every CA in the
    // path, applied to the certificates beneath each. The matched trust
    // anchor's own constraints (retained by the store at add time) seed the
    // state, so a deliberately constrained root governs the whole path.
    // Critical constraints referencing GeneralName variants we don't
    // evaluate have already been rejected upstream — by
    // check_critical_extensions_recognized for in-chain CAs, and by
    // RootCertStore::add_der for the anchor.
    let anchor_nc = matched_anchor.and_then(|a| a.name_constraints.as_ref());
    enforce_name_constraints(path, anchor_nc)?;

    // RFC 5280 §4.2.1.9 / §4.2.1.3 / §4.2.1.12 enforcement (CA / keyUsage /
    // extKeyUsage), over the validated path.
    enforce_constraints(path, purpose)?;

    certs[0]
        .subject_public_key()
        .map_err(|_| Error::BadCertificate)
}

/// Consults `crls` for any CRL whose issuer name matches `cert.issuer_der()`
/// and whose signature verifies against `issuer_key`. If a matching CRL
/// lists `cert.serial_bytes()`, the cert is revoked (returns
/// [`Error::BadCertificate`]).
///
/// A CRL outside its `thisUpdate..=nextUpdate` window (when `now` is given)
/// is treated as "not covering" — advisory behavior. CRLs that fail their
/// own signature verification under the issuer key are silently skipped
/// (an attacker cannot make us reject a chain by injecting a forged CRL).
fn check_revocation(
    cert: &Certificate,
    issuer_key: &AnyPublicKey,
    crls: &CrlStore,
    now: Option<&Time>,
    policy: &SignaturePolicy,
) -> Result<(), Error> {
    let cert_issuer = cert.issuer_der().map_err(|_| Error::BadCertificate)?;
    let serial = cert.serial_bytes().map_err(|_| Error::BadCertificate)?;
    let issuer_spki = issuer_key.to_spki_der();
    for crl in crls.crls_with_issuer(cert_issuer) {
        // RFC 5280 §5.1.1.2: the CRL's `signatureAlgorithm` must be one we
        // accept under `policy` — the same whitelist that gates cert-chain
        // signatures. A CRL signed with e.g. SHA-1-RSA is silently ignored
        // (treated as "not consulted") under `SignaturePolicy::modern()`.
        let Ok(crl_sig_alg) = crl.signature_algorithm_oid() else {
            continue;
        };
        let Some(crl_algo) = find_by_oid(&crl_sig_alg) else {
            continue;
        };
        if !policy.permits(crl_algo, &issuer_spki) {
            continue;
        }
        // Skip CRLs not signed by this issuer.
        if crl.verify_signature_with(issuer_key).is_err() {
            continue;
        }
        // Skip CRLs that are not currently valid (advisory: stale CRL ≈ no CRL).
        if let Some(n) = now {
            let this_update = crl.this_update().map_err(|_| Error::BadCertificate)?;
            let next_update = crl.next_update().map_err(|_| Error::BadCertificate)?;
            let covers = match next_update {
                Some(na) => Validity::new(this_update.clone(), na).accepts(n),
                // No nextUpdate ⇒ treat as not stale (RFC 5280 allows nextUpdate
                // to be omitted; clients accept indefinite freshness).
                None => true,
            };
            if !covers {
                continue;
            }
        }
        // A covering, validly-signed CRL gets the deciding vote.
        let revoked = crl.is_revoked(serial).map_err(|_| Error::BadCertificate)?;
        if revoked {
            return Err(Error::BadCertificate);
        }
    }
    Ok(())
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
///   * every non-leaf with a `keyUsage` extension must include `keyCertSign`
///     (RFC 5280 §4.2.1.3);
///   * `pathLenConstraint` on a non-leaf bounds the number of intermediates
///     between it and the leaf;
///   * if the leaf carries `keyUsage`, `digitalSignature` (bit 0) must be set;
///   * if the leaf carries `extKeyUsage`, it must include `id-kp-serverAuth`.
fn enforce_constraints(certs: &[Certificate], purpose: ChainPurpose) -> Result<(), Error> {
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
        // If a `keyUsage` extension is present, `keyCertSign` (bit 5) MUST
        // be set for this CA to sign certificates (RFC 5280 §4.2.1.3).
        if let Some(mask) = cert.key_usage().map_err(|_| Error::BadCertificate)?
            && (mask & KU_KEY_CERT_SIGN) == 0
        {
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
    let required = match purpose {
        ChainPurpose::Server => oid::ID_KP_SERVER_AUTH,
        ChainPurpose::Client => oid::ID_KP_CLIENT_AUTH,
    };
    if !ekus.is_empty() && !ekus.iter().any(|o| o.as_slice() == required) {
        return Err(Error::BadCertificate);
    }
    Ok(())
}

/// RFC 5280 §6.1.4 — name-constraints propagation.
///
/// A CA's `nameConstraints` extension applies to **every** certificate that
/// appears below it in the path — each subordinate intermediate CA *and* the
/// end-entity leaf — not only the leaf. The earlier implementation collected
/// every CA's permitted/excluded subtrees and applied them solely to the
/// leaf's SAN entries, so a constrained CA could issue an out-of-constraint
/// sub-CA that then issued an in-constraint leaf and the chain wrongly
/// validated (the intermediate's own names were never checked).
///
/// This walks the presented chain from the topmost supplied CA downward: as
/// each CA's constraints come into scope, they are enforced against the names
/// of every certificate beneath it (intermediates and leaf), using the same
/// `dns_in_subtree` / `ip_in_subtree` matchers. For each such certificate its
/// dNSName / iPAddress SAN entries (with a DNS-plausible subject commonName
/// standing in for the dNSName entries when the certificate has no dNSName
/// SAN — see [`enforce_constraints_on_cert`]) must satisfy, for every
/// in-scope CA constraint:
///   * the cert must NOT match any excluded subtree (any match is fatal);
///   * when a CA declares ANY permitted dNSName subtree, each of the cert's
///     DNS SANs must match at least one such entry; same for iPAddress.
///
/// `anchor_constraints` carries the matched trust anchor's own
/// `nameConstraints` (parsed and retained by [`RootCertStore`] when the root
/// was added). The anchor sits above the topmost supplied CA, so its
/// constraints are in scope for **every** certificate in the validated path
/// — they seed the constraint state before the walk begins, exactly as an
/// in-chain CA's constraints govern everything beneath it.
///
/// Scope / limitations:
///   * directoryName (subject DN) subtree constraints are NOT evaluated: the
///     parsed [`crate::x509::NameConstraints`] surfaces only dNSName and
///     iPAddress subtrees, and any constraint referencing another
///     GeneralName variant (including directoryName) sets a
///     `has_unenforceable_*` flag that causes
///     `check_critical_extensions_recognized` to reject the chain when the
///     constraint is critical. directoryName-subtree matching is therefore
///     flagged-for-review rather than implemented (possibly-wrong) here.
///   * Constraints referencing GeneralName variants other than dNSName /
///     iPAddress are skipped — a critical such constraint on an in-chain CA
///     has already been rejected upstream, and an anchor carrying one is
///     refused by [`RootCertStore::add_der`] regardless of criticality.
fn enforce_name_constraints(
    certs: &[Certificate],
    anchor_constraints: Option<&crate::x509::NameConstraints>,
) -> Result<(), Error> {
    // Pre-parse each certificate's own constraints (only CAs, indices
    // 1..=last, can declare governing constraints; index 0 is the leaf). The
    // owned values live here so the `&` borrows accumulated in `in_scope`
    // remain valid for the whole walk.
    let mut ca_constraints: Vec<Option<crate::x509::NameConstraints>> =
        Vec::with_capacity(certs.len());
    ca_constraints.push(None); // leaf
    for cert in certs.iter().skip(1) {
        ca_constraints.push(cert.name_constraints().map_err(|_| Error::BadCertificate)?);
    }

    // Walk from the topmost supplied CA (`certs[last]`) down to the leaf
    // (`certs[0]`). The CA at index `i` issues the certificate at index
    // `i - 1`, so a CA's constraints govern every certificate at a strictly
    // lower index. We accumulate constraints as they come into scope (higher
    // CAs first) and, for each subordinate certificate, enforce all in-scope
    // CAs' constraints against that certificate's own SAN names. The trust
    // anchor issued `certs[last]`, so its constraints are in scope from the
    // very first iteration.
    let mut in_scope: Vec<&crate::x509::NameConstraints> = Vec::new();
    if let Some(nc) = anchor_constraints {
        in_scope.push(nc);
    }
    for idx in (0..certs.len()).rev() {
        // Constraints declared by CAs above this position must hold for the
        // certificate at `idx`. Only meaningful once at least one such
        // constraint is in scope, i.e. for certificates that have a
        // constraint-declaring CA above them.
        if !in_scope.is_empty() {
            enforce_constraints_on_cert(&certs[idx], &in_scope)?;
        }
        // This certificate's own constraints (if it is a CA that declared
        // any) now come into scope for every certificate below it.
        if let Some(nc) = &ca_constraints[idx] {
            in_scope.push(nc);
        }
    }
    Ok(())
}

/// Enforces the accumulated, in-scope name constraints (`active`) against a
/// single subordinate certificate's dNSName and iPAddress SAN entries — and,
/// when the certificate carries no dNSName SAN, against its subject
/// commonName (see below).
///
/// Each constraint in `active` is checked independently (intersection
/// semantics across CAs): an excluded match in any CA is fatal, and a CA that
/// declares any permitted dNSName / iPAddress subtree requires every
/// corresponding SAN of `cert` to fall within one of its entries.
fn enforce_constraints_on_cert(
    cert: &Certificate,
    active: &[&crate::x509::NameConstraints],
) -> Result<(), Error> {
    let mut dns = cert
        .subject_alt_names()
        .map_err(|_| Error::BadCertificate)?;
    let ips = cert.subject_alt_ips().map_err(|_| Error::BadCertificate)?;

    // CN fallback parity with `verify_hostname` (which falls back to matching
    // the subject commonName when a certificate has no dNSName SAN): a name
    // constraint must govern every name a relying party might accept. When
    // there is no dNSName SAN and the CN is plausible as a DNS name — judged
    // by the same syntax checks `parse_dns_names` applies to SAN dNSName
    // entries — the CN is evaluated against the permitted AND excluded
    // dNSName subtrees exactly as if it were a dNSName (matching common
    // practice, e.g. OpenSSL). Without this, a CA constrained by only
    // EXCLUDED subtrees could issue a SAN-less leaf whose CN sits inside the
    // excluded subtree and have it pass both this check and
    // `verify_hostname`'s CN fallback. IP-shaped CNs are kept out of the
    // dNSName evaluation; they are inert for hostname verification anyway —
    // `verify_hostname` never consults the CN for IP-literal hosts, and
    // `dns_name_matches` refuses IP-shaped patterns — so they are not checked
    // against iPAddress constraints either.
    if dns.is_empty()
        && let Some(cn) = cert
            .subject()
            .map_err(|_| Error::BadCertificate)?
            .common_name
        && cn_is_plausible_dns_name(&cn)
    {
        dns.push(cn);
    }

    // Refuse certificates that present NO evaluable name at all (no SAN, no
    // DNS-plausible CN) while governed by an active *permitted* constraint:
    // the dNSName / iPAddress checks below only iterate the collected names,
    // so a nameless certificate would slip past every permitted-subtree
    // constraint trivially. When some active CA declared a permitted dNSName
    // / iPAddress subtree, require the certificate to carry a name those
    // constraints can apply to. (Modern PKI — CA/B Forum BR §7.1.4.2 —
    // already requires SAN on server certs.) A CA that declared ONLY
    // excluded subtrees does not by itself force a name to exist (RFC 5280:
    // a name absent from the cert cannot violate an exclusion).
    if dns.is_empty() && ips.is_empty() {
        let any_permitted = active
            .iter()
            .any(|nc| !nc.permitted_dns.is_empty() || !nc.permitted_ip.is_empty());
        if any_permitted {
            return Err(Error::BadCertificate);
        }
        return Ok(());
    }

    for nc in active {
        // Excluded subtrees: any match in any in-scope CA is fatal.
        for name in &dns {
            for base in &nc.excluded_dns {
                if dns_in_subtree(name, base) {
                    return Err(Error::BadCertificate);
                }
            }
        }
        for ip in &ips {
            let bytes = match ip {
                crate::x509::SanIp::V4(b) => &b[..],
                crate::x509::SanIp::V6(b) => &b[..],
            };
            for (addr, mask) in &nc.excluded_ip {
                if ip_in_subtree(bytes, addr, mask) {
                    return Err(Error::BadCertificate);
                }
            }
        }
        // Permitted subtrees: when this CA declares ANY permitted dNSName
        // subtree, every DNS SAN of `cert` must match at least one of them.
        if !nc.permitted_dns.is_empty() {
            for name in &dns {
                if !nc
                    .permitted_dns
                    .iter()
                    .any(|base| dns_in_subtree(name, base))
                {
                    return Err(Error::BadCertificate);
                }
            }
        }
        if !nc.permitted_ip.is_empty() {
            for ip in &ips {
                let bytes = match ip {
                    crate::x509::SanIp::V4(b) => &b[..],
                    crate::x509::SanIp::V6(b) => &b[..],
                };
                if !nc
                    .permitted_ip
                    .iter()
                    .any(|(addr, mask)| ip_in_subtree(bytes, addr, mask))
                {
                    return Err(Error::BadCertificate);
                }
            }
        }
    }
    Ok(())
}

/// True if `name` falls within the dNSName subtree `base` per RFC 5280
/// §4.2.1.10. The constraint is a domain name in standard form:
/// * base "example.com" matches "example.com" and any host of the form
///   "*.example.com" (label-aligned suffix match).
/// * base ".example.com" (leading dot) matches any "*.example.com" but
///   NOT "example.com" itself (this leading-dot convention is widely
///   implemented for "all subdomains, not the apex").
///
/// Case-insensitive compare per RFC 4343 §2.
fn dns_in_subtree(name: &str, base: &str) -> bool {
    let name_l = name.to_ascii_lowercase();
    let base_l = base.to_ascii_lowercase();
    if let Some(suffix) = base_l.strip_prefix('.') {
        // ".example.com" → match strict subdomains only.
        if name_l.len() <= suffix.len() {
            return false;
        }
        let cut = name_l.len() - suffix.len();
        return name_l.as_bytes()[cut - 1] == b'.' && name_l[cut..] == *suffix;
    }
    // "example.com" → exact match OR label-aligned suffix.
    if name_l == base_l {
        return true;
    }
    if name_l.len() > base_l.len() {
        let cut = name_l.len() - base_l.len();
        return name_l.as_bytes()[cut - 1] == b'.' && name_l[cut..] == base_l;
    }
    false
}

/// True if `host` (the raw SAN iPAddress octet string) is within the CIDR
/// subtree `addr / mask`. Lengths must match (both v4 = 4, both v6 = 16);
/// length mismatch returns false (a v4 host cannot match a v6 constraint
/// or vice versa).
fn ip_in_subtree(host: &[u8], addr: &[u8], mask: &[u8]) -> bool {
    if host.len() != addr.len() || host.len() != mask.len() {
        return false;
    }
    for i in 0..host.len() {
        if (host[i] & mask[i]) != (addr[i] & mask[i]) {
            return false;
        }
    }
    true
}

/// RFC 5280 §4.2: reject the certificate if it carries any critical extension
/// whose OID we don't recognize. The handler set (basicConstraints, keyUsage,
/// extKeyUsage, subjectAltName, nameConstraints) is intentionally narrow —
/// every critical extension outside this set is treated as "we cannot enforce
/// this constraint", which must result in rejection.
///
/// `nameConstraints` is special: it's "recognized" only when every GeneralName
/// subtree references a variant we evaluate (dNSName / iPAddress). If a
/// critical constraint mentions any other type we route it through the same
/// fail-closed path as an unknown OID — accepting it would let a constraint
/// we can't check appear to have been honored.
fn check_critical_extensions_recognized(cert: &Certificate) -> Result<(), Error> {
    let critical = cert
        .critical_extension_oids()
        .map_err(|_| Error::BadCertificate)?;
    for o in critical {
        let bytes = o.as_slice();
        if bytes == oid::BASIC_CONSTRAINTS
            || bytes == oid::KEY_USAGE
            || bytes == oid::EXT_KEY_USAGE
            || bytes == oid::SUBJECT_ALT_NAME
        {
            continue;
        }
        if bytes == oid::NAME_CONSTRAINTS {
            // Re-parse to confirm we can evaluate every subtree. If any
            // unenforceable type slipped in, treat the critical extension
            // as unknown and reject.
            let nc = cert
                .name_constraints()
                .map_err(|_| Error::BadCertificate)?
                .ok_or(Error::BadCertificate)?;
            if nc.has_unenforceable_permitted || nc.has_unenforceable_excluded {
                return Err(Error::BadCertificate);
            }
            continue;
        }
        return Err(Error::BadCertificate);
    }
    Ok(())
}

/// Whether `cert.issuer != issuer.subject`. Compared as raw DER bytes per
/// RFC 5280 §7.1: any difference in encoding (PrintableString vs UTF8String,
/// extra attributes, multi-valued RDNs) MUST result in a non-match, which the
/// parsed-form comparison missed.
fn names_differ(cert: &Certificate, issuer: &Certificate) -> Result<bool, Error> {
    let cert_issuer = cert.issuer_der().map_err(|_| Error::BadCertificate)?;
    let issuer_subject = issuer.subject_der().map_err(|_| Error::BadCertificate)?;
    Ok(cert_issuer != issuer_subject)
}

/// Checks that the end-entity certificate identifies `host`. Prefers the
/// `subjectAltName` dNSName entries (RFC 6125); if there are none, falls back
/// to the subject common name.
pub(crate) fn verify_hostname(cert: &Certificate, host: &str) -> Result<(), Error> {
    // If the caller asked for an IP-literal host, the only spec-correct
    // SAN slot that can authorise it is iPAddress ([7]). Dispatch
    // accordingly; dNSName entries and the CN fallback are not consulted
    // for IP-literal reference identifiers (RFC 6125 §6.5.2).
    if let Some(host_bytes) = parse_host_ip(host) {
        let ips = cert.subject_alt_ips().map_err(|_| Error::BadCertificate)?;
        let matched = ips.iter().any(|san| match (san, &host_bytes) {
            (crate::x509::SanIp::V4(a), HostIp::V4(b)) => a == b,
            (crate::x509::SanIp::V6(a), HostIp::V6(b)) => a == b,
            _ => false,
        });
        return if matched {
            Ok(())
        } else {
            Err(Error::BadCertificate)
        };
    }
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

/// Parsed IP-literal host. `None` means the host is not an IP literal
/// (so dNSName matching is the right path).
enum HostIp {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// Parses an IP-literal host (IPv4 dotted-quad, or any colon-bearing
/// string for IPv6). Returns `None` if the host is not an IP literal.
fn parse_host_ip(host: &str) -> Option<HostIp> {
    if !host.bytes().any(|b| b == b':') {
        // Pure dotted-quad IPv4.
        return crate::x509::cert::parse_ipv4(host).map(HostIp::V4);
    }
    parse_ipv6(host).map(HostIp::V6)
}

/// Parses an IPv6 literal in the canonical full or compressed forms
/// (RFC 4291 §2.2). Embedded-IPv4 form (`::ffff:192.0.2.1`) is
/// recognised on input — host machines accept it — and is returned as
/// its 16-byte IPv6 representation. The SAN-side matcher then refuses
/// to match it against a 16-byte iPAddress entry because
/// [`Certificate::subject_alt_ips`] never surfaces IPv4-mapped-IPv6
/// SAN entries. So a leaf claiming `::ffff:10.0.0.1` in iPAddress can
/// match neither `10.0.0.1` (the 4-byte SAN that would have been
/// correct) nor `::ffff:10.0.0.1` (rejected at parse).
fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    // Split on "::" to handle compression.
    let (head, tail) = if let Some(idx) = s.find("::") {
        let head = &s[..idx];
        let tail = &s[idx + 2..];
        if head.contains("::") || tail.contains("::") {
            return None;
        }
        (head, tail)
    } else {
        (s, "")
    };
    let mut head_groups: alloc::vec::Vec<u16> = alloc::vec::Vec::new();
    let mut tail_groups: alloc::vec::Vec<u16> = alloc::vec::Vec::new();
    for (target, src) in [(&mut head_groups, head), (&mut tail_groups, tail)] {
        if src.is_empty() {
            continue;
        }
        for group in src.split(':') {
            // Embedded-IPv4 in the last group (e.g. "::ffff:10.0.0.1") —
            // expand to two 16-bit groups.
            if group.contains('.') {
                let v4 = crate::x509::cert::parse_ipv4(group)?;
                target.push(((v4[0] as u16) << 8) | v4[1] as u16);
                target.push(((v4[2] as u16) << 8) | v4[3] as u16);
                continue;
            }
            if group.is_empty() || group.len() > 4 {
                return None;
            }
            let g = u16::from_str_radix(group, 16).ok()?;
            target.push(g);
        }
    }
    let total = head_groups.len() + tail_groups.len();
    if total > 8 {
        return None;
    }
    let zero_groups = 8 - total;
    // Compression `::` is required when total < 8 unless the original
    // string contained one explicit `::`.
    if zero_groups > 0 && !s.contains("::") {
        return None;
    }
    let mut out = [0u8; 16];
    let mut i = 0;
    for g in head_groups
        .into_iter()
        .chain(core::iter::repeat_n(0, zero_groups))
        .chain(tail_groups)
    {
        out[i] = (g >> 8) as u8;
        out[i + 1] = (g & 0xff) as u8;
        i += 2;
    }
    Some(out)
}

/// Matches a certificate dNSName `pattern` against `host`, case-insensitively,
/// allowing a single leftmost-label `*` wildcard (`*.example.com` matches
/// `a.example.com` but not `example.com` or `a.b.example.com`).
fn dns_name_matches(pattern: &str, host: &str) -> bool {
    // RFC 6125 §6.5.2: dNSName / CN-fallback matching MUST NOT be used
    // for IP-literal hosts. If either side looks IP-shaped, refuse the
    // match — IPs belong in the iPAddress SAN slot and have a separate
    // matcher.
    if looks_like_ip(pattern) || looks_like_ip(host) {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // RFC 6125 §6.4.3: wildcard is the leftmost label only, must
        // cover exactly one label, and the wildcard label MUST NOT be
        // partial (`f*.example.com` is forbidden — already prevented by
        // requiring the prefix `*.`).
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

/// Whether a subject commonName is plausible as a DNS name, applying the same
/// syntax checks `parse_dns_names` (the SAN parser in `x509::cert`) applies
/// to SAN dNSName entries: non-empty, printable ASCII only (`0x20..=0x7E` — no
/// control characters, NUL, or DEL), and not an IP literal in disguise. Only
/// such CNs take part in the dNSName name-constraint evaluation (the
/// CN-fallback path of [`enforce_constraints_on_cert`]).
fn cn_is_plausible_dns_name(cn: &str) -> bool {
    !cn.is_empty() && cn.bytes().all(|b| (0x20..=0x7E).contains(&b)) && !looks_like_ip(cn)
}

/// Coarse IP-literal heuristic; defense-in-depth against bytes that
/// slipped past [`parse_dns_names`] (e.g. via CN-fallback). Matches the
/// same shape: any colon, or an IPv4 dotted-quad of 1-3-digit labels.
fn looks_like_ip(s: &str) -> bool {
    if s.bytes().any(|b| b == b':') {
        return true;
    }
    let mut count = 0usize;
    for label in s.split('.') {
        count += 1;
        if count > 4 {
            return false;
        }
        if label.is_empty() || label.len() > 3 {
            return false;
        }
        if !label.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    count == 4
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

    /// A trust anchor reached BELOW the top of the presented chain must
    /// terminate verification; certificates the peer supplied above it are
    /// discarded. This is the real-world `example.com` shape: the chain ends
    /// with a cross-signed root whose own issuer is some CA we don't carry,
    /// while an earlier "transit"/intermediate cert is issued by a root we DO
    /// trust. Regression for only ever anchoring `certs.last()`.
    #[test]
    fn anchors_at_first_trusted_ca_ignoring_cross_signed_tail() {
        let root_key = rsa_test_key_a(); // the root we trust
        let other_key = rsa_test_key_b(); // an unrelated CA we do NOT trust
        let root_name = DistinguishedName::common_name("SSL.com TLS ECC Root CA 2022");
        let transit_name = DistinguishedName::common_name("SSL.com TLS Transit ECC CA R2");
        let leaf_name = DistinguishedName::common_name("example.com");
        let other_ca_name = DistinguishedName::common_name("AAA Certificate Services");

        // The transit CA is issued by the trusted root.
        let transit = Certificate::issue(
            &root_key,
            &root_name,
            &transit_name,
            &other_key.public_key(),
            &validity(),
            2,
            true,
        )
        .unwrap();
        // The leaf is issued by the transit CA (signed with other_key, whose
        // public half is the transit CA's subject key).
        let leaf = Certificate::issue(
            &other_key,
            &transit_name,
            &leaf_name,
            &other_key.public_key(),
            &validity(),
            3,
            false,
        )
        .unwrap();
        // A cross-signed copy of the root: subject = root_name, but ISSUED BY a
        // different CA ("AAA Certificate Services") that is not in our store.
        // Its own signature therefore cannot anchor.
        let cross_root = Certificate::issue(
            &other_key,
            &other_ca_name,
            &root_name,
            &root_key.public_key(),
            &validity(),
            4,
            true,
        )
        .unwrap();

        // Trust only the SSL.com root.
        let real_root =
            Certificate::self_signed(&root_key, &root_name, &validity(), 1, true).unwrap();
        let mut store = RootCertStore::new();
        store.add_der(real_root.to_der().to_vec()).unwrap();

        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        // Full presented chain, ending in the un-anchorable cross-signed root.
        let chain = alloc::vec![
            leaf.to_der().to_vec(),
            transit.to_der().to_vec(),
            cross_root.to_der().to_vec(),
        ];
        // Anchors at `transit` (issued by the trusted root); cross_root is
        // discarded. Before the fix this returned BadCertificate because only
        // cross_root's issuer ("AAA Certificate Services") was tried.
        verify_chain(&store, &chain, Some(&now), &policy()).unwrap();
    }

    /// A peer that appends an EXPIRED copy of the root above the trust anchor
    /// (cf. the 2021 "DST Root CA X3" cross-sign of ISRG Root X1) must still
    /// validate: certificates above the anchor are not part of the path and are
    /// never validity-checked. Regression for validity being enforced over the
    /// whole supplied chain instead of the validated path.
    #[test]
    fn ignores_expired_root_supplied_above_anchor() {
        let root_key = rsa_test_key_a();
        let int_key = rsa_test_key_b();
        let root_name = DistinguishedName::common_name("Root");
        let int_name = DistinguishedName::common_name("Intermediate");
        let leaf_name = DistinguishedName::common_name("leaf.example");

        let intermediate = Certificate::issue(
            &root_key,
            &root_name,
            &int_name,
            &int_key.public_key(),
            &validity(),
            2,
            true,
        )
        .unwrap();
        let leaf = Certificate::issue(
            &int_key,
            &int_name,
            &leaf_name,
            &int_key.public_key(),
            &validity(),
            3,
            false,
        )
        .unwrap();
        // An expired self-signed root with the same name + key as the anchor.
        let expired_root = Certificate::self_signed(
            &root_key,
            &root_name,
            &Validity::new(
                Time::utc(2020, 1, 1, 0, 0, 0),
                Time::utc(2021, 1, 1, 0, 0, 0),
            ),
            1,
            true,
        )
        .unwrap();

        // Trust the (valid) root; the chain carries the expired copy above the
        // anchor link.
        let valid_root =
            Certificate::self_signed(&root_key, &root_name, &validity(), 1, true).unwrap();
        let mut store = RootCertStore::new();
        store.add_der(valid_root.to_der().to_vec()).unwrap();

        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        let chain = alloc::vec![
            leaf.to_der().to_vec(),
            intermediate.to_der().to_vec(),
            expired_root.to_der().to_vec(),
        ];
        verify_chain(&store, &chain, Some(&now), &policy()).unwrap();
    }

    /// A trust anchor that appears only as an *intermediate* in the store (we
    /// trust the intermediate directly, not the root) terminates the path at
    /// that intermediate.
    #[test]
    fn anchors_at_trusted_intermediate() {
        let root_key = rsa_test_key_a();
        let int_key = rsa_test_key_b();
        let root_name = DistinguishedName::common_name("Root");
        let int_name = DistinguishedName::common_name("Intermediate");
        let leaf_name = DistinguishedName::common_name("leaf.example");

        let intermediate = Certificate::issue(
            &root_key,
            &root_name,
            &int_name,
            &int_key.public_key(),
            &validity(),
            2,
            true,
        )
        .unwrap();
        let leaf = Certificate::issue(
            &int_key,
            &int_name,
            &leaf_name,
            &int_key.public_key(),
            &validity(),
            3,
            false,
        )
        .unwrap();

        // Trust ONLY the intermediate.
        let mut store = RootCertStore::new();
        store.add_der(intermediate.to_der().to_vec()).unwrap();

        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        // chain = [leaf, intermediate]: anchors at the intermediate.
        verify_chain(
            &store,
            &[leaf.to_der().to_vec(), intermediate.to_der().to_vec()],
            Some(&now),
            &policy(),
        )
        .unwrap();
        // chain = [leaf] alone: leaf's issuer (the trusted intermediate) anchors.
        verify_chain(&store, &[leaf.to_der().to_vec()], Some(&now), &policy()).unwrap();
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

    /// A SHA-1-RSA legacy chain verifies only when the policy explicitly
    /// opts in via `permit("rsa-pkcs1-sha1")`. The default `modern()`
    /// policy refuses (SHA-1 is in the registry, not on the whitelist).
    #[test]
    fn legacy_sha1_chain_only_under_opt_in() {
        use crate::der::{encode_bit_string, encode_sequence};
        use crate::hash::Sha1;
        use crate::rsa::Pkcs1Digest;
        use crate::test_util::rsa_test_key_a;
        use crate::x509::cert::build_tbs_raw;
        use crate::x509::{AnyPublicKey, Certificate, algorithm_identifier};

        // Build a fully-consistent SHA-1-RSA self-signed cert: inner and
        // outer signature AlgorithmIdentifiers are BOTH `sha1WithRSAEncryption`
        // (RFC 5280 §4.1.1.2 requires equality, and chain validation enforces
        // it). The earlier version of this test crafted a mismatch on purpose
        // and is now rejected at the algid-consistency check before ever
        // reaching the policy whitelist — that's the desired behavior.
        assert_eq!(Sha1::DIGEST_INFO_PREFIX.len(), 15);
        let key = rsa_test_key_a();
        let subj = DistinguishedName::common_name("legacy.example");
        // Wrap the const-generic public key into a BoxedRsaPublicKey so we
        // can use the AnyPublicKey SPKI encoder.
        let mut n_bytes = alloc::vec![0u8; 256];
        key.public_key().modulus().write_be_bytes(&mut n_bytes);
        let mut e_bytes = alloc::vec![0u8; 256];
        key.public_key().exponent().write_be_bytes(&mut e_bytes);
        let boxed_pub = crate::rsa::BoxedRsaPublicKey::new(
            crate::bignum::BoxedUint::from_be_bytes(&n_bytes),
            crate::bignum::BoxedUint::from_be_bytes(&e_bytes),
        );
        let spki = AnyPublicKey::Rsa(boxed_pub).to_spki_der();
        let algid = algorithm_identifier(oid::SHA1_WITH_RSA, true);
        let exts = crate::x509::cert::legacy_extensions(true, &[]);
        let tbs = build_tbs_raw(1, &subj, &subj, &validity(), &spki, &algid, &exts);
        let sig = key.sign_pkcs1v15::<Sha1>(&tbs).unwrap();
        let der = encode_sequence(&[tbs.clone(), algid.clone(), encode_bit_string(&sig)].concat());
        let legacy = Certificate::from_der(der).unwrap();

        let mut store = RootCertStore::new();
        store.add_der(legacy.to_der().to_vec()).unwrap();

        // Default policy refuses.
        assert!(matches!(
            verify_chain(&store, &[legacy.to_der().to_vec()], None, &policy()),
            Err(Error::BadCertificate)
        ));
        // Opt-in permits.
        let with_sha1 = SignaturePolicy::modern().permit("rsa-pkcs1-sha1");
        verify_chain(&store, &[legacy.to_der().to_vec()], None, &with_sha1).unwrap();
    }

    /// A certificate whose inner `signature` AlgorithmIdentifier differs from
    /// its outer `signatureAlgorithm` is rejected at the consistency check,
    /// even when the signature itself would verify (RFC 5280 §4.1.1.2 /
    /// §4.1.2.3).
    #[test]
    fn rejects_inner_outer_algid_mismatch() {
        use crate::der::{encode_bit_string, encode_sequence};
        use crate::hash::Sha1;
        use crate::rsa::Pkcs1Digest;
        use crate::test_util::rsa_test_key_a;
        use crate::x509::cert::build_tbs_raw;
        use crate::x509::{AnyPublicKey, Certificate, algorithm_identifier};
        assert_eq!(Sha1::DIGEST_INFO_PREFIX.len(), 15);
        let key = rsa_test_key_a();
        let subj = DistinguishedName::common_name("mismatch.example");
        // Wrap the const-generic public key into a BoxedRsaPublicKey so we
        // can use the AnyPublicKey SPKI encoder.
        let mut n_bytes = alloc::vec![0u8; 256];
        key.public_key().modulus().write_be_bytes(&mut n_bytes);
        let mut e_bytes = alloc::vec![0u8; 256];
        key.public_key().exponent().write_be_bytes(&mut e_bytes);
        let boxed_pub = crate::rsa::BoxedRsaPublicKey::new(
            crate::bignum::BoxedUint::from_be_bytes(&n_bytes),
            crate::bignum::BoxedUint::from_be_bytes(&e_bytes),
        );
        let spki = AnyPublicKey::Rsa(boxed_pub).to_spki_der();
        // Inner = SHA-256, outer = SHA-1 — historically common in attempted
        // algorithm-substitution attacks.
        let inner = algorithm_identifier(oid::SHA256_WITH_RSA, true);
        let outer = algorithm_identifier(oid::SHA1_WITH_RSA, true);
        let exts = crate::x509::cert::legacy_extensions(true, &[]);
        let tbs = build_tbs_raw(1, &subj, &subj, &validity(), &spki, &inner, &exts);
        let sig = key.sign_pkcs1v15::<Sha1>(&tbs).unwrap();
        let der = encode_sequence(&[tbs, outer, encode_bit_string(&sig)].concat());
        let mismatched = Certificate::from_der(der).unwrap();

        let mut store = RootCertStore::new();
        store.add_der(mismatched.to_der().to_vec()).unwrap();

        let with_sha1 = SignaturePolicy::modern().permit("rsa-pkcs1-sha1");
        assert!(matches!(
            verify_chain(&store, &[mismatched.to_der().to_vec()], None, &with_sha1),
            Err(Error::BadCertificate)
        ));
    }

    /// A CRL signed by the CA that revokes the leaf serial → chain
    /// validation refuses the leaf; a sibling leaf with a different serial
    /// validates normally.
    #[test]
    fn crl_revokes_leaf_serial() {
        use crate::tls::pki::CrlStore;
        use crate::x509::{CertSigner, CrlBuilder};
        let ca_key = rsa_test_key_a();
        let leaf_key = rsa_test_key_b();
        let ca_name = DistinguishedName::common_name("CRL Test CA");

        let root = Certificate::self_signed(&ca_key, &ca_name, &validity(), 1, true).unwrap();
        let leaf_revoked = Certificate::issue(
            &ca_key,
            &ca_name,
            &DistinguishedName::common_name("revoked.example"),
            &leaf_key.public_key(),
            &validity(),
            42,
            false,
        )
        .unwrap();
        let leaf_ok = Certificate::issue(
            &ca_key,
            &ca_name,
            &DistinguishedName::common_name("ok.example"),
            &leaf_key.public_key(),
            &validity(),
            43,
            false,
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();

        // Build a CRL that revokes serial 42.
        let signer = CertSigner::Rsa(
            &crate::rsa::BoxedRsaPrivateKey::from_pkcs1_pem(include_str!(
                "../../../testdata/rsa2048_test_a.pem"
            ))
            .unwrap(),
        );
        let mut b = CrlBuilder::new(&ca_name, Time::utc(2026, 1, 1, 0, 0, 0), None);
        b.revoke(&[42], Time::utc(2026, 1, 2, 0, 0, 0), None);
        let crl = b.sign(&signer).unwrap();
        let mut crls = CrlStore::new();
        crls.add_der(crl.to_der().to_vec()).unwrap();

        // The OK leaf still validates.
        verify_chain_with_crls(&store, &crls, &[leaf_ok.to_der().to_vec()], None, &policy())
            .unwrap();
        // The revoked leaf is rejected.
        assert!(matches!(
            verify_chain_with_crls(
                &store,
                &crls,
                &[leaf_revoked.to_der().to_vec()],
                None,
                &policy(),
            ),
            Err(Error::BadCertificate)
        ));
        // With an empty CRL store the revoked leaf would have passed (sanity
        // check that we're testing the CRL path, not a different bug).
        verify_chain_with_crls(
            &store,
            &CrlStore::new(),
            &[leaf_revoked.to_der().to_vec()],
            None,
            &policy(),
        )
        .unwrap();
    }

    /// A CRL outside its `thisUpdate..=nextUpdate` window is advisory:
    /// the chain validates even though the leaf serial would otherwise
    /// be revoked.
    #[test]
    fn expired_crl_is_advisory() {
        use crate::tls::pki::CrlStore;
        use crate::x509::{CertSigner, CrlBuilder};
        let ca_key = rsa_test_key_a();
        let leaf_key = rsa_test_key_b();
        let ca_name = DistinguishedName::common_name("CRL Test CA");

        let root = Certificate::self_signed(&ca_key, &ca_name, &validity(), 1, true).unwrap();
        let leaf = Certificate::issue(
            &ca_key,
            &ca_name,
            &DistinguishedName::common_name("leaf.example"),
            &leaf_key.public_key(),
            &validity(),
            7,
            false,
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();

        let signer = CertSigner::Rsa(
            &crate::rsa::BoxedRsaPrivateKey::from_pkcs1_pem(include_str!(
                "../../../testdata/rsa2048_test_a.pem"
            ))
            .unwrap(),
        );
        // CRL window: 2024-01-01 .. 2024-12-31. We verify at `now =
        // 2026-01-01`, which is past nextUpdate ⇒ the CRL is treated as
        // not covering this point in time.
        let mut b = CrlBuilder::new(
            &ca_name,
            Time::utc(2024, 1, 1, 0, 0, 0),
            Some(Time::utc(2024, 12, 31, 0, 0, 0)),
        );
        b.revoke(&[7], Time::utc(2024, 6, 1, 0, 0, 0), None);
        let crl = b.sign(&signer).unwrap();
        let mut crls = CrlStore::new();
        crls.add_der(crl.to_der().to_vec()).unwrap();

        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        // Advisory: the expired CRL does not block the chain.
        verify_chain_with_crls(
            &store,
            &crls,
            &[leaf.to_der().to_vec()],
            Some(&now),
            &policy(),
        )
        .unwrap();
    }

    /// A CRL whose signature does not match the issuer key (e.g. signed by
    /// a different key) is silently ignored by chain validation.
    #[test]
    fn crl_signed_by_wrong_key_is_ignored() {
        use crate::tls::pki::CrlStore;
        use crate::x509::{CertSigner, CrlBuilder};
        let ca_key = rsa_test_key_a();
        let other_key = rsa_test_key_b();
        let ca_name = DistinguishedName::common_name("CRL Test CA");

        let root = Certificate::self_signed(&ca_key, &ca_name, &validity(), 1, true).unwrap();
        let leaf = Certificate::issue(
            &ca_key,
            &ca_name,
            &DistinguishedName::common_name("leaf.example"),
            &other_key.public_key(),
            &validity(),
            55,
            false,
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();

        // CRL signed by the OTHER key, not the CA. is_revoked would say
        // true, but the signature won't verify under the CA, so the CRL is
        // ignored.
        let bogus_signer = CertSigner::Rsa(
            &crate::rsa::BoxedRsaPrivateKey::from_pkcs1_pem(include_str!(
                "../../../testdata/rsa2048_test_b.pem"
            ))
            .unwrap(),
        );
        let mut b = CrlBuilder::new(&ca_name, Time::utc(2026, 1, 1, 0, 0, 0), None);
        b.revoke(&[55], Time::utc(2026, 1, 2, 0, 0, 0), None);
        let crl = b.sign(&bogus_signer).unwrap();
        let mut crls = CrlStore::new();
        crls.add_der(crl.to_der().to_vec()).unwrap();

        verify_chain_with_crls(&store, &crls, &[leaf.to_der().to_vec()], None, &policy()).unwrap();
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

    /// H-4 — RFC 5280 §5.1.1.2: weak CRL signature algorithms must be
    /// gated by the same `SignaturePolicy` that gates the certificate
    /// path. A CRL signed with SHA-1-RSA under `SignaturePolicy::modern()`
    /// must be silently dropped — the chain still validates the cert as
    /// not revoked. Under an explicit `permit("rsa-pkcs1-sha1")` opt-in,
    /// the same CRL is consulted and revokes the leaf.
    #[test]
    fn crl_signed_with_sha1_rejected_under_modern_policy() {
        use crate::der::{encode_bit_string, encode_sequence};
        use crate::hash::Sha1;
        use crate::tls::pki::CrlStore;
        use crate::x509::{CertificateRevocationList, algorithm_identifier};

        let ca_key = rsa_test_key_a();
        let leaf_key = rsa_test_key_b();
        let ca_name = DistinguishedName::common_name("CRL SHA-1 Test CA");

        let root = Certificate::self_signed(&ca_key, &ca_name, &validity(), 1, true).unwrap();
        let leaf = Certificate::issue(
            &ca_key,
            &ca_name,
            &DistinguishedName::common_name("sha1crl.example"),
            &leaf_key.public_key(),
            &validity(),
            99,
            false,
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();

        // Hand-build a SHA-1-RSA-signed CRL that revokes serial 99. The
        // inner and outer AlgorithmIdentifiers both carry
        // sha1WithRSAEncryption; the signature is computed under SHA-1
        // so it would verify under the issuer key — except `policy()`
        // refuses SHA-1, so the CRL is silently dropped.
        let algid_sha1 = algorithm_identifier(oid::SHA1_WITH_RSA, true);
        // Revoked-certificates SEQUENCE: one entry { serial=99, revoked_at }.
        let serial = crate::der::encode_integer(&[99]);
        let revoked_at = Time::utc(2026, 1, 2, 0, 0, 0).to_der_choice();
        let entry = encode_sequence(&[serial, revoked_at].concat());
        // Build the TBS body manually so we can splice in a revoked entry
        // (the in-tree `CrlBuilder` always uses the signer's chosen algid,
        // which for `BoxedRsaPrivateKey` is SHA-256-RSA — we need SHA-1
        // here).
        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(&crate::der::encode_integer(&[1])); // version v2
        body.extend_from_slice(&algid_sha1);
        body.extend_from_slice(&ca_name.to_der());
        body.extend_from_slice(&Time::utc(2026, 1, 1, 0, 0, 0).to_der_choice());
        body.extend_from_slice(&encode_sequence(&entry));
        let tbs = encode_sequence(&body);
        let sig = ca_key.sign_pkcs1v15::<Sha1>(&tbs).unwrap();
        let crl_der = encode_sequence(&[tbs, algid_sha1, encode_bit_string(&sig)].concat());
        let crl = CertificateRevocationList::from_der(crl_der).unwrap();

        let mut crls = CrlStore::new();
        crls.add_der(crl.to_der().to_vec()).unwrap();

        // Under modern policy: CRL is ignored, leaf validates as not revoked.
        verify_chain_with_crls(&store, &crls, &[leaf.to_der().to_vec()], None, &policy()).unwrap();

        // Sanity: under an explicit SHA-1 opt-in, the same CRL revokes the leaf.
        let with_sha1 = SignaturePolicy::modern().permit("rsa-pkcs1-sha1");
        assert!(matches!(
            verify_chain_with_crls(&store, &crls, &[leaf.to_der().to_vec()], None, &with_sha1,),
            Err(Error::BadCertificate)
        ));
    }

    /// dns_name_matches must refuse IP-literal patterns and IP-literal
    /// hosts (RFC 6125 §6.5.2 — IPs belong in iPAddress SAN, not dNSName /
    /// CN). The unit test asserts the refusal at both the pattern and
    /// host slots, including the IPv4-mapped-IPv6 form.
    #[test]
    fn dns_matcher_refuses_ip_pattern_or_host() {
        // Pattern is IPv4 → no match, even when host equals pattern byte-for-byte.
        assert!(!super::dns_name_matches("10.0.0.1", "10.0.0.1"));
        // Host is IPv4 → no match against any pattern.
        assert!(!super::dns_name_matches("example.com", "10.0.0.1"));
        assert!(!super::dns_name_matches("*.example.com", "10.0.0.1"));
        // IPv6 either side → no match.
        assert!(!super::dns_name_matches("::1", "::1"));
        assert!(!super::dns_name_matches("2001:db8::1", "2001:db8::1"));
        assert!(!super::dns_name_matches(
            "::ffff:10.0.0.1",
            "::ffff:10.0.0.1"
        ));
        // Sanity: normal hostnames still match.
        assert!(super::dns_name_matches("example.com", "example.com"));
        assert!(super::dns_name_matches("*.example.com", "host.example.com"));
        // Wildcard refuses a deeper host.
        assert!(!super::dns_name_matches("*.example.com", "a.b.example.com"));
        // Wildcard refuses the bare apex.
        assert!(!super::dns_name_matches("*.example.com", "example.com"));
        // Partial wildcard (`f*.example.com`) is not stripped → literal
        // compare → no match against `foo.example.com`.
        assert!(!super::dns_name_matches(
            "f*.example.com",
            "foo.example.com"
        ));
    }

    // ----------------------------------------------------------------------
    // Name-constraints unit tests (RFC 5280 §4.2.1.10 / §6.1.4).
    // ----------------------------------------------------------------------

    #[test]
    fn dns_in_subtree_label_alignment() {
        // base "example.com" matches exactly + any label-aligned subdomain.
        assert!(super::dns_in_subtree("example.com", "example.com"));
        assert!(super::dns_in_subtree("foo.example.com", "example.com"));
        assert!(super::dns_in_subtree("a.b.example.com", "example.com"));
        // ...but NOT a name with the same suffix at a different label boundary.
        assert!(!super::dns_in_subtree("notexample.com", "example.com"));
        // base ".example.com" matches strict subdomains only.
        assert!(super::dns_in_subtree("foo.example.com", ".example.com"));
        assert!(!super::dns_in_subtree("example.com", ".example.com"));
        // Case-insensitive.
        assert!(super::dns_in_subtree("FOO.Example.Com", "example.com"));
    }

    #[test]
    fn ip_in_subtree_cidr() {
        // 10.0.0.0/8 matches 10.x.y.z, not 11.x.y.z.
        let addr = [10u8, 0, 0, 0];
        let mask = [0xffu8, 0, 0, 0];
        assert!(super::ip_in_subtree(&[10, 1, 2, 3], &addr, &mask));
        assert!(super::ip_in_subtree(&[10, 0, 0, 0], &addr, &mask));
        assert!(!super::ip_in_subtree(&[11, 0, 0, 1], &addr, &mask));
        // v4 host against a v6 constraint never matches.
        assert!(!super::ip_in_subtree(&[10, 0, 0, 1], &[0; 16], &[0; 16]));
    }

    /// Builds a 2-CA chain (root → intermediate → leaf) with the intermediate
    /// carrying the supplied `nameConstraints` extension. The leaf is a
    /// server cert with `Certificate::issue_with_extensions` so SANs are
    /// caller-controlled; `leaf_cn` is the leaf's subject commonName (the
    /// CN-fallback tests put constraint-relevant names there).
    fn build_chain_with_nc(
        nc_ext: crate::x509::Extension,
        leaf_cn: &str,
        leaf_sans: &[crate::x509::GeneralName],
    ) -> (Certificate, Certificate, Certificate) {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;
        use crate::x509::{
            CertSigner, DistinguishedName, Extension, GeneralName, KeyUsageBits,
            extension::{basic_constraints, extended_key_usage, key_usage, subject_alt_name},
        };

        let _ = GeneralName::Dns; // silence unused-import warning if no DNS SAN
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"nc-chain", b"n", &[]);
        let root_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let int_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let leaf_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let root_signer = CertSigner::Ecdsa(&root_key);
        let int_signer = CertSigner::Ecdsa(&int_key);

        let root_name = DistinguishedName::common_name("nc-root");
        let int_name = DistinguishedName::common_name("nc-intermediate");
        let leaf_name = DistinguishedName::common_name(leaf_cn);

        let root_exts = [
            basic_constraints(true, None),
            key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
        ];
        let root = Certificate::self_signed_with_extensions(
            &root_signer,
            &root_name,
            &validity(),
            1,
            &root_exts,
        )
        .unwrap();

        let int_exts: alloc::vec::Vec<Extension> = alloc::vec![
            basic_constraints(true, Some(0)),
            key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
            nc_ext,
        ];
        let int_pub = crate::x509::AnyPublicKey::Ecdsa(int_key.public_key());
        let int = Certificate::issue_with_extensions(
            &root_signer,
            &root_name,
            &int_name,
            &int_pub,
            &validity(),
            2,
            &int_exts,
        )
        .unwrap();

        let leaf_exts = [
            basic_constraints(false, None),
            key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
            extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
            subject_alt_name(leaf_sans),
        ];
        let leaf_pub = crate::x509::AnyPublicKey::Ecdsa(leaf_key.public_key());
        let leaf = Certificate::issue_with_extensions(
            &int_signer,
            &int_name,
            &leaf_name,
            &leaf_pub,
            &validity(),
            3,
            &leaf_exts,
        )
        .unwrap();
        (root, int, leaf)
    }

    #[test]
    fn name_constraints_permitted_dns_accepts_matching() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Dns(".good.example".into())],
            &[],
        );
        let leaf_sans = [GeneralName::Dns("host.good.example".into())];
        let (root, int, leaf) = build_chain_with_nc(nc, "nc-leaf", &leaf_sans);

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        verify_chain(
            &store,
            &[leaf.to_der().to_vec(), int.to_der().to_vec()],
            Some(&now),
            &policy(),
        )
        .unwrap();
    }

    #[test]
    fn name_constraints_permitted_dns_rejects_outside_subtree() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Dns(".good.example".into())],
            &[],
        );
        // Leaf claims a host outside the permitted subtree.
        let leaf_sans = [GeneralName::Dns("attacker.example".into())];
        let (root, int, leaf) = build_chain_with_nc(nc, "nc-leaf", &leaf_sans);

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        assert!(matches!(
            verify_chain(
                &store,
                &[leaf.to_der().to_vec(), int.to_der().to_vec()],
                Some(&now),
                &policy(),
            ),
            Err(Error::BadCertificate)
        ));
    }

    #[test]
    fn name_constraints_excluded_dns_rejects_matching() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[],
            &[GeneralName::Dns(".bad.example".into())],
        );
        let leaf_sans = [GeneralName::Dns("host.bad.example".into())];
        let (root, int, leaf) = build_chain_with_nc(nc, "nc-leaf", &leaf_sans);

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        assert!(matches!(
            verify_chain(
                &store,
                &[leaf.to_der().to_vec(), int.to_der().to_vec()],
                Some(&now),
                &policy(),
            ),
            Err(Error::BadCertificate)
        ));
    }

    #[test]
    fn name_constraints_chain_rejects_san_less_leaf() {
        // CN-fallback under a permitted constraint: a leaf without SAN is
        // evaluated through its commonName ("nc-leaf"), which falls outside
        // the permitted subtree — the chain must be refused. (Before the CN
        // fallback existed, the same chain was refused by the blanket
        // SAN-less-under-permitted rule; either way it must not verify.)
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Dns(".good.example".into())],
            &[],
        );
        // No SAN on the leaf — only a CN.
        let leaf_sans: [GeneralName; 0] = [];
        let (root, int, leaf) = build_chain_with_nc(nc, "nc-leaf", &leaf_sans);

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        assert!(matches!(
            verify_chain(
                &store,
                &[leaf.to_der().to_vec(), int.to_der().to_vec()],
                Some(&now),
                &policy(),
            ),
            Err(Error::BadCertificate)
        ));
    }

    #[test]
    fn name_constraints_excluded_cn_fallback_rejected() {
        // The CN-fallback bypass this closes: a CA constrained by ONLY
        // excluded subtrees issues a SAN-less leaf whose CN sits inside the
        // excluded subtree. With no dNSName SAN to iterate, the old code
        // accepted the chain, and `verify_hostname` would then match the
        // host against that very CN. The CN must be evaluated against the
        // excluded dNSName subtrees as if it were a dNSName.
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[],
            &[GeneralName::Dns(".bad.example".into())],
        );
        let leaf_sans: [GeneralName; 0] = [];
        let (root, int, leaf) = build_chain_with_nc(nc, "host.bad.example", &leaf_sans);

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        assert!(matches!(
            verify_chain(
                &store,
                &[leaf.to_der().to_vec(), int.to_der().to_vec()],
                Some(&now),
                &policy(),
            ),
            Err(Error::BadCertificate)
        ));
    }

    #[test]
    fn name_constraints_permitted_cn_fallback_accepted() {
        // A SAN-less leaf whose DNS-plausible CN falls INSIDE the permitted
        // subtree verifies: the CN stands in for the missing dNSName SAN on
        // both the constraint side (here) and the hostname side
        // (`verify_hostname`'s CN fallback), so the two must agree.
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Dns(".good.example".into())],
            &[],
        );
        let leaf_sans: [GeneralName; 0] = [];
        let (root, int, leaf) = build_chain_with_nc(nc, "host.good.example", &leaf_sans);

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        verify_chain(
            &store,
            &[leaf.to_der().to_vec(), int.to_der().to_vec()],
            Some(&now),
            &policy(),
        )
        .unwrap();
    }

    #[test]
    fn name_constraints_cn_ignored_when_dns_san_present() {
        // Certs WITH dNSName SANs keep the current behavior: the CN is not
        // consulted (mirroring `verify_hostname`, which never falls back to
        // CN when a dNSName SAN exists). An excluded-subtree CN next to an
        // unconstrained SAN must not fail the chain.
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[],
            &[GeneralName::Dns(".bad.example".into())],
        );
        let leaf_sans = [GeneralName::Dns("host.good.example".into())];
        let (root, int, leaf) = build_chain_with_nc(nc, "host.bad.example", &leaf_sans);

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        verify_chain(
            &store,
            &[leaf.to_der().to_vec(), int.to_der().to_vec()],
            Some(&now),
            &policy(),
        )
        .unwrap();
    }

    #[test]
    fn name_constraints_ip_shaped_cn_not_dns_evaluated() {
        // An IP-shaped CN is kept out of the dNSName evaluation (and is
        // inert for hostname verification: `verify_hostname` never consults
        // the CN for IP-literal hosts and `dns_name_matches` refuses
        // IP-shaped patterns). Under an excluded-only dNSName constraint the
        // SAN-less leaf therefore presents no evaluable name, which cannot
        // violate an exclusion — the chain verifies.
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[],
            &[GeneralName::Dns(".bad.example".into())],
        );
        let leaf_sans: [GeneralName; 0] = [];
        let (root, int, leaf) = build_chain_with_nc(nc, "10.0.0.1", &leaf_sans);

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        verify_chain(
            &store,
            &[leaf.to_der().to_vec(), int.to_der().to_vec()],
            Some(&now),
            &policy(),
        )
        .unwrap();
    }

    #[test]
    fn name_constraints_critical_with_unenforceable_type_rejected() {
        // A critical nameConstraints carrying an rfc822Name (email) subtree
        // is something we can't evaluate — the chain must fail closed.
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Email("admin@example.com".into())],
            &[],
        );
        // SAN unrelated; the rejection comes from the extension being a
        // critical unknown-shape rather than from SAN evaluation.
        let leaf_sans = [GeneralName::Dns("leaf.example".into())];
        let (root, int, leaf) = build_chain_with_nc(nc, "nc-leaf", &leaf_sans);

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        assert!(matches!(
            verify_chain(
                &store,
                &[leaf.to_der().to_vec(), int.to_der().to_vec()],
                Some(&now),
                &policy(),
            ),
            Err(Error::BadCertificate)
        ));
    }

    // ----------------------------------------------------------------------
    // RFC 5280 §6.1.4 propagation regression tests: a CA's nameConstraints
    // must apply to EVERY subordinate certificate (intermediates + leaf), not
    // only the end-entity leaf. The constraint is declared on the topmost
    // in-chain intermediate (`sub1`); anchor-resident constraints are covered
    // separately by the anchor_name_constraints_* tests below.
    // ----------------------------------------------------------------------

    /// Builds `root → sub1 → sub2 → leaf`. `sub1` (topmost in-chain
    /// intermediate) declares `nameConstraints` permitting only
    /// `.example.com`. `sub2_san` is sub-CA-2's dNSName SAN; `leaf_san` is the
    /// leaf's. The root is unconstrained. Returns `(root, sub1, sub2, leaf)`.
    #[allow(clippy::type_complexity)]
    fn build_propagation_chain(
        sub2_san: &str,
        leaf_san: &str,
    ) -> (Certificate, Certificate, Certificate, Certificate) {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;
        use crate::x509::{
            CertSigner, GeneralName, KeyUsageBits,
            extension::{
                basic_constraints, extended_key_usage, key_usage, name_constraints,
                subject_alt_name,
            },
        };

        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"nc-propagate", b"n", &[]);
        let root_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let sub1_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let sub2_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let leaf_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let root_signer = CertSigner::Ecdsa(&root_key);
        let sub1_signer = CertSigner::Ecdsa(&sub1_key);
        let sub2_signer = CertSigner::Ecdsa(&sub2_key);

        let root_name = DistinguishedName::common_name("prop-root");
        let sub1_name = DistinguishedName::common_name("prop-sub1");
        let sub2_name = DistinguishedName::common_name("prop-sub2");
        let leaf_name = DistinguishedName::common_name("prop-leaf");

        // Unconstrained root: these tests exercise in-chain propagation, so
        // the constraint lives on `sub1` rather than on the anchor.
        let root = Certificate::self_signed_with_extensions(
            &root_signer,
            &root_name,
            &validity(),
            1,
            &[
                basic_constraints(true, None),
                key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
            ],
        )
        .unwrap();

        // Topmost in-chain intermediate constrains the subtree below it to
        // `.example.com`. It declares no SAN of its own (the constraint it
        // declares governs its subordinates, not itself).
        let sub1_pub = crate::x509::AnyPublicKey::Ecdsa(sub1_key.public_key());
        let sub1 = Certificate::issue_with_extensions(
            &root_signer,
            &root_name,
            &sub1_name,
            &sub1_pub,
            &validity(),
            2,
            &[
                basic_constraints(true, None),
                key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
                name_constraints(&[GeneralName::Dns(".example.com".into())], &[]),
            ],
        )
        .unwrap();

        // Sub-CA-2: a subordinate CA governed by sub1's constraint. Its own
        // SAN is `sub2_san`.
        let sub2_pub = crate::x509::AnyPublicKey::Ecdsa(sub2_key.public_key());
        let sub2 = Certificate::issue_with_extensions(
            &sub1_signer,
            &sub1_name,
            &sub2_name,
            &sub2_pub,
            &validity(),
            3,
            &[
                basic_constraints(true, None),
                key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
                subject_alt_name(&[GeneralName::Dns(sub2_san.into())]),
            ],
        )
        .unwrap();

        // Leaf signed by sub2, with SAN `leaf_san`.
        let leaf_pub = crate::x509::AnyPublicKey::Ecdsa(leaf_key.public_key());
        let leaf = Certificate::issue_with_extensions(
            &sub2_signer,
            &sub2_name,
            &leaf_name,
            &leaf_pub,
            &validity(),
            4,
            &[
                basic_constraints(false, None),
                key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
                extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
                subject_alt_name(&[GeneralName::Dns(leaf_san.into())]),
            ],
        )
        .unwrap();
        (root, sub1, sub2, leaf)
    }

    /// Case a: a constraint-declaring intermediate (`sub1` permits
    /// `.example.com`) plus an out-of-constraint sub-CA (`sub2`'s own SAN is
    /// `evil.com`) plus an in-constraint leaf MUST be rejected — the sub-CA
    /// violates `sub1`'s constraint even though the leaf is in-scope. The old
    /// leaf-only check wrongly accepted this; it never looked at the
    /// intermediate's names.
    #[test]
    fn name_constraints_reject_out_of_scope_intermediate() {
        let (root, sub1, sub2, leaf) = build_propagation_chain("evil.com", "host.example.com");
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        let chain = alloc::vec![
            leaf.to_der().to_vec(),
            sub2.to_der().to_vec(),
            sub1.to_der().to_vec(),
        ];
        assert!(matches!(
            verify_chain(&store, &chain, Some(&now), &policy()),
            Err(Error::BadCertificate)
        ));
    }

    /// Case b: a fully in-constraint chain (the sub-CA below the constraint
    /// and the leaf both within `.example.com`) still validates.
    #[test]
    fn name_constraints_accept_fully_in_scope_chain() {
        let (root, sub1, sub2, leaf) =
            build_propagation_chain("ca2.example.com", "host.example.com");
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        let chain = alloc::vec![
            leaf.to_der().to_vec(),
            sub2.to_der().to_vec(),
            sub1.to_der().to_vec(),
        ];
        verify_chain(&store, &chain, Some(&now), &policy()).unwrap();
    }

    /// Variant of (a): the sub-CA is in-scope but the LEAF is out-of-scope —
    /// still rejected (the leaf check was already correct, and propagation
    /// must not regress it).
    #[test]
    fn name_constraints_reject_out_of_scope_leaf_below_in_scope_intermediate() {
        let (root, sub1, sub2, leaf) = build_propagation_chain("ca2.example.com", "host.evil.com");
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        let chain = alloc::vec![
            leaf.to_der().to_vec(),
            sub2.to_der().to_vec(),
            sub1.to_der().to_vec(),
        ];
        assert!(matches!(
            verify_chain(&store, &chain, Some(&now), &policy()),
            Err(Error::BadCertificate)
        ));
    }

    // ----------------------------------------------------------------------
    // Anchor-resident nameConstraints: a `nameConstraints` extension on the
    // trusted ROOT itself (retained by `RootCertStore::add_der`) must seed
    // the RFC 5280 §6.1.4 state and govern the whole validated path —
    // intermediates and leaf — exactly as an in-chain CA's constraints
    // would. Previously the store kept only the root's name + key and the
    // constraint was silently ignored.
    // ----------------------------------------------------------------------

    /// Builds `root → int → leaf` where the ROOT optionally carries
    /// `root_nc` as its `nameConstraints` extension. The intermediate's
    /// dNSName SAN is `int_san` and the leaf's is `leaf_san` (the anchor's
    /// constraints govern both).
    fn build_anchor_nc_chain(
        root_nc: Option<crate::x509::Extension>,
        int_san: &str,
        leaf_san: &str,
    ) -> (Certificate, Certificate, Certificate) {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;
        use crate::x509::{
            CertSigner, Extension, GeneralName, KeyUsageBits,
            extension::{basic_constraints, extended_key_usage, key_usage, subject_alt_name},
        };

        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"anchor-nc", b"n", &[]);
        let root_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let int_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let leaf_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let root_signer = CertSigner::Ecdsa(&root_key);
        let int_signer = CertSigner::Ecdsa(&int_key);

        let root_name = DistinguishedName::common_name("anchor-nc-root");
        let int_name = DistinguishedName::common_name("anchor-nc-int");
        let leaf_name = DistinguishedName::common_name("anchor-nc-leaf");

        let mut root_exts: alloc::vec::Vec<Extension> = alloc::vec![
            basic_constraints(true, None),
            key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
        ];
        if let Some(nc) = root_nc {
            root_exts.push(nc);
        }
        let root = Certificate::self_signed_with_extensions(
            &root_signer,
            &root_name,
            &validity(),
            1,
            &root_exts,
        )
        .unwrap();

        let int_pub = crate::x509::AnyPublicKey::Ecdsa(int_key.public_key());
        let int = Certificate::issue_with_extensions(
            &root_signer,
            &root_name,
            &int_name,
            &int_pub,
            &validity(),
            2,
            &[
                basic_constraints(true, Some(0)),
                key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
                subject_alt_name(&[GeneralName::Dns(int_san.into())]),
            ],
        )
        .unwrap();

        let leaf_pub = crate::x509::AnyPublicKey::Ecdsa(leaf_key.public_key());
        let leaf = Certificate::issue_with_extensions(
            &int_signer,
            &int_name,
            &leaf_name,
            &leaf_pub,
            &validity(),
            3,
            &[
                basic_constraints(false, None),
                key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
                extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
                subject_alt_name(&[GeneralName::Dns(leaf_san.into())]),
            ],
        )
        .unwrap();
        (root, int, leaf)
    }

    /// Case a: a leaf inside the anchor's permitted subtree validates.
    #[test]
    fn anchor_name_constraints_permitted_accepts_in_subtree_leaf() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Dns(".good.example".into())],
            &[],
        );
        let (root, int, leaf) =
            build_anchor_nc_chain(Some(nc), "int.good.example", "host.good.example");
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        verify_chain(
            &store,
            &[leaf.to_der().to_vec(), int.to_der().to_vec()],
            Some(&now),
            &policy(),
        )
        .unwrap();
    }

    /// Case b: a leaf outside the anchor's permitted subtree is rejected —
    /// this is exactly the chain that wrongly validated when the store
    /// dropped the root's constraints.
    #[test]
    fn anchor_name_constraints_permitted_rejects_outside_leaf() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Dns(".good.example".into())],
            &[],
        );
        let (root, int, leaf) =
            build_anchor_nc_chain(Some(nc), "int.good.example", "host.evil.example");
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        assert!(matches!(
            verify_chain(
                &store,
                &[leaf.to_der().to_vec(), int.to_der().to_vec()],
                Some(&now),
                &policy(),
            ),
            Err(Error::BadCertificate)
        ));
    }

    /// The anchor's constraints govern the INTERMEDIATE too, not only the
    /// leaf: an out-of-subtree intermediate below a constrained anchor is
    /// rejected even when the leaf is in-subtree.
    #[test]
    fn anchor_name_constraints_permitted_rejects_outside_intermediate() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Dns(".good.example".into())],
            &[],
        );
        let (root, int, leaf) =
            build_anchor_nc_chain(Some(nc), "int.evil.example", "host.good.example");
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        assert!(matches!(
            verify_chain(
                &store,
                &[leaf.to_der().to_vec(), int.to_der().to_vec()],
                Some(&now),
                &policy(),
            ),
            Err(Error::BadCertificate)
        ));
    }

    /// Case c: a leaf inside the anchor's EXCLUDED subtree is rejected.
    #[test]
    fn anchor_name_constraints_excluded_rejects_matching_leaf() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[],
            &[GeneralName::Dns(".bad.example".into())],
        );
        let (root, int, leaf) =
            build_anchor_nc_chain(Some(nc), "int.good.example", "host.bad.example");
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        assert!(matches!(
            verify_chain(
                &store,
                &[leaf.to_der().to_vec(), int.to_der().to_vec()],
                Some(&now),
                &policy(),
            ),
            Err(Error::BadCertificate)
        ));
    }

    /// Case d: an unconstrained anchor is unaffected — the same chain shape
    /// with arbitrary SANs still validates.
    #[test]
    fn anchor_without_name_constraints_unaffected() {
        let (root, int, leaf) =
            build_anchor_nc_chain(None, "int.evil.example", "host.evil.example");
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        verify_chain(
            &store,
            &[leaf.to_der().to_vec(), int.to_der().to_vec()],
            Some(&now),
            &policy(),
        )
        .unwrap();
    }

    /// Fail closed at add time: a root whose nameConstraints reference a
    /// GeneralName variant the validator cannot evaluate (here rfc822Name)
    /// is refused by `add_der` rather than installed with its constraints
    /// silently ignored.
    #[test]
    fn add_der_rejects_anchor_with_unenforceable_constraints() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Email("admin@example.com".into())],
            &[],
        );
        let (root, _int, _leaf) =
            build_anchor_nc_chain(Some(nc), "int.good.example", "host.good.example");
        let mut store = RootCertStore::new();
        assert!(matches!(
            store.add_der(root.to_der().to_vec()),
            Err(Error::BadCertificate)
        ));
        assert!(store.is_empty());
    }

    /// Fail closed at add time: a root carrying a nameConstraints extension
    /// that does not parse is refused by `add_der`.
    #[test]
    fn add_der_rejects_anchor_with_malformed_constraints() {
        let garbage_nc = crate::x509::Extension {
            oid: oid::NAME_CONSTRAINTS.to_vec(),
            critical: true,
            value: alloc::vec![0xff, 0x00],
        };
        let (root, _int, _leaf) =
            build_anchor_nc_chain(Some(garbage_nc), "int.good.example", "host.good.example");
        let mut store = RootCertStore::new();
        assert!(matches!(
            store.add_der(root.to_der().to_vec()),
            Err(Error::BadCertificate)
        ));
        assert!(store.is_empty());
    }
}
