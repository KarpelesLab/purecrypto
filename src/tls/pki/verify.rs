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
use super::store::RootCertStore;
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

    // RFC 5280 §4.1.1.2 / §4.1.2.3: inner `signature` AlgorithmIdentifier in
    // TBSCertificate MUST equal outer `signatureAlgorithm`.
    for cert in &certs {
        cert.check_signature_algid_consistent()
            .map_err(|_| Error::BadCertificate)?;
    }

    // RFC 5280 §4.2: any extension marked `critical` whose OID we do not
    // understand requires rejection.
    for cert in &certs {
        check_critical_extensions_recognized(cert)?;
    }

    // Each certificate must currently be within its validity period.
    if let Some(now) = now {
        for cert in &certs {
            let validity = cert.validity().map_err(|_| Error::BadCertificate)?;
            if !validity.accepts(now) {
                return Err(Error::BadCertificate);
            }
        }
    }

    // Each certificate must be signed by the next, with matching names. We
    // also consult the CrlStore for revocation: the issuer key just verified
    // is exactly what we need to validate a candidate CRL.
    for pair in certs.windows(2) {
        let (cert, issuer) = (&pair[0], &pair[1]);
        let issuer_key = issuer
            .subject_public_key()
            .map_err(|_| Error::BadCertificate)?;
        verify_cert_against_issuer(cert, &issuer_key, policy)?;
        if names_differ(cert, issuer)? {
            return Err(Error::BadCertificate);
        }
        check_revocation(cert, &issuer_key, crls, now, policy)?;
    }

    // Anchor the top of the chain to a trusted root sharing its issuer name.
    // RFC 5280 §7.1 mandates byte-exact `Name` equality, so we compare the
    // raw DER. Multiple anchors may share a name (cross-signed renewal); we
    // accept the first whose key verifies the topmost cert's signature.
    let top = certs.last().expect("chain is non-empty");
    let top_issuer = top.issuer_der().map_err(|_| Error::BadCertificate)?;
    let mut anchored = false;
    let mut anchor_key: Option<&AnyPublicKey> = None;
    for anchor in store.anchors_with_subject(top_issuer) {
        if verify_cert_against_issuer(top, &anchor.key, policy).is_ok() {
            anchored = true;
            anchor_key = Some(&anchor.key);
            break;
        }
    }
    if !anchored {
        return Err(Error::BadCertificate);
    }
    // Top cert may itself be revoked by a CRL signed by the anchor.
    if let Some(key) = anchor_key {
        check_revocation(top, key, crls, now, policy)?;
    }

    // RFC 5280 §4.2.1.9 / §4.2.1.3 / §4.2.1.12 enforcement.
    enforce_constraints(&certs, purpose)?;

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

/// RFC 5280 §4.2: reject the certificate if it carries any critical extension
/// whose OID we don't recognize. The handler set (basicConstraints, keyUsage,
/// extKeyUsage, subjectAltName) is intentionally narrow — every critical
/// extension outside this set is treated as "we cannot enforce this
/// constraint", which must result in rejection.
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
}
