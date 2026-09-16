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
use crate::signature_registry::SignaturePolicy;
use crate::tls::Error;
use crate::x509::{AnyPublicKey, Certificate, Time, Validity, oid};
use alloc::vec::Vec;

/// `keyUsage` bit-0 `digitalSignature` (RFC 5280 §4.2.1.3).
const KU_DIGITAL_SIGNATURE: u16 = 0x80; // bit 0 in BIT STRING wire order = MSB of byte 0
/// `keyUsage` bit-5 `keyCertSign`.
const KU_KEY_CERT_SIGN: u16 = 0x04;
/// `keyUsage` bit-6 `cRLSign` (RFC 5280 §4.2.1.3 / §6.3.3).
const KU_CRL_SIGN: u16 = 0x02;

/// Upper bound on the length of a peer-supplied certificate chain. Each cert
/// triggers a signature verification (RSA / ECDSA / PQ) plus repeated DN
/// parsing; an unbounded chain is a DoS vector during TLS handshake. The
/// value is generous — production CAs rarely exceed 4 — but caps the worst
/// case at a few milliseconds of verification work.
const MAX_CHAIN_LEN: usize = 10;

/// Upper bound on the number of CRLs consulted for a single (certificate,
/// issuer) pair. Each candidate CRL costs a public-key signature verification
/// before any cheap filter can rule it out, and the candidate list is
/// peer-controlled: a malicious TLS 1.3 server can staple hundreds of tiny
/// CRLs sharing the leaf issuer's DN through the `CRL_RESPONSE` certificate-
/// entry extension, multiplying by the chain length. Real deployments publish
/// one CRL (occasionally a couple during a rollover) per issuer, so a low cap
/// costs nothing and bounds the work at `MAX_CHAIN_LEN * MAX_CRLS_PER_ISSUER`
/// verifications per handshake.
const MAX_CRLS_PER_ISSUER: usize = 8;

/// The identity of the certificate that issued the end-entity certificate of
/// a validated chain — what an OCSP `CertID` (RFC 6960 §4.1.1) and a
/// delegated-responder check must be evaluated against.
///
/// The verifier closes the path at the FIRST certificate anchored by the
/// store and discards everything the peer supplied above it. When the leaf
/// anchors directly on a stored root, `chain[1]` (if present) is therefore an
/// arbitrary, never-validated, peer-chosen blob and MUST NOT be used as the
/// leaf's issuer; this value carries the *actual* issuer — the in-chain
/// certificate that signed the leaf, or the matched trust anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeafIssuer {
    /// The issuer's subject `Name` — full DER TLV, byte-exact as encoded in
    /// the issuing certificate (what `issuerNameHash` is computed over).
    pub(crate) name_der: Vec<u8>,
    /// The issuer's `SubjectPublicKeyInfo` — full DER TLV, byte-exact as
    /// encoded in the issuing certificate (its `subjectPublicKey` BIT STRING
    /// content is what `issuerKeyHash` is computed over).
    pub(crate) spki_der: Vec<u8>,
}

impl LeafIssuer {
    fn from_anchor(anchor: &TrustAnchor) -> Self {
        LeafIssuer {
            name_der: anchor.subject_der.clone(),
            spki_der: anchor.spki_der.clone(),
        }
    }

    fn from_cert(cert: &Certificate) -> Result<Self, Error> {
        Ok(LeafIssuer {
            name_der: cert
                .subject_der()
                .map_err(|_| Error::BadCertificate)?
                .to_vec(),
            spki_der: cert.spki_der().map_err(|_| Error::BadCertificate)?.to_vec(),
        })
    }
}

/// The result of a successful chain verification.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedChain {
    /// The end-entity (leaf) public key — the key whose possession the peer
    /// proves in its `CertificateVerify`.
    pub(crate) leaf_key: AnyPublicKey,
    /// The leaf's actual issuer within the validated path (see
    /// [`LeafIssuer`]).
    // The TLS clients resolve the issuer via `leaf_issuer()` in a later
    // handshake step; this field serves tests / future internal callers.
    #[allow(dead_code)]
    pub(crate) leaf_issuer: LeafIssuer,
}

/// Step (a) of the path walk: the first trust anchor in `store` whose subject
/// `Name` byte-equals `cert`'s issuer (RFC 5280 §7.1) AND whose key verifies
/// `cert`'s signature under `policy`. Several anchors may share a Name
/// (cross-signed renewal), so the signature decides. `None` when `cert` is
/// not directly anchored.
///
/// Shared by the verifier and by [`leaf_issuer`] so that both resolve the
/// leaf's issuer identically.
fn anchor_for<'a>(
    store: &'a RootCertStore,
    cert: &Certificate,
    policy: &SignaturePolicy,
) -> Result<Option<&'a TrustAnchor>, Error> {
    let issuer_der = cert.issuer_der().map_err(|_| Error::BadCertificate)?;
    Ok(store
        .anchors_with_subject(issuer_der)
        .find(|anchor| verify_cert_against_issuer(cert, &anchor.key, policy).is_ok()))
}

/// Resolves the issuer of `chain[0]` exactly as the chain verifier does —
/// the matched trust anchor when the leaf anchors directly on the store,
/// otherwise `chain[1]` (which must then verify the leaf's signature).
///
/// Intended for callers that hold an already-verified `chain` (the TLS
/// clients validate the chain in one handshake step and the stapled OCSP
/// response in another) and need the leaf's issuer without re-running full
/// path validation. Because the verifier closes the path at the first
/// anchored certificate, this is the ONLY correct way to obtain the leaf's
/// issuer from a peer-supplied chain — `chain[1]` alone is peer-chosen and
/// unvalidated whenever the leaf anchors directly.
///
/// Fails with `BadCertificate` when the leaf is neither anchored nor signed
/// by `chain[1]` (i.e. when the chain would not have verified).
pub(crate) fn leaf_issuer(
    store: &RootCertStore,
    chain: &[Vec<u8>],
    policy: &SignaturePolicy,
) -> Result<LeafIssuer, Error> {
    let leaf_der = chain.first().ok_or(Error::BadCertificate)?;
    let leaf = Certificate::from_der(leaf_der.clone()).map_err(|_| Error::BadCertificate)?;
    if let Some(anchor) = anchor_for(store, &leaf, policy)? {
        return Ok(LeafIssuer::from_anchor(anchor));
    }
    let issuer_der = chain.get(1).ok_or(Error::BadCertificate)?;
    let issuer = Certificate::from_der(issuer_der.clone()).map_err(|_| Error::BadCertificate)?;
    let issuer_key = issuer
        .subject_public_key()
        .map_err(|_| Error::BadCertificate)?;
    verify_cert_against_issuer(&leaf, &issuer_key, policy)?;
    if names_differ(&leaf, &issuer)? {
        return Err(Error::BadCertificate);
    }
    LeafIssuer::from_cert(&issuer)
}

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

/// Like [`verify_chain_with_crls`], but returns the full [`VerifiedChain`] —
/// the leaf key *and* the leaf's actual issuer within the validated path —
/// for callers that go on to evaluate revocation data (a stapled OCSP
/// response) keyed on the issuer.
#[allow(dead_code)] // useful for tests / future internal callers
pub(crate) fn verify_chain_with_crls_verified(
    store: &RootCertStore,
    crls: &CrlStore,
    chain: &[Vec<u8>],
    now: Option<&Time>,
    policy: &SignaturePolicy,
) -> Result<VerifiedChain, Error> {
    verify_chain_inner(
        store,
        crls,
        chain,
        now,
        policy,
        ChainPurpose::Server,
        &super::policy::PolicyOptions::none(),
    )
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

/// Like [`verify_chain_with_crls_for_purpose`], but additionally runs RFC 5280
/// §6.1 certificate-policy-tree processing over the validated path under
/// `policy_opts`.
///
/// Policy processing is **opt-in**: with [`super::PolicyOptions::none`] (the
/// value every other entry point passes) this is identical to
/// [`verify_chain_with_crls_for_purpose`] and the default validation behavior
/// is unchanged. When the caller supplies an initial policy set / requires an
/// explicit policy, a path whose computed policy tree cannot satisfy the
/// requirement is rejected with [`Error::BadCertificate`].
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn verify_chain_with_policy(
    store: &RootCertStore,
    crls: &CrlStore,
    chain: &[Vec<u8>],
    now: Option<&Time>,
    policy: &SignaturePolicy,
    purpose: ChainPurpose,
    policy_opts: &super::policy::PolicyOptions,
) -> Result<AnyPublicKey, Error> {
    verify_chain_inner(store, crls, chain, now, policy, purpose, policy_opts).map(|v| v.leaf_key)
}

pub(crate) fn verify_chain_with_crls_for_purpose(
    store: &RootCertStore,
    crls: &CrlStore,
    chain: &[Vec<u8>],
    now: Option<&Time>,
    policy: &SignaturePolicy,
    purpose: ChainPurpose,
) -> Result<AnyPublicKey, Error> {
    verify_chain_inner(
        store,
        crls,
        chain,
        now,
        policy,
        purpose,
        &super::policy::PolicyOptions::none(),
    )
    .map(|v| v.leaf_key)
}

#[allow(clippy::too_many_arguments)]
fn verify_chain_inner(
    store: &RootCertStore,
    crls: &CrlStore,
    chain: &[Vec<u8>],
    now: Option<&Time>,
    policy: &SignaturePolicy,
    purpose: ChainPurpose,
    policy_opts: &super::policy::PolicyOptions,
) -> Result<VerifiedChain, Error> {
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
    // The leaf's issuer within the validated path: the anchor when certs[0]
    // anchors directly, else certs[1]. Recorded here — NOT read back from
    // `chain[1]` by callers — because when the leaf anchors directly the
    // rest of the supplied chain is discarded unvalidated (see below).
    let mut leaf_issuer: Option<LeafIssuer> = None;
    for i in 0..certs.len() {
        // (a) Is certs[i] issued directly by a trusted anchor? Anchors match by
        //     byte-exact issuer/subject Name equality (RFC 5280 §7.1); several
        //     anchors may share a Name (cross-signed renewal), so accept the
        //     first whose key verifies certs[i]'s signature under `policy`.
        if let Some(anchor) = anchor_for(store, &certs[i], policy)? {
            // Path closes here: certs[0..=i] is the validated path. certs[i]
            // may still be revoked by a CRL signed by the anchor.
            // The anchor's full certificate is not retained by the store, so
            // its keyUsage cannot be consulted here (RFC 5280 excludes the
            // trust anchor from constraint processing anyway, §6.1).
            check_revocation(&certs[i], &anchor.key, None, crls, now, policy)?;
            anchor_at = Some(i + 1);
            matched_anchor = Some(anchor);
            if i == 0 {
                leaf_issuer = Some(LeafIssuer::from_anchor(anchor));
            }
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
        check_revocation(&certs[i], &issuer_key, Some(issuer), crls, now, policy)?;
        if i == 0 {
            leaf_issuer = Some(LeafIssuer::from_cert(issuer)?);
        }
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
        // requires rejection. When the caller has enabled policy processing,
        // the policy-related critical extensions (certificatePolicies,
        // policyMappings, policyConstraints, inhibitAnyPolicy) ARE processed
        // by `check_policies` below, so they count as recognized; with policy
        // processing disabled (the default) they remain fail-closed exactly as
        // before — the default path is unchanged.
        check_critical_extensions_recognized(cert, policy_opts.policy_processing_enabled())?;
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
    // path, applied to the certificates beneath each, critical or not. The
    // matched trust anchor's own constraints (retained by the store at add
    // time) seed the state, so a deliberately constrained root governs the
    // whole path.
    let anchor_nc = matched_anchor.and_then(|a| a.name_constraints.as_ref());
    enforce_name_constraints(path, anchor_nc)?;

    // RFC 5280 §4.2.1.9 / §4.2.1.3 / §4.2.1.12 enforcement (CA / keyUsage /
    // extKeyUsage), over the validated path.
    enforce_constraints(path, purpose)?;

    // RFC 5937 — honour the constraints the matched trust anchor declared on
    // itself (pathLenConstraint, extKeyUsage), when it declared any.
    if let Some(anchor) = matched_anchor {
        enforce_anchor_constraints(path, anchor, purpose)?;
    }

    // RFC 5280 §6.1.2–§6.1.5 — certificate-policy-tree processing. A no-op
    // (returns immediately) when `policy_opts` does not enable policy
    // processing, so the default path is unaffected.
    super::policy::check_policies(path, policy_opts)?;

    let leaf_key = certs[0]
        .subject_public_key()
        .map_err(|_| Error::BadCertificate)?;
    // Set on the very first loop iteration on both the anchored and the
    // in-chain branch (any other outcome returned early).
    let leaf_issuer = leaf_issuer.ok_or(Error::BadCertificate)?;
    Ok(VerifiedChain {
        leaf_key,
        leaf_issuer,
    })
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
///
/// When `issuer_cert` is supplied (in-chain issuer; absent for a trust
/// anchor, whose full certificate the store does not retain), RFC 5280
/// §6.3.3 requires that a key used to sign a CRL assert the `cRLSign`
/// keyUsage bit when a keyUsage extension is present. An issuer that carries
/// keyUsage *without* `cRLSign` cannot validly sign a CRL, so any matching
/// CRL is skipped (fail closed, exactly as the invalid-signature path does)
/// rather than being given the deciding vote.
///
/// At most [`MAX_CRLS_PER_ISSUER`] candidate CRLs reach the (expensive)
/// signature verification; see that constant for why the peer-controlled
/// candidate list must be bounded.
fn check_revocation(
    cert: &Certificate,
    issuer_key: &AnyPublicKey,
    issuer_cert: Option<&Certificate>,
    crls: &CrlStore,
    now: Option<&Time>,
    policy: &SignaturePolicy,
) -> Result<(), Error> {
    let cert_issuer = cert.issuer_der().map_err(|_| Error::BadCertificate)?;
    let serial = cert.serial_bytes().map_err(|_| Error::BadCertificate)?;
    let issuer_spki = issuer_key.to_spki_der();
    // RFC 5280 §6.3.3: a key used to sign a CRL MUST assert `cRLSign` in its
    // keyUsage extension when one is present. This is a property of the
    // issuer alone, so evaluate it once: an issuer that cannot validly sign
    // CRLs makes every candidate CRL inadmissible (fail closed, same as a
    // forged-signature CRL) and there is nothing to verify.
    if let Some(issuer) = issuer_cert
        && let Some(mask) = issuer.key_usage().map_err(|_| Error::BadCertificate)?
        && (mask & KU_CRL_SIGN) == 0
    {
        return Ok(());
    }
    // Budget for the expensive step (see `MAX_CRLS_PER_ISSUER`). Only CRLs
    // that survive every cheap filter and reach the signature verification
    // consume it, and the store lists locally configured CRLs before
    // peer-stapled ones — so a peer cannot spend the budget to hide a CRL the
    // relying party configured itself.
    let mut verifications_left = MAX_CRLS_PER_ISSUER;
    for crl in crls.crls_with_issuer(cert_issuer) {
        // RFC 5280 §5.1.1.2: the CRL's `signatureAlgorithm` must be one we
        // accept under `policy` — the same whitelist that gates cert-chain
        // signatures. A CRL signed with e.g. SHA-1-RSA is silently ignored
        // (treated as "not consulted") under `SignaturePolicy::modern()`.
        let Ok(crl_sig_alg) = crl.signature_algorithm() else {
            continue;
        };
        let Some(crl_algo) = issuer_key.signature_algorithm(&crl_sig_alg) else {
            continue;
        };
        if !policy.permits(crl_algo, &issuer_spki) {
            continue;
        }
        // Bound the peer-controlled public-key verification work. The
        // signature check stays FIRST among the per-CRL work that can fail
        // the chain, so the documented property above still holds: an
        // attacker cannot make us reject a chain by injecting a CRL whose
        // (unsigned, unauthenticated) body fails a later strict parse.
        if verifications_left == 0 {
            break;
        }
        verifications_left -= 1;
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
/// Resolves the certificate's `signatureAlgorithm` OID to the registry entry
/// the issuer key dispatches to ([`AnyPublicKey::signature_algorithm`] — the
/// entry a PSS-restricted key routes to depends on its restriction, not the
/// OID alone), rejects any algorithm not on the whitelist (with
/// `BadCertificate`), and only then delegates to the issuer key's verifier.
fn verify_cert_against_issuer(
    cert: &Certificate,
    issuer_key: &AnyPublicKey,
    policy: &SignaturePolicy,
) -> Result<(), Error> {
    let sig_alg = cert
        .signature_algorithm()
        .map_err(|_| Error::BadCertificate)?;
    let algo = issuer_key
        .signature_algorithm(&sig_alg)
        .ok_or(Error::BadCertificate)?;
    let issuer_spki = issuer_key.to_spki_der();
    if !policy.permits(algo, &issuer_spki) {
        return Err(Error::BadCertificate);
    }
    cert.verify_signature_with(issuer_key)
        .map_err(|_| Error::BadCertificate)
}

/// `anyExtendedKeyUsage` (2.5.29.37.0) — an EKU value that asserts the
/// certificate is valid for *any* purpose, satisfying every specific EKU
/// requirement (RFC 5280 §4.2.1.12).
const ANY_EXTENDED_KEY_USAGE: &[u64] = &[2, 5, 29, 37, 0];

/// Per-position chain constraints:
///   * every non-leaf must have `basicConstraints.cA = true`;
///   * every non-leaf with a `keyUsage` extension must include `keyCertSign`
///     (RFC 5280 §4.2.1.3);
///   * `pathLenConstraint` on a non-leaf bounds the number of *non-self-issued*
///     intermediates between it and the leaf (RFC 5280 §6.1.4(h)/(l));
///   * every non-leaf with an `extKeyUsage` extension must include
///     `id-kp-serverAuth`/`id-kp-clientAuth` (or `anyExtendedKeyUsage`), so a
///     TLS-scoped intermediate cannot smuggle an out-of-scope leaf;
///   * if the leaf carries `keyUsage`, `digitalSignature` (bit 0) must be set;
///   * if the leaf carries `extKeyUsage`, it must include the required purpose.
///
/// The trust anchor's *own* `pathLenConstraint` / `extKeyUsage` are not
/// enforced here — the anchor is not part of `certs` (it lives in the
/// [`RootCertStore`] and is excluded from processing per RFC 5280 §6.1) — but
/// they are enforced separately by [`enforce_anchor_constraints`].
fn enforce_constraints(certs: &[Certificate], purpose: ChainPurpose) -> Result<(), Error> {
    let required = match purpose {
        ChainPurpose::Server => oid::ID_KP_SERVER_AUTH,
        ChainPurpose::Client => oid::ID_KP_CLIENT_AUTH,
    };
    // RFC 5280 §6.1.4(h): a self-issued certificate (one whose subject equals
    // its issuer but that is not a self-signed trust anchor) does not consume a
    // pathLenConstraint "slot". We count only the non-self-issued intermediates
    // that sit *below* a given CA toward the leaf.
    let is_self_issued = |cert: &Certificate| -> bool {
        match (cert.subject_der(), cert.issuer_der()) {
            (Ok(s), Ok(i)) => s == i,
            _ => false,
        }
    };

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
        // RFC 5280 §4.2.1.12 chained to intermediates: an intermediate that
        // carries an `extKeyUsage` extension constrains what may appear beneath
        // it. A TLS-scoped intermediate must permit the required purpose
        // (serverAuth/clientAuth) or `anyExtendedKeyUsage`. An intermediate
        // with NO EKU extension is unconstrained and passes.
        let ekus = cert
            .extended_key_usages()
            .map_err(|_| Error::BadCertificate)?;
        if !ekus.is_empty()
            && !ekus
                .iter()
                .any(|o| o.as_slice() == required || o.as_slice() == ANY_EXTENDED_KEY_USAGE)
        {
            return Err(Error::BadCertificate);
        }
        // `pathLenConstraint = N` permits at most N non-self-issued
        // intermediate certificates between this CA and any leaf. The
        // intermediates below the CA at position `i` live at positions
        // 1..=i-1; self-issued ones among them do not count (§6.1.4(h)).
        if let Some(plc) = bc.1 {
            let intermediates_below = certs[1..i].iter().filter(|c| !is_self_issued(c)).count();
            if (plc as usize) < intermediates_below {
                return Err(Error::BadCertificate);
            }
        }
    }

    // Leaf: keyUsage (if present) must include digitalSignature; EKU (if
    // present) must include the required purpose.
    let leaf = &certs[0];
    if let Some(mask) = leaf.key_usage().map_err(|_| Error::BadCertificate)?
        && (mask & KU_DIGITAL_SIGNATURE) == 0
    {
        return Err(Error::BadCertificate);
    }
    let ekus = leaf
        .extended_key_usages()
        .map_err(|_| Error::BadCertificate)?;
    if !ekus.is_empty()
        && !ekus
            .iter()
            .any(|o| o.as_slice() == required || o.as_slice() == ANY_EXTENDED_KEY_USAGE)
    {
        return Err(Error::BadCertificate);
    }
    Ok(())
}

/// RFC 5937 — constraints the trust anchor declares on *itself*.
///
/// RFC 5280 §6.1 deliberately excludes the anchor's certificate from path
/// processing (the anchor is "a name and a key"), so a root that says
/// `basicConstraints: CA:TRUE, pathlen:0` or `extKeyUsage: codeSigning` was
/// previously unconstrained in practice. RFC 5937 lets a relying party apply
/// such constraints, and OpenSSL — which keeps the root in the chain — does.
/// Both checks fire **only when the anchor actually carries the extension**,
/// so an ordinary root (the overwhelming majority: of the 117 embedded roots,
/// two carry a pathLen and none carries an EKU) validates exactly as before.
///
/// * `pathLenConstraint = N` bounds the number of non-self-issued
///   intermediates between the anchor and the leaf — here, everything in
///   `path` above the leaf (RFC 5280 §4.2.1.9 / §6.1.4(h)).
/// * a non-empty `extKeyUsage` must permit the purpose being validated for,
///   or `anyExtendedKeyUsage`, mirroring the in-chain CA rule.
fn enforce_anchor_constraints(
    path: &[Certificate],
    anchor: &super::store::TrustAnchor,
    purpose: ChainPurpose,
) -> Result<(), Error> {
    if let Some(plc) = anchor.path_len_constraint {
        let intermediates_below = path[1..]
            .iter()
            .filter(|c| match (c.subject_der(), c.issuer_der()) {
                (Ok(s), Ok(i)) => s != i,
                _ => true,
            })
            .count();
        if (plc as usize) < intermediates_below {
            return Err(Error::BadCertificate);
        }
    }
    if !anchor.extended_key_usages.is_empty() {
        let required = match purpose {
            ChainPurpose::Server => oid::ID_KP_SERVER_AUTH,
            ChainPurpose::Client => oid::ID_KP_CLIENT_AUTH,
        };
        if !anchor
            .extended_key_usages
            .iter()
            .any(|o| o.as_slice() == required || o.as_slice() == ANY_EXTENDED_KEY_USAGE)
        {
            return Err(Error::BadCertificate);
        }
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
/// of every certificate beneath it (intermediates and leaf) by
/// [`enforce_constraints_on_cert`]. The constraints are applied whether or
/// not the extension was marked critical (RFC 5280 §6.1.4 processes it
/// regardless; CA/Browser Forum technically-constrained sub-CAs commonly
/// carry it non-critical).
///
/// RFC 5280 §6.1.3(b): a self-issued certificate (subject equal to issuer)
/// that is not the leaf is skipped — a CA re-certifying its own key under
/// its own name is not a name the constraints were written for (its subject
/// is the constrained CA's own, which need not sit inside the subtrees the
/// CA imposes on others), and nothing in it is ever authenticated as an
/// identity.
///
/// `anchor_constraints` carries the matched trust anchor's own
/// `nameConstraints` (parsed and retained by [`RootCertStore`] when the root
/// was added). The anchor sits above the topmost supplied CA, so its
/// constraints are in scope for **every** certificate in the validated path
/// — they seed the constraint state before the walk begins, exactly as an
/// in-chain CA's constraints govern everything beneath it.
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
    // CAs' constraints against that certificate's own names. The trust
    // anchor issued `certs[last]`, so its constraints are in scope from the
    // very first iteration.
    let mut in_scope: Vec<&crate::x509::NameConstraints> = Vec::new();
    if let Some(nc) = anchor_constraints {
        in_scope.push(nc);
    }
    for idx in (0..certs.len()).rev() {
        let cert = &certs[idx];
        let is_leaf = idx == 0;
        let self_issued = !is_leaf
            && cert.subject_der().map_err(|_| Error::BadCertificate)?
                == cert.issuer_der().map_err(|_| Error::BadCertificate)?;
        // Constraints declared by CAs above this position must hold for the
        // certificate at `idx`. Only meaningful once at least one such
        // constraint is in scope, i.e. for certificates that have a
        // constraint-declaring CA above them.
        if !in_scope.is_empty() && !self_issued {
            enforce_constraints_on_cert(cert, &in_scope, is_leaf)?;
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
/// single subordinate certificate, per RFC 5280 §4.2.1.10 / §6.1.4 step (g).
///
/// Each constraint in `active` is checked independently, which yields the
/// RFC's accumulated state (intersection of the permitted subtrees, union of
/// the excluded ones): a name matching an excluded subtree of *any* in-scope
/// CA is fatal, and every CA that declares a permitted subtree of some form
/// requires every name of that form in `cert` to fall within one of its
/// entries. A form no CA constrains is unrestricted — a leaf whose SAN holds
/// only rfc822Name / URI entries passes a CA that permits only dNSName
/// subtrees untouched, as the RFC requires.
///
/// The names of `cert` that take part, by form:
///   * dNSName — the SAN dNSName entries, plus (leaf only) the subject
///     commonName when the certificate carries no subjectAltName extension
///     at all and the CN is DNS-plausible: `verify_hostname` falls back to
///     the leaf's CN under exactly that condition (RFC 6125 §6.4.4), so a
///     dNSName constraint must govern it too, or a CA constrained by only
///     EXCLUDED subtrees could issue a SAN-less leaf whose CN sits inside the
///     excluded subtree. The fallback is keyed on SAN-extension *presence*,
///     not on the dNSName list being empty, so the two functions stay in
///     lockstep (an IP-only-SAN certificate's CN is ignored by both).
///     IP-shaped CNs are kept out (inert for hostname verification, and
///     `dns_name_matches` refuses IP-shaped patterns). Only the leaf's CN is
///     ever consumed as a hostname, so an intermediate CA's CN — a display
///     name such as `Corp Issuing CA 1` — is not held to dNSName subtrees.
///   * iPAddress — the SAN iPAddress entries.
///   * rfc822Name — the SAN rfc822Name entries, or, when there are none, the
///     PKCS#9 `emailAddress` attributes of the subject DN (§4.2.1.10).
///   * uniformResourceIdentifier — the SAN URI entries; the constraint
///     applies to each URI's host component ([`uri_in_subtree`]).
///   * directoryName — the subject DN (unless empty) plus every SAN
///     directoryName entry, matched by RDN prefix ([`dn_in_subtree`]).
///   * otherName / x400Address / ediPartyName / registeredID — forms this
///     crate cannot match. When some in-scope CA declares a subtree of such a
///     form *and* `cert` presents a SAN entry of that form, the certificate
///     is refused (it could be neither admitted nor excluded correctly);
///     when `cert` presents no name of that form the subtree is inert and
///     ignored, exactly as the RFC's per-form rule prescribes.
///
/// A dNSName wildcard SAN is treated as the subtree it spans when tested
/// against excluded subtrees (see the body); the permitted direction needs
/// no such treatment.
///
/// Beyond the RFC, a *leaf* with no subjectAltName extension and no
/// DNS-plausible CN — nothing `verify_hostname` could ever match — is
/// refused while some in-scope CA declares a permitted dNSName / iPAddress
/// subtree: this validator serves TLS, and a nameless leaf under a
/// host-constrained CA is never what the constraint intended (modern PKI —
/// CA/B Forum BR §7.1.4.2 — requires a SAN on server certificates anyway).
/// A CA that declared ONLY excluded subtrees does not by itself force a name
/// to exist. Intermediates are exempt: their names are never authenticated,
/// and a CA certificate carries no SAN as a rule.
fn enforce_constraints_on_cert(
    cert: &Certificate,
    active: &[&crate::x509::NameConstraints],
    is_leaf: bool,
) -> Result<(), Error> {
    let bad = |_| Error::BadCertificate;
    let has_san = cert.has_subject_alt_name().map_err(bad)?;
    let mut dns = cert.subject_alt_names().map_err(bad)?;
    let ips = cert.subject_alt_ips().map_err(bad)?;
    let mut emails = cert.subject_alt_emails().map_err(bad)?;
    let uris = cert.subject_alt_uris().map_err(bad)?;
    let mut dir_names = cert.subject_alt_directory_names().map_err(bad)?;
    let forms = cert.subject_alt_name_forms().map_err(bad)?;
    let subject_der = cert.subject_der().map_err(bad)?;

    // CN fallback parity with `verify_hostname` (leaf only; see above).
    if is_leaf
        && !has_san
        && let Some(cn) = cert.subject().map_err(bad)?.common_name
        && cn_is_plausible_dns_name(&cn)
    {
        dns.push(cn);
    }
    // RFC 5280 §4.2.1.10: "When rfc822Name constraints are in place and the
    // certificate does not include a subject alternative name [rfc822Name],
    // the rfc822Name constraint MUST be applied to the attribute of type
    // emailAddress in the subject distinguished name."
    if emails.is_empty() {
        emails = crate::x509::email_addresses_in_name(subject_der).map_err(bad)?;
    }
    // RFC 5280 §6.1.4 (g): the subject DN itself is a directoryName-form
    // name, unless it is empty (permitted for an end entity whose SAN is
    // critical, §4.1.2.6).
    if dn_rdns(subject_der).is_some_and(|rdns| !rdns.is_empty()) {
        dir_names.insert(0, subject_der.to_vec());
    }

    // Nameless-leaf rule (see above): no SAN extension and no DNS-plausible
    // CN. A SAN holding only names of other forms is not nameless — those
    // names are simply of forms a dNSName / iPAddress subtree does not
    // restrict.
    if is_leaf && !has_san && dns.is_empty() {
        let any_permitted_host = active
            .iter()
            .any(|nc| !nc.permitted.dns.is_empty() || !nc.permitted.ip.is_empty());
        if any_permitted_host {
            return Err(Error::BadCertificate);
        }
    }

    // A wildcard SAN authorises every host under its suffix, so an excluded
    // subtree that falls anywhere inside that span must count as a match.
    // Comparing literally (`dns_in_subtree("*.example.com",
    // "secure.example.com")` is false, because "*" is just a label) let the
    // standard "delegate example.com but not secure.example.com" pattern be
    // defeated: a leaf with `SAN = *.example.com` passed both the permitted
    // and excluded checks and then authenticated `secure.example.com` via
    // `dns_name_matches`. Normalise the wildcard to the subtree it covers.
    //
    // The permitted-subtree direction below needs no such treatment: a
    // wildcard is permitted only when its literal suffix already sits inside
    // a permitted base, which is the conservative answer.
    let excluded_dns_hit = |name: &str, base: &str| {
        dns_in_subtree(name, base)
            || name
                .strip_prefix("*.")
                .is_some_and(|apex| dns_in_subtree(base, apex))
    };
    let ip_bytes = |ip: &crate::x509::SanIp| -> Vec<u8> {
        match ip {
            crate::x509::SanIp::V4(b) => b.to_vec(),
            crate::x509::SanIp::V6(b) => b.to_vec(),
        }
    };

    for nc in active {
        // A subtree form we cannot evaluate, constraining a form the
        // certificate presents: fail closed.
        if nc.unsupported_forms() & forms != 0 {
            return Err(Error::BadCertificate);
        }

        // Excluded subtrees: any match in any in-scope CA is fatal.
        let ex = &nc.excluded;
        if dns
            .iter()
            .any(|n| ex.dns.iter().any(|b| excluded_dns_hit(n, b)))
            || ips.iter().any(|ip| {
                ex.ip
                    .iter()
                    .any(|(a, m)| ip_in_subtree(&ip_bytes(ip), a, m))
            })
            || emails
                .iter()
                .any(|n| ex.email.iter().any(|b| email_in_subtree(n, b)))
            || uris
                .iter()
                .any(|n| ex.uri.iter().any(|b| uri_in_subtree(n, b)))
            || dir_names
                .iter()
                .any(|n| ex.directory.iter().any(|b| dn_in_subtree(n, b)))
        {
            return Err(Error::BadCertificate);
        }

        // Permitted subtrees: for each form this CA constrains, every name
        // of that form must match at least one of its entries. A form with
        // no permitted entry here is unrestricted by this CA.
        let pm = &nc.permitted;
        if !pm.dns.is_empty()
            && !dns
                .iter()
                .all(|n| pm.dns.iter().any(|b| dns_in_subtree(n, b)))
        {
            return Err(Error::BadCertificate);
        }
        if !pm.ip.is_empty()
            && !ips.iter().all(|ip| {
                pm.ip
                    .iter()
                    .any(|(a, m)| ip_in_subtree(&ip_bytes(ip), a, m))
            })
        {
            return Err(Error::BadCertificate);
        }
        if !pm.email.is_empty()
            && !emails
                .iter()
                .all(|n| pm.email.iter().any(|b| email_in_subtree(n, b)))
        {
            return Err(Error::BadCertificate);
        }
        if !pm.uri.is_empty()
            && !uris
                .iter()
                .all(|n| pm.uri.iter().any(|b| uri_in_subtree(n, b)))
        {
            return Err(Error::BadCertificate);
        }
        if !pm.directory.is_empty()
            && !dir_names
                .iter()
                .all(|n| pm.directory.iter().any(|b| dn_in_subtree(n, b)))
        {
            return Err(Error::BadCertificate);
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
/// Case-insensitive compare per RFC 4343 §2. A single trailing dot (the
/// fully-qualified "root" form, `host.example.com.`) is stripped from both
/// sides first — see [`strip_trailing_dot`].
fn dns_in_subtree(name: &str, base: &str) -> bool {
    let name_l = strip_trailing_dot(name).to_ascii_lowercase();
    let base_l = strip_trailing_dot(base).to_ascii_lowercase();
    // RFC 5280 §4.2.1.10: a dNSName constraint matches every name built by
    // adding labels to its left, and the empty string is a left-extension of
    // every DNS name. So an empty base matches all DNS names — `permitted:
    // dNSName ""` permits every host, `excluded: dNSName ""` (the CA/Browser
    // Forum "no DNS names at all" technically-constrained sub-CA form) forbids
    // every host.
    if base_l.is_empty() {
        return true;
    }
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

/// True if `host` (the domain part of a mailbox, or the host component of a
/// URI) falls within the host-form constraint `base` per RFC 5280 §4.2.1.10:
/// * base "example.com" matches exactly that host;
/// * base ".example.com" (leading dot) matches any host in the domain —
///   "a.example.com", "a.b.example.com" — but NOT "example.com" itself.
///
/// Unlike dNSName subtrees, a host-form constraint without a leading dot
/// names one host, not a domain. Case-insensitive (RFC 4343 §2).
fn host_in_subtree(host: &str, base: &str) -> bool {
    let host_l = host.to_ascii_lowercase();
    let base_l = base.to_ascii_lowercase();
    if base_l.starts_with('.') {
        host_l.len() > base_l.len() && host_l.ends_with(&base_l)
    } else {
        host_l == base_l
    }
}

/// True if the rfc822Name `mailbox` falls within the rfc822Name subtree
/// `base` per RFC 5280 §4.2.1.10. `base` is either a full mailbox
/// (`user@example.com`: exact match, the domain part compared
/// case-insensitively and the local part verbatim, as RFC 5321 §2.4 leaves
/// local-part case to the receiving host) or a host / leading-dot domain
/// applied to the mailbox's domain part ([`host_in_subtree`]). A name
/// without an `@` has no domain part and matches no subtree.
fn email_in_subtree(mailbox: &str, base: &str) -> bool {
    let Some((local, domain)) = mailbox.rsplit_once('@') else {
        return false;
    };
    match base.rsplit_once('@') {
        Some((base_local, base_domain)) => {
            local == base_local && domain.eq_ignore_ascii_case(base_domain)
        }
        None => host_in_subtree(domain, base),
    }
}

/// The host component of `uri` (`scheme://[userinfo@]host[:port]/…`), or
/// `None` when the URI has no authority (`mailto:`, `urn:`, …), an empty
/// host, or an IP-literal host (`[::1]`, `10.0.0.1`). RFC 5280 §4.2.1.10:
/// "The constraint MUST be specified as a fully qualified domain name"; a
/// URI whose host is an IP address can therefore match no host-name subtree.
fn uri_host(uri: &str) -> Option<&str> {
    let (scheme, rest) = uri.split_once(':')?;
    // RFC 3986 §3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
    let mut scheme_bytes = scheme.bytes();
    if !scheme_bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        || !scheme_bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let rest = rest.strip_prefix("//")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // `[…]` is an IP-literal (IPv6 or IPvFuture); a bare host never contains
    // ':' so the split is unambiguous for the reg-name case.
    if hostport.starts_with('[') {
        return None;
    }
    let host = hostport.split_once(':').map_or(hostport, |(h, _)| h);
    if host.is_empty() || looks_like_ip(host) {
        return None;
    }
    Some(host)
}

/// True if the host component of `uri` falls within the URI subtree `base`
/// (a host or leading-dot domain, [`host_in_subtree`]). A URI with no host
/// name component ([`uri_host`]) matches no subtree.
fn uri_in_subtree(uri: &str, base: &str) -> bool {
    uri_host(uri).is_some_and(|host| host_in_subtree(host, base))
}

/// Splits a DER `Name` TLV into its RDN encodings (each the full
/// `SET` TLV), or `None` if the bytes are not a well-formed
/// `SEQUENCE OF RelativeDistinguishedName`.
fn dn_rdns(name_der: &[u8]) -> Option<Vec<&[u8]>> {
    let mut reader = crate::der::Reader::new(name_der);
    let mut seq = reader.read_sequence().ok()?;
    reader.finish().ok()?;
    let mut out = Vec::new();
    while !seq.is_empty() {
        out.push(seq.read_element().ok()?);
    }
    Some(out)
}

/// True if the distinguished name `name` (a DER `Name` TLV) falls within
/// the directoryName subtree `base` (likewise): RFC 5280 §4.2.1.10 /
/// §7.1 — the subtree's RDN sequence is a prefix of the name's, each RDN
/// compared as the crate compares issuer and subject names, byte-for-byte
/// (so encoding differences and a different RDN order are non-matches). An
/// empty subtree is a prefix of every name. Undecodable bytes on either
/// side never match.
fn dn_in_subtree(name: &[u8], base: &[u8]) -> bool {
    match (dn_rdns(name), dn_rdns(base)) {
        (Some(n), Some(b)) => b.len() <= n.len() && n.iter().zip(&b).all(|(x, y)| x == y),
        _ => false,
    }
}

/// RFC 5280 §4.2: reject the certificate if it carries any critical extension
/// whose OID we don't recognize. The handler set (basicConstraints, keyUsage,
/// extKeyUsage, subjectAltName, nameConstraints) is intentionally narrow —
/// every critical extension outside this set is treated as "we cannot enforce
/// this constraint", which must result in rejection.
///
/// `nameConstraints` is recognized whenever it parses: every subtree form is
/// evaluated by [`enforce_name_constraints`] irrespective of criticality, and
/// a form the crate cannot evaluate is failed closed there exactly when the
/// subordinate certificate presents a name of that form. A critical
/// `nameConstraints` that does not parse is rejected here (the leaf's is
/// otherwise never parsed).
fn check_critical_extensions_recognized(
    cert: &Certificate,
    policy_processing: bool,
) -> Result<(), Error> {
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
        // Policy-related critical extensions are "recognized" only when the
        // caller enabled policy processing — `check_policies` then evaluates
        // them. With policy processing off (the default) they fall through to
        // the fail-closed unknown-critical rejection, preserving the
        // pre-existing default behavior exactly.
        if policy_processing
            && (bytes == oid::CERTIFICATE_POLICIES
                || bytes == oid::POLICY_MAPPINGS
                || bytes == oid::POLICY_CONSTRAINTS
                || bytes == oid::INHIBIT_ANY_POLICY)
        {
            continue;
        }
        if bytes == oid::NAME_CONSTRAINTS {
            cert.name_constraints()
                .map_err(|_| Error::BadCertificate)?
                .ok_or(Error::BadCertificate)?;
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

/// Checks that the end-entity certificate identifies `host`. Uses the
/// `subjectAltName` entries (RFC 6125); the subject commonName is consulted
/// only when the certificate carries **no subjectAltName extension at all**
/// (see `Certificate::has_subject_alt_name`).
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
    // RFC 6125 §6.4.4 / CA-Browser Forum BR: the commonName fallback is
    // conditioned on the ABSENCE of a subjectAltName extension, not on the
    // absence of dNSName entries inside it. A certificate whose SAN holds
    // only iPAddress / rfc822Name / uniformResourceIdentifier entries is
    // still SAN-bearing, so its CN must be ignored — otherwise a legitimately
    // issued IP-only certificate carrying a misleading
    // `CN=login.bank.example` would authenticate that hostname.
    let matched = if cert
        .has_subject_alt_name()
        .map_err(|_| Error::BadCertificate)?
    {
        let sans = cert
            .subject_alt_names()
            .map_err(|_| Error::BadCertificate)?;
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

/// Strips a single trailing dot from a DNS name, if present.
///
/// `host.example.com.` and `host.example.com` denote the same name (the
/// trailing dot just makes the FQDN explicit). Both the reference identifier a
/// caller passes to [`verify_hostname`] and the names inside a certificate
/// (SAN dNSName entries, nameConstraints bases) may carry it, so every DNS
/// comparison in this module normalizes it away first. Without that, a leaf
/// whose SAN reads `secure.example.com.` escaped an `excluded` name constraint
/// on `secure.example.com` while still matching a hostname check for
/// `secure.example.com.`. A bare `"."` (the root) is left alone — stripping it
/// would produce the empty name.
fn strip_trailing_dot(name: &str) -> &str {
    match name.strip_suffix('.') {
        Some(stripped) if !stripped.is_empty() => stripped,
        _ => name,
    }
}

/// Matches a certificate dNSName `pattern` against `host`, case-insensitively,
/// allowing a single leftmost-label `*` wildcard (`*.example.com` matches
/// `a.example.com` but not `example.com` or `a.b.example.com`). A single
/// trailing dot on either side is normalized away first
/// ([`strip_trailing_dot`]).
fn dns_name_matches(pattern: &str, host: &str) -> bool {
    let pattern = strip_trailing_dot(pattern);
    let host = strip_trailing_dot(host);
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
        //
        // The remainder must also keep at least two labels: `*.com` (or
        // `*.co.uk`-shaped public suffixes, which we cannot enumerate) would
        // otherwise let one certificate speak for an entire TLD. Requiring a
        // dot in the remainder is the same floor browsers apply.
        if !suffix.contains('.') {
            return false;
        }
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
        let rsa_key = rsa_test_key_a();
        let any_key = crate::x509::AnyPrivateKey::Rsa(rsa_key.to_boxed());
        // SAN cert: matches SAN entries (incl. wildcard), ignores CN.
        let san_cert = Certificate::self_signed_with_sans(
            &any_key,
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
            &rsa_key,
            &DistinguishedName::common_name("host.example"),
            &validity(),
            2,
            false,
        )
        .unwrap();
        verify_hostname(&cn_cert, "HOST.example").unwrap(); // case-insensitive
        assert!(verify_hostname(&cn_cert, "wrong.example").is_err());
    }

    /// MEDIUM: a certificate whose subjectAltName carries only `iPAddress`
    /// entries has an empty dNSName list, but the extension IS present — so
    /// RFC 6125 §6.4.4 and the CA/Browser Forum BRs forbid falling back to
    /// the commonName. Otherwise a legitimately issued IP-only certificate
    /// (private/internal CAs routinely validate only the SAN for IP
    /// issuance) with `CN=login.bank.example` would authenticate that host.
    #[test]
    fn hostname_ip_only_san_does_not_fall_back_to_cn() {
        use crate::x509::{
            CertSigner, GeneralName, KeyUsageBits,
            extension::{basic_constraints, key_usage, subject_alt_name},
        };
        let rsa_key = rsa_test_key_a().to_boxed();
        let signer = CertSigner::Rsa(&rsa_key);
        let exts = [
            basic_constraints(false, None),
            key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
            // SAN present, but with no dNSName at all.
            subject_alt_name(&[GeneralName::IpV4([203, 0, 113, 5])]),
        ];
        let cert = Certificate::self_signed_with_extensions(
            &signer,
            &DistinguishedName::common_name("login.bank.example"),
            &validity(),
            1,
            &exts,
        )
        .unwrap();

        // The misleading CN must NOT authenticate the hostname.
        assert!(verify_hostname(&cert, "login.bank.example").is_err());
        // The iPAddress SAN still works for the IP-literal reference identifier.
        verify_hostname(&cert, "203.0.113.5").unwrap();
        assert!(verify_hostname(&cert, "203.0.113.6").is_err());

        // Same for an rfc822Name-only SAN: present ⇒ CN ignored.
        let email_exts = [
            basic_constraints(false, None),
            key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
            subject_alt_name(&[GeneralName::Email("ops@bank.example".into())]),
        ];
        let email_cert = Certificate::self_signed_with_extensions(
            &signer,
            &DistinguishedName::common_name("login.bank.example"),
            &validity(),
            2,
            &email_exts,
        )
        .unwrap();
        assert!(verify_hostname(&email_cert, "login.bank.example").is_err());
    }

    /// MEDIUM: an excluded dNSName subtree must not be escapable with a
    /// wildcard SAN. The classic delegation shape — `permitted = example.com`,
    /// `excluded = secure.example.com` — was defeated by a leaf carrying
    /// `SAN = *.example.com`: literal subtree comparison treats `*` as an
    /// ordinary label, so the exclusion never matched, yet `dns_name_matches`
    /// then happily authenticated `secure.example.com`.
    #[test]
    fn name_constraints_excluded_not_bypassed_by_wildcard_san() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Dns("example.com".into())],
            &[GeneralName::Dns("secure.example.com".into())],
        );
        let leaf_sans = [GeneralName::Dns("*.example.com".into())];
        let (root, int, leaf) = build_chain_with_nc(nc, "nc-leaf", &leaf_sans);

        // The wildcard really does cover the excluded host — that is the point.
        assert!(dns_name_matches("*.example.com", "secure.example.com"));

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

    /// The wildcard normalisation above must not over-reject: a wildcard SAN
    /// whose span does not reach the excluded subtree still verifies.
    #[test]
    fn name_constraints_wildcard_san_outside_excluded_subtree_accepted() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Dns("example.com".into())],
            &[GeneralName::Dns("secure.example.com".into())],
        );
        // "*.eu.example.com" spans only hosts under ".eu.example.com", which
        // does not contain "secure.example.com".
        let leaf_sans = [GeneralName::Dns("*.eu.example.com".into())];
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

    /// The name-constraint side of the SAN-presence rule must track
    /// `verify_hostname`: an IP-only-SAN leaf has no dNSName for a dNSName
    /// constraint to govern, and its CN is inert (never consulted for
    /// hostname verification), so an excluded-only dNSName constraint cannot
    /// be violated by it.
    #[test]
    fn name_constraints_cn_ignored_when_ip_only_san_present() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[],
            &[GeneralName::Dns(".bad.example".into())],
        );
        let leaf_sans = [GeneralName::IpV4([10, 0, 0, 1])];
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
        // ...and the CN it carries authenticates nothing.
        assert!(verify_hostname(&leaf, "host.bad.example").is_err());
    }

    /// Issuing and validating a self-signed ML-DSA-65 certificate through
    /// the full `verify_chain` path. ML-DSA is on the default whitelist as
    /// of commit 3, so no policy tuning is needed.
    #[cfg(feature = "mldsa")]
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
    #[cfg(feature = "slhdsa")]
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
        let signer_key = crate::rsa::BoxedRsaPrivateKey::from_pkcs1_pem(include_str!(
            "../../../testdata/rsa2048_test_a.pem"
        ))
        .unwrap();
        let signer = CertSigner::Rsa(&signer_key);
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

        let signer_key = crate::rsa::BoxedRsaPrivateKey::from_pkcs1_pem(include_str!(
            "../../../testdata/rsa2048_test_a.pem"
        ))
        .unwrap();
        let signer = CertSigner::Rsa(&signer_key);
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
        let bogus_signer_key = crate::rsa::BoxedRsaPrivateKey::from_pkcs1_pem(include_str!(
            "../../../testdata/rsa2048_test_b.pem"
        ))
        .unwrap();
        let bogus_signer = CertSigner::Rsa(&bogus_signer_key);
        let mut b = CrlBuilder::new(&ca_name, Time::utc(2026, 1, 1, 0, 0, 0), None);
        b.revoke(&[55], Time::utc(2026, 1, 2, 0, 0, 0), None);
        let crl = b.sign(&bogus_signer).unwrap();
        let mut crls = CrlStore::new();
        crls.add_der(crl.to_der().to_vec()).unwrap();

        verify_chain_with_crls(&store, &crls, &[leaf.to_der().to_vec()], None, &policy()).unwrap();
    }

    /// RFC 5280 §6.3.3: a key used to sign a CRL must assert `cRLSign` in its
    /// keyUsage extension when one is present. An intermediate CA that carries
    /// keyUsage with `keyCertSign` but WITHOUT `cRLSign` cannot validly sign a
    /// CRL, so a CRL it signs revoking the leaf must be ignored — the chain
    /// still validates. The companion `crl_with_crlsign_issuer_revokes` test
    /// confirms an issuer that *does* assert `cRLSign` revokes as expected.
    #[test]
    fn crl_issuer_without_crlsign_is_ignored() {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;
        use crate::tls::pki::CrlStore;
        use crate::x509::{
            CertSigner, CrlBuilder, KeyUsageBits,
            extension::{basic_constraints, extended_key_usage, key_usage},
        };

        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"crlsign-ku", b"n", &[]);
        let root_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let int_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let leaf_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let root_signer = CertSigner::Ecdsa(&root_key);
        let int_signer = CertSigner::Ecdsa(&int_key);

        let root_name = DistinguishedName::common_name("crlku-root");
        let int_name = DistinguishedName::common_name("crlku-int");
        let leaf_name = DistinguishedName::common_name("crlku-leaf");

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

        // Intermediate CA: keyCertSign is set (so it may sign the leaf) but
        // cRLSign is deliberately omitted.
        let int_pub = crate::x509::AnyPublicKey::Ecdsa(int_key.public_key());
        let int = Certificate::issue_with_extensions(
            &root_signer,
            &root_name,
            &int_name,
            &int_pub,
            &validity(),
            2,
            &[
                basic_constraints(true, None),
                key_usage(KeyUsageBits::KEY_CERT_SIGN),
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
            77,
            &[
                basic_constraints(false, None),
                key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
                extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
            ],
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();

        // The intermediate signs a CRL revoking the leaf (serial 77). Because
        // the intermediate lacks cRLSign, RFC 5280 §6.3.3 says it is not a
        // valid CRL signer, so the CRL is skipped and the leaf is NOT revoked.
        let mut b = CrlBuilder::new(&int_name, Time::utc(2026, 1, 1, 0, 0, 0), None);
        b.revoke(&[77], Time::utc(2026, 1, 2, 0, 0, 0), None);
        let crl = b.sign(&int_signer).unwrap();
        let mut crls = CrlStore::new();
        crls.add_der(crl.to_der().to_vec()).unwrap();

        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        let chain = alloc::vec![leaf.to_der().to_vec(), int.to_der().to_vec()];
        verify_chain_with_crls(&store, &crls, &chain, Some(&now), &policy()).unwrap();
    }

    /// Sanity counterpart to `crl_issuer_without_crlsign_is_ignored`: the same
    /// chain shape, but the intermediate asserts `cRLSign`, so its CRL is
    /// honored and the leaf is revoked.
    #[test]
    fn crl_with_crlsign_issuer_revokes() {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;
        use crate::tls::pki::CrlStore;
        use crate::x509::{
            CertSigner, CrlBuilder, KeyUsageBits,
            extension::{basic_constraints, extended_key_usage, key_usage},
        };

        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"crlsign-ok", b"n", &[]);
        let root_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let int_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let leaf_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let root_signer = CertSigner::Ecdsa(&root_key);
        let int_signer = CertSigner::Ecdsa(&int_key);

        let root_name = DistinguishedName::common_name("crlok-root");
        let int_name = DistinguishedName::common_name("crlok-int");
        let leaf_name = DistinguishedName::common_name("crlok-leaf");

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

        let int_pub = crate::x509::AnyPublicKey::Ecdsa(int_key.public_key());
        let int = Certificate::issue_with_extensions(
            &root_signer,
            &root_name,
            &int_name,
            &int_pub,
            &validity(),
            2,
            &[
                basic_constraints(true, None),
                key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
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
            77,
            &[
                basic_constraints(false, None),
                key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
                extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
            ],
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();

        let mut b = CrlBuilder::new(&int_name, Time::utc(2026, 1, 1, 0, 0, 0), None);
        b.revoke(&[77], Time::utc(2026, 1, 2, 0, 0, 0), None);
        let crl = b.sign(&int_signer).unwrap();
        let mut crls = CrlStore::new();
        crls.add_der(crl.to_der().to_vec()).unwrap();

        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        let chain = alloc::vec![leaf.to_der().to_vec(), int.to_der().to_vec()];
        assert!(matches!(
            verify_chain_with_crls(&store, &crls, &chain, Some(&now), &policy()),
            Err(Error::BadCertificate)
        ));
    }

    /// LOW: the candidate-CRL list is peer-controlled (TLS 1.3 stapled
    /// `CRL_RESPONSE` entries), and each candidate costs a public-key
    /// verification before anything cheap can rule it out. `check_revocation`
    /// bounds that work at [`MAX_CRLS_PER_ISSUER`] verifications per chain
    /// link. The cap must be comfortably above any real deployment: filler
    /// below the cap must not hide a genuine revocation.
    #[test]
    fn crl_verification_budget_is_bounded_but_not_tight() {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;
        use crate::tls::pki::CrlStore;
        use crate::x509::{
            CertSigner, CrlBuilder, KeyUsageBits,
            extension::{basic_constraints, extended_key_usage, key_usage},
        };

        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"crl-budget", b"n", &[]);
        let root_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let junk_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let leaf_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let root_signer = CertSigner::Ecdsa(&root_key);
        let junk_signer = CertSigner::Ecdsa(&junk_key);

        let root_name = DistinguishedName::common_name("budget-root");
        let leaf_name = DistinguishedName::common_name("budget-leaf");
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
        let leaf = Certificate::issue_with_extensions(
            &root_signer,
            &root_name,
            &leaf_name,
            &crate::x509::AnyPublicKey::Ecdsa(leaf_key.public_key()),
            &validity(),
            77,
            &[
                basic_constraints(false, None),
                key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
                extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
            ],
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        let chain = alloc::vec![leaf.to_der().to_vec()];

        // Well-formed, fresh, correctly-issuer-named CRLs signed by the WRONG
        // key: each survives every cheap filter and burns one verification.
        let junk = |serial: u8| {
            let mut b = CrlBuilder::new(&root_name, Time::utc(2026, 1, 1, 0, 0, 0), None);
            b.revoke(&[serial], Time::utc(2026, 1, 2, 0, 0, 0), None);
            b.sign(&junk_signer).unwrap().to_der().to_vec()
        };
        // The genuine one, revoking the leaf.
        let mut real = CrlBuilder::new(&root_name, Time::utc(2026, 1, 1, 0, 0, 0), None);
        real.revoke(&[77], Time::utc(2026, 1, 2, 0, 0, 0), None);
        let real = real.sign(&root_signer).unwrap().to_der().to_vec();

        // Filler up to one below the cap, genuine CRL last: still revoked.
        let mut crls = CrlStore::new();
        for i in 0..(MAX_CRLS_PER_ISSUER - 1) {
            crls.add_der(junk(i as u8)).unwrap();
        }
        crls.add_der(real.clone()).unwrap();
        assert!(matches!(
            verify_chain_with_crls(&store, &crls, &chain, Some(&now), &policy()),
            Err(Error::BadCertificate)
        ));

        // Sanity: the genuine CRL alone revokes (the filler above is inert).
        let mut only_real = CrlStore::new();
        only_real.add_der(real).unwrap();
        assert!(matches!(
            verify_chain_with_crls(&store, &only_real, &chain, Some(&now), &policy()),
            Err(Error::BadCertificate)
        ));

        // A pure flood consults nothing valid and leaves the chain accepted —
        // the budget bounds the work rather than changing the verdict.
        let mut flood = CrlStore::new();
        for i in 0..(MAX_CRLS_PER_ISSUER * 4) {
            flood.add_der(junk(i as u8)).unwrap();
        }
        verify_chain_with_crls(&store, &flood, &chain, Some(&now), &policy()).unwrap();
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
        // A single trailing dot on either side denotes the same name.
        assert!(super::dns_name_matches("example.com", "example.com."));
        assert!(super::dns_name_matches("example.com.", "example.com"));
        assert!(super::dns_name_matches(
            "*.example.com.",
            "host.example.com"
        ));
        assert!(super::dns_name_matches(
            "*.example.com",
            "host.example.com."
        ));
        assert!(!super::dns_name_matches("example.com.", "other.com"));
        // A wildcard must leave at least two labels: `*.com` must not
        // authenticate an entire TLD.
        assert!(!super::dns_name_matches("*.com", "example.com"));
        assert!(!super::dns_name_matches("*.com.", "example.com"));
        assert!(!super::dns_name_matches("*.", "example"));
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
        // A single trailing dot (the explicit-FQDN form) is normalized away on
        // both sides: it must not let a name escape a subtree.
        assert!(super::dns_in_subtree("example.com.", "example.com"));
        assert!(super::dns_in_subtree("foo.example.com.", "example.com"));
        assert!(super::dns_in_subtree("example.com", "example.com."));
        assert!(super::dns_in_subtree("foo.example.com.", ".example.com"));
        assert!(!super::dns_in_subtree("notexample.com.", "example.com"));
        // RFC 5280 §4.2.1.10: an empty base is a left-extension of every DNS
        // name, so it matches everything (the CA/B "no DNS names" form).
        assert!(super::dns_in_subtree("anything.example", ""));
        assert!(super::dns_in_subtree("example.com", ""));
    }

    /// RFC 5937 trust-anchor constraints: a root that declares
    /// `pathLenConstraint` / `extKeyUsage` on itself has them honoured, while
    /// a root declaring neither is unconstrained exactly as before.
    #[test]
    fn anchor_self_constraints_are_honoured() {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;
        use crate::x509::{
            CertSigner, DistinguishedName, Extension, GeneralName, KeyUsageBits,
            extension::{basic_constraints, extended_key_usage, key_usage, subject_alt_name},
        };

        // `root_exts` varies per case; everything below the root is fixed:
        // root -> intermediate -> leaf, plus a leaf issued directly by the root.
        let build = |root_exts: &[Extension]| {
            let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"anchor-constraints", b"n", &[]);
            let root_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
            let int_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
            let leaf_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
            let root_signer = CertSigner::Ecdsa(&root_key);
            let int_signer = CertSigner::Ecdsa(&int_key);
            let root_name = DistinguishedName::common_name("anchor-root");
            let int_name = DistinguishedName::common_name("anchor-intermediate");
            let root = Certificate::self_signed_with_extensions(
                &root_signer,
                &root_name,
                &validity(),
                1,
                root_exts,
            )
            .unwrap();
            let int = Certificate::issue_with_extensions(
                &root_signer,
                &root_name,
                &int_name,
                &crate::x509::AnyPublicKey::Ecdsa(int_key.public_key()),
                &validity(),
                2,
                &[
                    basic_constraints(true, None),
                    key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
                ],
            )
            .unwrap();
            let leaf_exts = [
                basic_constraints(false, None),
                key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
                extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
                subject_alt_name(&[GeneralName::Dns("leaf.example".into())]),
            ];
            let leaf_pub = crate::x509::AnyPublicKey::Ecdsa(leaf_key.public_key());
            let deep = Certificate::issue_with_extensions(
                &int_signer,
                &int_name,
                &DistinguishedName::common_name("leaf.example"),
                &leaf_pub,
                &validity(),
                3,
                &leaf_exts,
            )
            .unwrap();
            let direct = Certificate::issue_with_extensions(
                &root_signer,
                &root_name,
                &DistinguishedName::common_name("leaf.example"),
                &leaf_pub,
                &validity(),
                4,
                &leaf_exts,
            )
            .unwrap();
            (root, int, deep, direct)
        };
        let check = |root: &Certificate, chain: alloc::vec::Vec<alloc::vec::Vec<u8>>| {
            let mut store = RootCertStore::new();
            store.add_der(root.to_der().to_vec()).unwrap();
            let now = Time::utc(2026, 1, 1, 0, 0, 0);
            verify_chain(&store, &chain, Some(&now), &policy()).map(|_| ())
        };

        let ku = key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN);
        // Baseline: no pathLen, no EKU on the root → both chains validate.
        let (root, int, deep, direct) = build(&[basic_constraints(true, None), ku.clone()]);
        assert_eq!(
            check(
                &root,
                alloc::vec![deep.to_der().to_vec(), int.to_der().to_vec()]
            ),
            Ok(())
        );
        assert_eq!(check(&root, alloc::vec![direct.to_der().to_vec()]), Ok(()));

        // pathlen:0 on the root → no intermediate may sit below it.
        let (root, int, deep, direct) = build(&[basic_constraints(true, Some(0)), ku.clone()]);
        assert_eq!(
            check(
                &root,
                alloc::vec![deep.to_der().to_vec(), int.to_der().to_vec()]
            ),
            Err(Error::BadCertificate)
        );
        assert_eq!(check(&root, alloc::vec![direct.to_der().to_vec()]), Ok(()));

        // pathlen:1 leaves room for exactly that one intermediate.
        let (root, int, deep, _direct) = build(&[basic_constraints(true, Some(1)), ku.clone()]);
        assert_eq!(
            check(
                &root,
                alloc::vec![deep.to_der().to_vec(), int.to_der().to_vec()]
            ),
            Ok(())
        );

        // An EKU-scoped root must permit the purpose being validated for.
        let (root, int, deep, _direct) = build(&[
            basic_constraints(true, None),
            ku.clone(),
            extended_key_usage(&[oid::ID_KP_CLIENT_AUTH]),
        ]);
        assert_eq!(
            check(
                &root,
                alloc::vec![deep.to_der().to_vec(), int.to_der().to_vec()]
            ),
            Err(Error::BadCertificate),
            "clientAuth-only root must not anchor a serverAuth chain"
        );
        let (root, int, deep, _direct) = build(&[
            basic_constraints(true, None),
            ku,
            extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
        ]);
        assert_eq!(
            check(
                &root,
                alloc::vec![deep.to_der().to_vec(), int.to_der().to_vec()]
            ),
            Ok(())
        );
    }

    /// Regression: a SAN dNSName with a trailing dot used to slip past an
    /// `excluded` dNSName subtree while still authenticating the same host.
    #[test]
    fn trailing_dot_san_cannot_escape_excluded_subtree() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[],
            &[GeneralName::Dns("secure.example.com".into())],
        );
        let leaf_sans = [GeneralName::Dns("secure.example.com.".into())];
        let (root, int, leaf) = build_chain_with_nc(nc, "nc-leaf", &leaf_sans);

        // The trailing-dot SAN still names the excluded host...
        assert_eq!(
            super::verify_hostname(&leaf, "secure.example.com."),
            Ok(()),
            "trailing-dot reference identifier matches the trailing-dot SAN"
        );
        assert_eq!(
            super::verify_hostname(&leaf, "secure.example.com"),
            Ok(()),
            "and the same host without the dot"
        );
        // ...so the chain must be rejected by the excluded subtree.
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        assert_eq!(
            verify_chain(
                &store,
                &[leaf.to_der().to_vec(), int.to_der().to_vec()],
                Some(&now),
                &policy(),
            )
            .map(|_| ()),
            Err(Error::BadCertificate)
        );
    }

    /// An empty `excluded` dNSName constraint (CA/Browser Forum
    /// technically-constrained sub-CA, "this CA may not issue for any DNS
    /// name") parses and forbids every DNS name; an empty `permitted` one
    /// allows every DNS name.
    #[test]
    fn empty_dns_name_constraint_matches_all_names() {
        use crate::x509::GeneralName;
        let store_and_chain = |nc: crate::x509::Extension, sans: &[GeneralName]| {
            let (root, int, leaf) = build_chain_with_nc(nc, "nc-leaf", sans);
            let mut store = RootCertStore::new();
            store.add_der(root.to_der().to_vec()).unwrap();
            let now = Time::utc(2026, 1, 1, 0, 0, 0);
            verify_chain(
                &store,
                &[leaf.to_der().to_vec(), int.to_der().to_vec()],
                Some(&now),
                &policy(),
            )
            .map(|_| ())
        };
        // Excluded "" → no DNS name may be issued.
        let excluded_all =
            crate::x509::extension::name_constraints(&[], &[GeneralName::Dns("".into())]);
        assert_eq!(
            store_and_chain(excluded_all, &[GeneralName::Dns("host.example".into())]),
            Err(Error::BadCertificate)
        );
        // Permitted "" → every DNS name is inside the subtree.
        let permitted_all =
            crate::x509::extension::name_constraints(&[GeneralName::Dns("".into())], &[]);
        assert_eq!(
            store_and_chain(permitted_all, &[GeneralName::Dns("host.example".into())]),
            Ok(())
        );
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

        // An EMPTY `leaf_sans` means "no subjectAltName extension at all", not
        // "a SAN extension holding nothing": the CN fallback (here and in
        // `verify_hostname`) keys off extension PRESENCE, so emitting an empty
        // SAN would silently turn the CN-fallback tests into no-name tests.
        let mut leaf_exts = alloc::vec![
            basic_constraints(false, None),
            key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
            extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
        ];
        if !leaf_sans.is_empty() {
            leaf_exts.push(subject_alt_name(leaf_sans));
        }
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
    fn name_constraints_critical_rfc822_subtree_is_evaluated() {
        // A critical nameConstraints carrying an rfc822Name subtree is
        // evaluated like any other form: a leaf with only a dNSName SAN
        // presents no rfc822Name-form name, so it is unrestricted and the
        // chain validates (it used to be refused as an unevaluable critical
        // extension); a leaf with an out-of-range rfc822Name is refused.
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Email("admin@example.com".into())],
            &[],
        );
        let leaf_sans = [GeneralName::Dns("leaf.example".into())];
        let (root, int, leaf) = build_chain_with_nc(nc.clone(), "nc-leaf", &leaf_sans);

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

        let leaf_sans = [
            GeneralName::Dns("leaf.example".into()),
            GeneralName::Email("other@example.com".into()),
        ];
        let (root, int, leaf) = build_chain_with_nc(nc, "nc-leaf", &leaf_sans);
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
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

    /// A root whose nameConstraints use a form other than dNSName /
    /// iPAddress (here rfc822Name) is installed by `add_der` — every form is
    /// evaluated — and the chain below it is unaffected when it presents no
    /// name of that form (see `anchor_name_constraints_cover_every_form`
    /// for the enforcement itself).
    #[test]
    fn add_der_accepts_anchor_with_rfc822_constraints() {
        use crate::x509::GeneralName;
        let nc = crate::x509::extension::name_constraints(
            &[GeneralName::Email("admin@example.com".into())],
            &[],
        );
        let (root, int, leaf) =
            build_anchor_nc_chain(Some(nc), "int.good.example", "host.good.example");
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        assert_eq!(store.len(), 1);
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        verify_chain(
            &store,
            &[leaf.to_der().to_vec(), int.to_der().to_vec()],
            Some(&now),
            &policy(),
        )
        .unwrap();
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

    /// Builds a `[leaf, intermediate]` chain + anchored store where the
    /// intermediate carries the given EKU OIDs (none ⇒ no EKU extension). The
    /// leaf always has serverAuth. Returns `(store, chain_der)`.
    fn build_chain_with_int_eku(
        int_ekus: &[&[u64]],
    ) -> (RootCertStore, alloc::vec::Vec<alloc::vec::Vec<u8>>) {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;
        use crate::x509::GeneralName;
        use crate::x509::{
            CertSigner, DistinguishedName, Extension, KeyUsageBits,
            extension::{basic_constraints, extended_key_usage, key_usage, subject_alt_name},
        };

        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"eku-chain", b"n", &[]);
        let root_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let int_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let leaf_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let root_signer = CertSigner::Ecdsa(&root_key);
        let int_signer = CertSigner::Ecdsa(&int_key);

        let root_name = DistinguishedName::common_name("eku-root");
        let int_name = DistinguishedName::common_name("eku-int");
        let leaf_name = DistinguishedName::common_name("eku-leaf");

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

        let mut int_exts: alloc::vec::Vec<Extension> = alloc::vec![
            basic_constraints(true, Some(0)),
            key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
        ];
        if !int_ekus.is_empty() {
            int_exts.push(extended_key_usage(int_ekus));
        }
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

        let leaf = Certificate::issue_with_extensions(
            &int_signer,
            &int_name,
            &leaf_name,
            &crate::x509::AnyPublicKey::Ecdsa(leaf_key.public_key()),
            &validity(),
            3,
            &[
                basic_constraints(false, None),
                key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
                extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
                subject_alt_name(&[GeneralName::Dns("eku-leaf".into())]),
            ],
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let chain = alloc::vec![leaf.to_der().to_vec(), int.to_der().to_vec()];
        (store, chain)
    }

    fn verify_chain_now(store: &RootCertStore, chain: &[alloc::vec::Vec<u8>]) -> Result<(), Error> {
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        verify_chain(store, chain, Some(&now), &policy()).map(|_| ())
    }

    #[test]
    fn intermediate_with_no_eku_is_unconstrained() {
        // An intermediate carrying no extKeyUsage extension is unconstrained
        // and must still validate.
        let (store, chain) = build_chain_with_int_eku(&[]);
        verify_chain_now(&store, &chain).unwrap();
    }

    #[test]
    fn intermediate_with_serverauth_eku_passes() {
        // serverAuth on the intermediate covers the server chain purpose.
        let (store, chain) = build_chain_with_int_eku(&[oid::ID_KP_SERVER_AUTH]);
        verify_chain_now(&store, &chain).unwrap();
    }

    #[test]
    fn intermediate_with_any_eku_passes() {
        // anyExtendedKeyUsage on the intermediate satisfies every purpose.
        let (store, chain) = build_chain_with_int_eku(&[ANY_EXTENDED_KEY_USAGE]);
        verify_chain_now(&store, &chain).unwrap();
    }

    #[test]
    fn intermediate_eku_without_serverauth_is_rejected() {
        // A TLS-scoped intermediate that carries an extKeyUsage NOT including
        // serverAuth (here only clientAuth) must NOT be usable to issue a
        // serverAuth leaf — EKU is now chained to intermediates.
        let (store, chain) = build_chain_with_int_eku(&[oid::ID_KP_CLIENT_AUTH]);
        assert!(matches!(
            verify_chain_now(&store, &chain),
            Err(Error::BadCertificate)
        ));
    }

    /// A CA certified as plain `rsaEncryption` issues an intermediate and a
    /// leaf with `id-RSASSA-PSS` signatures over SHA-384 and SHA-512: the
    /// signature's own `RSASSA-PSS-params` select the registry entry, so
    /// the chain validates under `modern()` (it used to be verified as
    /// SHA-256 and fail), and a policy without those entries refuses it.
    #[test]
    fn rsa_encryption_ca_issuing_pss_sha384_chain_validates() {
        use crate::rsa::BoxedRsaPrivateKey;
        use crate::x509::{AnyPublicKey, CertSigner, PssHash};

        let ca_key = BoxedRsaPrivateKey::from_pkcs1_der(&rsa_test_key_a().to_pkcs1_der()).unwrap();
        let int_key = BoxedRsaPrivateKey::from_pkcs1_der(&rsa_test_key_b().to_pkcs1_der()).unwrap();
        let mut rng =
            crate::rng::HmacDrbg::<crate::hash::Sha256>::new(b"pss-rsae-chain", b"n", &[]);
        let leaf_key =
            crate::ec::BoxedEcdsaPrivateKey::generate(crate::ec::CurveId::P256, &mut rng);
        let ca_name = DistinguishedName::common_name("rsae-root");
        let int_name = DistinguishedName::common_name("rsae-int");
        let leaf_name = DistinguishedName::common_name("rsae-leaf");
        // The root certifies its key as `rsaEncryption` (PKCS#1 v1.5
        // self-signature) but signs what it issues with PSS-SHA-384.
        let root = Certificate::self_signed_general(
            &CertSigner::Rsa(&ca_key),
            &ca_name,
            &validity(),
            1,
            true,
            &[],
        )
        .unwrap();
        assert!(matches!(
            root.subject_public_key().unwrap(),
            AnyPublicKey::Rsa(_)
        ));
        let int = Certificate::issue_general(
            &CertSigner::RsaPss(&ca_key, PssHash::Sha384),
            &ca_name,
            &int_name,
            &AnyPublicKey::Rsa(int_key.public_key()),
            &validity(),
            2,
            true,
            &[],
        )
        .unwrap();
        let leaf = Certificate::issue_general(
            &CertSigner::RsaPss(&int_key, PssHash::Sha512),
            &int_name,
            &leaf_name,
            &AnyPublicKey::Ecdsa(leaf_key.public_key()),
            &validity(),
            3,
            false,
            &["pss.example"],
        )
        .unwrap();
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let chain = alloc::vec![leaf.to_der().to_vec(), int.to_der().to_vec()];
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        let leaf_pub = verify_chain(&store, &chain, Some(&now), &policy()).unwrap();
        assert!(matches!(leaf_pub, AnyPublicKey::Ecdsa(_)));
        // Gated as `rsa-pss-pss-sha384` / `-sha512`: a policy with only the
        // SHA-256 entry refuses the chain.
        let sha256_only = SignaturePolicy::empty()
            .permit("ecdsa-with-sha256")
            .permit("rsa-pkcs1-sha256")
            .permit("rsa-pss-pss-sha256");
        assert!(matches!(
            verify_chain(&store, &chain, Some(&now), &sha256_only),
            Err(Error::BadCertificate)
        ));
        let with_both = sha256_only
            .permit("rsa-pss-pss-sha384")
            .permit("rsa-pss-pss-sha512");
        verify_chain(&store, &chain, Some(&now), &with_both).unwrap();
    }

    /// A CA whose SPKI is `id-RSASSA-PSS` (RFC 4055, SHA-256-restricted)
    /// issues an intermediate and a leaf with `id-RSASSA-PSS` signatures; the
    /// chain validates under the default `modern()` policy through the
    /// `rsa-pss-pss-sha256` entry. Under the same PSS-restricted key a
    /// PKCS#1 v1.5 signature is refused, and a leaf issued with SHA-256 PSS
    /// is refused when the CA's SPKI pins the key to SHA-384 instead.
    #[test]
    fn pss_restricted_ca_chain_validates_under_modern_policy() {
        use crate::rsa::BoxedRsaPrivateKey;
        use crate::x509::{AnyPublicKey, CertSigner, PssHash, PssRestriction};

        let ca_key = BoxedRsaPrivateKey::from_pkcs1_der(&rsa_test_key_a().to_pkcs1_der()).unwrap();
        let int_key = BoxedRsaPrivateKey::from_pkcs1_der(&rsa_test_key_b().to_pkcs1_der()).unwrap();
        let mut rng = crate::rng::HmacDrbg::<crate::hash::Sha256>::new(b"pss-ca-chain", b"n", &[]);
        let leaf_key =
            crate::ec::BoxedEcdsaPrivateKey::generate(crate::ec::CurveId::P256, &mut rng);
        let ca_signer = CertSigner::RsaPss(&ca_key, PssHash::Sha256);
        let int_signer = CertSigner::RsaPss(&int_key, PssHash::Sha256);
        let ca_name = DistinguishedName::common_name("pss-root");
        let int_name = DistinguishedName::common_name("pss-int");
        let leaf_name = DistinguishedName::common_name("pss-leaf");

        let root =
            Certificate::self_signed_general(&ca_signer, &ca_name, &validity(), 1, true, &[])
                .unwrap();
        // The CA certifies itself as a PSS-restricted key, and the
        // certificate's own signature is `id-RSASSA-PSS`.
        assert!(matches!(
            root.subject_public_key().unwrap(),
            AnyPublicKey::RsaPss(_, r) if r == PssRestriction::for_hash(PssHash::Sha256)
        ));
        assert_eq!(
            root.signature_algorithm_oid().unwrap().as_slice(),
            oid::ID_RSASSA_PSS
        );
        let int = Certificate::issue_general(
            &ca_signer,
            &ca_name,
            &int_name,
            &int_signer.public_key(),
            &validity(),
            2,
            true,
            &[],
        )
        .unwrap();
        let leaf = Certificate::issue_general(
            &int_signer,
            &int_name,
            &leaf_name,
            &AnyPublicKey::Ecdsa(leaf_key.public_key()),
            &validity(),
            3,
            false,
            &["pss.example"],
        )
        .unwrap();

        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let chain = alloc::vec![leaf.to_der().to_vec(), int.to_der().to_vec()];
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        let leaf_pub = verify_chain(&store, &chain, Some(&now), &policy()).unwrap();
        assert!(matches!(leaf_pub, AnyPublicKey::Ecdsa(_)));
        // The chain's signatures are gated as `rsa-pss-pss-sha256`, which a
        // policy without it refuses.
        let no_pss = SignaturePolicy::empty()
            .permit("ecdsa-with-sha256")
            .permit("rsa-pkcs1-sha256")
            .permit("rsa-pss-rsae-sha256");
        assert!(matches!(
            verify_chain(&store, &chain, Some(&now), &no_pss),
            Err(Error::BadCertificate)
        ));

        // PKCS#1 v1.5 under the PSS-restricted CA key: the leaf is signed
        // with `sha256WithRSAEncryption` by the same private key, and the
        // chain is refused (RFC 4055 §1.2).
        let leaf_v15 = Certificate::issue_general(
            &CertSigner::Rsa(&ca_key),
            &ca_name,
            &leaf_name,
            &AnyPublicKey::Ecdsa(leaf_key.public_key()),
            &validity(),
            4,
            false,
            &["pss.example"],
        )
        .unwrap();
        assert!(matches!(
            verify_chain(&store, &[leaf_v15.to_der().to_vec()], Some(&now), &policy()),
            Err(Error::BadCertificate)
        ));
        // ... whereas the same certificate under the CA's `rsaEncryption`
        // form would verify — the refusal is the restriction, not the math.
        leaf_v15
            .verify_signature_with(&AnyPublicKey::Rsa(ca_key.public_key()))
            .unwrap();

        // Mismatched restriction: a trust anchor certifying the same CA key
        // pinned to SHA-384 refuses the SHA-256 PSS signature on the leaf.
        let ca_sha384 = AnyPublicKey::RsaPss(
            ca_key.public_key(),
            PssRestriction::for_hash(PssHash::Sha384),
        );
        let leaf_direct = Certificate::issue_general(
            &ca_signer,
            &ca_name,
            &leaf_name,
            &AnyPublicKey::Ecdsa(leaf_key.public_key()),
            &validity(),
            5,
            false,
            &["pss.example"],
        )
        .unwrap();
        let root_sha384 = Certificate::issue_general(
            &ca_signer,
            &ca_name,
            &ca_name,
            &ca_sha384,
            &validity(),
            6,
            true,
            &[],
        )
        .unwrap();
        let mut store_384 = RootCertStore::new();
        store_384.add_der(root_sha384.to_der().to_vec()).unwrap();
        assert!(matches!(
            verify_chain(
                &store_384,
                &[leaf_direct.to_der().to_vec()],
                Some(&now),
                &policy()
            ),
            Err(Error::BadCertificate)
        ));
        assert!(leaf_direct.verify_signature_with(&ca_sha384).is_err());
        // Sanity: the correctly-restricted anchor accepts the same leaf.
        verify_chain(
            &store,
            &[leaf_direct.to_der().to_vec()],
            Some(&now),
            &policy(),
        )
        .unwrap();
    }

    // ======================================================================
    // RFC 5280 §4.2.1.10 — rfc822Name / uniformResourceIdentifier /
    // directoryName subtrees, criticality-independent enforcement, and the
    // fail-closed rule for subtree forms the crate cannot evaluate.
    // ======================================================================

    /// Builds `root → int → leaf`. `root_nc` / `int_nc` are optional
    /// `nameConstraints` extensions for the root / intermediate. The
    /// intermediate has subject `int_subject` and SAN `int_sans`, the leaf
    /// subject `leaf_subject` and SAN `leaf_sans`; an empty SAN slice means
    /// "no subjectAltName extension at all" (the CN fallback keys off
    /// extension presence). `leaf_extra` is appended to the leaf's
    /// extensions verbatim (raw SAN encodings the typed builder cannot
    /// express). Returns `(root, int, leaf)`.
    #[allow(clippy::too_many_arguments)]
    fn build_nc_chain(
        root_nc: Option<crate::x509::Extension>,
        int_nc: Option<crate::x509::Extension>,
        int_subject: &DistinguishedName,
        int_sans: &[crate::x509::GeneralName],
        leaf_subject: &DistinguishedName,
        leaf_sans: &[crate::x509::GeneralName],
        leaf_extra: &[crate::x509::Extension],
    ) -> (Certificate, Certificate, Certificate) {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;
        use crate::x509::{
            CertSigner, Extension, KeyUsageBits,
            extension::{basic_constraints, extended_key_usage, key_usage, subject_alt_name},
        };

        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"nc-forms", b"n", &[]);
        let root_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let int_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let leaf_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let root_signer = CertSigner::Ecdsa(&root_key);
        let int_signer = CertSigner::Ecdsa(&int_key);
        let root_name = DistinguishedName::common_name("nc-forms-root");

        let mut root_exts: alloc::vec::Vec<Extension> = alloc::vec![
            basic_constraints(true, None),
            key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
        ];
        root_exts.extend(root_nc);
        let root = Certificate::self_signed_with_extensions(
            &root_signer,
            &root_name,
            &validity(),
            1,
            &root_exts,
        )
        .unwrap();

        let mut int_exts: alloc::vec::Vec<Extension> = alloc::vec![
            basic_constraints(true, Some(0)),
            key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
        ];
        int_exts.extend(int_nc);
        if !int_sans.is_empty() {
            int_exts.push(subject_alt_name(int_sans));
        }
        let int_pub = crate::x509::AnyPublicKey::Ecdsa(int_key.public_key());
        let int = Certificate::issue_with_extensions(
            &root_signer,
            &root_name,
            int_subject,
            &int_pub,
            &validity(),
            2,
            &int_exts,
        )
        .unwrap();

        let mut leaf_exts = alloc::vec![
            basic_constraints(false, None),
            key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
            extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
        ];
        if !leaf_sans.is_empty() {
            leaf_exts.push(subject_alt_name(leaf_sans));
        }
        leaf_exts.extend_from_slice(leaf_extra);
        let leaf_pub = crate::x509::AnyPublicKey::Ecdsa(leaf_key.public_key());
        let leaf = Certificate::issue_with_extensions(
            &int_signer,
            int_subject,
            leaf_subject,
            &leaf_pub,
            &validity(),
            3,
            &leaf_exts,
        )
        .unwrap();
        (root, int, leaf)
    }

    /// Verifies `[leaf, int]` anchored at `root` under the modern policy.
    fn verify_nc_chain(
        root: &Certificate,
        int: &Certificate,
        leaf: &Certificate,
    ) -> Result<(), Error> {
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec())?;
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        verify_chain(
            &store,
            &[leaf.to_der().to_vec(), int.to_der().to_vec()],
            Some(&now),
            &policy(),
        )
        .map(|_| ())
    }

    /// `name_constraints(permitted, excluded)` with the criticality flag set
    /// to `critical` (the builder always emits it critical).
    fn nc_ext(
        permitted: &[crate::x509::GeneralName],
        excluded: &[crate::x509::GeneralName],
        critical: bool,
    ) -> crate::x509::Extension {
        let mut ext = crate::x509::extension::name_constraints(permitted, excluded);
        ext.critical = critical;
        ext
    }

    /// A `nameConstraints` extension whose subtree bases are supplied as raw
    /// `GeneralName` TLVs — for shapes the typed builder cannot express (IP
    /// address + mask, otherName, a Name in a non-conventional RDN order).
    fn nc_ext_raw(
        permitted: &[Vec<u8>],
        excluded: &[Vec<u8>],
        critical: bool,
    ) -> crate::x509::Extension {
        use crate::der::{encode_context, encode_sequence};
        let subtrees = |bases: &[Vec<u8>]| -> Vec<u8> {
            bases.iter().flat_map(|b| encode_sequence(b)).collect()
        };
        let mut body = Vec::new();
        if !permitted.is_empty() {
            body.extend_from_slice(&encode_context(0, &subtrees(permitted)));
        }
        if !excluded.is_empty() {
            body.extend_from_slice(&encode_context(1, &subtrees(excluded)));
        }
        crate::x509::Extension {
            oid: oid::NAME_CONSTRAINTS.to_vec(),
            critical,
            value: encode_sequence(&body),
        }
    }

    /// A raw DER `Name` from `(attribute OID, string tag, value)` RDNs, in
    /// the order given.
    fn raw_name(rdns: &[(&[u64], u8, &str)]) -> Vec<u8> {
        use crate::der::{encode_sequence, encode_string, encode_tlv, oid_tlv, tag};
        let body: Vec<u8> = rdns
            .iter()
            .flat_map(|(o, t, v)| {
                let atv = encode_sequence(&[oid_tlv(o), encode_string(*t, v)].concat());
                encode_tlv(tag::SET, &atv)
            })
            .collect();
        encode_sequence(&body)
    }

    /// Verifies a leaf with subject `leaf_subject` and SAN `leaf_sans` under
    /// an intermediate carrying `nc`.
    fn leaf_under(
        nc: crate::x509::Extension,
        leaf_subject: &DistinguishedName,
        leaf_sans: &[crate::x509::GeneralName],
    ) -> Result<(), Error> {
        let (root, int, leaf) = build_nc_chain(
            None,
            Some(nc),
            &DistinguishedName::common_name("nc-forms-int"),
            &[],
            leaf_subject,
            leaf_sans,
            &[],
        );
        verify_nc_chain(&root, &int, &leaf)
    }

    fn corp_dn(cn: &str) -> DistinguishedName {
        DistinguishedName::common_name(cn)
            .with_country("US")
            .with_organization("Corp")
    }

    fn corp_base() -> crate::x509::GeneralName {
        crate::x509::GeneralName::DirectoryName(
            DistinguishedName::new()
                .with_country("US")
                .with_organization("Corp"),
        )
    }

    // ---- rfc822Name ------------------------------------------------------

    #[test]
    fn nc_rfc822_host_form_matches_exact_host_only() {
        use crate::x509::GeneralName::{Dns, Email};
        let nc = || nc_ext(&[Email("example.com".into())], &[], true);
        let cn = DistinguishedName::common_name("mail");
        leaf_under(nc(), &cn, &[Email("alice@example.com".into())]).unwrap();
        // Domain part is case-insensitive.
        leaf_under(nc(), &cn, &[Email("alice@EXAMPLE.COM".into())]).unwrap();
        // A host-form constraint names one host: no subdomains.
        assert!(matches!(
            leaf_under(nc(), &cn, &[Email("alice@sub.example.com".into())]),
            Err(Error::BadCertificate)
        ));
        assert!(matches!(
            leaf_under(nc(), &cn, &[Email("alice@example.org".into())]),
            Err(Error::BadCertificate)
        ));
        // One mailbox out of range poisons the certificate.
        assert!(matches!(
            leaf_under(
                nc(),
                &cn,
                &[
                    Email("alice@example.com".into()),
                    Email("alice@example.org".into())
                ]
            ),
            Err(Error::BadCertificate)
        ));
        // A name without a domain part matches no subtree.
        assert!(matches!(
            leaf_under(nc(), &cn, &[Email("alice".into())]),
            Err(Error::BadCertificate)
        ));
        // Other name forms in the same SAN are unaffected by an rfc822Name
        // permitted subtree.
        leaf_under(
            nc(),
            &cn,
            &[
                Email("alice@example.com".into()),
                Dns("anything.example.org".into()),
            ],
        )
        .unwrap();
    }

    #[test]
    fn nc_rfc822_leading_dot_form_matches_subdomains_not_apex() {
        use crate::x509::GeneralName::Email;
        let nc = || nc_ext(&[Email(".example.com".into())], &[], true);
        let cn = DistinguishedName::common_name("mail");
        leaf_under(nc(), &cn, &[Email("alice@sub.example.com".into())]).unwrap();
        leaf_under(nc(), &cn, &[Email("alice@a.b.example.com".into())]).unwrap();
        assert!(matches!(
            leaf_under(nc(), &cn, &[Email("alice@example.com".into())]),
            Err(Error::BadCertificate)
        ));
        // Label boundary: "notexample.com" is not in ".example.com".
        assert!(matches!(
            leaf_under(nc(), &cn, &[Email("alice@notexample.com".into())]),
            Err(Error::BadCertificate)
        ));
    }

    #[test]
    fn nc_rfc822_mailbox_form_is_exact() {
        use crate::x509::GeneralName::Email;
        let nc = || nc_ext(&[Email("alice@example.com".into())], &[], true);
        let cn = DistinguishedName::common_name("mail");
        leaf_under(nc(), &cn, &[Email("alice@example.com".into())]).unwrap();
        leaf_under(nc(), &cn, &[Email("alice@Example.COM".into())]).unwrap();
        assert!(matches!(
            leaf_under(nc(), &cn, &[Email("bob@example.com".into())]),
            Err(Error::BadCertificate)
        ));
        // The local part is compared verbatim (RFC 5321 §2.4).
        assert!(matches!(
            leaf_under(nc(), &cn, &[Email("Alice@example.com".into())]),
            Err(Error::BadCertificate)
        ));
    }

    #[test]
    fn nc_rfc822_excluded_subtree() {
        use crate::x509::GeneralName::Email;
        let nc = || nc_ext(&[], &[Email(".blocked.example".into())], true);
        let cn = DistinguishedName::common_name("mail");
        assert!(matches!(
            leaf_under(nc(), &cn, &[Email("x@mail.blocked.example".into())]),
            Err(Error::BadCertificate)
        ));
        // The apex is outside a leading-dot exclusion...
        leaf_under(nc(), &cn, &[Email("x@blocked.example".into())]).unwrap();
        // ...and so is any other domain.
        leaf_under(nc(), &cn, &[Email("x@ok.example".into())]).unwrap();
        // Excluded wins over permitted.
        let both = nc_ext(
            &[Email(".example".into())],
            &[Email(".blocked.example".into())],
            true,
        );
        assert!(matches!(
            leaf_under(both, &cn, &[Email("x@mail.blocked.example".into())]),
            Err(Error::BadCertificate)
        ));
    }

    /// RFC 5280 §4.2.1.10: with no rfc822Name SAN, the constraint applies to
    /// the subject's `emailAddress` attribute(s); with one, the subject
    /// attribute is not consulted.
    #[test]
    fn nc_rfc822_falls_back_to_subject_email_address() {
        use crate::x509::GeneralName::{Dns, Email};
        let nc = || nc_ext(&[Email("example.com".into())], &[], true);
        let mut inside = DistinguishedName::common_name("host.example.org");
        inside.email_address = Some("alice@example.com".into());
        let mut outside = DistinguishedName::common_name("host.example.org");
        outside.email_address = Some("alice@example.org".into());
        let dns_only = [Dns("host.example.org".into())];
        leaf_under(nc(), &inside, &dns_only).unwrap();
        assert!(matches!(
            leaf_under(nc(), &outside, &dns_only),
            Err(Error::BadCertificate)
        ));
        // An rfc822Name SAN takes over: the out-of-range subject attribute
        // is then ignored...
        leaf_under(nc(), &outside, &[Email("bob@example.com".into())]).unwrap();
        // ...and an in-range subject attribute does not rescue an
        // out-of-range SAN.
        assert!(matches!(
            leaf_under(nc(), &inside, &[Email("bob@example.org".into())]),
            Err(Error::BadCertificate)
        ));
        // A subject without emailAddress presents no rfc822Name-form name:
        // unconstrained.
        leaf_under(
            nc(),
            &DistinguishedName::common_name("host.example.org"),
            &dns_only,
        )
        .unwrap();
        // Excluded direction, via the subject attribute.
        let ex = nc_ext(&[], &[Email("example.org".into())], true);
        assert!(matches!(
            leaf_under(ex, &outside, &dns_only),
            Err(Error::BadCertificate)
        ));
    }

    // ---- uniformResourceIdentifier ----------------------------------------

    #[test]
    fn nc_uri_host_form_matches_host_component() {
        use crate::x509::GeneralName::Uri;
        let nc = || nc_ext(&[Uri("example.com".into())], &[], true);
        let cn = DistinguishedName::common_name("svc");
        leaf_under(nc(), &cn, &[Uri("https://example.com/path?q=1#f".into())]).unwrap();
        leaf_under(
            nc(),
            &cn,
            &[Uri("https://user:pw@example.com:8443/x".into())],
        )
        .unwrap();
        leaf_under(nc(), &cn, &[Uri("HTTPS://EXAMPLE.COM".into())]).unwrap();
        leaf_under(nc(), &cn, &[Uri("ldap://example.com".into())]).unwrap();
        assert!(matches!(
            leaf_under(nc(), &cn, &[Uri("https://sub.example.com/".into())]),
            Err(Error::BadCertificate)
        ));
        assert!(matches!(
            leaf_under(nc(), &cn, &[Uri("https://example.org/".into())]),
            Err(Error::BadCertificate)
        ));
        // Userinfo cannot smuggle the host: the host here is example.org.
        assert!(matches!(
            leaf_under(nc(), &cn, &[Uri("https://example.com@example.org/".into())]),
            Err(Error::BadCertificate)
        ));
    }

    #[test]
    fn nc_uri_leading_dot_form_matches_subdomains_not_apex() {
        use crate::x509::GeneralName::Uri;
        let nc = || nc_ext(&[Uri(".example.com".into())], &[], true);
        let cn = DistinguishedName::common_name("svc");
        leaf_under(nc(), &cn, &[Uri("https://a.example.com/".into())]).unwrap();
        leaf_under(nc(), &cn, &[Uri("https://a.b.example.com/".into())]).unwrap();
        assert!(matches!(
            leaf_under(nc(), &cn, &[Uri("https://example.com/".into())]),
            Err(Error::BadCertificate)
        ));
        assert!(matches!(
            leaf_under(nc(), &cn, &[Uri("https://notexample.com/".into())]),
            Err(Error::BadCertificate)
        ));
    }

    /// A URI whose host is an IP address, or which has no host at all,
    /// falls within no host-name subtree: refused under a permitted list,
    /// untouched by an excluded one.
    #[test]
    fn nc_uri_without_host_name_matches_no_subtree() {
        use crate::x509::GeneralName::Uri;
        let cn = DistinguishedName::common_name("svc");
        for uri in [
            "https://10.0.0.1/",
            "https://[2001:db8::1]:443/",
            "mailto:alice@example.com",
            "urn:example:foo",
            "https:///nohost",
            "//example.com/no-scheme",
        ] {
            let pm = nc_ext(&[Uri("example.com".into())], &[], true);
            assert!(
                matches!(
                    leaf_under(pm, &cn, &[Uri(uri.into())]),
                    Err(Error::BadCertificate)
                ),
                "permitted: {uri}"
            );
            let ex = nc_ext(&[], &[Uri("example.com".into())], true);
            leaf_under(ex, &cn, &[Uri(uri.into())])
                .unwrap_or_else(|e| panic!("excluded: {uri}: {e:?}"));
        }
    }

    #[test]
    fn nc_uri_excluded_subtree() {
        use crate::x509::GeneralName::Uri;
        let nc = || nc_ext(&[], &[Uri(".blocked.example".into())], true);
        let cn = DistinguishedName::common_name("svc");
        assert!(matches!(
            leaf_under(nc(), &cn, &[Uri("https://x.blocked.example/".into())]),
            Err(Error::BadCertificate)
        ));
        leaf_under(nc(), &cn, &[Uri("https://blocked.example/".into())]).unwrap();
        leaf_under(nc(), &cn, &[Uri("https://ok.example/".into())]).unwrap();
    }

    // ---- directoryName ----------------------------------------------------

    #[test]
    fn nc_directory_name_permitted_prefix_match() {
        use crate::x509::GeneralName::Dns;
        let nc = || nc_ext(&[corp_base()], &[], true);
        let san = [Dns("host.example".into())];
        // Longer subject with the constraint as RDN prefix: inside.
        let mut deep = corp_dn("host.example");
        deep.organizational_unit = Some("Eng".into());
        leaf_under(nc(), &deep, &san).unwrap();
        leaf_under(nc(), &corp_dn("host.example"), &san).unwrap();
        // The bare prefix itself is inside too.
        leaf_under(
            nc(),
            &DistinguishedName::new()
                .with_country("US")
                .with_organization("Corp"),
            &san,
        )
        .unwrap();
        // A differing RDN: outside.
        assert!(matches!(
            leaf_under(
                nc(),
                &DistinguishedName::common_name("host.example")
                    .with_country("US")
                    .with_organization("Other"),
                &san
            ),
            Err(Error::BadCertificate)
        ));
        // A subject shorter than the constraint cannot have it as prefix.
        assert!(matches!(
            leaf_under(nc(), &DistinguishedName::new().with_country("US"), &san),
            Err(Error::BadCertificate)
        ));
        // A subject with only a CN — the shape every other test uses —
        // is outside as well.
        assert!(matches!(
            leaf_under(nc(), &DistinguishedName::common_name("host.example"), &san),
            Err(Error::BadCertificate)
        ));
    }

    /// The RDN sequence is ordered: `O=Corp, C=US` is not a prefix of
    /// `C=US, O=Corp, CN=…`.
    #[test]
    fn nc_directory_name_rdn_order_matters() {
        use crate::der::{encode_tlv, tag};
        use crate::x509::GeneralName::Dns;
        let swapped = raw_name(&[
            (oid::ORGANIZATION, tag::UTF8_STRING, "Corp"),
            (oid::COUNTRY, tag::PRINTABLE_STRING, "US"),
        ]);
        let nc = nc_ext_raw(&[encode_tlv(0xA4, &swapped)], &[], true);
        assert!(matches!(
            leaf_under(nc, &corp_dn("host.example"), &[Dns("host.example".into())]),
            Err(Error::BadCertificate)
        ));
        // Sanity: the same RDNs in the subject's order do match.
        let ordered = raw_name(&[
            (oid::COUNTRY, tag::PRINTABLE_STRING, "US"),
            (oid::ORGANIZATION, tag::UTF8_STRING, "Corp"),
        ]);
        let nc = nc_ext_raw(&[encode_tlv(0xA4, &ordered)], &[], true);
        leaf_under(nc, &corp_dn("host.example"), &[Dns("host.example".into())]).unwrap();
    }

    /// RDNs are compared byte-for-byte, like issuer/subject chaining: a
    /// PrintableString `O=Corp` in the constraint does not match the
    /// UTF8String `O=Corp` the crate's builder emits.
    #[test]
    fn nc_directory_name_rdn_comparison_is_byte_exact() {
        use crate::der::{encode_tlv, tag};
        use crate::x509::GeneralName::Dns;
        let printable = raw_name(&[
            (oid::COUNTRY, tag::PRINTABLE_STRING, "US"),
            (oid::ORGANIZATION, tag::PRINTABLE_STRING, "Corp"),
        ]);
        let nc = nc_ext_raw(&[encode_tlv(0xA4, &printable)], &[], true);
        assert!(matches!(
            leaf_under(nc, &corp_dn("host.example"), &[Dns("host.example".into())]),
            Err(Error::BadCertificate)
        ));
    }

    #[test]
    fn nc_directory_name_excluded_subtree() {
        use crate::x509::GeneralName::{DirectoryName, Dns};
        let blocked = DirectoryName(
            DistinguishedName::new()
                .with_country("US")
                .with_organization("Corp")
                .with_organizational_unit("Blocked"),
        );
        let nc = || nc_ext(&[], core::slice::from_ref(&blocked), true);
        let san = [Dns("host.example".into())];
        let mut in_blocked = corp_dn("host.example");
        in_blocked.organizational_unit = Some("Blocked".into());
        assert!(matches!(
            leaf_under(nc(), &in_blocked, &san),
            Err(Error::BadCertificate)
        ));
        let mut in_eng = corp_dn("host.example");
        in_eng.organizational_unit = Some("Eng".into());
        leaf_under(nc(), &in_eng, &san).unwrap();
        leaf_under(nc(), &corp_dn("host.example"), &san).unwrap();
        // Excluded wins over permitted.
        let both = nc_ext(&[corp_base()], core::slice::from_ref(&blocked), true);
        assert!(matches!(
            leaf_under(both, &in_blocked, &san),
            Err(Error::BadCertificate)
        ));
    }

    /// directoryName SAN entries are names of the directoryName form too.
    #[test]
    fn nc_directory_name_applies_to_san_directory_names() {
        use crate::x509::GeneralName::{DirectoryName, Dns};
        let nc = || nc_ext(&[corp_base()], &[], true);
        let other = DirectoryName(
            DistinguishedName::common_name("alias")
                .with_country("US")
                .with_organization("Other"),
        );
        let alias = DirectoryName(corp_dn("alias"));
        leaf_under(
            nc(),
            &corp_dn("host.example"),
            &[Dns("host.example".into()), alias],
        )
        .unwrap();
        assert!(matches!(
            leaf_under(
                nc(),
                &corp_dn("host.example"),
                &[Dns("host.example".into()), other.clone()]
            ),
            Err(Error::BadCertificate)
        ));
        let ex = nc_ext(&[], &[corp_base()], true);
        assert!(matches!(
            leaf_under(
                ex,
                &DistinguishedName::common_name("host.example"),
                &[Dns("host.example".into()), DirectoryName(corp_dn("alias"))]
            ),
            Err(Error::BadCertificate)
        ));
    }

    /// An empty `Name` is an RDN-prefix of every name: permitted ⇒ every
    /// DN is inside, excluded ⇒ every non-empty subject is refused. An
    /// empty subject presents no directoryName-form name.
    #[test]
    fn nc_directory_name_empty_subtree_and_empty_subject() {
        use crate::x509::GeneralName::{DirectoryName, Dns};
        let san = [Dns("host.example".into())];
        let empty = || DirectoryName(DistinguishedName::new());
        leaf_under(
            nc_ext(&[empty()], &[], true),
            &corp_dn("host.example"),
            &san,
        )
        .unwrap();
        assert!(matches!(
            leaf_under(
                nc_ext(&[], &[empty()], true),
                &corp_dn("host.example"),
                &san
            ),
            Err(Error::BadCertificate)
        ));
        // Empty subject under a permitted directoryName subtree: nothing to
        // constrain (the leaf still carries a dNSName, so the nameless-leaf
        // rule is not what decides here).
        leaf_under(
            nc_ext(&[corp_base()], &[], true),
            &DistinguishedName::new(),
            &san,
        )
        .unwrap();
        leaf_under(
            nc_ext(&[], &[empty()], true),
            &DistinguishedName::new(),
            &san,
        )
        .unwrap();
    }

    // ---- criticality --------------------------------------------------------

    /// RFC 5280 §6.1.4 processes nameConstraints regardless of criticality
    /// — the non-critical form CA/Browser Forum TCSCs commonly use must be
    /// enforced, for every subtree form.
    #[test]
    fn nc_non_critical_constraints_are_enforced() {
        use crate::x509::GeneralName::{Dns, Email, Uri};
        let cn = DistinguishedName::common_name("leaf");
        assert!(matches!(
            leaf_under(
                nc_ext(&[Dns(".good.example".into())], &[], false),
                &cn,
                &[Dns("host.evil.example".into())]
            ),
            Err(Error::BadCertificate)
        ));
        assert!(matches!(
            leaf_under(
                nc_ext(&[Email("example.com".into())], &[], false),
                &cn,
                &[Email("x@example.org".into())]
            ),
            Err(Error::BadCertificate)
        ));
        assert!(matches!(
            leaf_under(
                nc_ext(&[], &[Uri(".blocked.example".into())], false),
                &cn,
                &[Uri("https://x.blocked.example/".into())]
            ),
            Err(Error::BadCertificate)
        ));
        assert!(matches!(
            leaf_under(
                nc_ext(&[corp_base()], &[], false),
                &cn,
                &[Dns("host.example".into())]
            ),
            Err(Error::BadCertificate)
        ));
        // And in-range names still pass a non-critical constraint.
        leaf_under(
            nc_ext(&[corp_base(), Dns(".good.example".into())], &[], false),
            &corp_dn("host.good.example"),
            &[Dns("host.good.example".into())],
        )
        .unwrap();
    }

    /// A CA/Browser Forum technically-constrained sub-CA: non-critical
    /// nameConstraints with a dNSName + directoryName permitted subtree and
    /// iPAddress `0.0.0.0/0` + `::/0` excluded.
    #[test]
    fn nc_cab_forum_technically_constrained_sub_ca() {
        use crate::der::encode_tlv;
        use crate::x509::GeneralName::{Dns, IpV4};
        let tcsc = || {
            let corp = DistinguishedName::new()
                .with_country("US")
                .with_organization("Corp");
            nc_ext_raw(
                &[
                    Dns("corp.example".into()).to_der(),
                    encode_tlv(0xA4, &corp.to_der()),
                ],
                &[encode_tlv(0x87, &[0u8; 8]), encode_tlv(0x87, &[0u8; 32])],
                false,
            )
        };
        leaf_under(
            tcsc(),
            &corp_dn("www.corp.example"),
            &[Dns("www.corp.example".into()), Dns("corp.example".into())],
        )
        .unwrap();
        // DNS name outside the permitted subtree.
        assert!(matches!(
            leaf_under(
                tcsc(),
                &corp_dn("www.other.example"),
                &[Dns("www.other.example".into())]
            ),
            Err(Error::BadCertificate)
        ));
        // Subject outside the permitted directoryName subtree.
        assert!(matches!(
            leaf_under(
                tcsc(),
                &DistinguishedName::common_name("www.corp.example")
                    .with_country("US")
                    .with_organization("Other"),
                &[Dns("www.corp.example".into())]
            ),
            Err(Error::BadCertificate)
        ));
        // Any IP address is excluded.
        assert!(matches!(
            leaf_under(
                tcsc(),
                &corp_dn("www.corp.example"),
                &[Dns("www.corp.example".into()), IpV4([10, 1, 2, 3])]
            ),
            Err(Error::BadCertificate)
        ));
    }

    // ---- per-form independence ----------------------------------------------

    /// A leaf whose SAN holds only rfc822Name / URI entries is not
    /// restricted by a CA that permits only dNSName subtrees: a name form
    /// with no constraint is unrestricted (RFC 5280 §4.2.1.10). The SAN
    /// extension is present, so the CN is not a dNSName fallback either.
    #[test]
    fn nc_leaf_with_only_email_or_uri_sans_passes_dns_only_permitted() {
        use crate::x509::GeneralName::{Dns, Email, Uri};
        let nc = || nc_ext(&[Dns(".good.example".into())], &[], true);
        let cn = DistinguishedName::common_name("nc-leaf");
        leaf_under(nc(), &cn, &[Email("alice@anywhere.example".into())]).unwrap();
        leaf_under(nc(), &cn, &[Uri("https://anywhere.example/".into())]).unwrap();
        // With a dNSName alongside, that dNSName is still held to the
        // subtree.
        assert!(matches!(
            leaf_under(
                nc(),
                &cn,
                &[
                    Email("alice@anywhere.example".into()),
                    Dns("host.evil.example".into())
                ]
            ),
            Err(Error::BadCertificate)
        ));
        // Without any SAN, the CN fallback still applies — "nc-leaf" is
        // outside `.good.example`.
        assert!(matches!(
            leaf_under(nc(), &cn, &[]),
            Err(Error::BadCertificate)
        ));
    }

    // ---- unsupported subtree forms -----------------------------------------

    /// A raw `otherName` GeneralName (`[0]`, constructed): a UPN-style
    /// `SEQUENCE { type-id OID, value [0] EXPLICIT UTF8String }`.
    fn other_name_tlv(value: &str) -> Vec<u8> {
        use crate::der::{encode_context, encode_sequence, encode_string, oid_tlv, tag};
        // Microsoft UPN 1.3.6.1.4.1.311.20.2.3.
        let body = [
            oid_tlv(&[1, 3, 6, 1, 4, 1, 311, 20, 2, 3]),
            encode_context(0, &encode_string(tag::UTF8_STRING, value)),
        ]
        .concat();
        encode_context(0, &encode_sequence(&body))
    }

    /// A raw `subjectAltName` extension from pre-encoded GeneralName TLVs.
    fn raw_san(entries: &[Vec<u8>]) -> crate::x509::Extension {
        crate::x509::Extension {
            oid: oid::SUBJECT_ALT_NAME.to_vec(),
            critical: false,
            value: crate::der::encode_sequence(&entries.concat()),
        }
    }

    /// An otherName subtree (a form the crate cannot match) is inert for a
    /// certificate that presents no otherName — whether the extension is
    /// critical or not — and fatal for one that does, in either direction.
    #[test]
    fn nc_unsupported_subtree_form_fails_closed_only_when_presented() {
        use crate::x509::GeneralName::Dns;
        let dns_tlv = Dns("host.example".into()).to_der();
        let cn = DistinguishedName::common_name("host.example");
        for critical in [true, false] {
            // Permitted otherName, no otherName in the SAN: ignored.
            let nc = nc_ext_raw(&[other_name_tlv("ca@corp")], &[], critical);
            leaf_under(nc, &cn, &[Dns("host.example".into())]).unwrap();
            // Excluded otherName, no otherName in the SAN: ignored.
            let nc = nc_ext_raw(&[], &[other_name_tlv("ca@corp")], critical);
            leaf_under(nc, &cn, &[Dns("host.example".into())]).unwrap();
            // Either direction with an otherName in the SAN: refused.
            for (pm, ex) in [
                (alloc::vec![other_name_tlv("ca@corp")], alloc::vec![]),
                (alloc::vec![], alloc::vec![other_name_tlv("ca@corp")]),
            ] {
                let (root, int, leaf) = build_nc_chain(
                    None,
                    Some(nc_ext_raw(&pm, &ex, critical)),
                    &DistinguishedName::common_name("nc-forms-int"),
                    &[],
                    &cn,
                    &[],
                    &[raw_san(&[dns_tlv.clone(), other_name_tlv("user@corp")])],
                );
                assert!(matches!(
                    verify_nc_chain(&root, &int, &leaf),
                    Err(Error::BadCertificate)
                ));
            }
        }
        // A different unsupported form in the SAN (registeredID) is not
        // what an otherName subtree constrains.
        let registered_id = crate::der::encode_tlv(0x88, &[0x2b, 0x06, 0x01]);
        let (root, int, leaf) = build_nc_chain(
            None,
            Some(nc_ext_raw(&[other_name_tlv("ca@corp")], &[], true)),
            &DistinguishedName::common_name("nc-forms-int"),
            &[],
            &cn,
            &[],
            &[raw_san(&[dns_tlv.clone(), registered_id])],
        );
        verify_nc_chain(&root, &int, &leaf).unwrap();
    }

    // ---- trust-anchor constraints ---------------------------------------------

    /// A root whose nameConstraints use the rfc822Name / directoryName /
    /// otherName forms is accepted by `add_der` and enforced like an
    /// in-chain CA's (including the fail-closed rule for otherName).
    #[test]
    fn anchor_name_constraints_cover_every_form() {
        use crate::x509::GeneralName::{Dns, Email};
        let int_dn = corp_dn("Corp Issuing CA");
        let leaf_ok = corp_dn("host.corp.example");
        let build = |root_nc, leaf_dn: &DistinguishedName, sans: &[crate::x509::GeneralName]| {
            build_nc_chain(Some(root_nc), None, &int_dn, &[], leaf_dn, sans, &[])
        };
        // rfc822Name on the anchor.
        let nc = nc_ext(&[Email("corp.example".into())], &[], true);
        let (root, int, leaf) = build(nc.clone(), &leaf_ok, &[Email("a@corp.example".into())]);
        verify_nc_chain(&root, &int, &leaf).unwrap();
        let (root, int, leaf) = build(nc, &leaf_ok, &[Email("a@other.example".into())]);
        assert!(matches!(
            verify_nc_chain(&root, &int, &leaf),
            Err(Error::BadCertificate)
        ));
        // directoryName on the anchor governs the intermediate as well.
        let nc = nc_ext(&[corp_base()], &[], false);
        let (root, int, leaf) = build(nc.clone(), &leaf_ok, &[Dns("host.corp.example".into())]);
        verify_nc_chain(&root, &int, &leaf).unwrap();
        let (root, int, leaf) = build_nc_chain(
            Some(nc),
            None,
            &DistinguishedName::common_name("Rogue CA"),
            &[],
            &leaf_ok,
            &[Dns("host.corp.example".into())],
            &[],
        );
        assert!(matches!(
            verify_nc_chain(&root, &int, &leaf),
            Err(Error::BadCertificate)
        ));
        // otherName on the anchor: installed, inert without an otherName
        // SAN, fatal with one.
        let nc = nc_ext_raw(&[other_name_tlv("ca@corp")], &[], true);
        let (root, int, leaf) = build(nc.clone(), &leaf_ok, &[Dns("host.corp.example".into())]);
        verify_nc_chain(&root, &int, &leaf).unwrap();
        let (root, int, leaf) = build_nc_chain(
            Some(nc),
            None,
            &int_dn,
            &[],
            &leaf_ok,
            &[],
            &[raw_san(&[other_name_tlv("user@corp")])],
        );
        assert!(matches!(
            verify_nc_chain(&root, &int, &leaf),
            Err(Error::BadCertificate)
        ));
    }

    // ---- RFC 5280 §6.1.3 per-certificate rules ----------------------------------

    /// Only the leaf's commonName is ever used as a hostname, so only the
    /// leaf's CN is held to dNSName subtrees: a SAN-less intermediate with
    /// a display-name CN under a dNSName-constrained root validates.
    #[test]
    fn nc_intermediate_cn_is_not_a_dns_name() {
        use crate::x509::GeneralName::Dns;
        let nc = nc_ext(&[Dns(".corp.example".into())], &[], true);
        let (root, int, leaf) = build_nc_chain(
            Some(nc),
            None,
            &corp_dn("Corp Issuing CA 1"),
            &[],
            &corp_dn("host.corp.example"),
            &[Dns("host.corp.example".into())],
            &[],
        );
        verify_nc_chain(&root, &int, &leaf).unwrap();
        // An intermediate's actual dNSName SAN is still held to the subtree.
        let nc = nc_ext(&[Dns(".corp.example".into())], &[], true);
        let (root, int, leaf) = build_nc_chain(
            Some(nc),
            None,
            &corp_dn("Corp Issuing CA 1"),
            &[Dns("ca.other.example".into())],
            &corp_dn("host.corp.example"),
            &[Dns("host.corp.example".into())],
            &[],
        );
        assert!(matches!(
            verify_nc_chain(&root, &int, &leaf),
            Err(Error::BadCertificate)
        ));
    }

    /// RFC 5280 §6.1.3(b): a self-issued certificate that is not the leaf is
    /// not checked against the name constraints. `root(NC) → int → int'
    /// (subject = issuer = int's name, new key, out-of-range SAN) → leaf`.
    #[test]
    fn nc_self_issued_intermediate_is_skipped() {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;
        use crate::x509::GeneralName::Dns;
        use crate::x509::{
            CertSigner, KeyUsageBits,
            extension::{
                basic_constraints, extended_key_usage, key_usage, name_constraints,
                subject_alt_name,
            },
        };
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"nc-self-issued", b"n", &[]);
        let root_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let int_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let int2_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let leaf_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let root_signer = CertSigner::Ecdsa(&root_key);
        let int_signer = CertSigner::Ecdsa(&int_key);
        let int2_signer = CertSigner::Ecdsa(&int2_key);
        let root_name = DistinguishedName::common_name("si-root");
        let int_name = DistinguishedName::common_name("si-int");
        let ca_exts = |extra: &[crate::x509::Extension]| {
            let mut v = alloc::vec![
                basic_constraints(true, None),
                key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
            ];
            v.extend_from_slice(extra);
            v
        };
        let root = Certificate::self_signed_with_extensions(
            &root_signer,
            &root_name,
            &validity(),
            1,
            &ca_exts(&[name_constraints(&[Dns(".corp.example".into())], &[])]),
        )
        .unwrap();
        let int = Certificate::issue_with_extensions(
            &root_signer,
            &root_name,
            &int_name,
            &crate::x509::AnyPublicKey::Ecdsa(int_key.public_key()),
            &validity(),
            2,
            &ca_exts(&[]),
        )
        .unwrap();
        // Self-issued re-key of `int`, carrying a dNSName outside the
        // root's subtree.
        let int2 = Certificate::issue_with_extensions(
            &int_signer,
            &int_name,
            &int_name,
            &crate::x509::AnyPublicKey::Ecdsa(int2_key.public_key()),
            &validity(),
            3,
            &ca_exts(&[subject_alt_name(&[Dns("rekey.other.example".into())])]),
        )
        .unwrap();
        let leaf = Certificate::issue_with_extensions(
            &int2_signer,
            &int_name,
            &DistinguishedName::common_name("host.corp.example"),
            &crate::x509::AnyPublicKey::Ecdsa(leaf_key.public_key()),
            &validity(),
            4,
            &[
                basic_constraints(false, None),
                key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
                extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
                subject_alt_name(&[Dns("host.corp.example".into())]),
            ],
        )
        .unwrap();
        let mut store = RootCertStore::new();
        store.add_der(root.to_der().to_vec()).unwrap();
        let now = Time::utc(2026, 1, 1, 0, 0, 0);
        let chain = alloc::vec![
            leaf.to_der().to_vec(),
            int2.to_der().to_vec(),
            int.to_der().to_vec(),
        ];
        verify_chain(&store, &chain, Some(&now), &policy()).unwrap();
        // The leaf below it is still governed by the root's constraint.
        let bad_leaf = Certificate::issue_with_extensions(
            &int2_signer,
            &int_name,
            &DistinguishedName::common_name("host.other.example"),
            &crate::x509::AnyPublicKey::Ecdsa(leaf_key.public_key()),
            &validity(),
            5,
            &[
                basic_constraints(false, None),
                key_usage(KeyUsageBits::DIGITAL_SIGNATURE),
                extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
                subject_alt_name(&[Dns("host.other.example".into())]),
            ],
        )
        .unwrap();
        let chain = alloc::vec![
            bad_leaf.to_der().to_vec(),
            int2.to_der().to_vec(),
            int.to_der().to_vec(),
        ];
        assert!(matches!(
            verify_chain(&store, &chain, Some(&now), &policy()),
            Err(Error::BadCertificate)
        ));
    }

    // ---- matcher unit tests ---------------------------------------------------------

    #[test]
    fn host_in_subtree_semantics() {
        assert!(super::host_in_subtree("example.com", "example.com"));
        assert!(super::host_in_subtree("EXAMPLE.com", "example.COM"));
        assert!(!super::host_in_subtree("a.example.com", "example.com"));
        assert!(!super::host_in_subtree("example.com", ".example.com"));
        assert!(super::host_in_subtree("a.example.com", ".example.com"));
        assert!(super::host_in_subtree("a.b.example.com", ".example.com"));
        assert!(!super::host_in_subtree("notexample.com", ".example.com"));
        assert!(!super::host_in_subtree("", ".example.com"));
        assert!(!super::host_in_subtree("example.com", ""));
    }

    #[test]
    fn email_in_subtree_semantics() {
        assert!(super::email_in_subtree("a@example.com", "example.com"));
        assert!(super::email_in_subtree("a@x.example.com", ".example.com"));
        assert!(super::email_in_subtree("a@example.com", "a@EXAMPLE.com"));
        assert!(!super::email_in_subtree("A@example.com", "a@example.com"));
        assert!(!super::email_in_subtree("b@example.com", "a@example.com"));
        assert!(!super::email_in_subtree("a", "example.com"));
        assert!(!super::email_in_subtree("a", "a@example.com"));
        // The domain part is what follows the LAST '@'.
        assert!(super::email_in_subtree(
            "\"a@b\"@example.com",
            "example.com"
        ));
        assert!(!super::email_in_subtree("a@b@evil.example", "b"));
    }

    #[test]
    fn uri_host_extraction() {
        assert_eq!(
            super::uri_host("https://example.com/p"),
            Some("example.com")
        );
        assert_eq!(super::uri_host("https://example.com"), Some("example.com"));
        assert_eq!(
            super::uri_host("https://example.com?x"),
            Some("example.com")
        );
        assert_eq!(
            super::uri_host("https://example.com#x"),
            Some("example.com")
        );
        assert_eq!(
            super::uri_host("https://u:p@example.com:8443/"),
            Some("example.com")
        );
        assert_eq!(
            super::uri_host("ldap://Example.COM:389/dc=x"),
            Some("Example.COM")
        );
        assert_eq!(super::uri_host("https://10.0.0.1/"), None);
        assert_eq!(super::uri_host("https://[::1]/"), None);
        assert_eq!(super::uri_host("https://[::1]:8443/"), None);
        assert_eq!(super::uri_host("mailto:a@example.com"), None);
        assert_eq!(super::uri_host("urn:isbn:123"), None);
        assert_eq!(super::uri_host("https:///path"), None);
        assert_eq!(super::uri_host("//example.com/"), None);
        assert_eq!(super::uri_host("example.com"), None);
        assert_eq!(super::uri_host("1http://example.com/"), None);
        assert_eq!(
            super::uri_host("https://example.com@evil.example/"),
            Some("evil.example")
        );
    }

    #[test]
    fn dn_in_subtree_semantics() {
        use crate::der::tag;
        let c = (oid::COUNTRY, tag::PRINTABLE_STRING, "US");
        let o = (oid::ORGANIZATION, tag::UTF8_STRING, "Corp");
        let cn = (oid::COMMON_NAME, tag::UTF8_STRING, "x");
        let full = raw_name(&[c, o, cn]);
        assert!(super::dn_in_subtree(&full, &raw_name(&[c, o])));
        assert!(super::dn_in_subtree(&full, &raw_name(&[c])));
        assert!(super::dn_in_subtree(&full, &raw_name(&[c, o, cn])));
        assert!(super::dn_in_subtree(&full, &raw_name(&[])));
        assert!(!super::dn_in_subtree(&full, &raw_name(&[o, c])));
        assert!(!super::dn_in_subtree(&full, &raw_name(&[o])));
        assert!(!super::dn_in_subtree(&raw_name(&[c]), &raw_name(&[c, o])));
        assert!(!super::dn_in_subtree(&raw_name(&[]), &raw_name(&[c])));
        // Not a Name on either side: no match.
        assert!(!super::dn_in_subtree(&[0x30, 0x01], &raw_name(&[c])));
        assert!(!super::dn_in_subtree(&full, &[0x04, 0x00]));
    }
}
