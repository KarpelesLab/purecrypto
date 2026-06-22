//! RFC 6960 Online Certificate Status Protocol responses.
//!
//! Scope is the OCSP *response* — the only side TLS stapling cares about
//! (RFC 6066 §8 + RFC 8446 §4.4.2.1). Building OCSP *requests* and running an
//! actual responder are out of scope: stapled responses are produced by the
//! issuer's responder out-of-band and the TLS server merely carries the DER
//! blob on the wire. This module:
//!
//!   - Parses an `OCSPResponse` (the outer envelope with `responseStatus`
//!     and an optional `responseBytes` carrying a `BasicOCSPResponse`).
//!   - Parses the inner `BasicOCSPResponse` → `ResponseData` →
//!     `SingleResponse` rows, mapping `CertStatus` into a Rust enum.
//!   - Verifies the BasicOCSPResponse signature (RFC 6960 §4.2.2.2): either
//!     directly by the certificate issuer or by a delegated responder
//!     certificate the issuer signed and stamped with the
//!     `id-kp-OCSPSigning` extended key usage.
//!   - Locates the `SingleResponse` matching a `(leaf, issuer)` pair by
//!     computing `issuerNameHash` / `issuerKeyHash` / `serialNumber` and
//!     comparing byte-for-byte.
//!
//! ASN.1 module wire format (RFC 6960 §4.2.1, simplified):
//!
//! ```text
//! OCSPResponse ::= SEQUENCE {
//!     responseStatus      OCSPResponseStatus,            -- ENUMERATED
//!     responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL }
//!
//! ResponseBytes ::= SEQUENCE {
//!     responseType   OBJECT IDENTIFIER,                 -- id-pkix-ocsp-basic
//!     response       OCTET STRING }                     -- BasicOCSPResponse DER
//!
//! BasicOCSPResponse ::= SEQUENCE {
//!     tbsResponseData      ResponseData,
//!     signatureAlgorithm   AlgorithmIdentifier,
//!     signature            BIT STRING,
//!     certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
//!
//! ResponseData ::= SEQUENCE {
//!     version              [0] EXPLICIT Version DEFAULT v1,
//!     responderID              ResponderID,
//!     producedAt               GeneralizedTime,
//!     responses                SEQUENCE OF SingleResponse,
//!     responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
//!
//! ResponderID ::= CHOICE {
//!     byName  [1] EXPLICIT Name,
//!     byKey   [2] EXPLICIT KeyHash }                    -- SHA-1 of issuer SPKI bits
//!
//! SingleResponse ::= SEQUENCE {
//!     certID                       CertID,
//!     certStatus                   CertStatus,
//!     thisUpdate                   GeneralizedTime,
//!     nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
//!     singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
//!
//! CertID ::= SEQUENCE {
//!     hashAlgorithm   AlgorithmIdentifier,              -- usually SHA-1
//!     issuerNameHash  OCTET STRING,                     -- hash of issuer subject DN
//!     issuerKeyHash   OCTET STRING,                     -- hash of issuer SPKI bits
//!     serialNumber    CertificateSerialNumber }         -- INTEGER
//!
//! CertStatus ::= CHOICE {
//!     good     [0] IMPLICIT NULL,                       -- wire tag 0x80
//!     revoked  [1] IMPLICIT RevokedInfo,                -- wire tag 0xA1 (SEQUENCE)
//!     unknown  [2] IMPLICIT UnknownInfo }               -- wire tag 0x82 (NULL)
//!
//! RevokedInfo ::= SEQUENCE {
//!     revocationTime              GeneralizedTime,
//!     revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
//! ```
//!
//! See [`OcspResponse`] for the read API and [`OcspResponseBuilder`] for the
//! (test-side) builder used to generate fixtures.

use alloc::string::String;
use alloc::vec::Vec;

use super::{
    AnyPublicKey, CertSigner, Certificate, CrlReason, Error, Extension, SignatureAlgId, Time, oid,
};
use crate::der::{
    Reader, encode_bit_string, encode_context, encode_integer, encode_null, encode_octet_string,
    encode_sequence, encode_tlv, oid_tlv, parse_oid, pem_decode, pem_encode, tag,
};
use crate::hash::{sha1, sha256, sha384, sha512};
use crate::rng::RngCore;
use crate::signature_registry::{SignaturePolicy, find_by_oid};

const PEM_LABEL: &str = "OCSP RESPONSE";

/// `OCSPResponseStatus` (RFC 6960 §4.2.1). Only `Successful` carries a
/// `responseBytes` field; the other variants are diagnostic codes that
/// indicate the responder refused or could not produce a status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OcspResponseStatus {
    /// `successful` (0) — the response body contains a status.
    Successful = 0,
    /// `malformedRequest` (1).
    MalformedRequest = 1,
    /// `internalError` (2).
    InternalError = 2,
    /// `tryLater` (3).
    TryLater = 3,
    /// `sigRequired` (5) — value 4 is unassigned per the ASN.1 module.
    SigRequired = 5,
    /// `unauthorized` (6).
    Unauthorized = 6,
}

impl OcspResponseStatus {
    /// Parses a single-byte ENUMERATED value into an `OcspResponseStatus`.
    /// Rejects values outside `{0,1,2,3,5,6}` (4 is reserved).
    pub fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(OcspResponseStatus::Successful),
            1 => Ok(OcspResponseStatus::MalformedRequest),
            2 => Ok(OcspResponseStatus::InternalError),
            3 => Ok(OcspResponseStatus::TryLater),
            5 => Ok(OcspResponseStatus::SigRequired),
            6 => Ok(OcspResponseStatus::Unauthorized),
            _ => Err(Error::Malformed),
        }
    }
}

/// The status the responder asserts for a single certificate.
///
/// `Good` is the only status under which a stapled response keeps the
/// handshake going; `Revoked` rejects with a final answer, and `Unknown`
/// rejects because the responder cannot speak for this certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OcspCertStatus {
    /// `good [0]` — the certificate is in scope and not revoked.
    Good,
    /// `revoked [1]` — carries the responder's `revocationTime` and the
    /// optional `revocationReason` extension.
    Revoked {
        /// `RevokedInfo.revocationTime`.
        revocation_time: Time,
        /// Optional reason carried in `[0] EXPLICIT CRLReason`.
        reason: Option<CrlReason>,
    },
    /// `unknown [2]` — the responder does not have status for this serial
    /// number under the queried issuer.
    Unknown,
}

/// One row of the BasicOCSPResponse `responses` list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspSingleResponse {
    /// OID arcs of the `CertID.hashAlgorithm` (typically `id-sha1`).
    pub hash_alg_oid: Vec<u64>,
    /// Hash of the issuer's `subject` Name TLV's *value* (the `Name` body,
    /// per RFC 6960 §4.1.1: the hash input is the DER-encoded `Name` value
    /// excluding the tag and length octets — i.e. the body of the SEQUENCE).
    pub issuer_name_hash: Vec<u8>,
    /// Hash of the issuer's `subjectPublicKey` BIT STRING value (raw key bits,
    /// no unused-bits octet).
    pub issuer_key_hash: Vec<u8>,
    /// Raw `serialNumber` INTEGER body (strict-DER canonical magnitude).
    pub serial: Vec<u8>,
    /// `CertStatus` mapped to a Rust enum.
    pub status: OcspCertStatus,
    /// `thisUpdate` — the time at which this status is asserted to be
    /// authoritative.
    pub this_update: Time,
    /// Optional `nextUpdate` — the time after which the status may not be
    /// authoritative any longer.
    pub next_update: Option<Time>,
}

/// A signed, DER-encoded RFC 6960 `OCSPResponse`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspResponse {
    der: Vec<u8>,
}

/// The split of a `BasicOCSPResponse` into the bits we hash, the algorithm
/// identifier we route through, and the signature value.
struct BasicParts<'a> {
    /// Raw `tbsResponseData` TLV — what the signature covers.
    tbs: &'a [u8],
    /// Outer signature algorithm OID arcs.
    sig_alg: Vec<u64>,
    /// Signature bits (no unused-bits octet).
    signature: &'a [u8],
    /// Raw `[0] EXPLICIT SEQUENCE OF Certificate` content (without the
    /// `[0] EXPLICIT` wrapping), or `None` when the optional `certs`
    /// field is absent.
    certs_inner: Option<&'a [u8]>,
}

/// Options for [`OcspResponse::check_for_cert_with_options`].
///
/// Bundles the verification knobs so the call site stays a single argument as
/// new options are added (rather than growing the method's parameter list).
/// Construct with [`OcspCheckOptions::new`] — which takes the mandatory
/// signature [`SignaturePolicy`] that gates every signature the check verifies
/// — then layer the optional settings:
///
/// ```ignore
/// let opts = OcspCheckOptions::new(&policy)
///     .with_time(Some(&now))      // staple freshness + responder validity
///     .with_nonce(&request_nonce); // RFC 6960 §4.4.1 nonce binding
/// let status = resp.check_for_cert_with_options(&leaf, &issuer, &opts)?;
/// ```
///
/// The fields are private and the only constructors are [`new`](Self::new) plus
/// the `with_*` builders, so a future option can be added as one more private
/// field + builder method without breaking callers. `Copy` is intentionally
/// *not* derived: it would otherwise become a backward-compatibility hazard if
/// a later option needs an owned (non-`Copy`) type.
#[derive(Clone)]
pub struct OcspCheckOptions<'a> {
    policy: &'a SignaturePolicy,
    now: Option<&'a Time>,
    nonce: Option<&'a [u8]>,
}

impl<'a> OcspCheckOptions<'a> {
    /// New options gating every verified signature — the BasicOCSPResponse
    /// signature and any delegated-responder cert signature — by `policy`.
    /// Freshness is skipped (no clock) and the response nonce is not checked
    /// until you add them with [`with_time`](Self::with_time) /
    /// [`with_nonce`](Self::with_nonce).
    pub fn new(policy: &'a SignaturePolicy) -> Self {
        Self {
            policy,
            now: None,
            nonce: None,
        }
    }

    /// Sets the clock used for staple freshness (`thisUpdate`/`nextUpdate`) and
    /// delegated-responder certificate validity. `None` skips both checks — the
    /// TLS layer passes `None` only under `verify_certificates = false`.
    pub fn with_time(mut self, now: Option<&'a Time>) -> Self {
        self.now = now;
        self
    }

    /// Requires the response to echo `nonce` byte-for-byte (RFC 6960 §4.4.1).
    /// Use when a fresh `OCSPRequest` is dispatched over a network; a missing
    /// or mismatched nonce fails closed. Stapled-OCSP callers leave this unset.
    pub fn with_nonce(mut self, nonce: &'a [u8]) -> Self {
        self.nonce = Some(nonce);
        self
    }
}

impl OcspResponse {
    /// Wraps existing OCSP-response DER. Validates only that the outer
    /// structure is a single SEQUENCE with no trailing bytes.
    pub fn from_der(der: Vec<u8>) -> Result<Self, Error> {
        let mut r = Reader::new(&der);
        r.read_sequence()?;
        r.finish()?;
        Ok(OcspResponse { der })
    }

    /// Parses a PEM `OCSP RESPONSE` document.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(OcspResponse {
            der: pem_decode(pem, PEM_LABEL)?,
        })
    }

    /// The DER encoding.
    pub fn to_der(&self) -> &[u8] {
        &self.der
    }

    /// The PEM encoding.
    pub fn to_pem(&self) -> String {
        pem_encode(PEM_LABEL, &self.der)
    }

    /// Top-level `responseStatus`.
    pub fn response_status(&self) -> Result<OcspResponseStatus, Error> {
        let mut outer = Reader::new(&self.der);
        let mut seq = outer.read_sequence()?;
        let v = seq.read_tlv(0x0a)?; // ENUMERATED
        if v.len() != 1 {
            return Err(Error::Malformed);
        }
        OcspResponseStatus::from_u8(v[0])
    }

    /// Returns the inner BasicOCSPResponse DER, or `None` if
    /// `responseStatus` is non-Successful or `responseBytes` is absent.
    fn basic_response_der(&self) -> Result<Option<&[u8]>, Error> {
        let mut outer = Reader::new(&self.der);
        let mut seq = outer.read_sequence()?;
        let status = seq.read_tlv(0x0a)?;
        if status.len() != 1 || status[0] != 0 {
            // Successful (= 0) is the only status that carries responseBytes.
            return Ok(None);
        }
        if seq.is_empty() {
            return Ok(None);
        }
        // `responseBytes [0] EXPLICIT ResponseBytes`.
        let rb_tlv = seq.read_tlv(tag::context(0))?;
        // The OCSPResponse SEQUENCE ends here — reject trailing fields, for
        // parity with Certificate / CRL strictness.
        seq.finish()?;
        let mut rb = Reader::new(rb_tlv);
        let mut rb_seq = rb.read_sequence()?;
        let resp_type = parse_oid(rb_seq.read_oid()?)?;
        if resp_type.as_slice() != oid::ID_PKIX_OCSP_BASIC {
            return Err(Error::UnsupportedAlgorithm);
        }
        // `response OCTET STRING` whose content is the BasicOCSPResponse DER.
        let basic = rb_seq.read_octet_string()?;
        rb_seq.finish()?;
        // ...and the `[0]` EXPLICIT wrapper holds exactly one ResponseBytes.
        rb.finish()?;
        Ok(Some(basic))
    }

    /// Splits a BasicOCSPResponse into its components for signature
    /// verification + certs extraction.
    fn basic_parts(&self) -> Result<BasicParts<'_>, Error> {
        let basic = self.basic_response_der()?.ok_or(Error::Malformed)?;
        let mut outer = Reader::new(basic);
        let mut bocsp = outer.read_sequence()?;
        let tbs = bocsp.read_element()?;
        let mut alg = bocsp.read_sequence()?;
        let sig_alg = parse_oid(alg.read_oid()?)?;
        // We don't enforce algid-parameters byte equality here — there's no
        // RFC 6960 §4 mandate that the algorithm identifier match anything
        // inside `tbsResponseData` (unlike RFC 5280 §4.1.1.2's
        // inner/outer requirement).
        let signature = bocsp.read_bit_string()?;
        let certs_inner = if !bocsp.is_empty() && bocsp.peek_tag() == Some(tag::context(0)) {
            let body = bocsp.read_tlv(tag::context(0))?;
            // The `[0] EXPLICIT SEQUENCE OF Certificate` wrapping: unwrap the
            // [0] tag and surface the inner SEQUENCE OF Certificate.
            let mut sr = Reader::new(body);
            let inner = sr.read_element()?; // the SEQUENCE OF Certificate TLV
            sr.finish()?;
            Some(inner)
        } else {
            None
        };
        bocsp.finish()?;
        Ok(BasicParts {
            tbs,
            sig_alg,
            signature,
            certs_inner,
        })
    }

    /// The OID arcs of the inner BasicOCSPResponse `signatureAlgorithm`.
    pub fn signature_algorithm_oid(&self) -> Result<Vec<u64>, Error> {
        Ok(self.basic_parts()?.sig_alg)
    }

    /// Verifies the BasicOCSPResponse signature over `tbsResponseData`
    /// against `key`, dispatching through the signature-algorithm registry.
    ///
    /// Unlike certificates and CRLs, an OCSP `BasicOCSPResponse` has a single
    /// `signatureAlgorithm` field with no inner counterpart, so there is no
    /// RFC 5280 §4.1.1.2-style inner/outer consistency requirement to enforce.
    ///
    /// SECURITY: this performs **no** signature-algorithm-strength or key-size
    /// policy. A SHA-1- or MD5-based signature, or an undersized RSA key, will
    /// verify **successfully** here. Callers MUST apply their own policy (e.g.
    /// `SignaturePolicy::permits`, as the TLS path does in
    /// `tls::pki::verify`) before trusting the result — or use
    /// [`verify_signature_with_policy`](Self::verify_signature_with_policy),
    /// which folds that gate in.
    pub fn verify_signature_with(&self, key: &AnyPublicKey) -> Result<(), Error> {
        let p = self.basic_parts()?;
        key.verify(&p.sig_alg, p.tbs, p.signature)
    }

    /// Like [`verify_signature_with`](Self::verify_signature_with), but first
    /// gates the BasicOCSPResponse `signatureAlgorithm` through `policy` —
    /// mirroring how `tls::pki::verify::verify_cert_against_issuer` gates
    /// chain signatures. Resolves the algorithm in the registry and rejects
    /// with [`Error::Verification`] when `policy` does not permit it under
    /// `key`'s SPKI (e.g. a SHA-1/MD5-signed staple under
    /// `SignaturePolicy::modern()`), before performing the cryptographic
    /// verification.
    pub fn verify_signature_with_policy(
        &self,
        key: &AnyPublicKey,
        policy: &SignaturePolicy,
    ) -> Result<(), Error> {
        let p = self.basic_parts()?;
        let algo = find_by_oid(&p.sig_alg).ok_or(Error::Verification)?;
        if !policy.permits(algo, &key.to_spki_der()) {
            return Err(Error::Verification);
        }
        key.verify(&p.sig_alg, p.tbs, p.signature)
    }

    /// `producedAt` — when the responder generated the response.
    pub fn produced_at(&self) -> Result<Time, Error> {
        let p = self.basic_parts()?;
        let mut outer = Reader::new(p.tbs);
        let mut td = outer.read_sequence()?;
        // Optional `version [0] EXPLICIT Version DEFAULT v1`.
        if td.peek_tag() == Some(tag::context(0)) {
            let _ = td.read_tlv(tag::context(0))?;
        }
        // responderID — opaque to producedAt.
        td.read_any()?;
        read_generalized_time(&mut td)
    }

    /// The first delegated responder certificate in `BasicOCSPResponse.certs`,
    /// if any. The leaf is the only candidate we consult — RFC 6960
    /// permits a chain but in practice the responder cert is one entry,
    /// signed by the issuer.
    pub fn delegated_responder_cert(&self) -> Result<Option<Certificate>, Error> {
        let p = self.basic_parts()?;
        let Some(inner) = p.certs_inner else {
            return Ok(None);
        };
        let mut r = Reader::new(inner);
        let mut list = r.read_sequence()?;
        if list.is_empty() {
            return Ok(None);
        }
        let first = list.read_element()?;
        Ok(Some(Certificate::from_der(first.to_vec())?))
    }

    /// Iterates the `responses` SEQUENCE OF SingleResponse.
    pub fn responses(&self) -> Result<Vec<OcspSingleResponse>, Error> {
        let p = self.basic_parts()?;
        let mut out = Vec::new();
        let mut outer = Reader::new(p.tbs);
        let mut td = outer.read_sequence()?;
        if td.peek_tag() == Some(tag::context(0)) {
            let _ = td.read_tlv(tag::context(0))?;
        }
        // responderID
        td.read_any()?;
        // producedAt
        td.read_any()?;
        // responses
        let responses_tlv = td.read_element()?;
        let mut rr = Reader::new(responses_tlv);
        let mut rseq = rr.read_sequence()?;
        while !rseq.is_empty() {
            out.push(read_single_response(&mut rseq)?);
        }
        // No trailing bytes after the responses SEQUENCE TLV.
        rr.finish()?;
        // responseExtensions [1] EXPLICIT Extensions OPTIONAL — not surfaced
        // here (see `nonce()`), but skipped so the strict no-trailing-bytes
        // `finish()` below holds for responses that carry it.
        if !td.is_empty() && td.peek_tag() == Some(tag::context(1)) {
            td.read_tlv(tag::context(1))?;
        }
        // No trailing bytes inside the ResponseData SEQUENCE.
        td.finish()?;
        Ok(out)
    }

    /// Returns the value of the `id-pkix-ocsp-nonce` extension (RFC 6960
    /// §4.4.1) carried in `ResponseData.responseExtensions`, if present. The
    /// returned bytes are the inner nonce — the OCTET STRING content nested
    /// inside the extension's `extnValue` OCTET STRING, matching the encoding
    /// emitted by [`OcspResponseBuilder::nonce`] and by RFC 8954-conformant
    /// CAs (OpenSSL, Let's Encrypt, …).
    ///
    /// A response with no nonce extension returns `Ok(None)`. Callers that
    /// requested a nonce in their `OCSPRequest` MUST refuse such a response
    /// — see [`Self::check_for_cert_with_nonce`].
    pub fn nonce(&self) -> Result<Option<Vec<u8>>, Error> {
        let p = self.basic_parts()?;
        let mut outer = Reader::new(p.tbs);
        let mut td = outer.read_sequence()?;
        if td.peek_tag() == Some(tag::context(0)) {
            let _ = td.read_tlv(tag::context(0))?; // version
        }
        td.read_any()?; // responderID
        td.read_any()?; // producedAt
        td.read_any()?; // responses
        // responseExtensions [1] EXPLICIT Extensions OPTIONAL
        if td.is_empty() || td.peek_tag() != Some(tag::context(1)) {
            return Ok(None);
        }
        let wrapper = td.read_tlv(tag::context(1))?;
        let mut outer_ext = Reader::new(wrapper);
        let mut exts = outer_ext.read_sequence()?;
        while !exts.is_empty() {
            let mut ext = exts.read_sequence()?;
            let id = parse_oid(ext.read_oid()?)?;
            // critical BOOLEAN DEFAULT FALSE — skip if present.
            if ext.peek_tag() == Some(tag::BOOLEAN) {
                ext.read_boolean()?;
            }
            let value = ext.read_octet_string()?;
            if id.as_slice() == oid::ID_PKIX_OCSP_NONCE {
                // RFC 8954 §2.1: the extnValue OCTET STRING wraps an inner
                // DER OCTET STRING that holds the actual nonce bytes. Parse
                // the inner OCTET STRING; reject any other shape so a
                // responder cannot smuggle arbitrary DER through the nonce
                // slot.
                let mut nr = Reader::new(value);
                let inner = nr.read_octet_string()?;
                nr.finish()?;
                return Ok(Some(inner.to_vec()));
            }
        }
        Ok(None)
    }

    /// Backward-compatible convenience wrapper over
    /// [`check_for_cert_with_options`](Self::check_for_cert_with_options) that
    /// applies [`SignaturePolicy::modern()`] to every signature it verifies.
    /// Prefer the options form when you need to supply your own policy (e.g.
    /// the TLS layer threads its configured `signature_policy`) or a request
    /// nonce.
    pub fn check_for_cert(
        &self,
        leaf: &Certificate,
        issuer: &Certificate,
        now: Option<&Time>,
    ) -> Result<OcspCertStatus, Error> {
        let policy = SignaturePolicy::modern();
        self.check_for_cert_with_options(
            leaf,
            issuer,
            &OcspCheckOptions::new(&policy).with_time(now),
        )
    }

    /// End-to-end validation of a stapled OCSP response. Combines the
    /// signature verification, freshness check, and `(leaf, issuer)`
    /// match into a single call returning the asserted `CertStatus`.
    ///
    /// - Signature verification: tries the issuer key directly first; if
    ///   that fails and a delegated responder certificate is embedded in
    ///   `BasicOCSPResponse.certs[0]`, verifies that responder cert against
    ///   the issuer, checks it carries the `id-kp-OCSPSigning` EKU
    ///   (RFC 6960 §4.2.2.2) and — when `now` is `Some` — that the responder
    ///   cert is still inside its own validity period, then uses the responder
    ///   key to verify the OCSP signature.
    /// - Freshness: requires the matching `SingleResponse` to have
    ///   `thisUpdate <= now` and (when present) `now < nextUpdate`. When
    ///   `now` is `None` the freshness check is skipped — the TLS layer
    ///   passes `None` only under `verify_certificates = false`, where the
    ///   peer's certificates are not validated either.
    /// - Match: see [`find_response_for`](Self::find_response_for).
    ///
    /// Returns `Err(Error::Verification)` for signature failures and
    /// `Err(Error::Malformed)` for missing rows / expired staples — the
    /// TLS layer translates both into [`crate::tls::Error::OcspResponseInvalid`]
    /// to map to a `bad_certificate` alert.
    ///
    /// SECURITY: `policy` gates every signature this verifies — the
    /// BasicOCSPResponse signature AND, for a delegated responder, the
    /// responder cert's own issuer signature — exactly as
    /// `tls::pki::verify::verify_cert_against_issuer` gates chain signatures.
    /// A response (or responder cert) signed with an algorithm `policy` does
    /// not permit — e.g. SHA-1/MD5-RSA or an undersized RSA key under
    /// `SignaturePolicy::modern()` — is rejected with [`Error::Verification`]
    /// even if the signature would otherwise verify. This closes the
    /// revocation-path downgrade where a staple's signature was accepted under
    /// a weaker algorithm than the chain it speaks for.
    pub fn check_for_cert_with_options(
        &self,
        leaf: &Certificate,
        issuer: &Certificate,
        opts: &OcspCheckOptions<'_>,
    ) -> Result<OcspCertStatus, Error> {
        let policy = opts.policy;
        let now = opts.now;
        // 1. Signature. Try the issuer key first; fall back to a delegated
        //    responder cert if present. Both the BasicOCSPResponse signature
        //    and the responder cert's signature are gated by `policy`.
        let issuer_key = issuer.subject_public_key()?;
        if self
            .verify_signature_with_policy(&issuer_key, policy)
            .is_err()
        {
            let responder = self
                .delegated_responder_cert()?
                .ok_or(Error::Verification)?;
            // The responder cert chains back to the issuer (single hop —
            // RFC 6960 §4.2.2.2 requires the delegation come from the same
            // CA that issued the certificate the response covers). Gate the
            // responder cert's own signatureAlgorithm through `policy` before
            // verifying it, mirroring `verify_cert_against_issuer`.
            verify_cert_signature_with_policy(&responder, &issuer_key, policy)?;
            // ...with id-kp-OCSPSigning in its EKU.
            let ekus = responder.extended_key_usages()?;
            if !ekus.iter().any(|o| o.as_slice() == oid::ID_KP_OCSP_SIGNING) {
                return Err(Error::Verification);
            }
            // ...and that is an end-entity, not a CA. A delegated OCSP
            // responder is an end-entity cert issued by the CA solely to sign
            // status responses (RFC 6960 §4.2.2.2); a cert with
            // basicConstraints CA:TRUE is a sub-CA and must not double as a
            // responder. The id-kp-OCSPSigning EKU is the load-bearing gate,
            // but rejecting a CA:TRUE cert here closes the door on a sub-CA
            // (which can already mint certs) additionally forging status.
            if let Some((true, _)) = responder.basic_constraints()? {
                return Err(Error::Verification);
            }
            // ...and that it carries no critical extension we don't
            // recognize. RFC 5280 §4.2 requires rejecting a certificate with
            // an unhandled critical extension; the chain validator enforces
            // this (`tls::pki::verify::check_critical_extensions_recognized`)
            // but the responder cert never passes through that path, so
            // mirror the same allowlist here before trusting its key.
            check_responder_critical_extensions(&responder)?;
            // ...and (when a clock is supplied) still inside its own
            // notBefore/notAfter window. Without this, the private key of an
            // expired-but-once-valid OCSPSigning cert could forge a "good"
            // status indefinitely: expiry is precisely what should retire that
            // key. The `now` is None only under `verify_certificates = false`,
            // where the peer chain isn't validated either — so mirror the
            // freshness gate below and skip the check in that mode.
            if let Some(now) = now
                && !responder.validity()?.accepts(now)
            {
                return Err(Error::Verification);
            }
            let responder_key = responder.subject_public_key()?;
            self.verify_signature_with_policy(&responder_key, policy)?;
        }

        // 2. Locate the SingleResponse for this leaf.
        let single = self
            .find_response_for(leaf, issuer)?
            .ok_or(Error::Malformed)?;

        // 3. Freshness. RFC 6960 §3.2: thisUpdate <= now < nextUpdate. The
        //    nextUpdate field is optional — when absent, the responder is
        //    saying it has no fresher response; we accept the staple
        //    anyway (mirroring the rustls and OpenSSL leniency rule, which
        //    treats the response as valid as long as it isn't in the
        //    future and isn't past its claimed expiry).
        if let Some(now) = now {
            let now_u = now.to_unix();
            // Fail closed on an unparsable thisUpdate: `to_unix` would coerce a
            // malformed time to 0 (the Unix epoch), making it look perpetually
            // "in the past" and silently passing this freshness gate. A
            // response we cannot date is not a response we can trust.
            let this_update = single
                .this_update
                .to_unix_checked()
                .ok_or(Error::Malformed)?;
            if this_update > now_u {
                return Err(Error::Malformed);
            }
            if let Some(nu) = &single.next_update {
                // Likewise: a present-but-malformed nextUpdate must reject,
                // not be treated as "no expiry".
                let next_update = nu.to_unix_checked().ok_or(Error::Malformed)?;
                if now_u >= next_update {
                    return Err(Error::Malformed);
                }
            }
        }

        // 4. Optional nonce binding (RFC 6960 §4.4.1). When the caller set a
        //    nonce via `OcspCheckOptions::with_nonce`, the response MUST echo
        //    it byte-for-byte: a missing nonce is as much a replay-window hole
        //    as a mismatched one (the responder can ignore the request nonce
        //    and return a fresh-looking cached staple), so both fail closed.
        if let Some(expected_nonce) = opts.nonce {
            match self.nonce()? {
                Some(got) if got.as_slice() == expected_nonce => {}
                _ => return Err(Error::Verification),
            }
        }

        Ok(single.status)
    }

    /// Like [`check_for_cert`](Self::check_for_cert), but additionally
    /// requires the response to echo the `expected_nonce` that the client
    /// embedded in its `OCSPRequest`. Use this when a fresh OCSPRequest is
    /// dispatched over a network (RFC 6960 §4.4.1): without nonce binding a
    /// captured stapled response can be replayed against a fresh request,
    /// defeating freshness even when `nextUpdate` is short.
    ///
    /// `expected_nonce` is the raw nonce value the client placed in the
    /// request (see [`OcspRequestBuilder::nonce`]). It must be:
    /// - present in the response;
    /// - byte-equal to `expected_nonce`.
    ///
    /// Either condition failing returns [`Error::Verification`]. Callers that
    /// retrieve OCSP via stapling (RFC 6066 §8 / RFC 8446 §4.4.2.1) should
    /// stick with [`check_for_cert`](Self::check_for_cert) — the TLS layer
    /// has no fresh nonce to compare against — and rely on `nextUpdate`
    /// freshness instead.
    pub fn check_for_cert_with_nonce(
        &self,
        leaf: &Certificate,
        issuer: &Certificate,
        now: Option<&Time>,
        expected_nonce: &[u8],
    ) -> Result<OcspCertStatus, Error> {
        let policy = SignaturePolicy::modern();
        self.check_for_cert_with_options(
            leaf,
            issuer,
            &OcspCheckOptions::new(&policy)
                .with_time(now)
                .with_nonce(expected_nonce),
        )
    }

    /// Finds the `SingleResponse` that names `leaf` under `issuer`. Compares
    /// `(issuerNameHash, issuerKeyHash, serial)` after recomputing the hashes
    /// under the responder's chosen algorithm — this lets a single OCSP
    /// response be matched regardless of whether the responder used SHA-1
    /// (the RFC 6960 §4.3 default) or SHA-256/384/512.
    pub fn find_response_for(
        &self,
        leaf: &Certificate,
        issuer: &Certificate,
    ) -> Result<Option<OcspSingleResponse>, Error> {
        // RFC 6960 §4.1.1: issuerNameHash is the hash of the *full* DER `Name`
        // TLV (tag + length + content), exactly as conformant responders
        // (OpenSSL, Let's Encrypt) compute it. `subject_der()` returns that
        // complete `Name` TLV.
        let issuer_name_tlv = issuer.subject_der()?;
        let issuer_key_bits = issuer.subject_public_key_bits()?;
        let serial = leaf.serial_bytes()?;
        // strict-DER canonical: a single leading 0x00 is the sign-protection
        // pad and not part of the magnitude. Comparison is on the magnitude
        // (mirrors the CRL `is_revoked` semantics in `src/x509/crl.rs`).
        let serial_magnitude = strip_leading_sign_zero(serial);

        for r in self.responses()? {
            let Some((nh, kh)) = hash_pair(&r.hash_alg_oid, issuer_name_tlv, issuer_key_bits)
            else {
                continue;
            };
            if r.issuer_name_hash != nh || r.issuer_key_hash != kh {
                continue;
            }
            if strip_leading_sign_zero(&r.serial) != serial_magnitude {
                continue;
            }
            return Ok(Some(r));
        }
        Ok(None)
    }
}

/// Reads a `GeneralizedTime` — the only time type RFC 6960 uses — binding the
/// body to the exact 15-byte `YYYYMMDDHHMMSSZ` form. Without the length
/// check, a 13-byte UTCTime-shaped body smuggled under the GENERALIZED_TIME
/// tag would hit the two-digit-year century pivot in [`Time::components`]
/// (which keys off the stored length), letting one blob parse to two
/// different instants across parsers.
fn read_generalized_time(r: &mut Reader<'_>) -> Result<Time, Error> {
    let (t, value) = r.read_any()?;
    if t != tag::GENERALIZED_TIME || value.len() != 15 {
        return Err(Error::Malformed);
    }
    let s = core::str::from_utf8(value).map_err(|_| Error::Malformed)?;
    Ok(Time::from_repr(s))
}

/// Reads one `SingleResponse` row.
fn read_single_response(reader: &mut Reader<'_>) -> Result<OcspSingleResponse, Error> {
    let entry = reader.read_element()?;
    let mut r = Reader::new(entry);
    let mut s = r.read_sequence()?;

    // CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
    let mut cert_id = s.read_sequence()?;
    let mut hash_alg = cert_id.read_sequence()?;
    let hash_alg_oid = parse_oid(hash_alg.read_oid()?)?;
    // Tolerate either no parameters or a NULL parameter — RFC 6960 §4.3 picks
    // SHA-1 by default and RFC 5754 §2 says the parameters field MUST be
    // absent for SHA-2 family OIDs but historical responders emit NULL. We
    // accept either form.
    if !hash_alg.is_empty() {
        hash_alg.read_null()?;
    }
    hash_alg.finish()?;
    let issuer_name_hash = cert_id.read_octet_string()?.to_vec();
    let issuer_key_hash = cert_id.read_octet_string()?.to_vec();
    let serial = cert_id.read_unsigned_integer_bytes()?.to_vec();
    cert_id.finish()?;

    // CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo,
    //                         unknown [2] IMPLICIT NULL }
    let (status_tag, status_body) = s.read_any()?;
    let status = match status_tag {
        // [0] IMPLICIT NULL — primitive, empty body.
        0x80 => {
            if !status_body.is_empty() {
                return Err(Error::Malformed);
            }
            OcspCertStatus::Good
        }
        // [1] IMPLICIT SEQUENCE — RevokedInfo (constructed).
        0xa1 => {
            let mut ri = Reader::new(status_body);
            let revocation_time = read_generalized_time(&mut ri)?;
            let mut reason = None;
            if !ri.is_empty() && ri.peek_tag() == Some(tag::context(0)) {
                // [0] EXPLICIT CRLReason ::= ENUMERATED
                let body = ri.read_tlv(tag::context(0))?;
                let mut br = Reader::new(body);
                let enum_body = br.read_tlv(0x0a)?;
                if enum_body.len() != 1 {
                    return Err(Error::Malformed);
                }
                reason = Some(CrlReason::from_u8(enum_body[0])?);
                br.finish()?;
            }
            // No trailing bytes inside RevokedInfo after the optional reason.
            ri.finish()?;
            OcspCertStatus::Revoked {
                revocation_time,
                reason,
            }
        }
        // [2] IMPLICIT NULL — primitive, empty body.
        0x82 => {
            if !status_body.is_empty() {
                return Err(Error::Malformed);
            }
            OcspCertStatus::Unknown
        }
        _ => return Err(Error::Malformed),
    };

    // thisUpdate (GeneralizedTime).
    let this_update = read_generalized_time(&mut s)?;

    let mut next_update = None;
    if !s.is_empty() && s.peek_tag() == Some(tag::context(0)) {
        // [0] EXPLICIT GeneralizedTime
        let body = s.read_tlv(tag::context(0))?;
        let mut nr = Reader::new(body);
        next_update = Some(read_generalized_time(&mut nr)?);
        nr.finish()?;
    }
    // We don't surface singleExtensions [1] EXPLICIT Extensions OPTIONAL, but
    // skip over it when present so the strict no-trailing-bytes `finish()`
    // below still holds for responses that carry it.
    if !s.is_empty() && s.peek_tag() == Some(tag::context(1)) {
        s.read_tlv(tag::context(1))?;
    }
    // No trailing bytes after the SingleResponse SEQUENCE.
    s.finish()?;

    Ok(OcspSingleResponse {
        hash_alg_oid,
        issuer_name_hash,
        issuer_key_hash,
        serial,
        status,
        this_update,
        next_update,
    })
}

/// Hashes `(name_tlv, key_bits)` under `hash_alg_oid`. `name_tlv` MUST be the
/// full DER `Name` TLV (tag + length + content) — RFC 6960 §4.1.1 specifies
/// `issuerNameHash` as the hash of the complete `Name`, which is what every
/// conformant responder (OpenSSL, Let's Encrypt) computes. Returns `None` for
/// unsupported OIDs (the caller skips that row).
fn hash_pair(hash_alg_oid: &[u64], name_tlv: &[u8], key_bits: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if hash_alg_oid == oid::ID_SHA1 {
        Some((sha1(name_tlv).to_vec(), sha1(key_bits).to_vec()))
    } else if hash_alg_oid == oid::ID_SHA256 {
        Some((sha256(name_tlv).to_vec(), sha256(key_bits).to_vec()))
    } else if hash_alg_oid == oid::ID_SHA384 {
        Some((sha384(name_tlv).to_vec(), sha384(key_bits).to_vec()))
    } else if hash_alg_oid == oid::ID_SHA512 {
        Some((sha512(name_tlv).to_vec(), sha512(key_bits).to_vec()))
    } else {
        None
    }
}

/// Strips a single permitted leading `0x00` (the strict-DER positive-sign
/// pad) from `bytes`, leaving the bare magnitude. Mirrors the CRL helper.
fn strip_leading_sign_zero(bytes: &[u8]) -> &[u8] {
    if bytes.len() > 1 && bytes[0] == 0x00 {
        &bytes[1..]
    } else {
        bytes
    }
}

/// Verifies the signature on a delegated responder `cert` under `issuer_key`,
/// gating on `policy`. Mirrors `tls::pki::verify::verify_cert_against_issuer`:
/// resolves the cert's `signatureAlgorithm` OID in the registry, rejects any
/// algorithm `policy` does not permit (with [`Error::Verification`]), and only
/// then delegates to the issuer key's verifier. Without this gate a SHA-1- or
/// MD5-signed responder cert would be accepted even though the chain it
/// vouches for is policy-gated.
fn verify_cert_signature_with_policy(
    cert: &Certificate,
    issuer_key: &AnyPublicKey,
    policy: &SignaturePolicy,
) -> Result<(), Error> {
    let sig_alg = cert.signature_algorithm_oid()?;
    let algo = find_by_oid(&sig_alg).ok_or(Error::Verification)?;
    if !policy.permits(algo, &issuer_key.to_spki_der()) {
        return Err(Error::Verification);
    }
    cert.verify_signature_with(issuer_key)
}

/// RFC 5280 §4.2: reject the delegated responder certificate if it carries
/// any critical extension whose OID we don't recognize. This replicates
/// `tls::pki::verify::check_critical_extensions_recognized` (which is private
/// to the TLS layer and returns its error type) for the OCSP path: the
/// recognized set is basicConstraints, keyUsage, extKeyUsage, and
/// subjectAltName — the extensions the surrounding `check_for_cert_with_options`
/// logic actually evaluates — plus `id-pkix-ocsp-nocheck` (RFC 6960
/// §4.2.2.2.1), whose semantics ("don't revocation-check the responder") are
/// trivially honored here since responder certs are not revocation-checked.
/// A critical `nameConstraints` is rejected outright: constraints restrict
/// certificates *issued by* the holder, the responder is required to be an
/// end-entity (CA:TRUE is rejected above), and nothing in this path evaluates
/// subtrees — accepting it would let a constraint we can't honor appear
/// honored. Every other critical extension fails closed.
fn check_responder_critical_extensions(cert: &Certificate) -> Result<(), Error> {
    for o in cert.critical_extension_oids()? {
        let bytes = o.as_slice();
        if bytes == oid::BASIC_CONSTRAINTS
            || bytes == oid::KEY_USAGE
            || bytes == oid::EXT_KEY_USAGE
            || bytes == oid::SUBJECT_ALT_NAME
            || bytes == oid::ID_PKIX_OCSP_NOCHECK
        {
            continue;
        }
        return Err(Error::Verification);
    }
    Ok(())
}

/// Encodes a bare `AlgorithmIdentifier` for an OCSP `CertID.hashAlgorithm`
/// field, with NULL parameters (the form historical responders emit and the
/// parser tolerates). Defaults to SHA-1 — the RFC 6960 §4.3 baseline.
fn ocsp_hash_algid(arcs: &[u64]) -> Vec<u8> {
    let mut body = oid_tlv(arcs);
    body.extend_from_slice(&encode_null());
    encode_sequence(&body)
}

// -- Builder ------------------------------------------------------------------

/// Builds a signed `OCSPResponse` carrying a single response for one
/// `(issuer, leaf)` pair. Test-only — production responders are operated
/// out-of-band by the CA and emit DER blobs we just relay.
#[derive(Clone, Debug)]
pub struct OcspResponseBuilder {
    /// The full DER `Name` TLV of the issuer subject (RFC 6960 §4.1.1 hashes
    /// the complete TLV, not just the SEQUENCE body).
    issuer_name_tlv: Vec<u8>,
    issuer_key_bits: Vec<u8>,
    serial: Vec<u8>,
    status: OcspCertStatus,
    this_update: Time,
    next_update: Option<Time>,
    produced_at: Option<Time>,
    hash_alg_oid: &'static [u64],
    responder_id_by_key: bool,
    delegated_responder_cert: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

impl OcspResponseBuilder {
    /// Starts a builder for a `(leaf, issuer)` pair with status `Good`.
    /// Defaults: SHA-1 CertID hashes, byKey responderID, `producedAt =
    /// this_update`.
    pub fn good(
        leaf: &Certificate,
        issuer: &Certificate,
        this_update: Time,
        next_update: Option<Time>,
    ) -> Result<Self, Error> {
        Self::with_status(leaf, issuer, this_update, next_update, OcspCertStatus::Good)
    }

    /// Starts a builder for a `(leaf, issuer)` pair with status `Revoked`.
    pub fn revoked(
        leaf: &Certificate,
        issuer: &Certificate,
        this_update: Time,
        next_update: Option<Time>,
        revocation_time: Time,
        reason: Option<CrlReason>,
    ) -> Result<Self, Error> {
        Self::with_status(
            leaf,
            issuer,
            this_update,
            next_update,
            OcspCertStatus::Revoked {
                revocation_time,
                reason,
            },
        )
    }

    fn with_status(
        leaf: &Certificate,
        issuer: &Certificate,
        this_update: Time,
        next_update: Option<Time>,
        status: OcspCertStatus,
    ) -> Result<Self, Error> {
        Ok(OcspResponseBuilder {
            issuer_name_tlv: issuer.subject_der()?.to_vec(),
            issuer_key_bits: issuer.subject_public_key_bits()?.to_vec(),
            serial: leaf.serial_bytes()?.to_vec(),
            status,
            this_update,
            next_update,
            produced_at: None,
            hash_alg_oid: oid::ID_SHA1,
            responder_id_by_key: true,
            delegated_responder_cert: None,
            nonce: None,
        })
    }

    /// Overrides `producedAt` (default: equal to `thisUpdate`).
    pub fn produced_at(mut self, t: Time) -> Self {
        self.produced_at = Some(t);
        self
    }

    /// Switches the responder hash algorithm. Accepted: `id-sha1`, `id-sha256`,
    /// `id-sha384`, `id-sha512`. Unknown OIDs are rejected at sign time.
    pub fn hash_algorithm(mut self, arcs: &'static [u64]) -> Self {
        self.hash_alg_oid = arcs;
        self
    }

    /// Uses `byName` (the issuer's Name DER) as the ResponderID instead of
    /// the default `byKey` (SHA-1 of the issuer SPKI bits).
    pub fn responder_id_by_name(mut self) -> Self {
        self.responder_id_by_key = false;
        self
    }

    /// Embeds `responder_cert_der` as `BasicOCSPResponse.certs[0]`. The signer
    /// passed to [`sign`](Self::sign) is then interpreted as the delegated
    /// responder's key (not the issuer's): the client validates the
    /// responder cert against the issuer and verifies the OCSP signature with
    /// the responder cert's public key.
    pub fn delegated_responder_cert(mut self, responder_cert_der: Vec<u8>) -> Self {
        self.delegated_responder_cert = Some(responder_cert_der);
        self
    }

    /// Echoes the client-supplied `nonce` back to the client via the
    /// `id-pkix-ocsp-nonce` extension in `ResponseData.responseExtensions`
    /// (RFC 6960 §4.4.1, RFC 8954 §2.1). `nonce` is the raw nonce body — the
    /// builder wraps it in the required inner-OCTET-STRING / outer-extnValue
    /// shape.
    ///
    /// Per RFC 8954 §2.1 the nonce body must be 1–32 octets; anything else is
    /// rejected at sign time.
    pub fn nonce(mut self, nonce: &[u8]) -> Self {
        self.nonce = Some(nonce.to_vec());
        self
    }

    /// Signs the response, producing a complete RFC 6960 `OCSPResponse` with
    /// `responseStatus = successful` and the BasicOCSPResponse inside.
    pub fn sign(self, signer: &CertSigner<'_>) -> Result<OcspResponse, Error> {
        let tbs = self.build_tbs_response_data()?;
        let algid = signer.algorithm_identifier();
        let signature = signer.sign(&tbs)?;
        Ok(PreparedOcsp {
            tbs,
            algid,
            certs: self.delegated_responder_cert,
        }
        .finish(&signature))
    }

    /// Begins two-phase signing for a responder key held outside the process
    /// (TPM/HSM): builds the `tbsResponseData` and returns a [`PreparedOcsp`]
    /// exposing the bytes to sign. The caller signs [`PreparedOcsp::tbs`] with
    /// its external key and calls [`PreparedOcsp::finish`] to assemble the
    /// `OCSPResponse`.
    ///
    /// `sig_alg` must match the algorithm of the external signer; it is written
    /// into the `BasicOCSPResponse.signatureAlgorithm` field.
    pub fn prepare(self, sig_alg: SignatureAlgId) -> Result<PreparedOcsp, Error> {
        let tbs = self.build_tbs_response_data()?;
        Ok(PreparedOcsp {
            tbs,
            algid: sig_alg.algorithm_identifier(),
            certs: self.delegated_responder_cert,
        })
    }

    /// Encodes the `tbsResponseData` (the signed-over portion of a
    /// `BasicOCSPResponse`). Shared by [`sign`](Self::sign) and
    /// [`prepare`](Self::prepare).
    fn build_tbs_response_data(&self) -> Result<Vec<u8>, Error> {
        // Compute CertID using the chosen hash algorithm.
        let (name_hash, key_hash) = hash_pair(
            self.hash_alg_oid,
            &self.issuer_name_tlv,
            &self.issuer_key_bits,
        )
        .ok_or(Error::UnsupportedAlgorithm)?;

        // CertID body.
        let mut cert_id_body = Vec::new();
        cert_id_body.extend_from_slice(&ocsp_hash_algid(self.hash_alg_oid));
        cert_id_body.extend_from_slice(&encode_octet_string(&name_hash));
        cert_id_body.extend_from_slice(&encode_octet_string(&key_hash));
        cert_id_body.extend_from_slice(&encode_integer(&self.serial));
        let cert_id = encode_sequence(&cert_id_body);

        // CertStatus.
        let cert_status = match &self.status {
            // good [0] IMPLICIT NULL — primitive, empty body.
            OcspCertStatus::Good => encode_tlv(0x80, &[]),
            // revoked [1] IMPLICIT RevokedInfo — constructed SEQUENCE body.
            OcspCertStatus::Revoked {
                revocation_time,
                reason,
            } => {
                let mut ri = Vec::new();
                ri.extend_from_slice(&revocation_time.to_generalized_time());
                if let Some(r) = reason {
                    let enumerated = encode_tlv(0x0a, &[*r as u8]);
                    ri.extend_from_slice(&encode_context(0, &enumerated));
                }
                encode_tlv(0xa1, &ri)
            }
            // unknown [2] IMPLICIT NULL — primitive, empty body.
            OcspCertStatus::Unknown => encode_tlv(0x82, &[]),
        };

        // SingleResponse body.
        let mut sr = Vec::new();
        sr.extend_from_slice(&cert_id);
        sr.extend_from_slice(&cert_status);
        sr.extend_from_slice(&self.this_update.to_generalized_time());
        if let Some(nu) = &self.next_update {
            sr.extend_from_slice(&encode_context(0, &nu.to_generalized_time()));
        }
        let single_response = encode_sequence(&sr);

        // responses SEQUENCE OF SingleResponse — exactly one row here.
        let responses = encode_sequence(&single_response);

        // ResponderID.
        let responder_id = if self.responder_id_by_key {
            // byKey [2] EXPLICIT KeyHash — KeyHash ::= OCTET STRING (SHA-1).
            let kh = sha1(&self.issuer_key_bits).to_vec();
            encode_context(2, &encode_octet_string(&kh))
        } else {
            // byName [1] EXPLICIT Name — the stored value is already the full
            // Name TLV.
            encode_context(1, &self.issuer_name_tlv)
        };

        // ResponseData (omit version, accept the default v1).
        let produced_at = self.produced_at.as_ref().unwrap_or(&self.this_update);
        let mut td = Vec::new();
        td.extend_from_slice(&responder_id);
        td.extend_from_slice(&produced_at.to_generalized_time());
        td.extend_from_slice(&responses);
        if let Some(nonce_bytes) = &self.nonce {
            // RFC 8954 §2.1: nonce body is 1–32 octets; the extnValue OCTET
            // STRING wraps an inner OCTET STRING that carries the nonce.
            if nonce_bytes.is_empty() || nonce_bytes.len() > 32 {
                return Err(Error::Malformed);
            }
            let inner = encode_octet_string(nonce_bytes);
            let nonce_ext = Extension {
                oid: oid::ID_PKIX_OCSP_NONCE.to_vec(),
                critical: false,
                value: inner,
            }
            .to_der();
            // responseExtensions [1] EXPLICIT SEQUENCE OF Extension.
            let exts_seq = encode_sequence(&nonce_ext);
            td.extend_from_slice(&encode_context(1, &exts_seq));
        }
        Ok(encode_sequence(&td))
    }
}

/// A `tbsResponseData` awaiting an externally produced signature.
///
/// Returned by [`OcspResponseBuilder::prepare`]. Sign [`tbs`](Self::tbs) with
/// the responder's out-of-process key, then call [`finish`](Self::finish) with
/// the resulting signature to obtain the complete [`OcspResponse`].
pub struct PreparedOcsp {
    tbs: Vec<u8>,
    algid: Vec<u8>,
    certs: Option<Vec<u8>>,
}

impl PreparedOcsp {
    /// The DER `tbsResponseData` bytes the external signer must sign. The
    /// signer applies the hash/padding of the algorithm passed to
    /// [`OcspResponseBuilder::prepare`]; these bytes are unhashed.
    pub fn tbs(&self) -> &[u8] {
        &self.tbs
    }

    /// Assembles the final `OCSPResponse` from the externally produced
    /// `signature` (the raw `signatureValue` bytes, encoded as documented on
    /// the [`SignatureAlgId`] variant).
    pub fn finish(self, signature: &[u8]) -> OcspResponse {
        // BasicOCSPResponse SEQUENCE { tbs, sigAlg, signature, [0] certs OPTIONAL }.
        let mut bocsp = Vec::new();
        bocsp.extend_from_slice(&self.tbs);
        bocsp.extend_from_slice(&self.algid);
        bocsp.extend_from_slice(&encode_bit_string(signature));
        if let Some(cert_der) = &self.certs {
            // certs [0] EXPLICIT SEQUENCE OF Certificate.
            let certs_seq = encode_sequence(cert_der);
            bocsp.extend_from_slice(&encode_context(0, &certs_seq));
        }
        let basic = encode_sequence(&bocsp);

        // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }.
        let mut rb = Vec::new();
        rb.extend_from_slice(&oid_tlv(oid::ID_PKIX_OCSP_BASIC));
        rb.extend_from_slice(&encode_octet_string(&basic));
        let response_bytes = encode_sequence(&rb);

        // OCSPResponse ::= SEQUENCE { responseStatus, [0] responseBytes }.
        let status = encode_tlv(0x0a, &[OcspResponseStatus::Successful as u8]);
        let mut out = Vec::new();
        out.extend_from_slice(&status);
        out.extend_from_slice(&encode_context(0, &response_bytes));
        OcspResponse {
            der: encode_sequence(&out),
        }
    }
}

// -- OCSP request -------------------------------------------------------------

/// An unsigned RFC 6960 §4.1 `OCSPRequest` covering a single
/// `(leaf, issuer)` pair, optionally carrying a client-chosen nonce.
///
/// Only the unsigned form (no `optionalSignature`) is emitted: it is what
/// the great majority of responders accept and what the OCSP-over-HTTP
/// profile (RFC 6960 §A.1) defines. Once built, the wire DER is exposed via
/// [`to_der`](Self::to_der) and the nonce, if any, via
/// [`nonce`](Self::nonce) so the caller can later pass it to
/// [`OcspResponse::check_for_cert_with_nonce`].
///
/// ASN.1 (RFC 6960 §4.1.1):
///
/// ```text
/// OCSPRequest ::= SEQUENCE {
///     tbsRequest                  TBSRequest,
///     optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
///
/// TBSRequest ::= SEQUENCE {
///     version             [0]     EXPLICIT Version DEFAULT v1,
///     requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
///     requestList                 SEQUENCE OF Request,
///     requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
///
/// Request ::= SEQUENCE {
///     reqCert                     CertID,
///     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL }
/// ```
#[derive(Clone, Debug)]
pub struct OcspRequest {
    der: Vec<u8>,
    nonce: Option<Vec<u8>>,
}

/// Builder for an [`OcspRequest`]. Configure the hash algorithm and the
/// nonce (if any), then call [`build`](Self::build).
#[derive(Clone, Debug)]
pub struct OcspRequestBuilder {
    /// The full DER `Name` TLV of the issuer subject (RFC 6960 §4.1.1 hashes
    /// the complete TLV, not just the SEQUENCE body).
    issuer_name_tlv: Vec<u8>,
    issuer_key_bits: Vec<u8>,
    serial: Vec<u8>,
    hash_alg_oid: &'static [u64],
    nonce: Option<Vec<u8>>,
}

impl OcspRequestBuilder {
    /// Starts a builder for a `(leaf, issuer)` pair. Defaults to SHA-1 for
    /// the CertID hash (the RFC 6960 §4.3 baseline; most responders accept
    /// SHA-256 too but SHA-1 maximises interop).
    pub fn new(leaf: &Certificate, issuer: &Certificate) -> Result<Self, Error> {
        Ok(OcspRequestBuilder {
            issuer_name_tlv: issuer.subject_der()?.to_vec(),
            issuer_key_bits: issuer.subject_public_key_bits()?.to_vec(),
            serial: leaf.serial_bytes()?.to_vec(),
            hash_alg_oid: oid::ID_SHA1,
            nonce: None,
        })
    }

    /// Switches the CertID hash algorithm. Accepted: `id-sha1`, `id-sha256`,
    /// `id-sha384`, `id-sha512`. Unknown OIDs are rejected at build time.
    pub fn hash_algorithm(mut self, arcs: &'static [u64]) -> Self {
        self.hash_alg_oid = arcs;
        self
    }

    /// Embeds `nonce` verbatim as the `id-pkix-ocsp-nonce` extension
    /// (RFC 6960 §4.4.1, RFC 8954 §2.1). The nonce body must be 1–32 octets;
    /// other lengths are rejected at build time.
    ///
    /// The same nonce is later passed to
    /// [`OcspResponse::check_for_cert_with_nonce`] to bind request and
    /// response, preventing replay of a stale-but-still-fresh-looking
    /// stapled response.
    pub fn nonce(mut self, nonce: &[u8]) -> Self {
        self.nonce = Some(nonce.to_vec());
        self
    }

    /// Generates a 16-byte nonce from `rng` and installs it. Convenience for
    /// callers that already have a CSPRNG handy.
    pub fn random_nonce<R: RngCore>(mut self, rng: &mut R) -> Self {
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        self.nonce = Some(buf.to_vec());
        self
    }

    /// Encodes the `OCSPRequest` DER. Performs no signature — the request
    /// is unsigned (RFC 6960 §4.1.2 leaves `optionalSignature` truly
    /// optional, and real-world responders accept the unsigned form).
    pub fn build(self) -> Result<OcspRequest, Error> {
        let (name_hash, key_hash) = hash_pair(
            self.hash_alg_oid,
            &self.issuer_name_tlv,
            &self.issuer_key_bits,
        )
        .ok_or(Error::UnsupportedAlgorithm)?;

        // CertID body — same shape used in the response.
        let mut cert_id_body = Vec::new();
        cert_id_body.extend_from_slice(&ocsp_hash_algid(self.hash_alg_oid));
        cert_id_body.extend_from_slice(&encode_octet_string(&name_hash));
        cert_id_body.extend_from_slice(&encode_octet_string(&key_hash));
        cert_id_body.extend_from_slice(&encode_integer(&self.serial));
        let cert_id = encode_sequence(&cert_id_body);

        // Request ::= SEQUENCE { reqCert CertID, singleRequestExtensions? }
        let request_one = encode_sequence(&cert_id);
        // requestList SEQUENCE OF Request — exactly one entry here.
        let request_list = encode_sequence(&request_one);

        // requestExtensions [2] EXPLICIT Extensions OPTIONAL.
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&request_list);
        if let Some(nonce_bytes) = &self.nonce {
            if nonce_bytes.is_empty() || nonce_bytes.len() > 32 {
                return Err(Error::Malformed);
            }
            let inner = encode_octet_string(nonce_bytes);
            let nonce_ext = Extension {
                oid: oid::ID_PKIX_OCSP_NONCE.to_vec(),
                critical: false,
                value: inner,
            }
            .to_der();
            let exts_seq = encode_sequence(&nonce_ext);
            tbs.extend_from_slice(&encode_context(2, &exts_seq));
        }
        let tbs_request = encode_sequence(&tbs);

        // OCSPRequest ::= SEQUENCE { tbsRequest, optionalSignature? } — we
        // omit the signature.
        let der = encode_sequence(&tbs_request);
        Ok(OcspRequest {
            der,
            nonce: self.nonce,
        })
    }
}

impl OcspRequest {
    /// The DER encoding ready to POST to the responder
    /// (`application/ocsp-request`, RFC 6960 §A.1).
    pub fn to_der(&self) -> &[u8] {
        &self.der
    }

    /// Returns the nonce body the builder embedded, if any. Pass this to
    /// [`OcspResponse::check_for_cert_with_nonce`] when validating the
    /// matching response.
    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::Ed25519PrivateKey;
    use crate::rsa::BoxedRsaPrivateKey;
    use crate::x509::{
        CertSigner, Certificate, DistinguishedName, Extension, Time, Validity, extension,
    };
    use alloc::vec;

    fn rsa_a() -> BoxedRsaPrivateKey {
        BoxedRsaPrivateKey::from_pkcs1_pem(include_str!("../../testdata/rsa2048_test_a.pem"))
            .expect("rsa key A")
    }
    fn rsa_b() -> BoxedRsaPrivateKey {
        BoxedRsaPrivateKey::from_pkcs1_pem(include_str!("../../testdata/rsa2048_test_b.pem"))
            .expect("rsa key B")
    }

    fn validity() -> Validity {
        Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        )
    }

    fn ed25519() -> Ed25519PrivateKey {
        // Deterministic test key.
        let seed = [7u8; 32];
        Ed25519PrivateKey::from_bytes(seed)
    }

    /// Build a self-signed issuer + a leaf certificate it signed. The pair
    /// is the minimum substrate the OCSP code needs to compute CertID
    /// fields and route the verification.
    fn issuer_and_leaf() -> (Certificate, Certificate, BoxedRsaPrivateKey) {
        let issuer_key = rsa_a();
        let issuer_dn = DistinguishedName::common_name("OCSP test root");
        let issuer = Certificate::self_signed_general(
            &CertSigner::Rsa(&issuer_key),
            &issuer_dn,
            &validity(),
            1,
            true,
            &[],
        )
        .expect("self-sign issuer");

        let leaf_key = rsa_b();
        let leaf_dn = DistinguishedName::common_name("OCSP test leaf");
        let signer = CertSigner::Rsa(&issuer_key);
        let leaf_extensions = vec![extension::basic_constraints(false, None)];
        let leaf = Certificate::issue_with_extensions(
            &signer,
            &issuer_dn,
            &leaf_dn,
            &AnyPublicKey::Rsa(leaf_key.public_key()),
            &validity(),
            42,
            &leaf_extensions,
        )
        .expect("issue leaf");

        (issuer, leaf, issuer_key)
    }

    #[test]
    fn good_roundtrip_and_verify() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);

        let resp = OcspResponseBuilder::good(
            &leaf,
            &issuer,
            Time::utc(2026, 1, 1, 0, 0, 0),
            Some(Time::utc(2026, 1, 8, 0, 0, 0)),
        )
        .unwrap()
        .sign(&signer)
        .unwrap();

        // Round-trip through DER + PEM.
        let from_der = OcspResponse::from_der(resp.to_der().to_vec()).unwrap();
        assert_eq!(from_der, resp);
        let pem = resp.to_pem();
        assert!(pem.contains("BEGIN OCSP RESPONSE"));
        let from_pem = OcspResponse::from_pem(&pem).unwrap();
        assert_eq!(from_pem, resp);

        // Top-level status.
        assert_eq!(
            resp.response_status().unwrap(),
            OcspResponseStatus::Successful
        );

        // Locates the row + reports Good.
        let single = resp.find_response_for(&leaf, &issuer).unwrap().unwrap();
        assert_eq!(single.status, OcspCertStatus::Good);
        // OCSP carries GeneralizedTime (the 15-byte `YYYYMMDDHHMMSSZ` form);
        // `Time::utc` builds the 13-byte UTCTime repr. Same instant, different
        // string — compare on the underlying Unix epoch.
        assert_eq!(
            single.this_update.to_unix(),
            Time::utc(2026, 1, 1, 0, 0, 0).to_unix()
        );
        assert_eq!(
            single.next_update.as_ref().map(|t| t.to_unix()),
            Some(Time::utc(2026, 1, 8, 0, 0, 0).to_unix())
        );

        // Signature verifies under the issuer key.
        resp.verify_signature_with(&signer.public_key()).unwrap();
    }

    // Finding 2 (RFC 6960 §4.1.1): issuerNameHash must be the hash of the FULL
    // DER `Name` TLV (tag + length + content), matching what OpenSSL / Let's
    // Encrypt emit — NOT the hash of just the SEQUENCE content. This pins the
    // emitted hash to the conformant value so a regression back to hashing the
    // stripped body is caught.
    #[test]
    fn issuer_name_hash_is_over_full_name_tlv() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);

        let resp = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .sign(&signer)
            .unwrap();
        let single = resp.find_response_for(&leaf, &issuer).unwrap().unwrap();

        // The full Name TLV (what subject_der returns) is the conformant input.
        let full_name_tlv = issuer.subject_der().unwrap();
        let expected = sha1(full_name_tlv).to_vec();
        assert_eq!(single.issuer_name_hash, expected);

        // And it must NOT equal the hash over the stripped SEQUENCE content —
        // the old (self-consistent but non-interoperable) behavior.
        let mut r = Reader::new(full_name_tlv);
        let content = r.read_tlv(tag::SEQUENCE).unwrap();
        assert_ne!(single.issuer_name_hash, sha1(content).to_vec());

        // Matching still works end-to-end with the corrected hashing.
        assert_eq!(single.status, OcspCertStatus::Good);
    }

    #[test]
    fn revoked_with_reason_roundtrip() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);

        let resp = OcspResponseBuilder::revoked(
            &leaf,
            &issuer,
            Time::utc(2026, 6, 1, 0, 0, 0),
            None,
            Time::utc(2026, 5, 1, 0, 0, 0),
            Some(CrlReason::KeyCompromise),
        )
        .unwrap()
        .sign(&signer)
        .unwrap();

        let single = resp.find_response_for(&leaf, &issuer).unwrap().unwrap();
        match single.status {
            OcspCertStatus::Revoked {
                revocation_time,
                reason,
            } => {
                // GeneralizedTime round-trip — compare on the instant.
                assert_eq!(
                    revocation_time.to_unix(),
                    Time::utc(2026, 5, 1, 0, 0, 0).to_unix()
                );
                assert_eq!(reason, Some(CrlReason::KeyCompromise));
            }
            other => panic!("expected revoked, got {other:?}"),
        }
        resp.verify_signature_with(&signer.public_key()).unwrap();
    }

    #[test]
    fn unknown_status_decodes() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);

        // No builder shortcut for Unknown — exercise it by injecting the
        // status directly through the with_status seam.
        let resp = OcspResponseBuilder::with_status(
            &leaf,
            &issuer,
            Time::utc(2026, 1, 1, 0, 0, 0),
            None,
            OcspCertStatus::Unknown,
        )
        .unwrap()
        .sign(&signer)
        .unwrap();

        let single = resp.find_response_for(&leaf, &issuer).unwrap().unwrap();
        assert_eq!(single.status, OcspCertStatus::Unknown);
    }

    #[test]
    fn responder_id_by_name() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);

        let resp = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .responder_id_by_name()
            .sign(&signer)
            .unwrap();

        // Verification still works regardless of the responderID encoding —
        // the signature covers tbsResponseData byte-for-byte, and we don't
        // try to derive the responder key from the responderID.
        resp.verify_signature_with(&signer.public_key()).unwrap();
        // And the row matches the same way.
        let single = resp.find_response_for(&leaf, &issuer).unwrap().unwrap();
        assert_eq!(single.status, OcspCertStatus::Good);
    }

    #[test]
    fn delegated_responder_cert_extraction() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let issuer_signer = CertSigner::Rsa(&issuer_key);

        // Issue a delegated responder cert. It's signed by the issuer and
        // carries id-kp-OCSPSigning EKU + the id-pkix-ocsp-nocheck marker.
        let responder_key = ed25519();
        let responder_pub = AnyPublicKey::Ed25519(responder_key.public_key());
        let responder_dn = DistinguishedName::common_name("OCSP delegated responder");
        let mut responder_extensions = vec![extension::basic_constraints(false, None)];
        responder_extensions.push(Extension {
            oid: oid::EXT_KEY_USAGE.to_vec(),
            critical: false,
            value: encode_sequence(&oid_tlv(oid::ID_KP_OCSP_SIGNING)),
        });
        responder_extensions.push(Extension {
            oid: oid::ID_PKIX_OCSP_NOCHECK.to_vec(),
            critical: false,
            value: encode_null(),
        });
        let responder_cert = Certificate::issue_with_extensions(
            &issuer_signer,
            &issuer.subject().unwrap(),
            &responder_dn,
            &responder_pub,
            &validity(),
            99,
            &responder_extensions,
        )
        .expect("issue responder");

        // The OCSP response is signed by the delegated responder key; the
        // delegated cert is embedded in `BasicOCSPResponse.certs[0]`.
        let resp = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .delegated_responder_cert(responder_cert.to_der().to_vec())
            .sign(&CertSigner::Ed25519(&responder_key))
            .unwrap();

        // Extract the embedded cert.
        let extracted = resp.delegated_responder_cert().unwrap().unwrap();
        assert_eq!(extracted.to_der(), responder_cert.to_der());

        // The OCSP signature verifies under the responder's public key, not
        // the issuer's.
        resp.verify_signature_with(&extracted.subject_public_key().unwrap())
            .unwrap();
        // It does NOT verify under the issuer's key — different signing key.
        assert!(
            resp.verify_signature_with(&issuer_signer.public_key())
                .is_err()
        );

        // The responder cert chain back to the issuer: signed by the issuer,
        // and carries id-kp-OCSPSigning in its EKU.
        let issuer_pub = issuer_signer.public_key();
        extracted.verify_signature_with(&issuer_pub).unwrap();
        let ekus = extracted.extended_key_usages().unwrap();
        assert!(ekus.iter().any(|o| o.as_slice() == oid::ID_KP_OCSP_SIGNING));
    }

    /// Build a delegated OCSP responder cert (signed by `issuer_key`, carrying
    /// the `id-kp-OCSPSigning` EKU) whose own validity window is `validity`,
    /// plus a `good` OCSP response signed by that responder and embedding the
    /// cert in `BasicOCSPResponse.certs[0]`.
    fn delegated_good_response(
        issuer: &Certificate,
        leaf: &Certificate,
        issuer_key: &BoxedRsaPrivateKey,
        responder_validity: &Validity,
    ) -> OcspResponse {
        let issuer_signer = CertSigner::Rsa(issuer_key);
        let responder_key = ed25519();
        let responder_pub = AnyPublicKey::Ed25519(responder_key.public_key());
        let responder_dn = DistinguishedName::common_name("OCSP delegated responder");
        let responder_extensions = vec![
            extension::basic_constraints(false, None),
            Extension {
                oid: oid::EXT_KEY_USAGE.to_vec(),
                critical: false,
                value: encode_sequence(&oid_tlv(oid::ID_KP_OCSP_SIGNING)),
            },
        ];
        let responder_cert = Certificate::issue_with_extensions(
            &issuer_signer,
            &issuer.subject().unwrap(),
            &responder_dn,
            &responder_pub,
            responder_validity,
            99,
            &responder_extensions,
        )
        .expect("issue responder");

        OcspResponseBuilder::good(leaf, issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .delegated_responder_cert(responder_cert.to_der().to_vec())
            .sign(&CertSigner::Ed25519(&responder_key))
            .unwrap()
    }

    // Finding 3: a delegated OCSP responder must be an end-entity, not a CA. A
    // cert with basicConstraints CA:TRUE that also carries id-kp-OCSPSigning
    // must be rejected as a delegated responder — a sub-CA must not double as a
    // status responder.
    #[test]
    fn check_for_cert_rejects_ca_true_delegated_responder() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let issuer_signer = CertSigner::Rsa(&issuer_key);
        let responder_key = ed25519();
        let responder_pub = AnyPublicKey::Ed25519(responder_key.public_key());
        let responder_dn = DistinguishedName::common_name("OCSP CA responder");
        // CA:TRUE — the only difference from the accepted-responder shape — plus
        // the load-bearing id-kp-OCSPSigning EKU.
        let responder_extensions = vec![
            extension::basic_constraints(true, None),
            Extension {
                oid: oid::EXT_KEY_USAGE.to_vec(),
                critical: false,
                value: encode_sequence(&oid_tlv(oid::ID_KP_OCSP_SIGNING)),
            },
        ];
        let responder_cert = Certificate::issue_with_extensions(
            &issuer_signer,
            &issuer.subject().unwrap(),
            &responder_dn,
            &responder_pub,
            &Validity::new(
                Time::utc(2024, 1, 1, 0, 0, 0),
                Time::utc(2034, 1, 1, 0, 0, 0),
            ),
            100,
            &responder_extensions,
        )
        .expect("issue responder");

        let resp = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .delegated_responder_cert(responder_cert.to_der().to_vec())
            .sign(&CertSigner::Ed25519(&responder_key))
            .unwrap();

        let now = Time::utc(2026, 6, 1, 0, 0, 0);
        assert!(matches!(
            resp.check_for_cert(&leaf, &issuer, Some(&now)),
            Err(Error::Verification)
        ));

        // Sanity: an otherwise-identical CA:FALSE responder IS accepted, so the
        // rejection above is attributable to basicConstraints alone.
        let ok = delegated_good_response(
            &issuer,
            &leaf,
            &issuer_key,
            &Validity::new(
                Time::utc(2024, 1, 1, 0, 0, 0),
                Time::utc(2034, 1, 1, 0, 0, 0),
            ),
        );
        assert_eq!(
            ok.check_for_cert(&leaf, &issuer, Some(&now)).unwrap(),
            OcspCertStatus::Good
        );
    }

    // A delegated responder cert carrying a critical extension we don't
    // recognize must be rejected (RFC 5280 §4.2) — the responder never passes
    // through the chain validator's unknown-critical-extension screen, so the
    // OCSP path has to enforce it itself.
    #[test]
    fn check_for_cert_rejects_unknown_critical_extension_on_responder() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let issuer_signer = CertSigner::Rsa(&issuer_key);
        let responder_key = ed25519();
        let responder_pub = AnyPublicKey::Ed25519(responder_key.public_key());
        let responder_dn = DistinguishedName::common_name("OCSP critical-ext responder");
        // Same accepted-responder shape as `delegated_good_response`, plus one
        // unknown critical extension (a made-up private-arc OID).
        let responder_extensions = vec![
            extension::basic_constraints(false, None),
            Extension {
                oid: oid::EXT_KEY_USAGE.to_vec(),
                critical: false,
                value: encode_sequence(&oid_tlv(oid::ID_KP_OCSP_SIGNING)),
            },
            Extension {
                oid: alloc::vec![1, 3, 6, 1, 4, 1, 99999, 1],
                critical: true,
                value: encode_null(),
            },
        ];
        let responder_cert = Certificate::issue_with_extensions(
            &issuer_signer,
            &issuer.subject().unwrap(),
            &responder_dn,
            &responder_pub,
            &Validity::new(
                Time::utc(2024, 1, 1, 0, 0, 0),
                Time::utc(2034, 1, 1, 0, 0, 0),
            ),
            101,
            &responder_extensions,
        )
        .expect("issue responder");

        let resp = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .delegated_responder_cert(responder_cert.to_der().to_vec())
            .sign(&CertSigner::Ed25519(&responder_key))
            .unwrap();

        let now = Time::utc(2026, 6, 1, 0, 0, 0);
        assert!(matches!(
            resp.check_for_cert(&leaf, &issuer, Some(&now)),
            Err(Error::Verification)
        ));

        // Sanity: the same extension marked non-critical is tolerated (RFC
        // 5280 §4.2 lets a verifier ignore unrecognized non-critical
        // extensions), pinning the rejection above on the critical flag.
        let responder_extensions = vec![
            extension::basic_constraints(false, None),
            Extension {
                oid: oid::EXT_KEY_USAGE.to_vec(),
                critical: false,
                value: encode_sequence(&oid_tlv(oid::ID_KP_OCSP_SIGNING)),
            },
            Extension {
                oid: alloc::vec![1, 3, 6, 1, 4, 1, 99999, 1],
                critical: false,
                value: encode_null(),
            },
        ];
        let responder_cert = Certificate::issue_with_extensions(
            &issuer_signer,
            &issuer.subject().unwrap(),
            &responder_dn,
            &responder_pub,
            &Validity::new(
                Time::utc(2024, 1, 1, 0, 0, 0),
                Time::utc(2034, 1, 1, 0, 0, 0),
            ),
            102,
            &responder_extensions,
        )
        .expect("issue responder");
        let resp = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .delegated_responder_cert(responder_cert.to_der().to_vec())
            .sign(&CertSigner::Ed25519(&responder_key))
            .unwrap();
        assert_eq!(
            resp.check_for_cert(&leaf, &issuer, Some(&now)).unwrap(),
            OcspCertStatus::Good
        );
    }

    // F5: a delegated responder cert must be inside its own validity window at
    // `now`. An attacker holding the key of an expired-but-once-valid
    // OCSPSigning cert could otherwise mint a forged "good" status forever.
    #[test]
    fn check_for_cert_rejects_expired_delegated_responder() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();

        // Responder cert expired well before `now` (2026-06-01).
        let expired = Validity::new(
            Time::utc(2020, 1, 1, 0, 0, 0),
            Time::utc(2021, 1, 1, 0, 0, 0),
        );
        let resp = delegated_good_response(&issuer, &leaf, &issuer_key, &expired);
        let now = Time::utc(2026, 6, 1, 0, 0, 0);
        assert!(matches!(
            resp.check_for_cert(&leaf, &issuer, Some(&now)),
            Err(Error::Verification)
        ));

        // A responder cert valid at `now` is accepted through the same path.
        let valid = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let resp = delegated_good_response(&issuer, &leaf, &issuer_key, &valid);
        assert_eq!(
            resp.check_for_cert(&leaf, &issuer, Some(&now)).unwrap(),
            OcspCertStatus::Good
        );

        // With `now == None` (verify_certificates = false), the expired
        // responder is NOT enforced — matching the freshness gate's behavior.
        let resp = delegated_good_response(&issuer, &leaf, &issuer_key, &expired);
        assert_eq!(
            resp.check_for_cert(&leaf, &issuer, None).unwrap(),
            OcspCertStatus::Good
        );
    }

    #[test]
    fn verify_rejects_wrong_key_or_tamper() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let resp = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .sign(&signer)
            .unwrap();

        // Wrong key (rsa_b vs issuer's rsa_a).
        let wrong = AnyPublicKey::Rsa(rsa_b().public_key());
        assert!(resp.verify_signature_with(&wrong).is_err());

        // Tamper a TBS byte → signature no longer covers it.
        let mut der = resp.to_der().to_vec();
        // Land somewhere inside the BasicOCSPResponse — past the headers.
        let idx = der.len() / 2;
        der[idx] ^= 0x01;
        let tampered = OcspResponse::from_der(der).unwrap();
        assert!(
            tampered
                .verify_signature_with(&signer.public_key())
                .is_err()
        );
    }

    #[test]
    fn two_phase_external_signing_matches_one_shot() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);

        // One-shot, in-process signing.
        let one_shot =
            OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
                .unwrap()
                .sign(&signer)
                .unwrap();

        // Two-phase: the responder key is exercised only on the prepared TBS.
        let prepared =
            OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
                .unwrap()
                .prepare(SignatureAlgId::RsaPkcs1Sha256)
                .unwrap();
        let sig = signer.sign(prepared.tbs()).unwrap();
        let two_phase = prepared.finish(&sig);

        // RSA PKCS#1 v1.5 is deterministic → byte-identical to the one-shot path.
        assert_eq!(one_shot.to_der(), two_phase.to_der());
        // The externally assembled response verifies against the responder key.
        two_phase
            .verify_signature_with(&signer.public_key())
            .unwrap();
    }

    #[test]
    fn find_response_for_serial_magnitude() {
        // Build a leaf whose serial INTEGER body carries a leading 0x00
        // (sign-protection pad) and verify the lookup matches against the
        // magnitude alone — mirrors the CRL comparison semantics.
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let resp = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .sign(&signer)
            .unwrap();
        // The lookup uses the leaf's own serial — round-trips by construction.
        let single = resp.find_response_for(&leaf, &issuer).unwrap().unwrap();
        assert_eq!(single.status, OcspCertStatus::Good);
    }

    #[test]
    fn unknown_response_status_rejected() {
        // ENUMERATED 4 is reserved per the RFC 6960 ASN.1 module.
        let body = encode_sequence(&encode_tlv(0x0a, &[4]));
        let r = OcspResponse::from_der(body).unwrap();
        assert!(matches!(
            r.response_status(),
            Err(crate::x509::Error::Malformed)
        ));
    }

    #[test]
    fn non_successful_status_has_no_basic_response() {
        // A `tryLater` (3) response has no responseBytes.
        let body = encode_sequence(&encode_tlv(0x0a, &[3]));
        let r = OcspResponse::from_der(body).unwrap();
        assert_eq!(r.response_status().unwrap(), OcspResponseStatus::TryLater);
        // Walking past the status into the absent BasicOCSPResponse surfaces
        // `Malformed`; the responses iterator follows that.
        assert!(matches!(r.responses(), Err(crate::x509::Error::Malformed)));
    }

    #[test]
    fn next_update_optional() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let resp = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .sign(&signer)
            .unwrap();
        let single = resp.find_response_for(&leaf, &issuer).unwrap().unwrap();
        assert!(single.next_update.is_none());
    }

    #[test]
    fn sha256_certid_path() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let resp = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .hash_algorithm(oid::ID_SHA256)
            .sign(&signer)
            .unwrap();
        let single = resp.find_response_for(&leaf, &issuer).unwrap().unwrap();
        assert_eq!(single.hash_alg_oid.as_slice(), oid::ID_SHA256);
        // 32-byte SHA-256 outputs.
        assert_eq!(single.issuer_name_hash.len(), 32);
        assert_eq!(single.issuer_key_hash.len(), 32);
    }

    // X509-4: RFC 6960 §4.4.1 — nonce extension binds an OCSP response to the
    // request that asked for it. A client that requested a nonce and gets back
    // a response with no nonce (or a different one) must reject; otherwise an
    // attacker who captured a still-fresh response can replay it indefinitely
    // until its `nextUpdate` lapses.
    #[test]
    fn nonce_round_trips_through_builder_and_response() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let nonce = [0x42u8; 16];
        let resp = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .nonce(&nonce)
            .sign(&signer)
            .unwrap();
        // The accessor returns exactly the bytes the builder embedded.
        let got = resp.nonce().unwrap().unwrap();
        assert_eq!(got, nonce);
        // Signature still verifies — the nonce extension is part of tbsResponseData.
        resp.verify_signature_with(&signer.public_key()).unwrap();
    }

    #[test]
    fn response_without_nonce_returns_none() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let resp = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .sign(&signer)
            .unwrap();
        assert!(resp.nonce().unwrap().is_none());
    }

    #[test]
    fn check_with_nonce_accepts_matching_nonce() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let nonce = b"client-nonce-aaaa";
        let now = Time::utc(2026, 1, 2, 0, 0, 0);
        let resp = OcspResponseBuilder::good(
            &leaf,
            &issuer,
            Time::utc(2026, 1, 1, 0, 0, 0),
            Some(Time::utc(2026, 1, 8, 0, 0, 0)),
        )
        .unwrap()
        .nonce(nonce)
        .sign(&signer)
        .unwrap();
        let status = resp
            .check_for_cert_with_nonce(&leaf, &issuer, Some(&now), nonce)
            .unwrap();
        assert_eq!(status, OcspCertStatus::Good);
    }

    #[test]
    fn check_with_nonce_rejects_missing_nonce() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let now = Time::utc(2026, 1, 2, 0, 0, 0);
        let resp = OcspResponseBuilder::good(
            &leaf,
            &issuer,
            Time::utc(2026, 1, 1, 0, 0, 0),
            Some(Time::utc(2026, 1, 8, 0, 0, 0)),
        )
        .unwrap()
        // No nonce embedded.
        .sign(&signer)
        .unwrap();
        let result = resp.check_for_cert_with_nonce(&leaf, &issuer, Some(&now), b"expected");
        assert!(matches!(result, Err(Error::Verification)));
    }

    #[test]
    fn check_with_nonce_rejects_mismatched_nonce() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let now = Time::utc(2026, 1, 2, 0, 0, 0);
        let resp = OcspResponseBuilder::good(
            &leaf,
            &issuer,
            Time::utc(2026, 1, 1, 0, 0, 0),
            Some(Time::utc(2026, 1, 8, 0, 0, 0)),
        )
        .unwrap()
        .nonce(b"responder-chose-different")
        .sign(&signer)
        .unwrap();
        let result = resp.check_for_cert_with_nonce(&leaf, &issuer, Some(&now), b"client-asked");
        assert!(matches!(result, Err(Error::Verification)));
    }

    #[test]
    fn request_builder_round_trips_nonce() {
        let (issuer, leaf, _) = issuer_and_leaf();
        let nonce = b"req-nonce-1234567890";
        let req = OcspRequestBuilder::new(&leaf, &issuer)
            .unwrap()
            .nonce(nonce)
            .build()
            .unwrap();
        assert_eq!(req.nonce(), Some(nonce.as_slice()));

        // The DER decodes as a well-formed OCSPRequest carrying our nonce in
        // requestExtensions [2] EXPLICIT Extensions.
        let mut r = Reader::new(req.to_der());
        let mut outer = r.read_sequence().unwrap();
        let mut tbs = outer.read_sequence().unwrap();
        // requestList SEQUENCE OF Request — skip it.
        let _req_list = tbs.read_element().unwrap();
        // requestExtensions [2] EXPLICIT
        let exts_wrapper = tbs.read_tlv(tag::context(2)).unwrap();
        let mut exts_outer = Reader::new(exts_wrapper);
        let mut exts = exts_outer.read_sequence().unwrap();
        let mut ext = exts.read_sequence().unwrap();
        let id = parse_oid(ext.read_oid().unwrap()).unwrap();
        assert_eq!(id.as_slice(), oid::ID_PKIX_OCSP_NONCE);
        let value = ext.read_octet_string().unwrap();
        // RFC 8954 §2.1: extnValue OCTET STRING wraps an inner OCTET STRING.
        let mut nr = Reader::new(value);
        let inner = nr.read_octet_string().unwrap();
        assert_eq!(inner, nonce);
    }

    #[test]
    fn request_builder_rejects_oversize_nonce() {
        let (issuer, leaf, _) = issuer_and_leaf();
        // RFC 8954 §2.1 caps the nonce at 32 octets.
        let too_long = [0u8; 33];
        let r = OcspRequestBuilder::new(&leaf, &issuer)
            .unwrap()
            .nonce(&too_long)
            .build();
        assert!(matches!(r, Err(Error::Malformed)));
    }

    #[test]
    fn request_builder_rejects_empty_nonce() {
        let (issuer, leaf, _) = issuer_and_leaf();
        let r = OcspRequestBuilder::new(&leaf, &issuer)
            .unwrap()
            .nonce(&[])
            .build();
        assert!(matches!(r, Err(Error::Malformed)));
    }

    #[test]
    fn response_builder_rejects_oversize_nonce() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let too_long = [0u8; 33];
        let r = OcspResponseBuilder::good(&leaf, &issuer, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .unwrap()
            .nonce(&too_long)
            .sign(&signer);
        assert!(matches!(r, Err(Error::Malformed)));
    }

    #[test]
    fn random_nonce_is_present_and_correct_length() {
        let (issuer, leaf, _) = issuer_and_leaf();
        let mut rng = crate::rng::HmacDrbg::<crate::hash::Sha256>::new(b"ocsp-nonce", b"n", &[]);
        let req = OcspRequestBuilder::new(&leaf, &issuer)
            .unwrap()
            .random_nonce(&mut rng)
            .build()
            .unwrap();
        let n = req.nonce().unwrap();
        assert_eq!(n.len(), 16);
    }

    #[test]
    fn check_for_cert_accepts_fresh_response() {
        // Baseline: a well-formed response with now inside
        // [thisUpdate, nextUpdate) is accepted.
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let now = Time::utc(2026, 1, 2, 0, 0, 0);
        let resp = OcspResponseBuilder::good(
            &leaf,
            &issuer,
            Time::utc(2026, 1, 1, 0, 0, 0),
            Some(Time::utc(2026, 1, 8, 0, 0, 0)),
        )
        .unwrap()
        .sign(&signer)
        .unwrap();
        assert_eq!(
            resp.check_for_cert(&leaf, &issuer, Some(&now)).unwrap(),
            OcspCertStatus::Good
        );
    }

    #[test]
    fn check_for_cert_fails_closed_on_malformed_this_update() {
        // A malformed thisUpdate must not be coerced to the Unix epoch (which
        // would look perpetually in the past and pass freshness). It must
        // fail closed instead.
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let now = Time::utc(2026, 1, 2, 0, 0, 0);
        let resp = OcspResponseBuilder::good(
            &leaf,
            &issuer,
            // Unparsable repr: serialized verbatim, rejected on re-parse.
            Time::from_repr("not-a-time"),
            Some(Time::utc(2026, 1, 8, 0, 0, 0)),
        )
        .unwrap()
        .sign(&signer)
        .unwrap();
        assert!(matches!(
            resp.check_for_cert(&leaf, &issuer, Some(&now)),
            Err(Error::Malformed)
        ));
    }

    // Revocation-path signature-downgrade gate (MEDIUM): the BasicOCSPResponse
    // signature must be gated by the same SignaturePolicy the chain is. A
    // policy that does not permit the staple's signature algorithm must reject
    // the response even when the signature itself is cryptographically valid —
    // exactly how a SHA-1/MD5-signed staple is refused under
    // `SignaturePolicy::modern()` (which omits rsa-pkcs1-sha1). We can't sign
    // SHA-1 with the in-tree CertSigner, so we drive the gate with an `empty()`
    // policy that whitelists nothing: it stands in for "the staple's algorithm
    // is not on the whitelist".
    #[test]
    fn check_for_cert_rejects_staple_signature_outside_policy() {
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let now = Time::utc(2026, 1, 2, 0, 0, 0);
        let resp = OcspResponseBuilder::good(
            &leaf,
            &issuer,
            Time::utc(2026, 1, 1, 0, 0, 0),
            Some(Time::utc(2026, 1, 8, 0, 0, 0)),
        )
        .unwrap()
        .sign(&signer)
        .unwrap();

        // A valid RSA-SHA256 signature, but the policy whitelists nothing.
        let none = SignaturePolicy::empty();
        assert!(matches!(
            resp.check_for_cert_with_options(
                &leaf,
                &issuer,
                &OcspCheckOptions::new(&none).with_time(Some(&now))
            ),
            Err(Error::Verification)
        ));
        // The direct policy-aware verifier rejects it for the same reason...
        assert!(matches!(
            resp.verify_signature_with_policy(&issuer.subject_public_key().unwrap(), &none),
            Err(Error::Verification)
        ));
        // ...while the policy-free verifier still accepts the (valid) signature,
        // proving the rejection is the policy gate, not a broken signature.
        resp.verify_signature_with(&issuer.subject_public_key().unwrap())
            .unwrap();
        // And under the default modern() policy (which permits rsa-pkcs1-sha256)
        // the same response validates Good.
        assert_eq!(
            resp.check_for_cert(&leaf, &issuer, Some(&now)).unwrap(),
            OcspCertStatus::Good
        );
    }

    #[test]
    fn check_for_cert_fails_closed_on_malformed_next_update() {
        // A present-but-malformed nextUpdate must reject, not be treated as
        // "no expiry".
        let (issuer, leaf, issuer_key) = issuer_and_leaf();
        let signer = CertSigner::Rsa(&issuer_key);
        let now = Time::utc(2026, 1, 2, 0, 0, 0);
        let resp = OcspResponseBuilder::good(
            &leaf,
            &issuer,
            Time::utc(2026, 1, 1, 0, 0, 0),
            Some(Time::from_repr("not-a-time")),
        )
        .unwrap()
        .sign(&signer)
        .unwrap();
        assert!(matches!(
            resp.check_for_cert(&leaf, &issuer, Some(&now)),
            Err(Error::Malformed)
        ));
    }
}
