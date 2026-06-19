//! RFC 6962 Certificate Transparency: Signed Certificate Timestamp (SCT)
//! parsing and signature verification.
//!
//! Certificate Transparency (RFC 6962) makes CA misissuance publicly
//! detectable by requiring certificates to be logged in append-only,
//! cryptographically-verifiable logs. A log returns a **Signed Certificate
//! Timestamp** (SCT) — a signed promise to incorporate the (pre)certificate
//! within a bounded delay. A relying party that trusts a set of logs can
//! demand a quorum of valid SCTs before accepting a certificate.
//!
//! This module provides:
//!   * [`parse_sct_list`] — decode a TLS-serialized `SignedCertificateTimestamp
//!     List` (RFC 6962 §3.3), as carried in the cert's embedded-SCT extension
//!     (OID 1.3.6.1.4.1.11129.2.4.2), in a TLS `signed_certificate_timestamp`
//!     extension, or in an OCSP response.
//!   * [`Sct`] — one parsed SCT (version, log id, timestamp, extensions,
//!     and the TLS `digitally-signed` blob).
//!   * [`CtLog`] — a trusted log: its `LogID` (SHA-256 of the log's SPKI) and
//!     the SPKI DER itself (used to verify SCT signatures).
//!   * [`verify_embedded_scts`] — verify the embedded SCTs of a certificate against a
//!     set of trusted logs at a given time, returning per-SCT validity and a
//!     count of valid SCTs. The trust policy ("≥ N distinct logs") is the
//!     caller's decision.
//!
//! **Opt-in.** Nothing here runs in the default certificate-validation path;
//! a caller must explicitly invoke it.
//!
//! Signed data reconstruction (the subtle part) is handled per RFC 6962 §3.2
//! by [`Sct::signed_data_for_precert`] / [`Sct::signed_data_for_x509`]; see
//! those for the byte layout.

use alloc::vec::Vec;

use super::{Certificate, Error, oid};
use crate::der::Reader;
use crate::hash::{Digest, Sha256};

/// SCT protocol version. RFC 6962 defines only `v1` (0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SctVersion {
    /// `v1` (the only version RFC 6962 defines).
    V1,
}

/// One parsed Signed Certificate Timestamp (RFC 6962 §3.2). The
/// `digitally-signed` blob is kept in its TLS-serialized parts so verification
/// can reconstruct the exact bytes the log signed.
#[derive(Clone, Debug)]
pub struct Sct {
    /// Protocol version.
    pub version: SctVersion,
    /// `LogID`: the SHA-256 of the issuing log's `SubjectPublicKeyInfo`.
    pub log_id: [u8; 32],
    /// `timestamp`: milliseconds since the Unix epoch (RFC 6962 §3.2).
    pub timestamp: u64,
    /// `CtExtensions`: opaque, echoed verbatim into the signed structure.
    pub extensions: Vec<u8>,
    /// TLS `SignatureAndHashAlgorithm.hash` (RFC 5246 §7.4.1.4.1).
    pub sig_hash: u8,
    /// TLS `SignatureAndHashAlgorithm.signature`.
    pub sig_alg: u8,
    /// The raw signature bytes (for ECDSA, a DER `Ecdsa-Sig-Value`; for RSA,
    /// the PKCS#1 v1.5 signature octets).
    pub signature: Vec<u8>,
}

/// A trusted Certificate-Transparency log, as supplied by the relying party.
#[derive(Clone, Debug)]
pub struct CtLog {
    /// `LogID`: SHA-256 of `spki_der`. An SCT names its issuing log by this
    /// 32-byte id.
    pub log_id: [u8; 32],
    /// The log's `SubjectPublicKeyInfo` (DER) — used to verify SCT signatures.
    pub spki_der: Vec<u8>,
}

impl CtLog {
    /// Builds a [`CtLog`] from the log's SPKI DER, computing the `LogID` as
    /// `SHA-256(spki_der)` (RFC 6962 §3.2).
    pub fn from_spki_der(spki_der: &[u8]) -> CtLog {
        let log_id = Sha256::digest(spki_der);
        CtLog {
            log_id,
            spki_der: spki_der.to_vec(),
        }
    }
}

/// The result of verifying one SCT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SctVerification {
    /// The SCT verified against a trusted log.
    Valid,
    /// No trusted log matched the SCT's `LogID`.
    UnknownLog,
    /// A trusted log matched but the signature did not verify (or used an
    /// algorithm we don't support).
    BadSignature,
    /// The SCT's `timestamp` is in the future relative to the supplied
    /// verification time (a log must not issue an SCT dated after the moment
    /// it was created; a future timestamp is rejected, RFC 6962 §5.2).
    FutureTimestamp,
}

/// A small cursor over a TLS-style big-endian length-prefixed byte stream.
struct TlsReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> TlsReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        TlsReader { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.remaining() < n {
            return Err(Error::Malformed);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(((b[0] as u16) << 8) | b[1] as u16)
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        let mut v = 0u64;
        for &x in b {
            v = (v << 8) | x as u64;
        }
        Ok(v)
    }

    /// Reads a `<.. ; len-prefix = 2 bytes>` opaque vector.
    fn opaque_u16(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// Parses a TLS-serialized `SignedCertificateTimestampList` (RFC 6962 §3.3).
///
/// `body` is the inner bytes of the list (the value after any DER `OCTET
/// STRING` wrapper has been stripped — see [`sct_list_from_extension`] for the
/// embedded-cert case). The list is `opaque SerializedSCT<1..2^16-1>` repeated
/// under a single 2-byte total-length prefix.
pub fn parse_sct_list(body: &[u8]) -> Result<Vec<Sct>, Error> {
    let mut r = TlsReader::new(body);
    let total = r.u16()? as usize;
    if r.remaining() != total {
        // The declared list length must consume the whole body exactly.
        return Err(Error::Malformed);
    }
    let mut out = Vec::new();
    while !r.is_empty() {
        let one = r.opaque_u16()?;
        out.push(parse_one_sct(one)?);
    }
    Ok(out)
}

/// Strips the DER `OCTET STRING` wrapper from an embedded-SCT extension value
/// and parses the inner `SignedCertificateTimestampList`. The
/// `SignedCertificateTimestampList` extension's `extnValue` is itself a DER
/// `OCTET STRING` whose content is the TLS-serialized list (RFC 6962 §3.3).
pub fn sct_list_from_extension(ext_value: &[u8]) -> Result<Vec<Sct>, Error> {
    let mut r = Reader::new(ext_value);
    let inner = r.read_octet_string()?;
    r.finish()?;
    parse_sct_list(inner)
}

/// Parses one `SignedCertificateTimestamp` (RFC 6962 §3.2).
fn parse_one_sct(bytes: &[u8]) -> Result<Sct, Error> {
    let mut r = TlsReader::new(bytes);
    let version = match r.u8()? {
        0 => SctVersion::V1,
        _ => return Err(Error::UnsupportedAlgorithm),
    };
    let log_id: [u8; 32] = r.take(32)?.try_into().map_err(|_| Error::Malformed)?;
    let timestamp = r.u64()?;
    let extensions = r.opaque_u16()?.to_vec();
    // digitally-signed: SignatureAndHashAlgorithm { hash, signature } then
    // opaque signature<0..2^16-1>.
    let sig_hash = r.u8()?;
    let sig_alg = r.u8()?;
    let signature = r.opaque_u16()?.to_vec();
    // RFC 6962 §3.2: nothing follows the signature inside one SerializedSCT.
    if !r.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(Sct {
        version,
        log_id,
        timestamp,
        extensions,
        sig_hash,
        sig_alg,
        signature,
    })
}

impl Sct {
    /// Reconstructs the bytes a log signs for an **embedded** (precertificate)
    /// SCT (RFC 6962 §3.2), given the issuer's `SubjectPublicKeyInfo` DER and
    /// the precert's reconstructed `TBSCertificate` (poison + SCT-list
    /// extensions removed). Layout:
    ///
    /// ```text
    /// digitally-signed struct {
    ///   u8   version              = 0 (v1)
    ///   u8   signature_type       = 0 (certificate_timestamp)
    ///   u64  timestamp
    ///   u16  entry_type           = 1 (precert_entry)
    ///   opaque issuer_key_hash[32]                  // SHA-256(issuer SPKI)
    ///   opaque tbs_certificate<1..2^24-1>           // reconstructed TBS
    ///   opaque ct_extensions<0..2^16-1>             // echo of self.extensions
    /// }
    /// ```
    pub fn signed_data_for_precert(&self, issuer_spki_der: &[u8], tbs_der: &[u8]) -> Vec<u8> {
        let issuer_key_hash = Sha256::digest(issuer_spki_der);
        let mut out = Vec::with_capacity(64 + tbs_der.len());
        out.push(0); // version v1
        out.push(0); // signature_type = certificate_timestamp
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&[0x00, 0x01]); // entry_type = precert_entry (1)
        out.extend_from_slice(&issuer_key_hash);
        push_u24_vec(&mut out, tbs_der);
        push_u16_vec(&mut out, &self.extensions);
        out
    }

    /// Reconstructs the bytes a log signs for an **X.509-cert** SCT (the
    /// `x509_entry` case of RFC 6962 §3.2), delivered via the TLS extension or
    /// OCSP rather than embedded. `cert_der` is the full leaf certificate DER.
    ///
    /// ```text
    /// digitally-signed struct {
    ///   u8   version        = 0
    ///   u8   signature_type = 0
    ///   u64  timestamp
    ///   u16  entry_type     = 0 (x509_entry)
    ///   opaque certificate<1..2^24-1>     // full ASN.1Cert DER
    ///   opaque ct_extensions<0..2^16-1>
    /// }
    /// ```
    pub fn signed_data_for_x509(&self, cert_der: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + cert_der.len());
        out.push(0);
        out.push(0);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00]); // entry_type = x509_entry (0)
        push_u24_vec(&mut out, cert_der);
        push_u16_vec(&mut out, &self.extensions);
        out
    }

    /// Verifies this SCT's signature over `signed_data` against `log`'s public
    /// key, mapping the TLS `SignatureAndHashAlgorithm` to the corresponding
    /// X.509 signature-algorithm OID.
    ///
    /// RFC 6962 §2.1.4 / §3.2 specify ECDSA-P256-with-SHA256 and
    /// RSA-PKCS#1-v1.5-with-SHA256 (≥ 2048-bit). Both use SHA-256, the only
    /// `hash` value (4) we accept.
    fn verify_signature(&self, log: &CtLog, signed_data: &[u8]) -> bool {
        // TLS HashAlgorithm.sha256 = 4 (RFC 5246 §7.4.1.4.1).
        if self.sig_hash != 4 {
            return false;
        }
        // TLS SignatureAlgorithm: rsa = 1, ecdsa = 3.
        let sig_alg_oid: &[u64] = match self.sig_alg {
            1 => oid::SHA256_WITH_RSA,
            3 => oid::ECDSA_WITH_SHA256,
            _ => return false,
        };
        let Ok(key) = super::AnyPublicKey::from_spki_der(&log.spki_der) else {
            return false;
        };
        key.verify(sig_alg_oid, signed_data, &self.signature)
            .is_ok()
    }
}

impl Sct {
    /// Serializes this SCT to its `SerializedSCT` wire form (RFC 6962 §3.2):
    /// `version ‖ log_id ‖ timestamp ‖ ext-len ‖ ext ‖ hash ‖ sig ‖ sig-len ‖
    /// sig`. The inverse of the per-SCT parser; used to assemble a
    /// `SignedCertificateTimestampList` and in round-trip tests.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(match self.version {
            SctVersion::V1 => 0,
        });
        out.extend_from_slice(&self.log_id);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        push_u16_vec(&mut out, &self.extensions);
        out.push(self.sig_hash);
        out.push(self.sig_alg);
        push_u16_vec(&mut out, &self.signature);
        out
    }
}

/// Serializes a list of SCTs into a `SignedCertificateTimestampList` (RFC 6962
/// §3.3): a 2-byte total length over the concatenation of each SCT framed by
/// its own 2-byte length prefix. The inverse of [`parse_sct_list`].
pub fn serialize_sct_list(scts: &[Sct]) -> Vec<u8> {
    let mut inner = Vec::new();
    for s in scts {
        push_u16_vec(&mut inner, &s.to_bytes());
    }
    let mut out = Vec::new();
    push_u16_vec(&mut out, &inner);
    out
}

/// Appends `data` to `out` with a 3-byte big-endian length prefix
/// (`opaque<1..2^24-1>`).
fn push_u24_vec(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    out.push((n >> 16) as u8);
    out.push((n >> 8) as u8);
    out.push(n as u8);
    out.extend_from_slice(data);
}

/// Appends `data` to `out` with a 2-byte big-endian length prefix.
fn push_u16_vec(out: &mut Vec<u8>, data: &[u8]) {
    out.push((data.len() >> 8) as u8);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

/// Reconstructs a precertificate's `TBSCertificate` per RFC 6962 §3.2: the
/// leaf's TBS with both the CT poison extension (1.3.6.1.4.1.11129.2.4.3) and
/// the embedded-SCT-list extension (1.3.6.1.4.1.11129.2.4.2) removed.
///
/// This is what the log signed: when a CA submits a precertificate (carrying
/// the poison), the log signs the precert's TBS *minus the poison*. The final
/// certificate then carries the SCT list in place of the poison, so to verify
/// the embedded SCT we must reproduce the signed TBS by stripping BOTH
/// extensions from the issued cert's TBS and re-encoding.
///
/// Returns the re-encoded `TBSCertificate` DER.
pub fn reconstruct_precert_tbs(cert: &Certificate) -> Result<Vec<u8>, Error> {
    let tbs = cert.tbs_der()?;
    rebuild_tbs_without(tbs, &[oid::CT_POISON, oid::SCT_LIST])
}

/// Re-encodes a `TBSCertificate` with every extension whose OID is in
/// `remove_oids` deleted. The `extensions [3]` wrapper and inner `SEQUENCE`
/// are rebuilt; if no extensions remain, the `[3]` field is omitted entirely
/// (RFC 5280 §4.1.2.9 — an empty extensions SEQUENCE is not allowed, and a
/// precert always has at least the poison so post-removal emptiness is
/// possible only for degenerate inputs).
fn rebuild_tbs_without(tbs_der: &[u8], remove_oids: &[&[u64]]) -> Result<Vec<u8>, Error> {
    use crate::der::{encode_context, encode_sequence, parse_oid, tag};

    let mut outer = Reader::new(tbs_der);
    let mut seq = outer.read_sequence()?;
    outer.finish()?;

    // Collect the leading fields verbatim (everything up to, but not
    // including, the [3] extensions wrapper): version[0]?, serial, sigalg,
    // issuer, validity, subject, spki, then optional issuer/subject unique IDs.
    let mut prefix: Vec<u8> = Vec::new();
    if seq.peek_tag() == Some(tag::context(0)) {
        prefix.extend_from_slice(seq.read_element()?); // version
    }
    prefix.extend_from_slice(seq.read_element()?); // serialNumber
    prefix.extend_from_slice(seq.read_element()?); // signature algid
    prefix.extend_from_slice(seq.read_element()?); // issuer
    prefix.extend_from_slice(seq.read_element()?); // validity
    prefix.extend_from_slice(seq.read_element()?); // subject
    prefix.extend_from_slice(seq.read_element()?); // SPKI
    while matches!(seq.peek_tag(), Some(0x81) | Some(0x82)) {
        prefix.extend_from_slice(seq.read_element()?); // unique IDs
    }

    // The [3] EXPLICIT extensions wrapper.
    let exts_wrapper = match seq.peek_tag() {
        Some(t) if t == tag::context(3) => seq.read_tlv(tag::context(3))?,
        // No extensions to filter — return the TBS unchanged.
        _ => {
            seq.finish()?;
            return Ok(tbs_der.to_vec());
        }
    };
    seq.finish()?;

    let mut ew = Reader::new(exts_wrapper);
    let mut exts = ew.read_sequence()?;
    ew.finish()?;

    let mut kept: Vec<u8> = Vec::new();
    while !exts.is_empty() {
        let ext_tlv = exts.read_element()?;
        // Peek the extension's OID without consuming the whole TLV body.
        let mut er = Reader::new(ext_tlv);
        let mut es = er.read_sequence()?;
        let id = parse_oid(es.read_oid()?)?;
        let remove = remove_oids.contains(&id.as_slice());
        if !remove {
            kept.extend_from_slice(ext_tlv);
        }
    }

    let mut rebuilt = prefix;
    if !kept.is_empty() {
        rebuilt.extend_from_slice(&encode_context(3, &encode_sequence(&kept)));
    }
    Ok(encode_sequence(&rebuilt))
}

/// Verifies the **embedded** SCTs of `cert` (the leaf) against `logs`, using
/// `issuer` to compute the precert `issuer_key_hash`. Returns a vector of
/// per-SCT [`SctVerification`] results in list order, plus the count of valid
/// SCTs.
///
/// `now_ms` is the verification time in milliseconds since the Unix epoch; an
/// SCT whose `timestamp` is after `now_ms` is reported [`SctVerification::
/// FutureTimestamp`] and not counted as valid. The relying party decides
/// whether the valid count meets its policy (e.g. ≥ 2 distinct logs).
///
/// Returns `Ok((vec![], 0))` when the certificate carries no embedded-SCT
/// extension.
pub fn verify_embedded_scts(
    cert: &Certificate,
    issuer: &Certificate,
    logs: &[CtLog],
    now_ms: u64,
) -> Result<(Vec<SctVerification>, usize), Error> {
    let Some(ext_value) = cert.sct_list_extension()? else {
        return Ok((Vec::new(), 0));
    };
    let scts = sct_list_from_extension(&ext_value)?;
    let issuer_spki = issuer.spki_der()?;
    let tbs = reconstruct_precert_tbs(cert)?;

    let mut results = Vec::with_capacity(scts.len());
    let mut valid = 0usize;
    for sct in &scts {
        let res = verify_one(sct, issuer_spki, &tbs, logs, now_ms);
        if res == SctVerification::Valid {
            valid += 1;
        }
        results.push(res);
    }
    Ok((results, valid))
}

/// Verifies a single embedded SCT and classifies the result.
fn verify_one(
    sct: &Sct,
    issuer_spki: &[u8],
    tbs: &[u8],
    logs: &[CtLog],
    now_ms: u64,
) -> SctVerification {
    if sct.timestamp > now_ms {
        return SctVerification::FutureTimestamp;
    }
    let Some(log) = logs.iter().find(|l| l.log_id == sct.log_id) else {
        return SctVerification::UnknownLog;
    };
    let signed = sct.signed_data_for_precert(issuer_spki, tbs);
    if sct.verify_signature(log, &signed) {
        SctVerification::Valid
    } else {
        SctVerification::BadSignature
    }
}

/// Verifies a standalone SCT (delivered via the TLS `signed_certificate_
/// timestamp` extension or an OCSP response, RFC 6962 §3.3) over the **full
/// leaf certificate** (the `x509_entry` form), against `logs` at `now_ms`.
///
/// Unlike [`verify_embedded_scts`] this needs no precert reconstruction — the
/// signed entry is the leaf's complete DER — so it is the fully-validated,
/// simplest CT verification path.
pub fn verify_standalone_sct(
    sct: &Sct,
    leaf_cert_der: &[u8],
    logs: &[CtLog],
    now_ms: u64,
) -> SctVerification {
    if sct.timestamp > now_ms {
        return SctVerification::FutureTimestamp;
    }
    let Some(log) = logs.iter().find(|l| l.log_id == sct.log_id) else {
        return SctVerification::UnknownLog;
    };
    let signed = sct.signed_data_for_x509(leaf_cert_der);
    if sct.verify_signature(log, &signed) {
        SctVerification::Valid
    } else {
        SctVerification::BadSignature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
    use crate::rng::HmacDrbg;
    use crate::test_util::rsa_test_key_a;
    use crate::x509::extension;
    use crate::x509::{
        AnyPublicKey, CertSigner, Certificate, DistinguishedName, GeneralName, Time, Validity,
    };
    use alloc::vec;

    fn validity() -> Validity {
        Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        )
    }

    /// A test CT log: an ECDSA P-256 key we control plus the matching [`CtLog`]
    /// (SPKI + LogID).
    struct TestLog {
        sk: BoxedEcdsaPrivateKey,
        log: CtLog,
    }

    fn make_test_log(seed: &[u8]) -> TestLog {
        let mut rng = HmacDrbg::<Sha256>::new(b"ct-log", seed, &[]);
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let spki = AnyPublicKey::Ecdsa(sk.public_key()).to_spki_der();
        let log = CtLog::from_spki_der(&spki);
        TestLog { sk, log }
    }

    /// Signs `signed_data` with the log key, producing an SCT carrying a real
    /// ECDSA-P256-SHA256 signature naming this log.
    fn sign_sct(log: &TestLog, timestamp: u64, signed_data: &[u8]) -> Sct {
        let sig = log.sk.sign::<Sha256>(signed_data).unwrap();
        Sct {
            version: SctVersion::V1,
            log_id: log.log.log_id,
            timestamp,
            extensions: Vec::new(),
            sig_hash: 4, // sha256
            sig_alg: 3,  // ecdsa
            signature: sig.to_der(CurveId::P256),
        }
    }

    /// Issues an RSA-signed issuer (CA) + a leaf (no SCT extension), returning
    /// `(issuer, leaf)`.
    fn issue_issuer_and_leaf() -> (Certificate, Certificate) {
        let ca_key = rsa_test_key_a();
        let ca_b = BoxedRsaPrivateKey::from_pkcs1_der(&ca_key.to_pkcs1_der()).unwrap();
        let ca_name = DistinguishedName::common_name("CT Issuer");
        let leaf_name = DistinguishedName::common_name("ct.example");
        let issuer = Certificate::self_signed(&ca_key, &ca_name, &validity(), 1, true).unwrap();
        let leaf = Certificate::issue_with_extensions(
            &CertSigner::Rsa(&ca_b),
            &ca_name,
            &leaf_name,
            &AnyPublicKey::Rsa(ca_b.public_key()),
            &validity(),
            2,
            &[
                extension::basic_constraints(false, None),
                extension::subject_alt_name(&[GeneralName::Dns("ct.example".into())]),
            ],
        )
        .unwrap();
        (issuer, leaf)
    }

    use crate::rsa::BoxedRsaPrivateKey;

    #[test]
    fn sct_list_round_trip() {
        let log = make_test_log(b"rt");
        let sct = sign_sct(&log, 1_700_000_000_000, b"data");
        let list = serialize_sct_list(core::slice::from_ref(&sct));
        let parsed = parse_sct_list(&list).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].log_id, sct.log_id);
        assert_eq!(parsed[0].timestamp, sct.timestamp);
        assert_eq!(parsed[0].signature, sct.signature);
        // And through the DER OCTET STRING extension wrapper.
        let ext = extension::sct_list(&list);
        let via_ext = sct_list_from_extension(&ext.value).unwrap();
        assert_eq!(via_ext.len(), 1);
        assert_eq!(via_ext[0].timestamp, sct.timestamp);
    }

    #[test]
    fn standalone_x509_sct_accepts_and_rejects() {
        let (_issuer, leaf) = issue_issuer_and_leaf();
        let leaf_der = leaf.to_der().to_vec();
        let log = make_test_log(b"x509");
        let ts = 1_700_000_000_000u64;
        let now = ts + 1000;

        // Build a valid x509-entry SCT over the full leaf cert.
        let proto = Sct {
            version: SctVersion::V1,
            log_id: log.log.log_id,
            timestamp: ts,
            extensions: Vec::new(),
            sig_hash: 4,
            sig_alg: 3,
            signature: Vec::new(),
        };
        let signed = proto.signed_data_for_x509(&leaf_der);
        let sct = sign_sct(&log, ts, &signed);

        // Accepts against the right log.
        assert_eq!(
            verify_standalone_sct(&sct, &leaf_der, core::slice::from_ref(&log.log), now),
            SctVerification::Valid
        );
        // Unknown log → UnknownLog.
        let other = make_test_log(b"other");
        assert_eq!(
            verify_standalone_sct(&sct, &leaf_der, core::slice::from_ref(&other.log), now),
            SctVerification::UnknownLog
        );
        // Tampered timestamp → signature no longer matches (BadSignature),
        // because the timestamp is part of the signed structure.
        let mut tampered = sct.clone();
        tampered.timestamp = ts + 5;
        assert_eq!(
            verify_standalone_sct(&tampered, &leaf_der, core::slice::from_ref(&log.log), now),
            SctVerification::BadSignature
        );
        // Tampered signature bytes → BadSignature.
        let mut badsig = sct.clone();
        let n = badsig.signature.len();
        badsig.signature[n - 1] ^= 0x01;
        assert_eq!(
            verify_standalone_sct(&badsig, &leaf_der, core::slice::from_ref(&log.log), now),
            SctVerification::BadSignature
        );
        // Future timestamp (now before the SCT) → FutureTimestamp.
        assert_eq!(
            verify_standalone_sct(&sct, &leaf_der, core::slice::from_ref(&log.log), ts - 1),
            SctVerification::FutureTimestamp
        );
    }

    #[test]
    fn embedded_precert_sct_accepts_and_rejects() {
        let (issuer, leaf) = issue_issuer_and_leaf();
        let issuer_spki = issuer.spki_der().unwrap().to_vec();
        // The reconstructed precert TBS is the leaf's TBS with poison + SCT
        // removed. The leaf has neither yet, so reconstruction returns its TBS.
        let tbs = reconstruct_precert_tbs(&leaf).unwrap();

        let log = make_test_log(b"embed");
        let ts = 1_700_000_000_000u64;
        let now = ts + 1000;

        // Sign over the precert entry.
        let proto = Sct {
            version: SctVersion::V1,
            log_id: log.log.log_id,
            timestamp: ts,
            extensions: Vec::new(),
            sig_hash: 4,
            sig_alg: 3,
            signature: Vec::new(),
        };
        let signed = proto.signed_data_for_precert(&issuer_spki, &tbs);
        let sct = sign_sct(&log, ts, &signed);

        // Re-issue the leaf WITH the embedded SCT extension. Reconstruction of
        // THIS cert removes the SCT extension, recovering the same `tbs`.
        let list = serialize_sct_list(core::slice::from_ref(&sct));
        let ca_key = rsa_test_key_a();
        let ca_b = BoxedRsaPrivateKey::from_pkcs1_der(&ca_key.to_pkcs1_der()).unwrap();
        let leaf_with_sct = Certificate::issue_with_extensions(
            &CertSigner::Rsa(&ca_b),
            &DistinguishedName::common_name("CT Issuer"),
            &DistinguishedName::common_name("ct.example"),
            &AnyPublicKey::Rsa(ca_b.public_key()),
            &validity(),
            2,
            &[
                extension::basic_constraints(false, None),
                extension::subject_alt_name(&[GeneralName::Dns("ct.example".into())]),
                extension::sct_list(&list),
            ],
        )
        .unwrap();

        // Sanity: reconstruction of the SCT-bearing cert equals the signed TBS.
        assert_eq!(reconstruct_precert_tbs(&leaf_with_sct).unwrap(), tbs);

        // Verify the embedded SCT.
        let (results, valid) = verify_embedded_scts(
            &leaf_with_sct,
            &issuer,
            core::slice::from_ref(&log.log),
            now,
        )
        .unwrap();
        assert_eq!(results, vec![SctVerification::Valid]);
        assert_eq!(valid, 1);

        // Wrong issuer (different SPKI) → issuer_key_hash differs → BadSignature.
        let wrong_issuer = {
            let k = crate::test_util::rsa_test_key_b();
            Certificate::self_signed(
                &k,
                &DistinguishedName::common_name("Wrong"),
                &validity(),
                9,
                true,
            )
            .unwrap()
        };
        let (r2, v2) = verify_embedded_scts(
            &leaf_with_sct,
            &wrong_issuer,
            core::slice::from_ref(&log.log),
            now,
        )
        .unwrap();
        assert_eq!(r2, vec![SctVerification::BadSignature]);
        assert_eq!(v2, 0);

        // Unknown log.
        let other = make_test_log(b"nope");
        let (r3, v3) = verify_embedded_scts(
            &leaf_with_sct,
            &issuer,
            core::slice::from_ref(&other.log),
            now,
        )
        .unwrap();
        assert_eq!(r3, vec![SctVerification::UnknownLog]);
        assert_eq!(v3, 0);

        // Future timestamp.
        let (r4, _) = verify_embedded_scts(
            &leaf_with_sct,
            &issuer,
            core::slice::from_ref(&log.log),
            ts - 1,
        )
        .unwrap();
        assert_eq!(r4, vec![SctVerification::FutureTimestamp]);
    }

    #[test]
    fn precert_reconstruction_strips_poison_and_sct() {
        // A cert carrying poison + SCT-list, plus BC/SAN. Reconstruction must
        // drop exactly poison + SCT and keep BC + SAN, and the result must
        // re-parse as a valid TBS prefix.
        let ca_key = rsa_test_key_a();
        let ca_b = BoxedRsaPrivateKey::from_pkcs1_der(&ca_key.to_pkcs1_der()).unwrap();
        let with_both = Certificate::issue_with_extensions(
            &CertSigner::Rsa(&ca_b),
            &DistinguishedName::common_name("CA"),
            &DistinguishedName::common_name("leaf"),
            &AnyPublicKey::Rsa(ca_b.public_key()),
            &validity(),
            2,
            &[
                extension::basic_constraints(false, None),
                extension::ct_poison(),
                extension::subject_alt_name(&[GeneralName::Dns("leaf".into())]),
                extension::sct_list(&[0x00, 0x00]),
            ],
        )
        .unwrap();
        // Same cert WITHOUT poison/SCT — its TBS is the reconstruction target.
        let without = Certificate::issue_with_extensions(
            &CertSigner::Rsa(&ca_b),
            &DistinguishedName::common_name("CA"),
            &DistinguishedName::common_name("leaf"),
            &AnyPublicKey::Rsa(ca_b.public_key()),
            &validity(),
            2,
            &[
                extension::basic_constraints(false, None),
                extension::subject_alt_name(&[GeneralName::Dns("leaf".into())]),
            ],
        )
        .unwrap();
        let rebuilt = reconstruct_precert_tbs(&with_both).unwrap();
        assert_eq!(rebuilt, without.tbs_der().unwrap());
    }
}
