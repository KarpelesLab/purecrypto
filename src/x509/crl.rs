//! X.509 v2 Certificate Revocation Lists (RFC 5280 §5).
//!
//! A CRL is a signed list of revoked certificate serials, scoped to one
//! issuer. The signer is the same authority that issued the certificates
//! being revoked. `purecrypto`'s `tls::pki` chain validator consults a
//! [`crate::tls::pki::CrlStore`] of these objects to short-circuit any
//! signed-by-the-anchor certificate that appears in a covering CRL.
//!
//! The wire format (RFC 5280 §5.1):
//!
//! ```text
//! CertificateList  ::=  SEQUENCE {
//!     tbsCertList          TBSCertList,
//!     signatureAlgorithm   AlgorithmIdentifier,
//!     signatureValue       BIT STRING
//! }
//!
//! TBSCertList  ::=  SEQUENCE {
//!     version              Version OPTIONAL,         -- v2 = 1 here
//!     signature            AlgorithmIdentifier,      -- inner; MUST equal outer
//!     issuer               Name,
//!     thisUpdate           Time,
//!     nextUpdate           Time OPTIONAL,
//!     revokedCertificates  SEQUENCE OF SEQUENCE {
//!         userCertificate     CertificateSerialNumber,  -- INTEGER
//!         revocationDate      Time,
//!         crlEntryExtensions  Extensions OPTIONAL
//!     } OPTIONAL,
//!     crlExtensions        [0] EXPLICIT Extensions OPTIONAL
//! }
//! ```
//!
//! See [`CertificateRevocationList`] and [`CrlBuilder`] for the read/write APIs.

use alloc::string::String;
use alloc::vec::Vec;

use super::{AnyPublicKey, CertSigner, DistinguishedName, Error, Time, oid};
use crate::der::{
    Reader, encode_bit_string, encode_integer, encode_octet_string, encode_sequence, encode_tlv,
    oid_tlv, parse_oid, pem_decode, pem_encode, tag,
};

const PEM_LABEL: &str = "X509 CRL";

/// Reasons a certificate may be revoked (RFC 5280 §5.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CrlReason {
    /// `unspecified` (0). No `crlEntryExtensions` will be emitted when this
    /// is the only reason on an entry.
    Unspecified = 0,
    /// `keyCompromise` (1).
    KeyCompromise = 1,
    /// `cACompromise` (2).
    CACompromise = 2,
    /// `affiliationChanged` (3).
    AffiliationChanged = 3,
    /// `superseded` (4).
    Superseded = 4,
    /// `cessationOfOperation` (5).
    CessationOfOperation = 5,
    /// `certificateHold` (6).
    CertificateHold = 6,
    /// `removeFromCRL` (8). Only meaningful in delta-CRLs.
    RemoveFromCRL = 8,
    /// `privilegeWithdrawn` (9).
    PrivilegeWithdrawn = 9,
    /// `aACompromise` (10).
    AaCompromise = 10,
}

impl CrlReason {
    /// Parses a single-byte ENUMERATED value into a `CrlReason`. Unknown
    /// values map to [`CrlReason::Unspecified`].
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => CrlReason::KeyCompromise,
            2 => CrlReason::CACompromise,
            3 => CrlReason::AffiliationChanged,
            4 => CrlReason::Superseded,
            5 => CrlReason::CessationOfOperation,
            6 => CrlReason::CertificateHold,
            8 => CrlReason::RemoveFromCRL,
            9 => CrlReason::PrivilegeWithdrawn,
            10 => CrlReason::AaCompromise,
            _ => CrlReason::Unspecified,
        }
    }
}

/// One row in the CRL's `revokedCertificates` list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokedCertificate {
    /// Raw serial INTEGER body, big-endian (strict-DER canonical: at most
    /// one leading `0x00` to keep the value non-negative).
    pub serial: Vec<u8>,
    /// Time at which the certificate was revoked.
    pub revocation_date: Time,
    /// Optional reason code from the `cRLReason` entry extension.
    pub reason: Option<CrlReason>,
}

/// A signed, DER-encoded X.509 v2 CRL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateRevocationList {
    der: Vec<u8>,
}

/// Builder for a [`CertificateRevocationList`].
pub struct CrlBuilder {
    issuer_der: Vec<u8>,
    this_update: Time,
    next_update: Option<Time>,
    entries: Vec<RevokedCertificate>,
}

impl CrlBuilder {
    /// Starts a new CRL keyed by `issuer`.
    pub fn new(issuer: &DistinguishedName, this_update: Time, next_update: Option<Time>) -> Self {
        CrlBuilder {
            issuer_der: issuer.to_der(),
            this_update,
            next_update,
            entries: Vec::new(),
        }
    }

    /// Adds a revoked entry. `serial_be` is the raw big-endian serial number
    /// (the integer magnitude); it is canonicalized into a strict-DER INTEGER
    /// body at sign time.
    pub fn revoke(
        &mut self,
        serial_be: &[u8],
        revocation_date: Time,
        reason: Option<CrlReason>,
    ) -> &mut Self {
        self.entries.push(RevokedCertificate {
            serial: serial_be.to_vec(),
            revocation_date,
            reason,
        });
        self
    }

    /// Signs the accumulated CRL with `signer`, producing a
    /// [`CertificateRevocationList`].
    pub fn sign(self, signer: &CertSigner<'_>) -> Result<CertificateRevocationList, Error> {
        let algid = signer.algorithm_identifier();
        let tbs = encode_tbs_cert_list(
            &self.issuer_der,
            &self.this_update,
            self.next_update.as_ref(),
            &self.entries,
            &algid,
        );
        let sig = signer.sign(&tbs)?;
        let der = encode_sequence(&[tbs, algid, encode_bit_string(&sig)].concat());
        Ok(CertificateRevocationList { der })
    }
}

/// Encodes a `cRLReason` per-entry extension carrying an ENUMERATED.
fn crl_reason_extension(reason: CrlReason) -> Vec<u8> {
    // ENUMERATED ::= a single-byte body for the reason code.
    let enumerated = encode_tlv(0x0a, &[reason as u8]);
    let mut ext = oid_tlv(oid::CRL_REASON_CODE);
    ext.extend_from_slice(&encode_octet_string(&enumerated));
    encode_sequence(&ext)
}

/// Encodes one row of `revokedCertificates`.
fn encode_revoked(entry: &RevokedCertificate) -> Vec<u8> {
    let serial = encode_integer(&entry.serial);
    let rdate = entry.revocation_date.to_der_choice();
    let mut body = Vec::new();
    body.extend_from_slice(&serial);
    body.extend_from_slice(&rdate);
    if let Some(reason) = entry.reason
        && reason != CrlReason::Unspecified
    {
        // `crlEntryExtensions ::= Extensions ::= SEQUENCE OF Extension`.
        let ext = crl_reason_extension(reason);
        body.extend_from_slice(&encode_sequence(&ext));
    }
    encode_sequence(&body)
}

/// Encodes a `TBSCertList`, with the inner `signature` algid set to `algid`
/// (DER bytes — the outer `signatureAlgorithm` must equal this).
fn encode_tbs_cert_list(
    issuer_der: &[u8],
    this_update: &Time,
    next_update: Option<&Time>,
    entries: &[RevokedCertificate],
    algid: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    // version = v2 (1) — required when extensions or v2 fields are present.
    body.extend_from_slice(&encode_integer(&[1]));
    body.extend_from_slice(algid);
    body.extend_from_slice(issuer_der);
    body.extend_from_slice(&this_update.to_der_choice());
    if let Some(n) = next_update {
        body.extend_from_slice(&n.to_der_choice());
    }
    if !entries.is_empty() {
        let mut list = Vec::new();
        for e in entries {
            list.extend_from_slice(&encode_revoked(e));
        }
        body.extend_from_slice(&encode_sequence(&list));
    }
    // `crlExtensions [0] EXPLICIT Extensions OPTIONAL` — none emitted here.
    encode_sequence(&body)
}

/// The three top-level parts of a `CertificateList`.
struct CrlParts<'a> {
    /// Raw `TBSCertList` TLV (used for signature verification).
    tbs: &'a [u8],
    /// Outer signature algorithm OID arcs.
    sig_alg: Vec<u64>,
    /// Signature bits.
    signature: &'a [u8],
}

impl CertificateRevocationList {
    /// Wraps existing CRL DER. Validates only that it is a single SEQUENCE
    /// with no trailing bytes (strict, matching the certificate parser).
    pub fn from_der(der: Vec<u8>) -> Result<Self, Error> {
        let mut r = Reader::new(&der);
        r.read_sequence()?;
        r.finish()?;
        Ok(CertificateRevocationList { der })
    }

    /// Parses a PEM `X509 CRL` document (RFC 7468 label).
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(CertificateRevocationList {
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

    /// Splits the outer CRL into its three top-level parts.
    fn parts(&self) -> Result<CrlParts<'_>, Error> {
        let mut outer = Reader::new(&self.der);
        let mut crl = outer.read_sequence()?;
        let tbs = crl.read_element()?;
        let mut alg = crl.read_sequence()?;
        let sig_alg = parse_oid(alg.read_oid()?)?;
        let signature = crl.read_bit_string()?;
        // Strict DER (X.690 §11): no trailing bytes inside the outer
        // SEQUENCE.
        crl.finish()?;
        Ok(CrlParts {
            tbs,
            sig_alg,
            signature,
        })
    }

    /// Sub-reader over the `TBSCertList` body, positioned after the inner
    /// signature `AlgorithmIdentifier`.
    fn tbs_after_algid(&self) -> Result<Reader<'_>, Error> {
        let tbs = self.parts()?.tbs;
        let mut outer = Reader::new(tbs);
        let mut seq = outer.read_sequence()?;
        // Optional INTEGER version; v2 = 1. RFC 5280 says it MUST be present
        // when the CRL is v2, but tolerate its absence (legacy v1 CRLs).
        if seq.peek_tag() == Some(tag::INTEGER) {
            seq.read_integer_bytes()?;
        }
        seq.read_sequence()?; // inner signature AlgorithmIdentifier
        Ok(seq)
    }

    /// Returns the DER bytes of the inner `signature` AlgorithmIdentifier
    /// inside `TBSCertList`.
    pub(crate) fn inner_signature_algid_der(&self) -> Result<&[u8], Error> {
        let tbs = self.parts()?.tbs;
        let mut outer = Reader::new(tbs);
        let mut seq = outer.read_sequence()?;
        if seq.peek_tag() == Some(tag::INTEGER) {
            seq.read_integer_bytes()?;
        }
        Ok(seq.read_element()?)
    }

    /// Returns the DER bytes of the outer `signatureAlgorithm`
    /// AlgorithmIdentifier (RFC 5280 §5.1.1.2).
    pub(crate) fn outer_signature_algid_der(&self) -> Result<&[u8], Error> {
        let mut outer = Reader::new(&self.der);
        let mut crl = outer.read_sequence()?;
        crl.read_element()?; // skip TBSCertList
        Ok(crl.read_element()?)
    }

    /// RFC 5280 §5.1.1.2: the inner and outer signature AlgorithmIdentifier
    /// fields MUST be identical. Compares raw DER (parameters included),
    /// mirroring [`super::Certificate::check_signature_algid_consistent`].
    pub fn check_signature_algid_consistent(&self) -> Result<(), Error> {
        let inner = self.inner_signature_algid_der()?;
        let outer = self.outer_signature_algid_der()?;
        if inner == outer {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    /// The CRL issuer.
    pub fn issuer(&self) -> Result<DistinguishedName, Error> {
        let mut seq = self.tbs_after_algid()?;
        DistinguishedName::decode(&mut seq)
    }

    /// The raw DER bytes of the CRL's `issuer` field — the full `Name` TLV.
    pub fn issuer_der(&self) -> Result<&[u8], Error> {
        let mut seq = self.tbs_after_algid()?;
        Ok(seq.read_element()?)
    }

    /// `thisUpdate`.
    pub fn this_update(&self) -> Result<Time, Error> {
        let mut seq = self.tbs_after_algid()?;
        seq.read_element()?; // issuer
        read_time(&mut seq)
    }

    /// `nextUpdate`, if present.
    pub fn next_update(&self) -> Result<Option<Time>, Error> {
        let mut seq = self.tbs_after_algid()?;
        seq.read_element()?; // issuer
        read_time(&mut seq)?; // thisUpdate
        if seq.is_empty() {
            return Ok(None);
        }
        match seq.peek_tag() {
            Some(t) if t == tag::UTC_TIME || t == tag::GENERALIZED_TIME => {
                read_time(&mut seq).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// The OID arcs of the CRL's outer `signatureAlgorithm` field.
    pub fn signature_algorithm_oid(&self) -> Result<Vec<u64>, Error> {
        Ok(self.parts()?.sig_alg)
    }

    /// Verifies the CRL signature against `issuer_key`, dispatching on the
    /// CRL's `signatureAlgorithm` through the signature registry.
    pub fn verify_signature_with(&self, issuer_key: &AnyPublicKey) -> Result<(), Error> {
        let parts = self.parts()?;
        issuer_key.verify(&parts.sig_alg, parts.tbs, parts.signature)
    }

    /// Iterates the `revokedCertificates` entries. Returns an empty list if
    /// the field is absent.
    pub fn entries(&self) -> Result<Vec<RevokedCertificate>, Error> {
        let mut out = Vec::new();
        let mut seq = self.tbs_after_algid()?;
        seq.read_element()?; // issuer
        read_time(&mut seq)?; // thisUpdate

        // Skip nextUpdate when present.
        if let Some(t) = seq.peek_tag()
            && (t == tag::UTC_TIME || t == tag::GENERALIZED_TIME)
        {
            read_time(&mut seq)?;
        }

        // Optional revokedCertificates SEQUENCE OF SEQUENCE.
        if seq.peek_tag() == Some(tag::SEQUENCE) {
            let inner = seq.read_element()?;
            let mut r = Reader::new(inner);
            let mut list = r.read_sequence()?;
            while !list.is_empty() {
                let mut entry = list.read_sequence()?;
                let serial = entry.read_unsigned_integer_bytes()?.to_vec();
                let revocation_date = read_time(&mut entry)?;
                let mut reason = None;
                // Optional crlEntryExtensions (Extensions ::= SEQUENCE OF
                // Extension); scan for the cRLReason entry.
                if !entry.is_empty() {
                    let mut exts = entry.read_sequence()?;
                    while !exts.is_empty() {
                        let mut ext = exts.read_sequence()?;
                        let id = parse_oid(ext.read_oid()?)?;
                        let _critical = if ext.peek_tag() == Some(tag::BOOLEAN) {
                            ext.read_boolean()?
                        } else {
                            false
                        };
                        let value = ext.read_octet_string()?;
                        if id.as_slice() == oid::CRL_REASON_CODE {
                            let mut vr = Reader::new(value);
                            let enum_body = vr.read_tlv(0x0a)?;
                            // ENUMERATED is single-byte in practice for the
                            // values defined by RFC 5280 §5.3.1.
                            if enum_body.len() == 1 {
                                reason = Some(CrlReason::from_u8(enum_body[0]));
                            }
                        }
                    }
                }
                out.push(RevokedCertificate {
                    serial,
                    revocation_date,
                    reason,
                });
            }
        }
        Ok(out)
    }

    /// Whether `serial_be` (the raw INTEGER body, with at most one leading
    /// `0x00`) is revoked by this CRL.
    ///
    /// Comparison is on the *magnitude*: a leading sign-protection `0x00`
    /// is stripped from both sides, so `02 02 00 7F` matches `7F`.
    pub fn is_revoked(&self, serial_be: &[u8]) -> Result<bool, Error> {
        let needle = strip_leading_sign_zero(serial_be);
        for e in self.entries()? {
            if strip_leading_sign_zero(&e.serial) == needle {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Strips a single permitted leading `0x00` (the strict-DER positive-sign
/// pad) from `bytes`, leaving the bare magnitude.
fn strip_leading_sign_zero(bytes: &[u8]) -> &[u8] {
    if bytes.len() > 1 && bytes[0] == 0x00 {
        &bytes[1..]
    } else {
        bytes
    }
}

/// Reads one `Time` (`UTCTime` or `GeneralizedTime`) from `reader`.
fn read_time(reader: &mut Reader) -> Result<Time, Error> {
    let (t, value) = reader.read_any()?;
    if t != tag::UTC_TIME && t != tag::GENERALIZED_TIME {
        return Err(Error::Malformed);
    }
    let s = core::str::from_utf8(value).map_err(|_| Error::Malformed)?;
    Ok(Time::from_repr(s))
}

#[cfg(test)]
mod tests {
    use super::super::algorithm_identifier;
    use super::*;
    use crate::rsa::BoxedRsaPrivateKey;
    use crate::x509::{CertSigner, Validity};

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

    fn issuer_dn() -> DistinguishedName {
        DistinguishedName::common_name("purecrypto CRL test")
    }

    #[test]
    fn roundtrip_two_entries_and_verify() {
        let key = rsa_a();
        let signer = CertSigner::Rsa(&key);
        let dn = issuer_dn();
        let mut b = CrlBuilder::new(
            &dn,
            Time::utc(2026, 1, 1, 0, 0, 0),
            Some(Time::utc(2026, 12, 31, 0, 0, 0)),
        );
        b.revoke(
            &[0x01],
            Time::utc(2026, 2, 1, 0, 0, 0),
            Some(CrlReason::KeyCompromise),
        );
        b.revoke(
            &[0x02, 0x03],
            Time::utc(2026, 2, 2, 0, 0, 0),
            Some(CrlReason::Superseded),
        );
        let crl = b.sign(&signer).unwrap();

        // Round-trip through DER and PEM.
        let from_der = CertificateRevocationList::from_der(crl.to_der().to_vec()).unwrap();
        assert_eq!(from_der, crl);
        let pem = crl.to_pem();
        assert!(pem.contains("BEGIN X509 CRL"));
        let from_pem = CertificateRevocationList::from_pem(&pem).unwrap();
        assert_eq!(from_pem, crl);

        // Issuer / dates / algid consistency.
        assert_eq!(crl.issuer().unwrap(), dn);
        assert_eq!(crl.this_update().unwrap(), Time::utc(2026, 1, 1, 0, 0, 0));
        assert_eq!(
            crl.next_update().unwrap().unwrap(),
            Time::utc(2026, 12, 31, 0, 0, 0)
        );
        crl.check_signature_algid_consistent().unwrap();

        // Entries decode the way we encoded.
        let entries = crl.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].serial, alloc::vec![0x01]);
        assert_eq!(entries[0].reason, Some(CrlReason::KeyCompromise));
        assert_eq!(entries[1].serial, alloc::vec![0x02, 0x03]);
        assert_eq!(entries[1].reason, Some(CrlReason::Superseded));

        // Signature verifies against the issuer.
        let issuer_pub = signer.public_key();
        crl.verify_signature_with(&issuer_pub).unwrap();

        // is_revoked matches on the magnitude.
        assert!(crl.is_revoked(&[0x01]).unwrap());
        assert!(crl.is_revoked(&[0x02, 0x03]).unwrap());
        // Strict-DER canonical comparison: a sign-protection 0x00 is
        // transparently stripped.
        assert!(crl.is_revoked(&[0x00, 0x01]).unwrap());
        // A different serial: not revoked.
        assert!(!crl.is_revoked(&[0x07]).unwrap());
    }

    #[test]
    fn verify_signature_rejects_wrong_key() {
        let key_a = rsa_a();
        let key_b = rsa_b();
        let signer = CertSigner::Rsa(&key_a);
        let dn = issuer_dn();
        let b = CrlBuilder::new(&dn, Time::utc(2026, 1, 1, 0, 0, 0), None);
        let crl = b.sign(&signer).unwrap();

        // Signed by A; verifies under A, rejects under B.
        crl.verify_signature_with(&CertSigner::Rsa(&key_a).public_key())
            .unwrap();
        assert!(
            crl.verify_signature_with(&CertSigner::Rsa(&key_b).public_key())
                .is_err()
        );
    }

    #[test]
    fn verify_signature_rejects_tampered_byte() {
        let key = rsa_a();
        let signer = CertSigner::Rsa(&key);
        let dn = issuer_dn();
        let mut b = CrlBuilder::new(&dn, Time::utc(2026, 1, 1, 0, 0, 0), None);
        b.revoke(&[0x05], Time::utc(2026, 1, 2, 0, 0, 0), None);
        let crl = b.sign(&signer).unwrap();

        let mut der = crl.to_der().to_vec();
        // Flip a byte inside the TBS.
        let idx = der.len() / 3;
        der[idx] ^= 1;
        let bad = CertificateRevocationList::from_der(der).unwrap();
        assert!(bad.verify_signature_with(&signer.public_key()).is_err());

        // The unmodified CRL still verifies.
        crl.verify_signature_with(&signer.public_key()).unwrap();
        let _ = validity(); // keep the helper used.
    }

    #[test]
    fn rejects_inner_outer_algid_mismatch() {
        // Construct a CRL whose outer signatureAlgorithm differs from the
        // inner one (RFC 5280 §5.1.1.2 forbids this). The signature itself
        // is over the TBS bytes (with the inner algid), so the *signature*
        // would technically verify — but the consistency check refuses the
        // CRL before that.
        let key = rsa_a();
        let signer = CertSigner::Rsa(&key);
        let dn = issuer_dn();

        // Build a TBS with inner = ECDSA-SHA256 (any non-RSA algid will do).
        // We can't actually *sign* with ECDSA-SHA256 using an RSA key, so we
        // sign with the matching RSA algid for the wire encoding and then
        // splice the outer to a different OID.
        let inner_algid = algorithm_identifier(oid::SHA256_WITH_RSA, true);
        let tbs = encode_tbs_cert_list(
            &dn.to_der(),
            &Time::utc(2026, 1, 1, 0, 0, 0),
            None,
            &[],
            &inner_algid,
        );
        let sig = signer.sign(&tbs).unwrap();
        // Outer = sha1WithRSAEncryption (different OID than inner).
        let outer_algid = algorithm_identifier(oid::SHA1_WITH_RSA, true);
        let der = encode_sequence(&[tbs, outer_algid, encode_bit_string(&sig)].concat());
        let mismatched = CertificateRevocationList::from_der(der).unwrap();
        assert!(matches!(
            mismatched.check_signature_algid_consistent(),
            Err(Error::Malformed)
        ));
    }

    #[test]
    fn empty_crl_has_no_entries() {
        let key = rsa_a();
        let signer = CertSigner::Rsa(&key);
        let dn = issuer_dn();
        let b = CrlBuilder::new(&dn, Time::utc(2026, 1, 1, 0, 0, 0), None);
        let crl = b.sign(&signer).unwrap();
        assert!(crl.entries().unwrap().is_empty());
        assert!(!crl.is_revoked(&[0x42]).unwrap());
        assert!(crl.next_update().unwrap().is_none());
    }
}
