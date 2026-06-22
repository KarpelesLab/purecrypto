//! X.509 v3 extension types and encoders (RFC 5280 §4.2).
//!
//! Each builder returns a fully-formed [`Extension`] (oid + critical bit +
//! DER-encoded inner value). Pass a slice of these to
//! [`Certificate::issue_with_extensions`](super::Certificate::issue_with_extensions)
//! or
//! [`CertificationRequest::create_with_extensions`](super::CertificationRequest::create_with_extensions).

use alloc::string::String;
use alloc::vec::Vec;

use super::oid;
use crate::der::{
    Reader, encode_boolean, encode_context, encode_integer, encode_octet_string, encode_sequence,
    encode_tlv, oid_tlv, tag,
};
use crate::hash::{Digest, Sha1};

/// One X.509 v3 extension: oid + critical bit + DER-encoded inner value.
///
/// `value` is the **inner** DER (the body of the `extnValue OCTET STRING`),
/// not including the outer `SEQUENCE { OID, critical?, OCTET STRING }`
/// framing produced when the extension is serialised into a `TBSCertificate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    /// The extension's OID arcs (e.g. `2.5.29.19` for `basicConstraints`).
    pub oid: Vec<u64>,
    /// Whether the extension is marked critical (RFC 5280 §4.2).
    pub critical: bool,
    /// The inner DER bytes of the extension value (no `OCTET STRING` wrapper).
    pub value: Vec<u8>,
}

impl Extension {
    /// Serialises this extension as one `Extension ::= SEQUENCE { OID,
    /// critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }` element.
    pub(crate) fn to_der(&self) -> Vec<u8> {
        let mut body = oid_tlv(&self.oid);
        if self.critical {
            body.extend_from_slice(&encode_boolean(true));
        }
        body.extend_from_slice(&encode_octet_string(&self.value));
        encode_sequence(&body)
    }
}

/// One entry in `subjectAltName` / `issuerAltName` / a `nameConstraints`
/// permitted / excluded subtree. Mirrors RFC 5280 §4.2.1.6 `GeneralName`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeneralName {
    /// `dNSName` (`[2] IA5String`). Encoded as ASCII.
    Dns(String),
    /// `iPAddress` (`[7] OCTET STRING`) — 4-byte IPv4 form.
    IpV4([u8; 4]),
    /// `iPAddress` (`[7] OCTET STRING`) — 16-byte IPv6 form.
    IpV6([u8; 16]),
    /// `rfc822Name` (`[1] IA5String`).
    Email(String),
    /// `uniformResourceIdentifier` (`[6] IA5String`).
    Uri(String),
}

impl GeneralName {
    /// DER-encodes this entry as one `GeneralName` element, using the
    /// IMPLICIT context tag matching the variant.
    pub(crate) fn to_der(&self) -> Vec<u8> {
        match self {
            // [1] IMPLICIT IA5String → primitive context tag 0x81.
            GeneralName::Email(s) => encode_tlv(0x81, s.as_bytes()),
            // [2] IMPLICIT IA5String → primitive context tag 0x82.
            GeneralName::Dns(s) => encode_tlv(0x82, s.as_bytes()),
            // [6] IMPLICIT IA5String → primitive context tag 0x86.
            GeneralName::Uri(s) => encode_tlv(0x86, s.as_bytes()),
            // [7] IMPLICIT OCTET STRING → primitive context tag 0x87.
            GeneralName::IpV4(ip) => encode_tlv(0x87, ip),
            GeneralName::IpV6(ip) => encode_tlv(0x87, ip),
        }
    }
}

/// A `keyUsage` bit-mask (RFC 5280 §4.2.1.3). The low 9 usage bits are stored
/// in the low 9 bits of the `u16`, using the same wire layout the parser at
/// [`Certificate::key_usage`](super::Certificate::key_usage) produces:
/// `digitalSignature` in `0x80`, `keyCertSign` in `0x04`, `decipherOnly`
/// in `0x8000`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyUsageBits(pub u16);

impl KeyUsageBits {
    /// `digitalSignature` (BIT STRING bit 0).
    pub const DIGITAL_SIGNATURE: Self = Self(0x80);
    /// `nonRepudiation` (BIT STRING bit 1) — sometimes called
    /// `contentCommitment` in newer profiles.
    pub const NON_REPUDIATION: Self = Self(0x40);
    /// `keyEncipherment` (BIT STRING bit 2).
    pub const KEY_ENCIPHERMENT: Self = Self(0x20);
    /// `dataEncipherment` (BIT STRING bit 3).
    pub const DATA_ENCIPHERMENT: Self = Self(0x10);
    /// `keyAgreement` (BIT STRING bit 4).
    pub const KEY_AGREEMENT: Self = Self(0x08);
    /// `keyCertSign` (BIT STRING bit 5).
    pub const KEY_CERT_SIGN: Self = Self(0x04);
    /// `cRLSign` (BIT STRING bit 6).
    pub const CRL_SIGN: Self = Self(0x02);
    /// `encipherOnly` (BIT STRING bit 7).
    pub const ENCIPHER_ONLY: Self = Self(0x01);
    /// `decipherOnly` (BIT STRING bit 8, second byte).
    pub const DECIPHER_ONLY: Self = Self(0x80_00);

    /// An empty bit-mask.
    pub fn empty() -> Self {
        Self(0)
    }

    /// `true` if every bit in `other` is set in `self`.
    pub fn contains(&self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Set every bit from `other` in `self`.
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// `true` if no bits are set.
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for KeyUsageBits {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for KeyUsageBits {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// --- builders ---------------------------------------------------------------

/// `basicConstraints` (RFC 5280 §4.2.1.9). Always marked critical, as
/// recommended for CA certificates and required by RFC 5280 when `cA=TRUE`.
pub fn basic_constraints(is_ca: bool, path_len: Option<u32>) -> Extension {
    let mut body = Vec::new();
    if is_ca {
        body.extend_from_slice(&encode_boolean(true));
        if let Some(n) = path_len {
            // pathLenConstraint is INTEGER. Encode as the minimal big-endian
            // unsigned magnitude; encode_integer adds a leading 0x00 if the
            // high bit would otherwise be set.
            let be = n.to_be_bytes();
            body.extend_from_slice(&encode_integer(&be));
        }
    }
    Extension {
        oid: oid::BASIC_CONSTRAINTS.to_vec(),
        critical: true,
        value: encode_sequence(&body),
    }
}

/// `keyUsage` (RFC 5280 §4.2.1.3). Always critical per the RFC's SHOULD.
///
/// The BIT STRING value carries the minimal trailing-zero-trimmed wire form
/// described in DER §11.2.2: bits beyond the last 1 are dropped, the
/// unused-bits prefix is updated accordingly. Empty bit-masks return the
/// canonical `03 02 07 00` form.
pub fn key_usage(bits: KeyUsageBits) -> Extension {
    let mut value = Vec::with_capacity(4);
    let mask = bits.0;
    let bytes = if mask & 0xff00 != 0 {
        // Second byte non-zero → keep both.
        [(mask & 0xff) as u8, (mask >> 8) as u8].to_vec()
    } else if mask & 0x00ff != 0 {
        // Only first byte non-zero.
        [(mask & 0xff) as u8].to_vec()
    } else {
        Vec::new()
    };
    // Unused-bits count = number of trailing zero bits in the last byte; for
    // an empty mask the BIT STRING is "no bytes" + 0 unused-bits, encoded as
    // `03 01 00`.
    let unused = if bytes.is_empty() {
        0u8
    } else {
        let last = *bytes.last().unwrap();
        let mut u = 0u8;
        let mut b = last;
        while b & 1 == 0 && u < 8 {
            u += 1;
            b >>= 1;
        }
        u
    };
    value.push(unused);
    value.extend_from_slice(&bytes);
    let bs = encode_tlv(tag::BIT_STRING, &value);
    Extension {
        oid: oid::KEY_USAGE.to_vec(),
        critical: true,
        value: bs,
    }
}

/// `extendedKeyUsage` (RFC 5280 §4.2.1.12). Non-critical by default per
/// the RFC's recommendation. Each entry is one purpose OID.
pub fn extended_key_usage(oids: &[&[u64]]) -> Extension {
    let mut body = Vec::new();
    for o in oids {
        body.extend_from_slice(&oid_tlv(o));
    }
    Extension {
        oid: oid::EXT_KEY_USAGE.to_vec(),
        critical: false,
        value: encode_sequence(&body),
    }
}

/// `subjectAltName` (RFC 5280 §4.2.1.6). Non-critical when subject is
/// non-empty; the caller is expected to mark it critical (by post-mutating
/// the returned struct) when the subject DN is empty.
pub fn subject_alt_name(names: &[GeneralName]) -> Extension {
    let mut body = Vec::new();
    for n in names {
        body.extend_from_slice(&n.to_der());
    }
    Extension {
        oid: oid::SUBJECT_ALT_NAME.to_vec(),
        critical: false,
        value: encode_sequence(&body),
    }
}

/// `subjectKeyIdentifier` (RFC 5280 §4.2.1.2). Non-critical.
///
/// The key identifier is computed by method 1 of the RFC: SHA-1 over the
/// contents of the SPKI's BIT STRING (i.e. the public key bits themselves,
/// **without** the leading unused-bits prefix byte and **without** the outer
/// SPKI SEQUENCE).
pub fn subject_key_identifier(spki_bit_string_contents: &[u8]) -> Extension {
    let hash = Sha1::digest(spki_bit_string_contents);
    Extension {
        oid: oid::SUBJECT_KEY_IDENTIFIER.to_vec(),
        critical: false,
        value: encode_octet_string(&hash),
    }
}

/// `subjectKeyIdentifier` computed directly from a precomputed 20-byte SKI
/// (e.g. one extracted from the issuer's SKI extension).
pub fn subject_key_identifier_raw(ski: &[u8]) -> Extension {
    Extension {
        oid: oid::SUBJECT_KEY_IDENTIFIER.to_vec(),
        critical: false,
        value: encode_octet_string(ski),
    }
}

/// `authorityKeyIdentifier` (RFC 5280 §4.2.1.1) carrying just the issuer's
/// keyIdentifier. Non-critical.
pub fn authority_key_identifier(issuer_ski: &[u8]) -> Extension {
    // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
    // [0] IMPLICIT OCTET STRING is a primitive context-specific tag 0x80.
    let ki = encode_tlv(0x80, issuer_ski);
    Extension {
        oid: oid::AUTHORITY_KEY_IDENTIFIER.to_vec(),
        critical: false,
        value: encode_sequence(&ki),
    }
}

/// `nameConstraints` (RFC 5280 §4.2.1.10). Critical when present in a CA.
pub fn name_constraints(permitted: &[GeneralName], excluded: &[GeneralName]) -> Extension {
    let mut body = Vec::new();
    if !permitted.is_empty() {
        let subtrees = encode_subtrees(permitted);
        // permittedSubtrees [0] IMPLICIT GeneralSubtrees → constructed context 0xA0.
        body.extend_from_slice(&encode_tlv(tag::context(0), &subtrees));
    }
    if !excluded.is_empty() {
        let subtrees = encode_subtrees(excluded);
        // excludedSubtrees [1] IMPLICIT GeneralSubtrees → constructed context 0xA1.
        body.extend_from_slice(&encode_tlv(tag::context(1), &subtrees));
    }
    Extension {
        oid: oid::NAME_CONSTRAINTS.to_vec(),
        critical: true,
        value: encode_sequence(&body),
    }
}

fn encode_subtrees(names: &[GeneralName]) -> Vec<u8> {
    // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
    // GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] DEFAULT 0, maximum [1] OPTIONAL }
    // We only emit `base`; minimum defaults to 0 (and per RFC 5280 §4.2.1.10
    // MUST NOT be set to anything else).
    let mut out = Vec::new();
    for n in names {
        let subtree = encode_sequence(&n.to_der());
        out.extend_from_slice(&subtree);
    }
    out
}

/// `certificatePolicies` (RFC 5280 §4.2.1.4). Non-critical.
///
/// Each entry encodes only its `policyIdentifier` OID; policy qualifiers are
/// not emitted in v1.
pub fn certificate_policies(policy_oids: &[&[u64]]) -> Extension {
    let mut body = Vec::new();
    for o in policy_oids {
        // PolicyInformation ::= SEQUENCE { policyIdentifier OID, policyQualifiers? ... }
        body.extend_from_slice(&encode_sequence(&oid_tlv(o)));
    }
    Extension {
        oid: oid::CERTIFICATE_POLICIES.to_vec(),
        critical: false,
        value: encode_sequence(&body),
    }
}

/// `policyMappings` (RFC 5280 §4.2.1.5). Each pair is
/// `(issuerDomainPolicy, subjectDomainPolicy)` OID arcs. The RFC marks this
/// SHOULD-critical; emitted critical here.
pub fn policy_mappings(pairs: &[(&[u64], &[u64])]) -> Extension {
    let mut body = Vec::new();
    for (issuer, subject) in pairs {
        // PolicyMapping ::= SEQUENCE { issuerDomainPolicy OID,
        //                              subjectDomainPolicy OID }
        let pair = [oid_tlv(issuer), oid_tlv(subject)].concat();
        body.extend_from_slice(&encode_sequence(&pair));
    }
    Extension {
        oid: oid::POLICY_MAPPINGS.to_vec(),
        critical: true,
        value: encode_sequence(&body),
    }
}

/// `policyConstraints` (RFC 5280 §4.2.1.11). `require_explicit` and
/// `inhibit_mapping` are the two OPTIONAL `SkipCerts` (INTEGER) fields. Always
/// critical (the RFC mandates it).
pub fn policy_constraints(
    require_explicit: Option<u32>,
    inhibit_mapping: Option<u32>,
) -> Extension {
    let mut body = Vec::new();
    // requireExplicitPolicy [0] IMPLICIT SkipCerts — IMPLICIT INTEGER, so the
    // INTEGER body is carried under the primitive context tag 0x80.
    if let Some(n) = require_explicit {
        let int = encode_integer(&n.to_be_bytes());
        // Strip the INTEGER tag+len, keep the content, re-tag as [0] primitive.
        body.extend_from_slice(&encode_tlv(0x80, integer_content(&int)));
    }
    if let Some(n) = inhibit_mapping {
        let int = encode_integer(&n.to_be_bytes());
        body.extend_from_slice(&encode_tlv(0x81, integer_content(&int)));
    }
    Extension {
        oid: oid::POLICY_CONSTRAINTS.to_vec(),
        critical: true,
        value: encode_sequence(&body),
    }
}

/// `inhibitAnyPolicy` (RFC 5280 §4.2.1.14). The value is a bare `SkipCerts`
/// INTEGER. Always critical (the RFC mandates it).
pub fn inhibit_any_policy(skip_certs: u32) -> Extension {
    Extension {
        oid: oid::INHIBIT_ANY_POLICY.to_vec(),
        critical: true,
        value: encode_integer(&skip_certs.to_be_bytes()),
    }
}

/// Returns the content octets of a DER INTEGER TLV produced by
/// [`encode_integer`] (strips the tag + length prefix). Parses the length
/// through the crate's DER reader rather than assuming a short-form length
/// octet: although `encode_integer` of a `u32` magnitude never needs the long
/// form today, hardcoding the `02 LL` offset would silently corrupt the output
/// the moment a longer value flowed through here.
fn integer_content(int_tlv: &[u8]) -> &[u8] {
    // The input is always well-formed DER from `encode_integer`, so this parse
    // cannot fail; fall back to an empty slice rather than panic if it ever
    // somehow does.
    Reader::new(int_tlv).read_integer_bytes().unwrap_or(&[])
}

/// `cRLDistributionPoints` (RFC 5280 §4.2.1.13). Non-critical.
///
/// Each URL becomes a `DistributionPoint` with the URI carried as a
/// `fullName [0]` `GeneralName::uniformResourceIdentifier`.
pub fn crl_distribution_points(urls: &[&str]) -> Extension {
    let mut body = Vec::new();
    for url in urls {
        // GeneralName::uniformResourceIdentifier [6] IA5String → tag 0x86.
        let gn = encode_tlv(0x86, url.as_bytes());
        // GeneralNames ::= SEQUENCE OF GeneralName.
        let gnames = encode_sequence(&gn);
        // DistributionPointName ::= CHOICE { fullName [0] GeneralNames, ... }
        // [0] IMPLICIT GeneralNames → constructed context tag 0xA0.
        let dpn = encode_tlv(tag::context(0), &gnames);
        // DistributionPoint ::= SEQUENCE {
        //   distributionPoint [0] DistributionPointName OPTIONAL,
        //   reasons [1] ReasonFlags OPTIONAL,
        //   cRLIssuer [2] GeneralNames OPTIONAL }
        // We emit only distributionPoint, wrapped in [0] EXPLICIT.
        let dp_inner = encode_context(0, &dpn);
        body.extend_from_slice(&encode_sequence(&dp_inner));
    }
    Extension {
        oid: oid::CRL_DISTRIBUTION_POINTS.to_vec(),
        critical: false,
        value: encode_sequence(&body),
    }
}

/// `SignedCertificateTimestampList` embedded-SCT extension
/// (1.3.6.1.4.1.11129.2.4.2, RFC 6962 §3.3). `tls_sct_list` is the
/// TLS-serialized `SignedCertificateTimestampList` (its own 2-byte total
/// length prefix included); this wraps it in the DER `OCTET STRING` the
/// extension's `extnValue` carries. Non-critical (RFC 6962 §3.3). Primarily a
/// test / tooling helper — CAs normally obtain this list from the logs.
pub fn sct_list(tls_sct_list: &[u8]) -> Extension {
    Extension {
        oid: oid::SCT_LIST.to_vec(),
        critical: false,
        value: encode_octet_string(tls_sct_list),
    }
}

/// `CT Precertificate Poison` extension (1.3.6.1.4.1.11129.2.4.3, RFC 6962
/// §3.1). Critical, value is `DER NULL`. Marks a precertificate.
pub fn ct_poison() -> Extension {
    Extension {
        oid: oid::CT_POISON.to_vec(),
        critical: true,
        value: crate::der::encode_null(),
    }
}

/// Encodes a slice of [`Extension`]s as the `[3] EXPLICIT Extensions` field
/// of a `TBSCertificate`.
pub(crate) fn encode_extensions_field(exts: &[Extension]) -> Vec<u8> {
    let mut body = Vec::new();
    for e in exts {
        body.extend_from_slice(&e.to_der());
    }
    encode_context(3, &encode_sequence(&body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::{Reader, parse_oid};
    use alloc::vec;

    #[test]
    fn basic_constraints_ca_false() {
        let ext = basic_constraints(false, None);
        assert!(ext.critical);
        assert_eq!(ext.oid, oid::BASIC_CONSTRAINTS);
        // The value is just an empty SEQUENCE.
        assert_eq!(ext.value, &[0x30, 0x00]);
    }

    #[test]
    fn basic_constraints_ca_with_path_len() {
        let ext = basic_constraints(true, Some(2));
        assert!(ext.critical);
        // Parse: SEQUENCE { BOOLEAN TRUE, INTEGER 2 }
        let mut r = Reader::new(&ext.value);
        let mut seq = r.read_sequence().unwrap();
        let b = seq.read_boolean().unwrap();
        assert!(b);
        let i = seq.read_integer_bytes().unwrap();
        assert_eq!(i, &[2]);
    }

    #[test]
    fn basic_constraints_ca_path_len_high_bit() {
        // 0xff requires the encode_integer leading-zero padding.
        let ext = basic_constraints(true, Some(0xff));
        let mut r = Reader::new(&ext.value);
        let mut seq = r.read_sequence().unwrap();
        let _ = seq.read_boolean().unwrap();
        let i = seq.read_unsigned_integer_bytes().unwrap();
        // Strict-DER unsigned-integer body keeps the leading 0x00 when the
        // top bit is set, so the canonical encoding of 255 is `00 FF`.
        assert_eq!(i, &[0x00, 0xff]);
    }

    #[test]
    fn key_usage_digital_signature_plus_key_encipherment() {
        let bits = KeyUsageBits::DIGITAL_SIGNATURE | KeyUsageBits::KEY_ENCIPHERMENT;
        let ext = key_usage(bits);
        assert!(ext.critical);
        // Wire: 03 02 05 A0  — one content byte 0xA0 (= 0x80|0x20), 5 unused bits.
        assert_eq!(ext.value, &[0x03, 0x02, 0x05, 0xA0]);
    }

    #[test]
    fn key_usage_key_cert_sign_plus_crl_sign() {
        let bits = KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN;
        let ext = key_usage(bits);
        // 0x04 | 0x02 = 0x06; trailing-zero count = 1 → unused = 1.
        assert_eq!(ext.value, &[0x03, 0x02, 0x01, 0x06]);
    }

    #[test]
    fn key_usage_decipher_only_uses_second_byte() {
        let bits = KeyUsageBits::DIGITAL_SIGNATURE | KeyUsageBits::DECIPHER_ONLY;
        let ext = key_usage(bits);
        // Two-byte BIT STRING; second byte 0x80, unused = 7.
        assert_eq!(ext.value, &[0x03, 0x03, 0x07, 0x80, 0x80]);
    }

    #[test]
    fn extended_key_usage_server_and_client() {
        let ext = extended_key_usage(&[oid::ID_KP_SERVER_AUTH, oid::ID_KP_CLIENT_AUTH]);
        assert!(!ext.critical);
        // Parse two OIDs from inside the SEQUENCE.
        let mut r = Reader::new(&ext.value);
        let mut seq = r.read_sequence().unwrap();
        let a = parse_oid(seq.read_oid().unwrap()).unwrap();
        let b = parse_oid(seq.read_oid().unwrap()).unwrap();
        assert_eq!(a, oid::ID_KP_SERVER_AUTH);
        assert_eq!(b, oid::ID_KP_CLIENT_AUTH);
    }

    #[test]
    fn subject_alt_name_round_trip() {
        let names = [
            GeneralName::Dns("example.com".into()),
            GeneralName::IpV4([10, 0, 0, 1]),
            GeneralName::Email("admin@example.com".into()),
            GeneralName::Uri("https://example.com/x".into()),
        ];
        let ext = subject_alt_name(&names);
        assert!(!ext.critical);

        // Re-parse and confirm each entry.
        let mut r = Reader::new(&ext.value);
        let mut seq = r.read_sequence().unwrap();
        let (t1, v1) = seq.read_any().unwrap();
        assert_eq!(t1, 0x82);
        assert_eq!(v1, b"example.com");
        let (t2, v2) = seq.read_any().unwrap();
        assert_eq!(t2, 0x87);
        assert_eq!(v2, &[10, 0, 0, 1]);
        let (t3, v3) = seq.read_any().unwrap();
        assert_eq!(t3, 0x81);
        assert_eq!(v3, b"admin@example.com");
        let (t4, v4) = seq.read_any().unwrap();
        assert_eq!(t4, 0x86);
        assert_eq!(v4, b"https://example.com/x");
    }

    #[test]
    fn ski_matches_rfc5280_method1() {
        // Method 1: SHA-1 over the BIT STRING contents (the SPKI key bits).
        // Sanity: known-answer for the empty input.
        let ext = subject_key_identifier(b"");
        // Value is an OCTET STRING wrapping the 20-byte SHA-1 digest.
        assert_eq!(ext.value[0], 0x04);
        assert_eq!(ext.value[1], 20);
        assert_eq!(
            &ext.value[2..],
            // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
            &[
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
            ]
        );
    }

    #[test]
    fn aki_round_trip() {
        let ski = [0xAAu8; 20];
        let ext = authority_key_identifier(&ski);
        assert!(!ext.critical);
        // SEQUENCE { [0] IMPLICIT OCTET STRING 20 bytes }
        // 30 16 80 14 AA*20
        assert_eq!(ext.value[0], 0x30);
        assert_eq!(ext.value[1], 0x16);
        assert_eq!(ext.value[2], 0x80);
        assert_eq!(ext.value[3], 0x14);
        assert_eq!(&ext.value[4..], &ski);
    }

    #[test]
    fn name_constraints_permitted_only() {
        let permitted = [GeneralName::Dns(".internal".into())];
        let ext = name_constraints(&permitted, &[]);
        assert!(ext.critical);
        let mut r = Reader::new(&ext.value);
        let mut seq = r.read_sequence().unwrap();
        let (t, _) = seq.read_any().unwrap();
        assert_eq!(t, tag::context(0)); // permittedSubtrees [0]
    }

    #[test]
    fn name_constraints_excluded_only() {
        let excluded = [GeneralName::Dns(".bad".into())];
        let ext = name_constraints(&[], &excluded);
        let mut r = Reader::new(&ext.value);
        let mut seq = r.read_sequence().unwrap();
        let (t, _) = seq.read_any().unwrap();
        assert_eq!(t, tag::context(1)); // excludedSubtrees [1]
    }

    #[test]
    fn certificate_policies_emits_one_per_oid() {
        let p = certificate_policies(&[&[2, 23, 140, 1, 2, 1], &[2, 23, 140, 1, 2, 2]]);
        assert!(!p.critical);
        let mut r = Reader::new(&p.value);
        let mut seq = r.read_sequence().unwrap();
        let mut p1 = seq.read_sequence().unwrap();
        let _ = parse_oid(p1.read_oid().unwrap()).unwrap();
        let mut p2 = seq.read_sequence().unwrap();
        let _ = parse_oid(p2.read_oid().unwrap()).unwrap();
        assert!(seq.is_empty());
    }

    #[test]
    fn crldp_single_url() {
        let ext = crl_distribution_points(&["http://crl.example/r.crl"]);
        assert!(!ext.critical);
        // Wrapping layers: SEQUENCE { SEQUENCE { [0] EXPLICIT { [0] IMPLICIT SEQUENCE { [6] URI } } } }
        let mut r = Reader::new(&ext.value);
        let mut outer = r.read_sequence().unwrap();
        let mut dp = outer.read_sequence().unwrap();
        let dpn_explicit = dp.read_tlv(tag::context(0)).unwrap();
        let mut dpn = Reader::new(dpn_explicit);
        let names = dpn.read_tlv(tag::context(0)).unwrap();
        let mut gnames = Reader::new(names);
        let mut gns = gnames.read_sequence().unwrap();
        let (t, v) = gns.read_any().unwrap();
        assert_eq!(t, 0x86);
        assert_eq!(v, b"http://crl.example/r.crl");
    }

    #[test]
    fn encode_extensions_field_wraps_explicit() {
        let exts = vec![basic_constraints(false, None)];
        let der = encode_extensions_field(&exts);
        // [3] EXPLICIT SEQUENCE { Extension }
        assert_eq!(der[0], tag::context(3));
    }
}
