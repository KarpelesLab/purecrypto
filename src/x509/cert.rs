//! X.509 certificate building, parsing, and verification.
//!
//! Signatures use RSA with PKCS#1 v1.5 over SHA-256
//! (`sha256WithRSAEncryption`).

use alloc::string::String;
use alloc::vec::Vec;

use super::extension::{self, Extension, GeneralName};
use super::{
    AnyPublicKey, CertSigner, CertificationRequest, DistinguishedName, Error, Validity,
    algorithm_identifier, oid,
};
use crate::der::{
    Reader, encode_bit_string, encode_context, encode_integer, encode_sequence, parse_oid,
    pem_decode, pem_encode, tag,
};
use crate::hash::Sha256;
use crate::rsa::{RsaPrivateKey, RsaPublicKey};

const PEM_LABEL: &str = "CERTIFICATE";

/// A parsed/owned X.509 certificate, stored as its DER encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
}

/// The three top-level fields of a `Certificate`.
struct CertParts<'a> {
    /// Raw `TBSCertificate` element (tag-length-value), used for signing.
    tbs: &'a [u8],
    /// `signatureAlgorithm` OID arcs.
    sig_alg: Vec<u64>,
    /// Signature bits.
    signature: &'a [u8],
}

/// Encodes an RSA `SubjectPublicKeyInfo`.
fn rsa_spki<const LIMBS: usize>(pk: &RsaPublicKey<LIMBS>) -> Vec<u8> {
    let algid = algorithm_identifier(oid::RSA_ENCRYPTION, true);
    let key = pk.to_pkcs1_der();
    encode_sequence(&[algid, encode_bit_string(&key)].concat())
}

/// Translates the legacy `(is_ca, sans)` shape into a fresh [`Extension`]
/// vector: critical basicConstraints + (when non-empty) non-critical
/// subjectAltName. Each `sans` string is auto-routed to the correct
/// GeneralName variant by shape: an IPv4 dotted-quad becomes iPAddress
/// (`[7]` 4-byte form); any other string goes into dNSName (`[2]`). IPv6
/// strings require the explicit `GeneralName::IpV6` form via a caller
/// that builds extensions directly — this helper handles only IPv4 and
/// hostnames because that's what the existing `&[&str]` callers use.
pub(crate) fn legacy_extensions(is_ca: bool, sans: &[&str]) -> Vec<Extension> {
    let mut v = Vec::new();
    v.push(extension::basic_constraints(is_ca, None));
    if !sans.is_empty() {
        let names: Vec<GeneralName> = sans
            .iter()
            .map(|s| {
                if let Some(v4) = parse_ipv4(s) {
                    GeneralName::IpV4(v4)
                } else {
                    GeneralName::Dns((*s).into())
                }
            })
            .collect();
        v.push(extension::subject_alt_name(&names));
    }
    v
}

/// Encodes the `[3] Extensions` field for an arbitrary slice of extensions.
fn extensions_explicit(exts: &[Extension]) -> Vec<u8> {
    extension::encode_extensions_field(exts)
}

/// Builds the DER `TBSCertificate` from a pre-encoded subject
/// `SubjectPublicKeyInfo`, inner `signature` AlgorithmIdentifier, and an
/// arbitrary slice of v3 extensions.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_tbs_raw(
    serial: u64,
    issuer: &DistinguishedName,
    subject: &DistinguishedName,
    validity: &Validity,
    spki_der: &[u8],
    sig_algid: &[u8],
    extensions: &[Extension],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_context(0, &encode_integer(&[2]))); // version v3
    body.extend_from_slice(&encode_integer(&serial.to_be_bytes()));
    body.extend_from_slice(sig_algid);
    body.extend_from_slice(&issuer.to_der());
    body.extend_from_slice(&validity.to_der());
    body.extend_from_slice(&subject.to_der());
    body.extend_from_slice(spki_der);
    body.extend_from_slice(&extensions_explicit(extensions));
    encode_sequence(&body)
}

/// Builds the DER `TBSCertificate` for an RSA subject key (SHA-256 with RSA).
#[allow(clippy::too_many_arguments)]
fn build_tbs<const LIMBS: usize>(
    serial: u64,
    issuer: &DistinguishedName,
    subject: &DistinguishedName,
    validity: &Validity,
    subject_key: &RsaPublicKey<LIMBS>,
    is_ca: bool,
    dns_names: &[&str],
) -> Vec<u8> {
    let exts = legacy_extensions(is_ca, dns_names);
    build_tbs_raw(
        serial,
        issuer,
        subject,
        validity,
        &rsa_spki(subject_key),
        &algorithm_identifier(oid::SHA256_WITH_RSA, true),
        &exts,
    )
}

impl Certificate {
    /// Issues a certificate for `subject_key`, signed by `issuer_key` under
    /// `issuer` (use the same key/name for a self-signed certificate). Uses
    /// SHA-256 with RSA PKCS#1 v1.5.
    pub fn issue<const LIMBS: usize>(
        issuer_key: &RsaPrivateKey<LIMBS>,
        issuer: &DistinguishedName,
        subject: &DistinguishedName,
        subject_key: &RsaPublicKey<LIMBS>,
        validity: &Validity,
        serial: u64,
        is_ca: bool,
    ) -> Result<Certificate, Error> {
        Self::issue_with_sans(
            issuer_key,
            issuer,
            subject,
            subject_key,
            validity,
            serial,
            is_ca,
            &[],
        )
    }

    /// Like [`issue`](Self::issue) but adds a `subjectAltName` extension with
    /// the given dNSName entries (the modern way to bind host names).
    #[allow(clippy::too_many_arguments)]
    pub fn issue_with_sans<const LIMBS: usize>(
        issuer_key: &RsaPrivateKey<LIMBS>,
        issuer: &DistinguishedName,
        subject: &DistinguishedName,
        subject_key: &RsaPublicKey<LIMBS>,
        validity: &Validity,
        serial: u64,
        is_ca: bool,
        dns_names: &[&str],
    ) -> Result<Certificate, Error> {
        let tbs = build_tbs(
            serial,
            issuer,
            subject,
            validity,
            subject_key,
            is_ca,
            dns_names,
        );
        let sig = issuer_key.sign_pkcs1v15::<Sha256>(&tbs)?;
        let der = encode_sequence(
            &[
                tbs,
                algorithm_identifier(oid::SHA256_WITH_RSA, true),
                encode_bit_string(&sig),
            ]
            .concat(),
        );
        Ok(Certificate { der })
    }

    /// Issues a self-signed certificate (issuer == subject, signed by `key`).
    pub fn self_signed<const LIMBS: usize>(
        key: &RsaPrivateKey<LIMBS>,
        subject: &DistinguishedName,
        validity: &Validity,
        serial: u64,
        is_ca: bool,
    ) -> Result<Certificate, Error> {
        Self::issue(
            key,
            subject,
            subject,
            &key.public_key(),
            validity,
            serial,
            is_ca,
        )
    }

    /// Issues a self-signed certificate carrying a `subjectAltName` with the
    /// given dNSName entries.
    pub fn self_signed_with_sans<const LIMBS: usize>(
        key: &RsaPrivateKey<LIMBS>,
        subject: &DistinguishedName,
        validity: &Validity,
        serial: u64,
        is_ca: bool,
        dns_names: &[&str],
    ) -> Result<Certificate, Error> {
        Self::issue_with_sans(
            key,
            subject,
            subject,
            &key.public_key(),
            validity,
            serial,
            is_ca,
            dns_names,
        )
    }

    /// Issues a certificate signed by `signer` (RSA or ECDSA), binding
    /// `subject` to `subject_key`. This is the general form behind the RSA-only
    /// [`issue`](Self::issue): the subject key may be any [`AnyPublicKey`] and
    /// the CA key any [`CertSigner`].
    #[allow(clippy::too_many_arguments)]
    pub fn issue_general(
        signer: &CertSigner,
        issuer: &DistinguishedName,
        subject: &DistinguishedName,
        subject_key: &AnyPublicKey,
        validity: &Validity,
        serial: u64,
        is_ca: bool,
        dns_names: &[&str],
    ) -> Result<Certificate, Error> {
        let exts = legacy_extensions(is_ca, dns_names);
        Self::issue_with_extensions(
            signer,
            issuer,
            subject,
            subject_key,
            validity,
            serial,
            &exts,
        )
    }

    /// Issues a certificate carrying an arbitrary slice of v3 extensions.
    ///
    /// This is the broadest entry point — every other `issue_*` helper is
    /// either a wrapper around it ([`issue_general`](Self::issue_general)
    /// translates `is_ca`/`dns_names` into a default extension vector and
    /// calls into here) or a thin RSA-only convenience.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_with_extensions(
        signer: &CertSigner,
        issuer: &DistinguishedName,
        subject: &DistinguishedName,
        subject_key: &AnyPublicKey,
        validity: &Validity,
        serial: u64,
        extensions: &[Extension],
    ) -> Result<Certificate, Error> {
        let algid = signer.algorithm_identifier();
        let tbs = build_tbs_raw(
            serial,
            issuer,
            subject,
            validity,
            &subject_key.to_spki_der(),
            &algid,
            extensions,
        );
        let sig = signer.sign(&tbs)?;
        let der = encode_sequence(&[tbs, algid, encode_bit_string(&sig)].concat());
        Ok(Certificate { der })
    }

    /// Issues a self-signed certificate (issuer == subject, signed by `signer`)
    /// carrying an arbitrary slice of v3 extensions.
    pub fn self_signed_with_extensions(
        signer: &CertSigner,
        subject: &DistinguishedName,
        validity: &Validity,
        serial: u64,
        extensions: &[Extension],
    ) -> Result<Certificate, Error> {
        let key = signer.public_key();
        Self::issue_with_extensions(signer, subject, subject, &key, validity, serial, extensions)
    }

    /// Issues a self-signed certificate using `signer` for both the key and the
    /// signature (RSA or ECDSA).
    pub fn self_signed_general(
        signer: &CertSigner,
        subject: &DistinguishedName,
        validity: &Validity,
        serial: u64,
        is_ca: bool,
        dns_names: &[&str],
    ) -> Result<Certificate, Error> {
        let key = signer.public_key();
        Self::issue_general(
            signer, subject, subject, &key, validity, serial, is_ca, dns_names,
        )
    }

    /// Issues a certificate from a verified PKCS#10 [`CertificationRequest`].
    ///
    /// The CSR's self-signature is checked first; the new certificate takes its
    /// subject, public key, and `subjectAltName` dNSNames from the request, and
    /// is signed by `signer` under `issuer`.
    pub fn issue_from_csr(
        signer: &CertSigner,
        issuer: &DistinguishedName,
        csr: &CertificationRequest,
        validity: &Validity,
        serial: u64,
        is_ca: bool,
    ) -> Result<Certificate, Error> {
        csr.verify_self_signed()?;
        let subject = csr.subject()?;
        let subject_key = csr.public_key()?;
        let sans = csr.subject_alt_names()?;
        let san_refs: Vec<&str> = sans.iter().map(|s| s.as_str()).collect();
        Self::issue_general(
            signer,
            issuer,
            &subject,
            &subject_key,
            validity,
            serial,
            is_ca,
            &san_refs,
        )
    }

    /// Wraps existing certificate DER (validating only that it is a single
    /// SEQUENCE with no trailing bytes). Rejecting trailing junk is
    /// important so `to_der()` returns the same bytes a hash of the cert
    /// would commit to — two implementations parsing the same blob agree.
    pub fn from_der(der: Vec<u8>) -> Result<Certificate, Error> {
        let mut r = Reader::new(&der);
        r.read_sequence()?;
        r.finish()?;
        Ok(Certificate { der })
    }

    /// Parses a PEM `CERTIFICATE` document.
    pub fn from_pem(pem: &str) -> Result<Certificate, Error> {
        Ok(Certificate {
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

    /// Splits the outer certificate into its three top-level parts.
    fn parts(&self) -> Result<CertParts<'_>, Error> {
        let mut outer = Reader::new(&self.der);
        let mut cert = outer.read_sequence()?;
        let tbs = cert.read_element()?;
        let mut alg = cert.read_sequence()?;
        let sig_alg = parse_oid(alg.read_oid()?)?;
        let signature = cert.read_bit_string()?;
        // Strict DER (X.690 §11): no trailing bytes inside the outer
        // SEQUENCE. Two parsers must agree on what was signed; trailing
        // junk inside the wrapper is both a covert channel and a
        // fingerprint-collision risk.
        cert.finish()?;
        Ok(CertParts {
            tbs,
            sig_alg,
            signature,
        })
    }

    /// Returns a sub-reader over the `TBSCertificate` contents, positioned at
    /// the issuer (version, serial, and inner signature algorithm skipped).
    fn tbs_after_algid(&self) -> Result<Reader<'_>, Error> {
        let tbs = self.parts()?.tbs;
        let mut outer = Reader::new(tbs);
        let mut seq = outer.read_sequence()?;
        if seq.peek_tag() == Some(tag::context(0)) {
            seq.read_tlv(tag::context(0))?; // version
        }
        seq.read_integer_bytes()?; // serialNumber
        seq.read_sequence()?; // inner signature AlgorithmIdentifier
        Ok(seq)
    }

    /// Returns the raw DER body of the certificate's `serialNumber` INTEGER
    /// (big-endian, strict-DER-canonical: at most one leading `0x00` to keep
    /// the value non-negative). Used to compare against CRL `userCertificate`
    /// entries during revocation checks.
    ///
    /// RFC 5280 §4.1.2.2 enforcement:
    /// * the value must be non-negative (handled by
    ///   [`Reader::read_unsigned_integer_bytes`], which rejects two's-
    ///   complement negatives at the DER layer);
    /// * the magnitude must fit in 20 octets — i.e. at most 20 value bytes,
    ///   plus an optional leading `0x00` sign byte when the high bit of the
    ///   first magnitude byte is set. CAs that issue 21+ octet serials are
    ///   non-conformant and have been used in past trust-store confusion
    ///   attacks to collide with shorter serials in CRL/OCSP comparisons.
    #[allow(dead_code)]
    pub(crate) fn serial_bytes(&self) -> Result<&[u8], Error> {
        let tbs = self.parts()?.tbs;
        let mut outer = Reader::new(tbs);
        let mut seq = outer.read_sequence()?;
        if seq.peek_tag() == Some(tag::context(0)) {
            seq.read_tlv(tag::context(0))?; // version
        }
        let body = seq.read_unsigned_integer_bytes()?;
        // Strip an optional leading 0x00 sign byte (present iff the next
        // byte's high bit is set; strict-DER guarantees no other leading
        // 0x00). The remaining "magnitude" bytes must be ≤ 20.
        let magnitude_len = match body {
            [0x00, rest @ ..] if !rest.is_empty() => rest.len(),
            other => other.len(),
        };
        if magnitude_len > 20 {
            return Err(Error::Malformed);
        }
        Ok(body)
    }

    /// Returns the DER bytes of the inner `signature` AlgorithmIdentifier
    /// inside `TBSCertificate` (RFC 5280 §4.1.2.3). The outer
    /// `signatureAlgorithm` MUST match these bytes byte-for-byte; a
    /// difference indicates an algorithm-substitution attempt and triggers
    /// rejection in [`check_signature_algid_consistent`].
    pub(crate) fn inner_signature_algid_der(&self) -> Result<&[u8], Error> {
        let tbs = self.parts()?.tbs;
        let mut outer = Reader::new(tbs);
        let mut seq = outer.read_sequence()?;
        if seq.peek_tag() == Some(tag::context(0)) {
            seq.read_tlv(tag::context(0))?;
        }
        seq.read_integer_bytes()?;
        let bytes = seq.read_element()?;
        Ok(bytes)
    }

    /// Returns the DER bytes of the outer `signatureAlgorithm`
    /// AlgorithmIdentifier (RFC 5280 §4.1.1.2).
    pub(crate) fn outer_signature_algid_der(&self) -> Result<&[u8], Error> {
        let mut outer = Reader::new(&self.der);
        let mut cert = outer.read_sequence()?;
        cert.read_element()?; // skip TBSCertificate
        let bytes = cert.read_element()?;
        Ok(bytes)
    }

    /// RFC 5280 §4.1.1.2: the inner and outer signature AlgorithmIdentifier
    /// fields MUST be identical. We compare the raw DER (parameters
    /// included), which catches both OID and parameter mismatches.
    pub(crate) fn check_signature_algid_consistent(&self) -> Result<(), Error> {
        let inner = self.inner_signature_algid_der()?;
        let outer = self.outer_signature_algid_der()?;
        if inner == outer {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    /// The certificate issuer.
    pub fn issuer(&self) -> Result<DistinguishedName, Error> {
        let mut seq = self.tbs_after_algid()?;
        DistinguishedName::decode(&mut seq)
    }

    /// The raw DER bytes of the certificate's `issuer` field — the full
    /// `Name` TLV (`30 LL …`). Used for byte-exact chain-building matches
    /// (RFC 5280 §7.1 requires byte equality for issuer/subject linking).
    pub(crate) fn issuer_der(&self) -> Result<&[u8], Error> {
        let mut seq = self.tbs_after_algid()?;
        let bytes = seq.read_element()?;
        Ok(bytes)
    }

    /// The certificate subject.
    pub fn subject(&self) -> Result<DistinguishedName, Error> {
        let mut seq = self.tbs_after_algid()?;
        DistinguishedName::decode(&mut seq)?; // issuer
        Validity::decode(&mut seq)?; // validity
        DistinguishedName::decode(&mut seq)
    }

    /// The raw DER bytes of the certificate's `subject` field — the full
    /// `Name` TLV. Used for byte-exact chain-building matches.
    pub(crate) fn subject_der(&self) -> Result<&[u8], Error> {
        let mut seq = self.tbs_after_algid()?;
        seq.read_element()?; // issuer
        seq.read_element()?; // validity
        let bytes = seq.read_element()?;
        Ok(bytes)
    }

    /// The subject's RSA public key. `LIMBS` must match the key's modulus size.
    pub fn public_key<const LIMBS: usize>(&self) -> Result<RsaPublicKey<LIMBS>, Error> {
        let mut seq = self.tbs_after_algid()?;
        DistinguishedName::decode(&mut seq)?; // issuer
        Validity::decode(&mut seq)?; // validity
        DistinguishedName::decode(&mut seq)?; // subject
        let mut spki = seq.read_sequence()?;
        let alg = parse_oid(spki.read_sequence()?.read_oid()?)?;
        if alg.as_slice() != oid::RSA_ENCRYPTION {
            return Err(Error::UnsupportedAlgorithm);
        }
        let key_der = spki.read_bit_string()?;
        Ok(RsaPublicKey::from_pkcs1_der(key_der)?)
    }

    /// Verifies the certificate signature against `issuer_key`. Only
    /// `sha256WithRSAEncryption` is supported.
    pub fn verify_signature<const LIMBS: usize>(
        &self,
        issuer_key: &RsaPublicKey<LIMBS>,
    ) -> Result<(), Error> {
        let parts = self.parts()?;
        if parts.sig_alg.as_slice() != oid::SHA256_WITH_RSA {
            return Err(Error::UnsupportedAlgorithm);
        }
        issuer_key.verify_pkcs1v15::<Sha256>(parts.tbs, parts.signature)?;
        Ok(())
    }

    /// The subject's public key as an algorithm-agnostic [`AnyPublicKey`]
    /// (RSA of any size, or P-256 ECDSA).
    pub fn subject_public_key(&self) -> Result<super::AnyPublicKey, Error> {
        let mut seq = self.tbs_after_algid()?;
        DistinguishedName::decode(&mut seq)?; // issuer
        Validity::decode(&mut seq)?; // validity
        DistinguishedName::decode(&mut seq)?; // subject
        let spki = seq.read_element()?; // full SubjectPublicKeyInfo
        super::AnyPublicKey::from_spki_der(spki)
    }

    /// The raw value of the `subjectPublicKey` BIT STRING (the key bits,
    /// with the leading unused-bits octet stripped, exactly as the wire
    /// carried them). Used to compute the `issuerKeyHash` field of an OCSP
    /// `CertID` (RFC 6960 §4.1.1): the hash MUST be over the SubjectPublicKey
    /// BIT STRING's value content excluding the tag, length, and number-of-
    /// unused-bits octets.
    #[allow(dead_code)]
    pub(crate) fn subject_public_key_bits(&self) -> Result<&[u8], Error> {
        let mut seq = self.tbs_after_algid()?;
        DistinguishedName::decode(&mut seq)?; // issuer
        Validity::decode(&mut seq)?; // validity
        DistinguishedName::decode(&mut seq)?; // subject
        let spki = seq.read_element()?; // full SubjectPublicKeyInfo TLV
        let mut spki_r = Reader::new(spki);
        let mut spki_seq = spki_r.read_sequence()?;
        spki_seq.read_sequence()?; // algid
        Ok(spki_seq.read_bit_string()?)
    }

    /// Verifies the certificate signature against `issuer`, dispatching on the
    /// certificate's `signatureAlgorithm` (RSA-PKCS#1 or ECDSA over SHA-256/384).
    pub fn verify_signature_with(&self, issuer: &super::AnyPublicKey) -> Result<(), Error> {
        let parts = self.parts()?;
        issuer.verify(&parts.sig_alg, parts.tbs, parts.signature)
    }

    /// The OID arcs of the certificate's outer `signatureAlgorithm` field.
    /// Useful for routing the verify through the signature-algorithm registry
    /// or for inspection (e.g. CLI tooling printing a chain).
    pub fn signature_algorithm_oid(&self) -> Result<Vec<u64>, Error> {
        Ok(self.parts()?.sig_alg)
    }

    /// The certificate's validity period (`notBefore` / `notAfter`).
    pub fn validity(&self) -> Result<Validity, Error> {
        let mut seq = self.tbs_after_algid()?;
        DistinguishedName::decode(&mut seq)?; // issuer
        Validity::decode(&mut seq)
    }

    /// The dNSName entries of the `subjectAltName` extension, or an empty list
    /// if the certificate has no such extension.
    pub fn subject_alt_names(&self) -> Result<Vec<String>, Error> {
        let mut names = Vec::new();
        self.walk_extensions(|id, _critical, value| {
            if id == oid::SUBJECT_ALT_NAME {
                parse_dns_names(value, &mut names)?;
            }
            Ok(())
        })?;
        Ok(names)
    }

    /// The iPAddress entries of the `subjectAltName` extension, returned as
    /// the canonical 4-byte (IPv4) or 16-byte (IPv6) octet strings per
    /// RFC 5280 §4.2.1.6.
    ///
    /// IPv4-mapped-IPv6 addresses (`::ffff:0.0.0.0/96` — 16-byte entries
    /// whose first 10 bytes are zero and bytes 10..12 are `0xff 0xff`)
    /// are rejected: the host-level TCP/IP stack treats them as the
    /// embedded IPv4, but a name-constraints checker comparing 16-byte
    /// blobs would not. To avoid that scope confusion this accessor
    /// refuses to surface them at all; senders that genuinely mean to
    /// bind the IPv4 address should put it in a 4-byte iPAddress entry
    /// instead.
    pub fn subject_alt_ips(&self) -> Result<Vec<SanIp>, Error> {
        let mut out = Vec::new();
        self.walk_extensions(|id, _critical, value| {
            if id == oid::SUBJECT_ALT_NAME {
                parse_ip_addresses(value, &mut out)?;
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Returns `(is_ca, path_len_constraint)` from the `basicConstraints`
    /// extension, or `None` if the certificate has none. `path_len_constraint`
    /// is `None` when omitted (i.e. unlimited).
    pub fn basic_constraints(&self) -> Result<Option<(bool, Option<u32>)>, Error> {
        let mut out = None;
        self.walk_extensions(|id, _critical, value| {
            if id == oid::BASIC_CONSTRAINTS {
                let mut r = Reader::new(value);
                let mut seq = r.read_sequence()?;
                let is_ca = if seq.peek_tag() == Some(tag::BOOLEAN) {
                    seq.read_boolean()?
                } else {
                    false
                };
                let path_len = if !seq.is_empty() {
                    // Strict-DER unsigned INTEGER: no leading sign byte
                    // unnecessarily, no negative encodings, no empty body.
                    // `pathLenConstraint` must fit in u32 — reject ≥ 5 bytes
                    // (after the at-most-one permitted leading 0x00) before
                    // accumulation rather than relying on `checked_shl`,
                    // which doesn't detect value overflow (RFC 5280 §4.2.1.9).
                    let bytes = seq.read_unsigned_integer_bytes()?;
                    // Strip the at-most-one permitted leading 0x00.
                    let mag = if bytes.len() > 1 && bytes[0] == 0x00 {
                        &bytes[1..]
                    } else {
                        bytes
                    };
                    if mag.len() > 4 {
                        return Err(Error::Malformed);
                    }
                    let mut v: u32 = 0;
                    for &b in mag {
                        v = (v << 8) | b as u32;
                    }
                    Some(v)
                } else {
                    None
                };
                out = Some((is_ca, path_len));
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Returns the parsed `nameConstraints` extension (RFC 5280 §4.2.1.10),
    /// or `None` if the certificate has none. Only the dNSName and iPAddress
    /// variants are surfaced — any other GeneralName variant inside the
    /// constraint causes [`NameConstraints::has_unenforceable_permitted`]
    /// (or the excluded counterpart) to be set so the chain validator can
    /// fail closed on critical constraints it can't fully evaluate.
    pub fn name_constraints(&self) -> Result<Option<NameConstraints>, Error> {
        let mut out: Option<NameConstraints> = None;
        self.walk_extensions(|id, _critical, value| {
            if id == oid::NAME_CONSTRAINTS {
                out = Some(parse_name_constraints(value)?);
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Returns the `keyUsage` bit-mask, or `None` if the certificate has no
    /// such extension. The mask is read MSB-first per BIT STRING wire order:
    /// `keyUsage` bit 0 (`digitalSignature`) appears in `mask & 0x80`,
    /// bit 5 (`keyCertSign`) in `mask & 0x04`, etc.
    pub fn key_usage(&self) -> Result<Option<u16>, Error> {
        let mut out = None;
        self.walk_extensions(|id, _critical, value| {
            if id == oid::KEY_USAGE {
                // Parse the BIT STRING manually so we accept non-zero unused-
                // bits prefixes (the `Reader::read_bit_string` helper only
                // handles `unused_bits == 0`, which is fine for SPKI keys but
                // not for `keyUsage`).
                let mut r = Reader::new(value);
                let raw = r.read_tlv(tag::BIT_STRING)?;
                if raw.is_empty() {
                    return Err(Error::Malformed);
                }
                // X.690 §8.6.2.2: `unused_bits` is in the range 0..=7.
                if raw[0] > 7 {
                    return Err(Error::Malformed);
                }
                let _unused = raw[0];
                let bytes = &raw[1..];
                let mut mask: u16 = 0;
                if !bytes.is_empty() {
                    mask |= bytes[0] as u16;
                }
                if bytes.len() > 1 {
                    mask |= (bytes[1] as u16) << 8;
                }
                out = Some(mask);
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Returns the OIDs in the `extKeyUsage` extension, or an empty list if
    /// absent.
    pub fn extended_key_usages(&self) -> Result<Vec<Vec<u64>>, Error> {
        let mut out = Vec::new();
        self.walk_extensions(|id, _critical, value| {
            if id == oid::EXT_KEY_USAGE {
                let mut r = Reader::new(value);
                let mut seq = r.read_sequence()?;
                while !seq.is_empty() {
                    let raw = seq.read_oid()?;
                    out.push(parse_oid(raw)?);
                }
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Returns every v3 extension carried by this certificate, in order.
    /// Used by the CLI's `x509 -text -ext` dump and the chain validator
    /// for unknown-critical detection.
    pub fn extensions(&self) -> Result<Vec<Extension>, Error> {
        let mut out = Vec::new();
        self.walk_extensions(|id, critical, value| {
            out.push(Extension {
                oid: id.to_vec(),
                critical,
                value: value.to_vec(),
            });
            Ok(())
        })?;
        Ok(out)
    }

    /// Walks the certificate's extensions and returns the OIDs of every entry
    /// marked `critical = true`. Used by chain validation to enforce RFC 5280
    /// §4.2: any critical extension the verifier doesn't understand must
    /// cause the certificate to be rejected.
    pub(crate) fn critical_extension_oids(&self) -> Result<Vec<Vec<u64>>, Error> {
        let mut out = Vec::new();
        self.walk_extensions(|id, critical, _value| {
            if critical {
                out.push(id.to_vec());
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Walks the certificate's `extensions` field, calling `f(oid, critical,
    /// value)` for each entry. Returns `Ok(())` if the certificate has no
    /// extensions block at all.
    fn walk_extensions(
        &self,
        mut f: impl FnMut(&[u64], bool, &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        // RFC 5280 §4.1.2.1: the extensions field MUST only be present when
        // version is v3 (`INTEGER 2`). Re-parse the version field from the
        // raw TBSCertificate so we can enforce this constraint regardless
        // of what `tbs_after_algid` chose to skip.
        let tbs_bytes = self.parts()?.tbs;
        let version = {
            let mut outer = Reader::new(tbs_bytes);
            let mut seq = outer.read_sequence()?;
            if seq.peek_tag() == Some(tag::context(0)) {
                let body = seq.read_tlv(tag::context(0))?;
                let mut vr = Reader::new(body);
                let v = vr.read_integer_bytes()?;
                vr.finish()?;
                // INTEGER 0 ⇒ v1, INTEGER 1 ⇒ v2, INTEGER 2 ⇒ v3.
                match v {
                    [0] => 1u8,
                    [1] => 2u8,
                    [2] => 3u8,
                    _ => return Err(Error::Malformed),
                }
            } else {
                // Default is v1 when the version field is absent.
                1u8
            }
        };

        let mut seq = self.tbs_after_algid()?;
        DistinguishedName::decode(&mut seq)?; // issuer
        Validity::decode(&mut seq)?; // validity
        DistinguishedName::decode(&mut seq)?; // subject
        seq.read_element()?; // subjectPublicKeyInfo

        // Skip the optional issuerUniqueID [1] and subjectUniqueID [2]
        // (IMPLICIT primitive context tags 0x81 / 0x82). RFC 5280 §4.1.2.8
        // permits these in v2 / v3 only — a v1 cert carrying them is
        // malformed, and we will reject any v1/v2 cert that exposes an
        // extensions block below anyway.
        while matches!(seq.peek_tag(), Some(0x81) | Some(0x82)) {
            seq.read_element()?;
        }
        // The [3] EXPLICIT extensions wrapper (constructed context tag 0xA3).
        if seq.peek_tag() != Some(tag::context(3)) {
            return Ok(());
        }
        // RFC 5280 §4.1.2.1: extensions MUST only appear in v3 certificates.
        // Reject any v1 / v2 certificate that carries an `[3] extensions`
        // block — historically a downgrade vector when a verifier was
        // lulled into reading critical extensions (basicConstraints,
        // keyUsage, …) from a cert it then treated as pre-v3 and so
        // exempted from extension-driven policy.
        if version < 3 {
            return Err(Error::Malformed);
        }
        let wrapper = seq.read_tlv(tag::context(3))?;
        let mut outer = Reader::new(wrapper);
        let mut exts = outer.read_sequence()?;

        // RFC 5280 §4.2: "A certificate MUST NOT include more than one
        // instance of a particular extension." Track seen OIDs and reject
        // a duplicate at the first repetition. Without this check, two
        // parsers that disagree on which copy wins (the first or the last)
        // can be steered to opposite policy decisions on the same cert —
        // the classic CVE-2014-1568 / CVE-2020-0601 shape.
        let mut seen: Vec<Vec<u64>> = Vec::new();
        while !exts.is_empty() {
            let mut ext = exts.read_sequence()?;
            let id = parse_oid(ext.read_oid()?)?;
            if seen.iter().any(|prior| prior.as_slice() == id.as_slice()) {
                return Err(Error::Malformed);
            }
            seen.push(id.clone());
            let critical = if ext.peek_tag() == Some(tag::BOOLEAN) {
                ext.read_boolean()?
            } else {
                false
            };
            let value = ext.read_octet_string()?;
            f(&id, critical, value)?;
        }
        Ok(())
    }

    /// Checks that the certificate is structurally well-formed: the outer
    /// SEQUENCE, signature algorithm and value, and every parsed `TBSCertificate`
    /// field (issuer, validity, subject, SPKI, extensions). Returns
    /// [`Error::Malformed`] on any structural defect.
    pub fn check_well_formed(&self) -> Result<(), Error> {
        self.parts()?; // outer structure: tbs, signatureAlgorithm, signature
        self.issuer()?;
        self.validity()?;
        self.subject()?;
        self.subject_alt_names()?; // walks SPKI + extensions
        Ok(())
    }
}

/// Parses a `SubjectAltName` value (`SEQUENCE OF GeneralName`), collecting
/// the dNSName (`[2] IA5String`, tag 0x82) entries.
///
/// The validation here is intentionally strict beyond a literal reading of
/// RFC 5280 §4.2.1.6 (which only requires IA5). Each entry must additionally:
///
/// * be non-empty (zero-length dNSName entries are nonsense and exist only
///   to confuse downstream matchers);
/// * contain only printable ASCII (`0x20..=0x7E`) — control characters
///   (including NUL) are rejected to defeat embedded-NUL host confusion in
///   any consumer that forwards the parsed `String` across an FFI boundary
///   or into a log line that splits on `\n`;
/// * NOT be an IP literal in disguise. RFC 6125 §6.5.2: implementations
///   "MUST NOT seek a match for a reference identifier of CN-ID or DNS-ID
///   if the presented identifiers include an IP address". The cheapest way
///   to enforce that is at parse time: dNSName entries shaped like an IPv4
///   dotted-quad or containing a colon (any IPv6 form) are rejected here
///   so they can never reach the hostname matcher. IPs belong in the
///   iPAddress (`[7]`) slot — see [`Certificate::subject_alt_ips`].
pub(super) fn parse_dns_names(der: &[u8], out: &mut Vec<String>) -> Result<(), Error> {
    let mut reader = Reader::new(der);
    let mut seq = reader.read_sequence()?;
    while !seq.is_empty() {
        let (t, value) = seq.read_any()?;
        if t == 0x82 {
            if value.is_empty() {
                return Err(Error::Malformed);
            }
            for &b in value {
                // Reject non-ASCII, control characters (incl. NUL), and DEL.
                if !(0x20..=0x7E).contains(&b) {
                    return Err(Error::Malformed);
                }
            }
            // SAFETY of unwrap: every byte is 0x20..=0x7E, which is valid UTF-8.
            let s = core::str::from_utf8(value).map_err(|_| Error::Malformed)?;
            if looks_like_ip_literal(s) {
                return Err(Error::Malformed);
            }
            out.push(String::from(s));
        }
    }
    Ok(())
}

/// An iPAddress SAN entry surfaced from a parsed cert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SanIp {
    /// 4-byte IPv4 address as stored in the SAN.
    V4([u8; 4]),
    /// 16-byte IPv6 address (an IPv4-mapped form is rejected at parse
    /// time and never appears here).
    V6([u8; 16]),
}

/// Parses iPAddress (`[7] OCTET STRING`, tag 0x87) entries from a SAN
/// extension body. 4-byte entries are returned as `V4`; 16-byte entries
/// as `V6`, with IPv4-mapped-IPv6 (`::ffff:0.0.0.0/96`) rejected as
/// Malformed.
fn parse_ip_addresses(der: &[u8], out: &mut Vec<SanIp>) -> Result<(), Error> {
    let mut reader = Reader::new(der);
    let mut seq = reader.read_sequence()?;
    while !seq.is_empty() {
        let (t, value) = seq.read_any()?;
        if t == 0x87 {
            match value.len() {
                4 => {
                    let mut v = [0u8; 4];
                    v.copy_from_slice(value);
                    out.push(SanIp::V4(v));
                }
                16 => {
                    // RFC 4291 §2.5.5.2 IPv4-mapped-IPv6 form
                    // `::ffff:0.0.0.0/96`: first 10 bytes zero, bytes
                    // 10..12 = 0xff 0xff. The host stack treats it as
                    // the IPv4 in bytes 12..16, but a 16-byte
                    // comparator does not — so we refuse to surface it.
                    if value[..10].iter().all(|&b| b == 0) && value[10] == 0xff && value[11] == 0xff
                    {
                        return Err(Error::Malformed);
                    }
                    let mut v = [0u8; 16];
                    v.copy_from_slice(value);
                    out.push(SanIp::V6(v));
                }
                _ => return Err(Error::Malformed),
            }
        }
    }
    Ok(())
}

/// True if `s` is shaped like an IP literal — either an IPv4 dotted-quad
/// of 1-3-digit labels, or any string containing a colon (IPv6 in any
/// form). Used at both parse time (defense-in-depth: dNSName entries that
/// look like IPs are rejected outright) and at SAN-build time (route a
/// caller-supplied IP-shaped string into the iPAddress slot).
pub(crate) fn looks_like_ip_literal(s: &str) -> bool {
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

/// Parses an IPv4 dotted-quad string into 4 bytes. Returns `None` for
/// anything that is not exactly four decimal labels in `0..=255`.
pub(crate) fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut count = 0usize;
    for label in s.split('.') {
        if count >= 4 {
            return None;
        }
        let n: u32 = label.parse().ok()?;
        if n > 255 {
            return None;
        }
        out[count] = n as u8;
        count += 1;
    }
    if count != 4 {
        return None;
    }
    Some(out)
}

/// Parsed `nameConstraints` extension (RFC 5280 §4.2.1.10).
///
/// The validator surfaces only the dNSName and iPAddress subtree types it
/// can evaluate; if any constraint mentions a different GeneralName variant
/// (otherName, directoryName, rfc822Name, uniformResourceIdentifier, …)
/// the corresponding `has_unenforceable_*` flag is set so the chain
/// validator can fail closed when the extension is critical.
#[derive(Clone, Debug, Default)]
pub struct NameConstraints {
    /// Permitted dNSName subtrees. An entry of `".example.com"` permits
    /// any host ending with `.example.com`; `"example.com"` permits that
    /// exact name plus any subdomain.
    pub permitted_dns: Vec<String>,
    /// Excluded dNSName subtrees, same shape.
    pub excluded_dns: Vec<String>,
    /// Permitted iPAddress subtrees as `(address_octets, mask_octets)`.
    /// IPv4 subtrees use 4-byte addr + 4-byte mask; IPv6 uses 16+16.
    pub permitted_ip: Vec<(Vec<u8>, Vec<u8>)>,
    /// Excluded iPAddress subtrees, same shape.
    pub excluded_ip: Vec<(Vec<u8>, Vec<u8>)>,
    /// Set if a permitted subtree references a GeneralName variant other
    /// than dNSName / iPAddress — the chain validator MUST reject the
    /// certificate when this is true and the extension is critical
    /// (RFC 5280 §4.2 fail-closed).
    pub has_unenforceable_permitted: bool,
    /// Same, for excluded subtrees.
    pub has_unenforceable_excluded: bool,
}

/// Parses a `nameConstraints` extension body (the inner SEQUENCE of
/// `permittedSubtrees [0] OPTIONAL` and `excludedSubtrees [1] OPTIONAL`).
fn parse_name_constraints(value: &[u8]) -> Result<NameConstraints, Error> {
    let mut out = NameConstraints::default();
    let mut r = Reader::new(value);
    let mut seq = r.read_sequence()?;
    // permittedSubtrees [0] IMPLICIT GeneralSubtrees → constructed tag 0xA0.
    if seq.peek_tag() == Some(tag::context(0)) {
        let body = seq.read_tlv(tag::context(0))?;
        parse_subtrees(
            body,
            &mut out.permitted_dns,
            &mut out.permitted_ip,
            &mut out.has_unenforceable_permitted,
        )?;
    }
    if seq.peek_tag() == Some(tag::context(1)) {
        let body = seq.read_tlv(tag::context(1))?;
        parse_subtrees(
            body,
            &mut out.excluded_dns,
            &mut out.excluded_ip,
            &mut out.has_unenforceable_excluded,
        )?;
    }
    seq.finish()?;
    r.finish()?;
    Ok(out)
}

/// True if `mask` is a valid CIDR (contiguous) subnet mask: zero or more
/// high-order 1-bits followed by zero or more low-order 0-bits, big-endian.
/// `0.0.0.0`, `255.255.255.255`, and every `/n` in between (0..=len*8) pass;
/// `0xff00ff00`, `0x80800000`, or any inverted / interleaved pattern fails.
fn is_contiguous_cidr_mask(mask: &[u8]) -> bool {
    // Treat the mask as a big-endian unsigned integer m. Then m is contiguous
    // iff `m & (m + 1) == 0` after byte-wise NOT-folding into a u128, which we
    // do per-octet to stay length-agnostic.
    let mut seen_zero = false;
    for &b in mask {
        if seen_zero && b != 0 {
            return false;
        }
        match b {
            0x00 => seen_zero = true,
            0xff => {}
            // Within a single byte the bits must be a high-run of 1s, so
            // !b + 1 must be a power of two (or zero).
            other => {
                seen_zero = true;
                let inv = !other;
                if inv & (inv.wrapping_add(1)) != 0 {
                    return false;
                }
            }
        }
    }
    true
}

/// Parses a `GeneralSubtrees` (`SEQUENCE OF GeneralSubtree`) body.
/// `GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] DEFAULT 0,
/// maximum [1] OPTIONAL }`. RFC 5280 §4.2.1.10 forbids both `minimum` (when
/// not zero) and `maximum` — we refuse anything non-default.
fn parse_subtrees(
    body: &[u8],
    dns_out: &mut Vec<String>,
    ip_out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    unenforceable: &mut bool,
) -> Result<(), Error> {
    let mut r = Reader::new(body);
    while !r.is_empty() {
        let mut subtree = r.read_sequence()?;
        let (t, value) = subtree.read_any()?;
        match t {
            // dNSName [2] IMPLICIT IA5String → primitive context 0x82.
            0x82 => {
                let s = core::str::from_utf8(value).map_err(|_| Error::Malformed)?;
                dns_out.push(String::from(s));
            }
            // iPAddress [7] IMPLICIT OCTET STRING → primitive context 0x87.
            // RFC 5280 §4.2.1.10: constraint is `address || mask`,
            // 8 bytes for IPv4 (4+4) or 32 bytes for IPv6 (16+16). The mask
            // MUST be in CIDR form — contiguous high-order 1-bits followed
            // by contiguous low-order 0-bits (RFC 5280 §4.2.1.10 cites
            // RFC 4632 for the CIDR notation). A non-contiguous mask such
            // as 0xff00ff00 is rejected; otherwise an issuing CA could
            // smuggle a constraint that matches in mask-space but rules
            // out hosts the operator never intended to forbid (or vice
            // versa).
            0x87 => match value.len() {
                8 | 32 => {
                    let half = value.len() / 2;
                    let mask = &value[half..];
                    if !is_contiguous_cidr_mask(mask) {
                        return Err(Error::Malformed);
                    }
                    ip_out.push((value[..half].to_vec(), mask.to_vec()));
                }
                _ => return Err(Error::Malformed),
            },
            // Any other GeneralName variant is something we can't evaluate.
            // RFC 5280 §4.2 fail-closed: signal it so the validator can
            // reject the chain when the extension is critical.
            _ => {
                *unenforceable = true;
            }
        }
        // RFC 5280 §4.2.1.10: minimum MUST be 0 (the DEFAULT); maximum MUST be
        // absent. Anything else is non-conformant.
        if !subtree.is_empty() {
            return Err(Error::Malformed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{rsa_test_key_a, rsa_test_key_b};
    use crate::x509::Time;
    use alloc::vec;

    fn validity() -> Validity {
        Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        )
    }

    #[test]
    fn self_signed_roundtrip_and_verify() {
        let key = rsa_test_key_a();
        let name =
            DistinguishedName::common_name("purecrypto test CA").with_organization("Karpelès Lab");

        let cert = Certificate::self_signed(&key, &name, &validity(), 1, true).unwrap();

        // Structure round-trips through PEM.
        let pem = cert.to_pem();
        assert_eq!(Certificate::from_pem(&pem).unwrap(), cert);

        // Fields parse back.
        assert_eq!(cert.subject().unwrap(), name);
        assert_eq!(cert.issuer().unwrap(), name);
        let parsed_key = cert.public_key::<32>().unwrap();
        assert_eq!(parsed_key, key.public_key());

        // The self-signature verifies with the embedded key.
        cert.verify_signature::<32>(&parsed_key).unwrap();
    }

    #[test]
    fn ca_signs_leaf() {
        let ca_key = rsa_test_key_a();
        let leaf_key = rsa_test_key_b();
        let ca_name = DistinguishedName::common_name("Root CA");
        let leaf_name = DistinguishedName::common_name("leaf.example");

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

        assert_eq!(leaf.subject().unwrap(), leaf_name);
        assert_eq!(leaf.issuer().unwrap(), ca_name);
        // Verifies under the CA key, not under the leaf's own key.
        leaf.verify_signature::<32>(&ca_key.public_key()).unwrap();
        assert!(leaf.verify_signature::<32>(&leaf_key.public_key()).is_err());
    }

    #[test]
    fn tampered_cert_fails_verification() {
        let key = rsa_test_key_a();
        let cert = Certificate::self_signed(
            &key,
            &DistinguishedName::common_name("x"),
            &validity(),
            1,
            true,
        )
        .unwrap();

        let mut der = cert.to_der().to_vec();
        // Flip a byte inside the TBS.
        let idx = der.len() / 3;
        der[idx] ^= 1;
        let bad = Certificate::from_der(der).unwrap();
        assert!(bad.verify_signature::<32>(&key.public_key()).is_err());
    }

    // A P-256 ECDSA self-signed certificate produced by OpenSSL
    // (`openssl req -x509`, ecdsa-with-SHA256).
    const OPENSSL_EC_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBjjCCATWgAwIBAgIUdDq5AMJ2buWe3Zp8FzA8x1IJ/I4wCgYIKoZIzj0EAwIw\n\
HTEbMBkGA1UEAwwScHVyZWNyeXB0byBlYyB0ZXN0MB4XDTI2MDUyNTE1NTcwMloX\n\
DTM2MDUyMjE1NTcwMlowHTEbMBkGA1UEAwwScHVyZWNyeXB0byBlYyB0ZXN0MFkw\n\
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI/Rjb2Q5+virvsM30rQD4uAVpo5XDfzp\n\
6QEzGS5q032wAZMNKRyj79yAAFn9UwJzHjtFjQ8dexLQ+yFTHj994KNTMFEwHQYD\n\
VR0OBBYEFDkJ9uOVaokxPfzPjax49XgMM02PMB8GA1UdIwQYMBaAFDkJ9uOVaokx\n\
PfzPjax49XgMM02PMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIg\n\
RENTjAEB2yR6Dd5XY5jNxLqSJH4fJUKeGH8lMauQh7YCIGf8bBLXdk+nCnKjuiZw\n\
3sC6s2rrQa4gzDiVjwYM2ggX\n\
-----END CERTIFICATE-----\n";

    #[test]
    fn parse_and_verify_openssl_ec_cert() {
        let cert = Certificate::from_pem(OPENSSL_EC_CERT).unwrap();
        assert_eq!(
            cert.subject().unwrap(),
            DistinguishedName::common_name("purecrypto ec test")
        );
        let key = cert.subject_public_key().unwrap();
        assert!(matches!(key, crate::x509::AnyPublicKey::Ecdsa(_)));
        // Self-signed: verifies under its own embedded key.
        cert.verify_signature_with(&key).unwrap();
    }

    #[test]
    fn ec_self_signed_general() {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;

        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ec-ca", b"n", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let signer = crate::x509::CertSigner::Ecdsa(&key);
        let name = DistinguishedName::common_name("ec self-signed");

        let cert =
            Certificate::self_signed_general(&signer, &name, &validity(), 1, true, &[]).unwrap();

        assert_eq!(cert.subject().unwrap(), name);
        assert_eq!(cert.issuer().unwrap(), name);
        // The ecdsa-with-SHA256 self-signature verifies under the embedded key.
        let key = cert.subject_public_key().unwrap();
        assert!(matches!(key, crate::x509::AnyPublicKey::Ecdsa(_)));
        cert.verify_signature_with(&key).unwrap();
        cert.check_well_formed().unwrap();
    }

    #[test]
    fn validity_and_well_formed() {
        let key = rsa_test_key_a();
        let cert = Certificate::self_signed(
            &key,
            &DistinguishedName::common_name("x"),
            &validity(),
            1,
            false,
        )
        .unwrap();
        cert.check_well_formed().unwrap();
        let v = cert.validity().unwrap();
        assert_eq!(v.not_before, Time::utc(2024, 1, 1, 0, 0, 0));
        assert!(v.accepts(&Time::utc(2026, 5, 26, 0, 0, 0)));
        // No SAN extension on a plain self-signed cert.
        assert!(cert.subject_alt_names().unwrap().is_empty());
    }

    #[test]
    fn subject_alt_name_roundtrip() {
        let key = rsa_test_key_a();
        let cert = Certificate::self_signed_with_sans(
            &key,
            &DistinguishedName::common_name("ignored-cn"),
            &validity(),
            1,
            false,
            &["example.com", "*.example.com", "localhost"],
        )
        .unwrap();
        cert.check_well_formed().unwrap();
        assert_eq!(
            cert.subject_alt_names().unwrap(),
            ["example.com", "*.example.com", "localhost"]
        );
    }

    // An OpenSSL-issued P-384 self-signed certificate (ecdsa-with-SHA384) —
    // covers the parse + ECDSA-P-384 verification path offline.
    const OPENSSL_P384_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIB0DCCAVagAwIBAgIUFfDkHLsaJs8XpNp/X26eBwaW0GwwCgYIKoZIzj0EAwMw\n\
HzEdMBsGA1UEAwwUcHVyZWNyeXB0byBwMzg0IHRlc3QwHhcNMjYwNTI1MTc0MTA2\n\
WhcNMzYwNTIyMTc0MTA2WjAfMR0wGwYDVQQDDBRwdXJlY3J5cHRvIHAzODQgdGVz\n\
dDB2MBAGByqGSM49AgEGBSuBBAAiA2IABAaRzx9xN0xEjH+XylpvGcNzgATGjcJ5\n\
EG6ZcuaFhG77H9Mt9FZkSDSgExkKfyw4Ux+FucZyuqi/R1HAhvZQbsfDESwSzKaX\n\
eta82AAFlW21rNICGPlnbgcBWHdPRW75T6NTMFEwHQYDVR0OBBYEFMcuZqhquDSL\n\
HxHY+LHcSb+Q7JhiMB8GA1UdIwQYMBaAFMcuZqhquDSLHxHY+LHcSb+Q7JhiMA8G\n\
A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMDaAAwZQIxANhANplvbyG3UYpPKRBw\n\
zonaqEOgq726vkmse4rPtI3e2qssKRgyBnJ7eK3aw/QtZAIwN67oHB6vv9uYce3C\n\
ychU4nzuraYi2jNpgZhSF+plk2mEygHvRKTdSsvVFUfuVRIu\n\
-----END CERTIFICATE-----\n";

    #[test]
    fn issue_with_extensions_round_trip() {
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;
        use crate::x509::extension::{
            KeyUsageBits, basic_constraints, extended_key_usage, key_usage,
        };

        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ext-test", b"n", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let signer = crate::x509::CertSigner::Ecdsa(&key);
        let name = DistinguishedName::common_name("ext-cert");

        let exts = [
            basic_constraints(true, Some(0)),
            key_usage(KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN),
            extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
        ];
        let cert = Certificate::self_signed_with_extensions(&signer, &name, &validity(), 1, &exts)
            .unwrap();
        cert.check_well_formed().unwrap();

        // basic_constraints accessor reflects what we encoded.
        let bc = cert.basic_constraints().unwrap().unwrap();
        assert_eq!(bc, (true, Some(0)));
        // key_usage accessor sees the same wire mask.
        let ku = cert.key_usage().unwrap().unwrap();
        assert_eq!(ku, (KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN).0);
        // EKU survives.
        let eku = cert.extended_key_usages().unwrap();
        assert_eq!(eku, vec![oid::ID_KP_SERVER_AUTH.to_vec()]);
        // extensions() lists all three.
        let all = cert.extensions().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].oid, oid::BASIC_CONSTRAINTS);
        assert_eq!(all[1].oid, oid::KEY_USAGE);
        assert_eq!(all[2].oid, oid::EXT_KEY_USAGE);
        // Self-signature still verifies under the embedded key.
        let pk = cert.subject_public_key().unwrap();
        cert.verify_signature_with(&pk).unwrap();
    }

    #[test]
    fn key_usage_rejects_invalid_unused_bits() {
        // BIT STRING `unused_bits` is in 0..=7 (X.690 §8.6.2.2). Forge a
        // keyUsage extension with unused = 0xFF and confirm the accessor
        // refuses it.
        use crate::der::{encode_tlv, tag};
        use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
        use crate::rng::HmacDrbg;
        use crate::x509::extension::Extension;

        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ku-bad", b"n", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let signer = crate::x509::CertSigner::Ecdsa(&key);
        let name = DistinguishedName::common_name("ku-bad");

        // BIT STRING { unused=0xFF, bits=0x80 }: structurally a BIT STRING
        // (the parser reads the TLV), but `unused > 7` is illegal.
        let bad_bs = encode_tlv(tag::BIT_STRING, &[0xff, 0x80]);
        let ext = Extension {
            oid: oid::KEY_USAGE.to_vec(),
            critical: true,
            value: bad_bs,
        };
        let cert = Certificate::self_signed_with_extensions(&signer, &name, &validity(), 1, &[ext])
            .unwrap();
        assert!(matches!(cert.key_usage(), Err(Error::Malformed)));
    }

    #[test]
    fn parse_and_verify_openssl_p384_cert() {
        let cert = Certificate::from_pem(OPENSSL_P384_CERT).unwrap();
        cert.check_well_formed().unwrap();
        let key = cert.subject_public_key().unwrap();
        match &key {
            crate::x509::AnyPublicKey::Ecdsa(k) => {
                assert_eq!(k.curve(), crate::ec::CurveId::P384)
            }
            _ => panic!("expected ECDSA P-384"),
        }
        // Self-signed: the ecdsa-with-SHA384 signature verifies under its key.
        cert.verify_signature_with(&key).unwrap();
    }

    // H-6: strict DER (X.690 §11) — no trailing bytes inside the outer
    // SEQUENCE of a Certificate. Hand-build a cert wrapper that adds a
    // stray byte between the BIT STRING (signature) and the SEQUENCE
    // close; `from_der` lets it through (outer-only check) but `parts`,
    // which is what every accessor goes through, now rejects it.
    #[test]
    fn cert_rejects_intra_sequence_trailing_bytes() {
        use crate::der::{encode_sequence, encode_tlv};

        let key = rsa_test_key_a();
        let good = Certificate::self_signed(
            &key,
            &DistinguishedName::common_name("trail.example"),
            &validity(),
            1,
            false,
        )
        .unwrap();

        // Decompose the good cert's outer SEQUENCE into its three parts,
        // then re-encode with one extra (BOOLEAN false) TLV spliced in
        // before the close.
        let mut outer = Reader::new(good.to_der());
        let mut seq = outer.read_sequence().unwrap();
        let tbs = seq.read_element().unwrap();
        let algid = seq.read_element().unwrap();
        let sig_bit = seq.read_element().unwrap();
        // Stray trailer: a BOOLEAN(false). 0x01 / 0x01 / 0x00.
        let trailer = encode_tlv(0x01, &[0x00]);

        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(tbs);
        body.extend_from_slice(algid);
        body.extend_from_slice(sig_bit);
        body.extend_from_slice(&trailer);
        let tampered_der = encode_sequence(&body);

        // The outer SEQUENCE wrapper is well-formed, so from_der accepts —
        // but ANY accessor that goes through `parts()` now fails because
        // it calls `cert.finish()`.
        let tampered = Certificate::from_der(tampered_der).unwrap();
        assert!(tampered.subject().is_err());
        assert!(tampered.signature_algorithm_oid().is_err());
    }

    /// Builds a synthetic `SubjectAltName` extension body (the bytes that
    /// would sit inside the OCTET STRING wrapper of the v3 extension)
    /// containing a single dNSName entry with the supplied raw bytes.
    fn san_with_dns(value: &[u8]) -> alloc::vec::Vec<u8> {
        // GeneralName CHOICE [2] IMPLICIT IA5String  →  context tag 0x82.
        let mut entry = alloc::vec![0x82u8];
        // single-byte length (every test value is short).
        assert!(value.len() < 128, "test helper assumes short value");
        entry.push(value.len() as u8);
        entry.extend_from_slice(value);
        // Wrap in SEQUENCE.
        let mut seq = alloc::vec![0x30u8, entry.len() as u8];
        seq.extend_from_slice(&entry);
        seq
    }

    #[test]
    fn san_dns_parser_rejects_embedded_nul() {
        let der = san_with_dns(b"victim.example\x00attacker.example");
        let mut out = alloc::vec::Vec::new();
        assert!(super::parse_dns_names(&der, &mut out).is_err());
    }

    #[test]
    fn san_dns_parser_rejects_control_characters() {
        for bad in [
            b"victim.example\nattacker.example".as_slice(),
            b"victim.example\rinjection".as_slice(),
            b"victim.example\x01ctrl".as_slice(),
            b"victim.example\x7fdel".as_slice(),
        ] {
            let der = san_with_dns(bad);
            let mut out = alloc::vec::Vec::new();
            assert!(
                super::parse_dns_names(&der, &mut out).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn san_dns_parser_rejects_empty_entry() {
        let der = san_with_dns(b"");
        let mut out = alloc::vec::Vec::new();
        assert!(super::parse_dns_names(&der, &mut out).is_err());
    }

    #[test]
    fn san_dns_parser_rejects_ipv4_literal() {
        for bad in [
            b"10.0.0.1".as_slice(),
            b"127.0.0.1".as_slice(),
            b"255.255.255.255".as_slice(),
            b"0.0.0.0".as_slice(),
        ] {
            let der = san_with_dns(bad);
            let mut out = alloc::vec::Vec::new();
            assert!(
                super::parse_dns_names(&der, &mut out).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn san_dns_parser_rejects_ipv6_literal() {
        for bad in [
            b"::1".as_slice(),
            b"2001:db8::1".as_slice(),
            b"::ffff:10.0.0.1".as_slice(),
            b"fe80::1".as_slice(),
        ] {
            let der = san_with_dns(bad);
            let mut out = alloc::vec::Vec::new();
            assert!(
                super::parse_dns_names(&der, &mut out).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn san_dns_parser_accepts_normal_names() {
        for ok in [
            b"example.com".as_slice(),
            b"www.example.com".as_slice(),
            b"*.example.com".as_slice(),
            b"xn--bcher-kva.example.de".as_slice(), // IDN A-label
            // Numeric-looking labels are fine as long as they're not a full
            // IPv4 dotted-quad (e.g. AS-number-style labels).
            b"v6.example.com".as_slice(),
            b"10.example".as_slice(), // not 4 dotted labels → not IP
        ] {
            let der = san_with_dns(ok);
            let mut out = alloc::vec::Vec::new();
            super::parse_dns_names(&der, &mut out).expect("should accept");
            assert_eq!(
                out.last().map(String::as_str),
                Some(core::str::from_utf8(ok).unwrap())
            );
        }
    }

    /// Builds a synthetic `SubjectAltName` body containing a single
    /// iPAddress (tag 0x87) entry of the supplied length.
    fn san_with_ip(bytes: &[u8]) -> alloc::vec::Vec<u8> {
        let mut entry = alloc::vec![0x87u8, bytes.len() as u8];
        entry.extend_from_slice(bytes);
        let mut seq = alloc::vec![0x30u8, entry.len() as u8];
        seq.extend_from_slice(&entry);
        seq
    }

    #[test]
    fn san_ip_parser_accepts_v4_and_v6() {
        let v4_der = san_with_ip(&[10, 0, 0, 1]);
        let mut out = alloc::vec::Vec::new();
        super::parse_ip_addresses(&v4_der, &mut out).unwrap();
        assert_eq!(out, alloc::vec![super::SanIp::V4([10, 0, 0, 1])]);

        let mut v6 = [0u8; 16];
        v6[..2].copy_from_slice(&[0x20, 0x01]); // 2001:db8::1
        v6[2..4].copy_from_slice(&[0x0d, 0xb8]);
        v6[15] = 1;
        let v6_der = san_with_ip(&v6);
        let mut out = alloc::vec::Vec::new();
        super::parse_ip_addresses(&v6_der, &mut out).unwrap();
        assert_eq!(out, alloc::vec![super::SanIp::V6(v6)]);
    }

    #[test]
    fn san_ip_parser_rejects_ipv4_mapped_ipv6() {
        // ::ffff:10.0.0.1 — first 10 bytes zero, bytes 10-11 = 0xff 0xff,
        // bytes 12..16 = the IPv4. The host stack treats this as the
        // IPv4 address, but the SAN matcher compares 16 bytes — refuse.
        let mut bytes = [0u8; 16];
        bytes[10] = 0xff;
        bytes[11] = 0xff;
        bytes[12] = 10;
        bytes[13] = 0;
        bytes[14] = 0;
        bytes[15] = 1;
        let der = san_with_ip(&bytes);
        let mut out = alloc::vec::Vec::new();
        assert!(super::parse_ip_addresses(&der, &mut out).is_err());
    }

    #[test]
    fn san_ip_parser_rejects_wrong_length() {
        // 5 bytes is neither IPv4 nor IPv6.
        let der = san_with_ip(&[10, 0, 0, 1, 99]);
        let mut out = alloc::vec::Vec::new();
        assert!(super::parse_ip_addresses(&der, &mut out).is_err());
    }

    #[test]
    fn cidr_mask_accepts_canonical_and_rejects_non_contiguous() {
        // Every valid /n prefix length for IPv4 passes.
        for n in 0..=32u32 {
            let mut mask = [0u8; 4];
            let mut bits = n;
            for byte in mask.iter_mut() {
                let take = bits.min(8);
                *byte = if take == 0 { 0 } else { 0xffu8 << (8 - take) };
                bits -= take;
            }
            assert!(
                super::is_contiguous_cidr_mask(&mask),
                "rejected canonical /{n}: {mask:02x?}"
            );
        }
        // Classic non-CIDR shapes are rejected.
        assert!(!super::is_contiguous_cidr_mask(&[0xff, 0x00, 0xff, 0x00]));
        assert!(!super::is_contiguous_cidr_mask(&[0x80, 0x80, 0x00, 0x00]));
        assert!(!super::is_contiguous_cidr_mask(&[0xfe, 0xff, 0xff, 0xff])); // gap in MSB byte
        // A byte that is itself non-contiguous (0x0f, 0xa5, ...) fails.
        assert!(!super::is_contiguous_cidr_mask(&[0xff, 0xff, 0x0f, 0x00]));
    }

    #[test]
    fn name_constraints_rejects_non_contiguous_ip_mask() {
        use crate::der::encode_sequence;
        // Forge a permittedSubtrees containing a single GeneralSubtree whose
        // base is iPAddress [7] = addr (4) || mask (4), with the mask set to
        // a non-CIDR shape (0xff00ff00). The parser must reject this rather
        // than store it as a usable subtree.
        let bad = [10u8, 0, 0, 0, 0xff, 0x00, 0xff, 0x00];
        // iPAddress [7] IMPLICIT OCTET STRING — primitive context-specific 7.
        let mut ip_tlv = alloc::vec::Vec::new();
        ip_tlv.push(0x87);
        ip_tlv.push(bad.len() as u8);
        ip_tlv.extend_from_slice(&bad);
        let subtree = encode_sequence(&ip_tlv);
        // permittedSubtrees [0] IMPLICIT SEQUENCE OF GeneralSubtree
        let mut perm = alloc::vec::Vec::new();
        perm.push(0xA0); // context 0, constructed
        perm.push(subtree.len() as u8);
        perm.extend_from_slice(&subtree);
        let body = encode_sequence(&perm);
        assert!(super::parse_name_constraints(&body).is_err());
    }

    /// Forges a TBSCertificate with a caller-controlled `version` tag and an
    /// `[3] EXPLICIT extensions` block, signs it with the issuer key, and
    /// returns the resulting [`Certificate`]. Used by the v1/v2-extensions
    /// regression tests below.
    fn forge_cert_with_version_and_exts(version: u8, exts: &[Extension]) -> Certificate {
        use crate::der::{encode_bit_string, encode_context, encode_integer, encode_sequence};

        let key = rsa_test_key_a();
        let name = DistinguishedName::common_name("forged");
        let algid = algorithm_identifier(oid::SHA256_WITH_RSA, true);
        let spki = rsa_spki(&key.public_key());
        let mut body = alloc::vec::Vec::new();
        // version [0] EXPLICIT INTEGER. Only emit when caller asks for a non-default
        // version; a missing version tag means v1 per RFC 5280.
        body.extend_from_slice(&encode_context(0, &encode_integer(&[version])));
        body.extend_from_slice(&encode_integer(&1u64.to_be_bytes()));
        body.extend_from_slice(&algid);
        body.extend_from_slice(&name.to_der());
        body.extend_from_slice(&validity().to_der());
        body.extend_from_slice(&name.to_der());
        body.extend_from_slice(&spki);
        // Bypass the legitimate v3-only builder: encode the `[3] extensions`
        // block directly so the cert can carry extensions regardless of the
        // version field. This is the exact non-conformant shape the parser
        // must reject.
        body.extend_from_slice(&extension::encode_extensions_field(exts));
        let tbs = encode_sequence(&body);
        let sig = key.sign_pkcs1v15::<Sha256>(&tbs).unwrap();
        let der = encode_sequence(&[tbs, algid, encode_bit_string(&sig)].concat());
        Certificate { der }
    }

    // X509-1: RFC 5280 §4.1.2.1 forbids the `[3] extensions` field on v1
    // (version INTEGER 0) and v2 (version INTEGER 1) certificates. Two parsers
    // that disagree on whether to read those extensions for policy can be
    // steered to opposite trust decisions; reject the malformed shape outright.
    #[test]
    fn v1_cert_with_extensions_is_rejected() {
        let ext = extension::basic_constraints(true, None);
        let cert = forge_cert_with_version_and_exts(0, &[ext]);
        // Every accessor that goes through `walk_extensions` must reject.
        assert!(matches!(cert.subject_alt_names(), Err(Error::Malformed)));
        assert!(matches!(cert.basic_constraints(), Err(Error::Malformed)));
        assert!(matches!(cert.extensions(), Err(Error::Malformed)));
        assert!(matches!(cert.check_well_formed(), Err(Error::Malformed)));
    }

    #[test]
    fn v2_cert_with_extensions_is_rejected() {
        let ext = extension::basic_constraints(false, None);
        let cert = forge_cert_with_version_and_exts(1, &[ext]);
        assert!(matches!(cert.subject_alt_names(), Err(Error::Malformed)));
        assert!(matches!(cert.basic_constraints(), Err(Error::Malformed)));
        assert!(matches!(cert.extensions(), Err(Error::Malformed)));
        assert!(matches!(cert.check_well_formed(), Err(Error::Malformed)));
    }

    #[test]
    fn v3_cert_with_extensions_is_accepted() {
        // Same forge path, but with the version tag set to 2 (v3); this must
        // succeed so the prior two tests are not spuriously passing because
        // of an unrelated parse failure.
        let ext = extension::basic_constraints(true, None);
        let cert = forge_cert_with_version_and_exts(2, &[ext]);
        cert.check_well_formed().unwrap();
        let bc = cert.basic_constraints().unwrap().unwrap();
        assert_eq!(bc, (true, None));
    }

    // X509-2: RFC 5280 §4.1.2.2 — serial magnitude must fit in 20 octets.
    // Build a TBSCertificate with a 21-octet INTEGER body and confirm
    // `serial_bytes` rejects it. Negative serials are already rejected at the
    // DER layer by `Reader::read_unsigned_integer_bytes`, but exercise that
    // path here too so the check stays exercised.
    #[test]
    fn serial_with_21_octet_magnitude_is_rejected() {
        use crate::der::{encode_bit_string, encode_context, encode_integer, encode_sequence};

        let key = rsa_test_key_a();
        let name = DistinguishedName::common_name("serial-test");
        let algid = algorithm_identifier(oid::SHA256_WITH_RSA, true);
        let spki = rsa_spki(&key.public_key());

        // 21 magnitude bytes all = 0x01: high bit clear so no sign-byte pad
        // is added by encode_integer; the INTEGER body itself is 21 bytes.
        let serial_body = [0x01u8; 21];
        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(&encode_context(0, &encode_integer(&[2])));
        body.extend_from_slice(&encode_integer(&serial_body));
        body.extend_from_slice(&algid);
        body.extend_from_slice(&name.to_der());
        body.extend_from_slice(&validity().to_der());
        body.extend_from_slice(&name.to_der());
        body.extend_from_slice(&spki);
        body.extend_from_slice(&extension::encode_extensions_field(&[
            extension::basic_constraints(false, None),
        ]));
        let tbs = encode_sequence(&body);
        let sig = key.sign_pkcs1v15::<Sha256>(&tbs).unwrap();
        let der = encode_sequence(&[tbs, algid, encode_bit_string(&sig)].concat());
        let cert = Certificate { der };
        assert!(matches!(cert.serial_bytes(), Err(Error::Malformed)));
    }

    #[test]
    fn serial_with_20_octet_magnitude_and_leading_zero_is_accepted() {
        use crate::der::{encode_bit_string, encode_context, encode_integer, encode_sequence};

        let key = rsa_test_key_a();
        let name = DistinguishedName::common_name("serial-test");
        let algid = algorithm_identifier(oid::SHA256_WITH_RSA, true);
        let spki = rsa_spki(&key.public_key());

        // 20 magnitude bytes with the high bit set on the first; encode_integer
        // will prepend a 0x00 sign byte → 21-byte INTEGER body, of which 20 are
        // magnitude. RFC 5280 permits this.
        let mut serial_body = [0xCCu8; 20];
        serial_body[0] = 0x80;
        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(&encode_context(0, &encode_integer(&[2])));
        body.extend_from_slice(&encode_integer(&serial_body));
        body.extend_from_slice(&algid);
        body.extend_from_slice(&name.to_der());
        body.extend_from_slice(&validity().to_der());
        body.extend_from_slice(&name.to_der());
        body.extend_from_slice(&spki);
        body.extend_from_slice(&extension::encode_extensions_field(&[
            extension::basic_constraints(false, None),
        ]));
        let tbs = encode_sequence(&body);
        let sig = key.sign_pkcs1v15::<Sha256>(&tbs).unwrap();
        let der = encode_sequence(&[tbs, algid, encode_bit_string(&sig)].concat());
        let cert = Certificate { der };
        let bytes = cert.serial_bytes().unwrap();
        // The returned body still includes the leading 0x00 sign byte.
        assert_eq!(bytes.len(), 21);
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x80);
    }

    #[test]
    fn negative_serial_is_rejected() {
        use crate::der::{encode_bit_string, encode_context, encode_sequence, encode_tlv, tag};

        let key = rsa_test_key_a();
        let name = DistinguishedName::common_name("neg-serial");
        let algid = algorithm_identifier(oid::SHA256_WITH_RSA, true);
        let spki = rsa_spki(&key.public_key());

        // Forge a negative INTEGER serial (high bit set, no leading 0x00).
        // `Reader::read_unsigned_integer_bytes` (called from `serial_bytes`)
        // must reject this as malformed per X.690.
        let neg = encode_tlv(tag::INTEGER, &[0xFF, 0x42]);
        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(&encode_context(0, &crate::der::encode_integer(&[2])));
        body.extend_from_slice(&neg);
        body.extend_from_slice(&algid);
        body.extend_from_slice(&name.to_der());
        body.extend_from_slice(&validity().to_der());
        body.extend_from_slice(&name.to_der());
        body.extend_from_slice(&spki);
        body.extend_from_slice(&extension::encode_extensions_field(&[
            extension::basic_constraints(false, None),
        ]));
        let tbs = encode_sequence(&body);
        let sig = key.sign_pkcs1v15::<Sha256>(&tbs).unwrap();
        let der = encode_sequence(&[tbs, algid, encode_bit_string(&sig)].concat());
        let cert = Certificate { der };
        assert!(cert.serial_bytes().is_err());
    }

    // X509-3: RFC 5280 §4.2 — at most one occurrence of any extension OID.
    // Forge a TBSCertificate carrying two basicConstraints extensions and
    // confirm every extension-walking accessor returns `Error::Malformed`.
    #[test]
    fn duplicate_extension_oid_is_rejected() {
        let dup_a = extension::basic_constraints(true, Some(0));
        let dup_b = extension::basic_constraints(false, None);
        // Version 2 (=v3) so the version check is satisfied and the duplicate
        // detection (not the version gate) is what fires.
        let cert = forge_cert_with_version_and_exts(2, &[dup_a, dup_b]);
        assert!(matches!(cert.basic_constraints(), Err(Error::Malformed)));
        assert!(matches!(cert.subject_alt_names(), Err(Error::Malformed)));
        assert!(matches!(cert.extensions(), Err(Error::Malformed)));
        assert!(matches!(cert.check_well_formed(), Err(Error::Malformed)));
    }

    #[test]
    fn distinct_extensions_are_accepted() {
        use crate::x509::extension::KeyUsageBits;
        let exts = [
            extension::basic_constraints(true, Some(0)),
            extension::key_usage(KeyUsageBits::KEY_CERT_SIGN),
        ];
        let cert = forge_cert_with_version_and_exts(2, &exts);
        cert.check_well_formed().unwrap();
        assert_eq!(cert.extensions().unwrap().len(), 2);
    }
}
