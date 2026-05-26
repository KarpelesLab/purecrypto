//! X.509 certificate building, parsing, and verification.
//!
//! Signatures use RSA with PKCS#1 v1.5 over SHA-256
//! (`sha256WithRSAEncryption`).

use alloc::string::String;
use alloc::vec::Vec;

use super::{
    AnyPublicKey, CertSigner, CertificationRequest, DistinguishedName, Error, Validity,
    algorithm_identifier, oid,
};
use crate::der::{
    Reader, encode_bit_string, encode_boolean, encode_context, encode_integer, encode_octet_string,
    encode_sequence, encode_tlv, oid_tlv, parse_oid, pem_decode, pem_encode, tag,
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

/// Encodes the critical `basicConstraints` extension as one `Extension`.
fn basic_constraints_ext(is_ca: bool) -> Vec<u8> {
    let bc_value = if is_ca {
        encode_sequence(&encode_boolean(true))
    } else {
        encode_sequence(&[]) // cA defaults to FALSE
    };
    let mut ext = oid_tlv(oid::BASIC_CONSTRAINTS);
    ext.extend_from_slice(&encode_boolean(true)); // critical
    ext.extend_from_slice(&encode_octet_string(&bc_value));
    encode_sequence(&ext)
}

/// Encodes a `subjectAltName` extension (dNSName entries) as one `Extension`.
pub(super) fn subject_alt_name_ext(dns_names: &[&str]) -> Vec<u8> {
    // GeneralNames ::= SEQUENCE OF GeneralName; dNSName is [2] IA5String,
    // an IMPLICIT primitive context tag (0x82).
    let mut names = Vec::new();
    for name in dns_names {
        names.extend_from_slice(&encode_tlv(0x82, name.as_bytes()));
    }
    let san = encode_sequence(&names);
    let mut ext = oid_tlv(oid::SUBJECT_ALT_NAME);
    ext.extend_from_slice(&encode_octet_string(&san));
    encode_sequence(&ext)
}

/// Encodes the `[3] Extensions` field (basicConstraints, plus subjectAltName
/// when `dns_names` is non-empty).
fn extensions(is_ca: bool, dns_names: &[&str]) -> Vec<u8> {
    let mut list = basic_constraints_ext(is_ca);
    if !dns_names.is_empty() {
        list.extend_from_slice(&subject_alt_name_ext(dns_names));
    }
    encode_context(3, &encode_sequence(&list))
}

/// Builds the DER `TBSCertificate` from a pre-encoded subject
/// `SubjectPublicKeyInfo` and inner `signature` AlgorithmIdentifier.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_tbs_raw(
    serial: u64,
    issuer: &DistinguishedName,
    subject: &DistinguishedName,
    validity: &Validity,
    spki_der: &[u8],
    sig_algid: &[u8],
    is_ca: bool,
    dns_names: &[&str],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_context(0, &encode_integer(&[2]))); // version v3
    body.extend_from_slice(&encode_integer(&serial.to_be_bytes()));
    body.extend_from_slice(sig_algid);
    body.extend_from_slice(&issuer.to_der());
    body.extend_from_slice(&validity.to_der());
    body.extend_from_slice(&subject.to_der());
    body.extend_from_slice(spki_der);
    body.extend_from_slice(&extensions(is_ca, dns_names));
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
    build_tbs_raw(
        serial,
        issuer,
        subject,
        validity,
        &rsa_spki(subject_key),
        &algorithm_identifier(oid::SHA256_WITH_RSA, true),
        is_ca,
        dns_names,
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
        let algid = signer.algorithm_identifier();
        let tbs = build_tbs_raw(
            serial,
            issuer,
            subject,
            validity,
            &subject_key.to_spki_der(),
            &algid,
            is_ca,
            dns_names,
        );
        let sig = signer.sign(&tbs)?;
        let der = encode_sequence(&[tbs, algid, encode_bit_string(&sig)].concat());
        Ok(Certificate { der })
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

    /// Wraps existing certificate DER (validating only that it is a SEQUENCE).
    pub fn from_der(der: Vec<u8>) -> Result<Certificate, Error> {
        let mut r = Reader::new(&der);
        r.read_sequence()?;
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
        let mut seq = self.tbs_after_algid()?;
        DistinguishedName::decode(&mut seq)?; // issuer
        Validity::decode(&mut seq)?; // validity
        DistinguishedName::decode(&mut seq)?; // subject
        seq.read_element()?; // subjectPublicKeyInfo

        // Skip the optional issuerUniqueID [1] and subjectUniqueID [2]
        // (IMPLICIT primitive context tags 0x81 / 0x82).
        while matches!(seq.peek_tag(), Some(0x81) | Some(0x82)) {
            seq.read_element()?;
        }
        // The [3] EXPLICIT extensions wrapper (constructed context tag 0xA3).
        if seq.peek_tag() != Some(tag::context(3)) {
            return Ok(());
        }
        let wrapper = seq.read_tlv(tag::context(3))?;
        let mut outer = Reader::new(wrapper);
        let mut exts = outer.read_sequence()?;

        while !exts.is_empty() {
            let mut ext = exts.read_sequence()?;
            let id = parse_oid(ext.read_oid()?)?;
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

/// Parses a `SubjectAltName` value (`SEQUENCE OF GeneralName`), collecting the
/// dNSName (`[2] IA5String`, tag 0x82) entries.
pub(super) fn parse_dns_names(der: &[u8], out: &mut Vec<String>) -> Result<(), Error> {
    let mut reader = Reader::new(der);
    let mut seq = reader.read_sequence()?;
    while !seq.is_empty() {
        let (t, value) = seq.read_any()?;
        if t == 0x82 {
            let s = core::str::from_utf8(value).map_err(|_| Error::Malformed)?;
            out.push(String::from(s));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{rsa_test_key_a, rsa_test_key_b};
    use crate::x509::Time;

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
}
