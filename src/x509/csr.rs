//! PKCS#10 certification requests (CSRs).
//!
//! A `CertificationRequest` binds a subject name (and optional `subjectAltName`
//! dNSNames, carried as an `extensionRequest` attribute) to a public key, signed
//! by the corresponding private key. A CA turns one into a certificate with
//! [`Certificate::issue_from_csr`](super::Certificate::issue_from_csr).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::cert::parse_dns_names;
use super::extension::{self, Extension, GeneralName};
use super::{AnyPublicKey, CertSigner, DistinguishedName, Error, oid};
use crate::der::{
    Reader, encode_bit_string, encode_context, encode_integer, encode_sequence, encode_tlv,
    oid_tlv, parse_oid, pem_decode, pem_encode, tag,
};

const PEM_LABEL: &str = "CERTIFICATE REQUEST";

/// A PKCS#10 certification request, stored as its DER encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificationRequest {
    der: Vec<u8>,
}

/// The three top-level fields of a `CertificationRequest`.
struct CsrParts<'a> {
    /// Raw `CertificationRequestInfo` element (TLV), used for signing.
    cri: &'a [u8],
    /// `signatureAlgorithm` OID arcs.
    sig_alg: Vec<u64>,
    /// Signature bits.
    signature: &'a [u8],
}

/// Encodes the `[0] attributes` field of a `CertificationRequestInfo`: empty, or
/// a single `extensionRequest` attribute carrying the given Extensions.
fn attributes(exts: &[Extension]) -> Vec<u8> {
    if exts.is_empty() {
        return encode_context(0, &[]);
    }
    // extensionRequest ::= Extensions ::= SEQUENCE OF Extension.
    let mut body = Vec::new();
    for e in exts {
        body.extend_from_slice(&e.to_der());
    }
    let exts_seq = encode_sequence(&body);
    let values = encode_tlv(tag::SET, &exts_seq); // values SET OF { Extensions }
    let attr = encode_sequence(&[oid_tlv(oid::EXTENSION_REQUEST), values].concat());
    encode_context(0, &attr) // [0] IMPLICIT SET OF Attribute
}

impl CertificationRequest {
    /// Creates a CSR for `subject`, signed by `signer`. The request's public key
    /// is the signer's; `dns_names`, when non-empty, are requested as a
    /// `subjectAltName` via an `extensionRequest` attribute.
    pub fn create(
        signer: &CertSigner,
        subject: &DistinguishedName,
        dns_names: &[&str],
    ) -> Result<Self, Error> {
        let exts = if dns_names.is_empty() {
            Vec::new()
        } else {
            let names: Vec<GeneralName> = dns_names
                .iter()
                .map(|s| GeneralName::Dns((*s).into()))
                .collect();
            vec![extension::subject_alt_name(&names)]
        };
        Self::create_with_extensions(signer, subject, &exts)
    }

    /// Creates a CSR for `subject` carrying an arbitrary slice of v3 extensions
    /// inside an `extensionRequest` PKCS#9 attribute (`SEQUENCE OF Extension`).
    /// An empty slice yields a CSR with an empty `attributes [0]` field.
    pub fn create_with_extensions(
        signer: &CertSigner,
        subject: &DistinguishedName,
        extensions: &[Extension],
    ) -> Result<Self, Error> {
        let spki = signer.public_key().to_spki_der();
        let cri = encode_sequence(
            &[
                encode_integer(&[0]), // version v1 (0)
                subject.to_der(),
                spki,
                attributes(extensions),
            ]
            .concat(),
        );
        let algid = signer.algorithm_identifier();
        let sig = signer.sign(&cri)?;
        let der = encode_sequence(&[cri, algid, encode_bit_string(&sig)].concat());
        Ok(CertificationRequest { der })
    }

    /// Wraps existing CSR DER (validating that it is a single SEQUENCE with
    /// no trailing bytes — matches the strict-DER posture of
    /// [`super::Certificate::from_der`] and
    /// [`super::CertificateRevocationList::from_der`]). Two implementations
    /// parsing the same blob then agree on what was signed.
    pub fn from_der(der: Vec<u8>) -> Result<Self, Error> {
        let mut r = Reader::new(&der);
        r.read_sequence()?;
        r.finish()?;
        Ok(CertificationRequest { der })
    }

    /// Parses a PEM `CERTIFICATE REQUEST` document.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Ok(CertificationRequest {
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

    /// Splits the request into its three top-level fields.
    fn parts(&self) -> Result<CsrParts<'_>, Error> {
        let mut outer = Reader::new(&self.der);
        let mut csr = outer.read_sequence()?;
        let cri = csr.read_element()?;
        let mut alg = csr.read_sequence()?;
        let sig_alg = parse_oid(alg.read_oid()?)?;
        let signature = csr.read_bit_string()?;
        // Strict DER (X.690 §11): no trailing bytes inside the outer
        // SEQUENCE.
        csr.finish()?;
        Ok(CsrParts {
            cri,
            sig_alg,
            signature,
        })
    }

    /// A sub-reader over the `CertificationRequestInfo`, positioned at `subject`.
    fn cri_after_version(&self) -> Result<Reader<'_>, Error> {
        let cri = self.parts()?.cri;
        let mut outer = Reader::new(cri);
        let mut seq = outer.read_sequence()?;
        seq.read_integer_bytes()?; // version
        Ok(seq)
    }

    /// The requested subject name.
    pub fn subject(&self) -> Result<DistinguishedName, Error> {
        let mut seq = self.cri_after_version()?;
        DistinguishedName::decode(&mut seq)
    }

    /// The requested public key.
    pub fn public_key(&self) -> Result<AnyPublicKey, Error> {
        let mut seq = self.cri_after_version()?;
        DistinguishedName::decode(&mut seq)?; // subject
        let spki = seq.read_element()?;
        AnyPublicKey::from_spki_der(spki)
    }

    /// The dNSName entries requested via an `extensionRequest`/`subjectAltName`
    /// attribute, or an empty list if none.
    pub fn subject_alt_names(&self) -> Result<Vec<String>, Error> {
        let mut seq = self.cri_after_version()?;
        DistinguishedName::decode(&mut seq)?; // subject
        seq.read_element()?; // subjectPublicKeyInfo
        if seq.peek_tag() != Some(tag::context(0)) {
            return Ok(Vec::new());
        }
        let attrs_der = seq.read_tlv(tag::context(0))?;
        let mut attrs = Reader::new(attrs_der);
        let mut names = Vec::new();
        while !attrs.is_empty() {
            let mut attr = attrs.read_sequence()?;
            let id = parse_oid(attr.read_oid()?)?;
            let values = attr.read_tlv(tag::SET)?;
            if id.as_slice() == oid::EXTENSION_REQUEST {
                let mut vreader = Reader::new(values);
                let mut exts = vreader.read_sequence()?; // Extensions
                while !exts.is_empty() {
                    let mut ext = exts.read_sequence()?;
                    let eid = parse_oid(ext.read_oid()?)?;
                    if ext.peek_tag() == Some(tag::BOOLEAN) {
                        ext.read_boolean()?; // critical
                    }
                    let value = ext.read_octet_string()?;
                    if eid.as_slice() == oid::SUBJECT_ALT_NAME {
                        parse_dns_names(value, &mut names)?;
                    }
                }
            }
        }
        Ok(names)
    }

    /// Returns every v3 extension this CSR requests via its
    /// `extensionRequest` PKCS#9 attribute, in order. An empty list if the
    /// CSR has no extension request.
    pub fn extension_requests(&self) -> Result<Vec<Extension>, Error> {
        let mut seq = self.cri_after_version()?;
        DistinguishedName::decode(&mut seq)?; // subject
        seq.read_element()?; // subjectPublicKeyInfo
        if seq.peek_tag() != Some(tag::context(0)) {
            return Ok(Vec::new());
        }
        let attrs_der = seq.read_tlv(tag::context(0))?;
        let mut attrs = Reader::new(attrs_der);
        let mut out = Vec::new();
        while !attrs.is_empty() {
            let mut attr = attrs.read_sequence()?;
            let id = parse_oid(attr.read_oid()?)?;
            let values = attr.read_tlv(tag::SET)?;
            if id.as_slice() == oid::EXTENSION_REQUEST {
                let mut vreader = Reader::new(values);
                let mut exts = vreader.read_sequence()?; // Extensions
                while !exts.is_empty() {
                    let mut ext = exts.read_sequence()?;
                    let eid = parse_oid(ext.read_oid()?)?;
                    let critical = if ext.peek_tag() == Some(tag::BOOLEAN) {
                        ext.read_boolean()?
                    } else {
                        false
                    };
                    let value = ext.read_octet_string()?;
                    out.push(Extension {
                        oid: eid,
                        critical,
                        value: value.to_vec(),
                    });
                }
            }
        }
        Ok(out)
    }

    /// Verifies the request's self-signature against its own public key.
    pub fn verify_self_signed(&self) -> Result<(), Error> {
        let parts = self.parts()?;
        let key = self.public_key()?;
        key.verify(&parts.sig_alg, parts.cri, parts.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::BoxedEcdsaPrivateKey;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::x509::{Certificate, Time, Validity};

    fn ec_signer_key() -> BoxedEcdsaPrivateKey {
        let mut rng = HmacDrbg::<Sha256>::new(b"csr-test", b"nonce", &[]);
        BoxedEcdsaPrivateKey::generate(crate::ec::CurveId::P256, &mut rng)
    }

    #[test]
    fn csr_roundtrip_and_verify() {
        let key = ec_signer_key();
        let signer = CertSigner::Ecdsa(&key);
        let subject = DistinguishedName::common_name("csr.example").with_organization("PC");
        let csr =
            CertificationRequest::create(&signer, &subject, &["csr.example", "www.csr.example"])
                .unwrap();

        // PEM round-trip.
        let pem = csr.to_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        let parsed = CertificationRequest::from_pem(&pem).unwrap();
        assert_eq!(parsed, csr);

        // Fields parse back, signature verifies.
        assert_eq!(csr.subject().unwrap(), subject);
        assert_eq!(
            csr.subject_alt_names().unwrap(),
            ["csr.example", "www.csr.example"]
        );
        assert!(matches!(csr.public_key().unwrap(), AnyPublicKey::Ecdsa(_)));
        csr.verify_self_signed().unwrap();
    }

    #[test]
    fn tampered_csr_fails() {
        let key = ec_signer_key();
        let csr = CertificationRequest::create(
            &CertSigner::Ecdsa(&key),
            &DistinguishedName::common_name("x"),
            &[],
        )
        .unwrap();
        let mut der = csr.to_der().to_vec();
        let idx = der.len() / 3;
        der[idx] ^= 1;
        let bad = CertificationRequest::from_der(der).unwrap();
        assert!(bad.verify_self_signed().is_err());
    }

    #[test]
    fn csr_create_with_extensions_round_trip() {
        use crate::x509::extension::{
            self as ext, GeneralName, KeyUsageBits, basic_constraints, extended_key_usage,
            key_usage, subject_alt_name,
        };

        let key = ec_signer_key();
        let signer = CertSigner::Ecdsa(&key);
        let subject = DistinguishedName::common_name("ext-csr.example");
        let exts = [
            basic_constraints(false, None),
            key_usage(KeyUsageBits::DIGITAL_SIGNATURE | KeyUsageBits::KEY_ENCIPHERMENT),
            extended_key_usage(&[oid::ID_KP_SERVER_AUTH]),
            subject_alt_name(&[
                GeneralName::Dns("ext-csr.example".into()),
                GeneralName::Dns("alt.example".into()),
            ]),
        ];
        let csr = CertificationRequest::create_with_extensions(&signer, &subject, &exts).unwrap();
        csr.verify_self_signed().unwrap();

        // SANs still surface via the legacy accessor.
        assert_eq!(
            csr.subject_alt_names().unwrap(),
            ["ext-csr.example", "alt.example"]
        );
        // The full extension list comes back, byte-for-byte, in order.
        let got = csr.extension_requests().unwrap();
        assert_eq!(got.len(), 4);
        assert_eq!(got[0].oid, oid::BASIC_CONSTRAINTS);
        assert_eq!(got[1].oid, oid::KEY_USAGE);
        assert_eq!(got[2].oid, oid::EXT_KEY_USAGE);
        assert_eq!(got[3].oid, oid::SUBJECT_ALT_NAME);
        // The expected bytes match the builder output.
        assert_eq!(got[0], ext::basic_constraints(false, None));
    }

    #[test]
    fn csr_empty_extension_requests() {
        let key = ec_signer_key();
        let csr = CertificationRequest::create(
            &CertSigner::Ecdsa(&key),
            &DistinguishedName::common_name("x"),
            &[],
        )
        .unwrap();
        assert!(csr.extension_requests().unwrap().is_empty());
    }

    #[test]
    fn ca_issues_from_csr() {
        // EC subject requests; RSA CA would also work, but keep it all-EC here.
        let subj_key = ec_signer_key();
        let csr = CertificationRequest::create(
            &CertSigner::Ecdsa(&subj_key),
            &DistinguishedName::common_name("leaf.example"),
            &["leaf.example"],
        )
        .unwrap();

        let mut rng = HmacDrbg::<Sha256>::new(b"ca-key", b"nonce", &[]);
        let ca_key = BoxedEcdsaPrivateKey::generate(crate::ec::CurveId::P384, &mut rng);
        let ca_signer = CertSigner::Ecdsa(&ca_key);
        let ca_name = DistinguishedName::common_name("Issuing CA");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );

        let cert =
            Certificate::issue_from_csr(&ca_signer, &ca_name, &csr, &validity, 7, false).unwrap();

        assert_eq!(
            cert.subject().unwrap(),
            DistinguishedName::common_name("leaf.example")
        );
        assert_eq!(cert.issuer().unwrap(), ca_name);
        assert_eq!(cert.subject_alt_names().unwrap(), ["leaf.example"]);
        // The cert verifies under the CA's public key.
        cert.verify_signature_with(&ca_signer.public_key()).unwrap();
    }

    // H-5: CertificationRequest::from_der rejects trailing bytes after the
    // outer SEQUENCE — matches the strict-DER behavior of
    // Certificate::from_der and CertificateRevocationList::from_der.
    #[test]
    fn csr_rejects_trailing_data_after_sequence() {
        let key = ec_signer_key();
        let signer = CertSigner::Ecdsa(&key);
        let subject = DistinguishedName::common_name("trail.example");
        let csr = CertificationRequest::create(&signer, &subject, &["trail.example"]).unwrap();

        let mut der = csr.to_der().to_vec();
        // Append a stray byte; self-signature still verifies if the
        // body is taken to be the original SEQUENCE — so this is exactly
        // the covert-channel / parser-mismatch case the check defends.
        der.push(0x00);
        assert!(CertificationRequest::from_der(der).is_err());
    }
}
