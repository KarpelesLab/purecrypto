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

/// Upper bound on the extensions a CSR may request, bounding the duplicate
/// scan in `walk_extension_requests` (the certificate walker's limit).
const MAX_REQUESTED_EXTENSIONS: usize = 64;

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
    sig_algid: &'a [u8],
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

    /// Parses a PEM `CERTIFICATE REQUEST` document. The decoded body goes
    /// through the same structural check as [`from_der`](Self::from_der): a
    /// single SEQUENCE with no trailing bytes.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        Self::from_der(pem_decode(pem, PEM_LABEL)?)
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
        let sig_algid = csr.read_element()?;
        let signature = csr.read_bit_string()?;
        // Strict DER (X.690 §11): no trailing bytes inside the outer
        // SEQUENCE.
        csr.finish()?;
        Ok(CsrParts {
            cri,
            sig_algid,
            signature,
        })
    }

    /// A sub-reader over the `CertificationRequestInfo`, positioned at `subject`.
    ///
    /// RFC 2986 §4.1 defines `version INTEGER { v1(0) } (v1,...)` and no
    /// later revision has added a value, so anything but the single octet
    /// `0` is rejected as [`Error::Malformed`] — the same stance the
    /// certificate and CRL parsers take on their version fields.
    fn cri_after_version(&self) -> Result<Reader<'_>, Error> {
        let cri = self.parts()?.cri;
        let mut outer = Reader::new(cri);
        let mut seq = outer.read_sequence()?;
        if seq.read_integer_bytes()? != [0x00] {
            return Err(Error::Malformed);
        }
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

    /// Walks every extension requested through `extensionRequest` PKCS#9
    /// attributes (RFC 2985 §5.4.2), calling `f(oid, critical, extnValue)`
    /// for each in order.
    ///
    /// The structure is held to the same strictness as a certificate's
    /// extensions ([`Certificate::walk_extensions`](super::Certificate)):
    /// every SEQUENCE and SET must be fully consumed, the attribute's
    /// values SET holds exactly one `Extensions` SEQUENCE, and an OID may
    /// appear only once across all requests — a CA that honours the first
    /// `subjectAltName` and a reviewer who reads the last would otherwise
    /// certify different names from the same CSR.
    fn walk_extension_requests(
        &self,
        mut f: impl FnMut(&[u64], bool, &[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut seq = self.cri_after_version()?;
        DistinguishedName::decode(&mut seq)?; // subject
        seq.read_element()?; // subjectPublicKeyInfo
        if seq.peek_tag() != Some(tag::context(0)) {
            return Ok(());
        }
        let attrs_der = seq.read_tlv(tag::context(0))?;
        let mut attrs = Reader::new(attrs_der);
        // OIDs compared as their canonical DER bodies, as in the cert walker.
        let mut seen: Vec<&[u8]> = Vec::new();
        while !attrs.is_empty() {
            let mut attr = attrs.read_sequence()?;
            let id = parse_oid(attr.read_oid()?)?;
            let values = attr.read_tlv(tag::SET)?;
            attr.finish()?;
            if id.as_slice() != oid::EXTENSION_REQUEST {
                continue;
            }
            let mut vreader = Reader::new(values);
            let mut exts = vreader.read_sequence()?; // Extensions
            vreader.finish()?;
            while !exts.is_empty() {
                let mut ext = exts.read_sequence()?;
                let eid_der = ext.read_oid()?;
                let eid = parse_oid(eid_der)?;
                if seen.contains(&eid_der) || seen.len() >= MAX_REQUESTED_EXTENSIONS {
                    return Err(Error::Malformed);
                }
                seen.push(eid_der);
                let critical = super::read_default_false_boolean(&mut ext)?;
                let value = ext.read_octet_string()?;
                ext.finish()?;
                f(&eid, critical, value)?;
            }
        }
        Ok(())
    }

    /// The dNSName entries requested via an `extensionRequest`/`subjectAltName`
    /// attribute, or an empty list if none.
    pub fn subject_alt_names(&self) -> Result<Vec<String>, Error> {
        let mut names = Vec::new();
        self.walk_extension_requests(|eid, _critical, value| {
            if eid == oid::SUBJECT_ALT_NAME {
                parse_dns_names(value, &mut names)?;
            }
            Ok(())
        })?;
        Ok(names)
    }

    /// Returns every v3 extension this CSR requests via its
    /// `extensionRequest` PKCS#9 attribute, in order. An empty list if the
    /// CSR has no extension request.
    pub fn extension_requests(&self) -> Result<Vec<Extension>, Error> {
        let mut out = Vec::new();
        self.walk_extension_requests(|eid, critical, value| {
            out.push(Extension {
                oid: eid.to_vec(),
                critical,
                value: value.to_vec(),
            });
            Ok(())
        })?;
        Ok(out)
    }

    /// The OID arcs of the request's `signatureAlgorithm` field, parameters
    /// ignored; see [`signature_algorithm`](Self::signature_algorithm).
    pub fn signature_algorithm_oid(&self) -> Result<Vec<u64>, Error> {
        super::sigalg::algid_oid(self.parts()?.sig_algid)
    }

    /// The request's `signatureAlgorithm` — OID plus the parameters that
    /// select the verifier (the `RSASSA-PSS-params` of an `id-RSASSA-PSS`
    /// signature, RFC 4055 §3.1).
    pub fn signature_algorithm(&self) -> Result<super::SignatureAlgorithmIdentifier, Error> {
        super::SignatureAlgorithmIdentifier::from_der(self.parts()?.sig_algid)
    }

    /// Verifies the request's self-signature against its own public key.
    ///
    /// A PKCS#10 `CertificationRequestInfo` carries no inner signature
    /// AlgorithmIdentifier, so there is no RFC 5280 §4.1.1.2-style inner/outer
    /// consistency check to perform here (unlike certificates and CRLs).
    ///
    /// SECURITY: this performs **no** signature-algorithm-strength or key-size
    /// policy. A SHA-1- or MD5-based signature, or an undersized RSA key, will
    /// verify **successfully** here. Callers MUST apply their own policy (e.g.
    /// `SignaturePolicy::permits`, as the TLS path does in
    /// `tls::pki::verify`) before trusting the result.
    pub fn verify_self_signed(&self) -> Result<(), Error> {
        let parts = self.parts()?;
        let key = self.public_key()?;
        let alg = super::SignatureAlgorithmIdentifier::from_der(parts.sig_algid)?;
        key.verify(&alg, parts.cri, parts.signature)
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

    /// `from_pem` must apply the same trailing-bytes check as `from_der`.
    #[test]
    fn from_pem_rejects_trailing_bytes() {
        let key = ec_signer_key();
        let csr = CertificationRequest::create(
            &CertSigner::Ecdsa(&key),
            &DistinguishedName::common_name("x"),
            &[],
        )
        .unwrap();
        let mut der = csr.to_der().to_vec();
        der.push(0x00);
        assert!(CertificationRequest::from_der(der.clone()).is_err());
        assert!(CertificationRequest::from_pem(&pem_encode(PEM_LABEL, &der)).is_err());
        CertificationRequest::from_pem(&csr.to_pem()).unwrap();
    }

    /// RFC 2986 §4.1: `version` is `v1(0)` and nothing else. A request whose
    /// version octet is anything but 0 is Malformed from every field accessor.
    #[test]
    fn csr_version_must_be_zero() {
        let key = ec_signer_key();
        let csr = CertificationRequest::create(
            &CertSigner::Ecdsa(&key),
            &DistinguishedName::common_name("v"),
            &[],
        )
        .unwrap();
        // Locate the version INTEGER: it is the first element inside the
        // CertificationRequestInfo SEQUENCE, i.e. `02 01 00` right after the
        // two nested SEQUENCE headers.
        let der = csr.to_der().to_vec();
        let outer_hdr = hdr_len(&der);
        let off = outer_hdr + hdr_len(&der[outer_hdr..]);
        assert_eq!(&der[off..off + 3], &[0x02, 0x01, 0x00]);
        let mut bad = der.clone();
        bad[off + 2] = 0x01;
        let bad = CertificationRequest::from_der(bad).unwrap();
        assert!(matches!(bad.subject(), Err(Error::Malformed)));
        assert!(matches!(bad.public_key(), Err(Error::Malformed)));
        assert!(matches!(bad.subject_alt_names(), Err(Error::Malformed)));
        assert!(bad.verify_self_signed().is_err());
        // The untouched request still parses.
        CertificationRequest::from_der(der)
            .unwrap()
            .subject()
            .unwrap();
    }

    /// Length of a DER element's tag + length header, for a short- or
    /// long-form length (the CRI is well over 127 bytes here).
    fn hdr_len(tlv: &[u8]) -> usize {
        if tlv[1] < 0x80 {
            2
        } else {
            2 + (tlv[1] & 0x7f) as usize
        }
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

    /// F4: a CSR requesting the same extension twice is rejected, as a
    /// certificate carrying a duplicate would be — a CA honouring the first
    /// `subjectAltName` and a reviewer reading the last would otherwise
    /// disagree on the names requested.
    #[test]
    fn csr_rejects_duplicate_requested_extension() {
        use crate::x509::extension::{GeneralName, subject_alt_name};
        let key = ec_signer_key();
        let csr = CertificationRequest::create_with_extensions(
            &CertSigner::Ecdsa(&key),
            &DistinguishedName::common_name("dup"),
            &[
                subject_alt_name(&[GeneralName::Dns("a.example".into())]),
                subject_alt_name(&[GeneralName::Dns("b.example".into())]),
            ],
        )
        .unwrap();
        assert!(matches!(csr.extension_requests(), Err(Error::Malformed)));
        assert!(matches!(csr.subject_alt_names(), Err(Error::Malformed)));
    }

    /// F4 / F5: the `extensionRequest` attribute is read as strictly as a
    /// certificate's extensions — no bytes after `extnValue` inside an
    /// `Extension`, exactly one `Extensions` SEQUENCE in the values SET,
    /// nothing after the last Extension, and no explicit `critical FALSE`.
    #[test]
    fn csr_extension_request_rejects_loose_structure() {
        use crate::der::{encode_boolean, encode_null, encode_octet_string};
        use crate::x509::extension::{GeneralName, subject_alt_name};

        let key = ec_signer_key();
        let signer = CertSigner::Ecdsa(&key);
        let san = subject_alt_name(&[GeneralName::Dns("strict.example".into())]);
        // Builds an unsigned CSR around a hand-made `Extension` (`critical`
        // slot and bytes after extnValue), `Extensions` tail and values-SET
        // tail. The accessors do not verify the signature, so an empty BIT
        // STRING will do.
        let build = |critical: &[u8], ext_tail: &[u8], exts_tail: &[u8], set_tail: &[u8]| {
            let mut ext_body = oid_tlv(&san.oid);
            ext_body.extend_from_slice(critical);
            ext_body.extend_from_slice(&encode_octet_string(&san.value));
            ext_body.extend_from_slice(ext_tail);
            let ext = encode_sequence(&ext_body);
            let exts = encode_sequence(&[ext, exts_tail.to_vec()].concat());
            let values = encode_tlv(tag::SET, &[exts, set_tail.to_vec()].concat());
            let attr = encode_sequence(&[oid_tlv(oid::EXTENSION_REQUEST), values].concat());
            let cri = encode_sequence(
                &[
                    encode_integer(&[0]),
                    DistinguishedName::common_name("strict").to_der(),
                    signer.public_key().to_spki_der(),
                    encode_context(0, &attr),
                ]
                .concat(),
            );
            let der = encode_sequence(
                &[cri, signer.algorithm_identifier(), encode_bit_string(&[])].concat(),
            );
            CertificationRequest::from_der(der).unwrap()
        };
        let clean = build(&[], &[], &[], &[]);
        assert_eq!(clean.subject_alt_names().unwrap(), ["strict.example"]);
        assert_eq!(clean.extension_requests().unwrap(), [san.clone()]);
        // Explicit `critical TRUE` is fine; an explicit FALSE encodes the
        // DEFAULT and is not DER.
        assert!(
            build(&encode_boolean(true), &[], &[], &[])
                .extension_requests()
                .unwrap()[0]
                .critical
        );
        assert!(matches!(
            build(&encode_boolean(false), &[], &[], &[]).extension_requests(),
            Err(Error::Malformed)
        ));
        // A NULL after extnValue inside the Extension SEQUENCE.
        let junk = build(&[], &encode_null(), &[], &[]);
        assert!(junk.extension_requests().is_err());
        assert!(junk.subject_alt_names().is_err());
        // Junk after the last Extension inside the Extensions SEQUENCE.
        assert!(
            build(&[], &[], &encode_null(), &[])
                .extension_requests()
                .is_err()
        );
        // A second value in the SET: the attribute must hold exactly one
        // Extensions SEQUENCE.
        assert!(
            build(&[], &[], &[], &encode_sequence(&[]))
                .extension_requests()
                .is_err()
        );
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

    /// A CSR self-signed with `id-RSASSA-PSS` carries its `RSASSA-PSS-params`
    /// in `signatureAlgorithm`; the self-signature verifies under the
    /// digest they name (the subject key is the PSS-restricted form the
    /// signer certifies), and a CA issues from it.
    #[test]
    fn pss_signed_csr_verifies_under_its_parameters() {
        use crate::rsa::BoxedRsaPrivateKey;
        use crate::x509::{AnyPublicKey, PssHash, PssParams, PssRestriction};
        let key =
            BoxedRsaPrivateKey::from_pkcs1_der(&crate::test_util::rsa_test_key_a().to_pkcs1_der())
                .unwrap();
        for hash in [PssHash::Sha256, PssHash::Sha384, PssHash::Sha512] {
            let signer = CertSigner::RsaPss(&key, hash);
            let csr = CertificationRequest::create(
                &signer,
                &DistinguishedName::common_name("pss.example"),
                &["pss.example"],
            )
            .unwrap();
            assert_eq!(
                csr.signature_algorithm_oid().unwrap(),
                crate::x509::oid::ID_RSASSA_PSS
            );
            assert_eq!(
                csr.signature_algorithm().unwrap().pss_params(),
                Some(&PssParams::for_hash(hash))
            );
            assert!(matches!(
                csr.public_key().unwrap(),
                AnyPublicKey::RsaPss(_, r) if r == PssRestriction::for_hash(hash)
            ));
            csr.verify_self_signed().unwrap();
            let mut der = csr.to_der().to_vec();
            let i = der.len() / 2;
            der[i] ^= 0x01;
            if let Ok(bad) = CertificationRequest::from_der(der) {
                assert!(bad.verify_self_signed().is_err());
            }
            let ca_key = ec_signer_key();
            let ca_signer = CertSigner::Ecdsa(&ca_key);
            let ca_name = DistinguishedName::common_name("Issuing CA");
            let validity = Validity::new(
                Time::utc(2024, 1, 1, 0, 0, 0),
                Time::utc(2034, 1, 1, 0, 0, 0),
            );
            let cert = Certificate::issue_from_csr(&ca_signer, &ca_name, &csr, &validity, 7, false)
                .unwrap();
            cert.verify_signature_with(&ca_signer.public_key()).unwrap();
            assert!(matches!(
                cert.subject_public_key().unwrap(),
                AnyPublicKey::RsaPss(_, r) if r == PssRestriction::for_hash(hash)
            ));
        }
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
