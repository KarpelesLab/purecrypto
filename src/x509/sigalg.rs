//! The signature `AlgorithmIdentifier` of a certificate, CRL, OCSP response
//! or CSR: the OID *and* the parameters that travel with it.
//!
//! For every signature algorithm but RSASSA-PSS the parameters are either
//! absent or a `NULL` that carries no information, so the OID alone names
//! the algorithm. `id-RSASSA-PSS` is different: RFC 4055 §3.1 puts the
//! digest, the MGF1 digest and the salt length in an `RSASSA-PSS-params`
//! SEQUENCE inside the signature's `AlgorithmIdentifier`, and a verifier
//! that reads only the OID verifies under whatever profile it assumed. The
//! [`SignatureAlgorithmIdentifier`] carries those parameters so dispatch
//! ([`AnyPublicKey::signature_algorithm`](super::AnyPublicKey::signature_algorithm))
//! can pick the registry entry for the *signature's* digest and hand its
//! salt length to the verifier.

use alloc::vec::Vec;

use super::{Error, PssParams, PssRestriction, oid};
use crate::der::{Reader, parse_oid};

/// The parameters a signature `AlgorithmIdentifier` carries, as far as they
/// affect verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SignatureParams {
    /// No parameters that affect verification: absent (ECDSA, EdDSA, ML-DSA,
    /// SLH-DSA, SM2) or the `NULL` the PKCS#1 v1.5 OIDs carry.
    #[default]
    None,
    /// The `RSASSA-PSS-params` (RFC 4055 §3.1) following `id-RSASSA-PSS`:
    /// the digest, the MGF1 digest, the salt length and the trailer field
    /// the signature was made with.
    RsaPss(PssParams),
}

/// A signature `AlgorithmIdentifier` (RFC 5280 §4.1.1.2): the OID plus
/// [`SignatureParams`].
///
/// Built by the X.509 parsers ([`Certificate::signature_algorithm`],
/// [`CertificateRevocationList::signature_algorithm`],
/// [`OcspResponse::signature_algorithm`],
/// [`CertificationRequest::signature_algorithm`]) and consumed by
/// [`AnyPublicKey::verify`] / [`AnyPublicKey::signature_algorithm`]. Callers
/// that hold a bare OID for an algorithm without parameters use
/// [`from_oid`](Self::from_oid); an `id-RSASSA-PSS` identifier always needs
/// its parameters ([`rsa_pss`](Self::rsa_pss)) — RFC 4055 §3.1 requires
/// them on a signature, and their DER defaults (SHA-1, salt 20) are not
/// something this crate verifies.
///
/// [`Certificate::signature_algorithm`]: super::Certificate::signature_algorithm
/// [`CertificateRevocationList::signature_algorithm`]: super::CertificateRevocationList::signature_algorithm
/// [`OcspResponse::signature_algorithm`]: super::OcspResponse::signature_algorithm
/// [`CertificationRequest::signature_algorithm`]: super::CertificationRequest::signature_algorithm
/// [`AnyPublicKey::verify`]: super::AnyPublicKey::verify
/// [`AnyPublicKey::signature_algorithm`]: super::AnyPublicKey::signature_algorithm
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureAlgorithmIdentifier {
    oid: Vec<u64>,
    params: SignatureParams,
}

impl SignatureAlgorithmIdentifier {
    /// An identifier with no verification-relevant parameters — every
    /// algorithm but RSASSA-PSS. Building one for `id-RSASSA-PSS` is
    /// permitted but names the unsupported SHA-1 default profile, so no
    /// registry entry ever verifies under it.
    pub fn from_oid(oid: &[u64]) -> Self {
        SignatureAlgorithmIdentifier {
            oid: oid.to_vec(),
            params: SignatureParams::None,
        }
    }

    /// `id-RSASSA-PSS` with explicit `RSASSA-PSS-params`.
    pub fn rsa_pss(params: PssParams) -> Self {
        SignatureAlgorithmIdentifier {
            oid: oid::ID_RSASSA_PSS.to_vec(),
            params: SignatureParams::RsaPss(params),
        }
    }

    /// Decodes one DER `AlgorithmIdentifier` TLV (`SEQUENCE { OID,
    /// parameters OPTIONAL }`).
    ///
    /// `id-RSASSA-PSS` parameters go through the strict RFC 4055 decoder
    /// shared with SPKIs ([`AnyPublicKey::from_spki_der`]): absent parameters
    /// (or an empty SEQUENCE, whose DER defaults are SHA-1 / MGF1-SHA-1 /
    /// salt 20), any digest other than SHA-256/384/512, or a MGF other than
    /// MGF1 is [`Error::UnsupportedAlgorithm`]; a `trailerField` other than
    /// 1 is [`Error::Malformed`] and trailing junk a DER error. Parameters
    /// after any other OID are not interpreted.
    ///
    /// [`AnyPublicKey::from_spki_der`]: super::AnyPublicKey::from_spki_der
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(der);
        let mut algid = r.read_sequence()?;
        let oid = parse_oid(algid.read_oid()?)?;
        let params = if oid.as_slice() == oid::ID_RSASSA_PSS {
            match PssRestriction::decode(&mut algid)? {
                // RFC 4055 §3.1: a signature AlgorithmIdentifier MUST carry
                // RSASSA-PSS-params; absent ones would mean the SHA-1
                // defaults, which the crate does not implement.
                PssRestriction::Unrestricted => return Err(Error::UnsupportedAlgorithm),
                PssRestriction::Restricted(p) => SignatureParams::RsaPss(p),
            }
        } else {
            SignatureParams::None
        };
        if oid.as_slice() == oid::ID_RSASSA_PSS {
            algid.finish()?;
        }
        r.finish()?;
        Ok(SignatureAlgorithmIdentifier { oid, params })
    }

    /// The algorithm OID arcs.
    pub fn oid(&self) -> &[u64] {
        &self.oid
    }

    /// The parameters.
    pub fn params(&self) -> SignatureParams {
        self.params
    }

    /// The `RSASSA-PSS-params`, when this is an `id-RSASSA-PSS` identifier
    /// that carries them.
    pub fn pss_params(&self) -> Option<&PssParams> {
        match &self.params {
            SignatureParams::RsaPss(p) => Some(p),
            SignatureParams::None => None,
        }
    }
}

/// The OID arcs of a DER `AlgorithmIdentifier` TLV, parameters ignored.
pub(crate) fn algid_oid(der: &[u8]) -> Result<Vec<u64>, Error> {
    let mut r = Reader::new(der);
    let mut algid = r.read_sequence()?;
    Ok(parse_oid(algid.read_oid()?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::{encode_context, encode_integer, encode_null, encode_sequence, oid_tlv};
    use crate::x509::PssHash;

    fn pss_algid(params: &[u8]) -> Vec<u8> {
        encode_sequence(&[oid_tlv(oid::ID_RSASSA_PSS), params.to_vec()].concat())
    }

    fn pss_params(hash: &[u64], mgf1_hash: &[u64], salt_len: u8) -> Vec<u8> {
        pss_params_with_trailer(hash, mgf1_hash, salt_len, 1)
    }

    fn pss_params_with_trailer(
        hash: &[u64],
        mgf1_hash: &[u64],
        salt_len: u8,
        trailer: u8,
    ) -> Vec<u8> {
        let hash_algid = encode_sequence(&[oid_tlv(hash), encode_null()].concat());
        let mgf1_hash_algid = encode_sequence(&[oid_tlv(mgf1_hash), encode_null()].concat());
        let mgf_algid = encode_sequence(&[oid_tlv(oid::ID_MGF1), mgf1_hash_algid].concat());
        encode_sequence(
            &[
                encode_context(0, &hash_algid),
                encode_context(1, &mgf_algid),
                encode_context(2, &encode_integer(&[salt_len])),
                encode_context(3, &encode_integer(&[trailer])),
            ]
            .concat(),
        )
    }

    #[test]
    fn decodes_pss_params_and_rejects_defaults() {
        let alg = SignatureAlgorithmIdentifier::from_der(&pss_algid(&pss_params(
            oid::ID_SHA384,
            oid::ID_SHA384,
            48,
        )))
        .unwrap();
        assert_eq!(alg.oid(), oid::ID_RSASSA_PSS);
        assert_eq!(
            alg.pss_params(),
            Some(&PssParams::for_hash(PssHash::Sha384))
        );
        assert_eq!(
            alg,
            SignatureAlgorithmIdentifier::rsa_pss(PssParams::for_hash(PssHash::Sha384))
        );
        // Absent parameters and an empty SEQUENCE both mean the SHA-1
        // defaults: unsupported, not silently SHA-256.
        assert_eq!(
            SignatureAlgorithmIdentifier::from_der(&pss_algid(&[])).err(),
            Some(Error::UnsupportedAlgorithm)
        );
        assert_eq!(
            SignatureAlgorithmIdentifier::from_der(&pss_algid(&encode_sequence(&[]))).err(),
            Some(Error::UnsupportedAlgorithm)
        );
        // Trailing junk after the parameters is rejected.
        let mut junk = pss_params(oid::ID_SHA256, oid::ID_SHA256, 32);
        junk.extend_from_slice(&encode_null());
        assert!(SignatureAlgorithmIdentifier::from_der(&pss_algid(&junk)).is_err());
        // A trailer field other than 1 is malformed.
        let bad_trailer = pss_params_with_trailer(oid::ID_SHA256, oid::ID_SHA256, 32, 2);
        assert_eq!(
            SignatureAlgorithmIdentifier::from_der(&pss_algid(&bad_trailer)).err(),
            Some(Error::Malformed)
        );
    }

    #[test]
    fn other_oids_carry_no_params() {
        let alg = SignatureAlgorithmIdentifier::from_der(&encode_sequence(
            &[oid_tlv(oid::SHA256_WITH_RSA), encode_null()].concat(),
        ))
        .unwrap();
        assert_eq!(alg.oid(), oid::SHA256_WITH_RSA);
        assert_eq!(alg.params(), SignatureParams::None);
        assert!(alg.pss_params().is_none());
        assert_eq!(
            alg,
            SignatureAlgorithmIdentifier::from_oid(oid::SHA256_WITH_RSA)
        );
        let alg = SignatureAlgorithmIdentifier::from_der(&encode_sequence(&oid_tlv(
            oid::ECDSA_WITH_SHA256,
        )))
        .unwrap();
        assert_eq!(alg.oid(), oid::ECDSA_WITH_SHA256);
        assert_eq!(
            algid_oid(&encode_sequence(&oid_tlv(oid::ID_ED25519))).unwrap(),
            oid::ID_ED25519
        );
    }
}
