//! ML-DSA entries in the signature registry.
//!
//! Three zero-sized types — `MlDsa44`, `MlDsa65`, `MlDsa87` — wrapping the
//! existing FIPS 204 implementation. Each `verify` parses the SPKI to recover
//! the public key and delegates to the primitive's `verify` (which uses an
//! empty context string per draft-ietf-lamps-dilithium-certificates).

use crate::der::{Reader, parse_oid};
use crate::mldsa::{MlDsa44PublicKey, MlDsa65PublicKey, MlDsa87PublicKey};
use crate::signature_registry::SignatureAlgorithm;
use crate::x509::{Error, oid};

/// Parses an ML-DSA SPKI under `expected_oid` and returns the raw key bytes.
fn parse_mldsa_spki<'a>(spki: &'a [u8], expected_oid: &[u64]) -> Result<&'a [u8], Error> {
    let mut reader = Reader::new(spki);
    let mut outer = reader.read_sequence()?;
    let mut algid = outer.read_sequence()?;
    let alg = parse_oid(algid.read_oid()?)?;
    if alg.as_slice() != expected_oid {
        return Err(Error::UnsupportedAlgorithm);
    }
    // draft-ietf-lamps-dilithium-certificates §4: the AlgorithmIdentifier is
    // the bare OID with parameters absent, and nothing may follow the
    // subjectPublicKey BIT STRING (mirrors `x509::pubkey::from_spki_der`
    // and the ECDSA / EdDSA registry parsers).
    algid.finish()?;
    let key_bits = outer.read_bit_string()?;
    outer.finish()?;
    Ok(key_bits)
}

/// `ml-dsa-44` (FIPS 204, security level 2).
/// X.509 OID `2.16.840.1.101.3.4.3.17`; TLS scheme `0x0904`
/// (draft-ietf-tls-mldsa).
pub(crate) struct MlDsa44;

impl SignatureAlgorithm for MlDsa44 {
    fn id(&self) -> &'static str {
        "ml-dsa-44"
    }
    fn x509_oids(&self) -> &'static [&'static [u64]] {
        &[oid::ID_ML_DSA_44]
    }
    fn tls_schemes(&self) -> &'static [u16] {
        &[0x0904]
    }
    fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let key_bits = parse_mldsa_spki(spki, oid::ID_ML_DSA_44)?;
        let key = MlDsa44PublicKey::from_bytes(key_bits).map_err(|_| Error::Malformed)?;
        if key.verify(signature, message, b"") {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

/// `ml-dsa-65` (FIPS 204, security level 3).
/// X.509 OID `2.16.840.1.101.3.4.3.18`; TLS scheme `0x0905`.
pub(crate) struct MlDsa65;

impl SignatureAlgorithm for MlDsa65 {
    fn id(&self) -> &'static str {
        "ml-dsa-65"
    }
    fn x509_oids(&self) -> &'static [&'static [u64]] {
        &[oid::ID_ML_DSA_65]
    }
    fn tls_schemes(&self) -> &'static [u16] {
        &[0x0905]
    }
    fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let key_bits = parse_mldsa_spki(spki, oid::ID_ML_DSA_65)?;
        let key = MlDsa65PublicKey::from_bytes(key_bits).map_err(|_| Error::Malformed)?;
        if key.verify(signature, message, b"") {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

/// `ml-dsa-87` (FIPS 204, security level 5).
/// X.509 OID `2.16.840.1.101.3.4.3.19`; TLS scheme `0x0906`.
pub(crate) struct MlDsa87;

impl SignatureAlgorithm for MlDsa87 {
    fn id(&self) -> &'static str {
        "ml-dsa-87"
    }
    fn x509_oids(&self) -> &'static [&'static [u64]] {
        &[oid::ID_ML_DSA_87]
    }
    fn tls_schemes(&self) -> &'static [u16] {
        &[0x0906]
    }
    fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let key_bits = parse_mldsa_spki(spki, oid::ID_ML_DSA_87)?;
        let key = MlDsa87PublicKey::from_bytes(key_bits).map_err(|_| Error::Malformed)?;
        if key.verify(signature, message, b"") {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mldsa::MlDsa65PrivateKey;
    use crate::rng::HmacDrbg;
    use crate::signature_registry::{find_by_id, find_by_oid};
    use crate::x509::AnyPublicKey;

    #[test]
    fn ml_dsa_65_registry_lookup() {
        let algo = find_by_id("ml-dsa-65").expect("ml-dsa-65");
        assert_eq!(algo.id(), "ml-dsa-65");
        let by_oid = find_by_oid(oid::ID_ML_DSA_65).expect("by OID");
        assert_eq!(by_oid.id(), "ml-dsa-65");
        // TLS scheme 0x0905 (draft-ietf-tls-mldsa).
        assert_eq!(algo.tls_schemes(), &[0x0905u16]);
    }

    /// The registry SPKI parser must be as strict as `x509::pubkey`: a
    /// trailing NULL inside the AlgorithmIdentifier (parameters MUST be
    /// absent) or junk after the subjectPublicKey BIT STRING is rejected.
    #[test]
    fn ml_dsa_spki_trailing_junk_rejected() {
        use crate::der::{Reader, encode_bit_string, encode_sequence, oid_tlv};
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"reg-mldsa-junk", b"n", &[]);
        let (sk, pk) = MlDsa65PrivateKey::generate(&mut rng);
        let sig = sk.sign(&mut rng, b"hi", b"").unwrap();
        let algo = find_by_id("ml-dsa-65").unwrap();

        let good = AnyPublicKey::MlDsa65(pk).to_spki_der();
        algo.verify(&good, b"hi", &sig).unwrap();
        let key_bits = {
            let mut outer = Reader::new(&good).read_sequence().unwrap();
            outer.read_sequence().unwrap();
            outer.read_bit_string().unwrap()
        };

        // NULL parameters inside the AlgorithmIdentifier.
        let algid =
            encode_sequence(&[oid_tlv(oid::ID_ML_DSA_65), alloc::vec![0x05, 0x00]].concat());
        let inner_junk = encode_sequence(&[algid, encode_bit_string(key_bits)].concat());
        assert!(algo.verify(&inner_junk, b"hi", &sig).is_err());

        // Junk after the BIT STRING.
        let algid = encode_sequence(&oid_tlv(oid::ID_ML_DSA_65));
        let outer_junk = encode_sequence(
            &[algid, encode_bit_string(key_bits), alloc::vec![0x05, 0x00]].concat(),
        );
        assert!(algo.verify(&outer_junk, b"hi", &sig).is_err());
    }

    #[test]
    fn ml_dsa_65_verify_via_registry() {
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"reg-mldsa65", b"n", &[]);
        let (sk, pk) = MlDsa65PrivateKey::generate(&mut rng);
        let spki = AnyPublicKey::MlDsa65(pk).to_spki_der();
        let sig = sk.sign(&mut rng, b"hi", b"").unwrap();

        let algo = find_by_id("ml-dsa-65").unwrap();
        algo.verify(&spki, b"hi", &sig).unwrap();
        assert!(algo.verify(&spki, b"other", &sig).is_err());
    }
}
