//! Algorithm-agnostic public keys and PKIX `SubjectPublicKeyInfo` (SPKI)
//! import/export.

use alloc::string::String;
use alloc::vec::Vec;

use super::{Error, algorithm_identifier, oid};
use crate::der::{
    Reader, encode_bit_string, encode_sequence, oid_tlv, parse_oid, pem_decode, pem_encode,
};
use crate::ec::ecdsa::{EcdsaPublicKey, Signature};
use crate::hash::{Sha256, Sha384};
use crate::rsa::BoxedRsaPublicKey;

const SPKI_LABEL: &str = "PUBLIC KEY";

/// A public key whose algorithm is determined at runtime — the form recovered
/// from a certificate or a PKIX SPKI document.
#[derive(Clone, Debug)]
pub enum AnyPublicKey {
    /// An RSA public key (runtime-sized).
    Rsa(BoxedRsaPublicKey),
    /// A NIST P-256 ECDSA public key.
    EcdsaP256(EcdsaPublicKey),
}

impl AnyPublicKey {
    /// Encodes the key as a PKIX `SubjectPublicKeyInfo` DER structure.
    pub fn to_spki_der(&self) -> Vec<u8> {
        match self {
            AnyPublicKey::Rsa(k) => {
                let algid = algorithm_identifier(oid::RSA_ENCRYPTION, true);
                encode_sequence(&[algid, encode_bit_string(&k.to_pkcs1_der())].concat())
            }
            AnyPublicKey::EcdsaP256(k) => {
                let algid = encode_sequence(
                    &[oid_tlv(oid::EC_PUBLIC_KEY), oid_tlv(oid::PRIME256V1)].concat(),
                );
                encode_sequence(&[algid, encode_bit_string(&k.to_sec1())].concat())
            }
        }
    }

    /// Encodes the key as a PKIX PEM document (`-----BEGIN PUBLIC KEY-----`).
    pub fn to_spki_pem(&self) -> String {
        pem_encode(SPKI_LABEL, &self.to_spki_der())
    }

    /// Parses a PKIX `SubjectPublicKeyInfo` DER structure.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(der);
        let mut spki = reader.read_sequence()?;
        let mut algid = spki.read_sequence()?;
        let alg = parse_oid(algid.read_oid()?)?;
        let key_bits = spki.read_bit_string()?;

        if alg.as_slice() == oid::RSA_ENCRYPTION {
            Ok(AnyPublicKey::Rsa(BoxedRsaPublicKey::from_pkcs1_der(
                key_bits,
            )?))
        } else if alg.as_slice() == oid::EC_PUBLIC_KEY {
            let curve = parse_oid(algid.read_oid()?)?;
            if curve.as_slice() != oid::PRIME256V1 {
                return Err(Error::UnsupportedAlgorithm);
            }
            Ok(AnyPublicKey::EcdsaP256(
                EcdsaPublicKey::from_sec1(key_bits).map_err(|_| Error::Malformed)?,
            ))
        } else {
            Err(Error::UnsupportedAlgorithm)
        }
    }

    /// Parses a PKIX PEM public key.
    pub fn from_spki_pem(pem: &str) -> Result<Self, Error> {
        Self::from_spki_der(&pem_decode(pem, SPKI_LABEL)?)
    }

    /// Verifies `sig` over `msg` under the signature algorithm identified by
    /// `sig_alg` OID arcs. RSA signatures are PKCS#1 v1.5; ECDSA signatures are
    /// DER `Ecdsa-Sig-Value`.
    pub fn verify(&self, sig_alg: &[u64], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        match self {
            AnyPublicKey::Rsa(k) => {
                if sig_alg == oid::SHA256_WITH_RSA {
                    k.verify_pkcs1v15::<Sha256>(msg, sig).map_err(Error::Rsa)
                } else if sig_alg == oid::SHA384_WITH_RSA {
                    k.verify_pkcs1v15::<Sha384>(msg, sig).map_err(Error::Rsa)
                } else {
                    Err(Error::UnsupportedAlgorithm)
                }
            }
            AnyPublicKey::EcdsaP256(k) => {
                let parsed = Signature::from_der(sig).map_err(|_| Error::Malformed)?;
                let ok = if sig_alg == oid::ECDSA_WITH_SHA256 {
                    k.verify::<Sha256>(msg, &parsed)
                } else if sig_alg == oid::ECDSA_WITH_SHA384 {
                    k.verify::<Sha384>(msg, &parsed)
                } else {
                    return Err(Error::UnsupportedAlgorithm);
                };
                ok.map_err(|_| Error::Verification)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::ecdsa::EcdsaPrivateKey;
    use crate::rng::HmacDrbg;
    use crate::test_util::rsa_test_key_a;

    #[test]
    fn rsa_spki_roundtrip() {
        let pk = rsa_test_key_a().public_key();
        let mut n = [0u8; 256];
        pk.modulus().write_be_bytes(&mut n);
        let mut e = [0u8; 256];
        pk.exponent().write_be_bytes(&mut e);
        let boxed = BoxedRsaPublicKey::new(
            crate::bignum::BoxedUint::from_be_bytes(&n),
            crate::bignum::BoxedUint::from_be_bytes(&e),
        );
        let any = AnyPublicKey::Rsa(boxed);

        let pem = any.to_spki_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        match AnyPublicKey::from_spki_pem(&pem).unwrap() {
            AnyPublicKey::Rsa(k) => assert_eq!(k.modulus().bit_len(), 2048),
            _ => panic!("expected RSA"),
        }
    }

    #[test]
    fn ec_spki_roundtrip_and_verify() {
        let mut rng = HmacDrbg::<Sha256>::new(b"spki-ec", b"n", &[]);
        let sk = EcdsaPrivateKey::generate(&mut rng);
        let any = AnyPublicKey::EcdsaP256(sk.public_key());

        let der = any.to_spki_der();
        let parsed = AnyPublicKey::from_spki_der(&der).unwrap();
        // Sign with ECDSA, DER-encode, verify through AnyPublicKey.
        let sig = sk.sign::<Sha256>(b"hello").unwrap();
        parsed
            .verify(oid::ECDSA_WITH_SHA256, b"hello", &sig.to_der())
            .unwrap();
        assert!(
            parsed
                .verify(oid::ECDSA_WITH_SHA256, b"other", &sig.to_der())
                .is_err()
        );
    }
}
