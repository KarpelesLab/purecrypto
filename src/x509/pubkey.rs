//! Algorithm-agnostic public keys and PKIX `SubjectPublicKeyInfo` (SPKI)
//! import/export.

use alloc::string::String;
use alloc::vec::Vec;

use super::{Error, algorithm_identifier, oid};
use crate::der::{
    Reader, encode_bit_string, encode_sequence, oid_tlv, parse_oid, pem_decode, pem_encode,
};
use crate::ec::{BoxedEcdsaPublicKey, CurveId, Ed25519PublicKey};
use crate::rsa::BoxedRsaPublicKey;

const SPKI_LABEL: &str = "PUBLIC KEY";

/// The X.509 named-curve OID for a curve.
fn curve_oid(curve: CurveId) -> &'static [u64] {
    match curve {
        CurveId::P256 => oid::PRIME256V1,
        CurveId::P384 => oid::SECP384R1,
        CurveId::P521 => oid::SECP521R1,
        CurveId::Secp256k1 => oid::SECP256K1,
    }
}

/// Maps a named-curve OID to a [`CurveId`].
fn curve_from_oid(arcs: &[u64]) -> Option<CurveId> {
    if arcs == oid::PRIME256V1 {
        Some(CurveId::P256)
    } else if arcs == oid::SECP384R1 {
        Some(CurveId::P384)
    } else if arcs == oid::SECP521R1 {
        Some(CurveId::P521)
    } else if arcs == oid::SECP256K1 {
        Some(CurveId::Secp256k1)
    } else {
        None
    }
}

/// A public key whose algorithm is determined at runtime — the form recovered
/// from a certificate or a PKIX SPKI document.
#[derive(Clone, Debug)]
pub enum AnyPublicKey {
    /// An RSA public key (runtime-sized).
    Rsa(BoxedRsaPublicKey),
    /// An ECDSA public key on one of the supported curves.
    Ecdsa(BoxedEcdsaPublicKey),
    /// An Ed25519 public key.
    Ed25519(Ed25519PublicKey),
}

impl AnyPublicKey {
    /// Encodes the key as a PKIX `SubjectPublicKeyInfo` DER structure.
    pub fn to_spki_der(&self) -> Vec<u8> {
        match self {
            AnyPublicKey::Rsa(k) => {
                let algid = algorithm_identifier(oid::RSA_ENCRYPTION, true);
                encode_sequence(&[algid, encode_bit_string(&k.to_pkcs1_der())].concat())
            }
            AnyPublicKey::Ecdsa(k) => {
                let algid = encode_sequence(
                    &[oid_tlv(oid::EC_PUBLIC_KEY), oid_tlv(curve_oid(k.curve()))].concat(),
                );
                encode_sequence(&[algid, encode_bit_string(&k.to_sec1())].concat())
            }
            AnyPublicKey::Ed25519(k) => {
                // RFC 8410: AlgorithmIdentifier is the bare OID (no parameters).
                let algid = encode_sequence(&oid_tlv(oid::ID_ED25519));
                encode_sequence(&[algid, encode_bit_string(&k.to_bytes())].concat())
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
            let curve_arcs = parse_oid(algid.read_oid()?)?;
            let curve = curve_from_oid(curve_arcs.as_slice()).ok_or(Error::UnsupportedAlgorithm)?;
            Ok(AnyPublicKey::Ecdsa(
                BoxedEcdsaPublicKey::from_sec1(curve, key_bits).map_err(|_| Error::Malformed)?,
            ))
        } else if alg.as_slice() == oid::ID_ED25519 {
            let bytes: [u8; 32] = key_bits.try_into().map_err(|_| Error::Malformed)?;
            Ok(AnyPublicKey::Ed25519(Ed25519PublicKey::from_bytes(bytes)))
        } else {
            Err(Error::UnsupportedAlgorithm)
        }
    }

    /// Parses a PKIX PEM public key.
    pub fn from_spki_pem(pem: &str) -> Result<Self, Error> {
        Self::from_spki_der(&pem_decode(pem, SPKI_LABEL)?)
    }

    /// Verifies `sig` over `msg` under the signature algorithm identified by
    /// `sig_alg` OID arcs.
    ///
    /// Dispatch goes through [`crate::signature_registry`]: the OID picks an
    /// entry in [`ALGORITHMS`](crate::signature_registry::ALGORITHMS), which
    /// then re-parses the SPKI to recover the key and verifies. RSA
    /// signatures are PKCS#1 v1.5 or RSA-PSS (the OID fixes which);
    /// ECDSA signatures are DER `Ecdsa-Sig-Value`; Ed25519 is raw 64-byte R‖S.
    pub fn verify(&self, sig_alg: &[u64], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let algo =
            crate::signature_registry::find_by_oid(sig_alg).ok_or(Error::UnsupportedAlgorithm)?;
        // The registry entry's `verify` parses an SPKI; round-trip ours.
        let spki = self.to_spki_der();
        algo.verify(&spki, msg, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::BoxedEcdsaPrivateKey;
    use crate::hash::{Sha256, Sha384, Sha512};
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
        // Each supported curve round-trips through SPKI and verifies a signature.
        for (curve, sig_alg) in [
            (CurveId::P256, oid::ECDSA_WITH_SHA256),
            (CurveId::P384, oid::ECDSA_WITH_SHA384),
            (CurveId::P521, oid::ECDSA_WITH_SHA512),
        ] {
            let mut rng = HmacDrbg::<Sha256>::new(b"spki-ec", b"n", &[]);
            let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
            let any = AnyPublicKey::Ecdsa(sk.public_key());

            let der = any.to_spki_der();
            let parsed = AnyPublicKey::from_spki_der(&der).unwrap();
            match &parsed {
                AnyPublicKey::Ecdsa(k) => assert_eq!(k.curve(), curve),
                _ => panic!("expected ECDSA"),
            }

            let sig = match curve {
                CurveId::P256 => sk.sign::<Sha256>(b"hello").unwrap(),
                CurveId::P384 => sk.sign::<Sha384>(b"hello").unwrap(),
                _ => sk.sign::<Sha512>(b"hello").unwrap(),
            };
            parsed
                .verify(sig_alg, b"hello", &sig.to_der(curve))
                .unwrap();
            assert!(
                parsed
                    .verify(sig_alg, b"other", &sig.to_der(curve))
                    .is_err()
            );
        }
    }

    #[test]
    fn ed25519_spki_roundtrip_and_verify() {
        use crate::ec::Ed25519PrivateKey;
        let mut rng = HmacDrbg::<Sha256>::new(b"spki-ed", b"n", &[]);
        let sk = Ed25519PrivateKey::generate(&mut rng);
        let any = AnyPublicKey::Ed25519(sk.public_key());

        let pem = any.to_spki_pem();
        let parsed = AnyPublicKey::from_spki_pem(&pem).unwrap();
        assert!(matches!(parsed, AnyPublicKey::Ed25519(_)));

        // Ed25519 signatures are raw 64-byte R‖S, verified under id-Ed25519.
        let sig = sk.sign(b"hello").to_bytes();
        parsed.verify(oid::ID_ED25519, b"hello", &sig).unwrap();
        assert!(parsed.verify(oid::ID_ED25519, b"other", &sig).is_err());
    }
}
