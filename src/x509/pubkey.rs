//! Algorithm-agnostic public keys and PKIX `SubjectPublicKeyInfo` (SPKI)
//! import/export.

use alloc::string::String;
use alloc::vec::Vec;

use super::{Error, algorithm_identifier, oid};
use crate::der::{
    Reader, encode_bit_string, encode_sequence, oid_tlv, parse_oid, pem_decode, pem_encode,
};
use crate::ec::{BoxedEcdsaPublicKey, CurveId, Ed448PublicKey, Ed25519PublicKey};
#[cfg(feature = "mldsa")]
use crate::mldsa::{MlDsa44PublicKey, MlDsa65PublicKey, MlDsa87PublicKey};
use crate::rsa::BoxedRsaPublicKey;
#[cfg(feature = "slhdsa")]
use crate::slhdsa;

const SPKI_LABEL: &str = "PUBLIC KEY";

/// Encodes an ML-DSA (FIPS 204) `SubjectPublicKeyInfo`: bare OID
/// AlgorithmIdentifier (no parameters) wrapping the raw key bytes.
#[cfg(feature = "mldsa")]
fn mldsa_spki(oid: &[u64], key: &[u8]) -> Vec<u8> {
    let algid = encode_sequence(&oid_tlv(oid));
    encode_sequence(&[algid, encode_bit_string(key)].concat())
}

/// The X.509 named-curve OID for a curve.
fn curve_oid(curve: CurveId) -> &'static [u64] {
    match curve {
        CurveId::P256 => oid::PRIME256V1,
        CurveId::P384 => oid::SECP384R1,
        CurveId::P521 => oid::SECP521R1,
        CurveId::Secp256k1 => oid::SECP256K1,
        CurveId::Sm2p256v1 => oid::SM2_P256V1,
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
    } else if arcs == oid::SM2_P256V1 {
        Some(CurveId::Sm2p256v1)
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
    /// An Ed448 public key.
    Ed448(Ed448PublicKey),
    /// An ML-DSA-44 (FIPS 204) public key.
    #[cfg(feature = "mldsa")]
    MlDsa44(MlDsa44PublicKey),
    /// An ML-DSA-65 (FIPS 204) public key.
    #[cfg(feature = "mldsa")]
    MlDsa65(MlDsa65PublicKey),
    /// An ML-DSA-87 (FIPS 204) public key.
    #[cfg(feature = "mldsa")]
    MlDsa87(MlDsa87PublicKey),
    /// An SLH-DSA (FIPS 205) public key. The variant carries the parameter
    /// set inside the [`slhdsa::PublicKey`] (so a single enum arm covers all
    /// twelve standardized sets).
    #[cfg(feature = "slhdsa")]
    SlhDsa(slhdsa::PublicKey),
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
            AnyPublicKey::Ed448(k) => {
                // RFC 8410: AlgorithmIdentifier is the bare OID (no parameters).
                let algid = encode_sequence(&oid_tlv(oid::ID_ED448));
                encode_sequence(&[algid, encode_bit_string(&k.to_bytes())].concat())
            }
            // ML-DSA (draft-ietf-lamps-dilithium-certificates): bare OID, no
            // parameters; key bytes are the raw FIPS 204 encoding.
            #[cfg(feature = "mldsa")]
            AnyPublicKey::MlDsa44(k) => mldsa_spki(oid::ID_ML_DSA_44, k.to_bytes()),
            #[cfg(feature = "mldsa")]
            AnyPublicKey::MlDsa65(k) => mldsa_spki(oid::ID_ML_DSA_65, k.to_bytes()),
            #[cfg(feature = "mldsa")]
            AnyPublicKey::MlDsa87(k) => mldsa_spki(oid::ID_ML_DSA_87, k.to_bytes()),
            #[cfg(feature = "slhdsa")]
            AnyPublicKey::SlhDsa(k) => k.to_spki_der(),
        }
    }

    /// Encodes the key as a PKIX PEM document (`-----BEGIN PUBLIC KEY-----`).
    pub fn to_spki_pem(&self) -> String {
        pem_encode(SPKI_LABEL, &self.to_spki_der())
    }

    /// Parses a PKIX `SubjectPublicKeyInfo` DER structure.
    ///
    /// The `AlgorithmIdentifier.parameters` field is validated per
    /// algorithm (RFC 5280 §4.1.1.2 / §4.1.2.7, RFC 4055 §2.1, RFC 8410):
    ///
    /// * `rsaEncryption` — explicit NULL required.
    /// * `id-ecPublicKey` — named-curve OID, then no trailing junk.
    /// * `id-Ed25519` — no parameters.
    /// * `id-Ed448` — no parameters.
    /// * `id-RSASSA-PSS` — parameter block accepted as-is; the verifier
    ///   hard-codes the SHA-256 / MGF1-SHA-256 / salt=32 set, so trailing
    ///   junk after that block is rejected.
    /// * `id-ml-dsa-*` / SLH-DSA — bare OID, no parameters.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(der);
        let mut spki = reader.read_sequence()?;
        let mut algid = spki.read_sequence()?;
        let alg = parse_oid(algid.read_oid()?)?;

        if alg.as_slice() == oid::RSA_ENCRYPTION {
            // RFC 3279 §2.3.1: parameters MUST be NULL for rsaEncryption.
            algid.read_null()?;
            algid.finish()?;
            let key_bits = spki.read_bit_string()?;
            spki.finish()?;
            Ok(AnyPublicKey::Rsa(BoxedRsaPublicKey::from_pkcs1_der(
                key_bits,
            )?))
        } else if alg.as_slice() == oid::EC_PUBLIC_KEY {
            let curve_arcs = parse_oid(algid.read_oid()?)?;
            // RFC 5480 §2.1.1: the only parameters we accept after the OID
            // are the namedCurve. Reject ECParameters trailers, implicitCA,
            // or any junk.
            algid.finish()?;
            let curve = curve_from_oid(curve_arcs.as_slice()).ok_or(Error::UnsupportedAlgorithm)?;
            let key_bits = spki.read_bit_string()?;
            spki.finish()?;
            Ok(AnyPublicKey::Ecdsa(
                BoxedEcdsaPublicKey::from_sec1(curve, key_bits).map_err(|_| Error::Malformed)?,
            ))
        } else if alg.as_slice() == oid::ID_ED25519 {
            // RFC 8410 §3: AlgorithmIdentifier MUST be the bare OID — no
            // parameters at all.
            algid.finish()?;
            let key_bits = spki.read_bit_string()?;
            spki.finish()?;
            let bytes: [u8; 32] = key_bits.try_into().map_err(|_| Error::Malformed)?;
            Ok(AnyPublicKey::Ed25519(Ed25519PublicKey::from_bytes(bytes)))
        } else if alg.as_slice() == oid::ID_ED448 {
            // RFC 8410 §3: AlgorithmIdentifier MUST be the bare OID — no
            // parameters at all.
            algid.finish()?;
            let key_bits = spki.read_bit_string()?;
            spki.finish()?;
            let bytes: [u8; 57] = key_bits.try_into().map_err(|_| Error::Malformed)?;
            Ok(AnyPublicKey::Ed448(Ed448PublicKey::from_bytes(bytes)))
        } else {
            #[cfg(feature = "mldsa")]
            {
                if alg.as_slice() == oid::ID_ML_DSA_44 {
                    // FIPS 204 / draft-ietf-lamps-dilithium-certificates:
                    // bare OID, no parameters.
                    algid.finish()?;
                    let key_bits = spki.read_bit_string()?;
                    spki.finish()?;
                    return Ok(AnyPublicKey::MlDsa44(
                        MlDsa44PublicKey::from_bytes(key_bits).map_err(|_| Error::Malformed)?,
                    ));
                } else if alg.as_slice() == oid::ID_ML_DSA_65 {
                    algid.finish()?;
                    let key_bits = spki.read_bit_string()?;
                    spki.finish()?;
                    return Ok(AnyPublicKey::MlDsa65(
                        MlDsa65PublicKey::from_bytes(key_bits).map_err(|_| Error::Malformed)?,
                    ));
                } else if alg.as_slice() == oid::ID_ML_DSA_87 {
                    algid.finish()?;
                    let key_bits = spki.read_bit_string()?;
                    spki.finish()?;
                    return Ok(AnyPublicKey::MlDsa87(
                        MlDsa87PublicKey::from_bytes(key_bits).map_err(|_| Error::Malformed)?,
                    ));
                }
            }
            #[cfg(feature = "slhdsa")]
            {
                if let Some(set) = slhdsa::ParamSet::from_oid(alg.as_slice()) {
                    // SLH-DSA: bare OID, no parameters.
                    algid.finish()?;
                    let key_bits = spki.read_bit_string()?;
                    spki.finish()?;
                    let pk = slhdsa::PublicKey::from_bytes(set, key_bits)
                        .map_err(|_| Error::Malformed)?;
                    return Ok(AnyPublicKey::SlhDsa(pk));
                }
            }
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

    #[test]
    fn ed448_spki_roundtrip_and_verify() {
        use crate::ec::Ed448PrivateKey;
        let mut rng = HmacDrbg::<Sha256>::new(b"spki-ed448", b"n", &[]);
        let sk = Ed448PrivateKey::generate(&mut rng);
        let any = AnyPublicKey::Ed448(sk.public_key());

        let pem = any.to_spki_pem();
        let parsed = AnyPublicKey::from_spki_pem(&pem).unwrap();
        assert!(matches!(parsed, AnyPublicKey::Ed448(_)));

        // Ed448 signatures are raw 114-byte R‖S (empty context), verified
        // under id-Ed448.
        let sig = sk.sign(b"hello").to_bytes();
        parsed.verify(oid::ID_ED448, b"hello", &sig).unwrap();
        assert!(parsed.verify(oid::ID_ED448, b"other", &sig).is_err());
    }

    // H-7: RFC 3279 §2.3.1 — rsaEncryption REQUIRES explicit NULL
    // parameters in the AlgorithmIdentifier. An SPKI that places an
    // ECParameters OID (or any other tag) where NULL belongs must be
    // rejected. id-Ed25519 likewise requires NO parameters; id-ecPublicKey
    // requires exactly the namedCurve OID and nothing trailing.
    #[test]
    fn spki_rsa_requires_null_params() {
        use crate::der::{encode_bit_string, encode_sequence, oid_tlv};

        // Build a real RSA public-key BIT STRING from the test key.
        let pk = rsa_test_key_a().public_key();
        let mut n_bytes = [0u8; 256];
        pk.modulus().write_be_bytes(&mut n_bytes);
        let mut e_bytes = [0u8; 256];
        pk.exponent().write_be_bytes(&mut e_bytes);
        let boxed = BoxedRsaPublicKey::new(
            crate::bignum::BoxedUint::from_be_bytes(&n_bytes),
            crate::bignum::BoxedUint::from_be_bytes(&e_bytes),
        );
        let pkcs1 = boxed.to_pkcs1_der();
        let key_bits = encode_bit_string(&pkcs1);

        // (a) rsaEncryption with NULL params — sanity: parses fine.
        let algid_ok =
            encode_sequence(&[oid_tlv(oid::RSA_ENCRYPTION), crate::der::encode_null()].concat());
        let spki_ok = encode_sequence(&[algid_ok, key_bits.clone()].concat());
        assert!(AnyPublicKey::from_spki_der(&spki_ok).is_ok());

        // (b) rsaEncryption with a non-NULL parameter (e.g. an OID where
        //     NULL belongs). Must be rejected.
        let algid_bad =
            encode_sequence(&[oid_tlv(oid::RSA_ENCRYPTION), oid_tlv(oid::PRIME256V1)].concat());
        let spki_bad = encode_sequence(&[algid_bad, key_bits.clone()].concat());
        assert!(AnyPublicKey::from_spki_der(&spki_bad).is_err());

        // (c) rsaEncryption with NO parameter at all (bare OID). Must be
        //     rejected — the NULL is mandatory.
        let algid_missing = encode_sequence(&oid_tlv(oid::RSA_ENCRYPTION));
        let spki_missing = encode_sequence(&[algid_missing, key_bits.clone()].concat());
        assert!(AnyPublicKey::from_spki_der(&spki_missing).is_err());

        // (d) rsaEncryption with NULL params followed by trailing junk
        //     inside the AlgorithmIdentifier SEQUENCE. Must be rejected.
        let algid_trailing = encode_sequence(
            &[
                oid_tlv(oid::RSA_ENCRYPTION),
                crate::der::encode_null(),
                crate::der::encode_tlv(0x01, &[0x00]), // BOOLEAN false
            ]
            .concat(),
        );
        let spki_trailing = encode_sequence(&[algid_trailing, key_bits].concat());
        assert!(AnyPublicKey::from_spki_der(&spki_trailing).is_err());
    }
}
