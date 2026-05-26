//! Elliptic-curve entries in the signature registry.
//!
//! Three ECDSA entries (matched-curve / matched-hash pairs over the NIST
//! curves) and Ed25519. Each `verify` parses the SPKI to recover the public
//! key and delegates to the existing primitive.
//!
//! ECDSA signatures are DER-encoded `Ecdsa-Sig-Value` per RFC 5480, regardless
//! of where they came from (X.509 chain signatures and TLS 1.3
//! `CertificateVerify` both wrap them this way).

use crate::der::{Reader, parse_oid};
use crate::ec::{
    BoxedEcdsaPublicKey, BoxedEcdsaSignature, CurveId, Ed25519PublicKey, Ed25519Signature,
};
use crate::hash::{Sha256, Sha384, Sha512};
use crate::signature_registry::SignatureAlgorithm;
use crate::x509::{Error, oid};

/// Parses an `id-ecPublicKey` SPKI and returns `(curve, key)`. Errors on a
/// non-EC SPKI or an unsupported curve.
fn parse_ecdsa_spki(spki: &[u8]) -> Result<(CurveId, BoxedEcdsaPublicKey), Error> {
    let mut reader = Reader::new(spki);
    let mut outer = reader.read_sequence()?;
    let mut algid = outer.read_sequence()?;
    let alg = parse_oid(algid.read_oid()?)?;
    if alg.as_slice() != oid::EC_PUBLIC_KEY {
        return Err(Error::UnsupportedAlgorithm);
    }
    let curve_arcs = parse_oid(algid.read_oid()?)?;
    let curve = if curve_arcs.as_slice() == oid::PRIME256V1 {
        CurveId::P256
    } else if curve_arcs.as_slice() == oid::SECP384R1 {
        CurveId::P384
    } else if curve_arcs.as_slice() == oid::SECP521R1 {
        CurveId::P521
    } else if curve_arcs.as_slice() == oid::SECP256K1 {
        CurveId::Secp256k1
    } else {
        return Err(Error::UnsupportedAlgorithm);
    };
    let key_bits = outer.read_bit_string()?;
    let key = BoxedEcdsaPublicKey::from_sec1(curve, key_bits).map_err(|_| Error::Malformed)?;
    Ok((curve, key))
}

/// Parses an Ed25519 SPKI and returns the 32-byte key.
fn parse_ed25519_spki(spki: &[u8]) -> Result<Ed25519PublicKey, Error> {
    let mut reader = Reader::new(spki);
    let mut outer = reader.read_sequence()?;
    let mut algid = outer.read_sequence()?;
    let alg = parse_oid(algid.read_oid()?)?;
    if alg.as_slice() != oid::ID_ED25519 {
        return Err(Error::UnsupportedAlgorithm);
    }
    let key_bits = outer.read_bit_string()?;
    let bytes: [u8; 32] = key_bits.try_into().map_err(|_| Error::Malformed)?;
    Ok(Ed25519PublicKey::from_bytes(bytes))
}

/// Shared ECDSA verify path: the OID fixes the hash; the key's curve must
/// match `expected_curve`.
fn verify_ecdsa<D: crate::hash::Digest>(
    spki: &[u8],
    message: &[u8],
    signature: &[u8],
    expected_curve: CurveId,
) -> Result<(), Error> {
    let (curve, key) = parse_ecdsa_spki(spki)?;
    if curve != expected_curve {
        return Err(Error::UnsupportedAlgorithm);
    }
    let sig = BoxedEcdsaSignature::from_der(signature).map_err(|_| Error::Malformed)?;
    key.verify::<D>(message, &sig)
        .map_err(|_| Error::Verification)
}

/// `ecdsa_secp256r1_sha256` — ECDSA on P-256 with SHA-256.
/// X.509 OID `1.2.840.10045.4.3.2`; TLS scheme `0x0403`.
pub(crate) struct EcdsaP256Sha256;

impl SignatureAlgorithm for EcdsaP256Sha256 {
    fn id(&self) -> &'static str {
        "ecdsa-secp256r1-sha256"
    }
    fn x509_oids(&self) -> &'static [&'static [u64]] {
        &[oid::ECDSA_WITH_SHA256]
    }
    fn tls_schemes(&self) -> &'static [u16] {
        &[0x0403]
    }
    fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        verify_ecdsa::<Sha256>(spki, message, signature, CurveId::P256)
    }
}

/// `ecdsa_secp384r1_sha384` — ECDSA on P-384 with SHA-384.
/// X.509 OID `1.2.840.10045.4.3.3`; TLS scheme `0x0503`.
pub(crate) struct EcdsaP384Sha384;

impl SignatureAlgorithm for EcdsaP384Sha384 {
    fn id(&self) -> &'static str {
        "ecdsa-secp384r1-sha384"
    }
    fn x509_oids(&self) -> &'static [&'static [u64]] {
        &[oid::ECDSA_WITH_SHA384]
    }
    fn tls_schemes(&self) -> &'static [u16] {
        &[0x0503]
    }
    fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        verify_ecdsa::<Sha384>(spki, message, signature, CurveId::P384)
    }
}

/// `ecdsa_secp521r1_sha512` — ECDSA on P-521 with SHA-512.
/// X.509 OID `1.2.840.10045.4.3.4`; TLS scheme `0x0603`.
pub(crate) struct EcdsaP521Sha512;

impl SignatureAlgorithm for EcdsaP521Sha512 {
    fn id(&self) -> &'static str {
        "ecdsa-secp521r1-sha512"
    }
    fn x509_oids(&self) -> &'static [&'static [u64]] {
        &[oid::ECDSA_WITH_SHA512]
    }
    fn tls_schemes(&self) -> &'static [u16] {
        &[0x0603]
    }
    fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        verify_ecdsa::<Sha512>(spki, message, signature, CurveId::P521)
    }
}

/// `ed25519` — pure Ed25519 (RFC 8032 / RFC 8410).
/// X.509 OID `1.3.101.112`; TLS scheme `0x0807`.
pub(crate) struct Ed25519;

impl SignatureAlgorithm for Ed25519 {
    fn id(&self) -> &'static str {
        "ed25519"
    }
    fn x509_oids(&self) -> &'static [&'static [u64]] {
        &[oid::ID_ED25519]
    }
    fn tls_schemes(&self) -> &'static [u16] {
        &[0x0807]
    }
    fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let key = parse_ed25519_spki(spki)?;
        // Ed25519 signatures are the raw 64-byte R‖S.
        let bytes: [u8; 64] = signature.try_into().map_err(|_| Error::Malformed)?;
        key.verify(message, &Ed25519Signature::from_bytes(bytes))
            .map_err(|_| Error::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::BoxedEcdsaPrivateKey;
    use crate::rng::HmacDrbg;
    use crate::signature_registry::{find_by_id, find_by_oid, find_by_tls_scheme};
    use crate::x509::AnyPublicKey;

    #[test]
    fn ecdsa_p256_sha256_verify_via_registry() {
        let mut rng = HmacDrbg::<Sha256>::new(b"reg-ec-p256", b"n", &[]);
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let pk = AnyPublicKey::Ecdsa(sk.public_key());
        let spki = pk.to_spki_der();
        let sig = sk.sign::<Sha256>(b"hi").unwrap().to_der(CurveId::P256);

        let algo = find_by_id("ecdsa-secp256r1-sha256").unwrap();
        algo.verify(&spki, b"hi", &sig).unwrap();
        assert!(algo.verify(&spki, b"other", &sig).is_err());

        // Lookups by OID and TLS scheme.
        let by_oid = find_by_oid(oid::ECDSA_WITH_SHA256).unwrap();
        assert_eq!(by_oid.id(), "ecdsa-secp256r1-sha256");
        let by_scheme = find_by_tls_scheme(0x0403).unwrap();
        assert_eq!(by_scheme.id(), "ecdsa-secp256r1-sha256");
    }

    #[test]
    fn ecdsa_p384_curve_mismatch_rejected() {
        let mut rng = HmacDrbg::<Sha256>::new(b"reg-ec-p256-2", b"n", &[]);
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let pk = AnyPublicKey::Ecdsa(sk.public_key());
        let spki = pk.to_spki_der();
        let sig = sk.sign::<Sha256>(b"hi").unwrap().to_der(CurveId::P256);
        // The registry entry pins P-384 + SHA-384; a P-256 SPKI must be
        // rejected (regardless of whether the signature would actually verify
        // under a SHA-384 path).
        let algo = find_by_id("ecdsa-secp384r1-sha384").unwrap();
        assert!(algo.verify(&spki, b"hi", &sig).is_err());
    }

    #[test]
    fn ed25519_verify_via_registry() {
        use crate::ec::Ed25519PrivateKey;
        let mut rng = HmacDrbg::<Sha256>::new(b"reg-ed25519", b"n", &[]);
        let sk = Ed25519PrivateKey::generate(&mut rng);
        let pk = AnyPublicKey::Ed25519(sk.public_key());
        let spki = pk.to_spki_der();
        let sig = sk.sign(b"hi").to_bytes().to_vec();

        let algo = find_by_id("ed25519").unwrap();
        algo.verify(&spki, b"hi", &sig).unwrap();
        assert!(algo.verify(&spki, b"other", &sig).is_err());
    }
}
