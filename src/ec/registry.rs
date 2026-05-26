//! Elliptic-curve entries in the signature registry.
//!
//! Two "shapes" of ECDSA entry:
//!
//! 1. **OID-keyed** entries (`EcdsaSha{256,384,512}AnyCurve`) — used for
//!    X.509 chain dispatch. The X.509 OID `ecdsa-with-SHA-N` does NOT pin
//!    the curve; the curve is inferred from the issuer SPKI. These entries
//!    accept any supported curve at verify time. They have no TLS scheme.
//! 2. **Strict curve/hash pair** entries (`EcdsaP{256,384,521}Sha{256,384,
//!    512}`, `EcdsaSecp256k1Sha{256,384,512}`) — used for TLS 1.3
//!    `CertificateVerify` dispatch (one TLS scheme code point per pair) and
//!    for fine-grained policy whitelisting (the modern default permits only
//!    the matched-curve / matched-hash pairs; cross-hash pairs and
//!    secp256k1 require opt-in).
//!
//! Ed25519 has a single entry (the OID and the TLS scheme both fully pin
//! the algorithm).
//!
//! ECDSA signatures are DER-encoded `Ecdsa-Sig-Value` per RFC 5480, in both
//! X.509 chain signatures and TLS 1.3 `CertificateVerify`.

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

/// Shared ECDSA strict verify: the curve in the SPKI must equal
/// `expected_curve`. Used by the TLS-keyed entries.
fn verify_ecdsa_strict<D: crate::hash::Digest>(
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

/// Shared ECDSA OID-keyed verify: any supported curve is accepted. The hash
/// is fixed by the OID. Used by the X.509-keyed entries.
fn verify_ecdsa_any_curve<D: crate::hash::Digest>(
    spki: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let (_curve, key) = parse_ecdsa_spki(spki)?;
    let sig = BoxedEcdsaSignature::from_der(signature).map_err(|_| Error::Malformed)?;
    key.verify::<D>(message, &sig)
        .map_err(|_| Error::Verification)
}

// --- X.509-keyed ECDSA entries (one per OID, any curve) ---

/// X.509 `ecdsa-with-SHA256` — used as the OID-keyed dispatch entry for the
/// chain verifier. Accepts any supported curve; the hash is fixed at SHA-256.
pub(crate) struct EcdsaSha256AnyCurve;

impl SignatureAlgorithm for EcdsaSha256AnyCurve {
    fn id(&self) -> &'static str {
        "ecdsa-with-sha256"
    }
    fn x509_oids(&self) -> &'static [&'static [u64]] {
        &[oid::ECDSA_WITH_SHA256]
    }
    fn tls_schemes(&self) -> &'static [u16] {
        &[]
    }
    fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        verify_ecdsa_any_curve::<Sha256>(spki, message, signature)
    }
}

/// X.509 `ecdsa-with-SHA384` — OID-keyed dispatch entry.
pub(crate) struct EcdsaSha384AnyCurve;

impl SignatureAlgorithm for EcdsaSha384AnyCurve {
    fn id(&self) -> &'static str {
        "ecdsa-with-sha384"
    }
    fn x509_oids(&self) -> &'static [&'static [u64]] {
        &[oid::ECDSA_WITH_SHA384]
    }
    fn tls_schemes(&self) -> &'static [u16] {
        &[]
    }
    fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        verify_ecdsa_any_curve::<Sha384>(spki, message, signature)
    }
}

/// X.509 `ecdsa-with-SHA512` — OID-keyed dispatch entry.
pub(crate) struct EcdsaSha512AnyCurve;

impl SignatureAlgorithm for EcdsaSha512AnyCurve {
    fn id(&self) -> &'static str {
        "ecdsa-with-sha512"
    }
    fn x509_oids(&self) -> &'static [&'static [u64]] {
        &[oid::ECDSA_WITH_SHA512]
    }
    fn tls_schemes(&self) -> &'static [u16] {
        &[]
    }
    fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        verify_ecdsa_any_curve::<Sha512>(spki, message, signature)
    }
}

// --- TLS / strict-pair ECDSA entries ---
//
// Each entry pins both the curve and the hash. The TLS-allocated scheme
// codes (RFC 8446 §4.2.3) match the matched-curve / matched-hash pairs;
// cross-hash pairs have no TLS scheme but exist as registry entries so
// the policy can decide pair-by-pair (the modern default permits only the
// matched-pair set).
macro_rules! strict_ecdsa_entry {
    (
        $(#[$m:meta])*
        $name:ident, $id:expr, $curve:expr, $digest:ty, $tls_schemes:expr
    ) => {
        $(#[$m])*
        pub(crate) struct $name;

        impl SignatureAlgorithm for $name {
            fn id(&self) -> &'static str { $id }
            fn x509_oids(&self) -> &'static [&'static [u64]] { &[] }
            fn tls_schemes(&self) -> &'static [u16] { $tls_schemes }
            fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
                verify_ecdsa_strict::<$digest>(spki, message, signature, $curve)
            }
        }
    };
}

strict_ecdsa_entry!(
    /// `ecdsa_secp256r1_sha256` — P-256 + SHA-256. TLS scheme `0x0403`.
    EcdsaP256Sha256, "ecdsa-secp256r1-sha256", CurveId::P256, Sha256, &[0x0403]
);
strict_ecdsa_entry!(
    /// `ecdsa_secp384r1_sha384` — P-384 + SHA-384. TLS scheme `0x0503`.
    EcdsaP384Sha384, "ecdsa-secp384r1-sha384", CurveId::P384, Sha384, &[0x0503]
);
strict_ecdsa_entry!(
    /// `ecdsa_secp521r1_sha512` — P-521 + SHA-512. TLS scheme `0x0603`.
    EcdsaP521Sha512, "ecdsa-secp521r1-sha512", CurveId::P521, Sha512, &[0x0603]
);

// Cross-hash pairs — no TLS scheme; opt-in via policy.
strict_ecdsa_entry!(
    /// P-256 with SHA-384. No IANA TLS scheme; registered for policy
    /// whitelisting only.
    EcdsaP256Sha384, "ecdsa-secp256r1-sha384", CurveId::P256, Sha384, &[]
);
strict_ecdsa_entry!(
    /// P-256 with SHA-512. Policy-only.
    EcdsaP256Sha512, "ecdsa-secp256r1-sha512", CurveId::P256, Sha512, &[]
);
strict_ecdsa_entry!(
    /// P-384 with SHA-256. Policy-only.
    EcdsaP384Sha256, "ecdsa-secp384r1-sha256", CurveId::P384, Sha256, &[]
);
strict_ecdsa_entry!(
    /// P-384 with SHA-512. Policy-only.
    EcdsaP384Sha512, "ecdsa-secp384r1-sha512", CurveId::P384, Sha512, &[]
);
strict_ecdsa_entry!(
    /// P-521 with SHA-256. Policy-only.
    EcdsaP521Sha256, "ecdsa-secp521r1-sha256", CurveId::P521, Sha256, &[]
);
strict_ecdsa_entry!(
    /// P-521 with SHA-384. Policy-only.
    EcdsaP521Sha384, "ecdsa-secp521r1-sha384", CurveId::P521, Sha384, &[]
);

// secp256k1 — no TLS scheme; opt-in for X.509 chains carrying secp256k1.
strict_ecdsa_entry!(
    /// secp256k1 with SHA-256. Policy-only.
    EcdsaSecp256k1Sha256, "ecdsa-secp256k1-sha256", CurveId::Secp256k1, Sha256, &[]
);
strict_ecdsa_entry!(
    /// secp256k1 with SHA-384. Policy-only.
    EcdsaSecp256k1Sha384, "ecdsa-secp256k1-sha384", CurveId::Secp256k1, Sha384, &[]
);
strict_ecdsa_entry!(
    /// secp256k1 with SHA-512. Policy-only.
    EcdsaSecp256k1Sha512, "ecdsa-secp256k1-sha512", CurveId::Secp256k1, Sha512, &[]
);

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

        // X.509 OID resolves to the any-curve entry; TLS scheme to the strict pair.
        let by_oid = find_by_oid(oid::ECDSA_WITH_SHA256).unwrap();
        assert_eq!(by_oid.id(), "ecdsa-with-sha256");
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
        // The strict-pair P-384 entry must reject a P-256 SPKI.
        let algo = find_by_id("ecdsa-secp384r1-sha384").unwrap();
        assert!(algo.verify(&spki, b"hi", &sig).is_err());
    }

    /// secp256k1 entries are registered but not on the modern() whitelist;
    /// the verify path itself works once an explicit policy permits it.
    #[test]
    fn secp256k1_verify_via_registry() {
        let mut rng = HmacDrbg::<Sha256>::new(b"reg-ec-k1", b"n", &[]);
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::Secp256k1, &mut rng);
        let pk = AnyPublicKey::Ecdsa(sk.public_key());
        let spki = pk.to_spki_der();
        let sig = sk.sign::<Sha256>(b"hi").unwrap().to_der(CurveId::Secp256k1);

        let algo = find_by_id("ecdsa-secp256k1-sha256").unwrap();
        algo.verify(&spki, b"hi", &sig).unwrap();
        // The OID-keyed any-curve SHA-256 entry also accepts it (different OID
        // path: chains signed with secp256k1 carry `ecdsa-with-SHA256`).
        let any = find_by_id("ecdsa-with-sha256").unwrap();
        any.verify(&spki, b"hi", &sig).unwrap();
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
