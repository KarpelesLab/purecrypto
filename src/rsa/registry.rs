//! RSA entries in the signature registry.
//!
//! Six zero-sized types — three PKCS#1 v1.5 (SHA-256/384/512) and three
//! RSA-PSS (RSAE keys, MGF1 = same hash, salt-len = hash-len) — each
//! implementing [`SignatureAlgorithm`]. Each `verify` parses the SPKI to
//! recover the RSA public key, then delegates to the existing
//! `BoxedRsaPublicKey::verify_pkcs1v15` / `verify_pss`.

use crate::der::{Reader, parse_oid};
use crate::hash::{Sha1, Sha256, Sha384, Sha512};
use crate::rsa::BoxedRsaPublicKey;
use crate::signature_registry::SignatureAlgorithm;
use crate::x509::{Error, oid};

/// Parses the SPKI to extract an RSA public key. Accepts both the common
/// `rsaEncryption` OID and the PSS-key-restricted `id-RSASSA-PSS` OID
/// (RFC 4055 §1.2). PSS parameters in the AlgorithmIdentifier are not
/// enforced here — the verifier knows its own hash and the canonical
/// salt-length / MGF1 parameters.
fn parse_rsa_spki(spki: &[u8]) -> Result<BoxedRsaPublicKey, Error> {
    let mut reader = Reader::new(spki);
    let mut outer = reader.read_sequence()?;
    let mut algid = outer.read_sequence()?;
    let alg = parse_oid(algid.read_oid()?)?;
    if alg.as_slice() != oid::RSA_ENCRYPTION && alg.as_slice() != oid::ID_RSASSA_PSS {
        return Err(Error::UnsupportedAlgorithm);
    }
    let key_bits = outer.read_bit_string()?;
    Ok(BoxedRsaPublicKey::from_pkcs1_der(key_bits)?)
}

/// Returns the modulus length, in bits, of the RSA key inside `spki`.
fn rsa_bits(spki: &[u8]) -> Option<u32> {
    parse_rsa_spki(spki)
        .ok()
        .map(|k| k.modulus().bit_len() as u32)
}

macro_rules! rsa_pkcs1_entry {
    ($(#[$m:meta])* $name:ident, $id:expr, $oid:expr, $tls:expr, $digest:ty) => {
        $(#[$m])*
        pub(crate) struct $name;

        impl SignatureAlgorithm for $name {
            fn id(&self) -> &'static str { $id }
            fn x509_oids(&self) -> &'static [&'static [u64]] { &[$oid] }
            fn tls_schemes(&self) -> &'static [u16] { $tls }
            fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
                let key = parse_rsa_spki(spki)?;
                key.verify_pkcs1v15::<$digest>(message, signature).map_err(Error::Rsa)
            }
            fn rsa_modulus_bits(&self, spki: &[u8]) -> Option<u32> { rsa_bits(spki) }
        }
    };
}

macro_rules! rsa_pss_entry {
    ($(#[$m:meta])* $name:ident, $id:expr, $oid:expr, $tls:expr, $digest:ty) => {
        $(#[$m])*
        pub(crate) struct $name;

        impl SignatureAlgorithm for $name {
            fn id(&self) -> &'static str { $id }
            fn x509_oids(&self) -> &'static [&'static [u64]] { &[$oid] }
            fn tls_schemes(&self) -> &'static [u16] { $tls }
            fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
                let key = parse_rsa_spki(spki)?;
                key.verify_pss::<$digest>(message, signature).map_err(Error::Rsa)
            }
            fn rsa_modulus_bits(&self, spki: &[u8]) -> Option<u32> { rsa_bits(spki) }
        }
    };
}

rsa_pkcs1_entry!(
    /// `rsa_pkcs1_sha1` — RSASSA-PKCS1-v1_5 with SHA-1.
    /// X.509 OID `1.2.840.113549.1.1.5`. Legacy: SHA-1 is collision-broken;
    /// this entry exists in the registry for opt-in interop only and is
    /// **not** on the default whitelist.
    Pkcs1Sha1,
    "rsa-pkcs1-sha1",
    oid::SHA1_WITH_RSA,
    &[],
    Sha1
);
rsa_pkcs1_entry!(
    /// `rsa_pkcs1_sha256` — RSASSA-PKCS1-v1_5 with SHA-256.
    /// X.509 OID `1.2.840.113549.1.1.11`; TLS scheme `0x0401`.
    Pkcs1Sha256,
    "rsa-pkcs1-sha256",
    oid::SHA256_WITH_RSA,
    &[0x0401],
    Sha256
);
rsa_pkcs1_entry!(
    /// `rsa_pkcs1_sha384` — RSASSA-PKCS1-v1_5 with SHA-384.
    /// X.509 OID `1.2.840.113549.1.1.12`; TLS scheme `0x0501`.
    Pkcs1Sha384,
    "rsa-pkcs1-sha384",
    oid::SHA384_WITH_RSA,
    &[0x0501],
    Sha384
);
rsa_pkcs1_entry!(
    /// `rsa_pkcs1_sha512` — RSASSA-PKCS1-v1_5 with SHA-512.
    /// X.509 OID `1.2.840.113549.1.1.13`; no TLS scheme (RFC 8446 retired the
    /// signature scheme code points for legacy PKCS#1-v1_5-SHA-512).
    Pkcs1Sha512,
    "rsa-pkcs1-sha512",
    oid::SHA512_WITH_RSA,
    &[],
    Sha512
);

rsa_pss_entry!(
    /// `rsa_pss_rsae_sha256` — RSASSA-PSS (MGF1 = SHA-256, salt = 32) on an
    /// `rsaEncryption` SPKI key. TLS scheme `0x0804`; X.509 reuses the
    /// `sha256WithRSAEncryption` OID for the certificate signature.
    PssRsaeSha256,
    "rsa-pss-rsae-sha256",
    oid::SHA256_WITH_RSA,
    &[0x0804],
    Sha256
);
rsa_pss_entry!(
    /// `rsa_pss_rsae_sha384`. TLS scheme `0x0805`.
    PssRsaeSha384,
    "rsa-pss-rsae-sha384",
    oid::SHA384_WITH_RSA,
    &[0x0805],
    Sha384
);
rsa_pss_entry!(
    /// `rsa_pss_rsae_sha512`. TLS scheme `0x0806`.
    PssRsaeSha512,
    "rsa-pss-rsae-sha512",
    oid::SHA512_WITH_RSA,
    &[0x0806],
    Sha512
);

// RSA-PSS with PSS-key-restricted SPKI (`id-RSASSA-PSS` as the key OID).
// The X.509 signatureAlgorithm OID is also `id-RSASSA-PSS`; the hash and
// MGF parameters live inside the AlgorithmIdentifier parameters. The
// registry entry assumes the SHA-256 / MGF1-SHA-256 / salt = 32 parameter
// set, which is what real-world PSS-PSS issuers overwhelmingly use today.
// Chains carrying a different hash inside the PSS parameters require a
// per-cert parameter parse and aren't yet reachable here.
rsa_pss_entry!(
    /// RSA-PSS over a PSS-key-restricted SPKI, SHA-256. X.509 OID
    /// `id-RSASSA-PSS` (1.2.840.113549.1.1.10), no TLS scheme. Also
    /// accepts an `rsaEncryption` SPKI under the same registry entry,
    /// so this is the natural fallback for callers parsing the PSS-key
    /// OID form.
    PssPssSha256,
    "rsa-pss-pss-sha256",
    oid::ID_RSASSA_PSS,
    &[],
    Sha256
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_registry::{find_by_id, find_by_oid, find_by_tls_scheme};
    use crate::test_util::rsa_test_key_a;
    use crate::x509::AnyPublicKey;

    #[test]
    fn ids_and_oids_resolve() {
        for (id, scheme) in [
            ("rsa-pkcs1-sha256", 0x0401u16),
            ("rsa-pkcs1-sha384", 0x0501),
            ("rsa-pss-rsae-sha256", 0x0804),
            ("rsa-pss-rsae-sha384", 0x0805),
            ("rsa-pss-rsae-sha512", 0x0806),
        ] {
            let by_id = find_by_id(id).expect(id);
            assert_eq!(by_id.id(), id);
            let by_scheme = find_by_tls_scheme(scheme).expect(id);
            assert_eq!(by_scheme.id(), id);
        }
        // RSA-PKCS1-SHA512 has an X.509 OID but no TLS scheme.
        assert!(find_by_id("rsa-pkcs1-sha512").is_some());
        assert!(find_by_oid(oid::SHA512_WITH_RSA).is_some());
    }

    fn boxed_pk_from_rsa_test_key() -> BoxedRsaPublicKey {
        let pk = rsa_test_key_a().public_key();
        let mut n = [0u8; 256];
        pk.modulus().write_be_bytes(&mut n);
        let mut e = [0u8; 256];
        pk.exponent().write_be_bytes(&mut e);
        BoxedRsaPublicKey::new(
            crate::bignum::BoxedUint::from_be_bytes(&n),
            crate::bignum::BoxedUint::from_be_bytes(&e),
        )
    }

    #[test]
    fn pkcs1_sha1_verify_via_registry() {
        // SHA-1 is in the registry for opt-in interop. The verify path
        // round-trips a freshly minted SHA-1 RSA signature.
        let key = rsa_test_key_a();
        let spki = AnyPublicKey::Rsa(boxed_pk_from_rsa_test_key()).to_spki_der();
        let sig = key.sign_pkcs1v15::<crate::hash::Sha1>(b"hi").unwrap();
        let algo = find_by_id("rsa-pkcs1-sha1").expect("rsa-pkcs1-sha1");
        algo.verify(&spki, b"hi", &sig).unwrap();
        assert!(algo.verify(&spki, b"other", &sig).is_err());
        // No TLS scheme.
        assert!(algo.tls_schemes().is_empty());
    }

    #[test]
    fn pss_pss_sha256_verify_accepts_rsa_encryption_spki() {
        // Real-world PSS-PSS-keys carry `id-RSASSA-PSS` as the SPKI key OID,
        // but for symmetry the verify path also accepts an `rsaEncryption`
        // SPKI (the underlying RSA bytes are identical).
        let key = rsa_test_key_a();
        let spki = AnyPublicKey::Rsa(boxed_pk_from_rsa_test_key()).to_spki_der();
        let mut rng = crate::rng::HmacDrbg::<Sha256>::new(b"reg-pss-pss", b"n", &[]);
        let sig = key.sign_pss::<Sha256, _>(b"hi", &mut rng).unwrap();
        let algo = find_by_id("rsa-pss-pss-sha256").unwrap();
        algo.verify(&spki, b"hi", &sig).unwrap();
    }

    #[test]
    fn pkcs1_sha256_verify_via_registry() {
        let key = rsa_test_key_a();
        let spki = AnyPublicKey::Rsa(boxed_pk_from_rsa_test_key()).to_spki_der();
        let sig = key.sign_pkcs1v15::<Sha256>(b"hi").unwrap();

        let algo = find_by_id("rsa-pkcs1-sha256").unwrap();
        algo.verify(&spki, b"hi", &sig).unwrap();
        assert!(algo.verify(&spki, b"other", &sig).is_err());
        // Modulus bits exposed for policy.
        assert_eq!(algo.rsa_modulus_bits(&spki), Some(2048));
    }
}
