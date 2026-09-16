//! RSA entries in the signature registry.
//!
//! Zero-sized types — four PKCS#1 v1.5 (SHA-1 legacy + SHA-256/384/512),
//! three RSA-PSS-RSAE (TLS-scheme-keyed; MGF1 = same hash, salt-len =
//! hash-len), and three PSS-key-restricted `id-RSASSA-PSS` entries (one per
//! SHA-2 digest) — each implementing [`SignatureAlgorithm`]. Each `verify`
//! parses the SPKI to recover the RSA public key, then delegates to the
//! existing `BoxedRsaPublicKey::verify_pkcs1v15` / `verify_pss`.

use crate::der::{Reader, parse_oid};
use crate::hash::{Sha1, Sha256, Sha384, Sha512};
use crate::rsa::BoxedRsaPublicKey;
use crate::signature_registry::SignatureAlgorithm;
use crate::x509::{Error, PssHash, PssRestriction, oid};

/// Parses the SPKI to extract an RSA public key. Accepts the common
/// `rsaEncryption` OID always, and the PSS-key-restricted `id-RSASSA-PSS`
/// OID (RFC 4055 §1.2) only for a PSS entry — `pss` names the digest the
/// entry verifies with (MGF1 over the same digest, salt = digest length).
///
/// RFC 4055 §1.2 makes `id-RSASSA-PSS` a *key restriction*: "the key MUST
/// only be used with RSASSA-PSS". So the PKCS#1 v1.5 registry entries pass
/// `None` — verifying a v1.5 signature under a PSS-restricted key would
/// ignore the very restriction the issuer encoded — while the PSS entries
/// pass their digest.
///
/// For `rsaEncryption` the explicit `NULL` parameters are required
/// (RFC 3279 §2.3.1). For `id-RSASSA-PSS` the parameters are either absent
/// (an unrestricted PSS key) or an `RSASSA-PSS-params` SEQUENCE, decoded by
/// [`PssRestriction::decode`] and then required to permit exactly this
/// entry's parameter set — a key restricted to any other set is rejected
/// rather than silently verified with the wrong parameters. Trailing junk
/// inside the AlgorithmIdentifier SEQUENCE or after the BIT STRING is
/// rejected (strict DER).
fn parse_rsa_spki(spki: &[u8], pss: Option<PssHash>) -> Result<BoxedRsaPublicKey, Error> {
    let mut reader = Reader::new(spki);
    let mut outer = reader.read_sequence()?;
    let mut algid = outer.read_sequence()?;
    let alg = parse_oid(algid.read_oid()?)?;
    if alg.as_slice() == oid::RSA_ENCRYPTION {
        algid.read_null()?;
        algid.finish()?;
    } else if alg.as_slice() == oid::ID_RSASSA_PSS {
        // RFC 4055 §1.2: a PSS-restricted key must not verify PKCS#1 v1.5
        // signatures.
        let hash = pss.ok_or(Error::UnsupportedAlgorithm)?;
        let restriction = PssRestriction::decode(&mut algid)?;
        algid.finish()?;
        if !restriction.permits(hash) {
            return Err(Error::UnsupportedAlgorithm);
        }
    } else {
        return Err(Error::UnsupportedAlgorithm);
    }
    let key_bits = outer.read_bit_string()?;
    outer.finish()?;
    reader.finish()?;
    Ok(BoxedRsaPublicKey::from_pkcs1_der(key_bits)?)
}

/// Returns the modulus length, in bits, of the RSA key inside `spki` — or
/// `None` when this entry would not accept the key at all, so the key-size
/// policy hook agrees with `verify`.
fn rsa_bits(spki: &[u8], pss: Option<PssHash>) -> Option<u32> {
    parse_rsa_spki(spki, pss)
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
                // `None`: RFC 4055 §1.2 forbids verifying PKCS#1 v1.5 under
                // an `id-RSASSA-PSS` (PSS-restricted) key.
                let key = parse_rsa_spki(spki, None)?;
                key.verify_pkcs1v15::<$digest>(message, signature).map_err(Error::Rsa)
            }
            fn rsa_modulus_bits(&self, spki: &[u8]) -> Option<u32> { rsa_bits(spki, None) }
        }
    };
}

macro_rules! rsa_pss_entry {
    ($(#[$m:meta])* $name:ident, $id:expr, $oids:expr, $tls:expr, $digest:ty, $pss_hash:expr) => {
        $(#[$m])*
        pub(crate) struct $name;

        impl SignatureAlgorithm for $name {
            fn id(&self) -> &'static str { $id }
            fn x509_oids(&self) -> &'static [&'static [u64]] { $oids }
            fn tls_schemes(&self) -> &'static [u16] { $tls }
            fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
                let key = parse_rsa_spki(spki, Some($pss_hash))?;
                key.verify_pss::<$digest>(message, signature).map_err(Error::Rsa)
            }
            fn rsa_modulus_bits(&self, spki: &[u8]) -> Option<u32> {
                rsa_bits(spki, Some($pss_hash))
            }
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

// The PSS-RSAE entries are reached exclusively through their TLS 1.3
// signature-scheme code points (RFC 8446 §4.2.3). They deliberately
// advertise NO X.509 OIDs: in X.509, RSA-PSS signatures are identified by
// `id-RSASSA-PSS` (handled by `PssPssSha256` below), while the PKCS#1
// `sha*WithRSAEncryption` OIDs identify PKCS#1 v1.5 signatures and belong
// to the `Pkcs1Sha*` entries above. Listing the PKCS#1 OIDs here too (as an
// earlier revision did) made `find_by_oid` correct only by slice ordering.
rsa_pss_entry!(
    /// `rsa_pss_rsae_sha256` — RSASSA-PSS (MGF1 = SHA-256, salt = 32) on an
    /// `rsaEncryption` SPKI key. TLS scheme `0x0804`; no X.509 OID.
    PssRsaeSha256,
    "rsa-pss-rsae-sha256",
    &[],
    &[0x0804],
    Sha256,
    PssHash::Sha256
);
rsa_pss_entry!(
    /// `rsa_pss_rsae_sha384`. TLS scheme `0x0805`; no X.509 OID.
    PssRsaeSha384,
    "rsa-pss-rsae-sha384",
    &[],
    &[0x0805],
    Sha384,
    PssHash::Sha384
);
rsa_pss_entry!(
    /// `rsa_pss_rsae_sha512`. TLS scheme `0x0806`; no X.509 OID.
    PssRsaeSha512,
    "rsa-pss-rsae-sha512",
    &[],
    &[0x0806],
    Sha512,
    PssHash::Sha512
);

// RSA-PSS with PSS-key-restricted SPKI (`id-RSASSA-PSS` as the key OID).
// The X.509 signatureAlgorithm OID is also `id-RSASSA-PSS`; the hash and
// MGF parameters live inside the AlgorithmIdentifier parameters. One entry
// per SHA-2 digest, each implementing the MGF1-same-digest / salt = digest
// length profile; an SPKI whose RSASSA-PSS-params restrict the key to
// another set is rejected by `parse_rsa_spki` rather than mis-verified.
//
// Only the SHA-256 entry carries the X.509 OID (the registry's OID lookup
// is first-match and keys must be unique). The digest a PSS chain
// signature actually needs is fixed by the *key's* restriction, so
// `AnyPublicKey::signature_algorithm` routes an `id-RSASSA-PSS` signature
// under an `AnyPublicKey::RsaPss` key to the entry for that digest; the OID
// lookup alone (an `rsaEncryption` key signed with `id-RSASSA-PSS`) reaches
// the SHA-256 entry, the set real-world PSS issuers overwhelmingly use.
rsa_pss_entry!(
    /// RSA-PSS over a PSS-key-restricted SPKI, SHA-256. X.509 OID
    /// `id-RSASSA-PSS` (1.2.840.113549.1.1.10), no TLS scheme. Also
    /// accepts an `rsaEncryption` SPKI under the same registry entry,
    /// so this is the natural fallback for callers parsing the PSS-key
    /// OID form.
    PssPssSha256,
    "rsa-pss-pss-sha256",
    &[oid::ID_RSASSA_PSS],
    &[],
    Sha256,
    PssHash::Sha256
);
rsa_pss_entry!(
    /// RSA-PSS over a PSS-key-restricted SPKI, SHA-384 (MGF1-SHA-384, salt
    /// 48). Reached through `AnyPublicKey::signature_algorithm` for a key
    /// restricted to SHA-384; no X.509 OID of its own, no TLS scheme.
    PssPssSha384,
    "rsa-pss-pss-sha384",
    &[],
    &[],
    Sha384,
    PssHash::Sha384
);
rsa_pss_entry!(
    /// RSA-PSS over a PSS-key-restricted SPKI, SHA-512 (MGF1-SHA-512, salt
    /// 64). Reached through `AnyPublicKey::signature_algorithm` for a key
    /// restricted to SHA-512; no X.509 OID of its own, no TLS scheme.
    PssPssSha512,
    "rsa-pss-pss-sha512",
    &[],
    &[],
    Sha512,
    PssHash::Sha512
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

    #[test]
    fn pkcs1_oids_resolve_to_pkcs1_entries_only() {
        // The `sha*WithRSAEncryption` OIDs identify PKCS#1 v1.5 in X.509 and
        // must resolve to the PKCS#1 entries. The PSS-RSAE entries used to
        // also list these OIDs, which made the dispatch depend on
        // `ALGORITHMS` slice ordering — they now carry no X.509 OIDs at all
        // (RSA-PSS in X.509 is `id-RSASSA-PSS`).
        for (o, id) in [
            (oid::SHA256_WITH_RSA, "rsa-pkcs1-sha256"),
            (oid::SHA384_WITH_RSA, "rsa-pkcs1-sha384"),
            (oid::SHA512_WITH_RSA, "rsa-pkcs1-sha512"),
        ] {
            assert_eq!(find_by_oid(o).expect(id).id(), id);
        }
        for id in [
            "rsa-pss-rsae-sha256",
            "rsa-pss-rsae-sha384",
            "rsa-pss-rsae-sha512",
        ] {
            assert!(
                find_by_id(id).unwrap().x509_oids().is_empty(),
                "{id} must not advertise X.509 OIDs"
            );
        }
        assert_eq!(
            find_by_oid(oid::ID_RSASSA_PSS).unwrap().id(),
            "rsa-pss-pss-sha256"
        );
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

    /// Builds an `id-RSASSA-PSS` SPKI around the shared RSA test key, with
    /// the given AlgorithmIdentifier parameters (`None` = absent =
    /// unrestricted key).
    fn pss_spki(params: Option<alloc::vec::Vec<u8>>) -> alloc::vec::Vec<u8> {
        use crate::der::{encode_bit_string, encode_sequence, oid_tlv};
        let pkcs1 = boxed_pk_from_rsa_test_key().to_pkcs1_der();
        let mut algid = oid_tlv(oid::ID_RSASSA_PSS);
        if let Some(p) = params {
            algid.extend_from_slice(&p);
        }
        encode_sequence(&[encode_sequence(&algid), encode_bit_string(&pkcs1)].concat())
    }

    /// Encodes an `RSASSA-PSS-params` SEQUENCE with the given hash OID, MGF1
    /// hash OID, and salt length (trailerField left absent = DEFAULT 1).
    fn pss_params(hash: &[u64], mgf1_hash: &[u64], salt_len: u8) -> alloc::vec::Vec<u8> {
        use crate::der::{encode_context, encode_integer, encode_null, encode_sequence, oid_tlv};
        let hash_algid = encode_sequence(&[oid_tlv(hash), encode_null()].concat());
        let mgf1_hash_algid = encode_sequence(&[oid_tlv(mgf1_hash), encode_null()].concat());
        let mgf_algid = encode_sequence(&[oid_tlv(oid::ID_MGF1), mgf1_hash_algid].concat());
        encode_sequence(
            &[
                encode_context(0, &hash_algid),
                encode_context(1, &mgf_algid),
                encode_context(2, &encode_integer(&[salt_len])),
            ]
            .concat(),
        )
    }

    #[test]
    fn pss_pss_sha256_validates_rsassa_pss_params() {
        use crate::der::encode_sequence;
        let key = rsa_test_key_a();
        let mut rng = crate::rng::HmacDrbg::<Sha256>::new(b"reg-pss-params", b"n", &[]);
        let sig = key.sign_pss::<Sha256, _>(b"hi", &mut rng).unwrap();
        let algo = find_by_id("rsa-pss-pss-sha256").unwrap();

        // Absent parameters: unrestricted key, accepted.
        algo.verify(&pss_spki(None), b"hi", &sig).unwrap();
        // The supported parameter set (SHA-256 / MGF1-SHA-256 / salt 32).
        let good = pss_params(oid::ID_SHA256, oid::ID_SHA256, 32);
        algo.verify(&pss_spki(Some(good)), b"hi", &sig).unwrap();

        // An empty params SEQUENCE means ALL fields take their DER DEFAULTs —
        // SHA-1 / MGF1-SHA-1 / salt 20 — which is not the supported set.
        let empty = encode_sequence(&[]);
        assert!(algo.verify(&pss_spki(Some(empty)), b"hi", &sig).is_err());
        // Mismatched hash, MGF1 hash, or salt length must each reject.
        let bad_hash = pss_params(oid::ID_SHA384, oid::ID_SHA256, 32);
        assert!(algo.verify(&pss_spki(Some(bad_hash)), b"hi", &sig).is_err());
        let bad_mgf = pss_params(oid::ID_SHA256, oid::ID_SHA384, 32);
        assert!(algo.verify(&pss_spki(Some(bad_mgf)), b"hi", &sig).is_err());
        let bad_salt = pss_params(oid::ID_SHA256, oid::ID_SHA256, 20);
        assert!(algo.verify(&pss_spki(Some(bad_salt)), b"hi", &sig).is_err());
        // Key-size probing goes through the same parse: restricted-to-other
        // parameters also hide the modulus from policy.
        assert_eq!(algo.rsa_modulus_bits(&pss_spki(None)), Some(2048));
        let bad_hash = pss_params(oid::ID_SHA384, oid::ID_SHA256, 32);
        assert_eq!(algo.rsa_modulus_bits(&pss_spki(Some(bad_hash))), None);
    }

    /// The SHA-384 / SHA-512 PSS-PSS entries mirror the SHA-256 one: an
    /// unrestricted key or a key restricted to exactly their profile
    /// verifies, a key restricted to another digest does not, and a
    /// signature over the other digest never verifies. Neither carries the
    /// `id-RSASSA-PSS` OID (that lookup stays with SHA-256); the key's
    /// restriction routes to them via `AnyPublicKey::signature_algorithm`.
    #[test]
    fn pss_pss_sha384_and_sha512_follow_the_key_restriction() {
        let key = rsa_test_key_a();
        let mut rng = crate::rng::HmacDrbg::<Sha256>::new(b"reg-pss-384-512", b"n", &[]);
        let sig384 = key.sign_pss::<Sha384, _>(b"hi", &mut rng).unwrap();
        let sig512 = key.sign_pss::<Sha512, _>(b"hi", &mut rng).unwrap();
        let a384 = find_by_id("rsa-pss-pss-sha384").unwrap();
        let a512 = find_by_id("rsa-pss-pss-sha512").unwrap();
        assert!(a384.x509_oids().is_empty() && a512.x509_oids().is_empty());
        assert!(a384.tls_schemes().is_empty() && a512.tls_schemes().is_empty());

        let r384 = pss_spki(Some(pss_params(oid::ID_SHA384, oid::ID_SHA384, 48)));
        let r512 = pss_spki(Some(pss_params(oid::ID_SHA512, oid::ID_SHA512, 64)));
        let r256 = pss_spki(Some(pss_params(oid::ID_SHA256, oid::ID_SHA256, 32)));
        a384.verify(&pss_spki(None), b"hi", &sig384).unwrap();
        a384.verify(&r384, b"hi", &sig384).unwrap();
        a512.verify(&pss_spki(None), b"hi", &sig512).unwrap();
        a512.verify(&r512, b"hi", &sig512).unwrap();
        // Wrong digest for the entry, or a key pinned elsewhere.
        assert!(a384.verify(&pss_spki(None), b"hi", &sig512).is_err());
        assert!(a384.verify(&r256, b"hi", &sig384).is_err());
        assert!(a384.verify(&r512, b"hi", &sig384).is_err());
        assert!(a512.verify(&r256, b"hi", &sig512).is_err());
        assert_eq!(a384.rsa_modulus_bits(&r384), Some(2048));
        assert_eq!(a384.rsa_modulus_bits(&r256), None);
        // The RSAE entries apply the same per-digest restriction check (a
        // key pinned to SHA-384 verifies `rsa_pss_rsae_sha384`, not
        // `rsa_pss_rsae_sha256`).
        find_by_id("rsa-pss-rsae-sha384")
            .unwrap()
            .verify(&r384, b"hi", &sig384)
            .unwrap();
        assert!(
            find_by_id("rsa-pss-rsae-sha256")
                .unwrap()
                .verify(&r384, b"hi", &sig384)
                .is_err()
        );
        // The key's own dispatch picks the entry for its digest.
        let any = AnyPublicKey::from_spki_der(&r384).unwrap();
        assert_eq!(
            any.signature_algorithm(oid::ID_RSASSA_PSS).unwrap().id(),
            "rsa-pss-pss-sha384"
        );
        any.verify(oid::ID_RSASSA_PSS, b"hi", &sig384).unwrap();
        assert!(any.verify(oid::ID_RSASSA_PSS, b"hi", &sig512).is_err());
    }

    /// RFC 4055 §1.2: an `id-RSASSA-PSS` SPKI is a *restricted* key — "the
    /// key MUST only be used with RSASSA-PSS". The PKCS#1 v1.5 entries used
    /// to accept it (they shared the permissive SPKI parser), verifying v1.5
    /// signatures under a key whose issuer restricted it to PSS.
    #[test]
    fn pkcs1_entries_reject_pss_restricted_keys() {
        let key = rsa_test_key_a();
        let spki = pss_spki(None); // id-RSASSA-PSS, unrestricted parameters
        let sig = key.sign_pkcs1v15::<Sha256>(b"hi").unwrap();
        for id in ["rsa-pkcs1-sha256", "rsa-pkcs1-sha384", "rsa-pkcs1-sha1"] {
            let algo = find_by_id(id).unwrap();
            assert!(
                algo.verify(&spki, b"hi", &sig).is_err(),
                "{id} must refuse a PSS-restricted key"
            );
            // The key-size hook agrees with `verify` rather than reporting a
            // modulus for a key this entry would never accept.
            assert_eq!(algo.rsa_modulus_bits(&spki), None, "{id}");
        }
        // The same signature under an `rsaEncryption` SPKI still verifies.
        let rsa_spki = AnyPublicKey::Rsa(boxed_pk_from_rsa_test_key()).to_spki_der();
        find_by_id("rsa-pkcs1-sha256")
            .unwrap()
            .verify(&rsa_spki, b"hi", &sig)
            .unwrap();
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
