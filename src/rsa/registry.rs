//! RSA entries in the signature registry.
//!
//! Zero-sized types — four PKCS#1 v1.5 (SHA-1 legacy + SHA-256/384/512),
//! three RSA-PSS-RSAE (TLS-scheme-keyed; MGF1 = same hash, salt-len =
//! hash-len), and one PSS-key-restricted `id-RSASSA-PSS` entry — each
//! implementing [`SignatureAlgorithm`]. Each `verify` parses the SPKI to
//! recover the RSA public key, then delegates to the existing
//! `BoxedRsaPublicKey::verify_pkcs1v15` / `verify_pss`.

use crate::der::{Reader, parse_oid, tag};
use crate::hash::{Sha1, Sha256, Sha384, Sha512};
use crate::rsa::BoxedRsaPublicKey;
use crate::signature_registry::SignatureAlgorithm;
use crate::x509::{Error, oid};

/// Parses the SPKI to extract an RSA public key. Accepts both the common
/// `rsaEncryption` OID and the PSS-key-restricted `id-RSASSA-PSS` OID
/// (RFC 4055 §1.2).
///
/// For `rsaEncryption` the explicit `NULL` parameters are required
/// (RFC 3279 §2.3.1). For `id-RSASSA-PSS` the parameters are either absent
/// (an unrestricted PSS key) or an `RSASSA-PSS-params` SEQUENCE, which is
/// validated against the single parameter set the registry's PSS verifier
/// implements (SHA-256 / MGF1-SHA-256 / saltLength 32 / trailerField 1) —
/// any other restriction is rejected rather than silently verified with
/// the wrong parameters. Trailing junk inside the AlgorithmIdentifier
/// SEQUENCE or after the BIT STRING is rejected (strict DER).
fn parse_rsa_spki(spki: &[u8]) -> Result<BoxedRsaPublicKey, Error> {
    let mut reader = Reader::new(spki);
    let mut outer = reader.read_sequence()?;
    let mut algid = outer.read_sequence()?;
    let alg = parse_oid(algid.read_oid()?)?;
    if alg.as_slice() == oid::RSA_ENCRYPTION {
        algid.read_null()?;
        algid.finish()?;
    } else if alg.as_slice() == oid::ID_RSASSA_PSS {
        if !algid.is_empty() {
            check_rsassa_pss_params(&mut algid)?;
        }
        algid.finish()?;
    } else {
        return Err(Error::UnsupportedAlgorithm);
    }
    let key_bits = outer.read_bit_string()?;
    outer.finish()?;
    Ok(BoxedRsaPublicKey::from_pkcs1_der(key_bits)?)
}

/// Validates an `RSASSA-PSS-params` SEQUENCE (RFC 4055 §3.1) against the one
/// parameter set the registry's PSS verifier implements: hashAlgorithm
/// SHA-256, maskGenAlgorithm MGF1 with SHA-256, saltLength 32, trailerField 1.
///
/// DER `DEFAULT` handling is load-bearing: an *absent* field encodes the
/// SHA-1 / MGF1-SHA-1 / saltLength 20 default, which is **not** the supported
/// set, so the hash, MGF, and salt fields must all be explicitly present.
/// `trailerField` may be absent (its DEFAULT 1 *is* the supported value) or
/// present with value 1.
fn check_rsassa_pss_params(algid: &mut Reader) -> Result<(), Error> {
    let mut params = algid.read_sequence()?;
    // hashAlgorithm [0] EXPLICIT, DEFAULT sha1 — must be present: SHA-256.
    if params.peek_tag() != Some(tag::context(0)) {
        return Err(Error::UnsupportedAlgorithm);
    }
    let body = params.read_tlv(tag::context(0))?;
    check_hash_algid(body, oid::ID_SHA256)?;
    // maskGenAlgorithm [1] EXPLICIT, DEFAULT mgf1SHA1 — must be present:
    // MGF1 parameterized with SHA-256.
    if params.peek_tag() != Some(tag::context(1)) {
        return Err(Error::UnsupportedAlgorithm);
    }
    let body = params.read_tlv(tag::context(1))?;
    let mut r = Reader::new(body);
    let mut mgf = r.read_sequence()?;
    if parse_oid(mgf.read_oid()?)?.as_slice() != oid::ID_MGF1 {
        return Err(Error::UnsupportedAlgorithm);
    }
    let mgf_hash = mgf.read_element()?;
    mgf.finish()?;
    r.finish()?;
    check_hash_algid(mgf_hash, oid::ID_SHA256)?;
    // saltLength [2] EXPLICIT, DEFAULT 20 — must be present: 32.
    if params.peek_tag() != Some(tag::context(2)) {
        return Err(Error::UnsupportedAlgorithm);
    }
    let body = params.read_tlv(tag::context(2))?;
    let mut r = Reader::new(body);
    let salt_ok = r.read_integer_bytes()? == [32];
    r.finish()?;
    if !salt_ok {
        return Err(Error::UnsupportedAlgorithm);
    }
    // trailerField [3] EXPLICIT, DEFAULT 1 — absent or explicitly 1.
    if !params.is_empty() {
        let body = params.read_tlv(tag::context(3))?;
        let mut r = Reader::new(body);
        let trailer_ok = r.read_integer_bytes()? == [1];
        r.finish()?;
        if !trailer_ok {
            return Err(Error::UnsupportedAlgorithm);
        }
    }
    params.finish()?;
    Ok(())
}

/// Checks that `der` is exactly one hash `AlgorithmIdentifier` SEQUENCE whose
/// OID is `want`, with parameters absent or NULL (RFC 4055 §2.1 allows both
/// encodings for the SHA-2 family).
fn check_hash_algid(der: &[u8], want: &[u64]) -> Result<(), Error> {
    let mut r = Reader::new(der);
    let mut h = r.read_sequence()?;
    if parse_oid(h.read_oid()?)?.as_slice() != want {
        return Err(Error::UnsupportedAlgorithm);
    }
    if !h.is_empty() {
        h.read_null()?;
    }
    h.finish()?;
    r.finish()?;
    Ok(())
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
    ($(#[$m:meta])* $name:ident, $id:expr, $oids:expr, $tls:expr, $digest:ty) => {
        $(#[$m])*
        pub(crate) struct $name;

        impl SignatureAlgorithm for $name {
            fn id(&self) -> &'static str { $id }
            fn x509_oids(&self) -> &'static [&'static [u64]] { $oids }
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
    Sha256
);
rsa_pss_entry!(
    /// `rsa_pss_rsae_sha384`. TLS scheme `0x0805`; no X.509 OID.
    PssRsaeSha384,
    "rsa-pss-rsae-sha384",
    &[],
    &[0x0805],
    Sha384
);
rsa_pss_entry!(
    /// `rsa_pss_rsae_sha512`. TLS scheme `0x0806`; no X.509 OID.
    PssRsaeSha512,
    "rsa-pss-rsae-sha512",
    &[],
    &[0x0806],
    Sha512
);

// RSA-PSS with PSS-key-restricted SPKI (`id-RSASSA-PSS` as the key OID).
// The X.509 signatureAlgorithm OID is also `id-RSASSA-PSS`; the hash and
// MGF parameters live inside the AlgorithmIdentifier parameters. The
// registry entry implements only the SHA-256 / MGF1-SHA-256 / salt = 32
// parameter set, which is what real-world PSS-PSS issuers overwhelmingly
// use today; SPKIs whose RSASSA-PSS-params restrict the key to any other
// set are rejected by `parse_rsa_spki` rather than mis-verified.
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
