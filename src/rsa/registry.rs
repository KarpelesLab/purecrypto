//! RSA entries in the signature registry.
//!
//! Zero-sized types — four PKCS#1 v1.5 (SHA-1 legacy + SHA-256/384/512),
//! three RSA-PSS-RSAE (the TLS `rsa_pss_rsae_*` schemes, `rsaEncryption`
//! SPKI only), three RSA-PSS-PSS (X.509 `id-RSASSA-PSS` signatures,
//! dispatched by their `RSASSA-PSS-params`, and the TLS `rsa_pss_pss_*`
//! schemes) entries, one per SHA-2 digest, and two RSA-PSS-SHAKE (RFC 8702
//! `id-RSASSA-PSS-SHAKE128` / `-SHAKE256`, X.509 only) entries — each
//! implementing [`SignatureAlgorithm`].
//! Each `verify` parses the SPKI to recover the RSA public key, then
//! delegates to the existing `BoxedRsaPublicKey::verify_pkcs1v15` /
//! `verify_pss*`. A PSS entry's digest is the *message* digest; under
//! `verify_with_params` the MGF1 digest is whichever SHA-2 the signature's
//! parameters name (RFC 8017 §8.1 lets it differ), via `verify_pss*_mgf`.

use crate::der::{Reader, parse_oid};
use crate::hash::{Digest, Sha1, Sha256, Sha384, Sha512, Shake128, Shake256};
use crate::rsa::{BoxedRsaPublicKey, PssShake};
use crate::signature_registry::SignatureAlgorithm;
use crate::x509::{Error, PssHash, PssParams, PssRestriction, SignatureParams, oid};

/// Which SPKI forms an RSA registry entry accepts, and how it checks an
/// `id-RSASSA-PSS` key's restriction.
#[derive(Clone, Copy)]
enum SpkiUse {
    /// PKCS#1 v1.5: `rsaEncryption` only. RFC 4055 §1.2 makes
    /// `id-RSASSA-PSS` a *key restriction* ("the key MUST only be used with
    /// RSASSA-PSS"), so verifying a v1.5 signature under such a key would
    /// ignore the very restriction the issuer encoded.
    Pkcs1,
    /// RSASSA-PSS over `hash` with MGF1 over `mgf1_hash` (trailer 1) and a
    /// salt of `salt_len` octets — either being "whatever the key's own
    /// restriction says" when `None` (the key-size policy probe, which must
    /// accept every SPKI some parameter set would verify under): an
    /// `rsaEncryption` SPKI, or — unless `rsa_encryption_only` — an
    /// `id-RSASSA-PSS` SPKI whose `RSASSA-PSS-params`, when present, permit
    /// that signature (RFC 4055 §3.3: digests equal, salt at least the
    /// key's). The `rsa_pss_rsae_*` entries set `rsa_encryption_only`: RFC
    /// 8446 §4.2.3 defines those schemes for a key certified as
    /// `rsaEncryption`, and a PSS-restricted key signs under `rsa_pss_pss_*`.
    Pss {
        hash: PssHash,
        mgf1_hash: Option<PssHash>,
        salt_len: Option<u32>,
        rsa_encryption_only: bool,
    },
    /// RSASSA-PSS with SHAKE (RFC 8702): an `rsaEncryption` SPKI, or an
    /// `id-RSASSA-PSS` one with *absent* parameters. `RSASSA-PSS-params`
    /// name a SHA-2 hash and MGF1, which a SHAKE signature can never
    /// satisfy (RFC 4055 §3.3 requires equal hash and MGF), so a restricted
    /// key is refused.
    PssShake,
}

/// Parses the SPKI to extract an RSA public key, accepting the SPKI forms
/// `use_` names.
///
/// For `rsaEncryption` the explicit `NULL` parameters are required
/// (RFC 3279 §2.3.1). For `id-RSASSA-PSS` the parameters are either absent
/// (an unrestricted PSS key) or an `RSASSA-PSS-params` SEQUENCE, decoded by
/// [`PssRestriction::decode`] and then required to permit the entry's
/// parameter set — a key restricted to another set is rejected rather than
/// silently verified with the wrong parameters. Trailing junk inside the
/// AlgorithmIdentifier SEQUENCE or after the BIT STRING is rejected (strict
/// DER).
fn parse_rsa_spki(spki: &[u8], use_: SpkiUse) -> Result<BoxedRsaPublicKey, Error> {
    let mut reader = Reader::new(spki);
    let mut outer = reader.read_sequence()?;
    let mut algid = outer.read_sequence()?;
    let alg = parse_oid(algid.read_oid()?)?;
    if alg.as_slice() == oid::RSA_ENCRYPTION {
        algid.read_null()?;
        algid.finish()?;
    } else if alg.as_slice() == oid::ID_RSASSA_PSS {
        let restriction = PssRestriction::decode(&mut algid)?;
        algid.finish()?;
        let (hash, mgf1_hash, salt_len) = match use_ {
            SpkiUse::Pss {
                hash,
                mgf1_hash,
                salt_len,
                rsa_encryption_only: false,
            } => (hash, mgf1_hash, salt_len),
            SpkiUse::PssShake if restriction == PssRestriction::Unrestricted => {
                let key_bits = outer.read_bit_string()?;
                outer.finish()?;
                reader.finish()?;
                return Ok(BoxedRsaPublicKey::from_pkcs1_der(key_bits)?);
            }
            _ => return Err(Error::UnsupportedAlgorithm),
        };
        // The key-size policy probe leaves the MGF1 digest and the salt
        // open: the key is usable by this entry iff its message digest
        // matches; the MGF1 digest and the salt bound are checked per
        // signature (`verify_with_params` names both).
        let mgf1_hash = match (mgf1_hash, &restriction) {
            (Some(m), _) => m,
            (None, PssRestriction::Restricted(k)) => k.mgf1_hash,
            (None, PssRestriction::Unrestricted) => hash,
        };
        let permitted = restriction.permits_params(&PssParams {
            hash,
            mgf1_hash,
            salt_len: salt_len.unwrap_or(u32::MAX),
            trailer_field: 1,
        });
        if !permitted {
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
fn rsa_bits(spki: &[u8], use_: SpkiUse) -> Option<u32> {
    parse_rsa_spki(spki, use_)
        .ok()
        .map(|k| k.modulus().bit_len() as u32)
}

/// RSASSA-PSS verification with the signature's `RSASSA-PSS-params`: `D`
/// (the entry's digest, already checked to be `p.hash`) hashes the message,
/// MGF1 runs over `p.mgf1_hash` and the salt is `p.salt_len` octets. The
/// equal-digest case takes the single-digest method, so the TLS 1.3 / X.509
/// profile runs through exactly the path it always did.
fn verify_pss_with_params<D: Digest>(
    key: &BoxedRsaPublicKey,
    entry_hash: PssHash,
    message: &[u8],
    signature: &[u8],
    p: &PssParams,
) -> Result<(), Error> {
    let salt_len = usize::try_from(p.salt_len).map_err(|_| Error::Malformed)?;
    if p.mgf1_hash == entry_hash {
        return key
            .verify_pss_with_salt_len::<D>(message, signature, salt_len)
            .map_err(Error::Rsa);
    }
    match p.mgf1_hash {
        PssHash::Sha256 => {
            key.verify_pss_with_salt_len_mgf::<D, Sha256>(message, signature, salt_len)
        }
        PssHash::Sha384 => {
            key.verify_pss_with_salt_len_mgf::<D, Sha384>(message, signature, salt_len)
        }
        PssHash::Sha512 => {
            key.verify_pss_with_salt_len_mgf::<D, Sha512>(message, signature, salt_len)
        }
    }
    .map_err(Error::Rsa)
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
                let key = parse_rsa_spki(spki, SpkiUse::Pkcs1)?;
                key.verify_pkcs1v15::<$digest>(message, signature).map_err(Error::Rsa)
            }
            fn rsa_modulus_bits(&self, spki: &[u8]) -> Option<u32> { rsa_bits(spki, SpkiUse::Pkcs1) }
        }
    };
}

/// The RSA-PSS entries: message digest `$digest`; MGF1 over the same digest
/// and salt = digest length under `verify`, the signature's MGF1 digest and
/// salt under `verify_with_params`; `$rsae` restricts the entry to
/// `rsaEncryption` SPKIs.
macro_rules! rsa_pss_entry {
    ($(#[$m:meta])* $name:ident, $id:expr, $tls:expr, $digest:ty, $pss_hash:expr, $rsae:expr) => {
        $(#[$m])*
        pub(crate) struct $name;

        impl $name {
            fn spki_use(mgf1_hash: Option<PssHash>, salt_len: Option<u32>) -> SpkiUse {
                SpkiUse::Pss {
                    hash: $pss_hash,
                    mgf1_hash,
                    salt_len,
                    rsa_encryption_only: $rsae,
                }
            }
        }

        impl SignatureAlgorithm for $name {
            fn id(&self) -> &'static str { $id }
            fn x509_oids(&self) -> &'static [&'static [u64]] { &[] }
            fn tls_schemes(&self) -> &'static [u16] { $tls }
            fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
                let salt_len = $pss_hash.output_len();
                let key = parse_rsa_spki(spki, Self::spki_use(Some($pss_hash), Some(salt_len)))?;
                key.verify_pss::<$digest>(message, signature).map_err(Error::Rsa)
            }
            fn verify_with_params(
                &self,
                spki: &[u8],
                message: &[u8],
                signature: &[u8],
                params: SignatureParams,
            ) -> Result<(), Error> {
                let p = match params {
                    SignatureParams::None => return self.verify(spki, message, signature),
                    SignatureParams::RsaPss(p) => p,
                };
                // The message digest must be the entry's and the trailer
                // field 1 (RFC 4055 §3.1); the MGF1 digest and the salt
                // length are the signature's.
                if p.hash != $pss_hash || p.trailer_field != 1 {
                    return Err(Error::UnsupportedAlgorithm);
                }
                let key =
                    parse_rsa_spki(spki, Self::spki_use(Some(p.mgf1_hash), Some(p.salt_len)))?;
                verify_pss_with_params::<$digest>(&key, $pss_hash, message, signature, &p)
            }
            fn rsa_modulus_bits(&self, spki: &[u8]) -> Option<u32> {
                rsa_bits(spki, Self::spki_use(None, None))
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
// `id-RSASSA-PSS` (the `PssPss*` entries below), while the PKCS#1
// `sha*WithRSAEncryption` OIDs identify PKCS#1 v1.5 signatures and belong
// to the `Pkcs1Sha*` entries above. Listing the PKCS#1 OIDs here too (as an
// earlier revision did) made `find_by_oid` correct only by slice ordering.
// RFC 8446 §4.2.3 defines the RSAE code points for a key certified as
// `rsaEncryption`; a PSS-restricted `id-RSASSA-PSS` key is refused here and
// signs under the `rsa_pss_pss_*` code points (the `PssPss*` entries).
rsa_pss_entry!(
    /// `rsa_pss_rsae_sha256` — RSASSA-PSS (MGF1 = SHA-256, salt = 32) on an
    /// `rsaEncryption` SPKI key. TLS scheme `0x0804`; no X.509 OID.
    PssRsaeSha256,
    "rsa-pss-rsae-sha256",
    &[0x0804],
    Sha256,
    PssHash::Sha256,
    true
);
rsa_pss_entry!(
    /// `rsa_pss_rsae_sha384`. TLS scheme `0x0805`; no X.509 OID.
    PssRsaeSha384,
    "rsa-pss-rsae-sha384",
    &[0x0805],
    Sha384,
    PssHash::Sha384,
    true
);
rsa_pss_entry!(
    /// `rsa_pss_rsae_sha512`. TLS scheme `0x0806`; no X.509 OID.
    PssRsaeSha512,
    "rsa-pss-rsae-sha512",
    &[0x0806],
    Sha512,
    PssHash::Sha512,
    true
);

// The `id-RSASSA-PSS` entries, one per SHA-2 message digest, with trailer
// field 1.
//
// In X.509 they verify `id-RSASSA-PSS` signatures, whose digest, MGF and
// salt length live inside the `RSASSA-PSS-params` of the signature's
// AlgorithmIdentifier (RFC 4055 §3.1) — so no entry carries the OID:
// `AnyPublicKey::signature_algorithm` resolves the params to the entry for
// their message digest and passes them to `verify_with_params`, which
// verifies with the signature's MGF1 digest (any SHA-2, equal to the
// message digest or not) and salt length. The signing key may be certified
// as `rsaEncryption` or, PSS-restricted, as `id-RSASSA-PSS`; an SPKI whose
// own RSASSA-PSS-params restrict the key to another digest or MGF1 digest,
// or to a longer salt, is rejected by `parse_rsa_spki` rather than
// mis-verified (RFC 4055 §3.3).
//
// In TLS they are the `rsa_pss_pss_*` schemes (RFC 8446 §4.2.3; salt =
// digest length). The RFC ties those code points to an `id-RSASSA-PSS`
// SPKI; the entries accept both forms because the X.509 path needs the
// `rsaEncryption` one, and `tls::crypto::sign::verify_signature` enforces
// the SPKI form per scheme.
rsa_pss_entry!(
    /// RSA-PSS with SHA-256 (MGF1-SHA-256) under `id-RSASSA-PSS`: X.509
    /// signatures whose parameters name SHA-256, reached through
    /// `AnyPublicKey::signature_algorithm` (no OID of its own), and the
    /// TLS scheme `rsa_pss_pss_sha256` (`0x0809`).
    PssPssSha256,
    "rsa-pss-pss-sha256",
    &[0x0809],
    Sha256,
    PssHash::Sha256,
    false
);
rsa_pss_entry!(
    /// RSA-PSS with SHA-384 (MGF1-SHA-384) under `id-RSASSA-PSS`: X.509
    /// signatures whose parameters name SHA-384, and the TLS scheme
    /// `rsa_pss_pss_sha384` (`0x080A`).
    PssPssSha384,
    "rsa-pss-pss-sha384",
    &[0x080A],
    Sha384,
    PssHash::Sha384,
    false
);
rsa_pss_entry!(
    /// RSA-PSS with SHA-512 (MGF1-SHA-512) under `id-RSASSA-PSS`: X.509
    /// signatures whose parameters name SHA-512, and the TLS scheme
    /// `rsa_pss_pss_sha512` (`0x080B`).
    PssPssSha512,
    "rsa-pss-pss-sha512",
    &[0x080B],
    Sha512,
    PssHash::Sha512,
    false
);

/// The RFC 8702 entries: RSASSA-PSS with SHAKE `$xof` as hash and mask
/// generation function and a salt of the hash length, identified in X.509
/// by their own parameterless OID (`id-RSASSA-PSS-SHAKE128` / `-SHAKE256`,
/// §3.1). The key may be certified as `rsaEncryption` or as an unrestricted
/// `id-RSASSA-PSS` key (RFC 8702 §3.3). No TLS scheme exists for them.
macro_rules! rsa_pss_shake_entry {
    ($(#[$m:meta])* $name:ident, $id:expr, $oid:expr, $xof:ty) => {
        $(#[$m])*
        pub(crate) struct $name;

        impl SignatureAlgorithm for $name {
            fn id(&self) -> &'static str { $id }
            fn x509_oids(&self) -> &'static [&'static [u64]] { &[$oid] }
            fn tls_schemes(&self) -> &'static [u16] { &[] }
            fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
                let key = parse_rsa_spki(spki, SpkiUse::PssShake)?;
                key.verify_pss_shake::<$xof>(message, signature).map_err(Error::Rsa)
            }
            fn rsa_modulus_bits(&self, spki: &[u8]) -> Option<u32> {
                rsa_bits(spki, SpkiUse::PssShake)
            }
        }
    };
}

rsa_pss_shake_entry!(
    /// `id-RSASSA-PSS-SHAKE128` (`1.3.6.1.5.5.7.6.30`): RSASSA-PSS with
    /// SHAKE128 as hash (32 octets) and MGF, salt 32 (RFC 8702 §3.1).
    PssShake128,
    "rsa-pss-shake128",
    oid::ID_RSASSA_PSS_SHAKE128,
    Shake128
);
rsa_pss_shake_entry!(
    /// `id-RSASSA-PSS-SHAKE256` (`1.3.6.1.5.5.7.6.31`): RSASSA-PSS with
    /// SHAKE256 as hash (64 octets) and MGF, salt 64 (RFC 8702 §3.1).
    PssShake256,
    "rsa-pss-shake256",
    oid::ID_RSASSA_PSS_SHAKE256,
    Shake256
);

/// Keeps the `PssShake` bound in use where the entries name a concrete
/// SHAKE, so the trait is what ties the two OIDs to their `hLen`.
const _: () = {
    assert!(<Shake128 as PssShake>::OUTPUT_LEN == 32);
    assert!(<Shake256 as PssShake>::OUTPUT_LEN == 64);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_registry::{find_by_id, find_by_oid, find_by_tls_scheme};
    use crate::test_util::rsa_test_key_a;
    use crate::x509::{AnyPublicKey, SignatureAlgorithmIdentifier};

    #[test]
    fn ids_and_oids_resolve() {
        for (id, scheme) in [
            ("rsa-pkcs1-sha256", 0x0401u16),
            ("rsa-pkcs1-sha384", 0x0501),
            ("rsa-pss-rsae-sha256", 0x0804),
            ("rsa-pss-rsae-sha384", 0x0805),
            ("rsa-pss-rsae-sha512", 0x0806),
            ("rsa-pss-pss-sha256", 0x0809),
            ("rsa-pss-pss-sha384", 0x080A),
            ("rsa-pss-pss-sha512", 0x080B),
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
            "rsa-pss-pss-sha256",
            "rsa-pss-pss-sha384",
            "rsa-pss-pss-sha512",
        ] {
            assert!(
                find_by_id(id).unwrap().x509_oids().is_empty(),
                "{id} must not advertise X.509 OIDs"
            );
        }
        // `id-RSASSA-PSS` names no digest by itself: the OID lookup resolves
        // nothing, the signature's parameters pick the entry.
        assert!(find_by_oid(oid::ID_RSASSA_PSS).is_none());
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

    /// RFC 8446 §4.2.3 defines the `rsa_pss_rsae_*` schemes for a key
    /// certified as `rsaEncryption`: the RSAE entries refuse an
    /// `id-RSASSA-PSS` SPKI (restricted or not), and the key-size hook
    /// agrees. The `rsa-pss-pss-*` entries keep accepting both forms — the
    /// X.509 path needs the `rsaEncryption` one — and the TLS layer
    /// enforces the form per scheme.
    #[test]
    fn pss_rsae_entries_require_rsa_encryption_spki() {
        let key = rsa_test_key_a();
        let mut rng = crate::rng::HmacDrbg::<Sha256>::new(b"reg-rsae-form", b"n", &[]);
        let sig = key.sign_pss::<Sha256, _>(b"hi", &mut rng).unwrap();
        let rsae_spki = AnyPublicKey::Rsa(boxed_pk_from_rsa_test_key()).to_spki_der();
        let unrestricted = pss_spki(None);
        let restricted = pss_spki(Some(pss_params(oid::ID_SHA256, oid::ID_SHA256, 32)));
        let rsae = find_by_id("rsa-pss-rsae-sha256").unwrap();
        let pss = find_by_id("rsa-pss-pss-sha256").unwrap();
        rsae.verify(&rsae_spki, b"hi", &sig).unwrap();
        assert_eq!(rsae.rsa_modulus_bits(&rsae_spki), Some(2048));
        for spki in [&unrestricted, &restricted] {
            assert_eq!(
                rsae.verify(spki, b"hi", &sig).err(),
                Some(Error::UnsupportedAlgorithm)
            );
            assert_eq!(rsae.rsa_modulus_bits(spki), None);
            pss.verify(spki, b"hi", &sig).unwrap();
        }
        pss.verify(&rsae_spki, b"hi", &sig).unwrap();
    }

    /// The RFC 8702 entries resolve by id and by their own OID (no TLS
    /// scheme), verify a SHAKE-PSS signature under an `rsaEncryption` SPKI
    /// and under an unrestricted `id-RSASSA-PSS` SPKI, refuse a restricted
    /// `id-RSASSA-PSS` key (whose params name SHA-2 / MGF1), reject the
    /// other SHAKE's signature, and take only parameterless identifiers.
    #[test]
    fn pss_shake_entries_verify_via_registry() {
        use crate::hash::{Shake128, Shake256};
        let key = rsa_test_key_a();
        let mut rng = crate::rng::HmacDrbg::<Sha256>::new(b"reg-pss-shake", b"n", &[]);
        let sig128 = key.sign_pss_shake::<Shake128, _>(b"hi", &mut rng).unwrap();
        let sig256 = key.sign_pss_shake::<Shake256, _>(b"hi", &mut rng).unwrap();
        let rsae_spki = AnyPublicKey::Rsa(boxed_pk_from_rsa_test_key()).to_spki_der();
        let unrestricted = pss_spki(None);
        let restricted = pss_spki(Some(pss_params(oid::ID_SHA256, oid::ID_SHA256, 32)));

        for (id, o, sig, other) in [
            (
                "rsa-pss-shake128",
                oid::ID_RSASSA_PSS_SHAKE128,
                &sig128,
                &sig256,
            ),
            (
                "rsa-pss-shake256",
                oid::ID_RSASSA_PSS_SHAKE256,
                &sig256,
                &sig128,
            ),
        ] {
            let algo = find_by_id(id).expect(id);
            assert_eq!(find_by_oid(o).expect(id).id(), id);
            assert!(algo.tls_schemes().is_empty());
            for spki in [&rsae_spki, &unrestricted] {
                algo.verify(spki, b"hi", sig).unwrap();
                assert!(algo.verify(spki, b"other", sig).is_err());
                assert!(algo.verify(spki, b"hi", other).is_err());
                assert_eq!(algo.rsa_modulus_bits(spki), Some(2048));
            }
            assert_eq!(
                algo.verify(&restricted, b"hi", sig).err(),
                Some(Error::UnsupportedAlgorithm)
            );
            assert_eq!(algo.rsa_modulus_bits(&restricted), None);
            // Parameters belonging to `id-RSASSA-PSS` are refused.
            let params = PssParams::for_hash(PssHash::Sha256);
            assert_eq!(
                algo.verify_with_params(&rsae_spki, b"hi", sig, SignatureParams::RsaPss(params))
                    .err(),
                Some(Error::UnsupportedAlgorithm)
            );
            algo.verify_with_params(&rsae_spki, b"hi", sig, SignatureParams::None)
                .unwrap();

            // Through the X.509 dispatch: the identifier must be the bare
            // OID (RFC 8702 §3.1), and an `AnyPublicKey` routes it to this
            // entry — for an `rsaEncryption` key and an unrestricted PSS
            // key, never for a restricted one.
            use crate::der::{encode_null, encode_sequence, oid_tlv};
            let algid =
                SignatureAlgorithmIdentifier::from_der(&encode_sequence(&oid_tlv(o))).unwrap();
            assert_eq!(algid.oid(), o);
            assert!(algid.pss_params().is_none());
            assert_eq!(
                SignatureAlgorithmIdentifier::from_der(&encode_sequence(
                    &[oid_tlv(o), encode_null()].concat()
                ))
                .err(),
                Some(Error::Der(crate::der::Error::TrailingData))
            );
            for spki in [&rsae_spki, &unrestricted] {
                let pk = AnyPublicKey::from_spki_der(spki).unwrap();
                assert_eq!(pk.signature_algorithm(&algid).map(|a| a.id()), Some(id));
                pk.verify(&algid, b"hi", sig).unwrap();
                assert!(pk.verify(&algid, b"hi", other).is_err());
            }
            let pk = AnyPublicKey::from_spki_der(&restricted).unwrap();
            assert!(pk.signature_algorithm(&algid).is_none());
            assert_eq!(
                pk.verify(&algid, b"hi", sig).err(),
                Some(Error::UnsupportedAlgorithm)
            );
        }
    }

    #[test]
    fn pss_pss_sha256_verify_accepts_rsa_encryption_spki() {
        // An `id-RSASSA-PSS` *signature* may be made under a key certified
        // as plain `rsaEncryption` (RFC 4055 §3.1 only constrains the
        // parameters when the key is `id-RSASSA-PSS`), so the X.509 PSS
        // entries accept both SPKI forms.
        let key = rsa_test_key_a();
        let spki = AnyPublicKey::Rsa(boxed_pk_from_rsa_test_key()).to_spki_der();
        let mut rng = crate::rng::HmacDrbg::<Sha256>::new(b"reg-pss-pss", b"n", &[]);
        let sig = key.sign_pss::<Sha256, _>(b"hi", &mut rng).unwrap();
        let algo = find_by_id("rsa-pss-pss-sha256").unwrap();
        algo.verify(&spki, b"hi", &sig).unwrap();
        assert_eq!(algo.rsa_modulus_bits(&spki), Some(2048));
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
        // Mismatched hash or MGF1 hash must each reject.
        let bad_hash = pss_params(oid::ID_SHA384, oid::ID_SHA256, 32);
        assert!(algo.verify(&pss_spki(Some(bad_hash)), b"hi", &sig).is_err());
        let bad_mgf = pss_params(oid::ID_SHA256, oid::ID_SHA384, 32);
        assert!(algo.verify(&pss_spki(Some(bad_mgf)), b"hi", &sig).is_err());
        // RFC 4055 §3.3: the signature's salt (32 here) must be at least the
        // key's — a key restricted to salt 20 accepts it, one restricted to
        // salt 48 does not.
        let short_salt = pss_params(oid::ID_SHA256, oid::ID_SHA256, 20);
        algo.verify(&pss_spki(Some(short_salt)), b"hi", &sig)
            .unwrap();
        let long_salt = pss_params(oid::ID_SHA256, oid::ID_SHA256, 48);
        assert!(
            algo.verify(&pss_spki(Some(long_salt)), b"hi", &sig)
                .is_err()
        );
        // Key-size probing goes through the same parse: restricted-to-other
        // parameters also hide the modulus from policy, while a salt
        // restriction (checked per signature) does not.
        assert_eq!(algo.rsa_modulus_bits(&pss_spki(None)), Some(2048));
        let bad_hash = pss_params(oid::ID_SHA384, oid::ID_SHA256, 32);
        assert_eq!(algo.rsa_modulus_bits(&pss_spki(Some(bad_hash))), None);
        let long_salt = pss_params(oid::ID_SHA256, oid::ID_SHA256, 48);
        assert_eq!(
            algo.rsa_modulus_bits(&pss_spki(Some(long_salt))),
            Some(2048)
        );
    }

    /// `verify_with_params` honours the signature's `RSASSA-PSS-params`:
    /// the salt length is the signature's (not assumed equal to the
    /// digest), parameters naming another digest or trailer are refused,
    /// parameters naming another MGF1 digest verify under that digest (and
    /// so fail for a plain-profile signature), and a restricted key bounds
    /// the salt from below.
    #[test]
    fn pss_verify_with_params_uses_the_signature_salt_length() {
        let key = rsa_test_key_a();
        let mut rng = crate::rng::HmacDrbg::<Sha256>::new(b"reg-pss-salt", b"n", &[]);
        let sig32 = key.sign_pss::<Sha256, _>(b"hi", &mut rng).unwrap();
        let sig20 = key
            .sign_pss_with_salt_len::<Sha256, _>(b"hi", 20, &mut rng)
            .unwrap();
        let sig0 = key
            .sign_pss_with_salt_len::<Sha256, _>(b"hi", 0, &mut rng)
            .unwrap();
        let algo = find_by_id("rsa-pss-pss-sha256").unwrap();
        let params = |salt_len| {
            SignatureParams::RsaPss(PssParams {
                hash: PssHash::Sha256,
                mgf1_hash: PssHash::Sha256,
                salt_len,
                trailer_field: 1,
            })
        };
        let unrestricted = pss_spki(None);
        for (sig, salt) in [(&sig32, 32), (&sig20, 20), (&sig0, 0)] {
            algo.verify_with_params(&unrestricted, b"hi", sig, params(salt))
                .unwrap();
            assert!(
                algo.verify_with_params(&unrestricted, b"other", sig, params(salt))
                    .is_err()
            );
            for other in [0, 20, 32] {
                if other != salt {
                    assert!(
                        algo.verify_with_params(&unrestricted, b"hi", sig, params(other))
                            .is_err(),
                        "salt {salt} accepted as {other}"
                    );
                }
            }
        }
        // `None` params = the entry's default profile (salt = digest length).
        algo.verify_with_params(&unrestricted, b"hi", &sig32, SignatureParams::None)
            .unwrap();
        assert!(
            algo.verify_with_params(&unrestricted, b"hi", &sig20, SignatureParams::None)
                .is_err()
        );
        // Parameters for another digest, MGF1 digest or trailer: refused.
        assert_eq!(
            algo.verify_with_params(
                &unrestricted,
                b"hi",
                &sig32,
                SignatureParams::RsaPss(PssParams::for_hash(PssHash::Sha384))
            )
            .err(),
            Some(Error::UnsupportedAlgorithm)
        );
        assert_eq!(
            algo.verify_with_params(
                &unrestricted,
                b"hi",
                &sig32,
                SignatureParams::RsaPss(PssParams {
                    hash: PssHash::Sha256,
                    mgf1_hash: PssHash::Sha384,
                    salt_len: 32,
                    trailer_field: 1,
                })
            )
            .err(),
            Some(Error::Rsa(crate::rsa::Error::Verification))
        );
        assert_eq!(
            algo.verify_with_params(
                &unrestricted,
                b"hi",
                &sig32,
                SignatureParams::RsaPss(PssParams {
                    hash: PssHash::Sha256,
                    mgf1_hash: PssHash::Sha256,
                    salt_len: 32,
                    trailer_field: 2,
                })
            )
            .err(),
            Some(Error::UnsupportedAlgorithm)
        );
        // A key restricted to salt 32 refuses a salt-20 signature even with
        // honest parameters; a key restricted to salt 20 accepts both.
        let r32 = pss_spki(Some(pss_params(oid::ID_SHA256, oid::ID_SHA256, 32)));
        let r20 = pss_spki(Some(pss_params(oid::ID_SHA256, oid::ID_SHA256, 20)));
        assert_eq!(
            algo.verify_with_params(&r32, b"hi", &sig20, params(20))
                .err(),
            Some(Error::UnsupportedAlgorithm)
        );
        algo.verify_with_params(&r20, b"hi", &sig20, params(20))
            .unwrap();
        algo.verify_with_params(&r20, b"hi", &sig32, params(32))
            .unwrap();
        // Non-PSS entries take no parameters.
        assert_eq!(
            find_by_id("rsa-pkcs1-sha256")
                .unwrap()
                .verify_with_params(&unrestricted, b"hi", &sig32, params(32))
                .err(),
            Some(Error::UnsupportedAlgorithm)
        );
    }

    /// RFC 8017 §8.1 / RFC 4055 §3.1: the MGF1 digest is a parameter of its
    /// own. A signature made with `<SHA-256, MGF1-SHA-384>` (and the
    /// Wycheproof `sha512_mgf1sha256_32` profile) verifies through the
    /// entry for its *message* digest under parameters naming that MGF1
    /// digest — for an unrestricted key and for a key restricted to exactly
    /// that pair — and under no other parameters; a key restricted to the
    /// plain profile refuses the pair, and the key-size probe accepts every
    /// SPKI `verify_with_params` would.
    #[test]
    fn pss_verify_with_params_honours_the_mgf1_digest() {
        let key = rsa_test_key_a();
        let mut rng = crate::rng::HmacDrbg::<Sha256>::new(b"reg-pss-mgf", b"n", &[]);
        let plain = key.sign_pss::<Sha256, _>(b"hi", &mut rng).unwrap();
        let mixed = key
            .sign_pss_mgf::<Sha256, Sha384, _>(b"hi", &mut rng)
            .unwrap();
        let algo = find_by_id("rsa-pss-pss-sha256").unwrap();
        let params = |mgf1_hash| {
            SignatureParams::RsaPss(PssParams {
                hash: PssHash::Sha256,
                mgf1_hash,
                salt_len: 32,
                trailer_field: 1,
            })
        };
        let unrestricted = pss_spki(None);
        let r_mixed = pss_spki(Some(pss_params(oid::ID_SHA256, oid::ID_SHA384, 32)));
        let r_plain = pss_spki(Some(pss_params(oid::ID_SHA256, oid::ID_SHA256, 32)));
        let rsa_spki = AnyPublicKey::Rsa(boxed_pk_from_rsa_test_key()).to_spki_der();

        for spki in [&unrestricted, &r_mixed, &rsa_spki] {
            algo.verify_with_params(spki, b"hi", &mixed, params(PssHash::Sha384))
                .unwrap();
            assert!(
                algo.verify_with_params(spki, b"other", &mixed, params(PssHash::Sha384))
                    .is_err()
            );
            // Another MGF1 digest: a verification failure for the keys
            // that permit it, a refused parameter set for the restricted one.
            assert!(
                algo.verify_with_params(spki, b"hi", &mixed, params(PssHash::Sha512))
                    .is_err()
            );
            assert_eq!(algo.rsa_modulus_bits(spki), Some(2048));
        }
        assert_eq!(
            algo.verify_with_params(&unrestricted, b"hi", &mixed, params(PssHash::Sha512))
                .err(),
            Some(Error::Rsa(crate::rsa::Error::Verification))
        );
        // The plain-profile signature does not verify under the mixed
        // parameters, nor the mixed one under the plain parameters or the
        // parameterless default profile.
        assert_eq!(
            algo.verify_with_params(&unrestricted, b"hi", &plain, params(PssHash::Sha384))
                .err(),
            Some(Error::Rsa(crate::rsa::Error::Verification))
        );
        assert_eq!(
            algo.verify_with_params(&unrestricted, b"hi", &mixed, params(PssHash::Sha256))
                .err(),
            Some(Error::Rsa(crate::rsa::Error::Verification))
        );
        assert!(
            algo.verify_with_params(&unrestricted, b"hi", &mixed, SignatureParams::None)
                .is_err()
        );
        // Restrictions are honoured in both directions (RFC 4055 §3.3).
        assert_eq!(
            algo.verify_with_params(&r_plain, b"hi", &mixed, params(PssHash::Sha384))
                .err(),
            Some(Error::UnsupportedAlgorithm)
        );
        assert_eq!(
            algo.verify_with_params(&r_mixed, b"hi", &plain, params(PssHash::Sha256))
                .err(),
            Some(Error::UnsupportedAlgorithm)
        );
        assert_eq!(
            algo.verify(&r_mixed, b"hi", &plain).err(),
            Some(Error::UnsupportedAlgorithm)
        );
        // Another entry never verifies these parameters: the message digest
        // is the entry's.
        assert_eq!(
            find_by_id("rsa-pss-pss-sha384")
                .unwrap()
                .verify_with_params(&unrestricted, b"hi", &mixed, params(PssHash::Sha384))
                .err(),
            Some(Error::UnsupportedAlgorithm)
        );

        // SHA-512 message digest with MGF1-SHA-256 and a 32-octet salt: the
        // `rsa_pss_2048_sha512_mgf1sha256_32_params` Wycheproof profile.
        let sig = key
            .sign_pss_with_salt_len_mgf::<Sha512, Sha256, _>(b"hi", 32, &mut rng)
            .unwrap();
        let p = SignatureParams::RsaPss(PssParams {
            hash: PssHash::Sha512,
            mgf1_hash: PssHash::Sha256,
            salt_len: 32,
            trailer_field: 1,
        });
        let a512 = find_by_id("rsa-pss-pss-sha512").unwrap();
        a512.verify_with_params(&unrestricted, b"hi", &sig, p)
            .unwrap();
        let r = pss_spki(Some(pss_params(oid::ID_SHA512, oid::ID_SHA256, 32)));
        a512.verify_with_params(&r, b"hi", &sig, p).unwrap();
        assert_eq!(a512.rsa_modulus_bits(&r), Some(2048));
        assert!(a512.verify_with_params(&r, b"other", &sig, p).is_err());
        assert!(
            a512.verify_with_params(
                &unrestricted,
                b"hi",
                &sig,
                SignatureParams::RsaPss(PssParams::for_hash(PssHash::Sha512))
            )
            .is_err()
        );
        // The parameter set round-trips through `AnyPublicKey`.
        let any = AnyPublicKey::from_spki_der(&r).unwrap();
        let alg = SignatureAlgorithmIdentifier::rsa_pss(PssParams {
            hash: PssHash::Sha512,
            mgf1_hash: PssHash::Sha256,
            salt_len: 32,
            trailer_field: 1,
        });
        assert_eq!(
            any.signature_algorithm(&alg).unwrap().id(),
            "rsa-pss-pss-sha512"
        );
        any.verify(&alg, b"hi", &sig).unwrap();
        assert!(any.verify(&alg, b"hi", &plain).is_err());
    }

    /// The SHA-384 / SHA-512 PSS-PSS entries mirror the SHA-256 one: an
    /// unrestricted key or a key restricted to exactly their profile
    /// verifies, a key restricted to another digest does not, and a
    /// signature over the other digest never verifies. The key's
    /// restriction and the signature's parameters route to them via
    /// `AnyPublicKey::signature_algorithm`.
    #[test]
    fn pss_pss_sha384_and_sha512_follow_the_key_restriction() {
        let key = rsa_test_key_a();
        let mut rng = crate::rng::HmacDrbg::<Sha256>::new(b"reg-pss-384-512", b"n", &[]);
        let sig384 = key.sign_pss::<Sha384, _>(b"hi", &mut rng).unwrap();
        let sig512 = key.sign_pss::<Sha512, _>(b"hi", &mut rng).unwrap();
        let a384 = find_by_id("rsa-pss-pss-sha384").unwrap();
        let a512 = find_by_id("rsa-pss-pss-sha512").unwrap();
        assert!(a384.x509_oids().is_empty() && a512.x509_oids().is_empty());
        assert_eq!(a384.tls_schemes(), &[0x080A]);
        assert_eq!(a512.tls_schemes(), &[0x080B]);

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
        // The RSAE entries never accept a PSS-restricted key, whatever its
        // digest (RFC 8446 §4.2.3).
        assert!(
            find_by_id("rsa-pss-rsae-sha384")
                .unwrap()
                .verify(&r384, b"hi", &sig384)
                .is_err()
        );
        // The key's own dispatch picks the entry for the signature's digest,
        // gated by its restriction.
        let any = AnyPublicKey::from_spki_der(&r384).unwrap();
        let alg384 = SignatureAlgorithmIdentifier::rsa_pss(PssParams::for_hash(PssHash::Sha384));
        let alg512 = SignatureAlgorithmIdentifier::rsa_pss(PssParams::for_hash(PssHash::Sha512));
        assert_eq!(
            any.signature_algorithm(&alg384).unwrap().id(),
            "rsa-pss-pss-sha384"
        );
        assert!(any.signature_algorithm(&alg512).is_none());
        any.verify(&alg384, b"hi", &sig384).unwrap();
        assert!(any.verify(&alg512, b"hi", &sig512).is_err());
        assert!(any.verify(&alg384, b"hi", &sig512).is_err());
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
