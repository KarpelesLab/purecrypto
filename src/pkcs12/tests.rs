//! PKCS#12 parse + build tests, including OpenSSL 3 interop fixtures.

use super::*;
use crate::hash::Sha256 as Sha256Hash;
use crate::rng::HmacDrbg;

fn rng(seed: &[u8]) -> HmacDrbg<Sha256Hash> {
    HmacDrbg::<Sha256Hash>::new(seed, b"pkcs12-test", &[])
}

/// The plaintext PKCS#8 key and DER cert behind both OpenSSL fixtures.
const KEY_PK8: &[u8] = include_bytes!("../../testdata/pkcs12_test_key.pk8.der");
const CERT_DER: &[u8] = include_bytes!("../../testdata/pkcs12_test_cert.der");
/// OpenSSL 3 default: PBES2 (PBKDF2-SHA256 + AES-256-CBC) content + SHA-256 MAC.
const P12_DEFAULT: &[u8] = include_bytes!("../../testdata/pkcs12_openssl3_default.p12");
/// OpenSSL legacy: pbeWithSHAAnd3-KeyTripleDES-CBC content + SHA-1 MAC.
const P12_LEGACY: &[u8] = include_bytes!("../../testdata/pkcs12_openssl_legacy_3des.p12");
const PASSWORD: &str = "hunter2";

#[test]
fn openssl3_default_interop() {
    let parsed = Pfx::parse(P12_DEFAULT, PASSWORD).expect("parse OpenSSL3 default p12");
    assert_eq!(parsed.certs.len(), 1, "one cert");
    assert_eq!(parsed.certs[0], CERT_DER, "cert DER round-trips OpenSSL");
    assert_eq!(parsed.keys.len(), 1, "one key");
    assert_eq!(parsed.keys[0], KEY_PK8, "key PKCS#8 round-trips OpenSSL");
    assert!(
        parsed.friendly_names.iter().any(|n| n == "purecrypto test"),
        "friendlyName recovered, got {:?}",
        parsed.friendly_names
    );
}

#[test]
fn openssl_legacy_3des_interop() {
    let parsed = Pfx::parse(P12_LEGACY, PASSWORD).expect("parse OpenSSL legacy 3DES p12");
    assert_eq!(parsed.certs.len(), 1);
    assert_eq!(parsed.certs[0], CERT_DER);
    assert_eq!(parsed.keys.len(), 1);
    assert_eq!(parsed.keys[0], KEY_PK8);
}

#[test]
fn wrong_password_is_mac_mismatch() {
    // The MAC must reject a wrong password before any content decryption.
    assert_eq!(
        Pfx::parse(P12_DEFAULT, "wrong").unwrap_err(),
        Error::MacMismatch
    );
    assert_eq!(
        Pfx::parse(P12_LEGACY, "nope").unwrap_err(),
        Error::MacMismatch
    );
}

#[test]
fn tampered_content_is_rejected() {
    // Flip a byte inside the authSafe content; the SHA-256 MAC must catch it.
    let mut bad = P12_DEFAULT.to_vec();
    // Offset 100 sits well inside the AuthenticatedSafe OCTET STRING.
    bad[100] ^= 0x01;
    assert_eq!(Pfx::parse(&bad, PASSWORD).unwrap_err(), Error::MacMismatch);
}

#[test]
fn build_then_parse_roundtrip() {
    let mut r = rng(b"build-roundtrip");
    let p12 = Pfx::build(KEY_PK8, &[CERT_DER], "s3cret", Some("my identity"), &mut r);
    let parsed = Pfx::parse(&p12, "s3cret").expect("parse our own build");
    assert_eq!(parsed.keys.len(), 1);
    assert_eq!(parsed.keys[0], KEY_PK8, "key survives build->parse");
    assert_eq!(parsed.certs.len(), 1);
    assert_eq!(parsed.certs[0], CERT_DER, "cert survives build->parse");
    assert!(parsed.friendly_names.iter().any(|n| n == "my identity"));

    // Wrong password rejected on our own output too.
    assert_eq!(Pfx::parse(&p12, "wrong").unwrap_err(), Error::MacMismatch);
}

#[test]
fn build_multi_cert_chain() {
    // Two certs in the chain (leaf + a second cert reusing the same DER).
    let mut r = rng(b"build-chain");
    let p12 = Pfx::build(KEY_PK8, &[CERT_DER, CERT_DER], "pw", None, &mut r);
    let parsed = Pfx::parse(&p12, "pw").unwrap();
    assert_eq!(parsed.certs.len(), 2);
    assert_eq!(parsed.keys.len(), 1);
}

#[test]
fn missing_mac_rejected() {
    // A PFX with no MacData (authSafe only) must be refused.
    let inner = encode_sequence(&[]); // empty AuthenticatedSafe
    let ci = encode_data_content_info(&inner);
    let version = encode_integer(&[0x03]);
    let pfx = encode_sequence(&[version, ci].concat());
    assert_eq!(Pfx::parse(&pfx, "x").unwrap_err(), Error::MissingMac);
}

/// The recovered key and cert actually parse through the crate's own X.509 /
/// PKCS#8 entry points (end-to-end usability, not just byte equality).
#[test]
fn recovered_material_is_usable() {
    let parsed = Pfx::parse(P12_DEFAULT, PASSWORD).unwrap();
    let cert =
        crate::x509::Certificate::from_der(parsed.certs[0].clone()).expect("recovered cert parses");
    assert!(cert.subject().is_ok());
    let key = crate::x509::AnyPrivateKey::from_pkcs8_der(
        &parsed.keys[0],
        crate::x509::Pkcs8ReadOptions::new(),
    )
    .expect("recovered key parses");
    // The fixture key is a P-256 ECDSA key.
    assert!(matches!(key, crate::x509::AnyPrivateKey::Ecdsa(_)));
}

/// SHA-based KDF sanity: the MAC over the OpenSSL fixture must reproduce the
/// stored tag byte-for-byte (this is the indirect KAT for the RFC 7292 §B KDF
/// — a wrong derivation would mismatch and `parse` would already have failed,
/// but we assert it explicitly here for clarity).
#[test]
fn sha_based_mac_matches_openssl_tag() {
    // Re-extract the AuthenticatedSafe and the stored MAC from the fixture,
    // then recompute and compare.
    let mut reader = Reader::new(P12_DEFAULT);
    let mut pfx = reader.read_sequence().unwrap();
    let _version = pfx.read_integer_bytes().unwrap();
    let auth_safe = read_content_info_data(&mut pfx).unwrap();
    let mac = pfx.read_element().unwrap();

    // Parse the stored tag + salt + iterations out of MacData.
    let mut mr = Reader::new(mac);
    let mut md = mr.read_sequence().unwrap();
    let mut di = md.read_sequence().unwrap();
    let _alg = di.read_sequence().unwrap();
    let stored = di.read_octet_string().unwrap().to_vec();
    let salt = md.read_octet_string().unwrap().to_vec();
    let iters = read_iterations(&mut md).unwrap();

    let pw = password_to_bmp(PASSWORD);
    let computed = sha_based_hmac(PkcsHash::Sha256, &pw, &salt, iters, auth_safe);
    assert_eq!(computed, stored, "RFC 7292 §B SHA-256 MAC matches OpenSSL");
}

#[cfg(feature = "std")]
#[test]
#[ignore = "writes /tmp/purecrypto_built.p12 for manual openssl interop check"]
fn dump_built_for_openssl() {
    let mut r = rng(b"openssl-interop-dump");
    let p12 = Pfx::build(KEY_PK8, &[CERT_DER], "hunter2", Some("pc built"), &mut r);
    std::fs::write("/tmp/purecrypto_built.p12", &p12).unwrap();
}

// ---------------------------------------------------------------------------
// Aggregate key-derivation work budget
//
// `MAX_ITERATIONS` bounds each *individual* KDF run, but nothing bounded the
// *number* of runs. A PFX with a valid MAC (the "import this .p12" scenario,
// where the attacker knows the password) could pack thousands of ~125-byte
// `pkcs8ShroudedKeyBag`s into one megabyte, each declaring
// `iterationCount = 10_000_000` with `prf = hmacWithSHA512` — hours to days of
// CPU per upload, with every bag decrypting fine so the `?` never short-
// circuits. Two defences: a per-parse cumulative iteration budget, and a hard
// cap on the number of bags / ContentInfos.
// ---------------------------------------------------------------------------

/// A real `pkcs8ShroudedKeyBag` bagValue: PBES2 (PBKDF2-HMAC-SHA-256 +
/// AES-256-CBC) over the fixture key, at a caller-chosen iteration count. These
/// decrypt successfully under [`PASSWORD`], which is the whole point — the
/// published attack has the attacker knowing the password, so every bag
/// succeeds and the `?` in the bag loop never short-circuits.
fn shrouded_key_bag_value(iterations: u32, rng: &mut HmacDrbg<Sha256Hash>) -> Vec<u8> {
    pbes2::encrypt(
        KEY_PK8,
        PASSWORD.as_bytes(),
        &pbes2::Pbes2Params {
            kdf: pbes2::KdfChoice::Pbkdf2HmacSha256 { iterations },
            cipher: pbes2::CipherChoice::Aes256Cbc,
            salt_len: 16,
        },
        rng,
    )
}

/// Wraps `content_infos` (already-encoded ContentInfo DER, concatenated) into a
/// complete, correctly MAC'd PFX under [`PASSWORD`]. The MAC is genuine, so the
/// parser reaches the bag loop exactly as it would for a real archive.
fn mac_sealed_pfx(content_infos: &[u8]) -> Vec<u8> {
    let auth_safe = encode_sequence(content_infos);
    let auth_safe_ci = encode_data_content_info(&auth_safe);
    let pw_bmp = password_to_bmp(PASSWORD);
    let mac_data = build_mac_data(&auth_safe, &pw_bmp, &[0x77; 8], 2048);
    encode_sequence(&[encode_integer(&[0x03]), auth_safe_ci, mac_data].concat())
}

/// One `data` ContentInfo holding `n` shrouded key bags at `iterations` each.
fn shrouded_bag_content_info(n: usize, iterations: u32) -> Vec<u8> {
    let mut r = rng(b"pkcs12-budget-bags");
    let mut bags = Vec::new();
    for _ in 0..n {
        bags.extend_from_slice(&encode_safe_bag(
            OID_PKCS8_SHROUDED_KEY_BAG,
            &shrouded_key_bag_value(iterations, &mut r),
            None,
            None,
        ));
    }
    encode_data_content_info(&encode_sequence(&bags))
}

/// The aggregate budget must be shared across bags: several cheap-looking bags
/// that together exceed the pool are rejected, and the rejection happens
/// *before* the over-budget derivation is run. Driven through `parse_budgeted`
/// with a tiny pool so the test does not have to burn `MAX_TOTAL_ITERATIONS`
/// rounds of real PBKDF2 to prove the accounting works.
#[test]
fn aggregate_kdf_budget_is_shared_across_bags() {
    // 4 bags x 2000 iterations x 1 PBKDF2 output block (a 32-byte AES-256 key
    // from the 32-byte HMAC-SHA-256 PRF) = 8000 charged. Every bag decrypts
    // fine, so nothing else stops the loop.
    let pfx = mac_sealed_pfx(&shrouded_bag_content_info(4, 2000));
    let pw_bmp = password_to_bmp(PASSWORD);

    // The MAC KDF (2048 rounds in `mac_sealed_pfx`) draws on the same pool
    // first. A pool that then covers only the first bag: the second is
    // refused, even though it is perfectly well-formed and would have
    // decrypted.
    let mut budget = Budget {
        remaining: 5000,
        ..Budget::new()
    };
    assert_eq!(
        Pfx::parse_budgeted(&pfx, PASSWORD, &pw_bmp, &mut budget).unwrap_err(),
        Error::WorkBudgetExceeded,
    );
    // With room for the MAC and all four bags, the same archive parses — so
    // the budget is what rejected it above, not the archive being malformed.
    let mut budget = Budget {
        remaining: 2048 + 8000,
        ..Budget::new()
    };
    let parsed = Pfx::parse_budgeted(&pfx, PASSWORD, &pw_bmp, &mut budget).expect("in budget");
    assert_eq!(parsed.keys.len(), 4);
    assert_eq!(budget.remaining, 0, "exact fit: MAC + four bags");
}

/// The same budget must span *ContentInfo* boundaries, not restart per
/// ContentInfo.
#[test]
fn aggregate_kdf_budget_spans_content_infos() {
    let mut cis = Vec::new();
    for _ in 0..4 {
        cis.extend_from_slice(&shrouded_bag_content_info(1, 2000));
    }
    let pfx = mac_sealed_pfx(&cis);
    let pw_bmp = password_to_bmp(PASSWORD);
    let mut budget = Budget {
        remaining: 5000,
        ..Budget::new()
    };
    assert_eq!(
        Pfx::parse_budgeted(&pfx, PASSWORD, &pw_bmp, &mut budget).unwrap_err(),
        Error::WorkBudgetExceeded,
    );
    let mut budget = Budget {
        remaining: 2048 + 8000,
        ..Budget::new()
    };
    assert_eq!(
        Pfx::parse_budgeted(&pfx, PASSWORD, &pw_bmp, &mut budget)
            .expect("in budget")
            .keys
            .len(),
        4,
    );
}

/// The published attack shape — thousands of tiny bags packed into one
/// megabyte — is refused by the *default* `Pfx::parse` entry point on the bag
/// cap alone, before the aggregate budget even matters. Uses bags that cost
/// nothing to process, so this stays a fast test while still exercising the
/// real entry point.
#[test]
fn safe_bag_count_is_capped() {
    // certBags with an unknown certId are skipped entirely — no KDF at all.
    let empty_cert_bag = encode_sequence(
        &[
            oid_tlv(&[1, 2, 3, 4]),
            encode_context(0, &encode_octet_string(&[])),
        ]
        .concat(),
    );
    let mut bags = Vec::new();
    for _ in 0..(MAX_SAFE_BAGS + 1) {
        bags.extend_from_slice(&encode_safe_bag(OID_CERT_BAG, &empty_cert_bag, None, None));
    }
    let pfx = mac_sealed_pfx(&encode_data_content_info(&encode_sequence(&bags)));
    assert_eq!(
        Pfx::parse(&pfx, PASSWORD).unwrap_err(),
        Error::WorkBudgetExceeded
    );

    // One under the cap parses fine (the bags are simply ignored).
    let mut ok_bags = Vec::new();
    for _ in 0..MAX_SAFE_BAGS {
        ok_bags.extend_from_slice(&encode_safe_bag(OID_CERT_BAG, &empty_cert_bag, None, None));
    }
    let pfx = mac_sealed_pfx(&encode_data_content_info(&encode_sequence(&ok_bags)));
    let parsed = Pfx::parse(&pfx, PASSWORD).expect("at the cap, still parses");
    assert!(parsed.certs.is_empty());
}

/// And the ContentInfo loop is capped too.
#[test]
fn content_info_count_is_capped() {
    let empty_ci = encode_data_content_info(&encode_sequence(&[]));
    let mut cis = Vec::new();
    for _ in 0..(MAX_CONTENT_INFOS + 1) {
        cis.extend_from_slice(&empty_ci);
    }
    let pfx = mac_sealed_pfx(&cis);
    assert_eq!(
        Pfx::parse(&pfx, PASSWORD).unwrap_err(),
        Error::WorkBudgetExceeded
    );
}

/// The budget arithmetic itself: exact-fit succeeds, one more round does not,
/// and a huge `iterations * passes` product saturates instead of wrapping.
#[test]
fn budget_charge_arithmetic() {
    let mut b = Budget {
        remaining: 100,
        ..Budget::new()
    };
    b.charge(40, 2).expect("80 of 100");
    assert_eq!(b.remaining, 20);
    b.charge(20, 1).expect("exact fit");
    assert_eq!(b.remaining, 0);
    assert_eq!(b.charge(1, 1).unwrap_err(), Error::WorkBudgetExceeded);

    // `passes = 0` still charges one run's worth (never free).
    let mut b = Budget {
        remaining: 10,
        ..Budget::new()
    };
    assert_eq!(b.charge(11, 0).unwrap_err(), Error::WorkBudgetExceeded);

    // No wrap on a hostile product.
    let mut b = Budget::new();
    assert_eq!(
        b.charge(u32::MAX, u64::MAX).unwrap_err(),
        Error::WorkBudgetExceeded
    );
    assert_eq!(
        b.remaining, MAX_TOTAL_ITERATIONS,
        "a refused charge spends nothing"
    );
}

/// Real archives are nowhere near the budget — the existing OpenSSL fixtures
/// must keep parsing.
#[test]
fn real_archives_stay_within_the_budget() {
    Pfx::parse(P12_DEFAULT, PASSWORD).expect("OpenSSL 3 default within budget");
    Pfx::parse(P12_LEGACY, PASSWORD).expect("OpenSSL legacy within budget");
}

// ---------------------------------------------------------------------------
// PBMAC1 (RFC 9579) parameter validation
// ---------------------------------------------------------------------------

/// Builds a PBMAC1 `MacData` over `content`. `key_len`/`with_prf` let tests
/// omit or weaken the PBKDF2 parameters; `tag_key_len` is the key length the
/// tag is actually computed under (what a forger would use).
fn pbmac1_mac_data(
    content: &[u8],
    password: &str,
    key_len: Option<u32>,
    with_prf: bool,
    tag_key_len: usize,
) -> Vec<u8> {
    let salt = [0x42u8; 16];
    let iterations = 1u32;
    let hmac_alg = encode_sequence(&[oid_tlv(OID_HMAC_SHA256), crate::der::encode_null()].concat());
    let mut kdf_params = encode_octet_string(&salt);
    kdf_params.extend_from_slice(&encode_integer(&iterations.to_be_bytes()));
    if let Some(k) = key_len {
        kdf_params.extend_from_slice(&encode_integer(&k.to_be_bytes()));
    }
    if with_prf {
        kdf_params.extend_from_slice(&hmac_alg);
    }
    let kdf = encode_sequence(&[oid_tlv(OID_PBKDF2), encode_sequence(&kdf_params)].concat());
    let params = encode_sequence(&[kdf, hmac_alg].concat());
    let alg = encode_sequence(&[oid_tlv(OID_PBMAC1), params].concat());

    let mut key = vec![0u8; tag_key_len];
    crate::kdf::pbkdf2::<Sha256>(password.as_bytes(), &salt, iterations, &mut key);
    let tag = Hmac::<Sha256>::mac(&key, content);
    let digest_info = encode_sequence(&[alg, encode_octet_string(tag.as_ref())].concat());
    encode_sequence(
        &[
            digest_info,
            encode_octet_string(&[0u8; 8]),
            encode_integer(&[0x01]),
        ]
        .concat(),
    )
}

fn pbmac1_verify(mac: &[u8], content: &[u8], password: &str) -> Result<(), Error> {
    verify_mac(
        mac,
        content,
        password,
        &password_to_bmp(password),
        &mut Budget::new(),
    )
}

#[test]
fn pbmac1_well_formed_verifies() {
    let content = b"authenticated safe";
    let mac = pbmac1_mac_data(content, "hunter2", Some(32), true, 32);
    assert_eq!(pbmac1_verify(&mac, content, "hunter2"), Ok(()));
    assert_eq!(
        pbmac1_verify(&mac, content, "hunter3"),
        Err(Error::MacMismatch)
    );
}

/// Regression: a forged archive declaring `keyLength = 1` used to verify under
/// roughly 1/256 of all passwords (a 1-byte HMAC key). RFC 9579 requires the
/// key length to equal the HMAC output length, so short keys are refused.
#[test]
fn pbmac1_short_key_length_rejected() {
    let content = b"forged";
    for k in [1u32, 16, 20, 31] {
        let mac = pbmac1_mac_data(content, "any", Some(k), true, k as usize);
        assert_eq!(
            pbmac1_verify(&mac, content, "any"),
            Err(Error::BadParameters),
            "keyLength {k}"
        );
    }
    // Original PoC shape: count passwords a 1-byte-key forgery verifies under.
    let mac = pbmac1_mac_data(content, "attacker", Some(1), true, 1);
    let accepted = (0..500)
        .filter(|i| pbmac1_verify(&mac, content, &alloc::format!("pw{i}")).is_ok())
        .count();
    assert_eq!(accepted, 0);
}

#[test]
fn pbmac1_missing_key_length_rejected() {
    let content = b"x";
    let mac = pbmac1_mac_data(content, "pw", None, true, 32);
    assert_eq!(
        pbmac1_verify(&mac, content, "pw"),
        Err(Error::BadParameters)
    );
}

#[test]
fn pbmac1_missing_prf_rejected() {
    // An absent PRF is the PKCS#5 default hmacWithSHA1, which cannot match
    // the HMAC-SHA-256 messageAuthScheme.
    let content = b"x";
    let mac = pbmac1_mac_data(content, "pw", Some(32), false, 32);
    assert_eq!(
        pbmac1_verify(&mac, content, "pw"),
        Err(Error::UnsupportedAlgorithm)
    );
}

#[test]
fn pbmac1_oversized_key_length_rejected() {
    let content = b"x";
    let mac = pbmac1_mac_data(content, "pw", Some(65), true, 65);
    assert_eq!(
        pbmac1_verify(&mac, content, "pw"),
        Err(Error::BadParameters)
    );
    let mac = pbmac1_mac_data(content, "pw", Some(64), true, 64);
    assert_eq!(pbmac1_verify(&mac, content, "pw"), Ok(()));
}

// ---------------------------------------------------------------------------
// Empty-password encodings (RFC 7292 §B.1)
// ---------------------------------------------------------------------------

/// A legacy `pkcs8ShroudedKeyBag` bagValue — `pbeWithSHAAnd3-KeyTripleDES-CBC`
/// over the fixture key — keyed on an explicit BMP password encoding, so a
/// test can pick the zero-length form that `password_to_bmp` never produces.
fn legacy_3des_shrouded_key(pw_bmp: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    use crate::cipher::{Cbc64, TdesEde3};
    let mut key = [0u8; 24];
    let mut iv = [0u8; 8];
    derive(PkcsHash::Sha1, pw_bmp, salt, iterations, ID_KEY, &mut key);
    derive(PkcsHash::Sha1, pw_bmp, salt, iterations, ID_IV, &mut iv);
    let mut buf = KEY_PK8.to_vec();
    let pad = 8 - (buf.len() % 8);
    buf.extend(core::iter::repeat_n(pad as u8, pad));
    Cbc64::new(TdesEde3::new(&key), &iv)
        .encrypt(&mut buf)
        .unwrap();
    let params = encode_sequence(
        &[
            encode_octet_string(salt),
            encode_integer(&iterations.to_be_bytes()),
        ]
        .concat(),
    );
    let alg = encode_sequence(&[oid_tlv(OID_PBE_SHA1_3DES), params].concat());
    encode_sequence(&[alg, encode_octet_string(&buf)].concat())
}

/// A complete PFX — one legacy-shrouded key bag plus one x509 certBag —
/// MAC-sealed under the given BMP password encoding.
fn pfx_under_bmp(pw_bmp: &[u8]) -> Vec<u8> {
    let key_bag = encode_safe_bag(
        OID_PKCS8_SHROUDED_KEY_BAG,
        &legacy_3des_shrouded_key(pw_bmp, &[0x5a; 8], 2048),
        None,
        None,
    );
    let cert_bag_body = encode_sequence(
        &[
            oid_tlv(OID_CERT_TYPE_X509),
            encode_context(0, &encode_octet_string(CERT_DER)),
        ]
        .concat(),
    );
    let cert_bag = encode_safe_bag(OID_CERT_BAG, &cert_bag_body, None, None);
    let content_infos = [
        encode_data_content_info(&encode_sequence(&key_bag)),
        encode_data_content_info(&encode_sequence(&cert_bag)),
    ]
    .concat();
    let auth_safe = encode_sequence(&content_infos);
    let auth_safe_ci = encode_data_content_info(&auth_safe);
    let mac_data = build_mac_data(&auth_safe, pw_bmp, &[0x77; 8], 2048);
    encode_sequence(&[encode_integer(&[0x03]), auth_safe_ci, mac_data].concat())
}

/// RFC 7292 §B.1 gives an empty password two wire forms — the lone two-byte
/// NUL terminator and a genuinely zero-length string — and they derive
/// different MAC and content keys. OpenSSL emits the first for `pass:` and
/// the second for a NULL password, and its parser accepts both; so must
/// ours. The retry must carry the winning encoding through to the legacy
/// PBE bags, and a non-empty password must never be retried.
#[test]
fn empty_password_accepts_both_bmp_encodings() {
    // `password_to_bmp("")` is the terminated form; the parser's first try.
    assert_eq!(password_to_bmp(""), [0x00, 0x00]);

    for pw_bmp in [&[0x00u8, 0x00][..], &[][..]] {
        let pfx = pfx_under_bmp(pw_bmp);
        let parsed = Pfx::parse(&pfx, "").unwrap_or_else(|e| panic!("{pw_bmp:?}: {e}"));
        assert_eq!(parsed.keys, [KEY_PK8.to_vec()], "{pw_bmp:?}");
        assert_eq!(parsed.certs, [CERT_DER.to_vec()], "{pw_bmp:?}");
        // A wrong (non-empty) password is a plain MAC mismatch either way.
        assert_eq!(Pfx::parse(&pfx, "x").unwrap_err(), Error::MacMismatch);
    }

    // A non-empty password has a single encoding: an archive sealed under
    // the zero-length form is NOT reachable by retrying it.
    let pfx = pfx_under_bmp(&[]);
    assert_eq!(Pfx::parse(&pfx, PASSWORD).unwrap_err(), Error::MacMismatch);
}

// ---------------------------------------------------------------------------
// PBES2 AES-GCM parameters
// ---------------------------------------------------------------------------

/// RFC 5084 §3.2: `GCMParameters.aes-ICVlen` has DEFAULT 12, so an envelope
/// that omits it (or says 12 explicitly) carries a 12-byte tag we do not
/// support. It must be refused as `UnsupportedAlgorithm` before any PBKDF2
/// work, not split at a 16-byte tag boundary after the KDF and misreported
/// as a wrong-password `Decryption` failure. An explicit 16 is the supported
/// form and gets past the parameter checks. Mirrors the `crate::kdf::pbes2`
/// guard for the PKCS#12-tolerant decryptor.
#[test]
fn pbes2_gcm_icvlen_default_is_12_and_unsupported() {
    const OID_PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
    const OID_PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
    const OID_HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
    const OID_AES256_GCM: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 46];

    let build = |icvlen: Option<u32>| {
        let prf = encode_sequence(&[oid_tlv(OID_HMAC_SHA256), crate::der::encode_null()].concat());
        let kdf_params = encode_sequence(
            &[
                encode_octet_string(&[0u8; 16]),
                encode_integer(&2048u32.to_be_bytes()),
                prf,
            ]
            .concat(),
        );
        let kdf = encode_sequence(&[oid_tlv(OID_PBKDF2), kdf_params].concat());
        let mut gcm_params = encode_octet_string(&[0u8; 12]);
        if let Some(icv) = icvlen {
            gcm_params.extend_from_slice(&encode_integer(&icv.to_be_bytes()));
        }
        let enc =
            encode_sequence(&[oid_tlv(OID_AES256_GCM), encode_sequence(&gcm_params)].concat());
        let params = encode_sequence(&[kdf, enc].concat());
        encode_sequence(&[oid_tlv(OID_PBES2), params].concat())
    };
    // 32 bytes of garbage "ciphertext": enough for a 16-byte tag split.
    let ct = [0xa5u8; 32];
    let run = |alg: Vec<u8>| pbes2_p12::decrypt(&alg, &ct, b"x", &mut Budget::new());

    assert_eq!(
        run(build(None)),
        Err(Error::UnsupportedAlgorithm),
        "absent aes-ICVlen is DEFAULT 12"
    );
    assert_eq!(
        run(build(Some(12))),
        Err(Error::UnsupportedAlgorithm),
        "explicit 12-byte ICV"
    );
    // Explicit 16 passes the parameter checks; the garbage ciphertext then
    // fails authentication instead.
    assert_eq!(run(build(Some(16))), Err(Error::Decryption));
}

// ---------------------------------------------------------------------------
// MAC-first ordering and caller-tunable work limits
// ---------------------------------------------------------------------------

/// A `pkcs8ShroudedKeyBag` whose legacy-PBE AlgorithmIdentifier declares
/// `iterations` rounds over garbage ciphertext. It is never decryptable, and
/// must never be *attempted* unless the file MAC verified first.
fn hostile_legacy_bag(iterations: u32) -> Vec<u8> {
    let params = encode_sequence(
        &[
            encode_octet_string(&[0x5a; 8]),
            encode_integer(&iterations.to_be_bytes()),
        ]
        .concat(),
    );
    let alg = encode_sequence(&[oid_tlv(OID_PBE_SHA1_3DES), params].concat());
    let epki = encode_sequence(&[alg, encode_octet_string(&[0u8; 32])].concat());
    encode_safe_bag(OID_PKCS8_SHROUDED_KEY_BAG, &epki, None, None)
}

/// Seals `content_infos` under [`PASSWORD`] with a *one-iteration* SHA-256
/// MAC, so verifying (and failing) the MAC costs nothing measurable.
fn cheaply_sealed_pfx(content_infos: &[u8]) -> Vec<u8> {
    let auth_safe = encode_sequence(content_infos);
    let auth_safe_ci = encode_data_content_info(&auth_safe);
    let mac_data = build_mac_data(&auth_safe, &password_to_bmp(PASSWORD), &[0x77; 8], 1);
    encode_sequence(&[encode_integer(&[0x03]), auth_safe_ci, mac_data].concat())
}

/// The MAC is checked before any bag KDF runs. A file whose bags declare
/// the maximum iteration count 64 times over (1.3 billion SHA-1 rounds if
/// they were touched) but whose MAC fails is rejected after one cheap MAC
/// derivation — proved two ways: a budget too small for a single bag still
/// yields `MacMismatch` (a bag charge would have surfaced as
/// `WorkBudgetExceeded` instead), and the call is fast.
#[test]
fn bad_mac_is_rejected_before_any_bag_kdf() {
    let mut bags = Vec::new();
    for _ in 0..64 {
        bags.extend_from_slice(&hostile_legacy_bag(MAX_ITERATIONS));
    }
    let pfx = cheaply_sealed_pfx(&encode_data_content_info(&encode_sequence(&bags)));

    let tiny = ParseLimits {
        max_total_iterations: 16,
        ..ParseLimits::default()
    };
    #[cfg(feature = "std")]
    let start = std::time::Instant::now();
    assert_eq!(
        Pfx::parse_with_limits(&pfx, "wrong", &tiny).unwrap_err(),
        Error::MacMismatch,
        "the bags were charged (so run) before the MAC was checked"
    );
    assert_eq!(Pfx::parse(&pfx, "wrong").unwrap_err(), Error::MacMismatch);
    // An empty password retries the MAC under its second encoding — still
    // no bag work.
    assert_eq!(Pfx::parse(&pfx, "").unwrap_err(), Error::MacMismatch);
    // With the right password the first bag *is* charged — and refused
    // before it runs, under the tiny budget and under the default one
    // (10 M rounds x 2 derivations is the whole default pool, and the MAC
    // already took one round of it).
    assert_eq!(
        Pfx::parse_with_limits(&pfx, PASSWORD, &tiny).unwrap_err(),
        Error::WorkBudgetExceeded
    );
    assert_eq!(
        Pfx::parse(&pfx, PASSWORD).unwrap_err(),
        Error::WorkBudgetExceeded
    );
    #[cfg(feature = "std")]
    assert!(
        start.elapsed() < core::time::Duration::from_secs(5),
        "a rejected archive must not burn its declared iterations: {:?}",
        start.elapsed()
    );
}

/// `parse_with_limits` lowers both ceilings below the defaults: the OpenSSL
/// fixture's 2048-iteration MAC then trips whichever is tighter, and the
/// defaults still accept it.
#[test]
fn parse_limits_lower_the_ceilings() {
    assert_eq!(ParseLimits::default().max_iterations, MAX_ITERATIONS);
    assert_eq!(
        ParseLimits::default().max_total_iterations,
        MAX_TOTAL_ITERATIONS
    );

    let strict = ParseLimits {
        max_iterations: 1000,
        ..ParseLimits::default()
    };
    assert_eq!(
        Pfx::parse_with_limits(P12_DEFAULT, PASSWORD, &strict).unwrap_err(),
        Error::BadParameters
    );
    let poor = ParseLimits {
        max_total_iterations: 100,
        ..ParseLimits::default()
    };
    assert_eq!(
        Pfx::parse_with_limits(P12_DEFAULT, PASSWORD, &poor).unwrap_err(),
        Error::WorkBudgetExceeded
    );
    let parsed = Pfx::parse_with_limits(P12_DEFAULT, PASSWORD, &ParseLimits::default())
        .expect("defaults accept the fixture");
    assert_eq!(parsed.keys.len(), 1);
}

/// The MAC KDF draws on the same aggregate pool as the bag KDFs, and is
/// charged before it runs.
#[test]
fn mac_kdf_is_charged_against_the_budget() {
    // MAC: 2048 rounds (`mac_sealed_pfx`); one bag: 2000 rounds.
    let pfx = mac_sealed_pfx(&shrouded_bag_content_info(1, 2000));
    let pw_bmp = password_to_bmp(PASSWORD);
    let run = |remaining: u64| {
        let mut budget = Budget {
            remaining,
            ..Budget::new()
        };
        Pfx::parse_budgeted(&pfx, PASSWORD, &pw_bmp, &mut budget).map(|p| p.keys.len())
    };
    assert_eq!(
        run(2047).unwrap_err(),
        Error::WorkBudgetExceeded,
        "MAC refused"
    );
    assert_eq!(
        run(4047).unwrap_err(),
        Error::WorkBudgetExceeded,
        "bag refused"
    );
    assert_eq!(run(4048).expect("exact fit"), 1);
}
