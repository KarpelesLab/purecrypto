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

    // A pool that covers only the first two bags: the third is refused, even
    // though it is perfectly well-formed and would have decrypted.
    assert_eq!(
        Pfx::parse_budgeted(&pfx, PASSWORD, &pw_bmp, Budget { remaining: 5000 }).unwrap_err(),
        Error::WorkBudgetExceeded,
    );
    // With room for all four, the same archive parses — so the budget is what
    // rejected it above, not the archive being malformed.
    let parsed = Pfx::parse_budgeted(&pfx, PASSWORD, &pw_bmp, Budget { remaining: 8000 })
        .expect("in budget");
    assert_eq!(parsed.keys.len(), 4);
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
    assert_eq!(
        Pfx::parse_budgeted(&pfx, PASSWORD, &pw_bmp, Budget { remaining: 5000 }).unwrap_err(),
        Error::WorkBudgetExceeded,
    );
    assert_eq!(
        Pfx::parse_budgeted(&pfx, PASSWORD, &pw_bmp, Budget { remaining: 8000 })
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
    let mut b = Budget { remaining: 100 };
    b.charge(40, 2).expect("80 of 100");
    assert_eq!(b.remaining, 20);
    b.charge(20, 1).expect("exact fit");
    assert_eq!(b.remaining, 0);
    assert_eq!(b.charge(1, 1).unwrap_err(), Error::WorkBudgetExceeded);

    // `passes = 0` still charges one run's worth (never free).
    let mut b = Budget { remaining: 10 };
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
