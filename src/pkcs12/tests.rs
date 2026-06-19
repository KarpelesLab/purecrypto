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
