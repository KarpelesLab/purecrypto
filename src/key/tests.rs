//! End-to-end tests that drive the per-algorithm keys through the unified
//! [`key`](crate::key) facade over `dyn` objects — proving operations work,
//! that unsupported operations and unsupported parameters fail loudly, and that
//! peer-mismatch is rejected.
//!
//! Gated to the feature set these tests exercise (the default build has them
//! all); see the `#[cfg(...)] mod tests` line in `key/mod.rs`.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::hash::Sha256;
use crate::key::{
    Algorithm, Decapsulator, DecryptParams, Encapsulator, EncryptParams, Error, Hash, Operation,
    PrivateKey, PublicKey, SignParams, StatefulSigner,
};
use crate::rng::HmacDrbg;

fn rng() -> HmacDrbg<Sha256> {
    HmacDrbg::new(
        b"purecrypto-key-trait-tests-seed!",
        b"nonce-001",
        b"key-traits",
    )
}

// ----------------------------------------------------------------------------
// Ed25519: sign/verify through the facade, and unsupported-op behaviour
// ----------------------------------------------------------------------------

#[test]
fn ed25519_sign_verify_via_facade() {
    let mut r = rng();
    let sk = crate::ec::Ed25519PrivateKey::generate(&mut r);
    let priv_dyn: Box<dyn PrivateKey> = Box::new(sk);
    assert_eq!(priv_dyn.algorithm(), Algorithm::Ed25519);

    let params = SignParams::new();
    let sig = priv_dyn.sign(b"hello", &params, &mut r).expect("sign");

    let pub_dyn = priv_dyn.public_key().expect("public key");
    assert_eq!(pub_dyn.algorithm(), Algorithm::Ed25519);
    pub_dyn.verify(b"hello", &sig, &params).expect("verify ok");
    assert!(pub_dyn.verify(b"tampered", &sig, &params).is_err());
}

#[test]
fn ed25519_unsupported_operations() {
    let mut r = rng();
    let sk = crate::ec::Ed25519PrivateKey::generate(&mut r);
    let priv_dyn: Box<dyn PrivateKey> = Box::new(sk);

    match priv_dyn.decrypt(b"ct", &DecryptParams::new()) {
        Err(Error::Unsupported {
            operation: Operation::Decrypt,
            algorithm: Algorithm::Ed25519,
        }) => {}
        other => panic!("expected Unsupported(Decrypt, Ed25519), got {other:?}"),
    }
}

// ----------------------------------------------------------------------------
// ECDSA P-256: sign/verify with hash params, plus the prehash path
// ----------------------------------------------------------------------------

#[test]
fn ecdsa_p256_sign_verify_via_facade() {
    let mut r = rng();
    let sk = crate::ec::ecdsa::EcdsaPrivateKey::generate(&mut r);
    let priv_dyn: Box<dyn PrivateKey> = Box::new(sk);
    assert_eq!(priv_dyn.algorithm(), Algorithm::P256);

    let params = SignParams::new().hash(Hash::Sha256);
    let sig = priv_dyn.sign(b"msg", &params, &mut r).expect("sign");
    let pk = priv_dyn.public_key().expect("public key");
    pk.verify(b"msg", &sig, &params).expect("verify");
    assert!(pk.verify(b"msg2", &sig, &params).is_err());
}

#[test]
fn boxed_ecdsa_p384_sign_verify_via_facade() {
    // Exercises the runtime-curve path, incl. the fixed-width r||s signature
    // reconstruction in the boxed `Verifier` impl.
    let mut r = rng();
    let sk = crate::ec::BoxedEcdsaPrivateKey::generate(crate::ec::CurveId::P384, &mut r);
    let priv_dyn: Box<dyn PrivateKey> = Box::new(sk);
    assert_eq!(priv_dyn.algorithm(), Algorithm::P384);

    let params = SignParams::new().hash(Hash::Sha384);
    let sig = priv_dyn.sign(b"boxed", &params, &mut r).expect("sign");
    let pk = priv_dyn.public_key().expect("public key");
    assert_eq!(pk.algorithm(), Algorithm::P384);
    pk.verify(b"boxed", &sig, &params).expect("verify");
    assert!(pk.verify(b"boxed!", &sig, &params).is_err());
}

// ----------------------------------------------------------------------------
// RSA: PSS sign/verify and OAEP encrypt/decrypt through the facade
// ----------------------------------------------------------------------------

#[test]
fn rsa_sign_verify_and_encrypt_decrypt_via_facade() {
    let mut r = rng();
    let sk = crate::test_util::rsa_test_key_a();
    let pk = sk.public_key();
    let priv_dyn: Box<dyn PrivateKey> = Box::new(sk);
    let pub_dyn: Box<dyn PublicKey> = Box::new(pk);
    assert_eq!(priv_dyn.algorithm(), Algorithm::Rsa);

    // PSS (default) sign/verify.
    let sp = SignParams::new();
    let sig = priv_dyn.sign(b"data", &sp, &mut r).expect("rsa sign");
    pub_dyn.verify(b"data", &sig, &sp).expect("rsa verify");
    assert!(pub_dyn.verify(b"other", &sig, &sp).is_err());

    // PKCS#1 v1.5 sign/verify.
    let sp15 = SignParams::new().pkcs1v15();
    let sig15 = priv_dyn
        .sign(b"data", &sp15, &mut r)
        .expect("rsa pkcs1 sign");
    pub_dyn
        .verify(b"data", &sig15, &sp15)
        .expect("rsa pkcs1 verify");

    // OAEP encrypt/decrypt.
    let ep = EncryptParams::new();
    let ct = pub_dyn
        .encrypt(b"secret", &ep, &mut r)
        .expect("rsa encrypt");
    let pt = priv_dyn
        .decrypt(&ct, &DecryptParams::new())
        .expect("rsa decrypt");
    assert_eq!(pt.as_bytes(), b"secret");
}

// ----------------------------------------------------------------------------
// Key agreement: X25519 + ECDH P-256 equality, and peer-mismatch rejection
// ----------------------------------------------------------------------------

#[test]
fn x25519_agreement_and_mismatch() {
    let mut r = rng();
    let a = crate::ec::X25519PrivateKey::generate(&mut r);
    let b = crate::ec::X25519PrivateKey::generate(&mut r);
    let a_dyn: Box<dyn PrivateKey> = Box::new(a);
    let b_dyn: Box<dyn PrivateKey> = Box::new(b);

    let a_pub = a_dyn.public_key().expect("a pub");
    let b_pub = b_dyn.public_key().expect("b pub");

    let s_ab = a_dyn.agree(b_pub.as_ref()).expect("a·B");
    let s_ba = b_dyn.agree(a_pub.as_ref()).expect("b·A");
    assert_eq!(s_ab.as_bytes(), s_ba.as_bytes());

    // A peer of a different algorithm is rejected before any computation.
    let ed = crate::ec::Ed25519PrivateKey::generate(&mut r);
    let ed_dyn: Box<dyn PrivateKey> = Box::new(ed);
    let ed_pub = ed_dyn.public_key().expect("ed pub");
    match a_dyn.agree(ed_pub.as_ref()) {
        Err(Error::AlgorithmMismatch {
            expected: Algorithm::X25519,
            found: Algorithm::Ed25519,
        }) => {}
        other => panic!("expected AlgorithmMismatch, got {other:?}"),
    }
}

#[test]
fn ecdh_p256_agreement() {
    let mut r = rng();
    let a = crate::ec::ecdh::EcdhPrivateKey::generate(&mut r);
    let b = crate::ec::ecdh::EcdhPrivateKey::generate(&mut r);
    let a_dyn: Box<dyn PrivateKey> = Box::new(a);
    let b_dyn: Box<dyn PrivateKey> = Box::new(b);
    let a_pub = a_dyn.public_key().expect("a pub");
    let b_pub = b_dyn.public_key().expect("b pub");
    let s_ab = a_dyn.agree(b_pub.as_ref()).expect("a·B");
    let s_ba = b_dyn.agree(a_pub.as_ref()).expect("b·A");
    assert_eq!(s_ab.as_bytes(), s_ba.as_bytes());
}

// ----------------------------------------------------------------------------
// ML-KEM: encapsulate -> decapsulate equality via the capability traits
// ----------------------------------------------------------------------------

#[test]
fn mlkem768_encapsulate_decapsulate() {
    let mut r = rng();
    let (dk, ek) = crate::mlkem::MlKem768DecapsKey::generate(&mut r);
    // Call the capability-trait methods explicitly (the inherent
    // encapsulate/decapsulate shadow them and have different shapes).
    let (ct, ss_enc) = Encapsulator::encapsulate(&ek, &mut r).expect("encapsulate");
    let ss_dec = Decapsulator::decapsulate(&dk, &ct).expect("decapsulate");
    assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    assert_eq!(ss_enc.len(), 32);
}

// ----------------------------------------------------------------------------
// ML-DSA: sign/verify through the facade
// ----------------------------------------------------------------------------

#[test]
fn mldsa65_sign_verify_via_facade() {
    let mut r = rng();
    let (sk, pk) = crate::mldsa::MlDsa65PrivateKey::generate(&mut r);
    let priv_dyn: Box<dyn PrivateKey> = Box::new(sk);
    let pub_dyn: Box<dyn PublicKey> = Box::new(pk);
    assert_eq!(priv_dyn.algorithm(), Algorithm::MlDsa65);

    let params = SignParams::new();
    let sig = priv_dyn.sign(b"pq", &params, &mut r).expect("mldsa sign");
    pub_dyn.verify(b"pq", &sig, &params).expect("mldsa verify");
    assert!(pub_dyn.verify(b"pq!", &sig, &params).is_err());
}

// ----------------------------------------------------------------------------
// XMSS: stateful signer advances. (Stateful private keys are deliberately NOT
// `PrivateKey`s — they are reached only through `StatefulSigner`.)
// ----------------------------------------------------------------------------

#[test]
fn xmss_stateful_signer() {
    let mut r = rng();
    let mut sk =
        crate::xmss::XmssPrivateKey::generate(crate::xmss::XmssParamSet::Sha2_10_256, &mut r);

    let before = StatefulSigner::remaining(&sk);
    let sig = StatefulSigner::sign(&mut sk, b"once", &mut r).expect("xmss sign");
    let after = StatefulSigner::remaining(&sk);
    assert_eq!(after, before - 1, "stateful sign must consume one OTS key");

    // The public key (a normal `&self` verifier) still works through the facade.
    let pub_dyn: Box<dyn PublicKey> = Box::new(sk.public_key());
    assert_eq!(pub_dyn.algorithm(), Algorithm::Xmss);
    pub_dyn
        .verify(b"once", &sig, &SignParams::new())
        .expect("xmss verify");
}

// ----------------------------------------------------------------------------
// Consume-tracked params: an unsupported field set by the caller fails loudly.
// ----------------------------------------------------------------------------

#[test]
fn unsupported_param_is_rejected() {
    let mut r = rng();
    let sk = crate::ec::Ed25519PrivateKey::generate(&mut r);
    let priv_dyn: Box<dyn PrivateKey> = Box::new(sk);

    // Ed25519 honours no parameters; setting a hash must fail loudly.
    let params = SignParams::new().hash(Hash::Sha256);
    match priv_dyn.sign(b"m", &params, &mut r) {
        Err(Error::UnsupportedParam { param: "hash" }) => {}
        other => panic!("expected UnsupportedParam(hash), got {other:?}"),
    }
    // Default params (nothing set) are accepted.
    priv_dyn
        .sign(b"m", &SignParams::new(), &mut r)
        .expect("default params ok");
}

// ----------------------------------------------------------------------------
// Generic decoders: PKCS#8 / SPKI -> Box<dyn ...>, then operate
// ----------------------------------------------------------------------------

#[test]
fn decode_pkcs8_private_then_sign() {
    let mut r = rng();
    let sk = crate::ec::Ed25519PrivateKey::generate(&mut r);
    let sk_pem = sk.to_pkcs8_pem();

    let priv_dyn = crate::key::private_key_from_pkcs8_pem(&sk_pem).expect("decode pkcs8");
    assert_eq!(priv_dyn.algorithm(), Algorithm::Ed25519);

    let params = SignParams::new();
    let sig = priv_dyn.sign(b"decoded", &params, &mut r).expect("sign");
    // Public key derived from the decoded private key verifies its signature.
    let pub_dyn = priv_dyn.public_key().expect("derive public");
    pub_dyn.verify(b"decoded", &sig, &params).expect("verify");
}

#[test]
fn decode_spki_public() {
    let pk_der = crate::test_util::rsa_test_key_a()
        .public_key()
        .to_spki_der();
    let pub_dyn = crate::key::public_key_from_spki_der(&pk_der).expect("decode spki");
    assert_eq!(pub_dyn.algorithm(), Algorithm::Rsa);
}

#[test]
fn any_key_into_dyn_bridge() {
    // The enum world (`key::AnyPrivateKey`, re-exported from x509) crosses into
    // the trait world via `into_dyn()`.
    let mut r = rng();
    let sk = crate::ec::Ed25519PrivateKey::generate(&mut r);
    let pkcs8 = sk.to_pkcs8_der();
    let any: crate::key::AnyPrivateKey =
        crate::x509::AnyPrivateKey::from_pkcs8_der(&pkcs8, crate::x509::Pkcs8ReadOptions::new())
            .expect("parse pkcs8");
    let priv_dyn = any.into_dyn();
    assert_eq!(priv_dyn.algorithm(), Algorithm::Ed25519);

    let params = SignParams::new();
    let sig = priv_dyn.sign(b"bridge", &params, &mut r).expect("sign");
    priv_dyn
        .public_key()
        .expect("pub")
        .verify(b"bridge", &sig, &params)
        .expect("verify");
}

#[test]
fn any_key_is_a_facade_key_directly() {
    // `AnyPrivateKey` implements `PrivateKey` itself, so the parsed enum is
    // usable as a facade key WITHOUT erasing it via `into_dyn` / `Box`.
    let mut r = rng();
    let sk = crate::ec::Ed25519PrivateKey::generate(&mut r);
    let any = crate::x509::AnyPrivateKey::from_pkcs8_der(
        &sk.to_pkcs8_der(),
        crate::x509::Pkcs8ReadOptions::new(),
    )
    .expect("parse pkcs8");

    // Call the facade methods straight on the enum value.
    assert_eq!(PrivateKey::algorithm(&any), Algorithm::Ed25519);
    let params = SignParams::new();
    let sig = any.sign(b"direct", &params, &mut r).expect("sign");
    let pk = any.public_key().expect("pub");
    pk.verify(b"direct", &sig, &params).expect("verify");

    // ...and it can still be matched for the concrete, algorithm-specific API.
    match any {
        crate::key::AnyPrivateKey::Ed25519(ref k) => {
            let _ = k.public_key(); // concrete Ed25519PublicKey, not the facade
        }
        _ => panic!("expected Ed25519 variant"),
    }
}

// ----------------------------------------------------------------------------
// ECDSA signature wire encoding: Raw r||s vs DER round-trips, and differ
// ----------------------------------------------------------------------------

#[test]
fn ecdsa_der_vs_raw_encoding() {
    use crate::key::SigEncoding;
    let mut r = rng();
    let sk = crate::ec::ecdsa::EcdsaPrivateKey::generate(&mut r);
    let priv_dyn: Box<dyn PrivateKey> = Box::new(sk);
    let pk = priv_dyn.public_key().expect("pub");

    let raw_p = SignParams::new().hash(Hash::Sha256); // SigEncoding::Raw default
    let der_p = SignParams::new()
        .hash(Hash::Sha256)
        .sig_encoding(SigEncoding::Der);

    let raw = priv_dyn.sign(b"m", &raw_p, &mut r).expect("raw sign");
    let der = priv_dyn.sign(b"m", &der_p, &mut r).expect("der sign");
    assert_eq!(raw.len(), 64, "raw r||s is fixed 64 bytes for P-256");
    assert_eq!(
        der.first(),
        Some(&0x30),
        "DER signature starts with SEQUENCE"
    );
    assert_ne!(raw, der);

    // Each verifies only under its matching encoding.
    pk.verify(b"m", &raw, &raw_p).expect("raw verify");
    pk.verify(b"m", &der, &der_p).expect("der verify");
    assert!(pk.verify(b"m", &der, &raw_p).is_err());
    assert!(pk.verify(b"m", &raw, &der_p).is_err());
}

// ----------------------------------------------------------------------------
// Object safety: a heterogeneous collection of boxed private keys
// ----------------------------------------------------------------------------

#[test]
fn heterogeneous_private_keys_are_object_safe() {
    let mut r = rng();
    let keys: Vec<Box<dyn PrivateKey>> = alloc::vec![
        Box::new(crate::ec::Ed25519PrivateKey::generate(&mut r)),
        Box::new(crate::ec::ecdsa::EcdsaPrivateKey::generate(&mut r)),
        Box::new(crate::ec::X25519PrivateKey::generate(&mut r)),
    ];
    let algs: Vec<Algorithm> = keys.iter().map(|k| k.algorithm()).collect();
    assert_eq!(
        algs,
        alloc::vec![Algorithm::Ed25519, Algorithm::P256, Algorithm::X25519]
    );
}
