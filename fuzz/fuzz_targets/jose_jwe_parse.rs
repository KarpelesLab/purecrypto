//! Fuzz `Jwe::parse` — the compact and (flattened / general) JSON
//! serializations — plus every accessor and a decryption attempt against
//! a pinned key set.
//!
//! The protected header, the per-recipient headers, the `enc` / `alg` /
//! `zip` / `crit` policy and the five base64url segments are all
//! attacker-controlled. Decryption can't succeed on fuzz input, but the
//! path up to the AEAD failure is exactly the untrusted surface: key
//! selection, the `A256KW` unwrap of an arbitrary `encrypted_key`, the
//! `ECDH-ES` ephemeral-key (`epk`) JWK parsing and point validation, the
//! `PBES2` salt / iteration-count bounds, and the IV / tag length checks.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::hash::Sha256;
use purecrypto::jose::{Jwe, Jwk, JwkSet};
use purecrypto::rng::HmacDrbg;
use std::sync::OnceLock;

static KEYS: OnceLock<JwkSet> = OnceLock::new();

/// A pinned, deterministic key set: a 32-byte `oct` key (reachable by
/// `dir`, `A256KW`, `A256GCMKW` and the PBES2 family's password form) and
/// a P-256 key (`ECDH-ES`, `ECDH-ES+A*KW`), both with `kid`s.
fn keys() -> &'static JwkSet {
    KEYS.get_or_init(|| {
        let mut rng = HmacDrbg::<Sha256>::new(b"fuzz-jose-jwe", b"keys", &[]);
        let ec = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let mut set = JwkSet::new();
        set.push(Jwk::oct(&[0xa5; 32]).with_kid("kw")).unwrap();
        set.push(Jwk::from_ec_private(&ec).unwrap().with_kid("ec"))
            .unwrap();
        set
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(jwe) = Jwe::parse(text) else {
        let _ = Jwe::parse_compact(text);
        let _ = Jwe::parse_json(text);
        return;
    };
    let _ = jwe.protected();
    let _ = jwe.unprotected();
    let _ = jwe.enc();
    for (i, r) in jwe.recipients().iter().enumerate() {
        let _ = r.header();
        let _ = r.encrypted_key();
        let _ = jwe.alg(i);
        let _ = jwe.kid(i);
    }
    let set = keys();
    let _ = jwe.decrypt_with_set(set);
    for key in set.keys() {
        let _ = jwe.decrypt(key);
    }
});
