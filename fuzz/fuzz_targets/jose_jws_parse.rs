//! Fuzz `Jws::parse` — the compact and (flattened / general) JSON
//! serializations, dispatched on the first non-blank byte — plus every
//! accessor and a verification attempt against a pinned key set.
//!
//! A JWS arrives as an attacker-controlled token: the header JSON, the
//! base64url segments, the per-signature header merging and the `alg` /
//! `crit` / `kid` policy all run on untrusted text. The verification
//! calls can't succeed on fuzz input (no key material leaks into the
//! target) but must *reject cleanly* whatever `alg` and signature bytes
//! the header pairs with each pinned key type: the key-selection logic
//! (`kid` match, key-type-vs-algorithm, `use` / `key_ops`) runs before
//! any crypto, and the signature decoders (DER-less ECDSA `r‖s`, RSA
//! length checks) run after.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::hash::Sha256;
use purecrypto::jose::{Jwk, JwkSet, Jws};
use purecrypto::rng::HmacDrbg;
use std::sync::OnceLock;

static KEYS: OnceLock<JwkSet> = OnceLock::new();

/// A pinned, deterministic key set: one `oct` HMAC key and one P-256 key,
/// both with `kid`s so the `kid`-driven selection path is reachable.
fn keys() -> &'static JwkSet {
    KEYS.get_or_init(|| {
        let mut rng = HmacDrbg::<Sha256>::new(b"fuzz-jose-jws", b"keys", &[]);
        let ec = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let mut set = JwkSet::new();
        set.push(Jwk::oct(&[0x5a; 32]).with_kid("hs")).unwrap();
        set.push(Jwk::from_ec_private(&ec).unwrap().with_kid("es"))
            .unwrap();
        set
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(jws) = Jws::parse(text) else {
        // The dispatcher picked one form; run the other explicitly too so
        // a compact-looking JSON text (or vice versa) still reaches both.
        let _ = Jws::parse_compact(text);
        let _ = Jws::parse_json(text);
        return;
    };
    let _ = std::hint::black_box(jws.payload());
    for sig in jws.signatures() {
        let _ = sig.protected();
        let _ = sig.header();
        let _ = sig.signature();
        let _ = sig.alg();
        let _ = sig.kid();
    }
    let set = keys();
    let _ = jws.verify_with_set(set);
    for key in set.keys() {
        let _ = jws.verify(key);
    }
});
