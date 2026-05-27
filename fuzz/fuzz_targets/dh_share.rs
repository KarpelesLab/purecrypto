//! Fuzz the finite-field DH public-value parser and the secret-derivation
//! that follows. `from_bytes` does the public-value validation
//! (range check on `[2, p-2]`), and `shared_secret` adds the
//! contributory-failure check on the resulting `g^(xy) mod p`. Driving
//! both in sequence catches anything either layer misses.
//!
//! The local exponent is built once via `OnceLock` so the fuzz loop
//! pays the modexp cost only on inputs that pass the public-value gate.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::dh::{DhPrivateKey, DhPublicKey, group14};
use purecrypto::hash::Sha256;
use purecrypto::rng::HmacDrbg;
use std::sync::OnceLock;

static LOCAL_KEY: OnceLock<DhPrivateKey> = OnceLock::new();

fn local_key() -> &'static DhPrivateKey {
    LOCAL_KEY.get_or_init(|| {
        let mut rng = HmacDrbg::<Sha256>::new(b"fuzz-dh-share-key", b"nonce", &[]);
        DhPrivateKey::generate(group14(), &mut rng)
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(peer) = DhPublicKey::from_bytes(group14(), data) else {
        return;
    };
    let _ = local_key().shared_secret(&peer);
});
