//! Fuzz the wire decoder for an `encrypted_client_hello` extension
//! body (`EchExtension::decode`, draft-ietf-tls-esni-22 §5). Covers
//! both the outer-form payload (sym cipher suite + config_id +
//! HPKE-encapsulated key + AEAD payload) and the inner-form marker.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::tls::ech::extension::EchExtension;

fuzz_target!(|data: &[u8]| {
    let _ = EchExtension::decode(data);
});
