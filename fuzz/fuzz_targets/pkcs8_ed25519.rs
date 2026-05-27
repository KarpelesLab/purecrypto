//! Fuzz the Ed25519 PKCS#8 parser.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::ec::Ed25519PrivateKey;

fuzz_target!(|data: &[u8]| {
    let _ = Ed25519PrivateKey::from_pkcs8_der(data);
});
