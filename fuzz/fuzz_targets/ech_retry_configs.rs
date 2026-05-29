//! Fuzz `decode_retry_configs` — the entry point the ECH client uses
//! on the bytes of an `encrypted_client_hello` extension carried in
//! the server's `EncryptedExtensions` after an ECH rejection
//! (draft-ietf-tls-esni-22 §6.1.6). The body is the same wire shape as
//! a plain `ECHConfigList` but is reached over a hostile network, so
//! it gets its own target.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::tls::ech::retry::decode_retry_configs;

fuzz_target!(|data: &[u8]| {
    let _ = decode_retry_configs(data);
});
