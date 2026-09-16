//! Fuzz the crate-private TLS handshake / extension / record decoders
//! directly, via the hidden `__fuzz` feature's `purecrypto::tls::fuzz`
//! module.
//!
//! The `tls_*_feed` targets push bytes through `Connection::feed`, which
//! means every encrypted-flight decoder — EncryptedExtensions,
//! Certificate, CertificateRequest, CertificateVerify, NewSessionTicket,
//! KeyUpdate, EndOfEarlyData — sits behind a key exchange the fuzzer can
//! never complete. This target skips the handshake: the first input byte
//! selects a decoder (see `purecrypto::tls::fuzz::selector`) and the rest
//! is handed to it raw. The TLS 1.2 flight decoders, the ECH parsers and
//! every extension-body parser are reachable the same way.
//!
//! Corpus seeds: a one-byte selector followed by any valid message body of
//! that type (e.g. `[8, 0]` is `KeyUpdate(not_requested)`).

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    purecrypto::tls::fuzz::dispatch(data);
});
