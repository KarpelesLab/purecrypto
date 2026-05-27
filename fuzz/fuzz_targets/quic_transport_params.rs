//! Fuzz the QUIC TLS transport-parameters extension decoder. The wire
//! format is a stream of `(id, length, value)` triples encoded with
//! QUIC variable-length integers, so this target reaches the varint
//! decoder, the parameter dispatch table, and every per-parameter
//! value parser.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::quic::TransportParameters;

fuzz_target!(|data: &[u8]| {
    let _ = TransportParameters::decode(data);
});
