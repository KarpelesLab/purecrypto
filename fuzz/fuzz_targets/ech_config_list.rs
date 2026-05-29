//! Fuzz `EchConfigList::decode` — the public entry point for parsing
//! an `ECHConfigList` blob obtained from DNS HTTPS/SVCB records, a
//! `.well-known` endpoint, an `Error::EchRejected` retry payload, or
//! any other untrusted source. Reaches the per-`ECHConfig` parser, the
//! `HpkeKeyConfig` parser, and the `HpkeSymCipherSuite` decoder.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::tls::ech::EchConfigList;

fuzz_target!(|data: &[u8]| {
    let _ = EchConfigList::decode(data);
});
