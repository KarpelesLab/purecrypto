//! Fuzz the SLH-DSA PKCS#8 parser. The parser picks the parameter set
//! from the algorithm OID, so this one target covers every variant.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::slhdsa::PrivateKey;

fuzz_target!(|data: &[u8]| {
    let _ = PrivateKey::from_pkcs8_der(data);
});
