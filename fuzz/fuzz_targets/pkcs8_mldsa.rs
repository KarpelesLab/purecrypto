//! Fuzz the ML-DSA-65 PKCS#8 parser. ML-DSA-44 and ML-DSA-87 share the
//! same macro-generated parser body, differing only in expected key
//! length and OID — fuzzing one covers the family.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::mldsa::MlDsa65PrivateKey;

fuzz_target!(|data: &[u8]| {
    let _ = MlDsa65PrivateKey::from_pkcs8_der(data);
});
