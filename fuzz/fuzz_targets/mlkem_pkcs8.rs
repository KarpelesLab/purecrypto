//! Fuzz the ML-KEM-768 PKCS#8 parser. The 512/768/1024 parameter sets
//! share the same macro-generated parser body, differing only in
//! expected key length and OID — fuzzing one covers the family.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::mlkem::MlKem768DecapsKey;

fuzz_target!(|data: &[u8]| {
    let _ = MlKem768DecapsKey::from_pkcs8_der(data);
});
