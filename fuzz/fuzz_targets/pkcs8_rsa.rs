//! Fuzz the RSA PKCS#8 parser. Uses the runtime-sized `BoxedRsaPrivateKey`
//! so we don't have to commit to a `LIMBS` constant — covers any
//! modulus length the parser is willing to accept.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::rsa::BoxedRsaPrivateKey;

fuzz_target!(|data: &[u8]| {
    let _ = BoxedRsaPrivateKey::from_pkcs8_der(data);
});
