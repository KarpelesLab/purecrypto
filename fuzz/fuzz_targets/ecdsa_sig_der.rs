//! Fuzz the ECDSA DER signature parser. `BoxedEcdsaSignature::from_der`
//! is curve-agnostic — it decodes the `SEQUENCE { r INTEGER, s INTEGER }`
//! without committing to a fixed-size limb count, so a single target
//! covers every curve the parser is willing to accept.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::ec::BoxedEcdsaSignature;

fuzz_target!(|data: &[u8]| {
    let _ = BoxedEcdsaSignature::from_der(data);
});
