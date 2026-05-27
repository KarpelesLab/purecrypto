//! Fuzz `AnyPublicKey::from_spki_der`. This single entry point selects
//! between RSA / ECDSA / Ed25519 / ML-DSA / SLH-DSA based on the
//! algorithm OID in the SubjectPublicKeyInfo header, so a single target
//! covers every public-key-parse path through SPKI.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::x509::AnyPublicKey;

fuzz_target!(|data: &[u8]| {
    let _ = AnyPublicKey::from_spki_der(data);
});
