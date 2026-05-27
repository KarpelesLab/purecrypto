//! Fuzz `pbes2::decrypt`. The DER structure encodes both the
//! key-derivation parameters (PBKDF2 / scrypt) and the inner cipher,
//! so this target reaches the KDF, the AEAD, and all DER parsing in
//! between.
//!
//! The password is pinned — fuzzing the password would just produce
//! "MAC mismatch" rejections, which isn't the interesting code path.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::kdf::pbes2;

fuzz_target!(|data: &[u8]| {
    let _ = pbes2::decrypt(data, b"password");
});
