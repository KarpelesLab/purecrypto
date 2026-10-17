//! Fuzz `Jwk::parse` and `JwkSet::parse`.
//!
//! A JWK (Set) is fetched from a `jku`-style URL or pasted from a config
//! file, so every member is untrusted: the `kty` dispatch, base64url
//! decoding of each coordinate / modulus / private member, the exact
//! field-width and on-curve checks for EC and OKP keys, the RSA size,
//! exponent and ROCA checks, the private-vs-public consistency check, and
//! the Set-level `kid` uniqueness / mixed-key rules. The private-member
//! wiping (`Zeroizing`) runs on every rejection path too. A key that
//! survives is round-tripped through its JSON export and re-parsed, and
//! the Set's `kid` lookup is exercised with each key's own `kid`.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::jose::{Jwk, JwkSet};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(key) = Jwk::parse(text) {
        let _ = key.key();
        let _ = key.kid();
        let _ = key.alg();
        let _ = key.key_use();
        let _ = key.key_ops();
        let _ = key.is_private();
        let _ = key.key().kty();
        let again = key.to_json();
        let _ = Jwk::parse(&again).expect("exported JWK must re-parse");
    }
    if let Ok(set) = JwkSet::parse(text) {
        for key in set.keys() {
            if let Some(kid) = key.kid() {
                let _ = set.find_by_kid(kid);
            }
        }
        let again = set.to_json();
        let _ = JwkSet::parse(&again).expect("exported JWK Set must re-parse");
    }
});
