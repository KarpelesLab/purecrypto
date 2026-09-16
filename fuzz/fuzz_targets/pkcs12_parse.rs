//! Fuzz `Pfx::parse` — the PKCS#12 / PFX (RFC 7292) archive reader that
//! applications hand attacker-supplied `.p12` / `.pfx` files to.
//!
//! `parse` verifies the RFC 7292 Appendix B MAC *before* decrypting
//! anything, so with a pinned password an arbitrary input can only reach
//! the outer `PFX` / `ContentInfo` / `MacData` DER walk, the MAC-KDF
//! parameter decoding (digest OID, salt, iteration count) and the
//! aggregate KDF-work budget accounting. That is exactly the surface an
//! attacker who does *not* know the password can hit, so it is the
//! important one. The `AuthenticatedSafe` / `SafeBag` / shrouded-key /
//! cert-bag parsers behind the MAC are only reachable from a seed corpus
//! written with the same password — drop a few `Pfx::build(...)` outputs
//! (password `"password"`) in `fuzz/corpus/pkcs12_parse/` to get them into
//! the loop. A mutated seed still fails the MAC, so the fuzzer cannot get
//! *past* the MAC on its own.
//!
//! COST NOTE: the MAC iteration count is attacker-controlled and is only
//! capped by the crate-wide PBKDF budget (`MAX_TOTAL_ITERATIONS`), so a
//! single input may legitimately burn seconds. Pass `-- -timeout=120` if
//! libFuzzer's slow-unit reports get noisy.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::pkcs12::Pfx;

/// Real PFX archives are a few KiB; a larger input only adds DER walking.
const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let _ = Pfx::parse(data, "password");
});
