//! Fuzz the PEM decoder. `pem_decode` accepts arbitrary text and must
//! reject everything that isn't a well-formed `-----BEGIN/END label-----`
//! envelope wrapping valid base64.
//!
//! We try a handful of labels per input — `"ANY"` would always
//! mismatch a real label, so to actually exercise the body parser we
//! cycle through the labels the crate emits in practice.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::der::pem_decode;

// Each label the crate's writers actually emit. Mismatches return Err
// early without touching the base64 decoder; matches exercise the
// envelope + base64 path.
const LABELS: &[&str] = &[
    "CERTIFICATE",
    "CERTIFICATE REQUEST",
    "X509 CRL",
    "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "PUBLIC KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
];

fuzz_target!(|data: &[u8]| {
    // `pem_decode` takes &str; reject inputs that aren't UTF-8 quickly
    // — the unit tests already cover the UTF-8 conversion boundary.
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    for label in LABELS {
        let _ = pem_decode(s, label);
    }
});
