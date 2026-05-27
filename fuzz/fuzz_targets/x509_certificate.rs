//! Fuzz `Certificate::from_der` plus every public accessor. The parser
//! is lazy: `from_der` does the outer structural pass, and the accessors
//! parse sub-regions on demand. A bug hiding behind an accessor only
//! surfaces if we actually call it.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::x509::Certificate;

fuzz_target!(|data: &[u8]| {
    let Ok(cert) = Certificate::from_der(data.to_vec()) else {
        return;
    };
    let _ = cert.issuer();
    let _ = cert.subject();
    let _ = cert.basic_constraints();
    let _ = cert.extensions();
    let _ = cert.subject_public_key();
});
