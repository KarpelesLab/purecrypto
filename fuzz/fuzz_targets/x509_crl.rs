//! Fuzz `CertificateRevocationList::from_der`. Unlike `Certificate`,
//! the CRL parser does most of its work eagerly in `from_der` — no
//! accessor pass is needed to surface internal bugs.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::x509::CertificateRevocationList;

fuzz_target!(|data: &[u8]| {
    let _ = CertificateRevocationList::from_der(data.to_vec());
});
