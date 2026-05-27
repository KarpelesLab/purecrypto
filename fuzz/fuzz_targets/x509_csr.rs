//! Fuzz `CertificationRequest::from_der` (PKCS#10).

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::x509::CertificationRequest;

fuzz_target!(|data: &[u8]| {
    let _ = CertificationRequest::from_der(data.to_vec());
});
