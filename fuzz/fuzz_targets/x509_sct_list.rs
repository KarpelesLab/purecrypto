//! Fuzz the RFC 6962 `SignedCertificateTimestampList` decoders:
//! `parse_sct_list` (the TLS-serialized list as it arrives in the
//! `signed_certificate_timestamp` handshake extension or an OCSP
//! response) and `sct_list_from_extension` (the same list behind the DER
//! `OCTET STRING` wrapper of the embedded-certificate extension). Each
//! decoded SCT is re-serialized, the list is round-tripped, and the
//! standalone verifier runs against an empty log set so the signed-data
//! reconstruction over the SCT's `extensions` bytes executes too.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::x509::sct::{
    parse_sct_list, sct_list_from_extension, serialize_sct_list, verify_standalone_sct,
};

fuzz_target!(|data: &[u8]| {
    let _ = sct_list_from_extension(data);
    let Ok(scts) = parse_sct_list(data) else {
        return;
    };
    for sct in &scts {
        let _ = sct.to_bytes();
        let _ = sct.signed_data_for_x509(data);
        let _ = sct.signed_data_for_precert(data, data);
        let _ = verify_standalone_sct(sct, data, &[], u64::MAX);
    }
    let again = serialize_sct_list(&scts);
    let reparsed = parse_sct_list(&again).expect("serialized SCT list must re-parse");
    assert_eq!(reparsed.len(), scts.len());
});
