//! Stress the low-level DER `Reader` API with arbitrary bytes. Every
//! higher-level parser in the crate (X.509, PKCS#8, ECDSA-DER signatures,
//! …) sits on top of this — bugs found here propagate everywhere.
//!
//! The harness picks one of the public read methods per iteration based
//! on the first input byte, then drives the reader to exhaustion. The
//! goal is to surface panics in length/tag handling, not to validate any
//! particular grammar — the higher-level targets do that.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::der::Reader;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (selector, body) = (data[0], &data[1..]);
    let mut r = Reader::new(body);
    // Drive a sequence of reads picked from `selector`. Every method on
    // `Reader` is fault-tolerant by contract: it must return `Result`
    // and never panic regardless of input.
    for k in 0..32 {
        let pick = selector.rotate_left((k & 7) as u32) & 0x0f;
        let stop = match pick {
            0 => r.read_sequence().is_err(),
            1 => r.read_integer_bytes().is_err(),
            2 => r.read_unsigned_integer_bytes().is_err(),
            3 => r.read_octet_string().is_err(),
            4 => r.read_oid().is_err(),
            5 => r.read_bit_string().is_err(),
            6 => r.read_boolean().is_err(),
            _ => r.read_any().is_err(),
        };
        if stop {
            break;
        }
    }
});
