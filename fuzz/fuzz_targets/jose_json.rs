//! Fuzz the strict JSON reader behind every JOSE parser (`jose::json`).
//! It is the first thing a JWS / JWE / JWK text goes through, so it sees
//! raw attacker bytes; the nesting-depth cap, the duplicate-member
//! check, the number and string-escape decoders and the trailing-data
//! rule all live here. A parsed value is re-serialized and parsed again
//! so the serializer's escaping stays in sync with the reader.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::jose::json;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = json::parse(text) else {
        let _ = json::parse_object(text);
        return;
    };
    let again = value.to_json();
    let reparsed = json::parse(&again).expect("serialized JSON must re-parse");
    assert_eq!(
        reparsed.to_json(),
        again,
        "JSON round-trip is not a fixed point"
    );
    if let Some(obj) = value.as_object() {
        for (name, member) in obj.iter() {
            let _ = obj.get(name);
            let _ = obj.get_str(name);
            let _ = obj.get_object(name);
            let _ = obj.get_array(name);
            let _ = std::hint::black_box(member);
        }
    }
});
