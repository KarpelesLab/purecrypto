//! Fuzz SLH-DSA verification with attacker-controlled signature bytes,
//! plus the raw and SPKI public-key decoders.
//!
//! An SLH-DSA signature is a fixed-layout concatenation
//! (`R || FORS sig || HT sig`) whose length must equal the parameter
//! set's signature size exactly, so rather than let libFuzzer spend its
//! budget on length rejects, every input is zero-padded / truncated to
//! that size and run through the verifier. The verifier is largely
//! shape-oblivious (every field is fixed-width), so the expected yield is
//! low; the value is that the WOTS+ chain walk, the FORS root recompute
//! and the hypertree auth-path recompute are driven by arbitrary bytes
//! and must never index out of range or panic. SLH-DSA-SHA2-128s is the
//! cheapest set to verify.
//!
//! The twelve `PublicKey::from_bytes` variants and the SPKI decoder are
//! fed the raw input too.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::slhdsa::{ParamSet, PrivateKey, PublicKey};
use std::sync::OnceLock;

const SET: ParamSet = ParamSet::Sha2_128s;

const ALL_SETS: [ParamSet; 12] = [
    ParamSet::Sha2_128s,
    ParamSet::Sha2_128f,
    ParamSet::Sha2_192s,
    ParamSet::Sha2_192f,
    ParamSet::Sha2_256s,
    ParamSet::Sha2_256f,
    ParamSet::Shake_128s,
    ParamSet::Shake_128f,
    ParamSet::Shake_192s,
    ParamSet::Shake_192f,
    ParamSet::Shake_256s,
    ParamSet::Shake_256f,
];

static PINNED: OnceLock<PublicKey> = OnceLock::new();

fn pinned() -> &'static PublicKey {
    PINNED.get_or_init(|| {
        // 16-byte seeds for n = 16 (the 128-bit sets).
        PrivateKey::from_seeds(SET, &[0xa5u8; 16], &[0x5au8; 16], &[0x3cu8; 16]).1
    })
}

fuzz_target!(|data: &[u8]| {
    // Pad / truncate to the exact signature size so every input reaches
    // the verifier instead of dying in the length check.
    let sig_len = SET.signature_size();
    let mut sig = vec![0u8; sig_len];
    let n = data.len().min(sig_len);
    sig[..n].copy_from_slice(&data[..n]);
    let _ = pinned().verify(&sig, b"fuzz message", b"");

    // Public-key decoders.
    for set in ALL_SETS {
        let _ = PublicKey::from_bytes(set, data);
    }
    let _ = PublicKey::from_spki_der(SET, data);
});
