//! Fuzz ML-DSA signature decoding through verification. An ML-DSA
//! signature is `c_tilde || z (bit-packed) || h (hint encoding)`; the
//! hint block is a variable-structure encoding (per-polynomial
//! cumulative counts followed by sorted indices) that FIPS 204
//! Algorithm 21 (`HintBitUnpack`) requires the verifier to reject when
//! non-canonical, and `z` must be range-checked before use. Those
//! decoders are what this target drives; the lattice arithmetic behind
//! them is shape-oblivious.
//!
//! ML-DSA-44 is used: the three levels share one macro-generated
//! `verify_internal`, and 44 has the smallest signature (2420 bytes) and
//! the cheapest verify.
//!
//! The signature length is fixed, so — as in `slhdsa_verify` — the input
//! is zero-padded / truncated to `SIG_LEN` before the pinned-key verify;
//! otherwise nearly every libFuzzer input dies in the length check and
//! the hint decoder is never reached. Two further views: the SPKI decoder
//! on the raw input, and, when the input is long enough, its first
//! `PUBKEY_LEN` bytes as an attacker-supplied public key (`t1` unpacking)
//! with the remainder as the signature.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::mldsa::{MlDsa44PrivateKey, MlDsa44PublicKey};
use std::sync::OnceLock;

/// ML-DSA-44 encoded public-key / signature lengths (FIPS 204 Table 2).
const PUBKEY_LEN: usize = 1312;
const SIG_LEN: usize = 2420;

static PINNED: OnceLock<MlDsa44PublicKey> = OnceLock::new();

fn pinned() -> &'static MlDsa44PublicKey {
    PINNED.get_or_init(|| MlDsa44PrivateKey::from_seed(&[0x42u8; 32]).1)
}

fuzz_target!(|data: &[u8]| {
    // Pad / truncate to the exact signature size so every input reaches
    // the `z` / hint decoders instead of dying in the length check.
    let mut sig = [0u8; SIG_LEN];
    let n = data.len().min(SIG_LEN);
    sig[..n].copy_from_slice(&data[..n]);
    let _ = pinned().verify(&sig, b"fuzz message", b"");

    // SPKI decoder (OID + BIT STRING framing around the raw key).
    let _ = MlDsa44PublicKey::from_spki_der(data);

    // Fuzz bytes as public key || signature.
    if data.len() > PUBKEY_LEN
        && let Ok(pk) = MlDsa44PublicKey::from_bytes(&data[..PUBKEY_LEN])
    {
        let _ = pk.verify(&data[PUBKEY_LEN..], b"fuzz message", b"ctx");
    }
});
