//! Fuzz the Falcon (FN-DSA) public-key and signature decoders through
//! verification. Both blobs are variable-structure byte strings parsed
//! from untrusted input: the public key is `0000nnnn || 14-bit-packed h`
//! (every coefficient must be `< q`), and the signature is
//! `header || nonce(40) || Golomb-Rice-compressed s2` in either the
//! padded (`0x30|logn`, fixed length) or the compressed (`0x20|logn`,
//! variable length) encoding. The compressed-`s2` decoder walks
//! attacker-chosen unary runs and must reject overlong, non-canonical
//! or truncated encodings without panicking or reading past the buffer
//! — that decoder is the reason this target exists; the NTT / norm
//! check behind it is shape-oblivious.
//!
//! Three views of the same bytes per iteration:
//!  1. `FalconPublicKey::from_bytes(data)` — the key decoder alone.
//!  2. `data` as a signature against pinned Falcon-512 / Falcon-1024
//!     keys, once per `Format` (the real API pins one format per call,
//!     and each header nibble takes a different length-check branch).
//!  3. `data` as *both* key and signature through the free-function
//!     form.
//!
//! COST NOTE: the pinned keys are *not* generated — `FalconPrivateKey::
//! generate` (NTRU solve) takes well over ten seconds and ~1.4 GiB under
//! ASAN, which would eat the whole `-max_total_time` budget of a CI run.
//! Instead each key is the all-zero polynomial `h = 0`, which the key
//! decoder accepts (every coefficient is `0 < q`). Verification against
//! it decodes the signature exactly as for a real key, computes
//! `s1 = c - s2·h = c`, and then fails the norm bound — the decoder is
//! what we are after, so nothing of value is lost.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::falcon::{FalconPublicKey, Format, verify_with_format};
use std::sync::OnceLock;

/// Falcon-1024 padded signatures are 1280 bytes and public keys 1793;
/// anything longer can only be rejected by a length check.
const MAX_INPUT: usize = 4096;

/// Encoded public-key lengths (spec §3.13): `1 + ⌈14·n / 8⌉`.
const PK_LEN_512: usize = 897;
const PK_LEN_1024: usize = 1793;

static PINNED: OnceLock<(FalconPublicKey, FalconPublicKey)> = OnceLock::new();

fn pinned() -> &'static (FalconPublicKey, FalconPublicKey) {
    PINNED.get_or_init(|| {
        // Header `0000nnnn` with logn = 9 (512) / 10 (1024), then h = 0.
        let mut pk512 = vec![0u8; PK_LEN_512];
        pk512[0] = 0x09;
        let mut pk1024 = vec![0u8; PK_LEN_1024];
        pk1024[0] = 0x0a;
        (
            FalconPublicKey::from_bytes(&pk512).expect("h = 0 is a valid Falcon-512 key"),
            FalconPublicKey::from_bytes(&pk1024).expect("h = 0 is a valid Falcon-1024 key"),
        )
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }

    // Key decoder alone.
    let _ = FalconPublicKey::from_bytes(data);

    // Fuzz bytes as a signature against pinned keys, both degrees, both
    // formats.
    let (pk512, pk1024) = pinned();
    for pk in [pk512, pk1024] {
        let _ = pk.verify_with_format(b"fuzz message", data, Format::Padded);
        let _ = pk.verify_with_format(b"fuzz message", data, Format::Compressed);
    }

    // Fuzz bytes as key *and* signature (free-function form).
    let _ = verify_with_format(data, b"fuzz message", data, Format::Padded);
    let _ = verify_with_format(data, b"fuzz message", data, Format::Compressed);
});
