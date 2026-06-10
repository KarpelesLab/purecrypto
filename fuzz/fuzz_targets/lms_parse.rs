//! Fuzz the LMS / HSS (RFC 8554) byte-level parsers plus signature
//! verification with attacker-controlled signature bytes.
//!
//! The CLI's `pkeyutl` feeds raw key files straight into
//! `LmsPrivateKey::from_bytes` / `HssPrivateKey::from_bytes` (see
//! `parse_stateful` in `src/bin/purecrypto/pkeyutl.rs`), and the public
//! keys + signatures are exchanged as raw byte strings — all four
//! `from_bytes` framings (distinct magic / typecode / length checks)
//! are attacker-facing.
//!
//! Verification runs the fuzz input *as a signature* against fixed,
//! deterministically-derived public keys: it can essentially never
//! succeed, but the verifier must walk the LM-OTS chains / path arrays
//! described by arbitrary typecodes and counts without panicking or
//! over-allocating. The smallest parameter sets (H5 / W8) keep the
//! one-time keygen and the per-iteration chain work cheap.
//!
//! COST GUARD: `LmsPrivateKey::from_bytes` / `HssPrivateKey::from_bytes`
//! recompute the Merkle root from the parsed `(typecode, seed)` — for a
//! hostile H25 typecode that is 2^25 leaf computations (hours) in a
//! single call, which would wedge the fuzzer (libFuzzer only checks
//! `max_total_time` between iterations). The private-key parsers are
//! therefore only invoked when every embedded LMS typecode is H5; the
//! framing/validation code is typecode-independent, so this loses no
//! parser coverage, only keygen wall-time.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::lms::{
    HssPrivateKey, HssPublicKey, LmotsType, LmsPrivateKey, LmsPublicKey, LmsType, verify_hss,
    verify_lms,
};
use std::sync::OnceLock;

/// LMS / HSS signatures for the supported sets are < 10 KiB; anything
/// longer can only be rejected by a length check, so don't waste time.
const MAX_INPUT: usize = 16 * 1024;

struct Pinned {
    lms_pub: LmsPublicKey,
    hss_pub: HssPublicKey,
}

static PINNED: OnceLock<Pinned> = OnceLock::new();

fn pinned() -> &'static Pinned {
    PINNED.get_or_init(|| {
        let i_id = [0xa5u8; 16];
        let seed = [0x5au8; 32];
        let lms = LmsPrivateKey::from_seed(LmsType::Sha256M32H5, LmotsType::Sha256N32W8, &i_id, &seed);
        // Two-level HSS so the multi-level signature walk is reachable.
        let hss = HssPrivateKey::from_levels(&[
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8, i_id, seed),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8, [0x3cu8; 16], [0xc3u8; 32]),
        ])
        .unwrap();
        Pinned {
            lms_pub: lms.public_key(),
            hss_pub: hss.public_key(),
        }
    })
}

/// One serialized LMS level record: `u32(lms_type) || u32(ots_type) ||
/// I(16) || seed(32) || u32(q)`.
const LEVEL_RECORD: usize = 4 + 4 + 16 + 32 + 4;

/// True when `rec` (a level record prefix) pins the cheap H5 tree.
fn level_is_h5(rec: &[u8]) -> bool {
    rec.len() >= 4
        && u32::from_be_bytes([rec[0], rec[1], rec[2], rec[3]]) == LmsType::Sha256M32H5 as u32
}

/// True when every level record of a serialized `HssPrivateKey`
/// (`u32(L) || L * level_record`) is H5. Structurally-invalid inputs
/// return true — they die in the real parser's framing checks before
/// any tree is computed.
fn hss_levels_are_h5(data: &[u8]) -> bool {
    if data.len() < 4 {
        return true;
    }
    let l = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if !(1..=8).contains(&l) || data.len() != 4 + l * LEVEL_RECORD {
        return true;
    }
    (0..l).all(|i| level_is_h5(&data[4 + i * LEVEL_RECORD..]))
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }

    // Key-file / public-key parsers (the CLI `parse_stateful` surface).
    // The private-key forms recompute the Merkle root, so only feed
    // them inputs whose typecodes pin the cheap H5 tree (see COST GUARD
    // in the module docs).
    // (Wrong-length inputs die in the parser's framing check before any
    // tree is computed, so they stay fair game.)
    if data.len() != LEVEL_RECORD || level_is_h5(data) {
        let _ = LmsPrivateKey::from_bytes(data);
    }
    if hss_levels_are_h5(data) {
        let _ = HssPrivateKey::from_bytes(data);
    }
    let _ = LmsPublicKey::from_bytes(data);
    let _ = HssPublicKey::from_bytes(data);

    // Fuzz bytes as a signature against pinned valid public keys.
    let p = pinned();
    let _ = p.lms_pub.verify(b"fuzz message", data);
    let _ = p.hss_pub.verify(b"fuzz message", data);

    // Free-function forms: fuzz bytes as the *public key* with a fixed
    // signature-shaped blob, and as both at once.
    let _ = verify_lms(data, b"fuzz message", data);
    let _ = verify_hss(data, b"fuzz message", data);
});
