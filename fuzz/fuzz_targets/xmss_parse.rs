//! Fuzz the XMSS / XMSS^MT (RFC 8391) byte-level parsers plus signature
//! verification with attacker-controlled signature bytes. Counterpart
//! to `lms_parse` — the CLI's `parse_stateful` feeds raw key files into
//! `XmssPrivateKey::from_bytes` / `XmssMtPrivateKey::from_bytes`, and
//! public keys + signatures travel as raw byte strings.
//!
//! Verification runs the fuzz input as a signature against a fixed
//! seed-derived public key per scheme. It can essentially never verify,
//! but the WOTS+ chain walk, the L-tree, and the auth-path recompute
//! are all driven by attacker-controlled `idx` / chain values and must
//! reject cleanly. The smallest parameter sets (h=10 single-tree,
//! h=20/d=2 multi-tree) bound the one-time keygen cost.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::xmss::{
    XmssMtParamSet, XmssMtPrivateKey, XmssMtPublicKey, XmssParamSet, XmssPrivateKey,
    XmssPublicKey,
};
use std::sync::OnceLock;

/// XMSS / XMSS^MT signatures for the supported sets are < 10 KiB;
/// longer inputs only exercise a length check.
const MAX_INPUT: usize = 16 * 1024;

struct Pinned {
    xmss_pub: XmssPublicKey,
    mt_pub: XmssMtPublicKey,
}

static PINNED: OnceLock<Pinned> = OnceLock::new();

fn pinned() -> &'static Pinned {
    PINNED.get_or_init(|| {
        // 3n-byte deterministic seeds (SK_SEED ‖ SK_PRF ‖ PUB_SEED).
        let xmss = XmssPrivateKey::from_seed(XmssParamSet::Sha2_10_256, &[0xa5u8; 96]);
        let mt = XmssMtPrivateKey::from_seed(XmssMtParamSet::Sha2_20_2_256, &[0x5au8; 96]);
        Pinned {
            xmss_pub: xmss.public_key(),
            mt_pub: mt.public_key(),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }

    // Key-file parsers (the CLI `parse_stateful` surface).
    let _ = XmssPrivateKey::from_bytes(data);
    let _ = XmssMtPrivateKey::from_bytes(data);

    // Public-key parsers — the parameter set is pinned by the caller
    // (e.g. read from the OID prefix), so exercise one set per scheme.
    let _ = XmssPublicKey::from_bytes(XmssParamSet::Sha2_10_256, data);
    let _ = XmssMtPublicKey::from_bytes(XmssMtParamSet::Sha2_20_2_256, data);

    // Fuzz bytes as a signature against pinned valid public keys.
    let p = pinned();
    let _ = p.xmss_pub.verify(b"fuzz message", data);
    let _ = p.mt_pub.verify(b"fuzz message", data);
});
