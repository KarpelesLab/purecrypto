//! RFC 8391 / reference-implementation known-answer tests and stateful-safety
//! checks for XMSS and XMSS^MT.
//!
//! The KAT vectors in `testdata/xmss_kat.kat` were produced by the upstream
//! XMSS reference implementation (github.com/XMSS/xmss-reference, the deployed
//! SP 800-208 variant) from the deterministic 3n-byte seed `seed[i] = 7i + 13`,
//! signing the fixed 8-byte message `{37,1,2,3,4,5,6,7}` at the listed leaf
//! index. Each line:
//!
//! `TAG oid n full_height d seed(3n) idx pk(2n) sig(sig_bytes)`
//!
//! where `TAG` is `XMSS` or `XMSSMT`. We re-derive the key from the seed, sign
//! at `idx`, and assert the public key and signature reproduce the reference
//! bytes exactly, then assert `verify` accepts them.

use super::*;
use crate::hash::Sha256;
use crate::rng::HmacDrbg;

fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut v = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16).unwrap() as u8;
        let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
        v.push((hi << 4) | lo);
        i += 2;
    }
    v
}

/// The message every KAT line signs (matches the C generator).
const KAT_MSG: &[u8] = &[37, 1, 2, 3, 4, 5, 6, 7];

#[test]
fn rfc8391_xmss_kat() {
    let mut count = 0;
    for line in include_str!("../../testdata/xmss_kat.kat").lines() {
        let mut it = line.split_whitespace();
        let tag = it.next().unwrap();
        if tag != "XMSS" {
            continue;
        }
        let oid: u32 = it.next().unwrap().parse().unwrap();
        let _n: usize = it.next().unwrap().parse().unwrap();
        let _h: u32 = it.next().unwrap().parse().unwrap();
        let _d: u32 = it.next().unwrap().parse().unwrap();
        let seed = unhex(it.next().unwrap());
        let idx: u64 = it.next().unwrap().parse().unwrap();
        let pk_exp = unhex(it.next().unwrap());
        let sig_exp = unhex(it.next().unwrap());

        let set = XmssParamSet::from_oid(oid).unwrap();
        let p = set.params();
        let mut sk = XmssPrivateKey::from_seed(set, &seed);
        let pk = sk.public_key();
        assert_eq!(
            pk.to_bytes(),
            pk_exp.as_slice(),
            "pk mismatch oid={oid} idx={idx}"
        );

        // Fast-forward the index to the vector's leaf without intermediate signs.
        idx_to_bytes(idx, &mut sk.bytes[..p.index_bytes]);
        assert_eq!(sk.index(), idx, "index fast-forward");

        let sig = sk.sign(KAT_MSG).unwrap();
        assert_eq!(sig, sig_exp, "signature mismatch oid={oid} idx={idx}");
        assert!(
            pk.verify(KAT_MSG, &sig),
            "verify failed oid={oid} idx={idx}"
        );

        // Negative checks: wrong message and tampered signature are rejected.
        assert!(
            !pk.verify(b"wrong message", &sig),
            "wrong msg accepted oid={oid}"
        );
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(!pk.verify(KAT_MSG, &bad), "tampered sig accepted oid={oid}");
        count += 1;
    }
    assert!(count >= 7, "expected XMSS KAT lines, got {count}");
}

#[test]
fn rfc8391_xmssmt_kat() {
    let mut count = 0;
    for line in include_str!("../../testdata/xmss_kat.kat").lines() {
        let mut it = line.split_whitespace();
        let tag = it.next().unwrap();
        if tag != "XMSSMT" {
            continue;
        }
        let oid: u32 = it.next().unwrap().parse().unwrap();
        let _n: usize = it.next().unwrap().parse().unwrap();
        let _h: u32 = it.next().unwrap().parse().unwrap();
        let _d: u32 = it.next().unwrap().parse().unwrap();
        let seed = unhex(it.next().unwrap());
        let idx: u64 = it.next().unwrap().parse().unwrap();
        let pk_exp = unhex(it.next().unwrap());
        let sig_exp = unhex(it.next().unwrap());

        let set = XmssMtParamSet::from_oid(oid).unwrap();
        let p = set.params();
        let mut sk = XmssMtPrivateKey::from_seed(set, &seed);
        let pk = sk.public_key();
        assert_eq!(
            pk.to_bytes(),
            pk_exp.as_slice(),
            "pk mismatch oid={oid} idx={idx}"
        );

        idx_to_bytes(idx, &mut sk.bytes[..p.index_bytes]);
        assert_eq!(sk.index(), idx);

        let sig = sk.sign(KAT_MSG).unwrap();
        assert_eq!(sig, sig_exp, "signature mismatch oid={oid} idx={idx}");
        assert!(
            pk.verify(KAT_MSG, &sig),
            "verify failed oid={oid} idx={idx}"
        );

        assert!(!pk.verify(b"wrong message", &sig));
        let mut bad = sig.clone();
        bad[p.index_bytes + p.n] ^= 1; // perturb start of WOTS sig
        assert!(!pk.verify(KAT_MSG, &bad), "tampered sig accepted oid={oid}");
        count += 1;
    }
    assert!(count >= 6, "expected XMSS^MT KAT lines, got {count}");
}

#[test]
fn xmss_roundtrip_and_negatives() {
    let mut rng = HmacDrbg::<Sha256>::new(b"xmss", b"rt", &[]);
    let mut sk = XmssPrivateKey::generate(XmssParamSet::Sha2_10_256, &mut rng);
    let pk = sk.public_key();

    let sig = sk.sign(b"hello purecrypto").unwrap();
    assert!(pk.verify(b"hello purecrypto", &sig));
    assert!(!pk.verify(b"other", &sig));

    // Wrong-length signature is rejected.
    assert!(!pk.verify(b"hello purecrypto", &sig[..sig.len() - 1]));

    // Every bit of the signature is load-bearing: flip one byte, reject.
    for off in [0, sig.len() / 2, sig.len() - 1] {
        let mut bad = sig.clone();
        bad[off] ^= 0x80;
        assert!(!pk.verify(b"hello purecrypto", &bad), "tamper at {off}");
    }
}

#[test]
fn stateful_distinct_index_per_sign() {
    let mut rng = HmacDrbg::<Sha256>::new(b"xmss", b"state", &[]);
    let mut sk = XmssPrivateKey::generate(XmssParamSet::Sha2_10_256, &mut rng);
    let pk = sk.public_key();

    assert_eq!(sk.index(), 0);
    let total = 1u64 << 10;
    assert_eq!(sk.remaining(), total);

    let mut sigs = Vec::new();
    for i in 0..5 {
        assert_eq!(sk.index(), i, "index advances");
        let sig = sk.sign(b"msg").unwrap();
        // The first index_bytes encode the consumed leaf index.
        assert_eq!(bytes_to_idx(&sig[..4]), i, "signature carries its index");
        assert!(pk.verify(b"msg", &sig));
        sigs.push(sig);
    }
    assert_eq!(sk.index(), 5);
    assert_eq!(sk.remaining(), total - 5);

    // Each signature is distinct (different one-time key per index).
    for i in 0..sigs.len() {
        for j in i + 1..sigs.len() {
            assert_ne!(sigs[i], sigs[j], "index reuse would repeat signatures");
        }
    }
}

#[test]
fn stateful_reload_resumes() {
    let mut rng = HmacDrbg::<Sha256>::new(b"xmss", b"reload", &[]);
    let mut sk = XmssPrivateKey::generate(XmssParamSet::Sha2_10_256, &mut rng);
    let pk = sk.public_key();

    let _ = sk.sign(b"a").unwrap();
    let _ = sk.sign(b"b").unwrap();
    assert_eq!(sk.index(), 2);

    // Persist and reload: the index must survive serialization.
    let serialized = sk.to_bytes();
    drop(sk);
    let mut sk2 = XmssPrivateKey::from_bytes(&serialized).unwrap();
    assert_eq!(sk2.index(), 2, "reload resumes at the persisted index");
    assert_eq!(sk2.parameter_set(), XmssParamSet::Sha2_10_256);

    let sig = sk2.sign(b"c").unwrap();
    assert_eq!(
        bytes_to_idx(&sig[..4]),
        2,
        "resumed sign uses index 2, not 0"
    );
    assert!(pk.verify(b"c", &sig));
    assert_eq!(sk2.index(), 3);

    // The reloaded public key matches the original.
    assert_eq!(sk2.public_key(), pk);
}

#[test]
fn stateful_exhaustion_errors() {
    // Use a synthetic tiny key by fast-forwarding to the last index.
    let mut rng = HmacDrbg::<Sha256>::new(b"xmss", b"exhaust", &[]);
    let mut sk = XmssPrivateKey::generate(XmssParamSet::Sha2_10_256, &mut rng);
    let p = sk.parameter_set().params();
    let last = (1u64 << p.full_height) - 1;
    idx_to_bytes(last, &mut sk.bytes[..p.index_bytes]);

    assert_eq!(sk.remaining(), 1);
    let sig = sk.sign(b"last").unwrap();
    assert!(sk.public_key().verify(b"last", &sig));
    assert_eq!(sk.index(), last + 1);
    assert_eq!(sk.remaining(), 0);

    // No keys left: signing must error, not reuse the final index.
    assert_eq!(sk.sign(b"too many"), Err(Error::KeyExhausted));
    assert_eq!(sk.index(), last + 1, "exhausted sign does not advance");
}

#[test]
fn xmssmt_roundtrip() {
    let mut rng = HmacDrbg::<Sha256>::new(b"xmssmt", b"rt", &[]);
    let mut sk = XmssMtPrivateKey::generate(XmssMtParamSet::Sha2_20_2_256, &mut rng);
    let pk = sk.public_key();

    let sig = sk.sign(b"multi-tree").unwrap();
    assert_eq!(sig.len(), sk.parameter_set().params().sig_bytes());
    assert!(pk.verify(b"multi-tree", &sig));
    assert!(!pk.verify(b"nope", &sig));

    // Reload resumes for XMSS^MT too.
    let bytes = sk.to_bytes();
    let mut sk2 = XmssMtPrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(sk2.index(), 1);
    let sig2 = sk2.sign(b"again").unwrap();
    assert!(pk.verify(b"again", &sig2));
}

#[test]
fn key_serialization_rejects_mismatch() {
    let mut rng = HmacDrbg::<Sha256>::new(b"xmss", b"mismatch", &[]);
    let sk = XmssPrivateKey::generate(XmssParamSet::Sha2_10_256, &mut rng);
    let bytes = sk.to_bytes();

    // An XMSS key must not parse as an XMSS^MT key, and vice versa.
    assert!(XmssMtPrivateKey::from_bytes(&bytes).is_err());
    assert!(XmssPrivateKey::from_bytes(&bytes[..bytes.len() - 1]).is_err());

    let mut corrupt = bytes.clone();
    corrupt[0] ^= 0xff; // break the magic
    assert!(XmssPrivateKey::from_bytes(&corrupt).is_err());
}

#[test]
fn public_key_roundtrip() {
    let mut rng = HmacDrbg::<Sha256>::new(b"xmss", b"pk", &[]);
    let sk = XmssPrivateKey::generate(XmssParamSet::Sha2_10_256, &mut rng);
    let pk = sk.public_key();
    let raw = pk.to_bytes().to_vec();
    let pk2 = XmssPublicKey::from_bytes(XmssParamSet::Sha2_10_256, &raw).unwrap();
    assert_eq!(pk, pk2);
    assert!(XmssPublicKey::from_bytes(XmssParamSet::Sha2_10_256, &raw[..raw.len() - 1]).is_err());
}

#[test]
fn from_bytes_rejects_out_of_range_index_and_bad_root() {
    // Stateful integrity gap (MEDIUM): `from_bytes` must reject a corrupted or
    // rewound index and a stored root that does not match the seeds, so a
    // tampered persisted key cannot lead to one-time-key reuse.
    let mut rng = HmacDrbg::<Sha256>::new(b"xmss", b"validate", &[]);
    let set = XmssParamSet::Sha2_10_256;
    let sk = XmssPrivateKey::generate(set, &mut rng);
    let p = set.params();
    let good = sk.to_bytes();
    // `magic(4) ‖ oid(4) ‖ idx ‖ SK_SEED ‖ SK_PRF ‖ root ‖ PUB_SEED`.
    let idx_off = 8;
    let root_off = 8 + p.index_bytes + 2 * p.n;

    // The pristine key parses, and the exhausted sentinel `idx == 2^h` is a
    // legitimate persisted state (matches the signer's exhaustion convention).
    assert!(XmssPrivateKey::from_bytes(&good).is_ok());
    let mut exhausted = good.clone();
    idx_to_bytes(
        1u64 << p.full_height,
        &mut exhausted[idx_off..idx_off + p.index_bytes],
    );
    assert!(XmssPrivateKey::from_bytes(&exhausted).is_ok());

    // One past the sentinel is out of range and must be rejected.
    let mut over = good.clone();
    idx_to_bytes(
        (1u64 << p.full_height) + 1,
        &mut over[idx_off..idx_off + p.index_bytes],
    );
    assert!(matches!(
        XmssPrivateKey::from_bytes(&over),
        Err(Error::InvalidKey)
    ));

    // A tampered root (seed/root mismatch) must be rejected.
    let mut bad_root = good.clone();
    bad_root[root_off] ^= 0xff;
    assert!(matches!(
        XmssPrivateKey::from_bytes(&bad_root),
        Err(Error::InvalidKey)
    ));

    // Same checks for XMSS^MT.
    let mut rng = HmacDrbg::<Sha256>::new(b"xmssmt", b"validate", &[]);
    let mtset = XmssMtParamSet::Sha2_20_2_256;
    let mtsk = XmssMtPrivateKey::generate(mtset, &mut rng);
    let mp = mtset.params();
    let mt_good = mtsk.to_bytes();
    let mt_root_off = 8 + mp.index_bytes + 2 * mp.n;

    assert!(XmssMtPrivateKey::from_bytes(&mt_good).is_ok());

    let mut mt_over = mt_good.clone();
    idx_to_bytes(
        (1u64 << mp.full_height) + 1,
        &mut mt_over[8..8 + mp.index_bytes],
    );
    assert!(matches!(
        XmssMtPrivateKey::from_bytes(&mt_over),
        Err(Error::InvalidKey)
    ));

    let mut mt_bad_root = mt_good.clone();
    mt_bad_root[mt_root_off] ^= 0xff;
    assert!(matches!(
        XmssMtPrivateKey::from_bytes(&mt_bad_root),
        Err(Error::InvalidKey)
    ));
}

#[test]
fn from_bytes_tall_tree_loads_without_recompute() {
    // CPU-DoS (MEDIUM): a hostile blob whose attacker-chosen OID selects a
    // tall per-layer subtree (`tree_height` 20 ⇒ ~2^20 WOTS+ keygens, ~10^9
    // hash compressions) must NOT trigger the eager root recompute in
    // `validate_raw_sk`. Above `RECOMPUTE_MAX_TREE_HEIGHT` the stored root is
    // public data and is trusted on load; structurally-valid garbage seeds
    // load instantly (a tampered root only makes signatures fail to verify —
    // fail-closed, never a forgery).
    let start = std::time::Instant::now();

    // XMSS Sha2_20_256: tree_height = 20 (single tree).
    let set = XmssParamSet::Sha2_20_256;
    let p = set.params();
    let mut blob = Vec::new();
    blob.extend_from_slice(SK_MAGIC);
    blob.extend_from_slice(&set.oid().to_be_bytes());
    blob.resize(8 + p.sk_bytes(), 0xa5); // garbage seeds/root/pub_seed
    blob[8..8 + p.index_bytes].fill(0); // in-range idx = 0
    let sk = XmssPrivateKey::from_bytes(&blob).expect("tall XMSS blob loads without recompute");
    assert_eq!(sk.index(), 0);
    assert_eq!(sk.parameter_set(), set);

    // Out-of-range index is still rejected on the trusted-root path.
    let mut over = blob.clone();
    idx_to_bytes((1u64 << p.full_height) + 1, &mut over[8..8 + p.index_bytes]);
    assert!(matches!(
        XmssPrivateKey::from_bytes(&over),
        Err(Error::InvalidKey)
    ));

    // XMSS^MT Sha2_40_2_256: tree_height = 40 / 2 = 20 per layer.
    let mtset = XmssMtParamSet::Sha2_40_2_256;
    let mp = mtset.params();
    let mut mtblob = Vec::new();
    mtblob.extend_from_slice(MTSK_MAGIC);
    mtblob.extend_from_slice(&mtset.oid().to_be_bytes());
    mtblob.resize(8 + mp.sk_bytes(), 0x5a);
    mtblob[8..8 + mp.index_bytes].fill(0);
    let mtsk =
        XmssMtPrivateKey::from_bytes(&mtblob).expect("tall XMSS^MT blob loads without recompute");
    assert_eq!(mtsk.index(), 0);
    assert_eq!(mtsk.parameter_set(), mtset);

    // The whole test must complete instantly; the 2^20 recompute it guards
    // against takes minutes. Generous bound for slow CI machines.
    assert!(
        start.elapsed() < core::time::Duration::from_secs(10),
        "tall-tree from_bytes took {:?} — eager recompute not capped?",
        start.elapsed()
    );
}
