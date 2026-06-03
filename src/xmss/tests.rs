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
