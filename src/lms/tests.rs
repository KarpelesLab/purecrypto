//! RFC 8554 Appendix F known-answer tests plus stateful-safety tests.

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

/// Parses the KAT file into (label -> list of hex fields).
fn kat() -> alloc::collections::BTreeMap<alloc::string::String, Vec<Vec<u8>>> {
    use alloc::string::ToString;
    let mut m = alloc::collections::BTreeMap::new();
    for line in include_str!("../../testdata/lms_rfc8554.kat").lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let label = it.next().unwrap().to_string();
        let fields: Vec<Vec<u8>> = it.map(unhex).collect();
        m.insert(label, fields);
    }
    m
}

/// RFC 8554 Test Case 1 (two-level HSS, H5/W8 over H5/W8): verify accepts.
#[test]
fn rfc8554_tc1_verify() {
    let k = kat();
    let pubk = &k["tc1_pub"][0];
    let msg = &k["tc1_msg"][0];
    let sig = &k["tc1_sig"][0];
    assert!(verify_hss(pubk, msg, sig), "TC1 HSS verify must accept");

    // Through the typed API.
    let hpk = HssPublicKey::from_bytes(pubk).unwrap();
    assert!(hpk.verify(msg, sig));

    // Tampered signature is rejected (flip a byte in the OTS region).
    let mut bad = sig.clone();
    bad[40] ^= 1;
    assert!(!verify_hss(pubk, msg, &bad), "tampered TC1 sig must reject");

    // Wrong message is rejected.
    let mut other = msg.clone();
    other[0] ^= 1;
    assert!(!verify_hss(pubk, &other, sig), "wrong msg must reject");
}

/// RFC 8554 Test Case 2 (two-level HSS, H10/W4 over H5/W8): verify accepts.
#[test]
fn rfc8554_tc2_verify() {
    let k = kat();
    let pubk = &k["tc2_pub"][0];
    let msg = &k["tc2_msg"][0];
    let sig = &k["tc2_sig"][0];
    assert!(verify_hss(pubk, msg, sig), "TC2 HSS verify must accept");

    let mut bad = sig.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert!(!verify_hss(pubk, msg, &bad), "tampered TC2 sig must reject");

    let mut other = msg.clone();
    other[0] ^= 1;
    assert!(!verify_hss(pubk, &other, sig), "wrong msg must reject");
}

/// `verify_hss` bounds the raw level count to RFC 8554's `1 <= L <= 8`, like
/// `HssPublicKey::from_bytes` does, even when fed raw out-of-range bytes.
#[test]
fn verify_hss_rejects_out_of_range_levels() {
    let k = kat();
    let msg = &k["tc1_msg"][0];
    let sig = &k["tc1_sig"][0];
    for levels in [0u32, 9, u32::MAX] {
        let mut pubk = k["tc1_pub"][0].clone();
        pubk[..4].copy_from_slice(&levels.to_be_bytes());
        let mut s = sig.clone();
        s[..4].copy_from_slice(&levels.wrapping_sub(1).to_be_bytes());
        assert!(!verify_hss(&pubk, msg, &s), "L = {levels} must reject");
    }
}

/// Extracts the LM-OTS randomizer `C` (the n bytes right after the 4-byte type)
/// from the LMS signature that starts at `off` in an HSS signature.
fn extract_c(sig: &[u8], off: usize) -> [u8; N] {
    // LMS sig: u32(q) || u32(ots_type) || C(n) || ...
    let mut c = [0u8; N];
    c.copy_from_slice(&sig[off + 8..off + 8 + N]);
    c
}

/// Returns the byte length of the LMS signature prefixing `buf` (mirrors the
/// production helper, but in the test module for locating field offsets).
fn lms_len(buf: &[u8]) -> usize {
    super::lms_sig_len(buf).unwrap()
}

/// RFC 8554 Test Case 2 signing: with the vector's seeds and the leaf indices
/// and randomizers `C` pinned from the published signature, `sign` reproduces
/// the exact signature bytes.
#[test]
fn rfc8554_tc2_sign_reproduces() {
    let k = kat();
    let pubk = &k["tc2_pub"][0];
    let msg = &k["tc2_msg"][0];
    let sig = &k["tc2_sig"][0];
    let priv_fields = &k["tc2_priv"];
    let top_seed = &priv_fields[0];
    let top_i = &priv_fields[1];
    let l2_seed = &priv_fields[2];
    let l2_i = &priv_fields[3];

    let mut ti = [0u8; 16];
    ti.copy_from_slice(top_i);
    let mut ts = [0u8; N];
    ts.copy_from_slice(top_seed);
    let mut li = [0u8; 16];
    li.copy_from_slice(l2_i);
    let mut ls = [0u8; N];
    ls.copy_from_slice(l2_seed);

    let mut key = HssPrivateKey::from_levels(&[
        (LmsType::Sha256M32H10, LmotsType::Sha256N32W4, ti, ts),
        (LmsType::Sha256M32H5, LmotsType::Sha256N32W8, li, ls),
    ])
    .unwrap();

    // The generated public key must match the vector.
    assert_eq!(key.public_key().to_bytes(), &pubk[..], "TC2 public key");

    // Locate the two per-level C values and leaf indices q in the vector.
    // HSS sig layout: u32(Nspk) || sig[0] || pub[1] || sig[1].
    let sig0_off = 4;
    let q0 = u32::from_be_bytes([
        sig[sig0_off],
        sig[sig0_off + 1],
        sig[sig0_off + 2],
        sig[sig0_off + 3],
    ]);
    let c0 = extract_c(sig, sig0_off);
    let sig0_len = lms_len(&sig[sig0_off..]);
    let pub1_off = sig0_off + sig0_len;
    let sig1_off = pub1_off + 24 + N;
    let q1 = u32::from_be_bytes([
        sig[sig1_off],
        sig[sig1_off + 1],
        sig[sig1_off + 2],
        sig[sig1_off + 3],
    ]);
    let c1 = extract_c(sig, sig1_off);

    // Re-sign the child tree with the vector's top leaf and randomizer, then
    // park the bottom level on the vector's leaf.
    key.set_q(0, q0);
    key.resign_child_with_c(0, &c0);
    key.set_q(1, q1);

    let produced = key.sign_with_c(msg, &c1).unwrap();
    assert_eq!(
        produced,
        sig[..],
        "TC2 sign must reproduce the RFC signature"
    );
    assert!(verify_hss(pubk, msg, &produced));
    assert_eq!(produced.len(), key.signature_len());
}

/// Single-tree LMS roundtrip + reject (uses the L=1 path internally via tree).
#[test]
fn lms_roundtrip_and_reject() {
    let mut rng = HmacDrbg::<Sha256>::new(b"lms-roundtrip", b"nonce", &[]);
    let mut sk = LmsPrivateKey::generate(LmsType::Sha256M32H5, LmotsType::Sha256N32W8, &mut rng);
    let pk = sk.public_key();
    let sig = sk.sign(&mut rng, b"purecrypto lms").unwrap();
    assert!(pk.verify(b"purecrypto lms", &sig));
    assert!(verify_lms(pk.to_bytes(), b"purecrypto lms", &sig));
    assert!(!pk.verify(b"other message", &sig));

    let mut bad = sig.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(!pk.verify(b"purecrypto lms", &bad));
}

/// Two consecutive signs consume distinct leaf indices `q`.
#[test]
fn lms_distinct_q() {
    let mut rng = HmacDrbg::<Sha256>::new(b"lms-q", b"n", &[]);
    let mut sk = LmsPrivateKey::generate(LmsType::Sha256M32H5, LmotsType::Sha256N32W8, &mut rng);
    let pk = sk.public_key();
    assert_eq!(sk.remaining(), 32);
    let s0 = sk.sign(&mut rng, b"m0").unwrap();
    assert_eq!(sk.remaining(), 31);
    let s1 = sk.sign(&mut rng, b"m1").unwrap();
    assert_eq!(sk.remaining(), 30);
    // q is the first 4 bytes of the LMS signature.
    let q0 = u32::from_be_bytes([s0[0], s0[1], s0[2], s0[3]]);
    let q1 = u32::from_be_bytes([s1[0], s1[1], s1[2], s1[3]]);
    assert_eq!(q0, 0);
    assert_eq!(q1, 1);
    assert!(pk.verify(b"m0", &s0));
    assert!(pk.verify(b"m1", &s1));
}

/// Reload from serialized bytes resumes at the persisted `q`.
#[test]
fn lms_reload_resumes_q() {
    let mut rng = HmacDrbg::<Sha256>::new(b"lms-reload", b"n", &[]);
    let mut sk = LmsPrivateKey::generate(LmsType::Sha256M32H5, LmotsType::Sha256N32W8, &mut rng);
    let _ = sk.sign(&mut rng, b"a").unwrap();
    let _ = sk.sign(&mut rng, b"b").unwrap();
    let bytes = sk.to_bytes();
    assert_eq!(bytes.len(), 92, "new root-bearing private-key length");

    let mut reloaded = LmsPrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(reloaded.remaining(), 30);
    let s = reloaded.sign(&mut rng, b"c").unwrap();
    let q = u32::from_be_bytes([s[0], s[1], s[2], s[3]]);
    assert_eq!(q, 2, "reload must resume at persisted q");
}

/// Exhausting an LMS tree errors rather than reusing `q`.
#[test]
fn lms_exhaustion_errors() {
    // Use the smallest tree (H5 = 32 leaves) but fast-forward q via reload.
    let mut rng = HmacDrbg::<Sha256>::new(b"lms-exhaust", b"n", &[]);
    let sk = LmsPrivateKey::generate(LmsType::Sha256M32H5, LmotsType::Sha256N32W8, &mut rng);
    let mut bytes = sk.to_bytes();
    // Set q = 32 (= leaves), the exhausted state. Layout is
    // type(4) type(4) I(16) seed(32) q(4) root(32), so q precedes the root.
    let qoff = 4 + 4 + 16 + N;
    bytes[qoff..qoff + 4].copy_from_slice(&32u32.to_be_bytes());
    let mut exhausted = LmsPrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(exhausted.remaining(), 0);
    assert_eq!(exhausted.sign(&mut rng, b"x"), Err(Error::Exhausted));
}

/// Every leaf of a tree signs from the node cache and verifies, including
/// after a reload (which rebuilds the cache lazily) part-way through.
#[test]
fn lms_every_leaf_signs_from_cache() {
    let mut rng = HmacDrbg::<Sha256>::new(b"lms-all-leaves", b"n", &[]);
    let mut sk = LmsPrivateKey::generate(LmsType::Sha256M32H5, LmotsType::Sha256N32W2, &mut rng);
    let pk = sk.public_key();
    for q in 0..16u32 {
        let s = sk.sign(&mut rng, b"leaf").unwrap();
        assert_eq!(u32::from_be_bytes([s[0], s[1], s[2], s[3]]), q);
        assert!(pk.verify(b"leaf", &s), "leaf {q}");
    }
    let mut sk = LmsPrivateKey::from_bytes(&sk.to_bytes()).unwrap();
    for q in 16..32u32 {
        let s = sk.sign(&mut rng, b"leaf").unwrap();
        assert_eq!(u32::from_be_bytes([s[0], s[1], s[2], s[3]]), q);
        assert!(pk.verify(b"leaf", &s), "leaf {q} after reload");
    }
    assert_eq!(sk.sign(&mut rng, b"leaf"), Err(Error::Exhausted));
}

/// A reloaded key whose stored root was corrupted fails closed on its first
/// signature — the rebuilt cache disagrees with the root — without consuming
/// a leaf, and keeps failing the same way.
#[test]
fn lms_reload_refuses_corrupted_root_without_burning_a_leaf() {
    let mut rng = HmacDrbg::<Sha256>::new(b"lms-bad-root", b"n", &[]);
    let sk = LmsPrivateKey::generate(LmsType::Sha256M32H5, LmotsType::Sha256N32W8, &mut rng);
    let mut bytes = sk.to_bytes();
    bytes[28 + N + 3] ^= 0x40; // inside the appended root
    let mut bad = LmsPrivateKey::from_bytes(&bytes).expect("root is trusted at load");
    assert_eq!(bad.remaining(), 32);
    assert_eq!(bad.sign(&mut rng, b"m"), Err(Error::Tampered));
    assert_eq!(bad.remaining(), 32, "no leaf may be consumed");
    assert_eq!(bad.sign(&mut rng, b"m"), Err(Error::Tampered));
    let mut sig = alloc::vec![0u8; bad.signature_len()];
    assert_eq!(
        bad.sign_into(&mut rng, b"m", &mut sig),
        Err(Error::Tampered)
    );
}

// ===================================================================
// HSS
// ===================================================================

/// Two-level `H5/W1` over `H5/W1`: the cheapest configuration whose bottom
/// tree can be exhausted (and regenerated) many times inside a debug test.
fn small_hss(tag: &[u8]) -> (HssPrivateKey, HmacDrbg<Sha256>) {
    let mut rng = HmacDrbg::<Sha256>::new(tag, b"n", &[]);
    let sk = HssPrivateKey::generate(
        &[
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W1),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W1),
        ],
        &mut rng,
    )
    .unwrap();
    (sk, rng)
}

/// Returns `(q of sig[0], I of pub[1], q of sig[1])` from a two-level HSS
/// signature `u32(Nspk) || sig[0] || pub[1] || sig[1]`.
fn two_level_leaves(sig: &[u8]) -> (u32, [u8; 16], u32) {
    let sig0_off = 4;
    let q0 = u32::from_be_bytes(sig[sig0_off..sig0_off + 4].try_into().unwrap());
    let pub1_off = sig0_off + lms_len(&sig[sig0_off..]);
    let mut i1 = [0u8; 16];
    i1.copy_from_slice(&sig[pub1_off + 8..pub1_off + 24]);
    let sig1_off = pub1_off + 24 + N;
    let q1 = u32::from_be_bytes(sig[sig1_off..sig1_off + 4].try_into().unwrap());
    (q0, i1, q1)
}

/// Returns the bottom-level LMS signature's leaf index `q` from a two-level
/// HSS signature.
fn bottom_leaf_q(sig: &[u8]) -> u32 {
    two_level_leaves(sig).2
}

/// Byte length of the upper-level part (`sig[0] || pub[1]`) of a two-level
/// HSS signature, i.e. everything before the bottom LMS signature.
fn upper_end(sig: &[u8]) -> usize {
    4 + lms_len(&sig[4..]) + 24 + N
}

/// HSS roundtrip, reload, and per-signature state advance.
#[test]
fn hss_roundtrip_and_reload() {
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-roundtrip", b"n", &[]);
    let mut sk = HssPrivateKey::generate(
        &[
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
        ],
        &mut rng,
    )
    .unwrap();
    let pk = sk.public_key();
    assert_eq!(pk.to_bytes().len(), 60);
    // Full RFC 8554 capacity: 32 bottom trees of 32 leaves each.
    assert_eq!(sk.remaining(), 32 * 32);

    let s0 = sk.sign(&mut rng, b"hss-0").unwrap();
    assert_eq!(s0.len(), sk.signature_len());
    assert!(pk.verify(b"hss-0", &s0));
    assert!(!pk.verify(b"hss-x", &s0));
    assert_eq!(sk.remaining(), 32 * 32 - 1);

    // Serialize, reload, continue: distinct signatures, both verify.
    let bytes = sk.to_bytes();
    let mut reloaded = HssPrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(reloaded.remaining(), 32 * 32 - 1);
    let s1 = reloaded.sign(&mut rng, b"hss-1").unwrap();
    assert!(pk.verify(b"hss-1", &s1));
    assert_ne!(s0, s1);
    assert_eq!(bottom_leaf_q(&s1), 1);
}

/// HSS L=1 is the degenerate single-tree case and still verifies.
#[test]
fn hss_single_level() {
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-l1", b"n", &[]);
    let mut sk =
        HssPrivateKey::generate(&[(LmsType::Sha256M32H5, LmotsType::Sha256N32W8)], &mut rng)
            .unwrap();
    let pk = sk.public_key();
    assert_eq!(sk.remaining(), 32);
    let sig = sk.sign(&mut rng, b"single").unwrap();
    // Nspk must be 0 for L=1.
    assert_eq!(&sig[..4], &[0, 0, 0, 0]);
    assert_eq!(sig.len(), sk.signature_len());
    assert!(pk.verify(b"single", &sig));
}

/// `signature_len` matches the emitted length for mixed parameter sets.
#[test]
fn hss_signature_len_matches_emitted() {
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-siglen", b"n", &[]);
    let mut sk = HssPrivateKey::generate(
        &[
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W4),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W1),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
        ],
        &mut rng,
    )
    .unwrap();
    let expected = 4
        + signature_len(LmsType::Sha256M32H5, LmotsType::Sha256N32W4)
        + PUBKEY_LEN
        + signature_len(LmsType::Sha256M32H5, LmotsType::Sha256N32W1)
        + PUBKEY_LEN
        + signature_len(LmsType::Sha256M32H5, LmotsType::Sha256N32W8);
    assert_eq!(sk.signature_len(), expected);
    let sig = sk.sign(&mut rng, b"len").unwrap();
    assert_eq!(sig.len(), expected);
    assert!(sk.public_key().verify(b"len", &sig));
}

/// SECURITY REGRESSION (RFC 8554 / SP 800-208 LM-OTS reuse) — now over the
/// *full* RFC 8554 capacity.
///
/// A two-level key issues exactly `2^h_top * 2^h_bottom` signatures. Every
/// one must use a distinct bottom one-time key `(I_bottom, q_bottom)`, every
/// bottom tree must be signed by a distinct top leaf, and the key must then
/// fail closed with `Error::Exhausted` rather than wrap.
#[test]
fn hss_full_capacity_never_reuses_a_one_time_key() {
    use alloc::collections::BTreeSet;
    let (mut key, mut rng) = small_hss(b"hss-no-reuse");
    let pk = key.public_key();
    assert_eq!(key.remaining(), 1024);

    let mut bottom_keys: BTreeSet<([u8; 16], u32)> = BTreeSet::new();
    let mut top_leaves: BTreeSet<u32> = BTreeSet::new();
    let mut tree_of_top_leaf: alloc::collections::BTreeMap<u32, [u8; 16]> = Default::default();
    let mut count = 0u32;
    loop {
        let msg = alloc::format!("msg-{count}");
        match key.sign(&mut rng, msg.as_bytes()) {
            Ok(sig) => {
                assert!(pk.verify(msg.as_bytes(), &sig), "signature {count}");
                let (q0, i1, q1) = two_level_leaves(&sig);
                assert!(
                    bottom_keys.insert((i1, q1)),
                    "bottom one-time key ({i1:02x?}, {q1}) re-used at signature {count}"
                );
                // A top leaf signs exactly one bottom tree.
                let prev = tree_of_top_leaf.insert(q0, i1);
                assert!(
                    prev.is_none_or(|p| p == i1),
                    "top leaf {q0} signed two trees"
                );
                top_leaves.insert(q0);
                assert_eq!(q0, count / 32, "top leaf advances every 32 signatures");
                assert_eq!(q1, count % 32);
                assert_eq!(key.remaining(), 1023 - count as u64);
                count += 1;
            }
            Err(Error::Exhausted) => break,
            Err(e) => panic!("unexpected error {e:?}"),
        }
    }
    assert_eq!(
        count, 1024,
        "must issue exactly 2^h_top * 2^h_bottom signatures"
    );
    assert_eq!(bottom_keys.len(), 1024);
    assert_eq!(top_leaves.len(), 32, "all 32 top leaves used exactly once");
    assert_eq!(key.remaining(), 0);
    assert_eq!(key.sign(&mut rng, b"after").err(), Some(Error::Exhausted));
    // Serialized exhausted state reloads as exhausted.
    let mut reloaded = HssPrivateKey::from_bytes(&key.to_bytes()).unwrap();
    assert_eq!(reloaded.remaining(), 0);
    assert_eq!(
        reloaded.sign(&mut rng, b"after").err(),
        Some(Error::Exhausted)
    );
}

/// Exhausting the bottom tree replaces it (RFC 8554 §6.2): the next signature
/// carries a new bottom public key signed by the next top leaf, and the new
/// tree's `I` is the deterministic child derivation from that leaf.
#[test]
fn hss_bottom_rollover_regenerates_the_bottom_tree() {
    let (mut key, mut rng) = small_hss(b"hss-rollover");
    let pk = key.public_key();
    let mut last = Vec::new();
    for _ in 0..32 {
        last = key.sign(&mut rng, b"m").unwrap();
    }
    let (q0, i_first, q1) = two_level_leaves(&last);
    assert_eq!((q0, q1), (0, 31));
    assert_eq!(key.remaining(), 1024 - 32);

    let s = key.sign(&mut rng, b"after-rollover").unwrap();
    assert!(pk.verify(b"after-rollover", &s));
    let (q0, i_second, q1) = two_level_leaves(&s);
    assert_eq!(
        (q0, q1),
        (1, 0),
        "second top leaf signs a fresh bottom tree"
    );
    assert_ne!(i_first, i_second, "the replacement tree has a fresh I");
    assert_eq!(
        i_second,
        ots::derive_child(&key.levels[0].i_id, &key.levels[0].seed, 1).0,
        "child I must follow the reference derivation from the parent leaf"
    );
    assert_eq!(key.remaining(), 1024 - 33);
    // The reserved-first discipline: the serialized top q is already 2.
    let reloaded = HssPrivateKey::from_bytes(&key.to_bytes()).unwrap();
    assert_eq!(reloaded.levels[0].q, 2);
    assert_eq!(reloaded.levels[1].q, 1);
}

/// Three levels: exhausting the middle tree replaces it from the top level,
/// which then replaces the bottom tree in turn.
#[test]
fn hss_three_levels_regenerate_middle_tree() {
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-l3", b"n", &[]);
    let mut key = HssPrivateKey::generate(
        &[
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W1),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W1),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W1),
        ],
        &mut rng,
    )
    .unwrap();
    let pk = key.public_key();
    assert_eq!(key.remaining(), 32 * 32 * 32);
    assert_eq!(key.levels[0].q, 1);
    assert_eq!(key.levels[1].q, 1);
    assert_eq!(key.levels[2].q, 0);

    let mut last = Vec::new();
    for i in 0..1025u32 {
        last = key.sign(&mut rng, b"m").unwrap();
        if i % 97 == 0 {
            assert!(pk.verify(b"m", &last), "signature {i}");
        }
    }
    assert!(pk.verify(b"m", &last));
    // Signature 1024 is the first of the second middle tree.
    let sig0_len = lms_len(&last[4..]);
    let sig1_off = 4 + sig0_len + PUBKEY_LEN;
    let sig2_off = sig1_off + lms_len(&last[sig1_off..]) + PUBKEY_LEN;
    let q = |off: usize| u32::from_be_bytes(last[off..off + 4].try_into().unwrap());
    assert_eq!((q(4), q(sig1_off), q(sig2_off)), (1, 0, 0));
    assert_eq!(key.levels[0].q, 2);
    assert_eq!(key.levels[1].q, 1);
    assert_eq!(key.levels[2].q, 1);
    assert_eq!(key.remaining(), 32 * 32 * 32 - 1025);
    // Reload and keep going.
    let mut reloaded = HssPrivateKey::from_bytes(&key.to_bytes()).unwrap();
    assert_eq!(reloaded.remaining(), 32 * 32 * 32 - 1025);
    let s = reloaded.sign(&mut rng, b"again").unwrap();
    assert!(pk.verify(b"again", &s));
}

/// The upper-level signature is produced once per child tree and cached: it
/// is byte-identical across calls and across a serialize/reload cycle, so a
/// non-bottom one-time key is never exposed under two randomizers.
#[test]
fn hss_upper_level_signature_is_cached() {
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-upper-det", b"n", &[]);
    let mut key = HssPrivateKey::generate(
        &[
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
        ],
        &mut rng,
    )
    .unwrap();
    let pk = key.public_key();

    let s0 = key.sign(&mut rng, b"det-0").unwrap();
    let s1 = key.sign(&mut rng, b"det-1").unwrap();
    assert!(pk.verify(b"det-0", &s0));
    assert!(pk.verify(b"det-1", &s1));

    let end = upper_end(&s0);
    assert_eq!(
        s0[..end],
        s1[..end],
        "upper-level LM-OTS signature must be byte-identical across sign() calls"
    );

    let mut reloaded = HssPrivateKey::from_bytes(&key.to_bytes()).unwrap();
    let s2 = reloaded.sign(&mut rng, b"det-2").unwrap();
    assert!(pk.verify(b"det-2", &s2));
    assert_eq!(
        s0[..end],
        s2[..end],
        "upper-level signature must survive serialize/reload unchanged"
    );

    // The bottom-level signatures differ (distinct leaves and messages).
    assert_ne!(s0[end..], s1[end..]);
}

// -------------------------------------------------------------------
// Serialization: v3 round-trip, tamper detection, older-format mapping.
// -------------------------------------------------------------------

/// Each level's 92-byte block from a `v3` serialization, with every
/// non-bottom `q` reset to `0` — which is what every pre-`v3` format stored.
/// Only meaningful for a key whose upper levels are still on their initial
/// trees (signed with leaf `0`).
fn legacy_blocks(sk: &HssPrivateKey) -> Vec<Vec<u8>> {
    let v3 = sk.to_bytes();
    assert_eq!(&v3[..4], HSS_V3_MAGIC);
    let l = u32::from_be_bytes(v3[4..8].try_into().unwrap()) as usize;
    (0..l)
        .map(|i| {
            let off = 8 + i * HSS_LEVEL_LEN;
            let mut b = v3[off..off + HSS_LEVEL_LEN].to_vec();
            if i + 1 < l {
                b[56..60].copy_from_slice(&0u32.to_be_bytes());
            }
            b
        })
        .collect()
}

/// The untagged root-bearing `v1` form: `u32(L) || L * 92`.
fn v1_bytes(sk: &HssPrivateKey) -> Vec<u8> {
    let blocks = legacy_blocks(sk);
    let mut v = (blocks.len() as u32).to_be_bytes().to_vec();
    for b in &blocks {
        v.extend_from_slice(b);
    }
    v
}

/// The tagged `v2` form: `v1 || HMAC(seed0, "…-v2" || I0 || v1)`.
fn v2_bytes(sk: &HssPrivateKey) -> Vec<u8> {
    let mut v = v1_bytes(sk);
    let mut i0 = [0u8; 16];
    i0.copy_from_slice(&v[12..28]);
    let mut seed0 = [0u8; N];
    seed0.copy_from_slice(&v[28..28 + N]);
    let tag = hss_tag(HSS_TAG_DOMAIN_V2, &v, &i0, &seed0);
    v.extend_from_slice(&tag);
    v
}

/// The root-less legacy form: `u32(L) || L * 60`.
fn legacy_bytes(sk: &HssPrivateKey) -> Vec<u8> {
    let blocks = legacy_blocks(sk);
    let mut v = (blocks.len() as u32).to_be_bytes().to_vec();
    for b in &blocks {
        v.extend_from_slice(&b[..HSS_LEGACY_LEVEL_LEN]);
    }
    v
}

/// Recomputes the `v3` tag of a (possibly edited) serialization, so tests
/// can reach the checks behind the tag.
fn retag_v3(bytes: &mut [u8]) {
    let n = bytes.len();
    let (body, tag) = bytes.split_at_mut(n - HSS_TAG_LEN);
    let mut i0 = [0u8; 16];
    i0.copy_from_slice(&body[16..32]);
    let mut seed0 = [0u8; N];
    seed0.copy_from_slice(&body[32..32 + N]);
    tag.copy_from_slice(&hss_tag(HSS_TAG_DOMAIN_V3, body, &i0, &seed0));
}

/// `v3` round-trips: stored per-level state reproduces the public key, the
/// leaf indices and the cached upper signatures, so re-serializing a loaded
/// key yields the identical bytes and the loaded key signs verifiably.
#[test]
fn hss_v3_roundtrip() {
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-v3", b"n", &[]);
    let mut sk = HssPrivateKey::generate(
        &[
            (LmsType::Sha256M32H10, LmotsType::Sha256N32W4),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
        ],
        &mut rng,
    )
    .unwrap();
    let pk = sk.public_key();
    let _ = sk.sign(&mut rng, b"warmup").unwrap();

    let bytes = sk.to_bytes();
    assert_eq!(&bytes[..4], b"HSS3");
    assert_eq!(
        bytes.len(),
        8 + 2 * HSS_LEVEL_LEN
            + signature_len(LmsType::Sha256M32H10, LmotsType::Sha256N32W4)
            + HSS_TAG_LEN,
        "v3 = magic || L || level blocks || cached upper signature || tag"
    );
    let mut reloaded = HssPrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(reloaded.public_key().to_bytes(), pk.to_bytes());
    assert_eq!(reloaded.remaining(), sk.remaining());
    assert_eq!(reloaded.to_bytes(), bytes, "serialization is canonical");
    let s = reloaded.sign(&mut rng, b"after-reload").unwrap();
    assert!(pk.verify(b"after-reload", &s));
    assert_eq!(bottom_leaf_q(&s), 1);
}

/// A truncated or extended tag is rejected, and the tag itself is authenticated.
#[test]
fn hss_tag_must_verify() {
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-tag", b"n", &[]);
    let sk = HssPrivateKey::generate(&[(LmsType::Sha256M32H5, LmotsType::Sha256N32W8)], &mut rng)
        .unwrap();
    let good = sk.to_bytes();
    for i in [0usize, 7, 31] {
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - 32 + i] ^= 0x80;
        assert_eq!(
            HssPrivateKey::from_bytes(&bad).err(),
            Some(Error::Tampered),
            "a corrupted tag byte {i} must be refused"
        );
    }
    // Even a single-level key's top root is authenticated by the tag.
    let mut bad = good.clone();
    let root_off = 8 + 4 + 4 + 16 + N + 4;
    bad[root_off] ^= 0x01;
    assert_eq!(HssPrivateKey::from_bytes(&bad).err(), Some(Error::Tampered));
    // Length edits are caught before the tag is even checked.
    assert_eq!(
        HssPrivateKey::from_bytes(&good[..good.len() - 1]).err(),
        Some(Error::Malformed)
    );
    let mut longer = good.clone();
    longer.push(0);
    assert_eq!(
        HssPrivateKey::from_bytes(&longer).err(),
        Some(Error::Malformed)
    );
}

/// SECURITY REGRESSION (HSS key-file tampering).
///
/// Every byte of a `v3` file — level blocks and the cached upper signatures —
/// is covered by the tag, so any edit is refused. In the untagged `v1` form
/// the child level's stored root is recomputed from its seed, so an edited
/// child typecode / `I` / root is still refused.
#[test]
fn hss_from_bytes_rejects_tampered_child_level() {
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-tamper", b"n", &[]);
    let sk = HssPrivateKey::generate(
        &[
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
        ],
        &mut rng,
    )
    .unwrap();
    let good = sk.to_bytes();
    let sig0_len = signature_len(LmsType::Sha256M32H5, LmotsType::Sha256N32W8);
    assert_eq!(good.len(), 8 + 2 * HSS_LEVEL_LEN + sig0_len + HSS_TAG_LEN);
    assert!(HssPrivateKey::from_bytes(&good).is_ok());

    // (a) v3: every byte is authenticated.
    let child = 8 + HSS_LEVEL_LEN;
    let sig0 = 8 + 2 * HSS_LEVEL_LEN;
    for off in [
        4,                   // L
        8 + 3,               // top lms typecode
        8 + 56,              // top q
        child + 3,           // child lms typecode
        child + 7,           // child ots typecode
        child + 8,           // child I
        child + 24,          // child seed
        child + 56,          // child q
        child + 60,          // child root
        child + 92 - 1,      // child root (last byte)
        sig0,                // cached upper signature: q
        sig0 + 8,            // cached upper signature: C
        sig0 + sig0_len - 1, // cached upper signature: last path node
    ] {
        let mut t = good.clone();
        t[off] ^= 0x01;
        assert!(
            matches!(
                HssPrivateKey::from_bytes(&t),
                Err(Error::Tampered) | Err(Error::Malformed)
            ),
            "v3: flipping byte {off} must be refused"
        );
    }

    // (b) untagged v1: the seed-derived root recompute still catches a
    // changed child typecode / I / root.
    let v1 = v1_bytes(&sk);
    let child = 4 + HSS_LEVEL_LEN;
    for (what, off) in [
        ("lms typecode", child + 3),
        ("ots typecode", child + 7),
        ("I", child + 8),
        ("I (last byte)", child + 23),
        ("root", child + 60),
        ("root (last byte)", child + HSS_LEVEL_LEN - 1),
    ] {
        let mut t = v1.clone();
        t[off] ^= 0x01;
        assert!(
            matches!(
                HssPrivateKey::from_bytes(&t),
                Err(Error::Tampered) | Err(Error::Malformed)
            ),
            "untagged: flipping the child {what} must be refused"
        );
    }
    // ... and a corrupted TOP root is caught when the top tree is built to
    // sign the child (a tampered public value can only self-DoS).
    let mut t = v1.clone();
    t[4 + 60] ^= 0x01;
    assert_eq!(HssPrivateKey::from_bytes(&t).err(), Some(Error::Tampered));

    // The unmodified untagged form still loads (compatibility).
    let loaded = HssPrivateKey::from_bytes(&v1).expect("untagged v1 key must still load");
    assert_eq!(loaded.public_key().to_bytes(), sk.public_key().to_bytes());
}

/// Behind the tag, `v3` loading also verifies each cached upper signature
/// against the levels it links and requires its leaf to be already reserved:
/// a re-tagged file with a corrupted signature or a rewound parent index is
/// refused.
#[test]
fn hss_v3_rejects_bad_upper_signature_and_rewound_index() {
    let (sk, _) = small_hss(b"hss-v3-inner");
    let good = sk.to_bytes();
    assert!(HssPrivateKey::from_bytes(&good).is_ok());
    let sig0 = 8 + 2 * HSS_LEVEL_LEN;

    // Corrupt a path node of the cached upper signature, re-tag.
    let mut t = good.clone();
    t[sig0 + 40] ^= 0x01;
    retag_v3(&mut t);
    assert_eq!(HssPrivateKey::from_bytes(&t).err(), Some(Error::Tampered));

    // Rewind the top level's q to 0: the cached signature uses leaf 0, which
    // would then be "unused" and re-signed later.
    let mut t = good.clone();
    t[8 + 56..8 + 60].copy_from_slice(&0u32.to_be_bytes());
    retag_v3(&mut t);
    assert_eq!(HssPrivateKey::from_bytes(&t).err(), Some(Error::Tampered));

    // Swap the child level for one with a different seed (root recomputed
    // consistently): the parent's cached signature no longer matches.
    let mut t = good.clone();
    let other = LmsPrivateKey::from_seed(
        LmsType::Sha256M32H5,
        LmotsType::Sha256N32W1,
        &[0x99u8; 16],
        &[0x77u8; N],
    );
    let child = 8 + HSS_LEVEL_LEN;
    t[child..child + HSS_LEVEL_LEN].copy_from_slice(&other.to_bytes_array());
    retag_v3(&mut t);
    assert_eq!(HssPrivateKey::from_bytes(&t).err(), Some(Error::Tampered));

    // Re-tagging alone (no edit) still loads — the helper is sound.
    let mut t = good.clone();
    retag_v3(&mut t);
    assert!(HssPrivateKey::from_bytes(&t).is_ok());
}

/// A persisted pre-`v3` multi-level key with an advanced higher level is
/// rejected: those formats never produced one, so it can only be a
/// pre-mitigation (already-wrapped) key that would re-use one-time keys.
#[test]
fn hss_from_bytes_rejects_advanced_higher_level_in_legacy_formats() {
    let (sk, _) = small_hss(b"hss-reject");
    let mut v1 = v1_bytes(&sk);
    let top_q_off = 4 + 56;
    v1[top_q_off..top_q_off + 4].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(
        HssPrivateKey::from_bytes(&v1).err(),
        Some(Error::Malformed),
        "advanced higher-level q must be rejected as a reuse-prone state"
    );
}

/// Backward compatibility: `v2` (tagged), `v1` (untagged) and root-less
/// legacy files map onto the current structure — same public key, same
/// capacity, and the upper-level signature they implied (leaf `0`,
/// deterministic `C`) reproduced exactly, so the re-saved `v3` bytes equal
/// those of the key that was serialized.
#[test]
fn hss_older_formats_map_onto_current_structure() {
    let (mut sk, mut rng) = small_hss(b"hss-older-formats");
    let pk = sk.public_key();
    let v3 = sk.to_bytes();
    // The older forms describe the fresh key (bottom q = 0); capture them
    // before the reference signature consumes a leaf.
    let forms = [
        ("v2", v2_bytes(&sk)),
        ("v1", v1_bytes(&sk)),
        ("legacy", legacy_bytes(&sk)),
    ];
    let reference = sk.sign(&mut rng, b"ref").unwrap();
    let end = upper_end(&reference);

    for (name, bytes) in forms {
        let mut loaded =
            HssPrivateKey::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(loaded.public_key().to_bytes(), pk.to_bytes(), "{name}");
        assert_eq!(loaded.levels[0].q, 1, "{name}: child signed with leaf 0");
        assert_eq!(loaded.remaining(), 1024, "{name}");
        assert_eq!(
            loaded.to_bytes(),
            v3,
            "{name}: re-saved bytes are the v3 form"
        );
        let s = loaded.sign(&mut rng, b"mapped").unwrap();
        assert!(pk.verify(b"mapped", &s), "{name}");
        assert_eq!(
            s[..end],
            reference[..end],
            "{name}: identical upper signature"
        );
    }
    // A v2 file with a corrupted tag is refused before any tree is built.
    let mut bad = v2_bytes(&sk);
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert_eq!(HssPrivateKey::from_bytes(&bad).err(), Some(Error::Tampered));
}

/// Unauthenticated legacy formats refuse to derive a tree taller than H15;
/// authenticated / non-deriving loads accept any height instantly.
#[test]
fn hss_legacy_height_cap() {
    // Legacy root-less single-level H20 blob -> rejected without recompute.
    let mut legacy = Vec::new();
    legacy.extend_from_slice(&1u32.to_be_bytes()); // L = 1
    legacy.extend_from_slice(&LmsType::Sha256M32H20.typecode().to_be_bytes());
    legacy.extend_from_slice(&LmotsType::Sha256N32W8.typecode().to_be_bytes());
    legacy.extend_from_slice(&[0u8; 16]);
    legacy.extend_from_slice(&[0u8; N]);
    legacy.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(legacy.len(), 4 + 60);
    assert_eq!(
        HssPrivateKey::from_bytes(&legacy).err(),
        Some(Error::LegacyKeyTooTall),
        "legacy H20 level must be rejected, not recomputed"
    );

    // Same single-level H20 in the untagged root-bearing form loads
    // instantly: a bottom level's stored root is trusted until it signs.
    let mut v1 = legacy.clone();
    v1.extend_from_slice(&[0x7cu8; N]);
    assert_eq!(v1.len(), 4 + 92);
    let loaded = HssPrivateKey::from_bytes(&v1).expect("v1 H20 must load, no recompute");
    assert_eq!(loaded.levels(), 1);

    // An untagged two-level file whose TOP level is H20 would have to build
    // that tree to sign the child: refused without doing so.
    let mut two = Vec::new();
    two.extend_from_slice(&2u32.to_be_bytes());
    two.extend_from_slice(&v1[4..]); // H20 top block (q = 0, root)
    two.extend_from_slice(&LmsType::Sha256M32H5.typecode().to_be_bytes());
    two.extend_from_slice(&LmotsType::Sha256N32W8.typecode().to_be_bytes());
    two.extend_from_slice(&[1u8; 16]);
    two.extend_from_slice(&[2u8; N]);
    two.extend_from_slice(&0u32.to_be_bytes());
    two.extend_from_slice(&[3u8; N]);
    assert_eq!(two.len(), 4 + 2 * 92);
    assert_eq!(
        HssPrivateKey::from_bytes(&two).err(),
        Some(Error::LegacyKeyTooTall)
    );

    // A v3 file with an H25 top level loads with no derivation at all.
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-v3-tall", b"n", &[]);
    let small = HssPrivateKey::generate(
        &[
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
        ],
        &mut rng,
    )
    .unwrap();
    let mut tall = small.to_bytes();
    // Relabel the top level as H25 and pad its cached signature's path to 25
    // nodes; the tag is recomputed, the signature will not verify.
    tall[8..12].copy_from_slice(&LmsType::Sha256M32H25.typecode().to_be_bytes());
    let sig0 = 8 + 2 * HSS_LEVEL_LEN;
    let old_len = signature_len(LmsType::Sha256M32H5, LmotsType::Sha256N32W8);
    let mut sig = tall[sig0..sig0 + old_len].to_vec();
    let lms_type_off = 4 + LmotsType::Sha256N32W8.sig_len();
    sig[lms_type_off..lms_type_off + 4]
        .copy_from_slice(&LmsType::Sha256M32H25.typecode().to_be_bytes());
    sig.resize(
        signature_len(LmsType::Sha256M32H25, LmotsType::Sha256N32W8),
        0,
    );
    tall.splice(sig0..sig0 + old_len, sig);
    retag_v3(&mut tall);
    assert_eq!(
        HssPrivateKey::from_bytes(&tall).err(),
        Some(Error::Tampered),
        "the relabelled upper signature cannot verify — but nothing was derived"
    );
}

/// Wrong-length or wrongly-framed HSS blobs are rejected as `Malformed`.
#[test]
fn hss_from_bytes_rejects_bad_length() {
    // L=2 but neither 4+2*60 nor 4+2*92 bytes long.
    let mut blob = alloc::vec![0u8; 4 + 2 * 70];
    blob[..4].copy_from_slice(&2u32.to_be_bytes());
    assert_eq!(
        HssPrivateKey::from_bytes(&blob).err(),
        Some(Error::Malformed)
    );
    // v3 magic with a bad level count, or too short for its levels.
    for (l, len) in [
        (0u32, 8 + 92),
        (9, 8 + 92),
        (1, 8 + 92),
        (2, 8 + 2 * 92 + 32),
    ] {
        let mut blob = alloc::vec![0u8; len];
        blob[..4].copy_from_slice(HSS_V3_MAGIC);
        blob[4..8].copy_from_slice(&l.to_be_bytes());
        assert_eq!(
            HssPrivateKey::from_bytes(&blob).err(),
            Some(Error::Malformed),
            "v3 L={l} len={len}"
        );
    }
    assert_eq!(
        HssPrivateKey::from_bytes(b"HSS").err(),
        Some(Error::Malformed)
    );
    assert_eq!(
        HssPrivateKey::from_bytes(b"HSS3").err(),
        Some(Error::Malformed)
    );
}

/// The leaf index is reserved BEFORE the signature is produced (SP 800-208
/// §8.1). If signing aborts part-way — here the bottom level's randomizer RNG
/// panics — the state must still have moved past the leaf, so the next call
/// cannot re-sign it.
#[cfg(feature = "std")]
#[test]
fn hss_aborted_sign_still_burns_its_leaf() {
    struct PanicRng;
    impl crate::rng::RngCore for PanicRng {
        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            panic!("rng failure mid-sign");
        }
    }

    let mut rng = HmacDrbg::<Sha256>::new(b"hss-abort", b"n", &[]);
    let mut key = HssPrivateKey::generate(
        &[
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
        ],
        &mut rng,
    )
    .unwrap();
    let pk = key.public_key();
    assert_eq!(key.remaining(), 1024);

    // Silence the panic message for this deliberate unwind.
    let prev = std::panic::take_hook();
    std::panic::set_hook(alloc::boxed::Box::new(|_| {}));
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        key.sign(&mut PanicRng, b"aborted")
    }));
    std::panic::set_hook(prev);
    assert!(res.is_err(), "the panicking rng must unwind out of sign");

    // Leaf 0 was consumed by the aborted attempt; the next signature is on
    // leaf 1 and still verifies.
    assert_eq!(
        key.remaining(),
        1023,
        "aborted sign must have burnt its leaf"
    );
    let sig = key.sign(&mut rng, b"after-abort").unwrap();
    assert_eq!(bottom_leaf_q(&sig), 1, "leaf 0 must never be signed again");
    assert!(pk.verify(b"after-abort", &sig));
}

// ===================================================================
// Root-bearing LMS serialization: fast-load path, backward compat, height cap.
// ===================================================================

/// Builds the legacy 60-byte LMS serialization (no appended root) for a key,
/// by truncating off the 32-byte root the new `to_bytes` appends.
fn lms_legacy_bytes(sk: &LmsPrivateKey) -> Vec<u8> {
    let mut b = sk.to_bytes();
    assert_eq!(b.len(), 92);
    b.truncate(60);
    b
}

/// New-format LMS round-trips: same public key and resumes at the persisted q,
/// and the loaded key signs verifiably (the stored-root fast path is correct).
#[test]
fn lms_new_format_roundtrip() {
    let mut rng = HmacDrbg::<Sha256>::new(b"lms-newfmt", b"n", &[]);
    // H10 exercises a non-trivial (1024-leaf) tree on the stored-root path.
    let mut sk = LmsPrivateKey::generate(LmsType::Sha256M32H10, LmotsType::Sha256N32W4, &mut rng);
    let _ = sk.sign(&mut rng, b"warmup").unwrap();
    let pk = sk.public_key();

    let bytes = sk.to_bytes();
    assert_eq!(bytes.len(), 92);
    let mut reloaded = LmsPrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(
        reloaded.public_key().to_bytes(),
        pk.to_bytes(),
        "stored root must reproduce the public key"
    );
    assert_eq!(reloaded.remaining(), sk.remaining());
    let s = reloaded.sign(&mut rng, b"after-reload").unwrap();
    assert!(pk.verify(b"after-reload", &s));
    let q = u32::from_be_bytes([s[0], s[1], s[2], s[3]]);
    assert_eq!(q, 1, "must resume at persisted q");
}

/// Backward compatibility: a hand-truncated legacy 60-byte LMS blob still loads
/// (recomputing the root) and yields the correct public key.
#[test]
fn lms_legacy_60_byte_load() {
    let mut rng = HmacDrbg::<Sha256>::new(b"lms-legacy", b"n", &[]);
    let sk = LmsPrivateKey::generate(LmsType::Sha256M32H5, LmotsType::Sha256N32W8, &mut rng);
    let pk = sk.public_key();
    let legacy = lms_legacy_bytes(&sk);
    assert_eq!(legacy.len(), 60);
    let loaded = LmsPrivateKey::from_bytes(&legacy).unwrap();
    assert_eq!(
        loaded.public_key().to_bytes(),
        pk.to_bytes(),
        "legacy recompute path must reproduce the public key"
    );
}

/// The legacy recompute path rejects a tree taller than H15 (CPU-DoS guard),
/// while the new root-bearing format accepts any height (no recompute).
#[test]
fn lms_legacy_height_cap() {
    // Hand-build a legacy 60-byte H25 blob (typecode 9). The recompute path
    // must refuse it WITHOUT attempting the O(2^25) keygen.
    let mut legacy = Vec::with_capacity(60);
    legacy.extend_from_slice(&LmsType::Sha256M32H25.typecode().to_be_bytes());
    legacy.extend_from_slice(&LmotsType::Sha256N32W8.typecode().to_be_bytes());
    legacy.extend_from_slice(&[0u8; 16]); // I
    legacy.extend_from_slice(&[0u8; N]); // seed
    legacy.extend_from_slice(&0u32.to_be_bytes()); // q
    assert_eq!(legacy.len(), 60);
    assert_eq!(
        LmsPrivateKey::from_bytes(&legacy).err(),
        Some(Error::LegacyKeyTooTall),
        "legacy H25 must be rejected, not recomputed"
    );

    // The same H25 typecode in the NEW 92-byte format loads instantly: the
    // appended root is trusted (arbitrary 32 bytes here), no recompute.
    let mut new = legacy.clone();
    new.extend_from_slice(&[0x5au8; N]); // arbitrary trusted root
    assert_eq!(new.len(), 92);
    let loaded =
        LmsPrivateKey::from_bytes(&new).expect("new-format H25 must load with no recompute");
    assert_eq!(loaded.lms_type(), LmsType::Sha256M32H25);
    // The trusted root flows straight into the public key.
    assert_eq!(&loaded.public_key().to_bytes()[24..24 + N], &[0x5au8; N]);
}

/// A non-trivial (H10, 1024-leaf) legacy blob loads via the recompute path and
/// reproduces the public key. (The H15 cap boundary itself is covered by
/// `lms_legacy_height_cap`; an actual H15+ keygen is too slow for `debug` CI.)
#[test]
fn lms_legacy_multilevel_recompute_load() {
    let mut rng = HmacDrbg::<Sha256>::new(b"lms-h10-legacy", b"n", &[]);
    let sk = LmsPrivateKey::generate(LmsType::Sha256M32H10, LmotsType::Sha256N32W4, &mut rng);
    let pk = sk.public_key();
    let legacy = lms_legacy_bytes(&sk);
    let loaded = LmsPrivateKey::from_bytes(&legacy).expect("H10 legacy blob must load");
    assert_eq!(loaded.public_key().to_bytes(), pk.to_bytes());
}

/// Wrong-length LMS blobs are rejected as `Malformed` (not 60 or 92).
#[test]
fn lms_from_bytes_rejects_bad_length() {
    for len in [0usize, 59, 61, 91, 93, 120] {
        let blob = alloc::vec![0u8; len];
        assert_eq!(
            LmsPrivateKey::from_bytes(&blob).err(),
            Some(Error::Malformed)
        );
    }
}

/// Same reservation order for a single-tree key: `q` moves before `tree::sign`
/// runs, and the emitted signature carries the reserved (pre-advance) leaf.
#[test]
fn lms_signature_carries_reserved_leaf() {
    let mut rng = HmacDrbg::<Sha256>::new(b"lms-reserve", b"n", &[]);
    let mut sk = LmsPrivateKey::generate(LmsType::Sha256M32H5, LmotsType::Sha256N32W8, &mut rng);
    let pk = sk.public_key();
    for expected_q in 0..3u32 {
        let sig = sk.sign(&mut rng, b"m").unwrap();
        let q = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]);
        assert_eq!(q, expected_q);
        assert_eq!(sk.remaining(), 32 - u64::from(expected_q) - 1);
        assert!(pk.verify(b"m", &sig));
    }
}

/// Verification binds both typecodes of the signature to the public key's and
/// rejects any length that does not match them (RFC 8554 §5.4.2 / §4.6 step 2).
#[test]
fn lms_verify_rejects_typecode_mismatch_and_wrong_length() {
    let mut rng = HmacDrbg::<Sha256>::new(b"lms-typecode", b"n", &[]);
    let mut sk = LmsPrivateKey::generate(LmsType::Sha256M32H5, LmotsType::Sha256N32W4, &mut rng);
    let pk = sk.public_key();
    let sig = sk.sign(&mut rng, b"typed").unwrap();
    assert!(pk.verify(b"typed", &sig));
    let ots_len = LmotsType::Sha256N32W4.sig_len();

    // LM-OTS typecode in the signature != the key's (W4 -> W8 / W2 / unknown).
    for bad_ots in [4u32, 2, 0, 5, u32::MAX] {
        let mut s = sig.clone();
        s[4..8].copy_from_slice(&bad_ots.to_be_bytes());
        assert!(
            !pk.verify(b"typed", &s),
            "ots typecode {bad_ots} must reject"
        );
    }
    // LMS typecode in the signature != the key's (H5 -> H10 / unknown).
    let lms_off = 4 + ots_len;
    for bad_lms in [6u32, 0, 4, 10, u32::MAX] {
        let mut s = sig.clone();
        s[lms_off..lms_off + 4].copy_from_slice(&bad_lms.to_be_bytes());
        assert!(
            !pk.verify(b"typed", &s),
            "lms typecode {bad_lms} must reject"
        );
    }
    // Any length other than the exact one is rejected — including a valid
    // signature with a trailing byte, and one truncated by a single byte.
    assert!(!pk.verify(b"typed", &sig[..sig.len() - 1]));
    let mut longer = sig.clone();
    longer.push(0);
    assert!(!pk.verify(b"typed", &longer));
    assert!(!pk.verify(b"typed", &[]));
    assert!(!pk.verify(b"typed", &sig[..7]));
    // Leaf index >= 2^h is rejected even if everything else parses.
    let mut s = sig.clone();
    s[..4].copy_from_slice(&32u32.to_be_bytes());
    assert!(!pk.verify(b"typed", &s), "q = 2^h must reject");

    // A public key with a mismatching pair (W8 instead of W4) rejects too.
    let mut pk_bytes = pk.to_bytes().to_vec();
    pk_bytes[4..8].copy_from_slice(&4u32.to_be_bytes());
    assert!(!verify_lms(&pk_bytes, b"typed", &sig));
    // ... and an unknown typecode in the key is refused at parse time.
    pk_bytes[4..8].copy_from_slice(&9u32.to_be_bytes());
    assert_eq!(
        LmsPublicKey::from_bytes(&pk_bytes).err(),
        Some(Error::InvalidKey)
    );
    assert!(!verify_lms(&pk_bytes, b"typed", &sig));
}

/// Sign/verify round-trip for every LM-OTS width. The RFC 8554 vectors only
/// pin `W4` and `W8`; this keeps `coef` / `Cksm` (`w = 1, 2`) consistent
/// between the signer and the verifier, and checks each is length-exact.
#[test]
fn lms_all_ots_widths_roundtrip() {
    let mut rng = HmacDrbg::<Sha256>::new(b"lms-widths", b"n", &[]);
    for ots in [
        LmotsType::Sha256N32W1,
        LmotsType::Sha256N32W2,
        LmotsType::Sha256N32W4,
        LmotsType::Sha256N32W8,
    ] {
        let mut sk = LmsPrivateKey::generate(LmsType::Sha256M32H5, ots, &mut rng);
        let pk = sk.public_key();
        let sig = sk.sign(&mut rng, b"width").unwrap();
        assert_eq!(sig.len(), signature_len(LmsType::Sha256M32H5, ots));
        assert!(pk.verify(b"width", &sig), "{ots:?}");
        assert!(!pk.verify(b"other", &sig), "{ots:?}");
        // Corrupt one Winternitz chain element: the recovered public key changes.
        let mut bad = sig.clone();
        bad[4 + 4 + N + 5] ^= 1;
        assert!(!pk.verify(b"width", &bad), "{ots:?}");
    }
}
