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

    // Advance each level's q to the vector's values.
    key.q[0] = q0;
    key.q[1] = q1;

    let produced = key.sign_with_cs(msg, &[c0, c1]).unwrap();
    assert_eq!(
        produced,
        sig[..],
        "TC2 sign must reproduce the RFC signature"
    );
    assert!(verify_hss(pubk, msg, &produced));
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
    assert_eq!(bytes.len(), 60);

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
    // Set q = 32 (= leaves), the exhausted state.
    let qoff = bytes.len() - 4;
    bytes[qoff..].copy_from_slice(&32u32.to_be_bytes());
    let mut exhausted = LmsPrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(exhausted.remaining(), 0);
    assert_eq!(exhausted.sign(&mut rng, b"x"), Err(Error::Exhausted));
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
    // Capacity is one bottom tree (32) under the fail-closed mitigation, not
    // 32*32 — advancing higher levels would re-use the fixed bottom OTS keys.
    assert_eq!(sk.remaining(), 32);

    let s0 = sk.sign(&mut rng, b"hss-0").unwrap();
    assert!(pk.verify(b"hss-0", &s0));
    assert!(!pk.verify(b"hss-x", &s0));
    assert_eq!(sk.remaining(), 32 - 1);

    // Serialize, reload, continue: distinct signatures, both verify.
    let bytes = sk.to_bytes();
    let mut reloaded = HssPrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(reloaded.remaining(), 32 - 1);
    let s1 = reloaded.sign(&mut rng, b"hss-1").unwrap();
    assert!(pk.verify(b"hss-1", &s1));
    assert_ne!(s0, s1);
}

/// HSS L=1 is the degenerate single-tree case and still verifies.
#[test]
fn hss_single_level() {
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-l1", b"n", &[]);
    let mut sk =
        HssPrivateKey::generate(&[(LmsType::Sha256M32H5, LmotsType::Sha256N32W8)], &mut rng)
            .unwrap();
    let pk = sk.public_key();
    let sig = sk.sign(&mut rng, b"single").unwrap();
    // Nspk must be 0 for L=1.
    assert_eq!(&sig[..4], &[0, 0, 0, 0]);
    assert!(pk.verify(b"single", &sig));
}

/// Returns the bottom-level LMS signature's leaf index `q` from an HSS sig.
/// HSS sig layout: `u32(Nspk) || sig[0] || pub[1] || sig[1]`; `sig[1]` is the
/// bottom level for a two-level key.
fn bottom_leaf_q(sig: &[u8]) -> u32 {
    let sig0_off = 4;
    let sig0_len = lms_len(&sig[sig0_off..]);
    let sig1_off = sig0_off + sig0_len + 24 + N;
    u32::from_be_bytes([
        sig[sig1_off],
        sig[sig1_off + 1],
        sig[sig1_off + 2],
        sig[sig1_off + 3],
    ])
}

/// SECURITY REGRESSION (RFC 8554 / SP 800-208 LM-OTS reuse).
///
/// A two-level HSS key keeps a *fixed* `(I, seed)` per level. Before the
/// fail-closed mitigation, exhausting the bottom tree reset its leaf index to 0
/// while the parent advanced, re-using the bottom tree's one-time keys to sign a
/// second, different message (catastrophic forgery vector). This test asserts
/// the key now refuses to wrap: it issues exactly `2^h_bottom` signatures, each
/// on a *distinct* bottom leaf, and then fails closed with `Error::Exhausted`.
/// No `(I, seed, leaf)` LM-OTS key is ever reused.
#[test]
fn hss_no_ots_reuse_fails_closed() {
    use alloc::collections::BTreeSet;
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-no-reuse", b"n", &[]);
    let mut key = HssPrivateKey::generate(
        &[
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
        ],
        &mut rng,
    )
    .unwrap();
    let pk = key.public_key();

    // Capacity is exactly one bottom tree (32 leaves), not 32*32.
    assert_eq!(key.remaining(), 32);

    let mut seen_bottom: BTreeSet<u32> = BTreeSet::new();
    let mut count = 0u32;
    loop {
        let msg = alloc::format!("msg-{count}");
        match key.sign(&mut rng, msg.as_bytes()) {
            Ok(sig) => {
                assert!(pk.verify(msg.as_bytes(), &sig));
                let q = bottom_leaf_q(&sig);
                assert!(
                    seen_bottom.insert(q),
                    "bottom LM-OTS leaf {q} re-used — OTS reuse!"
                );
                count += 1;
            }
            Err(Error::Exhausted) => break,
            Err(e) => panic!("unexpected error {e:?}"),
        }
    }
    // Used exactly one full bottom tree, every leaf once, then failed closed.
    assert_eq!(count, 32, "must issue exactly 2^h_bottom signatures");
    assert_eq!(
        seen_bottom.len(),
        32,
        "all 32 bottom leaves used exactly once"
    );
    assert_eq!(key.remaining(), 0);
    assert_eq!(key.sign(&mut rng, b"after").err(), Some(Error::Exhausted));
}

/// The last bottom leaf signs fine, then the key fails closed instead of
/// wrapping into LM-OTS reuse (the pre-mitigation rollover behaviour).
#[test]
fn hss_bottom_rollover_fails_closed() {
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-rollover", b"n", &[]);
    let sk = HssPrivateKey::generate(
        &[
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
        ],
        &mut rng,
    )
    .unwrap();
    let pk = sk.public_key();
    let mut bytes = sk.to_bytes();
    // Layout: u32(L) then per level [type(4) ots(4) I(16) seed(32) q(4)].
    // Park the bottom level on its last leaf (q=31), top q stays 0.
    let per = 4 + 4 + 16 + N + 4;
    let bottom_q_off = 4 + per + (per - 4);
    bytes[bottom_q_off..bottom_q_off + 4].copy_from_slice(&31u32.to_be_bytes());
    let mut key = HssPrivateKey::from_bytes(&bytes).unwrap();
    assert_eq!(key.remaining(), 1);

    // The final bottom leaf signs and verifies.
    let s_last = key.sign(&mut rng, b"last-of-bottom").unwrap();
    assert!(pk.verify(b"last-of-bottom", &s_last));
    assert_eq!(bottom_leaf_q(&s_last), 31);

    // The bottom tree is now exhausted; the key MUST fail closed rather than
    // wrap (which would re-use bottom OTS leaf 0).
    assert_eq!(key.remaining(), 0);
    assert_eq!(
        key.sign(&mut rng, b"after-rollover").err(),
        Some(Error::Exhausted),
        "multi-level HSS must fail closed at bottom-tree wrap, never reuse OTS"
    );
}

/// A persisted multi-level key with an advanced higher level is rejected: it
/// could only be a pre-mitigation (already-wrapped) key that would re-use OTS.
#[test]
fn hss_from_bytes_rejects_advanced_higher_level() {
    let mut rng = HmacDrbg::<Sha256>::new(b"hss-reject", b"n", &[]);
    let sk = HssPrivateKey::generate(
        &[
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
            (LmsType::Sha256M32H5, LmotsType::Sha256N32W8),
        ],
        &mut rng,
    )
    .unwrap();
    let mut bytes = sk.to_bytes();
    let per = 4 + 4 + 16 + N + 4;
    // Set the TOP level q to 1 (a state the mitigation never produces).
    let top_q_off = 4 + (per - 4);
    bytes[top_q_off..top_q_off + 4].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(
        HssPrivateKey::from_bytes(&bytes).err(),
        Some(Error::Malformed),
        "advanced higher-level q must be rejected as a reuse-prone state"
    );
}
