//! In-crate tests exercising the `extern "C"` entry points directly.

use alloc::vec;
use alloc::vec::Vec;

use super::common::PcStatus;
use super::{ec, hash, kdf, lms, mldsa, mlkem, quic, rsa, tls, x509, x25519, xmss};
use crate::der::pem_decode;

/// Sets a single ALPN protocol ("test") on a QUIC config. ALPN is
/// mandatory for QUIC (RFC 9001 §8.1) — `pc_quic_new` rejects a config
/// without it.
fn set_test_alpn(cfg: *mut quic::PcQuicCfg) {
    let alpn = b"test\0";
    let arr = [alpn.as_ptr() as *const core::ffi::c_char];
    let st = unsafe { quic::pc_quic_cfg_set_alpn(cfg, arr.as_ptr(), 1) };
    assert_eq!(st, PcStatus::Ok);
}

/// Calls an FFI writer twice (query length, then fill) and returns the bytes.
fn read_out(mut call: impl FnMut(*mut u8, *mut usize) -> PcStatus) -> Vec<u8> {
    let mut len = 0usize;
    let st = call(core::ptr::null_mut(), &mut len);
    if st == PcStatus::Ok {
        return Vec::new(); // empty output fits in a zero buffer
    }
    assert_eq!(st, PcStatus::BufferTooSmall);
    let mut buf = vec![0u8; len];
    let st = call(buf.as_mut_ptr(), &mut len);
    assert_eq!(st, PcStatus::Ok);
    buf.truncate(len);
    buf
}

#[test]
fn digest_oneshot_and_streaming() {
    let msg = b"abc";
    let expected = crate::hash::sha256(msg);

    // One-shot.
    let mut out = [0u8; 64];
    let mut len = out.len();
    let st = unsafe {
        hash::pc_digest(
            hash::id::SHA256,
            msg.as_ptr(),
            msg.len(),
            out.as_mut_ptr(),
            &mut len,
        )
    };
    assert_eq!(st, PcStatus::Ok);
    assert_eq!(&out[..len], &expected);

    // Streaming, fed in two parts.
    let h = hash::pc_hash_new(hash::id::SHA256);
    assert!(!h.is_null());
    unsafe {
        assert_eq!(hash::pc_hash_update(h, msg.as_ptr(), 1), PcStatus::Ok);
        assert_eq!(hash::pc_hash_update(h, msg[1..].as_ptr(), 2), PcStatus::Ok);
    }
    let got = read_out(|o, l| unsafe { hash::pc_hash_finish(h, o, l) });
    unsafe { hash::pc_hash_free(h) };
    assert_eq!(got, expected);

    // Unknown algorithm.
    assert!(hash::pc_hash_new(9999).is_null());
}

#[test]
fn hmac_matches() {
    let key = b"secret";
    let msg = b"message";
    let want = crate::hash::HmacSha256::mac(key, msg);
    let got = read_out(|o, l| unsafe {
        hash::pc_hmac(
            hash::id::SHA256,
            key.as_ptr(),
            key.len(),
            msg.as_ptr(),
            msg.len(),
            o,
            l,
        )
    });
    assert_eq!(got, want.as_ref());
}

#[test]
fn rand_fills() {
    let mut buf = [0u8; 32];
    let st = unsafe { super::rng::pc_rand_bytes(buf.as_mut_ptr(), buf.len()) };
    assert_eq!(st, PcStatus::Ok);
    assert!(buf.iter().any(|&b| b != 0));
}

#[test]
fn ec_generate_sign_verify() {
    let key = ec::pc_ec_generate(ec::curve::P256);
    assert!(!key.is_null());

    let msg = b"ec message";
    let sig = read_out(|o, l| unsafe { ec::pc_ec_sign(key, msg.as_ptr(), msg.len(), o, l) });

    let pub_pem = read_out(|o, l| unsafe { ec::pc_ec_public_to_pem(key, o, l) });
    let spki = pem_decode(core::str::from_utf8(&pub_pem).unwrap(), "PUBLIC KEY").unwrap();

    let ok = unsafe {
        ec::pc_ec_verify(
            spki.as_ptr(),
            spki.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        )
    };
    assert_eq!(ok, PcStatus::Ok);

    // A different message must fail.
    let bad = b"ec messagX";
    let st = unsafe {
        ec::pc_ec_verify(
            spki.as_ptr(),
            spki.len(),
            bad.as_ptr(),
            bad.len(),
            sig.as_ptr(),
            sig.len(),
        )
    };
    assert_eq!(st, PcStatus::Verification);

    // Private PEM round-trips back into a usable key.
    let priv_pem = read_out(|o, l| unsafe { ec::pc_ec_private_to_pem(key, o, l) });
    let key2 = unsafe { ec::pc_ec_from_pem(priv_pem.as_ptr(), priv_pem.len()) };
    assert!(!key2.is_null());
    unsafe {
        ec::pc_ec_free(key);
        ec::pc_ec_free(key2);
    }
}

#[test]
fn rsa_sign_verify_from_pem() {
    // Load a fixed test key (no slow keygen).
    let pem = crate::test_util::rsa_test_key_a().to_pkcs1_pem();
    let key = unsafe { rsa::pc_rsa_from_pem(pem.as_ptr(), pem.len()) };
    assert!(!key.is_null());

    let msg = b"rsa message";
    let sig = read_out(|o, l| unsafe {
        rsa::pc_rsa_sign_pkcs1(key, hash::id::SHA256, msg.as_ptr(), msg.len(), o, l)
    });

    let pub_pem = read_out(|o, l| unsafe { rsa::pc_rsa_public_to_pem(key, o, l) });
    let spki = pem_decode(core::str::from_utf8(&pub_pem).unwrap(), "PUBLIC KEY").unwrap();

    let ok = unsafe {
        rsa::pc_rsa_verify_pkcs1(
            spki.as_ptr(),
            spki.len(),
            hash::id::SHA256,
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        )
    };
    assert_eq!(ok, PcStatus::Ok);
    unsafe { rsa::pc_rsa_free(key) };
}

#[test]
fn cert_parse_and_verify() {
    use crate::x509::{Certificate, DistinguishedName, Time, Validity};
    let key = crate::test_util::rsa_test_key_a();
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let pem = Certificate::self_signed(
        &key,
        &DistinguishedName::common_name("ffi cert"),
        &validity,
        1,
        true,
    )
    .unwrap()
    .to_pem();

    let cert = unsafe { x509::pc_cert_from_pem(pem.as_ptr(), pem.len()) };
    assert!(!cert.is_null());

    // SPKI is extractable.
    let spki = read_out(|o, l| unsafe { x509::pc_cert_public_key_spki(cert, o, l) });
    assert!(!spki.is_empty());

    // Self-signed: verifies against itself.
    assert_eq!(unsafe { x509::pc_cert_verify(cert, cert) }, PcStatus::Ok);
    unsafe { x509::pc_cert_free(cert) };
}

/// I-6: `pc_mlkem_encaps`'s C ABI is "raw SPKI DER bytes" — the body must
/// accept DER (not require UTF-8 PEM framing as the original implementation
/// did).
#[test]
fn pc_mlkem_encaps_accepts_der() {
    let k = mlkem::pc_mlkem_generate(mlkem::set_id::ML_KEM_768);
    assert!(!k.is_null());

    // Export as DER. The new exporter pairs with the DER-expecting encaps.
    let der = read_out(|o, l| unsafe { mlkem::pc_mlkem_public_to_der(k, o, l) });
    assert!(!der.is_empty());

    let mut ct = vec![0u8; 1500];
    let mut ct_len = ct.len();
    let mut ss = [0u8; 32];
    let st = unsafe {
        mlkem::pc_mlkem_encaps(
            mlkem::set_id::ML_KEM_768,
            der.as_ptr(),
            der.len(),
            ct.as_mut_ptr(),
            &mut ct_len,
            ss.as_mut_ptr(),
        )
    };
    assert_eq!(st, PcStatus::Ok);
    assert_eq!(ct_len, 1088);

    unsafe { mlkem::pc_mlkem_free(k) };
}

/// `pc_quic_stream_read` caps the caller-controlled `*out_len` so a
/// hostile / pathological value (e.g. `SIZE_MAX`) cannot trigger a
/// multi-GiB allocation inside the FFI. Above the cap, the call
/// returns `BufferTooSmall` and rewrites `*out_len` to the documented
/// maximum.
#[test]
fn quic_stream_read_rejects_oversized_out_len() {
    use core::ffi::c_char;
    // QuicRole::Client == 0 per the enum.
    let cfg = quic::pc_quic_cfg_new(0);
    assert!(!cfg.is_null());
    // SNI required for client-mode pc_quic_new.
    let sni = b"loopback.example\0";
    let st = unsafe { quic::pc_quic_cfg_set_server_name(cfg, sni.as_ptr() as *const c_char) };
    assert_eq!(st, PcStatus::Ok);
    // Disable certificate verification so the client builds without a
    // trust store (we never actually run the handshake — we just need
    // a valid PcQuic to call stream_read on).
    let _ = unsafe { quic::pc_quic_cfg_set_verify_certificates(cfg, 0) };
    set_test_alpn(cfg);
    let q = unsafe { quic::pc_quic_new(cfg) };
    assert!(!q.is_null(), "expected a constructible client");

    let mut out_len: usize = usize::MAX;
    let mut fin: i32 = 0;
    let st =
        unsafe { quic::pc_quic_stream_read(q, 0, core::ptr::null_mut(), &mut out_len, &mut fin) };
    assert_eq!(st, PcStatus::BufferTooSmall);
    assert_eq!(out_len, 1 << 20, "out_len must report the 1 MiB cap");

    unsafe { quic::pc_quic_free(q) };
    unsafe { quic::pc_quic_cfg_free(cfg) };
}

/// `pc_dtls_cfg_set_cookie_secret` now takes an explicit length; any width
/// other than 32 is rejected up front instead of silently reading past the
/// end of a short caller buffer.
#[test]
fn dtls_cookie_secret_rejects_wrong_length() {
    // PC_TLS_SERVER == 1, PC_DTLS_1_2 == 0xFEFD (kept in sync with the
    // C header at `include/purecrypto.h`).
    let cfg = tls::pc_tls_cfg_new(1, 0xFEFD_u32 as i32);
    assert!(!cfg.is_null());

    // The 32-byte happy path.
    let ok_secret = [0xa5u8; 32];
    let st =
        unsafe { tls::pc_dtls_cfg_set_cookie_secret(cfg, ok_secret.as_ptr(), ok_secret.len()) };
    assert_eq!(st, PcStatus::Ok);

    // 31 bytes — too short; must be rejected without reading past the end.
    let short = [0u8; 31];
    let st = unsafe { tls::pc_dtls_cfg_set_cookie_secret(cfg, short.as_ptr(), short.len()) };
    assert_eq!(st, PcStatus::Unsupported);

    // 33 bytes — too long; same rejection.
    let long = [0u8; 33];
    let st = unsafe { tls::pc_dtls_cfg_set_cookie_secret(cfg, long.as_ptr(), long.len()) };
    assert_eq!(st, PcStatus::Unsupported);

    // NULL secret with non-zero length → NullPointer.
    let st = unsafe { tls::pc_dtls_cfg_set_cookie_secret(cfg, core::ptr::null(), 32) };
    assert_eq!(st, PcStatus::NullPointer);

    unsafe { tls::pc_tls_cfg_free(cfg) };
}

/// `pc_quic_set_peer_addr` now takes an explicit length; any width other
/// than 16 is rejected up front. Tests both the IPv4-mapped happy path and
/// the rejection paths.
#[test]
fn quic_set_peer_addr_rejects_wrong_length() {
    use core::ffi::c_char;
    let cfg = quic::pc_quic_cfg_new(0);
    assert!(!cfg.is_null());
    let sni = b"loopback.example\0";
    let st = unsafe { quic::pc_quic_cfg_set_server_name(cfg, sni.as_ptr() as *const c_char) };
    assert_eq!(st, PcStatus::Ok);
    let _ = unsafe { quic::pc_quic_cfg_set_verify_certificates(cfg, 0) };
    set_test_alpn(cfg);
    let q = unsafe { quic::pc_quic_new(cfg) };
    assert!(!q.is_null());

    // IPv4-mapped 127.0.0.1, 16 bytes — accepted.
    let v4mapped: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1];
    let st = unsafe { quic::pc_quic_set_peer_addr(q, v4mapped.as_ptr(), 16, 4433) };
    assert_eq!(st, PcStatus::Ok);

    // 4 bytes (a raw IPv4 address) — rejected; IPv6 form required.
    let v4: [u8; 4] = [127, 0, 0, 1];
    let st = unsafe { quic::pc_quic_set_peer_addr(q, v4.as_ptr(), 4, 4433) };
    assert_eq!(st, PcStatus::Unsupported);

    // 0 length is treated as an empty slice → can't fit into [u8; 16].
    let st = unsafe { quic::pc_quic_set_peer_addr(q, core::ptr::null(), 0, 4433) };
    assert_eq!(st, PcStatus::Unsupported);

    // NULL pointer with non-zero length → NullPointer.
    let st = unsafe { quic::pc_quic_set_peer_addr(q, core::ptr::null(), 16, 4433) };
    assert_eq!(st, PcStatus::NullPointer);

    unsafe { quic::pc_quic_free(q) };
    unsafe { quic::pc_quic_cfg_free(cfg) };
}

/// `pc_mldsa_verify` must honour the caller-pinned parameter set: a key of a
/// different set must be rejected with `Unsupported`, never verified under
/// the set the SPKI happens to declare.
#[test]
fn mldsa_verify_rejects_set_mismatch() {
    let k = mldsa::pc_mldsa_generate(mldsa::set_id::ML_DSA_44);
    assert!(!k.is_null());

    let msg = b"mldsa set pinning";
    let sig = read_out(|o, l| unsafe { mldsa::pc_mldsa_sign(k, msg.as_ptr(), msg.len(), o, l) });

    let pub_pem = read_out(|o, l| unsafe { mldsa::pc_mldsa_public_to_pem(k, o, l) });
    let spki = pem_decode(core::str::from_utf8(&pub_pem).unwrap(), "PUBLIC KEY").unwrap();

    // Matching set verifies.
    let st = unsafe {
        mldsa::pc_mldsa_verify(
            mldsa::set_id::ML_DSA_44,
            spki.as_ptr(),
            spki.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        )
    };
    assert_eq!(st, PcStatus::Ok);

    // A 44-key must NOT satisfy a caller demanding 65 or 87 — and an unknown
    // set id must be rejected too.
    for set in [mldsa::set_id::ML_DSA_65, mldsa::set_id::ML_DSA_87, 999] {
        let st = unsafe {
            mldsa::pc_mldsa_verify(
                set,
                spki.as_ptr(),
                spki.len(),
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                sig.len(),
            )
        };
        assert_eq!(
            st,
            PcStatus::Unsupported,
            "set {set} must not verify under a 44 key"
        );
    }

    unsafe { mldsa::pc_mldsa_free(k) };
}

// ---- Stateful hash-based signing: a size query must not burn a key ---------

#[test]
fn lms_sign_size_query_does_not_burn_a_key() {
    let msg = b"lms size-query message";
    // Every LM-OTS width, smallest tree (H5) — validates the length formula
    // across all four `p` values.
    for ots in [1i32, 2, 3, 4] {
        let k = lms::pc_lms_generate(5 /* SHA256_M32_H5 */, ots);
        assert!(!k.is_null());
        let state = |k| read_out(|o, l| unsafe { lms::pc_lms_private_to_bytes(k, o, l) });
        let before = state(k);

        // Size query (capacity 0): reports the length, advances nothing.
        let mut need = 0usize;
        let st = unsafe {
            lms::pc_lms_sign(k, msg.as_ptr(), msg.len(), core::ptr::null_mut(), &mut need)
        };
        assert_eq!(st, PcStatus::BufferTooSmall);
        assert!(need > 0);
        assert_eq!(
            before,
            state(k),
            "size query must not consume a one-time key"
        );

        // Too-small buffer: same.
        let mut small = vec![0u8; need - 1];
        let mut cap = small.len();
        let st =
            unsafe { lms::pc_lms_sign(k, msg.as_ptr(), msg.len(), small.as_mut_ptr(), &mut cap) };
        assert_eq!(st, PcStatus::BufferTooSmall);
        assert_eq!(cap, need);
        assert_eq!(
            before,
            state(k),
            "too-small sign must not consume a one-time key"
        );

        // Full sign: the predicted length must match the actual encoding.
        let mut sig = vec![0u8; need];
        let mut cap = need;
        let st =
            unsafe { lms::pc_lms_sign(k, msg.as_ptr(), msg.len(), sig.as_mut_ptr(), &mut cap) };
        assert_eq!(st, PcStatus::Ok);
        assert_eq!(
            cap, need,
            "predicted LMS signature length != actual (ots {ots})"
        );
        assert_ne!(before, state(k), "successful sign must advance the state");

        // And it verifies.
        let pk = read_out(|o, l| unsafe { lms::pc_lms_public_to_bytes(k, o, l) });
        let st = unsafe {
            lms::pc_lms_verify(
                pk.as_ptr(),
                pk.len(),
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                cap,
            )
        };
        assert_eq!(st, PcStatus::Ok);
        unsafe { lms::pc_lms_free(k) };
    }
}

#[test]
fn hss_sign_size_query_does_not_burn_a_key() {
    let msg = b"hss size-query message";
    // Single-level and multi-level (which appends the signed child public key).
    for levels in [1usize, 2] {
        let k = lms::pc_hss_generate(levels, 5 /* H5 */, 3 /* W4 */);
        assert!(!k.is_null());
        let state = |k| read_out(|o, l| unsafe { lms::pc_hss_private_to_bytes(k, o, l) });
        let before = state(k);

        let mut need = 0usize;
        let st = unsafe {
            lms::pc_hss_sign(k, msg.as_ptr(), msg.len(), core::ptr::null_mut(), &mut need)
        };
        assert_eq!(st, PcStatus::BufferTooSmall);
        assert!(need > 0);
        assert_eq!(
            before,
            state(k),
            "size query must not consume a one-time key"
        );

        let mut small = vec![0u8; need - 1];
        let mut cap = small.len();
        let st =
            unsafe { lms::pc_hss_sign(k, msg.as_ptr(), msg.len(), small.as_mut_ptr(), &mut cap) };
        assert_eq!(st, PcStatus::BufferTooSmall);
        assert_eq!(cap, need);
        assert_eq!(
            before,
            state(k),
            "too-small sign must not consume a one-time key"
        );

        let mut sig = vec![0u8; need];
        let mut cap = need;
        let st =
            unsafe { lms::pc_hss_sign(k, msg.as_ptr(), msg.len(), sig.as_mut_ptr(), &mut cap) };
        assert_eq!(st, PcStatus::Ok);
        assert_eq!(
            cap, need,
            "predicted HSS signature length != actual (L = {levels})"
        );
        assert_ne!(before, state(k), "successful sign must advance the state");

        let pk = read_out(|o, l| unsafe { lms::pc_hss_public_to_bytes(k, o, l) });
        let st = unsafe {
            lms::pc_hss_verify(
                pk.as_ptr(),
                pk.len(),
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                cap,
            )
        };
        assert_eq!(st, PcStatus::Ok);
        unsafe { lms::pc_hss_free(k) };
    }
}

#[test]
fn xmss_sign_size_query_does_not_burn_a_key() {
    let msg = b"xmss size-query message";
    let k = xmss::pc_xmss_generate(1 /* XMSS-SHA2_10_256 */);
    assert!(!k.is_null());
    let state = |k| read_out(|o, l| unsafe { xmss::pc_xmss_private_to_bytes(k, o, l) });
    let before = state(k);

    let mut need = 0usize;
    let st =
        unsafe { xmss::pc_xmss_sign(k, msg.as_ptr(), msg.len(), core::ptr::null_mut(), &mut need) };
    assert_eq!(st, PcStatus::BufferTooSmall);
    assert!(need > 0);
    assert_eq!(
        before,
        state(k),
        "size query must not consume a one-time key"
    );

    let mut small = vec![0u8; need - 1];
    let mut cap = small.len();
    let st =
        unsafe { xmss::pc_xmss_sign(k, msg.as_ptr(), msg.len(), small.as_mut_ptr(), &mut cap) };
    assert_eq!(st, PcStatus::BufferTooSmall);
    assert_eq!(cap, need);
    assert_eq!(
        before,
        state(k),
        "too-small sign must not consume a one-time key"
    );

    let mut sig = vec![0u8; need];
    let mut cap = need;
    let st = unsafe { xmss::pc_xmss_sign(k, msg.as_ptr(), msg.len(), sig.as_mut_ptr(), &mut cap) };
    assert_eq!(st, PcStatus::Ok);
    assert_eq!(cap, need, "predicted XMSS signature length != actual");
    assert_ne!(before, state(k), "successful sign must advance the state");

    let pk = read_out(|o, l| unsafe { xmss::pc_xmss_public_to_bytes(k, o, l) });
    let st = unsafe {
        xmss::pc_xmss_verify(
            pk.as_ptr(),
            pk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            cap,
        )
    };
    assert_eq!(st, PcStatus::Ok);
    unsafe { xmss::pc_xmss_free(k) };
}

#[test]
fn xmssmt_sign_size_query_does_not_burn_a_key() {
    let msg = b"xmssmt size-query message";
    let k = xmss::pc_xmssmt_generate(1 /* XMSSMT-SHA2_20/2_256 */);
    assert!(!k.is_null());
    let state = |k| read_out(|o, l| unsafe { xmss::pc_xmssmt_private_to_bytes(k, o, l) });
    let before = state(k);

    let mut need = 0usize;
    let st = unsafe {
        xmss::pc_xmssmt_sign(k, msg.as_ptr(), msg.len(), core::ptr::null_mut(), &mut need)
    };
    assert_eq!(st, PcStatus::BufferTooSmall);
    assert!(need > 0);
    assert_eq!(
        before,
        state(k),
        "size query must not consume a one-time key"
    );

    let mut small = vec![0u8; need - 1];
    let mut cap = small.len();
    let st =
        unsafe { xmss::pc_xmssmt_sign(k, msg.as_ptr(), msg.len(), small.as_mut_ptr(), &mut cap) };
    assert_eq!(st, PcStatus::BufferTooSmall);
    assert_eq!(cap, need);
    assert_eq!(
        before,
        state(k),
        "too-small sign must not consume a one-time key"
    );

    let mut sig = vec![0u8; need];
    let mut cap = need;
    let st =
        unsafe { xmss::pc_xmssmt_sign(k, msg.as_ptr(), msg.len(), sig.as_mut_ptr(), &mut cap) };
    assert_eq!(st, PcStatus::Ok);
    assert_eq!(cap, need, "predicted XMSS^MT signature length != actual");
    assert_ne!(before, state(k), "successful sign must advance the state");

    let pk = read_out(|o, l| unsafe { xmss::pc_xmssmt_public_to_bytes(k, o, l) });
    let st = unsafe {
        xmss::pc_xmssmt_verify(
            pk.as_ptr(),
            pk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            cap,
        )
    };
    assert_eq!(st, PcStatus::Ok);
    unsafe { xmss::pc_xmssmt_free(k) };
}

// ---- Non-destructive dequeue (pop / recv must survive BufferTooSmall) ------

/// Generates a P-256 self-signed certificate + key as `(chain_pem, key_pem)`.
fn loopback_identity() -> (alloc::string::String, alloc::string::String) {
    use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
    let mut rng =
        crate::rng::HmacDrbg::<crate::hash::Sha256>::new(b"ffi-loopback-identity", b"nonce", &[]);
    let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
    let name = DistinguishedName::common_name("loopback.example");
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2044, 1, 1, 0, 0, 0),
    );
    let cert = Certificate::self_signed_general(
        &CertSigner::Ecdsa(&key),
        &name,
        &validity,
        1,
        false,
        &["loopback.example"],
    )
    .unwrap();
    (cert.to_pem(), key.to_sec1_pem())
}

/// Drains every pending wire chunk from `from` and feeds it to `to`, always
/// size-querying (capacity 0) before reading. The regression mode under test
/// is that the size query itself used to discard the chunk.
unsafe fn pump_wire(from: *mut tls::PcTls, to: *mut tls::PcTls) {
    loop {
        let mut len = 0usize;
        let st = unsafe { tls::pc_tls_pop(from, core::ptr::null_mut(), &mut len) };
        if st == PcStatus::Ok {
            assert_eq!(len, 0);
            break;
        }
        assert_eq!(st, PcStatus::BufferTooSmall);
        assert!(len > 0);
        let mut buf = vec![0u8; len];
        let mut cap = len;
        let st = unsafe { tls::pc_tls_pop(from, buf.as_mut_ptr(), &mut cap) };
        assert_eq!(st, PcStatus::Ok);
        assert_eq!(cap, len, "retry must deliver exactly the queried bytes");
        let mut consumed = 0usize;
        let st = unsafe { tls::pc_tls_feed(to, buf.as_ptr(), cap, &mut consumed) };
        assert_eq!(st, PcStatus::Ok);
        assert_eq!(consumed, cap);
    }
}

#[test]
fn tls_pop_and_recv_too_small_are_non_destructive() {
    let (chain_pem, key_pem) = loopback_identity();

    let scfg = tls::pc_tls_cfg_new(1 /* server */, 0x0304);
    assert!(!scfg.is_null());
    let st = unsafe {
        tls::pc_tls_cfg_set_certificate(
            scfg,
            chain_pem.as_ptr(),
            chain_pem.len(),
            key_pem.as_ptr(),
            key_pem.len(),
        )
    };
    assert_eq!(st, PcStatus::Ok);
    let server = unsafe { tls::pc_tls_new(scfg) };
    unsafe { tls::pc_tls_cfg_free(scfg) };
    assert!(!server.is_null());

    let ccfg = tls::pc_tls_cfg_new(0 /* client */, 0x0304);
    assert!(!ccfg.is_null());
    unsafe {
        assert_eq!(
            tls::pc_tls_cfg_set_verify_certificates(ccfg, 0),
            PcStatus::Ok
        );
        let sni = b"loopback.example\0";
        assert_eq!(
            tls::pc_tls_cfg_set_server_name(ccfg, sni.as_ptr() as *const core::ffi::c_char),
            PcStatus::Ok
        );
    }
    let client = unsafe { tls::pc_tls_new(ccfg) };
    unsafe { tls::pc_tls_cfg_free(ccfg) };
    assert!(!client.is_null());

    // Drive the handshake to completion, size-querying before every pop.
    // Before the fix, the very first query discarded the ClientHello and the
    // handshake could never complete.
    for _ in 0..20 {
        unsafe {
            let _ = tls::pc_tls_handshake(client);
            pump_wire(client, server);
            let _ = tls::pc_tls_handshake(server);
            pump_wire(server, client);
        }
        if unsafe { tls::pc_tls_is_handshake_complete(client) } == 1
            && unsafe { tls::pc_tls_is_handshake_complete(server) } == 1
        {
            break;
        }
    }
    assert_eq!(unsafe { tls::pc_tls_is_handshake_complete(client) }, 1);
    assert_eq!(unsafe { tls::pc_tls_is_handshake_complete(server) }, 1);

    // Server -> client application data.
    let msg = b"pop/recv must not eat plaintext";
    let st = unsafe { tls::pc_tls_send(server, msg.as_ptr(), msg.len()) };
    assert_eq!(st, PcStatus::Ok);
    unsafe { pump_wire(server, client) };

    // 1. Size query with zero capacity reports the length, destroys nothing.
    let mut need = 0usize;
    let st = unsafe { tls::pc_tls_recv(client, core::ptr::null_mut(), &mut need) };
    assert_eq!(st, PcStatus::BufferTooSmall);
    assert_eq!(need, msg.len());

    // 2. Too-small buffer: still BufferTooSmall, still nothing lost.
    let mut small = [0u8; 1];
    let mut cap = small.len();
    let st = unsafe { tls::pc_tls_recv(client, small.as_mut_ptr(), &mut cap) };
    assert_eq!(st, PcStatus::BufferTooSmall);
    assert_eq!(cap, msg.len());

    // 3. Full read returns the same bytes.
    let mut buf = vec![0u8; need];
    let mut cap = need;
    let st = unsafe { tls::pc_tls_recv(client, buf.as_mut_ptr(), &mut cap) };
    assert_eq!(st, PcStatus::Ok);
    assert_eq!(&buf[..cap], msg);

    // 4. Queue is now empty.
    let mut cap = 0usize;
    let st = unsafe { tls::pc_tls_recv(client, core::ptr::null_mut(), &mut cap) };
    assert_eq!(st, PcStatus::Ok);
    assert_eq!(cap, 0);

    unsafe {
        tls::pc_tls_free(client);
        tls::pc_tls_free(server);
    }
}

/// The C ABI close surface: `pc_quic_close` before any close is reported as
/// `PC_WANT_READ`, then reports the local application close it queued, and
/// `pc_quic_close_info` size-queries its reason phrase non-destructively.
#[test]
fn quic_close_info_reports_local_application_close() {
    let cfg = quic::pc_quic_cfg_new(0 /* client */);
    assert!(!cfg.is_null());
    unsafe {
        assert_eq!(
            quic::pc_quic_cfg_set_verify_certificates(cfg, 0),
            PcStatus::Ok
        );
        let sni = b"loopback.example\0";
        assert_eq!(
            quic::pc_quic_cfg_set_server_name(cfg, sni.as_ptr() as *const core::ffi::c_char),
            PcStatus::Ok
        );
    }
    set_test_alpn(cfg);
    let q = unsafe { quic::pc_quic_new(cfg) };
    unsafe { quic::pc_quic_cfg_free(cfg) };
    assert!(!q.is_null());

    // Live connection: nothing to report yet.
    let (mut code, mut initiator, mut is_app, mut rlen) = (0u64, 0i32, 0i32, 0usize);
    let st = unsafe {
        quic::pc_quic_close_info(
            q,
            &mut code,
            &mut initiator,
            &mut is_app,
            core::ptr::null_mut(),
            &mut rlen,
        )
    };
    assert_eq!(st, PcStatus::WantRead);

    let mut closed = -1i32;
    assert_eq!(
        unsafe { quic::pc_quic_is_closed(q, &mut closed) },
        PcStatus::Ok
    );
    assert_eq!(closed, 0);

    let reason = b"shutting down";
    assert_eq!(
        unsafe { quic::pc_quic_close(q, 0x1234, reason.as_ptr(), reason.len()) },
        PcStatus::Ok
    );

    // Size query first — non-destructive, like pc_quic_pop_datagram.
    let mut rlen = 0usize;
    let st = unsafe {
        quic::pc_quic_close_info(
            q,
            &mut code,
            &mut initiator,
            &mut is_app,
            core::ptr::null_mut(),
            &mut rlen,
        )
    };
    assert_eq!(st, PcStatus::BufferTooSmall);
    assert_eq!(rlen, reason.len());

    let mut buf = vec![0u8; rlen];
    let mut cap = rlen;
    let st = unsafe {
        quic::pc_quic_close_info(
            q,
            &mut code,
            &mut initiator,
            &mut is_app,
            buf.as_mut_ptr(),
            &mut cap,
        )
    };
    assert_eq!(st, PcStatus::Ok);
    assert_eq!(&buf[..cap], reason);
    assert_eq!(code, 0x1234);
    assert_eq!(initiator, 0, "locally initiated");
    assert_eq!(is_app, 1, "application close");

    unsafe { quic::pc_quic_free(q) };
}

#[test]
fn quic_pop_datagram_too_small_is_non_destructive() {
    let cfg = quic::pc_quic_cfg_new(0 /* client */);
    assert!(!cfg.is_null());
    unsafe {
        assert_eq!(
            quic::pc_quic_cfg_set_verify_certificates(cfg, 0),
            PcStatus::Ok
        );
        let sni = b"loopback.example\0";
        assert_eq!(
            quic::pc_quic_cfg_set_server_name(cfg, sni.as_ptr() as *const core::ffi::c_char),
            PcStatus::Ok
        );
    }
    set_test_alpn(cfg);
    let q = unsafe { quic::pc_quic_new(cfg) };
    unsafe { quic::pc_quic_cfg_free(cfg) };
    assert!(!q.is_null());

    // The first pop assembles the client's Initial flight (irreversibly, on
    // the engine side). Size-query it: before the fix this discarded the
    // datagram outright.
    let mut need = 0usize;
    let st = unsafe { quic::pc_quic_pop_datagram(q, core::ptr::null_mut(), &mut need) };
    assert_eq!(st, PcStatus::BufferTooSmall);
    assert!(need > 0);

    // Too-small retry must not lose the datagram either.
    let mut small = [0u8; 8];
    let mut cap = small.len();
    let st = unsafe { quic::pc_quic_pop_datagram(q, small.as_mut_ptr(), &mut cap) };
    assert_eq!(st, PcStatus::BufferTooSmall);
    assert_eq!(cap, need);

    // Full read delivers the same (sized) datagram: a QUIC long-header packet.
    let mut buf = vec![0u8; need];
    let mut cap = need;
    let st = unsafe { quic::pc_quic_pop_datagram(q, buf.as_mut_ptr(), &mut cap) };
    assert_eq!(st, PcStatus::Ok);
    assert_eq!(cap, need);
    assert_ne!(buf[0] & 0x80, 0, "expected a long-header packet");

    unsafe { quic::pc_quic_free(q) };
}

#[test]
fn buffer_too_small_reports_length() {
    let msg = b"abc";
    let mut len = 0usize;
    let st = unsafe {
        hash::pc_digest(
            hash::id::SHA256,
            msg.as_ptr(),
            msg.len(),
            core::ptr::null_mut(),
            &mut len,
        )
    };
    assert_eq!(st, PcStatus::BufferTooSmall);
    assert_eq!(len, 32);
}

// --- Memory-hard KDF cost caps -------------------------------------------
//
// `pc_argon2`/`pc_scrypt` size their working buffer directly from caller-
// supplied cost parameters. Rust reports an allocation failure through
// `handle_alloc_error`, which ABORTS — `guard`'s `catch_unwind` cannot
// intercept that, so an unbounded cost would take the process down with no
// `PcStatus` ever returned, in violation of the module contract ("every entry
// point catches panics"). Since verifying a password hash means re-deriving
// with the cost parameters stored *in the hash string*, those values are
// routinely attacker-influenced. These tests pin the cap: an oversized cost
// must come back as `Unsupported`. If a regression removes the check they do
// not merely fail — the whole test binary dies with SIGABRT, which is also a
// very visible signal.

/// An `m_cost` above the ceiling is rejected rather than aborting the process.
#[test]
fn argon2_rejects_oversized_m_cost() {
    let pw = b"password";
    let salt = b"saltsaltsaltsalt";
    let mut out = [0u8; 32];
    for m_cost in [u32::MAX, u32::MAX / 2, 4 * 1024 * 1024 + 1] {
        let st = unsafe {
            kdf::pc_argon2(
                kdf::argon2_id::ARGON2ID,
                pw.as_ptr(),
                pw.len(),
                salt.as_ptr(),
                salt.len(),
                1,
                m_cost,
                1,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(
            st,
            PcStatus::Unsupported,
            "m_cost={m_cost} must be rejected, not allocated"
        );
    }
}

/// Ordinary Argon2 parameters still work, so the cap does not intrude on the
/// useful range.
#[test]
fn argon2_accepts_ordinary_cost() {
    let pw = b"password";
    let salt = b"saltsaltsaltsalt";
    let mut out = [0u8; 32];
    let st = unsafe {
        kdf::pc_argon2(
            kdf::argon2_id::ARGON2ID,
            pw.as_ptr(),
            pw.len(),
            salt.as_ptr(),
            salt.len(),
            1,
            64,
            1,
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(st, PcStatus::Ok);
    assert_ne!(out, [0u8; 32]);
}

/// scrypt's working set is `128 * r * n` bytes; combinations above the ceiling
/// are rejected even though RFC 7914 itself permits them (its `r * N < 2^30`
/// bound allows ~128 GiB).
#[test]
fn scrypt_rejects_oversized_cost() {
    let pw = b"password";
    let salt = b"NaCl";
    let mut out = [0u8; 32];
    // (n, r): 2^29 * 128 B = 64 GiB; 2^25 * 8 * 128 B = 32 GiB; 2^26 = 8 GiB.
    for (n, r) in [(1u32 << 29, 1u32), (1u32 << 25, 8u32), (1u32 << 26, 1u32)] {
        let st = unsafe {
            kdf::pc_scrypt(
                pw.as_ptr(),
                pw.len(),
                salt.as_ptr(),
                salt.len(),
                n,
                r,
                1,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(
            st,
            PcStatus::Unsupported,
            "scrypt n={n} r={r} must be rejected, not allocated"
        );
    }
}

/// The cost accounting must not overflow. `128 * r * n` reaches ~2^71 for `r`
/// near `u32::MAX` and `n = 2^31`, so computing it in `u64` would wrap in
/// release to a small value, sail past the ceiling, and reach the very
/// allocation the cap exists to prevent. `p` counts too: scrypt's first PBKDF2
/// expansion allocates `128 * r * p` bytes on top of the `V` array.
#[test]
fn scrypt_cost_check_does_not_overflow() {
    let pw = b"password";
    let salt = b"NaCl";
    let mut out = [0u8; 32];
    for (n, r, p) in [
        (1u32 << 31, u32::MAX, 1u32),
        (1u32 << 31, 1, u32::MAX),
        (2, u32::MAX, u32::MAX),
        (1u32 << 30, 0x0010_0000, 1),
    ] {
        let st = unsafe {
            kdf::pc_scrypt(
                pw.as_ptr(),
                pw.len(),
                salt.as_ptr(),
                salt.len(),
                n,
                r,
                p,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(
            st,
            PcStatus::Unsupported,
            "scrypt n={n} r={r} p={p} must be rejected, not allocated"
        );
    }
}

/// `r == 0` is degenerate (zero-sized working set) and must be rejected up
/// front rather than reaching the implementation.
#[test]
fn scrypt_rejects_zero_r() {
    let pw = b"password";
    let salt = b"NaCl";
    let mut out = [0u8; 32];
    let st = unsafe {
        kdf::pc_scrypt(
            pw.as_ptr(),
            pw.len(),
            salt.as_ptr(),
            salt.len(),
            16,
            0,
            1,
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(st, PcStatus::Unsupported);
}

/// Ordinary scrypt parameters still work (RFC 7914 §11, second vector).
#[test]
fn scrypt_accepts_ordinary_cost() {
    let pw = b"password";
    let salt = b"NaCl";
    let mut out = [0u8; 64];
    let st = unsafe {
        kdf::pc_scrypt(
            pw.as_ptr(),
            pw.len(),
            salt.as_ptr(),
            salt.len(),
            1024,
            8,
            16,
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(st, PcStatus::Ok);
    assert_eq!(out[..4], [0xfd, 0xba, 0xbe, 0x1c]);
}

// --- X25519/X448 scrub the caller's private scalar ------------------------
//
// The entry points copy the caller's scalar into a stack array (`[u8; N]` is
// `Copy`, so `from_bytes` leaves a second copy behind) and must wipe it before
// returning — the treatment the shared secret already gets, applied to the more
// valuable secret. There is no portable way to inspect a dead stack frame, so
// these tests pin the observable half of the contract: the wipe targets the
// FFI's private copy and never the caller's own buffer, and the operations
// still produce the right answers. The wipe itself is reviewed in
// `src/ffi/x25519.rs`.

/// RFC 7748 §6.1 test vector: the X25519 shared secret is computed correctly
/// and the caller's scalar buffer is not disturbed by the internal wipe.
#[test]
fn x25519_preserves_caller_scalar_and_matches_rfc7748() {
    // Alice's private key / Bob's public key (RFC 7748 §6.1).
    let alice_sk: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let bob_pk: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    let expect: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];
    let mut out = [0u8; 32];
    let st = unsafe { x25519::pc_x25519(alice_sk.as_ptr(), bob_pk.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(st, PcStatus::Ok);
    assert_eq!(out, expect);
    assert_eq!(
        alice_sk[0], 0x77,
        "pc_x25519 must not scrub the caller's own scalar buffer"
    );

    // Public-key derivation takes the same copy-and-wipe path.
    let mut pk = [0u8; 32];
    let st = unsafe { x25519::pc_x25519_public(alice_sk.as_ptr(), pk.as_mut_ptr()) };
    assert_eq!(st, PcStatus::Ok);
    assert_eq!(alice_sk[0], 0x77);
    assert_ne!(pk, [0u8; 32]);
}

/// The X448 path mirrors X25519: agreement still round-trips and the caller's
/// scalar survives.
#[test]
fn x448_preserves_caller_scalar_and_agrees() {
    let a_sk = [0x11u8; 56];
    let b_sk = [0x22u8; 56];
    let (mut a_pk, mut b_pk) = ([0u8; 56], [0u8; 56]);
    assert_eq!(
        unsafe { x25519::pc_x448_public(a_sk.as_ptr(), a_pk.as_mut_ptr()) },
        PcStatus::Ok
    );
    assert_eq!(
        unsafe { x25519::pc_x448_public(b_sk.as_ptr(), b_pk.as_mut_ptr()) },
        PcStatus::Ok
    );
    let (mut ss1, mut ss2) = ([0u8; 56], [0u8; 56]);
    assert_eq!(
        unsafe { x25519::pc_x448(a_sk.as_ptr(), b_pk.as_ptr(), ss1.as_mut_ptr()) },
        PcStatus::Ok
    );
    assert_eq!(
        unsafe { x25519::pc_x448(b_sk.as_ptr(), a_pk.as_ptr(), ss2.as_mut_ptr()) },
        PcStatus::Ok
    );
    assert_eq!(ss1, ss2);
    assert_ne!(ss1, [0u8; 56]);
    assert_eq!(a_sk, [0x11u8; 56], "caller's scalar buffer must be intact");
    assert_eq!(b_sk, [0x22u8; 56], "caller's scalar buffer must be intact");
}
