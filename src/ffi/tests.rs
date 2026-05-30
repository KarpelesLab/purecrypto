//! In-crate tests exercising the `extern "C"` entry points directly.

use alloc::vec;
use alloc::vec::Vec;

use super::common::PcStatus;
use super::{ec, hash, mlkem, quic, rsa, tls, x509};
use crate::der::pem_decode;

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
