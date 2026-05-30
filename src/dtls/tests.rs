//! End-to-end loopback tests for the DTLS 1.2 and 1.3 client / server pairs.
//!
//! Tests cover:
//! 1. Loopback handshake (no cookie) — sanity of the protocol path.
//! 2. HelloVerifyRequest cookie: first CH gets HVR, second CH succeeds.
//! 3. Reordered records: server's flight delivered out of order.
//! 4. Replay rejection: post-handshake replayed record is silently dropped.
//! 5. Application data exchange after handshake completion.

use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
use crate::hash::Sha256;
use crate::rng::HmacDrbg;
use crate::tls::pki::RootCertStore;
use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{
    ClientConfig12Internal as PcClientConfig12, DtlsClientConnection12, DtlsServerConnection12,
    ServerConfig12Internal as PcServerConfig12,
};

/// Build an ECDSA P-256 server config + the cert DER suitable for the
/// client's trust store.
fn make_server() -> (PcServerConfig12, Vec<u8>) {
    let mut rng = HmacDrbg::<Sha256>::new(b"dtls12-test-key", b"nonce", &[]);
    let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
    let name = DistinguishedName::common_name("dtls.example");
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let cert = Certificate::self_signed_general(
        &CertSigner::Ecdsa(&key),
        &name,
        &validity,
        1,
        false,
        &["dtls.example"],
    )
    .unwrap();
    let der = cert.to_der().to_vec();
    (
        PcServerConfig12::with_ecdsa(alloc::vec![der.clone()], key),
        der,
    )
}

fn make_client(server_cert: &[u8]) -> DtlsClientConnection12 {
    let mut roots = RootCertStore::new();
    roots.add_der(server_cert.to_vec()).unwrap();
    let cfg = PcClientConfig12::new(roots, "dtls.example")
        .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
    let mut crng = HmacDrbg::<Sha256>::new(b"dtls12-client", b"nonce", &[]);
    DtlsClientConnection12::new(cfg, b"client-addr".to_vec(), &mut crng)
}

/// Pump until both sides report `is_handshake_complete()` or we hit the
/// iteration cap. Returns whether both succeeded.
fn pump_handshake<R: crate::rng::RngCore>(
    client: &mut DtlsClientConnection12,
    server: &mut DtlsServerConnection12<R>,
) -> bool {
    for _ in 0..32 {
        let c_out = client.pop_outbound_datagrams();
        for dg in &c_out {
            server.feed_datagram(dg).unwrap();
        }
        let s_out = server.pop_outbound_datagrams();
        for dg in &s_out {
            client.feed_datagram(dg).unwrap();
        }
        if c_out.is_empty() && s_out.is_empty() {
            break;
        }
    }
    client.is_handshake_complete() && server.is_handshake_complete()
}

#[test]
fn loopback_no_cookie() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg.require_cookie_exchange(false);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
    assert!(pump_handshake(&mut client, &mut server));
}

#[test]
fn loopback_with_cookie() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg
        .with_cookie_secret([0xa5; 32])
        .require_cookie_exchange(true);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-cookie", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
    assert!(pump_handshake(&mut client, &mut server));
}

/// Regression (DTLS-cookie fail-closed): a server that requires the cookie
/// exchange but was never given a `cookie_secret` MUST reject the first
/// ClientHello and emit NO server flight, rather than silently degrading to
/// the no-cookie path and serving an unverified, spoofable source.
#[test]
fn require_cookie_without_secret_fails_closed_12() {
    let (server_cfg, cert) = make_server();
    // `with_ecdsa` already defaults require_cookie_exchange = true; do NOT
    // call with_cookie_secret, so cookie_secret stays None.
    let server_cfg = server_cfg.require_cookie_exchange(true);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-failclosed", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

    let c1 = client.pop_outbound_datagrams();
    assert!(!c1.is_empty(), "client should emit CH1");
    let mut saw_err = false;
    for dg in &c1 {
        if server.feed_datagram(dg).is_err() {
            saw_err = true;
        }
    }
    assert!(
        saw_err,
        "cookie-required server with no secret must error on CH1"
    );
    // And it must NOT have produced any server flight.
    assert!(
        server.pop_outbound_datagrams().is_empty(),
        "no server flight may be emitted to an unverified source"
    );
}

#[test]
fn reordered_server_flight() {
    // Drive a handshake but deliver the server's first flight in reverse
    // order. The client's reassembler is order-independent within a single
    // record; here we test record-level reordering of the SH/Cert/SKE/SHDone
    // datagrams.
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg.require_cookie_exchange(false);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-reorder", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

    // Round 1: client → server (CH).
    let c1 = client.pop_outbound_datagrams();
    for dg in &c1 {
        server.feed_datagram(dg).unwrap();
    }
    // Server emits its full flight (SH..SHDone).
    let s1 = server.pop_outbound_datagrams();
    assert!(!s1.is_empty(), "server should have emitted flight");
    // Reverse delivery.
    for dg in s1.iter().rev() {
        client.feed_datagram(dg).unwrap();
    }
    // Pump the remainder.
    for _ in 0..16 {
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        let s = server.pop_outbound_datagrams();
        for dg in &s {
            client.feed_datagram(dg).unwrap();
        }
        if c.is_empty() && s.is_empty() {
            break;
        }
    }
    assert!(client.is_handshake_complete());
    assert!(server.is_handshake_complete());
}

#[test]
fn replay_rejected_silently() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg.require_cookie_exchange(false);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-replay", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
    assert!(pump_handshake(&mut client, &mut server));

    // Send a real app-data record from server to client.
    server.send(b"first").unwrap();
    let s = server.pop_outbound_datagrams();
    assert_eq!(s.len(), 1);
    let recorded = s[0].clone();
    client.feed_datagram(&recorded).unwrap();
    assert_eq!(client.take_received(), b"first");

    // Replay the same record: should be silently dropped (anti-replay
    // window). The client must not panic and must not emit data again.
    client.feed_datagram(&recorded).unwrap();
    assert!(
        client.take_received().is_empty(),
        "replay should be silently dropped",
    );

    // A fresh record (seq advances) still works.
    server.send(b"second").unwrap();
    let s2 = server.pop_outbound_datagrams();
    for dg in &s2 {
        client.feed_datagram(dg).unwrap();
    }
    assert_eq!(client.take_received(), b"second");
}

/// DTLS-1 (DTLS 1.2 read path): forged record with a fresh seq number that
/// fails AEAD must NOT burn the replay window. See dtls13 counterpart for
/// the rationale.
#[test]
fn forged_record_does_not_burn_replay_slot_dtls12() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg.require_cookie_exchange(false);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-fwd", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
    assert!(pump_handshake(&mut client, &mut server));

    server.send(b"one").unwrap();
    let s1 = server.pop_outbound_datagrams();
    assert_eq!(s1.len(), 1);

    server.send(b"two").unwrap();
    let s2 = server.pop_outbound_datagrams();
    assert_eq!(s2.len(), 1);
    // Tamper the ciphertext.
    let mut tampered = s2[0].clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 1;

    client.feed_datagram(&s1[0]).unwrap();
    assert_eq!(client.take_received(), b"one");
    // Tampered: AEAD fails. The window must NOT mark the slot.
    let _ = client.feed_datagram(&tampered);
    assert!(client.take_received().is_empty());
    // Legit #2 still accepted — its slot wasn't burnt by the forgery.
    client.feed_datagram(&s2[0]).unwrap();
    assert_eq!(client.take_received(), b"two");
}

/// DTLS-3 (DTLS 1.2): `set_now` advances the cookie generator's clock.
/// Without this hook, a server with no firing timeouts would issue cookies
/// with a stale timestamp forever, defeating the embedded-TS age check.
#[test]
fn set_now_advances_cookie_clock_dtls12() {
    use core::time::Duration;
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg
        .with_cookie_secret([0xa5; 32])
        .require_cookie_exchange(true);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-set-now", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

    // CH1 → HVR(cookie) at t=0.
    let c1 = client.pop_outbound_datagrams();
    for dg in &c1 {
        server.feed_datagram(dg).unwrap();
    }
    let hvr_at_zero = server.pop_outbound_datagrams();
    assert!(!hvr_at_zero.is_empty());

    // Advance clock by 5 minutes — cookie TS field (in minutes) changes.
    server.set_now(Duration::from_secs(60 * 5));

    let mut other_client = make_client(&cert);
    let other_c1 = other_client.pop_outbound_datagrams();
    for dg in &other_c1 {
        server.feed_datagram(dg).unwrap();
    }
    let hvr_at_five = server.pop_outbound_datagrams();
    assert!(!hvr_at_five.is_empty());
    assert_ne!(hvr_at_zero, hvr_at_five);

    // Rewind is a no-op.
    server.set_now(Duration::from_secs(0));
    let mut third_client = make_client(&cert);
    let third_c1 = third_client.pop_outbound_datagrams();
    for dg in &third_c1 {
        server.feed_datagram(dg).unwrap();
    }
    let hvr_rewound = server.pop_outbound_datagrams();
    assert!(!hvr_rewound.is_empty());
}

#[test]
fn application_data_both_ways_12() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg.require_cookie_exchange(false);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-app", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
    assert!(pump_handshake(&mut client, &mut server));

    client.send(b"hello world").unwrap();
    let c = client.pop_outbound_datagrams();
    for dg in &c {
        server.feed_datagram(dg).unwrap();
    }
    assert_eq!(server.take_received(), b"hello world");

    server.send(b"pong from server").unwrap();
    let s = server.pop_outbound_datagrams();
    for dg in &s {
        client.feed_datagram(dg).unwrap();
    }
    assert_eq!(client.take_received(), b"pong from server");
}

/// RFC 5705 §4 — DTLS 1.2 exporter agrees on both sides for a given
/// `(label, context)`, and the no-context vs empty-context branches differ.
#[test]
fn exporter_agrees_both_sides_12() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg.require_cookie_exchange(false);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-exporter", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
    assert!(pump_handshake(&mut client, &mut server));

    let mut c_out = [0u8; 48];
    let mut s_out = [0u8; 48];
    client
        .tls_exporter(b"EXPERIMENTAL-dtls", None, &mut c_out)
        .unwrap();
    server
        .tls_exporter(b"EXPERIMENTAL-dtls", None, &mut s_out)
        .unwrap();
    assert_eq!(c_out, s_out);

    let mut c_ctx = [0u8; 48];
    let mut s_ctx = [0u8; 48];
    client
        .tls_exporter(b"EXPERIMENTAL-dtls", Some(b"binding"), &mut c_ctx)
        .unwrap();
    server
        .tls_exporter(b"EXPERIMENTAL-dtls", Some(b"binding"), &mut s_ctx)
        .unwrap();
    assert_eq!(c_ctx, s_ctx);

    // RFC 5705 §4 — `None` vs `Some(&[])` MUST differ.
    let mut c_empty = [0u8; 48];
    client
        .tls_exporter(b"EXPERIMENTAL-dtls", Some(&[]), &mut c_empty)
        .unwrap();
    assert_ne!(c_out, c_empty);
}

/// DTLS 1.3 end-to-end loopback tests.
mod dtls13 {
    use super::*;
    use crate::dtls::{
        ClientConfig13Internal as PcClientConfig13, DtlsClientConnection13, DtlsServerConnection13,
        ServerConfig13Internal as PcServerConfig13,
    };

    fn make_server13() -> (PcServerConfig13, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"dtls13-test-key", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let name = DistinguishedName::common_name("dtls.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            false,
            &["dtls.example"],
        )
        .unwrap();
        let der = cert.to_der().to_vec();
        (
            PcServerConfig13::with_ecdsa(alloc::vec![der.clone()], key),
            der,
        )
    }

    fn make_client13(server_cert: &[u8]) -> DtlsClientConnection13 {
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert.to_vec()).unwrap();
        let cfg = PcClientConfig13::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls13-client", b"nonce", &[]);
        DtlsClientConnection13::new(cfg, b"client-addr".to_vec(), &mut crng)
    }

    fn pump_handshake_13<R: crate::rng::RngCore>(
        client: &mut DtlsClientConnection13,
        server: &mut DtlsServerConnection13<R>,
    ) -> bool {
        for _ in 0..32 {
            let c_out = client.pop_outbound_datagrams();
            for dg in &c_out {
                server.feed_datagram(dg).unwrap();
            }
            let s_out = server.pop_outbound_datagrams();
            for dg in &s_out {
                client.feed_datagram(dg).unwrap();
            }
            if c_out.is_empty() && s_out.is_empty() {
                break;
            }
        }
        client.is_handshake_complete() && server.is_handshake_complete()
    }

    #[test]
    fn loopback_no_cookie() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));
    }

    #[test]
    fn loopback_with_cookie() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-cookie", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));
    }

    /// Regression (DTLS-cookie fail-closed): DTLS 1.3 server with the cookie
    /// exchange required but no `cookie_secret` must reject the first
    /// ClientHello and emit no HRR / server flight to a spoofable source.
    #[test]
    fn require_cookie_without_secret_fails_closed_13() {
        let (server_cfg, cert) = make_server13();
        // require_cookie defaults to true; do NOT set a cookie_secret.
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-failclosed", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

        let c1 = client.pop_outbound_datagrams();
        assert!(!c1.is_empty(), "client should emit CH1");
        let mut saw_err = false;
        for dg in &c1 {
            if server.feed_datagram(dg).is_err() {
                saw_err = true;
            }
        }
        assert!(
            saw_err,
            "cookie-required server with no secret must error on CH1"
        );
        assert!(
            server.pop_outbound_datagrams().is_empty(),
            "no server flight may be emitted to an unverified source"
        );
    }

    /// RFC 8446 §7.5 / RFC 5705 — DTLS 1.3 exporter agrees on both sides
    /// for a given `(label, context)`, and distinct contexts diverge.
    #[test]
    fn exporter_agrees_both_sides_13() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-exporter", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        let mut c_out = [0u8; 64];
        let mut s_out = [0u8; 64];
        client
            .tls_exporter(b"EXPORTER-dtls-test", b"some context", &mut c_out)
            .unwrap();
        server
            .tls_exporter(b"EXPORTER-dtls-test", b"some context", &mut s_out)
            .unwrap();
        assert_eq!(c_out, s_out);

        // Distinct contexts must yield distinct streams.
        let mut c_other = [0u8; 64];
        client
            .tls_exporter(b"EXPORTER-dtls-test", b"other context", &mut c_other)
            .unwrap();
        assert_ne!(c_out, c_other);
    }

    /// DTLS 1.3 + Ed25519 server certificate: proves the generalised
    /// signing path (RFC 8446 §4.4.3 `CertificateVerify` dispatch) works
    /// for non-ECDSA key types in the DTLS server. Before the
    /// `unified-tls-config.md` refactor, the DTLS 1.3 server's signing
    /// site was hard-coded to ECDSA only.
    #[test]
    fn loopback_ed25519() {
        use crate::ec::Ed25519PrivateKey;
        use crate::tls::conn::ServerKey;

        // Build an Ed25519 self-signed server cert.
        let mut rng = HmacDrbg::<Sha256>::new(b"dtls13-ed25519-key", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut rng);
        let name = DistinguishedName::common_name("dtls.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ed25519(&key),
            &name,
            &validity,
            1,
            false,
            &["dtls.example"],
        )
        .unwrap();
        let der = cert.to_der().to_vec();

        let server_cfg =
            PcServerConfig13::with_signing_key(alloc::vec![der.clone()], ServerKey::Ed25519(key))
                .with_no_cookie();

        let mut client = make_client13(&der);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-ed25519", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        // App-data round-trip under Ed25519-signed CertificateVerify.
        client.send(b"ping-ed25519").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-ed25519");

        server.send(b"pong-ed25519").unwrap();
        let s = server.pop_outbound_datagrams();
        for dg in &s {
            client.feed_datagram(dg).unwrap();
        }
        assert_eq!(client.take_received(), b"pong-ed25519");
    }

    /// DTLS 1.3 + RSA-2048 server certificate: the server signs its
    /// `CertificateVerify` with RSA-PSS-RSAE-SHA256 (RFC 8446 §4.2.3).
    /// Confirms the generalised signing dispatch handles the RSA path
    /// end-to-end, including chain validation under
    /// [`SignaturePolicy::modern`] (which permits RSA-PSS).
    #[test]
    fn loopback_rsa_cert() {
        use crate::rsa::BoxedRsaPrivateKey;
        use crate::test_util::rsa_test_key_a;
        use crate::tls::conn::ServerKey;
        use crate::x509::CertSigner;

        let rsa_key = rsa_test_key_a();
        let boxed = BoxedRsaPrivateKey::from_pkcs1_der(&rsa_key.to_pkcs1_der()).unwrap();
        let name = DistinguishedName::common_name("dtls.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Rsa(&boxed),
            &name,
            &validity,
            1,
            false,
            &["dtls.example"],
        )
        .unwrap();
        let der = cert.to_der().to_vec();

        let server_cfg =
            PcServerConfig13::with_signing_key(alloc::vec![der.clone()], ServerKey::Rsa(boxed))
                .with_no_cookie();

        let mut client = make_client13(&der);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-rsa", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        // App-data round-trip under RSA-PSS-signed CertificateVerify.
        client.send(b"ping-rsa").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-rsa");
    }

    /// DTLS 1.3 + ML-DSA-65 server certificate (draft-ietf-tls-mldsa):
    /// covers the post-quantum signing path in DTLS, mirroring the TLS
    /// `tls_mldsa_server_cert` test.
    #[test]
    fn loopback_mldsa65_cert() {
        use crate::tls::conn::ServerKey;

        let mut rng = HmacDrbg::<Sha256>::new(b"dtls13-mldsa-key", b"nonce", &[]);
        let (sk, _pk) = crate::mldsa::MlDsa65PrivateKey::generate(&mut rng);
        let name = DistinguishedName::common_name("dtls.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::MlDsa65(&sk),
            &name,
            &validity,
            1,
            false,
            &["dtls.example"],
        )
        .unwrap();
        let der = cert.to_der().to_vec();

        let server_cfg =
            PcServerConfig13::with_signing_key(alloc::vec![der.clone()], ServerKey::MlDsa65(sk))
                .with_no_cookie();

        let mut client = make_client13(&der);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-mldsa", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        // App-data round-trip under ML-DSA-signed CertificateVerify.
        client.send(b"ping-mldsa").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-mldsa");
    }

    /// SSLKEYLOGFILE plumbing for DTLS 1.3: client + server share a
    /// `WriterKeyLog<Vec<u8>>` sink; the captured log contains every
    /// TLS 1.3 label twice (once per peer) with matching secret bytes.
    /// Confirms DTLS picks up the keylog wiring through the shared
    /// `tls::Config` plumbing without a separate code path.
    #[test]
    fn keylog_loopback_agrees() {
        use crate::tls::WriterKeyLog;
        use alloc::collections::BTreeMap;
        use alloc::string::ToString;

        let buf: Vec<u8> = Vec::new();
        let sink = Arc::new(WriterKeyLog::new(buf));

        let (mut server_cfg, cert) = make_server13();
        server_cfg.key_log = Some(sink.clone());
        let server_cfg = server_cfg.with_no_cookie();

        let mut roots = RootCertStore::new();
        roots.add_der(cert.clone()).unwrap();
        let mut client_cfg = PcClientConfig13::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        client_cfg.key_log = Some(sink.clone());

        let mut crng = HmacDrbg::<Sha256>::new(b"dtls13-kl-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-kl-server", b"nonce", &[]);
        let mut client =
            DtlsClientConnection13::new(client_cfg, b"client-addr".to_vec(), &mut crng);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        drop(client);
        drop(server);

        let log_text: alloc::string::String = {
            let buf = sink.writer_lock_for_test();
            core::str::from_utf8(&buf).unwrap().to_string()
        };
        let want_labels = [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET",
        ];
        let mut per_label: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for line in log_text.lines() {
            let parts: Vec<&str> = line.split_ascii_whitespace().collect();
            assert_eq!(parts.len(), 3, "malformed keylog line: {line}");
            assert_eq!(parts[1].len(), 64);
            per_label.entry(parts[0]).or_default().push(parts[2]);
        }
        for label in want_labels {
            let entries = per_label
                .get(label)
                .unwrap_or_else(|| panic!("missing label {label} in keylog:\n{log_text}"));
            assert_eq!(
                entries.len(),
                2,
                "expected {label} twice, got {}",
                entries.len()
            );
            assert_eq!(entries[0], entries[1], "client/server disagree on {label}");
        }
    }

    #[test]
    fn application_data_both_ways() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-app", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        client.send(b"hello world").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"hello world");

        server.send(b"pong from server").unwrap();
        let s = server.pop_outbound_datagrams();
        for dg in &s {
            client.feed_datagram(dg).unwrap();
        }
        assert_eq!(client.take_received(), b"pong from server");
    }

    /// Verify that the on-wire sequence-number bytes differ from the
    /// plaintext seq: i.e. RFC 9147 §4.2.3 sequence-number obfuscation is
    /// actually applied (and the mask isn't all-zeros by coincidence).
    #[test]
    fn encrypted_seq_is_masked() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-mask", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        // Drive a few app-data records so we have multiple wire seq values
        // to inspect.
        for i in 0..4u8 {
            client.send(&[i; 8]).unwrap();
        }
        let datagrams = client.pop_outbound_datagrams();
        assert!(datagrams.len() >= 4);

        // First app-data record is at epoch 3, seq 0. The on-wire seq
        // bytes should be the seq XOR'd with the sn_mask. seq=0 means the
        // mask shows directly; if the mask is all-zero, on-wire would be
        // 0x00 0x00 — but with a real sn_key the mask is essentially random,
        // so at least one of the first records' wire seq bytes will be
        // non-zero.
        let mut any_nonzero_seq_byte = false;
        for dg in &datagrams {
            // Unified header: first byte's prefix bits must be 001.
            assert_eq!(dg[0] & 0b1110_0000, 0b0010_0000);
            // S bit set → 2-byte seq follows the first byte.
            if (dg[0] & 0b0000_1000) != 0 && (dg[1] != 0 || dg[2] != 0) {
                any_nonzero_seq_byte = true;
            }
        }
        assert!(
            any_nonzero_seq_byte,
            "expected at least one record to have a non-zero masked seq byte",
        );
    }

    /// ACK-driven retransmit: drop the server's final encrypted record
    /// (Finished), drive the client through the remaining records, then
    /// fire a timer on the server — it should retransmit only the missing
    /// records (everything still in its in-flight set).
    #[test]
    fn ack_driven_retransmit() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-ack-rt", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

        // Round 1: CH → server.
        let c1 = client.pop_outbound_datagrams();
        for dg in &c1 {
            server.feed_datagram(dg).unwrap();
        }
        // Server emits its full encrypted flight (SH plaintext + EE/Cert/
        // CV/Fin protected).
        let s1 = server.pop_outbound_datagrams();
        assert!(
            s1.len() >= 4,
            "server should have emitted multi-record flight"
        );
        // Drop the last record (server Finished). Deliver everything else.
        let dropped = s1.last().cloned().unwrap();
        for dg in &s1[..s1.len() - 1] {
            client.feed_datagram(dg).unwrap();
        }
        // Client should NOT yet be complete (didn't see Finished).
        assert!(!client.is_handshake_complete());
        // The client will have queued ACKs for the records it did receive.
        let c_ack = client.pop_outbound_datagrams();
        // Feed those ACKs to the server.
        for dg in &c_ack {
            server.feed_datagram(dg).unwrap();
        }
        // Server's in-flight set should now contain only the un-ACKed
        // Finished. Fire the retransmit timer.
        let deadline = server.next_timeout().expect("server timer armed");
        server.on_timeout(deadline);
        let retransmitted = server.pop_outbound_datagrams();
        assert!(!retransmitted.is_empty(), "server should retransmit");
        // The retransmitted set must contain the (dropped) Finished and
        // *only* records that haven't been ACKed yet — fewer than the
        // original flight.
        assert!(
            retransmitted.len() < s1.len(),
            "retransmit should drop ACKed records ({} < {})",
            retransmitted.len(),
            s1.len()
        );
        // Sanity: at least one of the retransmitted bytes matches the
        // dropped record (it's the only one still in the in-flight set).
        let contains_dropped = retransmitted.iter().any(|dg| dg == &dropped);
        assert!(
            contains_dropped,
            "retransmitted set should include the dropped server Finished"
        );
        // Deliver the retransmit and finish the handshake.
        for dg in &retransmitted {
            client.feed_datagram(dg).unwrap();
        }
        // Drain whatever the client emits in response and finish.
        for _ in 0..16 {
            let c = client.pop_outbound_datagrams();
            for dg in &c {
                server.feed_datagram(dg).unwrap();
            }
            let s = server.pop_outbound_datagrams();
            for dg in &s {
                client.feed_datagram(dg).unwrap();
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        assert!(client.is_handshake_complete());
        assert!(server.is_handshake_complete());
    }

    /// Multi-suite negotiation (RFC 8446 §4.1.1 / RFC 9147 §5): when the
    /// client advertises only `TLS_CHACHA20_POLY1305_SHA256`, the server
    /// must pick that suite. Confirms the sequence-number obfuscation
    /// (RFC 9147 §4.2.3) and record protection both work under ChaCha20.
    #[test]
    fn loopback_negotiates_chacha20() {
        use crate::tls::codec::CipherSuite;

        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut roots = RootCertStore::new();
        roots.add_der(cert.clone()).unwrap();
        let mut client_cfg = PcClientConfig13::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        client_cfg.cipher_suites = alloc::vec![CipherSuite::CHACHA20_POLY1305_SHA256];
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls13-cl-chacha", b"nonce", &[]);
        let mut client =
            DtlsClientConnection13::new(client_cfg, b"client-addr".to_vec(), &mut crng);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-srv-chacha", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));
        assert_eq!(client.negotiated_cipher_suite(), Some(0x1303));

        // App-data round-trip under ChaCha20-Poly1305 record protection.
        client.send(b"ping-chacha").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-chacha");

        server.send(b"pong-chacha").unwrap();
        let s = server.pop_outbound_datagrams();
        for dg in &s {
            client.feed_datagram(dg).unwrap();
        }
        assert_eq!(client.take_received(), b"pong-chacha");
    }

    /// Multi-suite negotiation: when the client advertises only
    /// `TLS_AES_256_GCM_SHA384`, the server must pick that suite, and
    /// the handshake transcript switches to SHA-384.
    #[test]
    fn loopback_negotiates_aes256_gcm() {
        use crate::tls::codec::CipherSuite;

        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut roots = RootCertStore::new();
        roots.add_der(cert.clone()).unwrap();
        let mut client_cfg = PcClientConfig13::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        client_cfg.cipher_suites = alloc::vec![CipherSuite::AES_256_GCM_SHA384];
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls13-cl-aes256", b"nonce", &[]);
        let mut client =
            DtlsClientConnection13::new(client_cfg, b"client-addr".to_vec(), &mut crng);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-srv-aes256", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));
        assert_eq!(client.negotiated_cipher_suite(), Some(0x1302));

        // App-data round-trip under AES-256-GCM record protection.
        client.send(b"ping-aes256").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-aes256");

        server.send(b"pong-aes256").unwrap();
        let s = server.pop_outbound_datagrams();
        for dg in &s {
            client.feed_datagram(dg).unwrap();
        }
        assert_eq!(client.take_received(), b"pong-aes256");
    }

    /// Server preference order: when the client offers all three suites
    /// (the default), the server picks `TLS_AES_128_GCM_SHA256` — the
    /// first entry in the server's `SUPPORTED` table.
    #[test]
    fn loopback_prefers_aes128_when_offered() {
        use crate::tls::codec::CipherSuite;

        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut roots = RootCertStore::new();
        roots.add_der(cert.clone()).unwrap();
        let mut client_cfg = PcClientConfig13::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        // Explicit default order: all three, AES-128 first.
        client_cfg.cipher_suites = alloc::vec![
            CipherSuite::AES_128_GCM_SHA256,
            CipherSuite::AES_256_GCM_SHA384,
            CipherSuite::CHACHA20_POLY1305_SHA256,
        ];
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls13-cl-all", b"nonce", &[]);
        let mut client =
            DtlsClientConnection13::new(client_cfg, b"client-addr".to_vec(), &mut crng);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-srv-all", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));
        assert_eq!(client.negotiated_cipher_suite(), Some(0x1301));
    }

    /// Multi-group negotiation (RFC 8446 §4.2.7-8): when the client offers
    /// only P-256, the server must derive the ECDHE shared secret over
    /// P-256 and the handshake must complete with an app-data round trip.
    #[test]
    fn negotiates_p256() {
        use crate::tls::codec::NamedGroup;

        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut roots = RootCertStore::new();
        roots.add_der(cert.clone()).unwrap();
        let mut client_cfg = PcClientConfig13::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        client_cfg.groups = alloc::vec![NamedGroup::SECP256R1];
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls13-cl-p256", b"nonce", &[]);
        let mut client =
            DtlsClientConnection13::new(client_cfg, b"client-addr".to_vec(), &mut crng);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-srv-p256", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        client.send(b"ping-p256").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-p256");
    }

    /// Multi-group negotiation: the client offers only SECP384R1, so
    /// both sides resolve to the P-384 ECDHE arm in DTLS 1.3.
    #[test]
    fn negotiates_p384() {
        use crate::tls::codec::NamedGroup;

        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut roots = RootCertStore::new();
        roots.add_der(cert.clone()).unwrap();
        let mut client_cfg = PcClientConfig13::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        client_cfg.groups = alloc::vec![NamedGroup::SECP384R1];
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls13-cl-p384", b"nonce", &[]);
        let mut client =
            DtlsClientConnection13::new(client_cfg, b"client-addr".to_vec(), &mut crng);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-srv-p384", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        client.send(b"ping-p384").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-p384");
    }

    /// Multi-group negotiation: the X25519+ML-KEM-768 hybrid
    /// (draft-ietf-tls-ecdhe-mlkem). Client offers only the hybrid; the
    /// server encapsulates against the client's ML-KEM key and the
    /// handshake completes with an app-data round trip.
    #[test]
    fn negotiates_mlkem768() {
        use crate::tls::codec::NamedGroup;

        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut roots = RootCertStore::new();
        roots.add_der(cert.clone()).unwrap();
        let mut client_cfg = PcClientConfig13::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        client_cfg.groups = alloc::vec![NamedGroup::X25519MLKEM768];
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls13-cl-mlkem", b"nonce", &[]);
        let mut client =
            DtlsClientConnection13::new(client_cfg, b"client-addr".to_vec(), &mut crng);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-srv-mlkem", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        client.send(b"ping-mlkem").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-mlkem");

        server.send(b"pong-mlkem").unwrap();
        let s = server.pop_outbound_datagrams();
        for dg in &s {
            client.feed_datagram(dg).unwrap();
        }
        assert_eq!(client.take_received(), b"pong-mlkem");
    }

    /// HRR-driven group upgrade (RFC 8446 §4.1.4): client offers all three
    /// groups in `supported_groups` but only sends a `key_share` for
    /// P-256. The server prefers X25519MLKEM768 and issues an HRR
    /// requesting that group; the client retries with the hybrid share
    /// and the handshake completes. With cookies disabled, the only HRR
    /// sent is the group-upgrade one.
    #[test]
    fn hrr_upgrades_group() {
        use crate::tls::codec::NamedGroup;

        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut roots = RootCertStore::new();
        roots.add_der(cert.clone()).unwrap();
        let mut client_cfg = PcClientConfig13::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        // Advertise all three groups; ship only a P-256 key_share so the
        // server has to HRR for its preferred (X25519MLKEM768) group.
        client_cfg.groups = alloc::vec![
            NamedGroup::X25519MLKEM768,
            NamedGroup::X25519,
            NamedGroup::SECP256R1,
        ];
        client_cfg.key_share_groups = Some(alloc::vec![NamedGroup::SECP256R1]);
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls13-cl-hrr", b"nonce", &[]);
        let mut client =
            DtlsClientConnection13::new(client_cfg, b"client-addr".to_vec(), &mut crng);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-srv-hrr", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        client.send(b"ping-hrr").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-hrr");
    }

    /// DTLS-2 / DTLS-4: the cookie-required CH1 path must NOT pin
    /// per-connection handshake state (suite, group, transcript). All such
    /// state must be derived from the cookie's `aux` payload on CH2.
    ///
    /// We exercise this by:
    ///   1. Driving CH1 → HRR(cookie) end-to-end so the server is in
    ///      `WaitSecondClientHello`.
    ///   2. Re-creating a fresh client (different random, different shape)
    ///      and feeding its CH1 to the server again. Because the server is
    ///      stateless across HRR, this second CH1 should also trigger HRR
    ///      with its own cookie, not error out due to stale state.
    ///   3. The originally-issued cookie carries (suite, group, Hash(CH1))
    ///      so the original client's CH2 still completes the handshake.
    #[test]
    fn cookie_round_does_not_pin_state() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-no-pin", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

        // CH1 → HRR(cookie).
        let c1 = client.pop_outbound_datagrams();
        assert!(!c1.is_empty(), "client should have emitted CH1");
        for dg in &c1 {
            server.feed_datagram(dg).unwrap();
        }
        let hrr = server.pop_outbound_datagrams();
        assert!(!hrr.is_empty(), "server should emit HRR with cookie");

        // Inject a *different* CH1 from a freshly-built client. If the
        // server pinned state on the first CH1, this would either error or
        // silently keep the old pinned suite/group; with the stateless
        // aux-cookie design, the server simply re-issues a cookie.
        let mut other_client = make_client13(&cert);
        let other_c1 = other_client.pop_outbound_datagrams();
        for dg in &other_c1 {
            server.feed_datagram(dg).unwrap();
        }
        let hrr2 = server.pop_outbound_datagrams();
        assert!(
            !hrr2.is_empty(),
            "server must re-issue HRR for the second client's CH1, not silently drop"
        );

        // Now deliver the original HRR to the original client and finish
        // the handshake. This proves the original cookie still works after
        // the server processed an interloper CH1.
        for dg in &hrr {
            client.feed_datagram(dg).unwrap();
        }
        assert!(pump_handshake_13(&mut client, &mut server));
    }

    /// DTLS-5: the cookie binds the CH content fingerprint (cipher_suites,
    /// supported_groups, supported_versions, key_share groups). A CH2 with
    /// rewritten cipher_suites fails cookie validation.
    ///
    /// We can't easily produce a CH2 with the right cookie but different
    /// suites from outside the layer, so we instead drive a real
    /// CH1→HRR(cookie) exchange and verify that the issued cookie's HMAC
    /// covers the CH content via the cookie generator directly.
    #[test]
    fn cookie_binds_ch_content_fingerprint() {
        use crate::dtls::cookie::{CookieGenerator, build_ch_fingerprint};

        // Use a fixed secret + addr + random so the cookie is deterministic.
        let cg = CookieGenerator::new([0x11; 32]);
        let addr = b"client";
        let rand = [0x77; 32];
        let fp1 = build_ch_fingerprint(b"\x13\x01\x13\x02", None, None, b"\x00\x1d");
        let fp2 = build_ch_fingerprint(b"\x13\x01", None, None, b"\x00\x1d");
        let ts = 12_345_u32;
        let cookie = cg.generate(addr, &rand, &fp1, ts);
        assert!(cg.validate(addr, &rand, &fp1, ts, &cookie));
        // A CH2 advertising a weaker suite list — same address, same
        // random, same TS, only `cipher_suites` differs — fails validation.
        assert!(!cg.validate(addr, &rand, &fp2, ts, &cookie));
    }

    /// DTLS-3: the cookie generator's `now_minutes` must advance even when
    /// no timeouts fire. `set_now` provides that hook.
    #[test]
    fn set_now_advances_cookie_clock() {
        use core::time::Duration;
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-set-now", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

        // Drive CH1 → HRR(cookie) at t=0.
        let c1 = client.pop_outbound_datagrams();
        for dg in &c1 {
            server.feed_datagram(dg).unwrap();
        }
        let hrr_at_zero = server.pop_outbound_datagrams();
        assert!(!hrr_at_zero.is_empty());

        // Advance the server's clock far enough that a cookie issued NOW
        // would have a different TS field than the one above. (Cookie TS
        // is in minutes, so we need at least a minute.)
        server.set_now(Duration::from_secs(60 * 5));

        // Drive CH1 from a fresh client. The server must use the new clock.
        let mut other_client = make_client13(&cert);
        let other_c1 = other_client.pop_outbound_datagrams();
        for dg in &other_c1 {
            server.feed_datagram(dg).unwrap();
        }
        let hrr_at_five = server.pop_outbound_datagrams();
        assert!(!hrr_at_five.is_empty());
        // The two cookies (with different TS) must differ.
        // We compare the raw HRR datagrams — the cookie extension is the
        // only varying field given fixed random/addr (and the random does
        // differ here, so the test is "at least different"). Strict
        // equality would only hold if we could pin the client randoms.
        assert_ne!(hrr_at_zero, hrr_at_five);

        // set_now is monotonic: rewinding is a no-op.
        server.set_now(Duration::from_secs(0));
        let mut third_client = make_client13(&cert);
        let third_c1 = third_client.pop_outbound_datagrams();
        for dg in &third_c1 {
            server.feed_datagram(dg).unwrap();
        }
        let hrr_after_rewind = server.pop_outbound_datagrams();
        assert!(!hrr_after_rewind.is_empty(), "clock rewind is a no-op");
    }

    /// DTLS-1 (DTLS 1.3 read path): a forged record with a fresh seq number
    /// that fails AEAD verification must NOT burn slots in the anti-replay
    /// window. After the forgery is rejected, legitimate records around the
    /// forged seq must still be accepted.
    ///
    /// This is enforced at the replay-window layer (see
    /// `replay::tests::forged_seq_does_not_burn_slots`); the server-level
    /// regression is that the `check`-then-AEAD-then-`mark` ordering is in
    /// place rather than the old `accept` (which marked unconditionally).
    /// We verify by completing a handshake, then sending a deliberately
    /// corrupted record from the server (tampered ciphertext = AEAD fail),
    /// and checking that a subsequent good record at a smaller seq still
    /// arrives. Without the fix, the bad record's seq would burn the slot
    /// and the good record would be dropped as a duplicate.
    #[test]
    fn forged_record_does_not_burn_replay_slot_dtls13() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-fwd", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        // Send legit record #1.
        server.send(b"one").unwrap();
        let s1 = server.pop_outbound_datagrams();
        assert_eq!(s1.len(), 1);

        // Now build a tampered version of a future record. We send #2 first
        // to get a baseline ciphertext, tamper it, deliver the tampered
        // version, and observe that the tampering is silently dropped
        // without recording the seq.
        server.send(b"two").unwrap();
        let s2 = server.pop_outbound_datagrams();
        assert_eq!(s2.len(), 1);
        let mut tampered = s2[0].clone();
        // Flip a byte deep inside the ciphertext payload (avoid the header
        // so the record parses).
        let mid = tampered.len() / 2;
        tampered[mid] ^= 1;

        // Deliver legit #1, then tampered #2, then legit #1 again as a
        // "replay" to confirm the window state.
        client.feed_datagram(&s1[0]).unwrap();
        assert_eq!(client.take_received(), b"one");

        // Tampered record: AEAD fails. The connection should ignore it
        // without erroring. We don't assert here on the exact behaviour
        // (some impls return Err, some Ok-with-drop); the key property is
        // that the slot is NOT marked.
        let _ = client.feed_datagram(&tampered);
        assert!(client.take_received().is_empty());

        // Deliver legit #2 (untampered): must be accepted, confirming the
        // tampered attempt didn't burn the slot for seq=#2.
        client.feed_datagram(&s2[0]).unwrap();
        assert_eq!(client.take_received(), b"two");
    }
}

/// DTLS 1.2 multi-suite negotiation tests (Phase 4). The server has an
/// ECDSA P-256 key, so only the three ECDSA entries of `SUITES_12` are
/// selectable end-to-end; the client may advertise all six.
mod dtls12 {
    use super::*;
    use crate::tls::codec::CipherSuite;

    /// Drive a client/server pair to completion. Returns whether both sides
    /// reported a complete handshake within the iteration cap.
    fn pump<R: crate::rng::RngCore>(
        client: &mut DtlsClientConnection12,
        server: &mut DtlsServerConnection12<R>,
    ) -> bool {
        super::pump_handshake(client, server)
    }

    /// Build a client whose ClientHello advertises only `suites`.
    fn client_with_suites(server_cert: &[u8], suites: Vec<CipherSuite>) -> DtlsClientConnection12 {
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert.to_vec()).unwrap();
        let mut cfg = PcClientConfig12::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        cfg.cipher_suites = suites;
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls12-multi-suite-cli", b"nonce", &[]);
        DtlsClientConnection12::new(cfg, b"client-addr".to_vec(), &mut crng)
    }

    /// Multi-suite negotiation (RFC 5246 §7.4.1.3 + RFC 6347 §4.2.1): when
    /// the client advertises only `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`,
    /// the server must pick that suite. Exercises ChaCha20-Poly1305 record
    /// protection on the DTLS path.
    #[test]
    fn negotiates_chacha20() {
        let (server_cfg, cert) = make_server();
        let server_cfg = server_cfg.require_cookie_exchange(false);
        let mut client = client_with_suites(
            &cert,
            alloc::vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256],
        );
        let srng = HmacDrbg::<Sha256>::new(b"dtls12-srv-chacha", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump(&mut client, &mut server));
        assert_eq!(
            client.negotiated_cipher_suite(),
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.0)
        );
        assert_eq!(
            server.negotiated_cipher_suite(),
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.0)
        );

        // App-data round-trip under ChaCha20-Poly1305.
        client.send(b"ping-chacha").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-chacha");

        server.send(b"pong-chacha").unwrap();
        let s = server.pop_outbound_datagrams();
        for dg in &s {
            client.feed_datagram(dg).unwrap();
        }
        assert_eq!(client.take_received(), b"pong-chacha");
    }

    /// Multi-suite negotiation: when the client advertises only
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, the server must pick that
    /// suite — exercising the SHA-384 transcript / PRF path along with
    /// AES-256-GCM record protection.
    #[test]
    fn negotiates_aes256_sha384() {
        let (server_cfg, cert) = make_server();
        let server_cfg = server_cfg.require_cookie_exchange(false);
        let mut client = client_with_suites(
            &cert,
            alloc::vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384],
        );
        let srng = HmacDrbg::<Sha256>::new(b"dtls12-srv-aes256", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump(&mut client, &mut server));
        assert_eq!(
            client.negotiated_cipher_suite(),
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.0)
        );
        assert_eq!(
            server.negotiated_cipher_suite(),
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.0)
        );

        // App-data round-trip under AES-256-GCM record protection +
        // SHA-384-derived keys.
        client.send(b"ping-sha384").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-sha384");

        server.send(b"pong-sha384").unwrap();
        let s = server.pop_outbound_datagrams();
        for dg in &s {
            client.feed_datagram(dg).unwrap();
        }
        assert_eq!(client.take_received(), b"pong-sha384");
    }

    /// Server preference order: when the client offers all three ECDSA
    /// entries of `SUITES_12`, the server picks `TLS_ECDHE_ECDSA_*_AES_128_GCM_SHA256`
    /// — the top of our preference table.
    #[test]
    fn prefers_aes128_when_offered() {
        let (server_cfg, cert) = make_server();
        let server_cfg = server_cfg.require_cookie_exchange(false);
        let mut client = client_with_suites(
            &cert,
            alloc::vec![
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            ],
        );
        let srng = HmacDrbg::<Sha256>::new(b"dtls12-srv-pref", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump(&mut client, &mut server));
        assert_eq!(
            client.negotiated_cipher_suite(),
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.0)
        );
        assert_eq!(
            server.negotiated_cipher_suite(),
            Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.0)
        );
    }

    /// Multi-group negotiation on DTLS 1.2: when the client advertises only
    /// `SECP256R1`, the server must complete the handshake by generating a
    /// P-256 ECDHE share and signing it in the ServerKeyExchange. Exercises
    /// the per-group dispatch in `on_client_hello_after_cookie` (key share
    /// generation), `signed_message` (SKE signing with `group = P-256`),
    /// and `on_client_key_exchange` (ECDH completion under P-256).
    #[test]
    fn negotiates_p256() {
        use crate::tls::codec::NamedGroup;

        let (server_cfg, cert) = make_server();
        let server_cfg = server_cfg.require_cookie_exchange(false);

        let mut roots = RootCertStore::new();
        roots.add_der(cert.clone()).unwrap();
        let mut client_cfg = PcClientConfig12::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        client_cfg.groups = alloc::vec![NamedGroup::SECP256R1];
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls12-p256-cli", b"nonce", &[]);
        let mut client =
            DtlsClientConnection12::new(client_cfg, b"client-addr".to_vec(), &mut crng);

        let srng = HmacDrbg::<Sha256>::new(b"dtls12-srv-p256", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump(&mut client, &mut server));

        // App-data round-trip on a P-256-derived master secret.
        client.send(b"ping-p256").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-p256");

        server.send(b"pong-p256").unwrap();
        let s = server.pop_outbound_datagrams();
        for dg in &s {
            client.feed_datagram(dg).unwrap();
        }
        assert_eq!(client.take_received(), b"pong-p256");
    }

    /// Build a DTLS 1.2 server fixture with an RSA-2048 signing key. The
    /// fixture issues a self-signed RSA leaf, advertises it to the
    /// `PcServerConfig12`, and returns both the config and the DER cert
    /// (the latter is used to seed the client's trust store).
    fn make_server_rsa() -> (PcServerConfig12, Vec<u8>) {
        use crate::rsa::BoxedRsaPrivateKey;
        use crate::test_util::rsa_test_key_a;

        let rsa_key = rsa_test_key_a();
        let boxed = BoxedRsaPrivateKey::from_pkcs1_der(&rsa_key.to_pkcs1_der()).unwrap();
        let name = DistinguishedName::common_name("dtls.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Rsa(&boxed),
            &name,
            &validity,
            1,
            false,
            &["dtls.example"],
        )
        .unwrap();
        let der = cert.to_der().to_vec();
        (
            PcServerConfig12::with_rsa(alloc::vec![der.clone()], boxed),
            der,
        )
    }

    /// DTLS 1.2 + RSA-2048 server certificate: the server signs its
    /// `ServerKeyExchange` under `rsa_pss_rsae_sha256` (RFC 8446 §4.2.3 /
    /// RFC 8447 IANA registry). With the client offering all six entries
    /// of `SUITES_12`, the RSA-keyed server must pick an `ECDHE-RSA-*`
    /// suite — driving the multi-sig dispatch in
    /// `send_server_key_exchange`.
    #[test]
    fn loopback_rsa_cert() {
        let (server_cfg, cert) = make_server_rsa();
        let server_cfg = server_cfg.require_cookie_exchange(false);
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls12-srv-rsa", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump(&mut client, &mut server));

        // The server's RSA key forces an ECDHE-RSA-* suite. Verify the
        // negotiated id is one of the three RSA entries of `SUITES_12`.
        let suite = client.negotiated_cipher_suite().expect("negotiated");
        assert!(
            suite == CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.0
                || suite == CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.0
                || suite == CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.0,
            "unexpected suite 0x{suite:04x}"
        );
        assert_eq!(server.negotiated_cipher_suite(), Some(suite));

        // App-data round-trip under the RSA-signed handshake.
        client.send(b"ping-rsa").unwrap();
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping-rsa");

        server.send(b"pong-rsa").unwrap();
        let s = server.pop_outbound_datagrams();
        for dg in &s {
            client.feed_datagram(dg).unwrap();
        }
        assert_eq!(client.take_received(), b"pong-rsa");
    }

    /// Multi-sig × multi-suite intersection: the client pins
    /// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` and the RSA-keyed
    /// server must select it — exercising the RSA-PSS signature path
    /// together with ChaCha20-Poly1305 record protection.
    #[test]
    fn loopback_ecdhe_rsa_chacha() {
        let (server_cfg, cert) = make_server_rsa();
        let server_cfg = server_cfg.require_cookie_exchange(false);
        let mut client = client_with_suites(
            &cert,
            alloc::vec![CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256],
        );
        let srng = HmacDrbg::<Sha256>::new(b"dtls12-srv-rsa-chacha", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump(&mut client, &mut server));
        assert_eq!(
            client.negotiated_cipher_suite(),
            Some(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.0)
        );
        assert_eq!(
            server.negotiated_cipher_suite(),
            Some(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.0)
        );
    }
}
