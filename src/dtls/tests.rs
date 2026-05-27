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
}
