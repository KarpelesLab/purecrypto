//! End-to-end loopback tests for the DTLS 1.2 client / server pair.
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
    DtlsClientConfig12, DtlsClientConnection12, DtlsServerConfig12, DtlsServerConnection12,
};

/// Build an ECDSA P-256 server config + the cert DER suitable for the
/// client's trust store.
fn make_server() -> (DtlsServerConfig12, Vec<u8>) {
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
        DtlsServerConfig12::with_ecdsa(alloc::vec![der.clone()], key),
        der,
    )
}

fn make_client(server_cert: &[u8]) -> DtlsClientConnection12 {
    let mut roots = RootCertStore::new();
    roots.add_der(server_cert.to_vec()).unwrap();
    let cfg = DtlsClientConfig12::new(roots, "dtls.example")
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
fn application_data_both_ways() {
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
