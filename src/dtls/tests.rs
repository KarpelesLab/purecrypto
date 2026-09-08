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
    make_client_named(server_cert, "dtls.example")
}

/// Like `make_client` but lets the test pick the SNI / hostname that the
/// client will require the server certificate to match.
fn make_client_named(server_cert: &[u8], server_name: &str) -> DtlsClientConnection12 {
    let mut roots = RootCertStore::new();
    roots.add_der(server_cert.to_vec()).unwrap();
    let cfg = PcClientConfig12::new(roots, server_name)
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

/// Server-authentication: the DTLS 1.2 client MUST reject a certificate whose
/// SAN/CN does not cover the requested `server_name`, even when the chain is
/// otherwise trusted. Without the hostname check a MITM presenting any cert
/// chaining to a trusted CA (e.g. a legit cert for `attacker.example`) would be
/// accepted for any target host.
#[test]
fn rejects_certificate_with_mismatched_hostname_12() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg.require_cookie_exchange(false);
    // Trust the server's (self-signed) cert as a root, but ask the client to
    // connect to a DIFFERENT name than the cert is issued for ("dtls.example").
    let mut client = make_client_named(&cert, "wrong.example");
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-badname", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

    // CH → server.
    let c1 = client.pop_outbound_datagrams();
    for dg in &c1 {
        server.feed_datagram(dg).unwrap();
    }
    // Server flight (SH/Cert/SKE/SHDone). Feeding the Certificate must make the
    // client fail closed because the leaf does not match "wrong.example".
    let s1 = server.pop_outbound_datagrams();
    assert!(!s1.is_empty(), "server should have emitted flight");
    let mut saw_err = false;
    for dg in &s1 {
        if client.feed_datagram(dg).is_err() {
            saw_err = true;
        }
    }
    assert!(
        saw_err,
        "client must reject a certificate that does not match the requested host"
    );
    assert!(
        !client.is_handshake_complete(),
        "handshake must not complete with a mismatched server certificate"
    );
}

/// Sanity counterpart to the rejection test: when the requested `server_name`
/// matches a SAN on the leaf, the handshake completes as normal.
#[test]
fn accepts_certificate_with_matching_hostname_12() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg.require_cookie_exchange(false);
    let mut client = make_client_named(&cert, "dtls.example");
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-goodname", b"nonce", &[]);
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

/// Regression (cookie max-age vs a never-driven clock), DTLS 1.2 flavour
/// of `dtls13::stale_ts_zero_cookie_rejected_without_caller_clock_13`:
/// under `std` a server whose sans-I/O clock was never driven stamps and
/// validates HelloVerifyRequest cookies with wall time, so a `TS = 0`
/// cookie is rejected as expired instead of validating forever.
#[cfg(feature = "std")]
#[test]
fn stale_ts_zero_cookie_rejected_without_caller_clock_12() {
    use core::time::Duration;
    let secret = [0x42u8; 32];

    // Server B: caller-driven clock pinned at t=0 → issues TS=0 cookies.
    let (cfg_b, cert) = make_server();
    let cfg_b = cfg_b
        .with_cookie_secret(secret)
        .require_cookie_exchange(true);
    let mut client = make_client(&cert);
    let rng_b = HmacDrbg::<Sha256>::new(b"dtls12-cookie-clk-b", b"nonce", &[]);
    let mut server_b = DtlsServerConnection12::new(Arc::new(cfg_b), b"client-addr".to_vec(), rng_b);
    server_b.set_now(Duration::from_secs(0));

    // CH1 → B → HVR(TS=0 cookie) → client → CH2 echoing the cookie.
    for dg in client.pop_outbound_datagrams() {
        server_b.feed_datagram(&dg).unwrap();
    }
    let hvr = server_b.pop_outbound_datagrams();
    assert!(!hvr.is_empty());
    for dg in &hvr {
        client.feed_datagram(dg).unwrap();
    }
    let ch2 = client.pop_outbound_datagrams();
    assert!(!ch2.is_empty());

    // Server A: same cookie secret + peer address, clock NEVER driven →
    // wall time. The TS=0 cookie is decades past the 10-minute window: it
    // must be rejected (no server flight, no error).
    let (cfg_a, _) = make_server();
    let cfg_a = cfg_a
        .with_cookie_secret(secret)
        .require_cookie_exchange(true);
    let rng_a = HmacDrbg::<Sha256>::new(b"dtls12-cookie-clk-a", b"nonce", &[]);
    let mut server_a = DtlsServerConnection12::new(Arc::new(cfg_a), b"client-addr".to_vec(), rng_a);
    for dg in &ch2 {
        assert_eq!(server_a.feed_datagram(dg), Ok(()));
    }
    assert!(
        server_a.pop_outbound_datagrams().is_empty(),
        "expired TS=0 cookie must be silently rejected under a wall clock"
    );

    // Control: the TS=0-clock server still accepts its own cookie.
    for dg in &ch2 {
        server_b.feed_datagram(dg).unwrap();
    }
    assert!(
        !server_b.pop_outbound_datagrams().is_empty(),
        "control: TS=0 cookie validates on the t=0 caller-clock server"
    );
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

/// Regression (retransmit GiveUp must not kill established connections):
/// after a completed DTLS 1.2 handshake, neither side may have a handshake
/// retransmit armed, and driving the clock through every backoff step must
/// produce no retransmissions and never flip the connection to Closed.
/// Previously the server registered its final CCS+Finished flight with the
/// timer-driven retransmit machine, re-emitted it on every backoff step,
/// and then GiveUp-closed the healthy connection ~2 minutes in.
#[test]
fn connection_survives_retransmit_backoff_after_handshake_12() {
    use core::time::Duration;
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg.require_cookie_exchange(false);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-backoff", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
    assert!(pump_handshake(&mut client, &mut server));

    // Once established, no handshake retransmit may be armed on either side.
    assert_eq!(client.next_timeout(), None, "client timer must be disarmed");
    assert_eq!(server.next_timeout(), None, "server timer must be disarmed");

    // Walk the clock far past every backoff step (1+2+4+8+16+32+60s).
    for i in 1..=8u64 {
        let t = Duration::from_secs(i * 120);
        client.on_timeout(t);
        server.on_timeout(t);
        assert!(
            client.pop_outbound_datagrams().is_empty(),
            "client must not retransmit after establishment"
        );
        assert!(
            server.pop_outbound_datagrams().is_empty(),
            "server must not retransmit after establishment"
        );
    }
    assert!(client.is_handshake_complete(), "client must stay Connected");
    assert!(server.is_handshake_complete(), "server must stay Connected");

    // The connection still carries application data both ways.
    client.send(b"still alive").unwrap();
    for dg in client.pop_outbound_datagrams() {
        server.feed_datagram(&dg).unwrap();
    }
    assert_eq!(server.take_received(), b"still alive");
    server.send(b"ack").unwrap();
    for dg in server.pop_outbound_datagrams() {
        client.feed_datagram(&dg).unwrap();
    }
    assert_eq!(client.take_received(), b"ack");
}

/// Pseudo-random garbage that does not resemble any valid DTLS record:
/// the first byte (11) routes it down the legacy-header path, where the
/// pseudo-random length bytes exceed `MAX_FRAGMENT` (RecordOverflow class).
fn garbage_datagram() -> Vec<u8> {
    (0..64u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect()
}

/// A syntactically valid 13-byte DTLS record header carrying a bogus
/// protocol version (wrong-version class).
fn wrong_version_record() -> Vec<u8> {
    alloc::vec![
        22u8, // handshake
        0xde, 0xad, // bogus version
        0x00, 0x00, // epoch 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x63, // seq = 99
        0x00, 0x04, // length 4
        0xaa, 0xbb, 0xcc, 0xdd,
    ]
}

/// A DTLS 1.2 plaintext handshake record whose fragment is too short to be
/// a handshake header (fragment-framing class, pre-authentication).
fn short_fragment_record() -> Vec<u8> {
    alloc::vec![
        22u8, // handshake
        0xfe, 0xfd, // DTLS 1.2
        0x00, 0x00, // epoch 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x63, // seq = 99
        0x00, 0x04, // length 4 (< 12-byte handshake header)
        0xaa, 0xbb, 0xcc, 0xdd,
    ]
}

/// Regression (RFC 6347 §4.1.2.7 — single-packet remote DoS): records an
/// off-path attacker can trivially spoof toward an ESTABLISHED DTLS 1.2
/// connection — (a) garbage, (b) a corrupted AEAD tag, (c) a wrong record
/// version — must be SILENTLY discarded (`feed_datagram` returns `Ok`), and
/// the connection must keep passing application data afterwards.
#[test]
fn spoofed_records_are_silently_dropped_12() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg.require_cookie_exchange(false);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-spoof", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
    assert!(pump_handshake(&mut client, &mut server));

    // (a) Garbage datagram: silently dropped on both sides.
    let garbage = garbage_datagram();
    assert_eq!(client.feed_datagram(&garbage), Ok(()));
    assert_eq!(server.feed_datagram(&garbage), Ok(()));

    // (b) Valid records with a corrupted AEAD tag: silently dropped.
    server.send(b"to-client").unwrap();
    let s = server.pop_outbound_datagrams();
    assert_eq!(s.len(), 1);
    let mut tampered_s = s[0].clone();
    let last = tampered_s.len() - 1;
    tampered_s[last] ^= 0x5a;
    assert_eq!(client.feed_datagram(&tampered_s), Ok(()));
    assert!(client.take_received().is_empty());

    client.send(b"to-server").unwrap();
    let c = client.pop_outbound_datagrams();
    assert_eq!(c.len(), 1);
    let mut tampered_c = c[0].clone();
    let last = tampered_c.len() - 1;
    tampered_c[last] ^= 0x5a;
    assert_eq!(server.feed_datagram(&tampered_c), Ok(()));
    assert!(server.take_received().is_empty());

    // (c) Wrong record version: silently dropped on both sides.
    let bad_version = wrong_version_record();
    assert_eq!(client.feed_datagram(&bad_version), Ok(()));
    assert_eq!(server.feed_datagram(&bad_version), Ok(()));

    // The untampered records still decrypt (the spoofs did not burn the
    // replay slots or any connection state).
    client.feed_datagram(&s[0]).unwrap();
    assert_eq!(client.take_received(), b"to-client");
    server.feed_datagram(&c[0]).unwrap();
    assert_eq!(server.take_received(), b"to-server");

    // And fresh application data keeps flowing both ways.
    client.send(b"still alive c2s").unwrap();
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    assert_eq!(server.take_received(), b"still alive c2s");
    server.send(b"still alive s2c").unwrap();
    for dg in &server.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    assert_eq!(client.take_received(), b"still alive s2c");
}

/// Regression (RFC 6347 §4.1.2.7): spoofed garbage / wrong-version /
/// short-fragment records injected while the DTLS 1.2 handshake is still
/// IN PROGRESS must not abort it — the handshake completes regardless.
#[test]
fn spoofed_records_during_handshake_are_ignored_12() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg.require_cookie_exchange(false);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-spoof-hs", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

    let spoofs = [
        garbage_datagram(),
        wrong_version_record(),
        short_fragment_record(),
    ];
    // Interleave spoofed datagrams with every legitimate flight.
    for _ in 0..32 {
        for sp in &spoofs {
            assert_eq!(client.feed_datagram(sp), Ok(()));
            assert_eq!(server.feed_datagram(sp), Ok(()));
        }
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
    assert!(client.is_handshake_complete());
    assert!(server.is_handshake_complete());
}

/// Regression (D1, RFC 6347 §4.1.2.7): well-framed plaintext ClientHellos
/// that fail handshake-layer validation — (a) a forged cookie (here: a
/// corrupted client random, which breaks the cookie's HMAC binding), (b) an
/// oversized `message_seq` — are exactly as spoofable as record-layer
/// garbage. Injected mid-handshake they must be SILENTLY dropped
/// (`feed_datagram` returns `Ok`), emit no server flight, and the genuine
/// handshake must still complete.
#[test]
fn spoofed_client_hellos_mid_handshake_are_ignored_12() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg
        .with_cookie_secret([0xa5; 32])
        .require_cookie_exchange(true);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-server-spoof-ch", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

    // CH1 → server → HelloVerifyRequest → client.
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    let hvr = server.pop_outbound_datagrams();
    assert!(!hvr.is_empty(), "server should emit HVR");
    for dg in &hvr {
        client.feed_datagram(dg).unwrap();
    }
    // The genuine cookie-bearing CH2 — hold it back while we spoof.
    let ch2 = client.pop_outbound_datagrams();
    assert!(!ch2.is_empty(), "client should emit CH2");

    // (a) CH2 with a corrupted client random: the cookie (which binds the
    // random) no longer validates — equivalent to a forged cookie. Offset
    // 27 = record header (13) + handshake header (12) + legacy_version (2).
    let mut bad_cookie = ch2[0].clone();
    bad_cookie[27] ^= 0x5a;
    assert_eq!(server.feed_datagram(&bad_cookie), Ok(()));
    assert!(
        server.pop_outbound_datagrams().is_empty(),
        "no flight may be emitted for a forged-cookie CH"
    );

    // (b) CH2 with an implausibly large `message_seq` (offset 17 = record
    // header (13) + msg_type (1) + length (3)).
    let mut big_seq = ch2[0].clone();
    big_seq[17] = 0xff;
    big_seq[18] = 0xff;
    assert_eq!(server.feed_datagram(&big_seq), Ok(()));
    assert!(
        server.pop_outbound_datagrams().is_empty(),
        "no flight may be emitted for an oversized-message_seq CH"
    );

    // The genuine CH2 still drives the handshake to completion.
    for dg in &ch2 {
        server.feed_datagram(dg).unwrap();
    }
    assert!(pump_handshake(&mut client, &mut server));
}

/// Frames a single plaintext (epoch-0) DTLS 1.2 handshake message into one
/// record, with the DTLS handshake header (`msg_type || length(3) ||
/// message_seq(2) || fragment_offset(3) || fragment_length(3) || body`).
/// Used to forge spoofed handshake records an off-path attacker could inject.
fn dtls12_plaintext_handshake_record(msg_type: u8, message_seq: u16, body: &[u8]) -> Vec<u8> {
    let blen = body.len() as u32;
    let mut hs = Vec::new();
    hs.push(msg_type);
    hs.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
    hs.extend_from_slice(&message_seq.to_be_bytes());
    hs.extend_from_slice(&[0, 0, 0]); // fragment_offset = 0
    hs.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]); // fragment_length
    hs.extend_from_slice(body);

    let rlen = hs.len() as u16;
    let mut rec = Vec::new();
    rec.push(22u8); // ContentType::Handshake
    rec.extend_from_slice(&[0xfe, 0xfd]); // DTLS 1.2
    rec.extend_from_slice(&[0x00, 0x00]); // epoch 0
    rec.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x63]); // seq = 99
    rec.extend_from_slice(&rlen.to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// Regression (off-path one-datagram DoS / handshake derail): once the DTLS
/// 1.2 client has consumed its (genuine) HelloVerifyRequest, a SECOND HVR —
/// duplicate or off-path spoofed — must be IGNORED. A real HVR resets the
/// transcript, adopts the cookie, advances state and bumps the reassembler;
/// re-applying any of that on a second HVR would derail the in-flight second
/// flight (e.g. discard a just-received genuine ServerHello). Also: a
/// malformed spoofed HVR is silently dropped (never fatal). The genuine
/// handshake must still complete after all the spoof injections.
#[test]
fn spoofed_hello_verify_request_does_not_derail_client_12() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg
        .with_cookie_secret([0xa5; 32])
        .require_cookie_exchange(true);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-spoof-hvr", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

    // CH1 → server → genuine HVR → client. The client adopts the real cookie
    // and emits the cookie-bearing CH2.
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    let genuine_hvr = server.pop_outbound_datagrams();
    assert!(!genuine_hvr.is_empty(), "server should emit HVR");
    for dg in &genuine_hvr {
        client.feed_datagram(dg).unwrap();
    }
    let ch2 = client.pop_outbound_datagrams();
    assert!(
        !ch2.is_empty(),
        "client should emit a genuine cookie-bearing CH2 after the real HVR"
    );

    // A second, forged HVR carrying the attacker's cookie (well-formed body:
    // server_version(2) || cookie<len>). It must be ignored: no new CH2, no
    // transcript/state reset — and `feed_datagram` stays `Ok`.
    let mut forged_body = Vec::new();
    forged_body.extend_from_slice(&[0xfe, 0xfd]); // server_version
    forged_body.push(8u8); // cookie length
    forged_body.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
    let forged_hvr = dtls12_plaintext_handshake_record(3, 0, &forged_body); // 3 = HVR
    assert_eq!(client.feed_datagram(&forged_hvr), Ok(()));
    assert!(
        client.pop_outbound_datagrams().is_empty(),
        "a second/duplicate HVR must be ignored, not re-applied"
    );

    // A malformed spoofed HVR (truncated body: claims a cookie but supplies
    // no bytes) is silently dropped, never fatal.
    let malformed_hvr = dtls12_plaintext_handshake_record(3, 0, &[0xfe, 0xfd, 0x08]);
    assert_eq!(client.feed_datagram(&malformed_hvr), Ok(()));
    assert!(client.pop_outbound_datagrams().is_empty());

    // The genuine CH2 still drives the handshake to completion.
    for dg in &ch2 {
        server.feed_datagram(dg).unwrap();
    }
    assert!(pump_handshake(&mut client, &mut server));
}

/// Regression (off-path one-datagram DoS): a well-framed spoofed plaintext
/// ServerHello carrying a non-offered cipher suite (which fails
/// handshake-layer validation → HandshakeFailure) injected at the DTLS 1.2
/// client mid-handshake must be SILENTLY dropped, not propagated fatally; the
/// genuine handshake still completes.
#[test]
fn spoofed_server_hello_does_not_abort_client_12() {
    let (server_cfg, cert) = make_server();
    let server_cfg = server_cfg.require_cookie_exchange(false);
    let mut client = make_client(&cert);
    let srng = HmacDrbg::<Sha256>::new(b"dtls12-spoof-sh", b"nonce", &[]);
    let mut server =
        DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

    // Forge a ServerHello body the client will reject at the handshake layer:
    // legacy_version(2) || random(32) || session_id<0> || cipher_suite(2) ||
    // compression(1) || extensions<0>. cipher_suite = 0x0000
    // (TLS_NULL_WITH_NULL_NULL) is never offered → HandshakeFailure.
    let mut sh_body = Vec::new();
    sh_body.extend_from_slice(&[0xfe, 0xfd]); // legacy_version DTLS 1.2
    sh_body.extend_from_slice(&[0x11; 32]); // random
    sh_body.push(0); // session_id length 0
    sh_body.extend_from_slice(&[0x00, 0x00]); // cipher_suite (non-offered)
    sh_body.push(0); // compression_method = null
    sh_body.extend_from_slice(&[0x00, 0x00]); // extensions length 0
    // The client awaits SH at message_seq 0 (no-cookie path).
    let forged_sh = dtls12_plaintext_handshake_record(2, 0, &sh_body); // 2 = ServerHello

    // Inject the forged ServerHello at the very start, while the client is in
    // WaitServerHelloOrHvr: it must be silently dropped.
    assert_eq!(client.feed_datagram(&forged_sh), Ok(()));

    // The handshake still completes with the genuine server.
    assert!(pump_handshake(&mut client, &mut server));
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

    /// Regression (D1, RFC 9147 §4.5.2): well-framed plaintext ClientHellos
    /// that fail handshake-layer validation — (a) a forged cookie (here: a
    /// corrupted client random, which breaks the cookie's HMAC binding),
    /// (b) an oversized `message_seq` — are exactly as spoofable as
    /// record-layer garbage. Injected mid-handshake they must be SILENTLY
    /// dropped (`feed_datagram` returns `Ok`), emit no server flight, and
    /// the genuine handshake must still complete.
    #[test]
    fn spoofed_client_hellos_mid_handshake_are_ignored_13() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-spoof-ch", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

        // CH1 (possibly fragmented across datagrams) → server → HRR(cookie).
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        let hrr = server.pop_outbound_datagrams();
        assert!(!hrr.is_empty(), "server should emit cookie HRR");
        for dg in &hrr {
            client.feed_datagram(dg).unwrap();
        }
        // The genuine cookie-bearing CH2 — hold it back while we spoof.
        let ch2 = client.pop_outbound_datagrams();
        assert!(!ch2.is_empty(), "client should emit CH2");

        // (a) Full CH2 with a corrupted client random: the cookie (which
        // binds the random) no longer validates — equivalent to a forged
        // cookie. Corrupt the first fragment (fragment_offset 0 carries the
        // random at offset 27 = record header (13) + handshake header (12)
        // + legacy_version (2)) and deliver every fragment so the
        // reassembled CH reaches cookie validation.
        let mut tampered = ch2.clone();
        tampered[0][27] ^= 0x5a;
        for dg in &tampered {
            assert_eq!(server.feed_datagram(dg), Ok(()));
        }
        assert!(
            server.pop_outbound_datagrams().is_empty(),
            "no flight may be emitted for a forged-cookie CH"
        );

        // (b) A CH fragment with an implausibly large `message_seq`
        // (offset 17 = record header (13) + msg_type (1) + length (3)).
        let mut big_seq = ch2[0].clone();
        big_seq[17] = 0xff;
        big_seq[18] = 0xff;
        assert_eq!(server.feed_datagram(&big_seq), Ok(()));
        assert!(
            server.pop_outbound_datagrams().is_empty(),
            "no flight may be emitted for an oversized-message_seq CH"
        );

        // The genuine CH2 still drives the handshake to completion.
        for dg in &ch2 {
            server.feed_datagram(dg).unwrap();
        }
        assert!(pump_handshake_13(&mut client, &mut server));
    }

    /// Regression (D2): a pre-cookie ClientHello fragment claiming an
    /// enormous `total_length` must be dropped without seeding a large
    /// reassembly buffer — the pre-state reassembler runs BEFORE any
    /// address validation, so the default 256 KiB × 8-message budget would
    /// let ~2 MiB be pinned by a few spoofed one-byte fragments. The drop
    /// is silent, and a genuine handshake on the same connection still
    /// completes afterwards. (The legitimate fragmented-CH path — e.g. a
    /// multi-share ML-KEM offer — is covered by the default-group loopback
    /// tests above.)
    #[test]
    fn oversized_pre_cookie_ch_claim_is_dropped_13() {
        // A plaintext epoch-0 handshake record carrying one CH fragment
        // that claims total_length = 64 KiB with a 16-byte body.
        let mut frag = alloc::vec![
            0x01, // client_hello
            0x01, 0x00, 0x00, // total_length = 0x010000 (64 KiB)
            0x00, 0x00, // message_seq = 0
            0x00, 0x00, 0x00, // fragment_offset = 0
            0x00, 0x00, 0x10, // fragment_length = 16
        ];
        frag.extend_from_slice(&[0xab; 16]);
        let mut spoof = alloc::vec![
            22u8, // handshake
            0xfe,
            0xfd, // DTLS 1.2 wire version
            0x00,
            0x00, // epoch 0
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x07, // seq
            0x00,
            frag.len() as u8, // length
        ];
        spoof.extend_from_slice(&frag);

        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-bigclaim", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

        // The oversized claim is silently dropped — no flight, no error.
        assert_eq!(server.feed_datagram(&spoof), Ok(()));
        assert!(server.pop_outbound_datagrams().is_empty());

        // The genuine handshake (cookie roundtrip included) still works.
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
        // Exactly the dropped server Finished is re-sent — re-encrypted
        // under a FRESH record number (RFC 9147 §4.5.3), so it is the same
        // size as the original but never a byte-for-byte copy (which the
        // client's replay window would have discarded — DTLS-L3).
        assert_eq!(retransmitted.len(), 1);
        assert_eq!(retransmitted[0].len(), dropped.len());
        assert_ne!(
            retransmitted[0], dropped,
            "retransmit reused the record number"
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

    /// Regression (RFC 9147 §7): received ACK records must NOT themselves
    /// be acknowledged. Two of these endpoints previously locked into a
    /// perpetual encrypted ACK ping-pong — every ACK provoked an ACK in
    /// return. After the handshake completes, the exchange must quiesce.
    #[test]
    fn no_ack_of_ack_ping_pong_13() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-ackack", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        // Keep exchanging whatever is queued: the flow must die out within
        // a couple of rounds instead of ping-ponging ACK-of-ACKs forever.
        let mut quiesced = false;
        for _ in 0..4 {
            let c = client.pop_outbound_datagrams();
            for dg in &c {
                server.feed_datagram(dg).unwrap();
            }
            let s = server.pop_outbound_datagrams();
            for dg in &s {
                client.feed_datagram(dg).unwrap();
            }
            if c.is_empty() && s.is_empty() {
                quiesced = true;
                break;
            }
        }
        assert!(
            quiesced,
            "post-handshake ACK exchange must quiesce: an ACK is never ACKed"
        );
    }

    /// RFC 9147 / RFC 8446 §6.1: an authenticated close_notify from the
    /// peer is a clean shutdown — the connection leaves the Connected
    /// state and refuses further sends, with no error surfaced.
    #[test]
    fn close_notify_closes_connection_13() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-closenotify", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        // Server → client: warning-level close_notify (level 1, desc 0).
        server.send_alert_record_for_test(1, 0);
        for dg in server.pop_outbound_datagrams() {
            // Clean shutdown: no error surfaced.
            client.feed_datagram(&dg).unwrap();
        }
        assert!(
            !client.is_handshake_complete(),
            "close_notify must leave the Connected state"
        );
        assert!(
            client.send(b"after close").is_err(),
            "sends after close_notify must be refused"
        );

        // And the mirror direction: client → server.
        let (server_cfg2, cert2) = make_server13();
        let server_cfg2 = server_cfg2.with_no_cookie();
        let mut client2 = make_client13(&cert2);
        let srng2 = HmacDrbg::<Sha256>::new(b"dtls13-server-closenotify2", b"nonce", &[]);
        let mut server2 =
            DtlsServerConnection13::new(Arc::new(server_cfg2), b"client-addr".to_vec(), srng2);
        assert!(pump_handshake_13(&mut client2, &mut server2));
        client2.send_alert_record_for_test(1, 0);
        for dg in client2.pop_outbound_datagrams() {
            server2.feed_datagram(&dg).unwrap();
        }
        assert!(!server2.is_handshake_complete());
        assert!(server2.send(b"after close").is_err());
    }

    /// RFC 8446 §6: every alert other than close_notify is fatal in (D)TLS
    /// 1.3 — the receiver must surface `Error::AlertReceived` and close.
    /// Previously authenticated alerts were decrypted and silently
    /// discarded.
    #[test]
    fn fatal_alert_surfaces_error_13() {
        use crate::tls::{AlertDescription, Error};
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-fatalalert", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        // Client → server: fatal handshake_failure (level 2, desc 40).
        client.send_alert_record_for_test(2, 40);
        let mut got = None;
        for dg in client.pop_outbound_datagrams() {
            if let Err(e) = server.feed_datagram(&dg) {
                got = Some(e);
            }
        }
        assert_eq!(
            got,
            Some(Error::AlertReceived(AlertDescription::HandshakeFailure))
        );
        assert!(!server.is_handshake_complete());
        assert!(server.send(b"after fatal alert").is_err());
    }

    /// Regression (cookie max-age vs a never-driven clock): with the
    /// sans-I/O clock never driven, cookies used to be issued AND validated
    /// at `TS = 0`, which disabled the 10-minute max-age replay bound
    /// entirely. Under `std` the server now falls back to wall time, so a
    /// cookie stamped `TS = 0` is rejected as expired (silent drop — the
    /// epoch-0 path is spoofable), while a server whose caller pinned the
    /// clock at t=0 still accepts it.
    #[cfg(feature = "std")]
    #[test]
    fn stale_ts_zero_cookie_rejected_without_caller_clock_13() {
        use core::time::Duration;
        let secret = [0x42u8; 32];

        // Server B: caller-driven clock pinned at t=0 → issues TS=0 cookies.
        let (cfg_b, cert) = make_server13();
        let cfg_b = cfg_b.with_cookie_secret(secret);
        let mut client = make_client13(&cert);
        let rng_b = HmacDrbg::<Sha256>::new(b"dtls13-cookie-clk-b", b"nonce", &[]);
        let mut server_b =
            DtlsServerConnection13::new(Arc::new(cfg_b), b"client-addr".to_vec(), rng_b);
        server_b.set_now(Duration::from_secs(0));

        // CH1 → B → HRR(TS=0 cookie) → client → CH2 echoing the cookie.
        for dg in client.pop_outbound_datagrams() {
            server_b.feed_datagram(&dg).unwrap();
        }
        let hrr = server_b.pop_outbound_datagrams();
        assert!(!hrr.is_empty());
        for dg in &hrr {
            client.feed_datagram(dg).unwrap();
        }
        let ch2 = client.pop_outbound_datagrams();
        assert!(!ch2.is_empty());

        // Server A: same cookie secret + peer address, clock NEVER driven →
        // wall time. The TS=0 cookie is decades past the 10-minute window:
        // it must be rejected (no server flight, no error).
        let (cfg_a, _) = make_server13();
        let cfg_a = cfg_a.with_cookie_secret(secret);
        let rng_a = HmacDrbg::<Sha256>::new(b"dtls13-cookie-clk-a", b"nonce", &[]);
        let mut server_a =
            DtlsServerConnection13::new(Arc::new(cfg_a), b"client-addr".to_vec(), rng_a);
        for dg in &ch2 {
            assert_eq!(server_a.feed_datagram(dg), Ok(()));
        }
        assert!(
            server_a.pop_outbound_datagrams().is_empty(),
            "expired TS=0 cookie must be silently rejected under a wall clock"
        );

        // Control: the TS=0-clock server still accepts its own cookie.
        for dg in &ch2 {
            server_b.feed_datagram(dg).unwrap();
        }
        assert!(
            !server_b.pop_outbound_datagrams().is_empty(),
            "control: TS=0 cookie validates on the t=0 caller-clock server"
        );
    }

    /// Regression (retransmit GiveUp must not kill established connections):
    /// after a completed DTLS 1.3 handshake, neither side may have a
    /// handshake retransmit armed (the client's epoch-0 ClientHello is
    /// implicitly acknowledged by the ServerHello, the server's epoch-0
    /// ServerHello by the client's first authenticated record, and the
    /// whole server flight by the client Finished — RFC 9147 §7.1).
    /// Previously the epoch-0 records were never released, the timer kept
    /// firing after establishment, and both roles GiveUp-closed every
    /// connection ~2 minutes in.
    #[test]
    fn connection_survives_retransmit_backoff_after_handshake_13() {
        use core::time::Duration;
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-backoff", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        // Once established (and the final ACK delivered), no handshake
        // retransmit may be armed on either side.
        assert_eq!(client.next_timeout(), None, "client timer must be disarmed");
        assert_eq!(server.next_timeout(), None, "server timer must be disarmed");

        // Walk the clock far past every backoff step (1+2+4+8+16+32+60s).
        for i in 1..=8u64 {
            let t = Duration::from_secs(i * 120);
            client.on_timeout(t);
            server.on_timeout(t);
            assert!(
                client.pop_outbound_datagrams().is_empty(),
                "client must not retransmit after establishment"
            );
            assert!(
                server.pop_outbound_datagrams().is_empty(),
                "server must not retransmit after establishment"
            );
        }
        assert!(client.is_handshake_complete(), "client must stay Connected");
        assert!(server.is_handshake_complete(), "server must stay Connected");

        // The connection still carries application data both ways.
        client.send(b"still alive").unwrap();
        for dg in client.pop_outbound_datagrams() {
            server.feed_datagram(&dg).unwrap();
        }
        assert_eq!(server.take_received(), b"still alive");
        server.send(b"ack").unwrap();
        for dg in server.pop_outbound_datagrams() {
            client.feed_datagram(&dg).unwrap();
        }
        assert_eq!(client.take_received(), b"ack");
    }

    /// Regression (GiveUp guard): when the server's final ACK (covering the
    /// client Finished) is lost, the client legitimately keeps Finished in
    /// flight and retransmits it through the full backoff schedule — but
    /// exhausting the retransmit cap must NOT close the established
    /// connection.
    #[test]
    fn lost_final_ack_does_not_close_established_client_13() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-lostack", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

        // CH → server; full server flight → client; client Finished (+ACKs)
        // → server. Then DROP the server's final output (its ACK of the
        // client Finished).
        for dg in client.pop_outbound_datagrams() {
            server.feed_datagram(&dg).unwrap();
        }
        for dg in server.pop_outbound_datagrams() {
            client.feed_datagram(&dg).unwrap();
        }
        for dg in client.pop_outbound_datagrams() {
            server.feed_datagram(&dg).unwrap();
        }
        let dropped = server.pop_outbound_datagrams();
        assert!(!dropped.is_empty(), "server should have queued the ACK");
        assert!(client.is_handshake_complete());
        assert!(server.is_handshake_complete());

        // The unACKed Finished keeps the client's timer armed; drive it
        // through every retransmit and the final GiveUp.
        let mut fired = 0;
        while let Some(t) = client.next_timeout() {
            client.on_timeout(t);
            let _ = client.pop_outbound_datagrams();
            fired += 1;
            assert!(fired <= 16, "retransmit schedule must terminate");
        }
        assert!(
            client.is_handshake_complete(),
            "GiveUp must not close an established connection"
        );
        assert_eq!(client.next_timeout(), None);

        // And the connection still works.
        client.send(b"ping").unwrap();
        for dg in client.pop_outbound_datagrams() {
            server.feed_datagram(&dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping");
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

    /// A unified-header record claiming a Connection ID (unsupported —
    /// header layout becomes unparseable for us).
    fn cid_record() -> Vec<u8> {
        let mut v = alloc::vec![0x3Cu8]; // 001 C=1 S=1 L=1 EE=00
        v.extend_from_slice(&[0u8; 24]);
        v
    }

    /// A unified-header record whose declared body is smaller than the
    /// 16-byte AEAD tag (bogus by construction).
    fn short_body_record() -> Vec<u8> {
        // 0x2C = 001 C=0 S=1 L=1 EE=00; seq=0xBEEF, length=5.
        alloc::vec![0x2Cu8, 0xBE, 0xEF, 0x00, 0x05, 1, 2, 3, 4, 5]
    }

    /// A well-formed unified-header record at a wrong epoch (low 2 bits =
    /// 01 — neither the handshake epoch 2 nor the application epoch 3).
    fn wrong_epoch_record() -> Vec<u8> {
        let mut v = alloc::vec![0x2Du8, 0x12, 0x34, 0x00, 0x14]; // len 20
        v.extend_from_slice(&[0x42u8; 20]);
        v
    }

    /// Regression (RFC 9147 §4.5.2 — single-packet remote DoS): records an
    /// off-path attacker can trivially spoof toward an ESTABLISHED DTLS 1.3
    /// connection — (a) garbage, (b) a corrupted AEAD tag, (c) a wrong
    /// record version, plus malformed / wrong-epoch unified headers — must
    /// be SILENTLY discarded (`feed_datagram` returns `Ok`), and the
    /// connection must keep passing application data afterwards.
    #[test]
    fn spoofed_records_are_silently_dropped_13() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-spoof", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake_13(&mut client, &mut server));

        // Drop any residual post-handshake ACK records still queued so the
        // datagram counts below are exact.
        let _ = client.pop_outbound_datagrams();
        let _ = server.pop_outbound_datagrams();

        // (a) Garbage + malformed unified headers: silently dropped.
        for sp in [
            garbage_datagram(),
            cid_record(),
            short_body_record(),
            wrong_epoch_record(),
        ] {
            assert_eq!(client.feed_datagram(&sp), Ok(()));
            assert_eq!(server.feed_datagram(&sp), Ok(()));
        }

        // (b) Valid records with a corrupted AEAD tag: silently dropped.
        server.send(b"to-client").unwrap();
        let s = server.pop_outbound_datagrams();
        assert_eq!(s.len(), 1);
        let mut tampered_s = s[0].clone();
        let last = tampered_s.len() - 1;
        tampered_s[last] ^= 0x5a;
        assert_eq!(client.feed_datagram(&tampered_s), Ok(()));
        assert!(client.take_received().is_empty());

        client.send(b"to-server").unwrap();
        let c = client.pop_outbound_datagrams();
        assert_eq!(c.len(), 1);
        let mut tampered_c = c[0].clone();
        let last = tampered_c.len() - 1;
        tampered_c[last] ^= 0x5a;
        assert_eq!(server.feed_datagram(&tampered_c), Ok(()));
        assert!(server.take_received().is_empty());

        // (c) Wrong record version on the legacy-header path, and a
        // spoofed plaintext handshake record post-handshake: dropped.
        for sp in [wrong_version_record(), short_fragment_record()] {
            assert_eq!(client.feed_datagram(&sp), Ok(()));
            assert_eq!(server.feed_datagram(&sp), Ok(()));
        }

        // The untampered records still decrypt (the spoofs did not burn
        // the replay slots or any connection state).
        client.feed_datagram(&s[0]).unwrap();
        assert_eq!(client.take_received(), b"to-client");
        server.feed_datagram(&c[0]).unwrap();
        assert_eq!(server.take_received(), b"to-server");

        // And fresh application data keeps flowing both ways.
        client.send(b"still alive c2s").unwrap();
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"still alive c2s");
        server.send(b"still alive s2c").unwrap();
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        assert_eq!(client.take_received(), b"still alive s2c");
    }

    /// Regression (RFC 9147 §4.5.2): spoofed garbage / wrong-version /
    /// malformed-unified-header records injected while the DTLS 1.3
    /// handshake is still IN PROGRESS must not abort it.
    #[test]
    fn spoofed_records_during_handshake_are_ignored_13() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-server-spoof-hs", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

        let spoofs = [
            garbage_datagram(),
            wrong_version_record(),
            short_fragment_record(),
            cid_record(),
            short_body_record(),
            wrong_epoch_record(),
        ];
        // Interleave spoofed datagrams with every legitimate flight.
        for _ in 0..32 {
            for sp in &spoofs {
                assert_eq!(client.feed_datagram(sp), Ok(()));
                assert_eq!(server.feed_datagram(sp), Ok(()));
            }
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
        assert!(client.is_handshake_complete());
        assert!(server.is_handshake_complete());
    }

    /// Regression (off-path one-datagram DoS / derail): a well-framed spoofed
    /// plaintext ServerHello carrying a non-offered cipher suite (which fails
    /// handshake-layer validation → HandshakeFailure) injected at the DTLS 1.3
    /// client while it awaits ServerHello must be SILENTLY dropped, not
    /// propagated fatally, and must not advance the reassembler past the
    /// genuine ServerHello (same message_seq). The genuine handshake still
    /// completes.
    #[test]
    fn spoofed_server_hello_does_not_abort_client_13() {
        let (server_cfg, cert) = make_server13();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-spoof-sh", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);

        // Forge a TLS 1.3 ServerHello body the client rejects at the handshake
        // layer: legacy_version(2) || random(32) || session_id<0> ||
        // cipher_suite(2) || compression(1) || extensions<0>. cipher_suite =
        // 0x0000 is never offered → HandshakeFailure. (A random != HRR_RANDOM
        // so it isn't treated as a HelloRetryRequest.)
        let mut sh_body = Vec::new();
        sh_body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        sh_body.extend_from_slice(&[0x11; 32]); // random (not HRR magic)
        sh_body.push(0); // session_id length 0
        sh_body.extend_from_slice(&[0x00, 0x00]); // cipher_suite (non-offered)
        sh_body.push(0); // compression_method = null
        sh_body.extend_from_slice(&[0x00, 0x00]); // extensions length 0
        // ServerHello = handshake type 2; client awaits it at message_seq 0.
        let forged_sh = super::dtls12_plaintext_handshake_record(2, 0, &sh_body);

        // Inject the forged ServerHello while the client awaits SH: it must be
        // silently dropped (Ok) without derailing the handshake.
        assert_eq!(client.feed_datagram(&forged_sh), Ok(()));

        // The handshake still completes with the genuine server.
        assert!(pump_handshake_13(&mut client, &mut server));
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

/// Regression tests for the DTLS security audit (2026-09).
///
/// Each test in here maps to one audited finding; the comment above every
/// group names the primitive it protects.
mod security_regressions {
    use super::*;
    use crate::dtls::cookie::CookieGenerator;
    use crate::dtls::reassembly::{Reassembler, read_fragment, write_message};
    use crate::dtls::{
        ClientConfig13Internal as PcClientConfig13, DtlsClientConnection13, DtlsServerConnection13,
        ServerConfig13Internal as PcServerConfig13,
    };
    use crate::tls::Error;
    use crate::tls::codec::hs_type;

    /// Self-signed ECDSA P-256 leaf for `dtls.example` with a caller-chosen
    /// validity window, so tests can build an EXPIRED certificate. Returns
    /// `(cert_der, key_der)`.
    fn cert_with_validity(
        seed: &[u8],
        not_before: Time,
        not_after: Time,
    ) -> (Vec<u8>, BoxedEcdsaPrivateKey) {
        let mut rng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let name = DistinguishedName::common_name("dtls.example");
        let validity = Validity::new(not_before, not_after);
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            false,
            &["dtls.example"],
        )
        .unwrap();
        (cert.to_der().to_vec(), key)
    }

    // ---------------------------------------------------------------
    // HIGH 1 — DTLS clients must consult the system clock by default.
    //
    // `verification_time` defaults to `None`, and `verify_chain_inner`
    // skips the whole notBefore/notAfter loop (and CRL freshness) when it
    // is given `None`. Without an `.or_else(system_now)` fallback, ANY
    // expired certificate chaining to a trusted root authenticated to a
    // default-configured DTLS client.
    // ---------------------------------------------------------------

    /// Drives the DTLS 1.2 pair and returns the first error the CLIENT
    /// raised while consuming the server's flight, if any.
    fn pump_until_client_error<R: crate::rng::RngCore>(
        client: &mut DtlsClientConnection12,
        server: &mut DtlsServerConnection12<R>,
    ) -> Option<Error> {
        for _ in 0..32 {
            let c_out = client.pop_outbound_datagrams();
            for dg in &c_out {
                server.feed_datagram(dg).unwrap();
            }
            let s_out = server.pop_outbound_datagrams();
            for dg in &s_out {
                if let Err(e) = client.feed_datagram(dg) {
                    return Some(e);
                }
            }
            if c_out.is_empty() && s_out.is_empty() {
                break;
            }
        }
        None
    }

    #[test]
    fn expired_server_cert_rejected_by_default_client_12() {
        let (der, key) = cert_with_validity(
            b"dtls12-expired",
            Time::utc(2020, 1, 1, 0, 0, 0),
            Time::utc(2021, 1, 1, 0, 0, 0),
        );

        let server_cfg = PcServerConfig12::with_ecdsa(alloc::vec![der.clone()], key)
            .require_cookie_exchange(false);

        let mut roots = RootCertStore::new();
        roots.add_der(der.clone()).unwrap();
        // The point of the test: NO `with_verification_time`. This is the
        // default configuration a caller gets from `tls::Config`.
        let cfg = PcClientConfig12::new(roots, "dtls.example");
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls12-expired-client", b"nonce", &[]);
        let mut client = DtlsClientConnection12::new(cfg, b"client-addr".to_vec(), &mut crng);
        let srng = HmacDrbg::<Sha256>::new(b"dtls12-expired-server", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"peer-a".to_vec(), srng);

        let err = pump_until_client_error(&mut client, &mut server);
        assert!(
            err.is_some(),
            "a default-configured DTLS 1.2 client must reject an expired chain"
        );
        assert!(!client.is_handshake_complete());
    }

    /// Control for the test above: the SAME expired certificate is accepted
    /// when the caller explicitly pins a clock inside the validity window.
    /// This proves the rejection comes from the date check and not from
    /// some unrelated chain fault.
    #[test]
    fn expired_cert_accepted_when_clock_pinned_inside_validity_12() {
        let (der, key) = cert_with_validity(
            b"dtls12-expired",
            Time::utc(2020, 1, 1, 0, 0, 0),
            Time::utc(2021, 1, 1, 0, 0, 0),
        );

        let server_cfg = PcServerConfig12::with_ecdsa(alloc::vec![der.clone()], key)
            .require_cookie_exchange(false);

        let mut roots = RootCertStore::new();
        roots.add_der(der.clone()).unwrap();
        let cfg = PcClientConfig12::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2020, 6, 1, 0, 0, 0));
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls12-pinned-client", b"nonce", &[]);
        let mut client = DtlsClientConnection12::new(cfg, b"client-addr".to_vec(), &mut crng);
        let srng = HmacDrbg::<Sha256>::new(b"dtls12-pinned-server", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"peer-a".to_vec(), srng);

        assert!(pump_handshake(&mut client, &mut server));
    }

    #[test]
    fn expired_server_cert_rejected_by_default_client_13() {
        let (der, key) = cert_with_validity(
            b"dtls13-expired",
            Time::utc(2020, 1, 1, 0, 0, 0),
            Time::utc(2021, 1, 1, 0, 0, 0),
        );

        let server_cfg =
            PcServerConfig13::with_ecdsa(alloc::vec![der.clone()], key).with_no_cookie();

        let mut roots = RootCertStore::new();
        roots.add_der(der.clone()).unwrap();
        // No `with_verification_time` — the default configuration.
        let cfg = PcClientConfig13::new(roots, "dtls.example");
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls13-expired-client", b"nonce", &[]);
        let mut client = DtlsClientConnection13::new(cfg, b"client-addr".to_vec(), &mut crng);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-expired-server", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"peer-a".to_vec(), srng);

        let mut saw_err = false;
        'outer: for _ in 0..32 {
            let c_out = client.pop_outbound_datagrams();
            for dg in &c_out {
                let _ = server.feed_datagram(dg);
            }
            let s_out = server.pop_outbound_datagrams();
            for dg in &s_out {
                if client.feed_datagram(dg).is_err() {
                    saw_err = true;
                    break 'outer;
                }
            }
            if c_out.is_empty() && s_out.is_empty() {
                break;
            }
        }
        assert!(
            saw_err,
            "a default-configured DTLS 1.3 client must reject an expired chain"
        );
        assert!(!client.is_handshake_complete());
    }

    // ---------------------------------------------------------------
    // HIGH 2 — the HVR / HRR cookie must be bound to the client address.
    //
    // An unbound cookie proves only that SOMEONE completed one round trip
    // with these ClientHello bytes. An attacker harvests one from their
    // own address and replays that CH2 from arbitrary spoofed sources for
    // the cookie's lifetime, turning the server into a ~15-30x UDP
    // reflector that burns one asymmetric signature per spoofed packet.
    // ---------------------------------------------------------------

    #[test]
    fn cookie_is_bound_to_peer_address() {
        let cg = CookieGenerator::new([0x5c; 32]);
        let random = [7u8; 32];
        let fp = [9u8; 32];
        let cookie = cg.generate(b"peer-a", &random, &fp, 100);
        assert!(
            cg.validate(b"peer-a", &random, &fp, 100, &cookie),
            "cookie must validate for the address it was minted for"
        );
        assert!(
            !cg.validate(b"peer-b", &random, &fp, 100, &cookie),
            "a cookie minted for address A must NOT validate for address B"
        );
        // An empty address is just another address, not a wildcard.
        assert!(!cg.validate(b"", &random, &fp, 100, &cookie));
    }

    #[test]
    fn cookie_required_with_empty_peer_addr_fails_closed_12() {
        let (server_cfg, cert) = make_server();
        let server_cfg = server_cfg
            .with_cookie_secret([0xa5; 32])
            .require_cookie_exchange(true);
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls12-noaddr", b"nonce", &[]);
        // Empty peer address: the caller never told us who this is.
        let mut server = DtlsServerConnection12::new(Arc::new(server_cfg), Vec::new(), srng);

        let c1 = client.pop_outbound_datagrams();
        assert!(!c1.is_empty());
        let mut saw_err = false;
        for dg in &c1 {
            if matches!(server.feed_datagram(dg), Err(Error::InappropriateState)) {
                saw_err = true;
            }
        }
        assert!(
            saw_err,
            "cookie-required server with no peer address must fail closed"
        );
        assert!(
            server.pop_outbound_datagrams().is_empty(),
            "no cookie may be minted, and no flight emitted, without an address"
        );
    }

    #[test]
    fn cookie_required_with_empty_peer_addr_fails_closed_13() {
        let (server_cfg, cert) = make_server13_local();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut client = make_client13_local(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-noaddr", b"nonce", &[]);
        let mut server = DtlsServerConnection13::new(Arc::new(server_cfg), Vec::new(), srng);

        let c1 = client.pop_outbound_datagrams();
        assert!(!c1.is_empty());
        let mut saw_err = false;
        for dg in &c1 {
            if matches!(server.feed_datagram(dg), Err(Error::InappropriateState)) {
                saw_err = true;
            }
        }
        assert!(
            saw_err,
            "cookie-required server with no peer address must fail closed"
        );
        assert!(
            server.pop_outbound_datagrams().is_empty(),
            "no cookie may be minted, and no flight emitted, without an address"
        );
    }

    #[test]
    fn cookie_harvested_at_one_address_is_useless_at_another_12() {
        let (server_cfg, cert) = make_server();
        let server_cfg = Arc::new(
            server_cfg
                .with_cookie_secret([0xa5; 32])
                .require_cookie_exchange(true),
        );
        let mut client = make_client(&cert);

        // The attacker's own connection: complete one honest round trip
        // from `peer-a` to harvest a valid cookie.
        let arng = HmacDrbg::<Sha256>::new(b"dtls12-addr-a", b"nonce", &[]);
        let mut server_a =
            DtlsServerConnection12::new(server_cfg.clone(), b"peer-a".to_vec(), arng);
        for dg in &client.pop_outbound_datagrams() {
            server_a.feed_datagram(dg).unwrap();
        }
        let hvr = server_a.pop_outbound_datagrams();
        assert!(!hvr.is_empty(), "server should emit HelloVerifyRequest");
        for dg in &hvr {
            client.feed_datagram(dg).unwrap();
        }
        let ch2 = client.pop_outbound_datagrams();
        assert!(
            !ch2.is_empty(),
            "client should emit CH2 carrying the cookie"
        );

        // Now replay that exact CH2 at a server instance whose peer address
        // is the SPOOFING VICTIM's. It must not be accepted, and above all
        // must not produce a server flight aimed at that victim.
        let brng = HmacDrbg::<Sha256>::new(b"dtls12-addr-b", b"nonce", &[]);
        let mut server_b = DtlsServerConnection12::new(server_cfg, b"peer-b".to_vec(), brng);
        for dg in &ch2 {
            // Unauthenticated epoch-0 input: a cookie mismatch is a silent
            // drop, never fatal.
            server_b.feed_datagram(dg).unwrap();
        }
        assert!(
            server_b.pop_outbound_datagrams().is_empty(),
            "a cookie minted for peer-a must not buy a flight aimed at peer-b"
        );
        assert!(!server_b.is_handshake_complete());
    }

    #[test]
    fn cookie_harvested_at_one_address_is_useless_at_another_13() {
        let (server_cfg, cert) = make_server13_local();
        let server_cfg = Arc::new(server_cfg.with_cookie_secret([0xa5; 32]));
        let mut client = make_client13_local(&cert);

        let arng = HmacDrbg::<Sha256>::new(b"dtls13-addr-a", b"nonce", &[]);
        let mut server_a =
            DtlsServerConnection13::new(server_cfg.clone(), b"peer-a".to_vec(), arng);
        for dg in &client.pop_outbound_datagrams() {
            server_a.feed_datagram(dg).unwrap();
        }
        let hrr = server_a.pop_outbound_datagrams();
        assert!(!hrr.is_empty(), "server should emit a cookie HRR");
        for dg in &hrr {
            client.feed_datagram(dg).unwrap();
        }
        let ch2 = client.pop_outbound_datagrams();
        assert!(
            !ch2.is_empty(),
            "client should emit CH2 carrying the cookie"
        );

        let brng = HmacDrbg::<Sha256>::new(b"dtls13-addr-b", b"nonce", &[]);
        let mut server_b = DtlsServerConnection13::new(server_cfg, b"peer-b".to_vec(), brng);
        for dg in &ch2 {
            server_b.feed_datagram(dg).unwrap();
        }
        assert!(
            server_b.pop_outbound_datagrams().is_empty(),
            "a cookie minted for peer-a must not buy a flight aimed at peer-b"
        );
        assert!(!server_b.is_handshake_complete());
    }

    // ---------------------------------------------------------------
    // MEDIUM 3 — one spoofed fragment must not wedge reassembly forever.
    //
    // The in-progress map used to be keyed on `message_seq` alone, so the
    // FIRST fragment seen pinned `(msg_type, total_length)` for that
    // sequence number. A single spoofed epoch-0 fragment claiming a huge
    // `total_length` therefore starved the genuine message permanently:
    // every real fragment mismatched and was dropped, and nothing ever
    // evicted the poisoned entry.
    // ---------------------------------------------------------------

    /// Builds one raw DTLS handshake fragment header + body.
    fn raw_fragment(
        msg_type: u8,
        total_length: u32,
        message_seq: u16,
        fragment_offset: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(msg_type);
        out.extend_from_slice(&total_length.to_be_bytes()[1..]);
        out.extend_from_slice(&message_seq.to_be_bytes());
        out.extend_from_slice(&fragment_offset.to_be_bytes()[1..]);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn conflicting_first_fragment_does_not_wedge_reassembly() {
        let mut r = Reassembler::new();

        // Spoofed: message_seq 0 claiming a 32 KiB ClientHello, of which
        // exactly one byte is ever delivered. It can never complete.
        let poison = raw_fragment(hs_type::CLIENT_HELLO, 32 * 1024, 0, 0, &[0xAA]);
        assert!(r.feed(read_fragment(&poison).unwrap()).is_none());

        // Genuine message at the same message_seq, with the real length.
        let mut good = Vec::new();
        write_message(&mut good, hs_type::CLIENT_HELLO, 0, b"genuine-body", 0);
        let got = r.feed(read_fragment(&good).unwrap());
        assert_eq!(
            got,
            Some((hs_type::CLIENT_HELLO, b"genuine-body".to_vec())),
            "a poisoned candidate must not starve the genuine message"
        );

        // The losing candidate is evicted once the queue head advances, so
        // it cannot hold a slot of the `max_in_progress` budget forever.
        let mut next = Vec::new();
        write_message(&mut next, hs_type::CLIENT_HELLO, 1, b"second", 0);
        assert_eq!(
            r.feed(read_fragment(&next).unwrap()),
            Some((hs_type::CLIENT_HELLO, b"second".to_vec()))
        );
    }

    #[test]
    fn conflicting_msg_type_claims_coexist() {
        let mut r = Reassembler::new();
        // Same message_seq, same length, different type: still two distinct
        // candidates, so the genuine one still completes.
        let poison = raw_fragment(0x63, 5, 0, 0, b"XX");
        assert!(r.feed(read_fragment(&poison).unwrap()).is_none());
        let mut good = Vec::new();
        write_message(&mut good, hs_type::CLIENT_HELLO, 0, b"hello", 0);
        assert_eq!(
            r.feed(read_fragment(&good).unwrap()),
            Some((hs_type::CLIENT_HELLO, b"hello".to_vec()))
        );
    }

    #[test]
    fn clear_drops_partials_but_keeps_expected_seq() {
        let mut r = Reassembler::new();
        let partial = raw_fragment(hs_type::CLIENT_HELLO, 8, 0, 0, b"abcd");
        assert!(r.feed(read_fragment(&partial).unwrap()).is_none());
        r.clear();
        assert_eq!(r.expected_msg_seq(), 0);
        // A fresh, complete message at the same seq still lands.
        let mut good = Vec::new();
        write_message(&mut good, hs_type::CLIENT_HELLO, 0, b"whole", 0);
        assert_eq!(
            r.feed(read_fragment(&good).unwrap()),
            Some((hs_type::CLIENT_HELLO, b"whole".to_vec()))
        );
    }

    /// End-to-end: a single spoofed epoch-0 ClientHello fragment injected
    /// at the DTLS 1.3 server's pre-cookie reassembler (source address =
    /// the victim client's) must not stop the genuine handshake.
    #[test]
    fn spoofed_ch_fragment_does_not_wedge_server_13() {
        use crate::dtls::record;
        use crate::tls::{ContentType, ProtocolVersion};

        let (server_cfg, cert) = make_server13_local();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut client = make_client13_local(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-wedge", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"peer-a".to_vec(), srng);

        // The poison datagram: message_seq 0, total_length 32 KiB, one byte.
        let poison_frag = raw_fragment(hs_type::CLIENT_HELLO, 32 * 1024, 0, 0, &[0xAA]);
        let mut poison_dg = Vec::new();
        record::write_record(
            &mut poison_dg,
            ContentType::Handshake,
            ProtocolVersion::DTLSv1_2,
            0,
            0,
            &poison_frag,
        );
        server
            .feed_datagram(&poison_dg)
            .expect("spoofed epoch-0 input must never be fatal");
        assert!(
            server.pop_outbound_datagrams().is_empty(),
            "an incomplete CH must not produce any flight"
        );

        // Now the genuine handshake, on the very same connection.
        assert!(
            pump_handshake_13_local(&mut client, &mut server),
            "a spoofed fragment must not wedge the genuine handshake"
        );
    }

    // --- local copies of the DTLS 1.3 helpers (the ones in `mod dtls13`
    // --- are private to that module).

    fn make_server13_local() -> (PcServerConfig13, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"dtls13-sec-key", b"nonce", &[]);
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

    fn make_client13_local(server_cert: &[u8]) -> DtlsClientConnection13 {
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert.to_vec()).unwrap();
        let cfg = PcClientConfig13::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        let mut crng = HmacDrbg::<Sha256>::new(b"dtls13-sec-client", b"nonce", &[]);
        DtlsClientConnection13::new(cfg, b"client-addr".to_vec(), &mut crng)
    }

    fn pump_handshake_13_local<R: crate::rng::RngCore>(
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

    // ---------------------------------------------------------------
    // LOW 5 — DTLS 1.3 `send()` must cap the plaintext length rather than
    // let the record's u16 length field truncate silently.
    // ---------------------------------------------------------------

    #[test]
    fn oversized_send_is_rejected_13() {
        let (server_cfg, cert) = make_server13_local();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = make_client13_local(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"dtls13-oversize", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(Arc::new(server_cfg), b"peer-a".to_vec(), srng);
        assert!(pump_handshake_13_local(&mut client, &mut server));

        let big = alloc::vec![0u8; (1 << 14) + 1];
        assert!(matches!(client.send(&big), Err(Error::RecordOverflow)));
        assert!(matches!(server.send(&big), Err(Error::RecordOverflow)));
        // The boundary value itself is still accepted.
        let ok = alloc::vec![0u8; 1 << 14];
        assert!(client.send(&ok).is_ok());
    }
}

/// Regression tests for the DTLS security audit follow-up (2026-09,
/// findings DTLS-M1 / L1..L7 / I4). Each test is the auditor's
/// reproduction turned around: the exploit input is fed and the engine is
/// required to keep working.
mod audit_2026_09 {
    use super::*;
    use crate::dtls::record;
    use crate::dtls::{
        ClientConfig13Internal as PcClientConfig13, DtlsClientConnection13, DtlsServerConnection13,
        ServerConfig13Internal as PcServerConfig13,
    };
    use crate::tls::codec::{CipherSuite, NamedGroup, hs_type};
    use crate::tls::{ContentType, Error, ProtocolVersion};

    fn make_server13_local() -> (PcServerConfig13, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"dtls13-audit-key", b"nonce", &[]);
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

    fn client13_cfg(server_cert: &[u8]) -> PcClientConfig13 {
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert.to_vec()).unwrap();
        PcClientConfig13::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0))
    }

    fn client13(cfg: PcClientConfig13, seed: &[u8]) -> DtlsClientConnection13 {
        let mut crng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
        DtlsClientConnection13::new(cfg, b"peer-a".to_vec(), &mut crng)
    }

    fn server13(cfg: PcServerConfig13, seed: &[u8]) -> DtlsServerConnection13<HmacDrbg<Sha256>> {
        let srng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
        DtlsServerConnection13::new(Arc::new(cfg), b"peer-a".to_vec(), srng)
    }

    fn pump13<R: crate::rng::RngCore>(
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

    /// Exchanges one application-data round trip in both directions.
    fn app_data_round_trip<R: crate::rng::RngCore>(
        client: &mut DtlsClientConnection13,
        server: &mut DtlsServerConnection13<R>,
    ) {
        client.send(b"ping").unwrap();
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"ping");
        server.send(b"pong").unwrap();
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        assert_eq!(client.take_received(), b"pong");
    }

    /// Raw DTLS handshake fragment: 12-byte header + body.
    fn raw_fragment(
        msg_type: u8,
        total_length: u32,
        message_seq: u16,
        fragment_offset: u32,
        body: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(msg_type);
        out.extend_from_slice(&total_length.to_be_bytes()[1..]);
        out.extend_from_slice(&message_seq.to_be_bytes());
        out.extend_from_slice(&fragment_offset.to_be_bytes()[1..]);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    /// Splits a plaintext record carrying several handshake fragments
    /// (the client packs a fragmented CH into ONE record) into one
    /// datagram per fragment, so a test can interleave other traffic.
    fn split_record_fragments(dg: &[u8]) -> Vec<Vec<u8>> {
        let body = &dg[13..];
        let mut out = Vec::new();
        let mut off = 0;
        let mut seq = 100u64;
        while off < body.len() {
            let flen = ((body[off + 9] as usize) << 16)
                | ((body[off + 10] as usize) << 8)
                | body[off + 11] as usize;
            let end = off + 12 + flen;
            out.push(plain_record(seq, &body[off..end]));
            seq += 1;
            off = end;
        }
        out
    }

    /// Wraps `fragment` in one plaintext (epoch 0) DTLS record.
    fn plain_record(seq: u64, fragment: &[u8]) -> Vec<u8> {
        let mut dg = Vec::new();
        record::write_record(
            &mut dg,
            ContentType::Handshake,
            ProtocolVersion::DTLSv1_2,
            0,
            seq,
            fragment,
        );
        dg
    }

    // -----------------------------------------------------------------
    // DTLS-M1: a spoofed epoch-0 ClientHello fragment must not be able to
    // seed the pre-cookie reassembler's expected message_seq.
    // -----------------------------------------------------------------

    /// One spoofed CH fragment with `message_seq` 1..=8 used to pin the
    /// pre-cookie buffer's head at that value, after which the genuine
    /// CH1 (seq 0) / CH2 (seq 1) were dropped as stale for ever.
    #[test]
    fn spoofed_msg_seq_fragment_does_not_wedge_pre_cookie_server_13() {
        for poison_seq in 1..=8u16 {
            let (server_cfg, cert) = make_server13_local();
            let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
            let mut client = client13(client13_cfg(&cert), b"m1-client");
            let mut server = server13(server_cfg, b"m1-server");

            let poison = raw_fragment(hs_type::CLIENT_HELLO, 64, poison_seq, 0, &[0xAA]);
            server.feed_datagram(&plain_record(0, &poison)).unwrap();
            assert!(server.pop_outbound_datagrams().is_empty());

            assert!(
                pump13(&mut client, &mut server),
                "poison message_seq {poison_seq} wedged the server"
            );
            app_data_round_trip(&mut client, &mut server);
        }
    }

    /// Slot exhaustion: `PRE_COOKIE_MAX_IN_PROGRESS` spoofed partial
    /// claims at BOTH legitimate sequence numbers (0 and 1), each with a
    /// distinct claimed length so they are distinct candidates. A genuine
    /// client whose ClientHello is fragmented (the default ML-KEM offer is
    /// ~1.4 KiB, i.e. two fragments) must still complete: FIFO eviction
    /// recycles the junk.
    #[test]
    fn pre_cookie_slot_exhaustion_does_not_wedge_server_13() {
        let (server_cfg, cert) = make_server13_local();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut client = client13(client13_cfg(&cert), b"m1b-client");
        let mut server = server13(server_cfg, b"m1b-server");

        // The genuine CH really is fragmented, otherwise the fast path
        // would sidestep the buffer and prove nothing.
        let ch_dg = client.pop_outbound_datagrams();
        assert_eq!(ch_dg.len(), 1);
        let ch = split_record_fragments(&ch_dg[0]);
        assert!(ch.len() >= 2, "expected a fragmented ClientHello");

        let mut seq = 0u64;
        for msg_seq in [0u16, 1] {
            for i in 0..4u32 {
                let junk = raw_fragment(hs_type::CLIENT_HELLO, 2000 + i, msg_seq, 0, &[0xAA]);
                server.feed_datagram(&plain_record(seq, &junk)).unwrap();
                seq += 1;
            }
        }
        assert!(server.pop_outbound_datagrams().is_empty());

        for dg in &ch {
            server.feed_datagram(dg).unwrap();
        }
        let hrr = server.pop_outbound_datagrams();
        assert!(
            !hrr.is_empty(),
            "server must answer the genuine fragmented CH with an HRR"
        );
        for dg in &hrr {
            client.feed_datagram(dg).unwrap();
        }
        assert!(pump13(&mut client, &mut server));
        app_data_round_trip(&mut client, &mut server);
    }

    /// A spoofed *complete* CH that fails validation (bogus cookie) must
    /// not flush a genuine fragmented CH that is mid-reassembly.
    #[test]
    fn rejected_complete_ch_keeps_partial_genuine_ch_13() {
        let (server_cfg, cert) = make_server13_local();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut client = client13(client13_cfg(&cert), b"m1c-client");
        let mut server = server13(server_cfg, b"m1c-server");

        let ch_dg = client.pop_outbound_datagrams();
        let ch = split_record_fragments(&ch_dg[0]);
        assert!(ch.len() >= 2, "expected a fragmented ClientHello");
        server.feed_datagram(&ch[0]).unwrap();
        // Spoofed complete CH: body is garbage, so it fails to decode and
        // is dropped silently.
        let bogus = raw_fragment(hs_type::CLIENT_HELLO, 8, 0, 0, &[0xFF; 8]);
        server.feed_datagram(&plain_record(99, &bogus)).unwrap();
        assert!(server.pop_outbound_datagrams().is_empty());
        for dg in &ch[1..] {
            server.feed_datagram(dg).unwrap();
        }
        let hrr = server.pop_outbound_datagrams();
        assert!(!hrr.is_empty(), "genuine CH must still complete reassembly");
        for dg in &hrr {
            client.feed_datagram(dg).unwrap();
        }
        assert!(pump13(&mut client, &mut server));
    }

    // -----------------------------------------------------------------
    // DTLS-L1: the DTLS 1.3 server must not pin any state for a CH2
    // that still fails key agreement.
    // -----------------------------------------------------------------

    /// A replayed CH2 (valid cookie) with the X25519 share zeroed fails
    /// key agreement. Nothing may be pinned: the genuine CH2 must still be
    /// accepted, and a follow-up spoofed plaintext handshake fragment must
    /// be a silent drop, not a fatal error.
    #[test]
    fn corrupted_share_ch2_variant_does_not_pin_server_state_13() {
        let (server_cfg, cert) = make_server13_local();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut cfg = client13_cfg(&cert);
        cfg.groups = alloc::vec![NamedGroup::X25519];
        let mut client = client13(cfg, b"l1-client");
        let mut server = server13(server_cfg, b"l1-server");

        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        let c2 = client.pop_outbound_datagrams();
        assert_eq!(c2.len(), 1);
        let ch2 = c2[0].clone();
        // key_share ext: 00 33 | len | shares_len | 00 1d | 00 20 | 32 bytes
        let pos = ch2
            .windows(4)
            .position(|w| w == [0x00, 0x1d, 0x00, 0x20])
            .expect("x25519 share");
        let mut bad = ch2.clone();
        for b in &mut bad[pos + 4..pos + 36] {
            *b = 0;
        }
        assert_eq!(server.feed_datagram(&bad), Ok(()));
        assert!(server.pop_outbound_datagrams().is_empty());

        // A spoofed plaintext handshake fragment (which used to hit the
        // prematurely allocated reassembler and surface UnexpectedMessage).
        let spoof = raw_fragment(hs_type::FINISHED, 0, 2, 0, &[]);
        assert_eq!(server.feed_datagram(&plain_record(9, &spoof)), Ok(()));
        assert!(server.pop_outbound_datagrams().is_empty());

        // Genuine CH2 now completes the handshake.
        server.feed_datagram(&ch2).unwrap();
        let flight = server.pop_outbound_datagrams();
        assert!(!flight.is_empty(), "server must answer the genuine CH2");
        for dg in &flight {
            client.feed_datagram(dg).unwrap();
        }
        assert!(pump13(&mut client, &mut server));

        // Once the handshake state exists, plaintext handshake fragments
        // are still a silent drop.
        assert_eq!(server.feed_datagram(&plain_record(10, &spoof)), Ok(()));
        app_data_round_trip(&mut client, &mut server);
    }

    // -----------------------------------------------------------------
    // DTLS-L2: the DTLS 1.2 server must validate a cookie-bearing CH2
    // completely before touching the transcript / reassembler.
    // -----------------------------------------------------------------

    /// Locates the `extended_master_secret` extension inside a DTLS CH
    /// datagram, returning `(ems_ext_offset, extensions_len_offset)`.
    fn find_ems_in_dtls12_ch(ch: &[u8]) -> (usize, usize) {
        // record(13) + hs header(12) = 25; then version(2) random(32).
        let mut w = 25 + 2 + 32;
        w += 1 + ch[w] as usize; // session id
        w += 1 + ch[w] as usize; // cookie
        let csl = u16::from_be_bytes([ch[w], ch[w + 1]]) as usize;
        w += 2 + csl;
        w += 1 + ch[w] as usize; // compression
        let ext_len_at = w;
        w += 2;
        while w < ch.len() {
            let ty = u16::from_be_bytes([ch[w], ch[w + 1]]);
            let l = u16::from_be_bytes([ch[w + 2], ch[w + 3]]) as usize;
            if ty == 0x0017 {
                return (w, ext_len_at);
            }
            w += 4 + l;
        }
        panic!("no extended_master_secret extension");
    }

    fn bump16(b: &mut [u8], at: usize) {
        let v = u16::from_be_bytes([b[at], b[at + 1]]) + 1;
        b[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }

    fn bump24(b: &mut [u8], at: usize) {
        let v = (((b[at] as u32) << 16) | ((b[at + 1] as u32) << 8) | b[at + 2] as u32) + 1;
        b[at] = (v >> 16) as u8;
        b[at + 1] = (v >> 8) as u8;
        b[at + 2] = v as u8;
    }

    /// A replayed CH2 (valid cookie) whose `extended_master_secret` body
    /// was made non-empty used to be rejected only AFTER the transcript
    /// had absorbed it, so the genuine CH2 then appended a second CH and
    /// the client's Finished could never verify.
    #[test]
    fn replayed_ch2_variant_does_not_poison_transcript_12() {
        let (server_cfg, cert) = make_server();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"l2-server", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        let c2 = client.pop_outbound_datagrams();
        let ch2 = c2[0].clone();

        // Attacker's variant: EMS extension (0x0017, len 0) -> len 1, body [0].
        let (pos, ext_len_at) = find_ems_in_dtls12_ch(&ch2);
        let mut bad = ch2.clone();
        bad[pos + 3] = 1;
        bad.insert(pos + 4, 0x00);
        bump16(&mut bad, 11); // record length
        bump24(&mut bad, 14); // handshake total_length
        bump24(&mut bad, 22); // fragment_length
        bump16(&mut bad, ext_len_at); // extensions length
        assert_eq!(server.feed_datagram(&bad), Ok(()));
        assert!(
            server.pop_outbound_datagrams().is_empty(),
            "variant must not produce a flight"
        );

        // Genuine CH2 → full handshake, both directions of app data.
        for dg in &c2 {
            server.feed_datagram(dg).unwrap();
        }
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        assert!(server.is_handshake_complete());
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        assert!(client.is_handshake_complete());
        client.send(b"hello").unwrap();
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"hello");
    }

    // -----------------------------------------------------------------
    // DTLS-L3: a lost final server flight (DTLS 1.2) must be recoverable.
    // -----------------------------------------------------------------

    /// The server's CCS+Finished is dropped. The client's retransmit timer
    /// re-sends its own flight; the server must answer the retransmitted
    /// Finished by re-sending its final flight (RFC 6347 §4.2.4), after
    /// which the client completes.
    #[test]
    fn lost_final_server_flight_is_recovered_12() {
        let (server_cfg, cert) = make_server();
        let server_cfg = server_cfg.require_cookie_exchange(false);
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"l3-server", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        let s_final = server.pop_outbound_datagrams();
        assert!(server.is_handshake_complete());
        assert_eq!(s_final.len(), 2, "CCS + Finished");
        // ...lost on the wire (kept only to compare record headers below).

        // Client timer fires → its flight is retransmitted.
        let t = client.next_timeout().expect("client flight armed");
        client.on_timeout(t);
        let c_retx = client.pop_outbound_datagrams();
        assert!(!c_retx.is_empty());
        for dg in &c_retx {
            server.feed_datagram(dg).unwrap();
        }
        let s_retx = server.pop_outbound_datagrams();
        assert_eq!(s_retx.len(), 2, "server must re-send CCS + Finished");
        // Fresh record sequence numbers (RFC 6347 §4.1.2.6): the header's
        // 48-bit seq (bytes 5..11) must differ from the originals'.
        assert_ne!(&s_retx[0][5..11], &s_final[0][5..11], "CCS reused its seq");
        assert_ne!(
            &s_retx[1][5..11],
            &s_final[1][5..11],
            "Finished reused its seq"
        );
        assert_eq!(
            &s_retx[1][3..5],
            &s_final[1][3..5],
            "Finished must stay in epoch 1"
        );
        for dg in &s_retx {
            client.feed_datagram(dg).unwrap();
        }
        assert!(client.is_handshake_complete());
        assert!(client.next_timeout().is_none());

        // The connection is fully usable in both directions afterwards.
        client.send(b"after-loss").unwrap();
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        assert_eq!(server.take_received(), b"after-loss");
        server.send(b"reply").unwrap();
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        assert_eq!(client.take_received(), b"reply");
        // Application data from the client proved it holds our Finished:
        // a replayed client Finished no longer triggers a re-send.
        for dg in &c_retx {
            server.feed_datagram(dg).unwrap();
        }
        assert!(server.pop_outbound_datagrams().is_empty());
    }

    /// The re-send trigger is bounded: a captured client Finished replayed
    /// over and over cannot make the server emit its final flight
    /// indefinitely.
    #[test]
    fn final_flight_resend_is_bounded_12() {
        let (server_cfg, cert) = make_server();
        let server_cfg = server_cfg.require_cookie_exchange(false);
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"l3b-server", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        let c_final = client.pop_outbound_datagrams();
        for dg in &c_final {
            server.feed_datagram(dg).unwrap();
        }
        let _ = server.pop_outbound_datagrams();
        let mut resends = 0;
        for _ in 0..20 {
            for dg in &c_final {
                server.feed_datagram(dg).unwrap();
            }
            if !server.pop_outbound_datagrams().is_empty() {
                resends += 1;
            }
        }
        assert!(resends > 0 && resends < 20, "resends = {resends}");
        assert!(server.is_handshake_complete());
    }

    /// DTLS 1.3: the client's Finished (epoch 2) is lost AFTER the client
    /// switched its write keys to epoch 3. The retransmission must be
    /// re-encrypted under the retained epoch-2 keys with a fresh record
    /// number (RFC 9147 §4.2.1 / §4.5.3); the server then completes and
    /// its ACK for the re-sent copy releases the client's in-flight set.
    #[test]
    fn lost_client_finished_is_recovered_13() {
        let (server_cfg, cert) = make_server13_local();
        let server_cfg = server_cfg.with_no_cookie();
        let mut client = client13(client13_cfg(&cert), b"l3c-client");
        let mut server = server13(server_cfg, b"l3c-server");
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        assert!(client.is_handshake_complete());
        // Client output: ACKs + its Finished. Drop it all.
        let lost = client.pop_outbound_datagrams();
        assert!(!lost.is_empty());
        assert!(!server.is_handshake_complete());

        let t = client.next_timeout().expect("Finished in flight");
        client.on_timeout(t);
        let retx = client.pop_outbound_datagrams();
        assert_eq!(retx.len(), 1, "only the Finished is retransmitted");
        let fin_original = lost
            .iter()
            .find(|dg| dg.len() == retx[0].len())
            .expect("Finished");
        assert_ne!(
            &retx[0], fin_original,
            "retransmit reused the record number"
        );
        for dg in &retx {
            server.feed_datagram(dg).unwrap();
        }
        assert!(
            server.is_handshake_complete(),
            "server must accept the re-encrypted Finished"
        );
        // The server's ACK names the re-sent copy; it must release it.
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        assert!(
            client.next_timeout().is_none(),
            "ACK of the re-sent copy must disarm the timer"
        );
        app_data_round_trip(&mut client, &mut server);
    }

    /// DTLS 1.2: the client's final flight (CKE + CCS + Finished) is lost;
    /// the timer-driven retransmission carries fresh epoch-0 sequence
    /// numbers for CKE/CCS and a fresh epoch-1 number for Finished, and
    /// the server completes on it.
    #[test]
    fn lost_client_final_flight_is_recovered_12() {
        let (server_cfg, cert) = make_server();
        let server_cfg = server_cfg.require_cookie_exchange(false);
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"l3d-server", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        let lost = client.pop_outbound_datagrams();
        assert_eq!(lost.len(), 3, "CKE + CCS + Finished");
        let t = client.next_timeout().expect("flight armed");
        client.on_timeout(t);
        let retx = client.pop_outbound_datagrams();
        assert_eq!(retx.len(), 3);
        for (a, b) in retx.iter().zip(lost.iter()) {
            assert_eq!(&a[3..5], &b[3..5], "epoch must be preserved");
            assert_ne!(&a[5..11], &b[5..11], "record seq must be fresh");
        }
        for dg in &retx {
            server.feed_datagram(dg).unwrap();
        }
        assert!(server.is_handshake_complete());
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
        assert!(client.is_handshake_complete());
    }

    // -----------------------------------------------------------------
    // DTLS-L4: DTLS 1.3 client-side cipher-suite / HRR checks.
    // -----------------------------------------------------------------

    /// The client offers only AES-256-GCM; a ServerHello patched to select
    /// AES-128-GCM (a crate-supported but NOT offered suite) must be
    /// rejected.
    #[test]
    fn client13_rejects_non_offered_suite_in_server_hello() {
        let (server_cfg, cert) = make_server13_local();
        let server_cfg = server_cfg.with_no_cookie();
        let mut cfg = client13_cfg(&cert);
        cfg.cipher_suites = alloc::vec![CipherSuite(0x1302)];
        let mut client = client13(cfg, b"l4-client");
        let mut server = server13(server_cfg, b"l4-server");
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        let s = server.pop_outbound_datagrams();
        let mut sh = s[0].clone();
        assert_eq!(&sh[60..62], &[0x13, 0x02], "expected AES-256 suite in SH");
        sh[60] = 0x13;
        sh[61] = 0x01; // AES-128-GCM: never offered
        // Plaintext (epoch 0) input: a rejected SH is a silent drop. The
        // observable is that the CH retransmit timer stays armed — an
        // accepted SH disarms it — and that the genuine SH is still
        // accepted afterwards (nothing was pinned by the bad one).
        assert!(client.next_timeout().is_some());
        assert_eq!(client.feed_datagram(&sh), Ok(()));
        assert!(
            client.next_timeout().is_some(),
            "patched ServerHello was accepted"
        );
        assert!(!client.is_handshake_complete());
        client.feed_datagram(&s[0]).unwrap();
        assert!(
            client.next_timeout().is_none(),
            "genuine SH must disarm the CH timer"
        );
        for dg in &s[1..] {
            client.feed_datagram(dg).unwrap();
        }
        assert!(pump13(&mut client, &mut server));
    }

    /// RFC 8446 §4.1.4: the ServerHello after an HRR must carry the same
    /// suite the HRR did. The HRR is patched to a different (offered)
    /// suite; the server's real SH then mismatches it.
    #[test]
    fn client13_rejects_server_hello_suite_differing_from_hrr() {
        let (server_cfg, cert) = make_server13_local();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut client = client13(client13_cfg(&cert), b"l4b-client");
        let mut server = server13(server_cfg, b"l4b-server");
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        let hrr = server.pop_outbound_datagrams();
        assert_eq!(hrr.len(), 1);
        let mut patched = hrr[0].clone();
        // ServerHello body: version(2) random(32) sid_len(1) suite(2) —
        // suite sits at 25 + 35.
        assert_eq!(&patched[60..62], &[0x13, 0x01], "server picks AES-128");
        patched[61] = 0x03; // ChaCha20-Poly1305: offered, but not what SH says
        client.feed_datagram(&patched).unwrap();
        // CH2 (with the cookie) → genuine SH with suite 0x1301.
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        let flight = server.pop_outbound_datagrams();
        assert!(!flight.is_empty());
        assert_eq!(&flight[0][60..62], &[0x13, 0x01]);
        // Silent drop (plaintext input): the CH2 retransmit timer stays
        // armed and the handshake never completes.
        assert!(client.next_timeout().is_some());
        assert_eq!(client.feed_datagram(&flight[0]), Ok(()));
        assert!(
            client.next_timeout().is_some(),
            "ServerHello with a suite differing from the HRR was accepted"
        );
        for dg in &flight[1..] {
            client.feed_datagram(dg).unwrap();
        }
        assert!(!pump13(&mut client, &mut server));
        assert!(!client.is_handshake_complete());
    }

    /// RFC 8446 §4.2.8: an HRR that selects a group CH1 already carried a
    /// `key_share` for is illegal_parameter.
    #[test]
    fn client13_rejects_hrr_selecting_already_offered_group() {
        use crate::tls::codec::extension as ext;
        use crate::tls::codec::{ExtensionType, ServerHello};
        const HRR_RANDOM: [u8; 32] = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65,
            0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2,
            0xC8, 0xA8, 0x33, 0x9C,
        ];
        let (_, cert) = make_server13_local();
        let mut cfg = client13_cfg(&cert);
        cfg.groups = alloc::vec![NamedGroup::X25519, NamedGroup::SECP256R1];
        let mut client = client13(cfg, b"l4c-client");
        let _ = client.pop_outbound_datagrams(); // CH1 carries both shares

        let build_hrr = |group: u16| -> Vec<u8> {
            let mut ks = Vec::new();
            ks.extend_from_slice(&group.to_be_bytes());
            let hrr = ServerHello {
                random: HRR_RANDOM,
                session_id: Vec::new(),
                cipher_suite: CipherSuite(0x1301),
                extensions: alloc::vec![
                    ext::server_supported_versions(),
                    (ExtensionType::KEY_SHARE, ks),
                ],
            }
            .encode_dtls();
            let frag = raw_fragment(
                hs_type::SERVER_HELLO,
                (hrr.len() - 4) as u32,
                0,
                0,
                &hrr[4..],
            );
            plain_record(0, &frag)
        };
        // X25519 was offered with a share: illegal. Plaintext input, so
        // the rejection is a silent drop — no CH2 is produced and the CH1
        // retransmit timer stays armed.
        assert_eq!(
            client.feed_datagram(&build_hrr(NamedGroup::X25519.0)),
            Ok(())
        );
        assert!(
            client.pop_outbound_datagrams().is_empty(),
            "HRR selecting an already-offered group was accepted"
        );
        assert!(client.next_timeout().is_some());

        // Control: with only a P-256 share offered, an HRR for X25519 is
        // legitimate and yields a CH2 carrying exactly that share.
        let mut cfg = client13_cfg(&cert);
        cfg.groups = alloc::vec![NamedGroup::X25519, NamedGroup::SECP256R1];
        cfg.key_share_groups = Some(alloc::vec![NamedGroup::SECP256R1]);
        let mut client = client13(cfg, b"l4d-client");
        let _ = client.pop_outbound_datagrams();
        client
            .feed_datagram(&build_hrr(NamedGroup::X25519.0))
            .unwrap();
        let ch2 = client.pop_outbound_datagrams();
        assert_eq!(ch2.len(), 1);
        assert!(ch2[0].windows(4).any(|w| w == [0x00, 0x1d, 0x00, 0x20]));
    }

    // -----------------------------------------------------------------
    // DTLS-L5: cookie-required + group-change HRR must complete.
    // -----------------------------------------------------------------

    /// CH2 narrows `key_share` to the HRR-selected group (RFC 8446
    /// §4.1.2), so a cookie fingerprint covering the offered share groups
    /// could never validate CH2. `hrr_upgrades_group` only ran with
    /// cookies off; this is the same scenario with a cookie secret.
    #[test]
    fn hrr_upgrades_group_with_cookie_13() {
        let (server_cfg, cert) = make_server13_local();
        let server_cfg = server_cfg.with_cookie_secret([0xa5; 32]);
        let mut cfg = client13_cfg(&cert);
        cfg.groups = alloc::vec![
            NamedGroup::X25519MLKEM768,
            NamedGroup::X25519,
            NamedGroup::SECP256R1,
        ];
        cfg.key_share_groups = Some(alloc::vec![NamedGroup::SECP256R1]);
        let mut client = client13(cfg, b"l5-client");
        let mut server = server13(server_cfg, b"l5-server");
        assert!(pump13(&mut client, &mut server));
        app_data_round_trip(&mut client, &mut server);
    }

    // -----------------------------------------------------------------
    // DTLS-I4: DTLS 1.2 engines must not deliver application data after
    // close_notify.
    // -----------------------------------------------------------------

    #[test]
    fn application_data_after_close_notify_is_rejected_12() {
        let (server_cfg, cert) = make_server();
        let server_cfg = server_cfg.require_cookie_exchange(false);
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"i4-server", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake(&mut client, &mut server));

        // Server → client: close_notify, then (a misbehaving peer's) data.
        server.send_alert_record_for_test(1, 0);
        let alert = server.pop_outbound_datagrams();
        server.send(b"late").unwrap();
        let late = server.pop_outbound_datagrams();
        for dg in &alert {
            client.feed_datagram(dg).unwrap();
        }
        assert!(!client.is_handshake_complete());
        for dg in &late {
            assert_eq!(client.feed_datagram(dg), Err(Error::UnexpectedMessage));
        }
        assert!(client.take_received().is_empty());

        // And the mirror image, client → server.
        let (server_cfg, cert) = make_server();
        let server_cfg = server_cfg.require_cookie_exchange(false);
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"i4-server-2", b"nonce", &[]);
        let mut server =
            DtlsServerConnection12::new(Arc::new(server_cfg), b"client-addr".to_vec(), srng);
        assert!(pump_handshake(&mut client, &mut server));
        client.send_alert_record_for_test(1, 0);
        let alert = client.pop_outbound_datagrams();
        client.send(b"late").unwrap();
        let late = client.pop_outbound_datagrams();
        for dg in &alert {
            server.feed_datagram(dg).unwrap();
        }
        assert!(!server.is_handshake_complete());
        for dg in &late {
            assert_eq!(server.feed_datagram(dg), Err(Error::UnexpectedMessage));
        }
        assert!(server.take_received().is_empty());
    }
}
