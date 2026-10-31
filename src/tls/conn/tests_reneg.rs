//! TLS 1.2 secure renegotiation (RFC 5746) at the engine level: the
//! `renegotiation_info` binding, the peer-identity check, the limiter clock,
//! and data interleaving with the new handshake. The `Config`-level round
//! trips live in `tls::tests_reneg`.

use super::test_fixtures::client_config12;
use super::{ClientConfig12, ClientConnection12, ServerConfig12, ServerConnection12};
use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
use crate::hash::Sha256;
use crate::rng::HmacDrbg;
use crate::tls::codec::{CipherSuite, NamedGroup};
use crate::tls::{ContentType, RootCertStore};
use crate::tls::{Error, RenegotiationLimit, RenegotiationPolicy};
use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
use alloc::vec::Vec;

type Server = ServerConnection12<HmacDrbg<Sha256>>;

/// A P-256 self-signed server identity for `loopback.example` from `seed`.
fn ecdsa_server12(seed: &[u8]) -> (ServerConfig12, Vec<u8>) {
    let mut rng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
    let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let der = Certificate::self_signed_general(
        &CertSigner::Ecdsa(&key),
        &DistinguishedName::common_name("loopback.example"),
        &validity,
        1,
        false,
        &["loopback.example"],
    )
    .unwrap()
    .to_der()
    .to_vec();
    (
        ServerConfig12::with_ecdsa(alloc::vec![der.clone()], key),
        der,
    )
}

fn enabled() -> RenegotiationPolicy {
    RenegotiationPolicy::enabled()
}

fn server_with(cfg: ServerConfig12, policy: RenegotiationPolicy, label: &[u8]) -> Server {
    let mut cfg = cfg;
    cfg.renegotiation = policy;
    ServerConnection12::new(cfg, HmacDrbg::<Sha256>::new(label, b"nonce", &[]))
}

fn client_with(
    roots: RootCertStore,
    policy: RenegotiationPolicy,
    label: &[u8],
) -> ClientConnection12 {
    let mut cfg: ClientConfig12 = client_config12(roots);
    cfg.renegotiation = policy;
    let mut rng = HmacDrbg::<Sha256>::new(label, b"nonce", &[]);
    ClientConnection12::new_with_offer(
        cfg,
        "loopback.example",
        &mut rng,
        &[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        &[NamedGroup::X25519],
    )
}

fn roots(der: &[u8]) -> RootCertStore {
    let mut r = RootCertStore::new();
    r.add_der(der.to_vec()).unwrap();
    r
}

/// Shuttles records until both sides are idle, returning each side's first
/// error. A failing side's queued alert is still delivered.
fn pump(
    client: &mut ClientConnection12,
    server: &mut Server,
) -> (Result<(), Error>, Result<(), Error>) {
    let (mut ce, mut se) = (Ok(()), Ok(()));
    for _ in 0..32 {
        let c = client.write_tls();
        if !c.is_empty() && se.is_ok() {
            server.read_tls(&c);
            se = server.process_new_packets();
        }
        let s = server.write_tls();
        if !s.is_empty() && ce.is_ok() {
            client.read_tls(&s);
            ce = client.process_new_packets();
        }
        if c.is_empty() && s.is_empty() {
            break;
        }
    }
    (ce, se)
}

/// [`pump`], asserting neither side failed.
fn pump_ok(client: &mut ClientConnection12, server: &mut Server) {
    let (c, s) = pump(client, server);
    c.unwrap();
    s.unwrap();
}

/// A connected pair with renegotiation enabled on both sides.
fn connected_pair() -> (ClientConnection12, Server) {
    let (cfg, der) = ecdsa_server12(b"reneg-server-key-a");
    let mut server = server_with(cfg, enabled(), b"reneg-s");
    let mut client = client_with(roots(&der), enabled(), b"reneg-c");
    let (c, s) = pump(&mut client, &mut server);
    c.unwrap();
    s.unwrap();
    assert!(client.is_handshake_complete() && server.is_handshake_complete());
    assert!(client.ems_negotiated());
    (client, server)
}

/// Data before, during and after a client-initiated renegotiation, with
/// the keys (and the master secret) replaced.
#[test]
fn client_initiated_renegotiation_replaces_the_keys() {
    let (mut client, mut server) = connected_pair();
    let ms_before = client.master_secret().unwrap();

    client.send_application_data(b"before").unwrap();
    pump_ok(&mut client, &mut server);
    assert_eq!(server.take_received_plaintext(), b"before");

    client.renegotiate().unwrap();
    assert!(client.is_renegotiating());
    // Queued until the new handshake completes.
    client.send_application_data(b"during").unwrap();
    // The server's own data flows to the client under the old keys while
    // the client waits for the ServerHello.
    server
        .send_application_data(b"server-before-hello")
        .unwrap();
    let ch = client.write_tls();
    let to_client = server.write_tls();
    client.read_tls(&to_client);
    client.process_new_packets().unwrap();
    assert_eq!(client.take_received_plaintext(), b"server-before-hello");
    server.read_tls(&ch);
    server.process_new_packets().unwrap();
    assert!(server.is_renegotiating());
    let (c, s) = pump(&mut client, &mut server);
    c.unwrap();
    s.unwrap();

    assert!(!client.is_renegotiating() && !server.is_renegotiating());
    assert_eq!(client.renegotiation_count(), 1);
    assert_eq!(server.renegotiation_count(), 1);
    assert_eq!(server.peer_renegotiation_requests(), 1);
    let ms_after = client.master_secret().unwrap();
    assert_ne!(
        ms_before, ms_after,
        "a renegotiation runs a fresh key exchange"
    );
    assert_eq!(Some(ms_after), server.master_secret());
    assert_eq!(server.take_received_plaintext(), b"during");

    client.send_application_data(b"after").unwrap();
    server.send_application_data(b"back").unwrap();
    pump_ok(&mut client, &mut server);
    assert_eq!(server.take_received_plaintext(), b"after");
    assert_eq!(client.take_received_plaintext(), b"back");

    // A second renegotiation binds to the first one's Finished values.
    client.renegotiate().unwrap();
    let (c, s) = pump(&mut client, &mut server);
    c.unwrap();
    s.unwrap();
    assert_eq!(client.renegotiation_count(), 2);
}

/// Server-initiated: a HelloRequest the client answers with a new hello,
/// which is not counted as client-initiated.
#[test]
fn server_initiated_renegotiation() {
    let (mut client, mut server) = connected_pair();
    server.renegotiate().unwrap();
    let (c, s) = pump(&mut client, &mut server);
    c.unwrap();
    s.unwrap();
    assert_eq!(client.renegotiation_count(), 1);
    assert_eq!(server.renegotiation_count(), 1);
    assert_eq!(server.peer_renegotiation_requests(), 0);
    server.send_application_data(b"ping").unwrap();
    pump_ok(&mut client, &mut server);
    assert_eq!(client.take_received_plaintext(), b"ping");
}

/// RFC 5746 §3.7: a renegotiating ClientHello whose `renegotiation_info`
/// does not carry the session's `client_verify_data` is refused.
#[test]
fn server_rejects_a_mismatched_client_binding() {
    let (mut client, mut server) = connected_pair();
    client.test_corrupt_renegotiation_binding();
    client.renegotiate().unwrap();
    let (_c, s) = pump(&mut client, &mut server);
    assert_eq!(s, Err(Error::HandshakeFailure));
}

/// RFC 5746 §3.5: the client checks the ServerHello's
/// `client_verify_data || server_verify_data` echo.
#[test]
fn client_rejects_a_mismatched_server_binding() {
    let (mut client, mut server) = connected_pair();
    server.test_corrupt_renegotiation_binding();
    client.renegotiate().unwrap();
    let (c, _s) = pump(&mut client, &mut server);
    assert_eq!(c, Err(Error::HandshakeFailure));
}

/// A renegotiation presenting another (equally trusted) server certificate
/// is refused by default, and accepted when the policy allows it.
#[test]
fn certificate_change_is_refused_unless_allowed() {
    let (_, der_a) = ecdsa_server12(b"reneg-server-key-a");
    let (_, der_b) = ecdsa_server12(b"reneg-server-key-b");
    let mut trust = roots(&der_a);
    trust.add_der(der_b.clone()).unwrap();

    for allow in [false, true] {
        let (cfg_a, _) = ecdsa_server12(b"reneg-server-key-a");
        let mut server = server_with(cfg_a, enabled(), b"reneg-chg-s");
        let policy = enabled().with_peer_certificate_change(allow);
        let mut client = client_with(trust.clone_store(), policy, b"reneg-chg-c");
        let (c, s) = pump(&mut client, &mut server);
        c.unwrap();
        s.unwrap();
        assert_eq!(client.peer_certificates()[0], der_a);

        let (mut next, _) = ecdsa_server12(b"reneg-server-key-b");
        next.renegotiation = enabled();
        server.test_replace_config(next);
        client.renegotiate().unwrap();
        let (c, _s) = pump(&mut client, &mut server);
        if allow {
            c.unwrap();
            assert_eq!(client.peer_certificates()[0], der_b);
            assert_eq!(client.renegotiation_count(), 1);
        } else {
            assert_eq!(c, Err(Error::PeerCertificateChanged));
        }
    }
}

/// The default server declines with a warning and keeps the session; the
/// client gives up the renegotiation and carries on.
#[test]
fn declined_renegotiation_keeps_the_session() {
    let (cfg, der) = ecdsa_server12(b"reneg-server-key-a");
    let mut server = server_with(cfg, RenegotiationPolicy::default(), b"reneg-dec-s");
    let mut client = client_with(roots(&der), enabled(), b"reneg-dec-c");
    let (c, s) = pump(&mut client, &mut server);
    c.unwrap();
    s.unwrap();
    let cr = client.client_random();
    let ms = client.master_secret();

    client.renegotiate().unwrap();
    client.send_application_data(b"queued").unwrap();
    let (c, s) = pump(&mut client, &mut server);
    c.unwrap();
    s.unwrap();
    assert!(!client.is_renegotiating());
    assert_eq!(client.renegotiation_count(), 0);
    assert_eq!(server.peer_renegotiation_requests(), 1);
    assert_eq!(client.client_random(), cr, "the old session stays in place");
    assert_eq!(client.master_secret(), ms);
    assert_eq!(server.take_received_plaintext(), b"queued");
    server.send_application_data(b"still").unwrap();
    pump_ok(&mut client, &mut server);
    assert_eq!(client.take_received_plaintext(), b"still");
}

/// The default client declines a HelloRequest with a warning; the server
/// clears its outstanding request and the session carries on.
#[test]
fn client_declines_a_hello_request_by_default() {
    let (cfg, der) = ecdsa_server12(b"reneg-server-key-a");
    let mut server = server_with(cfg, enabled(), b"reneg-hr-s");
    let mut client = client_with(roots(&der), RenegotiationPolicy::default(), b"reneg-hr-c");
    pump(&mut client, &mut server).0.unwrap();
    assert_eq!(client.renegotiate(), Err(Error::InappropriateState));
    server.renegotiate().unwrap();
    let (c, s) = pump(&mut client, &mut server);
    c.unwrap();
    s.unwrap();
    assert_eq!(client.renegotiation_count(), 0);
    // The request was answered, so a new one goes out.
    server.renegotiate().unwrap();
    assert!(!server.write_tls().is_empty());
}

/// The limiter drains over the window: two quick renegotiations fit the
/// PHP default, the third exceeds it (closing the connection), and after a
/// window's worth of time the bucket has room again.
#[test]
fn client_limit_follows_the_clock() {
    let policy = enabled().with_client_limit(Some(RenegotiationLimit::PHP_DEFAULT));
    let (cfg, der) = ecdsa_server12(b"reneg-server-key-a");
    let mut server = server_with(cfg, policy.clone(), b"reneg-clk-s");
    server.test_set_renegotiation_clock(1_000);
    let mut client = client_with(roots(&der), enabled(), b"reneg-clk-c");
    pump(&mut client, &mut server).0.unwrap();

    for _ in 0..2 {
        client.renegotiate().unwrap();
        pump(&mut client, &mut server).1.unwrap();
    }
    // 300 s later two tokens have drained: two more fit.
    server.test_set_renegotiation_clock(1_300);
    for _ in 0..2 {
        client.renegotiate().unwrap();
        pump(&mut client, &mut server).1.unwrap();
    }
    assert!(!server.renegotiation_limit_exceeded());
    client.renegotiate().unwrap();
    let (c, s) = pump(&mut client, &mut server);
    assert_eq!(s, Err(Error::RenegotiationLimitExceeded));
    assert_eq!(
        c,
        Err(Error::AlertReceived(
            crate::tls::AlertDescription::HandshakeFailure
        ))
    );
    assert!(server.renegotiation_limit_exceeded());
    assert_eq!(server.renegotiation_count(), 4);
}

/// A server's Finished protected under the old keys (no ChangeCipherSpec)
/// cannot complete a renegotiation, and a HelloRequest the server sends
/// mid-renegotiation is ignored.
#[test]
fn renegotiation_requires_the_change_cipher_spec() {
    let (mut client, mut server) = connected_pair();
    client.renegotiate().unwrap();
    server.read_tls(&client.write_tls());
    server.process_new_packets().unwrap();
    // A HelloRequest while the client is renegotiating is ignored.
    let hr = crate::tls::codec::handshake12::HelloRequest.encode();
    server
        .test_emit_encrypted(ContentType::Handshake, &hr)
        .unwrap();
    client.read_tls(&server.write_tls());
    client.process_new_packets().unwrap();
    assert!(client.is_renegotiating());

    // Start over on a fresh renegotiation: queue a forged Finished right
    // behind the server's first flight, under the old keys, so it reaches
    // the client while it waits for the server's ChangeCipherSpec.
    let (mut client, mut server) = connected_pair();
    client.renegotiate().unwrap();
    server.read_tls(&client.write_tls());
    server.process_new_packets().unwrap();
    let mut forged = alloc::vec![20u8, 0, 0, 12];
    forged.extend_from_slice(&[0u8; 12]);
    server
        .test_emit_encrypted(ContentType::Handshake, &forged)
        .unwrap();
    client.read_tls(&server.write_tls());
    assert_eq!(client.process_new_packets(), Err(Error::UnexpectedMessage));
}

/// RFC 7627 §6.2: a session without Extended Master Secret is never
/// renegotiated — neither side starts one, and a HelloRequest is declined.
#[test]
fn sessions_without_ems_do_not_renegotiate() {
    let (cfg, der) = ecdsa_server12(b"reneg-server-key-a");
    let mut server = server_with(cfg, enabled(), b"reneg-noems-s");
    server.test_force_no_ems = true;
    let mut ccfg: ClientConfig12 = client_config12(roots(&der)).with_require_ems(false);
    ccfg.renegotiation = enabled();
    let mut rng = HmacDrbg::<Sha256>::new(b"reneg-noems-c", b"nonce", &[]);
    let mut client = ClientConnection12::new_with_offer(
        ccfg,
        "loopback.example",
        &mut rng,
        &[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        &[NamedGroup::X25519],
    );
    pump_ok(&mut client, &mut server);
    assert!(!client.ems_negotiated());
    assert_eq!(client.renegotiate(), Err(Error::InappropriateState));
    assert_eq!(server.renegotiate(), Err(Error::InappropriateState));

    let hr = crate::tls::codec::handshake12::HelloRequest.encode();
    server
        .test_emit_encrypted(ContentType::Handshake, &hr)
        .unwrap();
    pump_ok(&mut client, &mut server);
    assert!(!client.is_renegotiating());
    assert_eq!(client.renegotiation_count(), 0);
}

/// A peer that starts a renegotiation and then stalls cannot make the other
/// side buffer without limit: past 1 MiB, `send_application_data` refuses
/// (queueing nothing) with `RenegotiationBufferFull`, and once the
/// renegotiation completes the queued data is delivered and sending works
/// again.
#[test]
fn stalled_renegotiation_bounds_the_send_queue() {
    use crate::tls::reneg::MAX_RENEG_PENDING_APP_OUT;
    let (mut client, mut server) = connected_pair();
    // The client asks for a renegotiation; the server enters it and sends
    // its flight, which the client then sits on.
    client.renegotiate().unwrap();
    let ch = client.write_tls();
    server.read_tls(&ch);
    server.process_new_packets().unwrap();
    assert!(server.is_renegotiating());

    let chunk = alloc::vec![0x5a; 64 * 1024];
    let mut queued = 0usize;
    loop {
        match server.send_application_data(&chunk) {
            Ok(()) => queued += chunk.len(),
            Err(e) => {
                assert_eq!(e, Error::RenegotiationBufferFull);
                break;
            }
        }
        assert!(
            queued <= MAX_RENEG_PENDING_APP_OUT,
            "queue grew past the cap"
        );
    }
    assert_eq!(queued, MAX_RENEG_PENDING_APP_OUT);
    assert_eq!(
        server.send_application_data(b"x"),
        Err(Error::RenegotiationBufferFull)
    );
    // The client side is bounded the same way.
    let mut cqueued = 0usize;
    while client.send_application_data(&chunk).is_ok() {
        cqueued += chunk.len();
        assert!(cqueued <= MAX_RENEG_PENDING_APP_OUT);
    }
    assert_eq!(cqueued, MAX_RENEG_PENDING_APP_OUT);

    // The client resumes: the renegotiation completes and both queues flush.
    let (c, s) = pump(&mut client, &mut server);
    c.unwrap();
    s.unwrap();
    assert!(!client.is_renegotiating() && !server.is_renegotiating());
    assert_eq!(client.take_received_plaintext().len(), queued);
    assert_eq!(server.take_received_plaintext().len(), cqueued);
    server.send_application_data(&chunk).unwrap();
    pump_ok(&mut client, &mut server);
    assert_eq!(client.take_received_plaintext().len(), chunk.len());
}

/// RFC 5246 §7.2.1 / RFC 8446 §6.1 parity: bytes after the peer's
/// `close_notify` — coalesced behind it or fed later — are ignored, in both
/// roles, instead of failing the cleanly closed connection with a fatal
/// alert.
#[test]
fn input_after_close_notify_is_ignored() {
    // An application_data record no key could open.
    let junk: &[u8] = &[23, 3, 3, 0, 5, 1, 2, 3, 4, 5];

    let (mut client, mut server) = connected_pair();
    client.send_close_notify();
    let mut wire = client.write_tls();
    wire.extend_from_slice(junk);
    server.read_tls(&wire);
    server.process_new_packets().unwrap();
    assert!(server.received_close_notify());
    server.process_new_packets().unwrap();
    server.read_tls(junk);
    server.process_new_packets().unwrap();
    assert!(
        server.write_tls().is_empty(),
        "no fatal alert after a clean close"
    );
    // Our own close_notify still goes out.
    server.send_close_notify();
    assert!(!server.write_tls().is_empty());

    let (mut client, mut server) = connected_pair();
    server.send_close_notify();
    let mut wire = server.write_tls();
    wire.extend_from_slice(junk);
    client.read_tls(&wire);
    client.process_new_packets().unwrap();
    assert!(client.received_close_notify());
    client.read_tls(junk);
    client.process_new_packets().unwrap();
    assert!(
        client.write_tls().is_empty(),
        "no fatal alert after a clean close"
    );
}
