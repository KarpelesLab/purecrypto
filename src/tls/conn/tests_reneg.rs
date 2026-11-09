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

// ---- Staging of the renegotiated session (nothing unproven is exposed) ----

/// A P-256 self-signed client identity named `cn` from `seed`.
fn client_identity(seed: &[u8], cn: &str) -> (Vec<u8>, BoxedEcdsaPrivateKey) {
    let mut rng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
    let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
    let der = Certificate::self_signed_general(
        &CertSigner::Ecdsa(&key),
        &DistinguishedName::common_name(cn),
        &Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        ),
        1,
        false,
        &[cn],
    )
    .unwrap()
    .to_der()
    .to_vec();
    (der, key)
}

/// A server config that asks for (but does not require) a client
/// certificate chaining to `client_root`, speaking ALPN `h2`.
fn optional_client_auth_server(client_root: &[u8]) -> (ServerConfig12, Vec<u8>) {
    let (cfg, der) = ecdsa_server12(b"reneg-server-key-a");
    let mut cfg = cfg
        .with_client_auth(roots(client_root), false)
        .with_alpn(alloc::vec![b"h2".to_vec()])
        .with_verification_time(Time::utc(2026, 1, 1, 0, 0, 0));
    cfg.renegotiation = enabled();
    (cfg, der)
}

/// A renegotiation-enabled client speaking ALPN `h2`, with an optional
/// client identity.
fn alpn_client(
    trust: RootCertStore,
    policy: RenegotiationPolicy,
    identity: Option<(Vec<u8>, BoxedEcdsaPrivateKey)>,
    label: &[u8],
) -> ClientConnection12 {
    let mut cfg: ClientConfig12 = client_config12(trust).with_alpn(alloc::vec![b"h2".to_vec()]);
    if let Some((der, key)) = identity {
        cfg = cfg.with_client_cert(crate::tls::ClientCertConfig::with_ecdsa(
            alloc::vec![der],
            key,
        ));
    }
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

/// Splits a TLS byte stream into its records (header included).
fn split_records(mut wire: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while wire.len() >= 5 {
        let len = 5 + usize::from(u16::from_be_bytes([wire[3], wire[4]]));
        out.push(wire[..len].to_vec());
        wire = &wire[len..];
    }
    assert!(wire.is_empty(), "trailing partial record");
    out
}

/// Everything the server reports about its session.
#[derive(Debug, PartialEq, Eq)]
struct ServerView {
    certs: Vec<Vec<u8>>,
    sig_scheme: Option<u16>,
    suite: Option<u16>,
    group: Option<NamedGroup>,
    alpn: Option<Vec<u8>>,
    sni: Option<alloc::string::String>,
    master: Option<[u8; 48]>,
    exporter: [u8; 32],
    ems: bool,
    resumed: bool,
}

fn server_view(s: &Server) -> ServerView {
    let mut exporter = [0u8; 32];
    s.tls_exporter(b"EXPORTER-reneg-test", None, &mut exporter)
        .unwrap();
    ServerView {
        certs: s.peer_certificates().to_vec(),
        sig_scheme: s.peer_signature_scheme(),
        suite: s.negotiated_cipher_suite(),
        group: s.negotiated_group(),
        alpn: s.alpn_protocol().map(<[u8]>::to_vec),
        sni: s.peer_server_name().map(alloc::string::String::from),
        master: s.master_secret(),
        exporter,
        ems: s.ems_negotiated(),
        resumed: s.did_resume(),
    }
}

/// Everything the client reports about its session.
#[derive(Debug, PartialEq, Eq)]
struct ClientView {
    certs: Vec<Vec<u8>>,
    sig_scheme: Option<u16>,
    suite: Option<u16>,
    group: Option<NamedGroup>,
    alpn: Option<Vec<u8>>,
    client_random: [u8; 32],
    master: Option<[u8; 48]>,
    exporter: [u8; 32],
    ems: bool,
    resumed: bool,
}

fn client_view(c: &ClientConnection12) -> ClientView {
    let mut exporter = [0u8; 32];
    c.tls_exporter(b"EXPORTER-reneg-test", None, &mut exporter)
        .unwrap();
    ClientView {
        certs: c.peer_certificates().to_vec(),
        sig_scheme: c.peer_signature_scheme(),
        suite: c.negotiated_cipher_suite(),
        group: c.negotiated_group(),
        alpn: c.alpn_protocol().map(<[u8]>::to_vec),
        client_random: c.client_random(),
        master: c.master_secret(),
        exporter,
        ems: c.ems_negotiated(),
        resumed: c.did_resume(),
    }
}

/// A forged 12-byte `Finished` handshake message.
fn forged_finished() -> Vec<u8> {
    let mut forged = alloc::vec![20u8, 0, 0, 12];
    forged.extend_from_slice(&[0u8; 12]);
    forged
}

/// The attack the staging exists for: an anonymous client starts a
/// renegotiation, sends a `Certificate` carrying somebody else's (public)
/// chain, never proves possession of its key, and keeps sending
/// application data under the old keys. The server must keep describing
/// the anonymous session it actually authenticated — `peer_certificates()`
/// empty, exporter and every other accessor unchanged — when that data is
/// delivered, and after the renegotiation is torn down.
#[test]
fn unproven_client_certificate_is_not_exposed_mid_renegotiation() {
    let (victim_der, _victim_key) = client_identity(b"reneg-victim", "victim");
    let (cfg, der) = optional_client_auth_server(&victim_der);
    let mut server = server_with(cfg, enabled(), b"reneg-f1-s");
    let mut client = alpn_client(roots(&der), enabled(), None, b"reneg-f1-c");
    pump_ok(&mut client, &mut server);
    assert!(server.is_handshake_complete());
    let before = server_view(&server);
    assert!(before.certs.is_empty(), "the client is anonymous");
    assert_eq!(before.alpn.as_deref(), Some(&b"h2"[..]));
    assert_eq!(before.sni.as_deref(), Some("loopback.example"));

    // The renegotiating ClientHello; the server answers with its flight
    // (CertificateRequest included), which the attacker ignores.
    client.renegotiate().unwrap();
    server.read_tls(&client.write_tls());
    server.process_new_packets().unwrap();
    assert!(server.is_renegotiating());
    let _ = server.write_tls();
    assert_eq!(server_view(&server), before, "nothing changes at the hello");

    // Certificate(victim), then a request under the old keys.
    let mut entries = Vec::new();
    entries.extend_from_slice(&(victim_der.len() as u32).to_be_bytes()[1..]);
    entries.extend_from_slice(&victim_der);
    let mut msg = alloc::vec![11u8];
    msg.extend_from_slice(&(entries.len() as u32 + 3).to_be_bytes()[1..]);
    msg.extend_from_slice(&(entries.len() as u32).to_be_bytes()[1..]);
    msg.extend_from_slice(&entries);
    client
        .test_emit_encrypted(ContentType::Handshake, &msg)
        .unwrap();
    client
        .test_emit_encrypted(ContentType::ApplicationData, b"GET /admin")
        .unwrap();
    server.read_tls(&client.write_tls());
    server.process_new_packets().unwrap();
    assert!(server.is_renegotiating());
    assert_eq!(server.take_received_plaintext(), b"GET /admin");
    assert!(
        server.peer_certificates().is_empty(),
        "a certificate the client has not proven possession of"
    );
    assert_eq!(server_view(&server), before);

    // The renegotiation dies (the client's next message is not the
    // ClientKeyExchange): the anonymous session is still what is reported.
    client
        .test_emit_encrypted(ContentType::Handshake, &forged_finished())
        .unwrap();
    server.read_tls(&client.write_tls());
    assert!(server.process_new_packets().is_err());
    assert_eq!(server_view(&server), before);
}

/// "Certificate on demand": the client authenticates on the renegotiation.
/// The new session — the certificate, the master secret, the exporter —
/// becomes visible on the server only once the client's Finished has
/// verified; not when the Certificate arrives, nor after the
/// CertificateVerify and the ChangeCipherSpec.
#[test]
fn server_commits_the_renegotiated_session_at_the_client_finished() {
    let (client_der, client_key) = client_identity(b"reneg-ondemand", "client");
    // The first handshake does not ask for a certificate.
    let (cfg, der) = ecdsa_server12(b"reneg-server-key-a");
    let cfg = cfg.with_alpn(alloc::vec![b"h2".to_vec()]);
    let mut server = server_with(cfg, enabled(), b"reneg-f1b-s");
    let mut client = alpn_client(
        roots(&der),
        enabled(),
        Some((client_der.clone(), client_key)),
        b"reneg-f1b-c",
    );
    pump_ok(&mut client, &mut server);
    let before = server_view(&server);
    assert!(before.certs.is_empty());

    // The renegotiation does.
    server.test_replace_config(optional_client_auth_server(&client_der).0);
    client.renegotiate().unwrap();
    server.read_tls(&client.write_tls());
    server.process_new_packets().unwrap();
    client.read_tls(&server.write_tls());
    client.process_new_packets().unwrap();
    // Certificate, ClientKeyExchange, CertificateVerify, CCS, Finished.
    let flight = split_records(&client.write_tls());
    assert_eq!(flight.len(), 5);
    for record in &flight[..4] {
        server.read_tls(record);
        server.process_new_packets().unwrap();
        assert!(server.is_renegotiating());
        assert_eq!(server_view(&server), before);
    }
    server.read_tls(&flight[4]);
    server.process_new_packets().unwrap();
    assert!(!server.is_renegotiating());
    let after = server_view(&server);
    assert_eq!(after.certs, alloc::vec![client_der]);
    assert!(after.sig_scheme.is_some());
    assert_ne!(after.master, before.master);
    assert_ne!(after.exporter, before.exporter);
    assert_eq!(after.alpn, before.alpn);
    assert_eq!(after.sni, before.sni);
    pump_ok(&mut client, &mut server);
    assert_eq!(client.master_secret(), after.master);
}

/// The client mirror: until the server's Finished verifies, the client
/// keeps reporting the session being replaced — the old certificate, master
/// secret, randoms and exporter — and reports the new one afterwards. A
/// renegotiation that fails leaves the old session's values in place.
#[test]
fn client_commits_the_renegotiated_session_at_the_server_finished() {
    let (_, der_a) = ecdsa_server12(b"reneg-server-key-a");
    let (_, der_b) = ecdsa_server12(b"reneg-server-key-b");
    let mut trust = roots(&der_a);
    trust.add_der(der_b.clone()).unwrap();
    let policy = enabled().with_peer_certificate_change(true);

    for complete in [true, false] {
        let (cfg_a, _) = ecdsa_server12(b"reneg-server-key-a");
        let mut server = server_with(cfg_a, enabled(), b"reneg-f1c-s");
        let mut client = alpn_client(trust.clone_store(), policy.clone(), None, b"reneg-f1c-c");
        pump_ok(&mut client, &mut server);
        let before = client_view(&client);
        assert_eq!(before.certs, alloc::vec![der_a.clone()]);

        let (mut next, _) = ecdsa_server12(b"reneg-server-key-b");
        next.renegotiation = enabled();
        server.test_replace_config(next);
        client.renegotiate().unwrap();
        assert_eq!(client_view(&client), before);
        server.read_tls(&client.write_tls());
        server.process_new_packets().unwrap();
        // ServerHello .. ServerHelloDone, with the other certificate: the
        // client answers with its own flight and waits for the Finished.
        client.read_tls(&server.write_tls());
        client.process_new_packets().unwrap();
        assert!(client.is_renegotiating());
        assert_eq!(client_view(&client), before);

        if complete {
            pump_ok(&mut client, &mut server);
            assert!(!client.is_renegotiating());
            let after = client_view(&client);
            assert_eq!(after.certs, alloc::vec![der_b.clone()]);
            assert_ne!(after.master, before.master);
            assert_ne!(after.client_random, before.client_random);
            assert_ne!(after.exporter, before.exporter);
            assert_eq!(after.master, server.master_secret());
        } else {
            // A Finished under the old keys instead of the server's CCS.
            let _ = client.write_tls();
            server
                .test_emit_encrypted(ContentType::Handshake, &forged_finished())
                .unwrap();
            client.read_tls(&server.write_tls());
            assert_eq!(client.process_new_packets(), Err(Error::UnexpectedMessage));
            assert_eq!(client_view(&client), before);
        }
    }
}

/// A renegotiation that fails closes the engine for good: application data
/// arriving afterwards under the (still installed) old keys is refused, not
/// delivered — in both roles, and whether the failure came from the
/// handshake, a fatal alert or `abort`.
#[test]
fn failed_renegotiation_stops_delivering_application_data() {
    // Server: the renegotiating ClientHello carries a corrupted binding.
    let (mut client, mut server) = connected_pair();
    client.test_corrupt_renegotiation_binding();
    client.renegotiate().unwrap();
    server.read_tls(&client.write_tls());
    assert_eq!(server.process_new_packets(), Err(Error::HandshakeFailure));
    assert!(!server.is_renegotiating());
    assert_eq!(
        server.send_application_data(b"x"),
        Err(Error::InappropriateState)
    );
    client
        .test_emit_encrypted(ContentType::ApplicationData, b"after the failure")
        .unwrap();
    server.read_tls(&client.write_tls());
    assert_eq!(server.process_new_packets(), Err(Error::UnexpectedMessage));
    assert!(server.take_received_plaintext().is_empty());

    // Client: the ServerHello's echo does not match.
    let (mut client, mut server) = connected_pair();
    server.test_corrupt_renegotiation_binding();
    client.renegotiate().unwrap();
    client.send_application_data(b"queued, never sent").unwrap();
    server.read_tls(&client.write_tls());
    server.process_new_packets().unwrap();
    client.read_tls(&server.write_tls());
    assert_eq!(client.process_new_packets(), Err(Error::HandshakeFailure));
    assert!(!client.is_renegotiating());
    server
        .test_emit_encrypted(ContentType::ApplicationData, b"after the failure")
        .unwrap();
    client.read_tls(&server.write_tls());
    assert_eq!(client.process_new_packets(), Err(Error::UnexpectedMessage));
    assert!(client.take_received_plaintext().is_empty());

    // A fatal alert mid-renegotiation, and `abort`, close the same way.
    let (mut client, mut server) = connected_pair();
    client.renegotiate().unwrap();
    server.read_tls(&client.write_tls());
    server.process_new_packets().unwrap();
    assert!(server.is_renegotiating());
    let _ = server.write_tls();
    client
        .test_emit_encrypted(ContentType::Alert, &[2, 40])
        .unwrap();
    client
        .test_emit_encrypted(ContentType::ApplicationData, b"after the alert")
        .unwrap();
    server.read_tls(&client.write_tls());
    assert_eq!(
        server.process_new_packets(),
        Err(Error::AlertReceived(
            crate::tls::AlertDescription::HandshakeFailure
        ))
    );
    assert_eq!(server.process_new_packets(), Err(Error::UnexpectedMessage));
    assert!(server.take_received_plaintext().is_empty());

    let (mut client, mut server) = connected_pair();
    client.renegotiate().unwrap();
    let _ = client.write_tls();
    client.abort(crate::tls::AlertDescription::InternalError);
    assert!(!client.is_renegotiating());
    server
        .test_emit_encrypted(ContentType::ApplicationData, b"after the abort")
        .unwrap();
    client.read_tls(&server.write_tls());
    assert_eq!(client.process_new_packets(), Err(Error::UnexpectedMessage));
    assert!(client.take_received_plaintext().is_empty());
}

/// A default server (renegotiation off) declines a ClientHello with a
/// `no_renegotiation` warning — a bounded number of times. A flood of
/// 4-byte ClientHellos does not buy an alert each: past the budget the
/// connection is closed with a fatal `unexpected_message`, and what the
/// server queued stays small.
#[test]
fn client_hello_flood_gets_bounded_declines() {
    let (cfg, der) = ecdsa_server12(b"reneg-server-key-a");
    let mut server = server_with(cfg, RenegotiationPolicy::default(), b"reneg-fl-s");
    server.test_set_renegotiation_clock(1_000);
    let mut client = client_with(roots(&der), enabled(), b"reneg-fl-c");
    pump_ok(&mut client, &mut server);

    // `ClientHello` with an empty body: declined before it is parsed.
    for _ in 0..10_000 {
        client
            .test_emit_encrypted(ContentType::Handshake, &[1, 0, 0, 0])
            .unwrap();
    }
    server.read_tls(&client.write_tls());
    assert_eq!(server.process_new_packets(), Err(Error::UnexpectedMessage));
    let out = split_records(&server.write_tls());
    // Four warnings and the fatal alert.
    assert_eq!(out.len(), 5);
    assert!(out.iter().all(|r| r[0] == 21 && r.len() < 64));
    assert_eq!(server.peer_renegotiation_requests(), 5);
    // The engine is closed: nothing further is answered or delivered.
    assert_eq!(
        server.send_application_data(b"x"),
        Err(Error::InappropriateState)
    );

    // The budget is a rate, not a lifetime cap: a client asking (and being
    // refused) now and then is never cut off.
    let (cfg, der) = ecdsa_server12(b"reneg-server-key-a");
    let mut server = server_with(cfg, RenegotiationPolicy::default(), b"reneg-fl2-s");
    let mut client = client_with(roots(&der), enabled(), b"reneg-fl2-c");
    pump_ok(&mut client, &mut server);
    for round in 0..20u64 {
        server.test_set_renegotiation_clock(1_000 + round * 300);
        for _ in 0..4 {
            client
                .test_emit_encrypted(ContentType::Handshake, &[1, 0, 0, 0])
                .unwrap();
        }
        server.read_tls(&client.write_tls());
        server.process_new_packets().unwrap();
        assert_eq!(split_records(&server.write_tls()).len(), 4);
    }
    client.send_application_data(b"still up").unwrap();
    server.read_tls(&client.write_tls());
    server.process_new_packets().unwrap();
    assert_eq!(server.take_received_plaintext(), b"still up");
}

/// A server that keeps asking for a renegotiation (`HelloRequest`) and then
/// declining it (`no_renegotiation`) gets a bounded number of ClientHellos
/// — each of which costs the client fresh ephemeral keys — out of a
/// renegotiation-enabled client; after that its prompts earn one warning
/// and are then ignored. The session stays up throughout.
#[test]
fn solicited_then_declined_renegotiations_are_bounded() {
    use crate::tls::reneg::MAX_SOLICITED_DECLINES;
    let (mut client, mut server) = connected_pair();
    let hr = crate::tls::codec::handshake12::HelloRequest.encode();
    let mut hellos = 0usize;
    let mut alerts = 0usize;
    for _ in 0..200 {
        server
            .test_emit_encrypted(ContentType::Handshake, &hr)
            .unwrap();
        client.read_tls(&server.write_tls());
        client.process_new_packets().unwrap();
        // The server never reads the ClientHello; it just says no.
        for record in split_records(&client.write_tls()) {
            match record[0] {
                22 => hellos += 1,
                21 => alerts += 1,
                other => panic!("unexpected record type {other}"),
            }
        }
        server
            .test_emit_encrypted(ContentType::Alert, &[1, 100])
            .unwrap();
        client.read_tls(&server.write_tls());
        client.process_new_packets().unwrap();
        assert!(!client.is_renegotiating());
    }
    assert_eq!(hellos, usize::from(MAX_SOLICITED_DECLINES));
    assert_eq!(alerts, 1, "one no_renegotiation warning, then silence");
    assert_eq!(client.renegotiation_count(), 0);
    server.send_application_data(b"still up").unwrap();
    client.read_tls(&server.write_tls());
    client.process_new_packets().unwrap();
    assert_eq!(client.take_received_plaintext(), b"still up");
    // The application's own renegotiations are not affected by the cap.
    client.renegotiate().unwrap();
    assert!(client.is_renegotiating());
}

/// A ticket-issuing server config (identity `a`), renegotiation enabled.
fn ticket_server() -> (ServerConfig12, Vec<u8>) {
    let (cfg, der) = ecdsa_server12(b"reneg-server-key-a");
    let mut cfg = cfg
        .with_ticket_key([0x42; 32])
        .with_verification_time(Time::utc(2026, 1, 1, 0, 0, 0));
    cfg.renegotiation = enabled();
    (cfg, der)
}

/// A client for [`ticket_server`], optionally resuming `session`.
fn ticket_client(
    trust: RootCertStore,
    policy: RenegotiationPolicy,
    session: Option<crate::tls::conn::StoredSession12>,
    label: &[u8],
) -> ClientConnection12 {
    let mut cfg: ClientConfig12 = client_config12(trust);
    if let Some(s) = session {
        cfg = cfg.with_session(s);
    }
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

/// A resumed session and its server: a full handshake against
/// [`ticket_server`], then a second connection resuming the ticket (with
/// `edit` applied to the stored session first).
fn resumed_pair(
    policy: RenegotiationPolicy,
    edit: impl FnOnce(&mut crate::tls::conn::StoredSession12),
) -> (ClientConnection12, Server, Vec<u8>) {
    let (cfg, der) = ticket_server();
    let mut server = server_with(cfg, enabled(), b"reneg-f4-s1");
    let mut client = ticket_client(roots(&der), policy.clone(), None, b"reneg-f4-c1");
    pump_ok(&mut client, &mut server);
    let mut session = client.take_session().expect("the server issued a ticket");
    assert_eq!(
        session.server_leaf_sha256,
        Some(crate::tls::reneg::leaf_pin(&der))
    );
    edit(&mut session);

    let (cfg, _) = ticket_server();
    let mut server = server_with(cfg, enabled(), b"reneg-f4-s2");
    let mut trust = roots(&der);
    trust
        .add_der(ecdsa_server12(b"reneg-server-key-b").1)
        .unwrap();
    let mut client = ticket_client(trust, policy, Some(session), b"reneg-f4-c2");
    pump_ok(&mut client, &mut server);
    assert!(client.did_resume() && server.did_resume());
    assert!(client.peer_certificates().is_empty());
    (client, server, der)
}

/// A session resumed from a ticket ran no `Certificate` message, but the
/// same-certificate check still applies to its renegotiation: the stored
/// session remembers the leaf its originating handshake authenticated. The
/// same certificate is accepted (and the pin carried into the next stored
/// session); another one — trusted or not — is `PeerCertificateChanged`.
#[test]
fn resumed_client_session_pins_the_original_server_certificate() {
    // Same certificate: the renegotiation completes.
    let (mut client, mut server, der) = resumed_pair(enabled(), |_| {});
    client.renegotiate().unwrap();
    pump_ok(&mut client, &mut server);
    assert_eq!(client.renegotiation_count(), 1);
    assert!(!client.did_resume());
    assert_eq!(client.peer_certificates(), &[der][..]);

    // A different (equally trusted) certificate: refused.
    let (mut client, mut server, _) = resumed_pair(enabled(), |_| {});
    let (mut next, _) = ecdsa_server12(b"reneg-server-key-b");
    next.renegotiation = enabled();
    server.test_replace_config(next);
    client.renegotiate().unwrap();
    let (c, _s) = pump(&mut client, &mut server);
    assert_eq!(c, Err(Error::PeerCertificateChanged));

    // ... unless the policy allows the change.
    let policy = enabled().with_peer_certificate_change(true);
    let (mut client, mut server, _) = resumed_pair(policy, |_| {});
    let (mut next, der_b) = ecdsa_server12(b"reneg-server-key-b");
    next.renegotiation = enabled();
    server.test_replace_config(next);
    client.renegotiate().unwrap();
    pump_ok(&mut client, &mut server);
    assert_eq!(client.peer_certificates(), &[der_b][..]);

    // The pin survives a chain of resumptions: a session taken from a
    // resumed connection still carries the original leaf's digest.
    let (cfg, der) = ticket_server();
    let mut server = server_with(cfg, enabled(), b"reneg-f4-s3");
    let mut client = ticket_client(roots(&der), enabled(), None, b"reneg-f4-c3");
    pump_ok(&mut client, &mut server);
    let first = client.take_session().unwrap();
    let (cfg, _) = ticket_server();
    let mut server = server_with(cfg, enabled(), b"reneg-f4-s4");
    let mut client = ticket_client(roots(&der), enabled(), Some(first), b"reneg-f4-c4");
    pump_ok(&mut client, &mut server);
    assert!(client.did_resume());
    if let Some(second) = client.take_session() {
        assert_eq!(
            second.server_leaf_sha256,
            Some(crate::tls::reneg::leaf_pin(&der))
        );
    }
}

/// A resumed session whose stored form carries no pin gives the client
/// nothing to hold a renegotiation's certificate to. Unless the policy
/// allows the certificate to change, the client does not renegotiate such a
/// session: `renegotiate()` is refused, a HelloRequest is declined, and the
/// session carries on.
#[test]
fn resumed_client_session_without_a_pin_is_not_renegotiated() {
    for allow in [false, true] {
        let policy = enabled().with_peer_certificate_change(allow);
        let (mut client, mut server, der) = resumed_pair(policy, |s| s.server_leaf_sha256 = None);
        if allow {
            client.renegotiate().unwrap();
            pump_ok(&mut client, &mut server);
            assert_eq!(client.renegotiation_count(), 1);
            assert_eq!(client.peer_certificates(), &[der][..]);
        } else {
            assert_eq!(client.renegotiate(), Err(Error::InappropriateState));
            assert!(!client.is_renegotiating());
            // The server asks: declined with a warning, nothing changes.
            server.renegotiate().unwrap();
            pump_ok(&mut client, &mut server);
            assert_eq!(client.renegotiation_count(), 0);
            assert_eq!(server.renegotiation_count(), 0);
            assert!(!server.is_renegotiating());
            server.send_application_data(b"still up").unwrap();
            pump_ok(&mut client, &mut server);
            assert_eq!(client.take_received_plaintext(), b"still up");
        }
    }
}

/// The backstop behind that: `check_peer_leaf` on a client fails closed
/// when the replaced session has no leaf on record, where a server treats
/// the same state as a client that was anonymous before.
#[test]
fn missing_previous_leaf_is_only_acceptable_to_a_server() {
    use crate::tls::reneg::{RenegState, leaf_pin};
    let state = RenegState {
        active: true,
        ..RenegState::default()
    };
    let policy = enabled();
    assert_eq!(state.check_peer_leaf(&policy, Some(b"leaf"), true), Ok(()));
    assert_eq!(
        state.check_peer_leaf(&policy, Some(b"leaf"), false),
        Err(Error::PeerCertificateChanged)
    );
    let lenient = enabled().with_peer_certificate_change(true);
    assert_eq!(
        state.check_peer_leaf(&lenient, Some(b"leaf"), false),
        Ok(())
    );

    let pinned = RenegState {
        active: true,
        prev_peer_leaf: Some(leaf_pin(b"leaf")),
        ..RenegState::default()
    };
    for role in [true, false] {
        assert_eq!(pinned.check_peer_leaf(&policy, Some(b"leaf"), role), Ok(()));
        assert_eq!(
            pinned.check_peer_leaf(&policy, Some(b"other"), role),
            Err(Error::PeerCertificateChanged)
        );
        assert_eq!(
            pinned.check_peer_leaf(&policy, None, role),
            Err(Error::PeerCertificateChanged)
        );
    }
}

/// Resumes `session` against a fresh [`ticket_server`] and reports whether
/// the server accepted the ticket (an abbreviated handshake) — which it
/// only does, and the Finished messages only verify, when the ticket and
/// the stored master secret belong together.
fn resumes(der: &[u8], session: crate::tls::conn::StoredSession12) -> bool {
    let (cfg, _) = ticket_server();
    let mut server = server_with(cfg, enabled(), b"reneg-f5-rs");
    let mut client = ticket_client(roots(der), enabled(), Some(session), b"reneg-f5-rc");
    pump_ok(&mut client, &mut server);
    client.did_resume() && server.did_resume()
}

/// `take_session` never pairs a ticket with a master secret other than the
/// one it seals: nothing is handed out while a renegotiation is in flight,
/// the renegotiated handshake's own ticket replaces the earlier one, and a
/// renegotiation that brings no ticket leaves no session to store.
#[test]
fn take_session_pairs_a_ticket_with_its_own_handshake() {
    // Mid-renegotiation: nothing, and nothing is lost by asking.
    let (cfg, der) = ticket_server();
    let mut server = server_with(cfg, enabled(), b"reneg-f5-s1");
    let mut client = ticket_client(roots(&der), enabled(), None, b"reneg-f5-c1");
    pump_ok(&mut client, &mut server);
    let ms_first = client.master_secret().unwrap();
    client.renegotiate().unwrap();
    assert!(client.take_session().is_none());
    server.read_tls(&client.write_tls());
    server.process_new_packets().unwrap();
    client.read_tls(&server.write_tls());
    client.process_new_packets().unwrap();
    // The new master secret is derived, the server's Finished not yet in.
    assert!(client.is_renegotiating());
    assert!(client.take_session().is_none());
    pump_ok(&mut client, &mut server);
    assert_eq!(client.renegotiation_count(), 1);
    // The renegotiated handshake issued its own ticket: that pair resumes.
    let session = client
        .take_session()
        .expect("a ticket from the renegotiation");
    assert_ne!(session.master_secret, ms_first);
    assert_eq!(Some(session.master_secret), client.master_secret());
    assert!(resumes(&der, session));
    assert!(client.take_session().is_none());

    // A renegotiation that issues no ticket: the first handshake's ticket
    // is not handed out with the renegotiated master secret.
    let (cfg, der) = ticket_server();
    let mut server = server_with(cfg, enabled(), b"reneg-f5-s2");
    let mut client = ticket_client(roots(&der), enabled(), None, b"reneg-f5-c2");
    pump_ok(&mut client, &mut server);
    let (mut no_tickets, _) = ecdsa_server12(b"reneg-server-key-a");
    no_tickets.renegotiation = enabled();
    server.test_replace_config(no_tickets);
    client.renegotiate().unwrap();
    pump_ok(&mut client, &mut server);
    assert_eq!(client.renegotiation_count(), 1);
    assert!(client.take_session().is_none());

    // A declined renegotiation leaves the first session, ticket included.
    let (cfg, der) = ticket_server();
    let mut server = server_with(cfg, RenegotiationPolicy::default(), b"reneg-f5-s3");
    let mut client = ticket_client(roots(&der), enabled(), None, b"reneg-f5-c3");
    pump_ok(&mut client, &mut server);
    let ms = client.master_secret().unwrap();
    client.renegotiate().unwrap();
    assert!(client.take_session().is_none());
    pump_ok(&mut client, &mut server);
    assert!(!client.is_renegotiating());
    let session = client.take_session().expect("the first handshake's ticket");
    assert_eq!(session.master_secret, ms);
    assert!(resumes(&der, session));

    // So does one that fails after the new master secret was derived.
    let (cfg, der) = ticket_server();
    let mut server = server_with(cfg, enabled(), b"reneg-f5-s4");
    let mut client = ticket_client(roots(&der), enabled(), None, b"reneg-f5-c4");
    pump_ok(&mut client, &mut server);
    let ms = client.master_secret().unwrap();
    client.renegotiate().unwrap();
    server.read_tls(&client.write_tls());
    server.process_new_packets().unwrap();
    client.read_tls(&server.write_tls());
    client.process_new_packets().unwrap();
    let _ = client.write_tls();
    server
        .test_emit_encrypted(ContentType::Handshake, &forged_finished())
        .unwrap();
    client.read_tls(&server.write_tls());
    assert_eq!(client.process_new_packets(), Err(Error::UnexpectedMessage));
    let session = client.take_session().expect("the first handshake's ticket");
    assert_eq!(session.master_secret, ms);
    assert!(resumes(&der, session));
}
