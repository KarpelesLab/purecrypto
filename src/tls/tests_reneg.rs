//! TLS 1.2 secure renegotiation (RFC 5746) through the public
//! [`Connection`]: the `Config::renegotiation` knobs, both initiators, the
//! client limit's three actions, and the protocols that do not renegotiate.
//! Engine-level cases (binding mismatch, certificate change, the limiter
//! clock) live in `conn::tests_reneg`.
//!
//! The harness draws entropy from `rng::OsRng`, so the module needs `std`.

use alloc::vec;
use alloc::vec::Vec;

use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
use crate::hash::Sha256;
use crate::rng::HmacDrbg;
use crate::tls::{
    AlertDescription, ClientAuth, Config, ConfigBuilder, Connection, Error, ProtocolVersion,
    RenegotiationLimit, RenegotiationLimitAction, RenegotiationPolicy, RootCertStore, SigningKey,
};
use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

const HOST: &str = "reneg.example";
const V12: ProtocolVersion = ProtocolVersion::TLSv1_2;
const V13: ProtocolVersion = ProtocolVersion::TLSv1_3;

fn key(seed: &[u8]) -> BoxedEcdsaPrivateKey {
    let mut rng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
    BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng)
}

fn leaf(key: &BoxedEcdsaPrivateKey) -> Vec<u8> {
    Certificate::self_signed_general(
        &CertSigner::Ecdsa(key),
        &DistinguishedName::common_name(HOST),
        &Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        ),
        1,
        false,
        &[HOST],
    )
    .unwrap()
    .to_der()
    .to_vec()
}

fn roots_of(der: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::new();
    roots.add_der(der.to_vec()).unwrap();
    roots
}

/// A server (`min..=max`) and the client trust anchor for it.
fn server(min: ProtocolVersion, max: ProtocolVersion) -> (ConfigBuilder, Vec<u8>) {
    let k = key(b"reneg-conn-server");
    let der = leaf(&k);
    let b = Config::builder()
        .os_rng()
        .versions(min, max)
        .identity(vec![der.clone()], SigningKey::Ecdsa(k));
    (b, der)
}

fn client(min: ProtocolVersion, max: ProtocolVersion, trust: &[u8]) -> ConfigBuilder {
    Config::builder()
        .os_rng()
        .versions(min, max)
        .server_name(HOST)
        .roots(roots_of(trust))
        .verification_time(Time::utc(2030, 6, 1, 0, 0, 0))
}

/// Moves bytes both ways until neither side has any, returning each side's
/// first error. A failing side's queued alert is still delivered.
fn pump(c: &mut Connection, s: &mut Connection) -> (Result<(), Error>, Result<(), Error>) {
    let (mut ce, mut se) = (Ok(()), Ok(()));
    for _ in 0..64 {
        let a = c.pop().unwrap();
        if !a.is_empty() && se.is_ok() {
            se = s.feed(&a).map(drop);
        }
        let b = s.pop().unwrap();
        if !b.is_empty() && ce.is_ok() {
            ce = c.feed(&b).map(drop);
        }
        if a.is_empty() && b.is_empty() {
            break;
        }
    }
    (ce, se)
}

fn pump_ok(c: &mut Connection, s: &mut Connection) {
    let (ce, se) = pump(c, s);
    ce.unwrap();
    se.unwrap();
}

fn connect(client_cfg: &Config, server_cfg: &Config) -> (Connection, Connection) {
    let mut c = Connection::client(client_cfg).unwrap();
    let mut s = Connection::server(server_cfg).unwrap();
    pump_ok(&mut c, &mut s);
    assert!(c.is_handshake_complete() && s.is_handshake_complete());
    (c, s)
}

/// Sends `data` from `from` to `to` and returns what `to` received.
fn echo(from: &mut Connection, to: &mut Connection, data: &[u8]) -> Vec<u8> {
    from.send(data).unwrap();
    pump_ok(from, to);
    to.recv().unwrap()
}

fn exporter(c: &Connection) -> [u8; 32] {
    let mut out = [0u8; 32];
    c.tls_exporter(b"EXPORTER-reneg-test", b"", &mut out)
        .unwrap();
    out
}

/// Client- and server-initiated renegotiation, with data flowing before
/// and after and the keys replaced each time — on a pinned TLS 1.2 server
/// and on a version-spanning one that negotiated 1.2.
#[test]
fn both_initiators_renegotiate_when_enabled() {
    for server_max in [V12, V13] {
        let (sb, der) = server(V12, server_max);
        let server_cfg = sb.allow_renegotiation(true).build();
        let client_cfg = client(V12, V12, &der).allow_renegotiation(true).build();
        let (mut c, mut s) = connect(&client_cfg, &server_cfg);
        assert_eq!(c.negotiated_version(), Some(V12));
        assert_eq!(echo(&mut c, &mut s, b"one"), b"one");
        let k0 = exporter(&c);

        c.renegotiate().unwrap();
        assert!(c.is_renegotiating());
        assert!(c.is_handshake_complete(), "the session stays usable");
        pump_ok(&mut c, &mut s);
        assert_eq!((c.renegotiation_count(), s.renegotiation_count()), (1, 1));
        let k1 = exporter(&c);
        assert_ne!(k0, k1);
        assert_eq!(k1, exporter(&s));
        assert_eq!(echo(&mut s, &mut c, b"two"), b"two");

        s.renegotiate().unwrap();
        pump_ok(&mut c, &mut s);
        assert_eq!((c.renegotiation_count(), s.renegotiation_count()), (2, 2));
        assert_ne!(k1, exporter(&s));
        assert_eq!(
            s.peer_renegotiation_requests(),
            1,
            "the solicited one is not counted"
        );
        assert_eq!(echo(&mut c, &mut s, b"three"), b"three");
    }
}

/// Off by default: `renegotiate` is refused, and a peer's request is
/// declined with a warning that leaves the session up — both directions.
#[test]
fn renegotiation_is_declined_by_default() {
    let (sb, der) = server(V12, V12);
    let default_server = sb.build();
    let (sb, _) = server(V12, V12);
    let enabled_server = sb.allow_renegotiation(true).build();
    let default_client = client(V12, V12, &der).build();
    let enabled_client = client(V12, V12, &der).allow_renegotiation(true).build();

    // Neither side can start one.
    let (mut c, mut s) = connect(&default_client, &default_server);
    assert_eq!(c.renegotiate(), Err(Error::InappropriateState));
    assert_eq!(s.renegotiate(), Err(Error::InappropriateState));
    assert_eq!(echo(&mut c, &mut s, b"x"), b"x");

    // Client-initiated, declined by the default server.
    let (mut c, mut s) = connect(&enabled_client, &default_server);
    c.renegotiate().unwrap();
    c.send(b"queued").unwrap();
    pump_ok(&mut c, &mut s);
    assert!(!c.is_renegotiating());
    assert_eq!(c.renegotiation_count(), 0);
    assert_eq!(s.peer_renegotiation_requests(), 1);
    assert_eq!(s.recv().unwrap(), b"queued");
    assert_eq!(echo(&mut s, &mut c, b"still up"), b"still up");

    // Server-initiated, declined by the default client.
    let (mut c, mut s) = connect(&default_client, &enabled_server);
    s.renegotiate().unwrap();
    pump_ok(&mut c, &mut s);
    assert_eq!(s.renegotiation_count(), 0);
    assert_eq!(echo(&mut c, &mut s, b"y"), b"y");
}

/// The three limit actions: `Close` fails the connection, `Refuse`
/// declines and keeps it, `Notify` lets the renegotiation through and
/// raises the flag (PHP's `reneg_limit_callback`).
#[test]
fn client_limit_actions() {
    let one = Some(RenegotiationLimit {
        max: 1,
        window_secs: 300,
    });
    for action in [
        RenegotiationLimitAction::Close,
        RenegotiationLimitAction::Refuse,
        RenegotiationLimitAction::Notify,
    ] {
        let (sb, der) = server(V12, V12);
        let server_cfg = sb
            .allow_renegotiation(true)
            .renegotiation_limit(one, action)
            .build();
        let client_cfg = client(V12, V12, &der).allow_renegotiation(true).build();
        let (mut c, mut s) = connect(&client_cfg, &server_cfg);

        c.renegotiate().unwrap();
        pump_ok(&mut c, &mut s);
        assert_eq!(s.renegotiation_count(), 1);
        assert!(!s.renegotiation_limit_exceeded());

        c.renegotiate().unwrap();
        let (ce, se) = pump(&mut c, &mut s);
        assert!(s.renegotiation_limit_exceeded(), "{action:?}");
        assert_eq!(s.peer_renegotiation_requests(), 2);
        match action {
            RenegotiationLimitAction::Close => {
                assert_eq!(se, Err(Error::RenegotiationLimitExceeded));
                assert_eq!(
                    ce,
                    Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
                );
            }
            RenegotiationLimitAction::Refuse => {
                ce.unwrap();
                se.unwrap();
                assert_eq!(s.renegotiation_count(), 1);
                assert_eq!(echo(&mut c, &mut s, b"kept"), b"kept");
            }
            _ => {
                ce.unwrap();
                se.unwrap();
                assert_eq!(s.renegotiation_count(), 2);
                // The caller decides (PHP: close unless the callback says
                // otherwise).
                s.close().unwrap();
                pump_ok(&mut c, &mut s);
                assert!(c.received_close_notify());
            }
        }
    }
}

/// `client_limit: None` lifts the limit; a server-solicited renegotiation
/// never counts against it, even at `max = 0`.
#[test]
fn unlimited_and_solicited_renegotiations() {
    let (sb, der) = server(V12, V12);
    let server_cfg = sb
        .renegotiation(RenegotiationPolicy::enabled().with_client_limit(None))
        .build();
    let client_cfg = client(V12, V12, &der).allow_renegotiation(true).build();
    let (mut c, mut s) = connect(&client_cfg, &server_cfg);
    for _ in 0..5 {
        c.renegotiate().unwrap();
        pump_ok(&mut c, &mut s);
    }
    assert_eq!(s.renegotiation_count(), 5);

    let (sb, der) = server(V12, V12);
    let server_cfg = sb
        .allow_renegotiation(true)
        .renegotiation_limit(
            Some(RenegotiationLimit {
                max: 0,
                window_secs: 1,
            }),
            RenegotiationLimitAction::Close,
        )
        .build();
    let client_cfg = client(V12, V12, &der).allow_renegotiation(true).build();
    let (mut c, mut s) = connect(&client_cfg, &server_cfg);
    for _ in 0..3 {
        s.renegotiate().unwrap();
        pump_ok(&mut c, &mut s);
    }
    assert_eq!(s.renegotiation_count(), 3);
    assert!(!s.renegotiation_limit_exceeded());
}

/// mTLS: the renegotiation re-authenticates the client with the same
/// certificate.
#[test]
fn mutual_tls_renegotiation_keeps_the_client_identity() {
    let ck = key(b"reneg-conn-client");
    let cder = leaf(&ck);
    let (sb, der) = server(V12, V12);
    let server_cfg = sb
        .allow_renegotiation(true)
        .client_auth(ClientAuth::new(roots_of(&cder), true))
        .verification_time(Time::utc(2030, 6, 1, 0, 0, 0))
        .build();
    let client_cfg = client(V12, V12, &der)
        .allow_renegotiation(true)
        .identity(vec![cder.clone()], SigningKey::Ecdsa(ck))
        .build();
    let (mut c, mut s) = connect(&client_cfg, &server_cfg);
    s.renegotiate().unwrap();
    pump_ok(&mut c, &mut s);
    assert_eq!(s.renegotiation_count(), 1);
    assert_eq!(s.peer_certificates(), &[cder]);
    assert_eq!(echo(&mut c, &mut s, b"authenticated"), b"authenticated");
}

/// TLS 1.3 has no renegotiation (KeyUpdate replaces it), whatever the
/// policy.
#[test]
fn tls13_does_not_renegotiate() {
    let (sb, der) = server(V12, V13);
    let server_cfg = sb.allow_renegotiation(true).build();
    let client_cfg = client(V12, V13, &der).allow_renegotiation(true).build();
    let (mut c, mut s) = connect(&client_cfg, &server_cfg);
    assert_eq!(c.negotiated_version(), Some(V13));
    assert_eq!(c.renegotiate(), Err(Error::InappropriateState));
    assert_eq!(s.renegotiate(), Err(Error::InappropriateState));
    assert_eq!(c.renegotiation_count(), 0);
}
