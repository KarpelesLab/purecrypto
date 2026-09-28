//! The last flight of a DTLS handshake on a lossy path.
//!
//! One side of every handshake finishes first: the DTLS 1.3 client when it
//! has *sent* its Finished, the servers when they have *received* the
//! client's. Whatever that side sends last — the client's Finished, the
//! DTLS 1.3 server's ACK for it, the DTLS 1.2 server's ChangeCipherSpec +
//! Finished — can be lost, and the other side is then still inside its
//! handshake. These tests drop exactly those datagrams and check that
//!
//! - the handshake still completes on both sides once the retransmission
//!   machinery runs (RFC 9147 §5.8.1 / §7, RFC 6347 §4.2.4);
//! - `handshake_flight_pending` tells the caller for how long that
//!   machinery must be driven;
//! - writing application data or closing in the meantime cannot strand the
//!   peer in its handshake;
//! - retransmission timers are armed from the clock the caller set.

use crate::dtls::{
    ClientConfig12Internal as PcClientConfig12, ClientConfig13Internal as PcClientConfig13,
    DtlsClientConnection12, DtlsClientConnection13, DtlsServerConnection12, DtlsServerConnection13,
    ServerConfig12Internal as PcServerConfig12, ServerConfig13Internal as PcServerConfig13,
};
use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
use crate::hash::Sha256;
use crate::rng::HmacDrbg;
use crate::tls::Error;
use crate::tls::pki::RootCertStore;
use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

type Server13 = DtlsServerConnection13<HmacDrbg<Sha256>>;
type Server12 = DtlsServerConnection12<HmacDrbg<Sha256>>;

/// ECDSA P-256 self-signed server certificate + key.
fn identity() -> (BoxedEcdsaPrivateKey, Vec<u8>) {
    let mut rng = HmacDrbg::<Sha256>::new(b"final-flight-key", b"nonce", &[]);
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
    (key, cert.to_der().to_vec())
}

fn roots(cert: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::new();
    roots.add_der(cert.to_vec()).unwrap();
    roots
}

fn pair13() -> (DtlsClientConnection13, Server13) {
    let (key, cert) = identity();
    let ccfg = PcClientConfig13::new(roots(&cert), "dtls.example")
        .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
    let mut crng = HmacDrbg::<Sha256>::new(b"ff13-client", b"nonce", &[]);
    let client = DtlsClientConnection13::new(ccfg, b"peer".to_vec(), &mut crng);
    let scfg = PcServerConfig13::with_ecdsa(alloc::vec![cert], key).with_no_cookie();
    let srng = HmacDrbg::<Sha256>::new(b"ff13-server", b"nonce", &[]);
    let server = DtlsServerConnection13::new(Arc::new(scfg), b"peer".to_vec(), srng);
    (client, server)
}

fn pair12() -> (DtlsClientConnection12, Server12) {
    let (key, cert) = identity();
    let ccfg = PcClientConfig12::new(roots(&cert), "dtls.example")
        .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
    let mut crng = HmacDrbg::<Sha256>::new(b"ff12-client", b"nonce", &[]);
    let client = DtlsClientConnection12::new(ccfg, b"peer".to_vec(), &mut crng);
    let scfg = PcServerConfig12::with_ecdsa(alloc::vec![cert], key).require_cookie_exchange(false);
    let srng = HmacDrbg::<Sha256>::new(b"ff12-server", b"nonce", &[]);
    let server = DtlsServerConnection12::new(Arc::new(scfg), b"peer".to_vec(), srng);
    (client, server)
}

/// Runs the DTLS 1.3 handshake up to the point where the client has
/// processed the server's flight — it is complete and its Finished is
/// queued — and the server has seen nothing of it.
fn until_client_finished_13(client: &mut DtlsClientConnection13, server: &mut Server13) {
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    for dg in &server.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    assert!(client.is_handshake_complete());
    assert!(!server.is_handshake_complete());
}

fn deliver13_to_server(client: &mut DtlsClientConnection13, server: &mut Server13) -> usize {
    let out = client.pop_outbound_datagrams();
    for dg in &out {
        server.feed_datagram(dg).unwrap();
    }
    out.len()
}

fn deliver13_to_client(server: &mut Server13, client: &mut DtlsClientConnection13) -> usize {
    let out = server.pop_outbound_datagrams();
    for dg in &out {
        client.feed_datagram(dg).unwrap();
    }
    out.len()
}

/// Fires the client's retransmission timer at its deadline.
fn fire13(client: &mut DtlsClientConnection13) {
    let t = client.next_timeout().expect("a flight is in the air");
    client.on_timeout(t);
}

// ------------------------------------------------------------- DTLS 1.3

/// The reproduction of the interop failure, in process: the client's
/// Finished is lost, the application writes and closes right away. The
/// close_notify must not be put on the wire ahead of the Finished's
/// acknowledgement — a server still in its handshake fails on it — and
/// the Finished must keep being retransmitted until the server has it.
#[test]
fn write_and_close_before_the_finished_is_acked_do_not_strand_the_server_13() {
    let (mut client, mut server) = pair13();
    until_client_finished_13(&mut client, &mut server);
    assert!(client.handshake_flight_pending(), "Finished unacknowledged");

    // The application does not wait: one write, then close.
    client.send(b"request").unwrap();
    let before_close = client.pop_outbound_datagrams();
    assert!(before_close.len() >= 2, "ACKs, Finished, application data");
    client.send_close_notify().unwrap();
    assert!(
        client.pop_outbound_datagrams().is_empty(),
        "close_notify must be held while the Finished is unacknowledged"
    );
    // Closed for writing all the same.
    assert_eq!(client.send(b"more"), Err(Error::InappropriateState));
    assert!(client.handshake_flight_pending());
    // Everything sent so far is lost.
    drop(before_close);
    assert!(!server.is_handshake_complete());

    // The timer fires: the Finished, and only it, goes out again.
    fire13(&mut client);
    let retx = client.pop_outbound_datagrams();
    assert_eq!(retx.len(), 1, "the Finished alone, still no close_notify");
    for dg in &retx {
        server.feed_datagram(dg).unwrap();
    }
    assert!(
        server.is_handshake_complete(),
        "server completes on the retransmitted Finished"
    );
    assert!(!server.received_close_notify());

    // The server's ACK releases the flight and, with it, the alert.
    assert!(deliver13_to_client(&mut server, &mut client) > 0);
    assert!(!client.handshake_flight_pending());
    assert!(client.next_timeout().is_none());
    let alert = client.pop_outbound_datagrams();
    assert_eq!(alert.len(), 1, "the held close_notify");
    for dg in &alert {
        server.feed_datagram(dg).unwrap();
    }
    assert!(server.received_close_notify());
    // Idempotent, and nothing further is queued.
    client.send_close_notify().unwrap();
    assert!(client.pop_outbound_datagrams().is_empty());
}

/// The Finished is lost several times in a row: every timer step
/// retransmits it (with backoff), and the handshake completes on the first
/// copy that gets through.
#[test]
fn finished_lost_repeatedly_is_retransmitted_until_acked_13() {
    let (mut client, mut server) = pair13();
    until_client_finished_13(&mut client, &mut server);
    let _lost = client.pop_outbound_datagrams();
    let mut last = Duration::ZERO;
    for _ in 0..3 {
        let t = client.next_timeout().expect("Finished in flight");
        assert!(t > last, "deadlines move forward");
        last = t;
        client.on_timeout(t);
        assert_eq!(client.pop_outbound_datagrams().len(), 1);
        assert!(client.handshake_flight_pending());
    }
    fire13(&mut client);
    assert_eq!(deliver13_to_server(&mut client, &mut server), 1);
    assert!(server.is_handshake_complete());
    deliver13_to_client(&mut server, &mut client);
    assert!(!client.handshake_flight_pending());
}

/// A close_notify held for a Finished that is never acknowledged goes out
/// when the retransmission budget is spent: the close is not lost, and the
/// engine does not retransmit forever.
#[test]
fn held_close_notify_is_released_when_retransmission_gives_up_13() {
    let (mut client, mut server) = pair13();
    until_client_finished_13(&mut client, &mut server);
    let _lost = client.pop_outbound_datagrams();
    client.send_close_notify().unwrap();
    let mut retransmissions = 0;
    while let Some(t) = client.next_timeout() {
        client.on_timeout(t);
        if client.handshake_flight_pending() {
            assert_eq!(client.pop_outbound_datagrams().len(), 1, "Finished only");
            retransmissions += 1;
        }
        assert!(retransmissions < 32);
    }
    assert!(retransmissions > 0);
    assert!(!client.handshake_flight_pending());
    assert_eq!(
        client.pop_outbound_datagrams().len(),
        1,
        "the close_notify, at last"
    );
}

/// The peer's own close_notify ends the wait: the held alert answers it.
#[test]
fn held_close_notify_answers_the_peers_close_notify_13() {
    let (mut client, mut server) = pair13();
    until_client_finished_13(&mut client, &mut server);
    // The Finished arrives, the server's ACK does not.
    deliver13_to_server(&mut client, &mut server);
    assert!(server.is_handshake_complete());
    let _lost_ack = server.pop_outbound_datagrams();
    client.send_close_notify().unwrap();
    assert!(client.pop_outbound_datagrams().is_empty());

    client.send(b"x").unwrap_err();
    server.send_close_notify().unwrap();
    deliver13_to_client(&mut server, &mut client);
    assert!(client.received_close_notify());
    let out = client.pop_outbound_datagrams();
    assert!(!out.is_empty(), "close_notify answered in kind");
    for dg in &out {
        server.feed_datagram(dg).unwrap();
    }
    assert!(server.received_close_notify());
}

/// Without a pending flight `send_close_notify` queues the alert at once,
/// as it always did.
#[test]
fn close_after_the_ack_is_immediate_13() {
    let (mut client, mut server) = pair13();
    until_client_finished_13(&mut client, &mut server);
    deliver13_to_server(&mut client, &mut server);
    deliver13_to_client(&mut server, &mut client);
    assert!(!client.handshake_flight_pending());
    client.send_close_notify().unwrap();
    assert_eq!(deliver13_to_server(&mut client, &mut server), 1);
    assert!(server.received_close_notify());
}

/// The server's ACK for the client's Finished is lost. The server reports
/// the handshake as unconfirmed, re-ACKs every retransmitted Finished, and
/// takes the client's first application data as the confirmation.
#[test]
fn server_reacks_a_retransmitted_finished_until_the_client_moves_on_13() {
    let (mut client, mut server) = pair13();
    until_client_finished_13(&mut client, &mut server);
    deliver13_to_server(&mut client, &mut server);
    assert!(server.is_handshake_complete());
    assert!(
        server.handshake_flight_pending(),
        "the client has not been seen past its handshake"
    );
    let lost_ack = server.pop_outbound_datagrams();
    assert!(!lost_ack.is_empty());

    for _ in 0..2 {
        fire13(&mut client);
        assert_eq!(deliver13_to_server(&mut client, &mut server), 1);
        assert!(server.handshake_flight_pending());
        // Lost again.
        assert!(!server.pop_outbound_datagrams().is_empty(), "re-ACK");
        assert!(client.handshake_flight_pending());
    }
    fire13(&mut client);
    deliver13_to_server(&mut client, &mut server);
    assert!(deliver13_to_client(&mut server, &mut client) > 0);
    assert!(!client.handshake_flight_pending());
    assert!(server.handshake_flight_pending(), "an ACK is no evidence");

    client.send(b"ping").unwrap();
    deliver13_to_server(&mut client, &mut server);
    assert_eq!(server.take_received(), b"ping");
    assert!(!server.handshake_flight_pending());
}

/// A server that closes while its ACK may have been lost sends that ACK
/// once more ahead of the close_notify: the client's Finished is released
/// before the alert is processed, so a client that waits for the ACK to
/// complete its handshake does complete it.
#[test]
fn server_close_while_unconfirmed_is_preceded_by_the_ack_13() {
    let (mut client, mut server) = pair13();
    until_client_finished_13(&mut client, &mut server);
    deliver13_to_server(&mut client, &mut server);
    let _lost_ack = server.pop_outbound_datagrams();
    assert!(client.handshake_flight_pending());

    server.send_close_notify().unwrap();
    let out = server.pop_outbound_datagrams();
    assert_eq!(out.len(), 2, "ACK, then close_notify");
    client.feed_datagram(&out[0]).unwrap();
    assert!(
        !client.handshake_flight_pending(),
        "the first datagram acknowledges the Finished"
    );
    assert!(!client.received_close_notify());
    client.feed_datagram(&out[1]).unwrap();
    assert!(client.received_close_notify());
}

/// Once the client is confirmed the close is the alert alone.
#[test]
fn server_close_after_confirmation_is_the_alert_alone_13() {
    let (mut client, mut server) = pair13();
    until_client_finished_13(&mut client, &mut server);
    deliver13_to_server(&mut client, &mut server);
    deliver13_to_client(&mut server, &mut client);
    client.send(b"ping").unwrap();
    deliver13_to_server(&mut client, &mut server);
    assert!(!server.handshake_flight_pending());
    server.send_close_notify().unwrap();
    assert_eq!(server.pop_outbound_datagrams().len(), 1);
}

/// `set_now` is what a flight's retransmission timer is armed from: the
/// Finished queued while a datagram is fed at t = 5 s is due at 6 s, not
/// one second after the last timer fire.
#[test]
fn retransmission_timer_is_armed_from_set_now_13() {
    let (mut client, mut server) = pair13();
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    let flight = server.pop_outbound_datagrams();
    client.set_now(Duration::from_secs(5));
    for dg in &flight {
        client.feed_datagram(dg).unwrap();
    }
    assert!(client.is_handshake_complete());
    assert_eq!(client.next_timeout(), Some(Duration::from_secs(6)));
    // The clock never runs backwards.
    client.set_now(Duration::from_secs(1));
    assert_eq!(client.next_timeout(), Some(Duration::from_secs(6)));
    let _sent = client.pop_outbound_datagrams();
    client.on_timeout(Duration::from_millis(5500));
    assert!(
        client.pop_outbound_datagrams().is_empty(),
        "nothing is retransmitted before the deadline"
    );
    client.on_timeout(Duration::from_secs(6));
    assert_eq!(client.pop_outbound_datagrams().len(), 1, "the Finished");
}

// ------------------------------------------------------------- DTLS 1.2

/// Runs the DTLS 1.2 handshake until the server has completed and queued
/// its final flight; the client has not seen it.
fn until_server_finished_12(client: &mut DtlsClientConnection12, server: &mut Server12) {
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    for dg in &server.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    assert!(server.is_handshake_complete());
    assert!(!client.is_handshake_complete());
}

/// The DTLS 1.2 client completes on the server's Finished, which answers
/// its own last flight: nothing is pending from then on.
#[test]
fn client_has_nothing_pending_once_complete_12() {
    let (mut client, mut server) = pair12();
    assert!(client.handshake_flight_pending(), "ClientHello in the air");
    until_server_finished_12(&mut client, &mut server);
    assert!(client.handshake_flight_pending(), "final flight in the air");
    for dg in &server.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    assert!(client.is_handshake_complete());
    assert!(!client.handshake_flight_pending());
    assert!(client.next_timeout().is_none());
}

/// The DTLS 1.2 server's final flight is lost: the server reports the
/// handshake as unconfirmed until the client's first application data.
#[test]
fn server_is_unconfirmed_until_the_client_speaks_12() {
    let (mut client, mut server) = pair12();
    until_server_finished_12(&mut client, &mut server);
    assert!(server.handshake_flight_pending());
    let _lost = server.pop_outbound_datagrams();

    let t = client.next_timeout().expect("client flight armed");
    client.on_timeout(t);
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    assert!(server.handshake_flight_pending());
    for dg in &server.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    assert!(client.is_handshake_complete());

    client.send(b"ping").unwrap();
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    assert_eq!(server.take_received(), b"ping");
    assert!(!server.handshake_flight_pending());
}

/// A DTLS 1.2 server that closes while its final flight may have been lost
/// sends the flight once more ahead of the close_notify, so a client still
/// waiting for it completes its handshake and then sees the closure.
#[test]
fn server_close_while_unconfirmed_is_preceded_by_the_final_flight_12() {
    let (mut client, mut server) = pair12();
    until_server_finished_12(&mut client, &mut server);
    let lost = server.pop_outbound_datagrams();
    assert_eq!(lost.len(), 2, "CCS + Finished");

    server.send_close_notify().unwrap();
    let out = server.pop_outbound_datagrams();
    assert_eq!(out.len(), 3, "CCS + Finished + close_notify");
    client.feed_datagram(&out[0]).unwrap();
    client.feed_datagram(&out[1]).unwrap();
    assert!(client.is_handshake_complete());
    assert!(!client.received_close_notify());
    client.feed_datagram(&out[2]).unwrap();
    assert!(client.received_close_notify());
    assert!(!server.handshake_flight_pending());
}

/// The DTLS 1.2 client's flights are armed from `set_now` too.
#[test]
fn retransmission_timer_is_armed_from_set_now_12() {
    let (mut client, mut server) = pair12();
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    let flight = server.pop_outbound_datagrams();
    client.set_now(Duration::from_secs(7));
    for dg in &flight {
        client.feed_datagram(dg).unwrap();
    }
    assert_eq!(client.next_timeout(), Some(Duration::from_secs(8)));
    // And the server's, from its own `set_now`.
    let (mut client, mut server) = pair12();
    server.set_now(Duration::from_secs(3));
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    assert_eq!(server.next_timeout(), Some(Duration::from_secs(4)));
}

/// A connection the peer has closed, or whose handshake has failed for
/// good, waits for nothing.
#[test]
fn nothing_is_pending_on_a_closed_connection() {
    // DTLS 1.3 client: the server is never heard from, the retransmission
    // budget runs out and the handshake is over.
    let (mut client, _server) = pair13();
    assert!(client.handshake_flight_pending());
    while let Some(t) = client.next_timeout() {
        client.on_timeout(t);
    }
    assert!(!client.is_handshake_complete());
    assert!(!client.handshake_flight_pending());

    // DTLS 1.3 server: closed by the client before it said anything else.
    let (mut client, mut server) = pair13();
    until_client_finished_13(&mut client, &mut server);
    deliver13_to_server(&mut client, &mut server);
    deliver13_to_client(&mut server, &mut client);
    assert!(server.handshake_flight_pending());
    client.send_close_notify().unwrap();
    deliver13_to_server(&mut client, &mut server);
    assert!(server.received_close_notify());
    assert!(!server.handshake_flight_pending());

    // DTLS 1.2 client, same as the first.
    let (mut client, _server) = pair12();
    while let Some(t) = client.next_timeout() {
        client.on_timeout(t);
    }
    assert!(!client.handshake_flight_pending());
}
