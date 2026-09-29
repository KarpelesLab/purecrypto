//! Client certificates (mutual authentication) over DTLS 1.3 (RFC 9147
//! over the RFC 8446 handshake) and DTLS 1.2 (RFC 6347 over RFC 5246).
//!
//! The happy paths, with the cookie exchange on, and the checks the servers
//! must make: a `CertificateVerify` is required once a chain was presented,
//! its scheme must be one the `CertificateRequest` offered, an empty
//! `Certificate` is refused when the policy requires one and admitted
//! otherwise, an untrusted or expired chain is refused. The DTLS 1.3
//! client's final flight is multi-message and, at a small MTU, fragmented:
//! its ACK-driven retransmission and the close-behind-unacknowledged-flight
//! rule are checked with a fragment lost.
//!
//! Every server-side check is exercised through the wire where the
//! protocol allows it; a client message a conforming client never sends (a
//! Finished in place of the CertificateVerify) is handed to the state
//! machine directly through `dispatch_handshake_for_test`.

use crate::dtls::{
    ClientConfig12Internal as PcClientConfig12, ClientConfig13Internal as PcClientConfig13,
    DtlsClientConnection12, DtlsClientConnection13, DtlsServerConnection12, DtlsServerConnection13,
    ServerConfig12Internal as PcServerConfig12, ServerConfig13Internal as PcServerConfig13,
};
use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
use crate::hash::Sha256;
use crate::rng::HmacDrbg;
use crate::tls::Error;
use crate::tls::codec::{SignatureScheme, hs_type};
use crate::tls::conn::ClientCertConfig;
use crate::tls::pki::RootCertStore;
use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
use alloc::sync::Arc;
use alloc::vec::Vec;

type Server13 = DtlsServerConnection13<HmacDrbg<Sha256>>;
type Server12 = DtlsServerConnection12<HmacDrbg<Sha256>>;

/// The clock every verification runs at.
fn now() -> Time {
    Time::utc(2026, 6, 1, 0, 0, 0)
}

/// An ECDSA P-256 self-signed certificate (a CA, so it can be its own
/// trust anchor) + key, valid over `validity`.
fn identity(seed: &[u8], cn: &str, validity: Validity) -> (BoxedEcdsaPrivateKey, Vec<u8>) {
    let mut rng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
    let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
    let name = DistinguishedName::common_name(cn);
    let cert = Certificate::self_signed_general(
        &CertSigner::Ecdsa(&key),
        &name,
        &validity,
        1,
        true,
        &[cn],
    )
    .unwrap();
    (key, cert.to_der().to_vec())
}

fn valid() -> Validity {
    Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    )
}

fn expired() -> Validity {
    Validity::new(
        Time::utc(2020, 1, 1, 0, 0, 0),
        Time::utc(2021, 1, 1, 0, 0, 0),
    )
}

fn server_identity() -> (BoxedEcdsaPrivateKey, Vec<u8>) {
    identity(b"mtls-server-key", "dtls.example", valid())
}

fn client_identity() -> (BoxedEcdsaPrivateKey, Vec<u8>) {
    identity(b"mtls-client-key", "client.example", valid())
}

fn roots(cert: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::new();
    roots.add_der(cert.to_vec()).unwrap();
    roots
}

/// What a case configures on each side.
struct Setup {
    /// The client presents this identity (chain + key); `None` for an
    /// anonymous client.
    client_cert: Option<(Vec<u8>, BoxedEcdsaPrivateKey)>,
    /// The server's policy: `Some((anchor, required))` requests a
    /// certificate and verifies it against `anchor`; `None` requests none.
    client_auth: Option<(Vec<u8>, bool)>,
    /// The cookie exchange (HelloVerifyRequest / HelloRetryRequest) on.
    cookie: bool,
    /// The client's record ceiling (DTLS 1.3 only).
    client_mtu: usize,
}

impl Setup {
    fn mutual(required: bool) -> Self {
        let (ckey, ccert) = client_identity();
        Self {
            client_cert: Some((ccert.clone(), ckey)),
            client_auth: Some((ccert, required)),
            cookie: true,
            client_mtu: 1200,
        }
    }

    fn anonymous(required: bool) -> Self {
        let (_, ccert) = client_identity();
        Self {
            client_cert: None,
            client_auth: Some((ccert, required)),
            cookie: true,
            client_mtu: 1200,
        }
    }

    fn pair13(&self) -> (DtlsClientConnection13, Server13) {
        let (skey, scert) = server_identity();
        let mut ccfg =
            PcClientConfig13::new(roots(&scert), "dtls.example").with_verification_time(now());
        if let Some((chain, key)) = &self.client_cert {
            ccfg = ccfg.with_client_cert(ClientCertConfig::with_ecdsa(
                alloc::vec![chain.clone()],
                key.clone(),
            ));
        }
        ccfg.max_record_size = self.client_mtu;
        let mut crng = HmacDrbg::<Sha256>::new(b"mtls13-client", b"nonce", &[]);
        let client = DtlsClientConnection13::new(ccfg, b"peer".to_vec(), &mut crng);
        let mut scfg = PcServerConfig13::with_ecdsa(alloc::vec![scert], skey);
        if let Some((anchor, required)) = &self.client_auth {
            scfg = scfg.with_client_auth(roots(anchor), *required);
        }
        scfg.verification_time = Some(now());
        scfg = if self.cookie {
            scfg.with_cookie_secret([7u8; 32])
        } else {
            scfg.with_no_cookie()
        };
        let srng = HmacDrbg::<Sha256>::new(b"mtls13-server", b"nonce", &[]);
        let server = DtlsServerConnection13::new(Arc::new(scfg), b"peer".to_vec(), srng);
        (client, server)
    }

    fn pair12(&self) -> (DtlsClientConnection12, Server12) {
        let (skey, scert) = server_identity();
        let mut ccfg =
            PcClientConfig12::new(roots(&scert), "dtls.example").with_verification_time(now());
        if let Some((chain, key)) = &self.client_cert {
            ccfg = ccfg.with_client_cert(ClientCertConfig::with_ecdsa(
                alloc::vec![chain.clone()],
                key.clone(),
            ));
        }
        let mut crng = HmacDrbg::<Sha256>::new(b"mtls12-client", b"nonce", &[]);
        let client = DtlsClientConnection12::new(ccfg, b"peer".to_vec(), &mut crng);
        let mut scfg = PcServerConfig12::with_ecdsa(alloc::vec![scert], skey);
        if let Some((anchor, required)) = &self.client_auth {
            scfg = scfg.with_client_auth(roots(anchor), *required);
        }
        scfg.verification_time = Some(now());
        scfg = if self.cookie {
            scfg.with_cookie_secret([7u8; 32])
        } else {
            scfg.require_cookie_exchange(false)
        };
        let srng = HmacDrbg::<Sha256>::new(b"mtls12-server", b"nonce", &[]);
        let server = DtlsServerConnection12::new(Arc::new(scfg), b"peer".to_vec(), srng);
        (client, server)
    }
}

/// Pumps datagrams both ways until both sides are done or a side fails;
/// the first error is returned.
fn pump13(client: &mut DtlsClientConnection13, server: &mut Server13) -> Result<(), Error> {
    for _ in 0..32 {
        let c_out = client.pop_outbound_datagrams();
        for dg in &c_out {
            server.feed_datagram(dg)?;
        }
        let s_out = server.pop_outbound_datagrams();
        for dg in &s_out {
            client.feed_datagram(dg)?;
        }
        if c_out.is_empty() && s_out.is_empty() {
            break;
        }
    }
    Ok(())
}

fn pump12(client: &mut DtlsClientConnection12, server: &mut Server12) -> Result<(), Error> {
    for _ in 0..32 {
        let c_out = client.pop_outbound_datagrams();
        for dg in &c_out {
            server.feed_datagram(dg)?;
        }
        let s_out = server.pop_outbound_datagrams();
        for dg in &s_out {
            client.feed_datagram(dg)?;
        }
        if c_out.is_empty() && s_out.is_empty() {
            break;
        }
    }
    Ok(())
}

/// Runs the DTLS 1.3 handshake until the client has processed the server's
/// flight and queued its final flight, which is returned without being
/// delivered: `[Certificate fragments…, CertificateVerify, Finished, ACK]`
/// for a client with an identity.
fn client_final_flight_13(
    client: &mut DtlsClientConnection13,
    server: &mut Server13,
) -> Vec<Vec<u8>> {
    // The cookie exchange: CH1, HRR, CH2, then the server flight.
    for _ in 0..2 {
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
    }
    assert!(client.is_handshake_complete());
    assert!(!server.is_handshake_complete());
    client.pop_outbound_datagrams()
}

/// Runs the DTLS 1.2 handshake until the client has queued its final
/// flight, returned undelivered: `[Certificate, ClientKeyExchange,
/// CertificateVerify, ChangeCipherSpec, Finished]` with an identity.
fn client_final_flight_12(
    client: &mut DtlsClientConnection12,
    server: &mut Server12,
) -> Vec<Vec<u8>> {
    // CH1, HelloVerifyRequest, CH2, then the server flight.
    for _ in 0..2 {
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
    }
    assert!(!client.is_handshake_complete());
    assert!(!server.is_handshake_complete());
    client.pop_outbound_datagrams()
}

/// A `CertificateVerify` body: `scheme ‖ opaque signature<0..2^16-1>`.
fn cert_verify_body(scheme: u16, signature: &[u8]) -> Vec<u8> {
    let mut body = scheme.to_be_bytes().to_vec();
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(signature);
    body
}

// ------------------------------------------------------------- DTLS 1.3

/// The client presents its certificate, the server verifies it, both
/// report the peer's chain and application data flows — through the
/// stateless cookie exchange, as on the wire.
#[test]
fn mutual_authentication_13() {
    for required in [true, false] {
        let setup = Setup::mutual(required);
        let (mut client, mut server) = setup.pair13();
        pump13(&mut client, &mut server).unwrap();
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        let (_, ccert) = client_identity();
        let (_, scert) = server_identity();
        assert_eq!(server.peer_certificates(), &[ccert]);
        assert_eq!(client.peer_certificates(), &[scert]);
        client.send(b"ping").unwrap();
        pump13(&mut client, &mut server).unwrap();
        assert_eq!(server.take_received(), b"ping");
        server.send(b"pong").unwrap();
        pump13(&mut client, &mut server).unwrap();
        assert_eq!(client.take_received(), b"pong");
    }
}

/// RFC 8446 §4.4.2.4: an empty `Certificate` is `certificate_required`
/// when the policy requires one. The record was authenticated, so the
/// fault is fatal on the server.
#[test]
fn empty_certificate_is_refused_when_required_13() {
    let (mut client, mut server) = Setup::anonymous(true).pair13();
    assert_eq!(
        pump13(&mut client, &mut server),
        Err(Error::CertificateRequired)
    );
    assert!(!server.is_handshake_complete());
    assert!(server.peer_certificates().is_empty());
}

/// RFC 8446 §4.4.2: with the certificate optional, an empty `Certificate`
/// is followed directly by the Finished and the client is admitted
/// anonymously.
#[test]
fn empty_certificate_is_admitted_when_optional_13() {
    let (mut client, mut server) = Setup::anonymous(false).pair13();
    pump13(&mut client, &mut server).unwrap();
    assert!(client.is_handshake_complete() && server.is_handshake_complete());
    assert!(server.peer_certificates().is_empty());
}

/// RFC 8446 §4.4.3: a client that presented a chain MUST send a
/// `CertificateVerify`; a Finished in its place is out of order, whatever
/// the policy — never a mere `decrypt_error` on the Finished itself.
#[test]
fn certificate_verify_is_required_after_a_chain_13() {
    for required in [true, false] {
        let (mut client, mut server) = Setup::mutual(required).pair13();
        let flight = client_final_flight_13(&mut client, &mut server);
        // The Certificate alone.
        server.feed_datagram(&flight[0]).unwrap();
        assert_eq!(
            server.dispatch_handshake_for_test(hs_type::FINISHED, &[0u8; 32]),
            Err(Error::UnexpectedMessage)
        );
        assert!(!server.is_handshake_complete());
    }
}

/// RFC 8446 §4.4.3: the `CertificateVerify` scheme "MUST be one offered in
/// the server's CertificateRequest", and `rsa_pkcs1_*` never is; a bad
/// signature under an offered scheme is refused as well.
#[test]
fn certificate_verify_scheme_and_signature_are_checked_13() {
    let (mut client, mut server) = Setup::mutual(true).pair13();
    let flight = client_final_flight_13(&mut client, &mut server);
    server.feed_datagram(&flight[0]).unwrap();
    // rsa_pkcs1_sha256: chain signatures only in TLS 1.3.
    assert_eq!(
        server.dispatch_handshake_for_test(
            hs_type::CERTIFICATE_VERIFY,
            &cert_verify_body(SignatureScheme::RSA_PKCS1_SHA256.0, &[0u8; 64])
        ),
        Err(Error::IllegalParameter)
    );
    // A code point nobody offered.
    assert_eq!(
        server.dispatch_handshake_for_test(
            hs_type::CERTIFICATE_VERIFY,
            &cert_verify_body(0xfe00, &[0u8; 64])
        ),
        Err(Error::IllegalParameter)
    );
    // The right scheme, a garbage signature.
    let r = server.dispatch_handshake_for_test(
        hs_type::CERTIFICATE_VERIFY,
        &cert_verify_body(SignatureScheme::ECDSA_SECP256R1_SHA256.0, &[0x30u8; 70]),
    );
    assert!(
        matches!(r, Err(Error::BadCertificate) | Err(Error::Decode)),
        "{r:?}"
    );
    assert!(!server.is_handshake_complete());
    // The genuine CertificateVerify still verifies — nothing above was
    // committed to the transcript.
    server.feed_datagram(&flight[1]).unwrap();
    server.feed_datagram(&flight[2]).unwrap();
    assert!(server.is_handshake_complete());
}

/// A chain the policy's roots do not anchor, or one outside its validity
/// period at the server's clock, is `bad_certificate` (RFC 8446 §4.4.2.4).
#[test]
fn untrusted_or_expired_client_chain_is_refused_13() {
    // Untrusted: the policy anchors another certificate.
    let (_, other) = identity(b"mtls-other-key", "other.example", valid());
    let mut setup = Setup::mutual(true);
    setup.client_auth = Some((other, true));
    let (mut client, mut server) = setup.pair13();
    assert_eq!(pump13(&mut client, &mut server), Err(Error::BadCertificate));

    // Expired: the client's own certificate, but its validity is over.
    let (ckey, ccert) = identity(b"mtls-expired-key", "client.example", expired());
    let setup = Setup {
        client_cert: Some((ccert.clone(), ckey)),
        client_auth: Some((ccert, true)),
        cookie: true,
        client_mtu: 1200,
    };
    let (mut client, mut server) = setup.pair13();
    assert_eq!(pump13(&mut client, &mut server), Err(Error::BadCertificate));
    assert!(server.peer_certificates().is_empty());
}

/// At a small MTU the client's Certificate spans several records, so its
/// final flight is many records long. With one fragment lost, the server
/// acknowledges what it received (RFC 9147 §7), the client retransmits
/// only the missing record (§7.2) and the handshake completes with the
/// chain verified.
#[test]
fn lost_certificate_fragment_is_the_only_retransmission_13() {
    let mut setup = Setup::mutual(true);
    setup.client_mtu = 256;
    let (mut client, mut server) = setup.pair13();
    let flight = client_final_flight_13(&mut client, &mut server);
    // Certificate fragments, CertificateVerify, Finished and the ACK of the
    // server flight: the certificate alone is several records.
    assert!(flight.len() >= 5, "{} datagrams", flight.len());
    for (i, dg) in flight.iter().enumerate() {
        if i == 1 {
            continue; // the second Certificate fragment is lost
        }
        server.feed_datagram(dg).unwrap();
    }
    assert!(!server.is_handshake_complete());
    // The server ACKs every record it got; the client is left with the
    // one it lost.
    for dg in &server.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    assert!(client.handshake_flight_pending());
    let t = client
        .next_timeout()
        .expect("the lost fragment is in flight");
    client.on_timeout(t);
    let resent = client.pop_outbound_datagrams();
    assert_eq!(resent.len(), 1, "only the lost record is retransmitted");
    server.feed_datagram(&resent[0]).unwrap();
    assert!(server.is_handshake_complete());
    let (_, ccert) = client_identity();
    assert_eq!(server.peer_certificates(), &[ccert]);
    for dg in &server.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    assert!(!client.handshake_flight_pending());
}

/// The whole final flight lost, the application writing and closing right
/// away: the close_notify is held behind the (retransmitted) flight until
/// the server acknowledges it, and the server — still in its handshake
/// meanwhile — completes it with the chain verified before it sees the
/// close (the mTLS version of the final-flight rule).
#[test]
fn close_behind_the_unacknowledged_final_flight_13() {
    let mut setup = Setup::mutual(true);
    setup.client_mtu = 256;
    let (mut client, mut server) = setup.pair13();
    let lost = client_final_flight_13(&mut client, &mut server);
    assert!(lost.len() >= 5);
    client.send(b"bye").unwrap();
    client.send_close_notify().unwrap();
    // Application data goes out, the alert does not.
    let now = client.pop_outbound_datagrams();
    assert_eq!(now.len(), 1);
    for dg in &now {
        // A server still in its handshake buffers or drops early data.
        let _ = server.feed_datagram(dg);
    }
    assert!(client.handshake_flight_pending());
    // The retransmitted flight (every record) arrives.
    let t = client.next_timeout().unwrap();
    client.on_timeout(t);
    let resent = client.pop_outbound_datagrams();
    assert_eq!(
        resent.len(),
        lost.len() - 1,
        "the flight minus its ACK record"
    );
    for dg in &resent {
        server.feed_datagram(dg).unwrap();
    }
    assert!(server.is_handshake_complete());
    let (_, ccert) = client_identity();
    assert_eq!(server.peer_certificates(), &[ccert]);
    // Its ACK releases the flight and, with it, the held close_notify.
    for dg in &server.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    assert!(!client.handshake_flight_pending());
    let alert = client.pop_outbound_datagrams();
    assert_eq!(alert.len(), 1);
    server.feed_datagram(&alert[0]).unwrap();
    assert!(server.received_close_notify());
}

// ------------------------------------------------------------- DTLS 1.2

/// The client presents its certificate, the server verifies it (the
/// CertificateVerify is over the DTLS-shaped transcript, RFC 6347 §4.2.6),
/// both report the peer's chain and application data flows — through the
/// HelloVerifyRequest exchange.
#[test]
fn mutual_authentication_12() {
    for required in [true, false] {
        let (mut client, mut server) = Setup::mutual(required).pair12();
        pump12(&mut client, &mut server).unwrap();
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        let (_, ccert) = client_identity();
        let (_, scert) = server_identity();
        assert_eq!(server.peer_certificates(), &[ccert]);
        assert_eq!(client.peer_certificates(), &[scert]);
        client.send(b"ping").unwrap();
        pump12(&mut client, &mut server).unwrap();
        assert_eq!(server.take_received(), b"ping");
        server.send(b"pong").unwrap();
        pump12(&mut client, &mut server).unwrap();
        assert_eq!(client.take_received(), b"pong");
    }
}

/// An empty `Certificate` under a required policy: the message arrives in
/// plaintext (spoofable), so the refusal is a silent drop rather than a
/// fatal error — a forged empty Certificate must not be a one-datagram
/// kill — and the handshake never completes. The genuine fault is
/// `certificate_required` at the state machine.
#[test]
fn empty_certificate_is_refused_when_required_12() {
    let (mut client, mut server) = Setup::anonymous(true).pair12();
    pump12(&mut client, &mut server).unwrap();
    assert!(!server.is_handshake_complete());
    assert!(!client.is_handshake_complete());

    let (mut client, mut server) = Setup::anonymous(true).pair12();
    let _flight = client_final_flight_12(&mut client, &mut server);
    // The empty Certificate body: an empty `certificate_list<0..2^24-1>`.
    assert_eq!(
        server.dispatch_handshake_for_test(hs_type::CERTIFICATE, &[0, 0, 0]),
        Err(Error::CertificateRequired)
    );
}

/// With the certificate optional, an empty `Certificate` is admitted and
/// the client stays anonymous (RFC 5246 §7.4.6).
#[test]
fn empty_certificate_is_admitted_when_optional_12() {
    let (mut client, mut server) = Setup::anonymous(false).pair12();
    pump12(&mut client, &mut server).unwrap();
    assert!(client.is_handshake_complete() && server.is_handshake_complete());
    assert!(server.peer_certificates().is_empty());
}

/// RFC 5246 §7.4.8: a chain must be followed by a `CertificateVerify`
/// after the ClientKeyExchange; a Finished without one is out of order,
/// under either policy.
#[test]
fn certificate_verify_is_required_after_a_chain_12() {
    for required in [true, false] {
        let (mut client, mut server) = Setup::mutual(required).pair12();
        let flight = client_final_flight_12(&mut client, &mut server);
        assert_eq!(flight.len(), 5);
        // Certificate, ClientKeyExchange, ChangeCipherSpec — no
        // CertificateVerify.
        server.feed_datagram(&flight[0]).unwrap();
        server.feed_datagram(&flight[1]).unwrap();
        server.feed_datagram(&flight[3]).unwrap();
        assert_eq!(
            server.dispatch_handshake_for_test(hs_type::FINISHED, &[0u8; 12]),
            Err(Error::UnexpectedMessage)
        );
        assert!(!server.is_handshake_complete());
        assert!(server.peer_certificates().is_empty());
    }
}

/// RFC 5246 §7.4.8: the scheme "MUST be one of those present in the
/// supported_signature_algorithms field of the CertificateRequest"; a bad
/// signature under a listed scheme is `decrypt_error`. Neither is committed:
/// the genuine CertificateVerify still completes the handshake.
#[test]
fn certificate_verify_scheme_and_signature_are_checked_12() {
    let (mut client, mut server) = Setup::mutual(true).pair12();
    let flight = client_final_flight_12(&mut client, &mut server);
    server.feed_datagram(&flight[0]).unwrap();
    server.feed_datagram(&flight[1]).unwrap();
    // The RFC 8734 Brainpool code points are TLS 1.3 only: never listed.
    assert_eq!(
        server.dispatch_handshake_for_test(
            hs_type::CERTIFICATE_VERIFY,
            &cert_verify_body(
                SignatureScheme::ECDSA_BRAINPOOLP256R1TLS13_SHA256.0,
                &[0u8; 64]
            )
        ),
        Err(Error::IllegalParameter)
    );
    assert_eq!(
        server.dispatch_handshake_for_test(
            hs_type::CERTIFICATE_VERIFY,
            &cert_verify_body(0xfe00, &[0u8; 64])
        ),
        Err(Error::IllegalParameter)
    );
    let r = server.dispatch_handshake_for_test(
        hs_type::CERTIFICATE_VERIFY,
        &cert_verify_body(SignatureScheme::ECDSA_SECP256R1_SHA256.0, &[0x30u8; 70]),
    );
    assert!(
        matches!(r, Err(Error::DecryptError) | Err(Error::Decode)),
        "{r:?}"
    );
    for dg in &flight[2..] {
        server.feed_datagram(dg).unwrap();
    }
    assert!(server.is_handshake_complete());
    let (_, ccert) = client_identity();
    assert_eq!(server.peer_certificates(), &[ccert]);
}

/// RFC 5246 §7.3: with a CertificateRequest out, the client's Certificate
/// is the first message of its flight — a ClientKeyExchange ahead of it,
/// a second Certificate, or one after the key exchange is out of order.
#[test]
fn client_flight_order_is_enforced_12() {
    let (mut client, mut server) = Setup::mutual(true).pair12();
    let flight = client_final_flight_12(&mut client, &mut server);
    let (_, ccert) = client_identity();
    let mut cert_body = Vec::new();
    let entry_len = ccert.len() as u32;
    let list_len = entry_len + 3;
    cert_body.extend_from_slice(&list_len.to_be_bytes()[1..]);
    cert_body.extend_from_slice(&entry_len.to_be_bytes()[1..]);
    cert_body.extend_from_slice(&ccert);
    // ClientKeyExchange before the Certificate.
    assert_eq!(
        server.dispatch_handshake_for_test(hs_type::CLIENT_KEY_EXCHANGE, &[0u8; 33]),
        Err(Error::UnexpectedMessage)
    );
    server.feed_datagram(&flight[0]).unwrap();
    // A second Certificate.
    assert_eq!(
        server.dispatch_handshake_for_test(hs_type::CERTIFICATE, &cert_body),
        Err(Error::UnexpectedMessage)
    );
    server.feed_datagram(&flight[1]).unwrap();
    // A Certificate after the key exchange.
    assert_eq!(
        server.dispatch_handshake_for_test(hs_type::CERTIFICATE, &cert_body),
        Err(Error::UnexpectedMessage)
    );
    for dg in &flight[2..] {
        server.feed_datagram(dg).unwrap();
    }
    assert!(server.is_handshake_complete());
}

/// A server that requested no certificate refuses an unsolicited one, and
/// a client that was not asked sends none.
#[test]
fn unsolicited_certificate_is_refused_12() {
    let mut setup = Setup::mutual(true);
    setup.client_auth = None;
    let (mut client, mut server) = setup.pair12();
    let flight = client_final_flight_12(&mut client, &mut server);
    // ClientKeyExchange, ChangeCipherSpec, Finished: no Certificate.
    assert_eq!(flight.len(), 3);
    assert_eq!(
        server.dispatch_handshake_for_test(hs_type::CERTIFICATE, &[0, 0, 0]),
        Err(Error::UnexpectedMessage)
    );
    for dg in &flight {
        server.feed_datagram(dg).unwrap();
    }
    assert!(server.is_handshake_complete());
    assert!(server.peer_certificates().is_empty());
}

/// An untrusted or expired client chain is refused: silently on the wire
/// (plaintext), `bad_certificate` at the state machine.
#[test]
fn untrusted_or_expired_client_chain_is_refused_12() {
    let (ckey, ccert) = identity(b"mtls-expired-key", "client.example", expired());
    let setup = Setup {
        client_cert: Some((ccert.clone(), ckey)),
        client_auth: Some((ccert, true)),
        cookie: false,
        client_mtu: 1200,
    };
    let (mut client, mut server) = setup.pair12();
    pump12(&mut client, &mut server).unwrap();
    assert!(!server.is_handshake_complete());
    assert!(server.peer_certificates().is_empty());
}

/// Session resumption at an mTLS listener: the ticket carries the client
/// identity the issuing handshake verified, the resumed handshake (which
/// authenticates no client of its own) restores it into
/// `peer_certificates()`, and the ticket-sealing key is bound to the
/// listener's client-auth policy, so a ticket minted where no certificate
/// was demanded never stands in for one at a listener that demands it.
mod resumption {
    use super::*;
    use crate::tls::conn::{StoredSession, StoredSession12};

    const TICKET_KEY: [u8; 32] = [0x3c; 32];

    /// The server policy of a case: `None` requests no certificate.
    type Policy = Option<(Vec<u8>, bool)>;

    fn server13(policy: &Policy, seed: &[u8]) -> Server13 {
        let (skey, scert) = server_identity();
        let mut scfg = PcServerConfig13::with_ecdsa(alloc::vec![scert], skey)
            .with_ticket_key(TICKET_KEY)
            .with_no_cookie();
        if let Some((anchor, required)) = policy {
            scfg = scfg.with_client_auth(roots(anchor), *required);
        }
        scfg.verification_time = Some(now());
        let srng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
        DtlsServerConnection13::new(Arc::new(scfg), b"peer".to_vec(), srng)
    }

    fn client13(with_identity: bool, session: Option<StoredSession>) -> DtlsClientConnection13 {
        let (_, scert) = server_identity();
        let mut ccfg =
            PcClientConfig13::new(roots(&scert), "dtls.example").with_verification_time(now());
        if with_identity {
            let (ckey, ccert) = client_identity();
            ccfg = ccfg.with_client_cert(ClientCertConfig::with_ecdsa(alloc::vec![ccert], ckey));
        }
        ccfg.session = session;
        let mut crng = HmacDrbg::<Sha256>::new(b"mtls13-resume-c", b"nonce", &[]);
        DtlsClientConnection13::new(ccfg, b"peer".to_vec(), &mut crng)
    }

    /// A full DTLS 1.3 handshake at `policy`, returning the session the
    /// server's post-handshake NewSessionTicket built.
    fn session13(policy: &Policy, with_identity: bool) -> StoredSession {
        let mut c = client13(with_identity, None);
        let mut s = server13(policy, b"mtls13-resume-s1");
        pump13(&mut c, &mut s).unwrap();
        assert!(c.is_handshake_complete() && s.is_handshake_complete());
        c.take_session().expect("a ticket")
    }

    #[test]
    fn resumed_dtls13_connection_carries_the_client_identity() {
        let (_, ccert) = client_identity();
        let policy: Policy = Some((ccert.clone(), true));
        let session = session13(&policy, true);
        let mut c = client13(true, Some(session));
        let mut s = server13(&policy, b"mtls13-resume-s2");
        pump13(&mut c, &mut s).unwrap();
        assert!(c.is_handshake_complete() && s.is_handshake_complete());
        assert!(c.psk_accepted() && s.psk_used(), "resumed");
        assert_eq!(s.peer_certificates(), &[ccert.clone()][..]);
        // The resumed connection's own ticket carries the identity on: a
        // second resumption restores it again.
        let again = c
            .take_session()
            .expect("a ticket on the resumed connection");
        let mut c = client13(true, Some(again));
        let mut s = server13(&policy, b"mtls13-resume-s3");
        pump13(&mut c, &mut s).unwrap();
        assert!(s.psk_used());
        assert_eq!(s.peer_certificates(), &[ccert][..]);
    }

    #[test]
    fn dtls13_ticket_from_a_listener_without_client_auth_does_not_resume_at_one_with_it() {
        let (_, ccert) = client_identity();
        let session = session13(&None, true);
        let policy: Policy = Some((ccert.clone(), true));
        let mut c = client13(true, Some(session));
        let mut s = server13(&policy, b"mtls13-resume-s4");
        pump13(&mut c, &mut s).unwrap();
        assert!(s.is_handshake_complete());
        assert!(!s.psk_used(), "the ticket must not open here");
        // The full handshake authenticated the client itself.
        assert_eq!(s.peer_certificates(), &[ccert][..]);
    }

    fn server12(policy: &Policy, seed: &[u8]) -> Server12 {
        let (skey, scert) = server_identity();
        let mut scfg = PcServerConfig12::with_ecdsa(alloc::vec![scert], skey)
            .with_ticket_key(TICKET_KEY)
            .require_cookie_exchange(false);
        if let Some((anchor, required)) = policy {
            scfg = scfg.with_client_auth(roots(anchor), *required);
        }
        scfg.verification_time = Some(now());
        let srng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
        DtlsServerConnection12::new(Arc::new(scfg), b"peer".to_vec(), srng)
    }

    fn client12(with_identity: bool, session: Option<StoredSession12>) -> DtlsClientConnection12 {
        let (_, scert) = server_identity();
        let mut ccfg =
            PcClientConfig12::new(roots(&scert), "dtls.example").with_verification_time(now());
        if with_identity {
            let (ckey, ccert) = client_identity();
            ccfg = ccfg.with_client_cert(ClientCertConfig::with_ecdsa(alloc::vec![ccert], ckey));
        }
        ccfg.session = session;
        let mut crng = HmacDrbg::<Sha256>::new(b"mtls12-resume-c", b"nonce", &[]);
        DtlsClientConnection12::new(ccfg, b"peer".to_vec(), &mut crng)
    }

    fn session12(policy: &Policy, with_identity: bool) -> StoredSession12 {
        let mut c = client12(with_identity, None);
        let mut s = server12(policy, b"mtls12-resume-s1");
        pump12(&mut c, &mut s).unwrap();
        assert!(c.is_handshake_complete() && s.is_handshake_complete());
        c.take_session().expect("a ticket")
    }

    #[test]
    fn resumed_dtls12_connection_carries_the_client_identity() {
        let (_, ccert) = client_identity();
        let policy: Policy = Some((ccert.clone(), true));
        let session = session12(&policy, true);
        let mut c = client12(true, Some(session));
        let mut s = server12(&policy, b"mtls12-resume-s2");
        pump12(&mut c, &mut s).unwrap();
        assert!(c.is_handshake_complete() && s.is_handshake_complete());
        assert!(c.did_resume() && s.did_resume(), "abbreviated handshake");
        assert_eq!(s.peer_certificates(), &[ccert][..]);
    }

    #[test]
    fn dtls12_ticket_from_a_listener_without_client_auth_does_not_resume_at_one_with_it() {
        let (_, ccert) = client_identity();
        let session = session12(&None, true);
        let policy: Policy = Some((ccert.clone(), true));
        let mut c = client12(true, Some(session));
        let mut s = server12(&policy, b"mtls12-resume-s3");
        pump12(&mut c, &mut s).unwrap();
        assert!(s.is_handshake_complete());
        assert!(
            !s.did_resume() && !c.did_resume(),
            "the ticket must not open here"
        );
        assert_eq!(s.peer_certificates(), &[ccert][..]);
    }

    /// An anonymous client's session at an optional-auth listener resumes
    /// as anonymous (no identity is invented), and never at a listener that
    /// requires a certificate.
    #[test]
    fn anonymous_sessions_stay_anonymous() {
        let (_, ccert) = client_identity();
        let optional: Policy = Some((ccert.clone(), false));
        let session = session12(&optional, false);
        let mut c = client12(false, Some(session.clone()));
        let mut s = server12(&optional, b"mtls12-resume-s4");
        pump12(&mut c, &mut s).unwrap();
        assert!(s.did_resume());
        assert!(s.peer_certificates().is_empty());

        let required: Policy = Some((ccert, true));
        let mut c = client12(false, Some(session));
        let mut s = server12(&required, b"mtls12-resume-s5");
        let _ = pump12(&mut c, &mut s);
        assert!(!s.did_resume());
        assert!(!s.is_handshake_complete(), "an anonymous client is refused");

        let session = session13(&optional, false);
        let mut c = client13(false, Some(session));
        let mut s = server13(&optional, b"mtls13-resume-s5");
        pump13(&mut c, &mut s).unwrap();
        assert!(s.psk_used());
        assert!(s.peer_certificates().is_empty());
    }
}
