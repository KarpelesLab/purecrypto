//! Regression tests for the DTLS items deferred from the 2026-09 audit
//! (DTLS-I1 … DTLS-I6): RFC 9147 wire shape of the DTLS 1.3 hellos,
//! post-handshake `KeyUpdate` / `NewSessionTicket`, the epoch-2 grace window
//! for a retransmitted client Finished, MTU-bounded fragmentation, and
//! cookie-secret rotation.

use crate::dtls::{
    ClientConfig12Internal as PcClientConfig12, ClientConfig13Internal as PcClientConfig13,
    DtlsClientConnection12, DtlsClientConnection13, DtlsServerConnection12, DtlsServerConnection13,
    ServerConfig12Internal as PcServerConfig12, ServerConfig13Internal as PcServerConfig13, record,
};
use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
use crate::hash::Sha256;
use crate::rng::HmacDrbg;
use crate::tls::codec::{ClientHello, ExtensionType, NamedGroup, ReadCursor, ServerHello, hs_type};
use crate::tls::pki::RootCertStore;
use crate::tls::{ContentType, ProtocolVersion};
use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// ECDSA P-256 self-signed server certificate + key.
fn server_identity(seed: &[u8]) -> (BoxedEcdsaPrivateKey, Vec<u8>) {
    let mut rng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
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

fn server13_cfg() -> (PcServerConfig13, Vec<u8>) {
    let (key, der) = server_identity(b"deferred-dtls13-key");
    (
        PcServerConfig13::with_ecdsa(alloc::vec![der.clone()], key),
        der,
    )
}

fn server12_cfg() -> (PcServerConfig12, Vec<u8>) {
    let (key, der) = server_identity(b"deferred-dtls12-key");
    (
        PcServerConfig12::with_ecdsa(alloc::vec![der.clone()], key),
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

fn client12(server_cert: &[u8], seed: &[u8]) -> DtlsClientConnection12 {
    let mut roots = RootCertStore::new();
    roots.add_der(server_cert.to_vec()).unwrap();
    let cfg = PcClientConfig12::new(roots, "dtls.example")
        .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
    let mut crng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
    DtlsClientConnection12::new(cfg, b"peer-a".to_vec(), &mut crng)
}

fn server12(cfg: PcServerConfig12, seed: &[u8]) -> DtlsServerConnection12<HmacDrbg<Sha256>> {
    let srng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
    DtlsServerConnection12::new(Arc::new(cfg), b"peer-a".to_vec(), srng)
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

fn pump12<R: crate::rng::RngCore>(
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

/// Splits a plaintext (epoch 0) datagram holding exactly one record with
/// exactly one unfragmented handshake message into `(msg_type, body)`.
fn single_plaintext_handshake(dg: &[u8]) -> (u8, Vec<u8>) {
    let rec = record::read_record(dg).unwrap().unwrap();
    assert_eq!(rec.len, dg.len(), "one record per datagram");
    assert_eq!(rec.content_type, ContentType::Handshake);
    assert_eq!(rec.version, ProtocolVersion::DTLSv1_2);
    let frag = crate::dtls::reassembly::read_fragment(rec.fragment).unwrap();
    assert_eq!(frag.len, rec.fragment.len(), "one fragment per record");
    assert_eq!(frag.fragment_offset, 0);
    assert_eq!(frag.fragment.len() as u32, frag.total_length);
    (frag.msg_type, frag.fragment.to_vec())
}

/// Client configuration with an X25519-only offer, so the ClientHello fits
/// a single fragment and the tests below can index into it directly.
fn small_client13_cfg(server_cert: &[u8]) -> PcClientConfig13 {
    let mut cfg = client13_cfg(server_cert);
    cfg.groups = alloc::vec![NamedGroup::X25519];
    cfg
}

// ---------------------------------------------------------------------
// DTLS-I1: RFC 9147 §5.3 hello wire format.
// ---------------------------------------------------------------------

/// The DTLS 1.3 ClientHello is DTLS-shaped: `legacy_version = 0xfefd`, a
/// zero-length `legacy_cookie` right after `legacy_session_id`, and
/// `supported_versions` offering exactly `0xfefc`.
#[test]
fn dtls13_client_hello_is_rfc9147_shaped() {
    let (_, cert) = server13_cfg();
    let mut client = client13(small_client13_cfg(&cert), b"i1-client");
    let out = client.pop_outbound_datagrams();
    assert_eq!(out.len(), 1);
    let (ty, body) = single_plaintext_handshake(&out[0]);
    assert_eq!(ty, hs_type::CLIENT_HELLO);
    // legacy_version(2) ‖ random(32) ‖ legacy_session_id<u8>=∅ ‖
    // legacy_cookie<u8>=∅ ‖ cipher_suites<u16> …
    assert_eq!(&body[..2], &[0xfe, 0xfd], "legacy_version must be DTLS 1.2");
    assert_eq!(body[34], 0, "legacy_session_id must be empty");
    assert_eq!(body[35], 0, "legacy_cookie must be empty in DTLS 1.3");
    let (ch, cookie) = ClientHello::decode_dtls(&body).unwrap();
    assert!(cookie.is_empty());
    assert_eq!(ch.legacy_version, 0xfefd);
    let sv = ch
        .extensions
        .iter()
        .find(|(t, _)| *t == ExtensionType::SUPPORTED_VERSIONS)
        .map(|(_, v)| v.clone())
        .expect("supported_versions");
    assert_eq!(sv, alloc::vec![0x02, 0xfe, 0xfc]);
    // The TLS-shaped decoder must not accept the DTLS body.
    assert!(ClientHello::decode(&body).is_err());
}

/// The DTLS 1.3 ServerHello — and, on the cookie path, the
/// HelloRetryRequest — carry `legacy_version = 0xfefd` and select `0xfefc`.
#[test]
fn dtls13_server_hello_and_hrr_select_dtlsv1_3() {
    for cookie in [false, true] {
        let (server_cfg, cert) = server13_cfg();
        let server_cfg = if cookie {
            server_cfg.with_cookie_secret([0x5a; 32])
        } else {
            server_cfg.with_no_cookie()
        };
        let mut client = client13(small_client13_cfg(&cert), b"i1-client-sh");
        let mut server = server13(server_cfg, b"i1-server-sh");
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        let s_out = server.pop_outbound_datagrams();
        let (ty, body) = single_plaintext_handshake(&s_out[0]);
        assert_eq!(ty, hs_type::SERVER_HELLO);
        assert_eq!(&body[..2], &[0xfe, 0xfd]);
        // The DTLS decoder (which insists on 0xfefd) parses it; the TLS
        // decoder (which insists on 0x0303) does not.
        let sh = ServerHello::decode_dtls(&body).unwrap();
        assert!(ServerHello::decode(&body).is_err());
        assert_eq!(
            sh.random == crate::tls::codec::HRR_RANDOM,
            cookie,
            "cookie server answers CH1 with an HRR"
        );
        let sv = sh
            .extensions
            .iter()
            .find(|(t, _)| *t == ExtensionType::SUPPORTED_VERSIONS)
            .map(|(_, v)| v.clone())
            .expect("supported_versions");
        assert_eq!(sv, alloc::vec![0xfe, 0xfc]);
        // And the handshake still completes end to end.
        for dg in &s_out {
            client.feed_datagram(dg).unwrap();
        }
        assert!(pump13(&mut client, &mut server));
    }
}

/// A TLS-shaped ClientHello (no `legacy_cookie` field) is not a DTLS
/// ClientHello: the server drops it silently (epoch-0 input is spoofable)
/// and answers nothing; the genuine DTLS-shaped hello still completes.
#[test]
fn dtls13_server_drops_tls_shaped_client_hello() {
    let (server_cfg, cert) = server13_cfg();
    let mut client = client13(small_client13_cfg(&cert), b"i1-client-tls-shape");
    let mut server = server13(server_cfg.with_no_cookie(), b"i1-server-tls-shape");
    let genuine = client.pop_outbound_datagrams().remove(0);

    // Re-encode the same hello TLS-style (drop the cookie length byte) and
    // patch the three enclosing length fields.
    let (_, body) = single_plaintext_handshake(&genuine);
    let mut tls_body = body.clone();
    tls_body.remove(35);
    let mut forged = genuine.clone();
    forged.truncate(record::HEADER_LEN + 12);
    forged.extend_from_slice(&tls_body);
    let n = tls_body.len() as u32;
    let frag_len = (12 + tls_body.len()) as u16;
    forged[11..13].copy_from_slice(&frag_len.to_be_bytes());
    forged[13 + 1..13 + 4].copy_from_slice(&n.to_be_bytes()[1..]);
    forged[13 + 9..13 + 12].copy_from_slice(&n.to_be_bytes()[1..]);
    // Sanity: the forged body is what a TLS 1.3 client would have sent.
    assert!(ClientHello::decode(&tls_body).is_ok());

    assert_eq!(server.feed_datagram(&forged), Ok(()));
    assert!(
        server.pop_outbound_datagrams().is_empty(),
        "a TLS-shaped hello must not elicit a server flight"
    );
    server.feed_datagram(&genuine).unwrap();
    assert!(
        !server.pop_outbound_datagrams().is_empty(),
        "the genuine DTLS hello is served"
    );
}

/// A ClientHello that only offers TLS 1.3 (`0x0304`) in
/// `supported_versions` is refused by the DTLS 1.3 server: RFC 9147 §5.3
/// forbids selecting a non-DTLS codepoint.
#[test]
fn dtls13_server_refuses_tls_only_supported_versions() {
    let (server_cfg, cert) = server13_cfg();
    let mut client = client13(small_client13_cfg(&cert), b"i1-client-0304");
    let mut server = server13(server_cfg.with_no_cookie(), b"i1-server-0304");
    let mut dg = client.pop_outbound_datagrams().remove(0);
    // Locate the `supported_versions` body `02 fe fc` and rewrite it to
    // `02 03 04`.
    let pos = dg
        .windows(7)
        .position(|w| w == [0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc])
        .expect("supported_versions extension");
    dg[pos + 5] = 0x03;
    dg[pos + 6] = 0x04;
    assert_eq!(server.feed_datagram(&dg), Ok(()));
    assert!(server.pop_outbound_datagrams().is_empty());
}

/// The client accepts only `0xfefc`: a ServerHello selecting the TLS
/// codepoint `0x0304` is rejected (dropped as spoofable epoch-0 input) and
/// the client neither installs keys nor completes.
#[test]
fn dtls13_client_rejects_tls_version_in_server_hello() {
    let (server_cfg, cert) = server13_cfg();
    let mut client = client13(small_client13_cfg(&cert), b"i1-client-sh-0304");
    let mut server = server13(server_cfg.with_no_cookie(), b"i1-server-sh-0304");
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    let mut s_out = server.pop_outbound_datagrams();
    let sh = &mut s_out[0];
    let pos = sh
        .windows(6)
        .position(|w| w == [0x00, 0x2b, 0x00, 0x02, 0xfe, 0xfc])
        .expect("supported_versions extension");
    sh[pos + 4] = 0x03;
    sh[pos + 5] = 0x04;
    for dg in &s_out {
        client.feed_datagram(dg).unwrap();
    }
    assert!(!client.is_handshake_complete());
    assert!(
        client.pop_outbound_datagrams().is_empty(),
        "no Finished / ACKs without accepted keys"
    );
}

/// DTLS 1.2 (RFC 6347 §4.2.1): the ClientHello carries `legacy_version =
/// 0xfefd` and the `cookie` field — empty on the first attempt, echoing the
/// HelloVerifyRequest cookie on the second.
#[test]
fn dtls12_client_hello_carries_version_and_cookie_field() {
    let (server_cfg, cert) = server12_cfg();
    let server_cfg = server_cfg
        .with_cookie_secret([0x77; 32])
        .require_cookie_exchange(true);
    let mut client = client12(&cert, b"i1-client-12");
    let mut server = server12(server_cfg, b"i1-server-12");

    let ch1 = client.pop_outbound_datagrams().remove(0);
    let (ty, body) = single_plaintext_handshake(&ch1);
    assert_eq!(ty, hs_type::CLIENT_HELLO);
    assert_eq!(&body[..2], &[0xfe, 0xfd]);
    assert_eq!(body[34], 0, "empty session id");
    assert_eq!(body[35], 0, "first CH carries an empty cookie");
    let (ch, cookie) = ClientHello::decode_dtls(&body).unwrap();
    assert!(cookie.is_empty());
    assert_eq!(ch.legacy_version, 0xfefd);

    server.feed_datagram(&ch1).unwrap();
    let hvr = server.pop_outbound_datagrams().remove(0);
    let (ty, hvr_body) = single_plaintext_handshake(&hvr);
    assert_eq!(ty, 3, "hello_verify_request");
    let mut c = ReadCursor::new(&hvr_body);
    assert_eq!(c.u16().unwrap(), 0xfefd);
    let issued = c.vec_u8().unwrap().to_vec();
    assert!(!issued.is_empty());

    client.feed_datagram(&hvr).unwrap();
    let ch2 = client.pop_outbound_datagrams().remove(0);
    let (_, body2) = single_plaintext_handshake(&ch2);
    let (_, echoed) = ClientHello::decode_dtls(&body2).unwrap();
    assert_eq!(echoed, issued, "CH2 echoes the HVR cookie verbatim");
    assert_eq!(body2[35] as usize, issued.len());

    server.feed_datagram(&ch2).unwrap();
    assert!(pump12(&mut client, &mut server));
}

// ---------------------------------------------------------------------
// DTLS-I2: post-handshake KeyUpdate / NewSessionTicket (RFC 9147 §8).
// ---------------------------------------------------------------------

fn connected_pair() -> (
    DtlsClientConnection13,
    DtlsServerConnection13<HmacDrbg<Sha256>>,
) {
    let (server_cfg, cert) = server13_cfg();
    let mut client = client13(small_client13_cfg(&cert), b"i2-client");
    let mut server = server13(server_cfg.with_no_cookie(), b"i2-server");
    assert!(pump13(&mut client, &mut server));
    // Drain the trailing ACK exchange so nothing is in flight.
    for _ in 0..4 {
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
    }
    assert_eq!(client.write_epoch(), 3);
    assert_eq!(server.write_epoch(), 3);
    assert_eq!(client.read_epoch(), Some(3));
    assert_eq!(server.read_epoch(), Some(3));
    (client, server)
}

/// Server-initiated KeyUpdate: the server keeps writing under epoch 3
/// until the client's ACK arrives, the client moves its read epoch to 4 on
/// the KeyUpdate itself, still decrypts the straggling epoch-3 record, and
/// data flows both ways afterwards.
#[test]
fn key_update_server_initiated_13() {
    let (mut client, mut server) = connected_pair();
    server.request_key_update(false).unwrap();
    assert!(server.key_update_pending());
    let ku = server.pop_outbound_datagrams();
    assert_eq!(ku.len(), 1);
    // RFC 9147 §8: no new-epoch traffic before the ACK — this record is
    // still epoch 3 (low bits 0b11).
    server.send(b"before-ack").unwrap();
    let straggler = server.pop_outbound_datagrams().remove(0);
    assert_eq!(straggler[0] & 0b11, 3);
    assert_eq!(server.write_epoch(), 3);

    for dg in &ku {
        client.feed_datagram(dg).unwrap();
    }
    assert_eq!(client.read_epoch(), Some(4));
    // The epoch-3 straggler arrives after the switch: previous-epoch keys
    // are retained for it.
    client.feed_datagram(&straggler).unwrap();
    assert_eq!(client.take_received(), b"before-ack");

    // Client ACK → server switches to epoch 4.
    let acks = client.pop_outbound_datagrams();
    assert!(!acks.is_empty());
    for dg in &acks {
        server.feed_datagram(dg).unwrap();
    }
    assert!(!server.key_update_pending());
    assert_eq!(server.write_epoch(), 4);
    assert!(server.next_timeout().is_none(), "KeyUpdate released");
    server.send(b"after").unwrap();
    let rec = server.pop_outbound_datagrams().remove(0);
    assert_eq!(rec[0] & 0b11, 0, "epoch 4 → low bits 00");
    client.feed_datagram(&rec).unwrap();
    assert_eq!(client.take_received(), b"after");
    app_data_round_trip(&mut client, &mut server);
    // The client did not update its own keys (update_not_requested).
    assert_eq!(client.write_epoch(), 3);
    assert_eq!(server.read_epoch(), Some(3));
}

/// Client-initiated KeyUpdate with `update_requested`: the server answers
/// with its own KeyUpdate; both directions end up at epoch 4.
#[test]
fn key_update_client_initiated_with_request_13() {
    let (mut client, mut server) = connected_pair();
    client.request_key_update(true).unwrap();
    // A second one while the first is unacknowledged is refused (§8).
    assert_eq!(
        client.request_key_update(false),
        Err(crate::tls::Error::InappropriateState)
    );
    for _ in 0..6 {
        for dg in &client.pop_outbound_datagrams() {
            server.feed_datagram(dg).unwrap();
        }
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
    }
    assert!(!client.key_update_pending());
    assert!(!server.key_update_pending());
    assert_eq!(client.write_epoch(), 4);
    assert_eq!(server.write_epoch(), 4);
    assert_eq!(client.read_epoch(), Some(4));
    assert_eq!(server.read_epoch(), Some(4));
    app_data_round_trip(&mut client, &mut server);
    // Two more rounds: epochs keep advancing (5, 6) and nothing wedges.
    for _ in 0..2 {
        server.request_key_update(true).unwrap();
        for _ in 0..6 {
            for dg in &server.pop_outbound_datagrams() {
                client.feed_datagram(dg).unwrap();
            }
            for dg in &client.pop_outbound_datagrams() {
                server.feed_datagram(dg).unwrap();
            }
        }
        app_data_round_trip(&mut client, &mut server);
    }
    assert_eq!(client.write_epoch(), 6);
    assert_eq!(server.read_epoch(), Some(6));
}

/// A lost ACK: the server retransmits the KeyUpdate under the old epoch,
/// the client (already at the new read epoch) decrypts it with the retained
/// keys, ignores the stale message and re-ACKs; the server then switches.
#[test]
fn retransmitted_key_update_is_reacked_13() {
    let (mut client, mut server) = connected_pair();
    server.request_key_update(false).unwrap();
    for dg in &server.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    assert_eq!(client.read_epoch(), Some(4));
    let _lost_ack = client.pop_outbound_datagrams();
    let t = server.next_timeout().expect("KeyUpdate in flight");
    server.on_timeout(t);
    let retx = server.pop_outbound_datagrams();
    assert_eq!(retx.len(), 1);
    assert_eq!(retx[0][0] & 0b11, 3, "retransmitted under epoch 3");
    client.feed_datagram(&retx[0]).unwrap();
    assert_eq!(
        client.read_epoch(),
        Some(4),
        "stale KeyUpdate not re-applied"
    );
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    assert_eq!(server.write_epoch(), 4);
    assert!(server.next_timeout().is_none());
    app_data_round_trip(&mut client, &mut server);
}

/// The previous read epoch is retained only for a bounded window: after
/// `PREV_EPOCH_GRACE_RECORDS` records under the new epoch, an old-epoch
/// record is dropped.
#[test]
fn old_epoch_records_rejected_after_grace_window_13() {
    use crate::dtls::epoch13::PREV_EPOCH_GRACE_RECORDS;
    let (mut client, mut server) = connected_pair();
    server.request_key_update(false).unwrap();
    let ku = server.pop_outbound_datagrams();
    server.send(b"old-epoch").unwrap();
    let old = server.pop_outbound_datagrams().remove(0);
    for dg in &ku {
        client.feed_datagram(dg).unwrap();
    }
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    assert_eq!(server.write_epoch(), 4);
    for _ in 0..PREV_EPOCH_GRACE_RECORDS {
        server.send(b"x").unwrap();
        for dg in &server.pop_outbound_datagrams() {
            client.feed_datagram(dg).unwrap();
        }
    }
    let _ = client.take_received();
    // Past the window: silently dropped (never fatal — a stale datagram
    // must not kill the connection).
    assert_eq!(client.feed_datagram(&old), Ok(()));
    assert!(client.take_received().is_empty());
    app_data_round_trip(&mut client, &mut server);
}

/// A NewSessionTicket from the server is accepted (no resumption store:
/// discarded) and acknowledged, so the server's retransmit timer clears.
#[test]
fn new_session_ticket_accepted_and_acked_13() {
    let (mut client, mut server) = connected_pair();
    let nst = crate::tls::codec::NewSessionTicket {
        ticket_lifetime: 3600,
        ticket_age_add: 0x1234_5678,
        ticket_nonce: alloc::vec![0, 1],
        ticket: alloc::vec![0xab; 64],
        extensions: Vec::new(),
    }
    .encode();
    server.send_handshake_for_test(hs_type::NEW_SESSION_TICKET, &nst[4..]);
    assert!(server.next_timeout().is_some());
    for dg in &server.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    assert!(client.is_handshake_complete());
    let acks = client.pop_outbound_datagrams();
    assert!(!acks.is_empty(), "NST must be ACKed");
    for dg in &acks {
        server.feed_datagram(dg).unwrap();
    }
    assert!(server.next_timeout().is_none(), "ACK released the NST");
    app_data_round_trip(&mut client, &mut server);

    // A malformed ticket from the authenticated server is still fatal.
    server.send_handshake_for_test(hs_type::NEW_SESSION_TICKET, &[0u8; 13]);
    for dg in &server.pop_outbound_datagrams() {
        assert!(client.feed_datagram(dg).is_err());
    }
}

/// Only the server issues tickets: one from the client is a protocol
/// violation, as is any other post-handshake message type.
#[test]
fn server_rejects_client_post_handshake_junk_13() {
    let (mut client, mut server) = connected_pair();
    let nst = crate::tls::codec::NewSessionTicket {
        ticket_lifetime: 1,
        ticket_age_add: 0,
        ticket_nonce: Vec::new(),
        ticket: alloc::vec![1],
        extensions: Vec::new(),
    }
    .encode();
    client.send_handshake_for_test(hs_type::NEW_SESSION_TICKET, &nst[4..]);
    for dg in &client.pop_outbound_datagrams() {
        assert_eq!(
            server.feed_datagram(dg),
            Err(crate::tls::Error::UnexpectedMessage)
        );
    }
    let (mut client, mut server) = connected_pair();
    client.send_handshake_for_test(hs_type::FINISHED, &[0u8; 32]);
    for dg in &client.pop_outbound_datagrams() {
        assert_eq!(
            server.feed_datagram(dg),
            Err(crate::tls::Error::UnexpectedMessage)
        );
    }
}

/// An authenticated peer cannot grind key derivations forever: the 65th
/// inbound KeyUpdate is refused.
#[test]
fn key_updates_received_are_bounded_13() {
    use crate::dtls::epoch13::MAX_KEY_UPDATES_RECEIVED;
    let (mut client, mut server) = connected_pair();
    for i in 0..=MAX_KEY_UPDATES_RECEIVED {
        server.request_key_update(false).unwrap();
        let ku = server.pop_outbound_datagrams();
        let res = client.feed_datagram(&ku[0]);
        if i < MAX_KEY_UPDATES_RECEIVED {
            res.unwrap();
            for dg in &client.pop_outbound_datagrams() {
                server.feed_datagram(dg).unwrap();
            }
            assert_eq!(server.write_epoch() as u32, 4 + i);
        } else {
            assert_eq!(res, Err(crate::tls::Error::PeerMisbehaved));
        }
    }
}

/// A KeyUpdate whose ACK never arrives closes the connection once the
/// retransmit budget is spent (the peer may have moved on to the new epoch
/// while we, per §8, may not).
#[test]
fn unacked_key_update_eventually_closes_13() {
    let (mut client, _server) = connected_pair();
    client.request_key_update(false).unwrap();
    let _ = client.pop_outbound_datagrams();
    for _ in 0..16 {
        let Some(t) = client.next_timeout() else {
            break;
        };
        client.on_timeout(t);
        let _ = client.pop_outbound_datagrams();
    }
    assert!(!client.is_handshake_complete(), "closed after giving up");
    assert_eq!(
        client.send(b"x"),
        Err(crate::tls::Error::InappropriateState)
    );
}

// ---------------------------------------------------------------------
// DTLS-I3: epoch-2 grace window at the end of the handshake
// (RFC 9147 §5.8.3 / §8).
// ---------------------------------------------------------------------

/// The server's ACK of the client Finished is lost. The client's single
/// timer-driven retransmission (still epoch 2, fresh record number) must be
/// decrypted with the retained epoch-2 keys and re-ACKed, so the client
/// completes without any further retransmit.
#[test]
fn server_reacks_retransmitted_client_finished_13() {
    let (server_cfg, cert) = server13_cfg();
    let mut client = client13(small_client13_cfg(&cert), b"i3-client");
    let mut server = server13(server_cfg.with_no_cookie(), b"i3-server");
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    for dg in &server.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    assert!(client.is_handshake_complete());
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    assert!(server.is_handshake_complete());
    // Server → client ACK: lost.
    let lost = server.pop_outbound_datagrams();
    assert!(!lost.is_empty());
    assert!(client.next_timeout().is_some(), "Finished still in flight");

    // One retransmit.
    let t = client.next_timeout().unwrap();
    client.on_timeout(t);
    let retx = client.pop_outbound_datagrams();
    assert_eq!(retx.len(), 1, "exactly the Finished is re-sent");
    assert_eq!(retx[0][0] & 0b11, 2, "re-sent under epoch 2");
    for dg in &retx {
        server.feed_datagram(dg).unwrap();
    }
    assert!(
        server.is_handshake_complete(),
        "duplicate Finished is harmless"
    );
    let reack = server.pop_outbound_datagrams();
    assert!(
        !reack.is_empty(),
        "server must re-ACK the retransmitted Finished"
    );
    for dg in &reack {
        client.feed_datagram(dg).unwrap();
    }
    assert!(
        client.next_timeout().is_none(),
        "the re-ACK releases the Finished: no further retransmits"
    );
    app_data_round_trip(&mut client, &mut server);
}

/// Mirror image: the client's ACKs (and its Finished) are lost, so the
/// server retransmits its epoch-2 flight. The already-connected client must
/// decrypt those copies with the retained epoch-2 keys and ACK them rather
/// than drop them — and must not be derailed by the duplicates. (The ACKs
/// travel under epoch 3, which the server only starts reading once the
/// client's Finished arrives; the Finished retransmit then implicitly
/// acknowledges the whole server flight.)
#[test]
fn client_reacks_retransmitted_server_flight_13() {
    let (server_cfg, cert) = server13_cfg();
    let mut client = client13(small_client13_cfg(&cert), b"i3c-client");
    let mut server = server13(server_cfg.with_no_cookie(), b"i3c-server");
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    let flight = server.pop_outbound_datagrams();
    for dg in &flight {
        client.feed_datagram(dg).unwrap();
    }
    assert!(client.is_handshake_complete());
    let _lost_client_output = client.pop_outbound_datagrams();

    let t = server.next_timeout().expect("server flight in flight");
    server.on_timeout(t);
    let retx = server.pop_outbound_datagrams();
    assert_eq!(retx.len(), flight.len(), "whole flight re-sent");
    for dg in &retx {
        client.feed_datagram(dg).unwrap();
    }
    let acks = client.pop_outbound_datagrams();
    assert!(!acks.is_empty(), "client re-ACKs the epoch-2 copies");
    assert!(
        acks.iter().all(|dg| dg[0] >= 32 && (dg[0] & 0b11) == 3),
        "only protected epoch-3 (ACK) records, no new handshake output"
    );
    assert!(client.is_handshake_complete(), "duplicates are harmless");
    for dg in &acks {
        server.feed_datagram(dg).unwrap();
    }
    // The client's Finished retransmit completes the server.
    let t = client.next_timeout().unwrap();
    client.on_timeout(t);
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    assert!(server.is_handshake_complete());
    for dg in &server.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    assert!(client.next_timeout().is_none());
    app_data_round_trip(&mut client, &mut server);
}

// ---------------------------------------------------------------------
// DTLS-I5: MTU-bounded handshake fragmentation (RFC 9147 §4.4 /
// RFC 6347 §4.1.1).
// ---------------------------------------------------------------------

/// A "certificate chain" whose second entry is 70 000 opaque bytes: the
/// Certificate message alone exceeds the 16-bit record length field, so it
/// used to hit the silent `as u16` truncation. With verification off the
/// client only parses the leaf, so the padding may be arbitrary.
const JUNK_CERT_LEN: usize = 70_000;

fn oversized_chain(leaf: &[u8]) -> Vec<Vec<u8>> {
    alloc::vec![leaf.to_vec(), alloc::vec![0x5a; JUNK_CERT_LEN]]
}

/// Drives a DTLS 1.3 handshake with a >64 KiB Certificate at the given
/// record ceiling, asserting that no datagram from either side exceeds it.
fn huge_chain_handshake_13(max_record_size: usize) {
    let (key, leaf) = server_identity(b"i5-key-13");
    let mut server_cfg = PcServerConfig13::with_ecdsa(oversized_chain(&leaf), key).with_no_cookie();
    server_cfg.max_record_size = max_record_size;
    let mut client_cfg = client13_cfg(&leaf).without_certificate_verification();
    client_cfg.max_record_size = max_record_size;
    let mut client = client13(client_cfg, b"i5-client-13");
    let mut server = server13(server_cfg, b"i5-server-13");
    let mut records = 0usize;
    for _ in 0..32 {
        let c_out = client.pop_outbound_datagrams();
        for dg in &c_out {
            assert!(
                dg.len() <= max_record_size,
                "client datagram {} > {max_record_size}",
                dg.len()
            );
            server.feed_datagram(dg).unwrap();
        }
        let s_out = server.pop_outbound_datagrams();
        for dg in &s_out {
            assert!(
                dg.len() <= max_record_size,
                "server datagram {} > {max_record_size}",
                dg.len()
            );
            client.feed_datagram(dg).unwrap();
        }
        records += c_out.len() + s_out.len();
        if c_out.is_empty() && s_out.is_empty() {
            break;
        }
    }
    assert!(client.is_handshake_complete());
    assert!(server.is_handshake_complete());
    assert!(
        records > JUNK_CERT_LEN / max_record_size,
        "the chain must have been split across many datagrams"
    );
    assert_eq!(client.peer_certificates().len(), 2);
    assert_eq!(client.peer_certificates()[1].len(), JUNK_CERT_LEN);
    app_data_round_trip(&mut client, &mut server);
}

#[test]
fn huge_certificate_chain_respects_default_mtu_13() {
    huge_chain_handshake_13(record::DEFAULT_MAX_RECORD_SIZE);
}

#[test]
fn huge_certificate_chain_respects_small_mtu_13() {
    huge_chain_handshake_13(600);
}

/// Same for DTLS 1.2: every fragment of the server's Certificate is its
/// own record and datagram, none above the 1200-byte default ceiling.
#[test]
fn huge_certificate_chain_respects_mtu_12() {
    let (key, leaf) = server_identity(b"i5-key-12");
    let server_cfg =
        PcServerConfig12::with_ecdsa(oversized_chain(&leaf), key).require_cookie_exchange(false);
    let mut roots = RootCertStore::new();
    roots.add_der(leaf.clone()).unwrap();
    let cfg = PcClientConfig12::new(roots, "dtls.example").without_certificate_verification();
    let mut crng = HmacDrbg::<Sha256>::new(b"i5-client-12", b"nonce", &[]);
    let mut client = DtlsClientConnection12::new(cfg, b"peer-a".to_vec(), &mut crng);
    let mut server = server12(server_cfg, b"i5-server-12");
    let mut records = 0usize;
    for _ in 0..32 {
        let c_out = client.pop_outbound_datagrams();
        for dg in &c_out {
            assert!(dg.len() <= record::DEFAULT_MAX_RECORD_SIZE);
            server.feed_datagram(dg).unwrap();
        }
        let s_out = server.pop_outbound_datagrams();
        for dg in &s_out {
            assert!(dg.len() <= record::DEFAULT_MAX_RECORD_SIZE);
            client.feed_datagram(dg).unwrap();
        }
        records += c_out.len() + s_out.len();
        if c_out.is_empty() && s_out.is_empty() {
            break;
        }
    }
    assert!(client.is_handshake_complete());
    assert!(server.is_handshake_complete());
    assert!(records > JUNK_CERT_LEN / record::DEFAULT_MAX_RECORD_SIZE);
    client.send(b"ping").unwrap();
    for dg in &client.pop_outbound_datagrams() {
        server.feed_datagram(dg).unwrap();
    }
    assert_eq!(server.take_received(), b"ping");
}

// ---------------------------------------------------------------------
// DTLS-I6: cookie-secret rotation with one previous generation.
// ---------------------------------------------------------------------

const GEN1: [u8; 32] = [0x11; 32];
const GEN2: [u8; 32] = [0x22; 32];
const GEN3: [u8; 32] = [0x33; 32];

/// DTLS 1.3: a cookie minted under the old secret validates on a server
/// that has rotated to a new one and kept the old as `previous`; the same
/// cookie is refused once the secret has rotated twice. The server is
/// stateless across the HRR round trip, so the post-rotation server is a
/// fresh connection object, exactly as a real deployment's would be.
#[test]
fn rotated_cookie_secret_accepts_previous_generation_13() {
    let (server_cfg, cert) = server13_cfg();
    let mut client = client13(small_client13_cfg(&cert), b"i6-client-13");
    let mut issuer = server13(server_cfg.with_cookie_secret(GEN1), b"i6-issuer-13");
    for dg in &client.pop_outbound_datagrams() {
        issuer.feed_datagram(dg).unwrap();
    }
    for dg in &issuer.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    let ch2 = client.pop_outbound_datagrams();
    assert!(!ch2.is_empty(), "client answers the HRR with CH2");

    // Two generations stale: refused (silent drop, no server flight).
    let (server_cfg, _) = server13_cfg();
    let mut stale = server13(
        server_cfg
            .with_cookie_secret(GEN3)
            .with_previous_cookie_secret(GEN2),
        b"i6-stale-13",
    );
    for dg in &ch2 {
        assert_eq!(stale.feed_datagram(dg), Ok(()));
    }
    assert!(stale.pop_outbound_datagrams().is_empty());

    // One generation stale: accepted, handshake completes.
    let (server_cfg, _) = server13_cfg();
    let mut rotated = server13(
        server_cfg
            .with_cookie_secret(GEN2)
            .with_previous_cookie_secret(GEN1),
        b"i6-rotated-13",
    );
    for dg in &ch2 {
        rotated.feed_datagram(dg).unwrap();
    }
    let flight = rotated.pop_outbound_datagrams();
    assert!(
        !flight.is_empty(),
        "rotated server must serve the old cookie"
    );
    for dg in &flight {
        client.feed_datagram(dg).unwrap();
    }
    assert!(pump13(&mut client, &mut rotated));
    app_data_round_trip(&mut client, &mut rotated);
}

/// DTLS 1.2 mirror of the above with the HelloVerifyRequest cookie.
#[test]
fn rotated_cookie_secret_accepts_previous_generation_12() {
    let (server_cfg, cert) = server12_cfg();
    let mut client = client12(&cert, b"i6-client-12");
    let mut issuer = server12(
        server_cfg
            .with_cookie_secret(GEN1)
            .require_cookie_exchange(true),
        b"i6-issuer-12",
    );
    for dg in &client.pop_outbound_datagrams() {
        issuer.feed_datagram(dg).unwrap();
    }
    for dg in &issuer.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    let ch2 = client.pop_outbound_datagrams();
    assert!(!ch2.is_empty(), "client answers the HVR with CH2");

    let (server_cfg, _) = server12_cfg();
    let mut stale = server12(
        server_cfg
            .with_cookie_secret(GEN3)
            .with_previous_cookie_secret(GEN2)
            .require_cookie_exchange(true),
        b"i6-stale-12",
    );
    for dg in &ch2 {
        assert_eq!(stale.feed_datagram(dg), Ok(()));
    }
    assert!(stale.pop_outbound_datagrams().is_empty());

    let (server_cfg, _) = server12_cfg();
    let mut rotated = server12(
        server_cfg
            .with_cookie_secret(GEN2)
            .with_previous_cookie_secret(GEN1)
            .require_cookie_exchange(true),
        b"i6-rotated-12",
    );
    for dg in &ch2 {
        rotated.feed_datagram(dg).unwrap();
    }
    let flight = rotated.pop_outbound_datagrams();
    assert!(
        !flight.is_empty(),
        "rotated server must serve the old cookie"
    );
    for dg in &flight {
        client.feed_datagram(dg).unwrap();
    }
    assert!(pump12(&mut client, &mut rotated));
}

/// Cookies are minted only under the current secret: a server holding
/// `(GEN2, previous = GEN1)` issues cookies that a `(GEN1)`-only server
/// does not accept.
#[test]
fn cookies_are_minted_under_current_secret_only_13() {
    let (server_cfg, cert) = server13_cfg();
    let mut client = client13(small_client13_cfg(&cert), b"i6-mint-client");
    let mut issuer = server13(
        server_cfg
            .with_cookie_secret(GEN2)
            .with_previous_cookie_secret(GEN1),
        b"i6-mint-issuer",
    );
    for dg in &client.pop_outbound_datagrams() {
        issuer.feed_datagram(dg).unwrap();
    }
    for dg in &issuer.pop_outbound_datagrams() {
        client.feed_datagram(dg).unwrap();
    }
    let ch2 = client.pop_outbound_datagrams();
    let (server_cfg, _) = server13_cfg();
    let mut old = server13(server_cfg.with_cookie_secret(GEN1), b"i6-mint-old");
    for dg in &ch2 {
        assert_eq!(old.feed_datagram(dg), Ok(()));
    }
    assert!(old.pop_outbound_datagrams().is_empty());
}
