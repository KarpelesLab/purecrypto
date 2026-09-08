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
#[allow(dead_code)] // used from DTLS-I2 onward
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
