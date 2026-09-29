//! Loopback tests for RFC 9146 / RFC 9147 §9 connection IDs on both DTLS
//! versions: negotiation in each direction, the record forms on the wire,
//! the receive-side rules (a record without a CID once one is expected, a
//! CID this side never issued, a CID when none was negotiated — all
//! silently dropped), the RFC 9146 §6 peer-address-update conditions, the
//! DTLS 1.3 `NewConnectionId` / `RequestConnectionId` exchange and its
//! bounds, and retransmission under a CID.

use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
use crate::hash::Sha256;
use crate::rng::HmacDrbg;
use crate::tls::codec::hs_type;
use crate::tls::pki::RootCertStore;
use crate::tls::{ContentType, Error};
use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::cid::{
    ConnectionIdUsage, LOCAL_CID_POOL, MAX_CID_REQUESTS_RECEIVED, NewConnectionId,
    peek_connection_id,
};
use super::record::TLS12_CID_CONTENT_TYPE;
use super::{
    ClientConfig12Internal, ClientConfig13Internal, DtlsClientConnection12, DtlsClientConnection13,
    DtlsServerConnection12, DtlsServerConnection13, ServerConfig12Internal, ServerConfig13Internal,
};

type Rng = HmacDrbg<Sha256>;

fn rng(tag: &[u8]) -> Rng {
    Rng::new(tag, b"nonce", &[])
}

/// A self-signed P-256 server certificate and its key.
fn server_identity() -> (BoxedEcdsaPrivateKey, Vec<u8>) {
    let mut r = rng(b"cid-test-key");
    let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut r);
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

fn roots_for(cert: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::new();
    roots.add_der(cert.to_vec()).unwrap();
    roots
}

const CLIENT_CID: [u8; 4] = [0xc1, 0xc2, 0xc3, 0xc4];
const SERVER_CID: [u8; 6] = [0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e];

// ---------------------------------------------------------------------
// DTLS 1.2
// ---------------------------------------------------------------------

fn pair12(
    client_cid: Option<&[u8]>,
    server_cid: Option<&[u8]>,
) -> (DtlsClientConnection12, DtlsServerConnection12<Rng>) {
    let (key, cert) = server_identity();
    let mut sc = ServerConfig12Internal::with_ecdsa(alloc::vec![cert.clone()], key)
        .require_cookie_exchange(false)
        .with_connection_id(server_cid.map(<[u8]>::to_vec));
    sc.key_log = None;
    let server = DtlsServerConnection12::new(Arc::new(sc), b"addr".to_vec(), rng(b"srv12"));
    let mut cc = ClientConfig12Internal::new(roots_for(&cert), "dtls.example")
        .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
    cc.connection_id = client_cid.map(<[u8]>::to_vec);
    let client = DtlsClientConnection12::new(cc, b"addr".to_vec(), &mut rng(b"cli12"));
    (client, server)
}

fn pump12(client: &mut DtlsClientConnection12, server: &mut DtlsServerConnection12<Rng>) -> bool {
    for _ in 0..32 {
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
    client.is_handshake_complete() && server.is_handshake_complete()
}

/// Both sides receive under their own CID: every protected record is a
/// `tls12_cid` record carrying the *receiver's* CID (RFC 9146 §3, §4), the
/// stateless peek reads it, and data flows both ways.
#[test]
fn cid_both_directions_12() {
    let (mut client, mut server) = pair12(Some(&CLIENT_CID), Some(&SERVER_CID));
    assert!(pump12(&mut client, &mut server));
    assert_eq!(client.local_connection_id(), Some(&CLIENT_CID[..]));
    assert_eq!(client.peer_connection_id(), Some(&SERVER_CID[..]));
    assert_eq!(server.local_connection_id(), Some(&SERVER_CID[..]));
    assert_eq!(server.peer_connection_id(), Some(&CLIENT_CID[..]));

    client.send(b"ping").unwrap();
    let c = client.pop_outbound_datagrams();
    assert_eq!(c.len(), 1);
    assert_eq!(c[0][0], TLS12_CID_CONTENT_TYPE);
    assert_eq!(&c[0][11..17], &SERVER_CID);
    assert_eq!(peek_connection_id(&c[0], 6), Some(&SERVER_CID[..]));
    server.feed_datagram(&c[0]).unwrap();
    assert_eq!(server.take_received(), b"ping");
    assert!(server.datagram_allows_peer_address_update());

    server.send(b"pong").unwrap();
    let s = server.pop_outbound_datagrams();
    assert_eq!(s[0][0], TLS12_CID_CONTENT_TYPE);
    assert_eq!(peek_connection_id(&s[0], 4), Some(&CLIENT_CID[..]));
    client.feed_datagram(&s[0]).unwrap();
    assert_eq!(client.take_received(), b"pong");
    assert!(client.datagram_allows_peer_address_update());
}

/// A zero-length offer (RFC 9146 §3): the client sends with the server's
/// CID but receives plain RFC 6347 records; the server's own records
/// carry no CID and the client accepts them.
#[test]
fn cid_one_direction_12() {
    let (mut client, mut server) = pair12(Some(&[]), Some(&SERVER_CID));
    assert!(pump12(&mut client, &mut server));
    assert_eq!(client.local_connection_id(), Some(&[][..]));
    assert_eq!(server.peer_connection_id(), Some(&[][..]));

    client.send(b"ping").unwrap();
    let c = client.pop_outbound_datagrams();
    assert_eq!(c[0][0], TLS12_CID_CONTENT_TYPE);
    server.feed_datagram(&c[0]).unwrap();
    assert_eq!(server.take_received(), b"ping");

    server.send(b"pong").unwrap();
    let s = server.pop_outbound_datagrams();
    assert_eq!(s[0][0], ContentType::ApplicationData.as_u8());
    assert_eq!(peek_connection_id(&s[0], 4), None);
    client.feed_datagram(&s[0]).unwrap();
    assert_eq!(client.take_received(), b"pong");
    // No CID on the record: the RFC 9146 §6 conditions are not met.
    assert!(!client.datagram_allows_peer_address_update());
}

/// CIDs need both sides: a server without one answers nothing, a client
/// that offered nothing gets nothing, and the records stay plain.
#[test]
fn cid_needs_both_sides_12() {
    for (c, s) in [(Some(&CLIENT_CID[..]), None), (None, Some(&SERVER_CID[..]))] {
        let (mut client, mut server) = pair12(c, s);
        assert!(pump12(&mut client, &mut server));
        assert_eq!(client.local_connection_id(), None);
        assert_eq!(client.peer_connection_id(), None);
        assert_eq!(server.local_connection_id(), None);
        client.send(b"x").unwrap();
        let dg = client.pop_outbound_datagrams().remove(0);
        assert_eq!(dg[0], ContentType::ApplicationData.as_u8());
        server.feed_datagram(&dg).unwrap();
        assert_eq!(server.take_received(), b"x");
        assert!(!server.datagram_allows_peer_address_update());
    }
}

/// RFC 9146 §3: once a non-zero CID is expected, a record without one is
/// invalid; one under a CID this side never issued is another
/// association's. Both are dropped without error and without touching
/// the connection. A `tls12_cid` record to a side that receives no CID is
/// dropped too.
#[test]
fn cid_receive_rules_12() {
    let (mut client, mut server) = pair12(Some(&CLIENT_CID), Some(&SERVER_CID));
    assert!(pump12(&mut client, &mut server));

    // A plain record where a CID is expected: dropped before the AEAD.
    client.send_without_cid_for_test(b"plain");
    let dg = client.pop_outbound_datagrams().remove(0);
    assert_eq!(dg[0], ContentType::ApplicationData.as_u8());
    server.feed_datagram(&dg).unwrap();
    assert!(server.take_received().is_empty());
    assert!(!server.datagram_allows_peer_address_update());

    // A CID the server never issued.
    client.send(b"data").unwrap();
    let mut dg = client.pop_outbound_datagrams().remove(0);
    dg[11] ^= 0x01;
    server.feed_datagram(&dg).unwrap();
    assert!(server.take_received().is_empty());
    assert!(!server.datagram_allows_peer_address_update());
    // The genuine record still goes through afterwards.
    dg[11] ^= 0x01;
    server.feed_datagram(&dg).unwrap();
    assert_eq!(server.take_received(), b"data");
    assert!(server.datagram_allows_peer_address_update());

    // A side that receives no CID drops a `tls12_cid` record.
    let (mut client, mut server) = pair12(Some(&[]), Some(&SERVER_CID));
    assert!(pump12(&mut client, &mut server));
    server.send(b"pong").unwrap();
    let mut dg = server.pop_outbound_datagrams().remove(0);
    dg[0] = TLS12_CID_CONTENT_TYPE;
    client.feed_datagram(&dg).unwrap();
    assert!(client.take_received().is_empty());
}

/// RFC 9146 §6: only a record newer than every record before it may move
/// the peer's address — a replay or a reordered older record must not.
#[test]
fn address_update_conditions_12() {
    let (mut client, mut server) = pair12(Some(&CLIENT_CID), Some(&SERVER_CID));
    assert!(pump12(&mut client, &mut server));
    client.send(b"one").unwrap();
    client.send(b"two").unwrap();
    let dgs = client.pop_outbound_datagrams();
    // The second record first: newest, qualifies.
    server.feed_datagram(&dgs[1]).unwrap();
    assert!(server.datagram_allows_peer_address_update());
    // The first, reordered: valid data, but older.
    server.feed_datagram(&dgs[0]).unwrap();
    assert_eq!(server.take_received(), b"twoone");
    assert!(!server.datagram_allows_peer_address_update());
    // A replay: dropped by the window, never qualifies.
    server.feed_datagram(&dgs[1]).unwrap();
    assert!(server.take_received().is_empty());
    assert!(!server.datagram_allows_peer_address_update());
    // A datagram that fails to authenticate never qualifies either.
    client.send(b"three").unwrap();
    let mut dg = client.pop_outbound_datagrams().remove(0);
    let last = dg.len() - 1;
    dg[last] ^= 0xff;
    server.feed_datagram(&dg).unwrap();
    assert!(!server.datagram_allows_peer_address_update());
}

/// The client's Finished — the first record under a CID (RFC 9146 §7:
/// "the CID is included in the record layer once encryption is enabled")
/// — is retransmitted under the CID when the server's flight is lost, and
/// the server re-sends its own CID-bearing final flight.
#[test]
fn retransmitted_final_flights_carry_cids_12() {
    let (mut client, mut server) = pair12(Some(&CLIENT_CID), Some(&SERVER_CID));
    // Drive the handshake up to the client's final flight: the server
    // completes on it, the client is still waiting for the server's.
    for _ in 0..8 {
        let c = client.pop_outbound_datagrams();
        for dg in &c {
            server.feed_datagram(dg).unwrap();
        }
        if server.is_handshake_complete() {
            break;
        }
        let s = server.pop_outbound_datagrams();
        for dg in &s {
            client.feed_datagram(dg).unwrap();
        }
    }
    assert!(server.is_handshake_complete());
    assert!(!client.is_handshake_complete());
    // The server's CCS + Finished was lost: the client retransmits its
    // flight on the timer, its Finished under the server's CID.
    let _lost = server.pop_outbound_datagrams();
    let deadline = client.next_timeout().expect("client timer armed");
    client.on_timeout(deadline);
    let again = client.pop_outbound_datagrams();
    let fin = again.last().expect("retransmitted flight");
    assert_eq!(fin[0], TLS12_CID_CONTENT_TYPE);
    assert_eq!(peek_connection_id(fin, 6), Some(&SERVER_CID[..]));
    for dg in &again {
        server.feed_datagram(dg).unwrap();
    }
    // The server re-sends its final flight (RFC 6347 §4.2.4), Finished
    // under the client's CID, and the client completes.
    let resent = server.pop_outbound_datagrams();
    let fin = resent.last().expect("re-sent final flight");
    assert_eq!(peek_connection_id(fin, 4), Some(&CLIENT_CID[..]));
    for dg in &resent {
        client.feed_datagram(dg).unwrap();
    }
    assert!(client.is_handshake_complete());
}

// ---------------------------------------------------------------------
// DTLS 1.3
// ---------------------------------------------------------------------

fn pair13(
    client_cid: Option<&[u8]>,
    server_cid: Option<&[u8]>,
) -> (DtlsClientConnection13, DtlsServerConnection13<Rng>) {
    let (key, cert) = server_identity();
    let mut sc =
        ServerConfig13Internal::with_ecdsa(alloc::vec![cert.clone()], key).with_no_cookie();
    sc.connection_id = server_cid.map(<[u8]>::to_vec);
    let server = DtlsServerConnection13::new(Arc::new(sc), b"addr".to_vec(), rng(b"srv13"));
    let mut cc = ClientConfig13Internal::new(roots_for(&cert), "dtls.example")
        .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
    cc.connection_id = client_cid.map(<[u8]>::to_vec);
    let client = DtlsClientConnection13::new(cc, b"addr".to_vec(), &mut rng(b"cli13"));
    (client, server)
}

/// One exchange of everything queued on both sides; `Err` from either
/// engine is returned.
fn exchange13(
    client: &mut DtlsClientConnection13,
    server: &mut DtlsServerConnection13<Rng>,
) -> Result<bool, Error> {
    let c = client.pop_outbound_datagrams();
    for dg in &c {
        server.feed_datagram(dg)?;
    }
    let s = server.pop_outbound_datagrams();
    for dg in &s {
        client.feed_datagram(dg)?;
    }
    Ok(!(c.is_empty() && s.is_empty()))
}

fn pump13(client: &mut DtlsClientConnection13, server: &mut DtlsServerConnection13<Rng>) -> bool {
    for _ in 0..32 {
        if !exchange13(client, server).unwrap() {
            break;
        }
    }
    client.is_handshake_complete() && server.is_handshake_complete()
}

/// The C bit and the CID field of the unified header (RFC 9147 §4).
fn unified_cid(dg: &[u8], len: usize) -> Option<&[u8]> {
    assert_eq!(dg[0] & 0b1110_0000, 0b0010_0000, "not a unified header");
    (dg[0] & 0b0001_0000 != 0).then(|| &dg[1..1 + len])
}

/// Both sides receive under their own CID: every protected record —
/// handshake, ACK and application data alike — carries the receiver's
/// CID with the C bit set (RFC 9147 §4, §9.1), and the stateless peek
/// reads it.
#[test]
fn cid_both_directions_13() {
    let (mut client, mut server) = pair13(Some(&CLIENT_CID), Some(&SERVER_CID));
    // The first exchange: ClientHello → server flight. Every protected
    // server record carries the client's CID.
    exchange13(&mut client, &mut server).unwrap();
    let flight = client.pop_outbound_datagrams();
    for dg in &flight {
        if dg[0] >= 32 {
            assert_eq!(unified_cid(dg, 6), Some(&SERVER_CID[..]));
            assert_eq!(peek_connection_id(dg, 6), Some(&SERVER_CID[..]));
        }
    }
    for dg in &flight {
        server.feed_datagram(dg).unwrap();
    }
    assert!(pump13(&mut client, &mut server));
    assert_eq!(client.local_connection_id(), Some(&CLIENT_CID[..]));
    assert_eq!(client.peer_connection_id(), Some(&SERVER_CID[..]));
    assert_eq!(server.local_connection_id(), Some(&SERVER_CID[..]));
    assert_eq!(server.peer_connection_id(), Some(&CLIENT_CID[..]));

    client.send(b"ping").unwrap();
    let dg = client.pop_outbound_datagrams().remove(0);
    assert_eq!(unified_cid(&dg, 6), Some(&SERVER_CID[..]));
    server.feed_datagram(&dg).unwrap();
    assert_eq!(server.take_received(), b"ping");
    assert!(server.datagram_allows_peer_address_update());

    server.send(b"pong").unwrap();
    let dg = server.pop_outbound_datagrams().remove(0);
    assert_eq!(peek_connection_id(&dg, 4), Some(&CLIENT_CID[..]));
    client.feed_datagram(&dg).unwrap();
    assert_eq!(client.take_received(), b"pong");
    assert!(client.datagram_allows_peer_address_update());
}

/// A zero-length offer: the server's records carry no CID (C clear) and
/// the client, which receives none, accepts them; the client's records
/// carry the server's CID.
#[test]
fn cid_one_direction_13() {
    let (mut client, mut server) = pair13(Some(&[]), Some(&SERVER_CID));
    assert!(pump13(&mut client, &mut server));
    assert_eq!(client.local_connection_id(), Some(&[][..]));
    assert_eq!(server.peer_connection_id(), Some(&[][..]));
    client.send(b"ping").unwrap();
    let dg = client.pop_outbound_datagrams().remove(0);
    assert_eq!(unified_cid(&dg, 6), Some(&SERVER_CID[..]));
    server.feed_datagram(&dg).unwrap();
    assert_eq!(server.take_received(), b"ping");
    server.send(b"pong").unwrap();
    let dg = server.pop_outbound_datagrams().remove(0);
    assert_eq!(unified_cid(&dg, 0), None);
    client.feed_datagram(&dg).unwrap();
    assert_eq!(client.take_received(), b"pong");
    assert!(!client.datagram_allows_peer_address_update());
}

/// CIDs need both sides (RFC 9146 §3), and without them the records are
/// the plain unified-header form.
#[test]
fn cid_needs_both_sides_13() {
    for (c, s) in [(Some(&CLIENT_CID[..]), None), (None, Some(&SERVER_CID[..]))] {
        let (mut client, mut server) = pair13(c, s);
        assert!(pump13(&mut client, &mut server));
        assert_eq!(client.local_connection_id(), None);
        assert_eq!(server.local_connection_id(), None);
        client.send(b"x").unwrap();
        let dg = client.pop_outbound_datagrams().remove(0);
        assert_eq!(unified_cid(&dg, 0), None);
        server.feed_datagram(&dg).unwrap();
        assert_eq!(server.take_received(), b"x");
    }
}

/// RFC 9147 §4 / §9: a record without a CID once one is expected, one
/// under a CID never issued, and one with the C bit set when no CID was
/// negotiated are all silently dropped before any key is used.
#[test]
fn cid_receive_rules_13() {
    let (mut client, mut server) = pair13(Some(&CLIENT_CID), Some(&SERVER_CID));
    assert!(pump13(&mut client, &mut server));

    // Strip the CID and clear the C bit: a CID-less record.
    client.send(b"data").unwrap();
    let dg = client.pop_outbound_datagrams().remove(0);
    let mut stripped = alloc::vec![dg[0] & !0b0001_0000];
    stripped.extend_from_slice(&dg[7..]);
    server.feed_datagram(&stripped).unwrap();
    assert!(server.take_received().is_empty());
    assert!(!server.datagram_allows_peer_address_update());

    // A CID the server never issued.
    let mut wrong = dg.clone();
    wrong[3] ^= 0x80;
    server.feed_datagram(&wrong).unwrap();
    assert!(server.take_received().is_empty());
    // The genuine one still decrypts afterwards.
    server.feed_datagram(&dg).unwrap();
    assert_eq!(server.take_received(), b"data");
    assert!(server.datagram_allows_peer_address_update());

    // No CID negotiated: the C bit alone gets the record refused.
    let (mut client, mut server) = pair13(None, None);
    assert!(pump13(&mut client, &mut server));
    client.send(b"data").unwrap();
    let mut dg = client.pop_outbound_datagrams().remove(0);
    dg[0] |= 0b0001_0000;
    server.feed_datagram(&dg).unwrap();
    assert!(server.take_received().is_empty());
}

/// RFC 9146 §6 on DTLS 1.3, across a `KeyUpdate`: a reordered older
/// record does not qualify, a record under a newer epoch does whatever
/// its sequence number.
#[test]
fn address_update_conditions_13() {
    let (mut client, mut server) = pair13(Some(&CLIENT_CID), Some(&SERVER_CID));
    assert!(pump13(&mut client, &mut server));
    client.send(b"one").unwrap();
    client.send(b"two").unwrap();
    let dgs = client.pop_outbound_datagrams();
    server.feed_datagram(&dgs[1]).unwrap();
    assert!(server.datagram_allows_peer_address_update());
    server.feed_datagram(&dgs[0]).unwrap();
    assert!(!server.datagram_allows_peer_address_update());
    assert_eq!(server.take_received(), b"twoone");
    // Replay: dropped, does not qualify.
    server.feed_datagram(&dgs[1]).unwrap();
    assert!(!server.datagram_allows_peer_address_update());
    // Rekey: the first record of epoch 4 (seq 0) is newer than epoch 3's.
    client.request_key_update(false).unwrap();
    for _ in 0..8 {
        exchange13(&mut client, &mut server).unwrap();
    }
    assert_eq!(client.write_epoch(), 4);
    client.send(b"four").unwrap();
    let dg = client.pop_outbound_datagrams().remove(0);
    server.feed_datagram(&dg).unwrap();
    assert_eq!(server.take_received(), b"four");
    assert!(server.datagram_allows_peer_address_update());
}

/// RFC 9147 §9: `RequestConnectionId` is answered with a
/// `NewConnectionId(cid_spare)` of fresh CIDs, both messages are
/// acknowledged like any handshake message, the requester switches to a
/// spare and the issuer accepts records under it — while records still
/// arriving under the earlier CID are accepted too.
#[test]
fn request_and_switch_connection_ids_13() {
    let (mut client, mut server) = pair13(Some(&CLIENT_CID), Some(&SERVER_CID));
    assert!(pump13(&mut client, &mut server));
    assert_eq!(client.spare_connection_ids(), 0);
    client.request_connection_ids(2).unwrap();
    // One request at a time.
    assert!(matches!(
        client.request_connection_ids(1),
        Err(Error::InappropriateState)
    ));
    assert!(client.handshake_flight_pending());
    for _ in 0..8 {
        exchange13(&mut client, &mut server).unwrap();
    }
    assert_eq!(client.spare_connection_ids(), 2);
    assert!(!client.handshake_flight_pending());
    assert!(!server.handshake_flight_pending());
    // Answered: a new request is allowed again.
    client.request_connection_ids(1).unwrap();
    for _ in 0..8 {
        exchange13(&mut client, &mut server).unwrap();
    }
    assert_eq!(client.spare_connection_ids(), 3);

    client.use_spare_connection_id().unwrap();
    let new_cid = client.peer_connection_id().unwrap().to_vec();
    assert_eq!(new_cid.len(), SERVER_CID.len());
    assert_ne!(new_cid, SERVER_CID);
    client.send(b"moved").unwrap();
    let dg = client.pop_outbound_datagrams().remove(0);
    assert_eq!(unified_cid(&dg, 6), Some(&new_cid[..]));
    server.feed_datagram(&dg).unwrap();
    assert_eq!(server.take_received(), b"moved");
    assert!(server.datagram_allows_peer_address_update());
    assert_eq!(client.spare_connection_ids(), 2);
    // The server keeps answering under the client's CID (it never
    // switched), and the client still receives.
    server.send(b"ok").unwrap();
    let dg = server.pop_outbound_datagrams().remove(0);
    client.feed_datagram(&dg).unwrap();
    assert_eq!(client.take_received(), b"ok");
    // The server side can request too.
    server.request_connection_ids(1).unwrap();
    for _ in 0..8 {
        exchange13(&mut client, &mut server).unwrap();
    }
    assert_eq!(server.spare_connection_ids(), 1);
    server.use_spare_connection_id().unwrap();
    assert!(matches!(
        server.use_spare_connection_id(),
        Err(Error::InappropriateState)
    ));
    server.send(b"again").unwrap();
    let dg = server.pop_outbound_datagrams().remove(0);
    assert_ne!(unified_cid(&dg, 4), Some(&CLIENT_CID[..]));
    client.feed_datagram(&dg).unwrap();
    assert_eq!(client.take_received(), b"again");
}

/// The pool of issuable CIDs is bounded (`LOCAL_CID_POOL`): a request for
/// more gets what is left, and a later one an empty `NewConnectionId`,
/// which §9 permits ("including no CIDs at all"). The spares kept from
/// the peer are bounded too.
#[test]
fn connection_id_pool_is_bounded_13() {
    let (mut client, mut server) = pair13(Some(&CLIENT_CID), Some(&SERVER_CID));
    assert!(pump13(&mut client, &mut server));
    client.request_connection_ids(255).unwrap();
    for _ in 0..8 {
        exchange13(&mut client, &mut server).unwrap();
    }
    assert_eq!(client.spare_connection_ids(), LOCAL_CID_POOL);
    client.request_connection_ids(1).unwrap();
    for _ in 0..8 {
        exchange13(&mut client, &mut server).unwrap();
    }
    assert_eq!(client.spare_connection_ids(), LOCAL_CID_POOL);
    assert!(!client.handshake_flight_pending());
}

/// RFC 9147 §9 violations are fatal with `unexpected_message`: a
/// `NewConnectionId` from a peer that receives no CID, a
/// `RequestConnectionId` from a peer that sends with none, and either
/// message when CIDs were never negotiated.
#[test]
fn connection_id_message_rules_13() {
    // The server negotiated receiving an empty CID: it may not issue
    // CIDs, and the client, sending with none, may not request any.
    let (mut client, mut server) = pair13(Some(&CLIENT_CID), Some(&[]));
    assert!(pump13(&mut client, &mut server));
    assert!(matches!(
        client.request_connection_ids(1),
        Err(Error::InappropriateState)
    ));
    let body = NewConnectionId {
        cids: alloc::vec![alloc::vec![1, 2, 3]],
        usage: ConnectionIdUsage::Spare,
    }
    .encode_body();
    server.send_handshake_for_test(hs_type::NEW_CONNECTION_ID, &body);
    let dg = server.pop_outbound_datagrams().remove(0);
    assert!(matches!(
        client.feed_datagram(&dg),
        Err(Error::UnexpectedMessage)
    ));
    let (mut client, mut server) = pair13(Some(&CLIENT_CID), Some(&[]));
    assert!(pump13(&mut client, &mut server));
    client.send_handshake_for_test(hs_type::REQUEST_CONNECTION_ID, &[1]);
    let dg = client.pop_outbound_datagrams().remove(0);
    assert!(matches!(
        server.feed_datagram(&dg),
        Err(Error::UnexpectedMessage)
    ));

    // Not negotiated at all.
    let (mut client, mut server) = pair13(None, None);
    assert!(pump13(&mut client, &mut server));
    assert!(matches!(
        server.request_connection_ids(1),
        Err(Error::InappropriateState)
    ));
    client.send_handshake_for_test(hs_type::REQUEST_CONNECTION_ID, &[1]);
    let dg = client.pop_outbound_datagrams().remove(0);
    assert!(matches!(
        server.feed_datagram(&dg),
        Err(Error::UnexpectedMessage)
    ));
    let (mut client, mut server) = pair13(None, None);
    assert!(pump13(&mut client, &mut server));
    server.send_handshake_for_test(hs_type::NEW_CONNECTION_ID, &body);
    let dg = server.pop_outbound_datagrams().remove(0);
    assert!(matches!(
        client.feed_datagram(&dg),
        Err(Error::UnexpectedMessage)
    ));

    // A malformed NewConnectionId from a legitimate issuer.
    let (mut client, mut server) = pair13(Some(&CLIENT_CID), Some(&SERVER_CID));
    assert!(pump13(&mut client, &mut server));
    server.send_handshake_for_test(hs_type::NEW_CONNECTION_ID, &[0, 0, 7]);
    let dg = server.pop_outbound_datagrams().remove(0);
    assert!(matches!(
        client.feed_datagram(&dg),
        Err(Error::IllegalParameter)
    ));
}

/// A peer `NewConnectionId(cid_immediate)` switches this side's send CID
/// at once (RFC 9147 §9: "one of the new CIDs MUST be used immediately
/// for all future records"); the rest are spares.
#[test]
fn immediate_connection_id_switch_13() {
    let (mut client, mut server) = pair13(Some(&CLIENT_CID), Some(&SERVER_CID));
    assert!(pump13(&mut client, &mut server));
    let body = NewConnectionId {
        cids: alloc::vec![alloc::vec![0x11; 6], alloc::vec![0x22; 6]],
        usage: ConnectionIdUsage::Immediate,
    }
    .encode_body();
    server.send_handshake_for_test(hs_type::NEW_CONNECTION_ID, &body);
    let dg = server.pop_outbound_datagrams().remove(0);
    client.feed_datagram(&dg).unwrap();
    assert_eq!(client.peer_connection_id(), Some(&[0x11; 6][..]));
    assert_eq!(client.spare_connection_ids(), 1);
    // The ACK for it already carries the new CID.
    let ack = client.pop_outbound_datagrams().remove(0);
    assert_eq!(unified_cid(&ack, 6), Some(&[0x11; 6][..]));
}

/// Too many `RequestConnectionId` messages end the connection with
/// `too_many_cids_requested` (RFC 9147 §9).
#[test]
fn excessive_connection_id_requests_are_fatal_13() {
    let (mut client, mut server) = pair13(Some(&CLIENT_CID), Some(&SERVER_CID));
    assert!(pump13(&mut client, &mut server));
    for i in 0..=MAX_CID_REQUESTS_RECEIVED {
        client.send_handshake_for_test(hs_type::REQUEST_CONNECTION_ID, &[1]);
        let dg = client.pop_outbound_datagrams().remove(0);
        let r = server.feed_datagram(&dg);
        if i < MAX_CID_REQUESTS_RECEIVED {
            r.unwrap();
            // Whatever the server owes is sent or held; either way the
            // connection lives.
            let _ = server.pop_outbound_datagrams();
        } else {
            assert!(matches!(r, Err(Error::TooManyConnectionIdsRequested)));
        }
    }
}

/// A `NewConnectionId` is retransmitted until acknowledged, and a second
/// request that arrives meanwhile is answered only once the first answer
/// is acknowledged (RFC 9147 §9: one outstanding `NewConnectionId`).
#[test]
fn new_connection_id_waits_for_the_ack_of_the_previous_one_13() {
    let (mut client, mut server) = pair13(Some(&CLIENT_CID), Some(&SERVER_CID));
    assert!(pump13(&mut client, &mut server));
    client.request_connection_ids(1).unwrap();
    let req = client.pop_outbound_datagrams().remove(0);
    server.feed_datagram(&req).unwrap();
    // The server's answer and its ACK of the request are lost.
    let lost = server.pop_outbound_datagrams();
    assert_eq!(lost.len(), 2, "NewConnectionId + ACK");
    assert!(server.handshake_flight_pending());
    // A second request from the client (over a test helper, since the
    // engine refuses one while the first is unanswered) is queued.
    client.send_handshake_for_test(hs_type::REQUEST_CONNECTION_ID, &[1]);
    let req2 = client.pop_outbound_datagrams().remove(0);
    server.feed_datagram(&req2).unwrap();
    let out = server.pop_outbound_datagrams();
    // Only the ACK for the second request: no second NewConnectionId
    // while the first is unacknowledged.
    assert_eq!(out.len(), 1, "ACK only");
    // The timer retransmits the first NewConnectionId under a fresh
    // record number; the client ACKs it, and then the second one goes out.
    let deadline = server.next_timeout().expect("timer armed");
    server.on_timeout(deadline);
    for _ in 0..8 {
        exchange13(&mut client, &mut server).unwrap();
    }
    assert_eq!(client.spare_connection_ids(), 2);
    assert!(!server.handshake_flight_pending());
}

/// The client's Finished is retransmitted under the retired handshake
/// write keys *and* the server's CID when its ACK is lost (RFC 9147
/// §4.2.1, §7).
#[test]
fn retransmitted_finished_carries_cid_13() {
    let (mut client, mut server) = pair13(Some(&CLIENT_CID), Some(&SERVER_CID));
    exchange13(&mut client, &mut server).unwrap();
    let flight = client.pop_outbound_datagrams();
    assert!(client.is_handshake_complete());
    // The Finished never arrives; the client retransmits on its timer.
    let _ = flight;
    let deadline = client.next_timeout().expect("client timer armed");
    client.on_timeout(deadline);
    let again = client.pop_outbound_datagrams();
    assert!(!again.is_empty());
    for dg in &again {
        assert_eq!(unified_cid(dg, 6), Some(&SERVER_CID[..]));
        server.feed_datagram(dg).unwrap();
    }
    assert!(server.is_handshake_complete());
    for _ in 0..8 {
        exchange13(&mut client, &mut server).unwrap();
    }
    assert!(!client.handshake_flight_pending());
}
