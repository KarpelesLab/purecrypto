//! DTLS connection IDs (RFC 9146; RFC 9147 §9 for DTLS 1.3).
//!
//! A connection ID (CID) is an identifier the *receiver* chooses and the
//! sender copies into the header of every protected record, so a server
//! can route a datagram to its connection without the 4-tuple — which
//! changes when a NAT rebinds or a mobile client moves. Each side names
//! the CID it wants to receive in the `connection_id` extension
//! (RFC 9146 §3): the client in its ClientHello, the server in its
//! ServerHello; a zero-length value means "I will send with your CID but
//! do not need one myself". Both sides therefore send under the CID the
//! *peer* chose and receive under their own.
//!
//! What this module holds, shared by the DTLS 1.2 and 1.3 engines:
//!
//! - the extension codec and the negotiation rules (§3);
//! - the DTLS 1.3 `NewConnectionId` / `RequestConnectionId` post-handshake
//!   messages (RFC 9147 §9) and the bounded bookkeeping around them:
//!   the receive CIDs this side has issued (all of one length, so records
//!   stay parseable), a small pool of spare send CIDs the peer issued, and
//!   the caps that keep a hostile peer from growing either without bound;
//! - the RFC 9146 §6 record-layer half of the peer-address-update rule
//!   ([`CidState::note_authenticated`]);
//! - the stateless [`peek_connection_id`] a server demultiplexes with.
//!
//! CIDs are public: they travel in the clear in every record header, so
//! nothing here is secret-dependent. Their *values* are drawn from the
//! caller's entropy source ([`crate::tls::Config::rng`]) so that they are
//! unguessable by an off-path attacker who wants to inject records that
//! reach a connection's AEAD (they would still fail authentication, but
//! cost the decryption).

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::rng::RngCore;
use crate::tls::Error;
use crate::tls::codec::{
    ExtensionType, RawExtension, ReadCursor, put_u8, with_len_u8, with_len_u16,
};

use super::record::TLS12_CID_CONTENT_TYPE;

/// Longest connection ID this crate will ask to *receive*. RFC 9146 §3
/// allows up to 255 bytes; 20 (QUIC's ceiling, RFC 9000 §17.2) is plenty
/// for routing and keeps the per-record overhead small. CIDs the peer
/// asks us to *send* are accepted at any length up to 255, as §3
/// requires ("implementations MUST still be able to send CIDs of
/// different lengths to other parties").
pub const MAX_LOCAL_CID_LEN: usize = 20;

/// Spare receive CIDs drawn at connection start and handed out through
/// `NewConnectionId` (RFC 9147 §9) — one per `RequestConnectionId`, or on
/// demand. Drawn up front so that a `no_std` engine needs no entropy after
/// construction. Once the pool is spent, requests are answered with an
/// empty `NewConnectionId`, which §9 permits.
pub(crate) const LOCAL_CID_POOL: usize = 8;

/// Spare *send* CIDs kept from the peer's `NewConnectionId(cid_spare)`
/// messages; extra ones are discarded (RFC 9147 §9: "implementations which
/// receive more spare CIDs than they wish to maintain MAY simply discard
/// any extra CIDs"). Each is at most 255 bytes, so a hostile peer can pin
/// at most 2 KiB here.
pub(crate) const MAX_PEER_SPARE_CIDS: usize = 8;

/// `RequestConnectionId` messages accepted from the peer over the life of
/// a connection before it is torn down with `too_many_cids_requested`
/// (RFC 9147 §9). Each request costs a `NewConnectionId` we must send and
/// retransmit until acknowledged; nothing legitimate asks more often than
/// it changes paths.
pub(crate) const MAX_CID_REQUESTS_RECEIVED: u32 = 32;

/// Encodes the `connection_id` extension (RFC 9146 §3): `opaque
/// cid<0..2^8-1>`, the CID this side wants to receive.
pub(crate) fn connection_id_extension(cid: &[u8]) -> RawExtension {
    let mut body = Vec::with_capacity(1 + cid.len());
    with_len_u8(&mut body, |b| b.extend_from_slice(cid));
    (ExtensionType::CONNECTION_ID, body)
}

/// Parses a `connection_id` extension body into the CID the peer wants us
/// to send with (RFC 9146 §3). Any length 0..=255 is legal here: the peer
/// picks what *it* receives.
pub(crate) fn parse_connection_id(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut c = ReadCursor::new(body);
    let cid = c.vec_u8()?.to_vec();
    c.expect_empty()?;
    Ok(cid)
}

/// `ConnectionIdUsage` (RFC 9147 §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionIdUsage {
    /// `cid_immediate(0)`: one of the new CIDs MUST be used for all future
    /// records.
    Immediate,
    /// `cid_spare(1)`: keep them; the current CID may stay in use.
    Spare,
}

/// A `NewConnectionId` message body (RFC 9147 §9):
///
/// ```text
/// struct {
///     ConnectionId cids<0..2^16-1>;   // each an opaque<0..2^8-1>
///     ConnectionIdUsage usage;
/// } NewConnectionId;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewConnectionId {
    pub(crate) cids: Vec<Vec<u8>>,
    pub(crate) usage: ConnectionIdUsage,
}

impl NewConnectionId {
    /// The message body (without the handshake header).
    pub(crate) fn encode_body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        with_len_u16(&mut out, |b| {
            for cid in &self.cids {
                with_len_u8(b, |bb| bb.extend_from_slice(cid));
            }
        });
        put_u8(
            &mut out,
            match self.usage {
                ConnectionIdUsage::Immediate => 0,
                ConnectionIdUsage::Spare => 1,
            },
        );
        out
    }

    /// Decodes a message body. An unknown `usage` is `illegal_parameter`;
    /// so is an empty CID in the list (a zero-length CID cannot identify
    /// anything, and a sender that negotiated receiving none may not send
    /// this message at all, §9) or an `cid_immediate` with nothing to
    /// switch to.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut c = ReadCursor::new(body);
        let list = c.vec_u16()?;
        let usage = match c.u8()? {
            0 => ConnectionIdUsage::Immediate,
            1 => ConnectionIdUsage::Spare,
            _ => return Err(Error::IllegalParameter),
        };
        c.expect_empty()?;
        let mut cids = Vec::new();
        let mut lc = ReadCursor::new(list);
        while !lc.is_empty() {
            let cid = lc.vec_u8()?;
            if cid.is_empty() {
                return Err(Error::IllegalParameter);
            }
            cids.push(cid.to_vec());
        }
        if usage == ConnectionIdUsage::Immediate && cids.is_empty() {
            return Err(Error::IllegalParameter);
        }
        Ok(NewConnectionId { cids, usage })
    }
}

/// A `RequestConnectionId` message body (RFC 9147 §9): `uint8 num_cids`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RequestConnectionId {
    pub(crate) num_cids: u8,
}

impl RequestConnectionId {
    pub(crate) fn encode_body(&self) -> Vec<u8> {
        alloc::vec![self.num_cids]
    }

    pub(crate) fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut c = ReadCursor::new(body);
        let num_cids = c.u8()?;
        c.expect_empty()?;
        Ok(RequestConnectionId { num_cids })
    }
}

/// The record number of the newest authenticated record, for the RFC 9146
/// §6 "newer than the newest datagram received" test: epoch first, then
/// sequence number.
type RecordNumber = (u16, u64);

/// A negotiation outcome: `(local, peer)` — the CID this side receives
/// under and the one it sends with — or `None` when CIDs are not in use.
pub(crate) type Negotiated = Option<(Vec<u8>, Vec<u8>)>;

/// Per-connection connection-ID state, once the extension has been
/// negotiated. Constructed by the engines from the negotiation outcome
/// ([`CidState::negotiated`]); `None` on their side means "no CIDs".
pub(crate) struct CidState {
    /// The CIDs the peer may put in records to us: the one negotiated in
    /// the handshake first, then every one issued since through
    /// `NewConnectionId`. All of `local_len` bytes — the record header does
    /// not say how long the CID is (RFC 9146 §4), so one length per
    /// connection is what keeps the parser total. Once issued, a CID stays
    /// acceptable for the life of the connection: a record under a
    /// retired CID may still be in flight, exactly like one under a
    /// retired epoch, and a CID value is never handed out twice.
    local: Vec<Vec<u8>>,
    /// Spare receive CIDs drawn at construction and not yet issued
    /// ([`LOCAL_CID_POOL`]).
    local_unissued: Vec<Vec<u8>>,
    /// The CID we currently put in records to the peer (possibly empty:
    /// the peer negotiated receiving none).
    peer: Vec<u8>,
    /// Send CIDs the peer issued as spares, in the order provided
    /// (RFC 9147 §9: "endpoints SHOULD use receiver-provided CIDs in the
    /// order they were provided"); bounded by [`MAX_PEER_SPARE_CIDS`].
    peer_spares: VecDeque<Vec<u8>>,
    /// Our `RequestConnectionId` is unanswered (RFC 9147 §9: at most one
    /// outstanding).
    request_pending: bool,
    /// `RequestConnectionId` messages received, against
    /// [`MAX_CID_REQUESTS_RECEIVED`].
    requests_received: u32,
    /// Newest authenticated record so far, whatever its header.
    newest: Option<RecordNumber>,
    /// Set while the datagram being processed has authenticated a record
    /// that carried a CID and was newer than everything before it — the
    /// two record-layer conditions of RFC 9146 §6 for moving the peer's
    /// address to that datagram's source. Reset by
    /// [`CidState::start_datagram`].
    address_update_ok: bool,
}

impl CidState {
    /// The outcome of a negotiation: `local` is the CID this side asked to
    /// receive, `peer` the one the peer asked for, `local_unissued` the pool
    /// of spare receive CIDs from [`draw_cid_pool`] (DTLS 1.3; empty for
    /// DTLS 1.2, which has no `NewConnectionId`).
    pub(crate) fn negotiated(local: Vec<u8>, peer: Vec<u8>, local_unissued: Vec<Vec<u8>>) -> Self {
        debug_assert!(local_unissued.iter().all(|c| c.len() == local.len()));
        CidState {
            local: alloc::vec![local],
            local_unissued,
            peer,
            peer_spares: VecDeque::new(),
            request_pending: false,
            requests_received: 0,
            newest: None,
            address_update_ok: false,
        }
    }

    /// The CID negotiated for records the peer sends us (empty: none).
    pub(crate) fn local(&self) -> &[u8] {
        &self.local[0]
    }

    /// The length every receive CID has (0 when we receive none).
    pub(crate) fn local_len(&self) -> usize {
        self.local[0].len()
    }

    /// The CID we currently send with (empty: the peer receives none).
    pub(crate) fn peer(&self) -> &[u8] {
        &self.peer
    }

    /// Whether `cid` is one of the CIDs the peer may address us by.
    pub(crate) fn accepts(&self, cid: &[u8]) -> bool {
        // Public values: a plain comparison is fine.
        self.local.iter().any(|c| c == cid)
    }

    /// Takes up to `n` unissued receive CIDs out of the pool, recording
    /// them as acceptable from now on (they are about to go out in a
    /// `NewConnectionId`).
    pub(crate) fn issue(&mut self, n: usize) -> Vec<Vec<u8>> {
        let n = n.min(self.local_unissued.len());
        let issued: Vec<Vec<u8>> = self.local_unissued.drain(..n).collect();
        self.local.extend(issued.iter().cloned());
        issued
    }

    /// Applies a peer `NewConnectionId`: `cid_immediate` switches the send
    /// CID to the first one listed and keeps the rest as spares;
    /// `cid_spare` only adds spares. Both are bounded; a spare beyond
    /// [`MAX_PEER_SPARE_CIDS`] is discarded. Clears an outstanding request
    /// of ours: the message is the answer, whatever its usage.
    pub(crate) fn on_new_connection_id(&mut self, msg: NewConnectionId) {
        self.request_pending = false;
        let mut cids = msg.cids.into_iter();
        if msg.usage == ConnectionIdUsage::Immediate
            && let Some(first) = cids.next()
        {
            self.peer = first;
        }
        for cid in cids {
            if self.peer_spares.len() >= MAX_PEER_SPARE_CIDS {
                break;
            }
            self.peer_spares.push_back(cid);
        }
    }

    /// Switches the send CID to the next spare the peer issued. `false`
    /// when there is none.
    pub(crate) fn use_spare(&mut self) -> bool {
        match self.peer_spares.pop_front() {
            Some(cid) => {
                self.peer = cid;
                true
            }
            None => false,
        }
    }

    /// Spare send CIDs on hand.
    pub(crate) fn spare_count(&self) -> usize {
        self.peer_spares.len()
    }

    /// Notes that our `RequestConnectionId` went out; refuses a second one
    /// while the first is unanswered (RFC 9147 §9).
    pub(crate) fn begin_request(&mut self) -> Result<(), Error> {
        if self.request_pending {
            return Err(Error::InappropriateState);
        }
        self.request_pending = true;
        Ok(())
    }

    /// Counts a peer `RequestConnectionId` against
    /// [`MAX_CID_REQUESTS_RECEIVED`].
    pub(crate) fn note_request_received(&mut self) -> Result<(), Error> {
        self.requests_received += 1;
        if self.requests_received > MAX_CID_REQUESTS_RECEIVED {
            return Err(Error::TooManyConnectionIdsRequested);
        }
        Ok(())
    }

    /// Begins a datagram: nothing in it has qualified for an address
    /// update yet.
    pub(crate) fn start_datagram(&mut self) {
        self.address_update_ok = false;
    }

    /// Records an authenticated record's number and whether it carried a
    /// CID, and applies the RFC 9146 §6 rule: only a record that carried a
    /// CID *and* is newer than every record authenticated before it may
    /// move the peer's address (a reordered or replayed record must not
    /// revert or force one).
    pub(crate) fn note_authenticated(&mut self, epoch: u16, seq: u64, with_cid: bool) {
        let rn = (epoch, seq);
        let newer = self.newest.is_none_or(|n| rn > n);
        if newer {
            self.newest = Some(rn);
            if with_cid {
                self.address_update_ok = true;
            }
        }
    }

    /// See [`CidState::note_authenticated`].
    pub(crate) fn address_update_ok(&self) -> bool {
        self.address_update_ok
    }
}

/// Draws the pool of [`LOCAL_CID_POOL`] spare receive CIDs of `len` bytes
/// from `rng`, for [`CidState::negotiated`]. Empty when `len == 0`: a side
/// that receives no CID may not issue any (RFC 9147 §9).
pub(crate) fn draw_cid_pool<R: RngCore>(rng: &mut R, len: usize) -> Vec<Vec<u8>> {
    let mut pool = Vec::new();
    if len > 0 {
        for _ in 0..LOCAL_CID_POOL {
            let mut cid = alloc::vec![0u8; len];
            rng.fill_bytes(&mut cid);
            pool.push(cid);
        }
    }
    pool
}

/// Client-side negotiation (RFC 9146 §3): `offered` is the CID we put in
/// the ClientHello (`None` = extension not offered), `answer` the
/// ServerHello's `connection_id` body. Returns `(local, peer)` when CIDs
/// are in use. A `connection_id` we never offered is `unsupported_extension`
/// (RFC 5246 §7.4.1.4 / RFC 8446 §4.2).
pub(crate) fn negotiate_client(
    offered: Option<&[u8]>,
    answer: Option<&[u8]>,
) -> Result<Negotiated, Error> {
    match (offered, answer) {
        (None, Some(_)) => Err(Error::UnsupportedExtension),
        (Some(local), Some(body)) => Ok(Some((local.to_vec(), parse_connection_id(body)?))),
        (_, None) => Ok(None),
    }
}

/// Server-side negotiation (RFC 9146 §3): `ours` is the CID this server
/// wants to receive (`None` = CIDs not enabled), `offer` the ClientHello's
/// `connection_id` body. Returns `(local, peer)` when CIDs are in use: the
/// server answers only when both sides want the extension.
pub(crate) fn negotiate_server(
    ours: Option<&[u8]>,
    offer: Option<&[u8]>,
) -> Result<Negotiated, Error> {
    match (ours, offer) {
        (Some(local), Some(body)) => Ok(Some((local.to_vec(), parse_connection_id(body)?))),
        _ => Ok(None),
    }
}

/// Reads the connection ID off the front of a DTLS datagram without
/// decrypting anything, so a server can route it to the connection it
/// belongs to when the 4-tuple is no longer a usable key (RFC 9146 §3:
/// "the CID is used to look up the connection").
///
/// `cid_len` is the length of the CIDs this server issues (RFC 9146 §4:
/// the record does not carry the length, so a receiver uses one length —
/// [`crate::tls::ConfigBuilder::connection_id_len`] — for all of its
/// connections). Returns the CID of the first record when it is a
/// DTLS 1.2 `tls12_cid` record (RFC 9146 §4) or a DTLS 1.3 unified-header
/// record with the C bit set (RFC 9147 §4); `None` for a plaintext or
/// CID-less record, a datagram too short to hold the CID, or `cid_len ==
/// 0`. Nothing is authenticated here: the CID is a routing hint, and the
/// connection it names still has to verify the record.
pub fn peek_connection_id(datagram: &[u8], cid_len: usize) -> Option<&[u8]> {
    if cid_len == 0 {
        return None;
    }
    let first = *datagram.first()?;
    if first == TLS12_CID_CONTENT_TYPE {
        // type(1) ‖ version(2) ‖ epoch(2) ‖ sequence_number(6) ‖ cid.
        datagram.get(11..11 + cid_len)
    } else if first & 0b1110_0000 == 0b0010_0000 && first & 0b0001_0000 != 0 {
        datagram.get(1..1 + cid_len)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn rng() -> HmacDrbg<Sha256> {
        HmacDrbg::new(b"cid tests", b"", b"")
    }

    #[test]
    fn extension_roundtrip_and_shape() {
        let (ty, body) = connection_id_extension(&[1, 2, 3]);
        assert_eq!(ty, ExtensionType::CONNECTION_ID);
        assert_eq!(body, [3, 1, 2, 3]);
        assert_eq!(parse_connection_id(&body).unwrap(), [1, 2, 3]);
        // Zero-length: the sender does not want a CID (RFC 9146 §3).
        let (_, empty) = connection_id_extension(&[]);
        assert_eq!(empty, [0]);
        assert!(parse_connection_id(&empty).unwrap().is_empty());
        // Trailing bytes and a truncated list are decode errors.
        assert!(matches!(
            parse_connection_id(&[3, 1, 2, 3, 9]),
            Err(Error::Decode)
        ));
        assert!(matches!(
            parse_connection_id(&[3, 1, 2]),
            Err(Error::Decode)
        ));
        assert!(matches!(parse_connection_id(&[]), Err(Error::Decode)));
    }

    #[test]
    fn new_connection_id_roundtrip_and_rejections() {
        let m = NewConnectionId {
            cids: alloc::vec![alloc::vec![0xaa; 4], alloc::vec![0xbb; 4]],
            usage: ConnectionIdUsage::Spare,
        };
        let body = m.encode_body();
        assert_eq!(
            body,
            [
                0, 10, 4, 0xaa, 0xaa, 0xaa, 0xaa, 4, 0xbb, 0xbb, 0xbb, 0xbb, 1
            ]
        );
        assert_eq!(NewConnectionId::decode(&body).unwrap(), m);
        // Unknown usage.
        assert!(matches!(
            NewConnectionId::decode(&[0, 0, 2]),
            Err(Error::IllegalParameter)
        ));
        // Immediate with no CID to switch to.
        assert!(matches!(
            NewConnectionId::decode(&[0, 0, 0]),
            Err(Error::IllegalParameter)
        ));
        // An empty CID in the list.
        assert!(matches!(
            NewConnectionId::decode(&[0, 1, 0, 1]),
            Err(Error::IllegalParameter)
        ));
        // Truncated list / trailing bytes.
        assert!(matches!(
            NewConnectionId::decode(&[0, 5, 4, 1, 2, 1]),
            Err(Error::Decode)
        ));
        assert!(matches!(
            NewConnectionId::decode(&[0, 0, 1, 7]),
            Err(Error::Decode)
        ));
        // Spare with an empty list is legal (§9: "including no CIDs at all").
        assert!(NewConnectionId::decode(&[0, 0, 1]).unwrap().cids.is_empty());
    }

    #[test]
    fn request_connection_id_roundtrip() {
        let r = RequestConnectionId { num_cids: 3 };
        assert_eq!(r.encode_body(), [3]);
        assert_eq!(RequestConnectionId::decode(&[3]).unwrap(), r);
        assert!(matches!(
            RequestConnectionId::decode(&[]),
            Err(Error::Decode)
        ));
        assert!(matches!(
            RequestConnectionId::decode(&[1, 2]),
            Err(Error::Decode)
        ));
    }

    #[test]
    fn negotiation_rules() {
        // Client: an unsolicited answer is unsupported_extension.
        assert!(matches!(
            negotiate_client(None, Some(&[1, 7])),
            Err(Error::UnsupportedExtension)
        ));
        assert_eq!(negotiate_client(Some(&[1]), None).unwrap(), None);
        assert_eq!(
            negotiate_client(Some(&[1]), Some(&[2, 8, 9])).unwrap(),
            Some((alloc::vec![1], alloc::vec![8, 9]))
        );
        // Server: both sides must want it.
        assert_eq!(negotiate_server(None, Some(&[1, 7])).unwrap(), None);
        assert_eq!(negotiate_server(Some(&[1]), None).unwrap(), None);
        assert_eq!(
            negotiate_server(Some(&[1]), Some(&[0])).unwrap(),
            Some((alloc::vec![1], Vec::new()))
        );
        assert!(matches!(
            negotiate_server(Some(&[1]), Some(&[5, 1])),
            Err(Error::Decode)
        ));
    }

    #[test]
    fn state_pool_spares_and_bounds() {
        let pool = draw_cid_pool(&mut rng(), 4);
        assert_eq!(pool.len(), LOCAL_CID_POOL);
        assert!(pool.iter().all(|c| c.len() == 4));
        let mut s = CidState::negotiated(alloc::vec![1, 2, 3, 4], alloc::vec![9], pool);
        assert_eq!(s.local_len(), 4);
        assert!(s.accepts(&[1, 2, 3, 4]));
        assert!(!s.accepts(&[1, 2, 3]));
        // The pool holds LOCAL_CID_POOL CIDs of the local length, each
        // accepted once issued and never before.
        let issued = s.issue(2);
        assert_eq!(issued.len(), 2);
        assert!(issued.iter().all(|c| c.len() == 4));
        assert!(s.accepts(&issued[1]));
        let rest = s.issue(100);
        assert_eq!(rest.len(), LOCAL_CID_POOL - 2);
        assert!(s.issue(1).is_empty());
        // Peer spares are bounded; extras are discarded.
        let many: Vec<Vec<u8>> = (0..(MAX_PEER_SPARE_CIDS as u8 + 4))
            .map(|i| alloc::vec![i; 3])
            .collect();
        s.on_new_connection_id(NewConnectionId {
            cids: many.clone(),
            usage: ConnectionIdUsage::Spare,
        });
        assert_eq!(s.spare_count(), MAX_PEER_SPARE_CIDS);
        assert_eq!(s.peer(), [9]);
        assert!(s.use_spare());
        assert_eq!(s.peer(), [0, 0, 0]);
        // Immediate: the first CID is used now, the rest are spares.
        s.on_new_connection_id(NewConnectionId {
            cids: alloc::vec![alloc::vec![7, 7], alloc::vec![8, 8]],
            usage: ConnectionIdUsage::Immediate,
        });
        assert_eq!(s.peer(), [7, 7]);
        // One request outstanding at a time.
        assert!(s.begin_request().is_ok());
        assert!(matches!(s.begin_request(), Err(Error::InappropriateState)));
        s.on_new_connection_id(NewConnectionId {
            cids: Vec::new(),
            usage: ConnectionIdUsage::Spare,
        });
        assert!(s.begin_request().is_ok());
        // Requests received are capped.
        for _ in 0..MAX_CID_REQUESTS_RECEIVED {
            s.note_request_received().unwrap();
        }
        assert!(matches!(
            s.note_request_received(),
            Err(Error::TooManyConnectionIdsRequested)
        ));
        // A side receiving no CID has no pool to issue from.
        assert!(draw_cid_pool(&mut rng(), 0).is_empty());
        let mut none = CidState::negotiated(Vec::new(), alloc::vec![1], Vec::new());
        assert!(none.issue(1).is_empty());
    }

    #[test]
    fn address_update_needs_cid_and_newer_record() {
        let mut s = CidState::negotiated(alloc::vec![1], alloc::vec![2], Vec::new());
        s.start_datagram();
        s.note_authenticated(3, 5, true);
        assert!(s.address_update_ok());
        // A reordered (older) record with a CID does not qualify.
        s.start_datagram();
        s.note_authenticated(3, 4, true);
        assert!(!s.address_update_ok());
        // A newer record without a CID does not either, but it moves the
        // high-water mark.
        s.start_datagram();
        s.note_authenticated(3, 9, false);
        assert!(!s.address_update_ok());
        s.start_datagram();
        s.note_authenticated(3, 9, true);
        assert!(!s.address_update_ok());
        // A newer epoch is newer whatever the sequence number.
        s.start_datagram();
        s.note_authenticated(4, 0, true);
        assert!(s.address_update_ok());
    }

    #[test]
    fn peek_reads_both_header_forms() {
        // DTLS 1.2 tls12_cid: type ‖ version ‖ epoch ‖ seq(6) ‖ cid ‖ len.
        let mut d12 = alloc::vec![25, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 7];
        d12.extend_from_slice(&[0xc1, 0xd2, 0xe3]);
        d12.extend_from_slice(&[0, 0]);
        assert_eq!(peek_connection_id(&d12, 3), Some(&[0xc1, 0xd2, 0xe3][..]));
        assert_eq!(peek_connection_id(&d12[..12], 3), None);
        // DTLS 1.3 unified header with C set: flags ‖ cid ‖ seq ‖ …
        let d13 = [0b0011_1101, 0xa1, 0xb2, 0, 1, 0, 0];
        assert_eq!(peek_connection_id(&d13, 2), Some(&[0xa1, 0xb2][..]));
        // C clear, plaintext records, empty input, cid_len 0: nothing.
        assert_eq!(peek_connection_id(&[0b0010_1101, 0, 1], 2), None);
        assert_eq!(peek_connection_id(&[22, 0xfe, 0xfd, 0, 0], 2), None);
        assert_eq!(peek_connection_id(&[], 2), None);
        assert_eq!(peek_connection_id(&d13, 0), None);
    }
}
