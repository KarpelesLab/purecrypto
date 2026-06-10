//! `Streams` — the per-connection map of QUIC streams plus the
//! connection-level flow-control and round-robin scheduler.
//!
//! Responsibilities:
//!
//! * Own the [`BTreeMap<u64, Stream>`] keyed by stream id.
//! * Track the peer's `MAX_STREAMS_bidi` / `MAX_STREAMS_uni` (what the
//!   peer has authorized US to open) and our `self_max_streams_*` (what
//!   we have authorized the peer to open).
//! * Track connection-level flow control (RFC 9000 §4.1): `conn_send_max`
//!   (the peer's MAX_DATA — our outgoing ceiling) and `conn_recv_max`
//!   (the credit we have promised the peer).
//! * Provide [`Streams::pop_frame`] — the packet packer's entry point
//!   that returns the next ready frame (STREAM, RESET_STREAM,
//!   STOP_SENDING, MAX_DATA, MAX_STREAM_DATA, DATA_BLOCKED,
//!   STREAM_DATA_BLOCKED, MAX_STREAMS, STREAMS_BLOCKED).
//! * Drive STREAM frame fragmentation: the packet packer's budget covers
//!   the on-wire bytes of the entire STREAM frame, so we account for the
//!   per-frame header overhead (type byte + varint(id) + varint(offset)
//!   + varint(len)) when deciding the payload slice.
//!
//! The connection-level flow control invariant (RFC 9000 §4.1.2):
//! `conn_send_used` counts NEW bytes only. Retransmissions don't bump
//! it. On the receive side, `conn_recv_used` is the high-water mark of
//! bytes received across all streams (checked against `conn_recv_max`),
//! while fresh credit is anchored on `conn_consumed` — bytes the
//! application has READ (or that were discarded by a stream reset).
//! When `conn_consumed + threshold > conn_recv_max_announced`, we queue
//! a fresh MAX_DATA at `conn_consumed + window`. Anchoring credit on
//! consumption rather than receipt means a peer can never force more
//! than ~one window of unread bytes to sit in `RecvStream::delivered`:
//! if the application stops reading, the announced limits stop growing
//! and the sender blocks.

#![allow(dead_code)]

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::quic::connection::Role;
use crate::quic::frame::{Frame, StreamDir};
use crate::quic::stream::{SendState, Stream, StreamId};
use crate::quic::transport_params::TransportParameters;
use crate::quic::varint;
use crate::tls::Error;

/// Conservative MAX_*-credit replenishment threshold (RFC 9000 §4.5).
/// When `used + window/4 > announced`, we bump the announced limit by a
/// fresh window. The threshold is the QUIC implementation's choice; we
/// pick "consume 1/2 of the window" so we don't flood the peer with
/// MAX_STREAM_DATA frames during slow-start.
const REPLENISH_RATIO_NUM: u64 = 1;
const REPLENISH_RATIO_DEN: u64 = 2;

/// Frame produced by [`Streams::pop_frame`]. Owned so the packet packer
/// can serialize it without juggling lifetimes against the borrow on
/// the [`Streams`] map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PoppedFrame {
    /// STREAM frame (RFC 9000 §19.8). The encoded form sets OFF iff
    /// `offset != 0` and LEN always (length-prefixed; the connection
    /// packer never needs the implicit-length form because we know the
    /// budget up front).
    Stream {
        /// Stream identifier.
        id: u64,
        /// Stream offset.
        offset: u64,
        /// Stream data.
        data: Vec<u8>,
        /// FIN bit.
        fin: bool,
    },
    /// RESET_STREAM (§19.4).
    ResetStream {
        /// Stream identifier.
        id: u64,
        /// Application error code.
        code: u64,
        /// Final size.
        final_size: u64,
    },
    /// STOP_SENDING (§19.5).
    StopSending {
        /// Stream identifier.
        id: u64,
        /// Application error code.
        code: u64,
    },
    /// MAX_DATA (§19.9).
    MaxData(u64),
    /// MAX_STREAM_DATA (§19.10).
    MaxStreamData {
        /// Stream identifier.
        id: u64,
        /// New limit.
        limit: u64,
    },
    /// DATA_BLOCKED (§19.12).
    DataBlocked(u64),
    /// STREAM_DATA_BLOCKED (§19.13).
    StreamDataBlocked {
        /// Stream identifier.
        id: u64,
        /// Stream-data limit at which we were blocked.
        limit: u64,
    },
    /// MAX_STREAMS (§19.11).
    MaxStreams {
        /// Bidi or uni.
        dir: StreamDir,
        /// New maximum count of streams the peer may open.
        limit: u64,
    },
    /// STREAMS_BLOCKED (§19.14).
    StreamsBlocked {
        /// Bidi or uni.
        dir: StreamDir,
        /// Stream count at which we were blocked.
        limit: u64,
    },
}

impl PoppedFrame {
    /// Serialize this frame into `out`. Mirrors `Frame::encode` so the
    /// connection packer doesn't need to construct borrowed `Frame<'a>`
    /// values for owned data.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match self {
            PoppedFrame::Stream {
                id,
                offset,
                data,
                fin,
            } => {
                let frame = Frame::Stream {
                    id: *id,
                    offset: *offset,
                    fin: *fin,
                    data,
                };
                frame.encode(out);
            }
            PoppedFrame::ResetStream {
                id,
                code,
                final_size,
            } => {
                let frame = Frame::ResetStream {
                    id: *id,
                    code: *code,
                    final_size: *final_size,
                };
                frame.encode(out);
            }
            PoppedFrame::StopSending { id, code } => {
                let frame = Frame::StopSending {
                    id: *id,
                    code: *code,
                };
                frame.encode(out);
            }
            PoppedFrame::MaxData(v) => {
                Frame::MaxData(*v).encode(out);
            }
            PoppedFrame::MaxStreamData { id, limit } => {
                Frame::MaxStreamData {
                    id: *id,
                    limit: *limit,
                }
                .encode(out);
            }
            PoppedFrame::DataBlocked(v) => {
                Frame::DataBlocked(*v).encode(out);
            }
            PoppedFrame::StreamDataBlocked { id, limit } => {
                Frame::StreamDataBlocked {
                    id: *id,
                    limit: *limit,
                }
                .encode(out);
            }
            PoppedFrame::MaxStreams { dir, limit } => {
                Frame::MaxStreams {
                    dir: *dir,
                    limit: *limit,
                }
                .encode(out);
            }
            PoppedFrame::StreamsBlocked { dir, limit } => {
                Frame::StreamsBlocked {
                    dir: *dir,
                    limit: *limit,
                }
                .encode(out);
            }
        }
    }

    /// Approximate on-wire size of this frame (after encoding). Used by
    /// the packet packer to budget the next frame against the packet's
    /// remaining bytes.
    pub(crate) fn encoded_len(&self) -> usize {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf.len()
    }
}

/// Connection-wide stream state.
pub(crate) struct Streams {
    pub(crate) map: BTreeMap<u64, Stream>,

    /// Maximum number of bidi streams the peer has authorized US to
    /// open. Initialized from peer's `initial_max_streams_bidi`.
    pub(crate) peer_max_bidi: u64,
    /// Maximum number of uni streams the peer has authorized US to open.
    pub(crate) peer_max_uni: u64,

    /// Maximum number of bidi streams WE have authorized the peer to
    /// open. Initialized from our `initial_max_streams_bidi`.
    pub(crate) self_max_bidi: u64,
    /// Maximum number of uni streams WE have authorized the peer to open.
    pub(crate) self_max_uni: u64,
    /// Most-recently-announced `self_max_bidi` (for hysteresis).
    pub(crate) self_max_bidi_announced: u64,
    /// Most-recently-announced `self_max_uni`.
    pub(crate) self_max_uni_announced: u64,
    /// Highest bidi stream the peer has actually opened. Used together
    /// with `self_max_bidi_announced` to decide when to bump
    /// `self_max_bidi` (RFC 9000 §4.6).
    pub(crate) peer_bidi_used: u64,
    /// Highest uni stream the peer has actually opened.
    pub(crate) peer_uni_used: u64,

    /// Next bidi-stream ID this side will assign. Already includes the
    /// initiator + direction bit pattern.
    pub(crate) next_local_bidi: u64,
    /// Next uni-stream ID this side will assign.
    pub(crate) next_local_uni: u64,

    /// Count of bidi streams we have opened so far.
    pub(crate) opened_local_bidi: u64,
    /// Count of uni streams we have opened so far.
    pub(crate) opened_local_uni: u64,

    /// Connection-level send credit ceiling — the peer's MAX_DATA.
    pub(crate) conn_send_max: u64,
    /// Bytes that have ever been counted toward the peer's MAX_DATA
    /// (sum of new bytes carved into STREAM frames). Retransmissions
    /// don't bump this; per RFC 9000 §4.1.2 only new bytes count.
    pub(crate) conn_send_used: u64,
    /// Connection-level receive limit we have promised the peer.
    pub(crate) conn_recv_max: u64,
    /// Last `conn_recv_max` we ANNOUNCED via MAX_DATA. Used for
    /// hysteresis to avoid issuing a MAX_DATA every byte.
    pub(crate) conn_recv_max_announced: u64,
    /// Highest contiguous bytes received across all streams (sum of
    /// per-stream `next_offset` advances).
    pub(crate) conn_recv_used: u64,
    /// Connection-level receive credit window — the `initial_max_data`
    /// WE advertised. Fresh credit is granted as `conn_consumed +
    /// conn_recv_window`.
    pub(crate) conn_recv_window: u64,
    /// Total bytes CONSUMED across all streams: application reads
    /// (per-stream `read_off` advances) plus bytes discarded when a
    /// receive stream is reset. Connection-level credit replenishment
    /// is anchored HERE, not on bytes received, so a slow (or absent)
    /// reader bounds the peer at one window of in-flight data instead
    /// of letting it grow `RecvStream::delivered` without limit.
    pub(crate) conn_consumed: u64,

    /// RFC 9000 §4.1 — per-stream maximum offset *ever observed* on any
    /// inbound STREAM frame. Used to compute the connection-level
    /// flow-control charge for a frame independently of whether the
    /// stream has been admitted into [`Self::map`] yet, and
    /// independently of whether the bytes have become contiguous (which
    /// is what `RecvStream::on_data` tracks).
    ///
    /// Persists across stream close so a late retransmit of an
    /// already-closed stream's tail never re-charges conn-level credit.
    pub(crate) stream_high_offset: BTreeMap<u64, u64>,

    /// True if a DATA_BLOCKED frame at level `conn_send_max` is queued.
    pub(crate) data_blocked_at: Option<u64>,
    /// True if a MAX_DATA frame is queued.
    pub(crate) max_data_pending: bool,
    /// True if STREAMS_BLOCKED(bidi) is queued at `peer_max_bidi`.
    pub(crate) streams_blocked_bidi_at: Option<u64>,
    /// True if STREAMS_BLOCKED(uni) is queued at `peer_max_uni`.
    pub(crate) streams_blocked_uni_at: Option<u64>,
    /// True if MAX_STREAMS(bidi) is queued.
    pub(crate) max_streams_bidi_pending: bool,
    /// True if MAX_STREAMS(uni) is queued.
    pub(crate) max_streams_uni_pending: bool,

    /// Round-robin queue of stream IDs that have outbound STREAM bytes
    /// or RESET_STREAM / STOP_SENDING / MAX_STREAM_DATA /
    /// STREAM_DATA_BLOCKED queued.
    pub(crate) ready_to_send: VecDeque<u64>,
    /// Set tracking which IDs are already in `ready_to_send` to avoid
    /// duplicates.
    pub(crate) ready_set: BTreeSet<u64>,
    /// Streams that have unread bytes — surfaced through
    /// `QuicConnection::readable_streams`.
    pub(crate) readable: BTreeSet<u64>,

    /// Our peer's per-direction stream-data limits, captured at the
    /// start of the connection. Used to initialize new SendStream
    /// `peer_max_data` when the peer opens a bidi stream we hadn't yet
    /// seen (the peer's `initial_max_stream_data_bidi_remote` is what
    /// constrains writes on the recv-initiator's send half). For
    /// streams we initiate, we use `initial_max_stream_data_bidi_remote`
    /// for the bidi case or `initial_max_stream_data_uni` for uni.
    pub(crate) peer_initial_max_stream_data_bidi_local: u64,
    pub(crate) peer_initial_max_stream_data_bidi_remote: u64,
    pub(crate) peer_initial_max_stream_data_uni: u64,

    /// Our advertised per-stream credit. Same conventions as above but
    /// for the receive direction.
    pub(crate) self_initial_max_stream_data_bidi_local: u64,
    pub(crate) self_initial_max_stream_data_bidi_remote: u64,
    pub(crate) self_initial_max_stream_data_uni: u64,

    pub(crate) role: Role,
}

impl Streams {
    /// Fresh state. `our_params` is what THIS side advertised; `peer_params`
    /// is what the peer advertised (captured after the TLS handshake
    /// exposed it).
    pub(crate) fn new(
        role: Role,
        our_params: &TransportParameters,
        peer_params: &TransportParameters,
    ) -> Self {
        let (next_bidi, next_uni) = match role {
            // Client-initiated: low bit = 0; bidi has bit1 = 0, uni bit1 = 1.
            Role::Client => (0u64, 2u64),
            // Server-initiated: low bit = 1.
            Role::Server => (1u64, 3u64),
        };
        Self {
            map: BTreeMap::new(),
            peer_max_bidi: peer_params.initial_max_streams_bidi.unwrap_or(0),
            peer_max_uni: peer_params.initial_max_streams_uni.unwrap_or(0),
            self_max_bidi: our_params.initial_max_streams_bidi.unwrap_or(0),
            self_max_uni: our_params.initial_max_streams_uni.unwrap_or(0),
            self_max_bidi_announced: our_params.initial_max_streams_bidi.unwrap_or(0),
            self_max_uni_announced: our_params.initial_max_streams_uni.unwrap_or(0),
            peer_bidi_used: 0,
            peer_uni_used: 0,
            next_local_bidi: next_bidi,
            next_local_uni: next_uni,
            opened_local_bidi: 0,
            opened_local_uni: 0,
            conn_send_max: peer_params.initial_max_data.unwrap_or(0),
            conn_send_used: 0,
            conn_recv_max: our_params.initial_max_data.unwrap_or(0),
            conn_recv_max_announced: our_params.initial_max_data.unwrap_or(0),
            conn_recv_used: 0,
            conn_recv_window: our_params.initial_max_data.unwrap_or(0),
            conn_consumed: 0,
            stream_high_offset: BTreeMap::new(),
            data_blocked_at: None,
            max_data_pending: false,
            streams_blocked_bidi_at: None,
            streams_blocked_uni_at: None,
            max_streams_bidi_pending: false,
            max_streams_uni_pending: false,
            ready_to_send: VecDeque::new(),
            ready_set: BTreeSet::new(),
            readable: BTreeSet::new(),
            peer_initial_max_stream_data_bidi_local: peer_params
                .initial_max_stream_data_bidi_local
                .unwrap_or(0),
            peer_initial_max_stream_data_bidi_remote: peer_params
                .initial_max_stream_data_bidi_remote
                .unwrap_or(0),
            peer_initial_max_stream_data_uni: peer_params.initial_max_stream_data_uni.unwrap_or(0),
            self_initial_max_stream_data_bidi_local: our_params
                .initial_max_stream_data_bidi_local
                .unwrap_or(0),
            self_initial_max_stream_data_bidi_remote: our_params
                .initial_max_stream_data_bidi_remote
                .unwrap_or(0),
            self_initial_max_stream_data_uni: our_params.initial_max_stream_data_uni.unwrap_or(0),
            role,
        }
    }

    /// Mark `id` as ready to send. No-op if already queued.
    fn enqueue_ready(&mut self, id: u64) {
        if self.ready_set.insert(id) {
            self.ready_to_send.push_back(id);
        }
    }

    /// Update the `readable` set for `id` based on the current recv state.
    fn refresh_readable(&mut self, id: u64) {
        let readable = self
            .map
            .get(&id)
            .and_then(|s| s.recv.as_ref())
            .map(|r| r.is_readable())
            .unwrap_or(false);
        if readable {
            self.readable.insert(id);
        } else {
            self.readable.remove(&id);
        }
    }

    /// Iterator over IDs of streams that have unread bytes.
    pub(crate) fn readable_iter(&self) -> impl Iterator<Item = StreamId> + '_ {
        self.readable.iter().map(|&id| StreamId(id))
    }

    // ====================================================================
    // Outbound side — public API plumbed through QuicConnection.
    // ====================================================================

    /// Opens a new bidirectional stream initiated by this side. Returns
    /// the new `StreamId` or queues a STREAMS_BLOCKED frame and returns
    /// `Err`.
    pub(crate) fn open_bidi(&mut self) -> Result<StreamId, Error> {
        if self.opened_local_bidi >= self.peer_max_bidi {
            self.streams_blocked_bidi_at = Some(self.peer_max_bidi);
            return Err(Error::InappropriateState);
        }
        let id = StreamId(self.next_local_bidi);
        // For bidi streams we open: our send-side credit is the peer's
        // initial_max_stream_data_bidi_remote (the peer's authorization
        // for streams we initiate). Our recv-side credit is the value
        // WE advertised under initial_max_stream_data_bidi_local.
        let peer_max_data = self.peer_initial_max_stream_data_bidi_remote;
        let self_max_data = self.self_initial_max_stream_data_bidi_local;
        self.map
            .insert(id.0, Stream::new_bidi(id, peer_max_data, self_max_data));
        self.next_local_bidi += 4; // step by 4 to preserve the (initiator,dir) bits
        self.opened_local_bidi += 1;
        Ok(id)
    }

    /// Opens a new unidirectional (send-only) stream.
    pub(crate) fn open_uni(&mut self) -> Result<StreamId, Error> {
        if self.opened_local_uni >= self.peer_max_uni {
            self.streams_blocked_uni_at = Some(self.peer_max_uni);
            return Err(Error::InappropriateState);
        }
        let id = StreamId(self.next_local_uni);
        let peer_max_data = self.peer_initial_max_stream_data_uni;
        self.map.insert(id.0, Stream::new_send(id, peer_max_data));
        self.next_local_uni += 4;
        self.opened_local_uni += 1;
        Ok(id)
    }

    /// Queue `data` for transmission. Returns the number of bytes
    /// accepted; the caller may need to retry after a credit
    /// replenishment.
    pub(crate) fn write(&mut self, id: StreamId, data: &[u8]) -> Result<usize, Error> {
        // Verify the stream exists and we are allowed to write to it.
        let stream = self.map.get_mut(&id.0).ok_or(Error::InappropriateState)?;
        let send = stream.send.as_mut().ok_or(Error::InappropriateState)?;
        if !matches!(send.state, SendState::Ready | SendState::Send) {
            return Err(Error::InappropriateState);
        }
        // Connection-level credit.
        let conn_room = self.conn_send_max.saturating_sub(self.conn_send_used);
        let cap = core::cmp::min(conn_room as usize, data.len());
        if cap == 0 {
            // If the per-stream credit is also exhausted, queue a
            // STREAM_DATA_BLOCKED. If the conn credit is exhausted,
            // queue a DATA_BLOCKED.
            if conn_room == 0 {
                self.data_blocked_at = Some(self.conn_send_max);
            }
            if send.available_credit() == 0 {
                send.blocked_at = Some(send.peer_max_data);
                self.enqueue_ready(id.0);
            }
            return Ok(0);
        }
        let stream_take = send.enqueue(&data[..cap]);
        if stream_take == 0 {
            // Per-stream credit exhausted: queue STREAM_DATA_BLOCKED.
            send.blocked_at = Some(send.peer_max_data);
            self.enqueue_ready(id.0);
            return Ok(0);
        }
        // Charge against the connection-level credit at write time, so
        // the next write() observes the correct remaining room. This is
        // mirrored at carve time: the packet packer does NOT charge
        // again for these same bytes. RFC 9000 §4.1.2 only counts new
        // bytes; we count them at the earliest possible moment.
        self.conn_send_used += stream_take as u64;
        // Surface DATA_BLOCKED if conn-level credit was the limiter and
        // we accepted strictly less than `data.len()`.
        if cap < data.len() && conn_room as usize == cap {
            self.data_blocked_at = Some(self.conn_send_max);
        }
        // Surface STREAM_DATA_BLOCKED if the per-stream credit limited.
        if stream_take < cap {
            send.blocked_at = Some(send.peer_max_data);
        }
        self.enqueue_ready(id.0);
        Ok(stream_take)
    }

    /// FIN the send side of `id`.
    pub(crate) fn finish(&mut self, id: StreamId) -> Result<(), Error> {
        let stream = self.map.get_mut(&id.0).ok_or(Error::InappropriateState)?;
        let send = stream.send.as_mut().ok_or(Error::InappropriateState)?;
        if matches!(send.state, SendState::ResetSent | SendState::ResetRecvd) {
            return Err(Error::InappropriateState);
        }
        send.finish();
        self.enqueue_ready(id.0);
        Ok(())
    }

    /// RESET_STREAM on `id` with `app_error`.
    pub(crate) fn reset(&mut self, id: StreamId, app_error: u64) -> Result<(), Error> {
        let stream = self.map.get_mut(&id.0).ok_or(Error::InappropriateState)?;
        let send = stream.send.as_mut().ok_or(Error::InappropriateState)?;
        send.enter_reset(app_error);
        self.enqueue_ready(id.0);
        Ok(())
    }

    /// STOP_SENDING on `id` with `app_error`.
    pub(crate) fn stop_sending(&mut self, id: StreamId, app_error: u64) -> Result<(), Error> {
        let stream = self.map.get_mut(&id.0).ok_or(Error::InappropriateState)?;
        let recv = stream.recv.as_mut().ok_or(Error::InappropriateState)?;
        recv.stop_sending_sent = true;
        recv.reset_code = Some(app_error);
        self.enqueue_ready(id.0);
        Ok(())
    }

    // ====================================================================
    // Inbound side — dispatched from connection's frame handler.
    // ====================================================================

    /// Inbound STREAM frame.
    pub(crate) fn on_stream(
        &mut self,
        id: u64,
        offset: u64,
        fin: bool,
        data: &[u8],
    ) -> Result<(), Error> {
        // RFC 9000 §4.6 — admit the stream (and enforce STREAM_LIMIT)
        // BEFORE charging any connection-level flow-control credit. A
        // peer probing unknown stream IDs above its advertised limit
        // must be rejected with STREAM_LIMIT_ERROR without first
        // mutating `conn_recv_used` / `stream_high_offset` — otherwise
        // the rejected (and now connection-fatal) frame would have left
        // those counters perturbed. This keeps the QUIC-3 audit fix
        // (conn-FC charged against the high-water mark, not contiguous
        // progress) but runs it strictly after stream admission.
        self.ensure_remote_stream_exists(id)?;

        // RFC 9000 §4.1 — connection-level flow control is charged
        // against the highest byte offset *ever observed* on each
        // stream, not against contiguous progress.
        //
        // `new_high = max(0, end - prev_high)` is the count of "newly
        // seen high-water bytes" for this stream. Retransmits of
        // already-seen ranges contribute 0.
        let end = offset.saturating_add(data.len() as u64);
        let prev_high = self.stream_high_offset.get(&id).copied().unwrap_or(0);
        let new_high = end.saturating_sub(prev_high);
        if new_high > 0 {
            // Cap-check FIRST so that a frame that would overflow the
            // peer's MAX_DATA is rejected before we mutate any state.
            let projected = self.conn_recv_used.saturating_add(new_high);
            if projected > self.conn_recv_max {
                // FLOW_CONTROL_ERROR equivalent (RFC 9000 §11.2).
                return Err(Error::Decode);
            }
            self.conn_recv_used = projected;
            self.stream_high_offset.insert(id, end);
        }

        let stream = self.map.get_mut(&id).expect("just-ensured");
        let recv = stream.recv.as_mut().ok_or(Error::InappropriateState)?;
        // We no longer use the contig-progress return value at the
        // connection level — the QUIC-3 fix above already charged
        // conn-level credit against the high-water mark. The per-stream
        // FC check inside `on_data` is still required.
        recv.on_data(offset, data, fin)?;
        // NOTE: no credit replenishment here. Flow-control credit is
        // anchored on CONSUMPTION (application reads / reset discards),
        // not on receipt — see `read` and `maybe_replenish_conn`. If we
        // re-issued credit as fast as data arrived, a peer could grow
        // `RecvStream::delivered` without bound whenever the
        // application reads slower than the network delivers.
        self.refresh_readable(id);
        Ok(())
    }

    /// Connection-level credit replenishment, anchored on
    /// `conn_consumed`. Once the consumed total comes within the
    /// hysteresis threshold of the last announced limit, queue a
    /// MAX_DATA granting `conn_consumed + window`.
    fn maybe_replenish_conn(&mut self) {
        let window = self.conn_recv_window;
        if window == 0 {
            return;
        }
        let threshold = window * REPLENISH_RATIO_NUM / REPLENISH_RATIO_DEN.max(1);
        if self.conn_consumed + threshold > self.conn_recv_max_announced {
            let new_max = self.conn_consumed.saturating_add(window);
            if new_max > self.conn_recv_max {
                self.conn_recv_max = new_max;
                self.max_data_pending = true;
            }
        }
    }

    /// Inbound RESET_STREAM.
    pub(crate) fn on_reset(
        &mut self,
        id: u64,
        app_error: u64,
        final_size: u64,
    ) -> Result<(), Error> {
        self.ensure_remote_stream_exists(id)?;
        let stream = self.map.get_mut(&id).expect("just-ensured");
        let recv = stream.recv.as_mut().ok_or(Error::InappropriateState)?;
        recv.on_reset(app_error, final_size)?;
        self.refresh_readable(id);
        Ok(())
    }

    /// Inbound STOP_SENDING. RFC 9000 §3.5: triggers us to RESET_STREAM
    /// our own send side with the same application error code.
    pub(crate) fn on_stop_sending(&mut self, id: u64, app_error: u64) -> Result<(), Error> {
        let stream = self.map.get_mut(&id).ok_or(Error::InappropriateState)?;
        if let Some(send) = stream.send.as_mut() {
            send.enter_reset(app_error);
            self.enqueue_ready(id);
        }
        Ok(())
    }

    /// Inbound MAX_DATA. Raises `conn_send_max` if higher.
    pub(crate) fn on_max_data(&mut self, limit: u64) {
        if limit > self.conn_send_max {
            self.conn_send_max = limit;
            // Clear any pending DATA_BLOCKED if we're no longer blocked
            // at the old limit.
            if let Some(prev) = self.data_blocked_at
                && limit > prev
            {
                self.data_blocked_at = None;
            }
        }
    }

    /// Inbound MAX_STREAM_DATA.
    pub(crate) fn on_max_stream_data(&mut self, id: u64, limit: u64) -> Result<(), Error> {
        // RFC 9000 §19.10: receiving MAX_STREAM_DATA on a recv-only
        // stream is a STREAM_STATE_ERROR.
        let stream = self.map.get_mut(&id).ok_or(Error::InappropriateState)?;
        let send = stream.send.as_mut().ok_or(Error::InappropriateState)?;
        if limit > send.peer_max_data {
            send.peer_max_data = limit;
            if let Some(prev) = send.blocked_at
                && limit > prev
            {
                send.blocked_at = None;
            }
        }
        Ok(())
    }

    /// Inbound DATA_BLOCKED. If the peer reports being blocked below
    /// the limit we have already granted, the MAX_DATA announcing that
    /// grant was evidently lost — re-queue it. (Credit replenishment
    /// itself is driven by consumption in [`Self::read`]; this is the
    /// loss-recovery path.)
    pub(crate) fn on_data_blocked(&mut self, limit: u64) {
        if self.conn_recv_max > limit {
            self.max_data_pending = true;
        }
    }

    /// Inbound STREAM_DATA_BLOCKED — same recovery as
    /// [`Self::on_data_blocked`], at the stream level.
    pub(crate) fn on_stream_data_blocked(&mut self, id: u64, limit: u64) -> Result<(), Error> {
        if let Some(stream) = self.map.get_mut(&id)
            && let Some(recv) = stream.recv.as_mut()
            && recv.max_data > limit
        {
            recv.max_data_pending = true;
            self.enqueue_ready(id);
        }
        Ok(())
    }

    /// Inbound MAX_STREAMS.
    pub(crate) fn on_max_streams(&mut self, dir: StreamDir, limit: u64) {
        match dir {
            StreamDir::Bidi => {
                if limit > self.peer_max_bidi {
                    self.peer_max_bidi = limit;
                    if let Some(prev) = self.streams_blocked_bidi_at
                        && limit > prev
                    {
                        self.streams_blocked_bidi_at = None;
                    }
                }
            }
            StreamDir::Uni => {
                if limit > self.peer_max_uni {
                    self.peer_max_uni = limit;
                    if let Some(prev) = self.streams_blocked_uni_at
                        && limit > prev
                    {
                        self.streams_blocked_uni_at = None;
                    }
                }
            }
        }
    }

    /// Inbound STREAMS_BLOCKED — informational; we may choose to bump
    /// our MAX_STREAMS.
    pub(crate) fn on_streams_blocked(&mut self, _dir: StreamDir, _limit: u64) {
        // No-op for now.
    }

    /// Application read on `id`. Returns `(bytes_copied, fin_seen)`.
    ///
    /// This is the credit-replenishment point: both the per-stream and
    /// the connection-level windows are re-anchored on the CONSUMED
    /// offsets (`recv.read_off` / `conn_consumed`) here. Data merely
    /// received does not generate credit.
    pub(crate) fn read(&mut self, id: StreamId, into: &mut [u8]) -> Result<(usize, bool), Error> {
        let stream = self.map.get_mut(&id.0).ok_or(Error::InappropriateState)?;
        let recv = stream.recv.as_mut().ok_or(Error::InappropriateState)?;
        let (copied, fin) = recv.read(into);
        // Stream-level replenishment, anchored on the consumed offset.
        let r_window = recv.window;
        if r_window > 0 {
            let r_threshold = r_window * REPLENISH_RATIO_NUM / REPLENISH_RATIO_DEN.max(1);
            if recv.read_off + r_threshold > recv.max_data_announced {
                let new_max = recv.read_off.saturating_add(r_window);
                if new_max > recv.max_data {
                    recv.max_data = new_max;
                    recv.max_data_pending = true;
                    self.enqueue_ready(id.0);
                }
            }
        }
        // Connection-level consumption + replenishment.
        self.conn_consumed = self.conn_consumed.saturating_add(copied as u64);
        self.maybe_replenish_conn();
        self.refresh_readable(id.0);
        Ok((copied, fin))
    }

    // ====================================================================
    // Packet packer hook.
    // ====================================================================

    /// Returns the next ready frame for inclusion in a packet, sized to
    /// fit within `budget` bytes (the packet's remaining payload room).
    /// Returns `None` if nothing fits or nothing is queued.
    ///
    /// Frame priority order:
    ///   1. Connection-level credit / stream-credit replenishment
    ///      (MAX_DATA, MAX_STREAM_DATA) — these unblock the peer.
    ///   2. RESET_STREAM / STOP_SENDING — terminate state machines fast.
    ///   3. MAX_STREAMS — let the peer open more streams.
    ///   4. STREAM data (round-robin across the ready queue).
    ///   5. *_BLOCKED frames — informational.
    pub(crate) fn pop_frame(&mut self, budget: usize) -> Option<PoppedFrame> {
        // 1. MAX_DATA.
        if self.max_data_pending {
            let frame = PoppedFrame::MaxData(self.conn_recv_max);
            if frame.encoded_len() <= budget {
                self.max_data_pending = false;
                self.conn_recv_max_announced = self.conn_recv_max;
                return Some(frame);
            }
        }

        // 2. MAX_STREAMS (bidi / uni).
        if self.max_streams_bidi_pending {
            let frame = PoppedFrame::MaxStreams {
                dir: StreamDir::Bidi,
                limit: self.self_max_bidi,
            };
            if frame.encoded_len() <= budget {
                self.max_streams_bidi_pending = false;
                self.self_max_bidi_announced = self.self_max_bidi;
                return Some(frame);
            }
        }
        if self.max_streams_uni_pending {
            let frame = PoppedFrame::MaxStreams {
                dir: StreamDir::Uni,
                limit: self.self_max_uni,
            };
            if frame.encoded_len() <= budget {
                self.max_streams_uni_pending = false;
                self.self_max_uni_announced = self.self_max_uni;
                return Some(frame);
            }
        }

        // 3. DATA_BLOCKED.
        if let Some(lim) = self.data_blocked_at {
            let frame = PoppedFrame::DataBlocked(lim);
            if frame.encoded_len() <= budget {
                self.data_blocked_at = None;
                return Some(frame);
            }
        }

        // 4. STREAMS_BLOCKED.
        if let Some(lim) = self.streams_blocked_bidi_at {
            let frame = PoppedFrame::StreamsBlocked {
                dir: StreamDir::Bidi,
                limit: lim,
            };
            if frame.encoded_len() <= budget {
                self.streams_blocked_bidi_at = None;
                return Some(frame);
            }
        }
        if let Some(lim) = self.streams_blocked_uni_at {
            let frame = PoppedFrame::StreamsBlocked {
                dir: StreamDir::Uni,
                limit: lim,
            };
            if frame.encoded_len() <= budget {
                self.streams_blocked_uni_at = None;
                return Some(frame);
            }
        }

        // 5. Per-stream urgent frames (RESET_STREAM, STOP_SENDING,
        //    MAX_STREAM_DATA, STREAM_DATA_BLOCKED). We walk the
        //    `ready_to_send` queue round-robin; each iteration emits at
        //    most one frame and re-enqueues the stream if more work
        //    remains.
        let scan_count = self.ready_to_send.len();
        for _ in 0..scan_count {
            let id = match self.ready_to_send.pop_front() {
                Some(id) => id,
                None => break,
            };
            self.ready_set.remove(&id);
            // Take the stream out of the map briefly so we can examine
            // both send + recv halves without aliasing.
            let mut stream = match self.map.remove(&id) {
                Some(s) => s,
                None => continue,
            };
            // First: RESET_STREAM on the send side.
            if let Some(send) = stream.send.as_mut()
                && send.reset_pending
            {
                let frame = PoppedFrame::ResetStream {
                    id,
                    code: send.reset_code.unwrap_or(0),
                    final_size: send.sent_offset,
                };
                if frame.encoded_len() <= budget {
                    send.reset_pending = false;
                    self.map.insert(id, stream);
                    // Stream still has other pending work? Re-queue.
                    let need_requeue = stream_needs_to_send(self.map.get(&id).unwrap());
                    if need_requeue {
                        self.enqueue_ready(id);
                    }
                    return Some(frame);
                } else {
                    self.map.insert(id, stream);
                    self.enqueue_ready(id);
                    continue;
                }
            }
            // STOP_SENDING (recv side has been signaled).
            if let Some(recv) = stream.recv.as_mut()
                && recv.stop_sending_sent
                && recv.reset_code.is_some()
            {
                let code = recv.reset_code.expect("just-checked");
                let frame = PoppedFrame::StopSending { id, code };
                if frame.encoded_len() <= budget {
                    // Clear the trigger so we don't re-emit.
                    recv.reset_code = None;
                    self.map.insert(id, stream);
                    let need_requeue = stream_needs_to_send(self.map.get(&id).unwrap());
                    if need_requeue {
                        self.enqueue_ready(id);
                    }
                    return Some(frame);
                } else {
                    self.map.insert(id, stream);
                    self.enqueue_ready(id);
                    continue;
                }
            }
            // MAX_STREAM_DATA (recv side).
            if let Some(recv) = stream.recv.as_mut()
                && recv.max_data_pending
            {
                let frame = PoppedFrame::MaxStreamData {
                    id,
                    limit: recv.max_data,
                };
                if frame.encoded_len() <= budget {
                    recv.max_data_pending = false;
                    recv.max_data_announced = recv.max_data;
                    self.map.insert(id, stream);
                    let need_requeue = stream_needs_to_send(self.map.get(&id).unwrap());
                    if need_requeue {
                        self.enqueue_ready(id);
                    }
                    return Some(frame);
                } else {
                    self.map.insert(id, stream);
                    self.enqueue_ready(id);
                    continue;
                }
            }
            // STREAM_DATA_BLOCKED (send side).
            if let Some(send) = stream.send.as_mut()
                && let Some(lim) = send.blocked_at
            {
                let frame = PoppedFrame::StreamDataBlocked { id, limit: lim };
                if frame.encoded_len() <= budget {
                    send.blocked_at = None;
                    self.map.insert(id, stream);
                    let need_requeue = stream_needs_to_send(self.map.get(&id).unwrap());
                    if need_requeue {
                        self.enqueue_ready(id);
                    }
                    return Some(frame);
                } else {
                    self.map.insert(id, stream);
                    self.enqueue_ready(id);
                    continue;
                }
            }
            // Retransmissions before fresh data: a queued rtx chunk is
            // (usually) the receiver's contiguity gap, so it unblocks
            // the peer's delivery (and credit consumption) fastest.
            if let Some(send) = stream.send.as_mut()
                && let Some((r_off, r_len)) = send.peek_rtx()
            {
                // Header sized with the FULL chunk length; the emitted
                // length is ≤ that, so its varint is never wider.
                let header_overhead = 1
                    + varint::encoded_len(id)
                    + (if r_off > 0 {
                        varint::encoded_len(r_off)
                    } else {
                        0
                    })
                    + varint::encoded_len(r_len as u64);
                let min_payload = usize::from(r_len > 0);
                if budget >= header_overhead + min_payload {
                    let max_payload = budget - header_overhead;
                    let (off, bytes, fin) = send.pop_rtx(max_payload).expect("just-peeked");
                    self.map.insert(id, stream);
                    if stream_needs_to_send(self.map.get(&id).unwrap()) {
                        self.enqueue_ready(id);
                    }
                    return Some(PoppedFrame::Stream {
                        id,
                        offset: off,
                        data: bytes,
                        fin,
                    });
                } else {
                    self.map.insert(id, stream);
                    self.enqueue_ready(id);
                    continue;
                }
            }
            // Fallback: STREAM frame. Try to carve as much as possible
            // up to the budget AND the conn_send_used credit.
            if let Some(send) = stream.send.as_mut()
                && send.has_outbound()
            {
                // Compute the frame-header overhead so we know how many
                // payload bytes can fit.
                let offset = send.write_off;
                // We pessimistically encode with OFF + LEN bits always
                // (the `Frame::encode` does this; matches what we
                // serialize).
                let header_overhead = 1
                    + varint::encoded_len(id)
                    + (if offset > 0 {
                        varint::encoded_len(offset)
                    } else {
                        0
                    })
                    + varint::encoded_len(send.write_buf.len() as u64);
                if budget < header_overhead + 1 {
                    // Not even one byte of payload fits.
                    self.map.insert(id, stream);
                    self.enqueue_ready(id);
                    continue;
                }
                // conn_send_used is charged at write() time; carve here
                // just respects the packet budget. The per-stream + conn
                // credit limits already capped what we ever accepted
                // into write_buf, so we can carve up to `write_buf.len()`
                // freely (modulo the packet budget).
                let sent_off = send.sent_offset;
                let buf_len = send.write_buf.len();
                let payload_budget = budget.saturating_sub(header_overhead);
                let chunk_size = core::cmp::min(payload_budget, buf_len);
                if chunk_size == 0 {
                    // FIN-only carve possible? Only if finish() was called
                    // and FIN hasn't been emitted yet.
                    if send.fin_offset.is_some() && !send.fin_sent && send.write_buf.is_empty() {
                        // header_overhead recomputed for length=0.
                        let header0 = 1
                            + varint::encoded_len(id)
                            + (if offset > 0 {
                                varint::encoded_len(offset)
                            } else {
                                0
                            })
                            + varint::encoded_len(0);
                        if budget >= header0 {
                            let (off, bytes, fin) = send.carve(0).expect("FIN-only carve");
                            debug_assert!(fin && bytes.is_empty());
                            self.map.insert(id, stream);
                            return Some(PoppedFrame::Stream {
                                id,
                                offset: off,
                                data: bytes,
                                fin,
                            });
                        }
                    }
                    self.map.insert(id, stream);
                    self.enqueue_ready(id);
                    continue;
                }
                let (off, bytes, fin) = send.carve(chunk_size).expect("just-checked");
                // Don't double-charge: conn_send_used was bumped at
                // write() time. (Retransmits also don't re-charge.)
                let _ = sent_off;
                // Re-enqueue if more work remains.
                let need_requeue = send.has_outbound();
                self.map.insert(id, stream);
                if need_requeue {
                    self.enqueue_ready(id);
                }
                return Some(PoppedFrame::Stream {
                    id,
                    offset: off,
                    data: bytes,
                    fin,
                });
            }
            // Nothing more on this stream; drop it from ready set and
            // re-insert.
            self.map.insert(id, stream);
        }
        None
    }

    /// A packet carrying stream chunk `[offset, offset+len)` (with
    /// `fin` per its FIN bit) on stream `id` was acknowledged. Prunes
    /// the sender-side retransmission state for that range.
    pub(crate) fn on_chunk_acked(&mut self, id: u64, offset: u64, len: u64, fin: bool) {
        if let Some(stream) = self.map.get_mut(&id)
            && let Some(send) = stream.send.as_mut()
        {
            send.on_range_acked(offset, len, fin);
        }
    }

    /// A packet carrying stream chunk `[offset, offset+len)` on stream
    /// `id` was declared lost (RFC 9002 §6.1): queue the overlapping
    /// unacked chunks for retransmission.
    pub(crate) fn on_chunk_lost(&mut self, id: u64, offset: u64, len: u64, fin: bool) {
        let moved = if let Some(stream) = self.map.get_mut(&id)
            && let Some(send) = stream.send.as_mut()
        {
            send.on_range_lost(offset, len, fin)
        } else {
            false
        };
        if moved {
            self.enqueue_ready(id);
        }
    }

    /// On PTO: requeue every sent-but-unconfirmed stream chunk so the
    /// next packet build re-emits it. RFC 9002 §6.2.4 says to send a
    /// probe; we retransmit all unacked stream data (chunks whose
    /// ranges have meanwhile been acked are pruned by
    /// `requeue_all_sent`). Duplicates are dropped by the receiver's
    /// reassembly.
    pub(crate) fn on_pto(&mut self) {
        for (&id, stream) in self.map.iter_mut() {
            if let Some(send) = stream.send.as_mut()
                && send.has_unacked()
            {
                send.requeue_all_sent();
                if !self.ready_set.contains(&id) {
                    self.ready_set.insert(id);
                    self.ready_to_send.push_back(id);
                }
            }
        }
    }

    /// True if any frames are ready to send (from `pop_frame`'s POV).
    pub(crate) fn has_pending(&self) -> bool {
        if self.max_data_pending
            || self.max_streams_bidi_pending
            || self.max_streams_uni_pending
            || self.data_blocked_at.is_some()
            || self.streams_blocked_bidi_at.is_some()
            || self.streams_blocked_uni_at.is_some()
        {
            return true;
        }
        !self.ready_to_send.is_empty()
    }

    /// When the connection observes a STREAM frame for stream `id` we
    /// haven't seen before, materialize a recv-only or bidi entry. RFC
    /// 9000 §3.2 — receiving the first STREAM frame implicitly opens the
    /// stream.
    fn ensure_remote_stream_exists(&mut self, id: u64) -> Result<(), Error> {
        if self.map.contains_key(&id) {
            return Ok(());
        }
        let sid = StreamId(id);
        // Streams we initiate can never first appear from the peer.
        // Initiator bit of `id`: 0 → client, 1 → server.
        let peer_initiated = match self.role {
            Role::Client => sid.is_server_initiated(),
            Role::Server => sid.is_client_initiated(),
        };
        if !peer_initiated {
            // Peer is referencing a stream we should have opened — but
            // didn't. Per RFC 9000 §19.8 this is STREAM_STATE_ERROR.
            return Err(Error::Decode);
        }
        // Stream-limit check (RFC 9000 §4.6).
        if sid.is_bidi() {
            // Stream number = (id - 1) / 4 + 1 for server-initiated bidi,
            // or id/4 + 1 for client-initiated bidi. We just compare the
            // count of streams the peer has opened.
            self.peer_bidi_used = self.peer_bidi_used.max((id / 4) + 1);
            if self.peer_bidi_used > self.self_max_bidi {
                return Err(Error::Decode); // STREAM_LIMIT_ERROR
            }
            let peer_max_data = self.peer_initial_max_stream_data_bidi_local;
            let self_max_data = self.self_initial_max_stream_data_bidi_remote;
            self.map
                .insert(id, Stream::new_bidi(sid, peer_max_data, self_max_data));
            // Replenishment for self_max_bidi.
            let window = self.self_max_bidi_announced;
            if window > 0 {
                let threshold = window * REPLENISH_RATIO_NUM / REPLENISH_RATIO_DEN.max(1);
                if self.peer_bidi_used + threshold > self.self_max_bidi_announced {
                    self.self_max_bidi = self
                        .self_max_bidi
                        .saturating_add(window)
                        .max(self.peer_bidi_used + window);
                    self.max_streams_bidi_pending = true;
                }
            }
        } else {
            self.peer_uni_used = self.peer_uni_used.max((id / 4) + 1);
            if self.peer_uni_used > self.self_max_uni {
                return Err(Error::Decode);
            }
            let self_max_data = self.self_initial_max_stream_data_uni;
            self.map.insert(id, Stream::new_recv(sid, self_max_data));
            let window = self.self_max_uni_announced;
            if window > 0 {
                let threshold = window * REPLENISH_RATIO_NUM / REPLENISH_RATIO_DEN.max(1);
                if self.peer_uni_used + threshold > self.self_max_uni_announced {
                    self.self_max_uni = self
                        .self_max_uni
                        .saturating_add(window)
                        .max(self.peer_uni_used + window);
                    self.max_streams_uni_pending = true;
                }
            }
        }
        Ok(())
    }
}

/// True if the stream still has any frame to emit (RESET_STREAM,
/// STOP_SENDING, MAX_STREAM_DATA, STREAM_DATA_BLOCKED, or STREAM data).
fn stream_needs_to_send(stream: &Stream) -> bool {
    if let Some(send) = stream.send.as_ref() {
        if send.reset_pending {
            return true;
        }
        if send.has_outbound() {
            return true;
        }
        if send.blocked_at.is_some() {
            return true;
        }
    }
    if let Some(recv) = stream.recv.as_ref() {
        if recv.max_data_pending {
            return true;
        }
        if recv.stop_sending_sent && recv.reset_code.is_some() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params_with(stream_data: u64, conn_data: u64, max_streams: u64) -> TransportParameters {
        TransportParameters {
            initial_max_data: Some(conn_data),
            initial_max_stream_data_bidi_local: Some(stream_data),
            initial_max_stream_data_bidi_remote: Some(stream_data),
            initial_max_stream_data_uni: Some(stream_data),
            initial_max_streams_bidi: Some(max_streams),
            initial_max_streams_uni: Some(max_streams),
            ..TransportParameters::default()
        }
    }

    #[test]
    fn open_bidi_assigns_proper_id() {
        let our = params_with(64, 1024, 10);
        let peer = params_with(64, 1024, 10);
        let mut s = Streams::new(Role::Client, &our, &peer);
        let id = s.open_bidi().expect("open bidi");
        // Client-initiated bidi → id = 0.
        assert_eq!(id.0, 0);
        let id2 = s.open_bidi().expect("open bidi");
        assert_eq!(id2.0, 4);
    }

    #[test]
    fn open_uni_assigns_proper_id() {
        let our = params_with(64, 1024, 10);
        let peer = params_with(64, 1024, 10);
        let mut s = Streams::new(Role::Client, &our, &peer);
        let id = s.open_uni().expect("open uni");
        assert_eq!(id.0, 2);
    }

    #[test]
    fn flow_control_blocks_writes_at_stream_limit() {
        let our = params_with(1024, 1024 * 1024, 100);
        // Peer's initial_max_stream_data_bidi_remote = 100, which is
        // what limits OUR writes on client-initiated bidi streams.
        let peer = TransportParameters {
            initial_max_data: Some(1 << 20),
            initial_max_stream_data_bidi_local: Some(1024),
            initial_max_stream_data_bidi_remote: Some(100),
            initial_max_stream_data_uni: Some(1024),
            initial_max_streams_bidi: Some(100),
            initial_max_streams_uni: Some(3),
            ..TransportParameters::default()
        };
        let mut s = Streams::new(Role::Client, &our, &peer);
        let id = s.open_bidi().expect("open bidi");
        let accepted = s.write(id, &[0u8; 150]).expect("write");
        assert_eq!(accepted, 100);
        // A STREAM_DATA_BLOCKED should be queued.
        let pop = s.pop_frame(64).expect("pop");
        // The packer may emit the STREAM frame first; loop until we see
        // a STREAM_DATA_BLOCKED or empty.
        let mut saw_blocked = matches!(pop, PoppedFrame::StreamDataBlocked { .. });
        for _ in 0..20 {
            match s.pop_frame(256) {
                None => break,
                Some(f) => {
                    if matches!(f, PoppedFrame::StreamDataBlocked { .. }) {
                        saw_blocked = true;
                    }
                }
            }
        }
        assert!(saw_blocked, "STREAM_DATA_BLOCKED must be queued");
    }

    #[test]
    fn flow_control_blocks_writes_at_conn_limit() {
        let our = params_with(1 << 20, 1024, 100);
        let peer = params_with(1 << 20, 100, 100);
        let mut s = Streams::new(Role::Client, &our, &peer);
        let id1 = s.open_bidi().expect("bidi 1");
        let id2 = s.open_bidi().expect("bidi 2");
        let n1 = s.write(id1, &[0u8; 80]).expect("w1");
        let n2 = s.write(id2, &[0u8; 80]).expect("w2");
        assert!(n1 + n2 <= 100, "conn-level cap: {} + {} <= 100", n1, n2);
    }

    #[test]
    fn reset_clears_buffers_and_blocks_writes() {
        let our = params_with(1024, 1024 * 1024, 100);
        let peer = params_with(1024, 1024 * 1024, 100);
        let mut s = Streams::new(Role::Client, &our, &peer);
        let id = s.open_bidi().expect("open");
        let _ = s.write(id, &[0u8; 200]).unwrap();
        s.reset(id, 42).expect("reset");
        let err = s.write(id, &[0u8; 10]);
        assert!(err.is_err());
        // A RESET_STREAM frame is queued.
        let frame = s.pop_frame(64).expect("pop");
        assert!(matches!(frame, PoppedFrame::ResetStream { code: 42, .. }));
    }

    #[test]
    fn stop_sending_triggers_local_reset() {
        let our = params_with(1024, 1024 * 1024, 100);
        let peer = params_with(1024, 1024 * 1024, 100);
        let mut s = Streams::new(Role::Server, &our, &peer);
        // Client-initiated bidi id=0; the server receives data first.
        s.on_stream(0, 0, false, b"data").unwrap();
        // Now the peer (client) sends STOP_SENDING for id=0; we should
        // RESET_STREAM our send side.
        s.on_stop_sending(0, 7).expect("stop");
        // Pop a frame; we expect a RESET_STREAM.
        let mut saw_reset = false;
        for _ in 0..10 {
            match s.pop_frame(64) {
                None => break,
                Some(PoppedFrame::ResetStream { code: 7, .. }) => {
                    saw_reset = true;
                    break;
                }
                _ => continue,
            }
        }
        assert!(saw_reset, "RESET_STREAM must be queued after STOP_SENDING");
    }

    #[test]
    fn max_streams_exhaustion_emits_streams_blocked() {
        let our = params_with(1024, 1024 * 1024, 100);
        // Peer authorized only 2 bidi streams.
        let peer = TransportParameters {
            initial_max_data: Some(1 << 20),
            initial_max_stream_data_bidi_local: Some(1024),
            initial_max_stream_data_bidi_remote: Some(1024),
            initial_max_stream_data_uni: Some(1024),
            initial_max_streams_bidi: Some(2),
            initial_max_streams_uni: Some(3),
            ..TransportParameters::default()
        };
        let mut s = Streams::new(Role::Client, &our, &peer);
        let _ = s.open_bidi().expect("1");
        let _ = s.open_bidi().expect("2");
        // 3rd open: must fail and queue STREAMS_BLOCKED.
        let err = s.open_bidi();
        assert!(err.is_err());
        let frame = s.pop_frame(64).expect("pop");
        assert!(matches!(
            frame,
            PoppedFrame::StreamsBlocked {
                dir: StreamDir::Bidi,
                limit: 2
            }
        ));
    }

    #[test]
    fn max_data_credit_replenishment() {
        let our = TransportParameters {
            initial_max_data: Some(100),
            initial_max_stream_data_bidi_local: Some(100),
            initial_max_stream_data_bidi_remote: Some(100),
            initial_max_stream_data_uni: Some(100),
            initial_max_streams_bidi: Some(10),
            initial_max_streams_uni: Some(3),
            ..TransportParameters::default()
        };
        let peer = params_with(100, 100, 10);
        let mut s = Streams::new(Role::Server, &our, &peer);
        // Peer (client) opens id=0 and sends 80 bytes.
        s.on_stream(0, 0, false, &[0u8; 80]).expect("recv");
        // The application CONSUMES them — this is what generates fresh
        // credit (receipt alone must not).
        let mut buf = [0u8; 128];
        let (n, _) = s.read(StreamId(0), &mut buf).expect("read");
        assert_eq!(n, 80);
        // We should have queued a MAX_DATA frame.
        let mut saw_max_data = false;
        for _ in 0..5 {
            match s.pop_frame(64) {
                Some(PoppedFrame::MaxData(limit)) => {
                    // Credit is anchored on consumption: 80 consumed +
                    // a 100-byte window.
                    assert_eq!(limit, 180);
                    saw_max_data = true;
                    break;
                }
                Some(_) => continue,
                None => break,
            }
        }
        assert!(saw_max_data, "MAX_DATA must be queued for replenishment");
    }

    /// ISSUE 1 (memory exhaustion) — flow-control credit must be
    /// anchored on bytes CONSUMED, not bytes received. If the
    /// application never reads, the announced limits stop growing and
    /// the sender blocks at ~one window; `RecvStream::delivered` can
    /// never grow without bound.
    #[test]
    fn no_credit_growth_without_consumption() {
        let our = TransportParameters {
            initial_max_data: Some(100),
            initial_max_stream_data_bidi_local: Some(100),
            initial_max_stream_data_bidi_remote: Some(100),
            initial_max_stream_data_uni: Some(100),
            initial_max_streams_bidi: Some(10),
            initial_max_streams_uni: Some(3),
            ..TransportParameters::default()
        };
        let peer = params_with(1 << 20, 1 << 20, 10);
        let mut s = Streams::new(Role::Server, &our, &peer);
        // Peer fills the entire window in small chunks; the app never
        // reads.
        for off in (0..100u64).step_by(20) {
            s.on_stream(0, off, false, &[0u8; 20]).expect("recv");
        }
        // No credit may have been issued or queued.
        assert_eq!(s.conn_recv_max, 100, "conn limit must not grow unread");
        assert!(!s.max_data_pending);
        for _ in 0..10 {
            match s.pop_frame(256) {
                None => break,
                Some(f) => assert!(
                    !matches!(
                        f,
                        PoppedFrame::MaxData(_) | PoppedFrame::MaxStreamData { .. }
                    ),
                    "no credit frame may be emitted without consumption: {f:?}"
                ),
            }
        }
        {
            let recv = s.map.get(&0).unwrap().recv.as_ref().unwrap();
            assert_eq!(recv.max_data, 100, "stream limit must not grow unread");
            assert!(!recv.max_data_pending);
        }
        // The sender is now blocked: one more byte overflows both the
        // stream and the connection limit.
        assert!(
            s.on_stream(0, 100, false, &[0u8; 1]).is_err(),
            "window-overflowing byte must be rejected"
        );
        // Once the application reads, credit replenishes — anchored on
        // the consumed offset.
        let mut buf = [0u8; 100];
        let (n, _) = s.read(StreamId(0), &mut buf).expect("read");
        assert_eq!(n, 100);
        assert!(s.max_data_pending);
        assert_eq!(s.conn_recv_max, 200);
        let recv = s.map.get(&0).unwrap().recv.as_ref().unwrap();
        assert!(recv.max_data_pending);
        assert_eq!(recv.max_data, 200);
    }

    /// Lost-credit recovery: a DATA_BLOCKED / STREAM_DATA_BLOCKED at a
    /// limit below what we already granted re-queues the (evidently
    /// lost) MAX_DATA / MAX_STREAM_DATA announcement.
    #[test]
    fn blocked_frames_requeue_lost_credit() {
        let our = params_with(100, 100, 10);
        let peer = params_with(1 << 20, 1 << 20, 10);
        let mut s = Streams::new(Role::Server, &our, &peer);
        s.on_stream(0, 0, false, &[0u8; 100]).expect("recv");
        let mut buf = [0u8; 100];
        let _ = s.read(StreamId(0), &mut buf).expect("read");
        // Drain the queued credit frames (pretend they were sent —
        // and then lost on the wire).
        while s.pop_frame(256).is_some() {}
        assert!(!s.max_data_pending);
        // The peer reports being blocked at the OLD limits.
        s.on_data_blocked(100);
        assert!(s.max_data_pending, "lost MAX_DATA must be re-queued");
        s.on_stream_data_blocked(0, 100).expect("sdb");
        let recv = s.map.get(&0).unwrap().recv.as_ref().unwrap();
        assert!(
            recv.max_data_pending,
            "lost MAX_STREAM_DATA must be re-queued"
        );
        // But a report at the CURRENT limit re-queues nothing.
        while s.pop_frame(256).is_some() {}
        s.on_data_blocked(s.conn_recv_max);
        assert!(!s.max_data_pending);
    }

    // QUIC-3 — RFC 9000 §4.1: conn-level FC must be charged on receipt
    // of every STREAM frame's high-water-mark advance, regardless of
    // whether the per-stream admission step succeeds.

    /// A STREAM frame for a peer-initiated id that's *within* limits but
    /// whose high-water-mark advances must charge `conn_recv_used`
    /// proportionally to the frame's high-water rather than to the
    /// stream's contiguous progress.
    #[test]
    fn quic3_conn_fc_charges_on_high_offset_not_contig() {
        let our = TransportParameters {
            initial_max_data: Some(1 << 20),
            initial_max_stream_data_bidi_local: Some(1 << 16),
            initial_max_stream_data_bidi_remote: Some(1 << 16),
            initial_max_stream_data_uni: Some(1 << 16),
            initial_max_streams_bidi: Some(10),
            initial_max_streams_uni: Some(3),
            ..TransportParameters::default()
        };
        let peer = params_with(1 << 16, 1 << 20, 10);
        let mut s = Streams::new(Role::Server, &our, &peer);
        // Client-initiated bidi id=0. Send an *out-of-order* fragment
        // [1000, 1100). Contiguous progress is still 0 (the [0, 1000)
        // gap hasn't filled), but conn-level FC must reflect 1100 bytes
        // of high-water reservation.
        s.on_stream(0, 1000, false, &[0u8; 100]).expect("recv");
        assert_eq!(
            s.conn_recv_used, 1100,
            "conn_recv_used must reflect high-water mark"
        );
        assert_eq!(s.stream_high_offset.get(&0).copied(), Some(1100));
    }

    /// A STREAM frame for a stream id that exceeds the negotiated
    /// stream limit (would fail `ensure_remote_stream_exists`) must NOT
    /// have already silently charged conn-level credit. The FC charge
    /// runs first, then admission; if admission fails we propagate
    /// the error but the credit IS charged (so the peer cannot probe
    /// gaps).
    ///
    /// More importantly: a duplicate frame on a never-admitted stream
    /// must not charge twice. We verify the high-water-mark dedup.
    #[test]
    fn quic3_conn_fc_charge_is_idempotent_on_retransmit() {
        let our = TransportParameters {
            initial_max_data: Some(1 << 20),
            initial_max_stream_data_bidi_local: Some(1 << 16),
            initial_max_stream_data_bidi_remote: Some(1 << 16),
            initial_max_stream_data_uni: Some(1 << 16),
            initial_max_streams_bidi: Some(10),
            initial_max_streams_uni: Some(3),
            ..TransportParameters::default()
        };
        let peer = params_with(1 << 16, 1 << 20, 10);
        let mut s = Streams::new(Role::Server, &our, &peer);
        // Two non-overlapping in-order chunks.
        s.on_stream(0, 0, false, &[0u8; 100]).expect("r1");
        s.on_stream(0, 100, false, &[0u8; 50]).expect("r2");
        assert_eq!(s.conn_recv_used, 150);
        // Replay the FIRST chunk. Conn-level credit must not bump.
        let before = s.conn_recv_used;
        s.on_stream(0, 0, false, &[0u8; 100]).expect("replay");
        assert_eq!(s.conn_recv_used, before, "replay must not re-charge");
    }

    /// If a STREAM frame's high-water advance would push
    /// `conn_recv_used` above `conn_recv_max`, the frame must be
    /// rejected with a FLOW_CONTROL_ERROR-mapping `Error::Decode`.
    #[test]
    fn quic3_conn_fc_overflow_rejects_frame() {
        let our = TransportParameters {
            // Connection-level cap of 50 bytes.
            initial_max_data: Some(50),
            initial_max_stream_data_bidi_local: Some(1 << 16),
            initial_max_stream_data_bidi_remote: Some(1 << 16),
            initial_max_stream_data_uni: Some(1 << 16),
            initial_max_streams_bidi: Some(10),
            initial_max_streams_uni: Some(3),
            ..TransportParameters::default()
        };
        let peer = params_with(1 << 16, 1 << 20, 10);
        let mut s = Streams::new(Role::Server, &our, &peer);
        let before = s.conn_recv_used;
        let err = s.on_stream(0, 0, false, &[0u8; 100]);
        assert!(err.is_err(), "must reject frame that overflows MAX_DATA");
        // No partial-state mutation: the high-water map and the credit
        // counter must remain at the pre-frame snapshot.
        assert_eq!(s.conn_recv_used, before);
        assert!(s.stream_high_offset.is_empty());
    }

    /// A STREAM frame on a peer-initiated stream ID that exceeds the
    /// advertised stream limit (STREAM_LIMIT_ERROR) must be rejected
    /// WITHOUT charging connection-level flow-control credit or
    /// recording a high-water mark — admission runs before the FC
    /// charge.
    #[test]
    fn stream_limit_violation_does_not_charge_conn_fc() {
        let our = TransportParameters {
            initial_max_data: Some(1 << 20),
            initial_max_stream_data_bidi_local: Some(1 << 16),
            initial_max_stream_data_bidi_remote: Some(1 << 16),
            initial_max_stream_data_uni: Some(1 << 16),
            // Only ONE client-initiated bidi stream permitted (number 1,
            // i.e. stream id 0). Id 4 is stream number 2 → over limit.
            initial_max_streams_bidi: Some(1),
            initial_max_streams_uni: Some(3),
            ..TransportParameters::default()
        };
        let peer = params_with(1 << 16, 1 << 20, 10);
        let mut s = Streams::new(Role::Server, &our, &peer);
        let before = s.conn_recv_used;
        let err = s.on_stream(4, 0, false, &[0u8; 100]);
        assert!(err.is_err(), "must reject stream over STREAM_LIMIT");
        assert_eq!(s.conn_recv_used, before, "conn FC must not be charged");
        assert!(
            !s.stream_high_offset.contains_key(&4),
            "no high-water for the rejected stream"
        );
    }
}
