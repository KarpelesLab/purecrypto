//! Per-stream state for QUIC bidirectional and unidirectional streams.
//!
//! RFC 9000 §3 defines two independent state machines per stream: a send
//! half (governing outgoing data on this side) and a recv half (governing
//! incoming data on this side). A bidirectional stream owns both halves;
//! a unidirectional stream owns whichever half matches its initiator's
//! direction.
//!
//! This module models:
//!
//! * [`SendState`] / [`RecvState`] — the two state machines.
//! * [`SendStream`] — outbound byte buffer, per-stream flow-control ceiling
//!   (`peer_max_data`), the ack-frontier `acked_offset`, and the FIN/RESET
//!   bookkeeping.
//! * [`RecvStream`] — gap-buffered reassembly mirroring the
//!   [`crate::quic::crypto_buf::CryptoBuf`] pattern, plus per-stream credit
//!   accounting (`max_data` / `max_data_announced`).
//! * [`Stream`] — bundles a [`StreamId`] with optional send + recv halves.
//!
//! The encoding of `StreamId` follows RFC 9000 §2.1: the low two bits
//! select one of four spaces — (initiator ∈ {client, server}) × (direction
//! ∈ {bidi, uni}). Helpers live on the public [`StreamId`] newtype
//! re-exported from `crate::quic`.

#![allow(dead_code)]

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

/// Public stream identifier, RFC 9000 §2.1.
///
/// The 62-bit value has two interpretive bits:
/// * bit 0 (the low bit): 0 = client-initiated, 1 = server-initiated.
/// * bit 1: 0 = bidirectional, 1 = unidirectional.
///
/// Helpers (`is_client_initiated`, `is_uni`, …) expose this without
/// requiring the caller to know the bit layout.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(pub u64);

impl StreamId {
    /// True if the low bit of the ID is 0 (RFC 9000 §2.1).
    pub fn is_client_initiated(self) -> bool {
        self.0 & 0x1 == 0
    }

    /// True if the low bit of the ID is 1.
    pub fn is_server_initiated(self) -> bool {
        self.0 & 0x1 == 1
    }

    /// True if bit 1 is 0 (bidirectional).
    pub fn is_bidi(self) -> bool {
        self.0 & 0x2 == 0
    }

    /// True if bit 1 is 1 (unidirectional).
    pub fn is_uni(self) -> bool {
        self.0 & 0x2 != 0
    }

    /// Returns the inner u64.
    pub fn value(self) -> u64 {
        self.0
    }
}

/// Direction of a stream, kept separate from initiator for ID composition.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum StreamKind {
    Bidi,
    Uni,
}

/// RFC 9000 §3.1 — send-side state machine.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum SendState {
    /// No data sent yet (just created).
    Ready,
    /// At least one byte sent, FIN not yet sent.
    Send,
    /// FIN sent; waiting for all data to be acked.
    DataSent,
    /// All data + FIN acked. Terminal.
    DataRecvd,
    /// We sent a RESET_STREAM. Awaiting ack.
    ResetSent,
    /// Peer acked our reset. Terminal.
    ResetRecvd,
}

/// RFC 9000 §3.2 — recv-side state machine.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum RecvState {
    /// Receiving stream data; FIN not yet observed.
    Recv,
    /// FIN observed but not all bytes received.
    SizeKnown,
    /// All bytes + FIN received; not yet delivered to the application.
    DataRecvd,
    /// All data delivered to the application. Terminal.
    DataRead,
    /// Peer sent RESET_STREAM; reset not yet surfaced to the application.
    ResetRecvd,
    /// Reset surfaced to the application. Terminal.
    ResetRead,
}

/// Send half of one stream.
pub(crate) struct SendStream {
    pub(crate) state: SendState,
    /// Bytes the application has handed us but the packet packer has not
    /// yet carved into a STREAM frame. The front of the deque is offset
    /// `write_off`.
    pub(crate) write_buf: VecDeque<u8>,
    /// Offset of `write_buf[0]` in the absolute stream byte stream. The
    /// packet packer carves chunks starting here and advances `write_off`
    /// accordingly. On loss, we re-prepend the lost chunk and rewind
    /// `write_off`.
    pub(crate) write_off: u64,
    /// Largest stream offset that has been put into any STREAM frame so
    /// far. Increases monotonically with new bytes; retransmissions do
    /// NOT advance it.
    pub(crate) sent_offset: u64,
    /// Largest contiguous offset the peer has acknowledged. Bytes below
    /// this can be discarded; we keep `write_buf` content past
    /// `write_off`, so `acked_offset` is informational here.
    pub(crate) acked_offset: u64,
    /// Once the caller has invoked `finish()`, this records the exact
    /// total length of the stream (i.e. the offset of the byte after the
    /// last byte the application will send).
    pub(crate) fin_offset: Option<u64>,
    /// True once a STREAM frame with the FIN bit has been carved. The
    /// packet packer's carve loop sets this when it emits the FIN.
    pub(crate) fin_sent: bool,
    /// MAX_STREAM_DATA the peer has advertised — the sender's per-stream
    /// flow-control ceiling. Initialized to the peer's
    /// `initial_max_stream_data_*` for this direction.
    pub(crate) peer_max_data: u64,
    /// Application error code, set once `reset()` has been called and
    /// before the RESET_STREAM frame has been queued for transmission.
    pub(crate) reset_code: Option<u64>,
    /// True once we have queued a STREAM_DATA_BLOCKED frame at the
    /// current `peer_max_data`. Cleared when `peer_max_data` rises.
    pub(crate) blocked_at: Option<u64>,
    /// True if a RESET_STREAM frame is queued and not yet emitted.
    pub(crate) reset_pending: bool,
    /// Chunks that have been emitted on the wire and are not yet
    /// confirmed (ack of the carrying packet has not arrived). On PTO
    /// we requeue all entries here; ack-level tracking lands in a
    /// follow-up phase. Each entry is (offset, bytes, fin).
    pub(crate) sent_chunks: VecDeque<(u64, Vec<u8>, bool)>,
}

impl SendStream {
    pub(crate) fn new(peer_max_data: u64) -> Self {
        Self {
            state: SendState::Ready,
            write_buf: VecDeque::new(),
            write_off: 0,
            sent_offset: 0,
            acked_offset: 0,
            fin_offset: None,
            fin_sent: false,
            peer_max_data,
            reset_code: None,
            blocked_at: None,
            reset_pending: false,
            sent_chunks: VecDeque::new(),
        }
    }

    /// True if any STREAM frame bytes (or a FIN-only STREAM frame) are
    /// queued in `write_buf`.
    pub(crate) fn has_outbound(&self) -> bool {
        if !self.write_buf.is_empty() {
            return true;
        }
        // FIN-only STREAM frame: finish() called but the FIN bit hasn't
        // been carved into any frame yet.
        if self.fin_offset.is_some() && !self.fin_sent {
            return true;
        }
        false
    }

    /// Number of bytes the sender has been authorized to put on the wire
    /// at the per-stream level (not yet sent). `peer_max_data` is the
    /// total cumulative authorization; we already sent `sent_offset`
    /// bytes, so we have `peer_max_data - sent_offset` bytes of credit.
    pub(crate) fn available_credit(&self) -> u64 {
        self.peer_max_data.saturating_sub(self.sent_offset)
    }

    /// Push `data` into `write_buf`, returning the number of bytes
    /// accepted. Caller has already trimmed by connection-level credit;
    /// this only enforces the per-stream credit ceiling.
    pub(crate) fn enqueue(&mut self, data: &[u8]) -> usize {
        if self.state != SendState::Ready && self.state != SendState::Send {
            return 0;
        }
        let cap = self.available_credit();
        // `available_credit` is the maximum NEW bytes we may stamp into
        // STREAM frames. write_buf grows freely (caller may have less
        // credit available than data.len()); we accept up to cap.
        let already_buffered = self.write_buf.len() as u64;
        let stream_room = cap.saturating_sub(already_buffered);
        let take = core::cmp::min(stream_room as usize, data.len());
        if take == 0 {
            return 0;
        }
        self.write_buf.extend(data[..take].iter().copied());
        if matches!(self.state, SendState::Ready) {
            self.state = SendState::Send;
        }
        take
    }

    /// Mark FIN. Subsequent enqueue() calls return 0.
    pub(crate) fn finish(&mut self) {
        if self.fin_offset.is_some() {
            return;
        }
        let fin_off = self.write_off + self.write_buf.len() as u64;
        self.fin_offset = Some(fin_off);
    }

    /// Carve up to `cap` bytes from the front of `write_buf` and return
    /// `(offset, bytes, fin)`. Returns `None` if there's nothing to send.
    ///
    /// `fin` is set only if the carve drains every byte AND `finish()`
    /// has been called (so this exact chunk ends at `fin_offset`).
    pub(crate) fn carve(&mut self, cap: usize) -> Option<(u64, Vec<u8>, bool)> {
        if !self.has_outbound() {
            return None;
        }
        let offset = self.write_off;
        let take = core::cmp::min(cap, self.write_buf.len());
        let mut bytes: Vec<u8> = Vec::with_capacity(take);
        for _ in 0..take {
            bytes.push(self.write_buf.pop_front().expect("just-checked"));
        }
        self.write_off += take as u64;
        if self.write_off > self.sent_offset {
            self.sent_offset = self.write_off;
        }
        // Determine FIN: caller has called finish() AND the chunk we
        // just carved ends exactly at the final-byte offset AND we
        // haven't emitted FIN before.
        let fin = matches!(self.fin_offset, Some(fin) if self.write_off == fin && self.write_buf.is_empty())
            && !self.fin_sent;
        if fin {
            self.fin_sent = true;
            self.state = SendState::DataSent;
        } else if matches!(self.state, SendState::Ready) && !bytes.is_empty() {
            self.state = SendState::Send;
        }
        // Record the chunk so PTO can requeue it.
        self.sent_chunks.push_back((offset, bytes.clone(), fin));
        Some((offset, bytes, fin))
    }

    /// Requeue every sent-but-unconfirmed chunk at the front of
    /// `write_buf`. Called on PTO timeout for streams that may have
    /// lost packets. Phase-6 simplification: we don't track per-chunk
    /// acks, so this is best-effort and may re-emit bytes the peer
    /// already received (the receiver's reassembly drops dupes).
    pub(crate) fn requeue_all_sent(&mut self) {
        // Drain sent_chunks in reverse order, prepending each.
        let mut earliest_off = self.write_off;
        let mut any_fin = false;
        let chunks: alloc::vec::Vec<(u64, alloc::vec::Vec<u8>, bool)> =
            self.sent_chunks.drain(..).collect();
        for (off, _bytes, fin) in chunks.iter() {
            if *off < earliest_off {
                earliest_off = *off;
            }
            if *fin {
                any_fin = true;
            }
        }
        // Concatenate all chunks (sorted by offset) into a single
        // contiguous prepend.
        let mut sorted = chunks;
        sorted.sort_by_key(|c| c.0);
        let mut new_buf: VecDeque<u8> = VecDeque::new();
        let mut cur_off = earliest_off;
        for (off, bytes, _fin) in sorted.iter() {
            // Skip any duplicates already covered.
            if off + bytes.len() as u64 <= cur_off {
                continue;
            }
            let skip = cur_off.saturating_sub(*off) as usize;
            if skip < bytes.len() {
                for &b in &bytes[skip..] {
                    new_buf.push_back(b);
                }
                cur_off = off + bytes.len() as u64;
            }
        }
        // Append the (pre-existing) write_buf tail.
        while let Some(b) = self.write_buf.pop_front() {
            new_buf.push_back(b);
        }
        self.write_buf = new_buf;
        self.write_off = earliest_off;
        if any_fin {
            self.fin_sent = false;
        }
    }

    /// True if any chunks are currently unconfirmed.
    pub(crate) fn has_unacked(&self) -> bool {
        !self.sent_chunks.is_empty()
    }

    /// Re-queue a lost chunk at the front of `write_buf` and rewind
    /// `write_off` to its start. The packet packer treats this just like
    /// a fresh carve.
    ///
    /// `was_fin` is `true` if the lost frame had FIN set; in that case
    /// we also rewind `fin_sent` so the next carve re-emits the FIN bit.
    pub(crate) fn requeue(&mut self, offset: u64, bytes: &[u8], was_fin: bool) {
        // Prepend.
        let mut new_buf: VecDeque<u8> = VecDeque::with_capacity(bytes.len() + self.write_buf.len());
        for b in bytes.iter() {
            new_buf.push_back(*b);
        }
        while let Some(b) = self.write_buf.pop_front() {
            new_buf.push_back(b);
        }
        self.write_buf = new_buf;
        self.write_off = offset;
        if was_fin {
            self.fin_sent = false;
        }
        // sent_offset stays at its high-water mark; on retransmits we
        // do NOT advance the connection-level credit counter further.
    }

    /// Drop all buffered bytes (RFC 9000 §3.5 RESET_STREAM): the send
    /// side abandons unsent data, transitions to ResetSent.
    pub(crate) fn enter_reset(&mut self, code: u64) {
        self.write_buf.clear();
        self.reset_code = Some(code);
        self.reset_pending = true;
        self.state = SendState::ResetSent;
    }
}

/// RFC 9000 §4 (QUIC-4 audit finding) — hard cap on the number of
/// out-of-order STREAM fragments we will buffer per receive stream.
/// A peer that gaps + flexes its offsets can otherwise force us to
/// hold an unbounded `BTreeMap` of pending fragments without ever
/// completing a contiguous prefix, since per-stream flow control only
/// constrains *byte count*, not *fragment count*. Once we reach the
/// cap, the next out-of-order insert is rejected and the connection
/// is closed with FLOW_CONTROL_ERROR (Error::Decode maps to that in
/// the current shutdown path).
///
/// Cap value: 128 fragments is generous (typical retransmit /
/// reorder scenarios produce at most a handful of gaps) while still
/// hard-bounding the memory footprint of one stream.
pub(crate) const MAX_PENDING_FRAGMENTS: usize = 128;

/// Receive half of one stream.
pub(crate) struct RecvStream {
    pub(crate) state: RecvState,
    /// Bytes the application can read. Front-of-deque is offset
    /// `next_offset - delivered.len()` (in absolute terms, the offset at
    /// the front is `read_off`).
    pub(crate) delivered: VecDeque<u8>,
    /// Offset of the next byte not yet released by reassembly (i.e.
    /// `next_offset = total bytes ever appended to `delivered`).
    pub(crate) next_offset: u64,
    /// Offset of the next byte that the application has not yet read.
    pub(crate) read_off: u64,
    /// Out-of-order fragments keyed by start offset.
    pub(crate) pending: BTreeMap<u64, Vec<u8>>,
    /// Total stream length once the FIN bit is observed.
    pub(crate) fin_offset: Option<u64>,
    /// Local credit limit — the absolute byte count we have promised to
    /// accept. Initialized to our `initial_max_stream_data_*` for this
    /// direction.
    pub(crate) max_data: u64,
    /// The last `max_data` value we ANNOUNCED to the peer via
    /// MAX_STREAM_DATA. Used for hysteresis.
    pub(crate) max_data_announced: u64,
    /// Application error code surfaced by the peer's RESET_STREAM frame.
    pub(crate) reset_code: Option<u64>,
    /// True if we have sent STOP_SENDING for this stream — subsequent
    /// inbound bytes are dropped.
    pub(crate) stop_sending_sent: bool,
    /// True if a MAX_STREAM_DATA frame is queued for this stream.
    pub(crate) max_data_pending: bool,
}

impl RecvStream {
    pub(crate) fn new(max_data: u64) -> Self {
        Self {
            state: RecvState::Recv,
            delivered: VecDeque::new(),
            next_offset: 0,
            read_off: 0,
            pending: BTreeMap::new(),
            fin_offset: None,
            max_data,
            max_data_announced: max_data,
            reset_code: None,
            stop_sending_sent: false,
            max_data_pending: false,
        }
    }

    /// True if the application has unread bytes or a final reset/FIN
    /// status it has not yet observed.
    pub(crate) fn is_readable(&self) -> bool {
        if !self.delivered.is_empty() {
            return true;
        }
        // FIN seen but no fresh bytes — still "readable" in that
        // read() will return (0, true) to surface the FIN.
        if matches!(self.state, RecvState::DataRecvd | RecvState::ResetRecvd) {
            return true;
        }
        false
    }

    /// Inbound STREAM frame. Returns the number of NEW contiguous-prefix
    /// bytes that just became deliverable (caller uses this to bump the
    /// connection-level `conn_recv_used`).
    ///
    /// Errors:
    /// * `Error::Decode` if the frame would write past `max_data` (RFC
    ///   9000 §4.2 — FLOW_CONTROL_ERROR).
    /// * `Error::Decode` if a FIN's final size disagrees with a previously
    ///   recorded one.
    pub(crate) fn on_data(
        &mut self,
        mut offset: u64,
        mut data: &[u8],
        fin: bool,
    ) -> Result<u64, crate::tls::Error> {
        if matches!(self.state, RecvState::ResetRecvd | RecvState::ResetRead) {
            // Post-reset: drop silently.
            return Ok(0);
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(crate::tls::Error::Decode)?;
        // Flow-control check (RFC 9000 §4.2).
        if end > self.max_data {
            return Err(crate::tls::Error::Decode);
        }
        // G-2: RFC 9000 §4.5 — once the final size is known (a FIN was
        // observed), any STREAM frame whose payload extends at or beyond
        // that final size MUST be treated as FINAL_SIZE_ERROR. This
        // catches non-FIN bytes claiming to live past the FIN, and also
        // a contradictory FIN at a different offset (the explicit
        // `prev != fin_off` branch below would otherwise catch the
        // latter, but only when `fin == true`).
        if let Some(prev_fin) = self.fin_offset {
            // A frame whose extent exceeds the known final size is
            // illegal regardless of whether it carries FIN.
            if end > prev_fin {
                return Err(crate::tls::Error::Decode);
            }
            // A FIN-bearing frame whose end disagrees with the recorded
            // final size is also illegal.
            if fin && end != prev_fin {
                return Err(crate::tls::Error::Decode);
            }
        }
        // FIN final-size consistency (RFC 9000 §4.5, §19.8) — record the
        // final size on the first FIN we see.
        if fin {
            let fin_off = end;
            match self.fin_offset {
                Some(prev) if prev != fin_off => return Err(crate::tls::Error::Decode),
                _ => self.fin_offset = Some(fin_off),
            }
        }
        // If a STOP_SENDING has been sent locally, peer is allowed to
        // keep sending until it processes that; we just discard.
        if self.stop_sending_sent {
            return Ok(0);
        }
        // Trim already-delivered prefix.
        if offset < self.next_offset {
            let skip = (self.next_offset - offset) as usize;
            if skip >= data.len() {
                // Fully duplicate; nothing new. Still might transition
                // to DataRecvd if FIN-only.
                if fin && self.next_offset == end && self.pending.is_empty() {
                    self.state = RecvState::DataRecvd;
                }
                return Ok(0);
            }
            data = &data[skip..];
            offset = self.next_offset;
        }
        let mut newly_contig: u64 = 0;
        if offset == self.next_offset {
            // Fast-path: appends in order.
            self.delivered.extend(data.iter().copied());
            newly_contig += data.len() as u64;
            self.next_offset += data.len() as u64;
            // Absorb pending fragments at or below next_offset.
            while let Some((&p_off, _)) = self.pending.iter().next()
                && p_off <= self.next_offset
            {
                let frag = self.pending.remove(&p_off).expect("just-peeked");
                let p_end = p_off + frag.len() as u64;
                if p_end <= self.next_offset {
                    continue; // fully covered
                }
                let skip = (self.next_offset - p_off) as usize;
                let take = &frag[skip..];
                self.delivered.extend(take.iter().copied());
                newly_contig += take.len() as u64;
                self.next_offset = p_end;
            }
        } else {
            // Out-of-order. Coalesce: if pending already has a covering
            // entry at or before this offset, drop. Otherwise insert.
            let new_end = offset + data.len() as u64;
            let mut should_insert = true;
            if let Some((&prev_off, prev_data)) = self.pending.range(..=offset).next_back() {
                let prev_end = prev_off + prev_data.len() as u64;
                if prev_end >= new_end {
                    should_insert = false;
                }
            }
            if should_insert {
                // If an existing entry at the same offset is shorter,
                // replace it.
                let existing = self.pending.get(&offset).map(|v| v.len()).unwrap_or(0);
                if data.len() > existing {
                    // QUIC-4: bound the per-stream fragment count.
                    // A replacement at the same offset doesn't grow
                    // the map, so it's always allowed; a new key
                    // would only be allowed if we're below the cap.
                    if !self.pending.contains_key(&offset)
                        && self.pending.len() >= MAX_PENDING_FRAGMENTS
                    {
                        // The out-of-order reassembly buffer is full. This is
                        // NOT a protocol violation: it happens legitimately
                        // under heavy loss/reordering when a low-offset gap
                        // stays unfilled while the peer keeps sending (and
                        // PTO-retransmitting) higher-offset fragments — e.g. a
                        // bulk transfer over a link that drops every Nth packet.
                        //
                        // Per-stream flow control (`end <= max_data`, enforced
                        // above) already bounds how far ahead of the contiguous
                        // point the peer can be, so the buffered byte volume is
                        // bounded; this fragment *count* cap is only a secondary
                        // guard against a flood of tiny fragments. The correct,
                        // loss-tolerant response is to drop this fragment rather
                        // than tear the connection down with FLOW_CONTROL_ERROR
                        // (the previous `Err(Decode)`): the sender still holds it
                        // as unacked and will retransmit once the contiguity gap
                        // fills and frees a buffer slot. RFC 9000 §2.2 permits a
                        // receiver to discard out-of-order data it cannot buffer.
                        // `newly_contig` is 0 on this out-of-order path.
                        return Ok(newly_contig);
                    }
                    self.pending.insert(offset, data.to_vec());
                }
            }
        }
        // FIN sets state. SizeKnown if FIN observed but bytes still pending.
        if self.fin_offset.is_some() {
            if Some(self.next_offset) == self.fin_offset && self.pending.is_empty() {
                self.state = RecvState::DataRecvd;
            } else if !matches!(self.state, RecvState::DataRecvd) {
                self.state = RecvState::SizeKnown;
            }
        }
        Ok(newly_contig)
    }

    /// Application read: copies up to `into.len()` bytes from
    /// `delivered`, returns `(bytes_copied, fin_seen)`. `fin_seen` is
    /// true only when all stream bytes have been delivered.
    pub(crate) fn read(&mut self, into: &mut [u8]) -> (usize, bool) {
        let mut copied = 0;
        while copied < into.len() {
            match self.delivered.pop_front() {
                Some(b) => {
                    into[copied] = b;
                    copied += 1;
                }
                None => break,
            }
        }
        self.read_off += copied as u64;
        // FIN-seen: all data delivered AND read out.
        let fin_seen = matches!(self.fin_offset, Some(fin) if self.read_off == fin)
            && matches!(
                self.state,
                RecvState::DataRecvd | RecvState::SizeKnown | RecvState::DataRead
            );
        if fin_seen && self.delivered.is_empty() {
            self.state = RecvState::DataRead;
        }
        (copied, fin_seen)
    }

    /// Inbound RESET_STREAM (RFC 9000 §3.4). Transitions to ResetRecvd
    /// (or stays in a terminal state).
    pub(crate) fn on_reset(&mut self, code: u64, final_size: u64) -> Result<(), crate::tls::Error> {
        // §3.4.1 / §4.5: final_size must be ≥ any previously-observed
        // offset and consistent with a prior FIN. The "previously-
        // observed offset" includes out-of-order pending fragments —
        // the contiguous-prefix `next_offset` alone undercounts when
        // we've buffered a later fragment.
        if final_size < self.next_offset {
            return Err(crate::tls::Error::Decode);
        }
        // G-2: tighten — pending out-of-order fragments may already
        // extend past `next_offset`. RESET_STREAM cannot declare a
        // final size that is below any byte the peer has *already*
        // committed to (RFC 9000 §4.5). Scan all pending entries —
        // overlap suppression is not strict enough to guarantee the
        // last-key entry has the maximal end.
        for (&p_off, p_data) in self.pending.iter() {
            let p_end = p_off + p_data.len() as u64;
            if final_size < p_end {
                return Err(crate::tls::Error::Decode);
            }
        }
        if let Some(fin) = self.fin_offset
            && final_size != fin
        {
            return Err(crate::tls::Error::Decode);
        }
        if matches!(self.state, RecvState::ResetRecvd | RecvState::ResetRead) {
            return Ok(()); // idempotent
        }
        self.pending.clear();
        self.reset_code = Some(code);
        self.fin_offset = Some(final_size);
        self.state = RecvState::ResetRecvd;
        Ok(())
    }

    /// Notes the application has consumed the reset signal.
    pub(crate) fn ack_reset(&mut self) {
        if matches!(self.state, RecvState::ResetRecvd) {
            self.state = RecvState::ResetRead;
        }
    }
}

/// One stream: either send-only, recv-only, or both (bidirectional).
pub(crate) struct Stream {
    pub(crate) id: StreamId,
    pub(crate) send: Option<SendStream>,
    pub(crate) recv: Option<RecvStream>,
}

impl Stream {
    pub(crate) fn new_send(id: StreamId, peer_max_data: u64) -> Self {
        Self {
            id,
            send: Some(SendStream::new(peer_max_data)),
            recv: None,
        }
    }

    pub(crate) fn new_recv(id: StreamId, max_data: u64) -> Self {
        Self {
            id,
            send: None,
            recv: Some(RecvStream::new(max_data)),
        }
    }

    pub(crate) fn new_bidi(id: StreamId, peer_max_data: u64, self_max_data: u64) -> Self {
        Self {
            id,
            send: Some(SendStream::new(peer_max_data)),
            recv: Some(RecvStream::new(self_max_data)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive check of the 4 ID spaces (RFC 9000 §2.1).
    #[test]
    fn stream_id_helpers() {
        // 0: client-initiated, bidirectional.
        let a = StreamId(0);
        assert!(a.is_client_initiated());
        assert!(!a.is_server_initiated());
        assert!(a.is_bidi());
        assert!(!a.is_uni());

        // 1: server-initiated, bidirectional.
        let b = StreamId(1);
        assert!(!b.is_client_initiated());
        assert!(b.is_server_initiated());
        assert!(b.is_bidi());
        assert!(!b.is_uni());

        // 2: client-initiated, unidirectional.
        let c = StreamId(2);
        assert!(c.is_client_initiated());
        assert!(!c.is_server_initiated());
        assert!(!c.is_bidi());
        assert!(c.is_uni());

        // 3: server-initiated, unidirectional.
        let d = StreamId(3);
        assert!(!d.is_client_initiated());
        assert!(d.is_server_initiated());
        assert!(!d.is_bidi());
        assert!(d.is_uni());

        // Sample high-value IDs preserve the bit semantics.
        let e = StreamId(0x4000_0000); // ...0000 in low 2 bits
        assert!(e.is_client_initiated());
        assert!(e.is_bidi());
    }

    /// Ready → Send → DataSent → DataRecvd lifecycle (RFC 9000 §3.1).
    #[test]
    fn send_state_transitions() {
        let mut s = SendStream::new(1024);
        assert_eq!(s.state, SendState::Ready);
        // enqueue some bytes → Send.
        let n = s.enqueue(b"hello");
        assert_eq!(n, 5);
        assert_eq!(s.state, SendState::Send);
        // carve them — still Send (no FIN).
        let (off, bytes, fin) = s.carve(100).expect("carve");
        assert_eq!(off, 0);
        assert_eq!(bytes, b"hello");
        assert!(!fin);
        assert_eq!(s.state, SendState::Send);
        // finish() then carve → DataSent.
        s.finish();
        // FIN-only carve.
        let (off, bytes, fin) = s.carve(100).expect("carve-fin");
        assert_eq!(off, 5);
        assert!(bytes.is_empty());
        assert!(fin);
        assert_eq!(s.state, SendState::DataSent);

        // ResetSent path on a separate stream.
        let mut s2 = SendStream::new(1024);
        let _ = s2.enqueue(b"abc");
        s2.enter_reset(7);
        assert_eq!(s2.state, SendState::ResetSent);
        assert!(s2.write_buf.is_empty());
        assert_eq!(s2.reset_code, Some(7));
    }

    /// Recv → SizeKnown → DataRecvd → DataRead (RFC 9000 §3.2).
    #[test]
    fn recv_state_transitions() {
        let mut r = RecvStream::new(1024);
        assert_eq!(r.state, RecvState::Recv);
        // Receive bytes at offset 0.
        let n = r.on_data(0, b"hello", false).unwrap();
        assert_eq!(n, 5);
        assert_eq!(r.state, RecvState::Recv);
        // Read them.
        let mut buf = [0u8; 16];
        let (got, fin) = r.read(&mut buf);
        assert_eq!(got, 5);
        assert!(!fin);
        assert_eq!(&buf[..got], b"hello");

        // Receive a final fragment with FIN at offset 5..10.
        let n = r.on_data(5, b"world", true).unwrap();
        assert_eq!(n, 5);
        // All bytes received + FIN → DataRecvd.
        assert_eq!(r.state, RecvState::DataRecvd);
        let (got, fin) = r.read(&mut buf);
        assert_eq!(got, 5);
        assert!(fin);
        assert_eq!(r.state, RecvState::DataRead);

        // Reset path.
        let mut r2 = RecvStream::new(1024);
        r2.on_reset(7, 0).unwrap();
        assert_eq!(r2.state, RecvState::ResetRecvd);
        r2.ack_reset();
        assert_eq!(r2.state, RecvState::ResetRead);
    }

    /// Insert fragments at offsets {100, 50, 0, 150}; `delivered` is the
    /// concatenated contiguous prefix.
    #[test]
    fn recv_out_of_order_reassembly() {
        let mut r = RecvStream::new(1024);
        // Offset 100, len 50 — out of order, pending only.
        let n = r.on_data(100, &[b'C'; 50], false).unwrap();
        assert_eq!(n, 0);
        assert!(r.delivered.is_empty());
        // Offset 50, len 50.
        let n = r.on_data(50, &[b'B'; 50], false).unwrap();
        assert_eq!(n, 0);
        // Offset 0, len 50 — now everything in [0..150] becomes contiguous.
        let n = r.on_data(0, &[b'A'; 50], false).unwrap();
        assert_eq!(n, 150);
        assert_eq!(r.next_offset, 150);
        assert!(r.pending.is_empty());

        // Offset 150 fragment with FIN — final.
        let n = r.on_data(150, &[b'D'; 10], true).unwrap();
        assert_eq!(n, 10);
        assert_eq!(r.state, RecvState::DataRecvd);
    }

    /// Re-insert the same fragment twice; assert idempotent (no extra bytes
    /// in `delivered`).
    #[test]
    fn recv_duplicate_dropped() {
        let mut r = RecvStream::new(1024);
        let n1 = r.on_data(0, b"hello", false).unwrap();
        let n2 = r.on_data(0, b"hello", false).unwrap();
        assert_eq!(n1, 5);
        assert_eq!(n2, 0);
        assert_eq!(r.next_offset, 5);
        // Strict subset.
        let n3 = r.on_data(1, b"ell", false).unwrap();
        assert_eq!(n3, 0);
    }

    /// FIN-only-with-gap: receive STREAM with FIN at offset 100, then a
    /// missing fragment at offset 50. State should be SizeKnown until the
    /// gap fills.
    #[test]
    fn fin_only_after_all_data() {
        let mut r = RecvStream::new(1024);
        // FIN at offset 100 (len 0): claims total = 100, but we haven't
        // received [0..100] yet — gap.
        // Send a fragment [50..100] with FIN.
        let _ = r.on_data(50, &[b'B'; 50], true).unwrap();
        assert_eq!(r.fin_offset, Some(100));
        assert_eq!(r.state, RecvState::SizeKnown);
        // Fill the gap.
        let n = r.on_data(0, &[b'A'; 50], false).unwrap();
        assert_eq!(n, 100);
        assert_eq!(r.state, RecvState::DataRecvd);
    }

    /// Flow-control: writes are capped at peer's stream limit.
    #[test]
    fn send_enqueue_respects_credit() {
        let mut s = SendStream::new(100);
        let n = s.enqueue(&[0u8; 200]);
        assert_eq!(n, 100);
        assert_eq!(s.write_buf.len(), 100);
        // A second write returns 0.
        let n = s.enqueue(&[0u8; 50]);
        assert_eq!(n, 0);
    }

    #[test]
    fn carve_advances_offsets_and_marks_fin() {
        let mut s = SendStream::new(1024);
        let _ = s.enqueue(b"hello world");
        s.finish();
        // First carve takes 5 bytes — not FIN.
        let (off, bytes, fin) = s.carve(5).unwrap();
        assert_eq!(off, 0);
        assert_eq!(bytes, b"hello");
        assert!(!fin);
        assert_eq!(s.sent_offset, 5);
        // Second carve takes the remaining 6 bytes — FIN.
        let (off, bytes, fin) = s.carve(100).unwrap();
        assert_eq!(off, 5);
        assert_eq!(bytes, b" world");
        assert!(fin);
        assert_eq!(s.state, SendState::DataSent);
    }

    #[test]
    fn requeue_rewinds_write_off() {
        let mut s = SendStream::new(1024);
        let _ = s.enqueue(b"hello");
        let (off, bytes, _fin) = s.carve(5).unwrap();
        assert_eq!(off, 0);
        // Append more bytes after a successful carve.
        let _ = s.enqueue(b" world");
        // Requeue the lost chunk.
        s.requeue(off, &bytes, false);
        // Carve everything; we should see "hello world".
        let (off2, bytes2, _fin) = s.carve(100).unwrap();
        assert_eq!(off2, 0);
        assert_eq!(bytes2, b"hello world");
    }

    #[test]
    fn recv_flow_control_overshoot_errors() {
        let mut r = RecvStream::new(50);
        // 51 bytes at offset 0 — overshoots.
        let err = r.on_data(0, &[0u8; 51], false);
        assert!(err.is_err());
        // 50 bytes is fine.
        let ok = r.on_data(0, &[0u8; 50], false);
        assert!(ok.is_ok());
    }

    #[test]
    fn reset_clears_pending_and_state() {
        let mut r = RecvStream::new(1024);
        let _ = r.on_data(100, &[b'X'; 10], false).unwrap();
        r.on_reset(42, 200).unwrap();
        assert!(r.pending.is_empty());
        assert_eq!(r.reset_code, Some(42));
        assert_eq!(r.state, RecvState::ResetRecvd);
    }

    /// G-2: STREAM frame with FIN at offset 0 declares final_size=100.
    /// A subsequent non-FIN frame at offset 150 must error
    /// (FINAL_SIZE_ERROR — RFC 9000 §4.5).
    #[test]
    fn recv_data_past_fin_offset_errors() {
        let mut r = RecvStream::new(1024);
        // FIN frame establishing final_size = 100.
        let n = r.on_data(0, &[b'A'; 100], true).unwrap();
        assert_eq!(n, 100);
        assert_eq!(r.fin_offset, Some(100));
        // Non-FIN frame whose extent (160) exceeds the recorded final
        // size — MUST be rejected.
        let err = r.on_data(150, &[b'B'; 10], false);
        assert!(err.is_err(), "data past fin_offset must error");
        // A FIN frame at the same final size is fine (idempotent).
        let _ = r.on_data(99, &[b'A'; 1], true); // already delivered, idempotent
    }

    /// G-2: FIN at offset 0..100; another FIN at 0..120 is contradictory.
    #[test]
    fn recv_contradictory_fin_errors() {
        let mut r = RecvStream::new(1024);
        let _ = r.on_data(0, &[b'A'; 100], true).unwrap();
        // FIN at a different final size must error.
        let err = r.on_data(0, &[b'A'; 120], true);
        assert!(err.is_err(), "contradictory FIN must error");
    }

    /// G-2: on_reset rejects final_size below the highest pending end.
    #[test]
    fn reset_below_pending_end_errors() {
        let mut r = RecvStream::new(1024);
        // Out-of-order: stash [100..150] pending; next_offset stays 0.
        let _ = r.on_data(100, &[b'C'; 50], false).unwrap();
        // RESET_STREAM declaring final_size=80 — below the 150 we've
        // already committed to via pending.
        let err = r.on_reset(0, 80);
        assert!(err.is_err(), "reset below pending end must error");
        // final_size >= 150 is fine.
        let ok = r.on_reset(0, 200);
        assert!(ok.is_ok());
    }

    // QUIC-4 — RFC 9000 §4: per-stream pending-fragment count must be
    // bounded. A peer that drips out-of-order one-byte fragments at
    // strictly-increasing offsets (with the [0, n) prefix never
    // arriving) would otherwise force unbounded BTreeMap growth.
    //
    // We verify the cap by sending MAX_PENDING_FRAGMENTS non-touching
    // fragments and then asserting that the (MAX+1)th errors out.
    #[test]
    fn recv_pending_fragments_are_bounded() {
        // Allow plenty of byte-level credit so the per-stream FC check
        // doesn't fire first.
        let mut r = RecvStream::new(1u64 << 30);
        // Fragments live at offsets 1, 3, 5, ... (gaps of 1 so they
        // never coalesce). MAX_PENDING_FRAGMENTS such frags fit; the
        // next one must error.
        for i in 0..MAX_PENDING_FRAGMENTS {
            let off = 1 + (i as u64) * 2;
            r.on_data(off, &[0xABu8; 1], false)
                .expect("fragment within cap");
        }
        assert_eq!(r.pending.len(), MAX_PENDING_FRAGMENTS);
        // The next non-touching fragment must error.
        let off = 1 + (MAX_PENDING_FRAGMENTS as u64) * 2;
        let err = r.on_data(off, &[0xABu8; 1], false);
        assert!(err.is_err(), "fragment beyond cap must be rejected");
        // The cap must hold — no silent admission.
        assert_eq!(r.pending.len(), MAX_PENDING_FRAGMENTS);
    }

    /// A replacement insertion at an *existing* offset must NOT count
    /// against the cap (it doesn't grow the map). This is important so
    /// a peer that legitimately resends a longer fragment of an
    /// already-buffered offset isn't penalized.
    #[test]
    fn recv_pending_replacement_does_not_grow_map() {
        let mut r = RecvStream::new(1u64 << 30);
        // Fill the cap.
        for i in 0..MAX_PENDING_FRAGMENTS {
            let off = 1 + (i as u64) * 4;
            r.on_data(off, &[0xCDu8; 1], false).expect("fragment");
        }
        assert_eq!(r.pending.len(), MAX_PENDING_FRAGMENTS);
        // A longer payload at offset 1 (an existing key) must succeed:
        // it's a same-key replacement, not a new entry.
        r.on_data(1, &[0xCDu8; 2], false).expect("replacement");
        assert_eq!(r.pending.len(), MAX_PENDING_FRAGMENTS);
    }
}
