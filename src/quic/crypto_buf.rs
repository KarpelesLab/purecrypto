//! Per-level CRYPTO frame reassembly and outbound queue.
//!
//! Each QUIC encryption level has its own CRYPTO byte stream (RFC 9000
//! §19.6): a stream of bytes that carry TLS handshake messages, framed
//! independently of the level's packet framing. CRYPTO frames carry a
//! starting byte offset plus payload bytes; the receiver must reassemble
//! the stream in order even when frames arrive out of order.
//!
//! [`CryptoBuf`] holds:
//! * `next_offset` — how many bytes of the in-order prefix we have
//!   released to the TLS engine so far.
//! * `pending` — out-of-order fragments keyed by their starting offset.
//!   Each value is the byte slice the caller passed in `on_crypto`.
//! * `outbound` — bytes the TLS engine has handed to the QUIC layer at
//!   this level (via `on_handshake_data`) that have not yet been carved
//!   into CRYPTO frames and packed into a packet. The outbound side also
//!   tracks `outbound_offset` — the running byte offset to be stamped on
//!   the next CRYPTO frame, mirroring the TLS-record stream offset on the
//!   sending side. The "last sent" suffix is retained as `last_chunk`
//!   for the Phase-4 PTO retransmit (we just resend the trailing chunk —
//!   full RFC 9002 lands in Phase 5).
//!
//! The reassembly logic is conservative: any byte already covered by
//! `delivered` is silently discarded (duplicate retransmits), and any
//! fragment whose start lies before `next_offset` is trimmed at the
//! boundary.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::tls::Error;

/// Per-level cap on out-of-order CRYPTO frame pending bytes. RFC 9000 §7.5
/// motivates an implementation-defined limit; this value is large enough to
/// accommodate a typical TLS 1.3 server flight (cert chain + CV + Finished
/// often ~20 KiB) while bounded enough to defeat the trivial pre-handshake
/// DoS class.
///
/// Background — pre-handshake CRYPTO-flood DoS: Initial-level AEAD keys
/// are derived from the publicly-visible DCID via the v1 salt (RFC 9001
/// §5.2), so any on-path attacker can synthesize AEAD-valid Initial
/// packets carrying CRYPTO frames at attacker-chosen offsets. Without a
/// cap, those out-of-order fragments accumulate in
/// [`CryptoBuf::pending`] without bound; this cap is what makes
/// [`on_crypto`](CryptoBuf::on_crypto) return [`Error::Decode`] before
/// memory grows past a small fixed budget. The QUIC connection layer
/// maps that error to a fatal connection close.
pub(crate) const MAX_PENDING_CRYPTO_BYTES: usize = 64 * 1024;

/// Per-level cap on the number of disjoint pending fragments. Prevents
/// fragment-count amplification of small-fragment floods (a stream of
/// 1-byte fragments at distinct offsets would otherwise grow `pending`'s
/// `BTreeMap` node count unboundedly without coming anywhere near
/// `MAX_PENDING_CRYPTO_BYTES`).
pub(crate) const MAX_PENDING_FRAGMENTS: usize = 32;

/// Per-encryption-level CRYPTO byte stream.
///
/// Inbound side: [`on_crypto`](Self::on_crypto) inserts a fragment and
/// returns the freshly in-order suffix that the caller should hand to the
/// TLS engine via `process_quic_handshake_bytes`.
///
/// Outbound side: [`enqueue_outbound`](Self::enqueue_outbound) appends
/// bytes from the TLS engine, [`carve`](Self::carve) hands the next chunk
/// to the packet assembler, and [`last_chunk`](Self::last_chunk) lets the
/// PTO timer retransmit the most recent chunk on loss.
#[derive(Default)]
pub(crate) struct CryptoBuf {
    /// Number of in-order bytes the receiver has released.
    next_offset: u64,
    /// Out-of-order fragments, keyed by start offset. Values are owned
    /// `Vec<u8>` so the caller's `&[u8]` is free to be dropped.
    pending: BTreeMap<u64, Vec<u8>>,
    /// Outbound bytes from the TLS engine waiting to be put on the wire.
    outbound: Vec<u8>,
    /// Starting offset for the next outbound CRYPTO frame (i.e. how many
    /// bytes have already been carved into outbound CRYPTO frames at this
    /// level).
    outbound_offset: u64,
    /// The most recent chunk we carved, retained for PTO retransmit. Tuple
    /// is `(offset, bytes)`. `None` until the first carve.
    last_sent: Option<(u64, Vec<u8>)>,
    /// History of every CRYPTO chunk we have ever carved at this level,
    /// keyed by start offset. RFC 9002 loss detection (`requeue_range`)
    /// looks up the exact bytes for a previously-sent CRYPTO range and
    /// re-prepends them to the outbound queue. The TLS engine reads
    /// each handshake byte exactly once on output, so this map is the
    /// only source-of-truth for retransmittable CRYPTO bytes at this
    /// level. Bounded in practice by the handshake size (typically a few
    /// KiB per level; tens of KiB with a full cert chain).
    sent_history: BTreeMap<u64, Vec<u8>>,
}

impl CryptoBuf {
    /// Constructs an empty buffer.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns the offset of the next byte we have *not* yet delivered.
    pub(crate) fn next_offset(&self) -> u64 {
        self.next_offset
    }

    /// True if no out-of-order fragments are pending.
    pub(crate) fn is_pending_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Inserts an inbound CRYPTO fragment at `offset` and returns any
    /// freshly in-order bytes (the suffix that just became deliverable).
    ///
    /// Duplicate / fully-overlapping fragments return an empty vector.
    /// The caller forwards the returned bytes to
    /// `process_quic_handshake_bytes(level, &bytes)`.
    ///
    /// Returns `Err(Error::Decode)` (RFC 9000 §7.5 — the
    /// `CRYPTO_BUFFER_EXCEEDED` class) if accepting this fragment would
    /// push the out-of-order pending budget above
    /// [`MAX_PENDING_CRYPTO_BYTES`] or [`MAX_PENDING_FRAGMENTS`]. The
    /// connection layer maps that error to a fatal close, which is the
    /// correct response to a pre-handshake CRYPTO-flood DoS attempt.
    pub(crate) fn on_crypto(&mut self, mut offset: u64, mut data: &[u8]) -> Result<Vec<u8>, Error> {
        // Trim any bytes already delivered.
        if offset < self.next_offset {
            let skip = (self.next_offset - offset) as usize;
            if skip >= data.len() {
                // Entirely already delivered.
                return Ok(Vec::new());
            }
            data = &data[skip..];
            offset = self.next_offset;
        }
        // Empty fragment — nothing to do.
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // If this fragment is the exact in-order continuation, fast-path
        // append and then absorb any consecutive pending fragments. This
        // path only shrinks `pending` (it never grows it), so no cap
        // check is needed here — by definition the in-order bytes leave
        // the out-of-order budget.
        if offset == self.next_offset {
            let mut released = data.to_vec();
            self.next_offset += data.len() as u64;
            // Drain consecutive pending fragments.
            while let Some((&p_off, _)) = self.pending.iter().next()
                && p_off <= self.next_offset
            {
                let frag = self.pending.remove(&p_off).expect("just peeked");
                let end = p_off + frag.len() as u64;
                if end <= self.next_offset {
                    // Fragment fully overlaps already-delivered bytes.
                    continue;
                }
                let skip = (self.next_offset - p_off) as usize;
                let new_bytes = &frag[skip..];
                released.extend_from_slice(new_bytes);
                self.next_offset = end;
            }
            return Ok(released);
        }

        // Out-of-order. Coalesce with adjacent pending entries to avoid
        // unbounded fragmentation under hostile inputs. Specifically: if
        // the existing entry at the same offset is shorter, replace it;
        // otherwise drop the new fragment.
        let end = offset + data.len() as u64;
        // First, check overlap with the predecessor.
        if let Some((&prev_off, prev_data)) = self.pending.range(..offset).next_back() {
            let prev_end = prev_off + prev_data.len() as u64;
            if prev_end >= end {
                // New fragment fully covered; drop.
                return Ok(Vec::new());
            }
        }
        // Determine whether the insert grows `pending` (a fresh offset)
        // or replaces an existing shorter entry at the same offset. Only
        // the net delta matters for the byte cap; the fragment-count cap
        // is checked when we'd be allocating a new key.
        let existing_len = self.pending.get(&offset).map(|v| v.len()).unwrap_or(0);
        if data.len() <= existing_len {
            // New fragment is not larger than what we already have at
            // this offset — silently drop (the predecessor-overlap check
            // above only catches strict prefixes).
            return Ok(Vec::new());
        }
        let new_total_bytes = self
            .total_pending_bytes()
            .saturating_add(data.len() - existing_len);
        if new_total_bytes > MAX_PENDING_CRYPTO_BYTES {
            // RFC 9000 §7.5 — out-of-order reassembly budget exhausted.
            return Err(Error::Decode);
        }
        if existing_len == 0 && self.pending.len() >= MAX_PENDING_FRAGMENTS {
            // Fragment-count cap. Only checked on a fresh offset (a same-
            // offset replace doesn't add a node).
            return Err(Error::Decode);
        }
        self.pending.insert(offset, data.to_vec());
        Ok(Vec::new())
    }

    /// Total size of out-of-order pending bytes across all fragments.
    /// Used by the RFC 9000 §7.5 cap check in [`on_crypto`] and by the
    /// tests that exercise it.
    fn total_pending_bytes(&self) -> usize {
        self.pending.values().map(Vec::len).sum()
    }

    // ---- Outbound side --------------------------------------------------

    /// Appends `data` to the outbound queue at this level.
    pub(crate) fn enqueue_outbound(&mut self, data: &[u8]) {
        self.outbound.extend_from_slice(data);
    }

    /// True if outbound bytes are queued waiting to be put in CRYPTO frames.
    pub(crate) fn outbound_pending(&self) -> bool {
        !self.outbound.is_empty()
    }

    /// Number of outbound bytes queued.
    pub(crate) fn outbound_len(&self) -> usize {
        self.outbound.len()
    }

    /// Current outbound offset (how many bytes have been carved so far).
    /// Used as the Phase-4 in-flight predicate for the PTO timer.
    pub(crate) fn outbound_offset_for_test(&self) -> u64 {
        self.outbound_offset
    }

    /// Removes up to `cap` bytes from the outbound queue, returns
    /// `(offset, chunk)` ready to be wrapped in a CRYPTO frame.
    ///
    /// Returns `None` if no bytes are queued. Side-effect: stores
    /// `(offset, chunk.clone())` as `last_sent` for PTO retransmit.
    pub(crate) fn carve(&mut self, cap: usize) -> Option<(u64, Vec<u8>)> {
        if self.outbound.is_empty() {
            return None;
        }
        let take = core::cmp::min(cap, self.outbound.len());
        let chunk = self.outbound.drain(..take).collect::<Vec<u8>>();
        let offset = self.outbound_offset;
        self.outbound_offset += chunk.len() as u64;
        self.last_sent = Some((offset, chunk.clone()));
        // Record in sent-history for RFC 9002 retransmit-on-loss.
        // The same offset may be carved more than once (PTO retransmit
        // via `schedule_last_chunk_retransmit`); we overwrite with the
        // freshest copy, which is byte-identical.
        self.sent_history.insert(offset, chunk.clone());
        Some((offset, chunk))
    }

    /// Re-prepends a previously-carved CRYPTO range back to the front of
    /// the outbound queue, so the next [`carve`](Self::carve) call hands
    /// it back to the packet assembler. Used by the RFC 9002 packet-
    /// threshold / time-threshold loss path: when the connection
    /// determines that a packet carrying CRYPTO at `[offset, offset+length)`
    /// was lost, it calls this method to schedule retransmission.
    ///
    /// The retransmitted bytes are looked up in [`Self::sent_history`].
    /// If the exact range cannot be reconstructed (e.g. the history
    /// entry is missing — never happens in practice because every carve
    /// records an entry), the call is a no-op.
    ///
    /// Returns `true` if any byte was re-queued.
    pub(crate) fn requeue_range(&mut self, offset: u64, length: u64) -> bool {
        if length == 0 {
            return false;
        }
        // Find the history entry whose start is ≤ offset and which
        // covers `length` bytes starting at `offset`. In practice every
        // call corresponds to a chunk we carved with the exact same
        // start offset, so an exact lookup succeeds.
        let mut bytes_to_requeue: Vec<u8> = Vec::new();
        let mut cursor = offset;
        let end = offset.saturating_add(length);
        while cursor < end {
            // Find the history entry whose start is the largest value
            // ≤ cursor.
            let entry = self.sent_history.range(..=cursor).next_back();
            let (entry_off, entry_bytes) = match entry {
                Some((k, v)) => (*k, v.clone()),
                None => return false,
            };
            let entry_end = entry_off + entry_bytes.len() as u64;
            if entry_end <= cursor {
                // Gap — no history covers this range. Bail.
                return false;
            }
            let local_skip = (cursor - entry_off) as usize;
            let local_take =
                core::cmp::min((end - cursor) as usize, entry_bytes.len() - local_skip);
            bytes_to_requeue.extend_from_slice(&entry_bytes[local_skip..local_skip + local_take]);
            cursor += local_take as u64;
        }
        // Splice at the front so the next carve hands them out first.
        // We also rewind `outbound_offset` so the re-carved chunk gets
        // its original offset stamped on the CRYPTO frame.
        let mut new_buf = bytes_to_requeue;
        new_buf.append(&mut self.outbound);
        self.outbound = new_buf;
        self.outbound_offset = offset;
        true
    }

    /// Confirms that the CRYPTO range `[offset, offset+length)` was
    /// received by the peer (the packet that carried it was acked) and
    /// prunes every `sent_history` entry fully covered by it. Without
    /// pruning, the history grows for the lifetime of the connection —
    /// post-handshake CRYPTO (NewSessionTicket flights) would
    /// accumulate without bound.
    ///
    /// Entries only *partially* covered are kept: their unacked tail
    /// may still be needed by [`Self::requeue_range`] for
    /// retransmission. (Every carve is also covered by its own packet's
    /// retransmit hint, so a fully-lost range remains reconstructable
    /// from the entries that survive.)
    pub(crate) fn on_range_acked(&mut self, offset: u64, length: u64) {
        if length == 0 {
            return;
        }
        let end = offset.saturating_add(length);
        let covered: Vec<u64> = self
            .sent_history
            .range(offset..end)
            .filter(|(k, v)| *k + v.len() as u64 <= end)
            .map(|(k, _)| *k)
            .collect();
        for k in covered {
            self.sent_history.remove(&k);
        }
    }

    /// Re-queue the most recent chunk at the *front* of `outbound` so it
    /// will be re-carved on the next packet build. Used by the PTO timer
    /// for the only level where we have a `last_sent` to retransmit.
    ///
    /// Returns `true` if a retransmit was scheduled. A no-op (and
    /// `false`) if no chunk has ever been sent at this level.
    pub(crate) fn schedule_last_chunk_retransmit(&mut self) -> bool {
        if let Some((off, bytes)) = self.last_sent.as_ref() {
            // Rewind the outbound offset and prepend the bytes. Since
            // `outbound` already contains anything queued after `last_sent`
            // (carved *after* the chunk was carved), splicing at the front
            // re-establishes the original byte stream.
            let mut new_buf = bytes.clone();
            new_buf.append(&mut self.outbound);
            self.outbound = new_buf;
            self.outbound_offset = *off;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_pass_through() {
        let mut b = CryptoBuf::new();
        let out = b.on_crypto(0, b"hello").expect("ok");
        assert_eq!(out, b"hello");
        assert_eq!(b.next_offset(), 5);
        assert!(b.is_pending_empty());

        let out = b.on_crypto(5, b" world").expect("ok");
        assert_eq!(out, b" world");
        assert_eq!(b.next_offset(), 11);
    }

    #[test]
    fn out_of_order_then_in_order_merges() {
        // Insert offset=100 (out of order), then offset=0 (in order); the
        // delivered_so_far should merge.
        let mut b = CryptoBuf::new();
        let out = b.on_crypto(100, b"second-block").expect("ok");
        assert!(out.is_empty());
        assert_eq!(b.next_offset(), 0);
        assert!(!b.is_pending_empty());

        // Now fill the gap [0..100):
        let filler = alloc::vec![b'a'; 100];
        let out = b.on_crypto(0, &filler).expect("ok");
        // We expect the filler PLUS the previously-pending block.
        assert_eq!(out.len(), 100 + 12);
        assert_eq!(&out[..100], &filler[..]);
        assert_eq!(&out[100..], b"second-block");
        assert_eq!(b.next_offset(), 112);
        assert!(b.is_pending_empty());
    }

    #[test]
    fn duplicate_fragment_is_swallowed() {
        let mut b = CryptoBuf::new();
        let _ = b.on_crypto(0, b"hello world").expect("ok");
        // Resend offset 0 — already delivered.
        let out = b.on_crypto(0, b"hello world").expect("ok");
        assert!(out.is_empty());
        // Resend a strict subset.
        let out = b.on_crypto(2, b"llo").expect("ok");
        assert!(out.is_empty());
        assert_eq!(b.next_offset(), 11);
    }

    #[test]
    fn fragment_straddles_boundary() {
        let mut b = CryptoBuf::new();
        let _ = b.on_crypto(0, b"hello").expect("ok");
        // Fragment at offset 3 ("lo world") — first two bytes already
        // delivered, last six are new.
        let out = b.on_crypto(3, b"lo world").expect("ok");
        assert_eq!(out, b" world");
        assert_eq!(b.next_offset(), 11);
    }

    #[test]
    fn outbound_enqueue_and_carve() {
        let mut b = CryptoBuf::new();
        assert!(!b.outbound_pending());
        b.enqueue_outbound(b"hello world");
        assert!(b.outbound_pending());
        assert_eq!(b.outbound_len(), 11);

        let (off, chunk) = b.carve(5).expect("carve");
        assert_eq!(off, 0);
        assert_eq!(chunk, b"hello");
        let (off, chunk) = b.carve(100).expect("carve rest");
        assert_eq!(off, 5);
        assert_eq!(chunk, b" world");

        assert!(b.carve(10).is_none());
        assert!(!b.outbound_pending());
    }

    #[test]
    fn schedule_retransmit_replays_last_chunk() {
        let mut b = CryptoBuf::new();
        b.enqueue_outbound(b"AAABBB");
        let (off1, c1) = b.carve(3).expect("carve");
        assert_eq!(off1, 0);
        assert_eq!(c1, b"AAA");
        let (off2, c2) = b.carve(3).expect("carve");
        assert_eq!(off2, 3);
        assert_eq!(c2, b"BBB");
        assert!(!b.outbound_pending());

        // PTO fires — re-queue the last chunk ("BBB" at offset 3).
        let scheduled = b.schedule_last_chunk_retransmit();
        assert!(scheduled);
        let (off3, c3) = b.carve(3).expect("retransmit");
        assert_eq!(off3, 3);
        assert_eq!(c3, b"BBB");
    }

    #[test]
    fn schedule_retransmit_with_pending_after() {
        // After carving "AAA" we enqueue more bytes ("CCC"). PTO schedules
        // the retransmit of "AAA" — that re-prepends, leaving "AAA" + "CCC".
        let mut b = CryptoBuf::new();
        b.enqueue_outbound(b"AAA");
        let (off1, c1) = b.carve(3).expect("carve");
        assert_eq!(off1, 0);
        assert_eq!(c1, b"AAA");
        b.enqueue_outbound(b"CCC"); // appended after AAA in the byte stream

        let _ = b.schedule_last_chunk_retransmit();
        // Carve everything; first 3 bytes should be the retransmitted AAA,
        // and the offset rewinds.
        let (off, chunk) = b.carve(100).expect("carve all");
        assert_eq!(off, 0);
        assert_eq!(chunk, b"AAACCC");
    }

    #[test]
    fn pending_smaller_fragment_does_not_overwrite_larger() {
        let mut b = CryptoBuf::new();
        let _ = b.on_crypto(10, b"longer-fragment").expect("ok");
        // Insert a shorter fragment at the same offset — must NOT shrink
        // the pending entry.
        let _ = b.on_crypto(10, b"long").expect("ok");
        // Fill the gap and assert we still get the long fragment.
        let filler = alloc::vec![b'X'; 10];
        let out = b.on_crypto(0, &filler).expect("ok");
        assert_eq!(&out[10..], b"longer-fragment");
    }

    /// RFC 9000 §7.5 — CRYPTO_BUFFER_EXCEEDED. Feeding out-of-order
    /// fragments past [`MAX_PENDING_CRYPTO_BYTES`] must surface an
    /// error rather than growing `pending` unboundedly.
    #[test]
    fn crypto_buf_rejects_oversize_pending() {
        let mut b = CryptoBuf::new();
        // 8 KiB chunks at distinct out-of-order offsets, starting far
        // past zero so they all live in `pending`. 8 chunks = 64 KiB =
        // exactly MAX_PENDING_CRYPTO_BYTES; the 9th overflows the cap.
        let chunk_size = 8 * 1024;
        let chunk = alloc::vec![b'A'; chunk_size];
        // Use a starting offset well above zero so the in-order
        // fast-path is never hit.
        let base = 1u64 << 20;
        let max_chunks = MAX_PENDING_CRYPTO_BYTES / chunk_size;
        for i in 0..max_chunks {
            let off = base + (i as u64) * (chunk_size as u64);
            b.on_crypto(off, &chunk).expect("under cap");
        }
        // One more byte at a fresh offset should fail.
        let extra_off = base + (max_chunks as u64) * (chunk_size as u64);
        let res = b.on_crypto(extra_off, b"X");
        assert!(matches!(res, Err(Error::Decode)));
        // And `pending` is bounded — total stays at the cap.
        assert_eq!(b.total_pending_bytes(), MAX_PENDING_CRYPTO_BYTES);
    }

    /// Fragment-count amplification: small-fragment floods are bounded
    /// by [`MAX_PENDING_FRAGMENTS`].
    #[test]
    fn crypto_buf_rejects_too_many_fragments() {
        let mut b = CryptoBuf::new();
        // 32 single-byte fragments at distinct offsets above zero —
        // fill `pending` to MAX_PENDING_FRAGMENTS without coming
        // anywhere near MAX_PENDING_CRYPTO_BYTES.
        let base = 1u64 << 20;
        for i in 0..MAX_PENDING_FRAGMENTS {
            let off = base + (i as u64) * 1024; // strided so no overlap
            b.on_crypto(off, b"X").expect("under cap");
        }
        // The 33rd disjoint fragment fails.
        let extra_off = base + (MAX_PENDING_FRAGMENTS as u64) * 1024;
        let res = b.on_crypto(extra_off, b"X");
        assert!(matches!(res, Err(Error::Decode)));
        assert_eq!(b.pending.len(), MAX_PENDING_FRAGMENTS);
    }

    /// Once buffered fragments are delivered (by filling the gap), the
    /// budget relaxes — the cap is on currently-pending bytes, not
    /// lifetime CRYPTO bytes.
    #[test]
    fn crypto_buf_capacity_relaxes_after_delivery() {
        let mut b = CryptoBuf::new();
        // Stage 1: 32 KiB out-of-order at offset 32 KiB. Under cap.
        let half = MAX_PENDING_CRYPTO_BYTES / 2; // 32 KiB
        let block_a = alloc::vec![b'A'; half];
        b.on_crypto(half as u64, &block_a).expect("under cap");
        assert_eq!(b.total_pending_bytes(), half);

        // Stage 2: fill the gap [0..32 KiB) — delivery drains `pending`.
        let filler = alloc::vec![b'F'; half];
        let out = b.on_crypto(0, &filler).expect("delivery");
        assert_eq!(out.len(), half + half); // filler + previously-pending
        assert_eq!(b.next_offset(), (half * 2) as u64);
        assert_eq!(b.total_pending_bytes(), 0);

        // Stage 3: another 32 KiB at offset 96 KiB is in-order
        // continuation if we first fill [64 KiB..96 KiB); pre-fill
        // that gap so the second 32 KiB lands in-order without
        // tripping the cap (the cap is on out-of-order pending).
        let bridge = alloc::vec![b'B'; half];
        let _ = b.on_crypto((half * 2) as u64, &bridge).expect("in-order");
        let block_c = alloc::vec![b'C'; half];
        let _ = b
            .on_crypto((half * 3) as u64, &block_c)
            .expect("still in-order");
        assert_eq!(b.next_offset(), (half * 4) as u64);
        assert_eq!(b.total_pending_bytes(), 0);
    }

    /// A6 — acked CRYPTO ranges are pruned from `sent_history` so it
    /// doesn't grow for the lifetime of the connection, while unacked
    /// ranges stay retransmittable.
    #[test]
    fn sent_history_pruned_once_acked() {
        let mut b = CryptoBuf::new();
        b.enqueue_outbound(b"AAAABBBB");
        let _ = b.carve(4).expect("carve 1"); // [0, 4)
        let _ = b.carve(4).expect("carve 2"); // [4, 8)
        assert_eq!(b.sent_history.len(), 2);

        // Ack the first chunk — only its entry is pruned.
        b.on_range_acked(0, 4);
        assert_eq!(b.sent_history.len(), 1);
        // The acked range can no longer be requeued (no-op)…
        assert!(!b.requeue_range(0, 4));
        // …but the unacked one still can.
        assert!(b.requeue_range(4, 4));
        let (off, chunk) = b.carve(100).expect("recarve");
        assert_eq!(off, 4);
        assert_eq!(chunk, b"BBBB");

        // Ack the rest — history fully drains.
        b.on_range_acked(4, 4);
        assert!(b.sent_history.is_empty());
    }

    /// A partially-acked history entry is retained: its unacked tail
    /// must remain available for retransmission.
    #[test]
    fn sent_history_partial_ack_keeps_covering_entry() {
        let mut b = CryptoBuf::new();
        b.enqueue_outbound(b"AAAAAAAA");
        let _ = b.carve(8).expect("carve"); // single [0, 8) entry
        b.on_range_acked(0, 4);
        assert_eq!(b.sent_history.len(), 1, "partially-covered entry kept");
        assert!(b.requeue_range(4, 4), "unacked tail still retransmittable");
    }

    /// Inserting a strictly-longer fragment at an offset that already
    /// has a shorter entry only counts the delta against the cap —
    /// it must NOT double-count the replaced bytes.
    #[test]
    fn crypto_buf_replace_at_offset_counts_delta_only() {
        let mut b = CryptoBuf::new();
        let base = 1u64 << 20;
        // Fill to (cap - 1024) bytes via 8 KiB strided fragments.
        let chunk_size = 8 * 1024;
        let chunk_short = alloc::vec![b'S'; chunk_size - 128];
        let chunk_full = alloc::vec![b'F'; chunk_size];
        // 7 short fragments + 1 full = 7*(8192-128) + 8192 = 64 KiB - 896.
        for i in 0..7 {
            let off = base + (i as u64) * (chunk_size as u64);
            b.on_crypto(off, &chunk_short).expect("under cap");
        }
        let last_off = base + 7 * (chunk_size as u64);
        b.on_crypto(last_off, &chunk_full).expect("under cap");
        // Now upgrade fragment 0 from short to full — that's a +128
        // delta; cap is 64 KiB and we're at 64 KiB - 7*128 + 0 = some
        // value well under. Just confirm the replace succeeds.
        let replaced = b.on_crypto(base, &chunk_full);
        assert!(replaced.is_ok());
    }
}
