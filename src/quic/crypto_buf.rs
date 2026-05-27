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

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

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
    pub(crate) fn on_crypto(&mut self, mut offset: u64, mut data: &[u8]) -> Vec<u8> {
        // Trim any bytes already delivered.
        if offset < self.next_offset {
            let skip = (self.next_offset - offset) as usize;
            if skip >= data.len() {
                // Entirely already delivered.
                return Vec::new();
            }
            data = &data[skip..];
            offset = self.next_offset;
        }
        // Empty fragment — nothing to do.
        if data.is_empty() {
            return Vec::new();
        }

        // If this fragment is the exact in-order continuation, fast-path
        // append and then absorb any consecutive pending fragments.
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
            return released;
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
                return Vec::new();
            }
        }
        // Insert / replace.
        let existing_len = self
            .pending
            .get(&offset)
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        if data.len() as u64 > existing_len {
            self.pending.insert(offset, data.to_vec());
        }
        Vec::new()
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
        Some((offset, chunk))
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
        let out = b.on_crypto(0, b"hello");
        assert_eq!(out, b"hello");
        assert_eq!(b.next_offset(), 5);
        assert!(b.is_pending_empty());

        let out = b.on_crypto(5, b" world");
        assert_eq!(out, b" world");
        assert_eq!(b.next_offset(), 11);
    }

    #[test]
    fn out_of_order_then_in_order_merges() {
        // Insert offset=100 (out of order), then offset=0 (in order); the
        // delivered_so_far should merge.
        let mut b = CryptoBuf::new();
        let out = b.on_crypto(100, b"second-block");
        assert!(out.is_empty());
        assert_eq!(b.next_offset(), 0);
        assert!(!b.is_pending_empty());

        // Now fill the gap [0..100):
        let filler = alloc::vec![b'a'; 100];
        let out = b.on_crypto(0, &filler);
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
        let _ = b.on_crypto(0, b"hello world");
        // Resend offset 0 — already delivered.
        let out = b.on_crypto(0, b"hello world");
        assert!(out.is_empty());
        // Resend a strict subset.
        let out = b.on_crypto(2, b"llo");
        assert!(out.is_empty());
        assert_eq!(b.next_offset(), 11);
    }

    #[test]
    fn fragment_straddles_boundary() {
        let mut b = CryptoBuf::new();
        let _ = b.on_crypto(0, b"hello");
        // Fragment at offset 3 ("lo world") — first two bytes already
        // delivered, last six are new.
        let out = b.on_crypto(3, b"lo world");
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
        let _ = b.on_crypto(10, b"longer-fragment");
        // Insert a shorter fragment at the same offset — must NOT shrink
        // the pending entry.
        let _ = b.on_crypto(10, b"long");
        // Fill the gap and assert we still get the long fragment.
        let filler = alloc::vec![b'X'; 10];
        let out = b.on_crypto(0, &filler);
        assert_eq!(&out[10..], b"longer-fragment");
    }
}
