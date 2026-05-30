//! DTLS handshake fragmentation and reassembly (RFC 6347 §4.2.2).
//!
//! Whereas TLS handshake messages carry only `Type(1) ‖ Length(3) ‖ body`,
//! the DTLS handshake header inserts the message sequence number plus a
//! per-fragment offset and length so that an oversized message can be split
//! across multiple records and reassembled out of order at the receiver:
//!
//! ```text
//! struct {
//!     HandshakeType type;             //  1 byte
//!     uint24 length;                  //  3 bytes — full message length
//!     uint16 message_seq;             //  2 bytes — per-direction counter
//!     uint24 fragment_offset;         //  3 bytes
//!     uint24 fragment_length;         //  3 bytes
//!     opaque body[fragment_length];
//! } Handshake;
//! ```
//!
//! Total header = 12 bytes.
//!
//! The reassembler buffers fragments by `message_seq` and emits a complete
//! message body once *all* bytes of the next-expected message have arrived.
//! Duplicate fragments are idempotent (no panic, no corruption). A fragment
//! whose `offset + length` exceeds the message's claimed `length` is a
//! protocol violation and yields [`Error::Decode`] at parse time.
//!
//! The consumers (DTLS client/server state machines) arrive in follow-up
//! commits, so items below are `#[allow(dead_code)]` for now.

#![allow(dead_code)]

use crate::tls::Error;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Fixed DTLS handshake header length: 12 bytes.
pub(crate) const HEADER_LEN: usize = 12;

/// Upper bound on a peer-supplied `message_seq` the server is willing to
/// "catch up" to when seeding a reassembler from a ClientHello. The DTLS
/// `message_seq` field is 16-bit, but a legitimate first/second ClientHello
/// only ever uses seq 0 (no HRR) or 1 (after a cookie-HRR or group-HRR).
/// Allowing an arbitrary value lets an attacker — even on the pre-cookie,
/// epoch-0, unauthenticated path — force up to 65 535 allocate/serialize/
/// parse/feed cycles per record (a CPU/allocation DoS). Cap it well above
/// any legitimate value but far below the 16-bit ceiling. Mirrors the spirit
/// of `MAX_IN_PROGRESS`.
pub(crate) const MAX_HS_MSG_SEQ: u16 = 8;

/// One incoming handshake fragment, borrowed from the record fragment.
pub(crate) struct HandshakeFragment<'a> {
    pub(crate) msg_type: u8,
    pub(crate) total_length: u32,
    pub(crate) message_seq: u16,
    pub(crate) fragment_offset: u32,
    pub(crate) fragment: &'a [u8],
    /// Total bytes consumed from the input (header + fragment body). Lets
    /// the caller iterate over multiple concatenated handshake fragments
    /// inside a single record (RFC 6347 §4.2.3 permits this).
    pub(crate) len: usize,
}

/// Parses the next DTLS handshake fragment from the front of `buf`.
///
/// The fragment header is fixed-width; the `fragment_length` field selects
/// the trailing body. Buffers shorter than the claimed fragment length, or
/// whose offset/length exceeds the total message length, yield
/// [`Error::Decode`].
pub(crate) fn read_fragment(buf: &[u8]) -> Result<HandshakeFragment<'_>, Error> {
    if buf.len() < HEADER_LEN {
        return Err(Error::Decode);
    }
    let msg_type = buf[0];
    let total_length = u24_be(&buf[1..4]);
    let message_seq = u16::from_be_bytes([buf[4], buf[5]]);
    let fragment_offset = u24_be(&buf[6..9]);
    let fragment_length = u24_be(&buf[9..12]);

    let body_len = fragment_length as usize;
    let end_in_buf = HEADER_LEN.checked_add(body_len).ok_or(Error::Decode)?;
    if end_in_buf > buf.len() {
        return Err(Error::Decode);
    }
    // Detect `offset + length > total_length` without overflow.
    let end = (fragment_offset as u64) + (fragment_length as u64);
    if end > total_length as u64 {
        return Err(Error::Decode);
    }
    Ok(HandshakeFragment {
        msg_type,
        total_length,
        message_seq,
        fragment_offset,
        fragment: &buf[HEADER_LEN..end_in_buf],
        len: end_in_buf,
    })
}

/// Writes one full handshake message (or several fragments thereof) to
/// `out`, each fragment prefixed with the 12-byte DTLS handshake header.
///
/// `max_fragment_size` bounds the body-bytes-per-fragment; the resulting
/// records still need to be wrapped by [`super::record::write_record`]. A
/// `max_fragment_size` of zero or larger than the message produces exactly
/// one fragment.
pub(crate) fn write_message(
    out: &mut Vec<u8>,
    msg_type: u8,
    message_seq: u16,
    full_message_body: &[u8],
    max_fragment_size: usize,
) {
    let total = full_message_body.len();
    debug_assert!(
        total <= 0xFF_FFFF,
        "handshake message exceeds the 24-bit length field",
    );

    // Single fragment if no chunking is requested or the body fits whole.
    let chunk = if max_fragment_size == 0 || max_fragment_size >= total {
        total.max(1)
    } else {
        max_fragment_size
    };

    if total == 0 {
        // Empty body (e.g. ServerHelloDone). Emit one zero-length fragment.
        write_fragment_header(out, msg_type, total as u32, message_seq, 0, 0);
        return;
    }

    let mut offset = 0usize;
    while offset < total {
        let n = core::cmp::min(chunk, total - offset);
        write_fragment_header(
            out,
            msg_type,
            total as u32,
            message_seq,
            offset as u32,
            n as u32,
        );
        out.extend_from_slice(&full_message_body[offset..offset + n]);
        offset += n;
    }
}

/// Partial-message buffer indexed by `message_seq`.
struct PartialMessage {
    msg_type: u8,
    total_length: u32,
    /// Dense buffer of all message bytes (zero-initialised; sparse writes).
    buf: Vec<u8>,
    /// Per-byte arrival bitmap, packed 64 bits per word. One bit per message
    /// byte (8× smaller than the prior `Vec<bool>`). Mutated only through
    /// [`set_received`] / [`is_received`].
    received: Vec<u64>,
    /// Count of set bits in `received`.
    received_count: u32,
}

impl PartialMessage {
    #[inline]
    fn is_received(&self, byte_idx: usize) -> bool {
        let word = byte_idx >> 6;
        let bit = byte_idx & 0x3f;
        match self.received.get(word) {
            Some(w) => (*w >> bit) & 1 != 0,
            None => false,
        }
    }

    /// Returns `true` if this call flipped the bit from 0 to 1 (i.e. it's a
    /// genuinely new byte). Out-of-range indices are no-ops returning `false`.
    #[inline]
    fn set_received(&mut self, byte_idx: usize) -> bool {
        let word = byte_idx >> 6;
        let bit = byte_idx & 0x3f;
        let Some(w) = self.received.get_mut(word) else {
            return false;
        };
        let mask = 1u64 << bit;
        if *w & mask != 0 {
            false
        } else {
            *w |= mask;
            true
        }
    }
}

/// Upper bound on a single handshake message's `total_length`. RFC 6347 /
/// 9147 don't dictate one, but real-world handshake bodies are well under
/// 256 KiB even with PQC certificate chains and ML-DSA signatures (~50 KB
/// SLH-DSA signatures push the high end). Capping prevents a hostile peer
/// from claiming `total_length = 16 MiB` and triggering a multi-MiB
/// allocation per message_seq.
const MAX_MESSAGE_LEN: u32 = 256 * 1024;

/// Upper bound on the number of distinct `message_seq` values held in the
/// in-progress map. RFC allows up to 65 535; an attacker emitting one
/// fragment for each would otherwise pin tens of GiB of allocations. Eight
/// concurrent in-flight messages is more than any legitimate handshake
/// flight needs.
const MAX_IN_PROGRESS: usize = 8;

/// Handshake-message reassembler. Tracks one in-flight reassembly per
/// outstanding `message_seq` and gates dispatch on the next-expected
/// sequence number.
pub(crate) struct Reassembler {
    expected_msg_seq: u16,
    in_progress: BTreeMap<u16, PartialMessage>,
}

impl Reassembler {
    /// Creates a fresh reassembler waiting on `message_seq = 0`.
    pub(crate) fn new() -> Self {
        Self {
            expected_msg_seq: 0,
            in_progress: BTreeMap::new(),
        }
    }

    /// The message sequence number this reassembler is currently waiting for.
    #[allow(dead_code)] // exercised by tests + future commits
    pub(crate) fn expected_msg_seq(&self) -> u16 {
        self.expected_msg_seq
    }

    /// Feeds one fragment. Returns `Some((msg_type, body))` only if the
    /// next-expected message just completed. Future-sequence fragments are
    /// buffered silently; past-sequence fragments (already-dispatched) are
    /// dropped.
    pub(crate) fn feed(&mut self, frag: HandshakeFragment<'_>) -> Option<(u8, Vec<u8>)> {
        // Drop old fragments outright; they belong to a message we already
        // dispatched.
        if frag.message_seq < self.expected_msg_seq {
            return None;
        }
        // Reject implausibly large messages and out-of-budget concurrency
        // (memory-DoS protection).
        if frag.total_length > MAX_MESSAGE_LEN {
            return None;
        }
        if !self.in_progress.contains_key(&frag.message_seq)
            && self.in_progress.len() >= MAX_IN_PROGRESS
        {
            return None;
        }

        let total_length = frag.total_length;
        let entry = self
            .in_progress
            .entry(frag.message_seq)
            .or_insert_with(|| PartialMessage {
                msg_type: frag.msg_type,
                total_length,
                buf: vec_zeroed(total_length as usize),
                received: vec_bitmap_words(total_length as usize),
                received_count: 0,
            });

        // Cross-fragment consistency: every fragment of the same message
        // must agree on msg_type and total_length. A mismatch is a peer bug
        // — drop the fragment but keep the reassembly going.
        if entry.msg_type != frag.msg_type || entry.total_length != total_length {
            return None;
        }

        let off = frag.fragment_offset as usize;
        for (i, &b) in frag.fragment.iter().enumerate() {
            let idx = off + i;
            // `read_fragment` already verified the offset + length is in
            // bounds against total_length; this is belt-and-braces.
            if idx >= entry.buf.len() {
                return None;
            }
            if entry.set_received(idx) {
                entry.buf[idx] = b;
                entry.received_count += 1;
            }
            // else: duplicate byte — ignored, no overwrite.
        }

        // Empty messages (ServerHelloDone, HelloRequest) complete on receipt
        // of the one zero-length fragment, which `received_count` happens to
        // capture as 0 == total_length=0.
        if entry.received_count == entry.total_length {
            // Only dispatch if this is the head of the queue.
            if frag.message_seq == self.expected_msg_seq {
                let done = self.in_progress.remove(&frag.message_seq).unwrap();
                self.expected_msg_seq = self.expected_msg_seq.wrapping_add(1);
                return Some((done.msg_type, done.buf));
            }
        }
        None
    }

    /// Pops the next-expected message if it has already been fully
    /// assembled (e.g. its fragments arrived before earlier messages).
    /// Returns `None` when the head of the queue is still missing fragments.
    ///
    /// Callers typically loop `feed → handle → pop_ready → handle → …`
    /// until `pop_ready` yields `None`, so that an arbitrary delivery
    /// order ultimately releases everything in protocol order.
    pub(crate) fn pop_ready(&mut self) -> Option<(u8, Vec<u8>)> {
        let entry = self.in_progress.get(&self.expected_msg_seq)?;
        if entry.received_count != entry.total_length {
            return None;
        }
        let done = self.in_progress.remove(&self.expected_msg_seq)?;
        self.expected_msg_seq = self.expected_msg_seq.wrapping_add(1);
        Some((done.msg_type, done.buf))
    }
}

// --- helpers ---------------------------------------------------------------

#[inline]
fn u24_be(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
}

fn put_u24(out: &mut Vec<u8>, v: u32) {
    out.push(((v >> 16) & 0xff) as u8);
    out.push(((v >> 8) & 0xff) as u8);
    out.push((v & 0xff) as u8);
}

fn write_fragment_header(
    out: &mut Vec<u8>,
    msg_type: u8,
    total_length: u32,
    message_seq: u16,
    fragment_offset: u32,
    fragment_length: u32,
) {
    out.push(msg_type);
    put_u24(out, total_length);
    out.extend_from_slice(&message_seq.to_be_bytes());
    put_u24(out, fragment_offset);
    put_u24(out, fragment_length);
}

fn vec_zeroed(n: usize) -> Vec<u8> {
    alloc::vec![0u8; n]
}

/// Allocates a zeroed bitmap large enough to hold `bits` bits, packed into
/// 64-bit words. `bits = 0` yields an empty vector.
fn vec_bitmap_words(bits: usize) -> Vec<u64> {
    alloc::vec![0u64; bits.div_ceil(64)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_unfragmented_message_completes_immediately() {
        let mut buf = Vec::new();
        write_message(&mut buf, 1, 0, b"hello world", 0);
        let frag = read_fragment(&buf).unwrap();
        assert_eq!(frag.msg_type, 1);
        assert_eq!(frag.total_length, 11);
        assert_eq!(frag.message_seq, 0);
        assert_eq!(frag.fragment_offset, 0);
        assert_eq!(frag.fragment, b"hello world");

        let mut r = Reassembler::new();
        let out = r.feed(frag).unwrap();
        assert_eq!(out.0, 1);
        assert_eq!(out.1, b"hello world");
        assert_eq!(r.expected_msg_seq(), 1);
    }

    #[test]
    fn empty_body_message_completes() {
        // ServerHelloDone has type 14 and zero body.
        let mut buf = Vec::new();
        write_message(&mut buf, 14, 3, b"", 0);
        // Exactly one 12-byte header, no body.
        assert_eq!(buf.len(), HEADER_LEN);
        let frag = read_fragment(&buf).unwrap();
        assert_eq!(frag.fragment.len(), 0);
        assert_eq!(frag.total_length, 0);

        let mut r = Reassembler::new();
        // Note: reassembler expects msg_seq=0 first; this test only verifies
        // the empty-body path works once we're caught up.
        for s in 0..3 {
            let mut tmp = Vec::new();
            write_message(&mut tmp, 14, s as u16, b"", 0);
            let f = read_fragment(&tmp).unwrap();
            let res = r.feed(f).unwrap();
            assert_eq!(res.0, 14);
            assert!(res.1.is_empty());
        }
        let f3 = read_fragment(&buf).unwrap();
        let res = r.feed(f3).unwrap();
        assert_eq!(res.0, 14);
        assert!(res.1.is_empty());
    }

    #[test]
    fn out_of_order_fragments_reassemble() {
        // Total message body: 20 bytes "AAAAAAAAAABBBBBBBBBB".
        let body: Vec<u8> = (b'A'..=b'T').collect();
        assert_eq!(body.len(), 20);

        // Emit two fragments: offset=10 (10 bytes), offset=0 (10 bytes).
        let total = body.len() as u32;
        let mut frag_late = Vec::new();
        write_fragment_header(&mut frag_late, 2, total, 0, 10, 10);
        frag_late.extend_from_slice(&body[10..]);

        let mut frag_early = Vec::new();
        write_fragment_header(&mut frag_early, 2, total, 0, 0, 10);
        frag_early.extend_from_slice(&body[..10]);

        let mut r = Reassembler::new();
        // Late half first: no completion yet.
        assert!(r.feed(read_fragment(&frag_late).unwrap()).is_none());
        // Early half completes it.
        let out = r.feed(read_fragment(&frag_early).unwrap()).unwrap();
        assert_eq!(out.0, 2);
        assert_eq!(out.1, body);
    }

    #[test]
    fn duplicate_fragment_is_idempotent() {
        let body = b"some message bytes".to_vec();
        let total = body.len() as u32;

        let mut buf = Vec::new();
        write_fragment_header(&mut buf, 11, total, 0, 0, total);
        buf.extend_from_slice(&body);

        let mut r = Reassembler::new();
        let out1 = r.feed(read_fragment(&buf).unwrap()).unwrap();
        assert_eq!(out1.1, body);
        assert_eq!(r.expected_msg_seq(), 1);
        // Replay of the same fragment is dropped (msg_seq < expected).
        assert!(r.feed(read_fragment(&buf).unwrap()).is_none());
    }

    #[test]
    fn duplicate_partial_fragment_no_corruption() {
        // Send the offset=0 half twice before the offset=10 half arrives.
        let body: Vec<u8> = (0u8..20).collect();
        let total = body.len() as u32;

        let mut early = Vec::new();
        write_fragment_header(&mut early, 5, total, 0, 0, 10);
        early.extend_from_slice(&body[..10]);

        let mut late = Vec::new();
        write_fragment_header(&mut late, 5, total, 0, 10, 10);
        late.extend_from_slice(&body[10..]);

        let mut r = Reassembler::new();
        assert!(r.feed(read_fragment(&early).unwrap()).is_none());
        assert!(r.feed(read_fragment(&early).unwrap()).is_none());
        assert!(r.feed(read_fragment(&early).unwrap()).is_none());
        let out = r.feed(read_fragment(&late).unwrap()).unwrap();
        assert_eq!(out.0, 5);
        assert_eq!(out.1, body);
    }

    #[test]
    fn fragment_out_of_bounds_rejected() {
        // Claim total_length=10 but offset=8, length=5 → end=13 > 10.
        let mut buf = Vec::new();
        write_fragment_header(&mut buf, 1, 10, 0, 8, 5);
        buf.extend_from_slice(&[0; 5]);
        match read_fragment(&buf) {
            Err(Error::Decode) => {}
            Ok(_) => panic!("expected Decode error, got Ok"),
            Err(e) => panic!("expected Decode, got {e:?}"),
        }
    }

    #[test]
    fn fragment_length_truncated_rejected() {
        // Header says 5 body bytes but only 3 are present.
        let mut buf = Vec::new();
        write_fragment_header(&mut buf, 1, 10, 0, 0, 5);
        buf.extend_from_slice(&[0; 3]);
        match read_fragment(&buf) {
            Err(Error::Decode) => {}
            Ok(_) => panic!("expected Decode error, got Ok"),
            Err(e) => panic!("expected Decode, got {e:?}"),
        }
    }

    #[test]
    fn fragment_with_trailing_bytes_consumes_only_its_own() {
        // Two concatenated fragments. read_fragment should yield exactly one.
        let mut buf = Vec::new();
        write_fragment_header(&mut buf, 1, 4, 0, 0, 4);
        buf.extend_from_slice(b"AAAA");
        let tail_start = buf.len();
        write_fragment_header(&mut buf, 2, 6, 7, 0, 6);
        buf.extend_from_slice(b"BBBBBB");

        let f1 = read_fragment(&buf).unwrap();
        assert_eq!(f1.msg_type, 1);
        assert_eq!(f1.fragment, b"AAAA");
        assert_eq!(f1.len, tail_start);

        let f2 = read_fragment(&buf[f1.len..]).unwrap();
        assert_eq!(f2.msg_type, 2);
        assert_eq!(f2.message_seq, 7);
        assert_eq!(f2.fragment, b"BBBBBB");
    }

    #[test]
    fn write_message_chunks_at_max_fragment_size() {
        // 25-byte message, chunked at 10 → fragments at offsets 0, 10, 20.
        let body: Vec<u8> = (0u8..25).collect();
        let mut out = Vec::new();
        write_message(&mut out, 7, 9, &body, 10);

        let f1 = read_fragment(&out).unwrap();
        assert_eq!(f1.message_seq, 9);
        assert_eq!(f1.fragment_offset, 0);
        assert_eq!(f1.fragment.len(), 10);
        let f2 = read_fragment(&out[f1.len..]).unwrap();
        assert_eq!(f2.fragment_offset, 10);
        assert_eq!(f2.fragment.len(), 10);
        let f3 = read_fragment(&out[f1.len + f2.len..]).unwrap();
        assert_eq!(f3.fragment_offset, 20);
        assert_eq!(f3.fragment.len(), 5);
        assert_eq!(f1.len + f2.len + f3.len, out.len());
    }

    #[test]
    fn fragmented_reassembly_with_bitmap_transitions() {
        // Drive 1024 bytes through 4-byte chunks delivered in a shuffled
        // order; the bitmap must complete the message exactly once and
        // produce the same body bytes regardless of arrival order.
        let body: Vec<u8> = (0..1024).map(|i| (i & 0xff) as u8).collect();
        let total = body.len() as u32;

        // Build 256 fragments of 4 bytes each, then shuffle deterministically.
        let mut frags: Vec<Vec<u8>> = (0..256)
            .map(|i| {
                let off = i * 4;
                let mut f = Vec::new();
                write_fragment_header(&mut f, 11, total, 0, off as u32, 4);
                f.extend_from_slice(&body[off..off + 4]);
                f
            })
            .collect();
        // Pseudo-shuffle: pair up halves.
        let mid = frags.len() / 2;
        let mut shuffled = Vec::new();
        for i in 0..mid {
            shuffled.push(frags.swap_remove(0));
            if !frags.is_empty() {
                shuffled.push(frags.remove(mid - i - 1));
            }
        }
        shuffled.extend(frags);

        let mut r = Reassembler::new();
        let mut completion = None;
        for f in &shuffled {
            let frag = read_fragment(f).unwrap();
            if let Some(out) = r.feed(frag) {
                assert!(completion.is_none(), "completed twice!");
                completion = Some(out);
            }
        }
        let (ty, got) = completion.expect("message must complete");
        assert_eq!(ty, 11);
        assert_eq!(got, body);
        assert_eq!(r.expected_msg_seq(), 1);
    }

    #[test]
    fn out_of_order_message_sequence_buffered() {
        // Feed msg_seq=1 before msg_seq=0; only the second feed completes.
        let mut b0 = Vec::new();
        write_message(&mut b0, 1, 0, b"zero", 0);
        let mut b1 = Vec::new();
        write_message(&mut b1, 1, 1, b"one!", 0);

        let mut r = Reassembler::new();
        // Even though msg_seq=1 is "complete" inside its bucket, the
        // reassembler waits for msg_seq=0 to dispatch first.
        assert!(r.feed(read_fragment(&b1).unwrap()).is_none());
        // Now msg_seq=0 arrives → it dispatches; but msg_seq=1 stays buffered
        // until the next feed visits it. Our feed-driven design only emits
        // the message tied to the current feed; that's the documented API.
        let out0 = r.feed(read_fragment(&b0).unwrap()).unwrap();
        assert_eq!(out0.0, 1);
        assert_eq!(out0.1, b"zero");
        // Replay the b1 fragment (still in-buffer); the reassembler now
        // expects msg_seq=1 and the previously-buffered bytes complete it.
        let out1 = r.feed(read_fragment(&b1).unwrap()).unwrap();
        assert_eq!(out1.0, 1);
        assert_eq!(out1.1, b"one!");
    }
}
