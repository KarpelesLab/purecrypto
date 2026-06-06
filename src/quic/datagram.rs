//! RFC 9221 — Unreliable Datagram Extension for QUIC.
//!
//! DATAGRAM frames (frame types 0x30 / 0x31, RFC 9221 §4) provide
//! unreliable, in-flight delivery of opaque application payloads at the
//! 1-RTT encryption level. Unlike STREAM data they are NOT retransmitted
//! on loss — that is the whole point — but they ARE ack-eliciting and
//! they DO count against congestion control (the QUIC packet carrying
//! the frame is normal in every other respect).
//!
//! Both endpoints MUST advertise the `max_datagram_frame_size`
//! transport parameter (codepoint 0x20, RFC 9221 §3) before sending
//! DATAGRAM frames; the value is the maximum *frame* size (frame type
//! byte + varint length + payload) the endpoint is willing to accept.
//! An advertised value of 0 (the default when the parameter is absent)
//! means the peer refuses DATAGRAM frames.

#![allow(dead_code)]

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::quic::varint;
use crate::tls::Error;

/// Cap on the number of buffered inbound DATAGRAM payloads awaiting
/// application drain. DATAGRAM frames are NOT flow-controlled (RFC 9221
/// §4), so without a cap a peer could grow [`DatagramQueues::inbound`]
/// without bound — a memory-exhaustion DoS. Mirrors the spirit of
/// [`crate::quic::crypto_buf::MAX_PENDING_FRAGMENTS`]. RFC 9221 §5: "a
/// receiver MAY drop datagrams", so once the cap is hit we drop the new
/// arrival rather than close the connection.
pub(crate) const MAX_INBOUND_DATAGRAMS: usize = 64;

/// Cap on the total bytes buffered across the inbound DATAGRAM queue.
/// Complements [`MAX_INBOUND_DATAGRAMS`] so that a flood of large
/// datagrams is also bounded. Mirrors
/// [`crate::quic::crypto_buf::MAX_PENDING_CRYPTO_BYTES`].
pub(crate) const MAX_INBOUND_DATAGRAM_BYTES: usize = 1024 * 1024;

/// Per-connection outbound + inbound DATAGRAM queues.
///
/// Outbound: the application calls
/// [`crate::quic::QuicConnection::send_datagram`], which pushes into
/// `outbound`; the 1-RTT packet packer calls [`Self::pop_outbound`] to
/// carve one frame's worth of bytes into the next packet.
///
/// Inbound: the frame dispatcher calls [`Self::enqueue_inbound`] when it
/// sees a `Frame::Datagram`; the application drains via
/// [`crate::quic::QuicConnection::recv_datagram`] /
/// [`Self::recv`].
pub(crate) struct DatagramQueues {
    /// Pending outbound payloads. Drained FIFO by [`Self::pop_outbound`].
    pub(crate) outbound: VecDeque<Vec<u8>>,
    /// Received payloads awaiting application drain.
    pub(crate) inbound: VecDeque<Vec<u8>>,
    /// Running total of bytes buffered in `inbound`, kept in sync with
    /// every push/pop so the byte cap can be enforced in O(1) without
    /// rescanning the deque.
    inbound_bytes: usize,
    /// Peer-advertised `max_datagram_frame_size`. 0 means the peer
    /// refuses DATAGRAM (either absent transport parameter or explicit
    /// 0). RFC 9221 §3.
    pub(crate) peer_max_frame_size: u64,
    /// Our advertised `max_datagram_frame_size`. Used purely informational
    /// here; the encode side honours `peer_max_frame_size` only.
    pub(crate) our_max_frame_size: u64,
}

impl DatagramQueues {
    /// Build a fresh pair of queues. Caller supplies the optional
    /// transport-parameter values from each side; `None` is equivalent to
    /// `Some(0)` (no DATAGRAM support).
    pub(crate) fn new(peer_param: Option<u64>, our_param: Option<u64>) -> Self {
        Self {
            outbound: VecDeque::new(),
            inbound: VecDeque::new(),
            inbound_bytes: 0,
            peer_max_frame_size: peer_param.unwrap_or(0),
            our_max_frame_size: our_param.unwrap_or(0),
        }
    }

    /// True when the peer has advertised support for DATAGRAM frames
    /// (advertised value > 0). RFC 9221 §3 — endpoints that didn't
    /// advertise the parameter MUST NOT send DATAGRAM frames.
    pub(crate) fn peer_accepts(&self) -> bool {
        self.peer_max_frame_size > 0
    }

    /// Queue `data` for the next outbound 1-RTT packet. Returns
    /// [`Error::InappropriateState`] if the peer hasn't advertised
    /// support; returns [`Error::IllegalParameter`] if the resulting
    /// frame would exceed the peer's declared max size.
    ///
    /// Encoded frame layout (RFC 9221 §4):
    ///   1 byte frame type (0x31, length-prefixed form) ||
    ///   varint(length) ||
    ///   `data`
    ///
    /// We always plan in terms of the length-prefixed form (0x31) since
    /// it lets the packer place the frame anywhere in a packet payload;
    /// the lengthless form (0x30) is just an optimisation when this is
    /// the last frame.
    pub(crate) fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        if !self.peer_accepts() {
            return Err(Error::InappropriateState);
        }
        let frame_len = 1 + varint::encoded_len(data.len() as u64) + data.len();
        if (frame_len as u64) > self.peer_max_frame_size {
            return Err(Error::IllegalParameter);
        }
        self.outbound.push_back(data.to_vec());
        Ok(())
    }

    /// Drain one received datagram in arrival order, or `None` if the
    /// inbound queue is empty.
    pub(crate) fn recv(&mut self) -> Option<Vec<u8>> {
        let d = self.inbound.pop_front()?;
        self.inbound_bytes -= d.len();
        Some(d)
    }

    /// Pop the next outbound datagram if it fits in `budget` bytes
    /// (frame overhead = 1 byte type + varint(len)). Returns `None` if
    /// the queue is empty or the head datagram doesn't fit.
    ///
    /// The returned `Vec` is the raw payload bytes; the caller wraps it
    /// in a `Frame::Datagram { data: &payload }` and encodes via the
    /// standard frame codec, which always emits the length-prefixed
    /// 0x31 form.
    pub(crate) fn pop_outbound(&mut self, budget: usize) -> Option<Vec<u8>> {
        let head = self.outbound.front()?;
        let frame_len = 1 + varint::encoded_len(head.len() as u64) + head.len();
        if frame_len > budget {
            return None;
        }
        self.outbound.pop_front()
    }

    /// Push a received payload to the inbound queue. Called by the
    /// frame dispatcher when a `Frame::Datagram` is parsed.
    ///
    /// DATAGRAM frames are NOT flow-controlled (RFC 9221 §4), so the
    /// inbound queue is bounded by both a count cap
    /// ([`MAX_INBOUND_DATAGRAMS`]) and a total-byte cap
    /// ([`MAX_INBOUND_DATAGRAM_BYTES`]). When either would be exceeded
    /// the new datagram is DROPPED (RFC 9221 §5: "a receiver MAY drop
    /// datagrams") and `false` is returned — the connection is NOT
    /// closed. Returns `true` when the datagram was buffered.
    pub(crate) fn enqueue_inbound(&mut self, data: Vec<u8>) -> bool {
        if self.inbound.len() >= MAX_INBOUND_DATAGRAMS
            || self.inbound_bytes.saturating_add(data.len()) > MAX_INBOUND_DATAGRAM_BYTES
        {
            return false;
        }
        self.inbound_bytes += data.len();
        self.inbound.push_back(data);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_refused_if_peer_didnt_advertise() {
        let mut q = DatagramQueues::new(None, Some(1200));
        let r = q.send(b"hi");
        assert!(matches!(r, Err(Error::InappropriateState)));
        // Same with explicit 0.
        let mut q2 = DatagramQueues::new(Some(0), Some(1200));
        let r2 = q2.send(b"hi");
        assert!(matches!(r2, Err(Error::InappropriateState)));
    }

    #[test]
    fn send_rejects_payload_exceeding_peer_max() {
        let mut q = DatagramQueues::new(Some(100), Some(1200));
        // 200-byte payload is too big.
        let big = alloc::vec![0xABu8; 200];
        let r = q.send(&big);
        assert!(matches!(r, Err(Error::IllegalParameter)));
        // Small one fits.
        assert!(q.send(b"ok").is_ok());
    }

    #[test]
    fn send_then_pop_round_trips() {
        let mut q = DatagramQueues::new(Some(1200), Some(1200));
        q.send(b"hello").expect("send");
        q.send(b"world").expect("send");
        // The first datagram is "hello" (5 bytes) + 1 byte type + 1 byte
        // varint length = 7 bytes; fits in 7.
        let popped = q.pop_outbound(7).expect("pop");
        assert_eq!(popped, b"hello".to_vec());
        // Budget of 1 (less than the frame header) → None even though
        // the queue isn't empty.
        let no = q.pop_outbound(1);
        assert!(no.is_none());
        let popped2 = q.pop_outbound(1024).expect("pop second");
        assert_eq!(popped2, b"world".to_vec());
        assert!(q.pop_outbound(1024).is_none());
    }

    #[test]
    fn recv_round_trips() {
        let mut q = DatagramQueues::new(Some(1200), Some(1200));
        q.enqueue_inbound(b"a".to_vec());
        q.enqueue_inbound(b"b".to_vec());
        assert_eq!(q.recv().unwrap(), b"a".to_vec());
        assert_eq!(q.recv().unwrap(), b"b".to_vec());
        assert!(q.recv().is_none());
    }

    #[test]
    fn inbound_queue_caps_by_count_and_drops() {
        let mut q = DatagramQueues::new(Some(1200), Some(1200));
        // Fill exactly to the count cap.
        for _ in 0..MAX_INBOUND_DATAGRAMS {
            assert!(q.enqueue_inbound(b"x".to_vec()));
        }
        assert_eq!(q.inbound.len(), MAX_INBOUND_DATAGRAMS);
        // The next one is dropped, not buffered, and does NOT error.
        assert!(!q.enqueue_inbound(b"y".to_vec()));
        assert_eq!(q.inbound.len(), MAX_INBOUND_DATAGRAMS);
        // Draining one frees a slot.
        assert_eq!(q.recv().unwrap(), b"x".to_vec());
        assert!(q.enqueue_inbound(b"z".to_vec()));
    }

    #[test]
    fn inbound_queue_caps_by_bytes_and_drops() {
        let mut q = DatagramQueues::new(Some(1200), Some(1200));
        // One payload just under the byte cap fits.
        let big = alloc::vec![0u8; MAX_INBOUND_DATAGRAM_BYTES - 1];
        assert!(q.enqueue_inbound(big));
        // A 2-byte payload would push total over the cap → dropped.
        assert!(!q.enqueue_inbound(b"no".to_vec()));
        // A 1-byte payload exactly reaches the cap → accepted.
        assert!(q.enqueue_inbound(b"k".to_vec()));
        // Draining the big one restores headroom.
        let _ = q.recv().unwrap();
        assert!(q.enqueue_inbound(alloc::vec![0u8; 1024]));
    }

    #[test]
    fn peer_accepts_reflects_advertised_value() {
        assert!(!DatagramQueues::new(None, None).peer_accepts());
        assert!(!DatagramQueues::new(Some(0), None).peer_accepts());
        assert!(DatagramQueues::new(Some(1), None).peer_accepts());
        assert!(DatagramQueues::new(Some(1200), None).peer_accepts());
    }
}
