//! RFC 9000 §8.2 — PATH_CHALLENGE / PATH_RESPONSE state machine.
//!
//! A QUIC endpoint validates a peer's reachability on a network path by
//! sending an 8-byte unpredictable value in a PATH_CHALLENGE frame
//! (`0x1A`). The peer echoes the same value in a PATH_RESPONSE frame
//! (`0x1B`). Receipt of a matching PATH_RESPONSE proves that the peer
//! could read and respond to the challenge at the address the local
//! endpoint sent it to.
//!
//! This module owns three queues: challenges we have issued and are waiting
//! on (`outstanding`), challenges we have issued but not yet placed in a
//! packet (`pending_challenge`), and challenges the peer sent us that we owe
//! a response to (`pending_response`). `QuicConnection` drains the two
//! pending queues into PATH_CHALLENGE / PATH_RESPONSE frames and feeds
//! inbound frames back in. RFC 9000 §9 connection migration is driven from
//! `QuicConnection` on top of this state machine.
//!
//! [`Path`] is the per-address companion: the RFC 9000 §8.1 / §9.3.1
//! anti-amplification budget and validated flag of one network path.
//! `QuicConnection` keeps one for the address it is currently sending to and
//! parks the previous one inside its migration state, so a move to a new
//! address always starts from a fresh, unvalidated budget.

use alloc::vec::Vec;
use core::time::Duration;

use crate::rng::RngCore;

/// RFC 9000 §8.1 / §9.3.1 — the address-validation and anti-amplification
/// state of one network path (one peer address).
///
/// Until the peer has proven it can receive at the address — by echoing a
/// PATH_CHALLENGE (§8.2), by completing the handshake far enough to send
/// Handshake-level packets, or by returning a Retry token (§8.1.2) — an
/// endpoint MUST NOT send more than three times the bytes it has received
/// on that path. The limit is *per path*: bytes received on one address
/// never buy budget on another, so an attacker who spoofs a victim's source
/// address can only ever draw 3× what it sent *as* the victim, and a path
/// that fails validation takes its budget with it when it is abandoned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Path {
    /// Set once the peer has proven ownership of the address. Lifts the
    /// 3× limit for good; the counters below stop moving.
    pub(crate) validated: bool,
    /// Bytes received from the peer on this path while unvalidated.
    pub(crate) bytes_recv: u64,
    /// Bytes sent to the peer on this path while unvalidated.
    pub(crate) bytes_sent: u64,
}

impl Path {
    /// A path the peer has already proven it owns — the address a client
    /// was configured with, or one whose PATH_CHALLENGE came back.
    pub(crate) const fn validated() -> Self {
        Self {
            validated: true,
            bytes_recv: 0,
            bytes_sent: 0,
        }
    }

    /// Is there budget to send `n` more bytes on this path? Always true
    /// once validated; otherwise total outbound MUST NOT exceed 3× total
    /// inbound (RFC 9000 §8.1).
    #[inline]
    pub(crate) fn can_send(&self, n: usize) -> bool {
        if self.validated {
            return true;
        }
        let budget = self.bytes_recv.saturating_mul(3);
        self.bytes_sent.saturating_add(n as u64) <= budget
    }

    /// Records `n` outbound bytes against the budget. No-op once validated.
    #[inline]
    pub(crate) fn note_sent(&mut self, n: usize) {
        if !self.validated {
            self.bytes_sent = self.bytes_sent.saturating_add(n as u64);
        }
    }

    /// Records `n` inbound bytes, extending the budget by `3 × n`. No-op
    /// once validated.
    #[inline]
    pub(crate) fn note_recv(&mut self, n: usize) {
        if !self.validated {
            self.bytes_recv = self.bytes_recv.saturating_add(n as u64);
        }
    }
}

/// In-flight PATH_CHALLENGE state. Holds:
/// * Challenges this endpoint has issued and is waiting on a response for.
/// * Challenges received from the peer that this endpoint owes a response
///   to.
///
/// Both lists are bounded — a peer that floods PATH_CHALLENGE frames
/// doesn't get to allocate unbounded memory. The Phase 7 cap is 8 entries
/// in each direction; this is conservative (a healthy connection rarely
/// has more than 1 outstanding challenge at a time).
pub(crate) struct PathChallengeState {
    /// Challenges we've sent: `(data, sent_at)`. The peer's PATH_RESPONSE
    /// must echo `data` byte-for-byte (RFC 9000 §8.2.2).
    outstanding: Vec<([u8; 8], Duration)>,
    /// Challenges issued but not yet written into a packet. Drained by
    /// `QuicConnection::assemble_payload` into PATH_CHALLENGE frames.
    pending_challenge: Vec<[u8; 8]>,
    /// Challenges the peer sent us; we owe a PATH_RESPONSE carrying the
    /// same 8 bytes on the next outbound 1-RTT packet (RFC 9000 §8.2.2).
    pending_response: Vec<[u8; 8]>,
}

/// Bound on either-direction in-flight challenges. Tiny by design — a
/// well-behaved peer rarely keeps more than 1 challenge in flight.
const PATH_CHALLENGE_CAP: usize = 8;

impl PathChallengeState {
    /// Fresh state with no in-flight challenges.
    pub(crate) fn new() -> Self {
        Self {
            outstanding: Vec::new(),
            pending_challenge: Vec::new(),
            pending_response: Vec::new(),
        }
    }

    /// Generates a fresh 8-byte challenge from `rng` and records it as
    /// outstanding (with the current `now` as the send time). Returns the
    /// 8 bytes for the caller to wire into a PATH_CHALLENGE frame.
    ///
    /// If the outstanding queue is full, this drops the oldest entry —
    /// path validation is best-effort and the older challenge is most
    /// likely lost anyway.
    pub(crate) fn issue<R: RngCore>(&mut self, rng: &mut R, now: Duration) -> [u8; 8] {
        let mut data = [0u8; 8];
        rng.fill_bytes(&mut data);
        if self.outstanding.len() >= PATH_CHALLENGE_CAP {
            self.outstanding.remove(0);
        }
        self.outstanding.push((data, now));
        if self.pending_challenge.len() >= PATH_CHALLENGE_CAP {
            self.pending_challenge.remove(0);
        }
        self.pending_challenge.push(data);
        data
    }

    /// Re-queues `data` for transmission — used when a PATH_CHALLENGE is
    /// presumed lost and the validation attempt is retried (RFC 9000 §8.2.4).
    /// No-op if `data` is no longer outstanding (the peer already answered).
    pub(crate) fn requeue_challenge(&mut self, data: [u8; 8]) {
        if !self.outstanding.iter().any(|(d, _)| *d == data) {
            return;
        }
        if !self.pending_challenge.contains(&data) {
            self.pending_challenge.push(data);
        }
    }

    /// Records that the peer sent us a PATH_CHALLENGE. We owe them a
    /// PATH_RESPONSE carrying `data` on the next outbound 1-RTT packet.
    ///
    /// If the response queue is full, the new challenge is dropped (RFC
    /// 9000 §8.2 allows the responder to discard challenges it cannot
    /// keep up with).
    pub(crate) fn on_challenge(&mut self, data: [u8; 8]) {
        if self.pending_response.len() < PATH_CHALLENGE_CAP {
            // Avoid duplicating an identical outstanding response.
            if !self.pending_response.contains(&data) {
                self.pending_response.push(data);
            }
        }
    }

    /// Records a peer PATH_RESPONSE. Returns `true` if `data` matched an
    /// outstanding challenge (which is then removed from the list); the
    /// caller can use the return value to mark the path validated.
    /// Returns `false` for unsolicited / stale PATH_RESPONSE.
    pub(crate) fn on_response(&mut self, data: [u8; 8]) -> bool {
        use crate::ct::ConstantTimeEq;
        if let Some(idx) = self
            .outstanding
            .iter()
            .position(|(d, _)| bool::from(d.ct_eq(&data)))
        {
            self.outstanding.remove(idx);
            self.pending_challenge.retain(|d| *d != data);
            true
        } else {
            false
        }
    }

    /// Pops the next PATH_RESPONSE bytes we owe the peer (FIFO order),
    /// or `None` if none. The caller wires the returned bytes into a
    /// PATH_RESPONSE frame.
    pub(crate) fn pop_outbound_response(&mut self) -> Option<[u8; 8]> {
        if self.pending_response.is_empty() {
            None
        } else {
            Some(self.pending_response.remove(0))
        }
    }

    /// Pops the next PATH_CHALLENGE bytes awaiting transmission (FIFO), or
    /// `None` if none. The caller wires them into a PATH_CHALLENGE frame.
    pub(crate) fn pop_outbound_challenge(&mut self) -> Option<[u8; 8]> {
        if self.pending_challenge.is_empty() {
            None
        } else {
            Some(self.pending_challenge.remove(0))
        }
    }

    /// True iff a PATH_CHALLENGE is waiting to be written into a packet.
    pub(crate) fn has_pending_challenge(&self) -> bool {
        !self.pending_challenge.is_empty()
    }

    /// Number of PATH_CHALLENGE + PATH_RESPONSE frames still waiting to be
    /// written into a packet. A drop between two readings means a datagram
    /// carrying at least one of them was built in between.
    pub(crate) fn pending_len(&self) -> usize {
        self.pending_challenge.len() + self.pending_response.len()
    }

    /// Garbage-collect outstanding challenges older than `max_age`. RFC
    /// 9000 §8.2.4 says the timer SHOULD be at least 3×PTO; the caller
    /// supplies the value.
    pub(crate) fn gc(&mut self, now: Duration, max_age: Duration) {
        self.outstanding
            .retain(|(_, t)| now.saturating_sub(*t) <= max_age);
        let live = self.outstanding.clone();
        self.pending_challenge
            .retain(|d| live.iter().any(|(o, _)| o == d));
    }

    /// True iff there is at least one outstanding challenge awaiting a
    /// response.
    pub(crate) fn has_outstanding(&self) -> bool {
        !self.outstanding.is_empty()
    }

    /// True iff we owe the peer at least one PATH_RESPONSE.
    pub(crate) fn has_pending_response(&self) -> bool {
        !self.pending_response.is_empty()
    }
}

impl Default for PathChallengeState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    /// RFC 9000 §8.1 — the 3× rule, and its lifting on validation.
    #[test]
    fn path_budget_is_three_times_bytes_received() {
        let mut p = Path::default();
        assert!(!p.can_send(1), "nothing received: nothing may be sent");
        assert!(p.can_send(0));
        p.note_recv(100);
        assert!(p.can_send(300));
        assert!(!p.can_send(301));
        p.note_sent(200);
        assert!(p.can_send(100));
        assert!(!p.can_send(101));
        p.validated = true;
        assert!(p.can_send(usize::MAX / 4));
        // The counters freeze once validated.
        p.note_sent(5);
        p.note_recv(5);
        assert_eq!((p.bytes_sent, p.bytes_recv), (200, 100));
        assert!(Path::validated().can_send(1 << 40));
    }

    #[test]
    fn path_challenge_response_roundtrip() {
        let mut p = PathChallengeState::new();
        let mut rng = HmacDrbg::<Sha256>::new(b"path-test", b"nonce", &[]);
        let data = p.issue(&mut rng, Duration::from_millis(0));
        assert!(p.has_outstanding());
        // Peer echoes the same bytes — must match.
        assert!(p.on_response(data));
        assert!(!p.has_outstanding());
        // Replay of the same response is rejected (already removed).
        assert!(!p.on_response(data));
    }

    #[test]
    fn path_challenge_rejects_unsolicited() {
        let mut p = PathChallengeState::new();
        // We never issued anything → any PATH_RESPONSE is unsolicited.
        assert!(!p.on_response([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn path_challenge_queues_response() {
        let mut p = PathChallengeState::new();
        let chal = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8];
        p.on_challenge(chal);
        assert!(p.has_pending_response());
        let popped = p.pop_outbound_response().expect("response queued");
        assert_eq!(popped, chal);
        assert!(!p.has_pending_response());
        // After pop, the next pop returns None.
        assert!(p.pop_outbound_response().is_none());
    }

    #[test]
    fn path_challenge_dedups_pending_response() {
        let mut p = PathChallengeState::new();
        let chal = [0u8, 1, 2, 3, 4, 5, 6, 7];
        p.on_challenge(chal);
        p.on_challenge(chal); // duplicate, should not enqueue twice
        let _ = p.pop_outbound_response().expect("one response");
        assert!(p.pop_outbound_response().is_none());
    }

    #[test]
    fn path_challenge_gc_expires_old() {
        let mut p = PathChallengeState::new();
        let mut rng = HmacDrbg::<Sha256>::new(b"gc", b"n", &[]);
        let _ = p.issue(&mut rng, Duration::from_secs(0));
        let _ = p.issue(&mut rng, Duration::from_secs(10));
        // GC with max_age = 5s at now = 12s → first (age 12s) drops,
        // second (age 2s) survives.
        p.gc(Duration::from_secs(12), Duration::from_secs(5));
        // One challenge remains.
        assert!(p.has_outstanding());
        // GC with max_age = 1s at now = 12s → both drop.
        p.gc(Duration::from_secs(12), Duration::from_secs(1));
        assert!(!p.has_outstanding());
    }

    #[test]
    fn path_challenge_outstanding_capped() {
        let mut p = PathChallengeState::new();
        let mut rng = HmacDrbg::<Sha256>::new(b"cap", b"n", &[]);
        // Fill beyond the cap; the oldest must drop off.
        let mut first = None;
        for i in 0..(PATH_CHALLENGE_CAP + 3) {
            let d = p.issue(&mut rng, Duration::from_millis(i as u64));
            if first.is_none() {
                first = Some(d);
            }
        }
        // The very first challenge was bumped out.
        let first = first.unwrap();
        assert!(
            !p.on_response(first),
            "oldest challenge should have dropped"
        );
    }
}
