//! RFC 9000 §8.2 — PATH_CHALLENGE / PATH_RESPONSE state machine.
//!
//! A QUIC endpoint validates a peer's reachability on a network path by
//! sending an 8-byte unpredictable value in a PATH_CHALLENGE frame
//! (`0x1A`). The peer echoes the same value in a PATH_RESPONSE frame
//! (`0x1B`). Receipt of a matching PATH_RESPONSE proves that the peer
//! could read and respond to the challenge at the address the local
//! endpoint sent it to.
//!
//! Phase 7 ships *the frame round-trip* — both sides answer
//! PATH_CHALLENGE with PATH_RESPONSE and accept a matching PATH_RESPONSE
//! to clear an outstanding challenge. Phase 7 does NOT ship path
//! migration itself (detecting that the peer moved to a new address);
//! that is a Phase 8+ concern.

use alloc::vec::Vec;
use core::time::Duration;

use crate::rng::RngCore;

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
        data
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

    /// Garbage-collect outstanding challenges older than `max_age`. RFC
    /// 9000 §8.2.4 says the timer SHOULD be at least 3×PTO; the caller
    /// supplies the value.
    pub(crate) fn gc(&mut self, now: Duration, max_age: Duration) {
        self.outstanding
            .retain(|(_, t)| now.saturating_sub(*t) <= max_age);
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
