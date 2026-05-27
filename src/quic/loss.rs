//! Minimal PTO timer for the Phase-4 handshake.
//!
//! Full RFC 9002 loss recovery (RTT estimator with smoothed_rtt /
//! rttvar / min_rtt, OnPacketSent / OnAckReceived / DetectLost, in-flight
//! tracking per packet) lands in Phase 5. This phase only needs:
//!
//! * a single Probe Timeout (PTO, RFC 9002 §6.2) computed from
//!   `kInitialRtt = 333 ms` (RFC 9002 §6.2.2): no RTT sample yet, so PTO
//!   = `kInitialRtt * (1 + max_ack_delay/kInitialRtt) * 2^backoff` per
//!   the spec, which reduces to `2 * kInitialRtt * 2^backoff` until a
//!   `max_ack_delay` parameter is negotiated;
//! * an exponential backoff on consecutive timeouts, capped at 60 s per
//!   RFC 9002 §6.2.2;
//! * a single arm/disarm/fire surface used by [`QuicConnection`]
//!   ([`PtoState::next_deadline`], [`PtoState::on_fire`],
//!   [`PtoState::on_handshake_progress`]).
//!
//! "Progress" in this phase means "we received any handshake or 1-RTT
//! packet from the peer" — that resets the backoff and re-arms the timer
//! from `now`.

#![allow(dead_code)]

use core::time::Duration;

/// RFC 9002 §6.2.2 "kInitialRtt": 333 milliseconds. Used as the PTO when
/// no RTT sample is available.
pub(crate) const K_INITIAL_RTT: Duration = Duration::from_millis(333);

/// RFC 9002 §6.2.2 PTO upper bound after backoff. The spec says
/// "MUST be capped to at most one hour" (loosely); in practice every
/// implementation caps at 60 s and so do we.
pub(crate) const PTO_CAP: Duration = Duration::from_secs(60);

/// Minimal PTO state, sufficient for Phase 4.
#[derive(Debug, Clone, Default)]
pub(crate) struct PtoState {
    /// Wall-clock-since-start at which the PTO last armed. The deadline
    /// is `armed_at + base_pto * 2^backoff`.
    armed_at: Option<Duration>,
    /// Consecutive PTO firings since the last progress signal.
    backoff: u32,
}

impl PtoState {
    /// Fresh state — not armed.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Arms / re-arms the PTO timer at `now`.
    pub(crate) fn arm(&mut self, now: Duration) {
        self.armed_at = Some(now);
    }

    /// Disarms the PTO timer entirely (called when the handshake
    /// completes and there are no in-flight ack-eliciting packets).
    pub(crate) fn disarm(&mut self) {
        self.armed_at = None;
        self.backoff = 0;
    }

    /// True if currently armed.
    pub(crate) fn is_armed(&self) -> bool {
        self.armed_at.is_some()
    }

    /// Current PTO duration including backoff, capped at [`PTO_CAP`].
    pub(crate) fn current_pto(&self) -> Duration {
        // 2 * kInitialRtt * 2^backoff.
        // (We don't have an RTT sample, and we don't track
        // `max_ack_delay` separately at Initial/Handshake levels yet.)
        let mult = 1u64.checked_shl(self.backoff).unwrap_or(u64::MAX);
        let base = K_INITIAL_RTT.saturating_mul(2);
        match base.checked_mul(u32::try_from(mult).unwrap_or(u32::MAX)) {
            Some(d) if d <= PTO_CAP => d,
            _ => PTO_CAP,
        }
    }

    /// Time-until-fire from `now`, or `None` if not armed. Returns
    /// `Some(Duration::ZERO)` when the deadline has already passed.
    pub(crate) fn next_deadline(&self, now: Duration) -> Option<Duration> {
        let armed_at = self.armed_at?;
        let deadline = armed_at.saturating_add(self.current_pto());
        Some(deadline.saturating_sub(now))
    }

    /// True if the deadline has already passed at `now`.
    pub(crate) fn has_fired(&self, now: Duration) -> bool {
        match self.next_deadline(now) {
            Some(d) => d == Duration::ZERO,
            None => false,
        }
    }

    /// Records that the PTO fired: bumps the backoff, re-arms from
    /// `now`, and caps the backoff so that `current_pto` cannot exceed
    /// [`PTO_CAP`]. The caller invokes retransmit *separately* — this
    /// function doesn't know about the CRYPTO queue.
    pub(crate) fn on_fire(&mut self, now: Duration) {
        self.backoff = self.backoff.saturating_add(1);
        // Saturate so subsequent `current_pto` calls clamp to PTO_CAP.
        if self.backoff > 16 {
            self.backoff = 16;
        }
        self.armed_at = Some(now);
    }

    /// Records that handshake progress has been observed (we processed an
    /// ack-eliciting packet from the peer). Resets backoff and re-arms.
    pub(crate) fn on_handshake_progress(&mut self, now: Duration) {
        self.backoff = 0;
        self.armed_at = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_is_disarmed() {
        let s = PtoState::new();
        assert!(!s.is_armed());
        assert!(s.next_deadline(Duration::ZERO).is_none());
        assert!(!s.has_fired(Duration::ZERO));
    }

    #[test]
    fn arm_at_zero_fires_after_initial_pto() {
        let mut s = PtoState::new();
        s.arm(Duration::ZERO);
        // Initial PTO = 2 * 333 ms = 666 ms.
        assert_eq!(s.current_pto(), Duration::from_millis(666));
        assert!(!s.has_fired(Duration::from_millis(500)));
        assert!(s.has_fired(Duration::from_millis(666)));
        assert!(s.has_fired(Duration::from_secs(10)));
    }

    #[test]
    fn backoff_doubles_pto() {
        let mut s = PtoState::new();
        s.arm(Duration::ZERO);
        s.on_fire(Duration::from_millis(666));
        assert_eq!(s.current_pto(), Duration::from_millis(1332));
        s.on_fire(Duration::from_millis(2000));
        assert_eq!(s.current_pto(), Duration::from_millis(2664));
    }

    #[test]
    fn backoff_caps_at_pto_cap() {
        let mut s = PtoState::new();
        s.arm(Duration::ZERO);
        for _ in 0..40 {
            s.on_fire(Duration::ZERO);
        }
        assert!(s.current_pto() <= PTO_CAP);
        assert!(s.current_pto() >= Duration::from_secs(30));
    }

    #[test]
    fn progress_resets_backoff() {
        let mut s = PtoState::new();
        s.arm(Duration::ZERO);
        s.on_fire(Duration::from_millis(666));
        s.on_fire(Duration::from_millis(2000));
        s.on_handshake_progress(Duration::from_secs(5));
        assert_eq!(s.current_pto(), Duration::from_millis(666));
    }

    #[test]
    fn disarm_clears_state() {
        let mut s = PtoState::new();
        s.arm(Duration::ZERO);
        s.on_fire(Duration::from_millis(666));
        s.disarm();
        assert!(!s.is_armed());
        assert!(s.next_deadline(Duration::ZERO).is_none());
    }
}
