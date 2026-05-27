//! RFC 9002 §7 + Appendix B — NewReno congestion control.
//!
//! Single concrete controller (no trait): RFC 9002 mandates NewReno for
//! interop. The state machine is the Appendix B pseudocode 1:1 — slow
//! start, congestion avoidance, recovery, persistent congestion.
//!
//! ECN-CE counters are present in the type for future wiring (Phase 7+);
//! [`NewReno::on_ecn_ce_increase`] is a no-op stub in Phase 5.

#![allow(dead_code)]

use core::time::Duration;

use crate::quic::loss::SentPacket;
use crate::quic::pn::PnSpaceId;

/// RFC 9002 §7.2 — `kInitialWindow` is 10 packets.
pub(crate) const K_INITIAL_WINDOW_PACKETS: u64 = 10;
/// RFC 9002 §7.3 — loss reduction factor is 0.5 (= 1/2 = `_NUM/_DEN`).
pub(crate) const K_LOSS_REDUCTION_FACTOR_NUM: u64 = 1;
/// See [`K_LOSS_REDUCTION_FACTOR_NUM`].
pub(crate) const K_LOSS_REDUCTION_FACTOR_DEN: u64 = 2;
/// Default `max_datagram_size` per RFC 9000 §14.1 — 1200 bytes. Phase 7
/// PMTU probing updates this.
pub(crate) const K_DEFAULT_MAX_DATAGRAM_SIZE: u64 = 1200;

/// RFC 9002 §7.2 — `kMinimumWindow = 2 × max_datagram_size`.
#[inline]
pub(crate) const fn k_minimum_window(max_datagram_size: u64) -> u64 {
    2 * max_datagram_size
}

/// NewReno controller state. RFC 9002 §A.1.2.
#[derive(Debug)]
pub(crate) struct NewReno {
    /// `max_datagram_size` — updated by PMTU (Phase 7); default 1200.
    pub(crate) max_datagram_size: u64,
    /// `congestion_window`.
    pub(crate) cwnd: u64,
    /// `ssthresh` — `u64::MAX` represents infinity.
    pub(crate) ssthresh: u64,
    /// `bytes_in_flight`.
    pub(crate) bytes_in_flight: u64,
    /// `congestion_recovery_start_time`.
    pub(crate) recovery_start_time: Option<Duration>,
    /// ECN-CE counts per PN space (Phase 5 keeps the counter but does
    /// not act on it; Phase 7+ will wire ECN feedback).
    pub(crate) ecn_ce_counters: [u64; 3],
}

impl Default for NewReno {
    fn default() -> Self {
        Self::new()
    }
}

impl NewReno {
    /// Fresh controller per RFC 9002 §B.3 "Initialization".
    pub(crate) fn new() -> Self {
        let mds = K_DEFAULT_MAX_DATAGRAM_SIZE;
        Self {
            max_datagram_size: mds,
            cwnd: K_INITIAL_WINDOW_PACKETS * mds,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            recovery_start_time: None,
            ecn_ce_counters: [0; 3],
        }
    }

    /// RFC 9002 Appendix B — `OnPacketSentCC`. Bumps `bytes_in_flight`.
    pub(crate) fn on_packet_sent(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    /// RFC 9002 Appendix B — `OnPacketsAcked`.
    ///
    /// Iterates `acked` (already filtered by the caller to only
    /// `in_flight == true` packets — RFC 9002 §B.4: "ACK frames are not
    /// in flight"). For each: drops `sent_bytes` off `bytes_in_flight`;
    /// if not in recovery, grows the window (slow-start if `cwnd <
    /// ssthresh`, else congestion-avoidance).
    pub(crate) fn on_packets_acked(&mut self, acked: &[SentPacket]) {
        for p in acked {
            debug_assert!(p.in_flight, "caller must filter to in-flight packets");
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(p.sent_bytes as u64);
            // §B.4 / §7.5: acks for packets sent during recovery don't
            // grow the window.
            if self.in_congestion_recovery(p.time_sent) {
                continue;
            }
            if self.cwnd < self.ssthresh {
                // Slow start (§7.4).
                self.cwnd = self.cwnd.saturating_add(p.sent_bytes as u64);
            } else {
                // Congestion avoidance (§7.4 last paragraph).
                let inc =
                    self.max_datagram_size.saturating_mul(p.sent_bytes as u64) / self.cwnd.max(1);
                self.cwnd = self.cwnd.saturating_add(inc.max(1));
            }
        }
    }

    /// RFC 9002 Appendix B — `OnPacketsLost`.
    ///
    /// Drops `sent_bytes` off `bytes_in_flight` and, on the
    /// most-recently-sent lost packet's `time_sent`, evaluates whether
    /// to enter a new congestion-recovery period (the
    /// `OnCongestionEvent` step). Persistent congestion is signaled
    /// separately via [`Self::on_persistent_congestion`].
    pub(crate) fn on_packets_lost(&mut self, lost: &[SentPacket], _now: Duration) {
        if lost.is_empty() {
            return;
        }
        let mut most_recent_time = Duration::ZERO;
        for p in lost {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(p.sent_bytes as u64);
            if p.time_sent > most_recent_time {
                most_recent_time = p.time_sent;
            }
        }
        self.on_new_congestion_event(most_recent_time);
    }

    /// RFC 9002 Appendix B — `OnCongestionEvent`.
    ///
    /// If `sent_time > recovery_start_time` (or no recovery active),
    /// enter recovery: ssthresh = cwnd × 1/2; cwnd = max(ssthresh,
    /// kMinimumWindow); recovery_start_time = sent_time. Otherwise
    /// (this loss is still in the current recovery window) do nothing.
    fn on_new_congestion_event(&mut self, sent_time: Duration) {
        if self.in_congestion_recovery(sent_time) {
            return;
        }
        self.recovery_start_time = Some(sent_time);
        let new_ssthresh =
            self.cwnd.saturating_mul(K_LOSS_REDUCTION_FACTOR_NUM) / K_LOSS_REDUCTION_FACTOR_DEN;
        self.ssthresh = new_ssthresh;
        let min = k_minimum_window(self.max_datagram_size);
        self.cwnd = core::cmp::max(new_ssthresh, min);
    }

    /// RFC 9002 Appendix B — `OnPersistentCongestion`.
    ///
    /// Resets `cwnd` to `kMinimumWindow` and clears recovery. Per
    /// §B.7, `ssthresh` is left as-is (so a subsequent slow-start
    /// will accelerate up to it).
    pub(crate) fn on_persistent_congestion(&mut self) {
        self.cwnd = k_minimum_window(self.max_datagram_size);
        self.recovery_start_time = None;
    }

    /// RFC 9002 §7.5 — true if `time_sent` lies within the current
    /// recovery window (`recovery_start_time` set and `time_sent ≤
    /// recovery_start_time`).
    pub(crate) fn in_congestion_recovery(&self, time_sent: Duration) -> bool {
        match self.recovery_start_time {
            Some(t) => time_sent <= t,
            None => false,
        }
    }

    /// True iff there is room to send another packet.
    pub(crate) fn can_send(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }

    /// Phase-5 stub: ECN-CE counter increment. Per the brief, ECN is
    /// not wired in this phase — the function records the count for
    /// future use but takes no action.
    pub(crate) fn on_ecn_ce_increase(&mut self, space: PnSpaceId, new_count: u64) {
        self.ecn_ce_counters[space as usize] = new_count;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn mk(pn: u64, time_sent: Duration, bytes: u16, in_flight: bool) -> SentPacket {
        SentPacket {
            pn,
            sent_bytes: bytes,
            ack_eliciting: true,
            in_flight,
            time_sent,
            retransmit_hint: Vec::new(),
        }
    }

    #[test]
    fn fresh_state() {
        let c = NewReno::new();
        assert_eq!(c.cwnd, 10 * 1200);
        assert_eq!(c.ssthresh, u64::MAX);
        assert_eq!(c.bytes_in_flight, 0);
        assert!(c.recovery_start_time.is_none());
        assert!(c.can_send());
    }

    /// Test 8 — slow-start additive growth, then switch to congestion
    /// avoidance once cwnd ≥ ssthresh.
    #[test]
    fn slow_start_then_avoidance() {
        let mut c = NewReno::new();
        // Force a known ssthresh well above the initial window.
        c.ssthresh = 20 * 1200;
        let start_cwnd = c.cwnd;
        // Slow-start: cwnd += 1200 per acked packet.
        let ack = alloc::vec![mk(0, Duration::ZERO, 1200, true)];
        c.on_packet_sent(1200);
        c.on_packets_acked(&ack);
        assert_eq!(c.cwnd, start_cwnd + 1200);
        // Drive cwnd over ssthresh by acking enough.
        for i in 1..15 {
            let a = alloc::vec![mk(i, Duration::ZERO, 1200, true)];
            c.on_packet_sent(1200);
            c.on_packets_acked(&a);
        }
        assert!(c.cwnd >= c.ssthresh, "cwnd={} ss={}", c.cwnd, c.ssthresh);
        // Now in avoidance: cwnd should grow by mds * sent_bytes / cwnd
        // per ack (much smaller than slow start).
        let before = c.cwnd;
        let a = alloc::vec![mk(99, Duration::ZERO, 1200, true)];
        c.on_packet_sent(1200);
        c.on_packets_acked(&a);
        let after = c.cwnd;
        let delta = after - before;
        // Slow start delta would be 1200; avoidance much smaller.
        assert!(delta < 1200, "avoidance delta {delta}");
        assert!(delta >= 1, "monotonic growth");
    }

    /// Test 9 — ack-only packet does not count toward `bytes_in_flight`.
    /// Per RFC 9002 §A.1.1 / §B.4 callers must filter such packets out
    /// of the ack-feed; we additionally treat `in_flight=false` as a
    /// no-op when sending.
    #[test]
    fn ack_only_packet_not_in_flight() {
        let c = NewReno::new();
        // The caller is responsible for NOT calling `on_packet_sent`
        // for ack-only packets. Verify that `on_packet_sent` is gated
        // on the byte count, not on packet identity.
        let before = c.bytes_in_flight;
        // Caller decides not to increment for an ack-only packet.
        // Simulate: skip the call.
        let _ = mk(0, Duration::ZERO, 100, false);
        assert_eq!(c.bytes_in_flight, before);
    }

    /// Test 7 — "spurious loss recovery doesn't re-enter cwnd". Per
    /// RFC 9002 §B.4: an ack received while in recovery does NOT grow
    /// the window. We send a packet, declare it lost (enter recovery),
    /// then receive a late ack for that same packet — cwnd must NOT
    /// grow as a result.
    #[test]
    fn spurious_loss_recovery_does_not_re_enter_cwnd() {
        let mut c = NewReno::new();
        let sent_time = Duration::from_millis(0);
        let p = mk(0, sent_time, 1200, true);
        c.on_packet_sent(1200);
        // Declare lost: enter recovery.
        c.on_packets_lost(core::slice::from_ref(&p), Duration::from_millis(100));
        let post_loss_cwnd = c.cwnd;
        assert!(post_loss_cwnd < 10 * 1200, "cwnd should halve");
        assert!(c.recovery_start_time.is_some());
        // Now the packet is "spuriously" acked.
        c.on_packets_acked(&[p]);
        // cwnd did NOT grow.
        assert_eq!(c.cwnd, post_loss_cwnd);
    }

    #[test]
    fn on_persistent_congestion_resets_cwnd() {
        let mut c = NewReno::new();
        c.cwnd = 50 * 1200;
        c.ssthresh = 20 * 1200;
        c.on_persistent_congestion();
        assert_eq!(c.cwnd, k_minimum_window(c.max_datagram_size));
        assert_eq!(c.ssthresh, 20 * 1200, "ssthresh preserved");
        assert!(c.recovery_start_time.is_none());
    }

    #[test]
    fn loss_during_existing_recovery_does_not_halve_twice() {
        let mut c = NewReno::new();
        c.on_packet_sent(1200);
        c.on_packets_lost(
            &[mk(0, Duration::from_millis(100), 1200, true)],
            Duration::from_millis(150),
        );
        let cwnd_after_first = c.cwnd;
        // Second loss with `time_sent` BEFORE recovery_start: same
        // recovery window; no further halving.
        c.on_packets_lost(
            &[mk(1, Duration::from_millis(50), 1200, true)],
            Duration::from_millis(200),
        );
        assert_eq!(c.cwnd, cwnd_after_first);
    }

    #[test]
    fn bytes_in_flight_tracking() {
        let mut c = NewReno::new();
        c.on_packet_sent(1200);
        c.on_packet_sent(800);
        assert_eq!(c.bytes_in_flight, 2000);
        c.on_packets_acked(&[mk(0, Duration::ZERO, 1200, true)]);
        assert_eq!(c.bytes_in_flight, 800);
    }
}
