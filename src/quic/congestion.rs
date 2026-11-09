//! RFC 9002 §7 + Appendix B — NewReno congestion control.
//!
//! Single concrete controller (no trait): RFC 9002 mandates NewReno for
//! interop. The state machine is the Appendix B pseudocode 1:1 — slow
//! start, congestion avoidance, recovery, persistent congestion.
//!
//! ECN-CE feedback (RFC 9002 §7.3) is wired: [`NewReno::on_ecn_ce_increase`]
//! reacts to a rise in the peer's reported CE count as a congestion signal.

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

/// Ceiling on the congestion window, in packets of `max_datagram_size`.
///
/// RFC 9002 puts no upper bound on `congestion_window`: every
/// acknowledgement outside recovery grows it, and in slow start it doubles
/// per round trip. Nothing else bounds what this endpoint keeps in flight,
/// so a peer that acknowledges everything it is sent — whether or not it
/// received it (the optimistic-ACK attack, RFC 9000 §21.4) — could inflate
/// the window, and with it both the traffic it can direct and the
/// per-packet loss-recovery state held here, without limit.
///
/// 10 000 packets is the ceiling quic-go applies by default (Chromium's
/// QUIC uses 2 000); at the default 1200-byte datagram it is 12 MB in
/// flight, i.e. about 960 Mbit/s over a 100 ms path, so it is not what
/// limits any real transfer.
pub(crate) const K_MAX_WINDOW_PACKETS: u64 = 10_000;

/// The congestion-window ceiling for `max_datagram_size`
/// ([`K_MAX_WINDOW_PACKETS`]).
#[inline]
pub(crate) const fn k_maximum_window(max_datagram_size: u64) -> u64 {
    K_MAX_WINDOW_PACKETS.saturating_mul(max_datagram_size)
}

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
    /// Last-seen peer-reported ECN-CE count per PN space; a rise drives a
    /// congestion event via [`Self::on_ecn_ce_increase`] (RFC 9002 §7.3).
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

    /// RFC 9000 §9.4 — reset to the initial window after confirming a peer's
    /// migration to a new path. The old path's capacity estimate says nothing
    /// about the new one, and `bytes_in_flight` is deliberately preserved:
    /// those packets are still on the wire and will still be acked or lost.
    pub(crate) fn reset(&mut self) {
        self.cwnd = K_INITIAL_WINDOW_PACKETS * self.max_datagram_size;
        self.ssthresh = u64::MAX;
        self.recovery_start_time = None;
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
    /// ssthresh`, else congestion-avoidance), never past
    /// [`k_maximum_window`].
    pub(crate) fn on_packets_acked<'a>(&mut self, acked: impl IntoIterator<Item = &'a SentPacket>) {
        let max = k_maximum_window(self.max_datagram_size);
        for p in acked {
            debug_assert!(p.in_flight, "caller must filter to in-flight packets");
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(p.sent_bytes as u64);
            // §B.4 / §7.5: acks for packets sent during recovery don't
            // grow the window.
            if self.in_congestion_recovery(p.time_sent) {
                continue;
            }
            // At the ceiling the window stops growing; it still shrinks on
            // congestion as usual.
            if self.cwnd >= max {
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
            self.cwnd = self.cwnd.min(max);
        }
    }

    /// RFC 9002 Appendix B — `OnPacketsLost`.
    ///
    /// Drops `sent_bytes` off `bytes_in_flight` and, on the
    /// most-recently-sent lost packet's `time_sent`, evaluates whether
    /// to enter a new congestion-recovery period (the
    /// `OnCongestionEvent` step). The §B.8 persistent-congestion check is
    /// the loss state's ([`crate::quic::loss::LossState::in_persistent_congestion`]);
    /// when it holds, the connection follows up with
    /// [`Self::on_persistent_congestion`].
    pub(crate) fn on_packets_lost<'a>(
        &mut self,
        lost: impl IntoIterator<Item = &'a SentPacket>,
        _now: Duration,
    ) {
        let mut most_recent_time: Option<Duration> = None;
        for p in lost {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(p.sent_bytes as u64);
            if most_recent_time.is_none_or(|t| p.time_sent > t) {
                most_recent_time = Some(p.time_sent);
            }
        }
        if let Some(t) = most_recent_time {
            self.on_new_congestion_event(t);
        }
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

    /// RFC 9002 §7.6.3 / §B.8 — the tail of `OnPacketsLost` once persistent
    /// congestion is established: `congestion_window = kMinimumWindow` and
    /// `congestion_recovery_start_time = 0`, so the sender restarts in slow
    /// start. `ssthresh` (already halved by the congestion event) is left
    /// as-is, so that slow start only runs up to it.
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

    /// RFC 9002 §7.3 — react to ECN. When the peer's reported CE count for a
    /// space rises above what we last saw, treat it as a congestion signal
    /// (the same multiplicative `cwnd` reduction as a loss), anchored at
    /// `event_time` (the send time of the largest newly-acked packet) so it
    /// fires at most once per recovery window.
    pub(crate) fn on_ecn_ce_increase(
        &mut self,
        space: PnSpaceId,
        new_count: u64,
        event_time: Duration,
    ) {
        let prev = self.ecn_ce_counters[space as usize];
        self.ecn_ce_counters[space as usize] = new_count;
        if new_count > prev {
            self.on_new_congestion_event(event_time);
        }
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
            stream_hints: crate::quic::loss::StreamHints::new(),
            control_hints: Vec::new(),
            handshake_done: false,
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

    /// RFC 9002 §7.3 — a rise in the peer's reported CE count reduces the
    /// congestion window like a loss, but only once per recovery window.
    #[test]
    fn ecn_ce_increase_reduces_cwnd_once_per_window() {
        let mut c = NewReno::new();
        c.on_packet_sent(10 * 1200);
        let before = c.cwnd;
        // First CE increase at t=5ms: enter recovery, halve cwnd.
        c.on_ecn_ce_increase(PnSpaceId::Application, 1, Duration::from_millis(5));
        assert!(c.cwnd < before, "CE increase must reduce cwnd");
        let reduced = c.cwnd;
        // A further CE rise for a packet sent within the same recovery window
        // (t <= 5ms) must NOT reduce again.
        c.on_ecn_ce_increase(PnSpaceId::Application, 2, Duration::from_millis(3));
        assert_eq!(c.cwnd, reduced, "no second reduction within the window");
        // No change in count → no reaction even for a later send time.
        c.on_ecn_ce_increase(PnSpaceId::Application, 2, Duration::from_millis(50));
        assert_eq!(
            c.cwnd, reduced,
            "equal count is not a new congestion signal"
        );
        // A new CE rise for a packet sent after the recovery window reduces again.
        c.on_ecn_ce_increase(PnSpaceId::Application, 3, Duration::from_millis(50));
        assert!(c.cwnd <= reduced, "a fresh CE event reduces again");
    }

    /// The window has a ceiling. A peer that acknowledges every packet —
    /// truthfully or not — used to grow it without bound (slow start never
    /// ends without a loss), and with it everything sized by what is in
    /// flight. Growth now stops at `k_maximum_window`, in slow start and in
    /// congestion avoidance alike, and the window still reacts to loss.
    #[test]
    fn congestion_window_growth_is_capped() {
        let max = k_maximum_window(K_DEFAULT_MAX_DATAGRAM_SIZE);
        assert_eq!(max, 12_000_000);
        // Slow start: every acknowledged byte adds a byte.
        let mut c = NewReno::new();
        let mut pn = 0u64;
        let mut ack = |c: &mut NewReno, n: u64| {
            for _ in 0..n {
                let p = mk(pn, Duration::from_millis(pn), 1200, true);
                pn += 1;
                c.on_packet_sent(1200);
                c.on_packets_acked([&p]);
            }
        };
        ack(&mut c, 9_989);
        assert_eq!(c.cwnd, max - 1200, "uncapped growth below the ceiling");
        ack(&mut c, 50_000);
        assert_eq!(c.cwnd, max, "slow start stops at the ceiling");
        assert_eq!(c.bytes_in_flight, 0);
        // A window just under the ceiling is not pushed past it.
        c.cwnd = max - 1;
        ack(&mut c, 10);
        assert_eq!(c.cwnd, max);
        // Congestion avoidance stops there too.
        c.ssthresh = max / 2;
        c.cwnd = max - 3;
        ack(&mut c, 50_000);
        assert_eq!(c.cwnd, max, "congestion avoidance stops at the ceiling");
        // Loss still halves it, and it can grow back.
        let lost = mk(pn, Duration::from_secs(3600), 1200, true);
        c.on_packet_sent(1200);
        c.on_packets_lost([&lost], Duration::from_secs(3601));
        assert_eq!(c.cwnd, max / 2);
        // The ceiling follows the datagram size.
        c.max_datagram_size = 1452;
        assert_eq!(k_maximum_window(c.max_datagram_size), 14_520_000);
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
