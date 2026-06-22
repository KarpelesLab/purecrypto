//! RFC 9002 §6 — loss detection.
//!
//! Full implementation of the RFC 9002 loss recovery state machine. Tracks
//! per-PN-space [`SentPacket`] state, the RTT estimator (latest_rtt /
//! smoothed_rtt / rttvar / min_rtt — RFC 9002 §5.3), the PTO timer
//! (RFC 9002 §6.2), and packet-threshold + time-threshold loss detection
//! (RFC 9002 §6.1).
//!
//! Pseudocode in Appendix A of RFC 9002 is followed step-for-step; each
//! non-trivial function names the section it implements. Where the
//! pseudocode references `loss_detection_timer`, we materialize that as
//! [`LossState::loss_detection_timer`].
//!
//! In addition to the RFC 9002 state machine, this module preserves the
//! Phase-4 driver-facing shim API ([`LossState::arm`],
//! [`LossState::disarm`], [`LossState::has_fired`],
//! [`LossState::next_deadline`], [`LossState::on_fire`],
//! [`LossState::on_handshake_progress`], [`LossState::is_armed`]) so the
//! connection-level call sites stay surgical.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ops::RangeInclusive;
use core::time::Duration;

use crate::quic::pn::PnSpaceId;

/// RFC 9002 §6.1.1 — `kPacketThreshold = 3`.
pub(crate) const K_PACKET_THRESHOLD: u64 = 3;

/// RFC 9002 §6.1.2 — `kGranularity = 1 ms`.
pub(crate) const K_GRANULARITY: Duration = Duration::from_millis(1);

/// RFC 9002 §6.2.2 — `kInitialRtt = 333 ms`. Used when no RTT sample is
/// available yet.
pub(crate) const K_INITIAL_RTT: Duration = Duration::from_millis(333);

/// RFC 9002 §7.6 — `kPersistentCongestionThreshold = 3`.
pub(crate) const K_PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

/// PTO backoff multiplier cap. Spec leaves this unbounded but every
/// implementation caps to avoid `Duration` overflow; we cap at `1 << 16`
/// (deeper than any realistic deployment will reach before the idle
/// timer fires).
pub(crate) const PTO_BACKOFF_CAP: u32 = 16;

/// Bytes-and-metadata for one packet we have sent and are tracking until
/// ack or loss. Per RFC 9002 §A.1.1 "Sent Packet Fields".
#[derive(Debug, Clone)]
pub(crate) struct SentPacket {
    /// Packet number.
    pub(crate) pn: u64,
    /// Total bytes-on-the-wire for this packet (header + ciphertext + tag).
    pub(crate) sent_bytes: u16,
    /// `ack_eliciting` (RFC 9002 §A.1.1).
    pub(crate) ack_eliciting: bool,
    /// `in_flight` (RFC 9002 §2). Packets carrying only ACK and/or
    /// CONNECTION_CLOSE frames do NOT count in flight (RFC 9002 §A.1.1).
    pub(crate) in_flight: bool,
    /// `time_sent` (RFC 9002 §A.1.1) — monotonic-since-connection-start.
    pub(crate) time_sent: Duration,
    /// Opaque per-frame retransmit hints. The connection records what
    /// CRYPTO bytes the packet carried; on loss it re-queues the same
    /// byte range. Phase-5 encoding is documented in
    /// [`build_retransmit_hint`].
    pub(crate) retransmit_hint: Vec<u8>,
    /// STREAM chunks this packet carried. On ack, the connection
    /// confirms the ranges (pruning the sender's retransmission state);
    /// on loss, it queues them for retransmission.
    pub(crate) stream_hints: Vec<StreamHint>,
}

/// One STREAM frame's `(id, offset, length, fin)` as carried by a sent
/// packet — the stream-data analogue of [`CryptoHint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StreamHint {
    /// Stream identifier.
    pub(crate) id: u64,
    /// Stream byte offset of the chunk.
    pub(crate) offset: u64,
    /// Chunk length in bytes (0 for a FIN-only frame).
    pub(crate) length: u64,
    /// FIN bit of the frame.
    pub(crate) fin: bool,
}

/// Per-PN-space state. RFC 9002 keeps three independent sets of sent
/// packets and per-space `largest_acked_packet` / `loss_time` /
/// `time_of_last_ack_eliciting_packet` (§A.1.1).
#[derive(Debug, Default)]
pub(crate) struct PerSpace {
    /// Outstanding sent packets, keyed by PN.
    pub(crate) sent_packets: BTreeMap<u64, SentPacket>,
    /// `largest_acked_packet` — RFC 9002 §A.1.1.
    pub(crate) largest_acked_packet: Option<u64>,
    /// `loss_time` — RFC 9002 §A.1.1.
    pub(crate) loss_time: Option<Duration>,
    /// `time_of_last_ack_eliciting_packet` — RFC 9002 §A.1.1.
    pub(crate) time_of_last_ack_eliciting_packet: Option<Duration>,
}

/// Full RFC 9002 loss-recovery state.
#[derive(Debug)]
pub(crate) struct LossState {
    // ---- RTT estimator (RFC 9002 §5.3) ------------------------------------
    /// `latest_rtt` (§A.1.2). `Duration::ZERO` if no sample yet.
    pub(crate) latest_rtt: Duration,
    /// `smoothed_rtt` (§A.1.2). Initialized to [`K_INITIAL_RTT`] per §5.3.
    pub(crate) smoothed_rtt: Duration,
    /// `rttvar` (§A.1.2). Initialized to `kInitialRtt / 2` per §5.3.
    pub(crate) rttvar: Duration,
    /// `min_rtt` (§A.1.2). `Duration::MAX` sentinel until first sample.
    pub(crate) min_rtt: Duration,
    /// Set when the first RTT sample lands (§5.3).
    pub(crate) first_rtt_sample: Option<Duration>,
    /// Peer's advertised `max_ack_delay` (RFC 9000 §18.2). 25 ms default.
    pub(crate) max_ack_delay: Duration,
    /// Peer's advertised `ack_delay_exponent` (RFC 9000 §18.2). 3 default.
    /// Recorded for posterity — for Initial+Handshake spaces RFC 9000
    /// §13.2.5 forces exponent 3 regardless.
    pub(crate) ack_delay_exponent: u8,

    // ---- PTO + loss-detection timer (RFC 9002 §6.2 + Appendix A) ----------
    /// `pto_count` (§A.1.2): consecutive PTO firings without progress.
    pub(crate) pto_count: u32,
    /// `loss_detection_timer` (§A.1.2) — absolute deadline.
    pub(crate) loss_detection_timer: Option<Duration>,

    /// Per-PN-space state, indexed by `PnSpaceId as usize`.
    pub(crate) per_space: [PerSpace; 3],

    // ---- Persistent-congestion bookkeeping (RFC 9002 §7.6) ----------------
    /// Time of the most recent ack-eliciting packet whose ack would
    /// reset PTO progress. Used by the persistent-congestion
    /// approximation described in [`Self::on_timeout`].
    pub(crate) last_progress_time: Option<Duration>,
    /// True once a PTO has fired without subsequent ack progress. Cleared
    /// by [`Self::on_ack_received`] when any newly-acked packet shows up.
    pub(crate) pto_outstanding: bool,
    /// True once we have flagged a persistent-congestion event to the
    /// caller. Cleared once the caller has consumed
    /// [`Self::take_persistent_congestion`]. Used so the same event isn't
    /// reported twice.
    pub(crate) persistent_congestion_pending: bool,

    // ---- Phase-4 shim state -----------------------------------------------
    /// Phase-4-compatible "armed-at" anchor. Drives the simple
    /// [`arm`/`has_fired`/`next_deadline`/`on_fire`] surface used by
    /// the connection driver. Independent of `loss_detection_timer`,
    /// which is RFC-9002-driven.
    shim_armed_at: Option<Duration>,
}

impl LossState {
    /// Fresh state per RFC 9002 §A.4 "Initialization".
    pub(crate) fn new() -> Self {
        Self {
            latest_rtt: Duration::ZERO,
            smoothed_rtt: K_INITIAL_RTT,
            rttvar: K_INITIAL_RTT / 2,
            min_rtt: Duration::MAX,
            first_rtt_sample: None,
            max_ack_delay: Duration::from_millis(25),
            ack_delay_exponent: 3,
            pto_count: 0,
            loss_detection_timer: None,
            per_space: [
                PerSpace::default(),
                PerSpace::default(),
                PerSpace::default(),
            ],
            last_progress_time: None,
            pto_outstanding: false,
            persistent_congestion_pending: false,
            shim_armed_at: None,
        }
    }

    /// Configure the peer's transport parameters (after the handshake
    /// exposes them). Updates `max_ack_delay` and `ack_delay_exponent`.
    /// Per RFC 9000 §13.2.5, callers must still apply exponent 3 to ACKs
    /// in the Initial+Handshake spaces.
    pub(crate) fn set_peer_params(&mut self, max_ack_delay: Duration, ack_delay_exponent: u8) {
        self.max_ack_delay = max_ack_delay;
        self.ack_delay_exponent = ack_delay_exponent;
    }

    /// RFC 9002 Appendix A — `OnPacketSent`.
    ///
    /// Records `pkt` in the per-space sent-packets table and re-arms the
    /// loss-detection timer. Also bumps `time_of_last_ack_eliciting_packet`
    /// if applicable.
    pub(crate) fn on_packet_sent(&mut self, space: PnSpaceId, pkt: SentPacket) {
        let now = pkt.time_sent;
        let ack_eliciting = pkt.ack_eliciting;
        let in_flight = pkt.in_flight;
        let pn = pkt.pn;
        let ps = &mut self.per_space[space as usize];
        if ack_eliciting {
            ps.time_of_last_ack_eliciting_packet = Some(now);
        }
        if in_flight {
            ps.sent_packets.insert(pn, pkt);
        }
        self.set_loss_detection_timer(now);
    }

    /// RFC 9002 Appendix A — `OnAckReceived`.
    ///
    /// `acked_ranges` carries the newly-acknowledged PN ranges from the
    /// peer's ACK frame (descending or ascending — order is immaterial).
    /// `ack_delay` is the already-scaled delay (caller has applied the
    /// `2^ack_delay_exponent` factor, taking RFC 9000 §13.2.5 into
    /// account for Initial+Handshake spaces). `now` is the current time.
    ///
    /// Returns the list of newly-acked [`SentPacket`]s the caller must
    /// hand to the congestion controller. RTT is updated when the
    /// largest-acked PN moved (§5.3).
    pub(crate) fn on_ack_received(
        &mut self,
        space: PnSpaceId,
        acked_ranges: &[RangeInclusive<u64>],
        ack_delay: Duration,
        now: Duration,
    ) -> Vec<SentPacket> {
        let mut newly_acked: Vec<SentPacket> = Vec::new();
        // Compute the largest acknowledged in this ACK frame, across all
        // ranges. Per §A.7 the largest in this ACK is `largest_acknowledged`.
        let mut frame_largest: Option<u64> = None;
        for r in acked_ranges {
            let end = *r.end();
            frame_largest = Some(match frame_largest {
                Some(v) => v.max(end),
                None => end,
            });
        }
        let frame_largest = match frame_largest {
            Some(v) => v,
            None => return newly_acked,
        };

        // Collect newly-acked packets (drained out of sent_packets) per
        // §A.7 "DetectAndRemoveAckedPackets".
        //
        // Iterate sparsely over only the packet numbers actually in flight
        // that fall within each acknowledged range, rather than walking the
        // range densely. The peer-controlled ranges can span up to the full
        // 62-bit packet-number space, so a dense `pn..=end` walk would let a
        // single forged ACK pin the CPU for an unbounded time (a
        // CPU-exhaustion DoS). `BTreeMap::range` bounds the work by the number
        // of packets we are tracking, not by the width of the range, and is
        // behaviourally identical for legitimate ACKs.
        let ps = &mut self.per_space[space as usize];
        for r in acked_ranges {
            let pns: Vec<u64> = ps
                .sent_packets
                .range(*r.start()..=*r.end())
                .map(|(k, _)| *k)
                .collect();
            for pn in pns {
                if let Some(p) = ps.sent_packets.remove(&pn) {
                    newly_acked.push(p);
                }
            }
        }

        // Update `largest_acked_packet` per §A.7 step 1.
        ps.largest_acked_packet = Some(match ps.largest_acked_packet {
            Some(v) => v.max(frame_largest),
            None => frame_largest,
        });

        // RTT sample: §A.7 step "If the largest acknowledged is newly
        // acked and at least one ack-eliciting packet was newly acked".
        let largest_newly_acked = newly_acked.iter().find(|p| p.pn == frame_largest).cloned();
        let any_ack_eliciting_newly_acked = newly_acked.iter().any(|p| p.ack_eliciting);
        if let Some(largest_pkt) = largest_newly_acked
            && any_ack_eliciting_newly_acked
        {
            // RFC 9002 §5.3 — UpdateRtt.
            let latest = now.saturating_sub(largest_pkt.time_sent);
            self.update_rtt(latest, ack_delay, space);
        }

        // §A.7 step "DetectAndRemoveLostPackets" is invoked separately by
        // the caller (so the caller can hand the lost packets to the
        // congestion controller).

        // Progress: clear pto_count and PTO-outstanding flag (§A.6 / §6.2.2).
        if !newly_acked.is_empty() {
            self.pto_count = 0;
            self.pto_outstanding = false;
            self.persistent_congestion_pending = false;
            self.last_progress_time = Some(now);
            // Phase-4 shim: any ack progress also resets the shim
            // backoff and re-arms from `now`.
            self.shim_armed_at = Some(now);
        }

        // §A.7 final step: re-arm loss-detection timer.
        self.set_loss_detection_timer(now);

        newly_acked
    }

    /// RFC 9002 §5.3 — `UpdateRtt`.
    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: Duration, space: PnSpaceId) {
        self.latest_rtt = latest_rtt;
        // §5.2 — min_rtt tracks the minimum observed RTT.
        if latest_rtt < self.min_rtt {
            self.min_rtt = latest_rtt;
        }
        // First sample: initialize.
        if self.first_rtt_sample.is_none() {
            self.first_rtt_sample = Some(latest_rtt);
            self.smoothed_rtt = latest_rtt;
            self.rttvar = latest_rtt / 2;
            return;
        }
        // §5.3 — clamp ack_delay to the peer's advertised max_ack_delay before
        // it is applied. The Initial and Handshake spaces use an implicit
        // ack_delay of 0 (the peer is not yet bound by max_ack_delay there), so
        // the clamp only applies to the Application (1-RTT) space. Without this
        // ceiling a peer could report an arbitrarily large ack_delay and shrink
        // our RTT sample below what it should be.
        let ack_delay = if space == PnSpaceId::Application {
            ack_delay.min(self.max_ack_delay)
        } else {
            ack_delay
        };
        // §5.3 — apply ack_delay only if it would not reduce adjusted_rtt
        // below min_rtt (the spec's "adjusted_rtt = max(min_rtt,
        // latest_rtt - ack_delay)" rule), and only when this is a 1-RTT
        // ACK (Initial+Handshake have implicit ack_delay = 0 anyway).
        let adjusted_rtt = if self.min_rtt.saturating_add(ack_delay) <= latest_rtt {
            latest_rtt - ack_delay
        } else {
            latest_rtt
        };
        // rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
        let diff = self.smoothed_rtt.abs_diff(adjusted_rtt);
        // Compute fractional updates carefully in nanos.
        let rttvar_ns =
            (self.rttvar.as_nanos() as u64).saturating_mul(3) / 4 + (diff.as_nanos() as u64) / 4;
        self.rttvar = Duration::from_nanos(rttvar_ns);
        let smoothed_ns = (self.smoothed_rtt.as_nanos() as u64).saturating_mul(7) / 8
            + (adjusted_rtt.as_nanos() as u64) / 8;
        self.smoothed_rtt = Duration::from_nanos(smoothed_ns);
    }

    /// RFC 9002 Appendix A — `DetectAndRemoveLostPackets`.
    ///
    /// Walks the per-space sent-packets table; packets satisfying either
    /// the packet-threshold (`pn ≤ largest_acked − kPacketThreshold`) or
    /// the time-threshold (`time_sent ≤ now − loss_delay`) rule are
    /// declared lost and removed. The function also updates `loss_time`
    /// (the time at which the next not-yet-lost packet will become lost
    /// under the time-threshold rule) so the caller can re-arm the
    /// loss-detection timer.
    pub(crate) fn detect_lost(&mut self, space: PnSpaceId, now: Duration) -> Vec<SentPacket> {
        let ps = &mut self.per_space[space as usize];
        let largest_acked = match ps.largest_acked_packet {
            Some(v) => v,
            None => return Vec::new(),
        };

        // RFC 9002 §6.1.2 — `loss_delay = max(kTimeThreshold ×
        // max(smoothed_rtt, latest_rtt), kGranularity)` with
        // `kTimeThreshold = 9/8`.
        let max_rtt = core::cmp::max(self.smoothed_rtt, self.latest_rtt);
        let loss_delay_ns = (max_rtt.as_nanos() as u64).saturating_mul(9) / 8;
        let loss_delay = core::cmp::max(Duration::from_nanos(loss_delay_ns), K_GRANULARITY);
        let lost_send_time = now.saturating_sub(loss_delay);

        let mut lost: Vec<SentPacket> = Vec::new();
        ps.loss_time = None;
        // Iterate in ascending PN order; remove matching keys after the
        // walk to avoid borrowing both an iterator and a mutable map.
        let candidate_pns: Vec<u64> = ps.sent_packets.keys().copied().collect();
        for pn in candidate_pns {
            if pn > largest_acked {
                // Per §6.1: only packets sent before the largest-acked
                // are eligible. The map is BTreeMap-sorted so we could
                // break early, but explicit is clearer.
                continue;
            }
            let p = ps.sent_packets.get(&pn).expect("just-listed key");
            // Packet-threshold (§6.1.1): `largest_acked − pn ≥
            // kPacketThreshold`.
            let is_threshold_lost = largest_acked.saturating_sub(pn) >= K_PACKET_THRESHOLD;
            // Time-threshold (§6.1.2).
            let is_time_lost = p.time_sent <= lost_send_time;
            if is_threshold_lost || is_time_lost {
                let removed = ps.sent_packets.remove(&pn).expect("just-checked key");
                lost.push(removed);
            } else {
                // Track the earliest send-time among still-unacked
                // packets ≤ largest_acked; the next loss-time deadline
                // is that send-time + loss_delay.
                let cand = p.time_sent.saturating_add(loss_delay);
                ps.loss_time = Some(match ps.loss_time {
                    Some(t) => core::cmp::min(t, cand),
                    None => cand,
                });
            }
        }

        // Re-arm the loss-detection timer with the updated loss_time.
        self.set_loss_detection_timer(now);
        lost
    }

    /// RFC 9002 Appendix A — `OnLossDetectionTimeout`.
    ///
    /// Returns the `retransmit_hint`s of any packet(s) the caller should
    /// re-queue. If the timer fired for time-threshold loss (the
    /// `loss_time` path), this returns the hints of the lost packets;
    /// otherwise it fired for PTO, and we return the hints of the
    /// oldest ack-eliciting packet(s) in the appropriate space (or an
    /// empty vector if there are none — the caller then sends a PING
    /// per §6.2.4).
    pub(crate) fn on_timeout(&mut self, now: Duration) -> Vec<Vec<u8>> {
        // First check if any loss_time has fired (§A.10 step 1).
        let (earliest_loss_time, earliest_loss_space) = self.earliest_loss_time();
        if let (Some(t), Some(space)) = (earliest_loss_time, earliest_loss_space)
            && t <= now
        {
            let lost = self.detect_lost(space, now);
            let mut hints: Vec<Vec<u8>> = Vec::new();
            for p in lost {
                hints.push(p.retransmit_hint);
            }
            return hints;
        }

        // Otherwise it's a PTO. §6.2.4 — increment `pto_count` and send
        // probe packets. We surface the retransmit hints of the OLDEST
        // ack-eliciting packets across all spaces with outstanding
        // ack-eliciting data (capped at 2 — §6.2.4 "send one or two
        // probe packets").
        self.pto_count = self.pto_count.saturating_add(1);
        self.pto_outstanding = true;
        // Phase-4 shim accounting.
        if self.shim_armed_at.is_some() {
            self.shim_armed_at = Some(now);
        }

        let mut hints: Vec<Vec<u8>> = Vec::new();
        for space in [
            PnSpaceId::Initial,
            PnSpaceId::Handshake,
            PnSpaceId::Application,
        ] {
            let ps = &self.per_space[space as usize];
            if let Some((_pn, pkt)) = ps
                .sent_packets
                .iter()
                .find(|(_, p)| p.ack_eliciting && !p.retransmit_hint.is_empty())
            {
                hints.push(pkt.retransmit_hint.clone());
                if hints.len() >= 2 {
                    break;
                }
            }
        }

        // Re-arm with backoff.
        self.set_loss_detection_timer(now);
        hints
    }

    /// RFC 9002 §6.2.2 — `PTOPeriod`.
    ///
    /// `pto = smoothed_rtt + max(4 × rttvar, kGranularity) + max_ack_delay`.
    /// The Initial+Handshake spaces use `max_ack_delay = 0` per §6.2.1;
    /// the caller decides which to use. This default returns the
    /// 1-RTT-applicable value (with `max_ack_delay`).
    pub(crate) fn pto_period(&self) -> Duration {
        let four_rttvar = self.rttvar.saturating_mul(4);
        let g = core::cmp::max(four_rttvar, K_GRANULARITY);
        self.smoothed_rtt
            .saturating_add(g)
            .saturating_add(self.max_ack_delay)
    }

    /// PTO period for the Initial / Handshake spaces, which omit
    /// `max_ack_delay` per RFC 9002 §6.2.1.
    pub(crate) fn pto_period_handshake(&self) -> Duration {
        let four_rttvar = self.rttvar.saturating_mul(4);
        let g = core::cmp::max(four_rttvar, K_GRANULARITY);
        self.smoothed_rtt.saturating_add(g)
    }

    /// RFC 9002 Appendix A — `SetLossDetectionTimer`.
    ///
    /// Recomputes [`Self::loss_detection_timer`] from the current state.
    /// The timer fires at the earliest of:
    ///   * `loss_time` across all spaces (time-threshold loss), OR
    ///   * `time_of_last_ack_eliciting_packet + PTO × 2^pto_count` for
    ///     the space with the most recent ack-eliciting send.
    pub(crate) fn set_loss_detection_timer(&mut self, _now: Duration) {
        // 1. Earliest loss_time wins (§A.8 step "GetLossTimeAndSpace").
        let (loss_time, _loss_space) = self.earliest_loss_time();
        if let Some(t) = loss_time {
            self.loss_detection_timer = Some(t);
            return;
        }
        // 2. No outstanding ack-eliciting → disarm.
        let mut any_ack_eliciting = false;
        for space_idx in 0..3 {
            for p in self.per_space[space_idx].sent_packets.values() {
                if p.ack_eliciting {
                    any_ack_eliciting = true;
                    break;
                }
            }
            if any_ack_eliciting {
                break;
            }
        }
        if !any_ack_eliciting {
            self.loss_detection_timer = None;
            return;
        }
        // 3. PTO time = `time_of_last_ack_eliciting_packet + PTO × 2^pto_count`.
        //    Choose the space with the most-recent ack-eliciting send;
        //    that produces the latest deadline, which is what the spec
        //    pseudocode picks (§A.8 GetPtoTimeAndSpace).
        let mut latest_ack_eliciting: Option<(Duration, PnSpaceId)> = None;
        for (i, space_id) in [
            PnSpaceId::Initial,
            PnSpaceId::Handshake,
            PnSpaceId::Application,
        ]
        .iter()
        .enumerate()
        {
            if let Some(t) = self.per_space[i].time_of_last_ack_eliciting_packet {
                latest_ack_eliciting = Some(match latest_ack_eliciting {
                    Some((prev, prev_space)) if prev > t => (prev, prev_space),
                    _ => (t, *space_id),
                });
            }
        }
        let (anchor, space) = match latest_ack_eliciting {
            Some(v) => v,
            None => {
                self.loss_detection_timer = None;
                return;
            }
        };
        // PTO duration with backoff.
        let backoff = self.pto_count.min(PTO_BACKOFF_CAP);
        let pto_base = match space {
            PnSpaceId::Initial | PnSpaceId::Handshake => self.pto_period_handshake(),
            PnSpaceId::Application => self.pto_period(),
        };
        let mult = 1u64.checked_shl(backoff).unwrap_or(u64::MAX);
        let pto = match pto_base.checked_mul(u32::try_from(mult).unwrap_or(u32::MAX)) {
            Some(d) => d,
            None => Duration::from_secs(60),
        };
        self.loss_detection_timer = Some(anchor.saturating_add(pto));
    }

    /// Earliest pending `loss_time` across all spaces, and the space.
    fn earliest_loss_time(&self) -> (Option<Duration>, Option<PnSpaceId>) {
        let mut earliest: Option<(Duration, PnSpaceId)> = None;
        for (i, space) in [
            PnSpaceId::Initial,
            PnSpaceId::Handshake,
            PnSpaceId::Application,
        ]
        .iter()
        .enumerate()
        {
            if let Some(t) = self.per_space[i].loss_time {
                earliest = Some(match earliest {
                    Some((prev, prev_space)) if prev < t => (prev, prev_space),
                    _ => (t, *space),
                });
            }
        }
        match earliest {
            Some((t, s)) => (Some(t), Some(s)),
            None => (None, None),
        }
    }

    /// Discard a level's keys (RFC 9000 §4.10 — Initial keys discarded
    /// when Handshake keys derived; Handshake keys discarded when the
    /// handshake completes). Wipes the per-space sent-packets table and
    /// clears `loss_time` / `time_of_last_ack_eliciting_packet`.
    pub(crate) fn discard_keys(&mut self, space: PnSpaceId) {
        let ps = &mut self.per_space[space as usize];
        ps.sent_packets.clear();
        ps.largest_acked_packet = None;
        ps.loss_time = None;
        ps.time_of_last_ack_eliciting_packet = None;
        self.set_loss_detection_timer(Duration::ZERO);
    }

    /// Returns whether a persistent-congestion event was detected since
    /// the last call. One-shot: once consumed, must not re-fire until
    /// fresh progress (an ack) clears `pto_outstanding` and a new
    /// burst of PTOs accumulates.
    ///
    /// Phase-5 approximation per the brief: if `pto_count ≥
    /// kPersistentCongestionThreshold` and no successful ack has been
    /// received since the first PTO, signal persistent congestion. The
    /// full RFC 9002 §7.6 rule requires also checking that the duration
    /// since first PTO exceeds `(smoothed_rtt + max(4×rttvar, kG) +
    /// max_ack_delay) × (2^kPersistentCongestionThreshold − 1)`; we
    /// don't make this distinction in Phase 5 because the only
    /// observable effect is a `cwnd → kMinimumWindow` reset, which is
    /// safe to be slightly conservative about.
    pub(crate) fn take_persistent_congestion(&mut self) -> bool {
        if self.pto_count >= K_PERSISTENT_CONGESTION_THRESHOLD
            && self.pto_outstanding
            && !self.persistent_congestion_pending
        {
            // Mark as reported so subsequent calls return false until
            // either an ack arrives (clears `pto_outstanding`) or a
            // disarm clears `pto_count`.
            self.persistent_congestion_pending = true;
            true
        } else {
            false
        }
    }

    // -----------------------------------------------------------------------
    // Phase-4 shim API
    // -----------------------------------------------------------------------
    // Connection-level driver still uses arm/disarm/has_fired/next_deadline
    // /on_fire/on_handshake_progress. Bridge to the underlying RFC 9002
    // state where it makes sense; otherwise track a parallel "shim"
    // anchor that mirrors Phase-4 semantics.

    /// Phase-4 shim: arms the PTO at `now`. Re-arms if already armed.
    pub(crate) fn arm(&mut self, now: Duration) {
        self.shim_armed_at = Some(now);
    }

    /// Phase-4 shim: disarms the shim PTO entirely. Also clears
    /// `pto_count`. The RFC 9002 state (`sent_packets`, `loss_time`,
    /// …) is left untouched — callers that want to wipe a space's
    /// state use [`discard_keys`].
    pub(crate) fn disarm(&mut self) {
        self.shim_armed_at = None;
        self.pto_count = 0;
        self.pto_outstanding = false;
        self.persistent_congestion_pending = false;
    }

    /// Phase-4 shim: true iff the shim PTO is armed.
    pub(crate) fn is_armed(&self) -> bool {
        self.shim_armed_at.is_some()
    }

    /// Phase-4 shim: time-until-fire from `now`. Returns
    /// `Some(Duration::ZERO)` if the deadline has already passed,
    /// `None` if not armed. The deadline is `armed_at + base_pto ×
    /// 2^pto_count`. `base_pto = 2 × kInitialRtt` when there is no
    /// RTT sample (the Phase-4 expectation), otherwise
    /// [`Self::pto_period_handshake`].
    pub(crate) fn next_deadline(&self, now: Duration) -> Option<Duration> {
        let armed_at = self.shim_armed_at?;
        let base = if self.first_rtt_sample.is_some() {
            self.pto_period_handshake()
        } else {
            K_INITIAL_RTT.saturating_mul(2)
        };
        let backoff = self.pto_count.min(PTO_BACKOFF_CAP);
        let mult = 1u64.checked_shl(backoff).unwrap_or(u64::MAX);
        let pto = match base.checked_mul(u32::try_from(mult).unwrap_or(u32::MAX)) {
            Some(d) => d.min(Duration::from_secs(60)),
            None => Duration::from_secs(60),
        };
        let deadline = armed_at.saturating_add(pto);
        Some(deadline.saturating_sub(now))
    }

    /// Phase-4 shim: true if the shim deadline has elapsed at `now`.
    pub(crate) fn has_fired(&self, now: Duration) -> bool {
        match self.next_deadline(now) {
            Some(d) => d == Duration::ZERO,
            None => false,
        }
    }

    /// Phase-4 shim: records that the PTO fired. Bumps `pto_count`,
    /// caps at [`PTO_BACKOFF_CAP`], re-arms the shim anchor from
    /// `now`, and flips `pto_outstanding` so the persistent-congestion
    /// check can find it.
    pub(crate) fn on_fire(&mut self, now: Duration) {
        self.pto_count = self.pto_count.saturating_add(1).min(PTO_BACKOFF_CAP);
        self.pto_outstanding = true;
        self.shim_armed_at = Some(now);
    }

    /// Phase-4 shim: ack-eliciting progress observed. Resets
    /// `pto_count`, clears `pto_outstanding`, re-arms shim from `now`.
    pub(crate) fn on_handshake_progress(&mut self, now: Duration) {
        self.pto_count = 0;
        self.pto_outstanding = false;
        self.persistent_congestion_pending = false;
        self.last_progress_time = Some(now);
        self.shim_armed_at = Some(now);
    }
}

// =========================================================================
// Retransmit-hint encoding
// =========================================================================

/// One CRYPTO span the connection sent in a packet, encoded as a
/// `(level_byte, crypto_offset_varint, crypto_len_varint)` tuple inside
/// the retransmit_hint blob. `level_byte` is `Level as u8` per
/// [`crate::tls::quic_hooks::Level`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CryptoHint {
    /// Encryption level (`Level as u8`).
    pub(crate) level: u8,
    /// CRYPTO byte-stream offset.
    pub(crate) offset: u64,
    /// CRYPTO byte-stream length.
    pub(crate) length: u64,
}

/// Encodes a `(level, offset, length)` list into the retransmit_hint blob.
/// Output: `varint(count) [level_byte varint(offset) varint(length)]+`.
pub(crate) fn build_retransmit_hint(hints: &[CryptoHint]) -> Vec<u8> {
    let mut out = Vec::new();
    crate::quic::varint::encode(hints.len() as u64, &mut out);
    for h in hints {
        out.push(h.level);
        crate::quic::varint::encode(h.offset, &mut out);
        crate::quic::varint::encode(h.length, &mut out);
    }
    out
}

/// Decodes a retransmit_hint blob built by [`build_retransmit_hint`].
pub(crate) fn parse_retransmit_hint(buf: &[u8]) -> Result<Vec<CryptoHint>, crate::tls::Error> {
    let mut p = 0usize;
    let (count, n) = crate::quic::varint::decode(&buf[p..])?;
    p += n;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if p >= buf.len() {
            return Err(crate::tls::Error::Decode);
        }
        let level = buf[p];
        p += 1;
        let (offset, n) = crate::quic::varint::decode(&buf[p..])?;
        p += n;
        let (length, n) = crate::quic::varint::decode(&buf[p..])?;
        p += n;
        out.push(CryptoHint {
            level,
            offset,
            length,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_packet(pn: u64, ack_eliciting: bool, in_flight: bool, time_sent: Duration) -> SentPacket {
        SentPacket {
            pn,
            sent_bytes: 1200,
            ack_eliciting,
            in_flight,
            time_sent,
            retransmit_hint: Vec::new(),
            stream_hints: Vec::new(),
        }
    }

    /// Test 1 — RFC 9002 §6.2.2: `pto = smoothed_rtt + max(4 × rttvar,
    /// kGranularity) + max_ack_delay`. With smoothed=100ms rttvar=25ms
    /// max_ack_delay=25ms → 100 + 100 + 25 = 225ms.
    #[test]
    fn pto_period_matches_spec() {
        let mut s = LossState::new();
        s.smoothed_rtt = Duration::from_millis(100);
        s.rttvar = Duration::from_millis(25);
        s.max_ack_delay = Duration::from_millis(25);
        assert_eq!(s.pto_period(), Duration::from_millis(225));
    }

    /// Test 2 — RFC 9002 §5.3 first-sample initialization.
    #[test]
    fn rtt_first_sample_initializes() {
        let mut s = LossState::new();
        // First sample of 80ms with no ack_delay.
        s.update_rtt(
            Duration::from_millis(80),
            Duration::ZERO,
            PnSpaceId::Initial,
        );
        assert_eq!(s.smoothed_rtt, Duration::from_millis(80));
        assert_eq!(s.rttvar, Duration::from_millis(40));
        assert_eq!(s.min_rtt, Duration::from_millis(80));
    }

    /// Test 3 — subsequent samples smooth per RFC 9002 §5.3.
    #[test]
    fn rtt_subsequent_samples_smooth() {
        let mut s = LossState::new();
        s.update_rtt(
            Duration::from_millis(80),
            Duration::ZERO,
            PnSpaceId::Initial,
        );
        // After 1st: smoothed=80ms rttvar=40ms.
        // 2nd sample = 100ms, no ack_delay, min_rtt=80ms still.
        s.update_rtt(
            Duration::from_millis(100),
            Duration::ZERO,
            PnSpaceId::Initial,
        );
        // adjusted = 100 (since min_rtt + 0 <= 100? yes — 80 <= 100 — but ack_delay=0 so adjusted=100).
        // diff = |80 - 100| = 20ms
        // rttvar' = 3/4 * 40 + 1/4 * 20 = 30 + 5 = 35ms
        // smoothed' = 7/8 * 80 + 1/8 * 100 = 70 + 12.5 = 82.5ms
        assert_eq!(s.rttvar, Duration::from_millis(35));
        assert_eq!(s.smoothed_rtt, Duration::from_micros(82_500));
        // 3rd sample = 60ms.
        s.update_rtt(
            Duration::from_millis(60),
            Duration::ZERO,
            PnSpaceId::Initial,
        );
        // adjusted = 60; min_rtt updates to 60.
        // diff = |82.5 - 60| = 22.5ms
        // rttvar' = 3/4 * 35 + 1/4 * 22.5 = 26.25 + 5.625 = 31.875ms
        // smoothed' = 7/8 * 82.5 + 1/8 * 60 = 72.1875 + 7.5 = 79.6875ms
        assert!(s.min_rtt == Duration::from_millis(60));
        // Allow small rounding (integer ns arithmetic).
        let want_rttvar = Duration::from_nanos(31_875_000);
        let got = s.rttvar;
        let delta = got.abs_diff(want_rttvar);
        assert!(delta < Duration::from_micros(2), "rttvar={got:?}");
        let want_smoothed = Duration::from_nanos(79_687_500);
        let got = s.smoothed_rtt;
        let delta = got.abs_diff(want_smoothed);
        assert!(delta < Duration::from_micros(2), "smoothed={got:?}");
    }

    /// Test 4 — PTO backoff doubles per consecutive timeout. The shim
    /// API tracks the same `pto_count` as the RFC 9002 state.
    #[test]
    fn pto_backoff_doubles() {
        let mut s = LossState::new();
        s.arm(Duration::ZERO);
        // Initial PTO with no RTT sample: 2 * kInitialRtt = 666ms.
        let base = K_INITIAL_RTT * 2;
        assert_eq!(s.next_deadline(Duration::ZERO), Some(base), "initial pto");
        s.on_fire(base);
        // After 1 fire: pto_count=1; deadline = base * 2 from `base`.
        assert_eq!(s.next_deadline(base), Some(base * 2), "after 1 timeout");
        s.on_fire(base * 3);
        // pto_count=2; deadline = base * 4.
        assert_eq!(
            s.next_deadline(base * 3),
            Some(base * 4),
            "after 2 timeouts"
        );
    }

    /// Test 5 — packet-threshold loss per RFC 9002 §6.1.1. We send PNs
    /// 1..=5 packed near `now` so the time-threshold rule does NOT
    /// fire; only the packet-threshold rule matters.
    #[test]
    fn packet_threshold_loss() {
        let mut s = LossState::new();
        // Pre-seed a large RTT so loss_delay is large enough that none
        // of the recent sends fall outside it.
        s.smoothed_rtt = Duration::from_millis(1000);
        s.latest_rtt = Duration::from_millis(1000);
        s.first_rtt_sample = Some(Duration::ZERO);
        // Send PNs 1..=5 spaced 1ms apart, all at t≈now.
        for pn in 1..=5u64 {
            s.on_packet_sent(
                PnSpaceId::Initial,
                mk_packet(pn, true, true, Duration::from_millis(pn)),
            );
        }
        // Ack PN 5 at t=10ms. (No RTT update because RTT only updates
        // when the largest_newly_acked is ack-eliciting AND we update
        // smoothed/rttvar — but first_rtt_sample is already set, so
        // a new sample of 5ms would smooth our 1000ms down. We set
        // `min_rtt` to a high value first.)
        s.min_rtt = Duration::from_millis(1000);
        let _ = s.on_ack_received(
            PnSpaceId::Initial,
            &[5u64..=5u64],
            Duration::ZERO,
            Duration::from_millis(10),
        );
        // After the ack, smoothed_rtt could be smoothed down toward
        // the latest 5ms sample. Re-pin to keep the test focused on
        // the packet-threshold rule.
        s.smoothed_rtt = Duration::from_millis(1000);
        s.latest_rtt = Duration::from_millis(1000);
        // Detect lost — at t=10ms, kPacketThreshold=3 means PNs ≤ 5−3 = 2
        // are declared lost (PN 1, PN 2). PNs 3 and 4 are not yet lost
        // (gap = 2 and 1) and the time-threshold doesn't fire (every
        // packet was sent ≤ 10ms ago, well within loss_delay = 9/8 ×
        // 1000ms).
        let lost = s.detect_lost(PnSpaceId::Initial, Duration::from_millis(10));
        let mut lost_pns: Vec<u64> = lost.iter().map(|p| p.pn).collect();
        lost_pns.sort_unstable();
        assert_eq!(lost_pns, alloc::vec![1u64, 2u64]);
    }

    /// Test 6 — time-threshold loss per RFC 9002 §6.1.2.
    #[test]
    fn time_threshold_loss() {
        let mut s = LossState::new();
        s.smoothed_rtt = Duration::from_millis(100);
        s.latest_rtt = Duration::from_millis(100);
        // Send PN 1 at t=0.
        s.on_packet_sent(PnSpaceId::Initial, mk_packet(1, true, true, Duration::ZERO));
        // Send PN 2 at t=50ms, ack at t=200ms.
        s.on_packet_sent(
            PnSpaceId::Initial,
            mk_packet(2, true, true, Duration::from_millis(50)),
        );
        let _ = s.on_ack_received(
            PnSpaceId::Initial,
            &[2u64..=2u64],
            Duration::ZERO,
            Duration::from_millis(200),
        );
        // At t=300ms: loss_delay = max(9/8 * 100ms, 1ms) = 112.5ms;
        // PN 1 was sent at 0; 0 ≤ 300 − 112.5 ⇒ lost.
        let lost = s.detect_lost(PnSpaceId::Initial, Duration::from_millis(300));
        let lost_pns: Vec<u64> = lost.iter().map(|p| p.pn).collect();
        assert_eq!(lost_pns, alloc::vec![1u64]);
    }

    #[test]
    fn rfc9002_init_state() {
        let s = LossState::new();
        assert_eq!(s.smoothed_rtt, K_INITIAL_RTT);
        assert_eq!(s.rttvar, K_INITIAL_RTT / 2);
        assert_eq!(s.min_rtt, Duration::MAX);
        assert_eq!(s.pto_count, 0);
        assert!(s.loss_detection_timer.is_none());
        assert!(s.first_rtt_sample.is_none());
    }

    #[test]
    fn on_packet_sent_records_and_arms_timer() {
        let mut s = LossState::new();
        s.on_packet_sent(PnSpaceId::Initial, mk_packet(0, true, true, Duration::ZERO));
        assert_eq!(s.per_space[0].sent_packets.len(), 1);
        assert_eq!(
            s.per_space[0].time_of_last_ack_eliciting_packet,
            Some(Duration::ZERO)
        );
        // Timer armed.
        assert!(s.loss_detection_timer.is_some());
    }

    #[test]
    fn ack_received_drains_packet_and_updates_rtt() {
        let mut s = LossState::new();
        let send_time = Duration::from_millis(0);
        s.on_packet_sent(PnSpaceId::Initial, mk_packet(0, true, true, send_time));
        let acked = s.on_ack_received(
            PnSpaceId::Initial,
            &[0u64..=0u64],
            Duration::ZERO,
            Duration::from_millis(50),
        );
        assert_eq!(acked.len(), 1);
        assert!(s.per_space[0].sent_packets.is_empty());
        assert_eq!(s.smoothed_rtt, Duration::from_millis(50));
        assert_eq!(s.rttvar, Duration::from_millis(25));
        assert_eq!(s.min_rtt, Duration::from_millis(50));
    }

    /// Regression test for the QUIC ACK-range CPU-exhaustion DoS.
    ///
    /// A forged ACK whose range spans nearly the entire 62-bit packet-number
    /// space used to drive `on_ack_received` into a dense `pn..=end` walk of
    /// ~2^62 iterations, hanging the connection forever. The fix iterates
    /// sparsely over only the packets actually in flight (via
    /// `BTreeMap::range`), so processing such an ACK is bounded by the (tiny)
    /// number of tracked packets and returns essentially instantly. The
    /// connection layer additionally rejects an ACK whose `largest` exceeds
    /// the highest PN ever sent (RFC 9000 §13.1) before reaching here; this
    /// test exercises the loss layer's own DoS resistance directly.
    #[test]
    fn enormous_ack_range_iterates_sparsely() {
        let mut s = LossState::new();
        for pn in 0..3u64 {
            s.on_packet_sent(
                PnSpaceId::Application,
                mk_packet(pn, true, true, Duration::from_millis(10)),
            );
        }

        let start = std::time::Instant::now();
        // Attacker-controlled range covering essentially the whole PN space.
        let acked = s.on_ack_received(
            PnSpaceId::Application,
            &[0..=(u64::MAX - 1)],
            Duration::ZERO,
            Duration::from_millis(60),
        );
        let elapsed = start.elapsed();

        // Only the three in-flight packets are reported, and the call returns
        // quickly rather than looping ~2^64 times.
        assert_eq!(acked.len(), 3);
        assert!(s.per_space[2].sent_packets.is_empty());
        assert!(
            elapsed < Duration::from_secs(1),
            "sparse ACK iteration took too long: {elapsed:?}"
        );

        // A subsequent legitimate ACK over a real sub-range still behaves
        // exactly as before: only the packets inside the range are acked.
        let mut s = LossState::new();
        for pn in 0..4u64 {
            s.on_packet_sent(
                PnSpaceId::Application,
                mk_packet(pn, true, true, Duration::from_millis(10)),
            );
        }
        let acked = s.on_ack_received(
            PnSpaceId::Application,
            &[1..=2],
            Duration::ZERO,
            Duration::from_millis(60),
        );
        assert_eq!(acked.len(), 2);
        assert_eq!(s.per_space[2].sent_packets.len(), 2);
    }

    #[test]
    fn discard_keys_wipes_space() {
        let mut s = LossState::new();
        s.on_packet_sent(PnSpaceId::Initial, mk_packet(0, true, true, Duration::ZERO));
        s.discard_keys(PnSpaceId::Initial);
        assert!(s.per_space[0].sent_packets.is_empty());
        assert!(s.per_space[0].largest_acked_packet.is_none());
        assert!(s.per_space[0].loss_time.is_none());
        assert!(s.per_space[0].time_of_last_ack_eliciting_packet.is_none());
    }

    #[test]
    fn retransmit_hint_roundtrip() {
        let hints = alloc::vec![
            CryptoHint {
                level: 0,
                offset: 0,
                length: 100
            },
            CryptoHint {
                level: 2,
                offset: 100,
                length: 1024
            },
        ];
        let buf = build_retransmit_hint(&hints);
        let parsed = parse_retransmit_hint(&buf).expect("parse");
        assert_eq!(parsed, hints);
    }

    #[test]
    fn shim_disarm_clears_state() {
        let mut s = LossState::new();
        s.arm(Duration::ZERO);
        s.on_fire(Duration::from_millis(666));
        s.disarm();
        assert!(!s.is_armed());
        assert!(s.next_deadline(Duration::ZERO).is_none());
        assert_eq!(s.pto_count, 0);
    }

    #[test]
    fn shim_handshake_progress_resets_backoff() {
        let mut s = LossState::new();
        s.arm(Duration::ZERO);
        s.on_fire(Duration::from_millis(666));
        s.on_fire(Duration::from_millis(2_000));
        s.on_handshake_progress(Duration::from_secs(5));
        assert_eq!(s.pto_count, 0);
        // base = 2 * kInitialRtt = 666ms.
        assert_eq!(
            s.next_deadline(Duration::from_secs(5)),
            Some(K_INITIAL_RTT * 2)
        );
    }

    #[test]
    fn persistent_congestion_after_threshold_ptos() {
        let mut s = LossState::new();
        s.arm(Duration::ZERO);
        for _ in 0..K_PERSISTENT_CONGESTION_THRESHOLD {
            s.on_fire(Duration::from_millis(666));
        }
        assert!(s.take_persistent_congestion());
        // Cleared on consume.
        assert!(!s.take_persistent_congestion());
    }
}
