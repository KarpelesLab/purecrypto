//! RFC 9002 §6 — loss detection.
//!
//! Full implementation of the RFC 9002 loss recovery state machine. Tracks
//! per-PN-space [`SentPacket`] state, the RTT estimator (latest_rtt /
//! smoothed_rtt / rttvar / min_rtt — RFC 9002 §5.3), the PTO timer
//! (RFC 9002 §6.2), packet-threshold + time-threshold loss detection
//! (RFC 9002 §6.1) and the §7.6 persistent-congestion test the congestion
//! controller consults for every batch of lost packets
//! ([`LossState::record_lost_batch`], which judges the batch together with
//! the recently declared losses it keeps).
//!
//! Pseudocode in Appendix A of RFC 9002 is followed step-for-step; each
//! non-trivial function names the section it implements. Where the
//! pseudocode references `loss_detection_timer`, we materialize that as
//! [`LossState::loss_detection_timer`].
//!
//! The connection drives this state machine through exactly the Appendix A
//! entry points: [`LossState::on_packet_sent`], [`LossState::on_ack_received`],
//! [`LossState::detect_lost`], [`LossState::on_loss_detection_timeout`] and
//! [`LossState::discard_keys`], each of which re-arms the timer with
//! [`LossState::set_loss_detection_timer`]. The handful of connection facts
//! §A.8 consults (role, handshake confirmation, key availability, the
//! server's anti-amplification state) live in [`LossContext`], which the
//! connection refreshes before the timer is recomputed.

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

/// RFC 9002 §6.2.4 — probe packets one PTO expiry may send: "an endpoint
/// MAY send up to two full-sized datagrams containing ack-eliciting
/// packets". RFC 9002 §7.5 exempts these from the congestion window.
pub(crate) const K_PTO_PROBES: u8 = 2;

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
    /// True if this packet carried the server's HANDSHAKE_DONE frame
    /// (RFC 9000 §19.20). The connection re-queues the frame if the packet
    /// is declared lost before any copy of it is acknowledged.
    pub(crate) handshake_done: bool,
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

/// What [`LossState`] remembers of a packet it declared lost, for the RFC
/// 9002 §7.6 persistent-congestion test across loss batches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LostRecord {
    /// `time_sent` of the packet.
    time_sent: Duration,
    /// The packet-number space it was sent in.
    space: PnSpaceId,
    /// Whether it was ack-eliciting — only such packets can be the edges
    /// of a persistent-congestion period (§7.6.2).
    ack_eliciting: bool,
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
    /// `first_rtt_sample` (§A.1.2) — the time the first RTT sample was
    /// obtained, `None` until then. §7.6.1 only lets packets sent after it
    /// count towards persistent congestion.
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

    // ---- PTO probe bookkeeping (RFC 9002 §6.2.4 / §7.5) --------------------
    /// The packet-number space whose PTO expired most recently and still owes
    /// probe packets, with [`Self::probe_credit`] counting how many. `None`
    /// once the probes have gone out or an ACK showed progress.
    probe_space: Option<PnSpaceId>,
    /// RFC 9002 §6.2.4 / §7.5 — ack-eliciting packets the sender may still
    /// emit in [`Self::probe_space`] *past* the congestion window as PTO
    /// probes. Armed to [`K_PTO_PROBES`] when a PTO fires, consumed one per
    /// ack-eliciting packet actually built in that space, and cleared by ack
    /// progress. Probes still count toward `bytes_in_flight` and are
    /// loss-tracked like any other packet; the credit only lets them *leave*
    /// while the window is full, so a peer that stopped acknowledging can be
    /// provoked into revealing what was lost.
    probe_credit: u8,

    // ---- Persistent congestion (RFC 9002 §7.6) ------------------------------
    /// `time_sent` of every acknowledged packet that was sent no earlier
    /// than the oldest packet still in flight or the oldest entry of
    /// [`Self::lost_history`], across all packet-number spaces.
    /// [`Self::in_persistent_congestion`] consults it to tell an
    /// acknowledged packet apart from a lost one when it checks that nothing
    /// sent between two lost packets got through (§7.6.2). Anything older
    /// can never fall between two packets a future batch could pair, so
    /// [`Self::prune_acked_send_times`] drops it; the packet threshold keeps
    /// the oldest in-flight packet within a few packet numbers of the
    /// largest acknowledged one, and the history is time-bounded, which
    /// keeps this short.
    acked_send_times: Vec<Duration>,
    /// Packets declared lost by earlier batches that could still be the
    /// older edge of a persistent-congestion period. The reference §B.8
    /// judges each `DetectAndRemoveLostPackets` batch on its own, but a
    /// period's losses are usually revealed a few at a time — by the packet
    /// threshold as successive ACKs arrive, or by one ACK per packet-number
    /// space — so [`Self::record_lost_batch`] judges the union of this
    /// history and the new batch. [`Self::prune_lost_history`] keeps it to
    /// packets sent within twice [`Self::persistent_congestion_duration`]
    /// and after the last declaration, so a period is declared once.
    lost_history: Vec<LostRecord>,
    /// When persistent congestion was last declared. Packets sent before it
    /// belong to that period, which has been acted on.
    persistent_congestion_declared: Option<Duration>,

    /// Connection facts RFC 9002 §A.8 consults when arming the timer.
    pub(crate) ctx: LossContext,
}

/// The connection-level facts RFC 9002 Appendix A reads while arming the
/// loss-detection timer (`SetLossDetectionTimer`, `GetPtoTimeAndSpace`,
/// `PeerCompletedAddressValidation`). The connection refreshes these before
/// every timer recomputation it triggers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LossContext {
    /// This endpoint is the server.
    pub(crate) is_server: bool,
    /// RFC 9001 §4.1.2 — the handshake is confirmed. Until then the
    /// Application space gets no PTO timer (§6.2.1) and the client keeps
    /// probing even with nothing in flight (§6.2.2.1).
    pub(crate) handshake_confirmed: bool,
    /// Handshake write keys are installed — decides whether the client's
    /// anti-deadlock probe is a Handshake or a padded Initial packet.
    pub(crate) has_handshake_keys: bool,
    /// Client only: an ACK for one of our Handshake packets has arrived, so
    /// the server has validated our address (§6.2.2.1).
    pub(crate) peer_handshake_acked: bool,
    /// Server only: the RFC 9000 §8.1 anti-amplification budget is
    /// exhausted, so nothing could be sent if the timer fired (§6.2.2.1).
    pub(crate) at_amplification_limit: bool,
}

/// What [`LossState::on_loss_detection_timeout`] decided the expired timer
/// was for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeoutAction {
    /// RFC 9002 §6.1.2 — a time-threshold loss deadline passed in `space`:
    /// the caller runs [`LossState::detect_lost`] there and handles the lost
    /// packets.
    DetectLoss(PnSpaceId),
    /// RFC 9002 §6.2.4 — the PTO expired for `space`: the caller sends one or
    /// two ack-eliciting probe packets there.
    Pto(PnSpaceId),
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
            probe_space: None,
            probe_credit: 0,
            acked_send_times: Vec::new(),
            lost_history: Vec::new(),
            persistent_congestion_declared: None,
            ctx: LossContext::default(),
        }
    }

    /// RFC 9002 §6.2.4 — a PTO fired for `space`: allow [`K_PTO_PROBES`]
    /// ack-eliciting probe packets there, past the congestion window (§7.5).
    fn arm_probe(&mut self, space: PnSpaceId) {
        self.probe_space = Some(space);
        self.probe_credit = K_PTO_PROBES;
    }

    /// Forget any probes still owed.
    fn clear_probe(&mut self) {
        self.probe_space = None;
        self.probe_credit = 0;
    }

    /// The space whose PTO probes are still owed, if any.
    #[inline]
    pub(crate) fn probe_space(&self) -> Option<PnSpaceId> {
        self.probe_space
    }

    /// Probe packets still permitted in `space` past the congestion window
    /// (§7.5). Zero for every space but [`Self::probe_space`].
    #[inline]
    pub(crate) fn probe_credit(&self, space: PnSpaceId) -> u8 {
        if self.probe_space == Some(space) {
            self.probe_credit
        } else {
            0
        }
    }

    /// An ack-eliciting probe packet was emitted in [`Self::probe_space`];
    /// spend one credit.
    #[inline]
    pub(crate) fn consume_probe_credit(&mut self) {
        self.probe_credit = self.probe_credit.saturating_sub(1);
        if self.probe_credit == 0 {
            self.probe_space = None;
        }
    }

    /// True while a PTO has fired for `space` and *no* probe has gone out
    /// since: §6.2.4 requires at least one ack-eliciting packet, so if
    /// nothing else ack-eliciting is available the packet builder adds a
    /// PING.
    #[inline]
    pub(crate) fn probe_needs_ping(&self, space: PnSpaceId) -> bool {
        self.probe_space == Some(space) && self.probe_credit == K_PTO_PROBES
    }

    /// RFC 9002 §A.8 `PeerCompletedAddressValidation`: a server assumes its
    /// client validated it implicitly; a client knows once one of its
    /// Handshake packets is acknowledged or the handshake is confirmed.
    #[inline]
    pub(crate) fn peer_completed_address_validation(&self) -> bool {
        self.ctx.is_server || self.ctx.peer_handshake_acked || self.ctx.handshake_confirmed
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
            self.update_rtt(latest, ack_delay, space, now);
        }

        // §7.6.2 — remember when the acknowledged packets were sent, so a
        // later loss batch can tell that something sent between two of its
        // packets did get through. The loss history is aged first: what it
        // still holds decides how far back the acknowledgments must reach.
        self.prune_lost_history(now);
        self.acked_send_times
            .extend(newly_acked.iter().map(|p| p.time_sent));
        self.prune_acked_send_times();

        // §A.7 step "DetectAndRemoveLostPackets" is invoked separately by
        // the caller (so the caller can hand the lost packets to the
        // congestion controller).

        // Progress (§A.7): the peer is acknowledging, so any PTO backoff and
        // unspent probe credit are stale — the window is the authority
        // again. `pto_count` itself is only reset once the peer is known to
        // have validated our address (§6.2.2.1): a client whose Initial was
        // acknowledged but whose Handshake packets were not keeps backing
        // off, so the anti-deadlock probes do not hammer an amplification-
        // limited server.
        if !newly_acked.is_empty() {
            if space == PnSpaceId::Handshake {
                self.ctx.peer_handshake_acked = true;
            }
            if self.peer_completed_address_validation() {
                self.pto_count = 0;
            }
            self.clear_probe();
        }

        // §A.7 final step: re-arm loss-detection timer.
        self.set_loss_detection_timer(now);

        newly_acked
    }

    /// RFC 9002 §5.3 — `UpdateRtt`. `now` is when the sample was taken.
    fn update_rtt(
        &mut self,
        latest_rtt: Duration,
        ack_delay: Duration,
        space: PnSpaceId,
        now: Duration,
    ) {
        self.latest_rtt = latest_rtt;
        // §5.2 — min_rtt tracks the minimum observed RTT.
        if latest_rtt < self.min_rtt {
            self.min_rtt = latest_rtt;
        }
        // First sample: initialize.
        if self.first_rtt_sample.is_none() {
            self.first_rtt_sample = Some(now);
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

        // Re-arm the loss-detection timer with the updated loss_time. The
        // acknowledged-send-time record is deliberately left alone here:
        // `in_persistent_congestion` still needs it for this batch, and the
        // next ACK prunes it.
        self.set_loss_detection_timer(now);
        lost
    }

    /// RFC 9002 §7.6.1 — the persistent-congestion duration:
    /// `(smoothed_rtt + max(4 × rttvar, kGranularity) + max_ack_delay) ×
    /// kPersistentCongestionThreshold`. The PTO here always includes
    /// `max_ack_delay`, whatever the space the lost packets were sent in.
    pub(crate) fn persistent_congestion_duration(&self) -> Duration {
        self.pto_period()
            .saturating_mul(K_PERSISTENT_CONGESTION_THRESHOLD)
    }

    /// RFC 9002 §7.6.2 / §B.9 `InPersistentCongestion` — whether `lost`, a
    /// batch [`Self::detect_lost`] just declared lost (and so no longer
    /// tracks), establishes persistent congestion together with the losses
    /// earlier batches declared ([`Self::lost_history`]).
    ///
    /// It does when two ack-eliciting packets among them were sent at
    /// least [`Self::persistent_congestion_duration`] apart, every packet
    /// sent between them was declared lost and none was acknowledged, and
    /// both were sent after the first RTT sample was taken (§7.6.1 — before
    /// that the duration is a guess, so §B.8 only considers packets sent
    /// after `first_rtt_sample`) and after the last declaration (that
    /// period has been acted on).
    ///
    /// The reference §B.8 pseudocode evaluates one
    /// `DetectAndRemoveLostPackets` batch, so a period whose losses are
    /// revealed by several ACKs — a few packets per ACK under the packet
    /// threshold, or one batch per packet-number space — would never be
    /// recognised; hence the history. The "nothing between them got
    /// through" condition is checked across all packet-number spaces as
    /// §7.6.2 requires: a packet sent between the two edges in *any* space
    /// breaks the period if it was acknowledged, or if it is still in flight
    /// (its fate is not known yet, so it has not been declared lost either).
    /// Packets that were never in flight (ACK-only) are not tracked and
    /// therefore not considered, as in the reference. The walk below simply
    /// follows send time: within a space packet-number order is send order
    /// and both loss rules are monotone in it, and the history holds only
    /// packets already judged, so a packet sent between two of the losses
    /// and not among them is either acknowledged or still in flight.
    pub(crate) fn in_persistent_congestion(&self, lost: &[SentPacket]) -> bool {
        let Some(first_sample) = self.first_rtt_sample else {
            return false;
        };
        let floor = self
            .persistent_congestion_declared
            .map_or(first_sample, |declared| first_sample.max(declared));
        let duration = self.persistent_congestion_duration();
        let mut losses: Vec<(Duration, bool)> = self
            .lost_history
            .iter()
            .map(|r| (r.time_sent, r.ack_eliciting))
            .chain(lost.iter().map(|p| (p.time_sent, p.ack_eliciting)))
            .filter(|&(time_sent, _)| time_sent > floor)
            .collect();
        losses.sort_by_key(|&(time_sent, _)| time_sent);
        // `run_start`: send time of the earliest ack-eliciting packet of the
        // current run of losses with nothing acknowledged or outstanding in
        // between. `prev`: send time of the previous loss.
        let mut run_start: Option<Duration> = None;
        let mut prev: Option<Duration> = None;
        for (time_sent, ack_eliciting) in losses {
            if let Some(prev_t) = prev
                && self.progress_between(prev_t, time_sent)
            {
                run_start = None;
            }
            prev = Some(time_sent);
            if !ack_eliciting {
                continue;
            }
            match run_start {
                None => run_start = Some(time_sent),
                Some(start) if time_sent.saturating_sub(start) >= duration => return true,
                Some(_) => {}
            }
        }
        false
    }

    /// RFC 9002 §B.8 `OnPacketsLost`, the persistent-congestion part, for
    /// `lost`, a batch [`Self::detect_lost`] just declared lost in `space` at
    /// `now`: judges it together with the recent-loss history
    /// ([`Self::in_persistent_congestion`]), then folds it into that history
    /// — or, once persistent congestion is established, clears the history
    /// and records the declaration, so one period collapses the window
    /// once. Returns whether the caller must collapse it.
    pub(crate) fn record_lost_batch(
        &mut self,
        space: PnSpaceId,
        lost: &[SentPacket],
        now: Duration,
    ) -> bool {
        self.prune_lost_history(now);
        let established = self.in_persistent_congestion(lost);
        if established {
            self.lost_history.clear();
            self.persistent_congestion_declared = Some(now);
        } else {
            self.lost_history.extend(lost.iter().map(|p| LostRecord {
                time_sent: p.time_sent,
                space,
                ack_eliciting: p.ack_eliciting,
            }));
            self.prune_lost_history(now);
        }
        established
    }

    /// Drops the recorded losses that can no longer be the older edge of a
    /// persistent-congestion period: packets sent more than twice
    /// [`Self::persistent_congestion_duration`] ago (a period reaching `now`
    /// is established by newer losses alone) or before the last declaration.
    fn prune_lost_history(&mut self, now: Duration) {
        let horizon = now.saturating_sub(self.persistent_congestion_duration().saturating_mul(2));
        let floor = self
            .persistent_congestion_declared
            .map_or(horizon, |declared| horizon.max(declared));
        self.lost_history.retain(|r| r.time_sent > floor);
    }

    /// §7.6.2 — did anything sent between two lost packets (sent at `lo` and
    /// `hi`, in any space) get acknowledged, or is it still awaiting a
    /// verdict? An acknowledgment counts even for a packet sent in the same
    /// instant as an edge (something sent then did get through); a packet
    /// still in flight only counts strictly between, since the packet
    /// threshold routinely declares a packet lost while its
    /// same-instant successors are still pending.
    fn progress_between(&self, lo: Duration, hi: Duration) -> bool {
        self.acked_send_times.iter().any(|&t| lo <= t && t <= hi)
            || self.per_space.iter().any(|ps| {
                ps.sent_packets
                    .values()
                    .any(|q| lo < q.time_sent && q.time_sent < hi)
            })
    }

    /// Drops every recorded acknowledged send time older than both the
    /// oldest packet still in flight in any space and the oldest recorded
    /// loss (all of them once neither exists): no future loss batch can
    /// have an edge sent before that.
    fn prune_acked_send_times(&mut self) {
        let oldest = self
            .per_space
            .iter()
            .filter_map(|ps| ps.sent_packets.values().next().map(|p| p.time_sent))
            .chain(self.lost_history.iter().map(|r| r.time_sent))
            .min();
        match oldest {
            Some(t) => self.acked_send_times.retain(|&a| a >= t),
            None => self.acked_send_times.clear(),
        }
    }

    /// RFC 9002 Appendix A — `OnLossDetectionTimeout`.
    ///
    /// Returns `None` when the timer is not armed or has not expired at
    /// `now`. Otherwise decides what it expired for: a pending time-threshold
    /// loss deadline ([`TimeoutAction::DetectLoss`] — the caller runs
    /// [`Self::detect_lost`] for that space, which re-arms the timer) or the
    /// PTO ([`TimeoutAction::Pto`]). On PTO expiry `pto_count` is bumped, the
    /// §6.2.4 probe credit is armed for the space the caller must probe, and
    /// the timer is re-armed with the doubled backoff (§6.2.4).
    ///
    /// At most one PTO fires per call: a clock that jumped several PTO
    /// periods ahead yields one expiry now and the next on the following
    /// call, so a single late timer tick cannot inflate the backoff.
    pub(crate) fn on_loss_detection_timeout(&mut self, now: Duration) -> Option<TimeoutAction> {
        let deadline = self.loss_detection_timer?;
        if deadline > now {
            return None;
        }
        // §A.9 step 1 — time-threshold loss first.
        if let (Some(t), Some(space)) = self.earliest_loss_time()
            && t <= now
        {
            return Some(TimeoutAction::DetectLoss(space));
        }
        // §A.9 step 2 — PTO. With nothing in flight this is the client's
        // anti-deadlock probe (§6.2.2.1): a Handshake packet once Handshake
        // keys exist, otherwise a padded Initial.
        let space = if !self.has_ack_eliciting_in_flight() {
            if self.peer_completed_address_validation() {
                // Nothing to probe for; the timer was stale. Re-arm (which
                // disarms it) and report nothing.
                self.set_loss_detection_timer(now);
                return None;
            }
            if self.ctx.has_handshake_keys {
                PnSpaceId::Handshake
            } else {
                PnSpaceId::Initial
            }
        } else {
            match self.pto_time_and_space(now) {
                Some((_, space)) => space,
                None => {
                    self.set_loss_detection_timer(now);
                    return None;
                }
            }
        };
        self.pto_count = self.pto_count.saturating_add(1).min(PTO_BACKOFF_CAP);
        self.arm_probe(space);
        self.set_loss_detection_timer(now);
        Some(TimeoutAction::Pto(space))
    }

    /// The `n` oldest ack-eliciting packets still outstanding in `space`, in
    /// send order — what a PTO probe retransmits when there is no new data
    /// to send (RFC 9002 §6.2.4). The packets stay in flight: they are
    /// neither acknowledged nor lost yet, only re-sent.
    pub(crate) fn oldest_ack_eliciting(&self, space: PnSpaceId, n: usize) -> Vec<SentPacket> {
        self.per_space[space as usize]
            .sent_packets
            .values()
            .filter(|p| p.ack_eliciting)
            .take(n)
            .cloned()
            .collect()
    }

    /// RFC 9000 §9.4 — discard the RTT estimate after confirming a peer's
    /// migration to a new path, returning the estimator to the §5.3 initial
    /// values. `min_rtt` in particular must go: it is a floor derived from a
    /// path that is no longer in use.
    pub(crate) fn reset_rtt(&mut self) {
        self.latest_rtt = Duration::ZERO;
        self.smoothed_rtt = K_INITIAL_RTT;
        self.rttvar = K_INITIAL_RTT / 2;
        self.min_rtt = Duration::MAX;
        self.first_rtt_sample = None;
        // Losses on the old path say nothing about the new one.
        self.lost_history.clear();
        self.persistent_congestion_declared = None;
    }

    /// RFC 9002 §6.2.1 — the PTO period without `max_ack_delay`:
    /// `smoothed_rtt + max(4 × rttvar, kGranularity)`. This is the whole
    /// period for the Initial and Handshake spaces; the Application space
    /// adds `max_ack_delay` (see [`Self::pto_period`]). Before the first RTT
    /// sample the §5.3 initial values make it `333 ms + 4 × 166.5 ms`
    /// (§6.2.2).
    pub(crate) fn pto_base(&self) -> Duration {
        let four_rttvar = self.rttvar.saturating_mul(4);
        let g = core::cmp::max(four_rttvar, K_GRANULARITY);
        self.smoothed_rtt.saturating_add(g)
    }

    /// RFC 9002 §6.2.1 — `PTO` for the Application space:
    /// `smoothed_rtt + max(4 × rttvar, kGranularity) + max_ack_delay`. Also
    /// what RFC 9000 §10.1 / §10.2 mean by "the PTO" when sizing the idle
    /// and closing periods.
    pub(crate) fn pto_period(&self) -> Duration {
        self.pto_base().saturating_add(self.max_ack_delay)
    }

    /// `2^pto_count`, capped so the multiplication below cannot overflow.
    fn pto_backoff(&self) -> u32 {
        1u32 << self.pto_count.min(PTO_BACKOFF_CAP)
    }

    /// `d × 2^pto_count`, saturating at one minute rather than overflowing.
    fn backed_off(&self, d: Duration) -> Duration {
        d.checked_mul(self.pto_backoff())
            .unwrap_or(Duration::from_secs(60))
    }

    /// RFC 9002 §A.8 — `GetPtoTimeAndSpace`.
    ///
    /// The PTO deadline and the space it belongs to: for every space with
    /// ack-eliciting packets in flight, `time_of_last_ack_eliciting_packet +
    /// PTO(space) × 2^pto_count`, and the earliest wins. The Application
    /// space is skipped until the handshake is confirmed (§6.2.1) and is the
    /// only one whose period includes `max_ack_delay`. With nothing in
    /// flight the client's anti-deadlock deadline (§6.2.2.1) starts from
    /// `now`. `None` when no space qualifies.
    pub(crate) fn pto_time_and_space(&self, now: Duration) -> Option<(Duration, PnSpaceId)> {
        let duration = self.backed_off(self.pto_base());
        if !self.has_ack_eliciting_in_flight() {
            if self.peer_completed_address_validation() {
                return None;
            }
            let space = if self.ctx.has_handshake_keys {
                PnSpaceId::Handshake
            } else {
                PnSpaceId::Initial
            };
            return Some((now.saturating_add(duration), space));
        }
        let mut earliest: Option<(Duration, PnSpaceId)> = None;
        for space in [
            PnSpaceId::Initial,
            PnSpaceId::Handshake,
            PnSpaceId::Application,
        ] {
            let ps = &self.per_space[space as usize];
            if !ps.sent_packets.values().any(|p| p.ack_eliciting) {
                continue;
            }
            let mut duration = duration;
            if space == PnSpaceId::Application {
                if !self.ctx.handshake_confirmed {
                    return earliest;
                }
                duration = duration.saturating_add(self.backed_off(self.max_ack_delay));
            }
            let Some(anchor) = ps.time_of_last_ack_eliciting_packet else {
                continue;
            };
            let t = anchor.saturating_add(duration);
            if earliest.is_none_or(|(prev, _)| t < prev) {
                earliest = Some((t, space));
            }
        }
        earliest
    }

    /// RFC 9002 Appendix A — `SetLossDetectionTimer`.
    ///
    /// Recomputes [`Self::loss_detection_timer`] from the current state. The
    /// timer is the earliest `loss_time` across all spaces if any is pending
    /// (§6.1.2); otherwise it is cancelled while a server is at its
    /// anti-amplification limit or while nothing ack-eliciting is in flight
    /// and the peer has validated our address (§6.2.2.1); otherwise it is the
    /// PTO deadline from [`Self::pto_time_and_space`].
    pub(crate) fn set_loss_detection_timer(&mut self, now: Duration) {
        if let (Some(t), _) = self.earliest_loss_time() {
            self.loss_detection_timer = Some(t);
            return;
        }
        if self.ctx.is_server && self.ctx.at_amplification_limit {
            self.loss_detection_timer = None;
            return;
        }
        if !self.has_ack_eliciting_in_flight() && self.peer_completed_address_validation() {
            self.loss_detection_timer = None;
            return;
        }
        self.loss_detection_timer = self.pto_time_and_space(now).map(|(t, _)| t);
    }

    /// The earliest pending time-threshold loss deadline across all spaces,
    /// with the space it belongs to. The connection driver arms a timer on it
    /// so RFC 9002 §6.1.2 loss detection fires on time rather than only when
    /// the next ACK happens to arrive (H-6).
    pub(crate) fn next_loss_time(&self) -> Option<(Duration, PnSpaceId)> {
        match self.earliest_loss_time() {
            (Some(t), Some(s)) => Some((t, s)),
            _ => None,
        }
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
    ///
    /// Returns the packets that were still outstanding in the space. RFC 9002
    /// §A.10 (`OnPacketNumberSpaceDiscarded`) requires the caller to subtract
    /// their `sent_bytes` from the congestion controller's `bytes_in_flight`
    /// — without a source of ACKs for a space whose keys are gone, those bytes
    /// would otherwise stay counted for the life of the connection and
    /// eventually wedge `can_send()` at `false` (H-6).
    ///
    /// Per §A.10 the PTO backoff restarts too, and any probes still owed in
    /// the discarded space are forgotten. `now` anchors the re-armed timer.
    #[must_use = "the drained packets must be removed from bytes_in_flight (RFC 9002 §A.10)"]
    pub(crate) fn discard_keys(&mut self, space: PnSpaceId, now: Duration) -> Vec<SentPacket> {
        let ps = &mut self.per_space[space as usize];
        let drained: Vec<SentPacket> = core::mem::take(&mut ps.sent_packets)
            .into_values()
            .collect();
        ps.largest_acked_packet = None;
        ps.loss_time = None;
        ps.time_of_last_ack_eliciting_packet = None;
        self.pto_count = 0;
        if self.probe_space == Some(space) {
            self.clear_probe();
        }
        // The space's packets no longer count, its recorded losses included.
        self.lost_history.retain(|r| r.space != space);
        self.prune_acked_send_times();
        self.set_loss_detection_timer(now);
        drained
    }

    /// True iff any packet-number space has ack-eliciting packets in flight —
    /// the RFC 9002 §6.2.1 condition for the PTO timer to be armed at all.
    pub(crate) fn has_ack_eliciting_in_flight(&self) -> bool {
        self.per_space
            .iter()
            .any(|ps| ps.sent_packets.values().any(|p| p.ack_eliciting))
    }

    /// True iff `space` has ack-eliciting packets in flight.
    pub(crate) fn space_has_ack_eliciting_in_flight(&self, space: PnSpaceId) -> bool {
        self.per_space[space as usize]
            .sent_packets
            .values()
            .any(|p| p.ack_eliciting)
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
// These tests pass ACK ranges as `&[a..=b]` slices, and a range covering a
// single packet number is a legitimate (and common) case. The lint reads a
// one-element array of `RangeInclusive` as a mistyped `vec![v; n]`, which it is
// not here.
#[allow(clippy::single_range_in_vec_init)]
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
            handshake_done: false,
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
            Duration::from_secs(1),
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
            Duration::from_secs(1),
        );
        // After 1st: smoothed=80ms rttvar=40ms.
        // 2nd sample = 100ms, no ack_delay, min_rtt=80ms still.
        s.update_rtt(
            Duration::from_millis(100),
            Duration::ZERO,
            PnSpaceId::Initial,
            Duration::from_secs(1),
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
            Duration::from_secs(1),
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

    /// Test 4 — RFC 9002 §6.2.2 / §6.2.4: before any RTT sample the PTO is
    /// `kInitialRtt + 4 × kInitialRtt/2 = 999 ms` from the last ack-eliciting
    /// send, the timer fires exactly then (not a moment earlier), and every
    /// consecutive expiry doubles the period (`2^pto_count`) while the anchor
    /// stays the last ack-eliciting send.
    #[test]
    fn pto_fires_at_computed_time_and_backs_off() {
        let mut s = LossState::new();
        s.ctx.is_server = true;
        s.on_packet_sent(PnSpaceId::Initial, mk_packet(0, true, true, Duration::ZERO));
        let base = K_INITIAL_RTT + (K_INITIAL_RTT / 2) * 4;
        assert_eq!(base, Duration::from_millis(999));
        assert_eq!(s.pto_base(), base);
        assert_eq!(s.loss_detection_timer, Some(base), "initial pto");
        assert_eq!(
            s.on_loss_detection_timeout(base - Duration::from_millis(1)),
            None,
            "not yet"
        );
        assert_eq!(
            s.on_loss_detection_timeout(base),
            Some(TimeoutAction::Pto(PnSpaceId::Initial))
        );
        assert_eq!(s.pto_count, 1);
        assert_eq!(s.probe_space(), Some(PnSpaceId::Initial));
        assert_eq!(s.probe_credit(PnSpaceId::Initial), K_PTO_PROBES);
        assert!(s.probe_needs_ping(PnSpaceId::Initial));
        assert_eq!(s.loss_detection_timer, Some(base * 2), "after 1 timeout");
        // The clock jumping far past the deadline still fires once per call.
        assert_eq!(
            s.on_loss_detection_timeout(Duration::from_secs(60)),
            Some(TimeoutAction::Pto(PnSpaceId::Initial))
        );
        assert_eq!(s.pto_count, 2);
        assert_eq!(s.loss_detection_timer, Some(base * 4), "after 2 timeouts");
        // Progress: an ACK resets the backoff and re-arms from the remaining
        // in-flight packet (none here — so the timer is disarmed).
        let _ = s.on_ack_received(
            PnSpaceId::Initial,
            &[0u64..=0u64],
            Duration::ZERO,
            Duration::from_secs(61),
        );
        assert_eq!(s.pto_count, 0);
        assert_eq!(s.probe_space(), None);
        assert_eq!(s.loss_detection_timer, None);
    }

    /// RFC 9002 §6.2.1 — the Application space gets no PTO timer until the
    /// handshake is confirmed, and its period includes `max_ack_delay`
    /// (backed off with the rest) once it does.
    #[test]
    fn application_pto_waits_for_handshake_confirmation() {
        let mut s = LossState::new();
        s.ctx.is_server = true;
        s.on_packet_sent(
            PnSpaceId::Application,
            mk_packet(0, true, true, Duration::from_millis(100)),
        );
        assert_eq!(s.loss_detection_timer, None, "not confirmed yet");
        s.ctx.handshake_confirmed = true;
        s.set_loss_detection_timer(Duration::from_millis(100));
        assert_eq!(
            s.loss_detection_timer,
            Some(Duration::from_millis(100) + s.pto_period())
        );
        assert_eq!(s.pto_period(), s.pto_base() + Duration::from_millis(25));
        assert_eq!(
            s.on_loss_detection_timeout(Duration::from_secs(5)),
            Some(TimeoutAction::Pto(PnSpaceId::Application))
        );
        assert_eq!(
            s.loss_detection_timer,
            Some(Duration::from_millis(100) + s.pto_period() * 2)
        );
    }

    /// RFC 9002 §6.2.2.1 — a client keeps a PTO armed with nothing in flight
    /// until the server acknowledges a Handshake packet (or the handshake is
    /// confirmed); the probe is a padded Initial without Handshake keys and a
    /// Handshake packet with them. A server never probes on an empty flight.
    #[test]
    fn client_probes_with_nothing_in_flight_until_validated() {
        let mut s = LossState::new();
        let now = Duration::from_secs(1);
        s.set_loss_detection_timer(now);
        assert_eq!(s.loss_detection_timer, Some(now + s.pto_base()));
        assert_eq!(
            s.on_loss_detection_timeout(now + s.pto_base()),
            Some(TimeoutAction::Pto(PnSpaceId::Initial))
        );
        s.ctx.has_handshake_keys = true;
        assert_eq!(
            s.on_loss_detection_timeout(Duration::from_secs(30)),
            Some(TimeoutAction::Pto(PnSpaceId::Handshake))
        );
        // A Handshake ACK ends the anti-deadlock probing.
        s.on_packet_sent(
            PnSpaceId::Handshake,
            mk_packet(0, true, true, Duration::from_secs(31)),
        );
        let _ = s.on_ack_received(
            PnSpaceId::Handshake,
            &[0u64..=0u64],
            Duration::ZERO,
            Duration::from_secs(32),
        );
        assert!(s.ctx.peer_handshake_acked);
        assert_eq!(s.pto_count, 0, "validated peer: backoff reset");
        assert_eq!(s.loss_detection_timer, None);
        // A server with nothing in flight has no timer either.
        let mut srv = LossState::new();
        srv.ctx.is_server = true;
        srv.set_loss_detection_timer(now);
        assert_eq!(srv.loss_detection_timer, None);
        assert_eq!(srv.on_loss_detection_timeout(Duration::from_secs(9)), None);
    }

    /// RFC 9002 §6.2.2.1 — a server at its anti-amplification limit cannot
    /// send a probe, so its timer is cancelled until a client datagram lifts
    /// the limit.
    #[test]
    fn server_timer_is_cancelled_at_amplification_limit() {
        let mut s = LossState::new();
        s.ctx.is_server = true;
        s.ctx.at_amplification_limit = true;
        s.on_packet_sent(PnSpaceId::Initial, mk_packet(0, true, true, Duration::ZERO));
        assert_eq!(s.loss_detection_timer, None);
        s.ctx.at_amplification_limit = false;
        s.set_loss_detection_timer(Duration::from_millis(50));
        assert_eq!(s.loss_detection_timer, Some(s.pto_base()));
    }

    /// The §6.2.4 probe credit belongs to the space whose PTO expired and is
    /// spent one ack-eliciting packet at a time.
    #[test]
    fn probe_credit_is_per_space() {
        let mut s = LossState::new();
        s.ctx.is_server = true;
        s.on_packet_sent(
            PnSpaceId::Handshake,
            mk_packet(0, true, true, Duration::ZERO),
        );
        assert_eq!(
            s.on_loss_detection_timeout(Duration::from_secs(2)),
            Some(TimeoutAction::Pto(PnSpaceId::Handshake))
        );
        assert_eq!(s.probe_credit(PnSpaceId::Handshake), K_PTO_PROBES);
        assert_eq!(s.probe_credit(PnSpaceId::Application), 0);
        assert!(!s.probe_needs_ping(PnSpaceId::Application));
        s.consume_probe_credit();
        assert!(!s.probe_needs_ping(PnSpaceId::Handshake));
        assert_eq!(s.probe_credit(PnSpaceId::Handshake), 1);
        s.consume_probe_credit();
        assert_eq!(s.probe_space(), None);
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

    /// RFC 9002 §A.8 `GetPtoTimeAndSpace` — the PTO timer is the earliest
    /// per-space deadline among spaces with ack-eliciting packets in flight,
    /// each anchored on its own last ack-eliciting send.
    #[test]
    fn pto_timer_is_the_earliest_space_deadline() {
        let mut s = LossState::new();
        s.ctx.is_server = true;
        s.ctx.handshake_confirmed = true;
        // Handshake in flight since t=0; Application sent later at t=500ms.
        s.on_packet_sent(
            PnSpaceId::Handshake,
            mk_packet(0, true, true, Duration::ZERO),
        );
        s.on_packet_sent(
            PnSpaceId::Application,
            mk_packet(0, true, true, Duration::from_millis(500)),
        );
        assert_eq!(
            s.loss_detection_timer,
            Some(s.pto_base()),
            "the older Handshake deadline fires first"
        );
        // Once the Handshake packet is acked, only the Application space
        // counts — anchored on ITS last send, with max_ack_delay included.
        let _ = s.on_ack_received(
            PnSpaceId::Handshake,
            &[0u64..=0u64],
            Duration::ZERO,
            Duration::from_millis(600),
        );
        assert_eq!(
            s.loss_detection_timer,
            Some(Duration::from_millis(500) + s.pto_period())
        );
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
        assert_eq!(
            s.first_rtt_sample,
            Some(Duration::from_millis(50)),
            "§A.1.2: the time the first sample was obtained"
        );
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
        let drained = s.discard_keys(PnSpaceId::Initial, Duration::from_secs(1));
        assert!(!drained.is_empty(), "outstanding packets must be returned");
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

    /// RFC 9002 §A.10 — discarding a space restarts the PTO backoff and
    /// forgets probes owed there.
    #[test]
    fn discard_keys_resets_backoff_and_probes() {
        let mut s = LossState::new();
        s.ctx.is_server = true;
        s.on_packet_sent(PnSpaceId::Initial, mk_packet(0, true, true, Duration::ZERO));
        assert!(
            s.on_loss_detection_timeout(Duration::from_secs(2))
                .is_some()
        );
        assert!(
            s.on_loss_detection_timeout(Duration::from_secs(4))
                .is_some()
        );
        assert_eq!(s.pto_count, 2);
        let _ = s.discard_keys(PnSpaceId::Initial, Duration::from_secs(4));
        assert_eq!(s.pto_count, 0);
        assert_eq!(s.probe_space(), None);
        assert_eq!(s.loss_detection_timer, None);
    }

    /// RFC 9002 §7.6.1 — the duration is `PTO × kPersistentCongestionThreshold`
    /// with `max_ack_delay` always included.
    #[test]
    fn persistent_congestion_duration_is_three_ptos() {
        let mut s = LossState::new();
        s.smoothed_rtt = Duration::from_millis(100);
        s.rttvar = Duration::from_millis(25);
        s.max_ack_delay = Duration::from_millis(25);
        assert_eq!(
            s.persistent_congestion_duration(),
            Duration::from_millis(3 * 225)
        );
    }

    /// Sends and acknowledges one Application packet so the state has an
    /// RTT sample taken at `t = 100 ms` (`smoothed_rtt = 100 ms`,
    /// `rttvar = 50 ms`).
    fn state_with_rtt_sample() -> LossState {
        let mut s = LossState::new();
        s.ctx.is_server = true;
        s.ctx.handshake_confirmed = true;
        s.on_packet_sent(
            PnSpaceId::Application,
            mk_packet(0, true, true, Duration::ZERO),
        );
        let acked = s.on_ack_received(
            PnSpaceId::Application,
            &[0u64..=0u64],
            Duration::ZERO,
            Duration::from_millis(100),
        );
        assert_eq!(acked.len(), 1);
        assert_eq!(s.first_rtt_sample, Some(Duration::from_millis(100)));
        s
    }

    /// Sends Application packets 1..=5 at the given times, then packet 6 at
    /// 1600 ms and acknowledges it at 1700 ms (a 100 ms sample), and returns
    /// the batch `detect_lost` declares lost at that point.
    fn lose_flight(s: &mut LossState, times_ms: [u64; 5]) -> Vec<SentPacket> {
        for (i, t) in times_ms.iter().enumerate() {
            s.on_packet_sent(
                PnSpaceId::Application,
                mk_packet(i as u64 + 1, true, true, Duration::from_millis(*t)),
            );
        }
        s.on_packet_sent(
            PnSpaceId::Application,
            mk_packet(6, true, true, Duration::from_millis(1600)),
        );
        let acked = s.on_ack_received(
            PnSpaceId::Application,
            &[6u64..=6u64],
            Duration::ZERO,
            Duration::from_millis(1700),
        );
        assert_eq!(acked.len(), 1);
        s.detect_lost(PnSpaceId::Application, Duration::from_millis(1700))
    }

    /// RFC 9002 §7.6.2 (1) — two lost ack-eliciting packets sent further
    /// apart than the duration, with everything between them lost too and
    /// an RTT sample taken before the first: persistent congestion.
    #[test]
    fn persistent_congestion_when_losses_span_the_duration() {
        let mut s = state_with_rtt_sample();
        let lost = lose_flight(&mut s, [200, 400, 1000, 1300, 1500]);
        assert_eq!(lost.len(), 5, "packets 1..=5 all lost");
        let duration = s.persistent_congestion_duration();
        assert!(
            Duration::from_millis(1300) >= duration,
            "test premise: the span exceeds {duration:?}"
        );
        assert!(s.in_persistent_congestion(&lost));
        // Lost packets sent before the first RTT sample are not
        // considered (§7.6.1 / §B.8).
        let mut fresh = LossState::new();
        fresh.first_rtt_sample = Some(Duration::from_millis(1400));
        assert!(!fresh.in_persistent_congestion(&lost));
        // The edges have to be ack-eliciting: with only packets 3 and 4
        // (1000 ms and 1300 ms) ack-eliciting, the losses span 300 ms.
        let padding: Vec<SentPacket> = lost
            .iter()
            .cloned()
            .map(|mut p| {
                if p.pn != 3 && p.pn != 4 {
                    p.ack_eliciting = false;
                }
                p
            })
            .collect();
        assert!(!s.in_persistent_congestion(&padding));
    }

    /// RFC 9002 §7.6.2 (2) — a packet acknowledged between the two lost
    /// edges means the period was not one of persistent congestion, whether
    /// it lived in the same space or (§7.6.2 "across packet number spaces")
    /// another one; so does a packet in another space whose fate is still
    /// unknown.
    #[test]
    fn persistent_congestion_needs_nothing_acked_in_between() {
        // Same space: packet 3 (sent at 1000 ms) is acknowledged.
        let mut s = state_with_rtt_sample();
        for (pn, t) in [(1, 200), (2, 400), (3, 1000), (4, 1300), (5, 1500)] {
            s.on_packet_sent(
                PnSpaceId::Application,
                mk_packet(pn, true, true, Duration::from_millis(t)),
            );
        }
        s.on_packet_sent(
            PnSpaceId::Application,
            mk_packet(6, true, true, Duration::from_millis(1600)),
        );
        let _ = s.on_ack_received(
            PnSpaceId::Application,
            &[3u64..=3u64, 6u64..=6u64],
            Duration::ZERO,
            Duration::from_millis(1700),
        );
        let lost = s.detect_lost(PnSpaceId::Application, Duration::from_millis(1700));
        assert_eq!(lost.len(), 4);
        assert!(!s.in_persistent_congestion(&lost));

        // Another space: a Handshake packet sent at 1000 ms, between
        // Application packets 2 and 3, is acknowledged (at 1100 ms) or is
        // still in flight when the Application batch is judged. Either way
        // the batch does not establish persistent congestion: the Handshake
        // packet was sent between its edges and has not been declared lost.
        for acked in [true, false] {
            let mut s = state_with_rtt_sample();
            for (pn, t) in [(1, 200), (2, 400)] {
                s.on_packet_sent(
                    PnSpaceId::Application,
                    mk_packet(pn, true, true, Duration::from_millis(t)),
                );
            }
            s.on_packet_sent(
                PnSpaceId::Handshake,
                mk_packet(0, true, true, Duration::from_millis(1000)),
            );
            if acked {
                let got = s.on_ack_received(
                    PnSpaceId::Handshake,
                    &[0u64..=0u64],
                    Duration::ZERO,
                    Duration::from_millis(1100),
                );
                assert_eq!(got.len(), 1);
            }
            for (pn, t) in [(3, 1200), (4, 1300), (5, 1500), (6, 1600)] {
                s.on_packet_sent(
                    PnSpaceId::Application,
                    mk_packet(pn, true, true, Duration::from_millis(t)),
                );
            }
            let got = s.on_ack_received(
                PnSpaceId::Application,
                &[6u64..=6u64],
                Duration::ZERO,
                Duration::from_millis(1700),
            );
            assert_eq!(got.len(), 1);
            let lost = s.detect_lost(PnSpaceId::Application, Duration::from_millis(1700));
            assert_eq!(lost.len(), 5);
            assert!(
                Duration::from_millis(1300) >= s.persistent_congestion_duration(),
                "test premise: the batch would otherwise qualify"
            );
            assert!(
                !s.in_persistent_congestion(&lost),
                "handshake packet acked={acked}"
            );
        }
    }

    /// RFC 9002 §7.6.2 (3) — no RTT sample before the losses: the very ACK
    /// that reveals them takes the first sample, so every lost packet
    /// predates it and none counts.
    #[test]
    fn persistent_congestion_needs_an_rtt_sample() {
        let mut s = LossState::new();
        s.ctx.is_server = true;
        s.ctx.handshake_confirmed = true;
        assert!(s.first_rtt_sample.is_none());
        let lost = lose_flight(&mut s, [200, 400, 1000, 1300, 1500]);
        assert_eq!(lost.len(), 5);
        assert_eq!(s.first_rtt_sample, Some(Duration::from_millis(1700)));
        assert!(!s.in_persistent_congestion(&lost));
    }

    /// RFC 9002 §7.6.2 (4) — losses closer together than the duration are
    /// ordinary losses.
    #[test]
    fn persistent_congestion_needs_the_full_duration() {
        let mut s = state_with_rtt_sample();
        let lost = lose_flight(&mut s, [200, 300, 400, 500, 600]);
        assert_eq!(lost.len(), 5);
        assert!(Duration::from_millis(400) < s.persistent_congestion_duration());
        assert!(!s.in_persistent_congestion(&lost));
    }

    /// The acknowledged-send-time record only keeps what can still fall
    /// between two packets awaiting a verdict.
    #[test]
    fn acked_send_times_are_pruned() {
        let mut s = state_with_rtt_sample();
        assert!(s.acked_send_times.is_empty(), "nothing in flight");
        s.on_packet_sent(
            PnSpaceId::Application,
            mk_packet(1, true, true, Duration::from_millis(200)),
        );
        for pn in 2..=4u64 {
            s.on_packet_sent(
                PnSpaceId::Application,
                mk_packet(pn, true, true, Duration::from_millis(200 + pn)),
            );
            let _ = s.on_ack_received(
                PnSpaceId::Application,
                &[pn..=pn],
                Duration::ZERO,
                Duration::from_millis(300 + pn),
            );
        }
        assert_eq!(s.acked_send_times.len(), 3, "packet 1 is still pending");
        let lost = s.detect_lost(PnSpaceId::Application, Duration::from_millis(400));
        assert_eq!(lost.len(), 1);
        assert_eq!(
            s.acked_send_times.len(),
            3,
            "kept until the batch has been judged"
        );
        s.on_packet_sent(
            PnSpaceId::Application,
            mk_packet(5, true, true, Duration::from_millis(500)),
        );
        let _ = s.on_ack_received(
            PnSpaceId::Application,
            &[5u64..=5u64],
            Duration::ZERO,
            Duration::from_millis(600),
        );
        assert!(s.acked_send_times.is_empty(), "nothing left in flight");
    }

    fn ms(t: u64) -> Duration {
        Duration::from_millis(t)
    }

    /// An outage from 200 ms to 1400 ms in which Application packets A1..A3
    /// and Handshake packets H1, H2 are all lost, then Application A4, A5
    /// and Handshake H3 sent once the path recovers and acknowledged by one
    /// ACK each, at 1510, 1520 and 1540 ms. The losses surface in three
    /// batches: the packet and time thresholds give A1, A2 on the first ACK
    /// and A3 on the second, and the Handshake ACK gives H1, H2. With
    /// `acked_in_between`, an Application packet sent at 950 ms is
    /// acknowledged at 1050 ms: something got through mid-outage.
    /// Returns the three batches and what `record_lost_batch` said of each.
    fn three_batch_outage(
        s: &mut LossState,
        acked_in_between: bool,
    ) -> [(Vec<SentPacket>, bool); 3] {
        let app = PnSpaceId::Application;
        let hs = PnSpaceId::Handshake;
        s.on_packet_sent(app, mk_packet(1, true, true, ms(200)));
        s.on_packet_sent(hs, mk_packet(0, true, true, ms(500)));
        s.on_packet_sent(app, mk_packet(2, true, true, ms(800)));
        let mut pn = 3u64;
        if acked_in_between {
            s.on_packet_sent(app, mk_packet(pn, true, true, ms(950)));
            let got = s.on_ack_received(app, &[pn..=pn], Duration::ZERO, ms(1050));
            assert_eq!(got.len(), 1);
            pn += 1;
        }
        s.on_packet_sent(hs, mk_packet(1, true, true, ms(1100)));
        let a3 = pn;
        s.on_packet_sent(app, mk_packet(a3, true, true, ms(1400)));
        let (a4, a5) = (a3 + 1, a3 + 2);
        s.on_packet_sent(app, mk_packet(a4, true, true, ms(1410)));
        s.on_packet_sent(app, mk_packet(a5, true, true, ms(1420)));
        s.on_packet_sent(hs, mk_packet(2, true, true, ms(1440)));

        assert_eq!(
            s.on_ack_received(app, &[a4..=a4], Duration::ZERO, ms(1510))
                .len(),
            1
        );
        let first = s.detect_lost(app, ms(1510));
        assert_eq!(first.len(), 2, "A1 and A2");
        let first_pc = s.record_lost_batch(app, &first, ms(1510));

        assert_eq!(
            s.on_ack_received(app, &[a5..=a5], Duration::ZERO, ms(1520))
                .len(),
            1
        );
        let second = s.detect_lost(app, ms(1520));
        assert_eq!(second.len(), 1, "A3");
        let second_pc = s.record_lost_batch(app, &second, ms(1520));

        assert_eq!(
            s.on_ack_received(hs, &[2u64..=2u64], Duration::ZERO, ms(1540))
                .len(),
            1
        );
        let third = s.detect_lost(hs, ms(1540));
        assert_eq!(third.len(), 2, "H1 and H2");
        assert!(
            ms(1200) >= s.persistent_congestion_duration(),
            "test premise: 200..1400 ms spans {:?}",
            s.persistent_congestion_duration()
        );
        let third_pc = s.record_lost_batch(hs, &third, ms(1540));
        [(first, first_pc), (second, second_pc), (third, third_pc)]
    }

    /// RFC 9002 §7.6 — losses revealed by three ACKs, in two packet-number
    /// spaces, that together span the persistent-congestion duration with
    /// nothing acknowledged in between establish persistent congestion on
    /// the batch that completes the picture; each batch on its own does
    /// not (the first two have the Handshake packets still in flight
    /// between their edges). The period is then declared once: a later
    /// batch of losses from the same period does not re-declare it, and
    /// the history starts over.
    #[test]
    fn persistent_congestion_across_loss_batches() {
        let mut s = state_with_rtt_sample();
        let [(first, first_pc), (second, second_pc), (third, third_pc)] =
            three_batch_outage(&mut s, false);
        assert!(!first_pc, "A1, A2 alone: {first:?}");
        assert!(!second_pc, "A1..A3 with H1, H2 outstanding: {second:?}");
        assert!(third_pc, "A1..A3 + H1, H2: {third:?}");
        assert!(s.lost_history.is_empty(), "the history restarts");
        assert_eq!(s.persistent_congestion_declared, Some(ms(1540)));

        // A straggler from the same period — an Initial packet sent at
        // 300 ms, revealed lost by an Initial ACK — must not declare again.
        let init = PnSpaceId::Initial;
        s.on_packet_sent(init, mk_packet(0, true, true, ms(300)));
        s.on_packet_sent(init, mk_packet(1, true, true, ms(1450)));
        assert_eq!(
            s.on_ack_received(init, &[1u64..=1u64], Duration::ZERO, ms(1550))
                .len(),
            1
        );
        let straggler = s.detect_lost(init, ms(1550));
        assert_eq!(straggler.len(), 1);
        assert!(!s.record_lost_batch(init, &straggler, ms(1550)));
        assert!(
            s.lost_history.is_empty(),
            "a loss from the declared period is not kept"
        );
    }

    /// RFC 9002 §7.6.2 — the same three batches, but a packet sent in the
    /// middle of the outage was acknowledged: the period is broken there,
    /// and neither half spans the duration.
    #[test]
    fn persistent_congestion_across_batches_needs_nothing_acked_in_between() {
        let mut s = state_with_rtt_sample();
        let [(_, first_pc), (_, second_pc), (third, third_pc)] = three_batch_outage(&mut s, true);
        assert!(!first_pc && !second_pc);
        assert!(!third_pc, "the 950 ms packet got through: {third:?}");
        assert!(s.persistent_congestion_declared.is_none());
        // Every loss sent within twice the duration stays on record.
        let horizon = ms(1540).saturating_sub(s.persistent_congestion_duration() * 2);
        let within = [200u64, 500, 800, 1100, 1400]
            .iter()
            .filter(|&&t| ms(t) > horizon)
            .count();
        assert!(within >= 3, "test premise: the horizon keeps most of them");
        assert_eq!(s.lost_history.len(), within);
    }

    /// The loss history and the acknowledged-send-time record it pins are
    /// pruned as time passes: after a loss-free run longer than twice the
    /// persistent-congestion duration both are empty, and neither grows
    /// past the losses actually recorded meanwhile.
    #[test]
    fn lost_history_is_pruned() {
        let app = PnSpaceId::Application;
        let mut s = state_with_rtt_sample();
        let lost = lose_flight(&mut s, [200, 300, 400, 500, 600]);
        assert_eq!(lost.len(), 5);
        assert!(!s.record_lost_batch(app, &lost, ms(1700)));
        assert_eq!(s.lost_history.len(), 5);
        // The record of the ACK that revealed them stays as long as the
        // history reaches back to 200 ms.
        assert_eq!(s.acked_send_times, alloc::vec![ms(1600)]);

        let mut t = 1700u64;
        for pn in 7..=200u64 {
            t += 100;
            s.on_packet_sent(app, mk_packet(pn, true, true, ms(t)));
            let acked = s.on_ack_received(app, &[pn..=pn], Duration::ZERO, ms(t + 50));
            assert_eq!(acked.len(), 1);
            assert!(s.detect_lost(app, ms(t + 50)).is_empty());
            assert!(s.lost_history.len() <= 5);
            assert!(
                s.acked_send_times.len() <= 1 + s.lost_history.len() * 4,
                "{} acknowledgments kept for {} losses",
                s.acked_send_times.len(),
                s.lost_history.len()
            );
        }
        assert!(s.lost_history.is_empty(), "aged out");
        assert!(s.acked_send_times.is_empty(), "nothing left to pin it");
        assert!(s.persistent_congestion_declared.is_none());
    }

    /// Discarding a packet-number space (RFC 9002 §6.4) forgets its
    /// recorded losses along with its packets; a path migration's RTT reset
    /// (RFC 9000 §9.4) forgets everything.
    #[test]
    fn lost_history_follows_key_discard_and_rtt_reset() {
        let mut s = state_with_rtt_sample();
        let hs = PnSpaceId::Handshake;
        let app = PnSpaceId::Application;
        for (space, pn, t) in [(hs, 0, 1000), (app, 1, 1100), (hs, 1, 1200), (app, 2, 1300)] {
            s.on_packet_sent(space, mk_packet(pn, true, true, ms(t)));
        }
        s.on_packet_sent(app, mk_packet(3, true, true, ms(1600)));
        s.on_packet_sent(hs, mk_packet(2, true, true, ms(1600)));
        let _ = s.on_ack_received(app, &[3u64..=3u64], Duration::ZERO, ms(1700));
        let _ = s.on_ack_received(hs, &[2u64..=2u64], Duration::ZERO, ms(1700));
        let app_lost = s.detect_lost(app, ms(1700));
        let hs_lost = s.detect_lost(hs, ms(1700));
        assert_eq!((app_lost.len(), hs_lost.len()), (2, 2));
        assert!(!s.record_lost_batch(app, &app_lost, ms(1700)));
        assert!(!s.record_lost_batch(hs, &hs_lost, ms(1700)));
        assert_eq!(s.lost_history.len(), 4);

        let _ = s.discard_keys(hs, ms(1800));
        assert_eq!(s.lost_history.len(), 2);
        assert!(s.lost_history.iter().all(|r| r.space == app));

        s.persistent_congestion_declared = Some(ms(1000));
        s.reset_rtt();
        assert!(s.lost_history.is_empty());
        assert!(s.persistent_congestion_declared.is_none());
    }
}
