//! QUIC packet numbers and per-space bookkeeping.
//!
//! QUIC has three packet-number spaces (RFC 9000 §12.3): Initial, Handshake,
//! and Application. The 0-RTT and 1-RTT levels share the Application space,
//! so although there are four *encryption levels* there are only three PN
//! spaces.
//!
//! Each space tracks:
//! - the next outbound packet number (`next_tx`),
//! - the largest received PN (`largest_rx`),
//! - the largest of our own PNs that the peer has acked (`largest_acked_tx`),
//! - a set of received PNs awaiting acknowledgement ([`AckRanges`]).
//!
//! Packet numbers are transmitted truncated to 1–4 bytes (RFC 9000 §17.1,
//! reference algorithm in Appendix A). [`decode_packet_number`] is the
//! verbatim §A.3 algorithm; [`encode_packet_number_length`] picks the
//! shortest length such that the receiver — armed with the same algorithm —
//! cannot mistake the encoded PN for any other PN ≤ `largest_acked`.

#![allow(dead_code)]

use alloc::vec::Vec;
use core::ops::RangeInclusive;

/// The three QUIC packet-number spaces. 0-RTT and 1-RTT share `Application`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum PnSpaceId {
    /// Initial keys — the very first handshake packets.
    Initial = 0,
    /// Handshake keys.
    Handshake = 1,
    /// 0-RTT + 1-RTT.
    Application = 2,
}

/// A sorted-descending set of disjoint inclusive packet-number ranges.
///
/// Stored largest-first because that is the order the QUIC ACK frame
/// transmits ranges (RFC 9000 §19.3).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct AckRanges {
    /// Disjoint inclusive ranges sorted descending by `start()`. The first
    /// element therefore covers the largest acknowledged PN.
    ranges: Vec<RangeInclusive<u64>>,
}

impl AckRanges {
    /// Returns an empty set.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Inserts `pn`, coalescing with any neighboring range.
    pub(crate) fn insert(&mut self, pn: u64) {
        // Find the position where this PN belongs. We scan from the largest
        // range downward; the list is short in practice (a handful of gaps).
        // First, swallow any existing range that already contains `pn`.
        for r in &self.ranges {
            if r.contains(&pn) {
                return;
            }
        }

        // Locate the index whose range starts immediately above `pn` (or
        // the first range whose start ≤ pn — see below).
        // We end up with three insertion behaviors:
        //   1. extend an existing range downward (pn == start - 1)
        //   2. extend an existing range upward (pn == end + 1)
        //   3. coalesce two adjacent ranges via pn
        //   4. plain insert
        // After any extension we may also need to merge with a neighbor.

        let mut insert_idx = self.ranges.len();
        for (i, r) in self.ranges.iter().enumerate() {
            if *r.start() <= pn {
                insert_idx = i;
                break;
            }
        }

        // Try to extend the range *above* (lower index, larger PNs).
        let extended_above = if insert_idx > 0 {
            let above = &mut self.ranges[insert_idx - 1];
            if *above.start() == pn + 1 {
                *above = pn..=*above.end();
                true
            } else {
                false
            }
        } else {
            false
        };

        // Try to extend the range *below* (higher index, smaller PNs).
        let extended_below = if insert_idx < self.ranges.len() {
            let below = &mut self.ranges[insert_idx];
            if *below.end() + 1 == pn {
                *below = *below.start()..=pn;
                true
            } else {
                false
            }
        } else {
            false
        };

        match (extended_above, extended_below) {
            (true, true) => {
                // Coalesce the two ranges that now touch.
                let below = self.ranges.remove(insert_idx);
                let above = &mut self.ranges[insert_idx - 1];
                *above = *below.start()..=*above.end();
            }
            (true, false) | (false, true) => {}
            (false, false) => {
                self.ranges.insert(insert_idx, pn..=pn);
            }
        }
    }

    /// True if `pn` lies in any stored range.
    pub(crate) fn contains(&self, pn: u64) -> bool {
        self.ranges.iter().any(|r| r.contains(&pn))
    }

    /// Largest acknowledged PN, or `None` if empty.
    pub(crate) fn largest(&self) -> Option<u64> {
        self.ranges.first().map(|r| *r.end())
    }

    /// True if no PN has been inserted.
    pub(crate) fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Ranges in descending order (largest range first).
    pub(crate) fn ranges(&self) -> &[RangeInclusive<u64>] {
        &self.ranges
    }

    /// Discards all ranges.
    pub(crate) fn clear(&mut self) {
        self.ranges.clear();
    }
}

/// Per-PN-space transmit/receive state.
#[derive(Debug, Default)]
pub(crate) struct PnSpace {
    /// Next PN to assign to an outbound packet.
    pub(crate) next_tx: u64,
    /// Largest received PN, or `None` if no packet has been received.
    pub(crate) largest_rx: Option<u64>,
    /// Largest of our own PNs ever acked by the peer.
    pub(crate) largest_acked_tx: Option<u64>,
    /// Received PNs awaiting an outbound ACK frame.
    pub(crate) pending_ack: AckRanges,
    /// Whether at least one ack-eliciting packet is awaiting acknowledgement.
    pub(crate) ack_eliciting_pending: bool,
}

/// Decodes a truncated packet number per RFC 9000 §17.1 (reference
/// algorithm in Appendix A.3).
///
/// * `largest_pn` — the largest PN already processed in this space; the
///   decoder picks the candidate closest to `largest_pn + 1`.
/// * `truncated_pn` — the encoded PN read from the packet.
/// * `pn_nbits` — the number of *bits* used to encode it on the wire
///   (8, 16, 24, or 32).
pub(crate) fn decode_packet_number(largest_pn: u64, truncated_pn: u64, pn_nbits: u32) -> u64 {
    debug_assert!(pn_nbits == 8 || pn_nbits == 16 || pn_nbits == 24 || pn_nbits == 32);
    let expected_pn = largest_pn.wrapping_add(1);
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win >> 1;
    let pn_mask = pn_win - 1;

    // candidate_pn = (expected_pn & ~pn_mask) | truncated_pn
    let candidate_pn = (expected_pn & !pn_mask) | truncated_pn;

    if candidate_pn.wrapping_add(pn_hwin) <= expected_pn && candidate_pn < (1u64 << 62) - pn_win {
        candidate_pn.wrapping_add(pn_win)
    } else if candidate_pn > expected_pn.wrapping_add(pn_hwin) && candidate_pn >= pn_win {
        candidate_pn.wrapping_sub(pn_win)
    } else {
        candidate_pn
    }
}

/// Picks the on-wire packet-number encoding length in *bits* per the
/// algorithm in RFC 9000 §17.1.
///
/// The length must be large enough that the receiver — applying the
/// matching decode algorithm with the same `largest_acked` — uniquely
/// reconstructs `pn`. Specifically, twice the gap between `pn` and
/// `largest_acked` must fit in `pn_nbits` (so that the decoder's window
/// rule is unambiguous).
pub(crate) fn encode_packet_number_length(pn: u64, largest_acked: Option<u64>) -> u32 {
    // Per §17.1: "The sender MUST use a packet number size able to represent
    // more than twice as large a range as the difference between the largest
    // acknowledged packet number and the packet number being sent."
    //
    // Equivalently: if `gap = pn - largest_acked` (or `pn + 1` if no PN has
    // been acked, since the implicit baseline is "−1"), pick the smallest
    // `nbits ∈ {8,16,24,32}` such that `2 * gap` fits in `nbits` bits.
    let gap = match largest_acked {
        Some(la) => pn.saturating_sub(la),
        None => pn.saturating_add(1),
    };
    // Number of bits needed to represent `gap`, then +1 to satisfy the
    // "more than twice" requirement. `gap = 0` would need 0 bits, but a PN
    // must always be at least 8 bits on the wire — clamp.
    let needed_bits = if gap == 0 {
        1
    } else {
        64 - gap.leading_zeros()
    } + 1;
    if needed_bits <= 8 {
        8
    } else if needed_bits <= 16 {
        16
    } else if needed_bits <= 24 {
        24
    } else {
        32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_a_decode_examples() {
        // RFC 9000 Appendix A.3:
        //   largest_pn   = 0xa82f30ea
        //   truncated_pn = 0x9b32
        //   pn_nbits     = 16
        //   expected     = 0xa82f9b32
        let pn = decode_packet_number(0xa82f30ea, 0x9b32, 16);
        assert_eq!(pn, 0xa82f9b32);
    }

    #[test]
    fn decode_around_wrap() {
        // Truncated PN just above the window: result should NOT wrap around
        // when the candidate is below largest by more than pn_hwin.
        let pn = decode_packet_number(0x100, 0x00, 8);
        // expected_pn = 0x101, window = 256, candidate = 0x100, hwin = 128.
        // candidate + hwin = 0x180 <= 0x101? No (0x180 > 0x101), so
        // candidate stays at 0x100.
        assert_eq!(pn, 0x100);
    }

    #[test]
    fn encode_length_grows_with_gap() {
        // Small gap → 1-byte (8-bit) PN.
        let nbits_small = encode_packet_number_length(10, Some(5));
        assert_eq!(nbits_small, 8);

        // Large gap → wider PN.
        let nbits_mid = encode_packet_number_length(1 << 20, Some(0));
        assert!(nbits_mid >= 24);

        // Very large gap → maximum 32-bit PN.
        let nbits_max = encode_packet_number_length(1 << 60, Some(0));
        assert_eq!(nbits_max, 32);

        // No prior ack with a high PN behaves like a huge gap.
        let nbits_no_ack = encode_packet_number_length(1 << 40, None);
        assert_eq!(nbits_no_ack, 32);
    }

    #[test]
    fn ackranges_insert_coalesces() {
        let mut r = AckRanges::new();
        r.insert(3);
        r.insert(5);
        r.insert(4); // coalesces 3..=3 + 5..=5 via the bridge.
        assert_eq!(r.ranges(), &[3..=5]);

        let mut r = AckRanges::new();
        r.insert(1);
        r.insert(3);
        // 3..=3 should come first (largest), then 1..=1.
        assert_eq!(r.ranges(), &[3..=3, 1..=1]);
    }

    #[test]
    fn ackranges_descending_order() {
        let mut r = AckRanges::new();
        for &pn in &[10u64, 1, 5, 4, 11] {
            r.insert(pn);
        }
        assert_eq!(r.ranges(), &[10..=11, 4..=5, 1..=1]);
    }

    #[test]
    fn ackranges_largest_and_contains() {
        let mut r = AckRanges::new();
        assert!(r.is_empty());
        assert_eq!(r.largest(), None);
        r.insert(7);
        r.insert(2);
        r.insert(3);
        assert_eq!(r.largest(), Some(7));
        assert!(r.contains(2));
        assert!(r.contains(3));
        assert!(r.contains(7));
        assert!(!r.contains(4));
        r.clear();
        assert!(r.is_empty());
    }

    #[test]
    fn ackranges_idempotent_duplicate() {
        let mut r = AckRanges::new();
        r.insert(5);
        r.insert(5);
        assert_eq!(r.ranges(), &[5..=5]);
    }
}
