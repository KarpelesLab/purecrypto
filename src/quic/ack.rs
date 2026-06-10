//! RFC 9000 §19.3 — ACK frame builder and parser.
//!
//! Builds the ACK-frame payload (with or without the leading 0x02 type
//! byte) from a set of received PN ranges, encodes `ack_delay` per the
//! configured `ack_delay_exponent`, and provides a matching decoder.
//!
//! RFC 9000 §13.2.5 — `ack_delay_exponent` is fixed at 3 for the
//! Initial and Handshake spaces regardless of the negotiated transport
//! parameter. Caller is responsible for selecting the right exponent
//! per space.
//!
//! Wire format (RFC 9000 §19.3):
//! ```text
//!   type (1 byte)              -- 0x02 or 0x03 (with ECN counts)
//!   largest_acknowledged       -- varint
//!   ack_delay                  -- varint, in `exponent`-scaled µs units
//!   ack_range_count            -- varint, # of (gap, range_length) pairs
//!                                 AFTER the first range
//!   first_ack_range            -- varint, `largest_acked − smallest_in_first_range`
//!   { gap, ack_range_length }+ -- both varints, BOTH "value − 1" encoded
//! ```
//!
//! "Value − 1" encoding is subtle: the on-wire `gap` integer represents
//! `(real_gap_in_packets − 1)`, and `ack_range_length` represents
//! `(real_range_length_in_packets − 1)`. See [`build_ack_payload`] for
//! the exact arithmetic.

#![allow(dead_code)]

use alloc::vec::Vec;
use core::ops::RangeInclusive;
use core::time::Duration;

use crate::quic::pn::AckRanges;
use crate::quic::varint;
use crate::tls::Error;

/// Builds the ACK-frame *payload* (no leading 0x02 type byte). See the
/// module docstring for the field semantics.
///
/// `ranges` is the (descending-sorted, disjoint, inclusive) set of PN
/// ranges to acknowledge. `largest_arrival` is the local time at which
/// the largest-acked PN was received; `now` is the current time;
/// `ack_delay_exponent` is the scaling factor (3 for Initial+Handshake
/// per RFC 9000 §13.2.5).
///
/// Returns an empty `Vec` if `ranges` is empty (caller must check).
pub(crate) fn build_ack_payload(
    ranges: &AckRanges,
    largest_arrival: Duration,
    now: Duration,
    ack_delay_exponent: u8,
) -> Vec<u8> {
    let stored = ranges.ranges();
    let mut out = Vec::new();
    if stored.is_empty() {
        return out;
    }
    let largest = *stored[0].end();
    let first_range = largest - *stored[0].start(); // already "value − 1" semantics: count of PNs below largest in first range

    // ack_delay (RFC 9000 §13.2.3): microseconds from `largest_arrival`
    // to `now`, divided by `2^ack_delay_exponent`.
    let delta_us = now.saturating_sub(largest_arrival).as_micros() as u64;
    let scaled = delta_us >> (ack_delay_exponent as u32).min(62);

    varint::encode(largest, &mut out);
    varint::encode(scaled, &mut out);

    // Build the trailing (gap, range_length) pairs from the
    // descending-sorted ranges. Both fields are encoded as the value
    // minus one.
    let mut trailing = Vec::new();
    let mut count = 0u64;
    for i in 1..stored.len() {
        let prev_smallest = *stored[i - 1].start();
        let cur_largest = *stored[i].end();
        let cur_smallest = *stored[i].start();
        // Real gap (RFC 9000 §19.3.1): number of unacked PNs between
        // prev_smallest and cur_largest. = prev_smallest − cur_largest − 1.
        // On-wire: real_gap − 1 = prev_smallest − cur_largest − 2.
        let gap_wire = prev_smallest
            .checked_sub(cur_largest)
            .and_then(|v| v.checked_sub(2));
        let gap_wire = match gap_wire {
            Some(v) => v,
            None => continue, // malformed input; skip this range
        };
        // Real range length (RFC 9000 §19.3.1): packet count in the
        // range = cur_largest − cur_smallest + 1. On-wire: −1.
        let len_wire = cur_largest - cur_smallest;
        varint::encode(gap_wire, &mut trailing);
        varint::encode(len_wire, &mut trailing);
        count += 1;
    }
    varint::encode(count, &mut out);
    varint::encode(first_range, &mut out);
    out.extend_from_slice(&trailing);
    out
}

/// Builds a complete ACK frame: emits 0x02 (no ECN) followed by the
/// payload from [`build_ack_payload`].
pub(crate) fn build_ack_frame(
    ranges: &AckRanges,
    largest_arrival: Duration,
    now: Duration,
    ack_delay_exponent: u8,
) -> Vec<u8> {
    let mut out = Vec::new();
    if ranges.is_empty() {
        return out;
    }
    out.push(0x02);
    let payload = build_ack_payload(ranges, largest_arrival, now, ack_delay_exponent);
    out.extend_from_slice(&payload);
    out
}

/// Decodes an ACK-frame *body* (the bytes after the 0x02/0x03 type byte
/// — caller has already consumed and identified it). Returns
/// `(ranges, ack_delay_raw)` where `ack_delay_raw` is the
/// already-decoded but NOT-yet-scaled microseconds value (caller
/// applies `2^exponent` and the §13.2.5 Initial/Handshake rule).
pub(crate) fn parse_ack_payload(body: &[u8]) -> Result<(Vec<RangeInclusive<u64>>, u64), Error> {
    let mut p = 0usize;
    let (largest, n) = varint::decode(&body[p..])?;
    p += n;
    let (ack_delay_raw, n) = varint::decode(&body[p..])?;
    p += n;
    let (range_count, n) = varint::decode(&body[p..])?;
    p += n;
    let (first_range, n) = varint::decode(&body[p..])?;
    p += n;
    if first_range > largest {
        return Err(Error::Decode);
    }
    // `range_count` is attacker-controlled (a varint can claim up to
    // 2^62-1 ranges) — never preallocate from it directly. Every
    // (gap, range_length) pair costs at least 2 bytes on the wire, so
    // `body.len() / 2` upper-bounds the count of ranges that can
    // actually decode; a bogus count fails varint::decode below long
    // before memory becomes a concern.
    let capacity_hint = core::cmp::min(range_count as usize, body.len() / 2);
    let mut ranges: Vec<RangeInclusive<u64>> = Vec::with_capacity(1 + capacity_hint);
    let mut smallest_in_block = largest - first_range;
    ranges.push(smallest_in_block..=largest);
    for _ in 0..range_count {
        let (gap_wire, n) = varint::decode(&body[p..])?;
        p += n;
        let (len_wire, n) = varint::decode(&body[p..])?;
        p += n;
        // Real gap = gap_wire + 1. Next range's `cur_largest` =
        // smallest_in_block − real_gap − 1 = smallest_in_block −
        // gap_wire − 2.
        let sub = gap_wire.checked_add(2).ok_or(Error::Decode)?;
        if smallest_in_block < sub {
            return Err(Error::Decode);
        }
        let cur_largest = smallest_in_block - sub;
        // Real length = len_wire + 1. cur_smallest = cur_largest − len_wire.
        if len_wire > cur_largest {
            return Err(Error::Decode);
        }
        let cur_smallest = cur_largest - len_wire;
        ranges.push(cur_smallest..=cur_largest);
        smallest_in_block = cur_smallest;
    }
    Ok((ranges, ack_delay_raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges_from(pns: &[u64]) -> AckRanges {
        let mut r = AckRanges::new();
        for &p in pns {
            r.insert(p);
        }
        r
    }

    /// Boundary cases from the master plan's risk-surface section:
    /// {one PN}, {two PNs}, {two single disjoint PNs}, {two pairs of two},
    /// {one PN at 0}. For each: build → parse → assert exact ranges.
    #[test]
    fn ack_frame_roundtrip_boundary_cases() {
        let cases: &[&[u64]] = &[
            &[5],          // one PN
            &[5, 6],       // two PNs in a row
            &[5, 9],       // two single disjoint PNs
            &[1, 2, 5, 6], // two pairs of two
            &[0],          // one PN at 0
            &[0, 1, 2, 5, 6, 10, 20],
        ];
        for pns in cases {
            let r = ranges_from(pns);
            let payload = build_ack_payload(&r, Duration::ZERO, Duration::ZERO, 3);
            let (decoded, ack_delay) = parse_ack_payload(&payload).expect("parse");
            assert_eq!(ack_delay, 0, "ack_delay zero for now==arrival");
            // Build expected ranges in descending order. Use the same
            // descending-disjoint representation `AckRanges` produces.
            let stored = r.ranges();
            assert_eq!(decoded.len(), stored.len(), "case {pns:?}: range count");
            for (got, want) in decoded.iter().zip(stored.iter()) {
                assert_eq!(got, want, "case {pns:?}");
            }
        }
    }

    /// Hand-checked wire bytes for each master-plan boundary case
    /// (catches off-by-one in the value-minus-one encoding).
    ///
    /// Layout of each payload (no leading 0x02 type byte):
    ///   largest_ack | ack_delay | range_count | first_range | (gap, len)*
    /// Each field is a varint; for the small values below every varint
    /// is one byte.
    #[test]
    fn ack_frame_boundary_wire_bytes() {
        // {one PN = 5}:
        //   largest=5 ack_delay=0 range_count=0 first_range=0
        //   → 05 00 00 00
        let p = build_ack_payload(&ranges_from(&[5]), Duration::ZERO, Duration::ZERO, 3);
        assert_eq!(p, alloc::vec![0x05, 0x00, 0x00, 0x00], "{{one PN=5}}");

        // {two PNs 5,6}:
        //   largest=6 ack_delay=0 range_count=0 first_range=1
        //   → 06 00 00 01
        let p = build_ack_payload(&ranges_from(&[5, 6]), Duration::ZERO, Duration::ZERO, 3);
        assert_eq!(p, alloc::vec![0x06, 0x00, 0x00, 0x01], "{{two PNs}}");

        // {two single disjoint PNs 5, 9}:
        //   ranges descending: 9..=9 then 5..=5
        //   largest=9 ack_delay=0 range_count=1 first_range=0
        //   gap = prev_smallest(9) - cur_largest(5) - 2 = 2
        //   len = 5 - 5 = 0
        //   → 09 00 01 00 02 00
        let p = build_ack_payload(&ranges_from(&[5, 9]), Duration::ZERO, Duration::ZERO, 3);
        assert_eq!(
            p,
            alloc::vec![0x09, 0x00, 0x01, 0x00, 0x02, 0x00],
            "{{two single disjoint PNs}}"
        );

        // {two pairs of two: 1,2 and 5,6}:
        //   ranges descending: 5..=6 then 1..=2
        //   largest=6 ack_delay=0 range_count=1 first_range=1
        //   gap = prev_smallest(5) - cur_largest(2) - 2 = 1
        //   len = 2 - 1 = 1
        //   → 06 00 01 01 01 01
        let p = build_ack_payload(
            &ranges_from(&[1, 2, 5, 6]),
            Duration::ZERO,
            Duration::ZERO,
            3,
        );
        assert_eq!(
            p,
            alloc::vec![0x06, 0x00, 0x01, 0x01, 0x01, 0x01],
            "{{two pairs of two}}"
        );

        // {one PN at 0}:
        //   largest=0 ack_delay=0 range_count=0 first_range=0
        //   → 00 00 00 00
        let p = build_ack_payload(&ranges_from(&[0]), Duration::ZERO, Duration::ZERO, 3);
        assert_eq!(p, alloc::vec![0x00, 0x00, 0x00, 0x00], "{{one PN at 0}}");
    }

    #[test]
    fn full_frame_starts_with_0x02() {
        let r = ranges_from(&[5]);
        let frame = build_ack_frame(&r, Duration::ZERO, Duration::ZERO, 3);
        assert!(!frame.is_empty());
        assert_eq!(frame[0], 0x02);
    }

    #[test]
    fn ack_delay_scales_by_exponent() {
        let r = ranges_from(&[5]);
        let now = Duration::from_micros(800);
        let arrival = Duration::from_micros(0);
        // Exponent 3 ⇒ scale = 1<<3 = 8. raw_us = 800. on-wire = 100.
        let payload = build_ack_payload(&r, arrival, now, 3);
        let (_, ack_delay) = parse_ack_payload(&payload).expect("parse");
        assert_eq!(ack_delay, 100);
        // Same delta, exponent 10 ⇒ scale = 1024. on-wire = 0.
        let payload = build_ack_payload(&r, arrival, now, 10);
        let (_, ack_delay) = parse_ack_payload(&payload).expect("parse");
        assert_eq!(ack_delay, 0);
    }

    #[test]
    fn empty_ranges_emits_empty() {
        let r = AckRanges::new();
        assert!(build_ack_payload(&r, Duration::ZERO, Duration::ZERO, 3).is_empty());
        assert!(build_ack_frame(&r, Duration::ZERO, Duration::ZERO, 3).is_empty());
    }

    #[test]
    fn two_pairs_of_two_value_minus_one_encoding() {
        // Sanity check that the on-wire gap field is encoded as
        // (real_gap − 1), so the master-plan boundary case "two pairs
        // of two" produces the right gap. PNs: {1, 2} and {5, 6}.
        // Descending ranges: 5..=6 then 1..=2. Real gap between
        // smallest of upper range (=5) and largest of lower range (=2)
        // is 2 unacked PNs (3 and 4). On-wire gap = 2 − 1 = 1.
        let r = ranges_from(&[1, 2, 5, 6]);
        let payload = build_ack_payload(&r, Duration::ZERO, Duration::ZERO, 3);
        // Decode it via varint to spot-check the gap value.
        let mut p = 0;
        let (largest, n) = varint::decode(&payload[p..]).unwrap();
        p += n;
        assert_eq!(largest, 6);
        let (_ack_delay, n) = varint::decode(&payload[p..]).unwrap();
        p += n;
        let (range_count, n) = varint::decode(&payload[p..]).unwrap();
        p += n;
        assert_eq!(range_count, 1);
        let (first_range, n) = varint::decode(&payload[p..]).unwrap();
        p += n;
        // First range covers 5..=6, so first_range = 6 − 5 = 1.
        assert_eq!(first_range, 1);
        // Trailing pair:
        let (gap_wire, n) = varint::decode(&payload[p..]).unwrap();
        p += n;
        assert_eq!(gap_wire, 1, "gap_wire = real_gap(2) − 1 = 1");
        let (len_wire, _) = varint::decode(&payload[p..]).unwrap();
        // Second range covers 1..=2, len_wire = 2 − 1 = 1.
        assert_eq!(len_wire, 1, "len_wire = (real_len=2) − 1 = 1");
    }

    /// Test 11 — RFC 9000 §13.2.5: even if the peer's negotiated
    /// `ack_delay_exponent` is e.g. 10, ACKs emitted in the Initial /
    /// Handshake spaces must use exponent 3 on both sides. We
    /// simulate: build the ACK with exponent 3 (as a sender of an
    /// Initial-space ACK would), then decode with exponent 3 on the
    /// peer side. The resulting time delta matches the original.
    #[test]
    fn ack_delay_exponent_3_for_initial_handshake() {
        let r = ranges_from(&[5]);
        let arrival = Duration::from_micros(0);
        // ack_delay = 128 µs → with exponent 3, scaled = 16. The peer
        // (also using exponent 3 per §13.2.5) reconstructs 16 × 8 =
        // 128 µs.
        let now = Duration::from_micros(128);
        let payload = build_ack_payload(&r, arrival, now, 3);
        let (_ranges, ack_delay_raw) = parse_ack_payload(&payload).expect("parse");
        let reconstructed = Duration::from_micros(ack_delay_raw << 3);
        assert_eq!(reconstructed, now - arrival);
    }

    #[test]
    fn pn_at_zero_roundtrips() {
        let r = ranges_from(&[0]);
        let payload = build_ack_payload(&r, Duration::ZERO, Duration::ZERO, 3);
        let (decoded, _) = parse_ack_payload(&payload).expect("parse");
        assert_eq!(decoded, alloc::vec![0u64..=0u64]);
    }
}
