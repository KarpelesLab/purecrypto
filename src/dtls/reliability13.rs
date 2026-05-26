//! DTLS 1.3 ACK-driven retransmission state machine (RFC 9147 §7).
//!
//! DTLS 1.2 retransmission ([`super::reliability`]) treats a flight as
//! atomic: if the next expected flight from the peer is not seen before
//! the timer fires, the *entire* previous flight is put back on the wire.
//! That works but wastes bandwidth when only one record was actually lost.
//!
//! DTLS 1.3 (RFC 9147 §7) replaces that model with **selective ACKs**: the
//! peer explicitly tells us which (epoch, sequence_number) pairs it
//! received via an [`super::ack::ACK_CONTENT_TYPE`] record, and we only
//! retransmit the records that have *not* yet been ACKed. The timer still
//! exists — it covers the case where the ACK itself is lost, or the peer
//! has not yet had a chance to send one — but each tick now retransmits
//! the *current in-flight set*, not the whole flight.
//!
//! State held per endpoint:
//!
//! - The in-flight set: every protected DTLS record we have emitted whose
//!   `(epoch, seq)` has not yet appeared in an ACK from the peer.
//! - One retransmit timer covering that set as a whole; cancelled when the
//!   set is empty, re-armed when we transmit a new record into an empty
//!   set.
//! - The current per-attempt timeout and a retransmit-attempts counter
//!   borrowed wholesale from the 1.2 design — same `INITIAL_TIMEOUT`,
//!   `MAX_TIMEOUT`, `MAX_RETRANSMITS` constants and same exponential
//!   backoff. RFC 9147 §5.8.1 and §7.2 explicitly recommend the same
//!   1-second initial / 60-second cap as RFC 6347.
//!
//! Composition with the 1.2 layer: the 1.2 [`super::reliability::Action`]
//! enum (Idle/Retransmit/GiveUp) is reused unchanged so the connection
//! poll loop in `client12` / `server12` and the upcoming `client13` /
//! `server13` can share the same outer dispatch shape — only the inner
//! "what bytes do we put back on the wire" differs (full last flight vs.
//! the current in-flight set).
//!
//! Sans-I/O shape (matches [`super::reliability::Retransmit`]):
//!
//! ```text
//! // After putting a protected record on the wire:
//! r13.on_record_sent(InFlightRecord { record_number, datagram }, now);
//!
//! // When an ACK arrives from the peer:
//! let acks = ack::decode(body)?;
//! r13.on_ack(&acks);
//!
//! // Poll loop:
//! if let Some(deadline) = r13.next_timeout() {
//!     if clock.now() >= deadline {
//!         match r13.on_timeout(clock.now()) {
//!             Action::Retransmit => transport.send_all(r13.in_flight_datagrams()),
//!             Action::GiveUp     => return Err(Error::HandshakeTimeout),
//!             Action::Idle       => {},
//!         }
//!     }
//! }
//! ```
//!
//! Consumed by the DTLS 1.3 client / server state machines in commit 14,
//! so the items here are `#[allow(dead_code)]` until then.

#![allow(dead_code)]

use super::ack::RecordNumber;
use super::reliability::Action;
use alloc::vec::Vec;
use core::time::Duration;

/// Initial retransmit timeout. RFC 9147 §5.8.1: "as in DTLS 1.2, the
/// recommended initial timer value is 1 second".
const INITIAL_TIMEOUT: Duration = Duration::from_millis(1000);
/// Cap on per-attempt timeout. RFC 9147 §5.8.1 inherits the DTLS 1.2
/// recommendation of "at most 60 seconds".
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum number of retransmits before the caller is told to give up.
/// Matches the 1.2 layer's choice so the two state machines behave
/// equivalently when no ACKs are ever produced.
const MAX_RETRANSMITS: u32 = 6;

/// Monotonic time abstraction (caller-chosen epoch).
type Instant = Duration;

/// One DTLS record that has been transmitted but not yet ACKed. The
/// reliability layer keeps both the [`RecordNumber`] (so it can match
/// incoming ACKs) and the original wire bytes (so it can put the record
/// back on the wire on a timeout).
pub(crate) struct InFlightRecord {
    /// (epoch, seq) the receiver will reference in any ACK.
    pub(crate) record_number: RecordNumber,
    /// The exact datagram (or single-record slice of one) that was sent;
    /// resent verbatim on retransmit.
    pub(crate) datagram: Vec<u8>,
}

/// DTLS 1.3 retransmit state machine for one endpoint.
pub(crate) struct Retransmit13 {
    /// Records emitted but not yet acknowledged. Order is preserved so
    /// retransmissions go back on the wire in the same order they were
    /// originally sent (matters for fragment reassembly).
    in_flight: Vec<InFlightRecord>,
    /// Absolute deadline at which `on_timeout` should be invoked, or
    /// `None` if no records are in flight.
    deadline: Option<Instant>,
    /// Per-attempt timeout, doubling on each retransmit up to `MAX_TIMEOUT`.
    timeout: Duration,
    /// Retransmit attempts performed since the in-flight set last went
    /// from empty to non-empty. Resets when the set is fully drained.
    attempts: u32,
}

impl Retransmit13 {
    /// Creates a fresh state machine with no in-flight records and no
    /// pending timer.
    pub(crate) fn new() -> Self {
        Self {
            in_flight: Vec::new(),
            deadline: None,
            timeout: INITIAL_TIMEOUT,
            attempts: 0,
        }
    }

    /// Registers a record we just sent at `now`. Adds it to the in-flight
    /// set; if that set was previously empty, arms the timer at
    /// `now + INITIAL_TIMEOUT` and resets the attempt counter / per-attempt
    /// timeout to their initial values.
    ///
    /// If the timer was already running, neither the deadline nor the
    /// backoff state is touched — sending more records does not extend or
    /// reset the existing retransmit schedule.
    pub(crate) fn on_record_sent(&mut self, rec: InFlightRecord, now: Instant) {
        let was_empty = self.in_flight.is_empty();
        self.in_flight.push(rec);
        if was_empty {
            self.timeout = INITIAL_TIMEOUT;
            self.attempts = 0;
            self.deadline = Some(now + INITIAL_TIMEOUT);
        }
    }

    /// Applies an ACK from the peer: removes every in-flight record whose
    /// `RecordNumber` appears in `acks`. If the in-flight set becomes
    /// empty, cancels the timer and resets backoff state so the next send
    /// starts from `INITIAL_TIMEOUT` again.
    ///
    /// ACK entries that reference records we never sent (or that we
    /// already saw ACKed) are silently ignored — the peer is permitted to
    /// re-ACK and the protocol does not require us to police that.
    pub(crate) fn on_ack(&mut self, acks: &[RecordNumber]) {
        if acks.is_empty() {
            return;
        }
        // O(n*m) is fine here: ACK bodies and in-flight sets are both
        // bounded by the number of records in a single flight (a handful).
        self.in_flight.retain(|r| !acks.contains(&r.record_number));
        if self.in_flight.is_empty() {
            self.deadline = None;
            self.timeout = INITIAL_TIMEOUT;
            self.attempts = 0;
        }
    }

    /// Returns the absolute time at which `on_timeout` should next be
    /// invoked, or `None` if no records are in flight.
    pub(crate) fn next_timeout(&self) -> Option<Instant> {
        self.deadline
    }

    /// Timer-expiry handler. Mirrors [`super::reliability::Retransmit::on_timeout`]:
    ///
    /// - [`Action::Idle`] if no records are in flight, or the caller polled
    ///   before the deadline.
    /// - [`Action::Retransmit`] if the deadline elapsed and attempts remain.
    ///   The caller resends every byte slice in [`Self::in_flight_datagrams`]
    ///   and the next deadline is armed at `now + 2 * previous_timeout`
    ///   (capped at `MAX_TIMEOUT`).
    /// - [`Action::GiveUp`] once `MAX_RETRANSMITS` retransmits have happened
    ///   without the in-flight set being fully drained. The deadline is
    ///   cleared so subsequent polls return `Idle`.
    pub(crate) fn on_timeout(&mut self, now: Instant) -> Action {
        let Some(deadline) = self.deadline else {
            return Action::Idle;
        };
        if self.in_flight.is_empty() {
            // Defensive: deadline should always be `None` when empty, but
            // never gives an early-fire on a stale timer.
            self.deadline = None;
            return Action::Idle;
        }
        if now < deadline {
            return Action::Idle;
        }
        if self.attempts >= MAX_RETRANSMITS {
            self.deadline = None;
            return Action::GiveUp;
        }
        self.attempts += 1;
        self.timeout = (self.timeout * 2).min(MAX_TIMEOUT);
        self.deadline = Some(now + self.timeout);
        Action::Retransmit
    }

    /// Returns the byte slices of every still-in-flight record. The
    /// caller iterates this on every [`Action::Retransmit`] and puts each
    /// slice back on the wire.
    pub(crate) fn in_flight_datagrams(&self) -> impl Iterator<Item = &[u8]> {
        self.in_flight.iter().map(|r| r.datagram.as_slice())
    }

    /// Number of records currently in the in-flight set. Useful for tests
    /// and for emitting metrics.
    pub(crate) fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }
}

impl Default for Retransmit13 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn rec(epoch: u64, seq: u64, datagram: &[u8]) -> InFlightRecord {
        InFlightRecord {
            record_number: RecordNumber { epoch, seq },
            datagram: datagram.to_vec(),
        }
    }

    #[test]
    fn new_is_idle() {
        let r = Retransmit13::new();
        assert!(r.next_timeout().is_none());
        assert_eq!(r.in_flight_len(), 0);
    }

    #[test]
    fn on_record_sent_starts_timer() {
        let mut r = Retransmit13::new();
        assert_eq!(r.next_timeout(), None);
        r.on_record_sent(rec(0, 1, b"hello"), Duration::from_secs(0));
        assert_eq!(r.next_timeout(), Some(Duration::from_secs(1)));
        assert_eq!(r.in_flight_len(), 1);
    }

    #[test]
    fn sending_more_records_does_not_re_arm_timer() {
        let mut r = Retransmit13::new();
        r.on_record_sent(rec(0, 1, b"a"), Duration::from_secs(0));
        let first = r.next_timeout();
        // Second send at a later time should NOT push the deadline back.
        r.on_record_sent(rec(0, 2, b"b"), Duration::from_millis(500));
        assert_eq!(r.next_timeout(), first);
        assert_eq!(r.in_flight_len(), 2);
    }

    #[test]
    fn ack_clears_matching_record_only() {
        let mut r = Retransmit13::new();
        r.on_record_sent(rec(1, 10, b"x"), Duration::from_secs(0));
        r.on_record_sent(rec(1, 11, b"y"), Duration::from_secs(0));
        r.on_record_sent(rec(1, 12, b"z"), Duration::from_secs(0));

        // ACK only the middle one.
        r.on_ack(&[RecordNumber { epoch: 1, seq: 11 }]);
        assert_eq!(r.in_flight_len(), 2);
        // Timer remains armed because two records are still outstanding.
        assert!(r.next_timeout().is_some());

        // Surviving entries are 10 and 12, in original order.
        let remaining: Vec<&[u8]> = r.in_flight_datagrams().collect();
        assert_eq!(remaining, vec![b"x".as_slice(), b"z".as_slice()]);
    }

    #[test]
    fn full_ack_cancels_timer() {
        let mut r = Retransmit13::new();
        r.on_record_sent(rec(0, 1, b"a"), Duration::from_secs(0));
        r.on_record_sent(rec(0, 2, b"b"), Duration::from_secs(0));
        assert!(r.next_timeout().is_some());

        r.on_ack(&[
            RecordNumber { epoch: 0, seq: 1 },
            RecordNumber { epoch: 0, seq: 2 },
        ]);
        assert_eq!(r.in_flight_len(), 0);
        assert_eq!(r.next_timeout(), None);
    }

    #[test]
    fn unknown_ack_is_ignored() {
        let mut r = Retransmit13::new();
        r.on_record_sent(rec(0, 1, b"a"), Duration::from_secs(0));
        let before = r.next_timeout();
        r.on_ack(&[RecordNumber {
            epoch: 999,
            seq: 999,
        }]);
        assert_eq!(r.in_flight_len(), 1);
        assert_eq!(r.next_timeout(), before);
    }

    #[test]
    fn empty_ack_is_no_op() {
        let mut r = Retransmit13::new();
        r.on_record_sent(rec(0, 1, b"a"), Duration::from_secs(0));
        let before = r.next_timeout();
        r.on_ack(&[]);
        assert_eq!(r.in_flight_len(), 1);
        assert_eq!(r.next_timeout(), before);
    }

    #[test]
    fn timeout_triggers_retransmit_of_all_in_flight() {
        let mut r = Retransmit13::new();
        r.on_record_sent(rec(0, 1, b"alpha"), Duration::from_secs(0));
        r.on_record_sent(rec(0, 2, b"beta"), Duration::from_secs(0));

        // Polling before the deadline is Idle.
        assert_eq!(r.on_timeout(Duration::from_millis(500)), Action::Idle);

        // At the deadline, Retransmit fires and the in-flight slice is
        // available for the caller to put back on the wire.
        assert_eq!(r.on_timeout(Duration::from_secs(1)), Action::Retransmit);
        let datagrams: Vec<&[u8]> = r.in_flight_datagrams().collect();
        assert_eq!(datagrams, vec![b"alpha".as_slice(), b"beta".as_slice()]);
        // Next deadline doubled.
        assert_eq!(r.next_timeout(), Some(Duration::from_secs(3)));
    }

    #[test]
    fn backoff_doubles_and_caps_at_max() {
        let mut r = Retransmit13::new();
        r.on_record_sent(rec(0, 1, b"x"), Duration::from_secs(0));

        // Walk through MAX_RETRANSMITS attempts and check the gap between
        // successive deadlines equals the doubled per-attempt timeout,
        // capped at MAX_TIMEOUT. Starting at 1s the sequence is
        // 2, 4, 8, 16, 32, 60 (capped from 64) — exactly 6 doublings.
        let expected_gaps = [
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(8),
            Duration::from_secs(16),
            Duration::from_secs(32),
            MAX_TIMEOUT, // would be 64, clamped to 60
        ];
        assert_eq!(expected_gaps.len() as u32, MAX_RETRANSMITS);
        for expected in expected_gaps {
            let deadline = r.next_timeout().expect("armed");
            assert_eq!(r.on_timeout(deadline), Action::Retransmit);
            let next = r.next_timeout().expect("re-armed");
            assert_eq!(next - deadline, expected);
        }
    }

    #[test]
    fn give_up_after_max_retransmits() {
        let mut r = Retransmit13::new();
        r.on_record_sent(rec(0, 1, b"x"), Duration::from_secs(0));
        for _ in 0..MAX_RETRANSMITS {
            let deadline = r.next_timeout().expect("armed");
            assert_eq!(r.on_timeout(deadline), Action::Retransmit);
        }
        let deadline = r.next_timeout().expect("still armed");
        assert_eq!(r.on_timeout(deadline), Action::GiveUp);
        // Timer cleared so we don't fire again, but in-flight is still
        // populated — the caller will fail the connection regardless.
        assert_eq!(r.next_timeout(), None);
        assert_eq!(r.in_flight_len(), 1);
    }

    #[test]
    fn idle_with_no_in_flight() {
        let mut r = Retransmit13::new();
        assert_eq!(r.on_timeout(Duration::from_secs(10)), Action::Idle);
        assert_eq!(r.next_timeout(), None);
    }

    #[test]
    fn timer_resets_to_initial_after_full_drain() {
        let mut r = Retransmit13::new();
        r.on_record_sent(rec(0, 1, b"x"), Duration::from_secs(0));
        // Drive one timeout so backoff doubles to 2s.
        assert_eq!(r.on_timeout(Duration::from_secs(1)), Action::Retransmit);

        // Full ACK clears in-flight and resets backoff.
        r.on_ack(&[RecordNumber { epoch: 0, seq: 1 }]);
        assert_eq!(r.next_timeout(), None);

        // A brand-new send at t=10s should arm at t=11s, not t=14s.
        r.on_record_sent(rec(0, 2, b"y"), Duration::from_secs(10));
        assert_eq!(r.next_timeout(), Some(Duration::from_secs(11)));
    }

    #[test]
    fn ack_does_not_cancel_until_all_records_drained() {
        let mut r = Retransmit13::new();
        r.on_record_sent(rec(0, 1, b"a"), Duration::from_secs(0));
        r.on_record_sent(rec(0, 2, b"b"), Duration::from_secs(0));
        r.on_record_sent(rec(0, 3, b"c"), Duration::from_secs(0));

        // ACK two of three; timer must remain armed.
        r.on_ack(&[
            RecordNumber { epoch: 0, seq: 1 },
            RecordNumber { epoch: 0, seq: 3 },
        ]);
        assert_eq!(r.in_flight_len(), 1);
        assert!(r.next_timeout().is_some());

        // Final ACK clears it.
        r.on_ack(&[RecordNumber { epoch: 0, seq: 2 }]);
        assert_eq!(r.in_flight_len(), 0);
        assert!(r.next_timeout().is_none());
    }
}
