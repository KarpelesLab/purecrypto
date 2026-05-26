//! DTLS 1.2 retransmission (RFC 6347 §4.2.4).
//!
//! DTLS handshakes are organized into "flights" — sequences of handshake
//! messages a peer emits in one go (e.g. the server's
//! `ServerHello..ServerHelloDone` is one flight; the client's
//! `Certificate..Finished` is another). Because the underlying transport
//! is unreliable, each side runs a retransmit timer: if the *next* expected
//! flight from the peer doesn't arrive before the timer fires, the local
//! side puts the *previous* flight back on the wire.
//!
//! RFC 6347 §4.2.4.1 recommends an initial timeout of "at least one second"
//! and bounds the per-attempt timeout to "at most 60 seconds", with
//! exponential backoff (doubling) in between. We implement exactly that,
//! plus a configurable cap on total retransmits so a peer that never
//! answers eventually fails the connection instead of looping forever.
//!
//! Sans-I/O shape: this module knows nothing about sockets, clocks, or
//! the handshake state machine. The caller drives it with monotonic time
//! values (any `Duration` measured against a fixed epoch the caller
//! chose) and reads back what to do:
//!
//! ```text
//! // After putting flight datagrams on the wire:
//! retransmit.set_flight(flight, now);
//!
//! // In the connection's poll loop:
//! if let Some(deadline) = retransmit.next_timeout() {
//!     if clock.now() >= deadline {
//!         match retransmit.on_timeout(clock.now()) {
//!             Action::Retransmit => transport.send_all(retransmit.flight_datagrams()),
//!             Action::GiveUp     => return Err(Error::HandshakeTimeout),
//!             Action::Idle       => {},
//!         }
//!     }
//! }
//!
//! // When the peer's next flight arrives:
//! retransmit.on_peer_response();
//! ```
//!
//! Using a generic `Duration`-since-epoch instant keeps this `no_std`-clean
//! (`std::time::Instant` is not available without `std`) while still
//! letting the std-using caller plug in `Instant::elapsed_since(epoch)`.
//!
//! The DTLS 1.2 state machine that consumes this lands in commit 10, so the
//! items below are `#[allow(dead_code)]` for now.

#![allow(dead_code)]

use alloc::vec::Vec;
use core::time::Duration;

/// Initial retransmit timeout. RFC 6347 §4.2.4.1: "The recommended initial
/// value is one second."
const INITIAL_TIMEOUT: Duration = Duration::from_millis(1000);
/// Cap on per-attempt timeout. RFC 6347 §4.2.4.1: "The timer values
/// SHOULD be doubled after each retransmission, with a maximum value of
/// 60 seconds."
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum number of retransmits before the caller is told to give up.
/// RFC 6347 does not pin a specific value; 6 attempts (covering 1+2+4+8+16+32 = 63s
/// of doubling plus a 60s-capped tail) matches the de-facto behavior of
/// established stacks and bounds the worst-case stall.
const MAX_RETRANSMITS: u32 = 6;

/// Monotonic time abstraction. Caller picks an epoch and passes the
/// `Duration` since that epoch to every method that takes `now`.
///
/// Aliased rather than newtyped so `Duration` arithmetic (`+`, `>=`) is
/// available without extra glue.
type Instant = Duration;

/// One flight worth of datagrams to retransmit. Each entry is one full
/// DTLS record (record header + protected fragment) ready to put on the
/// wire — the reliability layer does not look inside.
#[derive(Default)]
pub(crate) struct Flight {
    pub(crate) datagrams: Vec<Vec<u8>>,
}

impl Flight {
    /// Creates an empty flight.
    pub(crate) fn new() -> Self {
        Self {
            datagrams: Vec::new(),
        }
    }

    /// Appends a single datagram to this flight.
    pub(crate) fn push(&mut self, datagram: Vec<u8>) {
        self.datagrams.push(datagram);
    }

    /// Returns `true` if the flight contains no datagrams.
    pub(crate) fn is_empty(&self) -> bool {
        self.datagrams.is_empty()
    }

    /// Drops all datagrams.
    pub(crate) fn clear(&mut self) {
        self.datagrams.clear();
    }
}

/// What the caller should do after `on_timeout`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Timer hasn't actually fired yet (caller polled too early) or there
    /// is no pending flight. Do nothing.
    Idle,
    /// Resend every datagram returned by `flight_datagrams()`. The next
    /// deadline has already been scheduled.
    Retransmit,
    /// The retransmit cap was reached. The caller should fail the
    /// connection with a handshake-timeout error.
    GiveUp,
}

/// Retransmit state machine for one DTLS endpoint.
///
/// Holds the most recently transmitted flight plus the timer that
/// governs when (and whether) to put it back on the wire.
pub(crate) struct Retransmit {
    /// Datagrams of the flight last put on the wire. Empty until
    /// `set_flight` is called the first time.
    last_flight: Flight,
    /// Absolute time at which the next retransmit should fire, or `None`
    /// if there is no pending flight (e.g. peer already responded).
    deadline: Option<Instant>,
    /// Per-attempt timeout. Starts at `INITIAL_TIMEOUT`, doubles on each
    /// `on_timeout` that returns `Retransmit`, capped at `MAX_TIMEOUT`.
    timeout: Duration,
    /// Number of retransmits performed for the current flight.
    attempts: u32,
}

impl Retransmit {
    /// Creates a fresh state machine with no pending flight and no timer.
    pub(crate) fn new() -> Self {
        Self {
            last_flight: Flight::new(),
            deadline: None,
            timeout: INITIAL_TIMEOUT,
            attempts: 0,
        }
    }

    /// Records that `flight` has just been sent at `now`. Resets the
    /// attempt counter and per-attempt timeout, and arms the timer for
    /// `now + INITIAL_TIMEOUT`.
    pub(crate) fn set_flight(&mut self, flight: Flight, now: Instant) {
        self.last_flight = flight;
        self.timeout = INITIAL_TIMEOUT;
        self.attempts = 0;
        self.deadline = Some(now + INITIAL_TIMEOUT);
    }

    /// Returns the absolute time the timer will next fire, or `None` if
    /// no flight is pending (peer already responded, or `set_flight` was
    /// never called).
    pub(crate) fn next_timeout(&self) -> Option<Instant> {
        self.deadline
    }

    /// Called by the caller when its monotonic clock reaches the value
    /// returned by `next_timeout()`. The returned `Action` tells the
    /// caller what to do; see `Action`.
    pub(crate) fn on_timeout(&mut self, now: Instant) -> Action {
        let Some(deadline) = self.deadline else {
            // No flight pending — nothing to retransmit.
            return Action::Idle;
        };
        if now < deadline {
            // Caller polled before the timer actually fired.
            return Action::Idle;
        }
        if self.attempts >= MAX_RETRANSMITS {
            // Out of attempts; tell the caller to fail the connection.
            self.deadline = None;
            return Action::GiveUp;
        }
        // Double the per-attempt timeout (saturating at MAX_TIMEOUT) and
        // arm the next deadline from `now`, not from the missed one — a
        // late wake-up shouldn't compress the schedule.
        self.attempts += 1;
        self.timeout = (self.timeout * 2).min(MAX_TIMEOUT);
        self.deadline = Some(now + self.timeout);
        Action::Retransmit
    }

    /// Called when the *next* expected flight has arrived from the peer.
    /// Cancels the timer, drops the last flight, and resets the attempt
    /// counter so the next `set_flight` starts from `INITIAL_TIMEOUT`.
    pub(crate) fn on_peer_response(&mut self) {
        self.last_flight.clear();
        self.deadline = None;
        self.timeout = INITIAL_TIMEOUT;
        self.attempts = 0;
    }

    /// Returns the datagrams of the last-sent flight. The caller resends
    /// every entry on a `Retransmit` action.
    pub(crate) fn flight_datagrams(&self) -> &[Vec<u8>] {
        &self.last_flight.datagrams
    }
}

impl Default for Retransmit {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn flight_of(datagrams: &[&[u8]]) -> Flight {
        let mut f = Flight::new();
        for d in datagrams {
            f.push(d.to_vec());
        }
        f
    }

    #[test]
    fn initial_deadline_is_one_second_after_set() {
        let mut r = Retransmit::new();
        r.set_flight(flight_of(&[b"hello"]), Duration::from_secs(0));
        assert_eq!(r.next_timeout(), Some(Duration::from_secs(1)));
    }

    #[test]
    fn timeout_doubles_each_attempt() {
        let mut r = Retransmit::new();
        // t=0: send flight, deadline at t=1s.
        r.set_flight(flight_of(&[b"a"]), Duration::from_secs(0));
        assert_eq!(r.next_timeout(), Some(Duration::from_secs(1)));

        // t=1s: timer fires, retransmit, next deadline at 1s+2s=3s.
        assert_eq!(r.on_timeout(Duration::from_secs(1)), Action::Retransmit);
        assert_eq!(r.next_timeout(), Some(Duration::from_secs(3)));

        // t=3s: timer fires, retransmit, next deadline at 3s+4s=7s.
        assert_eq!(r.on_timeout(Duration::from_secs(3)), Action::Retransmit);
        assert_eq!(r.next_timeout(), Some(Duration::from_secs(7)));
    }

    #[test]
    fn caps_at_60_seconds() {
        let mut r = Retransmit::new();
        // Force enough doublings to exceed the 60s cap.
        // Start timeout = 1s; doublings: 2,4,8,16,32,64→capped to 60.
        r.set_flight(flight_of(&[b"x"]), Duration::from_secs(0));
        let mut now = Duration::from_secs(0);
        // Walk attempts up to (but not past) MAX_RETRANSMITS to observe
        // the timeout value before any GiveUp.
        for _ in 0..MAX_RETRANSMITS {
            now = r.next_timeout().expect("deadline armed");
            assert_eq!(r.on_timeout(now), Action::Retransmit);
        }
        // After 6 retransmits starting from 1s and doubling, the
        // per-attempt timeout would be 64s but must be clamped to 60s.
        // Confirm the final deadline gap equals MAX_TIMEOUT.
        let final_deadline = r.next_timeout().expect("still armed");
        assert_eq!(final_deadline - now, MAX_TIMEOUT);
    }

    #[test]
    fn gives_up_after_max_attempts() {
        let mut r = Retransmit::new();
        r.set_flight(flight_of(&[b"x"]), Duration::from_secs(0));
        // Exhaust MAX_RETRANSMITS retransmits.
        for _ in 0..MAX_RETRANSMITS {
            let now = r.next_timeout().expect("deadline armed");
            assert_eq!(r.on_timeout(now), Action::Retransmit);
        }
        // One more timeout: out of attempts, expect GiveUp and the
        // deadline cleared so we don't fire again.
        let now = r.next_timeout().expect("deadline still armed");
        assert_eq!(r.on_timeout(now), Action::GiveUp);
        assert_eq!(r.next_timeout(), None);
    }

    #[test]
    fn on_peer_response_clears_state() {
        let mut r = Retransmit::new();
        r.set_flight(flight_of(&[b"x", b"y"]), Duration::from_secs(0));
        assert!(r.next_timeout().is_some());
        r.on_peer_response();
        assert_eq!(r.next_timeout(), None);
        assert!(r.flight_datagrams().is_empty());
    }

    #[test]
    fn idle_when_called_early() {
        let mut r = Retransmit::new();
        r.set_flight(flight_of(&[b"x"]), Duration::from_secs(0));
        let before = r.next_timeout();
        // Half a second in — the 1s timer hasn't fired yet.
        assert_eq!(r.on_timeout(Duration::from_millis(500)), Action::Idle);
        // Deadline is unchanged.
        assert_eq!(r.next_timeout(), before);
    }

    #[test]
    fn idle_with_no_flight_pending() {
        let mut r = Retransmit::new();
        // No set_flight call: nothing to do.
        assert_eq!(r.on_timeout(Duration::from_secs(10)), Action::Idle);
        assert_eq!(r.next_timeout(), None);
    }

    #[test]
    fn simulate_dropped_first_flight() {
        // Sender pushes a 2-datagram flight; peer drops it; timer fires
        // at t=1s; expect Retransmit and the original two datagrams.
        let dg1: Vec<u8> = vec![0x16, 0xfe, 0xfd, 0xaa];
        let dg2: Vec<u8> = vec![0x16, 0xfe, 0xfd, 0xbb];
        let mut flight = Flight::new();
        flight.push(dg1.clone());
        flight.push(dg2.clone());

        let mut r = Retransmit::new();
        r.set_flight(flight, Duration::from_secs(0));
        assert_eq!(r.on_timeout(Duration::from_secs(1)), Action::Retransmit);
        let out = r.flight_datagrams();
        assert_eq!(out.len(), 2);
        assert_eq!(&out[0], &dg1);
        assert_eq!(&out[1], &dg2);
    }

    #[test]
    fn set_flight_resets_attempts_and_timeout() {
        let mut r = Retransmit::new();
        r.set_flight(flight_of(&[b"x"]), Duration::from_secs(0));
        // Drive one retransmit so timeout doubles to 2s.
        assert_eq!(r.on_timeout(Duration::from_secs(1)), Action::Retransmit);
        // A fresh flight should re-arm at INITIAL_TIMEOUT, not 4s.
        r.set_flight(flight_of(&[b"y"]), Duration::from_secs(10));
        assert_eq!(r.next_timeout(), Some(Duration::from_secs(11)));
    }

    #[test]
    fn flight_helpers() {
        let mut f = Flight::new();
        assert!(f.is_empty());
        f.push(vec![1, 2, 3]);
        assert!(!f.is_empty());
        f.clear();
        assert!(f.is_empty());
    }
}
