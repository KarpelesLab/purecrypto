//! Sliding-window anti-replay (RFC 6347 §4.1.2.6, RFC 4303 §3.4.3).
//!
//! DTLS records arrive over a datagram transport that may duplicate,
//! reorder, and lose packets at will. Per-record sequence numbers prevent
//! reassembly confusion, but an attacker (or a buggy middlebox) replaying a
//! record can still pass the cipher check. The sliding-window filter rejects
//! a record if:
//!
//! 1. its sequence number has been seen before (duplicate), or
//! 2. its sequence number is so far behind the highest accepted that it
//!    cannot be tracked in the window (too old).
//!
//! We use a standard 64-entry window: a single `u64` bitmap shadowing the 64
//! most recent sequence numbers. Acceptance updates the window; rejection is
//! silent — the caller drops the datagram and reads the next.
//!
//! Initial state: the window has no "highest yet" — the first record sets
//! `highest` to whatever value arrives. This matches both the RFC 4303
//! convention and how OpenSSL initializes its DTLS anti-replay state.
//!
//! The consumer (DTLS receive path in commits 10 and 14) is added later, so
//! the items below are `#[allow(dead_code)]` for now.

#![allow(dead_code)]

/// Width of the sliding window. RFC 4303 §3.4.3 mandates ≥32; 64 is the
/// canonical choice (one `u64`) and matches OpenSSL.
pub(crate) const WINDOW_BITS: u64 = 64;

/// A 64-entry sliding window anti-replay filter.
///
/// Sequence numbers are taken from the DTLS record header (48 bits) and
/// widened to `u64` here, so the filter is sufficient for all of DTLS 1.2's
/// representable sequence space.
pub(crate) struct AntiReplayWindow {
    /// Highest sequence number accepted so far.
    highest: u64,
    /// 64-bit shadow of seen sequence numbers. Bit `i` corresponds to
    /// `highest - i`; bit 0 is always set (the highest itself).
    bitmap: u64,
    /// `true` until the first record has been accepted. The first record
    /// always wins regardless of value.
    seeded: bool,
}

impl AntiReplayWindow {
    /// Creates a fresh window in the unseeded state.
    pub(crate) fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            seeded: false,
        }
    }

    /// Tests `seq` against the window and, if it should be processed,
    /// updates the window to remember it. Returns `true` to accept, `false`
    /// to silently drop.
    pub(crate) fn accept(&mut self, seq: u64) -> bool {
        if !self.seeded {
            self.highest = seq;
            self.bitmap = 1; // bit 0 = the highest itself.
            self.seeded = true;
            return true;
        }

        if seq > self.highest {
            // New record advances the window. Shift the bitmap left by the
            // delta, then set bit 0.
            let delta = seq - self.highest;
            self.bitmap = if delta >= WINDOW_BITS {
                // Slide past the entire current window.
                1
            } else {
                (self.bitmap << delta) | 1
            };
            self.highest = seq;
            true
        } else {
            // seq <= highest. Either inside the window (maybe seen, maybe
            // not), or older than the window can track.
            let delta = self.highest - seq;
            if delta >= WINDOW_BITS {
                // Too old: outside the window. Silently drop.
                return false;
            }
            let bit = 1u64 << delta;
            if self.bitmap & bit != 0 {
                // Duplicate.
                return false;
            }
            self.bitmap |= bit;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_record_accepted_regardless_of_value() {
        let mut w = AntiReplayWindow::new();
        // The first record sets `highest` — no notion of "old" yet.
        assert!(w.accept(0));

        let mut w = AntiReplayWindow::new();
        assert!(w.accept(1_000_000));

        let mut w = AntiReplayWindow::new();
        assert!(w.accept((1u64 << 48) - 1));
    }

    #[test]
    fn slides_in_within_window() {
        let mut w = AntiReplayWindow::new();
        assert!(w.accept(5));
        // Older but inside the 64-entry window — accept.
        assert!(w.accept(4));
        assert!(w.accept(3));
        assert!(w.accept(0));
    }

    #[test]
    fn rejects_duplicate() {
        let mut w = AntiReplayWindow::new();
        assert!(w.accept(5));
        assert!(!w.accept(5));
        assert!(w.accept(7));
        assert!(!w.accept(7));
        // Earlier slot, no duplicate, OK.
        assert!(w.accept(6));
        // Replay of the in-window record.
        assert!(!w.accept(6));
    }

    #[test]
    fn rejects_too_old() {
        let mut w = AntiReplayWindow::new();
        // Push the window way out, then offer something below the floor.
        assert!(w.accept(100));
        // Window covers (100 - 63) ..= 100 inclusive. seq=37 (delta=63) is
        // the last in-window slot.
        assert!(w.accept(37));
        // seq=36 (delta=64) is just past the window — reject.
        assert!(!w.accept(36));
        // Wildly old: also rejected.
        assert!(!w.accept(20));
    }

    #[test]
    fn accepts_large_forward_jump() {
        let mut w = AntiReplayWindow::new();
        assert!(w.accept(5));
        assert!(w.accept(200));
        // The shift was 195, so the bitmap is now just bit 0. Reaccepting
        // 199 should work (newly visible).
        assert!(w.accept(199));
        // 5 is now far outside the window.
        assert!(!w.accept(5));
    }

    #[test]
    fn window_floor_inclusive() {
        // Bit (WINDOW_BITS - 1) corresponds to seq = highest - 63. Make sure
        // that exact slot is reachable.
        let mut w = AntiReplayWindow::new();
        assert!(w.accept(63));
        // Now window is highest=63, bit 0 set.
        assert!(w.accept(0));
        // Replay of 0:
        assert!(!w.accept(0));
        // 64 advances by 1; oldest in window is now 1.
        assert!(w.accept(64));
        // Replay 0 (delta=64, just outside the window): rejected.
        assert!(!w.accept(0));
    }

    #[test]
    fn boundary_jump_clears_window() {
        // Forward jump of exactly WINDOW_BITS clears the window completely
        // (the codepath that bypasses the shift).
        let mut w = AntiReplayWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(WINDOW_BITS));
        // 0 should now be outside the window (delta = 64).
        assert!(!w.accept(0));
        // But everything from highest - 63 up should be acceptable on first
        // sight.
        assert!(w.accept(1));
    }
}
