//! Bridge between the TLS engine and the rest of [`QuicConnection`].
//!
//! The TLS engine (Phase 3) accepts a `Box<dyn QuicHooks>` at construction
//! and invokes it at three moments:
//!
//! 1. `on_handshake_data(level, msg)` — every handshake message emitted by
//!    the engine. The QUIC layer puts those bytes into CRYPTO frames at
//!    the matching encryption level.
//! 2. `on_traffic_secret(level, dir, secret)` — every traffic-secret
//!    derivation. The QUIC layer turns each `(level, dir, secret)` into
//!    `(level, dir, DirKeys)` and installs it into `CryptoState`.
//! 3. `on_peer_transport_params(raw)` — the peer's
//!    `quic_transport_parameters` extension body, exactly once.
//!
//! Plus one *outbound* call site:
//!
//! 4. `our_transport_params() -> Vec<u8>` — the engine reads this when
//!    building the `ClientHello` / `EncryptedExtensions` extension body.
//!    Phase 7 made this owned (rather than borrowed) so the QUIC layer
//!    can mutate the bytes between construction and the engine read
//!    (server-only transport params like
//!    `original_destination_connection_id` aren't known until the first
//!    Initial arrives).
//!
//! ## Ownership pattern
//!
//! The engine owns its `Box<dyn QuicHooks + Send>` (Phase 3 set the `:
//! Send` bound). [`QuicConnection`] needs to *see* the queues those hooks
//! fill in order to react. Because the trait is `Send`, the only stable
//! `Send`-compatible shared-mutable-state pattern is `Arc<Mutex<…>>`. The
//! `Mutex` is uncontended in practice — `QuicConnection` is itself `!Sync`
//! (and only mutably-borrowed by one thread at a time), so the lock is
//! a single-thread fast path — but it has to be there to satisfy the
//! trait bound. RFC-wise this is irrelevant: QUIC state machines are
//! single-threaded by design.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::Mutex;

use crate::tls::quic_hooks::{Direction, Level, QuicHooks};

/// Mutable state shared between [`QuicTlsHooks`] (engine side) and
/// [`QuicConnection`] (driver side). The driver drains the queues after
/// every engine pump.
#[derive(Default)]
pub(crate) struct QuicHookState {
    /// Handshake bytes the engine produced, queued per level. Indexed by
    /// `Level as usize` — 4 slots (`Initial`, `EarlyData`, `Handshake`,
    /// `OneRtt`).
    pub(crate) tx_handshake: [Vec<u8>; 4],
    /// Each event the engine reported: `(level, dir, secret bytes)`. The
    /// driver consumes this list in order, mapping each entry to a
    /// `DirKeys` and installing it in `CryptoState`.
    pub(crate) secret_events: Vec<(Level, Direction, Vec<u8>)>,
    /// The peer's transport-params bytes, set at most once per handshake.
    pub(crate) peer_params: Option<Vec<u8>>,
}

/// The engine-side hook implementation. Stores `Arc<Mutex<state>>` for
/// mutable callbacks, plus a separate `Arc<Mutex<Vec<u8>>>` for the
/// `our_transport_params` accessor.
///
/// Phase 7: `our_params` is mutable so the QUIC layer can update it between
/// the engine's construction and its first read (server-only transport
/// parameters like `original_destination_connection_id` aren't known until
/// the first Initial arrives — see [`crate::quic::connection::QuicConnection::populate_server_only_tp`]).
pub(crate) struct QuicTlsHooks {
    pub(crate) state: Arc<Mutex<QuicHookState>>,
    /// Caller-supplied transport-parameters bytes. Mutated by the QUIC
    /// layer through the shared [`HookHandle`] when post-construction
    /// updates are needed (Retry path).
    pub(crate) our_params: Arc<Mutex<Vec<u8>>>,
}

impl QuicHooks for QuicTlsHooks {
    fn on_handshake_data(&mut self, level: Level, data: &[u8]) {
        let mut g = self.state.lock().expect("hooks mutex poisoned");
        g.tx_handshake[level as usize].extend_from_slice(data);
    }

    fn on_traffic_secret(&mut self, level: Level, dir: Direction, secret: &[u8]) {
        let mut g = self.state.lock().expect("hooks mutex poisoned");
        g.secret_events.push((level, dir, secret.to_vec()));
    }

    fn our_transport_params(&self) -> Vec<u8> {
        // Clone the current bytes under the mutex so the caller receives
        // an owned `Vec`. The mutex is single-threaded in practice.
        self.our_params
            .lock()
            .expect("our_params mutex poisoned")
            .clone()
    }

    fn on_peer_transport_params(&mut self, raw: &[u8]) {
        let mut g = self.state.lock().expect("hooks mutex poisoned");
        g.peer_params = Some(raw.to_vec());
    }
}

/// Construct a `(boxed hooks, driver handle)` pair for installing into a
/// TLS engine. The driver holds the handle; the engine holds the boxed
/// trait object.
pub(crate) fn build_hooks(our_params: Vec<u8>) -> (Box<QuicTlsHooks>, HookHandle) {
    let state = Arc::new(Mutex::new(QuicHookState::default()));
    let our_params = Arc::new(Mutex::new(our_params));
    let handle = HookHandle {
        state: state.clone(),
        our_params: our_params.clone(),
    };
    let boxed = Box::new(QuicTlsHooks { state, our_params });
    (boxed, handle)
}

/// Driver-side handle for inspecting / draining the shared hook state.
///
/// Cloning is cheap (Arc bumps) and intended.
#[derive(Clone)]
pub(crate) struct HookHandle {
    pub(crate) state: Arc<Mutex<QuicHookState>>,
    pub(crate) our_params: Arc<Mutex<Vec<u8>>>,
}

impl HookHandle {
    /// Returns the bytes the engine wants to send at `level`, moving them
    /// out of the shared queue. After this call, `tx_handshake[level]` is
    /// empty.
    pub(crate) fn drain_handshake(&self, level: Level) -> Vec<u8> {
        let mut g = self.state.lock().expect("hooks mutex poisoned");
        core::mem::take(&mut g.tx_handshake[level as usize])
    }

    /// Drains every traffic-secret event queued so far. Order is
    /// preserved: the first emitted event is the first one returned.
    pub(crate) fn drain_secret_events(&self) -> Vec<(Level, Direction, Vec<u8>)> {
        let mut g = self.state.lock().expect("hooks mutex poisoned");
        core::mem::take(&mut g.secret_events)
    }

    /// Returns and clears the peer's transport-params bytes if set,
    /// `None` otherwise. The engine sets this at most once per handshake.
    pub(crate) fn take_peer_params(&self) -> Option<Vec<u8>> {
        let mut g = self.state.lock().expect("hooks mutex poisoned");
        g.peer_params.take()
    }

    /// Overwrites the bytes the engine will read from
    /// [`QuicHooks::our_transport_params`]. Phase 7 calls this on the
    /// server when transport parameters become known mid-handshake
    /// (e.g. `original_destination_connection_id` after the first
    /// Initial). Idempotent and cheap.
    pub(crate) fn set_our_params(&self, bytes: Vec<u8>) {
        let mut g = self.our_params.lock().expect("our_params mutex poisoned");
        *g = bytes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hooks_round_trip_handshake_bytes() {
        let (mut boxed, handle) = build_hooks(alloc::vec![1, 2, 3]);
        boxed.on_handshake_data(Level::Initial, b"hello-CH");
        boxed.on_handshake_data(Level::Handshake, b"finished");
        boxed.on_handshake_data(Level::Initial, b"-cont");

        let init = handle.drain_handshake(Level::Initial);
        assert_eq!(init, b"hello-CH-cont");
        let hs = handle.drain_handshake(Level::Handshake);
        assert_eq!(hs, b"finished");
        // Subsequent drains return empty.
        assert!(handle.drain_handshake(Level::Initial).is_empty());
    }

    #[test]
    fn hooks_capture_secret_events_in_order() {
        let (mut boxed, handle) = build_hooks(alloc::vec![]);
        boxed.on_traffic_secret(Level::Handshake, Direction::Tx, b"shts");
        boxed.on_traffic_secret(Level::Handshake, Direction::Rx, b"chts");
        boxed.on_traffic_secret(Level::OneRtt, Direction::Tx, b"app");

        let events = handle.drain_secret_events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].0, Level::Handshake);
        assert_eq!(events[0].1, Direction::Tx);
        assert_eq!(events[0].2, b"shts");
        assert_eq!(events[1].1, Direction::Rx);
        assert_eq!(events[2].0, Level::OneRtt);
        // Drain is destructive.
        assert!(handle.drain_secret_events().is_empty());
    }

    #[test]
    fn hooks_capture_peer_params() {
        let (mut boxed, handle) = build_hooks(alloc::vec![0xa, 0xb]);
        assert!(handle.take_peer_params().is_none());
        boxed.on_peer_transport_params(&[0xde, 0xad]);
        let got = handle.take_peer_params().expect("set");
        assert_eq!(got, &[0xde, 0xad]);
        // Taken; second take returns None.
        assert!(handle.take_peer_params().is_none());
    }

    #[test]
    fn hooks_return_our_params() {
        let (boxed, handle) = build_hooks(alloc::vec![1, 2, 3, 4]);
        assert_eq!(boxed.our_transport_params(), alloc::vec![1u8, 2, 3, 4]);
        // The driver can update the bytes the engine reads later.
        handle.set_our_params(alloc::vec![5, 6]);
        assert_eq!(boxed.our_transport_params(), alloc::vec![5u8, 6]);
    }
}
