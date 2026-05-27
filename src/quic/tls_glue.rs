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
//! 4. `our_transport_params() -> &[u8]` — the engine reads this at
//!    construction time and embeds the bytes verbatim in the outgoing
//!    `ClientHello` / `EncryptedExtensions`.
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
//!
//! The transport-params bytes never change after construction, so we
//! keep them in a separate `Arc<Vec<u8>>` (not behind the `Mutex`) so
//! [`QuicHooks::our_transport_params`] can return `&[u8]` directly,
//! without a `MutexGuard` borrow that the trait signature wouldn't allow.
//! Same idiom as the Phase-3 `SharedHooks` test impl.

#![allow(dead_code)]

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
/// mutable callbacks, plus a separate `Arc<Vec<u8>>` for the immutable
/// `our_transport_params` accessor (the trait returns `&[u8]` with the
/// `&self` lifetime, which a `MutexGuard` cannot satisfy).
pub(crate) struct QuicTlsHooks {
    pub(crate) state: Arc<Mutex<QuicHookState>>,
    /// Caller-supplied transport-parameters bytes. Read-only at this
    /// layer; returned verbatim from [`QuicHooks::our_transport_params`].
    pub(crate) our_params: Arc<Vec<u8>>,
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

    fn our_transport_params(&self) -> &[u8] {
        // Borrowed straight from the immutable `Arc<Vec<u8>>` — no Mutex
        // involvement, so the returned slice's lifetime is `&self`.
        self.our_params.as_slice()
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
    let our_params = Arc::new(our_params);
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
    pub(crate) our_params: Arc<Vec<u8>>,
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
    fn hooks_return_immutable_our_params() {
        let (boxed, handle) = build_hooks(alloc::vec![1, 2, 3, 4]);
        assert_eq!(boxed.our_transport_params(), &[1, 2, 3, 4]);
        // Both views point at the same underlying allocation.
        assert_eq!(handle.our_params.as_slice(), &[1, 2, 3, 4]);
    }
}
