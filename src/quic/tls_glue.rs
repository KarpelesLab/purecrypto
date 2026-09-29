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
//!    can mutate the parameters between construction and the engine read
//!    (server-only transport params like
//!    `original_destination_connection_id` aren't known until the first
//!    Initial arrives).
//! 5. `session_context() -> Vec<u8>` — the QUIC version the server's
//!    session tickets are bound to (RFC 9369 §5).
//!
//! One decision is taken *inside* callback 3 rather than by the driver
//! afterwards: RFC 9368 §2.3 compatible version negotiation. The server's
//! `EncryptedExtensions` — built by the engine in the same call that parses
//! the `ClientHello` — must already carry the Negotiated Version in its
//! `version_information` (§3), so the hook selects it from the client's
//! offer the moment the client's parameters arrive and rewrites our own
//! parameters before the engine reads them. The driver reads the outcome
//! back with [`HookHandle::take_negotiated_version`] and re-keys.
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

use crate::quic::transport_params::{TransportParameters, VersionInformation};
use crate::quic::version::{QuicVersion, select_server_version};
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
    /// RFC 9369 §5 — what the server's session tickets are bound to: the
    /// wire form of the connection's QUIC version. Empty until the driver
    /// learns the version (the first authenticated Initial); moved to the
    /// Negotiated Version when compatible negotiation picks another.
    pub(crate) session_context: Vec<u8>,
    /// Server only — installed by the driver once the first Initial has
    /// authenticated: the versions this server accepts, in preference
    /// order, and the version that Initial was sent in. With it in place the
    /// hook performs RFC 9368 §2.3 compatible version negotiation when the
    /// client's transport parameters arrive.
    pub(crate) version_policy: Option<(Vec<QuicVersion>, QuicVersion)>,
    /// The Negotiated Version the hook selected (server), for the driver to
    /// pick up. `None` while the client's parameters have not arrived, did
    /// not parse, or failed the §4 checks — the driver re-runs the same
    /// selection on the parsed parameters and reports the error then.
    pub(crate) negotiated: Option<QuicVersion>,
}

/// The engine-side hook implementation. Stores `Arc<Mutex<state>>` for
/// mutable callbacks, plus a separate `Arc<Mutex<TransportParameters>>`
/// for the `our_transport_params` accessor, which encodes on demand.
///
/// Phase 7: `our_params` is mutable so the QUIC layer can update it between
/// the engine's construction and its first read (server-only transport
/// parameters like `original_destination_connection_id` aren't known until
/// the first Initial arrives — see [`crate::quic::connection::QuicConnection::populate_server_only_tp`]).
pub(crate) struct QuicTlsHooks {
    pub(crate) state: Arc<Mutex<QuicHookState>>,
    /// Our transport parameters. Mutated by the QUIC layer through the
    /// shared [`HookHandle`] when post-construction updates are needed
    /// (Retry path), and by [`Self::on_peer_transport_params`] when
    /// compatible version negotiation settles the Chosen Version.
    pub(crate) our_params: Arc<Mutex<TransportParameters>>,
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
        // Encode the current parameters under the mutex so the caller
        // receives an owned `Vec`. The mutex is single-threaded in practice.
        let mut out = Vec::new();
        self.our_params
            .lock()
            .expect("our_params mutex poisoned")
            .encode(&mut out);
        out
    }

    fn on_peer_transport_params(&mut self, raw: &[u8]) {
        let mut g = self.state.lock().expect("hooks mutex poisoned");
        g.peer_params = Some(raw.to_vec());
        // RFC 9368 §2.3 — server-side compatible version negotiation has to
        // happen *now*: the engine builds EncryptedExtensions, and reads our
        // `version_information` for it, before control returns to the
        // driver. A body that does not decode, or fails the §4 rules, is
        // left for the driver, which parses the same bytes again and closes
        // the connection with the right error code.
        let Some((ours, in_use)) = g.version_policy.clone() else {
            return;
        };
        let Ok(parsed) = TransportParameters::decode(raw) else {
            return;
        };
        let Ok(negotiated) =
            select_server_version(&ours, in_use, parsed.version_information.as_ref())
        else {
            return;
        };
        g.negotiated = Some(negotiated);
        g.session_context = negotiated.wire().to_be_bytes().to_vec();
        drop(g);
        let mut p = self.our_params.lock().expect("our_params mutex poisoned");
        match p.version_information.as_mut() {
            Some(vi) => vi.chosen = negotiated.wire(),
            None => {
                p.version_information = Some(VersionInformation {
                    chosen: negotiated.wire(),
                    available: ours.iter().map(|v| v.wire()).collect(),
                })
            }
        }
    }

    fn session_context(&self) -> Vec<u8> {
        self.state
            .lock()
            .expect("hooks mutex poisoned")
            .session_context
            .clone()
    }
}

/// Construct a `(boxed hooks, driver handle)` pair for installing into a
/// TLS engine. The driver holds the handle; the engine holds the boxed
/// trait object.
pub(crate) fn build_hooks(our_params: TransportParameters) -> (Box<QuicTlsHooks>, HookHandle) {
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
    pub(crate) our_params: Arc<Mutex<TransportParameters>>,
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

    /// Overwrites the parameters the engine will read from
    /// [`QuicHooks::our_transport_params`]. Phase 7 calls this on the
    /// server when transport parameters become known mid-handshake
    /// (e.g. `original_destination_connection_id` after the first
    /// Initial). Idempotent and cheap.
    pub(crate) fn set_our_params(&self, params: TransportParameters) {
        let mut g = self.our_params.lock().expect("our_params mutex poisoned");
        *g = params;
    }

    /// Installs the server's version-negotiation policy: the versions it
    /// accepts, in preference order, and the version the connection is in
    /// (that of its first Initial). See [`QuicHookState::version_policy`].
    /// Also binds session tickets to that version (RFC 9369 §5) until
    /// negotiation moves the connection to another.
    pub(crate) fn set_version_policy(&self, ours: Vec<QuicVersion>, in_use: QuicVersion) {
        let mut g = self.state.lock().expect("hooks mutex poisoned");
        g.session_context = in_use.wire().to_be_bytes().to_vec();
        g.version_policy = Some((ours, in_use));
    }

    /// Sets the version session tickets are bound to (RFC 9369 §5) without
    /// installing a policy — the client's side of the same binding is
    /// applied by the driver, so this is for tests and symmetry.
    #[cfg(test)]
    pub(crate) fn set_session_context(&self, version: QuicVersion) {
        let mut g = self.state.lock().expect("hooks mutex poisoned");
        g.session_context = version.wire().to_be_bytes().to_vec();
    }

    /// Returns the Negotiated Version the hook selected when the client's
    /// transport parameters arrived (server side), clearing it. See
    /// [`QuicHookState::negotiated`].
    pub(crate) fn take_negotiated_version(&self) -> Option<QuicVersion> {
        let mut g = self.state.lock().expect("hooks mutex poisoned");
        g.negotiated.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parameters carrying only a `max_idle_timeout` of `ms`, whose
    /// encoding is what the tests compare.
    fn params(ms: u64) -> TransportParameters {
        TransportParameters {
            max_idle_timeout_ms: Some(ms),
            ..TransportParameters::default()
        }
    }

    fn encoded(tp: &TransportParameters) -> Vec<u8> {
        let mut out = Vec::new();
        tp.encode(&mut out);
        out
    }

    #[test]
    fn hooks_round_trip_handshake_bytes() {
        let (mut boxed, handle) = build_hooks(params(1));
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
        let (mut boxed, handle) = build_hooks(params(1));
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
        let (mut boxed, handle) = build_hooks(params(1));
        assert!(handle.take_peer_params().is_none());
        boxed.on_peer_transport_params(&[0xde, 0xad]);
        let got = handle.take_peer_params().expect("set");
        assert_eq!(got, &[0xde, 0xad]);
        // Taken; second take returns None.
        assert!(handle.take_peer_params().is_none());
    }

    #[test]
    fn hooks_return_our_params() {
        let (boxed, handle) = build_hooks(params(1));
        assert_eq!(boxed.our_transport_params(), encoded(&params(1)));
        // The driver can update the parameters the engine reads later.
        handle.set_our_params(params(2));
        assert_eq!(boxed.our_transport_params(), encoded(&params(2)));
    }

    /// RFC 9368 §2.3 — with a server policy installed, the client's
    /// `version_information` selects the Negotiated Version before the
    /// engine reads our parameters for EncryptedExtensions: the Chosen
    /// Version we send is the negotiated one, the driver can read it back,
    /// and session tickets move to that version (RFC 9369 §5).
    #[test]
    fn hooks_negotiate_version_from_peer_params() {
        let ours = TransportParameters {
            version_information: Some(VersionInformation {
                chosen: QuicVersion::V1.wire(),
                available: alloc::vec![QuicVersion::V2.wire(), QuicVersion::V1.wire()],
            }),
            ..TransportParameters::default()
        };
        let (mut boxed, handle) = build_hooks(ours);
        // Nothing happens without a policy (the client side).
        let client = TransportParameters {
            version_information: Some(VersionInformation {
                chosen: QuicVersion::V1.wire(),
                available: alloc::vec![QuicVersion::V1.wire(), QuicVersion::V2.wire()],
            }),
            ..TransportParameters::default()
        };
        boxed.on_peer_transport_params(&encoded(&client));
        assert!(handle.take_negotiated_version().is_none());
        assert!(boxed.session_context().is_empty());
        handle.take_peer_params();

        // A v2-preferring server picks v2 from a client that offers both.
        handle.set_version_policy(
            alloc::vec![QuicVersion::V2, QuicVersion::V1],
            QuicVersion::V1,
        );
        assert_eq!(
            boxed.session_context(),
            QuicVersion::V1.wire().to_be_bytes()
        );
        boxed.on_peer_transport_params(&encoded(&client));
        assert_eq!(handle.take_negotiated_version(), Some(QuicVersion::V2));
        assert_eq!(
            boxed.session_context(),
            QuicVersion::V2.wire().to_be_bytes()
        );
        let ee = TransportParameters::decode(&boxed.our_transport_params()).unwrap();
        let vi = ee.version_information.unwrap();
        assert_eq!(vi.chosen, QuicVersion::V2.wire());
        assert_eq!(
            vi.available,
            alloc::vec![QuicVersion::V2.wire(), QuicVersion::V1.wire()]
        );
    }

    /// A client whose Chosen Version is not the version its packets carry
    /// (RFC 9368 §4) yields no negotiated version from the hook — the driver
    /// closes with VERSION_NEGOTIATION_ERROR — and our Chosen Version is
    /// left alone.
    #[test]
    fn hooks_leave_a_bad_offer_to_the_driver() {
        let ours = TransportParameters {
            version_information: Some(VersionInformation {
                chosen: QuicVersion::V1.wire(),
                available: alloc::vec![QuicVersion::V1.wire()],
            }),
            ..TransportParameters::default()
        };
        let (mut boxed, handle) = build_hooks(ours);
        handle.set_version_policy(alloc::vec![QuicVersion::V1], QuicVersion::V1);
        let client = TransportParameters {
            version_information: Some(VersionInformation {
                chosen: QuicVersion::V2.wire(),
                available: alloc::vec![QuicVersion::V2.wire(), QuicVersion::V1.wire()],
            }),
            ..TransportParameters::default()
        };
        boxed.on_peer_transport_params(&encoded(&client));
        assert!(handle.take_negotiated_version().is_none());
        let ee = TransportParameters::decode(&boxed.our_transport_params()).unwrap();
        assert_eq!(
            ee.version_information.unwrap().chosen,
            QuicVersion::V1.wire()
        );
        // The raw bytes still reach the driver for its own validation.
        assert_eq!(handle.take_peer_params().unwrap(), encoded(&client));
    }
}
