//! Plumbing seam between the TLS 1.3 engine and a future QUIC layer.
//!
//! The QUIC transport (RFC 9001) reuses the TLS 1.3 handshake state machine
//! but carries the handshake messages in CRYPTO frames at distinct encryption
//! levels instead of in TLS records. To keep the engine sans-I/O and avoid a
//! second copy of the state machine, the engine in this crate runs in one of
//! three modes (TLS, DTLS, QUIC). In QUIC mode it:
//!
//! * suppresses record framing (the `ConnectionCore` outbound buffer never
//!   receives bytes), and instead surfaces each handshake message to the
//!   QUIC layer through [`QuicHooks::on_handshake_data`];
//! * surfaces each freshly derived TLS 1.3 traffic secret to the QUIC layer
//!   through [`QuicHooks::on_traffic_secret`] (the QUIC layer turns it into
//!   `quic key` / `quic iv` / `quic hp` via `expand_label_dyn`);
//! * never emits `ChangeCipherSpec` (forbidden in QUIC by RFC 9001 §8.4);
//! * never expects `KeyUpdate` or `EndOfEarlyData` (QUIC has its own key
//!   update via the Key Phase bit per RFC 9001 §6, and 0-RTT termination is
//!   not signalled in-band per RFC 9001 §8.3);
//! * emits a `quic_transport_parameters` (codepoint 0x0039, RFC 9001 §8.2)
//!   extension in `ClientHello` / `EncryptedExtensions` whose opaque body
//!   comes from [`QuicHooks::our_transport_params`], and feeds the peer's
//!   body back through [`QuicHooks::on_peer_transport_params`].
//!
//! Phase 3 only adds the seam — the QUIC layer that drives it lands in
//! later phases. In TLS or DTLS mode none of the hooks fire; the engine
//! behaves byte-for-byte as before this refactor.

use alloc::boxed::Box;

/// Encryption levels exposed to QUIC (RFC 9001 §4.1.1).
///
/// 0-RTT and 1-RTT share the application packet-number space at the QUIC
/// layer (RFC 9000 §12.3), but the TLS engine still needs to distinguish
/// them when surfacing the early-data secret separately from the
/// application-data secret. Variant ordinals are stable and match the
/// PN-space numbering used by the future QUIC layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Level {
    Initial = 0,
    EarlyData = 1,
    Handshake = 2,
    OneRtt = 3,
}

/// Which side of an encryption level a secret keys: outgoing (write) or
/// incoming (read).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Direction {
    Tx,
    Rx,
}

/// Which framing mode the engine is operating in.
///
/// * `Tls` and `Dtls` are unchanged from before this refactor — record
///   framing is active and hooks are never invoked.
/// * `Quic` skips record framing entirely, suppresses outbound
///   `ChangeCipherSpec`, omits record-layer key installation, and invokes
///   the [`QuicHooks`] callbacks at every emit / key-derivation site.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum EngineMode {
    #[default]
    Tls,
    /// Used by the DTLS engine path (lands in a follow-up); kept in the
    /// enum so the variant numbering stays stable when the DTLS engine
    /// adopts the same hooks.
    #[allow(dead_code)]
    Dtls,
    Quic,
}

/// Callbacks the TLS engine invokes when running in [`EngineMode::Quic`].
///
/// The QUIC layer (Phase 4+) implements this and installs an instance on
/// the engine at construction (`new_for_quic`). Calls always happen on the
/// same thread as the engine's owning Connection — no internal
/// synchronization required (hence the `Send` bound but no `Sync`).
pub(crate) trait QuicHooks: Send {
    /// The engine just produced a handshake message. The QUIC layer will
    /// carry it in CRYPTO frames at `level`. `data` is the full handshake
    /// message including its 4-byte type/length header (i.e. exactly what
    /// `ConnectionCore::emit_handshake` would feed to the record stream).
    fn on_handshake_data(&mut self, level: Level, data: &[u8]);

    /// The engine just derived a TLS 1.3 traffic secret. The QUIC layer
    /// turns it into `quic key` / `quic iv` / `quic hp` via
    /// `expand_label_dyn` and installs it into its level keys.
    ///
    /// Called once per direction. For example, at handshake-secret
    /// derivation the engine invokes this twice: once with
    /// `(Handshake, Tx, …)` and once with `(Handshake, Rx, …)`.
    fn on_traffic_secret(&mut self, level: Level, dir: Direction, secret: &[u8]);

    /// The caller-supplied `transport_parameters` body to embed in our
    /// outgoing `ClientHello` (client) or `EncryptedExtensions` (server).
    /// Returning an empty slice causes the engine to omit the extension
    /// entirely; QUIC handshakes are required to carry it but enforcement
    /// is the QUIC layer's job, not the TLS engine's.
    fn our_transport_params(&self) -> &[u8];

    /// The peer's `quic_transport_parameters` body, extracted from their
    /// `ClientHello` (server side) or `EncryptedExtensions` (client side).
    /// The engine calls this at most once per handshake.
    fn on_peer_transport_params(&mut self, raw: &[u8]);
}

/// A no-op [`QuicHooks`] used internally so the engine can route through
/// the same code path without an `Option` unwrap on every callback.
///
/// In practice the engine stores `Option<Box<dyn QuicHooks>>` and only
/// touches the hooks when [`EngineMode`] is `Quic`, so this type is
/// reserved for tests that want a hooks impl that does nothing.
// Used by tests below; the engine itself uses `Option<Box<dyn QuicHooks>>`.
#[allow(dead_code)]
pub(crate) struct NoHooks;

impl QuicHooks for NoHooks {
    fn on_handshake_data(&mut self, _level: Level, _data: &[u8]) {}
    fn on_traffic_secret(&mut self, _level: Level, _dir: Direction, _secret: &[u8]) {}
    fn our_transport_params(&self) -> &[u8] {
        &[]
    }
    fn on_peer_transport_params(&mut self, _raw: &[u8]) {}
}

/// Type alias for the boxed hooks the TLS engine stores.
pub(crate) type BoxedHooks = Box<dyn QuicHooks>;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// A [`QuicHooks`] impl that captures every callback for inspection in
    /// tests. Two instances can be paired with their `tx_handshake` queues
    /// pumped into the other side via `process_quic_handshake_bytes` to
    /// drive a full TLS 1.3 handshake without ever emitting record bytes.
    pub(crate) struct CapturingHooks {
        /// Our outgoing transport-parameters body.
        pub our_params: Vec<u8>,
        /// The peer's transport-parameters body, captured at most once.
        pub peer_params: Vec<u8>,
        /// Whether [`on_peer_transport_params`] has been invoked.
        pub peer_params_seen: bool,
        /// Handshake messages the engine asked us to carry, in order, tagged
        /// by their encryption level.
        pub tx_handshake: Vec<(Level, Vec<u8>)>,
        /// Traffic secrets the engine derived, in order.
        pub secrets: Vec<(Level, Direction, Vec<u8>)>,
    }

    impl CapturingHooks {
        pub(crate) fn new(our_params: Vec<u8>) -> Self {
            Self {
                our_params,
                peer_params: Vec::new(),
                peer_params_seen: false,
                tx_handshake: Vec::new(),
                secrets: Vec::new(),
            }
        }
    }

    impl QuicHooks for CapturingHooks {
        fn on_handshake_data(&mut self, level: Level, data: &[u8]) {
            self.tx_handshake.push((level, data.to_vec()));
        }
        fn on_traffic_secret(&mut self, level: Level, dir: Direction, secret: &[u8]) {
            self.secrets.push((level, dir, secret.to_vec()));
        }
        fn our_transport_params(&self) -> &[u8] {
            &self.our_params
        }
        fn on_peer_transport_params(&mut self, raw: &[u8]) {
            self.peer_params = raw.to_vec();
            self.peer_params_seen = true;
        }
    }

    /// `NoHooks` is callable in both directions without panicking.
    #[test]
    fn no_hooks_is_inert() {
        let mut h = NoHooks;
        h.on_handshake_data(Level::Initial, &[1, 2, 3]);
        h.on_traffic_secret(Level::Handshake, Direction::Tx, &[4, 5]);
        h.on_peer_transport_params(&[6, 7]);
        assert!(h.our_transport_params().is_empty());
    }

    #[test]
    fn capturing_hooks_records_calls() {
        let mut h = CapturingHooks::new(alloc::vec![1, 2, 3]);
        h.on_handshake_data(Level::Initial, b"hello");
        h.on_handshake_data(Level::Handshake, b"finished");
        h.on_traffic_secret(Level::Handshake, Direction::Tx, b"shts");
        h.on_traffic_secret(Level::Handshake, Direction::Rx, b"chts");
        h.on_peer_transport_params(b"peer");

        assert_eq!(h.our_transport_params(), &[1, 2, 3]);
        assert_eq!(h.tx_handshake.len(), 2);
        assert_eq!(h.tx_handshake[0].0, Level::Initial);
        assert_eq!(h.tx_handshake[1].0, Level::Handshake);
        assert_eq!(h.secrets.len(), 2);
        assert_eq!(h.peer_params, b"peer");
        assert!(h.peer_params_seen);
    }

    #[test]
    fn engine_mode_default_is_tls() {
        assert_eq!(EngineMode::default(), EngineMode::Tls);
    }
}
