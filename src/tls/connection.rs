//! Unified [`Connection`] enum over the four TLS/DTLS connection engines.
//!
//! All eight per-(version, role) connection types live behind a single
//! state-machine-pump API: [`Connection::handshake`], [`feed`](Connection::feed),
//! [`pop`](Connection::pop), [`send`](Connection::send), and
//! [`recv`](Connection::recv). The variants are `pub(crate)` so the public API
//! is the methods only.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::time::Duration;

use crate::rng::{CryptoRng, RngCore};

use super::config::Config;
use super::error::Error;
use super::groups::NamedGroup;
#[cfg(feature = "dtls")]
use super::opts::DtlsOpts;
use super::opts::{ClientOpts, CommonOpts, ServerOpts};
use super::version::ProtocolVersion;

/// Type-erased RNG the public [`Connection`] hands to its engines: the
/// caller-supplied [`EntropySource`](super::config::EntropySource), wrapped so
/// it satisfies the `R: RngCore` bound the per-(version, role) engines are
/// generic over (the public enum itself cannot be generic).
///
/// There is deliberately no `OsRng` default — a sans-I/O engine takes entropy
/// as an input, so the caller must always supply a source via
/// [`ConfigBuilder::rng`](super::ConfigBuilder::rng). `OsRng` is just one
/// [`EntropySource`] the caller may choose to pass.
struct ConfigRng(alloc::sync::Arc<dyn super::config::EntropySource>);

impl RngCore for ConfigRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }
}

// The configured source is contractually a CSPRNG — the caller promises the
// `EntropySource` is cryptographically secure — so it is valid wherever the
// engines require `CryptoRng`.
impl CryptoRng for ConfigRng {}

/// The engine RNG for `cfg`. Errors with [`Error::MissingEntropySource`] when
/// the caller did not install one: the engine never falls back to a default.
fn config_rng(cfg: &Config) -> Result<ConfigRng, Error> {
    match &cfg.rng {
        Some(src) => Ok(ConfigRng(src.clone())),
        None => Err(Error::MissingEntropySource),
    }
}

/// Handshake progress, as observed from the uniform API.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HandshakeStatus {
    /// The handshake is complete; application data may flow.
    Complete,
    /// The engine has nothing to emit; the caller should
    /// [`feed`](Connection::feed) bytes from the peer — **or**, for an
    /// [`SigningKey::External`](super::config::SigningKey::External) identity,
    /// supply a pending external signature. Check
    /// [`signature_request`](Connection::signature_request) before blocking on
    /// a read: when it returns `Some`, the handshake is suspended awaiting a
    /// `CertificateVerify` signature, not peer bytes.
    WantRead,
    /// The engine has wire bytes ready; the caller should drain them with
    /// [`pop`](Connection::pop) and forward them to the peer.
    WantWrite,
}

/// What [`Connection::drive`] needs next — the unified, key-agnostic drive
/// surface. Unlike [`HandshakeStatus`], this folds the signing device into the
/// same loop, so a caller services peer I/O *and* (transparently) a TPM/HSM
/// without ever branching on the kind of key behind [`Config::signer`].
///
/// `#[non_exhaustive]`: future drive reasons can be added without breaking
/// exhaustive matches.
#[non_exhaustive]
pub enum Step {
    /// The engine needs bytes from the peer: read the socket and
    /// [`feed`](Connection::feed) them.
    WantRead,
    /// The engine has wire bytes to send: [`pop`](Connection::pop) and write
    /// them to the peer.
    WantWrite,
    /// The signing device needs servicing. If `Some`, wait on the
    /// [`Readiness`](super::signer::Readiness) (sync: [`wait`][super::signer::Readiness::wait];
    /// async: register its fd with your reactor), then call
    /// [`drive`](Connection::drive) again. `None` means the op has no waitable
    /// descriptor — just call `drive` again. In-process keys never yield this.
    #[cfg_attr(
        not(feature = "std"),
        doc = "",
        doc = "[super::signer::Readiness::wait]: crate#no_std"
    )]
    WantSigner(Option<super::signer::Readiness>),
    /// The handshake is complete; application data may flow.
    Complete,
}

/// A request for an external `CertificateVerify` signature, returned by
/// [`Connection::signature_request`]. The caller signs `message` under the
/// algorithm identified by `scheme` (the signature operation applies the
/// scheme's own hashing/padding) and resumes via
/// [`Connection::provide_signature`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignatureRequest {
    /// IANA `SignatureScheme` code point (RFC 8446 §4.2.3) negotiated for this
    /// handshake — the algorithm the returned signature must use.
    pub scheme: u16,
    /// The exact bytes to sign: the TLS 1.3 `CertificateVerify` signature input
    /// (the 64-octet pad, context string, `0x00`, and transcript hash).
    pub message: Vec<u8>,
}

/// An opaque, resumable TLS session captured from a completed client
/// handshake.
///
/// Obtain one with [`Connection::take_session`] after the handshake finishes,
/// persist it, and prime a later connection to the same server by passing it
/// to [`super::ConfigBuilder::resumption_session`]. A TLS 1.3 session resumes
/// via PSK (RFC 8446 §2.2); a TLS 1.2 session via an RFC 5077 ticket. The
/// contents are version-specific and deliberately not inspectable.
#[derive(Clone)]
pub struct ResumptionSession(ResumptionSessionKind);

#[derive(Clone)]
enum ResumptionSessionKind {
    Tls13(super::conn::StoredSession),
    Tls12(super::conn::StoredSession12),
}

/// A unified TLS or DTLS connection (client or server, any supported
/// version).
///
/// Construct via [`Connection::client`] or [`Connection::server`], passing a
/// shared [`super::Config`]. The internal engine is picked from
/// `config.max_version`.
pub struct Connection {
    inner: Engine,
    /// Pending outbound DTLS datagrams; [`Connection::pop`] returns one per
    /// call. Empty for TLS engines, which return their entire write buffer
    /// in one call. Always constructed (keeps the connection constructors
    /// uniform); only read on the DTLS paths, hence dead when `dtls` is off.
    #[cfg_attr(not(feature = "dtls"), allow(dead_code))]
    pending_dtls: alloc::collections::VecDeque<Vec<u8>>,
    /// Transparent pluggable signer (from [`Config::signer`]), brokered by
    /// [`Connection::drive`]. `None` when the identity signs in-process.
    signer: Option<alloc::sync::Arc<dyn super::signer::HandshakeSigner>>,
    /// The in-flight external signing operation, while [`Connection::drive`] is
    /// waiting on the signer's device.
    active_sign: Option<Box<dyn super::signer::SignOp>>,
}

#[allow(clippy::large_enum_variant)]
enum Engine {
    /// TLS 1.3 client.
    ClientTls13(Box<super::conn::ClientConnection>),
    /// TLS 1.2 client.
    ClientTls12(Box<super::conn::ClientConnection12>),
    /// TLS 1.3 server.
    ServerTls13(Box<super::conn::ServerConnection<ConfigRng>>),
    /// TLS 1.2 server.
    ServerTls12(Box<super::conn::ServerConnection12<ConfigRng>>),
    /// Deferred TLS server whose concrete version (1.2 or 1.3) is chosen from
    /// the first ClientHello — used when the configured range spans both.
    ServerTlsAuto(Box<ServerConnectionAuto>),
    /// Version-spanning TLS client: starts as a 1.3 client emitting a hybrid
    /// ClientHello and downgrades to a 1.2 client (adopting that ClientHello)
    /// if the server selects TLS 1.2.
    ClientTlsAuto(Box<ClientConnectionAuto>),
    /// DTLS 1.3 client.
    #[cfg(feature = "dtls")]
    ClientDtls13(Box<crate::dtls::DtlsClientConnection13>),
    /// DTLS 1.2 client.
    #[cfg(feature = "dtls")]
    ClientDtls12(Box<crate::dtls::DtlsClientConnection12>),
    /// DTLS 1.3 server.
    #[cfg(feature = "dtls")]
    ServerDtls13(Box<crate::dtls::DtlsServerConnection13<ConfigRng>>),
    /// DTLS 1.2 server.
    #[cfg(feature = "dtls")]
    ServerDtls12(Box<crate::dtls::DtlsServerConnection12<ConfigRng>>),
}

/// Upper bound on bytes buffered while waiting to decide a deferred server's
/// version. A ClientHello (even with PQ key shares / ECH / large CA lists) fits
/// comfortably under this; a peer that dribbles bytes without ever completing a
/// ClientHello is cut off with `decode_error` rather than buffered unboundedly.
const MAX_HS_PEEK: usize = 64 * 1024;

/// The single concrete server engine a [`ServerConnectionAuto`] resolves to.
#[allow(clippy::large_enum_variant)]
enum ResolvedServer {
    Tls13(Box<super::conn::ServerConnection<ConfigRng>>),
    Tls12(Box<super::conn::ServerConnection12<ConfigRng>>),
}

/// Deferred TLS server front-end for a config whose version range spans TLS 1.2
/// and 1.3. `Connection::server` runs before any ClientHello exists, so the
/// concrete engine cannot be chosen from config alone. This buffers the opening
/// bytes, peeks the first ClientHello's `supported_versions` (RFC 8446 §4.1.1 /
/// Appendix D.1), then builds the ONE matching engine and replays the buffered
/// bytes into it. Exactly one engine is ever constructed.
struct ServerConnectionAuto {
    /// Raw wire bytes received before the version was resolved.
    buffered: Vec<u8>,
    /// Incremental ClientHello reassembly over `buffered`. Keeps a cursor so
    /// each wire byte is parsed once regardless of how the transport segments
    /// them (re-scanning from offset 0 on every `feed` is quadratic in the
    /// record count).
    peeker: super::peek::ClientHelloPeeker,
    /// Owned config the selected engine is built from; taken (dropped) on
    /// resolution. `Config` is immutable, so this clone never diverges.
    config: Option<Config>,
    /// The selected engine, once the version is known.
    resolved: Option<ResolvedServer>,
}

impl ServerConnectionAuto {
    /// Feed wire bytes. Before resolution, buffer and try to decide the
    /// version from the first ClientHello; after resolution, delegate.
    fn feed(&mut self, wire_in: &[u8]) -> Result<(), Error> {
        match &mut self.resolved {
            Some(ResolvedServer::Tls13(c)) => {
                c.read_tls(wire_in);
                c.process_new_packets()
            }
            Some(ResolvedServer::Tls12(c)) => {
                c.read_tls(wire_in);
                c.process_new_packets()
            }
            None => {
                if self.buffered.len().saturating_add(wire_in.len()) > MAX_HS_PEEK {
                    return Err(Error::Decode);
                }
                self.buffered.extend_from_slice(wire_in);
                self.try_resolve()
            }
        }
    }

    /// Once enough of the first ClientHello is buffered, select the version,
    /// build the one matching engine, and replay the buffered bytes into it.
    fn try_resolve(&mut self) -> Result<(), Error> {
        let offers13 = match self.peeker.feed(&self.buffered)? {
            None => return Ok(()), // need more bytes; nothing to emit yet
            Some(ch) => super::peek::client_hello_offers_tls13(&ch)?,
        };
        let config = self.config.take().ok_or(Error::InappropriateState)?;
        let buffered = core::mem::take(&mut self.buffered);
        if offers13 {
            let mut c = Box::new(build_tls13_server(&config)?);
            c.read_tls(&buffered);
            let r = c.process_new_packets();
            self.resolved = Some(ResolvedServer::Tls13(c));
            r
        } else {
            // Client offered no TLS 1.3: build the 1.2 (or legacy) engine. A key
            // that cannot sign TLS 1.2 suites (Ed25519/Ed448/ML-DSA) makes the
            // build fail; surface that as `handshake_failure`.
            let mut c = Box::new(build_tls12_server(&config).map_err(|_| Error::HandshakeFailure)?);
            c.read_tls(&buffered);
            let r = c.process_new_packets();
            self.resolved = Some(ResolvedServer::Tls12(c));
            r
        }
    }

    fn write_tls(&mut self) -> Vec<u8> {
        match &mut self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.write_tls(),
            Some(ResolvedServer::Tls12(c)) => c.write_tls(),
            None => Vec::new(),
        }
    }

    fn send_application_data(&mut self, app: &[u8]) -> Result<(), Error> {
        match &mut self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.send_application_data(app),
            Some(ResolvedServer::Tls12(c)) => c.send_application_data(app),
            None => Err(Error::InappropriateState),
        }
    }

    fn take_received_plaintext(&mut self) -> Vec<u8> {
        match &mut self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.take_received_plaintext(),
            Some(ResolvedServer::Tls12(c)) => c.take_received_plaintext(),
            None => Vec::new(),
        }
    }

    fn take_early_data(&mut self) -> Vec<u8> {
        // Only the resolved TLS 1.3 engine can have accepted 0-RTT.
        match &mut self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.take_early_data(),
            _ => Vec::new(),
        }
    }

    fn tls_exporter(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let ctx12 = if context.is_empty() {
            None
        } else {
            Some(context)
        };
        match &self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.tls_exporter(label, context, out),
            Some(ResolvedServer::Tls12(c)) => c.tls_exporter(label, ctx12, out),
            None => Err(Error::InappropriateState),
        }
    }

    fn close(&mut self) {
        match &mut self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.send_close_notify(),
            Some(ResolvedServer::Tls12(c)) => c.send_close_notify(),
            None => {}
        }
    }

    /// `true` while still handshaking — which includes the pre-resolution
    /// buffering window.
    fn is_handshaking(&self) -> bool {
        match &self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.is_handshaking(),
            Some(ResolvedServer::Tls12(c)) => c.is_handshaking(),
            None => true,
        }
    }

    /// `true` only once a resolved engine actually completed its handshake.
    fn is_handshake_complete(&self) -> bool {
        match &self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.is_handshake_complete(),
            Some(ResolvedServer::Tls12(c)) => c.is_handshake_complete(),
            None => false,
        }
    }

    fn received_close_notify(&self) -> bool {
        match &self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.received_close_notify(),
            Some(ResolvedServer::Tls12(c)) => c.received_close_notify(),
            None => false,
        }
    }

    fn negotiated_version(&self) -> Option<ProtocolVersion> {
        match &self.resolved {
            Some(ResolvedServer::Tls13(_)) => Some(ProtocolVersion::TLSv1_3),
            Some(ResolvedServer::Tls12(c)) => c.negotiated_protocol_version(),
            None => None,
        }
    }

    fn negotiated_cipher_suite(&self) -> Option<u16> {
        match &self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.negotiated_cipher_suite(),
            Some(ResolvedServer::Tls12(c)) => c.negotiated_cipher_suite(),
            None => None,
        }
    }

    fn alpn_protocol(&self) -> Option<&[u8]> {
        match &self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.alpn_protocol(),
            Some(ResolvedServer::Tls12(c)) => c.alpn_protocol(),
            None => None,
        }
    }

    fn peer_server_name(&self) -> Option<&str> {
        match &self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.peer_server_name(),
            Some(ResolvedServer::Tls12(c)) => c.peer_server_name(),
            None => None,
        }
    }

    fn peer_certificates(&self) -> &[Vec<u8>] {
        match &self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.peer_certificates(),
            Some(ResolvedServer::Tls12(c)) => c.peer_certificates(),
            None => &[],
        }
    }

    fn wants_write(&self) -> bool {
        match &self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.wants_write(),
            Some(ResolvedServer::Tls12(c)) => c.wants_write(),
            None => false,
        }
    }

    fn pending_signature(&self) -> Option<(u16, Vec<u8>)> {
        // Only the TLS 1.3 server brokers an external CertificateVerify here.
        match &self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.pending_signature(),
            _ => None,
        }
    }

    fn provide_signature(&mut self, signature: Vec<u8>) -> Result<(), Error> {
        match &mut self.resolved {
            Some(ResolvedServer::Tls13(c)) => c.provide_signature(signature),
            _ => Err(Error::InappropriateState),
        }
    }
}

/// The active engine inside a [`ClientConnectionAuto`].
#[allow(clippy::large_enum_variant)]
enum ClientInner {
    Tls13(Box<super::conn::ClientConnection>),
    Tls12(Box<super::conn::ClientConnection12>),
}

/// Version-spanning TLS client front-end. Starts as a TLS 1.3 client that
/// emitted a hybrid ClientHello (offering 1.2 too). If the server's ServerHello
/// selects TLS 1.2, it builds a TLS 1.2 client that ADOPTS the already-sent
/// ClientHello and replays the buffered server flight into it. At most one
/// downgrade happens; once the version is `decided`, every call delegates
/// straight to the chosen engine.
struct ClientConnectionAuto {
    inner: ClientInner,
    /// Owned config used to build the 1.2 engine on downgrade. `Config` is
    /// immutable, so the clone never diverges.
    config: Config,
    /// The exact ClientHello handshake-message bytes the 1.3 engine emitted —
    /// used to seed the 1.2 engine's transcript on downgrade.
    sent_ch: Vec<u8>,
    /// Server bytes received before the version is decided; replayed into the
    /// 1.2 engine on downgrade so it sees the full flight from offset 0.
    recv_buffer: Vec<u8>,
    /// `true` once the negotiated version is fixed (1.3 kept, or downgraded to
    /// 1.2). Until then only the 1.3 engine is live and bytes are buffered.
    decided: bool,
}

impl ClientConnectionAuto {
    fn feed(&mut self, wire_in: &[u8]) -> Result<(), Error> {
        if self.decided {
            return match &mut self.inner {
                ClientInner::Tls13(c) => {
                    c.read_tls(wire_in);
                    c.process_new_packets()
                }
                ClientInner::Tls12(c) => {
                    c.read_tls(wire_in);
                    c.process_new_packets()
                }
            };
        }
        // Undecided: only the 1.3 engine is live. Buffer the server bytes so we
        // can replay them into a 1.2 engine if the server downgrades us.
        if self.recv_buffer.len().saturating_add(wire_in.len()) > MAX_HS_PEEK {
            return Err(Error::Decode);
        }
        self.recv_buffer.extend_from_slice(wire_in);
        let ClientInner::Tls13(c) = &mut self.inner else {
            return Err(Error::InappropriateState);
        };
        c.read_tls(wire_in);
        c.process_new_packets()?;
        if c.downgrade_requested() {
            // Server selected TLS 1.2: build a 1.2 engine adopting our sent
            // ClientHello, then replay the full buffered server flight into it.
            let mut t12 = Box::new(build_tls12_client_adopt(&self.config, &self.sent_ch)?);
            let buffered = core::mem::take(&mut self.recv_buffer);
            t12.read_tls(&buffered);
            let r = t12.process_new_packets();
            self.inner = ClientInner::Tls12(t12);
            self.decided = true;
            return r;
        }
        // The 1.3 engine fixed its suite (ServerHello processed) ⇒ committed to
        // 1.3; stop buffering.
        if c.negotiated_cipher_suite().is_some() {
            self.decided = true;
            self.recv_buffer = Vec::new();
        }
        Ok(())
    }

    fn write_tls(&mut self) -> Vec<u8> {
        match &mut self.inner {
            ClientInner::Tls13(c) => c.write_tls(),
            ClientInner::Tls12(c) => c.write_tls(),
        }
    }

    fn send_application_data(&mut self, app: &[u8]) -> Result<(), Error> {
        match &mut self.inner {
            ClientInner::Tls13(c) => c.send_application_data(app),
            ClientInner::Tls12(c) => c.send_application_data(app),
        }
    }

    fn take_received_plaintext(&mut self) -> Vec<u8> {
        match &mut self.inner {
            ClientInner::Tls13(c) => c.take_received_plaintext(),
            ClientInner::Tls12(c) => c.take_received_plaintext(),
        }
    }

    fn tls_exporter(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let ctx12 = if context.is_empty() {
            None
        } else {
            Some(context)
        };
        match &self.inner {
            ClientInner::Tls13(c) => c.tls_exporter(label, context, out),
            ClientInner::Tls12(c) => c.tls_exporter(label, ctx12, out),
        }
    }

    fn write_early_data(&mut self, data: &[u8]) -> Result<(), Error> {
        match &mut self.inner {
            ClientInner::Tls13(c) => c.write_early_data(data),
            ClientInner::Tls12(_) => Err(Error::InappropriateState),
        }
    }

    fn take_session(&mut self) -> Option<ResumptionSession> {
        match &mut self.inner {
            ClientInner::Tls13(c) => c
                .take_session()
                .map(|s| ResumptionSession(ResumptionSessionKind::Tls13(s))),
            ClientInner::Tls12(c) => c
                .take_session()
                .map(|s| ResumptionSession(ResumptionSessionKind::Tls12(s))),
        }
    }

    fn close(&mut self) {
        match &mut self.inner {
            ClientInner::Tls13(c) => c.send_close_notify(),
            ClientInner::Tls12(c) => c.send_close_notify(),
        }
    }

    fn is_handshaking(&self) -> bool {
        match &self.inner {
            ClientInner::Tls13(c) => c.is_handshaking(),
            ClientInner::Tls12(c) => c.is_handshaking(),
        }
    }

    /// `true` only once the live engine actually completed its handshake.
    fn is_handshake_complete(&self) -> bool {
        match &self.inner {
            ClientInner::Tls13(c) => c.is_handshake_complete(),
            ClientInner::Tls12(c) => c.is_handshake_complete(),
        }
    }

    fn received_close_notify(&self) -> bool {
        match &self.inner {
            ClientInner::Tls13(c) => c.received_close_notify(),
            ClientInner::Tls12(c) => c.received_close_notify(),
        }
    }

    fn negotiated_version(&self) -> Option<ProtocolVersion> {
        // Unknown until the ServerHello fixes the version.
        if !self.decided {
            return None;
        }
        match &self.inner {
            ClientInner::Tls13(_) => Some(ProtocolVersion::TLSv1_3),
            ClientInner::Tls12(c) => c.negotiated_protocol_version(),
        }
    }

    fn negotiated_cipher_suite(&self) -> Option<u16> {
        match &self.inner {
            ClientInner::Tls13(c) => c.negotiated_cipher_suite(),
            ClientInner::Tls12(c) => c.negotiated_cipher_suite(),
        }
    }

    fn alpn_protocol(&self) -> Option<&[u8]> {
        match &self.inner {
            ClientInner::Tls13(c) => c.alpn_protocol(),
            ClientInner::Tls12(c) => c.alpn_protocol(),
        }
    }

    fn peer_certificates(&self) -> &[Vec<u8>] {
        match &self.inner {
            ClientInner::Tls13(c) => c.peer_certificates(),
            ClientInner::Tls12(c) => c.peer_certificates(),
        }
    }

    fn wants_write(&self) -> bool {
        match &self.inner {
            ClientInner::Tls13(c) => c.wants_write(),
            ClientInner::Tls12(c) => c.wants_write(),
        }
    }

    fn pending_signature(&self) -> Option<(u16, Vec<u8>)> {
        // Client-side external mTLS signing is a TLS 1.3 path here.
        match &self.inner {
            ClientInner::Tls13(c) => c.pending_signature(),
            ClientInner::Tls12(_) => None,
        }
    }

    fn provide_signature(&mut self, signature: Vec<u8>) -> Result<(), Error> {
        match &mut self.inner {
            ClientInner::Tls13(c) => c.provide_signature(signature),
            ClientInner::Tls12(_) => Err(Error::InappropriateState),
        }
    }
}

impl Connection {
    /// Build a client connection. Picks the engine from `config.max_version`.
    pub fn client(config: &Config) -> Result<Self, Error> {
        config.check_versions()?;
        // When the range spans TLS 1.2 and 1.3 (e.g. the default
        // `min 1.2 / max 1.3`), the client speaks first and so must offer both
        // versions in one ClientHello and pick the engine from the ServerHello.
        // Start a 1.3 client emitting a hybrid ClientHello; it downgrades to a
        // 1.2 engine if the server selects 1.2. Pinning `min_version = TLSv1_3`
        // keeps a pure-1.3 client.
        if config.max_version == ProtocolVersion::TLSv1_3
            && config.min_version != ProtocolVersion::TLSv1_3
        {
            let t13 = build_tls13_client(config)?;
            // The hybrid ClientHello was emitted at construction; capture it to
            // seed the 1.2 engine on downgrade.
            let sent_ch = t13.sent_client_hello().to_vec();
            let inner = Engine::ClientTlsAuto(Box::new(ClientConnectionAuto {
                inner: ClientInner::Tls13(Box::new(t13)),
                config: config.clone(),
                sent_ch,
                recv_buffer: Vec::new(),
                decided: false,
            }));
            return Ok(Connection {
                inner,
                pending_dtls: alloc::collections::VecDeque::new(),
                signer: config.signer.clone(),
                active_sign: None,
            });
        }
        let inner = match config.max_version {
            ProtocolVersion::TLSv1_3 => Engine::ClientTls13(Box::new(build_tls13_client(config)?)),
            ProtocolVersion::TLSv1_2 => Engine::ClientTls12(Box::new(build_tls12_client(config)?)),
            // The TLS 1.2 engine also drives the opt-in legacy path; a caller
            // that tops out at TLS 1.0/1.1 still routes through it.
            #[cfg(feature = "tls-legacy")]
            ProtocolVersion::TLSv1_1 | ProtocolVersion::TLSv1_0 | ProtocolVersion::SSLv3 => {
                Engine::ClientTls12(Box::new(build_tls12_client(config)?))
            }
            #[cfg(feature = "dtls")]
            ProtocolVersion::DTLSv1_3 => {
                Engine::ClientDtls13(Box::new(build_dtls13_client(config)?))
            }
            #[cfg(feature = "dtls")]
            ProtocolVersion::DTLSv1_2 => {
                Engine::ClientDtls12(Box::new(build_dtls12_client(config)?))
            }
            _ => return Err(Error::UnsupportedVersion),
        };
        Ok(Connection {
            inner,
            pending_dtls: alloc::collections::VecDeque::new(),
            signer: config.signer.clone(),
            active_sign: None,
        })
    }

    /// Build a server connection. Picks the engine from `config.max_version`.
    /// Requires `config.identity.is_some()`.
    pub fn server(config: &Config) -> Result<Self, Error> {
        config.check_versions()?;
        if config.identity.is_none() {
            return Err(Error::InappropriateState);
        }
        // When the configured range spans TLS 1.2 and 1.3 (e.g. the default
        // `min 1.2 / max 1.3`), the engine cannot be chosen from config alone —
        // a 1.2-only client offers no `supported_versions`, so the version is
        // decided from the first ClientHello. Defer construction: keep an owned
        // (immutable) `Config` clone and let `ServerConnectionAuto` build the
        // ONE matching engine after peeking the ClientHello. Pinning
        // `min_version = TLSv1_3` opts back into 1.3-only.
        if config.max_version == ProtocolVersion::TLSv1_3
            && config.min_version != ProtocolVersion::TLSv1_3
        {
            let inner = Engine::ServerTlsAuto(Box::new(ServerConnectionAuto {
                buffered: Vec::new(),
                peeker: super::peek::ClientHelloPeeker::default(),
                config: Some(config.clone()),
                resolved: None,
            }));
            return Ok(Connection {
                inner,
                pending_dtls: alloc::collections::VecDeque::new(),
                signer: config.signer.clone(),
                active_sign: None,
            });
        }
        let inner = match config.max_version {
            ProtocolVersion::TLSv1_3 => Engine::ServerTls13(Box::new(build_tls13_server(config)?)),
            ProtocolVersion::TLSv1_2 => Engine::ServerTls12(Box::new(build_tls12_server(config)?)),
            #[cfg(feature = "tls-legacy")]
            ProtocolVersion::TLSv1_1 | ProtocolVersion::TLSv1_0 | ProtocolVersion::SSLv3 => {
                Engine::ServerTls12(Box::new(build_tls12_server(config)?))
            }
            #[cfg(feature = "dtls")]
            ProtocolVersion::DTLSv1_3 => {
                Engine::ServerDtls13(Box::new(build_dtls13_server(config)?))
            }
            #[cfg(feature = "dtls")]
            ProtocolVersion::DTLSv1_2 => {
                Engine::ServerDtls12(Box::new(build_dtls12_server(config)?))
            }
            _ => return Err(Error::UnsupportedVersion),
        };
        Ok(Connection {
            inner,
            pending_dtls: alloc::collections::VecDeque::new(),
            signer: config.signer.clone(),
            active_sign: None,
        })
    }

    /// Drive the handshake forward. Returns the next [`HandshakeStatus`].
    pub fn handshake(&mut self) -> Result<HandshakeStatus, Error> {
        if self.is_handshake_complete() {
            return Ok(HandshakeStatus::Complete);
        }
        // The engine closed without completing (a failed handshake, or a peer
        // alert such as an injected `close_notify`). Never report progress —
        // a caller that ignored the original error must not be able to loop
        // back in here and be told the handshake is fine.
        if self.handshake_failed() {
            return Err(Error::InappropriateState);
        }
        // Refill DTLS pending queue.
        #[cfg(feature = "dtls")]
        self.refill_dtls_pending();
        if self.wants_write() {
            Ok(HandshakeStatus::WantWrite)
        } else {
            Ok(HandshakeStatus::WantRead)
        }
    }

    /// Drive the handshake forward, transparently brokering the identity
    /// signature through the [`HandshakeSigner`](super::HandshakeSigner) installed via
    /// [`ConfigBuilder::private_key`](super::ConfigBuilder::private_key).
    ///
    /// This is the key-agnostic alternative to [`handshake`](Self::handshake):
    /// the same loop drives an in-process key, a local TPM, or a network HSM,
    /// because the signing device is folded into the returned [`Step`]. The
    /// caller services peer I/O on `WantRead`/`WantWrite` exactly as with
    /// `handshake`, and on `WantSigner` waits on the (opaque) device readiness
    /// before calling `drive` again — it never touches the message, the
    /// signature, or the device transport.
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")] {
    /// # use purecrypto::tls::{Connection, Step};
    /// # fn run(conn: &mut Connection, sock: &mut std::net::TcpStream) -> std::io::Result<()> {
    /// use std::io::{Read, Write};
    /// let mut buf = [0u8; 16 * 1024];
    /// loop {
    ///     match conn.drive().map_err(std::io::Error::other)? {
    ///         Step::WantWrite => sock.write_all(&conn.pop().map_err(std::io::Error::other)?)?,
    ///         Step::WantRead => {
    ///             let n = sock.read(&mut buf)?;
    ///             conn.feed(&buf[..n]).map_err(std::io::Error::other)?;
    ///         }
    ///         // Sync: block on the device fd. Async: register
    ///         // `r.as_raw_fd()` with your reactor and `.await` instead.
    ///         Step::WantSigner(Some(r)) => r.wait()?,
    ///         Step::WantSigner(None) => {} // no fd: just loop and re-drive
    ///         Step::Complete => break,
    ///         _ => {} // `Step` is #[non_exhaustive]
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn drive(&mut self) -> Result<Step, Error> {
        // If the engine has parked awaiting the identity signature, broker it
        // through the installed HandshakeSigner rather than asking the caller.
        if self.active_sign.is_none()
            && let Some(req) = self.signature_request()
        {
            let op = {
                let signer = self.signer.as_ref().ok_or(Error::InappropriateState)?;
                signer.start_sign(req.scheme, &req.message)?
            };
            self.active_sign = Some(op);
        }
        if self.active_sign.is_some() {
            let progress = {
                let op = self.active_sign.as_mut().expect("checked is_some");
                op.resume()?
            };
            match progress {
                super::signer::SignProgress::Pending => {
                    let readiness = self
                        .active_sign
                        .as_ref()
                        .expect("still in flight")
                        .readiness();
                    return Ok(Step::WantSigner(readiness));
                }
                super::signer::SignProgress::Done(sig) => {
                    self.active_sign = None;
                    self.provide_signature(sig)?;
                    // Fall through: provide_signature drove the engine, so the
                    // CertificateVerify + Finished records are now pending.
                }
            }
        }
        // Drain any buffered output before reporting completion. The engine
        // marks the handshake complete as soon as it *builds* its last flight
        // (e.g. the TLS 1.3 client's Finished), so `handshake()` — which checks
        // completion first — would otherwise return `Complete` with that flight
        // still in the buffer and the driver would stop without sending it,
        // leaving the peer waiting forever. Prioritising the write here makes
        // `drive` fully flush the final flight first.
        if self.wants_write() {
            #[cfg(feature = "dtls")]
            self.refill_dtls_pending();
            return Ok(Step::WantWrite);
        }
        match self.handshake()? {
            HandshakeStatus::Complete => Ok(Step::Complete),
            HandshakeStatus::WantWrite => Ok(Step::WantWrite),
            HandshakeStatus::WantRead => Ok(Step::WantRead),
        }
    }

    /// If the handshake is suspended awaiting an external `CertificateVerify`
    /// signature (an [`SigningKey::External`](super::config::SigningKey::External)
    /// identity), returns the [`SignatureRequest`] describing what to sign;
    /// otherwise `None`.
    ///
    /// Drive loop: after [`feed`](Self::feed) and draining [`pop`](Self::pop),
    /// check this **before** blocking on a peer read. When it is `Some`, sign
    /// `request.message` under `request.scheme` (on a TPM/HSM, synchronously or
    /// `.await`ed) and call [`provide_signature`](Self::provide_signature); the
    /// engine then emits the rest of its flight.
    pub fn signature_request(&self) -> Option<SignatureRequest> {
        let pending = match &self.inner {
            Engine::ServerTls13(c) => c.pending_signature(),
            Engine::ClientTls13(c) => c.pending_signature(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.pending_signature(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.pending_signature(),
            Engine::ServerTlsAuto(c) => c.pending_signature(),
            Engine::ClientTlsAuto(c) => c.pending_signature(),
            _ => None,
        };
        pending.map(|(scheme, message)| SignatureRequest { scheme, message })
    }

    /// Resumes a handshake suspended by [`signature_request`](Self::signature_request),
    /// supplying the externally-produced `CertificateVerify` signature.
    ///
    /// # Errors
    /// Returns [`Error::InappropriateState`] if the handshake is not currently
    /// awaiting an external signature.
    pub fn provide_signature(&mut self, signature: Vec<u8>) -> Result<(), Error> {
        match &mut self.inner {
            Engine::ServerTls13(c) => c.provide_signature(signature),
            Engine::ClientTls13(c) => c.provide_signature(signature),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.provide_signature(signature),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.provide_signature(signature),
            Engine::ServerTlsAuto(c) => c.provide_signature(signature),
            Engine::ClientTlsAuto(c) => c.provide_signature(signature),
            _ => Err(Error::InappropriateState),
        }
    }

    /// Wire bytes from the peer into the engine. Returns the number of
    /// bytes consumed.
    pub fn feed(&mut self, wire_in: &[u8]) -> Result<usize, Error> {
        match &mut self.inner {
            Engine::ClientTls13(c) => {
                c.read_tls(wire_in);
                c.process_new_packets()?;
            }
            Engine::ClientTls12(c) => {
                c.read_tls(wire_in);
                c.process_new_packets()?;
            }
            Engine::ServerTls13(c) => {
                c.read_tls(wire_in);
                c.process_new_packets()?;
            }
            Engine::ServerTls12(c) => {
                c.read_tls(wire_in);
                c.process_new_packets()?;
            }
            Engine::ServerTlsAuto(c) => c.feed(wire_in)?,
            Engine::ClientTlsAuto(c) => c.feed(wire_in)?,
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.feed_datagram(wire_in)?,
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.feed_datagram(wire_in)?,
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.feed_datagram(wire_in)?,
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.feed_datagram(wire_in)?,
        }
        // Eagerly pull DTLS datagrams into the buffer.
        #[cfg(feature = "dtls")]
        self.refill_dtls_pending();
        Ok(wire_in.len())
    }

    /// Wire bytes the engine wants to send to the peer. For TLS, this is a
    /// contiguous stream slice; for DTLS, this is one datagram per call.
    pub fn pop(&mut self) -> Result<Vec<u8>, Error> {
        let bytes: Vec<u8> = match &mut self.inner {
            Engine::ClientTls13(c) => c.write_tls(),
            Engine::ClientTls12(c) => c.write_tls(),
            Engine::ServerTls13(c) => c.write_tls(),
            Engine::ServerTls12(c) => c.write_tls(),
            Engine::ServerTlsAuto(c) => c.write_tls(),
            Engine::ClientTlsAuto(c) => c.write_tls(),
            #[cfg(feature = "dtls")]
            _ => {
                // Refill if buffer empty, then pop the next datagram.
                if self.pending_dtls.is_empty() {
                    let drained = match &mut self.inner {
                        #[cfg(feature = "dtls")]
                        Engine::ClientDtls12(c) => c.pop_outbound_datagrams(),
                        #[cfg(feature = "dtls")]
                        Engine::ClientDtls13(c) => c.pop_outbound_datagrams(),
                        #[cfg(feature = "dtls")]
                        Engine::ServerDtls12(c) => c.pop_outbound_datagrams(),
                        #[cfg(feature = "dtls")]
                        Engine::ServerDtls13(c) => c.pop_outbound_datagrams(),
                        _ => Vec::new(),
                    };
                    for dg in drained {
                        self.pending_dtls.push_back(dg);
                    }
                }
                self.pending_dtls.pop_front().unwrap_or_default()
            }
        };
        Ok(bytes)
    }

    /// App bytes into the engine (post-handshake).
    pub fn send(&mut self, app: &[u8]) -> Result<(), Error> {
        match &mut self.inner {
            Engine::ClientTls13(c) => c.send_application_data(app),
            Engine::ClientTls12(c) => c.send_application_data(app),
            Engine::ServerTls13(c) => c.send_application_data(app),
            Engine::ServerTls12(c) => c.send_application_data(app),
            Engine::ServerTlsAuto(c) => c.send_application_data(app),
            Engine::ClientTlsAuto(c) => c.send_application_data(app),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.send(app),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.send(app),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.send(app),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.send(app),
        }
    }

    /// App bytes out (post-handshake).
    pub fn recv(&mut self) -> Result<Vec<u8>, Error> {
        Ok(match &mut self.inner {
            Engine::ClientTls13(c) => c.take_received_plaintext(),
            Engine::ClientTls12(c) => c.take_received_plaintext(),
            Engine::ServerTls13(c) => c.take_received_plaintext(),
            Engine::ServerTls12(c) => c.take_received_plaintext(),
            Engine::ServerTlsAuto(c) => c.take_received_plaintext(),
            Engine::ClientTlsAuto(c) => c.take_received_plaintext(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.take_received(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.take_received(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.take_received(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.take_received(),
        })
    }

    /// Accepted 0-RTT early-data plaintext out (server side).
    ///
    /// Early data is **replayable by an active attacker** (RFC 8446 §8), so
    /// it is quarantined away from [`recv`](Connection::recv) — `recv` only
    /// ever returns data protected by the completed handshake. Drain the
    /// replayable bytes explicitly here and only act on them when doing so
    /// is idempotent. Returns an empty vector on client engines, on engines
    /// without 0-RTT support, when the server did not accept early data, or
    /// once the buffer has been drained.
    pub fn take_early_data(&mut self) -> Result<Vec<u8>, Error> {
        Ok(match &mut self.inner {
            Engine::ServerTls13(c) => c.take_early_data(),
            Engine::ServerTlsAuto(c) => c.take_early_data(),
            // No other engine accepts 0-RTT early data today.
            _ => Vec::new(),
        })
    }

    /// Exports keying material bound to this connection (RFC 8446 §7.5 for
    /// TLS 1.3, RFC 5705 for TLS 1.2 / DTLS). `label` and `context` namespace
    /// the output; `out` is filled with `out.len()` bytes derived from the
    /// connection's master/exporter secret. Available once the handshake has
    /// completed on every TLS and DTLS engine; an error is returned if called
    /// too early.
    pub fn tls_exporter(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        // RFC 5705 (TLS 1.2 / DTLS 1.2) distinguishes "no context" from an
        // empty context; RFC 8446 (TLS 1.3) always carries a context value.
        // Unify on `&[u8]` where empty means "no context", matching the 1.3
        // empty-context behaviour across versions.
        let ctx12 = if context.is_empty() {
            None
        } else {
            Some(context)
        };
        match &self.inner {
            Engine::ClientTls13(c) => c.tls_exporter(label, context, out),
            Engine::ClientTls12(c) => c.tls_exporter(label, ctx12, out),
            Engine::ServerTls13(c) => c.tls_exporter(label, context, out),
            Engine::ServerTls12(c) => c.tls_exporter(label, ctx12, out),
            Engine::ServerTlsAuto(c) => c.tls_exporter(label, context, out),
            Engine::ClientTlsAuto(c) => c.tls_exporter(label, context, out),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.tls_exporter(label, ctx12, out),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.tls_exporter(label, context, out),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.tls_exporter(label, ctx12, out),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.tls_exporter(label, context, out),
        }
    }

    /// Client 0-RTT: queue application `data` to be sent under the
    /// early-traffic key before `ServerHello` arrives. Valid only on a TLS 1.3
    /// client whose [`super::ConfigBuilder::resumption_session`] enabled 0-RTT
    /// (the stored session carried a non-zero `max_early_data_size`); any other
    /// engine returns [`Error::InappropriateState`]. See the 0-RTT replay
    /// caveat in the crate docs — early data is replayable.
    pub fn write_early_data(&mut self, data: &[u8]) -> Result<(), Error> {
        match &mut self.inner {
            Engine::ClientTls13(c) => c.write_early_data(data),
            Engine::ClientTlsAuto(c) => c.write_early_data(data),
            _ => Err(Error::InappropriateState),
        }
    }

    /// Client only: move out a [`ResumptionSession`] derived from a
    /// `NewSessionTicket` the server sent, for resumption on a later
    /// connection (feed it back via
    /// [`super::ConfigBuilder::resumption_session`]). Returns `None` on a
    /// server engine, or when the server issued no resumable ticket.
    pub fn take_session(&mut self) -> Option<ResumptionSession> {
        match &mut self.inner {
            Engine::ClientTls13(c) => c
                .take_session()
                .map(|s| ResumptionSession(ResumptionSessionKind::Tls13(s))),
            Engine::ClientTls12(c) => c
                .take_session()
                .map(|s| ResumptionSession(ResumptionSessionKind::Tls12(s))),
            Engine::ClientTlsAuto(c) => c.take_session(),
            _ => None,
        }
    }

    /// Close the connection, emitting a close_notify alert (RFC 8446 §6.1 /
    /// RFC 5246 §7.2.1; a protected record on DTLS). The alert is queued
    /// for [`pop`](Self::pop); nothing more can be sent afterwards, but the
    /// peer's records — its answering close_notify above all — are still
    /// read.
    pub fn close(&mut self) -> Result<(), Error> {
        match &mut self.inner {
            Engine::ClientTls13(c) => c.send_close_notify(),
            Engine::ClientTls12(c) => c.send_close_notify(),
            Engine::ServerTls13(c) => c.send_close_notify(),
            Engine::ServerTls12(c) => c.send_close_notify(),
            Engine::ServerTlsAuto(c) => c.close(),
            Engine::ClientTlsAuto(c) => c.close(),
            // The DTLS engines queue the alert as one protected record (an
            // error before the handshake completes: there are no keys to
            // protect it with, and a plaintext alert is spoofable).
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.send_close_notify()?,
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.send_close_notify()?,
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.send_close_notify()?,
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.send_close_notify()?,
        }
        Ok(())
    }

    /// True once the handshake has completed.
    pub fn is_handshake_complete(&self) -> bool {
        match &self.inner {
            // NOT `!is_handshaking()`: the engines also park in their closed
            // state when the handshake *fails* (a protocol error, or a peer
            // alert — including an injected pre-handshake `close_notify`).
            // Completion must be reported only for a handshake that really
            // finished, so an attacker cannot make an unauthenticated
            // connection look established.
            Engine::ClientTls13(c) => c.is_handshake_complete(),
            Engine::ClientTls12(c) => c.is_handshake_complete(),
            Engine::ServerTls13(c) => c.is_handshake_complete(),
            Engine::ServerTls12(c) => c.is_handshake_complete(),
            Engine::ServerTlsAuto(c) => c.is_handshake_complete(),
            Engine::ClientTlsAuto(c) => c.is_handshake_complete(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.is_handshake_complete(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.is_handshake_complete(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.is_handshake_complete(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.is_handshake_complete(),
        }
    }

    /// True when a TLS engine has closed without ever completing its
    /// handshake — i.e. the handshake failed (protocol error, or a peer alert
    /// such as an injected pre-handshake `close_notify`).
    fn handshake_failed(&self) -> bool {
        match &self.inner {
            Engine::ClientTls13(c) => !c.is_handshaking() && !c.is_handshake_complete(),
            Engine::ClientTls12(c) => !c.is_handshaking() && !c.is_handshake_complete(),
            Engine::ServerTls13(c) => !c.is_handshaking() && !c.is_handshake_complete(),
            Engine::ServerTls12(c) => !c.is_handshaking() && !c.is_handshake_complete(),
            Engine::ServerTlsAuto(c) => !c.is_handshaking() && !c.is_handshake_complete(),
            Engine::ClientTlsAuto(c) => !c.is_handshaking() && !c.is_handshake_complete(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(_)
            | Engine::ClientDtls13(_)
            | Engine::ServerDtls12(_)
            | Engine::ServerDtls13(_) => false,
        }
    }

    /// True once the peer's close_notify alert has been processed.
    ///
    /// Distinguishes a graceful TLS shutdown from an abrupt transport
    /// close: after transport EOF, `false` here means the peer (or an
    /// active attacker injecting a TCP FIN/RST) cut the stream without
    /// the RFC 8446 §6.1 / RFC 5246 §7.2.1 closure alert. Callers using
    /// EOF-delimited application framing should treat that as a
    /// truncation attack and reject the data.
    ///
    /// On DTLS the alert arrives in a protected record, so `true` here is
    /// an authenticated end of session; a datagram transport has no EOF,
    /// so `false` only means no closure alert has been seen (yet).
    pub fn received_close_notify(&self) -> bool {
        match &self.inner {
            Engine::ClientTls13(c) => c.received_close_notify(),
            Engine::ClientTls12(c) => c.received_close_notify(),
            Engine::ServerTls13(c) => c.received_close_notify(),
            Engine::ServerTls12(c) => c.received_close_notify(),
            Engine::ServerTlsAuto(c) => c.received_close_notify(),
            Engine::ClientTlsAuto(c) => c.received_close_notify(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.received_close_notify(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.received_close_notify(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.received_close_notify(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.received_close_notify(),
        }
    }

    /// The negotiated wire version, if the handshake has progressed enough
    /// to determine it.
    pub fn negotiated_version(&self) -> Option<ProtocolVersion> {
        match &self.inner {
            Engine::ClientTls13(_) | Engine::ServerTls13(_) => Some(ProtocolVersion::TLSv1_3),
            // The TLS 1.2 engine also drives the opt-in legacy versions, so it
            // reports its own negotiated version (TLS 1.0/1.1 when lowered).
            Engine::ClientTls12(c) => c.negotiated_protocol_version(),
            Engine::ServerTls12(c) => c.negotiated_protocol_version(),
            Engine::ServerTlsAuto(c) => c.negotiated_version(),
            Engine::ClientTlsAuto(c) => c.negotiated_version(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(_) | Engine::ServerDtls12(_) => Some(ProtocolVersion::DTLSv1_2),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(_) | Engine::ServerDtls13(_) => Some(ProtocolVersion::DTLSv1_3),
        }
    }

    /// IANA cipher-suite identifier of the negotiated suite. `None`
    /// until the handshake has advanced far enough to fix the suite
    /// (ServerHello processed on the client, ClientHello processed on
    /// the server).
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        match &self.inner {
            Engine::ClientTls13(c) => c.negotiated_cipher_suite(),
            Engine::ClientTls12(c) => c.negotiated_cipher_suite(),
            Engine::ServerTls13(c) => {
                // The TLS 1.3 server tracks its suite internally; the
                // existing public surface is `negotiated_suite()`-shaped
                // (Option<CipherSuite>). Defer to the same accessor.
                c.negotiated_cipher_suite()
            }
            Engine::ServerTls12(c) => c.negotiated_cipher_suite(),
            Engine::ServerTlsAuto(c) => c.negotiated_cipher_suite(),
            Engine::ClientTlsAuto(c) => c.negotiated_cipher_suite(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.negotiated_cipher_suite(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.negotiated_cipher_suite(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.negotiated_cipher_suite(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.negotiated_cipher_suite(),
        }
    }

    /// The IANA name of the negotiated cipher suite, or `None` until the
    /// suite is fixed. Returns the well-known strings for the suites
    /// purecrypto negotiates (TLS 1.3 trio + the TLS 1.2 ECDHE-AEAD
    /// set); unknown codes resolve to `"UNKNOWN"`.
    pub fn negotiated_cipher_suite_name(&self) -> Option<&'static str> {
        self.negotiated_cipher_suite().map(cipher_suite_name)
    }

    /// The negotiated ALPN protocol, if any.
    pub fn alpn_selected(&self) -> Option<&[u8]> {
        match &self.inner {
            Engine::ClientTls13(c) => c.alpn_protocol(),
            Engine::ClientTls12(c) => c.alpn_protocol(),
            Engine::ServerTls13(c) => c.alpn_protocol(),
            Engine::ServerTls12(c) => c.alpn_protocol(),
            Engine::ServerTlsAuto(c) => c.alpn_protocol(),
            Engine::ClientTlsAuto(c) => c.alpn_protocol(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.alpn_protocol(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.alpn_protocol(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.alpn_protocol(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.alpn_protocol(),
        }
    }

    /// Server-side: the SNI host_name the client offered in the ClientHello
    /// `server_name` extension (RFC 6066 §3). `None` for client engines,
    /// for DTLS engines (no SNI plumbing yet), or when the peer omitted the
    /// extension. Available once the ClientHello has been processed.
    pub fn peer_server_name(&self) -> Option<&str> {
        match &self.inner {
            Engine::ServerTls13(c) => c.peer_server_name(),
            Engine::ServerTls12(c) => c.peer_server_name(),
            Engine::ServerTlsAuto(c) => c.peer_server_name(),
            _ => None,
        }
    }

    /// Encrypted Client Hello (RFC 9849): `true` when ECH was accepted.
    ///
    /// On a client this means the server's accept confirmation matched
    /// (RFC 9849 §6.1.4) and the handshake runs on the inner ClientHello —
    /// the configured `server_name` was never sent in cleartext. On a
    /// server it means the outer ClientHello decrypted under one of the
    /// configured keys. `false` for GREASE, for a rejected ECH offer (a
    /// client then fails the handshake with [`Error::EchRejected`]), for
    /// connections without ECH, before the ServerHello, and for DTLS.
    #[cfg(feature = "ech")]
    pub fn ech_accepted(&self) -> bool {
        use super::conn::EchOutcome;
        match &self.inner {
            Engine::ClientTls13(c) => c.ech_outcome() == Some(EchOutcome::Accepted),
            Engine::ClientTlsAuto(c) => match &c.inner {
                ClientInner::Tls13(c) => c.ech_outcome() == Some(EchOutcome::Accepted),
                ClientInner::Tls12(_) => false,
            },
            Engine::ServerTls13(c) => c.ech_accepted(),
            Engine::ServerTlsAuto(c) => match &c.resolved {
                Some(ResolvedServer::Tls13(c)) => c.ech_accepted(),
                _ => false,
            },
            _ => false,
        }
    }

    /// The peer's certificate chain (leaf first, DER).
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        match &self.inner {
            Engine::ClientTls13(c) => c.peer_certificates(),
            Engine::ClientTls12(c) => c.peer_certificates(),
            Engine::ServerTls13(c) => c.peer_certificates(),
            Engine::ServerTls12(c) => c.peer_certificates(),
            Engine::ServerTlsAuto(c) => c.peer_certificates(),
            Engine::ClientTlsAuto(c) => c.peer_certificates(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.peer_certificates(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.peer_certificates(),
            // Reachable only when `dtls` is enabled (catches the DTLS variants
            // not handled above); exhaustive over the TLS variants otherwise.
            #[cfg_attr(not(feature = "dtls"), allow(unreachable_patterns))]
            _ => &[],
        }
    }

    /// The TLS 1.3 client engine, when this connection is (still) one.
    fn tls13_client(&self) -> Option<&super::conn::ClientConnection> {
        match &self.inner {
            Engine::ClientTls13(c) => Some(c),
            Engine::ClientTlsAuto(a) => match &a.inner {
                ClientInner::Tls13(c) => Some(c),
                ClientInner::Tls12(_) => None,
            },
            _ => None,
        }
    }

    fn tls13_client_mut(&mut self) -> Option<&mut super::conn::ClientConnection> {
        match &mut self.inner {
            Engine::ClientTls13(c) => Some(c),
            Engine::ClientTlsAuto(a) => match &mut a.inner {
                ClientInner::Tls13(c) => Some(c),
                ClientInner::Tls12(_) => None,
            },
            _ => None,
        }
    }

    /// The TLS 1.3 server engine, once resolved.
    fn tls13_server(&self) -> Option<&super::conn::ServerConnection<ConfigRng>> {
        match &self.inner {
            Engine::ServerTls13(c) => Some(c),
            Engine::ServerTlsAuto(a) => match &a.resolved {
                Some(ResolvedServer::Tls13(c)) => Some(c),
                _ => None,
            },
            _ => None,
        }
    }

    fn tls13_server_mut(&mut self) -> Option<&mut super::conn::ServerConnection<ConfigRng>> {
        match &mut self.inner {
            Engine::ServerTls13(c) => Some(c),
            Engine::ServerTlsAuto(a) => match &mut a.resolved {
                Some(ResolvedServer::Tls13(c)) => Some(c),
                _ => None,
            },
            _ => None,
        }
    }

    fn tls12_client(&self) -> Option<&super::conn::ClientConnection12> {
        match &self.inner {
            Engine::ClientTls12(c) => Some(c),
            Engine::ClientTlsAuto(a) => match &a.inner {
                ClientInner::Tls12(c) => Some(c),
                ClientInner::Tls13(_) => None,
            },
            _ => None,
        }
    }

    fn tls12_server(&self) -> Option<&super::conn::ServerConnection12<ConfigRng>> {
        match &self.inner {
            Engine::ServerTls12(c) => Some(c),
            Engine::ServerTlsAuto(a) => match &a.resolved {
                Some(ResolvedServer::Tls12(c)) => Some(c),
                _ => None,
            },
            _ => None,
        }
    }

    /// The key-exchange group the handshake used: the group of the
    /// ServerHello `key_share` on (D)TLS 1.3, the `ServerKeyExchange` curve
    /// on (D)TLS 1.2. `None` until the handshake has fixed it and on a
    /// resumed TLS 1.2 session (no key exchange).
    pub fn negotiated_group(&self) -> Option<NamedGroup> {
        let wire = if let Some(c) = self.tls13_client() {
            c.negotiated_group()
        } else if let Some(c) = self.tls13_server() {
            c.negotiated_group()
        } else if let Some(c) = self.tls12_client() {
            c.negotiated_group()
        } else if let Some(c) = self.tls12_server() {
            c.negotiated_group()
        } else {
            match &self.inner {
                #[cfg(feature = "dtls")]
                Engine::ClientDtls12(c) => c.negotiated_group(),
                #[cfg(feature = "dtls")]
                Engine::ClientDtls13(c) => c.negotiated_group(),
                #[cfg(feature = "dtls")]
                Engine::ServerDtls12(c) => c.negotiated_group(),
                #[cfg(feature = "dtls")]
                Engine::ServerDtls13(c) => c.negotiated_group(),
                _ => None,
            }
        };
        wire.and_then(NamedGroup::from_wire)
    }

    /// `true` when a (D)TLS 1.3 HelloRetryRequest was part of this
    /// handshake (received, on a client; sent, on a server) — RFC 8446
    /// §4.1.4. On DTLS 1.3 that is the usual case: the server's stateless
    /// cookie exchange rides on one (RFC 9147 §5.1).
    pub fn hello_retry_request_used(&self) -> bool {
        if let Some(c) = self.tls13_client() {
            c.hello_retry_request_seen()
        } else if let Some(c) = self.tls13_server() {
            c.hello_retry_request_sent()
        } else {
            match &self.inner {
                #[cfg(feature = "dtls")]
                Engine::ClientDtls13(c) => c.hello_retry_request_seen(),
                #[cfg(feature = "dtls")]
                Engine::ServerDtls13(c) => c.hello_retry_request_sent(),
                _ => false,
            }
        }
    }

    /// `true` when the handshake resumed an earlier session: a TLS 1.3
    /// PSK (RFC 8446 §2.2) or a TLS 1.2 session ticket (RFC 5077).
    pub fn resumed(&self) -> bool {
        if let Some(c) = self.tls13_client() {
            c.psk_accepted()
        } else if let Some(c) = self.tls13_server() {
            c.psk_used()
        } else if let Some(c) = self.tls12_client() {
            c.did_resume()
        } else if let Some(c) = self.tls12_server() {
            c.did_resume()
        } else {
            false
        }
    }

    /// TLS 1.3 0-RTT: `true` when the server accepted the early data this
    /// client offered, or (on a server) when this server accepted the
    /// client's — RFC 8446 §4.2.10. Early data the server rejected was
    /// never delivered; the client must resend it after the handshake.
    pub fn early_data_accepted(&self) -> bool {
        if let Some(c) = self.tls13_client() {
            c.early_data_accepted()
        } else if let Some(c) = self.tls13_server() {
            c.early_data_accepted()
        } else {
            false
        }
    }

    /// TLS 1.3 0-RTT: `true` when early data was offered on this
    /// connection — by this client, or by the peer of this server — whether
    /// or not it was then accepted (see
    /// [`early_data_accepted`](Self::early_data_accepted)).
    pub fn early_data_offered(&self) -> bool {
        if let Some(c) = self.tls13_client() {
            c.early_data_offered()
        } else if let Some(c) = self.tls13_server() {
            c.early_data_offered()
        } else {
            false
        }
    }

    /// TLS 1.3 post-handshake rekey (RFC 8446 §4.6.3): sends
    /// `KeyUpdate(update_requested)`, rolls this side's write key forward
    /// at once, and asks the peer to do the same; the peer's answering
    /// `KeyUpdate` rolls the read key. Errors with
    /// [`Error::InappropriateState`] before the handshake completes, on a
    /// TLS 1.2 connection (no such mechanism) and on QUIC (which rekeys
    /// through its Key Phase bit, RFC 9001 §6). On DTLS 1.3 (RFC 9147 §8)
    /// the write keys advance only once the peer has acknowledged the
    /// `KeyUpdate`, and a second request while one is in flight is refused.
    pub fn request_key_update(&mut self) -> Result<(), Error> {
        if let Some(c) = self.tls13_client_mut() {
            c.request_key_update()
        } else if let Some(c) = self.tls13_server_mut() {
            c.request_key_update()
        } else {
            match &mut self.inner {
                #[cfg(feature = "dtls")]
                Engine::ClientDtls13(c) => c.request_key_update(true),
                #[cfg(feature = "dtls")]
                Engine::ServerDtls13(c) => c.request_key_update(true),
                _ => Err(Error::InappropriateState),
            }
        }
    }

    /// Number of (D)TLS 1.3 `KeyUpdate` messages received from the peer so
    /// far.
    pub fn peer_key_updates(&self) -> u32 {
        if let Some(c) = self.tls13_client() {
            c.peer_key_updates()
        } else if let Some(c) = self.tls13_server() {
            c.peer_key_updates()
        } else {
            match &self.inner {
                #[cfg(feature = "dtls")]
                Engine::ClientDtls13(c) => c.peer_key_updates(),
                #[cfg(feature = "dtls")]
                Engine::ServerDtls13(c) => c.peer_key_updates(),
                _ => 0,
            }
        }
    }

    /// Number of TLS 1.3 `KeyUpdate` messages this side has sent so far:
    /// explicit [`request_key_update`](Self::request_key_update) calls,
    /// replies to the peer's `update_requested`, and the engine's automatic
    /// pre-limit rekeys alike.
    pub fn sent_key_updates(&self) -> u32 {
        if let Some(c) = self.tls13_client() {
            c.sent_key_updates()
        } else if let Some(c) = self.tls13_server() {
            c.sent_key_updates()
        } else {
            match &self.inner {
                #[cfg(feature = "dtls")]
                Engine::ClientDtls13(c) => c.sent_key_updates(),
                #[cfg(feature = "dtls")]
                Engine::ServerDtls13(c) => c.sent_key_updates(),
                _ => 0,
            }
        }
    }

    /// RFC 7250: `true` when the peer authenticated with a raw public key
    /// (a bare `SubjectPublicKeyInfo`) rather than an X.509 chain — the
    /// negotiated `server_certificate_type` on a client, the negotiated
    /// `client_certificate_type` on a server. `false` when the peer sent
    /// X.509, sent nothing (a resumed handshake, an anonymous client) or
    /// on TLS 1.2 / DTLS.
    pub fn peer_raw_public_key(&self) -> bool {
        const RAW_PUBLIC_KEY: u8 = super::codec::cert_type::RAW_PUBLIC_KEY;
        if let Some(c) = self.tls13_client() {
            c.negotiated_server_cert_type() == RAW_PUBLIC_KEY && !c.peer_certificates().is_empty()
        } else if let Some(c) = self.tls13_server() {
            c.negotiated_client_cert_type() == RAW_PUBLIC_KEY && !c.peer_certificates().is_empty()
        } else {
            false
        }
    }

    /// RFC 7250: `true` when this side's own identity went out as a raw
    /// public key (a client's mTLS identity, a server's identity) rather
    /// than an X.509 chain.
    pub fn own_raw_public_key(&self) -> bool {
        const RAW_PUBLIC_KEY: u8 = super::codec::cert_type::RAW_PUBLIC_KEY;
        if let Some(c) = self.tls13_client() {
            c.negotiated_client_cert_type() == RAW_PUBLIC_KEY
        } else if let Some(c) = self.tls13_server() {
            c.negotiated_server_cert_type() == RAW_PUBLIC_KEY
        } else {
            false
        }
    }

    /// RFC 8879: the `CertificateCompressionAlgorithm` codepoint the peer
    /// compressed its `Certificate` with (`1` = zlib), or `None` when it
    /// arrived uncompressed. Only a TLS 1.3 client receives compressed
    /// certificates today.
    #[cfg(feature = "cert-compression")]
    pub fn peer_cert_compression(&self) -> Option<u16> {
        self.tls13_client().and_then(|c| c.peer_cert_compression())
    }

    /// RFC 8879: the `CertificateCompressionAlgorithm` codepoint this side
    /// compressed its own `Certificate` with, or `None` when it went out
    /// uncompressed. Only a TLS 1.3 server compresses today.
    #[cfg(feature = "cert-compression")]
    pub fn own_cert_compression(&self) -> Option<u16> {
        self.tls13_server().and_then(|c| c.own_cert_compression())
    }

    /// Client: the DER `OCSPResponse` the server stapled (RFC 6066 §8 /
    /// RFC 6960), when it did. TLS 1.3 only.
    pub fn peer_ocsp_response(&self) -> Option<&[u8]> {
        self.tls13_client().and_then(|c| c.peer_ocsp_response())
    }

    /// RFC 8449: `true` when both sides sent `record_size_limit`, so the
    /// negotiated limits bind this connection. TLS 1.3 only.
    pub fn record_size_limit_negotiated(&self) -> bool {
        if let Some(c) = self.tls13_client() {
            c.record_size_limit_negotiated()
        } else if let Some(c) = self.tls13_server() {
            c.record_size_limit_negotiated()
        } else {
            false
        }
    }

    /// DTLS: next retransmit timeout. None on TLS variants.
    pub fn next_timeout(&self) -> Option<Duration> {
        match &self.inner {
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.next_timeout(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.next_timeout(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.next_timeout(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.next_timeout(),
            _ => None,
        }
    }

    /// DTLS: notify the engine that the retransmit deadline has elapsed.
    /// No-op on TLS variants.
    #[cfg_attr(not(feature = "dtls"), allow(unused_variables))]
    pub fn on_timeout(&mut self, now: Duration) {
        match &mut self.inner {
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.on_timeout(now),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.on_timeout(now),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.on_timeout(now),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.on_timeout(now),
            _ => {}
        }
    }

    fn wants_write(&self) -> bool {
        match &self.inner {
            Engine::ClientTls13(c) => c.wants_write(),
            Engine::ClientTls12(c) => c.wants_write(),
            Engine::ServerTls13(c) => c.wants_write(),
            Engine::ServerTls12(c) => c.wants_write(),
            Engine::ServerTlsAuto(c) => c.wants_write(),
            Engine::ClientTlsAuto(c) => c.wants_write(),
            // DTLS: any pending datagram counts as wanting-write.
            #[cfg(feature = "dtls")]
            _ => !self.pending_dtls.is_empty(),
        }
    }

    /// Drain new outbound datagrams from the DTLS engine into the pending
    /// buffer. No-op for TLS variants.
    #[cfg(feature = "dtls")]
    fn refill_dtls_pending(&mut self) {
        let drained: Vec<Vec<u8>> = match &mut self.inner {
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(c) => c.pop_outbound_datagrams(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls13(c) => c.pop_outbound_datagrams(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls12(c) => c.pop_outbound_datagrams(),
            #[cfg(feature = "dtls")]
            Engine::ServerDtls13(c) => c.pop_outbound_datagrams(),
            _ => return,
        };
        for dg in drained {
            self.pending_dtls.push_back(dg);
        }
    }
}

/// Maps an IANA cipher-suite wire code to its registered name. Covers
/// every suite this crate negotiates; unknown codes resolve to
/// `"UNKNOWN"` so the function is total.
fn cipher_suite_name(id: u16) -> &'static str {
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        // Opt-in legacy CBC suites (tls-legacy).
        0x000A => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0xC012 => "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xC027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xC028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA256",
        _ => "UNKNOWN",
    }
}

// ---- Engine builders --------------------------------------------------------
//
// Each builder translates the shared `Config` into one engine's own config
// type. To keep them from drifting apart, every builder consumes the option
// groups of `Config::parts` (see `super::opts`) by destructuring them WITHOUT
// `..`: a field added to `Config` is a compile error in each builder until it
// is forwarded, refused (fail closed), or explicitly marked inert with a
// `let _ = field;` and a reason. The TLS 1.3 translation is shared with the
// QUIC adapters in `crate::quic::connection` through `tls13_client_config` /
// `tls13_server_config`, so the two cannot diverge.

/// The client's intended server name, used for SNI and (when enabled) hostname
/// verification. A name is **required only when `verify_certificates` is on** —
/// without it there is nothing to check the peer certificate against, so a
/// missing name is a misconfiguration. With verification off (e.g. connecting to
/// a device by IP), the name is optional; an empty string means "no SNI, no
/// hostname check", which the engines honour by omitting the SNI extension.
fn client_server_name(cfg: &Config) -> Result<&str, Error> {
    resolve_server_name(cfg.server_name.as_deref(), cfg.verify_certificates)
}

/// [`client_server_name`] over the already-split `ClientOpts` values.
fn resolve_server_name(
    server_name: Option<&str>,
    verify_certificates: bool,
) -> Result<&str, Error> {
    match server_name {
        Some(name) => Ok(name),
        None if !verify_certificates => Ok(""),
        None => Err(Error::MissingServerName),
    }
}

/// Which transport a TLS 1.3 engine config is being built for.
///
/// QUIC (RFC 9001) carries the TLS 1.3 handshake without TLS records and
/// pins the version, so the record-layer options and the version range do
/// not apply there; the QUIC adapter also owns 0-RTT sizing and resumption.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tls13Transport {
    /// A stream transport (TCP): the TLS record layer is in use.
    Tls,
    /// QUIC: no record layer, TLS 1.3 only.
    Quic,
}

/// Translates `cfg` into the TLS 1.3 client engine's config. Shared by
/// [`build_tls13_client`] and the QUIC client adapter; `quic_session` is the
/// QUIC caller's stored session (QUIC resumes from
/// `QuicConfig::resumption`, which carries the transport parameters the
/// ticket was issued under, not from `Config::resumption`).
pub(crate) fn tls13_client_config(
    cfg: &Config,
    transport: Tls13Transport,
    quic_session: Option<super::conn::StoredSession>,
) -> Result<super::conn::ClientConfig, Error> {
    let parts = cfg.parts();
    let CommonOpts {
        min_version,
        max_version,
        identity,
        roots,
        crls,
        signature_policy,
        verification_time,
        alpn_protocols,
        record_size_limit,
        cipher_suites,
        key_exchange_groups,
        require_extended_master_secret,
        server_cert_type_preference,
        client_cert_type_preference,
        raw_public_key_spki,
        #[cfg(feature = "cert-compression")]
        cert_compression_algorithms,
        key_log,
        rng,
        signer,
    } = parts.common;
    let ClientOpts {
        server_name,
        verify_certificates,
        key_shares,
        expected_raw_public_keys,
        #[cfg(feature = "ech")]
        ech,
        resumption,
    } = parts.client;
    // Inert here: `max_version` chose this engine; EMS (RFC 7627) is a TLS
    // 1.2 mechanism; `rng` is drawn through `config_rng` and `signer` through
    // `Connection::drive`; the caller resolves `server_name` (see
    // `client_server_name` / `QuicConnection::client`).
    let _ = (
        max_version,
        require_extended_master_secret,
        rng,
        signer,
        server_name,
    );

    let mut cc = super::conn::ClientConfig::new(roots.clone_store());
    cc.verify_certificates = verify_certificates;
    if let Some(groups) = key_shares {
        cc.key_share_groups = groups.iter().map(|g| g.to_wire()).collect();
    }
    if let Some(groups) = key_exchange_groups {
        // Fail closed on an empty restriction (see `Config::key_exchange_groups`).
        if groups.is_empty() {
            return Err(Error::HandshakeFailure);
        }
        cc.groups = groups.iter().map(|g| g.to_wire()).collect();
    }
    match transport {
        Tls13Transport::Tls => {
            cc.cipher_suites = cipher_suites.map(<[u16]>::to_vec);
            // Offer TLS 1.2 alongside 1.3 when the configured range spans down
            // to 1.2 — so a 1.2-only server can negotiate and the engine can
            // downgrade, whatever session is stored. Pinned `min == 1.3` keeps
            // a pure 1.3 ClientHello. A stored 1.3 session rides as a PSK
            // offer next to the 1.2 suites; a stored 1.2 session presents its
            // ticket, and the downgraded engine picks the rest of it up
            // through `tls12_client_config`.
            cc.offer_tls12 = min_version != ProtocolVersion::TLSv1_3;
            if cc.offer_tls12
                && let Some(ResumptionSession(ResumptionSessionKind::Tls12(s))) = resumption
            {
                cc.tls12_session = Some(s.clone());
            }
            if let Some(rsl) = record_size_limit {
                cc = cc.with_record_size_limit(rsl);
            }
        }
        Tls13Transport::Quic => {
            // QUIC v1 is TLS 1.3 only (`offer_tls12` stays off and
            // `min_version` is moot) and has no record layer, so RFC 8449
            // does not apply. The suite restriction is forwarded: the QUIC
            // client narrows its GCM / ChaCha20 offer by it (RFC 9001 §5.3
            // rules the CCM suites out, so those entries are dropped) — see
            // `crate::quic::client::offered_cipher_suites`.
            cc.cipher_suites = cipher_suites.map(<[u16]>::to_vec);
            let _ = (min_version, record_size_limit);
        }
    }
    if !alpn_protocols.is_empty() {
        cc = cc.with_alpn(alpn_protocols.to_vec());
    }
    if !crls.is_empty() {
        cc = cc.with_crls(crls.clone_store());
    }
    if let Some(t) = verification_time {
        cc.verification_time = Some(t.clone());
    }
    cc = cc.with_signature_policy(signature_policy.clone());
    if let Some(id) = identity
        && let Some(c) = client_cert_from_signing(id)
    {
        cc = cc.with_client_cert(c);
    }
    cc = cc.with_server_cert_type_preference(server_cert_type_preference.to_vec());
    cc = cc.with_client_cert_type_preference(client_cert_type_preference.to_vec());
    for spki in expected_raw_public_keys {
        cc = cc.add_expected_raw_public_key(spki.clone());
    }
    if let Some(spki) = raw_public_key_spki {
        cc = cc.with_client_raw_public_key_spki(spki.to_vec());
    }
    cc.key_log = key_log.clone();
    // ECH and certificate compression are TLS 1.3 handshake features that
    // apply to QUIC unchanged (ECH is how HTTP/3 hides its SNI).
    #[cfg(feature = "ech")]
    {
        cc.ech = ech.clone();
    }
    #[cfg(feature = "cert-compression")]
    {
        cc = cc.with_cert_compression_algorithms(cert_compression_algorithms.to_vec());
    }
    match transport {
        // Prime PSK resumption from a stored TLS 1.3 session, if one was
        // supplied (a 1.2 session here is simply ignored — version mismatch).
        Tls13Transport::Tls => {
            if let Some(ResumptionSession(ResumptionSessionKind::Tls13(s))) = resumption {
                cc = cc.with_session(s.clone());
            }
        }
        Tls13Transport::Quic => {
            let _ = resumption;
            if let Some(s) = quic_session {
                cc = cc.with_session(s);
            }
        }
    }
    Ok(cc)
}

fn build_tls13_client(cfg: &Config) -> Result<super::conn::ClientConnection, Error> {
    let cc = tls13_client_config(cfg, Tls13Transport::Tls, None)?;
    let server_name = client_server_name(cfg)?;
    super::conn::ClientConnection::new(cc, server_name, &mut config_rng(cfg)?)
}

/// Assembles the per-engine TLS 1.2 client config from the public `Config`.
/// Shared by [`build_tls12_client`] (fresh handshake) and
/// [`build_tls12_client_adopt`] (version-spanning downgrade).
fn tls12_client_config(cfg: &Config) -> Result<super::conn::ClientConfig12, Error> {
    let parts = cfg.parts();
    let CommonOpts {
        min_version,
        max_version,
        identity,
        roots,
        crls,
        signature_policy,
        verification_time,
        alpn_protocols,
        record_size_limit,
        cipher_suites,
        key_exchange_groups,
        require_extended_master_secret,
        server_cert_type_preference,
        client_cert_type_preference,
        raw_public_key_spki,
        #[cfg(feature = "cert-compression")]
        cert_compression_algorithms,
        key_log,
        rng,
        signer,
    } = parts.common;
    let ClientOpts {
        server_name,
        verify_certificates,
        key_shares,
        expected_raw_public_keys,
        #[cfg(feature = "ech")]
        ech,
        resumption,
    } = parts.client;
    // Inert on the TLS 1.2 engine: RFC 8879 certificate compression and ECH
    // are TLS 1.3 features (see the `Config` field docs); `rng` is drawn
    // through `config_rng`, `signer` through `Connection::drive`, and the
    // caller resolves `server_name`.
    // TLS 1.2 has no key shares (its ECDHE group is picked by the server
    // from `supported_groups`).
    let _ = (rng, signer, server_name, key_shares, key_exchange_groups);
    #[cfg(feature = "cert-compression")]
    let _ = cert_compression_algorithms;
    #[cfg(feature = "ech")]
    let _ = ech;
    #[cfg(not(feature = "tls-legacy"))]
    let _ = (min_version, max_version);

    let mut cc = super::conn::ClientConfig12::new(roots.clone_store());
    cc.verify_certificates = verify_certificates;
    cc.cipher_suites = cipher_suites.map(<[u16]>::to_vec);
    if !alpn_protocols.is_empty() {
        cc = cc.with_alpn(alpn_protocols.to_vec());
    }
    if !crls.is_empty() {
        cc = cc.with_crls(crls.clone_store());
    }
    if let Some(t) = verification_time {
        cc = cc.with_verification_time(t.clone());
    }
    if let Some(rsl) = record_size_limit {
        cc = cc.with_record_size_limit(rsl);
    }
    cc = cc.with_signature_policy(signature_policy.clone());
    cc = cc.with_require_ems(require_extended_master_secret);
    if let Some(id) = identity
        && let Some(c) = client_cert_from_signing(id)
    {
        cc = cc.with_client_cert(c);
    }
    // RFC 7250 raw public keys, forwarded exactly as to the TLS 1.3 engine so
    // a version-spanning handshake authenticates the peer the same way
    // whichever version is negotiated.
    cc = cc.with_server_cert_type_preference(server_cert_type_preference.to_vec());
    cc = cc.with_client_cert_type_preference(client_cert_type_preference.to_vec());
    for spki in expected_raw_public_keys {
        cc = cc.add_expected_raw_public_key(spki.clone());
    }
    if let Some(spki) = raw_public_key_spki {
        cc = cc.with_client_raw_public_key_spki(spki.to_vec());
    }
    cc.key_log = key_log.clone();
    #[cfg(feature = "tls-legacy")]
    {
        cc = cc.with_min_version(min_version);
        // The 1.2 engine caps at TLS 1.2; only propagate a lower max so a
        // legacy-only caller offers `legacy_version` ≤ 1.1 and no AEAD suites.
        if max_version.as_u16() < ProtocolVersion::TLSv1_2.as_u16() {
            cc = cc.with_max_version(max_version);
        }
    }
    // Prime RFC 5077 ticket resumption from a stored TLS 1.2 session, if one
    // was supplied (a 1.3 session here is simply ignored — version mismatch).
    if let Some(ResumptionSession(ResumptionSessionKind::Tls12(s))) = resumption {
        cc = cc.with_session(s.clone());
    }
    Ok(cc)
}

/// Builds a TLS 1.2 client that adopts an already-sent (hybrid) ClientHello —
/// the downgrade target of [`ClientConnectionAuto`]. No new ClientHello is
/// emitted; the engine resumes at `WaitServerHello` with the transcript seeded
/// by `sent_ch`.
fn build_tls12_client_adopt(
    cfg: &Config,
    sent_ch: &[u8],
) -> Result<super::conn::ClientConnection12, Error> {
    let cc = tls12_client_config(cfg)?;
    let server_name = client_server_name(cfg)?;
    super::conn::ClientConnection12::adopt_sent_client_hello(
        cc,
        server_name,
        sent_ch,
        &mut config_rng(cfg)?,
    )
}

fn build_tls12_client(cfg: &Config) -> Result<super::conn::ClientConnection12, Error> {
    let cc = tls12_client_config(cfg)?;
    let server_name = client_server_name(cfg)?;
    super::conn::ClientConnection12::new(cc, server_name, &mut config_rng(cfg)?)
}

/// The TLS 1.3 server engine config for `id`'s chain and signing key.
fn tls13_server_config_from_identity(id: &super::config::Identity) -> super::conn::ServerConfig {
    let chain = id.cert_chain.clone();
    match &id.key {
        super::config::SigningKey::Rsa(k) => super::conn::ServerConfig::with_rsa(chain, k.clone()),
        super::config::SigningKey::Ecdsa(k) => {
            super::conn::ServerConfig::with_ecdsa(chain, k.clone())
        }
        super::config::SigningKey::Ed25519(k) => {
            super::conn::ServerConfig::with_ed25519(chain, k.clone())
        }
        super::config::SigningKey::Ed448(k) => {
            super::conn::ServerConfig::with_ed448(chain, k.clone())
        }
        #[cfg(feature = "mldsa")]
        super::config::SigningKey::MlDsa44(k) => {
            super::conn::ServerConfig::with_mldsa44(chain, k.clone())
        }
        #[cfg(feature = "mldsa")]
        super::config::SigningKey::MlDsa65(k) => {
            super::conn::ServerConfig::with_mldsa65(chain, k.clone())
        }
        #[cfg(feature = "mldsa")]
        super::config::SigningKey::MlDsa87(k) => {
            super::conn::ServerConfig::with_mldsa87(chain, k.clone())
        }
        super::config::SigningKey::External { schemes } => {
            super::conn::ServerConfig::with_external(chain, schemes.clone())
        }
    }
}

/// Translates `cfg` into the TLS 1.3 server engine's config. Shared by
/// [`build_tls13_server`] and the QUIC server adapter.
pub(crate) fn tls13_server_config(
    cfg: &Config,
    transport: Tls13Transport,
) -> Result<super::conn::ServerConfig, Error> {
    let parts = cfg.parts();
    let CommonOpts {
        min_version,
        max_version,
        identity,
        roots,
        crls,
        signature_policy,
        verification_time,
        alpn_protocols,
        record_size_limit,
        cipher_suites,
        key_exchange_groups,
        require_extended_master_secret,
        server_cert_type_preference,
        client_cert_type_preference,
        raw_public_key_spki,
        #[cfg(feature = "cert-compression")]
        cert_compression_algorithms,
        key_log,
        rng,
        signer,
    } = parts.common;
    let ServerOpts {
        client_auth,
        stapled_crl,
        stapled_ocsp_response,
        ticket_key,
        max_early_data_size,
        #[cfg(feature = "std")]
        replay_window,
        expected_client_raw_public_keys,
        preferred_key_exchange_group,
        #[cfg(feature = "ech")]
        ech_server,
    } = parts.server;
    // Inert here: the version pair chose this engine; EMS is TLS 1.2 only;
    // a server's trust anchors for mTLS come from `client_auth`, not `roots`;
    // `rng` is drawn through `config_rng` and `signer` through
    // `Connection::drive`.
    let _ = (
        min_version,
        max_version,
        require_extended_master_secret,
        roots,
        rng,
        signer,
    );

    let id = identity.ok_or(Error::InappropriateState)?;
    if transport == Tls13Transport::Quic
        && matches!(id.key, super::config::SigningKey::External { .. })
    {
        // External (suspend/resume) signing is not wired through the QUIC
        // driver — the QUIC connection has no `provide_signature` resume path
        // — so reject it at construction rather than stalling the handshake.
        return Err(Error::InappropriateState);
    }
    let mut sc = tls13_server_config_from_identity(id);
    if !alpn_protocols.is_empty() {
        sc = sc.with_alpn(alpn_protocols.to_vec());
    }
    if !crls.is_empty() {
        sc = sc.with_crls(crls.clone_store());
    }
    if let Some(ca) = client_auth {
        sc = sc.with_client_auth(ca.roots.clone_store(), ca.required);
    }
    if let Some(tk) = ticket_key {
        sc = sc.with_ticket_key(*tk.as_bytes());
    }
    match transport {
        Tls13Transport::Tls => {
            if let Some(rsl) = record_size_limit {
                sc = sc.with_record_size_limit(rsl);
            }
            if max_early_data_size > 0 {
                sc = sc.with_max_early_data(max_early_data_size);
            }
            #[cfg(feature = "std")]
            if let Some(rw) = replay_window {
                sc = sc.with_replay_window(rw.clone());
            }
        }
        Tls13Transport::Quic => {
            // No record layer, so RFC 8449 does not apply. RFC 9001 §4.6.1
            // fixes the advertised early-data size at 0xffffffff, and the
            // QUIC adapter sets it — together with the replay window — only
            // when `QuicConfig::enable_early_data` opts in.
            let _ = (record_size_limit, max_early_data_size);
            #[cfg(feature = "std")]
            let _ = replay_window;
        }
    }
    if let Some(crl) = stapled_crl {
        sc = sc.with_stapled_crl(crl.to_vec());
    }
    if let Some(ocsp) = stapled_ocsp_response {
        sc = sc.with_stapled_ocsp_response(ocsp.to_vec());
    }
    sc = sc.with_server_cert_type_preference(server_cert_type_preference.to_vec());
    sc = sc.with_client_cert_type_preference(client_cert_type_preference.to_vec());
    if let Some(spki) = raw_public_key_spki {
        sc = sc.with_raw_public_key_spki(spki.to_vec());
    }
    for spki in expected_client_raw_public_keys {
        sc = sc.add_expected_client_raw_public_key(spki.clone());
    }
    sc = sc.with_signature_policy(signature_policy.clone());
    #[cfg(feature = "cert-compression")]
    {
        sc = sc.with_cert_compression_algorithms(cert_compression_algorithms.to_vec());
    }
    #[cfg(feature = "ech")]
    if let Some(ech) = ech_server.clone() {
        sc = sc.with_ech_server(ech);
    }
    if let Some(g) = preferred_key_exchange_group {
        sc = sc.with_preferred_key_exchange_group(g);
    }
    if let Some(groups) = key_exchange_groups {
        // Fail closed on a restriction naming nothing the engine implements
        // (see `Config::key_exchange_groups`); every public `NamedGroup` is
        // implemented, so only the empty list can trip this.
        if groups.is_empty() {
            return Err(Error::HandshakeFailure);
        }
        sc = sc.with_groups(groups.iter().map(|g| g.to_wire()).collect());
    }
    if let Some(list) = cipher_suites {
        // The server's accept-set and preference order (see
        // `Config::cipher_suites`); fail closed like the client when nothing
        // usable is left, rather than widening back to the full set.
        let supported: Vec<super::codec::CipherSuite> = super::crypto::supported_suites()
            .iter()
            .map(|s| s.suite)
            .collect();
        sc = sc.with_cipher_suites(super::conn::select_offered_suites(
            &Some(list.to_vec()),
            &supported,
        )?);
    }
    if let Some(t) = verification_time {
        sc = sc.with_verification_time(t.clone());
    }
    sc.key_log = key_log.clone();
    Ok(sc)
}

fn build_tls13_server(cfg: &Config) -> Result<super::conn::ServerConnection<ConfigRng>, Error> {
    let sc = tls13_server_config(cfg, Tls13Transport::Tls)?;
    Ok(super::conn::ServerConnection::new(sc, config_rng(cfg)?))
}

fn build_tls12_server(cfg: &Config) -> Result<super::conn::ServerConnection12<ConfigRng>, Error> {
    let parts = cfg.parts();
    let CommonOpts {
        min_version,
        max_version,
        identity,
        roots,
        crls,
        signature_policy,
        verification_time,
        alpn_protocols,
        record_size_limit,
        cipher_suites,
        key_exchange_groups,
        require_extended_master_secret,
        server_cert_type_preference,
        client_cert_type_preference,
        raw_public_key_spki,
        #[cfg(feature = "cert-compression")]
        cert_compression_algorithms,
        key_log,
        rng,
        signer,
    } = parts.common;
    let ServerOpts {
        client_auth,
        stapled_crl,
        stapled_ocsp_response,
        ticket_key,
        max_early_data_size,
        #[cfg(feature = "std")]
        replay_window,
        expected_client_raw_public_keys,
        preferred_key_exchange_group,
        #[cfg(feature = "ech")]
        ech_server,
    } = parts.server;
    // Inert on the TLS 1.2 engine (see the `Config` field docs): a server's
    // trust anchors for mTLS come from `client_auth`; there is no per-cert
    // extension slot for a stapled CRL, no 0-RTT, no RFC 8879 compression,
    // no ECH and no HelloRetryRequest group preference (the 1.2 engine
    // negotiates from its own fixed group list and picks its suite from its
    // own fixed order). `rng` is drawn through `config_rng`, `signer`
    // through `Connection::drive`.
    let _ = (
        roots,
        stapled_crl,
        max_early_data_size,
        preferred_key_exchange_group,
        key_exchange_groups,
        cipher_suites,
        rng,
        signer,
    );
    #[cfg(feature = "std")]
    let _ = replay_window;
    #[cfg(feature = "cert-compression")]
    let _ = cert_compression_algorithms;
    #[cfg(feature = "ech")]
    let _ = ech_server;
    #[cfg(not(feature = "tls-legacy"))]
    let _ = min_version;

    let id = identity.ok_or(Error::InappropriateState)?;
    let chain = id.cert_chain.clone();
    let mut sc = id
        .key
        .try_into_server_config_12(chain)
        .ok_or(Error::UnsupportedVersion)?;
    // RFC 8446 §4.1.3 downgrade sentinel: only set it when this deployment is
    // actually TLS-1.3-capable (a version-spanning server). A pinned `max=1.2`
    // server must not, or 1.3-capable clients would abort.
    sc = sc.with_supports_tls13(max_version == ProtocolVersion::TLSv1_3);
    if !alpn_protocols.is_empty() {
        sc = sc.with_alpn(alpn_protocols.to_vec());
    }
    if !crls.is_empty() {
        sc = sc.with_crls(crls.clone_store());
    }
    if let Some(rsl) = record_size_limit {
        sc = sc.with_record_size_limit(rsl);
    }
    if let Some(ca) = client_auth {
        sc = sc.with_client_auth(ca.roots.clone_store(), ca.required);
    }
    if let Some(tk) = ticket_key {
        sc = sc.with_ticket_key(*tk.as_bytes());
    }
    if let Some(ocsp) = stapled_ocsp_response {
        sc = sc.with_stapled_ocsp_response(ocsp.to_vec());
    }
    sc = sc.with_signature_policy(signature_policy.clone());
    sc = sc.with_require_ems(require_extended_master_secret);
    if let Some(t) = verification_time {
        sc = sc.with_verification_time(t.clone());
    }
    // RFC 7250 raw public keys, forwarded exactly as to the TLS 1.3 engine.
    sc = sc.with_server_cert_type_preference(server_cert_type_preference.to_vec());
    sc = sc.with_client_cert_type_preference(client_cert_type_preference.to_vec());
    if let Some(spki) = raw_public_key_spki {
        sc = sc.with_raw_public_key_spki(spki.to_vec());
    }
    for spki in expected_client_raw_public_keys {
        sc = sc.add_expected_client_raw_public_key(spki.clone());
    }
    sc.key_log = key_log.clone();
    #[cfg(feature = "tls-legacy")]
    {
        sc = sc.with_min_version(min_version);
    }
    Ok(super::conn::ServerConnection12::new(sc, config_rng(cfg)?))
}

/// The `Config` options a DTLS client engine consumes, checked once for both
/// DTLS versions by [`dtls_client_opts`].
#[cfg(feature = "dtls")]
struct DtlsClientOpts<'a> {
    roots: &'a super::pki::RootCertStore,
    server_name: &'a str,
    verify_certificates: bool,
    crls: &'a super::pki::CrlStore,
    verification_time: Option<&'a crate::x509::Time>,
    signature_policy: &'a crate::signature_registry::SignaturePolicy,
    key_log: &'a Option<alloc::sync::Arc<dyn super::keylog::KeyLog>>,
    cipher_suites: Option<&'a [u16]>,
    alpn_protocols: &'a [Vec<u8>],
    require_extended_master_secret: bool,
    max_record_size: usize,
    key_exchange_groups: Option<&'a [NamedGroup]>,
    key_shares: Option<&'a [NamedGroup]>,
}

/// Takes `cfg` apart for a DTLS client and refuses, with
/// [`Error::InappropriateState`], any option the DTLS engines cannot honour
/// where ignoring it would weaken what the caller asked for: ECH (the server
/// name would go out in the clear), a client identity (the client would
/// connect anonymously — the DTLS engines never send a `Certificate`), a
/// `record_size_limit` (RFC 8449 is not implemented over DTLS), and RFC 7250
/// raw public keys (a pinned raw key with `verify_certificates` off would
/// leave the peer entirely unauthenticated). This mirrors the fail-closed
/// posture of the cookie and client-auth checks in the server builders.
#[cfg(feature = "dtls")]
fn dtls_client_opts(cfg: &Config) -> Result<DtlsClientOpts<'_>, Error> {
    let parts = cfg.parts();
    let CommonOpts {
        min_version,
        max_version,
        identity,
        roots,
        crls,
        signature_policy,
        verification_time,
        alpn_protocols,
        record_size_limit,
        cipher_suites,
        key_exchange_groups,
        require_extended_master_secret,
        server_cert_type_preference,
        client_cert_type_preference,
        raw_public_key_spki,
        #[cfg(feature = "cert-compression")]
        cert_compression_algorithms,
        key_log,
        rng,
        signer,
    } = parts.common;
    let ClientOpts {
        server_name,
        verify_certificates,
        key_shares,
        expected_raw_public_keys,
        #[cfg(feature = "ech")]
        ech,
        resumption,
    } = parts.client;
    let DtlsOpts {
        cookie_secret,
        previous_cookie_secret,
        require_cookie,
        max_record_size,
        peer_address,
    } = parts.dtls;
    // Inert on a DTLS client: the version pair chose the engine; the cookie
    // knobs and the peer address are server-side; `rng` is drawn through
    // `config_rng` and `signer` through `Connection::drive` (a signer without
    // an identity is impossible — `ConfigBuilder::private_key` sets both, and
    // an identity is refused below); a stored session is always a TLS one
    // (the DTLS servers issue no tickets), so `resumption` never matches —
    // the documented "wrong version is ignored" rule. RFC 8879 certificate
    // compression is not implemented over DTLS: the advertisement is not
    // sent, and the peer's certificate arrives uncompressed.
    let _ = (
        min_version,
        max_version,
        cookie_secret,
        previous_cookie_secret,
        require_cookie,
        peer_address,
        rng,
        signer,
        resumption,
    );
    #[cfg(feature = "cert-compression")]
    let _ = cert_compression_algorithms;

    // Fail closed (see the doc comment above).
    #[cfg(feature = "ech")]
    if ech.is_some() {
        return Err(Error::InappropriateState);
    }
    if identity.is_some() || record_size_limit.is_some() {
        return Err(Error::InappropriateState);
    }
    if server_cert_type_preference != [0]
        || client_cert_type_preference != [0]
        || raw_public_key_spki.is_some()
        || !expected_raw_public_keys.is_empty()
    {
        return Err(Error::InappropriateState);
    }
    let server_name = resolve_server_name(server_name, verify_certificates)?;
    Ok(DtlsClientOpts {
        roots,
        server_name,
        verify_certificates,
        crls,
        verification_time,
        signature_policy,
        key_log,
        cipher_suites,
        alpn_protocols,
        require_extended_master_secret,
        max_record_size,
        key_exchange_groups,
        key_shares,
    })
}

/// Applies a [`Config::key_exchange_groups`] restriction to a DTLS
/// engine's group list: keeps the groups the engine implements that the
/// caller listed, in the caller's order, and fails closed with
/// [`Error::HandshakeFailure`] when nothing is left (an empty list, or one
/// naming only groups this engine lacks — the DTLS 1.2 engines have no
/// ML-KEM hybrid), exactly as the TLS engines do.
#[cfg(feature = "dtls")]
fn restrict_dtls_groups(
    supported: &[super::codec::NamedGroup],
    wanted: Option<&[NamedGroup]>,
) -> Result<Vec<super::codec::NamedGroup>, Error> {
    let Some(wanted) = wanted else {
        return Ok(supported.to_vec());
    };
    let mut picked: Vec<super::codec::NamedGroup> = Vec::new();
    for g in wanted {
        let w = g.to_wire();
        if supported.contains(&w) && !picked.contains(&w) {
            picked.push(w);
        }
    }
    if picked.is_empty() {
        return Err(Error::HandshakeFailure);
    }
    Ok(picked)
}

/// Applies a [`Config::cipher_suites`] restriction to a DTLS engine's
/// supported suite list: keeps the engine's suites that the caller listed, in
/// the caller's order, and fails closed with
/// [`Error::NoUsableCipherSuites`] when nothing is left — exactly as the TLS
/// engines do — so a typo'd list cannot silently re-enable every suite.
#[cfg(feature = "dtls")]
fn restrict_dtls_cipher_suites(
    supported: Vec<super::codec::CipherSuite>,
    wanted: Option<&[u16]>,
) -> Result<Vec<super::codec::CipherSuite>, Error> {
    let Some(wanted) = wanted else {
        return Ok(supported);
    };
    let mut picked: Vec<super::codec::CipherSuite> = Vec::new();
    for &id in wanted {
        if let Some(s) = supported.iter().find(|s| s.0 == id)
            && !picked.contains(s)
        {
            picked.push(*s);
        }
    }
    if picked.is_empty() {
        return Err(Error::NoUsableCipherSuites);
    }
    Ok(picked)
}

#[cfg(feature = "dtls")]
fn build_dtls12_client(cfg: &Config) -> Result<crate::dtls::DtlsClientConnection12, Error> {
    let DtlsClientOpts {
        roots,
        server_name,
        verify_certificates,
        crls,
        verification_time,
        signature_policy,
        key_log,
        cipher_suites,
        alpn_protocols,
        require_extended_master_secret,
        max_record_size,
        key_exchange_groups,
        key_shares,
    } = dtls_client_opts(cfg)?;
    // DTLS 1.2 fragments handshake records at a fixed 1100 bytes (see
    // `Config::max_record_size`) and has no key shares.
    let _ = (max_record_size, key_shares);

    let mut dc = crate::dtls::ClientConfig12Internal::new(roots.clone_store(), server_name)
        .with_require_ems(require_extended_master_secret)
        .with_alpn(alpn_protocols.to_vec());
    if !verify_certificates {
        dc = dc.without_certificate_verification();
    }
    if !crls.is_empty() {
        dc = dc.with_crls(crls.clone_store());
    }
    if let Some(t) = verification_time {
        dc = dc.with_verification_time(t.clone());
    }
    dc = dc.with_signature_policy(signature_policy.clone());
    dc.cipher_suites = restrict_dtls_cipher_suites(dc.cipher_suites, cipher_suites)?;
    dc.groups = restrict_dtls_groups(&dc.groups, key_exchange_groups)?;
    dc.key_log = key_log.clone();
    Ok(crate::dtls::DtlsClientConnection12::new(
        dc,
        Vec::new(),
        &mut config_rng(cfg)?,
    ))
}

#[cfg(feature = "dtls")]
fn build_dtls13_client(cfg: &Config) -> Result<crate::dtls::DtlsClientConnection13, Error> {
    let DtlsClientOpts {
        roots,
        server_name,
        verify_certificates,
        crls,
        verification_time,
        signature_policy,
        key_log,
        cipher_suites,
        alpn_protocols,
        require_extended_master_secret,
        max_record_size,
        key_exchange_groups,
        key_shares,
    } = dtls_client_opts(cfg)?;
    // EMS is a TLS 1.2 mechanism (DTLS 1.3 binds every secret to the
    // transcript).
    let _ = require_extended_master_secret;

    let mut dc = crate::dtls::ClientConfig13Internal::new(roots.clone_store(), server_name);
    if !verify_certificates {
        dc = dc.without_certificate_verification();
    }
    if !crls.is_empty() {
        dc = dc.with_crls(crls.clone_store());
    }
    if let Some(t) = verification_time {
        dc = dc.with_verification_time(t.clone());
    }
    dc = dc.with_signature_policy(alloc::sync::Arc::new(signature_policy.clone()));
    dc.cipher_suites = restrict_dtls_cipher_suites(dc.cipher_suites, cipher_suites)?;
    dc.groups = restrict_dtls_groups(&dc.groups, key_exchange_groups)?;
    // `key_shares` narrows the shares, never the offer: a group listed here
    // but not offered is simply ignored, and a list naming none of the
    // offered groups sends no share at all (the server then asks for one).
    if let Some(shares) = key_shares {
        dc.key_share_groups = Some(shares.iter().map(|g| g.to_wire()).collect());
    }
    dc.alpn_protocols = alpn_protocols.to_vec();
    dc.max_record_size = max_record_size;
    dc.key_log = key_log.clone();
    Ok(crate::dtls::DtlsClientConnection13::new(
        dc,
        Vec::new(),
        &mut config_rng(cfg)?,
    ))
}

/// The `Config` options a DTLS server engine consumes, checked once for both
/// DTLS versions by [`dtls_server_opts`].
#[cfg(feature = "dtls")]
struct DtlsServerOpts<'a> {
    identity: &'a super::config::Identity,
    cookie_secret: Option<&'a super::secret::Secret32>,
    previous_cookie_secret: Option<&'a super::secret::Secret32>,
    require_cookie: bool,
    peer_address: &'a [u8],
    key_log: &'a Option<alloc::sync::Arc<dyn super::keylog::KeyLog>>,
    signature_policy: &'a crate::signature_registry::SignaturePolicy,
    alpn_protocols: &'a [Vec<u8>],
    require_extended_master_secret: bool,
    max_record_size: usize,
    key_exchange_groups: Option<&'a [NamedGroup]>,
}

/// Takes `cfg` apart for a DTLS server, failing closed on what the DTLS
/// engines cannot honour:
///
/// * a cookie-requiring server with no `cookie_secret` —
///   [`Error::InappropriateState`]. RFC 6347 §4.2.1 / RFC 9147 §5.1: the
///   cookie exchange defeats blind amplification attacks; silently disabling
///   it under a misconfiguration is the 50-100x DoS amplification vector, so
///   the operator must make a deliberate choice (`ConfigBuilder::no_cookie`);
/// * `client_auth` — [`Error::UnsupportedVersion`]. The DTLS servers never
///   emit a `CertificateRequest`, so access control would fail OPEN,
///   admitting every anonymous client;
/// * ECH, a `record_size_limit`, or RFC 7250 raw public keys /
///   certificate-type preferences — [`Error::InappropriateState`], as in
///   [`dtls_client_opts`].
#[cfg(feature = "dtls")]
fn dtls_server_opts(cfg: &Config) -> Result<DtlsServerOpts<'_>, Error> {
    let parts = cfg.parts();
    let CommonOpts {
        min_version,
        max_version,
        identity,
        roots,
        crls,
        signature_policy,
        verification_time,
        alpn_protocols,
        record_size_limit,
        cipher_suites,
        key_exchange_groups,
        require_extended_master_secret,
        server_cert_type_preference,
        client_cert_type_preference,
        raw_public_key_spki,
        #[cfg(feature = "cert-compression")]
        cert_compression_algorithms,
        key_log,
        rng,
        signer,
    } = parts.common;
    let ServerOpts {
        client_auth,
        stapled_crl,
        stapled_ocsp_response,
        ticket_key,
        max_early_data_size,
        #[cfg(feature = "std")]
        replay_window,
        expected_client_raw_public_keys,
        preferred_key_exchange_group,
        #[cfg(feature = "ech")]
        ech_server,
    } = parts.server;
    let DtlsOpts {
        cookie_secret,
        previous_cookie_secret,
        require_cookie,
        max_record_size,
        peer_address,
    } = parts.dtls;
    // Inert on a DTLS server (see the `Config` docs): the version pair chose
    // the engine; `roots` / `crls` / `verification_time` only serve mTLS,
    // which is refused below; the DTLS servers issue no session tickets,
    // accept no 0-RTT (so `max_early_data_size` and the replay window have
    // nothing to guard), staple nothing, do not compress certificates, take
    // no `preferred_key_exchange_group` (`key_exchange_groups` orders the
    // accept-set instead) and pick the cipher suite from their own fixed
    // order. `rng` is drawn through `config_rng` and `signer` through
    // `Connection::drive`.
    let _ = (
        min_version,
        max_version,
        cipher_suites,
        roots,
        crls,
        verification_time,
        stapled_crl,
        stapled_ocsp_response,
        ticket_key,
        max_early_data_size,
        preferred_key_exchange_group,
        rng,
        signer,
    );
    #[cfg(feature = "std")]
    let _ = replay_window;
    #[cfg(feature = "cert-compression")]
    let _ = cert_compression_algorithms;

    let identity = identity.ok_or(Error::InappropriateState)?;
    #[cfg(feature = "ech")]
    if ech_server.is_some() {
        return Err(Error::InappropriateState);
    }
    if require_cookie && cookie_secret.is_none() {
        return Err(Error::InappropriateState);
    }
    if client_auth.is_some() {
        return Err(Error::UnsupportedVersion);
    }
    if record_size_limit.is_some()
        || server_cert_type_preference != [0]
        || client_cert_type_preference != [0]
        || raw_public_key_spki.is_some()
        || !expected_client_raw_public_keys.is_empty()
    {
        return Err(Error::InappropriateState);
    }
    Ok(DtlsServerOpts {
        identity,
        cookie_secret,
        previous_cookie_secret,
        require_cookie,
        peer_address,
        key_log,
        signature_policy,
        alpn_protocols,
        require_extended_master_secret,
        max_record_size,
        key_exchange_groups,
    })
}

#[cfg(feature = "dtls")]
fn build_dtls12_server(
    cfg: &Config,
) -> Result<crate::dtls::DtlsServerConnection12<ConfigRng>, Error> {
    let DtlsServerOpts {
        identity,
        cookie_secret,
        previous_cookie_secret,
        require_cookie,
        peer_address,
        key_log,
        signature_policy,
        alpn_protocols,
        require_extended_master_secret,
        max_record_size,
        key_exchange_groups,
    } = dtls_server_opts(cfg)?;
    // The DTLS 1.2 server verifies no client certificate (so the signature
    // policy has nothing to govern) and fragments at a fixed 1100 bytes; see
    // the `Config` docs.
    let _ = (signature_policy, max_record_size);

    let chain = identity.cert_chain.clone();
    let mut sc = match &identity.key {
        super::config::SigningKey::Ecdsa(k) => {
            crate::dtls::ServerConfig12Internal::with_ecdsa(chain, k.clone())
        }
        super::config::SigningKey::Rsa(k) => {
            crate::dtls::ServerConfig12Internal::with_rsa(chain, k.clone())
        }
        super::config::SigningKey::External { schemes } => {
            crate::dtls::ServerConfig12Internal::with_external(chain, schemes.clone())
        }
        // DTLS 1.2 mirrors TLS 1.2's scope: RSA + ECDSA only. Ed25519 and
        // ML-DSA are not common in TLS 1.2 practice.
        _ => return Err(Error::UnsupportedVersion),
    };
    if let Some(secret) = cookie_secret {
        sc = sc.with_cookie_secret(*secret.as_bytes());
    }
    if let Some(previous) = previous_cookie_secret {
        sc = sc.with_previous_cookie_secret(*previous.as_bytes());
    }
    if !require_cookie {
        sc = sc.require_cookie_exchange(false);
    }
    sc = sc.with_require_ems(require_extended_master_secret);
    sc = sc.with_alpn(alpn_protocols.to_vec());
    let groups = restrict_dtls_groups(&sc.groups, key_exchange_groups)?;
    sc = sc.with_groups(groups);
    sc.key_log = key_log.clone();
    Ok(crate::dtls::DtlsServerConnection12::new(
        alloc::sync::Arc::new(sc),
        peer_address.to_vec(),
        config_rng(cfg)?,
    ))
}

#[cfg(feature = "dtls")]
fn build_dtls13_server(
    cfg: &Config,
) -> Result<crate::dtls::DtlsServerConnection13<ConfigRng>, Error> {
    let DtlsServerOpts {
        identity,
        cookie_secret,
        previous_cookie_secret,
        require_cookie,
        peer_address,
        key_log,
        signature_policy,
        alpn_protocols,
        require_extended_master_secret,
        max_record_size,
        key_exchange_groups,
    } = dtls_server_opts(cfg)?;
    // The DTLS 1.3 server verifies no client certificate (so the signature
    // policy has nothing to govern) and EMS is a TLS 1.2 mechanism; see the
    // `Config` docs.
    let _ = (signature_policy, require_extended_master_secret);

    let chain = identity.cert_chain.clone();
    let server_key = identity.key.to_server_key_13();
    let mut sc = crate::dtls::ServerConfig13Internal::with_signing_key(chain, server_key);
    if let Some(secret) = cookie_secret {
        sc = sc.with_cookie_secret(*secret.as_bytes());
    }
    if let Some(previous) = previous_cookie_secret {
        sc = sc.with_previous_cookie_secret(*previous.as_bytes());
    }
    if !require_cookie {
        sc = sc.with_no_cookie();
    }
    sc.max_record_size = max_record_size;
    sc.alpn_protocols = alpn_protocols.to_vec();
    sc.groups = restrict_dtls_groups(&sc.groups, key_exchange_groups)?;
    sc.key_log = key_log.clone();
    Ok(crate::dtls::DtlsServerConnection13::new(
        alloc::sync::Arc::new(sc),
        peer_address.to_vec(),
        config_rng(cfg)?,
    ))
}

/// The TLS 1.3 / TLS 1.2 client-certificate config for `id`'s chain and
/// signing key (mTLS). Shared with the QUIC client adapter.
pub(crate) fn client_cert_from_signing(
    id: &super::config::Identity,
) -> Option<super::conn::ClientCertConfig> {
    Some(match &id.key {
        super::config::SigningKey::Rsa(k) => {
            super::conn::ClientCertConfig::with_rsa(id.cert_chain.clone(), k.clone())
        }
        super::config::SigningKey::Ecdsa(k) => {
            super::conn::ClientCertConfig::with_ecdsa(id.cert_chain.clone(), k.clone())
        }
        super::config::SigningKey::Ed25519(k) => {
            super::conn::ClientCertConfig::with_ed25519(id.cert_chain.clone(), k.clone())
        }
        super::config::SigningKey::Ed448(k) => {
            super::conn::ClientCertConfig::with_ed448(id.cert_chain.clone(), k.clone())
        }
        #[cfg(feature = "mldsa")]
        super::config::SigningKey::MlDsa44(k) => {
            super::conn::ClientCertConfig::with_mldsa44(id.cert_chain.clone(), k.clone())
        }
        #[cfg(feature = "mldsa")]
        super::config::SigningKey::MlDsa65(k) => {
            super::conn::ClientCertConfig::with_mldsa65(id.cert_chain.clone(), k.clone())
        }
        #[cfg(feature = "mldsa")]
        super::config::SigningKey::MlDsa87(k) => {
            super::conn::ClientCertConfig::with_mldsa87(id.cert_chain.clone(), k.clone())
        }
        super::config::SigningKey::External { schemes } => {
            super::conn::ClientCertConfig::with_external(id.cert_chain.clone(), schemes.clone())
        }
    })
}

// The `Connection` loopback harness seeds its configs from `rng::OsRng` and
// the external-signer cases model a device over unix fds, so the suite as a
// whole needs `std`. The engine itself does not.
#[cfg(all(test, feature = "std"))]
mod tests {
    use super::super::config::EntropySource;
    use super::*;
    use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::tls::AlertDescription;
    #[cfg(feature = "dtls")]
    use crate::tls::RootCertStore;
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    /// Build a minimal DTLS server [`Config`] (P-256 ECDSA leaf, self-signed)
    /// with `require_cookie` defaulted to true and `cookie_secret = None`.
    #[cfg(feature = "dtls")]
    fn dtls_server_cfg_without_cookie_secret(max_version: ProtocolVersion) -> Config {
        let mut rng = HmacDrbg::<Sha256>::new(b"h3-dtls-cookie", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let name = DistinguishedName::common_name("dtls.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            false,
            &["dtls.example"],
        )
        .unwrap();
        Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(max_version, max_version)
            .identity(
                alloc::vec![cert.to_der().to_vec()],
                super::super::config::SigningKey::Ecdsa(key),
            )
            .build()
    }

    /// Minimal TLS 1.3 server [`Config`] (P-256 ECDSA self-signed leaf for
    /// `tls.example`). With `with_tickets`, a ticket key is installed so the
    /// server issues `NewSessionTicket` (enabling resumption).
    fn tls13_server_cfg(with_tickets: bool) -> Config {
        let mut rng = HmacDrbg::<Sha256>::new(b"tls13-conn-test", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let name = DistinguishedName::common_name("tls.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            false,
            &["tls.example"],
        )
        .unwrap();
        let mut b = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .identity(
                alloc::vec![cert.to_der().to_vec()],
                super::super::config::SigningKey::Ecdsa(key),
            );
        if with_tickets {
            b = b.ticket_key([0x5a; 32]);
        }
        b.build()
    }

    /// Matching TLS 1.3 client `Config` (verification off, SNI `tls.example`),
    /// optionally primed with a resumption session.
    fn tls13_client_cfg(session: Option<ResumptionSession>) -> Config {
        let mut b = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .server_name("tls.example")
            .verify_certificates(false);
        if let Some(s) = session {
            b = b.resumption_session(s);
        }
        b.build()
    }

    /// `Config::cipher_suites` used to be inert on the server, which then
    /// took the first suite of ITS built-in order the client offered — so a
    /// client that cannot narrow its offer (Apple's Network.framework sends
    /// both AES-GCM suites for either) could never be steered to
    /// AES-256-GCM. It is now the server's accept-set in server preference
    /// order (RFC 8446 §4.1.3: the suite is the server's choice among the
    /// client's), and fails closed like the client's.
    #[test]
    fn tls13_server_honours_cipher_suites_preference() {
        const AES_128: u16 = 0x1301;
        const AES_256: u16 = 0x1302;
        const CHACHA20: u16 = 0x1303;
        for (server_list, client_list, expect) in [
            // Server preference wins among what the client offered.
            (&[AES_256, AES_128][..], &[AES_128, AES_256][..], AES_256),
            (&[CHACHA20][..], &[AES_128, AES_256, CHACHA20][..], CHACHA20),
            // A suite the engine lacks is skipped, not a fallback to all.
            (&[0x1304, AES_256][..], &[AES_128, AES_256][..], AES_256),
        ] {
            let server_cfg = tls13_server_builder().cipher_suites(server_list).build();
            let client_cfg = tls13_client_builder().cipher_suites(client_list).build();
            let mut server = Connection::server(&server_cfg).unwrap();
            let mut client = Connection::client(&client_cfg).unwrap();
            drive_pair(&mut client, &mut server);
            assert_eq!(
                server.negotiated_cipher_suite(),
                Some(expect),
                "{server_list:?}"
            );
            assert_eq!(client.negotiated_cipher_suite(), Some(expect));
        }

        // No overlap between the server's accept-set and the client's offer:
        // the handshake is refused, not widened.
        let server_cfg = tls13_server_builder().cipher_suites(&[AES_256]).build();
        let client_cfg = tls13_client_builder().cipher_suites(&[AES_128]).build();
        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();
        let _ = client.handshake();
        let ch = client.pop().unwrap();
        assert!(matches!(server.feed(&ch), Err(Error::HandshakeFailure)));

        // A list naming nothing the engine implements fails at construction.
        let server_cfg = tls13_server_builder()
            .cipher_suites(&[0x1304, 0x0000])
            .build();
        assert!(matches!(
            Connection::server(&server_cfg),
            Err(Error::NoUsableCipherSuites)
        ));
    }

    /// The builder behind [`tls13_server_cfg`] (no ticket key), for tests
    /// that add options of their own.
    fn tls13_server_builder() -> super::super::ConfigBuilder {
        let mut rng = HmacDrbg::<Sha256>::new(b"tls13-conn-test", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let name = DistinguishedName::common_name("tls.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            false,
            &["tls.example"],
        )
        .unwrap();
        Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .identity(
                alloc::vec![cert.to_der().to_vec()],
                super::super::config::SigningKey::Ecdsa(key),
            )
    }

    /// The builder behind [`tls13_client_cfg`] (no session).
    fn tls13_client_builder() -> super::super::ConfigBuilder {
        Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .server_name("tls.example")
            .verify_certificates(false)
    }

    /// Drive two public [`Connection`]s to a completed handshake and then pump
    /// a few extra rounds so post-handshake flights (e.g. NewSessionTicket)
    /// are delivered. Panics if the handshake stalls.
    fn drive_pair(client: &mut Connection, server: &mut Connection) {
        let mut completed = false;
        for _ in 0..64 {
            let _ = client.handshake();
            let c = client.pop().unwrap();
            if !c.is_empty() {
                server.feed(&c).unwrap();
            }
            let _ = server.handshake();
            let s = server.pop().unwrap();
            if !s.is_empty() {
                client.feed(&s).unwrap();
            }
            if client.is_handshake_complete() && server.is_handshake_complete() {
                if completed {
                    return; // one extra round after completion flushed tickets
                }
                completed = true;
            }
        }
        if !completed {
            panic!("TLS 1.3 handshake did not complete");
        }
    }

    /// Server `Config` whose version range spans TLS 1.2 and 1.3 (the
    /// `Config::default` shape): `Connection::server` builds the deferred
    /// `ServerTlsAuto` engine. P-256 ECDSA self-signed leaf for `tls.example`.
    fn auto_server_cfg() -> Config {
        let mut rng = HmacDrbg::<Sha256>::new(b"tls-auto-test", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let name = DistinguishedName::common_name("tls.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            false,
            &["tls.example"],
        )
        .unwrap();
        Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3)
            .identity(
                alloc::vec![cert.to_der().to_vec()],
                super::super::config::SigningKey::Ecdsa(key),
            )
            .build()
    }

    /// TLS 1.2-only client `Config` (verification off, SNI `tls.example`).
    fn tls12_client_cfg() -> Config {
        Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_2)
            .server_name("tls.example")
            .verify_certificates(false)
            .build()
    }

    /// `ConfigBuilder::key_shares` narrows the first ClientHello's
    /// `key_share` list without narrowing `supported_groups`, so a server
    /// preferring another offered group gets it through a HelloRetryRequest.
    #[test]
    fn key_shares_limits_the_first_hello_and_hrr_recovers() {
        use crate::tls::NamedGroup;
        use crate::tls::codec::extension as ext;
        use crate::tls::codec::{ClientHello, ExtensionType};
        let client_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .server_name("tls.example")
            .verify_certificates(false)
            .key_shares(&[NamedGroup::X25519])
            .build();
        let mut server_cfg = tls13_server_cfg(false);
        server_cfg.preferred_key_exchange_group = Some(NamedGroup::Secp256r1);
        let mut client = Connection::client(&client_cfg).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();

        let _ = client.handshake();
        let ch1 = client.pop().unwrap();
        // One plaintext handshake record: 5-byte record header, then the
        // 4-byte handshake header, then the ClientHello structure.
        let hello = ClientHello::decode(&ch1[9..]).expect("ClientHello");
        let shares = ext::parse_client_key_shares(
            ext::find(&hello.extensions, ExtensionType::KEY_SHARE).expect("key_share"),
        )
        .expect("key shares");
        let groups: Vec<_> = shares.iter().map(|(g, _)| *g).collect();
        assert_eq!(groups, [NamedGroup::X25519.to_wire()]);
        let supported = ext::find(&hello.extensions, ExtensionType::SUPPORTED_GROUPS)
            .expect("supported_groups");
        assert!(
            supported
                .windows(2)
                .any(|w| w == NamedGroup::Secp256r1.to_wire().0.to_be_bytes())
        );

        server.feed(&ch1).unwrap();
        drive_pair(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
    }

    /// The negotiated-parameter accessors on a plain TLS 1.3 handshake, and
    /// the client's `psk_key_exchange_modes` advertisement earning a ticket.
    #[test]
    fn negotiated_parameters_of_a_fresh_handshake() {
        use crate::tls::NamedGroup;
        let client_cfg = tls13_client_cfg(None);
        let server_cfg = tls13_server_cfg(true);
        let mut client = Connection::client(&client_cfg).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        drive_pair(&mut client, &mut server);
        for c in [&client, &server] {
            assert_eq!(c.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
            // The client shares X25519MLKEM768 first and the server takes
            // the first usable share.
            assert_eq!(c.negotiated_group(), Some(NamedGroup::X25519MlKem768));
            assert!(!c.hello_retry_request_used());
            assert!(!c.resumed());
            assert!(!c.early_data_offered());
            assert!(!c.early_data_accepted());
            assert!(!c.peer_raw_public_key());
            assert!(!c.own_raw_public_key());
            assert!(!c.record_size_limit_negotiated());
            assert_eq!((c.sent_key_updates(), c.peer_key_updates()), (0, 0));
        }
        assert!(client.peer_ocsp_response().is_none());
        // A session was issued (the ticket rides on drive_pair's extra round).
        assert!(client.take_session().is_some());
    }

    /// `ConfigBuilder::key_exchange_groups` on the client narrows both the
    /// `supported_groups` offer and the shares to the listed groups, in
    /// order; an empty list fails closed.
    #[test]
    fn key_exchange_groups_restricts_the_client_offer() {
        use crate::tls::NamedGroup;
        use crate::tls::codec::extension as ext;
        use crate::tls::codec::{ClientHello, ExtensionType};
        let client_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .server_name("tls.example")
            .verify_certificates(false)
            .key_exchange_groups(&[NamedGroup::Secp384r1, NamedGroup::X25519])
            .build();
        let mut client = Connection::client(&client_cfg).unwrap();
        let _ = client.handshake();
        let ch1 = client.pop().unwrap();
        let hello = ClientHello::decode(&ch1[9..]).expect("ClientHello");
        let shares = ext::parse_client_key_shares(
            ext::find(&hello.extensions, ExtensionType::KEY_SHARE).expect("key_share"),
        )
        .expect("key shares");
        let share_groups: Vec<_> = shares.iter().map(|(g, _)| *g).collect();
        assert_eq!(
            share_groups,
            [
                NamedGroup::Secp384r1.to_wire(),
                NamedGroup::X25519.to_wire()
            ]
        );
        let supported = ext::parse_supported_groups(
            ext::find(&hello.extensions, ExtensionType::SUPPORTED_GROUPS)
                .expect("supported_groups"),
        )
        .expect("supported groups");
        assert_eq!(
            supported,
            [
                NamedGroup::Secp384r1.to_wire(),
                NamedGroup::X25519.to_wire()
            ]
        );
        // The server takes the client's first share, and both agree.
        let mut server = Connection::server(&tls13_server_cfg(false)).unwrap();
        server.feed(&ch1).unwrap();
        drive_pair(&mut client, &mut server);
        assert_eq!(client.negotiated_group(), Some(NamedGroup::Secp384r1));
        assert_eq!(server.negotiated_group(), Some(NamedGroup::Secp384r1));

        let empty = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .server_name("tls.example")
            .key_exchange_groups(&[])
            .build();
        assert!(Connection::client(&empty).is_err());
    }

    /// `ConfigBuilder::key_exchange_groups` on the server selects in the
    /// server's order among the client's shares, and asks for a listed group
    /// the client only advertised through a HelloRetryRequest.
    #[test]
    fn server_key_exchange_groups_selects_and_retries() {
        use crate::tls::NamedGroup;
        // The default client shares every group; a server preferring P-384
        // takes it although the client listed it last.
        let mut server_cfg = tls13_server_cfg(false);
        server_cfg.key_exchange_groups =
            Some(alloc::vec![NamedGroup::Secp384r1, NamedGroup::X25519]);
        let mut client = Connection::client(&tls13_client_cfg(None)).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        drive_pair(&mut client, &mut server);
        assert_eq!(client.negotiated_group(), Some(NamedGroup::Secp384r1));
        assert_eq!(server.negotiated_group(), Some(NamedGroup::Secp384r1));
        assert!(!server.hello_retry_request_used());

        // A client sharing only X25519 against a P-256-only server: HRR.
        let client_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .server_name("tls.example")
            .verify_certificates(false)
            .key_shares(&[NamedGroup::X25519])
            .build();
        let mut server_cfg = tls13_server_cfg(false);
        server_cfg.key_exchange_groups = Some(alloc::vec![NamedGroup::Secp256r1]);
        let mut client = Connection::client(&client_cfg).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        drive_pair(&mut client, &mut server);
        assert!(client.hello_retry_request_used());
        assert!(server.hello_retry_request_used());
        assert_eq!(client.negotiated_group(), Some(NamedGroup::Secp256r1));
        assert_eq!(server.negotiated_group(), Some(NamedGroup::Secp256r1));

        // A client that neither shares nor advertises the server's group
        // cannot be served.
        let client_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .server_name("tls.example")
            .verify_certificates(false)
            .key_exchange_groups(&[NamedGroup::X25519])
            .build();
        let mut client = Connection::client(&client_cfg).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        let _ = client.handshake();
        let ch = client.pop().unwrap();
        assert!(server.feed(&ch).is_err() || server.handshake().is_err());
    }

    /// `Connection::request_key_update` rolls both directions and the
    /// counters see the request and the peer's reply.
    #[test]
    fn key_update_round_trips_and_is_counted() {
        let mut client = Connection::client(&tls13_client_cfg(None)).unwrap();
        let mut server = Connection::server(&tls13_server_cfg(false)).unwrap();
        drive_pair(&mut client, &mut server);
        client.request_key_update().unwrap();
        client.send(b"after rekey").unwrap();
        server.feed(&client.pop().unwrap()).unwrap();
        assert_eq!(server.recv().unwrap(), b"after rekey");
        assert_eq!(server.peer_key_updates(), 1);
        // The server owes a reply, sent with its next write.
        server.send(b"reply").unwrap();
        client.feed(&server.pop().unwrap()).unwrap();
        assert_eq!(client.recv().unwrap(), b"reply");
        assert_eq!(
            (client.sent_key_updates(), client.peer_key_updates()),
            (1, 1)
        );
        assert_eq!(
            (server.sent_key_updates(), server.peer_key_updates()),
            (1, 1)
        );
        // TLS 1.2 has no KeyUpdate.
        let mut c12 = Connection::client(&tls12_client_cfg()).unwrap();
        assert!(matches!(
            c12.request_key_update(),
            Err(Error::InappropriateState)
        ));
    }

    /// `resumed` / `early_data_*` follow a PSK resumption with 0-RTT.
    #[test]
    fn resumption_and_early_data_are_reported() {
        let server_cfg = {
            let mut c = tls13_server_cfg(true);
            c.max_early_data_size = 4096;
            c
        };
        let mut client = Connection::client(&tls13_client_cfg(None)).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        drive_pair(&mut client, &mut server);
        let session = client.take_session().expect("ticket");
        let mut client = Connection::client(&tls13_client_cfg(Some(session))).unwrap();
        client.write_early_data(b"0rtt").unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        drive_pair(&mut client, &mut server);
        for c in [&client, &server] {
            assert!(c.resumed());
            assert!(c.early_data_offered());
            assert!(c.early_data_accepted());
            assert!(!c.hello_retry_request_used());
        }
        assert_eq!(server.take_early_data().unwrap(), b"0rtt");
    }

    /// `Connection::ech_accepted` reports real ECH on both ends, and stays
    /// `false` for GREASE.
    #[cfg(feature = "ech")]
    #[test]
    fn ech_accepted_reports_both_sides() {
        use crate::hpke::{HpkeAead, HpkeKdf, HpkeKem};
        use crate::tls::ech::{EchClient, EchKeyPair, EchKeyRing, EchServer, HpkeSymCipherSuite};
        let pair = EchKeyPair::generate(
            &mut crate::rng::OsRng,
            HpkeKem::DhkemX25519HkdfSha256,
            3,
            b"tls.example",
            32,
            alloc::vec![HpkeSymCipherSuite {
                kdf_id: HpkeKdf::HkdfSha256.id(),
                aead_id: HpkeAead::Aes128Gcm.id(),
            }],
        )
        .unwrap();
        let ring = EchKeyRing::from_pairs(alloc::vec![pair]);
        let list = ring.to_config_list();
        let mut server_cfg = tls13_server_cfg(false);
        server_cfg.ech_server = Some(EchServer::new(ring, list.clone()));
        for (ech, accepted) in [
            (EchClient::from_config_list(list), true),
            (EchClient::default_grease(), false),
        ] {
            let mut client_cfg = tls13_client_cfg(None);
            client_cfg.ech = Some(ech);
            let mut client = Connection::client(&client_cfg).unwrap();
            let mut server = Connection::server(&server_cfg).unwrap();
            drive_pair(&mut client, &mut server);
            assert_eq!(client.ech_accepted(), accepted);
            assert_eq!(server.ech_accepted(), accepted);
        }
    }

    /// A version-spanning (auto) server negotiates TLS 1.3 with a 1.3 client.
    #[test]
    fn auto_server_completes_with_tls13_client() {
        let mut client = Connection::client(&tls13_client_cfg(None)).unwrap();
        let mut server = Connection::server(&auto_server_cfg()).unwrap();
        drive_pair(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        assert_eq!(server.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(client.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
    }

    /// The same auto server negotiates TLS 1.2 with a 1.2-only client — the
    /// case that previously failed with `handshake_failure`.
    #[test]
    fn auto_server_completes_with_tls12_client() {
        let mut client = Connection::client(&tls12_client_cfg()).unwrap();
        let mut server = Connection::server(&auto_server_cfg()).unwrap();
        drive_pair(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        assert_eq!(server.negotiated_version(), Some(ProtocolVersion::TLSv1_2));
        assert_eq!(client.negotiated_version(), Some(ProtocolVersion::TLSv1_2));
        // The auto server reports the 1.2 ECDHE-ECDSA suite it negotiated.
        assert_eq!(
            server.negotiated_cipher_suite(),
            client.negotiated_cipher_suite()
        );
    }

    /// A version-spanning server `Config` whose identity is also offered as
    /// an RFC 7250 raw public key, plus the bare SPKI clients pin.
    fn rpk_auto_server_cfg() -> (Config, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"tls-auto-rpk", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let spki = crate::x509::AnyPublicKey::Ecdsa(key.public_key()).to_spki_der();
        let name = DistinguishedName::common_name("tls.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            false,
            &["tls.example"],
        )
        .unwrap();
        let cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3)
            .identity(
                alloc::vec![cert.to_der().to_vec()],
                super::super::config::SigningKey::Ecdsa(key),
            )
            .raw_public_key_spki(spki.clone())
            .server_cert_type_preference(alloc::vec![2, 0])
            .build();
        (cfg, spki)
    }

    /// A client `Config` that accepts only a raw public key pinned to `pin`,
    /// with X.509 verification off (the pin is its whole authentication),
    /// offering TLS 1.2 up to `max`.
    fn pinned_client_cfg(max: ProtocolVersion, pin: Vec<u8>) -> Config {
        Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_2, max)
            .server_name("tls.example")
            .verify_certificates(false)
            .server_cert_type_preference(alloc::vec![2])
            .add_expected_raw_public_key(pin)
            .build()
    }

    /// Like [`drive_pair`] but surfaces the first failure instead of
    /// panicking, for handshakes that are expected to be refused.
    fn try_drive_pair(client: &mut Connection, server: &mut Connection) -> Result<(), Error> {
        for _ in 0..64 {
            client.handshake()?;
            let c = client.pop()?;
            if !c.is_empty() {
                server.feed(&c)?;
            }
            server.handshake()?;
            let s = server.pop()?;
            if !s.is_empty() {
                client.feed(&s)?;
            }
            if client.is_handshake_complete() && server.is_handshake_complete() {
                return Ok(());
            }
        }
        panic!("handshake did not complete");
    }

    /// RFC 7250 through the public `Config`: a client that pins the server's
    /// raw public key with `verify_certificates(false)` and is capped at
    /// TLS 1.2 authenticates the server over TLS 1.2 exactly as it would
    /// over 1.3 — a bare SPKI in the `Certificate`, checked against the pin
    /// — and a wrong pin is refused instead of silently accepted.
    #[test]
    fn pinned_raw_public_key_authenticates_over_tls12() {
        let (server_cfg, spki) = rpk_auto_server_cfg();
        let mut client =
            Connection::client(&pinned_client_cfg(ProtocolVersion::TLSv1_2, spki.clone())).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        try_drive_pair(&mut client, &mut server).unwrap();
        assert_eq!(client.negotiated_version(), Some(ProtocolVersion::TLSv1_2));
        assert_eq!(server.negotiated_version(), Some(ProtocolVersion::TLSv1_2));
        assert_eq!(client.peer_certificates(), core::slice::from_ref(&spki));

        let mut wrong = spki;
        let last = wrong.len() - 1;
        wrong[last] ^= 0x01;
        let mut client =
            Connection::client(&pinned_client_cfg(ProtocolVersion::TLSv1_2, wrong)).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        assert!(matches!(
            try_drive_pair(&mut client, &mut server),
            Err(Error::BadCertificate)
        ));
        assert!(!client.is_handshake_complete());
    }

    /// The same pinned client, allowed up to TLS 1.3, still negotiates 1.3
    /// with the same server — wiring RFC 7250 into the 1.2 engine changed
    /// nothing about version selection or the 1.3 raw-key path.
    #[test]
    fn pinned_raw_public_key_still_negotiates_tls13_when_available() {
        let (server_cfg, spki) = rpk_auto_server_cfg();
        let mut client =
            Connection::client(&pinned_client_cfg(ProtocolVersion::TLSv1_3, spki.clone())).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        try_drive_pair(&mut client, &mut server).unwrap();
        assert_eq!(client.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(server.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(client.peer_certificates(), core::slice::from_ref(&spki));
    }

    /// A server pinned to TLS 1.3 (`min == max == 1.3`) still refuses a
    /// 1.2-only client — the auto path must not weaken the 1.3-only opt-out.
    #[test]
    fn pinned_tls13_server_rejects_tls12_client() {
        let mut client = Connection::client(&tls12_client_cfg()).unwrap();
        let mut server = Connection::server(&tls13_server_cfg(false)).unwrap();
        let _ = client.handshake();
        let ch = client.pop().unwrap();
        assert!(!ch.is_empty());
        // The pinned 1.3 engine cannot negotiate the 1.2-only ClientHello: it
        // rejects with handshake_failure (and emits a fatal alert) rather than
        // silently downgrading.
        assert!(matches!(server.feed(&ch), Err(Error::HandshakeFailure)));
    }

    /// The auto detector must not resolve on a partial ClientHello: feeding the
    /// 1.2 client's opening flight one byte at a time stays unresolved (no
    /// version, still handshaking) until the full ClientHello arrives, then the
    /// handshake completes normally.
    #[test]
    fn auto_server_resolves_on_fragmented_client_hello() {
        let mut client = Connection::client(&tls12_client_cfg()).unwrap();
        let mut server = Connection::server(&auto_server_cfg()).unwrap();
        let _ = client.handshake();
        let ch = client.pop().unwrap();
        assert!(ch.len() > 8);
        // Feed all but the last byte one at a time: must never resolve early.
        for b in &ch[..ch.len() - 1] {
            server.feed(core::slice::from_ref(b)).unwrap();
            assert!(!server.is_handshake_complete());
            assert_eq!(server.negotiated_version(), None);
            assert!(server.pop().unwrap().is_empty());
        }
        // The final byte completes the ClientHello and resolves to TLS 1.2.
        server.feed(&ch[ch.len() - 1..]).unwrap();
        assert_eq!(server.negotiated_version(), Some(ProtocolVersion::TLSv1_2));
        drive_pair(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
    }

    /// Re-frames the single handshake record `rec` into records carrying
    /// `chunk` payload bytes each.
    fn refragment_handshake_record(rec: &[u8], chunk: usize) -> Vec<u8> {
        let parsed = super::super::codec::read_record(rec).unwrap().unwrap();
        assert_eq!(parsed.len, rec.len(), "expected exactly one record");
        let mut out = Vec::new();
        for frag in parsed.fragment.chunks(chunk) {
            super::super::codec::write_record(
                &mut out,
                crate::tls::ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                frag,
            )
            .unwrap();
        }
        out
    }

    /// TLS-CORE-5 — the deferred server used to re-parse its whole peek
    /// buffer from offset 0 on every `feed`, so a ClientHello chopped into
    /// one-byte-payload records and delivered a byte at a time cost
    /// O(records²) header parses before it resolved. The peeker keeps a
    /// cursor now; this drives that worst case end to end (a real 1.3
    /// ClientHello is ~1.5 KB → ~1,500 records → ~9,000 one-byte feeds) and
    /// checks the handshake still completes.
    #[test]
    fn auto_server_resolves_a_client_hello_in_one_byte_records_fed_bytewise() {
        let mut client = Connection::client(&tls13_client_cfg(None)).unwrap();
        let mut server = Connection::server(&auto_server_cfg()).unwrap();
        let _ = client.handshake();
        let ch = client.pop().unwrap();
        let wire = refragment_handshake_record(&ch, 1);
        assert!(wire.len() > 6 * 1000, "a fragmented CH of >1,000 records");

        let started = std::time::Instant::now();
        for b in &wire {
            server.feed(core::slice::from_ref(b)).unwrap();
        }
        assert_eq!(server.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
        // Generous even for a debug build; the quadratic version took
        // multiple seconds here.
        assert!(
            started.elapsed() < core::time::Duration::from_secs(5),
            "ClientHello resolution must be linear in the record count"
        );
        drive_pair(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
    }

    /// TLS-CORE-5 — RFC 8446 §5.1: a zero-length handshake fragment is a
    /// protocol violation; the deferred server refuses it instead of
    /// spending parse budget on records that never advance the message.
    #[test]
    fn auto_server_rejects_zero_length_handshake_fragment() {
        let mut client = Connection::client(&tls13_client_cfg(None)).unwrap();
        let mut server = Connection::server(&auto_server_cfg()).unwrap();
        let _ = client.handshake();
        let ch = client.pop().unwrap();
        let mut wire = alloc::vec![22u8, 0x03, 0x01, 0x00, 0x00];
        wire.extend_from_slice(&ch);
        assert!(matches!(server.feed(&wire), Err(Error::UnexpectedMessage)));
        assert_eq!(server.negotiated_version(), None);
    }

    /// Auto server with an **Ed25519** leaf (which cannot sign TLS 1.2 suites):
    /// serves a TLS 1.3 client normally, but a 1.2-only client is refused with
    /// `handshake_failure`. Proves the 1.2 engine is built *lazily* — its
    /// unsupported-key failure surfaces at the (1.2) ClientHello, not at
    /// `Connection::server` construction, and the 1.3 path never needs it.
    #[test]
    fn auto_server_ed25519_serves_tls13_refuses_tls12() {
        let ed25519_cfg = || {
            let mut rng = HmacDrbg::<Sha256>::new(b"tls-auto-ed25519", b"nonce", &[]);
            let key = crate::ec::Ed25519PrivateKey::generate(&mut rng);
            let name = DistinguishedName::common_name("tls.example");
            let validity = Validity::new(
                Time::utc(2024, 1, 1, 0, 0, 0),
                Time::utc(2034, 1, 1, 0, 0, 0),
            );
            let cert = Certificate::self_signed_general(
                &CertSigner::Ed25519(&key),
                &name,
                &validity,
                1,
                false,
                &["tls.example"],
            )
            .unwrap();
            Config::builder()
                .rng(alloc::sync::Arc::new(crate::rng::OsRng))
                .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3)
                .identity(
                    alloc::vec![cert.to_der().to_vec()],
                    super::super::config::SigningKey::Ed25519(key),
                )
                .build()
        };

        // TLS 1.3 client: completes (Ed25519 is a valid 1.3 identity), and the
        // server never builds a 1.2 engine.
        let mut c13 = Connection::client(&tls13_client_cfg(None)).unwrap();
        let mut s13 = Connection::server(&ed25519_cfg()).unwrap();
        drive_pair(&mut c13, &mut s13);
        assert!(c13.is_handshake_complete() && s13.is_handshake_complete());
        assert_eq!(s13.negotiated_version(), Some(ProtocolVersion::TLSv1_3));

        // TLS 1.2-only client: the lazy 1.2 build fails (no 1.2-capable key) and
        // surfaces as handshake_failure on the ClientHello.
        let mut c12 = Connection::client(&tls12_client_cfg()).unwrap();
        let mut s12 = Connection::server(&ed25519_cfg()).unwrap();
        let _ = c12.handshake();
        let ch = c12.pop().unwrap();
        assert!(!ch.is_empty());
        assert!(matches!(s12.feed(&ch), Err(Error::HandshakeFailure)));
    }

    /// A version-spanning (auto) client `Config`: default min 1.2 / max 1.3,
    /// verification off, SNI `tls.example`. Builds `Engine::ClientTlsAuto`.
    fn auto_client_cfg() -> Config {
        Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3)
            .server_name("tls.example")
            .verify_certificates(false)
            .build()
    }

    /// A pinned TLS 1.2-only server `Config` (ECDSA P-256 leaf for `tls.example`).
    fn tls12_server_cfg() -> Config {
        let mut rng = HmacDrbg::<Sha256>::new(b"tls12-server-test", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let name = DistinguishedName::common_name("tls.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            false,
            &["tls.example"],
        )
        .unwrap();
        Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_2)
            .identity(
                alloc::vec![cert.to_der().to_vec()],
                super::super::config::SigningKey::Ecdsa(key),
            )
            .build()
    }

    /// A version-spanning (auto) client negotiates TLS 1.3 with a 1.3 server.
    #[test]
    fn auto_client_completes_with_tls13_server() {
        let mut client = Connection::client(&auto_client_cfg()).unwrap();
        let mut server = Connection::server(&tls13_server_cfg(false)).unwrap();
        drive_pair(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        assert_eq!(client.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(server.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
    }

    /// The same auto client completes with a TLS 1.2-only server by downgrading
    /// the engine (adopting the already-sent ClientHello) — the gap this fixes.
    #[test]
    fn auto_client_completes_with_tls12_server() {
        let mut client = Connection::client(&auto_client_cfg()).unwrap();
        let mut server = Connection::server(&tls12_server_cfg()).unwrap();
        drive_pair(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        assert_eq!(client.negotiated_version(), Some(ProtocolVersion::TLSv1_2));
        assert_eq!(server.negotiated_version(), Some(ProtocolVersion::TLSv1_2));
        assert_eq!(
            client.negotiated_cipher_suite(),
            server.negotiated_cipher_suite()
        );
    }

    /// RFC 5077 §3.1: the auto client's hybrid ClientHello requests a ticket,
    /// so a 1.2 server with tickets enabled issues one and the downgraded
    /// engine hands it back through `take_session`.
    #[test]
    fn auto_client_receives_a_tls12_session_ticket() {
        let mut server_cfg = tls12_server_cfg();
        server_cfg.ticket_key = Some([0x5a; 32].into());
        let mut client = Connection::client(&auto_client_cfg()).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        drive_pair(&mut client, &mut server);
        assert_eq!(client.negotiated_version(), Some(ProtocolVersion::TLSv1_2));
        let session = client
            .take_session()
            .expect("a 1.2 server with tickets on must issue one");
        assert!(matches!(session.0, ResumptionSessionKind::Tls12(_)));
    }

    /// RFC 5077 §3.4 through the version-spanning client: a stored TLS 1.2
    /// session keeps the 1.2 offer, presents its ticket with a fresh
    /// `session_id`, and the downgraded engine completes an abbreviated
    /// handshake. A 1.3 server handed the same hello ignores the ticket and
    /// runs a full 1.3 handshake.
    #[test]
    fn auto_client_resumes_a_tls12_session() {
        fn resumed(c: &Connection) -> bool {
            match &c.inner {
                Engine::ClientTlsAuto(a) => match &a.inner {
                    ClientInner::Tls12(c12) => c12.did_resume(),
                    ClientInner::Tls13(_) => false,
                },
                _ => panic!("expected the version-spanning client engine"),
            }
        }
        let mut server_cfg = tls12_server_cfg();
        server_cfg.ticket_key = Some([0x5a; 32].into());
        let mut client = Connection::client(&auto_client_cfg()).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        drive_pair(&mut client, &mut server);
        assert!(!resumed(&client));
        let session = client.take_session().expect("1.2 ticket");

        let resumed_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3)
            .server_name("tls.example")
            .verify_certificates(false)
            .resumption_session(session)
            .build();
        let mut client2 = Connection::client(&resumed_cfg).unwrap();
        let mut server2 = Connection::server(&server_cfg).unwrap();
        drive_pair(&mut client2, &mut server2);
        assert_eq!(client2.negotiated_version(), Some(ProtocolVersion::TLSv1_2));
        assert!(resumed(&client2), "the 1.2 ticket must be resumed");
        let mut ce = [0u8; 16];
        let mut se = [0u8; 16];
        client2.tls_exporter(b"EXPORTER-r", b"", &mut ce).unwrap();
        server2.tls_exporter(b"EXPORTER-r", b"", &mut se).unwrap();
        assert_eq!(ce, se);

        // The same stored session against a 1.3 server: full 1.3 handshake.
        let mut client3 = Connection::client(&resumed_cfg).unwrap();
        let mut server3 = Connection::server(&tls13_server_cfg(false)).unwrap();
        drive_pair(&mut client3, &mut server3);
        assert_eq!(client3.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
    }

    /// A stored TLS 1.3 session no longer pins the version-spanning client to
    /// a pure-1.3 hello: it resumes against a 1.3 server and still reaches a
    /// 1.2-only one (full 1.2 handshake). A session that makes the client
    /// offer 0-RTT fails against 1.2 instead, per RFC 8446 §4.2.10.
    #[test]
    fn auto_client_with_tls13_session_still_offers_tls12() {
        fn psk_accepted(c: &Connection) -> bool {
            match &c.inner {
                Engine::ClientTlsAuto(a) => match &a.inner {
                    ClientInner::Tls13(c13) => c13.psk_accepted(),
                    ClientInner::Tls12(_) => false,
                },
                _ => panic!("expected the version-spanning client engine"),
            }
        }
        let session_from = |server_cfg: &Config| {
            let mut client = Connection::client(&auto_client_cfg()).unwrap();
            let mut server = Connection::server(server_cfg).unwrap();
            drive_pair(&mut client, &mut server);
            assert_eq!(client.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
            client.take_session().expect("1.3 ticket")
        };
        let resuming = |session: ResumptionSession| {
            Config::builder()
                .rng(alloc::sync::Arc::new(crate::rng::OsRng))
                .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3)
                .server_name("tls.example")
                .verify_certificates(false)
                .resumption_session(session)
                .build()
        };

        let server13 = tls13_server_cfg(true);
        let cfg = resuming(session_from(&server13));
        let mut client = Connection::client(&cfg).unwrap();
        let mut server = Connection::server(&server13).unwrap();
        drive_pair(&mut client, &mut server);
        assert_eq!(client.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
        assert!(psk_accepted(&client), "the 1.3 session must resume");

        let mut client = Connection::client(&cfg).unwrap();
        let mut server = Connection::server(&tls12_server_cfg()).unwrap();
        drive_pair(&mut client, &mut server);
        assert_eq!(client.negotiated_version(), Some(ProtocolVersion::TLSv1_2));

        // 0-RTT-capable session: the hello offers early data, so a 1.2
        // ServerHello must fail the connection.
        let mut server13_0rtt = tls13_server_cfg(true);
        server13_0rtt.max_early_data_size = 1024;
        let cfg = resuming(session_from(&server13_0rtt));
        let mut client = Connection::client(&cfg).unwrap();
        let mut server = Connection::server(&tls12_server_cfg()).unwrap();
        let _ = client.handshake();
        server.feed(&client.pop().unwrap()).unwrap();
        let _ = server.handshake();
        assert!(matches!(
            client.feed(&server.pop().unwrap()),
            Err(Error::UnsupportedVersion)
        ));
    }

    /// Auto client ↔ auto server: both default configs interoperate, and 1.3 is
    /// preferred (the server picks the 1.3 engine for the hybrid ClientHello).
    #[test]
    fn auto_client_auto_server_prefers_tls13() {
        let mut client = Connection::client(&auto_client_cfg()).unwrap();
        let mut server = Connection::server(&auto_server_cfg()).unwrap();
        drive_pair(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        assert_eq!(client.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(server.negotiated_version(), Some(ProtocolVersion::TLSv1_3));
    }

    /// A client pinned to TLS 1.3 (`min == max == 1.3`) cannot complete with a
    /// 1.2-only server — it offers no 1.2 suites, so there's no overlap.
    #[test]
    fn pinned_tls13_client_rejects_tls12_server() {
        let mut client = Connection::client(&tls13_client_cfg(None)).unwrap();
        let mut server = Connection::server(&tls12_server_cfg()).unwrap();
        // The pure-1.3 ClientHello offers no 1.2 suite, so the 1.2-only server
        // (or the client, on the server's alert) MUST error out — they cannot
        // negotiate. Drive a bounded loop and require that a feed fails.
        let mut errored = false;
        for _ in 0..16 {
            let _ = client.handshake();
            let c = client.pop().unwrap_or_default();
            if !c.is_empty() && server.feed(&c).is_err() {
                errored = true;
                break;
            }
            let s = server.pop().unwrap_or_default();
            if !s.is_empty() && client.feed(&s).is_err() {
                errored = true;
                break;
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        assert!(
            errored,
            "a pinned TLS 1.3 client and a 1.2-only server must fail to negotiate"
        );
    }

    /// RFC 8446 §4.1.3 downgrade-attack guard: an auto client that offered 1.3
    /// MUST abort if it receives a TLS 1.2 ServerHello bearing the `DOWNGRD`
    /// sentinel. We obtain such a ServerHello from the (1.3-capable) auto server
    /// when it is fed a stripped, 1.2-only ClientHello — exactly what an in-path
    /// downgrade attacker would produce.
    #[test]
    fn auto_client_aborts_on_downgrade_sentinel() {
        // 1.3-capable server forced to 1.2 by a stripped (pure-1.2) ClientHello:
        // it negotiates 1.2 and sets the sentinel.
        let mut server = Connection::server(&auto_server_cfg()).unwrap();
        let mut stripped = Connection::client(&tls12_client_cfg()).unwrap();
        let _ = stripped.handshake();
        let ch12 = stripped.pop().unwrap();
        server.feed(&ch12).unwrap();
        let sh_flight = server.pop().unwrap();
        assert!(!sh_flight.is_empty());

        // A real auto client (which offered 1.3) must treat the sentinel-bearing
        // 1.2 ServerHello as a downgrade attack and abort.
        let mut client = Connection::client(&auto_client_cfg()).unwrap();
        let _ = client.pop(); // drain our ClientHello
        assert!(matches!(
            client.feed(&sh_flight),
            Err(Error::IllegalParameter)
        ));
    }

    /// RFC 8446 §7.5: the exporter is a function of the (shared) master secret,
    /// so both peers MUST derive identical material for the same label/context,
    /// and different material for a different label.
    #[test]
    fn tls_exporter_agrees_across_peers() {
        let server_cfg = tls13_server_cfg(false);
        let client_cfg = tls13_client_cfg(None);
        let mut client = Connection::client(&client_cfg).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        drive_pair(&mut client, &mut server);

        let mut ce = [0u8; 32];
        let mut se = [0u8; 32];
        client
            .tls_exporter(b"EXPORTER-test", b"ctx", &mut ce)
            .unwrap();
        server
            .tls_exporter(b"EXPORTER-test", b"ctx", &mut se)
            .unwrap();
        assert_eq!(ce, se, "exporter material must match across peers");

        let mut ce2 = [0u8; 32];
        client
            .tls_exporter(b"EXPORTER-other", b"ctx", &mut ce2)
            .unwrap();
        assert_ne!(ce, ce2, "different label must derive different material");
    }

    /// `take_session` yields `None` on a server engine and before any ticket;
    /// `write_early_data` is rejected on a non-(TLS 1.3 client) engine.
    #[test]
    fn session_and_early_data_guards() {
        let server_cfg = tls13_server_cfg(true);
        let mut server = Connection::server(&server_cfg).unwrap();
        assert!(server.take_session().is_none());
        assert!(matches!(
            server.write_early_data(b"x"),
            Err(Error::InappropriateState)
        ));
    }

    /// End-to-end TLS 1.3 PSK resumption through the public API: a first
    /// handshake yields a `ResumptionSession` via `take_session`; feeding it
    /// back through `ConfigBuilder::resumption_session` drives a second
    /// handshake that still completes and still agrees on an exporter.
    #[test]
    fn tls13_resumption_round_trip() {
        let server_cfg = tls13_server_cfg(true);
        let client_cfg = tls13_client_cfg(None);
        let mut client = Connection::client(&client_cfg).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        drive_pair(&mut client, &mut server);
        let session = client
            .take_session()
            .expect("server should have issued a NewSessionTicket");

        // Second connection, primed with the stored session.
        let resumed_client_cfg = tls13_client_cfg(Some(session));
        let mut client2 = Connection::client(&resumed_client_cfg).unwrap();
        let mut server2 = Connection::server(&server_cfg).unwrap();
        drive_pair(&mut client2, &mut server2);
        assert!(client2.is_handshake_complete() && server2.is_handshake_complete());

        let mut ce = [0u8; 16];
        let mut se = [0u8; 16];
        client2.tls_exporter(b"EXPORTER-r", b"", &mut ce).unwrap();
        server2.tls_exporter(b"EXPORTER-r", b"", &mut se).unwrap();
        assert_eq!(ce, se);
    }

    // RFC 6347 §4.2.1 / RFC 9147 §5.1: the cookie exchange is the DoS-
    // amplification mitigation. A server that intends to require it but
    // forgot to wire a cookie secret used to silently downgrade to "no
    // cookies" — the AND-combine of `require_cookie && cookie_secret`.

    /// ECH is a TLS-only feature in this crate: the DTLS engines never emit
    /// or process the extension, so a DTLS `Config` carrying an `EchClient`
    /// (even the GREASE form) or an `EchServer` must fail at construction
    /// rather than silently downgrade to a cleartext SNI.
    #[cfg(all(feature = "dtls", feature = "ech"))]
    #[test]
    fn dtls_refuses_ech_configuration() {
        use crate::tls::ech::keys::EchKeyRing;
        use crate::tls::ech::{EchClient, EchConfigList, EchServer};
        for version in [ProtocolVersion::DTLSv1_2, ProtocolVersion::DTLSv1_3] {
            // Client: ECH configured, DTLS negotiated.
            let cfg = Config::builder()
                .rng(alloc::sync::Arc::new(crate::rng::OsRng))
                .versions(version, version)
                .roots(RootCertStore::new())
                .server_name("dtls.example")
                .ech(EchClient::default_grease())
                .build();
            assert!(matches!(
                Connection::client(&cfg),
                Err(Error::InappropriateState)
            ));
            // Same config without ECH builds.
            let cfg = Config::builder()
                .rng(alloc::sync::Arc::new(crate::rng::OsRng))
                .versions(version, version)
                .roots(RootCertStore::new())
                .server_name("dtls.example")
                .build();
            assert!(Connection::client(&cfg).is_ok());

            // Server: an ECH key ring on a DTLS server config.
            let mut cfg = dtls_server_cfg_without_cookie_secret(version);
            cfg.cookie_secret = Some([0x42u8; 32].into());
            assert!(Connection::server(&cfg).is_ok());
            cfg.ech_server = Some(EchServer::new(
                EchKeyRing::from_pairs(alloc::vec![]),
                EchConfigList::new(alloc::vec![]),
            ));
            assert!(matches!(
                Connection::server(&cfg),
                Err(Error::InappropriateState)
            ));
        }
    }
    // Fail-closed: refuse to construct the engine.
    // Exercises the DTLS engine paths.
    #[cfg(feature = "dtls")]
    #[test]
    fn dtls_server_refuses_construction_without_cookie_secret() {
        // DTLS 1.2 path.
        let cfg = dtls_server_cfg_without_cookie_secret(ProtocolVersion::DTLSv1_2);
        assert!(cfg.require_cookie);
        assert!(cfg.cookie_secret.is_none());
        match Connection::server(&cfg) {
            Err(Error::InappropriateState) => {}
            Err(e) => panic!("expected InappropriateState, got {e:?}"),
            Ok(_) => panic!("DTLS 1.2 server must refuse construction"),
        }

        // DTLS 1.3 path.
        let cfg = dtls_server_cfg_without_cookie_secret(ProtocolVersion::DTLSv1_3);
        match Connection::server(&cfg) {
            Err(Error::InappropriateState) => {}
            Err(e) => panic!("expected InappropriateState, got {e:?}"),
            Ok(_) => panic!("DTLS 1.3 server must refuse construction"),
        }

        // Explicit secret -> allowed.
        let mut cfg = dtls_server_cfg_without_cookie_secret(ProtocolVersion::DTLSv1_3);
        cfg.cookie_secret = Some([0x42u8; 32].into());
        assert!(Connection::server(&cfg).is_ok());

        // Explicit opt-out (require_cookie = false) -> allowed.
        let mut cfg = dtls_server_cfg_without_cookie_secret(ProtocolVersion::DTLSv1_3);
        cfg.require_cookie = false;
        assert!(Connection::server(&cfg).is_ok());
    }

    /// The DTLS engines never emit a `CertificateRequest`, so a `client_auth`
    /// configuration on a DTLS server would be silently ignored — access
    /// control failing open. Construction must fail closed instead.
    // Exercises the DTLS engine paths.
    #[cfg(feature = "dtls")]
    #[test]
    fn dtls_server_refuses_client_auth() {
        for version in [ProtocolVersion::DTLSv1_2, ProtocolVersion::DTLSv1_3] {
            let mut cfg = dtls_server_cfg_without_cookie_secret(version);
            cfg.require_cookie = false;
            // Sanity: without client auth the same config builds.
            assert!(Connection::server(&cfg).is_ok());

            cfg.client_auth = Some(super::super::config::ClientAuth {
                roots: RootCertStore::new(),
                required: true,
            });
            match Connection::server(&cfg) {
                Err(Error::UnsupportedVersion) => {}
                Err(e) => panic!("expected UnsupportedVersion, got {e:?}"),
                Ok(_) => panic!("{version:?} server must refuse a client_auth config"),
            }

            // Even the non-`required` (request-only) form is refused: we
            // cannot request anything.
            cfg.client_auth = Some(super::super::config::ClientAuth {
                roots: RootCertStore::new(),
                required: false,
            });
            assert!(Connection::server(&cfg).is_err());
        }
    }

    /// Pump two DTLS [`Connection`]s (one datagram per `pop`) until both
    /// sides report a completed handshake. Panics if it stalls.
    #[cfg(feature = "dtls")]
    fn drive_dtls_pair(client: &mut Connection, server: &mut Connection) {
        for _ in 0..64 {
            loop {
                let out = client.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                server.feed(&out).unwrap();
            }
            loop {
                let out = server.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                client.feed(&out).unwrap();
            }
            if client.is_handshake_complete() && server.is_handshake_complete() {
                return;
            }
        }
        panic!("DTLS handshake did not complete");
    }

    /// A DTLS client `Config` (verification off, SNI `dtls.example`) pinned
    /// to `version`.
    #[cfg(feature = "dtls")]
    fn dtls_client_builder(version: ProtocolVersion) -> super::super::ConfigBuilder {
        Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(version, version)
            .verify_certificates(false)
            .server_name("dtls.example")
    }

    /// `Config::cipher_suites` used to be silently ignored by the DTLS
    /// clients (the full suite set was offered whatever the caller wrote).
    /// It now restricts the offer exactly as over TLS — the negotiated suite
    /// is the one listed — and fails closed with `NoUsableCipherSuites` when
    /// the list matches nothing the engine supports.
    #[cfg(feature = "dtls")]
    #[test]
    fn dtls_client_honours_cipher_suites_restriction() {
        const ECDHE_ECDSA_CHACHA20: u16 = 0xCCA9;
        const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
        for (version, suite, other) in [
            (
                ProtocolVersion::DTLSv1_2,
                ECDHE_ECDSA_CHACHA20,
                TLS_CHACHA20_POLY1305_SHA256,
            ),
            (
                ProtocolVersion::DTLSv1_3,
                TLS_CHACHA20_POLY1305_SHA256,
                ECDHE_ECDSA_CHACHA20,
            ),
        ] {
            let mut server_cfg = dtls_server_cfg_without_cookie_secret(version);
            server_cfg.require_cookie = false;
            let client_cfg = dtls_client_builder(version).cipher_suites(&[suite]).build();
            let mut server = Connection::server(&server_cfg).unwrap();
            let mut client = Connection::client(&client_cfg).unwrap();
            drive_dtls_pair(&mut client, &mut server);
            assert_eq!(
                client.negotiated_cipher_suite(),
                Some(suite),
                "{version:?}: the client must negotiate the one suite it listed"
            );
            assert_eq!(server.negotiated_cipher_suite(), Some(suite));

            // A list naming only suites of the other DTLS version leaves this
            // engine nothing to offer: refuse at construction rather than
            // falling back to the full set.
            let client_cfg = dtls_client_builder(version)
                .cipher_suites(&[other, 0x0000])
                .build();
            assert!(matches!(
                Connection::client(&client_cfg),
                Err(Error::NoUsableCipherSuites)
            ));
        }
    }

    /// `Config::alpn_protocols` is negotiated over DTLS 1.2 and 1.3 (RFC
    /// 7301): the server picks the first of its own preferences the client
    /// offered and both sides report it; a client offer the server cannot
    /// match is refused (the server answers nothing), and a client that
    /// offered nothing negotiates nothing even against a server with
    /// preferences.
    #[cfg(feature = "dtls")]
    #[test]
    fn dtls_negotiates_alpn() {
        for version in [ProtocolVersion::DTLSv1_2, ProtocolVersion::DTLSv1_3] {
            let mut server_cfg = dtls_server_cfg_without_cookie_secret(version);
            server_cfg.require_cookie = false;
            server_cfg.alpn_protocols = alloc::vec![b"coap".to_vec(), b"h2".to_vec()];

            // Overlap: the server's first preference the client listed.
            let client_cfg = dtls_client_builder(version)
                .alpn(alloc::vec![b"h2".to_vec(), b"coap".to_vec()])
                .build();
            let mut server = Connection::server(&server_cfg).unwrap();
            let mut client = Connection::client(&client_cfg).unwrap();
            drive_dtls_pair(&mut client, &mut server);
            assert_eq!(client.alpn_selected(), Some(&b"coap"[..]), "{version:?}");
            assert_eq!(server.alpn_selected(), Some(&b"coap"[..]), "{version:?}");

            // No offer: nothing negotiated, handshake still completes.
            let client_cfg = dtls_client_builder(version).build();
            let mut server = Connection::server(&server_cfg).unwrap();
            let mut client = Connection::client(&client_cfg).unwrap();
            drive_dtls_pair(&mut client, &mut server);
            assert_eq!(client.alpn_selected(), None);
            assert_eq!(server.alpn_selected(), None);

            // No overlap: the server refuses the ClientHello (silently, as
            // for any unauthenticated rejection) and never completes.
            let client_cfg = dtls_client_builder(version)
                .alpn(alloc::vec![b"http/1.1".to_vec()])
                .build();
            let mut server = Connection::server(&server_cfg).unwrap();
            let mut client = Connection::client(&client_cfg).unwrap();
            for _ in 0..8 {
                loop {
                    let out = client.pop().unwrap();
                    if out.is_empty() {
                        break;
                    }
                    server.feed(&out).unwrap();
                }
                assert!(
                    server.pop().unwrap().is_empty(),
                    "{version:?}: a no-overlap ALPN offer must not be answered"
                );
            }
            assert!(!server.is_handshake_complete() && !client.is_handshake_complete());
        }
    }

    /// `Config::key_exchange_groups` and `key_shares` reach the DTLS engines
    /// as they do the TLS ones: the client offers (and shares) only what it
    /// listed, the server selects in its own order and steers a client that
    /// offered its choice without a share through a HelloRetryRequest
    /// (RFC 8446 §4.1.4, DTLS 1.3 only), and both report the group the
    /// handshake used. An empty restriction fails closed.
    #[cfg(feature = "dtls")]
    #[test]
    fn dtls_honours_key_exchange_groups() {
        use super::super::NamedGroup;
        for version in [ProtocolVersion::DTLSv1_2, ProtocolVersion::DTLSv1_3] {
            // The client pins P-384; the server's default order (X25519
            // first) does not matter — it can only pick what was offered.
            let mut server_cfg = dtls_server_cfg_without_cookie_secret(version);
            server_cfg.require_cookie = false;
            let client_cfg = dtls_client_builder(version)
                .key_exchange_groups(&[NamedGroup::Secp384r1])
                .build();
            let mut server = Connection::server(&server_cfg).unwrap();
            let mut client = Connection::client(&client_cfg).unwrap();
            drive_dtls_pair(&mut client, &mut server);
            assert_eq!(
                client.negotiated_group(),
                Some(NamedGroup::Secp384r1),
                "{version:?}"
            );
            assert_eq!(
                server.negotiated_group(),
                Some(NamedGroup::Secp384r1),
                "{version:?}"
            );

            // The server's list is its preference order, not the client's.
            let mut server_cfg = dtls_server_cfg_without_cookie_secret(version);
            server_cfg.require_cookie = false;
            server_cfg.key_exchange_groups =
                Some(alloc::vec![NamedGroup::Secp256r1, NamedGroup::X25519]);
            let client_cfg = dtls_client_builder(version)
                .key_exchange_groups(&[NamedGroup::X25519, NamedGroup::Secp256r1])
                .build();
            let mut server = Connection::server(&server_cfg).unwrap();
            let mut client = Connection::client(&client_cfg).unwrap();
            drive_dtls_pair(&mut client, &mut server);
            assert_eq!(
                server.negotiated_group(),
                Some(NamedGroup::Secp256r1),
                "{version:?}"
            );
            assert_eq!(
                client.negotiated_group(),
                Some(NamedGroup::Secp256r1),
                "{version:?}"
            );

            // Fail closed: nothing left to offer / accept.
            let client_cfg = dtls_client_builder(version)
                .key_exchange_groups(&[])
                .build();
            assert!(matches!(
                Connection::client(&client_cfg),
                Err(Error::HandshakeFailure)
            ));
            let mut server_cfg = dtls_server_cfg_without_cookie_secret(version);
            server_cfg.require_cookie = false;
            server_cfg.key_exchange_groups = Some(Vec::new());
            assert!(matches!(
                Connection::server(&server_cfg),
                Err(Error::HandshakeFailure)
            ));
        }

        // DTLS 1.2 has no ML-KEM hybrid: a list naming only that group
        // leaves the engine nothing, and is refused rather than widened.
        let client_cfg = dtls_client_builder(ProtocolVersion::DTLSv1_2)
            .key_exchange_groups(&[NamedGroup::X25519MlKem768])
            .build();
        assert!(matches!(
            Connection::client(&client_cfg),
            Err(Error::HandshakeFailure)
        ));

        // DTLS 1.3: a client sharing only X25519 against a server pinned
        // to P-256 goes through a HelloRetryRequest and ends on P-256 —
        // and the HRR shows in both reports.
        let version = ProtocolVersion::DTLSv1_3;
        let mut server_cfg = dtls_server_cfg_without_cookie_secret(version);
        server_cfg.require_cookie = false;
        server_cfg.key_exchange_groups = Some(alloc::vec![NamedGroup::Secp256r1]);
        let client_cfg = dtls_client_builder(version)
            .key_exchange_groups(&[NamedGroup::X25519, NamedGroup::Secp256r1])
            .key_shares(&[NamedGroup::X25519])
            .build();
        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();
        drive_dtls_pair(&mut client, &mut server);
        assert_eq!(client.negotiated_group(), Some(NamedGroup::Secp256r1));
        assert_eq!(server.negotiated_group(), Some(NamedGroup::Secp256r1));
        assert!(client.hello_retry_request_used());
        assert!(server.hello_retry_request_used());

        // Without a group change and without a cookie there is no HRR.
        let mut server_cfg = dtls_server_cfg_without_cookie_secret(version);
        server_cfg.require_cookie = false;
        let client_cfg = dtls_client_builder(version).build();
        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();
        drive_dtls_pair(&mut client, &mut server);
        assert!(!client.hello_retry_request_used());
        assert!(!server.hello_retry_request_used());
    }

    /// `Connection::request_key_update` and the `KeyUpdate` tallies work
    /// over DTLS 1.3 (RFC 9147 §8): the requester's write epoch advances
    /// once the peer ACKs, the peer answers `update_requested` with its own
    /// `KeyUpdate`, and data still flows both ways afterwards. DTLS 1.2 has
    /// no such mechanism and refuses.
    #[cfg(feature = "dtls")]
    #[test]
    fn dtls13_key_update_through_connection() {
        let version = ProtocolVersion::DTLSv1_3;
        let mut server_cfg = dtls_server_cfg_without_cookie_secret(version);
        server_cfg.require_cookie = false;
        let client_cfg = dtls_client_builder(version).build();
        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();
        drive_dtls_pair(&mut client, &mut server);

        client.request_key_update().unwrap();
        // A few exchanges: KeyUpdate → ACK + the server's own KeyUpdate →
        // ACK.
        for _ in 0..4 {
            drive_dtls_pair(&mut client, &mut server);
        }
        assert_eq!(client.sent_key_updates(), 1);
        assert_eq!(server.peer_key_updates(), 1);
        assert_eq!(server.sent_key_updates(), 1, "update_requested is answered");
        assert_eq!(client.peer_key_updates(), 1);

        client.send(b"after rekey").unwrap();
        server.send(b"and back").unwrap();
        drive_dtls_pair(&mut client, &mut server);
        assert_eq!(server.recv().unwrap(), b"after rekey");
        assert_eq!(client.recv().unwrap(), b"and back");

        let version = ProtocolVersion::DTLSv1_2;
        let mut server_cfg = dtls_server_cfg_without_cookie_secret(version);
        server_cfg.require_cookie = false;
        let client_cfg = dtls_client_builder(version).build();
        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();
        drive_dtls_pair(&mut client, &mut server);
        assert!(matches!(
            client.request_key_update(),
            Err(Error::InappropriateState)
        ));
    }

    /// `Connection::close` sends a protected `close_notify` over DTLS and
    /// `received_close_notify` reports the peer's (RFC 8446 §6.1 / RFC 5246
    /// §7.2.1): the peer can still answer in kind after receiving one, no
    /// application data can follow a sent one, and closing before the
    /// handshake completes (no keys to protect the alert with) is refused.
    #[cfg(feature = "dtls")]
    #[test]
    fn dtls_close_notify_through_connection() {
        for version in [ProtocolVersion::DTLSv1_2, ProtocolVersion::DTLSv1_3] {
            let mut server_cfg = dtls_server_cfg_without_cookie_secret(version);
            server_cfg.require_cookie = false;
            let client_cfg = dtls_client_builder(version).build();
            let mut server = Connection::server(&server_cfg).unwrap();
            let mut client = Connection::client(&client_cfg).unwrap();
            assert!(
                matches!(client.close(), Err(Error::InappropriateState)),
                "{version:?}: no keys before the handshake"
            );
            drive_dtls_pair(&mut client, &mut server);

            client.close().unwrap();
            assert!(matches!(
                client.send(b"late"),
                Err(Error::InappropriateState)
            ));
            let alert = client.pop().unwrap();
            assert!(!alert.is_empty(), "{version:?}: the alert is queued");
            assert!(!server.received_close_notify());
            server.feed(&alert).unwrap();
            assert!(server.received_close_notify(), "{version:?}");
            // The answer, after the peer's close_notify.
            server.close().unwrap();
            let reply = server.pop().unwrap();
            assert!(!reply.is_empty());
            assert!(!client.received_close_notify());
            client.feed(&reply).unwrap();
            assert!(client.received_close_notify(), "{version:?}");
        }
    }

    /// `Config` options the DTLS engines cannot honour, and whose silent
    /// loss would weaken what the caller asked for, are refused at
    /// construction with `InappropriateState` instead of being dropped:
    /// a client identity (the DTLS engines never send a `Certificate`), a
    /// `record_size_limit` (RFC 8449 is not implemented over DTLS), and RFC
    /// 7250 raw public keys / certificate-type preferences on either side.
    #[cfg(feature = "dtls")]
    #[test]
    fn dtls_refuses_options_it_cannot_honour() {
        type ClientTweak<'a> =
            Box<dyn Fn(super::super::ConfigBuilder) -> super::super::ConfigBuilder + 'a>;
        type ServerTweak = Box<dyn Fn(&mut Config)>;
        let (key, leaf) = ecdsa_identity(b"dtls-unsupported", "client.example");
        for version in [ProtocolVersion::DTLSv1_2, ProtocolVersion::DTLSv1_3] {
            // Control: the plain client and server configs build.
            assert!(Connection::client(&dtls_client_builder(version).build()).is_ok());
            let mut server_cfg = dtls_server_cfg_without_cookie_secret(version);
            server_cfg.require_cookie = false;
            assert!(Connection::server(&server_cfg).is_ok());

            let client_variants: [ClientTweak<'_>; 5] = [
                Box::new(|b| {
                    b.identity(
                        alloc::vec![leaf.clone()],
                        super::super::config::SigningKey::Ecdsa(key.clone()),
                    )
                }),
                Box::new(|b| b.record_size_limit(1000)),
                Box::new(|b| b.server_cert_type_preference(alloc::vec![2, 0])),
                Box::new(|b| b.add_expected_raw_public_key(alloc::vec![0x30, 0x00])),
                Box::new(|b| b.raw_public_key_spki(alloc::vec![0x30, 0x00])),
            ];
            for (i, variant) in client_variants.iter().enumerate() {
                let cfg = variant(dtls_client_builder(version)).build();
                assert!(
                    matches!(Connection::client(&cfg), Err(Error::InappropriateState)),
                    "{version:?}: client variant {i} must be refused"
                );
            }

            let server_variants: [ServerTweak; 4] = [
                Box::new(|c| c.record_size_limit = Some(1000)),
                Box::new(|c| c.client_cert_type_preference = alloc::vec![2, 0]),
                Box::new(|c| {
                    c.expected_client_raw_public_keys = alloc::vec![alloc::vec![0x30, 0x00]]
                }),
                Box::new(|c| c.raw_public_key_spki = Some(alloc::vec![0x30, 0x00])),
            ];
            for (i, variant) in server_variants.iter().enumerate() {
                let mut cfg = server_cfg.clone();
                variant(&mut cfg);
                assert!(
                    matches!(Connection::server(&cfg), Err(Error::InappropriateState)),
                    "{version:?}: server variant {i} must be refused"
                );
            }
        }
    }

    /// `server_name` is required only when certificate verification is on.
    ///
    /// When verifying (audit F1), a missing name must be rejected at
    /// construction rather than silently substituted — the old `"localhost"`
    /// substitution was a footgun, since any local cert listing `localhost` as a
    /// SAN would then satisfy verification for an unintended peer. But with
    /// verification *off* there is nothing to verify against, so a name is
    /// optional (e.g. connecting to a device by IP); the engines simply omit the
    /// SNI extension. This holds across every TLS/DTLS engine path.
    // Exercises the DTLS engine paths.
    #[cfg(feature = "dtls")]
    #[test]
    fn client_server_name_required_only_when_verifying() {
        for v in [
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_2,
            ProtocolVersion::DTLSv1_3,
            ProtocolVersion::DTLSv1_2,
        ] {
            // verify on (default) + no server_name → rejected at construction.
            let cfg = Config::builder()
                .rng(alloc::sync::Arc::new(crate::rng::OsRng))
                .versions(v, v)
                .build();
            assert!(cfg.verify_certificates && cfg.server_name.is_none());
            match Connection::client(&cfg) {
                Err(Error::MissingServerName) => {}
                Err(e) => panic!("{v:?}: expected MissingServerName, got {e:?}"),
                Ok(_) => panic!("{v:?}: verifying client must require server_name"),
            }

            // verify off + no server_name → allowed (no SNI, no hostname check).
            let cfg = Config::builder()
                .rng(alloc::sync::Arc::new(crate::rng::OsRng))
                .versions(v, v)
                .verify_certificates(false)
                .build();
            assert!(cfg.server_name.is_none());
            assert!(
                Connection::client(&cfg).is_ok(),
                "{v:?}: verify-off client must not require server_name"
            );

            // With an explicit server_name, construction succeeds either way.
            let cfg = Config::builder()
                .rng(alloc::sync::Arc::new(crate::rng::OsRng))
                .versions(v, v)
                .verify_certificates(false)
                .server_name("example.test")
                .build();
            assert!(Connection::client(&cfg).is_ok(), "{v:?}: explicit SNI ok");
        }
    }

    /// A non-empty `cipher_suites` restriction that excludes every suite the
    /// configured version supports must refuse construction. The old
    /// behaviour silently fell back to the engine's full default set, so a
    /// typo'd suite ID (or a list meant for the other protocol version)
    /// re-enabled everything the caller had deliberately disabled.
    #[test]
    fn cipher_suite_restriction_with_no_match_fails_closed() {
        let client_cfg = |max: ProtocolVersion, suites: &[u16]| {
            Config::builder()
                .rng(alloc::sync::Arc::new(crate::rng::OsRng))
                .versions(max, max)
                .verify_certificates(false)
                .server_name("example.test")
                .cipher_suites(suites)
                .build()
        };

        // A TLS-1.3-only list handed to the TLS 1.2 engine, and vice versa.
        for (v, suites) in [
            (ProtocolVersion::TLSv1_2, &[0x1301u16, 0x1302, 0x1303][..]),
            (ProtocolVersion::TLSv1_3, &[0xC02Fu16, 0xC030][..]),
            // A typo'd / unknown codepoint matching nothing at all.
            (ProtocolVersion::TLSv1_3, &[0x1300u16][..]),
            // Explicitly empty is a vacuous restriction, not "defaults".
            (ProtocolVersion::TLSv1_2, &[][..]),
        ] {
            match Connection::client(&client_cfg(v, suites)) {
                Err(Error::NoUsableCipherSuites) => {}
                Err(e) => panic!("{v:?}/{suites:?}: expected NoUsableCipherSuites, got {e:?}"),
                Ok(_) => panic!("{v:?}/{suites:?}: empty intersection must fail closed"),
            }
        }

        // A list that matches at least one suite of the engine's version
        // range still constructs — extra IDs from the other version are
        // simply not offered.
        let cfg = client_cfg(ProtocolVersion::TLSv1_2, &[0x1301, 0xC02F]);
        assert!(Connection::client(&cfg).is_ok(), "partial match must work");
        let cfg = client_cfg(ProtocolVersion::TLSv1_3, &[0x1301, 0xC02F]);
        assert!(Connection::client(&cfg).is_ok(), "partial match must work");

        // Unset (None) keeps meaning "offer the defaults".
        let cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .verify_certificates(false)
            .server_name("example.test")
            .build();
        assert!(cfg.cipher_suites.is_none());
        assert!(Connection::client(&cfg).is_ok());
    }

    /// `cipher_suite_name` covers every suite the negotiator can pick,
    /// plus the unknown-fallback case.
    #[test]
    fn cipher_suite_name_table() {
        assert_eq!(cipher_suite_name(0x1301), "TLS_AES_128_GCM_SHA256");
        assert_eq!(cipher_suite_name(0x1302), "TLS_AES_256_GCM_SHA384");
        assert_eq!(cipher_suite_name(0x1303), "TLS_CHACHA20_POLY1305_SHA256");
        assert_eq!(
            cipher_suite_name(0xC02B),
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        );
        assert_eq!(
            cipher_suite_name(0xC02C),
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        );
        assert_eq!(
            cipher_suite_name(0xC02F),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
        assert_eq!(
            cipher_suite_name(0xC030),
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        );
        assert_eq!(
            cipher_suite_name(0xCCA8),
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        );
        assert_eq!(
            cipher_suite_name(0xCCA9),
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        );
        assert_eq!(cipher_suite_name(0xFFFF), "UNKNOWN");
    }

    /// Before any wire bytes are exchanged the suite is undetermined on
    /// every engine variant. (Once the handshake progresses far enough
    /// the existing per-engine loopback tests in `tls::conn::mod` /
    /// `dtls::*` verify the positive case.)
    #[test]
    fn negotiated_cipher_suite_is_none_before_handshake() {
        let mut rng = HmacDrbg::<Sha256>::new(b"suite-none", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &DistinguishedName::common_name("suite.example"),
            &validity,
            1,
            false,
            &["suite.example"],
        )
        .unwrap();

        // TLS 1.3 client (cipher selected from ServerHello — None
        // before any bytes flow in).
        let cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .tls_only()
            .server_name("suite.example")
            .build();
        let client = Connection::client(&cfg).unwrap();
        assert!(client.negotiated_cipher_suite().is_none());
        assert!(client.negotiated_cipher_suite_name().is_none());

        // TLS 1.3 server (cipher selected during ClientHello dispatch).
        let cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .tls_only()
            .identity(
                alloc::vec![cert.to_der().to_vec()],
                super::super::config::SigningKey::Ecdsa(key),
            )
            .build();
        let server = Connection::server(&cfg).unwrap();
        assert!(server.negotiated_cipher_suite().is_none());
    }

    /// A caller-supplied [`EntropySource`] (here an HMAC-DRBG behind a mutex)
    /// must feed every server-side random draw — server random, ephemeral
    /// (EC)DHE key, signature salts — so a full TLS 1.3 handshake completes
    /// with `Config::rng` set instead of the default `OsRng`.
    #[test]
    fn server_drives_handshake_from_injected_entropy_source() {
        struct DrbgSource(std::sync::Mutex<HmacDrbg<Sha256>>);
        impl EntropySource for DrbgSource {
            fn fill(&self, dest: &mut [u8]) {
                self.0.lock().unwrap().fill_bytes(dest);
            }
        }

        let mut kg = HmacDrbg::<Sha256>::new(b"rng-inject-leaf", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut kg);
        let name = DistinguishedName::common_name("rng.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            false,
            &["rng.example"],
        )
        .unwrap();

        let source: alloc::sync::Arc<dyn EntropySource> = alloc::sync::Arc::new(DrbgSource(
            std::sync::Mutex::new(HmacDrbg::<Sha256>::new(b"entropy-source", b"nonce", &[])),
        ));
        let server_cfg = Config::builder()
            .tls_only()
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .identity(
                alloc::vec![cert.to_der().to_vec()],
                super::super::config::SigningKey::Ecdsa(key),
            )
            .rng(source)
            .build();
        let client_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .verify_certificates(false)
            .server_name("rng.example")
            .build();

        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();

        // Pump client <-> server until both sides finish (TLS 1.3 is 1-RTT, so
        // a handful of iterations is plenty).
        for _ in 0..16 {
            loop {
                let out = client.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                server.feed(&out).unwrap();
            }
            loop {
                let out = server.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                client.feed(&out).unwrap();
            }
            if client.is_handshake_complete() && server.is_handshake_complete() {
                break;
            }
        }
        assert!(
            client.is_handshake_complete() && server.is_handshake_complete(),
            "TLS 1.3 handshake must complete using the injected EntropySource"
        );
    }

    /// The sans-I/O engine never invents entropy: a `Config` with no
    /// `EntropySource` fails closed at construction rather than reaching for a
    /// hidden `OsRng`. Covers both roles across TLS and DTLS.
    // Exercises the DTLS engine paths.
    #[cfg(feature = "dtls")]
    #[test]
    fn construction_requires_an_entropy_source() {
        for v in [
            ProtocolVersion::TLSv1_3,
            ProtocolVersion::TLSv1_2,
            ProtocolVersion::DTLSv1_3,
            ProtocolVersion::DTLSv1_2,
        ] {
            // Client: no rng, verification off + a name so server_name is not
            // the failure → the missing entropy source must be what trips.
            let client_cfg = Config::builder()
                .versions(v, v)
                .verify_certificates(false)
                .server_name("rng.example")
                .build();
            assert!(client_cfg.rng.is_none());
            assert!(matches!(
                Connection::client(&client_cfg),
                Err(Error::MissingEntropySource)
            ));

            // Same config but WITH an OsRng source constructs fine.
            let ok_cfg = Config::builder()
                .versions(v, v)
                .verify_certificates(false)
                .server_name("rng.example")
                .rng(alloc::sync::Arc::new(crate::rng::OsRng))
                .build();
            assert!(Connection::client(&ok_cfg).is_ok());
        }

        // Server path (TLS 1.3): an identity but no rng → MissingEntropySource.
        let (key, leaf) = ecdsa_p256_identity();
        let server_cfg = Config::builder()
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .identity(
                alloc::vec![leaf],
                super::super::config::SigningKey::Ecdsa(key),
            )
            .build();
        assert!(matches!(
            Connection::server(&server_cfg),
            Err(Error::MissingEntropySource)
        ));
    }

    /// A self-signed ECDSA P-256 leaf + its key (seeded for reproducibility),
    /// for external-signing tests. `cn` is used as both the subject CN and the
    /// single DNS SAN.
    fn ecdsa_identity(seed: &[u8], cn: &str) -> (BoxedEcdsaPrivateKey, Vec<u8>) {
        let mut kg = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut kg);
        let name = DistinguishedName::common_name(cn);
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            // A self-signed cert used as a client-auth trust anchor must be a CA.
            true,
            &[cn],
        )
        .unwrap();
        (key, cert.to_der().to_vec())
    }

    /// A self-signed ECDSA P-256 leaf + its key, for external-signing tests.
    fn ecdsa_p256_identity() -> (BoxedEcdsaPrivateKey, Vec<u8>) {
        ecdsa_identity(b"ext-sign-leaf", "ext.example")
    }

    /// A TLS 1.3 server using `SigningKey::External` completes the handshake
    /// when the caller fulfils the `signature_request` out-of-band (here with
    /// an in-process ECDSA key standing in for an HSM). Completion implies the
    /// client verified the externally-produced CertificateVerify, so the
    /// suspend/resume produces a wire-valid signature.
    #[test]
    fn server_external_signing_round_trips() {
        const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
        let (key, leaf) = ecdsa_p256_identity();

        let server_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .identity(
                alloc::vec![leaf],
                super::super::config::SigningKey::External {
                    schemes: alloc::vec![ECDSA_SECP256R1_SHA256],
                },
            )
            .build();
        let client_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .verify_certificates(false)
            .server_name("ext.example")
            .build();

        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();

        let mut signed = false;
        for _ in 0..32 {
            loop {
                let out = client.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                server.feed(&out).unwrap();
            }
            // Fulfil a pending external signature: sign exactly as the in-process
            // ECDSA path would (P-256 → ECDSA-SHA256, DER-encoded).
            if let Some(req) = server.signature_request() {
                assert_eq!(req.scheme, ECDSA_SECP256R1_SHA256);
                let sig = key
                    .sign::<Sha256>(&req.message)
                    .unwrap()
                    .to_der(CurveId::P256);
                server.provide_signature(sig).unwrap();
                signed = true;
            }
            loop {
                let out = server.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                client.feed(&out).unwrap();
            }
            if client.is_handshake_complete() && server.is_handshake_complete() {
                break;
            }
        }
        assert!(
            signed,
            "the server must have requested an external signature"
        );
        assert!(
            client.is_handshake_complete() && server.is_handshake_complete(),
            "external-signed TLS 1.3 handshake must complete and verify"
        );
    }

    /// mTLS with an **external client** key: the client's `CertificateVerify`
    /// is produced out-of-band via the suspend/resume API, and the server (which
    /// requires and verifies client auth) completes the handshake — proving the
    /// externally-produced client signature verified.
    #[test]
    fn client_mtls_external_signing_round_trips() {
        const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
        let (server_key, server_leaf) = ecdsa_identity(b"mtls-server", "srv.example");
        let (client_key, client_leaf) = ecdsa_identity(b"mtls-client", "cli.example");

        // Server: inline identity; requires + verifies client auth against the
        // client's self-signed cert as trust anchor.
        let mut roots = crate::tls::RootCertStore::new();
        roots.add_der(client_leaf.clone()).unwrap();
        let server_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .identity(
                alloc::vec![server_leaf],
                super::super::config::SigningKey::Ecdsa(server_key),
            )
            .client_auth(crate::tls::ClientAuth::new(roots, true))
            .build();

        // Client: external identity; does not verify the server here.
        let client_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .verify_certificates(false)
            .server_name("srv.example")
            .identity(
                alloc::vec![client_leaf],
                super::super::config::SigningKey::External {
                    schemes: alloc::vec![ECDSA_SECP256R1_SHA256],
                },
            )
            .build();

        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();

        let mut signed = false;
        for _ in 0..32 {
            loop {
                let out = client.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                server.feed(&out).unwrap();
            }
            loop {
                let out = server.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                client.feed(&out).unwrap();
            }
            // The client suspends to sign its own CertificateVerify.
            if let Some(req) = client.signature_request() {
                assert_eq!(req.scheme, ECDSA_SECP256R1_SHA256);
                let sig = client_key
                    .sign::<Sha256>(&req.message)
                    .unwrap()
                    .to_der(CurveId::P256);
                client.provide_signature(sig).unwrap();
                signed = true;
            }
            if client.is_handshake_complete() && server.is_handshake_complete() {
                break;
            }
        }
        assert!(
            signed,
            "the client must have requested an external signature"
        );
        assert!(
            client.is_handshake_complete() && server.is_handshake_complete(),
            "external-signed client mTLS handshake must complete and verify"
        );
    }

    /// A DTLS 1.3 server using `SigningKey::External` completes the handshake
    /// when the caller fulfils `signature_request` out-of-band — the
    /// suspend/resume path works over the datagram engine too.
    // Exercises the DTLS engine paths.
    #[cfg(feature = "dtls")]
    #[test]
    fn dtls13_server_external_signing_round_trips() {
        const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
        let (key, leaf) = ecdsa_identity(b"dtls-ext", "dtls.example");

        let mut server_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::DTLSv1_3, ProtocolVersion::DTLSv1_3)
            .identity(
                alloc::vec![leaf],
                super::super::config::SigningKey::External {
                    schemes: alloc::vec![ECDSA_SECP256R1_SHA256],
                },
            )
            .build();
        // Keep the test single-round: skip the cookie exchange.
        server_cfg.require_cookie = false;
        let client_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::DTLSv1_3, ProtocolVersion::DTLSv1_3)
            .verify_certificates(false)
            .server_name("dtls.example")
            .build();

        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();

        let mut signed = false;
        for _ in 0..64 {
            loop {
                let out = client.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                server.feed(&out).unwrap();
            }
            if let Some(req) = server.signature_request() {
                assert_eq!(req.scheme, ECDSA_SECP256R1_SHA256);
                let sig = key
                    .sign::<Sha256>(&req.message)
                    .unwrap()
                    .to_der(CurveId::P256);
                server.provide_signature(sig).unwrap();
                signed = true;
            }
            loop {
                let out = server.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                client.feed(&out).unwrap();
            }
            if client.is_handshake_complete() && server.is_handshake_complete() {
                break;
            }
        }
        assert!(
            signed,
            "the DTLS server must have requested an external signature"
        );
        assert!(
            client.is_handshake_complete() && server.is_handshake_complete(),
            "external-signed DTLS 1.3 handshake must complete and verify"
        );
    }

    /// DTLS 1.2 signs the `ServerKeyExchange` (not a CertificateVerify), so the
    /// suspend/resume seam sits at a different point in the flight than 1.3.
    /// Drive a full loopback handshake where the server's identity is an
    /// `External` ECDSA key and the test "HSM" signs the SKE bytes out-of-band.
    // Exercises the DTLS engine paths.
    #[cfg(feature = "dtls")]
    #[test]
    fn dtls12_server_external_signing_round_trips() {
        const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
        let (key, leaf) = ecdsa_identity(b"dtls12-ext", "dtls12.example");

        let mut server_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::DTLSv1_2, ProtocolVersion::DTLSv1_2)
            .identity(
                alloc::vec![leaf],
                super::super::config::SigningKey::External {
                    schemes: alloc::vec![ECDSA_SECP256R1_SHA256],
                },
            )
            .build();
        // Keep the test single-round: skip the cookie exchange.
        server_cfg.require_cookie = false;
        let client_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::DTLSv1_2, ProtocolVersion::DTLSv1_2)
            .verify_certificates(false)
            .server_name("dtls12.example")
            .build();

        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();

        let mut signed = false;
        for _ in 0..64 {
            loop {
                let out = client.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                server.feed(&out).unwrap();
            }
            if let Some(req) = server.signature_request() {
                assert_eq!(req.scheme, ECDSA_SECP256R1_SHA256);
                let sig = key
                    .sign::<Sha256>(&req.message)
                    .unwrap()
                    .to_der(CurveId::P256);
                server.provide_signature(sig).unwrap();
                signed = true;
            }
            loop {
                let out = server.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                client.feed(&out).unwrap();
            }
            if client.is_handshake_complete() && server.is_handshake_complete() {
                break;
            }
        }
        assert!(
            signed,
            "the DTLS 1.2 server must have requested an external signature"
        );
        assert!(
            client.is_handshake_complete() && server.is_handshake_complete(),
            "external-signed DTLS 1.2 handshake must complete and verify"
        );
    }

    /// If the client offers no signature scheme the external key advertises,
    /// the server aborts the handshake (handshake_failure) rather than stalling.
    #[test]
    fn server_external_signing_rejects_disjoint_schemes() {
        // Advertise only an unassigned scheme no client ever offers, so the
        // intersection with the ClientHello's signature_algorithms is empty.
        const UNOFFERED: u16 = 0xFFFF;
        let (_key, leaf) = ecdsa_p256_identity();
        let server_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .identity(
                alloc::vec![leaf],
                super::super::config::SigningKey::External {
                    schemes: alloc::vec![UNOFFERED],
                },
            )
            .build();
        let client_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .verify_certificates(false)
            .server_name("ext.example")
            .build();
        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();

        let ch = client.pop().unwrap();
        // The server rejects the ClientHello: no scheme its key can produce was
        // offered. It must error, not suspend awaiting a signature.
        let res = server.feed(&ch);
        assert!(
            res.is_err(),
            "disjoint signature schemes must fail the handshake"
        );
        assert!(server.signature_request().is_none());
    }

    /// `Connection::drive()` brokers an in-process key through the transparent
    /// `HandshakeSigner` path (via `LocalSigner`) without ever yielding `WantSigner`:
    /// the same loop a device key would use also completes a normal handshake.
    #[test]
    fn drive_with_local_signer_completes_without_signer_step() {
        use super::super::signer::LocalSigner;
        use alloc::sync::Arc;

        let (key, leaf) = ecdsa_p256_identity();
        let server_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .private_key(
                alloc::vec![leaf],
                Arc::new(LocalSigner::new(super::super::config::SigningKey::Ecdsa(
                    key,
                ))),
            )
            .build();
        let client_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .verify_certificates(false)
            .server_name("ext.example")
            .build();

        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();

        // Drive the server via drive(); the client via the plain loop.
        let mut saw_signer_step = false;
        for _ in 0..32 {
            loop {
                let out = client.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                server.feed(&out).unwrap();
            }
            // Pump the server with drive() until it needs peer bytes / is done.
            loop {
                match server.drive().unwrap() {
                    Step::WantWrite => {
                        let out = server.pop().unwrap();
                        if out.is_empty() {
                            break;
                        }
                        client.feed(&out).unwrap();
                    }
                    Step::WantSigner(_) => saw_signer_step = true,
                    Step::WantRead | Step::Complete => break,
                }
            }
            if client.is_handshake_complete() && server.is_handshake_complete() {
                break;
            }
        }
        assert!(
            !saw_signer_step,
            "an in-process LocalSigner must never yield WantSigner"
        );
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
    }

    /// A `LocalSigner` around an RSA key advertises both RSA-PSS families,
    /// and the server engine narrows them to the one the leaf's SPKI form
    /// permits (RFC 8446 §4.2.3): installed with an `id-RSASSA-PSS` leaf
    /// pinned to SHA-384 the server signs `rsa_pss_pss_sha384`, with an
    /// `rsaEncryption` leaf `rsa_pss_rsae_sha256`. The client verifies the
    /// CertificateVerify under the leaf key — which refuses the other
    /// family — so a completed handshake pins the choice.
    #[test]
    fn local_signer_rsa_follows_the_leaf_spki_form() {
        use super::super::signer::{HandshakeSigner, LocalSigner};
        use crate::rsa::BoxedRsaPrivateKey;
        use crate::x509::{CertSigner, Certificate, DistinguishedName, PssHash, Time, Validity};
        use alloc::sync::Arc;

        let key = crate::test_util::rsa_test_key_a();
        let boxed = BoxedRsaPrivateKey::from_pkcs1_der(&key.to_pkcs1_der()).unwrap();
        let name = DistinguishedName::common_name("ext.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let pss_leaf = Certificate::self_signed_general(
            &CertSigner::RsaPss(&boxed, PssHash::Sha384),
            &name,
            &validity,
            1,
            false,
            &["ext.example"],
        )
        .unwrap()
        .to_der()
        .to_vec();
        let rsae_leaf = Certificate::self_signed_general(
            &CertSigner::Rsa(&boxed),
            &name,
            &validity,
            2,
            false,
            &["ext.example"],
        )
        .unwrap()
        .to_der()
        .to_vec();
        let signer: Arc<dyn HandshakeSigner> = Arc::new(LocalSigner::new(
            super::super::config::SigningKey::Rsa(boxed),
        ));
        assert_eq!(signer.schemes(), [0x0804, 0x0809, 0x080A, 0x080B]);

        for leaf in [pss_leaf, rsae_leaf] {
            let server_cfg = Config::builder()
                .rng(Arc::new(crate::rng::OsRng))
                .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
                .try_private_key(alloc::vec![leaf], signer.clone())
                .unwrap()
                .build();
            let client_cfg = Config::builder()
                .rng(Arc::new(crate::rng::OsRng))
                .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
                .verify_certificates(false)
                .server_name("ext.example")
                .build();
            let mut server = Connection::server(&server_cfg).unwrap();
            let mut client = Connection::client(&client_cfg).unwrap();
            // The server side goes through `drive()`, which brokers the
            // signer; the client through the plain loop.
            for _ in 0..32 {
                loop {
                    let out = client.pop().unwrap();
                    if out.is_empty() {
                        break;
                    }
                    server.feed(&out).unwrap();
                }
                loop {
                    match server.drive().unwrap() {
                        Step::WantWrite => {
                            let out = server.pop().unwrap();
                            if out.is_empty() {
                                break;
                            }
                            client.feed(&out).unwrap();
                        }
                        Step::WantSigner(_) => panic!("LocalSigner never yields WantSigner"),
                        Step::WantRead | Step::Complete => break,
                    }
                }
                if client.is_handshake_complete() && server.is_handshake_complete() {
                    break;
                }
            }
            assert!(client.is_handshake_complete() && server.is_handshake_complete());
        }
    }

    /// A device-backed `HandshakeSigner` whose `SignOp` returns `Pending` once
    /// (exposing a real, readable fd) before producing the signature drives a
    /// full handshake through `drive()` — exercising the `WantSigner` path and
    /// `Readiness::wait()`. The "device" is an in-process ECDSA key behind a
    /// `UnixStream` whose peer end is pre-armed so `wait()` returns at once.
    #[cfg(unix)]
    #[test]
    fn drive_with_device_signer_round_trips() {
        use super::super::signer::{HandshakeSigner, Readiness, SignOp, SignProgress};
        use alloc::sync::Arc;
        use std::os::fd::{AsFd, AsRawFd};
        use std::os::unix::net::UnixStream;

        const ECDSA_SECP256R1_SHA256: u16 = 0x0403;

        struct DeviceKey {
            key: BoxedEcdsaPrivateKey,
        }
        struct DeviceOp {
            key: BoxedEcdsaPrivateKey,
            message: Vec<u8>,
            // `near` is the fd we expose; `_far` keeps the peer end (and its
            // pre-written byte) alive so `near` stays readable.
            near: UnixStream,
            _far: UnixStream,
            polled: bool,
        }
        impl HandshakeSigner for DeviceKey {
            fn schemes(&self) -> Vec<u16> {
                alloc::vec![ECDSA_SECP256R1_SHA256]
            }
            fn start_sign(&self, _scheme: u16, message: &[u8]) -> Result<Box<dyn SignOp>, Error> {
                use std::io::Write;
                let (near, mut far) = UnixStream::pair().unwrap();
                // Pre-arm: a byte already waiting makes `near` readable, so the
                // test's wait() returns immediately (no real device latency).
                far.write_all(b"x").unwrap();
                Ok(Box::new(DeviceOp {
                    key: self.key.clone(),
                    message: message.to_vec(),
                    near,
                    _far: far,
                    polled: false,
                }))
            }
        }
        impl SignOp for DeviceOp {
            fn resume(&mut self) -> Result<SignProgress, Error> {
                if !self.polled {
                    // First step: not ready yet — make the caller wait.
                    self.polled = true;
                    return Ok(SignProgress::Pending);
                }
                let sig = self
                    .key
                    .sign::<Sha256>(&self.message)
                    .unwrap()
                    .to_der(CurveId::P256);
                Ok(SignProgress::Done(sig))
            }
            fn readiness(&self) -> Option<Readiness> {
                Some(Readiness::from_raw_fd(self.near.as_raw_fd()))
            }
        }

        let (key, leaf) = ecdsa_p256_identity();
        let server_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .private_key(alloc::vec![leaf], Arc::new(DeviceKey { key }))
            .build();
        let client_cfg = Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .verify_certificates(false)
            .server_name("ext.example")
            .build();

        let mut server = Connection::server(&server_cfg).unwrap();
        let mut client = Connection::client(&client_cfg).unwrap();

        let mut waited = false;
        for _ in 0..32 {
            loop {
                let out = client.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                server.feed(&out).unwrap();
            }
            loop {
                match server.drive().unwrap() {
                    Step::WantWrite => {
                        let out = server.pop().unwrap();
                        if out.is_empty() {
                            break;
                        }
                        client.feed(&out).unwrap();
                    }
                    Step::WantSigner(r) => {
                        if let Some(r) = r {
                            // Exercise the async-facing seam too: the std fd
                            // traits must yield the same valid descriptor an
                            // `AsyncFd`/`SourceFd` would register.
                            assert!(r.as_raw_fd() >= 0);
                            assert_eq!(r.as_fd().as_raw_fd(), r.as_raw_fd());
                            // Then the sync path: block until readable.
                            r.wait().unwrap();
                            waited = true;
                        }
                    }
                    Step::WantRead | Step::Complete => break,
                }
            }
            if client.is_handshake_complete() && server.is_handshake_complete() {
                break;
            }
        }
        assert!(waited, "the device SignOp must have suspended on its fd");
        assert!(
            client.is_handshake_complete() && server.is_handshake_complete(),
            "device-signed handshake must complete and verify"
        );
    }

    /// A plaintext `close_notify` record injected before the handshake
    /// completes must be a hard error on every engine, and must never make
    /// the connection report a completed (i.e. peer-authenticated) handshake
    /// — not even when the caller ignores the error and drives again.
    #[test]
    fn injected_close_notify_before_handshake_never_completes() {
        // A warning-level close_notify in a TLS 1.2 plaintext record.
        const CLOSE_NOTIFY: &[u8] = &[21, 0x03, 0x03, 0, 2, 1, 0];

        let clients = [
            ("client-1.2", tls12_client_cfg()),
            ("client-1.3", tls13_client_cfg(None)),
            ("client-auto", auto_client_cfg()),
        ];
        for (name, cfg) in clients {
            let mut c = Connection::client(&cfg).unwrap();
            // Drain the ClientHello so `drive` cannot report `WantWrite`.
            let _ = c.pop().unwrap();
            assert!(
                matches!(
                    c.feed(CLOSE_NOTIFY),
                    Err(Error::AlertReceived(AlertDescription::CloseNotify))
                ),
                "{name}: pre-handshake close_notify must be fatal"
            );
            assert!(!c.is_handshake_complete(), "{name}");
            assert!(!c.received_close_notify(), "{name}");
            assert!(c.peer_certificates().is_empty(), "{name}");
            // A caller that ignores the error must not be told all is well.
            assert!(c.handshake().is_err(), "{name}");
            assert!(c.drive().is_err(), "{name}");
            assert!(c.send(b"secret").is_err(), "{name}");
        }

        let servers = [
            ("server-1.2", tls12_server_cfg()),
            ("server-1.3", tls13_server_cfg(false)),
        ];
        for (name, cfg) in servers {
            let mut s = Connection::server(&cfg).unwrap();
            assert!(
                matches!(
                    s.feed(CLOSE_NOTIFY),
                    Err(Error::AlertReceived(AlertDescription::CloseNotify))
                ),
                "{name}: pre-handshake close_notify must be fatal"
            );
            assert!(!s.is_handshake_complete(), "{name}");
            assert!(!s.received_close_notify(), "{name}");
            assert!(s.handshake().is_err(), "{name}");
            assert!(s.drive().is_err(), "{name}");
            assert!(s.send(b"secret").is_err(), "{name}");
        }

        // The version-spanning server never even resolves an engine: it must
        // report neither completion nor progress.
        let mut auto = Connection::server(&auto_server_cfg()).unwrap();
        let _ = auto.feed(CLOSE_NOTIFY);
        assert!(!auto.is_handshake_complete());
        assert!(auto.send(b"secret").is_err());
    }

    /// The same injection *mid-handshake* (after the ServerHello flight, while
    /// the client is still waiting for the server's Finished) is equally fatal.
    #[test]
    fn close_notify_mid_handshake_is_fatal() {
        const CLOSE_NOTIFY: &[u8] = &[21, 0x03, 0x03, 0, 2, 1, 0];
        let mut client = Connection::client(&tls12_client_cfg()).unwrap();
        let mut server = Connection::server(&tls12_server_cfg()).unwrap();
        let _ = client.handshake();
        let ch = client.pop().unwrap();
        server.feed(&ch).unwrap();
        let flight = server.pop().unwrap();
        client.feed(&flight).unwrap();
        assert!(!client.is_handshake_complete());
        assert!(matches!(
            client.feed(CLOSE_NOTIFY),
            Err(Error::AlertReceived(AlertDescription::CloseNotify))
        ));
        assert!(!client.is_handshake_complete());
        assert!(client.handshake().is_err());
    }

    /// A close_notify *after* the handshake completed is still the graceful
    /// shutdown it always was.
    #[test]
    fn close_notify_after_handshake_is_graceful() {
        let mut client = Connection::client(&tls12_client_cfg()).unwrap();
        let mut server = Connection::server(&tls12_server_cfg()).unwrap();
        drive_pair(&mut client, &mut server);
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        server.close().unwrap();
        let bye = server.pop().unwrap();
        client.feed(&bye).unwrap();
        assert!(client.received_close_notify());
        // Completion reporting is sticky: the handshake really did complete.
        assert!(client.is_handshake_complete());
    }
}
