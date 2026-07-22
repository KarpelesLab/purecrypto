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
    /// [`Readiness`](super::signer::Readiness) (sync: [`wait`](super::signer::Readiness::wait);
    /// async: register its fd with your reactor), then call
    /// [`drive`](Connection::drive) again. `None` means the op has no waitable
    /// descriptor — just call `drive` again. In-process keys never yield this.
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
        let offers13 = match super::peek::peek_offers_tls13(&self.buffered)? {
            None => return Ok(()), // need more bytes; nothing to emit yet
            Some(v) => v,
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

    /// Close the connection, emitting a close_notify alert if the engine
    /// supports it.
    pub fn close(&mut self) -> Result<(), Error> {
        match &mut self.inner {
            Engine::ClientTls13(c) => c.send_close_notify(),
            Engine::ClientTls12(c) => c.send_close_notify(),
            Engine::ServerTls13(c) => c.send_close_notify(),
            Engine::ServerTls12(c) => c.send_close_notify(),
            Engine::ServerTlsAuto(c) => c.close(),
            Engine::ClientTlsAuto(c) => c.close(),
            // DTLS in this library does not emit an explicit close_notify
            // through its public API; the connection is closed when freed.
            #[cfg(feature = "dtls")]
            _ => {}
        }
        Ok(())
    }

    /// True once the handshake has completed.
    pub fn is_handshake_complete(&self) -> bool {
        match &self.inner {
            Engine::ClientTls13(c) => !c.is_handshaking(),
            Engine::ClientTls12(c) => !c.is_handshaking(),
            Engine::ServerTls13(c) => !c.is_handshaking(),
            Engine::ServerTls12(c) => !c.is_handshaking(),
            Engine::ServerTlsAuto(c) => !c.is_handshaking(),
            Engine::ClientTlsAuto(c) => !c.is_handshaking(),
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

    /// True once the peer's close_notify alert has been processed.
    ///
    /// Distinguishes a graceful TLS shutdown from an abrupt transport
    /// close: after transport EOF, `false` here means the peer (or an
    /// active attacker injecting a TCP FIN/RST) cut the stream without
    /// the RFC 8446 §6.1 / RFC 5246 §7.2.1 closure alert. Callers using
    /// EOF-delimited application framing should treat that as a
    /// truncation attack and reject the data.
    ///
    /// Always `false` for DTLS engines — purecrypto's DTLS does not
    /// exchange close_notify (datagram transports have no stream EOF to
    /// authenticate; an application protocol signals its own end).
    pub fn received_close_notify(&self) -> bool {
        match &self.inner {
            Engine::ClientTls13(c) => c.received_close_notify(),
            Engine::ClientTls12(c) => c.received_close_notify(),
            Engine::ServerTls13(c) => c.received_close_notify(),
            Engine::ServerTls12(c) => c.received_close_notify(),
            Engine::ServerTlsAuto(c) => c.received_close_notify(),
            Engine::ClientTlsAuto(c) => c.received_close_notify(),
            #[cfg(feature = "dtls")]
            Engine::ClientDtls12(_)
            | Engine::ClientDtls13(_)
            | Engine::ServerDtls12(_)
            | Engine::ServerDtls13(_) => false,
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
            // Reachable only when `dtls` is enabled (catches the DTLS variants
            // not handled above); exhaustive over the TLS variants otherwise.
            #[cfg_attr(not(feature = "dtls"), allow(unreachable_patterns))]
            _ => None,
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
            // Reachable only when `dtls` is enabled (catches the DTLS variants
            // not handled above); exhaustive over the TLS variants otherwise.
            #[cfg_attr(not(feature = "dtls"), allow(unreachable_patterns))]
            _ => &[],
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

/// The client's intended server name, used for SNI and (when enabled) hostname
/// verification. A name is **required only when `verify_certificates` is on** —
/// without it there is nothing to check the peer certificate against, so a
/// missing name is a misconfiguration. With verification off (e.g. connecting to
/// a device by IP), the name is optional; an empty string means "no SNI, no
/// hostname check", which the engines honour by omitting the SNI extension.
fn client_server_name(cfg: &Config) -> Result<&str, Error> {
    match cfg.server_name.as_deref() {
        Some(name) => Ok(name),
        None if !cfg.verify_certificates => Ok(""),
        None => Err(Error::MissingServerName),
    }
}

fn build_tls13_client(cfg: &Config) -> Result<super::conn::ClientConnection, Error> {
    let mut cc = super::conn::ClientConfig::new(cfg.roots.clone_store());
    cc.verify_certificates = cfg.verify_certificates;
    cc.cipher_suites = cfg.cipher_suites.clone();
    // Offer TLS 1.2 alongside 1.3 when the configured range spans down to 1.2
    // and we are not resuming a (1.3-only) session — so a 1.2-only server can
    // negotiate and the engine can downgrade. Pinned `min == 1.3` keeps a pure
    // 1.3 ClientHello.
    cc.offer_tls12 = cfg.min_version != ProtocolVersion::TLSv1_3 && cfg.resumption.is_none();
    if !cfg.alpn_protocols.is_empty() {
        cc = cc.with_alpn(cfg.alpn_protocols.clone());
    }
    if !cfg.crls.is_empty() {
        cc = cc.with_crls(cfg.crls.clone_store());
    }
    if let Some(t) = cfg.verification_time.clone() {
        cc.verification_time = Some(t);
    }
    if let Some(rsl) = cfg.record_size_limit {
        cc = cc.with_record_size_limit(rsl);
    }
    cc = cc.with_signature_policy(cfg.signature_policy.clone());
    if let Some(id) = &cfg.identity {
        let cc_cfg = client_cert_from_signing(id);
        if let Some(c) = cc_cfg {
            cc = cc.with_client_cert(c);
        }
    }
    cc = cc.with_server_cert_type_preference(cfg.server_cert_type_preference.clone());
    cc = cc.with_client_cert_type_preference(cfg.client_cert_type_preference.clone());
    for spki in &cfg.expected_raw_public_keys {
        cc = cc.add_expected_raw_public_key(spki.clone());
    }
    if let Some(spki) = cfg.raw_public_key_spki.clone() {
        cc = cc.with_client_raw_public_key_spki(spki);
    }
    cc.key_log = cfg.key_log.clone();
    #[cfg(feature = "ech")]
    {
        cc.ech = cfg.ech.clone();
    }
    #[cfg(feature = "cert-compression")]
    {
        cc = cc.with_cert_compression_algorithms(cfg.cert_compression_algorithms.clone());
    }
    // Prime PSK resumption from a stored TLS 1.3 session, if one was supplied
    // (a 1.2 session here is simply ignored — version mismatch).
    if let Some(ResumptionSession(ResumptionSessionKind::Tls13(s))) = &cfg.resumption {
        cc = cc.with_session(s.clone());
    }
    let server_name = client_server_name(cfg)?;
    super::conn::ClientConnection::new(cc, server_name, &mut config_rng(cfg)?)
}

/// Assembles the per-engine TLS 1.2 client config from the public `Config`.
/// Shared by [`build_tls12_client`] (fresh handshake) and
/// [`build_tls12_client_adopt`] (version-spanning downgrade).
fn tls12_client_config(cfg: &Config) -> Result<super::conn::ClientConfig12, Error> {
    let mut cc = super::conn::ClientConfig12::new(cfg.roots.clone_store());
    cc.verify_certificates = cfg.verify_certificates;
    cc.cipher_suites = cfg.cipher_suites.clone();
    if !cfg.alpn_protocols.is_empty() {
        cc = cc.with_alpn(cfg.alpn_protocols.clone());
    }
    if !cfg.crls.is_empty() {
        cc = cc.with_crls(cfg.crls.clone_store());
    }
    if let Some(t) = cfg.verification_time.clone() {
        cc = cc.with_verification_time(t);
    }
    if let Some(rsl) = cfg.record_size_limit {
        cc = cc.with_record_size_limit(rsl);
    }
    cc = cc.with_signature_policy(cfg.signature_policy.clone());
    cc = cc.with_require_ems(cfg.require_extended_master_secret);
    if let Some(id) = &cfg.identity {
        let cc_cfg = client_cert_from_signing(id);
        if let Some(c) = cc_cfg {
            cc = cc.with_client_cert(c);
        }
    }
    cc.key_log = cfg.key_log.clone();
    #[cfg(feature = "tls-legacy")]
    {
        cc = cc.with_min_version(cfg.min_version);
        // The 1.2 engine caps at TLS 1.2; only propagate a lower max so a
        // legacy-only caller offers `legacy_version` ≤ 1.1 and no AEAD suites.
        if cfg.max_version.as_u16() < ProtocolVersion::TLSv1_2.as_u16() {
            cc = cc.with_max_version(cfg.max_version);
        }
    }
    // Prime RFC 5077 ticket resumption from a stored TLS 1.2 session, if one
    // was supplied (a 1.3 session here is simply ignored — version mismatch).
    if let Some(ResumptionSession(ResumptionSessionKind::Tls12(s))) = &cfg.resumption {
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

fn build_tls13_server(cfg: &Config) -> Result<super::conn::ServerConnection<ConfigRng>, Error> {
    let id = cfg.identity.as_ref().ok_or(Error::InappropriateState)?;
    let chain = id.cert_chain.clone();
    let mut sc = match &id.key {
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
    };
    if !cfg.alpn_protocols.is_empty() {
        sc = sc.with_alpn(cfg.alpn_protocols.clone());
    }
    if !cfg.crls.is_empty() {
        sc = sc.with_crls(cfg.crls.clone_store());
    }
    if let Some(rsl) = cfg.record_size_limit {
        sc = sc.with_record_size_limit(rsl);
    }
    if let Some(ca) = &cfg.client_auth {
        sc = sc.with_client_auth(ca.roots.clone_store(), ca.required);
    }
    if let Some(tk) = cfg.ticket_key {
        sc = sc.with_ticket_key(tk);
    }
    if cfg.max_early_data_size > 0 {
        sc = sc.with_max_early_data(cfg.max_early_data_size);
    }
    #[cfg(feature = "std")]
    if let Some(rw) = cfg.replay_window.clone() {
        sc = sc.with_replay_window(rw);
    }
    if let Some(crl) = cfg.stapled_crl.clone() {
        sc = sc.with_stapled_crl(crl);
    }
    if let Some(ocsp) = cfg.stapled_ocsp_response.clone() {
        sc = sc.with_stapled_ocsp_response(ocsp);
    }
    sc = sc.with_server_cert_type_preference(cfg.server_cert_type_preference.clone());
    sc = sc.with_client_cert_type_preference(cfg.client_cert_type_preference.clone());
    if let Some(spki) = cfg.raw_public_key_spki.clone() {
        sc = sc.with_raw_public_key_spki(spki);
    }
    sc = sc.with_signature_policy(cfg.signature_policy.clone());
    #[cfg(feature = "cert-compression")]
    {
        sc = sc.with_cert_compression_algorithms(cfg.cert_compression_algorithms.clone());
    }
    #[cfg(feature = "ech")]
    if let Some(ech) = cfg.ech_server.clone() {
        sc = sc.with_ech_server(ech);
    }
    if let Some(g) = cfg.preferred_key_exchange_group {
        sc = sc.with_preferred_key_exchange_group(g);
    }
    if let Some(t) = cfg.verification_time.clone() {
        sc = sc.with_verification_time(t);
    }
    sc.key_log = cfg.key_log.clone();
    Ok(super::conn::ServerConnection::new(sc, config_rng(cfg)?))
}

fn build_tls12_server(cfg: &Config) -> Result<super::conn::ServerConnection12<ConfigRng>, Error> {
    let id = cfg.identity.as_ref().ok_or(Error::InappropriateState)?;
    let chain = id.cert_chain.clone();
    let mut sc = id
        .key
        .try_into_server_config_12(chain)
        .ok_or(Error::UnsupportedVersion)?;
    // RFC 8446 §4.1.3 downgrade sentinel: only set it when this deployment is
    // actually TLS-1.3-capable (a version-spanning server). A pinned `max=1.2`
    // server must not, or 1.3-capable clients would abort.
    sc = sc.with_supports_tls13(cfg.max_version == ProtocolVersion::TLSv1_3);
    if !cfg.alpn_protocols.is_empty() {
        sc = sc.with_alpn(cfg.alpn_protocols.clone());
    }
    if !cfg.crls.is_empty() {
        sc = sc.with_crls(cfg.crls.clone_store());
    }
    if let Some(rsl) = cfg.record_size_limit {
        sc = sc.with_record_size_limit(rsl);
    }
    if let Some(ca) = &cfg.client_auth {
        sc = sc.with_client_auth(ca.roots.clone_store(), ca.required);
    }
    if let Some(tk) = cfg.ticket_key {
        sc = sc.with_ticket_key(tk);
    }
    if let Some(ocsp) = cfg.stapled_ocsp_response.clone() {
        sc = sc.with_stapled_ocsp_response(ocsp);
    }
    sc = sc.with_signature_policy(cfg.signature_policy.clone());
    sc = sc.with_require_ems(cfg.require_extended_master_secret);
    if let Some(t) = cfg.verification_time.clone() {
        sc = sc.with_verification_time(t);
    }
    sc.key_log = cfg.key_log.clone();
    #[cfg(feature = "tls-legacy")]
    {
        sc = sc.with_min_version(cfg.min_version);
    }
    Ok(super::conn::ServerConnection12::new(sc, config_rng(cfg)?))
}

#[cfg(feature = "dtls")]
fn build_dtls12_client(cfg: &Config) -> Result<crate::dtls::DtlsClientConnection12, Error> {
    let server_name = client_server_name(cfg)?;
    let mut dc = crate::dtls::ClientConfig12Internal::new(cfg.roots.clone_store(), server_name);
    if !cfg.verify_certificates {
        dc = dc.without_certificate_verification();
    }
    if !cfg.crls.is_empty() {
        dc = dc.with_crls(cfg.crls.clone_store());
    }
    if let Some(t) = cfg.verification_time.clone() {
        dc = dc.with_verification_time(t);
    }
    dc = dc.with_signature_policy(cfg.signature_policy.clone());
    dc.key_log = cfg.key_log.clone();
    Ok(crate::dtls::DtlsClientConnection12::new(
        dc,
        Vec::new(),
        &mut config_rng(cfg)?,
    ))
}

#[cfg(feature = "dtls")]
fn build_dtls13_client(cfg: &Config) -> Result<crate::dtls::DtlsClientConnection13, Error> {
    let server_name = client_server_name(cfg)?;
    let mut dc = crate::dtls::ClientConfig13Internal::new(cfg.roots.clone_store(), server_name);
    if !cfg.verify_certificates {
        dc = dc.without_certificate_verification();
    }
    if !cfg.crls.is_empty() {
        dc = dc.with_crls(cfg.crls.clone_store());
    }
    if let Some(t) = cfg.verification_time.clone() {
        dc = dc.with_verification_time(t);
    }
    dc = dc.with_signature_policy(alloc::sync::Arc::new(cfg.signature_policy.clone()));
    dc.max_record_size = cfg.max_record_size;
    dc.key_log = cfg.key_log.clone();
    Ok(crate::dtls::DtlsClientConnection13::new(
        dc,
        Vec::new(),
        &mut config_rng(cfg)?,
    ))
}

#[cfg(feature = "dtls")]
fn build_dtls12_server(
    cfg: &Config,
) -> Result<crate::dtls::DtlsServerConnection12<ConfigRng>, Error> {
    let id = cfg.identity.as_ref().ok_or(Error::InappropriateState)?;
    // RFC 6347 §4.2.1: the cookie exchange defeats blind amplification
    // attacks. We refuse to construct a server that claims to require the
    // exchange but cannot mint cookies — silently disabling cookies under a
    // misconfiguration is the 50-100x DoS amplification vector. Fail-closed
    // so the operator makes a deliberate choice.
    if cfg.require_cookie && cfg.cookie_secret.is_none() {
        return Err(Error::InappropriateState);
    }
    let chain = id.cert_chain.clone();
    let mut sc = match &id.key {
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
    if let Some(secret) = cfg.cookie_secret {
        sc = sc.with_cookie_secret(secret);
    }
    if !cfg.require_cookie {
        sc = sc.require_cookie_exchange(false);
    }
    sc.key_log = cfg.key_log.clone();
    Ok(crate::dtls::DtlsServerConnection12::new(
        alloc::sync::Arc::new(sc),
        Vec::new(),
        config_rng(cfg)?,
    ))
}

#[cfg(feature = "dtls")]
fn build_dtls13_server(
    cfg: &Config,
) -> Result<crate::dtls::DtlsServerConnection13<ConfigRng>, Error> {
    let id = cfg.identity.as_ref().ok_or(Error::InappropriateState)?;
    // RFC 9147 §5.1: DTLS 1.3 retains the cookie-based stateless rejection
    // for the same DoS-amplification reason. Mirror the fail-closed posture
    // of `build_dtls12_server`.
    if cfg.require_cookie && cfg.cookie_secret.is_none() {
        return Err(Error::InappropriateState);
    }
    let chain = id.cert_chain.clone();
    let server_key = id.key.to_server_key_13();
    let mut sc = crate::dtls::ServerConfig13Internal::with_signing_key(chain, server_key);
    if let Some(secret) = cfg.cookie_secret {
        sc = sc.with_cookie_secret(secret);
    }
    if !cfg.require_cookie {
        sc = sc.with_no_cookie();
    }
    sc.key_log = cfg.key_log.clone();
    Ok(crate::dtls::DtlsServerConnection13::new(
        alloc::sync::Arc::new(sc),
        Vec::new(),
        config_rng(cfg)?,
    ))
}

fn client_cert_from_signing(id: &super::config::Identity) -> Option<super::conn::ClientCertConfig> {
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

#[cfg(test)]
mod tests {
    use super::super::config::EntropySource;
    use super::*;
    use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    /// Build a minimal DTLS server [`Config`] (P-256 ECDSA leaf, self-signed)
    /// with `require_cookie` defaulted to true and `cookie_secret = None`.
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
    // Fail-closed: refuse to construct the engine.
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
        cfg.cookie_secret = Some([0x42u8; 32]);
        assert!(Connection::server(&cfg).is_ok());

        // Explicit opt-out (require_cookie = false) -> allowed.
        let mut cfg = dtls_server_cfg_without_cookie_secret(ProtocolVersion::DTLSv1_3);
        cfg.require_cookie = false;
        assert!(Connection::server(&cfg).is_ok());
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
}
