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

use crate::rng::{CryptoRng, OsRng, RngCore};

use super::config::Config;
use super::error::Error;
use super::version::ProtocolVersion;

/// Type-erased RNG the public [`Connection`] hands to its engines, so the
/// `OsRng` default and a caller-supplied
/// [`EntropySource`](super::config::EntropySource) share one concrete type
/// (the per-(version, role) engines are generic over `R: RngCore`, but the
/// public enum cannot be).
enum ConfigRng {
    Os(OsRng),
    Shared(alloc::sync::Arc<dyn super::config::EntropySource>),
}

impl RngCore for ConfigRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            ConfigRng::Os(r) => r.fill_bytes(dest),
            ConfigRng::Shared(s) => s.fill(dest),
        }
    }
}

// The configured source is contractually a CSPRNG — `OsRng`, or an
// `EntropySource` the caller promises is cryptographically secure — so it is
// valid wherever the engines require `CryptoRng`.
impl CryptoRng for ConfigRng {}

/// The engine RNG for `cfg`: the caller's [`EntropySource`] if set, else `OsRng`.
fn config_rng(cfg: &Config) -> ConfigRng {
    match &cfg.rng {
        Some(src) => ConfigRng::Shared(src.clone()),
        None => ConfigRng::Os(OsRng),
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
    /// in one call.
    pending_dtls: alloc::collections::VecDeque<Vec<u8>>,
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
    /// DTLS 1.3 client.
    ClientDtls13(Box<crate::dtls::DtlsClientConnection13>),
    /// DTLS 1.2 client.
    ClientDtls12(Box<crate::dtls::DtlsClientConnection12>),
    /// DTLS 1.3 server.
    ServerDtls13(Box<crate::dtls::DtlsServerConnection13<ConfigRng>>),
    /// DTLS 1.2 server.
    ServerDtls12(Box<crate::dtls::DtlsServerConnection12<ConfigRng>>),
}

impl Connection {
    /// Build a client connection. Picks the engine from `config.max_version`.
    pub fn client(config: &Config) -> Result<Self, Error> {
        config.check_versions()?;
        let inner = match config.max_version {
            ProtocolVersion::TLSv1_3 => Engine::ClientTls13(Box::new(build_tls13_client(config)?)),
            ProtocolVersion::TLSv1_2 => Engine::ClientTls12(Box::new(build_tls12_client(config)?)),
            // The TLS 1.2 engine also drives the opt-in legacy path; a caller
            // that tops out at TLS 1.0/1.1 still routes through it.
            #[cfg(feature = "tls-legacy")]
            ProtocolVersion::TLSv1_1 | ProtocolVersion::TLSv1_0 | ProtocolVersion::SSLv3 => {
                Engine::ClientTls12(Box::new(build_tls12_client(config)?))
            }
            ProtocolVersion::DTLSv1_3 => {
                Engine::ClientDtls13(Box::new(build_dtls13_client(config)?))
            }
            ProtocolVersion::DTLSv1_2 => {
                Engine::ClientDtls12(Box::new(build_dtls12_client(config)?))
            }
            _ => return Err(Error::UnsupportedVersion),
        };
        Ok(Connection {
            inner,
            pending_dtls: alloc::collections::VecDeque::new(),
        })
    }

    /// Build a server connection. Picks the engine from `config.max_version`.
    /// Requires `config.identity.is_some()`.
    pub fn server(config: &Config) -> Result<Self, Error> {
        config.check_versions()?;
        if config.identity.is_none() {
            return Err(Error::InappropriateState);
        }
        let inner = match config.max_version {
            ProtocolVersion::TLSv1_3 => Engine::ServerTls13(Box::new(build_tls13_server(config)?)),
            ProtocolVersion::TLSv1_2 => Engine::ServerTls12(Box::new(build_tls12_server(config)?)),
            #[cfg(feature = "tls-legacy")]
            ProtocolVersion::TLSv1_1 | ProtocolVersion::TLSv1_0 | ProtocolVersion::SSLv3 => {
                Engine::ServerTls12(Box::new(build_tls12_server(config)?))
            }
            ProtocolVersion::DTLSv1_3 => {
                Engine::ServerDtls13(Box::new(build_dtls13_server(config)?))
            }
            ProtocolVersion::DTLSv1_2 => {
                Engine::ServerDtls12(Box::new(build_dtls12_server(config)?))
            }
            _ => return Err(Error::UnsupportedVersion),
        };
        Ok(Connection {
            inner,
            pending_dtls: alloc::collections::VecDeque::new(),
        })
    }

    /// Drive the handshake forward. Returns the next [`HandshakeStatus`].
    pub fn handshake(&mut self) -> Result<HandshakeStatus, Error> {
        if self.is_handshake_complete() {
            return Ok(HandshakeStatus::Complete);
        }
        // Refill DTLS pending queue.
        self.refill_dtls_pending();
        if self.wants_write() {
            Ok(HandshakeStatus::WantWrite)
        } else {
            Ok(HandshakeStatus::WantRead)
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
            Engine::ClientDtls12(c) => c.feed_datagram(wire_in)?,
            Engine::ClientDtls13(c) => c.feed_datagram(wire_in)?,
            Engine::ServerDtls12(c) => c.feed_datagram(wire_in)?,
            Engine::ServerDtls13(c) => c.feed_datagram(wire_in)?,
        }
        // Eagerly pull DTLS datagrams into the buffer.
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
            _ => {
                // Refill if buffer empty, then pop the next datagram.
                if self.pending_dtls.is_empty() {
                    let drained = match &mut self.inner {
                        Engine::ClientDtls12(c) => c.pop_outbound_datagrams(),
                        Engine::ClientDtls13(c) => c.pop_outbound_datagrams(),
                        Engine::ServerDtls12(c) => c.pop_outbound_datagrams(),
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
            Engine::ClientDtls12(c) => c.send(app),
            Engine::ClientDtls13(c) => c.send(app),
            Engine::ServerDtls12(c) => c.send(app),
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
            Engine::ClientDtls12(c) => c.take_received(),
            Engine::ClientDtls13(c) => c.take_received(),
            Engine::ServerDtls12(c) => c.take_received(),
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
            // No other engine accepts 0-RTT early data today.
            _ => Vec::new(),
        })
    }

    /// Close the connection, emitting a close_notify alert if the engine
    /// supports it.
    pub fn close(&mut self) -> Result<(), Error> {
        match &mut self.inner {
            Engine::ClientTls13(c) => c.send_close_notify(),
            Engine::ClientTls12(c) => c.send_close_notify(),
            Engine::ServerTls13(c) => c.send_close_notify(),
            Engine::ServerTls12(c) => c.send_close_notify(),
            // DTLS in this library does not emit an explicit close_notify
            // through its public API; the connection is closed when freed.
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
            Engine::ClientDtls12(c) => c.is_handshake_complete(),
            Engine::ClientDtls13(c) => c.is_handshake_complete(),
            Engine::ServerDtls12(c) => c.is_handshake_complete(),
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
            Engine::ClientDtls12(_) | Engine::ServerDtls12(_) => Some(ProtocolVersion::DTLSv1_2),
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
            Engine::ClientDtls13(c) => c.negotiated_cipher_suite(),
            Engine::ServerDtls13(c) => c.negotiated_cipher_suite(),
            Engine::ClientDtls12(c) => c.negotiated_cipher_suite(),
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
            Engine::ClientDtls13(c) => c.alpn_protocol(),
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
            Engine::ClientDtls13(c) => c.peer_certificates(),
            _ => &[],
        }
    }

    /// DTLS: next retransmit timeout. None on TLS variants.
    pub fn next_timeout(&self) -> Option<Duration> {
        match &self.inner {
            Engine::ClientDtls12(c) => c.next_timeout(),
            Engine::ClientDtls13(c) => c.next_timeout(),
            Engine::ServerDtls12(c) => c.next_timeout(),
            Engine::ServerDtls13(c) => c.next_timeout(),
            _ => None,
        }
    }

    /// DTLS: notify the engine that the retransmit deadline has elapsed.
    /// No-op on TLS variants.
    pub fn on_timeout(&mut self, now: Duration) {
        match &mut self.inner {
            Engine::ClientDtls12(c) => c.on_timeout(now),
            Engine::ClientDtls13(c) => c.on_timeout(now),
            Engine::ServerDtls12(c) => c.on_timeout(now),
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
            // DTLS: any pending datagram counts as wanting-write.
            _ => !self.pending_dtls.is_empty(),
        }
    }

    /// Drain new outbound datagrams from the DTLS engine into the pending
    /// buffer. No-op for TLS variants.
    fn refill_dtls_pending(&mut self) {
        let drained: Vec<Vec<u8>> = match &mut self.inner {
            Engine::ClientDtls12(c) => c.pop_outbound_datagrams(),
            Engine::ClientDtls13(c) => c.pop_outbound_datagrams(),
            Engine::ServerDtls12(c) => c.pop_outbound_datagrams(),
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
    cc.key_log = cfg.key_log.clone();
    #[cfg(feature = "ech")]
    {
        cc.ech = cfg.ech.clone();
    }
    #[cfg(feature = "cert-compression")]
    {
        cc = cc.with_cert_compression_algorithms(cfg.cert_compression_algorithms.clone());
    }
    let server_name = client_server_name(cfg)?;
    super::conn::ClientConnection::new(cc, server_name, &mut config_rng(cfg))
}

fn build_tls12_client(cfg: &Config) -> Result<super::conn::ClientConnection12, Error> {
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
    let server_name = client_server_name(cfg)?;
    super::conn::ClientConnection12::new(cc, server_name, &mut config_rng(cfg))
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
        super::config::SigningKey::MlDsa44(k) => {
            super::conn::ServerConfig::with_mldsa44(chain, k.clone())
        }
        super::config::SigningKey::MlDsa65(k) => {
            super::conn::ServerConfig::with_mldsa65(chain, k.clone())
        }
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
    Ok(super::conn::ServerConnection::new(sc, config_rng(cfg)))
}

fn build_tls12_server(cfg: &Config) -> Result<super::conn::ServerConnection12<ConfigRng>, Error> {
    let id = cfg.identity.as_ref().ok_or(Error::InappropriateState)?;
    let chain = id.cert_chain.clone();
    let mut sc = id
        .key
        .try_into_server_config_12(chain)
        .ok_or(Error::UnsupportedVersion)?;
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
    Ok(super::conn::ServerConnection12::new(sc, config_rng(cfg)))
}

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
        &mut config_rng(cfg),
    ))
}

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
        &mut config_rng(cfg),
    ))
}

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
        config_rng(cfg),
    ))
}

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
        config_rng(cfg),
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
        super::config::SigningKey::MlDsa44(k) => {
            super::conn::ClientCertConfig::with_mldsa44(id.cert_chain.clone(), k.clone())
        }
        super::config::SigningKey::MlDsa65(k) => {
            super::conn::ClientCertConfig::with_mldsa65(id.cert_chain.clone(), k.clone())
        }
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
            .versions(max_version, max_version)
            .identity(
                alloc::vec![cert.to_der().to_vec()],
                super::super::config::SigningKey::Ecdsa(key),
            )
            .build()
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
            let cfg = Config::builder().versions(v, v).build();
            assert!(cfg.verify_certificates && cfg.server_name.is_none());
            match Connection::client(&cfg) {
                Err(Error::MissingServerName) => {}
                Err(e) => panic!("{v:?}: expected MissingServerName, got {e:?}"),
                Ok(_) => panic!("{v:?}: verifying client must require server_name"),
            }

            // verify off + no server_name → allowed (no SNI, no hostname check).
            let cfg = Config::builder()
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
            .tls_only()
            .server_name("suite.example")
            .build();
        let client = Connection::client(&cfg).unwrap();
        assert!(client.negotiated_cipher_suite().is_none());
        assert!(client.negotiated_cipher_suite_name().is_none());

        // TLS 1.3 server (cipher selected during ClientHello dispatch).
        let cfg = Config::builder()
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

    /// A self-signed ECDSA P-256 leaf + its key, for external-signing tests.
    fn ecdsa_p256_identity() -> (BoxedEcdsaPrivateKey, Vec<u8>) {
        let mut kg = HmacDrbg::<Sha256>::new(b"ext-sign-leaf", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut kg);
        let name = DistinguishedName::common_name("ext.example");
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
            &["ext.example"],
        )
        .unwrap();
        (key, cert.to_der().to_vec())
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
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .identity(
                alloc::vec![leaf],
                super::super::config::SigningKey::External {
                    schemes: alloc::vec![ECDSA_SECP256R1_SHA256],
                },
            )
            .build();
        let client_cfg = Config::builder()
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

    /// If the client offers no signature scheme the external key advertises,
    /// the server aborts the handshake (handshake_failure) rather than stalling.
    #[test]
    fn server_external_signing_rejects_disjoint_schemes() {
        // Advertise only an unassigned scheme no client ever offers, so the
        // intersection with the ClientHello's signature_algorithms is empty.
        const UNOFFERED: u16 = 0xFFFF;
        let (_key, leaf) = ecdsa_p256_identity();
        let server_cfg = Config::builder()
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .identity(
                alloc::vec![leaf],
                super::super::config::SigningKey::External {
                    schemes: alloc::vec![UNOFFERED],
                },
            )
            .build();
        let client_cfg = Config::builder()
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
}
