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

use crate::rng::OsRng;

use super::config::Config;
use super::error::Error;
use super::version::ProtocolVersion;

/// Handshake progress, as observed from the uniform API.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HandshakeStatus {
    /// The handshake is complete; application data may flow.
    Complete,
    /// The engine has nothing to emit; the caller should
    /// [`feed`](Connection::feed) bytes from the peer.
    WantRead,
    /// The engine has wire bytes ready; the caller should drain them with
    /// [`pop`](Connection::pop) and forward them to the peer.
    WantWrite,
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
    ServerTls13(Box<super::conn::ServerConnection<OsRng>>),
    /// TLS 1.2 server.
    ServerTls12(Box<super::conn::ServerConnection12<OsRng>>),
    /// DTLS 1.3 client.
    ClientDtls13(Box<crate::dtls::DtlsClientConnection13>),
    /// DTLS 1.2 client.
    ClientDtls12(Box<crate::dtls::DtlsClientConnection12>),
    /// DTLS 1.3 server.
    ServerDtls13(Box<crate::dtls::DtlsServerConnection13<OsRng>>),
    /// DTLS 1.2 server.
    ServerDtls12(Box<crate::dtls::DtlsServerConnection12<OsRng>>),
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
            ProtocolVersion::TLSv1_1 | ProtocolVersion::TLSv1_0 => {
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
            ProtocolVersion::TLSv1_1 | ProtocolVersion::TLSv1_0 => {
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

    /// The negotiated wire version, if the handshake has progressed enough
    /// to determine it.
    pub fn negotiated_version(&self) -> Option<ProtocolVersion> {
        Some(match &self.inner {
            Engine::ClientTls13(_) | Engine::ServerTls13(_) => ProtocolVersion::TLSv1_3,
            Engine::ClientTls12(_) | Engine::ServerTls12(_) => ProtocolVersion::TLSv1_2,
            Engine::ClientDtls12(_) | Engine::ServerDtls12(_) => ProtocolVersion::DTLSv1_2,
            Engine::ClientDtls13(_) | Engine::ServerDtls13(_) => ProtocolVersion::DTLSv1_3,
        })
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
    Ok(super::conn::ClientConnection::new(
        cc,
        server_name,
        &mut OsRng,
    ))
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
    Ok(super::conn::ClientConnection12::new(
        cc,
        server_name,
        &mut OsRng,
    ))
}

fn build_tls13_server(cfg: &Config) -> Result<super::conn::ServerConnection<OsRng>, Error> {
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
    Ok(super::conn::ServerConnection::new(sc, OsRng))
}

fn build_tls12_server(cfg: &Config) -> Result<super::conn::ServerConnection12<OsRng>, Error> {
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
    if let Some(t) = cfg.verification_time.clone() {
        sc = sc.with_verification_time(t);
    }
    sc.key_log = cfg.key_log.clone();
    #[cfg(feature = "tls-legacy")]
    {
        sc = sc.with_min_version(cfg.min_version);
    }
    Ok(super::conn::ServerConnection12::new(sc, OsRng))
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
        &mut OsRng,
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
        &mut OsRng,
    ))
}

fn build_dtls12_server(cfg: &Config) -> Result<crate::dtls::DtlsServerConnection12<OsRng>, Error> {
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
        OsRng,
    ))
}

fn build_dtls13_server(cfg: &Config) -> Result<crate::dtls::DtlsServerConnection13<OsRng>, Error> {
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
        OsRng,
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
    })
}

#[cfg(test)]
mod tests {
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
}
