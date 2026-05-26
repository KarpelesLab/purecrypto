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

// ---- Engine builders --------------------------------------------------------

fn build_tls13_client(cfg: &Config) -> Result<super::conn::ClientConnection, Error> {
    let mut cc = super::conn::ClientConfig::new(cfg.roots.clone_store());
    cc.verify_certificates = cfg.verify_certificates;
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
    let server_name = cfg.server_name.as_deref().unwrap_or("localhost");
    Ok(super::conn::ClientConnection::new(
        cc,
        server_name,
        &mut OsRng,
    ))
}

fn build_tls12_client(cfg: &Config) -> Result<super::conn::ClientConnection12, Error> {
    let mut cc = super::conn::ClientConfig12::new(cfg.roots.clone_store());
    cc.verify_certificates = cfg.verify_certificates;
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
    let server_name = cfg.server_name.as_deref().unwrap_or("localhost");
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
    sc = sc.with_signature_policy(cfg.signature_policy.clone());
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
    sc = sc.with_signature_policy(cfg.signature_policy.clone());
    Ok(super::conn::ServerConnection12::new(sc, OsRng))
}

fn build_dtls12_client(cfg: &Config) -> Result<crate::dtls::DtlsClientConnection12, Error> {
    let server_name = cfg.server_name.as_deref().unwrap_or("localhost");
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
    Ok(crate::dtls::DtlsClientConnection12::new(
        dc,
        Vec::new(),
        &mut OsRng,
    ))
}

fn build_dtls13_client(cfg: &Config) -> Result<crate::dtls::DtlsClientConnection13, Error> {
    let server_name = cfg.server_name.as_deref().unwrap_or("localhost");
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
    Ok(crate::dtls::DtlsClientConnection13::new(
        dc,
        Vec::new(),
        &mut OsRng,
    ))
}

fn build_dtls12_server(cfg: &Config) -> Result<crate::dtls::DtlsServerConnection12<OsRng>, Error> {
    let id = cfg.identity.as_ref().ok_or(Error::InappropriateState)?;
    let chain = id.cert_chain.clone();
    let mut sc = match &id.key {
        super::config::SigningKey::Ecdsa(k) => {
            crate::dtls::ServerConfig12Internal::with_ecdsa(chain, k.clone())
        }
        _ => return Err(Error::UnsupportedVersion), // DTLS 1.2 server: ECDSA-only today
    };
    if let Some(secret) = cfg.cookie_secret {
        sc = sc.with_cookie_secret(secret);
    }
    if !cfg.require_cookie {
        sc = sc.require_cookie_exchange(false);
    }
    Ok(crate::dtls::DtlsServerConnection12::new(
        alloc::sync::Arc::new(sc),
        Vec::new(),
        OsRng,
    ))
}

fn build_dtls13_server(cfg: &Config) -> Result<crate::dtls::DtlsServerConnection13<OsRng>, Error> {
    let id = cfg.identity.as_ref().ok_or(Error::InappropriateState)?;
    let chain = id.cert_chain.clone();
    let server_key = id.key.to_server_key_13();
    let mut sc = crate::dtls::ServerConfig13Internal::with_signing_key(chain, server_key);
    if let Some(secret) = cfg.cookie_secret {
        sc = sc.with_cookie_secret(secret);
    }
    if !cfg.require_cookie {
        sc = sc.with_no_cookie();
    }
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
