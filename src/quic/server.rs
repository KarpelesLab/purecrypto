//! Server-side bootstrap helpers.
//!
//! On the server, Initial keys can't be derived at construction time —
//! they depend on the client's chosen DCID, which the server learns from
//! the first inbound Initial packet (RFC 9001 §5.2). Phase 4's
//! simplification: the [`crate::quic::QuicConnection::server`]
//! constructor leaves `Endpoint::cids` unset and derives Initial keys
//! lazily inside `feed_datagram`.
//!
//! The TLS engine itself can be constructed eagerly — it doesn't depend
//! on the DCID. But because [`crate::tls::conn::ServerConnection<R>`] is
//! generic over the RNG type, we monomorphize to `OsRng` here for the
//! sans-I/O wrapper.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::quic::cid::{CidPair, ConnectionId};
use crate::quic::crypto::{AeadAlg, derive_dir_keys, derive_initial_secrets};
use crate::quic::endpoint::Endpoint;
use crate::quic::tls_glue::{HookHandle, build_hooks};
use crate::rng::OsRng;
use crate::tls::Error;
use crate::tls::conn::{ServerConfig, ServerConnection};
use crate::tls::quic_hooks::Level;

/// Default server-side SCID length. Same value as the client's
/// [`crate::quic::client::DEFAULT_CID_LEN`] (8 bytes).
pub(crate) const DEFAULT_SCID_LEN: usize = 8;

/// Constructs the TLS engine in QUIC server mode and returns the engine
/// alongside the driver-side hook handle. The engine is *not* fed any
/// bytes yet — the first call to
/// [`crate::quic::QuicConnection::feed_datagram`] will feed the
/// reassembled ClientHello and `process_new_packets` will drive the
/// ServerHello.
pub(crate) fn build_tls_engine(
    tls_cfg: ServerConfig,
    transport_params: Vec<u8>,
) -> Result<(ServerConnection<OsRng>, HookHandle), Error> {
    let (hooks, handle) = build_hooks(transport_params);
    let engine = ServerConnection::new_for_quic(tls_cfg, OsRng, hooks as Box<_>);
    Ok((engine, handle))
}

/// Installs the Initial-level AEAD keys on `endpoint`, keyed by the
/// client's chosen DCID. The client picked this DCID at random; per RFC
/// 9001 §5.2 both Initial keys derive from
/// `HKDF-Extract(initial_salt, client_dcid)`.
///
/// `client_dcid` is the bytes the client wrote into the DCID slot of its
/// first Initial long header.
pub(crate) fn install_initial_keys(endpoint: &mut Endpoint, client_dcid: &[u8]) {
    let (client_secret, server_secret) = derive_initial_secrets(client_dcid);
    // On the server, Tx = "server in"; Rx = "client in".
    endpoint.crypto.levels[Level::Initial as usize].tx =
        Some(derive_dir_keys(AeadAlg::Aes128Gcm, &server_secret));
    endpoint.crypto.levels[Level::Initial as usize].rx =
        Some(derive_dir_keys(AeadAlg::Aes128Gcm, &client_secret));
}

/// Constructs a placeholder [`Endpoint`] with unset CIDs. The server's
/// CIDs are filled in by [`set_cids_from_first_initial`] on receipt of
/// the first client Initial.
pub(crate) fn build_pending_endpoint() -> Endpoint {
    Endpoint::new(CidPair::new(ConnectionId::empty(), ConnectionId::empty()))
}

/// Records the server's CID choice and the peer CID extracted from the
/// first client Initial. `peer_scid` is the SCID byte string from the
/// client's first long header (which becomes our DCID for outbound
/// packets per RFC 9000 §7.2). `our_local` is the server-chosen SCID we
/// will write back on every server long-header outbound — typically a
/// random 8-byte value.
pub(crate) fn set_cids_from_first_initial(
    endpoint: &mut Endpoint,
    peer_scid: ConnectionId,
    our_local: ConnectionId,
) {
    endpoint.cids = CidPair::new(peer_scid, our_local);
}

/// Convenience random-CID helper mirroring
/// [`crate::quic::client::random_default_cid`].
pub(crate) fn random_default_scid() -> ConnectionId {
    let mut rng = OsRng;
    ConnectionId::random(&mut rng, DEFAULT_SCID_LEN)
}

use core::time::Duration;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Instant;

use crate::quic::connection::{MIN_INITIAL_DATAGRAM, QuicConfig, QuicConnection};
use crate::quic::ecn::EcnCodepoint;
use crate::quic::pkt::{LongHeader, LongType, QUIC_V1, build_version_negotiation};
use crate::quic::reset::{MIN_STATELESS_RESET_LEN, build_stateless_reset, stateless_reset_token};
use crate::rng::RngCore;

/// Parses the version-independent invariant fields of a long header
/// (RFC 8999 §5.1): `(version, dcid, scid)`. Returns `None` if the buffer is
/// truncated or a CID length exceeds 20. Used to answer unsupported versions
/// with Version Negotiation before committing to v1-specific parsing.
fn parse_long_invariant(buf: &[u8]) -> Option<(u32, &[u8], &[u8])> {
    if buf.len() < 6 {
        return None;
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let dcid_len = buf[5] as usize;
    if dcid_len > 20 {
        return None;
    }
    let dcid_end = 6 + dcid_len;
    let scid_len_pos = dcid_end;
    if buf.len() <= scid_len_pos {
        return None;
    }
    let scid_len = buf[scid_len_pos] as usize;
    if scid_len > 20 {
        return None;
    }
    let scid_start = scid_len_pos + 1;
    let scid_end = scid_start + scid_len;
    if buf.len() < scid_end {
        return None;
    }
    Some((version, &buf[6..dcid_end], &buf[scid_start..scid_end]))
}

/// Default value of [`QuicServer::max_connections`].
///
/// Accepting a connection means building a fresh [`QuicConfig`] (TLS config,
/// certificate chain, private key) and a full [`QuicConnection`], all before
/// the peer has proved anything. RFC 9000 §8.1 anti-amplification bounds the
/// *bytes* such a peer can draw out of us but not the *state*, so the count is
/// capped here as well.
pub const DEFAULT_MAX_CONNECTIONS: usize = 4096;

/// Cap on [`QuicServer`]'s queue of connection-less responses (stateless
/// resets and Version Negotiation packets). The queue is fed by
/// unauthenticated inbound datagrams, so it needs an explicit bound; a host
/// that drains with [`QuicServer::poll_transmit`] after every
/// [`QuicServer::recv`] never comes close to it.
const MAX_PENDING_DATAGRAMS: usize = 256;

/// One hosted connection plus the peer address its outbound datagrams go to.
struct Hosted {
    conn: QuicConnection,
    addr: SocketAddr,
    /// The local connection IDs currently routed to this connection. Kept so
    /// `by_cid` can drop the entries for CIDs the peer has retired instead of
    /// growing without bound (M-5).
    cids: Vec<ConnectionId>,
}

/// A sans-I/O QUIC server that demultiplexes inbound UDP datagrams to per-peer
/// [`QuicConnection`]s by Destination Connection ID, accepts new connections on
/// unrecognised Initials, and emits the connection-less responses a single
/// connection cannot: **stateless resets** (RFC 9000 §10.3) for datagrams that
/// match no connection, and **Version Negotiation** (§6.1) for unsupported
/// versions.
///
/// Drive it like a connection: feed inbound datagrams with [`Self::recv`],
/// drain outbound datagrams with [`Self::poll_transmit`], and service timers
/// with [`Self::next_timeout`] / [`Self::on_timeout`]. The host owns one
/// unconnected `UdpSocket`; the `(SocketAddr, …)` pairs say where each datagram
/// came from and where each reply must go.
///
/// All hosted connections share one stateless-reset key, so a reset can be
/// regenerated for any connection ID the server ever issued — even after the
/// connection's own state has been dropped.
pub struct QuicServer {
    make_config: Box<dyn FnMut() -> Result<QuicConfig, Error>>,
    reset_key: [u8; 32],
    /// Hard cap on hosted connections. An unrecognised Initial arriving while
    /// the table is full is dropped rather than accepted (H-2).
    max_connections: usize,
    conns: HashMap<u64, Hosted>,
    /// Our issued local CIDs → connection id (primary routing table).
    by_cid: HashMap<ConnectionId, u64>,
    /// Source address → connection id. Fallback used before a CID is associated
    /// (e.g. a retransmitted first Initial still carrying the client's DCID).
    by_addr: HashMap<SocketAddr, u64>,
    /// Connection-less datagrams (resets, Version Negotiation) awaiting send.
    pending: VecDeque<(SocketAddr, EcnCodepoint, Vec<u8>)>,
    next_id: u64,
    now_secs: u64,
}

impl QuicServer {
    /// Builds a server. `make_config` is invoked once per accepted connection
    /// to produce its [`QuicConfig`] (typically the same TLS identity +
    /// transport parameters each time — the TLS [`Config`](crate::tls::Config)
    /// is not `Clone`, hence a factory). The server overrides `reset_key` on
    /// each config so every hosted connection shares one stateless-reset key.
    pub fn new<F>(make_config: F) -> Result<Self, Error>
    where
        F: FnMut() -> Result<QuicConfig, Error> + 'static,
    {
        let mut reset_key = [0u8; 32];
        OsRng.fill_bytes(&mut reset_key);
        Self::with_reset_key(reset_key, make_config)
    }

    /// Like [`Self::new`] but with an explicit stateless-reset key (RFC 9000
    /// §10.3.1). Persist the key across restarts so a restarted server can
    /// still reset connections established by its previous instance.
    pub fn with_reset_key<F>(reset_key: [u8; 32], make_config: F) -> Result<Self, Error>
    where
        F: FnMut() -> Result<QuicConfig, Error> + 'static,
    {
        Ok(QuicServer {
            make_config: Box::new(make_config),
            reset_key,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            conns: HashMap::new(),
            by_cid: HashMap::new(),
            by_addr: HashMap::new(),
            pending: VecDeque::new(),
            next_id: 0,
            now_secs: 0,
        })
    }

    /// Number of live connections currently hosted.
    pub fn connection_count(&self) -> usize {
        self.conns.len()
    }

    /// The cap on simultaneously hosted connections. Defaults to
    /// [`DEFAULT_MAX_CONNECTIONS`].
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Sets the cap on simultaneously hosted connections (H-2). While the
    /// table is full, an unrecognised Initial is dropped instead of allocating
    /// a whole new [`QuicConnection`] — including the TLS config, certificate
    /// chain and private key that `make_config` rebuilds per accept — for a
    /// peer that has proved nothing. Existing connections are never evicted.
    pub fn set_max_connections(&mut self, max: usize) {
        self.max_connections = max;
    }

    /// Sets the coarse wall-clock seconds source used for Retry-token minting
    /// (see [`QuicConnection::set_now_secs`]), propagated to every connection.
    pub fn set_now_secs(&mut self, secs: u64) {
        self.now_secs = secs;
        for h in self.conns.values_mut() {
            h.conn.set_now_secs(secs);
        }
    }

    /// Feeds one inbound UDP datagram received from `from` carrying IP ECN
    /// codepoint `ecn`. Routes it to the matching connection, accepts a new
    /// connection on an unrecognised Initial, or queues a connection-less
    /// response (Version Negotiation / stateless reset).
    pub fn recv(
        &mut self,
        from: SocketAddr,
        ecn: EcnCodepoint,
        datagram: &[u8],
    ) -> Result<(), Error> {
        if datagram.is_empty() {
            return Ok(());
        }
        if datagram[0] & 0x80 != 0 {
            // Long header. Read only the version-independent invariant fields
            // (RFC 8999) first: the rest of the format is version-specific, so
            // we must answer an unsupported version from these alone.
            let (version, inv_dcid, inv_scid) = match parse_long_invariant(datagram) {
                Some(t) => t,
                None => return Ok(()),
            };
            // Version 0 *is* a Version Negotiation packet, which a server never
            // receives — drop. Any other non-v1 version draws a VN listing what
            // we support (RFC 9000 §6.1); VN swaps the CIDs: its DCID echoes the
            // client's SCID and vice versa (§17.2.1).
            if version == 0 {
                return Ok(());
            }
            if version != QUIC_V1 {
                // RFC 9000 §14.1: "Servers MUST drop smaller packets that
                // specify unsupported versions." M-3: without this a 7-byte
                // spoofed datagram draws an 11-byte Version Negotiation at an
                // arbitrary address — a small but free reflector.
                if datagram.len() < MIN_INITIAL_DATAGRAM {
                    return Ok(());
                }
                let vn = build_version_negotiation(inv_scid, inv_dcid, &[QUIC_V1]);
                self.push_pending(from, EcnCodepoint::NotEct, vn);
                return Ok(());
            }
            // v1 — now the full type-aware parse is valid.
            let hdr = match LongHeader::parse(datagram) {
                Ok(h) => h,
                Err(_) => return Ok(()),
            };
            let dcid = match ConnectionId::from_slice(hdr.dcid) {
                Some(c) => c,
                None => return Ok(()),
            };
            if let Some(&id) = self.by_cid.get(&dcid) {
                self.feed(id, from, ecn, datagram);
            } else if let Some(&id) = self.by_addr.get(&from) {
                self.feed(id, from, ecn, datagram);
            } else if hdr.typ == LongType::Initial {
                self.accept(from, ecn, datagram)?;
            } else {
                // A Handshake/0-RTT packet for a connection we have no state
                // for — a stateless reset tells the peer to give up.
                self.queue_reset(from, &dcid, datagram.len());
            }
        } else {
            // Short header (1-RTT). Every CID we issue is `DEFAULT_SCID_LEN`
            // bytes, so the DCID is the bytes immediately after the first byte.
            let dlen = DEFAULT_SCID_LEN;
            if datagram.len() < 1 + dlen {
                return Ok(());
            }
            let dcid = ConnectionId::from_slice(&datagram[1..1 + dlen]).expect("len <= 20");
            if let Some(&id) = self.by_cid.get(&dcid) {
                self.feed(id, from, ecn, datagram);
            } else if let Some(&id) = self.by_addr.get(&from) {
                self.feed(id, from, ecn, datagram);
            } else {
                self.queue_reset(from, &dcid, datagram.len());
            }
        }
        Ok(())
    }

    /// Drains one outbound datagram — a queued connection-less packet first,
    /// then whatever a hosted connection has to send (paired with its peer
    /// address). `None` when there is nothing to send right now.
    pub fn poll_transmit(&mut self) -> Option<(SocketAddr, EcnCodepoint, Vec<u8>)> {
        if let Some(p) = self.pending.pop_front() {
            return Some(p);
        }
        for h in self.conns.values_mut() {
            let dg = h.conn.pop_datagram();
            if !dg.is_empty() {
                return Some((h.addr, h.conn.egress_ecn(), dg));
            }
        }
        None
    }

    /// The earliest pending timer across all hosted connections, as a duration
    /// from now. `None` if no connection has an armed timer.
    pub fn next_timeout(&self) -> Option<Duration> {
        let now = Instant::now();
        self.conns
            .values()
            .filter_map(|h| {
                h.conn
                    .next_timeout()
                    .map(|d| (h.conn.started_at() + d).saturating_duration_since(now))
            })
            .min()
    }

    /// Services timers on every hosted connection and reaps any that have
    /// closed (RFC 9002 PTO, RFC 9000 §10.1 idle timeout, …).
    pub fn on_timeout(&mut self) {
        let now = Instant::now();
        for h in self.conns.values_mut() {
            let elapsed = now.saturating_duration_since(h.conn.started_at());
            h.conn.on_timeout(elapsed);
        }
        self.reap_closed();
    }

    /// Iterates the hosted connections mutably, each paired with its peer
    /// address — e.g. to read delivered application data, open/answer streams,
    /// or queue sends, and to key per-connection host state. Outbound bytes a
    /// connection produces are routed to its peer automatically by
    /// [`Self::poll_transmit`].
    pub fn connections_mut(&mut self) -> impl Iterator<Item = (SocketAddr, &mut QuicConnection)> {
        self.conns.values_mut().map(|h| (h.addr, &mut h.conn))
    }

    // ---- internals ----

    /// Queues a connection-less response, dropping it if the queue is already
    /// at [`MAX_PENDING_DATAGRAMS`]. The queue is driven by unauthenticated
    /// inbound datagrams, so it must not be allowed to grow without bound
    /// (M-3).
    fn push_pending(&mut self, to: SocketAddr, ecn: EcnCodepoint, datagram: Vec<u8>) {
        if self.pending.len() >= MAX_PENDING_DATAGRAMS {
            return;
        }
        self.pending.push_back((to, ecn, datagram));
    }

    fn feed(&mut self, id: u64, from: SocketAddr, ecn: EcnCodepoint, datagram: &[u8]) {
        let (cids, prev_cids) = match self.conns.get_mut(&id) {
            Some(h) => {
                // Per-packet decode/auth errors are non-fatal: drop the bad
                // packet, keep the connection (RFC 9000 §5.2).
                let _ = h.conn.feed_datagram_from_with_ecn(from, ecn, datagram);
                // RFC 9000 §9 — the *connection* decides where replies go. It
                // follows the peer to a new address only after an
                // authenticated, non-probing, highest-numbered 1-RTT packet
                // arrives from there; copying `from` here unconditionally
                // would let anyone who can guess a Connection ID redirect our
                // output with a single spoofed datagram, valid or not.
                let addr = h.conn.peer_address().unwrap_or(from);
                if addr != h.addr {
                    self.by_addr.remove(&h.addr);
                    h.addr = addr;
                }
                let cids = h.conn.local_cids();
                let prev = core::mem::replace(&mut h.cids, cids.clone());
                (cids, prev)
            }
            None => return,
        };
        self.by_addr.insert(self.conns[&id].addr, id);
        // M-5: forget the CIDs this connection has stopped answering to. A
        // peer that spams RETIRE_CONNECTION_ID makes us mint a replacement
        // each time; inserting cumulatively left every superseded CID in the
        // routing table for the life of the process.
        for old in prev_cids {
            if !cids.contains(&old) {
                self.by_cid.remove(&old);
            }
        }
        // Learn any CIDs this connection now answers to (its SCID after the
        // first Initial, plus any issued via NEW_CONNECTION_ID).
        for cid in cids {
            self.by_cid.insert(cid, id);
        }
    }

    fn accept(
        &mut self,
        from: SocketAddr,
        ecn: EcnCodepoint,
        datagram: &[u8],
    ) -> Result<(), Error> {
        // H-2: reap first, so a table full of connections that have already
        // closed (idle-timed-out or reset) does not lock out fresh peers, then
        // refuse to allocate above the cap. Building the connection is
        // expensive — `make_config` rebuilds the TLS config, certificate chain
        // and private key — and nothing about an unrecognised Initial is
        // authenticated, so the state it creates has to be bounded.
        if self.conns.len() >= self.max_connections {
            self.reap_closed();
            if self.conns.len() >= self.max_connections {
                return Ok(());
            }
        }
        let mut cfg = (self.make_config)()?;
        cfg.reset_key = Some(self.reset_key);
        let mut conn = QuicConnection::server(cfg)?;
        conn.set_peer_addr(from);
        conn.set_now_secs(self.now_secs);
        let id = self.next_id;
        self.next_id += 1;
        self.conns.insert(
            id,
            Hosted {
                conn,
                addr: from,
                cids: Vec::new(),
            },
        );
        self.by_addr.insert(from, id);
        self.feed(id, from, ecn, datagram);
        Ok(())
    }

    fn queue_reset(&mut self, from: SocketAddr, dcid: &ConnectionId, triggering_len: usize) {
        // RFC 9000 §10.3: a reset must be shorter than the packet that
        // triggered it (so two resets cannot loop) and large enough to be
        // mistaken for a 1-RTT packet. Skip resets for packets too small to be
        // worth one.
        if triggering_len <= MIN_STATELESS_RESET_LEN {
            return;
        }
        let token = stateless_reset_token(&self.reset_key, dcid);
        let len = (triggering_len - 1).max(MIN_STATELESS_RESET_LEN);
        let pkt = build_stateless_reset(&mut OsRng, &token, len);
        self.push_pending(from, EcnCodepoint::NotEct, pkt);
    }

    fn reap_closed(&mut self) {
        let dead: Vec<u64> = self
            .conns
            .iter()
            .filter(|(_, h)| h.conn.is_closed())
            .map(|(&id, _)| id)
            .collect();
        for id in dead {
            self.conns.remove(&id);
            self.by_cid.retain(|_, v| *v != id);
            self.by_addr.retain(|_, v| *v != id);
        }
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use crate::ec::Ed25519PrivateKey;
    use crate::hash::Sha256;
    use crate::quic::transport_params::TransportParameters;
    use crate::rng::HmacDrbg;
    use crate::tls::{Config, Identity, ProtocolVersion, RootCertStore, SigningKey};
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
    use std::net::SocketAddr;

    /// Deterministic Ed25519 server identity for `loopback.example`. Rebuilt on
    /// each call (the TLS `Config` is not `Clone`), yielding the same key/cert.
    fn server_identity() -> (Config, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"quic-server-router-key", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut rng);
        let name = DistinguishedName::common_name("loopback.example");
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
            &["loopback.example"],
        )
        .unwrap();
        let der = cert.to_der().to_vec();
        let cfg = Config {
            identity: Some(Identity {
                cert_chain: alloc::vec![der.clone()],
                key: SigningKey::Ed25519(key),
            }),
            alpn_protocols: alloc::vec![b"test".to_vec()],
            max_version: ProtocolVersion::TLSv1_3,
            min_version: ProtocolVersion::TLSv1_3,
            ..Config::default()
        };
        (cfg, der)
    }

    fn client_config(cert_der: &[u8]) -> Config {
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der.to_vec()).unwrap();
        Config {
            roots,
            alpn_protocols: alloc::vec![b"test".to_vec()],
            max_version: ProtocolVersion::TLSv1_3,
            min_version: ProtocolVersion::TLSv1_3,
            ..Config::default()
        }
    }

    fn tp() -> TransportParameters {
        TransportParameters {
            max_idle_timeout_ms: Some(30_000),
            max_udp_payload_size: Some(1500),
            initial_max_data: Some(1 << 20),
            initial_max_stream_data_bidi_local: Some(1 << 16),
            initial_max_stream_data_bidi_remote: Some(1 << 16),
            initial_max_stream_data_uni: Some(1 << 16),
            initial_max_streams_bidi: Some(100),
            initial_max_streams_uni: Some(3),
            ack_delay_exponent: Some(3),
            max_ack_delay_ms: Some(25),
            active_connection_id_limit: Some(2),
            ..TransportParameters::default()
        }
    }

    fn client(cert_der: &[u8]) -> QuicConnection {
        QuicConnection::client(
            QuicConfig {
                tls: client_config(cert_der),
                transport_params: tp(),
                ..QuicConfig::default()
            },
            "loopback.example",
        )
        .expect("client build")
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn server(reset_key: [u8; 32]) -> QuicServer {
        QuicServer::with_reset_key(reset_key, || {
            Ok(QuicConfig {
                tls: server_identity().0,
                transport_params: tp(),
                ..QuicConfig::default()
            })
        })
        .expect("server build")
    }

    /// H-2 — an unrecognised Initial used to allocate a whole `QuicConnection`
    /// (rebuilding the TLS config, certificate chain and key) with no cap at
    /// all, so a spoofed-source flood could exhaust memory. `max_connections`
    /// now bounds the table; over the cap the Initial is dropped.
    #[test]
    fn max_connections_bounds_accepted_state() {
        let (_, cert) = server_identity();
        let mut srv = server([0x31; 32]);
        srv.set_max_connections(2);
        assert_eq!(srv.max_connections(), 2);
        for i in 0..8u16 {
            let mut c = client(&cert);
            let dg = c.pop_datagram();
            assert!(dg.len() >= 1200);
            srv.recv(addr(41000 + i), EcnCodepoint::NotEct, &dg)
                .unwrap();
        }
        assert_eq!(
            srv.connection_count(),
            2,
            "the connection table must not grow past max_connections"
        );
    }

    /// H-2 — a connection accepted from a spoofed Initial never sees peer
    /// transport parameters, so before the fix `effective_idle_timeout()`
    /// returned `None` and the entry never expired. It must now age out and be
    /// reaped by `on_timeout`.
    #[test]
    fn half_open_connection_is_reaped_by_the_idle_timer() {
        let (_, cert) = server_identity();
        // Neither side advertises a `max_idle_timeout`: exactly the shape of a
        // connection accepted from a spoofed Initial that never progresses.
        let mut srv = QuicServer::with_reset_key([0x32; 32], || {
            Ok(QuicConfig {
                tls: server_identity().0,
                transport_params: TransportParameters::default(),
                ..QuicConfig::default()
            })
        })
        .expect("server build");
        let mut c = client(&cert);
        let dg = c.pop_datagram();
        srv.recv(addr(41100), EcnCodepoint::NotEct, &dg).unwrap();
        assert_eq!(srv.connection_count(), 1);
        // Drop everything the server wants to say; the "client" never answers.
        while srv.poll_transmit().is_some() {}
        // Rewind each hosted connection's clock so the idle deadline is in the
        // past without the test having to sleep.
        let past = Instant::now() - Duration::from_secs(600);
        for h in srv.conns.values_mut() {
            h.conn.set_start_for_test(past);
        }
        srv.on_timeout();
        assert_eq!(
            srv.connection_count(),
            0,
            "a half-open connection must expire on the idle timer"
        );
        assert!(srv.by_cid.is_empty(), "its routing entries must go too");
    }

    /// M-3 — RFC 9000 §14.1: a server MUST drop packets specifying an
    /// unsupported version when they are carried in an undersized datagram.
    /// Otherwise a 7-byte spoofed datagram draws an 11-byte Version
    /// Negotiation at an address of the attacker's choosing.
    #[test]
    fn no_version_negotiation_for_undersized_datagram() {
        let mut srv = server([0x33; 32]);
        let mut pkt = alloc::vec![0xC0u8];
        pkt.extend_from_slice(&0x1a2a_3a4au32.to_be_bytes());
        pkt.push(0); // zero-length DCID
        pkt.push(0); // zero-length SCID
        assert!(pkt.len() < MIN_INITIAL_DATAGRAM);
        srv.recv(addr(50002), EcnCodepoint::NotEct, &pkt).unwrap();
        assert!(
            srv.poll_transmit().is_none(),
            "no reflected Version Negotiation for a tiny datagram"
        );
    }

    /// M-5 — retiring a connection ID must remove it from the router's `by_cid`
    /// table, not merely add its replacement.
    #[test]
    fn retired_cids_leave_the_routing_table() {
        let (_, cert) = server_identity();
        let mut srv = server([0x34; 32]);
        let mut c = client(&cert);
        let (ca, sa) = (addr(41200), addr(443));
        // Drive the handshake to completion so both sides issue extra CIDs.
        for _ in 0..64 {
            let dg = c.pop_datagram();
            if !dg.is_empty() {
                srv.recv(ca, EcnCodepoint::NotEct, &dg).unwrap();
            }
            match srv.poll_transmit() {
                Some((_, _, dg)) => c.feed_datagram_from(sa, &dg).unwrap(),
                None if dg.is_empty() => break,
                None => {}
            }
        }
        assert!(c.is_handshake_complete(), "handshake must complete");
        let before = srv.by_cid.len();
        assert!(before >= 2, "server should have issued a spare CID");
        // Retire the handshake CID, exactly as a peer's RETIRE_CONNECTION_ID
        // for sequence 0 would.
        let id = *srv.by_cid.values().next().expect("one connection");
        srv.conns
            .get_mut(&id)
            .expect("hosted")
            .conn
            .retire_local_cid_for_test(0);
        // Any subsequent feed refreshes the routing table.
        srv.feed(id, ca, EcnCodepoint::NotEct, &[]);
        assert_eq!(
            srv.by_cid.len(),
            before - 1,
            "the retired CID must be dropped from the routing table"
        );
    }

    /// Two clients sharing one `QuicServer` both complete the handshake (routed
    /// by Connection ID) and their stream data is delivered to the right
    /// connection — exercising demux, multi-connection acceptance, and routing.
    #[test]
    fn two_clients_multiplexed_with_stream_data() {
        let (_, cert) = server_identity();
        let mut srv = server([0x11; 32]);
        let mut c1 = client(&cert);
        let mut c2 = client(&cert);
        let (a1, a2, sa) = (addr(40001), addr(40002), addr(443));

        // Streams can only be opened once the handshake has surfaced the
        // peer's transport parameters, so open them mid-drive on completion.
        let mut opened = false;
        for _ in 0..128 {
            if !opened && c1.is_handshake_complete() && c2.is_handshake_complete() {
                let s1 = c1.open_bidi().unwrap();
                c1.write(s1, b"hello-from-client-1").unwrap();
                c1.finish(s1).unwrap();
                let s2 = c2.open_bidi().unwrap();
                c2.write(s2, b"hello-from-client-2").unwrap();
                c2.finish(s2).unwrap();
                opened = true;
            }
            for (c, a) in [(&mut c1, a1), (&mut c2, a2)] {
                loop {
                    let d = c.pop_datagram();
                    if d.is_empty() {
                        break;
                    }
                    srv.recv(a, EcnCodepoint::NotEct, &d).unwrap();
                }
            }
            while let Some((to, _ecn, d)) = srv.poll_transmit() {
                if to == a1 {
                    let _ = c1.feed_datagram_from(sa, &d);
                } else if to == a2 {
                    let _ = c2.feed_datagram_from(sa, &d);
                }
            }
        }

        assert!(c1.is_handshake_complete(), "client 1 handshake");
        assert!(c2.is_handshake_complete(), "client 2 handshake");
        assert_eq!(srv.connection_count(), 2, "server hosts both connections");

        // Collect the stream payloads delivered across all server connections.
        let mut got: Vec<Vec<u8>> = Vec::new();
        for (_addr, conn) in srv.connections_mut() {
            let ids: Vec<_> = conn.readable_streams().collect();
            for sid in ids {
                let mut buf = [0u8; 256];
                let (n, _fin) = conn.read(sid, &mut buf).unwrap();
                if n > 0 {
                    got.push(buf[..n].to_vec());
                }
            }
        }
        assert!(
            got.iter().any(|p| p == b"hello-from-client-1"),
            "client 1 payload delivered"
        );
        assert!(
            got.iter().any(|p| p == b"hello-from-client-2"),
            "client 2 payload delivered"
        );
    }

    /// RFC 9000 §9 through the router: when a client's address changes the
    /// server follows it — replies are addressed to the new address and the
    /// routing table moves with them — but *only* on an authenticated
    /// non-probing packet. A forged datagram claiming the same source must
    /// not redirect the connection's output.
    #[test]
    fn router_follows_client_migration_but_not_a_forged_source() {
        let (_, cert) = server_identity();
        let mut srv = server([0x44; 32]);
        let mut c = client(&cert);
        let (a_old, a_new, a_forged, sa) = (addr(41001), addr(41002), addr(41003), addr(443));

        for _ in 0..64 {
            loop {
                let d = c.pop_datagram();
                if d.is_empty() {
                    break;
                }
                srv.recv(a_old, EcnCodepoint::NotEct, &d).unwrap();
            }
            while let Some((to, _ecn, d)) = srv.poll_transmit() {
                assert_eq!(to, a_old, "pre-migration replies go to the old address");
                let _ = c.feed_datagram_from(sa, &d);
            }
            let server_done = srv
                .connections_mut()
                .next()
                .is_some_and(|(_, conn)| conn.is_handshake_complete());
            if c.is_handshake_complete() && server_done {
                break;
            }
        }
        assert!(c.is_handshake_complete());
        assert!(
            srv.connections_mut()
                .next()
                .is_some_and(|(_, conn)| conn.is_handshake_complete()),
            "server handshake complete — §9 forbids migrating before that"
        );

        // A datagram carrying the connection's real CID — which any observer
        // can read off the wire — but a payload that fails AEAD. It routes to
        // the connection, and must not redirect it.
        let cid = srv
            .connections_mut()
            .next()
            .expect("hosted connection")
            .1
            .local_cids()[0];
        let mut forged = alloc::vec![0x40u8];
        forged.extend_from_slice(cid.as_slice());
        forged.extend_from_slice(&[0x5a; 64]);
        srv.recv(a_forged, EcnCodepoint::NotEct, &forged).unwrap();
        while let Some((to, _ecn, _d)) = srv.poll_transmit() {
            assert_ne!(
                to, a_forged,
                "an unauthenticated datagram must not redirect"
            );
        }
        assert_eq!(
            srv.connections_mut().next().unwrap().1.peer_address(),
            Some(a_old),
            "the connection stays on the address that authenticated"
        );

        // A genuine packet delivered from the new address migrates the
        // connection; every subsequent reply is addressed there.
        let sid = c.open_bidi().unwrap();
        c.write(sid, b"moved").unwrap();
        let d = c.pop_datagram();
        assert!(!d.is_empty());
        srv.recv(a_new, EcnCodepoint::NotEct, &d).unwrap();

        let (to, _ecn, probe) = srv.poll_transmit().expect("path challenge");
        assert_eq!(to, a_new, "§9.3: replies follow the peer immediately");
        // Complete the validation so the connection leaves the migrating state.
        c.feed_datagram_from(sa, &probe).unwrap();
        loop {
            let d = c.pop_datagram();
            if d.is_empty() {
                break;
            }
            srv.recv(a_new, EcnCodepoint::NotEct, &d).unwrap();
        }
        let (_, conn) = srv.connections_mut().next().expect("the hosted connection");
        assert_eq!(conn.peer_address(), Some(a_new));
        assert!(
            !conn.is_migrating(),
            "PATH_RESPONSE completed the migration"
        );
    }

    /// A long-header packet carrying an unsupported version draws a Version
    /// Negotiation packet (RFC 9000 §6.1): version field 0, CIDs swapped, the
    /// supported-versions list contains QUIC v1.
    #[test]
    fn version_negotiation_for_unsupported_version() {
        let mut srv = server([0x22; 32]);
        // Hand-crafted long header: form+fixed bits, a GREASE version, an
        // 8-byte DCID and 4-byte SCID, then filler.
        let dcid = [0xA1u8; 8];
        let scid = [0xB2u8; 4];
        let mut pkt = alloc::vec![0xC0u8];
        pkt.extend_from_slice(&0x1a2a_3a4au32.to_be_bytes()); // unsupported version
        pkt.push(dcid.len() as u8);
        pkt.extend_from_slice(&dcid);
        pkt.push(scid.len() as u8);
        pkt.extend_from_slice(&scid);
        // RFC 9000 §14.1 — a server only answers datagrams of at least 1200
        // bytes, so pad the filler out to a realistic size.
        pkt.extend_from_slice(&[0u8; 1200]);

        srv.recv(addr(50001), EcnCodepoint::NotEct, &pkt).unwrap();
        let (to, _ecn, vn) = srv.poll_transmit().expect("a Version Negotiation reply");
        assert_eq!(to, addr(50001));
        // VN: long header, version field == 0.
        assert!(vn[0] & 0x80 != 0);
        assert_eq!(&vn[1..5], &[0, 0, 0, 0]);
        // CIDs are swapped: VN.dcid == incoming scid, VN.scid == incoming dcid.
        assert_eq!(vn[5] as usize, scid.len());
        assert_eq!(&vn[6..6 + scid.len()], &scid);
        let scid_len_pos = 6 + scid.len();
        assert_eq!(vn[scid_len_pos] as usize, dcid.len());
        let echoed_dcid = &vn[scid_len_pos + 1..scid_len_pos + 1 + dcid.len()];
        assert_eq!(echoed_dcid, &dcid);
        // The supported-versions list (the trailing 4-byte words) includes v1.
        let versions = &vn[scid_len_pos + 1 + dcid.len()..];
        assert!(
            versions
                .chunks_exact(4)
                .any(|w| u32::from_be_bytes([w[0], w[1], w[2], w[3]]) == QUIC_V1),
            "VN advertises QUIC v1"
        );
    }

    /// A short-header (1-RTT-shaped) packet for a Connection ID the server has
    /// no state for draws a stateless reset (RFC 9000 §10.3): short-header form,
    /// at least 21 bytes, shorter than the trigger, and ending in the token
    /// derived from the server's reset key and that CID — exactly what a peer
    /// holding the CID would recognise.
    #[test]
    fn stateless_reset_for_unknown_short_header() {
        const KEY: [u8; 32] = [0x33; 32];
        let mut srv = server(KEY);
        let unknown = crate::quic::cid::ConnectionId::from_slice(&[0xCDu8; 8]).unwrap();
        // Short header: fixed bit set, then the 8-byte DCID, then filler.
        let mut pkt = alloc::vec![0x42u8];
        pkt.extend_from_slice(unknown.as_slice());
        pkt.extend_from_slice(&[0u8; 40]);
        let trigger_len = pkt.len();

        srv.recv(addr(60001), EcnCodepoint::NotEct, &pkt).unwrap();
        let (to, _ecn, reset) = srv.poll_transmit().expect("a stateless reset reply");
        assert_eq!(to, addr(60001));
        assert!(reset.len() >= MIN_STATELESS_RESET_LEN, "reset >= 21 bytes");
        assert!(reset.len() < trigger_len, "reset shorter than the trigger");
        assert_eq!(reset[0] & 0xc0, 0x40, "short-header form (0b01xxxxxx)");
        let token = &reset[reset.len() - 16..];
        let expected = stateless_reset_token(&KEY, &unknown);
        assert_eq!(
            token, &expected,
            "reset carries the derivable token for the CID"
        );
    }
}
