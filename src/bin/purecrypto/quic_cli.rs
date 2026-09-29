//! `purecrypto` QUIC CLI driver — shared UDP I/O loop for the `q_client`
//! / `q_server` subcommands (and for the `-quic` flag on `s_client` /
//! `s_server`).
//!
//! Mirrors the [`crate::s_client`] `drive_udp_*` pattern used by DTLS,
//! but the engine here is [`purecrypto::quic::QuicConnection`]: it is
//! datagram-oriented at the UDP layer AND stream-oriented at the
//! application layer, which doesn't fit `tls::Connection`'s
//! byte-stream `feed`/`pop` / `send`/`recv` shape. The QUIC engine is
//! therefore driven directly.
//!
//! Application protocol (shared with the interop peers in
//! `tools/quic-interop/`): the server echoes every client-initiated
//! bidirectional stream back on itself, answers every client-initiated
//! unidirectional stream with a server-initiated one carrying the same
//! bytes, and echoes every DATAGRAM frame (RFC 9221). `-www` replaces the
//! bidi echo with a canned reply. The client sends stdin over one stream
//! (or as DATAGRAMs) and writes what comes back to stdout.
//!
//! Transport-parameter defaults (RFC 9000 §18.2):
//!
//! * `max_idle_timeout_ms = 60_000` (60 s — generous for CLI use; see
//!   `-idle-timeout`).
//! * `initial_max_data = 1 MiB`, `initial_max_stream_data_* = 256 KiB`.
//! * `initial_max_streams_bidi = 16`, `initial_max_streams_uni = 16`.
//! * `ack_delay_exponent = 3`, `max_ack_delay_ms = 25`.
//! * `active_connection_id_limit = 4` — the engine now propagates the
//!   locally-advertised limit into `cid_remote.limit` at construction,
//!   so values above the RFC 9000 §18.2 minimum of 2 are honored.
//! * `max_datagram_frame_size = 1200` (RFC 9221).

use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::util::{Args, die, load_cert_chain, open_keylog, parse_alpn, parse_hex_flag, zero_buf};
use purecrypto::hash::{Digest, Sha256};
use purecrypto::quic::{
    CloseInfo, CloseInitiator, CloseKind, QuicConfig, QuicConnection, QuicServer, QuicSession,
    QuicVersion, StreamId, TransportParameters,
};
use purecrypto::rng::OsRng;
use purecrypto::tls::{
    Config as TlsConfig, ProtocolVersion as PcVersion, RootCertStore, SigningKey,
};

/// Wall-clock seconds since the Unix epoch, for the QUIC retry-token
/// clock ([`QuicConnection::set_now_secs`]). The engine treats 0 as "no
/// clock configured" and disables stateless Retry fail-closed, so a
/// pre-epoch system clock (which maps to 0 here) simply turns the
/// `-retry` flag into a no-op rather than minting unexpirable tokens.
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Loads a PEM CA bundle into a `RootCertStore`.
fn load_roots_file(path: &str) -> RootCertStore {
    let mut store = RootCertStore::new();
    crate::util::load_pem_certs_into(path, |pem| store.add_pem(pem));
    store
}

/// Reads a PEM-encoded server key as a unified [`SigningKey`].
fn load_signing_key(key_path: &str) -> SigningKey {
    crate::util::warn_if_world_readable_key(key_path);
    let key_pem = std::fs::read_to_string(key_path)
        .unwrap_or_else(|e| die(format!("cannot read key file {key_path}: {e}")));
    crate::util::signing_key_from_pem(&key_pem).unwrap_or_else(|| {
        die(format!(
            "{key_path}: server key must be RSA (PKCS#1 or PKCS#8), ECDSA (SEC1 or PKCS#8), \
             Ed25519 or Ed448 (PKCS#8)"
        ))
    })
}

/// Standard QUIC transport-parameters defaults used by both client and
/// server. See module-level doc for rationale. `idle_ms` overrides the
/// `max_idle_timeout` (`-idle-timeout`).
fn default_transport_params(idle_ms: Option<u64>) -> TransportParameters {
    // `TransportParameters` is `#[non_exhaustive]` (new parameters keep
    // being registered), so start from the defaults and set fields.
    let mut tp = TransportParameters::default();
    tp.max_idle_timeout_ms = Some(idle_ms.unwrap_or(60_000));
    tp.initial_max_data = Some(1 << 20);
    tp.initial_max_stream_data_bidi_local = Some(256 * 1024);
    tp.initial_max_stream_data_bidi_remote = Some(256 * 1024);
    tp.initial_max_stream_data_uni = Some(256 * 1024);
    tp.initial_max_streams_bidi = Some(16);
    tp.initial_max_streams_uni = Some(16);
    tp.ack_delay_exponent = Some(3);
    tp.max_ack_delay_ms = Some(25);
    tp.active_connection_id_limit = Some(4);
    tp.max_datagram_frame_size = Some(1200);
    tp
}

/// `-quic_versions v1,v2` → [`QuicVersion`]s in preference order (the first
/// is the client's original / first-flight version). Comma-separated,
/// `v1`/`1` and `v2`/`2` accepted (RFC 9368 / RFC 9369).
fn parse_versions(list: &str) -> Vec<QuicVersion> {
    let mut out = Vec::new();
    for name in list.split(',').filter(|s| !s.is_empty()) {
        let v = match name.trim() {
            "v1" | "1" => QuicVersion::V1,
            "v2" | "2" => QuicVersion::V2,
            other => die(format!(
                "-quic_versions: unknown QUIC version '{other}' (v1, v2)"
            )),
        };
        if !out.contains(&v) {
            out.push(v);
        }
    }
    if out.is_empty() {
        die("-quic_versions: empty version list");
    }
    out
}

/// `-ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256` →
/// IANA ids, in order. Colon- or comma-separated, OpenSSL spelling.
fn parse_ciphersuites(list: &str) -> Vec<u16> {
    list.split([':', ','])
        .filter(|s| !s.is_empty())
        .map(|name| match name.to_ascii_uppercase().as_str() {
            "TLS_AES_128_GCM_SHA256" => 0x1301,
            "TLS_AES_256_GCM_SHA384" => 0x1302,
            "TLS_CHACHA20_POLY1305_SHA256" => 0x1303,
            _ => die(format!(
                "-ciphersuites: unknown TLS 1.3 suite '{name}' (TLS_AES_128_GCM_SHA256, \
                 TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256)"
            )),
        })
        .collect()
}

/// IANA cipher-suite id → registered name, for the negotiation log line.
fn suite_name(id: u16) -> &'static str {
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        _ => "UNKNOWN",
    }
}

/// Parses a `-flag N` numeric value, dying on garbage.
fn parse_num(args: &Args, flag: &str) -> Option<u64> {
    args.value(flag).map(|v| {
        v.parse::<u64>()
            .unwrap_or_else(|_| die(format!("{flag}: expected a number, got '{v}'")))
    })
}

fn sha256_hex(data: &[u8]) -> String {
    crate::util::to_hex(&Sha256::digest(data))
}

/// One line describing what the handshake negotiated — the interop matrix
/// checks these fields against the peer's own report.
fn negotiated_line(qc: &QuicConnection) -> String {
    let alpn = qc
        .alpn_protocol()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .unwrap_or_else(|| "none".into());
    let suite = qc
        .negotiated_cipher_suite()
        .map(suite_name)
        .unwrap_or("none");
    let early = match qc.early_data_accepted() {
        Some(true) => "accepted",
        Some(false) => "rejected",
        None if qc.early_data_offered() => "offered",
        None => "none",
    };
    // `group=` and `hrr=` go last: the interop harnesses match the line
    // by prefix.
    let group = qc.negotiated_group().map(|g| g.name()).unwrap_or("none");
    format!(
        "negotiated: alpn={alpn} suite={suite} version={} resumed={} early_data={early} retry={} group={group} hrr={}",
        qc.version(),
        yes_no(qc.is_resumed()),
        yes_no(qc.retry_used()),
        yes_no(qc.hello_retry_request_used()),
    )
}

/// RFC 9000 §13.4.2 — whether the peer's ACKs validated this endpoint's
/// ECT(0) marking. Only meaningful once 1-RTT traffic has been acknowledged,
/// so it is reported when the connection ends, not with the handshake.
fn ecn_line(qc: &QuicConnection) -> String {
    format!("ecn validated: {}", yes_no(qc.ecn_validated()))
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// Renders [`QuicConnection::close_info`] for the log.
fn close_line(qc: &QuicConnection) -> String {
    close_info_line(qc.close_info())
}

/// Renders a [`CloseInfo`] for the log.
fn close_info_line(info: Option<&CloseInfo>) -> String {
    let Some(info) = info else {
        return "closed: (no close information)".into();
    };
    match info.initiator {
        CloseInitiator::IdleTimeout => "closed: idle timeout".into(),
        CloseInitiator::StatelessReset => "closed: stateless reset".into(),
        who => {
            let who = if who == CloseInitiator::Peer {
                "peer"
            } else {
                "local"
            };
            let kind = match info.kind {
                CloseKind::Application => "application",
                CloseKind::Transport => "transport",
                _ => "unknown",
            };
            format!(
                "closed: {kind} error {:#x} ({}) by {who}",
                info.error_code, info.reason
            )
        }
    }
}

// ====================================================================
// Socket I/O
// ====================================================================

/// A connected client socket plus the connection's clock. Owns the
/// receive buffer so `pump` allocates nothing per datagram.
struct ClientIo {
    sock: UdpSocket,
    peer: SocketAddr,
    epoch: Instant,
    buf: Vec<u8>,
}

impl ClientIo {
    fn connect(host: &str, port: u16, epoch: Instant) -> Self {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .unwrap_or_else(|e| die(format!("cannot bind local UDP socket: {e}")));
        sock.connect((host, port))
            .unwrap_or_else(|e| die(format!("UDP connect to {host}:{port} failed: {e}")));
        // Mark egress ECT(0) and request the ECN codepoint on receive so the
        // engine's ECN support (RFC 9000 §13.4) works over the real socket;
        // Linux-only, a no-op elsewhere.
        crate::ecn_socket::configure(&sock);
        let peer = sock
            .peer_addr()
            .unwrap_or_else(|e| die(format!("UDP peer address unavailable: {e}")));
        ClientIo {
            sock,
            peer,
            epoch,
            buf: vec![0u8; 1500 + 256],
        }
    }

    fn local_addr(&self) -> String {
        self.sock
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into())
    }

    /// Pumps `qc.pop_datagram` until empty, sending each on the socket.
    fn drain_outbound(&self, qc: &mut QuicConnection) -> Result<(), String> {
        loop {
            let dg = qc.pop_datagram();
            if dg.is_empty() {
                return Ok(());
            }
            self.sock
                .send(&dg)
                .map_err(|e| format!("UDP send failed: {e}"))?;
        }
    }

    /// One I/O round: send what the engine queued, then block for at most
    /// the engine's next timer (capped at 50 ms) waiting for one datagram,
    /// feeding it or ticking the timers. Errors are fatal socket errors.
    fn pump(&mut self, qc: &mut QuicConnection) -> Result<(), String> {
        self.drain_outbound(qc)?;
        let wait = quic_wait(qc, self.epoch);
        self.sock.set_read_timeout(Some(wait)).ok();
        match crate::ecn_socket::recv_ecn(&self.sock, &mut self.buf) {
            Ok((n, _from, ecn)) if n > 0 => {
                qc.set_now_secs(unix_now_secs());
                // The socket is connected, so the datagram came from the
                // peer; the engine needs the address only for its
                // address-validation bookkeeping.
                if let Err(e) = qc.feed_datagram_from_with_ecn(self.peer, ecn, &self.buf[..n]) {
                    return Err(format!("QUIC feed_datagram failed: {e:?}"));
                }
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                qc.on_timeout(self.epoch.elapsed());
            }
            // ICMP port-unreachable surfaces here on a connected socket:
            // the peer is gone, and the caller decides what that means.
            Err(e) => return Err(format!("UDP recv failed: {e}")),
        }
        Ok(())
    }
}

/// How long to block in `recv` before ticking the engine: until its next
/// timer (`next_timeout` is absolute, measured from `epoch`), capped at
/// 50 ms so a quiet wire still gets regular `on_timeout` calls, and at
/// least 1 ms (a zero read timeout means "block forever" to the socket).
fn quic_wait(qc: &QuicConnection, epoch: Instant) -> Duration {
    qc.next_timeout()
        .map(|t| t.saturating_sub(epoch.elapsed()))
        .unwrap_or(Duration::from_millis(50))
        .clamp(Duration::from_millis(1), Duration::from_millis(50))
}

// ====================================================================
// Application exchange (client side)
// ====================================================================

#[derive(Copy, Clone, PartialEq, Eq)]
enum Mode {
    Bidi,
    Uni,
    Datagram,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Bidi => "bidi",
            Mode::Uni => "uni",
            Mode::Datagram => "datagram",
        }
    }
}

/// One echo round trip in progress: the payload going out and the reply
/// coming back. Started before the handshake for 0-RTT, after it otherwise.
struct Exchange {
    mode: Mode,
    payload: Vec<u8>,
    sent_off: usize,
    finished: bool,
    /// The stream we send on (bidi or our uni).
    send_stream: Option<StreamId>,
    /// The stream we read the reply from (the bidi stream, or the server's
    /// uni stream once it appears).
    recv_stream: Option<StreamId>,
    reply: Vec<u8>,
    reply_fin: bool,
    /// Datagram mode: how many echoes are still owed, and when to stop
    /// waiting for them (they are unreliable).
    datagrams_owed: usize,
    datagram_deadline: Option<Instant>,
}

impl Exchange {
    fn start(qc: &mut QuicConnection, mode: Mode, payload: Vec<u8>) -> Result<Self, String> {
        let mut ex = Exchange {
            mode,
            payload,
            sent_off: 0,
            finished: false,
            send_stream: None,
            recv_stream: None,
            reply: Vec::new(),
            reply_fin: false,
            datagrams_owed: 0,
            datagram_deadline: None,
        };
        match mode {
            Mode::Bidi => {
                let id = qc
                    .open_bidi()
                    .map_err(|e| format!("cannot open bidi stream: {e:?}"))?;
                ex.send_stream = Some(id);
                ex.recv_stream = Some(id);
            }
            Mode::Uni => {
                let id = qc
                    .open_uni()
                    .map_err(|e| format!("cannot open uni stream: {e:?}"))?;
                ex.send_stream = Some(id);
            }
            Mode::Datagram => {
                // Every line of the payload is one DATAGRAM; the handshake
                // must be complete (the engine keeps them out of 0-RTT).
                let mut owed = 0;
                let text = String::from_utf8_lossy(&ex.payload).into_owned();
                for line in text.lines().filter(|l| !l.is_empty()) {
                    let mut d = line.as_bytes().to_vec();
                    d.push(b'\n');
                    qc.send_datagram(&d)
                        .map_err(|e| format!("cannot send DATAGRAM: {e:?}"))?;
                    owed += 1;
                }
                ex.datagrams_owed = owed;
                ex.datagram_deadline = Some(Instant::now() + Duration::from_secs(2));
                ex.finished = true;
            }
        }
        Ok(ex)
    }

    /// Advances the exchange: writes as much payload as the peer's credit
    /// allows, reads what arrived. Returns `true` once the reply is
    /// complete.
    fn step(&mut self, qc: &mut QuicConnection) -> Result<bool, String> {
        if let Some(id) = self.send_stream {
            if self.sent_off < self.payload.len() {
                let n = qc
                    .write(id, &self.payload[self.sent_off..])
                    .map_err(|e| format!("stream write failed: {e:?}"))?;
                self.sent_off += n;
            }
            if self.sent_off == self.payload.len() && !self.finished {
                qc.finish(id)
                    .map_err(|e| format!("stream finish failed: {e:?}"))?;
                self.finished = true;
            }
        }
        match self.mode {
            Mode::Datagram => {
                while let Some(d) = qc.recv_datagram() {
                    self.reply.extend_from_slice(&d);
                    self.datagrams_owed = self.datagrams_owed.saturating_sub(1);
                }
                let expired = self.datagram_deadline.is_some_and(|t| Instant::now() >= t);
                Ok(self.datagrams_owed == 0 || expired)
            }
            Mode::Bidi | Mode::Uni => {
                let ids: Vec<StreamId> = qc.readable_streams().collect();
                for id in ids {
                    // Uni mode: the reply arrives on the first
                    // server-initiated unidirectional stream.
                    if self.recv_stream.is_none()
                        && self.mode == Mode::Uni
                        && id.is_server_initiated()
                        && id.is_uni()
                    {
                        self.recv_stream = Some(id);
                    }
                    if self.recv_stream != Some(id) {
                        continue;
                    }
                    let mut buf = [0u8; 16 * 1024];
                    while let Ok((n, fin)) = qc.read(id, &mut buf) {
                        self.reply.extend_from_slice(&buf[..n]);
                        if fin {
                            self.reply_fin = true;
                        }
                        if n == 0 || fin {
                            break;
                        }
                    }
                }
                Ok(self.reply_fin)
            }
        }
    }
}

// ====================================================================
// Client
// ====================================================================

/// Everything `-connect` needs to build one connection; kept so
/// `-reconnect` can build a second one with the first one's session.
struct ClientSetup<'a> {
    server_name: &'a str,
    insecure: bool,
    ca_file: Option<&'a str>,
    alpn: Vec<Vec<u8>>,
    keylog: Option<&'a str>,
    suites: Option<Vec<u16>>,
    groups: Option<Vec<purecrypto::tls::NamedGroup>>,
    key_shares: Option<Vec<purecrypto::tls::NamedGroup>>,
    idle_ms: Option<u64>,
    early_data: bool,
    versions: Option<Vec<QuicVersion>>,
}

impl ClientSetup<'_> {
    fn build(&self, resumption: Option<QuicSession>) -> QuicConnection {
        // Roots — QUIC v1 is TLS 1.3 only. `-insecure` skips verification;
        // otherwise trust comes from `-CAfile` if supplied, else the
        // embedded `cacrt` bundle (so chain validation works out of the
        // box).
        let roots = if self.insecure {
            RootCertStore::new()
        } else if let Some(path) = self.ca_file {
            load_roots_file(path)
        } else {
            RootCertStore::with_embedded_roots()
        };
        let mut builder = TlsConfig::builder()
            .versions(PcVersion::TLSv1_3, PcVersion::TLSv1_3)
            .roots(roots)
            .server_name(self.server_name)
            .verify_certificates(!self.insecure)
            .alpn(self.alpn.clone());
        if let Some(path) = self.keylog {
            builder = builder.key_log(open_keylog(path));
        }
        if let Some(suites) = &self.suites {
            builder = builder.cipher_suites(suites);
        }
        if let Some(groups) = &self.groups {
            builder = builder.key_exchange_groups(groups);
        }
        if let Some(groups) = &self.key_shares {
            builder = builder.key_shares(groups);
        }
        let mut qcfg = QuicConfig::default();
        qcfg.tls = builder.build();
        qcfg.transport_params = default_transport_params(self.idle_ms);
        qcfg.enable_early_data = self.early_data;
        qcfg.resumption = resumption;
        // `-quic_versions` (RFC 9368/9369): the first entry is the client's
        // original / first-flight version, the rest are offered for a
        // compatible upgrade. Left at the library default when unset.
        if let Some(versions) = &self.versions {
            qcfg.versions = versions.clone();
            qcfg.original_version = versions.first().copied();
        }
        QuicConnection::client(qcfg, self.server_name)
            .unwrap_or_else(|e| die(format!("QUIC client config rejected: {e:?}")))
    }
}

pub(crate) fn run_client(args: Args) {
    let value_flags = [
        "-connect",
        "-servername",
        "-CAfile",
        "-alpn",
        "-keylogfile",
        "-mtu",
        "-ciphersuites",
        "-groups",
        "-key-shares",
        "-close-code",
        "-close-reason",
        "-idle-timeout",
        "-linger",
        "-exchanges",
        "-pause",
        "-timeout",
        "-quic_versions",
    ];
    let connect = args
        .value("-connect")
        .or_else(|| args.positionals(&value_flags).first().copied())
        .unwrap_or_else(|| {
            die(
                "usage: purecrypto q_client -connect host:port -alpn proto [-insecure] \
                 [-servername name] [-CAfile bundle.pem] [-keylogfile keys.log] [-quiet] \
                 [-uni | -datagram] [-exchanges N] [-pause ms] [-migrate] [-switch-cid] \
                 [-reconnect [-early-data]] [-key-update] [-ciphersuites list] \
                 [-groups list] [-key-shares groups] [-close-code N] [-close-reason text] \
                 [-idle-timeout ms] [-linger ms] [-timeout secs]",
            )
        });
    let (host, port) = match connect.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .unwrap_or_else(|_| die(format!("invalid port: {p}"))),
        ),
        None => (connect, 443),
    };
    let server_name = args.value("-servername").unwrap_or(host);
    let insecure = args.flag("-insecure");
    let quiet = args.flag("-quiet");
    // ALPN is mandatory for QUIC (RFC 9001 §8.1) — the engine rejects a
    // config without it, so demand the flag up front with a clear error.
    let alpn = args
        .value("-alpn")
        .map(parse_alpn)
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| die("QUIC requires ALPN (RFC 9001 §8.1): pass -alpn (e.g. -alpn h3)"));
    let mode = match (args.flag("-uni"), args.flag("-datagram")) {
        (true, true) => die("-uni and -datagram are mutually exclusive"),
        (true, false) => Mode::Uni,
        (false, true) => Mode::Datagram,
        (false, false) => Mode::Bidi,
    };
    let exchanges = parse_num(&args, "-exchanges").unwrap_or(1).max(1);
    let pause = Duration::from_millis(parse_num(&args, "-pause").unwrap_or(0));
    let migrate = args.flag("-migrate");
    let switch_cid = args.flag("-switch-cid");
    let reconnect = args.flag("-reconnect");
    let early_data = args.flag("-early-data");
    if early_data && !reconnect {
        die("-early-data needs -reconnect: 0-RTT rides on the first connection's ticket");
    }
    let key_update = args.flag("-key-update");
    let close_code = parse_num(&args, "-close-code").unwrap_or(0);
    let close_reason = args
        .value("-close-reason")
        .unwrap_or("")
        .as_bytes()
        .to_vec();
    let linger = Duration::from_millis(parse_num(&args, "-linger").unwrap_or(0));
    let deadline = Duration::from_secs(parse_num(&args, "-timeout").unwrap_or(30));
    let setup = ClientSetup {
        server_name,
        insecure,
        ca_file: args.value("-CAfile"),
        alpn,
        keylog: args.value("-keylogfile"),
        suites: args.value("-ciphersuites").map(parse_ciphersuites),
        // `-groups`: the `supported_groups` offer, as `s_client -groups`.
        groups: args
            .value("-groups")
            .map(|list| crate::tlsinfo::parse_groups(list, "-groups")),
        key_shares: args.value("-key-shares").map(|list| {
            list.split(',')
                .filter(|g| !g.is_empty())
                .map(|g| crate::util::parse_group(g, "-key-shares"))
                .collect()
        }),
        idle_ms: parse_num(&args, "-idle-timeout"),
        early_data,
        versions: args.value("-quic_versions").map(parse_versions),
    };

    // The payload: stdin when piped, else empty (finish the stream at once,
    // which is what a `-www` server wants).
    let mut payload: Vec<u8> = Vec::new();
    if !std::io::stdin().is_terminal() {
        let _ = std::io::stdin().read_to_end(&mut payload);
    }

    let runs = if reconnect { 2 } else { 1 };
    let mut session: Option<QuicSession> = None;
    for run in 1..=runs {
        let resumption = session.take();
        if run == 2 && resumption.is_none() {
            die("-reconnect: the server issued no session ticket on the first connection");
        }
        let mut qc = setup.build(resumption);
        // One clock for the connection's whole life: `on_timeout` takes the
        // time since the connection was created, and the engine's own packet
        // clock starts here too. Restarting it per phase made the data phase
        // report a time that jumped back to zero, delaying PTO / loss
        // detection by the handshake duration.
        let epoch = Instant::now();
        let mut io = ClientIo::connect(host, port, epoch);
        let start = Instant::now();
        let mut stdout = std::io::stdout();

        // 0-RTT: the first exchange is started before the handshake so its
        // bytes travel in 0-RTT packets alongside the Initial. DATAGRAMs
        // are deliberately not allowed there by the engine.
        let mut pending: Option<Exchange> = None;
        if run == 2 && qc.early_data_offered() && mode != Mode::Datagram {
            pending = Some(
                Exchange::start(&mut qc, mode, payload.clone())
                    .unwrap_or_else(|e| die(format!("0-RTT: {e}"))),
            );
        }
        if !quiet && run == 2 {
            eprintln!(
                "reconnecting with the session ticket (0-RTT {})",
                if qc.early_data_offered() {
                    "offered"
                } else {
                    "not offered"
                }
            );
        }

        // Handshake.
        while !qc.is_handshake_complete() {
            if start.elapsed() > deadline {
                die(format!("QUIC handshake timed out after {deadline:?}"));
            }
            if qc.is_closed() {
                die(format!("QUIC handshake failed: {}", close_line(&qc)));
            }
            if let Err(e) = io.pump(&mut qc) {
                die(format!("QUIC handshake failed: {e}"));
            }
        }
        // Security-relevant, so it goes to stderr regardless of -quiet: an
        // unattended `-quiet -insecure` pipeline must not be able to hide
        // that the peer identity was never checked. Same string as
        // s_client.
        if insecure {
            eprintln!("WARNING: certificate NOT verified (-insecure)");
        }
        if !quiet {
            eprintln!(
                "connected: QUIC v1 / TLSv1.3{}",
                if insecure {
                    "  (certificate NOT verified)"
                } else {
                    "  (certificate verified)"
                }
            );
            eprintln!("{}", negotiated_line(&qc));
        }

        let mut key_update_started = false;
        let mut key_update_reported = false;
        let mut cid_switched = false;
        let mut failure: Option<String> = None;

        'runs: for i in 1..=exchanges {
            if i > 1 {
                // Between exchanges: optionally sit idle, then move to a new
                // local socket (a client-side migration, RFC 9000 §9): the
                // server sees the new source address on the next packet and
                // validates it with a PATH_CHALLENGE, which the engine
                // answers. Probe the new path ourselves too (§9.2).
                let until = Instant::now() + pause;
                while Instant::now() < until {
                    if qc.is_closed() {
                        break 'runs;
                    }
                    if let Err(e) = io.pump(&mut qc) {
                        failure = Some(e);
                        break 'runs;
                    }
                }
                if migrate {
                    io = ClientIo::connect(host, port, epoch);
                    match qc.send_path_challenge() {
                        Ok(_) => {
                            if !quiet {
                                eprintln!("migrated: now sending from {}", io.local_addr());
                            }
                        }
                        Err(e) => {
                            failure = Some(format!("migration: cannot probe the new path: {e:?}"));
                            break 'runs;
                        }
                    }
                }
            }
            let mut ex = match pending.take() {
                Some(ex) => ex,
                None => match Exchange::start(&mut qc, mode, payload.clone()) {
                    Ok(ex) => ex,
                    Err(e) => {
                        failure = Some(e);
                        break 'runs;
                    }
                },
            };
            loop {
                if qc.is_closed() {
                    failure = Some(format!(
                        "connection closed mid-exchange: {}",
                        close_line(&qc)
                    ));
                    break 'runs;
                }
                if start.elapsed() > deadline {
                    failure = Some(format!("exchange {i} timed out after {deadline:?}"));
                    break 'runs;
                }
                // Housekeeping the interop matrix can ask for: a key update
                // once the handshake is confirmed (the engine refuses
                // earlier, RFC 9001 §6.2), and a connection-ID switch.
                if key_update && !key_update_started && qc.initiate_key_update().is_ok() {
                    key_update_started = true;
                    if !quiet {
                        eprintln!(
                            "key update initiated: now sending in phase {}",
                            qc.key_phase()
                        );
                    }
                }
                if key_update_started && !key_update_reported && !qc.key_update_pending() {
                    key_update_reported = true;
                    if !quiet {
                        eprintln!("key update confirmed: phase {}", qc.key_phase());
                    }
                }
                if switch_cid && !cid_switched && qc.switch_connection_id().is_ok() {
                    cid_switched = true;
                    if !quiet {
                        eprintln!("switched to a new destination connection id");
                    }
                }
                match ex.step(&mut qc) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(e) => {
                        failure = Some(e);
                        break 'runs;
                    }
                }
                if let Err(e) = io.pump(&mut qc) {
                    failure = Some(e);
                    break 'runs;
                }
            }
            let _ = stdout.write_all(&ex.reply);
            let _ = stdout.flush();
            if !quiet {
                eprintln!(
                    "exchange {i}: {} {} bytes sent sha256={}, {} bytes received sha256={}, from {}",
                    ex.mode.name(),
                    ex.payload.len(),
                    sha256_hex(&ex.payload),
                    ex.reply.len(),
                    sha256_hex(&ex.reply),
                    io.local_addr(),
                );
            }
        }

        if let Some(e) = failure {
            eprintln!("purecrypto: {e}");
            if qc.close_info().is_some() {
                eprintln!("{}", close_line(&qc));
            }
            std::process::exit(1);
        }

        // Give a pending key update its confirmation ACK and let trailing
        // ACKs land; with `-linger`, stay idle until the peer closes (or the
        // idle timeout fires) so the close reason can be reported.
        let grace = if linger > Duration::ZERO {
            linger
        } else {
            Duration::from_millis(200)
        };
        let until = Instant::now() + grace;
        while Instant::now() < until && !qc.is_closed() {
            if qc.close_info().is_some() && linger == Duration::ZERO {
                break;
            }
            if key_update_started && !key_update_reported && !qc.key_update_pending() {
                key_update_reported = true;
                if !quiet {
                    eprintln!("key update confirmed: phase {}", qc.key_phase());
                }
            }
            if io.pump(&mut qc).is_err() {
                break;
            }
        }
        if key_update_started && !key_update_reported && !quiet {
            eprintln!("key update NOT confirmed: phase {}", qc.key_phase());
        }
        if !quiet {
            eprintln!("{}", ecn_line(&qc));
        }
        if !quiet && qc.close_info().is_some() {
            eprintln!("{}", close_line(&qc));
        }

        // RFC 9000 §10.2 — leave gracefully: emit an application
        // CONNECTION_CLOSE (NO_ERROR unless `-close-code`) so the peer learns
        // the connection ended deliberately instead of waiting out its idle
        // timeout.
        if qc.close_info().is_none() {
            let _ = qc.close(close_code, &close_reason);
            if !quiet {
                eprintln!("closing: application error {close_code:#x}");
            }
        }
        let _ = io.drain_outbound(&mut qc);

        if run == 1 && reconnect {
            session = qc.take_session();
            if !quiet {
                match &session {
                    Some(s) => eprintln!(
                        "session ticket received (0-RTT {})",
                        if s.supports_early_data() {
                            "permitted"
                        } else {
                            "not permitted"
                        }
                    ),
                    None => eprintln!("no session ticket received"),
                }
            }
        }
    }
}

// ====================================================================
// Server
// ====================================================================

pub(crate) fn run_server(args: Args) {
    let cert_path = args.value("-cert").unwrap_or_else(|| {
        die(
            "usage: purecrypto q_server -cert cert.pem -key key.pem -accept host:port -alpn proto \
             [-www] [-retry] [-early-data] [-key-update] [-switch-cid] [-ciphersuites list] \
             [-groups list] [-idle-timeout ms] [-reset-key hex32] [-naccept N] [-timeout secs] \
             [-keylogfile keys.log] [-quiet]",
        )
    });
    let key_path = args
        .value("-key")
        .unwrap_or_else(|| die("-key is required"));
    // ALPN is mandatory for QUIC (RFC 9001 §8.1) — see run_client.
    let alpn = args
        .value("-alpn")
        .map(parse_alpn)
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| die("QUIC requires ALPN (RFC 9001 §8.1): pass -alpn (e.g. -alpn h3)"));
    let www = args.flag("-www");
    let quiet = args.flag("-quiet");
    let retry = args.flag("-retry");
    let early_data = args.flag("-early-data");
    let keylog = args.value("-keylogfile").map(open_keylog);
    let suites = args.value("-ciphersuites").map(parse_ciphersuites);
    // `-groups`: the accept-set in server preference, as `s_server -groups`.
    let groups = args
        .value("-groups")
        .map(|list| crate::tlsinfo::parse_groups(list, "-groups"));
    let idle_ms = parse_num(&args, "-idle-timeout");
    // `-quic_versions` (RFC 9368/9369): the versions this server accepts and
    // advertises in Version Negotiation, in preference order. Default: the
    // library's SUPPORTED_VERSIONS.
    let versions = args.value("-quic_versions").map(parse_versions);
    let server_versions = versions.clone();
    let opts = ServerOpts {
        www,
        quiet,
        key_update: args.flag("-key-update"),
        switch_cid: args.flag("-switch-cid"),
        naccept: parse_num(&args, "-naccept").unwrap_or(1) as usize,
        deadline: Duration::from_secs(parse_num(&args, "-timeout").unwrap_or(30)),
    };
    // `-reset-key`: the RFC 9000 §10.3.1 stateless-reset key. Fixed so a
    // restarted server can still reset the connections its predecessor
    // held; random otherwise.
    let reset_key: [u8; 32] = match args.value("-reset-key") {
        Some(hex) => parse_hex_flag(hex, "-reset-key")
            .try_into()
            .unwrap_or_else(|_| die("-reset-key: expected 32 bytes of hex")),
        None => {
            let mut k = [0u8; 32];
            purecrypto::rng::RngCore::fill_bytes(&mut OsRng, &mut k);
            k
        }
    };

    // `-accept` accepts either `PORT` or `host:port` to match s_server.
    let accept_arg = args.value("-accept").unwrap_or("127.0.0.1:4433");
    let bind_addr = if accept_arg.contains(':') {
        accept_arg.to_string()
    } else {
        format!("127.0.0.1:{accept_arg}")
    };

    // One ticket key for the process, so a session issued on one connection
    // resumes on the next (`q_client -reconnect`). Fresh per run: tickets
    // outlive nothing here.
    let mut ticket_key = [0u8; 32];
    purecrypto::rng::RngCore::fill_bytes(&mut OsRng, &mut ticket_key);
    let ticket_key = purecrypto::tls::Secret32::from(ticket_key);

    // Own everything the per-connection config factory needs. The TLS
    // `Config` and `SigningKey` are rebuilt per accepted connection from the
    // files on disk (fine for a CLI server).
    let cert_path = cert_path.to_string();
    let key_path = key_path.to_string();
    let make_config = move || -> Result<QuicConfig, purecrypto::tls::Error> {
        let chain = load_cert_chain(&cert_path);
        let key = load_signing_key(&key_path);
        let mut builder = TlsConfig::builder()
            .versions(PcVersion::TLSv1_3, PcVersion::TLSv1_3)
            .try_identity(chain, key)
            .unwrap_or_else(|e| die(crate::util::identity_error(&cert_path, &key_path, e)))
            .alpn(alpn.clone())
            .ticket_key(ticket_key.clone());
        if let Some(sink) = keylog.clone() {
            builder = builder.key_log(sink);
        }
        if let Some(suites) = &suites {
            builder = builder.cipher_suites(suites);
        }
        if let Some(groups) = &groups {
            builder = builder.key_exchange_groups(groups);
        }
        let mut qcfg = QuicConfig::default();
        qcfg.tls = builder.build();
        qcfg.transport_params = default_transport_params(idle_ms);
        // 0-RTT data is replayable; an echo server has nothing to lose.
        qcfg.enable_early_data = early_data;
        if let Some(vs) = &versions {
            qcfg.versions = vs.clone();
        }
        if retry {
            let mut secret = [0u8; 32];
            purecrypto::rng::RngCore::fill_bytes(&mut OsRng, &mut secret);
            qcfg.require_retry = true;
            qcfg.retry_secret = Some(secret.into());
            // `Secret32::from` copies the array; scrub our stack copy.
            zero_buf(&mut secret);
        }
        Ok(qcfg)
    };

    // Validate the identity once, up front: the factory is otherwise first
    // run when the first Initial arrives, so a cert/key mismatch (which
    // `try_identity` reports by name) would surface long after "listening"
    // was printed. `s_server` refuses the same before listening.
    let _ = make_config();

    let socket = UdpSocket::bind(&bind_addr)
        .unwrap_or_else(|e| die(format!("cannot bind UDP {bind_addr}: {e}")));
    if !quiet {
        match socket.local_addr() {
            Ok(addr) => eprintln!("listening on {addr} (QUIC / UDP)"),
            Err(_) => eprintln!("listening on {bind_addr} (QUIC / UDP)"),
        }
    }

    // An UNconnected socket + a QuicServer router: datagrams from any peer
    // are demultiplexed by Connection ID, new connections are accepted, and
    // datagrams that match no connection draw a stateless reset (RFC 9000
    // §10.3) — which the old single-connection, `connect`'d-socket server
    // could never see, let alone answer.
    // Mark egress ECT(0) and request the IP ECN codepoint on receive so the
    // engine's ECN support (RFC 9000 §13.4) works over the real socket
    // (Linux; a no-op elsewhere).
    crate::ecn_socket::configure(&socket);

    let mut server = QuicServer::with_reset_key(reset_key, make_config)
        .unwrap_or_else(|e| die(format!("QUIC server build: {e:?}")));
    // Keep the router's Version Negotiation offer consistent with the config
    // factory's versions (RFC 9368 §5), so a client the router bounced with
    // a VN packet reconnects with a version this server actually accepts.
    if let Some(vs) = &server_versions {
        server.set_offered_versions(vs);
    }
    server.set_now_secs(unix_now_secs());

    run_quic_server_loop(&mut server, &socket, &opts);
}

/// Behaviour switches for [`run_quic_server_loop`].
struct ServerOpts {
    www: bool,
    quiet: bool,
    /// Initiate a key update on every connection once its handshake is
    /// confirmed.
    key_update: bool,
    /// Switch to a fresh peer-issued connection ID once available.
    switch_cid: bool,
    /// Exit after this many connections have ended (0 = keep serving until
    /// the deadline).
    naccept: usize,
    /// Exit after this long regardless.
    deadline: Duration,
}

/// Outbound bytes owed on one stream, drained as the peer grants credit.
#[derive(Default)]
struct StreamOut {
    pending: Vec<u8>,
    /// FIN once `pending` has drained.
    finish: bool,
    done: bool,
}

/// Per-connection application state for the demo server.
#[derive(Default)]
struct ServerConnState {
    /// The first peer-initiated bidi stream — the one `-www` answers on.
    first_bidi: Option<StreamId>,
    /// Bytes still to be written on a stream (echo backlog / uni reply).
    out: HashMap<StreamId, StreamOut>,
    /// Peer-initiated uni streams being collected until their FIN.
    uni_in: HashMap<StreamId, Vec<u8>>,
    /// Bytes seen per inbound stream, for the per-stream log line.
    seen: HashMap<StreamId, (usize, Sha256)>,
    /// `-www`: the canned reply has been sent + finished.
    canned_sent: Option<Instant>,
    announced: bool,
    key_update_started: bool,
    key_update_reported: bool,
    cid_switched: bool,
    last_addr: Option<SocketAddr>,
    ended: bool,
}

/// Drives the [`QuicServer`] router I/O loop: receive → route, run the demo
/// application logic (echo, or a canned `-www` reply) per connection, and
/// send outbound datagrams (including connection-less resets / Version
/// Negotiation) to their peers. Exits once `naccept` connections have ended
/// (plus a short grace for trailing ACKs) or the deadline elapses — the
/// `QuicServer` itself stays multi-connection; this CLI demo serves a fixed
/// number of connections then exits so it composes with the loopback tests.
fn run_quic_server_loop(server: &mut QuicServer, sock: &UdpSocket, opts: &ServerOpts) {
    let canned: &[u8] = b"hello from purecrypto q_server\n";
    let mut net_buf = vec![0u8; 1500 + 256];
    // Keyed by the original destination connection ID: stable across
    // connection-ID rotation and migration, unlike the peer address.
    let mut app: HashMap<Vec<u8>, ServerConnState> = HashMap::new();
    let post_done_grace = Duration::from_millis(500);
    let start = Instant::now();
    let mut ended = 0usize;
    let mut done_since: Option<Instant> = None;

    loop {
        if start.elapsed() > opts.deadline {
            break;
        }
        server.set_now_secs(unix_now_secs());

        // 1. Receive one datagram, bounded by the soonest connection timer.
        let wait = server
            .next_timeout()
            .unwrap_or(Duration::from_millis(100))
            .clamp(Duration::from_millis(1), Duration::from_millis(100));
        sock.set_read_timeout(Some(wait)).ok();
        match crate::ecn_socket::recv_ecn(sock, &mut net_buf) {
            Ok((n, from, ecn)) if n > 0 => {
                let vn_before = server.version_negotiations_sent();
                let _ = server.recv(from, ecn, &net_buf[..n]);
                if server.version_negotiations_sent() > vn_before && !opts.quiet {
                    eprintln!("version negotiation sent to {from} (unsupported version offered)");
                }
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                server.on_timeout();
            }
            Err(_) => break,
        }
        // Connections the router dropped since the last pass (idle timeout,
        // stateless reset, or a peer close whose draining period elapsed).
        for gone in server.drain_closed() {
            let st = app.entry(gone.original_dcid.clone()).or_default();
            if !st.ended {
                st.ended = true;
                if !opts.quiet && st.announced {
                    eprintln!("{}", close_info_line(gone.close.as_ref()));
                }
            }
        }

        // 2. Application logic per connection.
        for (addr, conn) in server.connections_mut() {
            let Some(key) = conn.original_dcid().map(|c| c.to_vec()) else {
                continue;
            };
            let st = app.entry(key).or_default();
            serve_connection(conn, addr, st, opts, canned);
            if st.ended && !st.announced {
                // Never completed a handshake: count it, say nothing.
                st.announced = true;
            }
        }

        // 3. Drain outbound datagrams to their peers.
        while let Some((to, _ecn, dg)) = server.poll_transmit() {
            let _ = sock.send_to(&dg, to);
        }

        // 4. Count ended connections; exit after `naccept` of them (plus a
        //    short grace so trailing ACKs / the close land before the socket
        //    goes away).
        let now_ended = app.values().filter(|s| s.ended).count();
        if now_ended > ended {
            ended = now_ended;
        }
        if opts.naccept > 0 && ended >= opts.naccept {
            let since = done_since.get_or_insert_with(Instant::now);
            if since.elapsed() > post_done_grace {
                break;
            }
        }
    }

    // RFC 9000 §10.2 — tell every peer we are going away with an application
    // CONNECTION_CLOSE (NO_ERROR) rather than vanishing and leaving them to
    // time out.
    for (_addr, conn) in server.connections_mut() {
        if !conn.is_closed() && conn.close_info().is_none() {
            let _ = conn.close(0, b"");
        }
    }
    while let Some((to, _ecn, dg)) = server.poll_transmit() {
        let _ = sock.send_to(&dg, to);
    }
    if !opts.quiet {
        eprintln!("served {} connection(s)", app.len());
    }
}

/// One pass of the demo application over one connection.
fn serve_connection(
    conn: &mut QuicConnection,
    addr: SocketAddr,
    st: &mut ServerConnState,
    opts: &ServerOpts,
    canned: &[u8],
) {
    let quiet = opts.quiet;
    if st.ended {
        return;
    }
    if !st.announced && conn.is_handshake_complete() {
        st.announced = true;
        st.last_addr = Some(addr);
        if !quiet {
            eprintln!("QUIC handshake complete");
            eprintln!("{} peer={addr}", negotiated_line(conn));
        }
    }
    if let Some(info) = conn.close_info()
        && (info.initiator != CloseInitiator::Local || conn.is_closed())
    {
        st.ended = true;
        if !quiet {
            // Streams the peer never finished (e.g. `openssl s_client`, which
            // closes the connection at EOF instead of the stream): report
            // what arrived before the close.
            let mut open: Vec<(StreamId, (usize, Sha256))> = st.seen.drain().collect();
            open.sort_by_key(|(id, _)| *id);
            for (id, (count, hasher)) in open {
                eprintln!(
                    "stream {}: {} bytes received sha256={} from {addr} (no FIN before close)",
                    id.value(),
                    count,
                    crate::util::to_hex(&hasher.finalize())
                );
            }
            eprintln!("{}", ecn_line(conn));
            eprintln!("{}", close_line(conn));
        }
        return;
    }
    if !conn.is_handshake_complete() {
        return;
    }
    if st.last_addr.is_some_and(|a| a != addr) {
        st.last_addr = Some(addr);
        if !quiet {
            eprintln!("peer migrated to {addr}");
        }
    }

    // Housekeeping the interop matrix can ask for.
    if opts.key_update && !st.key_update_started && conn.initiate_key_update().is_ok() {
        st.key_update_started = true;
        if !quiet {
            eprintln!(
                "key update initiated: now sending in phase {}",
                conn.key_phase()
            );
        }
    }
    if st.key_update_started && !st.key_update_reported && !conn.key_update_pending() {
        st.key_update_reported = true;
        if !quiet {
            eprintln!("key update confirmed: phase {}", conn.key_phase());
        }
    }
    if opts.switch_cid && !st.cid_switched && conn.switch_connection_id().is_ok() {
        st.cid_switched = true;
        if !quiet {
            eprintln!("switched to a new destination connection id");
        }
    }

    // Inbound streams. Bidi: echo (bounded backlog so a peer that stops
    // granting credit cannot make us buffer without limit). Uni: collect,
    // then answer on a uni stream of ours.
    const BACKLOG_CAP: usize = 256 * 1024;
    let ids: Vec<StreamId> = conn.readable_streams().collect();
    for id in ids {
        if !id.is_client_initiated() {
            continue;
        }
        if id.is_bidi() && st.first_bidi.is_none() {
            st.first_bidi = Some(id);
        }
        if id.is_bidi()
            && st
                .out
                .get(&id)
                .is_some_and(|o| o.pending.len() >= BACKLOG_CAP)
        {
            continue;
        }
        let mut buf = [0u8; 16 * 1024];
        while let Ok((n, fin)) = conn.read(id, &mut buf) {
            if n > 0 {
                let (count, hasher) = st.seen.entry(id).or_insert_with(|| (0, Sha256::new()));
                *count += n;
                hasher.update(&buf[..n]);
            }
            if id.is_bidi() {
                if !opts.www {
                    let o = st.out.entry(id).or_default();
                    o.pending.extend_from_slice(&buf[..n]);
                    if fin {
                        o.finish = true;
                    }
                }
            } else {
                st.uni_in
                    .entry(id)
                    .or_default()
                    .extend_from_slice(&buf[..n]);
                if fin && let Some(data) = st.uni_in.remove(&id) {
                    match conn.open_uni() {
                        Ok(reply_id) => {
                            st.out.insert(
                                reply_id,
                                StreamOut {
                                    pending: data,
                                    finish: true,
                                    done: false,
                                },
                            );
                            if !quiet {
                                eprintln!(
                                    "stream {}: {} bytes received on the uni stream, answering on uni {}",
                                    id.value(),
                                    st.seen.get(&id).map(|s| s.0).unwrap_or(0),
                                    reply_id.value()
                                );
                            }
                        }
                        Err(e) => eprintln!("purecrypto: cannot open a uni stream: {e:?}"),
                    }
                }
            }
            if fin && !quiet {
                let (count, hasher) = st.seen.remove(&id).unwrap_or_else(|| (0, Sha256::new()));
                eprintln!(
                    "stream {}: {} bytes received sha256={} from {addr}",
                    id.value(),
                    count,
                    crate::util::to_hex(&hasher.finalize())
                );
            }
            if n == 0 || fin {
                break;
            }
        }
    }

    // `-www`: send the canned body once we know the peer's bidi stream.
    if opts.www
        && st.canned_sent.is_none()
        && let Some(id) = st.first_bidi
    {
        st.out.insert(
            id,
            StreamOut {
                pending: canned.to_vec(),
                finish: true,
                done: false,
            },
        );
        st.canned_sent = Some(Instant::now());
    }

    // Drain outbound backlogs as credit allows; FIN when done.
    for (id, o) in st.out.iter_mut() {
        if o.done {
            continue;
        }
        if !o.pending.is_empty() {
            match conn.write(*id, &o.pending) {
                Ok(n) => {
                    o.pending.drain(..n);
                }
                Err(_) => {
                    o.done = true;
                    continue;
                }
            }
        }
        if o.pending.is_empty() && o.finish {
            let _ = conn.finish(*id);
            o.done = true;
        }
    }
    st.out.retain(|_, o| !o.done);

    // DATAGRAM echo (RFC 9221).
    while let Some(d) = conn.recv_datagram() {
        if conn.send_datagram(&d).is_ok() && !quiet {
            eprintln!(
                "echoed datagram {} bytes sha256={}",
                d.len(),
                sha256_hex(&d)
            );
        }
    }

    // `-www`: the connection's job is done once the reply is out; close it
    // ourselves if the client has not, after a grace for the data to land.
    if let Some(at) = st.canned_sent
        && at.elapsed() > Duration::from_secs(2)
        && conn.close_info().is_none()
    {
        let _ = conn.close(0, b"");
        st.ended = true;
    }
}
