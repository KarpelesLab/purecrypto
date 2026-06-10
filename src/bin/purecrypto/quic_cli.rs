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
//! Transport-parameter defaults (RFC 9000 §18.2):
//!
//! * `max_idle_timeout_ms = 60_000` (60 s — generous for CLI use).
//! * `initial_max_data = 1 MiB`, `initial_max_stream_data_* = 256 KiB`.
//! * `initial_max_streams_bidi = 16`, `initial_max_streams_uni = 16`.
//! * `ack_delay_exponent = 3`, `max_ack_delay_ms = 25`.
//! * `active_connection_id_limit = 4` — the engine now propagates the
//!   locally-advertised limit into `cid_remote.limit` at construction,
//!   so values above the RFC 9000 §18.2 minimum of 2 are honored.
//! * `max_datagram_frame_size = 1200` (RFC 9221).

use std::io::{IsTerminal, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::util::{Args, die};
use purecrypto::ec::{BoxedEcdsaPrivateKey, Ed25519PrivateKey};
use purecrypto::quic::{QuicConfig, QuicConnection, Role, StreamId, TransportParameters};
use purecrypto::rng::OsRng;
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::tls::{
    Config as TlsConfig, ProtocolVersion as PcVersion, RootCertStore, SigningKey, WriterKeyLog,
};
use purecrypto::x509::Certificate;
use std::sync::Arc;

/// Parses a comma-separated ALPN list ("h3,hq-interop") into bytes vectors.
fn parse_alpn(s: &str) -> Vec<Vec<u8>> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| p.as_bytes().to_vec())
        .collect()
}

/// Loads one or more PEM CERTIFICATE blocks from `path`, returning the
/// DER chain (leaf first).
fn load_cert_chain(path: &str) -> Vec<Vec<u8>> {
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(format!("cannot read cert file {path}: {e}")));
    let mut out = Vec::new();
    let mut block = String::new();
    let mut in_cert = false;
    for line in data.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            block.clear();
        }
        if in_cert {
            block.push_str(line);
            block.push('\n');
        }
        if line.starts_with("-----END CERTIFICATE-----") {
            in_cert = false;
            let cert = Certificate::from_pem(&block)
                .unwrap_or_else(|_| die(format!("could not parse cert in {path}")));
            out.push(cert.to_der().to_vec());
        }
    }
    if out.is_empty() {
        die(format!("{path} contained no CERTIFICATE blocks"));
    }
    out
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
    if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(&key_pem) {
        SigningKey::Rsa(k)
    } else if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(&key_pem) {
        SigningKey::Ecdsa(k)
    } else if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem(&key_pem) {
        SigningKey::Ed25519(k)
    } else {
        die(format!(
            "{key_path}: server key must be RSA (PKCS#1), ECDSA (SEC1), or Ed25519 (PKCS#8)"
        ));
    }
}

/// Opens a NSS `SSLKEYLOGFILE` sink for key logging (Unix mode 0o600).
fn open_keylog(path: &str) -> Arc<dyn purecrypto::tls::KeyLog> {
    use std::fs::OpenOptions;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let f = opts
        .open(path)
        .unwrap_or_else(|e| die(format!("cannot open keylog {path}: {e}")));
    Arc::new(WriterKeyLog::new(f))
}

/// Standard QUIC transport-parameters defaults used by both client and
/// server. See module-level doc for rationale.
fn default_transport_params() -> TransportParameters {
    TransportParameters {
        max_idle_timeout_ms: Some(60_000),
        initial_max_data: Some(1 << 20),
        initial_max_stream_data_bidi_local: Some(256 * 1024),
        initial_max_stream_data_bidi_remote: Some(256 * 1024),
        initial_max_stream_data_uni: Some(256 * 1024),
        initial_max_streams_bidi: Some(16),
        initial_max_streams_uni: Some(16),
        ack_delay_exponent: Some(3),
        max_ack_delay_ms: Some(25),
        active_connection_id_limit: Some(4),
        max_datagram_frame_size: Some(1200),
        ..TransportParameters::default()
    }
}

// ====================================================================
// Client
// ====================================================================

pub(crate) fn run_client(args: Args) {
    let value_flags = [
        "-connect",
        "-servername",
        "-CAfile",
        "-alpn",
        "-keylogfile",
        "-mtu",
    ];
    let connect = args
        .value("-connect")
        .or_else(|| args.positionals(&value_flags).first().copied())
        .unwrap_or_else(|| {
            die(
                "usage: purecrypto q_client -connect host:port [-alpn h3] [-insecure] \
                 [-servername name] [-CAfile bundle.pem] [-keylogfile keys.log] [-quiet]",
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
    let insecure = args.flag("-insecure") || args.flag("--insecure");
    let quiet = args.flag("-quiet") || args.flag("--quiet");
    // ALPN is mandatory for QUIC (RFC 9001 §8.1) — the engine rejects a
    // config without it, so demand the flag up front with a clear error.
    let alpn = args
        .value("-alpn")
        .map(parse_alpn)
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| die("QUIC requires ALPN (RFC 9001 §8.1): pass -alpn (e.g. -alpn h3)"));
    let keylog = args.value("-keylogfile").map(open_keylog);

    // Roots — QUIC v1 is TLS 1.3 only. `-insecure` skips verification;
    // otherwise trust comes from `-CAfile` if supplied, else the embedded
    // `cacrt` bundle (so chain validation works out of the box).
    let roots = if insecure {
        RootCertStore::new()
    } else if let Some(path) = args.value("-CAfile") {
        load_roots_file(path)
    } else {
        RootCertStore::with_embedded_roots()
    };

    let mut builder = TlsConfig::builder()
        .versions(PcVersion::TLSv1_3, PcVersion::TLSv1_3)
        .roots(roots)
        .server_name(server_name)
        .verify_certificates(!insecure)
        .alpn(alpn);
    if let Some(sink) = keylog {
        builder = builder.key_log(sink);
    }
    let tls_cfg = builder.build();

    let mut qcfg = QuicConfig::default();
    qcfg.tls = tls_cfg;
    qcfg.transport_params = default_transport_params();

    let socket = UdpSocket::bind("0.0.0.0:0")
        .unwrap_or_else(|e| die(format!("cannot bind local UDP socket: {e}")));
    socket
        .connect((host, port))
        .unwrap_or_else(|e| die(format!("UDP connect to {host}:{port} failed: {e}")));

    let mut qc = QuicConnection::client(qcfg, server_name)
        .unwrap_or_else(|e| die(format!("QUIC client config rejected: {e:?}")));

    drive_quic_handshake(&mut qc, &socket, None, Duration::from_secs(30));

    if !quiet {
        eprintln!(
            "connected: QUIC v1 / TLSv1.3{}",
            if insecure {
                "  (certificate NOT verified)"
            } else {
                "  (certificate verified)"
            }
        );
    }

    drive_quic_data_client(&mut qc, &socket, Duration::from_secs(30));
}

// ====================================================================
// Server
// ====================================================================

pub(crate) fn run_server(args: Args) {
    let cert_path = args.value("-cert").unwrap_or_else(|| {
        die(
            "usage: purecrypto q_server -cert cert.pem -key key.pem -accept host:port \
             [-alpn h3] [-www] [-retry] [-keylogfile keys.log] [-quiet]",
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
    let www = args.flag("-www") || args.flag("--www");
    let quiet = args.flag("-quiet") || args.flag("--quiet");
    let retry = args.flag("-retry") || args.flag("--retry");
    let keylog = args.value("-keylogfile").map(open_keylog);

    let chain = load_cert_chain(cert_path);
    let key = load_signing_key(key_path);

    let mut builder = TlsConfig::builder()
        .versions(PcVersion::TLSv1_3, PcVersion::TLSv1_3)
        .identity(chain, key)
        .alpn(alpn);
    if let Some(sink) = keylog {
        builder = builder.key_log(sink);
    }
    let tls_cfg = builder.build();

    // `-accept` accepts either `PORT` or `host:port` to match s_server.
    let accept_arg = args.value("-accept").unwrap_or("127.0.0.1:4433");
    let bind_addr = if accept_arg.contains(':') {
        accept_arg.to_string()
    } else {
        format!("127.0.0.1:{accept_arg}")
    };

    let mut qcfg = QuicConfig::default();
    qcfg.tls = tls_cfg;
    qcfg.transport_params = default_transport_params();
    if retry {
        let mut secret = [0u8; 32];
        purecrypto::rng::RngCore::fill_bytes(&mut OsRng, &mut secret);
        qcfg.require_retry = true;
        qcfg.retry_secret = Some(secret);
    }

    let socket = UdpSocket::bind(&bind_addr)
        .unwrap_or_else(|e| die(format!("cannot bind UDP {bind_addr}: {e}")));
    if !quiet {
        match socket.local_addr() {
            Ok(addr) => eprintln!("listening on {addr} (QUIC / UDP)"),
            Err(_) => eprintln!("listening on {bind_addr} (QUIC / UDP)"),
        }
    }

    // Wait for the first datagram so we learn the peer's address.
    socket.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let mut buf = vec![0u8; 1500 + 256];
    let (n, peer) = socket
        .recv_from(&mut buf)
        .unwrap_or_else(|e| die(format!("UDP recv (initial) failed: {e}")));
    if !quiet {
        eprintln!("accepted handshake start from {peer}");
    }

    // `connect` the socket so subsequent `send` / `recv` are bound to
    // this peer — and any spurious off-path datagrams (a different
    // attacker on the same machine) are filtered by the OS.
    socket
        .connect(peer)
        .unwrap_or_else(|e| die(format!("UDP connect to peer {peer}: {e}")));

    let mut qc =
        QuicConnection::server(qcfg).unwrap_or_else(|e| die(format!("QUIC server build: {e:?}")));
    qc.set_peer_addr(peer);
    qc.feed_datagram_from(peer, &buf[..n])
        .unwrap_or_else(|e| die(format!("QUIC initial feed_datagram failed: {e:?}")));

    drive_quic_handshake(&mut qc, &socket, Some(peer), Duration::from_secs(30));

    if !quiet {
        eprintln!("QUIC handshake complete");
    }

    drive_quic_data_server(&mut qc, &socket, www, Duration::from_secs(30));
}

// ====================================================================
// I/O loops
// ====================================================================

/// Drives the QUIC handshake to completion or until `deadline` expires.
///
/// `peer_addr`:
/// * `None` on the client side — the socket is already `connect`'d, so
///   `sock.send` / `sock.recv` are bound to the peer.
/// * `Some(addr)` on the server side — the server learned the peer's
///   address from the first datagram. We still use the connect'd socket
///   path (`send` / `recv`), so `peer_addr` is only carried for
///   `feed_datagram_from` (which propagates address-validation state
///   through to the engine).
fn drive_quic_handshake(
    qc: &mut QuicConnection,
    sock: &UdpSocket,
    peer_addr: Option<SocketAddr>,
    deadline: Duration,
) {
    let start = Instant::now();
    let mut buf = vec![0u8; 1500 + 256];
    loop {
        if qc.is_handshake_complete() {
            break;
        }
        if start.elapsed() > deadline {
            die(format!("QUIC handshake timed out after {deadline:?}"));
        }
        // 1. Drain outbound datagrams.
        loop {
            let dg = qc.pop_datagram();
            if dg.is_empty() {
                break;
            }
            if let Err(e) = sock.send(&dg) {
                die(format!("UDP send failed: {e}"));
            }
        }
        // 2. Choose a read deadline: bounded by next QUIC timeout and a
        //    50 ms cap so we still tick PTO timers if the wire is quiet.
        let next = qc.next_timeout().unwrap_or(Duration::from_millis(50));
        let wait = next.min(Duration::from_millis(50));
        sock.set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .ok();
        // 3. Recv. We use the connected-socket `recv` path; `peer_addr`
        //    is informational (already locked in by `connect()`).
        match sock.recv(&mut buf) {
            Ok(n) if n > 0 => {
                let res = if let Some(addr) = peer_addr {
                    qc.feed_datagram_from(addr, &buf[..n])
                } else {
                    qc.feed_datagram(&buf[..n])
                };
                if let Err(e) = res {
                    die(format!("QUIC feed_datagram failed: {e:?}"));
                }
            }
            Ok(_) => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                qc.on_timeout(start.elapsed());
            }
            Err(e) => die(format!("UDP recv failed: {e}")),
        }
    }

    // Drain any trailing handshake-tail datagrams (HANDSHAKE_DONE / final
    // acks).
    loop {
        let dg = qc.pop_datagram();
        if dg.is_empty() {
            break;
        }
        let _ = sock.send(&dg);
    }
}

/// Pumps `qc.pop_datagram` until empty, sending each on `sock`.
fn drain_outbound(qc: &mut QuicConnection, sock: &UdpSocket) {
    loop {
        let dg = qc.pop_datagram();
        if dg.is_empty() {
            break;
        }
        let _ = sock.send(&dg);
    }
}

/// Client data path: send `stdin` (if piped) over one bidi stream, dump
/// inbound stream bytes to stdout until that stream's FIN, then exit.
fn drive_quic_data_client(qc: &mut QuicConnection, sock: &UdpSocket, deadline: Duration) {
    // Open a bidirectional stream up-front; the server side accepts it
    // implicitly the first time any STREAM frame for the id arrives.
    let stream_id = match qc.open_bidi() {
        Ok(id) => id,
        Err(e) => die(format!("cannot open bidi stream: {e:?}")),
    };

    let mut to_send: Vec<u8> = Vec::new();
    if !std::io::stdin().is_terminal() {
        let _ = std::io::stdin().read_to_end(&mut to_send);
    }
    let mut sent_off = 0usize;
    let mut finished = false;
    let mut stdout = std::io::stdout();
    let mut read_buf = vec![0u8; 16 * 1024];
    let mut net_buf = vec![0u8; 1500 + 256];

    let start = Instant::now();
    let mut server_fin_seen = false;
    // After both directions are FIN'd, run the loop for a short grace
    // period so any trailing ACK datagrams land — but cap it tight so we
    // don't dawdle in the data path. 200 ms is well under any reasonable
    // RTT for the loopback test, and far below the 60 s idle timeout.
    let post_fin_grace = Duration::from_millis(200);
    let mut all_done_since: Option<Instant> = None;

    loop {
        if qc.is_closed() {
            break;
        }
        if start.elapsed() > deadline {
            break;
        }
        // Pump bytes into the stream when we have credit. `write` may
        // return 0 if the peer hasn't issued enough credit yet; the
        // QUIC engine surfaces STREAM_DATA_BLOCKED / DATA_BLOCKED.
        if sent_off < to_send.len() {
            match qc.write(stream_id, &to_send[sent_off..]) {
                Ok(n) => sent_off += n,
                Err(_) => break,
            }
            if sent_off == to_send.len() && !finished {
                let _ = qc.finish(stream_id);
                finished = true;
            }
        } else if !finished {
            // Empty stdin → finish immediately so the server isn't
            // waiting on a request body. Useful for `-www`.
            let _ = qc.finish(stream_id);
            finished = true;
        }

        drain_outbound(qc, sock);

        let next = qc.next_timeout().unwrap_or(Duration::from_millis(50));
        let wait = next.min(Duration::from_millis(50));
        sock.set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .ok();
        match sock.recv(&mut net_buf) {
            Ok(n) if n > 0 => {
                if qc.feed_datagram(&net_buf[..n]).is_err() {
                    break;
                }
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                qc.on_timeout(start.elapsed());
            }
            Err(_) => break,
        }

        // Read any inbound stream data on any readable stream (we only
        // opened one stream, but accept whatever the server sends).
        let ids: Vec<StreamId> = qc.readable_streams().collect();
        for id in ids {
            while let Ok((n, fin)) = qc.read(id, &mut read_buf) {
                if n > 0 {
                    let _ = stdout.write_all(&read_buf[..n]);
                }
                if fin && id == stream_id {
                    server_fin_seen = true;
                }
                if n == 0 {
                    break;
                }
            }
        }
        let _ = stdout.flush();

        // Once both directions are FIN'd, start a short grace timer.
        // Exit when that grace elapses with no new outbound work
        // pending. This guarantees a deterministic exit without an
        // explicit close-frame handshake.
        if finished && server_fin_seen {
            if all_done_since.is_none() {
                all_done_since = Some(Instant::now());
            }
            if all_done_since.unwrap().elapsed() > post_fin_grace {
                break;
            }
        }
    }

    drain_outbound(qc, sock);
    let _ = stdout.flush();
}

/// Server data path. With `-www`, sends a canned payload over the
/// peer-initiated bidi stream and closes. Otherwise, echoes inbound
/// bytes until FIN.
fn drive_quic_data_server(
    qc: &mut QuicConnection,
    sock: &UdpSocket,
    www: bool,
    deadline: Duration,
) {
    let mut read_buf = vec![0u8; 16 * 1024];
    let mut net_buf = vec![0u8; 1500 + 256];

    let start = Instant::now();
    let mut peer_stream: Option<StreamId> = None;
    let mut peer_fin_seen = false;
    let mut sent_canned = false;
    let mut finished = false;
    // Grace period AFTER both sides have FIN'd, to allow trailing ACKs
    // to land before we tear down the UDP socket. 500 ms is well below
    // the 60 s idle timeout but generous enough for a slow scheduler.
    let post_fin_grace = Duration::from_millis(500);
    let mut all_done_since: Option<Instant> = None;

    let canned: &[u8] = b"hello from purecrypto q_server\n";

    loop {
        if qc.is_closed() {
            break;
        }
        if start.elapsed() > deadline {
            break;
        }

        // Discover peer-initiated streams.
        let ids: Vec<StreamId> = qc.readable_streams().collect();
        for id in ids {
            if peer_stream.is_none() && id.is_client_initiated() && id.is_bidi() {
                peer_stream = Some(id);
            }
            while let Ok((n, fin)) = qc.read(id, &mut read_buf) {
                if !www && n > 0 {
                    // Echo what we read back into the same stream.
                    let _ = qc.write(id, &read_buf[..n]);
                }
                if fin && peer_stream == Some(id) {
                    peer_fin_seen = true;
                }
                if n == 0 {
                    break;
                }
            }
        }

        // Canned -www response. Send as soon as we know the peer's
        // bidi stream id (regardless of whether the peer has FIN'd
        // yet — they may be waiting for our reply before closing).
        if www
            && !sent_canned
            && let Some(id) = peer_stream
        {
            let _ = qc.write(id, canned);
            let _ = qc.finish(id);
            sent_canned = true;
            finished = true;
        }

        // Echo mode: once the peer FINs, FIN our send side back.
        if !www
            && peer_fin_seen
            && !finished
            && let Some(id) = peer_stream
        {
            let _ = qc.finish(id);
            finished = true;
        }

        drain_outbound(qc, sock);

        let next = qc.next_timeout().unwrap_or(Duration::from_millis(50));
        let wait = next.min(Duration::from_millis(50));
        sock.set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .ok();
        match sock.recv(&mut net_buf) {
            Ok(n) if n > 0 => {
                if qc.feed_datagram(&net_buf[..n]).is_err() {
                    break;
                }
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                qc.on_timeout(start.elapsed());
            }
            Err(_) => break,
        }

        // Termination — once we've FIN'd our side AND observed peer FIN
        // AND a short grace has elapsed, exit. Tying termination to
        // both-directions-FIN'd (rather than wire-idle) means the client
        // gets the full reply before the socket goes away.
        if finished && peer_fin_seen {
            if all_done_since.is_none() {
                all_done_since = Some(Instant::now());
            }
            if all_done_since.unwrap().elapsed() > post_fin_grace {
                break;
            }
        }
    }

    drain_outbound(qc, sock);
    let _: Role = qc.role();
}
