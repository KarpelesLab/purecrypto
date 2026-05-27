//! `purecrypto s_client` — open a TLS 1.2, TLS 1.3, DTLS 1.2, or DTLS 1.3
//! connection and report the result, like a minimal `openssl s_client`.
//!
//! Version selection is via mutually-exclusive flags:
//!
//! | flag          | protocol      | transport |
//! |---------------|---------------|-----------|
//! | (default)     | TLS 1.3       | TCP       |
//! | `-tls1_2`     | TLS 1.2       | TCP       |
//! | `-dtls1_2`    | DTLS 1.2      | UDP       |
//! | `-dtls1_3`    | DTLS 1.3      | UDP       |
//!
//! If more than one is given, the rightmost (latest on the command line)
//! wins — matching how `openssl s_client` resolves conflicting protocol
//! flags. The dedicated `s_dtls_client` binary is a convenience shim
//! around `s_client -dtls1_2`.

use std::io::{IsTerminal, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::pki::format_dn;
use crate::util::{Args, die};
use purecrypto::ec::{BoxedEcdsaPrivateKey, Ed25519PrivateKey};
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::tls::{
    Config, Connection, HandshakeStatus, ProtocolVersion as PcVersion, RootCertStore, SigningKey,
    WriterKeyLog,
};
use purecrypto::x509::Certificate;
use std::sync::Arc;

/// Which protocol/transport combination the CLI should drive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ProtocolVersion {
    Tls12,
    Tls13,
    Dtls12,
    Dtls13,
}

impl ProtocolVersion {
    fn to_pc_version(self) -> PcVersion {
        match self {
            ProtocolVersion::Tls12 => PcVersion::TLSv1_2,
            ProtocolVersion::Tls13 => PcVersion::TLSv1_3,
            ProtocolVersion::Dtls12 => PcVersion::DTLSv1_2,
            ProtocolVersion::Dtls13 => PcVersion::DTLSv1_3,
        }
    }
}

/// Resolves the requested protocol from CLI flags. The rightmost protocol
/// flag wins (matches openssl behaviour); if none are given, defaults to
/// TLS 1.3.
fn resolve_version(args: &Args) -> ProtocolVersion {
    let candidates = [
        (args.last_pos("-tls1_2"), ProtocolVersion::Tls12),
        (args.last_pos("--tls1_2"), ProtocolVersion::Tls12),
        (args.last_pos("-dtls1_2"), ProtocolVersion::Dtls12),
        (args.last_pos("--dtls1_2"), ProtocolVersion::Dtls12),
        (args.last_pos("-dtls1_3"), ProtocolVersion::Dtls13),
        (args.last_pos("--dtls1_3"), ProtocolVersion::Dtls13),
    ];
    let mut best: Option<(usize, ProtocolVersion)> = None;
    for (pos, v) in candidates {
        if let Some(p) = pos {
            match best {
                Some((bp, _)) if bp >= p => {}
                _ => best = Some((p, v)),
            }
        }
    }
    best.map(|(_, v)| v).unwrap_or(ProtocolVersion::Tls13)
}

/// `true` iff the rightmost protocol flag on the command line is `-quic`
/// (or `--quic`). Used to decide whether to dispatch to the QUIC driver
/// instead of the TLS / DTLS code path below. Mirrors the right-most-wins
/// semantics of [`resolve_version`].
fn has_latest_quic(args: &Args) -> bool {
    let quic_pos = args.last_pos("-quic").max(args.last_pos("--quic"));
    let Some(qp) = quic_pos else {
        return false;
    };
    for name in [
        "-tls1_2",
        "--tls1_2",
        "-tls1_3",
        "--tls1_3",
        "-dtls1_2",
        "--dtls1_2",
        "-dtls1_3",
        "--dtls1_3",
    ] {
        if let Some(op) = args.last_pos(name)
            && op > qp
        {
            return false;
        }
    }
    true
}

/// Loads trust roots: from `ca_file` if given, else the system bundle.
fn load_roots(ca_file: Option<&str>) -> RootCertStore {
    const SYSTEM_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";
    let path = ca_file.unwrap_or(SYSTEM_BUNDLE);
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(format!("cannot read CA bundle {path}: {e}")));

    let mut store = RootCertStore::new();
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
            let _ = store.add_pem(&block);
        }
    }
    store
}

/// Loads trust roots from a CA file if given, else returns an empty store.
fn load_roots_optional(ca_file: Option<&str>) -> RootCertStore {
    let mut store = RootCertStore::new();
    let Some(path) = ca_file else {
        return store;
    };
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(format!("cannot read CA bundle {path}: {e}")));
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
            let _ = store.add_pem(&block);
        }
    }
    store
}

fn print_chain(chain: &[Vec<u8>], showcerts: bool) {
    eprintln!("peer certificate chain ({} certs):", chain.len());
    for (i, der) in chain.iter().enumerate() {
        match Certificate::from_der(der.clone()) {
            Ok(cert) => {
                let subject = cert.subject().map(|d| format_dn(&d)).unwrap_or_default();
                let issuer = cert.issuer().map(|d| format_dn(&d)).unwrap_or_default();
                eprintln!("  [{i}] subject: {subject}");
                eprintln!("      issuer:  {issuer}");
                if let Ok(v) = cert.validity() {
                    eprintln!(
                        "      valid:   {} .. {}",
                        v.not_before.as_str(),
                        v.not_after.as_str()
                    );
                }
                if showcerts {
                    eprint!("{}", cert.to_pem());
                }
            }
            Err(_) => eprintln!("  [{i}] <unparseable certificate>"),
        }
    }
}

/// Parses a comma-separated ALPN list ("h2,http/1.1") into a Vec<Vec<u8>>.
fn parse_alpn(s: &str) -> Vec<Vec<u8>> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| p.as_bytes().to_vec())
        .collect()
}

/// Loads a single PEM certificate chain (one or more CERTIFICATE blocks).
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

/// Loads a client identity (cert chain + key) from `-cert` + `-key` paths.
fn load_client_identity(cert_path: &str, key_path: &str) -> (Vec<Vec<u8>>, SigningKey) {
    let chain = load_cert_chain(cert_path);
    let key_pem = std::fs::read_to_string(key_path)
        .unwrap_or_else(|e| die(format!("cannot read key file {key_path}: {e}")));
    let key = if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem(&key_pem) {
        SigningKey::Ed25519(k)
    } else if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(&key_pem) {
        SigningKey::Ecdsa(k)
    } else if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(&key_pem) {
        SigningKey::Rsa(k)
    } else {
        die(format!(
            "{key_path}: client cert key must be Ed25519 (PKCS#8), ECDSA (SEC1), or RSA (PKCS#1)"
        ));
    };
    (chain, key)
}

/// Opens `path` as the destination for an NSS `SSLKEYLOGFILE` dump.
/// Unix mode 0o600, append-only — multiple connections in the same
/// process append to the same file. The returned `Arc` is registered on
/// the [`Config`] via [`purecrypto::tls::ConfigBuilder::key_log`].
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

pub(crate) fn run(args: Args) {
    // -quic dispatches to the QUIC-specific UDP driver. We treat -quic
    // as the highest-priority protocol flag — if any other version flag
    // appears later on the command line it takes precedence (right-most
    // wins), so `q_client -tls1_3 ...` still demotes to TLS-over-TCP.
    if has_latest_quic(&args) {
        crate::quic_cli::run_client(args);
        return;
    }
    let version = resolve_version(&args);
    let value_flags = [
        "-connect",
        "-servername",
        "-CAfile",
        "-alpn",
        "-keylogfile",
        "-cert",
        "-key",
        "-mtu",
    ];
    let connect = args
        .value("-connect")
        .or_else(|| args.positionals(&value_flags).first().copied())
        .unwrap_or_else(|| {
            die(
                "usage: purecrypto s_client -connect host:port [-tls1_2 | -dtls1_2 | -dtls1_3] [-servername name] [-CAfile bundle.pem] [-insecure] [-showcerts] [-alpn h2,http/1.1] [-cert client.pem -key client.key] [-mtu N] [-keylogfile keys.log]",
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
    let showcerts = args.flag("-showcerts") || args.flag("--showcerts");
    let quiet = args.flag("-quiet") || args.flag("--quiet");
    let alpn = args.value("-alpn").map(parse_alpn);
    let mtu: usize = args
        .value("-mtu")
        .unwrap_or("1200")
        .parse()
        .unwrap_or_else(|_| die("-mtu expects a number"));
    let client_id = match (args.value("-cert"), args.value("-key")) {
        (Some(c), Some(k)) => Some(load_client_identity(c, k)),
        (Some(_), None) | (None, Some(_)) => die("both -cert and -key are required for mTLS"),
        _ => None,
    };
    let keylog = args.value("-keylogfile").map(open_keylog);

    // Build the unified config.
    let roots = match version {
        ProtocolVersion::Tls12 | ProtocolVersion::Tls13 => {
            if insecure {
                RootCertStore::new()
            } else {
                load_roots(args.value("-CAfile"))
            }
        }
        _ => {
            if !insecure && args.value("-CAfile").is_none() {
                die(
                    "DTLS client requires either -CAfile <bundle> for chain validation, \
                     or -insecure to explicitly skip verification (see openssl s_client)",
                );
            }
            load_roots_optional(args.value("-CAfile"))
        }
    };

    let mut builder = Config::builder()
        .versions(version.to_pc_version(), version.to_pc_version())
        .roots(roots)
        .server_name(server_name)
        .verify_certificates(!insecure)
        .max_record_size(mtu);
    if let Some(a) = alpn {
        builder = builder.alpn(a);
    }
    if let Some((chain, key)) = client_id {
        builder = builder.identity(chain, key);
    }
    if let Some(sink) = keylog {
        builder = builder.key_log(sink);
    }
    let cfg = builder.build();
    let mut conn = Connection::client(&cfg)
        .unwrap_or_else(|e| die(format!("client configuration rejected: {e:?}")));

    match version {
        ProtocolVersion::Tls12 | ProtocolVersion::Tls13 => {
            let mut sock = TcpStream::connect((host, port))
                .unwrap_or_else(|e| die(format!("TCP connect to {host}:{port} failed: {e}")));
            run_tcp(&mut conn, &mut sock, version, insecure, showcerts, quiet);
        }
        ProtocolVersion::Dtls12 | ProtocolVersion::Dtls13 => {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .unwrap_or_else(|e| die(format!("cannot bind local UDP socket: {e}")));
            socket
                .connect((host, port))
                .unwrap_or_else(|e| die(format!("UDP connect to {host}:{port} failed: {e}")));
            run_udp(&mut conn, &socket, mtu, version, insecure, showcerts, quiet);
        }
    }
}

fn run_tcp(
    conn: &mut Connection,
    sock: &mut TcpStream,
    version: ProtocolVersion,
    insecure: bool,
    showcerts: bool,
    quiet: bool,
) {
    drive_tcp_handshake(conn, sock);

    if !quiet {
        let v_str = match version {
            ProtocolVersion::Tls12 => "TLSv1.2",
            ProtocolVersion::Tls13 => "TLSv1.3",
            _ => "?",
        };
        eprintln!(
            "connected: {v_str}{}",
            if insecure {
                "  (certificate NOT verified)"
            } else {
                "  (certificate verified)"
            }
        );
        if let Some(p) = conn.alpn_selected() {
            eprintln!("ALPN: {}", String::from_utf8_lossy(p));
        }
        print_chain(conn.peer_certificates(), showcerts);
    }

    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    drive_tcp_data(conn, sock);
}

fn run_udp(
    conn: &mut Connection,
    socket: &UdpSocket,
    mtu: usize,
    version: ProtocolVersion,
    insecure: bool,
    showcerts: bool,
    quiet: bool,
) {
    drive_udp_handshake(conn, socket, mtu, Duration::from_secs(15));

    if !quiet {
        let v_str = match version {
            ProtocolVersion::Dtls12 => "DTLSv1.2",
            ProtocolVersion::Dtls13 => "DTLSv1.3",
            _ => "?",
        };
        eprintln!("connected: {v_str}");
        if insecure {
            eprintln!("WARNING: certificate NOT verified (-insecure)");
        } else {
            eprintln!("certificate verified");
        }
        if let Some(p) = conn.alpn_selected() {
            eprintln!("ALPN: {}", String::from_utf8_lossy(p));
        }
        let chain = conn.peer_certificates();
        if !chain.is_empty() {
            print_chain(chain, showcerts);
        }
    }

    drive_udp_data(conn, socket, mtu, Duration::from_secs(30));
}

fn drive_tcp_handshake(conn: &mut Connection, sock: &mut TcpStream) {
    let mut read_buf = [0u8; 8192];
    loop {
        // Push outbound bytes first.
        let out = conn.pop().unwrap_or_default();
        if !out.is_empty() {
            sock.write_all(&out)
                .unwrap_or_else(|e| die(format!("socket write: {e}")));
        }
        match conn.handshake() {
            Ok(HandshakeStatus::Complete) => return,
            Ok(HandshakeStatus::WantWrite) => continue,
            Ok(HandshakeStatus::WantRead) => {
                let n = sock
                    .read(&mut read_buf)
                    .unwrap_or_else(|e| die(format!("socket read: {e}")));
                if n == 0 {
                    die("peer closed during handshake");
                }
                conn.feed(&read_buf[..n])
                    .unwrap_or_else(|e| die(format!("TLS feed failed: {e:?}")));
            }
            Err(e) => die(format!("TLS handshake failed: {e:?}")),
        }
    }
}

fn drive_tcp_data(conn: &mut Connection, sock: &mut TcpStream) {
    let mut stdout = std::io::stdout();

    // Drain any plaintext the engine already decoded during the
    // handshake — the server may have piggy-backed the
    // CCS/Finished/AppData/close_notify into one TCP segment, in which
    // case the handshake loop's last `feed` already gave us the
    // response (and possibly the EOF too) before we ever entered this
    // function. Print it before we touch the socket.
    let pre = conn.recv().unwrap_or_default();
    if !pre.is_empty() {
        let _ = stdout.write_all(&pre);
    }

    if !std::io::stdin().is_terminal() {
        let mut input = Vec::new();
        if std::io::stdin().read_to_end(&mut input).is_ok() && !input.is_empty() {
            let _ = conn.send(&input);
            if let Ok(out) = conn.pop() {
                let _ = sock.write_all(&out);
                let _ = sock.flush();
            }
        }
    }

    let mut buf = [0u8; 4096];
    loop {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if conn.feed(&buf[..n]).is_err() {
                    break;
                }
                let plain = conn.recv().unwrap_or_default();
                if !plain.is_empty() && stdout.write_all(&plain).is_err() {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    let _ = stdout.flush();
}

fn drive_udp_handshake(conn: &mut Connection, socket: &UdpSocket, mtu: usize, deadline: Duration) {
    let start = Instant::now();
    let mut buf = vec![0u8; mtu.max(1500) + 256];
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    while !conn.is_handshake_complete() {
        if start.elapsed() > deadline {
            die("DTLS handshake deadline exceeded");
        }
        // Drain outbound datagrams.
        loop {
            let dg = conn.pop().unwrap_or_default();
            if dg.is_empty() {
                break;
            }
            socket
                .send(&dg)
                .unwrap_or_else(|e| die(format!("UDP send failed: {e}")));
        }
        // Try to receive.
        match socket.recv(&mut buf) {
            Ok(n) => {
                let _ = conn.feed(&buf[..n]);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Fire any pending timer.
                if let Some(t) = conn.next_timeout() {
                    conn.on_timeout(t);
                }
            }
            Err(e) => die(format!("UDP recv failed: {e}")),
        }
    }
    // Drain trailing handshake outputs (acks etc.).
    loop {
        let dg = conn.pop().unwrap_or_default();
        if dg.is_empty() {
            break;
        }
        let _ = socket.send(&dg);
    }
}

fn drive_udp_data(conn: &mut Connection, socket: &UdpSocket, mtu: usize, deadline: Duration) {
    if !std::io::stdin().is_terminal() {
        let mut input = Vec::new();
        if std::io::stdin().read_to_end(&mut input).is_ok() && !input.is_empty() {
            let _ = conn.send(&input);
            loop {
                let dg = conn.pop().unwrap_or_default();
                if dg.is_empty() {
                    break;
                }
                let _ = socket.send(&dg);
            }
        }
    }

    let mut stdout = std::io::stdout();
    let mut buf = vec![0u8; mtu.max(1500) + 256];
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .ok();
    let start = Instant::now();
    let idle_limit = Duration::from_secs(2);
    let mut last_inbound = Instant::now();
    while start.elapsed() < deadline {
        match socket.recv(&mut buf) {
            Ok(n) => {
                last_inbound = Instant::now();
                let _ = conn.feed(&buf[..n]);
                let plain = conn.recv().unwrap_or_default();
                if !plain.is_empty() && stdout.write_all(&plain).is_err() {
                    return;
                }
                let _ = stdout.flush();
                // Drain any outbound (e.g. ACKs) the engine queued.
                loop {
                    let dg = conn.pop().unwrap_or_default();
                    if dg.is_empty() {
                        break;
                    }
                    let _ = socket.send(&dg);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if last_inbound.elapsed() > idle_limit {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = stdout.flush();
}
