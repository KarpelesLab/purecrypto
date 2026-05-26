//! `purecrypto s_server` — minimal TLS 1.2, TLS 1.3, DTLS 1.2, or DTLS 1.3
//! echo / `-www` server, like a pared-down `openssl s_server`. Single-shot:
//! accepts one connection, completes the handshake, exchanges data, closes.
//!
//! Version selection mirrors `s_client`:
//!
//! | flag         | protocol | transport |
//! |--------------|----------|-----------|
//! | (default)    | TLS 1.3  | TCP       |
//! | `-tls1_2`    | TLS 1.2  | TCP       |
//! | `-dtls1_2`   | DTLS 1.2 | UDP       |
//! | `-dtls1_3`   | DTLS 1.3 | UDP       |

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::util::{Args, die};
use purecrypto::ec::{BoxedEcdsaPrivateKey, Ed25519PrivateKey};
use purecrypto::rng::OsRng;
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::tls::{
    ClientAuth, Config, Connection, HandshakeStatus, ProtocolVersion as PcVersion, RootCertStore,
    SigningKey,
};
use purecrypto::x509::Certificate;

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

/// Resolves the requested protocol from CLI flags. Right-most wins.
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

/// Parses a comma-separated ALPN list.
fn parse_alpn(s: &str) -> Vec<Vec<u8>> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| p.as_bytes().to_vec())
        .collect()
}

/// Loads a PEM cert file (one or more CERTIFICATE blocks) as a DER chain.
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

/// Loads a PEM CA bundle into a RootCertStore.
fn load_roots_file(path: &str) -> RootCertStore {
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

/// Reads a server key from PEM as a unified [`SigningKey`].
fn load_signing_key(key_path: &str) -> SigningKey {
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

pub(crate) fn run(args: Args) {
    let version = resolve_version(&args);
    let cert_path = args.value("-cert").unwrap_or_else(|| {
        die(
            "usage: purecrypto s_server -cert cert.pem -key key.pem -accept PORT \
             [-tls1_2 | -dtls1_2 | -dtls1_3] [-Verify ca.pem] [-alpn h2,http/1.1] [-www] \
             [-mtu N] [-no_cookie]",
        )
    });
    let key_path = args
        .value("-key")
        .unwrap_or_else(|| die("-key is required"));
    let verify_ca = args.value("-Verify");
    let alpn = args.value("-alpn").map(parse_alpn);
    let www = args.flag("-www") || args.flag("--www");
    let quiet = args.flag("-quiet") || args.flag("--quiet");
    let no_cookie = args.flag("-no_cookie") || args.flag("--no_cookie");
    let mtu: usize = args
        .value("-mtu")
        .unwrap_or("1200")
        .parse()
        .unwrap_or_else(|_| die("-mtu expects a number"));

    let chain = load_cert_chain(cert_path);
    let key = load_signing_key(key_path);

    let mut builder = Config::builder()
        .versions(version.to_pc_version(), version.to_pc_version())
        .identity(chain, key)
        .max_record_size(mtu);
    if let Some(a) = alpn {
        builder = builder.alpn(a);
    }
    if let Some(p) = verify_ca {
        let roots = load_roots_file(p);
        builder = builder.client_auth(ClientAuth {
            roots,
            required: true,
        });
    }
    if matches!(version, ProtocolVersion::Dtls12 | ProtocolVersion::Dtls13) {
        if no_cookie {
            builder = builder.no_cookie();
        } else {
            let mut secret = [0u8; 32];
            purecrypto::rng::RngCore::fill_bytes(&mut OsRng, &mut secret);
            builder = builder.cookie_secret(secret);
        }
    }
    let cfg = builder.build();

    match version {
        ProtocolVersion::Tls12 | ProtocolVersion::Tls13 => {
            let port: u16 = args
                .value("-accept")
                .unwrap_or("4433")
                .parse()
                .unwrap_or_else(|_| die("-accept expects a port number"));
            let listener = TcpListener::bind(("127.0.0.1", port))
                .unwrap_or_else(|e| die(format!("cannot bind 127.0.0.1:{port}: {e}")));
            if !quiet {
                eprintln!("listening on 127.0.0.1:{port}");
            }
            let (mut sock, peer) = listener
                .accept()
                .unwrap_or_else(|e| die(format!("accept failed: {e}")));
            if !quiet {
                eprintln!("accepted connection from {peer}");
            }
            let mut conn = Connection::server(&cfg)
                .unwrap_or_else(|e| die(format!("server config rejected: {e:?}")));
            run_tcp(&mut conn, &mut sock, www, quiet);
        }
        ProtocolVersion::Dtls12 | ProtocolVersion::Dtls13 => {
            if verify_ca.is_some() {
                die(
                    "DTLS server does not yet implement client authentication (-Verify unsupported)",
                );
            }
            let accept = args.value("-accept").unwrap_or("127.0.0.1:4434");
            run_udp(&cfg, accept, mtu, quiet);
        }
    }
}

fn run_tcp(conn: &mut Connection, sock: &mut TcpStream, www: bool, quiet: bool) {
    drive_tcp_handshake(conn, sock);

    if !quiet {
        eprintln!("handshake complete");
        if let Some(p) = conn.alpn_selected() {
            eprintln!("ALPN: {}", String::from_utf8_lossy(p));
        }
        if !conn.peer_certificates().is_empty() {
            eprintln!(
                "client presented {} certificate(s)",
                conn.peer_certificates().len()
            );
        }
    }

    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    if www {
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf);
        let _ = conn.recv();
        let body = b"hello from purecrypto s_server\n";
        let resp = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = conn.send(resp.as_bytes());
        let _ = conn.send(body);
        let out = conn.pop().unwrap_or_default();
        let _ = sock.write_all(&out);
        let _ = sock.flush();
    } else {
        let mut buf = [0u8; 4096];
        loop {
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if conn.feed(&buf[..n]).is_err() {
                        break;
                    }
                    let plain = conn.recv().unwrap_or_default();
                    if !plain.is_empty() {
                        if conn.send(&plain).is_err() {
                            break;
                        }
                        let out = conn.pop().unwrap_or_default();
                        if !out.is_empty() && sock.write_all(&out).is_err() {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }
}

fn drive_tcp_handshake(conn: &mut Connection, sock: &mut TcpStream) {
    let mut read_buf = [0u8; 8192];
    loop {
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

fn run_udp(cfg: &Config, accept: &str, mtu: usize, quiet: bool) {
    let socket =
        UdpSocket::bind(accept).unwrap_or_else(|e| die(format!("cannot bind UDP {accept}: {e}")));
    let bound = socket.local_addr().ok();
    if !quiet {
        match bound {
            Some(addr) => eprintln!("listening on {addr} (DTLS / UDP)"),
            None => eprintln!("listening on {accept} (DTLS / UDP)"),
        }
    }
    let mut buf = vec![0u8; mtu.max(1500) + 256];
    socket.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let (n, peer) = socket
        .recv_from(&mut buf)
        .unwrap_or_else(|e| die(format!("UDP recv (initial) failed: {e}")));
    if !quiet {
        eprintln!("accepted handshake start from {peer}");
    }
    buf.truncate(n);
    socket
        .connect(peer)
        .unwrap_or_else(|e| die(format!("UDP connect to peer {peer}: {e}")));

    let mut conn =
        Connection::server(cfg).unwrap_or_else(|e| die(format!("server config rejected: {e:?}")));
    let _ = conn.feed(&buf);

    drive_udp_handshake(&mut conn, &socket, mtu, Duration::from_secs(15));

    if !quiet {
        eprintln!("DTLS handshake complete");
    }
    drive_udp_echo(&mut conn, &socket, mtu, Duration::from_secs(5));
    let _ = peer;
    let _: Option<SocketAddr> = bound;
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
        loop {
            let dg = conn.pop().unwrap_or_default();
            if dg.is_empty() {
                break;
            }
            let _ = socket.send(&dg);
        }
        match socket.recv(&mut buf) {
            Ok(n) => {
                let _ = conn.feed(&buf[..n]);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if let Some(t) = conn.next_timeout() {
                    conn.on_timeout(t);
                }
            }
            Err(e) => die(format!("UDP recv failed: {e}")),
        }
    }
    // Drain any pending ACK datagrams.
    loop {
        let dg = conn.pop().unwrap_or_default();
        if dg.is_empty() {
            break;
        }
        let _ = socket.send(&dg);
    }
}

fn drive_udp_echo(conn: &mut Connection, socket: &UdpSocket, mtu: usize, idle_limit: Duration) {
    let mut buf = vec![0u8; mtu.max(1500) + 256];
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .ok();
    let mut last_activity = Instant::now();
    loop {
        if last_activity.elapsed() > idle_limit {
            break;
        }
        match socket.recv(&mut buf) {
            Ok(n) => {
                last_activity = Instant::now();
                if conn.feed(&buf[..n]).is_err() {
                    break;
                }
                let plain = conn.recv().unwrap_or_default();
                if !plain.is_empty() && conn.send(&plain).is_err() {
                    break;
                }
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
            { /* idle tick */ }
            Err(_) => break,
        }
    }
}
