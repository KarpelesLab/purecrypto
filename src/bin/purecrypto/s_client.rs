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
use std::time::Duration;

use crate::dtls_io;
use crate::pki::format_dn;
use crate::util::{Args, die, to_hex};
use purecrypto::dtls::{
    DtlsClientConfig12, DtlsClientConfig13, DtlsClientConnection12, DtlsClientConnection13,
};
use purecrypto::ec::{BoxedEcdsaPrivateKey, Ed25519PrivateKey};
use purecrypto::rng::OsRng;
use purecrypto::tls::{
    ClientCertConfig, ClientConfig, ClientConfig12, ClientConnection, ClientConnection12,
    RootCertStore, Stream,
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
            let _ = store.add_pem(&block); // skip roots with unsupported key types
        }
    }
    store
}

/// Loads trust roots from a CA file if given, else returns an empty store
/// (used by the DTLS paths whose default is `-insecure` without a bundle).
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

/// Loads a client cert configuration from `-cert` + `-key` paths. Supports
/// Ed25519 (PKCS#8) and ECDSA (SEC1) keys.
fn load_client_cert(cert_path: &str, key_path: &str) -> ClientCertConfig {
    let chain = load_cert_chain(cert_path);
    let key_pem = std::fs::read_to_string(key_path)
        .unwrap_or_else(|e| die(format!("cannot read key file {key_path}: {e}")));
    if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem(&key_pem) {
        ClientCertConfig::with_ed25519(chain, k)
    } else if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(&key_pem) {
        ClientCertConfig::with_ecdsa(chain, k)
    } else {
        die(format!(
            "{key_path}: client cert key must be Ed25519 (PKCS#8) or ECDSA (SEC1)"
        ));
    }
}

/// Appends NSS SSLKEYLOGFILE lines for a TLS 1.3 connection.
fn dump_keylog_13(conn: &ClientConnection, path: &str) {
    let cr_hex = to_hex(&conn.client_random());
    let mut lines = String::new();
    if let Some(s) = conn.client_handshake_traffic_secret() {
        lines.push_str(&format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
            cr_hex,
            to_hex(&s)
        ));
    }
    if let Some(s) = conn.server_handshake_traffic_secret() {
        lines.push_str(&format!(
            "SERVER_HANDSHAKE_TRAFFIC_SECRET {} {}\n",
            cr_hex,
            to_hex(&s)
        ));
    }
    if let Some(s) = conn.client_application_traffic_secret_0() {
        lines.push_str(&format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
            cr_hex,
            to_hex(&s)
        ));
    }
    if let Some(s) = conn.server_application_traffic_secret_0() {
        lines.push_str(&format!(
            "SERVER_TRAFFIC_SECRET_0 {} {}\n",
            cr_hex,
            to_hex(&s)
        ));
    }
    if let Some(s) = conn.exporter_master_secret() {
        lines.push_str(&format!("EXPORTER_SECRET {} {}\n", cr_hex, to_hex(&s)));
    }
    append_keylog(path, &lines);
}

/// Appends the NSS SSLKEYLOGFILE `CLIENT_RANDOM` line for a TLS 1.2 connection.
fn dump_keylog_12(conn: &ClientConnection12, path: &str) {
    let cr_hex = to_hex(&conn.client_random());
    if let Some(master) = conn.master_secret() {
        let line = format!("CLIENT_RANDOM {} {}\n", cr_hex, to_hex(&master));
        append_keylog(path, &line);
    }
}

fn append_keylog(path: &str, lines: &str) {
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| f.write_all(lines.as_bytes()))
    {
        eprintln!("warning: cannot write keylogfile {path}: {e}");
    }
}

pub(crate) fn run(args: Args) {
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
                "usage: purecrypto s_client -connect host:port [-tls1_2 | -dtls1_2 | -dtls1_3] [-servername name] [-CAfile bundle.pem] [-insecure] [-showcerts] [-alpn h2,http/1.1] [-keylogfile path] [-cert client.pem -key client.key] [-mtu N]",
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
    let keylog = args.value("-keylogfile").map(String::from);
    let mtu: usize = args
        .value("-mtu")
        .unwrap_or("1200")
        .parse()
        .unwrap_or_else(|_| die("-mtu expects a number"));
    let client_cert = match (args.value("-cert"), args.value("-key")) {
        (Some(c), Some(k)) => Some(load_client_cert(c, k)),
        (Some(_), None) | (None, Some(_)) => die("both -cert and -key are required for mTLS"),
        _ => None,
    };

    match version {
        ProtocolVersion::Tls12 | ProtocolVersion::Tls13 => {
            let mut sock = TcpStream::connect((host, port))
                .unwrap_or_else(|e| die(format!("TCP connect to {host}:{port} failed: {e}")));
            let ctx = RunCtx {
                server_name,
                insecure,
                showcerts,
                quiet,
                alpn,
                keylog,
                client_cert,
                ca_file: args.value("-CAfile"),
            };
            if version == ProtocolVersion::Tls12 {
                run_tls12(&mut sock, ctx);
            } else {
                run_tls13(&mut sock, ctx);
            }
        }
        ProtocolVersion::Dtls12 | ProtocolVersion::Dtls13 => {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .unwrap_or_else(|e| die(format!("cannot bind local UDP socket: {e}")));
            socket
                .connect((host, port))
                .unwrap_or_else(|e| die(format!("UDP connect to {host}:{port} failed: {e}")));
            let ctx = DtlsRunCtx {
                server_name,
                insecure,
                showcerts,
                quiet,
                alpn,
                client_cert,
                ca_file: args.value("-CAfile"),
                mtu,
            };
            if version == ProtocolVersion::Dtls12 {
                run_dtls12(socket, ctx);
            } else {
                run_dtls13(socket, ctx);
            }
        }
    }
}

struct RunCtx<'a> {
    server_name: &'a str,
    insecure: bool,
    showcerts: bool,
    quiet: bool,
    alpn: Option<Vec<Vec<u8>>>,
    keylog: Option<String>,
    client_cert: Option<ClientCertConfig>,
    ca_file: Option<&'a str>,
}

struct DtlsRunCtx<'a> {
    server_name: &'a str,
    insecure: bool,
    showcerts: bool,
    quiet: bool,
    alpn: Option<Vec<Vec<u8>>>,
    /// Accepted-but-unused: see commit 11 — the DTLS state machines do
    /// not yet implement client auth. We parse the flag so future work
    /// is a drop-in.
    #[allow(dead_code)]
    client_cert: Option<ClientCertConfig>,
    ca_file: Option<&'a str>,
    mtu: usize,
}

fn run_tls13(sock: &mut TcpStream, ctx: RunCtx<'_>) {
    let RunCtx {
        server_name,
        insecure,
        showcerts,
        quiet,
        alpn,
        keylog,
        client_cert,
        ca_file,
    } = ctx;

    let mut config = if insecure {
        let mut c = ClientConfig::new(RootCertStore::new());
        c.verify_certificates = false;
        c
    } else {
        ClientConfig::new(load_roots(ca_file))
    };
    if let Some(a) = alpn {
        config = config.with_alpn(a);
    }
    if let Some(cc) = client_cert {
        config = config.with_client_cert(cc);
    }

    let mut conn = ClientConnection::new(config, server_name, &mut OsRng);

    // Handshake.
    {
        let mut tls = Stream::new(&mut conn, sock);
        tls.complete_handshake()
            .unwrap_or_else(|e| die(format!("TLS handshake failed: {e:?}")));
    }

    if let Some(path) = keylog.as_deref() {
        dump_keylog_13(&conn, path);
    }

    if !quiet {
        eprintln!(
            "connected: {} / {}{}",
            conn.protocol_version().unwrap_or("?"),
            conn.negotiated_cipher_suite_name().unwrap_or("?"),
            if insecure {
                "  (certificate NOT verified)"
            } else {
                "  (certificate verified)"
            }
        );
        if let Some(p) = conn.alpn_protocol() {
            eprintln!("ALPN: {}", String::from_utf8_lossy(p));
        }
        print_chain(conn.peer_certificates(), showcerts);
    }

    // Data phase.
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut tls = Stream::new(&mut conn, sock);
    drive_data(&mut tls);
}

fn run_tls12(sock: &mut TcpStream, ctx: RunCtx<'_>) {
    let RunCtx {
        server_name,
        insecure,
        showcerts,
        quiet,
        alpn,
        keylog,
        client_cert,
        ca_file,
    } = ctx;

    let roots = if insecure {
        RootCertStore::new()
    } else {
        load_roots(ca_file)
    };
    let mut config = ClientConfig12::new(roots);
    config.verify_certificates = !insecure;
    // The CLI user opted into TLS 1.2 explicitly via `-tls1_2`, so accept the
    // RFC 8446 §4.1.3 downgrade sentinel without complaint — a modern server
    // serving a deliberately-downgraded TLS 1.2 connection will set it.
    config = config.with_accept_downgrade_sentinel(true);
    if let Some(a) = alpn {
        config = config.with_alpn(a);
    }
    if let Some(cc) = client_cert {
        config = config.with_client_cert(cc);
    }

    let mut conn = ClientConnection12::new(config, server_name, &mut OsRng);

    // Handshake.
    {
        let mut tls = Stream::new(&mut conn, sock);
        tls.complete_handshake()
            .unwrap_or_else(|e| die(format!("TLS handshake failed: {e:?}")));
    }

    if let Some(path) = keylog.as_deref() {
        dump_keylog_12(&conn, path);
    }

    if !quiet {
        let suite_name = conn
            .negotiated_cipher_suite()
            .map(tls12_suite_name)
            .unwrap_or("?");
        eprintln!(
            "connected: {} / {}{}",
            conn.protocol_version().unwrap_or("?"),
            suite_name,
            if insecure {
                "  (certificate NOT verified)"
            } else {
                "  (certificate verified)"
            }
        );
        if let Some(p) = conn.alpn_protocol() {
            eprintln!("ALPN: {}", String::from_utf8_lossy(p));
        }
        print_chain(conn.peer_certificates(), showcerts);
    }

    // Data phase.
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut tls = Stream::new(&mut conn, sock);
    drive_data(&mut tls);
}

fn run_dtls12(socket: UdpSocket, ctx: DtlsRunCtx<'_>) {
    let DtlsRunCtx {
        server_name,
        insecure,
        showcerts: _,
        quiet,
        alpn: _,
        client_cert: _,
        ca_file,
        mtu,
    } = ctx;

    if ca_file.is_none() && !insecure {
        die(
            "DTLS client requires either -CAfile <bundle> for chain validation, \
             or -insecure to explicitly skip verification (see openssl s_client)",
        );
    }
    let roots = load_roots_optional(ca_file);
    let mut cfg = DtlsClientConfig12::new(roots, server_name);
    if insecure {
        cfg = cfg.without_certificate_verification();
    }

    let mut conn = DtlsClientConnection12::new(cfg, b"udp-client".to_vec(), &mut OsRng);

    dtls_io::drive_handshake(&mut conn, &socket, mtu, Duration::from_secs(15));

    if !quiet {
        eprintln!("connected: DTLSv1.2");
        if insecure {
            eprintln!("WARNING: certificate NOT verified (-insecure)");
        } else {
            eprintln!("certificate verified");
        }
    }

    dtls_io::drive_client_data(&mut conn, &socket, mtu, Duration::from_secs(30));
}

fn run_dtls13(socket: UdpSocket, ctx: DtlsRunCtx<'_>) {
    let DtlsRunCtx {
        server_name,
        insecure,
        showcerts,
        quiet,
        alpn,
        client_cert: _,
        ca_file,
        mtu,
    } = ctx;

    if ca_file.is_none() && !insecure {
        die(
            "DTLS client requires either -CAfile <bundle> for chain validation, \
             or -insecure to explicitly skip verification (see openssl s_client)",
        );
    }
    let roots = load_roots_optional(ca_file);
    let mut cfg = DtlsClientConfig13::new(roots, server_name);
    if insecure {
        cfg = cfg.without_certificate_verification();
    }
    if let Some(a) = alpn {
        cfg.alpn_protocols = a;
    }

    let mut conn = DtlsClientConnection13::new(cfg, b"udp-client".to_vec(), &mut OsRng);

    dtls_io::drive_handshake(&mut conn, &socket, mtu, Duration::from_secs(15));

    if !quiet {
        eprintln!("connected: DTLSv1.3");
        if insecure {
            eprintln!("WARNING: certificate NOT verified (-insecure)");
        } else {
            eprintln!("certificate verified");
        }
        if let Some(p) = conn.alpn_protocol() {
            eprintln!("ALPN: {}", String::from_utf8_lossy(p));
        }
        print_chain(conn.peer_certificates(), showcerts);
    }

    dtls_io::drive_client_data(&mut conn, &socket, mtu, Duration::from_secs(30));
}

/// Stringifies a TLS 1.2 cipher-suite code for diagnostics.
fn tls12_suite_name(code: u16) -> &'static str {
    match code {
        0xC02B => "ECDHE-ECDSA-AES128-GCM-SHA256",
        0xC02C => "ECDHE-ECDSA-AES256-GCM-SHA384",
        0xC02F => "ECDHE-RSA-AES128-GCM-SHA256",
        0xC030 => "ECDHE-RSA-AES256-GCM-SHA384",
        0xCCA8 => "ECDHE-RSA-CHACHA20-POLY1305",
        0xCCA9 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        _ => "?",
    }
}

/// Drives the data phase: stdin → TLS, TLS → stdout, until EOF / timeout.
fn drive_data<C, T>(tls: &mut Stream<'_, C, T>)
where
    C: purecrypto::tls::Connection,
    T: Read + Write,
{
    if !std::io::stdin().is_terminal() {
        let mut input = Vec::new();
        if std::io::stdin().read_to_end(&mut input).is_ok() && !input.is_empty() {
            let _ = tls.write_all(&input);
            let _ = tls.flush();
        }
    }

    let mut stdout = std::io::stdout();
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if stdout.write_all(&buf[..n]).is_err() {
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
