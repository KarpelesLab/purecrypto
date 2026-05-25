//! `purecrypto s_client` — open a TLS 1.3 connection and report the result,
//! like a minimal `openssl s_client`.

use std::io::{IsTerminal, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::pki::format_dn;
use crate::util::{Args, die};
use purecrypto::rng::OsRng;
use purecrypto::tls::{ClientConfig, ClientConnection, RootCertStore, Stream};
use purecrypto::x509::Certificate;

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

fn print_chain(conn: &ClientConnection, showcerts: bool) {
    let chain = conn.peer_certificates();
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

pub(crate) fn run(args: Args) {
    let connect = args
        .value("-connect")
        .or_else(|| args.positionals(&["-connect", "-servername", "-CAfile"]).first().copied())
        .unwrap_or_else(|| {
            die("usage: purecrypto s_client -connect host:port [-servername name] [-CAfile bundle.pem] [-insecure] [-showcerts]")
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

    let config = if insecure {
        let mut c = ClientConfig::new(RootCertStore::new());
        c.verify_certificates = false;
        c
    } else {
        ClientConfig::new(load_roots(args.value("-CAfile")))
    };

    let mut sock = TcpStream::connect((host, port))
        .unwrap_or_else(|e| die(format!("TCP connect to {host}:{port} failed: {e}")));

    let mut conn = ClientConnection::new(config, server_name, &mut OsRng);

    // Handshake.
    {
        let mut tls = Stream::new(&mut conn, &mut sock);
        tls.complete_handshake()
            .unwrap_or_else(|e| die(format!("TLS handshake failed: {e:?}")));
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
        print_chain(&conn, showcerts);
    }

    // Data phase: forward stdin (when piped) to the server, server to stdout.
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut tls = Stream::new(&mut conn, &mut sock);

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
