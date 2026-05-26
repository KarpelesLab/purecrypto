//! `purecrypto s_client` — open a TLS 1.3 connection and report the result,
//! like a minimal `openssl s_client`.

use std::io::{IsTerminal, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::pki::format_dn;
use crate::util::{Args, die, to_hex};
use purecrypto::ec::{BoxedEcdsaPrivateKey, Ed25519PrivateKey};
use purecrypto::rng::OsRng;
use purecrypto::tls::{ClientCertConfig, ClientConfig, ClientConnection, RootCertStore, Stream};
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

/// Appends NSS SSLKEYLOGFILE lines for the negotiated secrets.
fn dump_keylog(conn: &ClientConnection, path: &str) {
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
    let connect = args
        .value("-connect")
        .or_else(|| args.positionals(&["-connect", "-servername", "-CAfile", "-alpn", "-keylogfile", "-cert", "-key"]).first().copied())
        .unwrap_or_else(|| {
            die("usage: purecrypto s_client -connect host:port [-servername name] [-CAfile bundle.pem] [-insecure] [-showcerts] [-alpn h2,http/1.1] [-keylogfile path] [-cert client.pem -key client.key]")
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
    let client_cert = match (args.value("-cert"), args.value("-key")) {
        (Some(c), Some(k)) => Some(load_client_cert(c, k)),
        (Some(_), None) | (None, Some(_)) => die("both -cert and -key are required for mTLS"),
        _ => None,
    };

    let mut config = if insecure {
        let mut c = ClientConfig::new(RootCertStore::new());
        c.verify_certificates = false;
        c
    } else {
        ClientConfig::new(load_roots(args.value("-CAfile")))
    };
    if let Some(a) = alpn {
        config = config.with_alpn(a);
    }
    if let Some(cc) = client_cert {
        config = config.with_client_cert(cc);
    }

    let mut sock = TcpStream::connect((host, port))
        .unwrap_or_else(|e| die(format!("TCP connect to {host}:{port} failed: {e}")));

    let mut conn = ClientConnection::new(config, server_name, &mut OsRng);

    // Handshake.
    {
        let mut tls = Stream::new(&mut conn, &mut sock);
        tls.complete_handshake()
            .unwrap_or_else(|e| die(format!("TLS handshake failed: {e:?}")));
    }

    if let Some(path) = keylog.as_deref() {
        dump_keylog(&conn, path);
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
