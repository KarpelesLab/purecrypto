//! An HTTPS GET over a real TCP connection, using the `purecrypto` TLS 1.3
//! client. By default the server certificate is verified against the system
//! trust store; pass `--insecure` to skip certificate verification.
//!
//! Run with: `cargo run --example tls_get [-- --insecure]`
//!
//! Note: chain verification requires every certificate's key (and its issuer's
//! signing key) to be RSA or ECDSA P-256 — the algorithms this library
//! implements. Hosts anchored through a P-384 CA (example.org via Cloudflare,
//! at the time of writing) cannot be verified yet and need `--insecure`.

use purecrypto::tls::{Config, Connection, HandshakeStatus, RootCertStore};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const HOST: &str = "example.org";

fn main() {
    let insecure = std::env::args().any(|a| a == "--insecure");

    let roots = if insecure {
        RootCertStore::new()
    } else {
        load_system_roots()
    };
    let cfg = Config::builder()
        .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
        .tls_only()
        .roots(roots)
        .server_name(HOST)
        .verify_certificates(!insecure)
        .build();
    let mut conn = Connection::client(&cfg).expect("client config");

    let mut sock = TcpStream::connect((HOST, 443)).expect("TCP connect");
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // Drive the handshake to completion.
    let mut read_buf = [0u8; 8192];
    loop {
        let out = conn.pop().unwrap_or_default();
        if !out.is_empty() {
            sock.write_all(&out).unwrap();
        }
        match conn.handshake().unwrap() {
            HandshakeStatus::Complete => break,
            HandshakeStatus::WantWrite => continue,
            HandshakeStatus::WantRead => {
                let n = sock.read(&mut read_buf).expect("read");
                assert!(n > 0, "peer closed during handshake");
                conn.feed(&read_buf[..n]).expect("feed");
            }
        }
    }
    eprintln!(
        "TLS 1.3 handshake with {HOST} complete (certificate {}verified)",
        if insecure { "NOT " } else { "" }
    );

    let request = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";
    conn.send(request.as_bytes()).unwrap();
    let out = conn.pop().unwrap_or_default();
    sock.write_all(&out).unwrap();
    sock.flush().unwrap();

    let mut response = Vec::new();
    loop {
        match sock.read(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => {
                if conn.feed(&read_buf[..n]).is_err() {
                    break;
                }
                let plain = conn.recv().unwrap_or_default();
                response.extend_from_slice(&plain);
                if response.len() > 16 * 1024 {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => {
                eprintln!("read error: {e}");
                break;
            }
        }
    }

    let text = String::from_utf8_lossy(&response);
    println!("--- {} bytes received ---", response.len());
    for line in text.lines().take(15) {
        println!("{line}");
    }
}

/// Loads the system CA bundle into a trust store, skipping any certificate
/// whose key type this library does not parse (e.g. Ed25519/P-384 roots).
fn load_system_roots() -> RootCertStore {
    const BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";
    let data = std::fs::read_to_string(BUNDLE).expect("read system CA bundle");

    let mut store = RootCertStore::new();
    let (mut loaded, mut skipped) = (0u32, 0u32);
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
            match store.add_pem(&block) {
                Ok(()) => loaded += 1,
                Err(_) => skipped += 1,
            }
        }
    }
    eprintln!("loaded {loaded} trusted roots ({skipped} skipped)");
    store
}
