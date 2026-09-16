//! An HTTPS GET over a real TCP connection, using the `purecrypto` TLS 1.3
//! client. By default the server certificate is verified against the root
//! bundle embedded in the crate (the `embedded-roots` feature, on by
//! default); pass `--insecure` to skip certificate verification.
//!
//! Run with: `cargo run --example tls_get [-- --insecure]`

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
        // Portable: the crate ships its own root bundle, so this works the
        // same on Linux, macOS and Windows (a hard-coded
        // `/etc/ssl/certs/ca-certificates.crt` path only exists on some
        // Linux distributions).
        RootCertStore::with_embedded_roots()
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
            Ok(0) => {
                // TCP EOF is only a clean end of the response if the
                // server's close_notify was processed first; otherwise the
                // stream was truncated (RFC 8446 §6.1) and the bytes below
                // must not be trusted as complete.
                if !conn.received_close_notify() {
                    eprintln!(
                        "WARNING: connection closed without close_notify (possible truncation)"
                    );
                    std::process::exit(1);
                }
                break;
            }
            Ok(n) => {
                if let Err(e) = conn.feed(&read_buf[..n]) {
                    eprintln!("TLS error after handshake: {e:?}");
                    std::process::exit(1);
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
