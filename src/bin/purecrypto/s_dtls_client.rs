//! `purecrypto s_dtls_client` — open a DTLS 1.2 connection over UDP and
//! report the result, like a minimal `openssl s_client -dtls1_2`.
//!
//! Scope matches the underlying [`DtlsClientConnection12`]: the single
//! cipher suite `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (RFC 5289),
//! X25519 ECDHE (RFC 8446 §4.2.7 group code), and ECDSA-P256 server
//! certificates. mTLS / client auth is parsed but not yet exercised at
//! the connection level — the underlying state machine does not accept
//! a CertificateRequest. We still wire the flags so a future commit
//! can drop in the implementation without changing the CLI surface.

use std::io::{Read, Write};
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use crate::util::{Args, die};
use purecrypto::dtls::{DtlsClientConfig12, DtlsClientConnection12};
use purecrypto::ec::{BoxedEcdsaPrivateKey, Ed25519PrivateKey};
use purecrypto::rng::OsRng;
use purecrypto::tls::{ClientCertConfig, RootCertStore};
use purecrypto::x509::Certificate;

/// Loads a PEM CA bundle into a [`RootCertStore`]. When `path` is `None`,
/// returns an empty store (suitable for `-Verify`-off operation).
fn load_roots(ca_file: Option<&str>) -> RootCertStore {
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

/// Loads one or more PEM CERTIFICATE blocks from `path` as a DER chain.
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

/// Loads a client cert configuration from `-cert` + `-key` paths.
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

pub(crate) fn run(args: Args) {
    let connect = args.value("-connect").unwrap_or_else(|| {
        die(
            "usage: purecrypto s_dtls_client -connect host:port [-servername name] \
             [-CAfile bundle.pem] [-Verify] [-cert client.pem -key client.key] [-mtu N] [-quiet]",
        )
    });
    let (host, port) = match connect.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .unwrap_or_else(|_| die(format!("invalid port: {p}"))),
        ),
        None => die("-connect needs host:port"),
    };
    let server_name = args.value("-servername").unwrap_or(host);
    let verify = args.flag("-Verify") || args.flag("--Verify");
    let quiet = args.flag("-quiet") || args.flag("--quiet");
    let mtu: usize = args
        .value("-mtu")
        .unwrap_or("1200")
        .parse()
        .unwrap_or_else(|_| die("-mtu expects a number"));
    // `-cert` / `-key` are accepted but not exercised; the underlying DTLS
    // 1.2 client state machine does not yet implement client auth. We
    // validate that both are present if either is, so the CLI surface
    // matches the eventual full implementation.
    let _client_cert = match (args.value("-cert"), args.value("-key")) {
        (Some(c), Some(k)) => Some(load_client_cert(c, k)),
        (Some(_), None) | (None, Some(_)) => die("both -cert and -key are required for mTLS"),
        _ => None,
    };
    let ca_file = args.value("-CAfile");

    // Bind a local UDP socket and "connect" it so we can use send/recv
    // without specifying the peer each time. `connect` here just sets the
    // default peer for I/O; the wire protocol is unchanged.
    let socket = UdpSocket::bind("0.0.0.0:0")
        .unwrap_or_else(|e| die(format!("cannot bind local UDP socket: {e}")));
    socket
        .connect((host, port))
        .unwrap_or_else(|e| die(format!("UDP connect to {host}:{port} failed: {e}")));

    // Build the DTLS 1.2 client config. `-Verify` toggles certificate
    // chain validation; without it we trust whatever the peer presents
    // (useful for self-signed / pinned-key scenarios — matches the
    // `s_client -insecure` behaviour).
    let roots = load_roots(ca_file);
    let mut cfg = DtlsClientConfig12::new(roots, server_name);
    if !verify {
        cfg = cfg.without_certificate_verification();
    }

    let mut conn = DtlsClientConnection12::new(cfg, b"udp-client".to_vec(), &mut OsRng);

    // Drive the handshake. We block on recv with a short timeout and
    // re-arm on retransmit deadlines (sans-I/O pump).
    let start = Instant::now();
    let handshake_deadline = start + Duration::from_secs(15);
    let mut buf = vec![0u8; mtu.max(1500) + 256];

    while !conn.is_handshake_complete() {
        if Instant::now() > handshake_deadline {
            die("DTLS handshake timed out");
        }

        // Pump outbound.
        for dg in conn.pop_outbound_datagrams() {
            socket
                .send(&dg)
                .unwrap_or_else(|e| die(format!("UDP send failed: {e}")));
        }

        // Choose a short read timeout — small enough to react to
        // retransmit timers, large enough not to spin.
        let to = match conn.next_timeout() {
            Some(t) => {
                let now = start.elapsed();
                if t > now {
                    (t - now).min(Duration::from_millis(200))
                } else {
                    Duration::from_millis(1)
                }
            }
            None => Duration::from_millis(200),
        };
        socket.set_read_timeout(Some(to)).ok();

        match socket.recv(&mut buf) {
            Ok(n) => {
                conn.feed_datagram(&buf[..n])
                    .unwrap_or_else(|e| die(format!("DTLS error: {e:?}")));
            }
            Err(e) if is_timeout(&e) => { /* fall through to timer pump */ }
            Err(e) => die(format!("UDP recv failed: {e}")),
        }

        // Pump retransmit timer if armed.
        if let Some(deadline) = conn.next_timeout()
            && start.elapsed() >= deadline
        {
            conn.on_timeout(start.elapsed());
        }
    }

    if !quiet {
        eprintln!("DTLS 1.2 handshake complete");
    }

    // Data phase. A background thread reads stdin line-by-line into a
    // channel; the main loop pumps both directions sans-I/O. When stdin
    // closes the thread drops the sender; the main loop detects that
    // and starts the post-stdin idle timer. We exit either:
    //   • after `app_deadline` (hard cap), or
    //   • once stdin is closed AND we've gone `post_stdin_idle` without
    //     receiving any plaintext from the peer.
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut line = Vec::new();
        let mut chunk = [0u8; 1];
        loop {
            match stdin.read(&mut chunk) {
                Ok(0) => break,
                Ok(_) => {
                    line.push(chunk[0]);
                    if chunk[0] == b'\n' && tx.send(core::mem::take(&mut line)).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
        if !line.is_empty() {
            let _ = tx.send(line);
        }
        // Drop tx implicitly so the main loop sees disconnect.
    });

    let mut stdout = std::io::stdout();
    let app_deadline = Instant::now() + Duration::from_secs(30);
    let post_stdin_idle = Duration::from_secs(2);
    let mut stdin_done = false;
    let mut last_inbound = Instant::now();

    loop {
        if Instant::now() > app_deadline {
            break;
        }
        // Outbound from stdin.
        loop {
            match rx.try_recv() {
                Ok(line) => {
                    last_inbound = Instant::now();
                    conn.send(&line)
                        .unwrap_or_else(|e| die(format!("DTLS send failed: {e:?}")));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    stdin_done = true;
                    break;
                }
            }
        }
        // Drain outbound datagrams.
        for dg in conn.pop_outbound_datagrams() {
            socket
                .send(&dg)
                .unwrap_or_else(|e| die(format!("UDP send failed: {e}")));
        }
        // Inbound.
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();
        match socket.recv(&mut buf) {
            Ok(n) => {
                last_inbound = Instant::now();
                conn.feed_datagram(&buf[..n])
                    .unwrap_or_else(|e| die(format!("DTLS error: {e:?}")));
                let plain = conn.take_received();
                if !plain.is_empty() {
                    let _ = stdout.write_all(&plain);
                    let _ = stdout.flush();
                }
            }
            Err(e) if is_timeout(&e) => { /* loop */ }
            Err(e) => die(format!("UDP recv failed: {e}")),
        }
        // Exit when stdin is closed and we've drained the network.
        if stdin_done && last_inbound.elapsed() > post_stdin_idle {
            break;
        }
    }
}

/// Whether `e` is a socket-read timeout (which the platform reports as
/// either WouldBlock or TimedOut depending on the OS / mode).
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}
