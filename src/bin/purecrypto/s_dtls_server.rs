//! `purecrypto s_dtls_server` — minimal DTLS 1.2 echo server over UDP,
//! like a pared-down `openssl s_server -dtls1_2`. Single-shot: accepts
//! traffic from the first peer that sends a ClientHello, completes the
//! handshake, echoes received plaintext back, exits on inactivity.
//!
//! Cipher-suite scope matches [`DtlsServerConnection12`]: only
//! `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (RFC 5289) with X25519
//! ECDHE and an ECDSA-P256 server certificate.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::util::{Args, die};
use purecrypto::dtls::{DtlsServerConfig12, DtlsServerConnection12};
use purecrypto::ec::BoxedEcdsaPrivateKey;
use purecrypto::rng::OsRng;
use purecrypto::x509::Certificate;

/// Loads one or more PEM CERTIFICATE blocks as a DER chain (leaf first).
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

/// Loads an ECDSA P-256 key from a SEC1 PEM file. (The DTLS 1.2 server
/// only supports ECDSA in this subset — RSA / Ed25519 keys would need
/// suite codes we don't yet enable.)
fn load_ecdsa_key(path: &str) -> BoxedEcdsaPrivateKey {
    let key_pem = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(format!("cannot read key file {path}: {e}")));
    BoxedEcdsaPrivateKey::from_sec1_pem(&key_pem)
        .unwrap_or_else(|_| die(format!("{path}: DTLS 1.2 server key must be ECDSA (SEC1)")))
}

pub(crate) fn run(args: Args) {
    let cert_path = args.value("-cert").unwrap_or_else(|| {
        die(
            "usage: purecrypto s_dtls_server -accept host:port -cert cert.pem -key key.pem \
             [-Verify ca.pem] [-mtu N] [-no_cookie] [-quiet]",
        )
    });
    let key_path = args
        .value("-key")
        .unwrap_or_else(|| die("-key is required"));
    let accept = args.value("-accept").unwrap_or("127.0.0.1:4434");
    let no_cookie = args.flag("-no_cookie") || args.flag("--no_cookie");
    let quiet = args.flag("-quiet") || args.flag("--quiet");
    let mtu: usize = args
        .value("-mtu")
        .unwrap_or("1200")
        .parse()
        .unwrap_or_else(|_| die("-mtu expects a number"));
    // `-Verify` is accepted for symmetry with the TCP `s_server` but the
    // underlying DTLS 1.2 server does not yet implement client-cert
    // verification. Reject it loudly rather than silently no-op.
    if args.value("-Verify").is_some() {
        die("DTLS 1.2 server does not yet implement client authentication (-Verify unsupported)");
    }

    let chain = load_cert_chain(cert_path);
    let key = load_ecdsa_key(key_path);

    let mut config = DtlsServerConfig12::with_ecdsa(chain, key);
    if no_cookie {
        config = config.require_cookie_exchange(false);
    } else {
        let mut secret = [0u8; 32];
        purecrypto::rng::RngCore::fill_bytes(&mut OsRng, &mut secret);
        config = config
            .with_cookie_secret(secret)
            .require_cookie_exchange(true);
    }
    let config = Arc::new(config);

    let socket =
        UdpSocket::bind(accept).unwrap_or_else(|e| die(format!("cannot bind UDP {accept}: {e}")));
    let bound = socket.local_addr().ok();
    if !quiet {
        match bound {
            Some(addr) => eprintln!("listening on {addr} (DTLS 1.2 / UDP)"),
            None => eprintln!("listening on {accept} (DTLS 1.2 / UDP)"),
        }
    }

    let mut buf = vec![0u8; mtu.max(1500) + 256];

    // Wait for the first datagram. The peer address it arrives from is
    // the peer we'll commit to for this single-shot server.
    socket.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let (n, peer) = socket
        .recv_from(&mut buf)
        .unwrap_or_else(|e| die(format!("UDP recv (initial) failed: {e}")));
    if !quiet {
        eprintln!("accepted DTLS handshake start from {peer}");
    }

    // "Connect" the socket to this peer so we can use send/recv after.
    socket
        .connect(peer)
        .unwrap_or_else(|e| die(format!("UDP connect to peer {peer}: {e}")));

    let peer_bytes = peer_addr_bytes(&peer);
    let mut conn = DtlsServerConnection12::new(config, peer_bytes, OsRng);
    conn.feed_datagram(&buf[..n])
        .unwrap_or_else(|e| die(format!("DTLS error on initial datagram: {e:?}")));

    let start = Instant::now();
    let handshake_deadline = start + Duration::from_secs(15);

    while !conn.is_handshake_complete() {
        if Instant::now() > handshake_deadline {
            die("DTLS handshake timed out");
        }

        for dg in conn.pop_outbound_datagrams() {
            socket
                .send(&dg)
                .unwrap_or_else(|e| die(format!("UDP send failed: {e}")));
        }

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
            Err(e) if is_timeout(&e) => { /* fall through */ }
            Err(e) => die(format!("UDP recv failed: {e}")),
        }

        // Final pump for any datagrams produced by the just-fed record.
        for dg in conn.pop_outbound_datagrams() {
            socket
                .send(&dg)
                .unwrap_or_else(|e| die(format!("UDP send failed: {e}")));
        }

        if let Some(deadline) = conn.next_timeout()
            && start.elapsed() >= deadline
        {
            conn.on_timeout(start.elapsed());
        }
    }

    if !quiet {
        eprintln!("DTLS 1.2 handshake complete");
    }

    // Echo phase. Anything decrypted from the peer gets fed back via
    // `conn.send`. Exit on read inactivity (5 s).
    let mut last_activity = Instant::now();
    let idle_limit = Duration::from_secs(5);
    loop {
        if last_activity.elapsed() > idle_limit {
            break;
        }
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .ok();
        match socket.recv(&mut buf) {
            Ok(n) => {
                last_activity = Instant::now();
                conn.feed_datagram(&buf[..n])
                    .unwrap_or_else(|e| die(format!("DTLS error: {e:?}")));
                let plain = conn.take_received();
                if !plain.is_empty() {
                    conn.send(&plain)
                        .unwrap_or_else(|e| die(format!("DTLS send failed: {e:?}")));
                }
            }
            Err(e) if is_timeout(&e) => { /* idle tick */ }
            Err(e) => die(format!("UDP recv failed: {e}")),
        }
        for dg in conn.pop_outbound_datagrams() {
            socket
                .send(&dg)
                .unwrap_or_else(|e| die(format!("UDP send failed: {e}")));
        }
    }
}

/// Produces opaque address bytes from a [`SocketAddr`] for the cookie
/// generator. Format is "IP|port"; the generator only needs stability
/// per peer for the duration of a handshake.
fn peer_addr_bytes(addr: &SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(addr.ip().to_string().as_bytes());
    bytes.push(b'|');
    bytes.extend_from_slice(addr.port().to_string().as_bytes());
    bytes
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}
