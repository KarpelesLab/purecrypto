//! `purecrypto s_server` — minimal TLS 1.2 or TLS 1.3 echo / `-www` server,
//! like a pared-down `openssl s_server`. Single-shot: accepts one connection,
//! completes the handshake, exchanges data, closes.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use crate::util::{Args, die};
use purecrypto::ec::{BoxedEcdsaPrivateKey, Ed25519PrivateKey};
use purecrypto::rng::OsRng;
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::tls::{
    Connection, RootCertStore, ServerConfig, ServerConfig12, ServerConnection, ServerConnection12,
    Stream,
};
use purecrypto::x509::Certificate;

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

/// Holds a private key parsed from PEM, regardless of algorithm.
enum AnyKey {
    Rsa(BoxedRsaPrivateKey),
    Ecdsa(BoxedEcdsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
}

fn load_key(key_path: &str) -> AnyKey {
    let key_pem = std::fs::read_to_string(key_path)
        .unwrap_or_else(|e| die(format!("cannot read key file {key_path}: {e}")));
    if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(&key_pem) {
        AnyKey::Rsa(k)
    } else if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(&key_pem) {
        AnyKey::Ecdsa(k)
    } else if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem(&key_pem) {
        AnyKey::Ed25519(k)
    } else {
        die(format!(
            "{key_path}: server key must be RSA (PKCS#1), ECDSA (SEC1), or Ed25519 (PKCS#8)"
        ));
    }
}

/// Builds a TLS 1.3 [`ServerConfig`] from a cert chain and key.
fn build_server_config(cert_path: &str, key_path: &str) -> ServerConfig {
    let chain = load_cert_chain(cert_path);
    match load_key(key_path) {
        AnyKey::Rsa(k) => ServerConfig::with_rsa(chain, k),
        AnyKey::Ecdsa(k) => ServerConfig::with_ecdsa(chain, k),
        AnyKey::Ed25519(k) => ServerConfig::with_ed25519(chain, k),
    }
}

/// Builds a TLS 1.2 [`ServerConfig12`] from a cert chain and key. Ed25519
/// is not selectable in our TLS 1.2 server (no ECDHE-Ed25519 suite codes
/// in our suite table); rejected at config-build time.
fn build_server_config_12(cert_path: &str, key_path: &str) -> ServerConfig12 {
    let chain = load_cert_chain(cert_path);
    match load_key(key_path) {
        AnyKey::Rsa(k) => ServerConfig12::with_rsa(chain, k),
        AnyKey::Ecdsa(k) => ServerConfig12::with_ecdsa(chain, k),
        AnyKey::Ed25519(_) => die(format!(
            "{key_path}: -tls1_2 server requires an RSA or ECDSA key (Ed25519 is not a TLS 1.2 cipher-suite signer)"
        )),
    }
}

pub(crate) fn run(args: Args) {
    let cert_path = args
        .value("-cert")
        .unwrap_or_else(|| die("usage: purecrypto s_server -cert cert.pem -key key.pem -accept PORT [-tls1_2] [-Verify ca.pem] [-alpn h2,http/1.1] [-www]"));
    let key_path = args
        .value("-key")
        .unwrap_or_else(|| die("-key is required"));
    let port: u16 = args
        .value("-accept")
        .unwrap_or("4433")
        .parse()
        .unwrap_or_else(|_| die("-accept expects a port number"));
    let verify_ca = args.value("-Verify");
    let alpn = args.value("-alpn").map(parse_alpn);
    let www = args.flag("-www") || args.flag("--www");
    let quiet = args.flag("-quiet") || args.flag("--quiet");
    let tls12 = args.flag("-tls1_2") || args.flag("--tls1_2");

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

    if tls12 {
        let mut config = build_server_config_12(cert_path, key_path);
        if let Some(a) = alpn {
            config = config.with_alpn(a);
        }
        if let Some(p) = verify_ca {
            let roots = load_roots_file(p);
            config = config.with_client_auth(roots, true);
        }
        let mut conn = ServerConnection12::new(config, OsRng);
        serve(&mut conn, &mut sock, www, quiet);
    } else {
        let mut config = build_server_config(cert_path, key_path);
        if let Some(a) = alpn {
            config = config.with_alpn(a);
        }
        if let Some(p) = verify_ca {
            let roots = load_roots_file(p);
            config = config.with_client_auth(roots, true);
        }
        let mut conn = ServerConnection::new(config, OsRng);
        serve(&mut conn, &mut sock, www, quiet);
    }
}

trait ServerInfo {
    fn alpn_protocol(&self) -> Option<&[u8]>;
    fn peer_certificates(&self) -> &[Vec<u8>];
}

impl<R: purecrypto::rng::RngCore> ServerInfo for ServerConnection<R> {
    fn alpn_protocol(&self) -> Option<&[u8]> {
        ServerConnection::alpn_protocol(self)
    }
    fn peer_certificates(&self) -> &[Vec<u8>] {
        ServerConnection::peer_certificates(self)
    }
}

impl<R: purecrypto::rng::RngCore> ServerInfo for ServerConnection12<R> {
    fn alpn_protocol(&self) -> Option<&[u8]> {
        ServerConnection12::alpn_protocol(self)
    }
    fn peer_certificates(&self) -> &[Vec<u8>] {
        ServerConnection12::peer_certificates(self)
    }
}

fn serve<C: Connection + ServerInfo>(conn: &mut C, sock: &mut TcpStream, www: bool, quiet: bool) {
    {
        let mut tls = Stream::new(conn, sock);
        tls.complete_handshake()
            .unwrap_or_else(|e| die(format!("TLS handshake failed: {e:?}")));
    }

    if !quiet {
        eprintln!("handshake complete");
        if let Some(p) = conn.alpn_protocol() {
            eprintln!("ALPN: {}", String::from_utf8_lossy(p));
        }
        if !conn.peer_certificates().is_empty() {
            eprintln!(
                "client presented {} certificate(s)",
                conn.peer_certificates().len()
            );
        }
    }

    // Data phase.
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    let mut tls = Stream::new(conn, sock);
    if www {
        // Read up to the first blank line of the request, then send a fixed
        // HTTP response.
        let mut buf = [0u8; 4096];
        let _ = tls.read(&mut buf);
        let body = b"hello from purecrypto s_server\n";
        let resp = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = tls.write_all(resp.as_bytes());
        let _ = tls.write_all(body);
        let _ = tls.flush();
    } else {
        // Echo: copy from peer to peer (and stdout for visibility) until EOF.
        let mut buf = [0u8; 4096];
        loop {
            match tls.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let _ = tls.write_all(&buf[..n]);
                    let _ = tls.flush();
                }
                Err(_) => break,
            }
        }
    }
}
