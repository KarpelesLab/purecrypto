//! A complete TLS 1.3 handshake between a `purecrypto` client and server, run
//! entirely in process (no sockets), then an application-data exchange.
//!
//! Run with: `cargo run --example tls_loopback`

use purecrypto::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
use purecrypto::tls::{Config, Connection, RootCertStore, SigningKey};
use purecrypto::x509::{Certificate, DistinguishedName, Time, Validity};

// A fixed RSA-2048 key, so the example needs no (slow) key generation.
const SERVER_KEY_PEM: &str = include_str!("../testdata/rsa2048_test_a.pem");

fn main() {
    // --- Server setup: a self-signed certificate for "example.test". ---
    let signing_key = RsaPrivateKey::<32>::from_pkcs1_pem(SERVER_KEY_PEM).unwrap();
    let name = DistinguishedName::common_name("example.test");
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let cert = Certificate::self_signed(&signing_key, &name, &validity, 1, false).unwrap();
    let cert_der = cert.to_der().to_vec();

    let server_key = BoxedRsaPrivateKey::from_pkcs1_pem(SERVER_KEY_PEM).unwrap();
    let server_cfg = Config::builder()
        .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
        .tls_only()
        .identity(vec![cert_der.clone()], SigningKey::Rsa(server_key))
        .build();
    let mut server = Connection::server(&server_cfg).expect("server config");

    // --- Client setup: trust the server's certificate. ---
    let mut roots = RootCertStore::new();
    roots.add_der(cert_der).unwrap();
    let client_cfg = Config::builder()
        .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
        .tls_only()
        .roots(roots)
        .server_name("example.test")
        .build();
    let mut client = Connection::client(&client_cfg).expect("client config");

    // --- Drive the handshake by shuttling records between the two ends. ---
    for _ in 0..16 {
        let to_server = client.pop().unwrap_or_default();
        if !to_server.is_empty() {
            server.feed(&to_server).unwrap();
        }
        let to_client = server.pop().unwrap_or_default();
        if !to_client.is_empty() {
            client.feed(&to_client).unwrap();
        }
        if to_server.is_empty() && to_client.is_empty() {
            break;
        }
    }
    assert!(client.is_handshake_complete() && server.is_handshake_complete());
    println!("handshake complete");

    // --- Application data: client -> server -> client. ---
    client.send(b"GET / HTTP/1.0").unwrap();
    let req = client.pop().unwrap_or_default();
    server.feed(&req).unwrap();
    println!(
        "server received: {:?}",
        String::from_utf8_lossy(&server.recv().unwrap_or_default())
    );

    server.send(b"HTTP/1.0 200 OK").unwrap();
    let resp = server.pop().unwrap_or_default();
    client.feed(&resp).unwrap();
    println!(
        "client received: {:?}",
        String::from_utf8_lossy(&client.recv().unwrap_or_default())
    );
}
