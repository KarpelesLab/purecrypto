//! A complete TLS 1.3 handshake between a `purecrypto` client and server, run
//! entirely in process (no sockets), then an application-data exchange.
//!
//! Run with: `cargo run --example tls_loopback`

use purecrypto::rng::OsRng;
use purecrypto::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
use purecrypto::tls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
};
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
    let server_config = ServerConfig::with_rsa(vec![cert_der.clone()], server_key);
    let mut server = ServerConnection::new(server_config, OsRng);

    // --- Client setup: trust the server's certificate. ---
    let mut roots = RootCertStore::new();
    roots.add_der(cert_der).unwrap();
    let mut client = ClientConnection::new(ClientConfig::new(roots), "example.test", &mut OsRng);

    // --- Drive the handshake by shuttling records between the two ends. ---
    for _ in 0..16 {
        let to_server = client.write_tls();
        if !to_server.is_empty() {
            server.read_tls(&to_server);
            server.process_new_packets().unwrap();
        }
        let to_client = server.write_tls();
        if !to_client.is_empty() {
            client.read_tls(&to_client);
            client.process_new_packets().unwrap();
        }
        if to_server.is_empty() && to_client.is_empty() {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    println!("handshake complete");

    // --- Application data: client -> server -> client. ---
    client.send_application_data(b"GET / HTTP/1.0").unwrap();
    let req = client.write_tls();
    server.read_tls(&req);
    server.process_new_packets().unwrap();
    println!(
        "server received: {:?}",
        String::from_utf8_lossy(&server.take_received_plaintext())
    );

    server.send_application_data(b"HTTP/1.0 200 OK").unwrap();
    let resp = server.write_tls();
    client.read_tls(&resp);
    client.process_new_packets().unwrap();
    println!(
        "client received: {:?}",
        String::from_utf8_lossy(&client.take_received_plaintext())
    );
}
