//! End-to-end Encrypted Client Hello (draft-ietf-tls-esni-22) loopback,
//! all in-process: the client seals its `ClientHello` against a
//! published `ECHConfigList`; the server HPKE-decaps it, presents a
//! certificate for the *inner* SNI, and the handshake completes
//! privately. The same code, with a deliberately stale `ECHConfigList`
//! on the client, demonstrates the rejection path with
//! `retry_configs` shipped back through `Error::EchRejected`.
//!
//! Run with: `cargo run --example tls_ech_loopback --features ech`
//!
//! What the example proves end-to-end:
//!  - The CH the network observes carries `public_name` as SNI; the
//!    server's `peer_server_name()` reports the *inner* SNI.
//!  - Application data round-trips over the inner-CH transcript.
//!  - On rejection (mismatched `config_id`) the client surfaces the
//!    server's published `retry_configs` so the application can
//!    refresh and retry.

use purecrypto::ec::Ed25519PrivateKey;
use purecrypto::hash::Sha256;
use purecrypto::hpke::{HpkeAead, HpkeKdf, HpkeKem};
use purecrypto::rng::{HmacDrbg, OsRng};
use purecrypto::tls::ech::keys::{EchKeyPair, EchKeyRing};
use purecrypto::tls::ech::{EchClient, EchConfigList, EchServer, HpkeSymCipherSuite};
use purecrypto::tls::{Config, Connection, Error, RootCertStore, SigningKey};
use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

/// Stable inner / outer names so the printed transcript is easy to
/// follow. The cert covers both — on accept the client validates
/// against the inner name; on reject it validates against the public
/// name.
const PUBLIC_NAME: &str = "public.example";
const INNER_SNI: &str = "secret.example";

fn make_server_cert() -> (Vec<u8>, Ed25519PrivateKey) {
    let mut keygen_rng = HmacDrbg::<Sha256>::new(b"ech-example-srvkey", b"nonce", &[]);
    let key = Ed25519PrivateKey::generate(&mut keygen_rng);
    let name = DistinguishedName::common_name(PUBLIC_NAME);
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let cert = Certificate::self_signed_general(
        &CertSigner::Ed25519(&key),
        &name,
        &validity,
        1,
        false,
        &[PUBLIC_NAME, INNER_SNI],
    )
    .expect("issue self-signed cert");
    (cert.to_der().to_vec(), key)
}

fn fresh_ech_keypair(config_id: u8, seed: &[u8]) -> EchKeyPair {
    let mut rng = HmacDrbg::<Sha256>::new(seed, b"ech-example", &[]);
    let suites = vec![HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    }];
    EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        config_id,
        PUBLIC_NAME.as_bytes(),
        64,
        suites,
    )
    .expect("ech keygen")
}

fn drive_until_done_or_err(client: &mut Connection, server: &mut Connection) -> Result<(), Error> {
    for _ in 0..16 {
        let c = client.pop().unwrap_or_default();
        if !c.is_empty() {
            server.feed(&c)?;
        }
        let s = server.pop().unwrap_or_default();
        if !s.is_empty() {
            client.feed(&s)?;
        }
        if c.is_empty() && s.is_empty() {
            break;
        }
    }
    Ok(())
}

fn run_accept_scenario(cert_der: &[u8], key: &Ed25519PrivateKey) {
    println!("--- ACCEPT scenario: matching config_id ---");

    // Fresh ECH keypair with config_id=0x33; both sides see it.
    let pair = fresh_ech_keypair(0x33, b"accept");
    let list = EchConfigList::new(vec![pair.config().clone()]);
    let ring = EchKeyRing::from_pairs(vec![pair]);

    // Server: real Ed25519 identity + ECH server with the matching ring.
    let server_cfg = Config::builder()
        .tls_only()
        .identity(vec![cert_der.to_vec()], SigningKey::Ed25519(key.clone()))
        .ech_server(EchServer::new(ring, list.clone()))
        .build();
    let mut server = Connection::server(&server_cfg).expect("server config");

    // Client: trust the server cert; opt into real ECH against `list`.
    let mut roots = RootCertStore::new();
    roots.add_der(cert_der.to_vec()).unwrap();
    let client_cfg = Config::builder()
        .tls_only()
        .roots(roots)
        .server_name(INNER_SNI)
        .ech(EchClient::from_config_list(list))
        .build();
    let mut client = Connection::client(&client_cfg).expect("client config");

    drive_until_done_or_err(&mut client, &mut server).expect("handshake");
    assert!(client.is_handshake_complete() && server.is_handshake_complete());

    // ECH proof: the server reports the inner SNI even though the
    // wire CH carried the public_name as SNI.
    println!(
        "  server saw SNI: {:?} (inner CH won; outer SNI was {:?})",
        server.peer_server_name(),
        PUBLIC_NAME,
    );
    assert_eq!(server.peer_server_name(), Some(INNER_SNI));

    client.send(b"hello from inner CH").expect("send");
    let req = client.pop().expect("client.pop");
    server.feed(&req).expect("feed");
    let got = server.recv().expect("server.recv");
    println!(
        "  app data via inner transcript: {:?}",
        String::from_utf8_lossy(&got)
    );
    assert_eq!(got.as_slice(), b"hello from inner CH");
}

fn run_reject_scenario(cert_der: &[u8], key: &Ed25519PrivateKey) {
    println!("--- REJECT scenario: stale config_id ---");

    // Client seals against config_id=0xAA (stale).
    let client_side = fresh_ech_keypair(0xAA, b"reject-client");
    let stale_list = EchConfigList::new(vec![client_side.config().clone()]);

    // Server publishes config_id=0xBB — decap will miss.
    let server_side = fresh_ech_keypair(0xBB, b"reject-server");
    let fresh_list = EchConfigList::new(vec![server_side.config().clone()]);
    let ring = EchKeyRing::from_pairs(vec![server_side]);

    let server_cfg = Config::builder()
        .tls_only()
        .identity(vec![cert_der.to_vec()], SigningKey::Ed25519(key.clone()))
        .ech_server(EchServer::new(ring, fresh_list))
        .build();
    let mut server = Connection::server(&server_cfg).expect("server config");

    let mut roots = RootCertStore::new();
    roots.add_der(cert_der.to_vec()).unwrap();
    let client_cfg = Config::builder()
        .tls_only()
        .roots(roots)
        // Outer-CH verification path: client connects to the
        // `public_name` so the outer-CH cert (which covers it) validates.
        .server_name(PUBLIC_NAME)
        .ech(EchClient::from_config_list(stale_list))
        .build();
    let mut client = Connection::client(&client_cfg).expect("client config");

    match drive_until_done_or_err(&mut client, &mut server) {
        Err(Error::EchRejected(retry_bytes)) => {
            let parsed = EchConfigList::decode(&retry_bytes).expect("decode retry_configs");
            let first = parsed
                .first_supported()
                .expect("retry_configs has a supported entry");
            let contents = first
                .contents
                .as_ref()
                .expect("retry_configs entry has contents");
            println!(
                "  client received retry_configs (config_id=0x{:02x}, public_name={:?})",
                contents.key_config.config_id,
                String::from_utf8_lossy(&contents.public_name),
            );
            assert_eq!(contents.key_config.config_id, 0xBB);
        }
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(()) => panic!("rejection did not surface; client completed handshake silently"),
    }
}

fn main() {
    // `OsRng` is touched to make sure the example compiles on any
    // target where the example feature is enabled. It is not used
    // directly (HMAC-DRBG drives the deterministic ECH keygen).
    let _ = OsRng;

    let (cert_der, key) = make_server_cert();

    run_accept_scenario(&cert_der, &key);
    run_reject_scenario(&cert_der, &key);
    println!("OK");
}
