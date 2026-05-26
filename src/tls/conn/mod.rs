//! Connection state machines over the sans-I/O [`ConnectionCore`].

mod client;
mod common;
mod server;
#[cfg(feature = "std")]
mod stream;

#[allow(unused_imports)]
pub use client::{ClientConfig, ClientConnection, ReceivedSessionTicket};
#[allow(unused_imports)]
pub use server::{ServerConfig, ServerConnection};
#[cfg(feature = "std")]
pub use stream::{Connection, Stream};

#[cfg(test)]
mod loopback_tests {
    use super::{ClientConnection, ServerConfig, ServerConnection};
    use crate::ec::Ed25519PrivateKey;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::rsa::BoxedRsaPrivateKey;
    use crate::test_util::rsa_test_key_a;
    use crate::tls::codec::{CipherSuite, NamedGroup};
    use crate::tls::{ClientConfig, RootCertStore};
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
    use alloc::vec::Vec;

    /// An RSA self-signed server config plus its certificate DER (for the
    /// client's trust store).
    fn rsa_server() -> (ServerConfig, Vec<u8>) {
        let key = rsa_test_key_a();
        let name = DistinguishedName::common_name("loopback.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed(&key, &name, &validity, 1, false).unwrap();
        let der = cert.to_der().to_vec();
        let boxed = BoxedRsaPrivateKey::from_pkcs1_der(&key.to_pkcs1_der()).unwrap();
        (ServerConfig::with_rsa(alloc::vec![der.clone()], boxed), der)
    }

    /// An Ed25519 self-signed server config plus its certificate DER.
    fn ed25519_server() -> (ServerConfig, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"loopback-ed-key", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut rng);
        let name = DistinguishedName::common_name("loopback.example");
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
            &["loopback.example"],
        )
        .unwrap();
        let der = cert.to_der().to_vec();
        (
            ServerConfig::with_ed25519(alloc::vec![der.clone()], key),
            der,
        )
    }

    /// Runs a full in-process handshake with an RSA server, then exchanges
    /// application data in both directions.
    fn run(suites: &[CipherSuite], groups: &[NamedGroup]) {
        run_with(rsa_server(), suites, groups);
    }

    /// Runs a full in-process handshake against `(server_config, cert_der)`,
    /// then exchanges application data in both directions.
    fn run_with(server: (ServerConfig, Vec<u8>), suites: &[CipherSuite], groups: &[NamedGroup]) {
        let (server_config, cert_der) = server;
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"loopback-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"loopback-server", b"nonce", &[]);

        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            suites,
            groups,
        );
        let mut server = ServerConnection::new(server_config, srng);

        for _ in 0..16 {
            let c = client.write_tls();
            if !c.is_empty() {
                server.read_tls(&c);
                server.process_new_packets().unwrap();
            }
            let s = server.write_tls();
            if !s.is_empty() {
                client.read_tls(&s);
                client.process_new_packets().unwrap();
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }

        assert!(!client.is_handshaking(), "client did not finish");
        assert!(!server.is_handshaking(), "server did not finish");

        // Application data, client -> server.
        client.send_application_data(b"ping from client").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"ping from client");

        // Application data, server -> client.
        server.send_application_data(b"pong from server").unwrap();
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), b"pong from server");
    }

    #[test]
    fn x25519_aes128_sha256() {
        run(&[CipherSuite::AES_128_GCM_SHA256], &[NamedGroup::X25519]);
    }

    #[test]
    fn secp256r1_aes256_sha384() {
        run(&[CipherSuite::AES_256_GCM_SHA384], &[NamedGroup::SECP256R1]);
    }

    #[test]
    fn x25519_chacha20poly1305_sha256() {
        run(
            &[CipherSuite::CHACHA20_POLY1305_SHA256],
            &[NamedGroup::X25519],
        );
    }

    #[test]
    fn x25519mlkem768_hybrid_kex() {
        // The post-quantum hybrid group completes a full handshake and agrees on
        // application data both ways.
        run(
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519MLKEM768],
        );
    }

    #[test]
    fn ed25519_server_certificate() {
        // An Ed25519 server cert exercises Ed25519 chain verification and the
        // Ed25519 CertificateVerify signature end to end.
        run_with(
            ed25519_server(),
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
    }

    #[test]
    fn both_offered_negotiates() {
        run(
            &[
                CipherSuite::AES_128_GCM_SHA256,
                CipherSuite::AES_256_GCM_SHA384,
            ],
            &[NamedGroup::X25519, NamedGroup::SECP256R1],
        );
    }

    /// Drives a handshake expecting the client to reject the server flight,
    /// returning the client's error.
    fn drive_until_client_error(
        client: &mut ClientConnection,
        server: &mut ServerConnection<HmacDrbg<Sha256>>,
    ) -> crate::tls::Error {
        for _ in 0..16 {
            let c = client.write_tls();
            if !c.is_empty() {
                server.read_tls(&c);
                server.process_new_packets().unwrap();
            }
            let s = server.write_tls();
            if !s.is_empty() {
                client.read_tls(&s);
                if let Err(e) = client.process_new_packets() {
                    return e;
                }
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        panic!("expected the client to reject the certificate");
    }

    #[test]
    fn rejects_wrong_hostname() {
        let (server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"hostname-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"hostname-server", b"nonce", &[]);
        // The server cert is for "loopback.example"; connect to a different name.
        let mut client =
            ClientConnection::new(ClientConfig::new(roots), "attacker.example", &mut crng);
        let mut server = ServerConnection::new(server_config, srng);

        assert_eq!(
            drive_until_client_error(&mut client, &mut server),
            crate::tls::Error::BadCertificate
        );
    }

    /// A server-emitted `NewSessionTicket` post-handshake is parsed and
    /// stashed in `ClientConnection::last_session_ticket()`. This mirrors the
    /// Cloudflare / real-world case where the peer sends one or more NSTs
    /// immediately after `Finished`.
    #[test]
    fn accepts_post_handshake_new_session_ticket() {
        use crate::tls::codec::ExtensionType;
        use crate::tls::codec::NewSessionTicket;

        let (server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"nst-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"nst-server", b"nonce", &[]);
        let mut client =
            ClientConnection::new(ClientConfig::new(roots), "loopback.example", &mut crng);
        let mut server = ServerConnection::new(server_config, srng);

        // Complete the handshake.
        for _ in 0..16 {
            let c = client.write_tls();
            if !c.is_empty() {
                server.read_tls(&c);
                server.process_new_packets().unwrap();
            }
            let s = server.write_tls();
            if !s.is_empty() {
                client.read_tls(&s);
                client.process_new_packets().unwrap();
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());

        // Server emits a NewSessionTicket carrying an early_data extension.
        let nst = NewSessionTicket {
            ticket_lifetime: 3600,
            ticket_age_add: 0xdeadbeef,
            ticket_nonce: alloc::vec![1, 2, 3, 4],
            ticket: alloc::vec![0xab; 32],
            extensions: alloc::vec![(ExtensionType(0x002a), alloc::vec![0x00, 0x00, 0x40, 0x00],)],
        };
        server.emit_post_handshake(nst.encode());
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();

        let got = client.last_session_ticket().expect("ticket stored");
        assert_eq!(got.lifetime_seconds, 3600);
        assert_eq!(got.age_add, 0xdeadbeef);
        assert_eq!(got.nonce, alloc::vec![1u8, 2, 3, 4]);
        assert_eq!(got.ticket, alloc::vec![0xab; 32]);
        assert_eq!(got.max_early_data_size, Some(16384));

        // The handshake state is unaffected; we can still exchange app data.
        server.send_application_data(b"after ticket").unwrap();
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), b"after ticket");
    }

    /// A malformed `NewSessionTicket` (empty ticket field) is rejected with a
    /// decode error; the client closes the connection rather than papering over
    /// it.
    #[test]
    fn rejects_malformed_new_session_ticket() {
        use crate::tls::codec::hs_type;

        let (server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"badnst-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"badnst-server", b"nonce", &[]);
        let mut client =
            ClientConnection::new(ClientConfig::new(roots), "loopback.example", &mut crng);
        let mut server = ServerConnection::new(server_config, srng);

        for _ in 0..16 {
            let c = client.write_tls();
            if !c.is_empty() {
                server.read_tls(&c);
                server.process_new_packets().unwrap();
            }
            let s = server.write_tls();
            if !s.is_empty() {
                client.read_tls(&s);
                client.process_new_packets().unwrap();
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        assert!(!client.is_handshaking());

        // Manually craft a NewSessionTicket message body with ticket length = 0,
        // which RFC 8446 §4.6.1 forbids (`ticket<1..2^16-1>`).
        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(&3600u32.to_be_bytes()); // ticket_lifetime
        body.extend_from_slice(&0u32.to_be_bytes()); // ticket_age_add
        body.push(0); // ticket_nonce<0..255> = empty
        body.extend_from_slice(&[0, 0]); // ticket<...> length = 0  (illegal)
        body.extend_from_slice(&[0, 0]); // extensions<...> length = 0

        // Wrap as a Handshake message: type ‖ u24 length ‖ body.
        let mut msg = alloc::vec::Vec::new();
        msg.push(hs_type::NEW_SESSION_TICKET);
        let blen = body.len() as u32;
        msg.extend_from_slice(&blen.to_be_bytes()[1..]);
        msg.extend_from_slice(&body);

        server.emit_post_handshake(msg);
        let s = server.write_tls();
        client.read_tls(&s);
        // The client must error out (no stored ticket).
        assert!(client.process_new_packets().is_err());
        assert!(client.last_session_ticket().is_none());
    }

    #[test]
    fn rejects_expired_certificate() {
        use crate::x509::Time;
        let (server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        // The cert is valid 2024–2034; verify as if it were 2020.
        let mut config = ClientConfig::new(roots);
        config.verification_time = Some(Time::utc(2020, 1, 1, 0, 0, 0));

        let mut crng = HmacDrbg::<Sha256>::new(b"expiry-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"expiry-server", b"nonce", &[]);
        let mut client = ClientConnection::new(config, "loopback.example", &mut crng);
        let mut server = ServerConnection::new(server_config, srng);

        assert_eq!(
            drive_until_client_error(&mut client, &mut server),
            crate::tls::Error::BadCertificate
        );
    }
}
