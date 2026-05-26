//! Connection state machines over the sans-I/O [`ConnectionCore`].

mod client;
mod client12;
mod common;
mod server;
mod server12;
#[cfg(feature = "std")]
mod stream;
mod ticket12;

#[allow(unused_imports)]
pub use client::{
    ClientCertConfig, ClientConfig, ClientConnection, ReceivedSessionTicket, StoredSession,
};
pub use client12::{ClientConfig12, ClientConnection12, StoredSession12};
#[cfg(feature = "std")]
pub use server::ReplayWindow;
#[allow(unused_imports)]
pub use server::{ClientAuthPolicy, ServerConfig, ServerConnection};
pub use server12::{ClientAuthPolicy12, ServerConfig12, ServerConnection12};
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

    /// `request_key_update` on the client side rolls the client's write keys
    /// forward, the server replies with its own `KeyUpdate(not_requested)`,
    /// and application data continues to flow under the new keys in both
    /// directions.
    #[test]
    fn key_update_client_initiated_round_trip() {
        let (server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"ku-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ku-server", b"nonce", &[]);
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
        assert!(!server.is_handshaking());

        // App data under the original keys.
        client.send_application_data(b"before").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"before");

        // Client requests a key update; flush.
        client.request_key_update().unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        // Server now responds with its own KeyUpdate(not_requested).
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();

        // App data under the *new* keys, both directions.
        client.send_application_data(b"after-client").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"after-client");

        server.send_application_data(b"after-server").unwrap();
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), b"after-server");
    }

    /// After a successful handshake, both sides derive identical
    /// application-layer keying material for the same `(label, context)`.
    #[test]
    fn tls_exporter_agrees_both_sides() {
        let (server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"exp-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"exp-server", b"nonce", &[]);
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
        assert!(!client.is_handshaking() && !server.is_handshaking());

        let mut c_out = [0u8; 64];
        let mut s_out = [0u8; 64];
        client
            .tls_exporter(b"EXPORTER-test", b"some context", &mut c_out)
            .unwrap();
        server
            .tls_exporter(b"EXPORTER-test", b"some context", &mut s_out)
            .unwrap();
        assert_eq!(c_out, s_out);

        // A different context yields a different output (sanity).
        let mut c_out2 = [0u8; 64];
        client
            .tls_exporter(b"EXPORTER-test", b"other context", &mut c_out2)
            .unwrap();
        assert_ne!(c_out, c_out2);
    }

    /// The client advertises `record_size_limit = 64`; the server's writes
    /// of a 500-byte payload fragment into multiple records (each ciphertext
    /// payload at most `64 + 16` bytes — content + tag).
    #[test]
    fn record_size_limit_fragments_writes() {
        use crate::tls::codec::{ParsedRecord, read_record};

        let (server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"rsl-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"rsl-server", b"nonce", &[]);
        let mut client = ClientConnection::new(
            ClientConfig::new(roots).with_record_size_limit(64),
            "loopback.example",
            &mut crng,
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
        assert!(!client.is_handshaking() && !server.is_handshaking());

        // Server writes 500 bytes; the client's record_size_limit caps each
        // server record's plaintext fragment at 63 (64 minus one byte for the
        // inner content type), so we should see ⌈500/63⌉ = 8 records.
        let payload: alloc::vec::Vec<u8> = (0..500u16).map(|i| i as u8).collect();
        server.send_application_data(&payload).unwrap();
        let s = server.write_tls();

        let mut consumed = 0;
        let mut records = 0;
        while consumed < s.len() {
            if let Some(ParsedRecord { fragment, len, .. }) = read_record(&s[consumed..]).unwrap() {
                // Ciphertext = content + 1 (type) + 16 (tag). Cap on content
                // is `limit - 1 = 63`, so fragment ≤ 80.
                assert!(
                    fragment.len() <= 64 + 16,
                    "fragment too large: {}",
                    fragment.len()
                );
                consumed += len;
                records += 1;
            } else {
                break;
            }
        }
        assert_eq!(records, 8, "expected 8 fragmented records, got {records}");

        // The client should still reassemble and receive the full payload.
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), payload);
    }

    /// ALPN: both sides negotiate `h2` when the server's preference also
    /// includes it.
    #[test]
    fn alpn_negotiates_h2() {
        let (server_config, cert_der) = rsa_server();
        let server_config =
            server_config.with_alpn(alloc::vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"alpn-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"alpn-server", b"nonce", &[]);
        let mut client = ClientConnection::new(
            ClientConfig::new(roots).with_alpn(alloc::vec![b"http/1.1".to_vec(), b"h2".to_vec()]),
            "loopback.example",
            &mut crng,
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
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert_eq!(client.alpn_protocol(), Some(&b"h2"[..]));
        assert_eq!(server.alpn_protocol(), Some(&b"h2"[..]));
    }

    /// PSK session resumption end-to-end.
    ///
    /// Phase 1: a fresh handshake completes; the server emits one
    /// NewSessionTicket; the client takes the resulting `StoredSession`.
    ///
    /// Phase 2: a new client connection seeds itself with that session,
    /// presents `pre_shared_key`, and resumes — bypassing
    /// Certificate / CertificateVerify in the server flight.
    #[test]
    fn psk_resumption_two_phase() {
        let (server_config, cert_der) = rsa_server();
        let server_config = server_config.with_ticket_key([0xa5u8; 32]);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        // Phase 1.
        let mut crng = HmacDrbg::<Sha256>::new(b"psk-client-1", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"psk-server-1", b"nonce", &[]);
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
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
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert!(!server.psk_used(), "first handshake is fresh");
        assert!(!client.psk_accepted(), "first handshake is fresh");

        let session = client
            .take_session()
            .expect("server should have emitted a NewSessionTicket");
        assert_eq!(session.psk.len(), 32);
        assert_eq!(session.cipher_suite_hash, crate::tls::HashAlg::Sha256);

        // Phase 2: a new handshake using the stored session.
        let (server_config2, cert_der2) = rsa_server();
        let server_config2 = server_config2.with_ticket_key([0xa5u8; 32]);
        let mut roots2 = RootCertStore::new();
        roots2.add_der(cert_der2).unwrap();

        let mut crng2 = HmacDrbg::<Sha256>::new(b"psk-client-2", b"nonce", &[]);
        let srng2 = HmacDrbg::<Sha256>::new(b"psk-server-2", b"nonce", &[]);
        let mut client2 = ClientConnection::new_with_offer(
            ClientConfig::new(roots2).with_session(session),
            "loopback.example",
            &mut crng2,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server2 = ServerConnection::new(server_config2, srng2);

        for _ in 0..16 {
            let c = client2.write_tls();
            if !c.is_empty() {
                server2.read_tls(&c);
                server2.process_new_packets().unwrap();
            }
            let s = server2.write_tls();
            if !s.is_empty() {
                client2.read_tls(&s);
                client2.process_new_packets().unwrap();
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        assert!(!client2.is_handshaking() && !server2.is_handshaking());
        assert!(
            server2.psk_used(),
            "second handshake should be a resumption"
        );
        assert!(client2.psk_accepted(), "client should see PSK acceptance");

        // App data still flows in both directions under the resumed keys.
        client2.send_application_data(b"resumed-ping").unwrap();
        let c = client2.write_tls();
        server2.read_tls(&c);
        server2.process_new_packets().unwrap();
        assert_eq!(server2.take_received_plaintext(), b"resumed-ping");

        server2.send_application_data(b"resumed-pong").unwrap();
        let s = server2.write_tls();
        client2.read_tls(&s);
        client2.process_new_packets().unwrap();
        assert_eq!(client2.take_received_plaintext(), b"resumed-pong");
    }

    /// mTLS happy path: server requires a client cert, client presents an
    /// Ed25519 chain signed by a root the server trusts, both sides reach
    /// `Connected` and exchange app data.
    #[test]
    fn mtls_required_round_trip() {
        use crate::tls::{ClientCertConfig, RootCertStore};

        let (server_config, server_cert_der) = rsa_server();

        // Build an Ed25519 client cert + the root that signed it (here the
        // leaf is self-signed, so the leaf IS the trust anchor).
        let mut crng_seed = HmacDrbg::<Sha256>::new(b"mtls-client-key", b"nonce", &[]);
        let client_key = Ed25519PrivateKey::generate(&mut crng_seed);
        let client_name = DistinguishedName::common_name("mtls-client");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let client_cert = Certificate::self_signed_general(
            &CertSigner::Ed25519(&client_key),
            &client_name,
            &validity,
            1,
            false,
            &["mtls-client"],
        )
        .unwrap();
        let client_cert_der = client_cert.to_der().to_vec();

        // Server trusts the client's root (self-signed: leaf == root).
        let mut server_roots = RootCertStore::new();
        server_roots.add_der(client_cert_der.clone()).unwrap();
        let server_config = server_config.with_client_auth(server_roots, true);

        // Client trusts the server's cert.
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der).unwrap();
        let cc = ClientCertConfig::with_ed25519(alloc::vec![client_cert_der], client_key);

        let mut crng = HmacDrbg::<Sha256>::new(b"mtls-client-rng", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"mtls-server-rng", b"nonce", &[]);
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots).with_client_cert(cc),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
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
        assert!(!client.is_handshaking() && !server.is_handshaking());

        // The server has the client's leaf cert in its peer-certificates view.
        assert_eq!(server.peer_certificates().len(), 1);

        // App data flows both ways.
        client.send_application_data(b"mtls-ping").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"mtls-ping");

        server.send_application_data(b"mtls-pong").unwrap();
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), b"mtls-pong");
    }

    /// mTLS rejection: server requires a client cert from a SPECIFIC root,
    /// client presents one from a DIFFERENT root → server rejects with
    /// `BadCertificate`.
    #[test]
    fn mtls_rejects_untrusted_client() {
        use crate::tls::{ClientCertConfig, RootCertStore};

        let (server_config, server_cert_der) = rsa_server();

        // Trusted client root and an unrelated client cert.
        let mut tk = HmacDrbg::<Sha256>::new(b"mtls-trusted-root", b"nonce", &[]);
        let trusted_key = Ed25519PrivateKey::generate(&mut tk);
        let trusted_cert = Certificate::self_signed_general(
            &CertSigner::Ed25519(&trusted_key),
            &DistinguishedName::common_name("trusted-root"),
            &Validity::new(
                Time::utc(2024, 1, 1, 0, 0, 0),
                Time::utc(2034, 1, 1, 0, 0, 0),
            ),
            1,
            false,
            &["trusted-root"],
        )
        .unwrap();
        let trusted_der = trusted_cert.to_der().to_vec();

        let mut uk = HmacDrbg::<Sha256>::new(b"mtls-untrusted", b"nonce", &[]);
        let untrusted_key = Ed25519PrivateKey::generate(&mut uk);
        let untrusted_cert = Certificate::self_signed_general(
            &CertSigner::Ed25519(&untrusted_key),
            &DistinguishedName::common_name("untrusted"),
            &Validity::new(
                Time::utc(2024, 1, 1, 0, 0, 0),
                Time::utc(2034, 1, 1, 0, 0, 0),
            ),
            1,
            false,
            &["untrusted"],
        )
        .unwrap();
        let untrusted_der = untrusted_cert.to_der().to_vec();

        let mut server_roots = RootCertStore::new();
        server_roots.add_der(trusted_der).unwrap();
        let server_config = server_config.with_client_auth(server_roots, true);

        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der).unwrap();
        let cc = ClientCertConfig::with_ed25519(alloc::vec![untrusted_der], untrusted_key);

        let mut crng = HmacDrbg::<Sha256>::new(b"mtls-bad-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"mtls-bad-server", b"nonce", &[]);
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots).with_client_cert(cc),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection::new(server_config, srng);

        let mut server_err: Option<crate::tls::Error> = None;
        for _ in 0..16 {
            let c = client.write_tls();
            if !c.is_empty() {
                server.read_tls(&c);
                if let Err(e) = server.process_new_packets() {
                    server_err = Some(e);
                    break;
                }
            }
            let s = server.write_tls();
            if !s.is_empty() {
                client.read_tls(&s);
                let _ = client.process_new_packets();
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        assert!(
            matches!(server_err, Some(crate::tls::Error::BadCertificate)),
            "expected BadCertificate from server, got {server_err:?}"
        );
    }

    /// mTLS optional: server's policy allows an empty client Certificate
    /// (no CertificateVerify required), the handshake still completes.
    #[test]
    fn mtls_optional_no_cert() {
        use crate::tls::RootCertStore;

        let (server_config, server_cert_der) = rsa_server();

        // Empty trust store; required = false.
        let server_roots = RootCertStore::new();
        let server_config = server_config.with_client_auth(server_roots, false);

        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"mtls-opt-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"mtls-opt-server", b"nonce", &[]);
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
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
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert!(server.peer_certificates().is_empty());
    }

    /// Server presents an ML-DSA-65 leaf and signs its `CertificateVerify`
    /// with the same key. Client validates the chain (under the default
    /// `modern()` policy, which permits ML-DSA) and reaches `Connected`.
    #[test]
    fn tls_mldsa_server_cert() {
        let mut rng = HmacDrbg::<Sha256>::new(b"tls-mldsa-server-key", b"nonce", &[]);
        let (sk, _pk) = crate::mldsa::MlDsa65PrivateKey::generate(&mut rng);
        let name = DistinguishedName::common_name("loopback.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::MlDsa65(&sk),
            &name,
            &validity,
            1,
            false,
            &["loopback.example"],
        )
        .unwrap();
        let cert_der = cert.to_der().to_vec();
        let server_config = ServerConfig::with_mldsa65(alloc::vec![cert_der.clone()], sk);

        run_with(
            (server_config, cert_der),
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
    }

    /// mTLS with an ML-DSA-65 client cert: server requires client auth, the
    /// client presents a self-signed ML-DSA-65 leaf, both sides reach
    /// `Connected`.
    #[test]
    fn tls_mtls_mldsa_client_cert() {
        use crate::tls::{ClientCertConfig, RootCertStore};

        let (server_config, server_cert_der) = rsa_server();

        // Build the client's ML-DSA-65 key and self-signed cert.
        let mut crng_seed = HmacDrbg::<Sha256>::new(b"tls-mtls-mldsa-client-key", b"nonce", &[]);
        let (client_sk, _client_pk) = crate::mldsa::MlDsa65PrivateKey::generate(&mut crng_seed);
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let client_cert = Certificate::self_signed_general(
            &CertSigner::MlDsa65(&client_sk),
            &DistinguishedName::common_name("mtls-mldsa-client"),
            &validity,
            1,
            false,
            &["mtls-mldsa-client"],
        )
        .unwrap();
        let client_cert_der = client_cert.to_der().to_vec();

        // Server trusts the client's self-signed root (leaf == anchor).
        let mut server_roots = RootCertStore::new();
        server_roots.add_der(client_cert_der.clone()).unwrap();
        let server_config = server_config.with_client_auth(server_roots, true);

        // Client trusts the server's cert.
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der).unwrap();
        let cc = ClientCertConfig::with_mldsa65(alloc::vec![client_cert_der], client_sk);

        let mut crng = HmacDrbg::<Sha256>::new(b"tls-mtls-mldsa-client-rng", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"tls-mtls-mldsa-server-rng", b"nonce", &[]);
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots).with_client_cert(cc),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
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
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert_eq!(server.peer_certificates().len(), 1);

        // App data both ways to confirm the application secrets work.
        client.send_application_data(b"mldsa-ping").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"mldsa-ping");

        server.send_application_data(b"mldsa-pong").unwrap();
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), b"mldsa-pong");
    }

    /// 0-RTT round-trip: phase 1 establishes a ticket with
    /// `max_early_data_size > 0`; phase 2 writes early data which the server
    /// reads under the early traffic key, before the handshake completes.
    #[test]
    fn zero_rtt_echo() {
        let (server_config, cert_der) = rsa_server();
        let server_config = server_config
            .with_ticket_key([0x33u8; 32])
            .with_max_early_data(16384);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        // Phase 1.
        let mut crng = HmacDrbg::<Sha256>::new(b"0rtt-client-1", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"0rtt-server-1", b"nonce", &[]);
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
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
        assert!(!client.is_handshaking() && !server.is_handshaking());
        let session = client.take_session().expect("ticket");
        assert_eq!(session.max_early_data_size, Some(16384));

        // Phase 2: send 0-RTT data right after CH.
        let (server_config2, cert_der2) = rsa_server();
        let server_config2 = server_config2
            .with_ticket_key([0x33u8; 32])
            .with_max_early_data(16384);
        let mut roots2 = RootCertStore::new();
        roots2.add_der(cert_der2).unwrap();

        let mut crng2 = HmacDrbg::<Sha256>::new(b"0rtt-client-2", b"nonce", &[]);
        let srng2 = HmacDrbg::<Sha256>::new(b"0rtt-server-2", b"nonce", &[]);
        let mut client2 = ClientConnection::new_with_offer(
            ClientConfig::new(roots2).with_session(session),
            "loopback.example",
            &mut crng2,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server2 = ServerConnection::new(server_config2, srng2);

        // Write early data immediately.
        client2.write_early_data(b"hello-0rtt").unwrap();

        // Drive the handshake.
        for _ in 0..16 {
            let c = client2.write_tls();
            if !c.is_empty() {
                server2.read_tls(&c);
                server2.process_new_packets().unwrap();
            }
            let s = server2.write_tls();
            if !s.is_empty() {
                client2.read_tls(&s);
                client2.process_new_packets().unwrap();
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        assert!(!client2.is_handshaking() && !server2.is_handshaking());
        assert!(server2.early_data_accepted(), "server accepted 0-RTT");
        assert!(client2.early_data_accepted(), "client saw 0-RTT acceptance");

        let received = server2.take_received_plaintext();
        assert_eq!(received, b"hello-0rtt", "server received 0-RTT data");
    }

    /// 0-RTT replay detection: when a ReplayWindow is shared across two
    /// servers, a second connection presenting the same binder is refused
    /// 0-RTT (the handshake still completes via the regular PSK path, so
    /// the replayed early data is silently dropped).
    #[test]
    fn zero_rtt_replay_detected() {
        use crate::tls::ReplayWindow;

        // Phase 1: establish a ticket with 0-RTT capability.
        let (server_config, cert_der) = rsa_server();
        let server_config = server_config
            .with_ticket_key([0xb2u8; 32])
            .with_max_early_data(16384);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"rep-client-1", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"rep-server-1", b"nonce", &[]);
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
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
        let session = client.take_session().expect("ticket");

        // The shared replay window across the two phase-2 servers.
        let window = ReplayWindow::new();

        // Phase 2a: first resumption with 0-RTT — accepted.
        let mut server_a = {
            let (server_config_a, cert_der_a) = rsa_server();
            let _ = cert_der_a;
            let server_config_a = server_config_a
                .with_ticket_key([0xb2u8; 32])
                .with_max_early_data(16384)
                .with_replay_window(window.clone());
            let srng_a = HmacDrbg::<Sha256>::new(b"rep-server-2a", b"nonce", &[]);
            ServerConnection::new(server_config_a, srng_a)
        };
        let mut crng_a = HmacDrbg::<Sha256>::new(b"rep-client-2a", b"nonce", &[]);
        let mut client_a = ClientConnection::new_with_offer(
            ClientConfig::new(RootCertStore::new()).with_session(session.clone()),
            "loopback.example",
            &mut crng_a,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        client_a.write_early_data(b"replay-bait").unwrap();
        let ch_records_a = client_a.write_tls();
        server_a.read_tls(&ch_records_a);
        server_a.process_new_packets().unwrap();
        assert!(
            server_a.early_data_accepted(),
            "first attempt accepts 0-RTT"
        );

        // Phase 2b: replay the SAME ClientHello + early-data records to a
        // fresh server that shares the replay window. The window blocks
        // the binder; 0-RTT is refused and the early data is dropped.
        let mut server_b = {
            let (server_config_b, cert_der_b) = rsa_server();
            let _ = cert_der_b;
            let server_config_b = server_config_b
                .with_ticket_key([0xb2u8; 32])
                .with_max_early_data(16384)
                .with_replay_window(window.clone());
            let srng_b = HmacDrbg::<Sha256>::new(b"rep-server-2b", b"nonce", &[]);
            ServerConnection::new(server_config_b, srng_b)
        };
        server_b.read_tls(&ch_records_a);
        // The server will fail to decrypt the early-data records (because
        // it never installed the early-read key) or — more cleanly — it
        // will continue without accepting them. Either way, 0-RTT is NOT
        // accepted.
        let _ = server_b.process_new_packets();
        assert!(
            !server_b.early_data_accepted(),
            "replayed binder must NOT accept 0-RTT"
        );
    }

    /// A PSK binder that's been tampered with: the server must reject with
    /// `decrypt_error` (RFC 8446 §4.2.11.2).
    #[test]
    fn psk_binder_mismatch_rejected() {
        let (server_config, cert_der) = rsa_server();
        let server_config = server_config.with_ticket_key([0x77u8; 32]);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        // Phase 1: get a real ticket.
        let mut crng = HmacDrbg::<Sha256>::new(b"badpsk-client-1", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"badpsk-server-1", b"nonce", &[]);
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
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
        let session = client.take_session().expect("ticket");

        // Phase 2: build the resumption CH, then tamper with its trailing
        // binder byte before feeding it to a fresh server.
        let (server_config2, cert_der2) = rsa_server();
        let server_config2 = server_config2.with_ticket_key([0x77u8; 32]);
        let mut roots2 = RootCertStore::new();
        roots2.add_der(cert_der2).unwrap();
        let mut crng2 = HmacDrbg::<Sha256>::new(b"badpsk-client-2", b"nonce", &[]);
        let srng2 = HmacDrbg::<Sha256>::new(b"badpsk-server-2", b"nonce", &[]);
        let mut client2 = ClientConnection::new_with_offer(
            ClientConfig::new(roots2).with_session(session),
            "loopback.example",
            &mut crng2,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server2 = ServerConnection::new(server_config2, srng2);

        // Pull the CH bytes, flip the last byte (which is part of the binder)
        // and feed the tampered record to the server.
        let ch_record = client2.write_tls();
        assert!(!ch_record.is_empty());
        let mut tampered = ch_record.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        server2.read_tls(&tampered);
        let err = server2.process_new_packets().unwrap_err();
        assert!(
            matches!(err, crate::tls::Error::DecryptError),
            "expected DecryptError, got {err:?}"
        );
    }

    /// ALPN: no overlap → server aborts with `no_application_protocol`.
    #[test]
    fn alpn_no_overlap_rejected() {
        let (server_config, cert_der) = rsa_server();
        let server_config = server_config.with_alpn(alloc::vec![b"h3".to_vec()]);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"alpn-bad-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"alpn-bad-server", b"nonce", &[]);
        let mut client = ClientConnection::new(
            ClientConfig::new(roots).with_alpn(alloc::vec![b"http/1.1".to_vec()]),
            "loopback.example",
            &mut crng,
        );
        let mut server = ServerConnection::new(server_config, srng);

        for _ in 0..16 {
            let c = client.write_tls();
            if !c.is_empty() {
                server.read_tls(&c);
                let r = server.process_new_packets();
                if let Err(e) = r {
                    assert!(matches!(e, crate::tls::Error::NoApplicationProtocol));
                    return;
                }
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
        panic!("server should have rejected with NoApplicationProtocol");
    }

    /// Builds a synthetic HelloRetryRequest record (handshake content type,
    /// plaintext): a `ServerHello` whose random is the HRR sentinel, carrying
    /// the given `selected_group` and the standard `supported_versions(TLS1.3)`.
    fn synthetic_hrr_record(suite: CipherSuite, selected_group: NamedGroup) -> Vec<u8> {
        use crate::tls::codec::{ExtensionType, ServerHello, hs_type, put_u16};
        // HRR magic random from RFC 8446 §4.1.3.
        let hrr_random: [u8; 32] = [
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
            0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c,
        ];

        // key_share extension body: selected_group u16.
        let mut ks_body = Vec::new();
        put_u16(&mut ks_body, selected_group.0);

        // supported_versions extension body: 0x0304.
        let sv_body = alloc::vec![0x03, 0x04];

        let sh = ServerHello {
            random: hrr_random,
            session_id: Vec::new(),
            cipher_suite: suite,
            extensions: alloc::vec![
                (ExtensionType::SUPPORTED_VERSIONS, sv_body),
                (ExtensionType::KEY_SHARE, ks_body),
            ],
        };
        let body = sh.encode();
        assert_eq!(body[0], hs_type::SERVER_HELLO);

        // Wrap as a handshake-type plaintext record.
        let mut out = Vec::new();
        crate::tls::codec::write_record(
            &mut out,
            crate::tls::ContentType::Handshake,
            crate::tls::ProtocolVersion::TLSv1_2,
            &body,
        );
        out
    }

    /// The client processes a HelloRetryRequest: it rewrites its transcript,
    /// re-emits a ClientHello narrowed to the HRR-selected group, and is
    /// willing to continue.
    #[test]
    fn accepts_hello_retry_request_and_resends() {
        use crate::tls::codec::{ClientHello, ExtensionType, ReadCursor, read_handshake};

        let (_server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"hrr-client", b"nonce", &[]);
        // Offer X25519 and SECP256R1; the server will "demand" SECP256R1.
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519, NamedGroup::SECP256R1],
        );

        // Drop the initial ClientHello so we can inspect the retry independently.
        let _ch1 = client.write_tls();

        // Feed the synthetic HRR forcing SECP256R1.
        let hrr = synthetic_hrr_record(CipherSuite::AES_128_GCM_SHA256, NamedGroup::SECP256R1);
        client.read_tls(&hrr);
        client.process_new_packets().unwrap();

        // The client must have emitted CH2. Pull it out and verify it carries
        // exactly one key_share entry for SECP256R1.
        let ch2_record = client.write_tls();
        assert!(!ch2_record.is_empty(), "client must emit CH2 after HRR");
        // The record is plaintext handshake; skip the 5-byte record header.
        let body = &ch2_record[5..];
        let mut c = ReadCursor::new(body);
        let (ty, hsbody) = read_handshake(&mut c).unwrap();
        assert_eq!(ty, crate::tls::codec::hs_type::CLIENT_HELLO);
        let ch2 = ClientHello::decode(hsbody).unwrap();
        // Locate the key_share extension and confirm its single entry is SECP256R1.
        let ks_ext = ch2
            .extensions
            .iter()
            .find(|(t, _)| *t == ExtensionType::KEY_SHARE)
            .expect("CH2 has key_share");
        let shares = crate::tls::codec::extension::parse_client_key_shares(&ks_ext.1).unwrap();
        assert_eq!(shares.len(), 1, "exactly one share in CH2");
        assert_eq!(shares[0].0, NamedGroup::SECP256R1);
    }

    /// A second HelloRetryRequest is rejected with `unexpected_message`
    /// (RFC 8446 §4.1.4).
    #[test]
    fn rejects_second_hello_retry_request() {
        let (_server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"hrr2-client", b"nonce", &[]);
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519, NamedGroup::SECP256R1],
        );
        let _ch1 = client.write_tls();

        // First HRR — accepted.
        let hrr1 = synthetic_hrr_record(CipherSuite::AES_128_GCM_SHA256, NamedGroup::SECP256R1);
        client.read_tls(&hrr1);
        client.process_new_packets().unwrap();
        let _ch2 = client.write_tls();

        // Second HRR — must be rejected.
        let hrr2 = synthetic_hrr_record(CipherSuite::AES_128_GCM_SHA256, NamedGroup::X25519);
        client.read_tls(&hrr2);
        let err = client.process_new_packets().unwrap_err();
        assert!(matches!(err, crate::tls::Error::UnexpectedMessage));
    }

    /// A HRR pointing at a group we did NOT offer is rejected with
    /// `illegal_parameter`.
    #[test]
    fn rejects_hrr_unoffered_group() {
        let (_server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"hrr-bad-client", b"nonce", &[]);
        // Offer only X25519. The HRR will ask for SECP256R1.
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let _ch1 = client.write_tls();
        let hrr = synthetic_hrr_record(CipherSuite::AES_128_GCM_SHA256, NamedGroup::SECP256R1);
        client.read_tls(&hrr);
        let err = client.process_new_packets().unwrap_err();
        assert!(matches!(err, crate::tls::Error::IllegalParameter));
    }

    /// A `KeyUpdate` body byte that is neither 0 nor 1 is rejected with
    /// `illegal_parameter` (RFC 8446 §4.6.3).
    #[test]
    fn rejects_illegal_key_update_byte() {
        use crate::tls::codec::hs_type;

        let (server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"ku-bad-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ku-bad-server", b"nonce", &[]);
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

        // Hand-craft a KeyUpdate with body byte 0x02 (illegal).
        // Wire: type ‖ u24 length ‖ body.
        let msg = alloc::vec![hs_type::KEY_UPDATE, 0, 0, 1, 0x02];
        server.emit_post_handshake(msg);
        let s = server.write_tls();
        client.read_tls(&s);
        let err = client.process_new_packets().unwrap_err();
        assert!(matches!(err, crate::tls::Error::IllegalParameter));
    }

    /// Duplicate extensions in a ServerHello are rejected per RFC 8446 §4.2.
    /// Inject a hand-crafted ServerHello with two `supported_versions` blocks
    /// and verify the client rejects with `illegal_parameter`.
    #[test]
    fn rejects_duplicate_extensions_in_server_hello() {
        use crate::tls::codec::{ExtensionType, ServerHello, put_u16, write_record};

        let (_server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"dup-ext-client", b"nonce", &[]);
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let _ch1 = client.write_tls();

        // Build a ServerHello with two supported_versions extensions.
        let sv_body = alloc::vec![0x03, 0x04];
        let mut ks_body = Vec::new();
        put_u16(&mut ks_body, NamedGroup::X25519.0);
        let key_body: Vec<u8> = alloc::vec![0u8; 32];
        crate::tls::codec::with_len_u16(&mut ks_body, |b| b.extend_from_slice(&key_body));
        let sh = ServerHello {
            random: [0x77; 32],
            session_id: Vec::new(),
            cipher_suite: CipherSuite::AES_128_GCM_SHA256,
            extensions: alloc::vec![
                (ExtensionType::SUPPORTED_VERSIONS, sv_body.clone()),
                (ExtensionType::SUPPORTED_VERSIONS, sv_body),
                (ExtensionType::KEY_SHARE, ks_body),
            ],
        };
        let mut out = Vec::new();
        write_record(
            &mut out,
            crate::tls::ContentType::Handshake,
            crate::tls::ProtocolVersion::TLSv1_2,
            &sh.encode(),
        );
        client.read_tls(&out);
        let err = client.process_new_packets().unwrap_err();
        assert!(matches!(err, crate::tls::Error::IllegalParameter));
    }

    /// A `ChangeCipherSpec` record after the handshake completes is rejected
    /// with `unexpected_message` per RFC 8446 §5.
    #[test]
    fn rejects_ccs_after_handshake() {
        let (server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"ccs-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ccs-server", b"nonce", &[]);
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

        // Inject a CCS record after the handshake.
        let mut bad = Vec::new();
        crate::tls::codec::write_record(
            &mut bad,
            crate::tls::ContentType::ChangeCipherSpec,
            crate::tls::ProtocolVersion::TLSv1_2,
            &[0x01],
        );
        client.read_tls(&bad);
        let err = client.process_new_packets().unwrap_err();
        assert!(matches!(err, crate::tls::Error::UnexpectedMessage));
    }

    /// A `ChangeCipherSpec` record carrying anything other than `[0x01]` is
    /// rejected with `unexpected_message`.
    #[test]
    fn rejects_ccs_with_bad_body() {
        let (_server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"badccs-client", b"nonce", &[]);
        let mut client =
            ClientConnection::new(ClientConfig::new(roots), "loopback.example", &mut crng);
        let _ch1 = client.write_tls();

        let mut bad = Vec::new();
        crate::tls::codec::write_record(
            &mut bad,
            crate::tls::ContentType::ChangeCipherSpec,
            crate::tls::ProtocolVersion::TLSv1_2,
            &[0x01, 0x02],
        );
        client.read_tls(&bad);
        let err = client.process_new_packets().unwrap_err();
        assert!(matches!(err, crate::tls::Error::UnexpectedMessage));
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

#[cfg(test)]
mod tls12_loopback_tests {
    //! End-to-end loopback for the TLS 1.2 client + server: drive a full
    //! handshake in-process across every AEAD-ECDHE suite × cert combination
    //! and confirm application data flows in both directions.

    use super::{ClientConfig12, ClientConnection12, ServerConfig12, ServerConnection12};
    use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::rsa::BoxedRsaPrivateKey;
    use crate::test_util::rsa_test_key_a;
    use crate::tls::RootCertStore;
    use crate::tls::codec::{CipherSuite, NamedGroup};
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
    use alloc::vec::Vec;

    /// An RSA self-signed server config plus its certificate DER (for the
    /// client's trust store).
    fn rsa_server12() -> (ServerConfig12, Vec<u8>) {
        let key = rsa_test_key_a();
        let name = DistinguishedName::common_name("loopback.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        // `self_signed` uses the raw RsaPrivateKey path, which auto-includes a
        // dNSName matching the CN — exactly what the TLS-1.2 client expects
        // when verifying "loopback.example".
        let cert = Certificate::self_signed(&key, &name, &validity, 1, false).unwrap();
        let der = cert.to_der().to_vec();
        let boxed = BoxedRsaPrivateKey::from_pkcs1_der(&key.to_pkcs1_der()).unwrap();
        (
            ServerConfig12::with_rsa(alloc::vec![der.clone()], boxed),
            der,
        )
    }

    /// A P-256 ECDSA self-signed server config plus its certificate DER.
    fn ecdsa_server12() -> (ServerConfig12, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"loopback-ec12-key", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let name = DistinguishedName::common_name("loopback.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            false,
            &["loopback.example"],
        )
        .unwrap();
        let der = cert.to_der().to_vec();
        (
            ServerConfig12::with_ecdsa(alloc::vec![der.clone()], key),
            der,
        )
    }

    /// Runs a full in-process TLS 1.2 handshake against `(server_config, cert)`
    /// using the given offered suites/groups, then exchanges application data
    /// in both directions.
    fn run_with(server: (ServerConfig12, Vec<u8>), suites: &[CipherSuite], groups: &[NamedGroup]) {
        let (server_config, cert_der) = server;
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"loopback12-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"loopback12-server", b"nonce", &[]);

        let mut client = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots),
            "loopback.example",
            &mut crng,
            suites,
            groups,
        );
        let mut server = ServerConnection12::new(server_config, srng);

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

        // Suite agreement.
        assert_eq!(
            client.negotiated_cipher_suite(),
            server.negotiated_cipher_suite(),
            "client and server disagree on cipher suite",
        );

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
    fn tls12_ecdhe_rsa_aes128gcm_x25519() {
        run_with(
            rsa_server12(),
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
    }

    #[test]
    fn tls12_ecdhe_rsa_aes256gcm_x25519() {
        run_with(
            rsa_server12(),
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384],
            &[NamedGroup::X25519],
        );
    }

    #[test]
    fn tls12_ecdhe_rsa_chacha20_x25519() {
        run_with(
            rsa_server12(),
            &[CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256],
            &[NamedGroup::X25519],
        );
    }

    #[test]
    fn tls12_ecdhe_ecdsa_aes128gcm_secp256r1() {
        run_with(
            ecdsa_server12(),
            &[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::SECP256R1],
        );
    }

    #[test]
    fn tls12_ecdhe_ecdsa_chacha20_x25519() {
        run_with(
            ecdsa_server12(),
            &[CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256],
            &[NamedGroup::X25519],
        );
    }

    #[test]
    fn tls12_secp256r1_with_rsa_cert() {
        run_with(
            rsa_server12(),
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::SECP256R1],
        );
    }

    /// Larger payload to exercise both record fragmentation (write side) and
    /// reassembly (read side) of application data.
    #[test]
    fn tls12_application_data_both_directions() {
        let (server_config, cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"loopback12-app-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"loopback12-app-s", b"nonce", &[]);
        let mut client = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection12::new(server_config, srng);

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
        assert!(!client.is_handshaking() && !server.is_handshaking());

        // Send two messages each way to exercise sequence-number progression.
        for msg in [b"hello-1".as_ref(), b"hello-2".as_ref()] {
            client.send_application_data(msg).unwrap();
            let c = client.write_tls();
            server.read_tls(&c);
            server.process_new_packets().unwrap();
            assert_eq!(server.take_received_plaintext(), msg);
        }
        for msg in [b"world-1".as_ref(), b"world-2".as_ref()] {
            server.send_application_data(msg).unwrap();
            let s = server.write_tls();
            client.read_tls(&s);
            client.process_new_packets().unwrap();
            assert_eq!(client.take_received_plaintext(), msg);
        }
    }

    /// A client offering only an unknown cipher suite is rejected with
    /// `HandshakeFailure`.
    #[test]
    fn tls12_rejects_client_with_no_overlap_suite() {
        let (server_config, _cert_der) = rsa_server12();
        let mut crng = HmacDrbg::<Sha256>::new(b"loopback12-bad-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"loopback12-bad-s", b"nonce", &[]);

        // The client offers TLS 1.2 suites, but they're all in the ECDSA half
        // (no RSA match for an RSA-keyed server). The server picks none →
        // HandshakeFailure.
        let mut client = ClientConnection12::new_with_offer(
            ClientConfig12::new(RootCertStore::new()),
            "loopback.example",
            &mut crng,
            &[
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection12::new(server_config, srng);

        let c = client.write_tls();
        server.read_tls(&c);
        assert!(matches!(
            server.process_new_packets(),
            Err(crate::tls::Error::HandshakeFailure)
        ));
    }

    // ----- mTLS (commit 5) -----

    /// Full mTLS round-trip: server demands a client cert (`required = true`),
    /// client presents one, the handshake completes and app data flows both
    /// ways.
    #[test]
    fn tls12_mtls_required_roundtrip() {
        use super::ClientCertConfig;
        use crate::ec::Ed25519PrivateKey;
        use crate::x509::CertSigner;

        let (server_config, server_cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der).unwrap();

        // Build a self-signed Ed25519 client cert.
        let mut crng_seed = HmacDrbg::<Sha256>::new(b"mtls12-client-key", b"nonce", &[]);
        let client_key = Ed25519PrivateKey::generate(&mut crng_seed);
        let client_name = DistinguishedName::common_name("mtls12-client");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let client_cert = Certificate::self_signed_general(
            &CertSigner::Ed25519(&client_key),
            &client_name,
            &validity,
            1,
            false,
            &["mtls12-client"],
        )
        .unwrap();
        let client_cert_der = client_cert.to_der().to_vec();

        let mut server_roots = RootCertStore::new();
        server_roots.add_der(client_cert_der.clone()).unwrap();
        let server_config = server_config.with_client_auth(server_roots, true);

        let cc = ClientCertConfig::with_ed25519(alloc::vec![client_cert_der], client_key);
        let client_cfg = ClientConfig12::new(roots).with_client_cert(cc);

        let mut crng = HmacDrbg::<Sha256>::new(b"mtls12-client-rng", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"mtls12-server-rng", b"nonce", &[]);
        let mut client = ClientConnection12::new_with_offer(
            client_cfg,
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection12::new(server_config, srng);

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
        assert!(!client.is_handshaking() && !server.is_handshaking());
        // Server learned the client's leaf cert.
        assert_eq!(server.peer_certificates().len(), 1);

        // App data both ways under mTLS.
        client.send_application_data(b"mtls12-ping").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"mtls12-ping");

        server.send_application_data(b"mtls12-pong").unwrap();
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), b"mtls12-pong");
    }

    /// mTLS with `required = false`: client has a cert and presents it — same
    /// path as the required case, both sides finish.
    #[test]
    fn tls12_mtls_optional_with_cert() {
        use super::ClientCertConfig;
        use crate::ec::Ed25519PrivateKey;
        use crate::x509::CertSigner;

        let (server_config, server_cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der).unwrap();

        let mut crng_seed = HmacDrbg::<Sha256>::new(b"mtls12-opt-c-key", b"nonce", &[]);
        let client_key = Ed25519PrivateKey::generate(&mut crng_seed);
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let client_cert = Certificate::self_signed_general(
            &CertSigner::Ed25519(&client_key),
            &DistinguishedName::common_name("mtls12-opt"),
            &validity,
            1,
            false,
            &["mtls12-opt"],
        )
        .unwrap();
        let client_cert_der = client_cert.to_der().to_vec();

        let mut server_roots = RootCertStore::new();
        server_roots.add_der(client_cert_der.clone()).unwrap();
        let server_config = server_config.with_client_auth(server_roots, false);

        let cc = ClientCertConfig::with_ed25519(alloc::vec![client_cert_der], client_key);
        let mut crng = HmacDrbg::<Sha256>::new(b"mtls12-opt-c-rng", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"mtls12-opt-s-rng", b"nonce", &[]);
        let mut client = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots).with_client_cert(cc),
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection12::new(server_config, srng);

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
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert_eq!(server.peer_certificates().len(), 1);
    }

    /// mTLS with `required = false` and a client that has no cert: the client
    /// sends an empty Certificate, skips CertVerify, and the handshake still
    /// completes.
    #[test]
    fn tls12_mtls_optional_without_cert() {
        let (server_config, server_cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der).unwrap();

        let server_roots = RootCertStore::new();
        let server_config = server_config.with_client_auth(server_roots, false);

        let mut crng = HmacDrbg::<Sha256>::new(b"mtls12-empty-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"mtls12-empty-s", b"nonce", &[]);
        let mut client = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots), // no client_cert
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection12::new(server_config, srng);

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
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert!(server.peer_certificates().is_empty());
    }

    /// mTLS with `required = true`: client has no cert, sends an empty
    /// Certificate, server rejects with `certificate_required`.
    #[test]
    fn tls12_mtls_required_no_cert_rejected() {
        let (server_config, server_cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der).unwrap();

        let server_roots = RootCertStore::new();
        let server_config = server_config.with_client_auth(server_roots, true);

        let mut crng = HmacDrbg::<Sha256>::new(b"mtls12-req-no-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"mtls12-req-no-s", b"nonce", &[]);
        let mut client = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection12::new(server_config, srng);

        let mut server_err: Option<crate::tls::Error> = None;
        for _ in 0..16 {
            let c = client.write_tls();
            if !c.is_empty() {
                server.read_tls(&c);
                if let Err(e) = server.process_new_packets() {
                    server_err = Some(e);
                    break;
                }
            }
            let s = server.write_tls();
            if !s.is_empty() {
                client.read_tls(&s);
                let _ = client.process_new_packets();
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        assert!(
            matches!(server_err, Some(crate::tls::Error::CertificateRequired)),
            "expected CertificateRequired, got {server_err:?}",
        );
    }

    // ----- RFC 5077 session tickets (commit 5) -----

    /// Two-phase resumption: a fresh handshake yields a session, a second
    /// connection resumes via the abbreviated flow.
    #[test]
    fn tls12_resumption_round_trip() {
        let (server_config, server_cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der.clone()).unwrap();

        let ticket_key = [0x77u8; 32];
        let server_config = server_config.with_ticket_key(ticket_key);

        // Phase 1: fresh handshake — server issues a NST.
        let mut crng = HmacDrbg::<Sha256>::new(b"tls12-resume-1c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"tls12-resume-1s", b"nonce", &[]);
        let mut client = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection12::new(server_config, srng);

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
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert!(!client.did_resume(), "first handshake must be fresh");
        let session = client
            .take_session()
            .expect("client must have received a ticket");

        // Phase 2: resume. We need a fresh server config (and a fresh client
        // root store, since RootCertStore isn't Clone) sharing the same
        // ticket_key and same cert chain.
        let (server_config2, _) = rsa_server12();
        let server_config2 = server_config2.with_ticket_key(ticket_key);
        let mut roots2 = RootCertStore::new();
        roots2.add_der(server_cert_der).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"tls12-resume-2c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"tls12-resume-2s", b"nonce", &[]);
        let mut client2 = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots2).with_session(session),
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server2 = ServerConnection12::new(server_config2, srng);

        for _ in 0..16 {
            let c = client2.write_tls();
            if !c.is_empty() {
                server2.read_tls(&c);
                server2.process_new_packets().unwrap();
            }
            let s = server2.write_tls();
            if !s.is_empty() {
                client2.read_tls(&s);
                client2.process_new_packets().unwrap();
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        assert!(!client2.is_handshaking() && !server2.is_handshaking());
        assert!(client2.did_resume(), "second handshake must resume");
        assert!(server2.did_resume(), "server must see this as a resume");

        // App data both ways on the resumed session.
        client2.send_application_data(b"resumed-ping").unwrap();
        let c = client2.write_tls();
        server2.read_tls(&c);
        server2.process_new_packets().unwrap();
        assert_eq!(server2.take_received_plaintext(), b"resumed-ping");
    }

    /// A tampered ticket falls back to a fresh full handshake (the server's
    /// AEAD decrypt fails and it ignores the ticket).
    #[test]
    fn tls12_resumption_falls_back_on_bad_ticket() {
        let (server_config, server_cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der.clone()).unwrap();
        let ticket_key = [0x77u8; 32];
        let server_config = server_config.with_ticket_key(ticket_key);

        // Phase 1: get a ticket.
        let mut crng = HmacDrbg::<Sha256>::new(b"tls12-bad-1c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"tls12-bad-1s", b"nonce", &[]);
        let mut client = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection12::new(server_config, srng);
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
        let mut session = client.take_session().expect("ticket issued");
        // Tamper a byte in the middle of the ticket.
        let i = session.ticket.len() / 2;
        session.ticket[i] ^= 0x01;

        // Phase 2: tampered ticket -> server falls back to fresh handshake.
        let (server_config2, _) = rsa_server12();
        let server_config2 = server_config2.with_ticket_key(ticket_key);
        let mut roots2 = RootCertStore::new();
        roots2.add_der(server_cert_der).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"tls12-bad-2c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"tls12-bad-2s", b"nonce", &[]);
        let mut client2 = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots2).with_session(session),
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server2 = ServerConnection12::new(server_config2, srng);

        for _ in 0..16 {
            let c = client2.write_tls();
            if !c.is_empty() {
                server2.read_tls(&c);
                server2.process_new_packets().unwrap();
            }
            let s = server2.write_tls();
            if !s.is_empty() {
                client2.read_tls(&s);
                client2.process_new_packets().unwrap();
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        assert!(!client2.is_handshaking() && !server2.is_handshaking());
        // Tampered ticket: client offered it, server rejected and ran a
        // fresh handshake. Both `did_resume()` calls must report false.
        assert!(
            !server2.did_resume(),
            "server must have fallen back to a fresh handshake",
        );
        assert!(!client2.did_resume(), "client must see a fresh handshake");
    }
}
