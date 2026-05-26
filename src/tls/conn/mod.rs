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
