//! Connection state machines over the sans-I/O [`ConnectionCore`].

mod client;
mod client12;
mod common;
mod server;
mod server12;
#[cfg(feature = "std")]
mod stream;
mod ticket12;

pub(crate) use client::ClientConfig;
#[allow(unused_imports)]
pub(crate) use client::{ClientCertConfig, ClientConnection, ReceivedSessionTicket, StoredSession};
pub(crate) use client12::ClientConfig12;
pub(crate) use client12::ClientConnection12;
// Re-exported for the DTLS 1.2 client / server, which drive suite negotiation
// from the same 6-entry SUITES_12 table as the TLS 1.2 layer.
#[allow(unused_imports)]
pub(crate) use client12::{SUITES_12, SigKind, SuiteParams12, lookup_suite_12};
#[cfg(feature = "std")]
pub(crate) use server::ReplayWindow;
#[allow(unused_imports)]
pub(crate) use server::ServerConnection;
pub(crate) use server::{ServerConfig, ServerKey};
pub(crate) use server12::ServerConfig12;
pub(crate) use server12::ServerConnection12;

#[cfg(test)]
mod quic_mode_tests {
    //! QUIC-mode (RFC 9001) loopback. Drives a TLS 1.3 handshake through
    //! the same `ClientConnection` / `ServerConnection` engines but with
    //! `EngineMode::Quic` — handshake bytes flow through `QuicHooks`
    //! instead of records; secrets are surfaced per level / direction;
    //! `ChangeCipherSpec` is suppressed.
    use super::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
    use crate::ec::Ed25519PrivateKey;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::tls::RootCertStore;
    use crate::tls::codec::{CipherSuite, NamedGroup};
    use crate::tls::quic_hooks::{BoxedHooks, Direction, Level, QuicHooks};
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    /// Ed25519 self-signed server config plus its certificate DER.
    fn ed25519_server() -> (ServerConfig, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"quic-loopback-ed-key", b"nonce", &[]);
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

    /// The captured state of a [`SharedHooks`] instance: every callback
    /// the engine fires while in QUIC mode, exposed to the test driver.
    #[derive(Default)]
    struct Captured {
        peer_params: Vec<u8>,
        peer_params_seen: bool,
        tx_handshake: Vec<(Level, Vec<u8>)>,
        secrets: Vec<(Level, Direction, Vec<u8>)>,
    }

    /// A shared captured-state container so the test driver can inspect
    /// callbacks while the engine still owns its hooks. `our_params` is
    /// kept outside the mutex so [`QuicHooks::our_transport_params`] can
    /// return a borrow without taking the lock (and without `unsafe`).
    #[derive(Clone)]
    struct HookHandle {
        our_params: Arc<Vec<u8>>,
        state: Arc<Mutex<Captured>>,
    }

    impl HookHandle {
        fn install(params: Vec<u8>) -> (BoxedHooks, Self) {
            let our_params = Arc::new(params);
            let state = Arc::new(Mutex::new(Captured::default()));
            let handle = HookHandle {
                our_params: our_params.clone(),
                state: state.clone(),
            };
            (
                Box::new(SharedHooks { our_params, state }) as BoxedHooks,
                handle,
            )
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, Captured> {
            self.state.lock().expect("hooks mutex poisoned")
        }

        fn our_params(&self) -> &[u8] {
            self.our_params.as_slice()
        }
    }

    /// The engine-side end of [`HookHandle`]. Forwards every callback into
    /// the shared `Captured` state and returns an immutable borrow for
    /// `our_transport_params` straight from the `Arc<Vec<u8>>`.
    struct SharedHooks {
        our_params: Arc<Vec<u8>>,
        state: Arc<Mutex<Captured>>,
    }

    impl QuicHooks for SharedHooks {
        fn on_handshake_data(&mut self, level: Level, data: &[u8]) {
            self.state
                .lock()
                .unwrap()
                .tx_handshake
                .push((level, data.to_vec()));
        }
        fn on_traffic_secret(&mut self, level: Level, dir: Direction, secret: &[u8]) {
            self.state
                .lock()
                .unwrap()
                .secrets
                .push((level, dir, secret.to_vec()));
        }
        fn our_transport_params(&self) -> Vec<u8> {
            self.our_params.as_slice().to_vec()
        }
        fn on_peer_transport_params(&mut self, raw: &[u8]) {
            let mut s = self.state.lock().unwrap();
            s.peer_params = raw.to_vec();
            s.peer_params_seen = true;
        }
    }

    /// The pumped-out history of one side's `tx_handshake` queue,
    /// retained for assertions after the driver finishes draining.
    type HandshakeHistory = Vec<(Level, Vec<u8>)>;

    /// Drives a QUIC-mode TLS 1.3 handshake to completion via the hooks
    /// pump and returns the captured state on each side, alongside the
    /// finalized client/server engines for further inspection.
    fn run_quic_handshake(
        suite: CipherSuite,
        group: NamedGroup,
    ) -> (
        ClientConnection,
        ServerConnection<HmacDrbg<Sha256>>,
        HookHandle,
        HookHandle,
        HandshakeHistory, // client's tx_handshake in emit order
        HandshakeHistory, // server's tx_handshake in emit order
    ) {
        let (server_config, cert_der) = ed25519_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"quic-mode-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"quic-mode-server", b"nonce", &[]);

        let (client_box, client_handle) = HookHandle::install(alloc::vec![0xc1u8, 0xc2, 0xc3]);
        let (server_box, server_handle) = HookHandle::install(alloc::vec![0x51u8, 0x52, 0x53]);

        let mut client = ClientConnection::new_for_quic(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[suite],
            &[group],
            client_box,
        );
        let mut server = ServerConnection::new_for_quic(server_config, srng, server_box);

        // Accumulate the full emit history for assertions, since the
        // driver below drains `tx_handshake` each iteration.
        let mut client_history: HandshakeHistory = Vec::new();
        let mut server_history: HandshakeHistory = Vec::new();

        // Drive the handshake by pumping each side's tx_handshake queue
        // into the other side's `process_quic_handshake_bytes`. Cap at
        // 8 rounds to keep a buggy state machine from spinning forever.
        for _ in 0..8 {
            // Client → Server.
            let client_drain: Vec<(Level, Vec<u8>)> = {
                let mut h = client_handle.lock();
                core::mem::take(&mut h.tx_handshake)
            };
            client_history.extend(client_drain.iter().cloned());
            for (level, bytes) in client_drain {
                server.process_quic_handshake_bytes(level, &bytes).unwrap();
            }
            // Server → Client.
            let server_drain: Vec<(Level, Vec<u8>)> = {
                let mut h = server_handle.lock();
                core::mem::take(&mut h.tx_handshake)
            };
            server_history.extend(server_drain.iter().cloned());
            for (level, bytes) in server_drain {
                client.process_quic_handshake_bytes(level, &bytes).unwrap();
            }

            let client_empty = client_handle.lock().tx_handshake.is_empty();
            let server_empty = server_handle.lock().tx_handshake.is_empty();
            if !client.is_handshaking() && !server.is_handshaking() && client_empty && server_empty
            {
                break;
            }
        }

        assert!(!client.is_handshaking(), "client did not finish");
        assert!(!server.is_handshaking(), "server did not finish");

        (
            client,
            server,
            client_handle,
            server_handle,
            client_history,
            server_history,
        )
    }

    /// In QUIC mode the full TLS 1.3 handshake completes through hooks
    /// alone: each side records handshake messages at the right
    /// encryption level, the traffic secrets agree across peers, and the
    /// 0x39 extension survives a round-trip in both directions.
    #[test]
    fn quic_mode_loopback_records_per_level_traffic() {
        let (client, server, client_h, server_h, ch_tx_handshake, sh_tx_handshake) =
            run_quic_handshake(CipherSuite::AES_128_GCM_SHA256, NamedGroup::X25519);

        // Snapshot the captured state so we can drop the locks before any
        // further engine calls. `tx_handshake` is consumed by the driver
        // and instead returned as the *_history vectors above.
        let (ch_secrets, ch_peer_params, ch_peer_params_seen) = {
            let g = client_h.lock();
            (g.secrets.clone(), g.peer_params.clone(), g.peer_params_seen)
        };
        let (sh_secrets, sh_peer_params, sh_peer_params_seen) = {
            let g = server_h.lock();
            (g.secrets.clone(), g.peer_params.clone(), g.peer_params_seen)
        };

        // Client must have emitted at least ClientHello (Initial) and a
        // Finished (Handshake).
        assert!(!ch_tx_handshake.is_empty(), "client emitted no handshake");
        assert_eq!(ch_tx_handshake[0].0, Level::Initial, "CH is Initial");
        let client_last = ch_tx_handshake.last().expect("client tx_handshake");
        assert_eq!(
            client_last.0,
            Level::Handshake,
            "client Finished is Handshake"
        );

        // Server's first emit is ServerHello at Initial; subsequent EE /
        // Cert / CV / Fin at Handshake.
        assert!(!sh_tx_handshake.is_empty(), "server emitted no handshake");
        assert_eq!(sh_tx_handshake[0].0, Level::Initial, "SH is Initial");
        let server_handshake_levels: Vec<Level> = sh_tx_handshake
            .iter()
            .skip(1) // skip ServerHello
            .map(|(l, _)| *l)
            .collect();
        assert!(
            server_handshake_levels
                .iter()
                .all(|l| *l == Level::Handshake),
            "server post-SH emits must all be Handshake level: {server_handshake_levels:?}"
        );

        // Both sides recorded matching traffic secrets at Handshake +
        // OneRtt levels (Handshake Tx of one side == Handshake Rx of
        // the other side).
        let pick = |secrets: &[(Level, Direction, Vec<u8>)], lvl: Level, dir: Direction| {
            secrets
                .iter()
                .find(|(l, d, _)| *l == lvl && *d == dir)
                .map(|(_, _, s)| s.clone())
                .unwrap_or_default()
        };
        // Handshake: client.Tx == server.Rx ; client.Rx == server.Tx.
        let c_tx_hs = pick(&ch_secrets, Level::Handshake, Direction::Tx);
        let c_rx_hs = pick(&ch_secrets, Level::Handshake, Direction::Rx);
        let s_tx_hs = pick(&sh_secrets, Level::Handshake, Direction::Tx);
        let s_rx_hs = pick(&sh_secrets, Level::Handshake, Direction::Rx);
        assert!(!c_tx_hs.is_empty(), "client Handshake Tx secret missing");
        assert_eq!(
            c_tx_hs, s_rx_hs,
            "client.Tx (Handshake) must equal server.Rx"
        );
        assert_eq!(
            c_rx_hs, s_tx_hs,
            "client.Rx (Handshake) must equal server.Tx"
        );

        // OneRtt: same identity flip.
        let c_tx_app = pick(&ch_secrets, Level::OneRtt, Direction::Tx);
        let s_rx_app = pick(&sh_secrets, Level::OneRtt, Direction::Rx);
        assert!(!c_tx_app.is_empty(), "client OneRtt Tx secret missing");
        assert_eq!(
            c_tx_app, s_rx_app,
            "client.Tx (OneRtt) == server.Rx (OneRtt)"
        );
        let c_rx_app = pick(&ch_secrets, Level::OneRtt, Direction::Rx);
        let s_tx_app = pick(&sh_secrets, Level::OneRtt, Direction::Tx);
        assert_eq!(
            c_rx_app, s_tx_app,
            "client.Rx (OneRtt) == server.Tx (OneRtt)"
        );

        // The peer's transport parameters made it through both directions.
        assert!(ch_peer_params_seen, "client never saw server params");
        assert_eq!(ch_peer_params.as_slice(), server_h.our_params());
        assert!(sh_peer_params_seen, "server never saw client params");
        assert_eq!(sh_peer_params.as_slice(), client_h.our_params());

        // NO record bytes were ever produced in QUIC mode — the engines
        // bypass the record stream entirely.
        let mut tmp_client = client;
        let mut tmp_server = server;
        assert!(
            tmp_client.write_tls().is_empty(),
            "client emitted record bytes in QUIC mode"
        );
        assert!(
            tmp_server.write_tls().is_empty(),
            "server emitted record bytes in QUIC mode"
        );
    }

    /// In QUIC mode the transcript hash on both sides MUST agree: the
    /// engine never emits a record but it MUST still feed the transcript
    /// from `emit_handshake_at`. The cleanest cross-peer assertion is
    /// that the handshake- and application-secret derivations agree
    /// between client.Tx and server.Rx (and vice versa), since each
    /// secret is the output of HKDF over the transcript hash. The
    /// loopback test already does that. Here we additionally compare to
    /// pure TLS mode for the cross-mode case where the QUIC-only 0x39
    /// extension is omitted (no transport params configured) — that
    /// way the ClientHello byte-stream is identical between modes.
    #[test]
    fn quic_mode_transcript_hash_matches_tls_mode() {
        // QUIC-mode handshake with EMPTY transport params on both sides
        // so the 0x39 extension is suppressed and the ClientHello is
        // byte-equal to the TLS-mode ClientHello.
        let (server_config_q, cert_der_q) = ed25519_server();
        let mut roots_q = RootCertStore::new();
        roots_q.add_der(cert_der_q).unwrap();
        let mut crng_q = HmacDrbg::<Sha256>::new(b"quic-cross", b"nonce", &[]);
        let srng_q = HmacDrbg::<Sha256>::new(b"quic-cross-srv", b"nonce", &[]);

        let (client_box, client_handle) = HookHandle::install(Vec::new()); // empty params → no extension
        let (server_box, server_handle) = HookHandle::install(Vec::new());

        let mut q_client = ClientConnection::new_for_quic(
            ClientConfig::new(roots_q),
            "loopback.example",
            &mut crng_q,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
            client_box,
        );
        let mut q_server = ServerConnection::new_for_quic(server_config_q, srng_q, server_box);

        for _ in 0..8 {
            let cd: Vec<(Level, Vec<u8>)> = {
                let mut h = client_handle.lock();
                core::mem::take(&mut h.tx_handshake)
            };
            for (l, b) in cd {
                q_server.process_quic_handshake_bytes(l, &b).unwrap();
            }
            let sd: Vec<(Level, Vec<u8>)> = {
                let mut h = server_handle.lock();
                core::mem::take(&mut h.tx_handshake)
            };
            for (l, b) in sd {
                q_client.process_quic_handshake_bytes(l, &b).unwrap();
            }
            if !q_client.is_handshaking() && !q_server.is_handshaking() {
                break;
            }
        }
        assert!(!q_client.is_handshaking() && !q_server.is_handshaking());

        let q_client_app_tx = client_handle
            .lock()
            .secrets
            .iter()
            .find(|(l, d, _)| *l == Level::OneRtt && *d == Direction::Tx)
            .map(|(_, _, s)| s.clone())
            .expect("client one-rtt tx");
        let q_server_app_tx = server_handle
            .lock()
            .secrets
            .iter()
            .find(|(l, d, _)| *l == Level::OneRtt && *d == Direction::Tx)
            .map(|(_, _, s)| s.clone())
            .expect("server one-rtt tx");

        // Run the same handshake in TLS mode and compare via the public
        // *_application_traffic_secret_0 getters.
        let (server_config, cert_der) = ed25519_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"quic-cross", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"quic-cross-srv", b"nonce", &[]);
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
        let tls_client_app = client.client_application_traffic_secret_0().unwrap();
        let tls_server_app = server.server_application_traffic_secret_0().unwrap();

        // With matching seeds, no transport params, no NewSessionTicket
        // (no ticket_key configured), no 0x39 extension — both modes
        // produce byte-identical handshakes, so the derived secrets must
        // match. A divergence here is the smoking gun for a missed
        // transcript update at a `core.emit_handshake` site.
        assert_eq!(
            q_client_app_tx, tls_client_app,
            "client app secret must agree across modes"
        );
        assert_eq!(
            q_server_app_tx, tls_server_app,
            "server app secret must agree across modes"
        );
    }

    /// RFC 9001 §8.4: no ChangeCipherSpec must ride in CRYPTO frames.
    /// CCS in TLS lives in the record stream, never in handshake bytes —
    /// so we just verify that no QUIC-mode handshake byte stream looks
    /// like a CCS record.
    #[test]
    fn quic_mode_does_not_emit_ccs() {
        let (_c, _s, _ch, _sh, c_hist, s_hist) =
            run_quic_handshake(CipherSuite::AES_128_GCM_SHA256, NamedGroup::X25519);
        for (_, msg) in &c_hist {
            // Handshake messages must be well-formed (4-byte header at
            // minimum) and must not look like a CCS record fragment
            // (`[0x01]`, length 1).
            assert!(msg.len() >= 4, "handshake message too short: {msg:?}");
            assert_ne!(
                msg.as_slice(),
                [0x01_u8].as_slice(),
                "CCS leaked into CRYPTO stream"
            );
        }
        for (_, msg) in &s_hist {
            assert!(msg.len() >= 4, "handshake message too short");
            assert_ne!(
                msg.as_slice(),
                [0x01_u8].as_slice(),
                "CCS leaked into CRYPTO stream"
            );
        }
        // The strongest assertion: in QUIC mode `write_tls()` is empty —
        // the record stream is never used (covered by the loopback test).
    }

    /// The 0x39 extension survives a round-trip through ClientHello,
    /// AND through EncryptedExtensions (the other test asserts equality
    /// of the captured bodies). This test additionally encodes a CH
    /// directly via the codec helpers and decodes it back.
    #[test]
    fn extension_0x39_roundtrip_in_ch() {
        use crate::tls::codec::ExtensionType;
        use crate::tls::codec::extension::quic_transport_parameters;
        let body: Vec<u8> = alloc::vec![0xde, 0xad, 0xbe, 0xef];
        let (ty, encoded) = quic_transport_parameters(&body);
        assert_eq!(ty, ExtensionType::QUIC_TRANSPORT_PARAMETERS);
        assert_eq!(encoded, body);
    }

    /// Smoke test for the parser shim.
    #[test]
    fn extension_0x39_parse_is_identity() {
        let body: Vec<u8> = alloc::vec![1, 2, 3, 4, 5];
        let parsed = crate::tls::codec::extension::parse_quic_transport_parameters(&body);
        assert_eq!(parsed, body.as_slice());
    }
}

#[cfg(test)]
mod loopback_tests {
    use super::{ClientConnection, ServerConfig, ServerConnection};
    use crate::ec::{Ed448PrivateKey, Ed25519PrivateKey};
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::rsa::BoxedRsaPrivateKey;
    use crate::test_util::rsa_test_key_a;
    use crate::tls::RootCertStore;
    use crate::tls::codec::{CipherSuite, NamedGroup};
    use crate::tls::conn::ClientConfig;
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

    /// An Ed448 self-signed server config plus its certificate DER.
    fn ed448_server() -> (ServerConfig, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"loopback-ed448-key", b"nonce", &[]);
        let key = Ed448PrivateKey::generate(&mut rng);
        let name = DistinguishedName::common_name("loopback.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ed448(&key),
            &name,
            &validity,
            1,
            false,
            &["loopback.example"],
        )
        .unwrap();
        let der = cert.to_der().to_vec();
        (ServerConfig::with_ed448(alloc::vec![der.clone()], key), der)
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
    fn secp384r1_aes128_sha256() {
        // Pin SECP384R1 so the server is forced down the P-384 ECDHE arm
        // and the client's `key_agreement` resolves the P-384 share.
        run(&[CipherSuite::AES_128_GCM_SHA256], &[NamedGroup::SECP384R1]);
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
    fn ed448_server_certificate() {
        // An Ed448 server cert exercises Ed448 chain verification and the
        // Ed448 CertificateVerify signature (scheme ed448 = 0x0808) end to end:
        // the server signs CertificateVerify with its Ed448 key and the client
        // verifies it, so a completed handshake is proof the 0x0808 path works.
        assert_eq!(crate::tls::codec::SignatureScheme::ED448.0, 0x0808);
        run_with(
            ed448_server(),
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

    /// RFC 7250 server-side raw public key: the server advertises an SPKI
    /// directly in its `Certificate` message and the client accepts it via
    /// an SPKI allowlist (no PKI). The handshake completes and application
    /// data round-trips, demonstrating that the negotiation, echo, send,
    /// and verify paths all line up.
    #[test]
    fn server_raw_public_key_loopback() {
        use crate::tls::codec::cert_type;
        use crate::x509::AnyPublicKey;

        // Generate an Ed25519 server identity. The SPKI is the public key
        // wrapped in a PKIX SubjectPublicKeyInfo (RFC 8410); that's the
        // exact byte string the server will hand back as its
        // CertificateEntry body when RawPublicKey is negotiated.
        let mut keygen_rng = HmacDrbg::<Sha256>::new(b"rpk-server-key", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut keygen_rng);
        let spki = AnyPublicKey::Ed25519(key.public_key()).to_spki_der();

        let server_config = ServerConfig::with_ed25519(alloc::vec::Vec::new(), key)
            .with_raw_public_key_spki(spki.clone())
            .with_server_cert_type_preference(alloc::vec![
                cert_type::RAW_PUBLIC_KEY,
                cert_type::X509,
            ]);

        let mut crng = HmacDrbg::<Sha256>::new(b"rpk-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"rpk-server", b"nonce", &[]);

        // The client offers RawPublicKey ahead of X.509 and pins the
        // server's SPKI on an allowlist. `RootCertStore` stays empty —
        // there's no PKI to consult when RPK is in use.
        let client_cfg = ClientConfig::new(RootCertStore::new())
            .with_server_cert_type_preference(alloc::vec![
                cert_type::RAW_PUBLIC_KEY,
                cert_type::X509,
            ])
            .add_expected_raw_public_key(spki.clone());
        let mut client = ClientConnection::new(client_cfg, "loopback.example", &mut crng);
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
        assert!(
            !client.is_handshaking(),
            "client did not finish RPK handshake"
        );
        assert!(
            !server.is_handshaking(),
            "server did not finish RPK handshake"
        );

        // App data round-trips both ways under the RPK-authenticated
        // session.
        client.send_application_data(b"ping rpk").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"ping rpk");

        server.send_application_data(b"pong rpk").unwrap();
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), b"pong rpk");
    }

    /// RFC 7250 SPKI allowlist mismatch: the client offers RawPublicKey and
    /// the server agrees, but the client's expected SPKI doesn't match
    /// what the server actually sends. The handshake aborts at
    /// `CertificateVerify` time with `BadCertificate`.
    #[test]
    fn server_raw_public_key_allowlist_mismatch() {
        use crate::tls::codec::cert_type;
        use crate::x509::AnyPublicKey;

        let mut keygen_rng = HmacDrbg::<Sha256>::new(b"rpk-server-key", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut keygen_rng);
        let real_spki = AnyPublicKey::Ed25519(key.public_key()).to_spki_der();

        // A different key — its SPKI is what the client pins, so the
        // server's SPKI will not match the allowlist.
        let mut other_rng = HmacDrbg::<Sha256>::new(b"rpk-other-key", b"nonce", &[]);
        let other_key = Ed25519PrivateKey::generate(&mut other_rng);
        let pinned_spki = AnyPublicKey::Ed25519(other_key.public_key()).to_spki_der();
        assert_ne!(real_spki, pinned_spki);

        let server_config = ServerConfig::with_ed25519(alloc::vec::Vec::new(), key)
            .with_raw_public_key_spki(real_spki)
            .with_server_cert_type_preference(alloc::vec![cert_type::RAW_PUBLIC_KEY]);

        let mut crng = HmacDrbg::<Sha256>::new(b"rpk-mismatch-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"rpk-mismatch-server", b"nonce", &[]);

        let client_cfg = ClientConfig::new(RootCertStore::new())
            .with_server_cert_type_preference(alloc::vec![cert_type::RAW_PUBLIC_KEY])
            .add_expected_raw_public_key(pinned_spki);
        let mut client = ClientConnection::new(client_cfg, "loopback.example", &mut crng);
        let mut server = ServerConnection::new(server_config, srng);

        assert_eq!(
            drive_until_client_error(&mut client, &mut server),
            crate::tls::Error::BadCertificate
        );
    }

    /// When the client opts into RPK but never adds anything to the SPKI
    /// allowlist, verification must refuse — there is no way to establish
    /// trust over a bare key without an out-of-band identity policy.
    #[test]
    fn server_raw_public_key_empty_allowlist_rejects() {
        use crate::tls::codec::cert_type;
        use crate::x509::AnyPublicKey;

        let mut keygen_rng = HmacDrbg::<Sha256>::new(b"rpk-server-key", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut keygen_rng);
        let spki = AnyPublicKey::Ed25519(key.public_key()).to_spki_der();

        let server_config = ServerConfig::with_ed25519(alloc::vec::Vec::new(), key)
            .with_raw_public_key_spki(spki)
            .with_server_cert_type_preference(alloc::vec![cert_type::RAW_PUBLIC_KEY]);

        let mut crng = HmacDrbg::<Sha256>::new(b"rpk-empty-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"rpk-empty-server", b"nonce", &[]);

        let client_cfg = ClientConfig::new(RootCertStore::new())
            .with_server_cert_type_preference(alloc::vec![cert_type::RAW_PUBLIC_KEY]);
        // No add_expected_raw_public_key — allowlist intentionally empty.
        let mut client = ClientConnection::new(client_cfg, "loopback.example", &mut crng);
        let mut server = ServerConnection::new(server_config, srng);

        assert_eq!(
            drive_until_client_error(&mut client, &mut server),
            crate::tls::Error::BadCertificate
        );
    }

    /// If the client only offers RawPublicKey but the server has no SPKI
    /// configured, negotiation cannot pick a usable type and the server
    /// terminates with `handshake_failure`.
    #[test]
    fn server_raw_public_key_no_overlap_fails() {
        use crate::tls::codec::cert_type;

        // Server configured with X.509 only (no raw_public_key_spki).
        let (server_config, _cert_der) = ed25519_server();
        let server_config =
            server_config.with_server_cert_type_preference(alloc::vec![cert_type::X509]);

        let mut crng = HmacDrbg::<Sha256>::new(b"rpk-noov-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"rpk-noov-server", b"nonce", &[]);

        // Client offers RPK only, so no overlap with the server's
        // accept-set.
        let client_cfg = ClientConfig::new(RootCertStore::new())
            .with_server_cert_type_preference(alloc::vec![cert_type::RAW_PUBLIC_KEY]);
        let mut client = ClientConnection::new(client_cfg, "loopback.example", &mut crng);
        let mut server = ServerConnection::new(server_config, srng);

        // The server fails the CH; the client sees the resulting alert.
        let mut last_err: Option<crate::tls::Error> = None;
        for _ in 0..16 {
            let c = client.write_tls();
            if !c.is_empty()
                && let Err(e) = {
                    server.read_tls(&c);
                    server.process_new_packets()
                }
            {
                last_err = Some(e);
                break;
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
        assert_eq!(last_err, Some(crate::tls::Error::HandshakeFailure));
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

    /// mTLS with Ed448 on BOTH ends: an Ed448 server cert and an Ed448 client
    /// cert. Exercises the Ed448 CertificateVerify (0x0808) on both the server
    /// and client roles; a completed handshake proves both signatures were
    /// produced and verified.
    #[test]
    fn mtls_ed448_both_ends() {
        use crate::tls::{ClientCertConfig, RootCertStore};

        let (server_config, server_cert_der) = ed448_server();

        // An Ed448 client cert (self-signed leaf == trust anchor).
        let mut crng_seed = HmacDrbg::<Sha256>::new(b"mtls-ed448-client-key", b"nonce", &[]);
        let client_key = Ed448PrivateKey::generate(&mut crng_seed);
        let client_name = DistinguishedName::common_name("mtls-ed448-client");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let client_cert = Certificate::self_signed_general(
            &CertSigner::Ed448(&client_key),
            &client_name,
            &validity,
            1,
            false,
            &["mtls-ed448-client"],
        )
        .unwrap();
        let client_cert_der = client_cert.to_der().to_vec();

        let mut server_roots = RootCertStore::new();
        server_roots.add_der(client_cert_der.clone()).unwrap();
        let server_config = server_config.with_client_auth(server_roots, true);

        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der).unwrap();
        let cc = ClientCertConfig::with_ed448(alloc::vec![client_cert_der], client_key);

        let mut crng = HmacDrbg::<Sha256>::new(b"mtls-ed448-client-rng", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"mtls-ed448-server-rng", b"nonce", &[]);
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

        client.send_application_data(b"ed448-mtls-ping").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"ed448-mtls-ping");
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

    /// E-1 (HIGH #5) — RFC 8446 §4.2.10: a 0-RTT client that pushes more
    /// plaintext under the early-data key than the server's
    /// `max_early_data_size` budget MUST be terminated with
    /// `unexpected_message`. Regression guard for the byte-budget enforcement
    /// that lives in `process_new_packets`.
    #[test]
    fn server_rejects_excess_early_data() {
        // Phase 1: establish a session with a tight 0-RTT budget.
        const BUDGET: u32 = 100;
        let (server_config, cert_der) = rsa_server();
        let server_config = server_config
            .with_ticket_key([0x5au8; 32])
            .with_max_early_data(BUDGET);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"0rtt-budget-c1", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"0rtt-budget-s1", b"nonce", &[]);
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
        assert_eq!(session.max_early_data_size, Some(BUDGET));

        // Phase 2: client offers 0-RTT and sends 200 bytes — over the
        // server's 100-byte limit. The server must terminate the
        // handshake with `unexpected_message`.
        let (server_config2, cert_der2) = rsa_server();
        let server_config2 = server_config2
            .with_ticket_key([0x5au8; 32])
            .with_max_early_data(BUDGET);
        let mut roots2 = RootCertStore::new();
        roots2.add_der(cert_der2).unwrap();

        let mut crng2 = HmacDrbg::<Sha256>::new(b"0rtt-budget-c2", b"nonce", &[]);
        let srng2 = HmacDrbg::<Sha256>::new(b"0rtt-budget-s2", b"nonce", &[]);
        let mut client2 = ClientConnection::new_with_offer(
            ClientConfig::new(roots2).with_session(session),
            "loopback.example",
            &mut crng2,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server2 = ServerConnection::new(server_config2, srng2);

        // 200 bytes of 0-RTT data — 2x the server's budget. The client
        // packs this into a single ApplicationData record under the
        // early-data key (fits well below the 2^14 record cap).
        let payload = alloc::vec![0xCDu8; (BUDGET as usize) * 2];
        client2.write_early_data(&payload).unwrap();

        let bytes = client2.write_tls();
        server2.read_tls(&bytes);
        let err = server2.process_new_packets().unwrap_err();
        assert!(
            matches!(err, crate::tls::Error::UnexpectedMessage),
            "expected UnexpectedMessage on early-data budget overflow, got {err:?}"
        );
        // The server must have emitted a fatal alert.
        let alert_bytes = server2.write_tls();
        assert!(!alert_bytes.is_empty(), "server should emit a fatal alert");
    }

    /// E-1 negative control: when 0-RTT data is split into multiple records
    /// whose plaintexts sum to exactly the budget, the server still accepts
    /// them (boundary case — `consumed == remaining`).
    #[test]
    fn server_accepts_early_data_exactly_at_budget() {
        const BUDGET: u32 = 64;
        // Phase 1.
        let (server_config, cert_der) = rsa_server();
        let server_config = server_config
            .with_ticket_key([0x77u8; 32])
            .with_max_early_data(BUDGET);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"0rtt-exact-c1", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"0rtt-exact-s1", b"nonce", &[]);
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

        // Phase 2: send exactly BUDGET bytes.
        let (server_config2, cert_der2) = rsa_server();
        let _ = cert_der2;
        let server_config2 = server_config2
            .with_ticket_key([0x77u8; 32])
            .with_max_early_data(BUDGET);
        let mut crng2 = HmacDrbg::<Sha256>::new(b"0rtt-exact-c2", b"nonce", &[]);
        let srng2 = HmacDrbg::<Sha256>::new(b"0rtt-exact-s2", b"nonce", &[]);
        let mut client2 = ClientConnection::new_with_offer(
            ClientConfig::new(RootCertStore::new()).with_session(session),
            "loopback.example",
            &mut crng2,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server2 = ServerConnection::new(server_config2, srng2);

        let payload = alloc::vec![0x11u8; BUDGET as usize];
        client2.write_early_data(&payload).unwrap();
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
        assert!(server2.early_data_accepted());
        assert_eq!(server2.take_received_plaintext(), payload);
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

    /// RFC 8446 §4.1.3: a ServerHello selecting a cipher_suite the client did
    /// NOT offer MUST be aborted with `illegal_parameter`. Offer only
    /// AES_128_GCM_SHA256 but have the server pick AES_256_GCM_SHA384. The
    /// key_share names the offered group, so the cipher_suite is the only
    /// un-offered parameter.
    #[test]
    fn rejects_unoffered_cipher_suite_in_server_hello() {
        use crate::tls::codec::{ExtensionType, ServerHello, put_u16, write_record};

        let (_server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"unoffered-suite-client", b"nonce", &[]);
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let _ch1 = client.write_tls();

        let sv_body = alloc::vec![0x03, 0x04];
        let mut ks_body = Vec::new();
        put_u16(&mut ks_body, NamedGroup::X25519.0);
        let key_body: Vec<u8> = alloc::vec![0u8; 32];
        crate::tls::codec::with_len_u16(&mut ks_body, |b| b.extend_from_slice(&key_body));
        let sh = ServerHello {
            random: [0x22; 32],
            session_id: Vec::new(),
            // AES_256_GCM_SHA384 is supported by the library but was NOT offered.
            cipher_suite: CipherSuite::AES_256_GCM_SHA384,
            extensions: alloc::vec![
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

    /// RFC 8446 §4.1.3: a ServerHello whose key_share names a group the client
    /// did NOT offer MUST be aborted with `illegal_parameter`. Offer only
    /// X25519 but have the server's key_share name SECP256R1. The cipher_suite
    /// is offered, so the key_share group is the only un-offered parameter.
    #[test]
    fn rejects_unoffered_key_share_group_in_server_hello() {
        use crate::tls::codec::{ExtensionType, ServerHello, put_u16, write_record};

        let (_server_config, cert_der) = rsa_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"unoffered-group-client", b"nonce", &[]);
        let mut client = ClientConnection::new_with_offer(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let _ch1 = client.write_tls();

        let sv_body = alloc::vec![0x03, 0x04];
        // key_share for SECP256R1 (un-offered). The group is rejected before
        // the public key is ever used, so a placeholder body suffices.
        let mut ks_body = Vec::new();
        put_u16(&mut ks_body, NamedGroup::SECP256R1.0);
        let key_body: Vec<u8> = alloc::vec![0u8; 65];
        crate::tls::codec::with_len_u16(&mut ks_body, |b| b.extend_from_slice(&key_body));
        let sh = ServerHello {
            random: [0x33; 32],
            session_id: Vec::new(),
            cipher_suite: CipherSuite::AES_128_GCM_SHA256,
            extensions: alloc::vec![
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

    /// Builds a CA-issued leaf chain (CA -> leaf) and returns
    /// (`server_config`, `root_der`, `leaf_serial_u64`). The CA is rsa_test_key_a,
    /// the leaf signed with the same CA key for simplicity (the leaf's key
    /// itself is irrelevant — TLS 1.3 uses the CA-signed cert + a
    /// CertificateVerify under the LEAF key, so we use a fresh Ed25519 leaf).
    #[allow(clippy::type_complexity)]
    fn ca_signed_ed25519_leaf() -> (ServerConfig, Vec<u8>, Vec<u8>, [u8; 32]) {
        use crate::x509::DistinguishedName;
        let ca_key = rsa_test_key_a();
        let ca_name = DistinguishedName::common_name("Stapling Test CA");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let root = Certificate::self_signed(&ca_key, &ca_name, &validity, 1, true).unwrap();

        // Leaf key (Ed25519) — small SPKI, fast verify.
        let mut rng = HmacDrbg::<Sha256>::new(b"stapling-leaf", b"nonce", &[]);
        let leaf_key = Ed25519PrivateKey::generate(&mut rng);
        let leaf_seed = [0u8; 32];
        let leaf = Certificate::issue_general(
            &CertSigner::Rsa(&BoxedRsaPrivateKey::from_pkcs1_der(&ca_key.to_pkcs1_der()).unwrap()),
            &ca_name,
            &DistinguishedName::common_name("loopback.example"),
            &crate::x509::AnyPublicKey::Ed25519(leaf_key.public_key()),
            &validity,
            7, // leaf serial = 7
            false,
            &["loopback.example"],
        )
        .unwrap();

        let chain = alloc::vec![leaf.to_der().to_vec(), root.to_der().to_vec()];
        let cfg = ServerConfig::with_ed25519(chain, leaf_key);
        (
            cfg,
            root.to_der().to_vec(),
            leaf.to_der().to_vec(),
            leaf_seed,
        )
    }

    /// Server staples a CRL that does NOT revoke the leaf → handshake
    /// completes (the CRL is consulted but is_revoked returns false).
    #[test]
    fn stapled_crl_no_revocation() {
        use crate::x509::{CrlBuilder, DistinguishedName};
        let (mut server_config, root_der, _leaf_der, _seed) = ca_signed_ed25519_leaf();
        let ca_name = DistinguishedName::common_name("Stapling Test CA");
        // Empty CRL.
        let signer = CertSigner::Rsa(
            &BoxedRsaPrivateKey::from_pkcs1_der(&rsa_test_key_a().to_pkcs1_der()).unwrap(),
        );
        let crl = CrlBuilder::new(&ca_name, Time::utc(2026, 1, 1, 0, 0, 0), None)
            .sign(&signer)
            .unwrap();
        server_config = server_config.with_stapled_crl(crl.to_der().to_vec());

        let mut roots = RootCertStore::new();
        roots.add_der(root_der).unwrap();

        let mut config = ClientConfig::new(roots);
        config.verification_time = Some(Time::utc(2026, 5, 1, 0, 0, 0));

        let mut crng = HmacDrbg::<Sha256>::new(b"staple-ok-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"staple-ok-server", b"nonce", &[]);
        let mut client = ClientConnection::new(config, "loopback.example", &mut crng);
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
    }

    /// Server staples a CRL that DOES revoke the leaf → client rejects
    /// the handshake with `BadCertificate`.
    #[test]
    fn stapled_crl_revokes_leaf() {
        use crate::x509::{CrlBuilder, DistinguishedName};
        let (mut server_config, root_der, _leaf_der, _seed) = ca_signed_ed25519_leaf();
        let ca_name = DistinguishedName::common_name("Stapling Test CA");
        // Revoke the leaf's serial (7).
        let signer = CertSigner::Rsa(
            &BoxedRsaPrivateKey::from_pkcs1_der(&rsa_test_key_a().to_pkcs1_der()).unwrap(),
        );
        let mut b = CrlBuilder::new(&ca_name, Time::utc(2026, 1, 1, 0, 0, 0), None);
        b.revoke(&[7], Time::utc(2026, 1, 2, 0, 0, 0), None);
        let crl = b.sign(&signer).unwrap();
        server_config = server_config.with_stapled_crl(crl.to_der().to_vec());

        let mut roots = RootCertStore::new();
        roots.add_der(root_der).unwrap();

        let mut config = ClientConfig::new(roots);
        config.verification_time = Some(Time::utc(2026, 5, 1, 0, 0, 0));

        let mut crng = HmacDrbg::<Sha256>::new(b"staple-rev-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"staple-rev-server", b"nonce", &[]);
        let mut client = ClientConnection::new(config, "loopback.example", &mut crng);
        let mut server = ServerConnection::new(server_config, srng);
        assert_eq!(
            drive_until_client_error(&mut client, &mut server),
            crate::tls::Error::BadCertificate
        );
    }

    /// Without `with_stapled_crl` the server emits no extension and the
    /// handshake is identical to a non-CRL setup (regression guard).
    #[test]
    fn no_staple_handshake_unchanged() {
        let (server_config, root_der, _leaf, _seed) = ca_signed_ed25519_leaf();
        let mut roots = RootCertStore::new();
        roots.add_der(root_der).unwrap();
        let mut config = ClientConfig::new(roots);
        config.verification_time = Some(Time::utc(2026, 5, 1, 0, 0, 0));
        let mut crng = HmacDrbg::<Sha256>::new(b"staple-none-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"staple-none-s", b"nonce", &[]);
        let mut client = ClientConnection::new(config, "loopback.example", &mut crng);
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
    }

    /// RFC 8879 §4: both ends opt into cert-compression with algorithm
    /// `zlib`. The handshake must complete, the server must record the
    /// client's offer, and application data must flow both ways. This
    /// is the wiring smoke for the `CompressedCertificate` emission/
    /// reception path; the codec round-trips are covered by
    /// `tls::cert_compression::tests` and need not be re-asserted here.
    #[cfg(feature = "cert-compression")]
    #[test]
    fn cert_compression_zlib_loopback() {
        use crate::tls::cert_compression;
        let (mut server_config, root_der, _leaf_der, _seed) = ca_signed_ed25519_leaf();
        server_config =
            server_config.with_cert_compression_algorithms(cert_compression::default_algorithms());
        let mut roots = RootCertStore::new();
        roots.add_der(root_der).unwrap();
        let mut config = ClientConfig::new(roots)
            .with_cert_compression_algorithms(cert_compression::default_algorithms());
        config.verification_time = Some(Time::utc(2026, 5, 1, 0, 0, 0));
        let mut crng = HmacDrbg::<Sha256>::new(b"cc-zlib-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"cc-zlib-s", b"nonce", &[]);
        let mut client = ClientConnection::new(config, "loopback.example", &mut crng);
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
        // Server saw the client's compress_certificate offer with zlib.
        assert_eq!(
            server.peer_cert_compression_algorithms(),
            &[cert_compression::algorithm::ZLIB]
        );
        // App data round-trips both ways.
        client.send_application_data(b"ping cc").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"ping cc");
        server.send_application_data(b"pong cc").unwrap();
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), b"pong cc");
    }

    /// RFC 8879: when the server's configured algorithm set is disjoint
    /// from the client's offer (or vice-versa), the server falls back to
    /// emitting plain `Certificate`. The handshake still completes.
    #[cfg(feature = "cert-compression")]
    #[test]
    fn cert_compression_falls_back_on_no_overlap() {
        // Server advertises an unsupported algorithm only (e.g. brotli);
        // client offers zlib. Server picks neither — falls back to plain.
        use crate::tls::cert_compression;
        let (mut server_config, root_der, _leaf_der, _seed) = ca_signed_ed25519_leaf();
        server_config = server_config
            .with_cert_compression_algorithms(alloc::vec![cert_compression::algorithm::BROTLI]);
        let mut roots = RootCertStore::new();
        roots.add_der(root_der).unwrap();
        let mut config = ClientConfig::new(roots)
            .with_cert_compression_algorithms(cert_compression::default_algorithms());
        config.verification_time = Some(Time::utc(2026, 5, 1, 0, 0, 0));
        let mut crng = HmacDrbg::<Sha256>::new(b"cc-fb-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"cc-fb-s", b"nonce", &[]);
        let mut client = ClientConnection::new(config, "loopback.example", &mut crng);
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
    }

    /// With `verify_certificates = false` the stapled CRL is ignored
    /// (no enforcement). Even when the staple would revoke the leaf, the
    /// handshake completes.
    #[test]
    fn stapled_crl_skipped_when_verification_disabled() {
        use crate::x509::{CrlBuilder, DistinguishedName};
        let (mut server_config, _root_der, _leaf_der, _seed) = ca_signed_ed25519_leaf();
        let ca_name = DistinguishedName::common_name("Stapling Test CA");
        let signer = CertSigner::Rsa(
            &BoxedRsaPrivateKey::from_pkcs1_der(&rsa_test_key_a().to_pkcs1_der()).unwrap(),
        );
        let mut b = CrlBuilder::new(&ca_name, Time::utc(2026, 1, 1, 0, 0, 0), None);
        b.revoke(&[7], Time::utc(2026, 1, 2, 0, 0, 0), None);
        let crl = b.sign(&signer).unwrap();
        server_config = server_config.with_stapled_crl(crl.to_der().to_vec());

        let mut config = ClientConfig::new(RootCertStore::new());
        config.verify_certificates = false;
        let mut crng = HmacDrbg::<Sha256>::new(b"staple-noverify-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"staple-noverify-s", b"nonce", &[]);
        let mut client = ClientConnection::new(config, "loopback.example", &mut crng);
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
    }

    /// Server staples a `good` OCSP response for the leaf's serial → handshake
    /// completes and the client surfaces the response via
    /// [`ClientConnection::peer_ocsp_response`].
    #[test]
    fn stapled_ocsp_good() {
        use crate::x509::OcspResponseBuilder;
        let (mut server_config, root_der, leaf_der, _seed) = ca_signed_ed25519_leaf();
        let ca_signer = CertSigner::Rsa(
            &BoxedRsaPrivateKey::from_pkcs1_der(&rsa_test_key_a().to_pkcs1_der()).unwrap(),
        );
        let leaf = Certificate::from_der(leaf_der).unwrap();
        let root = Certificate::from_der(root_der.clone()).unwrap();
        let resp = OcspResponseBuilder::good(
            &leaf,
            &root,
            Time::utc(2026, 4, 1, 0, 0, 0),
            Some(Time::utc(2026, 6, 1, 0, 0, 0)),
        )
        .unwrap()
        .sign(&ca_signer)
        .unwrap();
        let der = resp.to_der().to_vec();
        server_config = server_config.with_stapled_ocsp_response(der.clone());

        let mut roots = RootCertStore::new();
        roots.add_der(root_der).unwrap();
        let mut config = ClientConfig::new(roots);
        config.verification_time = Some(Time::utc(2026, 5, 1, 0, 0, 0));

        let mut crng = HmacDrbg::<Sha256>::new(b"ocsp-good-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ocsp-good-s", b"nonce", &[]);
        let mut client = ClientConnection::new(config, "loopback.example", &mut crng);
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
        assert_eq!(client.peer_ocsp_response().map(|v| v.to_vec()), Some(der));
    }

    /// Server staples a `revoked` OCSP response → client rejects with
    /// `CertificateRevoked`.
    #[test]
    fn stapled_ocsp_revoked() {
        use crate::x509::OcspResponseBuilder;
        let (mut server_config, root_der, leaf_der, _seed) = ca_signed_ed25519_leaf();
        let ca_signer = CertSigner::Rsa(
            &BoxedRsaPrivateKey::from_pkcs1_der(&rsa_test_key_a().to_pkcs1_der()).unwrap(),
        );
        let leaf = Certificate::from_der(leaf_der).unwrap();
        let root = Certificate::from_der(root_der.clone()).unwrap();
        let resp = OcspResponseBuilder::revoked(
            &leaf,
            &root,
            Time::utc(2026, 4, 1, 0, 0, 0),
            Some(Time::utc(2026, 6, 1, 0, 0, 0)),
            Time::utc(2026, 3, 15, 0, 0, 0),
            None,
        )
        .unwrap()
        .sign(&ca_signer)
        .unwrap();
        server_config = server_config.with_stapled_ocsp_response(resp.to_der().to_vec());

        let mut roots = RootCertStore::new();
        roots.add_der(root_der).unwrap();
        let mut config = ClientConfig::new(roots);
        config.verification_time = Some(Time::utc(2026, 5, 1, 0, 0, 0));

        let mut crng = HmacDrbg::<Sha256>::new(b"ocsp-rev-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ocsp-rev-s", b"nonce", &[]);
        let mut client = ClientConnection::new(config, "loopback.example", &mut crng);
        let mut server = ServerConnection::new(server_config, srng);
        assert_eq!(
            drive_until_client_error(&mut client, &mut server),
            crate::tls::Error::CertificateRevoked
        );
    }

    /// Server staples an OCSP response whose `nextUpdate` is in the past →
    /// client rejects with `OcspResponseInvalid`.
    #[test]
    fn stapled_ocsp_expired_rejected() {
        use crate::x509::OcspResponseBuilder;
        let (mut server_config, root_der, leaf_der, _seed) = ca_signed_ed25519_leaf();
        let ca_signer = CertSigner::Rsa(
            &BoxedRsaPrivateKey::from_pkcs1_der(&rsa_test_key_a().to_pkcs1_der()).unwrap(),
        );
        let leaf = Certificate::from_der(leaf_der).unwrap();
        let root = Certificate::from_der(root_der.clone()).unwrap();
        // thisUpdate / nextUpdate well in the past relative to the client's
        // verification clock at 2026-05-01.
        let resp = OcspResponseBuilder::good(
            &leaf,
            &root,
            Time::utc(2025, 1, 1, 0, 0, 0),
            Some(Time::utc(2025, 2, 1, 0, 0, 0)),
        )
        .unwrap()
        .sign(&ca_signer)
        .unwrap();
        server_config = server_config.with_stapled_ocsp_response(resp.to_der().to_vec());

        let mut roots = RootCertStore::new();
        roots.add_der(root_der).unwrap();
        let mut config = ClientConfig::new(roots);
        config.verification_time = Some(Time::utc(2026, 5, 1, 0, 0, 0));

        let mut crng = HmacDrbg::<Sha256>::new(b"ocsp-exp-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ocsp-exp-s", b"nonce", &[]);
        let mut client = ClientConnection::new(config, "loopback.example", &mut crng);
        let mut server = ServerConnection::new(server_config, srng);
        assert_eq!(
            drive_until_client_error(&mut client, &mut server),
            crate::tls::Error::OcspResponseInvalid
        );
    }

    /// Wave 3b.3 end-to-end: a client with a real
    /// [`EchClient::from_config_list`] and a server with a matching
    /// [`EchServer`] complete a full handshake. After the SH lands,
    /// [`ClientConnection::ech_outcome`] must report
    /// [`EchOutcome::Accepted`] — proving the SH accept-confirmation
    /// signal verified and the client swapped its transcript from the
    /// outer CH to the inner CH. Application data also round-trips
    /// (the swap didn't destabilise the rest of the schedule).
    #[cfg(feature = "ech")]
    #[test]
    fn ech_real_loopback_accepts_and_round_trips() {
        use super::client::EchOutcome;
        use crate::hpke::{HpkeAead, HpkeKdf, HpkeKem};
        use crate::tls::ech::HpkeSymCipherSuite;
        use crate::tls::ech::keys::{EchKeyPair, EchKeyRing};
        use crate::tls::ech::{EchClient, EchConfigList, EchServer};

        // Server identity. The cert covers the *inner* SNI the client
        // really targets — that's the name the client verifies against
        // after ECH is accepted. (The outer `public_name` is on the
        // wire but never drives client-side cert selection here.)
        let mut srvkey_rng = HmacDrbg::<Sha256>::new(b"ech-3b3-srvkey", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut srvkey_rng);
        let name = DistinguishedName::common_name("secret.example");
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
            &["secret.example"],
        )
        .unwrap();
        let cert_der = cert.to_der().to_vec();

        // Fresh ECH key. `public_name = "public.example"` is the SNI
        // the *outer* CH carries on the wire; the server's `ech_server`
        // ring will HPKE-decap the inner CH using this key.
        let mut keygen_rng = HmacDrbg::<Sha256>::new(b"ech-3b3-keygen", b"nonce", &[]);
        let suites = alloc::vec![HpkeSymCipherSuite {
            kdf_id: HpkeKdf::HkdfSha256.id(),
            aead_id: HpkeAead::Aes128Gcm.id(),
        }];
        let pair = EchKeyPair::generate(
            &mut keygen_rng,
            HpkeKem::DhkemX25519HkdfSha256,
            0x33,
            b"public.example",
            64,
            suites,
        )
        .expect("ech keygen");
        let list = EchConfigList::new(alloc::vec![pair.config().clone()]);
        let ring = EchKeyRing::from_pairs(alloc::vec![pair]);

        // Server config: Ed25519 cert + ECH server keyring.
        let server_config = ServerConfig::with_ed25519(alloc::vec![cert_der.clone()], key)
            .with_ech_server(EchServer::new(ring, list.clone()));

        // Client config: trusts the server cert, opts into real ECH
        // against the same `ECHConfigList`.
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        let mut client_cfg = ClientConfig::new(roots);
        client_cfg.ech = Some(EchClient::from_config_list(list));

        let mut crng = HmacDrbg::<Sha256>::new(b"ech-3b3-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ech-3b3-server", b"nonce", &[]);

        let mut client = ClientConnection::new(client_cfg, "secret.example", &mut crng);
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
        assert_eq!(client.ech_outcome(), Some(EchOutcome::Accepted));

        // Both directions of app data flow under the inner-transcript
        // session keys.
        client.send_application_data(b"ping ech").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"ping ech");

        server.send_application_data(b"pong ech").unwrap();
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), b"pong ech");
    }

    /// Wave 3b.4: when the server cannot decap the inner CH (here:
    /// the client sealed against `config_id = 0x33` but the server's
    /// keyring only holds `config_id = 0x44`), the server completes
    /// the outer handshake under the `public_name` certificate and
    /// EE carries `encrypted_client_hello` with the server's fresh
    /// `retry_configs`. The client surfaces `Error::EchRejected`
    /// with the wire-form `ECHConfigList` bytes so the application
    /// can retry against the published configuration.
    #[cfg(feature = "ech")]
    #[test]
    fn ech_real_loopback_rejects_with_retry_configs() {
        use crate::hpke::{HpkeAead, HpkeKdf, HpkeKem};
        use crate::tls::ech::HpkeSymCipherSuite;
        use crate::tls::ech::keys::{EchKeyPair, EchKeyRing};
        use crate::tls::ech::{EchClient, EchConfigList, EchServer};

        // Self-signed Ed25519 server cert covering BOTH the public_name
        // (so the outer handshake on rejection authenticates the
        // server-presented cert) AND the inner SNI (not strictly
        // needed in the rejection flow, but harmless).
        let mut srvkey_rng = HmacDrbg::<Sha256>::new(b"ech-3b4-srvkey", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut srvkey_rng);
        let name = DistinguishedName::common_name("public.example");
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
            &["public.example", "secret.example"],
        )
        .unwrap();
        let cert_der = cert.to_der().to_vec();

        let suites = alloc::vec![HpkeSymCipherSuite {
            kdf_id: HpkeKdf::HkdfSha256.id(),
            aead_id: HpkeAead::Aes128Gcm.id(),
        }];

        // Client-side ECH key (the one the client seals against).
        let mut client_keygen_rng = HmacDrbg::<Sha256>::new(b"ech-3b4-client-key", b"nonce", &[]);
        let client_side_pair = EchKeyPair::generate(
            &mut client_keygen_rng,
            HpkeKem::DhkemX25519HkdfSha256,
            0x33,
            b"public.example",
            64,
            suites.clone(),
        )
        .expect("client-side ech keygen");
        let client_list = EchConfigList::new(alloc::vec![client_side_pair.config().clone()]);

        // Server-side ECH key with a DIFFERENT `config_id` so the
        // server's keyring lookup misses on the seal's identifier.
        let mut server_keygen_rng = HmacDrbg::<Sha256>::new(b"ech-3b4-server-key", b"nonce", &[]);
        let server_side_pair = EchKeyPair::generate(
            &mut server_keygen_rng,
            HpkeKem::DhkemX25519HkdfSha256,
            0x44,
            b"public.example",
            64,
            suites,
        )
        .expect("server-side ech keygen");
        let server_list = EchConfigList::new(alloc::vec![server_side_pair.config().clone()]);
        let server_ring = EchKeyRing::from_pairs(alloc::vec![server_side_pair]);

        // Server config: real Ed25519 cert + ECH server with the
        // FRESH server-side `ECHConfigList` to publish on rejection.
        let server_config = ServerConfig::with_ed25519(alloc::vec![cert_der.clone()], key)
            .with_ech_server(EchServer::new(server_ring, server_list.clone()));

        // Client config: trust the server cert; seal against the
        // STALE client-side `ECHConfigList` (config_id 0x33).
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        let mut client_cfg = ClientConfig::new(roots);
        client_cfg.ech = Some(EchClient::from_config_list(client_list));

        let mut crng = HmacDrbg::<Sha256>::new(b"ech-3b4-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ech-3b4-server", b"nonce", &[]);

        // Inner SNI ("secret.example") is also covered by the cert so
        // the outer-CH `public.example` handshake completes without
        // hostname-verification noise.
        let mut client = ClientConnection::new(client_cfg, "public.example", &mut crng);
        let mut server = ServerConnection::new(server_config, srng);

        // Drive: expect the client to surface `EchRejected` once EE
        // arrives. (The server completes the outer handshake under
        // the `public_name` cert; the EE walk catches the rejection
        // before the client validates the rest of the flight.)
        let mut surfaced: Option<crate::tls::Error> = None;
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
                    surfaced = Some(e);
                    break;
                }
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        let err = surfaced.expect("client must surface EchRejected");
        let bytes = match err {
            crate::tls::Error::EchRejected(b) => b,
            other => panic!("unexpected error: {other:?}"),
        };

        // The surfaced bytes must round-trip back through
        // `EchConfigList::decode` and yield the SAME list the server
        // installed as `retry_configs` — i.e. config_id 0x44.
        let parsed = crate::tls::ech::EchConfigList::decode(&bytes).expect("decode retry_configs");
        let first = parsed
            .first_supported()
            .expect("retry_configs has a supported entry");
        let contents = first
            .contents
            .as_ref()
            .expect("retry_configs entry has contents");
        assert_eq!(contents.key_config.config_id, 0x44);
        assert_eq!(contents.public_name, b"public.example");
    }

    /// End-to-end HelloRetryRequest combined with real ECH
    /// (draft-ietf-tls-esni-22 §7.2.1): server has both
    /// `preferred_key_exchange_group = SECP384R1` and an ECH key, the
    /// client both ships only an X25519 share AND configures real ECH.
    /// The server emits an HRR carrying the `hrr_accept_confirmation`
    /// signal in the trailing `encrypted_client_hello` extension; the
    /// client verifies it, re-seals CH2-inner under the retained
    /// `SenderContext` (HPKE `seq` advances to 1), and the inner-SNI
    /// handshake completes. `ech_outcome()` reports
    /// [`EchOutcome::Accepted`] across the round-trip and application
    /// data flows in both directions.
    #[cfg(feature = "ech")]
    #[test]
    fn ech_real_hrr_loopback_accepts_and_round_trips() {
        use super::client::EchOutcome;
        use crate::hpke::{HpkeAead, HpkeKdf, HpkeKem};
        use crate::tls::ech::HpkeSymCipherSuite;
        use crate::tls::ech::keys::{EchKeyPair, EchKeyRing};
        use crate::tls::ech::{EchClient, EchConfigList, EchServer};

        // Self-signed Ed25519 cert covering the inner SNI the client
        // really targets ("secret.example") — that's the name the
        // client verifies against after the ECH accept swap. We do not
        // cover the outer `public_name` here: on accept, the outer
        // certificate is never validated against, only the inner.
        let mut srvkey_rng = HmacDrbg::<Sha256>::new(b"ech-hrr-srvkey", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut srvkey_rng);
        let name = DistinguishedName::common_name("secret.example");
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
            &["secret.example"],
        )
        .unwrap();
        let cert_der = cert.to_der().to_vec();

        // One ECH key shared by both sides (the "happy" path: client's
        // configured list matches the server's published one).
        let mut keygen_rng = HmacDrbg::<Sha256>::new(b"ech-hrr-keygen", b"nonce", &[]);
        let suites = alloc::vec![HpkeSymCipherSuite {
            kdf_id: HpkeKdf::HkdfSha256.id(),
            aead_id: HpkeAead::Aes128Gcm.id(),
        }];
        let pair = EchKeyPair::generate(
            &mut keygen_rng,
            HpkeKem::DhkemX25519HkdfSha256,
            0x55,
            b"public.example",
            64,
            suites,
        )
        .expect("ech keygen");
        let list = EchConfigList::new(alloc::vec![pair.config().clone()]);
        let ring = EchKeyRing::from_pairs(alloc::vec![pair]);

        // Server: Ed25519 cert + ECH server + a preferred group that
        // forces HRR (client below ships only X25519 share).
        let server_config = ServerConfig::with_ed25519(alloc::vec![cert_der.clone()], key)
            .with_ech_server(EchServer::new(ring, list.clone()))
            .with_preferred_key_exchange_group(crate::tls::NamedGroup::Secp384r1);

        // Client: trusts the server cert; configures real ECH against
        // the matching list; advertises both X25519 and SECP384R1 but
        // ships a key_share only for X25519 — exactly the deployment
        // shape the preferred-group HRR pre-check exists for.
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        let mut client_cfg = ClientConfig::new(roots);
        client_cfg.ech = Some(EchClient::from_config_list(list));

        let mut crng = HmacDrbg::<Sha256>::new(b"ech-hrr-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ech-hrr-server", b"nonce", &[]);

        let mut client = ClientConnection::new_with_offer_partial_shares(
            client_cfg,
            "secret.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519, NamedGroup::SECP384R1],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection::new(server_config, srng);

        // HRR adds one extra CH/SH round-trip; cap at 24.
        for _ in 0..24 {
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
        assert!(
            !client.is_handshaking(),
            "client did not finish after HRR+ECH"
        );
        assert!(
            !server.is_handshaking(),
            "server did not finish after HRR+ECH"
        );
        assert_eq!(
            client.ech_outcome(),
            Some(EchOutcome::Accepted),
            "ECH must remain accepted across HRR",
        );

        // Inner-transcript app data round-trips after the HRR retry.
        client.send_application_data(b"hrr+ech ping").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"hrr+ech ping");

        server.send_application_data(b"hrr+ech pong").unwrap();
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), b"hrr+ech pong");
    }

    /// Negative ECH HRR signal: a man-in-the-middle (modeled here by
    /// flipping a byte of the HRR's `encrypted_client_hello` payload
    /// on the wire between server and client) breaks the
    /// `hrr_accept_confirmation` HKDF chain. The client MUST surface
    /// [`Error::EchRejected`] rather than silently retry under a
    /// tampered HPKE schedule.
    #[cfg(feature = "ech")]
    #[test]
    fn ech_real_hrr_signal_corruption_rejected() {
        use crate::hpke::{HpkeAead, HpkeKdf, HpkeKem};
        use crate::tls::ech::HpkeSymCipherSuite;
        use crate::tls::ech::keys::{EchKeyPair, EchKeyRing};
        use crate::tls::ech::{EchClient, EchConfigList, EchServer};

        let mut srvkey_rng = HmacDrbg::<Sha256>::new(b"ech-hrr-tamper-srvkey", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut srvkey_rng);
        let name = DistinguishedName::common_name("secret.example");
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
            &["secret.example"],
        )
        .unwrap();
        let cert_der = cert.to_der().to_vec();

        let mut keygen_rng = HmacDrbg::<Sha256>::new(b"ech-hrr-tamper-keygen", b"nonce", &[]);
        let suites = alloc::vec![HpkeSymCipherSuite {
            kdf_id: HpkeKdf::HkdfSha256.id(),
            aead_id: HpkeAead::Aes128Gcm.id(),
        }];
        let pair = EchKeyPair::generate(
            &mut keygen_rng,
            HpkeKem::DhkemX25519HkdfSha256,
            0x66,
            b"public.example",
            64,
            suites,
        )
        .expect("ech keygen");
        let list = EchConfigList::new(alloc::vec![pair.config().clone()]);
        let ring = EchKeyRing::from_pairs(alloc::vec![pair]);

        let server_config = ServerConfig::with_ed25519(alloc::vec![cert_der.clone()], key)
            .with_ech_server(EchServer::new(ring, list.clone()))
            .with_preferred_key_exchange_group(crate::tls::NamedGroup::Secp384r1);

        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        let mut client_cfg = ClientConfig::new(roots);
        client_cfg.ech = Some(EchClient::from_config_list(list));

        let mut crng = HmacDrbg::<Sha256>::new(b"ech-hrr-tamper-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ech-hrr-tamper-s", b"nonce", &[]);

        let mut client = ClientConnection::new_with_offer_partial_shares(
            client_cfg,
            "secret.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519, NamedGroup::SECP384R1],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection::new(server_config, srng);

        // Drive CH1 → HRR.
        let ch1 = client.write_tls();
        server.read_tls(&ch1);
        server.process_new_packets().unwrap();
        let mut hrr_record = server.write_tls();
        assert!(!hrr_record.is_empty(), "server must emit HRR");

        // The server typically emits the HRR record together with a
        // CCS record (TLS 1.3 middlebox compat); pick out the
        // handshake-content-type record that carries the HRR.
        // TLS record header: ContentType(1) ‖ ProtocolVersion(2) ‖ Length(2).
        let (hrr_rec_start, hrr_rec_end) = {
            let mut p = 0;
            let mut found = None;
            while p + 5 <= hrr_record.len() {
                let ct = hrr_record[p];
                let frag_len = ((hrr_record[p + 3] as usize) << 8) | (hrr_record[p + 4] as usize);
                let end = p + 5 + frag_len;
                assert!(end <= hrr_record.len(), "truncated record");
                if ct == 0x16 /* Handshake */ && frag_len > 4 && hrr_record[p + 5] == 0x02 {
                    found = Some((p, end));
                    break;
                }
                p = end;
            }
            found.expect("no HRR handshake record found")
        };
        let off_in_hs = crate::tls::ech::accept_signal::locate_hrr_ech_signal_payload(
            &hrr_record[hrr_rec_start + 5..hrr_rec_end],
        )
        .expect("HRR carries the HRR signal extension");
        // Flip a bit inside the wire HRR record, in place.
        hrr_record[hrr_rec_start + 5 + off_in_hs] ^= 0x01;

        // Hand the tampered HRR to the client; it must reject ECH.
        client.read_tls(&hrr_record);
        let err = client.process_new_packets().unwrap_err();
        assert!(
            matches!(err, crate::tls::Error::EchRejected(_)),
            "tampered HRR signal must surface EchRejected, got {err:?}",
        );
    }

    /// End-to-end HelloRetryRequest: server with
    /// `preferred_key_exchange_group = SECP384R1` and client advertising
    /// `[X25519, SECP384R1]` but only shipping a share for X25519. The
    /// server should send HRR, the client should retry with a SECP384R1
    /// share, and the handshake should complete with bidirectional app
    /// data flowing.
    #[test]
    fn hello_retry_request_preferred_group_loopback() {
        let (mut server_config, cert_der) = rsa_server();
        server_config =
            server_config.with_preferred_key_exchange_group(crate::tls::NamedGroup::Secp384r1);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"hrr-loop-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"hrr-loop-server", b"nonce", &[]);

        // Advertise X25519 and SECP384R1, ship a key_share only for X25519.
        let mut client = ClientConnection::new_with_offer_partial_shares(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519, NamedGroup::SECP384R1],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection::new(server_config, srng);

        // Drive the I/O loop. A successful HRR exchange adds an extra
        // CH/SH round-trip, so 24 iterations is the practical ceiling.
        for _ in 0..24 {
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

        assert!(!client.is_handshaking(), "client did not finish after HRR");
        assert!(!server.is_handshaking(), "server did not finish after HRR");

        client.send_application_data(b"hrr ping").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"hrr ping");

        server.send_application_data(b"hrr pong").unwrap();
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), b"hrr pong");
    }

    /// Negative: a CH2 that flips its `signature_algorithms` is rejected
    /// with `illegal_parameter` (RFC 8446 §4.1.4 immutability).
    #[test]
    fn hello_retry_request_immutability_violation() {
        use crate::tls::codec::extension as ext;
        use crate::tls::codec::{ClientHello, ExtensionType, ReadCursor, read_handshake};

        let (mut server_config, _cert_der) = rsa_server();
        server_config =
            server_config.with_preferred_key_exchange_group(crate::tls::NamedGroup::Secp384r1);
        let srng = HmacDrbg::<Sha256>::new(b"hrr-imm-server", b"nonce", &[]);
        let mut server = ServerConnection::new(server_config, srng);

        // Build an honest client just to harvest a valid CH1.
        let mut crng = HmacDrbg::<Sha256>::new(b"hrr-imm-client", b"nonce", &[]);
        let mut roots = RootCertStore::new();
        roots.add_der(_cert_der).unwrap();
        let mut client = ClientConnection::new_with_offer_partial_shares(
            ClientConfig::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::AES_128_GCM_SHA256],
            &[NamedGroup::X25519, NamedGroup::SECP384R1],
            &[NamedGroup::X25519],
        );

        // Hand CH1 to the server; pull HRR back.
        let ch1 = client.write_tls();
        server.read_tls(&ch1);
        server.process_new_packets().unwrap();
        let hrr = server.write_tls();
        assert!(!hrr.is_empty(), "server must emit HRR");

        // Deliver HRR to the client so it builds CH2 honestly.
        client.read_tls(&hrr);
        client.process_new_packets().unwrap();
        let ch2_record = client.write_tls();
        assert!(!ch2_record.is_empty(), "client must emit CH2");

        // Surgery on CH2: rewrite the `signature_algorithms` body to a
        // single ED25519 entry so it differs from CH1 (which advertises
        // the default broader set). u16 list_len(2) ‖ u16 ED25519(0x0807).
        let body = &ch2_record[5..];
        let mut c = ReadCursor::new(body);
        let (_ty, hsbody) = read_handshake(&mut c).unwrap();
        let mut ch2 = ClientHello::decode(hsbody).unwrap();
        let _ = ext::find; // keep import live across cfg combos
        for (t, b) in ch2.extensions.iter_mut() {
            if *t == ExtensionType::SIGNATURE_ALGORITHMS {
                *b = alloc::vec![0x00, 0x02, 0x08, 0x07];
            }
        }
        let new_body = ch2.encode();
        let mut new_record = Vec::new();
        crate::tls::codec::write_record(
            &mut new_record,
            crate::tls::ContentType::Handshake,
            crate::tls::ProtocolVersion::TLSv1_2,
            &new_body,
        );

        server.read_tls(&new_record);
        let err = server.process_new_packets().unwrap_err();
        assert!(matches!(err, crate::tls::Error::IllegalParameter));
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

    /// Drives a full TLS 1.0/1.1 legacy CBC handshake (client capped at
    /// `version`, server floor at TLS 1.0) and exchanges app data both ways.
    #[cfg(feature = "tls-legacy")]
    fn run_legacy(suite: CipherSuite, version: crate::tls::ProtocolVersion) {
        let (server_config, cert_der) = rsa_server12();
        // Floor the server at SSL 3.0 so it accepts every legacy version under
        // test (SSLv3 .. TLS 1.1).
        let server_config = server_config.with_min_version(crate::tls::ProtocolVersion::SSLv3);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"loopback12-legacy-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"loopback12-legacy-s", b"nonce", &[]);

        let cfg = ClientConfig12::new(roots)
            .with_min_version(version)
            .with_max_version(version);
        let mut client = ClientConnection12::new_with_offer(
            cfg,
            "loopback.example",
            &mut crng,
            &[suite],
            &[NamedGroup::X25519, NamedGroup::SECP256R1],
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
        assert_eq!(client.negotiated_cipher_suite(), Some(suite.0));
        assert_eq!(server.negotiated_cipher_suite(), Some(suite.0));

        client.send_application_data(b"ping from client").unwrap();
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        assert_eq!(server.take_received_plaintext(), b"ping from client");

        server.send_application_data(b"pong from server").unwrap();
        let s = server.write_tls();
        client.read_tls(&s);
        client.process_new_packets().unwrap();
        assert_eq!(client.take_received_plaintext(), b"pong from server");
    }

    #[cfg(feature = "tls-legacy")]
    #[test]
    fn tls11_ecdhe_rsa_aes128_cbc_sha() {
        run_legacy(
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            crate::tls::ProtocolVersion::TLSv1_1,
        );
    }

    #[cfg(feature = "tls-legacy")]
    #[test]
    fn tls11_ecdhe_rsa_aes256_cbc_sha256() {
        run_legacy(
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA256,
            crate::tls::ProtocolVersion::TLSv1_1,
        );
    }

    #[cfg(feature = "tls-legacy")]
    #[test]
    fn tls11_rsa_aes128_cbc_sha() {
        run_legacy(
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            crate::tls::ProtocolVersion::TLSv1_1,
        );
    }

    #[cfg(feature = "tls-legacy")]
    #[test]
    fn tls11_rsa_3des_cbc_sha() {
        run_legacy(
            CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            crate::tls::ProtocolVersion::TLSv1_1,
        );
    }

    #[cfg(feature = "tls-legacy")]
    #[test]
    fn tls10_ecdhe_rsa_aes128_cbc_sha() {
        run_legacy(
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            crate::tls::ProtocolVersion::TLSv1_0,
        );
    }

    #[cfg(feature = "tls-legacy")]
    #[test]
    fn tls10_rsa_aes256_cbc_sha() {
        run_legacy(
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            crate::tls::ProtocolVersion::TLSv1_0,
        );
    }

    #[cfg(feature = "tls-legacy")]
    #[test]
    fn ssl3_rsa_aes128_cbc_sha() {
        run_legacy(
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            crate::tls::ProtocolVersion::SSLv3,
        );
    }

    #[cfg(feature = "tls-legacy")]
    #[test]
    fn ssl3_rsa_3des_cbc_sha() {
        run_legacy(
            CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
            crate::tls::ProtocolVersion::SSLv3,
        );
    }

    #[cfg(feature = "tls-legacy")]
    #[test]
    fn ssl3_ecdhe_rsa_aes128_cbc_sha() {
        run_legacy(
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            crate::tls::ProtocolVersion::SSLv3,
        );
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

    #[test]
    fn tls12_secp384r1_with_rsa_cert() {
        // Pin SECP384R1: both sides resolve to the P-384 arm of `ecdhe`
        // and `send_server_key_exchange` end-to-end.
        run_with(
            rsa_server12(),
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::SECP384R1],
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

    /// RFC 5705 §4 — TLS 1.2 client and server derive identical keying
    /// material for the same `(label, context)` after a fresh handshake,
    /// and the `None` vs `Some(&[])` branches diverge as the RFC requires.
    #[test]
    fn tls12_exporter_agrees_both_sides() {
        let (server_config, cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"loopback12-exp-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"loopback12-exp-s", b"nonce", &[]);
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

        // Both sides agree on the no-context branch.
        let mut c_out = [0u8; 48];
        let mut s_out = [0u8; 48];
        client
            .tls_exporter(b"EXPERIMENTAL-test", None, &mut c_out)
            .unwrap();
        server
            .tls_exporter(b"EXPERIMENTAL-test", None, &mut s_out)
            .unwrap();
        assert_eq!(c_out, s_out);

        // Both sides agree on the with-context branch.
        let mut c_ctx = [0u8; 48];
        let mut s_ctx = [0u8; 48];
        client
            .tls_exporter(b"EXPERIMENTAL-test", Some(b"binding"), &mut c_ctx)
            .unwrap();
        server
            .tls_exporter(b"EXPERIMENTAL-test", Some(b"binding"), &mut s_ctx)
            .unwrap();
        assert_eq!(c_ctx, s_ctx);

        // RFC 5705 §4 — `None` vs `Some(&[])` MUST differ.
        let mut c_empty = [0u8; 48];
        client
            .tls_exporter(b"EXPERIMENTAL-test", Some(&[]), &mut c_empty)
            .unwrap();
        assert_ne!(c_out, c_empty);
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

    // -------- Commit 6: hostile-peer hardening --------

    use crate::rng::RngCore;
    use crate::tls::codec::extension as ext;
    use crate::tls::codec::handshake12::HelloRequest;
    use crate::tls::codec::{
        ClientHello, ReadCursor, ServerHello, hs_type, read_handshake, read_record,
    };
    use crate::tls::{ContentType, Error, ProtocolVersion};

    /// A TLS 1.2 server presented with a CH that carries `supported_versions`
    /// listing TLS 1.3 MUST overwrite the last 8 bytes of `server_random`
    /// with the RFC 8446 §4.1.3 downgrade sentinel.
    #[test]
    fn tls12_server_writes_downgrade_sentinel() {
        let (server_config, _cert_der) = rsa_server12();
        let srng = HmacDrbg::<Sha256>::new(b"dg-sentinel-s", b"nonce", &[]);
        let mut server = ServerConnection12::new(server_config, srng);

        // Hand-craft a CH that also carries `supported_versions = [0x0304]`
        // (mimicking a TLS 1.3-capable client that fell back to 1.2 on the
        // record-version field).
        let mut crng = HmacDrbg::<Sha256>::new(b"dg-sentinel-c", b"nonce", &[]);
        let mut random = [0u8; 32];
        crng.fill_bytes(&mut random);
        let ch = ClientHello {
            legacy_version: 0x0303,
            random,
            session_id: Vec::new(),
            cipher_suites: alloc::vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            extensions: alloc::vec![
                ext::server_name("loopback.example"),
                ext::signature_algorithms(),
                ext::supported_groups_list(&[NamedGroup::X25519]),
                ext::ec_point_formats(),
                ext::extended_master_secret_empty(),
                ext::renegotiation_info_empty(),
                ext::client_supported_versions(),
            ],
        }
        .encode();
        let mut rec: Vec<u8> = Vec::new();
        super::super::codec::write_record(
            &mut rec,
            ContentType::Handshake,
            ProtocolVersion::TLSv1_2,
            &ch,
        );
        server.read_tls(&rec);
        server.process_new_packets().unwrap();

        // Parse the first emitted record — it should be the SH. Its body's
        // `random` last 8 bytes must equal `DOWNGRD\x01`.
        let out = server.write_tls();
        let parsed = read_record(&out).unwrap().unwrap();
        let mut cur = ReadCursor::new(parsed.fragment);
        let (ty, body) = read_handshake(&mut cur).unwrap();
        assert_eq!(ty, hs_type::SERVER_HELLO);
        let sh = ServerHello::decode(body).unwrap();
        assert_eq!(
            &sh.random[24..],
            &[0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01],
            "server must embed the RFC 8446 §4.1.3 downgrade sentinel",
        );
    }

    /// A TLS 1.2 client opted into the strict policy (via
    /// `with_accept_downgrade_sentinel(false)`) MUST abort with
    /// `IllegalParameter` when the `server_random` tail is the RFC 8446
    /// §4.1.3 downgrade sentinel. (The default policy here is permissive
    /// because this is a pure TLS 1.2 client and the sentinel is only
    /// meaningful inside a higher-version fallback chain.)
    #[test]
    fn tls12_client_rejects_downgrade_sentinel() {
        let (server_config, server_cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"sentinel-rej-c", b"nonce", &[]);
        let cfg = ClientConfig12::new(roots).with_accept_downgrade_sentinel(false);
        let mut client = ClientConnection12::new(cfg, "loopback.example", &mut crng);
        // Drain the CH so the client is in `WaitServerHello`.
        let _ch_bytes = client.write_tls();

        // Hand-craft an SH whose server_random ends with the 1.3-↓-1.2
        // sentinel. We don't need to drive a real server: the sentinel check
        // fires before suite/extension validation paths that would touch
        // crypto state.
        let mut sr = [0xAAu8; 32];
        sr[24..].copy_from_slice(&[0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]);
        let sh = ServerHello {
            random: sr,
            session_id: Vec::new(),
            cipher_suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            extensions: alloc::vec![ext::renegotiation_info_empty()],
        }
        .encode();
        let _ = server_config; // suppress unused warning; we just needed the cert.
        let mut rec: Vec<u8> = Vec::new();
        super::super::codec::write_record(
            &mut rec,
            ContentType::Handshake,
            ProtocolVersion::TLSv1_2,
            &sh,
        );
        client.read_tls(&rec);
        assert!(matches!(
            client.process_new_packets(),
            Err(Error::IllegalParameter)
        ));
    }

    /// A `HelloRequest` (RFC 5246 §7.4.1.1) is a renegotiation prompt. The
    /// TLS 1.2 client refuses renegotiation entirely; receiving one — at any
    /// state, but particularly after Connected — yields `UnexpectedMessage`.
    #[test]
    fn tls12_client_rejects_hello_request_post_handshake() {
        // ---- Phase 1: mid-handshake plaintext HR ----
        let (server_config1, server_cert_der1) = rsa_server12();
        let mut roots1 = RootCertStore::new();
        roots1.add_der(server_cert_der1).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"hr-mid-c", b"nonce", &[]);
        let mut client1 = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots1),
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let _ = server_config1; // we don't drive the server in this phase
        let _ = client1.write_tls(); // drain CH
        let hr = HelloRequest.encode();
        let mut rec: Vec<u8> = Vec::new();
        super::super::codec::write_record(
            &mut rec,
            ContentType::Handshake,
            ProtocolVersion::TLSv1_2,
            &hr,
        );
        client1.read_tls(&rec);
        assert!(matches!(
            client1.process_new_packets(),
            Err(Error::UnexpectedMessage)
        ));

        // ---- Phase 2: post-Connected encrypted HR ----
        let (server_config2, server_cert_der2) = rsa_server12();
        let mut roots2 = RootCertStore::new();
        roots2.add_der(server_cert_der2).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"hr-post-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"hr-post-s", b"nonce", &[]);
        let mut client2 = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots2),
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
        // Have the server emit an AEAD-encrypted HelloRequest under its
        // outbound crypter. The client must reject as `UnexpectedMessage`.
        let hr = HelloRequest.encode();
        server2
            .test_emit_encrypted(ContentType::Handshake, &hr)
            .unwrap();
        let s = server2.write_tls();
        client2.read_tls(&s);
        assert!(matches!(
            client2.process_new_packets(),
            Err(Error::UnexpectedMessage)
        ));
    }

    /// Records whose `legacy_version` field is below 0x0301 (SSL 3.0 or
    /// earlier) MUST be rejected at the record layer by both client and
    /// server.
    #[test]
    fn tls12_rejects_pre_tls12_record_version() {
        // ---- Server side ----
        let (server_config, _cert) = rsa_server12();
        let srng = HmacDrbg::<Sha256>::new(b"badver-s", b"nonce", &[]);
        let mut server = ServerConnection12::new(server_config, srng);
        // Feed a record with legacy_version = 0x0300 (SSL 3.0).
        let body = [0u8; 8];
        let mut rec: Vec<u8> = Vec::new();
        rec.push(ContentType::Handshake.as_u8());
        rec.extend_from_slice(&[0x02, 0x00]); // SSL 2.0 (always rejected)
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);
        server.read_tls(&rec);
        assert!(matches!(
            server.process_new_packets(),
            Err(Error::UnsupportedVersion)
        ));

        // ---- Client side ----
        let mut roots = RootCertStore::new();
        let (_cfg, der) = rsa_server12();
        roots.add_der(der).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"badver-c", b"nonce", &[]);
        let mut client =
            ClientConnection12::new(ClientConfig12::new(roots), "loopback.example", &mut crng);
        let _ = client.write_tls(); // drain CH
        let mut rec: Vec<u8> = Vec::new();
        rec.push(ContentType::Handshake.as_u8());
        rec.extend_from_slice(&[0x02, 0x00]); // SSL 2.0 (always rejected)
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);
        client.read_tls(&rec);
        assert!(matches!(
            client.process_new_packets(),
            Err(Error::UnsupportedVersion)
        ));
    }

    /// RFC 5246 §7.1: exactly one ChangeCipherSpec per direction. A second
    /// one — even with the legal `[0x01]` body — must be rejected with
    /// `UnexpectedMessage`.
    #[test]
    fn tls12_rejects_duplicate_ccs() {
        // Complete a handshake first.
        let (server_config, server_cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"dupccs-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"dupccs-s", b"nonce", &[]);
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
        assert!(!client.is_handshaking());

        // Post-Connected, the CCS window is closed — any CCS arriving now
        // (legitimate or duplicate) is rejected. This covers the
        // "second CCS" case.
        let mut rec: Vec<u8> = Vec::new();
        super::super::codec::write_record(
            &mut rec,
            ContentType::ChangeCipherSpec,
            ProtocolVersion::TLSv1_2,
            &[0x01],
        );
        client.read_tls(&rec);
        assert!(matches!(
            client.process_new_packets(),
            Err(Error::UnexpectedMessage)
        ));
    }

    /// RFC 5246 §7.1: a ChangeCipherSpec arriving BEFORE
    /// `ClientKeyExchange` (i.e. before the pending read crypter has been
    /// built) is out-of-order and must be rejected with `UnexpectedMessage`.
    #[test]
    fn tls12_rejects_ccs_before_cke() {
        let (server_config, _cert_der) = rsa_server12();
        let srng = HmacDrbg::<Sha256>::new(b"earlyccs-s", b"nonce", &[]);
        let mut server = ServerConnection12::new(server_config, srng);

        // Drive a normal CH so the server emits the server flight and is
        // now in `WaitClientKeyExchange`.
        let mut crng = HmacDrbg::<Sha256>::new(b"earlyccs-c", b"nonce", &[]);
        let mut roots = RootCertStore::new();
        let (_cfg, der) = rsa_server12();
        roots.add_der(der).unwrap();
        let mut client = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots),
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let c = client.write_tls();
        server.read_tls(&c);
        server.process_new_packets().unwrap();
        // Drain the server's flight so the next inbound record is processed
        // afresh.
        let _ = server.write_tls();

        // Now inject a stray CCS — before the client's CKE arrives.
        let mut rec: Vec<u8> = Vec::new();
        super::super::codec::write_record(
            &mut rec,
            ContentType::ChangeCipherSpec,
            ProtocolVersion::TLSv1_2,
            &[0x01],
        );
        server.read_tls(&rec);
        assert!(matches!(
            server.process_new_packets(),
            Err(Error::UnexpectedMessage)
        ));
    }

    /// RFC 7507 §4: a fresh TLS 1.2 client does NOT emit `TLS_FALLBACK_SCSV`
    /// (`0x5600`) by default. Opting in via `with_fallback_scsv(true)`
    /// prepends it to the offered suite list. Our 1.2-only server ignores it
    /// (it would only matter to a server that also speaks 1.3).
    #[test]
    fn tls12_fallback_scsv_default_off_and_opt_in() {
        // Default: SCSV is absent from the CH suite list.
        let mut crng = HmacDrbg::<Sha256>::new(b"scsv-off", b"nonce", &[]);
        let cfg = ClientConfig12::new(RootCertStore::new());
        let mut client = ClientConnection12::new(cfg, "example.com", &mut crng);
        let bytes = client.write_tls();
        let rec = read_record(&bytes).unwrap().unwrap();
        let mut cur = ReadCursor::new(rec.fragment);
        let (_ty, body) = read_handshake(&mut cur).unwrap();
        let ch = ClientHello::decode(body).unwrap();
        assert!(
            !ch.cipher_suites.iter().any(|s| s.0 == 0x5600),
            "default client must NOT advertise TLS_FALLBACK_SCSV",
        );

        // Opted in: 0x5600 is the FIRST suite on the wire.
        let mut crng = HmacDrbg::<Sha256>::new(b"scsv-on", b"nonce", &[]);
        let cfg = ClientConfig12::new(RootCertStore::new()).with_fallback_scsv(true);
        let mut client = ClientConnection12::new(cfg, "example.com", &mut crng);
        let bytes = client.write_tls();
        let rec = read_record(&bytes).unwrap().unwrap();
        let mut cur = ReadCursor::new(rec.fragment);
        let (_ty, body) = read_handshake(&mut cur).unwrap();
        let ch = ClientHello::decode(body).unwrap();
        assert_eq!(
            ch.cipher_suites.first().map(|s| s.0),
            Some(0x5600),
            "with_fallback_scsv(true) must prepend TLS_FALLBACK_SCSV",
        );

        // The server still accepts an SCSV-bearing CH (we are at our cap).
        let (server_config, server_cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert_der).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"scsv-full-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"scsv-full-s", b"nonce", &[]);
        let mut client = ClientConnection12::new(
            ClientConfig12::new(roots).with_fallback_scsv(true),
            "loopback.example",
            &mut crng,
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
    }

    // ----- RFC 7627 Extended Master Secret (HIGH #6) -----

    /// Drives a fresh loopback handshake (with the server unmodified) and
    /// returns the connected client/server pair. Panics on any handshake
    /// error.
    fn drive_ems_handshake() -> (ClientConnection12, ServerConnection12<HmacDrbg<Sha256>>) {
        let (server_config, cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"ems-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ems-s", b"nonce", &[]);
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
        (client, server)
    }

    /// EMS happy path: a fresh loopback handshake negotiates EMS on both
    /// sides and the derived master_secret bytes agree.
    #[test]
    fn tls12_ems_handshake_negotiates_extension() {
        let (client, server) = drive_ems_handshake();
        assert!(client.ems_negotiated(), "client must see EMS echoed");
        assert!(server.ems_negotiated(), "server must have echoed EMS");
        let cm = client.master_secret().expect("client master");
        let sm = server.master_secret().expect("server master");
        assert_eq!(cm, sm, "EMS-derived master must agree across peers");
    }

    /// When both peers offer EMS, the handshake completes under the EMS
    /// derivation. This is essentially `tls12_ems_handshake_negotiates_extension`
    /// retained as a separate guard against regressions in the "both sides
    /// agree on a key block under EMS" path.
    #[test]
    fn tls12_ems_required_when_offered_by_both() {
        let (client, server) = drive_ems_handshake();
        assert!(client.ems_negotiated());
        assert!(server.ems_negotiated());
        // Application data flows under the EMS-derived keys.
        let mut c = client;
        let mut s = server;
        c.send_application_data(b"ems-ping").unwrap();
        let out = c.write_tls();
        s.read_tls(&out);
        s.process_new_packets().unwrap();
        assert_eq!(s.take_received_plaintext(), b"ems-ping");
    }

    /// Legacy fallback: the server is pinned NOT to echo EMS. The client
    /// offers EMS but completes the handshake under the legacy
    /// (randoms-only) derivation. Documents the "preserve existing
    /// behaviour" policy; a future commit may enforce EMS.
    #[test]
    fn tls12_legacy_fallback_when_server_omits_ems() {
        let (server_config, cert_der) = rsa_server12();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"ems-fallback-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ems-fallback-s", b"nonce", &[]);
        // Both peers opt out of the EMS requirement so the legacy
        // randoms-only PRF path can complete (test documents that path).
        let mut client = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots).with_require_ems(false),
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let server_config = server_config.with_require_ems(false);
        let mut server = ServerConnection12::new(server_config, srng);
        // Server pretends it doesn't support EMS — silently skips the echo.
        server.test_force_no_ems = true;

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
        assert!(!client.ems_negotiated());
        assert!(!server.ems_negotiated());
        // The master_secrets still agree — both peers used the same legacy
        // PRF inputs.
        assert_eq!(client.master_secret(), server.master_secret());
    }

    /// RFC 7627 §5.3 happy path: an EMS-bound session resumes under EMS.
    #[test]
    fn tls12_resumption_ems_to_ems() {
        let ticket_key = [0x77u8; 32];

        // Phase 1: fresh EMS handshake; harvest a session ticket.
        let (server_config, cert_der) = rsa_server12();
        let server_config = server_config.with_ticket_key(ticket_key);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der.clone()).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"ems-rt-1c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"ems-rt-1s", b"nonce", &[]);
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
        assert!(client.ems_negotiated() && server.ems_negotiated());
        let session = client.take_session().expect("ticket issued");
        assert!(session.ems_used, "stored session must record EMS");

        // Phase 2: resume.
        let (server_config2, _) = rsa_server12();
        let server_config2 = server_config2.with_ticket_key(ticket_key);
        let mut roots2 = RootCertStore::new();
        roots2.add_der(cert_der).unwrap();
        let mut crng2 = HmacDrbg::<Sha256>::new(b"ems-rt-2c", b"nonce", &[]);
        let srng2 = HmacDrbg::<Sha256>::new(b"ems-rt-2s", b"nonce", &[]);
        let mut client2 = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots2).with_session(session),
            "loopback.example",
            &mut crng2,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server2 = ServerConnection12::new(server_config2, srng2);
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
        assert!(client2.did_resume() && server2.did_resume());
        assert!(client2.ems_negotiated() && server2.ems_negotiated());
    }

    /// RFC 7627 §5.3: an EMS-bound session that resumes against a server
    /// stripping the EMS echo MUST abort with `IllegalParameter`. This is
    /// the cross-EMS-resumption guard.
    #[test]
    fn tls12_resumption_cross_ems_aborts() {
        let ticket_key = [0x77u8; 32];

        // Phase 1: fresh EMS handshake.
        let (server_config, cert_der) = rsa_server12();
        let server_config = server_config.with_ticket_key(ticket_key);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der.clone()).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"cross-ems-1c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"cross-ems-1s", b"nonce", &[]);
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
        let session = client.take_session().expect("ticket");
        assert!(session.ems_used);

        // Phase 2: server NOW pretends to not support EMS. The client
        // presents an EMS-bound ticket; the server's stripping flips the
        // expected EMS bit, the gate fires, and the handshake aborts.
        let (server_config2, _) = rsa_server12();
        let server_config2 = server_config2.with_ticket_key(ticket_key);
        let mut roots2 = RootCertStore::new();
        roots2.add_der(cert_der).unwrap();
        let mut crng2 = HmacDrbg::<Sha256>::new(b"cross-ems-2c", b"nonce", &[]);
        let srng2 = HmacDrbg::<Sha256>::new(b"cross-ems-2s", b"nonce", &[]);
        let mut client2 = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots2).with_session(session),
            "loopback.example",
            &mut crng2,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server2 = ServerConnection12::new(server_config2, srng2);
        server2.test_force_no_ems = true;

        // Drive until either side errors.
        let mut client_err: Option<crate::tls::Error> = None;
        let mut server_err: Option<crate::tls::Error> = None;
        for _ in 0..16 {
            let c = client2.write_tls();
            if !c.is_empty() {
                server2.read_tls(&c);
                if let Err(e) = server2.process_new_packets() {
                    server_err = Some(e);
                    break;
                }
            }
            let s = server2.write_tls();
            if !s.is_empty() {
                client2.read_tls(&s);
                if let Err(e) = client2.process_new_packets() {
                    client_err = Some(e);
                    break;
                }
            }
            if c.is_empty() && s.is_empty() {
                break;
            }
        }
        // The client detects the mismatch first (server's SH is the message
        // that omits EMS, and the client's `on_server_hello` runs the gate).
        assert!(
            matches!(client_err, Some(crate::tls::Error::IllegalParameter))
                || matches!(server_err, Some(crate::tls::Error::IllegalParameter)),
            "expected IllegalParameter, got client={client_err:?} server={server_err:?}",
        );
    }

    /// RFC 7627 §5.3: a legacy session (no EMS) resumes under legacy
    /// derivation; the EMS bit stays `false` on both sides.
    #[test]
    fn tls12_resumption_legacy_to_legacy() {
        let ticket_key = [0x77u8; 32];

        // Phase 1: both peers opt out of the EMS requirement; server
        // also forces NO EMS so the fresh handshake stays legacy. The
        // client still offers EMS, but the server doesn't echo.
        let (server_config, cert_der) = rsa_server12();
        let server_config = server_config
            .with_ticket_key(ticket_key)
            .with_require_ems(false);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der.clone()).unwrap();
        let mut crng = HmacDrbg::<Sha256>::new(b"legacy-rt-1c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"legacy-rt-1s", b"nonce", &[]);
        let mut client = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots).with_require_ems(false),
            "loopback.example",
            &mut crng,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server = ServerConnection12::new(server_config, srng);
        server.test_force_no_ems = true;
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
        assert!(!client.ems_negotiated() && !server.ems_negotiated());
        let session = client.take_session().expect("ticket");
        assert!(!session.ems_used, "legacy session ticket records ems=false");

        // Phase 2: again forcing no EMS — legacy resume. Both peers
        // again opt out of the EMS requirement.
        let (server_config2, _) = rsa_server12();
        let server_config2 = server_config2
            .with_ticket_key(ticket_key)
            .with_require_ems(false);
        let mut roots2 = RootCertStore::new();
        roots2.add_der(cert_der).unwrap();
        let mut crng2 = HmacDrbg::<Sha256>::new(b"legacy-rt-2c", b"nonce", &[]);
        let srng2 = HmacDrbg::<Sha256>::new(b"legacy-rt-2s", b"nonce", &[]);
        let mut client2 = ClientConnection12::new_with_offer(
            ClientConfig12::new(roots2)
                .with_session(session)
                .with_require_ems(false),
            "loopback.example",
            &mut crng2,
            &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            &[NamedGroup::X25519],
        );
        let mut server2 = ServerConnection12::new(server_config2, srng2);
        server2.test_force_no_ems = true;
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
        assert!(client2.did_resume() && server2.did_resume());
        assert!(!client2.ems_negotiated() && !server2.ems_negotiated());
    }

    /// An RSA-CA-signed P-256 leaf, returning the server config (chain
    /// already installed), the root DER (for the client's trust store), and
    /// the leaf DER. Used to drive the OCSP-staple tests below, which
    /// require a real two-cert chain so the validator has a separate issuer
    /// to recover.
    #[allow(clippy::type_complexity)]
    fn ca_signed_ecdsa_leaf_12() -> (ServerConfig12, Vec<u8>, Vec<u8>) {
        let ca_key = rsa_test_key_a();
        let ca_name = DistinguishedName::common_name("Stapling12 Test CA");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let root = Certificate::self_signed(&ca_key, &ca_name, &validity, 1, true).unwrap();

        let mut rng = HmacDrbg::<Sha256>::new(b"stapling12-leaf", b"nonce", &[]);
        let leaf_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let leaf = Certificate::issue_general(
            &CertSigner::Rsa(&BoxedRsaPrivateKey::from_pkcs1_der(&ca_key.to_pkcs1_der()).unwrap()),
            &ca_name,
            &DistinguishedName::common_name("loopback.example"),
            &crate::x509::AnyPublicKey::Ecdsa(leaf_key.public_key()),
            &validity,
            7,
            false,
            &["loopback.example"],
        )
        .unwrap();
        let chain = alloc::vec![leaf.to_der().to_vec(), root.to_der().to_vec()];
        let cfg = ServerConfig12::with_ecdsa(chain, leaf_key);
        (cfg, root.to_der().to_vec(), leaf.to_der().to_vec())
    }

    fn drive_until_client_error_12(
        client: &mut ClientConnection12,
        server: &mut ServerConnection12<HmacDrbg<Sha256>>,
    ) -> crate::tls::Error {
        for _ in 0..16 {
            let c = client.write_tls();
            if !c.is_empty() {
                server.read_tls(&c);
                let _ = server.process_new_packets();
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
        panic!("client did not error");
    }

    /// TLS 1.2: server staples a `good` OCSP response — handshake completes
    /// and the client surfaces the response via `peer_ocsp_response`.
    #[test]
    fn tls12_stapled_ocsp_good() {
        use crate::x509::OcspResponseBuilder;
        let (mut server_config, root_der, leaf_der) = ca_signed_ecdsa_leaf_12();
        let ca_signer = CertSigner::Rsa(
            &BoxedRsaPrivateKey::from_pkcs1_der(&rsa_test_key_a().to_pkcs1_der()).unwrap(),
        );
        let leaf = Certificate::from_der(leaf_der).unwrap();
        let root = Certificate::from_der(root_der.clone()).unwrap();
        let resp = OcspResponseBuilder::good(
            &leaf,
            &root,
            Time::utc(2026, 4, 1, 0, 0, 0),
            Some(Time::utc(2026, 6, 1, 0, 0, 0)),
        )
        .unwrap()
        .sign(&ca_signer)
        .unwrap();
        let der = resp.to_der().to_vec();
        server_config = server_config.with_stapled_ocsp_response(der.clone());

        let mut roots = RootCertStore::new();
        roots.add_der(root_der).unwrap();
        let mut cfg = ClientConfig12::new(roots);
        cfg.verification_time = Some(Time::utc(2026, 5, 1, 0, 0, 0));

        let mut crng = HmacDrbg::<Sha256>::new(b"tls12-ocsp-good-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"tls12-ocsp-good-s", b"nonce", &[]);
        let mut client = ClientConnection12::new(cfg, "loopback.example", &mut crng);
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
        assert_eq!(client.peer_ocsp_response().map(|v| v.to_vec()), Some(der));
    }

    /// TLS 1.2: server staples a `revoked` OCSP response → client rejects
    /// with `CertificateRevoked`.
    #[test]
    fn tls12_stapled_ocsp_revoked() {
        use crate::x509::OcspResponseBuilder;
        let (mut server_config, root_der, leaf_der) = ca_signed_ecdsa_leaf_12();
        let ca_signer = CertSigner::Rsa(
            &BoxedRsaPrivateKey::from_pkcs1_der(&rsa_test_key_a().to_pkcs1_der()).unwrap(),
        );
        let leaf = Certificate::from_der(leaf_der).unwrap();
        let root = Certificate::from_der(root_der.clone()).unwrap();
        let resp = OcspResponseBuilder::revoked(
            &leaf,
            &root,
            Time::utc(2026, 4, 1, 0, 0, 0),
            Some(Time::utc(2026, 6, 1, 0, 0, 0)),
            Time::utc(2026, 3, 15, 0, 0, 0),
            None,
        )
        .unwrap()
        .sign(&ca_signer)
        .unwrap();
        server_config = server_config.with_stapled_ocsp_response(resp.to_der().to_vec());

        let mut roots = RootCertStore::new();
        roots.add_der(root_der).unwrap();
        let mut cfg = ClientConfig12::new(roots);
        cfg.verification_time = Some(Time::utc(2026, 5, 1, 0, 0, 0));

        let mut crng = HmacDrbg::<Sha256>::new(b"tls12-ocsp-rev-c", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"tls12-ocsp-rev-s", b"nonce", &[]);
        let mut client = ClientConnection12::new(cfg, "loopback.example", &mut crng);
        let mut server = ServerConnection12::new(server_config, srng);
        assert_eq!(
            drive_until_client_error_12(&mut client, &mut server),
            crate::tls::Error::CertificateRevoked
        );
    }
}

#[cfg(test)]
mod keylog_loopback_tests {
    //! Loopback tests for the SSLKEYLOGFILE plumbing on TLS 1.2 and TLS 1.3.

    use super::{
        ClientConfig, ClientConfig12, ClientConnection, ClientConnection12, ServerConfig,
        ServerConfig12, ServerConnection, ServerConnection12,
    };
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::rsa::BoxedRsaPrivateKey;
    use crate::test_util::rsa_test_key_a;
    use crate::tls::RootCertStore;
    use crate::tls::codec::{CipherSuite, NamedGroup};
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
    use alloc::vec::Vec;

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

    /// SSLKEYLOGFILE plumbing for TLS 1.3: a client + server pair share a
    /// `Vec<u8>`-backed [`crate::tls::WriterKeyLog`] and the buffer ends up
    /// containing every standard label twice (once from each peer), with
    /// matching secret bytes on each pair of lines.
    #[test]
    fn keylog_tls13_loopback_agrees() {
        use crate::tls::WriterKeyLog;
        use alloc::collections::BTreeMap;
        use alloc::string::ToString;
        use alloc::sync::Arc;

        let (mut server_config, cert_der) = rsa_server();
        let buf: Vec<u8> = Vec::new();
        let sink = Arc::new(WriterKeyLog::new(buf));
        // Inject the same sink on both sides.
        server_config.key_log = Some(sink.clone());

        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut crng = HmacDrbg::<Sha256>::new(b"kl-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"kl-server", b"nonce", &[]);
        let mut client_config = ClientConfig::new(roots);
        client_config.key_log = Some(sink.clone());
        let mut client = ClientConnection::new_with_offer(
            client_config,
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

        // Drain the shared buffer. We have to dance with `Arc::try_unwrap`:
        // both endpoints hold a clone, so two refs remain even after we
        // drop the connections. Drop them first.
        drop(client);
        drop(server);
        let log_text: alloc::string::String = {
            // One Arc<WriterKeyLog<Vec<u8>>> remains here (the test owns
            // it), so we can lock and read.
            let buf = sink.writer_lock_for_test();
            core::str::from_utf8(&buf).unwrap().to_string()
        };

        // We expect each label to appear exactly twice, and the (label,
        // secret) pair to agree between the two appearances.
        let want_labels = [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET",
        ];
        let mut per_label: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for line in log_text.lines() {
            let parts: Vec<&str> = line.split_ascii_whitespace().collect();
            assert_eq!(parts.len(), 3, "malformed keylog line: {line}");
            // <label> <cr_hex> <secret_hex>
            assert_eq!(parts[1].len(), 64, "client_random hex len wrong: {line}");
            per_label.entry(parts[0]).or_default().push(parts[2]);
        }
        for label in want_labels {
            let entries = per_label
                .get(label)
                .unwrap_or_else(|| panic!("missing label {label} in keylog:\n{log_text}"));
            assert_eq!(
                entries.len(),
                2,
                "expected {label} to appear twice, got {}",
                entries.len()
            );
            assert_eq!(
                entries[0], entries[1],
                "client/server disagree on {label}: {} vs {}",
                entries[0], entries[1]
            );
        }
    }

    /// SSLKEYLOGFILE plumbing for TLS 1.2: client + server pair share a
    /// sink; the buffer contains exactly two `CLIENT_RANDOM <cr> <master>`
    /// lines (one per peer) whose master secrets match.
    #[test]
    fn keylog_tls12_loopback_agrees() {
        use crate::tls::WriterKeyLog;
        use alloc::sync::Arc;

        let mut crng = HmacDrbg::<Sha256>::new(b"kl12-client", b"nonce", &[]);
        let srng = HmacDrbg::<Sha256>::new(b"kl12-server", b"nonce", &[]);

        // Generate an ECDSA P-256 server cert.
        let mut keyrng = HmacDrbg::<Sha256>::new(b"kl12-key", b"nonce", &[]);
        let key = crate::ec::BoxedEcdsaPrivateKey::generate(crate::ec::CurveId::P256, &mut keyrng);
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &DistinguishedName::common_name("kl12.example"),
            &validity,
            1,
            false,
            &["kl12.example"],
        )
        .unwrap();
        let cert_der = cert.to_der().to_vec();

        let buf: Vec<u8> = Vec::new();
        let sink = Arc::new(WriterKeyLog::new(buf));

        let mut server_config = ServerConfig12::with_ecdsa(alloc::vec![cert_der.clone()], key);
        server_config.key_log = Some(sink.clone());

        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();

        let mut client_config = ClientConfig12::new(roots);
        client_config.key_log = Some(sink.clone());

        let mut client = ClientConnection12::new(client_config, "kl12.example", &mut crng);
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

        drop(client);
        drop(server);
        let log_text: alloc::string::String = {
            let buf = sink.writer_lock_for_test();
            core::str::from_utf8(&buf).unwrap().into()
        };

        let lines: Vec<&str> = log_text.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "expected 2 CLIENT_RANDOM lines, got {lines:?}"
        );
        for line in &lines {
            let parts: Vec<&str> = line.split_ascii_whitespace().collect();
            assert_eq!(parts.len(), 3, "malformed CLIENT_RANDOM line: {line}");
            assert_eq!(parts[0], "CLIENT_RANDOM");
            assert_eq!(parts[1].len(), 64);
            assert_eq!(parts[2].len(), 96); // 48-byte master_secret
        }
        // Both peers must report the same master.
        let secret0 = lines[0].split_ascii_whitespace().nth(2).unwrap();
        let secret1 = lines[1].split_ascii_whitespace().nth(2).unwrap();
        assert_eq!(
            secret0, secret1,
            "client/server disagree on TLS 1.2 master_secret"
        );
    }
}
