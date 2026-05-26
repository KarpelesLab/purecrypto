//! The TLS 1.3 client handshake state machine.
//!
//! [`ClientConnection`] drives a full 1-RTT client handshake over the sans-I/O
//! [`ConnectionCore`]: it emits a `ClientHello`, processes the server flight
//! (`ServerHello`, then the encrypted `EncryptedExtensions`, `Certificate`,
//! `CertificateVerify`, `Finished`), authenticates the server, and sends its
//! own `Finished`, after which application data flows under the application
//! traffic keys.

use super::common::{ConnectionCore, Incoming};
use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPublicKey, CurveId};
use crate::mlkem::{CIPHERTEXT_BYTES, MlKem768Ciphertext, MlKem768DecapsKey};
use crate::rng::RngCore;
use crate::tls::codec::extension as ext;
use crate::tls::codec::{
    CipherSuite, ClientHello, KeyUpdate, NamedGroup, NewSessionTicket as NstWire, Random,
    ReadCursor, ServerHello, SignatureScheme, hs_type, read_handshake,
};
use crate::tls::crypto::{
    KeySchedule, RecordCrypter, Secret, SuiteParams, certificate_verify_content,
    finished_verify_data, lookup_suite, next_traffic_secret, tls_exporter, verify_signature,
};
use crate::tls::pki::{RootCertStore, verify_chain, verify_hostname};
use crate::tls::{AlertDescription, Error};
use crate::x509::{AnyPublicKey, Certificate, Time};
use alloc::string::String;
use alloc::vec::Vec;

use crate::ct::ConstantTimeEq;

/// Configuration for a TLS client.
pub struct ClientConfig {
    /// Trust anchors used to authenticate the server certificate chain.
    pub roots: RootCertStore,
    /// When `false`, the certificate chain, validity period, and host name are
    /// not checked (the `CertificateVerify` signature is still verified against
    /// the presented leaf key, and the leaf is still rejected if malformed).
    /// Intended for tests and pinned-key scenarios.
    pub verify_certificates: bool,
    /// The time used for validity-period checks. Defaults (`None`) to the
    /// system clock under the `std` feature; set it explicitly for `no_std`
    /// targets or for reproducible verification.
    pub verification_time: Option<Time>,
    /// ALPN protocols to offer (RFC 7301), in preference order. Empty
    /// suppresses the extension. Example: `[b"h2".to_vec(), b"http/1.1".to_vec()]`.
    pub alpn_protocols: Vec<Vec<u8>>,
    /// `record_size_limit` (RFC 8449) we advertise — the largest plaintext
    /// fragment the server may send us. `None` suppresses the extension; the
    /// peer is then free to use the TLS 1.3 default of 2¹⁴ bytes.
    pub record_size_limit: Option<u16>,
}

impl ClientConfig {
    /// A configuration trusting the given roots, with certificate verification
    /// enabled.
    pub fn new(roots: RootCertStore) -> Self {
        ClientConfig {
            roots,
            verify_certificates: true,
            verification_time: None,
            alpn_protocols: Vec::new(),
            record_size_limit: None,
        }
    }

    /// Offers the given ALPN protocols. The first match in the server's
    /// preference order is selected; if there's no overlap, the server
    /// sends `no_application_protocol`.
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Advertises `record_size_limit = limit` (RFC 8449). Must be in
    /// `64..=2^14 + 1`.
    pub fn with_record_size_limit(mut self, limit: u16) -> Self {
        self.record_size_limit = Some(limit);
        self
    }
}

/// The current time from the system clock, when available.
#[cfg(feature = "std")]
fn system_now() -> Option<Time> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| Time::from_unix(d.as_secs()))
}

#[cfg(not(feature = "std"))]
fn system_now() -> Option<Time> {
    None
}

/// The client handshake progress.
#[derive(PartialEq, Eq)]
enum State {
    WaitServerHello,
    WaitEncryptedExtensions,
    WaitCertificate,
    WaitCertificateVerify,
    WaitFinished,
    Connected,
    Closed,
}

/// A TLS 1.3 client connection.
pub struct ClientConnection {
    core: ConnectionCore,
    config: ClientConfig,
    server_name: String,
    state: State,

    x25519: X25519PrivateKey,
    p256: BoxedEcdhPrivateKey,
    mlkem: MlKem768DecapsKey,

    /// CH1 state retained for HelloRetryRequest replay (RFC 8446 §4.1.2):
    /// CH2 must reuse the same client_random and offered_groups, narrowed to
    /// the HRR-selected group.
    client_random: Random,
    offered_suites: Vec<CipherSuite>,
    offered_groups: Vec<NamedGroup>,
    /// Set to `true` after a single HelloRetryRequest has been processed; a
    /// second one is rejected (RFC 8446 §4.1.4).
    hrr_processed: bool,

    suite: Option<SuiteParams>,
    ks: Option<KeySchedule>,
    client_hs_secret: Option<Secret>,
    server_hs_secret: Option<Secret>,

    /// Current write-side (`client_application_traffic_secret_N`) — stepped by
    /// each outgoing `KeyUpdate`.
    client_app_secret: Option<Secret>,
    /// Current read-side (`server_application_traffic_secret_N`) — stepped by
    /// each incoming `KeyUpdate`.
    server_app_secret: Option<Secret>,
    /// `exporter_master_secret` for [`Self::tls_exporter`] (RFC 8446 §7.5).
    exporter_secret: Option<Secret>,

    cert_chain: Vec<Vec<u8>>,
    leaf_key: Option<AnyPublicKey>,

    /// Most recent `NewSessionTicket` from the peer (RFC 8446 §4.6.1). Real
    /// servers (Cloudflare, Google, …) commonly send one immediately after
    /// `Finished`; we accept and stash it. Used by future PSK resumption.
    last_ticket: Option<ReceivedSessionTicket>,

    /// The ALPN protocol the server picked from our advertised list, if any.
    /// Populated from the server's `EncryptedExtensions`.
    alpn_negotiated: Option<Vec<u8>>,
}

/// A `NewSessionTicket` received from the server, exposed for inspection and
/// (eventually) PSK-based resumption.
#[derive(Clone, Debug)]
pub struct ReceivedSessionTicket {
    /// Lifetime hint in seconds (RFC 8446 §4.6.1 caps at 7 days = 604800).
    pub lifetime_seconds: u32,
    /// Randomizer added to the obfuscated ticket age.
    pub age_add: u32,
    /// Per-ticket nonce used by `HKDF-Expand-Label(rms, "resumption", nonce)`
    /// to derive the PSK.
    pub nonce: Vec<u8>,
    /// Opaque ticket bytes — re-presented unchanged on resume.
    pub ticket: Vec<u8>,
    /// `max_early_data_size` from the `early_data` extension, when present.
    /// Cap on bytes the client may send under the 0-RTT key on a resumed
    /// connection.
    pub max_early_data_size: Option<u32>,
}

impl ReceivedSessionTicket {
    fn from_wire(nst: NstWire) -> Result<Self, Error> {
        // RFC 8446 §4.6.1 caps the lifetime at 7 days.
        const MAX_LIFETIME: u32 = 7 * 24 * 60 * 60;
        if nst.ticket_lifetime > MAX_LIFETIME {
            return Err(Error::Decode);
        }
        // Look up an optional early_data extension (type 0x002a).
        let mut max_early_data_size = None;
        for (ty, body) in &nst.extensions {
            if ty.0 == 0x002a {
                if body.len() != 4 {
                    return Err(Error::Decode);
                }
                let v = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                max_early_data_size = Some(v);
            }
        }
        Ok(ReceivedSessionTicket {
            lifetime_seconds: nst.ticket_lifetime,
            age_add: nst.ticket_age_add,
            nonce: nst.ticket_nonce,
            ticket: nst.ticket,
            max_early_data_size,
        })
    }
}

impl ClientConnection {
    /// The negotiated cipher suite's wire identifier (e.g. `0x1301` for
    /// `TLS_AES_128_GCM_SHA256`), available once the `ServerHello` has been
    /// processed.
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.suite.map(|s| s.suite.0)
    }

    /// The IANA name of the negotiated cipher suite, if known.
    pub fn negotiated_cipher_suite_name(&self) -> Option<&'static str> {
        self.negotiated_cipher_suite().map(|id| match id {
            0x1301 => "TLS_AES_128_GCM_SHA256",
            0x1302 => "TLS_AES_256_GCM_SHA384",
            _ => "UNKNOWN",
        })
    }

    /// The negotiated protocol version string (always `"TLSv1.3"` here),
    /// available once the `ServerHello` has been processed.
    pub fn protocol_version(&self) -> Option<&'static str> {
        self.suite.map(|_| "TLSv1.3")
    }

    /// The peer's certificate chain in wire order (DER), leaf first. Empty until
    /// the server's `Certificate` message has been received.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.cert_chain
    }

    /// The most recent `NewSessionTicket` received from the server, if any.
    /// Real-world servers (Cloudflare, Google, …) commonly send one or more
    /// post-handshake; the most recent is retained.
    pub fn last_session_ticket(&self) -> Option<&ReceivedSessionTicket> {
        self.last_ticket.as_ref()
    }

    /// The ALPN protocol the server selected, if any (e.g. `b"h2"`).
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_negotiated.as_deref()
    }

    /// TLS 1.3 application-layer Exporter (RFC 8446 §7.5 / RFC 5705).
    /// Derives `out.len()` bytes from the `exporter_master_secret` under
    /// `(label, context)`. Returns `Err(InappropriateState)` before the
    /// handshake completes.
    pub fn tls_exporter(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let ems = self
            .exporter_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        tls_exporter(suite.hash, ems, label, context, out);
        Ok(())
    }
}

impl ClientConnection {
    /// Starts a client handshake to `server_name`, emitting the `ClientHello`.
    /// `rng` supplies the ephemeral key shares and the client random. Offers all
    /// supported cipher suites and both key-exchange groups.
    pub fn new<R: RngCore>(config: ClientConfig, server_name: &str, rng: &mut R) -> Self {
        Self::new_with_offer(
            config,
            server_name,
            rng,
            &[
                CipherSuite::AES_128_GCM_SHA256,
                CipherSuite::AES_256_GCM_SHA384,
                CipherSuite::CHACHA20_POLY1305_SHA256,
            ],
            &[
                NamedGroup::X25519MLKEM768,
                NamedGroup::X25519,
                NamedGroup::SECP256R1,
            ],
        )
    }

    /// Like [`new`](Self::new) but with an explicit cipher-suite and
    /// key-exchange-group offer, letting callers (and tests) drive a specific
    /// negotiation outcome.
    pub(crate) fn new_with_offer<R: RngCore>(
        config: ClientConfig,
        server_name: &str,
        rng: &mut R,
        suites: &[CipherSuite],
        groups: &[NamedGroup],
    ) -> Self {
        let x25519 = X25519PrivateKey::generate(rng);
        let p256 = BoxedEcdhPrivateKey::generate(CurveId::P256, rng);
        let (mlkem, _) = MlKem768DecapsKey::generate(rng);
        let mut random: Random = [0u8; 32];
        rng.fill_bytes(&mut random);

        let mut conn = ClientConnection {
            core: ConnectionCore::new(),
            config,
            server_name: String::from(server_name),
            state: State::WaitServerHello,
            x25519,
            p256,
            mlkem,
            client_random: random,
            offered_suites: suites.to_vec(),
            offered_groups: groups.to_vec(),
            hrr_processed: false,
            suite: None,
            ks: None,
            client_hs_secret: None,
            server_hs_secret: None,
            client_app_secret: None,
            server_app_secret: None,
            exporter_secret: None,
            cert_chain: Vec::new(),
            leaf_key: None,
            last_ticket: None,
            alpn_negotiated: None,
        };
        let hello =
            conn.build_client_hello(random, String::from(server_name), suites, groups, &[], &[]);
        conn.core.emit_handshake(hello);
        conn
    }

    /// Builds a ClientHello. If `share_only` is non-empty, only those groups
    /// get a `key_share` entry (used for HRR retry, where the server picked a
    /// specific group); if empty, all `groups` get one. `extra_extensions`
    /// (typically the HRR-supplied `cookie`) are appended verbatim.
    fn build_client_hello(
        &self,
        random: Random,
        server_name: String,
        suites: &[CipherSuite],
        groups: &[NamedGroup],
        share_only: &[NamedGroup],
        extra_extensions: &[crate::tls::codec::RawExtension],
    ) -> Vec<u8> {
        let mut key_shares = Vec::new();
        for &g in groups {
            if !share_only.is_empty() && !share_only.contains(&g) {
                continue;
            }
            match g {
                NamedGroup::X25519 => {
                    key_shares.push((NamedGroup::X25519, self.x25519.public_key().to_vec()))
                }
                NamedGroup::SECP256R1 => {
                    key_shares.push((NamedGroup::SECP256R1, self.p256.public_key().to_sec1()))
                }
                NamedGroup::X25519MLKEM768 => {
                    // Client share: ML-KEM-768 encapsulation key ‖ X25519 key.
                    let mut share = self.mlkem.encapsulation_key().to_bytes().to_vec();
                    share.extend_from_slice(&self.x25519.public_key());
                    key_shares.push((NamedGroup::X25519MLKEM768, share));
                }
                _ => {}
            }
        }
        let mut extensions = alloc::vec![
            ext::server_name(&server_name),
            ext::supported_groups_list(groups),
            ext::signature_algorithms(),
            ext::client_supported_versions(),
            ext::client_key_shares(&key_shares),
        ];
        if !self.config.alpn_protocols.is_empty() {
            let protos: alloc::vec::Vec<&[u8]> = self
                .config
                .alpn_protocols
                .iter()
                .map(|v| v.as_slice())
                .collect();
            extensions.push(ext::alpn_protocols(&protos));
        }
        if let Some(limit) = self.config.record_size_limit {
            extensions.push(ext::record_size_limit(limit));
        }
        extensions.extend_from_slice(extra_extensions);
        ClientHello {
            random,
            session_id: Vec::new(),
            cipher_suites: suites.to_vec(),
            extensions,
        }
        .encode()
    }

    /// Feeds received TLS bytes.
    pub fn read_tls(&mut self, bytes: &[u8]) {
        self.core.read_tls(bytes);
    }

    /// Removes and returns bytes queued for transmission.
    pub fn write_tls(&mut self) -> Vec<u8> {
        self.core.write_tls()
    }

    /// Whether there are bytes queued for transmission.
    pub fn wants_write(&self) -> bool {
        self.core.wants_write()
    }

    /// Whether the handshake is still in progress.
    pub fn is_handshaking(&self) -> bool {
        !matches!(self.state, State::Connected | State::Closed)
    }

    /// Sends application data (only valid once the handshake completes).
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::InappropriateState);
        }
        self.core.send_application_data(data);
        Ok(())
    }

    /// Removes and returns any received application plaintext.
    pub fn take_received_plaintext(&mut self) -> Vec<u8> {
        self.core.take_received()
    }

    /// Queues a `close_notify`.
    pub fn send_close_notify(&mut self) {
        self.core.send_close_notify();
    }

    /// Processes all buffered records, advancing the handshake. On a protocol
    /// error it queues a fatal alert and returns the error.
    pub fn process_new_packets(&mut self) -> Result<(), Error> {
        loop {
            match self.core.next_message() {
                Ok(Some(Incoming::Handshake(msg))) => {
                    if let Err(e) = self.handle_handshake(msg) {
                        self.fail(&e);
                        return Err(e);
                    }
                }
                Ok(Some(Incoming::ApplicationData)) => {
                    if self.state != State::Connected {
                        let e = Error::UnexpectedMessage;
                        self.fail(&e);
                        return Err(e);
                    }
                }
                Ok(Some(Incoming::Alert(alert))) => {
                    if alert.description == AlertDescription::CloseNotify {
                        self.state = State::Closed;
                        return Ok(());
                    }
                    return Err(Error::AlertReceived(alert.description));
                }
                Ok(None) => return Ok(()),
                Err(e) => {
                    self.fail(&e);
                    return Err(e);
                }
            }
        }
    }

    fn fail(&mut self, error: &Error) {
        self.core.send_alert(alert_for(error));
        self.state = State::Closed;
    }

    fn handle_handshake(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        let mut c = ReadCursor::new(&msg);
        let (msg_type, body) = read_handshake(&mut c)?;

        match self.state {
            State::WaitServerHello => self.on_server_hello(msg_type, body, &msg),
            State::WaitEncryptedExtensions => self.on_encrypted_extensions(msg_type, &msg),
            State::WaitCertificate => self.on_certificate(msg_type, body, &msg),
            State::WaitCertificateVerify => self.on_certificate_verify(msg_type, body, &msg),
            State::WaitFinished => self.on_finished(msg_type, body, &msg),
            State::Connected => self.on_post_handshake(msg_type, body),
            State::Closed => Err(Error::UnexpectedMessage),
        }
    }

    /// Handles post-handshake messages (RFC 8446 §4.6).
    ///
    /// * `NewSessionTicket` (type 4) is parsed and the most recent one is
    ///   stashed in [`Self::last_ticket`] for later inspection / resumption.
    /// * `KeyUpdate` (type 24) rolls the read key forward and, if requested,
    ///   the write key plus an outgoing reply (`update_not_requested`).
    /// * Anything else fails with `unexpected_message`.
    fn on_post_handshake(&mut self, msg_type: u8, body: &[u8]) -> Result<(), Error> {
        match msg_type {
            hs_type::NEW_SESSION_TICKET => {
                let nst = NstWire::decode(body)?;
                self.last_ticket = Some(ReceivedSessionTicket::from_wire(nst)?);
                Ok(())
            }
            hs_type::KEY_UPDATE => self.handle_key_update(body),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Processes an incoming `KeyUpdate`. Re-keys the read side from the
    /// previous `server_application_traffic_secret_N`. If the peer asked us
    /// to update too (`update_requested == 1`), emit our own `KeyUpdate`
    /// (`update_not_requested`) and step the write side as well.
    fn handle_key_update(&mut self, body: &[u8]) -> Result<(), Error> {
        let ku = KeyUpdate::decode(body)?;
        let suite = self.suite.ok_or(Error::IllegalParameter)?;

        // Read side: derive next server_app_secret and re-key.
        let prev = self
            .server_app_secret
            .as_ref()
            .ok_or(Error::IllegalParameter)?;
        let next = next_traffic_secret(suite.hash, prev);
        self.core.set_read(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &next,
        ));
        self.server_app_secret = Some(next);

        if ku.request_update {
            // Send our own KeyUpdate (not_requested) and step the write side.
            // RFC 8446 §4.6.3: only one round of request is permitted, so we
            // reply with `update_not_requested` to avoid an infinite loop.
            self.send_key_update(false)?;
        }
        Ok(())
    }

    /// Emits a `KeyUpdate` and steps the write side. If `request_peer_update`
    /// is set, the peer will respond with its own `KeyUpdate(not_requested)`.
    fn send_key_update(&mut self, request_peer_update: bool) -> Result<(), Error> {
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let ku = KeyUpdate {
            request_update: request_peer_update,
        };
        // Emit the message under the *current* write key (RFC 8446 §4.6.3:
        // "after sending a KeyUpdate, the sender SHALL send all its traffic
        // using the next generation of keys").
        self.core.emit_handshake(ku.encode());

        let prev = self
            .client_app_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let next = next_traffic_secret(suite.hash, prev);
        self.core.set_write(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &next,
        ));
        self.client_app_secret = Some(next);
        Ok(())
    }

    /// Requests a key update from the peer. The write side rolls forward
    /// immediately; the read side rolls forward when the peer replies with
    /// its own `KeyUpdate(not_requested)`.
    ///
    /// Returns `Err(InappropriateState)` if called before the handshake
    /// completes.
    pub fn request_key_update(&mut self) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::InappropriateState);
        }
        self.send_key_update(true)
    }

    fn on_server_hello(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::SERVER_HELLO {
            return Err(Error::UnexpectedMessage);
        }
        let sh = ServerHello::decode(body)?;
        if is_hello_retry_request(&sh.random) {
            return self.on_hello_retry_request(sh, raw);
        }

        let suite = lookup_suite(sh.cipher_suite).ok_or(Error::HandshakeFailure)?;
        // Confirm TLS 1.3 was selected.
        let sv = ext::find(
            &sh.extensions,
            crate::tls::codec::ExtensionType::SUPPORTED_VERSIONS,
        )
        .ok_or(Error::UnsupportedVersion)?;
        if ext::parse_selected_version(sv)? != crate::tls::ProtocolVersion::TLSv1_3 {
            return Err(Error::UnsupportedVersion);
        }

        // The transcript hash now needs the negotiated hash.
        self.core.transcript.set_alg(suite.hash);
        self.core.transcript.update(raw);

        // ECDHE from the server's key share.
        let ks_ext = ext::find(&sh.extensions, crate::tls::codec::ExtensionType::KEY_SHARE)
            .ok_or(Error::HandshakeFailure)?;
        let (group, server_pub) = ext::parse_server_key_share(ks_ext)?;
        let shared = self.key_agreement(group, &server_pub)?;

        // Enter the handshake stage and derive the handshake traffic secrets.
        let mut ks = KeySchedule::new(suite.hash);
        ks.enter_handshake(shared.as_slice());
        let th = self.core.transcript.current_hash();
        let chts = ks.client_handshake_traffic_secret(th.as_slice());
        let shts = ks.server_handshake_traffic_secret(th.as_slice());

        // Server -> client uses the server handshake key; client -> server
        // (our Finished) uses the client handshake key.
        self.core.set_read(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &shts,
        ));
        self.core.set_write(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &chts,
        ));
        self.core.emit_ccs(); // middlebox compatibility

        self.suite = Some(suite);
        self.ks = Some(ks);
        self.client_hs_secret = Some(chts);
        self.server_hs_secret = Some(shts);
        self.state = State::WaitEncryptedExtensions;
        Ok(())
    }

    /// Handles a HelloRetryRequest (RFC 8446 §4.1.4): rewrites the transcript
    /// with the synthetic `message_hash`, validates the selected group is one
    /// we offered, and re-emits ClientHello2 narrowed to that group (echoing
    /// any cookie). Stays in `WaitServerHello` for the real ServerHello.
    fn on_hello_retry_request(&mut self, hrr: ServerHello, raw: &[u8]) -> Result<(), Error> {
        // Only one HRR per handshake (RFC §4.1.4: the client MUST abort with
        // unexpected_message if a second one arrives).
        if self.hrr_processed {
            return Err(Error::UnexpectedMessage);
        }

        // The HRR's cipher_suite must be one we offered.
        if !self.offered_suites.contains(&hrr.cipher_suite) {
            return Err(Error::IllegalParameter);
        }
        let suite = lookup_suite(hrr.cipher_suite).ok_or(Error::HandshakeFailure)?;

        // Validate selected version is TLS 1.3.
        let sv = ext::find(
            &hrr.extensions,
            crate::tls::codec::ExtensionType::SUPPORTED_VERSIONS,
        )
        .ok_or(Error::UnsupportedVersion)?;
        if ext::parse_selected_version(sv)? != crate::tls::ProtocolVersion::TLSv1_3 {
            return Err(Error::UnsupportedVersion);
        }

        // The HRR carries either a `key_share(selected_group)` or a `cookie`
        // (or both). The selected group, if present, must be in our offer.
        let selected_group =
            match ext::find(&hrr.extensions, crate::tls::codec::ExtensionType::KEY_SHARE) {
                Some(body) => {
                    let g = ext::parse_hrr_key_share(body)?;
                    if !self.offered_groups.contains(&g) {
                        return Err(Error::IllegalParameter);
                    }
                    Some(g)
                }
                None => None,
            };
        // If neither a new group nor a cookie is present, the HRR makes no
        // change and per RFC §4.1.4 the client MUST abort with
        // illegal_parameter (otherwise we'd loop).
        let cookie_ext = hrr
            .extensions
            .iter()
            .find(|(t, _)| t.0 == 0x002c) // cookie
            .cloned();
        if selected_group.is_none() && cookie_ext.is_none() {
            return Err(Error::IllegalParameter);
        }

        // Pin the negotiated hash and rewrite the transcript per §4.4.1.
        self.core.transcript.set_alg(suite.hash);
        self.core.transcript.replace_with_message_hash();
        self.core.transcript.update(raw);

        // Build CH2: same client_random, same offered_suites/groups, narrow
        // the key_share list to the selected group, echo the cookie verbatim.
        let share_only: alloc::vec::Vec<NamedGroup> = selected_group.into_iter().collect();
        let extras: alloc::vec::Vec<crate::tls::codec::RawExtension> =
            cookie_ext.into_iter().collect();
        let ch2 = self.build_client_hello(
            self.client_random,
            self.server_name.clone(),
            &self.offered_suites.clone(),
            &self.offered_groups.clone(),
            &share_only,
            &extras,
        );
        self.core.emit_handshake(ch2);
        self.hrr_processed = true;
        // Stay in WaitServerHello for the real ServerHello.
        Ok(())
    }

    fn key_agreement(&self, group: NamedGroup, server_pub: &[u8]) -> Result<Secret, Error> {
        match group {
            NamedGroup::X25519 => {
                let peer: [u8; 32] = server_pub.try_into().map_err(|_| Error::Decode)?;
                Ok(Secret::new(&self.x25519.diffie_hellman(&peer)))
            }
            NamedGroup::SECP256R1 => {
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, server_pub)
                    .map_err(|_| Error::Decode)?;
                let shared = self
                    .p256
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?;
                Ok(Secret::new(&shared))
            }
            NamedGroup::X25519MLKEM768 => {
                // Server share: ML-KEM ciphertext (1088) ‖ X25519 key (32).
                if server_pub.len() != CIPHERTEXT_BYTES + 32 {
                    return Err(Error::Decode);
                }
                let mut ct = [0u8; CIPHERTEXT_BYTES];
                ct.copy_from_slice(&server_pub[..CIPHERTEXT_BYTES]);
                let peer: [u8; 32] = server_pub[CIPHERTEXT_BYTES..]
                    .try_into()
                    .map_err(|_| Error::Decode)?;
                let ml_ss = self.mlkem.decapsulate(&MlKem768Ciphertext::from_bytes(ct));
                let x_ss = self.x25519.diffie_hellman(&peer);
                // Combined secret: ML-KEM shared secret first, then X25519.
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&ml_ss);
                combined[32..].copy_from_slice(&x_ss);
                Ok(Secret::new(&combined))
            }
            _ => Err(Error::HandshakeFailure),
        }
    }

    fn on_encrypted_extensions(&mut self, msg_type: u8, raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::ENCRYPTED_EXTENSIONS {
            return Err(Error::UnexpectedMessage);
        }
        // Parse the EE body to extract ALPN, ignoring others.
        // The handshake body lives in raw[4..] (4-byte header).
        if raw.len() >= 4 {
            let body = &raw[4..];
            let mut c = ReadCursor::new(body);
            let exts_bytes = c.vec_u16()?;
            let mut ec = ReadCursor::new(exts_bytes);
            while !ec.is_empty() {
                let ty = ec.u16()?;
                let ext_body = ec.vec_u16()?;
                if ty == crate::tls::codec::ExtensionType::ALPN.0 {
                    let names = ext::parse_alpn(ext_body)?;
                    if names.len() != 1 {
                        // RFC 7301: server MUST select exactly one protocol.
                        return Err(Error::IllegalParameter);
                    }
                    // The picked protocol must have been in our offer.
                    if !self.config.alpn_protocols.iter().any(|p| p == &names[0]) {
                        return Err(Error::IllegalParameter);
                    }
                    self.alpn_negotiated = Some(names.into_iter().next().unwrap());
                } else if ty == crate::tls::codec::ExtensionType::RECORD_SIZE_LIMIT.0 {
                    let limit = ext::parse_record_size_limit(ext_body)?;
                    self.core.set_peer_record_size_limit(limit);
                }
            }
        }
        self.core.transcript.update(raw);
        self.state = State::WaitCertificate;
        Ok(())
    }

    fn on_certificate(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::CERTIFICATE {
            return Err(Error::UnexpectedMessage);
        }
        self.cert_chain = parse_certificate_list(body)?;
        if self.cert_chain.is_empty() {
            return Err(Error::BadCertificate);
        }
        self.core.transcript.update(raw);
        self.state = State::WaitCertificateVerify;
        Ok(())
    }

    fn on_certificate_verify(
        &mut self,
        msg_type: u8,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), Error> {
        if msg_type != hs_type::CERTIFICATE_VERIFY {
            return Err(Error::UnexpectedMessage);
        }
        let mut c = ReadCursor::new(body);
        let scheme = SignatureScheme(c.u16()?);
        let signature = c.vec_u16()?.to_vec();
        c.expect_empty()?;

        // Always reject a malformed leaf certificate, regardless of policy.
        let leaf =
            Certificate::from_der(self.cert_chain[0].clone()).map_err(|_| Error::BadCertificate)?;
        leaf.check_well_formed()
            .map_err(|_| Error::BadCertificate)?;

        // Recover the leaf key, verifying the chain, validity, and host name
        // unless the configuration disables certificate verification.
        let leaf_key = if self.config.verify_certificates {
            let now = self.config.verification_time.clone().or_else(system_now);
            let key = verify_chain(&self.config.roots, &self.cert_chain, now.as_ref())?;
            verify_hostname(&leaf, &self.server_name)?;
            key
        } else {
            leaf.subject_public_key()
                .map_err(|_| Error::BadCertificate)?
        };

        let th = self.core.transcript.current_hash();
        let content = certificate_verify_content(true, th.as_slice());
        verify_signature(scheme, &leaf_key, &content, &signature)?;

        self.leaf_key = Some(leaf_key);
        self.core.transcript.update(raw);
        self.state = State::WaitFinished;
        Ok(())
    }

    fn on_finished(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::FINISHED {
            return Err(Error::UnexpectedMessage);
        }
        let suite = self.suite.expect("suite set");
        let shts = self.server_hs_secret.as_ref().expect("server hs secret");

        // Verify the server Finished over Hash(CH..CertificateVerify).
        let th = self.core.transcript.current_hash();
        let expected = finished_verify_data(suite.hash, shts, th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.core.transcript.update(raw);

        // Derive the application traffic secrets over Hash(CH..server Finished).
        let ks = self.ks.as_mut().expect("key schedule");
        ks.enter_master();
        let th_app = self.core.transcript.current_hash();
        let cats = ks.client_application_traffic_secret(th_app.as_slice());
        let sats = ks.server_application_traffic_secret(th_app.as_slice());
        let ems = ks.exporter_master_secret(th_app.as_slice());
        self.exporter_secret = Some(ems);

        // Our Finished, over Hash(CH..server Finished), under the client
        // handshake key.
        let chts = self.client_hs_secret.as_ref().expect("client hs secret");
        let verify_data = finished_verify_data(suite.hash, chts, th_app.as_slice());
        let finished = build_finished(verify_data.as_slice());
        self.core.emit_handshake(finished);

        // Switch to application traffic keys.
        self.core.set_write(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &cats,
        ));
        self.core.set_read(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &sats,
        ));
        // Retain both directions' app secrets so we can step them on KeyUpdate.
        self.client_app_secret = Some(cats);
        self.server_app_secret = Some(sats);
        // RFC 8446 §5: ChangeCipherSpec is no longer expected after the
        // handshake completes.
        self.core.close_ccs_window();
        self.state = State::Connected;
        Ok(())
    }
}

/// Maps an internal error to the alert to send the peer.
fn alert_for(error: &Error) -> AlertDescription {
    match error {
        Error::Decode => AlertDescription::DecodeError,
        Error::UnexpectedMessage => AlertDescription::UnexpectedMessage,
        Error::BadRecordMac => AlertDescription::BadRecordMac,
        Error::BadCertificate => AlertDescription::BadCertificate,
        Error::UnsupportedVersion => AlertDescription::ProtocolVersion,
        Error::PeerMisbehaved | Error::InappropriateState | Error::IllegalParameter => {
            AlertDescription::IllegalParameter
        }
        Error::RecordOverflow => AlertDescription::RecordOverflow,
        Error::TooManyRecords => AlertDescription::InternalError,
        Error::NoApplicationProtocol => AlertDescription::NoApplicationProtocol,
        _ => AlertDescription::HandshakeFailure,
    }
}

/// The HelloRetryRequest sentinel `ServerHello.random` (RFC 8446 §4.1.3):
/// `SHA-256("HelloRetryRequest")`.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

fn is_hello_retry_request(random: &Random) -> bool {
    random == &HRR_RANDOM
}

/// Parses a TLS 1.3 `Certificate` message body into a list of DER certificates
/// (end-entity first).
fn parse_certificate_list(body: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut c = ReadCursor::new(body);
    let _context = c.vec_u8()?; // certificate_request_context
    let list = c.vec_u24()?;
    c.expect_empty()?;

    let mut entries = ReadCursor::new(list);
    let mut certs = Vec::new();
    while !entries.is_empty() {
        let cert = entries.vec_u24()?.to_vec();
        let _exts = entries.vec_u16()?; // per-certificate extensions
        certs.push(cert);
    }
    Ok(certs)
}

/// Builds a `Finished` handshake message from its `verify_data`.
fn build_finished(verify_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + verify_data.len());
    out.push(hs_type::FINISHED);
    let len = verify_data.len();
    out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    out.extend_from_slice(verify_data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::tls::ContentType;
    use crate::tls::codec::{ClientHello, ExtensionType, read_record};

    #[test]
    fn client_hello_is_well_formed() {
        let mut rng = HmacDrbg::<Sha256>::new(b"p8-client", b"nonce", &[]);
        let config = ClientConfig::new(RootCertStore::new());
        let mut client = ClientConnection::new(config, "example.com", &mut rng);
        assert!(client.is_handshaking());

        let out = client.write_tls();
        let rec = read_record(&out).unwrap().unwrap();
        assert_eq!(rec.content_type, ContentType::Handshake);
        assert_eq!(rec.len, out.len());

        let mut c = ReadCursor::new(rec.fragment);
        assert_eq!(c.u8().unwrap(), hs_type::CLIENT_HELLO);
        let body = c.vec_u24().unwrap();
        let ch = ClientHello::decode(body).unwrap();

        assert_eq!(ch.cipher_suites.len(), 3);
        assert!(ch.session_id.is_empty());
        for ty in [
            ExtensionType::SERVER_NAME,
            ExtensionType::SUPPORTED_GROUPS,
            ExtensionType::SIGNATURE_ALGORITHMS,
            ExtensionType::SUPPORTED_VERSIONS,
            ExtensionType::KEY_SHARE,
        ] {
            assert!(ext::find(&ch.extensions, ty).is_some());
        }
        // The key_share offers x25519mlkem768, x25519 and secp256r1.
        let ks = ext::find(&ch.extensions, ExtensionType::KEY_SHARE).unwrap();
        assert_eq!(ext::parse_client_key_shares(ks).unwrap().len(), 3);
    }

    #[test]
    fn rejects_garbage_server_hello() {
        let mut rng = HmacDrbg::<Sha256>::new(b"p8-client-2", b"nonce", &[]);
        let mut client =
            ClientConnection::new(ClientConfig::new(RootCertStore::new()), "h", &mut rng);
        let _ = client.write_tls();
        // A handshake record claiming to be a (truncated) ServerHello.
        client.read_tls(&[0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00]);
        assert!(client.process_new_packets().is_err());
    }
}
