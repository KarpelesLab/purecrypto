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
use crate::rng::RngCore;
use crate::tls::codec::extension as ext;
use crate::tls::codec::{
    CipherSuite, ClientHello, NamedGroup, Random, ReadCursor, ServerHello, SignatureScheme,
    hs_type, read_handshake,
};
use crate::tls::crypto::{
    KeySchedule, RecordCrypter, Secret, SuiteParams, certificate_verify_content,
    finished_verify_data, lookup_suite, verify_signature,
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
}

impl ClientConfig {
    /// A configuration trusting the given roots, with certificate verification
    /// enabled.
    pub fn new(roots: RootCertStore) -> Self {
        ClientConfig {
            roots,
            verify_certificates: true,
            verification_time: None,
        }
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

    suite: Option<SuiteParams>,
    ks: Option<KeySchedule>,
    client_hs_secret: Option<Secret>,
    server_hs_secret: Option<Secret>,

    cert_chain: Vec<Vec<u8>>,
    leaf_key: Option<AnyPublicKey>,
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
}

impl ClientConnection {
    /// Starts a client handshake to `server_name`, emitting the `ClientHello`.
    /// `rng` supplies the ephemeral key shares and the client random. Offers
    /// both cipher suites and both key-exchange groups.
    pub fn new<R: RngCore>(config: ClientConfig, server_name: &str, rng: &mut R) -> Self {
        Self::new_with_offer(
            config,
            server_name,
            rng,
            &[
                CipherSuite::AES_128_GCM_SHA256,
                CipherSuite::AES_256_GCM_SHA384,
            ],
            &[NamedGroup::X25519, NamedGroup::SECP256R1],
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
        let mut random: Random = [0u8; 32];
        rng.fill_bytes(&mut random);

        let mut conn = ClientConnection {
            core: ConnectionCore::new(),
            config,
            server_name: String::from(server_name),
            state: State::WaitServerHello,
            x25519,
            p256,
            suite: None,
            ks: None,
            client_hs_secret: None,
            server_hs_secret: None,
            cert_chain: Vec::new(),
            leaf_key: None,
        };
        let hello = conn.build_client_hello(random, String::from(server_name), suites, groups);
        conn.core.emit_handshake(hello);
        conn
    }

    fn build_client_hello(
        &self,
        random: Random,
        server_name: String,
        suites: &[CipherSuite],
        groups: &[NamedGroup],
    ) -> Vec<u8> {
        let mut key_shares = Vec::new();
        for &g in groups {
            match g {
                NamedGroup::X25519 => {
                    key_shares.push((NamedGroup::X25519, self.x25519.public_key().to_vec()))
                }
                NamedGroup::SECP256R1 => {
                    key_shares.push((NamedGroup::SECP256R1, self.p256.public_key().to_sec1()))
                }
                _ => {}
            }
        }
        let extensions = alloc::vec![
            ext::server_name(&server_name),
            ext::supported_groups_list(groups),
            ext::signature_algorithms(),
            ext::client_supported_versions(),
            ext::client_key_shares(&key_shares),
        ];
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
            State::Connected => self.on_post_handshake(msg_type),
            State::Closed => Err(Error::UnexpectedMessage),
        }
    }

    /// Handles post-handshake messages (RFC 8446 §4.6). NewSessionTicket is
    /// ignored (resumption is unsupported); KeyUpdate is accepted but not yet
    /// acted on.
    fn on_post_handshake(&mut self, msg_type: u8) -> Result<(), Error> {
        match msg_type {
            hs_type::NEW_SESSION_TICKET | hs_type::KEY_UPDATE => Ok(()),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    fn on_server_hello(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::SERVER_HELLO {
            return Err(Error::UnexpectedMessage);
        }
        let sh = ServerHello::decode(body)?;
        if is_hello_retry_request(&sh.random) {
            // HelloRetryRequest is not yet supported.
            return Err(Error::HandshakeFailure);
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
        self.core
            .set_read(RecordCrypter::new(suite.hash, suite.key_len, &shts));
        self.core
            .set_write(RecordCrypter::new(suite.hash, suite.key_len, &chts));
        self.core.emit_ccs(); // middlebox compatibility

        self.suite = Some(suite);
        self.ks = Some(ks);
        self.client_hs_secret = Some(chts);
        self.server_hs_secret = Some(shts);
        self.state = State::WaitEncryptedExtensions;
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
            _ => Err(Error::HandshakeFailure),
        }
    }

    fn on_encrypted_extensions(&mut self, msg_type: u8, raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::ENCRYPTED_EXTENSIONS {
            return Err(Error::UnexpectedMessage);
        }
        // The contents (ALPN, server-name ack, etc.) are not acted on yet.
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

        // Our Finished, over Hash(CH..server Finished), under the client
        // handshake key.
        let chts = self.client_hs_secret.as_ref().expect("client hs secret");
        let verify_data = finished_verify_data(suite.hash, chts, th_app.as_slice());
        let finished = build_finished(verify_data.as_slice());
        self.core.emit_handshake(finished);

        // Switch to application traffic keys.
        self.core
            .set_write(RecordCrypter::new(suite.hash, suite.key_len, &cats));
        self.core
            .set_read(RecordCrypter::new(suite.hash, suite.key_len, &sats));
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
        Error::PeerMisbehaved | Error::InappropriateState => AlertDescription::IllegalParameter,
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

        assert_eq!(ch.cipher_suites.len(), 2);
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
        // The key_share offers both x25519 and secp256r1.
        let ks = ext::find(&ch.extensions, ExtensionType::KEY_SHARE).unwrap();
        assert_eq!(ext::parse_client_key_shares(ks).unwrap().len(), 2);
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
