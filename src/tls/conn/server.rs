//! The TLS 1.3 server handshake state machine.
//!
//! [`ServerConnection`] consumes a `ClientHello`, selects a cipher suite and
//! key-exchange group, and emits the server flight (`ServerHello`, then the
//! encrypted `EncryptedExtensions`, `Certificate`, `CertificateVerify`,
//! `Finished`). It then verifies the client's `Finished` and switches to the
//! application traffic keys.

use super::common::{ConnectionCore, Incoming};
use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{
    BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, CurveId, Ed25519PrivateKey,
};
use crate::hash::{Sha256, Sha384, Sha512};
use crate::mlkem::{ENCAPS_KEY_BYTES, MlKem768EncapsKey};
use crate::rng::RngCore;
use crate::rsa::BoxedRsaPrivateKey;
use crate::tls::codec::extension as ext;
use crate::tls::codec::{
    ClientHello, ExtensionType, KeyUpdate, NamedGroup, Random, ReadCursor, ServerHello,
    SignatureScheme, hs_type, read_handshake, with_len_u16, with_len_u24,
};
use crate::tls::crypto::{
    KeySchedule, RecordCrypter, Secret, SuiteParams, certificate_verify_content,
    finished_verify_data, next_traffic_secret, supported_suites,
};
use crate::tls::{AlertDescription, Error};
use alloc::vec::Vec;

use crate::ct::ConstantTimeEq;

/// The server's signing key, used to sign the `CertificateVerify`.
enum ServerKey {
    /// An RSA key; signs with `rsa_pss_rsae_sha256`.
    Rsa(BoxedRsaPrivateKey),
    /// An ECDSA key; signs with the scheme matching its curve.
    Ecdsa(BoxedEcdsaPrivateKey),
    /// An Ed25519 key; signs with `ed25519`.
    Ed25519(Ed25519PrivateKey),
}

/// Configuration for a TLS server: a certificate chain and its signing key.
pub struct ServerConfig {
    cert_chain: Vec<Vec<u8>>,
    key: ServerKey,
    /// ALPN protocols this server accepts, in preference order. The server
    /// picks its first entry that also appears in the client's offer.
    alpn_protocols: Vec<Vec<u8>>,
    /// `record_size_limit` (RFC 8449) we advertise to the client. None
    /// suppresses the extension.
    record_size_limit: Option<u16>,
}

impl ServerConfig {
    /// A configuration presenting `cert_chain` (leaf first) and signing with an
    /// RSA private `key` (RSA-PSS).
    pub fn with_rsa(cert_chain: Vec<Vec<u8>>, key: BoxedRsaPrivateKey) -> Self {
        ServerConfig {
            cert_chain,
            key: ServerKey::Rsa(key),
            alpn_protocols: Vec::new(),
            record_size_limit: None,
        }
    }

    /// A configuration presenting `cert_chain` (leaf first) and signing with an
    /// ECDSA private `key` (the scheme follows the key's curve).
    pub fn with_ecdsa(cert_chain: Vec<Vec<u8>>, key: BoxedEcdsaPrivateKey) -> Self {
        ServerConfig {
            cert_chain,
            key: ServerKey::Ecdsa(key),
            alpn_protocols: Vec::new(),
            record_size_limit: None,
        }
    }

    /// A configuration presenting `cert_chain` (leaf first) and signing with an
    /// Ed25519 private `key`.
    pub fn with_ed25519(cert_chain: Vec<Vec<u8>>, key: Ed25519PrivateKey) -> Self {
        ServerConfig {
            cert_chain,
            key: ServerKey::Ed25519(key),
            alpn_protocols: Vec::new(),
            record_size_limit: None,
        }
    }

    /// Sets the ALPN protocols this server is willing to negotiate, in
    /// preference order. If the client offers ALPN with no overlap, the
    /// handshake fails with `no_application_protocol`.
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Advertises `record_size_limit = limit` (RFC 8449).
    pub fn with_record_size_limit(mut self, limit: u16) -> Self {
        self.record_size_limit = Some(limit);
        self
    }

    fn signature_scheme(&self) -> SignatureScheme {
        match &self.key {
            ServerKey::Rsa(_) => SignatureScheme::RSA_PSS_RSAE_SHA256,
            ServerKey::Ecdsa(k) => match k.curve() {
                CurveId::P256 => SignatureScheme::ECDSA_SECP256R1_SHA256,
                CurveId::P384 => SignatureScheme::ECDSA_SECP384R1_SHA384,
                CurveId::P521 => SignatureScheme::ECDSA_SECP521R1_SHA512,
                CurveId::Secp256k1 => SignatureScheme::ECDSA_SECP256R1_SHA256,
            },
            ServerKey::Ed25519(_) => SignatureScheme::ED25519,
        }
    }
}

/// The server handshake progress.
#[derive(PartialEq, Eq)]
enum State {
    WaitClientHello,
    WaitClientFinished,
    Connected,
    Closed,
}

/// A TLS 1.3 server connection.
pub struct ServerConnection<R: RngCore> {
    core: ConnectionCore,
    config: ServerConfig,
    rng: R,
    state: State,

    suite: Option<SuiteParams>,
    client_hs_secret: Option<Secret>,
    client_app_secret: Option<Secret>,
    /// Current write-side (`server_application_traffic_secret_N`); stepped
    /// by each outgoing `KeyUpdate`.
    server_app_secret: Option<Secret>,
    /// ALPN protocol the server picked from the client's offer.
    alpn_negotiated: Option<Vec<u8>>,
    #[cfg(test)]
    server_hs_secret: Option<Secret>,
}

impl<R: RngCore> ServerConnection<R> {
    /// Creates a server awaiting a `ClientHello`. `rng` supplies the server
    /// random, the ephemeral key share, and (for RSA) the PSS salt.
    pub fn new(config: ServerConfig, rng: R) -> Self {
        ServerConnection {
            core: ConnectionCore::new(),
            config,
            rng,
            state: State::WaitClientHello,
            suite: None,
            client_hs_secret: None,
            client_app_secret: None,
            server_app_secret: None,
            alpn_negotiated: None,
            #[cfg(test)]
            server_hs_secret: None,
        }
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

    /// The ALPN protocol picked from the client's offer, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_negotiated.as_deref()
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

    /// Test/internal hook: emit an arbitrary post-handshake handshake message
    /// (e.g. a `NewSessionTicket`) under the application traffic key.
    ///
    /// Only valid once the handshake completes; the caller is responsible for
    /// building a syntactically valid handshake message body.
    #[cfg(test)]
    pub(crate) fn emit_post_handshake(&mut self, message: alloc::vec::Vec<u8>) {
        debug_assert!(matches!(self.state, State::Connected));
        self.core.emit_handshake(message);
    }

    /// Processes all buffered records, advancing the handshake.
    pub fn process_new_packets(&mut self) -> Result<(), Error> {
        loop {
            match self.core.next_message() {
                Ok(Some(Incoming::Handshake(msg))) => {
                    if let Err(e) = self.handle_handshake(msg) {
                        self.core.send_alert(alert_for(&e));
                        self.state = State::Closed;
                        return Err(e);
                    }
                }
                Ok(Some(Incoming::ApplicationData)) => {
                    if self.state != State::Connected {
                        return Err(Error::UnexpectedMessage);
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
                    self.core.send_alert(alert_for(&e));
                    self.state = State::Closed;
                    return Err(e);
                }
            }
        }
    }

    fn handle_handshake(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        let mut c = ReadCursor::new(&msg);
        let (msg_type, body) = read_handshake(&mut c)?;
        match self.state {
            State::WaitClientHello => self.on_client_hello(msg_type, body, &msg),
            State::WaitClientFinished => self.on_client_finished(msg_type, body, &msg),
            State::Connected => self.on_post_handshake(msg_type, body),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Handles post-handshake messages (RFC 8446 §4.6) on the server side.
    /// Currently only `KeyUpdate` is expected from the client; future commits
    /// may handle post-handshake `Certificate` / `CertificateVerify` for mTLS.
    fn on_post_handshake(&mut self, msg_type: u8, body: &[u8]) -> Result<(), Error> {
        match msg_type {
            hs_type::KEY_UPDATE => self.handle_key_update(body),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Symmetric counterpart of the client's `handle_key_update` — derives
    /// the next `client_application_traffic_secret`, re-keys the read side,
    /// and replies with our own `KeyUpdate(not_requested)` if the peer
    /// requested it.
    fn handle_key_update(&mut self, body: &[u8]) -> Result<(), Error> {
        let ku = KeyUpdate::decode(body)?;
        let suite = self.suite.ok_or(Error::IllegalParameter)?;
        let prev = self
            .client_app_secret
            .as_ref()
            .ok_or(Error::IllegalParameter)?;
        let next = next_traffic_secret(suite.hash, prev);
        self.core.set_read(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &next,
        ));
        self.client_app_secret = Some(next);
        if ku.request_update {
            self.send_key_update(false)?;
        }
        Ok(())
    }

    /// Emits a `KeyUpdate` and rolls the write side forward.
    fn send_key_update(&mut self, request_peer_update: bool) -> Result<(), Error> {
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let ku = KeyUpdate {
            request_update: request_peer_update,
        };
        self.core.emit_handshake(ku.encode());
        let prev = self
            .server_app_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let next = next_traffic_secret(suite.hash, prev);
        self.core.set_write(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &next,
        ));
        self.server_app_secret = Some(next);
        Ok(())
    }

    /// Requests a key update from the peer; symmetric to
    /// [`ClientConnection::request_key_update`](super::ClientConnection::request_key_update).
    pub fn request_key_update(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Connected) {
            return Err(Error::InappropriateState);
        }
        self.send_key_update(true)
    }

    fn on_client_hello(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::CLIENT_HELLO {
            return Err(Error::UnexpectedMessage);
        }
        let ch = ClientHello::decode(body)?;

        // Negotiate the cipher suite (our preference order).
        let suite = supported_suites()
            .iter()
            .copied()
            .find(|s| ch.cipher_suites.contains(&s.suite))
            .ok_or(Error::HandshakeFailure)?;

        // Require TLS 1.3.
        let sv = ext::find(&ch.extensions, ExtensionType::SUPPORTED_VERSIONS)
            .ok_or(Error::UnsupportedVersion)?;
        if !ext::client_offers_tls13(sv)? {
            return Err(Error::UnsupportedVersion);
        }

        // The client must accept the signature scheme our certificate uses.
        let our_scheme = self.config.signature_scheme();
        let sig_algs = ext::find(&ch.extensions, ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or(Error::HandshakeFailure)?;
        if !ext::parse_signature_algorithms(sig_algs)?.contains(&our_scheme) {
            return Err(Error::HandshakeFailure);
        }

        // ALPN: pick our first preference that appears in the client's offer.
        // If the client offered ALPN but there's no overlap *and* we have any
        // protocols configured, fail with `no_application_protocol`.
        if let Some(client_alpn_body) = ext::find(&ch.extensions, ExtensionType::ALPN) {
            let offered = ext::parse_alpn(client_alpn_body)?;
            if !self.config.alpn_protocols.is_empty() {
                let pick = self
                    .config
                    .alpn_protocols
                    .iter()
                    .find(|p| offered.iter().any(|o| o == *p))
                    .ok_or(Error::NoApplicationProtocol)?;
                self.alpn_negotiated = Some(pick.clone());
            }
        }

        // record_size_limit: parse the peer's advertisement.
        if let Some(rsl_body) = ext::find(&ch.extensions, ExtensionType::RECORD_SIZE_LIMIT) {
            let limit = ext::parse_record_size_limit(rsl_body)?;
            self.core.set_peer_record_size_limit(limit);
        }

        self.core.transcript.set_alg(suite.hash);
        self.core.transcript.update(raw);

        // Pick a key-exchange group offered by the client.
        let ks_ext =
            ext::find(&ch.extensions, ExtensionType::KEY_SHARE).ok_or(Error::HandshakeFailure)?;
        let shares = ext::parse_client_key_shares(ks_ext)?;
        let (group, client_pub) = shares
            .iter()
            .find(|(g, _)| {
                matches!(
                    *g,
                    NamedGroup::X25519MLKEM768 | NamedGroup::X25519 | NamedGroup::SECP256R1
                )
            })
            .ok_or(Error::HandshakeFailure)?;

        // Server random and ephemeral key share.
        let mut random: Random = [0u8; 32];
        self.rng.fill_bytes(&mut random);
        let (server_pub, shared) = self.key_agreement(*group, client_pub)?;

        // ServerHello with the selected suite and key share.
        let server_hello = ServerHello {
            random,
            session_id: ch.session_id.clone(),
            cipher_suite: suite.suite,
            extensions: alloc::vec![
                ext::server_key_share(*group, &server_pub),
                ext::server_supported_versions(),
            ],
        }
        .encode();
        self.core.emit_handshake(server_hello);

        // Derive handshake traffic secrets over Hash(CH..SH).
        let mut ks = KeySchedule::new(suite.hash);
        ks.enter_handshake(shared.as_slice());
        let th = self.core.transcript.current_hash();
        let chts = ks.client_handshake_traffic_secret(th.as_slice());
        let shts = ks.server_handshake_traffic_secret(th.as_slice());

        // Server writes with the server handshake key; reads (client Finished)
        // with the client handshake key.
        self.core.set_write(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &shts,
        ));
        self.core.set_read(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &chts,
        ));
        self.core.emit_ccs();

        // Encrypted server flight.
        self.send_encrypted_extensions();
        self.send_certificate();
        self.send_certificate_verify()?;
        self.send_finished(suite, &shts);

        // Derive application traffic secrets over Hash(CH..server Finished).
        ks.enter_master();
        let th_app = self.core.transcript.current_hash();
        let cats = ks.client_application_traffic_secret(th_app.as_slice());
        let sats = ks.server_application_traffic_secret(th_app.as_slice());

        // The server's subsequent writes use the application key; it still
        // reads the client Finished with the client handshake key.
        self.core.set_write(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &sats,
        ));

        self.suite = Some(suite);
        self.client_hs_secret = Some(chts);
        self.client_app_secret = Some(cats);
        self.server_app_secret = Some(sats);
        #[cfg(test)]
        {
            self.server_hs_secret = Some(shts);
        }
        self.state = State::WaitClientFinished;
        Ok(())
    }

    fn key_agreement(
        &mut self,
        group: NamedGroup,
        client_pub: &[u8],
    ) -> Result<(Vec<u8>, Secret), Error> {
        match group {
            NamedGroup::X25519 => {
                let sk = X25519PrivateKey::generate(&mut self.rng);
                let peer: [u8; 32] = client_pub.try_into().map_err(|_| Error::Decode)?;
                let shared = sk.diffie_hellman(&peer);
                Ok((sk.public_key().to_vec(), Secret::new(&shared)))
            }
            NamedGroup::SECP256R1 => {
                let sk = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut self.rng);
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, client_pub)
                    .map_err(|_| Error::Decode)?;
                let shared = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?;
                Ok((sk.public_key().to_sec1(), Secret::new(&shared)))
            }
            NamedGroup::X25519MLKEM768 => {
                // Client share: ML-KEM-768 encapsulation key (1184) ‖ X25519 (32).
                if client_pub.len() != ENCAPS_KEY_BYTES + 32 {
                    return Err(Error::Decode);
                }
                let mut ek = [0u8; ENCAPS_KEY_BYTES];
                ek.copy_from_slice(&client_pub[..ENCAPS_KEY_BYTES]);
                let peer: [u8; 32] = client_pub[ENCAPS_KEY_BYTES..]
                    .try_into()
                    .map_err(|_| Error::Decode)?;

                let (ct, ml_ss) = MlKem768EncapsKey::from_bytes(ek).encapsulate(&mut self.rng);
                let sk = X25519PrivateKey::generate(&mut self.rng);
                let x_ss = sk.diffie_hellman(&peer);

                // Server share: ML-KEM ciphertext ‖ X25519 key.
                let mut share = ct.to_bytes().to_vec();
                share.extend_from_slice(&sk.public_key());
                // Combined secret: ML-KEM shared secret first, then X25519.
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&ml_ss);
                combined[32..].copy_from_slice(&x_ss);
                Ok((share, Secret::new(&combined)))
            }
            _ => Err(Error::HandshakeFailure),
        }
    }

    fn send_encrypted_extensions(&mut self) {
        let mut msg = alloc::vec![hs_type::ENCRYPTED_EXTENSIONS];
        with_len_u24(&mut msg, |b| {
            with_len_u16(b, |exts| {
                // ALPN, when negotiated, echoes the chosen protocol as a list
                // of one entry per RFC 7301.
                if let Some(p) = self.alpn_negotiated.as_ref() {
                    let (ty, body) = ext::alpn_protocols(&[p.as_slice()]);
                    crate::tls::codec::put_u16(exts, ty.0);
                    crate::tls::codec::with_len_u16(exts, |b| b.extend_from_slice(&body));
                }
                // record_size_limit, when configured.
                if let Some(limit) = self.config.record_size_limit {
                    let (ty, body) = ext::record_size_limit(limit);
                    crate::tls::codec::put_u16(exts, ty.0);
                    crate::tls::codec::with_len_u16(exts, |b| b.extend_from_slice(&body));
                }
            });
        });
        self.core.emit_handshake(msg);
    }

    fn send_certificate(&mut self) {
        let mut msg = alloc::vec![hs_type::CERTIFICATE];
        with_len_u24(&mut msg, |b| {
            b.push(0); // certificate_request_context: empty
            with_len_u24(b, |list| {
                for cert in &self.config.cert_chain {
                    with_len_u24(list, |c| c.extend_from_slice(cert));
                    with_len_u16(list, |_| {}); // per-certificate extensions
                }
            });
        });
        self.core.emit_handshake(msg);
    }

    fn send_certificate_verify(&mut self) -> Result<(), Error> {
        let th = self.core.transcript.current_hash();
        let content = certificate_verify_content(true, th.as_slice());
        let scheme = self.config.signature_scheme();
        let signature = match &self.config.key {
            ServerKey::Rsa(k) => k
                .sign_pss::<Sha256, _>(&content, &mut self.rng)
                .map_err(|_| Error::HandshakeFailure)?,
            ServerKey::Ecdsa(k) => {
                let sig = match k.curve() {
                    CurveId::P384 => k.sign::<Sha384>(&content),
                    CurveId::P521 => k.sign::<Sha512>(&content),
                    _ => k.sign::<Sha256>(&content),
                }
                .map_err(|_| Error::HandshakeFailure)?;
                sig.to_der(k.curve())
            }
            ServerKey::Ed25519(k) => k.sign(&content).to_bytes().to_vec(),
        };

        let mut msg = alloc::vec![hs_type::CERTIFICATE_VERIFY];
        with_len_u24(&mut msg, |b| {
            b.extend_from_slice(&scheme.0.to_be_bytes());
            with_len_u16(b, |s| s.extend_from_slice(&signature));
        });
        self.core.emit_handshake(msg);
        Ok(())
    }

    fn send_finished(&mut self, suite: SuiteParams, shts: &Secret) {
        let th = self.core.transcript.current_hash();
        let verify_data = finished_verify_data(suite.hash, shts, th.as_slice());
        let mut msg = alloc::vec![hs_type::FINISHED];
        with_len_u24(&mut msg, |b| b.extend_from_slice(verify_data.as_slice()));
        self.core.emit_handshake(msg);
    }

    fn on_client_finished(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::FINISHED {
            return Err(Error::UnexpectedMessage);
        }
        let suite = self.suite.expect("suite set");
        let chts = self.client_hs_secret.as_ref().expect("client hs secret");

        let th = self.core.transcript.current_hash();
        let expected = finished_verify_data(suite.hash, chts, th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.core.transcript.update(raw);

        // The client now talks under its application traffic key.
        let cats = self.client_app_secret.as_ref().expect("client app secret");
        self.core.set_read(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            cats,
        ));
        // RFC 8446 §5: ChangeCipherSpec is no longer permitted after this point.
        self.core.close_ccs_window();
        self.state = State::Connected;
        Ok(())
    }

    /// Test hook: the server handshake traffic secret, for KAT comparison.
    #[cfg(test)]
    pub(crate) fn server_hs_secret_bytes(&self) -> Vec<u8> {
        self.server_hs_secret
            .as_ref()
            .map(|s| s.as_slice().to_vec())
            .unwrap_or_default()
    }
}

/// Maps an internal error to the alert to send the peer.
fn alert_for(error: &Error) -> AlertDescription {
    match error {
        Error::Decode => AlertDescription::DecodeError,
        Error::UnexpectedMessage => AlertDescription::UnexpectedMessage,
        Error::BadRecordMac => AlertDescription::BadRecordMac,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::BoxedRsaPrivateKey;
    use crate::test_util::{from_hex_vec, rsa_test_key_a};
    use crate::tls::ContentType;
    use crate::tls::codec::read_record;
    use crate::x509::{Certificate, DistinguishedName, Time, Validity};

    /// An RNG that returns a fixed script of bytes, then zeros — to reproduce
    /// the RFC 8448 server random and ephemeral key exactly.
    struct ScriptedRng {
        data: Vec<u8>,
        pos: usize,
    }
    impl RngCore for ScriptedRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest.iter_mut() {
                *b = self.data.get(self.pos).copied().unwrap_or(0);
                self.pos += 1;
            }
        }
    }

    fn test_server_config() -> ServerConfig {
        let key = rsa_test_key_a();
        let name = DistinguishedName::common_name("purecrypto test server");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed(&key, &name, &validity, 1, false).unwrap();
        let boxed = BoxedRsaPrivateKey::from_pkcs1_der(&key.to_pkcs1_der()).unwrap();
        ServerConfig::with_rsa(alloc::vec![cert.to_der().to_vec()], boxed)
    }

    // RFC 8448 §3: feed the exact ClientHello and seed the server's random and
    // ephemeral key; the emitted ServerHello and derived server handshake
    // traffic secret must match the trace byte-for-byte.
    #[test]
    fn rfc8448_server_hello_byte_exact() {
        let client_hello = from_hex_vec(include_str!("../../../testdata/rfc8448_client_hello.hex"));
        let expected_sh = from_hex_vec(include_str!("../../../testdata/rfc8448_server_hello.hex"));

        // Script: server random (from the trace ServerHello) || server x25519
        // private key (from the trace).
        let server_random =
            from_hex_vec("a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928");
        let server_priv =
            from_hex_vec("b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e");
        let mut script = server_random;
        script.extend_from_slice(&server_priv);
        let rng = ScriptedRng {
            data: script,
            pos: 0,
        };

        let mut server = ServerConnection::new(test_server_config(), rng);

        // Frame the ClientHello as a plaintext handshake record and feed it.
        let mut record = alloc::vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&client_hello);
        server.read_tls(&record);
        server.process_new_packets().unwrap();

        // The first emitted record is the plaintext ServerHello.
        let out = server.write_tls();
        let rec = read_record(&out).unwrap().unwrap();
        assert_eq!(rec.content_type, ContentType::Handshake);
        assert_eq!(rec.fragment, &expected_sh[..]);

        // And the derived server handshake traffic secret matches the trace.
        assert_eq!(
            server.server_hs_secret_bytes(),
            from_hex_vec("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        );
    }
}
