//! TLS 1.2 server state machine (RFC 5246) — ECDHE-AEAD, server-cert only.
//!
//! [`ServerConnection12`] is the server-side mirror of
//! [`super::client12::ClientConnection12`]: it consumes a `ClientHello`, picks
//! a cipher suite and key-exchange group, emits the server flight
//! (`ServerHello`, `Certificate`, `ServerKeyExchange`, `ServerHelloDone`), then
//! processes the client's `ClientKeyExchange` / `ChangeCipherSpec` / `Finished`
//! and emits its own `ChangeCipherSpec` + `Finished`.
//!
//! Client authentication (mTLS) and RFC 5077 session tickets land in commit 5.
//!
//! # Record-layer note
//!
//! As with [`super::client12`], we keep our own `inbuf`/`outbuf`/`hs_pending`
//! buffers and a pair of [`crate::tls::crypto::aead12::RecordCrypter12`]
//! instances rather than reuse the TLS-1.3-shaped
//! [`super::common::ConnectionCore`].

use super::super::codec::{ParsedRecord, read_record, write_record};
use super::client12::{SUITES_12, SigKind, SuiteParams12};
use super::server::ServerKey;
use crate::ct::ConstantTimeEq;
use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, CurveId};
use crate::hash::{Sha256, Sha384, Sha512};
use crate::rng::RngCore;
use crate::rsa::BoxedRsaPrivateKey;
use crate::signature_registry::SignaturePolicy;
use crate::tls::codec::extension as ext;
use crate::tls::codec::handshake12::{
    ClientKeyExchange, ServerHelloDone, ServerKeyExchange, signed_message,
};
use crate::tls::codec::{
    ClientHello, ExtensionType, NamedGroup, Random, ReadCursor, ServerHello, SignatureScheme,
    hs_type, read_handshake, with_len_u24,
};
use crate::tls::crypto::Transcript;
use crate::tls::crypto::aead12::RecordCrypter12;
use crate::tls::crypto::prf::{finished_verify_data, key_block, master_secret};
use crate::tls::{Alert, AlertDescription, ContentType, Error, ProtocolVersion};
use alloc::vec::Vec;

/// Configuration for a TLS 1.2 server connection.
///
/// Parallels [`super::server::ServerConfig`] but trims the TLS-1.3-only knobs
/// (PSK tickets, 0-RTT, mTLS — those land in later commits). Unlike the TLS
/// 1.3 server, ML-DSA and Ed25519 server keys are not accepted here: TLS 1.2
/// has no IANA-assigned `TLS_ECDHE_EDDSA_*` or `TLS_ECDHE_MLDSA_*` cipher
/// suites, so a non-RSA/non-ECDSA key would have nothing to match.
pub struct ServerConfig12 {
    /// Certificate chain (leaf first) presented to the peer.
    cert_chain: Vec<Vec<u8>>,
    /// The server's signing key. Reused from [`super::server::ServerKey`] but
    /// only [`ServerKey::Rsa`] and [`ServerKey::Ecdsa`] variants are valid
    /// here.
    key: ServerKey,
    /// ALPN protocols this server accepts, in preference order.
    alpn_protocols: Vec<Vec<u8>>,
    /// `record_size_limit` (RFC 8449) we advertise — the largest plaintext
    /// fragment the peer may send us.
    record_size_limit: Option<u16>,
    /// Whitelist of signature algorithms the server is willing to use in its
    /// `ServerKeyExchange` signature. Defaults to [`SignaturePolicy::modern`].
    signature_policy: SignaturePolicy,
}

impl ServerConfig12 {
    /// A configuration presenting `cert_chain` and signing with an RSA private
    /// `key` (RSA-PSS, scheme `rsa_pss_rsae_sha256`).
    pub fn with_rsa(cert_chain: Vec<Vec<u8>>, key: BoxedRsaPrivateKey) -> Self {
        ServerConfig12 {
            cert_chain,
            key: ServerKey::Rsa(key),
            alpn_protocols: Vec::new(),
            record_size_limit: None,
            signature_policy: SignaturePolicy::modern(),
        }
    }

    /// A configuration presenting `cert_chain` and signing with an ECDSA
    /// private `key` (scheme follows the curve).
    pub fn with_ecdsa(cert_chain: Vec<Vec<u8>>, key: BoxedEcdsaPrivateKey) -> Self {
        ServerConfig12 {
            cert_chain,
            key: ServerKey::Ecdsa(key),
            alpn_protocols: Vec::new(),
            record_size_limit: None,
            signature_policy: SignaturePolicy::modern(),
        }
    }

    /// Sets the ALPN protocols the server is willing to negotiate.
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Advertises `record_size_limit = limit` (RFC 8449).
    pub fn with_record_size_limit(mut self, limit: u16) -> Self {
        self.record_size_limit = Some(limit);
        self
    }

    /// Replaces the signature-algorithm whitelist.
    pub fn with_signature_policy(mut self, policy: SignaturePolicy) -> Self {
        self.signature_policy = policy;
        self
    }

    /// Which signature family the configured server key belongs to. Drives
    /// suite negotiation: an RSA key can only sign RSA suites; an ECDSA key
    /// can only sign ECDSA suites.
    fn sig_kind(&self) -> SigKind {
        match &self.key {
            ServerKey::Rsa(_) => SigKind::Rsa,
            ServerKey::Ecdsa(_) => SigKind::Ecdsa,
            // Other variants are inhabited by the shared `ServerKey` enum but
            // are unreachable through the public TLS-1.2 constructors. Default
            // to a kind that will fail to match any of our suites.
            _ => SigKind::Rsa,
        }
    }

    /// The signature scheme this server's key will use in `ServerKeyExchange`.
    /// For ECDSA the choice tracks the curve; for RSA we use RSA-PSS, the
    /// modern default for TLS 1.2 + 1.3 interop.
    fn signature_scheme(&self) -> SignatureScheme {
        match &self.key {
            ServerKey::Rsa(_) => SignatureScheme::RSA_PSS_RSAE_SHA256,
            ServerKey::Ecdsa(k) => match k.curve() {
                CurveId::P256 => SignatureScheme::ECDSA_SECP256R1_SHA256,
                CurveId::P384 => SignatureScheme::ECDSA_SECP384R1_SHA384,
                CurveId::P521 => SignatureScheme::ECDSA_SECP521R1_SHA512,
                CurveId::Secp256k1 => SignatureScheme::ECDSA_SECP256R1_SHA256,
            },
            // Unreachable through the public constructors but the compiler
            // requires the match to be total.
            _ => SignatureScheme::RSA_PSS_RSAE_SHA256,
        }
    }
}

/// The server handshake progress.
#[derive(PartialEq, Eq, Debug)]
enum State {
    WaitClientHello,
    WaitClientKeyExchange,
    /// We've processed CKE and are now expecting the client's CCS record (a
    /// non-handshake record) followed by their encrypted Finished.
    WaitClientFinished,
    Connected,
    Closed,
}

/// A TLS 1.2 server connection.
pub struct ServerConnection12<R: RngCore> {
    config: ServerConfig12,
    rng: R,
    state: State,

    /// Inbound TLS bytes to parse into records.
    inbuf: Vec<u8>,
    /// Outbound TLS bytes ready to send.
    outbuf: Vec<u8>,
    /// Reassembly buffer for handshake messages spanning records.
    hs_pending: Vec<u8>,
    /// Decrypted application data awaiting the application.
    app_in: Vec<u8>,
    /// Buffered handshake transcript hash (RFC 5246 §7.4.9).
    transcript: Transcript,
    /// `true` while ChangeCipherSpec is allowed (between CH and our Finished).
    /// Closed once we transition to `Connected`.
    ccs_window_open: bool,

    /// Negotiated suite parameters (set on CH).
    suite: Option<SuiteParams12>,
    /// Ephemeral X25519 private key (used when we pick X25519).
    x25519: Option<X25519PrivateKey>,
    /// Ephemeral P-256 ECDH private key (used when we pick SECP256R1).
    p256: Option<BoxedEcdhPrivateKey>,
    /// Negotiated group (X25519 or SECP256R1).
    group: Option<NamedGroup>,

    /// Handshake randoms.
    client_random: Option<Random>,
    server_random: Option<Random>,
    /// Negotiated ALPN, if any.
    alpn_negotiated: Option<Vec<u8>>,
    /// Whether the peer sent a `renegotiation_info` extension — drives whether
    /// we echo our own per RFC 5746 §3.6.
    peer_offered_reneg_info: bool,
    /// Whether the peer sent a `record_size_limit` — drives whether we echo
    /// our own configured value.
    peer_offered_record_size_limit: bool,

    /// 48-byte master secret derived once CKE is processed.
    master: Option<[u8; 48]>,
    /// Record-protection state once `server_crypter` is installed (after we
    /// emit our CCS).
    server_crypter: Option<RecordCrypter12>,
    /// Record-protection state once `client_crypter` is installed (after the
    /// peer's CCS arrives).
    client_crypter: Option<RecordCrypter12>,
    /// Pre-built crypters held until the matching CCS event installs them.
    /// `pending_client_crypter` is the read side, `pending_server_crypter` the
    /// write side; both are populated when we process the CKE.
    pending_client_crypter: Option<RecordCrypter12>,
    pending_server_crypter: Option<RecordCrypter12>,
}

impl<R: RngCore> ServerConnection12<R> {
    /// Creates a server awaiting a `ClientHello`. `rng` supplies the server
    /// random, the ephemeral key share, and (for RSA-PSS) the salt.
    pub fn new(config: ServerConfig12, rng: R) -> Self {
        ServerConnection12 {
            config,
            rng,
            state: State::WaitClientHello,
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            hs_pending: Vec::new(),
            app_in: Vec::new(),
            transcript: Transcript::new(),
            ccs_window_open: true,
            suite: None,
            x25519: None,
            p256: None,
            group: None,
            client_random: None,
            server_random: None,
            alpn_negotiated: None,
            peer_offered_reneg_info: false,
            peer_offered_record_size_limit: false,
            master: None,
            server_crypter: None,
            client_crypter: None,
            pending_client_crypter: None,
            pending_server_crypter: None,
        }
    }

    /// The negotiated cipher-suite wire identifier, available once the
    /// `ClientHello` has been processed.
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.suite.map(|s| s.suite.0)
    }

    /// Protocol version string, always `"TLSv1.2"` here once a CH has been
    /// processed.
    pub fn protocol_version(&self) -> Option<&'static str> {
        self.suite.map(|_| "TLSv1.2")
    }

    /// The ALPN protocol the server selected, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_negotiated.as_deref()
    }

    /// Feeds received TLS bytes.
    pub fn read_tls(&mut self, bytes: &[u8]) {
        self.inbuf.extend_from_slice(bytes);
    }

    /// Removes and returns bytes queued for transmission.
    pub fn write_tls(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outbuf)
    }

    /// Whether there are bytes queued for transmission.
    pub fn wants_write(&self) -> bool {
        !self.outbuf.is_empty()
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
        // Fragment to at most 2^14 bytes per record (RFC 5246 §6.2.1).
        const CAP: usize = 1 << 14;
        if data.len() <= CAP {
            self.emit_encrypted(ContentType::ApplicationData, data)?;
        } else {
            for chunk in data.chunks(CAP) {
                self.emit_encrypted(ContentType::ApplicationData, chunk)?;
            }
        }
        Ok(())
    }

    /// Removes and returns any received application plaintext.
    pub fn take_received_plaintext(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app_in)
    }

    /// Queues a `close_notify` warning alert.
    pub fn send_close_notify(&mut self) {
        let body = [1u8, AlertDescription::CloseNotify.as_u8()];
        let _ = self.emit_alert(&body);
    }

    /// Processes all buffered records, advancing the handshake.
    pub fn process_new_packets(&mut self) -> Result<(), Error> {
        loop {
            match self.next_message() {
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
        let body = [2u8, alert_for(error).as_u8()];
        let _ = self.emit_alert(&body);
        self.state = State::Closed;
    }

    /// Writes a plaintext record straight to the outbound buffer.
    fn write_plain_record(&mut self, ct: ContentType, payload: &[u8]) {
        write_record(&mut self.outbuf, ct, ProtocolVersion::TLSv1_2, payload);
    }

    /// Encrypts `payload` under the installed `server_crypter` and frames it.
    fn emit_encrypted(&mut self, ct: ContentType, payload: &[u8]) -> Result<(), Error> {
        let crypter = self
            .server_crypter
            .as_mut()
            .ok_or(Error::InappropriateState)?;
        let fragment = crypter.encrypt(ct, payload)?;
        write_record(&mut self.outbuf, ct, ProtocolVersion::TLSv1_2, &fragment);
        Ok(())
    }

    /// Queues an alert (plaintext or encrypted depending on whether write keys
    /// are installed).
    fn emit_alert(&mut self, body: &[u8; 2]) -> Result<(), Error> {
        if self.server_crypter.is_some() {
            self.emit_encrypted(ContentType::Alert, body)
        } else {
            self.write_plain_record(ContentType::Alert, body);
            Ok(())
        }
    }

    /// Pulls the next decoded message from the inbound buffer.
    fn next_message(&mut self) -> Result<Option<Incoming>, Error> {
        loop {
            if let Some(msg) = self.pop_handshake() {
                return Ok(Some(Incoming::Handshake(msg)));
            }

            let Some(ParsedRecord {
                content_type,
                fragment,
                len,
            }) = read_record(&self.inbuf)?
            else {
                return Ok(None);
            };
            let mut header = [0u8; 5];
            header.copy_from_slice(&self.inbuf[..5]);
            let fragment = fragment.to_vec();
            self.inbuf.drain(..len);

            match content_type {
                ContentType::ChangeCipherSpec => {
                    // RFC 5246 §7.1: the only legal body is `[0x01]`. We only
                    // accept it in the middlebox-compat window, and only when
                    // we're waiting for the client's Finished.
                    if !self.ccs_window_open || fragment.as_slice() != [0x01] {
                        return Err(Error::UnexpectedMessage);
                    }
                    if self.state != State::WaitClientFinished
                        || self.pending_client_crypter.is_none()
                    {
                        return Err(Error::UnexpectedMessage);
                    }
                    // Install the read crypter; the next handshake record
                    // (Finished) will be encrypted under it.
                    self.client_crypter = self.pending_client_crypter.take();
                    continue;
                }
                ContentType::Handshake => {
                    if let Some(c) = self.client_crypter.as_mut() {
                        let (_ct, plain) = c.decrypt(&header, &fragment)?;
                        if plain.is_empty() {
                            return Err(Error::UnexpectedMessage);
                        }
                        self.hs_pending.extend_from_slice(&plain);
                    } else {
                        self.hs_pending.extend_from_slice(&fragment);
                    }
                }
                ContentType::ApplicationData => {
                    let c = self
                        .client_crypter
                        .as_mut()
                        .ok_or(Error::UnexpectedMessage)?;
                    let (_ct, plain) = c.decrypt(&header, &fragment)?;
                    self.app_in.extend_from_slice(&plain);
                    return Ok(Some(Incoming::ApplicationData));
                }
                ContentType::Alert => {
                    let payload: Vec<u8> = if let Some(c) = self.client_crypter.as_mut() {
                        let (_ct, plain) = c.decrypt(&header, &fragment)?;
                        plain
                    } else {
                        fragment
                    };
                    return Ok(Some(parse_alert(&payload)?));
                }
                _ => return Err(Error::UnexpectedMessage),
            }
        }
    }

    /// Removes one complete handshake message from the reassembly buffer.
    fn pop_handshake(&mut self) -> Option<Vec<u8>> {
        if self.hs_pending.len() < 4 {
            return None;
        }
        let len = ((self.hs_pending[1] as usize) << 16)
            | ((self.hs_pending[2] as usize) << 8)
            | self.hs_pending[3] as usize;
        let total = 4 + len;
        if self.hs_pending.len() < total {
            return None;
        }
        Some(self.hs_pending.drain(..total).collect())
    }

    fn handle_handshake(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        let mut c = ReadCursor::new(&msg);
        let (msg_type, body) = read_handshake(&mut c)?;

        match self.state {
            State::WaitClientHello => self.on_client_hello(msg_type, body, &msg),
            State::WaitClientKeyExchange => self.on_client_key_exchange(msg_type, body, &msg),
            State::WaitClientFinished => self.on_client_finished(msg_type, body, &msg),
            State::Connected | State::Closed => Err(Error::UnexpectedMessage),
        }
    }

    fn on_client_hello(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::CLIENT_HELLO {
            return Err(Error::UnexpectedMessage);
        }
        let ch = ClientHello::decode(body)?;

        // If the client offered TLS 1.3 via `supported_versions`, we still
        // happily downgrade to TLS 1.2 here — a real TLS 1.3 client picks 1.3,
        // and downgrade signalling is commit 6's territory. We just process
        // the CH as the TLS 1.2 message it is.

        // Pick the first cipher suite in OUR preference order that the client
        // offered, subject to our key's signature family.
        let sig_kind = self.config.sig_kind();
        let suite = SUITES_12
            .iter()
            .copied()
            .find(|p| p.sig_kind == sig_kind && ch.cipher_suites.contains(&p.suite))
            .ok_or(Error::HandshakeFailure)?;

        // RFC 5246 §7.4.1.4.1: TLS 1.2 ClientHello MUST carry
        // `signature_algorithms`. The list must include a scheme our cert key
        // can produce.
        let sig_algs = ext::find(&ch.extensions, ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or(Error::HandshakeFailure)?;
        let offered = ext::parse_signature_algorithms(sig_algs)?;
        let our_scheme = self.config.signature_scheme();
        if !offered.contains(&our_scheme) {
            return Err(Error::HandshakeFailure);
        }

        // `supported_groups` must include at least one group we can complete
        // — we offer X25519 first then SECP256R1.
        let groups_body = ext::find(&ch.extensions, ExtensionType::SUPPORTED_GROUPS)
            .ok_or(Error::HandshakeFailure)?;
        let groups = parse_supported_groups(groups_body)?;
        let group = if groups.contains(&NamedGroup::X25519) {
            NamedGroup::X25519
        } else if groups.contains(&NamedGroup::SECP256R1) {
            NamedGroup::SECP256R1
        } else {
            return Err(Error::HandshakeFailure);
        };

        // RFC 4492 §5.1.2: `ec_point_formats` must include `uncompressed` (0).
        // The extension is mandatory for ECDHE peers in TLS 1.2.
        let epf = ext::find(&ch.extensions, ExtensionType::EC_POINT_FORMATS)
            .ok_or(Error::HandshakeFailure)?;
        let fmts = ext::parse_ec_point_formats(epf)?;
        if !fmts.contains(&0u8) {
            return Err(Error::HandshakeFailure);
        }

        // ALPN: if both sides have a non-empty offer, pick the first of OUR
        // preferences that's in the client's list. No overlap => fail.
        if let Some(alpn_body) = ext::find(&ch.extensions, ExtensionType::ALPN) {
            let offered_alpn = ext::parse_alpn(alpn_body)?;
            if !self.config.alpn_protocols.is_empty() {
                let pick = self
                    .config
                    .alpn_protocols
                    .iter()
                    .find(|p| offered_alpn.iter().any(|o| o == *p))
                    .ok_or(Error::NoApplicationProtocol)?;
                self.alpn_negotiated = Some(pick.clone());
            }
        }

        // Parse the client's `record_size_limit`, if any (we honour it on the
        // write side via send_application_data fragmentation — currently
        // bounded by the protocol cap; honouring this knob is a follow-up).
        if let Some(rsl_body) = ext::find(&ch.extensions, ExtensionType::RECORD_SIZE_LIMIT) {
            let _limit = ext::parse_record_size_limit(rsl_body)?;
            self.peer_offered_record_size_limit = true;
        }

        // RFC 5746 §3.6: echo `renegotiation_info` iff the peer sent it.
        if let Some(reneg) = ext::find(&ch.extensions, ExtensionType::RENEGOTIATION_INFO) {
            // The body must be a u8-length-prefixed empty vector (fresh handshake).
            let inner = ext::parse_renegotiation_info(reneg)?;
            if !inner.is_empty() {
                return Err(Error::HandshakeFailure);
            }
            self.peer_offered_reneg_info = true;
        }

        // Pin the transcript hash now that we know the suite.
        self.transcript.set_alg(suite.hash);
        self.transcript.update(raw);

        // Server random.
        let mut server_random: Random = [0u8; 32];
        self.rng.fill_bytes(&mut server_random);

        self.suite = Some(suite);
        self.group = Some(group);
        self.client_random = Some(ch.random);
        self.server_random = Some(server_random);

        // Emit the server flight: SH, Certificate, SKE, ServerHelloDone.
        self.send_server_hello()?;
        self.send_certificate();
        self.send_server_key_exchange()?;
        self.send_server_hello_done();

        self.state = State::WaitClientKeyExchange;
        Ok(())
    }

    fn send_server_hello(&mut self) -> Result<(), Error> {
        let suite = self.suite.expect("suite set");
        let sr = self.server_random.expect("server_random set");

        let mut extensions: Vec<(ExtensionType, Vec<u8>)> = Vec::new();
        if self.peer_offered_reneg_info {
            extensions.push(ext::renegotiation_info_empty());
        }
        if let Some(p) = self.alpn_negotiated.as_ref() {
            extensions.push(ext::alpn_protocols(&[p.as_slice()]));
        }
        // ec_point_formats: we always advertise uncompressed.
        extensions.push(ext::ec_point_formats());
        if let (Some(limit), true) = (
            self.config.record_size_limit,
            self.peer_offered_record_size_limit,
        ) {
            extensions.push(ext::record_size_limit(limit));
        }

        let sh = ServerHello {
            random: sr,
            session_id: Vec::new(),
            cipher_suite: suite.suite,
            extensions,
        }
        .encode();
        self.transcript.update(&sh);
        self.write_plain_record(ContentType::Handshake, &sh);
        Ok(())
    }

    fn send_certificate(&mut self) {
        // TLS 1.2 Certificate body: u24-length list of u24-length cert DERs
        // (no per-cert extensions).
        let mut msg = alloc::vec![hs_type::CERTIFICATE];
        with_len_u24(&mut msg, |b| {
            with_len_u24(b, |list| {
                for cert in &self.config.cert_chain {
                    with_len_u24(list, |c| c.extend_from_slice(cert));
                }
            });
        });
        self.transcript.update(&msg);
        self.write_plain_record(ContentType::Handshake, &msg);
    }

    fn send_server_key_exchange(&mut self) -> Result<(), Error> {
        let group = self.group.expect("group set");
        let cr = self.client_random.expect("client_random set");
        let sr = self.server_random.expect("server_random set");

        // Generate our ephemeral key and capture the on-wire share.
        let point: Vec<u8> = match group {
            NamedGroup::X25519 => {
                let sk = X25519PrivateKey::generate(&mut self.rng);
                let pk = sk.public_key().to_vec();
                self.x25519 = Some(sk);
                pk
            }
            NamedGroup::SECP256R1 => {
                let sk = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut self.rng);
                let pk = sk.public_key().to_sec1();
                self.p256 = Some(sk);
                pk
            }
            _ => return Err(Error::HandshakeFailure),
        };

        let to_sign = signed_message(&cr, &sr, group, &point);
        let scheme = self.config.signature_scheme();
        let signature: Vec<u8> = match &self.config.key {
            ServerKey::Rsa(k) => k
                .sign_pss::<Sha256, _>(&to_sign, &mut self.rng)
                .map_err(|_| Error::HandshakeFailure)?,
            ServerKey::Ecdsa(k) => {
                let sig = match k.curve() {
                    CurveId::P384 => k.sign::<Sha384>(&to_sign),
                    CurveId::P521 => k.sign::<Sha512>(&to_sign),
                    _ => k.sign::<Sha256>(&to_sign),
                }
                .map_err(|_| Error::HandshakeFailure)?;
                sig.to_der(k.curve())
            }
            // The public ServerConfig12 constructors only build RSA / ECDSA
            // server keys, so other variants are unreachable. Be explicit.
            _ => return Err(Error::HandshakeFailure),
        };

        let ske = ServerKeyExchange {
            group,
            point,
            scheme,
            signature,
        }
        .encode();
        self.transcript.update(&ske);
        self.write_plain_record(ContentType::Handshake, &ske);
        Ok(())
    }

    fn send_server_hello_done(&mut self) {
        let shd = ServerHelloDone.encode();
        self.transcript.update(&shd);
        self.write_plain_record(ContentType::Handshake, &shd);
    }

    fn on_client_key_exchange(
        &mut self,
        msg_type: u8,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), Error> {
        if msg_type != hs_type::CLIENT_KEY_EXCHANGE {
            return Err(Error::UnexpectedMessage);
        }
        let cke = ClientKeyExchange::decode(body)?;
        let group = self.group.expect("group set");
        let suite = self.suite.expect("suite set");

        // Complete ECDHE and derive the premaster.
        let premaster: Vec<u8> = match group {
            NamedGroup::X25519 => {
                let sk = self.x25519.as_ref().ok_or(Error::InappropriateState)?;
                let peer: [u8; 32] = cke.point.as_slice().try_into().map_err(|_| Error::Decode)?;
                sk.diffie_hellman(&peer).to_vec()
            }
            NamedGroup::SECP256R1 => {
                let sk = self.p256.as_ref().ok_or(Error::InappropriateState)?;
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, &cke.point)
                    .map_err(|_| Error::Decode)?;
                sk.diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?
            }
            _ => return Err(Error::HandshakeFailure),
        };

        // master_secret + key_block.
        let cr = self.client_random.expect("client_random set");
        let sr = self.server_random.expect("server_random set");
        let master = master_secret(suite.hash, &premaster, &cr, &sr);
        let kb_len = 2 * suite.key_len + 8;
        let mut kb = alloc::vec![0u8; kb_len];
        key_block(suite.hash, &master, &sr, &cr, &mut kb);
        let (c_key, rest) = kb.split_at(suite.key_len);
        let (s_key, rest) = rest.split_at(suite.key_len);
        let mut c_salt = [0u8; 4];
        c_salt.copy_from_slice(&rest[..4]);
        let mut s_salt = [0u8; 4];
        s_salt.copy_from_slice(&rest[4..8]);
        // Stash the crypters; we install the read side on the peer's CCS and
        // the write side after we emit our own CCS.
        self.pending_client_crypter = Some(RecordCrypter12::new(suite.aead, c_key, c_salt));
        self.pending_server_crypter = Some(RecordCrypter12::new(suite.aead, s_key, s_salt));
        self.master = Some(master);

        self.transcript.update(raw);
        self.state = State::WaitClientFinished;
        Ok(())
    }

    fn on_client_finished(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::FINISHED {
            return Err(Error::UnexpectedMessage);
        }
        if body.len() != 12 {
            return Err(Error::Decode);
        }
        // The client's CCS must have arrived first so the Finished decrypts
        // under `client_crypter`.
        if self.client_crypter.is_none() {
            return Err(Error::UnexpectedMessage);
        }
        let suite = self.suite.expect("suite set");
        let master = self.master.expect("master set");

        // The transcript at this point covers CH..CKE; the client's
        // verify_data is over exactly that prefix.
        let th = self.transcript.current_hash();
        let expected = finished_verify_data(suite.hash, &master, b"client finished", th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.transcript.update(raw);

        // Emit our CCS (plaintext, outside the transcript) and install the
        // server write crypter.
        self.write_plain_record(ContentType::ChangeCipherSpec, &[0x01]);
        self.server_crypter = self.pending_server_crypter.take();

        // Compute and emit our Finished under the freshly installed crypter.
        let th2 = self.transcript.current_hash();
        let verify_data =
            finished_verify_data(suite.hash, &master, b"server finished", th2.as_slice());
        let finished = build_finished(&verify_data);
        // Append to transcript for completeness; nothing reads it after.
        self.transcript.update(&finished);
        self.emit_encrypted(ContentType::Handshake, &finished)?;

        self.ccs_window_open = false;
        self.state = State::Connected;
        Ok(())
    }
}

/// One decoded inbound message.
enum Incoming {
    Handshake(Vec<u8>),
    ApplicationData,
    Alert(Alert),
}

fn parse_alert(body: &[u8]) -> Result<Incoming, Error> {
    if body.len() != 2 {
        return Err(Error::Decode);
    }
    Ok(Incoming::Alert(Alert {
        fatal: body[0] == 2,
        description: AlertDescription::from_u8(body[1]),
    }))
}

/// Parses a `supported_groups` extension body (RFC 8422 §5.1.1) — a
/// u16-length-prefixed list of u16 group identifiers.
fn parse_supported_groups(body: &[u8]) -> Result<Vec<NamedGroup>, Error> {
    let mut outer = ReadCursor::new(body);
    let list = outer.vec_u16()?;
    outer.expect_empty()?;
    if list.len() % 2 != 0 {
        return Err(Error::Decode);
    }
    let mut c = ReadCursor::new(list);
    let mut out = Vec::with_capacity(list.len() / 2);
    while !c.is_empty() {
        out.push(NamedGroup(c.u16()?));
    }
    Ok(out)
}

/// Builds a TLS 1.2 `Finished` handshake message body from a 12-byte
/// `verify_data`.
fn build_finished(verify_data: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 12);
    out.push(hs_type::FINISHED);
    out.extend_from_slice(&[0, 0, 12]);
    out.extend_from_slice(verify_data);
    out
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
        Error::DecryptError => AlertDescription::DecryptError,
        Error::CertificateRequired => AlertDescription::CertificateRequired,
        _ => AlertDescription::HandshakeFailure,
    }
}

#[cfg(feature = "std")]
impl<R: RngCore> super::stream::Connection for ServerConnection12<R> {
    fn read_tls(&mut self, bytes: &[u8]) {
        ServerConnection12::read_tls(self, bytes)
    }
    fn write_tls(&mut self) -> Vec<u8> {
        ServerConnection12::write_tls(self)
    }
    fn process_new_packets(&mut self) -> Result<(), Error> {
        ServerConnection12::process_new_packets(self)
    }
    fn is_handshaking(&self) -> bool {
        ServerConnection12::is_handshaking(self)
    }
    fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        ServerConnection12::send_application_data(self, data)
    }
    fn take_received_plaintext(&mut self) -> Vec<u8> {
        ServerConnection12::take_received_plaintext(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::tls::codec::{CipherSuite, ClientHello, hs_type, read_record};

    fn test_rsa_server_config() -> ServerConfig12 {
        use crate::test_util::rsa_test_key_a;
        use crate::x509::{Certificate, DistinguishedName, Time, Validity};
        let key = rsa_test_key_a();
        let name = DistinguishedName::common_name("test.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed(&key, &name, &validity, 1, false).unwrap();
        let boxed = BoxedRsaPrivateKey::from_pkcs1_der(&key.to_pkcs1_der()).unwrap();
        ServerConfig12::with_rsa(alloc::vec![cert.to_der().to_vec()], boxed)
    }

    /// A server with no offered cipher suites matching ours returns
    /// HandshakeFailure.
    #[test]
    fn server12_rejects_no_overlap_suite() {
        let cfg = test_rsa_server_config();
        let rng = HmacDrbg::<Sha256>::new(b"s12-bad", b"nonce", &[]);
        let mut s = ServerConnection12::new(cfg, rng);

        // Build a synthetic CH that lists only TLS_NULL_WITH_NULL_NULL.
        let mut crng = HmacDrbg::<Sha256>::new(b"s12-bad-c", b"nonce", &[]);
        let mut random = [0u8; 32];
        crng.fill_bytes(&mut random);
        let ch = ClientHello {
            random,
            session_id: Vec::new(),
            cipher_suites: alloc::vec![CipherSuite(0x0000)],
            extensions: alloc::vec![
                ext::signature_algorithms(),
                ext::supported_groups_list(&[NamedGroup::X25519]),
                ext::ec_point_formats(),
            ],
        }
        .encode();
        let mut rec = Vec::new();
        write_record(
            &mut rec,
            ContentType::Handshake,
            ProtocolVersion::TLSv1_2,
            &ch,
        );
        s.read_tls(&rec);
        assert!(matches!(
            s.process_new_packets(),
            Err(Error::HandshakeFailure)
        ));
    }

    /// A CH missing `signature_algorithms` is rejected with HandshakeFailure.
    #[test]
    fn server12_requires_signature_algorithms() {
        let cfg = test_rsa_server_config();
        let rng = HmacDrbg::<Sha256>::new(b"s12-nosig", b"nonce", &[]);
        let mut s = ServerConnection12::new(cfg, rng);

        let mut crng = HmacDrbg::<Sha256>::new(b"s12-nosig-c", b"nonce", &[]);
        let mut random = [0u8; 32];
        crng.fill_bytes(&mut random);
        let ch = ClientHello {
            random,
            session_id: Vec::new(),
            cipher_suites: alloc::vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            extensions: alloc::vec![
                ext::supported_groups_list(&[NamedGroup::X25519]),
                ext::ec_point_formats(),
            ],
        }
        .encode();
        let mut rec = Vec::new();
        write_record(
            &mut rec,
            ContentType::Handshake,
            ProtocolVersion::TLSv1_2,
            &ch,
        );
        s.read_tls(&rec);
        assert!(matches!(
            s.process_new_packets(),
            Err(Error::HandshakeFailure)
        ));
    }

    /// A normal CH yields a complete server flight: SH || Certificate ||
    /// ServerKeyExchange || ServerHelloDone.
    #[test]
    fn server12_emits_full_server_flight() {
        let cfg = test_rsa_server_config();
        let rng = HmacDrbg::<Sha256>::new(b"s12-flight", b"nonce", &[]);
        let mut s = ServerConnection12::new(cfg, rng);

        let mut crng = HmacDrbg::<Sha256>::new(b"s12-flight-c", b"nonce", &[]);
        let mut random = [0u8; 32];
        crng.fill_bytes(&mut random);
        let ch = ClientHello {
            random,
            session_id: Vec::new(),
            cipher_suites: alloc::vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            extensions: alloc::vec![
                ext::signature_algorithms(),
                ext::supported_groups_list(&[NamedGroup::X25519]),
                ext::ec_point_formats(),
                ext::renegotiation_info_empty(),
            ],
        }
        .encode();
        let mut rec = Vec::new();
        write_record(
            &mut rec,
            ContentType::Handshake,
            ProtocolVersion::TLSv1_2,
            &ch,
        );
        s.read_tls(&rec);
        s.process_new_packets().unwrap();
        assert_eq!(
            s.negotiated_cipher_suite(),
            Some(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.0)
        );

        // Walk the emitted records and confirm we see four handshake messages
        // in the right order.
        let out = s.write_tls();
        let mut consumed = 0;
        let mut types: Vec<u8> = Vec::new();
        while consumed < out.len() {
            let rec = read_record(&out[consumed..]).unwrap().unwrap();
            consumed += rec.len;
            // Each record carries one handshake message in this implementation.
            assert_eq!(rec.content_type, ContentType::Handshake);
            types.push(rec.fragment[0]);
        }
        assert_eq!(
            types,
            alloc::vec![
                hs_type::SERVER_HELLO,
                hs_type::CERTIFICATE,
                hs_type::SERVER_KEY_EXCHANGE,
                hs_type::SERVER_HELLO_DONE,
            ],
        );
    }
}
