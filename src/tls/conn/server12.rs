#![allow(dead_code, unreachable_pub)]

//! TLS 1.2 server state machine (RFC 5246 + RFC 5077) — ECDHE-AEAD.
//!
//! [`ServerConnection12`] is the server-side mirror of
//! [`super::client12::ClientConnection12`]: it consumes a `ClientHello`, picks
//! a cipher suite and key-exchange group, emits the server flight
//! (`ServerHello`, `Certificate`, `ServerKeyExchange`, [`CertificateRequest`],
//! `ServerHelloDone`), then processes the client's `Certificate` /
//! `ClientKeyExchange` / [`CertificateVerify`] / `ChangeCipherSpec` /
//! `Finished` and emits its own [`NewSessionTicket`] / `ChangeCipherSpec` +
//! `Finished`.
//!
//! Supports mTLS (RFC 5246 §7.4.4 + §7.4.6 + §7.4.8) via
//! [`ServerConfig12::with_client_auth`] and RFC 5077 stateless session
//! tickets via [`ServerConfig12::with_ticket_key`].
//!
//! # Record-layer note
//!
//! As with [`super::client12`], we keep our own `inbuf`/`outbuf`/`hs_pending`
//! buffers and a pair of [`crate::tls::crypto::aead12::RecordCrypter12`]
//! instances rather than reuse the TLS-1.3-shaped
//! [`super::common::ConnectionCore`].

use super::super::codec::{ParsedRecord, is_legal_record_version, read_record, write_record};
use super::client12::{
    SUITES_12, SigKind, SuiteParams12, lookup_suite_12, parse_certificate_list_12,
};
use super::server::ServerKey;
use super::ticket12::{Ticket12Plaintext, open_ticket, seal_ticket};
use crate::ct::ConstantTimeEq;
use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, CurveId};
use crate::hash::{Sha256, Sha384, Sha512};
use crate::rng::RngCore;
use crate::rsa::BoxedRsaPrivateKey;
use crate::signature_registry::{ALGORITHMS, SignaturePolicy};
use crate::tls::codec::extension as ext;
use crate::tls::codec::handshake12::{
    CertificateRequest12, ClientKeyExchange, NewSessionTicket12, ServerHelloDone,
    ServerKeyExchange, signed_message,
};
use crate::tls::codec::{
    ClientHello, ExtensionType, NamedGroup, Random, ReadCursor, ServerHello, SignatureScheme,
    hs_type, read_handshake, with_len_u24,
};
use crate::tls::crypto::Transcript;
use crate::tls::crypto::aead12::RecordCrypter12;
use crate::tls::crypto::prf::{
    extended_master_secret, finished_verify_data, key_block, master_secret,
};
use crate::tls::crypto::verify_signature;
use crate::tls::keylog::KeyLog;
use crate::tls::pki::RootCertStore;
use crate::tls::{Alert, AlertDescription, ContentType, Error, ProtocolVersion};
use crate::x509::AnyPublicKey;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Configuration for a TLS 1.2 server connection.
///
/// Parallels [`super::server::ServerConfig`], including mTLS via
/// [`Self::with_client_auth`] and RFC 5077 session tickets via
/// [`Self::with_ticket_key`]. Unlike the TLS 1.3 server, ML-DSA and Ed25519
/// server keys are not accepted here: TLS 1.2 has no IANA-assigned
/// `TLS_ECDHE_EDDSA_*` or `TLS_ECDHE_MLDSA_*` cipher suites, so a non-RSA /
/// non-ECDSA key would have nothing to match.
pub(crate) struct ServerConfig12 {
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
    /// `ServerKeyExchange` signature, and to accept in client-cert chains /
    /// `CertificateVerify` under mTLS. Defaults to
    /// [`SignaturePolicy::modern`].
    signature_policy: SignaturePolicy,
    /// mTLS policy: when set, the server emits `CertificateRequest` and
    /// validates the client's chain against `roots`. When `required` is
    /// `true`, an empty client `Certificate` aborts with
    /// `certificate_required`. `None` skips mTLS entirely.
    client_auth: Option<ClientAuthPolicy12>,
    /// RFC 5077 ticket-encryption key. When set, the server emits a
    /// `NewSessionTicket` on fresh full handshakes and accepts resumption
    /// from clients that present a valid ticket. `None` disables tickets.
    ticket_key: Option<[u8; 32]>,
    /// Lifetime advertised in NewSessionTickets (seconds) and used to
    /// expire decrypted tickets server-side. Defaults to 7200 (2 hours).
    ticket_lifetime: u32,
    /// CRLs consulted during client-cert chain validation under mTLS.
    /// Empty by default; opt in via [`ServerConfig12::with_crls`].
    crls: crate::tls::pki::CrlStore,
    /// Optional [`KeyLog`] sink (NSS `SSLKEYLOGFILE` format).
    pub(crate) key_log: Option<Arc<dyn KeyLog>>,
}

/// Client-authentication policy for a TLS 1.2 server (RFC 5246 §7.4.4 +
/// §7.4.6 + §7.4.8). Parallels [`super::server::ClientAuthPolicy`] — kept
/// separate so the TLS 1.2 path is not coupled to the TLS 1.3 server's
/// config layout.
pub(crate) struct ClientAuthPolicy12 {
    /// Trust anchors used to validate the client chain.
    pub roots: RootCertStore,
    /// When `true`, an empty client `Certificate` aborts the handshake with
    /// `certificate_required`. When `false`, an empty `Certificate` is
    /// accepted and no `CertificateVerify` is required.
    pub required: bool,
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
            client_auth: None,
            ticket_key: None,
            ticket_lifetime: 7200,
            crls: crate::tls::pki::CrlStore::new(),
            key_log: None,
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
            client_auth: None,
            ticket_key: None,
            ticket_lifetime: 7200,
            crls: crate::tls::pki::CrlStore::new(),
            key_log: None,
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

    /// Installs a [`crate::tls::pki::CrlStore`] consulted during client-cert
    /// chain validation under mTLS.
    pub fn with_crls(mut self, crls: crate::tls::pki::CrlStore) -> Self {
        self.crls = crls;
        self
    }

    /// Demand a client certificate from peers (RFC 5246 §7.4.4). When
    /// `required` is `true`, a peer that presents an empty `Certificate`
    /// aborts the handshake with `certificate_required`. When `false`, an
    /// absent client cert is allowed.
    pub fn with_client_auth(mut self, roots: RootCertStore, required: bool) -> Self {
        self.client_auth = Some(ClientAuthPolicy12 { roots, required });
        self
    }

    /// Enables RFC 5077 session resumption: the server emits one
    /// `NewSessionTicket` after a fresh handshake (encrypted under this 32-byte
    /// AES-256-GCM key) and decrypts client-presented tickets to resume.
    /// Without this, the server does not emit tickets and clients cannot
    /// resume.
    pub fn with_ticket_key(mut self, key: [u8; 32]) -> Self {
        self.ticket_key = Some(key);
        self
    }

    /// Sets the lifetime advertised in `NewSessionTicket` (seconds), also used
    /// as the server-side expiry cap on decrypted tickets. Capped at 7 days;
    /// defaults to two hours.
    pub fn with_ticket_lifetime(mut self, seconds: u32) -> Self {
        const MAX: u32 = 7 * 24 * 60 * 60;
        self.ticket_lifetime = seconds.min(MAX);
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
    /// mTLS only: after our `ServerHelloDone`, the client's first message
    /// MUST be `Certificate` (RFC 5246 §7.3).
    WaitClientCertificate,
    WaitClientKeyExchange,
    /// mTLS only: after `ClientKeyExchange`, expect `CertificateVerify` —
    /// but only if the client actually sent a non-empty `Certificate`.
    WaitClientCertVerify,
    /// We've processed CKE (+ CertVerify under mTLS) and are now expecting
    /// the client's CCS record followed by their encrypted Finished.
    WaitClientFinished,
    /// Resumed handshake (RFC 5077 §3.4): we picked up a valid ticket from
    /// the client's CH; the next message after our SH/CCS/Finished is the
    /// client's encrypted Finished.
    WaitResumedClientFinished,
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
    /// Set when the client's ChangeCipherSpec has been processed. A second
    /// CCS in the same handshake direction is a protocol violation (RFC 5246
    /// §7.1 allows exactly one per direction).
    ccs_received: bool,

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

    /// 48-byte master secret derived once CKE is processed (or recovered
    /// from a valid ticket on resumed handshakes).
    master: Option<[u8; 48]>,
    /// Record-protection state once `server_crypter` is installed (after we
    /// emit our CCS).
    server_crypter: Option<RecordCrypter12>,
    /// Record-protection state once `client_crypter` is installed (after the
    /// peer's CCS arrives).
    client_crypter: Option<RecordCrypter12>,
    /// Pre-built crypters held until the matching CCS event installs them.
    /// Populated when we process the CKE (fresh) or right after parsing the
    /// CH (resumed).
    pending_client_crypter: Option<RecordCrypter12>,
    pending_server_crypter: Option<RecordCrypter12>,

    /// mTLS: the client's certificate chain (leaf first) after parsing its
    /// `Certificate` message. Empty if the client offered no cert.
    client_cert_chain: Vec<Vec<u8>>,
    /// mTLS: the client's leaf public key, recovered from the chain. `None`
    /// when the chain is empty.
    client_leaf_key: Option<AnyPublicKey>,
    /// RFC 5077: whether the peer advertised the `session_ticket` extension
    /// in its CH. Drives whether we echo the empty extension in SH and emit
    /// `NewSessionTicket` after our Finished.
    peer_offered_session_ticket: bool,
    /// RFC 5077: true on resumed handshakes (we recovered a master secret
    /// from a valid ticket presented in the client's CH). Skips Certificate /
    /// SKE / CertReq / SHDone and changes the post-CH state path.
    resumed: bool,

    /// RFC 7627 §5.1 — set when the client offered
    /// `extended_master_secret` and we elected to echo it. Drives the
    /// master-secret derivation (EMS vs legacy) and resumption gating.
    pub(crate) ems_negotiated: bool,
    /// Test-only: when `true`, the server pretends it does NOT support
    /// EMS — it ignores the client's offer and never echoes the
    /// extension. Lets the loopback tests drive the legacy fallback
    /// derivation against an EMS-offering client.
    #[cfg(test)]
    pub(crate) test_force_no_ems: bool,
    /// RFC 7627 §4 — snapshot of `Hash(CH ‖ SH ‖ … ‖ CKE)` captured the
    /// instant the ClientKeyExchange is fed into the transcript. Used as
    /// the `session_hash` input to `extended_master_secret`.
    ems_session_hash: Option<Vec<u8>>,
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
            ccs_received: false,
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
            client_cert_chain: Vec::new(),
            client_leaf_key: None,
            peer_offered_session_ticket: false,
            resumed: false,
            ems_negotiated: false,
            ems_session_hash: None,
            #[cfg(test)]
            test_force_no_ems: false,
        }
    }

    /// The client's certificate chain in wire order (DER), leaf first. Empty
    /// when no mTLS was negotiated or the client offered an empty
    /// `Certificate`.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.client_cert_chain
    }

    /// `true` if this handshake resumed a prior session via RFC 5077
    /// session ticket.
    pub fn did_resume(&self) -> bool {
        self.resumed
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

    /// The TLS 1.2 master secret derived during the handshake. `None` until
    /// the CKE has been processed. Useful for cross-peer agreement checks
    /// and for writing the NSS `SSLKEYLOGFILE` `CLIENT_RANDOM` line from
    /// the server side.
    pub fn master_secret(&self) -> Option<[u8; 48]> {
        self.master
    }

    /// Whether the handshake negotiated RFC 7627 Extended Master Secret.
    pub fn ems_negotiated(&self) -> bool {
        self.ems_negotiated
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
                    // RFC 5246 §7.2.1: TLS 1.2 warning alerts other than
                    // close_notify are non-fatal.
                    match alert.description {
                        AlertDescription::CloseNotify => {
                            self.state = State::Closed;
                            return Ok(());
                        }
                        AlertDescription::UserCanceled | AlertDescription::NoRenegotiation => {
                            continue;
                        }
                        _ => return Err(Error::AlertReceived(alert.description)),
                    }
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

    /// Test-only: encrypt and emit an attacker-shaped record (any content
    /// type, any payload) under the server's outbound crypter. Used to drive
    /// hostile-peer hardening tests that need to inject post-handshake
    /// renegotiation prompts or other forbidden messages.
    #[cfg(test)]
    pub(super) fn test_emit_encrypted(
        &mut self,
        ct: ContentType,
        payload: &[u8],
    ) -> Result<(), Error> {
        self.emit_encrypted(ct, payload)
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
                version,
                fragment,
                len,
            }) = read_record(&self.inbuf)?
            else {
                return Ok(None);
            };
            // RFC 5246 §6.2.1: record `legacy_version` must be in
            // `0x0301..=0x0303`. Pre-TLS-1.0 codepoints (SSL 3.0 and below)
            // are downgrade attempts; unknown future codepoints are also
            // rejected.
            if !is_legal_record_version(version) {
                return Err(Error::UnsupportedVersion);
            }
            let mut header = [0u8; 5];
            header.copy_from_slice(&self.inbuf[..5]);
            let fragment = fragment.to_vec();
            self.inbuf.drain(..len);

            match content_type {
                ContentType::ChangeCipherSpec => {
                    // RFC 5246 §7.1: the only legal body is `[0x01]`. We only
                    // accept it in the middlebox-compat window, and only when
                    // we're waiting for the client's Finished (fresh or
                    // resumed) — and we have a pending read crypter ready.
                    if !self.ccs_window_open || fragment.as_slice() != [0x01] {
                        return Err(Error::UnexpectedMessage);
                    }
                    // RFC 5246 §7.1: exactly one CCS per direction.
                    if self.ccs_received {
                        return Err(Error::UnexpectedMessage);
                    }
                    let awaiting_finished = matches!(
                        self.state,
                        State::WaitClientFinished | State::WaitResumedClientFinished
                    );
                    // The pending read crypter is installed only after
                    // ClientKeyExchange (fresh) or right after CH (resumed).
                    // Receiving a CCS before that — e.g. while still in
                    // `WaitClientKeyExchange` or `WaitClientCertVerify` — is
                    // an out-of-order CCS and a protocol violation.
                    if !awaiting_finished || self.pending_client_crypter.is_none() {
                        return Err(Error::UnexpectedMessage);
                    }
                    // Install the read crypter; the next handshake record
                    // (Finished) will be encrypted under it.
                    self.client_crypter = self.pending_client_crypter.take();
                    self.ccs_received = true;
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

        // RFC 5246 §7.4.1.1: `HelloRequest` is server-emitted only. A client
        // that sends one to us is misbehaving — reject in every state.
        if msg_type == hs_type::HELLO_REQUEST {
            return Err(Error::UnexpectedMessage);
        }

        match self.state {
            State::WaitClientHello => self.on_client_hello(msg_type, body, &msg),
            State::WaitClientCertificate => self.on_client_certificate(msg_type, body, &msg),
            State::WaitClientKeyExchange => self.on_client_key_exchange(msg_type, body, &msg),
            State::WaitClientCertVerify => self.on_client_cert_verify(msg_type, body, &msg),
            State::WaitClientFinished => self.on_client_finished(msg_type, body, &msg),
            State::WaitResumedClientFinished => {
                self.on_resumed_client_finished(msg_type, body, &msg)
            }
            // RFC 5246 §7.4.1: a `ClientHello` post-Connected is a
            // renegotiation attempt. We do not support renegotiation.
            State::Connected | State::Closed => Err(Error::UnexpectedMessage),
        }
    }

    fn on_client_hello(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::CLIENT_HELLO {
            return Err(Error::UnexpectedMessage);
        }
        let ch = ClientHello::decode(body)?;

        // RFC 5246 §E.1: a TLS 1.2 server rejects any `ClientHello` whose
        // `legacy_version` is below 0x0303. A TLS 1.3 client keeps
        // `legacy_version = 0x0303` and advertises real versions via
        // `supported_versions`, so this only fails on a genuine pre-1.2
        // peer (or a misbehaving stack), in which case `protocol_version`
        // is the right alert.
        if ch.legacy_version < 0x0303 {
            return Err(Error::UnsupportedVersion);
        }

        // RFC 7507 §4 / RFC 8446 §4.1.3: `TLS_FALLBACK_SCSV` (0x5600) signals
        // a deliberate downgrade. Our server tops out at TLS 1.2, so we are
        // always at our maximum supported version and MUST NOT abort with
        // `inappropriate_fallback`; the codepoint is simply ignored. (A
        // hypothetical future server that also speaks TLS 1.3 would, when
        // seeing 0x5600 here while still able to negotiate 1.3, abort with
        // `IllegalParameter`.)

        // RFC 8446 §4.1.3: validate the structure of `supported_versions`
        // if present (the parser rejects malformed encodings), then ignore
        // its content — we always embed the downgrade sentinel in
        // `server_random` regardless of whether the client advertised
        // TLS 1.3, so an in-path attacker that strips the extension cannot
        // hide the downgrade from a 1.3-aware client.
        if let Some(body) = ext::find(&ch.extensions, ExtensionType::SUPPORTED_VERSIONS) {
            let _ = ext::client_offers_tls13(body)?;
        }

        // RFC 5246 §7.4.1.4.1: TLS 1.2 ClientHello MUST carry
        // `signature_algorithms`. (Required regardless of resumption: we may
        // fall back to a fresh handshake if the ticket is bad.)
        let sig_algs = ext::find(&ch.extensions, ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or(Error::HandshakeFailure)?;
        let offered = ext::parse_signature_algorithms(sig_algs)?;
        let our_scheme = self.config.signature_scheme();
        if !offered.contains(&our_scheme) {
            return Err(Error::HandshakeFailure);
        }

        // `supported_groups` must include at least one group we can complete.
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

        // record_size_limit echo (currently advisory on the write side).
        if let Some(rsl_body) = ext::find(&ch.extensions, ExtensionType::RECORD_SIZE_LIMIT) {
            let _limit = ext::parse_record_size_limit(rsl_body)?;
            self.peer_offered_record_size_limit = true;
        }

        // RFC 5746 §3.6: echo `renegotiation_info` iff the peer sent it.
        if let Some(reneg) = ext::find(&ch.extensions, ExtensionType::RENEGOTIATION_INFO) {
            let inner = ext::parse_renegotiation_info(reneg)?;
            if !inner.is_empty() {
                return Err(Error::HandshakeFailure);
            }
            self.peer_offered_reneg_info = true;
        }

        // RFC 7627 §5.1: client may offer `extended_master_secret`
        // (empty body). When present and well-formed we elect to echo it,
        // switching the master-secret derivation. Modern clients (rustls,
        // BoringSSL, OpenSSL, NSS) require EMS by default.
        #[cfg(test)]
        let echo_ems = !self.test_force_no_ems;
        #[cfg(not(test))]
        let echo_ems = true;
        if let Some(ems_body) = ext::find(&ch.extensions, ExtensionType::EXTENDED_MASTER_SECRET) {
            ext::parse_extended_master_secret(ems_body)?;
            if echo_ems {
                self.ems_negotiated = true;
            }
        }

        // RFC 5077 §3.1: the client advertises ticket support via the
        // `session_ticket` extension. An empty body = "support, no ticket";
        // non-empty = "please resume this ticket".
        let ticket_ext = ext::find(&ch.extensions, ExtensionType::SESSION_TICKET);
        self.peer_offered_session_ticket = ticket_ext.is_some();

        // Attempt resumption only if a ticket key is configured, the client
        // presented a non-empty ticket, and we can decrypt + parse it into a
        // suite we still support (matching the client's offered list).
        let resume = ticket_ext
            .filter(|t| !t.is_empty())
            .and_then(|t| self.try_resume(t, &ch.cipher_suites));

        if let Some(rs) = resume {
            // RFC 7627 §5.3: a session that used EMS MUST resume with EMS,
            // and a session that did NOT use EMS MUST NOT resume with EMS.
            // The current handshake's EMS status (`self.ems_negotiated`)
            // is set by the client's CH extension and the server's
            // willingness to echo; mismatch is a downgrade attempt and
            // we abort.
            if rs.ems_used != self.ems_negotiated {
                return Err(Error::IllegalParameter);
            }

            // RESUMED HANDSHAKE PATH (RFC 5077 §3.4).
            self.transcript.set_alg(rs.suite.hash);
            self.transcript.update(raw);

            let mut server_random: Random = [0u8; 32];
            self.rng.fill_bytes(&mut server_random);
            // RFC 8446 §4.1.3: a TLS 1.2 server SHOULD always embed the
            // downgrade sentinel in the last 8 bytes of `server_random`,
            // not only when the client advertised TLS 1.3 via
            // `supported_versions`. A 1.3-aware client checks this
            // unconditionally and aborts on mismatch, which protects
            // legacy clients that did not advertise 1.3 but were forced
            // down by an in-path attacker.
            apply_downgrade_sentinel(&mut server_random);

            self.suite = Some(rs.suite);
            self.client_random = Some(ch.random);
            self.server_random = Some(server_random);
            self.master = Some(rs.master_secret);
            self.resumed = true;

            if let Some(kl) = self.config.key_log.as_ref() {
                kl.log("CLIENT_RANDOM", &ch.random, &rs.master_secret);
            }

            // Derive a fresh key_block from the recovered master_secret and
            // the new randoms.
            let cr = ch.random;
            let sr = server_random;
            let kb_len = 2 * rs.suite.key_len + 8;
            let mut kb = alloc::vec![0u8; kb_len];
            key_block(rs.suite.hash, &rs.master_secret, &sr, &cr, &mut kb);
            let (c_key, rest) = kb.split_at(rs.suite.key_len);
            let (s_key, ivs) = rest.split_at(rs.suite.key_len);
            let mut c_salt = [0u8; 4];
            c_salt.copy_from_slice(&ivs[..4]);
            let mut s_salt = [0u8; 4];
            s_salt.copy_from_slice(&ivs[4..8]);
            self.pending_client_crypter = Some(RecordCrypter12::new(rs.suite.aead, c_key, c_salt));
            self.pending_server_crypter = Some(RecordCrypter12::new(rs.suite.aead, s_key, s_salt));

            // SH (without echoing session_ticket — signals resumption to client).
            self.send_server_hello()?;

            // Our CCS + Finished, encrypted under the new server crypter.
            self.write_plain_record(ContentType::ChangeCipherSpec, &[0x01]);
            self.server_crypter = self.pending_server_crypter.take();

            let th = self.transcript.current_hash();
            let verify_data = finished_verify_data(
                rs.suite.hash,
                &rs.master_secret,
                b"server finished",
                th.as_slice(),
            );
            let finished = build_finished(&verify_data);
            self.transcript.update(&finished);
            self.emit_encrypted(ContentType::Handshake, &finished)?;

            self.state = State::WaitResumedClientFinished;
            return Ok(());
        }

        // FRESH HANDSHAKE PATH.
        let sig_kind = self.config.sig_kind();
        let suite = SUITES_12
            .iter()
            .copied()
            .find(|p| p.sig_kind == sig_kind && ch.cipher_suites.contains(&p.suite))
            .ok_or(Error::HandshakeFailure)?;

        // Pin the transcript hash now that we know the suite.
        self.transcript.set_alg(suite.hash);
        self.transcript.update(raw);

        // Server random. RFC 8446 §4.1.3: a TLS 1.2 server SHOULD embed the
        // downgrade sentinel in the trailing 8 bytes of `server_random`
        // regardless of whether the client advertised TLS 1.3, so a 1.3-
        // aware client can detect an attacker that stripped supported_versions.
        let mut server_random: Random = [0u8; 32];
        self.rng.fill_bytes(&mut server_random);
        apply_downgrade_sentinel(&mut server_random);

        self.suite = Some(suite);
        self.group = Some(group);
        self.client_random = Some(ch.random);
        self.server_random = Some(server_random);

        // Emit the server flight: SH, Certificate, SKE, [CertificateRequest],
        // ServerHelloDone. Per RFC 5246 §7.3, CertificateRequest comes
        // AFTER ServerKeyExchange and BEFORE ServerHelloDone.
        self.send_server_hello()?;
        self.send_certificate();
        self.send_server_key_exchange()?;
        if self.config.client_auth.is_some() {
            self.send_certificate_request();
        }
        self.send_server_hello_done();

        // mTLS: the client's first message after our SHDone is Certificate.
        self.state = if self.config.client_auth.is_some() {
            State::WaitClientCertificate
        } else {
            State::WaitClientKeyExchange
        };
        Ok(())
    }

    /// RFC 5077 §3.4: try to decrypt the client's ticket, recover its
    /// `Ticket12Plaintext`, and check it against the client's offered cipher
    /// suites and our configured lifetime. Returns `None` on any failure —
    /// the caller falls back to a fresh full handshake.
    fn try_resume(
        &mut self,
        ticket: &[u8],
        offered: &[crate::tls::codec::CipherSuite],
    ) -> Option<ResumedState> {
        let key = self.config.ticket_key.as_ref()?;
        let plain = open_ticket(key, ticket)?;
        let parsed = Ticket12Plaintext::decode(&plain)?;
        let suite_code = crate::tls::codec::CipherSuite(parsed.cipher_suite);
        // The resumed suite MUST be one the client is still offering.
        if !offered.contains(&suite_code) {
            return None;
        }
        let suite = lookup_suite_12(suite_code)?;
        // The resumed suite must also match the configured server key's
        // signature family.
        if suite.sig_kind != self.config.sig_kind() {
            return None;
        }
        // Expiry: ticket_lifetime seconds from creation.
        let now = system_now_u64();
        if now != 0
            && parsed.creation_time != 0
            && now.saturating_sub(parsed.creation_time) > self.config.ticket_lifetime as u64
        {
            return None;
        }
        // ALPN match: keep the recovered ALPN if it's in our config.
        if let Some(ref alpn) = parsed.alpn
            && self.config.alpn_protocols.iter().any(|p| p == alpn)
        {
            self.alpn_negotiated = Some(alpn.clone());
        }
        Some(ResumedState {
            suite,
            master_secret: parsed.master_secret,
            ems_used: parsed.ems_used,
        })
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
        // RFC 7627 §5.1: echo `extended_master_secret` when negotiated. We
        // do this for both fresh and resumed handshakes — RFC 7627 §5.3
        // explicitly requires resumption to preserve the EMS bit.
        if self.ems_negotiated {
            extensions.push(ext::extended_master_secret_empty());
        }
        // ec_point_formats: we always advertise uncompressed.
        extensions.push(ext::ec_point_formats());
        if let (Some(limit), true) = (
            self.config.record_size_limit,
            self.peer_offered_record_size_limit,
        ) {
            extensions.push(ext::record_size_limit(limit));
        }
        // RFC 5077 §3.2: echo an empty `session_ticket` extension iff
        // (a) the peer advertised support AND (b) we will issue a fresh
        // ticket. On a successful resume we do NOT issue a new ticket this
        // round (simplifies the flow); the extension is therefore absent in
        // SH on resume.
        if self.peer_offered_session_ticket && !self.resumed && self.config.ticket_key.is_some() {
            extensions.push(ext::session_ticket(&[]));
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

    /// RFC 5246 §7.4.4: emit a `CertificateRequest` listing the cert types
    /// (rsa_sign + ecdsa_sign), our `signature_algorithms` (filtered by the
    /// configured policy), and an empty CA list (we accept any chain that
    /// validates against the configured `roots`).
    fn send_certificate_request(&mut self) {
        let cert_types = alloc::vec![1u8, 64u8]; // rsa_sign, ecdsa_sign
        // Permitted-by-policy entries with a non-empty TLS scheme list.
        // We use an empty SPKI as the "no key context" probe — the RSA
        // entries' `rsa_modulus_bits` returns None on an empty SPKI, so
        // the min-bits check is skipped; other entries return None
        // unconditionally.
        let mut sig_schemes: Vec<SignatureScheme> = Vec::new();
        for algo in ALGORITHMS {
            if !self.config.signature_policy.permits(*algo, &[]) {
                continue;
            }
            for &scheme in algo.tls_schemes() {
                let s = SignatureScheme(scheme);
                if !sig_schemes.contains(&s) {
                    sig_schemes.push(s);
                }
            }
        }
        let cr = CertificateRequest12 {
            cert_types,
            sig_schemes,
            cas: Vec::new(),
        };
        let bytes = cr.encode();
        self.transcript.update(&bytes);
        self.write_plain_record(ContentType::Handshake, &bytes);
    }

    /// mTLS: process the client's `Certificate` message. An empty chain is
    /// allowed only when policy is `required = false`; in that case we skip
    /// straight past `WaitClientCertVerify` to `WaitClientKeyExchange`
    /// (CertificateVerify is omitted per RFC 5246 §7.4.8).
    fn on_client_certificate(
        &mut self,
        msg_type: u8,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), Error> {
        if msg_type != hs_type::CERTIFICATE {
            return Err(Error::UnexpectedMessage);
        }
        let chain = parse_certificate_list_12(body)?;
        let policy = self
            .config
            .client_auth
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        if chain.is_empty() {
            if policy.required {
                return Err(Error::CertificateRequired);
            }
            self.transcript.update(raw);
            self.client_cert_chain.clear();
            self.client_leaf_key = None;
            self.state = State::WaitClientKeyExchange;
            return Ok(());
        }
        // Validate the chain. We pass `None` for `now`. mTLS: the leaf is
        // a client cert, so require `id-kp-clientAuth` EKU.
        let leaf_key = crate::tls::pki::verify_chain_with_crls_for_purpose(
            &policy.roots,
            &self.config.crls,
            &chain,
            None,
            &self.config.signature_policy,
            crate::tls::pki::ChainPurpose::Client,
        )?;
        self.transcript.update(raw);
        self.client_cert_chain = chain;
        self.client_leaf_key = Some(leaf_key);
        self.state = State::WaitClientKeyExchange;
        Ok(())
    }

    /// mTLS: verify the client's `CertificateVerify` over the raw transcript
    /// up to and including `ClientKeyExchange` (RFC 5246 §7.4.8). The signer
    /// hashes internally, so we pass the unmodified transcript bytes.
    fn on_client_cert_verify(
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

        let leaf_key = self
            .client_leaf_key
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        // The signed bytes are exactly the transcript buffer at this point
        // (CH..CKE inclusive). The registry verifier hashes internally.
        let message = self.transcript.buffered_bytes().to_vec();
        verify_signature(
            scheme,
            leaf_key,
            &message,
            &signature,
            &self.config.signature_policy,
        )
        .map_err(|e| match e {
            // RFC 5246 §7.4.8 calls a bad signature `decrypt_error`. Map
            // BadCertificate from the registry to that here.
            Error::BadCertificate => Error::DecryptError,
            other => other,
        })?;

        self.transcript.update(raw);
        self.state = State::WaitClientFinished;
        Ok(())
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
                // RFC 7748 §6.1: reject the all-zero (small-order) DH output.
                sk.diffie_hellman(&peer)
                    .map_err(|_| Error::IllegalParameter)?
                    .to_vec()
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

        // master_secret + key_block. The transcript at this point covers
        // CH .. SH .. Cert .. SKE .. (CertReq?) .. SHDone, and we are
        // about to feed CKE. EMS (RFC 7627 §4) requires the session_hash
        // to span CH..CKE inclusive — so we update the transcript with
        // `raw` (the CKE) BEFORE deriving and snapshot the hash here.
        self.transcript.update(raw);
        let cr = self.client_random.expect("client_random set");
        let sr = self.server_random.expect("server_random set");
        let master = if self.ems_negotiated {
            let sh = self.transcript.current_hash();
            self.ems_session_hash = Some(sh.as_slice().to_vec());
            extended_master_secret(suite.hash, &premaster, sh.as_slice())
        } else {
            master_secret(suite.hash, &premaster, &cr, &sr)
        };
        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log("CLIENT_RANDOM", &cr, &master);
        }
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

        // CKE was already added to the transcript above for the EMS path.
        // mTLS: if the client presented a non-empty Certificate, the next
        // message is CertificateVerify (RFC 5246 §7.4.8). Otherwise skip
        // straight to expecting their CCS + Finished.
        self.state = if self.client_leaf_key.is_some() {
            State::WaitClientCertVerify
        } else {
            State::WaitClientFinished
        };
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

        // The transcript at this point covers CH..CKE (and CertVerify if
        // mTLS was negotiated); the client's verify_data is over exactly
        // that prefix.
        let th = self.transcript.current_hash();
        let expected = finished_verify_data(suite.hash, &master, b"client finished", th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.transcript.update(raw);

        // RFC 5077 §3.3: NewSessionTicket comes AFTER the client's Finished
        // but BEFORE our CCS. Emit it under the plaintext (pre-CCS) write
        // path so the wire ordering matches the spec.
        if self.peer_offered_session_ticket && self.config.ticket_key.is_some() {
            self.emit_session_ticket(suite, &master)?;
        }

        // Emit our CCS (plaintext, outside the transcript) and install the
        // server write crypter.
        self.write_plain_record(ContentType::ChangeCipherSpec, &[0x01]);
        self.server_crypter = self.pending_server_crypter.take();

        // Compute and emit our Finished under the freshly installed crypter.
        let th2 = self.transcript.current_hash();
        let verify_data =
            finished_verify_data(suite.hash, &master, b"server finished", th2.as_slice());
        let finished = build_finished(&verify_data);
        self.transcript.update(&finished);
        self.emit_encrypted(ContentType::Handshake, &finished)?;

        self.ccs_window_open = false;
        self.state = State::Connected;
        Ok(())
    }

    /// On a resumed handshake the client's Finished is the LAST message; we
    /// then transition straight to `Connected`. The server's CCS+Finished
    /// were emitted in `on_client_hello`.
    fn on_resumed_client_finished(
        &mut self,
        msg_type: u8,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), Error> {
        if msg_type != hs_type::FINISHED {
            return Err(Error::UnexpectedMessage);
        }
        if body.len() != 12 {
            return Err(Error::Decode);
        }
        if self.client_crypter.is_none() {
            return Err(Error::UnexpectedMessage);
        }
        let suite = self.suite.expect("suite set");
        let master = self.master.expect("master set");

        let th = self.transcript.current_hash();
        let expected = finished_verify_data(suite.hash, &master, b"client finished", th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.transcript.update(raw);
        self.ccs_window_open = false;
        self.state = State::Connected;
        Ok(())
    }

    /// RFC 5077 §3.3: emit one `NewSessionTicket` encoding the negotiated
    /// suite + the freshly derived master secret + creation timestamp.
    fn emit_session_ticket(
        &mut self,
        suite: SuiteParams12,
        master: &[u8; 48],
    ) -> Result<(), Error> {
        let key = self
            .config
            .ticket_key
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let plain = Ticket12Plaintext {
            cipher_suite: suite.suite.0,
            master_secret: *master,
            creation_time: system_now_u64(),
            // RFC 7627 §5.3: record the EMS status so resumption can
            // enforce that EMS↔EMS and legacy↔legacy.
            ems_used: self.ems_negotiated,
            alpn: self.alpn_negotiated.clone(),
        };
        let ticket = seal_ticket(&mut self.rng, key, &plain.encode());
        let nst = NewSessionTicket12 {
            lifetime: self.config.ticket_lifetime,
            ticket,
        }
        .encode();
        // RFC 5077 §3.3: NST is a regular handshake message — feed it into
        // the transcript so the server's Finished signs over it (and the
        // client's expected verify_data matches).
        self.transcript.update(&nst);
        self.write_plain_record(ContentType::Handshake, &nst);
        Ok(())
    }
}

/// State recovered from a valid client-presented ticket.
struct ResumedState {
    suite: SuiteParams12,
    master_secret: [u8; 48],
    /// RFC 7627 §5.3 — whether the originating session used Extended
    /// Master Secret. The resumed handshake's EMS negotiation MUST match.
    ems_used: bool,
}

/// Current wall-clock time as a Unix timestamp under `std`; zero otherwise
/// (used for ticket creation_time + expiry — the AEAD is the real auth).
#[cfg(feature = "std")]
fn system_now_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(not(feature = "std"))]
fn system_now_u64() -> u64 {
    0
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

/// RFC 8446 §4.1.3 downgrade sentinel: overwrite the last 8 bytes of
/// `server_random` with `44 4F 57 4E 47 52 44 01` ("DOWNGRD\x01") so a
/// TLS 1.3-aware client can detect that we downgraded the connection from
/// 1.3 to 1.2.
fn apply_downgrade_sentinel(sr: &mut [u8; 32]) {
    // "DOWNGRD\x01"
    const SENTINEL: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
    sr[24..].copy_from_slice(&SENTINEL);
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
impl<R: RngCore> super::stream::ConnectionIo for ServerConnection12<R> {
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
    use crate::tls::codec::{CipherSuite, ClientHello, ServerHello, hs_type, read_record};

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
            legacy_version: 0x0303,
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
            legacy_version: 0x0303,
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

    /// RFC 8446 §4.1.3 — a TLS 1.2 server embeds the `DOWNGRD\x01`
    /// sentinel in `server_random` regardless of whether the client offered
    /// TLS 1.3 in `supported_versions`. This guards a legacy 1.2 client
    /// against an in-path attacker stripping the extension to hide the
    /// downgrade.
    #[test]
    fn server12_embeds_downgrade_sentinel_without_supported_versions() {
        const DOWNGRD_13: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];

        let cfg = test_rsa_server_config();
        let rng = HmacDrbg::<Sha256>::new(b"s12-dgrd", b"nonce", &[]);
        let mut s = ServerConnection12::new(cfg, rng);

        // Synthesise a legacy TLS 1.2 ClientHello — no supported_versions.
        let mut crng = HmacDrbg::<Sha256>::new(b"s12-dgrd-c", b"nonce", &[]);
        let mut random = [0u8; 32];
        crng.fill_bytes(&mut random);
        let ch = ClientHello {
            legacy_version: 0x0303,
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

        // Find the ServerHello in the emitted records and decode it.
        let out = s.write_tls();
        let parsed = read_record(&out).unwrap().unwrap();
        assert_eq!(parsed.content_type, ContentType::Handshake);
        // First handshake byte is the message type; the rest is type+len+body.
        assert_eq!(parsed.fragment[0], hs_type::SERVER_HELLO);
        // The handshake body starts after the 4-byte type+length header.
        let sh = ServerHello::decode(&parsed.fragment[4..]).unwrap();
        assert_eq!(&sh.random[24..], &DOWNGRD_13);
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
            legacy_version: 0x0303,
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
