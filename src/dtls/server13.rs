#![allow(dead_code, unreachable_pub)]

//! DTLS 1.3 server state machine (RFC 9147).
//!
//! Mirror of [`super::client13::DtlsClientConnection13`]. The server:
//!
//! 1. Receives the first ClientHello over a plaintext DTLS 1.2-framed
//!    record (epoch 0).
//! 2. If cookie validation is enabled (default), emits a
//!    HelloRetryRequest with a `cookie` extension (RFC 9147 §5.1) and
//!    DROPS all per-connection state — the next CH must echo the cookie
//!    before any further processing.
//! 3. On the cookie-validated CH, derives handshake traffic secrets and
//!    sends the encrypted server flight (EE / Certificate /
//!    CertificateVerify / Finished).
//! 4. On the client's Finished, transitions to the application epoch.
//!
//! Scope of this commit (mirroring commit 10 / DTLS 1.2):
//!
//! - One cipher suite: `TLS_AES_128_GCM_SHA256` (0x1301).
//! - One key-exchange group: X25519.
//! - Server cert: ECDSA P-256.
//! - No mTLS, no PSK, no 0-RTT, no Connection ID.

use crate::ct::ConstantTimeEq;
use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
use crate::rng::RngCore;
use crate::signature_registry::SignaturePolicy;
use crate::tls::codec::extension as ext;
use crate::tls::codec::{
    CipherSuite, ClientHello, ExtensionType, NamedGroup, Random, ReadCursor, ServerHello,
    SignatureScheme, hs_type, with_len_u16, with_len_u24,
};
use crate::tls::crypto::sign::sign_certificate_verify;
use crate::tls::crypto::{
    AeadAlg, HashAlg, KeySchedule, RecordCrypter, Transcript, certificate_verify_content,
    finished_verify_data,
};
use crate::tls::keylog::KeyLog;
use crate::tls::{ContentType, Error, ProtocolVersion};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use super::ack::{ACK_CONTENT_TYPE, RecordNumber, decode as decode_ack, encode as encode_ack};
use super::client13::{decrypt_dtls13_record, derive_sn_key, encrypt_dtls13_record};
use super::cookie::CookieGenerator;
use super::reassembly::{HandshakeFragment, Reassembler, read_fragment, write_message};
use super::record::{self, ParsedDtlsRecord};
use super::record13::{self, peek_header_layout, reconstruct_seq, sn_mask_aes128};
use super::reliability13::{InFlightRecord, Retransmit13};

/// HelloRetryRequest sentinel `random` value (RFC 8446 §4.1.3).
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// `cookie` extension type (RFC 8446 §4.2.2).
const EXT_COOKIE: u16 = 0x002C;

/// Default per-fragment payload size for outbound handshake messages.
const DEFAULT_MAX_FRAGMENT: usize = 1100;

/// Configuration for a DTLS 1.3 server.
///
/// `pub(crate)`: external users build a [`crate::tls::Config`] and call
/// [`crate::tls::Connection::server`], which derives this internal config.
pub(crate) struct ServerConfig13Internal {
    /// Certificate chain (leaf first).
    pub cert_chain: Vec<Vec<u8>>,
    /// Signing key for the leaf certificate. Any of the
    /// [`crate::tls::conn::ServerKey`] variants are accepted — RSA-PSS,
    /// ECDSA (any curve), Ed25519, ML-DSA-44/65/87.
    pub key: crate::tls::conn::ServerKey,
    /// Cookie secret. When `None`, the cookie exchange is skipped (tests
    /// only). A production configuration always sets this.
    pub cookie_secret: Option<[u8; 32]>,
    /// When `true`, every client must complete the cookie exchange before
    /// the server allocates any per-connection handshake state. Default
    /// `true`.
    pub require_cookie: bool,
    /// Allowed signature algorithms (reserved for client-auth in a future
    /// commit; currently unused on the server side because we don't accept
    /// client certificates yet).
    #[allow(dead_code)]
    pub signature_policy: Arc<SignaturePolicy>,
    /// Optional [`KeyLog`] sink (NSS `SSLKEYLOGFILE` format).
    pub key_log: Option<Arc<dyn KeyLog>>,
}

impl ServerConfig13Internal {
    /// New configuration with an opaque signing key. Cookie validation is
    /// required by default; call [`Self::with_no_cookie`] to disable it for
    /// tests.
    pub fn with_signing_key(cert_chain: Vec<Vec<u8>>, key: crate::tls::conn::ServerKey) -> Self {
        Self {
            cert_chain,
            key,
            cookie_secret: None,
            require_cookie: true,
            signature_policy: Arc::new(SignaturePolicy::modern()),
            key_log: None,
        }
    }

    /// Back-compat constructor that takes an ECDSA private key. Forwards to
    /// [`Self::with_signing_key`].
    #[allow(dead_code)]
    pub fn with_ecdsa(cert_chain: Vec<Vec<u8>>, key: BoxedEcdsaPrivateKey) -> Self {
        Self::with_signing_key(cert_chain, crate::tls::conn::ServerKey::Ecdsa(key))
    }

    /// Sets the long-lived cookie secret. Required when `require_cookie`
    /// is `true` (the default).
    pub fn with_cookie_secret(mut self, secret: [u8; 32]) -> Self {
        self.cookie_secret = Some(secret);
        self
    }

    /// Disables the cookie exchange. Tests only.
    pub fn with_no_cookie(mut self) -> Self {
        self.require_cookie = false;
        self
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum State {
    /// Awaiting the first ClientHello.
    WaitFirstClientHello,
    /// Sent HRR with cookie; awaiting cookie-bearing second CH.
    WaitSecondClientHello,
    /// Sent the server flight; awaiting client Finished.
    WaitClientFinished,
    Connected,
    Closed,
}

/// A DTLS 1.3 server connection.
pub struct DtlsServerConnection13<R: RngCore> {
    config: Arc<ServerConfig13Internal>,
    rng: R,

    peer_addr: Vec<u8>,

    state: State,

    /// DTLS handshake msg_seq counter for outbound messages.
    out_msg_seq: u16,
    /// Reassembler for inbound handshake messages.
    reassembler: Option<Reassembler>,

    out_dgrams: Vec<Vec<u8>>,
    app_in: Vec<u8>,

    /// Plaintext (epoch 0) record state.
    plain_write_epoch: u16,
    plain_write_seq: u64,

    /// Protected-write state (epoch 2 during handshake, epoch 3 after).
    enc_write_epoch: u16,
    enc_write_seq: u64,
    enc_read_seq: u64,
    /// RFC 9147 §4.5.1 anti-replay window for the current read epoch.
    /// Reset at every epoch transition. Required: an attacker who captures
    /// any encrypted record can otherwise replay it indefinitely.
    read_replay: crate::dtls::replay::AntiReplayWindow,

    /// Ephemeral X25519 key.
    x25519: Option<X25519PrivateKey>,

    client_random: Option<Random>,
    server_random: Option<Random>,

    transcript: Transcript,
    ks: Option<KeySchedule>,
    client_hs_secret: Option<crate::tls::crypto::Secret>,
    server_hs_secret: Option<crate::tls::crypto::Secret>,
    client_app_secret: Option<crate::tls::crypto::Secret>,
    server_app_secret: Option<crate::tls::crypto::Secret>,

    /// Active write-side RecordCrypter.
    write_crypter: Option<RecordCrypter>,
    /// Active read-side RecordCrypter.
    read_crypter: Option<RecordCrypter>,
    write_sn_key: Option<[u8; 16]>,
    read_sn_key: Option<[u8; 16]>,
    read_app_sn_key: Option<[u8; 16]>,
    write_app_sn_key: Option<[u8; 16]>,
    pending_read_app_crypter: Option<RecordCrypter>,
    pending_write_app_crypter: Option<RecordCrypter>,

    /// Pending ACKs to emit.
    pending_acks: Vec<RecordNumber>,
    /// ACK-driven retransmit state.
    retransmit: Retransmit13,
    last_now: Duration,
}

impl<R: RngCore> DtlsServerConnection13<R> {
    /// Creates a server awaiting a ClientHello from `peer_addr`. `peer_addr`
    /// is the opaque identifier used by the cookie generator.
    pub(crate) fn new(config: Arc<ServerConfig13Internal>, peer_addr: Vec<u8>, rng: R) -> Self {
        let mut t = Transcript::new();
        t.set_alg(HashAlg::Sha256);
        Self {
            config,
            rng,
            peer_addr,
            state: State::WaitFirstClientHello,
            out_msg_seq: 0,
            reassembler: None,
            out_dgrams: Vec::new(),
            app_in: Vec::new(),
            plain_write_epoch: 0,
            plain_write_seq: 0,
            enc_write_epoch: 0,
            enc_write_seq: 0,
            enc_read_seq: 0,
            read_replay: crate::dtls::replay::AntiReplayWindow::new(),
            x25519: None,
            client_random: None,
            server_random: None,
            transcript: t,
            ks: None,
            client_hs_secret: None,
            server_hs_secret: None,
            client_app_secret: None,
            server_app_secret: None,
            write_crypter: None,
            read_crypter: None,
            write_sn_key: None,
            read_sn_key: None,
            read_app_sn_key: None,
            write_app_sn_key: None,
            pending_read_app_crypter: None,
            pending_write_app_crypter: None,
            pending_acks: Vec::new(),
            retransmit: Retransmit13::new(),
            last_now: Duration::from_secs(0),
        }
    }

    /// Returns true once the handshake completes.
    pub fn is_handshake_complete(&self) -> bool {
        self.state == State::Connected
    }

    /// Drains pending UDP datagrams. Also drains any pending ACKs.
    pub fn pop_outbound_datagrams(&mut self) -> Vec<Vec<u8>> {
        self.flush_pending_acks();
        core::mem::take(&mut self.out_dgrams)
    }

    /// Drains decrypted application data.
    pub fn take_received(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app_in)
    }

    /// Encrypts application plaintext. Must be called only after the
    /// handshake completes.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::InappropriateState);
        }
        let dg = self.encrypt_protected_record(ContentType::ApplicationData, plaintext)?;
        self.out_dgrams.push(dg);
        Ok(())
    }

    /// Absolute monotonic time at which `on_timeout` should be called next.
    pub fn next_timeout(&self) -> Option<Duration> {
        self.retransmit.next_timeout()
    }

    /// Drives the retransmit machine.
    pub fn on_timeout(&mut self, now: Duration) {
        self.last_now = now;
        match self.retransmit.on_timeout(now) {
            super::reliability::Action::Retransmit => {
                for dg in self.retransmit.in_flight_datagrams() {
                    self.out_dgrams.push(dg.to_vec());
                }
            }
            super::reliability::Action::GiveUp => self.state = State::Closed,
            super::reliability::Action::Idle => {}
        }
    }

    /// Feeds one incoming UDP datagram.
    pub fn feed_datagram(&mut self, datagram: &[u8]) -> Result<(), Error> {
        let mut off = 0usize;
        while off < datagram.len() {
            let first = datagram[off];
            if first < 32 {
                let Some(rec) = record::read_record(&datagram[off..])? else {
                    return Ok(());
                };
                off += rec.len;
                self.process_plaintext_record(rec)?;
            } else if (first & 0b1110_0000) == 0b0010_0000 {
                let consumed = self.process_protected_record(&datagram[off..])?;
                if consumed == 0 {
                    return Ok(());
                }
                off += consumed;
            } else {
                return Ok(());
            }
        }
        Ok(())
    }

    fn process_plaintext_record(&mut self, rec: ParsedDtlsRecord<'_>) -> Result<(), Error> {
        if rec.version != ProtocolVersion::DTLSv1_2 && rec.version != ProtocolVersion::DTLSv1_0 {
            return Err(Error::UnsupportedVersion);
        }
        if rec.epoch != 0 {
            return Ok(());
        }
        match rec.content_type {
            ContentType::Handshake => self.process_handshake_record(rec.fragment),
            ContentType::Alert => Ok(()),
            ContentType::ChangeCipherSpec => Ok(()),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    fn process_protected_record(&mut self, buf: &[u8]) -> Result<usize, Error> {
        let (hdr_len, body_len) = peek_header_layout(buf)?;
        let total = hdr_len + body_len;
        if total > buf.len() {
            return Ok(0);
        }
        let body = &buf[hdr_len..total];
        if body.len() < 16 {
            return Err(Error::Decode);
        }
        let sn_key = self.read_sn_key.ok_or(Error::UnexpectedMessage)?;
        let mask_full = sn_mask_aes128(&sn_key, body);
        let mask: &[u8] = if (buf[0] & 0b0000_1000) != 0 {
            &mask_full[..2]
        } else {
            &mask_full[..1]
        };
        let (hdr, ct_body) = record13::decode_record(buf, mask)?;
        let consumed = hdr.header_len + ct_body.len();

        let read_epoch = self.current_read_epoch();
        if (read_epoch as u8 & 0b11) != hdr.epoch_low2 {
            return Ok(consumed);
        }
        let seq = reconstruct_seq(
            hdr.seq_low,
            hdr.seq_is_16bit,
            self.enc_read_seq.wrapping_add(1),
        );

        // RFC 9147 §4.2.3: AAD is the unified header prior to seq masking.
        let mut aad = buf[..hdr.header_len].to_vec();
        if hdr.seq_is_16bit {
            aad[1] ^= mask[0];
            aad[2] ^= mask[1];
        } else {
            aad[1] ^= mask[0];
        }
        let crypter = self.read_crypter.as_mut().ok_or(Error::UnexpectedMessage)?;
        let (inner_type, plain) = decrypt_dtls13_record(crypter, read_epoch, seq, &aad, ct_body)?;
        // RFC 9147 §4.5.1: drop duplicates and too-old records via the
        // sliding-window filter. The AEAD already verified the record, but
        // an attacker can replay any verified record indefinitely unless
        // we filter at this layer.
        if !self.read_replay.accept(seq) {
            return Ok(consumed);
        }
        if seq > self.enc_read_seq {
            self.enc_read_seq = seq;
        }
        let is_handshake = matches!(
            inner_type,
            ContentType::Handshake | ContentType::Alert | ContentType::Unknown(ACK_CONTENT_TYPE)
        );
        if is_handshake {
            self.pending_acks.push(RecordNumber {
                epoch: read_epoch as u64,
                seq,
            });
        }

        match inner_type {
            ContentType::Handshake => self.process_handshake_record(&plain)?,
            ContentType::ApplicationData => {
                if self.state != State::Connected {
                    return Err(Error::UnexpectedMessage);
                }
                self.app_in.extend_from_slice(&plain);
            }
            ContentType::Alert => {}
            ContentType::Unknown(t) if t == ACK_CONTENT_TYPE => {
                let acks = decode_ack(&plain)?;
                self.retransmit.on_ack(&acks);
            }
            _ => return Err(Error::UnexpectedMessage),
        }
        Ok(consumed)
    }

    fn current_read_epoch(&self) -> u16 {
        if matches!(self.state, State::Connected) {
            3
        } else {
            2
        }
    }

    fn process_handshake_record(&mut self, plain: &[u8]) -> Result<(), Error> {
        let mut off = 0;
        while off < plain.len() {
            let frag = read_fragment(&plain[off..])?;
            let consumed = frag.len;
            if self.reassembler.is_none() {
                // Pre-state cookie path: only ClientHello allowed.
                if frag.msg_type != hs_type::CLIENT_HELLO {
                    return Err(Error::UnexpectedMessage);
                }
                if frag.fragment_offset != 0 || (frag.fragment.len() as u32) != frag.total_length {
                    return Err(Error::Decode);
                }
                let body = frag.fragment.to_vec();
                let msg_seq = frag.message_seq;
                off += consumed;
                self.handle_pre_state_client_hello(msg_seq, &body)?;
                continue;
            }
            let frag = HandshakeFragment {
                msg_type: frag.msg_type,
                total_length: frag.total_length,
                message_seq: frag.message_seq,
                fragment_offset: frag.fragment_offset,
                fragment: frag.fragment,
                len: frag.len,
            };
            off += consumed;
            let feeding = self
                .reassembler
                .as_mut()
                .expect("reassembler built")
                .feed(frag);
            if let Some((mt, body)) = feeding {
                self.dispatch_one(mt, &body)?;
            }
            loop {
                let popped = self
                    .reassembler
                    .as_mut()
                    .expect("reassembler built")
                    .pop_ready();
                match popped {
                    Some((mt, body)) => self.dispatch_one(mt, &body)?,
                    None => break,
                }
            }
        }
        Ok(())
    }

    fn dispatch_one(&mut self, msg_type: u8, body: &[u8]) -> Result<(), Error> {
        let mut raw = Vec::with_capacity(4 + body.len());
        raw.push(msg_type);
        let n = body.len() as u32;
        raw.push(((n >> 16) & 0xff) as u8);
        raw.push(((n >> 8) & 0xff) as u8);
        raw.push((n & 0xff) as u8);
        raw.extend_from_slice(body);
        match self.state {
            State::WaitClientFinished => self.on_client_finished(msg_type, body, &raw),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Handle a fresh CH (no reassembler state).
    fn handle_pre_state_client_hello(&mut self, msg_seq: u16, body: &[u8]) -> Result<(), Error> {
        let ch = ClientHello::decode(body)?;
        let cookie_required = self.config.require_cookie && self.config.cookie_secret.is_some();
        // Look for an existing cookie extension in CH.
        let presented_cookie = ch
            .extensions
            .iter()
            .find(|(t, _)| t.0 == EXT_COOKIE)
            .map(|(_, b)| b.clone());

        if cookie_required && presented_cookie.is_none() {
            // First CH: emit HRR with a freshly-minted cookie.
            let secret = self
                .config
                .cookie_secret
                .as_ref()
                .ok_or(Error::InappropriateState)?;
            let cg = CookieGenerator::new(*secret);
            let now_min = (self.last_now.as_secs() / 60) as u32;
            let cookie = cg.generate(&self.peer_addr, &ch.random, now_min);
            // Transcript: per RFC 8446 §4.4.1, when HRR is in play, the
            // transcript replaces CH1 with `message_hash(CH1)`. We compute
            // CH1's hash NOW (before transcript update), emit HRR, then
            // continue with the normal transcript update from CH2.
            // We don't actually need the transcript-replacement step here
            // because we discard *all* server state on HRR; the CH2 path
            // will rebuild the transcript from scratch using
            // `replace_with_message_hash`.
            self.emit_hello_retry_request(&cookie)?;
            self.state = State::WaitSecondClientHello;
            // Stash CH1's transcript-hash so we can rebuild a proper
            // post-HRR transcript on CH2. We feed CH1 into a separate
            // transcript pass to compute message_hash(CH1).
            let mut t = Transcript::new();
            t.set_alg(HashAlg::Sha256);
            // CH1 in TLS-shape:
            let mut tls_ch = Vec::with_capacity(4 + body.len());
            tls_ch.push(hs_type::CLIENT_HELLO);
            let n = body.len() as u32;
            tls_ch.push(((n >> 16) & 0xff) as u8);
            tls_ch.push(((n >> 8) & 0xff) as u8);
            tls_ch.push((n & 0xff) as u8);
            tls_ch.extend_from_slice(body);
            t.update(&tls_ch);
            // We park `t` inside `self.transcript`; on CH2 we'll call
            // replace_with_message_hash on it before continuing.
            self.transcript = t;
            // Don't allocate a reassembler — the next CH must also enter
            // this pre-state path.
            // out_msg_seq is now 1 (HRR consumed msg_seq=0).
            self.out_msg_seq = 1;
            let _ = msg_seq;
            return Ok(());
        }

        if cookie_required {
            let cookie_bytes = presented_cookie
                .as_ref()
                .ok_or(Error::IllegalParameter)?
                .clone();
            // Validate cookie before any further work.
            let secret = self
                .config
                .cookie_secret
                .as_ref()
                .ok_or(Error::InappropriateState)?;
            let cg = CookieGenerator::new(*secret);
            // The cookie wire format is `opaque cookie<1..2^16-1>`, so the
            // first 2 bytes are a u16 length prefix.
            if cookie_bytes.len() < 2 {
                return Err(Error::Decode);
            }
            let clen = u16::from_be_bytes([cookie_bytes[0], cookie_bytes[1]]) as usize;
            if cookie_bytes.len() != 2 + clen {
                return Err(Error::Decode);
            }
            let cookie = &cookie_bytes[2..];
            let now_min = (self.last_now.as_secs() / 60) as u32;
            if !cg.validate(&self.peer_addr, &ch.random, now_min, cookie) {
                return Err(Error::IllegalParameter);
            }
            // CH2 transcript: replace CH1 with message_hash(CH1) (already
            // in self.transcript from the pre-state path above), then
            // append the HRR and CH2.
            self.transcript.replace_with_message_hash();
            // Re-derive the HRR bytes so we can update the transcript.
            let hrr_bytes = self.build_hrr_bytes(cookie);
            self.transcript.update(&hrr_bytes);
        }
        // Sanity checks: suites + groups.
        if !ch.cipher_suites.contains(&CipherSuite::AES_128_GCM_SHA256) {
            return Err(Error::HandshakeFailure);
        }
        let groups_ext = ext::find(&ch.extensions, ExtensionType::SUPPORTED_GROUPS)
            .ok_or(Error::HandshakeFailure)?;
        let groups = parse_supported_groups(groups_ext)?;
        if !groups.contains(&NamedGroup::X25519) {
            return Err(Error::HandshakeFailure);
        }
        let ks_ext =
            ext::find(&ch.extensions, ExtensionType::KEY_SHARE).ok_or(Error::HandshakeFailure)?;
        let client_shares = ext::parse_client_key_shares(ks_ext)?;
        let (g, client_pub) = client_shares
            .iter()
            .find(|(g, _)| *g == NamedGroup::X25519)
            .ok_or(Error::HandshakeFailure)?;
        if *g != NamedGroup::X25519 {
            return Err(Error::HandshakeFailure);
        }
        let client_pub = client_pub.clone();

        self.client_random = Some(ch.random);
        // CH2 (or first-and-only CH when cookies are off) into the
        // transcript (TLS-shaped).
        let mut tls_ch = Vec::with_capacity(4 + body.len());
        tls_ch.push(hs_type::CLIENT_HELLO);
        let n = body.len() as u32;
        tls_ch.push(((n >> 16) & 0xff) as u8);
        tls_ch.push(((n >> 8) & 0xff) as u8);
        tls_ch.push((n & 0xff) as u8);
        tls_ch.extend_from_slice(body);
        if !cookie_required {
            // Cookie-off path: this is CH1, transcript starts fresh.
            self.transcript = Transcript::new();
            self.transcript.set_alg(HashAlg::Sha256);
        }
        self.transcript.update(&tls_ch);

        // Initialise the reassembler at msg_seq+1.
        let mut reasm = Reassembler::new();
        for s in 0..=msg_seq {
            let mut buf = Vec::new();
            write_message(&mut buf, hs_type::CLIENT_HELLO, s, b"", 0);
            let f = read_fragment(&buf)?;
            let _ = reasm.feed(f);
        }
        self.reassembler = Some(reasm);

        // Generate server random + ephemeral X25519.
        let mut sr: Random = [0u8; 32];
        self.rng.fill_bytes(&mut sr);
        self.server_random = Some(sr);
        let sk = X25519PrivateKey::generate(&mut self.rng);
        let server_pub = sk.public_key().to_vec();
        // ECDHE.
        let client_peer: [u8; 32] = client_pub
            .as_slice()
            .try_into()
            .map_err(|_| Error::Decode)?;
        // RFC 7748 §6.1 / RFC 8446 §7.4.2: reject the all-zero DH output.
        let shared = sk
            .diffie_hellman(&client_peer)
            .map_err(|_| Error::IllegalParameter)?;
        self.x25519 = Some(sk);

        // ServerHello.
        let sh_extensions = alloc::vec![
            ext::server_key_share(NamedGroup::X25519, &server_pub),
            ext::server_supported_versions(),
        ];
        let sh_bytes = ServerHello {
            random: sr,
            session_id: ch.session_id.clone(),
            cipher_suite: CipherSuite::AES_128_GCM_SHA256,
            extensions: sh_extensions,
        }
        .encode();
        self.transcript.update(&sh_bytes);

        // Send SH as a plaintext DTLS record (epoch 0).
        let sh_body = &sh_bytes[4..];
        let sh_msg_seq = self.out_msg_seq;
        self.out_msg_seq += 1;
        let mut frag_buf = Vec::new();
        write_message(
            &mut frag_buf,
            hs_type::SERVER_HELLO,
            sh_msg_seq,
            sh_body,
            DEFAULT_MAX_FRAGMENT,
        );
        let sh_dgram = self.wrap_plain_record(ContentType::Handshake, &frag_buf);
        self.emit_plaintext(sh_dgram);

        // Derive handshake traffic secrets and install protected crypters.
        let mut ks = KeySchedule::new(HashAlg::Sha256);
        ks.enter_handshake(&shared);
        let th = self.transcript.current_hash();
        let chts = ks.client_handshake_traffic_secret(th.as_slice());
        let shts = ks.server_handshake_traffic_secret(th.as_slice());
        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                &ch.random,
                chts.as_slice(),
            );
            kl.log(
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                &ch.random,
                shts.as_slice(),
            );
        }
        let w_crypter = RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &shts);
        let r_crypter = RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &chts);
        self.write_crypter = Some(w_crypter);
        self.read_crypter = Some(r_crypter);
        self.write_sn_key = Some(derive_sn_key(HashAlg::Sha256, &shts));
        self.read_sn_key = Some(derive_sn_key(HashAlg::Sha256, &chts));
        self.enc_write_epoch = 2;
        self.enc_write_seq = 0;
        self.enc_read_seq = 0;
        self.read_replay = crate::dtls::replay::AntiReplayWindow::new();
        self.ks = Some(ks);
        self.client_hs_secret = Some(chts);
        self.server_hs_secret = Some(shts);

        // Build and emit the encrypted server flight: EE, Certificate, CV,
        // Finished.
        self.send_encrypted_extensions()?;
        self.send_certificate()?;
        self.send_certificate_verify()?;
        self.send_finished()?;

        // Derive application traffic secrets (Hash(CH..server Finished))
        // and stash them for installation at client Finished.
        let (cats, sats, ems) = {
            let ks = self.ks.as_mut().expect("ks");
            ks.enter_master();
            let th_app = self.transcript.current_hash();
            let cats = ks.client_application_traffic_secret(th_app.as_slice());
            let sats = ks.server_application_traffic_secret(th_app.as_slice());
            let ems = ks.exporter_master_secret(th_app.as_slice());
            (cats, sats, ems)
        };
        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log("CLIENT_TRAFFIC_SECRET_0", &ch.random, cats.as_slice());
            kl.log("SERVER_TRAFFIC_SECRET_0", &ch.random, sats.as_slice());
            kl.log("EXPORTER_SECRET", &ch.random, ems.as_slice());
        }
        let _ = ems;
        self.pending_write_app_crypter = Some(RecordCrypter::new(
            HashAlg::Sha256,
            AeadAlg::Aes128Gcm,
            16,
            &sats,
        ));
        self.pending_read_app_crypter = Some(RecordCrypter::new(
            HashAlg::Sha256,
            AeadAlg::Aes128Gcm,
            16,
            &cats,
        ));
        self.write_app_sn_key = Some(derive_sn_key(HashAlg::Sha256, &sats));
        self.read_app_sn_key = Some(derive_sn_key(HashAlg::Sha256, &cats));
        self.client_app_secret = Some(cats);
        self.server_app_secret = Some(sats);

        self.state = State::WaitClientFinished;
        Ok(())
    }

    fn send_encrypted_extensions(&mut self) -> Result<(), Error> {
        // EE body: extensions length (u16). Empty for our subset (no ALPN
        // configured by the server in this commit).
        let mut body = Vec::new();
        with_len_u16(&mut body, |_| {});
        let mut tls_msg = Vec::with_capacity(4 + body.len());
        tls_msg.push(hs_type::ENCRYPTED_EXTENSIONS);
        let n = body.len() as u32;
        tls_msg.push(((n >> 16) & 0xff) as u8);
        tls_msg.push(((n >> 8) & 0xff) as u8);
        tls_msg.push((n & 0xff) as u8);
        tls_msg.extend_from_slice(&body);
        self.transcript.update(&tls_msg);
        self.emit_encrypted_handshake(hs_type::ENCRYPTED_EXTENSIONS, &body)?;
        Ok(())
    }

    fn send_certificate(&mut self) -> Result<(), Error> {
        let mut body = Vec::new();
        body.push(0); // certificate_request_context: empty
        with_len_u24(&mut body, |list| {
            for cert in &self.config.cert_chain {
                with_len_u24(list, |c| c.extend_from_slice(cert));
                with_len_u16(list, |_| {}); // per-cert extensions
            }
        });
        let mut tls_msg = Vec::with_capacity(4 + body.len());
        tls_msg.push(hs_type::CERTIFICATE);
        let n = body.len() as u32;
        tls_msg.push(((n >> 16) & 0xff) as u8);
        tls_msg.push(((n >> 8) & 0xff) as u8);
        tls_msg.push((n & 0xff) as u8);
        tls_msg.extend_from_slice(&body);
        self.transcript.update(&tls_msg);
        self.emit_encrypted_handshake(hs_type::CERTIFICATE, &body)?;
        Ok(())
    }

    fn send_certificate_verify(&mut self) -> Result<(), Error> {
        let th = self.transcript.current_hash();
        let content = certificate_verify_content(true, th.as_slice());
        let (scheme, sig_der) = sign_certificate_verify(&self.config.key, &content, &mut self.rng)?;

        let mut body = Vec::new();
        body.extend_from_slice(&scheme.0.to_be_bytes());
        with_len_u16(&mut body, |b| b.extend_from_slice(&sig_der));
        let mut tls_msg = Vec::with_capacity(4 + body.len());
        tls_msg.push(hs_type::CERTIFICATE_VERIFY);
        let n = body.len() as u32;
        tls_msg.push(((n >> 16) & 0xff) as u8);
        tls_msg.push(((n >> 8) & 0xff) as u8);
        tls_msg.push((n & 0xff) as u8);
        tls_msg.extend_from_slice(&body);
        self.transcript.update(&tls_msg);
        self.emit_encrypted_handshake(hs_type::CERTIFICATE_VERIFY, &body)?;
        Ok(())
    }

    fn send_finished(&mut self) -> Result<(), Error> {
        let shts = self
            .server_hs_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let th = self.transcript.current_hash();
        let verify_data = finished_verify_data(HashAlg::Sha256, shts, th.as_slice());
        let body = verify_data.as_slice().to_vec();
        let mut tls_msg = Vec::with_capacity(4 + body.len());
        tls_msg.push(hs_type::FINISHED);
        let n = body.len() as u32;
        tls_msg.push(((n >> 16) & 0xff) as u8);
        tls_msg.push(((n >> 8) & 0xff) as u8);
        tls_msg.push((n & 0xff) as u8);
        tls_msg.extend_from_slice(&body);
        self.transcript.update(&tls_msg);
        self.emit_encrypted_handshake(hs_type::FINISHED, &body)?;
        Ok(())
    }

    fn on_client_finished(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::FINISHED {
            return Err(Error::UnexpectedMessage);
        }
        let chts = self
            .client_hs_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let th = self.transcript.current_hash();
        let expected = finished_verify_data(HashAlg::Sha256, chts, th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.transcript.update(raw);

        // Install application keys atomically.
        self.write_crypter = self.pending_write_app_crypter.take();
        self.read_crypter = self.pending_read_app_crypter.take();
        self.write_sn_key = self.write_app_sn_key.take();
        self.read_sn_key = self.read_app_sn_key.take();
        self.enc_write_epoch = 3;
        self.enc_write_seq = 0;
        self.enc_read_seq = 0;
        self.read_replay = crate::dtls::replay::AntiReplayWindow::new();
        self.state = State::Connected;
        Ok(())
    }

    /// Builds the on-wire HRR bytes (4-byte TLS handshake header + body).
    /// `cookie` is the raw cookie payload (no length prefix).
    fn build_hrr_bytes(&self, cookie: &[u8]) -> Vec<u8> {
        let extensions = alloc::vec![
            ext::server_supported_versions(),
            (
                ExtensionType(EXT_COOKIE),
                // cookie extension body: `opaque cookie<1..2^16-1>` →
                // 2-byte u16 length prefix.
                {
                    let mut v = Vec::with_capacity(2 + cookie.len());
                    v.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
                    v.extend_from_slice(cookie);
                    v
                }
            ),
        ];
        ServerHello {
            random: HRR_RANDOM,
            session_id: Vec::new(),
            cipher_suite: CipherSuite::AES_128_GCM_SHA256,
            extensions,
        }
        .encode()
    }

    fn emit_hello_retry_request(&mut self, cookie: &[u8]) -> Result<(), Error> {
        let bytes = self.build_hrr_bytes(cookie);
        let body = &bytes[4..];
        // HRR is a ServerHello with the magic random; msg_seq=0 (this is
        // the server's first outbound handshake message).
        let mut frag_buf = Vec::new();
        write_message(
            &mut frag_buf,
            hs_type::SERVER_HELLO,
            0,
            body,
            DEFAULT_MAX_FRAGMENT,
        );
        let dgram = self.wrap_plain_record(ContentType::Handshake, &frag_buf);
        // HRR is plaintext — push directly. We don't track it in the
        // retransmit machine since we'll drop all state if no CH2 arrives.
        self.out_dgrams.push(dgram);
        Ok(())
    }

    fn wrap_plain_record(&mut self, ct: ContentType, fragment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        record::write_record(
            &mut out,
            ct,
            ProtocolVersion::DTLSv1_2,
            self.plain_write_epoch,
            self.plain_write_seq,
            fragment,
        );
        self.plain_write_seq += 1;
        out
    }

    fn encrypt_protected_record(
        &mut self,
        ct: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let crypter = self
            .write_crypter
            .as_mut()
            .ok_or(Error::InappropriateState)?;
        let sn_key = self.write_sn_key.ok_or(Error::InappropriateState)?;
        let epoch = self.enc_write_epoch;
        let seq = self.enc_write_seq;
        self.enc_write_seq += 1;
        let seq_is_16bit = true;
        let omit_length = false;

        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.extend_from_slice(payload);
        inner.push(ct.as_u8());

        // AAD = unified header bytes with un-masked seq (RFC 9147 §4.2.3).
        let mut aad = Vec::new();
        let aad_zero_mask = [0u8; 2];
        let ct_len = inner.len() + 16;
        record13::encode_record(
            &mut aad,
            epoch,
            seq,
            seq_is_16bit,
            omit_length,
            &alloc::vec![0u8; ct_len],
            &aad_zero_mask,
        );
        let hdr_len = aad.len() - ct_len;
        aad.truncate(hdr_len);

        encrypt_dtls13_record(crypter, epoch, seq, &aad, &mut inner)?;

        let mask_full = sn_mask_aes128(&sn_key, &inner);
        let mask: &[u8] = if seq_is_16bit {
            &mask_full[..2]
        } else {
            &mask_full[..1]
        };
        let mut wire = Vec::new();
        record13::encode_record(
            &mut wire,
            epoch,
            seq,
            seq_is_16bit,
            omit_length,
            &inner,
            mask,
        );
        Ok(wire)
    }

    fn emit_plaintext(&mut self, datagram: Vec<u8>) {
        let seq = self.plain_write_seq.saturating_sub(1);
        let record_number = RecordNumber {
            epoch: self.plain_write_epoch as u64,
            seq,
        };
        self.out_dgrams.push(datagram.clone());
        self.retransmit.on_record_sent(
            InFlightRecord {
                record_number,
                datagram,
            },
            self.last_now,
        );
    }

    /// Builds an encrypted handshake record carrying `msg_type` / `body`
    /// (DTLS handshake header wrapped, single fragment). Pushes the record
    /// to the outbound queue AND registers it with the ACK-driven retransmit
    /// machine.
    fn emit_encrypted_handshake(&mut self, msg_type: u8, body: &[u8]) -> Result<(), Error> {
        let msg_seq = self.out_msg_seq;
        self.out_msg_seq += 1;
        let mut frag_buf = Vec::new();
        write_message(&mut frag_buf, msg_type, msg_seq, body, DEFAULT_MAX_FRAGMENT);
        let dg = self.encrypt_protected_record(ContentType::Handshake, &frag_buf)?;
        let seq = self.enc_write_seq.saturating_sub(1);
        let record_number = RecordNumber {
            epoch: self.enc_write_epoch as u64,
            seq,
        };
        self.out_dgrams.push(dg.clone());
        self.retransmit.on_record_sent(
            InFlightRecord {
                record_number,
                datagram: dg,
            },
            self.last_now,
        );
        Ok(())
    }

    fn flush_pending_acks(&mut self) {
        if self.pending_acks.is_empty() {
            return;
        }
        if self.write_crypter.is_none() {
            return;
        }
        let acks = core::mem::take(&mut self.pending_acks);
        let body = encode_ack(&acks);
        if let Ok(dg) = self.encrypt_protected_record(ContentType::Unknown(ACK_CONTENT_TYPE), &body)
        {
            self.out_dgrams.push(dg);
        }
    }
}

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

fn ecdsa_scheme_for(curve: CurveId) -> SignatureScheme {
    match curve {
        CurveId::P384 => SignatureScheme::ECDSA_SECP384R1_SHA384,
        CurveId::P521 => SignatureScheme::ECDSA_SECP521R1_SHA512,
        _ => SignatureScheme::ECDSA_SECP256R1_SHA256,
    }
}
