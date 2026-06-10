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
//! Negotiation surface (matches the TLS 1.3 layer):
//!
//! - Cipher suites: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
//!   `TLS_CHACHA20_POLY1305_SHA256`.
//! - Groups: X25519, P-256, X25519+ML-KEM-768
//!   (draft-ietf-tls-ecdhe-mlkem).
//! - Server certificate signatures: RSA-PSS, ECDSA (any curve), Ed25519,
//!   ML-DSA-44/65/87 (draft-ietf-tls-mldsa).
//! - Out of scope: mTLS, PSK, 0-RTT, Connection ID.

use crate::ct::ConstantTimeEq;
use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, CurveId};
use crate::mlkem::{ENCAPS_KEY_BYTES, MlKem768EncapsKey};
use crate::rng::RngCore;
use crate::signature_registry::SignaturePolicy;
use crate::tls::codec::extension as ext;
use crate::tls::codec::{
    CipherSuite, ClientHello, ExtensionType, NamedGroup, Random, ReadCursor, ServerHello, hs_type,
    put_u16, with_len_u16, with_len_u24,
};
use crate::tls::crypto::sign::sign_certificate_verify;
use crate::tls::crypto::{
    HashAlg, KeySchedule, RecordCrypter, SuiteParams, Transcript, certificate_verify_content,
    finished_verify_data, supported_suites,
};
use crate::tls::keylog::KeyLog;
use crate::tls::{ContentType, Error, ProtocolVersion};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use super::ack::{ACK_CONTENT_TYPE, RecordNumber, decode as decode_ack, encode as encode_ack};
use super::client13::{
    decrypt_dtls13_record, derive_sn_key, encrypt_dtls13_record, sn_key_len_for,
};
use super::cookie::{CookieGenerator, build_ch_fingerprint};
use super::reassembly::{
    HandshakeFragment, MAX_HS_MSG_SEQ, Reassembler, read_fragment, write_message,
};
use super::record::{self, ParsedDtlsRecord};
use super::record13::{self, peek_header_layout, reconstruct_seq, sn_mask_for};
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

/// Ceiling on the claimed `total_length` of a ClientHello fed through the
/// pre-state reassembler, paired with a single in-flight message. This is
/// the pre-cookie, pre-address-validation path: with the default
/// reassembler limits (256 KiB × 8 messages) eight spoofed one-byte
/// fragments with distinct `message_seq` values, each claiming the maximum
/// `total_length`, would pin ~2 MiB of eagerly allocated buffers before
/// any return-routability check. A legitimate CH — even multi-share with
/// ML-KEM-768 — is well under 16 KiB, and the post-HRR CH2 is a single
/// `message_seq`.
const PRE_COOKIE_MAX_CH_LEN: u32 = 32 * 1024;

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
    ///
    /// # Warning: amplification / DoS vector
    ///
    /// With the cookie exchange off, a single spoofed-source ClientHello
    /// makes the server allocate per-connection state, perform an
    /// asymmetric signature, and emit its full multi-KB flight (SH + EE +
    /// Certificate + CertificateVerify + Finished) to an unverified
    /// address — well over 3x amplification toward a victim of the
    /// attacker's choosing (RFC 9147 §5.1). Never disable cookies on a
    /// server reachable from untrusted networks.
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
    /// Pre-handshake reassembler for the (possibly fragmented) initial
    /// ClientHello and post-HRR CH2. A multi-group offer (X25519 + P-256 +
    /// ML-KEM-768) overflows the per-record fragment budget, so CH may arrive
    /// in multiple records before we've allocated `reassembler`.
    pre_state_reasm: Option<Reassembler>,

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

    /// Ephemeral X25519 key (kept across the handshake for keylog
    /// correlation; the shared secret is derived inline). Unused once we
    /// pick a non-X25519 group, but retained for symmetry with the wider
    /// connection state.
    #[allow(dead_code)]
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
    /// Sequence-number protection keys (length matches the AEAD key length:
    /// 16 for AES-128-GCM, 32 for AES-256-GCM and ChaCha20-Poly1305, per
    /// RFC 9147 §4.2.3).
    write_sn_key: Option<Vec<u8>>,
    read_sn_key: Option<Vec<u8>>,
    read_app_sn_key: Option<Vec<u8>>,
    write_app_sn_key: Option<Vec<u8>>,
    pending_read_app_crypter: Option<RecordCrypter>,
    pending_write_app_crypter: Option<RecordCrypter>,
    /// Negotiated cipher suite parameters (set once we pick a suite from
    /// the cookie-validated CH).
    suite: Option<SuiteParams>,
    /// `exporter_master_secret` (RFC 8446 §7.5), retained after the
    /// server-Finished derivation so [`Self::tls_exporter`] can be called
    /// any number of times once the handshake completes.
    exporter_secret: Option<crate::tls::crypto::Secret>,
    /// Group selected for HelloRetryRequest, if any. When set, CH2 must
    /// carry a `key_share` for this group (RFC 8446 §4.1.4 / §4.2.8).
    hrr_selected_group: Option<NamedGroup>,

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
        // Transcript hash is pinned later once we select a cipher suite from
        // the (cookie-validated) ClientHello — the buffer-everything design
        // lets us defer the hash choice until then.
        let t = Transcript::new();
        Self {
            config,
            rng,
            peer_addr,
            state: State::WaitFirstClientHello,
            out_msg_seq: 0,
            reassembler: None,
            pre_state_reasm: None,
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
            suite: None,
            exporter_secret: None,
            hrr_selected_group: None,
            pending_acks: Vec::new(),
            retransmit: Retransmit13::new(),
            last_now: Duration::from_secs(0),
        }
    }

    /// Returns true once the handshake completes.
    pub fn is_handshake_complete(&self) -> bool {
        self.state == State::Connected
    }

    /// IANA cipher-suite identifier of the negotiated suite, or `None`
    /// until the handshake completes.
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        if self.is_handshake_complete() {
            self.suite.map(|s| s.suite.0)
        } else {
            None
        }
    }

    /// RFC 8446 §7.5 / RFC 5705 — DTLS 1.3 application-layer Exporter.
    /// Derives `out.len()` bytes from the `exporter_master_secret` under
    /// `(label, context)`. The derivation matches TLS 1.3's exporter —
    /// DTLS 1.3 explicitly reuses the TLS 1.3 key schedule. Returns
    /// `Err(InappropriateState)` until the handshake completes.
    pub fn tls_exporter(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let ems = self
            .exporter_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        crate::tls::crypto::tls_exporter(suite.hash, ems, label, context, out);
        Ok(())
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

    /// Advances the connection's monotonic clock to `now`. Callers SHOULD
    /// invoke this (or [`Self::on_timeout`]) regularly so the cookie
    /// generator sees a current time — otherwise a server with no
    /// timeouts firing would reuse a stale cookie-issue timestamp and the
    /// embedded-`TS` age check (RFC 9147 §5.1) would be effectively
    /// disabled. Idempotent in the rewind direction (older times are
    /// ignored).
    pub fn set_now(&mut self, now: Duration) {
        if now > self.last_now {
            self.last_now = now;
        }
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
                // A truncated trailing record or a bogus declared length
                // (RecordOverflow) means framing is lost for the rest of the
                // datagram: silently discard (RFC 9147 §4.5.2) — a single
                // spoofed datagram must never be fatal.
                let rec = match record::read_record(&datagram[off..]) {
                    Ok(Some(rec)) => rec,
                    Ok(None) | Err(_) => return Ok(()),
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

    /// Processes one legacy-framed plaintext record (epoch 0).
    ///
    /// Everything in here is unauthenticated, attacker-spoofable input, so
    /// per RFC 9147 §4.5.2 every rejection is a silent drop — never fatal.
    fn process_plaintext_record(&mut self, rec: ParsedDtlsRecord<'_>) -> Result<(), Error> {
        if rec.version != ProtocolVersion::DTLSv1_2 && rec.version != ProtocolVersion::DTLSv1_0 {
            // Unknown record version: silently discard.
            return Ok(());
        }
        if rec.epoch != 0 {
            return Ok(());
        }
        match rec.content_type {
            ContentType::Handshake => {
                // Plaintext handshake records are only meaningful while we
                // still await a ClientHello. Afterwards (and in particular
                // once connected) they are trivially spoofable and must not
                // be able to affect the connection.
                if matches!(
                    self.state,
                    State::WaitFirstClientHello | State::WaitSecondClientHello
                ) {
                    self.process_handshake_record(rec.fragment, false)
                } else {
                    Ok(())
                }
            }
            ContentType::Alert => Ok(()),
            ContentType::ChangeCipherSpec => Ok(()),
            // Unknown / unexpected plaintext content type: silent discard.
            _ => Ok(()),
        }
    }

    /// Processes one unified-header protected record, returning the number
    /// of bytes consumed from `buf` (0 = couldn't parse, drop datagram).
    ///
    /// Until the AEAD tag verifies, everything in here is unauthenticated,
    /// attacker-spoofable input — per RFC 9147 §4.5.2 every rejection is a
    /// silent drop (skip the record, or the rest of the datagram where
    /// framing is lost), never connection-fatal.
    fn process_protected_record(&mut self, buf: &[u8]) -> Result<usize, Error> {
        // A malformed unified header means framing is lost: drop the rest
        // of the datagram.
        let Ok((hdr_len, body_len)) = peek_header_layout(buf) else {
            return Ok(0);
        };
        let total = hdr_len + body_len;
        if total > buf.len() {
            return Ok(0);
        }
        let body = &buf[hdr_len..total];
        if body.len() < 16 {
            // Smaller than the AEAD tag alone — bogus; skip this record.
            return Ok(total);
        }
        // A protected record that arrives before the protected read keys
        // exist is unprocessable — skip it.
        let Some(suite) = self.suite else {
            return Ok(total);
        };
        let Some(sn_key) = self.read_sn_key.as_ref() else {
            return Ok(total);
        };
        let Ok(mask_full) = sn_mask_for(suite, sn_key, body) else {
            return Ok(total);
        };
        let mask: &[u8] = if (buf[0] & 0b0000_1000) != 0 {
            &mask_full[..2]
        } else {
            &mask_full[..1]
        };
        let Ok((hdr, ct_body)) = record13::decode_record(buf, mask) else {
            return Ok(total);
        };
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
        // Pre-AEAD anti-replay check: cheap rejection of duplicate /
        // too-old seq numbers without touching window state. The window
        // is only `mark`-ed after AEAD verification succeeds so a forged
        // packet that fails AEAD does not burn a slot.
        if !self.read_replay.check(seq) {
            return Ok(consumed);
        }
        let Some(crypter) = self.read_crypter.as_mut() else {
            return Ok(consumed);
        };
        let Ok((inner_type, plain)) = decrypt_dtls13_record(crypter, seq, &aad, ct_body) else {
            // AEAD authentication failed — a single spoofed datagram must
            // not kill the connection (RFC 9147 §4.5.2): silent drop. The
            // replay window was deliberately not advanced.
            return Ok(consumed);
        };
        // RFC 9147 §4.5.1: AEAD verified — now commit to the window.
        self.read_replay.mark(seq);
        if seq > self.enc_read_seq {
            self.enc_read_seq = seq;
        }
        // Schedule an ACK for handshake records only (RFC 9147 §7): alerts
        // are not handshake messages, and ACK records themselves MUST NOT
        // be acknowledged — ACKing an ACK provokes the peer's ACK in
        // return, locking two conforming endpoints into a perpetual
        // encrypted ping-pong.
        let is_handshake = matches!(inner_type, ContentType::Handshake);
        if is_handshake {
            self.pending_acks.push(RecordNumber {
                epoch: read_epoch as u64,
                seq,
            });
        }

        // Past this point the record is authenticated: protocol violations
        // below come from the genuine peer and remain fatal.
        match inner_type {
            ContentType::Handshake => self.process_handshake_record(&plain, true)?,
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

    /// Processes the handshake fragments in one record body.
    ///
    /// `authenticated` is true when the bytes came out of a successfully
    /// AEAD-verified record. Framing errors in unauthenticated (plaintext)
    /// records are attacker-spoofable and dropped silently; the same errors
    /// in authenticated records are genuine peer faults and stay fatal.
    fn process_handshake_record(&mut self, plain: &[u8], authenticated: bool) -> Result<(), Error> {
        let mut off = 0;
        while off < plain.len() {
            let frag = match read_fragment(&plain[off..]) {
                Ok(f) => f,
                Err(e) => {
                    if authenticated {
                        return Err(e);
                    }
                    // Silently drop the rest of this spoofable record.
                    return Ok(());
                }
            };
            let consumed = frag.len;
            if self.reassembler.is_none() {
                // Pre-state path: only ClientHello allowed. A multi-group
                // offer overflows the per-record fragment budget, so CH may
                // arrive in several records — feed them through a temporary
                // reassembler (RFC 9147 §5.5) and only dispatch once the
                // full body is in hand.
                if frag.msg_type != hs_type::CLIENT_HELLO {
                    // Unauthenticated epoch-0 input: silently drop the rest
                    // of the record rather than killing the connection.
                    return Ok(());
                }
                let msg_seq = frag.message_seq;
                // F3: reject an implausibly large `message_seq` BEFORE seeding
                // the reassembler. This is the pre-cookie, epoch-0,
                // unauthenticated path — a hostile ClientHello with
                // message_seq=0xFFFF would otherwise force up to 65 535
                // allocate/serialize/parse/feed cycles below. Spoofable
                // input, so the rejection is a silent drop (RFC 9147
                // §4.5.2), never connection-fatal.
                if msg_seq > MAX_HS_MSG_SEQ {
                    return Ok(());
                }
                let f = HandshakeFragment {
                    msg_type: frag.msg_type,
                    total_length: frag.total_length,
                    message_seq: frag.message_seq,
                    fragment_offset: frag.fragment_offset,
                    fragment: frag.fragment,
                    len: frag.len,
                };
                off += consumed;
                let reasm = self.pre_state_reasm.get_or_insert_with(|| {
                    // Catch up to whatever message_seq the client used
                    // (CH2 after a group-HRR is msg_seq=1, after a
                    // cookie-HRR is also msg_seq=1). Tight limits: this
                    // is unauthenticated pre-cookie input, so cap the
                    // claimed message size and allow only one in-flight
                    // message (see `PRE_COOKIE_MAX_CH_LEN`).
                    let mut r = Reassembler::with_limits(PRE_COOKIE_MAX_CH_LEN, 1);
                    for s in 0..msg_seq {
                        let mut buf = Vec::new();
                        write_message(&mut buf, hs_type::CLIENT_HELLO, s, b"", 0);
                        if let Ok(empty) = read_fragment(&buf) {
                            let _ = r.feed(empty);
                        }
                    }
                    r
                });
                if let Some((_mt, body)) = reasm.feed(f) {
                    self.pre_state_reasm = None;
                    if let Err(e) = self.handle_pre_state_client_hello(msg_seq, &body) {
                        // Everything on this path is unauthenticated,
                        // epoch-0, attacker-spoofable input (a forged
                        // cookie being the most reachable). Per RFC 9147
                        // §4.5.2 these faults are silently dropped so a
                        // single spoofed datagram on the 4-tuple can never
                        // tear down a legitimate in-flight handshake. The
                        // one exception is the local fail-closed
                        // misconfiguration (cookie required but no
                        // `cookie_secret`), which fires identically for
                        // the genuine client and must stay loud.
                        if matches!(e, Error::InappropriateState) {
                            return Err(e);
                        }
                        return Ok(());
                    }
                }
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
        // F3: bound the client-supplied `message_seq` before the reassembler
        // seeding loop below (`for s in 0..=msg_seq`). `message_seq` is not
        // covered by the cookie fingerprint, so even a client that completes
        // the address-ownership roundtrip can drive this loop; an oversized
        // value would otherwise mean tens of thousands of synthetic-message
        // allocate/serialize/parse/feed cycles.
        if msg_seq > MAX_HS_MSG_SEQ {
            return Err(Error::IllegalParameter);
        }
        let ch = ClientHello::decode(body)?;
        // Fail closed: a server that asks for cookie enforcement but never
        // supplied a `cookie_secret` MUST NOT silently degrade to the
        // no-cookie path (which would emit the full, expensive server flight
        // to an unverified, possibly-spoofed source — an amplification +
        // asymmetric-signature DoS). Reject before any flight is generated.
        if self.config.require_cookie && self.config.cookie_secret.is_none() {
            return Err(Error::InappropriateState);
        }
        let cookie_required = self.config.require_cookie;
        // Look for an existing cookie extension in CH.
        let presented_cookie = ch
            .extensions
            .iter()
            .find(|(t, _)| t.0 == EXT_COOKIE)
            .map(|(_, b)| b.clone());

        // Pick the cipher suite from the client's offer, in our preference
        // order. We need this both for HRR (which must carry the chosen
        // suite per RFC 8446 §4.1.4) and for committing the transcript hash.
        let suite = supported_suites()
            .iter()
            .copied()
            .find(|s| ch.cipher_suites.contains(&s.suite))
            .ok_or(Error::HandshakeFailure)?;

        // Parse offered groups + offered shares. We need them both to
        // detect "send HRR-for-group-change" and to pick a share.
        let groups_ext = ext::find(&ch.extensions, ExtensionType::SUPPORTED_GROUPS)
            .ok_or(Error::HandshakeFailure)?;
        let offered_groups = parse_supported_groups(groups_ext)?;
        let ks_ext =
            ext::find(&ch.extensions, ExtensionType::KEY_SHARE).ok_or(Error::HandshakeFailure)?;
        let client_shares = ext::parse_client_key_shares(ks_ext)?;

        // Preferred group from `supported_groups`, in this server's order
        // (RFC 8446 §4.2.7 — server picks the first mutually-acceptable
        // entry). Mirrors the TLS layer's preference at
        // `src/tls/conn/server.rs:1106-1118`.
        let preferred_group = supported_server_groups()
            .iter()
            .copied()
            .find(|g| offered_groups.contains(g));

        // Share for the preferred group, if any.
        let preferred_share =
            preferred_group.and_then(|g| client_shares.iter().find(|(sg, _)| *sg == g).cloned());

        // CH content fingerprint binds the cookie to the security-critical
        // CH fields. An attacker who grabbed a cookie issued for a
        // strong-cipher CH1 cannot replay it with a weak-cipher CH2 — the
        // cookie HMAC mismatches (DTLS-5).
        let ch_fp = ch_fingerprint_dtls13(&ch);

        if cookie_required && presented_cookie.is_none() {
            // First CH (cookie required, no cookie yet): emit HRR with a
            // freshly-minted cookie. The cookie's `aux` payload carries the
            // (suite, selected_group, Hash(CH1)) tuple we'd otherwise have
            // to pin on `self` — keeping the server fully stateless across
            // the HRR roundtrip (DTLS-2 / DTLS-4: no per-connection state
            // before cookie validates).
            //
            // Also embed a `key_share(selected_group)` if the client didn't
            // already present a share for our preferred group — RFC 8446
            // §4.1.4 forbids a second HRR, so we combine cookie + group here.
            let group_needed = if preferred_share.is_none() {
                Some(preferred_group.ok_or(Error::HandshakeFailure)?)
            } else {
                None
            };

            // Compute Hash(CH1) using the picked suite's hash, so the CH2
            // path can rebuild the `message_hash(CH1)` transcript synthetic
            // from the cookie's aux payload (RFC 8446 §4.4.1).
            let mut tls_ch1 = Vec::with_capacity(4 + body.len());
            tls_ch1.push(hs_type::CLIENT_HELLO);
            let n = body.len() as u32;
            tls_ch1.push(((n >> 16) & 0xff) as u8);
            tls_ch1.push(((n >> 8) & 0xff) as u8);
            tls_ch1.push((n & 0xff) as u8);
            tls_ch1.extend_from_slice(body);
            let h_ch1 = suite.hash.hash(&tls_ch1);

            // Aux layout:
            //   suite_id : u16 BE
            //   sel_grp  : u16 BE (0x0000 sentinel = no group HRR)
            //   hash_alg : u8 (0=Sha256, 1=Sha384)
            //   hash_ch1 : hash_alg.output_len() bytes
            let mut aux = Vec::with_capacity(5 + suite.hash.output_len());
            aux.extend_from_slice(&suite.suite.0.to_be_bytes());
            aux.extend_from_slice(&group_needed.map(|g| g.0).unwrap_or(0).to_be_bytes());
            aux.push(hash_alg_to_byte(suite.hash));
            aux.extend_from_slice(h_ch1.as_slice());

            let secret = self
                .config
                .cookie_secret
                .as_ref()
                .ok_or(Error::InappropriateState)?;
            let cg = CookieGenerator::new(*secret);
            let now_min = (self.last_now.as_secs() / 60) as u32;
            let cookie = cg.generate_with_aux(&self.peer_addr, &ch.random, &ch_fp, &aux, now_min);

            // Emit HRR using the local (suite, group_needed) — we do NOT
            // pin them on `self`. CH2 will re-enter this path with the
            // cookie, at which point we'll recover (suite, group, Hash(CH1))
            // from `aux` and bootstrap the real handshake state.
            self.emit_hrr_stateless(suite.suite, &cookie, group_needed)?;
            self.state = State::WaitSecondClientHello;
            // Deliberately DO NOT mutate: self.suite, self.hrr_selected_group,
            // self.transcript, self.out_msg_seq. The CH2 path picks them up
            // from the cookie's aux payload only after the cookie HMAC has
            // verified. msg_seq from this unauthenticated CH is also
            // ignored — the reassembler is not allocated yet (DTLS-4).
            let _ = msg_seq;
            return Ok(());
        }

        if cookie_required {
            let cookie_bytes = presented_cookie
                .as_ref()
                .ok_or(Error::IllegalParameter)?
                .clone();
            // Validate cookie before any further work — and recover the
            // suite/group/Hash(CH1) tuple the CH1 path parked in `aux`.
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
            let aux = cg
                .validate_with_aux(&self.peer_addr, &ch.random, &ch_fp, now_min, cookie)
                .ok_or(Error::IllegalParameter)?;

            // Decode the aux payload: (suite_id, sel_group, hash_alg, Hash(CH1)).
            if aux.len() < 5 {
                return Err(Error::IllegalParameter);
            }
            let parked_suite_id = CipherSuite(u16::from_be_bytes([aux[0], aux[1]]));
            let parked_sel_group_id = u16::from_be_bytes([aux[2], aux[3]]);
            let parked_hash_alg = hash_alg_from_byte(aux[4]).ok_or(Error::IllegalParameter)?;
            let parked_hash_ch1 = &aux[5..];
            if parked_hash_ch1.len() != parked_hash_alg.output_len() {
                return Err(Error::IllegalParameter);
            }
            // Look up the SuiteParams for the parked suite.
            let parked_suite = supported_suites()
                .iter()
                .copied()
                .find(|s| s.suite == parked_suite_id)
                .ok_or(Error::IllegalParameter)?;
            if parked_suite.hash != parked_hash_alg {
                return Err(Error::IllegalParameter);
            }
            // CH2 must still offer the suite we picked in HRR — the cookie
            // fingerprint check already guarantees this transitively
            // (cipher_suites are part of `ch_fp`), but check explicitly so
            // a malformed cookie payload can't confuse the suite
            // selection.
            if !ch.cipher_suites.contains(&parked_suite.suite) {
                return Err(Error::IllegalParameter);
            }
            let parked_sel_group = if parked_sel_group_id == 0 {
                None
            } else {
                Some(NamedGroup(parked_sel_group_id))
            };

            // Now bootstrap the per-connection handshake state we
            // deliberately deferred at CH1 time.
            self.suite = Some(parked_suite);
            self.hrr_selected_group = parked_sel_group;

            // Transcript: build `message_hash(CH1) || HRR` synthetically
            // from the cookie's `Hash(CH1)`. This matches what the
            // pin-then-replace flow does at CH2, but without ever buffering
            // CH1 bytes on the server. RFC 8446 §4.4.1 says the post-HRR
            // transcript starts with the 4-byte message_hash header (type
            // 254, length = hash output length) followed by Hash(CH1);
            // `Transcript::update` accepts arbitrary bytes so we feed the
            // synthetic prefix directly.
            let mut t = Transcript::new();
            t.set_alg(parked_suite.hash);
            let h_len = parked_suite.hash.output_len();
            let mut synthetic = Vec::with_capacity(4 + h_len);
            synthetic.push(254); // message_hash
            synthetic.extend_from_slice(&[0, 0]);
            synthetic.push(h_len as u8);
            synthetic.extend_from_slice(parked_hash_ch1);
            t.update(&synthetic);
            self.transcript = t;

            // The HRR consumed our msg_seq=0 — bring out_msg_seq up to 1 so
            // ServerHello goes out at msg_seq=1 below.
            self.out_msg_seq = 1;

            // Re-derive the HRR bytes (the same bytes we sent at CH1 time)
            // so we can update the transcript. We use the *explicit*
            // builder rather than the `self.suite`-reading helper to make
            // it explicit that the bytes are reconstructed from cookie aux,
            // not from `self`.
            let hrr_bytes =
                Self::build_hrr_bytes_explicit(parked_suite.suite, Some(cookie), parked_sel_group);
            self.transcript.update(&hrr_bytes);
        } else {
            // Cookie-off path: this is CH1 — but we may still need to send a
            // group-change HRR. Detect that here. If we already sent a
            // group-change HRR, this is CH2 and we expect `hrr_selected_group`
            // to be set.
            if self.hrr_selected_group.is_none() {
                // Brand-new CH: decide whether to HRR for group.
                if preferred_share.is_none() {
                    let group_needed = preferred_group.ok_or(Error::HandshakeFailure)?;
                    self.suite = Some(suite);
                    self.hrr_selected_group = Some(group_needed);
                    // Transcript: stash CH1 hash, then we'll replay via
                    // message_hash on CH2.
                    let mut t = Transcript::new();
                    t.set_alg(suite.hash);
                    let mut tls_ch = Vec::with_capacity(4 + body.len());
                    tls_ch.push(hs_type::CLIENT_HELLO);
                    let n = body.len() as u32;
                    tls_ch.push(((n >> 16) & 0xff) as u8);
                    tls_ch.push(((n >> 8) & 0xff) as u8);
                    tls_ch.push((n & 0xff) as u8);
                    tls_ch.extend_from_slice(body);
                    t.update(&tls_ch);
                    self.transcript = t;
                    self.emit_hello_retry_request(None)?;
                    self.state = State::WaitSecondClientHello;
                    self.out_msg_seq = 1;
                    let _ = msg_seq;
                    return Ok(());
                }
                // No HRR needed: pin the suite for the CH1 path below.
                self.suite = Some(suite);
            } else {
                // Cookie-off CH2 (post group-HRR). Replay the synthetic
                // message_hash + HRR into the transcript.
                self.transcript.replace_with_message_hash();
                let hrr_bytes = self.build_hrr_bytes(None, self.hrr_selected_group);
                self.transcript.update(&hrr_bytes);
            }
        }

        // Pick the actual group + share to use this round.
        let (selected_group, client_pub) = if let Some(g) = self.hrr_selected_group {
            // CH2 path: must carry exactly the share we requested.
            let share = client_shares
                .iter()
                .find(|(sg, _)| *sg == g)
                .ok_or(Error::IllegalParameter)?;
            (g, share.1.clone())
        } else {
            // No HRR: use the preferred share we found earlier.
            let (g, k) = preferred_share.ok_or(Error::HandshakeFailure)?;
            (g, k)
        };

        let suite = self.suite.ok_or(Error::InappropriateState)?;
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
        if !cookie_required && self.hrr_selected_group.is_none() {
            // Cookie-off, no-HRR path: this is CH1, transcript starts fresh
            // under the just-picked suite's hash.
            self.transcript = Transcript::new();
            self.transcript.set_alg(suite.hash);
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

        // Generate server random + ephemeral key share for the selected
        // group, derive the shared secret.
        let mut sr: Random = [0u8; 32];
        self.rng.fill_bytes(&mut sr);
        self.server_random = Some(sr);
        let (server_pub, shared) = self.key_agreement(selected_group, &client_pub)?;

        // ServerHello with the negotiated group's `key_share`.
        let sh_extensions = alloc::vec![
            ext::server_key_share(selected_group, &server_pub),
            ext::server_supported_versions(),
        ];
        let sh_bytes = ServerHello {
            random: sr,
            session_id: ch.session_id.clone(),
            cipher_suite: suite.suite,
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
        let mut ks = KeySchedule::new(suite.hash);
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
        let w_crypter = RecordCrypter::new(suite.hash, suite.aead, suite.key_len, &shts);
        let r_crypter = RecordCrypter::new(suite.hash, suite.aead, suite.key_len, &chts);
        self.write_crypter = Some(w_crypter);
        self.read_crypter = Some(r_crypter);
        let sn_len = sn_key_len_for(suite.aead);
        self.write_sn_key = Some(derive_sn_key(suite.hash, &shts, sn_len));
        self.read_sn_key = Some(derive_sn_key(suite.hash, &chts, sn_len));
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
        self.exporter_secret = Some(ems);
        self.pending_write_app_crypter = Some(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &sats,
        ));
        self.pending_read_app_crypter = Some(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &cats,
        ));
        self.write_app_sn_key = Some(derive_sn_key(suite.hash, &sats, sn_len));
        self.read_app_sn_key = Some(derive_sn_key(suite.hash, &cats, sn_len));
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
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let shts = self
            .server_hs_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let th = self.transcript.current_hash();
        let verify_data = finished_verify_data(suite.hash, shts, th.as_slice());
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
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let chts = self
            .client_hs_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let th = self.transcript.current_hash();
        let expected = finished_verify_data(suite.hash, chts, th.as_slice());
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
    /// When present, `cookie` is the raw cookie payload (no length prefix)
    /// and emits the `cookie` extension; when present, `group` emits the
    /// `key_share(selected_group)` extension (RFC 8446 §4.2.8.1). Uses the
    /// suite pinned during CH1 processing — HRR commits to a single suite
    /// (RFC 8446 §4.1.4).
    fn build_hrr_bytes(&self, cookie: Option<&[u8]>, group: Option<NamedGroup>) -> Vec<u8> {
        // HRR is only emitted after `self.suite` is pinned during CH1
        // processing; fall back to the highest-preference suite if (somehow)
        // not set — this keeps the call total without taking a Result.
        let suite_id = self
            .suite
            .map(|s| s.suite)
            .unwrap_or_else(|| supported_suites()[0].suite);
        Self::build_hrr_bytes_explicit(suite_id, cookie, group)
    }

    /// Variant of [`Self::build_hrr_bytes`] that takes the suite explicitly,
    /// without reading `self.suite`. Used by the cookie-required CH1 path,
    /// which has not yet pinned `self.suite` and instead carries the suite
    /// inside the cookie's aux payload (DTLS-2: no per-connection state
    /// pinned before cookie validates).
    fn build_hrr_bytes_explicit(
        suite_id: CipherSuite,
        cookie: Option<&[u8]>,
        group: Option<NamedGroup>,
    ) -> Vec<u8> {
        let mut extensions = alloc::vec![ext::server_supported_versions(),];
        if let Some(g) = group {
            // HRR `key_share` body is just a u16 selected_group.
            let mut body = Vec::with_capacity(2);
            put_u16(&mut body, g.0);
            extensions.push((ExtensionType::KEY_SHARE, body));
        }
        if let Some(c) = cookie {
            // `opaque cookie<1..2^16-1>` → 2-byte u16 length prefix.
            let mut v = Vec::with_capacity(2 + c.len());
            v.extend_from_slice(&(c.len() as u16).to_be_bytes());
            v.extend_from_slice(c);
            extensions.push((ExtensionType(EXT_COOKIE), v));
        }
        ServerHello {
            random: HRR_RANDOM,
            session_id: Vec::new(),
            cipher_suite: suite_id,
            extensions,
        }
        .encode()
    }

    fn emit_hello_retry_request(&mut self, cookie: Option<&[u8]>) -> Result<(), Error> {
        let bytes = self.build_hrr_bytes(cookie, self.hrr_selected_group);
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

    /// Stateless variant of [`Self::emit_hello_retry_request`] used by the
    /// cookie-required CH1 path. Builds the HRR from the explicit
    /// (`suite_id`, `group`) so we don't have to pin them on `self`
    /// pre-validation, and emits as DTLS plaintext at message_seq=0. Does
    /// not advance `self.out_msg_seq`: the next CH (CH2) will re-enter the
    /// pre-state path, at which point cookie validation succeeds and the
    /// real handshake state is bootstrapped from the cookie's aux payload.
    fn emit_hrr_stateless(
        &mut self,
        suite_id: CipherSuite,
        cookie: &[u8],
        group: Option<NamedGroup>,
    ) -> Result<(), Error> {
        let bytes = Self::build_hrr_bytes_explicit(suite_id, Some(cookie), group);
        let body = &bytes[4..];
        let mut frag_buf = Vec::new();
        write_message(
            &mut frag_buf,
            hs_type::SERVER_HELLO,
            0,
            body,
            DEFAULT_MAX_FRAGMENT,
        );
        let dgram = self.wrap_plain_record(ContentType::Handshake, &frag_buf);
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
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let crypter = self
            .write_crypter
            .as_mut()
            .ok_or(Error::InappropriateState)?;
        let sn_key = self
            .write_sn_key
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let epoch = self.enc_write_epoch;
        let seq = self.enc_write_seq;
        // Refuse to reuse an AEAD nonce: the DTLS 1.3 nonce is `IV XOR seq`, so
        // cap the per-epoch record count well below the 48-bit field (see
        // `record::MAX_RECORDS_PER_EPOCH`). Connection-fatal — no rekey path.
        record::check_seq_cap(seq)?;
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

        encrypt_dtls13_record(crypter, seq, &aad, &mut inner)?;

        let mask_full = sn_mask_for(suite, sn_key, &inner)?;
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

    /// Generates the server-side ephemeral share and derives the
    /// ECDHE/KEM shared secret for the negotiated group. Returns
    /// `(server_public_key, shared_secret_bytes)` in the wire shapes used
    /// by RFC 8446 §4.2.8 / draft-ietf-tls-ecdhe-mlkem §3.
    fn key_agreement(
        &mut self,
        group: NamedGroup,
        client_pub: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match group {
            NamedGroup::X25519 => {
                let sk = X25519PrivateKey::generate(&mut self.rng);
                let peer: [u8; 32] = client_pub.try_into().map_err(|_| Error::Decode)?;
                // RFC 7748 §6.1 / RFC 8446 §7.4.2: reject all-zero output.
                let ss = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::IllegalParameter)?;
                let pk = sk.public_key().to_vec();
                self.x25519 = Some(sk);
                Ok((pk, ss.to_vec()))
            }
            NamedGroup::SECP256R1 => {
                let sk = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut self.rng);
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, client_pub)
                    .map_err(|_| Error::Decode)?;
                let ss = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?;
                Ok((sk.public_key().to_sec1(), ss))
            }
            NamedGroup::SECP384R1 => {
                let sk = BoxedEcdhPrivateKey::generate(CurveId::P384, &mut self.rng);
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P384, client_pub)
                    .map_err(|_| Error::Decode)?;
                let ss = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?;
                Ok((sk.public_key().to_sec1(), ss))
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
                // FIPS 203 §7.2: validate the peer's encapsulation key
                // before any cryptographic operation on it.
                let validated_ek = MlKem768EncapsKey::from_bytes_validated(ek)
                    .map_err(|_| Error::IllegalParameter)?;
                let (ct, ml_ss) = validated_ek.encapsulate(&mut self.rng);
                let sk = X25519PrivateKey::generate(&mut self.rng);
                // RFC 8446 §7.4.2: reject all-zero X25519 contribution.
                let x_ss = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::IllegalParameter)?;
                // Server share: ML-KEM ciphertext ‖ X25519 key.
                let mut share = ct.to_bytes().to_vec();
                share.extend_from_slice(&sk.public_key());
                // Combined secret: ML-KEM shared secret first, then X25519.
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&ml_ss);
                combined.extend_from_slice(&x_ss);
                Ok((share, combined))
            }
            _ => Err(Error::HandshakeFailure),
        }
    }
}

/// Builds the canonical CH-content fingerprint that the cookie HMAC binds
/// to. Covers (cipher_suites, supported_groups, supported_versions,
/// key_share groups) — every CH field that drives algorithm choice. CH2
/// must reproduce these byte-for-byte, otherwise cookie validation fails
/// and the handshake aborts (DTLS-5: cookie binds CH content).
fn ch_fingerprint_dtls13(ch: &ClientHello) -> Vec<u8> {
    let mut cs_be = Vec::with_capacity(ch.cipher_suites.len() * 2);
    for cs in &ch.cipher_suites {
        cs_be.extend_from_slice(&cs.0.to_be_bytes());
    }
    let groups = ext::find(&ch.extensions, ExtensionType::SUPPORTED_GROUPS);
    let versions = ext::find(&ch.extensions, ExtensionType::SUPPORTED_VERSIONS);
    // For `key_share`, we only fingerprint the offered groups (the u16
    // NamedGroup IDs) — the ephemeral key payload legitimately changes
    // between CH1 and CH2 when the server requests a different group via
    // HRR, so it must not be in the fingerprint. The offered groups
    // themselves, however, must stay constant.
    let ks_groups = ext::find(&ch.extensions, ExtensionType::KEY_SHARE)
        .and_then(|body| ext::parse_client_key_shares(body).ok())
        .map(|shares| {
            let mut out = Vec::with_capacity(shares.len() * 2);
            for (g, _) in shares {
                out.extend_from_slice(&g.0.to_be_bytes());
            }
            out
        })
        .unwrap_or_default();
    build_ch_fingerprint(&cs_be, groups, versions, &ks_groups)
}

/// Map [`HashAlg`] to its 1-byte aux tag. Compact, fixed, and reversible
/// via [`hash_alg_from_byte`].
fn hash_alg_to_byte(h: HashAlg) -> u8 {
    match h {
        HashAlg::Sha256 => 0,
        HashAlg::Sha384 => 1,
    }
}

/// Inverse of [`hash_alg_to_byte`]. `None` indicates a malformed cookie
/// payload — caller should reject as `IllegalParameter`.
fn hash_alg_from_byte(b: u8) -> Option<HashAlg> {
    match b {
        0 => Some(HashAlg::Sha256),
        1 => Some(HashAlg::Sha384),
        _ => None,
    }
}

/// Server-side group preference order, in descending preference. Mirrors
/// the TLS layer's preference at `src/tls/conn/server.rs:1106-1118`.
fn supported_server_groups() -> [NamedGroup; 4] {
    [
        NamedGroup::X25519MLKEM768,
        NamedGroup::X25519,
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1,
    ]
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

#[cfg(test)]
mod f3_msg_seq_tests {
    //! F3 regression: the DTLS 1.3 server must reject a ClientHello whose
    //! plaintext, epoch-0 `message_seq` is implausibly large BEFORE seeding a
    //! reassembler from it. An attacker setting `message_seq = 0xFFFF` would
    //! otherwise force up to 65 535 allocate/serialize/parse/feed cycles on
    //! the unauthenticated, pre-cookie path. The rejection is a SILENT DROP
    //! (`feed_datagram` returns `Ok`): the input is trivially spoofable, so a
    //! fatal error would hand an off-path attacker a one-datagram kill switch
    //! for in-flight handshakes (RFC 9147 §4.5.2).
    use super::*;
    use crate::dtls::{DtlsClientConnection13, DtlsServerConnection13};
    use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::tls::pki::RootCertStore;
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    fn make_server_cfg() -> (ServerConfig13Internal, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"f3-dtls13-key", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let name = DistinguishedName::common_name("dtls.example");
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
            &["dtls.example"],
        )
        .unwrap();
        let der = cert.to_der().to_vec();
        (
            ServerConfig13Internal::with_ecdsa(alloc::vec![der.clone()], key).with_no_cookie(),
            der,
        )
    }

    fn make_client(server_cert: &[u8]) -> DtlsClientConnection13 {
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert.to_vec()).unwrap();
        let cfg = crate::dtls::ClientConfig13Internal::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        let mut crng = HmacDrbg::<Sha256>::new(b"f3-dtls13-client", b"nonce", &[]);
        DtlsClientConnection13::new(cfg, b"client-addr".to_vec(), &mut crng)
    }

    /// Capture a genuine first-flight ClientHello datagram from the real
    /// client. The first plaintext handshake record carries the CH.
    fn client_hello_datagram() -> Vec<u8> {
        let (_, cert) = make_server_cfg();
        let mut client = make_client(&cert);
        let mut out = client.pop_outbound_datagrams();
        out.remove(0)
    }

    fn new_server() -> DtlsServerConnection13<HmacDrbg<Sha256>> {
        let (cfg, _) = make_server_cfg();
        let srng = HmacDrbg::<Sha256>::new(b"f3-dtls13-server", b"nonce", &[]);
        DtlsServerConnection13::new(alloc::sync::Arc::new(cfg), b"client-addr".to_vec(), srng)
    }

    /// Patch the 16-bit `message_seq` of the first handshake fragment inside a
    /// plaintext DTLS record. Record header is 13 bytes; the handshake header
    /// `message_seq` field sits 4 bytes into the fragment (after msg_type[1] +
    /// length[3]).
    fn patch_message_seq(dgram: &mut [u8], seq: u16) {
        const MSG_SEQ_OFF: usize = 13 + 4;
        dgram[MSG_SEQ_OFF] = (seq >> 8) as u8;
        dgram[MSG_SEQ_OFF + 1] = seq as u8;
    }

    #[test]
    fn oversized_message_seq_is_silently_dropped_without_giant_loop() {
        let mut dgram = client_hello_datagram();
        // A legitimate first CH uses message_seq 0; force the maximum.
        patch_message_seq(&mut dgram, 0xFFFF);
        let mut server = new_server();
        // Spoofable epoch-0 input: dropped, never fatal.
        assert_eq!(server.feed_datagram(&dgram), Ok(()));
        // No server flight may have been emitted for the dropped CH.
        assert!(server.pop_outbound_datagrams().is_empty());
    }

    #[test]
    fn message_seq_just_above_cap_is_silently_dropped() {
        let mut dgram = client_hello_datagram();
        patch_message_seq(&mut dgram, MAX_HS_MSG_SEQ + 1);
        let mut server = new_server();
        assert_eq!(server.feed_datagram(&dgram), Ok(()));
        assert!(server.pop_outbound_datagrams().is_empty());
    }

    #[test]
    fn legitimate_message_seq_zero_is_accepted() {
        // Unmodified CH (message_seq = 0) must NOT trip the F3 guard; it
        // drives a normal handshake to completion.
        let (cfg, cert) = make_server_cfg();
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"f3-dtls13-ok", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(alloc::sync::Arc::new(cfg), b"client-addr".to_vec(), srng);
        for _ in 0..32 {
            let c_out = client.pop_outbound_datagrams();
            for dg in &c_out {
                server.feed_datagram(dg).unwrap();
            }
            let s_out = server.pop_outbound_datagrams();
            for dg in &s_out {
                client.feed_datagram(dg).unwrap();
            }
            if c_out.is_empty() && s_out.is_empty() {
                break;
            }
        }
        assert!(server.is_handshake_complete());
        assert!(client.is_handshake_complete());
    }
}
