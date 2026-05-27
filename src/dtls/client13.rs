#![allow(dead_code, unreachable_pub)]

//! DTLS 1.3 client state machine (RFC 9147).
//!
//! Mirrors the TLS 1.3 client handshake flow (`TLS_AES_128_GCM_SHA256`,
//! X25519 group only — focused subset for this commit), wrapped in:
//!
//! - DTLS 1.3 unified record framing (`super::record13`) for protected
//!   records, including encrypted sequence numbers (RFC 9147 §4.2.3).
//! - Plaintext DTLS records (`super::record`) for the initial flight
//!   (ClientHello / HelloRetryRequest), per RFC 9147 §4.1.
//! - DTLS handshake header (`Type ‖ Length ‖ MessageSeq ‖ FragmentOffset ‖
//!   FragmentLength`) for handshake messages.
//! - ACK-driven retransmission (`super::reliability13`) — every received
//!   protected handshake record is ACKed back; unACKed records are
//!   retransmitted on timer fire (RFC 9147 §7).
//! - Server-initiated cookie exchange via HelloRetryRequest carrying a
//!   `cookie` extension (RFC 9147 §5.1, extension type 44 per RFC 8446
//!   §4.2.2). The client echoes the cookie in a new ClientHello.
//!
//! Scope of this commit (mirroring commit 10 / DTLS 1.2):
//!
//! - One cipher suite: `TLS_AES_128_GCM_SHA256` (0x1301).
//! - One key-exchange group: X25519.
//! - Server cert: ECDSA P-256.
//! - No mTLS, no PSK, no 0-RTT, no Connection ID (RFC 9146).
//!
//! These restrictions are enforced at config time; broader suite / group
//! coverage lands in follow-up commits.

use crate::ct::ConstantTimeEq;
use crate::ec::x25519::X25519PrivateKey;
use crate::rng::RngCore;
use crate::signature_registry::SignaturePolicy;
use crate::tls::codec::extension as ext;
use crate::tls::codec::{
    CipherSuite, ClientHello, ExtensionType, NamedGroup, Random, ReadCursor, ServerHello,
    SignatureScheme, hs_type,
};
use crate::tls::crypto::{
    AeadAlg, HashAlg, KeySchedule, RecordCrypter, Secret, Transcript, certificate_verify_content,
    expand_label_dyn, finished_verify_data, verify_signature,
};
use crate::tls::keylog::KeyLog;
use crate::tls::pki::{CrlStore, RootCertStore, verify_chain_with_crls, verify_hostname};
use crate::tls::{ContentType, Error, ProtocolVersion};
use crate::x509::{AnyPublicKey, Certificate, Time};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use super::ack::{ACK_CONTENT_TYPE, RecordNumber, decode as decode_ack, encode as encode_ack};
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

/// Maximum overall record size (handshake + record header overhead) the
/// caller wants us to emit.
const DEFAULT_MAX_RECORD_SIZE: usize = 1200;

/// Configuration for a DTLS 1.3 client connection.
pub(crate) struct ClientConfig13Internal {
    /// Trust anchors for the server's certificate chain.
    pub roots: RootCertStore,
    /// Hostname to verify in the leaf certificate. `None` disables hostname
    /// checking (e.g. for tests / pinned-key flows).
    pub server_name: Option<String>,
    /// Optional ALPN preferences (highest first).
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Allowed signature algorithms (chain + CertificateVerify).
    pub signature_policy: Arc<SignaturePolicy>,
    /// Suggested ceiling on emitted record size (default 1200, comfortably
    /// below typical 1500-byte path MTUs).
    pub max_record_size: usize,
    /// When `false`, the certificate chain is not validated. Intended for
    /// pinned-key and test scenarios.
    pub verify_certificates: bool,
    /// Wall-clock used to evaluate certificate validity. `None` uses the
    /// system clock under `std`.
    pub verification_time: Option<Time>,
    /// CRLs consulted during chain validation. Empty by default.
    pub crls: CrlStore,
    /// Optional [`KeyLog`] sink (NSS `SSLKEYLOGFILE` format).
    pub key_log: Option<Arc<dyn KeyLog>>,
}

impl ClientConfig13Internal {
    /// New configuration trusting `roots`, verifying certificates against
    /// `server_name`.
    pub fn new(roots: RootCertStore, server_name: &str) -> Self {
        Self {
            roots,
            server_name: Some(String::from(server_name)),
            alpn_protocols: Vec::new(),
            signature_policy: Arc::new(SignaturePolicy::modern()),
            max_record_size: DEFAULT_MAX_RECORD_SIZE,
            verify_certificates: true,
            verification_time: None,
            crls: CrlStore::new(),
            key_log: None,
        }
    }

    /// Installs a [`CrlStore`] consulted during chain validation.
    pub fn with_crls(mut self, crls: CrlStore) -> Self {
        self.crls = crls;
        self
    }

    /// Sets the verification clock (use on `no_std` targets).
    pub fn with_verification_time(mut self, t: Time) -> Self {
        self.verification_time = Some(t);
        self
    }

    /// Disables certificate-chain verification (for tests / pinned keys).
    pub fn without_certificate_verification(mut self) -> Self {
        self.verify_certificates = false;
        self
    }

    /// Replaces the signature-algorithm policy.
    pub fn with_signature_policy(mut self, p: Arc<SignaturePolicy>) -> Self {
        self.signature_policy = p;
        self
    }
}

/// Handshake progress.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum State {
    /// Sent ClientHello, awaiting ServerHello (or HelloRetryRequest).
    WaitServerHello,
    WaitEncryptedExtensions,
    WaitCertificate,
    WaitCertificateVerify,
    WaitFinished,
    Connected,
    Closed,
}

/// A DTLS 1.3 client connection.
pub struct DtlsClientConnection13 {
    config: ClientConfig13Internal,
    /// Caller-supplied opaque peer-address bytes — not used by the client
    /// (we just echo cookies the server gives us).
    #[allow(dead_code)]
    peer_addr: Vec<u8>,

    state: State,

    /// DTLS handshake msg_seq counter for outbound messages.
    out_msg_seq: u16,
    /// Reassembler for inbound handshake messages.
    reassembler: Reassembler,

    /// Outbound UDP datagrams.
    out_dgrams: Vec<Vec<u8>>,
    /// Decrypted application data ready for the consumer.
    app_in: Vec<u8>,

    /// Write-side record state for plaintext (epoch 0) records.
    plain_write_epoch: u16,
    plain_write_seq: u64,

    /// Write epoch for protected records: 2 = handshake, 3 = application.
    /// (Epochs 0 = plaintext, 1 = early-data 0-RTT [not used here].)
    enc_write_epoch: u16,
    /// Per-direction record sequence counter for protected records.
    enc_write_seq: u64,
    /// Highest read seq seen, for sequence-number reconstruction.
    enc_read_seq: u64,
    /// RFC 9147 §4.5.1 anti-replay window for the current read epoch. Reset
    /// at every epoch transition.
    read_replay: crate::dtls::replay::AntiReplayWindow,

    /// Random + key material.
    x25519: X25519PrivateKey,
    client_random: Random,
    server_random: Option<Random>,

    /// HRR-cookie storage: when present, the next CH echoes this extension
    /// verbatim (extension type 44).
    cookie_extension: Option<Vec<u8>>,
    /// Set true after one HRR has been processed; a second is rejected.
    hrr_processed: bool,

    /// Transcript hash carried through the handshake.
    transcript: Transcript,
    /// `KeySchedule` carried through Early → Handshake → Master.
    ks: Option<KeySchedule>,
    /// Cached secrets for record-layer keying.
    client_hs_secret: Option<Secret>,
    server_hs_secret: Option<Secret>,
    client_app_secret: Option<Secret>,
    server_app_secret: Option<Secret>,

    /// Active write-side RecordCrypter (post-handshake-keys).
    write_crypter: Option<RecordCrypter>,
    /// Active read-side RecordCrypter.
    read_crypter: Option<RecordCrypter>,
    /// Sequence-number protection key for outgoing records (16-byte AES key
    /// derived from the same traffic secret).
    write_sn_key: Option<[u8; 16]>,
    /// Sequence-number protection key for incoming records.
    read_sn_key: Option<[u8; 16]>,
    /// Application read-side `sn_key`, ready to swap in at our Finished.
    read_app_sn_key: Option<[u8; 16]>,
    /// Application write-side `sn_key`, ready to swap in at our Finished.
    write_app_sn_key: Option<[u8; 16]>,
    /// Application-secret read crypter, parked until our Finished.
    pending_read_app_crypter: Option<RecordCrypter>,
    /// Application-secret write crypter, parked until our Finished.
    pending_write_app_crypter: Option<RecordCrypter>,

    /// Peer cert chain (leaf first).
    cert_chain: Vec<Vec<u8>>,
    /// Peer leaf public key (recovered or verified).
    leaf_key: Option<AnyPublicKey>,
    /// Negotiated ALPN protocol from EncryptedExtensions.
    alpn_negotiated: Option<Vec<u8>>,

    /// Pending ACKs to emit: (epoch, seq) of records we received that need
    /// acknowledgement.
    pending_acks: Vec<RecordNumber>,
    /// ACK-driven retransmit state machine.
    retransmit: Retransmit13,
    /// Current logical time.
    last_now: Duration,
}

impl DtlsClientConnection13 {
    /// Creates a fresh client and emits the first ClientHello. The RNG
    /// supplies the ephemeral X25519 key and client random.
    pub(crate) fn new<R: RngCore>(
        config: ClientConfig13Internal,
        peer_addr: Vec<u8>,
        rng: &mut R,
    ) -> Self {
        let x25519 = X25519PrivateKey::generate(rng);
        let mut client_random: Random = [0u8; 32];
        rng.fill_bytes(&mut client_random);

        let mut conn = Self {
            config,
            peer_addr,
            state: State::WaitServerHello,
            out_msg_seq: 0,
            reassembler: Reassembler::new(),
            out_dgrams: Vec::new(),
            app_in: Vec::new(),
            plain_write_epoch: 0,
            plain_write_seq: 0,
            enc_write_epoch: 0,
            enc_write_seq: 0,
            enc_read_seq: 0,
            read_replay: crate::dtls::replay::AntiReplayWindow::new(),
            x25519,
            client_random,
            server_random: None,
            cookie_extension: None,
            hrr_processed: false,
            transcript: Transcript::new(),
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
            cert_chain: Vec::new(),
            leaf_key: None,
            alpn_negotiated: None,
            pending_acks: Vec::new(),
            retransmit: Retransmit13::new(),
            last_now: Duration::from_secs(0),
        };
        // Transcript hash is SHA-256 (fixed by the only suite we offer).
        conn.transcript.set_alg(HashAlg::Sha256);
        let dgram = conn.build_client_hello();
        conn.emit_plaintext(dgram);
        conn
    }

    /// Returns true once the handshake completes.
    pub fn is_handshake_complete(&self) -> bool {
        self.state == State::Connected
    }

    /// Drains pending UDP datagrams to send. Also drains any pending ACKs
    /// into a final ACK record.
    pub fn pop_outbound_datagrams(&mut self) -> Vec<Vec<u8>> {
        self.flush_pending_acks();
        core::mem::take(&mut self.out_dgrams)
    }

    /// Drains decrypted application data.
    pub fn take_received(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app_in)
    }

    /// The peer's certificate chain in wire order (DER), leaf first.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.cert_chain
    }

    /// The negotiated ALPN protocol, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_negotiated.as_deref()
    }

    /// Queues application plaintext for transmission. The handshake must
    /// already be complete.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::InappropriateState);
        }
        let dg = self.encrypt_protected_record(ContentType::ApplicationData, plaintext)?;
        self.out_dgrams.push(dg);
        Ok(())
    }

    /// Returns the next absolute monotonic time at which the caller should
    /// invoke `on_timeout`. None when no retransmit is armed.
    pub fn next_timeout(&self) -> Option<Duration> {
        self.retransmit.next_timeout()
    }

    /// Drives the retransmit machine. Any retransmitted datagrams land in
    /// `pop_outbound_datagrams`.
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

    /// Feeds an incoming UDP datagram.
    pub fn feed_datagram(&mut self, datagram: &[u8]) -> Result<(), Error> {
        // A datagram may carry multiple records back-to-back. Plaintext
        // records use the legacy 13-byte DTLS 1.2 header; protected records
        // use the DTLS 1.3 unified header (first byte's top 3 bits = 001).
        let mut off = 0usize;
        while off < datagram.len() {
            // Sniff first byte: a value of 20 (CCS), 21 (alert), 22 (handshake),
            // 23 (application_data), or 26 (ack) is the legacy plaintext path.
            // Anything in 0x20..=0x3F is the unified header.
            let first = datagram[off];
            if first < 32 {
                // Legacy plaintext record.
                let Some(rec) = record::read_record(&datagram[off..])? else {
                    return Ok(());
                };
                off += rec.len;
                self.process_plaintext_record(rec)?;
            } else if (first & 0b1110_0000) == 0b0010_0000 {
                // Unified-header (protected) record.
                let consumed = self.process_protected_record(&datagram[off..])?;
                if consumed == 0 {
                    return Ok(());
                }
                off += consumed;
            } else {
                // Unknown — drop the rest of the datagram silently.
                return Ok(());
            }
        }
        Ok(())
    }

    /// Processes one legacy-framed plaintext record (epoch 0).
    fn process_plaintext_record(&mut self, rec: ParsedDtlsRecord<'_>) -> Result<(), Error> {
        if rec.version != ProtocolVersion::DTLSv1_2 && rec.version != ProtocolVersion::DTLSv1_0 {
            return Err(Error::UnsupportedVersion);
        }
        if rec.epoch != 0 {
            // Plaintext records can only live in epoch 0.
            return Ok(());
        }
        match rec.content_type {
            ContentType::Handshake => self.process_handshake_record(rec.fragment),
            ContentType::Alert => Ok(()),
            ContentType::ChangeCipherSpec => Ok(()), // Middlebox compat: ignore.
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Processes one unified-header protected record, returning the number
    /// of bytes consumed from `buf` (0 = couldn't parse, drop datagram).
    fn process_protected_record(&mut self, buf: &[u8]) -> Result<usize, Error> {
        // First, peek the header layout (without unmasking the seq).
        let (hdr_len, body_len) = peek_header_layout(buf)?;
        let total = hdr_len + body_len;
        if total > buf.len() {
            return Ok(0);
        }
        let body = &buf[hdr_len..total];
        if body.len() < 16 {
            // Smaller than the AEAD tag alone — bogus.
            return Err(Error::Decode);
        }

        // Compute the sn_mask from the read sn_key.
        let sn_key = self.read_sn_key.ok_or(Error::UnexpectedMessage)?;
        let mask_full = sn_mask_aes128(&sn_key, body);
        let mask: &[u8] = if (buf[0] & 0b0000_1000) != 0 {
            &mask_full[..2]
        } else {
            &mask_full[..1]
        };

        let (hdr, ct_body) = record13::decode_record(buf, mask)?;
        let consumed = hdr.header_len + ct_body.len();

        // Reconstruct full 48-bit seq and full epoch. Our epoch is whichever
        // matches the low 2 bits. For this subset we know which read epoch
        // is active (2 or 3); pick that one if its low 2 bits match.
        let read_epoch = self.current_read_epoch();
        if (read_epoch as u8 & 0b11) != hdr.epoch_low2 {
            // Wrong epoch — drop silently.
            return Ok(consumed);
        }
        let seq = reconstruct_seq(
            hdr.seq_low,
            hdr.seq_is_16bit,
            self.enc_read_seq.wrapping_add(1),
        );

        // RFC 9147 §4.2.3: AAD is the unified header bytes prior to
        // sequence-number masking. Reconstruct by XOR'ing the wire seq
        // bytes with the mask back to the un-masked form.
        let mut aad = buf[..hdr.header_len].to_vec();
        if hdr.seq_is_16bit {
            aad[1] ^= mask[0];
            aad[2] ^= mask[1];
        } else {
            aad[1] ^= mask[0];
        }
        let crypter = self.read_crypter.as_mut().ok_or(Error::UnexpectedMessage)?;
        let (inner_type, plain) = decrypt_dtls13_record(crypter, seq, &aad, ct_body)?;

        // RFC 9147 §4.5.1: anti-replay window — drop duplicates and stale
        // sequence numbers even though the AEAD already verified them.
        if !self.read_replay.accept(seq) {
            return Ok(consumed);
        }
        if seq > self.enc_read_seq {
            self.enc_read_seq = seq;
        }
        // Schedule an ACK for this protected record (handshake-only; we
        // skip ACKing application_data per RFC 9147 §7 to reduce noise).
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
            ContentType::Alert => {
                // Ignore alerts in this subset.
            }
            ContentType::Unknown(t) if t == ACK_CONTENT_TYPE => {
                let acks = decode_ack(&plain)?;
                self.retransmit.on_ack(&acks);
            }
            _ => return Err(Error::UnexpectedMessage),
        }
        Ok(consumed)
    }

    /// The current protected-read epoch we expect (2 during handshake, 3
    /// once we receive the server Finished). We track a single value
    /// because the subset doesn't use KeyUpdate.
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
            let frag = HandshakeFragment {
                msg_type: frag.msg_type,
                total_length: frag.total_length,
                message_seq: frag.message_seq,
                fragment_offset: frag.fragment_offset,
                fragment: frag.fragment,
                len: frag.len,
            };
            off += consumed;
            if let Some((mt, body)) = self.reassembler.feed(frag) {
                self.dispatch_one(mt, &body)?;
            }
            while let Some((mt, body)) = self.reassembler.pop_ready() {
                self.dispatch_one(mt, &body)?;
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
            State::WaitServerHello => self.on_server_hello(msg_type, body, &raw),
            State::WaitEncryptedExtensions => self.on_encrypted_extensions(msg_type, &raw),
            State::WaitCertificate => self.on_certificate(msg_type, body, &raw),
            State::WaitCertificateVerify => self.on_certificate_verify(msg_type, body, &raw),
            State::WaitFinished => self.on_finished(msg_type, body, &raw),
            State::Connected | State::Closed => Err(Error::UnexpectedMessage),
        }
    }

    fn on_server_hello(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::SERVER_HELLO {
            return Err(Error::UnexpectedMessage);
        }
        let sh = ServerHello::decode(body)?;
        if sh.random == HRR_RANDOM {
            return self.on_hello_retry_request(sh, raw);
        }
        // The single suite we offer.
        if sh.cipher_suite != CipherSuite::AES_128_GCM_SHA256 {
            return Err(Error::HandshakeFailure);
        }
        // Confirm supported_versions = TLS 1.3.
        let sv = ext::find(&sh.extensions, ExtensionType::SUPPORTED_VERSIONS)
            .ok_or(Error::UnsupportedVersion)?;
        if ext::parse_selected_version(sv)? != ProtocolVersion::TLSv1_3 {
            return Err(Error::UnsupportedVersion);
        }
        self.server_random = Some(sh.random);

        // ECDHE from the server's key share.
        let ks_ext =
            ext::find(&sh.extensions, ExtensionType::KEY_SHARE).ok_or(Error::HandshakeFailure)?;
        let (group, server_pub) = ext::parse_server_key_share(ks_ext)?;
        if group != NamedGroup::X25519 {
            return Err(Error::HandshakeFailure);
        }
        let peer: [u8; 32] = server_pub
            .as_slice()
            .try_into()
            .map_err(|_| Error::Decode)?;
        // RFC 7748 §6.1 / RFC 8446 §7.4.2: reject the all-zero DH output.
        let shared = self
            .x25519
            .diffie_hellman(&peer)
            .map_err(|_| Error::IllegalParameter)?;

        // Update the transcript with SH.
        self.transcript.update(raw);

        // Derive handshake traffic secrets.
        let mut ks = KeySchedule::new(HashAlg::Sha256);
        ks.enter_handshake(&shared);
        let th = self.transcript.current_hash();
        let chts = ks.client_handshake_traffic_secret(th.as_slice());
        let shts = ks.server_handshake_traffic_secret(th.as_slice());

        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                &self.client_random,
                chts.as_slice(),
            );
            kl.log(
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                &self.client_random,
                shts.as_slice(),
            );
        }

        // Install protected crypters (epoch 2 for handshake).
        let w_crypter = RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &chts);
        let r_crypter = RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &shts);
        self.write_crypter = Some(w_crypter);
        self.read_crypter = Some(r_crypter);
        self.write_sn_key = Some(derive_sn_key(HashAlg::Sha256, &chts));
        self.read_sn_key = Some(derive_sn_key(HashAlg::Sha256, &shts));
        self.enc_write_epoch = 2;
        self.enc_write_seq = 0;
        self.enc_read_seq = 0;
        self.read_replay = crate::dtls::replay::AntiReplayWindow::new();

        self.ks = Some(ks);
        self.client_hs_secret = Some(chts);
        self.server_hs_secret = Some(shts);
        self.state = State::WaitEncryptedExtensions;
        Ok(())
    }

    fn on_hello_retry_request(&mut self, hrr: ServerHello, raw: &[u8]) -> Result<(), Error> {
        if self.hrr_processed {
            return Err(Error::UnexpectedMessage);
        }
        if hrr.cipher_suite != CipherSuite::AES_128_GCM_SHA256 {
            return Err(Error::IllegalParameter);
        }
        let sv = ext::find(&hrr.extensions, ExtensionType::SUPPORTED_VERSIONS)
            .ok_or(Error::UnsupportedVersion)?;
        if ext::parse_selected_version(sv)? != ProtocolVersion::TLSv1_3 {
            return Err(Error::UnsupportedVersion);
        }
        // Pull the cookie extension (must be present per RFC 9147 §5.1
        // for the cookie path we implement).
        let cookie_body = hrr
            .extensions
            .iter()
            .find(|(t, _)| t.0 == EXT_COOKIE)
            .ok_or(Error::IllegalParameter)?
            .1
            .clone();
        self.cookie_extension = Some(cookie_body);

        // Rewrite the transcript per RFC 8446 §4.4.1 (synthetic message_hash).
        self.transcript.set_alg(HashAlg::Sha256);
        self.transcript.replace_with_message_hash();
        self.transcript.update(raw);

        self.hrr_processed = true;
        // Re-arm the retransmit cycle for the new flight (drop any leftover
        // in-flight state from the prior CH).
        self.retransmit = Retransmit13::new();

        // Build and send CH2 (with cookie extension).
        let dgram = self.build_client_hello();
        self.emit_plaintext(dgram);
        Ok(())
    }

    fn on_encrypted_extensions(&mut self, msg_type: u8, raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::ENCRYPTED_EXTENSIONS {
            return Err(Error::UnexpectedMessage);
        }
        // Parse for ALPN; ignore the rest.
        if raw.len() >= 4 {
            let body = &raw[4..];
            let mut c = ReadCursor::new(body);
            let exts_bytes = c.vec_u16()?;
            let mut ec = ReadCursor::new(exts_bytes);
            while !ec.is_empty() {
                let ty = ec.u16()?;
                let ext_body = ec.vec_u16()?;
                if ty == ExtensionType::ALPN.0 {
                    let names = ext::parse_alpn(ext_body)?;
                    if names.len() != 1 {
                        return Err(Error::IllegalParameter);
                    }
                    if !self.config.alpn_protocols.iter().any(|p| p == &names[0]) {
                        return Err(Error::IllegalParameter);
                    }
                    self.alpn_negotiated = Some(names.into_iter().next().unwrap());
                }
            }
        }
        self.transcript.update(raw);
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
        self.transcript.update(raw);
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

        let leaf =
            Certificate::from_der(self.cert_chain[0].clone()).map_err(|_| Error::BadCertificate)?;
        leaf.check_well_formed()
            .map_err(|_| Error::BadCertificate)?;
        let leaf_key = if self.config.verify_certificates {
            let now = self.config.verification_time.clone();
            let key = verify_chain_with_crls(
                &self.config.roots,
                &self.config.crls,
                &self.cert_chain,
                now.as_ref(),
                &self.config.signature_policy,
            )?;
            if let Some(name) = self.config.server_name.as_deref() {
                verify_hostname(&leaf, name)?;
            }
            key
        } else {
            leaf.subject_public_key()
                .map_err(|_| Error::BadCertificate)?
        };

        let th = self.transcript.current_hash();
        let content = certificate_verify_content(true, th.as_slice());
        verify_signature(
            scheme,
            &leaf_key,
            &content,
            &signature,
            &self.config.signature_policy,
        )?;
        self.leaf_key = Some(leaf_key);
        self.transcript.update(raw);
        self.state = State::WaitFinished;
        Ok(())
    }

    fn on_finished(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::FINISHED {
            return Err(Error::UnexpectedMessage);
        }
        let shts = self
            .server_hs_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let th = self.transcript.current_hash();
        let expected = finished_verify_data(HashAlg::Sha256, shts, th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.transcript.update(raw);

        // Derive application traffic secrets.
        let (cats, sats, ems) = {
            let ks = self.ks.as_mut().ok_or(Error::InappropriateState)?;
            ks.enter_master();
            let th_app = self.transcript.current_hash();
            let cats = ks.client_application_traffic_secret(th_app.as_slice());
            let sats = ks.server_application_traffic_secret(th_app.as_slice());
            let ems = ks.exporter_master_secret(th_app.as_slice());
            (cats, sats, ems)
        };
        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log(
                "CLIENT_TRAFFIC_SECRET_0",
                &self.client_random,
                cats.as_slice(),
            );
            kl.log(
                "SERVER_TRAFFIC_SECRET_0",
                &self.client_random,
                sats.as_slice(),
            );
            kl.log("EXPORTER_SECRET", &self.client_random, ems.as_slice());
        }
        let _ = ems;
        // Stash the app keys; they're installed atomically below.
        self.pending_write_app_crypter = Some(RecordCrypter::new(
            HashAlg::Sha256,
            AeadAlg::Aes128Gcm,
            16,
            &cats,
        ));
        self.pending_read_app_crypter = Some(RecordCrypter::new(
            HashAlg::Sha256,
            AeadAlg::Aes128Gcm,
            16,
            &sats,
        ));
        self.write_app_sn_key = Some(derive_sn_key(HashAlg::Sha256, &cats));
        self.read_app_sn_key = Some(derive_sn_key(HashAlg::Sha256, &sats));
        self.client_app_secret = Some(cats);
        self.server_app_secret = Some(sats);

        // Emit our Finished under the handshake-write key.
        let chts = self
            .client_hs_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let th_for_cfin = self.transcript.current_hash();
        let verify_data = finished_verify_data(HashAlg::Sha256, chts, th_for_cfin.as_slice());
        let fin_body = verify_data.as_slice().to_vec();
        // Update transcript with Finished.
        let mut fin_tls = Vec::with_capacity(4 + fin_body.len());
        fin_tls.push(hs_type::FINISHED);
        let n = fin_body.len() as u32;
        fin_tls.push(((n >> 16) & 0xff) as u8);
        fin_tls.push(((n >> 8) & 0xff) as u8);
        fin_tls.push((n & 0xff) as u8);
        fin_tls.extend_from_slice(&fin_body);
        self.transcript.update(&fin_tls);

        let fin_msg_seq = self.out_msg_seq;
        self.out_msg_seq += 1;
        let mut frag_buf = Vec::new();
        write_message(
            &mut frag_buf,
            hs_type::FINISHED,
            fin_msg_seq,
            &fin_body,
            DEFAULT_MAX_FRAGMENT,
        );
        let fin_dgram = self.encrypt_protected_record(ContentType::Handshake, &frag_buf)?;
        self.emit_protected(fin_dgram, true);

        // Swap in application keys.
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

    /// Builds the current ClientHello as a DTLS plaintext record. If
    /// `self.cookie_extension` is set, the CH includes a `cookie` extension.
    fn build_client_hello(&mut self) -> Vec<u8> {
        let groups = alloc::vec![NamedGroup::X25519];
        let key_shares = alloc::vec![(NamedGroup::X25519, self.x25519.public_key().to_vec())];

        let mut extensions = alloc::vec![ext::supported_groups_list(&groups),];
        if let Some(name) = self.config.server_name.as_deref() {
            extensions.insert(0, ext::server_name(name));
        }
        extensions.push(ext::signature_algorithms());
        // Use DTLS 1.3 supported_versions (we still emit just TLS 1.3 here;
        // peers also implementing DTLS 1.3 read the version from the record
        // header / the wire-format alignment with TLS 1.3 is intentional).
        extensions.push(ext::client_supported_versions());
        extensions.push(ext::client_key_shares(&key_shares));
        if !self.config.alpn_protocols.is_empty() {
            let protos: Vec<&[u8]> = self
                .config
                .alpn_protocols
                .iter()
                .map(|v| v.as_slice())
                .collect();
            extensions.push(ext::alpn_protocols(&protos));
        }
        if let Some(cookie) = self.cookie_extension.as_ref() {
            extensions.push((ExtensionType(EXT_COOKIE), cookie.clone()));
        }

        let ch = ClientHello {
            legacy_version: 0x0303,
            random: self.client_random,
            session_id: Vec::new(),
            cipher_suites: alloc::vec![CipherSuite::AES_128_GCM_SHA256],
            extensions,
        }
        .encode();

        // Transcript: include the entire TLS-shaped CH (4-byte header + body).
        self.transcript.update(&ch);

        // Wrap as a DTLS handshake fragment.
        let ch_body = &ch[4..];
        let msg_seq = self.out_msg_seq;
        self.out_msg_seq += 1;
        let mut frag_buf = Vec::new();
        write_message(
            &mut frag_buf,
            hs_type::CLIENT_HELLO,
            msg_seq,
            ch_body,
            DEFAULT_MAX_FRAGMENT,
        );
        self.wrap_plain_record(ContentType::Handshake, &frag_buf)
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

    /// Encrypts and frames a protected DTLS 1.3 record. The returned
    /// `Vec<u8>` is a single record's worth of bytes (header + body), ready
    /// for the wire.
    fn encrypt_protected_record(
        &mut self,
        ct: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // RFC 9147 §4.2.3: the additional data is the unified-header bytes
        // PRIOR to sequence-number masking. Build the header, compute the
        // AEAD with that AAD, then compute and apply the sn_mask.
        let crypter = self
            .write_crypter
            .as_mut()
            .ok_or(Error::InappropriateState)?;
        let sn_key = self.write_sn_key.ok_or(Error::InappropriateState)?;
        let epoch = self.enc_write_epoch;
        let seq = self.enc_write_seq;
        self.enc_write_seq += 1;
        // Always emit 16-bit seq + explicit length (the simpler subset).
        let seq_is_16bit = true;
        let omit_length = false;

        // Inner = payload || true_content_type (TLS 1.3 InnerPlaintext,
        // no extra padding).
        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.extend_from_slice(payload);
        inner.push(ct.as_u8());

        // AAD bytes: encode the header against a placeholder ciphertext
        // of the known final size, then truncate to the header length.
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

        // Compute sn_mask over the first 16 bytes of ciphertext+tag and
        // emit the on-wire record with the masked seq.
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

    /// Pushes a freshly-built plaintext datagram to the outbound queue and
    /// registers it with the retransmit machine at the current epoch's
    /// `(epoch, seq)` (we use seq-1 because we just bumped).
    fn emit_plaintext(&mut self, datagram: Vec<u8>) {
        let seq = self.plain_write_seq.saturating_sub(1);
        let record_number = RecordNumber {
            epoch: self.plain_write_epoch as u64,
            seq,
        };
        // Push to output and to in-flight set.
        self.out_dgrams.push(datagram.clone());
        self.retransmit.on_record_sent(
            InFlightRecord {
                record_number,
                datagram,
            },
            self.last_now,
        );
    }

    /// Pushes a freshly-built protected datagram. If `track` is true, the
    /// record is registered with the retransmit machine (handshake records).
    /// Application records do not get retransmitted.
    fn emit_protected(&mut self, datagram: Vec<u8>, track: bool) {
        if track {
            let seq = self.enc_write_seq.saturating_sub(1);
            let record_number = RecordNumber {
                epoch: self.enc_write_epoch as u64,
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
        } else {
            self.out_dgrams.push(datagram);
        }
    }

    /// Emits all queued ACKs as a single ACK record under the current
    /// protected write key. No-op if there are no pending ACKs or we
    /// haven't yet installed the protected write key.
    fn flush_pending_acks(&mut self) {
        if self.pending_acks.is_empty() {
            return;
        }
        if self.write_crypter.is_none() {
            // No keys yet — keep them around for later.
            return;
        }
        let acks = core::mem::take(&mut self.pending_acks);
        let body = encode_ack(&acks);
        // ACK uses its own content type (26).
        if let Ok(dg) = self.encrypt_protected_record(ContentType::Unknown(ACK_CONTENT_TYPE), &body)
        {
            // ACK records are NOT retransmitted (RFC 9147 §7: only handshake
            // and application records get tracked).
            self.out_dgrams.push(dg);
        }
    }
}

/// Parses a TLS 1.3 Certificate body (with the 1-byte
/// `certificate_request_context` prefix). Returns the leaf-first chain of
/// DER blobs.
fn parse_certificate_list(body: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut c = ReadCursor::new(body);
    let _ctx = c.vec_u8()?;
    let list = c.vec_u24()?;
    c.expect_empty()?;
    let mut entries = ReadCursor::new(list);
    let mut certs = Vec::new();
    while !entries.is_empty() {
        let cert = entries.vec_u24()?.to_vec();
        if cert.is_empty() {
            return Err(Error::BadCertificate);
        }
        // Per-cert extensions: skip.
        let _exts = entries.vec_u16()?;
        certs.push(cert);
    }
    Ok(certs)
}

/// Derives a 16-byte DTLS 1.3 sequence-number protection key from a TLS 1.3
/// traffic secret (RFC 9147 §4.2.3, `sn = HKDF-Expand-Label(secret, "sn",
/// "", key_length)`).
pub(crate) fn derive_sn_key(hash: HashAlg, secret: &Secret) -> [u8; 16] {
    let mut out = [0u8; 16];
    expand_label_dyn(hash, secret.as_slice(), b"sn", &[], &mut out);
    out
}

/// Encrypts `inner` in-place under `crypter` with the DTLS-style AAD.
///
/// This bypasses `RecordCrypter::encrypt` because we need the AAD to be the
/// caller-supplied unified-header bytes (not the TLS-1.3 5-byte header
/// the standard wrapper produces). `seq` alone forms the nonce
/// (static IV XOR 64-bit big-endian seq, per RFC 9147 §4.2.2); the epoch
/// is implicit in `crypter`, which is keyed per-epoch.
pub(crate) fn encrypt_dtls13_record(
    crypter: &mut RecordCrypter,
    seq: u64,
    aad: &[u8],
    inner: &mut Vec<u8>,
) -> Result<(), Error> {
    let tag = crypter.encrypt_raw(seq, aad, inner)?;
    inner.extend_from_slice(&tag);
    Ok(())
}

/// Decrypts one DTLS 1.3 protected record.
pub(crate) fn decrypt_dtls13_record(
    crypter: &mut RecordCrypter,
    seq: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<(ContentType, Vec<u8>), Error> {
    if ciphertext.len() < 16 {
        return Err(Error::Decode);
    }
    let (ct, tag_bytes) = ciphertext.split_at(ciphertext.len() - 16);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(tag_bytes);
    let mut buf = ct.to_vec();
    crypter.decrypt_raw(seq, aad, &mut buf, &tag)?;
    // TLSInnerPlaintext: content || true_type || zeros*.
    let end = match buf.iter().rposition(|&b| b != 0) {
        Some(p) => p,
        None => return Err(Error::PeerMisbehaved),
    };
    let true_type = buf[end];
    buf.truncate(end);
    let ct = ContentType::from_u8(true_type);
    Ok((ct, buf))
}
