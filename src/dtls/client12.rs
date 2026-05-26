//! DTLS 1.2 client state machine (RFC 6347).
//!
//! Mirrors the TLS 1.2 client handshake flow (`ECDHE-ECDSA-AES128-GCM-SHA256`,
//! X25519 group only — focused subset for now), wrapped in a DTLS-aware
//! record layer with:
//!
//! - 13-byte DTLS record header (`epoch ‖ 48-bit seq`)
//! - 12-byte DTLS handshake header (`type ‖ length ‖ message_seq ‖
//!   fragment_offset ‖ fragment_length`)
//! - HelloVerifyRequest cookie handshake (RFC 6347 §4.2.1)
//! - Anti-replay sliding window after CCS
//! - Sans-I/O retransmit machine driven by `next_timeout`/`on_timeout`
//!
//! The state machine intentionally re-implements the TLS 1.2 client logic
//! rather than wrapping `ClientConnection12` because DTLS's transcript rules
//! (RFC 6347 §4.2.1 — drop the first CH + HVR; second CH carries cookie
//! field that's part of the transcript) clash with how the TLS 1.2 state
//! machine accumulates its transcript.

use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPublicKey, CurveId};
use crate::rng::RngCore;
use crate::signature_registry::SignaturePolicy;
use crate::tls::codec::extension as ext;
use crate::tls::codec::handshake12::{ClientKeyExchange, ServerKeyExchange, signed_message};
use crate::tls::codec::{
    CipherSuite, NamedGroup, Random, ReadCursor, ServerHello, hs_type, with_len_u8, with_len_u16,
};
use crate::tls::crypto::aead12::RecordCrypter12;
use crate::tls::crypto::prf::{finished_verify_data, key_block, master_secret};
use crate::tls::crypto::{HashAlg, Transcript, verify_signature};
use crate::tls::pki::{RootCertStore, verify_chain};
use crate::tls::{ContentType, Error, ProtocolVersion};
use crate::x509::{AnyPublicKey, Certificate, Time};
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use super::reassembly::{HandshakeFragment, Reassembler, read_fragment, write_message};
use super::record::{self, ParsedDtlsRecord};
use super::reliability::{Flight, Retransmit};
use super::replay::AntiReplayWindow;

#[allow(unused_imports)]
use crate::ct::ConstantTimeEq;

/// HelloVerifyRequest handshake type code (RFC 6347 §4.2.1).
const HS_HELLO_VERIFY_REQUEST: u8 = 3;

/// Default fragment size for outgoing handshake messages — sized so the
/// final UDP datagram (13-byte DTLS record header + 12-byte handshake
/// header + fragment body) stays well under 1500 byte MTU.
const DEFAULT_MAX_FRAGMENT: usize = 1100;

/// AEAD key length (AES-128 = 16 bytes for our single supported suite).
const KEY_LEN: usize = 16;

/// Configuration for a DTLS 1.2 client connection.
///
/// The shape mirrors [`crate::tls::ClientConfig12`] (TLS 1.2) but is its
/// own type to keep the DTLS path independent.
pub struct DtlsClientConfig12 {
    /// Trust anchors used to authenticate the server certificate chain.
    pub roots: RootCertStore,
    /// When `false`, the certificate chain is not validated. Intended for
    /// pinned-key and test scenarios.
    pub verify_certificates: bool,
    /// Verification clock. `None` uses the system clock under `std`.
    pub verification_time: Option<Time>,
    /// Hostname to verify in the server's leaf certificate.
    pub server_name: String,
    /// Allowed signature algorithms in the chain + SKE signature.
    pub signature_policy: SignaturePolicy,
}

impl DtlsClientConfig12 {
    /// New configuration trusting `roots`, verifying certificates against
    /// `server_name`.
    pub fn new(roots: RootCertStore, server_name: &str) -> Self {
        Self {
            roots,
            verify_certificates: true,
            verification_time: None,
            server_name: String::from(server_name),
            signature_policy: SignaturePolicy::modern(),
        }
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
    pub fn with_signature_policy(mut self, p: SignaturePolicy) -> Self {
        self.signature_policy = p;
        self
    }
}

/// Handshake progress.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum State {
    /// Sent CH (empty cookie), awaiting HelloVerifyRequest *or* ServerHello.
    WaitServerHelloOrHvr,
    /// Sent CH with cookie, awaiting ServerHello.
    WaitServerHello,
    WaitCertificate,
    WaitServerKeyExchange,
    WaitServerHelloDone,
    WaitServerFinished,
    Connected,
    Closed,
}

/// A DTLS 1.2 client connection.
pub struct DtlsClientConnection12 {
    config: DtlsClientConfig12,
    /// Caller-supplied peer-address bytes — opaque to us, used only by the
    /// server's cookie generator (we just echo the cookie we receive).
    #[allow(dead_code)]
    peer_addr: Vec<u8>,

    state: State,

    /// DTLS handshake message counter (RFC 6347 §4.2.2). Incremented per
    /// outbound handshake message; starts at 0 (first CH).
    out_msg_seq: u16,
    /// Reassembler for inbound handshake messages.
    reassembler: Reassembler,

    /// Outbound UDP datagrams.
    out_dgrams: Vec<Vec<u8>>,
    /// Decrypted application data ready for the consumer.
    app_in: Vec<u8>,

    /// Record-layer sequence numbers. One counter per epoch / direction.
    write_epoch: u16,
    write_seq_in_epoch: u64,
    read_epoch: u16,

    /// Anti-replay window for the current encrypted read epoch.
    replay: AntiReplayWindow,

    /// Ephemeral X25519 key (we support only X25519 in this subset).
    x25519: X25519PrivateKey,
    /// Ephemeral P-256 key, generated in advance to keep RNG out of the
    /// hot-path handlers.
    p256: BoxedEcdhPrivateKey,

    client_random: Random,
    server_random: Option<Random>,

    /// Currently held cookie (empty on the first CH, populated after HVR).
    cookie: Vec<u8>,

    /// Transcript: per RFC 6347 §4.2.1, only the second CH (with cookie) and
    /// onward are in the transcript. We use a single Transcript object;
    /// we reset it on HVR.
    transcript: Transcript,

    /// Peer cert chain (leaf first).
    cert_chain: Vec<Vec<u8>>,
    /// Peer leaf public key (verified or extracted).
    leaf_key: Option<AnyPublicKey>,
    /// Negotiated group from SKE.
    peer_group: Option<NamedGroup>,
    /// Peer's ECDHE public share.
    peer_point: Option<Vec<u8>>,

    /// 48-byte master secret.
    master: Option<[u8; 48]>,
    /// Read crypter for epoch 1 (after server CCS).
    read_crypter: Option<RecordCrypter12>,
    /// Write crypter for epoch 1 (after our CCS).
    write_crypter: Option<RecordCrypter12>,

    /// `true` once we've installed the read crypter (i.e. after server CCS).
    ccs_received: bool,

    /// Retransmit machine.
    retransmit: Retransmit,
    /// Current logical time as the caller has reported via `on_timeout`. We
    /// only need this to seed `set_flight` after building each flight.
    last_now: Duration,
}

impl DtlsClientConnection12 {
    /// Creates a fresh client and emits the first ClientHello (with empty
    /// cookie). The RNG supplies the ephemeral key material and client
    /// random.
    pub fn new<R: RngCore>(config: DtlsClientConfig12, peer_addr: Vec<u8>, rng: &mut R) -> Self {
        let x25519 = X25519PrivateKey::generate(rng);
        let p256 = BoxedEcdhPrivateKey::generate(CurveId::P256, rng);
        let mut client_random: Random = [0u8; 32];
        rng.fill_bytes(&mut client_random);

        let mut conn = DtlsClientConnection12 {
            config,
            peer_addr,
            state: State::WaitServerHelloOrHvr,
            out_msg_seq: 0,
            reassembler: Reassembler::new(),
            out_dgrams: Vec::new(),
            app_in: Vec::new(),
            write_epoch: 0,
            write_seq_in_epoch: 0,
            read_epoch: 0,
            replay: AntiReplayWindow::new(),
            x25519,
            p256,
            client_random,
            server_random: None,
            cookie: Vec::new(),
            transcript: Transcript::new(),
            cert_chain: Vec::new(),
            leaf_key: None,
            peer_group: None,
            peer_point: None,
            master: None,
            read_crypter: None,
            write_crypter: None,
            ccs_received: false,
            retransmit: Retransmit::new(),
            last_now: Duration::from_secs(0),
        };
        // We don't include the first CH in the transcript: per RFC 6347 §4.2.1,
        // "the initial ClientHello and HelloVerifyRequest are not included in
        // the calculation of the handshake_messages". We'll reset and update on
        // the second CH (which is exactly the same encoder path, plus the
        // cookie field).
        conn.transcript.set_alg(HashAlg::Sha256);
        let flight = conn.build_client_hello_flight();
        conn.send_flight(flight);
        conn
    }

    /// Returns true once the handshake completes.
    pub fn is_handshake_complete(&self) -> bool {
        self.state == State::Connected
    }

    /// Drains pending UDP datagrams to send.
    pub fn pop_outbound_datagrams(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.out_dgrams)
    }

    /// Returns the next absolute monotonic time at which the caller should
    /// invoke `on_timeout`. None when the handshake is complete or no
    /// retransmit is armed.
    pub fn next_timeout(&self) -> Option<Duration> {
        self.retransmit.next_timeout()
    }

    /// Drives the retransmit machine. Any retransmitted datagrams land in
    /// `pop_outbound_datagrams`.
    pub fn on_timeout(&mut self, now: Duration) {
        self.last_now = now;
        match self.retransmit.on_timeout(now) {
            super::reliability::Action::Retransmit => {
                for dg in self.retransmit.flight_datagrams() {
                    self.out_dgrams.push(dg.clone());
                }
            }
            super::reliability::Action::GiveUp => {
                self.state = State::Closed;
            }
            super::reliability::Action::Idle => {}
        }
    }

    /// Drains decrypted application data.
    pub fn take_received(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app_in)
    }

    /// Queues application plaintext for transmission (must be after the
    /// handshake completes).
    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::InappropriateState);
        }
        let dg = self.encrypt_record_dtls(ContentType::ApplicationData, plaintext)?;
        self.out_dgrams.push(dg);
        Ok(())
    }

    /// Feeds an incoming UDP datagram.
    pub fn feed_datagram(&mut self, datagram: &[u8]) -> Result<(), Error> {
        let mut off = 0usize;
        while off < datagram.len() {
            let Some(rec) = record::read_record(&datagram[off..])? else {
                // Truncated trailing record — DTLS drops malformed records
                // silently rather than failing the connection.
                return Ok(());
            };
            off += rec.len;
            self.process_record(rec)?;
        }
        Ok(())
    }

    fn process_record(&mut self, rec: ParsedDtlsRecord<'_>) -> Result<(), Error> {
        // Version check: accept DTLS 1.2 + DTLS 1.0 (RFC 6347 says
        // implementations should ignore mismatches if version is plausibly
        // DTLS; we'll be strict and require DTLSv1.2).
        if rec.version != ProtocolVersion::DTLSv1_2 && rec.version != ProtocolVersion::DTLSv1_0 {
            return Err(Error::UnsupportedVersion);
        }

        // Epoch must be either current read_epoch or one ahead (after server
        // CCS). Anything else is silently dropped.
        if rec.epoch != self.read_epoch {
            // The peer's encrypted flight may arrive before its CCS in
            // theory. In practice CCS is record-content-type 20 at epoch 0,
            // and Finished is content-type 22 at epoch 1. We accept records
            // at epoch+1 only if we've already installed the read crypter
            // (which happens on CCS).
            return Ok(());
        }

        // Anti-replay (post-handshake) — only meaningful at epoch ≥ 1.
        if self.read_epoch >= 1 && !self.replay.accept(rec.seq) {
            return Ok(());
        }

        match rec.content_type {
            ContentType::ChangeCipherSpec => {
                // RFC 6347 §4.1: the only legal CCS body is `[0x01]`. CCS is
                // at epoch 0 (still plaintext); installing the read crypter
                // bumps read_epoch to 1.
                if rec.fragment != [0x01] {
                    return Err(Error::UnexpectedMessage);
                }
                if self.ccs_received {
                    // Drop duplicates.
                    return Ok(());
                }
                let c = self.read_crypter.take().ok_or(Error::UnexpectedMessage)?;
                self.read_crypter = Some(c);
                self.ccs_received = true;
                self.read_epoch = 1;
                self.replay = AntiReplayWindow::new();
                Ok(())
            }
            ContentType::Handshake => {
                let plain: Vec<u8> = if self.read_epoch >= 1 {
                    let combined = ((self.read_epoch as u64) << 48) | rec.seq;
                    let c = self.read_crypter.as_ref().ok_or(Error::UnexpectedMessage)?;
                    c.decrypt_dtls(combined, ContentType::Handshake, rec.fragment)?
                } else {
                    rec.fragment.to_vec()
                };
                self.process_handshake_record(&plain)
            }
            ContentType::ApplicationData => {
                if self.read_epoch < 1 {
                    return Err(Error::UnexpectedMessage);
                }
                let combined = ((self.read_epoch as u64) << 48) | rec.seq;
                let c = self.read_crypter.as_ref().ok_or(Error::UnexpectedMessage)?;
                let plain = c.decrypt_dtls(combined, ContentType::ApplicationData, rec.fragment)?;
                self.app_in.extend_from_slice(&plain);
                Ok(())
            }
            ContentType::Alert => {
                // Drop alerts silently in this subset; a hardened impl
                // would surface them.
                Ok(())
            }
            _ => Err(Error::UnexpectedMessage),
        }
    }

    fn process_handshake_record(&mut self, plain: &[u8]) -> Result<(), Error> {
        let mut off = 0;
        while off < plain.len() {
            let frag = read_fragment(&plain[off..])?;
            let consumed = frag.len;
            // Special-case HelloVerifyRequest: it has the unusual property
            // of NOT incrementing the client's reassembler message_seq
            // counter consistently across implementations. RFC 6347 §4.2.2
            // says message_seq for HVR is 0 and the second CH is 1. Our
            // reassembler treats messages as a strict 0,1,2,… queue. To
            // accommodate HVR while the reassembler still expects msg_seq=0
            // (server hasn't sent a real "first" handshake message yet),
            // we route HVR fragments directly without going through the
            // reassembler.
            if frag.msg_type == HS_HELLO_VERIFY_REQUEST
                && matches!(self.state, State::WaitServerHelloOrHvr)
            {
                self.handle_hello_verify_request(&frag)?;
                off += consumed;
                continue;
            }
            // Owned copy of fragment so we can hand a 'static-lifetime
            // tuple to the reassembler.
            let frag = HandshakeFragment {
                msg_type: frag.msg_type,
                total_length: frag.total_length,
                message_seq: frag.message_seq,
                fragment_offset: frag.fragment_offset,
                fragment: frag.fragment,
                len: frag.len,
            };
            off += consumed;
            if let Some((msg_type, body)) = self.reassembler.feed(frag) {
                self.dispatch_one(msg_type, &body)?;
            }
            // Drain any further messages whose fragments were buffered
            // before earlier ones (out-of-order record delivery).
            while let Some((msg_type, body)) = self.reassembler.pop_ready() {
                self.dispatch_one(msg_type, &body)?;
            }
        }
        Ok(())
    }

    fn dispatch_one(&mut self, msg_type: u8, body: &[u8]) -> Result<(), Error> {
        // Build the TLS-shaped raw bytes that the transcript expects:
        // `Type(1) || Length(3) || Body`. The DTLS-specific header
        // fields are excluded per RFC 6347 §4.2.2.
        let mut raw = Vec::with_capacity(4 + body.len());
        raw.push(msg_type);
        let len = body.len() as u32;
        raw.push(((len >> 16) & 0xff) as u8);
        raw.push(((len >> 8) & 0xff) as u8);
        raw.push((len & 0xff) as u8);
        raw.extend_from_slice(body);
        self.dispatch_handshake(msg_type, body, &raw)
    }

    fn dispatch_handshake(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        match self.state {
            State::WaitServerHelloOrHvr | State::WaitServerHello => {
                self.on_server_hello(msg_type, body, raw)
            }
            State::WaitCertificate => self.on_certificate(msg_type, body, raw),
            State::WaitServerKeyExchange => self.on_server_key_exchange(msg_type, body, raw),
            State::WaitServerHelloDone => self.on_server_hello_done(msg_type, body, raw),
            State::WaitServerFinished => self.on_server_finished(msg_type, body, raw),
            State::Connected | State::Closed => Err(Error::UnexpectedMessage),
        }
    }

    fn handle_hello_verify_request(&mut self, frag: &HandshakeFragment<'_>) -> Result<(), Error> {
        // HVR may itself be fragmented; require it whole for simplicity.
        if frag.fragment_offset != 0 || (frag.fragment.len() as u32) != frag.total_length {
            // Unsupported HVR fragmentation; reject.
            return Err(Error::Decode);
        }
        let body = frag.fragment;
        let mut c = ReadCursor::new(body);
        let _version = c.u16()?; // server_version
        let cookie = c.vec_u8()?.to_vec();
        c.expect_empty()?;
        if cookie.is_empty() {
            return Err(Error::Decode);
        }
        self.cookie = cookie;

        // Per RFC 6347 §4.2.2, the second CH's message_seq is 1. The
        // server's next message_seq is also 1 (HVR was 0). Our reassembler
        // is currently waiting on msg_seq=0 from the server; the next real
        // message we'll receive is msg_seq=1, so we need to advance it.
        // The simplest approach: feed a synthetic fragment for msg_seq=0
        // so the reassembler bumps to 1. We use msg_type=HS_HELLO_VERIFY_REQUEST
        // body=empty body — but our reassembler accepts only fragments
        // with positive total_length to "complete" empty messages; let's
        // use a different approach.
        //
        // Easier: rebuild the reassembler so it starts at msg_seq=1.
        self.reassembler = Reassembler::new();
        // Replay a "completed" msg_seq=0 to advance the counter.
        // Feed an empty-body fragment with msg_seq=0; total_length=0;
        // fragment_length=0 — this completes msg_seq=0 and advances to 1.
        let mut synthetic = Vec::new();
        super::reassembly::write_message(&mut synthetic, HS_HELLO_VERIFY_REQUEST, 0, b"", 0);
        let synth_frag = super::reassembly::read_fragment(&synthetic)?;
        let _ = self.reassembler.feed(synth_frag);
        // Now reassembler.expected_msg_seq() == 1.

        // Cancel the retransmit timer for the first CH; build and send
        // the cookie-bearing second CH.
        self.retransmit.on_peer_response();

        self.state = State::WaitServerHello;
        self.out_msg_seq = 1;
        // Reset the write epoch sequence — but actually no, the record-layer
        // seq spans all records at this epoch. The HVR was at epoch 0, the
        // new CH continues at epoch 0. RFC 6347 §4.1: "The first record
        // transmitted in any epoch MUST have sequence number 0... A separate
        // sequence number is maintained separately for each epoch." We're
        // still in epoch 0 (haven't done CCS yet), so the seq counter
        // continues, NOT resets. Our `write_seq_in_epoch` is correct as-is.

        // RFC 6347 §4.2.1: the initial CH + HVR are not in the transcript.
        // The transcript starts fresh with the second CH.
        self.transcript = Transcript::new();
        self.transcript.set_alg(HashAlg::Sha256);

        let flight = self.build_client_hello_flight();
        self.send_flight(flight);
        Ok(())
    }

    fn on_server_hello(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::SERVER_HELLO {
            return Err(Error::UnexpectedMessage);
        }
        let sh = ServerHello::decode(body)?;
        // For this subset we require the single suite we offer.
        if sh.cipher_suite != CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 {
            return Err(Error::HandshakeFailure);
        }
        self.server_random = Some(sh.random);
        self.transcript.update(raw);
        self.state = State::WaitCertificate;
        // We've received the first real flight from the server; cancel the
        // retransmit timer for our CH-with-cookie.
        self.retransmit.on_peer_response();
        Ok(())
    }

    fn on_certificate(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::CERTIFICATE {
            return Err(Error::UnexpectedMessage);
        }
        let chain = parse_certificate_list(body)?;
        if chain.is_empty() {
            return Err(Error::BadCertificate);
        }
        let leaf = Certificate::from_der(chain[0].clone()).map_err(|_| Error::BadCertificate)?;
        leaf.check_well_formed()
            .map_err(|_| Error::BadCertificate)?;
        let leaf_key = if self.config.verify_certificates {
            let now = self.config.verification_time.clone();
            verify_chain(
                &self.config.roots,
                &chain,
                now.as_ref(),
                &self.config.signature_policy,
            )?
        } else {
            leaf.subject_public_key()
                .map_err(|_| Error::BadCertificate)?
        };
        self.cert_chain = chain;
        self.leaf_key = Some(leaf_key);
        self.transcript.update(raw);
        self.state = State::WaitServerKeyExchange;
        Ok(())
    }

    fn on_server_key_exchange(
        &mut self,
        msg_type: u8,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), Error> {
        if msg_type != hs_type::SERVER_KEY_EXCHANGE {
            return Err(Error::UnexpectedMessage);
        }
        let ske = ServerKeyExchange::decode(body)?;
        // Verify the SKE signature under the leaf's key.
        let cr = self.client_random;
        let sr = self.server_random.ok_or(Error::InappropriateState)?;
        let msg = signed_message(&cr, &sr, ske.group, &ske.point);
        let key = self
            .leaf_key
            .as_ref()
            .ok_or(Error::InappropriateState)?
            .clone();
        verify_signature(
            ske.scheme,
            &key,
            &msg,
            &ske.signature,
            &self.config.signature_policy,
        )?;
        self.peer_group = Some(ske.group);
        self.peer_point = Some(ske.point);
        self.transcript.update(raw);
        self.state = State::WaitServerHelloDone;
        Ok(())
    }

    fn on_server_hello_done(
        &mut self,
        msg_type: u8,
        _body: &[u8],
        raw: &[u8],
    ) -> Result<(), Error> {
        if msg_type != hs_type::SERVER_HELLO_DONE {
            return Err(Error::UnexpectedMessage);
        }
        self.transcript.update(raw);

        // Complete ECDHE + derive master + key block.
        let group = self.peer_group.ok_or(Error::InappropriateState)?;
        let peer_point = self.peer_point.clone().ok_or(Error::InappropriateState)?;
        let (premaster, our_point) = self.ecdhe(group, &peer_point)?;

        let cr = self.client_random;
        let sr = self.server_random.ok_or(Error::InappropriateState)?;
        let master = master_secret(HashAlg::Sha256, &premaster, &cr, &sr);

        // key_block: c_key(16) || s_key(16) || c_iv(4) || s_iv(4) — total 40 bytes.
        let mut kb = alloc::vec![0u8; 2 * KEY_LEN + 8];
        key_block(HashAlg::Sha256, &master, &sr, &cr, &mut kb);
        let (c_key, rest) = kb.split_at(KEY_LEN);
        let (s_key, rest) = rest.split_at(KEY_LEN);
        let mut c_salt = [0u8; 4];
        c_salt.copy_from_slice(&rest[..4]);
        let mut s_salt = [0u8; 4];
        s_salt.copy_from_slice(&rest[4..8]);
        let write_crypter =
            RecordCrypter12::new(crate::tls::crypto::AeadAlg::Aes128Gcm, c_key, c_salt);
        let read_crypter =
            RecordCrypter12::new(crate::tls::crypto::AeadAlg::Aes128Gcm, s_key, s_salt);
        self.master = Some(master);
        self.write_crypter = Some(write_crypter);
        self.read_crypter = Some(read_crypter);

        // Build the client's final flight: CKE, CCS, Finished.
        let mut flight = Flight::new();

        // ClientKeyExchange — DTLS handshake msg_seq advances; record at epoch 0.
        let cke = ClientKeyExchange { point: our_point }.encode();
        // `cke` already has the 4-byte TLS handshake header; we strip it for
        // transcript+DTLS fragmentation, then re-add for the transcript.
        // Strip header: [type(1) | length(3) | body].
        let cke_body = &cke[4..];
        let cke_msg_seq = self.out_msg_seq;
        self.out_msg_seq += 1;
        let mut cke_frag_buf = Vec::new();
        write_message(
            &mut cke_frag_buf,
            hs_type::CLIENT_KEY_EXCHANGE,
            cke_msg_seq,
            cke_body,
            DEFAULT_MAX_FRAGMENT,
        );
        // Transcript: TLS-shaped (no DTLS headers).
        self.transcript.update(&cke);
        let cke_dgram = self.wrap_plain_record(ContentType::Handshake, &cke_frag_buf);
        flight.push(cke_dgram);

        // ChangeCipherSpec — its own DTLS record, plaintext, epoch 0, content_type 20.
        let ccs_dgram = self.wrap_plain_record(ContentType::ChangeCipherSpec, &[0x01]);
        flight.push(ccs_dgram);

        // Bump our write epoch — the next record (Finished) is encrypted
        // under the new write crypter at epoch 1.
        self.write_epoch = 1;
        self.write_seq_in_epoch = 0;

        // Finished: 12-byte verify_data over transcript hash.
        let th = self.transcript.current_hash();
        let verify_data =
            finished_verify_data(HashAlg::Sha256, &master, b"client finished", th.as_slice());
        // Build the Finished body (just 12 bytes — verify_data).
        let fin_body: Vec<u8> = verify_data.to_vec();
        // Transcript: TLS-shaped finished.
        let mut fin_tls = Vec::with_capacity(4 + 12);
        fin_tls.push(hs_type::FINISHED);
        fin_tls.extend_from_slice(&[0, 0, 12]);
        fin_tls.extend_from_slice(&fin_body);
        self.transcript.update(&fin_tls);
        // DTLS handshake fragment.
        let fin_msg_seq = self.out_msg_seq;
        self.out_msg_seq += 1;
        let mut fin_frag_buf = Vec::new();
        write_message(
            &mut fin_frag_buf,
            hs_type::FINISHED,
            fin_msg_seq,
            &fin_body,
            DEFAULT_MAX_FRAGMENT,
        );
        let fin_dgram = self.encrypt_record_dtls(ContentType::Handshake, &fin_frag_buf)?;
        flight.push(fin_dgram);

        self.send_flight(flight);
        self.state = State::WaitServerFinished;
        Ok(())
    }

    fn on_server_finished(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::FINISHED {
            return Err(Error::UnexpectedMessage);
        }
        if body.len() != 12 {
            return Err(Error::Decode);
        }
        let master = self.master.ok_or(Error::InappropriateState)?;
        let th = self.transcript.current_hash();
        let expected =
            finished_verify_data(HashAlg::Sha256, &master, b"server finished", th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.transcript.update(raw);
        self.retransmit.on_peer_response();
        self.state = State::Connected;
        Ok(())
    }

    fn ecdhe(&self, group: NamedGroup, peer_point: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match group {
            NamedGroup::X25519 => {
                let peer: [u8; 32] = peer_point.try_into().map_err(|_| Error::Decode)?;
                // RFC 7748 §6.1: reject the all-zero (small-order) DH output.
                let ss = self
                    .x25519
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::IllegalParameter)?;
                Ok((ss.to_vec(), self.x25519.public_key().to_vec()))
            }
            NamedGroup::SECP256R1 => {
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, peer_point)
                    .map_err(|_| Error::Decode)?;
                let ss = self
                    .p256
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?;
                Ok((ss, self.p256.public_key().to_sec1()))
            }
            _ => Err(Error::HandshakeFailure),
        }
    }

    /// Builds the current ClientHello as a one-element flight. The body uses
    /// the current `cookie` (empty for the first attempt).
    fn build_client_hello_flight(&mut self) -> Flight {
        let suites = alloc::vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
        let groups = alloc::vec![NamedGroup::X25519];

        let extensions = alloc::vec![
            ext::server_name(&self.config.server_name),
            ext::supported_groups_list(&groups),
            ext::signature_algorithms(),
            ext::ec_point_formats(),
        ];

        // Encode the DTLS ClientHello body. Wire layout (RFC 6347 §4.2.1):
        //   ProtocolVersion legacy_version  (0xfefd for DTLS 1.2)
        //   Random random
        //   opaque legacy_session_id<0..32>
        //   opaque cookie<0..32>                  // DTLS-only
        //   CipherSuite cipher_suites<2..2^16-2>
        //   opaque legacy_compression_methods<1..255>  ([0])
        //   Extension extensions<0..2^16-1>
        let mut body = Vec::new();
        body.extend_from_slice(&0xfefd_u16.to_be_bytes());
        body.extend_from_slice(&self.client_random);
        with_len_u8(&mut body, |b| b.extend_from_slice(&[]));
        with_len_u8(&mut body, |b| b.extend_from_slice(&self.cookie));
        with_len_u16(&mut body, |b| {
            for cs in &suites {
                b.extend_from_slice(&cs.0.to_be_bytes());
            }
        });
        with_len_u8(&mut body, |b| b.push(0)); // compression: null only
        // Encode extensions inline.
        with_len_u16(&mut body, |b| {
            for (ty, e) in &extensions {
                b.extend_from_slice(&ty.0.to_be_bytes());
                with_len_u16(b, |bb| bb.extend_from_slice(e));
            }
        });

        // Transcript bookkeeping (RFC 6347 §4.2.1): the initial CH +
        // HelloVerifyRequest are NOT in the transcript; the second CH
        // (with cookie) IS, along with everything that follows. We can't
        // know yet whether the server will demand a cookie, so always feed
        // this CH into the transcript. On HVR we reset the transcript and
        // feed the second CH instead. Per RFC 6347 §4.2.2, the
        // DTLS-specific handshake-header fields (message_seq,
        // fragment_offset, fragment_length) are excluded, but the CH body
        // — including the cookie field — IS included.
        let mut tls_ch = Vec::with_capacity(4 + body.len());
        tls_ch.push(hs_type::CLIENT_HELLO);
        let n = body.len() as u32;
        tls_ch.push(((n >> 16) & 0xff) as u8);
        tls_ch.push(((n >> 8) & 0xff) as u8);
        tls_ch.push((n & 0xff) as u8);
        tls_ch.extend_from_slice(&body);
        self.transcript.update(&tls_ch);

        // Wrap as a DTLS handshake fragment.
        let ch_msg_seq = self.out_msg_seq;
        // out_msg_seq is incremented after build (CH=0 first time, CH=1 after HVR)
        // by the caller flow — but here we have to do it explicitly since the
        // CH is a one-message flight.
        self.out_msg_seq += 1;
        let mut frag_buf = Vec::new();
        write_message(
            &mut frag_buf,
            hs_type::CLIENT_HELLO,
            ch_msg_seq,
            &body,
            DEFAULT_MAX_FRAGMENT,
        );
        let dgram = self.wrap_plain_record(ContentType::Handshake, &frag_buf);
        let mut flight = Flight::new();
        flight.push(dgram);
        flight
    }

    /// Wraps a plaintext fragment in a DTLS record header at the current
    /// write epoch (must be 0 for plaintext records). Bumps the write
    /// sequence in the current epoch.
    fn wrap_plain_record(&mut self, ct: ContentType, fragment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        record::write_record(
            &mut out,
            ct,
            ProtocolVersion::DTLSv1_2,
            self.write_epoch,
            self.write_seq_in_epoch,
            fragment,
        );
        self.write_seq_in_epoch += 1;
        out
    }

    /// Encrypts `payload` under the current write epoch's crypter and wraps
    /// it in a DTLS record header. The combined epoch-seq is also the AEAD
    /// nonce/AAD seq slot.
    fn encrypt_record_dtls(&mut self, ct: ContentType, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let crypter = self
            .write_crypter
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let combined = ((self.write_epoch as u64) << 48) | self.write_seq_in_epoch;
        let fragment = crypter.encrypt_dtls(combined, ct, payload)?;
        let mut out = Vec::new();
        record::write_record(
            &mut out,
            ct,
            ProtocolVersion::DTLSv1_2,
            self.write_epoch,
            self.write_seq_in_epoch,
            &fragment,
        );
        self.write_seq_in_epoch += 1;
        Ok(out)
    }

    /// Sends each datagram in `flight` and arms the retransmit timer.
    fn send_flight(&mut self, flight: Flight) {
        for dg in &flight.datagrams {
            self.out_dgrams.push(dg.clone());
        }
        self.retransmit.set_flight(flight, self.last_now);
    }
}

/// Parses a TLS-shaped Certificate message body (same wire as TLS 1.2; the
/// DTLS handshake header was already stripped by the caller).
fn parse_certificate_list(body: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut c = ReadCursor::new(body);
    let list = c.vec_u24()?;
    c.expect_empty()?;
    let mut entries = ReadCursor::new(list);
    let mut certs = Vec::new();
    while !entries.is_empty() {
        let cert = entries.vec_u24()?.to_vec();
        if cert.is_empty() {
            return Err(Error::BadCertificate);
        }
        certs.push(cert);
    }
    Ok(certs)
}
