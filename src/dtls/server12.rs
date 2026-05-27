#![allow(dead_code, unreachable_pub)]

//! DTLS 1.2 server state machine (RFC 6347).
//!
//! Mirror of [`super::client12::DtlsClientConnection12`]. The server
//! consumes the first ClientHello, optionally responds with a
//! HelloVerifyRequest (RFC 6347 §4.2.1) so the client proves source-address
//! reachability before any state is allocated, then proceeds through the
//! TLS 1.2 ECDHE-ECDSA handshake under the DTLS record layer.

use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, CurveId};
use crate::hash::Sha256;
use crate::rng::RngCore;
use crate::signature_registry::SignaturePolicy;
use crate::tls::codec::extension as ext;
use crate::tls::codec::handshake12::{ClientKeyExchange, ServerKeyExchange, signed_message};
use crate::tls::codec::{
    CipherSuite, ExtensionType, NamedGroup, Random, ReadCursor, ServerHello, SignatureScheme,
    hs_type, with_len_u8, with_len_u24,
};
use crate::tls::crypto::aead12::RecordCrypter12;
use crate::tls::crypto::prf::{
    extended_master_secret, finished_verify_data, key_block, master_secret,
};
use crate::tls::crypto::{HashAlg, Transcript};
use crate::tls::keylog::KeyLog;
use crate::tls::{ContentType, Error, ProtocolVersion};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use super::cookie::CookieGenerator;
use super::reassembly::{HandshakeFragment, Reassembler, read_fragment, write_message};
use super::record::{self, ParsedDtlsRecord};
use super::reliability::{Flight, Retransmit};
use super::replay::AntiReplayWindow;

#[allow(unused_imports)]
use crate::ct::ConstantTimeEq;

/// HelloVerifyRequest handshake type code (RFC 6347 §4.2.1).
const HS_HELLO_VERIFY_REQUEST: u8 = 3;

/// Default per-fragment payload size for outbound handshake messages.
const DEFAULT_MAX_FRAGMENT: usize = 1100;

/// AEAD key length for AES-128-GCM.
const KEY_LEN: usize = 16;

/// Configuration for a DTLS 1.2 server.
pub(crate) struct ServerConfig12Internal {
    /// Certificate chain (leaf first).
    cert_chain: Vec<Vec<u8>>,
    /// ECDSA signing key. (RSA support is omitted in this subset to keep
    /// the implementation focused.)
    key: BoxedEcdsaPrivateKey,
    /// Cookie generator secret. When `None`, the server skips
    /// HelloVerifyRequest entirely (useful for tests; a production
    /// configuration always sets this).
    cookie_secret: Option<[u8; 32]>,
    /// When `true`, ALL clients must complete the cookie exchange before
    /// the server allocates any handshake state. When `false`, the cookie
    /// step is skipped — only safe for tests.
    require_cookie_exchange: bool,
    /// Allowed signature algorithms (reserved for client-auth in a future
    /// commit; currently unused on the server side because we don't accept
    /// client certificates yet).
    #[allow(dead_code)]
    signature_policy: SignaturePolicy,
    /// Optional [`KeyLog`] sink (NSS `SSLKEYLOGFILE` format).
    pub(crate) key_log: Option<Arc<dyn KeyLog>>,
}

impl ServerConfig12Internal {
    /// New configuration presenting `cert_chain` and signing with the
    /// ECDSA `key`. Cookie exchange is required by default.
    pub fn with_ecdsa(cert_chain: Vec<Vec<u8>>, key: BoxedEcdsaPrivateKey) -> Self {
        Self {
            cert_chain,
            key,
            cookie_secret: None,
            require_cookie_exchange: true,
            signature_policy: SignaturePolicy::modern(),
            key_log: None,
        }
    }

    /// Sets the cookie secret used for HelloVerifyRequest. Callers
    /// typically derive this from a long-lived high-entropy server secret.
    pub fn with_cookie_secret(mut self, secret: [u8; 32]) -> Self {
        self.cookie_secret = Some(secret);
        self
    }

    /// Toggles whether the cookie exchange is enforced. Default is `true`.
    /// Disable only for tests where the cookie path isn't under test.
    pub fn require_cookie_exchange(mut self, required: bool) -> Self {
        self.require_cookie_exchange = required;
        self
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum State {
    /// Awaiting the first ClientHello (cookie path) or the only CH (when
    /// cookies are disabled).
    WaitFirstClientHello,
    /// Sent HelloVerifyRequest, awaiting cookie-bearing second CH.
    WaitSecondClientHello,
    /// Sent server flight (SH/Cert/SKE/SHDone), awaiting client
    /// CKE/CCS/Finished.
    WaitClientFlight,
    /// Sent our CCS/Finished, awaiting nothing further from the client.
    Connected,
    Closed,
}

/// A DTLS 1.2 server connection.
pub struct DtlsServerConnection12<R: RngCore> {
    config: Arc<ServerConfig12Internal>,
    rng: R,

    /// Peer address bytes — opaque, used by the cookie generator.
    peer_addr: Vec<u8>,

    state: State,

    /// DTLS handshake message counter for outbound messages.
    out_msg_seq: u16,
    /// Reassembler for inbound messages (created lazily so cookie-bounce
    /// CHs don't allocate state until the cookie is validated).
    reassembler: Option<Reassembler>,

    /// Outbound UDP datagrams.
    out_dgrams: Vec<Vec<u8>>,
    /// Decrypted application data.
    app_in: Vec<u8>,

    /// Record-layer sequence numbers.
    write_epoch: u16,
    write_seq_in_epoch: u64,
    read_epoch: u16,

    /// Anti-replay window for the current encrypted read epoch.
    replay: AntiReplayWindow,

    /// Ephemeral X25519 ECDHE key (generated on second CH).
    x25519: Option<X25519PrivateKey>,
    /// Ephemeral P-256 key (unused in this subset; reserved for future).
    #[allow(dead_code)]
    p256: Option<BoxedEcdhPrivateKey>,

    client_random: Option<Random>,
    server_random: Option<Random>,

    transcript: Transcript,

    master: Option<[u8; 48]>,
    read_crypter: Option<RecordCrypter12>,
    write_crypter: Option<RecordCrypter12>,
    /// Pending read crypter parked until the client's CCS arrives.
    pending_read_crypter: Option<RecordCrypter12>,
    /// Pending write crypter parked until we emit our own CCS.
    pending_write_crypter: Option<RecordCrypter12>,

    ccs_received: bool,

    /// Last-built flight retransmit machine.
    retransmit: Retransmit,
    /// Current logical time the caller has reported.
    last_now: Duration,

    /// RFC 7627 §5.1 — set when the client offered `extended_master_secret`
    /// and we echoed it. Drives the master-secret derivation choice.
    ems_negotiated: bool,
}

impl<R: RngCore> DtlsServerConnection12<R> {
    /// Creates a server awaiting a ClientHello from `peer_addr`. `peer_addr`
    /// is the opaque identifier used by the cookie generator.
    pub(crate) fn new(config: Arc<ServerConfig12Internal>, peer_addr: Vec<u8>, rng: R) -> Self {
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
            write_epoch: 0,
            write_seq_in_epoch: 0,
            read_epoch: 0,
            replay: AntiReplayWindow::new(),
            x25519: None,
            p256: None,
            client_random: None,
            server_random: None,
            transcript: t,
            master: None,
            read_crypter: None,
            write_crypter: None,
            pending_read_crypter: None,
            pending_write_crypter: None,
            ccs_received: false,
            retransmit: Retransmit::new(),
            last_now: Duration::from_secs(0),
            ems_negotiated: false,
        }
    }

    /// Returns true once the handshake completes.
    pub fn is_handshake_complete(&self) -> bool {
        self.state == State::Connected
    }

    /// IANA cipher-suite identifier of the negotiated suite, or `None`
    /// until the handshake completes. DTLS 1.2 in this crate is locked
    /// to `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B).
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.is_handshake_complete().then_some(0xC02B)
    }

    /// Drains pending UDP datagrams to send.
    pub fn pop_outbound_datagrams(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.out_dgrams)
    }

    /// Drains decrypted application data.
    pub fn take_received(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app_in)
    }

    /// Encrypts application plaintext as a DTLS record. Must be called only
    /// after the handshake completes.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::InappropriateState);
        }
        let dg = self.encrypt_record_dtls(ContentType::ApplicationData, plaintext)?;
        self.out_dgrams.push(dg);
        Ok(())
    }

    /// Absolute monotonic time at which `on_timeout` should be called next.
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
            super::reliability::Action::GiveUp => self.state = State::Closed,
            super::reliability::Action::Idle => {}
        }
    }

    /// Feeds one incoming UDP datagram into the connection.
    pub fn feed_datagram(&mut self, datagram: &[u8]) -> Result<(), Error> {
        let mut off = 0usize;
        while off < datagram.len() {
            let Some(rec) = record::read_record(&datagram[off..])? else {
                return Ok(());
            };
            off += rec.len;
            self.process_record(rec)?;
        }
        Ok(())
    }

    fn process_record(&mut self, rec: ParsedDtlsRecord<'_>) -> Result<(), Error> {
        if rec.version != ProtocolVersion::DTLSv1_2 && rec.version != ProtocolVersion::DTLSv1_0 {
            return Err(Error::UnsupportedVersion);
        }
        if rec.epoch != self.read_epoch {
            return Ok(());
        }
        if self.read_epoch >= 1 && !self.replay.accept(rec.seq) {
            return Ok(());
        }
        match rec.content_type {
            ContentType::ChangeCipherSpec => {
                if rec.fragment != [0x01] {
                    return Err(Error::UnexpectedMessage);
                }
                if self.ccs_received {
                    return Ok(());
                }
                let c = self
                    .pending_read_crypter
                    .take()
                    .ok_or(Error::UnexpectedMessage)?;
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
            ContentType::Alert => Ok(()),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    fn process_handshake_record(&mut self, plain: &[u8]) -> Result<(), Error> {
        let mut off = 0;
        while off < plain.len() {
            let frag = read_fragment(&plain[off..])?;
            let consumed = frag.len;
            // Pre-state-allocation cookie path: when we're still
            // awaiting the first or second CH and the reassembler hasn't
            // been built, parse the fragment as a single CH directly.
            if self.reassembler.is_none() {
                // Require complete, unfragmented CH for the cookie dance.
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
            // Owned reborrow.
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
            if let Some((msg_type, body)) = feeding {
                self.dispatch_one(msg_type, &body)?;
            }
            // Drain any further already-buffered messages.
            loop {
                let popped = self
                    .reassembler
                    .as_mut()
                    .expect("reassembler built")
                    .pop_ready();
                match popped {
                    Some((msg_type, body)) => self.dispatch_one(msg_type, &body)?,
                    None => break,
                }
            }
        }
        Ok(())
    }

    fn dispatch_one(&mut self, msg_type: u8, body: &[u8]) -> Result<(), Error> {
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
            State::WaitClientFlight => self.on_client_flight(msg_type, body, raw),
            State::Connected | State::Closed => Err(Error::UnexpectedMessage),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Parses one ClientHello body (DTLS wire format) and either issues
    /// HelloVerifyRequest or transitions to the server-flight path.
    fn handle_pre_state_client_hello(&mut self, msg_seq: u16, body: &[u8]) -> Result<(), Error> {
        // Decode the DTLS-flavoured ClientHello body.
        let parsed = parse_dtls_client_hello(body)?;

        let cookie_required =
            self.config.require_cookie_exchange && self.config.cookie_secret.is_some();
        let first_attempt = parsed.cookie.is_empty();

        if cookie_required && first_attempt {
            // Emit HelloVerifyRequest with a freshly computed cookie.
            let secret = self
                .config
                .cookie_secret
                .as_ref()
                .ok_or(Error::InappropriateState)?;
            let cg = CookieGenerator::new(*secret);
            let now_min = (self.last_now.as_secs() / 60) as u32;
            let cookie = cg.generate(&self.peer_addr, &parsed.random, now_min);
            self.emit_hello_verify_request(&cookie)?;
            self.state = State::WaitSecondClientHello;
            // We deliberately do NOT add this CH or HVR to a transcript
            // and we keep `reassembler` None so the next CH also enters
            // this pre-state path (RFC 6347 §4.2.1).
            return Ok(());
        }

        if cookie_required && !first_attempt {
            // Validate the cookie.
            let secret = self
                .config
                .cookie_secret
                .as_ref()
                .ok_or(Error::InappropriateState)?;
            let cg = CookieGenerator::new(*secret);
            let now_min = (self.last_now.as_secs() / 60) as u32;
            if !cg.validate(&self.peer_addr, &parsed.random, now_min, &parsed.cookie) {
                return Err(Error::IllegalParameter);
            }
        }

        // Cookie validated (or skipped): proceed with the handshake. The
        // transcript starts with this CH per RFC 6347 §4.2.1.
        self.client_random = Some(parsed.random);
        // Pin the transcript hash (SHA256 — the only suite we support).
        // Already done at construction; update with the TLS-shaped CH.
        let mut tls_ch = Vec::with_capacity(4 + body.len());
        tls_ch.push(hs_type::CLIENT_HELLO);
        let n = body.len() as u32;
        tls_ch.push(((n >> 16) & 0xff) as u8);
        tls_ch.push(((n >> 8) & 0xff) as u8);
        tls_ch.push((n & 0xff) as u8);
        tls_ch.extend_from_slice(body);
        self.transcript.update(&tls_ch);

        // Sanity-check the suites: we require AES-128-GCM-SHA256-ECDSA.
        let want = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        if !parsed.cipher_suites.contains(&want) {
            return Err(Error::HandshakeFailure);
        }
        // Require X25519 in supported_groups.
        let groups_body = ext::find(&parsed.extensions, ExtensionType::SUPPORTED_GROUPS)
            .ok_or(Error::HandshakeFailure)?;
        let groups = parse_supported_groups(groups_body)?;
        if !groups.contains(&NamedGroup::X25519) {
            return Err(Error::HandshakeFailure);
        }

        // RFC 7627 §5.1: detect the client's EMS offer (DTLS 1.2 inherits
        // the rules from TLS 1.2). Body MUST be empty.
        if let Some(ems_body) = ext::find(&parsed.extensions, ExtensionType::EXTENDED_MASTER_SECRET)
        {
            ext::parse_extended_master_secret(ems_body)?;
            self.ems_negotiated = true;
        }
        // Initialise the reassembler at expected_msg_seq = msg_seq + 1
        // (the client's next handshake msg after CH).
        let mut reasm = Reassembler::new();
        for s in 0..=msg_seq {
            // Drive its counter up to msg_seq+1 by feeding synthetic
            // zero-length messages of type CLIENT_HELLO. Each call
            // expects the next seq.
            let mut buf = Vec::new();
            write_message(&mut buf, hs_type::CLIENT_HELLO, s, b"", 0);
            let f = read_fragment(&buf)?;
            let _ = reasm.feed(f);
        }
        self.reassembler = Some(reasm);

        // Generate the server's random + server flight.
        let mut sr: Random = [0u8; 32];
        self.rng.fill_bytes(&mut sr);
        self.server_random = Some(sr);

        // Generate the ECDHE key share.
        let sk = X25519PrivateKey::generate(&mut self.rng);
        let our_point = sk.public_key().to_vec();
        self.x25519 = Some(sk);

        // After HVR, the server's message_seq continues from 1 (HVR was 0);
        // without HVR, message_seq starts at 0. Cookie-disabled path: HVR
        // was never sent, so message_seq starts at 0.
        if cookie_required {
            // HVR was message_seq=0, so the next outbound message is 1.
            // We already set this when we sent HVR; nothing more here.
            // out_msg_seq is at 1.
        } else {
            self.out_msg_seq = 0;
        }

        // Build the server flight.
        let mut flight = Flight::new();

        // ServerHello. Always include ec_point_formats; echo EMS when
        // negotiated (RFC 7627 §5.1).
        let mut sh_exts: Vec<(ExtensionType, Vec<u8>)> = alloc::vec![ext::ec_point_formats()];
        if self.ems_negotiated {
            sh_exts.push(ext::extended_master_secret_empty());
        }
        let sh = ServerHello {
            random: sr,
            session_id: Vec::new(),
            cipher_suite: want,
            extensions: sh_exts,
        }
        .encode();
        // sh has leading 4-byte TLS header — strip for transcript not
        // needed (transcript wants full TLS-shaped including header). Keep
        // as-is for transcript.
        self.transcript.update(&sh);
        // Strip for DTLS fragment wrapping.
        let sh_body = &sh[4..];
        let sh_dgram = self.wrap_handshake(hs_type::SERVER_HELLO, sh_body);
        flight.push(sh_dgram);

        // Certificate.
        let cert_msg = build_certificate_msg(&self.config.cert_chain);
        self.transcript.update(&cert_msg);
        let cert_body = &cert_msg[4..];
        let cert_dgram = self.wrap_handshake(hs_type::CERTIFICATE, cert_body);
        flight.push(cert_dgram);

        // ServerKeyExchange.
        let cr = self.client_random.expect("set above");
        let to_sign = signed_message(&cr, &sr, NamedGroup::X25519, &our_point);
        let sig_der = self
            .config
            .key
            .sign::<Sha256>(&to_sign)
            .map_err(|_| Error::HandshakeFailure)?
            .to_der(self.config.key.curve());
        let ske = ServerKeyExchange {
            group: NamedGroup::X25519,
            point: our_point,
            scheme: ecdsa_scheme_for(self.config.key.curve()),
            signature: sig_der,
        }
        .encode();
        self.transcript.update(&ske);
        let ske_body = &ske[4..];
        let ske_dgram = self.wrap_handshake(hs_type::SERVER_KEY_EXCHANGE, ske_body);
        flight.push(ske_dgram);

        // ServerHelloDone (empty body).
        let mut shd = Vec::with_capacity(4);
        shd.push(hs_type::SERVER_HELLO_DONE);
        shd.extend_from_slice(&[0, 0, 0]);
        self.transcript.update(&shd);
        let shd_dgram = self.wrap_handshake(hs_type::SERVER_HELLO_DONE, &[]);
        flight.push(shd_dgram);

        self.send_flight(flight);
        self.state = State::WaitClientFlight;
        Ok(())
    }

    fn emit_hello_verify_request(&mut self, cookie: &[u8]) -> Result<(), Error> {
        // Body: ProtocolVersion(2) || opaque cookie<0..32>.
        let mut body = Vec::new();
        body.extend_from_slice(&0xfefd_u16.to_be_bytes());
        with_len_u8(&mut body, |b| b.extend_from_slice(cookie));

        // Wrap as a DTLS handshake fragment with msg_seq=0. NOTE: per
        // RFC 6347 §4.2.2, "[the server's] message_seq for HVR is 0", and
        // the server's *next* outbound handshake message (ServerHello)
        // also continues from message_seq=1.
        let mut frag_buf = Vec::new();
        write_message(&mut frag_buf, HS_HELLO_VERIFY_REQUEST, 0, &body, 0);
        let dgram = self.wrap_plain_record(ContentType::Handshake, &frag_buf);
        self.out_dgrams.push(dgram);
        // The server's out_msg_seq advances regardless of whether the
        // cookie path was taken — the next outbound message is 1.
        self.out_msg_seq = 1;
        Ok(())
    }

    fn wrap_handshake(&mut self, msg_type: u8, body: &[u8]) -> Vec<u8> {
        let msg_seq = self.out_msg_seq;
        self.out_msg_seq += 1;
        let mut frag = Vec::new();
        write_message(&mut frag, msg_type, msg_seq, body, DEFAULT_MAX_FRAGMENT);
        self.wrap_plain_record(ContentType::Handshake, &frag)
    }

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

    fn send_flight(&mut self, flight: Flight) {
        for dg in &flight.datagrams {
            self.out_dgrams.push(dg.clone());
        }
        self.retransmit.set_flight(flight, self.last_now);
    }

    /// Process the client's CKE / Finished flight (CCS is handled at the
    /// record layer in `process_record`).
    fn on_client_flight(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        match msg_type {
            hs_type::CLIENT_KEY_EXCHANGE => self.on_client_key_exchange(body, raw),
            hs_type::FINISHED => self.on_finished(body, raw),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    fn on_client_key_exchange(&mut self, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        let cke = ClientKeyExchange::decode(body)?;
        let sk = self.x25519.as_ref().ok_or(Error::InappropriateState)?;
        // Group is X25519.
        let peer: [u8; 32] = cke.point.as_slice().try_into().map_err(|_| Error::Decode)?;
        // RFC 7748 §6.1: reject the all-zero (small-order) DH output.
        let ss = sk
            .diffie_hellman(&peer)
            .map_err(|_| Error::IllegalParameter)?;
        let premaster = ss.to_vec();
        let cr = self.client_random.expect("set");
        let sr = self.server_random.expect("set");

        // Feed CKE into the transcript BEFORE deriving the master so the
        // EMS session_hash (RFC 7627 §4) spans CH..CKE inclusive.
        self.transcript.update(raw);

        let master = if self.ems_negotiated {
            let sh = self.transcript.current_hash();
            extended_master_secret(HashAlg::Sha256, &premaster, sh.as_slice())
        } else {
            master_secret(HashAlg::Sha256, &premaster, &cr, &sr)
        };
        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log("CLIENT_RANDOM", &cr, &master);
        }
        let mut kb = alloc::vec![0u8; 2 * KEY_LEN + 8];
        key_block(HashAlg::Sha256, &master, &sr, &cr, &mut kb);
        let (c_key, rest) = kb.split_at(KEY_LEN);
        let (s_key, rest) = rest.split_at(KEY_LEN);
        let mut c_salt = [0u8; 4];
        c_salt.copy_from_slice(&rest[..4]);
        let mut s_salt = [0u8; 4];
        s_salt.copy_from_slice(&rest[4..8]);
        self.pending_read_crypter = Some(RecordCrypter12::new(
            crate::tls::crypto::AeadAlg::Aes128Gcm,
            c_key,
            c_salt,
        ));
        self.pending_write_crypter = Some(RecordCrypter12::new(
            crate::tls::crypto::AeadAlg::Aes128Gcm,
            s_key,
            s_salt,
        ));
        self.master = Some(master);
        Ok(())
    }

    fn on_finished(&mut self, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if body.len() != 12 {
            return Err(Error::Decode);
        }
        if self.read_crypter.is_none() {
            // CCS must arrive first.
            return Err(Error::UnexpectedMessage);
        }
        let master = self.master.ok_or(Error::InappropriateState)?;
        let th = self.transcript.current_hash();
        let expected =
            finished_verify_data(HashAlg::Sha256, &master, b"client finished", th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.transcript.update(raw);

        // Emit our CCS + Finished.
        let mut flight = Flight::new();
        let ccs_dgram = self.wrap_plain_record(ContentType::ChangeCipherSpec, &[0x01]);
        flight.push(ccs_dgram);
        // Bump our write epoch.
        self.write_crypter = self.pending_write_crypter.take();
        self.write_epoch = 1;
        self.write_seq_in_epoch = 0;

        let th2 = self.transcript.current_hash();
        let verify_data =
            finished_verify_data(HashAlg::Sha256, &master, b"server finished", th2.as_slice());
        let fin_body: Vec<u8> = verify_data.to_vec();
        // Transcript update with TLS-shaped Finished.
        let mut fin_tls = Vec::with_capacity(16);
        fin_tls.push(hs_type::FINISHED);
        fin_tls.extend_from_slice(&[0, 0, 12]);
        fin_tls.extend_from_slice(&fin_body);
        self.transcript.update(&fin_tls);
        // DTLS handshake fragment with the next out_msg_seq.
        let msg_seq = self.out_msg_seq;
        self.out_msg_seq += 1;
        let mut fin_frag_buf = Vec::new();
        write_message(
            &mut fin_frag_buf,
            hs_type::FINISHED,
            msg_seq,
            &fin_body,
            DEFAULT_MAX_FRAGMENT,
        );
        let fin_dgram = self.encrypt_record_dtls(ContentType::Handshake, &fin_frag_buf)?;
        flight.push(fin_dgram);

        self.send_flight(flight);
        self.state = State::Connected;
        Ok(())
    }
}

/// Decoded DTLS ClientHello body (the bytes after the 4-byte TLS handshake
/// header).
struct ParsedDtlsClientHello {
    #[allow(dead_code)]
    legacy_version: u16,
    random: Random,
    #[allow(dead_code)]
    session_id: Vec<u8>,
    cookie: Vec<u8>,
    cipher_suites: Vec<CipherSuite>,
    extensions: Vec<(ExtensionType, Vec<u8>)>,
}

fn parse_dtls_client_hello(body: &[u8]) -> Result<ParsedDtlsClientHello, Error> {
    let mut c = ReadCursor::new(body);
    let legacy_version = c.u16()?;
    let mut random: Random = [0u8; 32];
    let r = c.take(32)?;
    random.copy_from_slice(r);
    let session_id = c.vec_u8()?.to_vec();
    let cookie = c.vec_u8()?.to_vec();
    let cs_bytes = c.vec_u16()?;
    if cs_bytes.len() % 2 != 0 {
        return Err(Error::Decode);
    }
    let mut cs_cursor = ReadCursor::new(cs_bytes);
    let mut cipher_suites = Vec::with_capacity(cs_bytes.len() / 2);
    while !cs_cursor.is_empty() {
        cipher_suites.push(CipherSuite(cs_cursor.u16()?));
    }
    let _compression = c.vec_u8()?;
    let ext_bytes = c.vec_u16()?;
    c.expect_empty()?;
    let extensions = parse_extensions(ext_bytes)?;
    Ok(ParsedDtlsClientHello {
        legacy_version,
        random,
        session_id,
        cookie,
        cipher_suites,
        extensions,
    })
}

fn parse_extensions(body: &[u8]) -> Result<Vec<(ExtensionType, Vec<u8>)>, Error> {
    let mut c = ReadCursor::new(body);
    let mut out = Vec::new();
    while !c.is_empty() {
        let ty = ExtensionType(c.u16()?);
        let data = c.vec_u16()?.to_vec();
        out.push((ty, data));
    }
    Ok(out)
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

fn build_certificate_msg(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut msg = alloc::vec![hs_type::CERTIFICATE];
    with_len_u24(&mut msg, |b| {
        with_len_u24(b, |list| {
            for cert in chain {
                with_len_u24(list, |c| c.extend_from_slice(cert));
            }
        });
    });
    msg
}

fn ecdsa_scheme_for(curve: CurveId) -> SignatureScheme {
    match curve {
        CurveId::P384 => SignatureScheme::ECDSA_SECP384R1_SHA384,
        CurveId::P521 => SignatureScheme::ECDSA_SECP521R1_SHA512,
        _ => SignatureScheme::ECDSA_SECP256R1_SHA256,
    }
}
