#![allow(dead_code, unreachable_pub)]

//! DTLS 1.2 server state machine (RFC 6347).
//!
//! Mirror of [`super::client12::DtlsClientConnection12`]. The server
//! consumes the first ClientHello, optionally responds with a
//! HelloVerifyRequest (RFC 6347 §4.2.1) so the client proves source-address
//! reachability before any state is allocated, then proceeds through the
//! TLS 1.2 ECDHE-ECDSA handshake under the DTLS record layer.

use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, CurveId};
use crate::hash::{Sha256, Sha384, Sha512};
use crate::rng::RngCore;
use crate::rsa::BoxedRsaPrivateKey;
use crate::signature_registry::SignaturePolicy;
use crate::tls::codec::extension as ext;
use crate::tls::codec::handshake12::{ClientKeyExchange, ServerKeyExchange, signed_message};
use crate::tls::codec::{
    CipherSuite, ExtensionType, NamedGroup, Random, ReadCursor, ServerHello, SignatureScheme,
    hs_type, with_len_u8, with_len_u24,
};
use crate::tls::conn::{SUITES_12, ServerKey, SigKind, SuiteParams12};
use crate::tls::crypto::Transcript;
use crate::tls::crypto::aead12::RecordCrypter12;
use crate::tls::crypto::prf::{
    extended_master_secret, finished_verify_data, key_block, master_secret, tls12_exporter,
};
use crate::tls::keylog::KeyLog;
use crate::tls::{ContentType, Error, ProtocolVersion};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use super::cookie::{CookieGenerator, build_ch_fingerprint};
use super::reassembly::{
    HandshakeFragment, MAX_HS_MSG_SEQ, Reassembler, read_fragment, write_message,
};
use super::record::{self, ParsedDtlsRecord};
use super::reliability::{Flight, Retransmit};
use super::replay::AntiReplayWindow;

#[allow(unused_imports)]
use crate::ct::ConstantTimeEq;

/// HelloVerifyRequest handshake type code (RFC 6347 §4.2.1).
const HS_HELLO_VERIFY_REQUEST: u8 = 3;

/// Default per-fragment payload size for outbound handshake messages.
const DEFAULT_MAX_FRAGMENT: usize = 1100;

/// Configuration for a DTLS 1.2 server.
pub(crate) struct ServerConfig12Internal {
    /// Certificate chain (leaf first).
    cert_chain: Vec<Vec<u8>>,
    /// Signing key. Matches TLS 1.2's scope: RSA-PSS or ECDSA. Other
    /// variants of [`ServerKey`] can be plumbed in but will fail at
    /// handshake time because no suite in `SUITES_12` matches them.
    key: ServerKey,
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
            key: ServerKey::Ecdsa(key),
            cookie_secret: None,
            require_cookie_exchange: true,
            signature_policy: SignaturePolicy::modern(),
            key_log: None,
        }
    }

    /// New configuration presenting `cert_chain` and signing with the RSA
    /// `key`. Drives the three `ECDHE-RSA-*` entries of `SUITES_12`; the
    /// signature scheme is `rsa_pss_rsae_sha256`. Mirrors the TLS 1.2
    /// server's `ServerConfig12::with_rsa`.
    pub fn with_rsa(cert_chain: Vec<Vec<u8>>, key: BoxedRsaPrivateKey) -> Self {
        Self {
            cert_chain,
            key: ServerKey::Rsa(key),
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
    ///
    /// # Warning: amplification / DoS vector
    ///
    /// With the cookie exchange off, a single spoofed-source ClientHello
    /// makes the server allocate per-connection state, perform an
    /// asymmetric signature, and emit its full multi-KB flight (SH +
    /// Certificate + ServerKeyExchange + ServerHelloDone) to an unverified
    /// address — well over 3x amplification toward a victim of the
    /// attacker's choosing (RFC 6347 §4.2.1). Never disable cookies on a
    /// server reachable from untrusted networks.
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

    /// Ephemeral X25519 ECDHE key, populated when [`Self::group`] is
    /// `X25519`.
    x25519: Option<X25519PrivateKey>,
    /// Ephemeral P-256 ECDHE key, populated when [`Self::group`] is
    /// `SECP256R1`.
    p256: Option<BoxedEcdhPrivateKey>,
    /// Ephemeral P-384 ECDHE key, populated when [`Self::group`] is
    /// `SECP384R1`.
    p384: Option<BoxedEcdhPrivateKey>,

    client_random: Option<Random>,
    server_random: Option<Random>,

    /// Negotiated cipher-suite parameters, pinned on the cookie-validated
    /// ClientHello (or the only CH when cookies are disabled).
    suite: Option<SuiteParams12>,
    /// Negotiated ECDHE group, pinned at suite-selection time. Preference
    /// order is X25519 > P-256 (mirrors the TLS 1.2 server in
    /// `src/tls/conn/server12.rs`).
    group: Option<NamedGroup>,

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
    /// True once the caller has driven the clock via [`Self::set_now`] /
    /// [`Self::on_timeout`]. Governs the cookie-clock fallback — see
    /// [`Self::cookie_now_minutes`].
    clock_driven: bool,

    /// RFC 7627 §5.1 — set when the client offered `extended_master_secret`
    /// and we echoed it. Drives the master-secret derivation choice.
    ems_negotiated: bool,
}

// The DTLS 1.2 master secret lives for the whole connection (exporters,
// Finished verification) — scrub it on drop so it does not linger in freed
// memory, same as the TLS 1.2 engine.
impl<R: RngCore> Drop for DtlsServerConnection12<R> {
    fn drop(&mut self) {
        if let Some(m) = self.master.as_mut() {
            crate::tls::conn::wipe(m);
        }
    }
}

impl<R: RngCore> DtlsServerConnection12<R> {
    /// Creates a server awaiting a ClientHello from `peer_addr`. `peer_addr`
    /// is the opaque identifier used by the cookie generator.
    pub(crate) fn new(config: Arc<ServerConfig12Internal>, peer_addr: Vec<u8>, rng: R) -> Self {
        // Don't pin the transcript hash yet: the negotiated suite (SHA-256
        // or SHA-384) is unknown until we parse the cookie-validated CH and
        // select from SUITES_12. `Transcript` buffers raw bytes; we call
        // `set_alg` once the suite is pinned.
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
            p384: None,
            client_random: None,
            server_random: None,
            suite: None,
            group: None,
            transcript: Transcript::new(),
            master: None,
            read_crypter: None,
            write_crypter: None,
            pending_read_crypter: None,
            pending_write_crypter: None,
            ccs_received: false,
            retransmit: Retransmit::new(),
            last_now: Duration::from_secs(0),
            clock_driven: false,
            ems_negotiated: false,
        }
    }

    /// Returns true once the handshake completes.
    pub fn is_handshake_complete(&self) -> bool {
        self.state == State::Connected
    }

    /// IANA cipher-suite identifier of the negotiated suite, or `None`
    /// until the cookie-validated ClientHello has pinned a suite from the
    /// 6-entry `SUITES_12` matrix (ECDHE-{ECDSA,RSA} × {AES-128-GCM,
    /// ChaCha20-Poly1305, AES-256-GCM-SHA384}). Both ECDSA and RSA-PSS
    /// signing keys are supported; matches the TLS 1.2 server's scope.
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.suite.map(|s| s.suite.0)
    }

    /// RFC 5705 §4 — DTLS 1.2 application-layer Exporter. Computes
    /// `PRF(master_secret, label, client_random ‖ server_random
    /// [‖ uint16(len(context)) ‖ context])`, matching TLS 1.2's exporter.
    /// `context = None` omits the length-prefixed context block;
    /// `context = Some(&[])` emits a zero-length context — the two outputs
    /// MUST differ per RFC 5705 §4. Returns `Err(InappropriateState)`
    /// before the handshake derives the master secret.
    pub fn tls_exporter(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let master = self.master.as_ref().ok_or(Error::InappropriateState)?;
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let cr = self.client_random.ok_or(Error::InappropriateState)?;
        let sr = self.server_random.ok_or(Error::InappropriateState)?;
        tls12_exporter(suite.hash, master, label, &cr, &sr, context, out);
        Ok(())
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

    /// Advances the connection's monotonic clock to `now`. Callers SHOULD
    /// invoke this (or [`Self::on_timeout`]) regularly so the cookie
    /// generator sees a current time. Idempotent in the rewind direction
    /// (older times are ignored).
    ///
    /// Cookie-clock contract: once this (or `on_timeout`) has been called,
    /// the caller's clock stamps and validates HelloVerifyRequest cookies.
    /// If the caller NEVER drives the clock, the server falls back to wall
    /// time under `std` so the cookie max-age bound (RFC 6347 §4.2.1)
    /// stays real; on `no_std` builds with no caller clock, cookies are
    /// issued and validated at `TS = 0` and therefore never expire — drive
    /// this method if cookie expiry matters there. Avoid switching from
    /// the never-driven mode to the caller-driven mode while a cookie
    /// exchange is in flight: a cookie stamped from one clock will not
    /// validate against the other.
    pub fn set_now(&mut self, now: Duration) {
        self.clock_driven = true;
        if now > self.last_now {
            self.last_now = now;
        }
    }

    /// Clock used to stamp / validate HelloVerifyRequest cookies, in
    /// minutes. Uses the caller-driven sans-I/O clock when the caller has
    /// ever advanced it; otherwise (under `std`) falls back to wall time so
    /// that with `last_now` stuck at 0 every cookie would not be issued AND
    /// validated at `TS = 0`, which would silently disable the 10-minute
    /// cookie max-age replay bound.
    fn cookie_now_minutes(&self) -> u32 {
        #[cfg(feature = "std")]
        if !self.clock_driven
            && let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        {
            return (d.as_secs() / 60) as u32;
        }
        (self.last_now.as_secs() / 60) as u32
    }

    /// Drives the retransmit machine. Any retransmitted datagrams land in
    /// `pop_outbound_datagrams`.
    pub fn on_timeout(&mut self, now: Duration) {
        self.clock_driven = true;
        self.last_now = now;
        match self.retransmit.on_timeout(now) {
            super::reliability::Action::Retransmit => {
                for dg in self.retransmit.flight_datagrams() {
                    self.out_dgrams.push(dg.clone());
                }
            }
            super::reliability::Action::GiveUp => {
                if self.state == State::Connected {
                    // A fully established connection must never self-close
                    // on a retransmit cap; drop the stale flight and stay
                    // Connected. Only an in-progress handshake times out.
                    self.retransmit.on_peer_response();
                } else {
                    self.state = State::Closed;
                }
            }
            super::reliability::Action::Idle => {}
        }
    }

    /// Feeds one incoming UDP datagram into the connection.
    pub fn feed_datagram(&mut self, datagram: &[u8]) -> Result<(), Error> {
        let mut off = 0usize;
        while off < datagram.len() {
            // Truncated trailing record, or a header whose declared length
            // is bogus (RecordOverflow): record framing is lost for the
            // rest of the datagram. RFC 6347 §4.1.2.7 requires invalid
            // records to be silently discarded — a single spoofed datagram
            // must never be fatal.
            let rec = match record::read_record(&datagram[off..]) {
                Ok(Some(rec)) => rec,
                Ok(None) | Err(_) => return Ok(()),
            };
            off += rec.len;
            self.process_record(rec)?;
        }
        Ok(())
    }

    /// Processes one DTLS record.
    ///
    /// Per RFC 6347 §4.1.2.7, records that fail record-layer sanity checks
    /// (bad version, wrong epoch, failed AEAD, unexpected content type) are
    /// SILENTLY discarded — they are trivially spoofable by an off-path
    /// attacker and must never be connection-fatal.
    fn process_record(&mut self, rec: ParsedDtlsRecord<'_>) -> Result<(), Error> {
        if rec.version != ProtocolVersion::DTLSv1_2 && rec.version != ProtocolVersion::DTLSv1_0 {
            // Unknown record version: silently discard.
            return Ok(());
        }
        if rec.epoch != self.read_epoch {
            return Ok(());
        }
        // Anti-replay pre-check: cheap rejection of duplicate / too-old
        // seq numbers. We deliberately DO NOT advance the window here —
        // an off-path attacker who can guess wire seq numbers could
        // otherwise burn slots in the window with packets that pass the
        // seq filter but fail AEAD verification, dropping legitimate
        // retransmits. The window is `mark`-ed only after the AEAD tag
        // verifies (below).
        if self.read_epoch >= 1 && !self.replay.check(rec.seq) {
            return Ok(());
        }
        match rec.content_type {
            ContentType::ChangeCipherSpec => {
                // CCS is plaintext (epoch 0, spoofable); every rejection
                // here is a silent drop (RFC 6347 §4.1.2.7).
                if rec.fragment != [0x01] {
                    return Ok(());
                }
                if self.ccs_received {
                    return Ok(());
                }
                let Some(c) = self.pending_read_crypter.take() else {
                    // CCS before the read keys exist (spoofed, or badly
                    // reordered): ignore — a real client retransmits.
                    return Ok(());
                };
                self.read_crypter = Some(c);
                self.ccs_received = true;
                self.read_epoch = 1;
                self.replay = AntiReplayWindow::new();
                Ok(())
            }
            ContentType::Handshake => {
                let plain: Vec<u8>;
                let authenticated;
                if self.read_epoch >= 1 {
                    let combined = ((self.read_epoch as u64) << 48) | rec.seq;
                    let Some(c) = self.read_crypter.as_ref() else {
                        return Ok(());
                    };
                    let Ok(p) = c.decrypt_dtls(combined, ContentType::Handshake, rec.fragment)
                    else {
                        // AEAD failure: silent drop (RFC 6347 §4.1.2.7) —
                        // a spoofed datagram must not kill the connection.
                        // The replay window was deliberately not advanced.
                        return Ok(());
                    };
                    // AEAD verified: now it's safe to commit to the window.
                    self.replay.mark(rec.seq);
                    plain = p;
                    authenticated = true;
                } else {
                    plain = rec.fragment.to_vec();
                    authenticated = false;
                }
                self.process_handshake_record(&plain, authenticated)
            }
            ContentType::ApplicationData => {
                if self.read_epoch < 1 {
                    // Plaintext application data is spoofable: silent drop.
                    return Ok(());
                }
                let combined = ((self.read_epoch as u64) << 48) | rec.seq;
                let Some(c) = self.read_crypter.as_ref() else {
                    return Ok(());
                };
                let Ok(plain) =
                    c.decrypt_dtls(combined, ContentType::ApplicationData, rec.fragment)
                else {
                    // AEAD failure: silent drop, window not advanced.
                    return Ok(());
                };
                // AEAD verified: commit to the window only now.
                self.replay.mark(rec.seq);
                self.app_in.extend_from_slice(&plain);
                Ok(())
            }
            ContentType::Alert => Ok(()),
            // Unknown / unexpected content type: silent discard.
            _ => Ok(()),
        }
    }

    /// Processes the handshake fragments in one record body.
    ///
    /// `authenticated` is true when the bytes came out of a successfully
    /// AEAD-verified record (epoch ≥ 1). Framing errors in unauthenticated
    /// (plaintext, epoch-0) records are attacker-spoofable and dropped
    /// silently; the same errors in authenticated records are genuine peer
    /// faults and stay fatal.
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
            // Pre-state-allocation cookie path: when we're still
            // awaiting the first or second CH and the reassembler hasn't
            // been built, parse the fragment as a single CH directly.
            // This path is plaintext, unauthenticated input — malformed
            // fragments are dropped silently rather than killing the
            // connection.
            if self.reassembler.is_none() {
                // Require complete, unfragmented CH for the cookie dance.
                if frag.msg_type != hs_type::CLIENT_HELLO {
                    return Ok(());
                }
                if frag.fragment_offset != 0 || (frag.fragment.len() as u32) != frag.total_length {
                    return Ok(());
                }
                let body = frag.fragment.to_vec();
                let msg_seq = frag.message_seq;
                off += consumed;
                if let Err(e) = self.handle_pre_state_client_hello(msg_seq, &body) {
                    // Everything on this path is unauthenticated, epoch-0,
                    // attacker-spoofable input (a forged cookie being the
                    // most reachable). Per RFC 6347 §4.1.2.7 these faults
                    // are silently dropped so a single spoofed datagram on
                    // the 4-tuple can never tear down a legitimate
                    // in-flight handshake. The one exception is the local
                    // fail-closed misconfiguration (cookie required but no
                    // `cookie_secret`), which fires identically for the
                    // genuine client and must stay loud.
                    if matches!(e, Error::InappropriateState) {
                        return Err(e);
                    }
                    return Ok(());
                }
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
            // The client's first post-cookie flight (ClientKeyExchange, and
            // optionally Certificate/CertificateVerify) arrives at epoch 0,
            // unauthenticated. A spoofed plaintext CKE that decodes to a bad
            // EC point would otherwise return Decode/IllegalParameter/
            // PeerMisbehaved fatally and abort a legitimate in-flight
            // handshake. On the unauthenticated path turn any reassembly/
            // dispatch fault into a silent drop, keeping only our own
            // `InappropriateState` misconfig fatal — mirroring the DTLS 1.3
            // server pre-cookie wrapper. The encrypted client Finished
            // (epoch ≥ 1, authenticated) keeps every error fatal.
            // `feed`/`pop_ready` advance `expected_msg_seq` BEFORE dispatch, so
            // on a silent drop we also rewind the reassembler: otherwise a
            // spoofed but well-framed message would pin `expected_msg_seq`
            // past the genuine one (same message_seq), which would then be
            // rejected as stale.
            let snapshot = self
                .reassembler
                .as_ref()
                .expect("reassembler built")
                .expected_msg_seq();
            let feeding = self
                .reassembler
                .as_mut()
                .expect("reassembler built")
                .feed(frag);
            if let Some((msg_type, body)) = feeding {
                match self.dispatch_one(msg_type, &body) {
                    Ok(()) => {}
                    Err(e) if authenticated || matches!(e, Error::InappropriateState) => {
                        return Err(e);
                    }
                    Err(_) => {
                        self.reassembler
                            .as_mut()
                            .expect("reassembler built")
                            .rewind_expected_msg_seq(snapshot);
                        return Ok(());
                    }
                }
            }
            // Drain any further already-buffered messages.
            loop {
                let snapshot = self
                    .reassembler
                    .as_ref()
                    .expect("reassembler built")
                    .expected_msg_seq();
                let popped = self
                    .reassembler
                    .as_mut()
                    .expect("reassembler built")
                    .pop_ready();
                match popped {
                    Some((msg_type, body)) => match self.dispatch_one(msg_type, &body) {
                        Ok(()) => {}
                        Err(e) if authenticated || matches!(e, Error::InappropriateState) => {
                            return Err(e);
                        }
                        Err(_) => {
                            self.reassembler
                                .as_mut()
                                .expect("reassembler built")
                                .rewind_expected_msg_seq(snapshot);
                            return Ok(());
                        }
                    },
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
        // F3: bound the client-supplied `message_seq` before the reassembler
        // seeding loop below (`for s in 0..=msg_seq`). `message_seq` is not
        // covered by the cookie fingerprint, so even a client that completes
        // the HelloVerifyRequest roundtrip can drive this loop; an oversized
        // value would otherwise mean tens of thousands of synthetic-message
        // allocate/serialize/parse/feed cycles.
        if msg_seq > MAX_HS_MSG_SEQ {
            return Err(Error::IllegalParameter);
        }
        // Decode the DTLS-flavoured ClientHello body.
        let parsed = parse_dtls_client_hello(body)?;

        // Fail closed: a server that asks for cookie enforcement but never
        // supplied a `cookie_secret` MUST NOT silently degrade to the
        // no-cookie path (which would emit the full, expensive server flight
        // to an unverified, possibly-spoofed source — an amplification +
        // asymmetric-signature DoS). Reject before any flight is generated.
        if self.config.require_cookie_exchange && self.config.cookie_secret.is_none() {
            return Err(Error::InappropriateState);
        }
        let cookie_required = self.config.require_cookie_exchange;
        let first_attempt = parsed.cookie.is_empty();

        // Bind the cookie MAC to the security-critical CH fields. An on-path
        // attacker that mutates CH2's cipher_suites / supported_groups /
        // supported_versions between HVR and the second flight will fail
        // cookie validation — closing the downgrade primitive described in
        // RFC 9147 §5.1 (and equivalent for DTLS 1.2's HVR cookie).
        let fp = ch_fingerprint_dtls12(&parsed);

        if cookie_required && first_attempt {
            // Emit HelloVerifyRequest with a freshly computed cookie. The
            // cookie binds (peer_addr, client_random, ch_fingerprint, TS) —
            // *no* per-connection state is allocated here; we rely on the
            // client echoing the cookie in CH2 to commit to the same CH
            // content.
            let secret = self
                .config
                .cookie_secret
                .as_ref()
                .ok_or(Error::InappropriateState)?;
            let cg = CookieGenerator::new(*secret);
            let now_min = self.cookie_now_minutes();
            let cookie = cg.generate(&self.peer_addr, &parsed.random, &fp, now_min);
            self.emit_hello_verify_request(&cookie)?;
            self.state = State::WaitSecondClientHello;
            // We deliberately do NOT add this CH or HVR to a transcript
            // and we keep `reassembler` None so the next CH also enters
            // this pre-state path (RFC 6347 §4.2.1). The msg_seq of this
            // pre-cookie CH is intentionally NOT stored — see DTLS-4.
            let _ = msg_seq;
            return Ok(());
        }

        if cookie_required && !first_attempt {
            // Validate the cookie. The CH fingerprint must match the one
            // that was bound when the cookie was issued, otherwise the
            // server treats this as if the cookie were forged.
            let secret = self
                .config
                .cookie_secret
                .as_ref()
                .ok_or(Error::InappropriateState)?;
            let cg = CookieGenerator::new(*secret);
            let now_min = self.cookie_now_minutes();
            if !cg.validate(
                &self.peer_addr,
                &parsed.random,
                &fp,
                now_min,
                &parsed.cookie,
            ) {
                return Err(Error::IllegalParameter);
            }
        }

        // Cookie validated (or skipped): proceed with the handshake. The
        // transcript starts with this CH per RFC 6347 §4.2.1. Buffer the
        // CH bytes BEFORE pinning the transcript hash — `Transcript`
        // accumulates raw bytes and applies the hash on demand once
        // `set_alg` is called, so the order of update / set_alg here is
        // irrelevant as long as set_alg happens before `current_hash`.
        self.client_random = Some(parsed.random);
        let mut tls_ch = Vec::with_capacity(4 + body.len());
        tls_ch.push(hs_type::CLIENT_HELLO);
        let n = body.len() as u32;
        tls_ch.push(((n >> 16) & 0xff) as u8);
        tls_ch.push(((n >> 8) & 0xff) as u8);
        tls_ch.push((n & 0xff) as u8);
        tls_ch.extend_from_slice(body);
        self.transcript.update(&tls_ch);

        // Suite selection — mirror the TLS 1.2 server (`src/tls/conn/server12.rs`):
        // walk SUITES_12 in OUR preference order, picking the first entry the
        // client offered whose signature half matches the configured key's
        // family. RSA and ECDSA keys are both supported; an Ed25519 / ML-DSA
        // server key can be plumbed in but will not match any suite.
        let sig_kind = sig_kind_for_key(&self.config.key);
        let suite = SUITES_12
            .iter()
            .copied()
            .find(|p| parsed.cipher_suites.contains(&p.suite) && p.sig_kind == sig_kind)
            .ok_or(Error::HandshakeFailure)?;
        // Pin the transcript hash now that the suite is known.
        self.transcript.set_alg(suite.hash);
        self.suite = Some(suite);
        // Pick the negotiated ECDHE group. Preference is X25519 > P-256,
        // mirroring `src/tls/conn/server12.rs::on_client_hello_initial`.
        let groups_body = ext::find(&parsed.extensions, ExtensionType::SUPPORTED_GROUPS)
            .ok_or(Error::HandshakeFailure)?;
        let groups = parse_supported_groups(groups_body)?;
        let group = if groups.contains(&NamedGroup::X25519) {
            NamedGroup::X25519
        } else if groups.contains(&NamedGroup::SECP256R1) {
            NamedGroup::SECP256R1
        } else if groups.contains(&NamedGroup::SECP384R1) {
            NamedGroup::SECP384R1
        } else {
            return Err(Error::HandshakeFailure);
        };
        self.group = Some(group);

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

        // Generate the ECDHE key share for the negotiated group.
        let our_point: Vec<u8> = match group {
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
            NamedGroup::SECP384R1 => {
                let sk = BoxedEcdhPrivateKey::generate(CurveId::P384, &mut self.rng);
                let pk = sk.public_key().to_sec1();
                self.p384 = Some(sk);
                pk
            }
            _ => return Err(Error::HandshakeFailure),
        };

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
            cipher_suite: suite.suite,
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

        // ServerKeyExchange. The SKE signature hash tracks the key's curve
        // for ECDSA (RFC 5246 §7.4.1.4.1 lets the server pick any acceptable
        // scheme independent of the PRF / suite hash); RSA-PSS uses
        // `rsa_pss_rsae_sha256` regardless of the suite hash. Mirrors
        // `src/tls/conn/server12.rs::send_server_key_exchange`.
        let cr = self.client_random.expect("set above");
        let to_sign = signed_message(&cr, &sr, group, &our_point);
        let scheme = signature_scheme(&self.config.key);
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
            // The public DTLS-1.2 server constructors (`with_ecdsa`,
            // `with_rsa`) only build RSA / ECDSA server keys, so other
            // variants are unreachable. Be explicit.
            _ => return Err(Error::HandshakeFailure),
        };
        let ske = ServerKeyExchange {
            group,
            point: our_point,
            scheme,
            signature,
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
        // Refuse to reuse an AEAD nonce: the nonce is `epoch‖seq`, so cap the
        // per-epoch record count well below the 48-bit field (see
        // `record::MAX_RECORDS_PER_EPOCH`). Connection-fatal — no rekey path.
        record::check_seq_cap(self.write_seq_in_epoch)?;
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
        // RFC 6347 §4.2.4: receipt of the client's responding flight
        // implicitly acknowledges our ServerHello..ServerHelloDone flight.
        // Cancel its retransmit timer (mirrors the client's
        // `on_server_hello`); leaving it armed would keep re-emitting the
        // flight on every backoff step.
        self.retransmit.on_peer_response();
        let cke = ClientKeyExchange::decode(body)?;
        let group = self.group.ok_or(Error::InappropriateState)?;
        // Complete ECDHE on the negotiated group and derive the premaster.
        // Mirrors `src/tls/conn/server12.rs::on_client_key_exchange`.
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
            NamedGroup::SECP384R1 => {
                let sk = self.p384.as_ref().ok_or(Error::InappropriateState)?;
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P384, &cke.point)
                    .map_err(|_| Error::Decode)?;
                sk.diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?
            }
            _ => return Err(Error::HandshakeFailure),
        };
        let cr = self.client_random.expect("set");
        let sr = self.server_random.expect("set");

        // Feed CKE into the transcript BEFORE deriving the master so the
        // EMS session_hash (RFC 7627 §4) spans CH..CKE inclusive.
        self.transcript.update(raw);

        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let master = if self.ems_negotiated {
            let sh = self.transcript.current_hash();
            extended_master_secret(suite.hash, &premaster, sh.as_slice())
        } else {
            master_secret(suite.hash, &premaster, &cr, &sr)
        };
        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log("CLIENT_RANDOM", &cr, &master);
        }
        // key_block: c_key || s_key || c_iv(4) || s_iv(4). The +8 is two
        // 4-byte salts for the GCM/ChaCha IV; the key half scales with
        // suite.key_len (16 bytes for AES-128, 32 for AES-256/ChaCha20).
        let mut kb = alloc::vec![0u8; 2 * suite.key_len + 8];
        key_block(suite.hash, &master, &sr, &cr, &mut kb);
        let (c_key, rest) = kb.split_at(suite.key_len);
        let (s_key, rest) = rest.split_at(suite.key_len);
        let mut c_salt = [0u8; 4];
        c_salt.copy_from_slice(&rest[..4]);
        let mut s_salt = [0u8; 4];
        s_salt.copy_from_slice(&rest[4..8]);
        self.pending_read_crypter = Some(RecordCrypter12::new(suite.aead, c_key, c_salt));
        self.pending_write_crypter = Some(RecordCrypter12::new(suite.aead, s_key, s_salt));
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
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let th = self.transcript.current_hash();
        let expected = finished_verify_data(suite.hash, &master, b"client finished", th.as_slice());
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
            finished_verify_data(suite.hash, &master, b"server finished", th2.as_slice());
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

        // This CCS + Finished is the LAST flight of the handshake: no
        // responding flight from the client will ever arrive to cancel a
        // retransmit timer, so we deliberately do NOT register it with the
        // retransmit machine (RFC 6347 §4.2.4 puts the last-flight sender
        // in the FINISHED state, where retransmission is triggered by
        // seeing the peer re-send ITS flight — not by a timer). Arming the
        // timer here would blindly re-emit the flight on every backoff step
        // and previously GiveUp-closed a perfectly healthy connection ~2
        // minutes after establishment.
        for dg in &flight.datagrams {
            self.out_dgrams.push(dg.clone());
        }
        self.retransmit.on_peer_response();
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

/// Builds a cookie-binding fingerprint from a parsed DTLS 1.2 CH. Covers
/// the negotiation-deciding wire fields so a CH2 with rewritten cipher
/// suites / supported_groups / supported_versions fails cookie validation.
fn ch_fingerprint_dtls12(parsed: &ParsedDtlsClientHello) -> Vec<u8> {
    let mut cs_be = Vec::with_capacity(parsed.cipher_suites.len() * 2);
    for cs in &parsed.cipher_suites {
        cs_be.extend_from_slice(&cs.0.to_be_bytes());
    }
    let groups = ext::find(&parsed.extensions, ExtensionType::SUPPORTED_GROUPS);
    let versions = ext::find(&parsed.extensions, ExtensionType::SUPPORTED_VERSIONS);
    // DTLS 1.2 cookie path doesn't carry `key_share`; pass an empty slot.
    build_ch_fingerprint(&cs_be, groups, versions, &[])
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

/// Maps the configured server key to the IANA `SignatureScheme` we
/// advertise in `ServerKeyExchange.signature_algorithm`. Mirrors
/// `src/tls/conn/server12.rs::signature_scheme`.
///
/// TLS 1.2 (RFC 5246 §7.4.1.4.1) allows an independent (hash, signature)
/// pair on the SKE — separate from the PRF / transcript hash fixed by the
/// suite. For ECDSA the scheme tracks the curve (RFC 8446 §4.2.3 / RFC 8447
/// IANA registry); for RSA we use `rsa_pss_rsae_sha256`, the modern default
/// for TLS 1.2 + 1.3 interop.
fn signature_scheme(key: &ServerKey) -> SignatureScheme {
    match key {
        ServerKey::Rsa(_) => SignatureScheme::RSA_PSS_RSAE_SHA256,
        ServerKey::Ecdsa(k) => match k.curve() {
            CurveId::P256 | CurveId::Secp256k1 | CurveId::Sm2p256v1 | CurveId::BrainpoolP256r1 => {
                SignatureScheme::ECDSA_SECP256R1_SHA256
            }
            CurveId::P384 | CurveId::BrainpoolP384r1 => SignatureScheme::ECDSA_SECP384R1_SHA384,
            CurveId::P521 | CurveId::BrainpoolP512r1 => SignatureScheme::ECDSA_SECP521R1_SHA512,
        },
        // Unreachable through the public constructors but the compiler
        // requires the match to be total.
        _ => SignatureScheme::RSA_PSS_RSAE_SHA256,
    }
}

/// Which signature family the configured server key belongs to. Drives suite
/// negotiation: an RSA key only matches the three `ECDHE-RSA-*` entries of
/// `SUITES_12`; an ECDSA key only matches the three `ECDHE-ECDSA-*` entries.
/// Mirrors `src/tls/conn/server12.rs::sig_kind`.
fn sig_kind_for_key(key: &ServerKey) -> SigKind {
    match key {
        ServerKey::Rsa(_) => SigKind::Rsa,
        ServerKey::Ecdsa(_) => SigKind::Ecdsa,
        // Other variants are inhabited by the shared `ServerKey` enum but
        // are unreachable through the public DTLS-1.2 constructors. Default
        // to a kind that will fail to match any of our suites.
        _ => SigKind::Rsa,
    }
}

#[cfg(test)]
mod f3_msg_seq_tests {
    //! F3 regression: the DTLS 1.2 server must reject a ClientHello whose
    //! `message_seq` is implausibly large before the reassembler-seeding loop
    //! (`for s in 0..=msg_seq`). `message_seq` is not bound by the cookie
    //! fingerprint, so a client that completed the HelloVerifyRequest
    //! roundtrip could otherwise still drive tens of thousands of cycles.
    //! The rejection is a SILENT DROP (`feed_datagram` returns `Ok`): the
    //! input is trivially spoofable, so a fatal error would hand an off-path
    //! attacker a one-datagram kill switch for in-flight handshakes
    //! (RFC 6347 §4.1.2.7).
    use super::*;
    use crate::dtls::{ClientConfig12Internal, DtlsClientConnection12, DtlsServerConnection12};
    use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::tls::pki::RootCertStore;
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    fn make_server_cfg() -> (ServerConfig12Internal, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"f3-dtls12-key", b"nonce", &[]);
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
            ServerConfig12Internal::with_ecdsa(alloc::vec![der.clone()], key)
                .require_cookie_exchange(false),
            der,
        )
    }

    fn make_client(server_cert: &[u8]) -> DtlsClientConnection12 {
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert.to_vec()).unwrap();
        let cfg = ClientConfig12Internal::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        let mut crng = HmacDrbg::<Sha256>::new(b"f3-dtls12-client", b"nonce", &[]);
        DtlsClientConnection12::new(cfg, b"client-addr".to_vec(), &mut crng)
    }

    fn client_hello_datagram() -> Vec<u8> {
        let (_, cert) = make_server_cfg();
        let mut client = make_client(&cert);
        let mut out = client.pop_outbound_datagrams();
        out.remove(0)
    }

    fn new_server() -> DtlsServerConnection12<HmacDrbg<Sha256>> {
        let (cfg, _) = make_server_cfg();
        let srng = HmacDrbg::<Sha256>::new(b"f3-dtls12-server", b"nonce", &[]);
        DtlsServerConnection12::new(Arc::new(cfg), b"client-addr".to_vec(), srng)
    }

    /// Patch the 16-bit `message_seq` of the first handshake fragment. Record
    /// header is 13 bytes; `message_seq` sits 4 bytes into the fragment.
    fn patch_message_seq(dgram: &mut [u8], seq: u16) {
        const MSG_SEQ_OFF: usize = 13 + 4;
        dgram[MSG_SEQ_OFF] = (seq >> 8) as u8;
        dgram[MSG_SEQ_OFF + 1] = seq as u8;
    }

    #[test]
    fn oversized_message_seq_is_silently_dropped_without_giant_loop() {
        let mut dgram = client_hello_datagram();
        patch_message_seq(&mut dgram, 0xFFFF);
        let mut server = new_server();
        // Spoofable epoch-0 input: dropped, never fatal.
        assert_eq!(server.feed_datagram(&dgram), Ok(()));
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
        let (cfg, cert) = make_server_cfg();
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"f3-dtls12-ok", b"nonce", &[]);
        let mut server = DtlsServerConnection12::new(Arc::new(cfg), b"client-addr".to_vec(), srng);
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
