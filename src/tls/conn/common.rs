//! The transport-agnostic ("sans-I/O") connection core shared by both roles.
//!
//! [`ConnectionCore`] owns the record layer (framing, optional AEAD
//! protection), the handshake-message reassembly buffer, the transcript hash,
//! and the inbound/outbound byte buffers. It never touches a socket: callers
//! feed it received bytes with [`read_tls`](ConnectionCore::read_tls) and drain
//! bytes to transmit with [`write_tls`](ConnectionCore::write_tls). The
//! role-specific state machines (client/server) drive it by pulling decoded
//! messages and emitting handshake messages.

use super::super::codec::{ParsedRecord, is_legal_record_version, read_record, write_record};
use super::super::crypto::{RecordCrypter, Transcript};
use crate::tls::{Alert, AlertDescription, ContentType, Error, ProtocolVersion};
use alloc::vec::Vec;

/// Maximum bytes the handshake-message reassembly buffer is allowed to hold
/// at once. The TLS record layer caps a single record's plaintext at
/// 2¹⁴ + 256 bytes, but a handshake message may legally span many records —
/// its own 3-byte length field allows up to 2²⁴ − 1 ≈ 16 MiB. Without a
/// ceiling, a peer that streams a giant length-claim or a slow drip of
/// fragments can grow `hs_pending` without bound and pin memory.
///
/// 128 KiB comfortably covers a real-world chain (4–5 X.509 certs of a few
/// kilobytes each, an ML-DSA-87 signature at ~4.6 KiB, a hybrid ML-KEM
/// keyshare blob) with margin to spare, and is far below what an oversized
/// handshake message could justify.
pub(crate) const MAX_HANDSHAKE_REASSEMBLY: usize = 128 * 1024;

/// A decoded inbound message handed to the state machine.
pub(crate) enum Incoming {
    /// A complete handshake message, including its 4-byte header.
    Handshake(Vec<u8>),
    /// Application data arrived (the bytes are buffered for the reader).
    /// The payload is the plaintext length the peer just consumed under the
    /// current read key; the state machine uses this to enforce the
    /// `max_early_data_size` budget on 0-RTT records (RFC 8446 §4.2.10).
    ApplicationData(usize),
    /// An alert from the peer.
    Alert(Alert),
}

/// The shared record-layer / transcript / buffering core.
pub(crate) struct ConnectionCore {
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    /// Reassembly buffer for handshake-message bytes spanning records.
    hs_pending: Vec<u8>,
    /// Decrypted application data awaiting the application.
    app_in: Vec<u8>,
    /// Decrypted 0-RTT early data awaiting the application, kept strictly
    /// separate from `app_in`: early data is replayable by an active
    /// attacker (RFC 8446 §8 / appendix E.5), so applications must be able
    /// to quarantine it. Filled only while `early_data_routing` is set.
    early_in: Vec<u8>,
    /// When true, inner `ApplicationData` plaintext is routed to
    /// `early_in` instead of `app_in`. The server-side state machine sets
    /// this while the client-early-traffic read key is installed (0-RTT
    /// accepted, EndOfEarlyData not yet received) and clears it when the
    /// read key rotates to the client-handshake key.
    early_data_routing: bool,
    read: Option<RecordCrypter>,
    write: Option<RecordCrypter>,
    pub(crate) transcript: Transcript,
    sent_close_notify: bool,
    /// RFC 8446 §5: ChangeCipherSpec records are only valid in the
    /// middlebox-compat window between the first ClientHello and the peer's
    /// `Finished`. The role-specific state machines call `close_ccs_window`
    /// once they reach Connected.
    ccs_window_open: bool,
    /// Peer-advertised `record_size_limit` (RFC 8449), bounding the
    /// plaintext fragment we may send them. `None` means "unbounded" (default
    /// TLS 1.3 cap of 2¹⁴).
    peer_record_size_limit: Option<u16>,
    /// Gates buffering of decrypted inner `ApplicationData` into `app_in`.
    /// Set by the state machines when the handshake completes. Before that
    /// the peer is not authenticated (under mTLS it may not have sent
    /// `Certificate`/`CertificateVerify` yet), so plaintext must never reach
    /// `take_received` even transiently — an application draining plaintext
    /// on the error path would otherwise read unauthenticated bytes.
    app_data_allowed: bool,
    /// Sticky write-side failure. `emit_record` cannot return a `Result`
    /// (`send_alert` / `send_close_notify` / `emit_handshake` are infallible
    /// by construction), so a record we failed to protect — in practice
    /// `TooManyRecords` once the per-key sequence cap is hit — latches here
    /// and the engines surface it instead of silently transmitting nothing.
    write_error: Option<Error>,
    /// RFC 8446 §4.2.10 "skip rejected early data": while set, records that
    /// fail the AEAD check are discarded (without consuming a read sequence
    /// number) rather than failing the connection, up to this many remaining
    /// ciphertext bytes. Armed by the server when it declines a 0-RTT offer
    /// the client made; cleared by the first record that deprotects.
    skip_early_data: Option<usize>,
}

impl ConnectionCore {
    pub(crate) fn new() -> Self {
        ConnectionCore {
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            hs_pending: Vec::new(),
            app_in: Vec::new(),
            early_in: Vec::new(),
            early_data_routing: false,
            read: None,
            write: None,
            transcript: Transcript::new(),
            sent_close_notify: false,
            ccs_window_open: true,
            peer_record_size_limit: None,
            app_data_allowed: false,
            write_error: None,
            skip_early_data: None,
        }
    }

    /// Allows (or forbids) buffering of received application plaintext. The
    /// state machines enable this on the transition to `Connected`; see the
    /// `app_data_allowed` field.
    pub(crate) fn set_app_data_allowed(&mut self, allowed: bool) {
        self.app_data_allowed = allowed;
    }

    /// `Err(..)` if a previous `emit_record` failed. Engines call this from
    /// `send_application_data` / `process_new_packets` so a caller learns the
    /// record was not transmitted instead of seeing a bogus `Ok(())`. The
    /// error is sticky: the record stream has a gap, so the connection cannot
    /// meaningfully continue.
    pub(crate) fn check_write_error(&self) -> Result<(), Error> {
        match &self.write_error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    /// The number of records already emitted under the current write key, or
    /// `None` while the record layer is still in the clear. Drives the
    /// automatic `KeyUpdate` before the per-key cap (RFC 8446 §5.5).
    pub(crate) fn write_seq(&self) -> Option<u64> {
        self.write.as_ref().map(|c| c.seq())
    }

    /// Arms the RFC 8446 §4.2.10 "skip rejected early data" mode with a
    /// ciphertext-byte budget: records that fail to deprotect are discarded
    /// instead of killing the connection until either one deprotects
    /// (the client's real flight under the handshake key) or the budget runs
    /// out. Without this a server that declines a 0-RTT offer would hard-fail
    /// every intended 1-RTT fallback.
    pub(crate) fn begin_skip_early_data(&mut self, budget: usize) {
        self.skip_early_data = Some(budget);
    }

    /// Whether the "skip rejected early data" window is still open (test and
    /// diagnostic hook).
    #[cfg(test)]
    pub(crate) fn skipping_early_data(&self) -> bool {
        self.skip_early_data.is_some()
    }

    /// Test hook: fast-forward the write-side record sequence counter.
    #[cfg(test)]
    pub(crate) fn set_write_seq_for_test(&mut self, seq: u64) {
        if let Some(c) = self.write.as_mut() {
            c.set_seq_for_test(seq);
        }
    }

    /// Sets the peer-advertised record-size limit (RFC 8449); subsequent
    /// `send_application_data` calls split into records of at most
    /// `limit - 1` plaintext bytes (the extra byte is the inner content type).
    pub(crate) fn set_peer_record_size_limit(&mut self, limit: u16) {
        self.peer_record_size_limit = Some(limit);
    }

    /// Called by the role-specific state machine when the handshake completes.
    /// After this, any further `ChangeCipherSpec` from the peer is treated as
    /// a protocol violation.
    pub(crate) fn close_ccs_window(&mut self) {
        self.ccs_window_open = false;
    }

    /// Feeds received TLS bytes into the input buffer.
    pub(crate) fn read_tls(&mut self, bytes: &[u8]) {
        self.inbuf.extend_from_slice(bytes);
    }

    /// Removes and returns all bytes queued for transmission.
    pub(crate) fn write_tls(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outbuf)
    }

    /// Whether there are bytes queued for transmission.
    pub(crate) fn wants_write(&self) -> bool {
        !self.outbuf.is_empty()
    }

    /// Installs the inbound (read) record-protection keys.
    pub(crate) fn set_read(&mut self, crypter: RecordCrypter) {
        self.read = Some(crypter);
    }

    /// Installs the outbound (write) record-protection keys.
    pub(crate) fn set_write(&mut self, crypter: RecordCrypter) {
        self.write = Some(crypter);
    }

    /// Drains any received application plaintext. Never includes 0-RTT
    /// early data — that is quarantined in its own buffer (see
    /// [`Self::take_early_data`]).
    pub(crate) fn take_received(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app_in)
    }

    /// Drains any received (accepted) 0-RTT early-data plaintext. The bytes
    /// were protected under `client_early_traffic_secret` and are replayable
    /// by an active attacker; callers must treat them accordingly.
    pub(crate) fn take_early_data(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.early_in)
    }

    /// Selects where inner `ApplicationData` plaintext lands: `early_in`
    /// (while the 0-RTT read key is installed) or `app_in` (otherwise).
    pub(crate) fn set_early_data_routing(&mut self, enabled: bool) {
        self.early_data_routing = enabled;
    }

    /// Updates the transcript with a handshake message and frames it for
    /// sending (encrypted if write keys are installed, else as plaintext).
    ///
    /// Once the transcript is sealed (see `Transcript::seal`, called at the
    /// `Connected` transition) the update is a no-op: post-handshake messages
    /// — `KeyUpdate`, `NewSessionTicket` — are not part of any transcript
    /// hash this code computes, and appending them would let a peer grow our
    /// heap without bound, five bytes per `KeyUpdate`, for the life of the
    /// connection.
    pub(crate) fn emit_handshake(&mut self, message: Vec<u8>) {
        self.transcript.update(&message);
        self.emit_record(ContentType::Handshake, &message);
    }

    /// QUIC mode (RFC 9001): updates the transcript with the bytes that would
    /// otherwise be passed to [`Self::emit_handshake`], but does NOT emit a
    /// record. The QUIC layer carries the message in CRYPTO frames instead;
    /// the engine only needs the transcript fed for `Finished` MAC agreement.
    // Used by the QUIC engine path (engines call this in `EngineMode::Quic`);
    // unreferenced in TLS / DTLS builds today.
    #[allow(dead_code)]
    pub(crate) fn transcript_only(&mut self, message: &[u8]) {
        self.transcript.update(message);
    }

    /// QUIC mode: feed reassembled CRYPTO-frame handshake bytes into the
    /// engine's inbound handshake-message reassembly buffer.
    ///
    /// In QUIC mode the record path is bypassed entirely — the QUIC layer
    /// hands the engine raw handshake bytes (already decrypted and
    /// reassembled across packets) and the engine pops complete handshake
    /// messages from `hs_pending` exactly the same way it would after a
    /// record-layer decrypt in TLS mode.
    // Used by the QUIC engine path (engines call this in `EngineMode::Quic`);
    // unreferenced in TLS / DTLS builds today.
    #[allow(dead_code)]
    pub(crate) fn quic_feed_handshake(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.append_handshake_bytes(bytes)
    }

    /// Appends handshake-message bytes to the reassembly buffer, enforcing
    /// [`MAX_HANDSHAKE_REASSEMBLY`]. A peer that streams a giant length-claim
    /// or fragments without ever completing a message would otherwise grow
    /// `hs_pending` without bound; reject with `RecordOverflow` instead.
    fn append_handshake_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.hs_pending.len().saturating_add(bytes.len()) > MAX_HANDSHAKE_REASSEMBLY {
            return Err(Error::RecordOverflow);
        }
        self.hs_pending.extend_from_slice(bytes);
        Ok(())
    }

    /// Sends a (plaintext) ChangeCipherSpec for middlebox compatibility.
    pub(crate) fn emit_ccs(&mut self) {
        write_record(
            &mut self.outbuf,
            ContentType::ChangeCipherSpec,
            ProtocolVersion::TLSv1_2,
            &[1],
        );
    }

    /// Sends application data (requires write keys to be installed). If the
    /// peer has advertised a `record_size_limit` smaller than `data.len()`
    /// (or the default 2¹⁴), the data is fragmented into multiple records.
    pub(crate) fn send_application_data(&mut self, data: &[u8]) {
        // Cap = min(peer_limit - 1, 2^14). The `-1` reserves room for the
        // inner content-type byte per RFC 8449 §4.
        let cap = self
            .peer_record_size_limit
            .map(|l| (l - 1) as usize)
            .unwrap_or(1 << 14);
        let cap = cap.min(1 << 14);
        if data.len() <= cap {
            self.emit_record(ContentType::ApplicationData, data);
        } else {
            for chunk in data.chunks(cap) {
                self.emit_record(ContentType::ApplicationData, chunk);
            }
        }
    }

    /// Sends a fatal alert.
    pub(crate) fn send_alert(&mut self, description: AlertDescription) {
        let body = [2, description.as_u8()]; // level = fatal
        self.emit_record(ContentType::Alert, &body);
    }

    /// Queues a `close_notify` (graceful shutdown, warning level).
    pub(crate) fn send_close_notify(&mut self) {
        if !self.sent_close_notify {
            self.sent_close_notify = true;
            let body = [1, AlertDescription::CloseNotify.as_u8()];
            self.emit_record(ContentType::Alert, &body);
        }
    }

    pub(crate) fn emit_record(&mut self, ct: ContentType, payload: &[u8]) {
        match &mut self.write {
            Some(crypter) => match crypter.encrypt(ct, payload) {
                Ok(rec) => self.outbuf.extend_from_slice(&rec),
                Err(e) => {
                    // The only failures here are `TooManyRecords` (the
                    // per-key sequence cap — the engines pre-empt it with an
                    // automatic `KeyUpdate`, but a peer that never lets us
                    // rekey can still get here) and `RecordOverflow` (a
                    // caller failed to fragment). The record is NOT on the
                    // wire, so silently returning would leave
                    // `send_application_data` / `send_close_notify` as
                    // no-ops that still report success. Latch the error so
                    // the engines can surface it.
                    self.write_error.get_or_insert(e);
                }
            },
            None => write_record(&mut self.outbuf, ct, ProtocolVersion::TLSv1_2, payload),
        }
    }

    /// Pulls the next decoded message, or `Ok(None)` if more bytes are needed.
    ///
    /// Reassembles handshake messages across records, decrypts protected
    /// records once read keys are installed, and silently drops the middlebox
    /// ChangeCipherSpec records.
    pub(crate) fn next_message(&mut self) -> Result<Option<Incoming>, Error> {
        loop {
            // A complete buffered handshake message takes priority.
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
            // RFC 8446 §5.1: every record header carries `legacy_version`
            // 0x0303, but for compatibility with peers that emit 0x0301 on the
            // initial ClientHello we accept 0x0301..=0x0303. Anything else is
            // an SSL 3.0 / unknown downgrade attempt.
            if !is_legal_record_version(version) {
                return Err(Error::UnsupportedVersion);
            }
            let fragment = fragment.to_vec();
            self.inbuf.drain(..len);

            match content_type {
                ContentType::ChangeCipherSpec => {
                    // RFC 8446 §5: must be exactly `[0x01]`, and only inside
                    // the middlebox-compat window. Reject anything else as
                    // `unexpected_message`.
                    if !self.ccs_window_open || fragment.as_slice() != [0x01] {
                        return Err(Error::UnexpectedMessage);
                    }
                    continue;
                }
                ContentType::ApplicationData if self.read.is_some() => {
                    match self.decrypt(&fragment) {
                        Ok((inner_ct, content)) => {
                            // A record that deprotects ends the RFC 8446
                            // §4.2.10 skip window: we have reached the
                            // client's real flight under the handshake key.
                            self.skip_early_data = None;
                            if let Some(msg) = self.dispatch_inner(inner_ct, content)? {
                                return Ok(Some(msg));
                            }
                        }
                        Err(Error::BadRecordMac) if self.skip_early_data.is_some() => {
                            // RFC 8446 §4.2.10: a server that rejects early
                            // data skips past it, discarding records that
                            // fail to deprotect under the handshake key.
                            // `decrypt` peeks the nonce, so the read sequence
                            // number has NOT advanced — the next record is
                            // tried at the same seq, which is exactly what
                            // the client's real flight expects.
                            let budget = self.skip_early_data.take().expect("armed");
                            match budget.checked_sub(fragment.len()) {
                                Some(rest) => self.skip_early_data = Some(rest),
                                // Budget exhausted: this really is a bad
                                // record, not skipped early data.
                                None => return Err(Error::BadRecordMac),
                            }
                        }
                        Err(e) => return Err(e),
                    }
                }
                ContentType::Handshake => {
                    // RFC 8446 §5: once read keys are installed, every
                    // record except CCS (in the middlebox-compat window)
                    // MUST be `application_data` (ciphertext). A plaintext
                    // Handshake record at this point is an injection
                    // attempt — refuse rather than feed it into the
                    // reassembly buffer.
                    if self.read.is_some() {
                        return Err(Error::UnexpectedMessage);
                    }
                    self.append_handshake_bytes(&fragment)?;
                }
                ContentType::Alert => {
                    // Same rule as Handshake above: plaintext Alert after
                    // read keys are active is forbidden (RFC 8446 §5).
                    if self.read.is_some() {
                        return Err(Error::UnexpectedMessage);
                    }
                    return Ok(Some(parse_alert(&fragment)?));
                }
                _ => return Err(Error::UnexpectedMessage),
            }
        }
    }

    /// Decrypts a protected record into `(inner content type, content)`.
    fn decrypt(&mut self, fragment: &[u8]) -> Result<(ContentType, Vec<u8>), Error> {
        // The AAD is the wire header of the ciphertext record.
        let mut header = [0u8; 5];
        header[0] = ContentType::ApplicationData.as_u8();
        header[1] = 0x03;
        header[2] = 0x03;
        header[3..5].copy_from_slice(&(fragment.len() as u16).to_be_bytes());
        let crypter = self.read.as_mut().expect("read keys present");
        crypter.decrypt(&header, fragment)
    }

    /// Routes the plaintext recovered from a protected record. RFC 8446 §5.4
    /// forbids zero-length inner `Handshake` and `Alert` records (only empty
    /// `ApplicationData` is permitted, as a traffic-analysis countermeasure).
    fn dispatch_inner(
        &mut self,
        inner_ct: ContentType,
        content: Vec<u8>,
    ) -> Result<Option<Incoming>, Error> {
        match inner_ct {
            ContentType::Handshake => {
                if content.is_empty() {
                    return Err(Error::UnexpectedMessage);
                }
                self.append_handshake_bytes(&content)?;
                Ok(None)
            }
            ContentType::ApplicationData => {
                let plaintext_len = content.len();
                if self.early_data_routing {
                    // Replayable 0-RTT bytes: quarantine away from `app_in`
                    // so `take_received` never mixes them with 1-RTT data.
                    self.early_in.extend_from_slice(&content);
                } else if self.app_data_allowed {
                    self.app_in.extend_from_slice(&content);
                }
                // Otherwise the handshake has not completed: the peer is not
                // yet authenticated, so the plaintext is dropped rather than
                // buffered. The event is still reported so the state machine
                // raises `unexpected_message` — but an application draining
                // plaintext on the error path can never see these bytes.
                Ok(Some(Incoming::ApplicationData(plaintext_len)))
            }
            ContentType::Alert => {
                if content.is_empty() {
                    return Err(Error::UnexpectedMessage);
                }
                Ok(Some(parse_alert(&content)?))
            }
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Removes one complete handshake message (header + body) from the
    /// reassembly buffer, if present. A length-claim larger than the
    /// reassembly cap is still observed here (the buffer's
    /// `append_handshake_bytes` ceiling stops growth long before the
    /// length-claim can be honored), but we return `None` so the caller
    /// keeps draining records until the bounded extend bails for us.
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
}

/// Parses a 2-byte alert body.
fn parse_alert(body: &[u8]) -> Result<Incoming, Error> {
    if body.len() != 2 {
        return Err(Error::Decode);
    }
    Ok(Incoming::Alert(Alert {
        fatal: body[0] == 2,
        description: AlertDescription::from_u8(body[1]),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `quic_feed_handshake` (and the record path it shares with) caps the
    /// reassembly buffer at `MAX_HANDSHAKE_REASSEMBLY`. A peer dripping
    /// fragments without ever completing a message can't grow it past that
    /// ceiling — the bounded extend returns `RecordOverflow`.
    #[test]
    fn handshake_reassembly_bound_enforces_ceiling() {
        let mut core = ConnectionCore::new();
        // Plausible chunk size matching a TLS record payload (~16 KiB).
        let chunk = alloc::vec![0u8; 16 * 1024];
        let chunks_to_fill = MAX_HANDSHAKE_REASSEMBLY / chunk.len();
        for _ in 0..chunks_to_fill {
            core.quic_feed_handshake(&chunk).unwrap();
        }
        // One more chunk pushes us past the cap → RecordOverflow.
        assert!(matches!(
            core.quic_feed_handshake(&chunk),
            Err(Error::RecordOverflow)
        ));
    }

    /// Finding: the write side silently dropped records once the per-key
    /// record-sequence cap was reached — `send_application_data`,
    /// `send_alert` and `send_close_notify` all became no-ops while still
    /// reporting success. The failure must latch and be observable.
    #[test]
    fn write_side_cap_latches_instead_of_silently_dropping() {
        use crate::tls::crypto::AeadAlg;
        use crate::tls::crypto::{HashAlg, RecordCrypter, Secret};

        let mut core = ConnectionCore::new();
        let secret = Secret::new(&[0x5au8; 32]);
        let mut crypter = RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &secret);
        // Park the counter one record below the cap: the first record still
        // goes out, the second cannot be protected.
        crypter.set_seq_for_test((1u64 << 23) - 1);
        core.set_write(crypter);

        core.send_application_data(b"last one through");
        assert!(core.check_write_error().is_ok());
        let queued = core.write_tls().len();
        assert!(queued > 0, "the first record must reach the wire");

        core.send_application_data(b"this one cannot be protected");
        assert!(
            matches!(core.check_write_error(), Err(Error::TooManyRecords)),
            "a dropped record must surface, not be swallowed"
        );
        assert!(
            core.write_tls().is_empty(),
            "nothing was queued for the failed record"
        );
        // The latch is sticky: a close_notify after the cap is equally lost,
        // and the caller must keep seeing the error.
        core.send_close_notify();
        assert!(matches!(
            core.check_write_error(),
            Err(Error::TooManyRecords)
        ));
    }

    /// Finding: rejected 0-RTT killed the connection. RFC 8446 §4.2.10 wants
    /// the undecryptable early-data records skipped, and — because
    /// `RecordCrypter::decrypt` used to consume a sequence number before the
    /// AEAD check — the skip must NOT advance the read sequence number, or
    /// the peer's real flight would never line up again.
    #[test]
    fn skip_early_data_discards_records_without_burning_read_sequence_numbers() {
        use crate::tls::crypto::AeadAlg;
        use crate::tls::crypto::{HashAlg, RecordCrypter, Secret};

        // Two independent keys: `real` is the handshake key both sides agree
        // on, `stale` stands in for the 0-RTT key the server never installed.
        let real_secret = Secret::new(&[0x11u8; 32]);
        let stale_secret = Secret::new(&[0x22u8; 32]);
        let mut peer_writer =
            RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &real_secret);

        let mut core = ConnectionCore::new();
        core.set_read(RecordCrypter::new(
            HashAlg::Sha256,
            AeadAlg::Aes128Gcm,
            16,
            &real_secret,
        ));
        core.set_app_data_allowed(true);
        core.begin_skip_early_data(64 * 1024);

        // Three records the reader cannot decrypt (the "early data"), then a
        // genuine record at read sequence number 0.
        let mut wire = Vec::new();
        let mut stale = RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &stale_secret);
        for _ in 0..3 {
            wire.extend_from_slice(
                &stale
                    .encrypt(ContentType::ApplicationData, b"0-RTT bytes")
                    .unwrap(),
            );
        }
        wire.extend_from_slice(
            &peer_writer
                .encrypt(ContentType::ApplicationData, b"1-RTT hello")
                .unwrap(),
        );
        core.read_tls(&wire);

        assert!(matches!(
            core.next_message(),
            Ok(Some(Incoming::ApplicationData(11)))
        ));
        assert_eq!(core.take_received(), b"1-RTT hello");
        assert!(
            !core.skipping_early_data(),
            "the first record that deprotects closes the skip window"
        );

        // With the window closed, a bad record is fatal again.
        let mut junk = Vec::new();
        junk.extend_from_slice(
            &stale
                .encrypt(ContentType::ApplicationData, b"late junk")
                .unwrap(),
        );
        core.read_tls(&junk);
        assert!(matches!(core.next_message(), Err(Error::BadRecordMac)));
    }

    /// The skip budget is finite: past it a `bad_record_mac` is fatal again,
    /// so an attacker cannot make us burn unbounded work discarding records.
    #[test]
    fn skip_early_data_budget_is_bounded() {
        use crate::tls::crypto::AeadAlg;
        use crate::tls::crypto::{HashAlg, RecordCrypter, Secret};

        let mut core = ConnectionCore::new();
        core.set_read(RecordCrypter::new(
            HashAlg::Sha256,
            AeadAlg::Aes128Gcm,
            16,
            &Secret::new(&[0x11u8; 32]),
        ));
        core.begin_skip_early_data(64);
        let mut stale = RecordCrypter::new(
            HashAlg::Sha256,
            AeadAlg::Aes128Gcm,
            16,
            &Secret::new(&[0x22u8; 32]),
        );
        let mut wire = Vec::new();
        for _ in 0..4 {
            wire.extend_from_slice(
                &stale
                    .encrypt(ContentType::ApplicationData, b"0-RTT bytes")
                    .unwrap(),
            );
        }
        core.read_tls(&wire);
        assert!(matches!(core.next_message(), Err(Error::BadRecordMac)));
    }

    /// Application plaintext must not be buffered before the state gate that
    /// rejects it: under mTLS a peer that has completed key exchange but not
    /// yet authenticated could otherwise deposit bytes an application reads
    /// off the error path.
    #[test]
    fn application_data_is_not_buffered_before_the_handshake_completes() {
        use crate::tls::crypto::AeadAlg;
        use crate::tls::crypto::{HashAlg, RecordCrypter, Secret};

        let secret = Secret::new(&[0x33u8; 32]);
        let mut peer = RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &secret);
        let mut core = ConnectionCore::new();
        core.set_read(RecordCrypter::new(
            HashAlg::Sha256,
            AeadAlg::Aes128Gcm,
            16,
            &secret,
        ));
        // `app_data_allowed` is false until the state machine reaches
        // Connected.
        core.read_tls(
            &peer
                .encrypt(ContentType::ApplicationData, b"unauthenticated")
                .unwrap(),
        );
        assert!(matches!(
            core.next_message(),
            Ok(Some(Incoming::ApplicationData(15)))
        ));
        assert!(
            core.take_received().is_empty(),
            "plaintext must not be readable before the handshake completes"
        );
    }

    /// A single fragment claiming to be larger than the cap is rejected
    /// outright (we never start accumulating it).
    #[test]
    fn handshake_reassembly_bound_rejects_oversize_fragment() {
        let mut core = ConnectionCore::new();
        let too_big = alloc::vec![0u8; MAX_HANDSHAKE_REASSEMBLY + 1];
        assert!(matches!(
            core.quic_feed_handshake(&too_big),
            Err(Error::RecordOverflow)
        ));
    }
}
