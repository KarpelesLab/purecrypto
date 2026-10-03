//! The transport-agnostic ("sans-I/O") connection core shared by both roles.
//!
//! [`ConnectionCore`] owns the record layer (framing, optional AEAD
//! protection), the handshake-message reassembly buffer, the transcript hash,
//! and the inbound/outbound byte buffers. It never touches a socket: callers
//! feed it received bytes with [`read_tls`](ConnectionCore::read_tls) and drain
//! bytes to transmit with [`write_tls`](ConnectionCore::write_tls). The
//! role-specific state machines (client/server) drive it by pulling decoded
//! messages and emitting handshake messages.

use super::super::codec::{
    MAX_PLAINTEXT_FRAGMENT, ParsedRecord, fragments, is_legal_record_version, read_record,
    write_record,
};
use super::super::crypto::{AEAD_TAG_LEN, RecordCrypter, Transcript};
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

/// The `server_name` extension's host name for a connection to
/// `server_name`, or `None` when the ClientHello must omit the extension.
///
/// RFC 6066 §3: "Literal IPv4 and IPv6 addresses are not permitted in
/// HostName", so an IP-literal reference identity — still verified against
/// the certificate's iPAddress SAN entries — is never sent. An empty name
/// (no identity, verification off) is omitted as well.
pub(crate) fn sni_host_name(server_name: &str) -> Option<&str> {
    (!server_name.is_empty() && !crate::tls::pki::is_ip_literal(server_name)).then_some(server_name)
}

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
    /// Read cursor into `inbuf`: the bytes before it are consumed records.
    /// Records are parsed (and decrypted in place) at the cursor; the
    /// consumed prefix is dropped when more input arrives, so a burst of
    /// records costs one memmove rather than one per record.
    in_off: usize,
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
    /// The `record_size_limit` (RFC 8449 §4) we advertised and the peer
    /// acknowledged, once it is in force on the read side: the largest
    /// `TLSInnerPlaintext` (content + type byte + padding) a protected
    /// inbound record may carry. The engines arm it when they install the
    /// application-traffic read key — the limit only governs records
    /// protected under keys derived from the handshake that negotiated it —
    /// and it survives `KeyUpdate` rotations. `None` means the extension
    /// was not negotiated (the protocol's own 2¹⁴ cap still applies).
    inbound_record_size_limit: Option<u16>,
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
    /// RFC 8446 §4.6.3: the peer sent `KeyUpdate(update_requested)` and we
    /// owe it a `KeyUpdate` of our own "prior to sending [our] next
    /// Application Data record". The engines record the obligation here
    /// instead of replying on the spot and discharge it once — however many
    /// requests arrived — at the end of the processing drain or before the
    /// next application write. Replying per request let a peer interleaving
    /// `[empty application_data, KeyUpdate(update_requested)]` (which keeps
    /// resetting the back-to-back flood guard) make us rotate our write key
    /// and queue one outbound record per inbound request, growing the
    /// output buffer without bound while it never reads.
    key_update_reply_pending: bool,
}

impl ConnectionCore {
    pub(crate) fn new() -> Self {
        ConnectionCore {
            inbuf: Vec::new(),
            in_off: 0,
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
            inbound_record_size_limit: None,
            app_data_allowed: false,
            write_error: None,
            skip_early_data: None,
            key_update_reply_pending: false,
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

    /// Notes that the peer requested a `KeyUpdate` (see
    /// `key_update_reply_pending`). Idempotent: any number of requests
    /// before the reply goes out are answered by that one reply.
    pub(crate) fn defer_key_update_reply(&mut self) {
        self.key_update_reply_pending = true;
    }

    /// Takes the pending `KeyUpdate` reply obligation, if any. The engine
    /// that gets `true` must emit its `KeyUpdate(update_not_requested)` and
    /// step its write key now.
    pub(crate) fn take_key_update_reply(&mut self) -> bool {
        core::mem::take(&mut self.key_update_reply_pending)
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
    /// protected records — application data and handshake messages alike —
    /// carry at most `limit - 1` plaintext bytes (the extra byte is the
    /// inner content type); see [`Self::outbound_fragment_cap`].
    pub(crate) fn set_peer_record_size_limit(&mut self, limit: u16) {
        self.peer_record_size_limit = Some(limit);
    }

    /// Arms enforcement of our own advertised `record_size_limit` (RFC 8449
    /// §4) on inbound protected records: from now on a record whose
    /// `TLSInnerPlaintext` exceeds `limit` bytes fails with
    /// [`Error::RecordOverflow`] (the engines answer with a
    /// `record_overflow` alert). Call it when installing the first read key
    /// derived from the handshake that negotiated the extension.
    pub(crate) fn set_inbound_record_size_limit(&mut self, limit: u16) {
        self.inbound_record_size_limit = Some(limit);
    }

    /// Called by the role-specific state machine when the handshake completes.
    /// After this, any further `ChangeCipherSpec` from the peer is treated as
    /// a protocol violation.
    pub(crate) fn close_ccs_window(&mut self) {
        self.ccs_window_open = false;
    }

    /// Opens or closes the RFC 8446 §5 middlebox-compatibility window. The
    /// core starts with it open (a client has sent its ClientHello by the
    /// time it reads anything); a server closes it at construction and opens
    /// it once the first ClientHello has been received, since a
    /// `change_cipher_spec` "before the first ClientHello message" MUST be
    /// treated as an unexpected record type.
    pub(crate) fn set_ccs_window_open(&mut self, open: bool) {
        self.ccs_window_open = open;
    }

    /// Feeds received TLS bytes into the input buffer.
    pub(crate) fn read_tls(&mut self, bytes: &[u8]) {
        if self.in_off > 0 {
            self.inbuf.drain(..self.in_off);
            self.in_off = 0;
        }
        self.inbuf.extend_from_slice(bytes);
    }

    /// Drops every received byte not yet handed to the state machine.
    /// RFC 8446 §6.1: "Any data received after a closure alert has been
    /// received MUST be ignored" — the engines call this once the peer's
    /// `close_notify` has been processed, so records coalesced behind it
    /// (or fed later) are neither decrypted nor delivered.
    pub(crate) fn discard_input(&mut self) {
        self.inbuf.clear();
        self.in_off = 0;
        self.hs_pending.clear();
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
    ///
    /// RFC 8446 §5.1: handshake messages MUST NOT span a key change, and an
    /// implementation that receives a key change with an unfinished (or
    /// unconsumed) handshake fragment MUST abort with `unexpected_message`.
    /// The record layer pops one complete message at a time before reading
    /// the next record, so anything still in `hs_pending` when the state
    /// machine rotates the read key is trailing data from the record that
    /// carried the message which triggered the rotation — bytes that were
    /// read under the *old* epoch (e.g. plaintext coalesced behind a
    /// ServerHello, or a NewSessionTicket riding behind Finished under the
    /// handshake key). Letting them through would process them as if they
    /// had been protected under the new key. Refuse instead.
    pub(crate) fn set_read(&mut self, crypter: RecordCrypter) -> Result<(), Error> {
        if !self.hs_pending.is_empty() {
            return Err(Error::UnexpectedMessage);
        }
        self.read = Some(crypter);
        Ok(())
    }

    /// Installs the outbound (write) record-protection keys.
    pub(crate) fn set_write(&mut self, crypter: RecordCrypter) {
        self.write = Some(crypter);
    }

    /// Drops the outbound record-protection keys, returning the write side
    /// to plaintext. Used by the client on HelloRetryRequest after a 0-RTT
    /// offer: the early-traffic write key installed at CH1 time must not
    /// protect CH2 (RFC 8446 §4.1.4 — CH2 is a plaintext handshake record),
    /// and no further early data may be sent (§4.2.10).
    pub(crate) fn clear_write(&mut self) {
        self.write = None;
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
    /// A message longer than one record's plaintext cap — a certificate
    /// chain of a few ML-DSA certificates runs past 2¹⁴ bytes — spans as
    /// many records as it takes (RFC 8446 §5.1); the peer reassembles.
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
    /// Deliberately bypasses the write crypter: the engines emit it right
    /// after installing the handshake write key, and RFC 8446 §5 wants it
    /// unprotected.
    pub(crate) fn emit_ccs(&mut self) {
        self.emit_plaintext_record(ContentType::ChangeCipherSpec, &[1]);
    }

    /// Sends application data (requires write keys to be installed). Data
    /// longer than one record's plaintext cap — the peer's
    /// `record_size_limit` or the protocol's 2¹⁴ — spans several records.
    pub(crate) fn send_application_data(&mut self, data: &[u8]) {
        self.emit_record(ContentType::ApplicationData, data);
    }

    /// Test hook: emits `data` as a single protected `application_data`
    /// record without the `record_size_limit` fragmentation of
    /// [`Self::send_application_data`], to exercise the peer's receive-side
    /// enforcement.
    #[cfg(test)]
    pub(crate) fn emit_unfragmented_application_data_for_test(&mut self, data: &[u8]) {
        self.emit_one_record(ContentType::ApplicationData, data);
    }

    /// The most plaintext one outbound record may carry right now.
    ///
    /// The protocol caps a record's plaintext at 2¹⁴ bytes (RFC 8446 §5.1).
    /// A peer that advertised `record_size_limit` (RFC 8449 §4) lowers that
    /// for *protected* records: its limit counts the whole
    /// `TLSInnerPlaintext`, so one byte is reserved for the inner content
    /// type. Unprotected records are not subject to the limit (§4:
    /// "Unprotected messages are not subject to this limit"), and a limit
    /// above the protocol maximum is clamped. The parser rejects limits
    /// below 64, so the cap is never zero.
    fn outbound_fragment_cap(&self) -> usize {
        match (&self.write, self.peer_record_size_limit) {
            (Some(_), Some(limit)) => usize::from(limit)
                .saturating_sub(1)
                .clamp(1, MAX_PLAINTEXT_FRAGMENT),
            _ => MAX_PLAINTEXT_FRAGMENT,
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

    /// Number of records deprotected under the *current* read key (the read
    /// crypter's sequence number), or 0 before any read key is installed.
    /// The engines' `KeyUpdate` flood guard uses it: a `KeyUpdate` that was
    /// the only record under the key it retires extends a back-to-back run.
    pub(crate) fn read_records_under_current_key(&self) -> u64 {
        self.read.as_ref().map_or(0, |c| c.seq())
    }

    /// True once [`Self::send_close_notify`] has queued our `close_notify`.
    /// RFC 8446 §6.1: "the sender MUST NOT send any more data" afterwards —
    /// the engines refuse `send_application_data` once this is set. Only the
    /// write side is closed; reading continues until the peer's own
    /// `close_notify` (half-close).
    pub(crate) fn sent_close_notify(&self) -> bool {
        self.sent_close_notify
    }

    /// Frames `payload` as one or more records of content type `ct`
    /// (protected once write keys are installed, plaintext before), each
    /// carrying at most [`Self::outbound_fragment_cap`] bytes. Every sender
    /// path funnels through here, so a handshake message or application
    /// write of any length is fragmented as RFC 8446 §5.1 requires — the
    /// crypter would otherwise refuse anything past 2¹⁴ as `RecordOverflow`
    /// and the message would never reach the wire. Alerts are two bytes and
    /// never split.
    pub(crate) fn emit_record(&mut self, ct: ContentType, payload: &[u8]) {
        let cap = self.outbound_fragment_cap();
        if payload.len() <= cap {
            self.emit_one_record(ct, payload);
        } else {
            for chunk in fragments(payload, cap) {
                self.emit_one_record(ct, chunk);
            }
        }
    }

    /// Frames exactly one record carrying all of `payload`; the caller has
    /// already bounded it (see [`Self::emit_record`]).
    fn emit_one_record(&mut self, ct: ContentType, payload: &[u8]) {
        match &mut self.write {
            Some(crypter) => match crypter.encrypt_into(ct, payload, &mut self.outbuf) {
                Ok(()) => {}
                Err(e) => {
                    // The only failures here are `TooManyRecords` (the
                    // per-key sequence cap — the engines pre-empt it with an
                    // automatic `KeyUpdate`, but a peer that never lets us
                    // rekey can still get here) and `RecordOverflow` (a
                    // caller bypassed `emit_record`'s fragmentation). The
                    // record is NOT on the wire, so silently returning
                    // would leave `send_application_data` /
                    // `send_close_notify` as no-ops that still report
                    // success. Latch the error so the engines can surface
                    // it.
                    self.write_error.get_or_insert(e);
                }
            },
            None => self.emit_plaintext_record(ct, payload),
        }
    }

    /// Frames one unprotected record. `write_record` only refuses a
    /// fragment past the largest legal record, which a payload bounded by
    /// [`Self::outbound_fragment_cap`] never is; should it ever happen the
    /// failure latches like a protection failure rather than vanishing.
    fn emit_plaintext_record(&mut self, ct: ContentType, payload: &[u8]) {
        if let Err(e) = write_record(&mut self.outbuf, ct, ProtocolVersion::TLSv1_2, payload) {
            self.write_error.get_or_insert(e);
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
            }) = read_record(&self.inbuf[self.in_off..])?
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
            // RFC 8446 §5.1: a TLSPlaintext fragment is capped at 2^14 bytes
            // (only protected TLSCiphertext records get the extra 256 bytes
            // of AEAD expansion, checked after decryption). Anything longer
            // is a `record_overflow`.
            if !matches!(content_type, ContentType::ApplicationData) && fragment.len() > (1 << 14) {
                return Err(Error::RecordOverflow);
            }
            let frag_start = self.in_off + 5;
            let frag_end = frag_start + fragment.len();
            self.in_off += len;

            // RFC 8446 §5.1: "Handshake messages MUST NOT be interleaved
            // with other record types. That is, if a handshake message is
            // split over two or more records, there MUST NOT be any other
            // records between them." `pop_handshake` above drains every
            // complete message first, so anything left in `hs_pending` is
            // an unfinished one; a plaintext record of another type here
            // (an alert, a middlebox CCS) is a protocol violation.
            // Protected records are checked on their inner type in
            // `dispatch_inner`.
            if !self.hs_pending.is_empty()
                && !matches!(
                    content_type,
                    ContentType::Handshake | ContentType::ApplicationData
                )
            {
                return Err(Error::UnexpectedMessage);
            }

            // The fragment is processed (and, if protected, decrypted) in
            // place. `inbuf` is moved out for the call so the record can be
            // borrowed mutably alongside `self`; nothing below reads it.
            let mut inbuf = core::mem::take(&mut self.inbuf);
            let r = self.process_record(content_type, &mut inbuf[frag_start..frag_end]);
            self.inbuf = inbuf;
            if self.in_off == self.inbuf.len() {
                self.inbuf.clear();
                self.in_off = 0;
            }
            if let Some(msg) = r? {
                return Ok(Some(msg));
            }
        }
    }

    /// Handles one record read by [`Self::next_message`]: `Ok(None)` when
    /// it yields no message and the next record should be read.
    fn process_record(
        &mut self,
        content_type: ContentType,
        fragment: &mut [u8],
    ) -> Result<Option<Incoming>, Error> {
        match content_type {
            ContentType::ChangeCipherSpec => {
                // RFC 8446 §5: must be exactly `[0x01]`, and only inside
                // the middlebox-compat window. Reject anything else as
                // `unexpected_message`.
                if !self.ccs_window_open || *fragment != [0x01] {
                    return Err(Error::UnexpectedMessage);
                }
                return Ok(None);
            }
            ContentType::ApplicationData if self.read.is_some() => {
                match self.decrypt(fragment) {
                    Ok((inner_ct, end)) => {
                        // A record that deprotects ends the RFC 8446
                        // §4.2.10 skip window: we have reached the
                        // client's real flight under the handshake key.
                        self.skip_early_data = None;
                        // RFC 8449 §4: the negotiated limit counts the
                        // whole TLSInnerPlaintext — content, the type
                        // byte and any padding — i.e. the ciphertext
                        // minus the AEAD tag. Receipt of a larger record
                        // "MUST be treated as a fatal error" with
                        // `record_overflow`.
                        if let Some(limit) = self.inbound_record_size_limit
                            && fragment.len().saturating_sub(AEAD_TAG_LEN) > usize::from(limit)
                        {
                            return Err(Error::RecordOverflow);
                        }
                        if let Some(msg) = self.dispatch_inner(inner_ct, &fragment[..end])? {
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
            ContentType::ApplicationData if self.skip_early_data.is_some() => {
                // No read key at all, yet a protected record arrived and
                // the skip window is armed: the server answered a 0-RTT
                // ClientHello with a HelloRetryRequest and the client's
                // early-data records were already in flight (RFC 8446
                // §4.2.10 / §4.1.4). They can never be deprotected — no
                // early-traffic key was ever installed — so discard
                // them against the same byte budget the post-CH2 skip
                // uses; exhausting it is a real protocol violation.
                let budget = self.skip_early_data.take().expect("armed");
                match budget.checked_sub(fragment.len()) {
                    Some(rest) => self.skip_early_data = Some(rest),
                    None => return Err(Error::UnexpectedMessage),
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
                // RFC 8446 §5.1: zero-length handshake fragments MUST
                // NOT be sent. Same treatment as the protected case in
                // `dispatch_inner` (§5.4): `unexpected_message`.
                if fragment.is_empty() {
                    return Err(Error::UnexpectedMessage);
                }
                self.append_handshake_bytes(fragment)?;
            }
            ContentType::Alert => {
                // Same rule as Handshake above: plaintext Alert after
                // read keys are active is forbidden (RFC 8446 §5).
                if self.read.is_some() {
                    return Err(Error::UnexpectedMessage);
                }
                return Ok(Some(parse_alert(fragment)?));
            }
            _ => return Err(Error::UnexpectedMessage),
        }
        Ok(None)
    }

    /// Decrypts a protected record in place into `(inner content type,
    /// content length)`; the content is `fragment[..len]`.
    fn decrypt(&mut self, fragment: &mut [u8]) -> Result<(ContentType, usize), Error> {
        // The AAD is the wire header of the ciphertext record.
        let mut header = [0u8; 5];
        header[0] = ContentType::ApplicationData.as_u8();
        header[1] = 0x03;
        header[2] = 0x03;
        header[3..5].copy_from_slice(&(fragment.len() as u16).to_be_bytes());
        let crypter = self.read.as_mut().expect("read keys present");
        crypter.decrypt_in_place(&header, fragment)
    }

    /// Routes the plaintext recovered from a protected record. RFC 8446 §5.4
    /// forbids zero-length inner `Handshake` and `Alert` records (only empty
    /// `ApplicationData` is permitted, as a traffic-analysis countermeasure).
    fn dispatch_inner(
        &mut self,
        inner_ct: ContentType,
        content: &[u8],
    ) -> Result<Option<Incoming>, Error> {
        // RFC 8446 §5.1 interleaving rule, for protected records (see the
        // plaintext check in `next_message`): while a handshake message is
        // only partly received, the next record must continue it. Without
        // this an application-data or alert record slipped between the
        // fragments was delivered as if the message boundary were intact.
        if !self.hs_pending.is_empty() && inner_ct != ContentType::Handshake {
            return Err(Error::UnexpectedMessage);
        }
        match inner_ct {
            ContentType::Handshake => {
                if content.is_empty() {
                    return Err(Error::UnexpectedMessage);
                }
                self.append_handshake_bytes(content)?;
                Ok(None)
            }
            ContentType::ApplicationData => {
                let plaintext_len = content.len();
                if self.early_data_routing {
                    // Replayable 0-RTT bytes: quarantine away from `app_in`
                    // so `take_received` never mixes them with 1-RTT data.
                    self.early_in.extend_from_slice(content);
                } else if self.app_data_allowed {
                    self.app_in.extend_from_slice(content);
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
                Ok(Some(parse_alert(content)?))
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

/// What a (D)TLS 1.3 client takes from a `CertificateRequest` (RFC 8446
/// §4.3.2), as parsed by [`parse_certificate_request_13`].
pub(crate) struct CertificateRequest13 {
    /// The `signature_algorithms` the client's `CertificateVerify` scheme is
    /// chosen from (§4.4.3).
    pub(crate) signature_algorithms: Vec<super::super::codec::SignatureScheme>,
    /// RFC 8879 §3: the `compress_certificate` algorithms the server can
    /// decompress the client's `Certificate` under; empty when the extension
    /// is absent.
    #[cfg(feature = "cert-compression")]
    pub(crate) cert_compression_algorithms: Vec<u16>,
}

/// Parses a (D)TLS 1.3 `CertificateRequest` body received during the
/// handshake (RFC 8446 §4.3.2). Shared by the TLS and DTLS 1.3 clients.
///
/// `certificate_request_context` MUST be empty in handshake authentication
/// (a non-empty one belongs to post-handshake authentication, which no
/// client of this crate opts into via `post_handshake_auth`), and "the
/// signature_algorithms extension MUST be specified"; a missing list is
/// [`Error::MissingExtension`]. "There MUST NOT be more than one extension
/// of the same type" (§4.2): a duplicated `signature_algorithms` or
/// `compress_certificate` is [`Error::IllegalParameter`]. Other extensions
/// (`certificate_authorities`, `oid_filters`, ...) are advisory and skipped.
pub(crate) fn parse_certificate_request_13(body: &[u8]) -> Result<CertificateRequest13, Error> {
    use super::super::codec::{ExtensionType, MAX_EXTENSIONS, ReadCursor, extension as ext};
    let mut c = ReadCursor::new(body);
    if !c.vec_u8()?.is_empty() {
        return Err(Error::IllegalParameter);
    }
    let exts = c.vec_u16()?;
    c.expect_empty()?;
    let mut ec = ReadCursor::new(exts);
    let mut sig_algs = None;
    #[cfg(feature = "cert-compression")]
    let mut cert_compression: Option<Vec<u16>> = None;
    let mut count = 0usize;
    while !ec.is_empty() {
        let ty = ec.u16()?;
        let ext_body = ec.vec_u16()?;
        count += 1;
        if count > MAX_EXTENSIONS {
            return Err(Error::Decode);
        }
        if ty == ExtensionType::SIGNATURE_ALGORITHMS.0 {
            if sig_algs.is_some() {
                return Err(Error::IllegalParameter);
            }
            sig_algs = Some(ext::parse_signature_algorithms(ext_body)?);
        }
        #[cfg(feature = "cert-compression")]
        if ty == ExtensionType::COMPRESS_CERTIFICATE.0 {
            if cert_compression.is_some() {
                return Err(Error::IllegalParameter);
            }
            cert_compression = Some(crate::tls::cert_compression::decode_extension(ext_body)?);
        }
    }
    Ok(CertificateRequest13 {
        signature_algorithms: sig_algs.ok_or(Error::MissingExtension)?,
        #[cfg(feature = "cert-compression")]
        cert_compression_algorithms: cert_compression.unwrap_or_default(),
    })
}

/// RFC 7250 trust decision for a peer's raw public key, shared by every
/// engine that negotiates `RawPublicKey`: `spki` is the bare
/// `SubjectPublicKeyInfo` DER the peer put in its `Certificate`, `allowlist`
/// the operator-configured pins. A raw key has no chain to validate, so the
/// allowlist is the entire trust root:
///
/// * a non-empty allowlist must contain `spki` — checked in constant time
///   over every entry so the match position does not leak (lengths are
///   public), and enforced whether or not X.509 verification is on, since a
///   configured pin is the out-of-band authentication that
///   `verify_certificates(false)` defers to;
/// * an empty allowlist with verification on has nothing to establish trust
///   against, so the key is refused;
/// * an empty allowlist with verification off accepts the key unverified,
///   exactly as an X.509 leaf is accepted in that mode.
///
/// Errors with [`Error::BadCertificate`].
pub(crate) fn check_raw_public_key(
    verify_certificates: bool,
    allowlist: &[Vec<u8>],
    spki: &[u8],
) -> Result<(), Error> {
    use crate::ct::ConstantTimeEq;
    if allowlist.is_empty() {
        return if verify_certificates {
            Err(Error::BadCertificate)
        } else {
            Ok(())
        };
    }
    let mut matched = crate::ct::Choice::from(0u8);
    for accepted in allowlist {
        if accepted.len() == spki.len() {
            matched |= accepted.as_slice().ct_eq(spki);
        }
    }
    if bool::from(matched) {
        Ok(())
    } else {
        Err(Error::BadCertificate)
    }
}

/// Parses a 2-byte alert body.
pub(crate) fn parse_alert(body: &[u8]) -> Result<Incoming, Error> {
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

    /// Finding: `emit_handshake` handed the whole message to the record
    /// crypter, which refuses anything past 2¹⁴ bytes, so a long
    /// `Certificate` latched `RecordOverflow` and never went out. Every
    /// emit path now splits at the record cap — the protocol's 2¹⁴, or the
    /// peer's `record_size_limit` (minus the inner type byte) for protected
    /// records — while unprotected records honour only the protocol cap
    /// (RFC 8449 §4: "Unprotected messages are not subject to this limit").
    #[test]
    fn emit_paths_fragment_at_the_record_cap() {
        use crate::tls::codec::{ParsedRecord, read_record};
        use crate::tls::crypto::{AeadAlg, HashAlg, RecordCrypter, Secret};

        fn records(wire: &[u8]) -> Vec<(ContentType, usize)> {
            let mut out = Vec::new();
            let mut off = 0;
            while off < wire.len() {
                let ParsedRecord {
                    content_type,
                    fragment,
                    len,
                    ..
                } = read_record(&wire[off..]).unwrap().expect("whole records");
                out.push((content_type, fragment.len()));
                off += len;
            }
            out
        }

        // Plaintext: a 40 000-byte handshake message spans three records of
        // at most 2^14 bytes, and the peer's limit does not apply.
        let mut core = ConnectionCore::new();
        core.set_peer_record_size_limit(64);
        core.emit_handshake(alloc::vec![0u8; 40_000]);
        assert!(core.check_write_error().is_ok());
        let recs = records(&core.write_tls());
        assert_eq!(
            recs,
            [
                (ContentType::Handshake, 1 << 14),
                (ContentType::Handshake, 1 << 14),
                (ContentType::Handshake, 40_000 - 2 * (1 << 14)),
            ]
        );

        // Protected: the same message under a peer limit of 100 goes out in
        // records whose content is at most 99 bytes (+ type byte + tag).
        let secret = Secret::new(&[0x77u8; 32]);
        core.set_write(RecordCrypter::new(
            HashAlg::Sha256,
            AeadAlg::Aes128Gcm,
            16,
            &secret,
        ));
        core.set_peer_record_size_limit(100);
        core.emit_handshake(alloc::vec![0u8; 1000]);
        assert!(core.check_write_error().is_ok());
        let recs = records(&core.write_tls());
        assert_eq!(recs.len(), 1000_usize.div_ceil(99));
        assert!(
            recs.iter()
                .all(|(ct, len)| *ct == ContentType::ApplicationData && *len <= 100 + AEAD_TAG_LEN)
        );

        // And without a peer limit the protocol cap applies to protected
        // records too: 2^14 + 1 bytes is two records, not a latched
        // `RecordOverflow`.
        let mut core = ConnectionCore::new();
        core.set_write(RecordCrypter::new(
            HashAlg::Sha256,
            AeadAlg::Aes128Gcm,
            16,
            &secret,
        ));
        core.send_application_data(&alloc::vec![0u8; (1 << 14) + 1]);
        assert!(core.check_write_error().is_ok());
        let recs = records(&core.write_tls());
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].1, (1 << 14) + 1 + AEAD_TAG_LEN);
        assert_eq!(recs[1].1, 1 + 1 + AEAD_TAG_LEN);
        // An empty application-data record (traffic-analysis padding) is
        // still one record, not zero.
        core.send_application_data(&[]);
        assert_eq!(records(&core.write_tls()).len(), 1);
    }

    /// Finding: RFC 8446 §5.1's interleaving rule was not enforced — while a
    /// handshake message was only partly received, an alert or
    /// application-data record was dispatched normally. Any record other
    /// than the message's continuation is now `unexpected_message`, on the
    /// plaintext and the protected path alike; the continuation itself
    /// still reassembles.
    #[test]
    fn records_interleaved_into_a_partial_handshake_message_are_refused() {
        use crate::tls::crypto::{AeadAlg, HashAlg, RecordCrypter, Secret};

        // A handshake header claiming a 32-byte body, split 4 + 10 | 22.
        let mut msg = alloc::vec![0x08, 0x00, 0x00, 32];
        msg.extend_from_slice(&[0xabu8; 32]);
        let (first, rest) = msg.split_at(14);

        fn plain(ct: ContentType, body: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            write_record(&mut out, ct, ProtocolVersion::TLSv1_2, body).unwrap();
            out
        }

        // Positive control: the continuation completes the message.
        let mut core = ConnectionCore::new();
        core.read_tls(&plain(ContentType::Handshake, first));
        core.read_tls(&plain(ContentType::Handshake, rest));
        assert!(matches!(core.next_message(), Ok(Some(Incoming::Handshake(m))) if m == msg));

        // Plaintext alert, or a middlebox CCS, between the fragments.
        for (ct, body) in [
            (ContentType::Alert, &[2u8, 40][..]),
            (ContentType::ChangeCipherSpec, &[1u8][..]),
        ] {
            let mut core = ConnectionCore::new();
            core.read_tls(&plain(ContentType::Handshake, first));
            core.read_tls(&plain(ct, body));
            core.read_tls(&plain(ContentType::Handshake, rest));
            assert!(
                matches!(core.next_message(), Err(Error::UnexpectedMessage)),
                "{ct:?} interleaved into a handshake message must be refused"
            );
        }

        // Protected: inner application data or an alert between the
        // fragments, with and without the application-data gate open.
        let secret = Secret::new(&[0x44u8; 32]);
        for (ct, body) in [
            (ContentType::ApplicationData, &b"sneaky"[..]),
            (ContentType::ApplicationData, &b""[..]),
            (ContentType::Alert, &[1u8, 0][..]),
        ] {
            let mut peer = RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &secret);
            let mut core = ConnectionCore::new();
            core.set_read(RecordCrypter::new(
                HashAlg::Sha256,
                AeadAlg::Aes128Gcm,
                16,
                &secret,
            ))
            .unwrap();
            core.set_app_data_allowed(true);
            core.read_tls(&peer.encrypt(ContentType::Handshake, first).unwrap());
            core.read_tls(&peer.encrypt(ct, body).unwrap());
            core.read_tls(&peer.encrypt(ContentType::Handshake, rest).unwrap());
            assert!(
                matches!(core.next_message(), Err(Error::UnexpectedMessage)),
                "protected {ct:?} interleaved into a handshake message must be refused"
            );
            assert!(
                core.take_received().is_empty(),
                "interleaved application data must not be delivered"
            );
        }

        // Protected positive control.
        let mut peer = RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &secret);
        let mut core = ConnectionCore::new();
        core.set_read(RecordCrypter::new(
            HashAlg::Sha256,
            AeadAlg::Aes128Gcm,
            16,
            &secret,
        ))
        .unwrap();
        core.read_tls(&peer.encrypt(ContentType::Handshake, first).unwrap());
        core.read_tls(&peer.encrypt(ContentType::Handshake, rest).unwrap());
        assert!(matches!(core.next_message(), Ok(Some(Incoming::Handshake(m))) if m == msg));
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
        ))
        .unwrap();
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
        ))
        .unwrap();
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
        ))
        .unwrap();
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

    /// RFC 8446 §5.1: a plaintext record longer than 2^14 bytes is a
    /// `record_overflow` even though the record layer's framing allows the
    /// ciphertext ceiling of 2^14 + 256.
    #[test]
    fn oversized_plaintext_record_is_record_overflow() {
        let mut core = ConnectionCore::new();
        let mut wire = alloc::vec![22u8, 0x03, 0x03];
        wire.extend_from_slice(&((1u16 << 14) + 1).to_be_bytes());
        wire.extend(core::iter::repeat_n(0u8, (1 << 14) + 1));
        core.read_tls(&wire);
        assert!(matches!(core.next_message(), Err(Error::RecordOverflow)));
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
