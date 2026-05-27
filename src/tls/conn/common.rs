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
}

impl ConnectionCore {
    pub(crate) fn new() -> Self {
        ConnectionCore {
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            hs_pending: Vec::new(),
            app_in: Vec::new(),
            read: None,
            write: None,
            transcript: Transcript::new(),
            sent_close_notify: false,
            ccs_window_open: true,
            peer_record_size_limit: None,
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

    /// Drains any received application plaintext.
    pub(crate) fn take_received(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app_in)
    }

    /// Updates the transcript with a handshake message and frames it for
    /// sending (encrypted if write keys are installed, else as plaintext).
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
    pub(crate) fn quic_feed_handshake(&mut self, bytes: &[u8]) {
        self.hs_pending.extend_from_slice(bytes);
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

    fn emit_record(&mut self, ct: ContentType, payload: &[u8]) {
        match &mut self.write {
            Some(crypter) => match crypter.encrypt(ct, payload) {
                Ok(rec) => self.outbuf.extend_from_slice(&rec),
                Err(_) => {
                    // The only failures here are `TooManyRecords` (callers
                    // should `request_key_update` first) and `RecordOverflow`
                    // (callers must fragment). Both are programmer errors;
                    // drop the record so the connection visibly stops making
                    // progress rather than emitting garbage.
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
                    let (inner_ct, content) = self.decrypt(&fragment)?;
                    if let Some(msg) = self.dispatch_inner(inner_ct, content)? {
                        return Ok(Some(msg));
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
                    self.hs_pending.extend_from_slice(&fragment);
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
                self.hs_pending.extend_from_slice(&content);
                Ok(None)
            }
            ContentType::ApplicationData => {
                let plaintext_len = content.len();
                self.app_in.extend_from_slice(&content);
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
    /// reassembly buffer, if present.
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
