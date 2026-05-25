//! The transport-agnostic ("sans-I/O") connection core shared by both roles.
//!
//! [`ConnectionCore`] owns the record layer (framing, optional AEAD
//! protection), the handshake-message reassembly buffer, the transcript hash,
//! and the inbound/outbound byte buffers. It never touches a socket: callers
//! feed it received bytes with [`read_tls`](ConnectionCore::read_tls) and drain
//! bytes to transmit with [`write_tls`](ConnectionCore::write_tls). The
//! role-specific state machines (client/server) drive it by pulling decoded
//! messages and emitting handshake messages.

use super::super::codec::{ParsedRecord, read_record, write_record};
use super::super::crypto::{RecordCrypter, Transcript};
use crate::tls::{Alert, AlertDescription, ContentType, Error, ProtocolVersion};
use alloc::vec::Vec;

/// A decoded inbound message handed to the state machine.
pub(crate) enum Incoming {
    /// A complete handshake message, including its 4-byte header.
    Handshake(Vec<u8>),
    /// Application data arrived (the bytes are buffered for the reader).
    ApplicationData,
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
        }
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

    /// Sends a (plaintext) ChangeCipherSpec for middlebox compatibility.
    pub(crate) fn emit_ccs(&mut self) {
        write_record(
            &mut self.outbuf,
            ContentType::ChangeCipherSpec,
            ProtocolVersion::TLSv1_2,
            &[1],
        );
    }

    /// Sends application data (requires write keys to be installed).
    pub(crate) fn send_application_data(&mut self, data: &[u8]) {
        self.emit_record(ContentType::ApplicationData, data);
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
            Some(crypter) => {
                let rec = crypter.encrypt(ct, payload);
                self.outbuf.extend_from_slice(&rec);
            }
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
                fragment,
                len,
            }) = read_record(&self.inbuf)?
            else {
                return Ok(None);
            };
            let fragment = fragment.to_vec();
            self.inbuf.drain(..len);

            match content_type {
                ContentType::ChangeCipherSpec => continue, // middlebox compat
                ContentType::ApplicationData if self.read.is_some() => {
                    let (inner_ct, content) = self.decrypt(&fragment)?;
                    if let Some(msg) = self.dispatch_inner(inner_ct, content)? {
                        return Ok(Some(msg));
                    }
                }
                ContentType::Handshake => self.hs_pending.extend_from_slice(&fragment),
                ContentType::Alert => return Ok(Some(parse_alert(&fragment)?)),
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

    /// Routes the plaintext recovered from a protected record.
    fn dispatch_inner(
        &mut self,
        inner_ct: ContentType,
        content: Vec<u8>,
    ) -> Result<Option<Incoming>, Error> {
        match inner_ct {
            ContentType::Handshake => {
                self.hs_pending.extend_from_slice(&content);
                Ok(None)
            }
            ContentType::ApplicationData => {
                self.app_in.extend_from_slice(&content);
                Ok(Some(Incoming::ApplicationData))
            }
            ContentType::Alert => Ok(Some(parse_alert(&content)?)),
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
