//! Handshake message structures and their wire encoding.
//!
//! Extensions are carried as raw `(type, body)` pairs at this layer; typed
//! construction/parsing of individual extensions lives in the handshake logic.

use super::{
    CipherSuite, ExtensionType, Random, ReadCursor, put_u8, put_u16, put_u32, with_len_u8,
    with_len_u16, with_len_u24,
};
use crate::tls::Error;
use alloc::vec::Vec;

/// Handshake message type codes.
pub(crate) mod hs_type {
    /// `hello_request` (RFC 5246 §7.4.1.1). TLS 1.2 only; body is empty. The
    /// server uses this to prompt renegotiation — we emit it for legacy peers
    /// only, and never accept it after the handshake.
    #[allow(dead_code)]
    pub(crate) const HELLO_REQUEST: u8 = 0;
    pub(crate) const CLIENT_HELLO: u8 = 1;
    pub(crate) const SERVER_HELLO: u8 = 2;
    pub(crate) const NEW_SESSION_TICKET: u8 = 4;
    /// `end_of_early_data` (RFC 8446 §4.5). Body is empty.
    pub(crate) const END_OF_EARLY_DATA: u8 = 5;
    pub(crate) const ENCRYPTED_EXTENSIONS: u8 = 8;
    pub(crate) const CERTIFICATE: u8 = 11;
    /// `server_key_exchange` (RFC 5246 §7.4.3). TLS 1.2 only.
    #[allow(dead_code)]
    pub(crate) const SERVER_KEY_EXCHANGE: u8 = 12;
    /// `certificate_request` (RFC 8446 §4.3.2 / RFC 5246 §7.4.4). Server-emitted
    /// to demand a client certificate; client replies with `Certificate`
    /// (possibly empty) and `CertificateVerify`.
    pub(crate) const CERTIFICATE_REQUEST: u8 = 13;
    /// `server_hello_done` (RFC 5246 §7.4.5). TLS 1.2 only; body is empty.
    #[allow(dead_code)]
    pub(crate) const SERVER_HELLO_DONE: u8 = 14;
    pub(crate) const CERTIFICATE_VERIFY: u8 = 15;
    /// `client_key_exchange` (RFC 5246 §7.4.7). TLS 1.2 only.
    #[allow(dead_code)]
    pub(crate) const CLIENT_KEY_EXCHANGE: u8 = 16;
    pub(crate) const FINISHED: u8 = 20;
    pub(crate) const KEY_UPDATE: u8 = 24;
}

/// A raw extension: its type and opaque body.
pub(crate) type RawExtension = (ExtensionType, Vec<u8>);

/// Reads one handshake message header, returning `(msg_type, body)`.
pub(crate) fn read_handshake<'a>(cursor: &mut ReadCursor<'a>) -> Result<(u8, &'a [u8]), Error> {
    let msg_type = cursor.u8()?;
    let body = cursor.vec_u24()?;
    Ok((msg_type, body))
}

fn encode_extensions(out: &mut Vec<u8>, extensions: &[RawExtension]) {
    with_len_u16(out, |b| {
        for (ty, data) in extensions {
            put_u16(b, ty.0);
            with_len_u16(b, |b| b.extend_from_slice(data));
        }
    });
}

fn parse_extensions(bytes: &[u8]) -> Result<Vec<RawExtension>, Error> {
    let mut c = ReadCursor::new(bytes);
    let mut out: Vec<RawExtension> = Vec::new();
    while !c.is_empty() {
        let ty = ExtensionType(c.u16()?);
        let data = c.vec_u16()?;
        // RFC 8446 §4.2: every extension type may appear at most once in a
        // single handshake message.
        if out.iter().any(|(t, _)| *t == ty) {
            return Err(Error::IllegalParameter);
        }
        out.push((ty, data.to_vec()));
    }
    Ok(out)
}

fn read_random(c: &mut ReadCursor<'_>) -> Result<Random, Error> {
    let mut r = [0u8; 32];
    r.copy_from_slice(c.take(32)?);
    Ok(r)
}

/// A `ClientHello` handshake message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientHello {
    /// `legacy_version` from the wire (typically `0x0303`). A TLS 1.3 client's
    /// CH still carries `0x0303` here, with the *real* offered versions in
    /// `supported_versions`. We expose it so the TLS 1.2 server can reject any
    /// codepoint below 0x0303 outright (RFC 5246 §E.1: downgrade probes).
    pub(crate) legacy_version: u16,
    pub(crate) random: Random,
    pub(crate) session_id: Vec<u8>,
    pub(crate) cipher_suites: Vec<CipherSuite>,
    pub(crate) extensions: Vec<RawExtension>,
}

impl ClientHello {
    /// Encodes the full handshake message (type + length + body).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u8(&mut out, hs_type::CLIENT_HELLO);
        with_len_u24(&mut out, |b| {
            put_u16(b, self.legacy_version);
            b.extend_from_slice(&self.random);
            with_len_u8(b, |b| b.extend_from_slice(&self.session_id));
            with_len_u16(b, |b| {
                for cs in &self.cipher_suites {
                    put_u16(b, cs.0);
                }
            });
            with_len_u8(b, |b| b.push(0)); // compression: null only
            encode_extensions(b, &self.extensions);
        });
        out
    }

    /// Decodes a `ClientHello` from a handshake message body.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut c = ReadCursor::new(body);
        let legacy_version = c.u16()?;
        let random = read_random(&mut c)?;
        let session_id = c.vec_u8()?.to_vec();
        let cs_bytes = c.vec_u16()?;
        let mut cs = ReadCursor::new(cs_bytes);
        let mut cipher_suites = Vec::new();
        while !cs.is_empty() {
            cipher_suites.push(CipherSuite(cs.u16()?));
        }
        let _compression = c.vec_u8()?;
        let extensions = parse_extensions(c.vec_u16()?)?;
        c.expect_empty()?;
        Ok(ClientHello {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            extensions,
        })
    }
}

/// A `ServerHello` handshake message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerHello {
    pub(crate) random: Random,
    pub(crate) session_id: Vec<u8>,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) extensions: Vec<RawExtension>,
}

impl ServerHello {
    /// Encodes the full handshake message (type + length + body).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u8(&mut out, hs_type::SERVER_HELLO);
        with_len_u24(&mut out, |b| {
            put_u16(b, 0x0303); // legacy_version
            b.extend_from_slice(&self.random);
            with_len_u8(b, |b| b.extend_from_slice(&self.session_id));
            put_u16(b, self.cipher_suite.0);
            put_u8(b, 0); // legacy_compression_method
            encode_extensions(b, &self.extensions);
        });
        out
    }

    /// Decodes a `ServerHello` from a handshake message body. RFC 8446
    /// §4.1.3 / RFC 5246 §7.4.1.3: `legacy_version` MUST be `0x0303` (TLS
    /// 1.2 wire) and `legacy_compression_method` MUST be `0`.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut c = ReadCursor::new(body);
        let legacy_version = c.u16()?;
        if legacy_version != 0x0303 {
            return Err(Error::Decode);
        }
        let random = read_random(&mut c)?;
        let session_id = c.vec_u8()?.to_vec();
        let cipher_suite = CipherSuite(c.u16()?);
        let compression = c.u8()?;
        if compression != 0 {
            return Err(Error::Decode);
        }
        let extensions = parse_extensions(c.vec_u16()?)?;
        c.expect_empty()?;
        Ok(ServerHello {
            random,
            session_id,
            cipher_suite,
            extensions,
        })
    }
}

/// A `KeyUpdate` handshake message (RFC 8446 §4.6.3). The single body byte is
/// `0` (update_not_requested) or `1` (update_requested); any other value MUST
/// be rejected with `illegal_parameter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyUpdate {
    /// If `true`, the peer wants us to send our own `KeyUpdate` in reply.
    pub(crate) request_update: bool,
}

impl KeyUpdate {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u8(&mut out, hs_type::KEY_UPDATE);
        with_len_u24(&mut out, |b| {
            put_u8(b, if self.request_update { 1 } else { 0 })
        });
        out
    }

    pub(crate) fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut c = ReadCursor::new(body);
        let request_update = match c.u8()? {
            0 => false,
            1 => true,
            _ => return Err(Error::IllegalParameter),
        };
        c.expect_empty()?;
        Ok(KeyUpdate { request_update })
    }
}

/// A `NewSessionTicket` handshake message (RFC 8446 §4.6.1).
///
/// Servers may issue one or more of these any time after the handshake to
/// enable PSK resumption on subsequent connections. The `extensions` field
/// most commonly carries the `early_data` extension with the server's
/// maximum-early-data budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewSessionTicket {
    /// Hint, in seconds, for how long the ticket may be reused (max 7 days).
    pub(crate) ticket_lifetime: u32,
    /// Randomizer added to the client's reported ticket-age before sending,
    /// so age values do not link the same ticket across resumptions.
    pub(crate) ticket_age_add: u32,
    /// Per-ticket nonce, used in `HKDF-Expand-Label(rms, "resumption", nonce)`
    /// to derive the PSK.
    pub(crate) ticket_nonce: Vec<u8>,
    /// Opaque ticket bytes — the client presents these unchanged on resume.
    pub(crate) ticket: Vec<u8>,
    /// Per-ticket extensions (typically `early_data` only).
    pub(crate) extensions: Vec<RawExtension>,
}

impl NewSessionTicket {
    /// Encodes the full handshake message (type + length + body).
    // Used by the server-side NST emission (lands in a follow-up commit) and
    // by codec tests; keep available.
    #[allow(dead_code)]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u8(&mut out, hs_type::NEW_SESSION_TICKET);
        with_len_u24(&mut out, |b| {
            put_u32(b, self.ticket_lifetime);
            put_u32(b, self.ticket_age_add);
            with_len_u8(b, |b| b.extend_from_slice(&self.ticket_nonce));
            with_len_u16(b, |b| b.extend_from_slice(&self.ticket));
            encode_extensions(b, &self.extensions);
        });
        out
    }

    /// Decodes a `NewSessionTicket` from a handshake message body.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut c = ReadCursor::new(body);
        let ticket_lifetime = c.u32()?;
        let ticket_age_add = c.u32()?;
        let ticket_nonce = c.vec_u8()?.to_vec();
        let ticket = c.vec_u16()?.to_vec();
        // RFC 8446 §4.6.1: ticket length is `1..2^16-1`; zero-length tickets
        // are not permitted.
        if ticket.is_empty() {
            return Err(Error::Decode);
        }
        let extensions = parse_extensions(c.vec_u16()?)?;
        c.expect_empty()?;
        Ok(NewSessionTicket {
            ticket_lifetime,
            ticket_age_add,
            ticket_nonce,
            ticket,
            extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_roundtrip() {
        let ch = ClientHello {
            legacy_version: 0x0303,
            random: [0x11; 32],
            session_id: alloc::vec![0xab; 32],
            cipher_suites: alloc::vec![
                CipherSuite::AES_128_GCM_SHA256,
                CipherSuite::AES_256_GCM_SHA384,
            ],
            extensions: alloc::vec![
                (
                    ExtensionType::SUPPORTED_VERSIONS,
                    alloc::vec![0x02, 0x03, 0x04]
                ),
                (ExtensionType::KEY_SHARE, alloc::vec![1, 2, 3, 4]),
            ],
        };
        let bytes = ch.encode();
        assert_eq!(bytes[0], hs_type::CLIENT_HELLO);

        let mut c = ReadCursor::new(&bytes);
        let (ty, body) = read_handshake(&mut c).unwrap();
        assert_eq!(ty, hs_type::CLIENT_HELLO);
        assert_eq!(ClientHello::decode(body).unwrap(), ch);
    }

    #[test]
    fn server_hello_roundtrip() {
        let sh = ServerHello {
            random: [0x22; 32],
            session_id: alloc::vec![0xcd; 32],
            cipher_suite: CipherSuite::AES_256_GCM_SHA384,
            extensions: alloc::vec![(ExtensionType::SUPPORTED_VERSIONS, alloc::vec![0x03, 0x04])],
        };
        let bytes = sh.encode();
        let mut c = ReadCursor::new(&bytes);
        let (ty, body) = read_handshake(&mut c).unwrap();
        assert_eq!(ty, hs_type::SERVER_HELLO);
        assert_eq!(ServerHello::decode(body).unwrap(), sh);
    }

    #[test]
    fn rejects_truncated() {
        let mut c = ReadCursor::new(&[1, 0, 0, 5, 0x03]); // claims 5 body bytes, has 1
        assert!(read_handshake(&mut c).is_err());
    }

    #[test]
    fn new_session_ticket_roundtrip() {
        let nst = NewSessionTicket {
            ticket_lifetime: 7200,
            ticket_age_add: 0x12345678,
            ticket_nonce: alloc::vec![0xa1, 0xa2],
            ticket: alloc::vec![0xb0; 48],
            // No extensions for the standard case.
            extensions: Vec::new(),
        };
        let bytes = nst.encode();
        assert_eq!(bytes[0], hs_type::NEW_SESSION_TICKET);
        let mut c = ReadCursor::new(&bytes);
        let (ty, body) = read_handshake(&mut c).unwrap();
        assert_eq!(ty, hs_type::NEW_SESSION_TICKET);
        assert_eq!(NewSessionTicket::decode(body).unwrap(), nst);
    }

    #[test]
    fn new_session_ticket_rejects_empty_ticket() {
        // ticket_lifetime=0, ticket_age_add=0, nonce=[], ticket=[], extensions=[]
        let body = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(NewSessionTicket::decode(&body).is_err());
    }

    #[test]
    fn new_session_ticket_with_early_data_ext() {
        // RFC 8446 §4.6.1: NST extensions may contain `early_data` carrying
        // a u32 max_early_data_size.
        let nst = NewSessionTicket {
            ticket_lifetime: 3600,
            ticket_age_add: 0xdeadbeef,
            ticket_nonce: alloc::vec![1, 2, 3, 4],
            ticket: alloc::vec![0xcc; 100],
            extensions: alloc::vec![(
                ExtensionType(0x002a),               // early_data
                alloc::vec![0x00, 0x00, 0x40, 0x00], // max_early_data_size = 16384
            )],
        };
        let body = &nst.encode()[4..]; // skip type + 3-byte length
        assert_eq!(NewSessionTicket::decode(body).unwrap(), nst);
    }
}
