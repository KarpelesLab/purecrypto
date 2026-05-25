//! Handshake message structures and their wire encoding.
//!
//! Extensions are carried as raw `(type, body)` pairs at this layer; typed
//! construction/parsing of individual extensions lives in the handshake logic.

use super::{
    CipherSuite, ExtensionType, Random, ReadCursor, put_u8, put_u16, with_len_u8, with_len_u16,
    with_len_u24,
};
use crate::tls::Error;
use alloc::vec::Vec;

/// Handshake message type codes.
pub(crate) mod hs_type {
    pub(crate) const CLIENT_HELLO: u8 = 1;
    pub(crate) const SERVER_HELLO: u8 = 2;
    pub(crate) const ENCRYPTED_EXTENSIONS: u8 = 8;
    pub(crate) const CERTIFICATE: u8 = 11;
    pub(crate) const CERTIFICATE_VERIFY: u8 = 15;
    pub(crate) const FINISHED: u8 = 20;
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
    let mut out = Vec::new();
    while !c.is_empty() {
        let ty = ExtensionType(c.u16()?);
        let data = c.vec_u16()?;
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
            put_u16(b, 0x0303); // legacy_version = TLS 1.2
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
        let _legacy_version = c.u16()?;
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

    /// Decodes a `ServerHello` from a handshake message body.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut c = ReadCursor::new(body);
        let _legacy_version = c.u16()?;
        let random = read_random(&mut c)?;
        let session_id = c.vec_u8()?.to_vec();
        let cipher_suite = CipherSuite(c.u16()?);
        let _compression = c.u8()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_roundtrip() {
        let ch = ClientHello {
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
}
