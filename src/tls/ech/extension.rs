//! `encrypted_client_hello` extension codec (draft-ietf-tls-esni-22
//! §5).
//!
//! ```text
//! enum {
//!    outer(0),
//!    inner(1),
//!    (255)
//! } ECHClientHelloType;
//!
//! struct {
//!    ECHClientHelloType type;
//!    select (ECHClientHello.type) {
//!        case outer:
//!            HpkeSymmetricCipherSuite cipher_suite;
//!            uint8 config_id;
//!            opaque enc<0..2^16-1>;       // empty on HRR retry
//!            opaque payload<1..2^16-1>;
//!        case inner:
//!            Empty;
//!    };
//! } ECHClientHello;
//! ```

use super::config::HpkeSymCipherSuite;
use crate::tls::Error;
use alloc::vec::Vec;

/// `outer(0)`.
pub(crate) const TYPE_OUTER: u8 = 0;
/// `inner(1)`.
pub(crate) const TYPE_INNER: u8 = 1;

/// Decoded `encrypted_client_hello` extension body.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EchExtension {
    /// `outer` form — the body the client puts on the wire and the
    /// server attempts to decrypt.
    Outer {
        /// `(kdf_id, aead_id)` HPKE cipher suite.
        cipher_suite: HpkeSymCipherSuite,
        /// `config_id` lookup byte.
        config_id: u8,
        /// HPKE encapsulated key (`enc`). Empty on HRR retry per draft
        /// §6.1.5: the retry inherits the original `enc`.
        enc: Vec<u8>,
        /// AEAD ciphertext (encrypted inner CH + tag).
        payload: Vec<u8>,
    },
    /// `inner` form — the marker placed inside the inner CH so the
    /// reconstructed inner is distinguishable from a non-ECH CH.
    Inner,
}

impl EchExtension {
    /// Encode to a raw extension body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            EchExtension::Outer {
                cipher_suite,
                config_id,
                enc,
                payload,
            } => {
                out.push(TYPE_OUTER);
                cipher_suite.encode_into(&mut out);
                out.push(*config_id);
                let enc_len: u16 = u16::try_from(enc.len()).unwrap_or(u16::MAX);
                out.extend_from_slice(&enc_len.to_be_bytes());
                out.extend_from_slice(enc);
                let pl_len: u16 = u16::try_from(payload.len()).unwrap_or(u16::MAX);
                out.extend_from_slice(&pl_len.to_be_bytes());
                out.extend_from_slice(payload);
            }
            EchExtension::Inner => {
                out.push(TYPE_INNER);
            }
        }
        out
    }

    /// Parse a raw extension body.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut rd = Reader::new(buf);
        let ty = rd.read_u8()?;
        match ty {
            TYPE_OUTER => {
                if rd.remaining() < 5 {
                    return Err(Error::EchDecodeError);
                }
                let cs_buf = rd.read(4)?;
                let cipher_suite = HpkeSymCipherSuite::decode(cs_buf)?;
                let config_id = rd.read_u8()?;
                let enc_len = rd.read_u16()? as usize;
                let enc = rd.read(enc_len)?.to_vec();
                let pl_len = rd.read_u16()? as usize;
                if pl_len == 0 {
                    return Err(Error::EchDecodeError);
                }
                let payload = rd.read(pl_len)?.to_vec();
                if !rd.is_empty() {
                    return Err(Error::EchDecodeError);
                }
                Ok(EchExtension::Outer {
                    cipher_suite,
                    config_id,
                    enc,
                    payload,
                })
            }
            TYPE_INNER => {
                if !rd.is_empty() {
                    return Err(Error::EchDecodeError);
                }
                Ok(EchExtension::Inner)
            }
            _ => Err(Error::EchDecodeError),
        }
    }
}

/// Re-encode an outer-form ECH extension with the `payload` field
/// zeroed (same length). Used to compute `ClientHelloOuterAAD` for
/// the HPKE seal/open (draft §6.1.2).
// Staged alongside the `inner` ech_outer_extensions primitive; called once
// the HPKE seal/open is wired through the connection state machine.
#[allow(dead_code)]
pub(crate) fn zero_payload(ext_body: &[u8]) -> Result<Vec<u8>, Error> {
    // Fast path: only mutate the payload bytes; preserve the rest
    // verbatim. We have to re-parse to find the offset.
    let mut rd = Reader::new(ext_body);
    let ty = rd.read_u8()?;
    if ty != TYPE_OUTER {
        return Err(Error::EchDecodeError);
    }
    rd.read(4)?; // cipher_suite
    rd.read_u8()?; // config_id
    let enc_len = rd.read_u16()? as usize;
    rd.read(enc_len)?;
    let pl_len = rd.read_u16()? as usize;
    let pl_off = rd.pos;
    if pl_off.checked_add(pl_len).is_none() || ext_body.len() < pl_off + pl_len {
        return Err(Error::EchDecodeError);
    }

    let mut out = ext_body.to_vec();
    for b in &mut out[pl_off..pl_off + pl_len] {
        *b = 0;
    }
    Ok(out)
}

/// Locate the `payload` field inside an outer-form ECH extension
/// body. Returns `(offset, length)` measured from the start of the
/// extension body (i.e. `body[offset..offset + length]` are the
/// payload bytes). Errors on inner-form bodies or malformed bytes.
pub(crate) fn decode_outer_position(ext_body: &[u8]) -> Result<(usize, usize), Error> {
    let mut rd = Reader::new(ext_body);
    let ty = rd.read_u8()?;
    if ty != TYPE_OUTER {
        return Err(Error::EchDecodeError);
    }
    rd.read(4)?; // cipher_suite
    rd.read_u8()?; // config_id
    let enc_len = rd.read_u16()? as usize;
    rd.read(enc_len)?;
    let pl_len = rd.read_u16()? as usize;
    let pl_off = rd.pos;
    if pl_len == 0 || ext_body.len() < pl_off + pl_len {
        return Err(Error::EchDecodeError);
    }
    Ok((pl_off, pl_len))
}

/// Tiny reader; private to this module. Same shape as the one in
/// [`super::config`] but with [`Self::pos`] exposed so
/// [`zero_payload`] can compute the payload offset.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        if self.remaining() < 1 {
            return Err(Error::EchDecodeError);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        if self.remaining() < 2 {
            return Err(Error::EchDecodeError);
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.remaining() < n {
            return Err(Error::EchDecodeError);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}
