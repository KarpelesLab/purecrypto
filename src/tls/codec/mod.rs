//! TLS wire encoding/decoding: a small cursor + length-prefix helpers, plus
//! record framing and handshake message structures.

pub(crate) mod extension;
mod handshake;
pub(crate) mod handshake12;
mod primitives;
mod record;

#[allow(unused_imports)]
pub(crate) use handshake::{
    ClientHello, KeyUpdate, NewSessionTicket, RawExtension, ServerHello, hs_type, read_handshake,
};
#[allow(unused_imports)]
pub(crate) use handshake12::{
    CertificateRequest12, ClientKeyExchange, HelloRequest, NewSessionTicket12, ServerHelloDone,
    ServerKeyExchange, signed_message,
};
#[allow(unused_imports)]
pub(crate) use primitives::{
    CipherSuite, ExtensionType, NamedGroup, Random, SignatureScheme, cert_type,
};
#[allow(unused_imports)]
pub(crate) use record::{ParsedRecord, is_legal_record_version, read_record, write_record};

use super::Error;
use alloc::vec::Vec;

/// A cursor over a byte slice for decoding TLS structures. Every read is
/// bounds-checked and yields [`Error::Decode`] on underflow.
pub(crate) struct ReadCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ReadCursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        ReadCursor { data, pos: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Decode)?;
        if end > self.data.len() {
            return Err(Error::Decode);
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u24(&mut self) -> Result<usize, Error> {
        let b = self.take(3)?;
        Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
    }

    /// Reads a `u8`-length-prefixed byte string.
    pub(crate) fn vec_u8(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    /// Reads a `u16`-length-prefixed byte string.
    pub(crate) fn vec_u16(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    /// Reads a `u24`-length-prefixed byte string.
    pub(crate) fn vec_u24(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u24()?;
        self.take(n)
    }

    /// Succeeds only if all input has been consumed.
    pub(crate) fn expect_empty(&self) -> Result<(), Error> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::Decode)
        }
    }
}

#[inline]
pub(crate) fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

#[inline]
pub(crate) fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

// Used by NewSessionTicket emission (server side, lands in a follow-up commit)
// and currently only exercised by the codec tests; keep around.
#[allow(dead_code)]
#[inline]
pub(crate) fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Writes a block produced by `f`, prefixed by its `u8` length. The
/// produced block must fit a single byte; in release builds an overflowing
/// length silently truncates, but `debug_assertions` make the bug visible.
pub(crate) fn with_len_u8(out: &mut Vec<u8>, f: impl FnOnce(&mut Vec<u8>)) {
    let pos = out.len();
    out.push(0);
    f(out);
    let len = out.len() - pos - 1;
    debug_assert!(len <= 0xFF, "with_len_u8: block of {len} bytes exceeds 255");
    out[pos] = len as u8;
}

/// Writes a block produced by `f`, prefixed by its `u16` length. The
/// produced block must fit two bytes; in release builds an overflowing
/// length silently truncates, but `debug_assertions` make the bug visible.
pub(crate) fn with_len_u16(out: &mut Vec<u8>, f: impl FnOnce(&mut Vec<u8>)) {
    let pos = out.len();
    out.extend_from_slice(&[0, 0]);
    f(out);
    let inner = out.len() - pos - 2;
    debug_assert!(
        inner <= 0xFFFF,
        "with_len_u16: block of {inner} bytes exceeds 65535",
    );
    let len = inner as u16;
    out[pos..pos + 2].copy_from_slice(&len.to_be_bytes());
}

/// Writes a block produced by `f`, prefixed by its `u24` length. The
/// produced block must fit three bytes; in release builds an overflowing
/// length silently truncates, but `debug_assertions` make the bug visible.
pub(crate) fn with_len_u24(out: &mut Vec<u8>, f: impl FnOnce(&mut Vec<u8>)) {
    let pos = out.len();
    out.extend_from_slice(&[0, 0, 0]);
    f(out);
    let inner = out.len() - pos - 3;
    debug_assert!(
        inner <= 0xFF_FFFF,
        "with_len_u24: block of {inner} bytes exceeds 16_777_215",
    );
    let len = inner as u32;
    out[pos..pos + 3].copy_from_slice(&len.to_be_bytes()[1..]);
}
