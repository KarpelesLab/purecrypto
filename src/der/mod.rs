//! Minimal ASN.1 DER (Distinguished Encoding Rules) reader and writer.
//!
//! Covers the subset needed for cryptographic key and certificate encoding:
//! `INTEGER`, `BIT STRING`, `OCTET STRING`, `NULL`, `OBJECT IDENTIFIER`, and
//! `SEQUENCE`. The [`Reader`] borrows its input and is `no_std`/allocation
//! free; the encoding helpers require the `alloc` feature.

#[cfg(feature = "alloc")]
mod oid;
#[cfg(feature = "alloc")]
mod pem;
#[cfg(feature = "alloc")]
mod writer;

#[cfg(feature = "alloc")]
pub use oid::{encode_oid_arcs, oid_tlv, oid_to_string, parse_oid};
#[cfg(feature = "alloc")]
pub use pem::{base64_decode, base64_encode, pem_decode, pem_encode};
#[cfg(feature = "alloc")]
pub use writer::{
    encode_bit_string, encode_boolean, encode_context, encode_integer, encode_null,
    encode_octet_string, encode_oid, encode_sequence, encode_string, encode_tlv,
};

/// DER tag bytes for the supported types.
pub mod tag {
    /// `BOOLEAN`.
    pub const BOOLEAN: u8 = 0x01;
    /// `INTEGER`.
    pub const INTEGER: u8 = 0x02;
    /// `BIT STRING`.
    pub const BIT_STRING: u8 = 0x03;
    /// `OCTET STRING`.
    pub const OCTET_STRING: u8 = 0x04;
    /// `NULL`.
    pub const NULL: u8 = 0x05;
    /// `OBJECT IDENTIFIER`.
    pub const OID: u8 = 0x06;
    /// `UTF8String`.
    pub const UTF8_STRING: u8 = 0x0c;
    /// `PrintableString`.
    pub const PRINTABLE_STRING: u8 = 0x13;
    /// `IA5String`.
    pub const IA5_STRING: u8 = 0x16;
    /// `UTCTime`.
    pub const UTC_TIME: u8 = 0x17;
    /// `GeneralizedTime`.
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// `SEQUENCE` (constructed).
    pub const SEQUENCE: u8 = 0x30;
    /// `SET` (constructed).
    pub const SET: u8 = 0x31;

    /// Constructed context-specific tag `[n]`.
    pub const fn context(n: u8) -> u8 {
        0xA0 | n
    }
}

/// An error encountered while decoding DER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Ran out of input before a structure was complete.
    Truncated,
    /// A tag did not match what was expected.
    UnexpectedTag {
        /// The tag the parser required.
        expected: u8,
        /// The tag actually found.
        found: u8,
    },
    /// A length was non-minimal, indefinite, or too large.
    InvalidLength,
    /// A value was structurally invalid (e.g. a malformed `NULL` or
    /// unsupported `BIT STRING` padding).
    Malformed,
    /// Unconsumed bytes remained after parsing.
    TrailingData,
    /// A PEM document or its Base64 body was malformed (e.g. missing
    /// `-----BEGIN/END-----` markers, label mismatch, or invalid Base64).
    Pem,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated => f.write_str("unexpected end of DER input"),
            Error::UnexpectedTag { expected, found } => {
                write!(
                    f,
                    "unexpected DER tag {found:#04x} (expected {expected:#04x})"
                )
            }
            Error::InvalidLength => f.write_str("invalid DER length encoding"),
            Error::Malformed => f.write_str("malformed DER value"),
            Error::TrailingData => f.write_str("trailing data after DER value"),
            Error::Pem => f.write_str("malformed PEM document"),
        }
    }
}

impl core::error::Error for Error {}

/// A cursor that reads DER values from a borrowed byte slice.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Creates a reader over `data`.
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    /// Returns true if all input has been consumed.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.data.len() < n {
            return Err(Error::Truncated);
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    /// Reads a DER length (definite form only, minimally encoded).
    fn read_length(&mut self) -> Result<usize, Error> {
        let first = self.read_u8()?;
        if first < 0x80 {
            return Ok(first as usize);
        }
        let count = (first & 0x7f) as usize;
        // 0x80 is the (forbidden) indefinite form; cap multi-byte lengths at
        // what usize can hold.
        if count == 0 || count > core::mem::size_of::<usize>() {
            return Err(Error::InvalidLength);
        }
        let mut len = 0usize;
        for _ in 0..count {
            len = (len << 8) | self.read_u8()? as usize;
        }
        // Must have used the short form if it fit.
        if len < 0x80 {
            return Err(Error::InvalidLength);
        }
        Ok(len)
    }

    /// Reads a tag-length-value with the given `expected_tag`, returning the
    /// value bytes.
    pub fn read_tlv(&mut self, expected_tag: u8) -> Result<&'a [u8], Error> {
        let tag = self.read_u8()?;
        if tag != expected_tag {
            return Err(Error::UnexpectedTag {
                expected: expected_tag,
                found: tag,
            });
        }
        let len = self.read_length()?;
        self.take(len)
    }

    /// Reads a `SEQUENCE`, returning a sub-reader over its contents.
    pub fn read_sequence(&mut self) -> Result<Reader<'a>, Error> {
        Ok(Reader::new(self.read_tlv(tag::SEQUENCE)?))
    }

    /// Reads an `INTEGER`, returning its raw (big-endian, possibly
    /// `0x00`-prefixed) content bytes.
    pub fn read_integer_bytes(&mut self) -> Result<&'a [u8], Error> {
        self.read_tlv(tag::INTEGER)
    }

    /// Reads an `OCTET STRING`.
    pub fn read_octet_string(&mut self) -> Result<&'a [u8], Error> {
        self.read_tlv(tag::OCTET_STRING)
    }

    /// Reads an `OBJECT IDENTIFIER`, returning its encoded body.
    pub fn read_oid(&mut self) -> Result<&'a [u8], Error> {
        self.read_tlv(tag::OID)
    }

    /// Reads a `NULL`.
    pub fn read_null(&mut self) -> Result<(), Error> {
        if self.read_tlv(tag::NULL)?.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    /// Reads a `BIT STRING`, returning its bits. Only the common case of zero
    /// unused bits is supported.
    pub fn read_bit_string(&mut self) -> Result<&'a [u8], Error> {
        match self.read_tlv(tag::BIT_STRING)?.split_first() {
            Some((0, rest)) => Ok(rest),
            _ => Err(Error::Malformed),
        }
    }

    /// Reads a `BOOLEAN`.
    pub fn read_boolean(&mut self) -> Result<bool, Error> {
        match self.read_tlv(tag::BOOLEAN)? {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(Error::Malformed),
        }
    }

    /// Returns the tag of the next value without consuming it, or `None` at end
    /// of input. Useful for optional / `DEFAULT` fields.
    #[inline]
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Reads a tag-length-value of any tag, returning `(tag, value)`.
    pub fn read_any(&mut self) -> Result<(u8, &'a [u8]), Error> {
        let tag = self.read_u8()?;
        let len = self.read_length()?;
        Ok((tag, self.take(len)?))
    }

    /// Succeeds only if all input has been consumed.
    pub fn finish(self) -> Result<(), Error> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(Error::TrailingData)
        }
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn roundtrip_sequence_of_integers() {
        let seq =
            encode_sequence(&[encode_integer(&[1]), encode_integer(&[0x01, 0x00, 0x01])].concat());
        // SEQUENCE { INTEGER 1, INTEGER 65537 }
        assert_eq!(
            seq,
            vec![0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01]
        );

        let mut r = Reader::new(&seq);
        let mut inner = r.read_sequence().unwrap();
        assert_eq!(inner.read_integer_bytes().unwrap(), &[0x01]);
        assert_eq!(inner.read_integer_bytes().unwrap(), &[0x01, 0x00, 0x01]);
        inner.finish().unwrap();
        r.finish().unwrap();
    }

    #[test]
    fn integer_high_bit_gets_zero_prefix() {
        // 0x80 has its top bit set, so DER prepends 0x00 to keep it positive.
        assert_eq!(encode_integer(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        // Leading zeros are stripped.
        assert_eq!(encode_integer(&[0x00, 0x00, 0x2a]), vec![0x02, 0x01, 0x2a]);
    }

    #[test]
    fn long_form_length() {
        let content = vec![0xabu8; 200];
        let tlv = encode_octet_string(&content);
        // 200 = 0xC8 needs long form: 0x81 0xC8.
        assert_eq!(&tlv[..2], &[0x04, 0x81]);
        assert_eq!(tlv[2], 200);
        let mut r = Reader::new(&tlv);
        assert_eq!(r.read_octet_string().unwrap(), &content[..]);
    }

    #[test]
    fn rejects_malformed() {
        // Truncated: claims 5 bytes but only 2 follow.
        assert_eq!(
            Reader::new(&[0x04, 0x05, 0x01, 0x02]).read_octet_string(),
            Err(Error::Truncated)
        );
        // Wrong tag.
        assert_eq!(
            Reader::new(&[0x02, 0x01, 0x01]).read_octet_string(),
            Err(Error::UnexpectedTag {
                expected: tag::OCTET_STRING,
                found: tag::INTEGER
            })
        );
        // Trailing data.
        let mut r = Reader::new(&[0x02, 0x01, 0x01, 0xff]);
        r.read_integer_bytes().unwrap();
        assert_eq!(r.finish(), Err(Error::TrailingData));
    }

    #[test]
    fn bit_string_and_null() {
        let bs = encode_bit_string(&[0xde, 0xad]);
        assert_eq!(bs, vec![0x03, 0x03, 0x00, 0xde, 0xad]);
        assert_eq!(Reader::new(&bs).read_bit_string().unwrap(), &[0xde, 0xad]);

        let n = encode_null();
        assert_eq!(n, vec![0x05, 0x00]);
        Reader::new(&n).read_null().unwrap();
    }
}
