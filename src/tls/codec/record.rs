//! TLS record-layer framing (the 5-byte header).
//!
//! A record is `ContentType(1) || legacy_version(2) || length(2) || fragment`.
//! This is version-stable: TLS 1.3 wraps all post-handshake records as
//! `application_data` and protects the fragment with AEAD (handled in the
//! record-protection layer); here we only frame the opaque payload.

use super::{put_u8, put_u16};
use crate::tls::{ContentType, Error, ProtocolVersion};
use alloc::vec::Vec;

/// Maximum plaintext/ciphertext fragment length (`2^14 + 256`, the TLS 1.3
/// ciphertext cap).
pub(crate) const MAX_FRAGMENT: usize = (1 << 14) + 256;

/// One parsed record: its content type, fragment, and total wire length.
pub(crate) struct ParsedRecord<'a> {
    pub(crate) content_type: ContentType,
    pub(crate) fragment: &'a [u8],
    /// Total bytes consumed (header + fragment).
    pub(crate) len: usize,
}

/// Attempts to parse one record from the front of `buf`. Returns `Ok(None)` if
/// more bytes are needed.
pub(crate) fn read_record(buf: &[u8]) -> Result<Option<ParsedRecord<'_>>, Error> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let content_type = ContentType::from_u8(buf[0]);
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if len > MAX_FRAGMENT {
        return Err(Error::Decode);
    }
    let total = 5 + len;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(ParsedRecord {
        content_type,
        fragment: &buf[5..total],
        len: total,
    }))
}

/// Writes a record (header + `fragment`) to `out`.
pub(crate) fn write_record(
    out: &mut Vec<u8>,
    ct: ContentType,
    version: ProtocolVersion,
    fragment: &[u8],
) {
    put_u8(out, ct.as_u8());
    put_u16(out, version.as_u16());
    put_u16(out, fragment.len() as u16);
    out.extend_from_slice(fragment);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_roundtrip_and_partial() {
        let mut out = Vec::new();
        write_record(
            &mut out,
            ContentType::Handshake,
            ProtocolVersion::TLSv1_2,
            b"hello",
        );
        assert_eq!(out[0], 22); // handshake
        assert_eq!(&out[1..3], &[0x03, 0x03]); // TLS 1.2 legacy version
        assert_eq!(&out[3..5], &[0x00, 0x05]);

        let rec = read_record(&out).unwrap().unwrap();
        assert_eq!(rec.content_type, ContentType::Handshake);
        assert_eq!(rec.fragment, b"hello");
        assert_eq!(rec.len, out.len());

        // A truncated buffer needs more data.
        assert!(read_record(&out[..4]).unwrap().is_none());
        assert!(read_record(&out[..7]).unwrap().is_none());
    }
}
