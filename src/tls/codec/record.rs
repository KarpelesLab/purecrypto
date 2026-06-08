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
    /// Record-layer `legacy_version`. RFC 5246 §6.2.1 / RFC 8446 §5.1 leave
    /// this field nominally version-specific but in practice it is always
    /// 0x0301..=0x0303 on the wire; pre-1.2 codepoints (`0x0300` SSL 3.0 and
    /// below) are explicit downgrade attempts and are rejected upstream.
    pub(crate) version: u16,
    pub(crate) fragment: &'a [u8],
    /// Total bytes consumed (header + fragment).
    pub(crate) len: usize,
}

/// Attempts to parse one record from the front of `buf`. Returns `Ok(None)` if
/// more bytes are needed.
///
/// The record `legacy_version` field is returned but not validated here so
/// that this helper stays useful for both TLS 1.2 and TLS 1.3 record paths.
/// Each protocol path applies its own version filter via
/// [`is_legal_record_version`] — TLS 1.2 / 1.3 accept `0x0301..=0x0303` and
/// reject anything else (notably SSL 3.0, `0x0300`).
pub(crate) fn read_record(buf: &[u8]) -> Result<Option<ParsedRecord<'_>>, Error> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let content_type = ContentType::from_u8(buf[0]);
    let version = u16::from_be_bytes([buf[1], buf[2]]);
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
        version,
        fragment: &buf[5..total],
        len: total,
    }))
}

/// Returns `true` iff `version` is a record-layer `legacy_version` we accept.
/// RFC 5246 / RFC 8446: TLS 1.2 and 1.3 mandate the record header carry
/// `0x0301`, `0x0302`, or `0x0303`; SSL 3.0 (`0x0300`) and unknown codepoints
/// are downgrade attempts and rejected with `protocol_version`.
pub(crate) fn is_legal_record_version(version: u16) -> bool {
    // The opt-in legacy build additionally accepts SSL 3.0 (`0x0300`) record
    // headers; without `tls-legacy` SSLv3 is treated as a downgrade attempt.
    #[cfg(feature = "tls-legacy")]
    {
        matches!(version, 0x0300..=0x0303)
    }
    #[cfg(not(feature = "tls-legacy"))]
    {
        matches!(version, 0x0301..=0x0303)
    }
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
        assert_eq!(rec.version, 0x0303);
        assert_eq!(rec.fragment, b"hello");
        assert_eq!(rec.len, out.len());

        // A truncated buffer needs more data.
        assert!(read_record(&out[..4]).unwrap().is_none());
        assert!(read_record(&out[..7]).unwrap().is_none());
    }

    #[test]
    fn record_version_filter() {
        // TLS 1.0 / 1.1 / 1.2 record versions: accept.
        assert!(is_legal_record_version(0x0301));
        assert!(is_legal_record_version(0x0302));
        assert!(is_legal_record_version(0x0303));
        // SSL 3.0 (0x0300): accepted only on the opt-in legacy build, otherwise
        // a downgrade attempt.
        #[cfg(feature = "tls-legacy")]
        assert!(is_legal_record_version(0x0300));
        #[cfg(not(feature = "tls-legacy"))]
        assert!(!is_legal_record_version(0x0300));
        // SSL 2.0 and earlier: always rejected.
        assert!(!is_legal_record_version(0x0200));
        // TLS 1.3 wire version is 0x0303 in the record header (the real version
        // lives in `supported_versions`), so 0x0304 should never appear here.
        assert!(!is_legal_record_version(0x0304));
        // Garbage.
        assert!(!is_legal_record_version(0xFFFF));
    }
}
