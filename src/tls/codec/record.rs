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
/// ciphertext cap, RFC 8446 §5.2). Also the bound applied to TLS 1.2 AEAD
/// records: their expansion is at most 24 bytes (RFC 5288 §3), so the
/// tighter cap costs nothing and rejects garbage sooner.
pub(crate) const MAX_FRAGMENT: usize = (1 << 14) + 256;

/// Maximum ciphertext fragment length for a TLS 1.2 block-cipher (CBC)
/// record: `2^14 + 2048` (RFC 5246 §6.2.3). A CBC record carries the IV,
/// up to a 32-byte MAC and up to 256 bytes of padding on top of the 2^14
/// plaintext — and peers such as GnuTLS deliberately use random padding
/// lengths, so a full-size record can legitimately exceed [`MAX_FRAGMENT`].
#[cfg(feature = "tls-legacy")]
pub(crate) const MAX_FRAGMENT_BLOCK: usize = (1 << 14) + 2048;

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
/// more bytes are needed, and `Err(RecordOverflow)` for a length field past
/// [`MAX_FRAGMENT`] (RFC 8446 §5.2 / RFC 5246 §6.2.3: `record_overflow`).
///
/// The record `legacy_version` field is returned but not validated here so
/// that this helper stays useful for both TLS 1.2 and TLS 1.3 record paths.
/// Each protocol path applies its own version filter via
/// [`is_legal_record_version`] — TLS 1.2 / 1.3 accept `0x0301..=0x0303` and
/// reject anything else (notably SSL 3.0, `0x0300`).
pub(crate) fn read_record(buf: &[u8]) -> Result<Option<ParsedRecord<'_>>, Error> {
    read_record_with_max(buf, MAX_FRAGMENT)
}

/// [`read_record`] with an explicit fragment-length ceiling. The TLS 1.2
/// engines pass the bound their negotiated record protection permits —
/// [`MAX_FRAGMENT_BLOCK`] once a CBC suite's read key is installed,
/// [`MAX_FRAGMENT`] otherwise; the TLS 1.3 core always uses the latter.
pub(crate) fn read_record_with_max(
    buf: &[u8],
    max_fragment: usize,
) -> Result<Option<ParsedRecord<'_>>, Error> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let content_type = ContentType::from_u8(buf[0]);
    let version = u16::from_be_bytes([buf[1], buf[2]]);
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if len > max_fragment {
        return Err(Error::RecordOverflow);
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

    /// RFC 8446 §5.2: a record whose length field exceeds `2^14 + 256` is a
    /// `record_overflow`, not a `decode_error`.
    #[test]
    fn oversized_length_field_is_record_overflow() {
        let len = (MAX_FRAGMENT + 1) as u16;
        let mut hdr = alloc::vec![23u8, 0x03, 0x03];
        hdr.extend_from_slice(&len.to_be_bytes());
        assert!(matches!(read_record(&hdr), Err(Error::RecordOverflow)));
        let ok = (MAX_FRAGMENT as u16).to_be_bytes();
        assert!(
            read_record(&[23u8, 0x03, 0x03, ok[0], ok[1]])
                .unwrap()
                .is_none()
        );
    }

    /// RFC 5246 §6.2.3: a TLS 1.2 block-cipher record may run to
    /// `2^14 + 2048` bytes; the bound is the caller's choice, and the
    /// default stays at the AEAD / TLS 1.3 figure.
    #[cfg(feature = "tls-legacy")]
    #[test]
    fn block_cipher_bound_admits_larger_records() {
        fn header(len: usize) -> [u8; 5] {
            let l = (len as u16).to_be_bytes();
            [23u8, 0x03, 0x03, l[0], l[1]]
        }
        // Between the two bounds: refused by default, admitted under the
        // block-cipher ceiling.
        let mid = header(MAX_FRAGMENT + 1);
        assert!(matches!(read_record(&mid), Err(Error::RecordOverflow)));
        assert!(matches!(
            read_record_with_max(&mid, MAX_FRAGMENT),
            Err(Error::RecordOverflow)
        ));
        assert!(
            read_record_with_max(&mid, MAX_FRAGMENT_BLOCK)
                .unwrap()
                .is_none()
        );
        // Exactly at, and one past, the block-cipher ceiling.
        assert!(
            read_record_with_max(&header(MAX_FRAGMENT_BLOCK), MAX_FRAGMENT_BLOCK)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            read_record_with_max(&header(MAX_FRAGMENT_BLOCK + 1), MAX_FRAGMENT_BLOCK),
            Err(Error::RecordOverflow)
        ));
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
