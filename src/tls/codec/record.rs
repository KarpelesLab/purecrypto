//! TLS record-layer framing (the 5-byte header).
//!
//! A record is `ContentType(1) || legacy_version(2) || length(2) || fragment`.
//! This is version-stable: TLS 1.3 wraps all post-handshake records as
//! `application_data` and protects the fragment with AEAD (handled in the
//! record-protection layer); here we only frame the opaque payload.

use super::{put_u8, put_u16};
use crate::tls::{ContentType, Error, ProtocolVersion};
use alloc::vec::Vec;

/// Maximum plaintext fragment length: `2^14` (RFC 5246 §6.2.1 / RFC 8446
/// §5.1). A sender whose message is longer — a certificate chain of several
/// post-quantum certificates easily is — MUST split it across records; the
/// record layer never carries more plaintext than this in one record.
pub(crate) const MAX_PLAINTEXT_FRAGMENT: usize = 1 << 14;

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
///
/// This is also the largest fragment any TLS record may legally carry, so
/// it doubles as the ceiling [`write_record`] enforces on the send side.
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
///
/// Refuses (`Err(RecordOverflow)`, nothing written) a fragment longer than
/// [`MAX_FRAGMENT_BLOCK`], the largest any TLS record may carry: the length
/// field is 16 bits, so a longer fragment used to be framed with a
/// silently truncated length and the peer would have read the tail as the
/// start of the next record. Fragmenting to the plaintext cap is the
/// caller's job (see [`fragments`]); this is the backstop.
pub(crate) fn write_record(
    out: &mut Vec<u8>,
    ct: ContentType,
    version: ProtocolVersion,
    fragment: &[u8],
) -> Result<(), Error> {
    if fragment.len() > MAX_FRAGMENT_BLOCK {
        return Err(Error::RecordOverflow);
    }
    put_u8(out, ct.as_u8());
    put_u16(out, version.as_u16());
    // Fits: `MAX_FRAGMENT_BLOCK` is well below `u16::MAX`.
    put_u16(out, fragment.len() as u16);
    out.extend_from_slice(fragment);
    Ok(())
}

/// Splits `payload` into the fragments the record layer sends it as: each
/// at most `cap` bytes, in order. Unlike `<[u8]>::chunks`, an empty payload
/// yields one empty fragment — an empty `application_data` record is
/// legitimate (RFC 8446 §5.4, traffic-analysis padding) and must still go
/// out. A message longer than `cap` (a certificate chain past 2¹⁴ bytes)
/// spans several records; the receiver reassembles them (RFC 5246 §6.2.1 /
/// RFC 8446 §5.1).
pub(crate) fn fragments(payload: &[u8], cap: usize) -> impl Iterator<Item = &[u8]> {
    let cap = cap.max(1);
    let count = payload.len().div_ceil(cap).max(1);
    (0..count).map(move |i| &payload[i * cap..payload.len().min((i + 1) * cap)])
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
        )
        .unwrap();
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

    /// Finding: `write_record` cast the fragment length to `u16`, so a
    /// fragment past 65535 bytes was framed with a truncated length and the
    /// tail leaked into the record stream as garbage. A fragment past the
    /// largest legal record is refused outright and nothing is written.
    #[test]
    fn write_record_refuses_oversized_fragment() {
        let mut out = Vec::new();
        let too_big = alloc::vec![0u8; MAX_FRAGMENT_BLOCK + 1];
        assert!(matches!(
            write_record(
                &mut out,
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                &too_big
            ),
            Err(Error::RecordOverflow)
        ));
        assert!(
            out.is_empty(),
            "a refused record must not be partially framed"
        );
        // Past the 16-bit length field: the case that used to truncate.
        let huge = alloc::vec![0u8; usize::from(u16::MAX) + 1];
        assert!(matches!(
            write_record(
                &mut out,
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                &huge
            ),
            Err(Error::RecordOverflow)
        ));
        assert!(out.is_empty());
        // Exactly the ceiling still frames.
        let max = alloc::vec![0u8; MAX_FRAGMENT_BLOCK];
        write_record(
            &mut out,
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &max,
        )
        .unwrap();
        assert_eq!(out.len(), 5 + MAX_FRAGMENT_BLOCK);
    }

    /// `fragments` splits at the cap, keeps order, and still yields one
    /// (empty) fragment for an empty payload.
    #[test]
    fn fragments_split_at_cap_and_keep_empty_payloads() {
        let payload: Vec<u8> = (0..10u8).collect();
        let parts: Vec<&[u8]> = fragments(&payload, 4).collect();
        assert_eq!(parts, [&[0, 1, 2, 3][..], &[4, 5, 6, 7][..], &[8, 9][..]]);
        // Exactly one cap's worth is a single record, as is anything shorter.
        assert_eq!(fragments(&payload, 10).count(), 1);
        assert_eq!(fragments(&payload, 100).count(), 1);
        // An empty payload is one empty record, not zero records.
        let empty: Vec<&[u8]> = fragments(&[], 4).collect();
        assert_eq!(empty, [&[][..]]);
        // A degenerate cap of 0 is treated as 1 rather than looping forever.
        assert_eq!(fragments(&payload, 0).count(), 10);
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
