//! DTLS record-layer framing (RFC 6347 §4.1).
//!
//! Unlike the 5-byte TLS record header, a DTLS record carries an explicit
//! epoch and a 48-bit sequence number so that out-of-order, lost, and
//! duplicated datagrams can be handled by the receiver without breaking the
//! AEAD nonce derivation:
//!
//! ```text
//! struct {
//!     ContentType    type;             //  1 byte
//!     ProtocolVersion version;         //  2 bytes (0xfefd for DTLS 1.2)
//!     uint16         epoch;            //  2 bytes
//!     uint48         sequence_number;  //  6 bytes
//!     uint16         length;           //  2 bytes
//!     opaque         fragment[length];
//! } DTLSPlaintext;
//! ```
//!
//! Total header = 13 bytes (vs TLS's 5).
//!
//! This module only frames the opaque payload — record protection (AEAD) is
//! layered on top in the version-specific connection modules.
//!
//! Consumed by the version-specific connection modules (DTLS 1.2 / 1.3
//! client and server).

use crate::tls::{ContentType, Error, ProtocolVersion};
use alloc::vec::Vec;

/// Maximum DTLS record fragment length: `2^14 + 2048` (RFC 6347 §4.1.1.1).
///
/// DTLS allows a slightly larger ciphertext expansion than TLS 1.3
/// (`2^14 + 256`) because some legacy cipher suites add more overhead.
pub(crate) const MAX_FRAGMENT: usize = (1 << 14) + 2048;

/// Fixed DTLS record header length: 13 bytes.
pub(crate) const HEADER_LEN: usize = 13;

/// The mask for a 48-bit sequence number. `write_record` debug-asserts that
/// callers respect this bound.
const SEQ_MASK_48: u64 = (1u64 << 48) - 1;

/// Per-epoch record-sequence cap for the DTLS send path.
///
/// In DTLS the AEAD nonce is derived from `epoch‖seq` (1.2) or `IV XOR seq`
/// (1.3), so a single epoch key must never protect two records under the same
/// sequence number. The wire field is 48 bits, but — exactly as the TLS 1.3
/// record layer does (`src/tls/crypto/aead.rs::MAX_RECORDS_PER_KEY = 1 << 23`)
/// — we refuse to send long before that, well inside every AEAD's safe-record
/// limit. DTLS has no KeyUpdate path here, so hitting the cap is
/// connection-fatal: callers return `Error::TooManyRecords` rather than rely on
/// the debug-only 48-bit assert that silently truncates in release builds.
pub(crate) const MAX_RECORDS_PER_EPOCH: u64 = 1 << 23;

/// Returns `Err(TooManyRecords)` once `seq` reaches [`MAX_RECORDS_PER_EPOCH`].
///
/// Call this on the send path with the sequence number that is *about to be*
/// used for a record, before incrementing the per-epoch counter.
pub(crate) fn check_seq_cap(seq: u64) -> Result<(), Error> {
    if seq >= MAX_RECORDS_PER_EPOCH {
        return Err(Error::TooManyRecords);
    }
    Ok(())
}

/// One parsed DTLS record: content type, protocol version, epoch, sequence
/// number, and the opaque fragment.
pub(crate) struct ParsedDtlsRecord<'a> {
    pub(crate) content_type: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) epoch: u16,
    /// 48-bit on the wire, widened to `u64` for arithmetic.
    pub(crate) seq: u64,
    pub(crate) fragment: &'a [u8],
    /// Total bytes consumed (header + fragment).
    pub(crate) len: usize,
}

/// Attempts to parse one DTLS record from the front of `buf`. Returns
/// `Ok(None)` if more bytes are needed for a complete record.
///
/// The version field is decoded but not validated — each protocol path
/// applies its own version filter at the call site.
pub(crate) fn read_record(buf: &[u8]) -> Result<Option<ParsedDtlsRecord<'_>>, Error> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    let content_type = ContentType::from_u8(buf[0]);
    let version = ProtocolVersion::from_u16(u16::from_be_bytes([buf[1], buf[2]]));
    let epoch = u16::from_be_bytes([buf[3], buf[4]]);
    // 48-bit sequence number, big-endian.
    let seq = ((buf[5] as u64) << 40)
        | ((buf[6] as u64) << 32)
        | ((buf[7] as u64) << 24)
        | ((buf[8] as u64) << 16)
        | ((buf[9] as u64) << 8)
        | (buf[10] as u64);
    let frag_len = u16::from_be_bytes([buf[11], buf[12]]) as usize;
    if frag_len > MAX_FRAGMENT {
        return Err(Error::RecordOverflow);
    }
    let total = HEADER_LEN + frag_len;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(ParsedDtlsRecord {
        content_type,
        version,
        epoch,
        seq,
        fragment: &buf[HEADER_LEN..total],
        len: total,
    }))
}

/// Writes a DTLS record (header + `fragment`) to `out`.
///
/// `seq` must fit in 48 bits. In debug builds this is asserted; release
/// builds silently truncate the top 16 bits.
pub(crate) fn write_record(
    out: &mut Vec<u8>,
    ct: ContentType,
    version: ProtocolVersion,
    epoch: u16,
    seq: u64,
    fragment: &[u8],
) {
    debug_assert!(
        seq <= SEQ_MASK_48,
        "DTLS sequence numbers are 48-bit; caller must rekey before overflow",
    );
    debug_assert!(
        fragment.len() <= MAX_FRAGMENT,
        "DTLS record fragment exceeds RFC 6347 §4.1.1.1 maximum",
    );
    let seq = seq & SEQ_MASK_48;

    out.push(ct.as_u8());
    out.extend_from_slice(&version.as_u16().to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.push((seq >> 40) as u8);
    out.push((seq >> 32) as u8);
    out.push((seq >> 24) as u8);
    out.push((seq >> 16) as u8);
    out.push((seq >> 8) as u8);
    out.push(seq as u8);
    out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
    out.extend_from_slice(fragment);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn record_roundtrip_known_header() {
        let mut out = Vec::new();
        write_record(
            &mut out,
            ContentType::Handshake,
            ProtocolVersion::DTLSv1_2,
            0,
            42,
            b"hi",
        );
        // 13-byte header + 2-byte fragment.
        assert_eq!(out.len(), HEADER_LEN + 2);
        // Expected header bytes:
        //   type=22, version=0xfefd, epoch=0x0000,
        //   seq=0x000000000002A, length=0x0002, fragment=b"hi"
        let expected: Vec<u8> = vec![
            22, // handshake
            0xfe, 0xfd, // DTLS 1.2
            0x00, 0x00, // epoch
            0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, // seq=42
            0x00, 0x02, // length
            b'h', b'i',
        ];
        assert_eq!(out, expected);

        let rec = read_record(&out).unwrap().unwrap();
        assert_eq!(rec.content_type, ContentType::Handshake);
        assert_eq!(rec.version, ProtocolVersion::DTLSv1_2);
        assert_eq!(rec.epoch, 0);
        assert_eq!(rec.seq, 42);
        assert_eq!(rec.fragment, b"hi");
        assert_eq!(rec.len, HEADER_LEN + 2);
    }

    #[test]
    fn record_roundtrip_full_48bit_seq() {
        // Largest legal 48-bit value.
        let max_seq = (1u64 << 48) - 1;
        let mut out = Vec::new();
        write_record(
            &mut out,
            ContentType::ApplicationData,
            ProtocolVersion::DTLSv1_2,
            7,
            max_seq,
            b"x",
        );
        let rec = read_record(&out).unwrap().unwrap();
        assert_eq!(rec.content_type, ContentType::ApplicationData);
        assert_eq!(rec.epoch, 7);
        assert_eq!(rec.seq, max_seq);
        assert_eq!(rec.fragment, b"x");
    }

    #[test]
    fn partial_buffer_returns_none() {
        // Build a record then truncate at every length below `header + frag`.
        let mut out = Vec::new();
        write_record(
            &mut out,
            ContentType::Handshake,
            ProtocolVersion::DTLSv1_2,
            0,
            1,
            b"hello",
        );
        for cut in 0..out.len() {
            assert!(
                read_record(&out[..cut]).unwrap().is_none(),
                "expected None at cut={cut}",
            );
        }
        // Exactly enough bytes: parse succeeds.
        assert!(read_record(&out).unwrap().is_some());
    }

    #[test]
    fn fragment_length_overflow_rejected() {
        // Hand-craft a header that claims a length of MAX_FRAGMENT + 1.
        let mut hdr = vec![
            22, // handshake
            0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let bad = (MAX_FRAGMENT as u32 + 1) as u16; // wraps below 2^16
        // Sanity: ensure the test value is actually decodable as a u16 length
        // and *exceeds* MAX_FRAGMENT.
        assert!(bad as usize > MAX_FRAGMENT);
        hdr.extend_from_slice(&bad.to_be_bytes());
        match read_record(&hdr) {
            Err(Error::RecordOverflow) => {}
            other => panic!("expected RecordOverflow, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn seq_cap_is_below_48_bits_and_enforced() {
        // The cap must sit well below the 48-bit wire field so we can never
        // reuse an AEAD nonce by overflowing the sequence number.
        const { assert!(MAX_RECORDS_PER_EPOCH < (1u64 << 48)) };

        // Below the cap: accepted.
        assert!(check_seq_cap(0).is_ok());
        assert!(check_seq_cap(MAX_RECORDS_PER_EPOCH - 1).is_ok());

        // At and above the cap: refused with the fatal record-cap error,
        // mirroring the TLS record layer's `TooManyRecords`.
        assert!(matches!(
            check_seq_cap(MAX_RECORDS_PER_EPOCH),
            Err(Error::TooManyRecords)
        ));
        assert!(matches!(
            check_seq_cap(MAX_RECORDS_PER_EPOCH + 1),
            Err(Error::TooManyRecords)
        ));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "DTLS sequence numbers are 48-bit")]
    fn write_record_panics_on_oversized_seq() {
        let mut out = Vec::new();
        // 1 << 48 is the first illegal value.
        write_record(
            &mut out,
            ContentType::Handshake,
            ProtocolVersion::DTLSv1_2,
            0,
            1u64 << 48,
            b"",
        );
    }
}
