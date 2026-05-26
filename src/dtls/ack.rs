//! DTLS 1.3 ACK record body (RFC 9147 §7).
//!
//! DTLS 1.3 replaces the blanket "retransmit the whole previous flight on
//! timeout" rule of DTLS 1.2 with **selective acknowledgements**. After
//! receiving one or more protected records that contributed to the current
//! flight, a peer MAY send an `ACK` record listing the (epoch,
//! sequence_number) pairs that successfully decrypted and verified. The
//! sender of those records then knows it does not need to retransmit them.
//!
//! Wire format (RFC 9147 §7.1):
//!
//! ```text
//! struct {
//!     RecordNumber record_numbers<0..2^16-1>;
//! } ACK;
//!
//! struct {
//!     uint64 epoch;
//!     uint64 sequence_number;
//! } RecordNumber;
//! ```
//!
//! The `<0..2^16-1>` vector prefix is the length of the vector contents in
//! bytes (TLS-presentation-language convention), so the on-wire layout is:
//!
//! ```text
//! +----+----+ +--------------------------------+
//! | u16 len| | RecordNumber (16 bytes) × N    |
//! +----+----+ +--------------------------------+
//! ```
//!
//! `len` must be a multiple of 16; the parser rejects anything else with
//! [`Error::Decode`].
//!
//! The ACK content type is `26` (RFC 9147 §7) — exported as
//! [`ACK_CONTENT_TYPE`] so the record layer can dispatch on it without
//! re-magic-numbering this constant.
//!
//! This codec is consumed by [`super::reliability13`]; the client / server
//! state machines that emit and consume ACKs land in commit 14, so the
//! items are `#[allow(dead_code)]` for now.

#![allow(dead_code)]

use crate::tls::Error;
use alloc::vec::Vec;

/// DTLS 1.3 content type for an ACK record (RFC 9147 §7).
pub(crate) const ACK_CONTENT_TYPE: u8 = 26;

/// One entry in an ACK's `record_numbers` vector. Identifies a single
/// protected DTLS record by its (epoch, sequence_number) pair.
///
/// The `epoch` is a 64-bit field on the wire even though epochs in practice
/// fit in a `u16`; the spec future-proofs it to match the sequence-number
/// field's width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordNumber {
    /// Epoch the acknowledged record belonged to.
    pub(crate) epoch: u64,
    /// Per-epoch sequence number of the acknowledged record.
    pub(crate) seq: u64,
}

/// Size of one `RecordNumber` on the wire: two `uint64`s.
const RECORD_NUMBER_LEN: usize = 16;

/// Encodes an ACK body: a `u16` vector-byte-length prefix followed by zero
/// or more 16-byte `RecordNumber` entries, each `(epoch: u64, seq: u64)` in
/// network byte order.
///
/// Returns a freshly allocated `Vec<u8>` so the caller can hand it directly
/// to the record layer.
pub(crate) fn encode(records: &[RecordNumber]) -> Vec<u8> {
    // `records.len() * 16` cannot overflow a usize on any platform we
    // support, but the wire format only has 16 bits to express the vector
    // length. ACK bodies in practice carry a handful of entries per flight;
    // capping at u16::MAX / 16 ≈ 4095 entries is well past anything sane.
    let len_bytes = records.len() * RECORD_NUMBER_LEN;
    debug_assert!(
        len_bytes <= u16::MAX as usize,
        "ACK record_numbers vector exceeds u16::MAX bytes"
    );
    let mut out = Vec::with_capacity(2 + len_bytes);
    out.extend_from_slice(&(len_bytes as u16).to_be_bytes());
    for rn in records {
        out.extend_from_slice(&rn.epoch.to_be_bytes());
        out.extend_from_slice(&rn.seq.to_be_bytes());
    }
    out
}

/// Parses an ACK body. Validates that:
///
/// - the body is at least two bytes (the length prefix),
/// - the declared vector length does not exceed the body remainder,
/// - the declared vector length is a whole number of `RecordNumber`s
///   (a multiple of 16).
///
/// Any failure returns [`Error::Decode`], which the DTLS record layer
/// turns into a `decode_error` alert.
///
/// Trailing bytes after the declared vector are also rejected — the wire
/// format permits no padding.
pub(crate) fn decode(body: &[u8]) -> Result<Vec<RecordNumber>, Error> {
    if body.len() < 2 {
        return Err(Error::Decode);
    }
    let len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let rest = &body[2..];
    if rest.len() != len {
        // Trailing garbage or truncation — both are protocol errors.
        return Err(Error::Decode);
    }
    if !len.is_multiple_of(RECORD_NUMBER_LEN) {
        return Err(Error::Decode);
    }
    let count = len / RECORD_NUMBER_LEN;
    let mut out = Vec::with_capacity(count);
    let mut off = 0;
    for _ in 0..count {
        let epoch = u64::from_be_bytes(rest[off..off + 8].try_into().unwrap());
        let seq = u64::from_be_bytes(rest[off + 8..off + 16].try_into().unwrap());
        out.push(RecordNumber { epoch, seq });
        off += RECORD_NUMBER_LEN;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn empty_ack_roundtrip() {
        let encoded = encode(&[]);
        // Just the 2-byte length prefix of value 0.
        assert_eq!(encoded, vec![0x00, 0x00]);
        let decoded = decode(&encoded).expect("empty ack decodes");
        assert!(decoded.is_empty());
    }

    #[test]
    fn single_record_roundtrip() {
        let input = [RecordNumber { epoch: 3, seq: 100 }];
        let encoded = encode(&input);
        // 2 (length) + 16 (one record).
        assert_eq!(encoded.len(), 18);
        // Length prefix = 16.
        assert_eq!(&encoded[..2], &[0x00, 0x10]);
        let decoded = decode(&encoded).expect("single ack decodes");
        assert_eq!(decoded.as_slice(), &input);
    }

    #[test]
    fn multi_record_roundtrip() {
        let input = [
            RecordNumber { epoch: 0, seq: 0 },
            RecordNumber { epoch: 1, seq: 1 },
            RecordNumber {
                epoch: 2,
                seq: 0xDEAD_BEEF,
            },
            RecordNumber {
                epoch: 0xFFFF,
                seq: 0x0123_4567_89AB_CDEF,
            },
            RecordNumber {
                epoch: 42,
                seq: 999_999_999,
            },
        ];
        let encoded = encode(&input);
        assert_eq!(encoded.len(), 2 + 5 * 16);
        let decoded = decode(&encoded).expect("multi ack decodes");
        assert_eq!(decoded.as_slice(), &input);
    }

    #[test]
    fn truncated_body_rejected() {
        // Length prefix claims 32 bytes but only 16 follow.
        let mut bad = vec![0x00, 0x20];
        bad.extend_from_slice(&[0u8; 16]);
        assert_eq!(decode(&bad), Err(Error::Decode));
    }

    #[test]
    fn shorter_than_length_prefix_rejected() {
        // One byte is not enough for the length prefix.
        assert_eq!(decode(&[0x00]), Err(Error::Decode));
        // Zero bytes ditto.
        assert_eq!(decode(&[]), Err(Error::Decode));
    }

    #[test]
    fn non_multiple_of_16_rejected() {
        // Length prefix = 15 (smaller than one RecordNumber) and 15 bytes
        // follow — well-formed except that 15 % 16 != 0.
        let mut bad = vec![0x00, 0x0F];
        bad.extend_from_slice(&[0u8; 15]);
        assert_eq!(decode(&bad), Err(Error::Decode));

        // Length prefix = 17 (one full RecordNumber plus a stray byte).
        let mut bad = vec![0x00, 0x11];
        bad.extend_from_slice(&[0u8; 17]);
        assert_eq!(decode(&bad), Err(Error::Decode));
    }

    #[test]
    fn trailing_bytes_after_vector_rejected() {
        // 18 bytes after a length prefix of 16 — the extra two bytes are
        // not allowed by the RFC's strict vector framing.
        let mut bad = vec![0x00, 0x10];
        bad.extend_from_slice(&[0u8; 18]);
        assert_eq!(decode(&bad), Err(Error::Decode));
    }

    #[test]
    fn ack_content_type_value() {
        // Sanity check on the IANA-assigned content-type code.
        assert_eq!(ACK_CONTENT_TYPE, 26);
    }
}
