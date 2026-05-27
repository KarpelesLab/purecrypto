//! RFC 9000 §16 — variable-length integer codec.
//!
//! QUIC carries most numeric fields as variable-length integers whose first
//! two bits select one of four size classes:
//!
//! ```text
//!   2-bit tag  | encoded length | value range
//!   -----------+----------------+----------------------------
//!   0b00       |  1 byte        |  0          .. 63          (2^6 − 1)
//!   0b01       |  2 bytes       |  0          .. 16383       (2^14 − 1)
//!   0b10       |  4 bytes       |  0          .. 1073741823  (2^30 − 1)
//!   0b11       |  8 bytes       |  0          .. 2^62 − 1
//! ```
//!
//! The tag bits live in the *top* two bits of the first byte; the remaining
//! bits of byte 0 plus all subsequent bytes are the big-endian value. Decoders
//! must mask out the tag bits before combining, and per §16 a decoder MUST
//! accept any of the four legal lengths for a given value — i.e. `0x40 0x00`
//! is a legal (non-minimal) encoding of `0`. Encoders, however, always emit
//! the *shortest* legal form.

use alloc::vec::Vec;

use crate::tls::Error;

/// Largest representable value: `2^62 − 1`.
pub(crate) const MAX: u64 = (1u64 << 62) - 1;

/// How many bytes [`encode`] will write for `value`.
pub(crate) const fn encoded_len(value: u64) -> usize {
    if value < 1 << 6 {
        1
    } else if value < 1 << 14 {
        2
    } else if value < 1 << 30 {
        4
    } else {
        8
    }
}

/// Encodes `value` using the shortest legal varint form.
///
/// # Panics
/// Panics if `value > 2^62 − 1` — the QUIC varint cannot represent such a
/// number and any caller producing one is buggy.
pub(crate) fn encode(value: u64, out: &mut Vec<u8>) {
    assert!(value <= MAX, "QUIC varint value out of range: {value:#x}");
    if value < 1 << 6 {
        out.push(value as u8);
    } else if value < 1 << 14 {
        let v = value as u16;
        let bytes = v.to_be_bytes();
        out.push(bytes[0] | 0x40);
        out.push(bytes[1]);
    } else if value < 1 << 30 {
        let v = value as u32;
        let bytes = v.to_be_bytes();
        out.push(bytes[0] | 0x80);
        out.push(bytes[1]);
        out.push(bytes[2]);
        out.push(bytes[3]);
    } else {
        let bytes = value.to_be_bytes();
        out.push(bytes[0] | 0xC0);
        out.extend_from_slice(&bytes[1..]);
    }
}

/// Decodes a varint from the front of `buf`.
///
/// Returns `(value, bytes_consumed)`. The decoder accepts any legal length —
/// non-minimal encodings are valid per RFC 9000 §16. Yields
/// [`Error::Decode`] on a buffer too short for the size class indicated by
/// the leading tag bits, or for an empty buffer.
pub(crate) fn decode(buf: &[u8]) -> Result<(u64, usize), Error> {
    if buf.is_empty() {
        return Err(Error::Decode);
    }
    let tag = buf[0] >> 6;
    let len = 1usize << tag;
    if buf.len() < len {
        return Err(Error::Decode);
    }
    let mut value = (buf[0] & 0x3F) as u64;
    for &b in &buf[1..len] {
        value = (value << 8) | b as u64;
    }
    Ok((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUNDARIES: &[(u64, usize)] = &[
        (0, 1),
        (63, 1),
        (64, 2),
        (16383, 2),
        (16384, 4),
        (1073741823, 4),
        (1073741824, 8),
        ((1u64 << 62) - 1, 8),
    ];

    #[test]
    fn roundtrip_boundaries() {
        for &(v, expected_len) in BOUNDARIES {
            let mut buf = Vec::new();
            encode(v, &mut buf);
            assert_eq!(buf.len(), expected_len, "len({v}) wrong");
            let (decoded, used) = decode(&buf).expect("decode");
            assert_eq!(decoded, v);
            assert_eq!(used, expected_len);
        }
    }

    #[test]
    fn accepts_oversized_legal_encodings() {
        // RFC 9000 §16: decoders MUST accept any of the four legal length
        // encodings of a value. 0x40 0x00 is a 2-byte form of 0.
        let (v, used) = decode(&[0x40, 0x00]).expect("decode");
        assert_eq!(v, 0);
        assert_eq!(used, 2);

        // 4-byte form of 0:
        let (v, used) = decode(&[0x80, 0x00, 0x00, 0x00]).expect("decode");
        assert_eq!(v, 0);
        assert_eq!(used, 4);

        // 8-byte form of 0:
        let (v, used) = decode(&[0xC0, 0, 0, 0, 0, 0, 0, 0]).expect("decode");
        assert_eq!(v, 0);
        assert_eq!(used, 8);
    }

    #[test]
    fn rejects_truncated_buffer() {
        // Empty.
        assert!(matches!(decode(&[]), Err(Error::Decode)));
        // 2-byte tag but only one byte present.
        assert!(matches!(decode(&[0x40]), Err(Error::Decode)));
        // 4-byte tag but only three bytes present.
        assert!(matches!(decode(&[0x80, 0x00, 0x00]), Err(Error::Decode)));
        // 8-byte tag but only seven bytes present.
        assert!(matches!(
            decode(&[0xC0, 0, 0, 0, 0, 0, 0]),
            Err(Error::Decode)
        ));
    }

    #[test]
    #[should_panic]
    fn panics_on_oversize() {
        let mut buf = Vec::new();
        encode(1u64 << 62, &mut buf);
    }

    #[test]
    fn encoded_len_matches_actual() {
        for &(v, _) in BOUNDARIES {
            let mut buf = Vec::new();
            encode(v, &mut buf);
            assert_eq!(encoded_len(v), buf.len(), "encoded_len({v}) mismatch");
        }
    }
}
