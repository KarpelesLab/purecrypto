//! DTLS 1.3 record framing (RFC 9147 §4).
//!
//! DTLS 1.3 replaces the legacy 13-byte header used for protected records
//! with a compact "unified header" whose layout is dictated by a flag byte
//! and whose sequence number is encrypted using a per-direction `sn_key`.
//!
//! ```text
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+
//! |0|0|1|C|S|L|E E|   <- first byte
//! +-+-+-+-+-+-+-+-+
//!
//! struct {
//!     uint8  unified_hdr_first_byte;
//!     opaque connection_id[len];                       // iff C = 1
//!     uint8 | uint16 sequence_number_lo;               // S picks 8/16-bit
//!     uint16 length;                                   // iff L = 1
//!     opaque encrypted_record[length];                 // ciphertext + tag
//! } DTLSCiphertext;
//! ```
//!
//! On the wire the sequence-number bytes are XORed with a 1- or 2-byte mask
//! derived from the AEAD-tied `sn_key` and the first 16 bytes of the
//! encrypted record body (RFC 9147 §4.2.3). The receiver reverses the XOR
//! before reconstructing the full 48-bit sequence number against its
//! expected next sequence per RFC 9147 §4.2.2.
//!
//! Plaintext records (e.g. an initial ClientHello on a fresh connection,
//! before keys are derived) still use the legacy DTLS 1.2 13-byte header
//! from [`super::record`].
//!
//! This commit lands the framing only; the DTLS 1.3 state machine and ACK
//! reliability layer build on top in subsequent commits.

#![allow(dead_code)]

use crate::cipher::{Aes128, Aes256, BlockCipher};
use crate::tls::Error;
use alloc::vec::Vec;

/// Fixed top 3 bits of every DTLS 1.3 protected record's first byte: `001`.
const UNIFIED_HDR_PREFIX: u8 = 0b0010_0000;
/// Mask covering the prefix bits we match against [`UNIFIED_HDR_PREFIX`].
const UNIFIED_HDR_PREFIX_MASK: u8 = 0b1110_0000;
/// Connection-ID-present flag.
const FLAG_CID: u8 = 0b0001_0000;
/// Sequence-number-is-16-bit flag (else 8-bit).
const FLAG_SEQ_16: u8 = 0b0000_1000;
/// Length-field-present flag (else implicit: last record in datagram).
const FLAG_LENGTH: u8 = 0b0000_0100;
/// Mask for the epoch's low 2 bits in the first byte.
const FLAG_EPOCH_LO2: u8 = 0b0000_0011;

/// Mask covering the 48 valid bits of a DTLS sequence number.
const SEQ_MASK_48: u64 = (1u64 << 48) - 1;

/// Parsed DTLS 1.3 unified record header.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UnifiedHeader {
    /// True for the encrypted DTLS-1.3 record; false (or absent path)
    /// for plaintext records that still use the legacy 13-byte header.
    pub(crate) is_ciphertext: bool,
    /// Epoch lower 2 bits as encoded in the first byte.
    pub(crate) epoch_low2: u8,
    /// Wire sequence number (after the mask was reversed) — 8 or 16 bits.
    /// Always widened to `u16`; for the 8-bit form only the low byte is
    /// meaningful.
    pub(crate) seq_low: u16,
    /// True if the on-wire seq was 16-bit, false if 8-bit. Callers
    /// reconstruct the full 48-bit seq from `epoch` + this low half plus
    /// their own monotonic counter (see [`reconstruct_seq`]).
    pub(crate) seq_is_16bit: bool,
    /// True if the record carried an explicit length; false means it
    /// occupies the rest of the datagram.
    pub(crate) has_length: bool,
    /// True if a Connection ID field was present. We don't support CID
    /// yet — set false in `encode_record`, returning [`Error::IllegalParameter`]
    /// in `decode_record` if encountered.
    pub(crate) has_cid: bool,
    /// Total bytes consumed by the header (1 + maybe 1/2 seq + maybe 2 len).
    pub(crate) header_len: usize,
}

/// Reconstructs the full 48-bit sequence number from a wire low-half and
/// the receiver's `expected_seq` (typically the next-expected seq value,
/// i.e. `last_received + 1`).
///
/// RFC 9147 §4.2.2: pick the candidate full sequence number whose low
/// bits match the wire value AND that is numerically closest to
/// `expected_seq`. We implement that by considering the three candidates
/// `expected_high - delta`, `expected_high`, and `expected_high + delta`
/// (where `delta` is the modulus, 2^8 or 2^16) and returning the one
/// with the smallest absolute distance.
pub(crate) fn reconstruct_seq(seq_low: u16, seq_is_16bit: bool, expected_seq: u64) -> u64 {
    let (modulus_bits, mask) = if seq_is_16bit {
        (16u32, 0xFFFFu64)
    } else {
        (8u32, 0xFFu64)
    };
    let modulus = 1u64 << modulus_bits;
    let low = (seq_low as u64) & mask;

    // The base candidate replaces `expected_seq`'s low bits with `low`.
    let expected_high = expected_seq & !mask;
    let base = expected_high | low;

    // Three candidates: one modulus below, the base, and one modulus above.
    // We saturate at the 48-bit boundary to avoid producing illegal seqs.
    let candidates = [
        base.checked_sub(modulus),
        Some(base),
        base.checked_add(modulus),
    ];

    let mut best = base;
    let mut best_dist = abs_diff(base, expected_seq);
    for c in candidates.iter().flatten() {
        if *c > SEQ_MASK_48 {
            continue;
        }
        let d = abs_diff(*c, expected_seq);
        if d < best_dist {
            best = *c;
            best_dist = d;
        }
    }
    best
}

#[inline]
fn abs_diff(a: u64, b: u64) -> u64 {
    a.abs_diff(b)
}

/// Encodes one DTLS 1.3 ciphertext record into `out`.
///
/// `sn_mask` is the 2-byte mask (or 1 byte if `seq_is_16bit` is false)
/// derived from `sn_key` and the first 16 bytes of `encrypted_payload`.
/// The mask is XORed into the on-wire sequence number bytes; the
/// `encrypted_payload` itself is written unchanged.
///
/// `omit_length` must only be true when this record is the LAST one in
/// its UDP datagram, per RFC 9147 §4.2.
///
/// Connection IDs are not supported in this commit; the `C` bit is always
/// cleared on output.
pub(crate) fn encode_record(
    out: &mut Vec<u8>,
    epoch: u16,
    seq: u64,
    seq_is_16bit: bool,
    omit_length: bool,
    encrypted_payload: &[u8],
    sn_mask: &[u8],
) {
    debug_assert!(seq <= SEQ_MASK_48, "DTLS seq must fit in 48 bits");
    let expected_mask_len = if seq_is_16bit { 2 } else { 1 };
    debug_assert_eq!(
        sn_mask.len(),
        expected_mask_len,
        "sn_mask length must match seq_is_16bit",
    );

    let mut first = UNIFIED_HDR_PREFIX;
    if seq_is_16bit {
        first |= FLAG_SEQ_16;
    }
    if !omit_length {
        first |= FLAG_LENGTH;
    }
    first |= (epoch as u8) & FLAG_EPOCH_LO2;
    out.push(first);

    // Connection ID: not yet supported — `C` bit stays clear, no bytes emitted.

    if seq_is_16bit {
        let seq_bytes = (seq as u16).to_be_bytes();
        out.push(seq_bytes[0] ^ sn_mask[0]);
        out.push(seq_bytes[1] ^ sn_mask[1]);
    } else {
        out.push((seq as u8) ^ sn_mask[0]);
    }

    if !omit_length {
        out.extend_from_slice(&(encrypted_payload.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(encrypted_payload);
}

/// Parses one DTLS 1.3 ciphertext record from the start of `buf`.
///
/// Returns the unified header plus a slice referencing the still-encrypted
/// record body. The caller is expected to:
///
/// 1. Identify the body slice (using `header.header_len` and either
///    `header.has_length` or the remaining datagram size),
/// 2. Compute `sn_mask` from `sn_key` and the first 16 bytes of that body,
/// 3. Pass that mask back in here so the sequence number can be unmasked.
///
/// Because of step 2, the caller has to know where the body begins before
/// it can compute the mask, but the header length depends only on the
/// flag byte — not on the sequence number. So [`decode_record`] is in
/// practice called twice on the wire: once with a zero mask just to
/// locate the body, and once with the real mask to unmask the seq. The
/// helper [`peek_header_layout`] performs the cheaper first pass.
///
/// The returned ciphertext slice covers `encrypted_payload` exactly: tag
/// included, header bytes excluded. When the L bit was absent the slice
/// runs to the end of `buf`.
pub(crate) fn decode_record<'a>(
    buf: &'a [u8],
    sn_mask: &[u8],
) -> Result<(UnifiedHeader, &'a [u8]), Error> {
    if buf.is_empty() {
        return Err(Error::Decode);
    }
    let first = buf[0];
    if (first & UNIFIED_HDR_PREFIX_MASK) != UNIFIED_HDR_PREFIX {
        return Err(Error::Decode);
    }
    let has_cid = (first & FLAG_CID) != 0;
    if has_cid {
        // RFC 9146 connection IDs are out of scope for this commit.
        return Err(Error::IllegalParameter);
    }
    let seq_is_16bit = (first & FLAG_SEQ_16) != 0;
    let has_length = (first & FLAG_LENGTH) != 0;
    let epoch_low2 = first & FLAG_EPOCH_LO2;

    let seq_bytes = if seq_is_16bit { 2usize } else { 1usize };
    if sn_mask.len() != seq_bytes {
        return Err(Error::Decode);
    }
    let len_bytes = if has_length { 2usize } else { 0usize };
    let header_len = 1 + seq_bytes + len_bytes;
    if buf.len() < header_len {
        return Err(Error::Decode);
    }

    let seq_low = if seq_is_16bit {
        let hi = buf[1] ^ sn_mask[0];
        let lo = buf[2] ^ sn_mask[1];
        ((hi as u16) << 8) | (lo as u16)
    } else {
        (buf[1] ^ sn_mask[0]) as u16
    };

    let body_start = header_len;
    let body_end = if has_length {
        let off = 1 + seq_bytes;
        let len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        let end = body_start + len;
        if end > buf.len() {
            return Err(Error::Decode);
        }
        end
    } else {
        buf.len()
    };

    Ok((
        UnifiedHeader {
            is_ciphertext: true,
            epoch_low2,
            seq_low,
            seq_is_16bit,
            has_length,
            has_cid,
            header_len,
        },
        &buf[body_start..body_end],
    ))
}

/// Peeks at the layout of the unified header without unmasking the seq.
///
/// Returns `(header_len, body_len)` where `body_len` is the explicit
/// length when L=1 or `buf.len() - header_len` when L=0. Used by callers
/// that need to locate the ciphertext to compute the sn_mask before they
/// can finish decoding.
pub(crate) fn peek_header_layout(buf: &[u8]) -> Result<(usize, usize), Error> {
    if buf.is_empty() {
        return Err(Error::Decode);
    }
    let first = buf[0];
    if (first & UNIFIED_HDR_PREFIX_MASK) != UNIFIED_HDR_PREFIX {
        return Err(Error::Decode);
    }
    if (first & FLAG_CID) != 0 {
        return Err(Error::IllegalParameter);
    }
    let seq_is_16bit = (first & FLAG_SEQ_16) != 0;
    let has_length = (first & FLAG_LENGTH) != 0;
    let seq_bytes = if seq_is_16bit { 2 } else { 1 };
    let len_bytes = if has_length { 2 } else { 0 };
    let header_len = 1 + seq_bytes + len_bytes;
    if buf.len() < header_len {
        return Err(Error::Decode);
    }
    let body_len = if has_length {
        let off = 1 + seq_bytes;
        let len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        if header_len + len > buf.len() {
            return Err(Error::Decode);
        }
        len
    } else {
        buf.len() - header_len
    };
    Ok((header_len, body_len))
}

/// Computes the DTLS 1.3 sequence-number mask under an AES-128 `sn_key`.
///
/// Per RFC 9147 §4.2.3, the mask is the first 2 bytes of
/// `AES-ECB-Encrypt(sn_key, ciphertext[..16])`. `ciphertext` must be at
/// least 16 bytes long — the AEAD tag alone is 16 bytes, so a real
/// ciphertext always satisfies that bound. Shorter inputs are zero-padded
/// in this helper to keep the API total.
pub(crate) fn sn_mask_aes128(sn_key: &[u8; 16], ciphertext: &[u8]) -> [u8; 2] {
    let cipher = Aes128::new(sn_key);
    sn_mask_block(&cipher, ciphertext)
}

/// Like [`sn_mask_aes128`] but using an AES-256 sn_key (32 bytes).
pub(crate) fn sn_mask_aes256(sn_key: &[u8; 32], ciphertext: &[u8]) -> [u8; 2] {
    let cipher = Aes256::new(sn_key);
    sn_mask_block(&cipher, ciphertext)
}

#[inline]
fn sn_mask_block<C: BlockCipher>(cipher: &C, ciphertext: &[u8]) -> [u8; 2] {
    let mut block = [0u8; 16];
    let take = ciphertext.len().min(16);
    block[..take].copy_from_slice(&ciphertext[..take]);
    cipher.encrypt_block(&mut block);
    [block[0], block[1]]
}

// TODO: ChaCha20-derived sn_mask for the ChaCha20-Poly1305 cipher suite
//       (RFC 9147 §4.2.3). The DTLS subset shipped today doesn't yet
//       advertise the ChaCha suite, so this is intentionally omitted —
//       the masking call sites in `encode_record` / `decode_record` are
//       cipher-agnostic and a `sn_mask_chacha20(...)` helper can be
//       added without touching the framing code.

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Dummy ciphertext used to exercise the codec — value-independent,
    /// 32 bytes so it's longer than one AES block.
    fn dummy_ct() -> Vec<u8> {
        (0u8..32).collect()
    }

    #[test]
    fn header_roundtrip_16bit_seq_with_length() {
        let mut out = Vec::new();
        let mask = [0u8; 2];
        let ct = dummy_ct();
        encode_record(&mut out, 1, 42, true, false, &ct, &mask);

        // first byte: 001_C=0_S=1_L=1_EE=01 = 0b0010_1101 = 0x2D
        assert_eq!(out[0], 0b0010_1101);
        // 2-byte seq (XORed with all-zero mask) = 0x00 0x2A
        assert_eq!(&out[1..3], &[0x00, 0x2A]);
        // length = 32
        assert_eq!(&out[3..5], &[0x00, 0x20]);
        assert_eq!(&out[5..], ct.as_slice());

        let (hdr, body) = decode_record(&out, &mask).unwrap();
        assert!(hdr.is_ciphertext);
        assert_eq!(hdr.epoch_low2, 0b01);
        assert!(hdr.seq_is_16bit);
        assert_eq!(hdr.seq_low, 42);
        assert!(hdr.has_length);
        assert!(!hdr.has_cid);
        assert_eq!(hdr.header_len, 1 + 2 + 2);
        assert_eq!(body, ct.as_slice());
    }

    #[test]
    fn header_roundtrip_8bit_seq() {
        let mut out = Vec::new();
        let mask = [0u8; 1];
        let ct = dummy_ct();
        encode_record(&mut out, 2, 0x0055, false, false, &ct, &mask);

        // first byte: 001_0_0_1_10 — S=0, L=1, EE=10 — = 0b0010_0110 = 0x26
        assert_eq!(out[0], 0b0010_0110);
        assert_eq!(out[1], 0x55);
        assert_eq!(&out[2..4], &[0x00, 0x20]);
        assert_eq!(&out[4..], ct.as_slice());

        let (hdr, body) = decode_record(&out, &mask).unwrap();
        assert_eq!(hdr.epoch_low2, 0b10);
        assert!(!hdr.seq_is_16bit);
        assert_eq!(hdr.seq_low, 0x55);
        assert!(hdr.has_length);
        assert_eq!(hdr.header_len, 1 + 1 + 2);
        assert_eq!(body, ct.as_slice());
    }

    #[test]
    fn header_roundtrip_length_omitted() {
        // L=0: the body runs to the end of the datagram.
        let mut out = Vec::new();
        let mask = [0u8; 2];
        let ct = dummy_ct();
        encode_record(&mut out, 0, 7, true, true, &ct, &mask);

        // first byte: 001 0_0_0_00 with S=1 -> 0b0010_1000 = 0x28
        assert_eq!(out[0], 0b0010_1000);
        // seq (2 bytes), then ciphertext directly — no length prefix.
        assert_eq!(&out[1..3], &[0x00, 0x07]);
        assert_eq!(&out[3..], ct.as_slice());
        assert_eq!(out.len(), 1 + 2 + ct.len());

        let (hdr, body) = decode_record(&out, &mask).unwrap();
        assert!(!hdr.has_length);
        assert!(hdr.seq_is_16bit);
        assert_eq!(hdr.seq_low, 7);
        assert_eq!(hdr.header_len, 1 + 2);
        assert_eq!(body, ct.as_slice());
    }

    #[test]
    fn cid_bit_rejected() {
        // C bit set; rest doesn't matter.
        let bad = vec![0b0011_0101u8, 0, 0, 0, 0];
        match decode_record(&bad, &[0u8; 2]) {
            Err(Error::IllegalParameter) => {}
            other => panic!("expected IllegalParameter, got {other:?}"),
        }
        // peek_header_layout enforces the same rule.
        match peek_header_layout(&bad) {
            Err(Error::IllegalParameter) => {}
            other => panic!("expected IllegalParameter, got {other:?}"),
        }
    }

    #[test]
    fn non_dtls13_prefix_rejected() {
        // First three bits != 001.
        let bad = vec![0b1010_0101u8, 0, 0, 0, 0];
        match decode_record(&bad, &[0u8; 2]) {
            Err(Error::Decode) => {}
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[test]
    fn truncated_buffer_rejected() {
        // L=1 with body length 32 but the buffer ends after the header.
        let mut out = Vec::new();
        let mask = [0u8; 2];
        let ct = dummy_ct();
        encode_record(&mut out, 0, 1, true, false, &ct, &mask);
        // Drop the last byte of the ciphertext.
        out.pop();
        match decode_record(&out, &mask) {
            Err(Error::Decode) => {}
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[test]
    fn reconstruct_seq_simple() {
        // expected_seq = 300, low = 0x0145 (16-bit) — same window, returns
        // 0x0145 directly.
        let got = reconstruct_seq(0x0145, true, 300);
        assert_eq!(got, 0x0145);
    }

    #[test]
    fn reconstruct_seq_wraparound() {
        // expected_seq = 0x10000, low = 0xFFFF (16-bit). Candidates:
        //   0x0FFFF (delta 1) vs 0x1FFFF (delta 0xFFFF). 0x0FFFF wins.
        let got = reconstruct_seq(0xFFFF, true, 0x10000);
        assert_eq!(got, 0x0FFFF);
    }

    #[test]
    fn reconstruct_seq_forward_wrap() {
        // expected_seq just below a 16-bit boundary: 0xFFFE. low = 0x0001.
        // Candidates: 0x10001 (delta 3) vs 0x00001 (delta 0xFFFD).
        // 0x10001 is closer.
        let got = reconstruct_seq(0x0001, true, 0xFFFE);
        assert_eq!(got, 0x10001);
    }

    #[test]
    fn reconstruct_seq_8bit() {
        // 8-bit form. expected_seq = 0x200, low = 0x05.
        // Candidates: 0x105 (delta 0xFB), 0x205 (delta 5), 0x305 (delta 0x105).
        // 0x205 wins.
        let got = reconstruct_seq(0x05, false, 0x200);
        assert_eq!(got, 0x205);
    }

    #[test]
    fn sn_mask_aes128_known_vector() {
        // Mask = first 2 bytes of AES-ECB-Encrypt(zero key, zero block).
        // FIPS-197 reference: AES-128(0..0, 0..0) =
        //     66 e9 4b d4 ef 8a 2c 3b 88 4c fa 59 ca 34 2b 2e
        let key = [0u8; 16];
        let ct = [0u8; 16];
        let mask = sn_mask_aes128(&key, &ct);
        assert_eq!(mask, [0x66, 0xe9]);
    }

    #[test]
    fn sn_mask_aes128_short_ciphertext_zero_padded() {
        // Padding policy: a sub-16-byte ciphertext is zero-padded so the
        // mask is well-defined. Real call sites never hit this because
        // the AEAD tag alone is 16 bytes; this guards the helper.
        let key = [0u8; 16];
        let short = [0u8; 4];
        let mask_short = sn_mask_aes128(&key, &short);
        let zero = [0u8; 16];
        let mask_zero = sn_mask_aes128(&key, &zero);
        assert_eq!(mask_short, mask_zero);
    }

    #[test]
    fn sn_mask_aes256_known_vector() {
        // FIPS-197 reference: AES-256(0..0, 0..0) =
        //     dc 95 c0 78 a2 40 89 89 ad 48 a2 14 92 84 20 87
        let key = [0u8; 32];
        let ct = [0u8; 16];
        let mask = sn_mask_aes256(&key, &ct);
        assert_eq!(mask, [0xdc, 0x95]);
    }

    #[test]
    fn encode_decode_with_real_mask() {
        // Apply a non-trivial sn_mask end-to-end: encode XORs it in, decode
        // XORs it out, the recovered seq_low must equal the input seq.
        let mut out = Vec::new();
        let mask = [0xAA, 0x55];
        let ct = dummy_ct();
        encode_record(&mut out, 3, 0x1234, true, false, &ct, &mask);

        // On the wire the seq bytes are 0x12^0xAA, 0x34^0x55 = 0xB8, 0x61.
        assert_eq!(&out[1..3], &[0xB8, 0x61]);
        let (hdr, body) = decode_record(&out, &mask).unwrap();
        assert_eq!(hdr.seq_low, 0x1234);
        assert_eq!(body, ct.as_slice());
    }

    #[test]
    fn peek_header_layout_matches_decode() {
        let mut out = Vec::new();
        let mask = [0u8; 2];
        let ct = dummy_ct();
        encode_record(&mut out, 0, 9, true, false, &ct, &mask);

        let (hdr_len, body_len) = peek_header_layout(&out).unwrap();
        assert_eq!(hdr_len, 5);
        assert_eq!(body_len, ct.len());

        // L=0 path: body_len = remaining datagram bytes.
        let mut out2 = Vec::new();
        encode_record(&mut out2, 0, 9, true, true, &ct, &mask);
        let (hdr_len2, body_len2) = peek_header_layout(&out2).unwrap();
        assert_eq!(hdr_len2, 3);
        assert_eq!(body_len2, ct.len());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "DTLS seq must fit in 48 bits")]
    fn encode_panics_on_oversized_seq() {
        let mut out = Vec::new();
        let mask = [0u8; 2];
        encode_record(&mut out, 0, 1u64 << 48, true, false, b"", &mask);
    }
}
