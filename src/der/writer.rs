//! DER encoding helpers (allocation-based).

use super::tag;
use alloc::vec::Vec;

/// Encodes a definite-form DER length.
fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let mut bytes = [0u8; core::mem::size_of::<usize>()];
    let mut n = 0;
    let mut l = len;
    while l > 0 {
        bytes[n] = (l & 0xff) as u8;
        l >>= 8;
        n += 1;
    }
    out.push(0x80 | n as u8);
    for i in (0..n).rev() {
        out.push(bytes[i]);
    }
}

/// Encodes a tag-length-value with the given `tag` wrapping `content`.
pub fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    encode_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

/// Wraps `content` (the already-encoded elements) in a `SEQUENCE`.
pub fn encode_sequence(content: &[u8]) -> Vec<u8> {
    encode_tlv(tag::SEQUENCE, content)
}

/// Encodes an unsigned big-endian integer as a DER `INTEGER`, trimming leading
/// zeros and prepending `0x00` when needed to keep the value positive.
pub fn encode_integer(unsigned_be: &[u8]) -> Vec<u8> {
    // Strip leading zero bytes, keeping at least one byte.
    let mut start = 0;
    while start + 1 < unsigned_be.len() && unsigned_be[start] == 0 {
        start += 1;
    }
    let trimmed = &unsigned_be[start..];

    let mut content = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        content.push(0x00);
    }
    content.extend_from_slice(trimmed);
    encode_tlv(tag::INTEGER, &content)
}

/// Encodes an `OCTET STRING`.
pub fn encode_octet_string(content: &[u8]) -> Vec<u8> {
    encode_tlv(tag::OCTET_STRING, content)
}

/// Encodes a `BIT STRING` with zero unused bits.
pub fn encode_bit_string(bits: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bits.len() + 1);
    content.push(0x00); // unused-bits count
    content.extend_from_slice(bits);
    encode_tlv(tag::BIT_STRING, &content)
}

/// Encodes an `OBJECT IDENTIFIER` from its already-encoded body bytes.
pub fn encode_oid(body: &[u8]) -> Vec<u8> {
    encode_tlv(tag::OID, body)
}

/// Encodes a `NULL`.
pub fn encode_null() -> Vec<u8> {
    encode_tlv(tag::NULL, &[])
}

/// Wraps `content` in a constructed context-specific tag `[n]`.
pub fn encode_context(n: u8, content: &[u8]) -> Vec<u8> {
    encode_tlv(tag::context(n), content)
}
