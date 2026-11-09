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
/// zeros and prepending `0x00` when needed to keep the value positive. The
/// empty slice is encoded as the canonical zero (`02 01 00`).
pub fn encode_integer(unsigned_be: &[u8]) -> Vec<u8> {
    if unsigned_be.is_empty() {
        // Canonical zero encoding rather than panicking on `trimmed[0]`.
        return encode_tlv(tag::INTEGER, &[0u8]);
    }
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

/// Encodes a `BOOLEAN` (DER uses `0xFF` for true).
pub fn encode_boolean(value: bool) -> Vec<u8> {
    encode_tlv(tag::BOOLEAN, &[if value { 0xff } else { 0x00 }])
}

/// Encodes a string value with the given string `tag` (e.g.
/// [`tag::UTF8_STRING`], [`tag::PRINTABLE_STRING`], [`tag::UTC_TIME`]).
pub fn encode_string(tag: u8, s: &str) -> Vec<u8> {
    encode_tlv(tag, s.as_bytes())
}

/// Wraps `content` in a constructed context-specific tag `[n]`.
pub fn encode_context(n: u8, content: &[u8]) -> Vec<u8> {
    encode_tlv(tag::context(n), content)
}

/// Upper bound on a DER tag + definite-form length header.
#[cfg(any(feature = "rsa", feature = "dsa"))]
const MAX_HEADER: usize = 2 + core::mem::size_of::<usize>();

/// Wipe-on-drop DER encoders for secret content (private-key export).
///
/// The generic encoders above build their result through intermediate
/// buffers that go back to the allocator intact (`encode_integer`'s
/// `content`, a caller's `[..].concat()`), and a `Vec` that grows leaves its
/// old buffer behind unwiped. These allocate every buffer once, at a
/// capacity that covers its final size, inside
/// [`Zeroizing`](crate::zeroize::Zeroizing), and emit exactly the same
/// bytes.
///
/// They are associated functions of `Zeroizing<Vec<u8>>` (rather than free
/// functions) so that every key module can reach them without this private
/// module being re-exported.
#[cfg(any(feature = "rsa", feature = "dsa"))]
impl crate::zeroize::Zeroizing<Vec<u8>> {
    /// [`encode_tlv`] for secret content.
    pub(crate) fn der_tlv(tag: u8, content: &[u8]) -> Self {
        let mut out = Self::new(Vec::with_capacity(content.len() + MAX_HEADER));
        out.push(tag);
        encode_length(content.len(), &mut out);
        out.extend_from_slice(content);
        out
    }

    /// [`encode_integer`] for a secret value: the same canonical DER
    /// `INTEGER` (leading zeros trimmed, `0x00` prepended for a set high
    /// bit, the empty slice encoded as zero), without the intermediate
    /// content buffer.
    pub(crate) fn der_integer(unsigned_be: &[u8]) -> Self {
        let start = unsigned_be
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(unsigned_be.len().saturating_sub(1));
        let trimmed = unsigned_be.get(start..).unwrap_or(&[]);
        let trimmed: &[u8] = if trimmed.is_empty() { &[0] } else { trimmed };
        let pad = usize::from(trimmed[0] & 0x80 != 0);
        let len = trimmed.len() + pad;
        let mut out = Self::new(Vec::with_capacity(len + MAX_HEADER));
        out.push(tag::INTEGER);
        encode_length(len, &mut out);
        if pad == 1 {
            out.push(0);
        }
        out.extend_from_slice(trimmed);
        out
    }

    /// Concatenates already-encoded elements into one buffer allocated at
    /// its final size.
    pub(crate) fn der_concat(parts: &[&[u8]]) -> Self {
        let mut out = Self::new(Vec::with_capacity(parts.iter().map(|p| p.len()).sum()));
        for p in parts {
            out.extend_from_slice(p);
        }
        out
    }

    /// Moves the encoding out of its wrapper for a caller that takes
    /// ownership of it (the wrapper is left holding an empty vector, so
    /// nothing is copied and nothing is left behind).
    pub(crate) fn into_plain(mut self) -> Vec<u8> {
        core::mem::take(&mut *self)
    }
}
