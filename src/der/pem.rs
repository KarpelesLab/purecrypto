//! Base64 and PEM encoding (RFC 4648 / RFC 7468).

use super::Error;
use alloc::string::String;
use alloc::vec::Vec;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64-encodes `data` (standard alphabet, with `=` padding).
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Maps a Base64 character to its 6-bit value.
fn decode_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Base64-decodes `s`, ignoring ASCII whitespace and treating `=` as padding.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = decode_char(c).ok_or(Error::Pem)?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// Wraps DER `der` bytes in a PEM document with the given `label`, e.g.
/// `pem_encode("PRIVATE KEY", &der)`.
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = base64_encode(der);
    let mut out = String::with_capacity(b64.len() + label.len() * 2 + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    let bytes = b64.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + 64).min(bytes.len());
        // base64 output is ASCII, so byte slicing is valid UTF-8.
        out.push_str(core::str::from_utf8(&bytes[i..end]).unwrap());
        out.push('\n');
        i = end;
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Decodes a PEM document, verifying the `expected_label`, and returns the
/// inner DER bytes.
pub fn pem_decode(pem: &str, expected_label: &str) -> Result<Vec<u8>, Error> {
    let begin = {
        let mut s = String::from("-----BEGIN ");
        s.push_str(expected_label);
        s.push_str("-----");
        s
    };
    let end = {
        let mut s = String::from("-----END ");
        s.push_str(expected_label);
        s.push_str("-----");
        s
    };

    let start = pem.find(&begin).ok_or(Error::Pem)? + begin.len();
    let stop = pem[start..].find(&end).ok_or(Error::Pem)? + start;
    base64_decode(&pem[start..stop])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        for (input, expected) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input), expected);
            assert_eq!(base64_decode(expected).unwrap(), input);
        }
    }

    #[test]
    fn base64_rejects_invalid() {
        assert_eq!(base64_decode("****"), Err(Error::Pem));
    }

    #[test]
    fn pem_roundtrip() {
        let der = [0x30u8, 0x03, 0x02, 0x01, 0x2a]; // SEQUENCE { INTEGER 42 }
        let pem = pem_encode("TEST KEY", &der);
        assert!(pem.starts_with("-----BEGIN TEST KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END TEST KEY-----"));
        assert_eq!(pem_decode(&pem, "TEST KEY").unwrap(), der);
        // Wrong label is rejected.
        assert_eq!(pem_decode(&pem, "OTHER").unwrap_err(), Error::Pem);
    }

    #[test]
    fn pem_line_wrapping() {
        // 120 bytes -> 160 base64 chars -> wrapped into 64-char lines.
        let der = [0xabu8; 120];
        let pem = pem_encode("DATA", &der);
        for line in pem.lines() {
            assert!(line.len() <= 64, "line too long: {}", line.len());
        }
        assert_eq!(pem_decode(&pem, "DATA").unwrap(), der);
    }
}
