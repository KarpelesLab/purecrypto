//! base64url without padding (RFC 7515 Appendix C, RFC 4648 §5).
//!
//! The decoder is strict: it rejects `=` padding, any character outside the
//! URL-safe alphabet, an encoding whose length is `1 mod 4` (no such
//! encoding exists) and non-zero trailing bits in the last character (the
//! encoding of a byte string is unique, so `AB` — whose second character
//! carries four bits that no byte uses — is not the encoding of anything).
//! JWS/JWE inputs feed straight into a MAC or signature check, so every
//! lenient decoding is a second, equally-signed spelling of the same message.

use super::Error;
use alloc::string::String;
use alloc::vec::Vec;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes `data` as base64url without padding.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

fn value_of(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(v as u32)
}

/// Strictly decodes unpadded base64url (see the module docs for what is
/// rejected). The empty string decodes to the empty byte string.
pub fn decode(s: &str) -> Result<Vec<u8>, Error> {
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(Error::Base64);
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for &c in chunk {
            n = (n << 6) | value_of(c).ok_or(Error::Base64)?;
        }
        match chunk.len() {
            4 => {
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            3 => {
                // 18 bits: two bytes plus two bits that must be zero.
                if n & 0b11 != 0 {
                    return Err(Error::Base64);
                }
                out.push((n >> 10) as u8);
                out.push((n >> 2) as u8);
            }
            2 => {
                // 12 bits: one byte plus four bits that must be zero.
                if n & 0b1111 != 0 {
                    return Err(Error::Base64);
                }
                out.push((n >> 4) as u8);
            }
            _ => unreachable!("chunk length 1 was rejected above"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7515_appendix_c() {
        let v = [3u8, 236, 255, 224, 193];
        assert_eq!(encode(&v), "A-z_4ME");
        assert_eq!(decode("A-z_4ME").unwrap(), v);
        assert_eq!(encode(b""), "");
        assert_eq!(decode("").unwrap(), b"");
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
    }

    #[test]
    fn strictness() {
        assert!(decode("Zg==").is_err(), "padding");
        assert!(decode("Zg=").is_err());
        assert!(decode("Z").is_err(), "length 1 mod 4");
        assert!(decode("Zm+v").is_err(), "standard alphabet");
        assert!(decode("Zm/v").is_err());
        assert!(decode("Zm9v ").is_err(), "whitespace");
        assert!(decode("AB").is_err(), "non-zero trailing bits");
        assert!(decode("AA").is_ok());
        assert!(decode("AAB").is_err());
        assert!(decode("AAA").is_ok());
        assert!(decode("?Zm9v").is_err());
    }

    #[test]
    fn round_trip() {
        for len in 0..70usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data);
        }
    }
}
