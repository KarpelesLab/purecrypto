//! RFC 9000 §8.1.2 — server-side stateless Retry token.
//!
//! The server mints a token that proves the client received a Retry packet
//! at the IP address it claims to be using. The token is sized so that the
//! server need not keep any per-token state: the token's HMAC tag
//! authenticates the binding `(client_addr, ODCID, timestamp)` under a
//! server-secret HMAC key. When the client retransmits its Initial with
//! the token, the server re-derives the tag and constant-time-compares.
//!
//! ## Wire format
//!
//! ```text
//!   client_addr_bytes  (18 bytes)  -- IPv4-mapped IPv6 address (16) + port (2 BE)
//!   odcid_len          (1 byte)    -- 0..=20
//!   odcid_bytes        (odcid_len) -- original Destination CID
//!   timestamp_be       (8 bytes)   -- u64 seconds since server start (big-endian)
//!   tag                (16 bytes)  -- HMAC-SHA256( retry_secret, body )[..16]
//! ```
//!
//! Both the address and the ODCID are inputs to the HMAC; recomputation on
//! validate uses the *received* `client_addr_bytes` (the same the server
//! observed on the second Initial), the ODCID extracted from the token
//! body, and the timestamp from the token body.
//!
//! ## Lifetime
//!
//! Tokens older than [`MAX_TOKEN_AGE_SECS`] (300 seconds = 5 minutes) are
//! rejected even if the HMAC is valid. The server picks a monotonic
//! `now_secs` reading (e.g. seconds since the engine started) and threads
//! it through both [`mint`] and [`validate`]. A 5-minute window is short
//! enough that an attacker who somehow exfiltrates a token cannot replay
//! it indefinitely, yet long enough that a slow legitimate client doesn't
//! get bounced.
//!
//! ## Constant-time HMAC comparison
//!
//! [`Hmac::verify`](crate::hash::Hmac::verify) uses
//! `Choice::from(ConstantTimeEq::ct_eq)` over the 16-byte tag, which
//! matches the entire byte string in constant time regardless of which
//! byte differs (RFC 9000 §21.1 forbids variable-time MAC comparison —
//! a timing oracle that leaks the first-differing byte would let an
//! attacker forge a token in 256 × 16 = 4096 queries).

#![allow(dead_code)]

use alloc::vec::Vec;

use crate::ct::ConstantTimeEq;
use crate::hash::HmacSha256;
use crate::tls::Error;

/// Maximum age of an accepted retry token, in seconds. RFC 9000 §8.1.2
/// recommends "a short period of time" without naming a concrete value;
/// 5 minutes is the de-facto standard across QUIC stacks (matches what
/// quiche, ngtcp2, and msquic use).
pub(crate) const MAX_TOKEN_AGE_SECS: u64 = 300;

/// Length of the canonical client-address encoding: 16 bytes of IPv6
/// address (IPv4 addresses are encoded as IPv4-mapped IPv6 per RFC 4291
/// §2.5.5.2) plus 2 bytes of UDP port in network byte order.
pub(crate) const CLIENT_ADDR_BYTES: usize = 18;

/// Truncated HMAC tag length used in the token.
const TAG_LEN: usize = 16;

/// Mints a retry token binding `(client_addr_bytes, odcid, now_secs)` under
/// `retry_secret`. Length of the returned `Vec` is
/// `18 + 1 + odcid.len() + 8 + 16`.
pub(crate) fn mint(
    retry_secret: &[u8; 32],
    client_addr_bytes: &[u8; CLIENT_ADDR_BYTES],
    odcid: &[u8],
    now_secs: u64,
) -> Vec<u8> {
    debug_assert!(odcid.len() <= 20, "QUIC v1 CID length must be ≤ 20 bytes");
    let mut out = Vec::with_capacity(CLIENT_ADDR_BYTES + 1 + odcid.len() + 8 + TAG_LEN);
    out.extend_from_slice(client_addr_bytes);
    out.push(odcid.len() as u8);
    out.extend_from_slice(odcid);
    out.extend_from_slice(&now_secs.to_be_bytes());
    // Body (everything we just wrote) is the HMAC input.
    let body_len = out.len();
    let tag = HmacSha256::mac(retry_secret, &out[..body_len]);
    out.extend_from_slice(&tag[..TAG_LEN]);
    out
}

/// Validates a retry token. Returns the bound ODCID on success.
///
/// Failure modes:
/// * Malformed wire syntax → [`Error::Decode`].
/// * Client address mismatch (the address bytes in the token don't equal
///   `client_addr_bytes`) → [`Error::Decode`].
/// * HMAC mismatch → [`Error::Decode`] (constant-time compare).
/// * Timestamp in the future, or `now_secs - ts > MAX_TOKEN_AGE_SECS` →
///   [`Error::Decode`].
pub(crate) fn validate(
    retry_secret: &[u8; 32],
    client_addr_bytes: &[u8; CLIENT_ADDR_BYTES],
    token: &[u8],
    now_secs: u64,
) -> Result<Vec<u8>, Error> {
    // Minimum: 18 addr + 1 odcid_len + 0 odcid + 8 ts + 16 tag = 43.
    if token.len() < CLIENT_ADDR_BYTES + 1 + 8 + TAG_LEN {
        return Err(Error::Decode);
    }

    // The address field is part of the HMAC input AND must equal the
    // observed peer address. We test both to give a clean failure mode in
    // both cases — but the equality check itself is non-secret (the
    // attacker can already see their own address), so a fast `==`
    // suffices.
    let addr_in_token = &token[..CLIENT_ADDR_BYTES];
    if addr_in_token != client_addr_bytes.as_slice() {
        return Err(Error::Decode);
    }

    let odcid_len = token[CLIENT_ADDR_BYTES] as usize;
    if odcid_len > 20 {
        return Err(Error::Decode);
    }
    let odcid_start = CLIENT_ADDR_BYTES + 1;
    let odcid_end = odcid_start + odcid_len;
    let ts_start = odcid_end;
    let ts_end = ts_start + 8;
    let tag_start = ts_end;
    let tag_end = tag_start + TAG_LEN;
    if token.len() != tag_end {
        // Strict length check: extraneous bytes are rejected (mirrors RFC
        // 9000 §16's "MUST decode as the shortest encoding" mindset).
        return Err(Error::Decode);
    }

    // Constant-time HMAC verify over the entire body. We re-MAC the body
    // ourselves (the slice `token[..tag_start]`) and verify; `Hmac::verify`
    // returns a `Choice` that we coerce to bool only after the compare.
    let body = &token[..tag_start];
    let computed = HmacSha256::mac(retry_secret, body);
    let provided = &token[tag_start..tag_end];
    // `ConstantTimeEq::ct_eq` on a fixed-length slice — same primitive
    // `Hmac::verify` uses, but applied to the truncated tag rather than
    // the full 32-byte SHA-256 output.
    let ok = computed[..TAG_LEN].ct_eq(provided);
    if !bool::from(ok) {
        return Err(Error::Decode);
    }

    // Timestamp range check (after the MAC succeeded — otherwise we leak a
    // timing oracle: "MAC failed" should look identical to "MAC succeeded
    // but timestamp out of range").
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&token[ts_start..ts_end]);
    let ts = u64::from_be_bytes(ts_bytes);
    // Reject tokens minted "in the future" (clock skew → adversary).
    if ts > now_secs {
        return Err(Error::Decode);
    }
    if now_secs - ts > MAX_TOKEN_AGE_SECS {
        return Err(Error::Decode);
    }

    Ok(token[odcid_start..odcid_end].to_vec())
}

/// Canonicalises a [`std::net::SocketAddr`] to the 18-byte form expected by
/// [`mint`] / [`validate`]. IPv4 addresses are encoded as IPv4-mapped IPv6
/// (`::ffff:a.b.c.d`) so that the same client reaching the server over a
/// dual-stack socket via either v4 or v6 produces the same token bytes.
#[cfg(feature = "std")]
pub(crate) fn encode_addr(addr: &std::net::SocketAddr) -> [u8; CLIENT_ADDR_BYTES] {
    let mut out = [0u8; CLIENT_ADDR_BYTES];
    let ip6 = match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        std::net::IpAddr::V6(v6) => v6,
    };
    out[..16].copy_from_slice(&ip6.octets());
    out[16..18].copy_from_slice(&addr.port().to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn fixed_secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    #[test]
    fn retry_token_roundtrip() {
        let secret = fixed_secret();
        let addr = encode_addr(&SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            4433,
        ));
        let odcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let now = 1000u64;
        let tok = mint(&secret, &addr, &odcid, now);
        let got = validate(&secret, &addr, &tok, now).expect("validate ok");
        assert_eq!(got, odcid);
    }

    #[test]
    fn retry_token_rejects_wrong_addr() {
        let secret = fixed_secret();
        let addr1 = encode_addr(&SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            4433,
        ));
        let addr2 = encode_addr(&SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            4433,
        ));
        let odcid = [0xaa; 8];
        let tok = mint(&secret, &addr1, &odcid, 1000);
        let err = validate(&secret, &addr2, &tok, 1000);
        assert!(err.is_err());
    }

    #[test]
    fn retry_token_rejects_wrong_secret() {
        let secret_a = fixed_secret();
        let mut secret_b = fixed_secret();
        secret_b[0] ^= 1;
        let addr = encode_addr(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0));
        let tok = mint(&secret_a, &addr, &[1, 2, 3, 4], 100);
        let err = validate(&secret_b, &addr, &tok, 100);
        assert!(err.is_err());
    }

    #[test]
    fn retry_token_rejects_expired() {
        let secret = fixed_secret();
        let addr = encode_addr(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0));
        let odcid = [0xab; 8];
        let tok = mint(&secret, &addr, &odcid, 100);
        // 100 + 300 = 400 → still good
        assert!(validate(&secret, &addr, &tok, 400).is_ok());
        // 100 + 301 = 401 → expired
        assert!(validate(&secret, &addr, &tok, 401).is_err());
    }

    #[test]
    fn retry_token_rejects_future_timestamp() {
        // Defensive: if the token claims to be minted in the future
        // (clock skew or attacker manipulation), reject.
        let secret = fixed_secret();
        let addr = encode_addr(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0));
        let tok = mint(&secret, &addr, &[0xcd; 4], 500);
        let err = validate(&secret, &addr, &tok, 100);
        assert!(err.is_err());
    }

    #[test]
    fn retry_token_rejects_tampered_hmac() {
        let secret = fixed_secret();
        let addr = encode_addr(&SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            7777,
        ));
        let odcid = [0xde, 0xad, 0xbe, 0xef];
        let mut tok = mint(&secret, &addr, &odcid, 1234);
        // Flip a byte inside the tag.
        let last = tok.len() - 1;
        tok[last] ^= 1;
        assert!(validate(&secret, &addr, &tok, 1234).is_err());
    }

    #[test]
    fn retry_token_rejects_tampered_body_bytes() {
        let secret = fixed_secret();
        let addr = encode_addr(&SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            7777,
        ));
        let odcid = [0xde, 0xad, 0xbe, 0xef];
        let mut tok = mint(&secret, &addr, &odcid, 1234);
        // Flip a byte in the ODCID bytes.
        let body_offset = CLIENT_ADDR_BYTES + 1; // first ODCID byte
        tok[body_offset] ^= 1;
        assert!(validate(&secret, &addr, &tok, 1234).is_err());
    }

    #[test]
    fn retry_token_rejects_short_token() {
        let secret = fixed_secret();
        let addr = encode_addr(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0));
        // Any sub-43-byte input is structurally invalid.
        assert!(validate(&secret, &addr, &[], 0).is_err());
        assert!(validate(&secret, &addr, &[0u8; 42], 0).is_err());
    }

    #[test]
    fn retry_token_rejects_extra_trailing_bytes() {
        let secret = fixed_secret();
        let addr = encode_addr(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0));
        let mut tok = mint(&secret, &addr, &[0u8; 8], 100);
        tok.push(0); // append garbage
        assert!(validate(&secret, &addr, &tok, 100).is_err());
    }

    #[test]
    fn encode_addr_ipv4_mapped_matches_ipv6() {
        // IPv4 127.0.0.1 → ::ffff:127.0.0.1. The same v6 literal should
        // encode identically (apart from port).
        let a = encode_addr(&SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            4242,
        ));
        let v6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001);
        let b = encode_addr(&SocketAddr::new(IpAddr::V6(v6), 4242));
        assert_eq!(a, b);
    }

    /// RFC 9000 §21.1: MAC comparison MUST be constant time. We can't
    /// directly observe timing here, but we can assert that the verify
    /// path uses [`ConstantTimeEq`] / [`HmacSha256::mac`] + `ct_eq` (a
    /// code-level invariant — flipping each byte still rejects, and the
    /// test passes uniformly regardless of which byte differs).
    #[test]
    fn retry_token_constant_time_compare() {
        let secret = fixed_secret();
        let addr = encode_addr(&SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
        ));
        let tok = mint(&secret, &addr, &[1, 2, 3, 4], 1000);
        // Flip each byte in the tag region; every single-bit corruption
        // must be rejected. (Earlier-byte vs later-byte rejection takes
        // the same code path — constant-time `ct_eq` accumulates a
        // bitwise OR across the whole slice.)
        let tag_start = tok.len() - TAG_LEN;
        for i in tag_start..tok.len() {
            let mut bad = tok.clone();
            bad[i] ^= 1;
            assert!(
                validate(&secret, &addr, &bad, 1000).is_err(),
                "tag corruption at byte {i} accepted"
            );
        }
    }
}
