//! HelloVerifyRequest cookie (RFC 6347 §4.2.1).
//!
//! DTLS adds a stateless DoS-mitigation step to the handshake: the server
//! refuses to allocate per-connection state until the client has echoed
//! back a server-issued *cookie*. Because the cookie's only job is to prove
//! that the client can receive packets at the source address it claims,
//! the server computes it from a long-lived secret and the salient parts of
//! the client's first ClientHello.
//!
//! Construction here: `HMAC-SHA256(secret, client_addr ‖ client_random)`,
//! truncated to 32 bytes. RFC 6347 leaves the cookie content opaque and
//! "verifiable using only the secret values held by the server", and the
//! standard cookbook choice is HMAC over the client identifier plus the
//! ClientHello fingerprint. Including the `client_random` binds the cookie
//! to the specific handshake attempt; including `client_addr` binds it to
//! the source.
//!
//! Validation runs in constant time: same HMAC computation, constant-time
//! tag comparison. A wrong length, wrong address, wrong random, or replay
//! from a different source all collapse to `false` without leaking which
//! byte differed.
//!
//! ## Cookie format
//!
//! `cookie := TS(4) ‖ HMAC-SHA256(secret, client_addr ‖ client_random ‖ TS)[..32]`
//!
//! `TS` is the issuing server's timestamp in minutes, big-endian (32-bit).
//! Validation rejects cookies whose `now - TS > max_age_minutes`; this
//! upper-bounds the replay window even if the secret is never rotated. The
//! HMAC binds `TS` so an attacker can't extend a cookie's lifetime by
//! editing the timestamp.

use crate::ct::{Choice, ConstantTimeEq};
use crate::hash::{HmacSha256, Sha256};

/// Length of an issued cookie: 4-byte timestamp || 32-byte HMAC.
pub(crate) const COOKIE_LEN: usize = 36;
/// Default cookie validity window in minutes. Cookies older than this are
/// rejected even if they validate the HMAC.
pub(crate) const DEFAULT_MAX_AGE_MIN: u32 = 10;

/// Stateless HelloVerifyRequest cookie generator/validator.
///
/// The server holds a long-lived 32-byte secret; rotating it invalidates all
/// outstanding cookies, which is the intended way to recover after suspected
/// secret compromise.
pub(crate) struct CookieGenerator {
    secret: [u8; 32],
    max_age_minutes: u32,
}

impl CookieGenerator {
    /// Creates a generator bound to `secret`. The caller is responsible for
    /// generating a high-entropy secret (e.g. via `crate::rng::OsRng`).
    pub(crate) fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            max_age_minutes: DEFAULT_MAX_AGE_MIN,
        }
    }

    /// Override the maximum cookie age in minutes.
    #[allow(dead_code)]
    pub(crate) fn with_max_age_minutes(mut self, minutes: u32) -> Self {
        self.max_age_minutes = minutes;
        self
    }

    /// Computes the cookie for a given client. `client_addr` is an opaque
    /// identifier for the source (typically the 6/18-byte IP+port packed
    /// representation), `client_random` is the 32-byte random nonce from
    /// CH1, and `now_minutes` is the issuing-server clock in minutes
    /// (typically `unix_time_seconds / 60`, truncated to `u32`).
    pub(crate) fn generate(
        &self,
        client_addr: &[u8],
        client_random: &[u8; 32],
        now_minutes: u32,
    ) -> [u8; COOKIE_LEN] {
        let ts = now_minutes.to_be_bytes();
        let tag = HmacSha256::new(&self.secret)
            .chain(client_addr)
            .chain(client_random)
            .chain(&ts)
            .finalize();
        let mut out = [0u8; COOKIE_LEN];
        out[..4].copy_from_slice(&ts);
        out[4..].copy_from_slice(tag.as_ref());
        out
    }

    /// Constant-time validation of `cookie` against a freshly-computed
    /// reference value. Returns `true` only if every byte matches AND the
    /// embedded timestamp is within the configured `max_age_minutes` of
    /// `now_minutes`.
    pub(crate) fn validate(
        &self,
        client_addr: &[u8],
        client_random: &[u8; 32],
        now_minutes: u32,
        cookie: &[u8],
    ) -> bool {
        if cookie.len() != COOKIE_LEN {
            return false;
        }
        let mut ts_bytes = [0u8; 4];
        ts_bytes.copy_from_slice(&cookie[..4]);
        let ts = u32::from_be_bytes(ts_bytes);
        // Reject cookies from the future (one-minute clock-skew tolerance) and
        // those older than max_age_minutes. Saturating to avoid wraparound.
        let age = now_minutes.saturating_sub(ts);
        let future_skew = ts.saturating_sub(now_minutes);
        if age > self.max_age_minutes || future_skew > 1 {
            return false;
        }
        let expected = self.generate(client_addr, client_random, ts);
        let eq: Choice = expected.as_slice().ct_eq(cookie);
        bool::from(eq)
    }
}

// `Sha256` is in scope as the digest backing `HmacSha256`; keep an explicit
// alias use so the import is exercised even if compiler optimisations drop
// the type elsewhere.
#[allow(dead_code)]
type _Sha256ForHmac = Sha256;

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    fn fixed_random() -> [u8; 32] {
        let mut r = [0u8; 32];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (0xa0 + i) as u8;
        }
        r
    }

    const TS: u32 = 1_000_000;

    #[test]
    fn generate_then_validate_succeeds() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"203.0.113.5:50000";
        let rand = fixed_random();
        let cookie = cg.generate(addr, &rand, TS);
        assert!(cg.validate(addr, &rand, TS, &cookie));
        // A minute later is still within the default window.
        assert!(cg.validate(addr, &rand, TS + 1, &cookie));
    }

    #[test]
    fn expired_cookie_fails() {
        let cg = CookieGenerator::new(fixed_secret()).with_max_age_minutes(5);
        let addr = b"client";
        let rand = fixed_random();
        let cookie = cg.generate(addr, &rand, TS);
        assert!(cg.validate(addr, &rand, TS + 5, &cookie));
        // One minute past the window.
        assert!(!cg.validate(addr, &rand, TS + 6, &cookie));
        // Far future also rejected.
        assert!(!cg.validate(addr, &rand, TS + 1_000_000, &cookie));
    }

    #[test]
    fn future_cookie_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"client";
        let rand = fixed_random();
        let cookie = cg.generate(addr, &rand, TS + 5);
        // Server clock 5 minutes behind the cookie's timestamp.
        assert!(!cg.validate(addr, &rand, TS, &cookie));
    }

    #[test]
    fn wrong_address_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr_a = b"203.0.113.5:50000";
        let addr_b = b"203.0.113.5:50001";
        let rand = fixed_random();
        let cookie = cg.generate(addr_a, &rand, TS);
        assert!(!cg.validate(addr_b, &rand, TS, &cookie));
    }

    #[test]
    fn wrong_random_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"203.0.113.5:50000";
        let rand_a = fixed_random();
        let mut rand_b = rand_a;
        rand_b[0] ^= 1;
        let cookie = cg.generate(addr, &rand_a, TS);
        assert!(!cg.validate(addr, &rand_b, TS, &cookie));
    }

    #[test]
    fn truncated_cookie_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"203.0.113.5:50000";
        let rand = fixed_random();
        let cookie = cg.generate(addr, &rand, TS);
        assert!(!cg.validate(addr, &rand, TS, &cookie[..COOKIE_LEN - 1]));
        assert!(!cg.validate(addr, &rand, TS, &[]));
        let mut bad = cookie;
        bad[COOKIE_LEN - 1] ^= 1;
        assert!(!cg.validate(addr, &rand, TS, &bad));
    }

    #[test]
    fn distinct_secrets_disagree() {
        let cg_a = CookieGenerator::new([0xaa; 32]);
        let cg_b = CookieGenerator::new([0xbb; 32]);
        let addr = b"client";
        let rand = fixed_random();
        let cookie_a = cg_a.generate(addr, &rand, TS);
        assert!(!cg_b.validate(addr, &rand, TS, &cookie_a));
    }
}
