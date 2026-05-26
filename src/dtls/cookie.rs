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
//! The DTLS server state machines that issue and validate cookies land in
//! commits 10 and 14, so the items below are `#[allow(dead_code)]` for now.

#![allow(dead_code)]

use crate::ct::{Choice, ConstantTimeEq};
use crate::hash::{HmacSha256, Sha256};

/// Length of an issued cookie. We size to 32 bytes — the full SHA-256 tag
/// width, which is well within the 0..255 cookie-length field DTLS allows.
pub(crate) const COOKIE_LEN: usize = 32;

/// Stateless HelloVerifyRequest cookie generator/validator.
///
/// The server holds a long-lived 32-byte secret; rotating it invalidates all
/// outstanding cookies, which is the intended way to recover after suspected
/// secret compromise.
pub(crate) struct CookieGenerator {
    secret: [u8; 32],
}

impl CookieGenerator {
    /// Creates a generator bound to `secret`. The caller is responsible for
    /// generating a high-entropy secret (e.g. via `crate::rng::OsRng`).
    pub(crate) fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    /// Computes the cookie for a given client. `client_addr` is an opaque
    /// identifier for the source (typically the 6/18-byte IP+port packed
    /// representation), and `client_random` is the 32-byte random nonce
    /// from the ClientHello.
    pub(crate) fn generate(
        &self,
        client_addr: &[u8],
        client_random: &[u8; 32],
    ) -> [u8; COOKIE_LEN] {
        let tag = HmacSha256::new(&self.secret)
            .chain(client_addr)
            .chain(client_random)
            .finalize();
        let mut out = [0u8; COOKIE_LEN];
        out.copy_from_slice(tag.as_ref());
        out
    }

    /// Constant-time validation of `cookie` against a freshly-computed
    /// reference value. Returns `true` only if every byte matches.
    ///
    /// A `cookie` whose length is not exactly [`COOKIE_LEN`] fails
    /// immediately — the underlying `Hmac::<Sha256>::verify` accepts
    /// shorter slices by truncating, which would weaken the proof.
    pub(crate) fn validate(
        &self,
        client_addr: &[u8],
        client_random: &[u8; 32],
        cookie: &[u8],
    ) -> bool {
        if cookie.len() != COOKIE_LEN {
            return false;
        }
        let expected = self.generate(client_addr, client_random);
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

    #[test]
    fn generate_then_validate_succeeds() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"203.0.113.5:50000";
        let rand = fixed_random();
        let cookie = cg.generate(addr, &rand);
        assert!(cg.validate(addr, &rand, &cookie));
    }

    #[test]
    fn wrong_address_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr_a = b"203.0.113.5:50000";
        let addr_b = b"203.0.113.5:50001";
        let rand = fixed_random();
        let cookie = cg.generate(addr_a, &rand);
        assert!(!cg.validate(addr_b, &rand, &cookie));
    }

    #[test]
    fn wrong_random_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"203.0.113.5:50000";
        let rand_a = fixed_random();
        let mut rand_b = rand_a;
        rand_b[0] ^= 1;
        let cookie = cg.generate(addr, &rand_a);
        assert!(!cg.validate(addr, &rand_b, &cookie));
    }

    #[test]
    fn truncated_cookie_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"203.0.113.5:50000";
        let rand = fixed_random();
        let cookie = cg.generate(addr, &rand);
        // Drop the last byte.
        assert!(!cg.validate(addr, &rand, &cookie[..COOKIE_LEN - 1]));
        // Empty cookie.
        assert!(!cg.validate(addr, &rand, &[]));
        // Right length, wrong bytes.
        let mut bad = cookie;
        bad[COOKIE_LEN - 1] ^= 1;
        assert!(!cg.validate(addr, &rand, &bad));
    }

    #[test]
    fn extended_cookie_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"203.0.113.5:50000";
        let rand = fixed_random();
        let cookie = cg.generate(addr, &rand);
        let mut padded = cookie.to_vec();
        padded.push(0); // 33 bytes — rejected on the length check.
        assert!(!cg.validate(addr, &rand, &padded));
    }

    #[test]
    fn distinct_secrets_disagree() {
        let cg_a = CookieGenerator::new([0xaa; 32]);
        let cg_b = CookieGenerator::new([0xbb; 32]);
        let addr = b"client";
        let rand = fixed_random();
        let cookie_a = cg_a.generate(addr, &rand);
        // The other server cannot validate cookies issued by the first.
        assert!(!cg_b.validate(addr, &rand, &cookie_a));
    }

    #[test]
    fn cookie_is_deterministic() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"client";
        let rand = fixed_random();
        let c1 = cg.generate(addr, &rand);
        let c2 = cg.generate(addr, &rand);
        assert_eq!(c1, c2);
    }
}
