//! HelloVerifyRequest cookie (RFC 6347 §4.2.1; RFC 9147 §5.1 for DTLS 1.3).
//!
//! DTLS adds a stateless DoS-mitigation step to the handshake: the server
//! refuses to allocate per-connection state until the client has echoed
//! back a server-issued *cookie*. Because the cookie's only job is to prove
//! that the client can receive packets at the source address it claims,
//! the server computes it from a long-lived secret and the salient parts of
//! the client's first ClientHello.
//!
//! Construction here:
//! `HMAC-SHA256(secret, client_addr ‖ client_random ‖ ch_fingerprint ‖ TS)`,
//! truncated to 32 bytes.
//!
//! Including the `client_random` binds the cookie to the specific handshake
//! attempt; including `client_addr` binds it to the source; the
//! `ch_fingerprint` is a caller-supplied digest of the security-critical
//! ClientHello fields (cipher_suites, supported_groups, supported_versions,
//! key_share groups, …). Binding the fingerprint prevents an on-path
//! attacker who can intercept the first CH / HRR roundtrip from rewriting
//! the second ClientHello to alter parameters that the server commits to —
//! a downgrade primitive on a vanilla `HMAC(addr ‖ rand)` cookie. RFC 9147
//! §5.1 explicitly calls out that the server may verify CH content via the
//! cookie.
//!
//! Validation runs in constant time: same HMAC computation, constant-time
//! tag comparison. A wrong length, wrong address, wrong random, wrong CH
//! fingerprint, or replay from a different source all collapse to `false`
//! without leaking which byte differed.
//!
//! ## Cookie format
//!
//! `cookie := TS(4) ‖ aux_len(2) ‖ aux(aux_len) ‖ HMAC[..32]`
//!
//! where
//!
//! `HMAC := HMAC-SHA256(secret, client_addr ‖ client_random ‖ ch_fingerprint ‖ TS ‖ aux_len ‖ aux)`.
//!
//! `TS` is the issuing server's timestamp in minutes, big-endian (32-bit).
//! Validation rejects cookies whose `now - TS > max_age_minutes`; this
//! upper-bounds the replay window even if the secret is never rotated. The
//! HMAC binds `TS` so an attacker can't extend a cookie's lifetime by
//! editing the timestamp.
//!
//! The variable-length `aux` payload lets the server carry the small bundle
//! of state (selected suite, selected group, `Hash(CH1)` for the
//! TLS 1.3 message_hash transcript) that would otherwise need to be pinned
//! per-connection before the cookie verifies. With `aux` bound by the
//! HMAC, the server can stay stateless across the HRR roundtrip and
//! rebuild state on the cookie-validated second ClientHello.

extern crate alloc;

use crate::ct::{Choice, ConstantTimeEq};
use crate::hash::{HmacSha256, Sha256};

/// Length of an issued cookie when no auxiliary state is embedded:
/// 4-byte timestamp || 2-byte aux length (0) || 32-byte HMAC.
pub(crate) const COOKIE_LEN: usize = 38;
/// Fixed overhead of an aux-carrying cookie: 4-byte TS || 2-byte aux_len
/// || 32-byte HMAC.
pub(crate) const COOKIE_OVERHEAD: usize = 4 + 2 + 32;
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

    /// Computes a cookie carrying no auxiliary state. Convenience wrapper
    /// over [`Self::generate_with_aux`] for the DTLS 1.2 path where the
    /// transcript starts fresh at CH2 and no inter-CH state needs to be
    /// stashed.
    pub(crate) fn generate(
        &self,
        client_addr: &[u8],
        client_random: &[u8; 32],
        ch_fingerprint: &[u8],
        now_minutes: u32,
    ) -> [u8; COOKIE_LEN] {
        let v =
            self.generate_with_aux(client_addr, client_random, ch_fingerprint, &[], now_minutes);
        let mut out = [0u8; COOKIE_LEN];
        debug_assert_eq!(v.len(), COOKIE_LEN);
        out.copy_from_slice(&v);
        out
    }

    /// Computes the cookie for a given client.
    ///
    /// * `client_addr` is an opaque identifier for the source (typically the
    ///   6/18-byte IP+port packed representation).
    /// * `client_random` is the 32-byte random nonce from CH1.
    /// * `ch_fingerprint` is a caller-supplied digest of the
    ///   security-critical ClientHello fields (cipher_suites,
    ///   supported_groups, supported_versions, key_share groups). Passing a
    ///   fingerprint binds the cookie to the CH's content so an on-path
    ///   attacker can't rewrite CH2 between the HRR roundtrip; pass `&[]`
    ///   only in test paths that don't care about CH binding.
    /// * `aux` is opaque server state to carry round-trip inside the cookie
    ///   (typically: chosen suite, selected group, `Hash(CH1)`). Bound by
    ///   the HMAC; recoverable on validate.
    /// * `now_minutes` is the issuing-server clock in minutes (typically
    ///   `unix_time_seconds / 60`, truncated to `u32`).
    pub(crate) fn generate_with_aux(
        &self,
        client_addr: &[u8],
        client_random: &[u8; 32],
        ch_fingerprint: &[u8],
        aux: &[u8],
        now_minutes: u32,
    ) -> alloc::vec::Vec<u8> {
        let ts = now_minutes.to_be_bytes();
        let aux_len = (aux.len() as u16).to_be_bytes();
        let tag = HmacSha256::new(&self.secret)
            .chain(client_addr)
            .chain(client_random)
            .chain(ch_fingerprint)
            .chain(&ts)
            .chain(&aux_len)
            .chain(aux)
            .finalize();
        let mut out = alloc::vec::Vec::with_capacity(COOKIE_OVERHEAD + aux.len());
        out.extend_from_slice(&ts);
        out.extend_from_slice(&aux_len);
        out.extend_from_slice(aux);
        out.extend_from_slice(tag.as_ref());
        out
    }

    /// Constant-time validation of an aux-less `cookie` (DTLS 1.2 path).
    /// Returns `true` only if the HMAC matches AND the embedded timestamp
    /// is within `max_age_minutes` of `now_minutes`.
    pub(crate) fn validate(
        &self,
        client_addr: &[u8],
        client_random: &[u8; 32],
        ch_fingerprint: &[u8],
        now_minutes: u32,
        cookie: &[u8],
    ) -> bool {
        self.validate_with_aux(
            client_addr,
            client_random,
            ch_fingerprint,
            now_minutes,
            cookie,
        )
        .map(|aux| aux.is_empty())
        .unwrap_or(false)
    }

    /// Constant-time validation of an aux-carrying `cookie`. On success
    /// returns the embedded `aux` bytes (the server's stashed-in-cookie
    /// state); on any failure (length mismatch, expired, future-dated,
    /// HMAC mismatch, address / random / fingerprint mismatch) returns
    /// `None`. The HMAC tag binds all inputs INCLUDING `aux`, so an
    /// attacker cannot rewrite the carried state.
    pub(crate) fn validate_with_aux(
        &self,
        client_addr: &[u8],
        client_random: &[u8; 32],
        ch_fingerprint: &[u8],
        now_minutes: u32,
        cookie: &[u8],
    ) -> Option<alloc::vec::Vec<u8>> {
        if cookie.len() < COOKIE_OVERHEAD {
            return None;
        }
        let mut ts_bytes = [0u8; 4];
        ts_bytes.copy_from_slice(&cookie[..4]);
        let ts = u32::from_be_bytes(ts_bytes);
        let aux_len = u16::from_be_bytes([cookie[4], cookie[5]]) as usize;
        if cookie.len() != COOKIE_OVERHEAD + aux_len {
            return None;
        }
        // Reject cookies from the future (one-minute clock-skew tolerance) and
        // those older than max_age_minutes. Saturating to avoid wraparound.
        let age = now_minutes.saturating_sub(ts);
        let future_skew = ts.saturating_sub(now_minutes);
        if age > self.max_age_minutes || future_skew > 1 {
            return None;
        }
        let aux = &cookie[6..6 + aux_len];
        let expected = self.generate_with_aux(client_addr, client_random, ch_fingerprint, aux, ts);
        // Constant-time over the full cookie image so a length-equal forgery
        // is rejected without leaking which byte differed.
        let eq: Choice = expected.as_slice().ct_eq(cookie);
        if bool::from(eq) {
            Some(aux.to_vec())
        } else {
            None
        }
    }
}

/// Builds a deterministic, length-prefixed fingerprint of the
/// security-critical ClientHello extensions to bind into the cookie MAC.
///
/// The fingerprint covers:
/// * the client's offered cipher suites (TLS layer),
/// * the `supported_groups` extension body (NamedGroup list),
/// * the `supported_versions` extension body (Version list),
/// * the offered `key_share` groups (NamedGroup list — drops the
///   ephemeral public material, which legitimately differs across CH2).
///
/// Each field is length-prefixed (4-byte big-endian) so that
/// `concat(A, B)` and `concat(A', B')` collide only when each pair matches
/// independently. The fingerprint is the raw concatenation — the cookie's
/// HMAC already binds it.
pub(crate) fn build_ch_fingerprint(
    cipher_suites_be: &[u8],
    supported_groups_ext: Option<&[u8]>,
    supported_versions_ext: Option<&[u8]>,
    key_share_groups_be: &[u8],
) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    fn push_field(out: &mut Vec<u8>, body: &[u8]) {
        let len = body.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(body);
    }
    let mut out = Vec::with_capacity(
        16 + cipher_suites_be.len()
            + supported_groups_ext.map(|b| b.len()).unwrap_or(0)
            + supported_versions_ext.map(|b| b.len()).unwrap_or(0)
            + key_share_groups_be.len(),
    );
    push_field(&mut out, cipher_suites_be);
    push_field(&mut out, supported_groups_ext.unwrap_or(&[]));
    push_field(&mut out, supported_versions_ext.unwrap_or(&[]));
    push_field(&mut out, key_share_groups_be);
    out
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

    const FP: &[u8] = b"fingerprint-bytes";

    #[test]
    fn generate_then_validate_succeeds() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"203.0.113.5:50000";
        let rand = fixed_random();
        let cookie = cg.generate(addr, &rand, FP, TS);
        assert!(cg.validate(addr, &rand, FP, TS, &cookie));
        // A minute later is still within the default window.
        assert!(cg.validate(addr, &rand, FP, TS + 1, &cookie));
    }

    #[test]
    fn expired_cookie_fails() {
        let cg = CookieGenerator::new(fixed_secret()).with_max_age_minutes(5);
        let addr = b"client";
        let rand = fixed_random();
        let cookie = cg.generate(addr, &rand, FP, TS);
        assert!(cg.validate(addr, &rand, FP, TS + 5, &cookie));
        // One minute past the window.
        assert!(!cg.validate(addr, &rand, FP, TS + 6, &cookie));
        // Far future also rejected.
        assert!(!cg.validate(addr, &rand, FP, TS + 1_000_000, &cookie));
    }

    #[test]
    fn future_cookie_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"client";
        let rand = fixed_random();
        let cookie = cg.generate(addr, &rand, FP, TS + 5);
        // Server clock 5 minutes behind the cookie's timestamp.
        assert!(!cg.validate(addr, &rand, FP, TS, &cookie));
    }

    #[test]
    fn wrong_address_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr_a = b"203.0.113.5:50000";
        let addr_b = b"203.0.113.5:50001";
        let rand = fixed_random();
        let cookie = cg.generate(addr_a, &rand, FP, TS);
        assert!(!cg.validate(addr_b, &rand, FP, TS, &cookie));
    }

    #[test]
    fn wrong_random_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"203.0.113.5:50000";
        let rand_a = fixed_random();
        let mut rand_b = rand_a;
        rand_b[0] ^= 1;
        let cookie = cg.generate(addr, &rand_a, FP, TS);
        assert!(!cg.validate(addr, &rand_b, FP, TS, &cookie));
    }

    #[test]
    fn wrong_fingerprint_fails() {
        // A CH2 whose security-critical extensions differ from CH1 must fail
        // cookie validation: this is what blocks the downgrade primitive
        // where an on-path attacker rewrites CH2's cipher_suites / groups.
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"203.0.113.5:50000";
        let rand = fixed_random();
        let fp_a = b"cipher=A,groups=X25519,versions=1.3";
        let fp_b = b"cipher=B,groups=X25519,versions=1.3"; // attacker-rewritten
        let cookie = cg.generate(addr, &rand, fp_a, TS);
        assert!(cg.validate(addr, &rand, fp_a, TS, &cookie));
        assert!(!cg.validate(addr, &rand, fp_b, TS, &cookie));
        // Empty fingerprint must also disagree with a real one.
        assert!(!cg.validate(addr, &rand, b"", TS, &cookie));
    }

    #[test]
    fn truncated_cookie_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"203.0.113.5:50000";
        let rand = fixed_random();
        let cookie = cg.generate(addr, &rand, FP, TS);
        assert!(!cg.validate(addr, &rand, FP, TS, &cookie[..COOKIE_LEN - 1]));
        assert!(!cg.validate(addr, &rand, FP, TS, &[]));
        let mut bad = cookie;
        bad[COOKIE_LEN - 1] ^= 1;
        assert!(!cg.validate(addr, &rand, FP, TS, &bad));
    }

    #[test]
    fn distinct_secrets_disagree() {
        let cg_a = CookieGenerator::new([0xaa; 32]);
        let cg_b = CookieGenerator::new([0xbb; 32]);
        let addr = b"client";
        let rand = fixed_random();
        let cookie_a = cg_a.generate(addr, &rand, FP, TS);
        assert!(!cg_b.validate(addr, &rand, FP, TS, &cookie_a));
    }

    #[test]
    fn aux_roundtrip() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"client";
        let rand = fixed_random();
        let aux = b"\x13\x01\x00\x1d\x04hash-of-ch1-32-bytes-........";
        let cookie = cg.generate_with_aux(addr, &rand, FP, aux, TS);
        let recovered = cg.validate_with_aux(addr, &rand, FP, TS, &cookie);
        assert_eq!(recovered.as_deref(), Some(aux.as_slice()));
        // The no-aux validator rejects an aux-bearing cookie.
        assert!(!cg.validate(addr, &rand, FP, TS, &cookie));
    }

    #[test]
    fn aux_tamper_fails() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"client";
        let rand = fixed_random();
        let aux = b"abcdef";
        let mut cookie = cg.generate_with_aux(addr, &rand, FP, aux, TS);
        // Flip a byte in the aux payload.
        cookie[6] ^= 1;
        assert!(cg.validate_with_aux(addr, &rand, FP, TS, &cookie).is_none());
    }

    #[test]
    fn aux_length_field_lie_rejected() {
        let cg = CookieGenerator::new(fixed_secret());
        let addr = b"client";
        let rand = fixed_random();
        let aux = b"abcdef";
        // Overstate the aux length so the framed cookie can no longer be
        // parsed.
        let mut cookie = cg.generate_with_aux(addr, &rand, FP, aux, TS);
        cookie[4] = 0xff;
        cookie[5] = 0xff;
        assert!(cg.validate_with_aux(addr, &rand, FP, TS, &cookie).is_none());
        // Lie with a plausible-but-wrong aux length: drops past the parse
        // check via the strict equality on `cookie.len()`.
        let mut cookie2 = cg.generate_with_aux(addr, &rand, FP, aux, TS);
        cookie2[4] = 0;
        cookie2[5] = (aux.len() as u8) + 1;
        assert!(
            cg.validate_with_aux(addr, &rand, FP, TS, &cookie2)
                .is_none()
        );
    }

    #[test]
    fn fingerprint_length_prefix_is_unambiguous() {
        // build_ch_fingerprint uses length-prefixed fields. Two distinct
        // (suites, groups, versions, key_shares) tuples must produce
        // distinct fingerprints even when their concatenation would
        // collide without the length prefix.
        let a = build_ch_fingerprint(b"AA", Some(b"BB"), Some(b""), b"");
        let b = build_ch_fingerprint(b"A", Some(b"ABB"), Some(b""), b"");
        assert_ne!(a, b);
        // And identical inputs reproduce.
        let c = build_ch_fingerprint(b"AA", Some(b"BB"), Some(b""), b"");
        assert_eq!(a, c);
    }
}
