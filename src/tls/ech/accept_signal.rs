//! ECH acceptance signal (draft-ietf-tls-esni-22 §7).
//!
//! The server tells the client whether ECH was accepted (the inner
//! CH won) or rejected (the outer CH won) by writing 8 bytes into
//! `ServerHello.random[24..32]` (§7.2). On a `HelloRetryRequest`,
//! whose `random` is fixed by RFC 8446 to `SHA-256("HelloRetryRequest")`
//! and so cannot carry per-handshake data, the 8 bytes ride in an
//! `encrypted_client_hello` extension on the HRR itself (§7.2.1).
//! Both signals are computed deterministically from the handshake
//! transcript and the inner CH's random — the client computes the
//! same value locally and compares constant-time.
//!
//! Concretely, draft §7.2 specifies:
//!
//! ```text
//! accept_confirmation =
//!     HKDF-Expand-Label(
//!         Derive-Secret(handshake_secret, "ech accept confirmation",
//!                       transcript_hash(ClientHelloInner..ServerHelloEchAcceptConfirmation)),
//!         "ech accept confirmation",
//!         "",
//!         8)
//! ```
//!
//! where `ServerHelloEchAcceptConfirmation` is the in-progress SH with
//! its last 8 random bytes zeroed.
//!
//! In our codebase the equivalent is computed below by piggy-backing
//! on the existing `derive_secret` / `expand_label_dyn` helpers.

use crate::tls::crypto::{HashAlg, derive_secret, expand_label_dyn, extract};
use alloc::vec::Vec;

/// `accept_confirmation` for `ServerHello` (the 8 bytes patched into
/// `sh.random[24..32]`). `handshake_secret` is the TLS-1.3 handshake
/// secret on the **inner** transcript; `transcript_hash` is the hash
/// of `(inner CH || zero-tail SH)` taken over the chosen `alg`.
///
/// The caller is responsible for zeroing the last 8 bytes of the SH's
/// random field before hashing — that's the "zero placeholder" form
/// the draft prescribes.
pub fn server_hello_signal(
    alg: HashAlg,
    handshake_secret: &[u8],
    transcript_hash: &[u8],
) -> [u8; 8] {
    let secret = derive_secret(
        alg,
        handshake_secret,
        b"ech accept confirmation",
        transcript_hash,
    );
    let mut out = [0u8; 8];
    expand_label_dyn(
        alg,
        secret.as_slice(),
        b"ech accept confirmation",
        b"",
        &mut out,
    );
    out
}

/// `hrr_accept_confirmation` for `HelloRetryRequest` (draft §7.2.1).
///
/// Per the spec the input keying material is **not** the handshake
/// secret (no ECDHE has been derived yet at HRR time). Instead it is
/// `HKDF-Extract(0, ClientHelloInner1.random)`, fed into a single
/// `HKDF-Expand-Label(_, "hrr ech accept confirmation",
/// transcript_hrr_ech_conf, 8)`. The transcript hash covers
/// `ClientHelloInner1 || HelloRetryRequest` where the HRR's
/// `encrypted_client_hello` extension payload is the 8 zero bytes the
/// caller emits as a placeholder before patching the real signal in.
///
/// Unlike the SH signal the HRR signal is **not** patched into
/// `HelloRetryRequest.random[24..32]` (whose value is fixed by RFC 8446
/// to `SHA-256("HelloRetryRequest")`); it travels in an
/// `encrypted_client_hello` extension within the HRR itself.
pub fn hello_retry_request_signal(
    alg: HashAlg,
    inner_ch1_random: &[u8; 32],
    transcript_hash: &[u8],
) -> [u8; 8] {
    // HKDF-Extract(0, ClientHelloInner1.random). The salt is a string
    // of `Hash.length` zero bytes per the spec's "0" notation; 64 is
    // the maximum hash output length across the suites we support
    // (SHA-256, SHA-384).
    let zeros = [0u8; 64];
    let salt = &zeros[..alg.output_len()];
    let prk = extract(alg, salt, inner_ch1_random);
    let mut out = [0u8; 8];
    expand_label_dyn(
        alg,
        prk.as_slice(),
        b"hrr ech accept confirmation",
        transcript_hash,
        &mut out,
    );
    out
}

/// Constant-time equality check on the 8-byte accept signal —
/// avoids a sequence-of-bytes timing side channel against an
/// adversary that can repeatedly stuff CHs.
pub fn signals_eq_ct(a: &[u8; 8], b: &[u8; 8]) -> bool {
    let mut acc = 0u8;
    for i in 0..8 {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// Helper: rebuild a wire `ServerHello.random` with the last 8 bytes
/// replaced with `signal`. Used by both the server (to patch the SH
/// it emits) and the client (to recompute what the SH *would* look
/// like if ECH had been accepted, before comparing to what arrived).
pub fn patch_random_tail(random: &[u8; 32], signal: &[u8; 8]) -> [u8; 32] {
    let mut out = *random;
    out[24..32].copy_from_slice(signal);
    out
}

/// Helper: extract the last 8 bytes of a 32-byte random.
pub fn random_tail(random: &[u8; 32]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&random[24..32]);
    out
}

/// Helper: zero the last 8 bytes of a 32-byte random in-place, returning
/// the modified copy. Used to build the "zero-placeholder" SH the draft
/// hashes for the accept-confirmation computation.
pub fn random_with_zero_tail(random: &[u8; 32]) -> [u8; 32] {
    let mut out = *random;
    for b in &mut out[24..32] {
        *b = 0;
    }
    out
}

/// Re-export — for callers that want to inspect the per-CH bytes used
/// to seed [`patch_random_tail`].
#[allow(dead_code)]
pub(crate) fn signal_to_vec(signal: &[u8; 8]) -> Vec<u8> {
    signal.to_vec()
}

/// Returns the absolute offset of the `encrypted_client_hello`
/// extension's 8-byte payload within a HelloRetryRequest (a
/// ServerHello-shaped handshake message), or `None` if the message is
/// malformed or has no such extension. Used by both the server (to
/// patch the signal into a freshly emitted HRR) and the client (to
/// zero the payload before recomputing the expected signal).
///
/// The body layout matches RFC 8446 §4.1.3 ServerHello: u8 type,
/// u24 length, version(2), random(32), session_id(u8), cipher_suite(2),
/// compression_method(1), extensions(u16 length-prefixed).
pub(crate) fn locate_hrr_ech_signal_payload(handshake_msg: &[u8]) -> Option<usize> {
    use crate::tls::codec::{ExtensionType, hs_type};
    if handshake_msg.len() < 4 || handshake_msg[0] != hs_type::SERVER_HELLO {
        return None;
    }
    let body_len = ((handshake_msg[1] as usize) << 16)
        | ((handshake_msg[2] as usize) << 8)
        | (handshake_msg[3] as usize);
    if 4 + body_len != handshake_msg.len() {
        return None;
    }
    let body = &handshake_msg[4..];
    if body.len() < 2 + 32 + 1 {
        return None;
    }
    let mut idx = 2 + 32;
    let sid_len = body[idx] as usize;
    idx += 1;
    if idx + sid_len + 2 + 1 + 2 > body.len() {
        return None;
    }
    idx += sid_len + 2 + 1; // session_id + cipher_suite + compression
    let ext_total = ((body[idx] as usize) << 8) | (body[idx + 1] as usize);
    idx += 2;
    if idx + ext_total > body.len() {
        return None;
    }
    let ext_start_in_body = idx;
    let ext_end_in_body = idx + ext_total;
    let mut p = ext_start_in_body;
    while p + 4 <= ext_end_in_body {
        let ty = ((body[p] as u16) << 8) | (body[p + 1] as u16);
        let bl = ((body[p + 2] as usize) << 8) | (body[p + 3] as usize);
        let body_start = p + 4;
        let body_end = body_start + bl;
        if body_end > ext_end_in_body {
            return None;
        }
        if ty == ExtensionType::ENCRYPTED_CLIENT_HELLO.0 && bl == 8 {
            return Some(4 + body_start);
        }
        p = body_end;
    }
    None
}
