//! ECH acceptance signal (draft-ietf-tls-esni-22 §7).
//!
//! The server tells the client whether ECH was accepted (the inner
//! CH won) or rejected (the outer CH won) by writing 8 bytes into
//! `ServerHello.random[24..32]` (or into `HelloRetryRequest.random[24..32]`
//! in the HRR case). The 8 bytes are computed deterministically
//! from the handshake transcript.
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

use crate::tls::crypto::{HashAlg, derive_secret, expand_label_dyn};
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

/// `accept_confirmation` for `HelloRetryRequest` (draft §7.2.1). Same
/// shape, different label so the two confirmations can't be confused.
///
/// The HRR's last 8 random bytes are zeroed before hashing as for SH.
pub fn hello_retry_request_signal(
    alg: HashAlg,
    handshake_secret: &[u8],
    transcript_hash: &[u8],
) -> [u8; 8] {
    let secret = derive_secret(
        alg,
        handshake_secret,
        b"hrr ech accept confirmation",
        transcript_hash,
    );
    let mut out = [0u8; 8];
    expand_label_dyn(
        alg,
        secret.as_slice(),
        b"hrr ech accept confirmation",
        b"",
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
