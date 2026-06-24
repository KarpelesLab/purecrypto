//! RFC 9000 §10.3 stateless reset — token derivation and packet construction.
//!
//! A stateless reset lets an endpoint that has lost all state for a connection
//! tell its peer to give up, without holding any per-connection state. The
//! mechanism is a 16-byte `stateless_reset_token` that the endpoint advertised
//! (in its transport parameters for the handshake CID, and in every
//! `NEW_CONNECTION_ID` frame) *while* it had state. To recompute that exact
//! token later — when a datagram arrives for a connection ID it no longer
//! recognises — the endpoint derives every token it issues as a deterministic
//! function of a long-lived secret key and the connection ID (§10.3.1):
//!
//! ```text
//! stateless_reset_token(cid) = HMAC-SHA256(reset_key, cid)[..16]
//! ```
//!
//! The same `reset_key` is shared across every connection an endpoint hosts
//! (e.g. all connections under one [`crate::quic::QuicServer`]), so the router
//! can regenerate the token for any CID it ever issued.

use alloc::vec::Vec;

use crate::hash::{Hmac, Sha256};
use crate::quic::cid::ConnectionId;
use crate::rng::RngCore;

/// Minimum length of a stateless reset packet (RFC 9000 §10.3): at least
/// 5 bytes of unpredictable prefix plus the 16-byte token.
pub(crate) const MIN_STATELESS_RESET_LEN: usize = 21;

/// Derives the 16-byte stateless reset token for `cid` under `reset_key`
/// (RFC 9000 §10.3.1): the first 16 bytes of `HMAC-SHA256(reset_key, cid)`.
///
/// An attacker who can observe a token but does not know `reset_key` cannot
/// forge a reset for any *other* connection ID — HMAC is a PRF.
pub(crate) fn stateless_reset_token(reset_key: &[u8; 32], cid: &ConnectionId) -> [u8; 16] {
    let full = Hmac::<Sha256>::mac(reset_key, cid.as_slice());
    let mut token = [0u8; 16];
    token.copy_from_slice(&full.as_ref()[..16]);
    token
}

/// Builds a stateless reset packet (RFC 9000 §10.3): a short-header-shaped
/// datagram of `len` bytes whose final 16 bytes are `token` and whose prefix is
/// unpredictable random with the first two bits set to `01` so it is decoded as
/// a short header (Header Form = 0, Fixed Bit = 1).
///
/// `len` is clamped to at least [`MIN_STATELESS_RESET_LEN`]. Per §10.3 the
/// packet should resemble a 1-RTT packet of a plausible size; the caller picks
/// `len` to roughly match the triggering datagram while staying smaller than it
/// (so resets cannot be looped).
pub(crate) fn build_stateless_reset<R: RngCore>(
    rng: &mut R,
    token: &[u8; 16],
    len: usize,
) -> Vec<u8> {
    let len = len.max(MIN_STATELESS_RESET_LEN);
    let mut pkt = alloc::vec![0u8; len];
    rng.fill_bytes(&mut pkt);
    // Short header: Header Form bit (0x80) clear, Fixed Bit (0x40) set.
    pkt[0] = (pkt[0] & 0x3f) | 0x40;
    let split = len - 16;
    pkt[split..].copy_from_slice(token);
    pkt
}
