//! Per-epoch DTLS 1.3 read state and the `KeyUpdate` epoch bookkeeping
//! shared by the client and server engines (RFC 9147 §4.2.2, §8).
//!
//! DTLS 1.3 keys are scoped to an *epoch*: 0 is plaintext, 1 early data
//! (unused here), 2 the handshake keys, 3 the first application keys, and
//! every `KeyUpdate` a peer sends advances that peer's write epoch by one.
//! Unlike TLS 1.3, where a KeyUpdate takes effect on the very next record,
//! a datagram transport can reorder the KeyUpdate against the records
//! around it, so RFC 9147 §8 pins down both sides:
//!
//! - **Sender.** The KeyUpdate is sent under the *old* epoch and MUST be
//!   acknowledged; the sender MUST NOT send under the new epoch, nor send a
//!   further KeyUpdate, until the ACK arrives. Only one epoch transition is
//!   ever in progress per direction.
//! - **Receiver.** On the KeyUpdate it installs the next epoch's keys but
//!   keeps the previous epoch's for a while: reordered records and the
//!   peer's retransmissions of the KeyUpdate itself (when our ACK was lost)
//!   still arrive under the old epoch and must decrypt and be re-ACKed.
//!   RFC 9147 §4.2.2 bounds the live set to the current and previous
//!   epoch; the previous one is dropped after
//!   [`PREV_EPOCH_GRACE_RECORDS`] records have been received under the
//!   current epoch, or as soon as the next KeyUpdate arrives.
//!
//! The same retention covers the epoch 2 → 3 transition at the end of the
//! handshake: the peer's last handshake flight (or its retransmission when
//! our ACK was lost) is still protected under epoch 2 after we have moved
//! to epoch 3 (RFC 9147 §5.8.3), so keeping epoch 2 readable lets us re-ACK
//! it instead of leaving the peer to retransmit until it gives up.

use super::replay::AntiReplayWindow;
use crate::tls::crypto::{RecordCrypter, Secret, SuiteParams};

use super::client13::{derive_sn_key, sn_key_len_for};

/// Records received under the current read epoch before the previous
/// epoch's read keys are discarded. Sized to outlast the peer's full
/// retransmit backoff (RFC 9147 §5.8.1: 1 s doubling to 60 s, six attempts
/// ≈ 63 s) at a typical real-time media rate, so a lost final ACK is
/// recovered by a single re-ACK rather than by the peer giving up.
pub(crate) const PREV_EPOCH_GRACE_RECORDS: u32 = 4096;

/// Wall-clock lifetime of a retired read epoch, as a backstop for
/// [`PREV_EPOCH_GRACE_RECORDS`] on a connection that carries too little
/// traffic to reach the record count. Twice the maximum retransmit timeout
/// (RFC 9147 §5.8.1 caps the backoff at 60 s), after which no record the
/// peer may still be retransmitting can plausibly be in flight — and the
/// old epoch's keys have no reason to stay in memory.
///
/// The expiry runs off the caller-driven sans-I/O clock (`on_timeout` /
/// `set_now`) and on authenticated records, so it only fires for callers
/// that drive the clock; the record-count bound still covers the rest.
pub(crate) const PREV_EPOCH_GRACE_TIME: core::time::Duration = core::time::Duration::from_secs(120);

/// Upper bound on the number of `KeyUpdate` messages accepted from the
/// peer within [`KEY_UPDATE_WINDOW`]. Mirrors the TLS 1.3 engines'
/// `MAX_KEY_UPDATES_RECEIVED`: each update costs a key derivation and two
/// AEAD schedules, so an unbounded stream of them is a cheap way for an
/// authenticated peer to burn CPU; nothing legitimate updates more often
/// than the per-epoch record cap forces it to. It is a rate limit rather
/// than a lifetime cap so that a long-lived, well-behaved connection is
/// never torn down for rekeying often enough.
pub(crate) const MAX_KEY_UPDATES_RECEIVED: u32 = 64;

/// Window over which [`MAX_KEY_UPDATES_RECEIVED`] is counted. Measured on
/// the caller-driven clock; a caller that never advances it keeps the old
/// behaviour of a per-connection cap (fail-closed, never fail-open).
pub(crate) const KEY_UPDATE_WINDOW: core::time::Duration = core::time::Duration::from_secs(60);

/// Read-side record protection state for one epoch: the AEAD, the
/// sequence-number encryption key (RFC 9147 §4.2.3), the highest sequence
/// number seen (for 16-bit → 48-bit reconstruction, §4.2.2) and the
/// anti-replay window (§4.5.1). Every field is per-epoch: sequence numbers
/// restart at zero and the replay window resets at each epoch change.
pub(crate) struct ReadEpoch {
    pub(crate) epoch: u16,
    pub(crate) crypter: RecordCrypter,
    pub(crate) sn_key: Secret,
    /// Highest sequence number successfully authenticated in this epoch.
    pub(crate) seq: u64,
    pub(crate) replay: AntiReplayWindow,
}

impl ReadEpoch {
    /// Derives the epoch's read keys from the peer's traffic `secret`.
    pub(crate) fn new(suite: SuiteParams, epoch: u16, secret: &Secret) -> Self {
        let sn_len = sn_key_len_for(suite.aead);
        Self {
            epoch,
            crypter: RecordCrypter::new(suite.hash, suite.aead, suite.key_len, secret),
            sn_key: derive_sn_key(suite.hash, secret, sn_len),
            seq: 0,
            replay: AntiReplayWindow::new(),
        }
    }

    /// True when the unified header's low two epoch bits name this epoch.
    pub(crate) fn matches_low2(&self, epoch_low2: u8) -> bool {
        (self.epoch as u8) & 0b11 == epoch_low2
    }
}

/// Selects which read epoch a protected record belongs to from the two
/// epoch bits in its unified header: the current epoch first, then the
/// retained previous one (RFC 9147 §4.2.2). `None` means the record is
/// from an epoch we cannot (or no longer) read and must be dropped.
pub(crate) fn select_read_epoch<'a>(
    current: &'a mut Option<ReadEpoch>,
    previous: &'a mut Option<ReadEpoch>,
    epoch_low2: u8,
) -> Option<(&'a mut ReadEpoch, bool)> {
    if let Some(cur) = current.as_mut()
        && cur.matches_low2(epoch_low2)
    {
        return Some((cur, false));
    }
    if let Some(prev) = previous.as_mut()
        && prev.matches_low2(epoch_low2)
    {
        return Some((prev, true));
    }
    None
}
