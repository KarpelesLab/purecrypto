//! Connection-ID newtype + minimal local/remote tracking.
//!
//! Per RFC 9000 §5.1 a Connection ID is an opaque byte string of length
//! 0..=20. In QUIC v1 each endpoint picks the CIDs the *peer* uses to
//! address it: the server picks the CID that appears as DCID on every
//! client→server packet after the first flight, and the client picks the
//! CID that appears as DCID on every server→client packet (RFC 9000 §7.2).
//!
//! Phase 4 only needs:
//! * `ConnectionId` — fixed-capacity inline byte string (1..=20 bytes).
//! * `CidPair` — the two CIDs that pin one connection during the handshake:
//!   the peer's chosen CID (what we write into DCID on outbound packets)
//!   and our chosen CID (what we expect in DCID on inbound packets, what
//!   the peer wrote into SCID on its first long-header packet).
//!
//! Full multi-CID management — NEW_CONNECTION_ID, RETIRE_CONNECTION_ID,
//! sequence numbers, stateless reset tokens — lands in Phase 7.

#![allow(dead_code)]

use alloc::collections::BTreeMap;

use crate::rng::RngCore;
use crate::tls::Error;

/// Maximum QUIC v1 connection-ID length, RFC 9000 §17.2.
const MAX_CID_LEN: usize = 20;

/// Hard upper bound on the number of sequences queued in
/// [`CidPool::pending_retire`] at once, expressed as a slack added on top
/// of the active-CID `limit`. A well-behaved peer never owes us more
/// outstanding RETIRE_CONNECTION_ID frames than the CIDs it has issued,
/// which is itself bounded by `limit`; the slack absorbs the brief window
/// between queueing a RETIRE and the caller draining it. A malicious peer
/// that floods NEW_CONNECTION_ID frames with large `retire_prior_to` and
/// distinct sequences is capped here, turning the would-be unbounded
/// growth into a connection error instead of memory exhaustion
/// (RFC 9000 §5.1.1 / §19.15). Kept small and constant so the bound is
/// independent of how large a `limit` the peer advertises.
const PENDING_RETIRE_SLACK: u64 = 8;

/// QUIC connection ID — opaque byte string of length 0..=20.
///
/// Stored inline (no heap allocation) to keep `QuicConnection` `Send`
/// without pulling in `Arc`. Cheap to copy and hash.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ConnectionId {
    /// Raw bytes; only the first `len` are meaningful.
    bytes: [u8; MAX_CID_LEN],
    /// Number of valid bytes in `bytes` (0..=20).
    len: u8,
}

impl ConnectionId {
    /// Constructs a CID from a slice. Returns `None` if `bytes.len() > 20`.
    pub(crate) fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_CID_LEN {
            return None;
        }
        let mut storage = [0u8; MAX_CID_LEN];
        storage[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            bytes: storage,
            len: bytes.len() as u8,
        })
    }

    /// The empty CID (0 bytes). RFC 9000 allows endpoints to use a
    /// zero-length CID as long as routing on (src, dst) still uniquely
    /// identifies a connection.
    pub(crate) const fn empty() -> Self {
        Self {
            bytes: [0; MAX_CID_LEN],
            len: 0,
        }
    }

    /// Generates a fresh CID of exactly `len` random bytes. `len` must be
    /// in 1..=20.
    ///
    /// Phase 4 always picks `len = 8` — enough entropy for a loopback
    /// test, short enough to keep Initial headers small. Phase 7 will
    /// expose a longer-CID server option.
    pub(crate) fn random<R: RngCore>(rng: &mut R, len: usize) -> Self {
        debug_assert!((1..=MAX_CID_LEN).contains(&len));
        let mut storage = [0u8; MAX_CID_LEN];
        rng.fill_bytes(&mut storage[..len]);
        Self {
            bytes: storage,
            len: len as u8,
        }
    }

    /// Borrowed bytes view.
    #[inline]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Number of bytes (0..=20).
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len as usize
    }

    /// True iff the CID is the zero-length CID.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ConnectionId(")?;
        for b in self.as_slice() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// The two CIDs that pin a connection during the handshake.
///
/// * `peer` — the CID we write into DCID on outbound packets. For a client
///   this is initially the random 8-byte value the client chose (which
///   keys the Initial secrets per RFC 9001 §5.2); the server replaces it
///   with its own chosen SCID on receipt of the first server flight. For
///   a server it is the SCID the client wrote on its first Initial.
/// * `local` — the CID we expect in DCID on inbound packets. The peer
///   reads this from a SCID we sent earlier (in the long-header SCID
///   slot for handshake-level packets).
#[derive(Clone, Debug)]
pub(crate) struct CidPair {
    pub peer: ConnectionId,
    pub local: ConnectionId,
}

impl CidPair {
    pub(crate) fn new(peer: ConnectionId, local: ConnectionId) -> Self {
        Self { peer, local }
    }
}

// =========================================================================
// Phase 7 — CidPool: NEW_CONNECTION_ID / RETIRE_CONNECTION_ID housekeeping
// =========================================================================

/// One CID in a [`CidPool`]: the connection-ID bytes, its sequence number
/// (RFC 9000 §5.1.1), and the stateless-reset token bound to it (16 bytes
/// per RFC 9000 §10.3). Phase 7 *stores* the reset token but does not
/// yet act on it — stateless reset emission lands in Phase 8.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CidEntry {
    /// The actual connection-ID bytes (≤ 20 in QUIC v1).
    pub(crate) cid: ConnectionId,
    /// Sequence number assigned by the issuing endpoint (RFC 9000 §5.1.1).
    /// Sequence 0 is the CID established during the handshake; subsequent
    /// CIDs come via NEW_CONNECTION_ID frames.
    pub(crate) sequence: u64,
    /// Stateless-reset token: 16 bytes (RFC 9000 §10.3). `None` for CIDs
    /// where no token was supplied (e.g. a zero-length CID, or a
    /// pre-handshake placeholder).
    pub(crate) reset_token: Option<[u8; 16]>,
}

/// A bounded pool of connection-IDs in one direction. The local pool
/// tracks CIDs *we* issued for the peer to use as DCIDs on inbound
/// packets; the remote pool tracks CIDs the peer issued for *us* to use
/// as DCIDs on outbound packets.
///
/// RFC 9000 §5.1.1: an endpoint MUST limit the number of unretired CIDs
/// it accepts from a peer to `active_connection_id_limit` (default 2,
/// minimum 2). Phase 7 enforces this on insertion.
///
/// RFC 9000 §5.1.2: when the peer's `retire_prior_to` advances, all
/// sequences strictly below it are retired automatically; the retiring
/// side emits a RETIRE_CONNECTION_ID frame per dropped sequence.
pub(crate) struct CidPool {
    /// All CIDs in this pool, keyed by sequence. Always non-empty after
    /// construction (the handshake CID is at sequence 0).
    pub(crate) entries: BTreeMap<u64, CidEntry>,
    /// Sequence of the CID currently in use. Phase 7 keeps this fixed at
    /// 0 (CID migration is a Phase 8+ concern); future phases will
    /// advance it when migrating to a new CID.
    pub(crate) active_seq: u64,
    /// The largest `retire_prior_to` value the peer has signalled. Any
    /// stored entry with `sequence < retire_prior_to` should be removed
    /// from this pool and a RETIRE_CONNECTION_ID emitted (per §5.1.2).
    pub(crate) retire_prior_to: u64,
    /// Bound from the peer's `active_connection_id_limit` transport
    /// parameter. We refuse to store more than `limit` non-retired entries
    /// per §5.1.1.
    pub(crate) limit: u64,
    /// Sequences this side has been asked to RETIRE but hasn't yet
    /// emitted a RETIRE_CONNECTION_ID frame for. (Remote pool only:
    /// when the peer tells us `retire_prior_to = N`, we owe the peer
    /// a RETIRE_CONNECTION_ID for every sequence we previously stored
    /// below N.)
    pub(crate) pending_retire: alloc::vec::Vec<u64>,
}

impl CidPool {
    /// Constructs a pool seeded with a single entry at sequence 0 — the
    /// handshake CID. The `active_connection_id_limit` defaults to 2
    /// (RFC 9000 §18.2 default); the caller updates `limit` once it
    /// learns the peer's actual value.
    pub(crate) fn new(initial: ConnectionId, initial_reset_token: Option<[u8; 16]>) -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(
            0,
            CidEntry {
                cid: initial,
                sequence: 0,
                reset_token: initial_reset_token,
            },
        );
        Self {
            entries,
            active_seq: 0,
            retire_prior_to: 0,
            limit: 2,
            pending_retire: alloc::vec::Vec::new(),
        }
    }

    /// Sets the peer-advertised `active_connection_id_limit` (RFC 9000
    /// §18.2). Per §5.1.1, the value MUST be at least 2; we clamp here
    /// for robustness rather than rejecting the peer outright.
    pub(crate) fn set_limit(&mut self, limit: u64) {
        self.limit = limit.max(2);
    }

    /// Maximum number of sequences we will hold in `pending_retire`
    /// before treating further growth as a connection error. Derived from
    /// the active-CID `limit` plus a small constant slack so legitimate
    /// peers (which never owe more than `limit` outstanding RETIREs) are
    /// unaffected, while a flood is bounded (RFC 9000 §5.1.1).
    pub(crate) fn pending_retire_cap(&self) -> usize {
        self.limit.saturating_add(PENDING_RETIRE_SLACK) as usize
    }

    /// Queues `sequence` for a RETIRE_CONNECTION_ID emission, deduping
    /// against already-queued sequences and enforcing the
    /// `pending_retire` cap. Returns [`Error::IllegalParameter`] when the
    /// cap would be exceeded, so the connection closes rather than letting
    /// a peer grow `pending_retire` without bound (F2).
    fn queue_pending_retire(&mut self, sequence: u64) -> Result<(), Error> {
        if self.pending_retire.contains(&sequence) {
            // Already owed; dedup so a peer can't inflate the queue by
            // re-announcing the same retired sequence.
            return Ok(());
        }
        if self.pending_retire.len() >= self.pending_retire_cap() {
            return Err(Error::IllegalParameter);
        }
        self.pending_retire.push(sequence);
        Ok(())
    }

    /// Inserts `entry`. Returns [`Error::IllegalParameter`] if the
    /// sequence already exists with different content (RFC 9000 §19.15:
    /// "the same sequence number MAY appear in multiple frames, but the
    /// content MUST be identical"). Returns [`Error::IllegalParameter`]
    /// if accepting this entry would exceed `limit` non-retired entries.
    pub(crate) fn add(&mut self, entry: CidEntry) -> Result<(), Error> {
        if let Some(existing) = self.entries.get(&entry.sequence) {
            if existing != &entry {
                return Err(Error::IllegalParameter);
            }
            return Ok(());
        }
        if entry.sequence < self.retire_prior_to {
            // RFC 9000 §5.1.2: a newly-received CID with sequence below
            // the retire_prior_to we already announced is immediately
            // retired. We emit the RETIRE for it but don't keep it.
            // `queue_pending_retire` dedups and caps growth so a peer
            // cannot flood distinct low sequences to exhaust memory (F2).
            return self.queue_pending_retire(entry.sequence);
        }
        let live = self
            .entries
            .iter()
            .filter(|(seq, _)| **seq >= self.retire_prior_to)
            .count() as u64;
        if live >= self.limit {
            // Exceeded active_connection_id_limit.
            return Err(Error::IllegalParameter);
        }
        self.entries.insert(entry.sequence, entry);
        Ok(())
    }

    /// Retires the CID at `sequence`. Returns the removed entry, or
    /// `Ok(None)` if no such sequence was present. Returns
    /// [`Error::IllegalParameter`] if the caller is trying to retire the
    /// CID that is currently in use (RFC 9000 §19.16: "Receipt of a
    /// RETIRE_CONNECTION_ID frame that retires the same connection ID
    /// the endpoint used to send the frame ... MUST be treated as a
    /// connection error"). Phase 7 conservatively checks this whether
    /// this side or the peer is retiring.
    pub(crate) fn retire(&mut self, sequence: u64) -> Result<Option<CidEntry>, Error> {
        if sequence == self.active_seq && self.entries.contains_key(&sequence) {
            // Phase 7 doesn't migrate; if asked to retire the active CID
            // we treat it as a protocol violation.
            return Err(Error::IllegalParameter);
        }
        Ok(self.entries.remove(&sequence))
    }

    /// Records a peer-advertised `retire_prior_to` value (from a
    /// NEW_CONNECTION_ID frame, RFC 9000 §19.15). All entries with
    /// `sequence < new` are removed; their sequences are added to
    /// `pending_retire` so the caller can emit RETIRE_CONNECTION_ID
    /// frames in the next outbound packet.
    ///
    /// L-2: if the currently-active CID (`active_seq`) is among the
    /// sequences being retired, the active sequence is first rotated to
    /// the lowest surviving entry whose sequence is `>= new` (a CID the
    /// peer wants us to keep using). If *no* such replacement exists yet
    /// — the peer advanced `retire_prior_to` past every CID it has so far
    /// issued — the active entry is RETAINED (not removed) so the
    /// connection keeps a usable outbound DCID until a replacement
    /// NEW_CONNECTION_ID arrives. This is RFC 9000 §5.1.2-consistent:
    /// retire_prior_to obligates us to retire old CIDs, but a peer that
    /// leaves us with no usable CID would be breaking the connection on
    /// itself; we degrade gracefully rather than discard our only DCID.
    ///
    /// Returns [`Error::IllegalParameter`] if queueing the dropped
    /// sequences would exceed the `pending_retire` cap — only reachable
    /// when a peer drives growth far beyond the active-CID `limit`, which
    /// is itself a protocol violation (F2 / RFC 9000 §5.1.1). Sequences
    /// are deduped against what is already queued.
    pub(crate) fn note_retire_prior_to(&mut self, new: u64) -> Result<(), Error> {
        if new <= self.retire_prior_to {
            return Ok(());
        }
        self.retire_prior_to = new;

        // Determine whether the active CID is being retired, and if so,
        // find a surviving replacement (lowest sequence >= new). The
        // entries map is sorted, so the first key >= new is the
        // replacement candidate.
        let active_retired = self.active_seq < new;
        let replacement = self.entries.range(new..).next().map(|(s, _)| *s);
        let keep_active = if active_retired {
            match replacement {
                Some(repl) => {
                    // Rotate to the surviving CID before removing the old
                    // active one.
                    self.active_seq = repl;
                    None
                }
                // No replacement available yet: keep the active entry so
                // we still have a usable outbound DCID. It will be
                // retired by a later note_retire_prior_to once the peer
                // supplies a higher-sequence CID.
                None => Some(self.active_seq),
            }
        } else {
            None
        };

        let dropped: alloc::vec::Vec<u64> = self
            .entries
            .keys()
            .copied()
            .filter(|s| *s < new && Some(*s) != keep_active)
            .collect();
        for s in dropped {
            self.entries.remove(&s);
            self.queue_pending_retire(s)?;
        }
        Ok(())
    }

    /// Currently-active CID entry (the one whose CID we write into the
    /// DCID of every outbound packet, for the remote pool; the one we
    /// expect in DCID on inbound packets, for the local pool). `None`
    /// only in pathological cases — the active entry should always be
    /// present.
    pub(crate) fn active(&self) -> Option<&CidEntry> {
        self.entries.get(&self.active_seq)
    }

    /// How many more fresh CIDs we should issue to the peer so the peer
    /// has `limit` unretired CIDs available. Returns 0 if we already
    /// have at least `limit` live entries.
    pub(crate) fn how_many_to_issue(&self) -> u64 {
        let live = self
            .entries
            .iter()
            .filter(|(seq, _)| **seq >= self.retire_prior_to)
            .count() as u64;
        self.limit.saturating_sub(live)
    }

    /// Pops the next pending RETIRE_CONNECTION_ID sequence to emit, or
    /// `None` if none are queued.
    pub(crate) fn pop_pending_retire(&mut self) -> Option<u64> {
        if self.pending_retire.is_empty() {
            None
        } else {
            Some(self.pending_retire.remove(0))
        }
    }

    /// Highest sequence number currently stored. Used by the issuing
    /// side to pick the next sequence number for a NEW_CONNECTION_ID
    /// emission.
    pub(crate) fn max_sequence(&self) -> u64 {
        self.entries.keys().next_back().copied().unwrap_or(0)
    }

    /// Installs / replaces the `reset_token` on the entry at the given
    /// sequence. Returns `true` if an entry was found and updated.
    ///
    /// G-3: the peer's `stateless_reset_token` transport parameter is
    /// bound to the *handshake* CID (sequence 0), which is constructed
    /// at pool-seed time with `initial_reset_token = None` because the
    /// token only arrives later in the TLS handshake's transport params.
    /// Without this hook, [`super::connection::QuicConnection::detect_stateless_reset`]
    /// would never recognize a stateless reset targeted at the
    /// handshake CID.
    pub(crate) fn set_token(&mut self, sequence: u64, token: [u8; 16]) -> bool {
        if let Some(e) = self.entries.get_mut(&sequence) {
            e.reset_token = Some(token);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    #[test]
    fn from_slice_caps_at_20() {
        assert!(ConnectionId::from_slice(&[0u8; 21]).is_none());
        let cid = ConnectionId::from_slice(&[1, 2, 3, 4]).unwrap();
        assert_eq!(cid.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(cid.len(), 4);
        assert!(!cid.is_empty());
    }

    #[test]
    fn empty_is_empty() {
        let e = ConnectionId::empty();
        assert!(e.is_empty());
        assert_eq!(e.len(), 0);
        assert_eq!(e.as_slice(), &[] as &[u8]);
    }

    #[test]
    fn random_has_right_length() {
        let mut rng = HmacDrbg::<Sha256>::new(b"cid-test", b"nonce", &[]);
        let cid = ConnectionId::random(&mut rng, 8);
        assert_eq!(cid.len(), 8);
        // Random 8 bytes are overwhelmingly unlikely to be all zero.
        assert_ne!(cid.as_slice(), &[0u8; 8]);
    }

    #[test]
    fn debug_is_hex() {
        let cid = ConnectionId::from_slice(&[0x83, 0x94]).unwrap();
        let s = alloc::format!("{cid:?}");
        assert!(s.contains("8394"));
    }

    // ============================================================
    // Phase 7 — CidPool tests
    // ============================================================

    fn cid_n(n: u8) -> ConnectionId {
        ConnectionId::from_slice(&[n; 8]).expect("8-byte cid")
    }

    #[test]
    fn cidpool_seeded_with_handshake_entry() {
        let pool = CidPool::new(cid_n(0), Some([0u8; 16]));
        assert_eq!(pool.active_seq, 0);
        assert!(pool.active().is_some());
        assert_eq!(pool.active().unwrap().cid, cid_n(0));
        assert_eq!(pool.limit, 2);
        // Default limit is 2 active CIDs; we already have 1 → can issue 1 more.
        assert_eq!(pool.how_many_to_issue(), 1);
    }

    #[test]
    fn cidpool_add_respects_limit() {
        let mut pool = CidPool::new(cid_n(0), None);
        pool.set_limit(2);
        let e1 = CidEntry {
            cid: cid_n(1),
            sequence: 1,
            reset_token: Some([1u8; 16]),
        };
        assert!(pool.add(e1).is_ok());
        // Now 2 live entries → can't add another while limit = 2.
        let e2 = CidEntry {
            cid: cid_n(2),
            sequence: 2,
            reset_token: Some([2u8; 16]),
        };
        assert!(matches!(pool.add(e2), Err(Error::IllegalParameter)));
        // Lift the limit; add now succeeds.
        pool.set_limit(3);
        let e2 = CidEntry {
            cid: cid_n(2),
            sequence: 2,
            reset_token: Some([2u8; 16]),
        };
        assert!(pool.add(e2).is_ok());
        assert_eq!(pool.max_sequence(), 2);
    }

    #[test]
    fn cidpool_add_rejects_inconsistent_duplicate() {
        let mut pool = CidPool::new(cid_n(0), None);
        let e1 = CidEntry {
            cid: cid_n(1),
            sequence: 1,
            reset_token: Some([7u8; 16]),
        };
        assert!(pool.add(e1.clone()).is_ok());
        // Identical re-add: fine.
        assert!(pool.add(e1.clone()).is_ok());
        // Mismatched re-add: error per RFC 9000 §19.15.
        let e1_bad = CidEntry {
            cid: cid_n(0xff),
            sequence: 1,
            reset_token: Some([7u8; 16]),
        };
        assert!(matches!(pool.add(e1_bad), Err(Error::IllegalParameter)));
    }

    #[test]
    fn cidpool_retire_prior_to_pulls_retires_and_queues() {
        let mut pool = CidPool::new(cid_n(0), None);
        pool.set_limit(4);
        for s in 1..=3 {
            pool.add(CidEntry {
                cid: cid_n(s as u8),
                sequence: s,
                reset_token: Some([s as u8; 16]),
            })
            .unwrap();
        }
        // Now there are 4 entries (sequences 0..=3). Move active to 2 so
        // retire of 0/1 doesn't trip the "active retired" check.
        pool.active_seq = 2;
        // The peer says "retire prior to 2" → 0 and 1 drop.
        pool.note_retire_prior_to(2).expect("retire ok");
        assert_eq!(pool.retire_prior_to, 2);
        assert!(!pool.entries.contains_key(&0));
        assert!(!pool.entries.contains_key(&1));
        // Pending-retire frames are queued for 0 and 1.
        let mut got = alloc::vec::Vec::new();
        while let Some(s) = pool.pop_pending_retire() {
            got.push(s);
        }
        got.sort();
        assert_eq!(got, alloc::vec![0u64, 1]);
    }

    #[test]
    fn cidpool_retire_active_is_protocol_error() {
        let mut pool = CidPool::new(cid_n(0), None);
        assert!(matches!(pool.retire(0), Err(Error::IllegalParameter)));
    }

    // L-2: retire_prior_to that covers the active CID must rotate the
    // active sequence to a surviving higher-sequence CID, never leaving
    // `active()` pointing at a removed entry.
    #[test]
    fn cidpool_retire_prior_to_rotates_active() {
        let mut pool = CidPool::new(cid_n(0), None);
        pool.set_limit(4);
        for s in 1..=3 {
            pool.add(CidEntry {
                cid: cid_n(s as u8),
                sequence: s,
                reset_token: Some([s as u8; 16]),
            })
            .unwrap();
        }
        // active is still the handshake CID (seq 0).
        assert_eq!(pool.active_seq, 0);
        // Peer retires everything below 2 — the active CID (0) goes too.
        pool.note_retire_prior_to(2).expect("retire ok");
        // Active must have rotated to the lowest survivor (seq 2), and
        // its entry must still be present.
        assert_eq!(pool.active_seq, 2, "active rotated to surviving CID");
        let active = pool.active().expect("active entry present");
        assert_eq!(active.sequence, 2);
        assert_eq!(active.cid, cid_n(2));
        // The retired sequences (0, 1) are gone and queued.
        assert!(!pool.entries.contains_key(&0));
        assert!(!pool.entries.contains_key(&1));
    }

    // L-2: if retire_prior_to advances past every CID the peer has so far
    // issued, the active entry is RETAINED (not removed) so a usable
    // outbound DCID survives until a replacement arrives.
    #[test]
    fn cidpool_retire_prior_to_keeps_active_when_no_replacement() {
        let mut pool = CidPool::new(cid_n(0), None);
        pool.set_limit(4);
        // Only the handshake CID (seq 0) exists. Peer retires prior to 5.
        pool.note_retire_prior_to(5).expect("retire ok");
        // No survivor >= 5, so the active CID (seq 0) is kept.
        assert_eq!(pool.active_seq, 0, "active unchanged with no replacement");
        let active = pool.active().expect("active entry retained");
        assert_eq!(active.cid, cid_n(0));
        // It was NOT queued for retire (we still use it).
        assert!(pool.pop_pending_retire().is_none());
        assert_eq!(pool.retire_prior_to, 5);

        // When a higher-sequence CID finally arrives, the next
        // retire_prior_to bump (or this one, re-evaluated) lets us rotate
        // and drop the stale active CID.
        pool.add(CidEntry {
            cid: cid_n(7),
            sequence: 7,
            reset_token: None,
        })
        .unwrap();
        // Re-announce a retire_prior_to that now has a survivor (>5).
        pool.note_retire_prior_to(6).expect("retire ok");
        assert_eq!(pool.active_seq, 7, "active rotates once a survivor exists");
        assert!(!pool.entries.contains_key(&0), "stale active CID dropped");
    }

    #[test]
    fn cidpool_retire_unknown_sequence_returns_none() {
        let mut pool = CidPool::new(cid_n(0), None);
        // Sequence 42 was never added; retire returns Ok(None).
        let r = pool.retire(42).expect("ok");
        assert!(r.is_none());
    }

    #[test]
    fn cidpool_add_below_retire_prior_to_immediately_retires() {
        let mut pool = CidPool::new(cid_n(0), None);
        pool.set_limit(4);
        pool.active_seq = 5;
        pool.note_retire_prior_to(3).expect("retire ok");
        // Now an entry at sequence 2 should be auto-retired.
        let e = CidEntry {
            cid: cid_n(0xab),
            sequence: 2,
            reset_token: None,
        };
        assert!(pool.add(e).is_ok());
        assert!(!pool.entries.contains_key(&2));
        let mut got = alloc::vec::Vec::new();
        while let Some(s) = pool.pop_pending_retire() {
            got.push(s);
        }
        assert!(got.contains(&2));
    }

    // F2: a peer that floods NEW_CONNECTION_ID-style entries with a large
    // retire_prior_to and distinct small sequences must not be able to
    // grow `pending_retire` without bound. The pool either dedups the
    // sequence away or errors once the cap is hit; it never grows
    // unboundedly.
    #[test]
    fn cidpool_pending_retire_is_bounded_under_flood() {
        let mut pool = CidPool::new(cid_n(0), None);
        pool.set_limit(2);
        // Announce a high retire_prior_to so every fresh low sequence is
        // immediately auto-retired (the unbounded-growth branch in `add`).
        pool.note_retire_prior_to(1_000_000).expect("retire ok");
        let cap = pool.pending_retire_cap();

        let mut hit_error = false;
        for s in 0..100_000u64 {
            let e = CidEntry {
                cid: cid_n((s % 256) as u8),
                sequence: s,
                reset_token: None,
            };
            // Every distinct sequence is below retire_prior_to → routed
            // through `queue_pending_retire`. Once the cap is reached the
            // pool returns an error rather than appending forever.
            if pool.add(e).is_err() {
                hit_error = true;
                break;
            }
        }
        assert!(hit_error, "flood must eventually be rejected");
        assert!(
            pool.pending_retire.len() <= cap,
            "pending_retire ({}) must stay within cap ({cap})",
            pool.pending_retire.len(),
        );
    }

    // F2: re-announcing an already-queued retire sequence is deduped and
    // does not consume cap budget, so a peer cannot inflate the queue by
    // repeating the same sequence.
    #[test]
    fn cidpool_pending_retire_dedups() {
        let mut pool = CidPool::new(cid_n(0), None);
        pool.set_limit(2);
        pool.note_retire_prior_to(10).expect("retire ok");
        // Add the same below-threshold sequence many times.
        for _ in 0..1000 {
            let e = CidEntry {
                cid: cid_n(7),
                sequence: 5,
                reset_token: None,
            };
            pool.add(e).expect("dedup keeps this within cap");
        }
        assert_eq!(
            pool.pending_retire.iter().filter(|&&s| s == 5).count(),
            1,
            "sequence 5 must be queued at most once",
        );
        assert!(pool.pending_retire.len() <= pool.pending_retire_cap());
    }
}
