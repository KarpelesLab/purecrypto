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

use crate::rng::RngCore;

/// Maximum QUIC v1 connection-ID length, RFC 9000 §17.2.
const MAX_CID_LEN: usize = 20;

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
}
