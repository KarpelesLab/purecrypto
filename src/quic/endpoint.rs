//! Endpoint-level helpers shared by client and server: the CryptoState
//! enclosure, the per-level reassembly buffers, the PTO timer, and the
//! datagram-assembly bookkeeping that doesn't change between roles.
//!
//! The hand-off shape between [`Endpoint`], [`QuicConnection`], and the
//! TLS engine is:
//!
//! * The engine holds the only `&mut` to its own state (and to the hook
//!   queues, indirectly through `Arc<Mutex>`). It never drives I/O.
//! * `Endpoint` holds the per-level [`CryptoBuf`], the [`PnSpace`], the
//!   [`CryptoState`], the [`PtoState`], and the connection's CIDs.
//! * `QuicConnection` glues the two together and exposes the public
//!   sans-I/O API.
//!
//! This module intentionally houses no large algorithms — only data
//! structures and trivial accessors. The handshake state machine,
//! datagram packing, and inbound dispatch live in `connection.rs`.

#![allow(dead_code)]

use crate::quic::cid::CidPair;
use crate::quic::crypto::LevelKeys;
use crate::quic::crypto_buf::CryptoBuf;
use crate::quic::loss::PtoState;
use crate::quic::pn::PnSpace;
use crate::tls::quic_hooks::Level;

/// Per-encryption-level AEAD state. Indexed by `Level as usize` — 4
/// slots, matching the [`crate::tls::quic_hooks::Level`] enum ordinals.
pub(crate) struct CryptoState {
    /// Per-level keys (tx and rx halves). `Initial` is populated at
    /// construction time; the others fill in as the TLS engine surfaces
    /// secrets via the hook.
    pub(crate) levels: [LevelKeys; 4],
}

impl CryptoState {
    /// Fresh state with all four levels empty.
    pub(crate) fn empty() -> Self {
        Self {
            levels: [
                LevelKeys::empty(),
                LevelKeys::empty(),
                LevelKeys::empty(),
                LevelKeys::empty(),
            ],
        }
    }

    /// Convenience accessor — keys for level `l`.
    #[inline]
    pub(crate) fn at(&self, l: Level) -> &LevelKeys {
        &self.levels[l as usize]
    }

    /// Mutable accessor.
    #[inline]
    pub(crate) fn at_mut(&mut self, l: Level) -> &mut LevelKeys {
        &mut self.levels[l as usize]
    }
}

/// Per-encryption-level reassembly + outbound CRYPTO buffers.
///
/// Distinct from `CryptoState` (which holds keys, not byte streams).
pub(crate) struct LevelBufs {
    pub(crate) bufs: [CryptoBuf; 4],
}

impl LevelBufs {
    pub(crate) fn new() -> Self {
        Self {
            bufs: [
                CryptoBuf::new(),
                CryptoBuf::new(),
                CryptoBuf::new(),
                CryptoBuf::new(),
            ],
        }
    }

    #[inline]
    pub(crate) fn at(&self, l: Level) -> &CryptoBuf {
        &self.bufs[l as usize]
    }

    #[inline]
    pub(crate) fn at_mut(&mut self, l: Level) -> &mut CryptoBuf {
        &mut self.bufs[l as usize]
    }
}

/// Per-PN-space bookkeeping. QUIC has 3 PN spaces (RFC 9000 §12.3):
/// Initial, Handshake, Application. 0-RTT and 1-RTT share Application.
pub(crate) struct PnSpaces {
    pub(crate) initial: PnSpace,
    pub(crate) handshake: PnSpace,
    pub(crate) application: PnSpace,
}

impl PnSpaces {
    pub(crate) fn new() -> Self {
        Self {
            initial: PnSpace::default(),
            handshake: PnSpace::default(),
            application: PnSpace::default(),
        }
    }

    /// Maps a [`Level`] to its PN space. `Initial` → initial,
    /// `Handshake` → handshake, `EarlyData` / `OneRtt` → application.
    pub(crate) fn for_level(&mut self, l: Level) -> &mut PnSpace {
        match l {
            Level::Initial => &mut self.initial,
            Level::Handshake => &mut self.handshake,
            Level::EarlyData | Level::OneRtt => &mut self.application,
        }
    }
}

/// Endpoint-level state: the shared mutable substrate that both client
/// and server [`crate::quic::QuicConnection`] objects own.
pub(crate) struct Endpoint {
    /// Per-level AEAD keys (tx + rx).
    pub(crate) crypto: CryptoState,
    /// Per-level CRYPTO byte streams (in + out).
    pub(crate) bufs: LevelBufs,
    /// Per-PN-space packet-number bookkeeping (3 spaces).
    pub(crate) pn: PnSpaces,
    /// Single PTO timer covering all unacked CRYPTO at all levels.
    pub(crate) pto: PtoState,
    /// The two CIDs pinning this connection.
    pub(crate) cids: CidPair,
    /// True once `pop_datagram` has emitted the very first outbound
    /// datagram (used by the client to know whether to pad to 1200
    /// bytes per RFC 9000 §14.1).
    pub(crate) sent_first_datagram: bool,
    /// True once the QUIC handshake is logically complete on this side
    /// (the TLS engine reported `!is_handshaking` and the 1-RTT keys
    /// are installed in both directions).
    pub(crate) handshake_complete: bool,
}

impl Endpoint {
    /// Fresh endpoint with no keys, no PNs, both CIDs as supplied.
    pub(crate) fn new(cids: CidPair) -> Self {
        Self {
            crypto: CryptoState::empty(),
            bufs: LevelBufs::new(),
            pn: PnSpaces::new(),
            pto: PtoState::new(),
            cids,
            sent_first_datagram: false,
            handshake_complete: false,
        }
    }
}
