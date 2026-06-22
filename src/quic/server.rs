//! Server-side bootstrap helpers.
//!
//! On the server, Initial keys can't be derived at construction time —
//! they depend on the client's chosen DCID, which the server learns from
//! the first inbound Initial packet (RFC 9001 §5.2). Phase 4's
//! simplification: the [`crate::quic::QuicConnection::server`]
//! constructor leaves `Endpoint::cids` unset and derives Initial keys
//! lazily inside `feed_datagram`.
//!
//! The TLS engine itself can be constructed eagerly — it doesn't depend
//! on the DCID. But because [`crate::tls::conn::ServerConnection<R>`] is
//! generic over the RNG type, we monomorphize to `OsRng` here for the
//! sans-I/O wrapper.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::quic::cid::{CidPair, ConnectionId};
use crate::quic::crypto::{AeadAlg, derive_dir_keys, derive_initial_secrets};
use crate::quic::endpoint::Endpoint;
use crate::quic::tls_glue::{HookHandle, build_hooks};
use crate::rng::OsRng;
use crate::tls::Error;
use crate::tls::conn::{ServerConfig, ServerConnection};
use crate::tls::quic_hooks::Level;

/// Default server-side SCID length. Same value as the client's
/// [`crate::quic::client::DEFAULT_CID_LEN`] (8 bytes).
pub(crate) const DEFAULT_SCID_LEN: usize = 8;

/// Constructs the TLS engine in QUIC server mode and returns the engine
/// alongside the driver-side hook handle. The engine is *not* fed any
/// bytes yet — the first call to
/// [`crate::quic::QuicConnection::feed_datagram`] will feed the
/// reassembled ClientHello and `process_new_packets` will drive the
/// ServerHello.
pub(crate) fn build_tls_engine(
    tls_cfg: ServerConfig,
    transport_params: Vec<u8>,
) -> Result<(ServerConnection<OsRng>, HookHandle), Error> {
    let (hooks, handle) = build_hooks(transport_params);
    let engine = ServerConnection::new_for_quic(tls_cfg, OsRng, hooks as Box<_>);
    Ok((engine, handle))
}

/// Installs the Initial-level AEAD keys on `endpoint`, keyed by the
/// client's chosen DCID. The client picked this DCID at random; per RFC
/// 9001 §5.2 both Initial keys derive from
/// `HKDF-Extract(initial_salt, client_dcid)`.
///
/// `client_dcid` is the bytes the client wrote into the DCID slot of its
/// first Initial long header.
pub(crate) fn install_initial_keys(endpoint: &mut Endpoint, client_dcid: &[u8]) {
    let (client_secret, server_secret) = derive_initial_secrets(client_dcid);
    // On the server, Tx = "server in"; Rx = "client in".
    endpoint.crypto.levels[Level::Initial as usize].tx =
        Some(derive_dir_keys(AeadAlg::Aes128Gcm, &server_secret));
    endpoint.crypto.levels[Level::Initial as usize].rx =
        Some(derive_dir_keys(AeadAlg::Aes128Gcm, &client_secret));
}

/// Constructs a placeholder [`Endpoint`] with unset CIDs. The server's
/// CIDs are filled in by [`set_cids_from_first_initial`] on receipt of
/// the first client Initial.
pub(crate) fn build_pending_endpoint() -> Endpoint {
    Endpoint::new(CidPair::new(ConnectionId::empty(), ConnectionId::empty()))
}

/// Records the server's CID choice and the peer CID extracted from the
/// first client Initial. `peer_scid` is the SCID byte string from the
/// client's first long header (which becomes our DCID for outbound
/// packets per RFC 9000 §7.2). `our_local` is the server-chosen SCID we
/// will write back on every server long-header outbound — typically a
/// random 8-byte value.
pub(crate) fn set_cids_from_first_initial(
    endpoint: &mut Endpoint,
    peer_scid: ConnectionId,
    our_local: ConnectionId,
) {
    endpoint.cids = CidPair::new(peer_scid, our_local);
}

/// Convenience random-CID helper mirroring
/// [`crate::quic::client::random_default_cid`].
pub(crate) fn random_default_scid() -> ConnectionId {
    let mut rng = OsRng;
    ConnectionId::random(&mut rng, DEFAULT_SCID_LEN)
}
