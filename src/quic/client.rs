//! Client-side bootstrap helpers.
//!
//! The interesting client-side logic — random CID picking, Initial-key
//! derivation, TLS engine construction in QUIC mode, draining the engine's
//! outbound CRYPTO bytes — is exposed as free functions here and is
//! invoked from [`crate::quic::QuicConnection::client`] /
//! [`crate::quic::QuicConnection::client_with_fixed_dcid`].

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::quic::cid::{CidPair, ConnectionId};
use crate::quic::crypto::{AeadAlg, derive_dir_keys, derive_initial_secrets};
use crate::quic::endpoint::Endpoint;
use crate::quic::tls_glue::{HookHandle, build_hooks};
use crate::rng::{OsRng, RngCore};
use crate::tls::Error;
use crate::tls::codec::{CipherSuite, NamedGroup};
use crate::tls::conn::{ClientConfig, ClientConnection};
use crate::tls::quic_hooks::Level;

/// Default Initial-CID byte length used by Phase 4. RFC 9000 §17.2 allows
/// 0..=20; 8 bytes is plenty of routing entropy for loopback tests and
/// keeps the long-header bookkeeping small.
pub(crate) const DEFAULT_CID_LEN: usize = 8;

/// Builds the Initial-level [`crate::quic::endpoint::Endpoint`] for a new
/// client connection: picks `our_scid`, derives Initial secrets from
/// `peer_dcid` (RFC 9001 §5.2), installs the Initial-level AEAD keys, and
/// records the CID pair. `peer_dcid` is the client's *chosen* DCID, which
/// the server will see as the DCID on the first Initial — and which also
/// keys both directions' Initial AEAD per RFC 9001 §5.2.
///
/// Returns the constructed `Endpoint`, ready to be wrapped in a
/// [`crate::quic::QuicConnection`].
pub(crate) fn build_initial_endpoint(peer_dcid: ConnectionId, our_scid: ConnectionId) -> Endpoint {
    let (client_secret, server_secret) = derive_initial_secrets(peer_dcid.as_slice());

    // Client Tx uses the "client in" secret; client Rx uses "server in"
    // (RFC 9001 §5.2).
    let mut ep = Endpoint::new(CidPair::new(peer_dcid, our_scid));
    ep.crypto.levels[Level::Initial as usize].tx =
        Some(derive_dir_keys(AeadAlg::Aes128Gcm, &client_secret));
    ep.crypto.levels[Level::Initial as usize].rx =
        Some(derive_dir_keys(AeadAlg::Aes128Gcm, &server_secret));
    ep
}

/// Constructs the TLS engine in QUIC mode with the supplied hooks, then
/// drives `process_new_packets` once to surface the ClientHello bytes
/// into the hook state.
///
/// `tls_cfg` is the `pub(crate)` engine-internal `ClientConfig` (built by
/// the QuicConfig adapter). `server_name` is the SNI hostname. Returns
/// the constructed engine and the hook handle; the caller then drains
/// `hook.drain_handshake(Level::Initial)` to discover the ClientHello.
pub(crate) fn build_tls_engine(
    tls_cfg: ClientConfig,
    server_name: &str,
    transport_params: Vec<u8>,
) -> Result<(ClientConnection, HookHandle), Error> {
    let (hooks, handle) = build_hooks(transport_params);
    // Phase 4 only tests Aes128Gcm against the RFC 9001 §A.1 vector and
    // the X25519 + Aes128Gcm loopback. Phase 5+ will widen the offer.
    let suites = [
        CipherSuite::AES_128_GCM_SHA256,
        CipherSuite::AES_256_GCM_SHA384,
        CipherSuite::CHACHA20_POLY1305_SHA256,
    ];
    let groups = [
        NamedGroup::X25519,
        NamedGroup::SECP256R1,
        NamedGroup::SECP384R1,
    ];

    let mut rng = OsRng;
    let engine = ClientConnection::new_for_quic(
        tls_cfg,
        server_name,
        &mut rng,
        &suites,
        &groups,
        hooks as Box<_>,
    );
    Ok((engine, handle))
}

/// Convenience: produces a freshly randomised CID of the
/// [`DEFAULT_CID_LEN`] length.
pub(crate) fn random_default_cid() -> ConnectionId {
    let mut rng = OsRng;
    ConnectionId::random(&mut rng, DEFAULT_CID_LEN)
}

/// Like [`random_default_cid`] but takes an explicit RNG — used by tests
/// that need reproducible CIDs.
pub(crate) fn random_default_cid_with<R: RngCore>(rng: &mut R) -> ConnectionId {
    ConnectionId::random(rng, DEFAULT_CID_LEN)
}

/// Stringify a server name. Kept here so the `connection.rs` constructor
/// reads as a single pass.
pub(crate) fn snify(name: &str) -> alloc::string::String {
    name.to_string()
}
