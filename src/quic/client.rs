//! Client-side bootstrap helpers.
//!
//! The interesting client-side logic — random CID picking, Initial-key
//! derivation, TLS engine construction in QUIC mode, draining the engine's
//! outbound CRYPTO bytes — is exposed as free functions here and is
//! invoked from [`crate::quic::QuicConnection::client`] /
//! [`crate::quic::QuicConnection::client_with_fixed_dcid`].

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::quic::cid::{CidPair, ConnectionId};
use crate::quic::crypto::{AeadAlg, derive_dir_keys, derive_initial_secrets};
use crate::quic::endpoint::Endpoint;
use crate::quic::tls_glue::{HookHandle, build_hooks};
use crate::rng::OsRng;
use crate::tls::Error;
use crate::tls::codec::{CipherSuite, NamedGroup};
use crate::tls::conn::{ClientConfig, ClientConnection, select_offered_suites};
use crate::tls::quic_hooks::Level;

/// Default Initial-CID byte length used by Phase 4. RFC 9000 §17.2 allows
/// 0..=20; 8 bytes is plenty of routing entropy for loopback tests and
/// keeps the long-header bookkeeping small.
pub(crate) const DEFAULT_CID_LEN: usize = 8;

/// The TLS 1.3 cipher suites QUIC v1 may negotiate, in the engine's
/// preference order — the set a client offers unless
/// [`Config::cipher_suites`](crate::tls::Config::cipher_suites) narrows it.
///
/// RFC 9001 §5.3 forbids `TLS_AES_128_CCM_8_SHA256` (its 8-byte tag is far
/// below the §6.6 integrity limits) and the packet protection in
/// [`crate::quic::crypto`] implements no CCM mode at all, so the two AES-GCM
/// suites and ChaCha20-Poly1305 are the whole set. Each has its header
/// protection algorithm there: an AES-ECB mask for the AES suites (§5.4.3)
/// and a raw ChaCha20 block for ChaCha20-Poly1305 (§5.4.4).
pub(crate) const QUIC_CIPHER_SUITES: [CipherSuite; 3] = [
    CipherSuite::AES_128_GCM_SHA256,
    CipherSuite::AES_256_GCM_SHA384,
    CipherSuite::CHACHA20_POLY1305_SHA256,
];

/// The key-exchange groups a QUIC client offers (with a `key_share` for
/// each), in preference order — the same offer the TLS 1.3 engine makes
/// over TCP, so a server's
/// [`preferred_key_exchange_group`](crate::tls::ConfigBuilder::preferred_key_exchange_group)
/// steers QUIC handshakes exactly as it steers TLS ones. The X25519MLKEM768
/// share is 1216 bytes, so the ClientHello no longer fits one 1200-byte
/// Initial: the CRYPTO stream is carved into two Initial packets, each in
/// its own datagram padded to the RFC 9000 §14.1 minimum, and the server's
/// ServerHello (a 1120-byte KEM ciphertext) crosses back the same way.
pub(crate) const QUIC_CLIENT_GROUPS: [NamedGroup; 4] = [
    NamedGroup::X25519MLKEM768,
    NamedGroup::X25519,
    NamedGroup::SECP256R1,
    NamedGroup::SECP384R1,
];

/// The suites a client offers: [`QUIC_CIPHER_SUITES`] narrowed and ordered
/// by a [`Config::cipher_suites`](crate::tls::Config::cipher_suites)
/// restriction. Suites QUIC cannot use — the CCM ones above all — are
/// dropped from the restriction rather than offered, and a restriction that
/// leaves nothing (say, only `TLS_AES_128_CCM_8_SHA256`) fails closed with
/// [`Error::NoUsableCipherSuites`].
pub(crate) fn offered_cipher_suites(
    restriction: &Option<Vec<u16>>,
) -> Result<Vec<CipherSuite>, Error> {
    select_offered_suites(restriction, &QUIC_CIPHER_SUITES)
}

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
/// the QuicConfig adapter); its `cipher_suites` restriction narrows the
/// [`QUIC_CIPHER_SUITES`] offer (see [`offered_cipher_suites`]) and the
/// key shares cover [`QUIC_CLIENT_GROUPS`]. `server_name` is the SNI
/// hostname. Returns the constructed engine and the hook handle; the caller
/// then drains `hook.drain_handshake(Level::Initial)` to discover the
/// ClientHello.
pub(crate) fn build_tls_engine(
    tls_cfg: ClientConfig,
    server_name: &str,
    transport_params: Vec<u8>,
) -> Result<(ClientConnection, HookHandle), Error> {
    let (hooks, handle) = build_hooks(transport_params);
    let suites = offered_cipher_suites(&tls_cfg.cipher_suites)?;

    let mut rng = OsRng;
    let engine = ClientConnection::new_for_quic(
        tls_cfg,
        server_name,
        &mut rng,
        &suites,
        &QUIC_CLIENT_GROUPS,
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
