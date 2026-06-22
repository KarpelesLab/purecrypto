//! Encrypted Client Hello (draft-ietf-tls-esni-22).
//!
//! ECH conceals the inner ClientHello — and therefore the SNI, ALPN,
//! and other rendezvous bits — by encrypting it under HPKE
//! ([`crate::hpke`]) to a public key the server has published in DNS
//! as an `ECHConfigList`. The wire CH the network sees is the *outer*
//! CH; its SNI is the `public_name` from the `ECHConfig`, and a single
//! `encrypted_client_hello` extension carries the HPKE-sealed inner CH.
//!
//! The server tries to decrypt; on success the inner CH supplants the
//! outer one and the handshake proceeds privately. On failure (no
//! matching `config_id`, AEAD reject, malformed payload, or server
//! deliberately not configured), the outer CH is completed under the
//! `public_name` certificate and `EncryptedExtensions` carries an
//! `ECHConfigList` of `retry_configs` for the client to retry against.
//!
//! Clients that don't have a fresh `ECHConfig` for a given host (or are
//! deliberately censorship-resistant) still emit a bit-shape-identical
//! "GREASE" `encrypted_client_hello` extension via
//! [`EchClient::grease`] so the wire image is constant.
//!
//! The acceptance signal — last 8 bytes of `ServerHello.random` — is
//! computed in [`accept_signal`] using `Derive-Secret(handshake_secret,
//! "ech accept confirmation", transcript_hash(CH..SH'))` per draft §7.
//!
//! ## Implementation status
//!
//! This module ships the ECH codec foundations (ECHConfig + extension
//! codecs, HPKE wrappers, accept signal, key types, GREASE producer), the
//! real-ECH inner/outer split, the server-side HPKE decap + inner-CH
//! dispatch, and the retry_configs flow. The one piece still staged for a
//! follow-up wave is the `ech_outer_extensions` compress/decompress
//! primitive (see [`inner`]); it is unit-tested but not yet wired into the
//! handshake, and carries its own scoped `#[allow(dead_code)]`.

pub mod accept_signal;
pub mod config;
pub mod extension;
pub mod grease;
pub mod hpke_setup;
pub mod inner;
pub mod keys;
pub mod outer;
pub mod retry;

#[cfg(test)]
mod tests;

pub use config::{EchConfig, EchConfigContents, EchConfigList, HpkeKeyConfig, HpkeSymCipherSuite};
pub use grease::GreaseParams;
pub use keys::{EchKeyPair, EchKeyRing};

use alloc::vec::Vec;

/// Client-side ECH configuration attached to a [`crate::tls::Config`].
///
/// Either a real `ECHConfigList` to seal against, or a GREASE marker
/// that produces a bit-shape-identical `encrypted_client_hello` so the
/// wire image is constant across users.
#[derive(Clone, Debug)]
pub struct EchClient {
    pub(crate) mode: EchClientMode,
}

#[derive(Clone, Debug)]
pub(crate) enum EchClientMode {
    /// Real ECH: seal the inner CH against one of these `ECHConfig`s.
    Real(EchConfigList),
    /// GREASE: emit a fake outer-form ECH extension shaped exactly
    /// like a real one but containing random bytes. Servers without
    /// ECH ignore it; ECH-aware servers complete the outer handshake
    /// and offer `retry_configs` in EE just as for any reject.
    Grease(GreaseParams),
}

impl EchClient {
    /// Build a real ECH client from a published `ECHConfigList`.
    pub fn from_config_list(list: EchConfigList) -> Self {
        Self {
            mode: EchClientMode::Real(list),
        }
    }

    /// Parse a wire-encoded `ECHConfigList` and wrap it.
    pub fn from_config_list_bytes(bytes: &[u8]) -> Result<Self, crate::tls::Error> {
        let list = EchConfigList::decode(bytes)?;
        Ok(Self::from_config_list(list))
    }

    /// Produce a GREASE-mode ECH client. The outer extension carries
    /// random bytes shaped exactly like a real ECH payload. Servers
    /// without ECH ignore it; ECH-aware servers will reject and may
    /// offer `retry_configs` in EE.
    pub fn grease(params: GreaseParams) -> Self {
        Self {
            mode: EchClientMode::Grease(params),
        }
    }

    /// Default GREASE: ChaCha20-Poly1305 / HKDF-SHA-256, random
    /// 32-byte enc and 144-byte payload (the median modern CH size
    /// rounded to a small modulus).
    pub fn default_grease() -> Self {
        Self::grease(GreaseParams::default())
    }
}

/// Server-side ECH configuration attached to a [`crate::tls::Config`].
///
/// Holds the active key ring (the keys the server will actually try
/// to decrypt with) and the `retry_configs` to publish to clients
/// when the inner CH cannot be decrypted.
#[derive(Clone, Debug)]
pub struct EchServer {
    pub(crate) keys: EchKeyRing,
    pub(crate) retry_configs: EchConfigList,
}

impl EchServer {
    /// Build a server-side ECH state from a key ring and the
    /// `retry_configs` to offer on rejection.
    pub fn new(keys: EchKeyRing, retry_configs: EchConfigList) -> Self {
        Self {
            keys,
            retry_configs,
        }
    }

    /// The keys this server will try to decrypt with.
    pub fn keys(&self) -> &EchKeyRing {
        &self.keys
    }

    /// The `retry_configs` ECHConfigList shipped in EE on reject.
    pub fn retry_configs(&self) -> &EchConfigList {
        &self.retry_configs
    }

    /// Encode `retry_configs` to wire form.
    pub(crate) fn retry_configs_bytes(&self) -> Vec<u8> {
        self.retry_configs.encode()
    }
}
