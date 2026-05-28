//! Server-side ECH key material: an [`EchKeyPair`] (one HPKE recipient
//! key bound to one `ECHConfig`) and an [`EchKeyRing`] (a small
//! ordered list of pairs the server tries in turn against the
//! incoming `config_id`).

use super::config::{
    EchConfig, EchConfigContents, EchConfigList, HpkeKeyConfig, HpkeSymCipherSuite,
};
use crate::hpke::{HpkeAead, HpkeKdf, HpkeKem};
use crate::rng::RngCore;
use crate::tls::Error;
use alloc::vec::Vec;

/// One server-side HPKE recipient key paired with the `ECHConfig`
/// the matching client will use.
#[derive(Clone, Debug)]
pub struct EchKeyPair {
    /// HPKE KEM choice for this key.
    pub(crate) kem: HpkeKem,
    /// Raw HPKE private-key bytes (`Nsk(kem)` bytes long).
    pub(crate) private_key: Vec<u8>,
    /// The published `ECHConfig` referring to this key. `config_id`,
    /// `public_key`, `kem_id`, and the announced symmetric cipher
    /// suites all come from this struct.
    pub(crate) config: EchConfig,
}

impl EchKeyPair {
    /// Generate a fresh ECH key pair and the matching `ECHConfig`.
    ///
    /// `public_name` is the SNI the outer CH will carry — the
    /// certificate the server actually presents on outer-CH handshakes
    /// (or on ECH reject) must cover this name. `cipher_suites` is the
    /// non-empty list of `(kdf, aead)` symmetric pairs the server is
    /// willing to accept; the client picks one for its CH.
    /// `maximum_name_length` is the longest inner SNI byte length the
    /// publisher commits to padding shorter names up to.
    /// `config_id` is the 8-bit lookup byte.
    pub fn generate<R: RngCore>(
        rng: &mut R,
        kem: HpkeKem,
        config_id: u8,
        public_name: &[u8],
        maximum_name_length: u8,
        cipher_suites: Vec<HpkeSymCipherSuite>,
    ) -> Result<Self, Error> {
        if public_name.is_empty() || public_name.len() > 255 {
            return Err(Error::EchDecodeError);
        }
        if cipher_suites.is_empty() {
            return Err(Error::EchDecodeError);
        }
        let (sk, pk) = kem
            .generate_key_pair(rng)
            .map_err(|_| Error::EchDecodeError)?;
        let key_config = HpkeKeyConfig {
            config_id,
            kem_id: kem.id(),
            public_key: pk,
            cipher_suites,
        };
        let contents = EchConfigContents {
            key_config,
            maximum_name_length,
            public_name: public_name.to_vec(),
            extensions: Vec::new(),
        };
        let config = EchConfig::new(contents);
        Ok(Self {
            kem,
            private_key: sk,
            config,
        })
    }

    /// The `config_id` byte clients echo to select this key.
    pub fn config_id(&self) -> u8 {
        // Safe by construction: only built via `generate` and only at
        // a supported version.
        self.config
            .contents
            .as_ref()
            .map(|c| c.key_config.config_id)
            .unwrap_or(0)
    }

    /// The `ECHConfig` this key pair publishes.
    pub fn config(&self) -> &EchConfig {
        &self.config
    }

    /// The HPKE KEM this key is bound to.
    pub fn kem(&self) -> HpkeKem {
        self.kem
    }

    /// Raw HPKE private-key bytes — kept opaque outside the ECH module.
    pub(crate) fn private_key_bytes(&self) -> &[u8] {
        &self.private_key
    }

    /// True if `(kdf_id, aead_id)` is in this key's announced suite list.
    pub(crate) fn accepts(&self, kdf: HpkeKdf, aead: HpkeAead) -> bool {
        let contents = match self.config.contents.as_ref() {
            Some(c) => c,
            None => return false,
        };
        contents
            .key_config
            .cipher_suites
            .iter()
            .any(|s| s.kdf_id == kdf.id() && s.aead_id == aead.id())
    }
}

/// An ordered ring of server-side ECH keys. Each incoming outer-CH ECH
/// extension carries a `config_id`; the server picks the first
/// matching pair to attempt decryption with. Multiple keys exist to
/// support key rotation without breaking in-flight clients that may
/// still hold an older config.
#[derive(Clone, Debug)]
pub struct EchKeyRing {
    pub(crate) pairs: Vec<EchKeyPair>,
}

impl EchKeyRing {
    /// Empty ring — no keys to decrypt with.
    pub fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    /// Build a ring from an existing list of pairs (order preserved).
    pub fn from_pairs(pairs: Vec<EchKeyPair>) -> Self {
        Self { pairs }
    }

    /// Append a key pair.
    pub fn push(&mut self, pair: EchKeyPair) {
        self.pairs.push(pair);
    }

    /// Find the first pair with this `config_id`.
    pub(crate) fn find_by_config_id(&self, config_id: u8) -> Option<&EchKeyPair> {
        self.pairs.iter().find(|p| p.config_id() == config_id)
    }

    /// Publish the keys as an `ECHConfigList` clients can use to seal.
    pub fn to_config_list(&self) -> EchConfigList {
        EchConfigList::new(self.pairs.iter().map(|p| p.config.clone()).collect())
    }
}

impl Default for EchKeyRing {
    fn default() -> Self {
        Self::new()
    }
}
