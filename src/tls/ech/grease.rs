//! Bit-shape-identical GREASE producer (draft §6.2).
//!
//! A non-ECH client emits an outer-form `encrypted_client_hello`
//! extension that is byte-shape-indistinguishable from a real ECH
//! payload: same `cipher_suite`, same `config_id`, same `enc`
//! length for the chosen KEM, and a `payload` of the size a real
//! sealed inner CH would have for the connection's CH size and
//! `maximum_name_length` settings. The body is just random bytes —
//! servers that don't speak ECH ignore it (unrecognised extension);
//! servers that do can either accept and decrypt (mismatch ⇒
//! reject ⇒ EE carries retry_configs).

use super::config::HpkeSymCipherSuite;
use super::extension::EchExtension;
use crate::rng::RngCore;
use alloc::vec::Vec;

/// Default GREASE `payload` length (bytes).
///
/// A real ECH payload is the AEAD output over a padded encoded inner
/// ClientHello: the inner CH is padded up to a multiple of 32 (ECH
/// draft §6.1.3, see `super::outer::pad_inner`) and then gains a
/// 16-byte HPKE/AEAD tag. A typical encoded inner CH (key_share, ALPN,
/// the usual extensions) lands in the ~250–290 byte range, padding to
/// 288, so a representative sealed payload is `288 + 16 = 304` bytes.
/// The previous default (144) was far below any real padded inner CH,
/// which let a passive observer distinguish GREASE from genuine ECH on
/// length alone — exactly what GREASE exists to prevent.
pub const DEFAULT_GREASE_PAYLOAD_LEN: usize = 304;

/// Defaults for a GREASE-mode `encrypted_client_hello`.
///
/// The default suite is `(HKDF-SHA-256, AES-128-GCM)` which is the
/// most commonly published ECH symmetric suite (Cloudflare, ITP).
/// The default `enc` is 32 bytes — DHKEM(X25519) — and the default
/// `payload` is [`DEFAULT_GREASE_PAYLOAD_LEN`] bytes, sized to match a
/// real sealed-and-padded inner CH so a passive censor cannot tell
/// GREASE apart from genuine ECH by length alone. All can be
/// overridden by the caller — and a client that *does* speak ECH on
/// other connections should set `payload_len` to the size its real
/// ECH payloads occupy so the two are indistinguishable.
#[derive(Copy, Clone, Debug)]
pub struct GreaseParams {
    /// `(kdf_id, aead_id)` advertised in the GREASE outer extension.
    pub cipher_suite: HpkeSymCipherSuite,
    /// `enc` length to emit (bytes). Should match the `Nenc` of the
    /// KEM whose `cipher_suite` you want to mimic: 32 for X25519, 65
    /// for P-256, 97 for P-384, 133 for P-521.
    pub enc_len: usize,
    /// `payload` length to emit (bytes). Defaults to
    /// [`DEFAULT_GREASE_PAYLOAD_LEN`], representative of a real
    /// sealed-and-padded inner CH. Set it to match the size your real
    /// ECH payloads occupy if you also speak genuine ECH, so a passive
    /// censor cannot distinguish the two by length. Must be ≥ 17 (one
    /// byte of compressed inner CH + 16-byte AEAD tag).
    pub payload_len: usize,
    /// `config_id` byte; rotating across CHs would be a fingerprint
    /// so the default is freshly random per call.
    pub config_id_strategy: GreaseConfigIdStrategy,
}

/// How GREASE picks its 8-bit `config_id`. Fresh random per CH is
/// the default and what the draft recommends.
#[derive(Copy, Clone, Debug)]
pub enum GreaseConfigIdStrategy {
    /// Random byte per CH.
    Random,
    /// Fixed byte — useful in tests where determinism matters.
    Fixed(u8),
}

impl Default for GreaseParams {
    fn default() -> Self {
        Self {
            cipher_suite: HpkeSymCipherSuite {
                kdf_id: 0x0001,  // HKDF-SHA-256
                aead_id: 0x0001, // AES-128-GCM
            },
            enc_len: 32,
            payload_len: DEFAULT_GREASE_PAYLOAD_LEN,
            config_id_strategy: GreaseConfigIdStrategy::Random,
        }
    }
}

impl GreaseParams {
    /// Build the outer-form `encrypted_client_hello` extension body.
    ///
    /// Calls into `rng` once to fill `enc` + `payload` (+ `config_id`
    /// when strategy is `Random`).
    pub(crate) fn build_extension<R: RngCore>(&self, rng: &mut R) -> EchExtension {
        let mut enc = alloc::vec![0u8; self.enc_len];
        if !enc.is_empty() {
            rng.fill_bytes(&mut enc);
        }
        let mut payload = alloc::vec![0u8; self.payload_len];
        if !payload.is_empty() {
            rng.fill_bytes(&mut payload);
        }
        let config_id = match self.config_id_strategy {
            GreaseConfigIdStrategy::Fixed(v) => v,
            GreaseConfigIdStrategy::Random => {
                let mut b = [0u8; 1];
                rng.fill_bytes(&mut b);
                b[0]
            }
        };
        EchExtension::Outer {
            cipher_suite: self.cipher_suite,
            config_id,
            enc,
            payload,
        }
    }

    /// Convenience: build the wire body (encoded extension) in one call.
    pub fn build_extension_bytes<R: RngCore>(&self, rng: &mut R) -> Vec<u8> {
        self.build_extension(rng).encode()
    }

    /// Derive GREASE bytes from a connection-private 32-byte seed plus
    /// the ClientHello random. The seed is fed in as IKM and the
    /// ClientHello random as the salt; the `"ech grease"` label
    /// separates this expansion from any other HKDF use.
    ///
    /// The seed MUST be unobservable to a passive on-path attacker —
    /// callers should source it from their RNG once at construction
    /// time (see [`crate::tls::ClientConnection`]). Deriving GREASE
    /// from the public ClientHello random alone is a fingerprint: an
    /// observer who sees the CH random can recompute the "encrypted"
    /// payload and detect a non-ECH client. Mixing in the private seed
    /// breaks that correlation while keeping the per-CH output fresh
    /// (the CH random is already fresh per handshake).
    pub(crate) fn build_extension_from_seed(
        &self,
        seed: &[u8; 32],
        ch_random: &[u8; 32],
    ) -> Vec<u8> {
        use crate::hash::Sha256;
        use crate::kdf::hkdf;
        // Output: 1 byte (config_id selector) + enc_len + payload_len.
        let mut out = alloc::vec![0u8; 1 + self.enc_len + self.payload_len];
        // IKM = private seed; salt = CH random; info = label.
        hkdf::<Sha256>(ch_random, seed, b"ech grease", &mut out);

        let config_id = match self.config_id_strategy {
            GreaseConfigIdStrategy::Fixed(v) => v,
            GreaseConfigIdStrategy::Random => out[0],
        };
        let (enc, payload) = out[1..].split_at(self.enc_len);
        let ext = super::extension::EchExtension::Outer {
            cipher_suite: self.cipher_suite,
            config_id,
            enc: enc.to_vec(),
            payload: payload.to_vec(),
        };
        ext.encode()
    }
}
