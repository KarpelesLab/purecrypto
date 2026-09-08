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
use crate::tls::Error;
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

/// Smallest `payload_len` that can correspond to a real sealed inner CH:
/// one byte of plaintext plus the 16-byte AEAD tag. A shorter GREASE payload
/// is the exact length distinguisher [`DEFAULT_GREASE_PAYLOAD_LEN`] exists to
/// eliminate — a passive censor can tell it apart from genuine ECH by size
/// alone.
pub const MIN_GREASE_PAYLOAD_LEN: usize = 17;

/// Upper bound on `1 + enc_len + payload_len`: the GREASE body is derived in
/// one HKDF-SHA-256 expansion (the seeded builder used for every ClientHello),
/// whose output is capped at `255 * HashLen = 8160` bytes by RFC 5869 §2.3
/// (the crate's `hkdf` panics beyond it). The `u16` wire limit alone would
/// admit `enc_len + payload_len` up to ~128 KiB, so a `GreaseParams` with,
/// say, `payload_len = 9000` would otherwise pass [`GreaseParams::validate`]
/// and then panic on every ClientHello built with it.
pub const MAX_GREASE_TOTAL_LEN: usize = 255 * 32;

/// Largest `enc_len` that still leaves room for a
/// [`MIN_GREASE_PAYLOAD_LEN`]-byte payload under [`MAX_GREASE_TOTAL_LEN`].
const MAX_GREASE_ENC_LEN: usize = MAX_GREASE_TOTAL_LEN - 1 - MIN_GREASE_PAYLOAD_LEN;

impl GreaseParams {
    /// Checks the lengths are representable on the wire, derivable, and
    /// large enough to pass for real ECH: `enc_len` and `payload_len` must
    /// fit a `u16` (`opaque <0..2^16-1>`), `payload_len` must be at least
    /// [`MIN_GREASE_PAYLOAD_LEN`], and `1 + enc_len + payload_len` must not
    /// exceed [`MAX_GREASE_TOTAL_LEN`] (the single-HKDF-expansion bound the
    /// seeded builder derives the body under).
    ///
    /// The builders clamp to this range rather than emitting an extension
    /// whose length prefix disagrees with its body, so a `GreaseParams` that
    /// fails this check produces valid-but-not-what-you-asked-for bytes; call
    /// it if you want a misconfiguration to be loud.
    pub fn validate(&self) -> Result<(), Error> {
        if self.enc_len > u16::MAX as usize
            || self.payload_len > u16::MAX as usize
            || self.payload_len < MIN_GREASE_PAYLOAD_LEN
            || 1 + self.enc_len + self.payload_len > MAX_GREASE_TOTAL_LEN
        {
            return Err(Error::IllegalParameter);
        }
        Ok(())
    }

    /// The lengths actually emitted: clamped into the representable,
    /// derivable, non-distinguishing range described by [`Self::validate`].
    /// `enc_len` is cut first (to leave room for a minimum payload), then
    /// `payload_len` to whatever remains under [`MAX_GREASE_TOTAL_LEN`].
    fn clamped_lens(&self) -> (usize, usize) {
        let enc_len = self.enc_len.min(MAX_GREASE_ENC_LEN);
        let payload_len = self
            .payload_len
            .clamp(MIN_GREASE_PAYLOAD_LEN, MAX_GREASE_TOTAL_LEN - 1 - enc_len);
        (enc_len, payload_len)
    }

    /// Build the outer-form `encrypted_client_hello` extension body.
    ///
    /// Calls into `rng` once to fill `enc` + `payload` (+ `config_id`
    /// when strategy is `Random`). Lengths outside the range
    /// [`Self::validate`] accepts are clamped.
    pub(crate) fn build_extension<R: RngCore>(&self, rng: &mut R) -> EchExtension {
        let (enc_len, payload_len) = self.clamped_lens();
        let mut enc = alloc::vec![0u8; enc_len];
        if !enc.is_empty() {
            rng.fill_bytes(&mut enc);
        }
        let mut payload = alloc::vec![0u8; payload_len];
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
        let (enc_len, payload_len) = self.clamped_lens();
        // Output: 1 byte (config_id selector) + enc_len + payload_len.
        let mut out = alloc::vec![0u8; 1 + enc_len + payload_len];
        // IKM = private seed; salt = CH random; info = label.
        hkdf::<Sha256>(ch_random, seed, b"ech grease", &mut out);

        let config_id = match self.config_id_strategy {
            GreaseConfigIdStrategy::Fixed(v) => v,
            GreaseConfigIdStrategy::Random => out[0],
        };
        let (enc, payload) = out[1..].split_at(enc_len);
        let ext = super::extension::EchExtension::Outer {
            cipher_suite: self.cipher_suite,
            config_id,
            enc: enc.to_vec(),
            payload: payload.to_vec(),
        };
        ext.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn params(enc_len: usize, payload_len: usize) -> GreaseParams {
        GreaseParams {
            enc_len,
            payload_len,
            config_id_strategy: GreaseConfigIdStrategy::Fixed(0x2a),
            ..GreaseParams::default()
        }
    }

    /// Outer-form wire overhead: type(1) + cipher_suite(4) + config_id(1) +
    /// two u16 length prefixes.
    const OUTER_OVERHEAD: usize = 1 + 4 + 1 + 2 + 2;

    /// PKI-2: `payload_len = 9000` fits a u16 (so it passed the old
    /// `validate`) but `1 + 32 + 9000` exceeds the 8160-byte HKDF-SHA-256
    /// expansion limit — the seeded builder used to panic on every
    /// ClientHello. `validate` must now reject it, and both builders must
    /// clamp instead of panicking.
    #[test]
    fn oversized_payload_is_rejected_and_clamped_not_panicking() {
        let p = params(32, 9000);
        assert_eq!(p.validate(), Err(Error::IllegalParameter));

        let (enc_len, payload_len) = p.clamped_lens();
        assert_eq!(enc_len, 32);
        assert_eq!(payload_len, MAX_GREASE_TOTAL_LEN - 1 - 32);
        assert_eq!(1 + enc_len + payload_len, MAX_GREASE_TOTAL_LEN);

        let body = p.build_extension_from_seed(&[7u8; 32], &[9u8; 32]);
        assert_eq!(body.len(), OUTER_OVERHEAD + enc_len + payload_len);

        let mut rng = HmacDrbg::<Sha256>::new(b"grease-clamp", b"nonce", &[]);
        match p.build_extension(&mut rng) {
            EchExtension::Outer { enc, payload, .. } => {
                assert_eq!(enc.len(), enc_len);
                assert_eq!(payload.len(), payload_len);
            }
            _ => panic!("GREASE builds the outer form"),
        }
    }

    /// An `enc_len` that alone exhausts the budget is cut first, leaving room
    /// for a minimum-size payload; the total stays derivable.
    #[test]
    fn oversized_enc_is_clamped_first() {
        let p = params(u16::MAX as usize, DEFAULT_GREASE_PAYLOAD_LEN);
        assert_eq!(p.validate(), Err(Error::IllegalParameter));
        let (enc_len, payload_len) = p.clamped_lens();
        assert_eq!(enc_len, MAX_GREASE_ENC_LEN);
        assert_eq!(payload_len, MIN_GREASE_PAYLOAD_LEN);
        assert_eq!(1 + enc_len + payload_len, MAX_GREASE_TOTAL_LEN);
        let body = p.build_extension_from_seed(&[1u8; 32], &[2u8; 32]);
        assert_eq!(body.len(), OUTER_OVERHEAD + enc_len + payload_len);
    }

    /// The exact ceiling is accepted, one byte over is not, and the defaults
    /// (and every realistic KEM `enc` size) validate unchanged.
    #[test]
    fn total_len_boundary() {
        assert!(GreaseParams::default().validate().is_ok());
        for enc_len in [32usize, 65, 97, 133] {
            assert!(
                params(enc_len, DEFAULT_GREASE_PAYLOAD_LEN)
                    .validate()
                    .is_ok()
            );
        }
        let at_limit = params(32, MAX_GREASE_TOTAL_LEN - 1 - 32);
        assert!(at_limit.validate().is_ok());
        assert_eq!(at_limit.clamped_lens(), (32, MAX_GREASE_TOTAL_LEN - 1 - 32));
        let over = params(32, MAX_GREASE_TOTAL_LEN - 32);
        assert_eq!(over.validate(), Err(Error::IllegalParameter));
    }
}
