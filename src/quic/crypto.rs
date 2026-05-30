//! RFC 9001 §5 — packet protection for QUIC v1.
//!
//! This module is the cryptographic core of the QUIC implementation. It
//! provides:
//!
//! * RFC 9001 §5.2 — Initial-secret derivation from the client's chosen
//!   Destination Connection ID and the version-1 salt.
//! * RFC 9001 §5.1 — per-direction expansion of a traffic secret into a
//!   `(key, iv, hp)` triple using the `quic key` / `quic iv` / `quic hp`
//!   HKDF-Expand-Label outputs.
//! * RFC 9001 §5.3 — AEAD nonce reconstruction: the packet number is
//!   left-padded to 8 bytes big-endian and XORed into IV bytes 4..12.
//!   The unprotected packet header (including the encoded packet number)
//!   is the AEAD's additional data.
//! * RFC 9001 §5.4 — header-protection mask production. AES-128/256
//!   suites mask the 16-byte sample through AES-ECB; ChaCha20 splits the
//!   sample into a 32-bit little-endian counter and a 12-byte nonce, then
//!   takes the first 5 bytes of the keystream block.
//! * RFC 9001 §6.1 — pre-derivation of the next application-traffic
//!   secret with label `quic ku`, exposed for the future key-update path.
//!
//! All other QUIC state (PN spaces, packet framing, frame codec, …) lives
//! in sibling modules. This module is sans-I/O and side-effect-free.

#![allow(dead_code)]

use alloc::vec::Vec;

use crate::cipher::{Aes128, Aes256, BlockCipher, ChaCha20, ChaCha20Poly1305, Gcm};
use crate::hash::Sha256;
use crate::kdf::hkdf_extract;
use crate::tls::Error;
use crate::tls::crypto::{HashAlg, expand_label_dyn};

/// AEAD suite selected for an encryption level.
///
/// Mirrors the TLS 1.3 cipher-suite set minus `TLS_AES_128_CCM_8_SHA256`,
/// which RFC 9001 §5.3 explicitly excludes from negotiation in QUIC v1
/// (no header-protection scheme defined for it).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum AeadAlg {
    /// `TLS_AES_128_GCM_SHA256`.
    Aes128Gcm,
    /// `TLS_AES_256_GCM_SHA384`.
    Aes256Gcm,
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    ChaCha20Poly1305,
}

impl AeadAlg {
    /// AEAD key length in bytes.
    pub(crate) const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
            Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Hash function used for HKDF-Expand-Label in this suite (RFC 8446
    /// §B.4).
    pub(crate) const fn hash(self) -> HashAlg {
        match self {
            Self::Aes128Gcm => HashAlg::Sha256,
            Self::Aes256Gcm => HashAlg::Sha384,
            Self::ChaCha20Poly1305 => HashAlg::Sha256,
        }
    }

    /// RFC 9001 §B.1 / §6.6 — per-key AEAD *usage* limit (maximum number
    /// of packets that may be encrypted with the same key before the key
    /// MUST be retired). Exceeding this MUST close the connection with
    /// AEAD_LIMIT_REACHED (transport error 0x0e, RFC 9000 §20).
    ///
    /// Per RFC 9001 §B.1:
    /// * AEAD_AES_128_GCM, AEAD_AES_256_GCM:   2^23 packets.
    /// * AEAD_CHACHA20_POLY1305:               2^62 packets (effectively
    ///   unreachable in practice).
    pub(crate) const fn usage_limit(self) -> u64 {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 1u64 << 23,
            Self::ChaCha20Poly1305 => 1u64 << 62,
        }
    }

    /// RFC 9001 §B.2 / §6.6 — per-key AEAD *integrity* limit (maximum
    /// number of AEAD authentication failures before the receive key
    /// MUST be retired). Exceeding this MUST close the connection with
    /// AEAD_LIMIT_REACHED (transport error 0x0e, RFC 9000 §20).
    ///
    /// Per RFC 9001 §B.2:
    /// * AEAD_AES_128_GCM, AEAD_AES_256_GCM:   2^52 failures.
    /// * AEAD_CHACHA20_POLY1305:               2^36 failures.
    pub(crate) const fn integrity_limit(self) -> u64 {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 1u64 << 52,
            Self::ChaCha20Poly1305 => 1u64 << 36,
        }
    }
}

/// One direction (transmit or receive) of packet protection for one
/// encryption level. Holds the derived AEAD key, IV, header-protection
/// state, and the traffic secret that produced them (kept so the key
/// update path can call [`derive_next_application_secret`]).
#[derive(Clone)]
pub(crate) struct DirKeys {
    pub(crate) alg: AeadAlg,
    /// AEAD key — exactly [`AeadAlg::key_len`] bytes long.
    pub(crate) key: Vec<u8>,
    /// AEAD static IV. Per RFC 9001 §5.1 the IV is always 12 bytes long
    /// (the QUIC nonce is also 12 bytes — see §5.3).
    pub(crate) iv: [u8; 12],
    /// Header-protection mask producer.
    pub(crate) hp: HeaderProt,
    /// The traffic secret these keys were derived from. Kept so that
    /// [`derive_next_application_secret`] can compute the next-generation
    /// secret without the caller threading state around.
    pub(crate) secret: Vec<u8>,
}

/// RFC 9001 §9.5 — per-key receive packet-number replay window.
///
/// QUIC requires that "each PN can only be used once per key" (RFC 9001
/// §9.5). The receiver MUST reject any PN that has already been opened
/// under the current rx key.
///
/// We track a 128-bit sliding window anchored at the largest PN ever
/// successfully decrypted with this key. The bit at position `i` records
/// "PN `top - i` already accepted" (bit 0 is the top itself). A PN that
/// falls below the window — i.e. its distance from `top` exceeds 128 —
/// is also rejected (it cannot be proved fresh).
///
/// This shape mirrors the DTLS replay window (`src/tls/dtls/replay.rs`).
#[derive(Default, Clone, Copy)]
pub(crate) struct PnReplayWindow {
    /// Largest PN ever accepted under this key (the bit-0 anchor).
    top: u64,
    /// Bitmask: bit `i` ⇒ PN `top - i` already accepted.
    bits: u128,
    /// True once `top` is meaningful (i.e. at least one PN accepted).
    seeded: bool,
}

impl PnReplayWindow {
    /// Returns an empty window.
    pub(crate) const fn new() -> Self {
        Self {
            top: 0,
            bits: 0,
            seeded: false,
        }
    }

    /// True if `pn` is fresh (has not previously been accepted, and lies
    /// within the 128-bit window above the floor).
    pub(crate) fn is_fresh(&self, pn: u64) -> bool {
        if !self.seeded {
            return true;
        }
        if pn > self.top {
            return true;
        }
        let dist = self.top - pn;
        if dist >= 128 {
            // Below the window — cannot prove freshness.
            return false;
        }
        (self.bits >> dist) & 1 == 0
    }

    /// Records `pn` as accepted. Caller MUST have already checked
    /// [`Self::is_fresh`] returned `true`; otherwise the call is a
    /// no-op (the bit was already set).
    pub(crate) fn record(&mut self, pn: u64) {
        if !self.seeded {
            self.top = pn;
            self.bits = 1; // bit 0 = top accepted.
            self.seeded = true;
            return;
        }
        if pn > self.top {
            let shift = pn - self.top;
            // Slide the window up; new bit 0 is `pn`, the *old* top is
            // at distance `shift`.
            if shift >= 128 {
                self.bits = 1;
            } else {
                self.bits = (self.bits << shift) | 1;
            }
            self.top = pn;
        } else {
            let dist = self.top - pn;
            if dist < 128 {
                self.bits |= 1u128 << dist;
            }
            // Else: below the window — record() is a no-op (caller
            // should not reach here after is_fresh()=false).
        }
    }
}

/// Header-protection mask producer (RFC 9001 §5.4.3 / §5.4.4).
///
/// Wraps the three permitted primitives behind a single type so the
/// packet layer can apply protection without branching on the negotiated
/// suite.
#[derive(Clone)]
pub(crate) enum HeaderProt {
    /// AES-128-ECB applied to the 16-byte sample (RFC 9001 §5.4.3).
    Aes128(Aes128),
    /// AES-256-ECB applied to the 16-byte sample (RFC 9001 §5.4.3).
    Aes256(Aes256),
    /// Raw ChaCha20 block (RFC 9001 §5.4.4): the sample is split into a
    /// 32-bit little-endian counter (`sample[0..4]`) and a 12-byte nonce
    /// (`sample[4..16]`); the mask is the first 5 bytes of the resulting
    /// 64-byte keystream block.
    ChaCha20(ChaCha20),
}

impl HeaderProt {
    /// Returns the 5-byte header-protection mask for `sample`.
    ///
    /// `sample` MUST be exactly 16 bytes long — RFC 9001 §5.4.1 fixes the
    /// sample length at 16 for all suites defined in §5.4. Callers should
    /// have ensured this by checking the packet has at least `pn_offset +
    /// 4 + 16` bytes (RFC 9001 §5.4.2: "An endpoint MUST discard packets
    /// that are not long enough to contain a complete sample.").
    pub(crate) fn mask(&self, sample: &[u8]) -> Result<[u8; 5], Error> {
        if sample.len() != 16 {
            return Err(Error::Decode);
        }
        let mut out = [0u8; 5];
        match self {
            HeaderProt::Aes128(c) => {
                let mut block = [0u8; 16];
                block.copy_from_slice(sample);
                c.encrypt_block(&mut block);
                out.copy_from_slice(&block[..5]);
            }
            HeaderProt::Aes256(c) => {
                let mut block = [0u8; 16];
                block.copy_from_slice(sample);
                c.encrypt_block(&mut block);
                out.copy_from_slice(&block[..5]);
            }
            HeaderProt::ChaCha20(c) => {
                // RFC 9001 §5.4.4: counter is sample[0..4] little-endian,
                // nonce is sample[4..16], "the encryption mask is produced
                // by invoking ChaCha20 to protect 5 zero bytes" — i.e. the
                // first 5 bytes of the keystream block.
                let counter = u32::from_le_bytes(sample[0..4].try_into().expect("16-byte sample"));
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&sample[4..16]);
                let ks = c.block(&nonce, counter);
                out.copy_from_slice(&ks[..5]);
            }
        }
        Ok(out)
    }
}

/// Per-level keys for one connection: optional transmit and receive
/// halves. A level has a `tx` half once we have derived keys to encrypt
/// outbound packets at that level, and an `rx` half once we have keys to
/// decrypt inbound packets.
///
/// For the 1-RTT level (Phase 8 key update, RFC 9001 §6) the keys are
/// additionally indexed by the Key Phase bit: `tx_by_phase[p]` and
/// `rx_by_phase[p]` carry the keys derived for phase `p ∈ {0, 1}`. The
/// "current" phase is held on the parent [`CryptoState::one_rtt_phase`].
/// Both phase slots are pre-derived from the current and the
/// next-generation traffic secrets so that an out-of-order packet
/// carrying the flipped phase bit can be opened without stalling
/// (RFC 9001 §6.2).
///
/// The legacy `tx`/`rx` fields stay populated for non-1-RTT levels and
/// for the *current* phase at the 1-RTT level; the rest of the crate
/// reads these fields unchanged. The phase-aware lookup is opt-in via
/// [`Self::rx_for_phase`] / [`Self::tx_for_phase`].
pub(crate) struct LevelKeys {
    pub(crate) tx: Option<DirKeys>,
    pub(crate) rx: Option<DirKeys>,

    // ---- Phase 8 (1-RTT only) ----
    /// Per-phase tx keys, indexed by the Key Phase bit (0 or 1). Populated
    /// once 1-RTT secrets land; both slots are kept current so the
    /// upcoming flip is a no-op.
    pub(crate) tx_by_phase: [Option<DirKeys>; 2],
    /// Per-phase rx keys, indexed by the Key Phase bit. The slot whose
    /// bit equals [`CryptoState::one_rtt_phase`] is the "current" rx;
    /// the other slot is the "next" rx that opens an out-of-order
    /// post-flip packet (RFC 9001 §6.2).
    pub(crate) rx_by_phase: [Option<DirKeys>; 2],
    /// RFC 9001 §6.2 — the *previous* phase's rx keys, kept across one
    /// commit so a delayed old-phase packet that arrives *after* we've
    /// flipped can still decrypt. Holds the keys we just rotated out
    /// of `rx_by_phase[old_phase]`. Cleared on the next flip.
    pub(crate) prev_rx_keys: Option<DirKeys>,
    /// True once we initiated a tx-side key update but haven't yet
    /// observed the peer use the new phase (which RFC 9001 §6.1
    /// requires before a second update can start).
    pub(crate) tx_phase_pending_confirm: bool,
    /// RFC 9001 §6 — the "quic hp" key bytes captured from the very
    /// first 1-RTT tx secret; reused unchanged across all subsequent
    /// key updates. RFC 9001 §6: "The same header protection key is
    /// used for the duration of the connection." Empty until 1-RTT
    /// secrets land.
    pub(crate) tx_hp_key_bytes: Vec<u8>,
    /// Counterpart for the rx direction.
    pub(crate) rx_hp_key_bytes: Vec<u8>,

    // ---- RFC 9001 §6.6 — AEAD usage / integrity limits ----
    /// Number of packets successfully encrypted with the *current* tx key.
    /// For non-1-RTT levels this is the only tx key; for 1-RTT it is reset
    /// on each tx-side key update (the per-key limit is per *key*, not per
    /// connection).
    pub(crate) tx_packets: u64,
    /// Number of AEAD authentication failures observed on the rx side for
    /// the current rx key. RFC 9001 §6.6: on reaching the integrity limit
    /// the connection MUST be closed.
    pub(crate) rx_aead_failures: u64,
    /// Test-only override of the usage limit. `None` ⇒ use
    /// `AeadAlg::usage_limit()`. Lets the test suite trip the close path
    /// without sending 2^23 packets.
    pub(crate) usage_limit_override: Option<u64>,
    /// Test-only override of the integrity limit. `None` ⇒ use
    /// `AeadAlg::integrity_limit()`.
    pub(crate) integrity_limit_override: Option<u64>,

    // ---- RFC 9001 §9.5 — per-key receive packet-number replay window ----
    /// Sliding 128-bit replay window over PNs decrypted under the
    /// current rx key. Reset whenever the rx key is replaced (key
    /// update, level switch). Note that QUIC packet numbers are
    /// per-PN-space (not per-key), but the *replay* constraint is
    /// per-key: once a key is retired, the next key's window restarts.
    pub(crate) rx_pn_window: PnReplayWindow,
}

impl LevelKeys {
    /// An empty pair (neither direction yet keyed).
    pub(crate) const fn empty() -> Self {
        Self {
            tx: None,
            rx: None,
            tx_by_phase: [None, None],
            rx_by_phase: [None, None],
            prev_rx_keys: None,
            tx_phase_pending_confirm: false,
            tx_hp_key_bytes: Vec::new(),
            rx_hp_key_bytes: Vec::new(),
            tx_packets: 0,
            rx_aead_failures: 0,
            usage_limit_override: None,
            integrity_limit_override: None,
            rx_pn_window: PnReplayWindow::new(),
        }
    }

    /// Returns the effective tx usage limit for this level's current
    /// suite, honoring any test-only override. Callers compare
    /// `tx_packets` against this value (RFC 9001 §6.6).
    pub(crate) fn effective_usage_limit(&self) -> u64 {
        if let Some(v) = self.usage_limit_override {
            return v;
        }
        // Use the legacy tx slot's alg if present; otherwise pick from
        // the phase table. If no tx key is installed, the limit is
        // irrelevant (we won't encrypt) — fall back to a huge value.
        let alg = self
            .tx
            .as_ref()
            .map(|k| k.alg)
            .or_else(|| self.tx_by_phase[0].as_ref().map(|k| k.alg))
            .or_else(|| self.tx_by_phase[1].as_ref().map(|k| k.alg));
        match alg {
            Some(a) => a.usage_limit(),
            None => u64::MAX,
        }
    }

    /// Returns the effective rx integrity limit (RFC 9001 §6.6).
    pub(crate) fn effective_integrity_limit(&self) -> u64 {
        if let Some(v) = self.integrity_limit_override {
            return v;
        }
        let alg = self
            .rx
            .as_ref()
            .map(|k| k.alg)
            .or_else(|| self.rx_by_phase[0].as_ref().map(|k| k.alg))
            .or_else(|| self.rx_by_phase[1].as_ref().map(|k| k.alg));
        match alg {
            Some(a) => a.integrity_limit(),
            None => u64::MAX,
        }
    }

    /// Phase-aware tx key lookup. `phase` is 0 or 1. Falls back to the
    /// legacy `tx` slot when the per-phase table hasn't been populated
    /// (i.e. for non-1-RTT levels, or before the first 1-RTT key
    /// install).
    pub(crate) fn tx_for_phase(&self, phase: u8) -> Option<&DirKeys> {
        let p = (phase & 1) as usize;
        self.tx_by_phase[p].as_ref().or(self.tx.as_ref())
    }

    /// Phase-aware rx key lookup. See [`Self::tx_for_phase`].
    pub(crate) fn rx_for_phase(&self, phase: u8) -> Option<&DirKeys> {
        let p = (phase & 1) as usize;
        self.rx_by_phase[p].as_ref().or(self.rx.as_ref())
    }
}

/// RFC 9001 §5.2 — the QUIC v1 Initial salt
/// `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`.
///
/// This is the salt fed to HKDF-Extract together with the client's chosen
/// Destination Connection ID to derive the per-connection Initial secret.
pub(crate) const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 9001 §5.2 — derive `(client_initial_secret, server_initial_secret)`
/// from the client's chosen Destination Connection ID:
///
/// ```text
///   initial_secret        = HKDF-Extract(initial_salt, client_dcid)
///   client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", Hash.length)
///   server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", Hash.length)
/// ```
///
/// Initial keys always use SHA-256 (RFC 9001 §5.2: "The hash function for
/// HKDF when deriving initial secrets and keys is SHA-256.").
pub(crate) fn derive_initial_secrets(client_dcid: &[u8]) -> ([u8; 32], [u8; 32]) {
    let initial_secret = hkdf_extract::<Sha256>(&INITIAL_SALT_V1, client_dcid);
    let mut cs = [0u8; 32];
    let mut ss = [0u8; 32];
    expand_label_dyn(
        HashAlg::Sha256,
        initial_secret.as_ref(),
        b"client in",
        &[],
        &mut cs,
    );
    expand_label_dyn(
        HashAlg::Sha256,
        initial_secret.as_ref(),
        b"server in",
        &[],
        &mut ss,
    );
    (cs, ss)
}

/// RFC 9001 §5.1 — derive `(key, iv, hp)` from a traffic secret.
///
/// `alg` selects the AEAD; its [`AeadAlg::hash`] selects the HKDF dispatch.
/// The labels (RFC 9001 §5.1) are `"quic key"`, `"quic iv"`, `"quic hp"`,
/// each with an empty context per the HKDF-Expand-Label structure inherited
/// from RFC 8446 §7.1.
pub(crate) fn derive_dir_keys(alg: AeadAlg, secret: &[u8]) -> DirKeys {
    let hash = alg.hash();
    let kl = alg.key_len();
    let mut key = alloc::vec![0u8; kl];
    let mut iv = [0u8; 12];
    expand_label_dyn(hash, secret, b"quic key", &[], &mut key);
    expand_label_dyn(hash, secret, b"quic iv", &[], &mut iv);

    let mut hp_key = alloc::vec![0u8; kl];
    expand_label_dyn(hash, secret, b"quic hp", &[], &mut hp_key);
    let hp = match alg {
        AeadAlg::Aes128Gcm => HeaderProt::Aes128(Aes128::new(hp_key[..16].try_into().expect("16"))),
        AeadAlg::Aes256Gcm => HeaderProt::Aes256(Aes256::new(hp_key[..32].try_into().expect("32"))),
        AeadAlg::ChaCha20Poly1305 => {
            HeaderProt::ChaCha20(ChaCha20::new(hp_key[..32].try_into().expect("32")))
        }
    };

    DirKeys {
        alg,
        key,
        iv,
        hp,
        secret: secret.to_vec(),
    }
}

/// RFC 9001 §6.1 — derive the next application-traffic secret for a
/// direction, using HKDF-Expand-Label with label `"quic ku"`.
///
/// Used by the Phase 8 key-update path; exposed now so the eventual
/// plumbing is a one-line call. The output is one hash-output long
/// (matching the input secret length).
pub(crate) fn derive_next_application_secret(alg: AeadAlg, current: &[u8]) -> Vec<u8> {
    let mut next = alloc::vec![0u8; current.len()];
    expand_label_dyn(alg.hash(), current, b"quic ku", &[], &mut next);
    next
}

/// RFC 9001 §6 — derive *only* the new AEAD `(key, iv)` from a
/// next-generation secret, keeping a previously-derived HP cipher
/// untouched.
///
/// The header-protection key MUST NOT change across key updates (RFC
/// 9001 §6 second paragraph: "The same header protection key is used
/// for the duration of the connection"). Cloning the existing hp
/// state out of an old `DirKeys` lets us produce the next phase's
/// `DirKeys` while preserving HP behavior.
///
/// Implementation note: [`HeaderProt`] embeds the block cipher state
/// (key-scheduled keys), not the raw bytes, so the only safe way to
/// "preserve" it across a key update is to re-derive it from the
/// secret that the original HP came from. We do that at install time
/// by recording the original hp key bytes alongside the secret, and
/// re-deriving the HP from those bytes; alternatively, the caller
/// can pass in the original "quic hp" key bytes via
/// [`derive_dir_keys_preserve_hp`].
pub(crate) fn derive_dir_keys_preserve_hp(
    alg: AeadAlg,
    secret: &[u8],
    hp_key_bytes: &[u8],
) -> DirKeys {
    let hash = alg.hash();
    let kl = alg.key_len();
    let mut key = alloc::vec![0u8; kl];
    let mut iv = [0u8; 12];
    expand_label_dyn(hash, secret, b"quic key", &[], &mut key);
    expand_label_dyn(hash, secret, b"quic iv", &[], &mut iv);

    let hp = match alg {
        AeadAlg::Aes128Gcm => {
            HeaderProt::Aes128(Aes128::new(hp_key_bytes[..16].try_into().expect("16")))
        }
        AeadAlg::Aes256Gcm => {
            HeaderProt::Aes256(Aes256::new(hp_key_bytes[..32].try_into().expect("32")))
        }
        AeadAlg::ChaCha20Poly1305 => {
            HeaderProt::ChaCha20(ChaCha20::new(hp_key_bytes[..32].try_into().expect("32")))
        }
    };

    DirKeys {
        alg,
        key,
        iv,
        hp,
        secret: secret.to_vec(),
    }
}

/// Compute the raw "quic hp" key bytes for a secret. The output length
/// equals [`AeadAlg::key_len`].
pub(crate) fn derive_hp_key_bytes(alg: AeadAlg, secret: &[u8]) -> Vec<u8> {
    let hash = alg.hash();
    let kl = alg.key_len();
    let mut hp_key = alloc::vec![0u8; kl];
    expand_label_dyn(hash, secret, b"quic hp", &[], &mut hp_key);
    hp_key
}

/// RFC 9001 §5.3 — construct the AEAD nonce.
///
/// "The 62 bits of the reconstructed QUIC packet number in network byte
/// order are left-padded with zeros to the size of the IV. The exclusive
/// OR of the padded packet number and the IV forms the AEAD nonce."
///
/// We mirror the TLS record-layer pattern in
/// `src/tls/crypto/aead.rs::next_nonce`: take the 8-byte big-endian
/// representation of the packet number and XOR it into IV bytes 4..12.
pub(crate) fn nonce_for(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn = packet_number.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn[i];
    }
    nonce
}

/// RFC 9001 §5.3 — seal one packet's payload.
///
/// Encrypts `plaintext_in_place` in place and returns the 16-byte AEAD
/// authentication tag. `aad` is the unprotected packet header (everything
/// from the first byte through the end of the encoded packet number,
/// inclusive — "The associated data, A, for the AEAD is the contents of
/// the QUIC header, starting from the first byte of either the short or
/// long header, up to and including the unprotected packet number.").
///
/// The caller is responsible for emitting `header || ciphertext || tag`
/// onto the wire and applying header protection afterwards
/// ([`crate::quic::pkt::apply_header_protection`]).
pub(crate) fn aead_seal(
    keys: &DirKeys,
    packet_number: u64,
    aad: &[u8],
    plaintext_in_place: &mut [u8],
) -> [u8; 16] {
    let nonce = nonce_for(&keys.iv, packet_number);
    match keys.alg {
        AeadAlg::Aes128Gcm => {
            let aes = Aes128::new(keys.key[..16].try_into().expect("16"));
            let g: Gcm<Aes128> = Gcm::new(aes);
            g.encrypt(&nonce, aad, plaintext_in_place)
        }
        AeadAlg::Aes256Gcm => {
            let aes = Aes256::new(keys.key[..32].try_into().expect("32"));
            let g: Gcm<Aes256> = Gcm::new(aes);
            g.encrypt(&nonce, aad, plaintext_in_place)
        }
        AeadAlg::ChaCha20Poly1305 => {
            let c = ChaCha20Poly1305::new(keys.key[..32].try_into().expect("32"));
            c.encrypt(&nonce, aad, plaintext_in_place)
        }
    }
}

/// RFC 9001 §5.3 / §5.5 — open one packet's payload.
///
/// Verifies `tag` and, on success, decrypts `ciphertext_in_place` in
/// place. On AEAD authentication failure returns [`Error::BadRecordMac`]
/// and the buffer is left as ciphertext (the underlying GCM / ChaCha20-
/// Poly1305 primitives both check the tag in constant time and refuse to
/// release plaintext on mismatch).
pub(crate) fn aead_open(
    keys: &DirKeys,
    packet_number: u64,
    aad: &[u8],
    ciphertext_in_place: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), Error> {
    let nonce = nonce_for(&keys.iv, packet_number);
    let ok = match keys.alg {
        AeadAlg::Aes128Gcm => {
            let aes = Aes128::new(keys.key[..16].try_into().expect("16"));
            let g: Gcm<Aes128> = Gcm::new(aes);
            g.decrypt(&nonce, aad, ciphertext_in_place, tag).is_ok()
        }
        AeadAlg::Aes256Gcm => {
            let aes = Aes256::new(keys.key[..32].try_into().expect("32"));
            let g: Gcm<Aes256> = Gcm::new(aes);
            g.decrypt(&nonce, aad, ciphertext_in_place, tag).is_ok()
        }
        AeadAlg::ChaCha20Poly1305 => {
            let c = ChaCha20Poly1305::new(keys.key[..32].try_into().expect("32"));
            c.decrypt(&nonce, aad, ciphertext_in_place, tag).is_ok()
        }
    };
    if ok { Ok(()) } else { Err(Error::BadRecordMac) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------- Helpers --------------------------------------------------

    /// Decodes a hex string into a byte vec. Hex must be lower-case and
    /// contain no whitespace. Used only in tests.
    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "hex length must be even");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    // -------- RFC 9001 §A.1 verbatim test vectors ----------------------

    /// The 8-byte client-chosen Destination Connection ID used throughout
    /// Appendix A (RFC 9001 §A: "These packets use an 8-byte
    /// client-chosen Destination Connection ID of 0x8394c8f03e515708.").
    const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    #[test]
    fn rfc9001_a1_initial_secrets() {
        // RFC 9001 §A.1:
        //   client_initial_secret
        //       = c00cf151ca5be075ed0ebfb5c80323c4
        //         2d6b7db67881289af4008f1f6c357aea
        //   server_initial_secret
        //       = 3c199828fd139efd216c155ad844cc81
        //         fb82fa8d7446fa7d78be803acdda951b
        let (cs, ss) = derive_initial_secrets(&DCID);
        assert_eq!(
            cs.as_slice(),
            hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea").as_slice(),
        );
        assert_eq!(
            ss.as_slice(),
            hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b").as_slice(),
        );
    }

    #[test]
    fn rfc9001_a1_client_dir_keys() {
        // RFC 9001 §A.1:
        //   key = 1f369613dd76d5467730efcbe3b1a22d
        //   iv  = fa044b2f42a3fd3b46fb255c
        //   hp  = 9f50449e04a0e810283a1e9933adedd2
        let (cs, _) = derive_initial_secrets(&DCID);
        let dk = derive_dir_keys(AeadAlg::Aes128Gcm, &cs);
        assert_eq!(dk.key.as_slice(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(dk.iv.as_slice(), hex("fa044b2f42a3fd3b46fb255c"));

        // Verify the hp key by re-deriving it directly (the hp key itself
        // is not stored on DirKeys; only the cipher built from it is).
        let mut hp_key = [0u8; 16];
        expand_label_dyn(HashAlg::Sha256, &cs, b"quic hp", &[], &mut hp_key);
        assert_eq!(&hp_key[..], hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn rfc9001_a1_server_dir_keys() {
        // RFC 9001 §A.1 (server side):
        //   key = cf3a5331653c364c88f0f379b6067e37
        //   iv  = 0ac1493ca1905853b0bba03e
        //   hp  = c206b8d9b9f0f37644430b490eeaa314
        let (_, ss) = derive_initial_secrets(&DCID);
        let dk = derive_dir_keys(AeadAlg::Aes128Gcm, &ss);
        assert_eq!(dk.key.as_slice(), hex("cf3a5331653c364c88f0f379b6067e37"));
        assert_eq!(dk.iv.as_slice(), hex("0ac1493ca1905853b0bba03e"));

        let mut hp_key = [0u8; 16];
        expand_label_dyn(HashAlg::Sha256, &ss, b"quic hp", &[], &mut hp_key);
        assert_eq!(&hp_key[..], hex("c206b8d9b9f0f37644430b490eeaa314"));
    }

    // -------- RFC 9001 §A.2 — Client Initial ---------------------------

    /// The Appendix A.2 plaintext: a CRYPTO frame containing a ClientHello
    /// followed by enough PADDING (0x00) to reach 1162 bytes.
    fn a2_plaintext() -> Vec<u8> {
        // Verbatim from RFC 9001 §A.2 ("plus enough PADDING frames to make
        // a 1162-byte payload"). The decoded CRYPTO frame is 245 bytes;
        // the remaining 917 bytes are PADDING (0x00).
        let mut p = hex(
            "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868\
             04fe3a47f06a2b69484c000004130113\
             02010000c000000010000e00000b6578\
             616d706c652e636f6dff01000100000a\
             00080006001d00170018001000070005\
             04616c706e000500050100000000\
             003300260024001d00209370b2c9caa47fba\
             baf4559fedba753de171fa71f50f1ce1\
             5d43e994ec74d748002b00030203040\
             00d0010000e040305030603020308040\
             8050806002d00020101001c00024001\
             003900320408ffffffffffffffff050480\
             00ffff07048000ffff080110010480\
             0075300901100f088394c8f03e515708\
             06048000ffff",
        );
        assert_eq!(p.len(), 245, "RFC 9001 §A.2 CRYPTO frame is 245 bytes");
        // Pad with zeros (PADDING frame is 0x00 — RFC 9000 §19.1) to
        // 1162 bytes.
        p.resize(1162, 0);
        p
    }

    #[test]
    fn rfc9001_a2_nonce() {
        // RFC 9001 §A.2 uses packet number 2 and the client IV
        // `fa044b2f42a3fd3b46fb255c`. The nonce is the IV XORed with the
        // 8-byte big-endian PN (`0000000000000002` → only the last byte
        // flips bit 1), giving `fa044b2f42a3fd3b46fb255e`.
        let (cs, _) = derive_initial_secrets(&DCID);
        let dk = derive_dir_keys(AeadAlg::Aes128Gcm, &cs);
        let nonce = nonce_for(&dk.iv, 2);
        assert_eq!(nonce.as_slice(), hex("fa044b2f42a3fd3b46fb255e"));
    }

    #[test]
    fn rfc9001_a2_client_initial_seal() {
        // Build the unprotected header from §A.2:
        //   c300000001088394c8f03e5157080000449e00000002
        let header = hex("c300000001088394c8f03e5157080000449e00000002");
        let mut payload = a2_plaintext();

        let (cs, _) = derive_initial_secrets(&DCID);
        let dk = derive_dir_keys(AeadAlg::Aes128Gcm, &cs);
        let tag = aead_seal(&dk, 2, &header, &mut payload);

        // The §A.2 sample is the first 16 bytes of the ciphertext
        // (starting at pn_offset + 4 = 4-byte-PN past the header, which
        // for this packet is the first 16 bytes of the protected
        // payload).
        assert_eq!(
            &payload[..16],
            hex("d1b1c98dd7689fb8ec11d242b123dc9b").as_slice()
        );

        // RFC 9001 §A.2 final protected packet, after concatenating
        // header || ciphertext || tag, has the trailing 16 bytes
        // `e221af44860018ab0856972e194cd934`.
        assert_eq!(tag.as_slice(), hex("e221af44860018ab0856972e194cd934"));
    }

    #[test]
    fn rfc9001_a2_header_protection_mask() {
        // §A.2: sample = d1b1c98dd7689fb8ec11d242b123dc9b
        //       mask   = 437b9aec36
        let (cs, _) = derive_initial_secrets(&DCID);
        let dk = derive_dir_keys(AeadAlg::Aes128Gcm, &cs);
        let sample = hex("d1b1c98dd7689fb8ec11d242b123dc9b");
        let mask = dk.hp.mask(&sample).expect("16-byte sample");
        assert_eq!(mask.as_slice(), hex("437b9aec36"));
    }

    // -------- RFC 9001 §A.3 — Server Initial ---------------------------

    #[test]
    fn rfc9001_a3_server_initial_seal() {
        // RFC 9001 §A.3 plaintext:
        //   02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566d
        //   c5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d10
        //   81287c834d5311bcf32bb9da1a002b00020304
        let payload = hex(
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566d\
             c5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d10\
             81287c834d5311bcf32bb9da1a002b00020304",
        );

        // RFC 9001 §A.3 unprotected header:
        //   c1000000010008f067a5502a4262b50040750001
        let header = hex("c1000000010008f067a5502a4262b50040750001");

        let mut buf = payload.clone();
        let (_, ss) = derive_initial_secrets(&DCID);
        let dk = derive_dir_keys(AeadAlg::Aes128Gcm, &ss);
        // Packet number for this server Initial is 1 (RFC 9001 §A.3:
        // "a 2-byte packet number encoding for a packet number of 1").
        let tag = aead_seal(&dk, 1, &header, &mut buf);

        // §A.3 sample = 2cd0991cd25b0aac406a5816b6394100; this is the 16
        // bytes starting at pn_offset + 4 inside the protected packet. The
        // 2-byte encoded PN occupies bytes [18..20] (relative to the
        // header start); the 4-byte sample window from §5.4.2 places the
        // sample at bytes [22..38] of the assembled wire packet — which is
        // bytes [2..18] of the ciphertext (header is 20 bytes, sample
        // starts 22 bytes in).
        assert_eq!(
            &buf[2..18],
            hex("2cd0991cd25b0aac406a5816b6394100").as_slice()
        );

        // The §A.3 final protected packet (135 bytes total) has its
        // 20-byte header at the front; the trailing 16 bytes are the AEAD
        // tag: `3d20398c276456cbc42158407dd074ee`.
        assert_eq!(tag.as_slice(), hex("3d20398c276456cbc42158407dd074ee"));
    }

    #[test]
    fn rfc9001_a3_header_protection_mask() {
        // §A.3: sample = 2cd0991cd25b0aac406a5816b6394100
        //       mask   = 2ec0d8356a
        let (_, ss) = derive_initial_secrets(&DCID);
        let dk = derive_dir_keys(AeadAlg::Aes128Gcm, &ss);
        let sample = hex("2cd0991cd25b0aac406a5816b6394100");
        let mask = dk.hp.mask(&sample).expect("16-byte sample");
        assert_eq!(mask.as_slice(), hex("2ec0d8356a"));
    }

    // -------- RFC 9001 §A.5 — ChaCha20-Poly1305 short header -----------

    /// Application traffic secret from RFC 9001 §A.5.
    fn a5_secret() -> Vec<u8> {
        hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
    }

    #[test]
    fn rfc9001_a5_key_derivation() {
        // RFC 9001 §A.5 expected outputs:
        //   key = c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8
        //   iv  = e0459b3474bdd0e44a41c144
        //   hp  = 25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4
        //   ku  = 1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9
        let s = a5_secret();
        let dk = derive_dir_keys(AeadAlg::ChaCha20Poly1305, &s);
        assert_eq!(
            dk.key.as_slice(),
            hex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8").as_slice(),
        );
        assert_eq!(dk.iv.as_slice(), hex("e0459b3474bdd0e44a41c144").as_slice());

        // Recompute the hp key independently — the cipher built from it
        // is opaque inside the DirKeys.
        let mut hp_key = [0u8; 32];
        expand_label_dyn(HashAlg::Sha256, &s, b"quic hp", &[], &mut hp_key);
        assert_eq!(
            &hp_key[..],
            hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4").as_slice(),
        );

        let ku = derive_next_application_secret(AeadAlg::ChaCha20Poly1305, &s);
        assert_eq!(
            ku.as_slice(),
            hex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9").as_slice(),
        );
    }

    #[test]
    fn rfc9001_a5_nonce_and_seal() {
        // RFC 9001 §A.5: pn = 654360564, nonce = e0459b3474bdd0e46d417eb0,
        // unprotected header = 4200bff4, plaintext = 01, ciphertext =
        // 655e5cd55c41f69080575d7999c25a5bfb (the 16-byte tag is the
        // trailing 16 bytes of the 17-byte ciphertext+tag sequence).
        let s = a5_secret();
        let dk = derive_dir_keys(AeadAlg::ChaCha20Poly1305, &s);

        let pn: u64 = 654360564;
        let nonce = nonce_for(&dk.iv, pn);
        assert_eq!(nonce.as_slice(), hex("e0459b3474bdd0e46d417eb0").as_slice());

        let header = hex("4200bff4");
        let mut payload = hex("01");
        let tag = aead_seal(&dk, pn, &header, &mut payload);
        // payload now holds the 1-byte ciphertext; concatenated with the
        // 16-byte tag this is the 17-byte sequence
        // `655e5cd55c41f69080575d7999c25a5bfb`.
        let mut got = payload.clone();
        got.extend_from_slice(&tag);
        assert_eq!(
            got.as_slice(),
            hex("655e5cd55c41f69080575d7999c25a5bfb").as_slice(),
        );
    }

    #[test]
    fn rfc9001_a5_header_protection_mask() {
        // RFC 9001 §A.5: sample = 5e5cd55c41f69080575d7999c25a5bfb,
        //                mask   = aefefe7d03.
        let s = a5_secret();
        let dk = derive_dir_keys(AeadAlg::ChaCha20Poly1305, &s);
        let sample = hex("5e5cd55c41f69080575d7999c25a5bfb");
        let mask = dk.hp.mask(&sample).expect("16-byte sample");
        assert_eq!(mask.as_slice(), hex("aefefe7d03").as_slice());
    }

    // -------- Unit tests (not from the RFC) ----------------------------

    #[test]
    fn nonce_for_xors_into_lower_8_bytes() {
        // Hand-computed: IV is 12 x 0x11; PN is 0x42; padded PN big-endian
        // = 00 00 00 00 00 00 00 42. XORing into nonce[4..12] flips the
        // last byte from 0x11 to 0x53.
        let nonce = nonce_for(&[0x11; 12], 0x42);
        let mut expected = [0x11u8; 12];
        expected[11] ^= 0x42;
        assert_eq!(nonce, expected);
        // And the first 4 IV bytes are untouched.
        assert_eq!(&nonce[..4], &[0x11, 0x11, 0x11, 0x11]);
    }

    #[test]
    fn nonce_for_full_pn_overlay() {
        // PN = 0x0102030405060708 should land in nonce[4..12] verbatim
        // (the IV is all zero).
        let n = nonce_for(&[0; 12], 0x0102030405060708);
        assert_eq!(
            n,
            [0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn header_protection_wrong_sample_length() {
        // RFC 9001 §5.4.1 fixes the sample at 16 bytes; anything else is
        // a protocol error and should be reported as a decode failure so
        // the packet is dropped.
        let (cs, _) = derive_initial_secrets(&DCID);
        let dk = derive_dir_keys(AeadAlg::Aes128Gcm, &cs);
        assert!(matches!(dk.hp.mask(&[0u8; 15]), Err(Error::Decode)));
        assert!(matches!(dk.hp.mask(&[0u8; 17]), Err(Error::Decode)));
        assert!(matches!(dk.hp.mask(&[]), Err(Error::Decode)));
    }

    /// Phase 8 — RFC 9001 §6.1: each application of
    /// `derive_next_application_secret` yields a fresh secret, and each
    /// secret expands to a distinct (key, iv, hp_key) triple. We chain
    /// S₀ → S₁ → S₂ and assert pairwise inequality on all three
    /// outputs.
    #[test]
    fn crypto_key_update_chain() {
        // Synthetic 32-byte initial secret. Hash output for SHA-256 ⇒
        // each Si is also 32 bytes.
        let s0: alloc::vec::Vec<u8> = (0..32u8).map(|i| i ^ 0x5a).collect();
        let s1 = derive_next_application_secret(AeadAlg::Aes128Gcm, &s0);
        let s2 = derive_next_application_secret(AeadAlg::Aes128Gcm, &s1);

        assert_ne!(s0, s1, "S0 vs S1 must differ");
        assert_ne!(s1, s2, "S1 vs S2 must differ");
        assert_ne!(s0, s2, "S0 vs S2 must differ");
        assert_eq!(s0.len(), s1.len());
        assert_eq!(s1.len(), s2.len());

        let dk0 = derive_dir_keys(AeadAlg::Aes128Gcm, &s0);
        let dk1 = derive_dir_keys(AeadAlg::Aes128Gcm, &s1);
        let dk2 = derive_dir_keys(AeadAlg::Aes128Gcm, &s2);

        // Pairwise: keys distinct, IVs distinct.
        assert_ne!(dk0.key, dk1.key);
        assert_ne!(dk1.key, dk2.key);
        assert_ne!(dk0.key, dk2.key);
        assert_ne!(dk0.iv, dk1.iv);
        assert_ne!(dk1.iv, dk2.iv);
        assert_ne!(dk0.iv, dk2.iv);

        // hp keys are stored only inside HeaderProt. Re-derive
        // independently for comparison.
        let mut hp0 = [0u8; 16];
        let mut hp1 = [0u8; 16];
        let mut hp2 = [0u8; 16];
        expand_label_dyn(HashAlg::Sha256, &s0, b"quic hp", &[], &mut hp0);
        expand_label_dyn(HashAlg::Sha256, &s1, b"quic hp", &[], &mut hp1);
        expand_label_dyn(HashAlg::Sha256, &s2, b"quic hp", &[], &mut hp2);
        assert_ne!(hp0, hp1);
        assert_ne!(hp1, hp2);
        assert_ne!(hp0, hp2);
    }

    #[test]
    fn level_keys_phase_lookup_falls_back_to_legacy() {
        let dk = derive_dir_keys(AeadAlg::Aes128Gcm, &alloc::vec![0u8; 32]);
        // Legacy fields populated, phase table empty: phase lookup
        // falls back.
        let lk = LevelKeys {
            tx: Some(DirKeys {
                alg: dk.alg,
                key: dk.key.clone(),
                iv: dk.iv,
                hp: match dk.alg {
                    AeadAlg::Aes128Gcm => {
                        HeaderProt::Aes128(Aes128::new(dk.key[..16].try_into().unwrap()))
                    }
                    _ => unreachable!(),
                },
                secret: dk.secret.clone(),
            }),
            rx: None,
            tx_by_phase: [None, None],
            rx_by_phase: [None, None],
            prev_rx_keys: None,
            tx_phase_pending_confirm: false,
            tx_hp_key_bytes: Vec::new(),
            rx_hp_key_bytes: Vec::new(),
            tx_packets: 0,
            rx_aead_failures: 0,
            usage_limit_override: None,
            integrity_limit_override: None,
            rx_pn_window: PnReplayWindow::new(),
        };
        assert!(lk.tx_for_phase(0).is_some());
        assert!(lk.tx_for_phase(1).is_some());
        assert!(lk.rx_for_phase(0).is_none());
    }

    #[test]
    fn aead_open_round_trips_seal() {
        // Symmetric round-trip on a synthetic header + payload using each
        // suite. Demonstrates that `aead_open` accepts the tag produced
        // by `aead_seal` and rejects a flipped tag.
        for &alg in &[
            AeadAlg::Aes128Gcm,
            AeadAlg::Aes256Gcm,
            AeadAlg::ChaCha20Poly1305,
        ] {
            let secret =
                alloc::vec![0x55u8; if matches!(alg, AeadAlg::Aes256Gcm) { 48 } else { 32 }];
            let dk = derive_dir_keys(alg, &secret);
            let aad = [0xc3, 0x00, 0x01];
            let original: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

            let mut buf = original;
            let tag = aead_seal(&dk, 7, &aad, &mut buf);
            // Ciphertext must differ from plaintext.
            assert_ne!(buf, original);
            aead_open(&dk, 7, &aad, &mut buf, &tag).expect("decrypt ok");
            assert_eq!(buf, original);

            // Flipped tag must fail.
            let mut bad_tag = tag;
            bad_tag[0] ^= 0x01;
            let mut buf2 = original;
            let _ = aead_seal(&dk, 7, &aad, &mut buf2);
            assert!(aead_open(&dk, 7, &aad, &mut buf2, &bad_tag).is_err());
        }
    }

    // QUIC-1 — RFC 9001 §B per-key AEAD limits.
    #[test]
    fn aead_alg_usage_limits_match_rfc_9001_appendix_b1() {
        assert_eq!(AeadAlg::Aes128Gcm.usage_limit(), 1u64 << 23);
        assert_eq!(AeadAlg::Aes256Gcm.usage_limit(), 1u64 << 23);
        assert_eq!(AeadAlg::ChaCha20Poly1305.usage_limit(), 1u64 << 62);
    }

    #[test]
    fn aead_alg_integrity_limits_match_rfc_9001_appendix_b2() {
        assert_eq!(AeadAlg::Aes128Gcm.integrity_limit(), 1u64 << 52);
        assert_eq!(AeadAlg::Aes256Gcm.integrity_limit(), 1u64 << 52);
        assert_eq!(AeadAlg::ChaCha20Poly1305.integrity_limit(), 1u64 << 36);
    }

    #[test]
    fn level_keys_effective_limit_falls_back_when_no_keys() {
        // No tx/rx installed → effective limit should fall back to
        // u64::MAX (i.e. unreachable), not 0.
        let lk = LevelKeys::empty();
        assert_eq!(lk.effective_usage_limit(), u64::MAX);
        assert_eq!(lk.effective_integrity_limit(), u64::MAX);
    }

    #[test]
    fn level_keys_effective_limit_uses_override_when_set() {
        let mut lk = LevelKeys::empty();
        lk.usage_limit_override = Some(7);
        lk.integrity_limit_override = Some(11);
        assert_eq!(lk.effective_usage_limit(), 7);
        assert_eq!(lk.effective_integrity_limit(), 11);
    }

    // QUIC-2 — RFC 9001 §9.5 per-key PN replay window.
    #[test]
    fn pn_replay_window_accepts_fresh_pns() {
        let mut w = PnReplayWindow::new();
        // Empty window: anything is fresh.
        assert!(w.is_fresh(0));
        assert!(w.is_fresh(42));
        assert!(w.is_fresh(u64::MAX));
        // Record 5.
        w.record(5);
        // 5 must now be considered a duplicate.
        assert!(!w.is_fresh(5));
        // Higher PNs are fresh.
        assert!(w.is_fresh(6));
        assert!(w.is_fresh(100));
        // PNs *just below* the anchor (within window) are fresh until
        // recorded, but they're below the bit-0 anchor — they should
        // be accepted as fresh-by-window if their bit is unset.
        assert!(w.is_fresh(4));
    }

    #[test]
    fn pn_replay_window_rejects_duplicates() {
        let mut w = PnReplayWindow::new();
        w.record(10);
        w.record(20);
        w.record(15);
        // All recorded PNs must now be considered duplicates.
        assert!(!w.is_fresh(10));
        assert!(!w.is_fresh(15));
        assert!(!w.is_fresh(20));
        // Unrecorded ones in the window remain fresh.
        assert!(w.is_fresh(11));
        assert!(w.is_fresh(16));
        assert!(w.is_fresh(21));
    }

    #[test]
    fn pn_replay_window_rejects_below_window() {
        let mut w = PnReplayWindow::new();
        w.record(500);
        // 500 - 128 = 372 is the floor; anything ≤ 372 is below the
        // 128-bit window and must be rejected as un-provable.
        assert!(!w.is_fresh(372));
        assert!(!w.is_fresh(0));
        // 373 sits exactly at the window's bottom and is still fresh
        // (the bit hasn't been set).
        assert!(w.is_fresh(373));
    }

    #[test]
    fn pn_replay_window_slides_up_on_higher_pn() {
        let mut w = PnReplayWindow::new();
        w.record(10);
        w.record(1000);
        // Old PN 10 is now far below the window — must be rejected.
        assert!(!w.is_fresh(10));
        // 1000 was just recorded.
        assert!(!w.is_fresh(1000));
        // Window now spans 873..=1000.
        assert!(w.is_fresh(873));
        assert!(!w.is_fresh(872));
    }
}
