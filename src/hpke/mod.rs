//! Hybrid Public Key Encryption (HPKE, RFC 9180).
//!
//! HPKE is a public-key encryption scheme that lifts a Key Encapsulation
//! Mechanism (KEM), a Key Derivation Function (KDF), and an Authenticated
//! Encryption with Associated Data (AEAD) primitive into an end-to-end
//! encryption / decryption API. It is the building block used by
//! Encrypted Client Hello (draft-ietf-tls-esni), Oblivious HTTP
//! (RFC 9458), and the Messaging Layer Security (MLS, RFC 9420) group key
//! handshake.
//!
//! # Cipher suites
//!
//! A suite is the triple `(kem_id, kdf_id, aead_id)`. All combinations of
//! the supported primitives are wired:
//!
//! | KEMs                       | KDFs              | AEADs                   |
//! |----------------------------|-------------------|-------------------------|
//! | DHKEM(P-256, HKDF-SHA-256) | HKDF-SHA-256      | AES-128-GCM             |
//! | DHKEM(P-384, HKDF-SHA-384) | HKDF-SHA-384      | AES-256-GCM             |
//! | DHKEM(P-521, HKDF-SHA-512) | HKDF-SHA-512      | ChaCha20-Poly1305       |
//! | DHKEM(X25519, HKDF-SHA-256)|                   | ExportOnly              |
//!
//! All four operation modes are implemented: Base, PSK, Auth, AuthPSK.
//!
//! # API
//!
//! The single-shot [`seal`] / [`open`] entry points cover the common
//! "encrypt one message" cases for each mode. For multiple messages on
//! the same `(KEM share, info)` pair, drive the stateful
//! [`SenderContext`] / [`ReceiverContext`] returned by
//! [`setup_sender`] / [`setup_receiver`] directly.
//!
//! # No foreign code
//!
//! The implementation is built entirely on existing in-crate primitives:
//! [`crate::kdf`] for HKDF, [`crate::ec`] for the four DH groups, and
//! [`crate::cipher`] for the AEADs. No new cryptographic code lives
//! under this module — only HPKE-specific framing, labels, and a key
//! schedule.

#![allow(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

mod aead;
mod kdf;
mod kem;
mod labeled;
mod schedule;
mod suite;

#[cfg(test)]
mod tests;

pub use aead::HpkeAead;
pub use kdf::HpkeKdf;
pub use kem::HpkeKem;
pub use schedule::Mode;
pub use suite::CipherSuite;

/// Errors produced by the HPKE state machine.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A KEM public or private key was the wrong length, malformed, or
    /// rejected by curve validation.
    InvalidKey,
    /// The Diffie-Hellman output was the all-zero / low-order share. Per
    /// RFC 9180 §7.1.3, the receiver rejects.
    InvalidDhOutput,
    /// `DeriveKeyPair` did not produce a valid scalar within 256 tries
    /// (NIST curves; X25519 always succeeds on the first try).
    DeriveKeyPair,
    /// An AEAD seal/open failed (open: tag mismatch).
    AeadError,
    /// The Context sequence counter overflowed the per-suite limit
    /// (`2^(8·Nn) − 1` invocations). Open a fresh setup_* to continue.
    MessageLimitReached,
    /// The selected suite identifies the `ExportOnly` AEAD; `seal` /
    /// `open` are unsupported. Use [`SenderContext::export`] /
    /// [`ReceiverContext::export`] instead.
    ExportOnly,
    /// `enc` (encapsulated key) did not have the length the KEM
    /// expects.
    InvalidEnc,
    /// `psk` / `psk_id` violated the joint emptiness / non-emptiness
    /// invariant (RFC 9180 §5.1.1).
    PskInputsInconsistent,
    /// An `Export` request asked for more bytes than the KDF can produce
    /// (`255·Nh`, capped at `u16::MAX`). RFC 9180 §5.3 requires a clean
    /// failure rather than a panic in the HKDF-Expand layer.
    ExportLengthExceeded,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidKey => f.write_str("invalid HPKE key"),
            Error::InvalidDhOutput => f.write_str("DH output was zero / low-order"),
            Error::DeriveKeyPair => f.write_str("DeriveKeyPair exhausted 256 tries"),
            Error::AeadError => f.write_str("HPKE AEAD seal/open failed"),
            Error::MessageLimitReached => f.write_str("HPKE per-suite message limit reached"),
            Error::ExportOnly => f.write_str("HPKE suite is export-only"),
            Error::InvalidEnc => f.write_str("HPKE encapsulated key has wrong length"),
            Error::PskInputsInconsistent => f.write_str("HPKE psk / psk_id inputs inconsistent"),
            Error::ExportLengthExceeded => f.write_str("HPKE export length exceeds KDF maximum"),
        }
    }
}

impl core::error::Error for Error {}

pub use schedule::{ReceiverContext, SenderContext};

/// Best-effort wipe of a secret buffer: overwrite with zeros, then fence
/// with `core::hint::black_box` so the writes are not elided as dead
/// stores. Same pattern the rest of the crate uses for secret
/// intermediates.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(buf);
}

/// `SetupBaseS`: derive a [`SenderContext`] for the given recipient
/// public key and info string. Returns the encapsulated KEM share
/// `enc` together with the sender state.
pub fn setup_sender<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
) -> Result<(Vec<u8>, SenderContext), Error> {
    let (mut shared_secret, enc) = suite.kem.encap(rng, pk_r)?;
    let ctx = SenderContext::new(suite, Mode::Base, &shared_secret, info, &[], &[]);
    wipe(&mut shared_secret);
    Ok((enc, ctx?))
}

/// `SetupBaseR`: derive a [`ReceiverContext`] from the encapsulated
/// KEM share `enc` and recipient private key.
pub fn setup_receiver(
    suite: CipherSuite,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
) -> Result<ReceiverContext, Error> {
    let mut shared_secret = suite.kem.decap(enc, sk_r)?;
    let ctx = ReceiverContext::new(suite, Mode::Base, &shared_secret, info, &[], &[]);
    wipe(&mut shared_secret);
    ctx
}

/// `SetupPSKS`: like [`setup_sender`] but binds a pre-shared key.
pub fn setup_sender_psk<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<(Vec<u8>, SenderContext), Error> {
    let (mut shared_secret, enc) = suite.kem.encap(rng, pk_r)?;
    let ctx = SenderContext::new(suite, Mode::Psk, &shared_secret, info, psk, psk_id);
    wipe(&mut shared_secret);
    Ok((enc, ctx?))
}

/// `SetupPSKR`.
pub fn setup_receiver_psk(
    suite: CipherSuite,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<ReceiverContext, Error> {
    let mut shared_secret = suite.kem.decap(enc, sk_r)?;
    let ctx = ReceiverContext::new(suite, Mode::Psk, &shared_secret, info, psk, psk_id);
    wipe(&mut shared_secret);
    ctx
}

/// `SetupAuthS`: like [`setup_sender`] but binds the sender's static
/// identity via `AuthEncap` for sender authentication.
pub fn setup_sender_auth<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
    sk_s: &[u8],
) -> Result<(Vec<u8>, SenderContext), Error> {
    let (mut shared_secret, enc) = suite.kem.auth_encap(rng, pk_r, sk_s)?;
    let ctx = SenderContext::new(suite, Mode::Auth, &shared_secret, info, &[], &[]);
    wipe(&mut shared_secret);
    Ok((enc, ctx?))
}

/// `SetupAuthR`.
pub fn setup_receiver_auth(
    suite: CipherSuite,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    pk_s: &[u8],
) -> Result<ReceiverContext, Error> {
    let mut shared_secret = suite.kem.auth_decap(enc, sk_r, pk_s)?;
    let ctx = ReceiverContext::new(suite, Mode::Auth, &shared_secret, info, &[], &[]);
    wipe(&mut shared_secret);
    ctx
}

/// `SetupAuthPSKS`.
#[allow(clippy::too_many_arguments)]
pub fn setup_sender_auth_psk<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    sk_s: &[u8],
) -> Result<(Vec<u8>, SenderContext), Error> {
    let (mut shared_secret, enc) = suite.kem.auth_encap(rng, pk_r, sk_s)?;
    let ctx = SenderContext::new(suite, Mode::AuthPsk, &shared_secret, info, psk, psk_id);
    wipe(&mut shared_secret);
    Ok((enc, ctx?))
}

/// `SetupAuthPSKR`.
#[allow(clippy::too_many_arguments)]
pub fn setup_receiver_auth_psk(
    suite: CipherSuite,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    pk_s: &[u8],
) -> Result<ReceiverContext, Error> {
    let mut shared_secret = suite.kem.auth_decap(enc, sk_r, pk_s)?;
    let ctx = ReceiverContext::new(suite, Mode::AuthPsk, &shared_secret, info, psk, psk_id);
    wipe(&mut shared_secret);
    ctx
}

/// Single-shot `SealBase` (RFC 9180 §6.1): encapsulate, seal one
/// message, throw the context away. Returns `(enc, ciphertext)`.
pub fn seal<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (enc, mut ctx) = setup_sender(rng, suite, pk_r, info)?;
    let ct = ctx.seal(aad, pt)?;
    Ok((enc, ct))
}

/// Single-shot `OpenBase` (RFC 9180 §6.1): decapsulate, open one
/// message.
pub fn open(
    suite: CipherSuite,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut ctx = setup_receiver(suite, enc, sk_r, info)?;
    ctx.open(aad, ct)
}
