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
//! # `alloc`
//!
//! The module builds without an allocator. Every setup, `Seal`, `Open` and
//! `Export` operation has an `_into` form that writes into caller-supplied
//! buffers and returns the byte count: [`setup_sender_into`],
//! [`SenderContext::seal_into`], [`ReceiverContext::open_into`],
//! [`SenderContext::export_into`], [`HpkeKem::generate_key_pair_into`], and so
//! on. Caller buffers rather than fixed-size returns because
//! [`CipherSuite`] is a *runtime* value: `Nenc`, `Nk` and `Nh` are only known
//! once a suite is picked. Size them from the suite's `const fn`s
//! ([`HpkeKem::n_enc`], [`HpkeAead::tag_len`], …), or from the
//! [`HpkeKem::MAX_N_ENC`] / [`HpkeKdf::MAX_OUTPUT`] upper bounds.
//!
//! With `alloc` on, every `_into` entry point also has a `Vec`-returning
//! convenience twin ([`seal`], [`SenderContext::seal`], …).
//!
//! Two KEM variants need a heap: `DHKEM(P-384, …)` and `DHKEM(P-521, …)` run
//! on the crate's heap-backed multi-curve arithmetic, so
//! [`HpkeKem::DhkemP384HkdfSha384`] and [`HpkeKem::DhkemP521HkdfSha512`] only
//! exist under `alloc`. P-256 and X25519 — and every KDF, AEAD and mode —
//! are available without one.
//!
//! # No foreign code
//!
//! The implementation is built entirely on existing in-crate primitives:
//! [`crate::kdf`] for HKDF, [`crate::ec`] for the four DH groups, and
//! [`crate::cipher`] for the AEADs. No new cryptographic code lives
//! under this module — only HPKE-specific framing, labels, and a key
//! schedule.

#![allow(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

mod aead;
mod kdf;
mod kem;
mod labeled;
mod schedule;
mod suite;

// The vector suite exercises every wired suite, including the two
// `alloc`-only KEMs, and builds its expected values into `Vec`s; the
// allocation-free build is covered by the `_into` tests inside it plus the
// bare-metal link job.
#[cfg(all(test, feature = "alloc"))]
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
    /// The PSK is shorter than 32 bytes in a PSK / AuthPSK mode.
    /// RFC 9180 §9.5 requires the PSK to carry at least 32 bytes of
    /// entropy so it cannot be brute-forced offline; length is the
    /// enforceable proxy for that requirement.
    PskTooShort,
    /// A caller-supplied output buffer was too small for the value the
    /// operation produces. Size it from the suite's `const fn`s — `Nenc`
    /// for an encapsulated share, `pt.len() + Nt` for a ciphertext,
    /// `ct.len() - Nt` for a plaintext.
    BufferTooSmall,
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
            Error::PskTooShort => f.write_str("HPKE psk must be at least 32 bytes"),
            Error::ExportLengthExceeded => f.write_str("HPKE export length exceeds KDF maximum"),
            Error::BufferTooSmall => f.write_str("HPKE output buffer too small"),
        }
    }
}

impl core::error::Error for Error {}

pub use schedule::{ReceiverContext, SenderContext};

/// Best-effort wipe of a secret buffer, through the crate's
/// [`zeroize`](crate::zeroize) helpers: volatile stores plus a compiler
/// fence, so the writes cannot be elided as dead stores.
fn wipe(buf: &mut [u8]) {
    crate::zeroize::Zeroize::zeroize(buf);
}

/// Scratch buffer for a KEM shared secret (`Nsecret` ≤ `Nh` ≤ 64 bytes),
/// wiped on drop so the secret never outlives the setup call that derived it.
struct SharedSecret([u8; HpkeKdf::MAX_OUTPUT]);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl crate::zeroize::ZeroizeOnDrop for SharedSecret {}

/// Runs one of the `Encap` family into a stack-held shared secret and turns it
/// into a sender context, so the KEM secret never crosses the public API.
///
/// `enc_out` receives the encapsulated share; the returned length is `Nenc`.
#[allow(clippy::too_many_arguments)]
fn setup_sender_common<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    mode: Mode,
    pk_r: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    sk_s: Option<&[u8]>,
    enc_out: &mut [u8],
) -> Result<(usize, SenderContext), Error> {
    let n_secret = suite.kem.n_secret();
    let mut shared = SharedSecret([0u8; HpkeKdf::MAX_OUTPUT]);
    let n_enc = match sk_s {
        Some(sk_s) => {
            suite
                .kem
                .auth_encap_into(rng, pk_r, sk_s, &mut shared.0[..n_secret], enc_out)?
        }
        None => suite
            .kem
            .encap_into(rng, pk_r, &mut shared.0[..n_secret], enc_out)?,
    };
    let ctx = SenderContext::new(suite, mode, &shared.0[..n_secret], info, psk, psk_id)?;
    Ok((n_enc, ctx))
}

/// The `Decap` counterpart of [`setup_sender_common`].
#[allow(clippy::too_many_arguments)]
fn setup_receiver_common(
    suite: CipherSuite,
    mode: Mode,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    pk_s: Option<&[u8]>,
) -> Result<ReceiverContext, Error> {
    let n_secret = suite.kem.n_secret();
    let mut shared = SharedSecret([0u8; HpkeKdf::MAX_OUTPUT]);
    match pk_s {
        Some(pk_s) => suite
            .kem
            .auth_decap_into(enc, sk_r, pk_s, &mut shared.0[..n_secret])?,
        None => suite.kem.decap_into(enc, sk_r, &mut shared.0[..n_secret])?,
    }
    ReceiverContext::new(suite, mode, &shared.0[..n_secret], info, psk, psk_id)
}

/// `SetupBaseS`: derive a [`SenderContext`] for the given recipient
/// public key and info string, writing the encapsulated KEM share into
/// `enc_out` and returning its length (`suite.kem.n_enc()`).
///
/// `enc_out` must hold at least [`HpkeKem::n_enc`] bytes; a shorter buffer
/// yields [`Error::BufferTooSmall`].
pub fn setup_sender_into<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
    enc_out: &mut [u8],
) -> Result<(usize, SenderContext), Error> {
    setup_sender_common(rng, suite, Mode::Base, pk_r, info, &[], &[], None, enc_out)
}

/// `SetupBaseS`, returning a freshly allocated `enc`.
///
/// Convenience wrapper over [`setup_sender_into`].
#[cfg(feature = "alloc")]
pub fn setup_sender<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
) -> Result<(Vec<u8>, SenderContext), Error> {
    let mut enc = alloc::vec![0u8; suite.kem.n_enc()];
    let (n, ctx) = setup_sender_into(rng, suite, pk_r, info, &mut enc)?;
    enc.truncate(n);
    Ok((enc, ctx))
}

/// `SetupBaseR`: derive a [`ReceiverContext`] from the encapsulated
/// KEM share `enc` and recipient private key.
pub fn setup_receiver(
    suite: CipherSuite,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
) -> Result<ReceiverContext, Error> {
    setup_receiver_common(suite, Mode::Base, enc, sk_r, info, &[], &[], None)
}

/// `SetupPSKS`: like [`setup_sender_into`] but binds a pre-shared key.
#[allow(clippy::too_many_arguments)]
pub fn setup_sender_psk_into<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    enc_out: &mut [u8],
) -> Result<(usize, SenderContext), Error> {
    setup_sender_common(
        rng,
        suite,
        Mode::Psk,
        pk_r,
        info,
        psk,
        psk_id,
        None,
        enc_out,
    )
}

/// `SetupPSKS`, returning a freshly allocated `enc`.
#[cfg(feature = "alloc")]
pub fn setup_sender_psk<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<(Vec<u8>, SenderContext), Error> {
    let mut enc = alloc::vec![0u8; suite.kem.n_enc()];
    let (n, ctx) = setup_sender_psk_into(rng, suite, pk_r, info, psk, psk_id, &mut enc)?;
    enc.truncate(n);
    Ok((enc, ctx))
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
    setup_receiver_common(suite, Mode::Psk, enc, sk_r, info, psk, psk_id, None)
}

/// `SetupAuthS`: like [`setup_sender_into`] but binds the sender's static
/// identity via `AuthEncap` for sender authentication.
pub fn setup_sender_auth_into<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
    sk_s: &[u8],
    enc_out: &mut [u8],
) -> Result<(usize, SenderContext), Error> {
    setup_sender_common(
        rng,
        suite,
        Mode::Auth,
        pk_r,
        info,
        &[],
        &[],
        Some(sk_s),
        enc_out,
    )
}

/// `SetupAuthS`, returning a freshly allocated `enc`.
#[cfg(feature = "alloc")]
pub fn setup_sender_auth<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
    sk_s: &[u8],
) -> Result<(Vec<u8>, SenderContext), Error> {
    let mut enc = alloc::vec![0u8; suite.kem.n_enc()];
    let (n, ctx) = setup_sender_auth_into(rng, suite, pk_r, info, sk_s, &mut enc)?;
    enc.truncate(n);
    Ok((enc, ctx))
}

/// `SetupAuthR`.
pub fn setup_receiver_auth(
    suite: CipherSuite,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    pk_s: &[u8],
) -> Result<ReceiverContext, Error> {
    setup_receiver_common(suite, Mode::Auth, enc, sk_r, info, &[], &[], Some(pk_s))
}

/// `SetupAuthPSKS`.
#[allow(clippy::too_many_arguments)]
pub fn setup_sender_auth_psk_into<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    sk_s: &[u8],
    enc_out: &mut [u8],
) -> Result<(usize, SenderContext), Error> {
    setup_sender_common(
        rng,
        suite,
        Mode::AuthPsk,
        pk_r,
        info,
        psk,
        psk_id,
        Some(sk_s),
        enc_out,
    )
}

/// `SetupAuthPSKS`, returning a freshly allocated `enc`.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "alloc")]
pub fn setup_sender_auth_psk<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    sk_s: &[u8],
) -> Result<(Vec<u8>, SenderContext), Error> {
    let mut enc = alloc::vec![0u8; suite.kem.n_enc()];
    let (n, ctx) = setup_sender_auth_psk_into(rng, suite, pk_r, info, psk, psk_id, sk_s, &mut enc)?;
    enc.truncate(n);
    Ok((enc, ctx))
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
    setup_receiver_common(
        suite,
        Mode::AuthPsk,
        enc,
        sk_r,
        info,
        psk,
        psk_id,
        Some(pk_s),
    )
}

/// Single-shot `SealBase` (RFC 9180 §6.1): encapsulate, seal one
/// message, throw the context away. Writes `enc` into `enc_out` and
/// `ciphertext || tag` into `ct_out`, returning `(Nenc, pt.len() + Nt)`.
#[allow(clippy::too_many_arguments)]
pub fn seal_into<R: crate::rng::RngCore>(
    rng: &mut R,
    suite: CipherSuite,
    pk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
    enc_out: &mut [u8],
    ct_out: &mut [u8],
) -> Result<(usize, usize), Error> {
    let (n_enc, mut ctx) = setup_sender_into(rng, suite, pk_r, info, enc_out)?;
    let n_ct = ctx.seal_into(aad, pt, ct_out)?;
    Ok((n_enc, n_ct))
}

/// Single-shot `SealBase`, returning freshly allocated `(enc, ciphertext)`.
///
/// Convenience wrapper over [`seal_into`].
#[cfg(feature = "alloc")]
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

/// Single-shot `OpenBase` (RFC 9180 §6.1): decapsulate, open one message
/// into `out`, returning the plaintext length (`ct.len() - Nt`).
#[allow(clippy::too_many_arguments)]
pub fn open_into(
    suite: CipherSuite,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut ctx = setup_receiver(suite, enc, sk_r, info)?;
    ctx.open_into(aad, ct, out)
}

/// Single-shot `OpenBase`, returning a freshly allocated plaintext.
///
/// Convenience wrapper over [`open_into`].
#[cfg(feature = "alloc")]
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
