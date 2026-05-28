//! HPKE key schedule and stateful sender / receiver contexts
//! (RFC 9180 §5).
//!
//! The four operation modes (Base, PSK, Auth, AuthPSK) all feed into
//! the same KDF chain; only the meaning of `shared_secret` and the
//! PSK inputs differ. The output is `(key, base_nonce, exporter_secret)`
//! — three byte strings used by the per-message AEAD and the export
//! interface respectively.

use super::Error;
use super::aead::HpkeAead;
use super::labeled::{labeled_expand, labeled_extract};
use super::suite::CipherSuite;
use alloc::vec::Vec;

/// HPKE operation mode (RFC 9180 §5.1).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Mode {
    /// `0x00` — Base: only the KEM share authenticates.
    Base,
    /// `0x01` — PSK: a pre-shared symmetric key augments the KEM
    /// share.
    Psk,
    /// `0x02` — Auth: an `AuthEncap` over the sender's static
    /// identity authenticates the share.
    Auth,
    /// `0x03` — AuthPSK: both Auth and PSK.
    AuthPsk,
}

impl Mode {
    /// The on-the-wire byte tag fed into the key schedule context.
    const fn tag(self) -> u8 {
        match self {
            Mode::Base => 0x00,
            Mode::Psk => 0x01,
            Mode::Auth => 0x02,
            Mode::AuthPsk => 0x03,
        }
    }

    /// Whether this mode binds a pre-shared key.
    const fn uses_psk(self) -> bool {
        matches!(self, Mode::Psk | Mode::AuthPsk)
    }
}

/// `VerifyPSKInputs(mode, psk, psk_id)` (RFC 9180 §5.1.1): the PSK and
/// `psk_id` must be jointly empty or jointly non-empty, with the
/// non-empty case selected only by PSK / AuthPSK modes.
fn verify_psk_inputs(mode: Mode, psk: &[u8], psk_id: &[u8]) -> Result<(), Error> {
    let got_psk = !psk.is_empty();
    let got_id = !psk_id.is_empty();
    if got_psk != got_id {
        return Err(Error::PskInputsInconsistent);
    }
    if got_psk != mode.uses_psk() {
        return Err(Error::PskInputsInconsistent);
    }
    Ok(())
}

/// Outputs of [`key_schedule`]: `(key, base_nonce, exporter_secret)`.
type KeyScheduleOutput = (Vec<u8>, Vec<u8>, Vec<u8>);

/// `KeySchedule(mode, shared_secret, info, psk, psk_id)` (RFC 9180
/// §5.1): produces `(key, base_nonce, exporter_secret)`.
fn key_schedule(
    suite: CipherSuite,
    mode: Mode,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<KeyScheduleOutput, Error> {
    verify_psk_inputs(mode, psk, psk_id)?;

    let suite_id = suite.suite_id();
    let kdf = suite.kdf;

    let psk_id_hash = labeled_extract(kdf, b"", &suite_id, b"psk_id_hash", psk_id);
    let info_hash = labeled_extract(kdf, b"", &suite_id, b"info_hash", info);

    let mut key_schedule_context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    key_schedule_context.push(mode.tag());
    key_schedule_context.extend_from_slice(&psk_id_hash);
    key_schedule_context.extend_from_slice(&info_hash);

    let secret = labeled_extract(kdf, shared_secret, &suite_id, b"secret", psk);

    let mut key = alloc::vec![0u8; suite.aead.key_len()];
    if !key.is_empty() {
        labeled_expand(
            kdf,
            &secret,
            &suite_id,
            b"key",
            &key_schedule_context,
            &mut key,
        );
    }
    let mut base_nonce = alloc::vec![0u8; suite.aead.nonce_len()];
    if !base_nonce.is_empty() {
        labeled_expand(
            kdf,
            &secret,
            &suite_id,
            b"base_nonce",
            &key_schedule_context,
            &mut base_nonce,
        );
    }
    let mut exporter_secret = alloc::vec![0u8; kdf.output_len()];
    labeled_expand(
        kdf,
        &secret,
        &suite_id,
        b"exp",
        &key_schedule_context,
        &mut exporter_secret,
    );

    Ok((key, base_nonce, exporter_secret))
}

/// `ComputeNonce(seq)`: XOR of `base_nonce` and the `Nn`-byte big-endian
/// encoding of `seq`.
fn compute_nonce(base_nonce: &[u8], seq: u64) -> Vec<u8> {
    let nn = base_nonce.len();
    let mut nonce = alloc::vec![0u8; nn];
    // I2OSP(seq, Nn): big-endian, right-justified.
    let seq_be = seq.to_be_bytes();
    let copy = nn.min(seq_be.len());
    nonce[nn - copy..].copy_from_slice(&seq_be[seq_be.len() - copy..]);
    for (n, b) in nonce.iter_mut().zip(base_nonce.iter()) {
        *n ^= *b;
    }
    nonce
}

/// HPKE sender context: stateful seal/export bound to the recipient's
/// encapsulated key share and the key schedule output. Created by the
/// `setup_sender_*` family in [`crate::hpke`].
pub struct SenderContext {
    suite: CipherSuite,
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    seq: u64,
    exporter_secret: Vec<u8>,
}

/// HPKE receiver context: stateful open/export complement to
/// [`SenderContext`]. Created by the `setup_receiver_*` family in
/// [`crate::hpke`].
pub struct ReceiverContext {
    suite: CipherSuite,
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    seq: u64,
    exporter_secret: Vec<u8>,
}

impl SenderContext {
    pub(super) fn new(
        suite: CipherSuite,
        mode: Mode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, Error> {
        let (key, base_nonce, exporter_secret) =
            key_schedule(suite, mode, shared_secret, info, psk, psk_id)?;
        Ok(Self {
            suite,
            key,
            base_nonce,
            seq: 0,
            exporter_secret,
        })
    }

    /// `Seal(aad, pt)`: encrypts under the current nonce and increments
    /// the sequence. Returns `ciphertext || tag`.
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, Error> {
        if self.suite.aead.is_export_only() {
            return Err(Error::ExportOnly);
        }
        let nonce = compute_nonce(&self.base_nonce, self.seq);
        let ct = self.suite.aead.seal(&self.key, &nonce, aad, pt)?;
        increment_seq(&mut self.seq, self.suite.aead)?;
        Ok(ct)
    }

    /// `Export(exporter_context, L)` (RFC 9180 §5.3): derives `L` bytes
    /// of secret material from this context's exporter key.
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Vec<u8> {
        export(self.suite, &self.exporter_secret, exporter_context, length)
    }
}

impl ReceiverContext {
    pub(super) fn new(
        suite: CipherSuite,
        mode: Mode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, Error> {
        let (key, base_nonce, exporter_secret) =
            key_schedule(suite, mode, shared_secret, info, psk, psk_id)?;
        Ok(Self {
            suite,
            key,
            base_nonce,
            seq: 0,
            exporter_secret,
        })
    }

    /// `Open(aad, ct)`: verifies the tag, decrypts, and increments the
    /// sequence. Sequence is not incremented when the AEAD rejects.
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, Error> {
        if self.suite.aead.is_export_only() {
            return Err(Error::ExportOnly);
        }
        let nonce = compute_nonce(&self.base_nonce, self.seq);
        let pt = self.suite.aead.open(&self.key, &nonce, aad, ct)?;
        increment_seq(&mut self.seq, self.suite.aead)?;
        Ok(pt)
    }

    /// `Export(exporter_context, L)` — symmetric to
    /// [`SenderContext::export`].
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Vec<u8> {
        export(self.suite, &self.exporter_secret, exporter_context, length)
    }
}

/// Shared `Export` implementation (RFC 9180 §5.3): a single
/// `LabeledExpand` from this context's `exporter_secret`.
fn export(
    suite: CipherSuite,
    exporter_secret: &[u8],
    exporter_context: &[u8],
    length: usize,
) -> Vec<u8> {
    let suite_id = suite.suite_id();
    let mut out = alloc::vec![0u8; length];
    labeled_expand(
        suite.kdf,
        exporter_secret,
        &suite_id,
        b"sec",
        exporter_context,
        &mut out,
    );
    out
}

/// `IncrementSeq()` (RFC 9180 §5.2): bumps `seq`, with overflow at
/// `2^(8·Nn) − 1` mapped to [`Error::MessageLimitReached`].
fn increment_seq(seq: &mut u64, aead: HpkeAead) -> Result<(), Error> {
    if aead.is_export_only() {
        return Ok(());
    }
    let nn = aead.nonce_len();
    // The spec limit is `2^(8·Nn) − 1`. For all wired AEADs Nn = 12,
    // i.e. 2^96 − 1 — far beyond u64::MAX, so the only ceiling we will
    // ever hit is u64::MAX. Smaller Nn (none today) would need an
    // earlier cutoff; keep the computation correct anyway.
    let limit_reached = if (8 * nn) >= 64 {
        *seq == u64::MAX
    } else {
        *seq == (1u64 << (8 * nn)) - 1
    };
    if limit_reached {
        return Err(Error::MessageLimitReached);
    }
    *seq += 1;
    Ok(())
}
