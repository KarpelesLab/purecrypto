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
use super::kdf::HpkeKdf;
use super::labeled::{labeled_expand, labeled_extract};
use super::suite::CipherSuite;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// The largest `Nk` across the wired AEADs (AES-256-GCM / ChaCha20-Poly1305).
pub(crate) const MAX_AEAD_KEY: usize = 32;

/// The largest `Nn` across the wired AEADs (12 for all of them).
pub(crate) const MAX_AEAD_NONCE: usize = 12;

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

/// RFC 9180 §9.5: the PSK must carry at least 32 bytes of entropy so it
/// resists offline guessing; a 32-byte length floor is the enforceable
/// proxy (matching BoringSSL / rust-hpke).
const MIN_PSK_LEN: usize = 32;

/// `VerifyPSKInputs(mode, psk, psk_id)` (RFC 9180 §5.1.1): the PSK and
/// `psk_id` must be jointly empty or jointly non-empty, with the
/// non-empty case selected only by PSK / AuthPSK modes. PSK modes
/// additionally require `psk.len() >= 32` (RFC 9180 §9.5).
fn verify_psk_inputs(mode: Mode, psk: &[u8], psk_id: &[u8]) -> Result<(), Error> {
    let got_psk = !psk.is_empty();
    let got_id = !psk_id.is_empty();
    if got_psk != got_id {
        return Err(Error::PskInputsInconsistent);
    }
    if got_psk != mode.uses_psk() {
        return Err(Error::PskInputsInconsistent);
    }
    if mode.uses_psk() && psk.len() < MIN_PSK_LEN {
        return Err(Error::PskTooShort);
    }
    Ok(())
}

/// The `KeySchedule` outputs, in fixed-capacity buffers sized by the widest
/// wired AEAD and KDF. Only the leading `Nk` / `Nn` / `Nh` bytes of each are
/// meaningful; the rest stay zero.
///
/// All three are secret, and this struct's `Drop` wipes them — which is what
/// makes the contexts that embed it zeroize-on-drop.
struct ScheduleKeys {
    key: [u8; MAX_AEAD_KEY],
    base_nonce: [u8; MAX_AEAD_NONCE],
    exporter_secret: [u8; HpkeKdf::MAX_OUTPUT],
}

impl ScheduleKeys {
    const fn zeroed() -> Self {
        Self {
            key: [0u8; MAX_AEAD_KEY],
            base_nonce: [0u8; MAX_AEAD_NONCE],
            exporter_secret: [0u8; HpkeKdf::MAX_OUTPUT],
        }
    }
}

impl Drop for ScheduleKeys {
    fn drop(&mut self) {
        // Best-effort wipe of the key-schedule secrets (the AEAD key, the base
        // nonce, and the exporter secret), with the crate's volatile `zeroize`
        // stores, which the optimizer may not elide.
        super::wipe(&mut self.key);
        super::wipe(&mut self.base_nonce);
        super::wipe(&mut self.exporter_secret);
    }
}

impl crate::zeroize::ZeroizeOnDrop for ScheduleKeys {}

/// `KeySchedule(mode, shared_secret, info, psk, psk_id)` (RFC 9180
/// §5.1): fills `out` in place.
///
/// The outputs are written through `&mut` rather than returned so the caller
/// can build them directly inside the context that owns (and wipes) them —
/// no intermediate copy of the key material.
///
/// Each `LabeledExpand` below targets a slice of exactly the suite's length,
/// never the whole backing array: `L` is bound into the expander's input, so
/// an over-long target would silently derive different keys.
fn key_schedule(
    suite: CipherSuite,
    mode: Mode,
    shared_secret: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    out: &mut ScheduleKeys,
) -> Result<(), Error> {
    verify_psk_inputs(mode, psk, psk_id)?;

    let suite_id = suite.suite_id();
    let kdf = suite.kdf;

    let psk_id_hash = labeled_extract(kdf, b"", &suite_id, b"psk_id_hash", &[psk_id]);
    let info_hash = labeled_extract(kdf, b"", &suite_id, b"info_hash", &[info]);

    // `key_schedule_context = mode || psk_id_hash || info_hash`, fed to the
    // expander as parts rather than concatenated into a buffer.
    let mode_tag = [mode.tag()];
    let ks_context: [&[u8]; 3] = [&mode_tag, psk_id_hash.as_slice(), info_hash.as_slice()];

    // `secret` is the extract-stage PRK all three outputs are expanded from,
    // so it is as sensitive as the key itself; its `Drop` wipes it with the
    // crate's volatile `zeroize` stores, which the optimizer may not elide.
    let secret = labeled_extract(kdf, shared_secret, &suite_id, b"secret", &[psk]);

    let nk = suite.aead.key_len();
    if nk != 0 {
        labeled_expand(
            kdf,
            secret.as_slice(),
            &suite_id,
            b"key",
            &ks_context,
            &mut out.key[..nk],
        );
    }
    let nn = suite.aead.nonce_len();
    if nn != 0 {
        labeled_expand(
            kdf,
            secret.as_slice(),
            &suite_id,
            b"base_nonce",
            &ks_context,
            &mut out.base_nonce[..nn],
        );
    }
    labeled_expand(
        kdf,
        secret.as_slice(),
        &suite_id,
        b"exp",
        &ks_context,
        &mut out.exporter_secret[..kdf.output_len()],
    );

    Ok(())
}

/// `ComputeNonce(seq)`: XOR of `base_nonce` and the `Nn`-byte big-endian
/// encoding of `seq`. Only `out[..nn]` is meaningful.
fn compute_nonce(base_nonce: &[u8], seq: u64) -> [u8; MAX_AEAD_NONCE] {
    let nn = base_nonce.len();
    debug_assert!(nn <= MAX_AEAD_NONCE);
    let mut nonce = [0u8; MAX_AEAD_NONCE];
    // I2OSP(seq, Nn): big-endian, right-justified.
    let seq_be = seq.to_be_bytes();
    let copy = nn.min(seq_be.len());
    nonce[nn - copy..nn].copy_from_slice(&seq_be[seq_be.len() - copy..]);
    for (n, b) in nonce[..nn].iter_mut().zip(base_nonce.iter()) {
        *n ^= *b;
    }
    nonce
}

/// HPKE sender context: stateful seal/export bound to the recipient's
/// encapsulated key share and the key schedule output. Created by the
/// `setup_sender_*` family in [`crate::hpke`].
pub struct SenderContext {
    suite: CipherSuite,
    /// The `(key, base_nonce, exporter_secret)` triple; wiped on drop.
    keys: ScheduleKeys,
    seq: u64,
    /// Sticky poison flag: set once the per-suite message limit is reached.
    /// Once set, all further `seal` calls fail without recomputing or using
    /// a nonce, preventing catastrophic AEAD nonce reuse if a caller ignores
    /// the first [`Error::MessageLimitReached`].
    exhausted: bool,
}

/// HPKE receiver context: stateful open/export complement to
/// [`SenderContext`]. Created by the `setup_receiver_*` family in
/// [`crate::hpke`].
pub struct ReceiverContext {
    suite: CipherSuite,
    /// The `(key, base_nonce, exporter_secret)` triple; wiped on drop.
    keys: ScheduleKeys,
    seq: u64,
    /// Sticky poison flag — see [`SenderContext::exhausted`].
    exhausted: bool,
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
        // Built zeroed first so a `key_schedule` failure still drops a context
        // whose `ScheduleKeys` wipes whatever was written.
        let mut this = Self {
            suite,
            keys: ScheduleKeys::zeroed(),
            seq: 0,
            exhausted: false,
        };
        key_schedule(
            suite,
            mode,
            shared_secret,
            info,
            psk,
            psk_id,
            &mut this.keys,
        )?;
        Ok(this)
    }

    /// `Seal(aad, pt)`: encrypts under the current nonce and increments
    /// the sequence, writing `ciphertext || tag` into `out` and returning
    /// its length.
    ///
    /// `out` must hold at least `pt.len() + suite.aead.tag_len()` bytes;
    /// a shorter buffer yields [`Error::BufferTooSmall`] and leaves the
    /// sequence untouched.
    pub fn seal_into(&mut self, aad: &[u8], pt: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.suite.aead.is_export_only() {
            return Err(Error::ExportOnly);
        }
        // Once the message limit has been reached, refuse *without* deriving
        // or using a nonce. This makes the limit sticky so a caller that
        // ignored the first error cannot trigger nonce reuse.
        if self.exhausted {
            return Err(Error::MessageLimitReached);
        }
        let nn = self.suite.aead.nonce_len();
        let nk = self.suite.aead.key_len();
        let nonce = compute_nonce(&self.keys.base_nonce[..nn], self.seq);
        let n = self
            .suite
            .aead
            .seal(&self.keys.key[..nk], &nonce[..nn], aad, pt, out)?;
        if let Err(e) = increment_seq(&mut self.seq, self.suite.aead) {
            self.exhausted = true;
            return Err(e);
        }
        Ok(n)
    }

    /// `Seal(aad, pt)`, returning a freshly allocated `ciphertext || tag`.
    ///
    /// Convenience wrapper over [`seal_into`](Self::seal_into) for callers
    /// that have a heap.
    #[cfg(feature = "alloc")]
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, Error> {
        if self.suite.aead.is_export_only() {
            return Err(Error::ExportOnly);
        }
        let mut out = alloc::vec![0u8; pt.len() + self.suite.aead.tag_len()];
        let n = self.seal_into(aad, pt, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// `Export(exporter_context, L)` (RFC 9180 §5.3): derives `out.len()`
    /// bytes of secret material from this context's exporter key into `out`.
    ///
    /// Returns [`Error::ExportLengthExceeded`] when `out` is larger than the
    /// underlying KDF can produce (`255·Nh`, capped at `u16::MAX`), per
    /// RFC 9180 §5.3, rather than panicking in the HKDF-Expand layer.
    pub fn export_into(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        export_into(
            self.suite,
            &self.keys.exporter_secret,
            exporter_context,
            out,
        )
    }

    /// `Export(exporter_context, L)`, returning a freshly allocated buffer.
    ///
    /// Convenience wrapper over [`export_into`](Self::export_into).
    #[cfg(feature = "alloc")]
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        export(
            self.suite,
            &self.keys.exporter_secret,
            exporter_context,
            length,
        )
    }
}

// `keys` wipes itself on drop (see `ScheduleKeys`), which is the whole of this
// context's secret state.
impl crate::zeroize::ZeroizeOnDrop for SenderContext {}

impl ReceiverContext {
    pub(super) fn new(
        suite: CipherSuite,
        mode: Mode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Self, Error> {
        let mut this = Self {
            suite,
            keys: ScheduleKeys::zeroed(),
            seq: 0,
            exhausted: false,
        };
        key_schedule(
            suite,
            mode,
            shared_secret,
            info,
            psk,
            psk_id,
            &mut this.keys,
        )?;
        Ok(this)
    }

    /// `Open(aad, ct)`: verifies the tag, decrypts into `out`, and increments
    /// the sequence, returning the plaintext length. The sequence is not
    /// incremented when the AEAD rejects.
    ///
    /// `out` must hold at least `ct.len() - suite.aead.tag_len()` bytes; a
    /// shorter buffer yields [`Error::BufferTooSmall`].
    pub fn open_into(&mut self, aad: &[u8], ct: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.suite.aead.is_export_only() {
            return Err(Error::ExportOnly);
        }
        // Sticky limit — symmetric to [`SenderContext::seal_into`].
        if self.exhausted {
            return Err(Error::MessageLimitReached);
        }
        let nn = self.suite.aead.nonce_len();
        let nk = self.suite.aead.key_len();
        let nonce = compute_nonce(&self.keys.base_nonce[..nn], self.seq);
        let n = self
            .suite
            .aead
            .open(&self.keys.key[..nk], &nonce[..nn], aad, ct, out)?;
        if let Err(e) = increment_seq(&mut self.seq, self.suite.aead) {
            self.exhausted = true;
            return Err(e);
        }
        Ok(n)
    }

    /// `Open(aad, ct)`, returning a freshly allocated plaintext.
    ///
    /// Convenience wrapper over [`open_into`](Self::open_into).
    #[cfg(feature = "alloc")]
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, Error> {
        if self.suite.aead.is_export_only() {
            return Err(Error::ExportOnly);
        }
        let tag_len = self.suite.aead.tag_len();
        if ct.len() < tag_len {
            return Err(Error::AeadError);
        }
        let mut out = alloc::vec![0u8; ct.len() - tag_len];
        let n = self.open_into(aad, ct, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// `Export(exporter_context, L)` — symmetric to
    /// [`SenderContext::export_into`].
    pub fn export_into(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        export_into(
            self.suite,
            &self.keys.exporter_secret,
            exporter_context,
            out,
        )
    }

    /// `Export(exporter_context, L)` — symmetric to
    /// [`SenderContext::export`].
    #[cfg(feature = "alloc")]
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        export(
            self.suite,
            &self.keys.exporter_secret,
            exporter_context,
            length,
        )
    }
}

// Symmetric to [`SenderContext`]: `keys` wipes itself on drop.
impl crate::zeroize::ZeroizeOnDrop for ReceiverContext {}

/// Shared `Export` implementation (RFC 9180 §5.3): a single
/// `LabeledExpand` from this context's `exporter_secret`.
///
/// `exporter_secret` is the context's full backing array; only its leading
/// `Nh` bytes are the PRK.
fn export_into(
    suite: CipherSuite,
    exporter_secret: &[u8; HpkeKdf::MAX_OUTPUT],
    exporter_context: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    // HKDF-Expand can emit at most 255·Nh bytes; LabeledExpand additionally
    // encodes L as I2OSP(L, 2), so L must also fit in u16. Reject over-long
    // requests cleanly (RFC 9180 §5.3) instead of letting hkdf_expand panic.
    let nh = suite.kdf.output_len();
    let max = nh.saturating_mul(255).min(u16::MAX as usize);
    if out.len() > max {
        return Err(Error::ExportLengthExceeded);
    }
    let suite_id = suite.suite_id();
    labeled_expand(
        suite.kdf,
        &exporter_secret[..nh],
        &suite_id,
        b"sec",
        &[exporter_context],
        out,
    );
    Ok(())
}

/// Allocating `Export`: see [`export_into`].
#[cfg(feature = "alloc")]
fn export(
    suite: CipherSuite,
    exporter_secret: &[u8; HpkeKdf::MAX_OUTPUT],
    exporter_context: &[u8],
    length: usize,
) -> Result<Vec<u8>, Error> {
    let max = suite
        .kdf
        .output_len()
        .saturating_mul(255)
        .min(u16::MAX as usize);
    if length > max {
        return Err(Error::ExportLengthExceeded);
    }
    let mut out = alloc::vec![0u8; length];
    export_into(suite, exporter_secret, exporter_context, &mut out)?;
    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpke::{HpkeAead, HpkeKdf, HpkeKem};

    fn aes128_suite() -> CipherSuite {
        CipherSuite::new(
            HpkeKem::DhkemX25519HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        )
    }

    fn sender_at(suite: CipherSuite, seq: u64) -> SenderContext {
        SenderContext {
            suite,
            keys: ScheduleKeys::zeroed(),
            seq,
            exhausted: false,
        }
    }

    /// A sender and receiver built from the same `key_schedule` output must
    /// still seal/open correctly after the addition of the wiping `Drop`
    /// impls and the `secret` PRK wipe — i.e. zeroization didn't disturb any
    /// key-schedule output. Both contexts are dropped at the end of this test,
    /// exercising the new `Drop` paths.
    #[test]
    fn paired_contexts_seal_open_roundtrip_after_zeroize() {
        let suite = aes128_suite();
        let shared_secret = [0x42u8; 32];
        let info = b"info";

        let mut sender =
            SenderContext::new(suite, Mode::Base, &shared_secret, info, b"", b"").unwrap();
        let mut receiver =
            ReceiverContext::new(suite, Mode::Base, &shared_secret, info, b"", b"").unwrap();

        let aad = b"aad";
        for i in 0u8..4 {
            let pt = alloc::vec![i; 16 + i as usize];
            let ct = sender.seal(aad, &pt).unwrap();
            assert_eq!(receiver.open(aad, &ct).unwrap(), pt);
        }

        // Exporter interface must agree across the paired contexts.
        assert_eq!(
            sender.export(b"exp-ctx", 32).unwrap(),
            receiver.export(b"exp-ctx", 32).unwrap(),
        );
    }

    /// Once the message limit is hit, the context is poisoned: every
    /// subsequent `seal` fails *without* recomputing/using a nonce, so the
    /// final nonce can never be reused (catastrophic AEAD nonce reuse).
    #[test]
    fn seal_poisons_after_limit_no_nonce_reuse() {
        let suite = aes128_suite();
        let mut ctx = sender_at(suite, u64::MAX);

        // First seal at seq == u64::MAX: increment_seq detects the limit and
        // returns the error; the context is now poisoned.
        let first = ctx.seal(b"aad", b"pt");
        assert_eq!(first, Err(Error::MessageLimitReached));
        assert!(ctx.exhausted, "context must be poisoned after limit");
        // seq must be unchanged at the saturation point.
        assert_eq!(ctx.seq, u64::MAX);

        // A caller that ignored the error and tries again must still fail,
        // again without using a nonce.
        let second = ctx.seal(b"aad", b"pt");
        assert_eq!(second, Err(Error::MessageLimitReached));
        assert_eq!(ctx.seq, u64::MAX);
    }

    /// `Export` rejects over-long lengths (RFC 9180 §5.3) instead of
    /// panicking inside HKDF-Expand.
    #[test]
    fn export_rejects_overlong_length() {
        let suite = aes128_suite();
        let ctx = sender_at(suite, 0);
        let max = suite.kdf.output_len() * 255;

        // At the boundary it succeeds.
        assert!(ctx.export(b"ctx", max).is_ok());
        // One byte over the KDF maximum is rejected cleanly.
        assert_eq!(
            ctx.export(b"ctx", max + 1),
            Err(Error::ExportLengthExceeded)
        );
        // A huge request is also rejected (and never panics).
        assert_eq!(
            ctx.export(b"ctx", usize::MAX),
            Err(Error::ExportLengthExceeded)
        );
    }
}
