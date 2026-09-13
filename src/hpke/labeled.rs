//! HPKE labeled HKDF wrappers (RFC 9180 §4.0).
//!
//! Both `LabeledExtract` and `LabeledExpand` prefix HKDF inputs with the
//! version tag `"HPKE-v1"` followed by a per-suite identifier. This keeps
//! every HKDF call domain-separated from every other use of HKDF that
//! may happen on the same `ikm` byte string.
//!
//! Neither wrapper concatenates anything: HMAC is streaming, so the
//! `"HPKE-v1" ‖ suite_id ‖ label ‖ ikm` (resp.
//! `I2OSP(L, 2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info`) prefix chain is fed to
//! the KDF as a sequence of parts. That removes the only variable-length
//! buffers in the labeled layer, so it needs no allocator.

use super::HpkeKdf;
use crate::zeroize::Zeroize;

/// HPKE version tag (RFC 9180 §4.0). The string is the same for every
/// suite and every label.
pub(crate) const HPKE_VERSION: &[u8] = b"HPKE-v1";

/// Largest number of `ikm` parts any in-crate `LabeledExtract` call site
/// passes (`AuthEncap` / `AuthDecap` feed `dh1 ‖ dh2`).
const MAX_IKM_PARTS: usize = 2;

/// Largest number of `info` parts any in-crate `LabeledExpand` call site
/// passes (`AuthEncap`'s `kem_context` is `pkE ‖ pkR ‖ pkS`, and the key
/// schedule's context is `mode ‖ psk_id_hash ‖ info_hash`).
const MAX_INFO_PARTS: usize = 3;

/// An `Nh`-byte HPKE pseudorandom key held in a fixed-capacity stack buffer.
///
/// Carrying the length alongside the buffer is what keeps the
/// [`LabeledExpand`](labeled_expand) contract safe: expanding under a PRK
/// slice longer than the KDF's `Nh` is a silent no-op, so call sites must
/// never hand the whole backing array to the expander. [`as_slice`] is the
/// only way to read it, and it always yields exactly `Nh` bytes.
///
/// [`as_slice`]: Prk::as_slice
pub(crate) struct Prk {
    buf: [u8; HpkeKdf::MAX_OUTPUT],
    len: usize,
}

impl Prk {
    /// The PRK bytes: exactly `Nh` of them.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Drop for Prk {
    fn drop(&mut self) {
        // A PRK is as sensitive as the key material it was extracted from.
        self.buf.zeroize();
    }
}

impl crate::zeroize::ZeroizeOnDrop for Prk {}

/// `LabeledExtract(salt, suite_id, label, ikm)`:
///
/// `Extract(salt, concat("HPKE-v1", suite_id, label, ikm))`.
///
/// `ikm` is supplied as a sequence of parts, bound exactly as if they had
/// been concatenated.
///
/// `suite_id` may be either the HPKE suite identifier
/// (`"HPKE" || ...`) or the KEM suite identifier (`"KEM" || ...`).
pub(crate) fn labeled_extract(
    kdf: HpkeKdf,
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    ikm: &[&[u8]],
) -> Prk {
    debug_assert!(ikm.len() <= MAX_IKM_PARTS, "too many LabeledExtract parts");
    let mut parts: [&[u8]; 3 + MAX_IKM_PARTS] = [&[]; 3 + MAX_IKM_PARTS];
    parts[0] = HPKE_VERSION;
    parts[1] = suite_id;
    parts[2] = label;
    let n = 3 + ikm.len().min(MAX_IKM_PARTS);
    parts[3..n].copy_from_slice(&ikm[..n - 3]);
    Prk {
        buf: kdf.extract_parts(salt, &parts[..n]),
        len: kdf.output_len(),
    }
}

/// `LabeledExpand(prk, suite_id, label, info, L)`:
///
/// `Expand(prk, concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info), L)`.
///
/// `info` is supplied as a sequence of parts, bound exactly as if they had
/// been concatenated.
///
/// **`L` is `out.len()`**, and it is bound into the expander's own input — so
/// `out` must be exactly the length the suite calls for, never a longer
/// backing buffer with the tail ignored. Expanding into an over-long `out`
/// silently derives *different* key bytes.
///
/// Returns `false` (leaving `out` untouched) if `prk` is not `Nh` bytes or
/// `out` is longer than HKDF can emit; see [`HpkeKdf::expand_parts`].
pub(crate) fn labeled_expand(
    kdf: HpkeKdf,
    prk: &[u8],
    suite_id: &[u8],
    label: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> bool {
    debug_assert!(info.len() <= MAX_INFO_PARTS, "too many LabeledExpand parts");
    // Bound to a local: an inline temporary would be dropped while still
    // borrowed by `parts` (E0716) under the crate's MSRV.
    let len_be = (out.len() as u16).to_be_bytes();
    let mut parts: [&[u8]; 4 + MAX_INFO_PARTS] = [&[]; 4 + MAX_INFO_PARTS];
    parts[0] = &len_be;
    parts[1] = HPKE_VERSION;
    parts[2] = suite_id;
    parts[3] = label;
    let n = 4 + info.len().min(MAX_INFO_PARTS);
    parts[4..n].copy_from_slice(&info[..n - 4]);
    kdf.expand_parts(prk, &parts[..n], out)
}
