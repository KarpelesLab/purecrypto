//! HPKE labeled HKDF wrappers (RFC 9180 §4.0).
//!
//! Both `LabeledExtract` and `LabeledExpand` prefix HKDF inputs with the
//! version tag `"HPKE-v1"` followed by a per-suite identifier. This keeps
//! every HKDF call domain-separated from every other use of HKDF that
//! may happen on the same `ikm` byte string.

use super::HpkeKdf;
use alloc::vec::Vec;

/// HPKE version tag (RFC 9180 §4.0). The string is the same for every
/// suite and every label.
pub(crate) const HPKE_VERSION: &[u8] = b"HPKE-v1";

/// `LabeledExtract(salt, suite_id, label, ikm)`:
///
/// `Extract(salt, concat("HPKE-v1", suite_id, label, ikm))`.
///
/// `suite_id` may be either the HPKE suite identifier
/// (`"HPKE" || ...`) or the KEM suite identifier (`"KEM" || ...`).
pub(crate) fn labeled_extract(
    kdf: HpkeKdf,
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Vec<u8> {
    let mut labeled_ikm =
        Vec::with_capacity(HPKE_VERSION.len() + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(HPKE_VERSION);
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    kdf.extract(salt, &labeled_ikm)
}

/// `LabeledExpand(prk, suite_id, label, info, L)`:
///
/// `Expand(prk, concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info), L)`.
pub(crate) fn labeled_expand(
    kdf: HpkeKdf,
    prk: &[u8],
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) {
    let len = out.len();
    let mut labeled_info =
        Vec::with_capacity(2 + HPKE_VERSION.len() + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(len as u16).to_be_bytes());
    labeled_info.extend_from_slice(HPKE_VERSION);
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    kdf.expand(prk, &labeled_info, out);
}
