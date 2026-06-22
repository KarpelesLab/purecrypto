//! HPKE KDF dispatcher: runtime selection of HKDF-SHA-{256,384,512}
//! (RFC 9180 §7.2).
//!
//! Wraps [`crate::kdf::hkdf_extract`] / [`crate::kdf::hkdf_expand`] in
//! a small enum so suite-id-driven call sites don't have to be
//! generic over [`crate::hash::Digest`].

use crate::hash::{Digest, Sha256, Sha384, Sha512};
use crate::kdf::{hkdf_expand, hkdf_extract};
use alloc::vec::Vec;

/// HPKE KDF identifiers (RFC 9180 §7.2).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HpkeKdf {
    /// `0x0001` — HKDF-SHA-256.
    HkdfSha256,
    /// `0x0002` — HKDF-SHA-384.
    HkdfSha384,
    /// `0x0003` — HKDF-SHA-512.
    HkdfSha512,
}

impl HpkeKdf {
    /// The IANA-assigned KDF id.
    pub const fn id(self) -> u16 {
        match self {
            HpkeKdf::HkdfSha256 => 0x0001,
            HpkeKdf::HkdfSha384 => 0x0002,
            HpkeKdf::HkdfSha512 => 0x0003,
        }
    }

    /// `Nh`: the underlying hash output length in bytes.
    pub const fn output_len(self) -> usize {
        match self {
            HpkeKdf::HkdfSha256 => Sha256::OUTPUT_LEN,
            HpkeKdf::HkdfSha384 => Sha384::OUTPUT_LEN,
            HpkeKdf::HkdfSha512 => Sha512::OUTPUT_LEN,
        }
    }

    /// HKDF-Extract, returning an `Nh`-byte PRK.
    pub(crate) fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            HpkeKdf::HkdfSha256 => {
                let prk = hkdf_extract::<Sha256>(salt, ikm);
                prk.as_ref().to_vec()
            }
            HpkeKdf::HkdfSha384 => {
                let prk = hkdf_extract::<Sha384>(salt, ikm);
                prk.as_ref().to_vec()
            }
            HpkeKdf::HkdfSha512 => {
                let prk = hkdf_extract::<Sha512>(salt, ikm);
                prk.as_ref().to_vec()
            }
        }
    }

    /// HKDF-Expand into `out`.
    ///
    /// `prk` must be exactly [`output_len`](Self::output_len) bytes and
    /// `out.len()` must not exceed `255 * output_len` (the RFC 5869 maximum).
    /// Both are invariants of the in-crate call sites (PRKs always come from
    /// [`extract`](Self::extract) and lengths are fixed by the suite), so a
    /// violation is a programming error rather than attacker-reachable.
    ///
    /// Returns `false` without touching `out` if either invariant is broken,
    /// rather than panicking on untrusted input; a `debug_assert` flags the
    /// contract violation in debug builds. Callers that need the output ignore
    /// the boolean for valid inputs (where it is always `true`).
    pub(crate) fn expand(self, prk: &[u8], info: &[u8], out: &mut [u8]) -> bool {
        let nh = self.output_len();
        debug_assert_eq!(
            prk.len(),
            nh,
            "HPKE HKDF prk length must equal output_len()"
        );
        debug_assert!(
            out.len() <= 255 * nh,
            "HPKE HKDF output too long (> 255 * HashLen)"
        );
        // Guard both RFC 5869 invariants up front so the panicking
        // `hkdf_expand` below is never reached with out-of-contract lengths.
        if prk.len() != nh || out.len() > 255 * nh {
            return false;
        }
        match self {
            HpkeKdf::HkdfSha256 => {
                let mut p = <Sha256 as Digest>::zeroed_output();
                p.as_mut().copy_from_slice(prk);
                hkdf_expand::<Sha256>(&p, info, out);
            }
            HpkeKdf::HkdfSha384 => {
                let mut p = <Sha384 as Digest>::zeroed_output();
                p.as_mut().copy_from_slice(prk);
                hkdf_expand::<Sha384>(&p, info, out);
            }
            HpkeKdf::HkdfSha512 => {
                let mut p = <Sha512 as Digest>::zeroed_output();
                p.as_mut().copy_from_slice(prk);
                hkdf_expand::<Sha512>(&p, info, out);
            }
        }
        true
    }
}
