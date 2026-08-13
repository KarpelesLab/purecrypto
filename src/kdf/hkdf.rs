//! HKDF — HMAC-based Extract-and-Expand KDF (RFC 5869).

// This module is declared `mod hkdf;` (private) in `kdf/mod.rs`, which
// re-exports the public entry points individually (`hkdf`, `hkdf_extract`,
// `hkdf_expand`, the fallible `try_hkdf_expand`, and `Error` as `HkdfError`).
use crate::hash::{Digest, Hmac};

/// Error returned by the fallible HKDF entry point [`try_hkdf_expand`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The requested output length exceeds the RFC 5869 maximum of
    /// `255 * HashLen` bytes, which the `L/HashLen` block counter (a single
    /// octet) cannot address.
    OutputTooLong,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::OutputTooLong => f.write_str("HKDF output length exceeds 255 * HashLen"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// HKDF-Extract: derives a pseudorandom key from input keying material `ikm`
/// and an optional `salt`. An empty salt is treated as `HashLen` zero bytes.
pub fn hkdf_extract<D: Digest>(salt: &[u8], ikm: &[u8]) -> D::Output {
    if salt.is_empty() {
        let zeros = D::zeroed_output();
        Hmac::<D>::mac(zeros.as_ref(), ikm)
    } else {
        Hmac::<D>::mac(salt, ikm)
    }
}

/// HKDF-Extract over a *sequence* of `ikm` parts, hashed as if concatenated.
///
/// Extract is `HMAC(salt, ikm)`, and HMAC is streaming, so callers that would
/// otherwise build `concat(a, b, c)` in a heap buffer purely to hash it can feed
/// the parts directly. Used by HPKE's `LabeledExtract`, whose input is
/// `"HPKE-v1" ‖ suite_id ‖ label ‖ ikm` with an arbitrary-length `ikm`.
pub fn hkdf_extract_parts<D: Digest>(salt: &[u8], ikm: &[&[u8]]) -> D::Output {
    // Hoisted rather than inlined into the `if`: a temporary here would be
    // dropped while still borrowed (E0716) under the crate's MSRV.
    let zeros = D::zeroed_output();
    let key: &[u8] = if salt.is_empty() {
        zeros.as_ref()
    } else {
        salt
    };
    let mut mac = Hmac::<D>::new(key);
    for part in ikm {
        mac.update(part);
    }
    mac.finalize()
}

/// HKDF-Expand with the `info` context supplied as a sequence of parts, bound
/// exactly as if they were concatenated. See [`hkdf_extract_parts`].
pub fn try_hkdf_expand_parts<D: Digest>(
    prk: &D::Output,
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), Error> {
    if out.len() > 255 * D::OUTPUT_LEN {
        return Err(Error::OutputTooLong);
    }
    let prf = Hmac::<D>::new(prk.as_ref());
    let mut prev = D::zeroed_output();
    let mut has_prev = false;
    let mut counter: u8 = 1;
    let mut filled = 0;

    while filled < out.len() {
        let mut mac = prf.clone();
        if has_prev {
            mac.update(prev.as_ref());
        }
        for part in info {
            mac.update(part);
        }
        mac.update(&[counter]);
        prev = mac.finalize();
        has_prev = true;

        let block = prev.as_ref();
        let take = (out.len() - filled).min(block.len());
        out[filled..filled + take].copy_from_slice(&block[..take]);
        filled += take;
        counter = counter.wrapping_add(1);
    }
    Ok(())
}

/// HKDF-Expand: expands a pseudorandom key `prk` into output keying material of
/// length `out.len()`, bound to the context `info`.
///
/// # Panics
/// Panics if `out.len() > 255 * HashLen` (the RFC 5869 maximum). Callers that
/// derive the output length from untrusted input should use the fallible
/// [`try_hkdf_expand`] instead.
pub fn hkdf_expand<D: Digest>(prk: &D::Output, info: &[u8], out: &mut [u8]) {
    try_hkdf_expand::<D>(prk, info, out).expect("HKDF output too long (> 255 * HashLen)");
}

/// Fallible HKDF-Expand: like [`hkdf_expand`], but returns
/// [`Error::OutputTooLong`] instead of panicking when
/// `out.len() > 255 * HashLen` (the RFC 5869 maximum). Behaviour is otherwise
/// byte-for-byte identical for valid lengths.
pub fn try_hkdf_expand<D: Digest>(
    prk: &D::Output,
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    if out.len() > 255 * D::OUTPUT_LEN {
        return Err(Error::OutputTooLong);
    }

    // Key the HMAC with `prk` once; each T(i) block clones this keyed state
    // rather than re-deriving the ipad/opad key schedule. `prf` holds
    // key-derived state and is wiped on drop.
    let prf = Hmac::<D>::new(prk.as_ref());

    let mut prev = D::zeroed_output();
    let mut has_prev = false;
    let mut counter: u8 = 1;
    let mut filled = 0;

    while filled < out.len() {
        let mut mac = prf.clone();
        if has_prev {
            mac.update(prev.as_ref());
        }
        mac.update(info);
        mac.update(&[counter]);
        prev = mac.finalize();
        has_prev = true;

        let block = prev.as_ref();
        let take = (out.len() - filled).min(block.len());
        out[filled..filled + take].copy_from_slice(&block[..take]);
        filled += take;
        counter = counter.wrapping_add(1);
    }

    Ok(())
}

/// One-shot HKDF: `Extract` then `Expand` into `out`.
pub fn hkdf<D: Digest>(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let prk = hkdf_extract::<D>(salt, ikm);
    hkdf_expand::<D>(&prk, info, out);
}

#[cfg(test)]
mod parts_tests {
    use super::*;
    use crate::hash::{Sha256, Sha512};

    /// The multi-part forms must be byte-identical to the concatenating ones —
    /// that equivalence is the whole contract, and it is what lets callers drop
    /// a heap buffer that existed only to be hashed.
    #[test]
    fn extract_parts_matches_concatenated() {
        let parts: [&[u8]; 4] = [
            b"HPKE-v1",
            b"KEM\x00\x20",
            b"eae_prk",
            b"shared secret bytes",
        ];
        let joined: alloc::vec::Vec<u8> = parts.concat();
        for salt in [b"".as_slice(), b"salty".as_slice()] {
            let a = hkdf_extract_parts::<Sha256>(salt, &parts);
            let b = hkdf_extract::<Sha256>(salt, &joined);
            assert_eq!(a.as_ref(), b.as_ref(), "sha256 salt={salt:?}");
            let a = hkdf_extract_parts::<Sha512>(salt, &parts);
            let b = hkdf_extract::<Sha512>(salt, &joined);
            assert_eq!(a.as_ref(), b.as_ref(), "sha512 salt={salt:?}");
        }
    }

    #[test]
    fn expand_parts_matches_concatenated() {
        let prk = hkdf_extract::<Sha256>(b"salt", b"ikm");
        let parts: [&[u8]; 3] = [b"\x00\x20", b"HPKE-v1", b"info string"];
        let joined: alloc::vec::Vec<u8> = parts.concat();
        for len in [1usize, 32, 64, 100] {
            let mut a = alloc::vec![0u8; len];
            let mut b = alloc::vec![0u8; len];
            try_hkdf_expand_parts::<Sha256>(&prk, &parts, &mut a).unwrap();
            try_hkdf_expand::<Sha256>(&prk, &joined, &mut b).unwrap();
            assert_eq!(a, b, "len={len}");
        }
    }

    /// An empty part list is the same as an empty input, and empty parts in the
    /// middle are transparent.
    #[test]
    fn empty_parts_are_transparent() {
        let a = hkdf_extract_parts::<Sha256>(b"s", &[b"", b"abc", b"", b"def"]);
        let b = hkdf_extract::<Sha256>(b"s", b"abcdef");
        assert_eq!(a.as_ref(), b.as_ref());
    }

    /// The length guard is shared with the single-slice form.
    #[test]
    fn expand_parts_rejects_over_long_output() {
        let prk = hkdf_extract::<Sha256>(b"", b"");
        let mut out = alloc::vec![0u8; 255 * 32 + 1];
        assert!(try_hkdf_expand_parts::<Sha256>(&prk, &[b"i"], &mut out).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::test_util::from_hex;

    #[test]
    fn rfc5869_case1() {
        let ikm = from_hex::<22>("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = from_hex::<13>("000102030405060708090a0b0c");
        let info = from_hex::<10>("f0f1f2f3f4f5f6f7f8f9");

        let prk = hkdf_extract::<Sha256>(&salt, &ikm);
        assert_eq!(
            prk,
            from_hex::<32>("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );

        let mut okm = [0u8; 42];
        hkdf_expand::<Sha256>(&prk, &info, &mut okm);
        assert_eq!(
            okm,
            from_hex::<42>(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865"
            )
        );
    }

    #[test]
    fn rfc5869_case3_empty_salt_info() {
        let ikm = from_hex::<22>("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let mut okm = [0u8; 42];
        hkdf::<Sha256>(&[], &ikm, &[], &mut okm);
        assert_eq!(
            okm,
            from_hex::<42>(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8"
            )
        );
    }

    #[test]
    fn short_and_zero_length_output() {
        let prk = hkdf_extract::<Sha256>(b"salt", b"ikm");
        let mut one = [0u8; 1];
        hkdf_expand::<Sha256>(&prk, b"", &mut one);
        // Zero-length output is a no-op (and must not panic).
        let mut none = [0u8; 0];
        hkdf_expand::<Sha256>(&prk, b"", &mut none);
    }
}
