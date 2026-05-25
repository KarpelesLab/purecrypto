//! HKDF — HMAC-based Extract-and-Expand KDF (RFC 5869).

use crate::hash::{Digest, Hmac};

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

/// HKDF-Expand: expands a pseudorandom key `prk` into output keying material of
/// length `out.len()`, bound to the context `info`.
///
/// # Panics
/// Panics if `out.len() > 255 * HashLen` (the RFC 5869 maximum).
pub fn hkdf_expand<D: Digest>(prk: &D::Output, info: &[u8], out: &mut [u8]) {
    assert!(
        out.len() <= 255 * D::OUTPUT_LEN,
        "HKDF output too long (> 255 * HashLen)"
    );

    let mut prev = D::zeroed_output();
    let mut has_prev = false;
    let mut counter: u8 = 1;
    let mut filled = 0;

    while filled < out.len() {
        let mut mac = Hmac::<D>::new(prk.as_ref());
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
}

/// One-shot HKDF: `Extract` then `Expand` into `out`.
pub fn hkdf<D: Digest>(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let prk = hkdf_extract::<D>(salt, ikm);
    hkdf_expand::<D>(&prk, info, out);
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
