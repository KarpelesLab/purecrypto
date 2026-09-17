//! `AES_CBC_HMAC_SHA2` content encryption (RFC 7518 §5.2) for JWE — the
//! `A128CBC-HS256` / `A192CBC-HS384` / `A256CBC-HS512` algorithms.
//!
//! A thin adapter over [`crate::cipher::CbcHmacSha2`], which owns the
//! construction (composite key split, PKCS#7, MAC-then-decrypt with a
//! constant-time tag check and padding check). The JWE code works with an
//! [`Enc`] value and a composite key slice, so this module just dispatches
//! to the right alias.

use super::Enc;
use crate::cipher::{A128CbcHs256, A192CbcHs384, A256CbcHs512, AeadError};
use alloc::vec::Vec;

/// Encrypts `plaintext` under composite key `key` (whose length must match
/// `enc`), returning `(ciphertext, tag)`.
///
/// # Panics
/// If `key.len() != enc.key_len()` (the caller derives `key` from `enc`), or
/// on an associated-data length beyond `2^61` bytes.
pub(crate) fn encrypt(
    enc: Enc,
    key: &[u8],
    iv: &[u8; 16],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let r = match enc {
        Enc::A128CbcHs256 => A128CbcHs256::try_new(key).and_then(|c| c.encrypt(iv, aad, plaintext)),
        Enc::A192CbcHs384 => A192CbcHs384::try_new(key).and_then(|c| c.encrypt(iv, aad, plaintext)),
        Enc::A256CbcHs512 => A256CbcHs512::try_new(key).and_then(|c| c.encrypt(iv, aad, plaintext)),
        _ => unreachable!("not a CBC-HMAC variant"),
    };
    r.expect("CEK length matches enc and AAD is below the AL bound")
}

/// Verifies `tag` and decrypts `ciphertext`; `Err(())` on any failure
/// (wrong key length, tag mismatch, bad length or padding — all collapsed).
pub(crate) fn decrypt(
    enc: Enc,
    key: &[u8],
    iv: &[u8; 16],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, ()> {
    let r: Result<Vec<u8>, AeadError> = match enc {
        Enc::A128CbcHs256 => {
            A128CbcHs256::try_new(key).and_then(|c| c.decrypt(iv, aad, ciphertext, tag))
        }
        Enc::A192CbcHs384 => {
            A192CbcHs384::try_new(key).and_then(|c| c.decrypt(iv, aad, ciphertext, tag))
        }
        Enc::A256CbcHs512 => {
            A256CbcHs512::try_new(key).and_then(|c| c.decrypt(iv, aad, ciphertext, tag))
        }
        _ => unreachable!("not a CBC-HMAC variant"),
    };
    r.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7516 Appendix B: AES_128_CBC_HMAC_SHA_256 with the A.3 values.
    #[test]
    fn rfc7516_appendix_b() {
        let key = [
            4u8, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124,
            212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207,
        ];
        let iv = [
            3u8, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101,
        ];
        let aad = b"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
        let pt = b"Live long and prosper.";
        let (ct, tag) = encrypt(Enc::A128CbcHs256, &key, &iv, aad, pt);
        assert_eq!(
            ct,
            [
                40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6, 75, 129, 223,
                127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143, 112, 56, 102
            ]
        );
        assert_eq!(
            tag,
            [
                83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38, 194, 85
            ]
        );
        assert_eq!(
            decrypt(Enc::A128CbcHs256, &key, &iv, aad, &ct, &tag).unwrap(),
            pt
        );
        let mut bad_tag = tag.clone();
        bad_tag[0] ^= 1;
        assert!(decrypt(Enc::A128CbcHs256, &key, &iv, aad, &ct, &bad_tag).is_err());
        assert!(decrypt(Enc::A128CbcHs256, &key, &iv, aad, &ct, &tag[..15]).is_err());
        assert!(decrypt(Enc::A128CbcHs256, &key, &iv, b"x", &ct, &tag).is_err());
    }

    #[test]
    fn all_variants_round_trip() {
        for (enc, klen) in [
            (Enc::A128CbcHs256, 32usize),
            (Enc::A192CbcHs384, 48),
            (Enc::A256CbcHs512, 64),
        ] {
            let key: Vec<u8> = (0..klen as u8).collect();
            let iv = [7u8; 16];
            for len in [0usize, 1, 15, 16, 17, 100] {
                let pt: Vec<u8> = (0..len as u8).collect();
                let (ct, tag) = encrypt(enc, &key, &iv, b"aad", &pt);
                assert_eq!(ct.len(), (len / 16 + 1) * 16);
                assert_eq!(tag.len(), klen / 2);
                assert_eq!(decrypt(enc, &key, &iv, b"aad", &ct, &tag).unwrap(), pt);
            }
        }
    }
}
