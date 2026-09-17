//! `AES_CBC_HMAC_SHA2` authenticated encryption (RFC 7518 §5.2), the JWE
//! `A128CBC-HS256` / `A192CBC-HS384` / `A256CBC-HS512` content encryption
//! algorithms.
//!
//! The composite key `K = MAC_KEY ‖ ENC_KEY` is split in halves; the
//! plaintext is PKCS#7-padded and AES-CBC encrypted under `ENC_KEY`; the tag
//! is the first half of `HMAC(MAC_KEY, A ‖ IV ‖ E ‖ AL)` where `AL` is the
//! bit length of the AAD as a 64-bit big-endian integer. Decryption checks
//! the tag in constant time *before* touching the ciphertext, so a padding
//! error is never observable separately from a MAC error.
//!
//! This is a self-contained implementation local to the JOSE module. A
//! reusable `AesCbcHmacSha2` type is being added to `crate::cipher`
//! separately; once it lands, this file should be reduced to a thin adapter
//! over it (the JWE-facing interface here is [`encrypt`] / [`decrypt`]).

use super::Enc;
use crate::cipher::{Aes128, Aes192, Aes256, BlockCipher, Cbc};
use crate::ct::ConstantTimeEq;
use crate::hash::{Digest, Hmac, Sha256, Sha384, Sha512};
use crate::zeroize::Zeroize;
use alloc::vec::Vec;

fn tag<D: Digest>(mac_key: &[u8], aad: &[u8], iv: &[u8], ct: &[u8], tag_len: usize) -> Vec<u8> {
    let mut h = Hmac::<D>::new(mac_key);
    h.update(aad);
    h.update(iv);
    h.update(ct);
    let al = (aad.len() as u64).wrapping_mul(8).to_be_bytes();
    h.update(&al);
    let mut full = h.finalize();
    let t = full.as_ref()[..tag_len].to_vec();
    full.as_mut().zeroize();
    t
}

fn encrypt_with<C: BlockCipher, D: Digest>(
    key: &[u8],
    iv: &[u8; 16],
    aad: &[u8],
    plaintext: &[u8],
    cipher: C,
) -> (Vec<u8>, Vec<u8>) {
    let half = key.len() / 2;
    let pad = 16 - plaintext.len() % 16;
    let mut buf = Vec::with_capacity(plaintext.len() + pad);
    buf.extend_from_slice(plaintext);
    buf.extend(core::iter::repeat_n(pad as u8, pad));
    let mut cbc = Cbc::new(cipher, iv);
    cbc.encrypt(&mut buf)
        .expect("padded buffer is a whole number of blocks");
    let t = tag::<D>(&key[..half], aad, iv, &buf, half);
    (buf, t)
}

fn decrypt_with<C: BlockCipher, D: Digest>(
    key: &[u8],
    iv: &[u8; 16],
    aad: &[u8],
    ciphertext: &[u8],
    tag_in: &[u8],
    cipher: C,
) -> Result<Vec<u8>, ()> {
    let half = key.len() / 2;
    // Structural checks first: nothing here depends on the key.
    if tag_in.len() != half || ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(());
    }
    let mut expected = tag::<D>(&key[..half], aad, iv, ciphertext, half);
    let ok = bool::from(expected.ct_eq(tag_in));
    expected.zeroize();
    if !ok {
        return Err(());
    }
    let mut buf = ciphertext.to_vec();
    let mut cbc = Cbc::new(cipher, iv);
    cbc.decrypt(&mut buf)
        .expect("length checked to be whole blocks");
    // PKCS#7 unpadding. The MAC already authenticated the ciphertext, so a
    // padding failure here is not an oracle against an attacker-chosen
    // message; it still runs without data-dependent early exits.
    let last = *buf.last().expect("non-empty") as usize;
    let mut bad = (last == 0) as u8 | (last > 16) as u8;
    let pad = last.clamp(1, 16);
    let start = buf.len() - pad;
    for &b in &buf[start..] {
        bad |= (b as usize != last) as u8;
    }
    if bad != 0 {
        buf.zeroize();
        return Err(());
    }
    buf.truncate(start);
    Ok(buf)
}

/// Encrypts `plaintext` under composite key `key` (whose length must match
/// `enc`), returning `(ciphertext, tag)`.
pub(crate) fn encrypt(
    enc: Enc,
    key: &[u8],
    iv: &[u8; 16],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    debug_assert_eq!(key.len(), enc.key_len());
    match enc {
        Enc::A128CbcHs256 => encrypt_with::<_, Sha256>(
            key,
            iv,
            aad,
            plaintext,
            Aes128::new(key[16..].try_into().expect("16-byte half")),
        ),
        Enc::A192CbcHs384 => encrypt_with::<_, Sha384>(
            key,
            iv,
            aad,
            plaintext,
            Aes192::new(key[24..].try_into().expect("24-byte half")),
        ),
        Enc::A256CbcHs512 => encrypt_with::<_, Sha512>(
            key,
            iv,
            aad,
            plaintext,
            Aes256::new(key[32..].try_into().expect("32-byte half")),
        ),
        _ => unreachable!("not a CBC-HMAC variant"),
    }
}

/// Verifies `tag` and decrypts `ciphertext`; `Err(())` on any failure.
pub(crate) fn decrypt(
    enc: Enc,
    key: &[u8],
    iv: &[u8; 16],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, ()> {
    debug_assert_eq!(key.len(), enc.key_len());
    match enc {
        Enc::A128CbcHs256 => decrypt_with::<_, Sha256>(
            key,
            iv,
            aad,
            ciphertext,
            tag,
            Aes128::new(key[16..].try_into().expect("16-byte half")),
        ),
        Enc::A192CbcHs384 => decrypt_with::<_, Sha384>(
            key,
            iv,
            aad,
            ciphertext,
            tag,
            Aes192::new(key[24..].try_into().expect("24-byte half")),
        ),
        Enc::A256CbcHs512 => decrypt_with::<_, Sha512>(
            key,
            iv,
            aad,
            ciphertext,
            tag,
            Aes256::new(key[32..].try_into().expect("32-byte half")),
        ),
        _ => unreachable!("not a CBC-HMAC variant"),
    }
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
