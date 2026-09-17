//! AEAD modes: AES-GCM, AES-GCM-SIV, AES-CCM, ChaCha20-Poly1305,
//! XChaCha20-Poly1305, AEGIS, plus AES-GMAC.

use crate::common::{Fields, Outcome, check, check_eq};
use purecrypto::cipher::{Aes128, Aes192, Aes256, Gcm};

/// Runs one `AeadTest` case through a 16-byte-tag AEAD given closures for
/// encrypt / decrypt. `enc` returns the tag; `dec` returns whether the tag
/// verified. Both work in place.
fn aead_case<E, D>(case: &Fields, mut enc: E, mut dec: D) -> Outcome
where
    E: FnMut(&[u8], &[u8], &mut [u8]) -> Option<Vec<u8>>,
    D: FnMut(&[u8], &[u8], &mut [u8], &[u8]) -> Option<bool>,
{
    let iv = case.hex("iv");
    let aad = case.hex("aad");
    let msg = case.hex("msg");
    let ct = case.hex("ct");
    let tag = case.hex("tag");

    // Decrypt first: for `invalid` cases the ciphertext/tag pair must be
    // rejected regardless of what encryption would produce.
    let mut buf = ct.clone();
    match dec(&iv, &aad, &mut buf, &tag) {
        None => return Outcome::Rejected,
        Some(false) => return Outcome::Rejected,
        Some(true) => {}
    }
    if buf != msg {
        return Outcome::Wrong("decrypted plaintext");
    }
    // A tag that verified on a valid case must also be what we produce.
    let mut buf = msg.clone();
    match enc(&iv, &aad, &mut buf) {
        None => Outcome::Wrong("encrypt refused a decryptable input"),
        Some(t) => {
            if buf != ct {
                Outcome::Wrong("ciphertext")
            } else {
                check_eq(&t, &tag, "tag")
            }
        }
    }
}

fn gcm_with<C: purecrypto::cipher::BlockCipher>(cipher: C, case: &Fields) -> Outcome {
    let gcm = Gcm::new(cipher);
    aead_case(
        case,
        |iv, aad, buf| gcm.try_encrypt(iv, aad, buf).ok().map(|t| t.to_vec()),
        |iv, aad, buf, tag| {
            let tag: [u8; 16] = tag.try_into().ok()?;
            Some(gcm.try_decrypt(iv, aad, buf, &tag).is_ok())
        },
    )
}

#[test]
fn aes_gcm() {
    check("aes_gcm", |group, case| {
        // Only full 128-bit tags are exposed by the API.
        if group.int("tagSize") != 128 {
            return Outcome::Skipped;
        }
        let key = case.hex("key");
        match key.len() {
            16 => gcm_with(Aes128::new(&key.try_into().unwrap()), case),
            24 => gcm_with(Aes192::new(&key.try_into().unwrap()), case),
            32 => gcm_with(Aes256::new(&key.try_into().unwrap()), case),
            _ => Outcome::Rejected,
        }
    });
}
