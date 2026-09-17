//! AEAD modes: AES-GCM, AES-GCM-SIV, AES-CCM, AES-EAX, ChaCha20-Poly1305,
//! XChaCha20-Poly1305, AEGIS (128 / 128L / 256), MORUS, Ascon-AEAD128 and
//! the Ascon v1.2 variants, the ARIA / Camellia / SM4 / SEED GCM and CCM
//! instantiations, the RFC 7518 AES-CBC-HMAC-SHA2 composites, plus AES-GMAC.

use crate::common::{Fields, Outcome, check, check_eq};
#[cfg(feature = "hash")]
use purecrypto::cipher::{A128CbcHs256, A192CbcHs384, A256CbcHs512};
use purecrypto::cipher::{
    Aegis128, Aegis128L, Aegis256, Aes128, Aes192, Aes256, AesGcmSiv, Aria128, Aria192, Aria256,
    BlockCipher, Camellia128, Camellia192, Camellia256, Ccm, ChaCha20Poly1305, Eax, Gcm, Gmac,
    Morus640, Morus1280, Seed, Sm4, XChaCha20Poly1305,
};

/// Runs one `AeadTest` case through an AEAD given closures for encrypt /
/// decrypt. `enc` returns the tag (`None` when the mode refuses the
/// parameters); `dec` returns whether the tag verified (`None` when the
/// parameters are refused). Both work in place.
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

/// [`aead_case`] for a mode whose nonce (`N` bytes) and tag (`T` bytes) are
/// array-typed: any other nonce or tag length cannot reach the mode and maps
/// to [`Outcome::Rejected`].
fn fixed_aead<const N: usize, const T: usize, E, D>(
    case: &Fields,
    mut enc: E,
    mut dec: D,
) -> Outcome
where
    E: FnMut(&[u8; N], &[u8], &mut [u8]) -> [u8; T],
    D: FnMut(&[u8; N], &[u8], &mut [u8], &[u8; T]) -> bool,
{
    aead_case(
        case,
        |iv, aad, buf| {
            let iv: [u8; N] = iv.try_into().ok()?;
            Some(enc(&iv, aad, buf).to_vec())
        },
        |iv, aad, buf, tag| {
            let iv: [u8; N] = iv.try_into().ok()?;
            let tag: [u8; T] = tag.try_into().ok()?;
            Some(dec(&iv, aad, buf, &tag))
        },
    )
}

/// Keys a block cipher chosen by the case's key length and hands it to
/// `$f(cipher, group, case)`; a key length none of the listed constructors
/// take is [`Outcome::Rejected`].
macro_rules! keyed {
    ($group:expr, $case:expr, $f:ident; $($len:literal => $ty:ty),+ $(,)?) => {{
        let key: Vec<u8> = $case.hex("key");
        match key.len() {
            $($len => $f(<$ty>::new(&key.try_into().unwrap()), $group, $case),)+
            _ => Outcome::Rejected,
        }
    }};
}

fn gcm_with<C: BlockCipher>(cipher: C, _group: &Fields, case: &Fields) -> Outcome {
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

/// GCM vectors also carry truncated-tag groups; only the full 128-bit tag is
/// exposed by the API, so those are skipped.
fn gcm_group_ok(group: &Fields) -> bool {
    group.int("tagSize") == 128
}

#[test]
fn aes_gcm() {
    check("aes_gcm", |group, case| {
        if !gcm_group_ok(group) {
            return Outcome::Skipped;
        }
        keyed!(group, case, gcm_with; 16 => Aes128, 24 => Aes192, 32 => Aes256)
    });
}

#[test]
fn aria_gcm() {
    check("aria_gcm", |group, case| {
        if !gcm_group_ok(group) {
            return Outcome::Skipped;
        }
        keyed!(group, case, gcm_with; 16 => Aria128, 24 => Aria192, 32 => Aria256)
    });
}

#[test]
fn sm4_gcm() {
    check("sm4_gcm", |group, case| {
        if !gcm_group_ok(group) {
            return Outcome::Skipped;
        }
        keyed!(group, case, gcm_with; 16 => Sm4)
    });
}

/// CCM with an `M`-byte tag. `try_new` reports the tag lengths CCM does not
/// define (SP 800-38C allows only 4, 6, ..., 16) and `try_encrypt` /
/// `try_decrypt` report nonces outside 7..=13 bytes, so every such group
/// comes back `Rejected` rather than panicking.
fn ccm_with<C: BlockCipher, const M: usize>(cipher: C, case: &Fields) -> Outcome {
    let Ok(ccm) = Ccm::<C, M>::try_new(cipher) else {
        return Outcome::Rejected;
    };
    aead_case(
        case,
        |iv, aad, buf| ccm.try_encrypt(iv, aad, buf).ok().map(|t| t.to_vec()),
        |iv, aad, buf, tag| {
            let tag: [u8; M] = tag.try_into().ok()?;
            Some(ccm.try_decrypt(iv, aad, buf, &tag).is_ok())
        },
    )
}

/// Picks the CCM tag length from the group's `tagSize` (bits). The tag
/// length is a const generic, so each byte length the vectors use gets its
/// own instantiation; lengths CCM rejects are exercised too (see
/// [`ccm_with`]).
fn ccm_tagged<C: BlockCipher>(cipher: C, group: &Fields, case: &Fields) -> Outcome {
    macro_rules! by_tag {
        ($($m:literal)*) => {
            match group.int("tagSize") / 8 {
                $($m => ccm_with::<C, $m>(cipher, case),)*
                _ => Outcome::Rejected,
            }
        };
    }
    by_tag!(2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
}

#[test]
fn aes_ccm() {
    check(
        "aes_ccm",
        |group, case| keyed!(group, case, ccm_tagged; 16 => Aes128, 24 => Aes192, 32 => Aes256),
    );
}

#[test]
fn aria_ccm() {
    check(
        "aria_ccm",
        |group, case| keyed!(group, case, ccm_tagged; 16 => Aria128, 24 => Aria192, 32 => Aria256),
    );
}

#[test]
fn camellia_ccm() {
    check(
        "camellia_ccm",
        |group, case| keyed!(group, case, ccm_tagged; 16 => Camellia128, 24 => Camellia192, 32 => Camellia256),
    );
}

#[test]
fn sm4_ccm() {
    check(
        "sm4_ccm",
        |group, case| keyed!(group, case, ccm_tagged; 16 => Sm4),
    );
}

#[test]
fn aes_gcm_siv() {
    check("aes_gcm_siv", |_, case| {
        // `try_new` takes 16- or 32-byte keys and reports anything else.
        let Ok(siv) = AesGcmSiv::try_new(&case.hex("key")) else {
            return Outcome::Rejected;
        };
        fixed_aead::<12, 16, _, _>(
            case,
            |n, aad, buf| siv.encrypt(n, aad, buf),
            |n, aad, buf, tag| siv.decrypt(n, aad, buf, tag).is_ok(),
        )
    });
}

#[test]
fn chacha20_poly1305() {
    check("chacha20_poly1305", |_, case| {
        let Some(key) = case.hex_array::<32>("key") else {
            return Outcome::Rejected;
        };
        let aead = ChaCha20Poly1305::new(&key);
        fixed_aead::<12, 16, _, _>(
            case,
            |n, aad, buf| aead.encrypt(n, aad, buf),
            |n, aad, buf, tag| aead.decrypt(n, aad, buf, tag).is_ok(),
        )
    });
}

#[test]
fn xchacha20_poly1305() {
    check("xchacha20_poly1305", |_, case| {
        let Some(key) = case.hex_array::<32>("key") else {
            return Outcome::Rejected;
        };
        let aead = XChaCha20Poly1305::new(&key);
        fixed_aead::<24, 16, _, _>(
            case,
            |n, aad, buf| aead.encrypt(n, aad, buf),
            |n, aad, buf, tag| aead.decrypt(n, aad, buf, tag).is_ok(),
        )
    });
}

/// AEGIS exposes a 128-bit and a 256-bit tag variant; the group's `tagSize`
/// selects which one the vectors were generated with.
macro_rules! aegis_case {
    ($aead:expr, $group:expr, $case:expr, $nonce:literal) => {
        match $group.int("tagSize") {
            128 => fixed_aead::<$nonce, 16, _, _>(
                $case,
                |n, aad, buf| $aead.encrypt(n, aad, buf),
                |n, aad, buf, tag| $aead.decrypt(n, aad, buf, tag).is_ok(),
            ),
            256 => fixed_aead::<$nonce, 32, _, _>(
                $case,
                |n, aad, buf| $aead.encrypt_tag256(n, aad, buf),
                |n, aad, buf, tag| $aead.decrypt_tag256(n, aad, buf, tag).is_ok(),
            ),
            _ => Outcome::Rejected,
        }
    };
}

#[test]
fn aegis128l() {
    check("aegis128L", |group, case| {
        let Some(key) = case.hex_array::<16>("key") else {
            return Outcome::Rejected;
        };
        let aead = Aegis128L::new(&key);
        aegis_case!(aead, group, case, 16)
    });
}

#[test]
fn aegis256() {
    check("aegis256", |group, case| {
        let Some(key) = case.hex_array::<32>("key") else {
            return Outcome::Rejected;
        };
        let aead = Aegis256::new(&key);
        aegis_case!(aead, group, case, 32)
    });
}

#[test]
fn ascon_aead128() {
    check("ascon_sp800_232_aead128", |_, case| {
        let Some(key) = case.hex_array::<16>("key") else {
            return Outcome::Rejected;
        };
        let aead = purecrypto::ascon::AsconAead128::new(&key);
        fixed_aead::<16, 16, _, _>(
            case,
            |n, aad, buf| aead.encrypt(n, aad, buf),
            |n, aad, buf, tag| aead.decrypt(n, aad, buf, tag).is_ok(),
        )
    });
}

/// One `MacWithIvTest` case. GMAC is GCM over an empty plaintext with the
/// message as associated data, and `Gmac` only takes the SP 800-38D 96-bit
/// nonce, so the tag is computed through `Gcm` (which accepts every nonce
/// length the vectors use, including the 128-bit groups) and, whenever the
/// nonce is 96 bits, cross-checked against the streaming `Gmac` API.
fn gmac_with<C: BlockCipher + Clone>(cipher: C, _group: &Fields, case: &Fields) -> Outcome {
    let iv = case.hex("iv");
    let msg = case.hex("msg");
    let tag = case.hex("tag");
    let Ok(via_gcm) = Gcm::new(cipher.clone()).try_encrypt(&iv, &msg, &mut []) else {
        return Outcome::Rejected;
    };
    if let Ok(nonce) = <[u8; 12]>::try_from(iv.as_slice()) {
        let mut gmac = Gmac::new(cipher, &nonce);
        // Feed in uneven chunks so the block buffering is exercised too.
        let (head, rest) = msg.split_at(msg.len().min(7));
        gmac.update(head);
        gmac.update(rest);
        if gmac.finalize() != via_gcm {
            return Outcome::Wrong("Gmac disagrees with Gcm");
        }
    }
    // A MAC vector is a verification: a tag that differs from the expected
    // one (the `ModifiedTag` cases) is a rejection, not a wrong output.
    if via_gcm[..] == tag[..] {
        Outcome::Accepted
    } else {
        Outcome::Rejected
    }
}

#[test]
fn aes_gmac() {
    check(
        "aes_gmac",
        |group, case| keyed!(group, case, gmac_with; 16 => Aes128, 24 => Aes192, 32 => Aes256),
    );
}

// ---- AES-EAX ---------------------------------------------------------------

/// EAX takes a nonce of any length (the vectors go from 0 to 2056 bits) and
/// always a 128-bit tag; the file only carries `tagSize=128` groups, so any
/// other tag length is a rejection rather than a skip.
fn eax_with<C: BlockCipher + Clone>(cipher: C, _group: &Fields, case: &Fields) -> Outcome {
    let eax = Eax::new(cipher);
    aead_case(
        case,
        |iv, aad, buf| Some(eax.encrypt(iv, aad, buf).to_vec()),
        |iv, aad, buf, tag| {
            let tag: [u8; 16] = tag.try_into().ok()?;
            Some(eax.decrypt(iv, aad, buf, &tag).is_ok())
        },
    )
}

#[test]
fn aes_eax() {
    check(
        "aes_eax",
        |group, case| keyed!(group, case, eax_with; 16 => Aes128, 24 => Aes192, 32 => Aes256),
    );
}

// ---- SEED ------------------------------------------------------------------

#[test]
fn seed_gcm() {
    check("seed_gcm", |group, case| {
        if !gcm_group_ok(group) {
            return Outcome::Skipped;
        }
        keyed!(group, case, gcm_with; 16 => Seed)
    });
}

#[test]
fn seed_ccm() {
    check(
        "seed_ccm",
        |group, case| keyed!(group, case, ccm_tagged; 16 => Seed),
    );
}

// ---- MORUS -----------------------------------------------------------------

#[test]
fn morus640() {
    check("morus640", |_, case| {
        let Some(key) = case.hex_array::<16>("key") else {
            return Outcome::Rejected;
        };
        let aead = Morus640::new(&key);
        fixed_aead::<16, 16, _, _>(
            case,
            |n, aad, buf| aead.encrypt(n, aad, buf),
            |n, aad, buf, tag| aead.decrypt(n, aad, buf, tag).is_ok(),
        )
    });
}

#[test]
fn morus1280() {
    check("morus1280", |_, case| {
        // `try_new` takes 16- or 32-byte keys and reports anything else.
        let Ok(aead) = Morus1280::try_new(&case.hex("key")) else {
            return Outcome::Rejected;
        };
        fixed_aead::<16, 16, _, _>(
            case,
            |n, aad, buf| aead.encrypt(n, aad, buf),
            |n, aad, buf, tag| aead.decrypt(n, aad, buf, tag).is_ok(),
        )
    });
}

// ---- AEGIS-128 (the original CAESAR variant) -------------------------------

#[test]
fn aegis128() {
    check("aegis128", |group, case| {
        let Some(key) = case.hex_array::<16>("key") else {
            return Outcome::Rejected;
        };
        // Only the 128-bit tag is defined for AEGIS-128.
        if group.int("tagSize") != 128 {
            return Outcome::Rejected;
        }
        let aead = Aegis128::new(&key);
        fixed_aead::<16, 16, _, _>(
            case,
            |n, aad, buf| aead.encrypt(n, aad, buf),
            |n, aad, buf, tag| aead.decrypt(n, aad, buf, tag).is_ok(),
        )
    });
}

// ---- Ascon v1.2 ------------------------------------------------------------

/// The three v1.2 variants share the 128-bit nonce / tag shape and differ
/// only in key length (`K` bytes) and type.
macro_rules! ascon_v12_test {
    ($name:ident, $file:literal, $ty:ident, $klen:literal) => {
        #[test]
        fn $name() {
            check($file, |_, case| {
                let Some(key) = case.hex_array::<$klen>("key") else {
                    return Outcome::Rejected;
                };
                let aead = purecrypto::ascon::$ty::new(&key);
                fixed_aead::<16, 16, _, _>(
                    case,
                    |n, aad, buf| aead.encrypt(n, aad, buf),
                    |n, aad, buf, tag| aead.decrypt(n, aad, buf, tag).is_ok(),
                )
            });
        }
    };
}

ascon_v12_test!(ascon128, "ascon128", Ascon128, 16);
ascon_v12_test!(ascon128a, "ascon128a", Ascon128a, 16);
ascon_v12_test!(ascon80pq, "ascon80pq", Ascon80pq, 20);

// ---- AES-CBC-HMAC-SHA2 (RFC 7518 §5.2) -------------------------------------

/// One `AeadTest` case through the composite's slice API. The tag length is
/// fixed by the variant, so a case whose `tag` has another length (none in
/// the current files) is rejected by `decrypt_into`. Decryption goes first,
/// as in [`aead_case`], so every `invalid` case fails there.
#[cfg(feature = "hash")]
fn cbc_hmac_case<C, D>(aead: &purecrypto::cipher::CbcHmacSha2<C, D>, case: &Fields) -> Outcome
where
    C: BlockCipher + Clone,
    D: purecrypto::hash::Digest,
{
    let Some(iv) = case.hex_array::<16>("iv") else {
        return Outcome::Rejected;
    };
    let aad = case.hex("aad");
    let msg = case.hex("msg");
    let ct = case.hex("ct");
    let tag = case.hex("tag");

    let mut out = vec![0u8; ct.len()];
    match aead.decrypt_into(&iv, &aad, &ct, &tag, &mut out) {
        Err(_) => return Outcome::Rejected,
        Ok(n) if out[..n] != msg[..] => return Outcome::Wrong("decrypted plaintext"),
        Ok(_) => {}
    }
    let mut ct_out = vec![0u8; purecrypto::cipher::CbcHmacSha2::<C, D>::ciphertext_len(msg.len())];
    let mut tag_out = vec![0u8; purecrypto::cipher::CbcHmacSha2::<C, D>::TAG_LEN];
    match aead.encrypt_into(&iv, &aad, &msg, &mut ct_out, &mut tag_out) {
        Err(_) => Outcome::Wrong("encrypt refused a decryptable input"),
        Ok(()) => {
            if ct_out != ct {
                Outcome::Wrong("ciphertext")
            } else {
                check_eq(&tag_out, &tag, "tag")
            }
        }
    }
}

#[cfg(feature = "hash")]
macro_rules! cbc_hmac_test {
    ($name:ident, $ty:ident) => {
        #[test]
        fn $name() {
            check(stringify!($name), |_, case| {
                // `try_new` reports every key length but the variant's own.
                let Ok(aead) = $ty::try_new(&case.hex("key")) else {
                    return Outcome::Rejected;
                };
                cbc_hmac_case(&aead, case)
            });
        }
    };
}

#[cfg(feature = "hash")]
cbc_hmac_test!(a128cbc_hs256, A128CbcHs256);
#[cfg(feature = "hash")]
cbc_hmac_test!(a192cbc_hs384, A192CbcHs384);
#[cfg(feature = "hash")]
cbc_hmac_test!(a256cbc_hs512, A256CbcHs512);
