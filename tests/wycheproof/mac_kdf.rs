//! MACs and KDFs: HMAC (12 hash functions), KMAC128/256, HKDF, PBKDF2 and
//! PBES2 (PBKDF2 + AES-CBC-PKCS#7).

use crate::common::{Fields, Outcome, check, check_eq};
use purecrypto::cipher::{Aes128, Aes192, Aes256, BlockCipher, Cbc};
use purecrypto::hash::{
    Digest, Hmac, Kmac128, Kmac256, Mac, Sha1, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha224,
    Sha256, Sha384, Sha512, Sha512_224, Sha512_256, Sm3,
};
use purecrypto::kdf::{try_hkdf, try_pbkdf2};

// ---- HMAC --------------------------------------------------------------

/// One `MacTest` case for HMAC-`D`. The group's `tagSize` may be shorter
/// than the digest, in which case the tag is a prefix of the full MAC. The
/// crate's constant-time [`Hmac::verify`] is length-strict (it never accepts
/// a truncated tag), so it is cross-checked rather than used as the outcome:
/// it must agree with the prefix compare on full-length tags and reject
/// every truncated one.
fn hmac_case<D: Digest>(group: &Fields, case: &Fields) -> Outcome {
    let key = case.hex("key");
    let msg = case.hex("msg");
    let tag = case.hex("tag");
    let tag_len = group.int("tagSize") as usize / 8;
    let full = Hmac::<D>::mac(&key, &msg);
    let full = full.as_ref();
    let verified = bool::from(Hmac::<D>::new(&key).chain(&msg).verify(&tag));
    if tag.len() != tag_len || tag.len() > full.len() {
        assert!(
            !verified,
            "tcId {}: verify accepted a bad-length tag",
            case.tc_id()
        );
        return Outcome::Rejected;
    }
    let matches = full[..tag.len()] == tag[..];
    assert_eq!(
        verified,
        matches && tag.len() == full.len(),
        "tcId {}: Hmac::verify disagrees with the prefix compare",
        case.tc_id()
    );
    if matches {
        Outcome::Accepted
    } else {
        Outcome::Rejected
    }
}

macro_rules! hmac_tests {
    ($($test:ident => $digest:ty),* $(,)?) => {$(
        #[test]
        fn $test() {
            check(stringify!($test), |group, case| hmac_case::<$digest>(group, case));
        }
    )*};
}

hmac_tests! {
    hmac_sha1 => Sha1,
    hmac_sha224 => Sha224,
    hmac_sha256 => Sha256,
    hmac_sha384 => Sha384,
    hmac_sha512 => Sha512,
    hmac_sha512_224 => Sha512_224,
    hmac_sha512_256 => Sha512_256,
    hmac_sha3_224 => Sha3_224,
    hmac_sha3_256 => Sha3_256,
    hmac_sha3_384 => Sha3_384,
    hmac_sha3_512 => Sha3_512,
    hmac_sm3 => Sm3,
}

// ---- KMAC --------------------------------------------------------------

/// One `MacTest` case for a variable-output MAC (KMAC, no customization).
/// The output length is part of the KMAC computation, so the tag is
/// recomputed at the group's `tagSize`. Every vector tag is 16..=64 bytes,
/// which is exactly the range the trait's [`Mac::verify`] handles without
/// `alloc`, so `verify` is exercised on every case and must agree.
fn kmac_case<M: Mac>(new: fn(&[u8], &[u8]) -> M, group: &Fields, case: &Fields) -> Outcome {
    let key = case.hex("key");
    let msg = case.hex("msg");
    let tag = case.hex("tag");
    let tag_len = group.int("tagSize") as usize / 8;
    let mut mac = new(&key, b"");
    mac.update(&msg);
    let mut out = vec![0u8; tag_len];
    mac.finalize_into(&mut out);
    let mut mac = new(&key, b"");
    mac.update(&msg);
    let verified = bool::from(mac.verify(&tag));
    let matches = out == tag;
    assert_eq!(
        verified,
        matches,
        "tcId {}: Mac::verify disagrees with the recomputed tag",
        case.tc_id()
    );
    if matches {
        Outcome::Accepted
    } else {
        Outcome::Rejected
    }
}

#[test]
fn kmac128_no_customization() {
    check("kmac128_no_customization", |g, c| {
        kmac_case(Kmac128::new, g, c)
    });
}

#[test]
fn kmac256_no_customization() {
    check("kmac256_no_customization", |g, c| {
        kmac_case(Kmac256::new, g, c)
    });
}

// ---- HKDF --------------------------------------------------------------

/// One `HkdfTest` case. `size` is the requested OKM length in bytes; the
/// `invalid` cases ask for more than `255 * HashLen`, which the fallible
/// entry point refuses.
fn hkdf_case<D: Digest>(case: &Fields) -> Outcome {
    let mut out = vec![0u8; case.int("size") as usize];
    match try_hkdf::<D>(
        &case.hex("salt"),
        &case.hex("ikm"),
        &case.hex("info"),
        &mut out,
    ) {
        Ok(()) => check_eq(&out, &case.hex("okm"), "okm"),
        Err(_) => Outcome::Rejected,
    }
}

macro_rules! hkdf_tests {
    ($($test:ident => $digest:ty),* $(,)?) => {$(
        #[test]
        fn $test() {
            check(stringify!($test), |_, case| hkdf_case::<$digest>(case));
        }
    )*};
}

hkdf_tests! {
    hkdf_sha1 => Sha1,
    hkdf_sha256 => Sha256,
    hkdf_sha384 => Sha384,
    hkdf_sha512 => Sha512,
}

// ---- PBKDF2 ------------------------------------------------------------

/// Cases above this iteration count are skipped for runtime, not
/// correctness: the only one is `pbkdf2_hmacsha1` tcId 4 (RFC 6070,
/// `LargeIterationCount`, 16 777 216 rounds), which alone takes ~40 s in a
/// debug build and passes when the threshold is lifted. Every other case
/// is at most 80 000 rounds.
const PBKDF2_MAX_ITERATIONS: u64 = 1_000_000;

/// One `PbkdfTest` case.
fn pbkdf2_case<D: Digest>(case: &Fields) -> Outcome {
    let iterations = case.int("iterationCount");
    if iterations > PBKDF2_MAX_ITERATIONS {
        return Outcome::Skipped;
    }
    let Ok(iterations) = u32::try_from(iterations) else {
        return Outcome::Rejected;
    };
    let mut out = vec![0u8; case.int("dkLen") as usize];
    match try_pbkdf2::<D>(
        &case.hex("password"),
        &case.hex("salt"),
        iterations,
        &mut out,
    ) {
        Ok(()) => check_eq(&out, &case.hex("dk"), "dk"),
        Err(_) => Outcome::Rejected,
    }
}

macro_rules! pbkdf2_tests {
    ($($test:ident => $digest:ty),* $(,)?) => {$(
        #[test]
        fn $test() {
            check(stringify!($test), |_, case| pbkdf2_case::<$digest>(case));
        }
    )*};
}

pbkdf2_tests! {
    pbkdf2_hmacsha1 => Sha1,
    pbkdf2_hmacsha224 => Sha224,
    pbkdf2_hmacsha256 => Sha256,
    pbkdf2_hmacsha384 => Sha384,
    pbkdf2_hmacsha512 => Sha512,
}

// ---- PBES2 -------------------------------------------------------------
//
// The `PbeTest` vectors are the bare RFC 8018 §6.2 scheme — PBKDF2-HMAC-H
// derives the AES key, AES-CBC with PKCS#7 padding encrypts `msg` under
// `iv` — not a PKCS#8 `EncryptedPrivateKeyInfo`. They are checked as that
// composition through the public `try_pbkdf2` + `Cbc` API in both
// directions. The crate's PKCS#8 wrapper (`kdf::pbes2::decrypt`) cannot
// accept any of them: every case uses 4096 iterations and the wrapper's
// documented floor is 10 000 (`Error::WeakKdfParameters`), and it only
// speaks HMAC-SHA-256/512 with AES-256. For the two files inside its
// algorithm set, each case is additionally wrapped in DER and fed to
// `decrypt`, asserting it fails for exactly that policy reason (which also
// proves the parameters parsed correctly).

fn pkcs7_pad(msg: &[u8]) -> Vec<u8> {
    let pad = 16 - msg.len() % 16;
    let mut out = msg.to_vec();
    out.extend(std::iter::repeat_n(pad as u8, pad));
    out
}

fn pkcs7_unpad(buf: &[u8]) -> Option<&[u8]> {
    let pad = *buf.last()? as usize;
    if pad == 0
        || pad > 16
        || pad > buf.len()
        || !buf[buf.len() - pad..].iter().all(|&b| b as usize == pad)
    {
        return None;
    }
    Some(&buf[..buf.len() - pad])
}

/// One `PbeTest` case: derive an `N`-byte AES key with PBKDF2-HMAC-`D`,
/// then decrypt `ct` (must unpad to `msg`) and re-encrypt `msg` (must give
/// `ct`).
fn pbes2_case<D: Digest, C: BlockCipher, const N: usize>(
    new: fn(&[u8; N]) -> C,
    case: &Fields,
) -> Outcome {
    let Some(iv) = case.hex_array::<16>("iv") else {
        return Outcome::Rejected;
    };
    let Ok(iterations) = u32::try_from(case.int("iterationCount")) else {
        return Outcome::Rejected;
    };
    let msg = case.hex("msg");
    let ct = case.hex("ct");
    let mut key = [0u8; N];
    if try_pbkdf2::<D>(
        &case.hex("password"),
        &case.hex("salt"),
        iterations,
        &mut key,
    )
    .is_err()
    {
        return Outcome::Rejected;
    }
    let mut buf = ct.clone();
    if Cbc::new(new(&key), &iv).decrypt(&mut buf).is_err() {
        return Outcome::Rejected;
    }
    match pkcs7_unpad(&buf) {
        None => return Outcome::Rejected,
        Some(pt) if pt != msg => return Outcome::Wrong("plaintext"),
        Some(_) => {}
    }
    let mut buf = pkcs7_pad(&msg);
    Cbc::new(new(&key), &iv)
        .encrypt(&mut buf)
        .expect("padded to whole blocks");
    check_eq(&buf, &ct, "ciphertext")
}

/// Wraps a case in an `EncryptedPrivateKeyInfo` with the given PBKDF2 PRF
/// OID and `aes256-CBC-PAD`, and checks `kdf::pbes2::decrypt` applies its
/// iteration-count floor (or, should a vector ever clear it, decrypts).
#[cfg(all(feature = "der", feature = "rng"))]
fn pbes2_pkcs8_check(prf_oid: &[u64], case: &Fields) {
    use purecrypto::der::{
        encode_integer, encode_null, encode_octet_string, encode_sequence, oid_tlv,
    };
    use purecrypto::kdf::pbes2::{self, Error};
    let iterations = case.int("iterationCount");
    let prf = encode_sequence(&[oid_tlv(prf_oid), encode_null()].concat());
    let pbkdf2_params = encode_sequence(
        &[
            encode_octet_string(&case.hex("salt")),
            encode_integer(&iterations.to_be_bytes()),
            prf,
        ]
        .concat(),
    );
    let kdf = encode_sequence(&[oid_tlv(&[1, 2, 840, 113549, 1, 5, 12]), pbkdf2_params].concat());
    let cipher = encode_sequence(
        &[
            oid_tlv(&[2, 16, 840, 1, 101, 3, 4, 1, 42]),
            encode_octet_string(&case.hex("iv")),
        ]
        .concat(),
    );
    let algid = encode_sequence(
        &[
            oid_tlv(&[1, 2, 840, 113549, 1, 5, 13]),
            encode_sequence(&[kdf, cipher].concat()),
        ]
        .concat(),
    );
    let blob = encode_sequence(&[algid, encode_octet_string(&case.hex("ct"))].concat());
    let expected = if iterations < 10_000 {
        Err(Error::WeakKdfParameters)
    } else {
        Ok(case.hex("msg"))
    };
    assert_eq!(
        pbes2::decrypt(&blob, &case.hex("password")),
        expected,
        "tcId {}: pbes2::decrypt",
        case.tc_id()
    );
}

macro_rules! pbes2_tests {
    ($($test:ident => $digest:ty, $cipher:ty, $n:literal $(, pkcs8 $prf:expr)?);* $(;)?) => {$(
        #[test]
        fn $test() {
            check(stringify!($test), |_, case| {
                $(
                    #[cfg(all(feature = "der", feature = "rng"))]
                    pbes2_pkcs8_check($prf, case);
                )?
                pbes2_case::<$digest, $cipher, $n>(<$cipher>::new, case)
            });
        }
    )*};
}

pbes2_tests! {
    pbes2_hmacsha1_aes_128 => Sha1, Aes128, 16;
    pbes2_hmacsha1_aes_192 => Sha1, Aes192, 24;
    pbes2_hmacsha1_aes_256 => Sha1, Aes256, 32;
    pbes2_hmacsha224_aes_128 => Sha224, Aes128, 16;
    pbes2_hmacsha224_aes_192 => Sha224, Aes192, 24;
    pbes2_hmacsha224_aes_256 => Sha224, Aes256, 32;
    pbes2_hmacsha256_aes_128 => Sha256, Aes128, 16;
    pbes2_hmacsha256_aes_192 => Sha256, Aes192, 24;
    // hmacWithSHA256 (RFC 8018 §B.1.2)
    pbes2_hmacsha256_aes_256 => Sha256, Aes256, 32, pkcs8 &[1, 2, 840, 113549, 2, 9];
    pbes2_hmacsha384_aes_128 => Sha384, Aes128, 16;
    pbes2_hmacsha384_aes_192 => Sha384, Aes192, 24;
    pbes2_hmacsha384_aes_256 => Sha384, Aes256, 32;
    pbes2_hmacsha512_aes_128 => Sha512, Aes128, 16;
    pbes2_hmacsha512_aes_192 => Sha512, Aes192, 24;
    // hmacWithSHA512 (RFC 8018 §B.1.2)
    pbes2_hmacsha512_aes_256 => Sha512, Aes256, 32, pkcs8 &[1, 2, 840, 113549, 2, 11];
}
