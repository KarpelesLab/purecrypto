//! Block-cipher modes: CBC with PKCS#7 padding, CMAC, AES-SIV (RFC 5297),
//! key wrap (RFC 3394 / RFC 5649) and XTS, over AES, ARIA and Camellia.

use crate::common::{Fields, Outcome, check, check_eq};
#[cfg(feature = "alloc")]
use purecrypto::cipher::AesSiv;
use purecrypto::cipher::{
    Aes128, Aes192, Aes256, AesKw, AesKwp, Aria128, Aria192, Aria256, BlockCipher, Camellia128,
    Camellia192, Camellia256, Cbc, Cmac, Xts, kw_ciphertext_len, kwp_ciphertext_len,
};

/// Keys the 128/192/256-bit member of a cipher family from `key` and applies
/// the generic `f(cipher, args..)`; any other key length is `Rejected`.
macro_rules! keyed {
    (aes, $key:expr, $f:ident($($arg:expr),*)) => {
        keyed!(@ $key, $f($($arg),*); Aes128, Aes192, Aes256)
    };
    (aria, $key:expr, $f:ident($($arg:expr),*)) => {
        keyed!(@ $key, $f($($arg),*); Aria128, Aria192, Aria256)
    };
    (camellia, $key:expr, $f:ident($($arg:expr),*)) => {
        keyed!(@ $key, $f($($arg),*); Camellia128, Camellia192, Camellia256)
    };
    (@ $key:expr, $f:ident($($arg:expr),*); $c16:ident, $c24:ident, $c32:ident) => {{
        let key: Vec<u8> = $key;
        match key.len() {
            16 => $f($c16::new(&key.try_into().unwrap()), $($arg),*),
            24 => $f($c24::new(&key.try_into().unwrap()), $($arg),*),
            32 => $f($c32::new(&key.try_into().unwrap()), $($arg),*),
            _ => Outcome::Rejected,
        }
    }};
}

/// One `#[test]` per `<family>_<mode>` file, keying the family from the
/// case's `key` and handing the cipher to the mode's case function.
macro_rules! family_tests {
    ($($name:ident = $family:ident / $case:ident;)*) => {$(
        #[test]
        fn $name() {
            check(stringify!($name), |group, case| {
                keyed!($family, case.hex("key"), $case(group, case))
            });
        }
    )*};
}

family_tests! {
    aes_cbc_pkcs5 = aes / cbc_case;
    aria_cbc_pkcs5 = aria / cbc_case;
    camellia_cbc_pkcs5 = camellia / cbc_case;
    aes_cmac = aes / cmac_case;
    aria_cmac = aria / cmac_case;
    camellia_cmac = camellia / cmac_case;
    aes_wrap = aes / kw_case;
    aria_wrap = aria / kw_case;
    camellia_wrap = camellia / kw_case;
    aes_kwp = aes / kwp_case;
    aria_kwp = aria / kwp_case;
}

// ---- CBC / PKCS#7 -------------------------------------------------------

/// PKCS#7 padding for 16-byte blocks (PKCS#5 in the vectors' naming). The
/// crate's `Cbc` is deliberately unpadded, so the padding lives here; the
/// vectors test the chaining plus a strict padding check on decrypt.
fn pkcs7_pad(msg: &[u8]) -> Vec<u8> {
    let p = 16 - msg.len() % 16;
    let mut out = msg.to_vec();
    out.resize(msg.len() + p, p as u8);
    out
}

fn pkcs7_unpad(buf: &[u8]) -> Option<&[u8]> {
    let p = usize::from(*buf.last()?);
    let body = buf.len().checked_sub(p)?;
    if p == 0 || p > 16 || buf[body..].iter().any(|&b| usize::from(b) != p) {
        return None;
    }
    Some(&buf[..body])
}

fn cbc_case<C: BlockCipher + Clone>(cipher: C, _: &Fields, case: &Fields) -> Outcome {
    let Some(iv) = case.hex_array::<16>("iv") else {
        return Outcome::Rejected;
    };
    let msg = case.hex("msg");
    let ct = case.hex("ct");
    // Decrypt first: a bad length or bad padding must be rejected outright.
    let mut buf = ct.clone();
    if buf.is_empty() || Cbc::new(cipher.clone(), &iv).decrypt(&mut buf).is_err() {
        return Outcome::Rejected;
    }
    match pkcs7_unpad(&buf) {
        None => return Outcome::Rejected,
        Some(pt) if pt != msg => return Outcome::Wrong("decrypted plaintext"),
        Some(_) => {}
    }
    let mut buf = pkcs7_pad(&msg);
    match Cbc::new(cipher, &iv).encrypt(&mut buf) {
        Err(_) => Outcome::Wrong("encrypt refused a decryptable input"),
        Ok(()) => check_eq(&buf, &ct, "ciphertext"),
    }
}

// ---- CMAC ----------------------------------------------------------------

fn cmac_case<C: BlockCipher>(cipher: C, group: &Fields, case: &Fields) -> Outcome {
    let tag = case.hex("tag");
    let n = group.int("tagSize") as usize / 8;
    if tag.len() != n || n > 16 {
        return Outcome::Rejected;
    }
    let mut mac = Cmac::new(cipher);
    mac.update(&case.hex("msg"));
    // `verify` only takes full tags; a truncated group compares the prefix
    // of the computed tag instead (none of the current files has one).
    let ok = if n == 16 {
        mac.verify(&tag)
    } else {
        mac.finalize()[..n] == tag[..]
    };
    if ok {
        Outcome::Accepted
    } else {
        Outcome::Rejected
    }
}

// ---- Key wrap (RFC 3394 / RFC 5649) ----------------------------------------

fn kw_case<C: BlockCipher>(cipher: C, _: &Fields, case: &Fields) -> Outcome {
    let msg = case.hex("msg");
    let ct = case.hex("ct");
    let kw = AesKw::new(cipher);
    // Unwrap first: every `invalid` case (modified IV, bad size) must fail
    // here regardless of what wrapping would produce.
    let mut pt = vec![0u8; ct.len().saturating_sub(8)];
    if kw.unwrap(&ct, &mut pt).is_err() {
        return Outcome::Rejected;
    }
    if pt != msg {
        return Outcome::Wrong("unwrapped key");
    }
    let mut out = vec![0u8; kw_ciphertext_len(msg.len())];
    match kw.wrap(&msg, &mut out) {
        Err(_) => Outcome::Wrong("wrap refused an unwrappable input"),
        Ok(()) => check_eq(&out, &ct, "wrapped key"),
    }
}

fn kwp_case<C: BlockCipher>(cipher: C, _: &Fields, case: &Fields) -> Outcome {
    let msg = case.hex("msg");
    let ct = case.hex("ct");
    let kwp = AesKwp::new(cipher);
    let mut pt = vec![0u8; ct.len().saturating_sub(8)];
    let n = match kwp.unwrap(&ct, &mut pt) {
        Ok(n) => n,
        Err(_) => return Outcome::Rejected,
    };
    if pt[..n] != msg[..] {
        return Outcome::Wrong("unwrapped key");
    }
    let mut out = vec![0u8; kwp_ciphertext_len(msg.len())];
    match kwp.wrap(&msg, &mut out) {
        Err(_) => Outcome::Wrong("wrap refused an unwrappable input"),
        Ok(()) => check_eq(&out, &ct, "wrapped key"),
    }
}

// ---- AES-SIV (RFC 5297) ----------------------------------------------------

/// Runs one SIV case: `blob` is the `V ‖ C` form the crate speaks, `ad` the
/// S2V header components.
#[cfg(feature = "alloc")]
fn siv_case(_: &Fields, case: &Fields, ad: &[&[u8]], blob: &[u8]) -> Outcome {
    // `AesSiv::try_new` selects AES-128/192/256-SIV from the 32/48/64-byte
    // key; any other length is a rejection.
    let Ok(siv) = AesSiv::try_new(&case.hex("key")) else {
        return Outcome::Rejected;
    };
    let msg = case.hex("msg");
    match siv.try_open(ad, blob) {
        Err(_) => return Outcome::Rejected,
        Ok(pt) if pt != msg => return Outcome::Wrong("decrypted plaintext"),
        Ok(_) => {}
    }
    match siv.try_seal(ad, &msg) {
        Err(_) => Outcome::Wrong("seal refused an openable input"),
        Ok(out) => check_eq(&out, blob, "V || ciphertext"),
    }
}

/// Deterministic form: one header (`aad`), output is `V ‖ C` as in the
/// vectors' `ct`.
#[cfg(feature = "alloc")]
#[test]
fn aes_siv_cmac() {
    check("aes_siv_cmac", |group, case| {
        siv_case(group, case, &[&case.hex("aad")], &case.hex("ct"))
    });
}

/// AEAD form (RFC 5297 §3): the nonce is the last S2V component and the
/// vectors split the output into `tag` (= V) and `ct`.
#[cfg(feature = "alloc")]
#[test]
fn aead_aes_siv_cmac() {
    check("aead_aes_siv_cmac", |group, case| {
        let mut blob = case.hex("tag");
        blob.extend_from_slice(&case.hex("ct"));
        siv_case(group, case, &[&case.hex("aad"), &case.hex("iv")], &blob)
    });
}

// ---- XTS -------------------------------------------------------------------

fn xts_case<C: BlockCipher>(xts: Xts<C>, case: &Fields) -> Outcome {
    // The vectors' `iv` is the raw 128-bit tweak block, given as 1..=16
    // bytes and zero-padded on the right. `Xts` derives its tweak block from
    // a little-endian sector index, so the same bytes read little-endian
    // reproduce it exactly.
    let iv = case.hex("iv");
    if iv.len() > 16 {
        return Outcome::Rejected;
    }
    let mut t = [0u8; 16];
    t[..iv.len()].copy_from_slice(&iv);
    let tweak = u128::from_le_bytes(t);
    let msg = case.hex("msg");
    let ct = case.hex("ct");
    let mut buf = ct.clone();
    if xts.decrypt_sector_checked(tweak, &mut buf).is_err() {
        return Outcome::Rejected;
    }
    if buf != msg {
        return Outcome::Wrong("decrypted plaintext");
    }
    let mut buf = msg.clone();
    match xts.encrypt_sector_checked(tweak, &mut buf) {
        Err(_) => Outcome::Wrong("encrypt refused a decryptable input"),
        Ok(()) => check_eq(&buf, &ct, "ciphertext"),
    }
}

#[test]
fn aes_xts() {
    check("aes_xts", |_, case| {
        let key = case.hex("key");
        let (k1, k2) = key.split_at(key.len() / 2);
        macro_rules! pair {
            ($c:ident) => {
                Xts::new(
                    $c::new(k1.try_into().unwrap()),
                    $c::new(k2.try_into().unwrap()),
                )
            };
        }
        match key.len() {
            32 => xts_case(pair!(Aes128), case),
            48 => xts_case(pair!(Aes192), case),
            64 => xts_case(pair!(Aes256), case),
            _ => Outcome::Rejected,
        }
    });
}
