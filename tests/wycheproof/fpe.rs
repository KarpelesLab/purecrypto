//! FF1 format-preserving encryption (NIST SP 800-38G) over AES-128/192/256:
//! the digit-list files (`aes_ff1_radix*`, `msg`/`ct` as comma-joined digits)
//! and the alphabet files (`aes_ff1_base*`, `msg`/`ct` as text over the
//! group's `alphabet`).
//!
//! The crate implements the SP 800-38G Rev. 1 domain floor
//! (`radix^n >= 10^6`), while the vectors follow the 2016 edition
//! (`>= 100`): a `SmallMessageSize` case must be refused by [`Ff1::new`] and
//! is then checked against [`Ff1::new_legacy`], so every `valid` case is
//! exercised and nothing is skipped.

use crate::common::{Fields, Outcome, check};
use purecrypto::cipher::{Aes128, Aes192, Aes256, BlockCipher};
use purecrypto::fpe::{Alphabet, Ff1};

/// One `#[test]` per file, keying AES from the case's `key` (any other
/// length is `InvalidKeySize`, rejected) and handing the cipher to the
/// file's case function.
macro_rules! ff1_tests {
    ($($name:ident = $case:ident;)*) => {$(
        #[test]
        fn $name() {
            check(stringify!($name), |group, case| {
                let key = case.hex("key");
                match key.len() {
                    16 => $case(Aes128::new(&key.try_into().unwrap()), group, case),
                    24 => $case(Aes192::new(&key.try_into().unwrap()), group, case),
                    32 => $case(Aes256::new(&key.try_into().unwrap()), group, case),
                    _ => Outcome::Rejected,
                }
            });
        }
    )*};
}

ff1_tests! {
    aes_ff1_radix10 = list_case;
    aes_ff1_radix16 = list_case;
    aes_ff1_radix26 = list_case;
    aes_ff1_radix32 = list_case;
    aes_ff1_radix36 = list_case;
    aes_ff1_radix45 = list_case;
    aes_ff1_radix62 = list_case;
    aes_ff1_radix64 = list_case;
    aes_ff1_radix85 = list_case;
    aes_ff1_radix255 = list_case;
    aes_ff1_radix256 = list_case;
    aes_ff1_radix65535 = list_case;
    aes_ff1_radix65536 = list_case;
    aes_ff1_base10 = str_case;
    aes_ff1_base16 = str_case;
    aes_ff1_base26 = str_case;
    aes_ff1_base32 = str_case;
    aes_ff1_base36 = str_case;
    aes_ff1_base45 = str_case;
    aes_ff1_base62 = str_case;
    aes_ff1_base64 = str_case;
    aes_ff1_base85 = str_case;
}

/// Runs `f` against the Rev. 1 instance. A `SmallMessageSize` case
/// (`100 <= radix^n < 10^6`, valid under the 2016 edition only) must be
/// refused there; it is then run against the legacy floor, whose result is
/// the case's outcome.
fn with_floor<C: BlockCipher + Clone>(
    cipher: C,
    radix: u32,
    case: &Fields,
    f: impl Fn(&Ff1<C>) -> Outcome,
) -> Outcome {
    let Ok(ff1) = Ff1::new(cipher.clone(), radix) else {
        return Outcome::Rejected;
    };
    let outcome = f(&ff1);
    if !case.has_flag("SmallMessageSize") {
        return outcome;
    }
    match outcome {
        Outcome::Rejected => {
            let legacy = Ff1::new_legacy(cipher, radix).expect("radix already accepted");
            f(&legacy)
        }
        _ => Outcome::Wrong("Rev. 1 floor accepted a message with radix^n < 10^6"),
    }
}

/// A comma-joined digit list (empty for the empty string); `None` when an
/// entry is not a `u16` (negative, or `>= 65536`).
fn parse_digits(s: &str) -> Option<Vec<u16>> {
    if s.is_empty() {
        return Some(Vec::new());
    }
    s.split(',').map(|d| d.parse().ok()).collect()
}

fn list_case<C: BlockCipher + Clone>(cipher: C, group: &Fields, case: &Fields) -> Outcome {
    let radix = group.int("radix") as u32;
    let tweak = case.hex("tweak");
    let Some(msg) = parse_digits(case.str("msg")) else {
        return Outcome::Rejected;
    };
    let ct = parse_digits(case.str("ct"));
    with_floor(cipher, radix, case, |ff1| {
        let Ok(out) = ff1.encrypt(&tweak, &msg) else {
            return Outcome::Rejected;
        };
        if ct.as_deref() != Some(out.as_slice()) {
            return Outcome::Wrong("ciphertext");
        }
        match ff1.decrypt(&tweak, &out) {
            Ok(back) if back == msg => Outcome::Accepted,
            Ok(_) => Outcome::Wrong("decrypted plaintext"),
            Err(_) => Outcome::Wrong("decrypt refused its own ciphertext"),
        }
    })
}

fn str_case<C: BlockCipher + Clone>(cipher: C, group: &Fields, case: &Fields) -> Outcome {
    let radix = group.int("radix") as u32;
    let alphabet = Alphabet::new(group.str("alphabet")).expect("well-formed alphabet");
    assert_eq!(alphabet.radix(), radix, "alphabet size vs radix");
    let tweak = case.hex("tweak");
    let msg = case.str("msg");
    let ct = case.str("ct");
    with_floor(cipher, radix, case, |ff1| {
        let Ok(out) = ff1.encrypt_str(&alphabet, &tweak, msg) else {
            return Outcome::Rejected;
        };
        if out != ct {
            return Outcome::Wrong("ciphertext");
        }
        match ff1.decrypt_str(&alphabet, &tweak, &out) {
            Ok(back) if back == msg => Outcome::Accepted,
            Ok(_) => Outcome::Wrong("decrypted plaintext"),
            Err(_) => Outcome::Wrong("decrypt refused its own ciphertext"),
        }
    })
}
