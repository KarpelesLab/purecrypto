//! RSA: PKCS#1 v1.5 signatures (verify + deterministic sign), RSASSA-PSS
//! (MGF1 and the RFC 8702 SHAKE forms), RSAES-OAEP (two-prime and
//! multi-prime keys) and RSAES-PKCS1-v1_5 decryption, and the primality
//! vectors.
//!
//! Groups whose MGF1 hash differs from the message hash (`mgfSha != sha`:
//! the `*_mgf1sha1` / `*_mgf1sha256` files and the mixed groups of
//! `rsa_pss_misc*` and `rsa_oaep_misc`) go through the `*_mgf::<D, M>`
//! forms of the API; the equal-hash groups keep using the single-digest
//! forms, so both surfaces are exercised. The `rsa_pss_*_shake*` groups
//! (`sha = mgf = SHAKE128/256`) go through `verify_pss_shake*::<X>`, and
//! the `rsa_three_primes_oaep_*` groups through a key parsed from the
//! multi-prime PKCS#8 blob and, separately, one built from the
//! `privateKey` components including `otherPrimeInfos`.

use crate::common::{Expected, Fields, Outcome, check_eq, load, outcome_of, run_with};
use purecrypto::bignum::{BoxedUint, Uint};
use purecrypto::hash::{
    Sha1, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha224, Sha256, Sha384, Sha512, Sha512_224,
    Sha512_256, Shake128, Shake256,
};
use purecrypto::rng::HmacDrbg;
use purecrypto::rsa::{BoxedRsaPrivateKey, BoxedRsaPublicKey, is_prime};

/// Runs `$body` with `$D` bound to the digest type named by a Wycheproof
/// `sha` field; an unknown name yields [`Outcome::Skipped`].
///
/// [`with_mgf_digest`] is the same dispatch over the `mgfSha` field, kept
/// to the digests the PSS / OAEP files actually pair with MGF1 (the SHA-1
/// and SHA-2 families) so the nested `sha` x `mgfSha` dispatch stays a
/// manageable number of monomorphisations.
macro_rules! with_digest {
    ($name:expr, $D:ident => $body:expr) => {
        match $name {
            "SHA-1" => {
                type $D = Sha1;
                $body
            }
            "SHA-224" => {
                type $D = Sha224;
                $body
            }
            "SHA-256" => {
                type $D = Sha256;
                $body
            }
            "SHA-384" => {
                type $D = Sha384;
                $body
            }
            "SHA-512" => {
                type $D = Sha512;
                $body
            }
            "SHA-512/224" => {
                type $D = Sha512_224;
                $body
            }
            "SHA-512/256" => {
                type $D = Sha512_256;
                $body
            }
            "SHA3-224" => {
                type $D = Sha3_224;
                $body
            }
            "SHA3-256" => {
                type $D = Sha3_256;
                $body
            }
            "SHA3-384" => {
                type $D = Sha3_384;
                $body
            }
            "SHA3-512" => {
                type $D = Sha3_512;
                $body
            }
            _ => Outcome::Skipped,
        }
    };
}

macro_rules! with_mgf_digest {
    ($name:expr, $M:ident => $body:expr) => {
        match $name {
            "SHA-1" => {
                type $M = Sha1;
                $body
            }
            "SHA-224" => {
                type $M = Sha224;
                $body
            }
            "SHA-256" => {
                type $M = Sha256;
                $body
            }
            "SHA-384" => {
                type $M = Sha384;
                $body
            }
            "SHA-512" => {
                type $M = Sha512;
                $body
            }
            "SHA-512/224" => {
                type $M = Sha512_224;
                $body
            }
            "SHA-512/256" => {
                type $M = Sha512_256;
                $body
            }
            _ => Outcome::Skipped,
        }
    };
}

/// Pins every `acceptable` case to what the crate does, so a change in
/// behaviour shows up instead of passing either way:
/// * `MissingNull` (a DigestInfo without the NULL parameters) is rejected —
///   the prefix comparison is exact (RFC 8017 §9.2 Note 1 form only).
/// * `NegativeOfPrime` is rejected by this harness before the call, see
///   [`primality`].
/// * Everything else (`WeakHash` / `SmallModulus` signing with SHA-1 and
///   1024-bit keys, `SmallIntegerCiphertext` OAEP ciphertexts with leading
///   zero octets) must succeed with the exact expected output.
fn policy(_: &Fields, case: &Fields) -> Option<Expected> {
    if case.has_flag("MissingNull") || case.has_flag("NegativeOfPrime") {
        Some(Expected::Invalid)
    } else {
        Some(Expected::Valid)
    }
}

/// One-entry cache so a group's key (whose Montgomery / CRT precomputation
/// is the expensive part) is parsed once rather than once per case.
struct Cached<K>(Option<(String, K)>);

impl<K> Cached<K> {
    fn new() -> Self {
        Cached(None)
    }
    fn get(&mut self, id: &str, make: impl FnOnce() -> K) -> &K {
        if self.0.as_ref().is_none_or(|(k, _)| k != id) {
            self.0 = Some((id.to_string(), make()));
        }
        &self.0.as_ref().unwrap().1
    }
}

/// The group's public key: from the SPKI for plain `rsaEncryption` keys, or
/// from the bare `RSAPublicKey` when the SPKI is an `id-RSASSA-PSS` one
/// (`*_params` files) — the crate only parses `rsaEncryption` SPKIs, so the
/// PSS parameters are taken from the group fields instead.
fn public_key(group: &Fields, pss_spki: bool) -> BoxedRsaPublicKey {
    let spki = BoxedRsaPublicKey::from_spki_der(&group.hex("publicKeyDer"));
    if pss_spki {
        assert!(
            spki.is_err(),
            "an id-RSASSA-PSS SPKI parsed as rsaEncryption"
        );
        BoxedRsaPublicKey::from_pkcs1_der(&group.hex("publicKeyAsn")).expect("RSAPublicKey")
    } else {
        spki.expect("SPKI")
    }
}

fn private_key(group: &Fields) -> BoxedRsaPrivateKey {
    BoxedRsaPrivateKey::from_pkcs8_der(&group.hex("privateKeyPkcs8")).expect("PKCS#8")
}

/// The hex value of `"key":"…"` in the compact JSON object `json` (the
/// group's `privateKey` field), decoded.
fn json_hex(json: &str, key: &str) -> Vec<u8> {
    let needle = format!("\"{key}\":\"");
    let start = json
        .find(&needle)
        .unwrap_or_else(|| panic!("no {key:?} in {json}"))
        + needle.len();
    let end = start + json[start..].find('"').expect("unterminated string");
    crate::common::from_hex(&json[start..end])
}

/// The `"otherPrimeInfos":[["r","d","t"],…]` triples of the group's
/// `privateKey` JSON, each decoded from hex.
fn json_other_prime_infos(json: &str) -> Vec<[Vec<u8>; 3]> {
    let needle = "\"otherPrimeInfos\":[";
    let start = json.find(needle).expect("no otherPrimeInfos") + needle.len();
    let mut out = Vec::new();
    let mut rest = &json[start..];
    while let Some(open) = rest.find('[') {
        let close = open + rest[open..].find(']').expect("unterminated triple");
        let triple: Vec<Vec<u8>> = rest[open + 1..close]
            .split(',')
            .map(|s| crate::common::from_hex(s.trim_matches('"')))
            .collect();
        out.push(triple.try_into().expect("prime, exponent, coefficient"));
        rest = &rest[close + 1..];
        if rest.starts_with(']') {
            break;
        }
    }
    assert!(!out.is_empty(), "empty otherPrimeInfos");
    out
}

/// A multi-prime private key assembled from the group's `privateKey`
/// components — `n`, `e`, `d`, `prime1`, `prime2` and the primes of
/// `otherPrimeInfos` (the blob's `exponent` / `coefficient` values are
/// recomputed by the crate and only sanity-checked here against the
/// PKCS#8-parsed key's serialization).
fn multi_prime_key_from_components(group: &Fields) -> BoxedRsaPrivateKey {
    let json = group.str("privateKey");
    let be = |key: &str| BoxedUint::from_be_bytes(&json_hex(json, key));
    let others = json_other_prime_infos(json);
    let key = BoxedRsaPrivateKey::from_components_with_other_primes(
        be("modulus"),
        be("publicExponent"),
        be("privateExponent"),
        be("prime1"),
        be("prime2"),
        others
            .iter()
            .map(|[r, _, _]| BoxedUint::from_be_bytes(r))
            .collect(),
    );
    assert_eq!(key.num_primes(), 2 + others.len());
    // The two constructions agree byte for byte on the PKCS#1 encoding —
    // which also pins the crate's derived `d_i` / `t_i` to the file's.
    let parsed = private_key(group);
    assert_eq!(parsed.num_primes(), key.num_primes());
    let der = key.to_pkcs1_der();
    assert_eq!(parsed.to_pkcs1_der(), der);
    let mut infos = purecrypto::der::Reader::new(&der);
    let mut seq = infos.read_sequence().unwrap();
    assert_eq!(seq.read_integer_bytes().unwrap(), [1], "version = 1");
    for _ in 0..8 {
        seq.read_unsigned_integer_bytes().unwrap();
    }
    let mut list = seq.read_sequence().unwrap();
    for [r, d_i, t_i] in &others {
        let mut info = list.read_sequence().unwrap();
        assert_eq!(info.read_unsigned_integer_bytes().unwrap(), r);
        assert_eq!(info.read_unsigned_integer_bytes().unwrap(), d_i);
        assert_eq!(info.read_unsigned_integer_bytes().unwrap(), t_i);
        info.finish().unwrap();
    }
    list.finish().unwrap();
    key
}

/// PKCS#1 v1.5 verification. `MissingNull` cases (`acceptable`) are
/// rejected: the DigestInfo prefix is compared byte for byte and always
/// carries the NULL parameters (RFC 8017 §9.2 Note 1).
#[test]
fn pkcs1v15_verify() {
    for name in [
        "rsa_signature_2048_sha224",
        "rsa_signature_2048_sha256",
        "rsa_signature_2048_sha384",
        "rsa_signature_2048_sha512",
        "rsa_signature_2048_sha512_224",
        "rsa_signature_2048_sha512_256",
        "rsa_signature_2048_sha3_224",
        "rsa_signature_2048_sha3_256",
        "rsa_signature_2048_sha3_384",
        "rsa_signature_2048_sha3_512",
        "rsa_signature_3072_sha256",
        "rsa_signature_3072_sha384",
        "rsa_signature_3072_sha512",
        "rsa_signature_3072_sha512_256",
        "rsa_signature_3072_sha3_256",
        "rsa_signature_3072_sha3_384",
        "rsa_signature_3072_sha3_512",
        "rsa_signature_4096_sha256",
        "rsa_signature_4096_sha384",
        "rsa_signature_4096_sha512",
        "rsa_signature_4096_sha512_256",
        "rsa_signature_8192_sha256",
        "rsa_signature_8192_sha384",
        "rsa_signature_8192_sha512",
    ] {
        let mut keys = Cached::new();
        run_with(&load(name), policy, |group, case| {
            let pk = keys.get(group.str("publicKeyDer"), || public_key(group, false));
            let (msg, sig) = (case.hex("msg"), case.hex("sig"));
            with_digest!(group.str("sha"), D => outcome_of(pk.verify_pkcs1v15::<D>(&msg, &sig)))
        });
    }
}

/// Deterministic PKCS#1 v1.5 signing: the output must be bit-exact.
#[test]
fn pkcs1v15_sign() {
    for name in [
        "rsa_pkcs1_1024_sig_gen",
        "rsa_pkcs1_1536_sig_gen",
        "rsa_pkcs1_2048_sig_gen",
        "rsa_pkcs1_3072_sig_gen",
        "rsa_pkcs1_4096_sig_gen",
    ] {
        let mut keys = Cached::new();
        run_with(&load(name), policy, |group, case| {
            let sk = keys.get(group.str("privateKeyPkcs8"), || private_key(group));
            let msg = case.hex("msg");
            with_digest!(group.str("sha"), D => match sk.sign_pkcs1v15::<D>(&msg) {
                Ok(sig) => check_eq(&sig, &case.hex("sig"), "signature"),
                Err(_) => Outcome::Rejected,
            })
        });
    }
}

/// RSASSA-PSS verification with the group's hash, MGF1 hash and salt
/// length: the single-digest verifier when `mgfSha == sha`, the `_mgf` one
/// otherwise. A signature accepted at the exact salt length must also be
/// accepted by the salt-recovering verifier.
#[test]
fn pss_verify() {
    for (name, pss_spki) in [
        ("rsa_pss_2048_sha1_mgf1_20", false),
        ("rsa_pss_2048_sha1_mgf1_20_params", true),
        ("rsa_pss_2048_sha256_mgf1_0", false),
        ("rsa_pss_2048_sha256_mgf1_0_params", true),
        ("rsa_pss_2048_sha256_mgf1_32", false),
        ("rsa_pss_2048_sha256_mgf1_32_params", true),
        ("rsa_pss_2048_sha256_mgf1sha1_20", false),
        ("rsa_pss_2048_sha384_mgf1_48", false),
        ("rsa_pss_2048_sha512_224_mgf1_28", false),
        ("rsa_pss_2048_sha512_256_mgf1_32", false),
        ("rsa_pss_2048_sha512_mgf1sha256_32_params", true),
        ("rsa_pss_3072_sha256_mgf1_32", false),
        ("rsa_pss_3072_sha256_mgf1_32_params", true),
        ("rsa_pss_4096_sha256_mgf1_32", false),
        ("rsa_pss_4096_sha384_mgf1_48", false),
        ("rsa_pss_4096_sha512_mgf1_32", false),
        ("rsa_pss_4096_sha512_mgf1_32_params", true),
        ("rsa_pss_4096_sha512_mgf1_64", false),
        ("rsa_pss_4096_sha512_mgf1_64_params", true),
        ("rsa_pss_misc", false),
        ("rsa_pss_misc_params", true),
    ] {
        let mut keys = Cached::new();
        run_with(&load(name), policy, |group, case| {
            if group.str("mgf") != "MGF1" {
                return Outcome::Skipped; // SHAKE-PSS (RFC 8702): unsupported
            }
            let pk = keys.get(group.str("publicKeyDer"), || public_key(group, pss_spki));
            let (msg, sig) = (case.hex("msg"), case.hex("sig"));
            let slen = group.int("sLen") as usize;
            let (sha, mgf_sha) = (group.str("sha"), group.str("mgfSha"));
            if sha == mgf_sha {
                with_digest!(sha, D => {
                    match pk.verify_pss_with_salt_len::<D>(&msg, &sig, slen) {
                        Err(_) => Outcome::Rejected,
                        Ok(()) if pk.verify_pss_any_salt::<D>(&msg, &sig).is_err() => {
                            Outcome::Wrong("any-salt verify disagrees")
                        }
                        Ok(()) => Outcome::Accepted,
                    }
                })
            } else {
                with_digest!(sha, D => with_mgf_digest!(mgf_sha, M => {
                    match pk.verify_pss_with_salt_len_mgf::<D, M>(&msg, &sig, slen) {
                        Err(_) => Outcome::Rejected,
                        Ok(()) if pk.verify_pss_any_salt_mgf::<D, M>(&msg, &sig).is_err() => {
                            Outcome::Wrong("any-salt verify disagrees")
                        }
                        Ok(()) => Outcome::Accepted,
                    }
                }))
            }
        });
    }
}

/// RSASSA-PSS with SHAKE (RFC 8702): `sha = mgf = SHAKE128` (hLen 32) or
/// `SHAKE256` (hLen 64), verified at the group's `sLen` — which is the
/// RFC 8702 profile's hash length, so the strict `verify_pss_shake` (no
/// explicit salt length) must agree, as must the salt-recovering verifier.
#[test]
fn pss_verify_shake() {
    for name in [
        "rsa_pss_2048_shake128",
        "rsa_pss_2048_shake256",
        "rsa_pss_3072_shake128",
        "rsa_pss_3072_shake256",
        "rsa_pss_4096_shake256",
    ] {
        let mut keys = Cached::new();
        run_with(&load(name), policy, |group, case| {
            let pk = keys.get(group.str("publicKeyDer"), || public_key(group, false));
            let (msg, sig) = (case.hex("msg"), case.hex("sig"));
            let slen = group.int("sLen") as usize;
            assert_eq!(group.str("sha"), group.str("mgf"), "SHAKE is hash and MGF");
            macro_rules! verify {
                ($X:ty) => {{
                    assert_eq!(slen, <$X as purecrypto::rsa::PssShake>::OUTPUT_LEN);
                    match pk.verify_pss_shake_with_salt_len::<$X>(&msg, &sig, slen) {
                        Err(_) => {
                            if pk.verify_pss_shake::<$X>(&msg, &sig).is_ok() {
                                Outcome::Wrong("profile verify disagrees")
                            } else {
                                Outcome::Rejected
                            }
                        }
                        Ok(()) if pk.verify_pss_shake::<$X>(&msg, &sig).is_err() => {
                            Outcome::Wrong("profile verify disagrees")
                        }
                        Ok(()) if pk.verify_pss_shake_any_salt::<$X>(&msg, &sig).is_err() => {
                            Outcome::Wrong("any-salt verify disagrees")
                        }
                        Ok(()) => Outcome::Accepted,
                    }
                }};
            }
            match group.str("sha") {
                "SHAKE128" => verify!(Shake128),
                "SHAKE256" => verify!(Shake256),
                _ => Outcome::Skipped,
            }
        });
    }
}

/// RSAES-OAEP decryption under a three-prime key (RFC 8017 §3.2), twice:
/// with the key parsed from the multi-prime PKCS#8 blob and with one built
/// from the `privateKey` components (`prime1`, `prime2`, `otherPrimeInfos`).
/// Both must produce the same outcome on every case.
#[test]
fn three_primes_oaep_decrypt() {
    for name in [
        "rsa_three_primes_oaep_2048_sha1_mgf1sha1",
        "rsa_three_primes_oaep_3072_sha224_mgf1sha224",
        "rsa_three_primes_oaep_4096_sha256_mgf1sha256",
    ] {
        let mut keys = Cached::new();
        run_with(&load(name), policy, |group, case| {
            let (sk, sk2) = keys.get(group.str("privateKeyPkcs8"), || {
                (private_key(group), multi_prime_key_from_components(group))
            });
            assert_eq!(sk.num_primes(), 3);
            let (ct, label) = (case.hex("ct"), case.hex("label"));
            let (sha, mgf_sha) = (group.str("sha"), group.str("mgfSha"));
            let decrypt = |k: &BoxedRsaPrivateKey| {
                if sha == mgf_sha {
                    with_digest!(sha, D => match k.decrypt_oaep::<D>(&ct, &label) {
                        Ok(msg) => check_eq(&msg, &case.hex("msg"), "plaintext"),
                        Err(_) => Outcome::Rejected,
                    })
                } else {
                    with_digest!(sha, D => with_mgf_digest!(mgf_sha, M => {
                        match k.decrypt_oaep_mgf::<D, M>(&ct, &label) {
                            Ok(msg) => check_eq(&msg, &case.hex("msg"), "plaintext"),
                            Err(_) => Outcome::Rejected,
                        }
                    }))
                }
            };
            let (a, b) = (decrypt(sk), decrypt(sk2));
            if a != b {
                return Outcome::Wrong("PKCS#8 and component keys disagree");
            }
            a
        });
    }
}

/// RSAES-OAEP decryption with label: the single-digest decryptor when
/// `mgfSha == sha`, the `_mgf` one otherwise.
#[test]
fn oaep_decrypt() {
    for name in [
        "rsa_oaep_2048_sha1_mgf1sha1",
        "rsa_oaep_2048_sha224_mgf1sha1",
        "rsa_oaep_2048_sha224_mgf1sha224",
        "rsa_oaep_2048_sha256_mgf1sha1",
        "rsa_oaep_2048_sha256_mgf1sha256",
        "rsa_oaep_2048_sha384_mgf1sha1",
        "rsa_oaep_2048_sha384_mgf1sha384",
        "rsa_oaep_2048_sha512_224_mgf1sha1",
        "rsa_oaep_2048_sha512_224_mgf1sha512_224",
        "rsa_oaep_2048_sha512_mgf1sha1",
        "rsa_oaep_2048_sha512_mgf1sha512",
        "rsa_oaep_3072_sha256_mgf1sha1",
        "rsa_oaep_3072_sha256_mgf1sha256",
        "rsa_oaep_3072_sha512_256_mgf1sha1",
        "rsa_oaep_3072_sha512_256_mgf1sha512_256",
        "rsa_oaep_3072_sha512_mgf1sha1",
        "rsa_oaep_3072_sha512_mgf1sha512",
        "rsa_oaep_4096_sha256_mgf1sha1",
        "rsa_oaep_4096_sha256_mgf1sha256",
        "rsa_oaep_4096_sha512_mgf1sha1",
        "rsa_oaep_4096_sha512_mgf1sha512",
        "rsa_oaep_misc",
    ] {
        let mut keys = Cached::new();
        run_with(&load(name), policy, |group, case| {
            if group.str("mgf") != "MGF1" {
                return Outcome::Skipped;
            }
            let sk = keys.get(group.str("privateKeyPkcs8"), || private_key(group));
            let (ct, label) = (case.hex("ct"), case.hex("label"));
            let (sha, mgf_sha) = (group.str("sha"), group.str("mgfSha"));
            if sha == mgf_sha {
                with_digest!(sha, D => match sk.decrypt_oaep::<D>(&ct, &label) {
                    Ok(msg) => check_eq(&msg, &case.hex("msg"), "plaintext"),
                    Err(_) => Outcome::Rejected,
                })
            } else {
                with_digest!(sha, D => with_mgf_digest!(mgf_sha, M => {
                    match sk.decrypt_oaep_mgf::<D, M>(&ct, &label) {
                        Ok(msg) => check_eq(&msg, &case.hex("msg"), "plaintext"),
                        Err(_) => Outcome::Rejected,
                    }
                }))
            }
        });
    }
}

/// RSAES-PKCS1-v1_5 decryption through `decrypt_pkcs1v15`, the variant
/// that reports a padding failure as an error — the contract these vectors
/// test. (`decrypt_pkcs1v15_implicit` deliberately never fails on bad
/// padding; it is checked here only to agree with the plain variant on the
/// well-formed ciphertexts.)
#[test]
fn pkcs1v15_decrypt() {
    for name in ["rsa_pkcs1_2048", "rsa_pkcs1_3072", "rsa_pkcs1_4096"] {
        let mut keys = Cached::new();
        run_with(&load(name), policy, |group, case| {
            let sk = keys.get(group.str("privateKeyPkcs8"), || private_key(group));
            let ct = case.hex("ct");
            match sk.decrypt_pkcs1v15(&ct) {
                Err(_) => Outcome::Rejected,
                Ok(msg) if sk.decrypt_pkcs1v15_implicit(&ct).as_deref() != Ok(&msg[..]) => {
                    Outcome::Wrong("implicit-rejection variant disagrees")
                }
                Ok(msg) => check_eq(&msg, &case.hex("msg"), "plaintext"),
            }
        });
    }
}

/// Miller-Rabin rounds for the primality vectors. Random bases from a
/// seeded DRBG defeat the fixed-base pseudoprimes in the file; 32 rounds
/// leave a composite at most a 2⁻⁶⁴ chance of slipping through.
const MR_ROUNDS: usize = 32;

/// Dispatches `is_prime` over the smallest `Uint` that holds `v`.
fn is_prime_bytes(v: &[u8], rng: &mut HmacDrbg<Sha256>) -> bool {
    macro_rules! at {
        ($limbs:literal) => {
            is_prime(&Uint::<$limbs>::from_be_bytes(v), rng, MR_ROUNDS)
        };
    }
    match v.len() {
        0..=8 => at!(1),
        9..=16 => at!(2),
        17..=32 => at!(4),
        33..=64 => at!(8),
        65..=128 => at!(16),
        129..=256 => at!(32),
        257..=512 => at!(64),
        _ => panic!("primality vector of {} bytes", v.len()),
    }
}

/// `value` is a two's-complement big-endian integer. Negative values
/// (`NegativeOfPrime`, `acceptable`) cannot be expressed by the unsigned
/// API and are reported as rejected without calling it.
#[test]
fn primality() {
    let mut rng = HmacDrbg::<Sha256>::new(b"wycheproof-primality", b"", &[]);
    run_with(&load("primality"), policy, |_, case| {
        let v = case.hex("value");
        if v.first().is_some_and(|b| b & 0x80 != 0) {
            return Outcome::Rejected;
        }
        let v = &v[v.iter().position(|&b| b != 0).unwrap_or(v.len())..];
        if is_prime_bytes(v, &mut rng) {
            Outcome::Accepted
        } else {
            Outcome::Rejected
        }
    });
}
