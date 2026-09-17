//! ECDSA verification over every supported curve and hash: DER
//! (`Ecdsa-Sig-Value`) and P1363 (fixed-width `r ‖ s`) signatures, plus the
//! Bitcoin low-S variant. Every group's key also goes through the SPKI
//! parser, and the P-256 / secp256k1 specialised types are checked against
//! the boxed implementation on their files.
//!
//! The DER parser is `BoxedEcdsaSignature::from_der_for_curve`, so the crate
//! needs its `der` feature here; the SPKI check needs `x509`.
#![cfg(feature = "der")]

use crate::common::{Fields, Outcome, check, outcome_of};
use purecrypto::bignum::BoxedUint;
use purecrypto::ec::ecdsa::{EcdsaPublicKey, Signature as P256Signature};
use purecrypto::ec::{
    BoxedEcdsaPublicKey, BoxedEcdsaSignature, CurveId, Secp256k1EcdsaPublicKey,
    Secp256k1EcdsaSignature,
};
use purecrypto::hash::{
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha224, Sha256, Sha384, Sha512, shake128, shake256,
};

/// How the `sig` field is encoded.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Enc {
    /// DER `Ecdsa-Sig-Value`; anything BER or otherwise lax must be rejected.
    Der,
    /// Fixed-width `r ‖ s`, each half the width of the group order.
    P1363,
    /// DER, and `s` must be in the low half of the order (BIP-62).
    Bitcoin,
}

impl Enc {
    fn of(file: &str) -> Enc {
        if file.ends_with("_p1363") {
            Enc::P1363
        } else if file.ends_with("_bitcoin") {
            Enc::Bitcoin
        } else {
            Enc::Der
        }
    }
}

fn curve_of(name: &str) -> CurveId {
    match name {
        "secp256r1" => CurveId::P256,
        "secp384r1" => CurveId::P384,
        "secp521r1" => CurveId::P521,
        "secp256k1" => CurveId::Secp256k1,
        "brainpoolP256r1" => CurveId::BrainpoolP256r1,
        "brainpoolP384r1" => CurveId::BrainpoolP384r1,
        "brainpoolP512r1" => CurveId::BrainpoolP512r1,
        "secp160k1" => CurveId::Secp160k1,
        "secp160r1" => CurveId::Secp160r1,
        "secp160r2" => CurveId::Secp160r2,
        "secp192k1" => CurveId::Secp192k1,
        "secp192r1" => CurveId::P192,
        "secp224k1" => CurveId::Secp224k1,
        "secp224r1" => CurveId::P224,
        "brainpoolP224r1" => CurveId::BrainpoolP224r1,
        "brainpoolP320r1" => CurveId::BrainpoolP320r1,
        other => panic!("unsupported curve {other}"),
    }
}

/// The group's public key, parsed from SEC1. The SPKI form is parsed too and
/// must decode to the same point, so the DER key path is exercised on every
/// group (the `x509` feature owns the public SPKI parser).
fn public_key(group: &Fields) -> BoxedEcdsaPublicKey {
    let curve = curve_of(group.str("publicKey.curve"));
    let pk = BoxedEcdsaPublicKey::from_sec1(curve, &group.hex("publicKey.uncompressed"))
        .expect("group public key is valid");
    #[cfg(feature = "x509")]
    {
        use purecrypto::x509::AnyPublicKey;
        match AnyPublicKey::from_spki_der(&group.hex("publicKeyDer")) {
            Ok(AnyPublicKey::Ecdsa(spki)) => {
                assert_eq!(spki.curve(), curve, "SPKI curve");
                assert_eq!(spki.to_sec1(), pk.to_sec1(), "SPKI key disagrees with SEC1");
            }
            other => panic!("SPKI parse of the group key: {other:?}"),
        }
    }
    pk
}

/// Verifies with the group's hash. SHAKE has no `Digest` impl (it is an
/// XOF), so those go through `verify_prehash` with the output lengths
/// Wycheproof fixes: 256 bits for SHAKE128, 512 for SHAKE256.
fn verify(pk: &BoxedEcdsaPublicKey, sha: &str, msg: &[u8], sig: &BoxedEcdsaSignature) -> Outcome {
    outcome_of(match sha {
        "SHA-224" => pk.verify::<Sha224>(msg, sig),
        "SHA-256" => pk.verify::<Sha256>(msg, sig),
        "SHA-384" => pk.verify::<Sha384>(msg, sig),
        "SHA-512" => pk.verify::<Sha512>(msg, sig),
        "SHA3-224" => pk.verify::<Sha3_224>(msg, sig),
        "SHA3-256" => pk.verify::<Sha3_256>(msg, sig),
        "SHA3-384" => pk.verify::<Sha3_384>(msg, sig),
        "SHA3-512" => pk.verify::<Sha3_512>(msg, sig),
        "SHAKE128" => {
            let mut h = [0u8; 32];
            shake128(msg, &mut h);
            pk.verify_prehash(&h, sig)
        }
        "SHAKE256" => {
            let mut h = [0u8; 64];
            shake256(msg, &mut h);
            pk.verify_prehash(&h, sig)
        }
        other => panic!("unsupported hash {other}"),
    })
}

/// The same case through the stack-only P-256 / secp256k1 types, which have
/// their own DER parsers and arithmetic. `None` when the curve or hash has
/// no native pairing; a parse failure is `Some(Rejected)`.
fn native(enc: Enc, curve: CurveId, sha: &str, group: &Fields, case: &Fields) -> Option<Outcome> {
    if curve != CurveId::P256 && curve != CurveId::Secp256k1 {
        return None;
    }
    let msg = case.hex("msg");
    // Both native verifiers take a prehash, so hash once here.
    let prehash: Vec<u8> = match sha {
        "SHA-256" => purecrypto::hash::sha256(&msg).to_vec(),
        "SHA-512" => purecrypto::hash::sha512(&msg).to_vec(),
        "SHA3-256" => purecrypto::hash::sha3_256(&msg).to_vec(),
        "SHA3-512" => purecrypto::hash::sha3_512(&msg).to_vec(),
        "SHAKE128" => {
            let mut h = [0u8; 32];
            shake128(&msg, &mut h);
            h.to_vec()
        }
        "SHAKE256" => {
            let mut h = [0u8; 64];
            shake256(&msg, &mut h);
            h.to_vec()
        }
        _ => return None,
    };
    let key = group.hex("publicKey.uncompressed");
    let sig = case.hex("sig");
    let fixed: Option<[u8; 64]> = sig.as_slice().try_into().ok();
    let (r, low_s) = if curve == CurveId::P256 {
        let pk = EcdsaPublicKey::from_sec1(&key).expect("P-256 group key");
        let sig = match enc {
            Enc::P1363 => fixed.map(|b| P256Signature::from_bytes(&b)),
            _ => P256Signature::from_der(&sig).ok(),
        };
        let Some(sig) = sig else {
            return Some(Outcome::Rejected);
        };
        (pk.verify_prehash(&prehash, &sig), sig.is_low_s())
    } else {
        let pk = Secp256k1EcdsaPublicKey::from_sec1(&key).expect("secp256k1 group key");
        let sig = match enc {
            Enc::P1363 => fixed.map(|b| Secp256k1EcdsaSignature::from_bytes(&b)),
            _ => Secp256k1EcdsaSignature::from_der(&sig).ok(),
        };
        let Some(sig) = sig else {
            return Some(Outcome::Rejected);
        };
        (pk.verify_prehash(&prehash, &sig), sig.is_low_s())
    };
    Some(match r {
        Ok(()) if enc == Enc::Bitcoin && !low_s => Outcome::Rejected,
        r => outcome_of(r),
    })
}

fn ecdsa_file(file: &str) {
    let enc = Enc::of(file);
    check(file, |group, case| {
        let pk = public_key(group);
        let curve = pk.curve();
        let sha = group.str("sha");
        let bytes = case.hex("sig");
        let sig = match enc {
            Enc::Der | Enc::Bitcoin => BoxedEcdsaSignature::from_der_for_curve(&bytes, curve).ok(),
            // Each half is the width of the group order — not of the field:
            // on secp160k1/r1/r2 and secp224k1 the order is a bit wider
            // than `publicKey.keySize`, and the vectors carry 21/29-byte
            // halves.
            Enc::P1363 => {
                let n = curve.order_len();
                (bytes.len() == 2 * n).then(|| {
                    let (r, s) = bytes.split_at(n);
                    BoxedEcdsaSignature::from_components(
                        BoxedUint::from_be_bytes(r),
                        BoxedUint::from_be_bytes(s),
                    )
                })
            }
        };
        let boxed = match sig {
            None => Outcome::Rejected,
            Some(sig) => match verify(&pk, sha, &case.hex("msg"), &sig) {
                // Verification is ECDSA's; the low-S rule is applied on top.
                Outcome::Accepted if enc == Enc::Bitcoin && !sig.is_low_s(curve) => {
                    Outcome::Rejected
                }
                o => o,
            },
        };
        if native(enc, curve, sha, group, case).is_some_and(|n| n != boxed) {
            return Outcome::Wrong("native and boxed disagree");
        }
        boxed
    });
}

macro_rules! ecdsa_files {
    ($($name:ident),* $(,)?) => {
        $(
            // Test names mirror the vector file names, curve case included.
            #[test]
            #[allow(non_snake_case)]
            fn $name() {
                ecdsa_file(stringify!($name));
            }
        )*
    };
}

ecdsa_files! {
    ecdsa_brainpoolP224r1_sha224,
    ecdsa_brainpoolP224r1_sha224_p1363,
    ecdsa_brainpoolP224r1_sha3_224,
    ecdsa_brainpoolP256r1_sha256,
    ecdsa_brainpoolP256r1_sha256_p1363,
    ecdsa_brainpoolP256r1_sha3_256,
    ecdsa_brainpoolP384r1_sha384,
    ecdsa_brainpoolP384r1_sha384_p1363,
    ecdsa_brainpoolP384r1_sha3_384,
    ecdsa_brainpoolP320r1_sha384,
    ecdsa_brainpoolP320r1_sha384_p1363,
    ecdsa_brainpoolP320r1_sha3_384,
    ecdsa_brainpoolP512r1_sha3_512,
    ecdsa_brainpoolP512r1_sha512,
    ecdsa_brainpoolP512r1_sha512_p1363,
    ecdsa_secp160k1_sha256,
    ecdsa_secp160k1_sha256_p1363,
    ecdsa_secp160r1_sha256,
    ecdsa_secp160r1_sha256_p1363,
    ecdsa_secp160r2_sha256,
    ecdsa_secp160r2_sha256_p1363,
    ecdsa_secp192k1_sha256,
    ecdsa_secp192k1_sha256_p1363,
    ecdsa_secp192r1_sha256,
    ecdsa_secp192r1_sha256_p1363,
    ecdsa_secp224k1_sha224,
    ecdsa_secp224k1_sha224_p1363,
    ecdsa_secp224k1_sha256,
    ecdsa_secp224k1_sha256_p1363,
    ecdsa_secp224r1_sha224,
    ecdsa_secp224r1_sha224_p1363,
    ecdsa_secp224r1_sha256,
    ecdsa_secp224r1_sha256_p1363,
    ecdsa_secp224r1_sha3_224,
    ecdsa_secp224r1_sha3_256,
    ecdsa_secp224r1_sha3_512,
    ecdsa_secp224r1_sha512,
    ecdsa_secp224r1_sha512_p1363,
    ecdsa_secp224r1_shake128,
    ecdsa_secp224r1_shake128_p1363,
    ecdsa_secp256k1_sha256,
    ecdsa_secp256k1_sha256_bitcoin,
    ecdsa_secp256k1_sha256_p1363,
    ecdsa_secp256k1_sha3_256,
    ecdsa_secp256k1_sha3_512,
    ecdsa_secp256k1_sha512,
    ecdsa_secp256k1_sha512_p1363,
    ecdsa_secp256k1_shake128,
    ecdsa_secp256k1_shake128_p1363,
    ecdsa_secp256k1_shake256,
    ecdsa_secp256k1_shake256_p1363,
    ecdsa_secp256r1_sha256,
    ecdsa_secp256r1_sha256_p1363,
    ecdsa_secp256r1_sha3_256,
    ecdsa_secp256r1_sha3_512,
    ecdsa_secp256r1_sha512,
    ecdsa_secp256r1_sha512_p1363,
    ecdsa_secp256r1_shake128,
    ecdsa_secp256r1_shake128_p1363,
    ecdsa_secp384r1_sha256,
    ecdsa_secp384r1_sha384,
    ecdsa_secp384r1_sha384_p1363,
    ecdsa_secp384r1_sha3_384,
    ecdsa_secp384r1_sha3_512,
    ecdsa_secp384r1_sha512,
    ecdsa_secp384r1_sha512_p1363,
    ecdsa_secp384r1_shake256,
    ecdsa_secp384r1_shake256_p1363,
    ecdsa_secp521r1_sha3_512,
    ecdsa_secp521r1_sha512,
    ecdsa_secp521r1_sha512_p1363,
    ecdsa_secp521r1_shake256,
    ecdsa_secp521r1_shake256_p1363,
}
