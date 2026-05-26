//! `purecrypto genpkey` — generate an RSA or EC private key (PEM).

use crate::util::{Args, die, write_output};
use purecrypto::bignum::{BoxedUint, Uint};
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId, Ed25519PrivateKey};
use purecrypto::mldsa::{MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey};
use purecrypto::mlkem::{MlKem512DecapsKey, MlKem768DecapsKey, MlKem1024DecapsKey};
use purecrypto::rng::OsRng;
use purecrypto::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
use purecrypto::slhdsa::{self, ParamSet as SlhDsa};

const E: u64 = 65537;
const ROUNDS: usize = 20;

fn curve_from_name(name: &str) -> Option<CurveId> {
    Some(match name.to_ascii_lowercase().as_str() {
        "p-256" | "p256" | "prime256v1" | "secp256r1" => CurveId::P256,
        "p-384" | "p384" | "secp384r1" => CurveId::P384,
        "p-521" | "p521" | "secp521r1" => CurveId::P521,
        "secp256k1" => CurveId::Secp256k1,
        _ => return None,
    })
}

/// Recognizes an SLH-DSA parameter-set name.
fn slhdsa_from_name(name: &str) -> Option<SlhDsa> {
    Some(match name.to_ascii_uppercase().as_str() {
        "SLH-DSA-SHA2-128S" => SlhDsa::Sha2_128s,
        "SLH-DSA-SHA2-128F" => SlhDsa::Sha2_128f,
        "SLH-DSA-SHA2-192S" => SlhDsa::Sha2_192s,
        "SLH-DSA-SHA2-192F" => SlhDsa::Sha2_192f,
        "SLH-DSA-SHA2-256S" => SlhDsa::Sha2_256s,
        "SLH-DSA-SHA2-256F" => SlhDsa::Sha2_256f,
        "SLH-DSA-SHAKE-128S" => SlhDsa::Shake_128s,
        "SLH-DSA-SHAKE-128F" => SlhDsa::Shake_128f,
        "SLH-DSA-SHAKE-192S" => SlhDsa::Shake_192s,
        "SLH-DSA-SHAKE-192F" => SlhDsa::Shake_192f,
        "SLH-DSA-SHAKE-256S" => SlhDsa::Shake_256s,
        "SLH-DSA-SHAKE-256F" => SlhDsa::Shake_256f,
        _ => return None,
    })
}

pub(crate) fn run(args: Args) {
    let algorithm = args
        .value("-algorithm")
        .or_else(|| args.value("--algorithm"))
        .unwrap_or_else(|| {
            die(
                "usage: purecrypto genpkey -algorithm ALG [-bits N|-curve NAME] [-out file]\n  \
                 ALG: RSA | EC | ED25519 | ML-DSA-{44,65,87} | ML-KEM-{512,768,1024} | \
                 SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}",
            )
        });
    let dest = args.value("-out");

    let pem = match algorithm.to_ascii_uppercase().as_str() {
        "RSA" => {
            let bits: u32 = args
                .value("-bits")
                .or_else(|| args.value("--bits"))
                .unwrap_or("2048")
                .parse()
                .unwrap_or_else(|_| die("invalid -bits value"));
            // The common sizes use the fast const-generic path; any other even
            // size up to 65536 bits falls back to the runtime-sized key.
            match bits {
                2048 => RsaPrivateKey::<32>::generate(Uint::from_u64(E), &mut OsRng, ROUNDS)
                    .to_pkcs1_pem(),
                3072 => RsaPrivateKey::<48>::generate(Uint::from_u64(E), &mut OsRng, ROUNDS)
                    .to_pkcs1_pem(),
                4096 => RsaPrivateKey::<64>::generate(Uint::from_u64(E), &mut OsRng, ROUNDS)
                    .to_pkcs1_pem(),
                _ => {
                    if !(512..=65536).contains(&bits) || !bits.is_multiple_of(2) {
                        die("unsupported RSA size (use an even value, 512..=65536 bits)");
                    }
                    BoxedRsaPrivateKey::generate(
                        bits as usize,
                        BoxedUint::from_u64(E),
                        &mut OsRng,
                        ROUNDS,
                    )
                    .to_pkcs1_pem()
                }
            }
        }
        "EC" | "ECDSA" => {
            let name = args
                .value("-curve")
                .or_else(|| args.value("--curve"))
                .unwrap_or("P-256");
            let curve =
                curve_from_name(name).unwrap_or_else(|| die(format!("unknown curve: {name}")));
            BoxedEcdsaPrivateKey::generate(curve, &mut OsRng).to_sec1_pem()
        }
        "ED25519" => Ed25519PrivateKey::generate(&mut OsRng).to_pkcs8_pem(),
        "ML-DSA-44" => MlDsa44PrivateKey::generate(&mut OsRng).0.to_pkcs8_pem(),
        "ML-DSA-65" => MlDsa65PrivateKey::generate(&mut OsRng).0.to_pkcs8_pem(),
        "ML-DSA-87" => MlDsa87PrivateKey::generate(&mut OsRng).0.to_pkcs8_pem(),
        "ML-KEM-512" => MlKem512DecapsKey::generate(&mut OsRng).0.to_pkcs8_pem(),
        "ML-KEM-768" => MlKem768DecapsKey::generate(&mut OsRng).0.to_pkcs8_pem(),
        "ML-KEM-1024" => MlKem1024DecapsKey::generate(&mut OsRng).0.to_pkcs8_pem(),
        other => {
            if let Some(set) = slhdsa_from_name(other) {
                slhdsa::PrivateKey::generate(set, &mut OsRng)
                    .0
                    .to_pkcs8_pem()
            } else {
                die(format!(
                    "unknown algorithm: {other} (RSA | EC | ED25519 | ML-DSA-44/65/87 | \
                     ML-KEM-512/768/1024 | SLH-DSA-{{SHA2,SHAKE}}-{{128,192,256}}{{s,f}})"
                ))
            }
        }
    };

    write_output(dest, pem.as_bytes());
}
