//! `purecrypto genpkey` — generate an RSA or EC private key (PEM).

use crate::util::{Args, die, write_output};
use purecrypto::bignum::Uint;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::rng::OsRng;
use purecrypto::rsa::RsaPrivateKey;

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

pub(crate) fn run(args: Args) {
    let algorithm = args
        .value("-algorithm")
        .or_else(|| args.value("--algorithm"))
        .unwrap_or_else(|| {
            die("usage: purecrypto genpkey -algorithm RSA|EC [-bits N|-curve NAME] [-out file]")
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
            match bits {
                2048 => RsaPrivateKey::<32>::generate(Uint::from_u64(E), &mut OsRng, ROUNDS)
                    .to_pkcs1_pem(),
                3072 => RsaPrivateKey::<48>::generate(Uint::from_u64(E), &mut OsRng, ROUNDS)
                    .to_pkcs1_pem(),
                4096 => RsaPrivateKey::<64>::generate(Uint::from_u64(E), &mut OsRng, ROUNDS)
                    .to_pkcs1_pem(),
                _ => die("unsupported RSA size (use 2048, 3072, or 4096)"),
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
        other => die(format!("unknown algorithm: {other} (use RSA or EC)")),
    };

    write_output(dest, pem.as_bytes());
}
