//! `purecrypto genpkey` — generate an RSA, EC, Ed25519/Ed448, ML-DSA, ML-KEM,
//! or SLH-DSA private key (PEM).

use crate::util::{Args, die, write_output_with_mode};
use purecrypto::bignum::{BoxedUint, Uint};
use purecrypto::ec::{
    BoxedEcdsaPrivateKey, CurveId, Ed448PrivateKey, Ed25519PrivateKey, Sm2PrivateKey,
};
use purecrypto::lms::{HssPrivateKey, LmotsType, LmsPrivateKey, LmsType};
use purecrypto::mldsa::{MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey};
use purecrypto::mlkem::{MlKem512DecapsKey, MlKem768DecapsKey, MlKem1024DecapsKey};
use purecrypto::rng::OsRng;
use purecrypto::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
use purecrypto::slhdsa::{self, ParamSet as SlhDsa};
use purecrypto::xmss::{XmssMtParamSet, XmssMtPrivateKey, XmssParamSet, XmssPrivateKey};

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

/// Maps an LMS tree-height token (`H5`..`H25`) to an [`LmsType`].
fn lms_height(tok: &str) -> Option<LmsType> {
    Some(match tok {
        "H5" => LmsType::Sha256M32H5,
        "H10" => LmsType::Sha256M32H10,
        "H15" => LmsType::Sha256M32H15,
        "H20" => LmsType::Sha256M32H20,
        "H25" => LmsType::Sha256M32H25,
        _ => return None,
    })
}

/// Maps an LM-OTS Winternitz token (`W1`/`W2`/`W4`/`W8`) to an [`LmotsType`].
fn lmots_w(tok: &str) -> Option<LmotsType> {
    Some(match tok {
        "W1" => LmotsType::Sha256N32W1,
        "W2" => LmotsType::Sha256N32W2,
        "W4" => LmotsType::Sha256N32W4,
        "W8" => LmotsType::Sha256N32W8,
        _ => return None,
    })
}

/// Parses an LMS algorithm name `LMS-SHA256-H{5,10,15,20,25}[-W{1,2,4,8}]`
/// (default `W8`) into a single-tree parameter pair.
fn lms_from_name(name: &str) -> Option<(LmsType, LmotsType)> {
    let parts: Vec<&str> = name.split('-').collect();
    // LMS - SHA256 - Hx [ - Wy ]
    if parts.len() < 3 || parts[0] != "LMS" || parts[1] != "SHA256" {
        return None;
    }
    let lms = lms_height(parts[2])?;
    let ots = match parts.get(3) {
        Some(w) => lmots_w(w)?,
        None => LmotsType::Sha256N32W8,
    };
    Some((lms, ots))
}

/// Parses an HSS algorithm name `HSS-L{1..8}-SHA256-H{..}[-W{..}]` into `L`
/// identical levels of the given single-tree parameters.
fn hss_from_name(name: &str) -> Option<Vec<(LmsType, LmotsType)>> {
    let parts: Vec<&str> = name.split('-').collect();
    // HSS - Ln - SHA256 - Hx [ - Wy ]
    if parts.len() < 4 || parts[0] != "HSS" {
        return None;
    }
    let levels: usize = parts[1].strip_prefix('L')?.parse().ok()?;
    if !(1..=8).contains(&levels) {
        return None;
    }
    if parts[2] != "SHA256" {
        return None;
    }
    let lms = lms_height(parts[3])?;
    let ots = match parts.get(4) {
        Some(w) => lmots_w(w)?,
        None => LmotsType::Sha256N32W8,
    };
    Some(vec![(lms, ots); levels])
}

/// Recognizes an XMSS parameter-set name, e.g. `XMSS-SHA2_10_256`,
/// `XMSS-SHAKE_16_256`, `XMSS-SHA2_20_192` (the RFC 8391 / SP 800-208 names,
/// hyphen- or underscore-separated).
fn xmss_from_name(name: &str) -> Option<XmssParamSet> {
    let n = name.strip_prefix("XMSS-")?.replace('-', "_");
    Some(match n.as_str() {
        "SHA2_10_256" => XmssParamSet::Sha2_10_256,
        "SHA2_16_256" => XmssParamSet::Sha2_16_256,
        "SHA2_20_256" => XmssParamSet::Sha2_20_256,
        "SHAKE_10_256" => XmssParamSet::Shake_10_256,
        "SHAKE_16_256" => XmssParamSet::Shake_16_256,
        "SHAKE_20_256" => XmssParamSet::Shake_20_256,
        "SHA2_10_192" => XmssParamSet::Sha2_10_192,
        "SHA2_16_192" => XmssParamSet::Sha2_16_192,
        "SHA2_20_192" => XmssParamSet::Sha2_20_192,
        "SHAKE256_10_256" => XmssParamSet::Shake256_10_256,
        "SHAKE256_16_256" => XmssParamSet::Shake256_16_256,
        "SHAKE256_20_256" => XmssParamSet::Shake256_20_256,
        _ => return None,
    })
}

/// Recognizes an XMSS^MT parameter-set name, e.g. `XMSSMT-SHA2_20/2_256`.
fn xmssmt_from_name(name: &str) -> Option<XmssMtParamSet> {
    let n = name.strip_prefix("XMSSMT-")?.replace(['-', '/'], "_");
    Some(match n.as_str() {
        "SHA2_20_2_256" => XmssMtParamSet::Sha2_20_2_256,
        "SHA2_20_4_256" => XmssMtParamSet::Sha2_20_4_256,
        "SHA2_40_2_256" => XmssMtParamSet::Sha2_40_2_256,
        "SHA2_40_4_256" => XmssMtParamSet::Sha2_40_4_256,
        "SHA2_40_8_256" => XmssMtParamSet::Sha2_40_8_256,
        "SHA2_60_3_256" => XmssMtParamSet::Sha2_60_3_256,
        "SHA2_60_6_256" => XmssMtParamSet::Sha2_60_6_256,
        "SHA2_60_12_256" => XmssMtParamSet::Sha2_60_12_256,
        "SHAKE_20_2_256" => XmssMtParamSet::Shake_20_2_256,
        "SHAKE_20_4_256" => XmssMtParamSet::Shake_20_4_256,
        _ => return None,
    })
}

/// Generates a stateful hash-based signing key (LMS/HSS/XMSS/XMSS^MT) and
/// returns its raw serialized private-key bytes (`to_bytes`), or `None` if
/// `algorithm` is not a stateful algorithm name.
///
/// The bytes embed the live one-time-key index; the CLI writes them verbatim
/// and `pkeyutl sign` rewrites the file after every signature (see `pkeyutl`).
fn stateful_key_bytes(algorithm: &str) -> Option<Vec<u8>> {
    let up = algorithm.to_ascii_uppercase();
    if let Some((lms, ots)) = lms_from_name(&up) {
        return Some(LmsPrivateKey::generate(lms, ots, &mut OsRng).to_bytes());
    }
    if let Some(levels) = hss_from_name(&up) {
        let sk = HssPrivateKey::generate(&levels, &mut OsRng)
            .unwrap_or_else(|e| die(format!("HSS keygen failed: {e:?}")));
        return Some(sk.to_bytes());
    }
    if up.starts_with("XMSSMT-") {
        let set = xmssmt_from_name(&up)
            .unwrap_or_else(|| die(format!("unknown XMSS^MT parameter set: {algorithm}")));
        return Some(XmssMtPrivateKey::generate(set, &mut OsRng).to_bytes());
    }
    if up.starts_with("XMSS-") {
        let set = xmss_from_name(&up)
            .unwrap_or_else(|| die(format!("unknown XMSS parameter set: {algorithm}")));
        return Some(XmssPrivateKey::generate(set, &mut OsRng).to_bytes());
    }
    None
}

pub(crate) fn run(args: Args) {
    let algorithm = args
        .value("-algorithm")
        .or_else(|| args.value("--algorithm"))
        .unwrap_or_else(|| {
            die(
                "usage: purecrypto genpkey -algorithm ALG [-bits N|-curve NAME] [-out file]\n  \
                 ALG: RSA | EC | SM2 | ED25519 | ED448 | ML-DSA-{44,65,87} | \
                 ML-KEM-{512,768,1024} | SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f} | \
                 LMS-SHA256-H{5,10,15,20,25}[-W{1,2,4,8}] | HSS-L{1..8}-SHA256-H..[-W..] | \
                 XMSS-{SHA2,SHAKE,SHAKE256}_{10,16,20}_{192,256} | XMSSMT-SHA2_{20,40,60}/L_256",
            )
        });
    let dest = args.value("-out");

    // Stateful hash-based signatures (LMS/HSS/XMSS/XMSS^MT) are serialized as
    // RAW private-key bytes (not PEM): the bytes embed the live one-time-key
    // index that `pkeyutl sign` must rewrite after each signature.
    if let Some(bytes) = stateful_key_bytes(algorithm) {
        write_output_with_mode(dest, &bytes, /* private = */ true);
        return;
    }

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
                    // RSA below 2048 bits is rejected by default per NIST
                    // SP 800-57: callers needing legacy interop can opt in
                    // with `--allow-weak`.
                    if !(2048..=65536).contains(&bits) || !bits.is_multiple_of(2) {
                        if !(512..=65536).contains(&bits) || !bits.is_multiple_of(2) {
                            die("unsupported RSA size (use an even value, 512..=65536 bits)");
                        }
                        if !(args.flag("--allow-weak") || args.flag("-allow-weak")) {
                            die("refusing to generate an RSA key below 2048 bits — pass \
                                 `--allow-weak` to override (NIST SP 800-57)");
                        }
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
        "SM2" => Sm2PrivateKey::generate(&mut OsRng).to_sec1_pem(),
        "ED25519" => Ed25519PrivateKey::generate(&mut OsRng).to_pkcs8_pem(),
        "ED448" => Ed448PrivateKey::generate(&mut OsRng).to_pkcs8_pem(),
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
                    "unknown algorithm: {other} (RSA | EC | SM2 | ED25519 | ED448 | \
                     ML-DSA-44/65/87 | ML-KEM-512/768/1024 | \
                     SLH-DSA-{{SHA2,SHAKE}}-{{128,192,256}}{{s,f}})"
                ))
            }
        }
    };

    write_output_with_mode(dest, pem.as_bytes(), /* private = */ true);
}
