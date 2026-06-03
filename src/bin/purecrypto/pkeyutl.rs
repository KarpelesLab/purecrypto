//! `purecrypto pkeyutl` — generic asymmetric encrypt/decrypt/sign/verify.

use crate::util::{Args, die, read_input, write_output};
use purecrypto::ec::{
    BoxedEcdsaPrivateKey, BoxedEcdsaSignature, CurveId, Ed448PrivateKey, Ed25519PrivateKey,
};
use purecrypto::hash::{Sha1, Sha256, Sha384, Sha512};
use purecrypto::mldsa::{MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey};
use purecrypto::rng::OsRng;
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::slhdsa;
use purecrypto::x509::AnyPublicKey;

const USAGE: &str = "\
purecrypto pkeyutl <subcommand>

  encrypt -inkey FILE [-pubin] -pkeyopt OPT [-in FILE] [-out FILE]
  decrypt -inkey FILE          -pkeyopt OPT [-in FILE] [-out FILE]
  sign    -inkey FILE          [-pkeyopt OPT] -in FILE -out FILE
  verify  -inkey FILE [-pubin] [-pkeyopt OPT] -sigfile FILE -in FILE

-pkeyopt options:
  rsa_padding_mode:oaep        OAEP encrypt/decrypt
  rsa_padding_mode:pkcs1       PKCS#1 v1.5 encrypt/decrypt / signature
  rsa_padding_mode:pss         RSA-PSS signature
  rsa_oaep_md:sha256|sha384|sha512   OAEP hash (default sha256)
  rsa_oaep_label:HEX           OAEP label (default empty)
  digest:sha256|sha384|sha512|sha1   hash for sign/verify (default sha256)";

/// Returns all `-pkeyopt key:value` entries.
fn pkeyopts(args: &Args) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // Args treats every occurrence of `-pkeyopt`'s value: walk argv ourselves.
    let mut iter = args.tokens_iter();
    while let Some(t) = iter.next() {
        if (t == "-pkeyopt" || t == "--pkeyopt")
            && let Some(v) = iter.next()
        {
            let (k, val) = v.split_once(':').unwrap_or((v.as_str(), ""));
            out.push((k.to_string(), val.to_string()));
        }
    }
    out
}

#[derive(Default)]
struct Opts {
    padding: Option<String>,
    oaep_md: Option<String>,
    oaep_label: Vec<u8>,
    digest: Option<String>,
}

fn parse_opts(args: &Args) -> Opts {
    let mut opts = Opts::default();
    for (k, v) in pkeyopts(args) {
        match k.as_str() {
            "rsa_padding_mode" => opts.padding = Some(v),
            "rsa_oaep_md" => opts.oaep_md = Some(v),
            "rsa_oaep_label" => {
                opts.oaep_label =
                    crate::util::from_hex(&v).unwrap_or_else(|| die("rsa_oaep_label must be hex"));
            }
            "digest" => opts.digest = Some(v),
            other => die(format!("unknown -pkeyopt key: {other}")),
        }
    }
    opts
}

// The RSA-2048 / -3072 / -4096 variant dominates the enum size, but the value
// is short-lived inside `pkeyutl` — boxing every arm would be ceremony for no
// real benefit. (See the matching pattern in `pkey.rs`.)
#[allow(clippy::large_enum_variant)]
enum PrivKey {
    Rsa(BoxedRsaPrivateKey),
    Ec(BoxedEcdsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
    Ed448(Ed448PrivateKey),
    MlDsa44(MlDsa44PrivateKey),
    MlDsa65(MlDsa65PrivateKey),
    MlDsa87(MlDsa87PrivateKey),
    SlhDsa(slhdsa::PrivateKey),
}

fn load_priv(path: &str) -> PrivKey {
    crate::util::warn_if_world_readable_key(path);
    let raw = std::fs::read(path).unwrap_or_else(|e| die(format!("cannot read {path}: {e}")));
    let pem = core::str::from_utf8(&raw).unwrap_or_else(|_| die("key file is not UTF-8 PEM"));
    if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(pem) {
        return PrivKey::Rsa(k);
    }
    if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(pem) {
        return PrivKey::Ec(k);
    }
    if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem(pem) {
        return PrivKey::Ed25519(k);
    }
    if let Ok(k) = Ed448PrivateKey::from_pkcs8_pem(pem) {
        return PrivKey::Ed448(k);
    }
    if let Ok(k) = MlDsa65PrivateKey::from_pkcs8_pem(pem) {
        return PrivKey::MlDsa65(k);
    }
    if let Ok(k) = MlDsa44PrivateKey::from_pkcs8_pem(pem) {
        return PrivKey::MlDsa44(k);
    }
    if let Ok(k) = MlDsa87PrivateKey::from_pkcs8_pem(pem) {
        return PrivKey::MlDsa87(k);
    }
    if let Ok(k) = slhdsa::PrivateKey::from_pkcs8_pem(pem) {
        return PrivKey::SlhDsa(k);
    }
    die("unrecognized private key (expected RSA PKCS#1, EC SEC1, or PKCS#8 PEM)");
}

fn load_spki(path: &str) -> AnyPublicKey {
    let raw = std::fs::read(path).unwrap_or_else(|e| die(format!("cannot read {path}: {e}")));
    let pem = core::str::from_utf8(&raw).unwrap_or_else(|_| die("pubkey is not UTF-8 PEM"));
    AnyPublicKey::from_spki_pem(pem).unwrap_or_else(|e| die(format!("cannot parse SPKI PEM: {e}")))
}

fn run_encrypt(args: Args) {
    let in_path = args.value("-in").or_else(|| args.value("--in"));
    let pt = read_input(in_path);
    let opts = parse_opts(&args);
    let padding = opts.padding.as_deref().unwrap_or("pkcs1");
    let inkey = args
        .value("-inkey")
        .or_else(|| args.value("--inkey"))
        .unwrap_or_else(|| die("missing -inkey"));

    let ct = if args.flag("-pubin") || args.flag("--pubin") {
        let any = load_spki(inkey);
        let rsa = match any {
            AnyPublicKey::Rsa(k) => k,
            _ => die("RSA encrypt requires an RSA SPKI"),
        };
        match padding {
            "oaep" => {
                let md = opts.oaep_md.as_deref().unwrap_or("sha256");
                match md.to_ascii_lowercase().as_str() {
                    "sha256" => rsa
                        .encrypt_oaep::<Sha256, _>(&pt, &opts.oaep_label, &mut OsRng)
                        .unwrap_or_else(|e| die(format!("OAEP encrypt failed: {e}"))),
                    "sha384" => rsa
                        .encrypt_oaep::<Sha384, _>(&pt, &opts.oaep_label, &mut OsRng)
                        .unwrap_or_else(|e| die(format!("OAEP encrypt failed: {e}"))),
                    "sha512" => rsa
                        .encrypt_oaep::<Sha512, _>(&pt, &opts.oaep_label, &mut OsRng)
                        .unwrap_or_else(|e| die(format!("OAEP encrypt failed: {e}"))),
                    _ => die(format!("unsupported rsa_oaep_md: {md}")),
                }
            }
            "pkcs1" => rsa
                .encrypt_pkcs1v15(&pt, &mut OsRng)
                .unwrap_or_else(|e| die(format!("PKCS1 encrypt failed: {e}"))),
            other => die(format!("unsupported rsa_padding_mode for encrypt: {other}")),
        }
    } else {
        let key = load_priv(inkey);
        let rsa = match key {
            PrivKey::Rsa(k) => k,
            _ => die("RSA encrypt requires an RSA key"),
        };
        let pub_k = rsa.public_key();
        match padding {
            "oaep" => {
                let md = opts.oaep_md.as_deref().unwrap_or("sha256");
                match md.to_ascii_lowercase().as_str() {
                    "sha256" => pub_k
                        .encrypt_oaep::<Sha256, _>(&pt, &opts.oaep_label, &mut OsRng)
                        .unwrap_or_else(|e| die(format!("OAEP encrypt failed: {e}"))),
                    "sha384" => pub_k
                        .encrypt_oaep::<Sha384, _>(&pt, &opts.oaep_label, &mut OsRng)
                        .unwrap_or_else(|e| die(format!("OAEP encrypt failed: {e}"))),
                    "sha512" => pub_k
                        .encrypt_oaep::<Sha512, _>(&pt, &opts.oaep_label, &mut OsRng)
                        .unwrap_or_else(|e| die(format!("OAEP encrypt failed: {e}"))),
                    _ => die(format!("unsupported rsa_oaep_md: {md}")),
                }
            }
            "pkcs1" => pub_k
                .encrypt_pkcs1v15(&pt, &mut OsRng)
                .unwrap_or_else(|e| die(format!("PKCS1 encrypt failed: {e}"))),
            other => die(format!("unsupported rsa_padding_mode: {other}")),
        }
    };
    let out_path = args.value("-out").or_else(|| args.value("--out"));
    write_output(out_path, &ct);
}

fn run_decrypt(args: Args) {
    let in_path = args.value("-in").or_else(|| args.value("--in"));
    let ct = read_input(in_path);
    let opts = parse_opts(&args);
    let padding = opts.padding.as_deref().unwrap_or("pkcs1");
    let inkey = args
        .value("-inkey")
        .or_else(|| args.value("--inkey"))
        .unwrap_or_else(|| die("missing -inkey"));
    let key = load_priv(inkey);
    let rsa = match key {
        PrivKey::Rsa(k) => k,
        _ => die("RSA decrypt requires an RSA key"),
    };
    let pt = match padding {
        "oaep" => {
            let md = opts.oaep_md.as_deref().unwrap_or("sha256");
            match md.to_ascii_lowercase().as_str() {
                "sha256" => rsa
                    .decrypt_oaep::<Sha256>(&ct, &opts.oaep_label)
                    .unwrap_or_else(|e| die(format!("OAEP decrypt failed: {e}"))),
                "sha384" => rsa
                    .decrypt_oaep::<Sha384>(&ct, &opts.oaep_label)
                    .unwrap_or_else(|e| die(format!("OAEP decrypt failed: {e}"))),
                "sha512" => rsa
                    .decrypt_oaep::<Sha512>(&ct, &opts.oaep_label)
                    .unwrap_or_else(|e| die(format!("OAEP decrypt failed: {e}"))),
                _ => die(format!("unsupported rsa_oaep_md: {md}")),
            }
        }
        "pkcs1" => rsa
            .decrypt_pkcs1v15(&ct)
            .unwrap_or_else(|e| die(format!("PKCS1 decrypt failed: {e}"))),
        other => die(format!("unsupported rsa_padding_mode: {other}")),
    };
    let out_path = args.value("-out").or_else(|| args.value("--out"));
    write_output(out_path, &pt);
}

fn run_sign(args: Args) {
    let in_path = args
        .value("-in")
        .or_else(|| args.value("--in"))
        .unwrap_or_else(|| die("missing -in FILE"));
    let msg = std::fs::read(in_path).unwrap_or_else(|e| die(format!("cannot read {in_path}: {e}")));
    let opts = parse_opts(&args);
    let inkey = args
        .value("-inkey")
        .or_else(|| args.value("--inkey"))
        .unwrap_or_else(|| die("missing -inkey"));
    let key = load_priv(inkey);
    let pss = matches!(opts.padding.as_deref(), Some("pss"));
    let digest = opts.digest.as_deref().unwrap_or("sha256");

    let sig = match key {
        PrivKey::Rsa(k) => {
            if pss {
                match digest.to_ascii_lowercase().as_str() {
                    "sha256" => k.sign_pss::<Sha256, _>(&msg, &mut OsRng),
                    "sha384" => k.sign_pss::<Sha384, _>(&msg, &mut OsRng),
                    "sha512" => k.sign_pss::<Sha512, _>(&msg, &mut OsRng),
                    _ => die(format!("unsupported RSA-PSS digest: {digest}")),
                }
                .unwrap_or_else(|e| die(format!("RSA-PSS sign failed: {e}")))
            } else {
                match digest.to_ascii_lowercase().as_str() {
                    "sha256" => k.sign_pkcs1v15::<Sha256>(&msg),
                    "sha384" => k.sign_pkcs1v15::<Sha384>(&msg),
                    "sha512" => k.sign_pkcs1v15::<Sha512>(&msg),
                    "sha1" => k.sign_pkcs1v15::<Sha1>(&msg),
                    _ => die(format!("unsupported RSA digest: {digest}")),
                }
                .unwrap_or_else(|e| die(format!("RSA sign failed: {e}")))
            }
        }
        PrivKey::Ec(k) => {
            let curve = k.curve();
            let sig = match curve {
                CurveId::P256 | CurveId::Secp256k1 => k.sign::<Sha256>(&msg),
                CurveId::P384 => k.sign::<Sha384>(&msg),
                CurveId::P521 => k.sign::<Sha512>(&msg),
            }
            .unwrap_or_else(|e| die(format!("ECDSA sign failed: {e}")));
            sig.to_der(curve)
        }
        PrivKey::Ed25519(k) => k.sign(&msg).to_bytes().to_vec(),
        PrivKey::Ed448(k) => k.sign(&msg).to_bytes().to_vec(),
        PrivKey::MlDsa44(k) => k
            .sign(&mut OsRng, &msg, b"")
            .unwrap_or_else(|e| die(format!("ML-DSA-44 sign failed: {e:?}"))),
        PrivKey::MlDsa65(k) => k
            .sign(&mut OsRng, &msg, b"")
            .unwrap_or_else(|e| die(format!("ML-DSA-65 sign failed: {e:?}"))),
        PrivKey::MlDsa87(k) => k
            .sign(&mut OsRng, &msg, b"")
            .unwrap_or_else(|e| die(format!("ML-DSA-87 sign failed: {e:?}"))),
        PrivKey::SlhDsa(k) => k
            .sign(&mut OsRng, &msg, b"")
            .unwrap_or_else(|e| die(format!("SLH-DSA sign failed: {e:?}"))),
    };
    let out_path = args
        .value("-out")
        .or_else(|| args.value("--out"))
        .unwrap_or_else(|| die("missing -out FILE"));
    write_output(Some(out_path), &sig);
}

fn run_verify(args: Args) {
    let in_path = args
        .value("-in")
        .or_else(|| args.value("--in"))
        .unwrap_or_else(|| die("missing -in FILE"));
    let msg = std::fs::read(in_path).unwrap_or_else(|e| die(format!("cannot read {in_path}: {e}")));
    let sig_path = args
        .value("-sigfile")
        .or_else(|| args.value("--sigfile"))
        .unwrap_or_else(|| die("missing -sigfile FILE"));
    let sig =
        std::fs::read(sig_path).unwrap_or_else(|e| die(format!("cannot read {sig_path}: {e}")));
    let inkey = args
        .value("-inkey")
        .or_else(|| args.value("--inkey"))
        .unwrap_or_else(|| die("missing -inkey"));
    let opts = parse_opts(&args);
    let pss = matches!(opts.padding.as_deref(), Some("pss"));
    let digest = opts.digest.as_deref().unwrap_or("sha256");

    let any = load_spki(inkey);
    let ok = match any {
        AnyPublicKey::Rsa(k) => {
            if pss {
                match digest.to_ascii_lowercase().as_str() {
                    "sha256" => k.verify_pss::<Sha256>(&msg, &sig),
                    "sha384" => k.verify_pss::<Sha384>(&msg, &sig),
                    "sha512" => k.verify_pss::<Sha512>(&msg, &sig),
                    _ => die(format!("unsupported RSA-PSS digest: {digest}")),
                }
                .is_ok()
            } else {
                match digest.to_ascii_lowercase().as_str() {
                    "sha256" => k.verify_pkcs1v15::<Sha256>(&msg, &sig),
                    "sha384" => k.verify_pkcs1v15::<Sha384>(&msg, &sig),
                    "sha512" => k.verify_pkcs1v15::<Sha512>(&msg, &sig),
                    "sha1" => k.verify_pkcs1v15::<Sha1>(&msg, &sig),
                    _ => die(format!("unsupported RSA digest: {digest}")),
                }
                .is_ok()
            }
        }
        AnyPublicKey::Ecdsa(k) => {
            let parsed = match BoxedEcdsaSignature::from_der(&sig) {
                Ok(s) => s,
                Err(_) => {
                    println!("verify FAIL");
                    std::process::exit(1);
                }
            };
            match k.curve() {
                CurveId::P256 | CurveId::Secp256k1 => k.verify::<Sha256>(&msg, &parsed),
                CurveId::P384 => k.verify::<Sha384>(&msg, &parsed),
                CurveId::P521 => k.verify::<Sha512>(&msg, &parsed),
            }
            .is_ok()
        }
        AnyPublicKey::Ed25519(k) => {
            use purecrypto::ec::Ed25519Signature;
            match <[u8; 64]>::try_from(sig.as_slice()) {
                Ok(b) => k.verify(&msg, &Ed25519Signature::from_bytes(b)).is_ok(),
                Err(_) => false,
            }
        }
        AnyPublicKey::Ed448(k) => {
            use purecrypto::ec::Ed448Signature;
            match <[u8; 114]>::try_from(sig.as_slice()) {
                Ok(b) => k.verify(&msg, &Ed448Signature::from_bytes(b)).is_ok(),
                Err(_) => false,
            }
        }
        AnyPublicKey::MlDsa44(k) => k.verify(&sig, &msg, b""),
        AnyPublicKey::MlDsa65(k) => k.verify(&sig, &msg, b""),
        AnyPublicKey::MlDsa87(k) => k.verify(&sig, &msg, b""),
        AnyPublicKey::SlhDsa(k) => k.verify(&sig, &msg, b""),
    };
    if ok {
        println!("Signature verified");
    } else {
        println!("Signature verification failure");
        std::process::exit(1);
    }
}

pub(crate) fn run(args: Args) {
    let pos = args.positionals(&[
        "-inkey",
        "--inkey",
        "-in",
        "--in",
        "-out",
        "--out",
        "-sigfile",
        "--sigfile",
        "-pkeyopt",
        "--pkeyopt",
    ]);
    let sub = pos.first().copied().unwrap_or("");
    match sub {
        "encrypt" => run_encrypt(args),
        "decrypt" => run_decrypt(args),
        "sign" => run_sign(args),
        "verify" => run_verify(args),
        "" => die(USAGE),
        other => die(format!("unknown pkeyutl subcommand '{other}'\n\n{USAGE}")),
    }
}
