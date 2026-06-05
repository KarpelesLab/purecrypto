//! `purecrypto kem <subcommand>` — ML-KEM keygen / encaps / decaps.

use crate::util::{Args, die, write_output, write_output_with_mode};
use purecrypto::mlkem::{
    MlKem512Ciphertext, MlKem512DecapsKey, MlKem512EncapsKey, MlKem768Ciphertext,
    MlKem768DecapsKey, MlKem768EncapsKey, MlKem1024Ciphertext, MlKem1024DecapsKey,
    MlKem1024EncapsKey,
};
use purecrypto::rng::OsRng;

#[derive(Clone, Copy)]
enum Set {
    K512,
    K768,
    K1024,
}

fn parse_set(s: &str) -> Option<Set> {
    Some(match s.to_ascii_uppercase().as_str() {
        "ML-KEM-512" => Set::K512,
        "ML-KEM-768" => Set::K768,
        "ML-KEM-1024" => Set::K1024,
        _ => return None,
    })
}

const USAGE: &str = "\
purecrypto kem <subcommand>

  keygen  -alg ML-KEM-{512,768,1024} -out-secret FILE -out-public FILE
  encaps  -peer FILE -out-ct FILE -out-ss FILE
  decaps  -key FILE -ct FILE -out-ss FILE";

fn run_keygen(args: Args) {
    let alg = args
        .value("-alg")
        .or_else(|| args.value("--alg"))
        .unwrap_or_else(|| die("missing -alg ML-KEM-{512,768,1024}"));
    let set = parse_set(alg).unwrap_or_else(|| die(format!("unsupported -alg: {alg}")));
    let out_sec = args
        .value("-out-secret")
        .or_else(|| args.value("--out-secret"))
        .unwrap_or_else(|| die("missing -out-secret FILE"));
    let out_pub = args
        .value("-out-public")
        .or_else(|| args.value("--out-public"))
        .unwrap_or_else(|| die("missing -out-public FILE"));

    let (sk_pem, ek_pem) = match set {
        Set::K512 => {
            let (sk, _) = MlKem512DecapsKey::generate(&mut OsRng);
            (sk.to_pkcs8_pem(), sk.encapsulation_key().to_spki_pem())
        }
        Set::K768 => {
            let (sk, _) = MlKem768DecapsKey::generate(&mut OsRng);
            (sk.to_pkcs8_pem(), sk.encapsulation_key().to_spki_pem())
        }
        Set::K1024 => {
            let (sk, _) = MlKem1024DecapsKey::generate(&mut OsRng);
            (sk.to_pkcs8_pem(), sk.encapsulation_key().to_spki_pem())
        }
    };
    write_output_with_mode(Some(out_sec), sk_pem.as_bytes(), /* private = */ true);
    write_output(Some(out_pub), ek_pem.as_bytes());
}

/// Reads an ML-KEM SPKI from PEM, validating the encapsulation key per
/// FIPS 203 §7.2 (audit fix S16) before any encaps call.
fn parse_ek_pem(pem: &str) -> Option<(Set, Vec<u8>)> {
    if let Ok(k) = MlKem768EncapsKey::from_spki_pem(pem) {
        // Re-encode to bytes then run the validated parse to enforce S16.
        let bytes = k.to_bytes();
        return match MlKem768EncapsKey::from_bytes_validated(bytes) {
            Ok(_) => Some((Set::K768, bytes.to_vec())),
            Err(_) => None,
        };
    }
    if let Ok(k) = MlKem512EncapsKey::from_spki_pem(pem) {
        let bytes = k.to_bytes();
        return match MlKem512EncapsKey::from_bytes_validated(bytes) {
            Ok(_) => Some((Set::K512, bytes.to_vec())),
            Err(_) => None,
        };
    }
    if let Ok(k) = MlKem1024EncapsKey::from_spki_pem(pem) {
        let bytes = k.to_bytes();
        return match MlKem1024EncapsKey::from_bytes_validated(bytes) {
            Ok(_) => Some((Set::K1024, bytes.to_vec())),
            Err(_) => None,
        };
    }
    None
}

fn run_encaps(args: Args) {
    let peer_path = args
        .value("-peer")
        .or_else(|| args.value("--peer"))
        .unwrap_or_else(|| die("missing -peer FILE (ML-KEM SPKI PEM)"));
    let out_ct = args
        .value("-out-ct")
        .unwrap_or_else(|| die("missing -out-ct FILE"));
    let out_ss = args
        .value("-out-ss")
        .unwrap_or_else(|| die("missing -out-ss FILE"));

    let pem_bytes =
        std::fs::read(peer_path).unwrap_or_else(|e| die(format!("cannot read {peer_path}: {e}")));
    let pem = core::str::from_utf8(&pem_bytes).unwrap_or_else(|_| die("peer is not valid PEM"));
    let (set, _bytes) = parse_ek_pem(pem).unwrap_or_else(|| {
        die("invalid ML-KEM encapsulation key (parse or FIPS 203 §7.2 check failed)")
    });

    // Re-parse the key with the validated path so callers can rely on a checked EK.
    let (ct, ss) = match set {
        Set::K512 => {
            let k = MlKem512EncapsKey::from_spki_pem(pem).unwrap();
            let (ct, ss) = k.encapsulate(&mut OsRng);
            (ct.to_bytes().to_vec(), ss)
        }
        Set::K768 => {
            let k = MlKem768EncapsKey::from_spki_pem(pem).unwrap();
            let (ct, ss) = k.encapsulate(&mut OsRng);
            (ct.to_bytes().to_vec(), ss)
        }
        Set::K1024 => {
            let k = MlKem1024EncapsKey::from_spki_pem(pem).unwrap();
            let (ct, ss) = k.encapsulate(&mut OsRng);
            (ct.to_bytes().to_vec(), ss)
        }
    };
    write_output(Some(out_ct), &ct);
    write_output_with_mode(Some(out_ss), &ss, /* private = */ true);
}

fn run_decaps(args: Args) {
    let key_path = args
        .value("-key")
        .or_else(|| args.value("--key"))
        .unwrap_or_else(|| die("missing -key FILE (ML-KEM PKCS#8 PEM)"));
    let ct_path = args.value("-ct").unwrap_or_else(|| die("missing -ct FILE"));
    let out_ss = args
        .value("-out-ss")
        .unwrap_or_else(|| die("missing -out-ss FILE"));

    let key_pem =
        std::fs::read(key_path).unwrap_or_else(|e| die(format!("cannot read {key_path}: {e}")));
    let key_pem = core::str::from_utf8(&key_pem).unwrap_or_else(|_| die("key is not valid PEM"));
    let ct_bytes =
        std::fs::read(ct_path).unwrap_or_else(|e| die(format!("cannot read {ct_path}: {e}")));

    let ss = if let Ok(k) = MlKem768DecapsKey::from_pkcs8_pem(key_pem) {
        let ct: [u8; 1088] = ct_bytes
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| die("ML-KEM-768 ciphertext must be 1088 bytes"));
        k.decapsulate(&MlKem768Ciphertext::from_bytes(ct))
    } else if let Ok(k) = MlKem512DecapsKey::from_pkcs8_pem(key_pem) {
        let ct: [u8; 768] = ct_bytes
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| die("ML-KEM-512 ciphertext must be 768 bytes"));
        k.decapsulate(&MlKem512Ciphertext::from_bytes(ct))
    } else if let Ok(k) = MlKem1024DecapsKey::from_pkcs8_pem(key_pem) {
        let ct: [u8; 1568] = ct_bytes
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| die("ML-KEM-1024 ciphertext must be 1568 bytes"));
        k.decapsulate(&MlKem1024Ciphertext::from_bytes(ct))
    } else {
        die("not a recognized ML-KEM PKCS#8 PEM");
    };
    write_output_with_mode(Some(out_ss), &ss, /* private = */ true);
}

pub(crate) fn run(args: Args) {
    let pos = args.positionals(&[
        "-alg",
        "--alg",
        "-out-secret",
        "--out-secret",
        "-out-public",
        "--out-public",
        "-peer",
        "--peer",
        "-out-ct",
        "--out-ct",
        "-out-ss",
        "--out-ss",
        "-key",
        "--key",
        "-ct",
        "--ct",
    ]);
    let sub = pos.first().copied().unwrap_or("");
    match sub {
        "keygen" => run_keygen(args),
        "encaps" => run_encaps(args),
        "decaps" => run_decaps(args),
        "" => die(USAGE),
        other => die(format!("unknown kem subcommand '{other}'\n\n{USAGE}")),
    }
}
