//! `purecrypto pkey -in key.pem [-pubout] [-text]` — inspect or convert a key.

use crate::util::{
    Args, die, read_input, warn_if_world_readable_key, write_output, write_output_with_mode,
};
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId, Ed448PrivateKey, Ed25519PrivateKey};
use purecrypto::mldsa::{MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey};
use purecrypto::mlkem::{MlKem512DecapsKey, MlKem768DecapsKey, MlKem1024DecapsKey};
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::slhdsa;
use purecrypto::x509::AnyPublicKey;

// The ML-KEM variants carry up to 3168-byte fixed arrays inline (ML-KEM-1024);
// the enum is short-lived in the CLI so boxing would be ceremony for no real
// benefit.
#[allow(clippy::large_enum_variant)]
enum Key {
    Rsa(BoxedRsaPrivateKey),
    Ec(BoxedEcdsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
    Ed448(Ed448PrivateKey),
    MlDsa44(MlDsa44PrivateKey),
    MlDsa65(MlDsa65PrivateKey),
    MlDsa87(MlDsa87PrivateKey),
    MlKem512(MlKem512DecapsKey),
    MlKem768(MlKem768DecapsKey),
    MlKem1024(MlKem1024DecapsKey),
    SlhDsa(slhdsa::PrivateKey),
}

fn curve_name(c: CurveId) -> &'static str {
    match c {
        CurveId::P256 => "P-256",
        CurveId::P384 => "P-384",
        CurveId::P521 => "P-521",
        CurveId::Secp256k1 => "secp256k1",
        CurveId::Sm2p256v1 => "sm2p256v1",
        _ => "unknown",
    }
}

/// Tries every supported PKCS#8 private-key flavor.
fn parse_pkcs8(pem: &str) -> Option<Key> {
    if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem(pem) {
        return Some(Key::Ed25519(k));
    }
    if let Ok(k) = Ed448PrivateKey::from_pkcs8_pem(pem) {
        return Some(Key::Ed448(k));
    }
    if let Ok(k) = MlDsa65PrivateKey::from_pkcs8_pem(pem) {
        return Some(Key::MlDsa65(k));
    }
    if let Ok(k) = MlDsa44PrivateKey::from_pkcs8_pem(pem) {
        return Some(Key::MlDsa44(k));
    }
    if let Ok(k) = MlDsa87PrivateKey::from_pkcs8_pem(pem) {
        return Some(Key::MlDsa87(k));
    }
    if let Ok(k) = MlKem768DecapsKey::from_pkcs8_pem(pem) {
        return Some(Key::MlKem768(k));
    }
    if let Ok(k) = MlKem512DecapsKey::from_pkcs8_pem(pem) {
        return Some(Key::MlKem512(k));
    }
    if let Ok(k) = MlKem1024DecapsKey::from_pkcs8_pem(pem) {
        return Some(Key::MlKem1024(k));
    }
    if let Ok(k) = slhdsa::PrivateKey::from_pkcs8_pem(pem) {
        return Some(Key::SlhDsa(k));
    }
    None
}

pub(crate) fn run(args: Args) {
    let in_path = args.value("-in").or_else(|| args.value("--in"));
    // `-in` is private-key material: warn if the file is group/world-
    // readable, matching the other secret-key readers. Only a real file
    // path is checkable (stdin / `-` has no mode).
    if let Some(p) = in_path {
        if p != "-" {
            warn_if_world_readable_key(p);
        }
    }
    let raw = read_input(in_path);
    let pem = core::str::from_utf8(&raw).unwrap_or_else(|_| die("input is not valid UTF-8 PEM"));

    let key = if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(pem) {
        Key::Rsa(k)
    } else if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(pem) {
        Key::Ec(k)
    } else if let Some(k) = parse_pkcs8(pem) {
        k
    } else {
        die(
            "could not parse key (expected RSA PKCS#1, EC SEC1, or a PKCS#8 \
             Ed25519/ML-DSA/ML-KEM/SLH-DSA PEM)",
        );
    };

    let dest = args.value("-out");

    if args.flag("-text") || args.flag("--text") {
        let text = match &key {
            Key::Rsa(k) => format!(
                "RSA private key, {} bits\n",
                k.public_key().modulus().bit_len()
            ),
            Key::Ec(k) => format!("EC private key, curve {}\n", curve_name(k.curve())),
            Key::Ed25519(_) => "Ed25519 private key\n".to_string(),
            Key::Ed448(_) => "Ed448 private key\n".to_string(),
            Key::MlDsa44(_) => "ML-DSA-44 private key\n".to_string(),
            Key::MlDsa65(_) => "ML-DSA-65 private key\n".to_string(),
            Key::MlDsa87(_) => "ML-DSA-87 private key\n".to_string(),
            Key::MlKem512(_) => "ML-KEM-512 decapsulation key\n".to_string(),
            Key::MlKem768(_) => "ML-KEM-768 decapsulation key\n".to_string(),
            Key::MlKem1024(_) => "ML-KEM-1024 decapsulation key\n".to_string(),
            Key::SlhDsa(_) => "SLH-DSA private key\n".to_string(),
        };
        write_output(dest, text.as_bytes());
        return;
    }

    if args.flag("-pubout") || args.flag("--pubout") {
        let spki = match &key {
            Key::Rsa(k) => AnyPublicKey::Rsa(k.public_key()).to_spki_pem(),
            Key::Ec(k) => AnyPublicKey::Ecdsa(k.public_key()).to_spki_pem(),
            Key::Ed25519(k) => AnyPublicKey::Ed25519(k.public_key()).to_spki_pem(),
            Key::Ed448(k) => AnyPublicKey::Ed448(k.public_key()).to_spki_pem(),
            Key::MlDsa44(k) => k.public_key().to_spki_pem(),
            Key::MlDsa65(k) => k.public_key().to_spki_pem(),
            Key::MlDsa87(k) => k.public_key().to_spki_pem(),
            Key::MlKem512(k) => k.encapsulation_key().to_spki_pem(),
            Key::MlKem768(k) => k.encapsulation_key().to_spki_pem(),
            Key::MlKem1024(k) => k.encapsulation_key().to_spki_pem(),
            Key::SlhDsa(k) => k.public_key().to_spki_pem(),
        };
        write_output(dest, spki.as_bytes());
        return;
    }

    // Default: re-emit the private key PEM (PKCS#8 for the modern types).
    // The earlier audit hardened `genpkey`, `kex`, `kem`, `ca init` to write
    // private-key bytes through `write_output_with_mode(..., private=true)`
    // — mode 0o600, refuse-overwrite, refuse a TTY stdout. The `pkey`
    // re-emit path was missed; restore symmetry here (I-7).
    let private = true;
    match &key {
        Key::Rsa(_) => write_output_with_mode(dest, raw.as_slice(), private),
        Key::Ec(k) => write_output_with_mode(dest, k.to_sec1_pem().as_bytes(), private),
        Key::Ed25519(k) => write_output_with_mode(dest, k.to_pkcs8_pem().as_bytes(), private),
        Key::Ed448(k) => write_output_with_mode(dest, k.to_pkcs8_pem().as_bytes(), private),
        Key::MlDsa44(k) => write_output_with_mode(dest, k.to_pkcs8_pem().as_bytes(), private),
        Key::MlDsa65(k) => write_output_with_mode(dest, k.to_pkcs8_pem().as_bytes(), private),
        Key::MlDsa87(k) => write_output_with_mode(dest, k.to_pkcs8_pem().as_bytes(), private),
        Key::MlKem512(k) => write_output_with_mode(dest, k.to_pkcs8_pem().as_bytes(), private),
        Key::MlKem768(k) => write_output_with_mode(dest, k.to_pkcs8_pem().as_bytes(), private),
        Key::MlKem1024(k) => write_output_with_mode(dest, k.to_pkcs8_pem().as_bytes(), private),
        Key::SlhDsa(k) => write_output_with_mode(dest, k.to_pkcs8_pem().as_bytes(), private),
    }
}
