//! `purecrypto pkey -in key.pem [-pubout] [-text]` — inspect or convert a key.

use crate::util::{Args, die, read_input, write_output};
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId, Ed25519PrivateKey};
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::x509::AnyPublicKey;

enum Key {
    Rsa(BoxedRsaPrivateKey),
    Ec(BoxedEcdsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
}

fn curve_name(c: CurveId) -> &'static str {
    match c {
        CurveId::P256 => "P-256",
        CurveId::P384 => "P-384",
        CurveId::P521 => "P-521",
        CurveId::Secp256k1 => "secp256k1",
    }
}

pub(crate) fn run(args: Args) {
    let in_path = args.value("-in").or_else(|| args.value("--in"));
    let raw = read_input(in_path);
    let pem = core::str::from_utf8(&raw).unwrap_or_else(|_| die("input is not valid UTF-8 PEM"));

    let key = if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(pem) {
        Key::Rsa(k)
    } else if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(pem) {
        Key::Ec(k)
    } else if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem(pem) {
        Key::Ed25519(k)
    } else {
        die("could not parse key (expected an RSA PKCS#1, EC SEC1, or Ed25519 PKCS#8 PEM)");
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
        };
        write_output(dest, text.as_bytes());
        return;
    }

    if args.flag("-pubout") || args.flag("--pubout") {
        let spki = match &key {
            Key::Rsa(k) => AnyPublicKey::Rsa(k.public_key()).to_spki_pem(),
            Key::Ec(k) => AnyPublicKey::Ecdsa(k.public_key()).to_spki_pem(),
            Key::Ed25519(k) => AnyPublicKey::Ed25519(k.public_key()).to_spki_pem(),
        };
        write_output(dest, spki.as_bytes());
        return;
    }

    // Default: re-emit the private key PEM.
    match &key {
        Key::Rsa(_) => write_output(dest, raw.as_slice()), // round-trips the input
        Key::Ec(k) => write_output(dest, k.to_sec1_pem().as_bytes()),
        Key::Ed25519(k) => write_output(dest, k.to_pkcs8_pem().as_bytes()),
    }
}
