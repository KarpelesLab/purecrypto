//! `purecrypto pkey -in key.pem [-pubout] [-text]` — inspect or convert a key.

use crate::util::{Args, die, read_input, write_output};
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::x509::AnyPublicKey;

enum Key {
    Rsa(BoxedRsaPrivateKey),
    Ec(BoxedEcdsaPrivateKey),
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
    } else {
        die("could not parse key (expected an RSA PKCS#1 or EC SEC1 PEM)");
    };

    let dest = args.value("-out");

    if args.flag("-text") || args.flag("--text") {
        let text = match &key {
            Key::Rsa(k) => format!(
                "RSA private key, {} bits\n",
                k.public_key().modulus().bit_len()
            ),
            Key::Ec(k) => format!("EC private key, curve {}\n", curve_name(k.curve())),
        };
        write_output(dest, text.as_bytes());
        return;
    }

    if args.flag("-pubout") || args.flag("--pubout") {
        let spki = match &key {
            Key::Rsa(k) => AnyPublicKey::Rsa(k.public_key()).to_spki_pem(),
            Key::Ec(k) => AnyPublicKey::Ecdsa(k.public_key()).to_spki_pem(),
        };
        write_output(dest, spki.as_bytes());
        return;
    }

    // Default: re-emit the private key PEM.
    match &key {
        Key::Rsa(_) => write_output(dest, raw.as_slice()), // round-trips the input
        Key::Ec(k) => write_output(dest, k.to_sec1_pem().as_bytes()),
    }
}
