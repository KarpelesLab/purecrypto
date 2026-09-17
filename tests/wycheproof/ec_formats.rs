//! PEM-encoded key agreement: the `ecdh_<curve>_pem` files carry the peer
//! key as an SPKI PEM document (`-----BEGIN PUBLIC KEY-----`) and the private
//! key as a PKCS#8 PEM document (`-----BEGIN PRIVATE KEY-----`);
//! `x25519_pem` / `x448_pem` do the same for XDH. Both go through the crate's
//! PEM readers and the same strict DER parsers as the `_asn` files, so the
//! `InvalidPem` cases (mangled DER behind a well-formed PEM armour) must be
//! rejected exactly like `InvalidAsn`.
//!
//! The `_webcrypto` / `_jwk` files are covered by the `jose` module.
#![cfg(feature = "x509")]

use crate::common::{Expected, Fields, Outcome, check_eq, load, run_with};
use crate::ec_agree::curve_id;
use purecrypto::ec::{BoxedEcdhPrivateKey, X448PrivateKey, X25519PrivateKey};
use purecrypto::x509::AnyPublicKey;

/// `acceptable` policy for the PEM ECDH files, the PEM counterpart of
/// `ec_agree::ecdh_strict`: explicit parameters (`UnnamedCurve`) and every
/// DER liberty (`InvalidPem`, `InvalidAsn`) must be rejected by the strict
/// reader; compressed points are supported and must yield the listed secret.
fn ecdh_pem_strict(_: &Fields, case: &Fields) -> Option<Expected> {
    if case.has_flag("InvalidPem") || case.has_flag("InvalidAsn") || case.has_flag("UnnamedCurve") {
        Some(Expected::Invalid)
    } else if case.has_flag("CompressedPoint") {
        Some(Expected::Valid)
    } else {
        None
    }
}

/// The ECDH PEM files. A peer key on another curve (`WrongCurve`) parses
/// but is not a key on this curve; `diffie_hellman` would refuse it too.
/// The PKCS#8 side is `BoxedEcdhPrivateKey::from_pkcs8_pem`, the
/// key-agreement reader of the same `id-ecPublicKey` document.
#[test]
fn ecdh_pem() {
    for name in ["secp224r1", "secp256r1", "secp384r1", "secp521r1"] {
        run_with(
            &load(&format!("ecdh_{name}_pem")),
            ecdh_pem_strict,
            |group, case| {
                let curve = curve_id(group.str("curve")).expect("supported curve");
                let peer = match AnyPublicKey::from_spki_pem(case.str("public")) {
                    Ok(AnyPublicKey::Ecdsa(k)) if k.curve() == curve => k,
                    _ => return Outcome::Rejected,
                };
                let Ok(sk) = BoxedEcdhPrivateKey::from_pkcs8_pem(case.str("private")) else {
                    return Outcome::Rejected;
                };
                if sk.curve() != curve {
                    return Outcome::Wrong("private key curve");
                }
                match sk.diffie_hellman(&peer) {
                    Ok(z) => check_eq(&z, &case.hex("shared"), "shared secret"),
                    Err(_) => Outcome::Rejected,
                }
            },
        );
    }
}

/// XDH policy, as in `ec_agree`: a low-order peer key (`ZeroSharedSecret`)
/// is refused by `diffie_hellman`; twist points and non-canonical
/// u-coordinates are handled per RFC 7748 and must give the listed secret.
fn xdh_pem_strict(_: &Fields, case: &Fields) -> Option<Expected> {
    Some(if case.has_flag("ZeroSharedSecret") {
        Expected::Invalid
    } else {
        Expected::Valid
    })
}

#[test]
fn x25519_pem() {
    run_with(&load("x25519_pem"), xdh_pem_strict, |_, case| {
        let public = match AnyPublicKey::from_spki_pem(case.str("public")) {
            Ok(AnyPublicKey::X25519(k)) => k.to_bytes(),
            _ => return Outcome::Rejected,
        };
        let Ok(sk) = X25519PrivateKey::from_pkcs8_pem(case.str("private")) else {
            return Outcome::Rejected;
        };
        match sk.diffie_hellman(&public) {
            Ok(z) => check_eq(&z, &case.hex("shared"), "shared secret"),
            Err(_) => Outcome::Rejected,
        }
    });
}

/// `PublicKeyTooLong` is a 57-byte key inside the SPKI, which is not an
/// X448 key at all.
#[test]
fn x448_pem() {
    run_with(&load("x448_pem"), xdh_pem_strict, |_, case| {
        let public = match AnyPublicKey::from_spki_pem(case.str("public")) {
            Ok(AnyPublicKey::X448(k)) => k.to_bytes(),
            _ => return Outcome::Rejected,
        };
        let Ok(sk) = X448PrivateKey::from_pkcs8_pem(case.str("private")) else {
            return Outcome::Rejected;
        };
        match sk.diffie_hellman(&public) {
            Ok(z) => check_eq(&z, &case.hex("shared"), "shared secret"),
            Err(_) => Outcome::Rejected,
        }
    });
}
