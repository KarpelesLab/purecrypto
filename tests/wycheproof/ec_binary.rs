//! ECDH on the SEC 2 binary curves sect283k1/r1, sect409k1/r1 and
//! sect571k1/r1 (`ecdh_sect*`): the peer key is an SPKI, the private key a
//! raw scalar, the shared secret the x-coordinate of `d·Q`.

use crate::common::{Expected, Fields, Outcome, check_eq, load, run_with};
use purecrypto::ec::binary::{BinaryCurveId, BinaryPrivateKey, BinaryPublicKey};

/// The Wycheproof curve name -> the crate's identifier.
fn curve_id(name: &str) -> BinaryCurveId {
    match name {
        "sect283k1" => BinaryCurveId::Sect283k1,
        "sect283r1" => BinaryCurveId::Sect283r1,
        "sect409k1" => BinaryCurveId::Sect409k1,
        "sect409r1" => BinaryCurveId::Sect409r1,
        "sect571k1" => BinaryCurveId::Sect571k1,
        "sect571r1" => BinaryCurveId::Sect571r1,
        other => panic!("unsupported curve {other}"),
    }
}

/// `acceptable` policy. The SPKI goes through the strict DER reader, so every
/// `InvalidAsn` mutation (including the `wrong oid` cases naming another
/// curve, and explicit-parameter `UnnamedCurve` SPKIs) must be rejected;
/// `LowOrderPublic` points fail the `n·Q = ∞` subgroup check, which the
/// cofactor-2/4 curves need to keep the shared secret from leaking scalar
/// bits; compressed points are supported and must give the listed secret.
fn strict(_: &Fields, case: &Fields) -> Option<Expected> {
    if case.has_flag("InvalidAsn")
        || case.has_flag("UnnamedCurve")
        || case.has_flag("LowOrderPublic")
    {
        Some(Expected::Invalid)
    } else if case.has_flag("CompressedPoint") {
        Some(Expected::Valid)
    } else {
        None
    }
}

#[test]
fn ecdh_sect() {
    for name in [
        "sect283k1",
        "sect283r1",
        "sect409k1",
        "sect409r1",
        "sect571k1",
        "sect571r1",
    ] {
        run_with(&load(&format!("ecdh_{name}")), strict, |group, case| {
            let curve = curve_id(group.str("curve"));
            let peer = match BinaryPublicKey::from_spki_der(&case.hex("public")) {
                Ok(k) if k.curve() == curve => k,
                _ => return Outcome::Rejected,
            };
            let Ok(sk) = BinaryPrivateKey::from_bytes(curve, &case.hex("private")) else {
                return Outcome::Rejected;
            };
            match sk.diffie_hellman(&peer) {
                Ok(z) => check_eq(&z, &case.hex("shared"), "shared secret"),
                Err(_) => Outcome::Rejected,
            }
        });
    }
}
