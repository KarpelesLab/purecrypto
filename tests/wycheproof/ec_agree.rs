//! Key agreement — ECDH on the Weierstrass curves (SPKI and raw SEC1 peer
//! keys), X25519 / X448 (raw and SPKI / PKCS#8 encoded) — plus EdDSA
//! verification (Ed25519, Ed448) and the `ec_prime_order_curves` parameter
//! check.
//!
//! The Wycheproof EdDSA groups carry only the public key, so the signing
//! path is not pinned here (the crate's own RFC 8032 unit tests do that).

use crate::common::{Expected, Fields, Outcome, check, check_eq, load, outcome_of, run_with};
use purecrypto::bignum::BoxedUint;
use purecrypto::ec::{
    BoxedEcdhPrivateKey, BoxedEcdsaPublicKey, CurveId, Ed448PublicKey, Ed448Signature,
    Ed25519PublicKey, Ed25519Signature, X448PrivateKey, X25519PrivateKey,
};
#[cfg(feature = "x509")]
use purecrypto::x509::AnyPublicKey;

/// The Wycheproof curve name -> the crate's identifier (`None` = unsupported:
/// the twisted Brainpool curves, FRP256v1, and the 160/192-bit Brainpool
/// curves). Shared with `ec_formats`.
pub fn curve_id(name: &str) -> Option<CurveId> {
    Some(match name {
        "secp256r1" => CurveId::P256,
        "secp384r1" => CurveId::P384,
        "secp521r1" => CurveId::P521,
        "secp256k1" => CurveId::Secp256k1,
        "brainpoolP256r1" => CurveId::BrainpoolP256r1,
        "brainpoolP384r1" => CurveId::BrainpoolP384r1,
        "brainpoolP512r1" => CurveId::BrainpoolP512r1,
        "secp160k1" => CurveId::Secp160k1,
        "secp160r1" => CurveId::Secp160r1,
        "secp160r2" => CurveId::Secp160r2,
        "secp192k1" => CurveId::Secp192k1,
        "secp192r1" => CurveId::P192,
        "secp224k1" => CurveId::Secp224k1,
        "secp224r1" => CurveId::P224,
        "brainpoolP224r1" => CurveId::BrainpoolP224r1,
        "brainpoolP320r1" => CurveId::BrainpoolP320r1,
        _ => return None,
    })
}

/// Every curve with an `ecdh_<curve>.txt` file; all are implemented.
const ECDH_CURVES: [&str; 10] = [
    "secp224r1",
    "secp256r1",
    "secp384r1",
    "secp521r1",
    "secp256k1",
    "brainpoolP224r1",
    "brainpoolP256r1",
    "brainpoolP320r1",
    "brainpoolP384r1",
    "brainpoolP512r1",
];

// ---------------------------------------------------------------------------
// ECDH
// ---------------------------------------------------------------------------

/// One ECDH case: `parse` turns the `public` bytes into a key on `curve`
/// (`None` = rejected), then `private * public` must equal `shared`.
fn ecdh_case<P>(curve: CurveId, case: &Fields, parse: P) -> Outcome
where
    P: FnOnce(CurveId, &[u8]) -> Option<BoxedEcdsaPublicKey>,
{
    let Some(peer) = parse(curve, &case.hex("public")) else {
        return Outcome::Rejected;
    };
    // The vector's scalar may carry a leading `00` sign byte or be shorter
    // than the order; `from_bytes` takes any big-endian width.
    let Ok(sk) = BoxedEcdhPrivateKey::from_bytes(curve, &case.hex("private")) else {
        return Outcome::Rejected;
    };
    match sk.diffie_hellman(&peer) {
        Ok(z) => check_eq(&z, &case.hex("shared"), "shared secret"),
        Err(_) => Outcome::Rejected,
    }
}

/// `acceptable` policy for the boxed ECDH API. The crate only parses
/// named-curve SPKIs through a strict DER reader, so explicit parameters
/// (`UnnamedCurve`, whatever else they claim) and sloppy encodings
/// (`InvalidAsn`) must stay rejected; compressed points are supported and
/// must yield the listed secret.
fn ecdh_strict(_: &Fields, case: &Fields) -> Option<Expected> {
    if case.has_flag("UnnamedCurve") || case.has_flag("InvalidAsn") {
        Some(Expected::Invalid)
    } else if case.has_flag("CompressedPoint") {
        Some(Expected::Valid)
    } else {
        None
    }
}

/// SPKI-encoded peer keys. A key on another curve (`WrongCurve`) parses but
/// is not a peer key for this one; `diffie_hellman` would refuse it too.
#[cfg(feature = "x509")]
#[test]
fn ecdh_spki() {
    for name in ECDH_CURVES {
        run_with(
            &load(&format!("ecdh_{name}")),
            ecdh_strict,
            |group, case| {
                let curve = curve_id(group.str("curve")).expect("supported curve");
                ecdh_case(
                    curve,
                    case,
                    |curve, der| match AnyPublicKey::from_spki_der(der) {
                        Ok(AnyPublicKey::Ecdsa(k)) if k.curve() == curve => Some(k),
                        _ => None,
                    },
                )
            },
        );
    }
}

/// Raw SEC1 peer points (uncompressed and compressed). The secp224r1 file's
/// compressed point is the `p ≡ 1 (mod 4)` Tonelli–Shanks decompression.
#[test]
fn ecdh_ecpoint() {
    for name in ["secp224r1", "secp256r1", "secp384r1", "secp521r1"] {
        run_with(
            &load(&format!("ecdh_{name}_ecpoint")),
            ecdh_strict,
            |group, case| {
                let curve = curve_id(group.str("curve")).expect("supported curve");
                ecdh_case(curve, case, |curve, sec1| {
                    BoxedEcdsaPublicKey::from_sec1(curve, sec1).ok()
                })
            },
        );
    }
}

/// Strips leading zero bytes (DER-style sign byte) and left-pads to `N`;
/// `None` when the value does not fit.
fn fit<const N: usize>(v: &[u8]) -> Option<[u8; N]> {
    let v = strip(v);
    let mut out = [0u8; N];
    out.get_mut(N.checked_sub(v.len())?..)?.copy_from_slice(v);
    Some(out)
}

/// The P-256 vectors again through the fixed-curve `ecdh` API, which takes
/// only uncompressed points and a 32-byte scalar (so the compressed
/// `acceptable` cases are rejected here).
#[test]
fn ecdh_p256_fixed() {
    use purecrypto::ec::ecdh::EcdhPrivateKey;
    use purecrypto::ec::ecdsa::EcdsaPublicKey;
    check("ecdh_secp256r1_ecpoint", |_, case| {
        let Ok(peer) = EcdsaPublicKey::from_sec1(&case.hex("public")) else {
            return Outcome::Rejected;
        };
        let Some(d) = fit::<32>(&case.hex("private")) else {
            return Outcome::Rejected;
        };
        match EcdhPrivateKey::from_bytes(&d).and_then(|sk| sk.diffie_hellman(&peer)) {
            Ok(z) => check_eq(&z, &case.hex("shared"), "shared secret"),
            Err(_) => Outcome::Rejected,
        }
    });
}

// ---------------------------------------------------------------------------
// Curve parameters
// ---------------------------------------------------------------------------

/// `v` without its leading zero bytes.
fn strip(v: &[u8]) -> &[u8] {
    let i = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    &v[i..]
}

/// Left-pads `v` to `len` bytes.
fn pad(v: &[u8], len: usize) -> Vec<u8> {
    let v = strip(v);
    let mut out = vec![0u8; len - v.len()];
    out.extend_from_slice(v);
    out
}

/// Uncompressed SEC1 encoding of `(x, y)`.
fn sec1(x: &[u8], y: &[u8]) -> Vec<u8> {
    [&[0x04][..], x, y].concat()
}

/// Checks the crate's built-in parameters against the listed ones through
/// the public API only: the generator must be on the curve and equal `1·G`,
/// `n` must be out of range for a scalar while `n − 1` is in range with
/// `(n − 1)·G = −G = (gx, p − gy)`, which pins `p`, `n`, `G` and — through
/// the on-curve test and the scalar multiplication — `a` and `b`. Under
/// `x509` the named-curve OID is pinned too, via a hand-built SPKI.
#[test]
fn ec_prime_order_curves() {
    check("ec_prime_order_curves", |_, case| {
        // Curves the crate does not implement (the twisted Brainpool curves,
        // brainpoolP160r1/P192r1, FRP256v1) are counted as skipped.
        let Some(curve) = curve_id(case.str("name")) else {
            return Outcome::Skipped;
        };
        let p = strip(&case.hex("p")).to_vec();
        let flen = p.len();
        let (gx, gy) = (pad(&case.hex("gx"), flen), pad(&case.hex("gy"), flen));
        let n = BoxedUint::from_be_bytes(&case.hex("n"));
        // Scalars are order-width: one byte more than a coordinate on
        // secp160k1/r1/r2 and secp224k1, whose `n` is a bit wider than `p`.
        let nlen = flen.max(n.bit_len().div_ceil(8));
        if nlen != curve.order_len() || flen != curve.field_len() {
            return Outcome::Wrong("field_len / order_len");
        }
        let g = sec1(&gx, &gy);
        // Every supported curve has prime order; the API cannot express `h`.
        if case.int("h") != 1 {
            return Outcome::Wrong("cofactor");
        }
        let Ok(parsed) = BoxedEcdsaPublicKey::from_sec1(curve, &g) else {
            return Outcome::Wrong("generator not on the crate's curve");
        };
        if parsed.to_sec1() != g {
            return Outcome::Wrong("generator round-trip");
        }
        let mul =
            |d: &[u8]| BoxedEcdhPrivateKey::from_bytes(curve, d).map(|k| k.public_key().to_sec1());
        if mul(&[1]) != Ok(g.clone()) {
            return Outcome::Wrong("1*G");
        }
        if mul(&n.to_be_bytes(nlen)).is_ok() {
            return Outcome::Wrong("n accepted as a scalar");
        }
        let neg_gy = BoxedUint::from_be_bytes(&p).sub(&BoxedUint::from_be_bytes(&gy));
        if mul(&n.sub(&BoxedUint::from_u64(1)).to_be_bytes(nlen))
            != Ok(sec1(&gx, &neg_gy.to_be_bytes(flen)))
        {
            return Outcome::Wrong("(n-1)*G != -G");
        }
        #[cfg(feature = "x509")]
        {
            use purecrypto::der::{encode_bit_string, encode_sequence, oid_tlv};
            let arcs: Vec<u64> = case
                .str("oid")
                .split('.')
                .map(|a| a.parse().unwrap())
                .collect();
            let algid =
                encode_sequence(&[oid_tlv(&[1, 2, 840, 10045, 2, 1]), oid_tlv(&arcs)].concat());
            let spki = encode_sequence(&[algid, encode_bit_string(&g)].concat());
            match AnyPublicKey::from_spki_der(&spki) {
                Ok(AnyPublicKey::Ecdsa(k)) if k.curve() == curve && k.to_sec1() == g => {}
                _ => return Outcome::Wrong("named-curve OID"),
            }
        }
        Outcome::Accepted
    });
}

// ---------------------------------------------------------------------------
// X25519 / X448
// ---------------------------------------------------------------------------

/// XDH policy. `diffie_hellman` refuses a peer key whose product lands in
/// the small subgroup — an all-zero u-coordinate (`ZeroSharedSecret`; RFC
/// 7748 §6.1 MAY, RFC 8446 §7.4.2 MUST) — so those `acceptable` cases must
/// be rejected. Points on the twist and non-canonical u-coordinates are
/// handled exactly as RFC 7748 prescribes and must give the listed secret.
fn xdh_strict(_: &Fields, case: &Fields) -> Option<Expected> {
    Some(if case.has_flag("ZeroSharedSecret") {
        Expected::Invalid
    } else {
        Expected::Valid
    })
}

/// One XDH case: `public` is the decoded peer key (`None` = rejected, e.g.
/// the wrong length) and `dh` runs the private side.
fn xdh_case<const N: usize>(
    case: &Fields,
    public: Option<[u8; N]>,
    dh: impl FnOnce(&[u8; N]) -> Option<[u8; N]>,
) -> Outcome {
    match public.and_then(|pk| dh(&pk)) {
        Some(z) => check_eq(&z, &case.hex("shared"), "shared secret"),
        None => Outcome::Rejected,
    }
}

#[test]
fn x25519() {
    run_with(&load("x25519"), xdh_strict, |_, case| {
        xdh_case(case, case.hex_array("public"), |pk| {
            let sk = X25519PrivateKey::from_bytes(case.hex_array("private")?);
            sk.diffie_hellman(pk).ok()
        })
    });
}

#[test]
fn x448() {
    run_with(&load("x448"), xdh_strict, |_, case| {
        xdh_case(case, case.hex_array("public"), |pk| {
            let sk = X448PrivateKey::from_bytes(case.hex_array("private")?);
            sk.diffie_hellman(pk).ok()
        })
    });
}

/// SPKI public / PKCS#8 private keys. `InvalidPublic` is an SPKI for another
/// algorithm (an EC named curve), which parses but is not an X25519 key.
#[cfg(feature = "x509")]
#[test]
fn x25519_asn() {
    run_with(&load("x25519_asn"), xdh_strict, |_, case| {
        let public = match AnyPublicKey::from_spki_der(&case.hex("public")) {
            Ok(AnyPublicKey::X25519(k)) => Some(k.to_bytes()),
            _ => None,
        };
        xdh_case(case, public, |pk| {
            let sk = X25519PrivateKey::from_pkcs8_der(&case.hex("private")).ok()?;
            sk.diffie_hellman(pk).ok()
        })
    });
}

#[cfg(feature = "x509")]
#[test]
fn x448_asn() {
    run_with(&load("x448_asn"), xdh_strict, |_, case| {
        let public = match AnyPublicKey::from_spki_der(&case.hex("public")) {
            Ok(AnyPublicKey::X448(k)) => Some(k.to_bytes()),
            _ => None,
        };
        xdh_case(case, public, |pk| {
            let sk = X448PrivateKey::from_pkcs8_der(&case.hex("private")).ok()?;
            sk.diffie_hellman(pk).ok()
        })
    });
}

// ---------------------------------------------------------------------------
// EdDSA
// ---------------------------------------------------------------------------

/// Under `x509`, the group's `publicKeyDer` must parse to the same raw key.
#[cfg(feature = "x509")]
fn spki_matches(group: &Fields, raw: &[u8], want: fn(&AnyPublicKey) -> Option<Vec<u8>>) -> bool {
    AnyPublicKey::from_spki_der(&group.hex("publicKeyDer"))
        .ok()
        .and_then(|k| want(&k))
        .is_some_and(|k| k == raw)
}

#[test]
fn ed25519() {
    check("ed25519", |group, case| {
        let raw: [u8; 32] = group.hex_array("publicKey.pk").expect("32-byte key");
        #[cfg(feature = "x509")]
        if !spki_matches(group, &raw, |k| match k {
            AnyPublicKey::Ed25519(k) => Some(k.to_bytes().to_vec()),
            _ => None,
        }) {
            return Outcome::Wrong("publicKeyDer");
        }
        // A signature of the wrong length has no `Ed25519Signature` encoding.
        let Some(sig) = case.hex_array::<64>("sig") else {
            return Outcome::Rejected;
        };
        let pk = Ed25519PublicKey::from_bytes(raw);
        outcome_of(pk.verify(&case.hex("msg"), &Ed25519Signature::from_bytes(sig)))
    });
}

/// The Ed448 vectors use an empty context, i.e. plain `verify`.
#[test]
fn ed448() {
    check("ed448", |group, case| {
        let raw: [u8; 57] = group.hex_array("publicKey.pk").expect("57-byte key");
        #[cfg(feature = "x509")]
        if !spki_matches(group, &raw, |k| match k {
            AnyPublicKey::Ed448(k) => Some(k.to_bytes().to_vec()),
            _ => None,
        }) {
            return Outcome::Wrong("publicKeyDer");
        }
        let Some(sig) = case.hex_array::<114>("sig") else {
            return Outcome::Rejected;
        };
        let pk = Ed448PublicKey::from_bytes(raw);
        outcome_of(pk.verify(&case.hex("msg"), &Ed448Signature::from_bytes(sig)))
    });
}
