//! JOSE — JWK / JWS / JWE (RFC 7515–7518, RFC 8037) — plus the JWK-encoded
//! ECDH (`ecdh_*_webcrypto`) and XDH (`x25519_jwk`, `x448_jwk`) files.
//!
//! Every group carries the recipient's key as a JWK or JWK Set (either as
//! compact JSON in `private` / `public`, or flattened into `private.<member>`
//! fields by the converter). The JWS/JWE cases are pushed through the
//! *compact* parsers: Wycheproof rates the JSON-serialized cases (flag
//! `JsonSerialization`) as `invalid` for a compact-only consumer, and a
//! separate test below checks that the JSON API does verify / decrypt them.
//!
//! Upstream vector defects (json_web_signature), skipped by comment:
//!
//! * tcIds 367 and 370 (`invalidBase64Padding*`) are byte-identical to the
//!   `valid` tcId 357 — the `=` padding they were meant to carry was lost —
//!   and tcIds 372 / 373 rate a stray `?` inside a base64url segment as
//!   `valid`. A strict RFC 7515 Appendix C decoder cannot satisfy both those
//!   and 357 / 361 / 371.
//! * tcIds 346 / 350 (`Figure20`, a PS384 JWS) come with a key whose `alg`
//!   is `PS256`, and tcIds 347 / 351 (`Figure27`, ES512) with a key whose
//!   `alg` is the non-registered `ES521`; Wycheproof added those `alg`
//!   members to the RFC 7520 keys itself and its own `WrongPrimitive` cases
//!   (tcIds 331–339) require a key to be refused for any other `alg`.

use crate::common::{Expected, Fields, Outcome, check_eq, load, outcome_of, run_with};
use purecrypto::jose::{Error, Jwe, Jwk, JwkSet, Jws, OkpCurve};

/// JWK members the converter may flatten into `private.<name>` fields.
const JWK_MEMBERS: [&str; 16] = [
    "kty", "crv", "x", "y", "d", "n", "e", "p", "q", "dp", "dq", "qi", "k", "kid", "alg", "use",
];

/// The recipient's key material for a group.
enum Keys {
    Set(JwkSet),
    One(Box<Jwk>),
}

/// Rebuilds the JSON text of a JWK from `prefix.<member>` fields (the
/// converter flattens simple objects; all such members are strings).
fn jwk_json_from_fields(fields: &Fields, prefix: &str) -> Option<String> {
    let mut members = Vec::new();
    for name in JWK_MEMBERS {
        if let Some(v) = fields.get(&format!("{prefix}.{name}")) {
            members.push(format!("\"{name}\":\"{v}\""));
        }
    }
    if members.is_empty() {
        None
    } else {
        Some(format!("{{{}}}", members.join(",")))
    }
}

/// Parses the group's key — the public one for a JWS (the verifier's
/// side), the private one for a JWE — falling back to whichever exists. A
/// JSON text is a JWK Set when it has `keys`, a single JWK otherwise.
fn group_keys(group: &Fields, prefer_public: bool) -> Result<Keys, Error> {
    let order = if prefer_public {
        ["public", "private"]
    } else {
        ["private", "public"]
    };
    for name in order {
        let json = match group.get(name) {
            Some(text) if text.starts_with('{') => text.to_string(),
            _ => match jwk_json_from_fields(group, name) {
                Some(j) => j,
                None => continue,
            },
        };
        return if json.contains("\"keys\"") {
            JwkSet::parse(&json).map(Keys::Set)
        } else {
            Jwk::parse(&json).map(|k| Keys::One(Box::new(k)))
        };
    }
    panic!("group without key material: {:?}", group.comment());
}

fn jws_case(keys: &Result<Keys, Error>, case: &Fields) -> Outcome {
    const DEFECTIVE: [&str; 6] = [
        "invalidBase64Padding",
        "invalidBase64PaddingInPayload",
        "InvalidCharacterInsertedInHeader",
        "InvalidCharacterInsertedInPayload",
        "Figure20",
        "Figure27",
    ];
    if DEFECTIVE.contains(&case.comment()) {
        return Outcome::Skipped;
    }
    let Ok(jws) = Jws::parse_compact(case.str("jws")) else {
        return Outcome::Rejected;
    };
    let Ok(keys) = keys else {
        return Outcome::Rejected;
    };
    outcome_of(match keys {
        Keys::Set(set) => jws.verify_with_set(set),
        Keys::One(key) => jws.verify(key),
    })
}

fn jwe_case(keys: &Result<Keys, Error>, case: &Fields) -> Outcome {
    if case.has_flag("CompressedPlaintext") && !cfg!(feature = "cert-compression") {
        return Outcome::Skipped;
    }
    let Ok(jwe) = Jwe::parse_compact(case.str("jwe")) else {
        return Outcome::Rejected;
    };
    let Ok(keys) = keys else {
        return Outcome::Rejected;
    };
    let res = match keys {
        Keys::Set(set) => jwe.decrypt_with_set(set),
        Keys::One(key) => jwe.decrypt(key),
    };
    match res {
        Ok(pt) => match case.get("pt") {
            Some(_) => check_eq(&pt, &case.hex("pt"), "plaintext"),
            None => Outcome::Accepted,
        },
        Err(_) => Outcome::Rejected,
    }
}

/// Dispatches on whether the case is a JWS or a JWE.
fn jose_case(group: &Fields, case: &Fields) -> Outcome {
    if case.has("jws") {
        jws_case(&group_keys(group, true), case)
    } else {
        jwe_case(&group_keys(group, false), case)
    }
}

#[test]
fn json_web_signature() {
    run_with(&load("json_web_signature"), |_, _| None, jose_case);
}

#[test]
fn json_web_key() {
    run_with(&load("json_web_key"), |_, _| None, jose_case);
}

#[test]
fn json_web_crypto() {
    run_with(&load("json_web_crypto"), |_, _| None, jose_case);
}

#[test]
fn json_web_encryption() {
    run_with(&load("json_web_encryption"), |_, _| None, jose_case);
}

/// The `JsonSerialization` cases are `invalid` for the compact parser (see
/// the module docs); through the JSON parser they are the same messages as
/// the `valid` compact ones and must verify / decrypt to the same payload.
#[test]
fn json_serialization_cases() {
    let mut seen = 0;
    for name in [
        "json_web_signature",
        "json_web_crypto",
        "json_web_encryption",
    ] {
        let file = load(name);
        for group in &file.groups {
            for case in group
                .tests
                .iter()
                .filter(|c| c.has_flag("JsonSerialization"))
            {
                let keys = group_keys(&group.fields, case.has("jws")).expect("group key parses");
                let text = case.get("jws").or(case.get("jwe")).expect("serialization");
                let json_ok = if case.has("jws") {
                    match Jws::parse(text) {
                        // json_web_signature tcId 17 is truncated JSON upstream.
                        Err(Error::Json) => continue,
                        Err(e) => panic!("{name} tcId {}: {e}", case.tc_id()),
                        Ok(jws) => match &keys {
                            Keys::Set(s) => jws.verify_with_set(s).map(<[u8]>::to_vec),
                            Keys::One(k) => jws.verify(k).map(<[u8]>::to_vec),
                        },
                    }
                } else {
                    let jwe = Jwe::parse(text)
                        .unwrap_or_else(|e| panic!("{name} tcId {}: {e}", case.tc_id()));
                    match &keys {
                        Keys::Set(s) => jwe.decrypt_with_set(s),
                        Keys::One(k) => jwe.decrypt(k),
                    }
                };
                let payload =
                    json_ok.unwrap_or_else(|e| panic!("{name} tcId {}: {e}", case.tc_id()));
                assert_eq!(payload, b"foo", "{name} tcId {}", case.tc_id());
                seen += 1;
            }
        }
    }
    assert_eq!(
        seen, 3,
        "json_web_crypto tcIds 17 / 22 and json_web_encryption tcId 22"
    );
}

// ---------------------------------------------------------------------------
// JWK-encoded ECDH / XDH
// ---------------------------------------------------------------------------

/// A JWK from `prefix.<member>` fields; no fields at all (an "empty key"
/// case) is as unusable as a malformed one.
fn jwk_from_prefix(case: &Fields, prefix: &str) -> Result<Jwk, Error> {
    let json = jwk_json_from_fields(case, prefix).ok_or(Error::Malformed)?;
    Jwk::parse(&json)
}

/// `ecdh_<curve>_webcrypto`: both keys are `EC` JWKs; the private key's
/// curve rules, the peer must parse as a point on that same curve.
#[test]
fn ecdh_webcrypto() {
    for curve in ["secp256r1", "secp384r1", "secp521r1", "secp256k1"] {
        run_with(
            &load(&format!("ecdh_{curve}_webcrypto")),
            |_, _| None,
            |_, case| {
                let (Ok(sk), Ok(peer)) = (
                    jwk_from_prefix(case, "private"),
                    jwk_from_prefix(case, "public"),
                ) else {
                    return Outcome::Rejected;
                };
                let (Ok(sk), Ok(peer)) = (sk.ecdh_private_key(), peer.ec_public_key()) else {
                    return Outcome::Rejected;
                };
                match sk.diffie_hellman(&peer) {
                    Ok(z) => check_eq(&z, &case.hex("shared"), "shared secret"),
                    Err(_) => Outcome::Rejected,
                }
            },
        );
    }
}

/// `acceptable` policy for the XDH files: the crate implements RFC 7748
/// including its all-zero output check, so a low-order peer that yields the
/// zero secret is rejected, while twist and non-canonical points are
/// computed exactly as the RFC defines them.
fn xdh_strict(_: &Fields, case: &Fields) -> Option<Expected> {
    if case.has_flag("ZeroSharedSecret") {
        Some(Expected::Invalid)
    } else if case.has_flag("Twist") || case.has_flag("NonCanonicalPublic") {
        Some(Expected::Valid)
    } else {
        None
    }
}

#[test]
fn xdh_jwk() {
    for name in ["x25519_jwk", "x448_jwk"] {
        run_with(&load(name), xdh_strict, |_, case| {
            let (Ok(sk), Ok(peer)) = (
                jwk_from_prefix(case, "private"),
                jwk_from_prefix(case, "public"),
            ) else {
                return Outcome::Rejected;
            };
            if sk.okp_curve() != peer.okp_curve() {
                return Outcome::Rejected;
            }
            let z: Result<Vec<u8>, ()> = match sk.okp_curve() {
                Some(OkpCurve::X25519) => {
                    let (Ok(sk), Ok(pk)) = (sk.x25519_private_key(), peer.x25519_public_key())
                    else {
                        return Outcome::Rejected;
                    };
                    sk.diffie_hellman(pk.as_bytes())
                        .map(|z| z.to_vec())
                        .map_err(|_| ())
                }
                Some(OkpCurve::X448) => {
                    let (Ok(sk), Ok(pk)) = (sk.x448_private_key(), peer.x448_public_key()) else {
                        return Outcome::Rejected;
                    };
                    sk.diffie_hellman(pk.as_bytes())
                        .map(|z| z.to_vec())
                        .map_err(|_| ())
                }
                _ => return Outcome::Rejected,
            };
            match z {
                Ok(z) => check_eq(&z, &case.hex("shared"), "shared secret"),
                Err(()) => Outcome::Rejected,
            }
        });
    }
}
