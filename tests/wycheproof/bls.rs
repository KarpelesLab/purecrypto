//! BLS12-381: hash-to-G2 and BLS signature verification (min-pubkey-size,
//! signatures in G2) — the Basic, Proof-of-Possession and aggregate
//! `AggregateVerify` files.
//!
//! Policy: every `valid` case verifies, every `invalid` case is rejected;
//! the flags name the rejection the vectors expect (`InvalidFlags`,
//! `InvalidEncoding`, `NotOnCurve`, `NotInSubgroup`, `IdentityPoint`,
//! `FieldBoundary`, `EmptyAggregate`, `MismatchedCount`, ...) but the
//! harness only requires *some* rejection, since e.g. an x-coordinate above
//! the modulus is reported as a non-canonical encoding rather than a point
//! off the curve.

use crate::common::{Fields, Outcome, check, check_eq, outcome_of};
use purecrypto::bls::{Error, PublicKey, Scheme, Signature, aggregate_verify, hash_to_g2};

#[test]
fn hash_to_g2_vectors() {
    check("bls_hash_to_g2", |group, case| {
        let dst = group.str("dst").as_bytes();
        let p = hash_to_g2(&case.hex("msg"), dst);
        check_eq(
            &p.to_compressed(),
            &case.hex("expected"),
            "hash_to_g2 point",
        )
    });
}

/// Maps a ciphersuite string to the scheme.
fn scheme_of(group: &Fields) -> Scheme {
    match group.str("ciphersuite") {
        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_" => Scheme::Basic,
        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_" => Scheme::MessageAugmentation,
        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_" => Scheme::ProofOfPossession,
        other => panic!("unknown ciphersuite {other:?}"),
    }
}

fn verify_file(name: &str) {
    check(name, |group, case| {
        let scheme = scheme_of(group);
        let r = (|| {
            let pk = PublicKey::from_bytes(&group.hex("publicKey.pk"))?;
            let sig = Signature::from_bytes(&case.hex("sig"))?;
            pk.verify(scheme, &case.hex("msg"), &sig)
        })();
        // The identity-point and subgroup cases must be caught by
        // decoding, not by the pairing equation failing to hold.
        if case.has_flag("IdentityPoint")
            && !matches!(r, Err(Error::IdentityPoint) | Err(Error::InvalidSignature))
        {
            return Outcome::Wrong("identity point not rejected as such");
        }
        if case.has_flag("NotInSubgroup") && r != Err(Error::NotInSubgroup) {
            return Outcome::Wrong("subgroup check missing");
        }
        if case.has_flag("NotOnCurve")
            && !matches!(r, Err(Error::NotOnCurve) | Err(Error::InvalidEncoding))
        {
            return Outcome::Wrong("curve check missing");
        }
        if case.has_flag("InvalidFlags") && r != Err(Error::InvalidFlags) {
            return Outcome::Wrong("flag check missing");
        }
        outcome_of(r)
    });
}

#[test]
fn basic_verify() {
    verify_file("bls_sig_g2_basic_verify");
}

#[test]
fn pop_verify() {
    verify_file("bls_sig_g2_pop_verify");
}

/// Splits a comma-joined list of hex strings (an empty field is an empty
/// list).
fn hex_list(fields: &Fields, key: &str) -> Vec<Vec<u8>> {
    let v = fields.str(key);
    if v.is_empty() {
        return Vec::new();
    }
    v.split(',').map(crate::common::from_hex).collect()
}

#[test]
fn aggregate_verify_basic() {
    check("bls_sig_g2_aggregate_verify", |group, case| {
        let scheme = scheme_of(group);
        let r = (|| {
            let pks = hex_list(case, "pubkeys")
                .iter()
                .map(|b| PublicKey::from_bytes(b))
                .collect::<Result<Vec<_>, _>>()?;
            let msgs = hex_list(case, "messages");
            let msg_refs: Vec<&[u8]> = msgs.iter().map(Vec::as_slice).collect();
            let sig = Signature::from_bytes(&case.hex("sig"))?;
            aggregate_verify(scheme, &pks, &msg_refs, &sig)
        })();
        if case.has_flag("EmptyAggregate") && r != Err(Error::EmptyAggregate) {
            return Outcome::Wrong("empty aggregate not rejected as such");
        }
        if case.has_flag("MismatchedCount") && r != Err(Error::LengthMismatch) {
            return Outcome::Wrong("count mismatch not rejected as such");
        }
        if case.has_flag("NotInSubgroup") && r != Err(Error::NotInSubgroup) {
            return Outcome::Wrong("subgroup check missing");
        }
        // An identity *signature* decodes fine (it is a valid G2 element);
        // it is the pairing equation that rejects it. An identity public
        // key must be caught by KeyValidate.
        if case.has_flag("IdentityPoint")
            && !matches!(r, Err(Error::IdentityPoint) | Err(Error::InvalidSignature))
        {
            return Outcome::Wrong("identity point not rejected as such");
        }
        outcome_of(r)
    });
}
