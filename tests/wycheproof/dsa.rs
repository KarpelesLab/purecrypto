//! FIPS 186-4 DSA verification: DER (`Dss-Sig-Value`) and P1363 (fixed-width
//! `r ‖ s`) signatures over the 2048/224, 2048/256 and 3072/256 parameter
//! sets with SHA-224 / SHA-256.
//!
//! Every group's key is built twice — from the `(p, q, g, y)` components and
//! from `publicKeyDer` through the SPKI parser — and the two must agree (and
//! re-encode to the group's exact DER). Accepted signatures must also
//! re-encode to the input bytes, since strict DER and P1363 are both
//! canonical.
//!
//! `acceptable` policy: the only such flag in these files is `MissingZero`
//! (a legacy encoding whose top-bit-set `r` lacks its `0x00` sign pad, i.e. a
//! negative INTEGER under DER). The crate's strict parser rejects it, and
//! this harness pins that as *required*. Any new `acceptable` flag fails the
//! run until it is pinned here too.

use crate::common::{Expected, Fields, Outcome, load, run_with};
use purecrypto::dsa::{DsaParams, DsaPublicKey, DsaSignature};
use purecrypto::hash::{Sha224, Sha256};

/// How the `sig` field is encoded.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Enc {
    Der,
    P1363,
}

impl Enc {
    fn of(file: &str) -> Enc {
        if file.ends_with("_p1363") {
            Enc::P1363
        } else {
            Enc::Der
        }
    }
}

/// The group's public key from its components, cross-checked against the
/// SPKI form and the advertised `keySize`.
fn public_key(group: &Fields) -> DsaPublicKey {
    let params = DsaParams::from_be_bytes(
        &group.hex("publicKey.p"),
        &group.hex("publicKey.q"),
        &group.hex("publicKey.g"),
    )
    .expect("group parameters are valid");
    assert_eq!(
        params.p_bits() as u64,
        group.int("publicKey.keySize"),
        "keySize is the width of p"
    );
    let pk = DsaPublicKey::from_be_bytes(params, &group.hex("publicKey.y"))
        .expect("group public key is valid");
    let der = group.hex("publicKeyDer");
    let spki = DsaPublicKey::from_spki_der(&der).expect("group SPKI parses");
    assert_eq!(spki, pk, "SPKI key disagrees with the components");
    assert_eq!(pk.to_spki_der(), der, "SPKI re-encoding differs");
    pk
}

fn verify(pk: &DsaPublicKey, sha: &str, msg: &[u8], sig: &DsaSignature) -> Result<(), ()> {
    match sha {
        "SHA-224" => pk.verify::<Sha224>(msg, sig),
        "SHA-256" => pk.verify::<Sha256>(msg, sig),
        other => panic!("unsupported hash {other}"),
    }
    .map_err(|_| ())
}

/// Which `acceptable` cases the crate must reject.
fn strict(_group: &Fields, case: &Fields) -> Option<Expected> {
    let flags = case.flags();
    assert_eq!(
        flags,
        ["MissingZero"],
        "tcId {}: unpinned acceptable flags {flags:?}",
        case.tc_id()
    );
    Some(Expected::Invalid)
}

fn dsa_file(file: &str) {
    let enc = Enc::of(file);
    let vectors = load(file);
    // Keys are parsed (and validated: two subgroup exponentiations plus the
    // Miller-Rabin rounds on q) once per group, not once per case.
    let mut cached: Option<(Vec<u8>, DsaPublicKey)> = None;
    run_with(&vectors, strict, |group, case| {
        let der = group.hex("publicKeyDer");
        if cached.as_ref().is_none_or(|(d, _)| *d != der) {
            cached = Some((der, public_key(group)));
        }
        let pk = &cached.as_ref().expect("cached").1;
        let q_len = pk.params().q_len();
        let sha = group.str("sha");
        let bytes = case.hex("sig");
        let sig = match enc {
            Enc::Der => DsaSignature::from_der(&bytes),
            Enc::P1363 => DsaSignature::from_p1363(&bytes, q_len),
        };
        let Ok(sig) = sig else {
            return Outcome::Rejected;
        };
        if verify(pk, sha, &case.hex("msg"), &sig).is_err() {
            return Outcome::Rejected;
        }
        // Both encodings are canonical, so an accepted signature must
        // re-encode to exactly the bytes that were parsed.
        let again = match enc {
            Enc::Der => sig.to_der(),
            Enc::P1363 => sig.to_p1363(q_len).expect("verified components fit q"),
        };
        if again != bytes {
            return Outcome::Wrong("accepted signature does not re-encode to its input");
        }
        Outcome::Accepted
    });
}

macro_rules! dsa_files {
    ($($name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                dsa_file(stringify!($name));
            }
        )*
    };
}

dsa_files! {
    dsa_2048_224_sha224,
    dsa_2048_224_sha224_p1363,
    dsa_2048_224_sha256,
    dsa_2048_224_sha256_p1363,
    dsa_2048_256_sha256,
    dsa_2048_256_sha256_p1363,
    dsa_3072_256_sha256,
    dsa_3072_256_sha256_p1363,
}
