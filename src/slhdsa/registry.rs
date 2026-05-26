//! SLH-DSA entries in the signature registry.
//!
//! Twelve zero-sized types, one per FIPS 205 parameter set. Each `verify`
//! parses the SPKI (whose `AlgorithmIdentifier` carries the set-specific
//! OID) and delegates to the existing `slhdsa::PublicKey::verify`.
//!
//! SLH-DSA signatures are large (7–50 KB depending on parameter set), so
//! none of these entries appear on the default
//! [`SignaturePolicy::modern`](crate::signature_registry::SignaturePolicy::modern)
//! whitelist — they require an explicit opt-in
//! (`policy.permit("slh-dsa-sha2-128f")`, etc.) when chains need them.

use crate::der::{Reader, parse_oid};
use crate::signature_registry::SignatureAlgorithm;
use crate::slhdsa::{ParamSet, PublicKey};
use crate::x509::Error;

/// Parses an SLH-DSA SPKI under the entry's OID; returns the parsed key.
fn parse_slhdsa_spki(spki: &[u8], expected_set: ParamSet) -> Result<PublicKey, Error> {
    let mut reader = Reader::new(spki);
    let mut outer = reader.read_sequence()?;
    let mut algid = outer.read_sequence()?;
    let alg = parse_oid(algid.read_oid()?)?;
    if alg.as_slice() != expected_set.oid() {
        return Err(Error::UnsupportedAlgorithm);
    }
    let key_bits = outer.read_bit_string()?;
    PublicKey::from_bytes(expected_set, key_bits).map_err(|_| Error::Malformed)
}

macro_rules! slhdsa_entry {
    (
        $(#[$m:meta])*
        $name:ident, $id:expr, $set:expr
    ) => {
        $(#[$m])*
        pub(crate) struct $name;

        impl SignatureAlgorithm for $name {
            fn id(&self) -> &'static str { $id }
            fn x509_oids(&self) -> &'static [&'static [u64]] {
                // Re-emit via a `const` so the macro keeps the slice
                // `'static`. `ParamSet::oid` is a const-eligible function
                // in spirit but uses an array-index lookup so we can't
                // call it in const context; embed the OID literally.
                $set.x509_oids_slice()
            }
            fn tls_schemes(&self) -> &'static [u16] { &[] }
            fn verify(&self, spki: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
                let key = parse_slhdsa_spki(spki, $set.set)?;
                if key.verify(signature, message, b"") {
                    Ok(())
                } else {
                    Err(Error::Verification)
                }
            }
        }
    };
}

/// Per-parameter-set static OID slice carrier. Each entry's `x509_oids`
/// returns its own `&[&[u64]]` constant via this helper.
struct SetOid {
    set: ParamSet,
    oids: &'static [&'static [u64]],
}

impl SetOid {
    const fn new(set: ParamSet, oids: &'static [&'static [u64]]) -> Self {
        SetOid { set, oids }
    }
    fn x509_oids_slice(&self) -> &'static [&'static [u64]] {
        self.oids
    }
}

// Literal OIDs from FIPS 205 (NIST). The SLH-DSA OIDs allocated under
// 2.16.840.1.101.3.4.3.{20..31} (SHA-2 then SHAKE × s/f × {128,192,256}).
const OID_SHA2_128S: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 20];
const OID_SHA2_128F: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 21];
const OID_SHA2_192S: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 22];
const OID_SHA2_192F: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 23];
const OID_SHA2_256S: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 24];
const OID_SHA2_256F: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 25];
const OID_SHAKE_128S: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 26];
const OID_SHAKE_128F: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 27];
const OID_SHAKE_192S: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 28];
const OID_SHAKE_192F: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 29];
const OID_SHAKE_256S: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 30];
const OID_SHAKE_256F: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 31];

const SHA2_128S: SetOid = SetOid::new(ParamSet::Sha2_128s, &[OID_SHA2_128S]);
const SHA2_128F: SetOid = SetOid::new(ParamSet::Sha2_128f, &[OID_SHA2_128F]);
const SHA2_192S: SetOid = SetOid::new(ParamSet::Sha2_192s, &[OID_SHA2_192S]);
const SHA2_192F: SetOid = SetOid::new(ParamSet::Sha2_192f, &[OID_SHA2_192F]);
const SHA2_256S: SetOid = SetOid::new(ParamSet::Sha2_256s, &[OID_SHA2_256S]);
const SHA2_256F: SetOid = SetOid::new(ParamSet::Sha2_256f, &[OID_SHA2_256F]);
const SHAKE_128S: SetOid = SetOid::new(ParamSet::Shake_128s, &[OID_SHAKE_128S]);
const SHAKE_128F: SetOid = SetOid::new(ParamSet::Shake_128f, &[OID_SHAKE_128F]);
const SHAKE_192S: SetOid = SetOid::new(ParamSet::Shake_192s, &[OID_SHAKE_192S]);
const SHAKE_192F: SetOid = SetOid::new(ParamSet::Shake_192f, &[OID_SHAKE_192F]);
const SHAKE_256S: SetOid = SetOid::new(ParamSet::Shake_256s, &[OID_SHAKE_256S]);
const SHAKE_256F: SetOid = SetOid::new(ParamSet::Shake_256f, &[OID_SHAKE_256F]);

slhdsa_entry!(
    /// SLH-DSA-SHA2-128s — small signatures (≈7.9 KB) at NIST level 1.
    SlhDsaSha2128s, "slh-dsa-sha2-128s", SHA2_128S
);
slhdsa_entry!(
    /// SLH-DSA-SHA2-128f — fast signing at NIST level 1.
    SlhDsaSha2128f, "slh-dsa-sha2-128f", SHA2_128F
);
slhdsa_entry!(
    /// SLH-DSA-SHA2-192s — NIST level 3.
    SlhDsaSha2192s, "slh-dsa-sha2-192s", SHA2_192S
);
slhdsa_entry!(
    /// SLH-DSA-SHA2-192f — NIST level 3.
    SlhDsaSha2192f, "slh-dsa-sha2-192f", SHA2_192F
);
slhdsa_entry!(
    /// SLH-DSA-SHA2-256s — NIST level 5.
    SlhDsaSha2256s, "slh-dsa-sha2-256s", SHA2_256S
);
slhdsa_entry!(
    /// SLH-DSA-SHA2-256f — NIST level 5.
    SlhDsaSha2256f, "slh-dsa-sha2-256f", SHA2_256F
);
slhdsa_entry!(
    /// SLH-DSA-SHAKE-128s — NIST level 1.
    SlhDsaShake128s, "slh-dsa-shake-128s", SHAKE_128S
);
slhdsa_entry!(
    /// SLH-DSA-SHAKE-128f — NIST level 1.
    SlhDsaShake128f, "slh-dsa-shake-128f", SHAKE_128F
);
slhdsa_entry!(
    /// SLH-DSA-SHAKE-192s — NIST level 3.
    SlhDsaShake192s, "slh-dsa-shake-192s", SHAKE_192S
);
slhdsa_entry!(
    /// SLH-DSA-SHAKE-192f — NIST level 3.
    SlhDsaShake192f, "slh-dsa-shake-192f", SHAKE_192F
);
slhdsa_entry!(
    /// SLH-DSA-SHAKE-256s — NIST level 5.
    SlhDsaShake256s, "slh-dsa-shake-256s", SHAKE_256S
);
slhdsa_entry!(
    /// SLH-DSA-SHAKE-256f — NIST level 5.
    SlhDsaShake256f, "slh-dsa-shake-256f", SHAKE_256F
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::signature_registry::{find_by_id, find_by_oid};
    use crate::slhdsa::PrivateKey;
    use crate::x509::AnyPublicKey;

    #[test]
    fn slh_dsa_128f_lookup_and_verify() {
        let mut rng = HmacDrbg::<Sha256>::new(b"reg-slhdsa-128f", b"n", &[]);
        let (sk, pk) = PrivateKey::generate(ParamSet::Sha2_128f, &mut rng);
        let spki = AnyPublicKey::SlhDsa(pk).to_spki_der();
        let sig = sk.sign(&mut rng, b"hi", b"").unwrap();

        let by_id = find_by_id("slh-dsa-sha2-128f").unwrap();
        by_id.verify(&spki, b"hi", &sig).unwrap();
        let by_oid = find_by_oid(OID_SHA2_128F).unwrap();
        assert_eq!(by_oid.id(), "slh-dsa-sha2-128f");
    }
}
