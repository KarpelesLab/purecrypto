//! BLS signatures on BLS12-377, minimal-pubkey-size variant: public keys in `G1`
//! (48 bytes compressed), signatures in `G2` (96 bytes compressed),
//! messages hashed with `BLS12377G2_XMD:SHA-256_SSWU_RO_`
//! ([`hash_to_g2`](super::hash_to_g2)).
//!
//! The scheme is `draft-irtf-cfrg-bls-signature-05` — `KeyGen`, `SkToPk`,
//! `Sign`, `Verify`, `Aggregate`, `AggregateVerify`, and the three schemes
//! ([`Scheme::Basic`], [`Scheme::MessageAugmentation`],
//! [`Scheme::ProofOfPossession`] with `PopProve` / `PopVerify` /
//! [`fast_aggregate_verify`]) — instantiated on BLS12-377.
//!
//! **No standard ciphersuite exists for BLS12-377**: the draft only
//! specifies BLS12-381. The ciphersuite IDs here ([`DST_BASIC`],
//! [`DST_AUG`], [`DST_POP`], [`DST_POP_PROOF`]) follow the draft's naming
//! rule (`BLS_SIG_` ‖ hash-to-curve suite ‖ `NUL_` / `AUG_` / `POP_`) over
//! the hash-to-curve suite this crate shares with gnark-crypto, so two
//! implementations interoperate exactly when they use these documented IDs.
//! Other deployments (Celo-style BLS12-377 BLS, …) use different hash-to-curve
//! constructions and are **not** compatible.
//!
//! `KeyValidate` (subgroup membership and non-identity) is applied by
//! [`PublicKey::from_bytes`], so every `PublicKey` value is valid;
//! signatures are subgroup-checked on decoding, as `CoreVerify` requires.
//! Key generation, signing and proofs of possession are constant time in
//! the secret key; everything here is allocator-free.
//!
//! # Example
//!
//! ```
//! use purecrypto::bls12_377::min_pk::{SecretKey, Scheme, Signature, aggregate_verify};
//!
//! let sk1 = SecretKey::generate(b"an IKM of at least thirty-two bytes!", b"").unwrap();
//! let sk2 = SecretKey::generate(b"another IKM of at least 32 bytes long", b"").unwrap();
//! let (pk1, pk2) = (sk1.public_key(), sk2.public_key());
//!
//! let sig1 = sk1.sign(Scheme::Basic, b"message one");
//! pk1.verify(Scheme::Basic, b"message one", &sig1).unwrap();
//! assert!(pk1.verify(Scheme::Basic, b"message two", &sig1).is_err());
//!
//! // Basic-scheme aggregation needs distinct messages.
//! let sig2 = sk2.sign(Scheme::Basic, b"message two");
//! let agg = Signature::aggregate(&[sig1, sig2]).unwrap();
//! aggregate_verify(Scheme::Basic, &[pk1, pk2], &[b"message one", b"message two"], &agg).unwrap();
//! ```

crate::pairing_common::bls_sig::bls_signature! {
    curve: "BLS12-377",
    variant: min_pk,
    suite: "BLS12377G2_XMD:SHA-256_SSWU_RO_",
    pk_len: 48,
    pk_ulen: 96,
    sig_len: 96,
    sig_ulen: 192,
}

#[cfg(test)]
crate::pairing_common::bls_sig::bls_signature_tests! {
    curve: "bls12-377",
    variant: "min_pk",
    pk_len: 48,
    sig_len: 96,
}
