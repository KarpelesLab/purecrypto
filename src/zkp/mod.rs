//! Zero-knowledge and commitment extensions over secp256k1.
//!
//! This module set mirrors the experimental modules of Blockstream's
//! `secp256k1-zkp`: sign-to-contract, ECDSA adaptor signatures, Pedersen
//! commitments, range proofs, asset surjection proofs, BIP340 half-aggregation
//! and ring-signature address whitelisting.
//!
//! # Stability
//!
//! **Every module here is EXPERIMENTAL.** They are off by default, carry **no
//! semver-stability guarantee**, and their APIs may change in any release. The
//! upstream modules they correspond to are themselves marked experimental.
//!
//! # Provenance and the clean-room policy
//!
//! These are implemented **clean-room**, from academic papers and public
//! specifications only. No `secp256k1-zkp` implementation source (`src/*.c`)
//! was consulted while writing them. `secp256k1-zkp` is MIT-licensed, so
//! derivation would have been permissible with attribution; the clean-room
//! route is a deliberate choice to keep this crate's "no foreign code" charter
//! intact and its provenance simple to audit.
//!
//! Interoperability is established by treating `secp256k1-zkp` as a **black-box
//! oracle**: it is built from source in a developer-only harness, driven
//! through its public C API (`include/*.h`, which is the interface contract),
//! and its outputs are compared byte-for-byte against ours. The harness lives
//! outside the crate and is never vendored, linked into the library, or shipped.
//! See `tools/zkp-interop/README.md`.
//!
//! Each submodule records the specific paper or specification it was built
//! from, so a reviewer can check the implementation against its source of
//! truth rather than against another implementation.
//!
//! # A caveat on wire formats
//!
//! Range proofs, surjection proofs and whitelisting have **no normative
//! specification**. The Confidential Assets paper describes the constructions,
//! but the byte layout is defined by the reference implementation. Those three
//! modules therefore document their interop status explicitly, and where
//! byte-exact compatibility has not been established against the oracle they
//! say so rather than implying it.

#[cfg(feature = "zkp-adaptor")]
pub mod adaptor;

#[cfg(feature = "zkp-halfagg")]
pub mod halfagg;

#[cfg(feature = "zkp-pedersen")]
pub mod pedersen;

#[cfg(feature = "zkp-rangeproof")]
pub mod rangeproof;

#[cfg(feature = "zkp-sign-to-contract")]
pub mod sign_to_contract;

#[cfg(feature = "zkp-surjection")]
pub mod surjection;

#[cfg(feature = "zkp-whitelist")]
pub mod whitelist;
