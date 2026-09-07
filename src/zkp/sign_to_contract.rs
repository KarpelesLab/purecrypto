//! ECDSA sign-to-contract: commit to arbitrary data inside a signature's nonce.
//!
//! **EXPERIMENTAL** — no semver-stability guarantee. See the [module-level
//! documentation](super) for the clean-room policy and interop caveats.
//!
//! # Source of truth
//!
//! Pay-to-contract/sign-to-contract construction (OpenTimestamps; Eternity Wall). The nonce is tweaked as `k' = k + H(R || data)` so the signature doubles as a commitment to `data`, verifiable by anyone given the opening.
//!
//! # Status
//!
//! Not yet implemented — this file is a placeholder so the feature flag and
//! module path exist. Implementation is in progress.
