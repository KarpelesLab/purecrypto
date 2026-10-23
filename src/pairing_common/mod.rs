//! Internals shared by the pairing-friendly curves: fixed-limb Montgomery
//! arithmetic, the RFC 9380 `expand_message_xmd`, and the BLS signature
//! scheme generic over BN254 and BLS12-377.

#[cfg(any(feature = "bn254", feature = "bls12-377"))]
pub(crate) mod bls_sig;
pub(crate) mod mont;
mod xmd;

pub use xmd::expand_message_xmd;
#[cfg(any(feature = "bn254", feature = "bls12-377"))]
pub(crate) use xmd::expand_message_xmd_parts;
