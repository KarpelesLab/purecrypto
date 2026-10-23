//! Internals shared by the pairing-friendly curves: fixed-limb Montgomery
//! arithmetic and the RFC 9380 `expand_message_xmd`.

pub(crate) mod mont;
mod xmd;

pub use xmd::expand_message_xmd;
