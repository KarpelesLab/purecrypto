//! Inner / outer ClientHello machinery (draft-ietf-tls-esni-22 §6).
//!
//! This module is the bridge between the wire-level codec
//! ([`super::config`], [`super::extension`]) and the live
//! [`crate::tls::Connection`] handshake state machine. It will host:
//!
//! - the **inner-CH builder**: same shape as the outer CH but with
//!   real SNI / ALPN / etc., minus any extensions that are echoed
//!   verbatim from the outer one (see `ech_outer_extensions`
//!   compression, §5.1);
//! - the **outer-CH derivation**: HPKE-seal the encoded inner CH and
//!   place the result in the outer's `encrypted_client_hello`
//!   extension. The outer CH's `server_name` is the
//!   `ECHConfig.public_name`;
//! - the **server-side decompressor**: reconstruct the canonical inner
//!   CH from the decrypted compressed form by substituting outer
//!   extensions for the named ones.
//!
//! The implementation lands incrementally; this module currently
//! exposes only the inner-form `encrypted_client_hello` marker
//! injected into the inner CH to disambiguate it from a non-ECH CH
//! after decompression (draft §5).

use super::extension::EchExtension;
use alloc::vec::Vec;

/// The inner-form `encrypted_client_hello` extension body the inner
/// CH carries (draft §5: `ECHClientHelloType inner` = `0x01`, no
/// further bytes). The server uses this marker to confirm a
/// decrypted CH was indeed sent as an ECH inner.
pub fn inner_extension_body() -> Vec<u8> {
    EchExtension::Inner.encode()
}
