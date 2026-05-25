//! TLS 1.3 (RFC 8446).
//!
//! A transport-agnostic ("sans-I/O") TLS implementation: the connection state
//! machine consumes and produces bytes through buffers and never touches a
//! socket. A blocking [`Stream`](stream::Stream) adapter over any
//! `std::io::Read + Write` (the TCP helper) is provided separately.
//!
//! Only TLS 1.3 is implemented, but the version abstraction
//! ([`ProtocolVersion`](version::ProtocolVersion)) leaves room for earlier
//! versions. Cipher suites: `TLS_AES_128_GCM_SHA256` and
//! `TLS_AES_256_GCM_SHA384`; key exchange: X25519 and secp256r1.
//!
//! **Status:** under construction — the wire codec and version handling are in
//! place; the handshake state machine is being built up.

// The module is built in phases; lower layers (codec, primitives) are consumed
// by the handshake state machine landing in later phases. Remove once wired.
#![allow(dead_code)]

mod codec;
mod error;
mod version;

pub use error::{Alert, AlertDescription, Error};
pub use version::{ContentType, ProtocolVersion};
