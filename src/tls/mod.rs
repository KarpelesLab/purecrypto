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
//! **Status:** experimental. A full 1-RTT handshake interoperates in-process
//! and over TCP, and the key schedule, record protection, and signatures are
//! validated against the RFC 8448 traces. Not audited; APIs may change.

pub(crate) mod codec;
mod conn;
pub(crate) mod crypto;
mod error;
pub(crate) mod pki;
mod version;

pub use conn::{
    ClientAuthPolicy, ClientAuthPolicy12, ClientCertConfig, ClientConfig, ClientConfig12,
    ClientConnection, ClientConnection12, ReceivedSessionTicket, ServerConfig, ServerConfig12,
    ServerConnection, ServerConnection12, StoredSession, StoredSession12,
};
#[cfg(feature = "std")]
pub use conn::{Connection, ReplayWindow, Stream};
pub use crypto::HashAlg;
pub use error::{Alert, AlertDescription, Error};
pub use pki::{CrlStore, RootCertStore};
pub use version::{ContentType, ProtocolVersion};
