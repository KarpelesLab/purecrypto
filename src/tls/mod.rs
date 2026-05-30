//! Transport Layer Security — TLS 1.2 (RFC 5246, AEAD suites per
//! RFC 7905 + Extended Master Secret per RFC 7627), TLS 1.3 (RFC 8446)
//! including session resumption, 0-RTT, and key update — and a unified
//! [`Config`] / [`Connection`] that also drives DTLS 1.2 / 1.3 (see
//! [`crate::dtls`]) and is reused by the QUIC stack ([`crate::quic`])
//! through an internal handshake-seam.
//!
//! A transport-agnostic ("sans-I/O") implementation: the connection
//! state machine consumes and produces bytes through buffers and never
//! touches a socket. The host wires the byte streams to a `TcpStream`
//! (see the `s_client` / `s_server` CLI examples) or any other
//! transport.
//!
//! **Cipher suites** — TLS 1.3: `TLS_AES_128_GCM_SHA256`,
//! `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`. TLS 1.2:
//! ECDHE with the same three AEAD suites per RFC 7905 (no CBC, no RC4).
//! **Key exchange** — X25519, secp256r1, secp384r1, plus the
//! X25519MLKEM768 PQ-hybrid group (draft-ietf-tls-ecdhe-mlkem).
//! **Signature schemes** — ECDSA (P-256/P-384/P-521), Ed25519, RSA-PSS,
//! RSA-PKCS1 (TLS 1.2 only), plus ML-DSA in TLS 1.3.
//!
//! **Status:** the handshake, record protection, key schedule, and
//! resumption paths are validated against the RFC 8448 traces and run
//! end-to-end against the in-tree CLI loopback tests across Linux,
//! macOS, and Windows. The codebase has had an internal security
//! audit (`b52157d`…`8aa0881`) but no external audit; APIs may still
//! evolve before 1.0.

#[cfg(feature = "cert-compression")]
#[doc(hidden)]
pub mod cert_compression;
pub(crate) mod codec;
mod config;
pub(crate) mod conn;
mod connection;
pub(crate) mod crypto;
#[cfg(feature = "ech")]
pub mod ech;
mod error;
mod groups;
pub(crate) mod keylog;
pub(crate) mod pki;
pub(crate) mod quic_hooks;
mod version;

pub use config::{ClientAuth, Config, ConfigBuilder, Identity, SigningKey};
#[cfg(test)]
pub(crate) use conn::ClientCertConfig;
#[cfg(test)]
#[cfg(feature = "std")]
pub(crate) use conn::ReplayWindow;
pub use connection::{Connection, HandshakeStatus};
pub use crypto::HashAlg;
pub use error::{Alert, AlertDescription, Error};
pub use groups::NamedGroup;
pub use keylog::KeyLog;
#[cfg(feature = "std")]
pub use keylog::{WriterKeyLog, file_keylog};
pub use pki::{CrlStore, RootCertStore};
pub use version::{ContentType, ProtocolVersion};
