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
//!
//! # Legacy TLS 1.0 / 1.1 / SSL 3.0 (opt-in, off by default)
//!
//! The non-default `tls-legacy` Cargo feature adds the deprecated
//! SSL 3.0 / TLS 1.0 / TLS 1.1 protocol versions and their CBC
//! MAC-then-encrypt cipher suites — `TLS_RSA_WITH_*` (static-RSA key
//! transport) and `TLS_ECDHE_RSA_WITH_*` over AES-CBC-SHA, AES-CBC-SHA256
//! (TLS 1.0/1.1 only) and 3DES-CBC-SHA — for client and server roles.
//! These exist purely to interoperate with legacy hardware (e.g. VoIP-phone
//! provisioning servers) that speaks nothing newer.
//!
//! Enabling the feature does **not** change defaults: a [`Config`] still
//! negotiates only TLS 1.2/1.3 unless the caller explicitly lowers
//! [`Config::min_version`] (e.g. to [`ProtocolVersion::TLSv1_0`]). To offer
//! *only* legacy versions — talking to a peer that rejects a TLS 1.2
//! ClientHello — also lower `max_version`.
//!
//! **These versions are insecure (RFC 8996).** They rely on MD5/SHA-1 in the
//! PRF and signatures, are subject to CBC padding-oracle attacks (Lucky13;
//! the legacy CBC decrypt is constant-time + uniform-error but does not yet
//! fully equalise the MAC block count), BEAST (mitigated on TLS 1.0 send via
//! 1/n-1 record splitting), and — for SSL 3.0 — POODLE (unauthenticated CBC
//! padding, which cannot be fixed). Enable `tls-legacy` only for last-resort
//! interop, and never expose it where an adversary controls a chosen-plaintext
//! timing/oracle channel. Prefer TLS 1.2+ AEAD, which this crate keeps fully
//! constant-time.

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
#[cfg(feature = "mio")]
pub mod mio;
pub(crate) mod pki;
pub(crate) mod quic_hooks;
mod signer;
#[cfg(feature = "tokio")]
pub mod tokio;
mod version;

pub use config::{ClientAuth, Config, ConfigBuilder, EntropySource, Identity, SigningKey};
#[cfg(test)]
pub(crate) use conn::ClientCertConfig;
#[cfg(test)]
#[cfg(feature = "std")]
pub(crate) use conn::ReplayWindow;
pub use connection::{Connection, HandshakeStatus, SignatureRequest, Step};
pub use crypto::HashAlg;
pub use error::{Alert, AlertDescription, Error};
pub use groups::NamedGroup;
pub use keylog::KeyLog;
#[cfg(feature = "std")]
pub use keylog::{WriterKeyLog, file_keylog};
pub use pki::{CrlStore, PolicyOptions, RootCertStore};
#[cfg(feature = "std")]
pub use signer::LocalSigner;
pub use signer::{PrivateKey, Readiness, SignOp, SignProgress};
pub use version::{ContentType, ProtocolVersion};
