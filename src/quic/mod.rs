//! QUIC v1 (RFC 9000) — transport layer over UDP, secured by TLS 1.3 keys
//! per RFC 9001. Includes RFC 9002 loss recovery + congestion control and
//! RFC 9221 unreliable datagram extension.
//!
//! This module is sans-I/O: the engine takes wire datagrams via `feed`
//! and produces wire datagrams via `pop`. The host wires it to a
//! `UdpSocket`.
//!
//! Phase 1 shipped the pure data-structure foundations: varint, packet
//! numbers, the frame codec, and the transport parameters. Phase 2 added
//! per-direction Initial + handshake keys plus the long/short header
//! codec and header-protection wrappers (RFC 9001 §5). Phase 3 added the
//! TLS-QUIC seam (`QuicHooks` trait, `EngineMode::Quic`).
//!
//! Phase 4 (this module) glues the previous three phases into the
//! [`QuicConnection`] state machine: per-level CRYPTO reassembly, ACK
//! emission, PADDING on the client's first datagram, PTO-driven Initial /
//! Handshake retransmission, in-process loopback handshake to completion.
//! Streams, full RFC 9002, Retry, key update, and DATAGRAM are deferred
//! to later phases per the master plan.

pub(crate) mod ack;
pub(crate) mod cid;
pub(crate) mod client;
pub(crate) mod congestion;
pub(crate) mod connection;
pub(crate) mod crypto;
pub(crate) mod crypto_buf;
pub(crate) mod endpoint;
pub(crate) mod frame;
pub(crate) mod loss;
pub(crate) mod pkt;
pub(crate) mod pn;
pub(crate) mod server;
pub(crate) mod stream;
pub(crate) mod streams;
pub(crate) mod tls_glue;
pub mod transport_params;
pub(crate) mod varint;

pub use connection::{QuicConfig, QuicConnection, Role};
pub use stream::StreamId;
pub use transport_params::TransportParameters;
