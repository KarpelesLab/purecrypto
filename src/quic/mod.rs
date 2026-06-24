//! QUIC v1 (RFC 9000) — transport layer over UDP, secured by TLS 1.3 keys
//! per RFC 9001. Includes RFC 9002 loss recovery + congestion control and
//! RFC 9221 unreliable datagram extension.
//!
//! This module is sans-I/O: the engine takes wire datagrams via `feed`
//! and produces wire datagrams via `pop`. The host wires it to a
//! `UdpSocket`.
//!
//! The [`QuicConnection`] state machine drives the full v1 transport over
//! the sans-I/O feed/pop seam: varint / packet-number / frame codecs and
//! transport parameters, per-direction Initial + Handshake + 1-RTT keys
//! with header protection (RFC 9001 §5), the TLS-QUIC seam (`QuicHooks`),
//! per-level CRYPTO reassembly, ACK emission, RFC 9002 loss recovery with
//! NewReno congestion control, streams with flow control, Retry + address
//! validation, connection-ID rotation, key update, and RFC 9221 unreliable
//! DATAGRAMs. Out of scope: 0-RTT emission, the idle-timeout timer (only
//! the PTO is wired), HTTP/3, and stateless-reset emission.

// QUIC v1 is shipped; the server direction interops with OpenSSL 3.5's QUIC
// client, with several follow-ups still open (see the project notes). A
// number of parsed-but-not-yet-consumed packet/header
// fields, ACK/version-negotiation codec helpers, ECN counters, PnSet query
// methods, and reserved RFC 9000 stream-state variants are intentionally
// retained for that pending work and for protocol-completeness/auditability
// against the RFCs. Rather than scatter per-item `#[allow]`s, dead_code is
// suppressed module-wide here; revisit and tighten once interop work lands.
#![allow(dead_code)]

pub(crate) mod ack;
pub(crate) mod cid;
pub(crate) mod client;
pub(crate) mod congestion;
pub(crate) mod connection;
pub(crate) mod crypto;
pub(crate) mod crypto_buf;
pub(crate) mod datagram;
pub(crate) mod endpoint;
pub(crate) mod frame;
pub(crate) mod loss;
pub(crate) mod path;
pub(crate) mod pkt;
pub(crate) mod pn;
pub(crate) mod retry;
pub(crate) mod server;
pub(crate) mod stream;
pub(crate) mod streams;
pub(crate) mod tls_glue;
pub mod transport_params;
pub(crate) mod varint;

pub use connection::{QuicConfig, QuicConnection, Role};
pub use stream::StreamId;
pub use transport_params::TransportParameters;
