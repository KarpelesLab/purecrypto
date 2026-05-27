//! QUIC v1 (RFC 9000) — transport layer over UDP, secured by TLS 1.3 keys
//! per RFC 9001. Includes RFC 9002 loss recovery + congestion control and
//! RFC 9221 unreliable datagram extension.
//!
//! This module is sans-I/O: the engine takes wire datagrams via `feed`
//! and produces wire datagrams via `pop`. The host wires it to a
//! `UdpSocket`.
//!
//! Phase 1 (this module) ships the pure data-structure foundations:
//! the variable-length integer codec, packet-number bookkeeping plus the
//! truncation/expansion algorithm, the [`frame`] codec for all standard
//! frame types, and the transport-parameter list used inside the TLS
//! `quic_transport_parameters` extension. No keys, no packet protection,
//! no TLS plumbing — those land in later phases.

pub(crate) mod frame;
pub(crate) mod pn;
pub mod transport_params;
pub(crate) mod varint;

pub use transport_params::TransportParameters;
