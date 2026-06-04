//! `purecrypto q_client` — open a QUIC v1 (RFC 9000) connection over UDP.
//!
//! This binary is a thin shim that injects `-quic` into the argument
//! list and dispatches into [`crate::s_client::run`]. The shared
//! `s_client.rs` dispatcher routes `-quic` to the QUIC-specific UDP
//! driver in [`crate::quic_cli`]. The plumbing mirrors the
//! `s_dtls_client` shim.
//!
//! Scope:
//! - Single QUIC v1 (RFC 9000) connection, TLS 1.3 keys (RFC 9001).
//! - One bidirectional stream carries stdin → server, and the server's
//!   reply → stdout.
//! - DATAGRAM (RFC 9221) is enabled at the transport-parameter layer
//!   (`max_datagram_frame_size = 1200`) but the CLI itself only drives
//!   the stream API. Use the library API directly for unreliable
//!   datagrams.

use crate::s_client;
use crate::util::Args;

pub(crate) fn run(args: Args) {
    // Inject `-quic` ahead of the user's flags. Right-most wins, so
    // `q_client -tls1_3 ...` still demotes to TLS 1.3 over TCP — useful
    // as an escape hatch when comparing behavior.
    s_client::run(args.with_prefix(&["-quic"]));
}

#[cfg(target_vendor = "fullrust")]
#[allow(unused_imports)]
use crate::__prelude::*;
