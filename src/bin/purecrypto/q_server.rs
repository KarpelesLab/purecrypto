//! `purecrypto q_server` — run a one-shot QUIC v1 (RFC 9000) server.
//!
//! Thin shim that injects `-quic` into the argument list and dispatches
//! into [`crate::s_server::run`]. The shared `s_server.rs` dispatcher
//! routes `-quic` to the QUIC-specific UDP driver in
//! [`crate::quic_cli`]. The plumbing mirrors the `s_dtls_server` shim.
//!
//! Useful server flags:
//! - `-cert PEM -key PEM` — server identity (required).
//! - `-accept host:port` or `-accept PORT` — listen address.
//! - `-alpn h3` — ALPN to negotiate.
//! - `-www` — after the handshake, send a single canned line on the
//!   peer-initiated bidi stream and close. Useful for integration tests.
//! - `-retry` — require stateless-retry address validation
//!   (RFC 9000 §8.1.2).

use crate::s_server;
use crate::util::Args;

pub(crate) fn run(args: Args) {
    // Inject `-quic` ahead of user-supplied flags. Right-most wins.
    s_server::run(args.with_prefix(&["-quic"]));
}
