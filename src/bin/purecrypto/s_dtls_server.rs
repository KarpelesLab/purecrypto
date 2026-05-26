//! `purecrypto s_dtls_server` — convenience alias for
//! `purecrypto s_server -dtls1_2`.
//!
//! This binary is a thin shim that injects `-dtls1_2` into the argument
//! list and dispatches into [`crate::s_server::run`]. The actual DTLS
//! 1.2 server logic lives in `s_server.rs` so that the unified
//! `-tls1_2` / `-dtls1_2` / `-dtls1_3` flag set on `s_server` reuses
//! the same UDP plumbing. See [`crate::dtls_io`].
//!
//! Cipher-suite scope matches
//! [`purecrypto::dtls::DtlsServerConnection12`]: only
//! `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (RFC 5289) with X25519
//! ECDHE and an ECDSA-P256 server certificate.

use crate::s_server;
use crate::util::Args;

pub(crate) fn run(args: Args) {
    // Inject `-dtls1_2` ahead of the user-supplied flags. Right-most
    // wins, so a user passing e.g. `s_dtls_server -dtls1_3 ...` will
    // still get DTLS 1.3 — which is the most useful escape hatch.
    s_server::run(args.with_prefix(&["-dtls1_2"]));
}
