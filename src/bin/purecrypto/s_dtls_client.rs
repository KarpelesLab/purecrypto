//! `purecrypto s_dtls_client` — convenience alias for
//! `purecrypto s_client -dtls1_2`.
//!
//! This binary is a thin shim that injects `-dtls1_2` into the argument
//! list and dispatches into [`crate::s_client::run`]. The actual DTLS
//! 1.2 client logic lives in `s_client.rs` so that the unified
//! `-tls1_2` / `-dtls1_2` / `-dtls1_3` flag set on `s_client` reuses
//! the same UDP plumbing. See [`crate::dtls_io`].
//!
//! Cipher-suite scope matches the underlying
//! [`purecrypto::dtls::DtlsClientConnection12`]: the single suite
//! `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (RFC 5289), X25519 ECDHE,
//! and ECDSA-P256 server certificates.

use crate::s_client;
use crate::util::Args;

pub(crate) fn run(args: Args) {
    // Inject `-dtls1_2` ahead of the user-supplied flags. Right-most
    // wins, so a user passing e.g. `s_dtls_client -dtls1_3 ...` will
    // still get DTLS 1.3 — which is the most useful escape hatch.
    s_client::run(args.with_prefix(&["-dtls1_2"]));
}
