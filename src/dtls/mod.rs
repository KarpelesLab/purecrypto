//! DTLS (Datagram TLS) — RFC 6347 (DTLS 1.2) and RFC 9147 (DTLS 1.3).
//!
//! Both protocols ride the same record / reassembly / replay / cookie chassis
//! defined in this module. Client and server state machines for each version
//! arrive in subsequent commits.
//!
//! The TLS handshake messages (ClientHello, ServerHello, Certificate, …) are
//! reused from [`crate::tls`]; this module is exclusively the datagram-shaped
//! transport that wraps them: 13-byte record headers, an explicit per-record
//! epoch, a 48-bit sequence number, anti-replay sliding window, and the
//! HelloVerifyRequest cookie that gates server resource allocation.

mod cookie;
mod reassembly;
mod record;
mod replay;
