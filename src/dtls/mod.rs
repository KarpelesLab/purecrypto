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

pub(crate) mod ack;
pub mod client12;
pub mod client13;
pub(crate) mod cookie;
pub(crate) mod reassembly;
pub(crate) mod record;
pub(crate) mod record13;
pub(crate) mod reliability;
pub(crate) mod reliability13;
pub(crate) mod replay;
pub mod server12;
pub mod server13;

pub(crate) use client12::ClientConfig12Internal;
pub use client12::DtlsClientConnection12;
pub(crate) use client13::ClientConfig13Internal;
pub use client13::DtlsClientConnection13;
pub use server12::DtlsServerConnection12;
pub(crate) use server12::ServerConfig12Internal;
pub use server13::DtlsServerConnection13;
pub(crate) use server13::ServerConfig13Internal;

#[cfg(test)]
mod tests;
