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

use crate::x509::Time;

/// The system clock, when available; `None` for `no_std`.
///
/// The DTLS client state machines fall back to this when
/// `verification_time` is unset, so that certificate validity periods and
/// CRL freshness are actually checked in the default configuration. On
/// `no_std` there is no clock, so date checks remain disabled — exactly as
/// in the TLS layer.
#[cfg(feature = "std")]
pub(crate) fn system_now() -> Option<Time> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| Time::from_unix(d.as_secs()))
}

/// The system clock, when available; `None` for `no_std`.
#[cfg(not(feature = "std"))]
pub(crate) fn system_now() -> Option<Time> {
    None
}

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
