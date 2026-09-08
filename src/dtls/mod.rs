//! DTLS (Datagram TLS) — RFC 6347 (DTLS 1.2) and RFC 9147 (DTLS 1.3).
//!
//! Both protocols ride the same record / reassembly / replay / cookie chassis
//! defined in this module. Client and server state machines for each version
//! arrive in subsequent commits.
//!
//! The TLS handshake messages (ServerHello, Certificate, …) are reused from
//! [`crate::tls`]; this module is exclusively the datagram-shaped transport
//! that wraps them: 13-byte record headers, an explicit per-record epoch, a
//! 48-bit sequence number, anti-replay sliding window, and the
//! HelloVerifyRequest cookie that gates server resource allocation.
//!
//! # Wire format notes
//!
//! - **ClientHello shape.** Both DTLS versions carry a mandatory
//!   `opaque legacy_cookie<0..2^8-1>` between `legacy_session_id` and
//!   `cipher_suites` (RFC 6347 §4.2.1, RFC 9147 §5.3); a TLS-shaped
//!   ClientHello is not a valid DTLS ClientHello and is silently dropped.
//!   DTLS 1.2 echoes the HelloVerifyRequest cookie in that field; DTLS 1.3
//!   leaves it empty and carries the HelloRetryRequest cookie in the
//!   `cookie` extension (RFC 9147 §5.1).
//! - **Version codepoints.** The DTLS 1.3 ClientHello carries
//!   `legacy_version = 0xfefd` (DTLS 1.2) and offers `0xfefc` (DTLS 1.3)
//!   in `supported_versions`; the ServerHello / HelloRetryRequest carry
//!   `legacy_version = 0xfefd` and select `0xfefc`. Plaintext (epoch 0)
//!   records carry `0xfefd` in the record header as well (RFC 9147 §4.1).
//!   DTLS 1.2 negotiates `0xfefd` in `legacy_version` alone.
//! - **Post-handshake messages (DTLS 1.3).** `KeyUpdate` is supported in
//!   both directions (RFC 9147 §8): the sender keeps writing under the old
//!   epoch until the peer ACKs the `KeyUpdate`, the receiver keeps the
//!   previous read epoch for a bounded window, and the number of inbound
//!   updates is capped. `NewSessionTicket` is accepted and acknowledged but
//!   discarded — the DTLS engines have no resumption store. DTLS 1.2 has no
//!   post-handshake handshake messages; anything after `Finished` is fatal.
//! - **Path MTU.** Outbound handshake messages are fragmented so that no
//!   record exceeds the configured `max_record_size` (default 1200 bytes,
//!   RFC 9147 §4.4); each fragment is its own record and datagram.

use crate::tls::codec::{ExtensionType, RawExtension, ReadCursor, put_u16, with_len_u8};
use crate::tls::{Error, ProtocolVersion};
use crate::x509::Time;
use alloc::vec::Vec;

/// `supported_versions` for a DTLS 1.3 ClientHello: a `u8`-length list
/// holding only DTLS 1.3 (`0xfefc`, RFC 9147 §5.3).
pub(crate) fn client_supported_versions_dtls13() -> RawExtension {
    let mut body = Vec::new();
    with_len_u8(&mut body, |b| {
        put_u16(b, ProtocolVersion::DTLSv1_3.as_u16())
    });
    (ExtensionType::SUPPORTED_VERSIONS, body)
}

/// `supported_versions` for a DTLS 1.3 ServerHello / HelloRetryRequest:
/// the bare selected version `0xfefc` (RFC 9147 §5.3).
pub(crate) fn server_supported_versions_dtls13() -> RawExtension {
    let mut body = Vec::new();
    put_u16(&mut body, ProtocolVersion::DTLSv1_3.as_u16());
    (ExtensionType::SUPPORTED_VERSIONS, body)
}

/// Parses a ClientHello `supported_versions` list, returning whether DTLS
/// 1.3 (`0xfefc`) is offered. The TLS codepoint `0x0304` does NOT count: a
/// DTLS server must only select DTLS versions (RFC 9147 §5.3).
pub(crate) fn client_offers_dtls13(body: &[u8]) -> Result<bool, Error> {
    let mut outer = ReadCursor::new(body);
    let list = outer.vec_u8()?;
    outer.expect_empty()?;
    if list.is_empty() || list.len() % 2 != 0 {
        return Err(Error::Decode);
    }
    let mut c = ReadCursor::new(list);
    let mut found = false;
    while !c.is_empty() {
        if c.u16()? == ProtocolVersion::DTLSv1_3.as_u16() {
            found = true;
        }
    }
    Ok(found)
}

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
pub(crate) mod epoch13;
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
#[cfg(test)]
mod tests_deferred;
