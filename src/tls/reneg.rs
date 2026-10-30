//! TLS 1.2 secure renegotiation (RFC 5746): the caller-facing policy and the
//! per-connection rate limiter for client-initiated renegotiations.
//!
//! Only the RFC 5746 form exists here. Every TLS 1.2 handshake this crate
//! runs carries `renegotiation_info`, and a renegotiation is accepted only
//! when the new hello's `renegotiation_info` carries the previous
//! handshake's `verify_data` (the client's, and in the server's echo the
//! client's followed by the server's). Legacy (pre-RFC 5746) renegotiation
//! is never performed, in either role.
//!
//! On top of RFC 5746, a renegotiation additionally requires
//!
//! * the Extended Master Secret (RFC 7627) on the handshake being replaced
//!   **and** on the new one — RFC 7627 §1 / §6.2: without it the "triple
//!   handshake" attack synchronises two connections' master secrets and
//!   lets a man in the middle splice a renegotiation onto a victim's
//!   session;
//! * the peer to present the same leaf certificate as before (unless
//!   [`RenegotiationPolicy::allow_peer_certificate_change`] is set), the
//!   identity check RFC 7627 §6.2 asks of applications that cannot rely
//!   on EMS alone: an identity change mid-connection is the observable
//!   symptom of the attack, and no application expects it. A peer that
//!   did not authenticate on the earlier handshake (a client without a
//!   certificate) may present one on the renegotiation — the
//!   "certificate on demand" use of renegotiation.
//!
//! Renegotiation is a TLS 1.2 mechanism only (TLS 1.3 replaced it with
//! `KeyUpdate` and post-handshake authentication). It is not performed on
//! the opt-in `tls-legacy` versions (TLS 1.0 / 1.1 / SSL 3.0), where a
//! peer's request is declined with a `no_renegotiation` warning as when
//! renegotiation is disabled, nor on DTLS 1.2, whose engines keep refusing
//! any handshake message after the `Finished`.

use alloc::vec::Vec;

/// What happens once a client exceeds
/// [`RenegotiationPolicy::client_limit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RenegotiationLimitAction {
    /// Abort the connection: a fatal `handshake_failure` alert is sent and
    /// processing fails with
    /// [`Error::RenegotiationLimitExceeded`](crate::tls::Error::RenegotiationLimitExceeded).
    /// The default, matching PHP's behaviour when no
    /// `reneg_limit_callback` is set.
    #[default]
    Close,
    /// Decline the renegotiation politely: a `no_renegotiation` warning is
    /// sent and the connection carries on under the current session.
    Refuse,
    /// Let the renegotiation proceed, but latch
    /// [`Connection::renegotiation_limit_exceeded`](crate::tls::Connection::renegotiation_limit_exceeded)
    /// so the caller can decide — PHP's `reneg_limit_callback`, whose
    /// `true` return keeps the stream open and anything else closes it.
    Notify,
}

/// A token-bucket limit on client-initiated renegotiations, with PHP's
/// `reneg_limit` / `reneg_window` semantics (`ext/openssl/xp_ssl.c`,
/// `php_openssl_limit_handshake_reneg`).
///
/// Each client-initiated renegotiation adds one token; tokens drain at
/// `max / window_secs` per second of wall-clock time between
/// renegotiations; the limit is exceeded when the bucket holds more than
/// `max` tokens. The initial handshake never counts. With PHP's defaults
/// (`max = 2`, `window_secs = 300`) a client may renegotiate twice in quick
/// succession, and the third renegotiation inside the window exceeds the
/// limit. `max = 0` makes every client-initiated renegotiation exceed it.
///
/// PHP computes the drain rate in integer arithmetic (`limit / window`),
/// which is zero for every `limit < window` — so in practice its bucket
/// never drains. This implementation drains at the exact rational rate the
/// option documents.
///
/// Without a clock (`no_std`, where the engine cannot read the time) the
/// bucket never drains, and the limit is a plain cap on the number of
/// client-initiated renegotiations per connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenegotiationLimit {
    /// Tokens the bucket may hold (PHP `reneg_limit`, default 2).
    pub max: u32,
    /// Seconds over which `max` tokens drain (PHP `reneg_window`, default
    /// 300). A zero window is treated as one second.
    pub window_secs: u32,
}

impl RenegotiationLimit {
    /// PHP's defaults: 2 client-initiated renegotiations per 300 seconds.
    pub const PHP_DEFAULT: RenegotiationLimit = RenegotiationLimit {
        max: 2,
        window_secs: 300,
    };
}

impl Default for RenegotiationLimit {
    fn default() -> Self {
        Self::PHP_DEFAULT
    }
}

/// TLS 1.2 renegotiation policy — [`Config::renegotiation`](crate::tls::Config::renegotiation).
///
/// Off by default: a peer's renegotiation request (a client's new
/// `ClientHello`, a server's `HelloRequest`) is declined with a warning
/// `no_renegotiation` alert (RFC 5746 §4.2 / §4.4) and the connection
/// stays up, and
/// [`Connection::renegotiate`](crate::tls::Connection::renegotiate) is
/// refused. When enabled, every renegotiation must also use the Extended
/// Master Secret (RFC 7627) on both the replaced and the new handshake (the
/// triple-handshake defence), and the peer must present the same leaf
/// certificate unless
/// [`allow_peer_certificate_change`](Self::allow_peer_certificate_change) is
/// set.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RenegotiationPolicy {
    /// Accept renegotiation requests from the peer and allow
    /// [`Connection::renegotiate`](crate::tls::Connection::renegotiate).
    /// Default `false`.
    pub enabled: bool,
    /// Server: the limit on *client-initiated* renegotiations (one the
    /// server solicited with
    /// [`Connection::renegotiate`](crate::tls::Connection::renegotiate)
    /// never counts). `None` disables limiting (PHP `reneg_limit = -1`).
    /// Default: [`RenegotiationLimit::PHP_DEFAULT`]. Inert on a client.
    pub client_limit: Option<RenegotiationLimit>,
    /// Server: what happens to a renegotiation that exceeds
    /// [`client_limit`](Self::client_limit). Default
    /// [`RenegotiationLimitAction::Close`].
    pub on_limit_exceeded: RenegotiationLimitAction,
    /// Accept a peer that presents a different leaf certificate on the
    /// renegotiation than on the handshake it replaces. Default `false`:
    /// the renegotiation fails with
    /// [`Error::PeerCertificateChanged`](crate::tls::Error::PeerCertificateChanged).
    /// The new chain is always fully verified either way.
    pub allow_peer_certificate_change: bool,
}

impl Default for RenegotiationPolicy {
    fn default() -> Self {
        RenegotiationPolicy {
            enabled: false,
            client_limit: Some(RenegotiationLimit::PHP_DEFAULT),
            on_limit_exceeded: RenegotiationLimitAction::Close,
            allow_peer_certificate_change: false,
        }
    }
}

impl RenegotiationPolicy {
    /// Renegotiation disabled (the default).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Renegotiation enabled, with the default client limit (PHP's 2 per
    /// 300 s, closing the connection when exceeded) and no certificate
    /// change.
    pub fn enabled() -> Self {
        RenegotiationPolicy {
            enabled: true,
            ..Self::default()
        }
    }

    /// Replaces [`client_limit`](Self::client_limit).
    pub fn with_client_limit(mut self, limit: Option<RenegotiationLimit>) -> Self {
        self.client_limit = limit;
        self
    }

    /// Replaces [`on_limit_exceeded`](Self::on_limit_exceeded).
    pub fn with_limit_action(mut self, action: RenegotiationLimitAction) -> Self {
        self.on_limit_exceeded = action;
        self
    }

    /// Replaces
    /// [`allow_peer_certificate_change`](Self::allow_peer_certificate_change).
    pub fn with_peer_certificate_change(mut self, allow: bool) -> Self {
        self.allow_peer_certificate_change = allow;
        self
    }
}

/// The token bucket behind [`RenegotiationLimit`]. Tokens are kept scaled by
/// the window (`tokens * window_secs`) so the drain `elapsed * max /
/// window_secs` stays exact in integers.
#[derive(Clone, Debug, Default)]
pub(crate) struct RenegotiationLimiter {
    /// Time of the previous handshake (initial or renegotiation), in
    /// seconds; `None` until the initial handshake or without a clock.
    prev: Option<u64>,
    /// The bucket level, scaled by the window.
    scaled_tokens: u64,
}

impl RenegotiationLimiter {
    /// Records the initial handshake's time. It is never rate-limited.
    pub(crate) fn initial_handshake(&mut self, now: Option<u64>) {
        self.prev = now;
    }

    /// Records one client-initiated renegotiation at `now` and reports
    /// whether it pushes the bucket past `limit`.
    pub(crate) fn record(&mut self, limit: RenegotiationLimit, now: Option<u64>) -> bool {
        let window = u64::from(limit.window_secs.max(1));
        let max = u64::from(limit.max);
        if let (Some(prev), Some(now)) = (self.prev, now) {
            let drained = now.saturating_sub(prev).saturating_mul(max);
            self.scaled_tokens = self.scaled_tokens.saturating_sub(drained);
        }
        if now.is_some() {
            self.prev = now;
        }
        self.scaled_tokens = self.scaled_tokens.saturating_add(window);
        self.scaled_tokens > max.saturating_mul(window)
    }
}

/// Upper bound on the application data a TLS 1.2 engine queues while a
/// renegotiation is in flight (1 MiB). The queue cannot drain until the
/// peer completes the new handshake, so without a cap a peer that starts a
/// renegotiation and then stalls makes every `send_application_data` call
/// grow memory without limit. Past the cap the call fails with
/// [`Error::RenegotiationBufferFull`](crate::tls::Error::RenegotiationBufferFull)
/// and queues nothing.
pub(crate) const MAX_RENEG_PENDING_APP_OUT: usize = 1 << 20;

/// Per-connection renegotiation bookkeeping shared by the TLS 1.2 client and
/// server engines.
#[derive(Default)]
pub(crate) struct RenegState {
    /// The `verify_data` of the client's `Finished` on the latest completed
    /// handshake (RFC 5746 §3.1 `client_verify_data`). Empty until then.
    pub(crate) client_verify_data: Vec<u8>,
    /// The `verify_data` of the server's `Finished` on the latest completed
    /// handshake (`server_verify_data`).
    pub(crate) server_verify_data: Vec<u8>,
    /// A renegotiation handshake is in flight.
    pub(crate) active: bool,
    /// The peer's leaf certificate on the handshake being replaced (`None`
    /// when the peer did not authenticate), checked against the one the
    /// renegotiation presents.
    pub(crate) prev_peer_leaf: Option<Vec<u8>>,
    /// Completed renegotiations.
    pub(crate) completed: u32,
    /// Application data the caller sent while the renegotiation was in
    /// flight, sent once it completes. OpenSSL refuses application data
    /// between its `ServerHello` and its `Finished`, so writing it under
    /// the old keys mid-handshake would break the connection.
    pub(crate) pending_app_out: Vec<u8>,
    /// `close_notify` requested while the renegotiation was in flight; sent
    /// after the queued application data once it completes.
    pub(crate) close_pending: bool,
    /// Server: a `HelloRequest` is outstanding, so the next `ClientHello`
    /// is solicited (and not rate-limited).
    pub(crate) hello_request_pending: bool,
    /// Server: client-initiated renegotiation requests seen.
    pub(crate) peer_requests: u32,
    /// Server: the client exceeded the limit (sticky).
    pub(crate) limit_exceeded: bool,
    /// Server: the rate limiter.
    pub(crate) limiter: RenegotiationLimiter,
}

impl RenegState {
    /// Queues `data` to send once the in-flight renegotiation completes,
    /// all or nothing: refuses with
    /// [`Error::RenegotiationBufferFull`](crate::tls::Error::RenegotiationBufferFull)
    /// when it would take the queue past [`MAX_RENEG_PENDING_APP_OUT`].
    pub(crate) fn queue_app_out(&mut self, data: &[u8]) -> Result<(), crate::tls::Error> {
        if data.len() > MAX_RENEG_PENDING_APP_OUT - self.pending_app_out.len() {
            return Err(crate::tls::Error::RenegotiationBufferFull);
        }
        self.pending_app_out.extend_from_slice(data);
        Ok(())
    }

    /// The `renegotiated_connection` a server's renegotiating `ServerHello`
    /// carries: `client_verify_data || server_verify_data` (RFC 5746 §3.5).
    /// A client's renegotiating `ClientHello` carries `client_verify_data`
    /// alone.
    pub(crate) fn server_binding(&self) -> Vec<u8> {
        let mut v = self.client_verify_data.clone();
        v.extend_from_slice(&self.server_verify_data);
        v
    }

    /// Whether the peer's `renegotiated_connection` equals `expected`,
    /// compared in constant time.
    pub(crate) fn binding_matches(expected: &[u8], received: &[u8]) -> bool {
        use crate::ct::ConstantTimeEq;
        expected.len() == received.len() && bool::from(expected.ct_eq(received))
    }

    /// On a renegotiation, refuses a peer leaf that differs from the one the
    /// replaced handshake authenticated (unless the policy allows it). A
    /// peer that was anonymous before may authenticate now.
    pub(crate) fn check_peer_leaf(
        &self,
        policy: &RenegotiationPolicy,
        new_leaf: Option<&[u8]>,
    ) -> Result<(), crate::tls::Error> {
        if !self.active || policy.allow_peer_certificate_change {
            return Ok(());
        }
        match self.prev_peer_leaf.as_deref() {
            Some(prev) if new_leaf != Some(prev) => Err(crate::tls::Error::PeerCertificateChanged),
            _ => Ok(()),
        }
    }
}

/// Wall-clock seconds for the limiter, when the build has a clock.
#[cfg(feature = "std")]
pub(crate) fn now_secs() -> Option<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Wall-clock seconds for the limiter: none without `std`.
#[cfg(not(feature = "std"))]
pub(crate) fn now_secs() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn php_default_allows_two_then_exceeds() {
        let mut l = RenegotiationLimiter::default();
        l.initial_handshake(Some(1000));
        let lim = RenegotiationLimit::PHP_DEFAULT;
        assert!(!l.record(lim, Some(1001)));
        assert!(!l.record(lim, Some(1002)));
        assert!(l.record(lim, Some(1003)));
    }

    #[test]
    fn bucket_drains_over_the_window() {
        let mut l = RenegotiationLimiter::default();
        l.initial_handshake(Some(0));
        let lim = RenegotiationLimit {
            max: 2,
            window_secs: 300,
        };
        assert!(!l.record(lim, Some(0)));
        assert!(!l.record(lim, Some(0)));
        // 150 s drain one token (2 per 300 s): the third fits again.
        assert!(!l.record(lim, Some(150)));
        // No time passes: the fourth overflows.
        assert!(l.record(lim, Some(150)));
        // A full window later the bucket is empty again.
        assert!(!l.record(lim, Some(10_000)));
    }

    #[test]
    fn zero_limit_exceeds_immediately_and_no_clock_never_drains() {
        let mut l = RenegotiationLimiter::default();
        let zero = RenegotiationLimit {
            max: 0,
            window_secs: 2,
        };
        assert!(l.record(zero, Some(5)));

        let mut l = RenegotiationLimiter::default();
        l.initial_handshake(None);
        let lim = RenegotiationLimit {
            max: 1,
            window_secs: 1,
        };
        assert!(!l.record(lim, None));
        assert!(l.record(lim, None));
    }
}
