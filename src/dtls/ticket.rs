//! Session tickets and PSK resumption, shared by the DTLS engines.
//!
//! The DTLS engines reuse the TLS ticket *formats* — the RFC 8446 §4.6.1
//! plaintext of the TLS 1.3 server
//! ([`TicketPlaintext`](crate::tls::conn::TicketPlaintext)) and the RFC 5077
//! plaintext of the TLS 1.2 server
//! ([`Ticket12Plaintext`](crate::tls::conn::Ticket12Plaintext)) — but seal
//! them under their own associated data ([`TICKET_DTLS13_AAD`],
//! [`TICKET_DTLS12_AAD`]) and, for DTLS 1.3, derive the PSK and its binder
//! under the `"dtls13"` label prefix (RFC 9147 §5.9). A ticket is therefore
//! single-protocol: one minted by a TLS listener never opens at a DTLS
//! listener sharing `Config::ticket_key`, nor the reverse, and a DTLS 1.3
//! ticket never opens at a DTLS 1.2 listener. On the client the same
//! separation is enforced by the [`ResumptionSession`] variant the session
//! was captured into.
//!
//! [`ResumptionSession`]: crate::tls::ResumptionSession
//!
//! What a resumed handshake must re-establish is spelled out in the TLS
//! engines (their 2026-09 audit findings) and mirrored here:
//!
//! - a ticket is sealed under a key bound to the listener's client-auth
//!   trust configuration ([`seal_key`]), so a recorded client identity is
//!   only honoured by a listener with the same roots;
//! - a recorded client identity must still be acceptable *now*
//!   ([`resumable_client_leaf`]), and a chain of resumptions expires
//!   `ticket_lifetime` after the one real verification (the TLS 1.3
//!   `client_auth_time`, enforced by `open_ticket13`);
//! - a client only offers a session to the server name that authenticated
//!   it, under a verification context at least as strict, before it
//!   expires ([`usable_session13`]);
//! - a ticket is only issued and accepted with a clock to bound its
//!   lifetime ([`ticket_now`]).

use crate::hash::{Hmac, Sha256};
use crate::tls::Error;
use crate::tls::codec::{CipherSuite, ClientHello, ExtensionType, extension as ext};
use crate::tls::conn::{StoredSession, TicketPlaintext, open_ticket13};
use crate::tls::crypto::{HashAlg, LabelPrefix, psk_binder_with};
use crate::tls::pki::RootCertStore;
use crate::x509::Time;
use crate::zeroize::Zeroizing;
use alloc::vec::Vec;

#[allow(unused_imports)]
use crate::ct::ConstantTimeEq;

/// Associated data every DTLS 1.3 ticket is sealed under (see the module
/// docs; the TLS 1.3 counterpart is `server::TICKET13_AAD`).
pub(crate) const TICKET_DTLS13_AAD: &[u8] = b"purecrypto dtls13 ticket v1";
/// Associated data every DTLS 1.2 (RFC 5077) ticket is sealed under — the
/// TLS 1.2 ticket plaintext, domain-separated from TLS 1.2's own AAD and
/// from DTLS 1.3's.
pub(crate) const TICKET_DTLS12_AAD: &[u8] = b"purecrypto dtls12 ticket v1";

/// Upper bound on a ticket the DTLS clients keep for resumption. The ticket
/// is re-presented verbatim in a later ClientHello, which the server must
/// reassemble before it holds any state (`PRE_COOKIE_MAX_CH_LEN`, 8 KiB):
/// a ticket this large would leave no room for the rest of the hello. The
/// tickets this crate mints are a few hundred bytes; wolfSSL's and
/// OpenSSL's are under 2 KiB.
pub(crate) const MAX_DTLS_SESSION_TICKET_LEN: usize = 4096;

/// RFC 8446 §8.2: maximum allowed deviation, in milliseconds, between the
/// client's reported ticket age and the server-side expected age before
/// 0-RTT is refused (the TLS 1.3 server uses the same window).
pub(crate) const MAX_TICKET_AGE_DEVIATION_MS: u64 = 10_000;

/// The effective ticket-sealing key: `ticket_key` bound, through `label`,
/// to the listener's client-auth trust configuration (present/absent, the
/// `required` flag, every anchor's subject + SPKI) — exactly as the TLS
/// engines bind theirs. Two listeners sharing a `ticket_key` but trusting
/// different client roots derive different sealing keys, so a ticket that
/// records "the client was authenticated" is only honoured where that
/// authentication would have been accepted (a cross-listener authentication
/// bypass otherwise). `client_auth` is the listener's `(roots, required)`
/// client-certificate policy, `None` when it requests no certificate.
pub(crate) fn seal_key(
    ticket_key: &[u8; 32],
    label: &[u8],
    client_auth: Option<(&RootCertStore, bool)>,
) -> Zeroizing<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new(ticket_key);
    mac.update(label);
    match client_auth {
        None => mac.update(&[0u8]),
        Some((roots, required)) => {
            mac.update(&[1u8, u8::from(required)]);
            for (subject, spki) in roots.anchor_identities() {
                mac.update(&(subject.len() as u32).to_be_bytes());
                mac.update(subject);
                mac.update(&(spki.len() as u32).to_be_bytes());
                mac.update(spki);
            }
        }
    }
    let out = mac.finalize();
    let mut bound = Zeroizing::new([0u8; 32]);
    bound.copy_from_slice(out.as_ref());
    bound
}

/// The clock a DTLS engine uses for session tickets: the configured
/// verification time when set, else the system clock. `None` when neither
/// is available (a `no_std` build without an explicit time) — tickets are
/// then neither issued nor accepted rather than minted with a
/// `creation_time` of 0, which could never expire and would turn every
/// ticket into a permanent bearer token.
pub(crate) fn ticket_now(verification_time: Option<&Time>) -> Option<u64> {
    verification_time
        .cloned()
        .or_else(super::system_now)
        .and_then(|t| t.to_unix_checked())
        .filter(|t| *t != 0)
}

/// Whether a client leaf recorded in a ticket may still stand in for client
/// authentication at unix time `now`: an X.509 leaf must be inside its
/// validity period; a leaf with no parsable validity period can only be an
/// RFC 7250 raw public key and remains acceptable exactly while it is on
/// `expected_raw_public_keys` (the whole trust root for that path — removing
/// a key from the allowlist also revokes its tickets). Mirrors the TLS
/// engines' checks; fails closed on anything else.
pub(crate) fn resumable_client_leaf(
    leaf: &[u8],
    now: u64,
    expected_raw_public_keys: &[Vec<u8>],
) -> bool {
    let validity = crate::x509::Certificate::from_der(leaf.to_vec())
        .ok()
        .and_then(|cert| cert.validity().ok());
    match validity {
        Some(v) => v.accepts(&Time::from_unix(now)),
        None => {
            crate::tls::conn::check_raw_public_key(true, expected_raw_public_keys, leaf).is_ok()
        }
    }
}

/// RFC 8446 §4.6.1 / §2.2: whether a stored DTLS 1.3 session may be offered
/// to `server_name` under `verify_certificates` at `now` (`None`: no
/// clock, no expiry check). A resumed handshake carries no certificate, so
/// a session is never presented to a different name than the one whose
/// certificate authenticated it (ASCII-case-insensitive, as host names
/// are), never under a config that verifies when the session was minted
/// without verification, never past `received_at + lifetime`, and never
/// when its ticket could not fit a ClientHello.
pub(crate) fn usable_session13(
    session: &StoredSession,
    server_name: Option<&str>,
    verify_certificates: bool,
    now: Option<u64>,
) -> bool {
    let expired = now.is_some_and(|now| {
        now.saturating_sub(session.received_at.to_unix()) > u64::from(session.lifetime_seconds)
    });
    let same_name = server_name.is_some_and(|n| session.server_name.eq_ignore_ascii_case(n));
    same_name
        && !expired
        && (session.verify_certificates || !verify_certificates)
        && !session.ticket.is_empty()
        && session.ticket.len() <= MAX_DTLS_SESSION_TICKET_LEN
}

/// The obfuscated ticket age (RFC 8446 §4.2.11.1): milliseconds since the
/// ticket was received, plus `ticket_age_add`, modulo 2^32. Without a clock
/// the age is reported as 0 (+ `age_add`); the server's freshness check then
/// refuses 0-RTT but still resumes.
pub(crate) fn obfuscated_age(session: &StoredSession, now: Option<u64>) -> u32 {
    let elapsed_ms = now
        .map(|now| {
            now.saturating_sub(session.received_at.to_unix())
                .saturating_mul(1000)
        })
        .unwrap_or(0);
    (elapsed_ms as u32).wrapping_add(session.age_add)
}

/// Whether two peer addresses name the same IP, the match RFC 9147 §5.1
/// conditions a resumption's cookie skip on ("the IP address matches one
/// associated with the PSK"). Addresses in the canonical form
/// `ConfigBuilder::peer_socket_addr` produces — 16 bytes of IPv6 (IPv4
/// v4-mapped) then a 2-byte port — are compared on the IP alone, so a
/// client that reconnects from a fresh source port (the wolfSSL and OpenSSL
/// clients open a new socket per connection) still qualifies; any other
/// encoding is opaque and must match exactly. Empty means "unknown" and
/// never matches.
pub(crate) fn same_ip(ticket_addr: &[u8], peer_addr: &[u8]) -> bool {
    if ticket_addr.is_empty() || ticket_addr.len() != peer_addr.len() {
        return false;
    }
    let n = if ticket_addr.len() == 18 {
        16
    } else {
        ticket_addr.len()
    };
    // Which address a resumption came from is not secret, but the
    // comparison is cheap to keep uniform.
    bool::from(ticket_addr[..n].ct_eq(&peer_addr[..n]))
}

/// Overwrites the (zero) binder at the tail of a DTLS 1.3 ClientHello with
/// the real one (RFC 8446 §4.2.11.2), computed under the `"dtls13"` label
/// prefix over `transcript_prefix ‖ ch[..ch.len() - binders_len]`. `ch` is
/// the DTLS-shaped hello with its 4-byte TLS handshake header (RFC 9147
/// §5.2: what the transcript hashes), `binders_len` the length of the
/// binders list at its end.
pub(crate) fn patch_binder13(
    ch: &mut [u8],
    binders_len: usize,
    hash: HashAlg,
    psk: &[u8],
    transcript_prefix: &[u8],
) {
    let truncated_len = ch.len().saturating_sub(binders_len);
    let binder = psk_binder_with(
        LabelPrefix::Dtls13,
        hash,
        psk,
        transcript_prefix,
        &ch[..truncated_len],
    );
    let hash_len = hash.output_len();
    let start = ch.len() - hash_len;
    ch[start..].copy_from_slice(binder.as_slice());
}

/// A PSK accepted from a DTLS 1.3 ClientHello (the DTLS twin of the TLS
/// server's `AcceptedPsk`).
pub(crate) struct AcceptedPsk13 {
    /// The resumption PSK recovered from the ticket, wiped on drop.
    pub(crate) psk: Zeroizing<Vec<u8>>,
    /// ALPN protocol negotiated on the connection that issued the ticket
    /// (empty when none was). RFC 8446 §4.2.10: 0-RTT may only be accepted
    /// when the new connection selects the identical protocol.
    pub(crate) alpn: Vec<u8>,
    /// RFC 8446 §8.2: the client's reported ticket age agrees with the
    /// server's expected age within [`MAX_TICKET_AGE_DEVIATION_MS`]. `false`
    /// refuses 0-RTT only.
    pub(crate) age_fresh: bool,
    /// The cipher suite the issuing handshake used; 0-RTT is refused unless
    /// this handshake negotiates the very same suite (the early-data keys
    /// are derived under it).
    pub(crate) suite: Option<CipherSuite>,
    /// Index of the selected identity (RFC 8446 §4.2.11).
    pub(crate) selected_identity: u16,
    /// The binder of the identity that was selected — what the 0-RTT
    /// [`ReplayWindow`](crate::tls::conn::ReplayWindow) is keyed on (only a
    /// `std` build has the window; the `no_std` server never reads this).
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    pub(crate) selected_binder: Vec<u8>,
    /// The client leaf the issuing handshake authenticated, if any, and
    /// when (see `TicketPlaintext::client_auth_secs`).
    pub(crate) client_leaf: Option<Vec<u8>>,
    pub(crate) client_auth_secs: u64,
    /// RFC 9147 §5.1: the resumption comes from the IP address the ticket
    /// was issued to ("the IP address matches one associated with the
    /// PSK" — see [`same_ip`]). Only then may the server skip the cookie
    /// exchange on resumption: return-routability to that address was
    /// proven when the ticket was issued, and a replayed hello from it can
    /// only cost the server what the genuine client already made it spend.
    pub(crate) same_address: bool,
}

/// What [`try_accept_psk13`] needs to know about the listener.
pub(crate) struct PskAcceptContext<'a> {
    /// The effective sealing key (see [`seal_key`]).
    pub(crate) seal_key: &'a [u8; 32],
    /// Unix time now (see [`ticket_now`]).
    pub(crate) now: u64,
    /// The configured ticket lifetime, seconds (0 disables the expiry check).
    pub(crate) ticket_lifetime: u32,
    /// The peer's transport address, as the cookie generator sees it.
    pub(crate) peer_addr: &'a [u8],
    /// Whether this listener requires an authenticated client: a ticket
    /// from a handshake that never authenticated one is then ignored.
    pub(crate) client_auth_required: bool,
    /// RFC 7250 raw client keys this listener accepts (see
    /// [`resumable_client_leaf`]).
    pub(crate) expected_client_raw_public_keys: &'a [Vec<u8>],
}

/// Tries to accept a `pre_shared_key` offer from a DTLS 1.3 ClientHello:
/// the twin of the TLS 1.3 server's `try_accept_psk`, opening the ticket
/// under [`TICKET_DTLS13_AAD`] and verifying the binder under the
/// `"dtls13"` prefix.
///
/// `raw` is the DTLS-shaped ClientHello with its 4-byte handshake header
/// (the transcript form), `transcript_prefix` the handshake transcript
/// preceding it: empty for a first ClientHello, `message_hash(CH1) ‖
/// HelloRetryRequest` for the cookie-bearing retry (RFC 8446 §4.2.11.2
/// binds the retry binder to the HRR-inclusive transcript).
///
/// Returns `Ok(None)` when nothing offered is usable (a full handshake
/// follows), `Err(DecryptError)` when a ticket opened but its binder is
/// wrong — an active attacker or a tampered hello, fatal.
pub(crate) fn try_accept_psk13(
    ctx: &PskAcceptContext<'_>,
    ch: &ClientHello,
    raw: &[u8],
    transcript_prefix: &[u8],
) -> Result<Option<AcceptedPsk13>, Error> {
    let Some(modes_body) = ext::find(&ch.extensions, ExtensionType::PSK_KEY_EXCHANGE_MODES) else {
        return Ok(None);
    };
    let modes = ext::parse_psk_key_exchange_modes(modes_body)?;
    if !modes.contains(&1) {
        // psk_dhe_ke only: a PSK-only key exchange (RFC 8446 §4.2.9) is not
        // offered by this crate and not accepted either.
        return Ok(None);
    }
    let Some(psk_body) = ext::find(&ch.extensions, ExtensionType::PRE_SHARED_KEY) else {
        return Ok(None);
    };
    let (identities, binders) = ext::parse_client_pre_shared_key(psk_body)?;
    // RFC 8446 §4.2.11: pick the first identity whose ticket decrypts
    // cleanly, then verify its binder; a mismatch is fatal.
    for (idx, (ticket, obfuscated_age)) in identities.iter().enumerate() {
        let Some(decrypted) = open_ticket13(
            ctx.seal_key,
            TICKET_DTLS13_AAD,
            ticket,
            ctx.now,
            ctx.ticket_lifetime,
        ) else {
            continue;
        };
        // A resumed handshake performs no client authentication of its
        // own: it can only stand in for the identity the issuing handshake
        // established, and that identity must still be acceptable now.
        if ctx.client_auth_required && decrypted.client_leaf.is_none() {
            continue;
        }
        if let Some(leaf) = decrypted.client_leaf.as_ref()
            && !resumable_client_leaf(leaf, ctx.now, ctx.expected_client_raw_public_keys)
        {
            continue;
        }
        let TicketPlaintext {
            psk,
            alpn,
            creation_secs,
            age_add,
            suite,
            client_leaf,
            client_auth_secs,
            peer_addr,
        } = decrypted;
        let hash = match psk.len() {
            32 => HashAlg::Sha256,
            48 => HashAlg::Sha384,
            _ => continue,
        };
        let hash_len = hash.output_len();
        // The binders list is the tail of the hello (RFC 8446 §4.2.11:
        // `pre_shared_key` is the last extension, which the caller checked).
        let binders_field_len: usize = 2 + binders.iter().map(|b| 1 + b.len()).sum::<usize>();
        if raw.len() < binders_field_len {
            continue;
        }
        let truncated = &raw[..raw.len() - binders_field_len];
        let expected = psk_binder_with(
            LabelPrefix::Dtls13,
            hash,
            &psk,
            transcript_prefix,
            truncated,
        );
        let presented = binders.get(idx).ok_or(Error::DecryptError)?;
        if presented.len() != hash_len
            || !bool::from(expected.as_slice().ct_eq(presented.as_slice()))
        {
            return Err(Error::DecryptError);
        }
        // RFC 8446 §8.2: ticket-age freshness, de-obfuscated with the
        // ticket's own `age_add`. A stale or forward-dated report marks the
        // PSK as unfit for 0-RTT; resumption itself is unaffected.
        let age_fresh = {
            let client_age_ms = obfuscated_age.wrapping_sub(age_add) as u64;
            let expected_age_ms = ctx.now.saturating_sub(creation_secs).saturating_mul(1000);
            client_age_ms.abs_diff(expected_age_ms) <= MAX_TICKET_AGE_DEVIATION_MS
        };
        let same_address = peer_addr
            .as_deref()
            .is_some_and(|a| same_ip(a, ctx.peer_addr));
        let selected_identity = u16::try_from(idx).map_err(|_| Error::IllegalParameter)?;
        return Ok(Some(AcceptedPsk13 {
            psk,
            alpn,
            age_fresh,
            suite,
            selected_identity,
            selected_binder: presented.to_vec(),
            client_leaf,
            client_auth_secs,
            same_address,
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::same_ip;

    fn addr(ip: [u8; 16], port: u16) -> alloc::vec::Vec<u8> {
        let mut a = ip.to_vec();
        a.extend_from_slice(&port.to_be_bytes());
        a
    }

    /// RFC 9147 §5.1 matches the IP: a fresh source port qualifies, another
    /// IP does not, an unknown (empty) address never does, and a
    /// non-canonical encoding must match byte for byte.
    #[test]
    fn same_ip_matches_on_the_address_not_the_port() {
        let ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1];
        let mut other = ip;
        other[15] = 2;
        assert!(same_ip(&addr(ip, 4433), &addr(ip, 50000)));
        assert!(!same_ip(&addr(ip, 4433), &addr(other, 4433)));
        assert!(!same_ip(&[], &addr(ip, 4433)));
        assert!(!same_ip(&addr(ip, 1), &[]));
        assert!(same_ip(b"opaque", b"opaque"));
        assert!(!same_ip(b"opaque1", b"opaque2"));
    }
}
