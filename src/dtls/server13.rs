// Private module, re-exported only as `pub(crate)`, so its `pub` items are
// crate-internal: allow `unreachable_pub` module-wide. `dead_code` is not
// suppressed (the module is fully used).
#![allow(unreachable_pub)]

//! DTLS 1.3 server state machine (RFC 9147).
//!
//! Mirror of [`super::client13::DtlsClientConnection13`]. The server:
//!
//! 1. Receives the first ClientHello over a plaintext DTLS 1.2-framed
//!    record (epoch 0). The hello is DTLS-shaped (RFC 9147 §5.3): it
//!    carries a `legacy_cookie` field (which must be empty) and offers
//!    `0xfefc` in `supported_versions`; the ServerHello / HRR select
//!    `0xfefc` with `legacy_version = 0xfefd`.
//! 2. If cookie validation is enabled (default), emits a
//!    HelloRetryRequest with a `cookie` extension (RFC 9147 §5.1) and
//!    DROPS all per-connection state — the next CH must echo the cookie
//!    before any further processing.
//! 3. On the cookie-validated CH, derives handshake traffic secrets and
//!    sends the encrypted server flight (EE / Certificate /
//!    CertificateVerify / Finished).
//! 4. On the client's Finished — preceded, when a client certificate was
//!    requested, by its Certificate and CertificateVerify (RFC 8446
//!    §4.4.2 / §4.4.3) — transitions to the application epoch,
//!    and, with a ticket key configured, issues a `NewSessionTicket` (RFC
//!    8446 §4.6.1) as a post-handshake flight of its own: retransmitted
//!    until the client ACKs it (RFC 9147 §5.8.4, §7).
//!
//! A ClientHello presenting one of those tickets (`pre_shared_key`, RFC
//! 8446 §4.2.11) resumes the session: the ticket is opened under the DTLS
//! 1.3 associated data, the binder verified under the `"dtls13"` prefix
//! over the DTLS transcript (RFC 9147 §5.2, §5.9) — on the cookie-bearing
//! retry hello over `message_hash(CH1) ‖ HelloRetryRequest ‖ CH2` (RFC
//! 8446 §4.2.11.2) — and the server flight omits Certificate /
//! CertificateVerify. The cookie exchange is skipped for a resumption from
//! the address the ticket was issued to (RFC 9147 §5.1), which is also the
//! only way 0-RTT can be accepted: a HelloRetryRequest rejects early data
//! (RFC 8446 §4.2.10). Accepted early data arrives in epoch-1 records (RFC
//! 9147 §6.1) and is quarantined in its own buffer
//! ([`DtlsServerConnection13::take_early_data`]); rejected early data is
//! unreadable and dropped with every other record of an unknown epoch.
//!
//! Negotiation surface (matches the TLS 1.3 layer):
//!
//! - Cipher suites: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
//!   `TLS_CHACHA20_POLY1305_SHA256`.
//! - Groups: X25519, P-256, X25519+ML-KEM-768
//!   (draft-ietf-tls-ecdhe-mlkem).
//! - Server certificate signatures: RSA-PSS, ECDSA (any curve), Ed25519,
//!   ML-DSA-44/65/87 (draft-ietf-tls-mldsa).
//! - Client certificates (mutual authentication, RFC 8446 §4.3.2): the
//!   same policy as the TLS 1.3 server (`ClientAuthPolicy`).
//! - Out of scope: external PSKs.

use crate::ct::ConstantTimeEq;
use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, CurveId};
use crate::mlkem::{ENCAPS_KEY_BYTES, MlKem768EncapsKey};
use crate::rng::RngCore;
use crate::signature_registry::SignaturePolicy;
use crate::tls::codec::SignatureScheme;
use crate::tls::codec::extension as ext;
use crate::tls::codec::{
    CipherSuite, ClientHello, ExtensionType, KeyUpdate, NamedGroup, NewSessionTicket, Random,
    ReadCursor, ServerHello, hs_type, put_u16, with_len_u16, with_len_u24,
};
use crate::tls::conn::{ClientAuthPolicy, TicketPlaintext, seal_ticket13};
use crate::tls::crypto::sign::{sign_certificate_verify, signature_scheme_for};
use crate::tls::crypto::{
    HashAlg, KeySchedule, LabelPrefix, RecordCrypter, Secret, SuiteParams, Transcript,
    certificate_verify_content, finished_verify_data_with, kex, next_traffic_secret_with,
    psk_from_resumption_with, supported_suites, verify_signature,
};
use crate::tls::keylog::KeyLog;
use crate::tls::pki::CrlStore;
use crate::tls::{AlertDescription, ContentType, Error, ProtocolVersion};
use crate::x509::{AnyPublicKey, Time};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use super::ack::{ACK_CONTENT_TYPE, MAX_PENDING_ACKS, RecordNumber, decode as decode_ack};
use super::cid::{
    CidState, ConnectionIdUsage, NewConnectionId, RequestConnectionId, connection_id_extension,
    draw_cid_pool, negotiate_server,
};
use super::client13::{
    decrypt_dtls13_record, derive_sn_key, encrypt_protected_record_with, sn_key_len_for,
};
use super::cookie::{CookieGenerator, build_ch_fingerprint};
use super::epoch13::{
    KEY_UPDATE_WINDOW, MAX_KEY_UPDATES_RECEIVED, PREV_EPOCH_GRACE_RECORDS, PREV_EPOCH_GRACE_TIME,
    ReadEpoch, select_read_epoch,
};
use super::reassembly::{
    HandshakeFragment, MAX_HS_MSG_SEQ, PreCookieBuffer, Reassembler, read_fragment,
    write_fragments, write_message,
};
use super::record::{self, MAX_PLAINTEXT_LEN, ParsedDtlsRecord};
use super::record13::{
    self, header_aad, header_cid, peek_header_layout, reconstruct_seq, sn_mask_for,
};
use super::reliability13::{InFlightRecord, Retransmit13};
use super::ticket::{
    AcceptedPsk13, PskAcceptContext, TICKET_DTLS13_AAD, seal_key, ticket_now, try_accept_psk13,
};

/// HelloRetryRequest sentinel `random` value (RFC 8446 §4.1.3).
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// `cookie` extension type (RFC 8446 §4.2.2).
const EXT_COOKIE: u16 = 0x002C;
/// Record numbers of the client's final flight kept for the ACK that
/// precedes an early `close_notify`: its Finished is one record, a
/// Certificate + CertificateVerify answering a `CertificateRequest` a
/// dozen more (a multi-KB chain is fragmented to the record ceiling), and
/// a client gives up after a handful of retransmissions. Bounded like the
/// ACK queue itself ([`MAX_PENDING_ACKS`]).
const MAX_FINAL_FLIGHT_RECORDS: usize = MAX_PENDING_ACKS;

/// Configuration for a DTLS 1.3 server.
///
/// `pub(crate)`: external users build a [`crate::tls::Config`] and call
/// [`crate::tls::Connection::server`], which derives this internal config.
pub(crate) struct ServerConfig13Internal {
    /// Certificate chain (leaf first).
    pub cert_chain: Vec<Vec<u8>>,
    /// Signing key for the leaf certificate. Any of the
    /// [`crate::tls::conn::ServerKey`] variants are accepted — RSA-PSS,
    /// ECDSA (any curve), Ed25519, ML-DSA-44/65/87.
    pub key: crate::tls::conn::ServerKey,
    /// Cookie secret. When `None`, the cookie exchange is skipped (tests
    /// only). A production configuration always sets this.
    pub cookie_secret: Option<[u8; 32]>,
    /// The cookie secret in use before the last rotation, if any. Cookies
    /// are only ever *minted* under `cookie_secret`, but are *accepted*
    /// under either, so rotating the secret does not strand every client
    /// whose HelloRetryRequest cookie is in flight (the cookie's own
    /// max-age still bounds how long the old secret stays useful — RFC 9147
    /// §5.1). Keep at most one previous generation: a cookie minted two
    /// rotations ago is refused.
    pub previous_cookie_secret: Option<[u8; 32]>,
    /// When `true`, every client must complete the cookie exchange before
    /// the server allocates any per-connection handshake state. Default
    /// `true`.
    pub require_cookie: bool,
    /// Allowed signature algorithms in a client's certificate chain and
    /// `CertificateVerify` (see [`Self::client_auth`]).
    pub signature_policy: Arc<SignaturePolicy>,
    /// Client-certificate policy (mutual authentication). `None` (the
    /// default) sends no `CertificateRequest`. Forwarded from
    /// [`crate::tls::Config::client_auth`].
    pub client_auth: Option<ClientAuthPolicy>,
    /// CRLs consulted while validating a client's chain. Forwarded from
    /// [`crate::tls::Config::crls`].
    pub crls: CrlStore,
    /// Clock for the client chain's validity period and for session
    /// tickets. `None` uses the system clock under `std`; on `no_std` a
    /// client chain is then refused (see
    /// [`crate::tls::pki::verify_client_chain`]) and no ticket is issued or
    /// accepted (a ticket that cannot expire is a permanent bearer token).
    /// Forwarded from [`crate::tls::Config::verification_time`].
    pub verification_time: Option<Time>,
    /// Optional [`KeyLog`] sink (NSS `SSLKEYLOGFILE` format).
    pub key_log: Option<Arc<dyn KeyLog>>,
    /// Ceiling on the size of an emitted handshake record, header included
    /// (default 1200 — RFC 9147 §4.4). Every outbound handshake message
    /// (the multi-KB Certificate above all) is fragmented so that each
    /// fragment, framed as its own record and datagram, fits within it.
    /// Application data is not fragmented: `send()` emits one record per
    /// call, capped at 2^14, so callers keep payloads under the path MTU
    /// themselves.
    pub max_record_size: usize,
    /// ALPN protocols this server accepts, in preference order (RFC 7301).
    /// Empty (the default) ignores the client's offer. Forwarded from
    /// [`crate::tls::Config::alpn_protocols`].
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Key-exchange groups this server accepts, in ITS preference order:
    /// the first listed group the client offered is selected, and a client
    /// that offered it without a `key_share` is sent a HelloRetryRequest
    /// for it (RFC 8446 §4.1.4). Defaults to every implemented group
    /// (X25519MLKEM768, X25519, P-256, P-384). Forwarded from
    /// [`crate::tls::Config::key_exchange_groups`].
    pub groups: Vec<NamedGroup>,
    /// The connection ID this server wants to receive on this connection
    /// (RFC 9146 §3), answered in the ServerHello when the client offered
    /// the `connection_id` extension; `None` never negotiates CIDs. An
    /// empty value asks the client to send without a CID while this server
    /// sends with the client's. At most [`super::cid::MAX_LOCAL_CID_LEN`]
    /// bytes; per connection, never shared across them.
    pub connection_id: Option<Vec<u8>>,
    /// AES-256-GCM key sealing the RFC 8446 §4.6.1 session tickets this
    /// server issues (bound to the listener's client-auth configuration
    /// and the DTLS 1.3 associated data before use, see
    /// `ticket::seal_key`). `None` (the default) issues no tickets and
    /// resumes nothing. Forwarded from [`crate::tls::Config::ticket_key`];
    /// wiped on drop. Rotate it well before 2^32 tickets have been issued
    /// (NIST SP 800-38D §8.3).
    pub ticket_key: Option<[u8; 32]>,
    /// Ticket lifetime advertised to clients and enforced on decrypt, in
    /// seconds (default 7200, at most 7 days — RFC 8446 §4.6.1).
    pub ticket_lifetime: u32,
    /// Largest 0-RTT payload accepted on a resumed connection, in bytes
    /// (RFC 8446 §4.2.10). `0` (the default) refuses early data. Forwarded
    /// from [`crate::tls::Config::max_early_data`].
    pub max_early_data_size: u32,
    /// Shared anti-replay set for 0-RTT binders (RFC 8446 §8), forwarded
    /// from [`crate::tls::Config::replay_window`]. Without one, early data
    /// is only defended by the ticket-age freshness window (§8.2).
    #[cfg(feature = "std")]
    pub replay_window: Option<crate::tls::conn::ReplayWindow>,
}

// The ticket key seals every resumption ticket this server issues: a leak
// lets an attacker mint tickets and recover their PSKs, so it is scrubbed
// when the configuration is dropped (as the TLS servers do).
impl Drop for ServerConfig13Internal {
    fn drop(&mut self) {
        if let Some(key) = self.ticket_key.as_mut() {
            crate::tls::conn::wipe(key);
        }
    }
}

impl ServerConfig13Internal {
    /// New configuration with an opaque signing key. Cookie validation is
    /// required by default; call [`Self::with_no_cookie`] to disable it for
    /// tests.
    pub fn with_signing_key(cert_chain: Vec<Vec<u8>>, key: crate::tls::conn::ServerKey) -> Self {
        // RFC 8446 §4.2.3: an RSA key signs the PSS family its leaf's SPKI
        // form calls for (see `ServerKey::bound_to_leaf`).
        let key = key.bound_to_leaf(&cert_chain);
        Self {
            cert_chain,
            key,
            cookie_secret: None,
            previous_cookie_secret: None,
            require_cookie: true,
            signature_policy: Arc::new(SignaturePolicy::modern()),
            client_auth: None,
            crls: CrlStore::new(),
            verification_time: None,
            key_log: None,
            max_record_size: record::DEFAULT_MAX_RECORD_SIZE,
            alpn_protocols: Vec::new(),
            groups: supported_server_groups().to_vec(),
            connection_id: None,
            ticket_key: None,
            ticket_lifetime: 7200,
            max_early_data_size: 0,
            #[cfg(feature = "std")]
            replay_window: None,
        }
    }

    /// Demands a client certificate: the server flight carries a
    /// `CertificateRequest` (RFC 8446 §4.3.2) and the client's chain is
    /// verified against `roots` for the client-authentication purpose.
    /// With `required`, an empty client `Certificate` aborts the handshake
    /// with `certificate_required` (§4.4.2.4); otherwise an anonymous
    /// client is admitted and [`DtlsServerConnection13::peer_certificates`]
    /// stays empty. Forwarded from [`crate::tls::Config::client_auth`].
    pub fn with_client_auth(mut self, roots: crate::tls::RootCertStore, required: bool) -> Self {
        self.client_auth = Some(ClientAuthPolicy { roots, required });
        self
    }

    /// Enables RFC 8446 §4.6.1 session tickets (see [`Self::ticket_key`]).
    pub fn with_ticket_key(mut self, key: [u8; 32]) -> Self {
        self.ticket_key = Some(key);
        self
    }

    /// Accepts up to `max` bytes of 0-RTT data on a resumed connection
    /// (see [`Self::max_early_data_size`]).
    pub fn with_max_early_data(mut self, max: u32) -> Self {
        self.max_early_data_size = max;
        self
    }

    /// Installs the 0-RTT anti-replay set (see [`Self::replay_window`]).
    #[cfg(feature = "std")]
    pub fn with_replay_window(mut self, window: crate::tls::conn::ReplayWindow) -> Self {
        self.replay_window = Some(window);
        self
    }

    /// Sets the ticket clock (see [`Self::verification_time`]).
    pub fn with_verification_time(mut self, t: Time) -> Self {
        self.verification_time = Some(t);
        self
    }

    /// Sets the pre-rotation cookie secret (see
    /// [`Self::previous_cookie_secret`]).
    /// Forwarded from [`crate::tls::Config::previous_cookie_secret`].
    pub fn with_previous_cookie_secret(mut self, secret: [u8; 32]) -> Self {
        self.previous_cookie_secret = Some(secret);
        self
    }

    /// Back-compat constructor that takes an ECDSA private key. Forwards to
    /// [`Self::with_signing_key`].
    #[allow(dead_code)]
    pub fn with_ecdsa(cert_chain: Vec<Vec<u8>>, key: BoxedEcdsaPrivateKey) -> Self {
        Self::with_signing_key(cert_chain, crate::tls::conn::ServerKey::Ecdsa(key))
    }

    /// Sets the long-lived cookie secret. Required when `require_cookie`
    /// is `true` (the default).
    pub fn with_cookie_secret(mut self, secret: [u8; 32]) -> Self {
        self.cookie_secret = Some(secret);
        self
    }

    /// Disables the cookie exchange. Tests only.
    ///
    /// # Warning: amplification / DoS vector
    ///
    /// With the cookie exchange off, a single spoofed-source ClientHello
    /// makes the server allocate per-connection state, perform an
    /// asymmetric signature, and emit its full multi-KB flight (SH + EE +
    /// Certificate + CertificateVerify + Finished) to an unverified
    /// address — well over 3x amplification toward a victim of the
    /// attacker's choosing (RFC 9147 §5.1). Never disable cookies on a
    /// server reachable from untrusted networks.
    pub fn with_no_cookie(mut self) -> Self {
        self.require_cookie = false;
        self
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum State {
    /// Awaiting the first ClientHello.
    WaitFirstClientHello,
    /// Sent HRR with cookie; awaiting cookie-bearing second CH.
    WaitSecondClientHello,
    /// Sent the server flight with a `CertificateRequest`; awaiting the
    /// client's `Certificate`.
    WaitClientCertificate,
    /// The client's `Certificate` carried a chain; awaiting its
    /// `CertificateVerify`.
    WaitClientCertVerify,
    /// Sent the server flight; awaiting client Finished.
    WaitClientFinished,
    /// External-signing pause: the flight is built through Certificate and is
    /// waiting for the caller to supply the `CertificateVerify` signature.
    AwaitingCertVerifySignature,
    Connected,
    Closed,
}

/// State stashed while a DTLS 1.3 server flight is suspended awaiting an
/// external `CertificateVerify` signature (see
/// [`ServerKey::External`](crate::tls::conn::ServerKey::External)). The
/// suite, key schedule, secrets, and client random already live on the
/// connection, so only the signature input + scheme need stashing.
struct PendingFlight {
    /// Negotiated signature scheme for the `CertificateVerify`.
    scheme: SignatureScheme,
    /// The signature input the caller signs.
    content: Vec<u8>,
}

/// A DTLS 1.3 server connection.
pub struct DtlsServerConnection13<R: RngCore> {
    config: Arc<ServerConfig13Internal>,
    rng: R,

    peer_addr: Vec<u8>,

    state: State,

    /// DTLS handshake msg_seq counter for outbound messages.
    out_msg_seq: u16,
    /// Reassembler for inbound handshake messages.
    reassembler: Option<Reassembler>,
    /// Bounded fragment buffer for the (possibly fragmented) initial
    /// ClientHello and post-HRR CH2. A multi-group offer (X25519 + P-256 +
    /// ML-KEM-768) overflows the per-record fragment budget, so CH may arrive
    /// in multiple records before we've allocated `reassembler`. See
    /// [`PreCookieBuffer`] for the limits and why it is only a buffer,
    /// never a sequencer (DTLS-M1).
    pre_cookie: PreCookieBuffer,

    out_dgrams: Vec<Vec<u8>>,
    app_in: Vec<u8>,

    /// Plaintext (epoch 0) record state.
    plain_write_epoch: u16,
    plain_write_seq: u64,

    /// Protected-write state (epoch 2 during handshake, epoch 3 after, one
    /// more per acknowledged `KeyUpdate` we sent).
    enc_write_epoch: u16,
    enc_write_seq: u64,
    /// Current protected read epoch (keys, seq reconstruction state, replay
    /// window — RFC 9147 §4.5.1: an attacker who captures any encrypted
    /// record could otherwise replay it indefinitely). `None` until the
    /// cookie-validated ClientHello installs the handshake keys.
    read: Option<ReadEpoch>,
    /// The read epoch retired by the most recent epoch change, kept so
    /// reordered / retransmitted records still protected under it decrypt
    /// and get ACKed (RFC 9147 §4.2.2, §8). Dropped after
    /// [`PREV_EPOCH_GRACE_RECORDS`] records arrive under `read`, or at the
    /// next epoch change.
    prev_read: Option<ReadEpoch>,
    /// Records authenticated under `read` since `prev_read` was retired.
    prev_read_grace: u32,
    /// Caller-clock deadline after which `prev_read` is dropped even if the
    /// record count never reaches [`PREV_EPOCH_GRACE_RECORDS`]. `None` when
    /// no epoch is retired, or while the caller has not driven the clock
    /// yet (it is armed at the first clock observation).
    prev_read_deadline: Option<Duration>,
    /// True while our own `KeyUpdate` is in flight: we keep writing under
    /// the current epoch until the peer ACKs it (RFC 9147 §8).
    key_update_pending: bool,
    /// Peer `KeyUpdate`s accepted in the current [`KEY_UPDATE_WINDOW`],
    /// bounded by [`MAX_KEY_UPDATES_RECEIVED`].
    key_updates_received: u32,
    /// Start of the current KeyUpdate rate-limit window on the caller's
    /// clock.
    key_update_window_start: Duration,

    /// Ephemeral X25519 key (kept across the handshake for keylog
    /// correlation; the shared secret is derived inline). Unused once we
    /// pick a non-X25519 group, but retained for symmetry with the wider
    /// connection state.
    #[allow(dead_code)]
    x25519: Option<X25519PrivateKey>,

    client_random: Option<Random>,
    server_random: Option<Random>,

    transcript: Transcript,
    ks: Option<KeySchedule>,
    client_hs_secret: Option<crate::tls::crypto::Secret>,
    server_hs_secret: Option<crate::tls::crypto::Secret>,
    client_app_secret: Option<crate::tls::crypto::Secret>,
    server_app_secret: Option<crate::tls::crypto::Secret>,

    /// Active write-side RecordCrypter.
    write_crypter: Option<RecordCrypter>,
    /// Sequence-number protection key (length matches the AEAD key length:
    /// 16 for AES-128-GCM, 32 for AES-256-GCM and ChaCha20-Poly1305, per
    /// RFC 9147 §4.2.3).
    write_sn_key: Option<crate::tls::crypto::Secret>,
    write_app_sn_key: Option<crate::tls::crypto::Secret>,
    /// Application (epoch 3) read epoch, parked until the client Finished.
    pending_read_app: Option<ReadEpoch>,
    pending_write_app_crypter: Option<RecordCrypter>,
    /// External-signing continuation; `Some` while suspended awaiting the
    /// `CertificateVerify` signature.
    pending_flight: Option<PendingFlight>,
    /// Negotiated cipher suite parameters (set once we pick a suite from
    /// the cookie-validated CH).
    suite: Option<SuiteParams>,
    /// ALPN protocol selected from the ClientHello (sent in
    /// EncryptedExtensions), if any.
    alpn_negotiated: Option<Vec<u8>>,
    /// `exporter_master_secret` (RFC 8446 §7.5), retained after the
    /// server-Finished derivation so [`Self::tls_exporter`] can be called
    /// any number of times once the handshake completes.
    exporter_secret: Option<crate::tls::crypto::Secret>,
    /// The client's certificate chain (leaf first, DER), once verified;
    /// empty for an anonymous client.
    client_cert_chain: Vec<Vec<u8>>,
    /// The verified client leaf key its `CertificateVerify` is checked
    /// under.
    client_leaf_key: Option<AnyPublicKey>,
    /// Group selected for HelloRetryRequest, if any. When set, CH2 must
    /// carry a `key_share` for this group (RFC 8446 §4.1.4 / §4.2.8).
    hrr_selected_group: Option<NamedGroup>,
    /// The committed ClientHello followed a HelloRetryRequest (cookie or
    /// group change) this server sent.
    hrr_sent: bool,
    /// The group of the ServerHello `key_share`, once known.
    negotiated_group: Option<NamedGroup>,
    /// `KeyUpdate`s sent (see [`Self::sent_key_updates`]).
    key_updates_sent: u32,
    /// `KeyUpdate`s received over the life of the connection (the windowed
    /// `key_updates_received` above is the rate limiter's).
    key_updates_received_total: u32,
    /// The peer's `close_notify` was authenticated.
    close_notify_received: bool,
    /// Our `close_notify` went out; no more application data may follow.
    close_notify_sent: bool,
    /// The client is known to be past its handshake: a record other than
    /// an ACK arrived under the application keys. Until then it may still
    /// be retransmitting its Finished, waiting for our ACK (see
    /// [`Self::handshake_flight_pending`]).
    client_confirmed: bool,
    /// Record numbers of the client's final flight (its Finished, every
    /// copy received), newest last and bounded by
    /// [`MAX_FINAL_FLIGHT_RECORDS`]: acknowledged once more ahead of a
    /// `close_notify` sent while the client is unconfirmed.
    final_flight_records: Vec<RecordNumber>,

    /// Pending ACKs to emit.
    pending_acks: Vec<RecordNumber>,
    /// ACK-driven retransmit state.
    retransmit: Retransmit13,
    last_now: Duration,
    /// True once the caller has driven the clock via [`Self::set_now`] /
    /// [`Self::on_timeout`]. Governs the cookie-clock fallback — see
    /// [`Self::cookie_now_minutes`].
    clock_driven: bool,

    /// Connection-ID state once the extension is negotiated (RFC 9146 §3,
    /// RFC 9147 §9); `None` when no CIDs are in use.
    cid: Option<CidState>,
    /// CIDs a client `RequestConnectionId` asked for while a
    /// `NewConnectionId` of ours was still unacknowledged — RFC 9147 §9
    /// allows only one outstanding, so the answer waits for the ACK.
    cid_reply_owed: u8,
    /// The handshake resumed a session by PSK (RFC 8446 §2.2).
    psk_used: bool,
    /// The client offered 0-RTT (`early_data` in its hello), whether or
    /// not it was accepted.
    early_data_offered: bool,
    /// This server accepted the client's 0-RTT (RFC 8446 §4.2.10).
    early_data_accepted: bool,
    /// The epoch-1 read keys (RFC 9147 §6.1) while accepted early data may
    /// still arrive: dropped at the first record under the application
    /// keys (§5.6). Rejected early data has no keys and is dropped as any
    /// record of an unreadable epoch.
    early_read: Option<ReadEpoch>,
    /// Early-data plaintext bytes still admitted under
    /// `max_early_data_size` (RFC 8446 §4.2.10).
    early_data_remaining: u32,
    /// Accepted early data, quarantined from the 1-RTT plaintext (it is
    /// replayable, RFC 8446 §8) — see [`Self::take_early_data`].
    early_in: Vec<u8>,
    /// `resumption_master_secret` (RFC 8446 §7.1), from the client's
    /// Finished; seeds every ticket this connection issues.
    rms: Option<Secret>,
    /// The client identity a resumed ticket carried, with when it was
    /// verified (`TicketPlaintext::client_auth_secs`): re-embedded in the
    /// ticket this connection issues so a chain of resumptions keeps
    /// expiring from the one real verification. (Populated by resumption
    /// only until the DTLS servers verify client certificates.)
    resumed_client_leaf: Option<Vec<u8>>,
    resumed_client_auth_secs: Option<u64>,
}

impl<R: RngCore> DtlsServerConnection13<R> {
    /// Creates a server awaiting a ClientHello from `peer_addr`.
    ///
    /// `peer_addr` is the peer's transport address in a **canonical binary**
    /// encoding -- the recommended shape being 16 bytes of IPv6 address (an
    /// IPv4 peer written as its v4-mapped form) followed by the 2-byte
    /// big-endian port, as produced by
    /// [`ConfigBuilder::peer_socket_addr`](crate::tls::ConfigBuilder::peer_socket_addr).
    /// It is mixed into every cookie MAC, which is what makes the cookie a
    /// proof of return-routability rather than merely a proof that someone
    /// completed one round trip. A non-canonical (e.g. textual) encoding
    /// would let an attacker mint several distinct cookies for one address
    /// by varying the spelling.
    ///
    /// An empty `peer_addr` means "unknown"; combined with a required
    /// cookie exchange the server then fails closed on the first
    /// ClientHello rather than issuing a replayable, address-independent
    /// cookie.
    pub(crate) fn new(config: Arc<ServerConfig13Internal>, peer_addr: Vec<u8>, rng: R) -> Self {
        // Transcript hash is pinned later once we select a cipher suite from
        // the (cookie-validated) ClientHello — the buffer-everything design
        // lets us defer the hash choice until then.
        let t = Transcript::new();
        Self {
            config,
            rng,
            peer_addr,
            state: State::WaitFirstClientHello,
            out_msg_seq: 0,
            reassembler: None,
            pre_cookie: PreCookieBuffer::new(),
            out_dgrams: Vec::new(),
            app_in: Vec::new(),
            plain_write_epoch: 0,
            plain_write_seq: 0,
            enc_write_epoch: 0,
            enc_write_seq: 0,
            read: None,
            prev_read: None,
            prev_read_grace: 0,
            prev_read_deadline: None,
            key_update_pending: false,
            key_updates_received: 0,
            key_update_window_start: Duration::from_secs(0),
            x25519: None,
            client_random: None,
            server_random: None,
            transcript: t,
            ks: None,
            client_hs_secret: None,
            server_hs_secret: None,
            client_app_secret: None,
            server_app_secret: None,
            write_crypter: None,
            write_sn_key: None,
            write_app_sn_key: None,
            pending_read_app: None,
            pending_write_app_crypter: None,
            pending_flight: None,
            suite: None,
            alpn_negotiated: None,
            exporter_secret: None,
            client_cert_chain: Vec::new(),
            client_leaf_key: None,
            hrr_selected_group: None,
            hrr_sent: false,
            negotiated_group: None,
            key_updates_sent: 0,
            key_updates_received_total: 0,
            close_notify_received: false,
            close_notify_sent: false,
            client_confirmed: false,
            final_flight_records: Vec::new(),
            pending_acks: Vec::new(),
            retransmit: Retransmit13::new(),
            last_now: Duration::from_secs(0),
            clock_driven: false,
            cid: None,
            cid_reply_owed: 0,
            psk_used: false,
            early_data_offered: false,
            early_data_accepted: false,
            early_read: None,
            early_data_remaining: 0,
            early_in: Vec::new(),
            rms: None,
            resumed_client_leaf: None,
            resumed_client_auth_secs: None,
        }
    }

    /// Returns true once the handshake completes.
    pub fn is_handshake_complete(&self) -> bool {
        self.state == State::Connected
    }

    /// `true` when the handshake resumed a session by PSK (RFC 8446 §2.2).
    pub fn psk_used(&self) -> bool {
        self.psk_used
    }

    /// `true` when this server accepted the client's 0-RTT early data
    /// (RFC 8446 §4.2.10); it is read with [`Self::take_early_data`].
    pub fn early_data_accepted(&self) -> bool {
        self.early_data_accepted
    }

    /// `true` when the client offered early data on this connection,
    /// whether or not it was accepted.
    pub fn early_data_offered(&self) -> bool {
        self.early_data_offered
    }

    /// Drains the accepted 0-RTT plaintext. Early data never reaches
    /// [`Self::take_received`]: it is replayable (RFC 8446 §8 — the
    /// anti-replay defences are best effort), so an application decides
    /// explicitly what to do with it.
    pub fn take_early_data(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.early_in)
    }

    /// Largest handshake fragment body that keeps every record we emit
    /// within the configured `max_record_size` (RFC 9147 §4.4).
    fn max_fragment(&self) -> usize {
        record::max_fragment_for(self.config.max_record_size)
    }

    /// The clock used for session tickets (see `ticket::ticket_now`).
    fn ticket_now(&self) -> Option<u64> {
        ticket_now(self.config.verification_time.as_ref())
    }

    /// The effective ticket-sealing key (see `ticket::seal_key`); `None`
    /// without a ticket key. The DTLS servers verify no client
    /// certificate yet, so the binding covers "no client auth".
    fn ticket_seal_key(&self) -> Option<crate::zeroize::Zeroizing<[u8; 32]>> {
        let key = self.config.ticket_key.as_ref()?;
        Some(seal_key(
            key,
            b"purecrypto dtls13 ticket client-auth binding v1",
            None,
        ))
    }

    /// Whether tickets can be issued and accepted: a key and a clock.
    fn tickets_available(&self) -> bool {
        self.config.ticket_key.is_some() && self.ticket_now().is_some()
    }

    /// Tries to accept a `pre_shared_key` offer from `ch` (the DTLS 1.3
    /// twin of the TLS server's `try_accept_psk`). `raw` is the TLS-shaped
    /// ClientHello (the transcript form), `transcript_prefix` the handshake
    /// transcript before it (empty on a first hello, `message_hash(CH1) ‖
    /// HelloRetryRequest` on the cookie/HRR retry — RFC 8446 §4.2.11.2). A
    /// binder mismatch is fatal; `Ok(None)` when nothing usable is offered.
    fn accept_ticket_psk(
        &self,
        ch: &ClientHello,
        raw: &[u8],
        transcript_prefix: &[u8],
    ) -> Result<Option<AcceptedPsk13>, Error> {
        let (Some(seal), Some(now)) = (self.ticket_seal_key(), self.ticket_now()) else {
            return Ok(None);
        };
        let ctx = PskAcceptContext {
            seal_key: &seal,
            now,
            ticket_lifetime: self.config.ticket_lifetime,
            peer_addr: &self.peer_addr,
            // The DTLS servers verify no client certificate yet.
            client_auth_required: false,
            expected_client_raw_public_keys: &[],
        };
        try_accept_psk13(&ctx, ch, raw, transcript_prefix)
    }

    /// IANA cipher-suite identifier of the negotiated suite, or `None`
    /// until the handshake completes.
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        if self.is_handshake_complete() {
            self.suite.map(|s| s.suite.0)
        } else {
            None
        }
    }

    /// The ALPN protocol selected from the client's offer, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_negotiated.as_deref()
    }

    /// The client's certificate chain (leaf first, DER) once its
    /// `CertificateVerify` has been checked; empty when no certificate was
    /// requested or the client presented none.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.client_cert_chain
    }

    /// `true` when the handshake went through a HelloRetryRequest this
    /// server sent — the stateless cookie exchange (RFC 9147 §5.1) or a
    /// key-share group change (RFC 8446 §4.1.4).
    pub fn hello_retry_request_sent(&self) -> bool {
        self.hrr_sent
    }

    /// The key-exchange group the handshake used (the `key_share` the
    /// ServerHello carried), or `None` before the ServerHello.
    pub(crate) fn negotiated_group(&self) -> Option<NamedGroup> {
        self.negotiated_group
    }

    /// Number of `KeyUpdate` messages this side has sent: explicit
    /// [`request_key_update`](Self::request_key_update) calls and answers to
    /// the peer's `update_requested` alike.
    pub fn sent_key_updates(&self) -> u32 {
        self.key_updates_sent
    }

    /// Number of `KeyUpdate` messages received from the peer.
    pub fn peer_key_updates(&self) -> u32 {
        self.key_updates_received_total
    }

    /// `true` once the peer's `close_notify` has been authenticated
    /// (RFC 8446 §6.1, carried in a protected record on DTLS 1.3).
    pub fn received_close_notify(&self) -> bool {
        self.close_notify_received
    }

    /// The connection ID the client puts in records to this server
    /// (RFC 9146 §3): `Some(&[])` when CIDs were negotiated but this side
    /// receives none, `None` when they were not negotiated (or not yet).
    pub fn local_connection_id(&self) -> Option<&[u8]> {
        self.cid.as_ref().map(CidState::local)
    }

    /// The connection ID this server currently puts in records to the
    /// client; `Some(&[])` when the client receives none, `None` when CIDs
    /// were not negotiated.
    pub fn peer_connection_id(&self) -> Option<&[u8]> {
        self.cid.as_ref().map(CidState::peer)
    }

    /// Spare send CIDs the client issued (`NewConnectionId(cid_spare)`,
    /// RFC 9147 §9) that [`Self::use_spare_connection_id`] can switch to.
    pub fn spare_connection_ids(&self) -> usize {
        self.cid.as_ref().map_or(0, CidState::spare_count)
    }

    /// `true` when the datagram most recently fed contained a record that
    /// carried a connection ID, authenticated, and was newer (epoch, then
    /// sequence number) than every record received before it — the two
    /// record-layer conditions RFC 9146 §6 sets for moving the peer's
    /// transport address to that datagram's source. The third, a
    /// reachability test of the new address, is the caller's: RFC 9147 §9
    /// / RFC 9146 §6 forbid updating the address without one, since an
    /// on-path attacker who rewrites source addresses can otherwise turn
    /// this side into a reflector towards a third party — a server that
    /// answers with more than it received must exchange a ping-pong (or a
    /// return-routability check) with the new address before sending it
    /// anything else. A datagram that fails this test is still a valid
    /// datagram; only the address must not move.
    pub fn datagram_allows_peer_address_update(&self) -> bool {
        self.cid.as_ref().is_some_and(CidState::address_update_ok)
    }

    /// Asks the client for `num` fresh send CIDs with a
    /// `RequestConnectionId` (RFC 9147 §9), tracked and retransmitted until
    /// acknowledged. Refused with [`Error::InappropriateState`] before the
    /// handshake completes, when CIDs were not negotiated, when this server
    /// sends without a CID (§9: "MUST NOT send RequestConnectionId when
    /// sending an empty Connection ID"), or while an earlier request is
    /// unanswered.
    pub fn request_connection_ids(&mut self, num: u8) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::InappropriateState);
        }
        let cid = self.cid.as_mut().ok_or(Error::InappropriateState)?;
        if cid.peer().is_empty() {
            return Err(Error::InappropriateState);
        }
        cid.begin_request()?;
        let body = RequestConnectionId { num_cids: num }.encode_body();
        self.emit_encrypted_handshake(hs_type::REQUEST_CONNECTION_ID, &body)
    }

    /// Switches the CID this server sends with to the next spare the
    /// client issued (RFC 9147 §9). [`Error::InappropriateState`] when no
    /// spare is on hand.
    pub fn use_spare_connection_id(&mut self) -> Result<(), Error> {
        if self.cid.as_mut().is_some_and(CidState::use_spare) {
            Ok(())
        } else {
            Err(Error::InappropriateState)
        }
    }

    /// `true` while the handshake is not known to be over on both sides:
    /// handshake records this side sent are unacknowledged (the flight in
    /// progress, or a `KeyUpdate`), or — once
    /// [`Self::is_handshake_complete`] — the client has not yet been seen
    /// to move past its handshake.
    ///
    /// The server's last act in the handshake is the ACK of the client's
    /// Finished (RFC 9147 §7.1), which is itself never acknowledged: if it
    /// is lost the client retransmits the Finished and must be ACKed again
    /// (§5.8.1: "the server MUST respond to retransmission of the client's
    /// final flight with a retransmit of its ACK"). The engine does that
    /// whenever such a copy is fed to it, so while this returns `true` the
    /// caller keeps reading datagrams and sending what
    /// [`Self::pop_outbound_datagrams`] returns. It turns `false` when a
    /// record other than an ACK arrives under the application keys
    /// (application data, an alert, a `KeyUpdate`): a client that is still
    /// inside its handshake sends none. A client with nothing to say never
    /// provides that evidence, so callers bound the wait.
    pub fn handshake_flight_pending(&self) -> bool {
        // (A closed connection waits for nothing.)
        self.state != State::Closed && (!self.retransmit.is_empty() || self.client_unconfirmed())
    }

    /// Connected, but the client may still be waiting for the ACK of its
    /// Finished.
    fn client_unconfirmed(&self) -> bool {
        self.state == State::Connected && !self.client_confirmed
    }

    /// Ends the session: queues a `close_notify` alert under the current
    /// write keys (RFC 9147 §4 / RFC 8446 §6.1). No application data can be
    /// sent afterwards, but records from the peer — its own `close_notify`
    /// in particular — are still read. Idempotent; an error before the
    /// handshake completes.
    ///
    /// While [`Self::handshake_flight_pending`] the client may be
    /// retransmitting its Finished because our ACK was lost, and a
    /// `close_notify` reaching it there fails its handshake. The alert is
    /// therefore preceded by one more ACK of the client's Finished, so
    /// that the two arrive together; callers that can afford to should
    /// wait (bounded) for `handshake_flight_pending` to turn `false`
    /// before closing.
    pub fn send_close_notify(&mut self) -> Result<(), Error> {
        // Allowed while connected and, since the peer's close_notify must be
        // answered in kind (RFC 8446 §6.1), after one has closed the session.
        if !(self.state == State::Connected || self.close_notify_received)
            || self.write_crypter.is_none()
        {
            return Err(Error::InappropriateState);
        }
        if self.close_notify_sent {
            return Ok(());
        }
        if self.client_unconfirmed() && !self.final_flight_records.is_empty() {
            // Anything already queued for acknowledgement goes out first,
            // then the final flight's ACK (RFC 9147 §5.8.1).
            self.flush_pending_acks();
            self.pending_acks = self.final_flight_records.clone();
            self.flush_pending_acks();
        }
        let dg = self.encrypt_protected_record(
            ContentType::Alert,
            // RFC 8446 §6: `close_notify` is a warning-level (1) alert.
            &[1, AlertDescription::CloseNotify.as_u8()],
        )?;
        self.out_dgrams.push(dg);
        self.close_notify_sent = true;
        Ok(())
    }

    /// RFC 8446 §7.5 / RFC 5705 — DTLS 1.3 application-layer Exporter.
    /// Derives `out.len()` bytes from the `exporter_master_secret` under
    /// `(label, context)`. The derivation matches TLS 1.3's exporter —
    /// DTLS 1.3 explicitly reuses the TLS 1.3 key schedule. Returns
    /// `Err(InappropriateState)` until the handshake completes.
    pub fn tls_exporter(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let ems = self
            .exporter_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        crate::tls::crypto::tls_exporter_with(
            LabelPrefix::Dtls13,
            suite.hash,
            ems,
            label,
            context,
            out,
        )
    }

    /// Drains pending UDP datagrams. Also drains any pending ACKs.
    pub fn pop_outbound_datagrams(&mut self) -> Vec<Vec<u8>> {
        self.flush_pending_acks();
        core::mem::take(&mut self.out_dgrams)
    }

    /// Drains decrypted application data.
    pub fn take_received(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app_in)
    }

    /// Encrypts application plaintext into a single DTLS record. Must be
    /// called only after the handshake completes.
    ///
    /// `plaintext` may be at most 2^14 bytes (`TLSPlaintext.length`, RFC
    /// 8446 §5.1); larger input is rejected with [`Error::RecordOverflow`]
    /// rather than silently truncating the record's 16-bit length field.
    /// Callers wanting to send more must chunk. Note that DTLS is a
    /// datagram protocol: a record above the path MTU will be fragmented
    /// or dropped by IP, so practical payloads are far smaller.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected || self.close_notify_sent {
            return Err(Error::InappropriateState);
        }
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::RecordOverflow);
        }
        let dg = self.encrypt_protected_record(ContentType::ApplicationData, plaintext)?;
        self.out_dgrams.push(dg);
        Ok(())
    }

    /// Absolute monotonic time at which `on_timeout` should be called next.
    pub fn next_timeout(&self) -> Option<Duration> {
        self.retransmit.next_timeout()
    }

    /// Advances the connection's monotonic clock to `now`. Callers SHOULD
    /// invoke this (or [`Self::on_timeout`]) regularly so the cookie
    /// generator sees a current time. Idempotent in the rewind direction
    /// (older times are ignored).
    ///
    /// Cookie-clock contract: once this (or `on_timeout`) has been called,
    /// the caller's clock stamps and validates HelloRetryRequest cookies.
    /// If the caller NEVER drives the clock, the server falls back to wall
    /// time under `std` so the cookie max-age bound (RFC 9147 §5.1) stays
    /// real; on `no_std` builds with no caller clock, cookies are issued
    /// and validated at `TS = 0` and therefore never expire — drive this
    /// method if cookie expiry matters there. Avoid switching from the
    /// never-driven mode to the caller-driven mode while a cookie exchange
    /// is in flight: a cookie stamped from one clock will not validate
    /// against the other.
    pub fn set_now(&mut self, now: Duration) {
        self.clock_driven = true;
        if now > self.last_now {
            self.last_now = now;
        }
        self.expire_prev_read();
    }

    /// Clock used to stamp / validate HelloRetryRequest cookies, in
    /// minutes. Uses the caller-driven sans-I/O clock when the caller has
    /// ever advanced it; otherwise (under `std`) falls back to wall time so
    /// that with `last_now` stuck at 0 every cookie would not be issued AND
    /// validated at `TS = 0`, which would silently disable the 10-minute
    /// cookie max-age replay bound.
    fn cookie_now_minutes(&self) -> u32 {
        #[cfg(feature = "std")]
        if !self.clock_driven
            && let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        {
            return (d.as_secs() / 60) as u32;
        }
        (self.last_now.as_secs() / 60) as u32
    }

    /// Drives the retransmit machine.
    pub fn on_timeout(&mut self, now: Duration) {
        self.clock_driven = true;
        self.last_now = now;
        self.expire_prev_read();
        match self.retransmit.on_timeout(now) {
            super::reliability::Action::Retransmit => {
                self.retransmit_in_flight();
                // Handshake retransmit: if nothing of the peer's flight
                // arrived since the last timer fire, drop the half-assembled
                // inbound handshake messages — evicting any poisoned
                // reassembly candidate seeded by a spoofed epoch-0 fragment,
                // which otherwise has no expiry at all. Partials that grew
                // since then are kept so a fragmented message can assemble
                // across retransmissions under loss. Only while still
                // handshaking — an established connection's partials are
                // AEAD-authenticated and must survive.
                if self.state != State::Connected {
                    self.pre_cookie.clear();
                    if let Some(r) = self.reassembler.as_mut() {
                        r.clear_if_stalled();
                    }
                }
            }
            super::reliability::Action::GiveUp => {
                if self.state == State::Connected && !self.key_update_pending {
                    // A fully established connection must never self-close
                    // just because a stale handshake record was not
                    // explicitly ACKed. Drop the leftover in-flight state
                    // and stay Connected; only an in-progress handshake
                    // times out.
                    self.retransmit = Retransmit13::new();
                } else {
                    // An unacknowledged KeyUpdate is different: RFC 9147
                    // §8 forbids moving to the new epoch without the ACK,
                    // and the peer may already have — the epochs can no
                    // longer be reconciled.
                    self.state = State::Closed;
                }
            }
            super::reliability::Action::Idle => {}
        }
    }

    /// Feeds one incoming UDP datagram.
    pub fn feed_datagram(&mut self, datagram: &[u8]) -> Result<(), Error> {
        if let Some(cid) = self.cid.as_mut() {
            cid.start_datagram();
        }
        let mut off = 0usize;
        while off < datagram.len() {
            let first = datagram[off];
            if first < 32 {
                // A truncated trailing record or a bogus declared length
                // (RecordOverflow) means framing is lost for the rest of the
                // datagram: silently discard (RFC 9147 §4.5.2) — a single
                // spoofed datagram must never be fatal.
                let rec = match record::read_record(&datagram[off..]) {
                    Ok(Some(rec)) => rec,
                    Ok(None) | Err(_) => return Ok(()),
                };
                off += rec.len;
                self.process_plaintext_record(rec)?;
            } else if (first & 0b1110_0000) == 0b0010_0000 {
                let consumed = self.process_protected_record(&datagram[off..])?;
                if consumed == 0 {
                    return Ok(());
                }
                off += consumed;
            } else {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Processes one legacy-framed plaintext record (epoch 0).
    ///
    /// Everything in here is unauthenticated, attacker-spoofable input, so
    /// per RFC 9147 §4.5.2 every rejection is a silent drop — never fatal.
    fn process_plaintext_record(&mut self, rec: ParsedDtlsRecord<'_>) -> Result<(), Error> {
        if rec.version != ProtocolVersion::DTLSv1_2 && rec.version != ProtocolVersion::DTLSv1_0 {
            // Unknown record version: silently discard.
            return Ok(());
        }
        if rec.epoch != 0 {
            return Ok(());
        }
        match rec.content_type {
            ContentType::Handshake => {
                // Plaintext handshake records are only meaningful while we
                // still await a ClientHello. Afterwards (and in particular
                // once connected) they are trivially spoofable and must not
                // be able to affect the connection.
                if matches!(
                    self.state,
                    State::WaitFirstClientHello | State::WaitSecondClientHello
                ) {
                    self.process_handshake_record(rec.fragment, false)
                } else {
                    Ok(())
                }
            }
            ContentType::Alert => Ok(()),
            ContentType::ChangeCipherSpec => Ok(()),
            // Unknown / unexpected plaintext content type: silent discard.
            _ => Ok(()),
        }
    }

    /// Processes one unified-header protected record, returning the number
    /// of bytes consumed from `buf` (0 = couldn't parse, drop datagram).
    ///
    /// Until the AEAD tag verifies, everything in here is unauthenticated,
    /// attacker-spoofable input — per RFC 9147 §4.5.2 every rejection is a
    /// silent drop (skip the record, or the rest of the datagram where
    /// framing is lost), never connection-fatal.
    fn process_protected_record(&mut self, buf: &[u8]) -> Result<usize, Error> {
        // The CID length this side receives (RFC 9147 §4: not on the wire,
        // so the header is parsed with the negotiated length). With none
        // negotiated, a record with the C bit set is refused (§9) — as a
        // malformed header, below.
        let cid_len = self.cid.as_ref().map_or(0, CidState::local_len);
        // A malformed unified header means framing is lost: drop the rest
        // of the datagram.
        let Ok((hdr_len, body_len)) = peek_header_layout(buf, cid_len) else {
            return Ok(0);
        };
        let total = hdr_len + body_len;
        if total > buf.len() {
            return Ok(0);
        }
        // RFC 9146 §3 / RFC 9147 §4: once this side receives a CID, a record
        // without one is invalid, and one under a CID we never issued is
        // another association's (or forged): silently dropped either way,
        // before any key is touched.
        if cid_len > 0 {
            let has_cid = buf[0] & 0b0001_0000 != 0;
            if !has_cid
                || !self
                    .cid
                    .as_ref()
                    .is_some_and(|c| c.accepts(&buf[1..1 + cid_len]))
            {
                return Ok(total);
            }
        }
        let body = &buf[hdr_len..total];
        if body.len() < 16 {
            // Smaller than the AEAD tag alone — bogus; skip this record.
            return Ok(total);
        }
        // A protected record that arrives before the protected read keys
        // exist is unprocessable — skip it.
        let Some(suite) = self.suite else {
            return Ok(total);
        };
        // RFC 9147 §4.2.2: the unified header carries only the low two
        // epoch bits. Resolve them against the current read epoch first,
        // then the retained previous one, then the early-data epoch while
        // accepted 0-RTT may still arrive (§6.1); anything else — a
        // rejected 0-RTT flight above all (RFC 8446 §4.2.10) — is
        // unreadable and dropped silently.
        let (ctx, is_prev, is_early) =
            match select_read_epoch(&mut self.read, &mut self.prev_read, buf[0] & 0b11) {
                Some((ctx, is_prev)) => (ctx, is_prev, false),
                None => match self.early_read.as_mut() {
                    Some(early) if early.matches_low2(buf[0] & 0b11) => (early, false, true),
                    _ => return Ok(total),
                },
            };
        let Ok(mask_full) = sn_mask_for(suite, ctx.sn_key.as_slice(), body) else {
            return Ok(total);
        };
        let mask: &[u8] = if (buf[0] & 0b0000_1000) != 0 {
            &mask_full[..2]
        } else {
            &mask_full[..1]
        };
        let Ok((hdr, ct_body)) = record13::decode_record(buf, mask, cid_len) else {
            return Ok(total);
        };
        let consumed = hdr.header_len + ct_body.len();

        let seq = reconstruct_seq(hdr.seq_low, hdr.seq_is_16bit, ctx.seq.wrapping_add(1));

        // RFC 9147 §4.2.3: AAD is the unified header (CID included) prior
        // to seq masking.
        let aad = header_aad(buf, &hdr, mask);
        // Pre-AEAD anti-replay check: cheap rejection of duplicate /
        // too-old seq numbers without touching window state. The window
        // is only `mark`-ed after AEAD verification succeeds so a forged
        // packet that fails AEAD does not burn a slot.
        if !ctx.replay.check(seq) {
            return Ok(consumed);
        }
        let Ok((inner_type, plain)) = decrypt_dtls13_record(&mut ctx.crypter, seq, &aad, ct_body)
        else {
            // AEAD authentication failed — a single spoofed datagram must
            // not kill the connection (RFC 9147 §4.5.2): silent drop. The
            // replay window was deliberately not advanced.
            return Ok(consumed);
        };
        // RFC 9147 §4.5.1: AEAD verified — now commit to the window.
        ctx.replay.mark(seq);
        if seq > ctx.seq {
            ctx.seq = seq;
        }
        let read_epoch = ctx.epoch;
        if is_early {
            self.on_early_data_record(inner_type, &plain)?;
            return Ok(consumed);
        }
        // RFC 9147 §5.6: once records arrive under the application keys
        // the client is past its early data; no more epoch-1 records are
        // accepted (the reordering window a datagram path needs is the
        // handshake round trip itself, which is over by now).
        if read_epoch >= 3 && !is_prev {
            self.early_read = None;
        }
        // RFC 9146 §6: an authenticated record newer than any before it,
        // carrying a CID, may move the peer's address (the caller's
        // decision, see `datagram_allows_peer_address_update`).
        if let Some(cid) = self.cid.as_mut() {
            cid.note_authenticated(read_epoch, seq, !header_cid(buf, &hdr).is_empty());
        }
        // Grace accounting for the retired epoch: once enough traffic has
        // arrived under the current epoch, nothing from the previous one is
        // still plausibly in flight (RFC 9147 §4.2.2).
        if !is_prev && self.prev_read.is_some() {
            self.prev_read_grace += 1;
            if self.prev_read_grace >= PREV_EPOCH_GRACE_RECORDS {
                self.prev_read = None;
                self.prev_read_deadline = None;
            }
        }
        // Wall-clock backstop for a connection too quiet to reach the
        // record count (see `PREV_EPOCH_GRACE_TIME`).
        self.expire_prev_read();
        // RFC 9147 §7.1 implicit acknowledgement: an authenticated record
        // from the client proves it holds the handshake keys, i.e. our
        // plaintext (epoch 0) ServerHello arrived. Epoch-0 records are never
        // explicitly ACKed, so release them here — otherwise the SH would
        // sit in the in-flight set forever and the GiveUp cap would tear
        // down a healthy connection minutes after it was established.
        self.retransmit.release_epoch(0);
        // Schedule an ACK for handshake records only (RFC 9147 §7): alerts
        // are not handshake messages, and ACK records themselves MUST NOT
        // be acknowledged — ACKing an ACK provokes the peer's ACK in
        // return, locking two conforming endpoints into a perpetual
        // encrypted ping-pong.
        let is_handshake = matches!(inner_type, ContentType::Handshake);
        if is_handshake {
            // Bounded queue: RFC 9147 §7.1 only requires acknowledging the
            // current flight, so drop the oldest entry rather than growing
            // one record number per AEAD-verified record forever.
            if self.pending_acks.len() >= MAX_PENDING_ACKS {
                self.pending_acks.remove(0);
            }
            self.pending_acks.push(RecordNumber {
                epoch: read_epoch as u64,
                seq,
            });
            // Every handshake record under epoch 2 belongs to the
            // client's final flight (it sends nothing else there).
            if read_epoch == 2 {
                if self.final_flight_records.len() >= MAX_FINAL_FLIGHT_RECORDS {
                    self.final_flight_records.remove(0);
                }
                self.final_flight_records.push(RecordNumber {
                    epoch: read_epoch as u64,
                    seq,
                });
            }
        }

        // Once connected, the handshake epoch (2) is only still readable as
        // the retired epoch so a retransmitted client Finished flight —
        // whose ACK we lost — can be re-ACKed, and that ACK was queued
        // above. RFC 9147 §4.2.1 / RFC 8446 §4.6 put every post-handshake
        // message (KeyUpdate) and every alert of an established connection
        // under the application keys, so nothing else under epoch 2 may
        // act on the connection: a handshake fragment with a fresh
        // `message_seq` would otherwise reach `on_post_handshake` through
        // the reassembler (and advance its `expected_msg_seq` past the
        // genuine epoch-3 stream), and a close_notify would tear the
        // connection down under keys the peer has retired. The genuine
        // client only ever retransmits under epoch 2, so the whole payload
        // is dropped here; application data under epoch 2 stays fatal
        // below, as before.
        let retired_handshake_epoch = self.state == State::Connected && read_epoch == 2;
        // Anything but an ACK under the application keys shows a client
        // that is past its handshake (see `handshake_flight_pending`).
        if self.state == State::Connected
            && read_epoch >= 3
            && !matches!(inner_type, ContentType::Unknown(t) if t == ACK_CONTENT_TYPE)
        {
            self.client_confirmed = true;
            self.final_flight_records = Vec::new();
        }

        // Past this point the record is authenticated: protocol violations
        // below come from the genuine peer and remain fatal.
        match inner_type {
            ContentType::Handshake if retired_handshake_epoch => {}
            ContentType::Handshake => self.process_handshake_record(&plain, true)?,
            ContentType::ApplicationData => {
                if self.state != State::Connected {
                    return Err(Error::UnexpectedMessage);
                }
                // RFC 9147 §4.2.2 / RFC 8446 §4.6: application data is
                // never protected with the handshake keys. Epoch 2 is only
                // still readable as the retired epoch, kept so a
                // retransmitted client flight can be re-ACKed; accepting
                // app data under it would extend the handshake keys'
                // reach over the connection's data.
                if read_epoch == 2 {
                    return Err(Error::UnexpectedMessage);
                }
                self.app_in.extend_from_slice(&plain);
            }
            ContentType::Alert if retired_handshake_epoch => {}
            ContentType::Alert => self.process_peer_alert(&plain)?,
            ContentType::Unknown(t) if t == ACK_CONTENT_TYPE => {
                let acks = decode_ack(&plain)?;
                // An ACK naming a record we sent under the application
                // keys (a NewSessionTicket) could only come from a client
                // that installed them — one past its handshake (see
                // `handshake_flight_pending`).
                if self.state == State::Connected
                    && acks.iter().any(|rn| {
                        rn.epoch >= 3
                            && self
                                .retransmit
                                .in_flight()
                                .iter()
                                .any(|r| r.record_numbers.contains(rn))
                    })
                {
                    self.client_confirmed = true;
                    self.final_flight_records = Vec::new();
                }
                self.retransmit.on_ack(&acks);
                self.complete_key_update_if_acked()?;
                self.flush_owed_new_connection_id()?;
            }
            _ => return Err(Error::UnexpectedMessage),
        }
        Ok(consumed)
    }

    /// An authenticated epoch-1 record (RFC 9147 §6.1): accepted 0-RTT
    /// application data, bounded by `max_early_data_size` (RFC 8446
    /// §4.2.10 — a client sending more than the ticket allowed is at fault,
    /// fatally), or an alert. Nothing else may travel under the early keys.
    fn on_early_data_record(&mut self, inner_type: ContentType, plain: &[u8]) -> Result<(), Error> {
        match inner_type {
            ContentType::ApplicationData => {
                let len = u32::try_from(plain.len()).map_err(|_| Error::UnexpectedMessage)?;
                if len > self.early_data_remaining {
                    return Err(Error::UnexpectedMessage);
                }
                self.early_data_remaining -= len;
                self.early_in.extend_from_slice(plain);
                Ok(())
            }
            ContentType::Alert => self.process_peer_alert(plain),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Initiates a key update (RFC 9147 §8 / RFC 8446 §4.6.3): sends a
    /// `KeyUpdate` under the current write epoch and, once the client
    /// acknowledges it, advances our write keys to the next epoch. Until
    /// that ACK arrives [`Self::send`] keeps using the current keys — the
    /// RFC forbids sending under the new epoch (or a further `KeyUpdate`)
    /// before then, so a second call while one is in flight is refused
    /// with [`Error::InappropriateState`]. With `request_peer` the client
    /// is asked to update its own keys too.
    ///
    /// Must be called only after the handshake completes. A `KeyUpdate`
    /// that is never acknowledged (six retransmits, RFC 9147 §5.8.1) closes
    /// the connection: the peer may already have moved on, and the two
    /// sides can no longer agree on an epoch.
    pub fn request_key_update(&mut self, request_peer: bool) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::InappropriateState);
        }
        if self.key_update_pending {
            return Err(Error::InappropriateState);
        }
        if self.enc_write_epoch == u16::MAX {
            return Err(Error::TooManyRecords);
        }
        let body = KeyUpdate {
            request_update: request_peer,
        }
        .encode();
        self.emit_encrypted_handshake(hs_type::KEY_UPDATE, &body[4..])?;
        self.key_update_pending = true;
        self.key_updates_sent += 1;
        Ok(())
    }

    /// True while a `KeyUpdate` we sent is still waiting for the client's
    /// ACK (our write epoch has not advanced yet).
    pub fn key_update_pending(&self) -> bool {
        self.key_update_pending
    }

    /// Current protected write epoch (3 for the first application keys;
    /// one more per acknowledged `KeyUpdate` we sent).
    pub fn write_epoch(&self) -> u16 {
        self.enc_write_epoch
    }

    /// Current protected read epoch (3 for the first application keys; one
    /// more per `KeyUpdate` received). `None` until the handshake keys are
    /// installed.
    pub fn read_epoch(&self) -> Option<u16> {
        self.read.as_ref().map(|r| r.epoch)
    }

    /// RFC 9147 §8: once the peer has ACKed our `KeyUpdate` — i.e. no
    /// `KeyUpdate` fragment remains in the in-flight set — switch the write
    /// keys to the next epoch. Application secrets advance with
    /// `HKDF-Expand-Label(secret, "traffic upd", "", Hash.length)`
    /// (RFC 8446 §7.2); the sequence-number key is re-derived from the new
    /// secret (RFC 9147 §4.2.3).
    fn complete_key_update_if_acked(&mut self) -> Result<(), Error> {
        if !self.key_update_pending {
            return Ok(());
        }
        let still_in_flight = self
            .retransmit
            .in_flight()
            .iter()
            .any(|r| r.fragment.first() == Some(&hs_type::KEY_UPDATE));
        if still_in_flight {
            return Ok(());
        }
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let cur = self
            .server_app_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let next = next_traffic_secret_with(LabelPrefix::Dtls13, suite.hash, cur);
        let sn_len = sn_key_len_for(suite.aead);
        self.write_crypter = Some(RecordCrypter::new_with(
            LabelPrefix::Dtls13,
            suite.hash,
            suite.aead,
            suite.key_len,
            &next,
        ));
        self.write_sn_key = Some(derive_sn_key(suite.hash, &next, sn_len));
        self.server_app_secret = Some(next);
        self.enc_write_epoch += 1;
        self.enc_write_seq = 0;
        self.key_update_pending = false;
        Ok(())
    }

    /// Post-handshake handshake messages from the client (RFC 9147 §8 /
    /// RFC 8446 §4.6). The record was AEAD-authenticated and has already
    /// been queued for ACK. Only `KeyUpdate` is legitimate from a client
    /// (NewSessionTicket is server-to-client).
    fn on_post_handshake(&mut self, msg_type: u8, body: &[u8]) -> Result<(), Error> {
        match msg_type {
            hs_type::KEY_UPDATE => {
                let ku = KeyUpdate::decode(body)?;
                self.on_key_update_received(ku)
            }
            hs_type::NEW_CONNECTION_ID => self.on_new_connection_id(body),
            hs_type::REQUEST_CONNECTION_ID => self.on_request_connection_id(body),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// A client `NewConnectionId` (RFC 9147 §9): switch to the first CID
    /// at once for `cid_immediate`, keep the rest as spares (bounded). A
    /// client that never negotiated CIDs, or that negotiated receiving an
    /// empty one, MUST NOT send this: `unexpected_message`.
    fn on_new_connection_id(&mut self, body: &[u8]) -> Result<(), Error> {
        let cid = self.cid.as_mut().ok_or(Error::UnexpectedMessage)?;
        if cid.peer().is_empty() {
            return Err(Error::UnexpectedMessage);
        }
        let msg = NewConnectionId::decode(body)?;
        cid.on_new_connection_id(msg);
        Ok(())
    }

    /// A client `RequestConnectionId` (RFC 9147 §9): answer with a
    /// `NewConnectionId(cid_spare)` carrying up to `num_cids` fresh receive
    /// CIDs from the pool (possibly none once it is spent), as soon as no
    /// earlier `NewConnectionId` of ours is unacknowledged. A client that
    /// sends without a CID MUST NOT ask (`unexpected_message`); one that
    /// asks too often is refused with `too_many_cids_requested`.
    fn on_request_connection_id(&mut self, body: &[u8]) -> Result<(), Error> {
        let cid = self.cid.as_mut().ok_or(Error::UnexpectedMessage)?;
        if cid.local().is_empty() {
            return Err(Error::UnexpectedMessage);
        }
        cid.note_request_received()?;
        let req = RequestConnectionId::decode(body)?;
        self.cid_reply_owed = self.cid_reply_owed.saturating_add(req.num_cids);
        self.flush_owed_new_connection_id()
    }

    /// Sends the `NewConnectionId` owed for received `RequestConnectionId`s
    /// once no earlier one is in flight (RFC 9147 §9: "endpoints MUST NOT
    /// have more than one NewConnectionId message outstanding").
    fn flush_owed_new_connection_id(&mut self) -> Result<(), Error> {
        if self.cid_reply_owed == 0 || self.state != State::Connected {
            return Ok(());
        }
        let outstanding = self
            .retransmit
            .in_flight()
            .iter()
            .any(|r| r.fragment.first() == Some(&hs_type::NEW_CONNECTION_ID));
        if outstanding {
            return Ok(());
        }
        let Some(cid) = self.cid.as_mut() else {
            return Ok(());
        };
        let cids = cid.issue(self.cid_reply_owed as usize);
        self.cid_reply_owed = 0;
        let body = NewConnectionId {
            cids,
            usage: ConnectionIdUsage::Spare,
        }
        .encode_body();
        self.emit_encrypted_handshake(hs_type::NEW_CONNECTION_ID, &body)
    }

    /// Arms the wall-clock expiry of the read epoch just retired into
    /// `prev_read` (see [`PREV_EPOCH_GRACE_TIME`]). While the caller has
    /// not driven the clock the deadline stays unarmed and is set at the
    /// first clock observation, so a caller whose clock starts far from
    /// zero cannot retire the epoch the instant it first calls in.
    fn arm_prev_read_expiry(&mut self) {
        self.prev_read_grace = 0;
        self.prev_read_deadline = self
            .clock_driven
            .then(|| self.last_now.saturating_add(PREV_EPOCH_GRACE_TIME));
    }

    /// Drops the retired read epoch once its grace period has elapsed:
    /// nothing the peer may still be retransmitting under it can plausibly
    /// be in flight any more, and stale keys should not outlive their use
    /// (RFC 9147 §4.2.2).
    fn expire_prev_read(&mut self) {
        if self.prev_read.is_none() {
            self.prev_read_deadline = None;
            return;
        }
        if !self.clock_driven {
            return;
        }
        match self.prev_read_deadline {
            None => {
                self.prev_read_deadline = Some(self.last_now.saturating_add(PREV_EPOCH_GRACE_TIME));
            }
            Some(deadline) if self.last_now >= deadline => {
                self.prev_read = None;
                self.prev_read_deadline = None;
            }
            Some(_) => {}
        }
    }

    /// Rate-limits inbound `KeyUpdate`s to [`MAX_KEY_UPDATES_RECEIVED`] per
    /// [`KEY_UPDATE_WINDOW`] instead of capping them for the life of the
    /// connection: an authenticated peer must not be able to burn our CPU
    /// on key schedules, but a long-lived connection that rekeys at a sane
    /// rate must not be torn down either.
    fn note_key_update_received(&mut self) -> Result<(), Error> {
        if self.clock_driven
            && self.last_now.saturating_sub(self.key_update_window_start) >= KEY_UPDATE_WINDOW
        {
            self.key_update_window_start = self.last_now;
            self.key_updates_received = 0;
        }
        self.key_updates_received += 1;
        if self.key_updates_received > MAX_KEY_UPDATES_RECEIVED {
            return Err(Error::PeerMisbehaved);
        }
        Ok(())
    }

    /// RFC 9147 §8: the client's write epoch advances. Install the next read
    /// epoch, retire the current one for the reordering / retransmit grace
    /// window, and — when asked — answer with a `KeyUpdate` of our own
    /// (`update_not_requested`, RFC 8446 §4.6.3) unless one is already in
    /// flight, which will rotate our keys just the same.
    fn on_key_update_received(&mut self, ku: KeyUpdate) -> Result<(), Error> {
        self.note_key_update_received()?;
        self.key_updates_received_total += 1;
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let cur_epoch = self.read.as_ref().map(|r| r.epoch).unwrap_or(0);
        if cur_epoch == u16::MAX {
            return Err(Error::TooManyRecords);
        }
        let prev_secret = self
            .client_app_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let next = next_traffic_secret_with(LabelPrefix::Dtls13, suite.hash, prev_secret);
        let new_read = ReadEpoch::new(suite, cur_epoch + 1, &next);
        self.client_app_secret = Some(next);
        // Only the immediately previous epoch stays readable (§4.2.2).
        self.prev_read = self.read.replace(new_read);
        self.arm_prev_read_expiry();
        if ku.request_update && !self.key_update_pending {
            self.request_key_update(false)?;
        }
        Ok(())
    }

    /// Handles an authenticated peer alert (RFC 9147 §4: once keys exist,
    /// alerts travel inside protected records; the payload is the 2-byte
    /// TLS alert `level ‖ description`). Mirrors the TLS engines:
    /// `close_notify` is a clean shutdown (state → Closed, no error); every
    /// other alert is fatal per RFC 8446 §6 and surfaced as
    /// [`Error::AlertReceived`].
    fn process_peer_alert(&mut self, plain: &[u8]) -> Result<(), Error> {
        // The record authenticated, so a malformed alert is a genuine peer
        // fault (RFC 8446 §6: an alert is exactly two bytes).
        if plain.len() != 2 {
            return Err(Error::Decode);
        }
        let desc = AlertDescription::from_u8(plain[1]);
        self.state = State::Closed;
        if desc == AlertDescription::CloseNotify {
            self.close_notify_received = true;
            Ok(())
        } else {
            Err(Error::AlertReceived(desc))
        }
    }

    /// Processes the handshake fragments in one record body.
    ///
    /// `authenticated` is true when the bytes came out of a successfully
    /// AEAD-verified record. Framing errors in unauthenticated (plaintext)
    /// records are attacker-spoofable and dropped silently; the same errors
    /// in authenticated records are genuine peer faults and stay fatal.
    fn process_handshake_record(&mut self, plain: &[u8], authenticated: bool) -> Result<(), Error> {
        let mut off = 0;
        while off < plain.len() {
            let frag = match read_fragment(&plain[off..]) {
                Ok(f) => f,
                Err(e) => {
                    if authenticated {
                        return Err(e);
                    }
                    // Silently drop the rest of this spoofable record.
                    return Ok(());
                }
            };
            let consumed = frag.len;
            if self.reassembler.is_none() {
                // Pre-state path: only ClientHello allowed. A multi-group
                // offer overflows the per-record fragment budget, so CH may
                // arrive in several records — feed them through a temporary
                // reassembler (RFC 9147 §5.5) and only dispatch once the
                // full body is in hand.
                // Only a ClientHello at `message_seq` 0 (a first CH) or 1
                // (the post-HRR CH2), within the pre-cookie length
                // ceiling, can be legitimate here. This is the epoch-0,
                // unauthenticated path, so the rejection is a silent drop
                // of the rest of the record (RFC 9147 §4.5.2), never fatal
                // — and, crucially, a spoofed `message_seq` never
                // influences which sequence numbers the buffer will accept
                // (DTLS-M1).
                if !PreCookieBuffer::admits(&frag) {
                    return Ok(());
                }
                let msg_seq = frag.message_seq;
                off += consumed;
                // A whole-message fragment is handed straight through; a
                // partial one is buffered (bounded on every axis, see
                // `PreCookieBuffer`) until the CH at this `message_seq`
                // completes. The buffer never dispatches on its own, so a
                // rejected spoofed CH cannot leave it refusing the genuine
                // seq-0 fragments.
                let Some(body) = self.pre_cookie.feed(frag) else {
                    continue;
                };
                match self.handle_pre_state_client_hello(msg_seq, &body) {
                    Ok(()) => {
                        // The CH was accepted (HRR emitted, or the real
                        // handshake state bootstrapped): whatever the
                        // fragment buffer still holds is stale.
                        self.pre_cookie.clear();
                    }
                    Err(e) => {
                        // Everything on this path is unauthenticated,
                        // epoch-0, attacker-spoofable input (a forged
                        // cookie being the most reachable). Per RFC 9147
                        // §4.5.2 these faults are silently dropped so a
                        // single spoofed datagram on the 4-tuple can never
                        // tear down a legitimate in-flight handshake — and
                        // a rejected CH leaves the fragment buffer alone,
                        // so a spoofed complete CH cannot flush a genuine
                        // fragmented one mid-reassembly. The one exception
                        // is the local fail-closed misconfiguration (cookie
                        // required but no `cookie_secret`), which fires
                        // identically for the genuine client and must stay
                        // loud.
                        if matches!(e, Error::InappropriateState) {
                            return Err(e);
                        }
                        return Ok(());
                    }
                }
                continue;
            }
            if !authenticated {
                // Once the handshake state exists, the only handshake
                // message the client still owes us is its Finished, which
                // travels in a protected (epoch 2) record. A plaintext
                // handshake fragment here is therefore spoofed by
                // construction: it must neither reach the reassembler
                // (where it could pin `expected_msg_seq`) nor surface a
                // fatal `UnexpectedMessage` from `dispatch_one` (DTLS-L1).
                return Ok(());
            }
            let frag = HandshakeFragment {
                msg_type: frag.msg_type,
                total_length: frag.total_length,
                message_seq: frag.message_seq,
                fragment_offset: frag.fragment_offset,
                fragment: frag.fragment,
                len: frag.len,
            };
            off += consumed;
            let feeding = self
                .reassembler
                .as_mut()
                .expect("reassembler built")
                .feed(frag);
            if let Some((mt, body)) = feeding {
                self.dispatch_one(mt, &body)?;
            }
            loop {
                let popped = self
                    .reassembler
                    .as_mut()
                    .expect("reassembler built")
                    .pop_ready();
                match popped {
                    Some((mt, body)) => self.dispatch_one(mt, &body)?,
                    None => break,
                }
            }
        }
        Ok(())
    }

    fn dispatch_one(&mut self, msg_type: u8, body: &[u8]) -> Result<(), Error> {
        let mut raw = Vec::with_capacity(4 + body.len());
        raw.push(msg_type);
        let n = body.len() as u32;
        raw.push(((n >> 16) & 0xff) as u8);
        raw.push(((n >> 8) & 0xff) as u8);
        raw.push((n & 0xff) as u8);
        raw.extend_from_slice(body);
        match self.state {
            State::WaitClientCertificate => self.on_client_certificate(msg_type, body, &raw),
            State::WaitClientCertVerify => self.on_client_cert_verify(msg_type, body, &raw),
            State::WaitClientFinished => self.on_client_finished(msg_type, body, &raw),
            State::Connected => self.on_post_handshake(msg_type, body),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Handle a fresh CH (no reassembler state).
    fn handle_pre_state_client_hello(&mut self, msg_seq: u16, body: &[u8]) -> Result<(), Error> {
        // F3: bound the client-supplied `message_seq` before the reassembler
        // seeding loop below (`for s in 0..=msg_seq`). `message_seq` is not
        // covered by the cookie fingerprint, so even a client that completes
        // the address-ownership roundtrip can drive this loop; an oversized
        // value would otherwise mean tens of thousands of synthetic-message
        // allocate/serialize/parse/feed cycles.
        if msg_seq > MAX_HS_MSG_SEQ {
            return Err(Error::IllegalParameter);
        }
        // RFC 9147 §5.3: the DTLS ClientHello carries a `legacy_cookie`
        // field a TLS-shaped hello lacks; a DTLS 1.3 client MUST send it
        // empty (the HRR cookie travels in the `cookie` extension) and the
        // server MUST abort with `illegal_parameter` otherwise.
        let (ch, legacy_cookie) = ClientHello::decode_dtls(body)?;
        if !legacy_cookie.is_empty() {
            return Err(Error::IllegalParameter);
        }
        // RFC 9147 §5.3: only the DTLS 1.3 codepoint `0xfefc` may be
        // selected. A hello that offers merely TLS 1.3 (`0x0304`) — or
        // nothing at all (a DTLS 1.2 client) — cannot be served here.
        let sv = ext::find(&ch.extensions, ExtensionType::SUPPORTED_VERSIONS)
            .ok_or(Error::UnsupportedVersion)?;
        if !super::client_offers_dtls13(sv)? {
            return Err(Error::UnsupportedVersion);
        }
        // Fail closed: a server that asks for cookie enforcement but never
        // supplied a `cookie_secret` MUST NOT silently degrade to the
        // no-cookie path (which would emit the full, expensive server flight
        // to an unverified, possibly-spoofed source — an amplification +
        // asymmetric-signature DoS). Reject before any flight is generated.
        if self.config.require_cookie && self.config.cookie_secret.is_none() {
            return Err(Error::InappropriateState);
        }
        let cookie_required = self.config.require_cookie;
        // Fail closed: a cookie that is not bound to the peer's transport
        // address proves nothing about return-routability. It would only
        // attest that *someone* completed one round trip with these
        // ClientHello bytes, so an attacker can harvest one cookie from
        // their own address and then replay that identical ~150-byte CH2
        // from arbitrary SPOOFED sources for the cookie's whole lifetime --
        // each replay costing the server an ephemeral keygen plus an
        // asymmetric signature and emitting a multi-KB flight at the
        // victim (~15-30x UDP reflection amplification). Refuse loudly
        // instead, mirroring the "cookie required but no secret" posture
        // above. Callers set the address via `Config::peer_address` /
        // `ConfigBuilder::peer_socket_addr`.
        if cookie_required && self.peer_addr.is_empty() {
            return Err(Error::InappropriateState);
        }
        // Look for an existing cookie extension in CH.
        let presented_cookie = ch
            .extensions
            .iter()
            .find(|(t, _)| t.0 == EXT_COOKIE)
            .map(|(_, b)| b.clone());

        // Pick the cipher suite from the client's offer, in our preference
        // order. We need this both for HRR (which must carry the chosen
        // suite per RFC 8446 §4.1.4) and for committing the transcript hash.
        let suite = supported_suites()
            .iter()
            .copied()
            .find(|s| ch.cipher_suites.contains(&s.suite))
            .ok_or(Error::HandshakeFailure)?;
        // ALPN (RFC 7301): decided here, before any state is touched, so a
        // no-overlap offer is rejected like any other unacceptable CH; it is
        // pinned on `self` only once this CH is committed (below the HRR
        // paths, which re-enter here with the cookie-bearing CH2).
        let alpn_pick = super::select_alpn(&self.config.alpn_protocols, &ch.extensions)?;
        // Connection IDs (RFC 9146 §3): negotiated only when the client
        // offered the extension and this server has a CID to receive under;
        // decided here, committed with the rest below.
        let cid_pick = negotiate_server(
            self.config.connection_id.as_deref(),
            ext::find(&ch.extensions, ExtensionType::CONNECTION_ID),
        )?;

        // Parse offered groups + offered shares. We need them both to
        // detect "send HRR-for-group-change" and to pick a share.
        let groups_ext = ext::find(&ch.extensions, ExtensionType::SUPPORTED_GROUPS)
            .ok_or(Error::HandshakeFailure)?;
        let offered_groups = parse_supported_groups(groups_ext)?;
        let ks_ext =
            ext::find(&ch.extensions, ExtensionType::KEY_SHARE).ok_or(Error::HandshakeFailure)?;
        let client_shares = ext::parse_client_key_shares(ks_ext)?;

        // Preferred group from `supported_groups`, in this server's order
        // (RFC 8446 §4.2.7 — server picks the first mutually-acceptable
        // entry). Mirrors the TLS layer's preference at
        // `src/tls/conn/server.rs:1106-1118`.
        let preferred_group = self
            .config
            .groups
            .iter()
            .copied()
            .find(|g| offered_groups.contains(g));

        // Share for the preferred group, if any.
        let preferred_share =
            preferred_group.and_then(|g| client_shares.iter().find(|(sg, _)| *sg == g).cloned());

        // CH content fingerprint binds the cookie to the security-critical
        // CH fields. An attacker who grabbed a cookie issued for a
        // strong-cipher CH1 cannot replay it with a weak-cipher CH2 — the
        // cookie HMAC mismatches (DTLS-5).
        let ch_fp = ch_fingerprint_dtls13(&ch);

        // TLS-shaped ClientHello (the transcript / binder form, RFC 9147
        // §5.2): the 4-byte handshake header + the DTLS-shaped body.
        let raw_ch = tls_client_hello(body);

        // RFC 9147 §5.1: the cookie exchange MAY be skipped when the
        // handshake resumes a PSK and the source address matches the one
        // the ticket was issued to — the return-routability the cookie
        // proves was proven when the ticket was issued, and a replay from
        // that address costs the server only what the genuine client
        // already made it spend. This is also the only path on which 0-RTT
        // can be accepted (a HelloRetryRequest rejects early data, RFC 8446
        // §4.2.10). We skip only when no group-change HRR is needed either
        // (the client shared our preferred group); otherwise the HRR would
        // reject the early data anyway, so the ordinary cookie exchange —
        // which the resumption then rides on — is just as good. The binder
        // is over the first hello, so the transcript prefix is empty.
        let resume_skip_cookie = cookie_required
            && presented_cookie.is_none()
            && preferred_share.is_some()
            && self
                .accept_ticket_psk(&ch, &raw_ch, &[])?
                .is_some_and(|s| s.same_address);
        let do_cookie = cookie_required && !resume_skip_cookie;

        if do_cookie && presented_cookie.is_none() {
            // First CH (cookie required, no cookie yet): emit HRR with a
            // freshly-minted cookie. The cookie's `aux` payload carries the
            // (suite, selected_group, Hash(CH1)) tuple we'd otherwise have
            // to pin on `self` — keeping the server fully stateless across
            // the HRR roundtrip (DTLS-2 / DTLS-4: no per-connection state
            // before cookie validates).
            //
            // Also embed a `key_share(selected_group)` if the client didn't
            // already present a share for our preferred group — RFC 8446
            // §4.1.4 forbids a second HRR, so we combine cookie + group here.
            let group_needed = if preferred_share.is_none() {
                Some(preferred_group.ok_or(Error::HandshakeFailure)?)
            } else {
                None
            };

            // Compute Hash(CH1) using the picked suite's hash, so the CH2
            // path can rebuild the `message_hash(CH1)` transcript synthetic
            // from the cookie's aux payload (RFC 8446 §4.4.1).
            let mut tls_ch1 = Vec::with_capacity(4 + body.len());
            tls_ch1.push(hs_type::CLIENT_HELLO);
            let n = body.len() as u32;
            tls_ch1.push(((n >> 16) & 0xff) as u8);
            tls_ch1.push(((n >> 8) & 0xff) as u8);
            tls_ch1.push((n & 0xff) as u8);
            tls_ch1.extend_from_slice(body);
            let h_ch1 = suite.hash.hash(&tls_ch1);

            // Aux layout:
            //   suite_id : u16 BE
            //   sel_grp  : u16 BE (0x0000 sentinel = no group HRR)
            //   hash_alg : u8 (0=Sha256, 1=Sha384)
            //   hash_ch1 : hash_alg.output_len() bytes
            let mut aux = Vec::with_capacity(5 + suite.hash.output_len());
            aux.extend_from_slice(&suite.suite.0.to_be_bytes());
            aux.extend_from_slice(&group_needed.map(|g| g.0).unwrap_or(0).to_be_bytes());
            aux.push(hash_alg_to_byte(suite.hash));
            aux.extend_from_slice(h_ch1.as_slice());

            let secret = self
                .config
                .cookie_secret
                .as_ref()
                .ok_or(Error::InappropriateState)?;
            let cg = CookieGenerator::new(*secret);
            let now_min = self.cookie_now_minutes();
            let cookie = cg.generate_with_aux(&self.peer_addr, &ch.random, &ch_fp, &aux, now_min);

            // Emit HRR using the local (suite, group_needed) — we do NOT
            // pin them on `self`. CH2 will re-enter this path with the
            // cookie, at which point we'll recover (suite, group, Hash(CH1))
            // from `aux` and bootstrap the real handshake state.
            self.emit_hrr_stateless(suite.suite, &cookie, group_needed)?;
            self.state = State::WaitSecondClientHello;
            // Deliberately DO NOT mutate: self.suite, self.hrr_selected_group,
            // self.transcript, self.out_msg_seq. The CH2 path picks them up
            // from the cookie's aux payload only after the cookie HMAC has
            // verified. msg_seq from this unauthenticated CH is also
            // ignored — the reassembler is not allocated yet (DTLS-4).
            let _ = msg_seq;
            return Ok(());
        }

        // ---- Validation phase ------------------------------------------
        //
        // Everything from here to the commit marker below computes into
        // locals; `self` is not touched until every check that can still
        // reject this CH — cookie MAC, aux decoding, share lookup, key
        // agreement — has passed. Failures on this path are silently
        // dropped as unauthenticated input (see the caller), so a
        // partially-applied state change would be permanent: a replayed
        // CH2 variant with a corrupted `key_share` (the payload is not
        // covered by the cookie fingerprint) used to pin the suite,
        // transcript, `out_msg_seq` and a fresh reassembler before key
        // agreement failed, after which the genuine CH2 was dropped as
        // stale (DTLS-L1).

        /// Where the post-CH transcript comes from at commit time.
        enum TranscriptPlan {
            /// Cookie path: a fully rebuilt `message_hash(CH1) ‖ HRR`.
            Replace(Transcript),
            /// Cookie-off group-HRR path: rewrite the CH1-only transcript
            /// in place as `message_hash(CH1) ‖ HRR`.
            ReplayGroupHrr,
            /// Cookie-off, no HRR: start fresh under the picked suite.
            Fresh,
        }

        let plan: TranscriptPlan;
        let sel_suite: SuiteParams;
        let hrr_group: Option<NamedGroup>;
        let next_out_msg_seq: u16;

        if do_cookie {
            let cookie_bytes = presented_cookie
                .as_ref()
                .ok_or(Error::IllegalParameter)?
                .clone();
            // Validate cookie before any further work — and recover the
            // suite/group/Hash(CH1) tuple the CH1 path parked in `aux`.
            let secret = self
                .config
                .cookie_secret
                .as_ref()
                .ok_or(Error::InappropriateState)?;
            let cg = CookieGenerator::new(*secret);
            // The cookie wire format is `opaque cookie<1..2^16-1>`, so the
            // first 2 bytes are a u16 length prefix.
            if cookie_bytes.len() < 2 {
                return Err(Error::Decode);
            }
            let clen = u16::from_be_bytes([cookie_bytes[0], cookie_bytes[1]]) as usize;
            if cookie_bytes.len() != 2 + clen {
                return Err(Error::Decode);
            }
            let cookie = &cookie_bytes[2..];
            let now_min = self.cookie_now_minutes();
            // Current secret first; on a miss, the previous generation
            // (DTLS-I6: a rotation must not invalidate in-flight cookies).
            // Only the outcome is secret-dependent — which of two
            // legitimately issued cookies validated is not sensitive.
            let aux = cg
                .validate_with_aux(&self.peer_addr, &ch.random, &ch_fp, now_min, cookie)
                .or_else(|| {
                    let prev = self.config.previous_cookie_secret.as_ref()?;
                    CookieGenerator::new(*prev).validate_with_aux(
                        &self.peer_addr,
                        &ch.random,
                        &ch_fp,
                        now_min,
                        cookie,
                    )
                })
                .ok_or(Error::IllegalParameter)?;

            // Decode the aux payload: (suite_id, sel_group, hash_alg, Hash(CH1)).
            if aux.len() < 5 {
                return Err(Error::IllegalParameter);
            }
            let parked_suite_id = CipherSuite(u16::from_be_bytes([aux[0], aux[1]]));
            let parked_sel_group_id = u16::from_be_bytes([aux[2], aux[3]]);
            let parked_hash_alg = hash_alg_from_byte(aux[4]).ok_or(Error::IllegalParameter)?;
            let parked_hash_ch1 = &aux[5..];
            if parked_hash_ch1.len() != parked_hash_alg.output_len() {
                return Err(Error::IllegalParameter);
            }
            // Look up the SuiteParams for the parked suite.
            let parked_suite = supported_suites()
                .iter()
                .copied()
                .find(|s| s.suite == parked_suite_id)
                .ok_or(Error::IllegalParameter)?;
            if parked_suite.hash != parked_hash_alg {
                return Err(Error::IllegalParameter);
            }
            // CH2 must still offer the suite we picked in HRR — the cookie
            // fingerprint check already guarantees this transitively
            // (cipher_suites are part of `ch_fp`), but check explicitly so
            // a malformed cookie payload can't confuse the suite
            // selection.
            if !ch.cipher_suites.contains(&parked_suite.suite) {
                return Err(Error::IllegalParameter);
            }
            let parked_sel_group = if parked_sel_group_id == 0 {
                None
            } else {
                Some(NamedGroup(parked_sel_group_id))
            };

            // Transcript: build `message_hash(CH1) || HRR` synthetically
            // from the cookie's `Hash(CH1)`. This matches what the
            // pin-then-replace flow does at CH2, but without ever buffering
            // CH1 bytes on the server. RFC 8446 §4.4.1 says the post-HRR
            // transcript starts with the 4-byte message_hash header (type
            // 254, length = hash output length) followed by Hash(CH1);
            // `Transcript::update` accepts arbitrary bytes so we feed the
            // synthetic prefix directly.
            let mut t = Transcript::new();
            t.set_alg(parked_suite.hash);
            let h_len = parked_suite.hash.output_len();
            let mut synthetic = Vec::with_capacity(4 + h_len);
            synthetic.push(254); // message_hash
            synthetic.extend_from_slice(&[0, 0]);
            synthetic.push(h_len as u8);
            synthetic.extend_from_slice(parked_hash_ch1);
            t.update(&synthetic);
            // Re-derive the HRR bytes (the same bytes we sent at CH1 time)
            // from the cookie aux, not from `self`.
            let hrr_bytes =
                Self::build_hrr_bytes_explicit(parked_suite.suite, Some(cookie), parked_sel_group);
            t.update(&hrr_bytes);

            plan = TranscriptPlan::Replace(t);
            sel_suite = parked_suite;
            hrr_group = parked_sel_group;
            // The HRR consumed our msg_seq=0 — ServerHello goes out at 1.
            next_out_msg_seq = 1;
        } else if self.hrr_selected_group.is_none() {
            // Cookie-off path: this is CH1 — but we may still need to send
            // a group-change HRR.
            if preferred_share.is_none() {
                let group_needed = preferred_group.ok_or(Error::HandshakeFailure)?;
                self.suite = Some(suite);
                self.hrr_selected_group = Some(group_needed);
                // Transcript: stash CH1 hash, then we'll replay via
                // message_hash on CH2.
                let mut t = Transcript::new();
                t.set_alg(suite.hash);
                let mut tls_ch = Vec::with_capacity(4 + body.len());
                tls_ch.push(hs_type::CLIENT_HELLO);
                let n = body.len() as u32;
                tls_ch.push(((n >> 16) & 0xff) as u8);
                tls_ch.push(((n >> 8) & 0xff) as u8);
                tls_ch.push((n & 0xff) as u8);
                tls_ch.extend_from_slice(body);
                t.update(&tls_ch);
                self.transcript = t;
                self.emit_hello_retry_request(None)?;
                self.state = State::WaitSecondClientHello;
                self.out_msg_seq = 1;
                let _ = msg_seq;
                return Ok(());
            }
            // No HRR needed: CH1 is the only CH; transcript starts fresh.
            plan = TranscriptPlan::Fresh;
            sel_suite = suite;
            hrr_group = None;
            next_out_msg_seq = 0;
        } else {
            // Cookie-off CH2 (post group-HRR). If the HelloRetryRequest was
            // lost, what arrives instead is the client's verbatim
            // retransmission of CH1 (RFC 9147 §5.8.1): it carries no share
            // for the HRR-selected group and used to be dropped as an
            // illegal CH2, so the client retransmitted a hello the server
            // never answered until its budget ran out. The cookie path is
            // immune (a cookie-less hello re-enters the stateless HRR path);
            // mirror that here by re-issuing the same HRR when the hello is
            // byte-identical to the CH1 the transcript still holds. Anything
            // else falls through to the CH2 checks below.
            let hrr_needs = self.hrr_selected_group;
            if hrr_needs.is_some_and(|g| !client_shares.iter().any(|(sg, _)| *sg == g)) {
                let mut tls_ch1 = Vec::with_capacity(4 + body.len());
                tls_ch1.push(hs_type::CLIENT_HELLO);
                let n = body.len() as u32;
                tls_ch1.push(((n >> 16) & 0xff) as u8);
                tls_ch1.push(((n >> 8) & 0xff) as u8);
                tls_ch1.push((n & 0xff) as u8);
                tls_ch1.extend_from_slice(body);
                if self.transcript.buffered_bytes() == tls_ch1.as_slice() {
                    self.emit_hello_retry_request(None)?;
                    return Ok(());
                }
            }
            // The transcript must be rewritten as `message_hash(CH1) ‖ HRR`
            // (RFC 8446 §4.4.1). `replace_with_message_hash()` is not
            // idempotent and the checks below can still fail, so the
            // rewrite is deferred to the commit phase.
            plan = TranscriptPlan::ReplayGroupHrr;
            sel_suite = self.suite.ok_or(Error::InappropriateState)?;
            hrr_group = self.hrr_selected_group;
            next_out_msg_seq = self.out_msg_seq;
        }

        // Pick the actual group + share to use this round.
        let (selected_group, client_pub) = if let Some(g) = hrr_group {
            // CH2 path: must carry exactly the share we requested.
            let share = client_shares
                .iter()
                .find(|(sg, _)| *sg == g)
                .ok_or(Error::IllegalParameter)?;
            (g, share.1.clone())
        } else {
            // No HRR: use the preferred share we found earlier.
            let (g, k) = preferred_share.ok_or(Error::HandshakeFailure)?;
            (g, k)
        };
        let suite = sel_suite;

        // Ephemeral key share + shared secret for the selected group. The
        // last fallible step: a corrupted client share fails here.
        let (server_pub, mut shared) = self.key_agreement(selected_group, &client_pub)?;
        let mut sr: Random = [0u8; 32];
        self.rng.fill_bytes(&mut sr);

        // ---- Commit phase ----------------------------------------------
        // Nothing below can reject the CH any more; apply the negotiated
        // state in one go.
        self.suite = Some(suite);
        self.hrr_selected_group = hrr_group;
        self.negotiated_group = Some(selected_group);
        let plan_was_fresh = matches!(plan, TranscriptPlan::Fresh);
        self.hrr_sent = !plan_was_fresh;
        self.out_msg_seq = next_out_msg_seq;
        match plan {
            TranscriptPlan::Replace(t) => self.transcript = t,
            TranscriptPlan::ReplayGroupHrr => {
                self.transcript.replace_with_message_hash();
                let hrr_bytes = self.build_hrr_bytes(None, hrr_group);
                self.transcript.update(&hrr_bytes);
            }
            TranscriptPlan::Fresh => {
                self.transcript = Transcript::new();
                self.transcript.set_alg(suite.hash);
            }
        }
        self.client_random = Some(ch.random);

        // PSK resumption (RFC 8446 §4.2.11): the binder is verified over the
        // transcript preceding this ClientHello — empty on a first hello,
        // `message_hash(CH1) ‖ HelloRetryRequest` after any HRR (§4.2.11.2),
        // which the transcript now holds. A binder mismatch is fatal.
        let binder_prefix = self.transcript.buffered_bytes().to_vec();
        let psk_state = self.accept_ticket_psk(&ch, &raw_ch, &binder_prefix)?;
        self.psk_used = psk_state.is_some();

        // 0-RTT: accept only when a PSK was taken, the client offered early
        // data, no HRR intervened (RFC 8446 §4.2.10), our policy is
        // non-zero, the ticket is age-fresh (§8.2) and from this address
        // (RFC 9147 §5.1 — the same condition that let us skip the cookie),
        // and the negotiated suite is exactly the ticket's (the early keys
        // are derived under it, §4.6.1).
        let client_offered_early = ext::find(&ch.extensions, ExtensionType::EARLY_DATA).is_some();
        self.early_data_offered = client_offered_early;
        let mut accept_early = client_offered_early
            && plan_was_fresh
            && self.config.max_early_data_size > 0
            && psk_state
                .as_ref()
                .is_some_and(|s| s.age_fresh && s.same_address && s.suite == Some(suite.suite));
        // Anti-replay (RFC 8446 §8): key the window on the *selected*
        // binder, not identity 0 — an attacker could otherwise park junk at
        // index 0 and vary it to replay a victim's early data at a later
        // index. A repeat refuses 0-RTT but still resumes (1-RTT).
        #[cfg(feature = "std")]
        if accept_early
            && let Some(window) = self.config.replay_window.as_ref()
            && let Some(s) = psk_state.as_ref()
            && !window.check_and_insert(&s.selected_binder)
        {
            accept_early = false;
        }
        // Anti-replay floor: never accept undefended 0-RTT. The §8.2
        // freshness window is real here (a clock is required to accept a
        // ticket at all), so it always provides a bound; a `ReplayWindow`
        // tightens it. (This mirrors the TLS 1.3 server, where the freshness
        // check can be skipped on a clock-less build; the DTLS servers never
        // reach this without a clock.)
        if accept_early {
            let ticket_alpn = psk_state.as_ref().expect("psk_state set").alpn.as_slice();
            if ticket_alpn != alpn_pick.as_deref().unwrap_or(&[]) {
                // RFC 8446 §4.2.10: 0-RTT needs the same ALPN as the issuing
                // connection. A mismatch refuses early data, not resumption.
                accept_early = false;
            }
        }

        // CH2 (or first-and-only CH when cookies are off) into the
        // transcript (TLS-shaped).
        self.transcript.update(&raw_ch);

        // Carry the issuing handshake's client identity forward (for the
        // ticket this connection may issue) — the DTLS servers do not yet
        // authenticate clients, so this is only ever set by resumption.
        if let Some(s) = psk_state.as_ref() {
            self.resumed_client_leaf = s.client_leaf.clone();
            self.resumed_client_auth_secs = Some(s.client_auth_secs);
        }

        // Initialise the reassembler at msg_seq+1.
        let mut reasm = Reassembler::new();
        for s in 0..=msg_seq {
            let mut buf = Vec::new();
            write_message(&mut buf, hs_type::CLIENT_HELLO, s, b"", 0);
            let f = read_fragment(&buf)?;
            let _ = reasm.feed(f);
        }
        self.reassembler = Some(reasm);
        self.server_random = Some(sr);
        self.alpn_negotiated = alpn_pick;
        // The spare receive CIDs come from the connection's RNG now, so no
        // entropy is needed later (RFC 9147 §9 `NewConnectionId`).
        self.cid = cid_pick.map(|(local, peer)| {
            let pool = draw_cid_pool(&mut self.rng, local.len());
            CidState::negotiated(local, peer, pool)
        });

        // 0-RTT: derive `client_early_traffic_secret` over Hash(CH1) NOW,
        // before ServerHello enters the transcript, and install the epoch-1
        // read keys (RFC 9147 §6.1) so the early-data records that trail
        // CH1 decrypt. The early secret is under the ticket's PSK and the
        // `"dtls13"` prefix (RFC 9147 §5.9).
        if accept_early {
            let psk = &psk_state.as_ref().expect("psk_state set").psk;
            let early_ks = KeySchedule::with_psk_prefixed(LabelPrefix::Dtls13, suite.hash, psk);
            let th_ch = self.transcript.current_hash();
            let cets = early_ks.client_early_traffic_secret(th_ch.as_slice());
            if let Some(kl) = self.config.key_log.as_ref() {
                kl.log("CLIENT_EARLY_TRAFFIC_SECRET", &ch.random, cets.as_slice());
            }
            self.early_read = Some(ReadEpoch::new(suite, 1, &cets));
            self.early_data_remaining = self.config.max_early_data_size;
            self.early_data_accepted = true;
        }

        // ServerHello with the negotiated group's `key_share`; selects
        // DTLS 1.3 (`0xfefc`, RFC 9147 §5.3), answers the client's
        // `connection_id` offer with the CID this server receives under
        // (RFC 9146 §3), and echoes `pre_shared_key` with the selected
        // identity when resuming (RFC 8446 §4.2.11).
        let mut sh_extensions = alloc::vec![
            ext::server_key_share(selected_group, &server_pub),
            super::server_supported_versions_dtls13(),
        ];
        if let Some(cid) = self.cid.as_ref() {
            sh_extensions.push(connection_id_extension(cid.local()));
        }
        if let Some(s) = psk_state.as_ref() {
            sh_extensions.push(ext::server_pre_shared_key(s.selected_identity));
        }
        let sh_bytes = ServerHello {
            random: sr,
            // RFC 9147 §5: DTLS 1.3 has no middlebox-compatibility mode and
            // "DTLS servers MUST NOT echo the legacy_session_id value from
            // the client". A client holding a pre-1.3 session ID sends one
            // (§5.3 SHOULD) — the wolfSSL client does on resumption — and
            // aborts on a non-empty echo with illegal_parameter.
            session_id: Vec::new(),
            cipher_suite: suite.suite,
            extensions: sh_extensions,
        }
        .encode_dtls();
        self.transcript.update(&sh_bytes);

        // Send SH as plaintext DTLS record(s) (epoch 0).
        let sh_body = &sh_bytes[4..];
        let sh_msg_seq = self.out_msg_seq;
        self.out_msg_seq += 1;
        for frag in write_fragments(
            hs_type::SERVER_HELLO,
            sh_msg_seq,
            sh_body,
            self.max_fragment(),
        ) {
            self.emit_plaintext(frag)?;
        }

        // Derive handshake traffic secrets and install protected crypters.
        // A resumed handshake seeds the schedule with the ticket's PSK
        // instead of zeros (RFC 8446 §7.1).
        let mut ks = match psk_state.as_ref() {
            Some(s) => KeySchedule::with_psk_prefixed(LabelPrefix::Dtls13, suite.hash, &s.psk),
            None => KeySchedule::new_with(LabelPrefix::Dtls13, suite.hash),
        };
        ks.enter_handshake(&shared);
        // The (EC)DHE / KEM shared secret is absorbed into the key
        // schedule; scrub the heap copy (DTLS-L7).
        crate::tls::conn::wipe(&mut shared);
        let th = self.transcript.current_hash();
        let chts = ks.client_handshake_traffic_secret(th.as_slice());
        let shts = ks.server_handshake_traffic_secret(th.as_slice());
        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                &ch.random,
                chts.as_slice(),
            );
            kl.log(
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                &ch.random,
                shts.as_slice(),
            );
        }
        let w_crypter = RecordCrypter::new_with(
            LabelPrefix::Dtls13,
            suite.hash,
            suite.aead,
            suite.key_len,
            &shts,
        );
        self.write_crypter = Some(w_crypter);
        let sn_len = sn_key_len_for(suite.aead);
        self.write_sn_key = Some(derive_sn_key(suite.hash, &shts, sn_len));
        self.enc_write_epoch = 2;
        self.enc_write_seq = 0;
        self.read = Some(ReadEpoch::new(suite, 2, &chts));
        self.prev_read = None;
        self.prev_read_deadline = None;
        self.ks = Some(ks);
        self.client_hs_secret = Some(chts);
        self.server_hs_secret = Some(shts);

        // Build and emit the encrypted server flight. Under PSK resumption
        // (RFC 8446 §2.2) Certificate and CertificateVerify are omitted —
        // the PSK authenticates the server — and EncryptedExtensions
        // carries `early_data` when we accepted 0-RTT (§4.2.10).
        self.send_encrypted_extensions(self.early_data_accepted)?;
        if psk_state.is_none() {
            // RFC 8446 §4.3.2: the request follows EncryptedExtensions and
            // precedes Certificate. A resumed handshake requests no client
            // certificate: the ticket carries the identity the issuing
            // handshake authenticated.
            if self.config.client_auth.is_some() {
                self.send_certificate_request()?;
            }
            self.send_certificate()?;
            // CertificateVerify. For an external key, stash the signature
            // input and suspend; the caller signs and resumes via
            // `provide_signature`, after which the rest of the flight runs.
            // For an in-process key, sign inline and continue.
            if matches!(
                self.config.key,
                crate::tls::conn::ServerKey::External { .. }
            ) {
                let th = self.transcript.current_hash();
                let content = certificate_verify_content(true, th.as_slice());
                let scheme =
                    signature_scheme_for(&self.config.key).ok_or(Error::UnsupportedKeyType)?;
                self.pending_flight = Some(PendingFlight { scheme, content });
                self.state = State::AwaitingCertVerifySignature;
                return Ok(());
            }
            self.send_certificate_verify()?;
        }
        self.finish_server_flight()
    }

    /// Builds and emits the `CertificateVerify` from a negotiated `scheme` and
    /// the produced `signature` bytes.
    fn emit_certificate_verify(
        &mut self,
        scheme: SignatureScheme,
        sig_der: &[u8],
    ) -> Result<(), Error> {
        let mut body = Vec::new();
        body.extend_from_slice(&scheme.0.to_be_bytes());
        with_len_u16(&mut body, |b| b.extend_from_slice(sig_der));
        let mut tls_msg = Vec::with_capacity(4 + body.len());
        tls_msg.push(hs_type::CERTIFICATE_VERIFY);
        let n = body.len() as u32;
        tls_msg.push(((n >> 16) & 0xff) as u8);
        tls_msg.push(((n >> 8) & 0xff) as u8);
        tls_msg.push((n & 0xff) as u8);
        tls_msg.extend_from_slice(&body);
        self.transcript.update(&tls_msg);
        self.emit_encrypted_handshake(hs_type::CERTIFICATE_VERIFY, &body)
    }

    /// The server flight tail shared by the inline and external-signing paths:
    /// emits the server `Finished`, derives the 1-RTT application secrets, and
    /// stages the application crypters/SN keys for install at client Finished.
    /// Reads the suite, key schedule, and client random from `self`.
    fn finish_server_flight(&mut self) -> Result<(), Error> {
        self.send_finished()?;
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let sn_len = sn_key_len_for(suite.aead);
        let client_random = self.client_random;

        // Derive application traffic secrets (Hash(CH..server Finished))
        // and stash them for installation at client Finished.
        let (cats, sats, ems) = {
            let ks = self.ks.as_mut().expect("ks");
            ks.enter_master();
            let th_app = self.transcript.current_hash();
            let cats = ks.client_application_traffic_secret(th_app.as_slice());
            let sats = ks.server_application_traffic_secret(th_app.as_slice());
            let ems = ks.exporter_master_secret(th_app.as_slice());
            (cats, sats, ems)
        };
        if let (Some(kl), Some(cr)) = (self.config.key_log.as_ref(), client_random.as_ref()) {
            kl.log("CLIENT_TRAFFIC_SECRET_0", cr, cats.as_slice());
            kl.log("SERVER_TRAFFIC_SECRET_0", cr, sats.as_slice());
            kl.log("EXPORTER_SECRET", cr, ems.as_slice());
        }
        self.exporter_secret = Some(ems);
        self.pending_write_app_crypter = Some(RecordCrypter::new_with(
            LabelPrefix::Dtls13,
            suite.hash,
            suite.aead,
            suite.key_len,
            &sats,
        ));
        self.pending_read_app = Some(ReadEpoch::new(suite, 3, &cats));
        self.write_app_sn_key = Some(derive_sn_key(suite.hash, &sats, sn_len));
        self.client_app_secret = Some(cats);
        self.server_app_secret = Some(sats);

        // With a CertificateRequest out, the client's flight opens with its
        // Certificate (RFC 8446 §4.4.2); otherwise its Finished is next.
        self.state = if self.config.client_auth.is_some() {
            State::WaitClientCertificate
        } else {
            State::WaitClientFinished
        };
        Ok(())
    }

    /// Resumes a flight suspended for an external `CertificateVerify` signature:
    /// emits the CertificateVerify with the caller-supplied `signature`, then
    /// finishes the flight.
    pub(crate) fn provide_signature(&mut self, signature: Vec<u8>) -> Result<(), Error> {
        let pf = self
            .pending_flight
            .take()
            .ok_or(Error::InappropriateState)?;
        self.emit_certificate_verify(pf.scheme, &signature)?;
        self.finish_server_flight()
    }

    /// If suspended awaiting an external signature, returns the IANA scheme code
    /// point and the bytes to sign.
    pub(crate) fn pending_signature(&self) -> Option<(u16, Vec<u8>)> {
        self.pending_flight
            .as_ref()
            .map(|pf| (pf.scheme.0, pf.content.clone()))
    }

    fn send_encrypted_extensions(&mut self, early_accepted: bool) -> Result<(), Error> {
        // EE body: extensions length (u16), carrying the selected ALPN
        // protocol (RFC 7301 §3.1 / RFC 8446 §4.3.1) when one was
        // negotiated, and an empty `early_data` (§4.2.10) when we accepted
        // the client's 0-RTT.
        let mut body = Vec::new();
        let alpn = self.alpn_negotiated.clone();
        with_len_u16(&mut body, |list| {
            if let Some(proto) = &alpn {
                let (ty, ext_body) = ext::alpn_protocols(&[proto.as_slice()]);
                put_u16(list, ty.0);
                with_len_u16(list, |b| b.extend_from_slice(&ext_body));
            }
            if early_accepted {
                let (ty, _) = ext::early_data_empty();
                put_u16(list, ty.0);
                with_len_u16(list, |_| {});
            }
        });
        let mut tls_msg = Vec::with_capacity(4 + body.len());
        tls_msg.push(hs_type::ENCRYPTED_EXTENSIONS);
        let n = body.len() as u32;
        tls_msg.push(((n >> 16) & 0xff) as u8);
        tls_msg.push(((n >> 8) & 0xff) as u8);
        tls_msg.push((n & 0xff) as u8);
        tls_msg.extend_from_slice(&body);
        self.transcript.update(&tls_msg);
        self.emit_encrypted_handshake(hs_type::ENCRYPTED_EXTENSIONS, &body)?;
        Ok(())
    }

    fn send_certificate(&mut self) -> Result<(), Error> {
        let mut body = Vec::new();
        body.push(0); // certificate_request_context: empty
        with_len_u24(&mut body, |list| {
            for cert in &self.config.cert_chain {
                with_len_u24(list, |c| c.extend_from_slice(cert));
                with_len_u16(list, |_| {}); // per-cert extensions
            }
        });
        let mut tls_msg = Vec::with_capacity(4 + body.len());
        tls_msg.push(hs_type::CERTIFICATE);
        let n = body.len() as u32;
        tls_msg.push(((n >> 16) & 0xff) as u8);
        tls_msg.push(((n >> 8) & 0xff) as u8);
        tls_msg.push((n & 0xff) as u8);
        tls_msg.extend_from_slice(&body);
        self.transcript.update(&tls_msg);
        self.emit_encrypted_handshake(hs_type::CERTIFICATE, &body)?;
        Ok(())
    }

    fn send_certificate_verify(&mut self) -> Result<(), Error> {
        let th = self.transcript.current_hash();
        let content = certificate_verify_content(true, th.as_slice());
        let (scheme, sig_der) = sign_certificate_verify(&self.config.key, &content, &mut self.rng)?;
        self.emit_certificate_verify(scheme, &sig_der)
    }

    fn send_finished(&mut self) -> Result<(), Error> {
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let shts = self
            .server_hs_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let th = self.transcript.current_hash();
        let verify_data =
            finished_verify_data_with(LabelPrefix::Dtls13, suite.hash, shts, th.as_slice());
        let body = verify_data.as_slice().to_vec();
        let mut tls_msg = Vec::with_capacity(4 + body.len());
        tls_msg.push(hs_type::FINISHED);
        let n = body.len() as u32;
        tls_msg.push(((n >> 16) & 0xff) as u8);
        tls_msg.push(((n >> 8) & 0xff) as u8);
        tls_msg.push((n & 0xff) as u8);
        tls_msg.extend_from_slice(&body);
        self.transcript.update(&tls_msg);
        self.emit_encrypted_handshake(hs_type::FINISHED, &body)?;
        Ok(())
    }

    /// RFC 8446 §4.3.2: emits a `CertificateRequest` with an empty
    /// `certificate_request_context` (handshake authentication) and the
    /// `signature_algorithms` a client `CertificateVerify` may use — the
    /// same list the TLS 1.3 server sends, which
    /// [`Self::on_client_cert_verify`] enforces.
    fn send_certificate_request(&mut self) -> Result<(), Error> {
        let mut body = Vec::new();
        body.push(0); // certificate_request_context: empty
        with_len_u16(&mut body, |exts| {
            let (ty, ext_body) = ext::signature_algorithms();
            put_u16(exts, ty.0);
            with_len_u16(exts, |b| b.extend_from_slice(&ext_body));
        });
        let mut tls_msg = Vec::with_capacity(4 + body.len());
        tls_msg.push(hs_type::CERTIFICATE_REQUEST);
        let n = body.len() as u32;
        tls_msg.push(((n >> 16) & 0xff) as u8);
        tls_msg.push(((n >> 8) & 0xff) as u8);
        tls_msg.push((n & 0xff) as u8);
        tls_msg.extend_from_slice(&body);
        self.transcript.update(&tls_msg);
        self.emit_encrypted_handshake(hs_type::CERTIFICATE_REQUEST, &body)
    }

    /// The client's `Certificate` answering our `CertificateRequest`
    /// (RFC 8446 §4.4.2). An empty chain is "no certificate": admitted when
    /// the policy does not require one (its Finished follows directly),
    /// `certificate_required` otherwise (§4.4.2.4). A chain is verified
    /// against the policy's roots for client authentication, and its
    /// `CertificateVerify` must follow (§4.4.3).
    ///
    /// The record was AEAD-authenticated under the handshake keys, so every
    /// rejection here is a genuine peer fault and fatal — mirroring the TLS
    /// 1.3 server, whose logic this is.
    fn on_client_certificate(
        &mut self,
        msg_type: u8,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), Error> {
        if msg_type != hs_type::CERTIFICATE {
            return Err(Error::UnexpectedMessage);
        }
        let chain = crate::tls::conn::parse_certificate_list_server(body)?;
        let policy = self
            .config
            .client_auth
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        if chain.is_empty() {
            if policy.required {
                return Err(Error::CertificateRequired);
            }
            self.transcript.update(raw);
            self.client_cert_chain.clear();
            self.client_leaf_key = None;
            self.state = State::WaitClientFinished;
            return Ok(());
        }
        // Chain validation for `ChainPurpose::Client` (`id-kp-clientAuth`),
        // under the server's signature policy, at the configured clock or
        // the system's — and fail closed with neither.
        let leaf_key = crate::tls::pki::verify_client_chain(
            &policy.roots,
            &self.config.crls,
            &chain,
            self.config.verification_time.as_ref(),
            &self.config.signature_policy,
        )?;
        self.transcript.update(raw);
        self.client_cert_chain = chain;
        self.client_leaf_key = Some(leaf_key);
        self.state = State::WaitClientCertVerify;
        Ok(())
    }

    /// The client's `CertificateVerify` (RFC 8446 §4.4.3): a signature, in
    /// the client context, over the transcript through its Certificate,
    /// under the leaf key [`Self::on_client_certificate`] verified. The
    /// scheme must be one our `CertificateRequest` offered and must not be
    /// `rsa_pkcs1_*` (chain signatures only in TLS 1.3).
    fn on_client_cert_verify(
        &mut self,
        msg_type: u8,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), Error> {
        if msg_type != hs_type::CERTIFICATE_VERIFY {
            return Err(Error::UnexpectedMessage);
        }
        let mut c = ReadCursor::new(body);
        let scheme = SignatureScheme(c.u16()?);
        let signature = c.vec_u16()?.to_vec();
        c.expect_empty()?;
        if scheme.is_rsa_pkcs1() || !ext::offered_signature_schemes().contains(&scheme) {
            return Err(Error::IllegalParameter);
        }
        let th = self.transcript.current_hash();
        let content = certificate_verify_content(false, th.as_slice());
        let leaf_key = self
            .client_leaf_key
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        verify_signature(
            scheme,
            leaf_key,
            &content,
            &signature,
            &self.config.signature_policy,
        )?;
        self.transcript.update(raw);
        self.state = State::WaitClientFinished;
        Ok(())
    }

    fn on_client_finished(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::FINISHED {
            return Err(Error::UnexpectedMessage);
        }
        // Defence in depth (RFC 8446 §4.4.2.4): with client authentication
        // required, a verified client key must exist before the connection
        // is accepted. The state machine already guarantees it (an empty
        // Certificate is refused, a chain must be followed by a verified
        // CertificateVerify); re-check so no later change to it can let a
        // required-certificate handshake reach `Connected` anonymously.
        if self.config.client_auth.as_ref().is_some_and(|p| p.required)
            && self.client_leaf_key.is_none()
        {
            return Err(Error::CertificateRequired);
        }
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let chts = self
            .client_hs_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let th = self.transcript.current_hash();
        let expected =
            finished_verify_data_with(LabelPrefix::Dtls13, suite.hash, chts, th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.transcript.update(raw);

        // `resumption_master_secret` over Hash(CH..client Finished) (RFC
        // 8446 §7.1): seeds the PSK of every ticket this connection issues.
        // Taken before the transcript is sealed below.
        if let Some(ks) = self.ks.as_ref() {
            let th_rms = self.transcript.current_hash();
            self.rms = Some(ks.resumption_master_secret(th_rms.as_slice()));
        }
        // The 0-RTT window is over: no more epoch-1 records (RFC 9147 §5.6).
        self.early_read = None;

        // Install application keys atomically. The epoch-2 read keys are
        // retired, not dropped (RFC 9147 §5.8.3 / §8): if our ACK for this
        // Finished is lost, the client retransmits it under epoch 2, and
        // that copy must still decrypt so we can re-ACK it — otherwise the
        // client keeps retransmitting until its budget is spent (DTLS-I3).
        // The reassembler recognises the duplicate `message_seq` and drops
        // it; only the ACK matters.
        self.write_crypter = self.pending_write_app_crypter.take();
        self.write_sn_key = self.write_app_sn_key.take();
        self.enc_write_epoch = 3;
        self.enc_write_seq = 0;
        let app_read = self.pending_read_app.take();
        self.prev_read = core::mem::replace(&mut self.read, app_read);
        self.arm_prev_read_expiry();
        // RFC 9147 §7.1: the client's Finished is the responding flight to
        // our entire server flight — everything we sent is implicitly
        // acknowledged. Drop the in-flight set and disarm the retransmit
        // timer; the server sends no further handshake flights, so leaving
        // anything armed here would re-emit stale records on every backoff
        // step and then GiveUp-close the established connection.
        self.retransmit = Retransmit13::new();
        self.state = State::Connected;

        // RFC 8446 §4.6.1 / RFC 9147 §5.8.4: with a ticket key configured,
        // issue one NewSessionTicket now, as a post-handshake flight under
        // the application keys — tracked by the retransmit machine so it is
        // resent until the client ACKs it (§7). It rides out in the same
        // drain as our ACK of the client's Finished.
        if self.tickets_available() {
            self.emit_session_ticket()?;
        }
        Ok(())
    }

    /// Emits one NewSessionTicket (RFC 8446 §4.6.1) under the application
    /// keys: `nonce ‖ AES-256-GCM(seal_key, nonce, plaintext)`, the
    /// plaintext carrying the resumption PSK, the negotiated suite, the
    /// issuing ALPN, this connection's transport address (so the resumed
    /// handshake may skip the cookie, RFC 9147 §5.1) and — once the DTLS
    /// servers authenticate clients — the client identity. Sealed under the
    /// DTLS 1.3 associated data, so a TLS listener sharing the key cannot
    /// open it, and the PSK is expanded under the `"dtls13"` prefix.
    fn emit_session_ticket(&mut self) -> Result<(), Error> {
        let key = self.ticket_seal_key().ok_or(Error::InappropriateState)?;
        let Some(creation) = self.ticket_now() else {
            return Ok(());
        };
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let rms = self.rms.clone().ok_or(Error::InappropriateState)?;

        let mut ticket_nonce = [0u8; 4];
        self.rng.fill_bytes(&mut ticket_nonce);
        let hash_len = suite.hash.output_len();
        let mut psk = crate::zeroize::Zeroizing::new(alloc::vec![0u8; hash_len]);
        psk_from_resumption_with(
            LabelPrefix::Dtls13,
            suite.hash,
            &rms,
            &ticket_nonce,
            &mut psk,
        );

        let mut age_add_bytes = [0u8; 4];
        self.rng.fill_bytes(&mut age_add_bytes);
        let ticket_age_add = u32::from_be_bytes(age_add_bytes);

        // A chain of resumptions keeps expiring `ticket_lifetime` after the
        // one real verification (the TLS 1.3 audit finding): carry the
        // recorded authentication time forward rather than re-stamping it.
        let client_auth_secs = self.resumed_client_auth_secs.unwrap_or(creation);
        let plain = TicketPlaintext {
            psk,
            alpn: self.alpn_negotiated.clone().unwrap_or_default(),
            creation_secs: creation,
            age_add: ticket_age_add,
            suite: Some(suite.suite),
            client_leaf: self.resumed_client_leaf.clone(),
            client_auth_secs,
            // RFC 9147 §5.1: bind the ticket to the address it was issued
            // to (empty means the server never learned it — no cookie skip).
            peer_addr: (!self.peer_addr.is_empty()).then(|| self.peer_addr.clone()),
        };
        let ticket = seal_ticket13(&mut self.rng, &key, TICKET_DTLS13_AAD, &plain);
        drop(plain);

        let mut extensions = Vec::new();
        if self.config.max_early_data_size > 0 {
            extensions.push(ext::early_data_with_size(self.config.max_early_data_size));
        }
        let nst = NewSessionTicket {
            ticket_lifetime: self.config.ticket_lifetime,
            ticket_age_add,
            ticket_nonce: ticket_nonce.to_vec(),
            ticket,
            extensions,
        };
        // A post-handshake message is not part of any transcript hash (RFC
        // 8446 §4.6.1); it is fragmented and tracked like any handshake
        // record under the current (application) epoch.
        let encoded = nst.encode();
        self.emit_encrypted_handshake(hs_type::NEW_SESSION_TICKET, &encoded[4..])
    }

    /// Builds the on-wire HRR bytes (4-byte TLS handshake header + body).
    /// When present, `cookie` is the raw cookie payload (no length prefix)
    /// and emits the `cookie` extension; when present, `group` emits the
    /// `key_share(selected_group)` extension (RFC 8446 §4.2.8.1). Uses the
    /// suite pinned during CH1 processing — HRR commits to a single suite
    /// (RFC 8446 §4.1.4).
    fn build_hrr_bytes(&self, cookie: Option<&[u8]>, group: Option<NamedGroup>) -> Vec<u8> {
        // HRR is only emitted after `self.suite` is pinned during CH1
        // processing; fall back to the highest-preference suite if (somehow)
        // not set — this keeps the call total without taking a Result.
        let suite_id = self
            .suite
            .map(|s| s.suite)
            .unwrap_or_else(|| supported_suites()[0].suite);
        Self::build_hrr_bytes_explicit(suite_id, cookie, group)
    }

    /// Variant of [`Self::build_hrr_bytes`] that takes the suite explicitly,
    /// without reading `self.suite`. Used by the cookie-required CH1 path,
    /// which has not yet pinned `self.suite` and instead carries the suite
    /// inside the cookie's aux payload (DTLS-2: no per-connection state
    /// pinned before cookie validates).
    fn build_hrr_bytes_explicit(
        suite_id: CipherSuite,
        cookie: Option<&[u8]>,
        group: Option<NamedGroup>,
    ) -> Vec<u8> {
        // RFC 9147 §5.3: the HRR selects DTLS 1.3 (`0xfefc`).
        let mut extensions = alloc::vec![super::server_supported_versions_dtls13(),];
        if let Some(g) = group {
            // HRR `key_share` body is just a u16 selected_group.
            let mut body = Vec::with_capacity(2);
            put_u16(&mut body, g.0);
            extensions.push((ExtensionType::KEY_SHARE, body));
        }
        if let Some(c) = cookie {
            // `opaque cookie<1..2^16-1>` → 2-byte u16 length prefix.
            let mut v = Vec::with_capacity(2 + c.len());
            v.extend_from_slice(&(c.len() as u16).to_be_bytes());
            v.extend_from_slice(c);
            extensions.push((ExtensionType(EXT_COOKIE), v));
        }
        ServerHello {
            random: HRR_RANDOM,
            session_id: Vec::new(),
            cipher_suite: suite_id,
            extensions,
        }
        .encode_dtls()
    }

    fn emit_hello_retry_request(&mut self, cookie: Option<&[u8]>) -> Result<(), Error> {
        let bytes = self.build_hrr_bytes(cookie, self.hrr_selected_group);
        let body = &bytes[4..];
        // HRR is a ServerHello with the magic random; msg_seq=0 (this is
        // the server's first outbound handshake message).
        for frag in write_fragments(hs_type::SERVER_HELLO, 0, body, self.max_fragment()) {
            let dgram = self.wrap_plain_record(ContentType::Handshake, &frag)?;
            // HRR is plaintext — push directly. We don't track it in the
            // retransmit machine since we'll drop all state if no CH2
            // arrives.
            self.out_dgrams.push(dgram);
        }
        Ok(())
    }

    /// Stateless variant of [`Self::emit_hello_retry_request`] used by the
    /// cookie-required CH1 path. Builds the HRR from the explicit
    /// (`suite_id`, `group`) so we don't have to pin them on `self`
    /// pre-validation, and emits as DTLS plaintext at message_seq=0. Does
    /// not advance `self.out_msg_seq`: the next CH (CH2) will re-enter the
    /// pre-state path, at which point cookie validation succeeds and the
    /// real handshake state is bootstrapped from the cookie's aux payload.
    fn emit_hrr_stateless(
        &mut self,
        suite_id: CipherSuite,
        cookie: &[u8],
        group: Option<NamedGroup>,
    ) -> Result<(), Error> {
        let bytes = Self::build_hrr_bytes_explicit(suite_id, Some(cookie), group);
        let body = &bytes[4..];
        for frag in write_fragments(hs_type::SERVER_HELLO, 0, body, self.max_fragment()) {
            let dgram = self.wrap_plain_record(ContentType::Handshake, &frag)?;
            self.out_dgrams.push(dgram);
        }
        Ok(())
    }

    fn wrap_plain_record(&mut self, ct: ContentType, fragment: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        record::write_record(
            &mut out,
            ct,
            ProtocolVersion::DTLSv1_2,
            self.plain_write_epoch,
            self.plain_write_seq,
            fragment,
        )?;
        self.plain_write_seq += 1;
        Ok(out)
    }

    fn encrypt_protected_record(
        &mut self,
        ct: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let crypter = self
            .write_crypter
            .as_mut()
            .ok_or(Error::InappropriateState)?;
        let sn_key = self
            .write_sn_key
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let epoch = self.enc_write_epoch;
        let seq = self.enc_write_seq;
        let cid = self.cid.as_ref().map_or(&[][..], CidState::peer);
        let wire =
            encrypt_protected_record_with(suite, crypter, sn_key, epoch, seq, cid, ct, payload)?;
        self.enc_write_seq += 1;
        Ok(wire)
    }

    /// Frames `fragment` as a plaintext (epoch 0) handshake record, sends
    /// it and registers it with the retransmit machine.
    fn emit_plaintext(&mut self, fragment: Vec<u8>) -> Result<(), Error> {
        let datagram = self.wrap_plain_record(ContentType::Handshake, &fragment)?;
        let record_number = RecordNumber {
            epoch: self.plain_write_epoch as u64,
            seq: self.plain_write_seq.saturating_sub(1),
        };
        self.out_dgrams.push(datagram);
        self.retransmit.on_record_sent(
            InFlightRecord::new(record_number, self.plain_write_epoch, fragment),
            self.last_now,
        );
        Ok(())
    }

    /// Re-frames every in-flight handshake record under a FRESH record
    /// number — plaintext for epoch 0, re-encrypted under the current write
    /// keys otherwise — and registers the new number so the client's ACK
    /// for this copy releases the record (RFC 9147 §4.5.3 / §7; DTLS-L3).
    /// The server's in-flight set is cleared at the client's Finished, so
    /// it never holds records of a retired epoch.
    fn retransmit_in_flight(&mut self) {
        for i in 0..self.retransmit.in_flight().len() {
            let (epoch, fragment) = {
                let r = &self.retransmit.in_flight()[i];
                (r.epoch, r.fragment.clone())
            };
            let framed = if epoch == self.plain_write_epoch {
                self.wrap_plain_record(ContentType::Handshake, &fragment)
                    .map(|dg| {
                        let rn = RecordNumber {
                            epoch: epoch as u64,
                            seq: self.plain_write_seq.saturating_sub(1),
                        };
                        (dg, rn)
                    })
            } else if epoch == self.enc_write_epoch {
                self.encrypt_protected_record(ContentType::Handshake, &fragment)
                    .map(|dg| {
                        let rn = RecordNumber {
                            epoch: epoch as u64,
                            seq: self.enc_write_seq.saturating_sub(1),
                        };
                        (dg, rn)
                    })
            } else {
                Err(Error::InappropriateState)
            };
            if let Ok((dg, rn)) = framed {
                self.out_dgrams.push(dg);
                self.retransmit.note_resent(i, rn);
            }
        }
    }

    /// Fragments the handshake message `msg_type` / `body` to the
    /// configured record ceiling and emits every fragment as its own
    /// encrypted record (RFC 9147 §4.4: a Certificate spans many
    /// datagrams). Each record is pushed to the outbound queue AND
    /// registered individually with the ACK-driven retransmit machine.
    fn emit_encrypted_handshake(&mut self, msg_type: u8, body: &[u8]) -> Result<(), Error> {
        let msg_seq = self.out_msg_seq;
        self.out_msg_seq += 1;
        for frag in write_fragments(msg_type, msg_seq, body, self.max_fragment()) {
            let dg = self.encrypt_protected_record(ContentType::Handshake, &frag)?;
            let record_number = RecordNumber {
                epoch: self.enc_write_epoch as u64,
                seq: self.enc_write_seq.saturating_sub(1),
            };
            self.out_dgrams.push(dg);
            self.retransmit.on_record_sent(
                InFlightRecord::new(record_number, self.enc_write_epoch, frag),
                self.last_now,
            );
        }
        Ok(())
    }

    fn flush_pending_acks(&mut self) {
        if self.pending_acks.is_empty() {
            return;
        }
        if self.write_crypter.is_none() {
            return;
        }
        let acks = core::mem::take(&mut self.pending_acks);
        // Chunked so every ACK record stays within `max_record_size` (a
        // fragmented multi-KB flight is dozens of record numbers), which
        // also keeps each body's `u16` length prefix exact.
        let per_ack = super::ack::entries_per_record(self.config.max_record_size);
        for body in super::ack::encode_with_limit(&acks, per_ack) {
            if let Ok(dg) =
                self.encrypt_protected_record(ContentType::Unknown(ACK_CONTENT_TYPE), &body)
            {
                self.out_dgrams.push(dg);
            }
        }
    }

    /// Test-only: queues a raw 2-byte alert (`level ‖ description`) under
    /// the current protected write key, so loopback tests can exercise the
    /// peer's authenticated-alert path without widening the public API.
    #[cfg(test)]
    pub(crate) fn send_alert_record_for_test(&mut self, level: u8, description: u8) {
        let dg = self
            .encrypt_protected_record(ContentType::Alert, &[level, description])
            .expect("protected write keys installed");
        self.out_dgrams.push(dg);
    }

    /// Test-only: queues application data under the CURRENT protected write
    /// key whatever the epoch, so tests can exercise a peer's handling of
    /// application data protected with the handshake keys (which this
    /// engine's `send` refuses to produce).
    #[cfg(test)]
    pub(crate) fn send_app_data_for_test(&mut self, data: &[u8]) {
        let dg = self
            .encrypt_protected_record(ContentType::ApplicationData, data)
            .expect("protected write keys installed");
        self.out_dgrams.push(dg);
    }

    /// Test-only: sends an arbitrary handshake message (`msg_type` + body)
    /// under the current protected write key and tracks it for
    /// retransmission, so tests can exercise the peer's post-handshake
    /// dispatch with messages this engine never emits itself.
    #[cfg(test)]
    pub(crate) fn send_handshake_for_test(&mut self, msg_type: u8, body: &[u8]) {
        self.emit_encrypted_handshake(msg_type, body)
            .expect("protected write keys installed");
    }

    /// Test-only: hands a reassembled handshake message straight to the
    /// state machine, as if it had arrived authenticated at the expected
    /// `message_seq`, so tests can present the client messages a conforming
    /// client never sends (a Finished in place of a CertificateVerify, a
    /// CertificateVerify under a scheme that was not offered).
    #[cfg(test)]
    pub(crate) fn dispatch_handshake_for_test(
        &mut self,
        msg_type: u8,
        body: &[u8],
    ) -> Result<(), Error> {
        self.dispatch_one(msg_type, body)
    }

    /// Test-only: like `send_handshake_for_test` but the message is framed
    /// at the NEXT `message_seq` without consuming it, and is not tracked
    /// for retransmission. A later genuine message then reuses the same
    /// sequence number, which lets a test confirm the peer never fed this
    /// copy to its reassembler (e.g. one sent under the handshake epoch
    /// after the peer connected).
    #[cfg(test)]
    pub(crate) fn send_handshake_untracked_for_test(&mut self, msg_type: u8, body: &[u8]) {
        let mut frags = write_fragments(msg_type, self.out_msg_seq, body, self.max_fragment());
        assert_eq!(frags.len(), 1, "test message must fit one fragment");
        let frag = frags.remove(0);
        let dg = self
            .encrypt_protected_record(ContentType::Handshake, &frag)
            .expect("protected write keys installed");
        self.out_dgrams.push(dg);
    }

    /// Generates the server-side ephemeral share and derives the
    /// ECDHE/KEM shared secret for the negotiated group. Returns
    /// `(server_public_key, shared_secret_bytes)` in the wire shapes used
    /// by RFC 8446 §4.2.8 / draft-ietf-tls-ecdhe-mlkem §3.
    fn key_agreement(
        &mut self,
        group: NamedGroup,
        client_pub: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match group {
            NamedGroup::X25519 => {
                let sk = X25519PrivateKey::generate(&mut self.rng);
                let peer: [u8; 32] = client_pub.try_into().map_err(|_| Error::Decode)?;
                // RFC 7748 §6.1 / RFC 8446 §7.4.2: reject all-zero output.
                let mut ss = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::IllegalParameter)?;
                let pk = sk.public_key().to_vec();
                self.x25519 = Some(sk);
                let out = ss.to_vec();
                crate::tls::conn::wipe(&mut ss);
                Ok((pk, out))
            }
            NamedGroup::SECP256R1 => {
                let sk = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut self.rng);
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, client_pub)
                    .map_err(|_| Error::Decode)?;
                let ss = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?;
                Ok((sk.public_key().to_sec1(), ss))
            }
            NamedGroup::SECP384R1 => {
                let sk = BoxedEcdhPrivateKey::generate(CurveId::P384, &mut self.rng);
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P384, client_pub)
                    .map_err(|_| Error::Decode)?;
                let ss = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?;
                Ok((sk.public_key().to_sec1(), ss))
            }
            NamedGroup::X25519MLKEM768 => {
                // Client share: ML-KEM-768 encapsulation key (1184) ‖ X25519 (32).
                if client_pub.len() != ENCAPS_KEY_BYTES + 32 {
                    return Err(Error::Decode);
                }
                let mut ek = [0u8; ENCAPS_KEY_BYTES];
                ek.copy_from_slice(&client_pub[..ENCAPS_KEY_BYTES]);
                let peer: [u8; 32] = client_pub[ENCAPS_KEY_BYTES..]
                    .try_into()
                    .map_err(|_| Error::Decode)?;
                // FIPS 203 §7.2: validate the peer's encapsulation key
                // before any cryptographic operation on it.
                let validated_ek = MlKem768EncapsKey::from_bytes_validated(ek)
                    .map_err(|_| Error::IllegalParameter)?;
                let (ct, mut ml_ss) = validated_ek.encapsulate(&mut self.rng);
                let sk = X25519PrivateKey::generate(&mut self.rng);
                // RFC 8446 §7.4.2: reject all-zero X25519 contribution.
                let mut x_ss = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::IllegalParameter)?;
                // Server share: ML-KEM ciphertext ‖ X25519 key.
                let mut share = ct.to_bytes().to_vec();
                share.extend_from_slice(&sk.public_key());
                // Combined secret: ML-KEM shared secret first, then X25519.
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&ml_ss);
                combined.extend_from_slice(&x_ss);
                // Only the combined copy survives (the caller wipes it once
                // the key schedule has absorbed it); scrub the halves.
                crate::tls::conn::wipe(&mut ml_ss);
                crate::tls::conn::wipe(&mut x_ss);
                Ok((share, combined))
            }
            // secp521r1 and the NIST-curve hybrids (RFC 10024) are shared
            // with the TLS 1.3 engine; the caller wipes the copy it gets.
            NamedGroup::SECP521R1 => kex::ecdhe_server(CurveId::P521, &mut self.rng, client_pub)
                .map(|(share, s)| (share, s.as_slice().to_vec())),
            NamedGroup::SECP256R1MLKEM768 => kex::p256_mlkem768_server(&mut self.rng, client_pub)
                .map(|(share, s)| (share, s.as_slice().to_vec())),
            NamedGroup::SECP384R1MLKEM1024 => kex::p384_mlkem1024_server(&mut self.rng, client_pub)
                .map(|(share, s)| (share, s.as_slice().to_vec())),
            _ => Err(Error::HandshakeFailure),
        }
    }
}

/// Builds the canonical CH-content fingerprint that the cookie HMAC binds
/// to. Covers (cipher_suites, supported_groups, supported_versions) —
/// every CH field that drives algorithm choice. CH2 must reproduce these
/// byte-for-byte, otherwise cookie validation fails and the handshake
/// aborts (DTLS-5: cookie binds CH content).
///
/// `key_share` is deliberately NOT covered, not even the list of offered
/// groups: RFC 8446 §4.1.2 requires CH2 to replace the `key_share` list
/// with the single group the HelloRetryRequest selected, so with cookies
/// required AND a group change the legitimate CH2 can never reproduce
/// CH1's share list — it used to fail cookie validation for ever
/// (DTLS-L5). Negotiation is still pinned: `supported_groups` is covered,
/// and the group the HRR selected travels in the cookie's `aux` payload
/// and is enforced on CH2.
/// Wraps a DTLS-shaped ClientHello body in the 4-byte TLS handshake header
/// the transcript and the PSK binder hash over (RFC 9147 §5.2: the DTLS
/// fragment fields are excluded).
fn tls_client_hello(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(hs_type::CLIENT_HELLO);
    let n = body.len() as u32;
    out.push(((n >> 16) & 0xff) as u8);
    out.push(((n >> 8) & 0xff) as u8);
    out.push((n & 0xff) as u8);
    out.extend_from_slice(body);
    out
}

fn ch_fingerprint_dtls13(ch: &ClientHello) -> Vec<u8> {
    let mut cs_be = Vec::with_capacity(ch.cipher_suites.len() * 2);
    for cs in &ch.cipher_suites {
        cs_be.extend_from_slice(&cs.0.to_be_bytes());
    }
    let groups = ext::find(&ch.extensions, ExtensionType::SUPPORTED_GROUPS);
    let versions = ext::find(&ch.extensions, ExtensionType::SUPPORTED_VERSIONS);
    build_ch_fingerprint(&cs_be, groups, versions, &[])
}

/// Map [`HashAlg`] to its 1-byte aux tag. Compact, fixed, and reversible
/// via [`hash_alg_from_byte`].
fn hash_alg_to_byte(h: HashAlg) -> u8 {
    match h {
        HashAlg::Sha256 => 0,
        HashAlg::Sha384 => 1,
    }
}

/// Inverse of [`hash_alg_to_byte`]. `None` indicates a malformed cookie
/// payload — caller should reject as `IllegalParameter`.
fn hash_alg_from_byte(b: u8) -> Option<HashAlg> {
    match b {
        0 => Some(HashAlg::Sha256),
        1 => Some(HashAlg::Sha384),
        _ => None,
    }
}

/// Server-side group preference order, in descending preference. Mirrors
/// the TLS layer's preference at `src/tls/conn/server.rs:1106-1118`.
fn supported_server_groups() -> [NamedGroup; 7] {
    crate::tls::conn::DEFAULT_GROUPS
}

fn parse_supported_groups(body: &[u8]) -> Result<Vec<NamedGroup>, Error> {
    let mut outer = ReadCursor::new(body);
    let list = outer.vec_u16()?;
    outer.expect_empty()?;
    if list.len() % 2 != 0 {
        return Err(Error::Decode);
    }
    let mut c = ReadCursor::new(list);
    let mut out = Vec::with_capacity(list.len() / 2);
    while !c.is_empty() {
        out.push(NamedGroup(c.u16()?));
    }
    Ok(out)
}

#[cfg(test)]
mod f3_msg_seq_tests {
    //! F3 regression: the DTLS 1.3 server must reject a ClientHello whose
    //! plaintext, epoch-0 `message_seq` is implausibly large BEFORE seeding a
    //! reassembler from it. An attacker setting `message_seq = 0xFFFF` would
    //! otherwise force up to 65 535 allocate/serialize/parse/feed cycles on
    //! the unauthenticated, pre-cookie path. The rejection is a SILENT DROP
    //! (`feed_datagram` returns `Ok`): the input is trivially spoofable, so a
    //! fatal error would hand an off-path attacker a one-datagram kill switch
    //! for in-flight handshakes (RFC 9147 §4.5.2).
    use super::*;
    use crate::dtls::{DtlsClientConnection13, DtlsServerConnection13};
    use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::tls::pki::RootCertStore;
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    fn make_server_cfg() -> (ServerConfig13Internal, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"f3-dtls13-key", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let name = DistinguishedName::common_name("dtls.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            false,
            &["dtls.example"],
        )
        .unwrap();
        let der = cert.to_der().to_vec();
        (
            ServerConfig13Internal::with_ecdsa(alloc::vec![der.clone()], key).with_no_cookie(),
            der,
        )
    }

    fn make_client(server_cert: &[u8]) -> DtlsClientConnection13 {
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert.to_vec()).unwrap();
        let cfg = crate::dtls::ClientConfig13Internal::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        let mut crng = HmacDrbg::<Sha256>::new(b"f3-dtls13-client", b"nonce", &[]);
        DtlsClientConnection13::new(cfg, b"client-addr".to_vec(), &mut crng)
    }

    /// Capture a genuine first-flight ClientHello datagram from the real
    /// client. The first plaintext handshake record carries the CH.
    fn client_hello_datagram() -> Vec<u8> {
        let (_, cert) = make_server_cfg();
        let mut client = make_client(&cert);
        let mut out = client.pop_outbound_datagrams();
        out.remove(0)
    }

    fn new_server() -> DtlsServerConnection13<HmacDrbg<Sha256>> {
        let (cfg, _) = make_server_cfg();
        let srng = HmacDrbg::<Sha256>::new(b"f3-dtls13-server", b"nonce", &[]);
        DtlsServerConnection13::new(alloc::sync::Arc::new(cfg), b"client-addr".to_vec(), srng)
    }

    /// Patch the 16-bit `message_seq` of the first handshake fragment inside a
    /// plaintext DTLS record. Record header is 13 bytes; the handshake header
    /// `message_seq` field sits 4 bytes into the fragment (after msg_type[1] +
    /// length[3]).
    fn patch_message_seq(dgram: &mut [u8], seq: u16) {
        const MSG_SEQ_OFF: usize = 13 + 4;
        dgram[MSG_SEQ_OFF] = (seq >> 8) as u8;
        dgram[MSG_SEQ_OFF + 1] = seq as u8;
    }

    #[test]
    fn oversized_message_seq_is_silently_dropped_without_giant_loop() {
        let mut dgram = client_hello_datagram();
        // A legitimate first CH uses message_seq 0; force the maximum.
        patch_message_seq(&mut dgram, 0xFFFF);
        let mut server = new_server();
        // Spoofable epoch-0 input: dropped, never fatal.
        assert_eq!(server.feed_datagram(&dgram), Ok(()));
        // No server flight may have been emitted for the dropped CH.
        assert!(server.pop_outbound_datagrams().is_empty());
    }

    #[test]
    fn message_seq_just_above_cap_is_silently_dropped() {
        let mut dgram = client_hello_datagram();
        patch_message_seq(&mut dgram, MAX_HS_MSG_SEQ + 1);
        let mut server = new_server();
        assert_eq!(server.feed_datagram(&dgram), Ok(()));
        assert!(server.pop_outbound_datagrams().is_empty());
    }

    #[test]
    fn spoofed_complete_hello_does_not_wedge_pre_cookie_buffer() {
        // One spoofed record carrying two fragments of an undecodable
        // ClientHello at message_seq 0. Completing it used to advance the
        // pre-cookie buffer's expected_msg_seq to 1, so every fragment of
        // the genuine (fragmented, X25519MLKEM768) CH was dropped as stale.
        let (cfg, cert) = make_server_cfg();
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"f3-dtls13-ok", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(alloc::sync::Arc::new(cfg), b"client-addr".to_vec(), srng);
        let mut frags = Vec::new();
        frags.extend_from_slice(&[hs_type::CLIENT_HELLO, 0, 0, 10, 0, 0, 0, 0, 1, 0, 0, 9]);
        frags.extend_from_slice(&[0xAA; 9]);
        frags.extend_from_slice(&[hs_type::CLIENT_HELLO, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 1]);
        frags.push(0xAA);
        let mut dg = Vec::new();
        record::write_record(
            &mut dg,
            ContentType::Handshake,
            ProtocolVersion::DTLSv1_2,
            0,
            99,
            &frags,
        )
        .unwrap();
        assert_eq!(server.feed_datagram(&dg), Ok(()));
        let mut pending = client.pop_outbound_datagrams();
        assert!(pending.len() >= 2, "default CH should be fragmented");
        let mut t = 0u64;
        for _ in 0..40 {
            for d in &pending {
                server.feed_datagram(d).unwrap();
            }
            let s_out = server.pop_outbound_datagrams();
            for d in &s_out {
                let _ = client.feed_datagram(d);
            }
            pending = client.pop_outbound_datagrams();
            if server.is_handshake_complete() && client.is_handshake_complete() {
                break;
            }
            if pending.is_empty() && s_out.is_empty() {
                t += 70;
                client.on_timeout(core::time::Duration::from_secs(t));
                pending = client.pop_outbound_datagrams();
            }
        }
        assert!(server.is_handshake_complete());
        assert!(client.is_handshake_complete());
    }

    #[test]
    fn legitimate_message_seq_zero_is_accepted() {
        // Unmodified CH (message_seq = 0) must NOT trip the F3 guard; it
        // drives a normal handshake to completion.
        let (cfg, cert) = make_server_cfg();
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"f3-dtls13-ok", b"nonce", &[]);
        let mut server =
            DtlsServerConnection13::new(alloc::sync::Arc::new(cfg), b"client-addr".to_vec(), srng);
        for _ in 0..32 {
            let c_out = client.pop_outbound_datagrams();
            for dg in &c_out {
                server.feed_datagram(dg).unwrap();
            }
            let s_out = server.pop_outbound_datagrams();
            for dg in &s_out {
                client.feed_datagram(dg).unwrap();
            }
            if c_out.is_empty() && s_out.is_empty() {
                break;
            }
        }
        assert!(server.is_handshake_complete());
        assert!(client.is_handshake_complete());
    }
}
