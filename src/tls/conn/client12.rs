#![allow(dead_code, unreachable_pub)]

//! TLS 1.2 client state machine (RFC 5246 + RFC 5077) — ECDHE-AEAD.
//!
//! [`ClientConnection12`] drives a full 1-RTT TLS 1.2 client handshake using
//! the AEAD-ECDHE suites only:
//!
//! * `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` / `AES_256_GCM_SHA384` /
//!   `CHACHA20_POLY1305_SHA256`
//! * `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` / `AES_256_GCM_SHA384` /
//!   `CHACHA20_POLY1305_SHA256`
//!
//! The state machine is a separate type from [`super::client::ClientConnection`]
//! (TLS 1.3): the wire formats, key schedule (PRF vs HKDF), and record-protection
//! semantics (TLS 1.2 has no `TLSInnerPlaintext` byte and uses an explicit
//! 8-byte nonce per record) are different enough that sharing a single type
//! would obscure both paths.
//!
//! Supports mTLS via [`ClientConfig12::with_client_cert`] (sharing the same
//! [`ClientCertConfig`] type as the TLS 1.3 client) and RFC 5077 session
//! tickets via [`ClientConfig12::with_session`]. The abbreviated resumed
//! handshake (RFC 5077 §3.4) skips Certificate / SKE / SHDone on both sides.
//! Session resumption via the legacy `session_id` path is not implemented;
//! we send an empty session_id and never accept a non-empty echo.
//!
//! # Record-layer note
//!
//! The shared [`super::common::ConnectionCore`] hardcodes TLS 1.3 record
//! protection (AAD with `ApplicationData` outer + `TLSInnerPlaintext` byte).
//! Rather than parameterize it, we keep our own `inbuf`/`outbuf`/`hs_pending`
//! buffers and run record framing inline with a pair of
//! [`crate::tls::crypto::aead12::RecordCrypter12`] instances. This isolates
//! the two protocol paths cleanly.

use super::super::codec::{ParsedRecord, is_legal_record_version, read_record, write_record};
use super::client::{ClientCertConfig, ClientKey};
use crate::ct::ConstantTimeEq;
use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPublicKey, CurveId};
use crate::hash::{Sha256, Sha384, Sha512};
use crate::rng::RngCore;
use crate::signature_registry::SignaturePolicy;
use crate::tls::codec::extension as ext;
use crate::tls::codec::handshake12::{
    CertificateRequest12, ClientKeyExchange, NewSessionTicket12, ServerHelloDone,
    ServerKeyExchange, signed_message,
};
use crate::tls::codec::{
    CipherSuite, ClientHello, ExtensionType, NamedGroup, Random, ReadCursor, ServerHello, hs_type,
    read_handshake, with_len_u16, with_len_u24,
};
use crate::tls::crypto::HashAlg;
use crate::tls::crypto::aead12::RecordCrypter12;
use crate::tls::crypto::prf::{
    extended_master_secret, finished_verify_data, key_block, master_secret,
};
use crate::tls::crypto::{AeadAlg, Transcript, verify_signature};
use crate::tls::keylog::KeyLog;
use crate::tls::pki::{CrlStore, RootCertStore, verify_chain_with_crls, verify_hostname};
use crate::tls::{Alert, AlertDescription, ContentType, Error, ProtocolVersion};
use crate::x509::{AnyPublicKey, Certificate, Time};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Configuration for a TLS 1.2 client connection.
///
/// Parallels [`super::client::ClientConfig`], including mTLS
/// ([`ClientCertConfig`], shared with the TLS 1.3 path) and RFC 5077
/// session-ticket resumption ([`StoredSession12`]).
pub(crate) struct ClientConfig12 {
    /// Trust anchors used to authenticate the server certificate chain.
    pub roots: RootCertStore,
    /// When `false`, the certificate chain, validity period, and host name are
    /// not checked (the SKE signature is still verified against the presented
    /// leaf key, and a malformed leaf is still rejected). Intended for tests
    /// and pinned-key scenarios.
    pub verify_certificates: bool,
    /// The time used for validity-period checks. Defaults (`None`) to the
    /// system clock under the `std` feature; set it explicitly for `no_std`
    /// targets or for reproducible verification.
    pub verification_time: Option<Time>,
    /// ALPN protocols to offer (RFC 7301), in preference order. Empty
    /// suppresses the extension.
    pub alpn_protocols: Vec<Vec<u8>>,
    /// `record_size_limit` (RFC 8449) we advertise — the largest plaintext
    /// fragment the server may send us.
    pub record_size_limit: Option<u16>,
    /// Whitelist of signature algorithms the client accepts in chain
    /// signatures and in the server's `ServerKeyExchange` signature. Defaults
    /// to [`SignaturePolicy::modern`].
    pub signature_policy: SignaturePolicy,
    /// mTLS: client certificate + signing key, used to satisfy a server's
    /// `CertificateRequest` (RFC 5246 §7.4.4). `None` means we send an empty
    /// `Certificate` and skip `CertificateVerify`; the server then decides
    /// per its `with_client_auth(required)` policy whether to accept us.
    pub client_cert: Option<ClientCertConfig>,
    /// RFC 5077: a previously stored session to attempt resuming via the
    /// `session_ticket` extension. `None` advertises ticket support but
    /// presents no ticket (fresh full handshake).
    pub session: Option<StoredSession12>,
    /// RFC 7507: when `true`, prepend the `TLS_FALLBACK_SCSV` pseudo-suite
    /// (`0x5600`) to the offered cipher-suite list. Set this **only** when the
    /// caller is explicitly downgrading from a higher TLS version after a
    /// previous attempt failed — a fresh TLS 1.2 client must NOT send it, or
    /// 1.3-aware servers will (correctly) abort with `inappropriate_fallback`.
    /// Default `false`.
    pub send_fallback_scsv: bool,
    /// RFC 8446 §4.1.3 downgrade-sentinel acceptance. When `false` (default),
    /// the client aborts with `IllegalParameter` if the last 8 bytes of
    /// `server_random` are the 1.3-↓-1.2 or 1.1-↓-1.0 sentinels. Set to `true`
    /// **only** in a deliberate-fallback flow where the higher-version probe
    /// has already failed and the caller has chosen to accept the downgrade.
    pub accept_downgrade_sentinel: bool,
    /// CRLs consulted during chain validation. Empty by default — opt in via
    /// [`ClientConfig12::with_crls`].
    pub crls: CrlStore,
    /// Optional [`KeyLog`] sink (NSS `SSLKEYLOGFILE` format). When `Some`,
    /// the engine logs the derived `master_secret` keyed by the
    /// `client_random` (TLS 1.2 emits a single `CLIENT_RANDOM` line).
    pub key_log: Option<Arc<dyn KeyLog>>,
}

impl ClientConfig12 {
    /// A configuration trusting the given roots, with certificate verification
    /// enabled.
    pub fn new(roots: RootCertStore) -> Self {
        ClientConfig12 {
            roots,
            verify_certificates: true,
            verification_time: None,
            alpn_protocols: Vec::new(),
            record_size_limit: None,
            signature_policy: SignaturePolicy::modern(),
            client_cert: None,
            session: None,
            send_fallback_scsv: false,
            accept_downgrade_sentinel: false,
            crls: CrlStore::new(),
            key_log: None,
        }
    }

    /// Installs a [`CrlStore`] consulted during chain validation. The
    /// store is advisory: a covering CRL signed by an issuer in the chain
    /// rejects the cert; anything else is silently ignored.
    pub fn with_crls(mut self, crls: CrlStore) -> Self {
        self.crls = crls;
        self
    }

    /// Offers the given ALPN protocols (preference order).
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Advertises `record_size_limit = limit` (RFC 8449).
    pub fn with_record_size_limit(mut self, limit: u16) -> Self {
        self.record_size_limit = Some(limit);
        self
    }

    /// Replaces the signature-algorithm whitelist.
    pub fn with_signature_policy(mut self, policy: SignaturePolicy) -> Self {
        self.signature_policy = policy;
        self
    }

    /// Sets the verification clock (use this on `no_std` targets where the
    /// system clock is unavailable).
    pub fn with_verification_time(mut self, t: Time) -> Self {
        self.verification_time = Some(t);
        self
    }

    /// Sets the client certificate + signing key used to satisfy a server's
    /// `CertificateRequest` (mTLS, RFC 5246 §7.4.4). The same
    /// [`ClientCertConfig`] type is shared with the TLS 1.3 client.
    pub fn with_client_cert(mut self, cert: ClientCertConfig) -> Self {
        self.client_cert = Some(cert);
        self
    }

    /// Primes the next handshake to attempt RFC 5077 session resumption
    /// using `session`. If the server rejects the ticket (or its key has
    /// rotated), the client transparently falls back to a fresh handshake.
    pub fn with_session(mut self, session: StoredSession12) -> Self {
        self.session = Some(session);
        self
    }

    /// RFC 7507: enable/disable emitting `TLS_FALLBACK_SCSV` (`0x5600`).
    /// Default is `false`. Use this only when the caller has deliberately
    /// downgraded to TLS 1.2 after a prior higher-version attempt failed.
    pub fn with_fallback_scsv(mut self, enabled: bool) -> Self {
        self.send_fallback_scsv = enabled;
        self
    }

    /// RFC 8446 §4.1.3: when `true`, the client will accept a `server_random`
    /// whose last 8 bytes match the version-downgrade sentinel instead of
    /// aborting with `illegal_parameter`. Default is `false`.
    pub fn with_accept_downgrade_sentinel(mut self, enabled: bool) -> Self {
        self.accept_downgrade_sentinel = enabled;
        self
    }
}

/// RFC 8446 §4.1.3 downgrade sentinels — the final 8 bytes of `server_random`
/// a TLS 1.3-aware server sets to flag that it has downgraded the connection.
///
/// * `DOWNGRADE_SENTINEL_TLS12` — server downgraded from 1.3 to 1.2.
/// * `DOWNGRADE_SENTINEL_TLS11_OR_BELOW` — server downgraded from 1.3 to 1.1
///   / 1.0. We never accept those versions ourselves, but include the value so
///   the client can still detect and reject a misbehaving peer that returned
///   such a marker in a 1.2 SH.
pub(crate) const DOWNGRADE_SENTINEL_TLS12: [u8; 8] =
    [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
pub(crate) const DOWNGRADE_SENTINEL_TLS11_OR_BELOW: [u8; 8] =
    [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

/// RFC 7507 §4: the `TLS_FALLBACK_SCSV` pseudo-suite codepoint.
pub(crate) const TLS_FALLBACK_SCSV: u16 = 0x5600;

/// A resumable session for the TLS 1.2 client (RFC 5077). Persist this
/// across connections; pass it back via [`ClientConfig12::with_session`] to
/// attempt resumption.
#[derive(Clone, Debug)]
pub struct StoredSession12 {
    /// The opaque ticket bytes received in `NewSessionTicket`. We re-present
    /// these unchanged in the next ClientHello's `session_ticket` extension.
    pub ticket: Vec<u8>,
    /// The 48-byte master secret derived on the originating connection — the
    /// resumed handshake's PRF expands this into a fresh key block.
    pub master_secret: [u8; 48],
    /// The cipher-suite of the originating connection. The resumed handshake
    /// MUST pick this same suite.
    pub cipher_suite: u16,
    /// ALPN protocol negotiated on the originating connection, if any.
    pub alpn: Option<Vec<u8>>,
    /// Wall-clock time the NST arrived (for caller-side expiry). The server
    /// has its own expiry policy; both are advisory.
    pub received_at: Option<Time>,
    /// RFC 7627 §5.3 — whether the originating session used Extended Master
    /// Secret. Resumption MUST preserve this status: if `true`, the resumed
    /// handshake's `extended_master_secret` MUST be negotiated; if `false`,
    /// it MUST NOT. Cross-EMS resumption is rejected with
    /// `IllegalParameter`.
    pub ems_used: bool,
}

/// Whether the cipher-suite's signature half is RSA or ECDSA — drives which
/// server-cert key types are acceptable.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(super) enum SigKind {
    Rsa,
    Ecdsa,
}

/// Parameters of a single TLS 1.2 AEAD-ECDHE cipher suite.
#[derive(Copy, Clone)]
pub(super) struct SuiteParams12 {
    pub(super) suite: CipherSuite,
    pub(super) hash: HashAlg,
    pub(super) aead: AeadAlg,
    /// AEAD key length in bytes (16 for AES-128, 32 for AES-256/ChaCha20).
    pub(super) key_len: usize,
    /// Which signature family the server's cert key must belong to (`Rsa` for
    /// `TLS_ECDHE_RSA_*`, `Ecdsa` for `TLS_ECDHE_ECDSA_*`).
    pub(super) sig_kind: SigKind,
}

/// The TLS 1.2 AEAD-ECDHE suites we offer, in descending preference order.
///
/// Choice rationale:
/// - ECDSA suites first within each AEAD bucket: ECDSA certs are faster to
///   sign/verify and shorter on the wire than RSA, so an ECDHE-ECDSA path is
///   measurably cheaper end-to-end when both are available.
/// - AES-128-GCM ahead of ChaCha20 ahead of AES-256-GCM: AES-128 with AES-NI
///   is the dominant choice in modern stacks, ChaCha20 is the no-AES-NI
///   fallback, and AES-256 is rarely preferred when AES-128 satisfies the
///   security target.
pub(super) const SUITES_12: [SuiteParams12; 6] = [
    SuiteParams12 {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        hash: HashAlg::Sha256,
        aead: AeadAlg::Aes128Gcm,
        key_len: 16,
        sig_kind: SigKind::Ecdsa,
    },
    SuiteParams12 {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        hash: HashAlg::Sha256,
        aead: AeadAlg::Aes128Gcm,
        key_len: 16,
        sig_kind: SigKind::Rsa,
    },
    SuiteParams12 {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        hash: HashAlg::Sha256,
        aead: AeadAlg::ChaCha20Poly1305,
        key_len: 32,
        sig_kind: SigKind::Ecdsa,
    },
    SuiteParams12 {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        hash: HashAlg::Sha256,
        aead: AeadAlg::ChaCha20Poly1305,
        key_len: 32,
        sig_kind: SigKind::Rsa,
    },
    SuiteParams12 {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        hash: HashAlg::Sha384,
        aead: AeadAlg::Aes256Gcm,
        key_len: 32,
        sig_kind: SigKind::Ecdsa,
    },
    SuiteParams12 {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        hash: HashAlg::Sha384,
        aead: AeadAlg::Aes256Gcm,
        key_len: 32,
        sig_kind: SigKind::Rsa,
    },
];

/// Looks up the parameters for a wire suite, if it's one we offer.
pub(super) fn lookup_suite_12(s: CipherSuite) -> Option<SuiteParams12> {
    SUITES_12.iter().copied().find(|p| p.suite == s)
}

/// Whether the leaf's public key is compatible with `kind` (matches what the
/// negotiated suite's signature half requires).
fn key_matches_sig_kind(key: &AnyPublicKey, kind: SigKind) -> bool {
    match (key, kind) {
        (AnyPublicKey::Rsa(_), SigKind::Rsa) => true,
        (AnyPublicKey::Ecdsa(_), SigKind::Ecdsa) => true,
        // Ed25519 / ML-DSA leaves don't fit either RSA or ECDSA TLS-1.2 ECDHE
        // suites (there are no IANA-assigned `TLS_ECDHE_EDDSA_*` or
        // `TLS_ECDHE_MLDSA_*` codepoints). Reject explicitly so the connection
        // visibly fails rather than misinterpreting the leaf later.
        _ => false,
    }
}

/// The client handshake progress.
#[derive(PartialEq, Eq, Debug)]
enum State {
    WaitServerHello,
    WaitCertificate,
    WaitServerKeyExchange,
    WaitServerHelloDone,
    /// We've sent our ClientKeyExchange / ChangeCipherSpec / Finished;
    /// expecting the server's [NewSessionTicket] / ChangeCipherSpec then
    /// encrypted Finished.
    WaitServerFinished,
    /// RFC 5077 resumption (RFC 5077 §3.4): after SH we're waiting for the
    /// server's [NewSessionTicket] / ChangeCipherSpec / Finished.
    WaitResumedServerFinished,
    Connected,
    Closed,
}

/// The system clock, when available; `None` for `no_std`.
#[cfg(feature = "std")]
fn system_now() -> Option<Time> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| Time::from_unix(d.as_secs()))
}

#[cfg(not(feature = "std"))]
fn system_now() -> Option<Time> {
    None
}

/// A TLS 1.2 client connection.
///
/// Created by [`ClientConnection12::new`]; drive it with `read_tls` /
/// `write_tls` / `process_new_packets` exactly like the TLS 1.3 client.
pub struct ClientConnection12 {
    config: ClientConfig12,
    server_name: String,
    state: State,

    /// Inbound TLS bytes to parse into records.
    inbuf: Vec<u8>,
    /// Outbound TLS bytes ready to send.
    outbuf: Vec<u8>,
    /// Reassembly buffer for handshake messages spanning records.
    hs_pending: Vec<u8>,
    /// Decrypted application data awaiting the application.
    app_in: Vec<u8>,
    /// Buffered handshake transcript hash (RFC 5246 §7.4.9).
    transcript: Transcript,
    /// `true` while ChangeCipherSpec is allowed (between CH and the server's
    /// Finished). Closed once we transition to `Connected`.
    ccs_window_open: bool,
    /// Set when the server's ChangeCipherSpec has been processed. A second
    /// CCS in the same handshake direction is a protocol violation (RFC 5246
    /// §7.1 allows exactly one).
    ccs_received: bool,

    /// Ephemeral X25519 private key (used when the server picks X25519).
    x25519: X25519PrivateKey,
    /// Ephemeral P-256 ECDH private key (used when the server picks SECP256R1).
    p256: BoxedEcdhPrivateKey,

    /// Our handshake randoms (sent in CH, echoed by SH).
    client_random: Random,
    server_random: Option<Random>,
    /// Our offered suites (preference order).
    offered_suites: Vec<CipherSuite>,
    /// Our offered groups.
    offered_groups: Vec<NamedGroup>,

    /// Negotiated suite parameters (set on SH).
    suite: Option<SuiteParams12>,
    /// Peer certificate chain (leaf first), populated from `Certificate`.
    cert_chain: Vec<Vec<u8>>,
    /// Peer leaf public key, extracted from the leaf cert (verified or raw).
    leaf_key: Option<AnyPublicKey>,
    /// Negotiated ECDHE share from `ServerKeyExchange`: (group, peer point).
    peer_share: Option<(NamedGroup, Vec<u8>)>,
    /// Negotiated ALPN, if any.
    alpn_negotiated: Option<Vec<u8>>,

    /// 48-byte master secret derived from the ECDHE premaster + randoms (or
    /// recovered from a stored session under resumption).
    master: Option<[u8; 48]>,
    /// Record-protection state once `client_crypter` is installed.
    client_crypter: Option<RecordCrypter12>,
    /// Record-protection state for inbound records once the server's CCS has
    /// been received.
    server_crypter: Option<RecordCrypter12>,
    /// Park the inbound crypter here until the server's CCS arrives. A
    /// plaintext `NewSessionTicket` (fresh handshake) or server `[NST]CCS
    /// Finished` (resumed handshake) may come before that CCS, so we must
    /// not install the read key early or the NST decode would be misread as
    /// encrypted bytes.
    pending_server_crypter: Option<RecordCrypter12>,

    /// mTLS: set to `true` after we see a server `CertificateRequest`.
    /// Drives whether we emit our own `Certificate` (+ CertificateVerify) in
    /// the client flight that follows ServerHelloDone.
    cert_request_received: bool,
    /// RFC 5077 resumption: the most recent ticket we received from the
    /// server (set when a `NewSessionTicket` arrives during the handshake).
    received_ticket: Option<Vec<u8>>,
    /// Lifetime hint from the received NST, in seconds. Held for caller
    /// consumption (currently unused by the state machine).
    #[allow(dead_code)]
    received_ticket_lifetime: u32,
    /// RFC 5077: `true` when this handshake is being resumed (we presented
    /// a non-empty `session_ticket` extension and the server accepted it —
    /// detected by the server's `session_ticket` extension being absent in
    /// the SH).
    resumed: bool,

    /// RFC 7627 §3 — we always offer `extended_master_secret` in our
    /// ClientHello; this flag stays `true` for the connection lifetime
    /// once the CH is built.
    pub(crate) ems_offered: bool,
    /// RFC 7627 §3 — set when the server echoed `extended_master_secret`
    /// in its ServerHello. Drives the master-secret derivation choice
    /// (EMS vs legacy) and the resumption-gating check.
    pub(crate) ems_negotiated: bool,
    /// RFC 7627 §4 — snapshot of `Hash(CH ‖ SH ‖ … ‖ CKE)` captured the
    /// instant the ClientKeyExchange is fed into the transcript. Used as
    /// the `session_hash` input to `extended_master_secret`.
    ems_session_hash: Option<Vec<u8>>,
}

impl ClientConnection12 {
    /// Starts a client handshake to `server_name`, emitting the `ClientHello`.
    /// `rng` supplies the ephemeral key shares and the client random. Offers
    /// all six AEAD-ECDHE suites and both supported groups.
    pub fn new<R: RngCore>(config: ClientConfig12, server_name: &str, rng: &mut R) -> Self {
        Self::new_with_offer(
            config,
            server_name,
            rng,
            &SUITES_12.iter().map(|p| p.suite).collect::<Vec<_>>(),
            &[NamedGroup::X25519, NamedGroup::SECP256R1],
        )
    }

    /// Like [`new`](Self::new) but with an explicit cipher-suite and
    /// key-exchange-group offer. The given suites are filtered to those we
    /// recognise; unknown codepoints are silently dropped.
    pub(crate) fn new_with_offer<R: RngCore>(
        config: ClientConfig12,
        server_name: &str,
        rng: &mut R,
        suites: &[CipherSuite],
        groups: &[NamedGroup],
    ) -> Self {
        let x25519 = X25519PrivateKey::generate(rng);
        let p256 = BoxedEcdhPrivateKey::generate(CurveId::P256, rng);
        let mut random: Random = [0u8; 32];
        rng.fill_bytes(&mut random);

        let offered_suites: Vec<CipherSuite> = suites
            .iter()
            .copied()
            .filter(|s| lookup_suite_12(*s).is_some())
            .collect();

        let mut conn = ClientConnection12 {
            config,
            server_name: String::from(server_name),
            state: State::WaitServerHello,
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            hs_pending: Vec::new(),
            app_in: Vec::new(),
            transcript: Transcript::new(),
            ccs_window_open: true,
            ccs_received: false,
            x25519,
            p256,
            client_random: random,
            server_random: None,
            offered_suites: offered_suites.clone(),
            offered_groups: groups.to_vec(),
            suite: None,
            cert_chain: Vec::new(),
            leaf_key: None,
            peer_share: None,
            alpn_negotiated: None,
            master: None,
            client_crypter: None,
            server_crypter: None,
            pending_server_crypter: None,
            cert_request_received: false,
            received_ticket: None,
            received_ticket_lifetime: 0,
            resumed: false,
            // We always offer EMS (RFC 7627 §3); the flag captures that on
            // both the fresh and resumed paths so resumption-gating can
            // compare it against the stored session's `ems_used`.
            ems_offered: true,
            ems_negotiated: false,
            ems_session_hash: None,
        };
        let hello = conn.build_client_hello(&offered_suites, groups);
        // Update the transcript even though the hash isn't selected yet —
        // `Transcript` buffers the bytes and applies the hash on demand once
        // `set_alg` is called (when we process SH).
        conn.transcript.update(&hello);
        conn.write_plain_record(ContentType::Handshake, &hello);
        conn
    }

    /// Builds the ClientHello with all the TLS-1.2-required extensions.
    fn build_client_hello(&self, suites: &[CipherSuite], groups: &[NamedGroup]) -> Vec<u8> {
        let mut extensions = alloc::vec![
            ext::server_name(&self.server_name),
            ext::supported_groups_list(groups),
            ext::signature_algorithms(),
            // RFC 4492 §5.1.2: TLS 1.2 ECDHE peers REQUIRE ec_point_formats
            // even though only "uncompressed" is widely deployed.
            ext::ec_point_formats(),
            // RFC 5746 §3.5: present `renegotiation_info` (empty) so a
            // strict server doesn't reject us for failing to advertise
            // secure-renegotiation support. We never actually renegotiate.
            ext::renegotiation_info_empty(),
            // RFC 7627 §5.1: always offer `extended_master_secret`. A
            // server that supports it echoes back the empty-body extension
            // and both sides switch to the session-hash-bound derivation;
            // a server that doesn't echo it falls back to the legacy
            // randoms-only derivation. Modern peers (rustls, BoringSSL,
            // OpenSSL, NSS) require EMS by default.
            ext::extended_master_secret_empty(),
        ];
        if !self.config.alpn_protocols.is_empty() {
            let protos: Vec<&[u8]> = self
                .config
                .alpn_protocols
                .iter()
                .map(|v| v.as_slice())
                .collect();
            extensions.push(ext::alpn_protocols(&protos));
        }
        if let Some(limit) = self.config.record_size_limit {
            extensions.push(ext::record_size_limit(limit));
        }
        // RFC 5077 §3.1: present a `session_ticket` extension. Empty body =
        // "I support tickets but have none to resume"; non-empty body =
        // "please resume this ticket". We always advertise support so the
        // server can issue tickets even on fresh handshakes.
        let ticket_bytes: &[u8] = self
            .config
            .session
            .as_ref()
            .map(|s| s.ticket.as_slice())
            .unwrap_or(&[]);
        extensions.push(ext::session_ticket(ticket_bytes));

        // RFC 7507 §4: caller opted into emitting `TLS_FALLBACK_SCSV`
        // (`0x5600`) to flag a deliberate downgrade. Prepend it to the wire
        // suite list; it never enters `self.offered_suites` (which is the
        // server-echo whitelist), so a server that mis-echoes 0x5600 in its
        // SH still gets rejected.
        let mut cipher_suites_wire: Vec<CipherSuite> = Vec::with_capacity(suites.len() + 1);
        if self.config.send_fallback_scsv {
            cipher_suites_wire.push(CipherSuite(TLS_FALLBACK_SCSV));
        }
        cipher_suites_wire.extend_from_slice(suites);

        // RFC 5246 §7.4.1.2: TLS 1.2 ClientHello carries `legacy_version =
        // 0x0303`.
        ClientHello {
            legacy_version: 0x0303,
            random: self.client_random,
            session_id: Vec::new(),
            cipher_suites: cipher_suites_wire,
            extensions,
        }
        .encode()
    }

    /// The negotiated cipher-suite wire identifier, available once the
    /// `ServerHello` has been processed.
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.suite.map(|s| s.suite.0)
    }

    /// Protocol version string, always `"TLSv1.2"` here once a SH has been
    /// processed.
    pub fn protocol_version(&self) -> Option<&'static str> {
        self.suite.map(|_| "TLSv1.2")
    }

    /// The peer's certificate chain in wire order (DER), leaf first.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.cert_chain
    }

    /// The ALPN protocol the server selected, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_negotiated.as_deref()
    }

    /// The client random sent in the ClientHello (matches the wire bytes).
    pub fn client_random(&self) -> [u8; 32] {
        self.client_random
    }

    /// The TLS 1.2 master secret derived during the handshake. Returns `None`
    /// until the master secret has been computed (i.e. after the
    /// `ServerHelloDone`/`ClientKeyExchange` exchange or after a resumed
    /// session is accepted). Useful for writing the NSS `SSLKEYLOGFILE`
    /// `CLIENT_RANDOM <client_random_hex> <master_secret_hex>` line.
    pub fn master_secret(&self) -> Option<[u8; 48]> {
        self.master
    }

    /// Returns the latest stored session suitable for RFC 5077 resumption
    /// on the next connection. `None` if the server never sent a NST. Combine
    /// with [`ClientConfig12::with_session`].
    pub fn take_session(&mut self) -> Option<StoredSession12> {
        let ticket = self.received_ticket.take()?;
        let suite = self.suite?;
        let master = self.master?;
        Some(StoredSession12 {
            ticket,
            master_secret: master,
            cipher_suite: suite.suite.0,
            alpn: self.alpn_negotiated.clone(),
            received_at: self.config.verification_time.clone().or_else(system_now),
            ems_used: self.ems_negotiated,
        })
    }

    /// `true` if this handshake resumed a prior session via RFC 5077.
    pub fn did_resume(&self) -> bool {
        self.resumed
    }

    /// Whether the handshake negotiated RFC 7627 Extended Master Secret.
    pub fn ems_negotiated(&self) -> bool {
        self.ems_negotiated
    }

    /// Feeds received TLS bytes into the input buffer.
    pub fn read_tls(&mut self, bytes: &[u8]) {
        self.inbuf.extend_from_slice(bytes);
    }

    /// Removes and returns all bytes queued for transmission.
    pub fn write_tls(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.outbuf)
    }

    /// Whether there are bytes queued for transmission.
    pub fn wants_write(&self) -> bool {
        !self.outbuf.is_empty()
    }

    /// Whether the handshake is still in progress.
    pub fn is_handshaking(&self) -> bool {
        !matches!(self.state, State::Connected | State::Closed)
    }

    /// Sends application data (only valid once the handshake completes).
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::InappropriateState);
        }
        // Fragment to at most 2^14 bytes per record (RFC 5246 §6.2.1). We
        // don't honour the peer's record_size_limit on the write side here
        // (the extension is advisory and the only sane way to honour it is
        // server-side); a follow-up commit can wire that.
        const CAP: usize = 1 << 14;
        if data.len() <= CAP {
            self.emit_encrypted(ContentType::ApplicationData, data)?;
        } else {
            for chunk in data.chunks(CAP) {
                self.emit_encrypted(ContentType::ApplicationData, chunk)?;
            }
        }
        Ok(())
    }

    /// Removes and returns any received application plaintext.
    pub fn take_received_plaintext(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app_in)
    }

    /// Queues a `close_notify` warning alert.
    pub fn send_close_notify(&mut self) {
        let body = [1u8, AlertDescription::CloseNotify.as_u8()]; // level = warning
        let _ = self.emit_alert(&body);
    }

    /// Processes all buffered records, advancing the handshake. On a protocol
    /// error it queues a fatal alert and returns the error.
    pub fn process_new_packets(&mut self) -> Result<(), Error> {
        loop {
            match self.next_message() {
                Ok(Some(Incoming::Handshake(msg))) => {
                    if let Err(e) = self.handle_handshake(msg) {
                        self.fail(&e);
                        return Err(e);
                    }
                }
                Ok(Some(Incoming::ApplicationData)) => {
                    if self.state != State::Connected {
                        let e = Error::UnexpectedMessage;
                        self.fail(&e);
                        return Err(e);
                    }
                }
                Ok(Some(Incoming::Alert(alert))) => {
                    // RFC 5246 §7.2.1: in TLS 1.2 only a subset of alerts are
                    // fatal. `close_notify` ends the connection cleanly;
                    // `user_canceled` and `no_renegotiation` are warning-level
                    // and we accept (logging via the consumer) rather than
                    // tear the connection down.
                    match alert.description {
                        AlertDescription::CloseNotify => {
                            self.state = State::Closed;
                            return Ok(());
                        }
                        AlertDescription::UserCanceled | AlertDescription::NoRenegotiation => {
                            // Non-fatal warning — stay connected.
                            continue;
                        }
                        _ => return Err(Error::AlertReceived(alert.description)),
                    }
                }
                Ok(None) => return Ok(()),
                Err(e) => {
                    self.fail(&e);
                    return Err(e);
                }
            }
        }
    }

    fn fail(&mut self, error: &Error) {
        let body = [2u8, alert_for(error).as_u8()]; // level = fatal
        let _ = self.emit_alert(&body);
        self.state = State::Closed;
    }

    /// Writes a plaintext record straight to the outbound buffer.
    fn write_plain_record(&mut self, ct: ContentType, payload: &[u8]) {
        write_record(&mut self.outbuf, ct, ProtocolVersion::TLSv1_2, payload);
    }

    /// Encrypts `payload` under the installed `client_crypter` and frames it.
    /// Returns `Err(InappropriateState)` if write keys aren't installed yet.
    fn emit_encrypted(&mut self, ct: ContentType, payload: &[u8]) -> Result<(), Error> {
        let crypter = self
            .client_crypter
            .as_mut()
            .ok_or(Error::InappropriateState)?;
        let fragment = crypter.encrypt(ct, payload)?;
        write_record(&mut self.outbuf, ct, ProtocolVersion::TLSv1_2, &fragment);
        Ok(())
    }

    /// Queues an alert (plaintext if keys aren't installed yet, encrypted
    /// otherwise).
    fn emit_alert(&mut self, body: &[u8; 2]) -> Result<(), Error> {
        if self.client_crypter.is_some() {
            self.emit_encrypted(ContentType::Alert, body)
        } else {
            self.write_plain_record(ContentType::Alert, body);
            Ok(())
        }
    }

    /// Pulls the next decoded message from the inbound buffer, or `Ok(None)`
    /// if more bytes are needed.
    fn next_message(&mut self) -> Result<Option<Incoming>, Error> {
        loop {
            // A complete buffered handshake message takes priority.
            if let Some(msg) = self.pop_handshake() {
                return Ok(Some(Incoming::Handshake(msg)));
            }

            let Some(ParsedRecord {
                content_type,
                version,
                fragment,
                len,
            }) = read_record(&self.inbuf)?
            else {
                return Ok(None);
            };
            // RFC 5246 §6.2.1 / RFC 8446 §5.1: the record `legacy_version`
            // field is `0x0301..=0x0303`. SSL 3.0 (`0x0300`) and unknown
            // versions are downgrade attempts — reject with `protocol_version`.
            if !is_legal_record_version(version) {
                return Err(Error::UnsupportedVersion);
            }
            // Snapshot the 5-byte header for the decrypt AAD before we drain.
            let mut header = [0u8; 5];
            header.copy_from_slice(&self.inbuf[..5]);
            let fragment = fragment.to_vec();
            self.inbuf.drain(..len);

            match content_type {
                ContentType::ChangeCipherSpec => {
                    // RFC 5246 §7.1: the only legal body is `[0x01]`, and we
                    // only accept it in the middlebox-compat window. The
                    // server's CCS installs the read crypter; subsequent
                    // records on the wire are encrypted.
                    if !self.ccs_window_open || fragment.as_slice() != [0x01] {
                        return Err(Error::UnexpectedMessage);
                    }
                    // RFC 5246 §7.1: exactly one CCS per direction. A second
                    // CCS here is a protocol violation regardless of state.
                    if self.ccs_received {
                        return Err(Error::UnexpectedMessage);
                    }
                    // Both fresh and resumed paths park the inbound crypter
                    // in `pending_server_crypter`; the server's CCS arrives
                    // AFTER any plaintext `NewSessionTicket`, so we only
                    // install the read key once we see the CCS.
                    match self.state {
                        State::WaitServerFinished | State::WaitResumedServerFinished => {
                            let crypter = self
                                .pending_server_crypter
                                .take()
                                .ok_or(Error::UnexpectedMessage)?;
                            self.server_crypter = Some(crypter);
                        }
                        _ => return Err(Error::UnexpectedMessage),
                    }
                    self.ccs_received = true;
                    continue;
                }
                ContentType::Handshake => {
                    // Handshake bytes are plaintext until the server's CCS
                    // arrives (the server's first encrypted record is its
                    // Finished). After that they're encrypted under
                    // `server_crypter` and reach us via ApplicationData
                    // record type? No — in TLS 1.2 the record header keeps
                    // its real content type (`Handshake`) even when the
                    // fragment is encrypted. So we need to branch on whether
                    // a server crypter is installed.
                    if let Some(c) = self.server_crypter.as_mut() {
                        let (_ct, plain) = c.decrypt(&header, &fragment)?;
                        if plain.is_empty() {
                            return Err(Error::UnexpectedMessage);
                        }
                        self.hs_pending.extend_from_slice(&plain);
                    } else {
                        self.hs_pending.extend_from_slice(&fragment);
                    }
                }
                ContentType::ApplicationData => {
                    let c = self
                        .server_crypter
                        .as_mut()
                        .ok_or(Error::UnexpectedMessage)?;
                    let (_ct, plain) = c.decrypt(&header, &fragment)?;
                    self.app_in.extend_from_slice(&plain);
                    return Ok(Some(Incoming::ApplicationData));
                }
                ContentType::Alert => {
                    let payload: Vec<u8> = if let Some(c) = self.server_crypter.as_mut() {
                        let (_ct, plain) = c.decrypt(&header, &fragment)?;
                        plain
                    } else {
                        fragment
                    };
                    return Ok(Some(parse_alert(&payload)?));
                }
                _ => return Err(Error::UnexpectedMessage),
            }
        }
    }

    /// Removes one complete handshake message (header + body) from the
    /// reassembly buffer, if present.
    fn pop_handshake(&mut self) -> Option<Vec<u8>> {
        if self.hs_pending.len() < 4 {
            return None;
        }
        let len = ((self.hs_pending[1] as usize) << 16)
            | ((self.hs_pending[2] as usize) << 8)
            | self.hs_pending[3] as usize;
        let total = 4 + len;
        if self.hs_pending.len() < total {
            return None;
        }
        Some(self.hs_pending.drain(..total).collect())
    }

    fn handle_handshake(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        let mut c = ReadCursor::new(&msg);
        let (msg_type, body) = read_handshake(&mut c)?;

        // RFC 5246 §7.4.1.1: `HelloRequest` is a renegotiation prompt. We do
        // not support renegotiation — reject it whatever the current state.
        // (Both before and after the handshake completes: a server that
        // emits it mid-flight is misbehaving; one that emits it after we
        // reach `Connected` is requesting renegotiation, which we refuse.)
        if msg_type == hs_type::HELLO_REQUEST {
            return Err(Error::UnexpectedMessage);
        }

        match self.state {
            State::WaitServerHello => self.on_server_hello(msg_type, body, &msg),
            State::WaitCertificate => self.on_certificate(msg_type, body, &msg),
            State::WaitServerKeyExchange => self.on_server_key_exchange(msg_type, body, &msg),
            State::WaitServerHelloDone => self.on_server_hello_done(msg_type, body, &msg),
            State::WaitServerFinished | State::WaitResumedServerFinished => {
                self.on_server_finished(msg_type, body, &msg)
            }
            State::Connected => Err(Error::UnexpectedMessage),
            State::Closed => Err(Error::UnexpectedMessage),
        }
    }

    fn on_server_hello(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::SERVER_HELLO {
            return Err(Error::UnexpectedMessage);
        }
        let sh = ServerHello::decode(body)?;

        // The wire encoder of `ServerHello` doesn't expose `legacy_version`
        // separately, but the codec already reads it as TLS 1.2 (0x0303).
        // What we still need to guard against is the server selecting TLS 1.3
        // via the `supported_versions` extension. If we see that, the server
        // thinks it's doing 1.3 — bail.
        if ext::find(&sh.extensions, ExtensionType::SUPPORTED_VERSIONS).is_some() {
            return Err(Error::UnsupportedVersion);
        }

        // RFC 8446 §4.1.3: a TLS-1.3-aware server that downgraded to TLS 1.2
        // (or 1.1) sets the last 8 bytes of `server_random` to a sentinel.
        // Our default 1.2 client never offers TLS 1.3, so seeing a sentinel
        // here means we're either talking to a misconfigured server or are
        // part of a fallback chain that hasn't opted in. Reject unless the
        // caller explicitly enabled `accept_downgrade_sentinel`.
        let tail: &[u8] = &sh.random[24..];
        let sentinel_seen =
            tail == DOWNGRADE_SENTINEL_TLS12 || tail == DOWNGRADE_SENTINEL_TLS11_OR_BELOW;
        if sentinel_seen && !self.config.accept_downgrade_sentinel {
            return Err(Error::IllegalParameter);
        }

        // Selected suite must be one we offered AND one we recognise. (The
        // SCSV pseudo-suite 0x5600 is never in `offered_suites`, so a server
        // echoing it as the selected suite gets rejected here.)
        if !self.offered_suites.contains(&sh.cipher_suite) {
            return Err(Error::HandshakeFailure);
        }
        let suite = lookup_suite_12(sh.cipher_suite).ok_or(Error::HandshakeFailure)?;

        // RFC 5746 §3.4: if the client included `renegotiation_info` (which
        // we always do), the server MUST echo it with an empty body in SH.
        // Anything else is a protocol violation.
        let reneg = ext::find(&sh.extensions, ExtensionType::RENEGOTIATION_INFO)
            .ok_or(Error::HandshakeFailure)?;
        let inner = ext::parse_renegotiation_info(reneg)?;
        if !inner.is_empty() {
            // A non-empty echo would only be valid mid-renegotiation, which
            // we never initiate.
            return Err(Error::HandshakeFailure);
        }

        // ALPN echo: at most one protocol, drawn from our offer.
        if let Some(alpn_body) = ext::find(&sh.extensions, ExtensionType::ALPN) {
            let names = ext::parse_alpn(alpn_body)?;
            if names.len() != 1 {
                return Err(Error::IllegalParameter);
            }
            if !self.config.alpn_protocols.iter().any(|p| p == &names[0]) {
                return Err(Error::IllegalParameter);
            }
            self.alpn_negotiated = Some(names.into_iter().next().unwrap());
        }
        // Optional record_size_limit echo (RFC 8449).
        if let Some(rsl) = ext::find(&sh.extensions, ExtensionType::RECORD_SIZE_LIMIT) {
            let _limit = ext::parse_record_size_limit(rsl)?;
            // Not currently honoured on the write side (see send_application_data).
        }

        // RFC 5077 §3.2 + §3.4: a server that intends to issue a NEW ticket
        // includes an empty `session_ticket` extension in SH; a server that
        // is RESUMING our offered ticket omits the extension entirely. We use
        // this signal to choose the resumed vs fresh post-SH path before any
        // post-SH bytes arrive.
        let server_will_issue_ticket =
            ext::find(&sh.extensions, ExtensionType::SESSION_TICKET).is_some();

        // RFC 7627 §5.1: server echoes `extended_master_secret` iff it
        // supports EMS. A server that echoes it MUST also have seen our
        // offer (which we always send) — if not, that's a server bug and
        // we reject with `IllegalParameter`. Empty body is mandatory; a
        // non-empty body is a protocol violation (`Decode` → decode_error).
        if let Some(ems_body) = ext::find(&sh.extensions, ExtensionType::EXTENDED_MASTER_SECRET) {
            ext::parse_extended_master_secret(ems_body)?;
            if !self.ems_offered {
                // We always offer; this branch is defensive in case a
                // future caller suppresses the offer.
                return Err(Error::IllegalParameter);
            }
            self.ems_negotiated = true;
        } else {
            self.ems_negotiated = false;
        }

        // Pin the negotiated hash on the transcript now that we know it.
        self.transcript.set_alg(suite.hash);
        self.transcript.update(raw);

        self.suite = Some(suite);
        self.server_random = Some(sh.random);

        // Try to resume: stored session present, suite matches, AND server
        // is NOT signalling a fresh-issue ticket. If the server's
        // session_ticket extension is present (empty) it's telling us "I'm
        // doing a fresh handshake and will issue a new ticket" — fall back.
        let resume = self
            .config
            .session
            .as_ref()
            .filter(|s| s.cipher_suite == sh.cipher_suite.0)
            .filter(|_| !server_will_issue_ticket)
            .cloned();
        if let Some(stored) = resume {
            // RFC 7627 §5.3: a session that used EMS MUST resume with EMS,
            // and a session that did NOT use EMS MUST NOT resume with EMS.
            // Cross-EMS resumption is forbidden — abort the handshake with
            // `IllegalParameter` to keep an active downgrader from
            // recombining a non-EMS handshake with an EMS-bound ticket.
            if stored.ems_used != self.ems_negotiated {
                return Err(Error::IllegalParameter);
            }

            // Resumed path: master_secret recovered from the ticket; derive a
            // fresh key block from the new randoms and wait for the server's
            // [NewSessionTicket] / CCS / Finished. We do NOT touch ECDHE — no
            // SKE, no CKE.
            let cr = self.client_random;
            let sr = sh.random;
            self.master = Some(stored.master_secret);
            self.resumed = true;

            if let Some(kl) = self.config.key_log.as_ref() {
                kl.log("CLIENT_RANDOM", &cr, &stored.master_secret);
            }

            let kb_len = 2 * suite.key_len + 8;
            let mut kb = alloc::vec![0u8; kb_len];
            key_block(suite.hash, &stored.master_secret, &sr, &cr, &mut kb);
            // Only the server (read) crypter is built up-front; the client
            // (write) crypter is re-derived in `on_server_finished` from the
            // same master_secret + randoms once we send our CCS.
            let (_c_key, rest) = kb.split_at(suite.key_len);
            let (s_key, ivs) = rest.split_at(suite.key_len);
            let mut s_salt = [0u8; 4];
            s_salt.copy_from_slice(&ivs[4..8]);
            self.pending_server_crypter = Some(RecordCrypter12::new(suite.aead, s_key, s_salt));
            self.state = State::WaitResumedServerFinished;
        } else {
            self.state = State::WaitCertificate;
        }
        Ok(())
    }

    fn on_certificate(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::CERTIFICATE {
            return Err(Error::UnexpectedMessage);
        }
        let chain = parse_certificate_list_12(body)?;
        if chain.is_empty() {
            return Err(Error::BadCertificate);
        }

        // Reject malformed leaves regardless of policy.
        let leaf = Certificate::from_der(chain[0].clone()).map_err(|_| Error::BadCertificate)?;
        leaf.check_well_formed()
            .map_err(|_| Error::BadCertificate)?;

        let leaf_key = if self.config.verify_certificates {
            let now = self.config.verification_time.clone().or_else(system_now);
            let key = verify_chain_with_crls(
                &self.config.roots,
                &self.config.crls,
                &chain,
                now.as_ref(),
                &self.config.signature_policy,
            )?;
            verify_hostname(&leaf, &self.server_name)?;
            key
        } else {
            leaf.subject_public_key()
                .map_err(|_| Error::BadCertificate)?
        };

        // The leaf's key family must match the suite's signature half.
        let suite = self.suite.expect("suite set in on_server_hello");
        if !key_matches_sig_kind(&leaf_key, suite.sig_kind) {
            return Err(Error::HandshakeFailure);
        }

        self.cert_chain = chain;
        self.leaf_key = Some(leaf_key);
        self.transcript.update(raw);
        self.state = State::WaitServerKeyExchange;
        Ok(())
    }

    fn on_server_key_exchange(
        &mut self,
        msg_type: u8,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), Error> {
        if msg_type != hs_type::SERVER_KEY_EXCHANGE {
            return Err(Error::UnexpectedMessage);
        }
        let ske = ServerKeyExchange::decode(body)?;

        // Group must be one we offered.
        if !self.offered_groups.contains(&ske.group) {
            return Err(Error::IllegalParameter);
        }

        // Verify the SKE signature: `signed_message(cr, sr, group, point)`
        // signed under the leaf key per scheme `ske.scheme`.
        let cr = self.client_random;
        let sr = self.server_random.expect("server_random set");
        let msg = signed_message(&cr, &sr, ske.group, &ske.point);
        let leaf_key = self
            .leaf_key
            .as_ref()
            .ok_or(Error::InappropriateState)?
            .clone();
        verify_signature(
            ske.scheme,
            &leaf_key,
            &msg,
            &ske.signature,
            &self.config.signature_policy,
        )?;

        self.peer_share = Some((ske.group, ske.point.clone()));
        self.transcript.update(raw);
        self.state = State::WaitServerHelloDone;
        Ok(())
    }

    fn on_server_hello_done(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        // mTLS: a `CertificateRequest` (RFC 5246 §7.4.4) MAY appear between
        // ServerKeyExchange and ServerHelloDone. Parse for structure, record
        // the request, and stay in `WaitServerHelloDone`.
        if msg_type == hs_type::CERTIFICATE_REQUEST {
            let _cr = CertificateRequest12::decode(body)?;
            self.cert_request_received = true;
            self.transcript.update(raw);
            return Ok(());
        }
        if msg_type != hs_type::SERVER_HELLO_DONE {
            return Err(Error::UnexpectedMessage);
        }
        let _ = ServerHelloDone::decode(body)?;
        self.transcript.update(raw);

        // Complete ECDHE and compute the premaster.
        let (group, peer_point) = self
            .peer_share
            .as_ref()
            .cloned()
            .ok_or(Error::InappropriateState)?;
        let (premaster, our_point) = self.ecdhe(group, &peer_point)?;

        // RFC 5246 §7.4.7.1 — the CKE goes into the transcript next. We need
        // its hash captured BEFORE we feed any further messages so the EMS
        // `session_hash` exactly matches `Hash(CH..CKE)` (RFC 7627 §4).
        // mTLS: if the server asked for a client cert, we MUST emit our
        // Certificate FIRST (RFC 5246 §7.3) — feed it into the transcript
        // before the CKE so the EMS session_hash includes it.
        let suite = self.suite.expect("suite set");
        if self.cert_request_received {
            self.send_client_certificate();
        }

        // Emit ClientKeyExchange.
        let cke = ClientKeyExchange { point: our_point }.encode();
        self.transcript.update(&cke);
        // Snapshot the EMS session_hash AFTER feeding CKE (and any earlier
        // client `Certificate`) into the transcript; this is exactly
        // `Hash(CH..CKE)`.
        if self.ems_negotiated {
            self.ems_session_hash = Some(self.transcript.current_hash().as_slice().to_vec());
        }
        self.write_plain_record(ContentType::Handshake, &cke);

        // Derive master_secret. RFC 7627 §4 vs RFC 5246 §8.1 — the choice
        // depends on whether both peers offered/echoed EMS.
        let cr = self.client_random;
        let sr = self.server_random.expect("server_random set");
        let master = if self.ems_negotiated {
            let session_hash = self
                .ems_session_hash
                .as_ref()
                .expect("EMS session_hash snapshot taken just above");
            extended_master_secret(suite.hash, &premaster, session_hash)
        } else {
            master_secret(suite.hash, &premaster, &cr, &sr)
        };

        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log("CLIENT_RANDOM", &cr, &master);
        }

        // key_block layout (RFC 5246 §6.3 / RFC 5288 §3): client_key,
        // server_key, client_iv (4-byte salt), server_iv (4-byte salt).
        let kb_len = 2 * suite.key_len + 8;
        let mut kb = alloc::vec![0u8; kb_len];
        key_block(suite.hash, &master, &sr, &cr, &mut kb);
        let (c_key, rest) = kb.split_at(suite.key_len);
        let (s_key, rest) = rest.split_at(suite.key_len);
        let mut c_salt = [0u8; 4];
        c_salt.copy_from_slice(&rest[..4]);
        let mut s_salt = [0u8; 4];
        s_salt.copy_from_slice(&rest[4..8]);
        let client_crypter = RecordCrypter12::new(suite.aead, c_key, c_salt);
        let server_crypter = RecordCrypter12::new(suite.aead, s_key, s_salt);

        // The client Certificate (under mTLS) and ClientKeyExchange were
        // emitted ABOVE so the EMS session_hash snapshot covers them
        // exactly. CertificateVerify follows next because it is signed over
        // the transcript through CKE.
        if self.cert_request_received && self.config.client_cert.is_some() {
            self.send_client_certificate_verify()?;
        }

        // Emit ChangeCipherSpec (plaintext, outside the transcript).
        self.write_plain_record(ContentType::ChangeCipherSpec, &[0x01]);

        // Install the client crypter — subsequent outbound records are
        // encrypted (starting with our Finished).
        self.client_crypter = Some(client_crypter);
        // Park the server crypter; we install it on the server's CCS. The
        // server's NewSessionTicket (if any) arrives BEFORE its CCS as a
        // plaintext handshake message, so we must not pre-install the
        // inbound crypter or NST decoding would corrupt it.
        self.pending_server_crypter = Some(server_crypter);
        self.master = Some(master);

        // Compute and emit our Finished.
        let th = self.transcript.current_hash();
        let verify_data =
            finished_verify_data(suite.hash, &master, b"client finished", th.as_slice());
        let finished = build_finished(&verify_data);
        // Transcript update BEFORE encrypting — the server's Finished
        // verify_data is over `Hash(CH..client_Finished)`.
        self.transcript.update(&finished);
        self.emit_encrypted(ContentType::Handshake, &finished)?;

        self.state = State::WaitServerFinished;
        Ok(())
    }

    /// mTLS: emit our `Certificate` (TLS 1.2 RFC 5246 §7.4.6). The chain is
    /// our configured one, or empty when no client cert is configured (the
    /// server then decides per its `required` flag).
    fn send_client_certificate(&mut self) {
        let mut msg = alloc::vec![hs_type::CERTIFICATE];
        with_len_u24(&mut msg, |b| {
            with_len_u24(b, |list| {
                if let Some(cc) = self.config.client_cert.as_ref() {
                    for cert in cc.chain() {
                        with_len_u24(list, |c| c.extend_from_slice(cert));
                    }
                }
            });
        });
        self.transcript.update(&msg);
        self.write_plain_record(ContentType::Handshake, &msg);
    }

    /// mTLS: emit `CertificateVerify` (RFC 5246 §7.4.8). The signature is
    /// over the raw concatenated handshake messages from CH up to and
    /// including ClientKeyExchange — the signer hashes them internally per
    /// its scheme.
    fn send_client_certificate_verify(&mut self) -> Result<(), Error> {
        let cc = self
            .config
            .client_cert
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        // The signer takes the un-hashed transcript bytes; PSS / ECDSA /
        // Ed25519 impls each apply their own hash internally.
        let to_sign = self.transcript.buffered_bytes().to_vec();
        let scheme = ClientCertConfig::signature_scheme_for(cc.key());
        let signature: Vec<u8> = match cc.key() {
            ClientKey::Rsa(_) => {
                // The Rsa signer needs an RNG; the TLS 1.3 client side
                // doesn't have one threaded through state either — defer to
                // a clear error rather than silently fail.
                return Err(Error::HandshakeFailure);
            }
            ClientKey::Ecdsa(k) => {
                let sig = match k.curve() {
                    CurveId::P384 => k.sign::<Sha384>(&to_sign),
                    CurveId::P521 => k.sign::<Sha512>(&to_sign),
                    _ => k.sign::<Sha256>(&to_sign),
                }
                .map_err(|_| Error::HandshakeFailure)?;
                sig.to_der(k.curve())
            }
            ClientKey::Ed25519(k) => k.sign(&to_sign).to_bytes().to_vec(),
            ClientKey::MlDsa44(k) => k
                .sign_deterministic(&to_sign, b"")
                .map_err(|_| Error::HandshakeFailure)?,
            ClientKey::MlDsa65(k) => k
                .sign_deterministic(&to_sign, b"")
                .map_err(|_| Error::HandshakeFailure)?,
            ClientKey::MlDsa87(k) => k
                .sign_deterministic(&to_sign, b"")
                .map_err(|_| Error::HandshakeFailure)?,
        };
        let mut msg = alloc::vec![hs_type::CERTIFICATE_VERIFY];
        with_len_u24(&mut msg, |b| {
            b.extend_from_slice(&scheme.0.to_be_bytes());
            with_len_u16(b, |s| s.extend_from_slice(&signature));
        });
        self.transcript.update(&msg);
        self.write_plain_record(ContentType::Handshake, &msg);
        Ok(())
    }

    fn on_server_finished(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        // RFC 5077 §3.3: a `NewSessionTicket` may arrive between the client's
        // Finished and the server's CCS. It's a plaintext handshake message,
        // included in the transcript, that the server's Finished signs.
        if msg_type == hs_type::NEW_SESSION_TICKET {
            let nst = NewSessionTicket12::decode(body)?;
            if !nst.ticket.is_empty() {
                self.received_ticket = Some(nst.ticket);
                self.received_ticket_lifetime = nst.lifetime;
            }
            self.transcript.update(raw);
            return Ok(());
        }
        if msg_type != hs_type::FINISHED {
            return Err(Error::UnexpectedMessage);
        }
        if body.len() != 12 {
            return Err(Error::Decode);
        }
        let suite = self.suite.expect("suite set");
        let master = self.master.expect("master set");

        // verify_data is computed over the transcript BEFORE this message is
        // appended — exactly what the server signed.
        let th = self.transcript.current_hash();
        let expected = finished_verify_data(suite.hash, &master, b"server finished", th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        // Append the server's Finished.
        self.transcript.update(raw);

        // Resumed path: NOW we send our CCS + Finished. Per RFC 5077 §3.4 the
        // client's final flight comes AFTER the server's Finished on a
        // resumed handshake.
        if self.state == State::WaitResumedServerFinished {
            self.write_plain_record(ContentType::ChangeCipherSpec, &[0x01]);
            // Re-derive the client crypter from the same master_secret +
            // randoms we computed in `on_server_hello`.
            let cr = self.client_random;
            let sr = self.server_random.expect("server_random set");
            let kb_len = 2 * suite.key_len + 8;
            let mut kb = alloc::vec![0u8; kb_len];
            key_block(suite.hash, &master, &sr, &cr, &mut kb);
            let (c_key, rest) = kb.split_at(suite.key_len);
            let (_s_key, ivs) = rest.split_at(suite.key_len);
            let mut c_salt = [0u8; 4];
            c_salt.copy_from_slice(&ivs[..4]);
            self.client_crypter = Some(RecordCrypter12::new(suite.aead, c_key, c_salt));

            // Our Finished, signed over Hash(CH..server_Finished).
            let th_cf = self.transcript.current_hash();
            let verify_data =
                finished_verify_data(suite.hash, &master, b"client finished", th_cf.as_slice());
            let finished = build_finished(&verify_data);
            self.transcript.update(&finished);
            self.emit_encrypted(ContentType::Handshake, &finished)?;
        }

        // No more ChangeCipherSpec allowed.
        self.ccs_window_open = false;
        self.state = State::Connected;
        Ok(())
    }

    /// Builds the ECDHE shared secret with the server. Returns
    /// `(premaster, our_public_point)`.
    fn ecdhe(&self, group: NamedGroup, peer_point: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match group {
            NamedGroup::X25519 => {
                let peer: [u8; 32] = peer_point.try_into().map_err(|_| Error::Decode)?;
                // RFC 8446 §7.4.2 / RFC 7748 §6.1: small-order peer rejection.
                let ss = self
                    .x25519
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::IllegalParameter)?;
                Ok((ss.to_vec(), self.x25519.public_key().to_vec()))
            }
            NamedGroup::SECP256R1 => {
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, peer_point)
                    .map_err(|_| Error::Decode)?;
                let ss = self
                    .p256
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?;
                Ok((ss, self.p256.public_key().to_sec1()))
            }
            _ => Err(Error::HandshakeFailure),
        }
    }
}

/// One decoded inbound message.
enum Incoming {
    Handshake(Vec<u8>),
    ApplicationData,
    Alert(Alert),
}

fn parse_alert(body: &[u8]) -> Result<Incoming, Error> {
    if body.len() != 2 {
        return Err(Error::Decode);
    }
    Ok(Incoming::Alert(Alert {
        fatal: body[0] == 2,
        description: AlertDescription::from_u8(body[1]),
    }))
}

/// Parses a TLS 1.2 `Certificate` message body (RFC 5246 §7.4.2): a single
/// `certificate_list<0..2^24-1>` of `ASN.1Cert<1..2^24-1>`. No per-cert
/// extensions (unlike TLS 1.3).
pub(super) fn parse_certificate_list_12(body: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut c = ReadCursor::new(body);
    let list = c.vec_u24()?;
    c.expect_empty()?;
    let mut entries = ReadCursor::new(list);
    let mut certs = Vec::new();
    while !entries.is_empty() {
        let cert = entries.vec_u24()?.to_vec();
        if cert.is_empty() {
            return Err(Error::BadCertificate);
        }
        certs.push(cert);
    }
    Ok(certs)
}

/// Builds a `Finished` handshake message body from a 12-byte `verify_data`.
fn build_finished(verify_data: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 12);
    out.push(hs_type::FINISHED);
    out.extend_from_slice(&[0, 0, 12]); // u24 length
    out.extend_from_slice(verify_data);
    out
}

/// Maps an internal error to the alert to send the peer.
fn alert_for(error: &Error) -> AlertDescription {
    match error {
        Error::Decode => AlertDescription::DecodeError,
        Error::UnexpectedMessage => AlertDescription::UnexpectedMessage,
        Error::BadRecordMac => AlertDescription::BadRecordMac,
        Error::BadCertificate => AlertDescription::BadCertificate,
        Error::UnsupportedVersion => AlertDescription::ProtocolVersion,
        Error::PeerMisbehaved | Error::InappropriateState | Error::IllegalParameter => {
            AlertDescription::IllegalParameter
        }
        Error::RecordOverflow => AlertDescription::RecordOverflow,
        Error::TooManyRecords => AlertDescription::InternalError,
        Error::NoApplicationProtocol => AlertDescription::NoApplicationProtocol,
        Error::DecryptError => AlertDescription::DecryptError,
        Error::CertificateRequired => AlertDescription::CertificateRequired,
        _ => AlertDescription::HandshakeFailure,
    }
}

#[cfg(feature = "std")]
impl super::stream::ConnectionIo for ClientConnection12 {
    fn read_tls(&mut self, bytes: &[u8]) {
        ClientConnection12::read_tls(self, bytes)
    }
    fn write_tls(&mut self) -> Vec<u8> {
        ClientConnection12::write_tls(self)
    }
    fn process_new_packets(&mut self) -> Result<(), Error> {
        ClientConnection12::process_new_packets(self)
    }
    fn is_handshaking(&self) -> bool {
        ClientConnection12::is_handshaking(self)
    }
    fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        ClientConnection12::send_application_data(self, data)
    }
    fn take_received_plaintext(&mut self) -> Vec<u8> {
        ClientConnection12::take_received_plaintext(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::tls::codec::{ClientHello, ExtensionType, hs_type, read_record};

    /// The first emitted bytes are a TLS 1.2 ClientHello carrying our six
    /// ECDHE-AEAD suites and the required extensions.
    #[test]
    fn client12_build_client_hello() {
        let mut rng = HmacDrbg::<Sha256>::new(b"c12-ch", b"nonce", &[]);
        let cfg = ClientConfig12::new(RootCertStore::new());
        let mut c = ClientConnection12::new(cfg, "example.com", &mut rng);
        assert!(c.is_handshaking());

        let out = c.write_tls();
        let rec = read_record(&out).unwrap().unwrap();
        assert_eq!(rec.content_type, ContentType::Handshake);
        assert_eq!(rec.len, out.len());

        let mut cur = ReadCursor::new(rec.fragment);
        assert_eq!(cur.u8().unwrap(), hs_type::CLIENT_HELLO);
        let body = cur.vec_u24().unwrap();
        let ch = ClientHello::decode(body).unwrap();

        // Six AEAD-ECDHE suites — see SUITES_12 order in this module.
        assert_eq!(ch.cipher_suites.len(), 6);
        assert!(ch.session_id.is_empty());

        // The required extension set: SNI, supported_groups,
        // signature_algorithms, ec_point_formats, renegotiation_info,
        // and extended_master_secret (RFC 7627 §5.1 — always offered).
        for ty in [
            ExtensionType::SERVER_NAME,
            ExtensionType::SUPPORTED_GROUPS,
            ExtensionType::SIGNATURE_ALGORITHMS,
            ExtensionType::EC_POINT_FORMATS,
            ExtensionType::RENEGOTIATION_INFO,
            ExtensionType::EXTENDED_MASTER_SECRET,
        ] {
            assert!(
                ext::find(&ch.extensions, ty).is_some(),
                "missing extension {ty:?}",
            );
        }
        // EMS must have an empty body (RFC 7627 §5.1).
        let ems_body = ext::find(&ch.extensions, ExtensionType::EXTENDED_MASTER_SECRET).unwrap();
        assert!(ems_body.is_empty(), "EMS body must be empty");
        // We must NOT send `supported_versions` from a TLS 1.2 client.
        assert!(ext::find(&ch.extensions, ExtensionType::SUPPORTED_VERSIONS).is_none());

        // The `renegotiation_info` body is exactly `[0x00]` (an empty inner
        // `renegotiated_connection` vector).
        let r = ext::find(&ch.extensions, ExtensionType::RENEGOTIATION_INFO).unwrap();
        assert_eq!(r, &[0u8]);
    }

    /// Build a synthetic ServerHello record (handshake type, plaintext) with
    /// the given cipher suite and the given list of extensions; returns the
    /// full record bytes (5-byte header + payload).
    fn synth_sh_record(suite: CipherSuite, exts: Vec<(ExtensionType, Vec<u8>)>) -> Vec<u8> {
        use crate::tls::codec::write_record;
        let sh = crate::tls::codec::ServerHello {
            random: [0x11u8; 32],
            session_id: Vec::new(),
            cipher_suite: suite,
            extensions: exts,
        };
        let body = sh.encode();
        let mut rec = Vec::new();
        write_record(
            &mut rec,
            ContentType::Handshake,
            ProtocolVersion::TLSv1_2,
            &body,
        );
        rec
    }

    /// A ServerHello picking an unsupported cipher suite is rejected with
    /// `HandshakeFailure`.
    #[test]
    fn client12_rejects_unknown_suite() {
        let mut rng = HmacDrbg::<Sha256>::new(b"c12-bad-suite", b"nonce", &[]);
        let mut c = ClientConnection12::new(
            ClientConfig12::new(RootCertStore::new()),
            "example.com",
            &mut rng,
        );
        let _ = c.write_tls();

        // Carry a `renegotiation_info` empty so we don't trip THAT check;
        // the suite check should fire first.
        let exts = alloc::vec![(ExtensionType::RENEGOTIATION_INFO, alloc::vec![0u8])];
        let sh = synth_sh_record(CipherSuite(0xFEFE), exts);
        c.read_tls(&sh);
        assert!(matches!(
            c.process_new_packets(),
            Err(Error::HandshakeFailure)
        ));
    }

    /// RFC 5746 §3.4: a ServerHello missing `renegotiation_info` is rejected.
    #[test]
    fn client12_rejects_missing_renegotiation_info() {
        let mut rng = HmacDrbg::<Sha256>::new(b"c12-no-reneg", b"nonce", &[]);
        let mut c = ClientConnection12::new(
            ClientConfig12::new(RootCertStore::new()),
            "example.com",
            &mut rng,
        );
        let _ = c.write_tls();

        // Pick a suite we offered (AES-128-GCM/SHA256/RSA) but emit NO
        // renegotiation_info — should be rejected.
        let sh = synth_sh_record(
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            Vec::new(),
        );
        c.read_tls(&sh);
        assert!(matches!(
            c.process_new_packets(),
            Err(Error::HandshakeFailure)
        ));
    }

    /// A ServerHello selecting TLS 1.3 via `supported_versions` from a 1.2
    /// client is rejected (we never offered the extension, so a server
    /// echoing one is misbehaving).
    #[test]
    fn client12_rejects_tls13_supported_versions() {
        let mut rng = HmacDrbg::<Sha256>::new(b"c12-1.3-downgrade", b"nonce", &[]);
        let mut c = ClientConnection12::new(
            ClientConfig12::new(RootCertStore::new()),
            "example.com",
            &mut rng,
        );
        let _ = c.write_tls();

        let exts = alloc::vec![
            (ExtensionType::RENEGOTIATION_INFO, alloc::vec![0u8]),
            (
                ExtensionType::SUPPORTED_VERSIONS,
                alloc::vec![0x03u8, 0x04u8],
            ),
        ];
        let sh = synth_sh_record(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, exts);
        c.read_tls(&sh);
        assert!(matches!(
            c.process_new_packets(),
            Err(Error::UnsupportedVersion)
        ));
    }
}
