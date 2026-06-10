// Many methods/fields on the internal `ClientConfig` / `StoredSession` /
// `ClientCertConfig` builders are reachable only through the unified
// `tls::Config` façade now; silence the dead-code lint here.
#![allow(dead_code, unreachable_pub)]

//! The TLS 1.3 client handshake state machine.
//!
//! [`ClientConnection`] drives a full 1-RTT client handshake over the sans-I/O
//! [`ConnectionCore`]: it emits a `ClientHello`, processes the server flight
//! (`ServerHello`, then the encrypted `EncryptedExtensions`, `Certificate`,
//! `CertificateVerify`, `Finished`), authenticates the server, and sends its
//! own `Finished`, after which application data flows under the application
//! traffic keys.

use super::common::{ConnectionCore, Incoming};
use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{
    BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, CurveId, Ed448PrivateKey,
    Ed25519PrivateKey,
};
use crate::hash::{Hmac, Sha256, Sha384, Sha512};
use crate::mlkem::{CIPHERTEXT_BYTES, MlKem768Ciphertext, MlKem768DecapsKey};
use crate::rng::RngCore;
use crate::rsa::BoxedRsaPrivateKey;
use crate::signature_registry::SignaturePolicy;
use crate::tls::codec::extension as ext;
use crate::tls::codec::{
    CipherSuite, ClientHello, ExtensionType, KeyUpdate, NamedGroup, NewSessionTicket as NstWire,
    Random, ReadCursor, ServerHello, SignatureScheme, hs_type, read_handshake, with_len_u16,
    with_len_u24,
};
use crate::tls::crypto::{
    HashAlg, KeySchedule, RecordCrypter, Secret, SuiteParams, binder_finished_key,
    certificate_verify_content, finished_verify_data, lookup_suite, next_traffic_secret,
    psk_from_resumption, tls_exporter, verify_signature,
};
use crate::tls::keylog::KeyLog;
use crate::tls::pki::{CrlStore, RootCertStore, verify_chain_with_crls, verify_hostname};
use crate::tls::{AlertDescription, Error};
use crate::x509::{AnyPublicKey, Certificate, Time};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ct::ConstantTimeEq;
#[cfg(feature = "ech")]
use crate::hpke::SenderContext;
#[cfg(feature = "ech")]
use crate::tls::ech::HpkeSymCipherSuite;

/// A client certificate + signing key, set on [`ClientConfig`] to satisfy a
/// server's `CertificateRequest` (mTLS, RFC 8446 §4.3.2).
pub struct ClientCertConfig {
    /// Certificate chain (leaf first), DER-encoded.
    pub(crate) chain: Vec<Vec<u8>>,
    /// Signing key paired with the leaf certificate.
    pub(crate) key: ClientKey,
}

/// The client's signing key, mirrors the server-side variants.
///
/// See [`ServerKey`](super::server::ServerKey) for the rationale on
/// suppressing `clippy::large_enum_variant` — same one-instance-per-config
/// shape, so boxing would add indirection without savings.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ClientKey {
    /// RSA-PSS. Not yet wired (requires an RNG for the PSS salt); accepted
    /// to keep the public API parallel to the server-side configuration.
    #[allow(dead_code)]
    Rsa(BoxedRsaPrivateKey),
    Ecdsa(BoxedEcdsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
    /// An Ed448 client key (TLS 1.3 only).
    Ed448(Ed448PrivateKey),
    /// An ML-DSA-44 client key (FIPS 204, draft-ietf-tls-mldsa).
    /// Client-side ML-DSA `CertificateVerify` signing is deterministic —
    /// the client doesn't thread an RNG through the handshake state machine.
    MlDsa44(crate::mldsa::MlDsa44PrivateKey),
    /// An ML-DSA-65 client key.
    MlDsa65(crate::mldsa::MlDsa65PrivateKey),
    /// An ML-DSA-87 client key.
    MlDsa87(crate::mldsa::MlDsa87PrivateKey),
}

impl ClientCertConfig {
    /// A client cert + RSA-PSS signing key.
    pub fn with_rsa(chain: Vec<Vec<u8>>, key: BoxedRsaPrivateKey) -> Self {
        ClientCertConfig {
            chain,
            key: ClientKey::Rsa(key),
        }
    }

    /// A client cert + ECDSA signing key.
    pub fn with_ecdsa(chain: Vec<Vec<u8>>, key: BoxedEcdsaPrivateKey) -> Self {
        ClientCertConfig {
            chain,
            key: ClientKey::Ecdsa(key),
        }
    }

    /// A client cert + Ed25519 signing key.
    pub fn with_ed25519(chain: Vec<Vec<u8>>, key: Ed25519PrivateKey) -> Self {
        ClientCertConfig {
            chain,
            key: ClientKey::Ed25519(key),
        }
    }

    /// A client cert + Ed448 signing key.
    pub fn with_ed448(chain: Vec<Vec<u8>>, key: Ed448PrivateKey) -> Self {
        ClientCertConfig {
            chain,
            key: ClientKey::Ed448(key),
        }
    }

    /// A client cert + ML-DSA-44 signing key (NIST FIPS 204).
    pub fn with_mldsa44(chain: Vec<Vec<u8>>, key: crate::mldsa::MlDsa44PrivateKey) -> Self {
        ClientCertConfig {
            chain,
            key: ClientKey::MlDsa44(key),
        }
    }

    /// A client cert + ML-DSA-65 signing key.
    pub fn with_mldsa65(chain: Vec<Vec<u8>>, key: crate::mldsa::MlDsa65PrivateKey) -> Self {
        ClientCertConfig {
            chain,
            key: ClientKey::MlDsa65(key),
        }
    }

    /// A client cert + ML-DSA-87 signing key.
    pub fn with_mldsa87(chain: Vec<Vec<u8>>, key: crate::mldsa::MlDsa87PrivateKey) -> Self {
        ClientCertConfig {
            chain,
            key: ClientKey::MlDsa87(key),
        }
    }

    fn signature_scheme(&self) -> SignatureScheme {
        Self::signature_scheme_for(&self.key)
    }

    /// Internal helper exposed to the TLS 1.2 client: the IANA-blessed
    /// signature scheme for a given [`ClientKey`]. Same code points as TLS
    /// 1.3 (the registry is shared).
    pub(super) fn signature_scheme_for(key: &ClientKey) -> SignatureScheme {
        match key {
            ClientKey::Rsa(_) => SignatureScheme::RSA_PSS_RSAE_SHA256,
            ClientKey::Ecdsa(k) => match k.curve() {
                CurveId::P256 => SignatureScheme::ECDSA_SECP256R1_SHA256,
                CurveId::P384 => SignatureScheme::ECDSA_SECP384R1_SHA384,
                CurveId::P521 => SignatureScheme::ECDSA_SECP521R1_SHA512,
                CurveId::Secp256k1 | CurveId::Sm2p256v1 => SignatureScheme::ECDSA_SECP256R1_SHA256,
            },
            ClientKey::Ed25519(_) => SignatureScheme::ED25519,
            ClientKey::Ed448(_) => SignatureScheme::ED448,
            ClientKey::MlDsa44(_) => SignatureScheme::MLDSA44,
            ClientKey::MlDsa65(_) => SignatureScheme::MLDSA65,
            ClientKey::MlDsa87(_) => SignatureScheme::MLDSA87,
        }
    }

    /// Access for the TLS 1.2 client (uses the same struct for mTLS).
    pub(super) fn chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    /// Access for the TLS 1.2 client.
    pub(super) fn key(&self) -> &ClientKey {
        &self.key
    }
}

/// Configuration for a TLS client.
///
/// `pub(crate)`: external users build a [`crate::tls::Config`] and call
/// [`crate::tls::Connection::client`], which derives this internal config.
pub(crate) struct ClientConfig {
    /// Trust anchors used to authenticate the server certificate chain.
    pub roots: RootCertStore,
    /// When `false`, the certificate chain, validity period, and host name are
    /// not checked (the `CertificateVerify` signature is still verified against
    /// the presented leaf key, and the leaf is still rejected if malformed).
    /// Intended for tests and pinned-key scenarios.
    pub verify_certificates: bool,
    /// The time used for validity-period checks. Defaults (`None`) to the
    /// system clock under the `std` feature; set it explicitly for `no_std`
    /// targets or for reproducible verification.
    pub verification_time: Option<Time>,
    /// ALPN protocols to offer (RFC 7301), in preference order. Empty
    /// suppresses the extension. Example: `[b"h2".to_vec(), b"http/1.1".to_vec()]`.
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Optional restriction on the offered TLS 1.3 cipher suites (IANA wire
    /// IDs, in preference order). `None` offers the full supported set. See
    /// [`crate::tls::Config::cipher_suites`].
    pub cipher_suites: Option<Vec<u16>>,
    /// `record_size_limit` (RFC 8449) we advertise — the largest plaintext
    /// fragment the server may send us. `None` suppresses the extension; the
    /// peer is then free to use the TLS 1.3 default of 2¹⁴ bytes.
    pub record_size_limit: Option<u16>,
    /// A previously stored session for PSK resumption (RFC 8446 §2.2 / §4.2.11).
    /// When set, the ClientHello carries `pre_shared_key` and
    /// `psk_key_exchange_modes`; on acceptance the handshake uses the resumed
    /// PSK combined with ECDHE (`psk_dhe_ke`).
    pub session: Option<StoredSession>,
    /// Client certificate + signing key, used to satisfy a server-issued
    /// `CertificateRequest` (mTLS). `None` means we won't present a cert; if
    /// the server requires one we'll abort with `certificate_required`.
    pub client_cert: Option<ClientCertConfig>,
    /// Whitelist of signature algorithms the client accepts in chain
    /// signatures and in the server's `CertificateVerify`. Defaults to
    /// [`SignaturePolicy::modern`]: the modern IANA-blessed set with
    /// RSA ≥ 2048 bits.
    pub signature_policy: SignaturePolicy,
    /// CRLs consulted during chain validation. Empty by default: callers
    /// opt in via [`ClientConfig::with_crls`]. Coverage is advisory — a
    /// missing CRL never causes a chain to be rejected.
    pub crls: CrlStore,
    /// RFC 7250 §3 `server_certificate_type` preference list offered in the
    /// ClientHello. `vec![0]` (X.509 only) is the default and suppresses the
    /// extension altogether. Set to e.g. `vec![2, 0]` to prefer raw public
    /// keys with X.509 fallback.
    pub server_cert_type_preference: Vec<u8>,
    /// Same as `server_cert_type_preference` but for the mTLS path: which
    /// certificate types the client is willing to SEND.
    pub client_cert_type_preference: Vec<u8>,
    /// Allowlist of bare `SubjectPublicKeyInfo` DER bytes accepted as the
    /// server's identity when RawPublicKey is the negotiated server-cert
    /// type. Empty disables the path even if the extension list advertises
    /// it (so the server's RawPublicKey would be rejected at receive time).
    pub expected_raw_public_keys: Vec<Vec<u8>>,
    /// Optional [`KeyLog`] sink (NSS `SSLKEYLOGFILE` format). When `Some`,
    /// the engine logs every derived traffic / master secret as it
    /// progresses through the handshake.
    pub key_log: Option<Arc<dyn KeyLog>>,
    /// ECH client configuration (draft-ietf-tls-esni-22). `None` (the
    /// default) emits no `encrypted_client_hello` extension. `Some` —
    /// either GREASE or a real `ECHConfigList` — emits a bit-shape-identical
    /// outer-form extension. The real-ECH inner/outer split + state
    /// machine integration lands in a follow-up under the same Phase 5
    /// banner; today the wire shape is GREASE in either case.
    #[cfg(feature = "ech")]
    pub ech: Option<crate::tls::ech::EchClient>,
    /// RFC 8879 `CertificateCompressionAlgorithm` IDs the client can
    /// DECOMPRESS (covering the server's `Certificate`) and is willing
    /// to USE when sending its own mTLS `Certificate`. Default `[1]`
    /// (zlib). Empty disables the path entirely (no extension on the
    /// wire; any `CompressedCertificate` received is rejected).
    #[cfg(feature = "cert-compression")]
    pub cert_compression_algorithms: Vec<u16>,
}

impl ClientConfig {
    /// A configuration trusting the given roots, with certificate verification
    /// enabled.
    pub fn new(roots: RootCertStore) -> Self {
        ClientConfig {
            roots,
            verify_certificates: true,
            verification_time: None,
            alpn_protocols: Vec::new(),
            cipher_suites: None,
            record_size_limit: None,
            session: None,
            client_cert: None,
            signature_policy: SignaturePolicy::modern(),
            crls: CrlStore::new(),
            server_cert_type_preference: alloc::vec![0u8],
            client_cert_type_preference: alloc::vec![0u8],
            expected_raw_public_keys: Vec::new(),
            key_log: None,
            #[cfg(feature = "ech")]
            ech: None,
            #[cfg(feature = "cert-compression")]
            cert_compression_algorithms: crate::tls::cert_compression::default_algorithms(),
        }
    }

    /// Sets the RFC 7250 `server_certificate_type` preference list offered
    /// in the ClientHello. `[0]` (the default) means X.509 only; the
    /// extension is suppressed entirely on the wire so non-7250-aware peers
    /// don't trip over it. To opt into raw public keys use `[2]`
    /// (RawPublicKey only) or `[2, 0]` (prefer RawPublicKey, accept X.509).
    pub fn with_server_cert_type_preference(mut self, prefs: Vec<u8>) -> Self {
        self.server_cert_type_preference = if prefs.is_empty() {
            alloc::vec![0u8]
        } else {
            prefs
        };
        self
    }

    /// Sets the RFC 7250 `client_certificate_type` preference list (mTLS).
    /// Same semantics as
    /// [`with_server_cert_type_preference`](Self::with_server_cert_type_preference).
    ///
    /// Note: the client side currently only emits X.509 `Certificate`
    /// messages; offering `RawPublicKey` here is wired through negotiation
    /// but the client's `send_client_certificate` path does not yet derive
    /// an SPKI from the configured private key. Production mTLS deployments
    /// should leave this at the default `[0]`.
    pub fn with_client_cert_type_preference(mut self, prefs: Vec<u8>) -> Self {
        self.client_cert_type_preference = if prefs.is_empty() {
            alloc::vec![0u8]
        } else {
            prefs
        };
        self
    }

    /// Appends a bare `SubjectPublicKeyInfo` DER to the allowlist of
    /// raw-public-key SPKIs accepted from the server (RFC 7250 §4.2). Only
    /// consulted when `RawPublicKey` is the negotiated server-cert type.
    pub fn add_expected_raw_public_key(mut self, spki_der: Vec<u8>) -> Self {
        self.expected_raw_public_keys.push(spki_der);
        self
    }

    /// Installs a [`CrlStore`] consulted during chain validation. The
    /// store is advisory: a covering CRL signed by an issuer in the chain
    /// rejects the cert; anything else is silently ignored.
    pub fn with_crls(mut self, crls: CrlStore) -> Self {
        self.crls = crls;
        self
    }

    /// Replaces the signature-algorithm whitelist. Defaults to
    /// [`SignaturePolicy::modern`]; tighten or widen it for legacy interop,
    /// PQC-only deployments, etc.
    pub fn with_signature_policy(mut self, policy: SignaturePolicy) -> Self {
        self.signature_policy = policy;
        self
    }

    /// Offers the given ALPN protocols. The first match in the server's
    /// preference order is selected; if there's no overlap, the server
    /// sends `no_application_protocol`.
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Advertises `record_size_limit = limit` (RFC 8449). Must be in
    /// `64..=2^14 + 1`.
    pub fn with_record_size_limit(mut self, limit: u16) -> Self {
        self.record_size_limit = Some(limit);
        self
    }

    /// Primes the next handshake to attempt PSK session resumption against
    /// `session`. The session's cipher-suite hash fixes which suites can be
    /// offered (only suites matching that hash will be sent).
    pub fn with_session(mut self, session: StoredSession) -> Self {
        self.session = Some(session);
        self
    }

    /// Sets the client certificate + signing key for mTLS. The client
    /// presents this chain whenever the server emits `CertificateRequest`.
    pub fn with_client_cert(mut self, cert: ClientCertConfig) -> Self {
        self.client_cert = Some(cert);
        self
    }

    /// Sets the RFC 8879 `compress_certificate` algorithm list — IDs the
    /// client can DECOMPRESS (covering the server's `Certificate`) and is
    /// itself willing to USE when sending its own mTLS `Certificate`.
    /// Default `[1]` (zlib). Empty disables the path entirely on the wire.
    #[cfg(feature = "cert-compression")]
    pub fn with_cert_compression_algorithms(mut self, algorithms: Vec<u16>) -> Self {
        self.cert_compression_algorithms = algorithms;
        self
    }
}

/// A resumable session, returned by [`ClientConnection::take_session`] after a
/// completed handshake. Pass it back via [`ClientConfig::with_session`] to
/// attempt PSK resumption on the next connection to the same server.
#[derive(Clone, Debug)]
pub struct StoredSession {
    /// The server we connected to (used to scope sessions in the caller's
    /// cache; the wire identity is the ticket bytes alone).
    pub server_name: String,
    /// The ticket bytes (`identity` in the wire format), to be re-presented in
    /// the next ClientHello.
    pub ticket: Vec<u8>,
    /// The PSK derived from `resumption_master_secret` and the ticket's nonce.
    pub psk: Vec<u8>,
    /// Randomizer the server added; XORed into the reported ticket age to
    /// avoid linkability across resumptions.
    pub age_add: u32,
    /// Lifetime hint, in seconds; the ticket should not be used past this
    /// many seconds after `received_at`.
    pub lifetime_seconds: u32,
    /// Wall-clock time the NewSessionTicket arrived (for age computation).
    pub received_at: Time,
    /// `max_early_data_size` from the ticket, when the server advertised
    /// 0-RTT capability.
    pub max_early_data_size: Option<u32>,
    /// ALPN protocol negotiated on the originating connection, if any.
    pub negotiated_alpn: Option<Vec<u8>>,
    /// Hash function of the original cipher suite (PSK binders and key
    /// schedule are tied to it).
    pub cipher_suite_hash: HashAlg,
}

/// The current time from the system clock, when available.
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

/// The client handshake progress.
#[derive(PartialEq, Eq)]
enum State {
    WaitServerHello,
    WaitEncryptedExtensions,
    WaitCertificate,
    WaitCertificateVerify,
    WaitFinished,
    Connected,
    Closed,
}

/// A TLS 1.3 client connection.
pub struct ClientConnection {
    core: ConnectionCore,
    config: ClientConfig,
    server_name: String,
    state: State,
    /// True once the peer's close_notify alert has been processed. Lets
    /// callers distinguish a graceful TLS shutdown from an abrupt
    /// transport close (truncation attack) — `state` alone can't, since
    /// `fail()` also parks the connection in [`State::Closed`].
    received_close_notify: bool,

    x25519: X25519PrivateKey,
    p256: BoxedEcdhPrivateKey,
    p384: BoxedEcdhPrivateKey,
    mlkem: MlKem768DecapsKey,

    /// CH1 state retained for HelloRetryRequest replay (RFC 8446 §4.1.2):
    /// CH2 must reuse the same client_random and offered_groups, narrowed to
    /// the HRR-selected group.
    client_random: Random,
    offered_suites: Vec<CipherSuite>,
    offered_groups: Vec<NamedGroup>,
    /// Set to `true` after a single HelloRetryRequest has been processed; a
    /// second one is rejected (RFC 8446 §4.1.4).
    hrr_processed: bool,
    /// The `key_share` group the server selected in a HelloRetryRequest, if the
    /// HRR carried one. RFC 8446 §4.1.4: the real ServerHello that follows the
    /// HRR MUST select this same group; any other group is a protocol
    /// violation. `None` when no HRR (or an HRR without key_share) was seen.
    hrr_selected_group: Option<NamedGroup>,
    /// The cipher suite the server selected in a HelloRetryRequest. RFC 8446
    /// §4.1.4: the ServerHello that follows MUST carry the same
    /// `cipher_suite`; re-checking only "was it offered" would let the
    /// server pick one suite's hash for the HRR transcript and then switch
    /// suites in SH. `None` when no HRR was seen.
    hrr_selected_suite: Option<CipherSuite>,

    suite: Option<SuiteParams>,
    ks: Option<KeySchedule>,
    client_hs_secret: Option<Secret>,
    server_hs_secret: Option<Secret>,

    /// Current write-side (`client_application_traffic_secret_N`) — stepped by
    /// each outgoing `KeyUpdate`.
    client_app_secret: Option<Secret>,
    /// Current read-side (`server_application_traffic_secret_N`) — stepped by
    /// each incoming `KeyUpdate`.
    server_app_secret: Option<Secret>,
    /// `exporter_master_secret` for [`Self::tls_exporter`] (RFC 8446 §7.5).
    exporter_secret: Option<Secret>,

    cert_chain: Vec<Vec<u8>>,
    /// Per-connection CRL store populated from the leaf's stapled
    /// `CRL_RESPONSE` extension. Empty when the server doesn't staple.
    stapled_crls: crate::tls::pki::CrlStore,
    /// RFC 6066 §8 + RFC 8446 §4.4.2.1: the OCSP response stapled on the
    /// leaf's per-cert `status_request` extension. Validated against the
    /// chain in `on_certificate_verify`; `None` when the server didn't
    /// staple.
    peer_ocsp_response: Option<Vec<u8>>,
    /// RFC 7250 §4.2: the server's selected cert type (echoed in EE).
    /// Defaults to `X509 = 0`; flipped to `RAW_PUBLIC_KEY = 2` only when
    /// the server's EncryptedExtensions actually carries
    /// `server_certificate_type` with that value.
    negotiated_server_cert_type: u8,
    /// RFC 7250 §4.2: the server's selected mTLS cert type (the type the
    /// CLIENT must send if `CertificateRequest` arrives). Defaults to
    /// `X509 = 0`.
    negotiated_client_cert_type: u8,
    leaf_key: Option<AnyPublicKey>,

    /// Most recent `NewSessionTicket` from the peer (RFC 8446 §4.6.1). Real
    /// servers (Cloudflare, Google, …) commonly send one immediately after
    /// `Finished`; we accept and stash it. Used by future PSK resumption.
    last_ticket: Option<ReceivedSessionTicket>,

    /// The ALPN protocol the server picked from our advertised list, if any.
    /// Populated from the server's `EncryptedExtensions`.
    alpn_negotiated: Option<Vec<u8>>,

    /// PSK we offered in CH (if `config.session` was set). When the server
    /// echoes `pre_shared_key` in SH with `selected_identity = 0`, we
    /// seed the key schedule from this PSK.
    psk_offered: Option<PskOfferState>,
    /// Set to `true` if the server accepted our PSK offer. Drives the
    /// resumption-specific code paths after SH.
    psk_accepted: bool,
    /// Wall-clock time at which the handshake started (used as the wall clock
    /// for the resulting [`StoredSession::received_at`]).
    handshake_start: Option<Time>,
    /// The most recent session built from a NewSessionTicket — ready to be
    /// moved out via [`Self::take_session`].
    stored_session: Option<StoredSession>,
    /// `resumption_master_secret`, computed at our Finished. Future
    /// NewSessionTicket messages derive their PSK from this.
    rms: Option<Secret>,

    /// True if we offered 0-RTT (`early_data` extension in CH); set when the
    /// session ticket carried a non-zero `max_early_data_size`.
    early_data_offered: bool,
    /// True if the server's EncryptedExtensions confirmed 0-RTT acceptance.
    early_data_accepted: bool,
    /// `client_early_traffic_secret`, computed at CH emission. The write
    /// side is keyed from this for the early-data records and the trailing
    /// `EndOfEarlyData` message.
    cets: Option<Secret>,
    /// Cached client-handshake-traffic-secret to install after we send EOED
    /// (or right at EE time if 0-RTT was rejected). Otherwise we install it
    /// at SH time.
    deferred_client_hs_secret: Option<Secret>,
    /// mTLS: set when the server sent a `CertificateRequest` between EE and
    /// its `Certificate`. Drives client-cert emission after server Finished.
    cert_request_received: bool,

    /// Which framing mode this engine runs in (TLS / DTLS / QUIC).
    ///
    /// In `Tls` mode (the default) the engine emits TLS records and behaves
    /// identically to pre-Phase-3 builds. In `Quic` mode the engine bypasses
    /// the record layer entirely: every handshake message is surfaced to
    /// the QUIC layer through `hooks`, no `ChangeCipherSpec` is emitted,
    /// and the record crypter is never installed (RFC 9001 §4–§5, §8.4).
    engine_mode: super::super::quic_hooks::EngineMode,
    /// QUIC-layer callback set (Phase 4+). `Some` only in `EngineMode::Quic`.
    hooks: Option<super::super::quic_hooks::BoxedHooks>,
    /// Whether we have already seen the server's `quic_transport_parameters`
    /// extension and dispatched it via [`QuicHooks::on_peer_transport_params`].
    /// Used to enforce the RFC 9001 §8.2 "at most once" rule on top of the
    /// existing TLS extension-uniqueness check.
    peer_quic_params_seen: bool,

    /// Per-handshake ECH state retained across CH emission (so SH
    /// processing can verify the accept signal over `Hash(inner_CH ||
    /// zero-tail SH)`) and EE processing (so a rejection can be
    /// surfaced with the server's `retry_configs`). `None` outside of
    /// the real-ECH attempt path. See [`ClientEchState`].
    #[cfg(feature = "ech")]
    ech_state: Option<ClientEchState>,

    /// Per-connection private seed mixed into the ECH GREASE expansion
    /// so the resulting payload is uncorrelated with anything a passive
    /// observer can see. Drawn from the RNG once at construction; never
    /// emitted on the wire. Without this seed the GREASE bytes would be
    /// recomputable by an observer who saw the public ClientHello
    /// random — defeating GREASE's only job.
    #[cfg(feature = "ech")]
    ech_grease_seed: [u8; 32],
}

/// Client-side per-handshake ECH state, populated when emitting a CH
/// under [`crate::tls::ech::EchClientMode::Real`] and consumed when
/// processing the server's ServerHello (to verify the accept signal
/// and swap the transcript from outer to inner) and
/// EncryptedExtensions (to surface a rejection with `retry_configs`).
#[cfg(feature = "ech")]
pub(crate) struct ClientEchState {
    /// The encoded **inner** CH handshake message bytes (header
    /// included), the bytes the server processes after HPKE-decap.
    /// Retained so we can recompute the accept signal and so we can
    /// swap them into the transcript when the server confirms accept.
    pub(crate) inner_ch_bytes: Vec<u8>,
    /// Set once the ServerHello has been processed and we know
    /// whether the server accepted ECH (the accept-confirmation
    /// signal in `random[24..32]` matched our recomputed signal) or
    /// rejected it. `None` between CH emission and SH receipt.
    pub(crate) outcome: Option<EchOutcome>,
    /// HPKE sender context retained for the HRR retry path. CH1's
    /// `seal` advanced `seq` to 1; CH2-outer's seal consumes it at
    /// `seq = 1` per draft §7.2.2. `None` on GREASE-only ECH.
    pub(crate) sender: Option<SenderContext>,
    /// Symmetric suite advertised in CH1-outer's
    /// `encrypted_client_hello`. CH2-outer MUST echo the same. `None`
    /// on GREASE-only ECH.
    pub(crate) sym: Option<HpkeSymCipherSuite>,
    /// `config_id` selected for CH1's HPKE setup. CH2-outer echoes it.
    pub(crate) config_id: Option<u8>,
    /// CH1-inner's `random`, used both as the IKM for verifying the
    /// HRR ECH confirmation signal (draft §7.2.1) and for the SH
    /// signal (§7.2). `None` on GREASE-only ECH.
    pub(crate) inner_ch1_random: Option<[u8; 32]>,
    /// `maximum_name_length` from the selected `ECHConfig.contents`,
    /// needed to re-pad CH2-inner identically on the HRR retry path.
    /// `None` on GREASE-only ECH.
    pub(crate) maximum_name_length: Option<u8>,
    /// `true` once the live transcript has been swapped from CH1-outer
    /// to the inner sequence. Set by the HRR retry path when the HRR's
    /// `encrypted_client_hello` confirmation signal validates; the SH
    /// processing then knows to hash the SH-with-zero-tail against the
    /// live transcript via `hash_with_appended` instead of recomputing
    /// from `inner_ch_bytes` (which alone wouldn't include the HRR or
    /// CH2-inner messages the SH binds to).
    pub(crate) inner_transcript_swapped: bool,
    /// The `ECHConfig.public_name` the outer CH used as its SNI. On ECH
    /// rejection the handshake continues under the *outer* identity, so
    /// the server certificate is verified against this name — not the
    /// inner (real) `server_name` — per draft-ietf-tls-esni-22 §6.1.6.
    pub(crate) outer_public_name: String,
    /// `retry_configs` bytes lifted from the server's
    /// `EncryptedExtensions` on rejection (draft §6.1.6 / §7.1). They are
    /// NOT surfaced to the caller at EE time: EncryptedExtensions is only
    /// handshake-traffic protected, so an active attacker could plant
    /// configs of its own. The bytes are held here until the server's
    /// CertificateVerify + Finished authenticate the `public_name`
    /// identity, and only then surfaced via [`Error::EchRejected`].
    pub(crate) retry_configs: Option<Vec<u8>>,
}

/// What the client learnt about ECH from the server's ServerHello.
/// `Accepted` means the SH accept-confirmation signal matched (the
/// real-ECH transcript is in use); `Rejected` means it didn't (the
/// handshake continues under the outer transcript and the EE may
/// carry `retry_configs`).
#[cfg(feature = "ech")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EchOutcome {
    Accepted,
    Rejected,
}

/// What the client retains across CH emission so it can verify the server's
/// PSK selection and seed the key schedule when the PSK is accepted.
struct PskOfferState {
    /// The PSK bytes (derived from a prior session's
    /// `resumption_master_secret`).
    psk: Vec<u8>,
    /// The hash function fixed by the original session's cipher suite.
    hash: HashAlg,
}

/// A `NewSessionTicket` received from the server, exposed for inspection and
/// (eventually) PSK-based resumption.
#[derive(Clone, Debug)]
pub struct ReceivedSessionTicket {
    /// Lifetime hint in seconds (RFC 8446 §4.6.1 caps at 7 days = 604800).
    pub lifetime_seconds: u32,
    /// Randomizer added to the obfuscated ticket age.
    pub age_add: u32,
    /// Per-ticket nonce used by `HKDF-Expand-Label(rms, "resumption", nonce)`
    /// to derive the PSK.
    pub nonce: Vec<u8>,
    /// Opaque ticket bytes — re-presented unchanged on resume.
    pub ticket: Vec<u8>,
    /// `max_early_data_size` from the `early_data` extension, when present.
    /// Cap on bytes the client may send under the 0-RTT key on a resumed
    /// connection.
    pub max_early_data_size: Option<u32>,
}

impl ReceivedSessionTicket {
    fn from_wire(nst: NstWire) -> Result<Self, Error> {
        // RFC 8446 §4.6.1 caps the lifetime at 7 days.
        const MAX_LIFETIME: u32 = 7 * 24 * 60 * 60;
        if nst.ticket_lifetime > MAX_LIFETIME {
            return Err(Error::Decode);
        }
        // Look up an optional early_data extension (type 0x002a).
        let mut max_early_data_size = None;
        for (ty, body) in &nst.extensions {
            if ty.0 == 0x002a {
                if body.len() != 4 {
                    return Err(Error::Decode);
                }
                let v = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                max_early_data_size = Some(v);
            }
        }
        Ok(ReceivedSessionTicket {
            lifetime_seconds: nst.ticket_lifetime,
            age_add: nst.ticket_age_add,
            nonce: nst.ticket_nonce,
            ticket: nst.ticket,
            max_early_data_size,
        })
    }
}

impl ClientConnection {
    /// The negotiated cipher suite's wire identifier (e.g. `0x1301` for
    /// `TLS_AES_128_GCM_SHA256`), available once the `ServerHello` has been
    /// processed.
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.suite.map(|s| s.suite.0)
    }

    /// The IANA name of the negotiated cipher suite, if known.
    pub fn negotiated_cipher_suite_name(&self) -> Option<&'static str> {
        self.negotiated_cipher_suite().map(|id| match id {
            0x1301 => "TLS_AES_128_GCM_SHA256",
            0x1302 => "TLS_AES_256_GCM_SHA384",
            _ => "UNKNOWN",
        })
    }

    /// The negotiated protocol version string (always `"TLSv1.3"` here),
    /// available once the `ServerHello` has been processed.
    pub fn protocol_version(&self) -> Option<&'static str> {
        self.suite.map(|_| "TLSv1.3")
    }

    /// The peer's certificate chain in wire order (DER), leaf first. Empty until
    /// the server's `Certificate` message has been received.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.cert_chain
    }

    /// DER bytes of the OCSP response stapled by the peer on the leaf
    /// `CertificateEntry`'s per-cert `status_request` extension (RFC 6066
    /// §8 + RFC 8446 §4.4.2.1). Already validated against the chain when
    /// `verify_certificates` was enabled. `None` when the server did not
    /// staple.
    pub fn peer_ocsp_response(&self) -> Option<&[u8]> {
        self.peer_ocsp_response.as_deref()
    }

    /// The most recent `NewSessionTicket` received from the server, if any.
    /// Real-world servers (Cloudflare, Google, …) commonly send one or more
    /// post-handshake; the most recent is retained.
    pub fn last_session_ticket(&self) -> Option<&ReceivedSessionTicket> {
        self.last_ticket.as_ref()
    }

    /// Moves out the latest [`StoredSession`] suitable for PSK resumption on
    /// the next connection to the same server. Returns `None` if no ticket
    /// was received from the peer (or has already been taken).
    ///
    /// Combine with [`ClientConfig::with_session`] to drive resumption:
    /// store the value in your session cache, then pass it back at the start
    /// of the next handshake.
    pub fn take_session(&mut self) -> Option<StoredSession> {
        self.stored_session.take()
    }

    /// Whether the server accepted our PSK offer in the just-completed
    /// handshake. Always `false` for a fresh connection; `true` only when
    /// `ClientConfig::with_session` was used and the server selected the PSK.
    pub fn psk_accepted(&self) -> bool {
        self.psk_accepted
    }

    /// Whether the server accepted our 0-RTT offer (`early_data` extension
    /// in EncryptedExtensions). Always `false` before the handshake.
    pub fn early_data_accepted(&self) -> bool {
        self.early_data_accepted
    }

    /// The ALPN protocol the server selected, if any (e.g. `b"h2"`).
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_negotiated.as_deref()
    }

    /// The client random sent in the ClientHello. Exposed for keylogfile
    /// output (NSS SSLKEYLOGFILE format keys each line by client random).
    pub fn client_random(&self) -> [u8; 32] {
        self.client_random
    }

    /// The negotiated client_handshake_traffic_secret, available after
    /// `ServerHello` is processed. Intended for keylogfile output.
    pub fn client_handshake_traffic_secret(&self) -> Option<Vec<u8>> {
        self.client_hs_secret.map(|s| s.as_slice().to_vec())
    }

    /// The negotiated server_handshake_traffic_secret. See
    /// `client_handshake_traffic_secret`.
    pub fn server_handshake_traffic_secret(&self) -> Option<Vec<u8>> {
        self.server_hs_secret.map(|s| s.as_slice().to_vec())
    }

    /// `client_application_traffic_secret_0`, available after the handshake
    /// completes.
    pub fn client_application_traffic_secret_0(&self) -> Option<Vec<u8>> {
        self.client_app_secret.map(|s| s.as_slice().to_vec())
    }

    /// `server_application_traffic_secret_0`, available after the handshake
    /// completes.
    pub fn server_application_traffic_secret_0(&self) -> Option<Vec<u8>> {
        self.server_app_secret.map(|s| s.as_slice().to_vec())
    }

    /// `exporter_master_secret`, available after the handshake completes.
    pub fn exporter_master_secret(&self) -> Option<Vec<u8>> {
        self.exporter_secret.map(|s| s.as_slice().to_vec())
    }

    /// TLS 1.3 application-layer Exporter (RFC 8446 §7.5 / RFC 5705).
    /// Derives `out.len()` bytes from the `exporter_master_secret` under
    /// `(label, context)`. Returns `Err(InappropriateState)` before the
    /// handshake completes.
    pub fn tls_exporter(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let ems = self
            .exporter_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        tls_exporter(suite.hash, ems, label, context, out);
        Ok(())
    }
}

impl ClientConnection {
    /// Emits a handshake message at the right encryption level for the
    /// current [`EngineMode`].
    ///
    /// In TLS / DTLS mode this is the legacy
    /// `self.core.emit_handshake(msg)` — the transcript is updated and the
    /// bytes are framed into a record.
    ///
    /// In QUIC mode the bytes are surfaced to the QUIC layer via
    /// [`QuicHooks::on_handshake_data`] tagged with `level`, and the
    /// transcript is fed with the same bytes — but no record is produced
    /// (RFC 9001 §4.1.1). The transcript update MUST happen on both paths
    /// or the `Finished` MAC will not agree between peers.
    #[inline]
    fn emit_handshake_at(
        &mut self,
        level: super::super::quic_hooks::Level,
        msg: alloc::vec::Vec<u8>,
    ) {
        use super::super::quic_hooks::EngineMode;
        if self.engine_mode == EngineMode::Quic {
            if let Some(h) = self.hooks.as_mut() {
                h.on_handshake_data(level, &msg);
            }
            // QUIC carries the bytes in CRYPTO frames; we only need to feed
            // the transcript here.
            self.core.transcript_only(&msg);
        } else {
            self.core.emit_handshake(msg);
        }
    }

    /// Surfaces a freshly derived TLS 1.3 traffic secret to the QUIC layer.
    /// No-op in TLS / DTLS mode.
    #[inline]
    fn notify_traffic_secret(
        &mut self,
        level: super::super::quic_hooks::Level,
        dir: super::super::quic_hooks::Direction,
        secret: &[u8],
    ) {
        use super::super::quic_hooks::EngineMode;
        if self.engine_mode == EngineMode::Quic
            && let Some(h) = self.hooks.as_mut()
        {
            h.on_traffic_secret(level, dir, secret);
        }
    }

    /// Whether record-layer key installation should be skipped (QUIC mode).
    #[inline]
    fn skip_record_keys(&self) -> bool {
        self.engine_mode == super::super::quic_hooks::EngineMode::Quic
    }

    /// QUIC mode (RFC 9001): hand the engine reassembled CRYPTO-frame
    /// handshake bytes at the given encryption level, then drive the
    /// state machine. Mirrors `read_tls` + `process_new_packets` on the
    /// TLS side.
    ///
    /// `level` is accepted into the signature so that Phase 4+ can plug in
    /// per-level validation (RFC 9001 §4.1.4 mandates that the receiver
    /// reject handshake messages at unexpected levels). Phase 3 ignores it.
    // Used by the QUIC engine path (lands in Phase 4); silent otherwise.
    #[allow(dead_code)]
    pub(crate) fn process_quic_handshake_bytes(
        &mut self,
        _level: super::super::quic_hooks::Level,
        bytes: &[u8],
    ) -> Result<(), Error> {
        debug_assert_eq!(
            self.engine_mode,
            super::super::quic_hooks::EngineMode::Quic,
            "process_quic_handshake_bytes called outside QUIC mode"
        );
        self.core.quic_feed_handshake(bytes)?;
        self.process_new_packets()
    }

    /// Starts a client handshake to `server_name`, emitting the `ClientHello`.
    /// `rng` supplies the ephemeral key shares and the client random. Offers all
    /// supported cipher suites and both key-exchange groups.
    pub fn new<R: RngCore>(config: ClientConfig, server_name: &str, rng: &mut R) -> Self {
        const DEFAULT_SUITES: [CipherSuite; 3] = [
            CipherSuite::AES_128_GCM_SHA256,
            CipherSuite::AES_256_GCM_SHA384,
            CipherSuite::CHACHA20_POLY1305_SHA256,
        ];
        let suites = super::select_offered_suites(&config.cipher_suites, &DEFAULT_SUITES);
        Self::new_with_offer(
            config,
            server_name,
            rng,
            &suites,
            &[
                NamedGroup::X25519MLKEM768,
                NamedGroup::X25519,
                NamedGroup::SECP256R1,
                NamedGroup::SECP384R1,
            ],
        )
    }

    /// Like [`new`](Self::new) but with an explicit cipher-suite and
    /// key-exchange-group offer, letting callers (and tests) drive a specific
    /// negotiation outcome.
    pub(crate) fn new_with_offer<R: RngCore>(
        config: ClientConfig,
        server_name: &str,
        rng: &mut R,
        suites: &[CipherSuite],
        groups: &[NamedGroup],
    ) -> Self {
        Self::new_with_offer_inner(
            config,
            server_name,
            rng,
            suites,
            groups,
            &[],
            super::super::quic_hooks::EngineMode::Tls,
            None,
        )
    }

    /// Like [`new_with_offer`] but only includes `key_share` entries for the
    /// groups listed in `share_groups` (a subset of `groups`). Lets a test
    /// drive a deployment where the client advertises more groups in
    /// `supported_groups` than it ships shares for — the configuration HRR
    /// exists to fix. Empty `share_groups` is equivalent to
    /// [`new_with_offer`] (share for every offered group).
    #[cfg(test)]
    pub(crate) fn new_with_offer_partial_shares<R: RngCore>(
        config: ClientConfig,
        server_name: &str,
        rng: &mut R,
        suites: &[CipherSuite],
        groups: &[NamedGroup],
        share_groups: &[NamedGroup],
    ) -> Self {
        Self::new_with_offer_inner(
            config,
            server_name,
            rng,
            suites,
            groups,
            share_groups,
            super::super::quic_hooks::EngineMode::Tls,
            None,
        )
    }

    /// QUIC-mode constructor (RFC 9001). The engine runs the same TLS 1.3
    /// state machine but:
    ///
    /// * surfaces every handshake message to `hooks` tagged by encryption
    ///   level (`Initial` for `ClientHello`, `Handshake` for `Finished` /
    ///   mTLS `Certificate` / `CertificateVerify`);
    /// * surfaces every traffic-secret derivation to `hooks`;
    /// * never emits a `ChangeCipherSpec` record (RFC 9001 §8.4);
    /// * never installs a record-layer crypter — the QUIC layer holds the
    ///   AEAD state per encryption level instead;
    /// * emits a `quic_transport_parameters` (0x0039, RFC 9001 §8.2)
    ///   extension in the outgoing ClientHello carrying
    ///   `hooks.our_transport_params()`.
    ///
    /// Phase 4+ wires this into [`crate::quic::QuicConnection`]; the engine
    /// itself never holds onto network state.
    // Used by the QUIC engine path (lands in Phase 4); silent otherwise.
    #[allow(dead_code)]
    pub(crate) fn new_for_quic<R: RngCore>(
        config: ClientConfig,
        server_name: &str,
        rng: &mut R,
        suites: &[CipherSuite],
        groups: &[NamedGroup],
        hooks: super::super::quic_hooks::BoxedHooks,
    ) -> Self {
        Self::new_with_offer_inner(
            config,
            server_name,
            rng,
            suites,
            groups,
            &[],
            super::super::quic_hooks::EngineMode::Quic,
            Some(hooks),
        )
    }

    /// Inner constructor shared by [`new_with_offer`] (TLS / DTLS mode) and
    /// [`new_for_quic`] (QUIC mode). The only differences observable from
    /// the body below are:
    ///
    /// * the seeded `engine_mode` and `hooks` fields, and
    /// * a `quic_transport_parameters` extension is appended to the
    ///   outgoing ClientHello whenever `engine_mode == Quic`.
    #[allow(clippy::too_many_arguments)] // 8 small args, splitting the seam adds no clarity
    fn new_with_offer_inner<R: RngCore>(
        config: ClientConfig,
        server_name: &str,
        rng: &mut R,
        suites: &[CipherSuite],
        groups: &[NamedGroup],
        share_groups: &[NamedGroup],
        engine_mode: super::super::quic_hooks::EngineMode,
        hooks: Option<super::super::quic_hooks::BoxedHooks>,
    ) -> Self {
        let x25519 = X25519PrivateKey::generate(rng);
        let p256 = BoxedEcdhPrivateKey::generate(CurveId::P256, rng);
        let p384 = BoxedEcdhPrivateKey::generate(CurveId::P384, rng);
        let (mlkem, _) = MlKem768DecapsKey::generate(rng);
        let mut random: Random = [0u8; 32];
        rng.fill_bytes(&mut random);
        // Private seed for the ECH GREASE HKDF expansion (see the
        // `ech_grease_seed` field). Drawn alongside the CH random so
        // both share the same RNG provenance but the seed is never
        // exposed on the wire.
        #[cfg(feature = "ech")]
        let mut ech_grease_seed = [0u8; 32];
        #[cfg(feature = "ech")]
        rng.fill_bytes(&mut ech_grease_seed);

        // If resuming, restrict the cipher-suite offer to suites whose hash
        // matches the session's. The PSK binder and handshake key schedule
        // are tied to that hash.
        let session_hash = config.session.as_ref().map(|s| s.cipher_suite_hash);
        let effective_suites: Vec<CipherSuite> = match session_hash {
            Some(h) => suites
                .iter()
                .copied()
                .filter(|s| suite_hash(*s) == Some(h))
                .collect(),
            None => suites.to_vec(),
        };

        let mut conn = ClientConnection {
            core: ConnectionCore::new(),
            config,
            server_name: String::from(server_name),
            state: State::WaitServerHello,
            received_close_notify: false,
            x25519,
            p256,
            p384,
            mlkem,
            client_random: random,
            offered_suites: effective_suites.clone(),
            offered_groups: groups.to_vec(),
            hrr_processed: false,
            hrr_selected_group: None,
            hrr_selected_suite: None,
            suite: None,
            ks: None,
            client_hs_secret: None,
            server_hs_secret: None,
            client_app_secret: None,
            server_app_secret: None,
            exporter_secret: None,
            cert_chain: Vec::new(),
            stapled_crls: crate::tls::pki::CrlStore::new(),
            peer_ocsp_response: None,
            negotiated_server_cert_type: 0, // X.509 default per RFC 7250.
            negotiated_client_cert_type: 0,
            leaf_key: None,
            last_ticket: None,
            alpn_negotiated: None,
            psk_offered: None,
            psk_accepted: false,
            handshake_start: system_now(),
            stored_session: None,
            rms: None,
            early_data_offered: false,
            early_data_accepted: false,
            cets: None,
            deferred_client_hs_secret: None,
            cert_request_received: false,
            engine_mode,
            hooks,
            peer_quic_params_seen: false,
            #[cfg(feature = "ech")]
            ech_state: None,
            #[cfg(feature = "ech")]
            ech_grease_seed,
        };
        // Remember the offered PSK so we can seed the schedule when the
        // server selects it in SH.
        if let Some(session) = conn.config.session.as_ref() {
            conn.psk_offered = Some(PskOfferState {
                psk: session.psk.clone(),
                hash: session.cipher_suite_hash,
            });
            if matches!(session.max_early_data_size, Some(n) if n > 0) {
                conn.early_data_offered = true;
            }
        }
        // draft-ietf-tls-esni-22 §6: if the client is configured for
        // Real ECH (Some(EchClient { mode: Real(list) })) and there's
        // no PSK in play (real ECH + PSK is a wave-later combo), try
        // to seal an inner CH under HPKE and emit the outer CH as the
        // wire ClientHello. Otherwise build the plain (possibly GREASE)
        // ClientHello via build_client_hello with `ech_override = None`.
        #[cfg(feature = "ech")]
        let ech_sealed: Option<EchSealOutput> = seal_real_ech_on_ch1(
            &conn,
            random,
            &effective_suites,
            groups,
            share_groups,
            server_name,
            rng,
        );

        #[cfg(feature = "ech")]
        let hello = match ech_sealed {
            Some(EchSealOutput {
                outer_ch,
                inner_ch_bytes,
                sender,
                sym,
                config_id,
                inner_ch1_random,
                maximum_name_length,
                public_name,
            }) => {
                conn.ech_state = Some(ClientEchState {
                    inner_ch_bytes,
                    outcome: None,
                    sender: Some(sender),
                    sym: Some(sym),
                    config_id: Some(config_id),
                    inner_ch1_random: Some(inner_ch1_random),
                    maximum_name_length: Some(maximum_name_length),
                    inner_transcript_swapped: false,
                    outer_public_name: public_name,
                    retry_configs: None,
                });
                outer_ch
            }
            None => conn.build_client_hello(
                random,
                String::from(server_name),
                &effective_suites,
                groups,
                share_groups,
                &[],
                None,
            ),
        };
        #[cfg(not(feature = "ech"))]
        let hello = conn.build_client_hello(
            random,
            String::from(server_name),
            &effective_suites,
            groups,
            share_groups,
            &[],
            None,
        );

        // Pre-set the transcript alg so the CH update settles the
        // ClientEarlyTrafficSecret derivation below at the right hash.
        if conn.early_data_offered
            && let Some(session) = conn.config.session.as_ref()
        {
            conn.core.transcript.set_alg(session.cipher_suite_hash);
        }
        // RFC 9001 §4.1.4: ClientHello rides at the Initial encryption level
        // in QUIC; in TLS / DTLS mode this just goes into the record stream.
        conn.emit_handshake_at(super::super::quic_hooks::Level::Initial, hello);

        // 0-RTT: install the client-early-traffic write key so the caller
        // can stream early data right after this constructor returns. The
        // secret is derived from `EarlySecret = HKDF-Extract(0, PSK)` and
        // `Hash(ClientHello)`. The cipher suite is the one we offered (a
        // single hash-matched suite is in effective_suites when the session
        // is set).
        if conn.early_data_offered
            && let (Some(psk_state), Some(first_suite)) =
                (conn.psk_offered.as_ref(), effective_suites.first())
            && let Some(suite) = lookup_suite(*first_suite)
        {
            let ks = KeySchedule::with_psk(psk_state.hash, &psk_state.psk);
            let th = conn.core.transcript.current_hash();
            let cets = ks.client_early_traffic_secret(th.as_slice());
            if let Some(kl) = conn.config.key_log.as_ref() {
                kl.log(
                    "CLIENT_EARLY_TRAFFIC_SECRET",
                    &conn.client_random,
                    cets.as_slice(),
                );
            }
            // RFC 9001 §4.1.1: the client-early-traffic secret keys 0-RTT
            // packets in QUIC's Application PN space at the EarlyData level.
            conn.notify_traffic_secret(
                super::super::quic_hooks::Level::EarlyData,
                super::super::quic_hooks::Direction::Tx,
                cets.as_slice(),
            );
            if !conn.skip_record_keys() {
                conn.core.set_write(RecordCrypter::new(
                    suite.hash,
                    suite.aead,
                    suite.key_len,
                    &cets,
                ));
            }
            conn.cets = Some(cets);
        }
        conn
    }

    /// Builds a ClientHello. If `share_only` is non-empty, only those groups
    /// get a `key_share` entry (used for HRR retry, where the server picked a
    /// specific group); if empty, all `groups` get one. `extra_extensions`
    /// (typically the HRR-supplied `cookie`) are appended verbatim.
    ///
    /// When `self.config.session` carries a resumption ticket, also adds
    /// `psk_key_exchange_modes` and a `pre_shared_key` extension whose binder
    /// is computed over the truncated ClientHello and patched in place. The
    /// returned bytes are ready to emit to the wire and to feed to the
    /// transcript.
    #[allow(clippy::too_many_arguments)]
    fn build_client_hello(
        &self,
        random: Random,
        server_name: String,
        suites: &[CipherSuite],
        groups: &[NamedGroup],
        share_only: &[NamedGroup],
        extra_extensions: &[crate::tls::codec::RawExtension],
        ech_override: Option<&[u8]>,
    ) -> Vec<u8> {
        // Without the `ech` feature there's no place where we'd consult
        // `ech_override`; mark it as deliberately unused so the rest of
        // this function is identical across feature combinations.
        #[cfg(not(feature = "ech"))]
        let _ = ech_override;
        let mut key_shares = Vec::new();
        for &g in groups {
            if !share_only.is_empty() && !share_only.contains(&g) {
                continue;
            }
            match g {
                NamedGroup::X25519 => {
                    key_shares.push((NamedGroup::X25519, self.x25519.public_key().to_vec()))
                }
                NamedGroup::SECP256R1 => {
                    key_shares.push((NamedGroup::SECP256R1, self.p256.public_key().to_sec1()))
                }
                NamedGroup::SECP384R1 => {
                    key_shares.push((NamedGroup::SECP384R1, self.p384.public_key().to_sec1()))
                }
                NamedGroup::X25519MLKEM768 => {
                    // Client share: ML-KEM-768 encapsulation key ‖ X25519 key.
                    let mut share = self.mlkem.encapsulation_key().to_bytes().to_vec();
                    share.extend_from_slice(&self.x25519.public_key());
                    key_shares.push((NamedGroup::X25519MLKEM768, share));
                }
                _ => {}
            }
        }
        let mut extensions = alloc::vec![
            ext::supported_groups_list(groups),
            ext::signature_algorithms(),
            ext::client_supported_versions(),
            ext::client_key_shares(&key_shares),
        ];
        // RFC 6066 §3: SNI carries a host name only. Omit it when there is no
        // server name (e.g. connecting by IP with certificate verification off).
        if !server_name.is_empty() {
            extensions.insert(0, ext::server_name(&server_name));
        }
        if !self.config.alpn_protocols.is_empty() {
            let protos: alloc::vec::Vec<&[u8]> = self
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
        // RFC 6066 §8: opt into OCSP stapling. We advertise unconditionally;
        // the server stapes only if it has a response provisioned, and on
        // TLS 1.3 the staple rides in the leaf `CertificateEntry`'s per-cert
        // `status_request` extension (RFC 8446 §4.4.2.1).
        extensions.push(ext::status_request_ocsp());
        // RFC 7250 §3 server_certificate_type / client_certificate_type.
        // Default-X.509 clients omit both extensions: emit them only when
        // the preference list contains anything other than just X.509 (a
        // non-7250-aware server otherwise has to ignore the extension, but
        // we'd rather minimize wire-format surface for the default flow).
        if self
            .config
            .server_cert_type_preference
            .iter()
            .any(|t| *t != 0)
        {
            extensions.push(ext::cert_type_list(
                crate::tls::codec::ExtensionType::SERVER_CERTIFICATE_TYPE,
                &self.config.server_cert_type_preference,
            ));
        }
        if self
            .config
            .client_cert_type_preference
            .iter()
            .any(|t| *t != 0)
        {
            extensions.push(ext::cert_type_list(
                crate::tls::codec::ExtensionType::CLIENT_CERTIFICATE_TYPE,
                &self.config.client_cert_type_preference,
            ));
        }
        // RFC 8879 §3: `compress_certificate`. Advertise the algorithms we
        // can decompress, in our preference order. Suppressed when the
        // configured list is empty (caller opted out).
        #[cfg(feature = "cert-compression")]
        if !self.config.cert_compression_algorithms.is_empty() {
            extensions.push((
                crate::tls::codec::ExtensionType::COMPRESS_CERTIFICATE,
                crate::tls::cert_compression::encode_extension(
                    &self.config.cert_compression_algorithms,
                ),
            ));
        }

        extensions.extend_from_slice(extra_extensions);

        // draft-ietf-tls-esni-22 §6: `encrypted_client_hello`. When the
        // caller supplied an explicit body (`ech_override`) — the real-
        // ECH inner-marker for the inner CH, or the outer-form body
        // for the outer CH skeleton during the seal — emit that
        // verbatim. Otherwise fall through to the GREASE path if the
        // config asks for one (a Real-ECH config without a usable
        // seal — e.g. no supported config in the list — also gets a
        // GREASE-shape extension so it doesn't downgrade to no ECH).
        #[cfg(feature = "ech")]
        if let Some(body) = ech_override {
            extensions.push((
                crate::tls::codec::ExtensionType::ENCRYPTED_CLIENT_HELLO,
                body.to_vec(),
            ));
        } else if let Some(ech) = self.config.ech.as_ref() {
            let params = match &ech.mode {
                crate::tls::ech::EchClientMode::Grease(p) => p,
                crate::tls::ech::EchClientMode::Real(_) => {
                    &crate::tls::ech::GreaseParams::default()
                }
            };
            // Mix the per-connection private seed in — the public CH
            // random alone would let a passive observer recompute the
            // "encrypted" GREASE payload (TLS-1 audit finding).
            let body = params.build_extension_from_seed(&self.ech_grease_seed, &random);
            extensions.push((
                crate::tls::codec::ExtensionType::ENCRYPTED_CLIENT_HELLO,
                body,
            ));
        }

        // RFC 9001 §8.2: in QUIC mode the ClientHello carries
        // `quic_transport_parameters` (0x0039) holding the QUIC layer's
        // opaque transport-parameter blob. We add it before the PSK
        // extension (PSK must remain last per RFC 8446 §4.2.11). An empty
        // blob suppresses the extension; the QUIC layer enforces that
        // QUIC handshakes actually carry one.
        if self.engine_mode == super::super::quic_hooks::EngineMode::Quic
            && let Some(h) = self.hooks.as_ref()
        {
            let body = h.our_transport_params();
            if !body.is_empty() {
                extensions.push(ext::quic_transport_parameters(&body));
            }
        }

        // PSK resumption: psk_key_exchange_modes, optional early_data,
        // pre_shared_key (must be LAST per RFC 8446 §4.2.11). The binder is
        // patched after we know the truncated CH bytes.
        let mut psk_binder_info: Option<(HashAlg, Vec<u8>, usize)> = None;
        if let Some(session) = &self.config.session {
            extensions.push(ext::psk_key_exchange_modes(&[1])); // psk_dhe_ke
            if matches!(session.max_early_data_size, Some(n) if n > 0) {
                extensions.push(ext::early_data_empty());
            }
            let hash = session.cipher_suite_hash;
            let hash_len = hash.output_len();
            let age = self.compute_obfuscated_age(session);
            let (ext_with_zeros, binders_len) =
                ext::client_pre_shared_key_placeholder(&[(session.ticket.clone(), age)], hash_len);
            extensions.push(ext_with_zeros);
            psk_binder_info = Some((hash, session.psk.clone(), binders_len));
        }

        let mut bytes = ClientHello {
            // RFC 8446 §4.1.2: TLS 1.3 keeps `legacy_version = 0x0303` and
            // signals the real version via `supported_versions`.
            legacy_version: 0x0303,
            random,
            session_id: Vec::new(),
            cipher_suites: suites.to_vec(),
            extensions,
        }
        .encode();

        // Patch the binder: HMAC(binder_finished_key, Hash(truncated_CH)).
        if let Some((hash, psk, binders_len)) = psk_binder_info {
            let truncated_len = bytes.len().saturating_sub(binders_len);
            patch_psk_binder(&mut bytes, truncated_len, hash, &psk);
        }
        bytes
    }

    /// Computes the obfuscated ticket age (RFC 8446 §4.2.11.1): elapsed
    /// milliseconds since the ticket was issued, plus `ticket_age_add`,
    /// modulo 2^32.
    fn compute_obfuscated_age(&self, session: &StoredSession) -> u32 {
        let elapsed_ms = self
            .handshake_start
            .as_ref()
            .map(|now| {
                let now_s = now.to_unix();
                let then_s = session.received_at.to_unix();
                now_s.saturating_sub(then_s).saturating_mul(1000)
            })
            .unwrap_or(0);
        let elapsed_ms_u32 = elapsed_ms as u32;
        elapsed_ms_u32.wrapping_add(session.age_add)
    }

    /// Feeds received TLS bytes.
    pub fn read_tls(&mut self, bytes: &[u8]) {
        self.core.read_tls(bytes);
    }

    /// Removes and returns bytes queued for transmission.
    pub fn write_tls(&mut self) -> Vec<u8> {
        self.core.write_tls()
    }

    /// Whether there are bytes queued for transmission.
    pub fn wants_write(&self) -> bool {
        self.core.wants_write()
    }

    /// Whether the handshake is still in progress.
    pub fn is_handshaking(&self) -> bool {
        !matches!(self.state, State::Connected | State::Closed)
    }

    /// True once the peer's close_notify alert has been processed.
    ///
    /// After transport EOF, a `false` here means the TLS stream was cut
    /// without a graceful shutdown — for EOF-delimited application
    /// protocols that is a truncation attack indicator (RFC 8446 §6.1).
    pub fn received_close_notify(&self) -> bool {
        self.received_close_notify
    }

    /// What the client learnt about ECH from the server's ServerHello,
    /// or `None` if real-ECH was not attempted (no `ech` configured, or
    /// only GREASE), or the SH has not yet been processed. Useful after
    /// `process_new_packets` has driven the handshake past the SH —
    /// `Some(EchOutcome::Accepted)` confirms the inner CH won, the
    /// transcript was swapped, and the live handshake is on the inner
    /// path; `Some(EchOutcome::Rejected)` means the SH carried no valid
    /// accept signal and the handshake is continuing on the outer
    /// transcript (the EE may still carry `retry_configs`).
    #[cfg(feature = "ech")]
    pub(crate) fn ech_outcome(&self) -> Option<EchOutcome> {
        self.ech_state.as_ref().and_then(|s| s.outcome)
    }

    /// Sends application data (only valid once the handshake completes).
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::InappropriateState);
        }
        self.core.send_application_data(data);
        Ok(())
    }

    /// Sends `data` as 0-RTT (early) application data under
    /// `client_early_traffic_secret`. Valid only between
    /// `ClientConnection::new`/`new_with_offer` and the arrival of
    /// `ServerHello`, and only when the active session enabled early data
    /// (`StoredSession::max_early_data_size > 0`).
    ///
    /// **Replay risk**: the server-side anti-replay window is best-effort.
    /// Application protocols that send 0-RTT data should treat it as
    /// idempotent (e.g. GET requests without side effects).
    pub fn write_early_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if !self.early_data_offered {
            return Err(Error::InappropriateState);
        }
        if self.state != State::WaitServerHello || self.cets.is_none() {
            return Err(Error::InappropriateState);
        }
        self.core.send_application_data(data);
        Ok(())
    }

    /// Removes and returns any received application plaintext.
    pub fn take_received_plaintext(&mut self) -> Vec<u8> {
        self.core.take_received()
    }

    /// Queues a `close_notify`.
    pub fn send_close_notify(&mut self) {
        self.core.send_close_notify();
    }

    /// Processes all buffered records, advancing the handshake. On a protocol
    /// error it queues a fatal alert and returns the error.
    pub fn process_new_packets(&mut self) -> Result<(), Error> {
        loop {
            match self.core.next_message() {
                Ok(Some(Incoming::Handshake(msg))) => {
                    if let Err(e) = self.handle_handshake(msg) {
                        self.fail(&e);
                        return Err(e);
                    }
                }
                Ok(Some(Incoming::ApplicationData(_))) => {
                    if self.state != State::Connected {
                        let e = Error::UnexpectedMessage;
                        self.fail(&e);
                        return Err(e);
                    }
                }
                Ok(Some(Incoming::Alert(alert))) => {
                    if alert.description == AlertDescription::CloseNotify {
                        self.received_close_notify = true;
                        self.state = State::Closed;
                        return Ok(());
                    }
                    return Err(Error::AlertReceived(alert.description));
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
        self.core.send_alert(alert_for(error));
        self.state = State::Closed;
    }

    fn handle_handshake(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        let mut c = ReadCursor::new(&msg);
        let (msg_type, body) = read_handshake(&mut c)?;

        match self.state {
            State::WaitServerHello => self.on_server_hello(msg_type, body, &msg),
            State::WaitEncryptedExtensions => self.on_encrypted_extensions(msg_type, &msg),
            State::WaitCertificate => self.on_certificate(msg_type, body, &msg),
            State::WaitCertificateVerify => self.on_certificate_verify(msg_type, body, &msg),
            State::WaitFinished => self.on_finished(msg_type, body, &msg),
            State::Connected => self.on_post_handshake(msg_type, body),
            State::Closed => Err(Error::UnexpectedMessage),
        }
    }

    /// Handles post-handshake messages (RFC 8446 §4.6).
    ///
    /// * `NewSessionTicket` (type 4) is parsed and the most recent one is
    ///   stashed in [`Self::last_ticket`] for later inspection / resumption.
    /// * `KeyUpdate` (type 24) rolls the read key forward and, if requested,
    ///   the write key plus an outgoing reply (`update_not_requested`).
    /// * Anything else fails with `unexpected_message`.
    fn on_post_handshake(&mut self, msg_type: u8, body: &[u8]) -> Result<(), Error> {
        match msg_type {
            hs_type::NEW_SESSION_TICKET => {
                let nst = NstWire::decode(body)?;
                let received = ReceivedSessionTicket::from_wire(nst.clone())?;
                self.last_ticket = Some(received.clone());

                // Derive the PSK and build a StoredSession ready for the next
                // connection. Requires `resumption_master_secret` (set when our
                // Finished completed) and the negotiated suite hash.
                if let (Some(rms), Some(suite)) = (self.rms.as_ref(), self.suite) {
                    let hash_len = suite.hash.output_len();
                    let mut psk = alloc::vec![0u8; hash_len];
                    psk_from_resumption(suite.hash, rms, &nst.ticket_nonce, &mut psk);
                    let received_at = system_now()
                        .or_else(|| self.handshake_start.clone())
                        .unwrap_or_else(|| Time::from_unix(0));
                    self.stored_session = Some(StoredSession {
                        server_name: self.server_name.clone(),
                        ticket: received.ticket.clone(),
                        psk,
                        age_add: received.age_add,
                        lifetime_seconds: received.lifetime_seconds,
                        received_at,
                        max_early_data_size: received.max_early_data_size,
                        negotiated_alpn: self.alpn_negotiated.clone(),
                        cipher_suite_hash: suite.hash,
                    });
                }
                Ok(())
            }
            hs_type::KEY_UPDATE => self.handle_key_update(body),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Processes an incoming `KeyUpdate`. Re-keys the read side from the
    /// previous `server_application_traffic_secret_N`. If the peer asked us
    /// to update too (`update_requested == 1`), emit our own `KeyUpdate`
    /// (`update_not_requested`) and step the write side as well.
    fn handle_key_update(&mut self, body: &[u8]) -> Result<(), Error> {
        let ku = KeyUpdate::decode(body)?;
        let suite = self.suite.ok_or(Error::IllegalParameter)?;

        // Read side: derive next server_app_secret and re-key.
        let prev = self
            .server_app_secret
            .as_ref()
            .ok_or(Error::IllegalParameter)?;
        let next = next_traffic_secret(suite.hash, prev);
        self.core.set_read(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &next,
        ));
        self.server_app_secret = Some(next);

        if ku.request_update {
            // Send our own KeyUpdate (not_requested) and step the write side.
            // RFC 8446 §4.6.3: only one round of request is permitted, so we
            // reply with `update_not_requested` to avoid an infinite loop.
            self.send_key_update(false)?;
        }
        Ok(())
    }

    /// Emits a `KeyUpdate` and steps the write side. If `request_peer_update`
    /// is set, the peer will respond with its own `KeyUpdate(not_requested)`.
    fn send_key_update(&mut self, request_peer_update: bool) -> Result<(), Error> {
        // RFC 9001 §6: TLS 1.3 `KeyUpdate` is not used in QUIC — QUIC has
        // its own key-update mechanism via the Key Phase bit in the
        // 1-RTT short-header. Refuse to emit one in QUIC mode rather than
        // produce a malformed flight.
        if self.engine_mode == super::super::quic_hooks::EngineMode::Quic {
            debug_assert!(false, "RFC 9001 §6 forbids TLS KeyUpdate in QUIC mode");
            return Err(Error::InappropriateState);
        }
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let ku = KeyUpdate {
            request_update: request_peer_update,
        };
        // Emit the message under the *current* write key (RFC 8446 §4.6.3:
        // "after sending a KeyUpdate, the sender SHALL send all its traffic
        // using the next generation of keys").
        self.core.emit_handshake(ku.encode());

        let prev = self
            .client_app_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let next = next_traffic_secret(suite.hash, prev);
        self.core.set_write(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &next,
        ));
        self.client_app_secret = Some(next);
        Ok(())
    }

    /// Requests a key update from the peer. The write side rolls forward
    /// immediately; the read side rolls forward when the peer replies with
    /// its own `KeyUpdate(not_requested)`.
    ///
    /// Returns `Err(InappropriateState)` if called before the handshake
    /// completes.
    pub fn request_key_update(&mut self) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::InappropriateState);
        }
        self.send_key_update(true)
    }

    fn on_server_hello(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::SERVER_HELLO {
            return Err(Error::UnexpectedMessage);
        }
        let sh = ServerHello::decode(body)?;
        if is_hello_retry_request(&sh.random) {
            return self.on_hello_retry_request(sh, raw);
        }

        // RFC 8446 §4.1.3: a TLS-1.3 ServerHello carrying the downgrade
        // sentinel "DOWNGRD\x01" (TLS 1.2) or "...\x00" (TLS 1.1/below) in
        // the last 8 bytes of `server_random` is a TLS-1.3-aware server
        // signaling that it intentionally negotiated a lower version.
        // Because this code path is the TLS-1.3 client (we always offered
        // 1.3), seeing the sentinel here means an attacker is downgrading
        // us; abort with `illegal_parameter`.
        let tail: &[u8] = &sh.random[24..];
        if tail == super::client12::DOWNGRADE_SENTINEL_TLS12
            || tail == super::client12::DOWNGRADE_SENTINEL_TLS11_OR_BELOW
        {
            return Err(Error::IllegalParameter);
        }

        // RFC 8446 §4.1.3: the ServerHello MUST echo `legacy_session_id` from
        // the ClientHello verbatim. This TLS 1.3 client never uses the
        // middlebox-compatibility session id — it always offers an empty
        // `legacy_session_id` — so the echo must be empty. Any non-empty echo
        // means the server did not faithfully reflect what we offered; abort
        // with illegal_parameter (the same check the RFC mandates the client
        // perform, also applied on the HRR path below).
        if !sh.session_id.is_empty() {
            return Err(Error::IllegalParameter);
        }

        // RFC 8446 §4.1.3: the server MUST select a cipher_suite the client
        // offered in this ClientHello. Reject any other suite with
        // illegal_parameter (mirrors the HRR path's offered-suite check).
        if !self.offered_suites.contains(&sh.cipher_suite) {
            return Err(Error::IllegalParameter);
        }
        // RFC 8446 §4.1.4: a ServerHello following a HelloRetryRequest MUST
        // carry the same cipher_suite the HRR selected — the HRR pinned the
        // transcript hash to that suite, so a switch here is a protocol
        // violation even if the new suite was offered.
        if let Some(hrr_suite) = self.hrr_selected_suite
            && sh.cipher_suite != hrr_suite
        {
            return Err(Error::IllegalParameter);
        }
        let suite = lookup_suite(sh.cipher_suite).ok_or(Error::HandshakeFailure)?;
        // Confirm TLS 1.3 was selected.
        let sv = ext::find(
            &sh.extensions,
            crate::tls::codec::ExtensionType::SUPPORTED_VERSIONS,
        )
        .ok_or(Error::UnsupportedVersion)?;
        if ext::parse_selected_version(sv)? != crate::tls::ProtocolVersion::TLSv1_3 {
            return Err(Error::UnsupportedVersion);
        }

        // The transcript hash now needs the negotiated hash. We
        // *defer* feeding `raw` into the transcript past the ECH
        // accept-signal verification below, because on a real-ECH
        // accept the live transcript still tracks the OUTER CH bytes
        // and we need to swap them for the INNER CH bytes before the
        // SH lands. On reject (or no ECH at all), this is purely a
        // reordering — the transcript update happens a few lines down.
        self.core.transcript.set_alg(suite.hash);

        // ECDHE from the server's key share.
        let ks_ext = ext::find(&sh.extensions, crate::tls::codec::ExtensionType::KEY_SHARE)
            .ok_or(Error::HandshakeFailure)?;
        let (group, server_pub) = ext::parse_server_key_share(ks_ext)?;
        // RFC 8446 §4.1.3: the server's key_share group MUST be one the client
        // offered (and for which we therefore hold a private key). Reject any
        // other group with illegal_parameter (mirrors the HRR path's check).
        if !self.offered_groups.contains(&group) {
            return Err(Error::IllegalParameter);
        }
        // RFC 8446 §4.1.4: when this ServerHello follows a HelloRetryRequest
        // that selected a group, the server MUST send a key_share for that
        // exact group. Pin it — a mismatch is a protocol violation (the server
        // forcing us to a different group than the one it just demanded).
        if let Some(hrr_group) = self.hrr_selected_group
            && group != hrr_group
        {
            return Err(Error::IllegalParameter);
        }
        let shared = self.key_agreement(group, &server_pub)?;

        // PSK acceptance: if the server echoes pre_shared_key in SH with
        // `selected_identity = 0`, seed the schedule from the offered PSK
        // instead of all-zeros. Suite hash must match the offered PSK's hash.
        let mut ks =
            if let Some(psk_body) = ext::find(&sh.extensions, ExtensionType::PRE_SHARED_KEY) {
                let idx = ext::parse_server_pre_shared_key(psk_body)?;
                let offered = self.psk_offered.as_ref().ok_or(Error::IllegalParameter)?;
                // We only offer one identity; the server must select index 0.
                if idx != 0 {
                    return Err(Error::IllegalParameter);
                }
                // The hash of the selected suite must match the offered PSK's hash.
                if suite.hash != offered.hash {
                    return Err(Error::IllegalParameter);
                }
                self.psk_accepted = true;
                KeySchedule::with_psk(suite.hash, &offered.psk)
            } else {
                KeySchedule::new(suite.hash)
            };
        ks.enter_handshake(shared.as_slice());

        // draft-ietf-tls-esni-22 §7: if real-ECH was attempted, the
        // server tells us whether it accepted by writing 8 bytes into
        // `sh.random[24..32]`. We recompute the expected signal over
        // `Hash(inner_CH || sh_with_zero_tail)` keyed from the inner
        // CH's `random` (§7.2: `HKDF-Extract(0, ClientHelloInner.random)`
        // — independent of the key schedule; CH2-inner reuses CH1-inner's
        // random on the HRR retry path per RFC 8446 §4.1.2). On match,
        // swap the in-transcript outer CH for the inner CH bytes so
        // every subsequent message ends up on the inner transcript.
        // On mismatch, leave the transcript alone (outer prevails)
        // and let EE processing surface a rejection via retry_configs
        // in wave 3b.4.
        #[cfg(feature = "ech")]
        if let Some(state) = self.ech_state.as_mut() {
            let mut sh_zero_tail: Vec<u8> = raw.to_vec();
            // Handshake wire: 1 (type) + 3 (length) + 2 (version) + 32
            // (random) → random[24..32] is at bytes 30..38.
            if sh_zero_tail.len() >= 38 {
                for b in &mut sh_zero_tail[30..38] {
                    *b = 0;
                }
                // On the HRR retry path the live transcript already
                // holds `message_hash(Hash(inner_CH1)) || HRR || inner_CH2`
                // (HRR processing swapped it in), so the SH signal hash
                // is `Hash(live_transcript || sh_zero_tail)`. On the
                // non-HRR path the live transcript still holds the
                // outer CH and we recompute `Hash(inner_CH || sh_zero_tail)`
                // from scratch.
                let th_sig = if state.inner_transcript_swapped {
                    self.core.transcript.hash_with_appended(&sh_zero_tail)
                } else {
                    let mut tbuf: Vec<u8> =
                        Vec::with_capacity(state.inner_ch_bytes.len() + sh_zero_tail.len());
                    tbuf.extend_from_slice(&state.inner_ch_bytes);
                    tbuf.extend_from_slice(&sh_zero_tail);
                    suite.hash.hash(&tbuf)
                };
                let inner_ch_random = state.inner_ch1_random.ok_or(Error::IllegalParameter)?;
                let expected = crate::tls::ech::accept_signal::server_hello_signal(
                    suite.hash,
                    &inner_ch_random,
                    th_sig.as_slice(),
                );
                let sh_tail = crate::tls::ech::accept_signal::random_tail(&sh.random);
                if crate::tls::ech::accept_signal::signals_eq_ct(&expected, &sh_tail) {
                    // ECH accepted. On the non-HRR path swap the live
                    // transcript from outer to inner now; on the HRR
                    // retry path the swap already happened during HRR
                    // processing, so leave the transcript alone.
                    if !state.inner_transcript_swapped {
                        self.core
                            .transcript
                            .replace_buf(state.inner_ch_bytes.clone());
                    }
                    state.outcome = Some(EchOutcome::Accepted);
                } else {
                    state.outcome = Some(EchOutcome::Rejected);
                }
            } else {
                state.outcome = Some(EchOutcome::Rejected);
            }
        }
        self.core.transcript.update(raw);
        let th = self.core.transcript.current_hash();
        let chts = ks.client_handshake_traffic_secret(th.as_slice());
        let shts = ks.server_handshake_traffic_secret(th.as_slice());

        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                &self.client_random,
                chts.as_slice(),
            );
            kl.log(
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                &self.client_random,
                shts.as_slice(),
            );
        }

        // QUIC layer hooks (RFC 9001 §5.1): once for each direction at
        // Handshake level. Client writes with `chts`, reads with `shts`.
        self.notify_traffic_secret(
            super::super::quic_hooks::Level::Handshake,
            super::super::quic_hooks::Direction::Tx,
            chts.as_slice(),
        );
        self.notify_traffic_secret(
            super::super::quic_hooks::Level::Handshake,
            super::super::quic_hooks::Direction::Rx,
            shts.as_slice(),
        );

        // Server -> client uses the server handshake key. If we offered
        // 0-RTT, keep the current write key (early-traffic) until we send
        // EndOfEarlyData; otherwise install the client-handshake write key
        // now. The handshake secret is always stashed so it can be installed
        // later. In QUIC mode the record crypter is never installed (the
        // QUIC layer holds the AEAD state per encryption level).
        if !self.skip_record_keys() {
            self.core.set_read(RecordCrypter::new(
                suite.hash,
                suite.aead,
                suite.key_len,
                &shts,
            ));
            if self.early_data_offered {
                self.deferred_client_hs_secret = Some(chts);
            } else {
                self.core.set_write(RecordCrypter::new(
                    suite.hash,
                    suite.aead,
                    suite.key_len,
                    &chts,
                ));
            }
            // RFC 9001 §8.4: ChangeCipherSpec MUST NOT appear in QUIC.
            self.core.emit_ccs(); // middlebox compatibility
        } else if self.early_data_offered {
            self.deferred_client_hs_secret = Some(chts);
        }

        self.suite = Some(suite);
        self.ks = Some(ks);
        self.client_hs_secret = Some(chts);
        self.server_hs_secret = Some(shts);
        self.state = State::WaitEncryptedExtensions;
        Ok(())
    }

    /// Handles a HelloRetryRequest (RFC 8446 §4.1.4): rewrites the transcript
    /// with the synthetic `message_hash`, validates the selected group is one
    /// we offered, and re-emits ClientHello2 narrowed to that group (echoing
    /// any cookie). Stays in `WaitServerHello` for the real ServerHello.
    fn on_hello_retry_request(&mut self, hrr: ServerHello, raw: &[u8]) -> Result<(), Error> {
        // Only one HRR per handshake (RFC §4.1.4: the client MUST abort with
        // unexpected_message if a second one arrives).
        if self.hrr_processed {
            return Err(Error::UnexpectedMessage);
        }

        // RFC 8446 §4.1.4: like the real ServerHello, the HRR MUST echo
        // `legacy_session_id` from the ClientHello verbatim. This client
        // always offers an empty `legacy_session_id`, so any non-empty echo
        // means the server did not faithfully reflect what we offered;
        // abort with illegal_parameter (mirrors the §4.1.3 check on the
        // real-ServerHello path).
        if !hrr.session_id.is_empty() {
            return Err(Error::IllegalParameter);
        }

        // The HRR's cipher_suite must be one we offered.
        if !self.offered_suites.contains(&hrr.cipher_suite) {
            return Err(Error::IllegalParameter);
        }
        let suite = lookup_suite(hrr.cipher_suite).ok_or(Error::HandshakeFailure)?;

        // Validate selected version is TLS 1.3.
        let sv = ext::find(
            &hrr.extensions,
            crate::tls::codec::ExtensionType::SUPPORTED_VERSIONS,
        )
        .ok_or(Error::UnsupportedVersion)?;
        if ext::parse_selected_version(sv)? != crate::tls::ProtocolVersion::TLSv1_3 {
            return Err(Error::UnsupportedVersion);
        }

        // The HRR carries either a `key_share(selected_group)` or a `cookie`
        // (or both). The selected group, if present, must be in our offer.
        let selected_group =
            match ext::find(&hrr.extensions, crate::tls::codec::ExtensionType::KEY_SHARE) {
                Some(body) => {
                    let g = ext::parse_hrr_key_share(body)?;
                    if !self.offered_groups.contains(&g) {
                        return Err(Error::IllegalParameter);
                    }
                    Some(g)
                }
                None => None,
            };
        // If neither a new group nor a cookie is present, the HRR makes no
        // change and per RFC §4.1.4 the client MUST abort with
        // illegal_parameter (otherwise we'd loop).
        let cookie_ext = hrr
            .extensions
            .iter()
            .find(|(t, _)| t.0 == 0x002c) // cookie
            .cloned();
        if selected_group.is_none() && cookie_ext.is_none() {
            return Err(Error::IllegalParameter);
        }

        // Pin the negotiated hash so the transcript helpers below can
        // run (HRR is the first message after CH1 where we know it).
        self.core.transcript.set_alg(suite.hash);

        // draft-ietf-tls-esni-22 §7.2.1: if the HRR carries an
        // `encrypted_client_hello` extension, it MUST be exactly 8
        // bytes (the `hrr_accept_confirmation` signal). The server
        // emits it only when it accepted CH1's real ECH; receiving one
        // when we didn't actually do real ECH is a protocol violation.
        // Verification happens *before* the §4.4.1 transcript rewrite
        // so the live transcript still holds the raw CH1-outer bytes
        // and we can build the inner-transcript signal input on a
        // throwaway buffer.
        #[cfg(feature = "ech")]
        let mut ech_signal_accepted = false;
        #[cfg(feature = "ech")]
        if let Some(ech_body) = ext::find(
            &hrr.extensions,
            crate::tls::codec::ExtensionType::ENCRYPTED_CLIENT_HELLO,
        ) {
            if ech_body.len() != 8 {
                return Err(Error::IllegalParameter);
            }
            let mut received = [0u8; 8];
            received.copy_from_slice(ech_body);
            // Real-ECH state must be in play; sender retention from
            // CH1 is the marker.
            let state = self
                .ech_state
                .as_ref()
                .filter(|s| s.sender.is_some())
                .ok_or(Error::IllegalParameter)?;
            let inner_ch1_random = state.inner_ch1_random.ok_or(Error::IllegalParameter)?;
            let inner_ch_bytes = state.inner_ch_bytes.clone();
            // Zero the 8 signal bytes in a copy of the HRR wire image
            // to recover the "placeholder" form the spec hashes.
            let mut hrr_zero = raw.to_vec();
            let off = crate::tls::ech::accept_signal::locate_hrr_ech_signal_payload(&hrr_zero)
                .ok_or(Error::IllegalParameter)?;
            for b in &mut hrr_zero[off..off + 8] {
                *b = 0;
            }
            // Build the inner-transcript input:
            //   message_hash(Hash(inner_CH1)) || HRR_with_zero_payload
            let inner_hash = suite.hash.hash(&inner_ch_bytes);
            let hash_len = suite.hash.output_len();
            let mut tbuf = Vec::with_capacity(4 + hash_len + hrr_zero.len());
            tbuf.push(254); // synthetic message_hash type
            tbuf.extend_from_slice(&[0, 0]);
            tbuf.push(hash_len as u8);
            tbuf.extend_from_slice(inner_hash.as_slice());
            tbuf.extend_from_slice(&hrr_zero);
            let th = suite.hash.hash(&tbuf);
            let expected = crate::tls::ech::accept_signal::hello_retry_request_signal(
                suite.hash,
                &inner_ch1_random,
                th.as_slice(),
            );
            if !crate::tls::ech::accept_signal::signals_eq_ct(&expected, &received) {
                // Signal mismatch: HRR claims ECH accept but the bits
                // don't match. Aborting with `EchRejected` (no
                // retry_configs in flight yet) reads cleaner than
                // illegal_parameter — wave 4 lifts the actual configs
                // from a subsequent EE on the rejected outer path.
                return Err(Error::EchRejected(Vec::new()));
            }
            ech_signal_accepted = true;
        }

        // RFC 8446 §4.4.1 transcript rewrite. On real-ECH accept, the
        // transcript first swaps from CH1-outer to CH1-inner so the
        // rewrite produces `message_hash(Hash(inner_CH1))` rather than
        // `message_hash(Hash(outer_CH1))` — every subsequent message
        // (HRR included) is then bound to the inner transcript.
        #[cfg(feature = "ech")]
        if ech_signal_accepted && let Some(state) = self.ech_state.as_mut() {
            self.core
                .transcript
                .replace_buf(state.inner_ch_bytes.clone());
            state.inner_transcript_swapped = true;
            state.outcome = Some(EchOutcome::Accepted);
        }
        self.core.transcript.replace_with_message_hash();
        self.core.transcript.update(raw);

        // Build CH2: same client_random, same offered_suites/groups, narrow
        // the key_share list to the selected group, echo the cookie verbatim.
        let share_only: alloc::vec::Vec<NamedGroup> = selected_group.into_iter().collect();
        let extras: alloc::vec::Vec<crate::tls::codec::RawExtension> =
            cookie_ext.into_iter().collect();

        #[cfg(feature = "ech")]
        let (ch2_wire, ch2_transcript) = if ech_signal_accepted {
            // Real-ECH retry: build CH2-inner, then build CH2-outer
            // skeleton with the same `(sym, config_id)` as CH1 and an
            // empty `enc` field (draft §6.1.5), and seal CH2-inner
            // under the retained `SenderContext` (its `seq` is 1, the
            // schedule position the server's receiver is at after
            // CH1's `open` call). The transcript is bound to CH2-inner
            // (the server unwraps CH2-outer to CH2-inner before
            // appending to its own transcript), so wire ≠ transcript
            // bytes here.
            let (outer, inner) = self.seal_real_ech_on_ch2(&share_only, &extras)?;
            (outer, Some(inner))
        } else {
            let ch = self.build_client_hello(
                self.client_random,
                self.server_name.clone(),
                &self.offered_suites.clone(),
                &self.offered_groups.clone(),
                &share_only,
                &extras,
                None,
            );
            (ch, None)
        };

        #[cfg(not(feature = "ech"))]
        let (ch2_wire, ch2_transcript): (Vec<u8>, Option<Vec<u8>>) = (
            self.build_client_hello(
                self.client_random,
                self.server_name.clone(),
                &self.offered_suites.clone(),
                &self.offered_groups.clone(),
                &share_only,
                &extras,
                None,
            ),
            None,
        );

        // RFC 9001 §4.1.4: like CH1, CH2 rides at Initial in QUIC mode.
        // ECH-real retry: send the outer to the wire and feed the inner
        // to the transcript separately. Non-ECH retry: wire and
        // transcript are the same bytes.
        match ch2_transcript {
            #[cfg(feature = "ech")]
            Some(inner) => {
                self.core
                    .emit_record(crate::tls::ContentType::Handshake, &ch2_wire);
                if let Some(h) = self.hooks.as_mut() {
                    h.on_handshake_data(super::super::quic_hooks::Level::Initial, &ch2_wire);
                }
                self.core.transcript_only(&inner);
            }
            _ => {
                self.emit_handshake_at(super::super::quic_hooks::Level::Initial, ch2_wire);
            }
        }
        self.hrr_processed = true;
        // Remember the HRR-selected group so the real ServerHello's key_share
        // can be pinned to it (RFC 8446 §4.1.4). `None` when the HRR carried
        // only a cookie and no key_share.
        self.hrr_selected_group = selected_group;
        // Pin the HRR-selected cipher suite too: §4.1.4 requires the
        // subsequent ServerHello to carry the same suite.
        self.hrr_selected_suite = Some(hrr.cipher_suite);
        // Stay in WaitServerHello for the real ServerHello.
        Ok(())
    }

    /// Re-seals CH2-inner into a CH2-outer skeleton under the
    /// `SenderContext` retained from CH1's seal (draft-ietf-tls-esni-22
    /// §6.1.5 / §7.2.2). CH2-outer's `encrypted_client_hello` extension
    /// MUST echo CH1's `(sym, config_id)` and carry an empty `enc`
    /// field; the AEAD seq increments to 1 by virtue of reusing the
    /// same HPKE schedule rather than spinning up a fresh sender.
    ///
    /// On real-ECH GREASE / config-mismatch / non-ECH paths the caller
    /// builds CH2 directly via `build_client_hello`; this function is
    /// only reached when CH1's HRR carried a validated ECH signal.
    ///
    /// Returns `(outer_ch2, inner_ch2)`: the outer goes on the wire (so
    /// the server can HPKE-decap CH2-outer under the retained sender),
    /// the inner goes into the transcript (the handshake hash is bound
    /// to the inner CH on both ends per draft §6.1).
    #[cfg(feature = "ech")]
    fn seal_real_ech_on_ch2(
        &mut self,
        share_only: &[NamedGroup],
        extras: &[crate::tls::codec::RawExtension],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // Look up the same ECHConfig CH1 picked. `first_supported` is
        // deterministic on the configured list so we land on the same
        // entry CH1 sealed under (and we cross-check via `config_id`).
        let ech_client = self.config.ech.as_ref().ok_or(Error::EchDecryptionFailed)?;
        let list = match &ech_client.mode {
            crate::tls::ech::EchClientMode::Real(l) => l,
            _ => return Err(Error::EchDecryptionFailed),
        };
        let echcfg = list
            .first_supported()
            .ok_or(Error::EchDecryptionFailed)?
            .clone();
        let contents = echcfg.contents.as_ref().ok_or(Error::EchDecryptionFailed)?;
        let public_name_str = String::from(
            core::str::from_utf8(&contents.public_name).map_err(|_| Error::EchDecodeError)?,
        );

        // Snapshot the per-CH1 ECH state without holding a borrow of
        // `self` across `build_client_hello`/`seal_into_skeleton`.
        let (sym, config_id, maximum_name_length) = {
            let state = self.ech_state.as_ref().ok_or(Error::EchDecryptionFailed)?;
            (
                state.sym.ok_or(Error::EchDecryptionFailed)?,
                state.config_id.ok_or(Error::EchDecryptionFailed)?,
                state
                    .maximum_name_length
                    .ok_or(Error::EchDecryptionFailed)?,
            )
        };

        let inner_marker = crate::tls::ech::inner::inner_extension_body();
        let server_name = self.server_name.clone();
        let suites = self.offered_suites.clone();
        let groups = self.offered_groups.clone();
        let random = self.client_random;
        let inner_ch2 = self.build_client_hello(
            random,
            server_name.clone(),
            &suites,
            &groups,
            share_only,
            extras,
            Some(&inner_marker),
        );
        let inner_sni_len = server_name.len();
        let padded =
            crate::tls::ech::outer::pad_inner(&inner_ch2, inner_sni_len, maximum_name_length);
        // CH2-outer's encrypted_client_hello extension carries an empty
        // `enc` field per draft §6.1.5; the receiver pulls `enc` from
        // its own retained CH1 setup, not the wire.
        let outer_body =
            crate::tls::ech::outer::build_outer_ext_body(sym, config_id, &[][..], padded.len());
        let skeleton = self.build_client_hello(
            random,
            public_name_str,
            &suites,
            &groups,
            share_only,
            extras,
            Some(&outer_body),
        );

        // Take the retained sender (it never goes back into state —
        // after CH2 no more CH-level HPKE seals happen) and seal.
        let state = self.ech_state.as_mut().ok_or(Error::EchDecryptionFailed)?;
        let mut sender = state.sender.take().ok_or(Error::EchDecryptionFailed)?;
        let outer_ch = crate::tls::ech::outer::seal_into_skeleton(&mut sender, skeleton, &padded)?;
        // Update `inner_ch_bytes` to CH2-inner; the SH signal
        // verification path reads the live transcript via
        // `hash_with_appended` after we feed CH2-INNER into it below,
        // but a few diagnostics and the `peer_inner_sni`-equivalent
        // surfaces still read this field.
        state.inner_ch_bytes = inner_ch2.clone();
        Ok((outer_ch, inner_ch2))
    }

    fn key_agreement(&self, group: NamedGroup, server_pub: &[u8]) -> Result<Secret, Error> {
        match group {
            NamedGroup::X25519 => {
                let peer: [u8; 32] = server_pub.try_into().map_err(|_| Error::Decode)?;
                // RFC 8446 §7.4.2: reject the all-zero (small-order) DH output.
                let shared = self
                    .x25519
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::IllegalParameter)?;
                Ok(Secret::new(&shared))
            }
            NamedGroup::SECP256R1 => {
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, server_pub)
                    .map_err(|_| Error::Decode)?;
                let shared = self
                    .p256
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?;
                Ok(Secret::new(&shared))
            }
            NamedGroup::SECP384R1 => {
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P384, server_pub)
                    .map_err(|_| Error::Decode)?;
                let shared = self
                    .p384
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?;
                Ok(Secret::new(&shared))
            }
            NamedGroup::X25519MLKEM768 => {
                // Server share: ML-KEM ciphertext (1088) ‖ X25519 key (32).
                if server_pub.len() != CIPHERTEXT_BYTES + 32 {
                    return Err(Error::Decode);
                }
                let mut ct = [0u8; CIPHERTEXT_BYTES];
                ct.copy_from_slice(&server_pub[..CIPHERTEXT_BYTES]);
                let peer: [u8; 32] = server_pub[CIPHERTEXT_BYTES..]
                    .try_into()
                    .map_err(|_| Error::Decode)?;
                let ml_ss = self.mlkem.decapsulate(&MlKem768Ciphertext::from_bytes(ct));
                // RFC 8446 §7.4.2: reject the all-zero X25519 contribution.
                // The ML-KEM contribution remains pristine even if X25519 is
                // small-order, but TLS 1.3 mandates aborting either way.
                let x_ss = self
                    .x25519
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::IllegalParameter)?;
                // Combined secret: ML-KEM shared secret first, then X25519.
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&ml_ss);
                combined[32..].copy_from_slice(&x_ss);
                Ok(Secret::new(&combined))
            }
            _ => Err(Error::HandshakeFailure),
        }
    }

    fn on_encrypted_extensions(&mut self, msg_type: u8, raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::ENCRYPTED_EXTENSIONS {
            return Err(Error::UnexpectedMessage);
        }
        // Parse the EE body to extract ALPN and early_data, ignoring others.
        // The handshake body lives in raw[4..] (4-byte header).
        let mut early_data_in_ee = false;
        // ECH (draft §7): on reject, the server may ship `retry_configs`
        // here. Capture the body and surface it as `Error::EchRejected`
        // *after* the EE walk has run its uniqueness/format checks (a
        // malformed neighbour extension still aborts the handshake — we
        // don't want the rejection to mask a protocol violation).
        #[cfg(feature = "ech")]
        let mut ech_retry_configs: Option<alloc::vec::Vec<u8>> = None;
        if raw.len() >= 4 {
            let body = &raw[4..];
            let mut c = ReadCursor::new(body);
            let exts_bytes = c.vec_u16()?;
            let mut ec = ReadCursor::new(exts_bytes);
            // RFC 8446 §4.2: every extension type may appear at most once
            // in a single handshake message. Track types we've seen and
            // reject duplicates with `illegal_parameter`.
            let mut seen: alloc::vec::Vec<u16> = alloc::vec::Vec::new();
            while !ec.is_empty() {
                let ty = ec.u16()?;
                let ext_body = ec.vec_u16()?;
                if seen.contains(&ty) {
                    return Err(Error::IllegalParameter);
                }
                seen.push(ty);
                if ty == crate::tls::codec::ExtensionType::ALPN.0 {
                    let names = ext::parse_alpn(ext_body)?;
                    if names.len() != 1 {
                        // RFC 7301: server MUST select exactly one protocol.
                        return Err(Error::IllegalParameter);
                    }
                    // The picked protocol must have been in our offer.
                    if !self.config.alpn_protocols.iter().any(|p| p == &names[0]) {
                        return Err(Error::IllegalParameter);
                    }
                    self.alpn_negotiated = Some(names.into_iter().next().unwrap());
                } else if ty == crate::tls::codec::ExtensionType::RECORD_SIZE_LIMIT.0 {
                    let limit = ext::parse_record_size_limit(ext_body)?;
                    self.core.set_peer_record_size_limit(limit);
                } else if ty == crate::tls::codec::ExtensionType::EARLY_DATA.0 {
                    // In EE, early_data is empty and signals acceptance of
                    // the client's 0-RTT offer.
                    if !ext_body.is_empty() {
                        return Err(Error::IllegalParameter);
                    }
                    if !self.early_data_offered {
                        // Server cannot accept what we didn't offer.
                        return Err(Error::IllegalParameter);
                    }
                    early_data_in_ee = true;
                } else if ty == crate::tls::codec::ExtensionType::SERVER_CERTIFICATE_TYPE.0 {
                    // RFC 7250 §4.2 server reply: a single byte picking the
                    // cert type for the server's leaf. Must be in our offer.
                    let selected = ext::parse_cert_type_selection(ext_body)?;
                    if !self.config.server_cert_type_preference.contains(&selected) {
                        return Err(Error::IllegalParameter);
                    }
                    self.negotiated_server_cert_type = selected;
                } else if ty == crate::tls::codec::ExtensionType::CLIENT_CERTIFICATE_TYPE.0 {
                    // RFC 7250 §4.2 server reply for the mTLS leaf. Must be
                    // in our offer.
                    let selected = ext::parse_cert_type_selection(ext_body)?;
                    if !self.config.client_cert_type_preference.contains(&selected) {
                        return Err(Error::IllegalParameter);
                    }
                    self.negotiated_client_cert_type = selected;
                } else if ty == crate::tls::codec::ExtensionType::ENCRYPTED_CLIENT_HELLO.0 {
                    // ECH (draft §7): the body is an `ECHConfigList` the
                    // client should retry against. Validate it now so a
                    // malformed list still trips `IllegalParameter`
                    // rather than being silently surfaced through
                    // `EchRejected`. Capture the raw bytes; the
                    // decision to surface as a rejection happens after
                    // the EE walk, predicated on our own ECH attempt
                    // having flagged the SH as rejected.
                    #[cfg(feature = "ech")]
                    {
                        let _ = crate::tls::ech::retry::decode_retry_configs(ext_body)
                            .map_err(|_| Error::IllegalParameter)?;
                        ech_retry_configs = Some(ext_body.to_vec());
                    }
                } else if ty == crate::tls::codec::ExtensionType::QUIC_TRANSPORT_PARAMETERS.0
                    && self.engine_mode == super::super::quic_hooks::EngineMode::Quic
                {
                    // RFC 9001 §8.2: the server's transport parameters are
                    // delivered to the QUIC layer verbatim. The extension
                    // appears at most once per handshake; reject duplicates
                    // here rather than rely on the QUIC layer to notice.
                    if self.peer_quic_params_seen {
                        return Err(Error::IllegalParameter);
                    }
                    self.peer_quic_params_seen = true;
                    if let Some(h) = self.hooks.as_mut() {
                        h.on_peer_transport_params(ext_body);
                    }
                }
            }
        }

        // ECH rejection (draft §7.1 / §6.1.6): the client attempted real
        // ECH (we have `ech_state`), the SH did not signal accept
        // (`outcome == Some(Rejected)`), and the EE may carry an
        // `encrypted_client_hello` extension whose body is a usable
        // `ECHConfigList` of retry_configs. Do NOT surface anything yet:
        // EncryptedExtensions is only handshake-traffic protected — it is
        // not bound to any server certificate — so trusting these bytes
        // now would let an active MITM (with no certificate at all) hand
        // us attacker-controlled retry configs and capture the real SNI
        // on the retry. Stash them and continue the handshake under the
        // outer/`public_name` identity; `Error::EchRejected` is surfaced
        // by `on_finished` only after CertificateVerify + Finished have
        // authenticated the server against `public_name`.
        #[cfg(feature = "ech")]
        if let Some(state) = self.ech_state.as_mut()
            && matches!(state.outcome, Some(EchOutcome::Rejected))
        {
            state.retry_configs = ech_retry_configs.take();
        }

        self.core.transcript.update(raw);

        // 0-RTT key transition (RFC 8446 §4.6.1) is split between here and
        // on_finished:
        //   - If REJECTED: install the client-handshake write key now and
        //     discard the queued early data (the server will skip it).
        //   - If ACCEPTED: keep the early write key until AFTER we verify
        //     the server's Finished (because the server's Finished MAC is
        //     over CH..SH..EE, which does NOT include EOED yet). Then emit
        //     EOED under the early key and install the handshake write key.
        if self.early_data_offered {
            let suite = self.suite.expect("suite set");
            if early_data_in_ee {
                self.early_data_accepted = true;
                // Defer EOED + handshake-key install until on_finished.
            } else if !self.skip_record_keys() {
                // QUIC mode doesn't install record crypters; the QUIC
                // layer keeps the per-level AEAD state itself.
                let chts = self
                    .deferred_client_hs_secret
                    .take()
                    .ok_or(Error::InappropriateState)?;
                self.core.set_write(RecordCrypter::new(
                    suite.hash,
                    suite.aead,
                    suite.key_len,
                    &chts,
                ));
            }
        }

        // Under PSK resumption (RFC 8446 §4.6.1) the server skips
        // Certificate / CertificateVerify and the client jumps straight to
        // expecting Finished.
        self.state = if self.psk_accepted {
            State::WaitFinished
        } else {
            State::WaitCertificate
        };
        Ok(())
    }

    fn on_certificate(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        // mTLS: the server's `CertificateRequest` may precede `Certificate`.
        if msg_type == hs_type::CERTIFICATE_REQUEST {
            // RFC 8446 §4.3.2: certificate_request_context is empty in
            // handshake auth; we ignore the extensions list contents (just
            // parse for structure) and remember that the server asked.
            let mut c = ReadCursor::new(body);
            let _ctx = c.vec_u8()?;
            let _exts = c.vec_u16()?;
            c.expect_empty()?;
            self.cert_request_received = true;
            self.core.transcript.update(raw);
            // Stay in WaitCertificate — Certificate is the next message.
            return Ok(());
        }
        // RFC 8879: a peer may compress its `Certificate` and send it as
        // `CompressedCertificate` (type 25) instead. Decompress in place;
        // the rest of this handler then runs on the recovered Certificate
        // body. The wire bytes that go into the transcript are the
        // compressed message (`raw`) — matching the BoringSSL / rustls
        // convention since both peers can reproduce that consistently.
        #[cfg(feature = "cert-compression")]
        let _decompressed: Vec<u8>;
        #[cfg(feature = "cert-compression")]
        let body: &[u8] = if msg_type == hs_type::COMPRESSED_CERTIFICATE {
            // Refuse if the client never advertised the extension —
            // a peer must not invent compression we did not consent to.
            if self.config.cert_compression_algorithms.is_empty() {
                return Err(Error::UnexpectedMessage);
            }
            _decompressed = crate::tls::cert_compression::decode_compressed_certificate(body)?;
            &_decompressed
        } else if msg_type == hs_type::CERTIFICATE {
            body
        } else {
            return Err(Error::UnexpectedMessage);
        };
        #[cfg(not(feature = "cert-compression"))]
        if msg_type != hs_type::CERTIFICATE {
            return Err(Error::UnexpectedMessage);
        }
        let entries = parse_certificate_list(body)?;
        if entries.is_empty() {
            return Err(Error::BadCertificate);
        }
        // RFC 7250 §4.2: when RawPublicKey is the negotiated server-cert
        // type, the CertificateEntry list MUST have exactly one entry and
        // its body is the bare `SubjectPublicKeyInfo` DER (no X.509
        // wrapping, no chain, and stapled OCSP/CRL extensions don't apply
        // — we ignore any that might be present rather than treat them
        // as authoritative).
        if self.negotiated_server_cert_type == crate::tls::codec::cert_type::RAW_PUBLIC_KEY {
            if entries.len() != 1 {
                return Err(Error::BadCertificate);
            }
            self.stapled_crls = crate::tls::pki::CrlStore::new();
            self.peer_ocsp_response = None;
            self.cert_chain = entries.into_iter().map(|(c, _)| c).collect();
            self.core.transcript.update(raw);
            self.state = State::WaitCertificateVerify;
            return Ok(());
        }
        // The TLS 1.3 `Certificate` message carries per-cert extensions
        // (RFC 8446 §4.4.2). We recognise two on the leaf entry: the
        // RFC 6066 §8 `status_request` (stapled OCSP response) and the
        // purecrypto-private `CRL_RESPONSE` staple.
        let mut stapled = crate::tls::pki::CrlStore::new();
        let mut stapled_ocsp: Option<Vec<u8>> = None;
        if let Some((_leaf, exts)) = entries.first() {
            for (ty, data) in exts.iter() {
                if *ty == crate::tls::codec::ExtensionType::CRL_RESPONSE {
                    // Best-effort: `add_der` enforces wire-format
                    // well-formedness; a malformed staple is dropped silently
                    // since stapling is purely advisory.
                    let _ = stapled.add_der(data.clone());
                } else if *ty == crate::tls::codec::ExtensionType::STATUS_REQUEST {
                    // RFC 8446 §4.4.2.1: the leaf's `status_request`
                    // extension body is the RFC 6066 `CertificateStatus`
                    // shape (u8 status_type ‖ u24-len response). Decode lazily;
                    // a malformed body fails the handshake.
                    let ocsp = ext::parse_certificate_status(data)
                        .map_err(|_| Error::OcspResponseInvalid)?;
                    stapled_ocsp = Some(ocsp);
                }
            }
        }
        self.stapled_crls = stapled;
        self.peer_ocsp_response = stapled_ocsp;
        self.cert_chain = entries.into_iter().map(|(c, _)| c).collect();
        self.core.transcript.update(raw);
        self.state = State::WaitCertificateVerify;
        Ok(())
    }

    fn on_certificate_verify(
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

        // RFC 8446 §4.4.3: the rsa_pkcs1_* schemes MUST NOT appear in
        // `CertificateVerify` (they are reserved for legacy chain signatures
        // in `signature_algorithms_cert` only). Reject before any
        // verification work.
        if scheme.is_rsa_pkcs1() {
            return Err(Error::IllegalParameter);
        }

        // RFC 7250 §4.2: when RawPublicKey is the negotiated server-cert
        // type, the leaf "Certificate" body is a bare `SubjectPublicKeyInfo`
        // DER. There is no X.509 chain to validate; trust is established by
        // matching the SPKI against the operator-configured allowlist
        // (constant-time compare). Hostname and OCSP/CRL checks don't
        // apply.
        if self.negotiated_server_cert_type == crate::tls::codec::cert_type::RAW_PUBLIC_KEY {
            let spki = self.cert_chain.first().ok_or(Error::BadCertificate)?;
            let leaf_key = AnyPublicKey::from_spki_der(spki).map_err(|_| Error::BadCertificate)?;
            if self.config.verify_certificates {
                if self.config.expected_raw_public_keys.is_empty() {
                    // No allowlist configured but verification is on — there
                    // is no way to establish trust, so refuse.
                    return Err(Error::BadCertificate);
                }
                // Constant-time membership check: walk every entry so the
                // match position doesn't leak via timing.
                let mut matched = crate::ct::Choice::from(0u8);
                for accepted in &self.config.expected_raw_public_keys {
                    if accepted.len() == spki.len() {
                        matched |= accepted.as_slice().ct_eq(spki.as_slice());
                    }
                }
                if !bool::from(matched) {
                    return Err(Error::BadCertificate);
                }
            }
            let th = self.core.transcript.current_hash();
            let content = certificate_verify_content(true, th.as_slice());
            verify_signature(
                scheme,
                &leaf_key,
                &content,
                &signature,
                &self.config.signature_policy,
            )?;
            self.leaf_key = Some(leaf_key);
            self.core.transcript.update(raw);
            self.state = State::WaitFinished;
            return Ok(());
        }

        // Always reject a malformed leaf certificate, regardless of policy.
        let leaf =
            Certificate::from_der(self.cert_chain[0].clone()).map_err(|_| Error::BadCertificate)?;
        leaf.check_well_formed()
            .map_err(|_| Error::BadCertificate)?;

        // Recover the leaf key, verifying the chain, validity, and host name
        // unless the configuration disables certificate verification. The
        // signature policy applies to every chain signature.
        let leaf_key = if self.config.verify_certificates {
            let now = self.config.verification_time.clone().or_else(system_now);
            let crls = self.config.crls.merged_with(&self.stapled_crls);
            let key = verify_chain_with_crls(
                &self.config.roots,
                &crls,
                &self.cert_chain,
                now.as_ref(),
                &self.config.signature_policy,
            )?;
            // draft-ietf-tls-esni-22 §6.1.6: when the server rejected ECH
            // the handshake continues under the *outer* identity — the
            // outer CH carried `ECHConfig.public_name` as its SNI — so the
            // certificate is checked against the public_name. Any other
            // path (no ECH, GREASE, or ECH accepted) verifies against the
            // real `server_name`.
            #[cfg(feature = "ech")]
            let reference_name: &str = match self.ech_state.as_ref() {
                Some(state) if matches!(state.outcome, Some(EchOutcome::Rejected)) => {
                    &state.outer_public_name
                }
                _ => &self.server_name,
            };
            #[cfg(not(feature = "ech"))]
            let reference_name: &str = &self.server_name;
            verify_hostname(&leaf, reference_name)?;
            // RFC 6066 §8 / RFC 6960: a stapled OCSP response is only
            // meaningful once the chain is trusted. Validate now against the
            // issuer; reject `revoked` or `unknown` outright.
            if let Some(ocsp) = self.peer_ocsp_response.as_deref()
                && self.cert_chain.len() >= 2
            {
                let issuer = Certificate::from_der(self.cert_chain[1].clone())
                    .map_err(|_| Error::BadCertificate)?;
                let resp = crate::x509::OcspResponse::from_der(ocsp.to_vec())
                    .map_err(|_| Error::OcspResponseInvalid)?;
                match resp
                    .check_for_cert_with_options(
                        &leaf,
                        &issuer,
                        &crate::x509::OcspCheckOptions::new(&self.config.signature_policy)
                            .with_time(now.as_ref()),
                    )
                    .map_err(|_| Error::OcspResponseInvalid)?
                {
                    crate::x509::OcspCertStatus::Good => {}
                    crate::x509::OcspCertStatus::Revoked { .. } => {
                        return Err(Error::CertificateRevoked);
                    }
                    crate::x509::OcspCertStatus::Unknown => {
                        return Err(Error::OcspResponseInvalid);
                    }
                }
            }
            key
        } else {
            leaf.subject_public_key()
                .map_err(|_| Error::BadCertificate)?
        };

        let th = self.core.transcript.current_hash();
        let content = certificate_verify_content(true, th.as_slice());
        verify_signature(
            scheme,
            &leaf_key,
            &content,
            &signature,
            &self.config.signature_policy,
        )?;

        self.leaf_key = Some(leaf_key);
        self.core.transcript.update(raw);
        self.state = State::WaitFinished;
        Ok(())
    }

    fn on_finished(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::FINISHED {
            return Err(Error::UnexpectedMessage);
        }
        let suite = self.suite.expect("suite set");
        let shts = self.server_hs_secret.as_ref().expect("server hs secret");

        // Verify the server Finished over Hash(CH..CertificateVerify) — or,
        // under PSK, Hash(CH..EE).
        let th = self.core.transcript.current_hash();
        let expected = finished_verify_data(suite.hash, shts, th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.core.transcript.update(raw);

        // draft-ietf-tls-esni-22 §6.1.6: the server rejected our real-ECH
        // offer. The handshake authenticated the server against the outer
        // `public_name` identity (chain + hostname in CertificateVerify,
        // MAC binding just above) — and ONLY now do we hand any
        // `retry_configs` lifted from EncryptedExtensions to the caller.
        // The connection itself must not become usable for application
        // data: we abort here (before deriving application traffic keys
        // or emitting our own Finished) and `process_new_packets` tears
        // the engine down with an `ech_required` alert. If server
        // authentication had failed, the error above surfaced WITHOUT the
        // configs. An empty Vec means the server published no
        // retry_configs (rejection without a refresh offer).
        #[cfg(feature = "ech")]
        if let Some(state) = self.ech_state.as_mut()
            && matches!(state.outcome, Some(EchOutcome::Rejected))
        {
            return Err(Error::EchRejected(
                state.retry_configs.take().unwrap_or_default(),
            ));
        }

        // Derive the application traffic secrets over Hash(CH..server
        // Finished). This must happen BEFORE we emit EOED (which would
        // otherwise enter the transcript) so the secret matches the server's
        // computation. Borrow ks just long enough to compute, then drop so
        // we can call other &mut self methods below.
        let (cats, sats, ems) = {
            let ks = self.ks.as_mut().expect("key schedule");
            ks.enter_master();
            let th_app = self.core.transcript.current_hash();
            let cats = ks.client_application_traffic_secret(th_app.as_slice());
            let sats = ks.server_application_traffic_secret(th_app.as_slice());
            let ems = ks.exporter_master_secret(th_app.as_slice());
            (cats, sats, ems)
        };
        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log(
                "CLIENT_TRAFFIC_SECRET_0",
                &self.client_random,
                cats.as_slice(),
            );
            kl.log(
                "SERVER_TRAFFIC_SECRET_0",
                &self.client_random,
                sats.as_slice(),
            );
            kl.log("EXPORTER_SECRET", &self.client_random, ems.as_slice());
        }
        // QUIC layer hooks: 1-RTT (application) traffic secrets. Client
        // writes with `cats`, reads with `sats`.
        self.notify_traffic_secret(
            super::super::quic_hooks::Level::OneRtt,
            super::super::quic_hooks::Direction::Tx,
            cats.as_slice(),
        );
        self.notify_traffic_secret(
            super::super::quic_hooks::Level::OneRtt,
            super::super::quic_hooks::Direction::Rx,
            sats.as_slice(),
        );
        self.exporter_secret = Some(ems);

        // 0-RTT acceptance: emit EndOfEarlyData under the early write key
        // (still installed), then switch to the client-handshake write key
        // before sending our Finished. RFC 9001 §8.3 forbids
        // EndOfEarlyData in QUIC — 0-RTT termination is signalled by the
        // packet-number space rather than by a handshake message.
        if self.early_data_accepted {
            if self.engine_mode == super::super::quic_hooks::EngineMode::Quic {
                debug_assert!(false, "RFC 9001 §8.3 forbids EndOfEarlyData in QUIC mode");
                return Err(Error::InappropriateState);
            }
            let mut eoed = alloc::vec![hs_type::END_OF_EARLY_DATA];
            eoed.extend_from_slice(&[0u8, 0, 0]); // u24 length = 0
            self.core.emit_handshake(eoed);
            let chts = self
                .deferred_client_hs_secret
                .take()
                .ok_or(Error::InappropriateState)?;
            self.core.set_write(RecordCrypter::new(
                suite.hash,
                suite.aead,
                suite.key_len,
                &chts,
            ));
        }

        // mTLS: if the server sent CertificateRequest, emit Certificate +
        // CertificateVerify before our Finished. An empty Certificate is
        // wire-legal when we have no cert configured; the server may then
        // close with `certificate_required` if it demanded one.
        if self.cert_request_received {
            self.send_client_certificate();
            if self.config.client_cert.is_some() {
                self.send_client_certificate_verify()?;
            }
        }

        // Our Finished, over the handshake context up to (and including, for
        // 0-RTT) EndOfEarlyData — i.e. the current transcript hash here.
        let chts = self.client_hs_secret.as_ref().expect("client hs secret");
        let th_for_cfin = self.core.transcript.current_hash();
        let verify_data = finished_verify_data(suite.hash, chts, th_for_cfin.as_slice());
        let finished = build_finished(verify_data.as_slice());
        // RFC 9001 §4.1.4: client Finished rides at Handshake level.
        self.emit_handshake_at(super::super::quic_hooks::Level::Handshake, finished);

        // Derive resumption_master_secret over Hash(CH..client Finished). The
        // PSK for a future ticket is `HKDF-Expand-Label(rms, "resumption",
        // nonce)`; we stash RMS now so that any NewSessionTicket that arrives
        // post-handshake can derive its PSK from this final transcript.
        let th_rms = self.core.transcript.current_hash();
        let rms = {
            let ks = self.ks.as_mut().expect("key schedule");
            ks.resumption_master_secret(th_rms.as_slice())
        };
        self.rms = Some(rms);

        // Switch to application traffic keys (TLS / DTLS only; the QUIC
        // layer holds 1-RTT AEAD state in its own crypto module).
        if !self.skip_record_keys() {
            self.core.set_write(RecordCrypter::new(
                suite.hash,
                suite.aead,
                suite.key_len,
                &cats,
            ));
            self.core.set_read(RecordCrypter::new(
                suite.hash,
                suite.aead,
                suite.key_len,
                &sats,
            ));
        }
        // Retain both directions' app secrets so we can step them on KeyUpdate.
        self.client_app_secret = Some(cats);
        self.server_app_secret = Some(sats);
        // RFC 8446 §5: ChangeCipherSpec is no longer expected after the
        // handshake completes.
        self.core.close_ccs_window();
        self.state = State::Connected;
        Ok(())
    }
}

impl ClientConnection {
    /// mTLS: emit a `Certificate` carrying our configured chain (or an empty
    /// chain if no client cert is configured).
    fn send_client_certificate(&mut self) {
        let mut msg = alloc::vec![hs_type::CERTIFICATE];
        with_len_u24(&mut msg, |b| {
            b.push(0); // certificate_request_context: empty
            with_len_u24(b, |list| {
                if let Some(cc) = self.config.client_cert.as_ref() {
                    for cert in &cc.chain {
                        with_len_u24(list, |c| c.extend_from_slice(cert));
                        with_len_u16(list, |_| {});
                    }
                }
            });
        });
        // RFC 9001 §4.1.4: mTLS client Certificate rides at Handshake level.
        self.emit_handshake_at(super::super::quic_hooks::Level::Handshake, msg);
    }

    /// mTLS: sign the running transcript with the configured client key and
    /// emit a `CertificateVerify`.
    fn send_client_certificate_verify(&mut self) -> Result<(), Error> {
        let cc = self
            .config
            .client_cert
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let th = self.core.transcript.current_hash();
        let content = certificate_verify_content(false, th.as_slice());
        let scheme = cc.signature_scheme();
        let signature = match &cc.key {
            ClientKey::Rsa(_) => {
                // The CertificateVerify needs an RNG; reuse our handshake one
                // is impractical here, so derive a deterministic one keyed on
                // the transcript. For now, return an error if the test ever
                // uses RSA; ECDSA and Ed25519 are deterministic.
                return Err(Error::HandshakeFailure);
            }
            ClientKey::Ecdsa(k) => {
                let sig = match k.curve() {
                    CurveId::P384 => k.sign::<Sha384>(&content),
                    CurveId::P521 => k.sign::<Sha512>(&content),
                    _ => k.sign::<Sha256>(&content),
                }
                .map_err(|_| Error::HandshakeFailure)?;
                sig.to_der(k.curve())
            }
            ClientKey::Ed25519(k) => k.sign(&content).to_bytes().to_vec(),
            // Ed448: raw 114-byte R‖S over the empty context (pure Ed448).
            ClientKey::Ed448(k) => k.sign(&content).to_bytes().to_vec(),
            // Client-side ML-DSA: sign deterministically (FIPS 204 supports
            // both deterministic and hedged modes; the client has no RNG
            // to thread here). The resulting signature still verifies under
            // the standard ML-DSA verify routine.
            ClientKey::MlDsa44(k) => k
                .sign_deterministic(&content, b"")
                .map_err(|_| Error::HandshakeFailure)?,
            ClientKey::MlDsa65(k) => k
                .sign_deterministic(&content, b"")
                .map_err(|_| Error::HandshakeFailure)?,
            ClientKey::MlDsa87(k) => k
                .sign_deterministic(&content, b"")
                .map_err(|_| Error::HandshakeFailure)?,
        };
        let mut msg = alloc::vec![hs_type::CERTIFICATE_VERIFY];
        with_len_u24(&mut msg, |b| {
            b.extend_from_slice(&scheme.0.to_be_bytes());
            with_len_u16(b, |s| s.extend_from_slice(&signature));
        });
        // RFC 9001 §4.1.4: mTLS client CertificateVerify rides at Handshake.
        self.emit_handshake_at(super::super::quic_hooks::Level::Handshake, msg);
        Ok(())
    }
}

/// Attempts the real-ECH seal pipeline for an initial ClientHello, per
/// Bundle returned by [`seal_real_ech_on_ch1`] — the outer + inner CH
/// wire bytes plus the HPKE state the connection needs to retain
/// across an HRR retry (draft-ietf-tls-esni-22 §6.1.5 / §7.2.2).
#[cfg(feature = "ech")]
pub(crate) struct EchSealOutput {
    pub outer_ch: Vec<u8>,
    pub inner_ch_bytes: Vec<u8>,
    pub sender: SenderContext,
    pub sym: HpkeSymCipherSuite,
    pub config_id: u8,
    pub inner_ch1_random: [u8; 32],
    pub maximum_name_length: u8,
    /// `ECHConfig.public_name` used as the outer CH's SNI; on rejection
    /// the server certificate is verified against this name.
    pub public_name: String,
}

/// draft-ietf-tls-esni-22 §6. Returns `Some(EchSealOutput)` if a
/// sealed pair was successfully produced; returns `None` otherwise
/// (the caller falls back to the GREASE-path CH built without
/// `ech_override`).
///
/// `None` covers every "no real-ECH today" condition uniformly so the
/// caller doesn't fork:
///
/// - `config.ech` is `None` or `Grease`
/// - the configured `ECHConfigList` has no supported (draft-22) entry
/// - the first supported entry has no usable HPKE symmetric suite
/// - `public_name` isn't valid UTF-8 (we need a `String` for the outer SNI)
/// - PSK resumption is offered (Real ECH + PSK lands in a wave-later)
/// - HPKE setup_sender or AEAD seal fail (unlikely; treated as falling
///   back to GREASE rather than aborting the handshake)
///
/// On success the caller pins the `EchSealOutput` into
/// [`ClientConnection::ech_state`] so the SH processing can verify the
/// accept signal over `Hash(inner_CH || zero-tail SH)`, swap the
/// transcript on accept, and re-seal CH2-inner under the retained
/// `SenderContext` on the HRR retry path.
#[cfg(feature = "ech")]
fn seal_real_ech_on_ch1<R: RngCore>(
    conn: &ClientConnection,
    random: Random,
    effective_suites: &[CipherSuite],
    groups: &[NamedGroup],
    share_groups: &[NamedGroup],
    server_name: &str,
    rng: &mut R,
) -> Option<EchSealOutput> {
    // Real ECH + PSK is a separate wave: defer.
    if conn.psk_offered.is_some() {
        return None;
    }
    let ech_client = conn.config.ech.as_ref()?;
    let list = match &ech_client.mode {
        crate::tls::ech::EchClientMode::Real(l) => l,
        crate::tls::ech::EchClientMode::Grease(_) => return None,
    };
    // Clone the first supported ECHConfig so we don't hold a long
    // borrow of `conn.config` across the seal closure (which itself
    // calls back into `conn.build_client_hello`).
    let echcfg = list.first_supported()?.clone();
    let contents = echcfg.contents.as_ref()?;
    let sym = *contents.key_config.cipher_suites.first()?;
    let config_id = contents.key_config.config_id;
    let maximum_name_length = contents.maximum_name_length;
    let public_name_str = String::from(core::str::from_utf8(&contents.public_name).ok()?);
    let inner_marker = crate::tls::ech::inner::inner_extension_body();
    // draft-ietf-tls-esni-22 §6.1: `key_share` is one of the
    // outer-extensions that gets compressed across the seam, so the
    // inner and outer CHs MUST present the same `key_share` bytes —
    // route `share_groups` into both build calls.
    let inner_ch = conn.build_client_hello(
        random,
        String::from(server_name),
        effective_suites,
        groups,
        share_groups,
        &[],
        Some(&inner_marker),
    );
    let inner_sni_len = server_name.len();
    let suites_owned = effective_suites.to_vec();
    let groups_owned = groups.to_vec();
    let share_groups_owned = share_groups.to_vec();
    let public_name_closure = public_name_str.clone();
    let conn_for_closure = conn;
    let sealed = crate::tls::ech::outer::seal_with(
        &echcfg,
        sym,
        &inner_ch,
        inner_sni_len,
        rng,
        |enc, padded_len| {
            let outer_body =
                crate::tls::ech::outer::build_outer_ext_body(sym, config_id, enc, padded_len);
            conn_for_closure.build_client_hello(
                random,
                public_name_closure.clone(),
                &suites_owned,
                &groups_owned,
                &share_groups_owned,
                &[],
                Some(&outer_body),
            )
        },
    )
    .ok()?;
    // Extract CH1-inner's `random` from the encoded inner CH. The
    // ClientHello body opens with version(2) + random(32); the
    // handshake header (type=1 + 24-bit length) precedes it, so the
    // random sits at offset 4 + 2 = 6.
    if inner_ch.len() < 38 {
        return None;
    }
    let mut inner_ch1_random = [0u8; 32];
    inner_ch1_random.copy_from_slice(&inner_ch[6..38]);
    Some(EchSealOutput {
        outer_ch: sealed.outer_ch,
        inner_ch_bytes: inner_ch,
        sender: sealed.sender,
        sym,
        config_id,
        inner_ch1_random,
        maximum_name_length,
        public_name: public_name_str,
    })
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
        Error::CertificateRevoked | Error::OcspResponseInvalid => AlertDescription::BadCertificate,
        #[cfg(feature = "ech")]
        Error::EchDecryptionFailed => AlertDescription::DecryptError,
        #[cfg(feature = "ech")]
        Error::EchDecodeError => AlertDescription::IllegalParameter,
        // draft-ietf-tls-esni-22 §11.2: `ech_required` (121). The named
        // variant is deliberately not added to the (exhaustive, public)
        // `AlertDescription` enum; the raw code is wire-identical.
        #[cfg(feature = "ech")]
        Error::EchRejected(_) => AlertDescription::Unknown(121),
        #[cfg(feature = "cert-compression")]
        Error::CertDecompressionFailed => AlertDescription::BadCertificate,
        _ => AlertDescription::HandshakeFailure,
    }
}

/// Returns the hash function fixed by a cipher suite, if we recognize the
/// suite identifier.
fn suite_hash(s: CipherSuite) -> Option<HashAlg> {
    lookup_suite(s).map(|p| p.hash)
}

/// Patches a single PSK binder into the ClientHello bytes built by
/// [`ClientConnection::build_client_hello`].
///
/// `ch[..truncated_len]` is the truncated CH (everything before the
/// `pre_shared_key` binders field). The remaining `ch[truncated_len..]` is
/// the binders field laid out as `u16 outer_len ‖ u8 inner_len ‖ binder_bytes`,
/// where `binder_bytes` is currently `hash_len` zeros. The function computes
/// `binder = HMAC(binder_finished_key(binder_key("res binder")),
/// Transcript-Hash(truncated_CH))` and overwrites the trailing `hash_len`
/// bytes of `ch` in place.
fn patch_psk_binder(ch: &mut [u8], truncated_len: usize, hash: HashAlg, psk: &[u8]) {
    let hash_len = hash.output_len();
    let ks = KeySchedule::with_psk(hash, psk);
    let res_bk = ks.binder_key(b"res binder");
    let fk = binder_finished_key(hash, &res_bk);
    let th = hash.hash(&ch[..truncated_len]);
    let binder: Vec<u8> = match hash {
        HashAlg::Sha256 => Hmac::<Sha256>::mac(fk.as_slice(), th.as_slice())
            .as_ref()
            .to_vec(),
        HashAlg::Sha384 => Hmac::<Sha384>::mac(fk.as_slice(), th.as_slice())
            .as_ref()
            .to_vec(),
    };
    let start = ch.len() - hash_len;
    ch[start..].copy_from_slice(&binder);
}

fn is_hello_retry_request(random: &Random) -> bool {
    random == &crate::tls::codec::HRR_RANDOM
}

/// One entry in the TLS 1.3 `Certificate` message: the cert DER and the
/// parsed per-cert extension list (RFC 8446 §4.4.2).
type CertificateEntry = (Vec<u8>, Vec<crate::tls::codec::RawExtension>);

/// Parses a TLS 1.3 `Certificate` message body into the per-entry
/// `(cert_der, extensions)` tuples (end-entity first).
fn parse_certificate_list(body: &[u8]) -> Result<Vec<CertificateEntry>, Error> {
    let mut c = ReadCursor::new(body);
    let _context = c.vec_u8()?; // certificate_request_context
    let list = c.vec_u24()?;
    c.expect_empty()?;

    let mut entries = ReadCursor::new(list);
    let mut out: Vec<CertificateEntry> = Vec::new();
    while !entries.is_empty() {
        let cert = entries.vec_u24()?.to_vec();
        let exts_bytes = entries.vec_u16()?;
        // Parse the per-cert extensions into RawExtension tuples. The
        // RFC 8446 §4.2 rule that an extension type appears at most once
        // applies here too.
        let mut ext_c = ReadCursor::new(exts_bytes);
        let mut exts: Vec<crate::tls::codec::RawExtension> = Vec::new();
        while !ext_c.is_empty() {
            let ty = crate::tls::codec::ExtensionType(ext_c.u16()?);
            let data = ext_c.vec_u16()?.to_vec();
            if exts.iter().any(|(t, _)| *t == ty) {
                return Err(Error::IllegalParameter);
            }
            exts.push((ty, data));
        }
        out.push((cert, exts));
    }
    Ok(out)
}

/// Builds a `Finished` handshake message from its `verify_data`.
fn build_finished(verify_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + verify_data.len());
    out.push(hs_type::FINISHED);
    let len = verify_data.len();
    out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    out.extend_from_slice(verify_data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::tls::ContentType;
    use crate::tls::codec::{ClientHello, ExtensionType, read_record};

    #[test]
    fn client_hello_is_well_formed() {
        let mut rng = HmacDrbg::<Sha256>::new(b"p8-client", b"nonce", &[]);
        let config = ClientConfig::new(RootCertStore::new());
        let mut client = ClientConnection::new(config, "example.com", &mut rng);
        assert!(client.is_handshaking());

        let out = client.write_tls();
        let rec = read_record(&out).unwrap().unwrap();
        assert_eq!(rec.content_type, ContentType::Handshake);
        assert_eq!(rec.len, out.len());

        let mut c = ReadCursor::new(rec.fragment);
        assert_eq!(c.u8().unwrap(), hs_type::CLIENT_HELLO);
        let body = c.vec_u24().unwrap();
        let ch = ClientHello::decode(body).unwrap();

        assert_eq!(ch.cipher_suites.len(), 3);
        assert!(ch.session_id.is_empty());
        for ty in [
            ExtensionType::SERVER_NAME,
            ExtensionType::SUPPORTED_GROUPS,
            ExtensionType::SIGNATURE_ALGORITHMS,
            ExtensionType::SUPPORTED_VERSIONS,
            ExtensionType::KEY_SHARE,
        ] {
            assert!(ext::find(&ch.extensions, ty).is_some());
        }
        // The key_share offers x25519mlkem768, x25519, secp256r1 and secp384r1.
        let ks = ext::find(&ch.extensions, ExtensionType::KEY_SHARE).unwrap();
        assert_eq!(ext::parse_client_key_shares(ks).unwrap().len(), 4);
    }

    #[test]
    fn rejects_garbage_server_hello() {
        let mut rng = HmacDrbg::<Sha256>::new(b"p8-client-2", b"nonce", &[]);
        let mut client =
            ClientConnection::new(ClientConfig::new(RootCertStore::new()), "h", &mut rng);
        let _ = client.write_tls();
        // A handshake record claiming to be a (truncated) ServerHello.
        client.read_tls(&[0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00]);
        assert!(client.process_new_packets().is_err());
    }

    // RFC 8446 §4.1.3: the ServerHello MUST echo the ClientHello's
    // `legacy_session_id`. This client always offers an empty session id, so a
    // ServerHello that echoes a non-empty one is a protocol violation and must
    // abort with illegal_parameter (fail-closed hardening).
    #[test]
    fn rejects_server_hello_with_nonempty_session_id_echo() {
        let mut rng = HmacDrbg::<Sha256>::new(b"sh-sid-echo", b"nonce", &[]);
        let mut client =
            ClientConnection::new(ClientConfig::new(RootCertStore::new()), "h", &mut rng);
        let _ = client.write_tls();

        // A ServerHello with a non-HRR random, a non-empty session_id, and an
        // otherwise plausible suite. The session_id echo check fires before any
        // suite/version/key_share processing, so this minimal SH reaches it.
        let sh = ServerHello {
            random: [0x11; 32],
            session_id: alloc::vec![0xab; 4], // non-empty: we offered empty
            cipher_suite: CipherSuite::AES_128_GCM_SHA256,
            extensions: alloc::vec![(ExtensionType::SUPPORTED_VERSIONS, alloc::vec![0x03, 0x04],)],
        };
        let raw = sh.encode();
        // `on_server_hello` takes the message body (after the u24 length).
        let mut c = ReadCursor::new(&raw);
        assert_eq!(c.u8().unwrap(), hs_type::SERVER_HELLO);
        let body = c.vec_u24().unwrap();

        let err = client
            .on_server_hello(hs_type::SERVER_HELLO, body, &raw)
            .unwrap_err();
        assert!(matches!(err, Error::IllegalParameter));
    }

    // RFC 8446 §4.2: a TLS 1.3 handshake message must not contain two
    // extensions with the same type. The EE walker rejects duplicates
    // with `illegal_parameter`.
    #[test]
    fn client_rejects_duplicate_ee_extension() {
        let mut rng = HmacDrbg::<Sha256>::new(b"h1-ee-dup", b"nonce", &[]);
        let mut config = ClientConfig::new(RootCertStore::new());
        // Offer "h2" so the ALPN extension survives the offer-match gate
        // and we actually exercise the duplicate-detection path. (Without
        // this, the second `alpn` is fine on its own but the test would
        // be checking the wrong code path.)
        config.alpn_protocols.push(b"h2".to_vec());
        let mut client = ClientConnection::new(config, "h", &mut rng);
        // One ALPN extension carrying a single protocol "h2".
        // ProtocolNameList: u16 length, then one entry (u8 length || bytes).
        let alpn_body: alloc::vec::Vec<u8> = alloc::vec![
            0x00, 0x03, // protocol_name_list length = 3
            0x02, // entry length 2
            b'h', b'2',
        ];
        // Wire bytes for one extension: type(2) || length(2) || body.
        let mut ext = alloc::vec::Vec::new();
        ext.extend_from_slice(&(ExtensionType::ALPN.0).to_be_bytes());
        ext.extend_from_slice(&(alpn_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&alpn_body);
        // Duplicate it.
        let mut all_exts = ext.clone();
        all_exts.extend_from_slice(&ext);
        // EE body = extensions_block_len(2) || all_exts.
        let mut body = alloc::vec::Vec::new();
        body.extend_from_slice(&(all_exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&all_exts);
        // Handshake header: msg_type(1=EE)=8 || length_u24 || body.
        let mut raw = alloc::vec::Vec::new();
        raw.push(hs_type::ENCRYPTED_EXTENSIONS);
        raw.push(0x00);
        raw.extend_from_slice(&(body.len() as u16).to_be_bytes());
        raw.extend_from_slice(&body);

        let err = client
            .on_encrypted_extensions(hs_type::ENCRYPTED_EXTENSIONS, &raw)
            .unwrap_err();
        assert!(matches!(err, Error::IllegalParameter));
    }

    /// Wave 3b.2: when [`ClientConfig::ech`] is set to a Real
    /// `ECHConfigList`, the client's first `ClientHello` on the wire is
    /// the **outer** CH — its SNI carries the `public_name` from the
    /// `ECHConfig` rather than the application-level `server_name`.
    /// Round-tripping the outer CH through `try_decap_inner` with the
    /// matching server key ring recovers the **inner** CH, whose SNI
    /// is the original `server_name`.
    #[cfg(feature = "ech")]
    #[test]
    fn ech_client_seals_outer_with_public_name() {
        use crate::hpke::{HpkeAead, HpkeKdf, HpkeKem};
        use crate::tls::ech::HpkeSymCipherSuite;
        use crate::tls::ech::keys::{EchKeyPair, EchKeyRing};
        use crate::tls::ech::outer::try_decap_inner;

        // Fresh server-side ECH key with public_name = "public.example".
        let mut keygen_rng = HmacDrbg::<Sha256>::new(b"ech-3b2-keygen", b"nonce", &[]);
        let suites = alloc::vec![HpkeSymCipherSuite {
            kdf_id: HpkeKdf::HkdfSha256.id(),
            aead_id: HpkeAead::Aes128Gcm.id(),
        }];
        let pair = EchKeyPair::generate(
            &mut keygen_rng,
            HpkeKem::DhkemX25519HkdfSha256,
            0x42,
            b"public.example",
            64,
            suites,
        )
        .expect("ech keygen");
        let config = pair.config().clone();
        let list = crate::tls::ech::EchConfigList::new(alloc::vec![config.clone()]);
        let ring = EchKeyRing::from_pairs(alloc::vec![pair]);

        // Build a client config that wants real ECH against `list`.
        let mut cfg = ClientConfig::new(RootCertStore::new());
        cfg.ech = Some(crate::tls::ech::EchClient::from_config_list(list));

        // Drive the client. The inner SNI is "secret.example"; the
        // outer SNI must be "public.example".
        let inner_sni = "secret.example";
        let mut rng = HmacDrbg::<Sha256>::new(b"ech-3b2-client", b"nonce", &[]);
        let mut client = ClientConnection::new(cfg, inner_sni, &mut rng);

        // First emitted record is the outer CH as a plaintext handshake
        // record. Extract the handshake message bytes (header + body).
        let out = client.write_tls();
        let rec = read_record(&out).unwrap().unwrap();
        assert_eq!(rec.content_type, ContentType::Handshake);
        let outer_msg = rec.fragment.to_vec();

        // Outer CH SNI must be the public_name.
        let mut c = ReadCursor::new(&outer_msg);
        assert_eq!(c.u8().unwrap(), hs_type::CLIENT_HELLO);
        let body = c.vec_u24().unwrap();
        let outer_ch = ClientHello::decode(body).unwrap();
        let outer_sni_body = ext::find(&outer_ch.extensions, ExtensionType::SERVER_NAME)
            .expect("outer CH has SNI extension");
        let outer_sni = crate::tls::codec::extension::parse_server_name(outer_sni_body)
            .unwrap()
            .expect("outer SNI present");
        assert_eq!(outer_sni, "public.example");

        // The outer CH must carry an encrypted_client_hello extension.
        assert!(
            ext::find(&outer_ch.extensions, ExtensionType::ENCRYPTED_CLIENT_HELLO).is_some(),
            "outer CH missing encrypted_client_hello"
        );

        // HPKE-decap → recover the inner CH bytes; its SNI must be the
        // application-level inner SNI.
        let inner_msg = try_decap_inner(&outer_msg, &ring)
            .expect("server-side decap")
            .inner_ch_bytes;
        let mut ic = ReadCursor::new(&inner_msg);
        assert_eq!(ic.u8().unwrap(), hs_type::CLIENT_HELLO);
        let inner_body = ic.vec_u24().unwrap();
        let inner_ch = ClientHello::decode(inner_body).unwrap();
        let inner_sni_body = ext::find(&inner_ch.extensions, ExtensionType::SERVER_NAME)
            .expect("inner CH has SNI extension");
        let inner_sni_parsed = crate::tls::codec::extension::parse_server_name(inner_sni_body)
            .unwrap()
            .expect("inner SNI present");
        assert_eq!(inner_sni_parsed, inner_sni);
    }
}
