// Private module, re-exported only as `pub(crate)`, so its `pub` items are
// crate-internal: allow `unreachable_pub` module-wide. `dead_code` is not
// suppressed (the module is fully used).
#![allow(unreachable_pub)]

//! DTLS 1.2 server state machine (RFC 6347).
//!
//! Mirror of [`super::client12::DtlsClientConnection12`]. The server
//! consumes the first ClientHello, optionally responds with a
//! HelloVerifyRequest (RFC 6347 §4.2.1) so the client proves source-address
//! reachability before any state is allocated, then proceeds through the
//! TLS 1.2 ECDHE-ECDSA handshake under the DTLS record layer. With a
//! `ServerConfig12Internal::with_client_auth` policy the server flight
//! carries a `CertificateRequest` and the client's `Certificate` /
//! `CertificateVerify` are verified as the TLS 1.2 server does (RFC 5246
//! §7.4.4, §7.4.6, §7.4.8).

use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, CurveId};
use crate::hash::{Sha256, Sha384, Sha512};
use crate::rng::RngCore;
use crate::rsa::BoxedRsaPrivateKey;
use crate::signature_registry::SignaturePolicy;
use crate::tls::codec::extension as ext;
use crate::tls::codec::handshake12::{
    CertificateRequest12, ClientKeyExchange, ServerKeyExchange, signed_message,
};
use crate::tls::codec::{
    CipherSuite, ExtensionType, NamedGroup, Random, ReadCursor, ServerHello, SignatureScheme,
    hs_type, with_len_u8, with_len_u24,
};
use crate::tls::conn::{
    ClientAuthPolicy12, SUITES_12, ServerKey, SigKind, SuiteParams12, parse_certificate_list_12,
};
use crate::tls::crypto::aead12::RecordCrypter12;
use crate::tls::crypto::prf::{
    extended_master_secret, finished_verify_data, master_secret, tls12_exporter,
};
use crate::tls::crypto::{Transcript, verify_signature_tls12};
use crate::tls::keylog::KeyLog;
use crate::tls::pki::CrlStore;
use crate::tls::{AlertDescription, ContentType, Error, ProtocolVersion};
use crate::x509::{AnyPublicKey, Time};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use super::cid::{CidState, connection_id_extension, negotiate_server};
use super::cookie::{CookieGenerator, build_ch_fingerprint};
use super::reassembly::{
    HandshakeFragment, MAX_HS_MSG_SEQ, PreCookieBuffer, Reassembler, read_fragment,
    transcript_message, write_fragments, write_message,
};
use super::record::{self, ParsedDtlsRecord, TLS12_CID_CONTENT_TYPE};
use super::reliability::{Flight, FlightRecord, Retransmit};
use super::replay::AntiReplayWindow;

#[allow(unused_imports)]
use crate::ct::ConstantTimeEq;

/// HelloVerifyRequest handshake type code (RFC 6347 §4.2.1).
const HS_HELLO_VERIFY_REQUEST: u8 = 3;

/// Cap on how many times the final CCS + Finished flight is re-sent in
/// answer to a retransmitted client Finished. Bounds the work a captured
/// client Finished replayed by an attacker can trigger (each re-send is
/// two small records — no amplification, but not unbounded either).
const MAX_FINAL_FLIGHT_RESENDS: u32 = 6;

/// Default per-fragment payload size for outbound handshake messages.
const DEFAULT_MAX_FRAGMENT: usize = 1100;

/// Configuration for a DTLS 1.2 server.
pub(crate) struct ServerConfig12Internal {
    /// Certificate chain (leaf first).
    cert_chain: Vec<Vec<u8>>,
    /// Signing key. Matches TLS 1.2's scope: RSA-PSS, ECDSA, or EdDSA under
    /// the `ECDHE_ECDSA` suites (RFC 8422 §2.2). An ML-DSA key can be
    /// plumbed in but fails at handshake time: nothing specifies it for
    /// (D)TLS 1.2, so it has no signature scheme there.
    key: ServerKey,
    /// Cookie generator secret. When `None`, the server skips
    /// HelloVerifyRequest entirely (useful for tests; a production
    /// configuration always sets this).
    cookie_secret: Option<[u8; 32]>,
    /// The cookie secret in use before the last rotation, if any. Cookies
    /// are only ever *minted* under `cookie_secret`, but are *accepted*
    /// under either, so rotating the secret does not strand every client
    /// whose HelloVerifyRequest cookie is in flight (the cookie's own
    /// max-age still bounds how long the old secret stays useful — RFC 6347
    /// §4.2.1). Keep at most one previous generation: a cookie minted two
    /// rotations ago is refused.
    previous_cookie_secret: Option<[u8; 32]>,
    /// When `true`, ALL clients must complete the cookie exchange before
    /// the server allocates any handshake state. When `false`, the cookie
    /// step is skipped — only safe for tests.
    require_cookie_exchange: bool,
    /// RFC 7627 §5.3 — when `true` (the default), a ClientHello that does
    /// not offer `extended_master_secret` is refused; without EMS the master
    /// secret is not bound to the transcript (the triple-handshake family).
    /// `false` only for legacy clients that predate RFC 7627. Forwarded from
    /// [`crate::tls::Config::require_extended_master_secret`].
    require_ems: bool,
    /// ALPN protocols this server accepts, in preference order (RFC 7301).
    /// Empty (the default) ignores the client's offer. Forwarded from
    /// [`crate::tls::Config::alpn_protocols`].
    alpn_protocols: Vec<Vec<u8>>,
    /// ECDHE groups this server accepts, in ITS preference order: the first
    /// listed group the client offered is used for `ServerKeyExchange`.
    /// Defaults to `[X25519, SECP256R1, SECP384R1, SECP521R1]`. Forwarded from
    /// [`crate::tls::Config::key_exchange_groups`].
    pub(crate) groups: Vec<NamedGroup>,
    /// Allowed signature algorithms in a client's certificate chain and
    /// `CertificateVerify` (see [`Self::client_auth`]); also the
    /// `supported_signature_algorithms` the `CertificateRequest` lists.
    signature_policy: SignaturePolicy,
    /// Client-certificate policy (mutual authentication). `None` (the
    /// default) sends no `CertificateRequest`. Forwarded from
    /// [`crate::tls::Config::client_auth`].
    client_auth: Option<ClientAuthPolicy12>,
    /// CRLs consulted while validating a client's chain. Forwarded from
    /// [`crate::tls::Config::crls`].
    pub(crate) crls: CrlStore,
    /// Clock for the client chain's validity period. `None` uses the
    /// system clock under `std` and fails closed on `no_std` (see
    /// [`crate::tls::pki::verify_client_chain`]). Forwarded from
    /// [`crate::tls::Config::verification_time`].
    pub(crate) verification_time: Option<Time>,
    /// Optional [`KeyLog`] sink (NSS `SSLKEYLOGFILE` format).
    pub(crate) key_log: Option<Arc<dyn KeyLog>>,
    /// The connection ID this server wants to receive on this connection
    /// (RFC 9146 §3), answered in the ServerHello when the client offered
    /// the `connection_id` extension; `None` never negotiates CIDs. An
    /// empty value asks the client to send without a CID while this server
    /// sends with the client's. At most [`super::cid::MAX_LOCAL_CID_LEN`]
    /// bytes; per connection, never shared across them.
    pub(crate) connection_id: Option<Vec<u8>>,
}

impl ServerConfig12Internal {
    /// New configuration presenting `cert_chain` and signing with the
    /// ECDSA `key`. Cookie exchange is required by default.
    pub fn with_ecdsa(cert_chain: Vec<Vec<u8>>, key: BoxedEcdsaPrivateKey) -> Self {
        Self::with_signing_key(cert_chain, ServerKey::Ecdsa(key))
    }

    /// Shared constructor: `key` is bound to the leaf's SPKI form
    /// ([`ServerKey::bound_to_leaf`]) — an RSA key certified as
    /// `id-RSASSA-PSS` signs `rsa_pss_pss_*`, an external key's schemes are
    /// narrowed to those the leaf permits.
    fn with_signing_key(cert_chain: Vec<Vec<u8>>, key: ServerKey) -> Self {
        let key = key.bound_to_leaf(&cert_chain);
        Self {
            cert_chain,
            key,
            cookie_secret: None,
            previous_cookie_secret: None,
            require_cookie_exchange: true,
            require_ems: true,
            alpn_protocols: Vec::new(),
            groups: crate::tls::conn::GROUPS_12.to_vec(),
            signature_policy: SignaturePolicy::modern(),
            client_auth: None,
            crls: CrlStore::new(),
            verification_time: None,
            key_log: None,
            connection_id: None,
        }
    }

    /// Demands a client certificate: the server flight carries a
    /// `CertificateRequest` (RFC 5246 §7.4.4) and the client's chain is
    /// verified against `roots` for the client-authentication purpose.
    /// With `required`, an empty client `Certificate` aborts the handshake
    /// (`handshake_failure`, §7.4.6); otherwise an anonymous client is
    /// admitted and [`DtlsServerConnection12::peer_certificates`] stays
    /// empty. Forwarded from [`crate::tls::Config::client_auth`].
    pub fn with_client_auth(mut self, roots: crate::tls::RootCertStore, required: bool) -> Self {
        self.client_auth = Some(ClientAuthPolicy12 { roots, required });
        self
    }

    /// Replaces the signature-algorithm policy (see
    /// [`Self::signature_policy`]).
    pub fn with_signature_policy(mut self, policy: SignaturePolicy) -> Self {
        self.signature_policy = policy;
        self
    }

    /// New configuration presenting `cert_chain` and signing with the
    /// Ed25519 `key`: the `ECDHE-ECDSA-*` suites (RFC 8422 §2.2), the
    /// `ServerKeyExchange` signed with `ed25519` (0x0807) — PureEdDSA over
    /// the unhashed parameters (RFC 8422 §5.4, §5.10). Mirrors
    /// `ServerConfig12::with_ed25519`.
    pub fn with_ed25519(cert_chain: Vec<Vec<u8>>, key: crate::ec::Ed25519PrivateKey) -> Self {
        Self::with_signing_key(cert_chain, ServerKey::Ed25519(key))
    }

    /// [`Self::with_ed25519`] for an Ed448 key, signing with `ed448`
    /// (0x0808) under the empty context (RFC 8422 §5.10).
    pub fn with_ed448(cert_chain: Vec<Vec<u8>>, key: crate::ec::Ed448PrivateKey) -> Self {
        Self::with_signing_key(cert_chain, ServerKey::Ed448(key))
    }

    /// Restricts and orders the ECDHE groups (see [`Self::groups`]).
    pub fn with_groups(mut self, groups: Vec<NamedGroup>) -> Self {
        self.groups = groups;
        self
    }

    /// New configuration presenting `cert_chain` and signing with the RSA
    /// `key`. Drives the three `ECDHE-RSA-*` entries of `SUITES_12`; the
    /// signature scheme is `rsa_pss_rsae_sha256` (`rsa_pss_pss_*` for a
    /// leaf certified as `id-RSASSA-PSS`). Mirrors the TLS 1.2 server's
    /// `ServerConfig12::with_rsa`.
    pub fn with_rsa(cert_chain: Vec<Vec<u8>>, key: BoxedRsaPrivateKey) -> Self {
        Self::with_signing_key(cert_chain, ServerKey::Rsa(key))
    }

    /// New configuration whose `ServerKeyExchange` signature is produced
    /// out-of-band by the caller (suspend/resume). `schemes` are the IANA
    /// `SignatureScheme` code points the external key can produce; the first
    /// one DTLS 1.2 defines is signed under and drives suite selection
    /// (ECDSA / EdDSA vs RSA `ECDHE-*`).
    pub fn with_external(cert_chain: Vec<Vec<u8>>, schemes: Vec<u16>) -> Self {
        let schemes = schemes.into_iter().map(SignatureScheme).collect();
        Self::with_signing_key(cert_chain, ServerKey::External { schemes })
    }

    /// Sets the cookie secret used for HelloVerifyRequest. Callers
    /// typically derive this from a long-lived high-entropy server secret.
    pub fn with_cookie_secret(mut self, secret: [u8; 32]) -> Self {
        self.cookie_secret = Some(secret);
        self
    }

    /// Sets the pre-rotation cookie secret (see
    /// [`Self::previous_cookie_secret`]).
    /// Forwarded from [`crate::tls::Config::previous_cookie_secret`].
    pub fn with_previous_cookie_secret(mut self, secret: [u8; 32]) -> Self {
        self.previous_cookie_secret = Some(secret);
        self
    }

    /// Toggles whether the cookie exchange is enforced. Default is `true`.
    /// Disable only for tests where the cookie path isn't under test.
    ///
    /// # Warning: amplification / DoS vector
    ///
    /// With the cookie exchange off, a single spoofed-source ClientHello
    /// makes the server allocate per-connection state, perform an
    /// asymmetric signature, and emit its full multi-KB flight (SH +
    /// Certificate + ServerKeyExchange + ServerHelloDone) to an unverified
    /// address — well over 3x amplification toward a victim of the
    /// attacker's choosing (RFC 6347 §4.2.1). Never disable cookies on a
    /// server reachable from untrusted networks.
    pub fn require_cookie_exchange(mut self, required: bool) -> Self {
        self.require_cookie_exchange = required;
        self
    }

    /// Sets whether clients must offer Extended Master Secret (see
    /// [`Self::require_ems`]). Default `true`.
    pub fn with_require_ems(mut self, required: bool) -> Self {
        self.require_ems = required;
        self
    }

    /// Sets the ALPN protocols this server accepts, in preference order
    /// (see [`Self::alpn_protocols`]).
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Sets the connection ID this server receives under (see
    /// [`Self::connection_id`]).
    pub fn with_connection_id(mut self, cid: Option<Vec<u8>>) -> Self {
        self.connection_id = cid;
        self
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum State {
    /// Awaiting the first ClientHello (cookie path) or the only CH (when
    /// cookies are disabled).
    WaitFirstClientHello,
    /// Sent HelloVerifyRequest, awaiting cookie-bearing second CH.
    WaitSecondClientHello,
    /// Sent server flight (SH/Cert/SKE/[CertificateRequest]/SHDone),
    /// awaiting the client's [Certificate]/CKE/[CertificateVerify]/CCS/
    /// Finished. The order within the flight is enforced by
    /// [`DtlsServerConnection12::on_client_flight`] from what has been
    /// accepted so far.
    WaitClientFlight,
    /// External-signing pause: SH + Certificate are built and the flight is
    /// held while the caller signs the `ServerKeyExchange` params; on resume
    /// the SKE + ServerHelloDone are appended and the flight is sent.
    AwaitingSkeSignature,
    /// Sent our CCS/Finished, awaiting nothing further from the client.
    Connected,
    Closed,
}

/// State stashed while a DTLS 1.2 server flight is suspended awaiting an
/// external `ServerKeyExchange` signature (see
/// [`ServerKey::External`](crate::tls::conn::ServerKey::External)). Holds the
/// half-built flight (ServerHello + Certificate) plus the ECDHE params the
/// resume needs to assemble the signed SKE.
struct PendingSke {
    /// Negotiated signature scheme for the SKE.
    scheme: SignatureScheme,
    /// The SKE signature input (`client_random ‖ server_random ‖ params`).
    content: Vec<u8>,
    /// The flight built so far (ServerHello, Certificate).
    flight: Flight,
    /// Negotiated (EC)DHE group.
    group: NamedGroup,
    /// The server's ephemeral public key share.
    our_point: Vec<u8>,
}

/// A DTLS 1.2 server connection.
pub struct DtlsServerConnection12<R: RngCore> {
    config: Arc<ServerConfig12Internal>,
    rng: R,

    /// Peer address bytes — opaque, used by the cookie generator.
    peer_addr: Vec<u8>,

    state: State,

    /// DTLS handshake message counter for outbound messages.
    out_msg_seq: u16,
    /// Reassembler for inbound messages (created lazily so cookie-bounce
    /// CHs don't allocate state until the cookie is validated).
    reassembler: Option<Reassembler>,
    /// Bounded fragment buffer for a first or cookie-bearing second
    /// ClientHello that does not fit one record — a client on a small path
    /// MTU splits even a plain CH (OpenSSL at its minimum link MTU leaves
    /// ~200 bytes of handshake payload per record), and without this it
    /// could never complete the HelloVerifyRequest round trip. See
    /// [`PreCookieBuffer`] for the limits and why it is only a buffer,
    /// never a sequencer.
    pre_cookie: PreCookieBuffer,

    /// Outbound UDP datagrams.
    out_dgrams: Vec<Vec<u8>>,
    /// Decrypted application data.
    app_in: Vec<u8>,

    /// Record-layer sequence numbers.
    write_epoch: u16,
    write_seq_in_epoch: u64,
    /// Record sequence counter for epoch-0 (plaintext) records. Separate
    /// from `write_seq_in_epoch` so a plaintext record can still be
    /// (re)framed after the write epoch has moved on — a retransmitted
    /// ChangeCipherSpec, for instance (RFC 6347 §4.1: one counter per
    /// epoch).
    plain_write_seq: u64,
    read_epoch: u16,

    /// Anti-replay window for the current encrypted read epoch.
    replay: AntiReplayWindow,

    /// Ephemeral X25519 ECDHE key, populated when [`Self::group`] is
    /// `X25519`.
    x25519: Option<X25519PrivateKey>,
    /// Ephemeral P-256 ECDHE key, populated when [`Self::group`] is
    /// `SECP256R1`.
    p256: Option<BoxedEcdhPrivateKey>,
    /// Ephemeral P-384 ECDHE key, populated when [`Self::group`] is
    /// `SECP384R1`.
    p384: Option<BoxedEcdhPrivateKey>,
    /// Ephemeral P-521 ECDH private key (used when we pick SECP521R1).
    p521: Option<BoxedEcdhPrivateKey>,

    client_random: Option<Random>,
    server_random: Option<Random>,
    /// External-signing continuation; `Some` while suspended awaiting the
    /// `ServerKeyExchange` signature.
    pending_ske: Option<PendingSke>,

    /// Negotiated cipher-suite parameters, pinned on the cookie-validated
    /// ClientHello (or the only CH when cookies are disabled).
    suite: Option<SuiteParams12>,
    /// Negotiated ECDHE group, pinned at suite-selection time. Preference
    /// order is X25519 > P-256 (mirrors the TLS 1.2 server in
    /// `src/tls/conn/server12.rs`).
    group: Option<NamedGroup>,

    transcript: Transcript,

    master: Option<[u8; 48]>,
    read_crypter: Option<RecordCrypter12>,
    write_crypter: Option<RecordCrypter12>,
    /// Pending read crypter parked until the client's CCS arrives.
    pending_read_crypter: Option<RecordCrypter12>,
    /// Pending write crypter parked until we emit our own CCS.
    pending_write_crypter: Option<RecordCrypter12>,

    ccs_received: bool,

    /// Last-built flight retransmit machine.
    retransmit: Retransmit,
    /// Our final flight (CCS + Finished), kept after the handshake so it
    /// can be re-sent when the client's retransmitted Finished shows we
    /// were not heard (RFC 6347 §4.2.4: the last-flight sender
    /// retransmits when the peer re-sends ITS flight). Released once the
    /// client's first application-data record proves it holds our
    /// Finished, or after `MAX_FINAL_FLIGHT_RESENDS` (DTLS-L3).
    final_flight: Option<Flight>,
    /// Re-sends of `final_flight` performed so far.
    final_flight_resends: u32,
    /// The client's Finished `verify_data`, so a retransmitted Finished
    /// can be recognised as the genuine one.
    client_finished: Option<[u8; 12]>,
    /// Current logical time the caller has reported.
    last_now: Duration,
    /// True once the caller has driven the clock via [`Self::set_now`] /
    /// [`Self::on_timeout`]. Governs the cookie-clock fallback — see
    /// [`Self::cookie_now_minutes`].
    clock_driven: bool,

    /// RFC 7627 §5.1 — set when the client offered `extended_master_secret`
    /// and we echoed it. Drives the master-secret derivation choice.
    ems_negotiated: bool,
    /// ALPN protocol selected from the ClientHello and echoed in the
    /// ServerHello (RFC 7301), if any.
    alpn_negotiated: Option<Vec<u8>>,
    /// The ECDHE group selected for `ServerKeyExchange`, once the
    /// ClientHello is committed.
    negotiated_group: Option<NamedGroup>,
    /// The peer's `close_notify` was authenticated.
    close_notify_received: bool,
    /// Our `close_notify` went out; no more application data may follow.
    close_notify_sent: bool,
    /// Connection-ID state once the extension is negotiated (RFC 9146 §3);
    /// `None` when no CIDs are in use.
    cid: Option<CidState>,

    /// mTLS: the client's `Certificate` has been accepted (a chain or,
    /// under a non-required policy, none).
    client_cert_seen: bool,
    /// mTLS: the client's chain (leaf first, DER), once verified; empty
    /// for an anonymous client.
    client_cert_chain: Vec<Vec<u8>>,
    /// mTLS: the verified client leaf key, awaiting (then past) its
    /// `CertificateVerify`.
    client_leaf_key: Option<AnyPublicKey>,
    /// mTLS: the client's `CertificateVerify` has been checked under
    /// `client_leaf_key`.
    client_cert_verified: bool,
}

// The DTLS 1.2 master secret lives for the whole connection (exporters,
// Finished verification) — scrub it on drop so it does not linger in freed
// memory, same as the TLS 1.2 engine.
impl<R: RngCore> Drop for DtlsServerConnection12<R> {
    fn drop(&mut self) {
        if let Some(m) = self.master.as_mut() {
            crate::tls::conn::wipe(m);
        }
    }
}

impl<R: RngCore> DtlsServerConnection12<R> {
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
    pub(crate) fn new(config: Arc<ServerConfig12Internal>, peer_addr: Vec<u8>, rng: R) -> Self {
        // Don't pin the transcript hash yet: the negotiated suite (SHA-256
        // or SHA-384) is unknown until we parse the cookie-validated CH and
        // select from SUITES_12. `Transcript` buffers raw bytes; we call
        // `set_alg` once the suite is pinned.
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
            write_epoch: 0,
            write_seq_in_epoch: 0,
            plain_write_seq: 0,
            read_epoch: 0,
            replay: AntiReplayWindow::new(),
            x25519: None,
            p256: None,
            p384: None,
            p521: None,
            client_random: None,
            server_random: None,
            pending_ske: None,
            suite: None,
            group: None,
            transcript: Transcript::new(),
            master: None,
            read_crypter: None,
            write_crypter: None,
            pending_read_crypter: None,
            pending_write_crypter: None,
            ccs_received: false,
            retransmit: Retransmit::new(),
            final_flight: None,
            final_flight_resends: 0,
            client_finished: None,
            last_now: Duration::from_secs(0),
            clock_driven: false,
            ems_negotiated: false,
            alpn_negotiated: None,
            negotiated_group: None,
            close_notify_received: false,
            close_notify_sent: false,
            cid: None,
            client_cert_seen: false,
            client_cert_chain: Vec::new(),
            client_leaf_key: None,
            client_cert_verified: false,
        }
    }

    /// Returns true once the handshake completes.
    pub fn is_handshake_complete(&self) -> bool {
        self.state == State::Connected
    }

    /// IANA cipher-suite identifier of the negotiated suite, or `None`
    /// until the cookie-validated ClientHello has pinned a suite from the
    /// 6-entry `SUITES_12` matrix (ECDHE-{ECDSA,RSA} × {AES-128-GCM,
    /// ChaCha20-Poly1305, AES-256-GCM-SHA384}). Both ECDSA and RSA-PSS
    /// signing keys are supported; matches the TLS 1.2 server's scope.
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.suite.map(|s| s.suite.0)
    }

    /// The ALPN protocol selected from the client's offer, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_negotiated.as_deref()
    }

    /// The client's certificate chain (leaf first, DER) once its
    /// `CertificateVerify` has been checked; empty when no certificate was
    /// requested or the client presented none.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        if self.client_cert_verified {
            &self.client_cert_chain
        } else {
            &[]
        }
    }

    /// The ECDHE group selected for the `ServerKeyExchange`, once the
    /// ClientHello is committed.
    pub(crate) fn negotiated_group(&self) -> Option<NamedGroup> {
        self.negotiated_group
    }

    /// `true` once the peer's `close_notify` has been authenticated
    /// (RFC 5246 §7.2.1).
    pub fn received_close_notify(&self) -> bool {
        self.close_notify_received
    }

    /// The connection ID the client puts in records to this server
    /// (RFC 9146 §3): `Some(&[])` when CIDs were negotiated but this side
    /// receives none, `None` when they were not negotiated (or not yet).
    pub fn local_connection_id(&self) -> Option<&[u8]> {
        self.cid.as_ref().map(CidState::local)
    }

    /// The connection ID this server puts in records to the client;
    /// `Some(&[])` when the client receives none, `None` when CIDs were
    /// not negotiated. Fixed for the connection's life: DTLS 1.2 has no
    /// way to change CIDs mid-session (RFC 9146 §3).
    pub fn peer_connection_id(&self) -> Option<&[u8]> {
        self.cid.as_ref().map(CidState::peer)
    }

    /// `true` when the datagram most recently fed contained a record that
    /// carried a connection ID, authenticated, and was newer (epoch, then
    /// sequence number) than every record received before it — the two
    /// record-layer conditions RFC 9146 §6 sets for moving the peer's
    /// transport address to that datagram's source. The third, a
    /// reachability test of the new address, is the caller's: RFC 9146 §6
    /// / §9 warn that an on-path attacker who rewrites source addresses can
    /// otherwise turn this server into a reflector towards a third party,
    /// so an application that answers with more than it received must
    /// exchange a ping-pong (or a return-routability check) with the new
    /// address before sending it anything else. A datagram that fails this
    /// test is still a valid datagram; only the address must not move.
    pub fn datagram_allows_peer_address_update(&self) -> bool {
        self.cid.as_ref().is_some_and(CidState::address_update_ok)
    }

    /// `true` while the handshake is not known to be over on both sides:
    /// a flight this side sent awaits the client's answer, or — once
    /// [`Self::is_handshake_complete`] — the client has not yet been seen
    /// to hold our final flight (ChangeCipherSpec + Finished).
    ///
    /// Nothing answers the final flight of a DTLS 1.2 handshake, so it is
    /// not retransmitted on a timer: a client that did not receive it
    /// retransmits *its* Finished, and the engine re-sends the flight in
    /// reply (RFC 6347 §4.2.4, the FINISHED state). While this returns
    /// `true` the caller keeps reading datagrams and sending what
    /// [`Self::pop_outbound_datagrams`] returns. It turns `false` when the
    /// client's first application data or alert arrives — it sends neither
    /// before it has verified our Finished. A client with nothing to say
    /// never provides that evidence, so callers bound the wait.
    pub fn handshake_flight_pending(&self) -> bool {
        // (A closed connection waits for nothing.)
        self.state != State::Closed
            && (self.retransmit.next_timeout().is_some() || self.final_flight_unconfirmed())
    }

    /// Connected, with the final flight still kept for a re-send.
    fn final_flight_unconfirmed(&self) -> bool {
        self.state == State::Connected && self.final_flight.is_some()
    }

    /// Ends the session: queues a `close_notify` alert under the current
    /// write keys (RFC 6347 §4.1 / RFC 5246 §7.2.1). No application data
    /// can be sent afterwards, but records from the peer — its own
    /// `close_notify` in particular — are still read. Idempotent; an error
    /// before the handshake completes.
    ///
    /// While [`Self::handshake_flight_pending`] the client may still be
    /// waiting for our final flight, and a `close_notify` reaching it
    /// there fails its handshake. The alert is therefore preceded by one
    /// more copy of that flight; callers that can afford to should wait
    /// (bounded) for `handshake_flight_pending` to turn `false` before
    /// closing.
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
        if self.final_flight_unconfirmed()
            && let Some(flight) = self.final_flight.take()
        {
            // Fresh sequence numbers (see `encode_flight_record`). The
            // flight is not kept: the session ends here.
            for rec in &flight.records {
                if let Ok(dg) = self.encode_flight_record(rec) {
                    self.out_dgrams.push(dg);
                }
            }
        }
        // RFC 5246 §7.2: `close_notify` is a warning-level (1) alert.
        let dg = self.encrypt_record_dtls(
            ContentType::Alert,
            &[1, AlertDescription::CloseNotify.as_u8()],
        )?;
        self.out_dgrams.push(dg);
        self.close_notify_sent = true;
        Ok(())
    }

    /// RFC 5705 §4 — DTLS 1.2 application-layer Exporter. Computes
    /// `PRF(master_secret, label, client_random ‖ server_random
    /// [‖ uint16(len(context)) ‖ context])`, matching TLS 1.2's exporter.
    /// `context = None` omits the length-prefixed context block;
    /// `context = Some(&[])` emits a zero-length context — the two outputs
    /// MUST differ per RFC 5705 §4. Returns `Err(InappropriateState)`
    /// before the handshake derives the master secret.
    pub fn tls_exporter(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), Error> {
        let master = self.master.as_ref().ok_or(Error::InappropriateState)?;
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let cr = self.client_random.ok_or(Error::InappropriateState)?;
        let sr = self.server_random.ok_or(Error::InappropriateState)?;
        tls12_exporter(suite.hash, master, label, &cr, &sr, context, out);
        Ok(())
    }

    /// Drains pending UDP datagrams to send.
    pub fn pop_outbound_datagrams(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.out_dgrams)
    }

    /// Drains decrypted application data.
    pub fn take_received(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app_in)
    }

    /// Encrypts application plaintext as a DTLS record. Must be called only
    /// after the handshake completes.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected || self.close_notify_sent {
            return Err(Error::InappropriateState);
        }
        let dg = self.encrypt_record_dtls(ContentType::ApplicationData, plaintext)?;
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
    /// the caller's clock stamps and validates HelloVerifyRequest cookies.
    /// If the caller NEVER drives the clock, the server falls back to wall
    /// time under `std` so the cookie max-age bound (RFC 6347 §4.2.1)
    /// stays real; on `no_std` builds with no caller clock, cookies are
    /// issued and validated at `TS = 0` and therefore never expire — drive
    /// this method if cookie expiry matters there. Avoid switching from
    /// the never-driven mode to the caller-driven mode while a cookie
    /// exchange is in flight: a cookie stamped from one clock will not
    /// validate against the other.
    pub fn set_now(&mut self, now: Duration) {
        self.clock_driven = true;
        if now > self.last_now {
            self.last_now = now;
        }
    }

    /// Clock used to stamp / validate HelloVerifyRequest cookies, in
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

    /// Drives the retransmit machine. Any retransmitted datagrams land in
    /// `pop_outbound_datagrams`.
    pub fn on_timeout(&mut self, now: Duration) {
        self.clock_driven = true;
        self.last_now = now;
        match self.retransmit.on_timeout(now) {
            super::reliability::Action::Retransmit => {
                // Re-frame (and re-encrypt) every record under a fresh
                // sequence number: the peer's replay window would reject a
                // verbatim copy of a record it already saw (DTLS-L3).
                let records = self.retransmit.flight_records().to_vec();
                for rec in &records {
                    if let Ok(dg) = self.encode_flight_record(rec) {
                        self.out_dgrams.push(dg);
                    }
                }
                // If nothing of the peer's flight arrived since the last
                // timer fire, drop the half-assembled inbound messages —
                // evicting any poisoned reassembly candidate seeded by a
                // spoofed epoch-0 fragment, which otherwise has no expiry.
                // Partials that grew since then are kept so a fragmented
                // message can assemble across retransmissions under loss.
                // Established connections keep their partials.
                if self.state != State::Connected {
                    self.pre_cookie.clear();
                    if let Some(r) = self.reassembler.as_mut() {
                        r.clear_if_stalled();
                    }
                }
            }
            super::reliability::Action::GiveUp => {
                if self.state == State::Connected {
                    // A fully established connection must never self-close
                    // on a retransmit cap; drop the stale flight and stay
                    // Connected. Only an in-progress handshake times out.
                    self.retransmit.on_peer_response();
                } else {
                    self.state = State::Closed;
                }
            }
            super::reliability::Action::Idle => {}
        }
    }

    /// Feeds one incoming UDP datagram into the connection.
    pub fn feed_datagram(&mut self, datagram: &[u8]) -> Result<(), Error> {
        if let Some(cid) = self.cid.as_mut() {
            cid.start_datagram();
        }
        // A `tls12_cid` record is framed with the CID length this side
        // receives (RFC 9146 §4: the length is not on the wire).
        let cid_len = self.cid.as_ref().map_or(0, CidState::local_len);
        let mut off = 0usize;
        while off < datagram.len() {
            // Truncated trailing record, or a header whose declared length
            // is bogus (RecordOverflow): record framing is lost for the
            // rest of the datagram. RFC 6347 §4.1.2.7 requires invalid
            // records to be silently discarded — a single spoofed datagram
            // must never be fatal.
            let rec = match record::read_record_cid(&datagram[off..], cid_len) {
                Ok(Some(rec)) => rec,
                Ok(None) | Err(_) => return Ok(()),
            };
            off += rec.len;
            self.process_record(rec)?;
        }
        Ok(())
    }

    /// Processes one DTLS record.
    ///
    /// Per RFC 6347 §4.1.2.7, records that fail record-layer sanity checks
    /// (bad version, wrong epoch, failed AEAD, unexpected content type) are
    /// SILENTLY discarded — they are trivially spoofable by an off-path
    /// attacker and must never be connection-fatal.
    fn process_record(&mut self, rec: ParsedDtlsRecord<'_>) -> Result<(), Error> {
        if rec.version != ProtocolVersion::DTLSv1_2 && rec.version != ProtocolVersion::DTLSv1_0 {
            // Unknown record version: silently discard.
            return Ok(());
        }
        if rec.epoch != self.read_epoch {
            return Ok(());
        }
        // Anti-replay pre-check: cheap rejection of duplicate / too-old
        // seq numbers. We deliberately DO NOT advance the window here —
        // an off-path attacker who can guess wire seq numbers could
        // otherwise burn slots in the window with packets that pass the
        // seq filter but fail AEAD verification, dropping legitimate
        // retransmits. The window is `mark`-ed only after the AEAD tag
        // verifies (below).
        if self.read_epoch >= 1 && !self.replay.check(rec.seq) {
            // A duplicate handshake record while our final flight is still
            // unconfirmed is exactly what a client that never received
            // that flight sends: a verbatim retransmit of its Finished.
            // Let it through to AEAD so `process_handshake_record` can
            // recognise it (RFC 6347 §4.2.4) — decrypting a duplicate is
            // harmless, and the window is not advanced. Everything else
            // is a replay: silent drop.
            let finished_retransmit = self.state == State::Connected
                && self.final_flight.is_some()
                && (rec.content_type == ContentType::Handshake
                    || rec.content_type == ContentType::Unknown(TLS12_CID_CONTENT_TYPE));
            if !finished_retransmit {
                return Ok(());
            }
        }

        // RFC 9146 §3: once this side receives a CID, only `tls12_cid`
        // records under one of its CIDs are valid at epoch ≥ 1 — a record
        // without a CID, one with a CID it did not issue, and a CID record
        // when none was negotiated (or at epoch 0, where nothing is
        // protected) are all invalid, i.e. silently discarded (RFC 6347
        // §4.1.2.7). The real content type is inside the envelope (§4).
        let expects_cid = self.cid.as_ref().is_some_and(|c| c.local_len() > 0);
        if let Some(cid) = rec.cid {
            if self.read_epoch < 1 || !expects_cid {
                return Ok(());
            }
            let Some(c) = self.read_crypter.as_ref() else {
                return Ok(());
            };
            if !self.cid.as_ref().is_some_and(|s| s.accepts(cid)) {
                return Ok(());
            }
            // The real content type is inside the envelope, so a record the
            // replay window already holds could only be let through above
            // as a possible Finished retransmission (RFC 6347 §4.2.4): once
            // decrypted, anything else that is a duplicate is a replay.
            let duplicate = !self.replay.check(rec.seq);
            let combined = ((self.read_epoch as u64) << 48) | rec.seq;
            let Ok((real_type, plain)) = c.decrypt_dtls_cid(combined, cid, rec.fragment) else {
                // AEAD failure: silent drop, window not advanced.
                return Ok(());
            };
            if duplicate && real_type != ContentType::Handshake {
                return Ok(());
            }
            // AEAD verified: commit to the window only now.
            self.replay.mark(rec.seq);
            self.note_authenticated(rec.seq, true);
            return self.on_authenticated_record(real_type, plain);
        }
        if self.read_epoch >= 1 && expects_cid {
            return Ok(());
        }
        match rec.content_type {
            ContentType::ChangeCipherSpec => {
                // CCS is plaintext (epoch 0, spoofable); every rejection
                // here is a silent drop (RFC 6347 §4.1.2.7).
                if rec.fragment != [0x01] {
                    return Ok(());
                }
                if self.ccs_received {
                    return Ok(());
                }
                let Some(c) = self.pending_read_crypter.take() else {
                    // CCS before the read keys exist (spoofed, or badly
                    // reordered): ignore — a real client retransmits.
                    return Ok(());
                };
                self.read_crypter = Some(c);
                self.ccs_received = true;
                self.read_epoch = 1;
                self.replay = AntiReplayWindow::new();
                Ok(())
            }
            ContentType::Handshake => {
                let plain: Vec<u8>;
                let authenticated;
                if self.read_epoch >= 1 {
                    let combined = ((self.read_epoch as u64) << 48) | rec.seq;
                    let Some(c) = self.read_crypter.as_ref() else {
                        return Ok(());
                    };
                    let Ok(p) = c.decrypt_dtls(combined, ContentType::Handshake, rec.fragment)
                    else {
                        // AEAD failure: silent drop (RFC 6347 §4.1.2.7) —
                        // a spoofed datagram must not kill the connection.
                        // The replay window was deliberately not advanced.
                        return Ok(());
                    };
                    // AEAD verified: now it's safe to commit to the window.
                    self.replay.mark(rec.seq);
                    self.note_authenticated(rec.seq, false);
                    plain = p;
                    authenticated = true;
                } else {
                    plain = rec.fragment.to_vec();
                    authenticated = false;
                }
                if authenticated {
                    self.on_authenticated_record(ContentType::Handshake, plain)
                } else {
                    self.process_handshake_record(&plain, false)
                }
            }
            ContentType::ApplicationData => {
                if self.read_epoch < 1 {
                    // Plaintext application data is spoofable: silent drop.
                    return Ok(());
                }
                let combined = ((self.read_epoch as u64) << 48) | rec.seq;
                let Some(c) = self.read_crypter.as_ref() else {
                    return Ok(());
                };
                let Ok(plain) =
                    c.decrypt_dtls(combined, ContentType::ApplicationData, rec.fragment)
                else {
                    // AEAD failure: silent drop, window not advanced.
                    return Ok(());
                };
                // AEAD verified: commit to the window only now.
                self.replay.mark(rec.seq);
                self.note_authenticated(rec.seq, false);
                self.on_authenticated_record(ContentType::ApplicationData, plain)
            }
            ContentType::Alert => {
                if self.read_epoch < 1 {
                    // Epoch-0 alerts travel in plaintext and are therefore
                    // trivially spoofable by any off-path attacker who can
                    // guess the 4-tuple: honouring one would hand out a
                    // one-datagram handshake teardown. Silent drop
                    // (RFC 6347 §4.1.2.7), matching the DTLS 1.3 engine.
                    return Ok(());
                }
                let combined = ((self.read_epoch as u64) << 48) | rec.seq;
                let Some(c) = self.read_crypter.as_ref() else {
                    return Ok(());
                };
                let Ok(plain) = c.decrypt_dtls(combined, ContentType::Alert, rec.fragment) else {
                    // AEAD failure: silent drop, window not advanced.
                    return Ok(());
                };
                // AEAD verified: commit to the window only now.
                self.replay.mark(rec.seq);
                self.note_authenticated(rec.seq, false);
                self.on_authenticated_record(ContentType::Alert, plain)
            }
            // Unknown / unexpected content type: silent discard.
            _ => Ok(()),
        }
    }

    /// RFC 9146 §6 bookkeeping for an authenticated record at the current
    /// read epoch (see [`Self::datagram_allows_peer_address_update`]).
    fn note_authenticated(&mut self, seq: u64, with_cid: bool) {
        if let Some(cid) = self.cid.as_mut() {
            cid.note_authenticated(self.read_epoch, seq, with_cid);
        }
    }

    /// Dispatches the content of an AEAD-authenticated record by its real
    /// content type — the header's for an RFC 6347 record, the one from
    /// inside the envelope for a `tls12_cid` record (RFC 9146 §4). Past
    /// this point protocol violations come from the genuine peer and are
    /// fatal.
    fn on_authenticated_record(&mut self, ct: ContentType, plain: Vec<u8>) -> Result<(), Error> {
        match ct {
            ContentType::Handshake => self.process_handshake_record(&plain, true),
            ContentType::ApplicationData => match self.state {
                State::Connected => {
                    // The client only sends application data once it
                    // has verified our Finished: the final flight is
                    // implicitly acknowledged.
                    self.final_flight = None;
                    self.app_in.extend_from_slice(&plain);
                    Ok(())
                }
                // The peer's close_notify ended the connection; data
                // after it is a genuine (authenticated) peer fault —
                // surface it instead of quietly delivering it, as the
                // DTLS 1.3 engine does (DTLS-I4).
                State::Closed => Err(Error::UnexpectedMessage),
                // Read keys exist (client CCS seen) but its Finished
                // has not been processed yet: a client only sends
                // application data once Connected, so this is a
                // record reordered ahead of its Finished — benign
                // under UDP, so drop it rather than abort.
                _ => Ok(()),
            },
            ContentType::Alert => {
                // Authenticated, so a malformed alert is a genuine peer
                // fault (RFC 5246 §7.2: an alert is exactly two bytes).
                if plain.len() != 2 {
                    return Err(Error::Decode);
                }
                let desc = AlertDescription::from_u8(plain[1]);
                self.state = State::Closed;
                // Whatever the alert, the client is past waiting for our
                // final flight.
                self.final_flight = None;
                if desc == AlertDescription::CloseNotify {
                    self.close_notify_received = true;
                    Ok(())
                } else {
                    Err(Error::AlertReceived(desc))
                }
            }
            // A `DTLSInnerPlaintext` naming any other type (a CCS is
            // never encrypted) is a protocol violation.
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Processes the handshake fragments in one record body.
    ///
    /// `authenticated` is true when the bytes came out of a successfully
    /// AEAD-verified record (epoch ≥ 1). Framing errors in unauthenticated
    /// (plaintext, epoch-0) records are attacker-spoofable and dropped
    /// silently; the same errors in authenticated records are genuine peer
    /// faults and stay fatal.
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
            // Pre-state-allocation cookie path: when we're still
            // awaiting the first or second CH and the reassembler hasn't
            // been built, the fragment can only be (part of) a ClientHello.
            // This path is plaintext, unauthenticated input — malformed
            // fragments are dropped silently rather than killing the
            // connection.
            if self.reassembler.is_none() {
                // Only a ClientHello at `message_seq` 0 (the first CH) or
                // 1 (the cookie-bearing second CH, RFC 6347 §4.2.2),
                // within the pre-cookie length ceiling, can be legitimate
                // here; anything else is dropped with the rest of the
                // record (RFC 6347 §4.1.2.7), and a spoofed `message_seq`
                // never influences which sequence numbers the buffer will
                // accept.
                if !PreCookieBuffer::admits(&frag) {
                    return Ok(());
                }
                let msg_seq = frag.message_seq;
                off += consumed;
                // A whole-message fragment is handed straight through; a
                // partial one — a client on a small path MTU splits its CH
                // across datagrams (RFC 6347 §4.2.3) — is buffered, bounded
                // on every axis (see `PreCookieBuffer`), until the CH at
                // this `message_seq` completes. Either way the cookie check
                // and the transcript (the reassembled body under its
                // single-fragment DTLS header, §4.2.6) see the same bytes.
                // The buffer never dispatches on its own, so a rejected
                // spoofed CH cannot leave it refusing the genuine seq-0
                // fragments.
                let Some(body) = self.pre_cookie.feed(frag) else {
                    continue;
                };
                match self.handle_pre_state_client_hello(msg_seq, &body) {
                    Ok(()) => {
                        // The CH was accepted (HVR emitted, or the real
                        // handshake state bootstrapped): whatever the
                        // fragment buffer still holds is stale.
                        self.pre_cookie.clear();
                    }
                    Err(e) => {
                        // Everything on this path is unauthenticated,
                        // epoch-0, attacker-spoofable input (a forged
                        // cookie being the most reachable). Per RFC 6347
                        // §4.1.2.7 these faults are silently dropped so a
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
            if self.state == State::Connected && authenticated {
                // RFC 6347 §4.2.4: an authenticated re-send of the
                // client's Finished means our CCS + Finished never
                // arrived — re-send them (DTLS-L3). Anything else from an
                // established peer falls through to the ordinary path
                // (stale sequence numbers are dropped by the reassembler;
                // a genuinely new handshake message is fatal).
                if self.on_retransmitted_client_finished(&frag) {
                    return Ok(());
                }
            }
            // Owned reborrow.
            let frag = HandshakeFragment {
                msg_type: frag.msg_type,
                total_length: frag.total_length,
                message_seq: frag.message_seq,
                fragment_offset: frag.fragment_offset,
                fragment: frag.fragment,
                len: frag.len,
            };
            off += consumed;
            // The client's first post-cookie flight (ClientKeyExchange, and
            // optionally Certificate/CertificateVerify) arrives at epoch 0,
            // unauthenticated. A spoofed plaintext CKE that decodes to a bad
            // EC point would otherwise return Decode/IllegalParameter/
            // PeerMisbehaved fatally and abort a legitimate in-flight
            // handshake. On the unauthenticated path turn any reassembly/
            // dispatch fault into a silent drop, keeping only our own
            // `InappropriateState` misconfig fatal — mirroring the DTLS 1.3
            // server pre-cookie wrapper. The encrypted client Finished
            // (epoch ≥ 1, authenticated) keeps every error fatal.
            // `feed`/`pop_ready` advance `expected_msg_seq` BEFORE dispatch, so
            // on a silent drop we also rewind the reassembler: otherwise a
            // spoofed but well-framed message would pin `expected_msg_seq`
            // past the genuine one (same message_seq), which would then be
            // rejected as stale.
            let snapshot = self
                .reassembler
                .as_ref()
                .expect("reassembler built")
                .expected_msg_seq();
            let feeding = self
                .reassembler
                .as_mut()
                .expect("reassembler built")
                .feed(frag);
            if let Some((msg_type, body)) = feeding {
                match self.dispatch_one(msg_type, snapshot, &body) {
                    Ok(()) => {}
                    Err(e) if authenticated || matches!(e, Error::InappropriateState) => {
                        return Err(e);
                    }
                    Err(_) => {
                        self.reassembler
                            .as_mut()
                            .expect("reassembler built")
                            .rewind_expected_msg_seq(snapshot);
                        return Ok(());
                    }
                }
            }
            // Drain any further already-buffered messages.
            loop {
                let snapshot = self
                    .reassembler
                    .as_ref()
                    .expect("reassembler built")
                    .expected_msg_seq();
                let popped = self
                    .reassembler
                    .as_mut()
                    .expect("reassembler built")
                    .pop_ready();
                match popped {
                    Some((msg_type, body)) => match self.dispatch_one(msg_type, snapshot, &body) {
                        Ok(()) => {}
                        Err(e) if authenticated || matches!(e, Error::InappropriateState) => {
                            return Err(e);
                        }
                        Err(_) => {
                            self.reassembler
                                .as_mut()
                                .expect("reassembler built")
                                .rewind_expected_msg_seq(snapshot);
                            return Ok(());
                        }
                    },
                    None => break,
                }
            }
        }
        Ok(())
    }

    /// Recognises a retransmitted client Finished (an unfragmented
    /// `Finished` whose `verify_data` equals the one we accepted) and
    /// re-sends our final flight in answer. Returns `true` when the
    /// fragment was consumed this way.
    fn on_retransmitted_client_finished(&mut self, frag: &HandshakeFragment<'_>) -> bool {
        if frag.msg_type != hs_type::FINISHED
            || frag.fragment_offset != 0
            || frag.total_length != 12
            || frag.fragment.len() != 12
        {
            return false;
        }
        let Some(expected) = self.client_finished.as_ref() else {
            return false;
        };
        if !bool::from(expected.as_slice().ct_eq(frag.fragment)) {
            return false;
        }
        if self.final_flight_resends >= MAX_FINAL_FLIGHT_RESENDS {
            // Budget spent: stop keeping the flight around at all.
            self.final_flight = None;
            return true;
        }
        if let Some(flight) = self.final_flight.take() {
            // Fresh sequence numbers again (see `encode_flight_record`).
            for rec in &flight.records {
                if let Ok(dg) = self.encode_flight_record(rec) {
                    self.out_dgrams.push(dg);
                }
            }
            self.final_flight = Some(flight);
            self.final_flight_resends += 1;
        }
        true
    }

    /// Dispatches one reassembled handshake message. `message_seq` is the
    /// sequence number it arrived under, which the transcript covers (RFC
    /// 6347 §4.2.6): `raw` is the message as hashed, DTLS header included.
    fn dispatch_one(&mut self, msg_type: u8, message_seq: u16, body: &[u8]) -> Result<(), Error> {
        let raw = transcript_message(msg_type, message_seq, body);
        self.dispatch_handshake(msg_type, body, &raw)
    }

    fn dispatch_handshake(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        match self.state {
            State::WaitClientFlight => self.on_client_flight(msg_type, body, raw),
            State::Connected | State::Closed => Err(Error::UnexpectedMessage),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Parses one ClientHello body (DTLS wire format) and either issues
    /// HelloVerifyRequest or transitions to the server-flight path.
    fn handle_pre_state_client_hello(&mut self, msg_seq: u16, body: &[u8]) -> Result<(), Error> {
        // F3: bound the client-supplied `message_seq` before the reassembler
        // seeding loop below (`for s in 0..=msg_seq`). `message_seq` is not
        // covered by the cookie fingerprint, so even a client that completes
        // the HelloVerifyRequest roundtrip can drive this loop; an oversized
        // value would otherwise mean tens of thousands of synthetic-message
        // allocate/serialize/parse/feed cycles.
        if msg_seq > MAX_HS_MSG_SEQ {
            return Err(Error::IllegalParameter);
        }
        // Decode the DTLS-flavoured ClientHello body.
        let parsed = parse_dtls_client_hello(body)?;
        // RFC 5246 §7.4.1.2: `SessionID<0..32>`. This server keeps no
        // session cache and never echoes the id (its ServerHello always
        // carries an empty one), so nothing downstream depends on it —
        // but an oversized id is a protocol violation and is refused
        // before anything else is decided from the hello, as the TLS 1.2
        // server does.
        if parsed.session_id.len() > 32 {
            return Err(Error::IllegalParameter);
        }

        // Fail closed: a server that asks for cookie enforcement but never
        // supplied a `cookie_secret` MUST NOT silently degrade to the
        // no-cookie path (which would emit the full, expensive server flight
        // to an unverified, possibly-spoofed source — an amplification +
        // asymmetric-signature DoS). Reject before any flight is generated.
        if self.config.require_cookie_exchange && self.config.cookie_secret.is_none() {
            return Err(Error::InappropriateState);
        }
        let cookie_required = self.config.require_cookie_exchange;
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
        let first_attempt = parsed.cookie.is_empty();

        // Bind the cookie MAC to the security-critical CH fields. An on-path
        // attacker that mutates CH2's cipher_suites / supported_groups /
        // supported_versions between HVR and the second flight will fail
        // cookie validation — closing the downgrade primitive described in
        // RFC 9147 §5.1 (and equivalent for DTLS 1.2's HVR cookie).
        let fp = ch_fingerprint_dtls12(&parsed);

        if cookie_required && first_attempt {
            // Emit HelloVerifyRequest with a freshly computed cookie. The
            // cookie binds (peer_addr, client_random, ch_fingerprint, TS) —
            // *no* per-connection state is allocated here; we rely on the
            // client echoing the cookie in CH2 to commit to the same CH
            // content.
            let secret = self
                .config
                .cookie_secret
                .as_ref()
                .ok_or(Error::InappropriateState)?;
            let cg = CookieGenerator::new(*secret);
            let now_min = self.cookie_now_minutes();
            let cookie = cg.generate(&self.peer_addr, &parsed.random, &fp, now_min);
            self.emit_hello_verify_request(&cookie)?;
            self.state = State::WaitSecondClientHello;
            // We deliberately do NOT add this CH or HVR to a transcript
            // and we keep `reassembler` None so the next CH also enters
            // this pre-state path (RFC 6347 §4.2.1). The msg_seq of this
            // pre-cookie CH is intentionally NOT stored — see DTLS-4.
            let _ = msg_seq;
            return Ok(());
        }

        if cookie_required && !first_attempt {
            // Validate the cookie. The CH fingerprint must match the one
            // that was bound when the cookie was issued, otherwise the
            // server treats this as if the cookie were forged.
            let secret = self
                .config
                .cookie_secret
                .as_ref()
                .ok_or(Error::InappropriateState)?;
            let cg = CookieGenerator::new(*secret);
            let now_min = self.cookie_now_minutes();
            // Current secret first; on a miss, the previous generation
            // (DTLS-I6: a rotation must not invalidate in-flight cookies).
            let valid = cg.validate(
                &self.peer_addr,
                &parsed.random,
                &fp,
                now_min,
                &parsed.cookie,
            ) || self
                .config
                .previous_cookie_secret
                .as_ref()
                .is_some_and(|prev| {
                    CookieGenerator::new(*prev).validate(
                        &self.peer_addr,
                        &parsed.random,
                        &fp,
                        now_min,
                        &parsed.cookie,
                    )
                });
            if !valid {
                return Err(Error::IllegalParameter);
            }
        }

        // ---- Validation phase ------------------------------------------
        //
        // Cookie validated (or skipped). Everything that can still reject
        // this CH is decided into locals FIRST; `self` is only mutated in
        // the commit phase below. Rejections on this path are silently
        // dropped as unauthenticated input (see the caller), so a partial
        // state change would be permanent: a replayed CH2 variant with a
        // 1-byte `extended_master_secret` body used to append itself to the
        // transcript before the EMS check rejected it, after which the
        // genuine CH2 appended a second ClientHello and the client's
        // Finished could never verify (DTLS-L2).

        // Suite selection — mirror the TLS 1.2 server (`src/tls/conn/server12.rs`):
        // walk SUITES_12 in OUR preference order, picking the first entry the
        // client offered whose signature half matches the configured key's
        // family (EdDSA counts as ECDSA, RFC 8422 §2.2). An ML-DSA server
        // key can be plumbed in but has no DTLS 1.2 scheme
        // (`signature_scheme` below).
        let sig_kind = sig_kind_for_key(&self.config.key);
        let suite = SUITES_12
            .iter()
            .copied()
            .find(|p| parsed.cipher_suites.contains(&p.suite) && p.sig_kind == sig_kind)
            .ok_or(Error::HandshakeFailure)?;
        // RFC 5246 §7.4.1.4.1: a (D)TLS 1.2 ClientHello MUST carry
        // `signature_algorithms`, and §7.4.3 has the ServerKeyExchange
        // signed under a pair "present in the signature_algorithms
        // extension" — the scheme this key signs under has to be one the
        // client offered, or the client has no verifier for it. Without
        // the extension the default would be SHA-1 pairs, which this server
        // does not sign; mirrors `src/tls/conn/server12.rs`.
        let sig_algs = ext::find(&parsed.extensions, ExtensionType::SIGNATURE_ALGORITHMS)
            .ok_or(Error::HandshakeFailure)?;
        let offered = ext::parse_signature_algorithms(sig_algs)?;
        let ske_scheme = signature_scheme(&self.config.key, &offered)?;
        // Pick the negotiated ECDHE group: the first of this server's
        // groups (its preference order, default X25519 > P-256 > P-384,
        // mirroring `src/tls/conn/server12.rs::on_client_hello_initial`)
        // that the client offered.
        let groups_body = ext::find(&parsed.extensions, ExtensionType::SUPPORTED_GROUPS)
            .ok_or(Error::HandshakeFailure)?;
        let groups = parse_supported_groups(groups_body)?;
        let group = self
            .config
            .groups
            .iter()
            .copied()
            .find(|g| groups.contains(g))
            .ok_or(Error::HandshakeFailure)?;

        // RFC 7627 §5.1: detect the client's EMS offer (DTLS 1.2 inherits
        // the rules from TLS 1.2). Body MUST be empty.
        let ems_negotiated =
            match ext::find(&parsed.extensions, ExtensionType::EXTENDED_MASTER_SECRET) {
                Some(ems_body) => {
                    ext::parse_extended_master_secret(ems_body)?;
                    true
                }
                None => false,
            };
        // RFC 7627 §5.3: a client that does not offer EMS would get a master
        // secret unbound from the transcript (the triple-handshake family).
        // Refuse it unless the operator opted into legacy interop, as the
        // TLS 1.2 server does. Still the validation phase: nothing has been
        // committed, so the rejection leaves no trace.
        if self.config.require_ems && !ems_negotiated {
            return Err(Error::HandshakeFailure);
        }
        // ALPN (RFC 7301), decided into a local like everything else here.
        let alpn_pick = super::select_alpn(&self.config.alpn_protocols, &parsed.extensions)?;
        // Connection IDs (RFC 9146 §3): negotiated only when the client
        // offered the extension and this server has a CID to receive under.
        let cid_pick = negotiate_server(
            self.config.connection_id.as_deref(),
            ext::find(&parsed.extensions, ExtensionType::CONNECTION_ID),
        )?;

        // RFC 5746 §3.6: echo an empty `renegotiation_info` when the client
        // signalled secure renegotiation — either via the extension (whose
        // body MUST be empty on an initial handshake) or the
        // `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` pseudo-suite (0x00FF). Strict
        // clients (OpenSSL) abort with `handshake_failure` otherwise.
        let signalled_reneg = match ext::find(&parsed.extensions, ExtensionType::RENEGOTIATION_INFO)
        {
            Some(reneg) => {
                // Reject a non-empty `renegotiated_connection` on an initial
                // handshake (we never renegotiate).
                if !ext::parse_renegotiation_info(reneg)?.is_empty() {
                    return Err(Error::HandshakeFailure);
                }
                true
            }
            None => parsed.cipher_suites.contains(&CipherSuite(0x00ff)),
        };

        // ---- Commit phase ----------------------------------------------
        // Nothing below can reject the CH any more.
        //
        // The transcript starts with this CH per RFC 6347 §4.2.1 — from a
        // clean slate, so nothing a previously rejected (or replayed) CH
        // could have left behind survives — hashed with its 12-byte DTLS
        // handshake header, `message_seq` included (§4.2.6). `Transcript`
        // accumulates raw bytes and applies the hash on demand once
        // `set_alg` is called, so the order of update / set_alg is
        // irrelevant as long as set_alg happens before `current_hash`.
        self.client_random = Some(parsed.random);
        self.transcript = Transcript::new();
        self.transcript
            .update(&transcript_message(hs_type::CLIENT_HELLO, msg_seq, body));
        // Pin the transcript hash now that the suite is known.
        self.transcript.set_alg(suite.hash);
        self.suite = Some(suite);
        self.negotiated_group = Some(group);
        self.group = Some(group);
        self.ems_negotiated = ems_negotiated;
        self.alpn_negotiated = alpn_pick;
        // DTLS 1.2 issues no further CIDs, so there is no pool to draw.
        self.cid = cid_pick.map(|(local, peer)| CidState::negotiated(local, peer, Vec::new()));
        // Initialise the reassembler at expected_msg_seq = msg_seq + 1
        // (the client's next handshake msg after CH).
        let mut reasm = Reassembler::new();
        for s in 0..=msg_seq {
            // Drive its counter up to msg_seq+1 by feeding synthetic
            // zero-length messages of type CLIENT_HELLO. Each call
            // expects the next seq.
            let mut buf = Vec::new();
            write_message(&mut buf, hs_type::CLIENT_HELLO, s, b"", 0);
            let f = read_fragment(&buf)?;
            let _ = reasm.feed(f);
        }
        self.reassembler = Some(reasm);

        // Generate the server's random + server flight.
        let mut sr: Random = [0u8; 32];
        self.rng.fill_bytes(&mut sr);
        self.server_random = Some(sr);

        // Generate the ECDHE key share for the negotiated group.
        let our_point: Vec<u8> = match group {
            NamedGroup::X25519 => {
                let sk = X25519PrivateKey::generate(&mut self.rng);
                let pk = sk.public_key().to_vec();
                self.x25519 = Some(sk);
                pk
            }
            NamedGroup::SECP256R1 => {
                let sk = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut self.rng);
                let pk = sk.public_key().to_sec1();
                self.p256 = Some(sk);
                pk
            }
            NamedGroup::SECP384R1 => {
                let sk = BoxedEcdhPrivateKey::generate(CurveId::P384, &mut self.rng);
                let pk = sk.public_key().to_sec1();
                self.p384 = Some(sk);
                pk
            }
            NamedGroup::SECP521R1 => {
                let sk = BoxedEcdhPrivateKey::generate(CurveId::P521, &mut self.rng);
                let pk = sk.public_key().to_sec1();
                self.p521 = Some(sk);
                pk
            }
            _ => return Err(Error::HandshakeFailure),
        };

        // After HVR, the server's message_seq continues from 1 (HVR was 0);
        // without HVR, message_seq starts at 0. Cookie-disabled path: HVR
        // was never sent, so message_seq starts at 0.
        if cookie_required {
            // HVR was message_seq=0, so the next outbound message is 1
            // (RFC 6347 §4.2.2). Set it here rather than relying on
            // `emit_hello_verify_request`: the cookie is stateless by
            // design, so the CH2 may land on a fresh server object that
            // never sent the HVR (a restart, a rotated cookie secret, a
            // stateless dispatcher) — one that still counted from 0 would
            // send a ServerHello the client's reassembler treats as a
            // stale duplicate of the HVR and the handshake would stall
            // (DTLS-I6).
            self.out_msg_seq = 1;
        } else {
            self.out_msg_seq = 0;
        }

        // Build the server flight.
        let mut flight = Flight::new();

        // ServerHello. Always include ec_point_formats; echo EMS when
        // negotiated (RFC 7627 §5.1).
        let mut sh_exts: Vec<(ExtensionType, Vec<u8>)> = alloc::vec![ext::ec_point_formats()];
        if self.ems_negotiated {
            sh_exts.push(ext::extended_master_secret_empty());
        }
        // RFC 7301 §3.1: echo the single selected protocol.
        if let Some(proto) = &self.alpn_negotiated {
            sh_exts.push(ext::alpn_protocols(&[proto.as_slice()]));
        }
        // RFC 5746 §3.6: echo an empty `renegotiation_info` when the client
        // signalled secure renegotiation (decided in the validation phase).
        if signalled_reneg {
            sh_exts.push(ext::renegotiation_info_empty());
        }
        // RFC 9146 §3: answer the client's `connection_id` offer with the
        // CID this server receives under.
        if let Some(cid) = self.cid.as_ref() {
            sh_exts.push(connection_id_extension(cid.local()));
        }
        let sh = ServerHello {
            random: sr,
            session_id: Vec::new(),
            cipher_suite: suite.suite,
            extensions: sh_exts,
        }
        .encode_dtls();
        // `encode_dtls` yields the TLS-shaped message (4-byte header);
        // `push_handshake` hashes the body under its DTLS header and
        // fragments it.
        self.push_handshake(&mut flight, hs_type::SERVER_HELLO, &sh[4..]);

        // Certificate.
        let cert_msg = build_certificate_msg(&self.config.cert_chain);
        self.push_handshake(&mut flight, hs_type::CERTIFICATE, &cert_msg[4..]);

        // ServerKeyExchange. The SKE signature hash tracks the key's curve
        // for ECDSA (RFC 5246 §7.4.1.4.1 lets the server pick any acceptable
        // scheme independent of the PRF / suite hash); RSA-PSS uses
        // `rsa_pss_rsae_sha256` regardless of the suite hash. Mirrors
        // `src/tls/conn/server12.rs::send_server_key_exchange`.
        let cr = self.client_random.expect("set above");
        let to_sign = signed_message(&cr, &sr, group, &our_point);
        let scheme = ske_scheme;
        let signature: Vec<u8> = match &self.config.key {
            // RSA-PSS or, for a client offering no PSS scheme, PKCS#1 v1.5.
            ServerKey::Rsa(k) => {
                crate::tls::crypto::sign::sign_rsa_tls12(k, scheme, &to_sign, &mut self.rng)?
            }
            ServerKey::RsaPss(k, _) => {
                crate::tls::crypto::sign::sign_rsa_pss(k, scheme, &to_sign, &mut self.rng)?
            }
            ServerKey::Ecdsa(k) => {
                let sig = match k.curve() {
                    CurveId::P384 => k.sign::<Sha384>(&to_sign),
                    CurveId::P521 => k.sign::<Sha512>(&to_sign),
                    _ => k.sign::<Sha256>(&to_sign),
                }
                .map_err(|_| Error::HandshakeFailure)?;
                sig.to_der(k.curve())
            }
            // RFC 8422 §5.4 / §5.10: PureEdDSA over the same bytes ECDSA
            // would hash, "with no hashing"; Ed448 under the empty context.
            // The signature is the raw octet string (64 / 114 bytes).
            ServerKey::Ed25519(k) => k.sign(&to_sign).to_bytes().to_vec(),
            ServerKey::Ed448(k) => k.sign(&to_sign).to_bytes().to_vec(),
            // External key: hold the half-built flight + ECDHE params and
            // suspend; the caller signs `to_sign` and resumes via
            // `provide_signature`, which assembles the SKE + ServerHelloDone.
            ServerKey::External { .. } => {
                self.pending_ske = Some(PendingSke {
                    scheme,
                    content: to_sign,
                    flight,
                    group,
                    our_point,
                });
                self.state = State::AwaitingSkeSignature;
                return Ok(());
            }
            // ML-DSA: `signature_scheme` found no scheme above, so this is
            // not reached.
            #[cfg(feature = "mldsa")]
            ServerKey::MlDsa44(_) | ServerKey::MlDsa65(_) | ServerKey::MlDsa87(_) => {
                return Err(Error::UnsupportedKeyType);
            }
        };
        self.finish_ske_flight(flight, scheme, group, our_point, signature)
    }

    /// Appends the signed `ServerKeyExchange` + `ServerHelloDone` to the
    /// half-built `flight`, then sends it. Shared by the inline and external
    /// signing paths.
    fn finish_ske_flight(
        &mut self,
        mut flight: Flight,
        scheme: SignatureScheme,
        group: NamedGroup,
        our_point: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), Error> {
        let ske = ServerKeyExchange {
            group,
            point: our_point,
            scheme,
            signature,
        }
        .encode();
        self.push_handshake(&mut flight, hs_type::SERVER_KEY_EXCHANGE, &ske[4..]);

        // CertificateRequest (RFC 5246 §7.4.4) between ServerKeyExchange
        // and ServerHelloDone (§7.3), listing the certificate types
        // (rsa_sign, ecdsa_sign), the `supported_signature_algorithms` the
        // policy permits (checked against the client's CertificateVerify
        // in `on_client_cert_verify`) and no CA names: any chain that
        // validates against the policy's roots is accepted.
        if self.config.client_auth.is_some() {
            let cr = CertificateRequest12 {
                cert_types: alloc::vec![1u8, 64u8],
                sig_schemes: crate::tls::crypto::sign::tls12_certificate_request_schemes(
                    &self.config.signature_policy,
                ),
                cas: Vec::new(),
            }
            .encode();
            self.push_handshake(&mut flight, hs_type::CERTIFICATE_REQUEST, &cr[4..]);
        }

        // ServerHelloDone (empty body).
        self.push_handshake(&mut flight, hs_type::SERVER_HELLO_DONE, &[]);

        self.send_flight(flight)?;
        self.state = State::WaitClientFlight;
        Ok(())
    }

    /// Resumes a flight suspended for an external `ServerKeyExchange` signature:
    /// assembles the SKE with the caller-supplied `signature`, then sends the
    /// flight.
    pub(crate) fn provide_signature(&mut self, signature: Vec<u8>) -> Result<(), Error> {
        let p = self.pending_ske.take().ok_or(Error::InappropriateState)?;
        self.finish_ske_flight(p.flight, p.scheme, p.group, p.our_point, signature)
    }

    /// If suspended awaiting an external signature, returns the IANA scheme code
    /// point and the bytes to sign.
    pub(crate) fn pending_signature(&self) -> Option<(u16, Vec<u8>)> {
        self.pending_ske
            .as_ref()
            .map(|p| (p.scheme.0, p.content.clone()))
    }

    fn emit_hello_verify_request(&mut self, cookie: &[u8]) -> Result<(), Error> {
        // Body: ProtocolVersion(2) || opaque cookie<0..32>.
        let mut body = Vec::new();
        body.extend_from_slice(&0xfefd_u16.to_be_bytes());
        with_len_u8(&mut body, |b| b.extend_from_slice(cookie));

        // Wrap as a DTLS handshake fragment with msg_seq=0. NOTE: per
        // RFC 6347 §4.2.2, "[the server's] message_seq for HVR is 0", and
        // the server's *next* outbound handshake message (ServerHello)
        // also continues from message_seq=1.
        let mut frag_buf = Vec::new();
        write_message(&mut frag_buf, HS_HELLO_VERIFY_REQUEST, 0, &body, 0);
        let dgram = self.wrap_plain_record(ContentType::Handshake, &frag_buf)?;
        self.out_dgrams.push(dgram);
        // The server's out_msg_seq advances regardless of whether the
        // cookie path was taken — the next outbound message is 1.
        self.out_msg_seq = 1;
        Ok(())
    }

    /// Allocates the next outbound `message_seq`, adds the message to the
    /// transcript under its DTLS header (RFC 6347 §4.2.6), fragments
    /// `msg_type` / `body` to [`DEFAULT_MAX_FRAGMENT`], and appends every
    /// fragment to `flight` as its own epoch-0 record — a Certificate
    /// larger than the path MTU must be split across datagrams, not merely
    /// fragmented inside one record (RFC 6347 §4.1.1 / §4.2.3).
    fn push_handshake(&mut self, flight: &mut Flight, msg_type: u8, body: &[u8]) {
        let msg_seq = self.out_msg_seq;
        self.out_msg_seq += 1;
        self.transcript
            .update(&transcript_message(msg_type, msg_seq, body));
        for frag in write_fragments(msg_type, msg_seq, body, DEFAULT_MAX_FRAGMENT) {
            flight.push_record(ContentType::Handshake, 0, frag);
        }
    }

    /// Frames a plaintext (epoch 0) record with the next epoch-0 sequence
    /// number.
    fn wrap_plain_record(&mut self, ct: ContentType, fragment: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        record::write_record(
            &mut out,
            ct,
            ProtocolVersion::DTLSv1_2,
            0,
            self.plain_write_seq,
            fragment,
        )?;
        self.plain_write_seq += 1;
        Ok(out)
    }

    /// Frames one stored flight record for the wire under a FRESH sequence
    /// number: plaintext for epoch 0, encrypted under the current write
    /// crypter otherwise. Used both for the initial send and for every
    /// retransmission, so a re-sent record is never a byte-for-byte copy
    /// the peer's replay window would discard (DTLS-L3).
    fn encode_flight_record(&mut self, rec: &FlightRecord) -> Result<Vec<u8>, Error> {
        if rec.epoch == 0 {
            self.wrap_plain_record(rec.content_type, &rec.plaintext)
        } else if rec.epoch == self.write_epoch {
            self.encrypt_record_dtls(rec.content_type, &rec.plaintext)
        } else {
            // The keys for that epoch are gone; nothing sensible to send.
            Err(Error::InappropriateState)
        }
    }

    fn encrypt_record_dtls(&mut self, ct: ContentType, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let crypter = self
            .write_crypter
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        // Refuse to reuse an AEAD nonce: the nonce is `epoch‖seq`, so cap the
        // per-epoch record count well below the 48-bit field (see
        // `record::MAX_RECORDS_PER_EPOCH`). Connection-fatal — no rekey path.
        record::check_seq_cap(self.write_seq_in_epoch)?;
        let combined = ((self.write_epoch as u64) << 48) | self.write_seq_in_epoch;
        // RFC 9146 §3: with a non-empty CID negotiated for this direction,
        // every protected record is a `tls12_cid` record under the CID
        // MAC input (§5.3); otherwise the RFC 6347 form is used.
        let cid = self
            .cid
            .as_ref()
            .map(CidState::peer)
            .filter(|c| !c.is_empty());
        let fragment = match cid {
            Some(cid) => crypter.encrypt_dtls_cid(combined, cid, ct, payload)?,
            None => crypter.encrypt_dtls(combined, ct, payload)?,
        };
        let mut out = Vec::new();
        record::write_record_cid(
            &mut out,
            ct,
            ProtocolVersion::DTLSv1_2,
            self.write_epoch,
            self.write_seq_in_epoch,
            cid,
            &fragment,
        )?;
        self.write_seq_in_epoch += 1;
        Ok(out)
    }

    /// Test-only: hands a reassembled handshake message straight to the
    /// state machine, as if it had arrived at the next expected
    /// `message_seq`, so tests can present the client messages a conforming
    /// client never sends (a Finished in place of a CertificateVerify, a
    /// CertificateVerify under a scheme that was not offered, a Certificate
    /// after the ClientKeyExchange).
    #[cfg(test)]
    pub(crate) fn dispatch_handshake_for_test(
        &mut self,
        msg_type: u8,
        body: &[u8],
    ) -> Result<(), Error> {
        let seq = self
            .reassembler
            .as_ref()
            .map_or(0, |r| r.expected_msg_seq());
        self.dispatch_one(msg_type, seq, body)
    }

    /// Test-only: queues a raw 2-byte alert (`level ‖ description`) under
    /// the current write key, so loopback tests can exercise the peer's
    /// authenticated-alert path without widening the public API.
    #[cfg(test)]
    pub(crate) fn send_alert_record_for_test(&mut self, level: u8, description: u8) {
        let dg = self
            .encrypt_record_dtls(ContentType::Alert, &[level, description])
            .expect("write keys installed");
        self.out_dgrams.push(dg);
    }

    fn send_flight(&mut self, flight: Flight) -> Result<(), Error> {
        for rec in &flight.records {
            let dg = self.encode_flight_record(rec)?;
            self.out_dgrams.push(dg);
        }
        self.retransmit.set_flight(flight, self.last_now);
        Ok(())
    }

    /// Process the client's [Certificate] / CKE / [CertificateVerify] /
    /// Finished flight (CCS is handled at the record layer in
    /// `process_record`). RFC 5246 §7.3 fixes the order: with a
    /// `CertificateRequest` out, the Certificate comes first, the
    /// CertificateVerify (when a chain was presented) right after the
    /// ClientKeyExchange; each handler refuses its message out of place.
    fn on_client_flight(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        match msg_type {
            hs_type::CERTIFICATE => self.on_client_certificate(body, raw),
            hs_type::CLIENT_KEY_EXCHANGE => self.on_client_key_exchange(body, raw),
            hs_type::CERTIFICATE_VERIFY => self.on_client_cert_verify(body, raw),
            hs_type::FINISHED => self.on_finished(body, raw),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// mTLS: the client's `Certificate` answering our `CertificateRequest`
    /// (RFC 5246 §7.4.6): the first message of its flight, exactly once.
    /// An empty chain is "no certificate": admitted when the policy does
    /// not require one, `handshake_failure` otherwise (§7.4.6: the server
    /// "MAY respond with a fatal handshake failure alert"). A chain is
    /// verified against the policy's roots for client authentication and
    /// its `CertificateVerify` must follow the ClientKeyExchange (§7.4.8).
    ///
    /// Like the ClientKeyExchange, this message travels in plaintext
    /// (epoch 0): the caller turns a rejection into a silent drop and
    /// rewinds the reassembler, so nothing is committed before the chain
    /// has verified. A spoofed message that *passes* — an empty
    /// Certificate under a non-required policy — is caught by the client's
    /// Finished, which covers its own transcript: the handshake then fails
    /// closed rather than admitting the wrong identity.
    fn on_client_certificate(&mut self, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        let Some(policy) = self.config.client_auth.as_ref() else {
            // No CertificateRequest went out: a Certificate is unsolicited.
            return Err(Error::UnexpectedMessage);
        };
        if self.client_cert_seen || self.master.is_some() {
            return Err(Error::UnexpectedMessage);
        }
        let chain = parse_certificate_list_12(body)?;
        if chain.is_empty() {
            if policy.required {
                return Err(Error::CertificateRequired);
            }
            self.transcript.update(raw);
            self.client_cert_seen = true;
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
        self.client_cert_seen = true;
        self.client_cert_chain = chain;
        self.client_leaf_key = Some(leaf_key);
        Ok(())
    }

    /// mTLS: the client's `CertificateVerify` (RFC 5246 §7.4.8) — a
    /// signature over the handshake messages so far, ClientHello through
    /// ClientKeyExchange in their DTLS form (RFC 6347 §4.2.6), under the
    /// leaf key [`Self::on_client_certificate`] verified. The scheme must
    /// be one our `CertificateRequest` listed. A bad signature is
    /// `decrypt_error` (§7.4.8).
    fn on_client_cert_verify(&mut self, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        // Only after a chain and the ClientKeyExchange, exactly once.
        let Some(leaf_key) = self.client_leaf_key.as_ref() else {
            return Err(Error::UnexpectedMessage);
        };
        if self.master.is_none() || self.client_cert_verified {
            return Err(Error::UnexpectedMessage);
        }
        let mut c = ReadCursor::new(body);
        let scheme = SignatureScheme(c.u16()?);
        let signature = c.vec_u16()?.to_vec();
        c.expect_empty()?;
        if !crate::tls::crypto::sign::tls12_certificate_request_schemes(
            &self.config.signature_policy,
        )
        .contains(&scheme)
        {
            return Err(Error::IllegalParameter);
        }
        // The signed bytes are exactly the transcript buffer at this point
        // (CH..CKE inclusive, DTLS headers included); the registry
        // verifier hashes internally.
        let message = self.transcript.buffered_bytes().to_vec();
        verify_signature_tls12(
            scheme,
            leaf_key,
            &message,
            &signature,
            &self.config.signature_policy,
        )
        .map_err(|e| match e {
            Error::BadCertificate => Error::DecryptError,
            other => other,
        })?;
        self.transcript.update(raw);
        self.client_cert_verified = true;
        Ok(())
    }

    fn on_client_key_exchange(&mut self, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        // Exactly one ClientKeyExchange per handshake. `WaitClientFlight`
        // covers both the CKE and the Finished, and the CKE travels at
        // epoch 0, unauthenticated: an off-path spoofer who guesses the
        // next `message_seq` could otherwise re-run ECDH here, overwrite
        // `master` and the pending crypters and append a second CKE to the
        // transcript, so the genuine (already in-flight) Finished would
        // never verify and the handshake would stall. Once the master
        // secret exists the key exchange is over; on the unauthenticated
        // path `process_handshake_record` turns this into a silent drop and
        // rewinds the reassembler so the genuine Finished (same
        // `message_seq`) is still accepted.
        if self.master.is_some() {
            return Err(Error::UnexpectedMessage);
        }
        // RFC 5246 §7.3: with a CertificateRequest out, the client's
        // Certificate precedes its ClientKeyExchange.
        if self.config.client_auth.is_some() && !self.client_cert_seen {
            return Err(Error::UnexpectedMessage);
        }
        let cke = ClientKeyExchange::decode(body)?;
        let group = self.group.ok_or(Error::InappropriateState)?;
        // Complete ECDHE on the negotiated group and derive the premaster.
        // Mirrors `src/tls/conn/server12.rs::on_client_key_exchange`.
        let mut premaster: Vec<u8> = match group {
            NamedGroup::X25519 => {
                let sk = self.x25519.as_ref().ok_or(Error::InappropriateState)?;
                let peer: [u8; 32] = cke.point.as_slice().try_into().map_err(|_| Error::Decode)?;
                // RFC 7748 §6.1: reject the all-zero (small-order) DH output.
                sk.diffie_hellman(&peer)
                    .map_err(|_| Error::IllegalParameter)?
                    .to_vec()
            }
            NamedGroup::SECP256R1 => {
                let sk = self.p256.as_ref().ok_or(Error::InappropriateState)?;
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, &cke.point)
                    .map_err(|_| Error::Decode)?;
                sk.diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?
            }
            NamedGroup::SECP384R1 => {
                let sk = self.p384.as_ref().ok_or(Error::InappropriateState)?;
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P384, &cke.point)
                    .map_err(|_| Error::Decode)?;
                sk.diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?
            }
            NamedGroup::SECP521R1 => {
                let sk = self.p521.as_ref().ok_or(Error::InappropriateState)?;
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P521, &cke.point)
                    .map_err(|_| Error::Decode)?;
                sk.diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?
            }
            _ => return Err(Error::HandshakeFailure),
        };
        let cr = self.client_random.expect("set");
        let sr = self.server_random.expect("set");

        // Feed CKE into the transcript BEFORE deriving the master so the
        // EMS session_hash (RFC 7627 §4) spans CH..CKE inclusive.
        self.transcript.update(raw);

        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let master = if self.ems_negotiated {
            let sh = self.transcript.current_hash();
            extended_master_secret(suite.hash, &premaster, sh.as_slice())
        } else {
            master_secret(suite.hash, &premaster, &cr, &sr)
        };
        // The premaster is dead once the master secret exists (DTLS-L7).
        crate::tls::conn::wipe(&mut premaster);
        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log("CLIENT_RANDOM", &cr, &master);
        }
        // key_block (RFC 5246 §6.3): c_key || s_key || c_iv || s_iv, the
        // IVs 4 bytes each for GCM (RFC 5288 §3) and 12 for ChaCha20-Poly1305
        // (RFC 7905 §2); `derive_pair` lays it out and scrubs the buffer.
        let (read_crypter, write_crypter) =
            RecordCrypter12::derive_pair(suite.hash, suite.aead, suite.key_len, &master, &sr, &cr);
        self.pending_read_crypter = Some(read_crypter);
        self.pending_write_crypter = Some(write_crypter);
        self.master = Some(master);
        // RFC 6347 §4.2.4: receipt of the client's responding flight
        // implicitly acknowledges our ServerHello..ServerHelloDone flight.
        // Cancel its retransmit timer (mirrors the client's
        // `on_server_hello`); leaving it armed would keep re-emitting the
        // flight on every backoff step.
        //
        // Only once the key agreement has succeeded: this message arrives
        // at epoch 0, unauthenticated, so a spoofed garbage CKE would
        // otherwise drop the stored flight (and disarm its timer) and the
        // genuine client would wait out the handshake with nothing left to
        // retransmit to it.
        self.retransmit.on_peer_response();
        Ok(())
    }

    fn on_finished(&mut self, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if body.len() != 12 {
            return Err(Error::Decode);
        }
        if self.read_crypter.is_none() {
            // CCS must arrive first.
            return Err(Error::UnexpectedMessage);
        }
        let master = self.master.ok_or(Error::InappropriateState)?;
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        // mTLS (RFC 5246 §7.4.8): a client that presented a chain MUST
        // prove possession of its key before its Finished; and with client
        // authentication required a verified key must exist at all
        // (defence in depth — `on_client_certificate` already refuses an
        // empty chain — so no later state-machine change can let a
        // required-certificate handshake complete anonymously).
        if self.client_leaf_key.is_some() && !self.client_cert_verified {
            return Err(Error::UnexpectedMessage);
        }
        if self.config.client_auth.as_ref().is_some_and(|p| p.required)
            && !self.client_cert_verified
        {
            return Err(Error::CertificateRequired);
        }
        let th = self.transcript.current_hash();
        let expected = finished_verify_data(suite.hash, &master, b"client finished", th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.transcript.update(raw);

        // Emit our CCS + Finished.
        let mut flight = Flight::new();
        flight.push_record(ContentType::ChangeCipherSpec, 0, alloc::vec![0x01]);
        // Bump our write epoch.
        self.write_crypter = self.pending_write_crypter.take();
        self.write_epoch = 1;
        self.write_seq_in_epoch = 0;

        let th2 = self.transcript.current_hash();
        let verify_data =
            finished_verify_data(suite.hash, &master, b"server finished", th2.as_slice());
        let fin_body: Vec<u8> = verify_data.to_vec();
        // DTLS handshake fragment with the next out_msg_seq; the transcript
        // covers the message under that header (RFC 6347 §4.2.6).
        let msg_seq = self.out_msg_seq;
        self.out_msg_seq += 1;
        self.transcript
            .update(&transcript_message(hs_type::FINISHED, msg_seq, &fin_body));
        for frag in write_fragments(hs_type::FINISHED, msg_seq, &fin_body, DEFAULT_MAX_FRAGMENT) {
            flight.push_record(ContentType::Handshake, 1, frag);
        }

        // This CCS + Finished is the LAST flight of the handshake: no
        // responding flight from the client will ever arrive to cancel a
        // retransmit timer, so we deliberately do NOT register it with the
        // retransmit machine (RFC 6347 §4.2.4 puts the last-flight sender
        // in the FINISHED state, where retransmission is triggered by
        // seeing the peer re-send ITS flight — not by a timer). Arming the
        // timer here would blindly re-emit the flight on every backoff step
        // and previously GiveUp-closed a perfectly healthy connection ~2
        // minutes after establishment.
        for rec in &flight.records {
            let dg = self.encode_flight_record(rec)?;
            self.out_dgrams.push(dg);
        }
        self.retransmit.on_peer_response();
        // Keep the flight so a retransmitted client Finished can trigger
        // a re-send (see `on_retransmitted_client_finished`).
        let mut client_fin = [0u8; 12];
        client_fin.copy_from_slice(body);
        self.client_finished = Some(client_fin);
        self.final_flight = Some(flight);
        self.final_flight_resends = 0;
        self.state = State::Connected;
        Ok(())
    }
}

/// Decoded DTLS ClientHello body (the bytes after the 4-byte TLS handshake
/// header).
struct ParsedDtlsClientHello {
    #[allow(dead_code)]
    legacy_version: u16,
    random: Random,
    #[allow(dead_code)]
    session_id: Vec<u8>,
    cookie: Vec<u8>,
    cipher_suites: Vec<CipherSuite>,
    extensions: Vec<(ExtensionType, Vec<u8>)>,
}

fn parse_dtls_client_hello(body: &[u8]) -> Result<ParsedDtlsClientHello, Error> {
    let mut c = ReadCursor::new(body);
    let legacy_version = c.u16()?;
    let mut random: Random = [0u8; 32];
    let r = c.take(32)?;
    random.copy_from_slice(r);
    let session_id = c.vec_u8()?.to_vec();
    let cookie = c.vec_u8()?.to_vec();
    let cs_bytes = c.vec_u16()?;
    if cs_bytes.len() % 2 != 0 {
        return Err(Error::Decode);
    }
    let mut cs_cursor = ReadCursor::new(cs_bytes);
    let mut cipher_suites = Vec::with_capacity(cs_bytes.len() / 2);
    while !cs_cursor.is_empty() {
        cipher_suites.push(CipherSuite(cs_cursor.u16()?));
    }
    let _compression = c.vec_u8()?;
    let ext_bytes = c.vec_u16()?;
    c.expect_empty()?;
    let extensions = parse_extensions(ext_bytes)?;
    Ok(ParsedDtlsClientHello {
        legacy_version,
        random,
        session_id,
        cookie,
        cipher_suites,
        extensions,
    })
}

/// Builds a cookie-binding fingerprint from a parsed DTLS 1.2 CH. Covers
/// the negotiation-deciding wire fields so a CH2 with rewritten cipher
/// suites / supported_groups / supported_versions fails cookie validation.
fn ch_fingerprint_dtls12(parsed: &ParsedDtlsClientHello) -> Vec<u8> {
    let mut cs_be = Vec::with_capacity(parsed.cipher_suites.len() * 2);
    for cs in &parsed.cipher_suites {
        cs_be.extend_from_slice(&cs.0.to_be_bytes());
    }
    let groups = ext::find(&parsed.extensions, ExtensionType::SUPPORTED_GROUPS);
    let versions = ext::find(&parsed.extensions, ExtensionType::SUPPORTED_VERSIONS);
    // DTLS 1.2 cookie path doesn't carry `key_share`; pass an empty slot.
    build_ch_fingerprint(&cs_be, groups, versions, &[])
}

fn parse_extensions(body: &[u8]) -> Result<Vec<(ExtensionType, Vec<u8>)>, Error> {
    let mut c = ReadCursor::new(body);
    let mut out = Vec::new();
    while !c.is_empty() {
        let ty = ExtensionType(c.u16()?);
        let data = c.vec_u16()?.to_vec();
        out.push((ty, data));
    }
    Ok(out)
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

fn build_certificate_msg(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut msg = alloc::vec![hs_type::CERTIFICATE];
    with_len_u24(&mut msg, |b| {
        with_len_u24(b, |list| {
            for cert in chain {
                with_len_u24(list, |c| c.extend_from_slice(cert));
            }
        });
    });
    msg
}

/// Maps the configured server key to the IANA `SignatureScheme` we
/// advertise in `ServerKeyExchange.signature_algorithm`. Mirrors
/// `src/tls/conn/server12.rs::signature_scheme`.
///
/// TLS 1.2 (RFC 5246 §7.4.1.4.1) allows an independent (hash, signature)
/// pair on the SKE — separate from the PRF / transcript hash fixed by the
/// suite. For ECDSA the scheme tracks the curve (RFC 8446 §4.2.3 / RFC 8447
/// IANA registry); an `rsaEncryption` RSA key takes the first of
/// `TLS12_RSA_SCHEME_PREFERENCE` the client offered — RSA-PSS, else
/// RSASSA-PKCS1-v1_5 (RFC 5246 §7.4.1.4.1; RFC 8446 forbids it only in TLS
/// 1.3 handshake signatures) — and an `id-RSASSA-PSS` one its
/// `rsa_pss_pss_*` scheme.
///
/// `Error::UnsupportedKeyType` when the key has no DTLS 1.2 scheme: the RFC
/// 8734 Brainpool code points are TLS 1.3 only (§2: "MUST NOT be used in
/// TLS 1.2"), secp256k1 / SM2 have none at all, and ML-DSA is not specified
/// for the version — a configuration error, not something to sign under a
/// code point the client would reject. `Error::HandshakeFailure` when the
/// key's scheme is not among the ones the client `offered` (RFC 5246
/// §7.4.3). An EdDSA key signs under its own scheme (RFC 8422 §5.9: an
/// Ed25519 key "MUST use the ed25519 signature algorithm", an Ed448 key
/// `ed448`); an external key under the first of its advertised schemes
/// that DTLS 1.2 defines and the client offered.
fn signature_scheme(
    key: &ServerKey,
    offered: &[SignatureScheme],
) -> Result<SignatureScheme, Error> {
    let own = match key {
        ServerKey::Rsa(_) => {
            return crate::tls::crypto::sign::tls12_rsa_scheme(offered)
                .ok_or(Error::HandshakeFailure);
        }
        ServerKey::RsaPss(_, hash) => Some(crate::tls::crypto::sign::rsa_pss_pss_scheme(*hash)),
        ServerKey::Ecdsa(k) => crate::tls::crypto::sign::tls_signature_scheme_for_curve(k.curve())
            .filter(|s| !s.is_brainpool_tls13()),
        ServerKey::Ed25519(_) => Some(SignatureScheme::ED25519),
        ServerKey::Ed448(_) => Some(SignatureScheme::ED448),
        ServerKey::External { schemes } => {
            let mut usable = schemes
                .iter()
                .copied()
                .filter(|s| crate::tls::crypto::sign::is_tls12_signature_scheme(*s))
                .peekable();
            if usable.peek().is_none() {
                return Err(Error::UnsupportedKeyType);
            }
            return usable
                .find(|s| offered.contains(s))
                .ok_or(Error::HandshakeFailure);
        }
        // ML-DSA: nothing specifies it for (D)TLS 1.2.
        #[cfg(feature = "mldsa")]
        ServerKey::MlDsa44(_) | ServerKey::MlDsa65(_) | ServerKey::MlDsa87(_) => None,
    };
    let own = own.ok_or(Error::UnsupportedKeyType)?;
    if offered.contains(&own) {
        Ok(own)
    } else {
        Err(Error::HandshakeFailure)
    }
}

/// The scheme [`signature_scheme`] would pick for `key` before any client
/// offer is known — what suite selection needs to know the key's family.
fn own_signature_scheme(key: &ServerKey) -> Option<SignatureScheme> {
    match key {
        // Every scheme the key could sign under is of one family; the
        // first is as good as any for that.
        ServerKey::External { schemes } => schemes
            .iter()
            .copied()
            .find(|s| crate::tls::crypto::sign::is_tls12_signature_scheme(*s)),
        _ => signature_scheme(key, &ALL_TLS12_SCHEMES).ok(),
    }
}

/// Every code point [`crate::tls::crypto::sign::is_tls12_signature_scheme`]
/// admits that this server could sign under, as an "offer" that never
/// narrows [`signature_scheme`].
const ALL_TLS12_SCHEMES: [SignatureScheme; 11] = [
    SignatureScheme::RSA_PSS_RSAE_SHA256,
    SignatureScheme::RSA_PSS_RSAE_SHA384,
    SignatureScheme::RSA_PSS_RSAE_SHA512,
    SignatureScheme::RSA_PSS_PSS_SHA256,
    SignatureScheme::RSA_PSS_PSS_SHA384,
    SignatureScheme::RSA_PSS_PSS_SHA512,
    SignatureScheme::ECDSA_SECP256R1_SHA256,
    SignatureScheme::ECDSA_SECP384R1_SHA384,
    SignatureScheme::ECDSA_SECP521R1_SHA512,
    SignatureScheme::ED25519,
    SignatureScheme::ED448,
];

/// The signature family of an IANA `SignatureScheme` code point, for DTLS 1.2
/// `ECDHE-*` suite selection: the ECDSA and EdDSA code points map to
/// `Ecdsa` (RFC 8422 §2.2), everything else (RSA-PSS) to `Rsa`.
fn sig_kind_from_scheme(scheme: SignatureScheme) -> SigKind {
    match scheme {
        SignatureScheme::ECDSA_SECP256R1_SHA256
        | SignatureScheme::ECDSA_SECP384R1_SHA384
        | SignatureScheme::ECDSA_SECP521R1_SHA512
        | SignatureScheme::ED25519
        | SignatureScheme::ED448 => SigKind::Ecdsa,
        _ => SigKind::Rsa,
    }
}

/// Which signature family the configured server key belongs to. Drives suite
/// negotiation: an RSA key only matches the three `ECDHE-RSA-*` entries of
/// `SUITES_12`; an ECDSA key only matches the three `ECDHE-ECDSA-*` entries.
/// Mirrors `src/tls/conn/server12.rs::sig_kind`.
fn sig_kind_for_key(key: &ServerKey) -> SigKind {
    match key {
        ServerKey::Rsa(_) | ServerKey::RsaPss(..) => SigKind::Rsa,
        ServerKey::Ecdsa(_) | ServerKey::Ed25519(_) | ServerKey::Ed448(_) => SigKind::Ecdsa,
        // External key: infer the family from the scheme `signature_scheme`
        // will sign under, so the matching `ECDHE-RSA-*` / `ECDHE-ECDSA-*`
        // suites are offered.
        ServerKey::External { .. } => {
            own_signature_scheme(key).map_or(SigKind::Rsa, sig_kind_from_scheme)
        }
        // ML-DSA has no DTLS 1.2 scheme (`signature_scheme` refuses it before
        // any suite is used); the family is immaterial.
        #[cfg(feature = "mldsa")]
        ServerKey::MlDsa44(_) | ServerKey::MlDsa65(_) | ServerKey::MlDsa87(_) => SigKind::Rsa,
    }
}

#[cfg(test)]
mod rsa_scheme_tests {
    use super::*;

    /// The DTLS 1.2 server's `ServerKeyExchange` scheme for an RSA identity
    /// against the client's offer, as on TLS 1.2: RSA-PSS when offered,
    /// else PKCS#1 v1.5 (RFC 5246 §7.4.1.4.1; Mbed TLS's DTLS 1.2 client
    /// lists no RSA-PSS), else `handshake_failure`; an `id-RSASSA-PSS` key
    /// stays PSS-only. The key's family (for suite selection) is RSA
    /// whatever the offer.
    #[test]
    fn rsa_scheme_follows_the_client_offer() {
        let s = |v: &[u16]| v.iter().map(|&c| SignatureScheme(c)).collect::<Vec<_>>();
        let key = crate::rsa::BoxedRsaPrivateKey::from_pkcs1_der(
            &crate::test_util::rsa_test_key_a().to_pkcs1_der(),
        )
        .unwrap();
        let rsa = ServerKey::Rsa(key.clone());
        assert_eq!(
            signature_scheme(&rsa, &s(&[0x0403, 0x0401, 0x0501])).unwrap(),
            SignatureScheme::RSA_PKCS1_SHA256
        );
        assert_eq!(
            signature_scheme(&rsa, &s(&[0x0501, 0x0805])).unwrap(),
            SignatureScheme::RSA_PSS_RSAE_SHA384
        );
        assert!(matches!(
            signature_scheme(&rsa, &s(&[0x0403, 0x0807])),
            Err(Error::HandshakeFailure)
        ));
        assert!(sig_kind_for_key(&rsa) == SigKind::Rsa);
        let pss = ServerKey::RsaPss(key, crate::x509::PssHash::Sha256);
        assert!(matches!(
            signature_scheme(&pss, &s(&[0x0401])),
            Err(Error::HandshakeFailure)
        ));
    }
}

#[cfg(test)]
mod f3_msg_seq_tests {
    //! F3 regression: the DTLS 1.2 server must reject a ClientHello whose
    //! `message_seq` is implausibly large before the reassembler-seeding loop
    //! (`for s in 0..=msg_seq`). `message_seq` is not bound by the cookie
    //! fingerprint, so a client that completed the HelloVerifyRequest
    //! roundtrip could otherwise still drive tens of thousands of cycles.
    //! The rejection is a SILENT DROP (`feed_datagram` returns `Ok`): the
    //! input is trivially spoofable, so a fatal error would hand an off-path
    //! attacker a one-datagram kill switch for in-flight handshakes
    //! (RFC 6347 §4.1.2.7).
    use super::*;
    use crate::dtls::{ClientConfig12Internal, DtlsClientConnection12, DtlsServerConnection12};
    use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::tls::pki::RootCertStore;
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    fn make_server_cfg() -> (ServerConfig12Internal, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"f3-dtls12-key", b"nonce", &[]);
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
            ServerConfig12Internal::with_ecdsa(alloc::vec![der.clone()], key)
                .require_cookie_exchange(false),
            der,
        )
    }

    fn make_client(server_cert: &[u8]) -> DtlsClientConnection12 {
        let mut roots = RootCertStore::new();
        roots.add_der(server_cert.to_vec()).unwrap();
        let cfg = ClientConfig12Internal::new(roots, "dtls.example")
            .with_verification_time(Time::utc(2026, 6, 1, 0, 0, 0));
        let mut crng = HmacDrbg::<Sha256>::new(b"f3-dtls12-client", b"nonce", &[]);
        DtlsClientConnection12::new(cfg, b"client-addr".to_vec(), &mut crng)
    }

    fn client_hello_datagram() -> Vec<u8> {
        let (_, cert) = make_server_cfg();
        let mut client = make_client(&cert);
        let mut out = client.pop_outbound_datagrams();
        out.remove(0)
    }

    fn new_server() -> DtlsServerConnection12<HmacDrbg<Sha256>> {
        let (cfg, _) = make_server_cfg();
        let srng = HmacDrbg::<Sha256>::new(b"f3-dtls12-server", b"nonce", &[]);
        DtlsServerConnection12::new(Arc::new(cfg), b"client-addr".to_vec(), srng)
    }

    /// Patch the 16-bit `message_seq` of the first handshake fragment. Record
    /// header is 13 bytes; `message_seq` sits 4 bytes into the fragment.
    fn patch_message_seq(dgram: &mut [u8], seq: u16) {
        const MSG_SEQ_OFF: usize = 13 + 4;
        dgram[MSG_SEQ_OFF] = (seq >> 8) as u8;
        dgram[MSG_SEQ_OFF + 1] = seq as u8;
    }

    #[test]
    fn oversized_message_seq_is_silently_dropped_without_giant_loop() {
        let mut dgram = client_hello_datagram();
        patch_message_seq(&mut dgram, 0xFFFF);
        let mut server = new_server();
        // Spoofable epoch-0 input: dropped, never fatal.
        assert_eq!(server.feed_datagram(&dgram), Ok(()));
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
    fn legitimate_message_seq_zero_is_accepted() {
        let (cfg, cert) = make_server_cfg();
        let mut client = make_client(&cert);
        let srng = HmacDrbg::<Sha256>::new(b"f3-dtls12-ok", b"nonce", &[]);
        let mut server = DtlsServerConnection12::new(Arc::new(cfg), b"client-addr".to_vec(), srng);
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
