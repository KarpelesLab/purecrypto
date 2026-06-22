//! Unified configuration shared between TLS 1.2, TLS 1.3, DTLS 1.2, and
//! DTLS 1.3, in both client and server roles.
//!
//! The library currently has eight per-(version, role) config types ;
//! [`Config`] collapses them into one. Role is chosen at
//! [`super::Connection`] construction time; version is bounded by
//! [`Config::min_version`] / [`Config::max_version`].

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ec::{BoxedEcdsaPrivateKey, Ed448PrivateKey, Ed25519PrivateKey};
use crate::rsa::BoxedRsaPrivateKey;
use crate::signature_registry::SignaturePolicy;

use super::groups::NamedGroup;
use super::keylog::KeyLog;
use super::pki::{CrlStore, RootCertStore};
use super::version::ProtocolVersion;
use crate::x509::Time;

#[cfg(feature = "std")]
use super::conn::ReplayWindow;

/// A signing key for the local endpoint (server certificate signing, or
/// client mTLS signing).
///
/// Renamed from `ServerKey` (which used to be misleadingly named for what is
/// also the client mTLS key). The old name remains as a
/// `pub type ServerKey = SigningKey;` alias for one
/// release.
///
/// The PQ variants (`MlDsa*`) carry their full key material inline. Since
/// this enum is held once per [`Config`] (effectively per endpoint), the
/// variant-size disparity flagged by `clippy::large_enum_variant` is a
/// non-issue.
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
pub enum SigningKey {
    /// RSA key; signs with `rsa_pss_rsae_sha256`.
    Rsa(BoxedRsaPrivateKey),
    /// ECDSA key; the scheme is chosen from the curve at sign time.
    Ecdsa(BoxedEcdsaPrivateKey),
    /// Ed25519 key.
    Ed25519(Ed25519PrivateKey),
    /// Ed448 key (TLS 1.3 only).
    Ed448(Ed448PrivateKey),
    /// ML-DSA-44 (FIPS 204, draft-ietf-tls-mldsa).
    MlDsa44(crate::mldsa::MlDsa44PrivateKey),
    /// ML-DSA-65.
    MlDsa65(crate::mldsa::MlDsa65PrivateKey),
    /// ML-DSA-87.
    MlDsa87(crate::mldsa::MlDsa87PrivateKey),
    /// An **external** signing key: no key material is held in-process. When the
    /// handshake needs the `CertificateVerify` (or DTLS 1.2 `ServerKeyExchange`)
    /// signature it suspends; the caller fetches the bytes via
    /// [`Connection::signature_request`](crate::tls::Connection::signature_request),
    /// signs them out-of-band (e.g. on a TPM/HSM, synchronously or `.await`ed),
    /// and resumes with
    /// [`Connection::provide_signature`](crate::tls::Connection::provide_signature).
    ///
    /// This is the low-level seam. For a transparent, key-agnostic experience —
    /// where the caller installs a [`PrivateKey`](crate::tls::PrivateKey) and
    /// drives the handshake with [`Connection::drive`](crate::tls::Connection::drive),
    /// never hand-managing the signature — use
    /// [`ConfigBuilder::private_key`](crate::tls::ConfigBuilder::private_key)
    /// instead (`std` only).
    ///
    /// `schemes` lists the IANA `SignatureScheme` code points the external key
    /// can produce (RFC 8446 §4.2.3 — e.g. `0x0804` rsa_pss_rsae_sha256,
    /// `0x0403` ecdsa_secp256r1_sha256, `0x0807` ed25519), most-preferred first.
    /// The endpoint signs with the first one the peer also offered; the
    /// handshake fails if none overlap. Supported for TLS 1.3 and DTLS 1.2/1.3
    /// (classic TLS 1.2 server auth is not).
    External {
        /// IANA `SignatureScheme` code points the key can produce, preferred
        /// first.
        schemes: Vec<u16>,
    },
}

/// A certificate chain (leaf first) paired with its signing key.
#[non_exhaustive]
pub struct Identity {
    /// DER-encoded certificate chain, leaf first.
    pub cert_chain: Vec<Vec<u8>>,
    /// Signing key matching the leaf certificate.
    pub key: SigningKey,
}

impl Identity {
    /// Construct an [`Identity`] from a cert chain (leaf first) and its
    /// signing key. Cross-crate-friendly alternative to literal construction,
    /// which is forbidden by `#[non_exhaustive]`.
    pub fn new(cert_chain: Vec<Vec<u8>>, key: SigningKey) -> Self {
        Self { cert_chain, key }
    }
}

/// Client-authentication policy for a server (mTLS).
#[non_exhaustive]
pub struct ClientAuth {
    /// Trust anchors for verifying the peer's chain.
    pub roots: RootCertStore,
    /// When `true`, no-cert clients are rejected with `certificate_required`
    /// (RFC 8446 §4.3.2). When `false`, anonymous clients are allowed.
    pub required: bool,
}

impl ClientAuth {
    /// Construct a [`ClientAuth`] policy from a trust store and a
    /// `required` flag (see the field for semantics). Cross-crate-friendly
    /// alternative to literal construction, which is forbidden by
    /// `#[non_exhaustive]`.
    pub fn new(roots: RootCertStore, required: bool) -> Self {
        Self { roots, required }
    }
}

/// Unified configuration for a TLS or DTLS endpoint, client or server.
///
/// Fields are arranged in five blocks: protocol versions, identity / trust
/// anchors / signing-algorithm policy, client-side knobs, server-side
/// knobs, and DTLS-specific knobs (inert when the negotiated version is
/// TLS).
///
/// `#[non_exhaustive]` because TLS evolves continuously (PQ-hybrid groups,
/// ECH, RFC 8879 cert compression, future RFCs) — every new knob would
/// otherwise be a source-breaking change. Construct via [`Config::default`]
/// or [`Config::builder`].
#[non_exhaustive]
pub struct Config {
    // ---- Protocol versions ----
    /// Lowest version this endpoint is willing to negotiate.
    pub min_version: ProtocolVersion,
    /// Highest version. The (TLS vs DTLS) discriminator is encoded here;
    /// `min_version` and `max_version` must agree on this dimension.
    pub max_version: ProtocolVersion,

    // ---- Identity ----
    /// Cert chain + signing key. Required for server role; optional for
    /// client (mTLS).
    pub identity: Option<Identity>,

    // ---- Trust ----
    /// Trust anchors for verifying the peer's chain.
    pub roots: RootCertStore,
    /// CRLs consulted during chain validation. Empty by default.
    pub crls: CrlStore,
    /// Signature-algorithm policy (chain + CertificateVerify / SKE sig).
    pub signature_policy: SignaturePolicy,

    // ---- Client-side ----
    /// SNI hostname offered AND verified in the peer leaf certificate.
    /// Required for client role.
    pub server_name: Option<String>,
    /// Validate the peer's chain. Set `false` for pinned-key flows.
    pub verify_certificates: bool,
    /// Clock used for cert validity (`notBefore`/`notAfter`). Applies to the
    /// server certificate the client verifies AND to the client certificate a
    /// server verifies under mTLS. `None` = system clock under `std`.
    pub verification_time: Option<Time>,

    // ---- Server-side ----
    /// Client-authentication policy. `None` = no client auth.
    pub client_auth: Option<ClientAuth>,
    /// DER bytes of a CRL to staple in the TLS 1.3 `Certificate` message
    /// (TLS 1.2 has no per-cert extension slot).
    pub stapled_crl: Option<Vec<u8>>,
    /// DER bytes of an OCSP `OCSPResponse` to staple (RFC 6066 §8 + RFC
    /// 6960). On TLS 1.2 the server emits it as the body of a
    /// `CertificateStatus` handshake message; on TLS 1.3 it is carried in
    /// the leaf `CertificateEntry`'s per-cert `status_request` extension.
    /// Honoured only when the client advertised `status_request` in its
    /// `ClientHello`.
    pub stapled_ocsp_response: Option<Vec<u8>>,
    /// TLS 1.2 / TLS 1.3 session-ticket key. `None` = no tickets issued.
    pub ticket_key: Option<[u8; 32]>,
    /// Cap on bytes the server accepts as 0-RTT early data. `0` = no 0-RTT.
    pub max_early_data_size: u32,
    /// 0-RTT replay protection (TLS 1.3 server). `None` = skip the check.
    #[cfg(feature = "std")]
    pub replay_window: Option<ReplayWindow>,

    // ---- Both ----
    /// ALPN protocols. Client: preferences offered. Server: accepted set in
    /// preference order.
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Client cipher-suite restriction (IANA wire IDs, in preference order).
    /// `None` (the default) offers the library's full curated set. When set,
    /// only suites that appear in BOTH this list and the engine's supported set
    /// are offered, ordered by this list — the seam for curl-style `--ciphers`
    /// / `--tls13-ciphers`. Fail-closed: a list that excludes every suite the
    /// configured protocol version(s) support makes
    /// [`Connection::client`](crate::tls::Connection::client) error with
    /// [`Error::NoUsableCipherSuites`](crate::tls::Error::NoUsableCipherSuites)
    /// instead of silently falling back to the full set (which would let a
    /// typo'd suite ID re-enable everything). A list matching only some of
    /// the enabled versions is fine — versions with no matching suite simply
    /// cannot be negotiated. TLS 1.3 and 1.2 are both covered (mix 0x13xx
    /// and classic codepoints in one list); the value is inert on the server.
    pub cipher_suites: Option<Vec<u16>>,
    /// `record_size_limit` extension (RFC 8449). `None` = library default.
    pub record_size_limit: Option<u16>,
    /// RFC 7627 §5.3 — when `true` (the default), a TLS 1.2 handshake
    /// MUST negotiate Extended Master Secret; if the peer doesn't echo
    /// the extension the connection aborts with `handshake_failure`.
    /// This blocks the triple-handshake family of cross-protocol attacks
    /// the EMS extension exists to prevent. Set to `false` only to
    /// interoperate with very old peers that predate RFC 7627. Inert
    /// outside TLS 1.2 (TLS 1.3 derives all secrets transcript-bound).
    pub require_extended_master_secret: bool,

    // ---- RFC 7250 raw public keys (TLS 1.3 only) ----
    /// Server-cert-type preference list offered in the `server_certificate_type`
    /// extension (RFC 7250 §3). Default `[0]` (X.509 only) leaves the extension
    /// off the wire. Set to e.g. `[2]` (RawPublicKey only) or `[2, 0]`
    /// (prefer RawPublicKey, accept X.509) to negotiate raw public keys.
    ///
    /// On the client side: the order is the client's preference. On the
    /// server side: this is the server's accept-set; selection picks the
    /// highest-priority client offer that the server also accepts. Empty
    /// is rejected at `build()` time.
    pub server_cert_type_preference: Vec<u8>,
    /// Client-cert-type preference list for `client_certificate_type` (mTLS).
    /// Wire encoding and defaults mirror `server_cert_type_preference`.
    pub client_cert_type_preference: Vec<u8>,
    /// Server: bare `SubjectPublicKeyInfo` DER to send as the single
    /// `CertificateEntry` body when `RawPublicKey` is the negotiated
    /// server-cert type (RFC 7250 §4.2). MUST be set if
    /// `server_cert_type_preference` advertises `RawPublicKey`; the server
    /// otherwise falls back to its X.509 chain (and may have to refuse the
    /// handshake if the client only offered RawPublicKey).
    pub raw_public_key_spki: Option<Vec<u8>>,
    /// Client: allowlist of bare `SubjectPublicKeyInfo` DER bytes accepted
    /// as the server's raw public key. When `RawPublicKey` is negotiated,
    /// the server's CertificateEntry body must constant-time match one of
    /// these entries — there is no X.509 PKI to fall back on, so trust must
    /// be established out-of-band. Hostname verification is skipped under
    /// RawPublicKey.
    pub expected_raw_public_keys: Vec<Vec<u8>>,

    // ---- TLS 1.3 key exchange (RFC 8446 §4.1.4) ----
    /// Server preference for the (EC)DHE group used in key exchange.
    /// When `Some(g)` and the client's `ClientHello` advertised `g` in
    /// `supported_groups` but did NOT include a `key_share` entry for
    /// it, the server emits a HelloRetryRequest (RFC 8446 §4.1.4)
    /// asking the client to retry with a share for `g`. When `None`
    /// (the default), the server takes the first group it accepts from
    /// the client's `key_share` and never emits HRR.
    ///
    /// Typical use is to bias clients toward a PQ-hybrid group
    /// (e.g. [`NamedGroup::X25519MlKem768`]) without giving up the
    /// freedom to negotiate non-PQ groups when the client truly cannot
    /// offer one.
    ///
    /// Inert on the client side and outside TLS 1.3.
    pub preferred_key_exchange_group: Option<NamedGroup>,

    // ---- Encrypted Client Hello (draft-ietf-tls-esni-22) ----
    /// Client-side ECH configuration. `None` (default) = no ECH and no
    /// GREASE — the CH carries no `encrypted_client_hello` extension at
    /// all. `Some(EchClient::default_grease())` emits a bit-shape
    /// identical GREASE extension so the wire image is constant across
    /// users. `Some(EchClient::from_config_list(list))` will, in a
    /// follow-up, actually seal the inner CH against the published
    /// `ECHConfigList` — for now this is stored but treated as GREASE
    /// at the wire layer.
    #[cfg(feature = "ech")]
    pub ech: Option<super::ech::EchClient>,
    /// Server-side ECH configuration. `None` (default) = no ECH. When
    /// set, in a follow-up the server will attempt HPKE-decap on the
    /// outer-CH `encrypted_client_hello` extension and, on success,
    /// continue the handshake against the decrypted inner CH; on
    /// failure it completes the outer handshake and emits
    /// `retry_configs` in `EncryptedExtensions`.
    #[cfg(feature = "ech")]
    pub ech_server: Option<super::ech::EchServer>,

    // ---- RFC 8879 certificate compression (TLS 1.3 only) ----
    /// IANA `CertificateCompressionAlgorithm` codepoints the endpoint
    /// will advertise in the `compress_certificate` extension and is
    /// itself willing to DECOMPRESS, in preference order. Only `1` (zlib)
    /// is wired today; entries for unsupported algorithms (`2 = brotli`,
    /// `3 = zstd`) are allowed on the advertisement but ignored when
    /// selecting on the receive path. Empty `Vec` disables the
    /// extension entirely on the wire — neither advertise nor accept.
    /// The default is `[1]` (advertise zlib). Applies bidirectionally:
    /// clients advertise in their `ClientHello` (covering the server's
    /// `Certificate`), servers advertise in `CertificateRequest`
    /// (covering the client's mTLS `Certificate`).
    #[cfg(feature = "cert-compression")]
    pub cert_compression_algorithms: Vec<u16>,

    // ---- DTLS-only (inert when version is TLS) ----
    /// 32-byte secret for stateless cookie issuance / validation. `None` on
    /// the DTLS server = cookie exchange is skipped (test-only).
    pub cookie_secret: Option<[u8; 32]>,
    /// When `true`, the DTLS server mandates a cookie round-trip before
    /// allocating per-connection state. Default `true` on server, ignored
    /// on client. **Setting this to `false` turns the server into a >3x
    /// traffic amplifier toward spoofed source addresses** — see
    /// [`ConfigBuilder::no_cookie`] for the full warning; tests only.
    pub require_cookie: bool,
    /// Target MTU for emitted DTLS records (default ~1200).
    pub max_record_size: usize,

    // ---- Observability ----
    /// Optional sink receiving every traffic / master secret as it is
    /// derived (NSS `SSLKEYLOGFILE` format). When `None`, secrets stay
    /// internal to the engine. Used to feed Wireshark / NSS-format key
    /// logs.
    pub key_log: Option<Arc<dyn KeyLog>>,

    /// Optional entropy source for all randomness this endpoint draws (server
    /// random, ephemeral (EC)DHE / ML-KEM key shares, RSA-PSS salts, ML-DSA
    /// hedging, session-ticket nonces). `None` (the default) uses the platform
    /// [`OsRng`](crate::rng::OsRng). Supply an [`EntropySource`] to route
    /// entropy through a hardware device (TPM/HSM). Shared (`Arc`) across every
    /// connection built from this `Config`.
    pub rng: Option<Arc<dyn EntropySource>>,

    /// Transparent pluggable private key (TPM/HSM or in-process), installed via
    /// [`ConfigBuilder::private_key`]. When set, the identity signature is
    /// brokered through this key during [`super::Connection::drive`] and the
    /// caller never hand-manages the signature. `std` only (the key may own a
    /// device file descriptor). See [`super::PrivateKey`].
    #[cfg(feature = "std")]
    pub signer: Option<Arc<dyn super::signer::PrivateKey>>,
}

/// A caller-supplied entropy source (e.g. a TPM/HSM RNG), installed via
/// [`Config::rng`].
///
/// Implementations MUST be cryptographically secure — the bytes seed keys,
/// nonces, and signature salts. `fill` takes `&self` (not `&mut self`) so one
/// source can be shared across connections behind an `Arc`; the implementation
/// owns any interior synchronization. It must fill the whole buffer or abort:
/// there is no short-read or error return, matching [`OsRng`](crate::rng::OsRng).
pub trait EntropySource: Send + Sync {
    /// Fills `dest` entirely with cryptographically secure random bytes.
    fn fill(&self, dest: &mut [u8]);
}

impl Default for Config {
    fn default() -> Self {
        Config {
            min_version: ProtocolVersion::TLSv1_2,
            max_version: ProtocolVersion::TLSv1_3,
            identity: None,
            roots: RootCertStore::new(),
            crls: CrlStore::new(),
            signature_policy: SignaturePolicy::modern(),
            server_name: None,
            verify_certificates: true,
            verification_time: None,
            client_auth: None,
            stapled_crl: None,
            stapled_ocsp_response: None,
            ticket_key: None,
            max_early_data_size: 0,
            #[cfg(feature = "std")]
            replay_window: None,
            alpn_protocols: Vec::new(),
            cipher_suites: None,
            record_size_limit: None,
            require_extended_master_secret: true,
            server_cert_type_preference: alloc::vec![0u8], // X.509 only.
            client_cert_type_preference: alloc::vec![0u8],
            raw_public_key_spki: None,
            expected_raw_public_keys: Vec::new(),
            preferred_key_exchange_group: None,
            #[cfg(feature = "ech")]
            ech: None,
            #[cfg(feature = "ech")]
            ech_server: None,
            #[cfg(feature = "cert-compression")]
            cert_compression_algorithms: super::cert_compression::default_algorithms(),
            cookie_secret: None,
            require_cookie: true,
            max_record_size: 1200,
            key_log: None,
            rng: None,
            #[cfg(feature = "std")]
            signer: None,
        }
    }
}

impl Config {
    /// A fresh builder for [`Config`].
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder {
            inner: Config::default(),
        }
    }

    /// True if this configuration's version range is DTLS.
    pub fn is_dtls(&self) -> bool {
        matches!(
            self.max_version,
            ProtocolVersion::DTLSv1_0 | ProtocolVersion::DTLSv1_2 | ProtocolVersion::DTLSv1_3
        )
    }

    /// Validate that the version range is internally consistent (min ≤ max,
    /// same TLS/DTLS family).
    pub(crate) fn check_versions(&self) -> Result<(), super::Error> {
        let min_dtls = is_dtls(self.min_version);
        let max_dtls = is_dtls(self.max_version);
        if min_dtls != max_dtls {
            return Err(super::Error::InappropriateState);
        }
        if version_rank(self.min_version) > version_rank(self.max_version) {
            return Err(super::Error::InappropriateState);
        }
        Ok(())
    }
}

fn is_dtls(v: ProtocolVersion) -> bool {
    matches!(
        v,
        ProtocolVersion::DTLSv1_0 | ProtocolVersion::DTLSv1_2 | ProtocolVersion::DTLSv1_3
    )
}

/// Rank of a [`ProtocolVersion`] for the min/max ordering. Higher is more
/// recent.
fn version_rank(v: ProtocolVersion) -> u8 {
    match v {
        ProtocolVersion::SSLv3 => 1,
        ProtocolVersion::TLSv1_0 => 2,
        ProtocolVersion::TLSv1_1 => 3,
        ProtocolVersion::TLSv1_2 => 4,
        ProtocolVersion::TLSv1_3 => 5,
        ProtocolVersion::DTLSv1_0 => 2,
        ProtocolVersion::DTLSv1_2 => 4,
        ProtocolVersion::DTLSv1_3 => 5,
        ProtocolVersion::Unknown(_) => 0,
    }
}

/// Fluent builder for [`Config`].
pub struct ConfigBuilder {
    inner: Config,
}

impl ConfigBuilder {
    /// Lowest version this endpoint will negotiate.
    pub fn min_version(mut self, v: ProtocolVersion) -> Self {
        self.inner.min_version = v;
        self
    }
    /// Highest version this endpoint will negotiate.
    pub fn max_version(mut self, v: ProtocolVersion) -> Self {
        self.inner.max_version = v;
        self
    }
    /// Lowest + highest in one call.
    pub fn versions(mut self, min: ProtocolVersion, max: ProtocolVersion) -> Self {
        self.inner.min_version = min;
        self.inner.max_version = max;
        self
    }
    /// Shorthand: bind both ends to a DTLS range (1.2..=1.3).
    pub fn dtls(mut self) -> Self {
        self.inner.min_version = ProtocolVersion::DTLSv1_2;
        self.inner.max_version = ProtocolVersion::DTLSv1_3;
        self
    }
    /// Shorthand: bind both ends to a TLS range (1.2..=1.3).
    pub fn tls_only(mut self) -> Self {
        self.inner.min_version = ProtocolVersion::TLSv1_2;
        self.inner.max_version = ProtocolVersion::TLSv1_3;
        self
    }
    /// Routes all of this endpoint's randomness through `source` (e.g. a
    /// TPM/HSM RNG) instead of the platform [`OsRng`](crate::rng::OsRng). See
    /// [`Config::rng`] / [`EntropySource`].
    pub fn rng(mut self, source: Arc<dyn EntropySource>) -> Self {
        self.inner.rng = Some(source);
        self
    }
    /// Install a cert chain + signing key.
    pub fn identity(mut self, chain: Vec<Vec<u8>>, key: SigningKey) -> Self {
        self.inner.identity = Some(Identity {
            cert_chain: chain,
            key,
        });
        self
    }
    /// Install a cert chain + a transparent pluggable [`PrivateKey`](super::PrivateKey)
    /// (TPM/HSM or in-process via [`LocalSigner`](super::LocalSigner)).
    ///
    /// The engine advertises `key.schemes()` and parks at the identity
    /// signature; [`super::Connection::drive`] then brokers the signature
    /// through `key` so the caller never hand-manages it. `std` only.
    #[cfg(feature = "std")]
    pub fn private_key(
        mut self,
        chain: Vec<Vec<u8>>,
        key: Arc<dyn super::signer::PrivateKey>,
    ) -> Self {
        self.inner.identity = Some(Identity {
            cert_chain: chain,
            key: SigningKey::External {
                schemes: key.schemes(),
            },
        });
        self.inner.signer = Some(key);
        self
    }
    /// Replace the trust anchors.
    pub fn roots(mut self, store: RootCertStore) -> Self {
        self.inner.roots = store;
        self
    }
    /// Set the SNI hostname offered by a client and verified in the peer
    /// leaf certificate.
    pub fn server_name(mut self, sni: impl Into<String>) -> Self {
        self.inner.server_name = Some(sni.into());
        self
    }
    /// ALPN protocols. Client: preferences. Server: accepted set in
    /// preference order.
    pub fn alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.inner.alpn_protocols = protocols;
        self
    }
    /// Restrict (and order) the client's offered cipher suites to the given
    /// IANA wire IDs — the seam for curl `--ciphers` / `--tls13-ciphers`. Only
    /// suites the engine also supports are offered, in this order; an empty
    /// intersection fails closed at construction with
    /// [`Error::NoUsableCipherSuites`](crate::tls::Error::NoUsableCipherSuites).
    /// See [`Config::cipher_suites`].
    pub fn cipher_suites(mut self, suites: &[u16]) -> Self {
        self.inner.cipher_suites = Some(suites.to_vec());
        self
    }
    /// Enable or disable peer-certificate chain validation.
    pub fn verify_certificates(mut self, v: bool) -> Self {
        self.inner.verify_certificates = v;
        self
    }
    /// Replace the signature-algorithm policy.
    pub fn signature_policy(mut self, p: SignaturePolicy) -> Self {
        self.inner.signature_policy = p;
        self
    }
    /// Install a CRL store consulted during chain validation.
    pub fn crls(mut self, store: CrlStore) -> Self {
        self.inner.crls = store;
        self
    }
    /// Set the client-authentication policy (server side).
    pub fn client_auth(mut self, auth: ClientAuth) -> Self {
        self.inner.client_auth = Some(auth);
        self
    }
    /// DTLS server: long-lived 32-byte cookie secret.
    pub fn cookie_secret(mut self, secret: [u8; 32]) -> Self {
        self.inner.cookie_secret = Some(secret);
        self.inner.require_cookie = true;
        self
    }
    /// DTLS server: disable the cookie exchange (tests only).
    ///
    /// # Warning: amplification / DoS vector
    ///
    /// With the cookie exchange off, a single ClientHello from a spoofed
    /// source address makes the server allocate per-connection state,
    /// perform an asymmetric signature, and emit its full multi-KB
    /// certificate flight to an unverified address — well over 3x
    /// amplification toward a victim of the attacker's choosing
    /// (RFC 6347 §4.2.1 / RFC 9147 §5.1). Never disable cookies on a
    /// server reachable from untrusted networks; production servers
    /// should call [`Self::cookie_secret`] instead.
    pub fn no_cookie(mut self) -> Self {
        self.inner.require_cookie = false;
        self
    }
    /// DTLS: target MTU for emitted records.
    pub fn max_record_size(mut self, n: usize) -> Self {
        self.inner.max_record_size = n;
        self
    }
    /// TLS 1.3 server: DER bytes of a CRL to staple to the leaf cert.
    pub fn stapled_crl(mut self, der: Vec<u8>) -> Self {
        self.inner.stapled_crl = Some(der);
        self
    }
    /// TLS 1.2 / 1.3 server: DER bytes of an OCSP response to staple to
    /// the leaf cert (RFC 6066 §8). The server only emits it when the
    /// client opted in by sending `status_request` in its ClientHello.
    pub fn stapled_ocsp_response(mut self, der: Vec<u8>) -> Self {
        self.inner.stapled_ocsp_response = Some(der);
        self
    }
    /// TLS 1.2 / 1.3 server: session-ticket / NewSessionTicket key.
    pub fn ticket_key(mut self, key: [u8; 32]) -> Self {
        self.inner.ticket_key = Some(key);
        self
    }
    /// TLS 1.3 server: 0-RTT max early data size.
    ///
    /// 0-RTT data is replayable. The server enforces the RFC 8446 §8.2
    /// ticket-age freshness window (~10 s), which bounds the replay
    /// exposure in time but does not detect replays inside that window —
    /// pair this knob with [`Self::replay_window`] (shared across all
    /// instances accepting the same ticket key) when early data triggers
    /// non-idempotent actions. Without a wall clock (`no_std`) the
    /// freshness check is skipped and the replay window is the only
    /// anti-replay protection.
    pub fn max_early_data(mut self, max: u32) -> Self {
        self.inner.max_early_data_size = max;
        self
    }
    /// TLS 1.3 server: shared anti-replay set for 0-RTT.
    #[cfg(feature = "std")]
    pub fn replay_window(mut self, window: ReplayWindow) -> Self {
        self.inner.replay_window = Some(window);
        self
    }
    /// `record_size_limit` (RFC 8449) advertised on the wire.
    pub fn record_size_limit(mut self, n: u16) -> Self {
        self.inner.record_size_limit = Some(n);
        self
    }
    /// RFC 7627 §5.3 — require the TLS 1.2 peer to negotiate Extended
    /// Master Secret. Default is `true`; flip to `false` only to
    /// interoperate with peers that predate RFC 7627 (most modern
    /// stacks already mandate EMS).
    pub fn require_extended_master_secret(mut self, required: bool) -> Self {
        self.inner.require_extended_master_secret = required;
        self
    }
    /// Sets the `server_certificate_type` preference list (RFC 7250). On the
    /// client side this is the ordered list offered; on the server it is the
    /// accept-set. Values: `0 = X509` (the default), `2 = RawPublicKey`.
    /// Empty lists are silently coerced to `[0]`. To switch a server to
    /// raw public keys, combine with [`raw_public_key_spki`](Self::raw_public_key_spki).
    pub fn server_cert_type_preference(mut self, prefs: Vec<u8>) -> Self {
        self.inner.server_cert_type_preference = if prefs.is_empty() {
            alloc::vec![0u8]
        } else {
            prefs
        };
        self
    }
    /// Sets the `client_certificate_type` preference list (RFC 7250) for
    /// mTLS scenarios. Same semantics as
    /// [`server_cert_type_preference`](Self::server_cert_type_preference).
    pub fn client_cert_type_preference(mut self, prefs: Vec<u8>) -> Self {
        self.inner.client_cert_type_preference = if prefs.is_empty() {
            alloc::vec![0u8]
        } else {
            prefs
        };
        self
    }
    /// Server: sets the bare `SubjectPublicKeyInfo` DER to send as the
    /// `CertificateEntry` body when `RawPublicKey` is the negotiated
    /// server-cert type (RFC 7250 §4.2). Combine with
    /// `server_cert_type_preference([2])` (or `[2, 0]` for a hybrid) and an
    /// [`identity`](Self::identity) whose signing key matches this SPKI.
    pub fn raw_public_key_spki(mut self, spki_der: Vec<u8>) -> Self {
        self.inner.raw_public_key_spki = Some(spki_der);
        self
    }
    /// Client: appends an accepted bare `SubjectPublicKeyInfo` DER to the
    /// allowlist (RFC 7250 §4.2). When `RawPublicKey` is negotiated, the
    /// server's CertificateEntry body must constant-time match one of these
    /// entries. There is no PKI fallback under RawPublicKey, so this list
    /// is the entire trust root.
    pub fn add_expected_raw_public_key(mut self, spki_der: Vec<u8>) -> Self {
        self.inner.expected_raw_public_keys.push(spki_der);
        self
    }
    /// Verification clock (use this on `no_std` targets or for reproducible
    /// verification).
    pub fn verification_time(mut self, t: Time) -> Self {
        self.inner.verification_time = Some(t);
        self
    }

    /// Server: prefer this (EC)DHE group when the client advertises it
    /// in `supported_groups` but did not pre-share a key for it. The
    /// server emits a HelloRetryRequest (RFC 8446 §4.1.4) asking the
    /// client to retry with a share for `group`. When the preferred
    /// group is not in the client's `supported_groups`, the server
    /// falls back silently to its normal first-match selection.
    ///
    /// Example: prefer the PQ-hybrid `X25519MLKEM768` but accept
    /// classic groups when the client is unable to offer it.
    ///
    /// Inert on the client side and outside TLS 1.3.
    pub fn preferred_key_exchange_group(mut self, group: NamedGroup) -> Self {
        self.inner.preferred_key_exchange_group = Some(group);
        self
    }

    /// Client: install an Encrypted Client Hello configuration
    /// (draft-ietf-tls-esni-22). Pass [`super::ech::EchClient::default_grease`]
    /// for GREASE — a wire-shape-identical `encrypted_client_hello`
    /// that hides whether the client speaks ECH from passive
    /// observers. Pass
    /// [`super::ech::EchClient::from_config_list`] to seal against a
    /// published `ECHConfigList`. The full real-ECH client lands in a
    /// follow-up commit; for now this stores the choice and emits
    /// GREASE on the wire either way.
    #[cfg(feature = "ech")]
    pub fn ech(mut self, ech: super::ech::EchClient) -> Self {
        self.inner.ech = Some(ech);
        self
    }
    /// Server: install Encrypted Client Hello key material
    /// (draft-ietf-tls-esni-22) — the active key ring and the
    /// `retry_configs` list to ship on rejection. Stored now; the
    /// outer-CH HPKE decap + inner-CH dispatch + retry_configs
    /// emission land in a follow-up under the same Phase 5 banner.
    #[cfg(feature = "ech")]
    pub fn ech_server(mut self, ech: super::ech::EchServer) -> Self {
        self.inner.ech_server = Some(ech);
        self
    }

    /// Sets the `compress_certificate` (RFC 8879) advertisement —
    /// `CertificateCompressionAlgorithm` IDs the endpoint can decompress,
    /// in preference order. The default is `[1]` (zlib only). Pass an
    /// empty `Vec` to turn the extension off entirely (no advertisement;
    /// `CompressedCertificate` replies are also refused). Only zlib is
    /// implemented today; entries for brotli (`2`) or zstd (`3`) are
    /// allowed on the wire but ignored when selecting.
    #[cfg(feature = "cert-compression")]
    pub fn cert_compression_algorithms(mut self, algorithms: Vec<u16>) -> Self {
        self.inner.cert_compression_algorithms = algorithms;
        self
    }

    /// Registers a [`KeyLog`] sink that receives every traffic / master
    /// secret as the engine derives it. The format is NSS
    /// `SSLKEYLOGFILE`. Use [`super::WriterKeyLog`] for a ready-made
    /// implementation over any `std::io::Write`.
    pub fn key_log(mut self, sink: Arc<dyn KeyLog>) -> Self {
        self.inner.key_log = Some(sink);
        self
    }

    /// Finalise the configuration.
    pub fn build(self) -> Config {
        self.inner
    }
}

// ---- Internal conversions ----------------------------------------------------

impl SigningKey {
    /// Construct a per-(version, role) [`super::conn::ServerKey`] from this
    /// signing key (TLS 1.3 server).
    pub(crate) fn to_server_key_13(&self) -> super::conn::ServerKey {
        match self {
            SigningKey::Rsa(k) => super::conn::ServerKey::Rsa(k.clone()),
            SigningKey::Ecdsa(k) => super::conn::ServerKey::Ecdsa(k.clone()),
            SigningKey::Ed25519(k) => super::conn::ServerKey::Ed25519(k.clone()),
            SigningKey::Ed448(k) => super::conn::ServerKey::Ed448(k.clone()),
            SigningKey::MlDsa44(k) => super::conn::ServerKey::MlDsa44(k.clone()),
            SigningKey::MlDsa65(k) => super::conn::ServerKey::MlDsa65(k.clone()),
            SigningKey::MlDsa87(k) => super::conn::ServerKey::MlDsa87(k.clone()),
            SigningKey::External { schemes } => super::conn::ServerKey::External {
                schemes: schemes
                    .iter()
                    .map(|&s| super::codec::SignatureScheme(s))
                    .collect(),
            },
        }
    }

    /// Construct a TLS 1.2 server config from this key + chain.
    /// Returns `None` for keys TLS 1.2 doesn't support (Ed25519, ML-DSA).
    pub(crate) fn try_into_server_config_12(
        &self,
        chain: Vec<Vec<u8>>,
    ) -> Option<super::conn::ServerConfig12> {
        match self {
            SigningKey::Rsa(k) => Some(super::conn::ServerConfig12::with_rsa(chain, k.clone())),
            SigningKey::Ecdsa(k) => Some(super::conn::ServerConfig12::with_ecdsa(chain, k.clone())),
            _ => None,
        }
    }
}
