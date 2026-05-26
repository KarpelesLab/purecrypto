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

use crate::ec::{BoxedEcdsaPrivateKey, Ed25519PrivateKey};
use crate::rsa::BoxedRsaPrivateKey;
use crate::signature_registry::SignaturePolicy;

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
/// [`pub type ServerKey = SigningKey;`](super::ServerKey) alias for one
/// release.
///
/// The PQ variants (`MlDsa*`) carry their full key material inline. Since
/// this enum is held once per [`Config`] (effectively per endpoint), the
/// variant-size disparity flagged by `clippy::large_enum_variant` is a
/// non-issue.
#[allow(clippy::large_enum_variant)]
pub enum SigningKey {
    /// RSA key; signs with `rsa_pss_rsae_sha256`.
    Rsa(BoxedRsaPrivateKey),
    /// ECDSA key; the scheme is chosen from the curve at sign time.
    Ecdsa(BoxedEcdsaPrivateKey),
    /// Ed25519 key.
    Ed25519(Ed25519PrivateKey),
    /// ML-DSA-44 (FIPS 204, draft-ietf-tls-mldsa).
    MlDsa44(crate::mldsa::MlDsa44PrivateKey),
    /// ML-DSA-65.
    MlDsa65(crate::mldsa::MlDsa65PrivateKey),
    /// ML-DSA-87.
    MlDsa87(crate::mldsa::MlDsa87PrivateKey),
}

/// A certificate chain (leaf first) paired with its signing key.
pub struct Identity {
    /// DER-encoded certificate chain, leaf first.
    pub cert_chain: Vec<Vec<u8>>,
    /// Signing key matching the leaf certificate.
    pub key: SigningKey,
}

/// Client-authentication policy for a server (mTLS).
pub struct ClientAuth {
    /// Trust anchors for verifying the peer's chain.
    pub roots: RootCertStore,
    /// When `true`, no-cert clients are rejected with `certificate_required`
    /// (RFC 8446 §4.3.2). When `false`, anonymous clients are allowed.
    pub required: bool,
}

/// Unified configuration for a TLS or DTLS endpoint, client or server.
///
/// Fields are arranged in five blocks: protocol versions, identity / trust
/// anchors / signing-algorithm policy, client-side knobs, server-side
/// knobs, and DTLS-specific knobs (inert when the negotiated version is
/// TLS).
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
    /// Clock used for cert validity. `None` = system clock under `std`.
    pub verification_time: Option<Time>,

    // ---- Server-side ----
    /// Client-authentication policy. `None` = no client auth.
    pub client_auth: Option<ClientAuth>,
    /// DER bytes of a CRL to staple in the TLS 1.3 `Certificate` message
    /// (TLS 1.2 has no per-cert extension slot).
    pub stapled_crl: Option<Vec<u8>>,
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
    /// `record_size_limit` extension (RFC 8449). `None` = library default.
    pub record_size_limit: Option<u16>,

    // ---- DTLS-only (inert when version is TLS) ----
    /// 32-byte secret for stateless cookie issuance / validation. `None` on
    /// the DTLS server = cookie exchange is skipped (test-only).
    pub cookie_secret: Option<[u8; 32]>,
    /// When `true`, the DTLS server mandates a cookie round-trip before
    /// allocating per-connection state. Default `true` on server, ignored
    /// on client.
    pub require_cookie: bool,
    /// Target MTU for emitted DTLS records (default ~1200).
    pub max_record_size: usize,

    // ---- Observability ----
    /// Optional sink receiving every traffic / master secret as it is
    /// derived (NSS `SSLKEYLOGFILE` format). When `None`, secrets stay
    /// internal to the engine. Used to feed Wireshark / NSS-format key
    /// logs.
    pub key_log: Option<Arc<dyn KeyLog>>,
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
            ticket_key: None,
            max_early_data_size: 0,
            #[cfg(feature = "std")]
            replay_window: None,
            alpn_protocols: Vec::new(),
            record_size_limit: None,
            cookie_secret: None,
            require_cookie: true,
            max_record_size: 1200,
            key_log: None,
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
    /// Install a cert chain + signing key.
    pub fn identity(mut self, chain: Vec<Vec<u8>>, key: SigningKey) -> Self {
        self.inner.identity = Some(Identity {
            cert_chain: chain,
            key,
        });
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
    /// TLS 1.2 / 1.3 server: session-ticket / NewSessionTicket key.
    pub fn ticket_key(mut self, key: [u8; 32]) -> Self {
        self.inner.ticket_key = Some(key);
        self
    }
    /// TLS 1.3 server: 0-RTT max early data size.
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
    /// Verification clock (use this on `no_std` targets or for reproducible
    /// verification).
    pub fn verification_time(mut self, t: Time) -> Self {
        self.inner.verification_time = Some(t);
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
            SigningKey::MlDsa44(k) => super::conn::ServerKey::MlDsa44(k.clone()),
            SigningKey::MlDsa65(k) => super::conn::ServerKey::MlDsa65(k.clone()),
            SigningKey::MlDsa87(k) => super::conn::ServerKey::MlDsa87(k.clone()),
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
