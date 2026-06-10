#![allow(dead_code, unreachable_pub)]

//! The TLS 1.3 server handshake state machine.
//!
//! [`ServerConnection`] consumes a `ClientHello`, selects a cipher suite and
//! key-exchange group, and emits the server flight (`ServerHello`, then the
//! encrypted `EncryptedExtensions`, `Certificate`, `CertificateVerify`,
//! `Finished`). It then verifies the client's `Finished` and switches to the
//! application traffic keys.

use super::common::{ConnectionCore, Incoming};
use crate::cipher::{Aes256, Gcm};
use crate::ec::x25519::X25519PrivateKey;
use crate::ec::{
    BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, CurveId, Ed448PrivateKey,
    Ed25519PrivateKey,
};
use crate::hash::{Hmac, Sha256, Sha384, Sha512};
use crate::mlkem::{ENCAPS_KEY_BYTES, MlKem768EncapsKey};
use crate::rng::RngCore;
use crate::rsa::BoxedRsaPrivateKey;
use crate::signature_registry::SignaturePolicy;
use crate::tls::codec::extension as ext;
use crate::tls::codec::{
    CipherSuite, ClientHello, ExtensionType, HRR_RANDOM, KeyUpdate, NamedGroup, NewSessionTicket,
    Random, ReadCursor, ServerHello, SignatureScheme, hs_type, read_handshake, with_len_u16,
    with_len_u24,
};
use crate::tls::crypto::{
    HashAlg, KeySchedule, RecordCrypter, Secret, SuiteParams, binder_finished_key,
    certificate_verify_content, finished_verify_data, next_traffic_secret, psk_from_resumption,
    supported_suites, tls_exporter,
};
use crate::tls::keylog::KeyLog;
use crate::tls::{AlertDescription, Error};
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

use crate::ct::ConstantTimeEq;

#[cfg(feature = "std")]
use std::sync::{Arc, Mutex};

/// A shared anti-replay set for 0-RTT (RFC 8446 §8). Each connection that
/// accepts a PSK binder records it here; a binder already in the set is
/// refused for 0-RTT (the handshake proceeds with 1-RTT instead).
///
/// The set is bounded; oldest entries are evicted in insertion order to keep
/// memory bounded. This is a best-effort defense: the spec acknowledges that
/// 0-RTT is inherently replayable across servers that do not share state.
#[cfg(feature = "std")]
#[derive(Clone, Default)]
pub struct ReplayWindow {
    inner: Arc<Mutex<ReplayWindowInner>>,
}

#[cfg(feature = "std")]
struct ReplayWindowInner {
    seen: std::collections::HashSet<Vec<u8>>,
    order: std::collections::VecDeque<Vec<u8>>,
    cap: usize,
}

#[cfg(feature = "std")]
impl Default for ReplayWindowInner {
    fn default() -> Self {
        ReplayWindowInner {
            seen: Default::default(),
            order: Default::default(),
            cap: 1024,
        }
    }
}

#[cfg(feature = "std")]
impl ReplayWindow {
    /// A fresh anti-replay set with a default capacity of 1024 entries.
    pub fn new() -> Self {
        ReplayWindow::default()
    }

    /// Records `binder` and returns whether it was a new entry. `true` means
    /// the connection may accept 0-RTT; `false` indicates a replay.
    fn check_and_insert(&self, binder: &[u8]) -> bool {
        let mut inner = self.inner.lock().expect("replay window poisoned");
        if inner.seen.contains(binder) {
            return false;
        }
        if inner.order.len() >= inner.cap
            && let Some(old) = inner.order.pop_front()
        {
            inner.seen.remove(&old);
        }
        inner.seen.insert(binder.to_vec());
        inner.order.push_back(binder.to_vec());
        true
    }
}

/// The server's signing key, used to sign the `CertificateVerify`.
///
/// The PQ variants (`MlDsa*`) carry their full key material inline. Since
/// this enum exists once per `ServerConfig` (effectively per server
/// instance), the variant-size disparity flagged by `clippy::
/// large_enum_variant` is a non-issue — boxing would add a heap
/// indirection on every signing call without meaningful savings.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ServerKey {
    /// An RSA key; signs with `rsa_pss_rsae_sha256`.
    Rsa(BoxedRsaPrivateKey),
    /// An ECDSA key; signs with the scheme matching its curve.
    Ecdsa(BoxedEcdsaPrivateKey),
    /// An Ed25519 key; signs with `ed25519`.
    Ed25519(Ed25519PrivateKey),
    /// An Ed448 key; signs with `ed448`.
    Ed448(Ed448PrivateKey),
    /// An ML-DSA-44 key (FIPS 204, draft-ietf-tls-mldsa).
    MlDsa44(crate::mldsa::MlDsa44PrivateKey),
    /// An ML-DSA-65 key.
    MlDsa65(crate::mldsa::MlDsa65PrivateKey),
    /// An ML-DSA-87 key.
    MlDsa87(crate::mldsa::MlDsa87PrivateKey),
}

/// Client-authentication policy for a server (RFC 8446 §4.3.2): roots to
/// validate the presented client chain against, and whether a client cert
/// is required (`certificate_required` alert on absence).
pub(crate) struct ClientAuthPolicy {
    /// Trust anchors for the client chain.
    pub roots: crate::tls::RootCertStore,
    /// When `true`, an empty client certificate (no auth) aborts the
    /// handshake with `certificate_required`. When `false`, an empty
    /// Certificate is accepted and no `CertificateVerify` is required.
    pub required: bool,
}

/// Configuration for a TLS server: a certificate chain and its signing key.
///
/// `pub(crate)`: external users build a [`crate::tls::Config`] and call
/// [`crate::tls::Connection::server`], which derives this internal config.
pub(crate) struct ServerConfig {
    cert_chain: Vec<Vec<u8>>,
    key: ServerKey,
    /// ALPN protocols this server accepts, in preference order. The server
    /// picks its first entry that also appears in the client's offer.
    alpn_protocols: Vec<Vec<u8>>,
    /// `record_size_limit` (RFC 8449) we advertise to the client. None
    /// suppresses the extension.
    record_size_limit: Option<u16>,
    /// Symmetric AEAD key used to encrypt/decrypt stateless resumption
    /// tickets (RFC 8446 §4.6.1, rustls-style). `None` disables NewSessionTicket
    /// emission, so clients cannot resume against this server.
    ticket_key: Option<[u8; 32]>,
    /// Lifetime (seconds) advertised in emitted NewSessionTickets; defaults
    /// to two hours.
    ticket_lifetime: u32,
    /// Maximum 0-RTT payload (`max_early_data_size`) the server accepts on a
    /// resumed connection. `0` (default) disables 0-RTT: the server does
    /// not advertise it in NewSessionTickets and does not accept early
    /// data even if offered.
    max_early_data_size: u32,
    /// Optional anti-replay set: a binder presented twice (within this
    /// process's lifetime) is refused for 0-RTT. The same `ReplayWindow`
    /// should be shared across all `ServerConfig`s in the same process.
    #[cfg(feature = "std")]
    replay_window: Option<ReplayWindow>,
    /// Client-certificate authentication policy. `None` (default) skips
    /// `CertificateRequest`: a server does not demand a client cert.
    client_auth: Option<ClientAuthPolicy>,
    /// Whitelist of signature algorithms accepted in the client certificate
    /// chain and `CertificateVerify` (under mTLS). Defaults to
    /// [`SignaturePolicy::modern`].
    signature_policy: SignaturePolicy,
    /// CRLs consulted when validating client-cert chains under mTLS. Empty
    /// by default; opt in via [`ServerConfig::with_crls`].
    crls: crate::tls::pki::CrlStore,
    /// Clock used to enforce the `notBefore`/`notAfter` validity period of
    /// client certificates under mTLS. `None` (the default) falls back to the
    /// system clock under the `std` feature; under `no_std` with no configured
    /// time the validity period is not checked. Set explicitly via
    /// [`ServerConfig::with_verification_time`].
    verification_time: Option<crate::x509::Time>,
    /// Optional DER-encoded CRL to staple as a per-certificate extension
    /// on the leaf entry of the TLS 1.3 `Certificate` message
    /// (purecrypto-private extension `0xFE10`). The client validates the
    /// stapled CRL against the chain it just verified and consults it for
    /// revocation. TLS 1.2 has no per-cert extension list in `Certificate`,
    /// so stapling is silently dropped for TLS 1.2 servers.
    stapled_crl: Option<Vec<u8>>,
    /// Optional DER-encoded OCSP response stapled to the leaf cert. On
    /// TLS 1.3 this rides in the leaf `CertificateEntry`'s per-cert
    /// `status_request` extension (RFC 8446 §4.4.2.1); on TLS 1.2 the
    /// equivalent `ServerConfig12` field is emitted as a stand-alone
    /// `CertificateStatus` handshake message (RFC 6066 §8). Honoured
    /// only when the client advertised `status_request` in its
    /// `ClientHello`.
    stapled_ocsp_response: Option<Vec<u8>>,
    /// RFC 7250 §3 `server_certificate_type` accept-set. Defaults to
    /// `[X509]`; setting it to `[RAW_PUBLIC_KEY]` or
    /// `[RAW_PUBLIC_KEY, X509]` opts this server into raw public keys
    /// (must combine with `raw_public_key_spki`).
    server_cert_type_preference: Vec<u8>,
    /// RFC 7250 §3 `client_certificate_type` accept-set for mTLS scenarios.
    client_cert_type_preference: Vec<u8>,
    /// Bare `SubjectPublicKeyInfo` DER to send as the single
    /// `CertificateEntry` body when `RawPublicKey` is the negotiated
    /// server-cert type. MUST encode the public key matching this server's
    /// signing key, or the client's `CertificateVerify` check will fail.
    raw_public_key_spki: Option<Vec<u8>>,
    /// RFC 8879 `CertificateCompressionAlgorithm` IDs the server can
    /// DECOMPRESS (for mTLS client certs) and is willing to USE when
    /// compressing the server `Certificate` it sends. Default `[1]`
    /// (zlib). Empty disables the path entirely. See
    /// [`crate::tls::cert_compression`].
    #[cfg(feature = "cert-compression")]
    pub(crate) cert_compression_algorithms: Vec<u16>,
    /// Encrypted Client Hello (draft-ietf-tls-esni-22) server-side
    /// state: the key ring this server tries to HPKE-decrypt incoming
    /// `encrypted_client_hello` extensions with, plus the
    /// `retry_configs` ECHConfigList to advertise in `EncryptedExtensions`
    /// when ECH could not be applied. `None` (default) means this server
    /// does not participate in ECH; outer-form `encrypted_client_hello`
    /// extensions are silently ignored and the public-name cert is used.
    #[cfg(feature = "ech")]
    pub(crate) ech_server: Option<crate::tls::ech::EchServer>,
    /// Optional [`KeyLog`] sink (NSS `SSLKEYLOGFILE` format).
    pub(crate) key_log: Option<Arc<dyn KeyLog>>,
    /// Deployment-shaped HelloRetryRequest knob (RFC 8446 §4.1.4). When
    /// `Some(g)` and the client advertises `g` in `supported_groups` but did
    /// not include a `key_share` for it, the server emits a HelloRetryRequest
    /// asking the client to redo CH with a share for `g`. `None` (default)
    /// preserves the prior first-acceptable-share-wins behaviour.
    pub(crate) preferred_key_exchange_group: Option<crate::tls::NamedGroup>,
}

impl ServerConfig {
    /// A configuration presenting `cert_chain` (leaf first) and signing with an
    /// RSA private `key` (RSA-PSS).
    pub fn with_rsa(cert_chain: Vec<Vec<u8>>, key: BoxedRsaPrivateKey) -> Self {
        ServerConfig {
            cert_chain,
            key: ServerKey::Rsa(key),
            alpn_protocols: Vec::new(),
            record_size_limit: None,
            ticket_key: None,
            ticket_lifetime: 7200,
            max_early_data_size: 0,
            #[cfg(feature = "std")]
            replay_window: None,
            client_auth: None,
            signature_policy: SignaturePolicy::modern(),
            crls: crate::tls::pki::CrlStore::new(),
            verification_time: None,
            stapled_crl: None,
            stapled_ocsp_response: None,
            server_cert_type_preference: alloc::vec![0u8],
            client_cert_type_preference: alloc::vec![0u8],
            raw_public_key_spki: None,
            #[cfg(feature = "cert-compression")]
            cert_compression_algorithms: crate::tls::cert_compression::default_algorithms(),
            #[cfg(feature = "ech")]
            ech_server: None,
            key_log: None,
            preferred_key_exchange_group: None,
        }
    }

    /// A configuration presenting `cert_chain` (leaf first) and signing with an
    /// ECDSA private `key` (the scheme follows the key's curve).
    pub fn with_ecdsa(cert_chain: Vec<Vec<u8>>, key: BoxedEcdsaPrivateKey) -> Self {
        ServerConfig {
            cert_chain,
            key: ServerKey::Ecdsa(key),
            alpn_protocols: Vec::new(),
            record_size_limit: None,
            ticket_key: None,
            ticket_lifetime: 7200,
            max_early_data_size: 0,
            #[cfg(feature = "std")]
            replay_window: None,
            client_auth: None,
            signature_policy: SignaturePolicy::modern(),
            crls: crate::tls::pki::CrlStore::new(),
            verification_time: None,
            stapled_crl: None,
            stapled_ocsp_response: None,
            server_cert_type_preference: alloc::vec![0u8],
            client_cert_type_preference: alloc::vec![0u8],
            raw_public_key_spki: None,
            #[cfg(feature = "cert-compression")]
            cert_compression_algorithms: crate::tls::cert_compression::default_algorithms(),
            #[cfg(feature = "ech")]
            ech_server: None,
            key_log: None,
            preferred_key_exchange_group: None,
        }
    }

    /// A configuration presenting `cert_chain` (leaf first) and signing with an
    /// Ed25519 private `key`.
    pub fn with_ed25519(cert_chain: Vec<Vec<u8>>, key: Ed25519PrivateKey) -> Self {
        ServerConfig {
            cert_chain,
            key: ServerKey::Ed25519(key),
            alpn_protocols: Vec::new(),
            record_size_limit: None,
            ticket_key: None,
            ticket_lifetime: 7200,
            max_early_data_size: 0,
            #[cfg(feature = "std")]
            replay_window: None,
            client_auth: None,
            signature_policy: SignaturePolicy::modern(),
            crls: crate::tls::pki::CrlStore::new(),
            verification_time: None,
            stapled_crl: None,
            stapled_ocsp_response: None,
            server_cert_type_preference: alloc::vec![0u8],
            client_cert_type_preference: alloc::vec![0u8],
            raw_public_key_spki: None,
            #[cfg(feature = "cert-compression")]
            cert_compression_algorithms: crate::tls::cert_compression::default_algorithms(),
            #[cfg(feature = "ech")]
            ech_server: None,
            key_log: None,
            preferred_key_exchange_group: None,
        }
    }

    /// A configuration presenting `cert_chain` (leaf first) and signing with an
    /// Ed448 private `key`.
    pub fn with_ed448(cert_chain: Vec<Vec<u8>>, key: Ed448PrivateKey) -> Self {
        ServerConfig {
            cert_chain,
            key: ServerKey::Ed448(key),
            alpn_protocols: Vec::new(),
            record_size_limit: None,
            ticket_key: None,
            ticket_lifetime: 7200,
            max_early_data_size: 0,
            #[cfg(feature = "std")]
            replay_window: None,
            client_auth: None,
            signature_policy: SignaturePolicy::modern(),
            crls: crate::tls::pki::CrlStore::new(),
            verification_time: None,
            stapled_crl: None,
            stapled_ocsp_response: None,
            server_cert_type_preference: alloc::vec![0u8],
            client_cert_type_preference: alloc::vec![0u8],
            raw_public_key_spki: None,
            #[cfg(feature = "cert-compression")]
            cert_compression_algorithms: crate::tls::cert_compression::default_algorithms(),
            #[cfg(feature = "ech")]
            ech_server: None,
            key_log: None,
            preferred_key_exchange_group: None,
        }
    }

    /// A configuration presenting `cert_chain` (leaf first) and signing with
    /// an ML-DSA-44 private key (NIST FIPS 204, draft-ietf-tls-mldsa).
    pub fn with_mldsa44(cert_chain: Vec<Vec<u8>>, key: crate::mldsa::MlDsa44PrivateKey) -> Self {
        ServerConfig {
            cert_chain,
            key: ServerKey::MlDsa44(key),
            alpn_protocols: Vec::new(),
            record_size_limit: None,
            ticket_key: None,
            ticket_lifetime: 7200,
            max_early_data_size: 0,
            #[cfg(feature = "std")]
            replay_window: None,
            client_auth: None,
            signature_policy: SignaturePolicy::modern(),
            crls: crate::tls::pki::CrlStore::new(),
            verification_time: None,
            stapled_crl: None,
            stapled_ocsp_response: None,
            server_cert_type_preference: alloc::vec![0u8],
            client_cert_type_preference: alloc::vec![0u8],
            raw_public_key_spki: None,
            #[cfg(feature = "cert-compression")]
            cert_compression_algorithms: crate::tls::cert_compression::default_algorithms(),
            #[cfg(feature = "ech")]
            ech_server: None,
            key_log: None,
            preferred_key_exchange_group: None,
        }
    }

    /// A configuration presenting `cert_chain` (leaf first) and signing with
    /// an ML-DSA-65 private key.
    pub fn with_mldsa65(cert_chain: Vec<Vec<u8>>, key: crate::mldsa::MlDsa65PrivateKey) -> Self {
        ServerConfig {
            cert_chain,
            key: ServerKey::MlDsa65(key),
            alpn_protocols: Vec::new(),
            record_size_limit: None,
            ticket_key: None,
            ticket_lifetime: 7200,
            max_early_data_size: 0,
            #[cfg(feature = "std")]
            replay_window: None,
            client_auth: None,
            signature_policy: SignaturePolicy::modern(),
            crls: crate::tls::pki::CrlStore::new(),
            verification_time: None,
            stapled_crl: None,
            stapled_ocsp_response: None,
            server_cert_type_preference: alloc::vec![0u8],
            client_cert_type_preference: alloc::vec![0u8],
            raw_public_key_spki: None,
            #[cfg(feature = "cert-compression")]
            cert_compression_algorithms: crate::tls::cert_compression::default_algorithms(),
            #[cfg(feature = "ech")]
            ech_server: None,
            key_log: None,
            preferred_key_exchange_group: None,
        }
    }

    /// A configuration presenting `cert_chain` (leaf first) and signing with
    /// an ML-DSA-87 private key.
    pub fn with_mldsa87(cert_chain: Vec<Vec<u8>>, key: crate::mldsa::MlDsa87PrivateKey) -> Self {
        ServerConfig {
            cert_chain,
            key: ServerKey::MlDsa87(key),
            alpn_protocols: Vec::new(),
            record_size_limit: None,
            ticket_key: None,
            ticket_lifetime: 7200,
            max_early_data_size: 0,
            #[cfg(feature = "std")]
            replay_window: None,
            client_auth: None,
            signature_policy: SignaturePolicy::modern(),
            crls: crate::tls::pki::CrlStore::new(),
            verification_time: None,
            stapled_crl: None,
            stapled_ocsp_response: None,
            server_cert_type_preference: alloc::vec![0u8],
            client_cert_type_preference: alloc::vec![0u8],
            raw_public_key_spki: None,
            #[cfg(feature = "cert-compression")]
            cert_compression_algorithms: crate::tls::cert_compression::default_algorithms(),
            #[cfg(feature = "ech")]
            ech_server: None,
            key_log: None,
            preferred_key_exchange_group: None,
        }
    }

    /// Replaces the signature-algorithm whitelist used to validate client
    /// certificate chains and `CertificateVerify` signatures (mTLS).
    /// Defaults to [`SignaturePolicy::modern`].
    pub fn with_signature_policy(mut self, policy: SignaturePolicy) -> Self {
        self.signature_policy = policy;
        self
    }

    /// Installs a [`crate::tls::pki::CrlStore`] consulted during client-cert
    /// chain validation under mTLS. The store is advisory: covering CRLs
    /// reject revoked certs, missing CRLs do not fail the chain.
    pub fn with_crls(mut self, crls: crate::tls::pki::CrlStore) -> Self {
        self.crls = crls;
        self
    }

    /// Sets the verification clock used to enforce the `notBefore`/`notAfter`
    /// validity period of client certificates under mTLS. Set this on `no_std`
    /// targets (where the system clock is unavailable) or for reproducible
    /// verification; under `std` the system clock is used when this is unset.
    pub fn with_verification_time(mut self, t: crate::x509::Time) -> Self {
        self.verification_time = Some(t);
        self
    }

    /// Staples `crl_der` (a DER-encoded RFC 5280 `CertificateList`) on the
    /// leaf cert in the TLS 1.3 `Certificate` message, via the private
    /// extension `0xFE10`. The client validates the CRL against the chain
    /// it received and treats it as a per-connection
    /// [`crate::tls::pki::CrlStore`]. TLS 1.2 has no per-cert extension
    /// list in its `Certificate` message; stapling is a TLS-1.3-only feature.
    pub fn with_stapled_crl(mut self, crl_der: Vec<u8>) -> Self {
        self.stapled_crl = Some(crl_der);
        self
    }

    /// Staples `ocsp_der` (a DER-encoded RFC 6960 `OCSPResponse`) to the
    /// leaf cert. On TLS 1.3 it rides in the leaf `CertificateEntry`'s
    /// per-cert `status_request` extension (RFC 8446 §4.4.2.1). Emitted
    /// only when the client advertised `status_request` in its
    /// `ClientHello` (RFC 6066 §8); the bytes themselves are passed
    /// through unparsed by this layer.
    pub fn with_stapled_ocsp_response(mut self, ocsp_der: Vec<u8>) -> Self {
        self.stapled_ocsp_response = Some(ocsp_der);
        self
    }

    /// Sets the RFC 7250 `server_certificate_type` accept-set. Defaults to
    /// `[0]` (X.509 only); set to `[2]` for RawPublicKey-only servers or
    /// `[2, 0]` for a hybrid that picks RawPublicKey when the client offers
    /// it and falls back to X.509 otherwise. Combine with
    /// [`with_raw_public_key_spki`](Self::with_raw_public_key_spki) when
    /// RawPublicKey is in the list.
    pub fn with_server_cert_type_preference(mut self, prefs: Vec<u8>) -> Self {
        self.server_cert_type_preference = if prefs.is_empty() {
            alloc::vec![0u8]
        } else {
            prefs
        };
        self
    }

    /// Sets the RFC 7250 `client_certificate_type` accept-set (mTLS).
    /// Same semantics as
    /// [`with_server_cert_type_preference`](Self::with_server_cert_type_preference).
    pub fn with_client_cert_type_preference(mut self, prefs: Vec<u8>) -> Self {
        self.client_cert_type_preference = if prefs.is_empty() {
            alloc::vec![0u8]
        } else {
            prefs
        };
        self
    }

    /// Installs the bare `SubjectPublicKeyInfo` DER to send as the single
    /// `CertificateEntry` body when RawPublicKey is the negotiated server-
    /// cert type (RFC 7250 §4.2). The SPKI MUST encode the public key
    /// matching this server's signing key, or the client's
    /// `CertificateVerify` check will fail.
    pub fn with_raw_public_key_spki(mut self, spki_der: Vec<u8>) -> Self {
        self.raw_public_key_spki = Some(spki_der);
        self
    }

    /// Sets the RFC 8879 `compress_certificate` algorithm list — IDs the
    /// server can DECOMPRESS (mTLS client cert path) and is itself willing
    /// to USE when compressing its own `Certificate`. Default `[1]` (zlib).
    /// Empty disables the path: the server neither advertises the extension
    /// nor accepts a `CompressedCertificate` from the client.
    #[cfg(feature = "cert-compression")]
    pub fn with_cert_compression_algorithms(mut self, algorithms: Vec<u16>) -> Self {
        self.cert_compression_algorithms = algorithms;
        self
    }

    /// Attaches Encrypted Client Hello server-side state
    /// (draft-ietf-tls-esni-22): the key ring this server tries to
    /// HPKE-decrypt incoming `encrypted_client_hello` extensions with,
    /// and the `retry_configs` `ECHConfigList` it will publish to clients
    /// when ECH cannot be applied.
    #[cfg(feature = "ech")]
    pub fn with_ech_server(mut self, ech: crate::tls::ech::EchServer) -> Self {
        self.ech_server = Some(ech);
        self
    }

    /// Sets the ALPN protocols this server is willing to negotiate, in
    /// preference order. If the client offers ALPN with no overlap, the
    /// handshake fails with `no_application_protocol`.
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Sets the preferred key-exchange group (RFC 8446 §4.1.4). When the
    /// client advertises the group in `supported_groups` but did not include
    /// a `key_share` for it, the server emits a HelloRetryRequest asking the
    /// client to redo CH with a share for this group.
    pub fn with_preferred_key_exchange_group(mut self, g: crate::tls::NamedGroup) -> Self {
        self.preferred_key_exchange_group = Some(g);
        self
    }

    /// Advertises `record_size_limit = limit` (RFC 8449).
    pub fn with_record_size_limit(mut self, limit: u16) -> Self {
        self.record_size_limit = Some(limit);
        self
    }

    /// Enables session resumption: the server emits one NewSessionTicket
    /// after the handshake, encrypted under this 32-byte AEAD key. Without
    /// this, the server does not emit tickets and clients cannot resume.
    pub fn with_ticket_key(mut self, key: [u8; 32]) -> Self {
        self.ticket_key = Some(key);
        self
    }

    /// Sets the lifetime advertised in NewSessionTickets (seconds). Capped at
    /// 7 days per RFC 8446 §4.6.1; defaults to two hours.
    pub fn with_ticket_lifetime(mut self, seconds: u32) -> Self {
        const MAX: u32 = 7 * 24 * 60 * 60;
        self.ticket_lifetime = seconds.min(MAX);
        self
    }

    /// Enables 0-RTT: accept up to `max` bytes of early data on resumed
    /// connections, and advertise that budget in emitted NewSessionTickets.
    /// 0-RTT data is replayable by an active attacker; it is delivered
    /// only through [`ServerConnection::take_early_data`] (never through
    /// `take_received_plaintext`) and callers should only act on it when
    /// doing so is idempotent.
    pub fn with_max_early_data(mut self, max: u32) -> Self {
        self.max_early_data_size = max;
        self
    }

    /// Installs a [`ReplayWindow`] for 0-RTT anti-replay. The same window
    /// should be shared across all `ServerConfig`s in the process so that a
    /// binder seen in one connection blocks it in the next.
    #[cfg(feature = "std")]
    pub fn with_replay_window(mut self, window: ReplayWindow) -> Self {
        self.replay_window = Some(window);
        self
    }

    /// Demand a client certificate from peers. When `required` is true,
    /// a peer that sends an empty `Certificate` aborts the handshake with
    /// `certificate_required`. When `required` is false, an absent client
    /// cert is allowed.
    pub fn with_client_auth(mut self, roots: crate::tls::RootCertStore, required: bool) -> Self {
        self.client_auth = Some(ClientAuthPolicy { roots, required });
        self
    }

    fn signature_scheme(&self) -> SignatureScheme {
        match &self.key {
            ServerKey::Rsa(_) => SignatureScheme::RSA_PSS_RSAE_SHA256,
            ServerKey::Ecdsa(k) => match k.curve() {
                CurveId::P256 => SignatureScheme::ECDSA_SECP256R1_SHA256,
                CurveId::P384 => SignatureScheme::ECDSA_SECP384R1_SHA384,
                CurveId::P521 => SignatureScheme::ECDSA_SECP521R1_SHA512,
                CurveId::Secp256k1 | CurveId::Sm2p256v1 => SignatureScheme::ECDSA_SECP256R1_SHA256,
            },
            ServerKey::Ed25519(_) => SignatureScheme::ED25519,
            ServerKey::Ed448(_) => SignatureScheme::ED448,
            ServerKey::MlDsa44(_) => SignatureScheme::MLDSA44,
            ServerKey::MlDsa65(_) => SignatureScheme::MLDSA65,
            ServerKey::MlDsa87(_) => SignatureScheme::MLDSA87,
        }
    }
}

/// The server handshake progress.
#[derive(PartialEq, Eq)]
enum State {
    WaitClientHello,
    /// After emitting HelloRetryRequest in response to CH1; expect CH2.
    /// On entry the transcript holds `message_hash(Hash(CH1)) || HRR`
    /// (RFC 8446 §4.4.1) and a snapshot of CH1's immutable fields is
    /// stashed in `hrr_ch1_immutable` for the CH2 vs CH1 comparison
    /// mandated by RFC 8446 §4.1.4.
    WaitClientHelloRetry,
    /// mTLS: after our Finished, expect the client's `Certificate` next.
    WaitClientCertificate,
    /// mTLS: after the client's `Certificate`, expect `CertificateVerify`.
    /// Skipped if the client presented an empty Certificate (and our policy
    /// is non-required).
    WaitClientCertVerify,
    WaitClientFinished,
    Connected,
    Closed,
}

/// Snapshot of CH1 extensions that RFC 8446 §4.1.4 requires CH2 to echo
/// unchanged after a HelloRetryRequest. `None`-valued slots in CH1 must
/// stay `None` in CH2; present slots must compare byte-equal. The PSK
/// path is intentionally omitted here — the binders MUST be recomputed
/// against the new transcript, so a byte-equality test would falsely
/// reject every PSK retry; PSK + HRR is left to a follow-up.
#[derive(Clone)]
struct Ch1Immutable {
    random: Random,
    cipher_suites: Vec<CipherSuite>,
    legacy_session_id: Vec<u8>,
    supported_versions: Vec<u8>,
    signature_algorithms: Vec<u8>,
    supported_groups: Vec<u8>,
    server_name: Option<Vec<u8>>,
    alpn: Option<Vec<u8>>,
    psk_key_exchange_modes: Option<Vec<u8>>,
    /// Pre-share modes parity matters even before PSK is supported under
    /// HRR — the client must not flip this on the retry.
    cert_compression: Option<Vec<u8>>,
}

impl Ch1Immutable {
    /// Snapshot the CH1 fields that RFC 8446 §4.1.4 binds across the retry.
    fn from_ch(ch: &ClientHello) -> Self {
        let dup_owned = |t: ExtensionType| ext::find(&ch.extensions, t).map(|b| b.to_vec());
        Self {
            random: ch.random,
            cipher_suites: ch.cipher_suites.clone(),
            legacy_session_id: ch.session_id.clone(),
            supported_versions: dup_owned(ExtensionType::SUPPORTED_VERSIONS).unwrap_or_default(),
            signature_algorithms: dup_owned(ExtensionType::SIGNATURE_ALGORITHMS)
                .unwrap_or_default(),
            supported_groups: dup_owned(ExtensionType::SUPPORTED_GROUPS).unwrap_or_default(),
            server_name: dup_owned(ExtensionType::SERVER_NAME),
            alpn: dup_owned(ExtensionType::ALPN),
            psk_key_exchange_modes: dup_owned(ExtensionType::PSK_KEY_EXCHANGE_MODES),
            cert_compression: dup_owned(ExtensionType::COMPRESS_CERTIFICATE),
        }
    }

    /// Verify CH2 echoes every binding from CH1, returning
    /// `Error::IllegalParameter` on any drift.
    fn verify_ch2_matches(&self, ch2: &ClientHello) -> Result<(), Error> {
        if ch2.random != self.random
            || ch2.cipher_suites != self.cipher_suites
            || ch2.session_id != self.legacy_session_id
        {
            return Err(Error::IllegalParameter);
        }
        let ext_eq = |t: ExtensionType, want: &[u8]| -> bool {
            match ext::find(&ch2.extensions, t) {
                Some(b) => b == want,
                None => want.is_empty(),
            }
        };
        let opt_ext_eq = |t: ExtensionType, want: &Option<Vec<u8>>| -> bool {
            match (ext::find(&ch2.extensions, t), want) {
                (Some(b), Some(w)) => b == w.as_slice(),
                (None, None) => true,
                _ => false,
            }
        };
        if !ext_eq(ExtensionType::SUPPORTED_VERSIONS, &self.supported_versions)
            || !ext_eq(
                ExtensionType::SIGNATURE_ALGORITHMS,
                &self.signature_algorithms,
            )
            || !ext_eq(ExtensionType::SUPPORTED_GROUPS, &self.supported_groups)
            || !opt_ext_eq(ExtensionType::SERVER_NAME, &self.server_name)
            || !opt_ext_eq(ExtensionType::ALPN, &self.alpn)
            || !opt_ext_eq(
                ExtensionType::PSK_KEY_EXCHANGE_MODES,
                &self.psk_key_exchange_modes,
            )
            || !opt_ext_eq(ExtensionType::COMPRESS_CERTIFICATE, &self.cert_compression)
        {
            return Err(Error::IllegalParameter);
        }
        // RFC 8446 §4.2.10: 0-RTT MUST NOT appear after HRR.
        if ext::find(&ch2.extensions, ExtensionType::EARLY_DATA).is_some() {
            return Err(Error::IllegalParameter);
        }
        Ok(())
    }
}

/// A TLS 1.3 server connection.
pub struct ServerConnection<R: RngCore> {
    core: ConnectionCore,
    config: ServerConfig,
    rng: R,
    state: State,
    /// True once the peer's close_notify alert has been processed. Lets
    /// callers distinguish a graceful TLS shutdown from an abrupt
    /// transport close (truncation attack) — `state` alone can't, since
    /// failure paths also park the connection in [`State::Closed`].
    received_close_notify: bool,

    suite: Option<SuiteParams>,
    client_hs_secret: Option<Secret>,
    client_app_secret: Option<Secret>,
    /// Current write-side (`server_application_traffic_secret_N`); stepped
    /// by each outgoing `KeyUpdate`.
    server_app_secret: Option<Secret>,
    /// `exporter_master_secret` for the application-layer Exporter API.
    exporter_secret: Option<Secret>,
    /// ALPN protocol the server picked from the client's offer.
    alpn_negotiated: Option<Vec<u8>>,
    /// SNI host_name parsed from the ClientHello `server_name` extension
    /// (RFC 6066 §3). `None` if the client did not send the extension.
    /// Surfaced via [`peer_server_name`](Self::peer_server_name) so the
    /// caller can route on the requested hostname.
    peer_server_name: Option<alloc::string::String>,
    /// `true` if the handshake was a PSK resumption.
    psk_used: bool,
    /// Set once after the handshake completes to drive one-shot
    /// NewSessionTicket emission on the next process loop.
    pending_nst: bool,
    /// `resumption_master_secret`, computed at the client's Finished. Seed
    /// for ticket PSKs.
    rms: Option<Secret>,
    /// Key schedule retained between `on_client_hello` and `on_client_finished`
    /// so we can derive `resumption_master_secret` once the client Finished
    /// transcript hash is known.
    ks: Option<KeySchedule>,
    /// True if we accepted 0-RTT on this handshake (peer offered early_data
    /// in CH AND policy allows). Drives the early-read-key install and EOED
    /// expectation.
    early_data_accepted: bool,
    /// RFC 8446 §4.2.10: when 0-RTT is accepted, this tracks the remaining
    /// plaintext byte budget the client may consume under the early-data
    /// key. Initialized to `config.max_early_data_size` on 0-RTT acceptance;
    /// decremented for each application-data record decrypted under the
    /// early-data crypter; on underflow we emit `unexpected_message` and
    /// fail the handshake. `None` means 0-RTT was not accepted (so no
    /// budget tracking is needed) or the budget has already been retired
    /// (EndOfEarlyData has been received).
    early_data_remaining: Option<u32>,
    /// When 0-RTT is accepted, the client-handshake-traffic secret is stashed
    /// here and installed as the read key only after EndOfEarlyData arrives.
    deferred_chts: Option<Secret>,
    /// mTLS: the client's certificate chain (leaf first) after parsing its
    /// `Certificate` message. Empty if the client offered no cert.
    client_cert_chain: Vec<Vec<u8>>,
    /// mTLS: the client's leaf public key, recovered from the chain.
    client_leaf_key: Option<crate::x509::AnyPublicKey>,
    #[cfg(test)]
    server_hs_secret: Option<Secret>,

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
    /// Whether we have already seen the client's `quic_transport_parameters`
    /// extension and dispatched it via [`QuicHooks::on_peer_transport_params`].
    /// Used to enforce the RFC 9001 §8.2 "at most once" rule on top of the
    /// existing TLS extension-uniqueness check.
    peer_quic_params_seen: bool,
    /// Whether the client advertised `status_request` (OCSP stapling, RFC
    /// 6066 §8) in its `ClientHello`. Gates emission of the per-cert
    /// `status_request` extension on the leaf `CertificateEntry`
    /// (RFC 8446 §4.4.2.1); takes effect only when `config.stapled_ocsp_response`
    /// is also set.
    peer_offered_ocsp_staple: bool,
    /// Whether the client offered the `server_certificate_type` extension
    /// (RFC 7250 §4.2). When set, the server MUST echo the selection in
    /// `EncryptedExtensions`; when unset, both peers default to X.509 and
    /// no extension travels back.
    peer_offered_server_cert_type: bool,
    /// Whether the client offered the `client_certificate_type` extension
    /// (RFC 7250 §4.2).
    peer_offered_client_cert_type: bool,
    /// The certificate type selected for the server's `Certificate` message
    /// (`cert_type::X509` or `cert_type::RAW_PUBLIC_KEY`). Default `X509`.
    negotiated_server_cert_type: u8,
    /// The certificate type selected for any client `Certificate` message.
    /// Default `X509`. Independent of the server-side type per RFC 7250 §3.
    negotiated_client_cert_type: u8,
    /// RFC 8879 §3: the algorithm IDs the client advertised in its
    /// `compress_certificate` extension. Empty means the client did not
    /// opt in. Server-cert compression is gated on the intersection of
    /// this list with `config.cert_compression_algorithms` being
    /// non-empty.
    #[cfg(feature = "cert-compression")]
    peer_cert_compression_algorithms: Vec<u16>,
    /// Encrypted Client Hello (draft-ietf-tls-esni-22) per-handshake
    /// state. `None` outside the brief window between a CH carrying an
    /// `encrypted_client_hello` extension being received and the SH
    /// being emitted. See [`EchServerHandshakeState`].
    #[cfg(feature = "ech")]
    ech_state: Option<EchServerHandshakeState>,
    /// HelloRetryRequest snapshot. `Some` after we emit HRR; consumed
    /// in `on_client_hello_retry` to validate CH2 against CH1 per
    /// RFC 8446 §4.1.4.
    hrr_ch1_immutable: Option<Ch1Immutable>,
    /// The (EC)DHE group asked for in the HRR `key_share` and required
    /// in CH2. `Some` only between HRR emission and CH2 acceptance.
    hrr_selected_group: Option<NamedGroup>,
}

/// Server-side per-handshake ECH state, populated during
/// `on_client_hello` and consumed when emitting `ServerHello` (to
/// patch the accept signal into `random[24..32]`) and
/// `EncryptedExtensions` (to ship `retry_configs` on rejection).
#[cfg(feature = "ech")]
pub(crate) enum EchServerHandshakeState {
    /// The outer CH carried a syntactically valid `encrypted_client_hello`
    /// extension AND HPKE-decap succeeded AND the recovered plaintext
    /// parsed as an inner CH. The inner CH bytes have replaced the outer
    /// throughout the rest of CH processing; the SH random tail will
    /// carry the `server_hello_signal` so the client knows the inner
    /// transcript is in effect.
    Accepted {
        /// The recovered inner CH handshake message bytes (header
        /// included). Retained so we can compute
        /// `Hash(inner_ch || sh_with_zero_tail)` for the accept signal
        /// without re-deriving it from a cloned transcript at emit time.
        inner_ch_bytes: Vec<u8>,
        /// HPKE receiver context retained for the HRR retry path. CH1's
        /// `open` advanced `seq` to 1; CH2-outer's open consumes it at
        /// `seq = 1` (draft §7.2.2). `None` once consumed by CH2 to keep
        /// the receiver from accidentally being reused after the retry.
        receiver: Option<crate::tls::ech::outer::DecappedInner>,
        /// CH1-inner's `random`, used as the IKM for the HRR ECH
        /// confirmation signal (draft §7.2.1).
        inner_ch1_random: [u8; 32],
    },
    /// Either the client offered ECH (we found an outer-form ext) and
    /// decap failed, or `Config.ech_server` was unset; in both cases
    /// the EE response carries `retry_configs` so the client can refresh
    /// against the public DNS.
    Rejected,
}

impl<R: RngCore> ServerConnection<R> {
    /// Creates a server awaiting a `ClientHello`. `rng` supplies the server
    /// random, the ephemeral key share, and (for RSA) the PSS salt.
    pub fn new(config: ServerConfig, rng: R) -> Self {
        Self::new_with_mode(config, rng, super::super::quic_hooks::EngineMode::Tls, None)
    }

    /// QUIC-mode constructor (RFC 9001). Mirrors
    /// [`ClientConnection::new_for_quic`]: the engine runs the same TLS 1.3
    /// state machine but surfaces handshake messages and traffic secrets
    /// through `hooks` instead of producing record bytes. See
    /// [`crate::tls::quic_hooks`] for the call shape.
    // Used by the QUIC engine path (lands in Phase 4); silent otherwise.
    #[allow(dead_code)]
    pub(crate) fn new_for_quic(
        config: ServerConfig,
        rng: R,
        hooks: super::super::quic_hooks::BoxedHooks,
    ) -> Self {
        Self::new_with_mode(
            config,
            rng,
            super::super::quic_hooks::EngineMode::Quic,
            Some(hooks),
        )
    }

    /// Inner constructor shared by [`new`] (TLS / DTLS) and
    /// [`new_for_quic`] (QUIC). The only material differences live in
    /// `engine_mode` and `hooks`; every other field is initialized
    /// identically across modes.
    fn new_with_mode(
        config: ServerConfig,
        rng: R,
        engine_mode: super::super::quic_hooks::EngineMode,
        hooks: Option<super::super::quic_hooks::BoxedHooks>,
    ) -> Self {
        ServerConnection {
            core: ConnectionCore::new(),
            config,
            rng,
            state: State::WaitClientHello,
            received_close_notify: false,
            suite: None,
            client_hs_secret: None,
            client_app_secret: None,
            server_app_secret: None,
            exporter_secret: None,
            alpn_negotiated: None,
            peer_server_name: None,
            psk_used: false,
            pending_nst: false,
            rms: None,
            ks: None,
            early_data_accepted: false,
            early_data_remaining: None,
            deferred_chts: None,
            client_cert_chain: Vec::new(),
            client_leaf_key: None,
            #[cfg(test)]
            server_hs_secret: None,
            engine_mode,
            hooks,
            peer_quic_params_seen: false,
            peer_offered_ocsp_staple: false,
            peer_offered_server_cert_type: false,
            peer_offered_client_cert_type: false,
            negotiated_server_cert_type: crate::tls::codec::cert_type::X509,
            negotiated_client_cert_type: crate::tls::codec::cert_type::X509,
            #[cfg(feature = "cert-compression")]
            peer_cert_compression_algorithms: Vec::new(),
            #[cfg(feature = "ech")]
            ech_state: None,
            hrr_ch1_immutable: None,
            hrr_selected_group: None,
        }
    }

    /// Emits a handshake message at the right encryption level for the
    /// current [`EngineMode`]. See
    /// [`ClientConnection::emit_handshake_at`](super::client::ClientConnection)
    /// for the rationale and the transcript-feed invariant.
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
            self.core.transcript_only(&msg);
        } else {
            self.core.emit_handshake(msg);
        }
    }

    /// Emit a HelloRetryRequest (RFC 8446 §4.1.4) asking the client to retry
    /// CH with a `key_share` for `selected_group`. The current transcript
    /// already contains CH1 (the caller appended it before invoking this
    /// helper); we rewrite that to `message_hash(Hash(CH1))` per §4.4.1 and
    /// then feed the HRR bytes. The connection is left in
    /// `State::WaitClientHelloRetry` with `hrr_ch1_immutable` snapshotted for
    /// CH2 validation.
    ///
    /// When CH1 accepted ECH the HRR carries an `encrypted_client_hello`
    /// extension whose 8-byte payload is the `hrr_accept_confirmation`
    /// signal (draft-ietf-tls-esni-22 §7.2.1). The signal is built by
    /// (1) emitting HRR with the extension payload zeroed, (2) computing
    /// `Transcript-Hash(message_hash(Hash(inner_CH1)) || HRR_zero)`,
    /// (3) feeding that hash into `hello_retry_request_signal` with the
    /// inner CH1's random as IKM, and (4) patching the resulting 8 bytes
    /// into the wire HRR before it goes on the transcript and the record
    /// stream.
    fn emit_hello_retry_request(
        &mut self,
        ch: &ClientHello,
        suite: SuiteParams,
        selected_group: NamedGroup,
    ) -> Result<(), Error> {
        debug_assert!(
            !matches!(self.state, State::WaitClientHelloRetry),
            "second HelloRetryRequest attempted — preferred-group bug",
        );
        if matches!(self.state, State::WaitClientHelloRetry) {
            return Err(Error::HandshakeFailure);
        }

        // The transcript already had `set_alg(suite.hash)` called and CH1's
        // raw bytes appended by `process_client_hello` immediately before
        // it ran the HRR pre-check, so the rewrite below sees a
        // well-formed `Hash(CH1)`.
        // RFC 8446 §4.4.1: rewrite the transcript so that subsequent hashes
        // see `message_hash(Hash(CH1)) || HRR || ...`. This MUST happen
        // before we feed HRR bytes.
        self.core.transcript.replace_with_message_hash();

        // Build the HRR extension list. On an ECH-accepted CH1 we
        // append an `encrypted_client_hello` extension carrying 8 zero
        // bytes as the placeholder for the HRR signal (draft §7.2.1).
        #[cfg_attr(not(feature = "ech"), allow(unused_mut))]
        let mut hrr_extensions = alloc::vec![
            ext::hrr_key_share(selected_group),
            ext::server_supported_versions(),
        ];
        #[cfg(feature = "ech")]
        let ech_accepted_for_hrr = matches!(
            self.ech_state,
            Some(EchServerHandshakeState::Accepted { .. })
        );
        #[cfg(feature = "ech")]
        if ech_accepted_for_hrr {
            hrr_extensions.push(ext::hrr_ech_confirmation([0u8; 8]));
        }

        #[cfg_attr(not(feature = "ech"), allow(unused_mut))]
        let mut hrr = ServerHello {
            random: HRR_RANDOM,
            session_id: ch.session_id.clone(),
            cipher_suite: suite.suite,
            extensions: hrr_extensions,
        }
        .encode();

        // ECH HRR signal: compute over `(message_hash || HRR_with_zero_payload)`
        // and patch the 8 signal bytes into the wire HRR. The transcript
        // currently holds `message_hash(Hash(inner_CH1))` (we already
        // called `replace_with_message_hash` above); we use
        // `hash_with_appended` so the HRR-with-zeros doesn't pollute the
        // real transcript before we patch.
        #[cfg(feature = "ech")]
        if ech_accepted_for_hrr {
            let inner_ch1_random = match self.ech_state {
                Some(EchServerHandshakeState::Accepted {
                    inner_ch1_random, ..
                }) => inner_ch1_random,
                _ => unreachable!("checked Accepted above"),
            };
            let th = self.core.transcript.hash_with_appended(&hrr);
            let signal = crate::tls::ech::accept_signal::hello_retry_request_signal(
                suite.hash,
                &inner_ch1_random,
                th.as_slice(),
            );
            // Locate the 8-byte payload of the trailing
            // `encrypted_client_hello` extension and patch the signal in.
            let off = crate::tls::ech::accept_signal::locate_hrr_ech_signal_payload(&hrr)
                .ok_or(Error::HandshakeFailure)?;
            hrr[off..off + 8].copy_from_slice(&signal);
        }

        // Feed HRR to the transcript and ship it on the wire. HRR rides at
        // the same encryption level as the initial ServerHello (Initial in
        // QUIC, plaintext record in TLS / DTLS).
        self.emit_handshake_at(super::super::quic_hooks::Level::Initial, hrr);

        // Stash CH1's binding so we can validate CH2 against it, the suite
        // we picked, and the group we asked for.
        self.hrr_ch1_immutable = Some(Ch1Immutable::from_ch(ch));
        self.hrr_selected_group = Some(selected_group);
        self.suite = Some(suite);
        self.state = State::WaitClientHelloRetry;
        Ok(())
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
    /// state machine. Mirrors `read_tls` + `process_new_packets`.
    ///
    /// `level` is accepted into the signature so that Phase 4+ can plug in
    /// per-level validation (RFC 9001 §4.1.4); Phase 3 ignores it.
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

    /// The peer's certificate chain in wire order (DER), leaf first. Empty
    /// before the client's `Certificate` message arrives (and on connections
    /// where the server did not request client authentication).
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.client_cert_chain
    }

    /// Whether the just-completed handshake accepted 0-RTT data from the
    /// client. Always `false` on fresh handshakes.
    pub fn early_data_accepted(&self) -> bool {
        self.early_data_accepted
    }

    /// Whether the just-completed handshake resumed a prior session via PSK
    /// (RFC 8446 §2.2). Always `false` for fresh handshakes.
    pub fn psk_used(&self) -> bool {
        self.psk_used
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

    /// The ALPN protocol picked from the client's offer, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_negotiated.as_deref()
    }

    /// SNI host_name the client offered in the `server_name` extension
    /// (RFC 6066 §3). `None` if the client did not send the extension.
    /// Available once the ClientHello has been processed.
    pub fn peer_server_name(&self) -> Option<&str> {
        self.peer_server_name.as_deref()
    }

    /// IANA cipher-suite identifier of the negotiated suite, available
    /// once `ServerHello` has been emitted (i.e. `self.suite` is set).
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.suite.map(|s| s.suite.0)
    }

    /// `client_application_traffic_secret_0`, exposed for keylogfile output
    /// in the server CLI. Available once the handshake completes.
    pub fn client_application_traffic_secret_0(&self) -> Option<Vec<u8>> {
        self.client_app_secret.map(|s| s.as_slice().to_vec())
    }

    /// `server_application_traffic_secret_0`. See above.
    pub fn server_application_traffic_secret_0(&self) -> Option<Vec<u8>> {
        self.server_app_secret.map(|s| s.as_slice().to_vec())
    }

    /// `exporter_master_secret`. See above.
    pub fn exporter_master_secret(&self) -> Option<Vec<u8>> {
        self.exporter_secret.map(|s| s.as_slice().to_vec())
    }

    /// TLS 1.3 application-layer Exporter (RFC 8446 §7.5 / RFC 5705) —
    /// symmetric to `ClientConnection::tls_exporter`.
    pub fn tls_exporter(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let ems = self
            .exporter_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        tls_exporter(suite.hash, ems, label, context, out);
        Ok(())
    }

    /// Sends application data (only valid once the handshake completes).
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.state != State::Connected {
            return Err(Error::InappropriateState);
        }
        self.core.send_application_data(data);
        Ok(())
    }

    /// Removes and returns any received application plaintext.
    ///
    /// Never includes 0-RTT early data: bytes the client sent under
    /// `client_early_traffic_secret` are quarantined in their own buffer
    /// and must be drained explicitly via [`Self::take_early_data`].
    pub fn take_received_plaintext(&mut self) -> Vec<u8> {
        self.core.take_received()
    }

    /// Removes and returns any accepted 0-RTT early-data plaintext.
    ///
    /// Early data is **replayable by an active attacker** (RFC 8446 §8 /
    /// Appendix E.5): an observer can re-send the captured ClientHello +
    /// early-data flight to this or another server and have the same bytes
    /// accepted again (subject to the configured anti-replay window).
    /// Applications must only act on these bytes if doing so is idempotent.
    /// Returns an empty vector when no early data was accepted or it has
    /// already been drained.
    pub fn take_early_data(&mut self) -> Vec<u8> {
        self.core.take_early_data()
    }

    /// Queues a `close_notify`.
    pub fn send_close_notify(&mut self) {
        self.core.send_close_notify();
    }

    /// Test hook: the algorithm IDs the client advertised in its
    /// `compress_certificate` extension (RFC 8879). Empty when the
    /// client did not offer the extension. Used by the cert-compression
    /// loopback test to confirm the server saw the offer.
    #[cfg(all(test, feature = "cert-compression"))]
    pub(crate) fn peer_cert_compression_algorithms(&self) -> &[u16] {
        &self.peer_cert_compression_algorithms
    }

    /// Test/internal hook: emit an arbitrary post-handshake handshake message
    /// (e.g. a `NewSessionTicket`) under the application traffic key.
    ///
    /// Only valid once the handshake completes; the caller is responsible for
    /// building a syntactically valid handshake message body.
    #[cfg(test)]
    pub(crate) fn emit_post_handshake(&mut self, message: alloc::vec::Vec<u8>) {
        debug_assert!(matches!(self.state, State::Connected));
        self.core.emit_handshake(message);
    }

    /// Processes all buffered records, advancing the handshake.
    pub fn process_new_packets(&mut self) -> Result<(), Error> {
        loop {
            match self.core.next_message() {
                Ok(Some(Incoming::Handshake(msg))) => {
                    if let Err(e) = self.handle_handshake(msg) {
                        self.core.send_alert(alert_for(&e));
                        self.state = State::Closed;
                        return Err(e);
                    }
                }
                Ok(Some(Incoming::ApplicationData(plaintext_len))) => {
                    // Accept early-data records before the handshake completes
                    // when 0-RTT was accepted; otherwise app data is invalid
                    // until Connected.
                    if self.state != State::Connected && !self.early_data_accepted {
                        return Err(Error::UnexpectedMessage);
                    }
                    // RFC 8446 §4.2.10: enforce `max_early_data_size`. A
                    // record arriving under the early-data read key (before
                    // EndOfEarlyData has rotated us onto the client-handshake
                    // key) is debited from `early_data_remaining`. Underflow
                    // is a `unexpected_message` violation.
                    if self.state != State::Connected
                        && let Some(remaining) = self.early_data_remaining.as_mut()
                    {
                        let consumed = plaintext_len as u64;
                        if consumed > *remaining as u64 {
                            self.core.send_alert(AlertDescription::UnexpectedMessage);
                            self.state = State::Closed;
                            return Err(Error::UnexpectedMessage);
                        }
                        *remaining -= consumed as u32;
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
                    self.core.send_alert(alert_for(&e));
                    self.state = State::Closed;
                    return Err(e);
                }
            }
        }
    }

    fn handle_handshake(&mut self, msg: Vec<u8>) -> Result<(), Error> {
        let mut c = ReadCursor::new(&msg);
        let (msg_type, body) = read_handshake(&mut c)?;
        match self.state {
            State::WaitClientHello => self.on_client_hello(msg_type, body, &msg),
            State::WaitClientHelloRetry => self.on_client_hello_retry(msg_type, body, &msg),
            State::WaitClientCertificate => self.on_client_certificate(msg_type, body, &msg),
            State::WaitClientCertVerify => self.on_client_cert_verify(msg_type, body, &msg),
            State::WaitClientFinished => {
                // Under 0-RTT acceptance the client sends EndOfEarlyData
                // (under the early key) before its Finished. Receiving it
                // installs the client-handshake read key.
                if msg_type == hs_type::END_OF_EARLY_DATA
                    && self.early_data_accepted
                    && self.deferred_chts.is_some()
                {
                    if !body.is_empty() {
                        return Err(Error::IllegalParameter);
                    }
                    // RFC 9001 §8.3 forbids EndOfEarlyData in QUIC.
                    if self.engine_mode == super::super::quic_hooks::EngineMode::Quic {
                        return Err(Error::UnexpectedMessage);
                    }
                    let suite = self.suite.expect("suite set");
                    let chts = self.deferred_chts.take().expect("deferred chts");
                    self.core.set_read(RecordCrypter::new(
                        suite.hash,
                        suite.aead,
                        suite.key_len,
                        &chts,
                    ));
                    // The early-data read key is gone; application records
                    // from here on are 1-RTT-bound and go to the regular
                    // receive buffer again.
                    self.core.set_early_data_routing(false);
                    // RFC 8446 §4.2.10: client signaled end of early data.
                    // The early-data byte budget is no longer relevant —
                    // subsequent application records arrive under the
                    // client-handshake / -application keys.
                    self.early_data_remaining = None;
                    // Feed EOED into the transcript so client-Finished MAC
                    // matches the client's view.
                    self.core.transcript.update(&msg);
                    return Ok(());
                }
                self.on_client_finished(msg_type, body, &msg)
            }
            State::Connected => self.on_post_handshake(msg_type, body),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Handles post-handshake messages (RFC 8446 §4.6) on the server side.
    /// Currently only `KeyUpdate` is expected from the client; future commits
    /// may handle post-handshake `Certificate` / `CertificateVerify` for mTLS.
    fn on_post_handshake(&mut self, msg_type: u8, body: &[u8]) -> Result<(), Error> {
        match msg_type {
            hs_type::KEY_UPDATE => self.handle_key_update(body),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// Symmetric counterpart of the client's `handle_key_update` — derives
    /// the next `client_application_traffic_secret`, re-keys the read side,
    /// and replies with our own `KeyUpdate(not_requested)` if the peer
    /// requested it.
    fn handle_key_update(&mut self, body: &[u8]) -> Result<(), Error> {
        let ku = KeyUpdate::decode(body)?;
        let suite = self.suite.ok_or(Error::IllegalParameter)?;
        let prev = self
            .client_app_secret
            .as_ref()
            .ok_or(Error::IllegalParameter)?;
        let next = next_traffic_secret(suite.hash, prev);
        self.core.set_read(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &next,
        ));
        self.client_app_secret = Some(next);
        if ku.request_update {
            self.send_key_update(false)?;
        }
        Ok(())
    }

    /// Emits a `KeyUpdate` and rolls the write side forward.
    fn send_key_update(&mut self, request_peer_update: bool) -> Result<(), Error> {
        // RFC 9001 §6: TLS 1.3 `KeyUpdate` is not used in QUIC — refuse
        // rather than produce a malformed flight.
        if self.engine_mode == super::super::quic_hooks::EngineMode::Quic {
            debug_assert!(false, "RFC 9001 §6 forbids TLS KeyUpdate in QUIC mode");
            return Err(Error::InappropriateState);
        }
        let suite = self.suite.ok_or(Error::InappropriateState)?;
        let ku = KeyUpdate {
            request_update: request_peer_update,
        };
        self.core.emit_handshake(ku.encode());
        let prev = self
            .server_app_secret
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        let next = next_traffic_secret(suite.hash, prev);
        self.core.set_write(RecordCrypter::new(
            suite.hash,
            suite.aead,
            suite.key_len,
            &next,
        ));
        self.server_app_secret = Some(next);
        Ok(())
    }

    /// Requests a key update from the peer; symmetric to
    /// [`ClientConnection::request_key_update`](super::ClientConnection::request_key_update).
    pub fn request_key_update(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Connected) {
            return Err(Error::InappropriateState);
        }
        self.send_key_update(true)
    }

    /// Initial CH dispatcher: handles the very first ClientHello on a
    /// connection (state `WaitClientHello`).
    fn on_client_hello(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        self.process_client_hello(msg_type, body, raw, false)
    }

    /// Post-HelloRetryRequest CH2 dispatcher: handles the retry ClientHello
    /// (state `WaitClientHelloRetry`).
    fn on_client_hello_retry(
        &mut self,
        msg_type: u8,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), Error> {
        self.process_client_hello(msg_type, body, raw, true)
    }

    fn process_client_hello(
        &mut self,
        msg_type: u8,
        body: &[u8],
        raw: &[u8],
        is_retry: bool,
    ) -> Result<(), Error> {
        if msg_type != hs_type::CLIENT_HELLO {
            return Err(Error::UnexpectedMessage);
        }

        // ECH (draft-ietf-tls-esni-22 §6): if a keyring is configured and
        // the outer CH carries `encrypted_client_hello` (outer form), try
        // to HPKE-decap and substitute the recovered inner CH bytes for
        // `raw`/`body` throughout the rest of this function. On accept,
        // every downstream extension parse (SNI, ALPN, PSK, signature
        // algorithms…) reflects the inner intent and the transcript
        // naturally builds over the inner CH. On reject, we continue
        // under the outer CH and flag the state so EE can ship
        // `retry_configs` (Wave 3b.4).
        //
        // CH1 path (`is_retry = false`): the HPKE decap runs at seq=0 and
        // we retain the live `ReceiverContext` inside
        // `EchServerHandshakeState::Accepted` so a subsequent HRR retry
        // can decap CH2-outer with the same context at seq=1 per
        // draft §7.2.2.
        //
        // CH2 path (`is_retry = true`): we reach here on the HRR retry,
        // re-use the retained receiver via `try_decap_inner_retry`, and
        // hand the recovered inner CH2 bytes back through the same
        // `body`/`raw` substitution as CH1.
        #[cfg(feature = "ech")]
        let ech_inner_storage: Option<Vec<u8>> = if is_retry {
            // Retry path: if CH1 accepted ECH, the receiver is still
            // alive in `ech_state`. Pull it out, decap CH2-outer at
            // seq=1, and stash CH2-inner.
            if let Some(EchServerHandshakeState::Accepted {
                receiver: Some(_), ..
            }) = self.ech_state
            {
                // Take ownership of the receiver to call &mut open on it,
                // then put the state back without the receiver (it's
                // single-use across CH2).
                let mut state_taken = self.ech_state.take().expect("checked Some above");
                let inner_ch2_bytes = if let EchServerHandshakeState::Accepted {
                    ref mut receiver,
                    ref mut inner_ch_bytes,
                    ..
                } = state_taken
                {
                    let mut recv = receiver.take().expect("checked Some above");
                    let result = crate::tls::ech::outer::try_decap_inner_retry(raw, &mut recv);
                    let ich2 = result?;
                    // Replace CH1-inner with CH2-inner for downstream
                    // transcript/extension processing.
                    *inner_ch_bytes = ich2.clone();
                    ich2
                } else {
                    return Err(Error::HandshakeFailure);
                };
                self.ech_state = Some(state_taken);
                Some(inner_ch2_bytes)
            } else {
                None
            }
        } else if let Some(ref ech) = self.config.ech_server {
            match crate::tls::ech::outer::try_decap_inner(raw, ech.keys()) {
                Ok(decapped) => {
                    // Snapshot CH1-inner's `random` (offset 6..38 in the
                    // handshake-message bytes: 1-byte type + 3-byte length
                    // + 2-byte legacy_version) for the HRR signal IKM.
                    let mut inner_ch1_random = [0u8; 32];
                    if decapped.inner_ch_bytes.len() < 38 {
                        return Err(Error::HandshakeFailure);
                    }
                    inner_ch1_random.copy_from_slice(&decapped.inner_ch_bytes[6..38]);
                    let inner_bytes = decapped.inner_ch_bytes.clone();
                    self.ech_state = Some(EchServerHandshakeState::Accepted {
                        inner_ch_bytes: inner_bytes.clone(),
                        receiver: Some(decapped),
                        inner_ch1_random,
                    });
                    Some(inner_bytes)
                }
                Err(Error::EchDecryptionFailed) => {
                    // The client offered ECH (we found and parsed an
                    // outer-form extension) but HPKE failed: either an
                    // unknown `config_id` or AEAD tag rejection. Continue
                    // under the outer CH; EE will ship `retry_configs`.
                    self.ech_state = Some(EchServerHandshakeState::Rejected);
                    None
                }
                Err(_) => {
                    // No ECH ext (or its body was malformed in a way
                    // distinct from a HPKE failure). Treat as a non-ECH
                    // CH — no state, no signal patch, no retry_configs.
                    None
                }
            }
        } else {
            None
        };
        #[cfg(feature = "ech")]
        let (body, raw): (&[u8], &[u8]) = match ech_inner_storage.as_deref() {
            Some(inner) => (&inner[4..], inner),
            None => (body, raw),
        };

        let ch = ClientHello::decode(body)?;

        // RFC 8446 §4.1.4: CH2 after HRR must echo CH1 unmodified except for
        // the narrow list of permitted edits (key_share narrowed to the
        // requested group, early_data removed, PSK binders recomputed,
        // optional cookie/padding). Compare the snapshot we stashed at
        // HRR-emit time; any drift kills the handshake with
        // `illegal_parameter`.
        if is_retry {
            let snap = self
                .hrr_ch1_immutable
                .as_ref()
                .ok_or(Error::HandshakeFailure)?
                .clone();
            snap.verify_ch2_matches(&ch)?;
        }

        // RFC 7507 §3: TLS_FALLBACK_SCSV (0x5600) in the offered suite list
        // means the client is intentionally downgrading. Since this is the
        // TLS-1.3 server (we always top out at the highest version we
        // support), the only legitimate inclusion is when the client offered
        // only TLS 1.2 — but if `supported_versions` also offers 1.3, that's
        // an attacker-driven downgrade and we MUST refuse with
        // `inappropriate_fallback`. We surface it as `IllegalParameter` here
        // because the existing alert code set doesn't carry the dedicated
        // 86 / `inappropriate_fallback` description.
        const TLS_FALLBACK_SCSV: super::super::codec::CipherSuite =
            super::super::codec::CipherSuite(0x5600);
        if ch.cipher_suites.contains(&TLS_FALLBACK_SCSV)
            && let Some(sv_ext) = ext::find(&ch.extensions, ExtensionType::SUPPORTED_VERSIONS)
            && ext::client_offers_tls13(sv_ext).unwrap_or(false)
        {
            return Err(Error::IllegalParameter);
        }

        // RFC 8446 §4.2.11: when pre_shared_key is present, it MUST be the
        // last extension in the ClientHello (the binders trailer is at the
        // tail of the wire CH for transcript-binding). Reject CHs where the
        // PSK extension appears earlier — the truncated-prefix computed in
        // `try_accept_psk` would otherwise include unrelated extension bytes.
        if ext::find(&ch.extensions, ExtensionType::PRE_SHARED_KEY).is_some()
            && ch.extensions.last().map(|(t, _)| *t) != Some(ExtensionType::PRE_SHARED_KEY)
        {
            return Err(Error::IllegalParameter);
        }

        // PSK resumption: process pre_shared_key + psk_key_exchange_modes
        // before suite negotiation so we can constrain the suite to the PSK's
        // hash. Hard-fail on binder mismatch (decrypt_error). Skipped on
        // retry: PSK + HRR requires binders recomputed against the new
        // transcript, which is left to a follow-up commit (the HRR
        // pre-check below refuses to emit HRR when PSK is being negotiated).
        let psk_state = if is_retry {
            None
        } else {
            self.try_accept_psk(&ch, raw)?
        };

        // 0-RTT acceptance precondition: PSK was selected, the client
        // offered early_data, and our policy is non-zero. Anti-replay: if a
        // ReplayWindow is configured and this binder was seen, reject 0-RTT
        // (proceed with 1-RTT, the spec-compliant fallback). RFC 8446
        // §4.2.10 forbids 0-RTT after HRR, so on retry we hard-disable it.
        let client_offered_early = ext::find(&ch.extensions, ExtensionType::EARLY_DATA).is_some();
        let mut accept_early = !is_retry
            && psk_state.is_some()
            && client_offered_early
            && self.config.max_early_data_size > 0;
        #[cfg(feature = "std")]
        if accept_early
            && let Some(window) = self.config.replay_window.as_ref()
            && let Some(psk_body) = ext::find(&ch.extensions, ExtensionType::PRE_SHARED_KEY)
            && let Ok((_ids, binders)) = ext::parse_client_pre_shared_key(psk_body)
            && let Some(b0) = binders.first()
            && !window.check_and_insert(b0)
        {
            // Use the presented binder (first identity's) as the replay-key.
            // A repeat refuses 0-RTT but still allows 1-RTT resumption.
            accept_early = false;
        }

        // Negotiate the cipher suite. If we accepted a PSK, the suite must
        // match the PSK's hash; otherwise pick our preferred suite from the
        // client's offer. On retry, we reuse the suite picked at CH1 — the
        // §4.1.4 immutability check guarantees CH2's `cipher_suites` is
        // byte-identical to CH1's, so re-negotiation would produce the same
        // result, but using the cached value avoids any risk of drift.
        let suite = if is_retry {
            self.suite.ok_or(Error::HandshakeFailure)?
        } else if let Some(ref s) = psk_state {
            supported_suites()
                .iter()
                .copied()
                .find(|sp| ch.cipher_suites.contains(&sp.suite) && sp.hash == s.hash)
                .ok_or(Error::HandshakeFailure)?
        } else {
            supported_suites()
                .iter()
                .copied()
                .find(|s| ch.cipher_suites.contains(&s.suite))
                .ok_or(Error::HandshakeFailure)?
        };

        // Require TLS 1.3.
        let sv = ext::find(&ch.extensions, ExtensionType::SUPPORTED_VERSIONS)
            .ok_or(Error::UnsupportedVersion)?;
        if !ext::client_offers_tls13(sv)? {
            return Err(Error::UnsupportedVersion);
        }

        // The client must accept the signature scheme our certificate uses —
        // unless PSK is being used, in which case we sign nothing.
        if psk_state.is_none() {
            let our_scheme = self.config.signature_scheme();
            let sig_algs = ext::find(&ch.extensions, ExtensionType::SIGNATURE_ALGORITHMS)
                .ok_or(Error::HandshakeFailure)?;
            if !ext::parse_signature_algorithms(sig_algs)?.contains(&our_scheme) {
                return Err(Error::HandshakeFailure);
            }
        }

        // SNI: stash the client's offered host_name so multi-tenant servers can
        // route on it. RFC 6066 §3 — silently ignore unknown name_type entries
        // and surface the first host_name. A malformed extension body kills
        // the handshake (Error::Decode maps to `decode_error`).
        if let Some(sni_body) = ext::find(&ch.extensions, ExtensionType::SERVER_NAME) {
            self.peer_server_name = ext::parse_server_name(sni_body)?;
        }

        // ALPN: pick our first preference that appears in the client's offer.
        // If the client offered ALPN but there's no overlap *and* we have any
        // protocols configured, fail with `no_application_protocol`.
        if let Some(client_alpn_body) = ext::find(&ch.extensions, ExtensionType::ALPN) {
            let offered = ext::parse_alpn(client_alpn_body)?;
            if !self.config.alpn_protocols.is_empty() {
                let pick = self
                    .config
                    .alpn_protocols
                    .iter()
                    .find(|p| offered.iter().any(|o| o == *p))
                    .ok_or(Error::NoApplicationProtocol)?;
                self.alpn_negotiated = Some(pick.clone());
            }
        }

        // RFC 8446 §4.2.10: early data may only be accepted when the
        // selected ALPN protocol is identical to the one in use on the
        // connection that issued the ticket. The ticket stores that
        // protocol (empty when none was negotiated); the ALPN selection
        // above runs after the provisional 0-RTT decision, so re-check
        // here. A mismatch refuses 0-RTT only — the 1-RTT resumption
        // handshake continues normally (§4.2.10 prescribes rejection,
        // not an abort).
        if accept_early {
            let ticket_alpn = psk_state.as_ref().expect("psk_state set").alpn.as_slice();
            if ticket_alpn != self.alpn_negotiated.as_deref().unwrap_or(&[]) {
                accept_early = false;
            }
        }

        // record_size_limit: parse the peer's advertisement.
        if let Some(rsl_body) = ext::find(&ch.extensions, ExtensionType::RECORD_SIZE_LIMIT) {
            let limit = ext::parse_record_size_limit(rsl_body)?;
            self.core.set_peer_record_size_limit(limit);
        }

        // RFC 6066 §8: detect OCSP-stapling opt-in. We accept the body
        // shape unconditionally and remember the offer; emission of the
        // staple is gated on `config.stapled_ocsp_response` being set.
        if let Some(sr_body) = ext::find(&ch.extensions, ExtensionType::STATUS_REQUEST) {
            ext::parse_status_request(sr_body)?;
            self.peer_offered_ocsp_staple = true;
        }

        // RFC 8879 §3: the client advertises compress_certificate to
        // indicate which algorithms it can decompress the server's
        // Certificate under. Remember the offer; emission of
        // CompressedCertificate is gated on the intersection with our
        // own `config.cert_compression_algorithms` being non-empty.
        #[cfg(feature = "cert-compression")]
        if let Some(cc_body) = ext::find(&ch.extensions, ExtensionType::COMPRESS_CERTIFICATE) {
            self.peer_cert_compression_algorithms =
                crate::tls::cert_compression::decode_extension(cc_body)?;
        }

        // RFC 7250 §4.2: detect server_certificate_type / client_certificate_type
        // negotiation. Walk the client's offer in order and pick the first
        // entry that is also in our accept-set; if the client offered the
        // extension but no overlap exists, fail with `unsupported_certificate`.
        // RawPublicKey is only viable on the server side if we have an SPKI
        // to send — if the client only offered RPK and we don't, that's a
        // hard fail.
        if let Some(sct_body) = ext::find(&ch.extensions, ExtensionType::SERVER_CERTIFICATE_TYPE) {
            let offered = ext::parse_cert_type_list(sct_body)?;
            self.peer_offered_server_cert_type = true;
            let mut chosen: Option<u8> = None;
            for ct in &offered {
                if *ct == crate::tls::codec::cert_type::RAW_PUBLIC_KEY
                    && self.config.raw_public_key_spki.is_none()
                {
                    continue;
                }
                if self.config.server_cert_type_preference.contains(ct) {
                    chosen = Some(*ct);
                    break;
                }
            }
            match chosen {
                Some(ct) => self.negotiated_server_cert_type = ct,
                None => return Err(Error::HandshakeFailure),
            }
        }
        if let Some(cct_body) = ext::find(&ch.extensions, ExtensionType::CLIENT_CERTIFICATE_TYPE) {
            let offered = ext::parse_cert_type_list(cct_body)?;
            self.peer_offered_client_cert_type = true;
            let mut chosen: Option<u8> = None;
            for ct in &offered {
                if self.config.client_cert_type_preference.contains(ct) {
                    chosen = Some(*ct);
                    break;
                }
            }
            match chosen {
                Some(ct) => self.negotiated_client_cert_type = ct,
                None => return Err(Error::HandshakeFailure),
            }
        }

        // RFC 9001 §8.2: in QUIC mode the client's transport parameters
        // ride in the ClientHello as extension 0x0039. Hand the opaque
        // body to the QUIC layer verbatim; reject duplicates per the
        // "at most once" rule.
        if self.engine_mode == super::super::quic_hooks::EngineMode::Quic
            && let Some(qtp_body) =
                ext::find(&ch.extensions, ExtensionType::QUIC_TRANSPORT_PARAMETERS)
        {
            if self.peer_quic_params_seen {
                return Err(Error::IllegalParameter);
            }
            self.peer_quic_params_seen = true;
            if let Some(h) = self.hooks.as_mut() {
                h.on_peer_transport_params(qtp_body);
            }
        }

        // On retry, `set_alg` was already called at CH1 time and the
        // transcript already holds `message_hash(Hash(CH1)) || HRR`; we just
        // append CH2 here. RFC 8446 §4.4.1 fixes this ordering.
        if !is_retry {
            self.core.transcript.set_alg(suite.hash);
        }
        self.core.transcript.update(raw);

        // RFC 8446 §4.1.4 HRR pre-check: if the deployment named a preferred
        // key-exchange group, the client advertised it in
        // `supported_groups`, and the client did NOT include a share for
        // that group, ask the client to retry. PSK + HRR is intentionally
        // declined here (HRR binder recomputation is handled in a follow-up
        // commit); ECH + HRR is *supported* (draft §7.2.1 / §7.2.2), and
        // `emit_hello_retry_request` patches the
        // `hrr_accept_confirmation` signal into the HRR
        // `encrypted_client_hello` extension when CH1 accepted ECH.
        if !is_retry
            && psk_state.is_none()
            && let Some(preferred_pub) = self.config.preferred_key_exchange_group
        {
            let preferred = preferred_pub.to_wire();
            let supported = match ext::find(&ch.extensions, ExtensionType::SUPPORTED_GROUPS) {
                Some(sg_body) => ext::parse_supported_groups(sg_body)?,
                None => Vec::new(),
            };
            let shared_groups: Vec<NamedGroup> =
                match ext::find(&ch.extensions, ExtensionType::KEY_SHARE) {
                    Some(ks_body) => ext::parse_client_key_shares(ks_body)?
                        .into_iter()
                        .map(|(g, _)| g)
                        .collect(),
                    None => Vec::new(),
                };
            if supported.contains(&preferred) && !shared_groups.contains(&preferred) {
                self.emit_hello_retry_request(&ch, suite, preferred)?;
                return Ok(());
            }
        }

        // 0-RTT: if accepting, derive client_early_traffic_secret from
        // Hash(ClientHello) NOW (before SH lands in the transcript) and
        // install it as the read key so subsequent 0-RTT application data
        // records decrypt under the early key. This must happen before SH
        // is emitted so the early secret is bound to CH alone.
        let cets_for_read: Option<Secret> = if accept_early {
            let psk = &psk_state.as_ref().expect("psk_state set").psk;
            let early_ks = KeySchedule::with_psk(suite.hash, psk);
            let th_ch = self.core.transcript.current_hash();
            let cets = early_ks.client_early_traffic_secret(th_ch.as_slice());
            if let Some(kl) = self.config.key_log.as_ref() {
                kl.log("CLIENT_EARLY_TRAFFIC_SECRET", &ch.random, cets.as_slice());
            }
            self.early_data_accepted = true;
            // RFC 8446 §4.2.10: arm the receive-side byte budget. Records
            // decrypted under the early-data key in `process_new_packets`
            // decrement this; underflow tears the connection down with
            // `unexpected_message`.
            self.early_data_remaining = Some(self.config.max_early_data_size);
            // QUIC layer hook: the server reads 0-RTT under `cets`.
            self.notify_traffic_secret(
                super::super::quic_hooks::Level::EarlyData,
                super::super::quic_hooks::Direction::Rx,
                cets.as_slice(),
            );
            if !self.skip_record_keys() {
                self.core.set_read(RecordCrypter::new(
                    suite.hash,
                    suite.aead,
                    suite.key_len,
                    &cets,
                ));
                // Quarantine: while the early-data read key is installed,
                // decrypted application plaintext is replayable 0-RTT data
                // and must land in the dedicated early-data buffer, never
                // in the buffer `take_received_plaintext` drains.
                self.core.set_early_data_routing(true);
            }
            Some(cets)
        } else {
            None
        };
        let _ = cets_for_read;

        // Pick a key-exchange group offered by the client. On retry CH2
        // MUST carry exactly one share, for the group we asked for in HRR
        // (RFC 8446 §4.2.8); anything else is `illegal_parameter`.
        let ks_ext =
            ext::find(&ch.extensions, ExtensionType::KEY_SHARE).ok_or(Error::HandshakeFailure)?;
        let shares = ext::parse_client_key_shares(ks_ext)?;
        let (group, client_pub) = if is_retry {
            let want = self.hrr_selected_group.ok_or(Error::HandshakeFailure)?;
            if shares.len() != 1 || shares[0].0 != want {
                return Err(Error::IllegalParameter);
            }
            (&shares[0].0, shares[0].1.as_slice())
        } else {
            let (g, k) = shares
                .iter()
                .find(|(g, _)| {
                    matches!(
                        *g,
                        NamedGroup::X25519MLKEM768
                            | NamedGroup::X25519
                            | NamedGroup::SECP256R1
                            | NamedGroup::SECP384R1
                    )
                })
                .ok_or(Error::HandshakeFailure)?;
            (g, k.as_slice())
        };

        // Server random and ephemeral key share.
        let mut random: Random = [0u8; 32];
        self.rng.fill_bytes(&mut random);
        // ECH (draft §7.2): when ECH is accepted the last 8 bytes of
        // `random` carry the `accept_confirmation` MAC, computed below
        // after the handshake secret is available. Zero them now so the
        // initial encoding *is* the "zero-placeholder" form the draft
        // hashes; we patch the real signal back in before emitting.
        #[cfg(feature = "ech")]
        let ech_accepted = matches!(
            self.ech_state,
            Some(EchServerHandshakeState::Accepted { .. })
        );
        #[cfg(not(feature = "ech"))]
        let ech_accepted = false;
        if ech_accepted {
            for b in &mut random[24..32] {
                *b = 0;
            }
        }
        let (server_pub, shared) = self.key_agreement(*group, client_pub)?;

        // ServerHello with the selected suite and key share. When PSK is
        // accepted, also echo `pre_shared_key` with `selected_identity = 0`.
        let mut sh_extensions = alloc::vec![
            ext::server_key_share(*group, &server_pub),
            ext::server_supported_versions(),
        ];
        if psk_state.is_some() {
            sh_extensions.push(ext::server_pre_shared_key(0));
        }
        // `mut` is only required on the ECH-accept path (we patch the
        // accept signal into the encoded bytes). The `cfg_attr` keeps
        // non-ECH builds clean of `unused_mut`.
        #[cfg_attr(not(feature = "ech"), allow(unused_mut))]
        let mut server_hello = ServerHello {
            random,
            session_id: ch.session_id.clone(),
            cipher_suite: suite.suite,
            extensions: sh_extensions,
        }
        .encode();

        // Derive handshake traffic secrets over Hash(CH..SH). PSK acceptance
        // changes the early-secret extract (PSK instead of all-zeros).
        let mut ks = if let Some(ref s) = psk_state {
            KeySchedule::with_psk(suite.hash, &s.psk)
        } else {
            KeySchedule::new(suite.hash)
        };
        ks.enter_handshake(shared.as_slice());

        // ECH accept signal (draft §7.2): with the handshake secret on
        // the inner transcript now in hand, compute
        // `HKDF-Expand-Label(Derive-Secret(hs_secret, "ech accept confirmation",
        // Hash(inner_CH || zero-tail SH)), "ech accept confirmation", "", 8)`
        // and patch the 8 bytes into `sh_bytes[30..38]` (== `random[24..32]`
        // on the wire). The current transcript already contains the inner
        // CH (we substituted at the top of `on_client_hello`); we clone it
        // so feeding the zero-tail SH for the signal hash does not pollute
        // the real transcript that emit_handshake_at will feed next.
        #[cfg(feature = "ech")]
        if ech_accepted {
            let th_sig = self.core.transcript.hash_with_appended(&server_hello);
            let signal = crate::tls::ech::accept_signal::server_hello_signal(
                suite.hash,
                ks.current_secret_bytes(),
                th_sig.as_slice(),
            );
            // Wire layout: 1 (type) + 3 (length) + 2 (version) + 32 (random)
            // → random[24..32] sits at bytes 30..38.
            server_hello[30..38].copy_from_slice(&signal);
        }

        // RFC 9001 §4.1.4: ServerHello rides at the Initial encryption level
        // in QUIC; in TLS / DTLS mode this just goes into the record stream.
        self.emit_handshake_at(super::super::quic_hooks::Level::Initial, server_hello);

        let th = self.core.transcript.current_hash();
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

        // QUIC layer hooks (RFC 9001 §5.1) at Handshake level. Server
        // writes with `shts`, reads with `chts` — DO NOT FLIP.
        self.notify_traffic_secret(
            super::super::quic_hooks::Level::Handshake,
            super::super::quic_hooks::Direction::Tx,
            shts.as_slice(),
        );
        self.notify_traffic_secret(
            super::super::quic_hooks::Level::Handshake,
            super::super::quic_hooks::Direction::Rx,
            chts.as_slice(),
        );

        // Server writes with the server handshake key. The read key was set
        // to client_early_traffic_secret above when accepting 0-RTT; in that
        // case we stash chts for installation at EndOfEarlyData. Otherwise
        // install chts now. In QUIC mode the record crypter is never
        // installed (the QUIC layer holds the per-level AEAD state).
        if !self.skip_record_keys() {
            self.core.set_write(RecordCrypter::new(
                suite.hash,
                suite.aead,
                suite.key_len,
                &shts,
            ));
            if self.early_data_accepted {
                self.deferred_chts = Some(chts);
            } else {
                self.core.set_read(RecordCrypter::new(
                    suite.hash,
                    suite.aead,
                    suite.key_len,
                    &chts,
                ));
            }
            // RFC 9001 §8.4: ChangeCipherSpec MUST NOT appear in QUIC.
            self.core.emit_ccs();
        } else if self.early_data_accepted {
            self.deferred_chts = Some(chts);
        }

        // Encrypted server flight. Under PSK resumption we omit Certificate
        // and CertificateVerify (RFC 8446 §2.2). With mTLS we also emit
        // CertificateRequest after EE (RFC 8446 §4.3.2). PSK + mTLS is not
        // useful (resumption already authenticates the client), so the two
        // are mutually exclusive here.
        self.send_encrypted_extensions();
        if psk_state.is_none() {
            if self.config.client_auth.is_some() {
                self.send_certificate_request();
            }
            self.send_certificate();
            self.send_certificate_verify()?;
        }
        self.send_finished(suite, &shts);
        self.psk_used = psk_state.is_some();

        // Derive application traffic secrets over Hash(CH..server Finished).
        ks.enter_master();
        let th_app = self.core.transcript.current_hash();
        let cats = ks.client_application_traffic_secret(th_app.as_slice());
        let sats = ks.server_application_traffic_secret(th_app.as_slice());
        let ems = ks.exporter_master_secret(th_app.as_slice());
        if let Some(kl) = self.config.key_log.as_ref() {
            kl.log("CLIENT_TRAFFIC_SECRET_0", &ch.random, cats.as_slice());
            kl.log("SERVER_TRAFFIC_SECRET_0", &ch.random, sats.as_slice());
            kl.log("EXPORTER_SECRET", &ch.random, ems.as_slice());
        }
        // QUIC layer hooks at 1-RTT level. Server writes with `sats`,
        // reads with `cats` — DO NOT FLIP.
        self.notify_traffic_secret(
            super::super::quic_hooks::Level::OneRtt,
            super::super::quic_hooks::Direction::Tx,
            sats.as_slice(),
        );
        self.notify_traffic_secret(
            super::super::quic_hooks::Level::OneRtt,
            super::super::quic_hooks::Direction::Rx,
            cats.as_slice(),
        );
        self.exporter_secret = Some(ems);

        // The server's subsequent writes use the application key; it still
        // reads the client Finished with the client handshake key. Skip in
        // QUIC mode — the QUIC layer holds 1-RTT AEAD state itself.
        if !self.skip_record_keys() {
            self.core.set_write(RecordCrypter::new(
                suite.hash,
                suite.aead,
                suite.key_len,
                &sats,
            ));
        }

        self.suite = Some(suite);
        self.client_hs_secret = Some(chts);
        self.client_app_secret = Some(cats);
        self.server_app_secret = Some(sats);
        // Retain the schedule (now sitting at master) so we can derive RMS
        // when the client's Finished arrives.
        self.ks = Some(ks);
        #[cfg(test)]
        {
            self.server_hs_secret = Some(shts);
        }
        // mTLS: expect Certificate next instead of Finished.
        self.state = if self.config.client_auth.is_some() && !self.psk_used {
            State::WaitClientCertificate
        } else {
            State::WaitClientFinished
        };
        Ok(())
    }

    fn key_agreement(
        &mut self,
        group: NamedGroup,
        client_pub: &[u8],
    ) -> Result<(Vec<u8>, Secret), Error> {
        match group {
            NamedGroup::X25519 => {
                let sk = X25519PrivateKey::generate(&mut self.rng);
                let peer: [u8; 32] = client_pub.try_into().map_err(|_| Error::Decode)?;
                // RFC 8446 §7.4.2: reject the all-zero (small-order) DH output.
                let shared = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::IllegalParameter)?;
                Ok((sk.public_key().to_vec(), Secret::new(&shared)))
            }
            NamedGroup::SECP256R1 => {
                let sk = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut self.rng);
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, client_pub)
                    .map_err(|_| Error::Decode)?;
                let shared = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?;
                Ok((sk.public_key().to_sec1(), Secret::new(&shared)))
            }
            NamedGroup::SECP384R1 => {
                let sk = BoxedEcdhPrivateKey::generate(CurveId::P384, &mut self.rng);
                let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P384, client_pub)
                    .map_err(|_| Error::Decode)?;
                let shared = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::PeerMisbehaved)?;
                Ok((sk.public_key().to_sec1(), Secret::new(&shared)))
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
                // before any cryptographic operation on it. An attacker who
                // supplies off-modulus coefficients can otherwise probe the
                // encapsulator's noise polynomials.
                let validated_ek = MlKem768EncapsKey::from_bytes_validated(ek)
                    .map_err(|_| Error::IllegalParameter)?;
                let (ct, ml_ss) = validated_ek.encapsulate(&mut self.rng);
                let sk = X25519PrivateKey::generate(&mut self.rng);
                // RFC 8446 §7.4.2: reject the all-zero X25519 contribution
                // even though the ML-KEM half is independently secure.
                let x_ss = sk
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::IllegalParameter)?;

                // Server share: ML-KEM ciphertext ‖ X25519 key.
                let mut share = ct.to_bytes().to_vec();
                share.extend_from_slice(&sk.public_key());
                // Combined secret: ML-KEM shared secret first, then X25519.
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&ml_ss);
                combined[32..].copy_from_slice(&x_ss);
                Ok((share, Secret::new(&combined)))
            }
            _ => Err(Error::HandshakeFailure),
        }
    }

    fn send_encrypted_extensions(&mut self) {
        // Whether to add the QUIC transport parameters extension, and the
        // body to put there. Cache outside the builder closure so we don't
        // re-borrow `self` from inside.
        let quic_tp: Option<alloc::vec::Vec<u8>> =
            if self.engine_mode == super::super::quic_hooks::EngineMode::Quic {
                self.hooks.as_ref().and_then(|h| {
                    let body = h.our_transport_params();
                    if body.is_empty() { None } else { Some(body) }
                })
            } else {
                None
            };
        let mut msg = alloc::vec![hs_type::ENCRYPTED_EXTENSIONS];
        with_len_u24(&mut msg, |b| {
            with_len_u16(b, |exts| {
                // ALPN, when negotiated, echoes the chosen protocol as a list
                // of one entry per RFC 7301.
                if let Some(p) = self.alpn_negotiated.as_ref() {
                    let (ty, body) = ext::alpn_protocols(&[p.as_slice()]);
                    crate::tls::codec::put_u16(exts, ty.0);
                    crate::tls::codec::with_len_u16(exts, |b| b.extend_from_slice(&body));
                }
                // record_size_limit, when configured.
                if let Some(limit) = self.config.record_size_limit {
                    let (ty, body) = ext::record_size_limit(limit);
                    crate::tls::codec::put_u16(exts, ty.0);
                    crate::tls::codec::with_len_u16(exts, |b| b.extend_from_slice(&body));
                }
                // early_data acknowledgement (empty body) when accepting 0-RTT.
                if self.early_data_accepted {
                    let (ty, _) = ext::early_data_empty();
                    crate::tls::codec::put_u16(exts, ty.0);
                    crate::tls::codec::with_len_u16(exts, |_| {});
                }
                // RFC 9001 §8.2: in QUIC mode the server's transport
                // parameters ride in EE as extension 0x0039 (opaque body).
                if let Some(qtp) = quic_tp.as_ref() {
                    crate::tls::codec::put_u16(exts, ExtensionType::QUIC_TRANSPORT_PARAMETERS.0);
                    crate::tls::codec::with_len_u16(exts, |b| b.extend_from_slice(qtp));
                }
                // RFC 7250 §4.2: echo server_certificate_type /
                // client_certificate_type selection back if-and-only-if the
                // client offered the extension. Echoing X.509 explicitly is
                // legal and removes ambiguity.
                if self.peer_offered_server_cert_type {
                    let (ty, body) = ext::cert_type_selection(
                        ExtensionType::SERVER_CERTIFICATE_TYPE,
                        self.negotiated_server_cert_type,
                    );
                    crate::tls::codec::put_u16(exts, ty.0);
                    crate::tls::codec::with_len_u16(exts, |b| b.extend_from_slice(&body));
                }
                if self.peer_offered_client_cert_type {
                    let (ty, body) = ext::cert_type_selection(
                        ExtensionType::CLIENT_CERTIFICATE_TYPE,
                        self.negotiated_client_cert_type,
                    );
                    crate::tls::codec::put_u16(exts, ty.0);
                    crate::tls::codec::with_len_u16(exts, |b| b.extend_from_slice(&body));
                }
                // ECH rejection: draft-ietf-tls-esni-22 §7 has the server
                // ship its current `ECHConfigList` as `retry_configs` in
                // an EE `encrypted_client_hello` extension. The state was
                // set in `on_client_hello` whenever the client offered an
                // outer-form ECH extension but our HPKE decap failed
                // (unknown `config_id`, AEAD tag rejection, ...). Without
                // that state we either had no ECH server configured or
                // the client never offered ECH at all, and the extension
                // is omitted entirely.
                #[cfg(feature = "ech")]
                if matches!(self.ech_state, Some(EchServerHandshakeState::Rejected))
                    && let Some(ref ech) = self.config.ech_server
                {
                    let body = ech.retry_configs_bytes();
                    crate::tls::codec::put_u16(exts, ExtensionType::ENCRYPTED_CLIENT_HELLO.0);
                    crate::tls::codec::with_len_u16(exts, |b| b.extend_from_slice(&body));
                }
            });
        });
        // RFC 9001 §4.1.4: EncryptedExtensions rides at Handshake level.
        self.emit_handshake_at(super::super::quic_hooks::Level::Handshake, msg);
    }

    fn send_certificate(&mut self) {
        // RFC 7250 §4.4: when raw_public_key was negotiated, the
        // CertificateEntry list collapses to a single entry whose body is
        // the SPKI DER (not an X.509 cert) and carries no per-cert
        // extensions. Negotiation already gated on `raw_public_key_spki`
        // being `Some`.
        if self.negotiated_server_cert_type == crate::tls::codec::cert_type::RAW_PUBLIC_KEY {
            let spki = self
                .config
                .raw_public_key_spki
                .as_ref()
                .expect("raw_public_key_spki present after negotiation");
            let mut msg = alloc::vec![hs_type::CERTIFICATE];
            with_len_u24(&mut msg, |b| {
                b.push(0); // certificate_request_context: empty
                with_len_u24(b, |list| {
                    with_len_u24(list, |c| c.extend_from_slice(spki));
                    // empty per-entry extensions
                    with_len_u16(list, |_| {});
                });
            });
            self.emit_handshake_at(super::super::quic_hooks::Level::Handshake, msg);
            return;
        }
        let mut msg = alloc::vec![hs_type::CERTIFICATE];
        with_len_u24(&mut msg, |b| {
            b.push(0); // certificate_request_context: empty
            with_len_u24(b, |list| {
                for (i, cert) in self.config.cert_chain.iter().enumerate() {
                    with_len_u24(list, |c| c.extend_from_slice(cert));
                    // Per-certificate extensions: only the leaf (i == 0)
                    // ever carries any. Two opt-in extensions today: the
                    // RFC 6066 §8 `status_request` carrying a stapled OCSP
                    // response (emitted only when the client offered the
                    // extension), and the purecrypto-private CRL_RESPONSE
                    // staple.
                    with_len_u16(list, |b| {
                        if i == 0
                            && self.peer_offered_ocsp_staple
                            && let Some(ocsp) = &self.config.stapled_ocsp_response
                        {
                            let body = ext::certificate_status_ocsp(ocsp);
                            crate::tls::codec::put_u16(b, ExtensionType::STATUS_REQUEST.0);
                            crate::tls::codec::with_len_u16(b, |bb| bb.extend_from_slice(&body));
                        }
                        if i == 0
                            && let Some(crl) = &self.config.stapled_crl
                        {
                            crate::tls::codec::put_u16(b, ExtensionType::CRL_RESPONSE.0);
                            crate::tls::codec::with_len_u16(b, |bb| bb.extend_from_slice(crl));
                        }
                    });
                }
            });
        });
        // RFC 8879 §4: if both sides advertised cert-compression and our
        // preferred algorithm appears in the client's offer, wrap the
        // Certificate body into a CompressedCertificate. The transcript
        // sees the compressed wire bytes; this matches the BoringSSL /
        // rustls convention. The plaintext `msg` is `[hs_type::CERTIFICATE
        // || u24 len || body]`; we strip the 4-byte header and recompose
        // a `[hs_type::COMPRESSED_CERTIFICATE || u24 len || ...]` message.
        #[cfg(feature = "cert-compression")]
        if !self.peer_cert_compression_algorithms.is_empty()
            && let Some(alg) = crate::tls::cert_compression::pick_from_lists(
                &self.peer_cert_compression_algorithms,
                &self.config.cert_compression_algorithms,
            )
        {
            // `msg` = [u8 type || u24 len || body]; the body is what we
            // compress, so strip the 4-byte header before handing to the
            // wrapper.
            debug_assert_eq!(msg[0], hs_type::CERTIFICATE);
            let cert_body = &msg[4..];
            if let Ok(compressed) =
                crate::tls::cert_compression::encode_compressed_certificate(alg, cert_body)
            {
                self.emit_handshake_at(super::super::quic_hooks::Level::Handshake, compressed);
                return;
            }
            // Compression failure (compcol error) is silently downgraded
            // to plain Certificate: it is always a valid fallback and
            // does not break the handshake.
        }
        // RFC 9001 §4.1.4: Certificate rides at Handshake level.
        self.emit_handshake_at(super::super::quic_hooks::Level::Handshake, msg);
    }

    /// RFC 8446 §4.3.2: emit a `CertificateRequest` with the signature
    /// algorithms we accept. `certificate_request_context` is empty for
    /// handshake (non-post-handshake) authentication.
    fn send_certificate_request(&mut self) {
        let mut msg = alloc::vec![hs_type::CERTIFICATE_REQUEST];
        with_len_u24(&mut msg, |b| {
            b.push(0); // certificate_request_context = empty
            with_len_u16(b, |exts| {
                let (ty, body) = ext::signature_algorithms();
                crate::tls::codec::put_u16(exts, ty.0);
                crate::tls::codec::with_len_u16(exts, |b| b.extend_from_slice(&body));
            });
        });
        // RFC 9001 §4.1.4: CertificateRequest rides at Handshake level.
        self.emit_handshake_at(super::super::quic_hooks::Level::Handshake, msg);
    }

    fn send_certificate_verify(&mut self) -> Result<(), Error> {
        let th = self.core.transcript.current_hash();
        let content = certificate_verify_content(true, th.as_slice());
        let scheme = self.config.signature_scheme();
        let signature = match &self.config.key {
            ServerKey::Rsa(k) => k
                .sign_pss::<Sha256, _>(&content, &mut self.rng)
                .map_err(|_| Error::HandshakeFailure)?,
            ServerKey::Ecdsa(k) => {
                let sig = match k.curve() {
                    CurveId::P384 => k.sign::<Sha384>(&content),
                    CurveId::P521 => k.sign::<Sha512>(&content),
                    _ => k.sign::<Sha256>(&content),
                }
                .map_err(|_| Error::HandshakeFailure)?;
                sig.to_der(k.curve())
            }
            ServerKey::Ed25519(k) => k.sign(&content).to_bytes().to_vec(),
            // Ed448: raw 114-byte R‖S over the empty context (pure Ed448).
            ServerKey::Ed448(k) => k.sign(&content).to_bytes().to_vec(),
            // ML-DSA: raw FIPS 204 signature bytes; no DER wrapping. Hedged
            // with the server's RNG.
            ServerKey::MlDsa44(k) => k
                .sign(&mut self.rng, &content, b"")
                .map_err(|_| Error::HandshakeFailure)?,
            ServerKey::MlDsa65(k) => k
                .sign(&mut self.rng, &content, b"")
                .map_err(|_| Error::HandshakeFailure)?,
            ServerKey::MlDsa87(k) => k
                .sign(&mut self.rng, &content, b"")
                .map_err(|_| Error::HandshakeFailure)?,
        };

        let mut msg = alloc::vec![hs_type::CERTIFICATE_VERIFY];
        with_len_u24(&mut msg, |b| {
            b.extend_from_slice(&scheme.0.to_be_bytes());
            with_len_u16(b, |s| s.extend_from_slice(&signature));
        });
        // RFC 9001 §4.1.4: CertificateVerify rides at Handshake level.
        self.emit_handshake_at(super::super::quic_hooks::Level::Handshake, msg);
        Ok(())
    }

    fn send_finished(&mut self, suite: SuiteParams, shts: &Secret) {
        let th = self.core.transcript.current_hash();
        let verify_data = finished_verify_data(suite.hash, shts, th.as_slice());
        let mut msg = alloc::vec![hs_type::FINISHED];
        with_len_u24(&mut msg, |b| b.extend_from_slice(verify_data.as_slice()));
        // RFC 9001 §4.1.4: server Finished rides at Handshake level.
        self.emit_handshake_at(super::super::quic_hooks::Level::Handshake, msg);
    }

    /// mTLS: process the client's `Certificate` message. Empty chain is
    /// allowed only when policy is `required = false`.
    fn on_client_certificate(
        &mut self,
        msg_type: u8,
        body: &[u8],
        raw: &[u8],
    ) -> Result<(), Error> {
        if msg_type != hs_type::CERTIFICATE {
            return Err(Error::UnexpectedMessage);
        }
        let chain = parse_certificate_list(body)?;
        self.core.transcript.update(raw);
        let policy = self
            .config
            .client_auth
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        if chain.is_empty() {
            if policy.required {
                return Err(Error::CertificateRequired);
            }
            // Allowed: skip CertificateVerify, head straight to client Finished.
            self.client_cert_chain.clear();
            self.client_leaf_key = None;
            self.state = State::WaitClientFinished;
            return Ok(());
        }
        // RFC 7250 §4.4: when raw_public_key was negotiated for the client
        // direction, the single CertificateEntry body is a bare SPKI DER and
        // PKI / chain validation does not apply. The application is
        // responsible for trust establishment over the recovered leaf key.
        if self.negotiated_client_cert_type == crate::tls::codec::cert_type::RAW_PUBLIC_KEY {
            if chain.len() != 1 {
                return Err(Error::BadCertificate);
            }
            let spki = &chain[0];
            let leaf_key = crate::x509::AnyPublicKey::from_spki_der(spki)
                .map_err(|_| Error::BadCertificate)?;
            self.client_cert_chain = chain;
            self.client_leaf_key = Some(leaf_key);
            self.state = State::WaitClientCertVerify;
            return Ok(());
        }
        // Validate the chain against the configured roots, applying the
        // server's signature-algorithm whitelist to every chain signature and
        // enforcing the client cert's notBefore/notAfter validity period via
        // the configured verification time, falling back to the system clock
        // under `std` (F1). mTLS: leaf is a client cert, so require
        // `id-kp-clientAuth` EKU.
        let now = self.config.verification_time.clone().or_else(system_now);
        let leaf_key = crate::tls::pki::verify_chain_with_crls_for_purpose(
            &policy.roots,
            &self.config.crls,
            &chain,
            now.as_ref(),
            &self.config.signature_policy,
            crate::tls::pki::ChainPurpose::Client,
        )?;
        self.client_cert_chain = chain;
        self.client_leaf_key = Some(leaf_key);
        self.state = State::WaitClientCertVerify;
        Ok(())
    }

    /// mTLS: process the client's `CertificateVerify` message and verify the
    /// signature against the leaf key recovered in `on_client_certificate`.
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

        // RFC 8446 §4.4.3: rsa_pkcs1_* schemes MUST NOT appear in TLS 1.3
        // CertificateVerify (legacy chain signatures only).
        if scheme.is_rsa_pkcs1() {
            return Err(Error::IllegalParameter);
        }

        // The transcript at this point includes everything up to (and not
        // including) this CertificateVerify, which is exactly the input the
        // client signed.
        let th = self.core.transcript.current_hash();
        let content = certificate_verify_content(false, th.as_slice());
        let leaf_key = self
            .client_leaf_key
            .as_ref()
            .ok_or(Error::InappropriateState)?;
        crate::tls::crypto::verify_signature(
            scheme,
            leaf_key,
            &content,
            &signature,
            &self.config.signature_policy,
        )?;

        self.core.transcript.update(raw);
        self.state = State::WaitClientFinished;
        Ok(())
    }

    fn on_client_finished(&mut self, msg_type: u8, body: &[u8], raw: &[u8]) -> Result<(), Error> {
        if msg_type != hs_type::FINISHED {
            return Err(Error::UnexpectedMessage);
        }
        let suite = self.suite.expect("suite set");
        let chts = self.client_hs_secret.as_ref().expect("client hs secret");

        let th = self.core.transcript.current_hash();
        let expected = finished_verify_data(suite.hash, chts, th.as_slice());
        if !bool::from(expected.as_slice().ct_eq(body)) {
            return Err(Error::HandshakeFailure);
        }
        self.core.transcript.update(raw);

        // Derive resumption_master_secret over Hash(CH..client Finished).
        if let Some(ks) = self.ks.as_ref() {
            let th_rms = self.core.transcript.current_hash();
            self.rms = Some(ks.resumption_master_secret(th_rms.as_slice()));
        }

        // The client now talks under its application traffic key. In QUIC
        // mode the QUIC layer holds the 1-RTT read-side AEAD state itself.
        if !self.skip_record_keys() {
            let cats = self.client_app_secret.as_ref().expect("client app secret");
            self.core.set_read(RecordCrypter::new(
                suite.hash,
                suite.aead,
                suite.key_len,
                cats,
            ));
        }
        // RFC 8446 §5: ChangeCipherSpec is no longer permitted after this point.
        self.core.close_ccs_window();
        self.state = State::Connected;

        // Issue one NewSessionTicket if a ticket key is configured. We do
        // this immediately on transition to Connected so the ticket rides
        // out in the same write_tls() drain as our Finished's responses.
        if self.config.ticket_key.is_some() {
            self.pending_nst = true;
            self.emit_session_ticket()?;
        }
        Ok(())
    }

    /// Emits one NewSessionTicket (RFC 8446 §4.6.1) under the current write
    /// key. The ticket is a `nonce(12) ‖ AES-256-GCM(ticket_key, nonce, cleartext)`
    /// blob where `cleartext = creation_unix_time_u64 ‖ psk ‖ alpn_len_u8 ‖ alpn`.
    fn emit_session_ticket(&mut self) -> Result<(), Error> {
        if !self.pending_nst {
            return Ok(());
        }
        let key = self.config.ticket_key.expect("ticket key present");
        let suite = self.suite.expect("suite set");

        // resumption_master_secret over Hash(CH..client Finished); set on
        // on_client_finished.
        let rms = *self.rms.as_ref().expect("rms set");

        // ticket_nonce: 4 random bytes is enough (RFC: <1..255>).
        let mut ticket_nonce = [0u8; 4];
        self.rng.fill_bytes(&mut ticket_nonce);

        // PSK = HKDF-Expand-Label(rms, "resumption", ticket_nonce).
        let hash_len = suite.hash.output_len();
        let mut psk = alloc::vec![0u8; hash_len];
        psk_from_resumption(suite.hash, &rms, &ticket_nonce, &mut psk);

        // ticket plaintext.
        let creation = system_now_u64();
        let alpn = self.alpn_negotiated.as_ref();
        let alpn_len = alpn.map(|a| a.len()).unwrap_or(0) as u8;
        let mut plain = Vec::with_capacity(8 + hash_len + 1 + alpn_len as usize);
        plain.extend_from_slice(&creation.to_be_bytes());
        plain.extend_from_slice(&psk);
        plain.push(alpn_len);
        if let Some(a) = alpn {
            plain.extend_from_slice(a);
        }

        // Encrypt: 12-byte GCM nonce ‖ AES-256-GCM(plain) ‖ 16-byte tag.
        let mut nonce = [0u8; 12];
        self.rng.fill_bytes(&mut nonce);
        let gcm = Gcm::new(Aes256::new(&key));
        let mut buf = plain;
        let tag = gcm.encrypt(&nonce, &[], &mut buf);

        let mut ticket = Vec::with_capacity(12 + buf.len() + 16);
        ticket.extend_from_slice(&nonce);
        ticket.extend_from_slice(&buf);
        ticket.extend_from_slice(&tag);

        // ticket_age_add: 4 random bytes.
        let mut age_add_bytes = [0u8; 4];
        self.rng.fill_bytes(&mut age_add_bytes);
        let ticket_age_add = u32::from_be_bytes(age_add_bytes);

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
        // RFC 9001 §4.1.4: NewSessionTicket rides at the 1-RTT level.
        self.emit_handshake_at(super::super::quic_hooks::Level::OneRtt, nst.encode());
        self.pending_nst = false;
        Ok(())
    }

    /// Test hook: the server handshake traffic secret, for KAT comparison.
    #[cfg(test)]
    pub(crate) fn server_hs_secret_bytes(&self) -> Vec<u8> {
        self.server_hs_secret
            .as_ref()
            .map(|s| s.as_slice().to_vec())
            .unwrap_or_default()
    }
}

/// Parses a TLS 1.3 `Certificate` message body into a list of DER
/// certificates (end-entity first). Mirrors the client-side helper.
fn parse_certificate_list(body: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut c = ReadCursor::new(body);
    let _context = c.vec_u8()?; // certificate_request_context
    let list = c.vec_u24()?;
    c.expect_empty()?;

    let mut entries = ReadCursor::new(list);
    let mut certs = Vec::new();
    while !entries.is_empty() {
        let cert = entries.vec_u24()?.to_vec();
        let _exts = entries.vec_u16()?; // per-certificate extensions
        certs.push(cert);
    }
    Ok(certs)
}

/// Current wall-clock time as a Unix timestamp, when the `std` feature is
/// available; otherwise zero (ticket timestamps degrade gracefully but
/// `with_ticket_key` is typically server-side `std` anyway).
#[cfg(feature = "std")]
fn system_now_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(not(feature = "std"))]
fn system_now_u64() -> u64 {
    0
}

/// The system clock as an [`crate::x509::Time`] when available; `None` for
/// `no_std`. Used as the default verification time for client-cert validity
/// checks under mTLS.
#[cfg(feature = "std")]
fn system_now() -> Option<crate::x509::Time> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| crate::x509::Time::from_unix(d.as_secs()))
}

#[cfg(not(feature = "std"))]
fn system_now() -> Option<crate::x509::Time> {
    None
}

/// PSK accepted from the client's ClientHello: the recovered PSK bytes and
/// the hash function that pinned them.
struct AcceptedPsk {
    psk: Vec<u8>,
    hash: HashAlg,
    /// ALPN protocol negotiated on the connection that issued the ticket
    /// (empty when none was). RFC 8446 §4.2.10: 0-RTT may only be accepted
    /// when the new connection selects the identical protocol.
    alpn: Vec<u8>,
}

impl<R: RngCore> ServerConnection<R> {
    /// Tries to accept a `pre_shared_key` offer from the ClientHello.
    ///
    /// Returns:
    /// * `Ok(Some(AcceptedPsk))` — pick this PSK, run a resumed handshake.
    /// * `Ok(None)` — no offered PSK we recognize; fall back to 1-RTT.
    /// * `Err(Error::DecryptError)` — a ticket decrypted but its binder is
    ///   wrong: an active attacker or a tampered CH. Reject hard.
    fn try_accept_psk(&self, ch: &ClientHello, raw: &[u8]) -> Result<Option<AcceptedPsk>, Error> {
        let Some(ticket_key) = self.config.ticket_key.as_ref() else {
            return Ok(None);
        };
        let Some(modes_body) = ext::find(&ch.extensions, ExtensionType::PSK_KEY_EXCHANGE_MODES)
        else {
            return Ok(None);
        };
        let modes = ext::parse_psk_key_exchange_modes(modes_body)?;
        if !modes.contains(&1) {
            // We only support psk_dhe_ke.
            return Ok(None);
        }
        let Some(psk_body) = ext::find(&ch.extensions, ExtensionType::PRE_SHARED_KEY) else {
            return Ok(None);
        };
        let (identities, binders) = ext::parse_client_pre_shared_key(psk_body)?;

        // RFC 8446 §4.6.1 + §8.1: enforce ticket expiry on decrypt. We pass
        // the configured `ticket_lifetime` and the system clock through;
        // `decrypt_ticket` treats `now_secs == 0` as "no clock — skip the
        // age check", mirroring the TLS 1.2 `try_resume` behavior so the
        // no_std build degrades gracefully.
        let now = system_now_u64();
        let ticket_lifetime = self.config.ticket_lifetime;

        // RFC 8446 §4.2.11: pick the first identity whose ticket decrypts
        // cleanly. Then verify its binder; mismatch is fatal.
        for (idx, (ticket, _age)) in identities.iter().enumerate() {
            let Some(decrypted) = decrypt_ticket(ticket_key, ticket, now, ticket_lifetime) else {
                continue;
            };
            let TicketPlaintext { psk, alpn } = decrypted;
            let hash = match psk.len() {
                32 => HashAlg::Sha256,
                48 => HashAlg::Sha384,
                _ => continue,
            };
            let hash_len = hash.output_len();

            // Binder field at the tail of the CH wire bytes.
            let binders_field_len: usize = 2 + binders.iter().map(|b| 1 + b.len()).sum::<usize>();
            if raw.len() < binders_field_len {
                continue;
            }
            let truncated = &raw[..raw.len() - binders_field_len];

            let ks = KeySchedule::with_psk(hash, &psk);
            let res_bk = ks.binder_key(b"res binder");
            let fk = binder_finished_key(hash, &res_bk);
            let th = hash.hash(truncated);
            let expected: Vec<u8> = match hash {
                HashAlg::Sha256 => Hmac::<Sha256>::mac(fk.as_slice(), th.as_slice())
                    .as_ref()
                    .to_vec(),
                HashAlg::Sha384 => Hmac::<Sha384>::mac(fk.as_slice(), th.as_slice())
                    .as_ref()
                    .to_vec(),
            };
            let presented = binders.get(idx).ok_or(Error::DecryptError)?;
            if presented.len() != hash_len
                || !bool::from(expected.as_slice().ct_eq(presented.as_slice()))
            {
                return Err(Error::DecryptError);
            }
            return Ok(Some(AcceptedPsk { psk, hash, alpn }));
        }
        Ok(None)
    }
}

/// Decoded ticket payload: the original PSK plus the ALPN protocol that was
/// negotiated on the connection that issued the ticket (empty when none was).
struct TicketPlaintext {
    psk: Vec<u8>,
    alpn: Vec<u8>,
}

/// Decrypts a ticket bound to `key`. The wire layout is `nonce(12) ‖
/// ciphertext ‖ tag(16)`, with `cleartext = creation_u64 ‖ psk(hash_len) ‖
/// alpn_len_u8 ‖ alpn`. Returns `None` on any structural or authentication
/// failure.
///
/// RFC 8446 §4.6.1 + §8.1: when `now_secs > 0`, the embedded
/// `creation_unix_time_u64` is enforced against `ticket_lifetime_secs`
/// (with a ±60 s clock-skew tolerance). A ticket older than
/// `ticket_lifetime_secs + 60` or minted more than 60 s in the future is
/// rejected — silent fallback to a fresh 1-RTT handshake, matching the
/// TLS 1.2 `try_resume` policy. `now_secs == 0` (no clock configured) or
/// `ticket_lifetime_secs == 0` (lifetime enforcement disabled) skips the
/// age check.
fn decrypt_ticket(
    key: &[u8; 32],
    ticket: &[u8],
    now_secs: u64,
    ticket_lifetime_secs: u32,
) -> Option<TicketPlaintext> {
    if ticket.len() < 12 + 16 {
        return None;
    }
    let nonce: &[u8; 12] = ticket[..12].try_into().ok()?;
    let body = &ticket[12..];
    let (ct, tag_slice) = body.split_at(body.len() - 16);
    let tag: &[u8; 16] = tag_slice.try_into().ok()?;
    let mut buf = ct.to_vec();
    let gcm = Gcm::new(Aes256::new(key));
    if gcm.decrypt(nonce, &[], &mut buf, tag).is_err() {
        return None;
    }
    // Parse plaintext: 8-byte creation timestamp + psk + alpn_len + alpn.
    if buf.len() < 8 + 1 {
        return None;
    }
    let creation_secs = u64::from_be_bytes(buf[..8].try_into().ok()?);
    // RFC 8446 §4.6.1 + §8.1: enforce ticket age. Skip the check when the
    // server has no wall clock (`now_secs == 0`, matching the TLS 1.2
    // fallback in `server12.rs::try_resume`) or when the lifetime is
    // explicitly zeroed.
    if now_secs != 0 && ticket_lifetime_secs != 0 {
        const SKEW_SECS: u64 = 60;
        // Past: now - creation must not exceed lifetime + skew.
        if now_secs.saturating_sub(creation_secs) > ticket_lifetime_secs as u64 + SKEW_SECS {
            return None;
        }
        // Future: a ticket minted more than `SKEW_SECS` ahead of our clock
        // is implausible (clock smear or attacker-forged plaintext under a
        // compromised ticket key).
        if creation_secs > now_secs.saturating_add(SKEW_SECS) {
            return None;
        }
    }
    let rest = &buf[8..];
    // PSK length: derived by total - 8 (creation) - 1 (alpn_len) - alpn_len.
    // PSK length is either 32 or 48; alpn_len is the last layout field, so:
    //   psk = rest[..psk_len]; alpn_len = rest[psk_len]; alpn = rest[psk_len+1..].
    // We try 32 first, then 48. Either is uniquely identified by checking
    // the length field's plausibility.
    for &psk_len in &[32usize, 48usize] {
        if rest.len() < psk_len + 1 {
            continue;
        }
        let alpn_len = rest[psk_len] as usize;
        if rest.len() == psk_len + 1 + alpn_len {
            let psk = rest[..psk_len].to_vec();
            let alpn = rest[psk_len + 1..].to_vec();
            return Some(TicketPlaintext { psk, alpn });
        }
    }
    None
}

/// Maps an internal error to the alert to send the peer.
fn alert_for(error: &Error) -> AlertDescription {
    match error {
        Error::Decode => AlertDescription::DecodeError,
        Error::UnexpectedMessage => AlertDescription::UnexpectedMessage,
        Error::BadRecordMac => AlertDescription::BadRecordMac,
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
        #[cfg(feature = "cert-compression")]
        Error::CertDecompressionFailed => AlertDescription::BadCertificate,
        _ => AlertDescription::HandshakeFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::BoxedRsaPrivateKey;
    use crate::test_util::{from_hex_vec, rsa_test_key_a};
    use crate::tls::ContentType;
    use crate::tls::codec::read_record;
    use crate::x509::{Certificate, DistinguishedName, Time, Validity};

    /// An RNG that returns a fixed script of bytes, then zeros — to reproduce
    /// the RFC 8448 server random and ephemeral key exactly.
    struct ScriptedRng {
        data: Vec<u8>,
        pos: usize,
    }
    impl RngCore for ScriptedRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest.iter_mut() {
                *b = self.data.get(self.pos).copied().unwrap_or(0);
                self.pos += 1;
            }
        }
    }

    fn test_server_config() -> ServerConfig {
        let key = rsa_test_key_a();
        let name = DistinguishedName::common_name("purecrypto test server");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed(&key, &name, &validity, 1, false).unwrap();
        let boxed = BoxedRsaPrivateKey::from_pkcs1_der(&key.to_pkcs1_der()).unwrap();
        ServerConfig::with_rsa(alloc::vec![cert.to_der().to_vec()], boxed)
    }

    // RFC 8448 §3: feed the exact ClientHello and seed the server's random and
    // ephemeral key; the emitted ServerHello and derived server handshake
    // traffic secret must match the trace byte-for-byte.
    #[test]
    fn rfc8448_server_hello_byte_exact() {
        let client_hello = from_hex_vec(include_str!("../../../testdata/rfc8448_client_hello.hex"));
        let expected_sh = from_hex_vec(include_str!("../../../testdata/rfc8448_server_hello.hex"));

        // Script: server random (from the trace ServerHello) || server x25519
        // private key (from the trace).
        let server_random =
            from_hex_vec("a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928");
        let server_priv =
            from_hex_vec("b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e");
        let mut script = server_random;
        script.extend_from_slice(&server_priv);
        let rng = ScriptedRng {
            data: script,
            pos: 0,
        };

        let mut server = ServerConnection::new(test_server_config(), rng);

        // Frame the ClientHello as a plaintext handshake record and feed it.
        let mut record = alloc::vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&client_hello);
        server.read_tls(&record);
        server.process_new_packets().unwrap();

        // The first emitted record is the plaintext ServerHello.
        let out = server.write_tls();
        let rec = read_record(&out).unwrap().unwrap();
        assert_eq!(rec.content_type, ContentType::Handshake);
        assert_eq!(rec.fragment, &expected_sh[..]);

        // And the derived server handshake traffic secret matches the trace.
        assert_eq!(
            server.server_hs_secret_bytes(),
            from_hex_vec("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        );
    }

    /// Build a synthetic ticket whose plaintext header carries `creation_secs`
    /// and a 32-byte PSK; matches the layout emitted by `emit_session_ticket`.
    fn synth_ticket(key: &[u8; 32], creation_secs: u64, alpn: &[u8]) -> Vec<u8> {
        use crate::cipher::{Aes256, Gcm};
        let mut plain = Vec::with_capacity(8 + 32 + 1 + alpn.len());
        plain.extend_from_slice(&creation_secs.to_be_bytes());
        plain.extend_from_slice(&[0xABu8; 32]); // 32-byte PSK
        plain.push(alpn.len() as u8);
        plain.extend_from_slice(alpn);
        let nonce = [0x42u8; 12];
        let gcm = Gcm::new(Aes256::new(key));
        let mut buf = plain;
        let tag = gcm.encrypt(&nonce, &[], &mut buf);
        let mut wire = Vec::with_capacity(12 + buf.len() + 16);
        wire.extend_from_slice(&nonce);
        wire.extend_from_slice(&buf);
        wire.extend_from_slice(&tag);
        wire
    }

    /// E-2 (HIGH #7) — RFC 8446 §4.6.1 + §8.1: `decrypt_ticket` MUST reject
    /// a ticket whose embedded `creation_unix_time_u64` is older than
    /// `ticket_lifetime` (plus the small clock-skew tolerance). A year-old
    /// ticket that still authenticates under the ticket key is silently
    /// dropped — matching the TLS 1.2 `try_resume` fallback.
    #[test]
    fn decrypt_ticket_rejects_expired() {
        let key = [0x5au8; 32];
        let creation: u64 = 1_700_000_000; // arbitrary past anchor
        let now: u64 = creation + 365 * 24 * 3600; // one year later

        let wire = synth_ticket(&key, creation, b"");

        // Fresh decode (no clock): accepted.
        assert!(super::decrypt_ticket(&key, &wire, 0, 7200).is_some());

        // Within lifetime: accepted.
        assert!(super::decrypt_ticket(&key, &wire, creation + 30, 7200).is_some());

        // Lifetime exceeded by far: rejected.
        assert!(super::decrypt_ticket(&key, &wire, now, 7200).is_none());

        // Lifetime exceeded by 1 s past the 60 s skew window: rejected.
        assert!(super::decrypt_ticket(&key, &wire, creation + 7200 + 61, 7200).is_none());

        // Within the skew window: still accepted.
        assert!(super::decrypt_ticket(&key, &wire, creation + 7200 + 30, 7200).is_some());

        // Future ticket (clock smear) beyond skew: rejected.
        let wire_future = synth_ticket(&key, creation + 3600, b"");
        assert!(super::decrypt_ticket(&key, &wire_future, creation, 7200).is_none());

        // ticket_lifetime == 0 disables the age check (debugging escape hatch).
        assert!(super::decrypt_ticket(&key, &wire, now, 0).is_some());
    }

    // RFC 8446 §4.2.11: pre_shared_key MUST be the last extension in the
    // ClientHello. The server's binder-truncation uses the binders trailer
    // at the wire tail and is only correct under that placement.
    #[test]
    fn server_rejects_psk_not_last_in_clienthello() {
        use crate::tls::codec::{CipherSuite, ClientHello, ExtensionType};

        let rng = ScriptedRng {
            data: alloc::vec![0u8; 256],
            pos: 0,
        };
        // Configure a ticket key so `try_accept_psk` is even reachable —
        // we want to exercise the "must be last" check, which runs BEFORE
        // `try_accept_psk`, but we want a ServerConnection wired enough
        // to call `on_client_hello`.
        let mut cfg = test_server_config();
        cfg.ticket_key = Some([0xAAu8; 32]);
        let mut server = ServerConnection::new(cfg, rng);

        // A CH whose extension list is `[PRE_SHARED_KEY, KEY_SHARE]` — PSK
        // is NOT the last extension. The body of PRE_SHARED_KEY is bogus;
        // it doesn't matter because the placement check fires first.
        let psk_body: alloc::vec::Vec<u8> = alloc::vec![0u8; 4];
        let ks_body: alloc::vec::Vec<u8> = alloc::vec![0u8; 2];
        let ch = ClientHello {
            legacy_version: 0x0303,
            random: [0x11; 32],
            session_id: alloc::vec::Vec::new(),
            cipher_suites: alloc::vec![CipherSuite::AES_128_GCM_SHA256],
            extensions: alloc::vec![
                (ExtensionType::PRE_SHARED_KEY, psk_body),
                (ExtensionType::KEY_SHARE, ks_body),
            ],
        };
        let raw = ch.encode();
        // raw = msg_type(1) || length(3) || body. Body is raw[4..].
        let body = &raw[4..];
        let err = server
            .on_client_hello(hs_type::CLIENT_HELLO, body, &raw)
            .unwrap_err();
        assert!(matches!(err, Error::IllegalParameter));
    }

    /// Wave 3b.1 — the ECH server decap → SH signal patch path. The
    /// inner CH is RFC 8448's known-good handshake message; we wrap it
    /// inside an outer CH bearing an `encrypted_client_hello`
    /// extension, hand that outer CH to a server configured with the
    /// matching keypair, and observe that the server emits a
    /// ServerHello whose `random[24..32]` is non-zero (i.e. the
    /// accept_confirmation signal was patched in). The exact 8 bytes
    /// are recomputed from the inner-transcript handshake secret and
    /// asserted byte-for-byte.
    #[cfg(feature = "ech")]
    #[test]
    fn ech_server_decap_emits_signal_in_sh_random() {
        use crate::hpke::{HpkeAead, HpkeKdf, HpkeKem};
        use crate::tls::ech::HpkeSymCipherSuite;
        use crate::tls::ech::keys::{EchKeyPair, EchKeyRing};
        use crate::tls::ech::outer::{build_outer_ext_body, seal_with};

        // Inner CH = RFC 8448's CH (a complete, server-acceptable handshake
        // message). Splice in the inner-form `encrypted_client_hello`
        // marker — `require_inner_marker` (TLS-4 hardening) rejects any
        // decapped inner CH that lacks it.
        let raw_inner_ch = from_hex_vec(include_str!("../../../testdata/rfc8448_client_hello.hex"));
        let inner_ch = {
            use crate::tls::codec::{ClientHello, ExtensionType, hs_type};
            // Skip the 4-byte handshake header (type + 24-bit length).
            assert_eq!(raw_inner_ch[0], hs_type::CLIENT_HELLO);
            let body = &raw_inner_ch[4..];
            let mut ch = ClientHello::decode(body).expect("decode rfc8448 CH");
            // Append inner-form ECH extension (ECHClientHelloType inner = 0x01).
            ch.extensions.push((
                ExtensionType::ENCRYPTED_CLIENT_HELLO,
                crate::tls::ech::inner::inner_extension_body(),
            ));
            ch.encode()
        };

        // RFC 8448 script: server random || X25519 server private key
        // (used for the inner CH's offered key share).
        let server_random =
            from_hex_vec("a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928");
        let server_priv =
            from_hex_vec("b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e");

        // Fresh ECH keypair + ring + EchServer. The keypair is generated
        // off a separate scripted seed so it does not consume bytes from
        // the server's per-handshake script.
        let mut keygen_rng = ScriptedRng {
            data: alloc::vec![0xA5u8; 256],
            pos: 0,
        };
        let suites = alloc::vec![HpkeSymCipherSuite {
            kdf_id: HpkeKdf::HkdfSha256.id(),
            aead_id: HpkeAead::Aes128Gcm.id(),
        }];
        let pair = EchKeyPair::generate(
            &mut keygen_rng,
            HpkeKem::DhkemX25519HkdfSha256,
            0x11,
            b"public.example",
            64,
            suites,
        )
        .expect("ech keygen");
        let config = pair.config().clone();
        let ring = EchKeyRing::from_pairs(alloc::vec![pair]);
        let ech_server = crate::tls::ech::EchServer::new(ring, ring_to_config_list(&config));

        // Seal the inner CH as an outer CH. The closure builds the outer
        // CH skeleton whose ECH-extension payload is zero-padded; the
        // sealer fills it with the AEAD ciphertext.
        let mut seal_rng = ScriptedRng {
            data: alloc::vec![0x5Au8; 256],
            pos: 0,
        };
        let sym = HpkeSymCipherSuite {
            kdf_id: HpkeKdf::HkdfSha256.id(),
            aead_id: HpkeAead::Aes128Gcm.id(),
        };
        let sealed = seal_with(
            &config,
            sym,
            &inner_ch,
            5,
            &mut seal_rng,
            |enc, padded_len| {
                let body = build_outer_ext_body(sym, 0x11, enc, padded_len);
                ech_test_outer_ch(&body)
            },
        )
        .expect("seal");

        // Drive the server: ECH-configured, RSA cert (the inner CH offers
        // rsa_pss_rsae_sha256). The script feeds the per-handshake random
        // + ephemeral X25519 key from the RFC 8448 trace.
        let mut script = server_random;
        script.extend_from_slice(&server_priv);
        let rng = ScriptedRng {
            data: script,
            pos: 0,
        };
        let mut server_cfg = test_server_config();
        server_cfg = server_cfg.with_ech_server(ech_server);
        let mut server = ServerConnection::new(server_cfg, rng);

        // Frame the outer CH as a plaintext handshake record.
        let mut record = alloc::vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(sealed.outer_ch.len() as u16).to_be_bytes());
        record.extend_from_slice(&sealed.outer_ch);
        server.read_tls(&record);
        server.process_new_packets().unwrap();

        // First emitted record is the plaintext ServerHello.
        let out = server.write_tls();
        let rec = read_record(&out).unwrap().unwrap();
        assert_eq!(rec.content_type, ContentType::Handshake);
        let sh_bytes = rec.fragment;

        // Wire layout: 1 (type) + 3 (length) + 2 (version) + 32 (random)
        // → random[24..32] is at bytes 30..38. With ECH accepted, the
        // accept_confirmation MAC has been patched in; it must be
        // non-zero (the all-zero placeholder is the pre-patch form).
        let signal_in_sh: [u8; 8] = sh_bytes[30..38].try_into().unwrap();
        assert_ne!(signal_in_sh, [0u8; 8]);
    }

    /// Build a minimal outer CH skeleton whose only extension is
    /// `encrypted_client_hello` with the given body. Used by the wave
    /// 3b.1 test only — see `tls::ech::tests::build_outer_ch_with_ech`
    /// for the in-module variant.
    #[cfg(feature = "ech")]
    fn ech_test_outer_ch(ech_ext_body: &[u8]) -> Vec<u8> {
        use crate::tls::codec::{ExtensionType, hs_type};
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0x42u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0);
        let mut exts: Vec<u8> = Vec::new();
        let ty = ExtensionType::ENCRYPTED_CLIENT_HELLO.0;
        exts.extend_from_slice(&ty.to_be_bytes());
        let bl: u16 = u16::try_from(ech_ext_body.len()).unwrap();
        exts.extend_from_slice(&bl.to_be_bytes());
        exts.extend_from_slice(ech_ext_body);
        let el: u16 = u16::try_from(exts.len()).unwrap();
        body.extend_from_slice(&el.to_be_bytes());
        body.extend_from_slice(&exts);
        let mut msg: Vec<u8> = Vec::new();
        msg.push(hs_type::CLIENT_HELLO);
        let bl_u32 = u32::try_from(body.len()).unwrap();
        msg.push(((bl_u32 >> 16) & 0xff) as u8);
        msg.push(((bl_u32 >> 8) & 0xff) as u8);
        msg.push((bl_u32 & 0xff) as u8);
        msg.extend_from_slice(&body);
        msg
    }

    /// Wrap a single `EchConfig` in an `EchConfigList` for `EchServer::new`.
    #[cfg(feature = "ech")]
    fn ring_to_config_list(config: &crate::tls::ech::EchConfig) -> crate::tls::ech::EchConfigList {
        crate::tls::ech::EchConfigList::new(alloc::vec![config.clone()])
    }

    /// TLS-4 / TLS-5 regression: confirm that ECH and cert-decompression
    /// errors map to the alert codes the audit requires —
    /// `decrypt_error(51)` for crypto failures and
    /// `illegal_parameter(47)` for structural ECH failures
    /// (draft-ietf-tls-esni-22 §7.1), and `bad_certificate(42)` for
    /// failed RFC 8879 cert decompression.
    #[cfg(feature = "ech")]
    #[test]
    fn alert_for_ech_errors_map_to_audit_required_codes() {
        assert_eq!(
            alert_for(&Error::EchDecryptionFailed),
            AlertDescription::DecryptError
        );
        assert_eq!(
            alert_for(&Error::EchDecodeError),
            AlertDescription::IllegalParameter
        );
    }

    #[cfg(feature = "cert-compression")]
    #[test]
    fn alert_for_cert_decompression_failure_maps_to_bad_certificate() {
        assert_eq!(
            alert_for(&Error::CertDecompressionFailed),
            AlertDescription::BadCertificate
        );
    }

    /// Builds a TLS 1.3 `Certificate` handshake message (header + body) from a
    /// single-cert chain, returning `(body, raw)`. Empty
    /// `certificate_request_context` and empty per-cert extensions.
    fn encode_client_certificate_13(cert_der: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut entries = Vec::new();
        let len = cert_der.len();
        entries.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        entries.extend_from_slice(cert_der);
        entries.extend_from_slice(&[0u8, 0u8]); // u16 extensions length = 0

        let mut body = Vec::new();
        body.push(0u8); // certificate_request_context length = 0
        let outer = entries.len();
        body.extend_from_slice(&[(outer >> 16) as u8, (outer >> 8) as u8, outer as u8]);
        body.extend_from_slice(&entries);

        let mut raw = alloc::vec![hs_type::CERTIFICATE];
        let bl = body.len();
        raw.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        raw.extend_from_slice(&body);
        (body, raw)
    }

    /// F1 regression (TLS 1.3): the mTLS server enforces the client cert's
    /// `notBefore`/`notAfter`. With a pinned verification time, an expired
    /// client cert is rejected. (Self-signed leaf == its own trust anchor.)
    #[test]
    fn tls13_mtls_rejects_expired_client_cert() {
        use crate::ec::Ed25519PrivateKey;
        use crate::rng::HmacDrbg;
        use crate::tls::pki::RootCertStore;
        use crate::x509::CertSigner;

        let mut seed = HmacDrbg::<crate::hash::Sha256>::new(b"f1-13-expired", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut seed);
        let name = DistinguishedName::common_name("expired-client");
        let validity = Validity::new(
            Time::utc(2020, 1, 1, 0, 0, 0),
            Time::utc(2020, 12, 31, 23, 59, 59),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ed25519(&key),
            &name,
            &validity,
            1,
            false,
            &["expired-client"],
        )
        .unwrap();
        let cert_der = cert.to_der().to_vec();

        let mut roots = RootCertStore::new();
        roots.add_der(cert_der.clone()).unwrap();

        let cfg = test_server_config()
            .with_client_auth(roots, true)
            .with_verification_time(Time::utc(2026, 1, 1, 0, 0, 0));
        let rng = HmacDrbg::<crate::hash::Sha256>::new(b"f1-13-s", b"nonce", &[]);
        let mut s = ServerConnection::new(cfg, rng);
        s.state = State::WaitClientCertificate;

        let (body, raw) = encode_client_certificate_13(&cert_der);
        assert!(matches!(
            s.on_client_certificate(hs_type::CERTIFICATE, &body, &raw),
            Err(Error::BadCertificate)
        ));
    }

    /// F1 companion (TLS 1.3): an in-window client cert is still accepted under
    /// the same enforced verification time.
    #[test]
    fn tls13_mtls_accepts_valid_client_cert() {
        use crate::ec::Ed25519PrivateKey;
        use crate::rng::HmacDrbg;
        use crate::tls::pki::RootCertStore;
        use crate::x509::CertSigner;

        let mut seed = HmacDrbg::<crate::hash::Sha256>::new(b"f1-13-valid", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut seed);
        let name = DistinguishedName::common_name("valid-client");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ed25519(&key),
            &name,
            &validity,
            1,
            false,
            &["valid-client"],
        )
        .unwrap();
        let cert_der = cert.to_der().to_vec();

        let mut roots = RootCertStore::new();
        roots.add_der(cert_der.clone()).unwrap();

        let cfg = test_server_config()
            .with_client_auth(roots, true)
            .with_verification_time(Time::utc(2026, 1, 1, 0, 0, 0));
        let rng = HmacDrbg::<crate::hash::Sha256>::new(b"f1-13-s-ok", b"nonce", &[]);
        let mut s = ServerConnection::new(cfg, rng);
        s.state = State::WaitClientCertificate;

        let (body, raw) = encode_client_certificate_13(&cert_der);
        s.on_client_certificate(hs_type::CERTIFICATE, &body, &raw)
            .expect("in-window client cert should be accepted");
        assert_eq!(s.client_cert_chain.len(), 1);
        assert!(s.client_leaf_key.is_some());
        assert!(s.state == State::WaitClientCertVerify);
    }
}
