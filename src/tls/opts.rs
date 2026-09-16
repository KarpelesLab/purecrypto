//! [`Config`] taken apart into the option groups the engine builders consume.
//!
//! `tls::Config` is one struct for every protocol (TLS 1.2 / 1.3, DTLS 1.2 /
//! 1.3, QUIC) and both roles, but each engine has its own config type, so a
//! hand-written builder per engine translates the shared `Config` into it.
//! Those builders used to drift: an option added to `Config` and wired into
//! one engine was silently ignored by the others. [`Config::parts`] is the
//! compile-time guard against that. It destructures `Config` **without**
//! `..`, and every builder destructures the groups it consumes the same way,
//! so adding a field to `Config` fails to compile here and then in each
//! builder, until that builder forwards the option, refuses the config (fail
//! closed), or names it in a `let _ = field;` with a comment saying why it is
//! inert for that engine.
//!
//! A field belongs to exactly one group:
//!
//! * [`CommonOpts`] — consumed by every (protocol, role) builder;
//! * [`ClientOpts`] / [`ServerOpts`] — consumed by the builders of that role;
//! * [`DtlsOpts`] — consumed by the DTLS builders (documented inert under
//!   TLS and QUIC, so their builders do not look at it).

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::signature_registry::SignaturePolicy;
use crate::x509::Time;

use super::config::{ClientAuth, Config, EntropySource, Identity};
use super::connection::ResumptionSession;
use super::groups::NamedGroup;
use super::keylog::KeyLog;
use super::pki::{CrlStore, RootCertStore};
use super::secret::Secret32;
use super::signer::HandshakeSigner;
use super::version::ProtocolVersion;

#[cfg(feature = "std")]
use super::conn::ReplayWindow;

/// A [`Config`] borrowed as its option groups. See the [module docs](self).
pub(crate) struct ConfigParts<'a> {
    /// Options every builder consumes.
    pub common: CommonOpts<'a>,
    /// Options only client builders consume.
    pub client: ClientOpts<'a>,
    /// Options only server builders consume.
    pub server: ServerOpts<'a>,
    /// Options only DTLS builders consume.
    #[cfg_attr(not(feature = "dtls"), allow(dead_code))]
    pub dtls: DtlsOpts<'a>,
}

/// Options that concern both roles of every protocol.
pub(crate) struct CommonOpts<'a> {
    pub min_version: ProtocolVersion,
    pub max_version: ProtocolVersion,
    pub identity: Option<&'a Identity>,
    pub roots: &'a RootCertStore,
    pub crls: &'a CrlStore,
    pub signature_policy: &'a SignaturePolicy,
    pub verification_time: Option<&'a Time>,
    pub alpn_protocols: &'a [Vec<u8>],
    pub record_size_limit: Option<u16>,
    pub require_extended_master_secret: bool,
    pub server_cert_type_preference: &'a [u8],
    pub client_cert_type_preference: &'a [u8],
    pub raw_public_key_spki: Option<&'a [u8]>,
    #[cfg(feature = "cert-compression")]
    pub cert_compression_algorithms: &'a [u16],
    pub key_log: &'a Option<Arc<dyn KeyLog>>,
    pub rng: &'a Option<Arc<dyn EntropySource>>,
    pub signer: &'a Option<Arc<dyn HandshakeSigner>>,
}

/// Options only a client consumes.
pub(crate) struct ClientOpts<'a> {
    pub server_name: Option<&'a str>,
    pub verify_certificates: bool,
    pub cipher_suites: Option<&'a [u16]>,
    pub expected_raw_public_keys: &'a [Vec<u8>],
    #[cfg(feature = "ech")]
    pub ech: &'a Option<super::ech::EchClient>,
    pub resumption: &'a Option<ResumptionSession>,
}

/// Options only a server consumes.
pub(crate) struct ServerOpts<'a> {
    pub client_auth: Option<&'a ClientAuth>,
    pub stapled_crl: Option<&'a [u8]>,
    pub stapled_ocsp_response: Option<&'a [u8]>,
    pub ticket_key: Option<&'a Secret32>,
    pub max_early_data_size: u32,
    #[cfg(feature = "std")]
    pub replay_window: Option<&'a ReplayWindow>,
    pub expected_client_raw_public_keys: &'a [Vec<u8>],
    pub preferred_key_exchange_group: Option<NamedGroup>,
    #[cfg(feature = "ech")]
    pub ech_server: &'a Option<super::ech::EchServer>,
}

/// Options only the DTLS engines consume.
#[cfg_attr(not(feature = "dtls"), allow(dead_code))]
pub(crate) struct DtlsOpts<'a> {
    pub cookie_secret: Option<&'a Secret32>,
    pub previous_cookie_secret: Option<&'a Secret32>,
    pub require_cookie: bool,
    pub max_record_size: usize,
    pub peer_address: &'a [u8],
}

impl Config {
    /// Borrows this config as the option groups the engine builders consume.
    ///
    /// Adding a field to `Config` fails to compile here until the field is
    /// placed in a group — and then in every builder that destructures that
    /// group. Do not add `..` to the pattern below.
    pub(crate) fn parts(&self) -> ConfigParts<'_> {
        let Config {
            min_version,
            max_version,
            identity,
            roots,
            crls,
            signature_policy,
            server_name,
            verify_certificates,
            verification_time,
            client_auth,
            stapled_crl,
            stapled_ocsp_response,
            ticket_key,
            max_early_data_size,
            #[cfg(feature = "std")]
            replay_window,
            alpn_protocols,
            cipher_suites,
            record_size_limit,
            require_extended_master_secret,
            server_cert_type_preference,
            client_cert_type_preference,
            raw_public_key_spki,
            expected_raw_public_keys,
            expected_client_raw_public_keys,
            preferred_key_exchange_group,
            #[cfg(feature = "ech")]
            ech,
            #[cfg(feature = "ech")]
            ech_server,
            #[cfg(feature = "cert-compression")]
            cert_compression_algorithms,
            cookie_secret,
            previous_cookie_secret,
            require_cookie,
            max_record_size,
            peer_address,
            key_log,
            rng,
            signer,
            resumption,
        } = self;
        ConfigParts {
            common: CommonOpts {
                min_version: *min_version,
                max_version: *max_version,
                identity: identity.as_ref(),
                roots,
                crls,
                signature_policy,
                verification_time: verification_time.as_ref(),
                alpn_protocols,
                record_size_limit: *record_size_limit,
                require_extended_master_secret: *require_extended_master_secret,
                server_cert_type_preference,
                client_cert_type_preference,
                raw_public_key_spki: raw_public_key_spki.as_deref(),
                #[cfg(feature = "cert-compression")]
                cert_compression_algorithms,
                key_log,
                rng,
                signer,
            },
            client: ClientOpts {
                server_name: server_name.as_deref(),
                verify_certificates: *verify_certificates,
                cipher_suites: cipher_suites.as_deref(),
                expected_raw_public_keys,
                #[cfg(feature = "ech")]
                ech,
                resumption,
            },
            server: ServerOpts {
                client_auth: client_auth.as_ref(),
                stapled_crl: stapled_crl.as_deref(),
                stapled_ocsp_response: stapled_ocsp_response.as_deref(),
                ticket_key: ticket_key.as_ref(),
                max_early_data_size: *max_early_data_size,
                #[cfg(feature = "std")]
                replay_window: replay_window.as_ref(),
                expected_client_raw_public_keys,
                preferred_key_exchange_group: *preferred_key_exchange_group,
                #[cfg(feature = "ech")]
                ech_server,
            },
            dtls: DtlsOpts {
                cookie_secret: cookie_secret.as_ref(),
                previous_cookie_secret: previous_cookie_secret.as_ref(),
                require_cookie: *require_cookie,
                max_record_size: *max_record_size,
                peer_address,
            },
        }
    }
}
