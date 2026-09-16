//! Fuzz-only entry points for the crate-private TLS decoders.
//!
//! INTERNAL. Compiled only under the hidden `__fuzz` cargo feature, which
//! exists for the `fuzz/` crate and nothing else; nothing here is part of
//! the public API and it may change or vanish without notice.
//!
//! The handshake-message and extension decoders are `pub(crate)`, and the
//! encrypted-flight handlers (EncryptedExtensions, Certificate,
//! CertificateRequest, CertificateVerify, KeyUpdate, NewSessionTicket) sit
//! behind a completed key exchange in the `Connection::feed` fuzz targets —
//! a fuzzer never gets a ServerHello past the client's key-share check, so
//! it never reaches them. Each `pub fn` here hands raw bytes straight to one
//! decoder (or to the real engine handler on a fresh, deterministic
//! client), and [`dispatch`](crate::tls::fuzz::dispatch) selects among them on the first input byte so
//! a single target covers the lot.
//!
//! Every wrapper discards the decoded value: the point is to surface
//! panics, not to expose the crate-private types.

use crate::hash::Sha256;
use crate::rng::HmacDrbg;
use crate::tls::codec::extension as ext;
use crate::tls::codec::{
    self, CertificateRequest12, CipherSuite, ClientHello, ClientKeyExchange, KeyUpdate, NamedGroup,
    NewSessionTicket, NewSessionTicket12, ReadCursor, ServerHello, ServerHelloDone,
    ServerKeyExchange, hs_type, read_handshake,
};
use crate::tls::conn::{ClientConfig, ClientConnection};
use crate::tls::{Error, RootCertStore};
use alloc::vec::Vec;

/// Selector values understood by [`dispatch`](crate::tls::fuzz::dispatch): the first input byte picks
/// the decoder, the rest is its input.
pub mod selector {
    /// [`handshake_header`](super::handshake_header).
    pub const HANDSHAKE_HEADER: u8 = 0;
    /// [`client_hello`](super::client_hello).
    pub const CLIENT_HELLO: u8 = 1;
    /// [`server_hello`](super::server_hello).
    pub const SERVER_HELLO: u8 = 2;
    /// [`encrypted_extensions`](super::encrypted_extensions).
    pub const ENCRYPTED_EXTENSIONS: u8 = 3;
    /// [`certificate`](super::certificate).
    pub const CERTIFICATE: u8 = 4;
    /// [`certificate_request`](super::certificate_request).
    pub const CERTIFICATE_REQUEST: u8 = 5;
    /// [`certificate_verify`](super::certificate_verify).
    pub const CERTIFICATE_VERIFY: u8 = 6;
    /// [`new_session_ticket`](super::new_session_ticket).
    pub const NEW_SESSION_TICKET: u8 = 7;
    /// [`key_update`](super::key_update).
    pub const KEY_UPDATE: u8 = 8;
    /// [`end_of_early_data`](super::end_of_early_data).
    pub const END_OF_EARLY_DATA: u8 = 9;
    /// [`certificate_list`](super::certificate_list).
    pub const CERTIFICATE_LIST: u8 = 10;
    /// [`certificate_list_server`](super::certificate_list_server).
    pub const CERTIFICATE_LIST_SERVER: u8 = 11;
    /// [`extensions_block`](super::extensions_block).
    pub const EXTENSIONS_BLOCK: u8 = 12;
    /// [`alert`](super::alert).
    pub const ALERT: u8 = 13;
    /// [`record`](super::record).
    pub const RECORD: u8 = 14;
    /// [`server_key_exchange`](super::server_key_exchange).
    pub const SERVER_KEY_EXCHANGE: u8 = 20;
    /// [`client_key_exchange`](super::client_key_exchange).
    pub const CLIENT_KEY_EXCHANGE: u8 = 21;
    /// [`rsa_client_key_exchange`](super::rsa_client_key_exchange).
    pub const RSA_CLIENT_KEY_EXCHANGE: u8 = 22;
    /// [`certificate_request12`](super::certificate_request12).
    pub const CERTIFICATE_REQUEST12: u8 = 23;
    /// [`server_hello_done`](super::server_hello_done).
    pub const SERVER_HELLO_DONE: u8 = 24;
    /// [`new_session_ticket12`](super::new_session_ticket12).
    pub const NEW_SESSION_TICKET12: u8 = 25;
    /// [`server_hello_relaxed`](super::server_hello_relaxed) (`tls-legacy`).
    pub const SERVER_HELLO_RELAXED: u8 = 26;
    /// [`server_key_exchange_legacy`](super::server_key_exchange_legacy)
    /// (`tls-legacy`).
    pub const SERVER_KEY_EXCHANGE_LEGACY: u8 = 27;
    /// [`ech_extension`](super::ech_extension) (`ech`).
    pub const ECH_EXTENSION: u8 = 30;
    /// [`ech_config_list`](super::ech_config_list) (`ech`).
    pub const ECH_CONFIG_LIST: u8 = 31;
    /// [`ech_retry_configs`](super::ech_retry_configs) (`ech`).
    pub const ECH_RETRY_CONFIGS: u8 = 32;
    /// [`ech_outer_position`](super::ech_outer_position) (`ech`).
    pub const ECH_OUTER_POSITION: u8 = 33;
    /// [`extension_body`](super::extension_body): the next byte picks the
    /// extension-body parser.
    pub const EXTENSION_BODY: u8 = 40;
}

/// Runs the decoder selected by `data[0]` on `data[1..]`, ignoring the
/// result. Unknown selectors and empty input are no-ops. This is what the
/// `tls_handshake_messages` fuzz target calls.
pub fn dispatch(data: &[u8]) {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    use selector::*;
    match sel {
        HANDSHAKE_HEADER => drop(handshake_header(body)),
        CLIENT_HELLO => drop(client_hello(body)),
        SERVER_HELLO => drop(server_hello(body)),
        ENCRYPTED_EXTENSIONS => drop(encrypted_extensions(body)),
        CERTIFICATE => drop(certificate(body)),
        CERTIFICATE_REQUEST => drop(certificate_request(body)),
        CERTIFICATE_VERIFY => drop(certificate_verify(body)),
        NEW_SESSION_TICKET => drop(new_session_ticket(body)),
        KEY_UPDATE => drop(key_update(body)),
        END_OF_EARLY_DATA => drop(end_of_early_data(body)),
        CERTIFICATE_LIST => drop(certificate_list(body)),
        CERTIFICATE_LIST_SERVER => drop(certificate_list_server(body)),
        EXTENSIONS_BLOCK => drop(extensions_block(body)),
        ALERT => drop(alert(body)),
        RECORD => drop(record(body)),
        SERVER_KEY_EXCHANGE => drop(server_key_exchange(body)),
        CLIENT_KEY_EXCHANGE => drop(client_key_exchange(body)),
        #[cfg(feature = "tls-legacy")]
        RSA_CLIENT_KEY_EXCHANGE => {
            if let Some((&ssl3, rest)) = body.split_first() {
                drop(rsa_client_key_exchange(rest, ssl3 & 1 == 1));
            }
        }
        CERTIFICATE_REQUEST12 => drop(certificate_request12(body)),
        SERVER_HELLO_DONE => drop(server_hello_done(body)),
        NEW_SESSION_TICKET12 => drop(new_session_ticket12(body)),
        #[cfg(feature = "tls-legacy")]
        SERVER_HELLO_RELAXED => drop(server_hello_relaxed(body)),
        #[cfg(feature = "tls-legacy")]
        SERVER_KEY_EXCHANGE_LEGACY => drop(server_key_exchange_legacy(body)),
        #[cfg(feature = "ech")]
        ECH_EXTENSION => drop(ech_extension(body)),
        #[cfg(feature = "ech")]
        ECH_CONFIG_LIST => drop(ech_config_list(body)),
        #[cfg(feature = "ech")]
        ECH_RETRY_CONFIGS => drop(ech_retry_configs(body)),
        #[cfg(feature = "ech")]
        ECH_OUTER_POSITION => drop(ech_outer_position(body)),
        EXTENSION_BODY => {
            if let Some((&which, rest)) = body.split_first() {
                drop(extension_body(which, rest));
            }
        }
        _ => {}
    }
}

// ---- Framing / record layer -------------------------------------------

/// Parses a handshake-message header (`type ‖ u24 length ‖ body`) and
/// returns the type and body length.
pub fn handshake_header(bytes: &[u8]) -> Result<(u8, usize), Error> {
    let mut c = ReadCursor::new(bytes);
    let (ty, body) = read_handshake(&mut c)?;
    Ok((ty, body.len()))
}

/// Parses a TLS record header + fragment (`read_record`).
pub fn record(bytes: &[u8]) -> Result<(), Error> {
    codec::read_record(bytes).map(drop)
}

/// Parses a two-byte alert body.
pub fn alert(body: &[u8]) -> Result<(), Error> {
    crate::tls::conn::parse_alert(body).map(drop)
}

/// Parses a `u16`-length-prefixed extensions vector into `(type, body)`
/// pairs, with the duplicate / count checks the hello decoders apply.
pub fn extensions_block(bytes: &[u8]) -> Result<(), Error> {
    codec::parse_extensions(bytes).map(drop)
}

// ---- TLS 1.3 handshake messages ---------------------------------------

/// `ClientHello` body decoder (the server's first untrusted input).
pub fn client_hello(body: &[u8]) -> Result<(), Error> {
    ClientHello::decode(body).map(drop)
}

/// `ServerHello` / `HelloRetryRequest` body decoder.
pub fn server_hello(body: &[u8]) -> Result<(), Error> {
    ServerHello::decode(body).map(drop)
}

/// `ServerHello` decoder that also admits a pre-1.2 `server_version`
/// (`tls-legacy`).
#[cfg(feature = "tls-legacy")]
pub fn server_hello_relaxed(body: &[u8]) -> Result<(), Error> {
    ServerHello::decode_relaxed(body).map(drop)
}

/// `KeyUpdate` body decoder.
pub fn key_update(body: &[u8]) -> Result<(), Error> {
    KeyUpdate::decode(body).map(drop)
}

/// TLS 1.3 `NewSessionTicket` body decoder.
pub fn new_session_ticket(body: &[u8]) -> Result<(), Error> {
    NewSessionTicket::decode(body).map(drop)
}

/// `EndOfEarlyData` has an empty body; anything else is a decode error.
pub fn end_of_early_data(body: &[u8]) -> Result<(), Error> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(Error::Decode)
    }
}

/// TLS 1.3 `Certificate` body → `(cert_der, extensions)` entries, the
/// client-side parser (per-entry extensions are decoded and checked).
pub fn certificate_list(body: &[u8]) -> Result<(), Error> {
    crate::tls::conn::parse_certificate_list_client(body).map(drop)
}

/// TLS 1.3 `Certificate` body → DER list, the server-side (mTLS) parser.
pub fn certificate_list_server(body: &[u8]) -> Result<(), Error> {
    crate::tls::conn::parse_certificate_list_server(body).map(drop)
}

/// A fresh, deterministic TLS 1.3 client engine (X25519 only, so building
/// it costs one keypair) whose encrypted-flight handlers the wrappers
/// below drive directly. Each call gets its own: no state leaks between
/// fuzz iterations.
fn fresh_client() -> ClientConnection {
    let mut rng = HmacDrbg::<Sha256>::new(b"purecrypto-fuzz", b"tls-client", &[]);
    ClientConnection::new_with_offer(
        ClientConfig::new(RootCertStore::new()),
        "fuzz.example",
        &mut rng,
        &[CipherSuite::AES_128_GCM_SHA256],
        &[NamedGroup::X25519],
    )
}

/// `body` wrapped in a handshake header of type `ty`.
fn frame(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(4 + body.len());
    raw.push(ty);
    raw.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    raw.extend_from_slice(body);
    raw
}

/// Runs the client's real `EncryptedExtensions` handler on `body`: the
/// extension walk, the RFC 8446 §4.2 "did we offer it" table, ALPN /
/// early_data / record_size_limit / cert-type / ECH retry-config parsing.
pub fn encrypted_extensions(body: &[u8]) -> Result<(), Error> {
    let raw = frame(hs_type::ENCRYPTED_EXTENSIONS, body);
    fresh_client().on_encrypted_extensions(hs_type::ENCRYPTED_EXTENSIONS, &raw)
}

/// Runs the client's real `Certificate` handler on `body`: the entry
/// parser, then X.509 decoding and chain building against an empty root
/// store (so it always ends in `BadCertificate`, after parsing every DER
/// the fuzzer hands it).
pub fn certificate(body: &[u8]) -> Result<(), Error> {
    let raw = frame(hs_type::CERTIFICATE, body);
    fresh_client().on_certificate(hs_type::CERTIFICATE, body, &raw)
}

/// Runs the client's real `CertificateRequest` handler on `body`
/// (context, extensions, mandatory `signature_algorithms`).
pub fn certificate_request(body: &[u8]) -> Result<(), Error> {
    let raw = frame(hs_type::CERTIFICATE_REQUEST, body);
    fresh_client().on_certificate(hs_type::CERTIFICATE_REQUEST, body, &raw)
}

/// Runs the client's real `CertificateVerify` handler on `body` (scheme +
/// signature parse and the scheme-policy checks; there is no peer key on a
/// fresh client, so it stops before any verification).
pub fn certificate_verify(body: &[u8]) -> Result<(), Error> {
    let raw = frame(hs_type::CERTIFICATE_VERIFY, body);
    fresh_client().on_certificate_verify(hs_type::CERTIFICATE_VERIFY, body, &raw)
}

/// Runs the client's real `KeyUpdate` handler on `body` (decode + flood
/// guard; no traffic keys on a fresh client, so it stops before rekeying).
pub fn key_update_message(body: &[u8]) -> Result<(), Error> {
    fresh_client().handle_key_update(body)
}

// ---- TLS 1.2 handshake messages ---------------------------------------

/// TLS 1.2 `ServerKeyExchange` (ECDHE, signed) body decoder.
pub fn server_key_exchange(body: &[u8]) -> Result<(), Error> {
    ServerKeyExchange::decode(body).map(drop)
}

/// TLS 1.0/1.1 `ServerKeyExchange` body decoder (`tls-legacy`; no
/// `signature_algorithms` prefix).
#[cfg(feature = "tls-legacy")]
pub fn server_key_exchange_legacy(body: &[u8]) -> Result<(), Error> {
    ServerKeyExchange::decode_legacy(body).map(drop)
}

/// TLS 1.2 ECDHE `ClientKeyExchange` body decoder.
pub fn client_key_exchange(body: &[u8]) -> Result<(), Error> {
    ClientKeyExchange::decode(body).map(drop)
}

/// TLS 1.2 static-RSA `ClientKeyExchange` body decoder; `ssl3` selects
/// the SSL 3.0 framing (no length prefix). Only present with `tls-legacy`.
#[cfg(feature = "tls-legacy")]
pub fn rsa_client_key_exchange(body: &[u8], ssl3: bool) -> Result<(), Error> {
    codec::handshake12::RsaClientKeyExchange::decode(body, ssl3).map(drop)
}

/// TLS 1.2 `CertificateRequest` body decoder.
pub fn certificate_request12(body: &[u8]) -> Result<(), Error> {
    CertificateRequest12::decode(body).map(drop)
}

/// TLS 1.2 `ServerHelloDone` body decoder (must be empty).
pub fn server_hello_done(body: &[u8]) -> Result<(), Error> {
    ServerHelloDone::decode(body).map(drop)
}

/// TLS 1.2 `NewSessionTicket` (RFC 5077) body decoder.
pub fn new_session_ticket12(body: &[u8]) -> Result<(), Error> {
    NewSessionTicket12::decode(body).map(drop)
}

// ---- ECH ----------------------------------------------------------------

/// `encrypted_client_hello` extension body decoder (outer / inner forms).
#[cfg(feature = "ech")]
pub fn ech_extension(body: &[u8]) -> Result<(), Error> {
    crate::tls::ech::extension::EchExtension::decode(body).map(drop)
}

/// `ECHConfigList` decoder (DNS / `.well-known` / retry-config input).
#[cfg(feature = "ech")]
pub fn ech_config_list(body: &[u8]) -> Result<(), Error> {
    crate::tls::ech::EchConfigList::decode(body).map(drop)
}

/// `retry_configs` (EncryptedExtensions ECH body) decoder.
#[cfg(feature = "ech")]
pub fn ech_retry_configs(body: &[u8]) -> Result<(), Error> {
    crate::tls::ech::retry::decode_retry_configs(body).map(drop)
}

/// Locates the `payload` field inside an outer-form ECH extension body.
#[cfg(feature = "ech")]
pub fn ech_outer_position(body: &[u8]) -> Result<(), Error> {
    crate::tls::ech::extension::decode_outer_position(body).map(drop)
}

// ---- Extension bodies ---------------------------------------------------

/// Runs one extension-body parser, selected by `which`, on `body`:
///
/// | `which` | parser |
/// |---|---|
/// | 0 | `supported_versions` (server selection) |
/// | 1 | `supported_groups` |
/// | 2 | `signature_algorithms` |
/// | 3 | `application_layer_protocol_negotiation` |
/// | 4 | `ec_point_formats` |
/// | 5 | `renegotiation_info` |
/// | 6 | `extended_master_secret` |
/// | 7 | `record_size_limit` (client) |
/// | 8 | `record_size_limit` (server) |
/// | 9 | `status_request` |
/// | 10 | `status_request` ServerHello ack |
/// | 11 | `CertificateStatus` body |
/// | 12 | `client_certificate_type` / `server_certificate_type` list |
/// | 13 | cert-type selection |
/// | 14 | `server_name` |
/// | 15 | `key_share` (server) |
/// | 16 | `key_share` (HelloRetryRequest) |
/// | 17 | `key_share` (client) |
/// | 18 | `psk_key_exchange_modes` |
/// | 19 | `pre_shared_key` (client) |
/// | 20 | `supported_versions` (client; "offers TLS 1.3?") |
///
/// Anything else is a no-op `Ok`.
pub fn extension_body(which: u8, body: &[u8]) -> Result<(), Error> {
    match which {
        0 => ext::parse_selected_version(body).map(drop),
        1 => ext::parse_supported_groups(body).map(drop),
        2 => ext::parse_signature_algorithms(body).map(drop),
        3 => ext::parse_alpn(body).map(drop),
        4 => ext::parse_ec_point_formats(body).map(drop),
        5 => ext::parse_renegotiation_info(body).map(drop),
        6 => ext::parse_extended_master_secret(body),
        7 => ext::parse_record_size_limit(body).map(drop),
        8 => ext::parse_record_size_limit_server(body).map(drop),
        9 => ext::parse_status_request(body),
        10 => ext::parse_status_request_sh_ack(body),
        11 => ext::parse_certificate_status(body).map(drop),
        12 => ext::parse_cert_type_list(body).map(drop),
        13 => ext::parse_cert_type_selection(body).map(drop),
        14 => ext::parse_server_name(body).map(drop),
        15 => ext::parse_server_key_share(body).map(drop),
        16 => ext::parse_hrr_key_share(body).map(drop),
        17 => ext::parse_client_key_shares(body).map(drop),
        18 => ext::parse_psk_key_exchange_modes(body).map(drop),
        19 => ext::parse_client_pre_shared_key(body).map(drop),
        20 => ext::client_offers_tls13(body).map(drop),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: every selector runs on a handful of inputs without
    /// panicking, and a few well-formed messages decode. This is what
    /// keeps the fuzz surface compiling under `cargo test --all-features`.
    #[test]
    fn dispatch_runs_every_selector() {
        dispatch(&[]);
        for sel in 0u8..=48 {
            dispatch(&[sel]);
            dispatch(&[sel, 0]);
            dispatch(&[sel, 0, 0, 0, 0]);
            dispatch(&[sel, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        }
        for which in 0u8..=24 {
            dispatch(&[selector::EXTENSION_BODY, which]);
            dispatch(&[selector::EXTENSION_BODY, which, 0, 2, 0, 0]);
        }
        // Well-formed inputs decode.
        assert_eq!(handshake_header(&[24, 0, 0, 1, 0]).unwrap(), (24, 1));
        key_update(&[0]).unwrap();
        key_update(&[1]).unwrap();
        assert!(key_update(&[2]).is_err());
        end_of_early_data(&[]).unwrap();
        assert!(end_of_early_data(&[0]).is_err());
        server_hello_done(&[]).unwrap();
        alert(&[1, 0]).unwrap();
        assert!(alert(&[1]).is_err());
        // An empty EncryptedExtensions is legal on a default client.
        encrypted_extensions(&[0, 0]).unwrap();
        // A CertificateRequest with an empty context and no
        // signature_algorithms is a missing_extension.
        assert!(matches!(
            certificate_request(&[0, 0, 0]),
            Err(Error::MissingExtension)
        ));
        // A Certificate with an empty entry list: nothing to verify.
        assert!(certificate(&[0, 0, 0, 0]).is_err());
        // CertificateVerify: an rsa_pkcs1 scheme is refused before any
        // verification is attempted.
        assert!(matches!(
            certificate_verify(&[0x04, 0x01, 0, 0]),
            Err(Error::IllegalParameter)
        ));
    }
}
