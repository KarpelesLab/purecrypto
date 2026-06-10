//! Fuzz the legacy-TLS (SSLv3 / TLS 1.0 / TLS 1.1, `tls-legacy`
//! feature) wire-input path, in both roles. The modern feed targets
//! never reach this code: the legacy record layer (CBC mac-then-encrypt
//! with SSLv3 MAC / implicit-IV TLS 1.0 paths), the SSL3/TLS1.x PRFs,
//! and the static-RSA ClientKeyExchange parser only run when
//! `min_version` is lowered at runtime, mirroring how
//! `examples/tls_legacy_interop.rs` configures its connections.
//!
//! Both directions matter: the server side parses legacy ClientHello +
//! ClientKeyExchange (static-RSA premaster decrypt) from anonymous
//! peers, the client side parses legacy ServerHello / Certificate /
//! ServerKeyExchange from a malicious server. Each iteration feeds the
//! same bytes to one server and one client connection — per-iteration
//! cost stays bounded because almost all inputs die in the record
//! layer, and the version span SSLv3..TLS1.1 keeps every legacy
//! version-dispatch branch reachable from one target.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
use purecrypto::tls::{Config, Connection, ProtocolVersion, RootCertStore, SigningKey};
use purecrypto::x509::{Certificate, DistinguishedName, Time, Validity};
use std::sync::OnceLock;

const SERVER_KEY_PEM: &str = include_str!("../../testdata/rsa2048_test_a.pem");

/// Legacy handshake flights are small; cap the per-iteration input.
const MAX_INPUT: usize = 64 * 1024;

struct Identity {
    server_cfg: Config,
    client_cfg: Config,
}

static IDENTITY: OnceLock<Identity> = OnceLock::new();

fn identity() -> &'static Identity {
    IDENTITY.get_or_init(|| {
        // Static-RSA key transport requires an RSA identity; the
        // deterministic test key + self-signed cert mirror the modern
        // tls_server_feed / tls_client_feed targets.
        let signing_key = RsaPrivateKey::<32>::from_pkcs1_pem(SERVER_KEY_PEM).unwrap();
        let name = DistinguishedName::common_name("fuzz.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2099, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed(&signing_key, &name, &validity, 1, false).unwrap();
        let cert_der = cert.to_der().to_vec();
        let server_key = BoxedRsaPrivateKey::from_pkcs1_pem(SERVER_KEY_PEM).unwrap();

        let server_cfg = Config::builder()
            .tls_only()
            .min_version(ProtocolVersion::SSLv3)
            .max_version(ProtocolVersion::TLSv1_1)
            .identity(vec![cert_der.clone()], SigningKey::Rsa(server_key))
            .build();

        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        let client_cfg = Config::builder()
            .tls_only()
            .min_version(ProtocolVersion::SSLv3)
            .max_version(ProtocolVersion::TLSv1_1)
            .roots(roots)
            .server_name("fuzz.example")
            .build();

        Identity {
            server_cfg,
            client_cfg,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let id = identity();
    if let Ok(mut server) = Connection::server(&id.server_cfg) {
        let _ = server.feed(data);
    }
    if let Ok(mut client) = Connection::client(&id.client_cfg) {
        let _ = client.feed(data);
    }
});
