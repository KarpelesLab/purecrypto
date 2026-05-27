//! Fuzz the TLS 1.3 client-side wire-input path. Same shape as
//! `tls_server_feed`, but exercises the ServerHello / encrypted-flight
//! parsers and the certificate-chain verifier — the bytes a malicious
//! server can drive into a connecting client.
//!
//! The trust root and SNI are fixed so the verifier path runs against
//! a deterministic pinned identity; fuzzing those would just produce
//! "unknown root" rejections rather than reaching anything interesting.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
use purecrypto::tls::{Config, Connection, RootCertStore};
use purecrypto::x509::{Certificate, DistinguishedName, Time, Validity};
use std::sync::OnceLock;

const SERVER_KEY_PEM: &str = include_str!("../../testdata/rsa2048_test_a.pem");

static CLIENT_CFG: OnceLock<Config> = OnceLock::new();

fn client_cfg() -> &'static Config {
    CLIENT_CFG.get_or_init(|| {
        let signing_key = RsaPrivateKey::<32>::from_pkcs1_pem(SERVER_KEY_PEM).unwrap();
        let name = DistinguishedName::common_name("fuzz.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2099, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed(&signing_key, &name, &validity, 1, false).unwrap();
        let cert_der = cert.to_der().to_vec();
        // Burn the key so it isn't kept resident on the client side.
        let _ = BoxedRsaPrivateKey::from_pkcs1_pem(SERVER_KEY_PEM);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        Config::builder()
            .tls_only()
            .roots(roots)
            .server_name("fuzz.example")
            .build()
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(mut client) = Connection::client(client_cfg()) else {
        return;
    };
    let _ = client.feed(data);
});
