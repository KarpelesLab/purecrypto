//! Fuzz the DTLS client-side wire-input path. Counterpart to
//! `dtls_server_feed`: exercises the ServerHello / HelloVerifyRequest
//! parsers (1.2) and the ServerHello / encrypted-flight parsers (1.3),
//! the certificate-chain verifier, plus the same datagram-level
//! record-layer and fragment-reassembly paths the server target hits.

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
        let _ = BoxedRsaPrivateKey::from_pkcs1_pem(SERVER_KEY_PEM);
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        Config::builder()
            .dtls()
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
