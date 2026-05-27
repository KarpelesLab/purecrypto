//! Fuzz the DTLS server-side wire-input path. Same shape as the TLS
//! variant, but DTLS adds the record-layer epoch field, the
//! datagram-level fragment reassembly, and (for 1.2) the
//! HelloVerifyRequest cookie exchange — all of which the fuzzer's
//! bytes can hit before any keys are installed.
//!
//! `Connection::feed` is the same unified entry point the TLS targets
//! use; the underlying state machine branches on the config's version
//! range, which `.dtls()` sets to `[DTLSv1_2, DTLSv1_3]`.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
use purecrypto::tls::{Config, Connection, SigningKey};
use purecrypto::x509::{Certificate, DistinguishedName, Time, Validity};
use std::sync::OnceLock;

const SERVER_KEY_PEM: &str = include_str!("../../testdata/rsa2048_test_a.pem");

static SERVER_CFG: OnceLock<Config> = OnceLock::new();

fn server_cfg() -> &'static Config {
    SERVER_CFG.get_or_init(|| {
        let signing_key = RsaPrivateKey::<32>::from_pkcs1_pem(SERVER_KEY_PEM).unwrap();
        let name = DistinguishedName::common_name("fuzz.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2099, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed(&signing_key, &name, &validity, 1, false).unwrap();
        let cert_der = cert.to_der().to_vec();
        let server_key = BoxedRsaPrivateKey::from_pkcs1_pem(SERVER_KEY_PEM).unwrap();
        Config::builder()
            .dtls()
            .identity(vec![cert_der], SigningKey::Rsa(server_key))
            .build()
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(mut server) = Connection::server(server_cfg()) else {
        return;
    };
    let _ = server.feed(data);
});
