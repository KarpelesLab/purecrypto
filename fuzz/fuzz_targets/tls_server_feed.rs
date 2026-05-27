//! Fuzz the TLS 1.3 server-side wire-input path. Each iteration spins
//! up a fresh `Connection` in server mode against a fixed self-signed
//! identity, then hands the fuzzer's bytes to `feed` — exactly the
//! shape an attacker can drive over a TCP socket before the handshake
//! is finished.
//!
//! `feed` walks the record layer, the handshake-message reassembly,
//! and (for plaintext records before keys are installed) the
//! ClientHello / extension parsers. Anything past the first encrypted
//! flight needs valid keys to reach, but the pre-key surface is
//! exactly what untrusted peers can hit anonymously.
//!
//! The identity is built once via `OnceLock` so the per-iteration cost
//! is just the `Connection::server` setup + one `feed` call.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
use purecrypto::tls::{Config, Connection, SigningKey};
use purecrypto::x509::{Certificate, DistinguishedName, Time, Validity};
use std::sync::OnceLock;

const SERVER_KEY_PEM: &str = include_str!("../../testdata/rsa2048_test_a.pem");

struct Identity {
    cfg: Config,
}

static IDENTITY: OnceLock<Identity> = OnceLock::new();

fn identity() -> &'static Identity {
    IDENTITY.get_or_init(|| {
        let signing_key = RsaPrivateKey::<32>::from_pkcs1_pem(SERVER_KEY_PEM).unwrap();
        let name = DistinguishedName::common_name("fuzz.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2099, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed(&signing_key, &name, &validity, 1, false).unwrap();
        let cert_der = cert.to_der().to_vec();
        let server_key = BoxedRsaPrivateKey::from_pkcs1_pem(SERVER_KEY_PEM).unwrap();
        let cfg = Config::builder()
            .tls_only()
            .identity(vec![cert_der], SigningKey::Rsa(server_key))
            .build();
        Identity { cfg }
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(mut server) = Connection::server(&identity().cfg) else {
        return;
    };
    let _ = server.feed(data);
});
