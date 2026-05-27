//! Fuzz the QUIC server-side datagram-input path. `feed_datagram` is
//! the byte-level entry point — it walks the long/short-header parser,
//! the AEAD-protected packet-number decoder, and (for Initial packets)
//! the Initial-key derivation that follows the connection-ID. Anything
//! past `pop_datagram`'s reply needs valid keys to reach, but the
//! pre-key surface is exactly what an attacker can drive blind.
//!
//! Like the TLS feed targets, the server identity is built once via
//! `OnceLock`. We use TLS 1.3 with an ECDSA P-256 cert — QUIC v1 is
//! TLS-1.3-only, and ECDSA is cheaper than RSA at handshake time.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::hash::Sha256;
use purecrypto::quic::{QuicConfig, QuicConnection, TransportParameters};
use purecrypto::rng::HmacDrbg;
use purecrypto::tls::{Config, SigningKey};
use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
use std::sync::OnceLock;

// `BoxedEcdsaPrivateKey` isn't `Clone`, so we can't stash one identity
// and hand it to every iteration's `Config::identity(...)`. Instead we
// pin the cert (which depends only on the deterministic DRBG seed and
// the fixed validity bounds) once via `OnceLock`, then re-derive the
// same key bit-identically per iteration from the same DRBG seed.
static CERT_DER: OnceLock<Vec<u8>> = OnceLock::new();

fn ecdsa_key() -> BoxedEcdsaPrivateKey {
    let mut rng = HmacDrbg::<Sha256>::new(b"fuzz-quic-server", b"nonce", &[]);
    BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng)
}

fn cert_der() -> &'static Vec<u8> {
    CERT_DER.get_or_init(|| {
        let key = ecdsa_key();
        let name = DistinguishedName::common_name("fuzz.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2099, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&key),
            &name,
            &validity,
            1,
            false,
            &["fuzz.example"],
        )
        .unwrap();
        cert.to_der().to_vec()
    })
}

fn make_config() -> QuicConfig {
    let tls = Config::builder()
        .tls_only()
        .identity(vec![cert_der().clone()], SigningKey::Ecdsa(ecdsa_key()))
        .build();
    QuicConfig {
        tls,
        transport_params: TransportParameters::default(),
        require_retry: false,
        retry_secret: None,
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(mut server) = QuicConnection::server(make_config()) else {
        return;
    };
    let _ = server.feed_datagram(data);
});
