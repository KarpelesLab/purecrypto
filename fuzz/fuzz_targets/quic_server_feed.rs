//! Fuzz the QUIC server-side datagram-input path. `feed_datagram` is
//! the byte-level entry point — it walks the long/short-header parser,
//! the AEAD-protected packet-number decoder, and (for Initial packets)
//! the Initial-key derivation that follows the connection-ID. Anything
//! past `pop_datagram`'s reply needs valid keys to reach, but the
//! pre-key surface is exactly what an attacker can drive blind.
//!
//! Input framing matches `quic_client_feed`: the bytes are split into
//! UDP-payload-sized chunks fed as separate datagrams, with
//! `pop_datagram` / `next_timeout` / `on_timeout` interleaved so the
//! ACK, loss-recovery, and PTO paths run between receives.
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

/// Keep per-iteration work bounded: at most 16 KiB of input, split into
/// at most 12 datagrams of a typical UDP payload size.
const MAX_INPUT: usize = 16 * 1024;
const MAX_DATAGRAMS: usize = 12;
const CHUNK: usize = 1350;

fn make_config() -> QuicConfig {
    // RFC 9001 §8.1: ALPN is mandatory for QUIC — `QuicConnection::server`
    // fails closed at construction without one.
    let tls = Config::builder()
        .tls_only()
        .identity(vec![cert_der().clone()], SigningKey::Ecdsa(ecdsa_key()))
        .alpn(vec![b"fuzz".to_vec()])
        .build();
    // `QuicConfig` is `#[non_exhaustive]`: default-construct, then set.
    let mut cfg = QuicConfig::default();
    cfg.tls = tls;
    cfg.transport_params = TransportParameters::default();
    cfg.require_retry = false;
    cfg.retry_secret = None;
    cfg
}

/// Drains the connection's outbound datagrams, bounded so a fuzz input
/// can't make us loop forever generating ACK-only packets.
fn drain(conn: &mut QuicConnection) {
    for _ in 0..8 {
        if conn.pop_datagram().is_empty() {
            break;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let Ok(mut server) = QuicConnection::server(make_config()) else {
        return;
    };
    let mut now = std::time::Duration::ZERO;
    for chunk in data.chunks(CHUNK).take(MAX_DATAGRAMS) {
        let _ = server.feed_datagram(chunk);
        drain(&mut server);
        // Fire the next timer (PTO / loss detection) between datagrams.
        if let Some(d) = server.next_timeout() {
            now += d.min(std::time::Duration::from_secs(60));
            server.on_timeout(now);
            drain(&mut server);
        }
        if server.is_closed() {
            break;
        }
    }
});
