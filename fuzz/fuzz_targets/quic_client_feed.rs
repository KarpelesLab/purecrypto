//! Fuzz the QUIC client-side datagram-input path — the bytes a
//! *malicious server* (or an on-path attacker, pre-handshake) can drive
//! into a connecting client. Counterpart to `quic_server_feed`.
//!
//! The client sends its Initial at construction, so by the time we feed
//! fuzz bytes the connection is in exactly the state a real client is
//! in while waiting for the server's first flight. That makes the
//! client-only parsers reachable: Version Negotiation (RFC 9000 §6),
//! Retry (token relay + Retry integrity tag, RFC 9001 §5.8), and the
//! server Initial/Handshake long-header packets (ServerHello /
//! certificate-flight parsing once header protection is stripped with
//! the deterministic Initial keys).
//!
//! Input framing: the bytes are split into UDP-payload-sized chunks and
//! fed as separate datagrams, with `pop_datagram` / `next_timeout` /
//! `on_timeout` interleaved so the ACK, loss-recovery, and PTO paths
//! run between receives the way a real event loop drives them.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::quic::{QuicConfig, QuicConnection, TransportParameters};
use purecrypto::rsa::RsaPrivateKey;
use purecrypto::tls::{Config, RootCertStore};
use purecrypto::x509::{Certificate, DistinguishedName, Time, Validity};
use std::sync::OnceLock;
use std::time::Duration;

const SERVER_KEY_PEM: &str = include_str!("../../testdata/rsa2048_test_a.pem");

/// Keep per-iteration work bounded: at most 16 KiB of input, split into
/// at most 12 datagrams.
const MAX_INPUT: usize = 16 * 1024;
const MAX_DATAGRAMS: usize = 12;
/// Typical UDP payload size; also comfortably above the 1200-byte QUIC
/// minimum so full-size server Initials fit in one chunk.
const CHUNK: usize = 1350;

static ROOT_DER: OnceLock<Vec<u8>> = OnceLock::new();

fn root_der() -> &'static Vec<u8> {
    ROOT_DER.get_or_init(|| {
        let signing_key = RsaPrivateKey::<32>::from_pkcs1_pem(SERVER_KEY_PEM).unwrap();
        let name = DistinguishedName::common_name("fuzz.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2099, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed(&signing_key, &name, &validity, 1, false).unwrap();
        cert.to_der().to_vec()
    })
}

fn make_config() -> QuicConfig {
    let mut roots = RootCertStore::new();
    roots.add_der(root_der().clone()).unwrap();
    // RFC 9001 §8.1: ALPN is mandatory for QUIC — `QuicConnection::client`
    // fails closed at construction without one.
    let tls = Config::builder()
        .tls_only()
        .roots(roots)
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
    let Ok(mut client) = QuicConnection::client(make_config(), "fuzz.example") else {
        return;
    };
    // Flush the client's own Initial flight (ClientHello) first, so the
    // connection state matches a client whose first datagram is on the
    // wire — the state Version Negotiation / Retry handling requires.
    drain(&mut client);

    let mut now = Duration::ZERO;
    for chunk in data.chunks(CHUNK).take(MAX_DATAGRAMS) {
        let _ = client.feed_datagram(chunk);
        drain(&mut client);
        // Fire the next timer (PTO / loss detection) between datagrams.
        if let Some(d) = client.next_timeout() {
            // Cap the step so a huge advertised idle timeout can't
            // overflow the accumulated clock.
            now += d.min(Duration::from_secs(60));
            client.on_timeout(now);
            drain(&mut client);
        }
        if client.is_closed() {
            break;
        }
    }
});
