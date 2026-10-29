//! Round trips through the public [`Connection`] for the per-`Config`
//! policy knobs: the RSA key-size floor, server cipher-suite selection and
//! the fatal alerts a rejected certificate produces.
//!
//! The harness draws entropy from `rng::OsRng`, so the module needs `std`.

use alloc::vec;
use alloc::vec::Vec;

use crate::bignum::BoxedUint;
use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
use crate::hash::Sha256;
use crate::rng::HmacDrbg;
use crate::rsa::BoxedRsaPrivateKey;
use crate::tls::{
    AlertDescription, Config, ConfigBuilder, Connection, Error, ProtocolVersion, RootCertStore,
    SigningKey,
};
use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

const HOST: &str = "tls.example";

/// Fixed verification clock inside every fixture's validity window.
fn now() -> Time {
    Time::utc(2030, 6, 1, 0, 0, 0)
}

fn validity() -> Validity {
    Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    )
}

/// A deterministic P-256 key.
fn ecdsa_key(seed: &[u8]) -> BoxedEcdsaPrivateKey {
    let mut rng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
    BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng)
}

/// A deterministic RSA key of `bits`.
fn rsa_key(seed: &[u8], bits: usize) -> BoxedRsaPrivateKey {
    let mut rng = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
    BoxedRsaPrivateKey::generate(bits, BoxedUint::from_u64(65537), &mut rng, 16)
}

/// Self-signed leaf for [`HOST`] over `signer`, as DER.
fn self_signed(signer: &CertSigner, validity: &Validity) -> Vec<u8> {
    Certificate::self_signed_general(
        signer,
        &DistinguishedName::common_name(HOST),
        validity,
        1,
        false,
        &[HOST],
    )
    .unwrap()
    .to_der()
    .to_vec()
}

/// A trust store holding exactly `der`.
fn roots_of(der: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::new();
    roots.add_der(der.to_vec()).unwrap();
    roots
}

/// Server builder for `version` with the given identity.
fn server_builder(
    min: ProtocolVersion,
    max: ProtocolVersion,
    chain: Vec<Vec<u8>>,
    key: SigningKey,
) -> ConfigBuilder {
    Config::builder()
        .os_rng()
        .versions(min, max)
        .identity(chain, key)
}

/// Client builder for `min..=max` that verifies against `roots` at [`now`].
fn verifying_client(
    min: ProtocolVersion,
    max: ProtocolVersion,
    roots: RootCertStore,
) -> ConfigBuilder {
    Config::builder()
        .os_rng()
        .versions(min, max)
        .server_name(HOST)
        .roots(roots)
        .verification_time(now())
}

/// Client builder for `min..=max` with verification off.
fn unverifying_client(min: ProtocolVersion, max: ProtocolVersion) -> ConfigBuilder {
    Config::builder()
        .os_rng()
        .versions(min, max)
        .server_name(HOST)
        .verify_certificates(false)
}

/// The outcome of [`run`]: each side's first error, if any.
struct Outcome {
    client: Result<(), Error>,
    server: Result<(), Error>,
}

/// Drives `client` and `server` against each other until both complete or
/// one fails. Bytes a failing side queued (its fatal alert) are still
/// delivered to the peer, the way a host that flushes before closing would.
fn run(client: &mut Connection, server: &mut Connection) -> Outcome {
    let mut out = Outcome {
        client: Ok(()),
        server: Ok(()),
    };
    for _ in 0..64 {
        if out.client.is_ok()
            && let Err(e) = client.handshake()
        {
            out.client = Err(e);
        }
        let c = client.pop().unwrap();
        if !c.is_empty()
            && out.server.is_ok()
            && let Err(e) = server.feed(&c)
        {
            out.server = Err(e);
        }
        if out.server.is_ok()
            && let Err(e) = server.handshake()
        {
            out.server = Err(e);
        }
        let s = server.pop().unwrap();
        if !s.is_empty()
            && out.client.is_ok()
            && let Err(e) = client.feed(&s)
        {
            out.client = Err(e);
        }
        let done = client.is_handshake_complete() && server.is_handshake_complete();
        let failed = out.client.is_err() || out.server.is_err();
        if (done || failed) && c.is_empty() && s.is_empty() {
            break;
        }
    }
    out
}

/// A 1024-bit RSA server certificate is refused under the default 2048-bit
/// floor, and accepted once the client opts in with `min_rsa_key_bits` —
/// for TLS 1.3 (`CertificateVerify`) and TLS 1.2 (`ServerKeyExchange`). The
/// override is per-`Config`: a second client without it still refuses.
#[test]
fn min_rsa_key_bits_admits_small_rsa_keys_per_config() {
    let key = rsa_key(b"rsa-1024-floor", 1024);
    let leaf = self_signed(&CertSigner::Rsa(&key), &validity());
    for v in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
        let server_cfg = server_builder(v, v, vec![leaf.clone()], SigningKey::Rsa(key.clone()))
            .min_rsa_key_bits(1024)
            .build();

        let strict = verifying_client(v, v, roots_of(&leaf)).build();
        let mut client = Connection::client(&strict).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        let out = run(&mut client, &mut server);
        assert!(
            matches!(out.client, Err(Error::BadCertificate)),
            "{v:?}: {:?}",
            out.client
        );
        assert!(
            matches!(
                out.server,
                Err(Error::AlertReceived(AlertDescription::BadCertificate))
            ),
            "{v:?}: {:?}",
            out.server
        );

        let relaxed = verifying_client(v, v, roots_of(&leaf))
            .min_rsa_key_bits(1024)
            .build();
        assert_eq!(relaxed.signature_policy.min_rsa_bits, 1024);
        let mut client = Connection::client(&relaxed).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        let out = run(&mut client, &mut server);
        out.client.unwrap();
        out.server.unwrap();
        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        assert_eq!(client.negotiated_version(), Some(v));
    }
}

/// The floor also governs client certificates a server verifies (mTLS).
#[test]
fn min_rsa_key_bits_applies_to_client_certificates() {
    let server_key = ecdsa_key(b"mtls-server");
    let server_leaf = self_signed(&CertSigner::Ecdsa(&server_key), &validity());
    let client_key = rsa_key(b"mtls-rsa-1024", 1024);
    let client_leaf = self_signed(&CertSigner::Rsa(&client_key), &validity());
    for v in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
        for (relax, ok) in [(false, false), (true, true)] {
            let mut b = server_builder(
                v,
                v,
                vec![server_leaf.clone()],
                SigningKey::Ecdsa(server_key.clone()),
            )
            .client_auth(crate::tls::ClientAuth::new(roots_of(&client_leaf), true))
            .verification_time(now());
            if relax {
                b = b.min_rsa_key_bits(1024);
            }
            let server_cfg = b.build();
            let client_cfg = unverifying_client(v, v)
                .identity(
                    vec![client_leaf.clone()],
                    SigningKey::Rsa(client_key.clone()),
                )
                .min_rsa_key_bits(1024)
                .build();
            let mut client = Connection::client(&client_cfg).unwrap();
            let mut server = Connection::server(&server_cfg).unwrap();
            let out = run(&mut client, &mut server);
            assert_eq!(
                out.server.is_ok(),
                ok,
                "{v:?} relax={relax}: {:?}",
                out.server
            );
            if ok {
                assert!(server.is_handshake_complete());
            }
        }
    }
}

const TLS13_AES_128: u16 = 0x1301;
const TLS13_AES_256: u16 = 0x1302;
const TLS13_CHACHA20: u16 = 0x1303;
const ECDSA_AES_128: u16 = 0xC02B;
const ECDSA_AES_256: u16 = 0xC02C;
const ECDSA_CHACHA20: u16 = 0xCCA9;

/// A P-256 server identity for [`HOST`].
fn ecdsa_identity() -> (Vec<Vec<u8>>, SigningKey) {
    let key = ecdsa_key(b"cipher-order-server");
    let leaf = self_signed(&CertSigner::Ecdsa(&key), &validity());
    (vec![leaf], SigningKey::Ecdsa(key))
}

/// Runs one handshake between `server_cfg` and `client_cfg` and returns
/// the suite both sides agreed on, or the server's error.
fn negotiate(server_cfg: &Config, client_cfg: &Config) -> Result<u16, Error> {
    let mut client = Connection::client(client_cfg).unwrap();
    let mut server = Connection::server(server_cfg)?;
    let out = run(&mut client, &mut server);
    out.server?;
    out.client.unwrap();
    assert!(client.is_handshake_complete() && server.is_handshake_complete());
    let suite = server.negotiated_cipher_suite().unwrap();
    assert_eq!(client.negotiated_cipher_suite(), Some(suite));
    Ok(suite)
}

/// Issue #85: `prefer_server_cipher_order(false)` makes the TLS 1.3 and
/// TLS 1.2 servers follow the client's order (OpenSSL's default, PHP's
/// `honor_cipher_order = false`); the default keeps the server's.
#[test]
fn server_can_follow_the_client_cipher_order() {
    let (chain, key) = ecdsa_identity();
    for (v, server_list, client_list) in [
        (
            ProtocolVersion::TLSv1_3,
            &[TLS13_AES_128, TLS13_AES_256, TLS13_CHACHA20][..],
            &[TLS13_AES_256, TLS13_CHACHA20, TLS13_AES_128][..],
        ),
        (
            ProtocolVersion::TLSv1_2,
            &[ECDSA_AES_128, ECDSA_AES_256, ECDSA_CHACHA20][..],
            &[ECDSA_AES_256, ECDSA_CHACHA20, ECDSA_AES_128][..],
        ),
    ] {
        let client_cfg = unverifying_client(v, v).cipher_suites(client_list).build();
        for (server_order, expect) in [(true, server_list[0]), (false, client_list[0])] {
            // With an explicit server list...
            let server_cfg = server_builder(v, v, chain.clone(), key.clone())
                .cipher_suites(server_list)
                .prefer_server_cipher_order(server_order)
                .build();
            assert_eq!(
                negotiate(&server_cfg, &client_cfg).unwrap(),
                expect,
                "{v:?} server_order={server_order}"
            );
        }
        // ...and with the engine's built-in order: the client's first choice
        // wins once the server follows the client.
        let server_cfg = server_builder(v, v, chain.clone(), key.clone())
            .prefer_server_cipher_order(false)
            .build();
        assert_eq!(negotiate(&server_cfg, &client_cfg).unwrap(), client_list[0]);
    }
    assert!(Config::default().prefer_server_cipher_order);
}

/// The same switch through a version-spanning server (the deferred engine
/// that picks TLS 1.2 or 1.3 from the ClientHello).
#[test]
fn auto_server_follows_the_client_cipher_order() {
    let (chain, key) = ecdsa_identity();
    let server_cfg = server_builder(
        ProtocolVersion::TLSv1_2,
        ProtocolVersion::TLSv1_3,
        chain,
        key,
    )
    .prefer_server_cipher_order(false)
    .build();
    for (v, client_list) in [
        (
            ProtocolVersion::TLSv1_3,
            &[TLS13_CHACHA20, TLS13_AES_128][..],
        ),
        (
            ProtocolVersion::TLSv1_2,
            &[ECDSA_CHACHA20, ECDSA_AES_128][..],
        ),
    ] {
        let client_cfg = unverifying_client(v, v).cipher_suites(client_list).build();
        assert_eq!(negotiate(&server_cfg, &client_cfg).unwrap(), client_list[0]);
    }
}

/// Issue #89: `Config::cipher_suites` restricts the TLS 1.2 server too. It
/// used to be inert there, so a server configured for AES-256-GCM only
/// still negotiated AES-128-GCM with a client offering both.
#[test]
fn tls12_server_honours_cipher_suites_restriction() {
    let (chain, key) = ecdsa_identity();
    let v = ProtocolVersion::TLSv1_2;
    let server_cfg = server_builder(v, v, chain.clone(), key.clone())
        .cipher_suites(&[ECDSA_AES_256])
        .build();

    let both = unverifying_client(v, v)
        .cipher_suites(&[ECDSA_AES_128, ECDSA_AES_256])
        .build();
    assert_eq!(negotiate(&server_cfg, &both).unwrap(), ECDSA_AES_256);

    // A client offering only an excluded suite is refused, and told so.
    let excluded = unverifying_client(v, v)
        .cipher_suites(&[ECDSA_AES_128])
        .build();
    let mut client = Connection::client(&excluded).unwrap();
    let mut server = Connection::server(&server_cfg).unwrap();
    let out = run(&mut client, &mut server);
    assert!(
        matches!(out.server, Err(Error::HandshakeFailure)),
        "{:?}",
        out.server
    );
    assert!(
        matches!(
            out.client,
            Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
        ),
        "{:?}",
        out.client
    );

    // Fail closed: a list naming no suite this engine implements.
    let tls13_only = server_builder(v, v, chain, key)
        .cipher_suites(&[TLS13_AES_128])
        .build();
    assert!(matches!(
        Connection::server(&tls13_only),
        Err(Error::NoUsableCipherSuites)
    ));
}

/// A version-spanning server whose suite list covers only one version
/// negotiates that version — without a TLS 1.3 downgrade sentinel when the
/// list has no TLS 1.3 suite, which a 1.3-capable client would otherwise
/// abort on — and a list covering neither fails at construction.
#[test]
fn version_spanning_server_follows_its_suite_list() {
    let (chain, key) = ecdsa_identity();
    let (lo, hi) = (ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3);
    let default_client = unverifying_client(lo, hi).build();

    let only12 = server_builder(lo, hi, chain.clone(), key.clone())
        .cipher_suites(&[ECDSA_AES_256])
        .build();
    let mut client = Connection::client(&default_client).unwrap();
    let mut server = Connection::server(&only12).unwrap();
    let out = run(&mut client, &mut server);
    out.client.unwrap();
    out.server.unwrap();
    assert_eq!(client.negotiated_version(), Some(ProtocolVersion::TLSv1_2));
    assert_eq!(server.negotiated_cipher_suite(), Some(ECDSA_AES_256));

    let only13 = server_builder(lo, hi, chain.clone(), key.clone())
        .cipher_suites(&[TLS13_AES_256])
        .build();
    assert_eq!(negotiate(&only13, &default_client).unwrap(), TLS13_AES_256);
    let client12 = unverifying_client(lo, lo).build();
    assert!(negotiate(&only13, &client12).is_err());

    let neither = server_builder(lo, hi, chain, key)
        .cipher_suites(&[0x0000])
        .build();
    assert!(matches!(
        Connection::server(&neither),
        Err(Error::NoUsableCipherSuites)
    ));
}

/// DTLS servers honour the restriction and the client-order switch too.
#[cfg(feature = "dtls")]
#[test]
fn dtls_servers_honour_cipher_suites_and_client_order() {
    let (chain, key) = ecdsa_identity();
    for (v, server_list, client_list) in [
        (
            ProtocolVersion::DTLSv1_3,
            &[TLS13_AES_128, TLS13_AES_256][..],
            &[TLS13_AES_256, TLS13_AES_128][..],
        ),
        (
            ProtocolVersion::DTLSv1_2,
            &[ECDSA_AES_128, ECDSA_AES_256][..],
            &[ECDSA_AES_256, ECDSA_AES_128][..],
        ),
    ] {
        let client_cfg = unverifying_client(v, v).cipher_suites(client_list).build();
        for (server_order, expect) in [(true, server_list[0]), (false, client_list[0])] {
            let server_cfg = server_builder(v, v, chain.clone(), key.clone())
                .no_cookie()
                .cipher_suites(server_list)
                .prefer_server_cipher_order(server_order)
                .build();
            assert_eq!(
                negotiate(&server_cfg, &client_cfg).unwrap(),
                expect,
                "{v:?} server_order={server_order}"
            );
        }
        // Restricted to the client's second choice: that is what is used.
        let server_cfg = server_builder(v, v, chain.clone(), key.clone())
            .no_cookie()
            .cipher_suites(&client_list[1..])
            .build();
        assert_eq!(negotiate(&server_cfg, &client_cfg).unwrap(), client_list[1]);
    }
}

/// The legacy CBC path (TLS 1.0/1.1) picks from the restriction as well.
#[cfg(feature = "tls-legacy")]
#[test]
fn legacy_server_honours_cipher_suites_and_client_order() {
    const RSA_AES_128_CBC: u16 = 0x002F;
    const RSA_AES_256_CBC: u16 = 0x0035;
    let key = crate::test_util::rsa_test_key_a();
    let boxed = BoxedRsaPrivateKey::from_pkcs1_der(&key.to_pkcs1_der()).unwrap();
    let leaf = self_signed(&CertSigner::Rsa(&boxed), &validity());
    let v = ProtocolVersion::TLSv1_0;
    let client_cfg = unverifying_client(v, v)
        .cipher_suites(&[RSA_AES_128_CBC, RSA_AES_256_CBC])
        .build();
    for (list, server_order, expect) in [
        (
            &[RSA_AES_256_CBC, RSA_AES_128_CBC][..],
            true,
            RSA_AES_256_CBC,
        ),
        (
            &[RSA_AES_256_CBC, RSA_AES_128_CBC][..],
            false,
            RSA_AES_128_CBC,
        ),
        (&[RSA_AES_256_CBC][..], false, RSA_AES_256_CBC),
    ] {
        let server_cfg = server_builder(v, v, vec![leaf.clone()], SigningKey::Rsa(boxed.clone()))
            .cipher_suites(list)
            .prefer_server_cipher_order(server_order)
            .build();
        assert_eq!(
            negotiate(&server_cfg, &client_cfg).unwrap(),
            expect,
            "{list:?}"
        );
    }
}
