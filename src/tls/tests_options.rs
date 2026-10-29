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

/// A CA (P-256, self-signed) and a leaf for [`HOST`] it issued with
/// `serial` and `validity`, plus the leaf's key.
struct CaFixture {
    ca_key: BoxedEcdsaPrivateKey,
    ca_name: DistinguishedName,
    ca_der: Vec<u8>,
}

impl CaFixture {
    fn new(seed: &[u8]) -> Self {
        let ca_key = ecdsa_key(seed);
        // Named after the seed: two fixtures are two distinct CAs.
        let ca_name = DistinguishedName::common_name(core::str::from_utf8(seed).unwrap());
        let ca_der = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&ca_key),
            &ca_name,
            &validity(),
            1,
            true,
            &[],
        )
        .unwrap()
        .to_der()
        .to_vec();
        CaFixture {
            ca_key,
            ca_name,
            ca_der,
        }
    }

    /// A leaf for `name` under this CA.
    fn issue(
        &self,
        seed: &[u8],
        name: &str,
        serial: u64,
        validity: &Validity,
    ) -> (Vec<u8>, SigningKey) {
        let key = ecdsa_key(seed);
        let der = Certificate::issue_general(
            &CertSigner::Ecdsa(&self.ca_key),
            &self.ca_name,
            &DistinguishedName::common_name(name),
            &crate::x509::AnyPublicKey::Ecdsa(key.public_key()),
            validity,
            serial,
            false,
            &[name],
        )
        .unwrap()
        .to_der()
        .to_vec();
        (der, SigningKey::Ecdsa(key))
    }

    fn roots(&self) -> RootCertStore {
        roots_of(&self.ca_der)
    }

    /// A CRL signed by this CA revoking `serial`.
    fn crl_revoking(&self, serial: u8) -> crate::tls::CrlStore {
        let mut b =
            crate::x509::CrlBuilder::new(&self.ca_name, Time::utc(2030, 1, 1, 0, 0, 0), None);
        b.revoke(&[serial], Time::utc(2030, 1, 2, 0, 0, 0), None);
        let crl = b.sign(&CertSigner::Ecdsa(&self.ca_key)).unwrap();
        let mut store = crate::tls::CrlStore::new();
        store.add_der(crl.to_der().to_vec()).unwrap();
        store
    }
}

/// Issue #84: a client whose built-in verification rejects the server
/// certificate sends the alert OpenSSL / rustls would — `unknown_ca`,
/// `certificate_expired`, `certificate_revoked`, `bad_certificate` — and
/// the server reports exactly that alert instead of an unexpected EOF.
#[test]
fn client_verification_failures_send_matching_alerts() {
    let ca = CaFixture::new(b"alert-ca");
    let other_ca = CaFixture::new(b"alert-other-ca");
    let expired = Validity::new(
        Time::utc(2020, 1, 1, 0, 0, 0),
        Time::utc(2021, 1, 1, 0, 0, 0),
    );
    let not_yet = Validity::new(
        Time::utc(2031, 1, 1, 0, 0, 0),
        Time::utc(2040, 1, 1, 0, 0, 0),
    );
    let (good, good_key) = ca.issue(b"alert-leaf", HOST, 77, &validity());
    let (old, old_key) = ca.issue(b"alert-leaf-old", HOST, 78, &expired);
    let (young, young_key) = ca.issue(b"alert-leaf-young", HOST, 79, &not_yet);
    let (wrong_name, wrong_key) = ca.issue(b"alert-leaf-name", "other.example", 80, &validity());
    let self_signed_leaf = self_signed(&CertSigner::Ecdsa(&ecdsa_key(b"alert-ss")), &validity());

    struct Case {
        what: &'static str,
        chain: Vec<Vec<u8>>,
        key: SigningKey,
        roots: RootCertStore,
        crls: Option<crate::tls::CrlStore>,
        local: Error,
        alert: AlertDescription,
    }
    let cases = [
        Case {
            what: "issuer not trusted",
            chain: vec![good.clone()],
            key: good_key.clone(),
            roots: other_ca.roots(),
            crls: None,
            local: Error::UnknownIssuer,
            alert: AlertDescription::UNKNOWN_CA,
        },
        Case {
            what: "untrusted self-signed leaf",
            chain: vec![self_signed_leaf],
            key: SigningKey::Ecdsa(ecdsa_key(b"alert-ss")),
            roots: ca.roots(),
            crls: None,
            local: Error::UnknownIssuer,
            alert: AlertDescription::UNKNOWN_CA,
        },
        Case {
            what: "expired",
            chain: vec![old],
            key: old_key,
            roots: ca.roots(),
            crls: None,
            local: Error::CertificateExpired,
            alert: AlertDescription::CertificateExpired,
        },
        Case {
            what: "not yet valid",
            chain: vec![young],
            key: young_key,
            roots: ca.roots(),
            crls: None,
            local: Error::CertificateExpired,
            alert: AlertDescription::CertificateExpired,
        },
        Case {
            what: "revoked by CRL",
            chain: vec![good.clone()],
            key: good_key.clone(),
            roots: ca.roots(),
            crls: Some(ca.crl_revoking(77)),
            local: Error::CertificateRevoked,
            alert: AlertDescription::CERTIFICATE_REVOKED,
        },
        Case {
            what: "host name mismatch",
            chain: vec![wrong_name],
            key: wrong_key,
            roots: ca.roots(),
            crls: None,
            local: Error::BadCertificate,
            alert: AlertDescription::BadCertificate,
        },
    ];
    for v in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
        for case in &cases {
            let server_cfg = server_builder(v, v, case.chain.clone(), case.key.clone()).build();
            let mut b = verifying_client(v, v, case.roots.clone_store());
            if let Some(crls) = &case.crls {
                b = b.crls(crls.clone_store());
            }
            let client_cfg = b.build();
            let mut client = Connection::client(&client_cfg).unwrap();
            let mut server = Connection::server(&server_cfg).unwrap();
            let out = run(&mut client, &mut server);
            assert_eq!(out.client, Err(case.local.clone()), "{v:?} {}", case.what);
            assert!(case.local.is_certificate_error());
            assert_eq!(
                out.server,
                Err(Error::AlertReceived(case.alert)),
                "{v:?} {}",
                case.what
            );
        }
        // Control: the good chain under the right roots completes.
        let server_cfg = server_builder(v, v, vec![good.clone()], good_key.clone()).build();
        let client_cfg = verifying_client(v, v, ca.roots()).build();
        let mut client = Connection::client(&client_cfg).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        let out = run(&mut client, &mut server);
        out.client.unwrap();
        out.server.unwrap();
    }
}

/// The same mapping on the server side of mTLS: an untrusted or expired
/// client certificate is answered with `unknown_ca` / `certificate_expired`.
#[test]
fn server_client_auth_failures_send_matching_alerts() {
    let ca = CaFixture::new(b"mtls-alert-ca");
    let other_ca = CaFixture::new(b"mtls-alert-other");
    let expired = Validity::new(
        Time::utc(2020, 1, 1, 0, 0, 0),
        Time::utc(2021, 1, 1, 0, 0, 0),
    );
    let (server_leaf, server_key) = ca.issue(b"mtls-alert-server", HOST, 2, &validity());
    let (client_leaf, client_key) =
        ca.issue(b"mtls-alert-client", "client.example", 3, &validity());
    let (old_leaf, old_key) = ca.issue(b"mtls-alert-old", "client.example", 4, &expired);
    for v in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
        for (what, roots, chain, key, local, alert) in [
            (
                "untrusted",
                other_ca.roots(),
                client_leaf.clone(),
                client_key.clone(),
                Error::UnknownIssuer,
                AlertDescription::UNKNOWN_CA,
            ),
            (
                "expired",
                ca.roots(),
                old_leaf.clone(),
                old_key.clone(),
                Error::CertificateExpired,
                AlertDescription::CertificateExpired,
            ),
        ] {
            let server_cfg = server_builder(v, v, vec![server_leaf.clone()], server_key.clone())
                .client_auth(crate::tls::ClientAuth::new(roots, true))
                .verification_time(now())
                .build();
            let client_cfg = unverifying_client(v, v).identity(vec![chain], key).build();
            let mut client = Connection::client(&client_cfg).unwrap();
            let mut server = Connection::server(&server_cfg).unwrap();
            let out = run(&mut client, &mut server);
            assert_eq!(out.server, Err(local), "{v:?} {what}");
            assert_eq!(out.client, Err(Error::AlertReceived(alert)), "{v:?} {what}");
        }
    }
}

/// What [`Recorder`] keeps of one call: chain, server name, `verified`,
/// `peer_is_server`.
type Seen = (Vec<Vec<u8>>, Option<alloc::string::String>, bool, bool);

/// A [`CertificateVerifier`](crate::tls::CertificateVerifier) that records
/// what it was shown and answers with a fixed verdict.
struct Recorder {
    verdict: Result<(), AlertDescription>,
    seen: std::sync::Mutex<Vec<Seen>>,
}

impl Recorder {
    fn new(verdict: Result<(), AlertDescription>) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Recorder {
            verdict,
            seen: std::sync::Mutex::new(Vec::new()),
        })
    }
    fn calls(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl crate::tls::CertificateVerifier for Recorder {
    fn verify(&self, peer: &crate::tls::PeerCertificates<'_>) -> Result<(), AlertDescription> {
        self.seen.lock().unwrap().push((
            peer.chain.to_vec(),
            peer.server_name.map(alloc::string::ToString::to_string),
            peer.verified,
            peer.peer_is_server,
        ));
        self.verdict
    }
}

/// A custom verifier on the client picks the alert: with the built-in
/// verification off it is the whole decision, with it on it runs after
/// (and only if) the built-in checks pass.
#[test]
fn client_certificate_verifier_chooses_the_alert() {
    let ca = CaFixture::new(b"verifier-ca");
    let (leaf, key) = ca.issue(b"verifier-leaf", HOST, 9, &validity());
    for v in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
        let server_cfg = server_builder(v, v, vec![leaf.clone()], key.clone()).build();

        // Verification off: the verifier alone rejects, with its alert.
        let rejecter = Recorder::new(Err(AlertDescription::UNKNOWN_CA));
        let client_cfg = unverifying_client(v, v)
            .certificate_verifier(rejecter.clone())
            .build();
        let mut client = Connection::client(&client_cfg).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        let out = run(&mut client, &mut server);
        assert_eq!(
            out.client,
            Err(Error::CertificateRejected(AlertDescription::UNKNOWN_CA)),
            "{v:?}"
        );
        assert_eq!(
            out.server,
            Err(Error::AlertReceived(AlertDescription::UNKNOWN_CA)),
            "{v:?}"
        );
        assert!(!client.is_handshake_complete() && !server.is_handshake_complete());
        let seen = rejecter.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0],
            (vec![leaf.clone()], Some(HOST.into()), false, true)
        );
        drop(seen);

        // Verification on and passing: the verifier sees `verified = true`
        // and its approval lets the handshake complete.
        let approver = Recorder::new(Ok(()));
        let client_cfg = verifying_client(v, v, ca.roots())
            .certificate_verifier(approver.clone())
            .build();
        let mut client = Connection::client(&client_cfg).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        let out = run(&mut client, &mut server);
        out.client.unwrap();
        out.server.unwrap();
        assert!(approver.seen.lock().unwrap()[0].2);

        // Verification on and failing: the built-in alert wins and the
        // verifier is never consulted (it cannot override a rejection).
        let bystander = Recorder::new(Ok(()));
        let client_cfg = verifying_client(v, v, RootCertStore::new())
            .certificate_verifier(bystander.clone())
            .build();
        let mut client = Connection::client(&client_cfg).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        let out = run(&mut client, &mut server);
        assert_eq!(out.client, Err(Error::UnknownIssuer));
        assert_eq!(bystander.calls(), 0);
    }
}

/// A server-side verifier refuses a client certificate the client-auth
/// roots accepted, with `access_denied`.
#[test]
fn server_certificate_verifier_chooses_the_alert() {
    let ca = CaFixture::new(b"srv-verifier-ca");
    let (server_leaf, server_key) = ca.issue(b"srv-verifier-server", HOST, 2, &validity());
    let (client_leaf, client_key) =
        ca.issue(b"srv-verifier-client", "client.example", 3, &validity());
    for v in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
        let verifier = Recorder::new(Err(AlertDescription::ACCESS_DENIED));
        let server_cfg = server_builder(v, v, vec![server_leaf.clone()], server_key.clone())
            .client_auth(crate::tls::ClientAuth::new(ca.roots(), true))
            .verification_time(now())
            .certificate_verifier(verifier.clone())
            .build();
        let client_cfg = unverifying_client(v, v)
            .identity(vec![client_leaf.clone()], client_key.clone())
            .build();
        let mut client = Connection::client(&client_cfg).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();
        let out = run(&mut client, &mut server);
        assert_eq!(
            out.server,
            Err(Error::CertificateRejected(AlertDescription::ACCESS_DENIED)),
            "{v:?}"
        );
        assert_eq!(
            out.client,
            Err(Error::AlertReceived(AlertDescription::ACCESS_DENIED)),
            "{v:?}"
        );
        let seen = verifier.seen.lock().unwrap();
        assert_eq!(seen[0], (vec![client_leaf.clone()], None, true, false));
    }
}

/// DTLS refuses a certificate verifier at construction rather than
/// skipping it.
#[cfg(feature = "dtls")]
#[test]
fn dtls_refuses_a_certificate_verifier() {
    let (chain, key) = ecdsa_identity();
    for v in [ProtocolVersion::DTLSv1_2, ProtocolVersion::DTLSv1_3] {
        let client_cfg = unverifying_client(v, v)
            .certificate_verifier(Recorder::new(Ok(())))
            .build();
        assert!(matches!(
            Connection::client(&client_cfg),
            Err(Error::InappropriateState)
        ));
        let server_cfg = server_builder(v, v, chain.clone(), key.clone())
            .no_cookie()
            .certificate_verifier(Recorder::new(Ok(())))
            .build();
        assert!(matches!(
            Connection::server(&server_cfg),
            Err(Error::InappropriateState)
        ));
        let mut conn = Connection::client(&unverifying_client(v, v).build()).unwrap();
        assert_eq!(
            conn.abort_with_alert(AlertDescription::UNKNOWN_CA),
            Err(Error::InappropriateState)
        );
    }
}

/// `abort_with_alert` after the handshake: the caller checked the peer
/// certificate itself and refuses it. The alert is queued behind the
/// client's final flight, protected, and the server reports it.
#[test]
fn abort_with_alert_after_handshake_reaches_the_peer() {
    let (chain, key) = ecdsa_identity();
    for v in [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2] {
        let server_cfg = server_builder(v, v, chain.clone(), key.clone()).build();
        let client_cfg = unverifying_client(v, v).build();
        let mut client = Connection::client(&client_cfg).unwrap();
        let mut server = Connection::server(&server_cfg).unwrap();

        // Run until the client has the server's certificate.
        client.handshake().unwrap();
        server.feed(&client.pop().unwrap()).unwrap();
        client.feed(&server.pop().unwrap()).unwrap();
        assert_eq!(client.peer_certificates(), &chain[..]);
        // TLS 1.3: the client is done; TLS 1.2: it awaits the server's
        // Finished. Either way its last flight is queued but not yet sent.
        client
            .abort_with_alert(AlertDescription::UNKNOWN_CA)
            .unwrap();
        // Idempotent; the connection refuses further use.
        client
            .abort_with_alert(AlertDescription::BadCertificate)
            .unwrap();
        assert!(matches!(client.drive(), Ok(crate::tls::Step::WantWrite)));
        let out = client.pop().unwrap();
        assert!(matches!(client.drive(), Err(Error::InappropriateState)));
        assert!(matches!(client.handshake(), Err(Error::InappropriateState)));
        assert!(matches!(client.feed(&[]), Err(Error::InappropriateState)));
        assert!(matches!(client.send(b"x"), Err(Error::InappropriateState)));

        assert_eq!(
            server.feed(&out),
            Err(Error::AlertReceived(AlertDescription::UNKNOWN_CA)),
            "{v:?}"
        );
    }
}

/// `abort_with_alert` before any key exists goes out as a plaintext
/// alert record — from a client that has not seen the ServerHello yet, and
/// from a version-spanning server that has not seen a ClientHello.
#[test]
fn abort_with_alert_before_keys_is_a_plaintext_record() {
    let (chain, key) = ecdsa_identity();
    // TLS 1.2 client, server flight not processed yet.
    let v = ProtocolVersion::TLSv1_2;
    let server_cfg = server_builder(v, v, chain.clone(), key.clone()).build();
    let mut client = Connection::client(&unverifying_client(v, v).build()).unwrap();
    let mut server = Connection::server(&server_cfg).unwrap();
    client.handshake().unwrap();
    server.feed(&client.pop().unwrap()).unwrap();
    let _flight = server.pop().unwrap();
    client
        .abort_with_alert(AlertDescription::HandshakeFailure)
        .unwrap();
    let alert = client.pop().unwrap();
    assert_eq!(alert, [21, 3, 3, 0, 2, 2, 40]);
    assert_eq!(
        server.feed(&alert),
        Err(Error::AlertReceived(AlertDescription::HandshakeFailure))
    );

    // Version-spanning server, nothing received.
    let auto_cfg = server_builder(
        ProtocolVersion::TLSv1_2,
        ProtocolVersion::TLSv1_3,
        chain,
        key,
    )
    .build();
    let mut server = Connection::server(&auto_cfg).unwrap();
    server
        .abort_with_alert(AlertDescription::UNKNOWN_CA)
        .unwrap();
    assert!(matches!(server.drive(), Ok(crate::tls::Step::WantWrite)));
    let alert = server.pop().unwrap();
    assert_eq!(alert, [21, 3, 3, 0, 2, 2, 48]);
    assert!(matches!(server.feed(&[22]), Err(Error::InappropriateState)));
    let mut client = Connection::client(
        &unverifying_client(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3).build(),
    )
    .unwrap();
    client.handshake().unwrap();
    let _ch = client.pop().unwrap();
    assert_eq!(
        client.feed(&alert),
        Err(Error::AlertReceived(AlertDescription::UNKNOWN_CA))
    );
}

/// Every alert code the new error variants map to round-trips through the
/// wire encoding.
#[test]
fn certificate_alert_codes() {
    assert_eq!(AlertDescription::UNKNOWN_CA.as_u8(), 48);
    assert_eq!(AlertDescription::CERTIFICATE_REVOKED.as_u8(), 44);
    assert_eq!(AlertDescription::ACCESS_DENIED.as_u8(), 49);
    assert_eq!(AlertDescription::CertificateExpired.as_u8(), 45);
    for a in [
        AlertDescription::UNKNOWN_CA,
        AlertDescription::CERTIFICATE_REVOKED,
        AlertDescription::ACCESS_DENIED,
    ] {
        assert_eq!(AlertDescription::from_u8(a.as_u8()), a);
    }
    assert!(!Error::HandshakeFailure.is_certificate_error());
}
