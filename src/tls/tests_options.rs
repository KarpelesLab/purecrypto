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
        if out.client.is_ok() {
            if let Err(e) = client.handshake() {
                out.client = Err(e);
            }
        }
        let c = client.pop().unwrap();
        if !c.is_empty() && out.server.is_ok() {
            if let Err(e) = server.feed(&c) {
                out.server = Err(e);
            }
        }
        if out.server.is_ok() {
            if let Err(e) = server.handshake() {
                out.server = Err(e);
            }
        }
        let s = server.pop().unwrap();
        if !s.is_empty() && out.client.is_ok() {
            if let Err(e) = client.feed(&s) {
                out.client = Err(e);
            }
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
