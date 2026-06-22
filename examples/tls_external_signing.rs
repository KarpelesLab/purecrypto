//! TLS 1.3 server handshake where the identity private key lives *outside* the
//! engine — the pattern you use to back a server with a TPM, HSM, or PKCS#11
//! device whose signing call may be slow or asynchronous.
//!
//! Instead of handing the engine a key, the server is configured with
//! [`SigningKey::External`], advertising only the IANA SignatureScheme code
//! points the external key can produce. When the handshake reaches the
//! `CertificateVerify`, the engine *suspends* and surfaces the bytes to sign
//! via [`Connection::signature_request`]. The caller signs them however it
//! likes (here, with an in-process key standing in for the HSM; in production
//! you would `.await` a network HSM or block on a device call) and resumes the
//! handshake with [`Connection::provide_signature`].
//!
//! Run with: `cargo run --example tls_external_signing`

use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::hash::Sha256;
use purecrypto::rng::HmacDrbg;
use purecrypto::tls::{Config, Connection, RootCertStore, SigningKey};
use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

// ecdsa_secp256r1_sha256 (RFC 8446 §4.2.3). The external key advertises this.
const ECDSA_SECP256R1_SHA256: u16 = 0x0403;

fn main() {
    // The "external" key. In a real deployment this never exists in process —
    // it lives in the HSM, and only its public certificate is known here.
    let mut rng = HmacDrbg::<Sha256>::new(b"tls-external-signing-example", b"nonce", &[]);
    let hsm_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);

    // --- Server setup: a self-signed cert for "example.test", External key. ---
    let name = DistinguishedName::common_name("example.test");
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let cert = Certificate::self_signed_general(
        &CertSigner::Ecdsa(&hsm_key),
        &name,
        &validity,
        1,
        false,
        &["example.test"],
    )
    .unwrap();
    let cert_der = cert.to_der().to_vec();

    let server_cfg = Config::builder()
        .tls_only()
        .identity(
            vec![cert_der.clone()],
            // No key material here — just the schemes the HSM can sign.
            SigningKey::External {
                schemes: vec![ECDSA_SECP256R1_SHA256],
            },
        )
        .build();
    let mut server = Connection::server(&server_cfg).expect("server config");

    // --- Client setup: trust the server's certificate. ---
    let mut roots = RootCertStore::new();
    roots.add_der(cert_der).unwrap();
    let client_cfg = Config::builder()
        .tls_only()
        .roots(roots)
        .server_name("example.test")
        .build();
    let mut client = Connection::client(&client_cfg).expect("client config");

    // --- Drive the handshake, handling the external-signature suspension. ---
    let mut signed_externally = false;
    for _ in 0..16 {
        let to_server = client.pop().unwrap_or_default();
        if !to_server.is_empty() {
            server.feed(&to_server).unwrap();
        }

        // When the engine needs the identity signature it yields here rather
        // than signing inline. This is the seam an async HSM driver plugs into.
        if let Some(req) = server.signature_request() {
            assert_eq!(req.scheme, ECDSA_SECP256R1_SHA256);
            println!(
                "server suspended for an external signature over {} bytes",
                req.message.len()
            );
            // === out-of-band signing: this is where a real HSM call goes ===
            let sig = hsm_key
                .sign::<Sha256>(&req.message)
                .unwrap()
                .to_der(CurveId::P256);
            server.provide_signature(sig).unwrap();
            signed_externally = true;
        }

        let to_client = server.pop().unwrap_or_default();
        if !to_client.is_empty() {
            client.feed(&to_client).unwrap();
        }
        if client.is_handshake_complete() && server.is_handshake_complete() {
            break;
        }
    }

    assert!(
        signed_externally,
        "the server must have requested a signature"
    );
    assert!(client.is_handshake_complete() && server.is_handshake_complete());
    println!("handshake complete (CertificateVerify signed out-of-band)");

    // --- A quick application-data exchange to prove the channel works. ---
    client.send(b"ping").unwrap();
    let req = client.pop().unwrap_or_default();
    server.feed(&req).unwrap();
    println!(
        "server received: {:?}",
        String::from_utf8_lossy(&server.recv().unwrap_or_default())
    );
}
