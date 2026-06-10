//! Fuzz `OcspResponse::from_der` plus every public accessor. Like the
//! certificate parser, `from_der` only does the outer structural pass —
//! the BasicOCSPResponse walk, the SingleResponse iterator, the nonce
//! extractor, and the embedded responder-cert parser all run lazily
//! behind accessors, so a bug there only surfaces if we call them.
//!
//! OCSP responses are attacker-supplied bytes: they arrive stapled in a
//! TLS handshake (`status_request`) or over plain HTTP from a responder
//! the network path controls. The signature-verification entries run
//! against a fixed deterministic key / self-signed cert — fuzz inputs
//! can't produce a valid signature, but the verifier must *reject*
//! arbitrary `signatureAlgorithm` + BIT STRING combinations without
//! panicking, which is exactly the surface this exercises.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::hash::Sha256;
use purecrypto::rng::HmacDrbg;
use purecrypto::signature_registry::SignaturePolicy;
use purecrypto::x509::{
    AnyPublicKey, CertSigner, Certificate, DistinguishedName, OcspCheckOptions, OcspResponse,
    Time, Validity,
};
use std::sync::OnceLock;

struct Pinned {
    /// The verification key handed to `verify_signature_with*`.
    key: AnyPublicKey,
    /// A self-signed cert used as both leaf and issuer for `check_for_cert`.
    cert: Certificate,
}

static PINNED: OnceLock<Pinned> = OnceLock::new();

fn pinned() -> &'static Pinned {
    PINNED.get_or_init(|| {
        let mut rng = HmacDrbg::<Sha256>::new(b"fuzz-ocsp-response", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
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
            true,
            &["fuzz.example"],
        )
        .unwrap();
        Pinned {
            key: AnyPublicKey::Ecdsa(key.public_key()),
            cert,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(resp) = OcspResponse::from_der(data.to_vec()) else {
        return;
    };
    let p = pinned();

    // Lazy accessors — each re-walks (parts of) the DER.
    let _ = resp.response_status();
    let _ = resp.produced_at();
    let _ = resp.signature_algorithm_oid();
    let _ = resp.nonce();
    let _ = resp.delegated_responder_cert();
    if let Ok(rows) = resp.responses() {
        // `read_single_response` already ran; touch the parsed rows so
        // the Time / CertStatus contents aren't optimized away.
        for r in rows {
            let _ = std::hint::black_box(r);
        }
    }

    // Signature verification against a pinned key: rejects (almost)
    // always, but must reject *cleanly* for arbitrary alg/BIT STRING.
    let _ = resp.verify_signature_with(&p.key);
    let policy = SignaturePolicy::modern();
    let _ = resp.verify_signature_with_policy(&p.key, &policy);

    // End-to-end staple validation path (issuer-key + delegated-responder
    // fallback + freshness + (leaf, issuer) matching) against a pinned
    // self-signed cert standing in for both roles.
    let now = Time::utc(2026, 1, 1, 0, 0, 0);
    let _ = resp.check_for_cert(&p.cert, &p.cert, Some(&now));
    let opts = OcspCheckOptions::new(&policy).with_nonce(b"fuzz-nonce");
    let _ = resp.check_for_cert_with_options(&p.cert, &p.cert, &opts);
});
