//! TLS 1.3 handshake signatures (RFC 8446 §4.4.3).
//!
//! A `CertificateVerify` proves possession of the certified key by signing a
//! context-bound digest of the handshake transcript. The signature scheme is a
//! 16-bit `SignatureScheme` code (not an X.509 OID); dispatch goes through
//! [`crate::signature_registry`]: the scheme code picks a registry entry,
//! whose `verify(spki, message, signature)` re-parses the SPKI and delegates
//! to the underlying primitive.

use crate::ec::CurveId;
use crate::hash::{Sha256, Sha384, Sha512};
use crate::rng::RngCore;
use crate::signature_registry::{SignaturePolicy, find_by_tls_scheme};
use crate::tls::Error;
use crate::tls::codec::SignatureScheme;
use crate::tls::conn::ServerKey;
use crate::x509::{AnyPublicKey, Error as X509Error};
use alloc::vec::Vec;

/// The 64 `0x20` (space) octets that prefix the signed content (RFC 8446
/// §4.4.3), guarding against cross-protocol signature reuse.
const SIG_PREFIX: [u8; 64] = [0x20; 64];

/// Builds the octet string signed in a `CertificateVerify`:
/// `0x20 * 64 || context_string || 0x00 || Transcript-Hash(Handshake Context)`.
///
/// `server` selects the server context string (the peer that signs during a
/// normal 1-RTT handshake) versus the client one (client authentication).
pub(crate) fn certificate_verify_content(server: bool, transcript_hash: &[u8]) -> Vec<u8> {
    let context: &[u8] = if server {
        b"TLS 1.3, server CertificateVerify"
    } else {
        b"TLS 1.3, client CertificateVerify"
    };
    let mut out = Vec::with_capacity(SIG_PREFIX.len() + context.len() + 1 + transcript_hash.len());
    out.extend_from_slice(&SIG_PREFIX);
    out.extend_from_slice(context);
    out.push(0);
    out.extend_from_slice(transcript_hash);
    out
}

/// The IANA [`SignatureScheme`] an ECDSA key on `curve` signs a TLS 1.3
/// `CertificateVerify` under, or `None` when no code point exists.
///
/// The `ecdsa_secp*` schemes (RFC 8446 §4.2.3) each name one NIST curve, and
/// RFC 8734 allocates `ecdsa_brainpoolP*r1tls13_sha*` for the three
/// Brainpool curves. secp256k1 and SM2 have no IANA assignment: a key on
/// either cannot produce a signature any conformant peer verifies, so the
/// engines refuse such an identity (`Error::UnsupportedKeyType`) instead of
/// signing under a NIST code point the peer is required to reject.
pub(crate) fn tls_signature_scheme_for_curve(curve: CurveId) -> Option<SignatureScheme> {
    match curve {
        CurveId::P256 => Some(SignatureScheme::ECDSA_SECP256R1_SHA256),
        CurveId::P384 => Some(SignatureScheme::ECDSA_SECP384R1_SHA384),
        CurveId::P521 => Some(SignatureScheme::ECDSA_SECP521R1_SHA512),
        CurveId::BrainpoolP256r1 => Some(SignatureScheme::ECDSA_BRAINPOOLP256R1TLS13_SHA256),
        CurveId::BrainpoolP384r1 => Some(SignatureScheme::ECDSA_BRAINPOOLP384R1TLS13_SHA384),
        CurveId::BrainpoolP512r1 => Some(SignatureScheme::ECDSA_BRAINPOOLP512R1TLS13_SHA512),
        CurveId::Secp256k1 | CurveId::Sm2p256v1 => None,
    }
}

/// The IANA-blessed [`SignatureScheme`] code for the given [`ServerKey`], or
/// `None` for a key that has none (ECDSA on secp256k1 / SM2, see
/// [`tls_signature_scheme_for_curve`]).
pub(crate) fn signature_scheme_for(key: &ServerKey) -> Option<SignatureScheme> {
    Some(match key {
        ServerKey::Rsa(_) => SignatureScheme::RSA_PSS_RSAE_SHA256,
        ServerKey::Ecdsa(k) => return tls_signature_scheme_for_curve(k.curve()),
        ServerKey::Ed25519(_) => SignatureScheme::ED25519,
        ServerKey::Ed448(_) => SignatureScheme::ED448,
        #[cfg(feature = "mldsa")]
        ServerKey::MlDsa44(_) => SignatureScheme::MLDSA44,
        #[cfg(feature = "mldsa")]
        ServerKey::MlDsa65(_) => SignatureScheme::MLDSA65,
        #[cfg(feature = "mldsa")]
        ServerKey::MlDsa87(_) => SignatureScheme::MLDSA87,
        // External keys advertise a list; the concrete scheme is negotiated
        // against the peer's offer at handshake time (the engine stores it and
        // never reaches the inline sign path). Report the preferred entry as a
        // representative for any single-scheme query.
        ServerKey::External { schemes } => schemes
            .first()
            .copied()
            .unwrap_or(SignatureScheme::RSA_PSS_RSAE_SHA256),
    })
}

/// Signs `content` for a TLS 1.3 / DTLS 1.3 `CertificateVerify` using
/// `key`, returning the (scheme, signature_bytes) tuple. Dispatches over
/// every supported key type — RSA-PSS, ECDSA (NIST and Brainpool curves),
/// Ed25519, Ed448, ML-DSA-44/65/87. A key with no IANA scheme (ECDSA on
/// secp256k1 / SM2) is [`Error::UnsupportedKeyType`].
pub(crate) fn sign_certificate_verify<R: RngCore>(
    key: &ServerKey,
    content: &[u8],
    rng: &mut R,
) -> Result<(SignatureScheme, Vec<u8>), Error> {
    let scheme = signature_scheme_for(key).ok_or(Error::UnsupportedKeyType)?;
    let signature = match key {
        ServerKey::Rsa(k) => k
            .sign_pss::<Sha256, _>(content, rng)
            .map_err(|_| Error::HandshakeFailure)?,
        ServerKey::Ecdsa(k) => {
            let curve = k.curve();
            let sig = match curve {
                CurveId::P384 | CurveId::BrainpoolP384r1 => k.sign::<Sha384>(content),
                CurveId::P521 | CurveId::BrainpoolP512r1 => k.sign::<Sha512>(content),
                _ => k.sign::<Sha256>(content),
            }
            .map_err(|_| Error::HandshakeFailure)?;
            sig.to_der(curve)
        }
        ServerKey::Ed25519(k) => k.sign(content).to_bytes().to_vec(),
        // Ed448: raw 114-byte R‖S over the empty context (pure Ed448).
        ServerKey::Ed448(k) => k.sign(content).to_bytes().to_vec(),
        // ML-DSA: raw FIPS 204 signature bytes; no DER wrapping. Hedged
        // with the supplied RNG.
        #[cfg(feature = "mldsa")]
        ServerKey::MlDsa44(k) => k
            .sign(rng, content, b"")
            .map(|s| s.to_vec())
            .map_err(|_| Error::HandshakeFailure)?,
        #[cfg(feature = "mldsa")]
        ServerKey::MlDsa65(k) => k
            .sign(rng, content, b"")
            .map(|s| s.to_vec())
            .map_err(|_| Error::HandshakeFailure)?,
        #[cfg(feature = "mldsa")]
        ServerKey::MlDsa87(k) => k
            .sign(rng, content, b"")
            .map(|s| s.to_vec())
            .map_err(|_| Error::HandshakeFailure)?,
        // External keys never reach the in-process sign path: the engine
        // suspends the handshake and the caller supplies the signature. This
        // arm is defensive only.
        ServerKey::External { .. } => return Err(Error::HandshakeFailure),
    };
    Ok((scheme, signature))
}

/// Verifies a TLS 1.3 handshake signature of `message` under `key`, dispatching
/// through [`crate::signature_registry`] on `scheme`.
///
/// `policy` gates the scheme: a scheme not on its whitelist (even one in the
/// registry) is rejected with [`Error::BadCertificate`].
///
/// Returns [`Error::PeerMisbehaved`] if the scheme is unsupported by the
/// registry or does not match the key type, [`Error::Decode`] if the
/// signature wire format is malformed, and [`Error::BadCertificate`] if the
/// signature is otherwise invalid (or policy-rejected).
pub(crate) fn verify_signature(
    scheme: SignatureScheme,
    key: &AnyPublicKey,
    message: &[u8],
    signature: &[u8],
    policy: &SignaturePolicy,
) -> Result<(), Error> {
    let algo = find_by_tls_scheme(scheme.0).ok_or(Error::PeerMisbehaved)?;
    // The registry verifier needs an SPKI; round-trip the parsed key. (A few
    // hundred bytes of allocation per CertificateVerify is negligible next to
    // the asymmetric verify itself.)
    let spki = key.to_spki_der();
    if !policy.permits(algo, &spki) {
        return Err(Error::BadCertificate);
    }
    match algo.verify(&spki, message, signature) {
        Ok(()) => Ok(()),
        // `UnsupportedAlgorithm` here means the SPKI's key type doesn't match
        // the scheme (e.g. an RSA key against `ecdsa_secp256r1_sha256`).
        Err(X509Error::UnsupportedAlgorithm) => Err(Error::PeerMisbehaved),
        Err(X509Error::Malformed) => Err(Error::Decode),
        Err(_) => Err(Error::BadCertificate),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Digest, Sha256};
    use crate::test_util::from_hex_vec;
    use crate::x509::Certificate;

    /// Every in-process `ServerKey` type round-trips through
    /// `sign_certificate_verify` -> `verify_signature`: the scheme the
    /// signer reports resolves in the registry, is permitted by the default
    /// `modern()` policy, and its `verify` accepts the signature over the
    /// SPKI re-encoded from the matching `AnyPublicKey`. This pins the
    /// scheme <-> hash <-> signature-encoding agreement between the TLS
    /// signer, the registry entry and the x509 SPKI codec for each
    /// algorithm.
    #[test]
    fn every_server_key_type_round_trips_certificate_verify() {
        use crate::ec::{BoxedEcdsaPrivateKey, Ed448PrivateKey, Ed25519PrivateKey};
        use crate::rng::HmacDrbg;
        use crate::rsa::BoxedRsaPrivateKey;
        use crate::x509::AnyPublicKey;

        let mut rng = HmacDrbg::<Sha256>::new(b"cv-all-keys", b"nonce", &[]);
        let content = certificate_verify_content(true, &[0x5a; 32]);

        let rsa = crate::test_util::rsa_test_key_a();
        let rsa = BoxedRsaPrivateKey::from_pkcs1_der(&rsa.to_pkcs1_der()).unwrap();
        let p256 = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let p384 = BoxedEcdsaPrivateKey::generate(CurveId::P384, &mut rng);
        let p521 = BoxedEcdsaPrivateKey::generate(CurveId::P521, &mut rng);
        let bp256 = BoxedEcdsaPrivateKey::generate(CurveId::BrainpoolP256r1, &mut rng);
        let bp384 = BoxedEcdsaPrivateKey::generate(CurveId::BrainpoolP384r1, &mut rng);
        let bp512 = BoxedEcdsaPrivateKey::generate(CurveId::BrainpoolP512r1, &mut rng);
        let ed25519 = Ed25519PrivateKey::generate(&mut rng);
        let ed448 = Ed448PrivateKey::generate(&mut rng);

        // secp256k1 and SM2 have no IANA scheme: refused, never signed under
        // a NIST code point.
        for curve in [CurveId::Secp256k1, CurveId::Sm2p256v1] {
            let key = ServerKey::Ecdsa(BoxedEcdsaPrivateKey::generate(curve, &mut rng));
            assert_eq!(signature_scheme_for(&key), None, "{curve:?}");
            assert!(matches!(
                sign_certificate_verify(&key, &content, &mut rng),
                Err(Error::UnsupportedKeyType)
            ));
        }

        // Only pushed to under `mldsa`.
        #[allow(unused_mut)]
        let mut cases: Vec<(ServerKey, AnyPublicKey, SignatureScheme)> = alloc::vec![
            (
                ServerKey::Rsa(rsa.clone()),
                AnyPublicKey::Rsa(rsa.public_key()),
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ),
            (
                ServerKey::Ecdsa(p256.clone()),
                AnyPublicKey::Ecdsa(p256.public_key()),
                SignatureScheme::ECDSA_SECP256R1_SHA256,
            ),
            (
                ServerKey::Ecdsa(p384.clone()),
                AnyPublicKey::Ecdsa(p384.public_key()),
                SignatureScheme::ECDSA_SECP384R1_SHA384,
            ),
            (
                ServerKey::Ecdsa(p521.clone()),
                AnyPublicKey::Ecdsa(p521.public_key()),
                SignatureScheme::ECDSA_SECP521R1_SHA512,
            ),
            (
                ServerKey::Ecdsa(bp256.clone()),
                AnyPublicKey::Ecdsa(bp256.public_key()),
                SignatureScheme::ECDSA_BRAINPOOLP256R1TLS13_SHA256,
            ),
            (
                ServerKey::Ecdsa(bp384.clone()),
                AnyPublicKey::Ecdsa(bp384.public_key()),
                SignatureScheme::ECDSA_BRAINPOOLP384R1TLS13_SHA384,
            ),
            (
                ServerKey::Ecdsa(bp512.clone()),
                AnyPublicKey::Ecdsa(bp512.public_key()),
                SignatureScheme::ECDSA_BRAINPOOLP512R1TLS13_SHA512,
            ),
            (
                ServerKey::Ed25519(ed25519.clone()),
                AnyPublicKey::Ed25519(ed25519.public_key()),
                SignatureScheme::ED25519,
            ),
            (
                ServerKey::Ed448(ed448.clone()),
                AnyPublicKey::Ed448(ed448.public_key()),
                SignatureScheme::ED448,
            ),
        ];
        #[cfg(feature = "mldsa")]
        {
            let (sk, pk) = crate::mldsa::MlDsa44PrivateKey::generate(&mut rng);
            cases.push((
                ServerKey::MlDsa44(sk),
                AnyPublicKey::MlDsa44(pk),
                SignatureScheme::MLDSA44,
            ));
            let (sk, pk) = crate::mldsa::MlDsa65PrivateKey::generate(&mut rng);
            cases.push((
                ServerKey::MlDsa65(sk),
                AnyPublicKey::MlDsa65(pk),
                SignatureScheme::MLDSA65,
            ));
            let (sk, pk) = crate::mldsa::MlDsa87PrivateKey::generate(&mut rng);
            cases.push((
                ServerKey::MlDsa87(sk),
                AnyPublicKey::MlDsa87(pk),
                SignatureScheme::MLDSA87,
            ));
        }

        let policy = SignaturePolicy::modern();
        for (key, pk, want_scheme) in &cases {
            let (scheme, sig) = sign_certificate_verify(key, &content, &mut rng).unwrap();
            assert_eq!(scheme, *want_scheme, "scheme for {want_scheme:?}");
            assert_eq!(signature_scheme_for(key), Some(scheme));
            let algo = find_by_tls_scheme(scheme.0).expect("scheme in registry");
            assert!(
                policy.permits(algo, &pk.to_spki_der()),
                "modern() must permit {}",
                algo.id()
            );
            verify_signature(scheme, pk, &content, &sig, &policy)
                .unwrap_or_else(|e| panic!("{}: {e:?}", algo.id()));
            // Wrong content: a bad signature, never a decode/misbehaviour error.
            let other = certificate_verify_content(false, &[0x5a; 32]);
            assert!(matches!(
                verify_signature(scheme, pk, &other, &sig, &policy),
                Err(Error::BadCertificate)
            ));
            // Every other case's key must be rejected as a key/scheme
            // mismatch, not verified.
            for (_, other_pk, other_scheme) in &cases {
                if other_scheme != want_scheme {
                    assert!(
                        verify_signature(scheme, other_pk, &content, &sig, &policy).is_err(),
                        "{} accepted a signature under a {other_scheme:?} key",
                        algo.id()
                    );
                }
            }
        }
    }

    // RFC 8448 §3: verify the server's CertificateVerify (rsa_pss_rsae_sha256,
    // RSA-1024 certified key) over the reconstructed transcript.
    #[test]
    fn rfc8448_certificate_verify() {
        let ch = from_hex_vec(include_str!("../../../testdata/rfc8448_client_hello.hex"));
        let sh = from_hex_vec(include_str!("../../../testdata/rfc8448_server_hello.hex"));
        let flight = from_hex_vec(include_str!(
            "../../../testdata/rfc8448_server_flight_payload.hex"
        ));

        // Server key from the Certificate message (cert DER at offset 51..483).
        let cert = Certificate::from_der(flight[51..483].to_vec()).unwrap();
        let key = cert.subject_public_key().unwrap();

        // Transcript-Hash(ClientHello .. Certificate): CH || SH || EE || Cert,
        // where EE||Cert is flight[0..485].
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&ch);
        transcript.extend_from_slice(&sh);
        transcript.extend_from_slice(&flight[0..485]);
        let th = Sha256::digest(&transcript);

        let content = certificate_verify_content(true, th.as_ref());

        // CertificateVerify message at flight[485..621]: 0f 00 00 84 | 08 04 |
        // 00 80 | sig(128).
        let scheme = SignatureScheme(u16::from_be_bytes([flight[489], flight[490]]));
        assert_eq!(scheme, SignatureScheme::RSA_PSS_RSAE_SHA256);
        let sig = &flight[493..621];

        // RFC 8448 uses an RSA-1024 server key; the modern default policy
        // floors RSA at 2048. Loosen for this single legacy fixture.
        let policy = SignaturePolicy::modern().with_min_rsa_bits(1024);
        verify_signature(scheme, &key, &content, sig, &policy).unwrap();

        // A tampered transcript must not verify.
        let mut bad = content.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            verify_signature(scheme, &key, &bad, sig, &policy),
            Err(Error::BadCertificate)
        ));

        // Wrong scheme for an RSA key (ECDSA) is a misbehavior, not a bad sig.
        assert!(matches!(
            verify_signature(
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                &key,
                &content,
                sig,
                &policy,
            ),
            Err(Error::PeerMisbehaved)
        ));
    }
}
