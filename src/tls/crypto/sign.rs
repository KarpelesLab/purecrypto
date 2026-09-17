//! TLS 1.3 handshake signatures (RFC 8446 §4.4.3).
//!
//! A `CertificateVerify` proves possession of the certified key by signing a
//! context-bound digest of the handshake transcript. The signature scheme is a
//! 16-bit `SignatureScheme` code (not an X.509 OID); dispatch goes through
//! [`crate::signature_registry`]: the scheme code picks a registry entry,
//! whose `verify(spki, message, signature)` re-parses the SPKI and delegates
//! to the underlying primitive.

use crate::ec::CurveId;
use crate::hash::{Digest, Sha256, Sha384, Sha512};
use crate::rng::RngCore;
use crate::rsa::BoxedRsaPrivateKey;
use crate::signature_registry::{SignaturePolicy, find_by_tls_scheme};
use crate::tls::Error;
use crate::tls::codec::SignatureScheme;
use crate::tls::conn::ServerKey;
use crate::x509::{AnyPublicKey, Certificate, Error as X509Error, PssHash};
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
        // No TLS 1.3 signature scheme exists for secp256k1, SM2, the SEC 2
        // 160/192/224-bit curves or the 224/320-bit Brainpool curves.
        CurveId::Secp256k1
        | CurveId::Sm2p256v1
        | CurveId::Secp160k1
        | CurveId::Secp160r1
        | CurveId::Secp160r2
        | CurveId::Secp192k1
        | CurveId::P192
        | CurveId::Secp224k1
        | CurveId::P224
        | CurveId::BrainpoolP224r1
        | CurveId::BrainpoolP320r1 => None,
    }
}

/// The digest one of the six RSA-PSS schemes (`rsa_pss_rsae_*` /
/// `rsa_pss_pss_*`, RFC 8446 §4.2.3) signs with — MGF1 over the same
/// digest, salt as long as the digest — or `None` for any other scheme.
pub(crate) fn rsa_pss_digest(scheme: SignatureScheme) -> Option<PssHash> {
    match scheme {
        SignatureScheme::RSA_PSS_RSAE_SHA256 | SignatureScheme::RSA_PSS_PSS_SHA256 => {
            Some(PssHash::Sha256)
        }
        SignatureScheme::RSA_PSS_RSAE_SHA384 | SignatureScheme::RSA_PSS_PSS_SHA384 => {
            Some(PssHash::Sha384)
        }
        SignatureScheme::RSA_PSS_RSAE_SHA512 | SignatureScheme::RSA_PSS_PSS_SHA512 => {
            Some(PssHash::Sha512)
        }
        _ => None,
    }
}

/// The `rsa_pss_pss_*` scheme for `hash` — what a key certified as
/// `id-RSASSA-PSS` signs a `CertificateVerify` under.
pub(crate) fn rsa_pss_pss_scheme(hash: PssHash) -> SignatureScheme {
    match hash {
        PssHash::Sha256 => SignatureScheme::RSA_PSS_PSS_SHA256,
        PssHash::Sha384 => SignatureScheme::RSA_PSS_PSS_SHA384,
        PssHash::Sha512 => SignatureScheme::RSA_PSS_PSS_SHA512,
    }
}

/// Signs `content` with RSASSA-PSS under `scheme`'s digest (any of the six
/// RSA-PSS schemes; the RSAE and PSS families differ only in the SPKI form
/// the peer requires, not in the signature). [`Error::UnsupportedKeyType`]
/// for a non-RSA-PSS scheme.
pub(crate) fn sign_rsa_pss<R: RngCore>(
    key: &BoxedRsaPrivateKey,
    scheme: SignatureScheme,
    content: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let hash = rsa_pss_digest(scheme).ok_or(Error::UnsupportedKeyType)?;
    match hash {
        PssHash::Sha256 => key.sign_pss::<Sha256, _>(content, rng),
        PssHash::Sha384 => key.sign_pss::<Sha384, _>(content, rng),
        PssHash::Sha512 => key.sign_pss::<Sha512, _>(content, rng),
    }
    .map_err(|_| Error::HandshakeFailure)
}

/// [`sign_rsa_pss`] with a salt derived deterministically (HMAC-DRBG) from
/// the key's public modulus and `content`, for the client engines, which
/// thread no RNG through the handshake state machine. The salt is public —
/// a verifier recovers it from the signature — so PSS's security does not
/// rest on it being unpredictable; a message-bound derivation only makes two
/// signatures of the same content identical, exactly as
/// `x509::CertSigner::RsaPss` issues certificates.
pub(crate) fn sign_rsa_pss_deterministic(
    key: &BoxedRsaPrivateKey,
    scheme: SignatureScheme,
    content: &[u8],
) -> Result<Vec<u8>, Error> {
    let modulus = key.public_key().to_pkcs1_der();
    let seed = Sha256::digest(&modulus);
    let nonce = Sha256::digest(content);
    let mut drbg = crate::rng::HmacDrbg::<Sha256>::new(
        seed.as_ref(),
        nonce.as_ref(),
        b"purecrypto tls RSASSA-PSS salt",
    );
    sign_rsa_pss(key, scheme, content, &mut drbg)
}

/// What a leaf certificate's SPKI says about the RSA-PSS scheme family an
/// identity may sign under. RFC 8446 §4.2.3 defines `rsa_pss_rsae_*` for a
/// key certified as `rsaEncryption` and `rsa_pss_pss_*` for one certified
/// as `id-RSASSA-PSS`, whose RFC 4055 restriction (if any) also pins the
/// digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeafRsaForm {
    /// `rsaEncryption`.
    RsaEncryption,
    /// `id-RSASSA-PSS`, restricted to the named digest when `Some`.
    RsaPss(Option<PssHash>),
    /// Not an RSA key, or no parseable leaf: nothing to bind (a chain that
    /// does not parse fails the handshake for its own reasons).
    Other,
}

/// The [`LeafRsaForm`] of `chain[0]`.
pub(crate) fn leaf_rsa_form(chain: &[Vec<u8>]) -> LeafRsaForm {
    let Some(leaf) = chain.first() else {
        return LeafRsaForm::Other;
    };
    let Ok(cert) = Certificate::from_der(leaf.clone()) else {
        return LeafRsaForm::Other;
    };
    match cert.subject_public_key() {
        Ok(AnyPublicKey::Rsa(_)) => LeafRsaForm::RsaEncryption,
        Ok(AnyPublicKey::RsaPss(_, restriction)) => LeafRsaForm::RsaPss(restriction.hash()),
        _ => LeafRsaForm::Other,
    }
}

/// Whether a leaf of `form` permits signing under `scheme` (RFC 8446
/// §4.2.3): an `rsaEncryption` leaf excludes `rsa_pss_pss_*`, an
/// `id-RSASSA-PSS` leaf excludes `rsa_pss_rsae_*` and, when restricted,
/// every `rsa_pss_pss_*` digest but its own. Non-RSA schemes are left to the
/// key/certificate consistency check.
pub(crate) fn leaf_permits_scheme(form: LeafRsaForm, scheme: SignatureScheme) -> bool {
    match form {
        LeafRsaForm::Other => true,
        LeafRsaForm::RsaEncryption => !scheme.is_rsa_pss_pss(),
        LeafRsaForm::RsaPss(restricted) => {
            !scheme.is_rsa_pss_rsae()
                && (!scheme.is_rsa_pss_pss()
                    || restricted.is_none_or(|hash| rsa_pss_digest(scheme) == Some(hash)))
        }
    }
}

/// The IANA-blessed [`SignatureScheme`] code for the given [`ServerKey`], or
/// `None` for a key that has none (ECDSA on secp256k1 / SM2, see
/// [`tls_signature_scheme_for_curve`]).
pub(crate) fn signature_scheme_for(key: &ServerKey) -> Option<SignatureScheme> {
    Some(match key {
        ServerKey::Rsa(_) => SignatureScheme::RSA_PSS_RSAE_SHA256,
        ServerKey::RsaPss(_, hash) => rsa_pss_pss_scheme(*hash),
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
/// every supported key type — RSA-PSS (`rsa_pss_rsae_sha256` for an
/// `rsaEncryption` leaf, `rsa_pss_pss_*` for an `id-RSASSA-PSS` one), ECDSA
/// (NIST and Brainpool curves), Ed25519, Ed448, ML-DSA-44/65/87. A key with
/// no IANA scheme (ECDSA on secp256k1 / SM2) is
/// [`Error::UnsupportedKeyType`].
pub(crate) fn sign_certificate_verify<R: RngCore>(
    key: &ServerKey,
    content: &[u8],
    rng: &mut R,
) -> Result<(SignatureScheme, Vec<u8>), Error> {
    let scheme = signature_scheme_for(key).ok_or(Error::UnsupportedKeyType)?;
    let signature = match key {
        ServerKey::Rsa(k) | ServerKey::RsaPss(k, _) => sign_rsa_pss(k, scheme, content, rng)?,
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
/// registry or does not match the key type — including the RFC 8446 §4.2.3
/// SPKI-form rule: `rsa_pss_rsae_*` only under a key certified as
/// `rsaEncryption`, `rsa_pss_pss_*` only under one certified as
/// `id-RSASSA-PSS` — [`Error::Decode`] if the signature wire format is
/// malformed, and [`Error::BadCertificate`] if the signature is otherwise
/// invalid (or policy-rejected).
pub(crate) fn verify_signature(
    scheme: SignatureScheme,
    key: &AnyPublicKey,
    message: &[u8],
    signature: &[u8],
    policy: &SignaturePolicy,
) -> Result<(), Error> {
    let algo = find_by_tls_scheme(scheme.0).ok_or(Error::PeerMisbehaved)?;
    // The `rsa-pss-pss-*` registry entries accept both RSA SPKI forms (the
    // X.509 path needs the `rsaEncryption` one), so the TLS rule is applied
    // here, where the parsed key is at hand.
    let form_ok = if scheme.is_rsa_pss_rsae() {
        matches!(key, AnyPublicKey::Rsa(_))
    } else if scheme.is_rsa_pss_pss() {
        matches!(key, AnyPublicKey::RsaPss(..))
    } else {
        true
    };
    if !form_ok {
        return Err(Error::PeerMisbehaved);
    }
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
            // The same RSA key certified as `id-RSASSA-PSS` signs the
            // `rsa_pss_pss_*` family: unrestricted (SHA-256) and pinned to
            // SHA-384 / SHA-512 by the SPKI's RSASSA-PSS-params.
            (
                ServerKey::RsaPss(rsa.clone(), PssHash::Sha256),
                AnyPublicKey::RsaPss(rsa.public_key(), crate::x509::PssRestriction::Unrestricted),
                SignatureScheme::RSA_PSS_PSS_SHA256,
            ),
            (
                ServerKey::RsaPss(rsa.clone(), PssHash::Sha384),
                AnyPublicKey::RsaPss(
                    rsa.public_key(),
                    crate::x509::PssRestriction::for_hash(PssHash::Sha384),
                ),
                SignatureScheme::RSA_PSS_PSS_SHA384,
            ),
            (
                ServerKey::RsaPss(rsa.clone(), PssHash::Sha512),
                AnyPublicKey::RsaPss(
                    rsa.public_key(),
                    crate::x509::PssRestriction::for_hash(PssHash::Sha512),
                ),
                SignatureScheme::RSA_PSS_PSS_SHA512,
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
            // mismatch, not verified. The one legitimate cross-match: the
            // RSA-PSS cases share one modulus, and an *unrestricted*
            // `id-RSASSA-PSS` key verifies any `rsa_pss_pss_*` digest.
            for (_, other_pk, other_scheme) in &cases {
                let unrestricted_pss = matches!(
                    other_pk,
                    AnyPublicKey::RsaPss(_, crate::x509::PssRestriction::Unrestricted)
                );
                if other_scheme != want_scheme && !(unrestricted_pss && scheme.is_rsa_pss_pss()) {
                    assert!(
                        verify_signature(scheme, other_pk, &content, &sig, &policy).is_err(),
                        "{} accepted a signature under a {other_scheme:?} key",
                        algo.id()
                    );
                }
            }
        }
    }

    /// RFC 8446 §4.2.3 ties each RSA-PSS scheme family to one SPKI form:
    /// `rsa_pss_rsae_*` verify only under a key certified as
    /// `rsaEncryption`, `rsa_pss_pss_*` only under one certified as
    /// `id-RSASSA-PSS` — and a restricted PSS key only under its digest.
    /// The signatures themselves are identical PSS signatures (the same
    /// bytes verify under both families' matching key form), so the family
    /// check is what separates them, as `PeerMisbehaved`.
    #[test]
    fn rsa_pss_scheme_families_are_tied_to_the_spki_form() {
        use crate::rng::HmacDrbg;
        use crate::rsa::BoxedRsaPrivateKey;
        use crate::x509::PssRestriction;

        let mut rng = HmacDrbg::<Sha256>::new(b"cv-pss-forms", b"nonce", &[]);
        let content = certificate_verify_content(true, &[0x5a; 32]);
        let rsa = crate::test_util::rsa_test_key_a();
        let rsa = BoxedRsaPrivateKey::from_pkcs1_der(&rsa.to_pkcs1_der()).unwrap();
        let policy = SignaturePolicy::modern();
        let rsae_key = AnyPublicKey::Rsa(rsa.public_key());
        let pss_any = AnyPublicKey::RsaPss(rsa.public_key(), PssRestriction::Unrestricted);
        let pss_for = |hash| AnyPublicKey::RsaPss(rsa.public_key(), PssRestriction::for_hash(hash));

        for (rsae, pss, hash) in [
            (
                SignatureScheme::RSA_PSS_RSAE_SHA256,
                SignatureScheme::RSA_PSS_PSS_SHA256,
                PssHash::Sha256,
            ),
            (
                SignatureScheme::RSA_PSS_RSAE_SHA384,
                SignatureScheme::RSA_PSS_PSS_SHA384,
                PssHash::Sha384,
            ),
            (
                SignatureScheme::RSA_PSS_RSAE_SHA512,
                SignatureScheme::RSA_PSS_PSS_SHA512,
                PssHash::Sha512,
            ),
        ] {
            assert_eq!(rsa_pss_digest(rsae), Some(hash));
            assert_eq!(rsa_pss_digest(pss), Some(hash));
            assert_eq!(rsa_pss_pss_scheme(hash), pss);
            assert!(rsae.is_rsa_pss_rsae() && !rsae.is_rsa_pss_pss());
            assert!(pss.is_rsa_pss_pss() && !pss.is_rsa_pss_rsae());
            for s in [rsae, pss] {
                let algo = find_by_tls_scheme(s.0).unwrap();
                assert!(
                    policy.permits(algo, &rsae_key.to_spki_der()),
                    "{}",
                    algo.id()
                );
                assert!(
                    policy.permits(algo, &pss_any.to_spki_der()),
                    "{}",
                    algo.id()
                );
            }
            // One PSS signature serves both code points; the key form decides.
            let sig = sign_rsa_pss(&rsa, rsae, &content, &mut rng).unwrap();
            verify_signature(rsae, &rsae_key, &content, &sig, &policy).unwrap();
            verify_signature(pss, &pss_any, &content, &sig, &policy).unwrap();
            verify_signature(pss, &pss_for(hash), &content, &sig, &policy).unwrap();
            assert!(matches!(
                verify_signature(rsae, &pss_any, &content, &sig, &policy),
                Err(Error::PeerMisbehaved)
            ));
            assert!(matches!(
                verify_signature(rsae, &pss_for(hash), &content, &sig, &policy),
                Err(Error::PeerMisbehaved)
            ));
            assert!(matches!(
                verify_signature(pss, &rsae_key, &content, &sig, &policy),
                Err(Error::PeerMisbehaved)
            ));
            // A PSS key restricted to another digest refuses the scheme.
            let other = if hash == PssHash::Sha256 {
                PssHash::Sha384
            } else {
                PssHash::Sha256
            };
            assert!(matches!(
                verify_signature(pss, &pss_for(other), &content, &sig, &policy),
                Err(Error::PeerMisbehaved)
            ));
            // The deterministic (client-side) signer produces a valid,
            // repeatable signature under the same scheme.
            let d1 = sign_rsa_pss_deterministic(&rsa, pss, &content).unwrap();
            let d2 = sign_rsa_pss_deterministic(&rsa, pss, &content).unwrap();
            assert_eq!(d1, d2);
            assert_ne!(d1, sign_rsa_pss_deterministic(&rsa, pss, b"other").unwrap());
            verify_signature(pss, &pss_any, &content, &d1, &policy).unwrap();
            verify_signature(rsae, &rsae_key, &content, &d1, &policy).unwrap();
        }
        assert_eq!(rsa_pss_digest(SignatureScheme::ED25519), None);
        assert!(matches!(
            sign_rsa_pss(&rsa, SignatureScheme::ED25519, &content, &mut rng),
            Err(Error::UnsupportedKeyType)
        ));
    }

    /// The leaf certificate's SPKI form decides which RSA-PSS family an
    /// identity signs under (RFC 8446 §4.2.3): `leaf_rsa_form` reads it,
    /// `leaf_permits_scheme` filters an external key's schemes by it, and
    /// `ServerKey::bound_to_leaf` turns an in-process RSA key certified as
    /// `id-RSASSA-PSS` into one that signs `rsa_pss_pss_*` over the
    /// restriction's digest.
    #[test]
    fn leaf_spki_form_binds_the_rsa_pss_family() {
        use crate::rsa::BoxedRsaPrivateKey;
        use crate::x509::{CertSigner, DistinguishedName, PssRestriction, Time, Validity};

        let rsa = crate::test_util::rsa_test_key_a();
        let rsa = BoxedRsaPrivateKey::from_pkcs1_der(&rsa.to_pkcs1_der()).unwrap();
        let name = DistinguishedName::common_name("leaf.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let rsae_leaf = Certificate::self_signed_general(
            &CertSigner::Rsa(&rsa),
            &name,
            &validity,
            1,
            false,
            &[],
        )
        .unwrap()
        .to_der()
        .to_vec();
        let pss384_leaf = Certificate::self_signed_general(
            &CertSigner::RsaPss(&rsa, PssHash::Sha384),
            &name,
            &validity,
            2,
            false,
            &[],
        )
        .unwrap()
        .to_der()
        .to_vec();
        // An unrestricted `id-RSASSA-PSS` SPKI: self-issued (PSS-SHA-256)
        // over the PSS form of the key with absent parameters.
        let pss_any_leaf = Certificate::issue_general(
            &CertSigner::RsaPss(&rsa, PssHash::Sha256),
            &name,
            &name,
            &AnyPublicKey::RsaPss(rsa.public_key(), PssRestriction::Unrestricted),
            &validity,
            3,
            false,
            &[],
        )
        .unwrap()
        .to_der()
        .to_vec();
        let mut rng = crate::rng::HmacDrbg::<Sha256>::new(b"leaf-form-ec", b"nonce", &[]);
        let ec = crate::ec::BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let ec_leaf = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&ec),
            &name,
            &validity,
            4,
            false,
            &[],
        )
        .unwrap()
        .to_der()
        .to_vec();

        assert_eq!(
            leaf_rsa_form(core::slice::from_ref(&rsae_leaf)),
            LeafRsaForm::RsaEncryption
        );
        assert_eq!(
            leaf_rsa_form(core::slice::from_ref(&pss384_leaf)),
            LeafRsaForm::RsaPss(Some(PssHash::Sha384))
        );
        assert_eq!(
            leaf_rsa_form(core::slice::from_ref(&pss_any_leaf)),
            LeafRsaForm::RsaPss(None)
        );
        assert_eq!(
            leaf_rsa_form(core::slice::from_ref(&ec_leaf)),
            LeafRsaForm::Other
        );
        assert_eq!(leaf_rsa_form(&[]), LeafRsaForm::Other);
        assert_eq!(
            leaf_rsa_form(&[alloc::vec![0x30, 0x00]]),
            LeafRsaForm::Other
        );

        let all = [
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA384,
            SignatureScheme::RSA_PSS_PSS_SHA256,
            SignatureScheme::RSA_PSS_PSS_SHA384,
            SignatureScheme::RSA_PSS_PSS_SHA512,
            SignatureScheme::ED25519,
        ];
        let permitted = |form| -> Vec<SignatureScheme> {
            all.iter()
                .copied()
                .filter(|s| leaf_permits_scheme(form, *s))
                .collect()
        };
        assert_eq!(
            permitted(LeafRsaForm::RsaEncryption),
            [
                SignatureScheme::RSA_PSS_RSAE_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA384,
                SignatureScheme::ED25519,
            ]
        );
        assert_eq!(
            permitted(LeafRsaForm::RsaPss(None)),
            [
                SignatureScheme::RSA_PSS_PSS_SHA256,
                SignatureScheme::RSA_PSS_PSS_SHA384,
                SignatureScheme::RSA_PSS_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        );
        assert_eq!(
            permitted(LeafRsaForm::RsaPss(Some(PssHash::Sha384))),
            [
                SignatureScheme::RSA_PSS_PSS_SHA384,
                SignatureScheme::ED25519
            ]
        );
        assert_eq!(permitted(LeafRsaForm::Other), all);

        // Binding an in-process key.
        let scheme_of =
            |key: ServerKey, chain: &[Vec<u8>]| signature_scheme_for(&key.bound_to_leaf(chain));
        assert_eq!(
            scheme_of(
                ServerKey::Rsa(rsa.clone()),
                core::slice::from_ref(&rsae_leaf)
            ),
            Some(SignatureScheme::RSA_PSS_RSAE_SHA256)
        );
        assert_eq!(
            scheme_of(
                ServerKey::Rsa(rsa.clone()),
                core::slice::from_ref(&pss384_leaf)
            ),
            Some(SignatureScheme::RSA_PSS_PSS_SHA384)
        );
        assert_eq!(
            scheme_of(
                ServerKey::Rsa(rsa.clone()),
                core::slice::from_ref(&pss_any_leaf)
            ),
            Some(SignatureScheme::RSA_PSS_PSS_SHA256)
        );
        assert_eq!(
            scheme_of(ServerKey::Rsa(rsa.clone()), &[]),
            Some(SignatureScheme::RSA_PSS_RSAE_SHA256)
        );
        // Binding an external key narrows its advertised schemes.
        let external = || ServerKey::External {
            schemes: all.to_vec(),
        };
        let schemes_of = |chain: &[Vec<u8>]| match external().bound_to_leaf(chain) {
            ServerKey::External { schemes } => schemes,
            _ => unreachable!(),
        };
        assert_eq!(
            schemes_of(core::slice::from_ref(&pss384_leaf)),
            [
                SignatureScheme::RSA_PSS_PSS_SHA384,
                SignatureScheme::ED25519
            ]
        );
        assert_eq!(
            schemes_of(core::slice::from_ref(&rsae_leaf)),
            permitted(LeafRsaForm::RsaEncryption)
        );
        assert_eq!(schemes_of(core::slice::from_ref(&ec_leaf)), all);
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
