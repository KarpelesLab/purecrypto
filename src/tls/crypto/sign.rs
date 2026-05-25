//! TLS 1.3 handshake signatures (RFC 8446 §4.4.3).
//!
//! A `CertificateVerify` proves possession of the certified key by signing a
//! context-bound digest of the handshake transcript. The signature scheme is a
//! 16-bit `SignatureScheme` code (not an X.509 OID), so verification is
//! dispatched here on the wire scheme and the peer's [`AnyPublicKey`].

use crate::ec::{BoxedEcdsaSignature, CurveId};
use crate::hash::{Sha256, Sha384, Sha512};
use crate::tls::Error;
use crate::tls::codec::SignatureScheme;
use crate::x509::AnyPublicKey;
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

/// Verifies a TLS 1.3 handshake signature of `message` under `key`, dispatching
/// on `scheme`. Returns [`Error::PeerMisbehaved`] if the scheme is unsupported
/// or does not match the key type, and [`Error::BadCertificate`] if the
/// signature is invalid.
pub(crate) fn verify_signature(
    scheme: SignatureScheme,
    key: &AnyPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    match key {
        AnyPublicKey::Rsa(k) => {
            let r = if scheme == SignatureScheme::RSA_PSS_RSAE_SHA256 {
                k.verify_pss::<Sha256>(message, signature)
            } else if scheme == SignatureScheme::RSA_PSS_RSAE_SHA384 {
                k.verify_pss::<Sha384>(message, signature)
            } else if scheme == SignatureScheme::RSA_PKCS1_SHA256 {
                k.verify_pkcs1v15::<Sha256>(message, signature)
            } else if scheme == SignatureScheme::RSA_PKCS1_SHA384 {
                k.verify_pkcs1v15::<Sha384>(message, signature)
            } else {
                return Err(Error::PeerMisbehaved);
            };
            r.map_err(|_| Error::BadCertificate)
        }
        AnyPublicKey::Ecdsa(k) => {
            // The scheme fixes both the curve and the hash; the key's curve
            // must match.
            let (expected_curve, hash) = if scheme == SignatureScheme::ECDSA_SECP256R1_SHA256 {
                (CurveId::P256, EcdsaHash::Sha256)
            } else if scheme == SignatureScheme::ECDSA_SECP384R1_SHA384 {
                (CurveId::P384, EcdsaHash::Sha384)
            } else if scheme == SignatureScheme::ECDSA_SECP521R1_SHA512 {
                (CurveId::P521, EcdsaHash::Sha512)
            } else {
                return Err(Error::PeerMisbehaved);
            };
            if k.curve() != expected_curve {
                return Err(Error::PeerMisbehaved);
            }
            let sig = BoxedEcdsaSignature::from_der(signature).map_err(|_| Error::Decode)?;
            let r = match hash {
                EcdsaHash::Sha256 => k.verify::<Sha256>(message, &sig),
                EcdsaHash::Sha384 => k.verify::<Sha384>(message, &sig),
                EcdsaHash::Sha512 => k.verify::<Sha512>(message, &sig),
            };
            r.map_err(|_| Error::BadCertificate)
        }
    }
}

/// Selects the hash for an ECDSA signature scheme.
enum EcdsaHash {
    Sha256,
    Sha384,
    Sha512,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Digest;
    use crate::test_util::from_hex_vec;
    use crate::x509::Certificate;

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

        verify_signature(scheme, &key, &content, sig).unwrap();

        // A tampered transcript must not verify.
        let mut bad = content.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            verify_signature(scheme, &key, &bad, sig),
            Err(Error::BadCertificate)
        ));

        // Wrong scheme for an RSA key (ECDSA) is a misbehavior, not a bad sig.
        assert!(matches!(
            verify_signature(SignatureScheme::ECDSA_SECP256R1_SHA256, &key, &content, sig),
            Err(Error::PeerMisbehaved)
        ));
    }
}
