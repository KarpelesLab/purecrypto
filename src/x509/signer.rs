//! A signing key for issuing certificates and certification requests — RSA,
//! ECDSA, Ed25519, or (under the `mldsa` feature) one of the three ML-DSA
//! security levels.

use alloc::vec::Vec;

use super::{AnyPublicKey, Error, PssHash, PssRestriction, algorithm_identifier, oid};
use crate::der::{encode_sequence, oid_tlv};
use crate::ec::{BoxedEcdsaPrivateKey, CurveId, Ed448PrivateKey, Ed25519PrivateKey};
use crate::hash::{Digest, Sha256, Sha384, Sha512};
#[cfg(feature = "mldsa")]
use crate::mldsa::{MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey};
#[cfg(any(feature = "mldsa", feature = "slhdsa"))]
use crate::rng::RngCore;
use crate::rsa::BoxedRsaPrivateKey;
#[cfg(feature = "slhdsa")]
use crate::slhdsa;

/// A certificate/CSR signing key.
///
/// RSA signs with PKCS#1 v1.5 over SHA-256 (`sha256WithRSAEncryption`) or,
/// as [`RsaPss`](Self::RsaPss), RSASSA-PSS over SHA-256 (`id-RSASSA-PSS`,
/// RFC 4055); ECDSA signs `ecdsa-with-SHAxxx` with the hash matched to the
/// curve (P-256 and secp256k1 → SHA-256, P-384 → SHA-384, P-521 → SHA-512);
/// Ed25519 signs `id-Ed25519` (PureEdDSA over SHA-512, RFC 8410); ML-DSA
/// signs under the matching `id-ml-dsa-N` OID (NIST FIPS 204 /
/// draft-ietf-lamps-dilithium-certificates) and SLH-DSA under its parameter
/// set's OID (FIPS 205).
///
/// Every variant signs **deterministically** through the public issuance
/// APIs (`Certificate::self_signed_general`, `issue_general`, the CSR / CRL /
/// OCSP builders): RSA PKCS#1 v1.5 and Ed25519/Ed448 are deterministic by
/// construction, ECDSA derives its nonce per RFC 6979, RSA-PSS derives its
/// salt from the key's modulus and the message (the salt is public — a
/// verifier recovers it — so it needs no fresh randomness), and ML-DSA /
/// SLH-DSA use their FIPS deterministic variants (hedging randomness set to
/// the zero string). No RNG is threaded through certificate issuance; a
/// caller that wants hedged PQ signatures signs the TBS out-of-band (see
/// [`SignatureAlgId`] and `Certificate::prepare`) and assembles the
/// certificate with `Certificate::from_der`.
#[non_exhaustive]
pub enum CertSigner<'a> {
    /// An RSA signing key, signing PKCS#1 v1.5 over SHA-256; the subject
    /// key it certifies for itself is `rsaEncryption`.
    Rsa(&'a BoxedRsaPrivateKey),
    /// An RSA signing key used as a PSS-restricted CA key (RFC 4055): signs
    /// RSASSA-PSS with SHA-256 / MGF1-SHA-256 / salt 32 under
    /// `id-RSASSA-PSS`, and [`public_key`](Self::public_key) is an
    /// [`AnyPublicKey::RsaPss`] pinned to exactly that parameter set, so a
    /// self-signed CA built from it carries an `id-RSASSA-PSS` SPKI that
    /// refuses PKCS#1 v1.5.
    RsaPss(&'a BoxedRsaPrivateKey),
    /// An ECDSA signing key.
    Ecdsa(&'a BoxedEcdsaPrivateKey),
    /// An Ed25519 signing key.
    Ed25519(&'a Ed25519PrivateKey),
    /// An Ed448 signing key.
    Ed448(&'a Ed448PrivateKey),
    /// An ML-DSA-44 signing key (FIPS 204).
    #[cfg(feature = "mldsa")]
    MlDsa44(&'a MlDsa44PrivateKey),
    /// An ML-DSA-65 signing key (FIPS 204).
    #[cfg(feature = "mldsa")]
    MlDsa65(&'a MlDsa65PrivateKey),
    /// An ML-DSA-87 signing key (FIPS 204).
    #[cfg(feature = "mldsa")]
    MlDsa87(&'a MlDsa87PrivateKey),
    /// An SLH-DSA signing key (FIPS 205). The parameter set lives inside
    /// the key.
    #[cfg(feature = "slhdsa")]
    SlhDsa(&'a slhdsa::PrivateKey),
}

/// The signature algorithm of an externally held (TPM/HSM) CA key.
///
/// This is the descriptor a caller supplies to the two-phase `prepare` /
/// `finish` issuance API ([`crate::x509::CrlBuilder::prepare`],
/// [`crate::x509::OcspResponseBuilder::prepare`],
/// [`crate::x509::Certificate::prepare`]) when the private key never enters
/// the process and the signature is produced out-of-band. It carries no key
/// material — only enough to emit the correct DER `AlgorithmIdentifier` and to
/// tell the caller which hash/padding their signer must apply to the TBS bytes.
///
/// The variants name the exact `signatureAlgorithm` OID written to the wire,
/// so the caller's signer must produce a matching signature (e.g.
/// [`EcdsaSha256`](Self::EcdsaSha256) → an ECDSA-over-SHA-256 signature encoded
/// as the `Ecdsa-Sig-Value` DER `SEQUENCE { r, s }`; RSA variants → PKCS#1 v1.5
/// over the named hash). The TBS bytes handed back are unhashed — the signer
/// applies the algorithm's own hash and encoding.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgId {
    /// `sha256WithRSAEncryption` — RSA PKCS#1 v1.5 over SHA-256.
    RsaPkcs1Sha256,
    /// `sha384WithRSAEncryption` — RSA PKCS#1 v1.5 over SHA-384.
    RsaPkcs1Sha384,
    /// `sha512WithRSAEncryption` — RSA PKCS#1 v1.5 over SHA-512.
    RsaPkcs1Sha512,
    /// `id-RSASSA-PSS` (RFC 4055) — RSASSA-PSS over SHA-256 with MGF1-SHA-256
    /// and a 32-octet salt; the `RSASSA-PSS-params` naming that set are
    /// written into the `AlgorithmIdentifier`. The signer's key may be
    /// certified as `rsaEncryption` or as an `id-RSASSA-PSS` key restricted
    /// to (or compatible with) this set.
    RsaPssSha256,
    /// `ecdsa-with-SHA256`. Signature is the `Ecdsa-Sig-Value` DER SEQUENCE.
    EcdsaSha256,
    /// `ecdsa-with-SHA384`. Signature is the `Ecdsa-Sig-Value` DER SEQUENCE.
    EcdsaSha384,
    /// `ecdsa-with-SHA512`. Signature is the `Ecdsa-Sig-Value` DER SEQUENCE.
    EcdsaSha512,
    /// `id-Ed25519` (PureEdDSA, RFC 8410). Signature is the raw 64-byte R‖S.
    Ed25519,
    /// `id-Ed448` (PureEdDSA, RFC 8410). Signature is the raw 114-byte R‖S.
    Ed448,
    /// `id-ml-dsa-44` (FIPS 204). Signature is the raw ML-DSA-44 signature.
    #[cfg(feature = "mldsa")]
    MlDsa44,
    /// `id-ml-dsa-65` (FIPS 204). Signature is the raw ML-DSA-65 signature.
    #[cfg(feature = "mldsa")]
    MlDsa65,
    /// `id-ml-dsa-87` (FIPS 204). Signature is the raw ML-DSA-87 signature.
    #[cfg(feature = "mldsa")]
    MlDsa87,
}

impl SignatureAlgId {
    /// The `signatureAlgorithm` OID arcs for this algorithm.
    pub(crate) fn sig_alg_oid(self) -> &'static [u64] {
        match self {
            SignatureAlgId::RsaPkcs1Sha256 => oid::SHA256_WITH_RSA,
            SignatureAlgId::RsaPkcs1Sha384 => oid::SHA384_WITH_RSA,
            SignatureAlgId::RsaPkcs1Sha512 => oid::SHA512_WITH_RSA,
            SignatureAlgId::RsaPssSha256 => oid::ID_RSASSA_PSS,
            SignatureAlgId::EcdsaSha256 => oid::ECDSA_WITH_SHA256,
            SignatureAlgId::EcdsaSha384 => oid::ECDSA_WITH_SHA384,
            SignatureAlgId::EcdsaSha512 => oid::ECDSA_WITH_SHA512,
            SignatureAlgId::Ed25519 => oid::ID_ED25519,
            SignatureAlgId::Ed448 => oid::ID_ED448,
            #[cfg(feature = "mldsa")]
            SignatureAlgId::MlDsa44 => oid::ID_ML_DSA_44,
            #[cfg(feature = "mldsa")]
            SignatureAlgId::MlDsa65 => oid::ID_ML_DSA_65,
            #[cfg(feature = "mldsa")]
            SignatureAlgId::MlDsa87 => oid::ID_ML_DSA_87,
        }
    }

    /// The DER `AlgorithmIdentifier` for this algorithm. RSA-PKCS1 carries a
    /// NULL `parameters`, RSA-PSS its `RSASSA-PSS-params`; everything else
    /// is the bare OID, matching [`CertSigner::algorithm_identifier`].
    pub(crate) fn algorithm_identifier(self) -> Vec<u8> {
        if self == SignatureAlgId::RsaPssSha256 {
            return rsassa_pss_sha256_algid();
        }
        algorithm_identifier(
            self.sig_alg_oid(),
            matches!(
                self,
                SignatureAlgId::RsaPkcs1Sha256
                    | SignatureAlgId::RsaPkcs1Sha384
                    | SignatureAlgId::RsaPkcs1Sha512
            ),
        )
    }
}

/// The `id-RSASSA-PSS` signature `AlgorithmIdentifier` naming the SHA-256 /
/// MGF1-SHA-256 / salt-32 parameter set (RFC 4055 §3.1) — the set
/// [`CertSigner::RsaPss`] and [`SignatureAlgId::RsaPssSha256`] sign with.
fn rsassa_pss_sha256_algid() -> Vec<u8> {
    let params = PssRestriction::for_hash(PssHash::Sha256).encode_params();
    encode_sequence(&[oid_tlv(oid::ID_RSASSA_PSS), params].concat())
}

/// Signs `tbs` with RSASSA-PSS over SHA-256 and a deterministic 32-octet
/// salt. The salt is derived (HMAC-DRBG) from the public modulus and the
/// message: PSS's security does not rest on salt secrecy or unpredictability
/// — a verifier recovers the salt from the signature — so a public, message-
/// bound derivation keeps issuance deterministic like every other
/// [`CertSigner`] variant without weakening the signature.
fn sign_pss_sha256_deterministic(key: &BoxedRsaPrivateKey, tbs: &[u8]) -> Result<Vec<u8>, Error> {
    let modulus = key.public_key().to_pkcs1_der();
    let seed = Sha256::digest(&modulus);
    let nonce = Sha256::digest(tbs);
    let mut drbg = crate::rng::HmacDrbg::<Sha256>::new(
        seed.as_ref(),
        nonce.as_ref(),
        b"purecrypto x509 RSASSA-PSS salt",
    );
    Ok(key.sign_pss::<Sha256, _>(tbs, &mut drbg)?)
}

impl CertSigner<'_> {
    /// The `signatureAlgorithm` OID arcs.
    pub(crate) fn sig_alg_oid(&self) -> &'static [u64] {
        match self {
            CertSigner::Rsa(_) => oid::SHA256_WITH_RSA,
            CertSigner::RsaPss(_) => oid::ID_RSASSA_PSS,
            CertSigner::Ecdsa(k) => match k.curve() {
                CurveId::P256
                | CurveId::Secp256k1
                | CurveId::Sm2p256v1
                | CurveId::BrainpoolP256r1 => oid::ECDSA_WITH_SHA256,
                CurveId::P384 | CurveId::BrainpoolP384r1 => oid::ECDSA_WITH_SHA384,
                CurveId::P521 | CurveId::BrainpoolP512r1 => oid::ECDSA_WITH_SHA512,
            },
            CertSigner::Ed25519(_) => oid::ID_ED25519,
            CertSigner::Ed448(_) => oid::ID_ED448,
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa44(_) => oid::ID_ML_DSA_44,
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa65(_) => oid::ID_ML_DSA_65,
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa87(_) => oid::ID_ML_DSA_87,
            #[cfg(feature = "slhdsa")]
            CertSigner::SlhDsa(k) => k.parameter_set().oid(),
        }
    }

    /// The DER `AlgorithmIdentifier` for the signature.
    ///
    /// RSA-PKCS1 carries a NULL `parameters`, RSA-PSS its
    /// `RSASSA-PSS-params`; everything else (ECDSA, Ed25519, ML-DSA) is the
    /// bare OID, no parameters.
    pub(crate) fn algorithm_identifier(&self) -> Vec<u8> {
        if matches!(self, CertSigner::RsaPss(_)) {
            return rsassa_pss_sha256_algid();
        }
        algorithm_identifier(self.sig_alg_oid(), matches!(self, CertSigner::Rsa(_)))
    }

    /// Signs `tbs`, returning the bytes for the signature BIT STRING.
    ///
    /// ML-DSA branches sign deterministically (the hedge randomness is set to
    /// the zero string). The deterministic mode is part of FIPS 204 and is
    /// fully verifiable; callers that need hedged ML-DSA issuance can sign
    /// the TBS out-of-band and call [`crate::x509::Certificate::from_der`]
    /// directly.
    pub(crate) fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            CertSigner::Rsa(k) => Ok(k.sign_pkcs1v15::<Sha256>(tbs)?),
            CertSigner::RsaPss(k) => sign_pss_sha256_deterministic(k, tbs),
            CertSigner::Ecdsa(k) => {
                let curve = k.curve();
                let sig = match curve {
                    CurveId::P256
                    | CurveId::Secp256k1
                    | CurveId::Sm2p256v1
                    | CurveId::BrainpoolP256r1 => k.sign::<Sha256>(tbs),
                    CurveId::P384 | CurveId::BrainpoolP384r1 => k.sign::<Sha384>(tbs),
                    CurveId::P521 | CurveId::BrainpoolP512r1 => k.sign::<Sha512>(tbs),
                }
                .map_err(|_| Error::Verification)?;
                Ok(sig.to_der(curve))
            }
            // Ed25519 is PureEdDSA: the raw 64-byte R‖S over the message itself.
            CertSigner::Ed25519(k) => Ok(k.sign(tbs).to_bytes().to_vec()),
            // Ed448 is PureEdDSA with the empty context: the raw 114-byte R‖S.
            CertSigner::Ed448(k) => Ok(k.sign(tbs).to_bytes().to_vec()),
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa44(k) => k
                .sign_deterministic(tbs, b"")
                .map(|s| s.to_vec())
                .map_err(|_| Error::Verification),
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa65(k) => k
                .sign_deterministic(tbs, b"")
                .map(|s| s.to_vec())
                .map_err(|_| Error::Verification),
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa87(k) => k
                .sign_deterministic(tbs, b"")
                .map(|s| s.to_vec())
                .map_err(|_| Error::Verification),
            #[cfg(feature = "slhdsa")]
            CertSigner::SlhDsa(k) => k
                .sign_deterministic(tbs, b"")
                .map_err(|_| Error::Verification),
        }
    }

    /// Like [`Self::sign`] but uses `rng` to hedge ML-DSA / SLH-DSA
    /// signatures. RSA / ECDSA / Ed25519 paths ignore the RNG (their signing
    /// is deterministic, or in the case of RSA-PKCS1 takes no fresh
    /// randomness in this code path).
    #[cfg(any(feature = "mldsa", feature = "slhdsa"))]
    #[allow(dead_code)]
    pub(crate) fn sign_with_rng<R: RngCore>(
        &self,
        tbs: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        match self {
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa44(k) => k
                .sign(rng, tbs, b"")
                .map_err(|_| Error::Verification)
                .map(|s| s.to_vec()),
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa65(k) => k
                .sign(rng, tbs, b"")
                .map_err(|_| Error::Verification)
                .map(|s| s.to_vec()),
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa87(k) => k
                .sign(rng, tbs, b"")
                .map_err(|_| Error::Verification)
                .map(|s| s.to_vec()),
            #[cfg(feature = "slhdsa")]
            CertSigner::SlhDsa(k) => k.sign(rng, tbs, b"").map_err(|_| Error::Verification),
            other => other.sign(tbs),
        }
    }

    /// The signer's own public key — the subject key when self-signing.
    pub fn public_key(&self) -> AnyPublicKey {
        match self {
            CertSigner::Rsa(k) => AnyPublicKey::Rsa(k.public_key()),
            CertSigner::RsaPss(k) => {
                AnyPublicKey::RsaPss(k.public_key(), PssRestriction::for_hash(PssHash::Sha256))
            }
            CertSigner::Ecdsa(k) => AnyPublicKey::Ecdsa(k.public_key()),
            CertSigner::Ed25519(k) => AnyPublicKey::Ed25519(k.public_key()),
            CertSigner::Ed448(k) => AnyPublicKey::Ed448(k.public_key()),
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa44(k) => AnyPublicKey::MlDsa44(k.public_key()),
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa65(k) => AnyPublicKey::MlDsa65(k.public_key()),
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa87(k) => AnyPublicKey::MlDsa87(k.public_key()),
            #[cfg(feature = "slhdsa")]
            CertSigner::SlhDsa(k) => AnyPublicKey::SlhDsa(k.public_key()),
        }
    }
}
