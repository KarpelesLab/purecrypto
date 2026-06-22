//! A signing key for issuing certificates and certification requests — RSA,
//! ECDSA, Ed25519, or (under the `mldsa` feature) one of the three ML-DSA
//! security levels.

use alloc::vec::Vec;

use super::{AnyPublicKey, Error, algorithm_identifier, oid};
use crate::ec::{BoxedEcdsaPrivateKey, CurveId, Ed448PrivateKey, Ed25519PrivateKey};
use crate::hash::{Sha256, Sha384, Sha512};
#[cfg(feature = "mldsa")]
use crate::mldsa::{MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey};
#[cfg(any(feature = "mldsa", feature = "slhdsa"))]
use crate::rng::RngCore;
use crate::rsa::BoxedRsaPrivateKey;
#[cfg(feature = "slhdsa")]
use crate::slhdsa;

/// A certificate/CSR signing key.
///
/// RSA signs with PKCS#1 v1.5 over SHA-256 (`sha256WithRSAEncryption`); ECDSA
/// signs `ecdsa-with-SHAxxx` with the hash matched to the curve (P-256 and
/// secp256k1 → SHA-256, P-384 → SHA-384, P-521 → SHA-512); Ed25519 signs
/// `id-Ed25519` (PureEdDSA over SHA-512, RFC 8410); ML-DSA signs under the
/// matching `id-ml-dsa-N` OID (NIST FIPS 204 / draft-ietf-lamps-dilithium-
/// certificates). ML-DSA signing is hedged with randomness from a caller-
/// supplied RNG; the public APIs that take a `CertSigner` thread the RNG
/// through via the `*_general_with_rng` helpers, falling back to a
/// transcript-keyed HMAC-DRBG when no RNG is supplied.
#[non_exhaustive]
pub enum CertSigner<'a> {
    /// An RSA signing key.
    Rsa(&'a BoxedRsaPrivateKey),
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
    /// NULL `parameters`; everything else is the bare OID, matching
    /// [`CertSigner::algorithm_identifier`].
    pub(crate) fn algorithm_identifier(self) -> Vec<u8> {
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

impl CertSigner<'_> {
    /// The `signatureAlgorithm` OID arcs.
    pub(crate) fn sig_alg_oid(&self) -> &'static [u64] {
        match self {
            CertSigner::Rsa(_) => oid::SHA256_WITH_RSA,
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
    /// RSA-PKCS1 carries a NULL `parameters`; everything else (ECDSA,
    /// Ed25519, ML-DSA) is the bare OID, no parameters.
    pub(crate) fn algorithm_identifier(&self) -> Vec<u8> {
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
                .map_err(|_| Error::Verification),
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa65(k) => k
                .sign_deterministic(tbs, b"")
                .map_err(|_| Error::Verification),
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa87(k) => k
                .sign_deterministic(tbs, b"")
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
            CertSigner::MlDsa44(k) => k.sign(rng, tbs, b"").map_err(|_| Error::Verification),
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa65(k) => k.sign(rng, tbs, b"").map_err(|_| Error::Verification),
            #[cfg(feature = "mldsa")]
            CertSigner::MlDsa87(k) => k.sign(rng, tbs, b"").map_err(|_| Error::Verification),
            #[cfg(feature = "slhdsa")]
            CertSigner::SlhDsa(k) => k.sign(rng, tbs, b"").map_err(|_| Error::Verification),
            other => other.sign(tbs),
        }
    }

    /// The signer's own public key — the subject key when self-signing.
    pub fn public_key(&self) -> AnyPublicKey {
        match self {
            CertSigner::Rsa(k) => AnyPublicKey::Rsa(k.public_key()),
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
