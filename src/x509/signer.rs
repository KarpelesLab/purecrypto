//! A signing key for issuing certificates and certification requests — RSA or
//! ECDSA, runtime-sized.

use alloc::vec::Vec;

use super::{AnyPublicKey, Error, algorithm_identifier, oid};
use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
use crate::hash::{Sha256, Sha384, Sha512};
use crate::rsa::BoxedRsaPrivateKey;

/// A certificate/CSR signing key.
///
/// RSA signs with PKCS#1 v1.5 over SHA-256 (`sha256WithRSAEncryption`); ECDSA
/// signs `ecdsa-with-SHAxxx` with the hash matched to the curve (P-256 and
/// secp256k1 → SHA-256, P-384 → SHA-384, P-521 → SHA-512).
pub enum CertSigner<'a> {
    /// An RSA signing key.
    Rsa(&'a BoxedRsaPrivateKey),
    /// An ECDSA signing key.
    Ecdsa(&'a BoxedEcdsaPrivateKey),
}

impl CertSigner<'_> {
    /// The `signatureAlgorithm` OID arcs.
    pub(crate) fn sig_alg_oid(&self) -> &'static [u64] {
        match self {
            CertSigner::Rsa(_) => oid::SHA256_WITH_RSA,
            CertSigner::Ecdsa(k) => match k.curve() {
                CurveId::P256 | CurveId::Secp256k1 => oid::ECDSA_WITH_SHA256,
                CurveId::P384 => oid::ECDSA_WITH_SHA384,
                CurveId::P521 => oid::ECDSA_WITH_SHA512,
            },
        }
    }

    /// The DER `AlgorithmIdentifier` for the signature (RSA carries a NULL
    /// `parameters`; ECDSA omits it).
    pub(crate) fn algorithm_identifier(&self) -> Vec<u8> {
        algorithm_identifier(self.sig_alg_oid(), matches!(self, CertSigner::Rsa(_)))
    }

    /// Signs `tbs`, returning the bytes for the signature BIT STRING.
    pub(crate) fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            CertSigner::Rsa(k) => Ok(k.sign_pkcs1v15::<Sha256>(tbs)?),
            CertSigner::Ecdsa(k) => {
                let curve = k.curve();
                let sig = match curve {
                    CurveId::P256 | CurveId::Secp256k1 => k.sign::<Sha256>(tbs),
                    CurveId::P384 => k.sign::<Sha384>(tbs),
                    CurveId::P521 => k.sign::<Sha512>(tbs),
                }
                .map_err(|_| Error::Verification)?;
                Ok(sig.to_der(curve))
            }
        }
    }

    /// The signer's own public key — the subject key when self-signing.
    pub fn public_key(&self) -> AnyPublicKey {
        match self {
            CertSigner::Rsa(k) => AnyPublicKey::Rsa(k.public_key()),
            CertSigner::Ecdsa(k) => AnyPublicKey::Ecdsa(k.public_key()),
        }
    }
}
