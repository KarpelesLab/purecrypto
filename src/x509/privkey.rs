//! Generic PKCS#8 private-key loading — the private-key mirror of
//! [`AnyPublicKey`](super::AnyPublicKey).
//!
//! PKCS#8 `PrivateKeyInfo` (RFC 5958) is self-describing: the
//! `privateKeyAlgorithm` OID names the key type. [`AnyPrivateKey::from_pkcs8_der`]
//! reads that OID and dispatches to the concrete key type's own parser, so a
//! caller can load "whatever key is in this file" without knowing its type up
//! front. Encrypted keys (PBES2 `EncryptedPrivateKeyInfo`) are decrypted
//! transparently when a password is supplied via [`Pkcs8ReadOptions`].

use super::{Error, oid};
use crate::der::{Reader, parse_oid, pem_decode, tag};
use crate::ec::{BoxedEcdsaPrivateKey, Ed448PrivateKey, Ed25519PrivateKey};
#[cfg(feature = "mldsa")]
use crate::mldsa::{MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey};
use crate::rsa::BoxedRsaPrivateKey;
#[cfg(feature = "slhdsa")]
use crate::slhdsa;
use alloc::borrow::Cow;

/// A private key of any algorithm this crate supports — the value returned by
/// [`AnyPrivateKey::from_pkcs8_der`]. Mirrors [`AnyPublicKey`](super::AnyPublicKey).
///
/// `#[non_exhaustive]`: new key algorithms are added over time. A `Debug` is
/// provided but deliberately redacts the secret key material.
#[derive(Clone)]
#[non_exhaustive]
pub enum AnyPrivateKey {
    /// An RSA private key (runtime-sized).
    Rsa(BoxedRsaPrivateKey),
    /// An ECDSA private key on one of the supported curves.
    Ecdsa(BoxedEcdsaPrivateKey),
    /// An Ed25519 private key.
    Ed25519(Ed25519PrivateKey),
    /// An Ed448 private key.
    Ed448(Ed448PrivateKey),
    /// An ML-DSA-44 (FIPS 204) private key.
    #[cfg(feature = "mldsa")]
    MlDsa44(MlDsa44PrivateKey),
    /// An ML-DSA-65 (FIPS 204) private key.
    #[cfg(feature = "mldsa")]
    MlDsa65(MlDsa65PrivateKey),
    /// An ML-DSA-87 (FIPS 204) private key.
    #[cfg(feature = "mldsa")]
    MlDsa87(MlDsa87PrivateKey),
    /// An SLH-DSA (FIPS 205) private key. The parameter set is carried inside
    /// the [`slhdsa::PrivateKey`].
    #[cfg(feature = "slhdsa")]
    SlhDsa(slhdsa::PrivateKey),
}

impl core::fmt::Debug for AnyPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material.
        let kind = match self {
            AnyPrivateKey::Rsa(_) => "Rsa",
            AnyPrivateKey::Ecdsa(_) => "Ecdsa",
            AnyPrivateKey::Ed25519(_) => "Ed25519",
            AnyPrivateKey::Ed448(_) => "Ed448",
            #[cfg(feature = "mldsa")]
            AnyPrivateKey::MlDsa44(_) => "MlDsa44",
            #[cfg(feature = "mldsa")]
            AnyPrivateKey::MlDsa65(_) => "MlDsa65",
            #[cfg(feature = "mldsa")]
            AnyPrivateKey::MlDsa87(_) => "MlDsa87",
            #[cfg(feature = "slhdsa")]
            AnyPrivateKey::SlhDsa(_) => "SlhDsa",
        };
        write!(f, "AnyPrivateKey::{kind}(<redacted>)")
    }
}

/// Options controlling how a PKCS#8 private key is read — currently the
/// password used to decrypt a PBES2 `EncryptedPrivateKeyInfo`. Build with
/// [`Pkcs8ReadOptions::new`] and the chained setters.
#[derive(Clone, Default)]
pub struct Pkcs8ReadOptions<'a> {
    password: Option<&'a [u8]>,
}

impl<'a> Pkcs8ReadOptions<'a> {
    /// Default options: no password (plaintext keys only).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the password used to decrypt an encrypted PKCS#8 key. Ignored for a
    /// plaintext key.
    pub fn password(mut self, password: &'a [u8]) -> Self {
        self.password = Some(password);
        self
    }
}

impl AnyPrivateKey {
    /// Parses a PKCS#8 private key from DER, returning the algorithm-specific
    /// variant. Handles both plaintext `PrivateKeyInfo` and PBES2
    /// `EncryptedPrivateKeyInfo` — the latter requires
    /// `opts.`[`password`](Pkcs8ReadOptions::password) (else
    /// [`Error::PasswordRequired`]); a plaintext key ignores any supplied
    /// password.
    ///
    /// Decryption needs the `kdf` feature; without it, an encrypted input
    /// yields [`Error::UnsupportedAlgorithm`]. A wrong password (or otherwise
    /// undecryptable blob) yields [`Error::Malformed`]. An algorithm this crate
    /// does not support yields [`Error::UnsupportedAlgorithm`].
    pub fn from_pkcs8_der(der: &[u8], opts: Pkcs8ReadOptions) -> Result<Self, Error> {
        let plaintext: Cow<[u8]> = if is_encrypted_pkcs8(der)? {
            let password = opts.password.ok_or(Error::PasswordRequired)?;
            Cow::Owned(decrypt_pkcs8(der, password)?)
        } else {
            Cow::Borrowed(der)
        };
        let plain = plaintext.as_ref();

        // Read the privateKeyAlgorithm OID, then hand the whole (plaintext)
        // PKCS#8 to the matching per-type parser.
        let mut reader = Reader::new(plain);
        let mut seq = reader.read_sequence()?;
        seq.read_integer_bytes()?; // version
        let mut algid = seq.read_sequence()?;
        let arcs = parse_oid(algid.read_oid()?)?;
        let alg = arcs.as_slice();

        if alg == oid::RSA_ENCRYPTION {
            Ok(AnyPrivateKey::Rsa(
                BoxedRsaPrivateKey::from_pkcs8_der(plain).map_err(|_| Error::Malformed)?,
            ))
        } else if alg == oid::EC_PUBLIC_KEY {
            Ok(AnyPrivateKey::Ecdsa(
                BoxedEcdsaPrivateKey::from_pkcs8_der(plain).map_err(|_| Error::Malformed)?,
            ))
        } else if alg == oid::ID_ED25519 {
            Ok(AnyPrivateKey::Ed25519(
                Ed25519PrivateKey::from_pkcs8_der(plain).map_err(|_| Error::Malformed)?,
            ))
        } else if alg == oid::ID_ED448 {
            Ok(AnyPrivateKey::Ed448(
                Ed448PrivateKey::from_pkcs8_der(plain).map_err(|_| Error::Malformed)?,
            ))
        } else {
            #[cfg(feature = "mldsa")]
            {
                if alg == oid::ID_ML_DSA_44 {
                    return Ok(AnyPrivateKey::MlDsa44(
                        MlDsa44PrivateKey::from_pkcs8_der(plain).map_err(|_| Error::Malformed)?,
                    ));
                } else if alg == oid::ID_ML_DSA_65 {
                    return Ok(AnyPrivateKey::MlDsa65(
                        MlDsa65PrivateKey::from_pkcs8_der(plain).map_err(|_| Error::Malformed)?,
                    ));
                } else if alg == oid::ID_ML_DSA_87 {
                    return Ok(AnyPrivateKey::MlDsa87(
                        MlDsa87PrivateKey::from_pkcs8_der(plain).map_err(|_| Error::Malformed)?,
                    ));
                }
            }
            #[cfg(feature = "slhdsa")]
            {
                if slhdsa::ParamSet::from_oid(alg).is_some() {
                    return Ok(AnyPrivateKey::SlhDsa(
                        slhdsa::PrivateKey::from_pkcs8_der(plain).map_err(|_| Error::Malformed)?,
                    ));
                }
            }
            Err(Error::UnsupportedAlgorithm)
        }
    }

    /// Parses a PKCS#8 private key from PEM, accepting both the
    /// `-----BEGIN PRIVATE KEY-----` and `-----BEGIN ENCRYPTED PRIVATE KEY-----`
    /// labels. See [`Self::from_pkcs8_der`].
    pub fn from_pkcs8_pem(pem: &str, opts: Pkcs8ReadOptions) -> Result<Self, Error> {
        let der = if pem.contains("ENCRYPTED PRIVATE KEY") {
            pem_decode(pem, "ENCRYPTED PRIVATE KEY")?
        } else {
            pem_decode(pem, "PRIVATE KEY")?
        };
        Self::from_pkcs8_der(&der, opts)
    }
}

/// Distinguishes a plaintext `PrivateKeyInfo` (first inner element is the
/// version `INTEGER`) from an `EncryptedPrivateKeyInfo` (first inner element is
/// the PBES2 `AlgorithmIdentifier` `SEQUENCE`).
fn is_encrypted_pkcs8(der: &[u8]) -> Result<bool, Error> {
    let mut reader = Reader::new(der);
    let seq = reader.read_sequence()?;
    match seq.peek_tag() {
        Some(tag::INTEGER) => Ok(false),
        Some(tag::SEQUENCE) => Ok(true),
        _ => Err(Error::Malformed),
    }
}

/// Decrypts a PBES2 `EncryptedPrivateKeyInfo` to its inner PKCS#8 DER. Requires
/// the `kdf` feature; otherwise encrypted keys are unsupported.
#[cfg(feature = "kdf")]
fn decrypt_pkcs8(der: &[u8], password: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    crate::kdf::pbes2::decrypt(der, password).map_err(|_| Error::Malformed)
}

#[cfg(not(feature = "kdf"))]
fn decrypt_pkcs8(_der: &[u8], _password: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    Err(Error::UnsupportedAlgorithm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::CurveId;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn rng(seed: &[u8]) -> HmacDrbg<Sha256> {
        HmacDrbg::<Sha256>::new(seed, b"nonce", &[])
    }

    #[test]
    fn dispatch_ecdsa() {
        let mut r = rng(b"any-ec");
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut r);
        let der = sk.to_pkcs8_der();
        match AnyPrivateKey::from_pkcs8_der(&der, Pkcs8ReadOptions::new()).unwrap() {
            AnyPrivateKey::Ecdsa(k) => {
                assert_eq!(k.public_key().to_sec1(), sk.public_key().to_sec1())
            }
            other => panic!("wrong variant: {other:?}"),
        }
        // PEM path too.
        let pem = sk.to_pkcs8_pem();
        assert!(matches!(
            AnyPrivateKey::from_pkcs8_pem(&pem, Pkcs8ReadOptions::new()).unwrap(),
            AnyPrivateKey::Ecdsa(_)
        ));
    }

    #[test]
    fn dispatch_ed25519() {
        let mut r = rng(b"any-ed");
        let sk = Ed25519PrivateKey::generate(&mut r);
        let der = sk.to_pkcs8_der();
        assert!(matches!(
            AnyPrivateKey::from_pkcs8_der(&der, Pkcs8ReadOptions::new()).unwrap(),
            AnyPrivateKey::Ed25519(_)
        ));
    }

    #[test]
    fn dispatch_rsa() {
        let key = crate::test_util::rsa_test_key_a();
        let sk = BoxedRsaPrivateKey::from_pkcs1_der(&key.to_pkcs1_der()).unwrap();
        let der = sk.to_pkcs8_der();
        assert!(matches!(
            AnyPrivateKey::from_pkcs8_der(&der, Pkcs8ReadOptions::new()).unwrap(),
            AnyPrivateKey::Rsa(_)
        ));
    }

    #[cfg(feature = "kdf")]
    #[test]
    fn encrypted_roundtrip_and_password_errors() {
        let mut r = rng(b"any-enc");
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut r);
        let params = crate::kdf::pbes2::Pbes2Params {
            kdf: crate::kdf::pbes2::KdfChoice::Pbkdf2HmacSha256 { iterations: 10_000 },
            cipher: crate::kdf::pbes2::CipherChoice::Aes256Gcm,
            salt_len: 16,
        };
        let pem = sk.to_pkcs8_pem_encrypted(b"swordfish", &params, &mut r);

        // Correct password decrypts and dispatches.
        let opts = Pkcs8ReadOptions::new().password(b"swordfish");
        assert!(matches!(
            AnyPrivateKey::from_pkcs8_pem(&pem, opts).unwrap(),
            AnyPrivateKey::Ecdsa(_)
        ));
        // Missing password is reported distinctly.
        assert!(matches!(
            AnyPrivateKey::from_pkcs8_pem(&pem, Pkcs8ReadOptions::new()),
            Err(Error::PasswordRequired)
        ));
        // Wrong password fails to decrypt.
        assert!(matches!(
            AnyPrivateKey::from_pkcs8_pem(&pem, Pkcs8ReadOptions::new().password(b"wrong")),
            Err(Error::Malformed)
        ));
    }

    /// OpenSSL 3.x interop (same fixtures as the EC PKCS#8 issue #24): load the
    /// plaintext and PBES2 (PBKDF2-SHA256/AES-256-CBC) P-256 keys through the
    /// generic entry point.
    #[cfg(feature = "kdf")]
    #[test]
    fn openssl_interop() {
        const PLAIN: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPWfLPOd/TFwWJTCr\n\
E5f4wo4KaaIPIAZWZMFAqEMjTfKhRANCAAQ2q5yE2IGZsOoMACF7A+349UNU4/bo\n\
HCwXnzad7AT3M3i/cpHzz4hQ5SamPVsiQHh79RPMIhptanrHl+IqHnZW\n\
-----END PRIVATE KEY-----\n";
        const ENC: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
MIH1MGAGCSqGSIb3DQEFDTBTMDIGCSqGSIb3DQEFDDAlBBCY+UTuXFns/MwLo3Ki\n\
xoqQAgMBhqAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEED21Z94FK0DiNUk7\n\
kyKSLr4EgZBQ3Gv8EdxHAbYJW4EQErkkR2BQcDXl94uMRcxb9grTUueECvaCoOJ\n\
FN7ev05ViuIhHs4Nf8urHf8E9mS7xW18RnHM0LqbtkLBpFgOCM7v0JXWsyacSGg\n\
E2aHEj9+RUM5NRAvRB/ggKn1BUHMrJ1RRFpTJHBmL+XV9GJ8KiIeIyiCcogoils\n\
x2dqVh/sT12MnE=\n\
-----END ENCRYPTED PRIVATE KEY-----\n";
        let a = AnyPrivateKey::from_pkcs8_pem(PLAIN, Pkcs8ReadOptions::new()).unwrap();
        let b = AnyPrivateKey::from_pkcs8_pem(ENC, Pkcs8ReadOptions::new().password(b"swordfish"))
            .unwrap();
        for k in [a, b] {
            match k {
                AnyPrivateKey::Ecdsa(ec) => assert_eq!(ec.curve(), CurveId::P256),
                other => panic!("expected ECDSA, got {other:?}"),
            }
        }
    }

    #[cfg(feature = "mldsa")]
    #[test]
    fn dispatch_mldsa() {
        let mut r = rng(b"any-mldsa");
        let (sk, _pk) = MlDsa65PrivateKey::generate(&mut r);
        let der = sk.to_pkcs8_der();
        assert!(matches!(
            AnyPrivateKey::from_pkcs8_der(&der, Pkcs8ReadOptions::new()).unwrap(),
            AnyPrivateKey::MlDsa65(_)
        ));
    }

    #[cfg(feature = "slhdsa")]
    #[test]
    fn dispatch_slhdsa() {
        let mut r = rng(b"any-slhdsa");
        let (sk, _pk) = slhdsa::PrivateKey::generate(slhdsa::ParamSet::Sha2_128f, &mut r);
        let der = sk.to_pkcs8_der();
        assert!(matches!(
            AnyPrivateKey::from_pkcs8_der(&der, Pkcs8ReadOptions::new()).unwrap(),
            AnyPrivateKey::SlhDsa(_)
        ));
    }

    #[test]
    fn unsupported_algorithm_is_reported() {
        // PKCS#8 with a bogus privateKeyAlgorithm OID (1.2.3): version INTEGER 0,
        // algid SEQUENCE { OID 1.2.3 }, empty privateKey OCTET STRING.
        let der: &[u8] = &[
            0x30, 0x0b, // SEQUENCE (11 content bytes)
            0x02, 0x01, 0x00, // version 0
            0x30, 0x04, 0x06, 0x02, 0x2a, 0x03, // SEQUENCE { OID 1.2.3 }
            0x04, 0x00, // privateKey OCTET STRING (empty)
        ];
        assert!(matches!(
            AnyPrivateKey::from_pkcs8_der(der, Pkcs8ReadOptions::new()),
            Err(Error::UnsupportedAlgorithm)
        ));
    }
}
