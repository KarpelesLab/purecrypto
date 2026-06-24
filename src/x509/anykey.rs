//! Algorithm-agnostic ML-KEM key loading and a unified outer enum that routes
//! between signing/agreement keys ([`AnyPrivateKey`](super::AnyPrivateKey) /
//! [`AnyPublicKey`](super::AnyPublicKey)) and KEM keys.
//!
//! ML-KEM (FIPS 203) decapsulation/encapsulation keys are not
//! [`PrivateKey`](crate::key::PrivateKey) / [`PublicKey`](crate::key::PublicKey)
//! facade keys — encapsulate/decapsulate is its own contract — so the
//! per-algorithm `Any*` enums in [`privkey`](super::AnyPrivateKey) /
//! [`pubkey`](super::AnyPublicKey) deliberately exclude them. This module adds
//! the KEM-only [`AnyDecapsulationKey`] / [`AnyEncapsulationKey`] and the outer
//! [`AnyKey`] / [`AnyKeyPublic`] enums that accept *either* a facade key or a
//! KEM key parsed from the same PKCS#8 / SPKI byte streams.
//!
//! Unlike the ML-KEM types' own `from_pkcs8_der`, the algorithm is not known up
//! front here: each parser tries the three parameter sets in turn (512, 768,
//! 1024) and the first that validates wins. Plaintext only — encrypted PKCS#8
//! KEM keys are out of scope for these entry points (use the per-set
//! `from_pkcs8_der_encrypted` constructors with a known parameter set).

use super::Error;
use crate::der::pem_decode;
use crate::mlkem::{
    MlKem512DecapsKey, MlKem512EncapsKey, MlKem768DecapsKey, MlKem768EncapsKey, MlKem1024DecapsKey,
    MlKem1024EncapsKey,
};

/// An ML-KEM (FIPS 203) decapsulation (secret) key of any parameter set — the
/// KEM counterpart to [`AnyPrivateKey`](super::AnyPrivateKey), returned by
/// [`AnyDecapsulationKey::from_pkcs8_der`].
///
/// `#[non_exhaustive]`: new parameter sets are added over time. A `Debug` is
/// provided but deliberately redacts the secret key material.
// ML-KEM keys are stack-allocated fixed-size arrays by design (the mlkem
// module is allocation-free), so the parameter sets differ in size; boxing
// them would defeat that. Mirrors the per-key types' own layout.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
#[non_exhaustive]
pub enum AnyDecapsulationKey {
    /// An ML-KEM-512 decapsulation key.
    MlKem512(MlKem512DecapsKey),
    /// An ML-KEM-768 decapsulation key.
    MlKem768(MlKem768DecapsKey),
    /// An ML-KEM-1024 decapsulation key.
    MlKem1024(MlKem1024DecapsKey),
}

impl core::fmt::Debug for AnyDecapsulationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material.
        let kind = match self {
            AnyDecapsulationKey::MlKem512(_) => "MlKem512",
            AnyDecapsulationKey::MlKem768(_) => "MlKem768",
            AnyDecapsulationKey::MlKem1024(_) => "MlKem1024",
        };
        write!(f, "AnyDecapsulationKey::{kind}(<redacted>)")
    }
}

impl AnyDecapsulationKey {
    /// Parses a PKCS#8 `PrivateKeyInfo` DER (raw expanded `dk` form) by trying
    /// each ML-KEM parameter set in turn (512, then 768, then 1024); the first
    /// that parses and validates (FIPS 203 §7.3 key check) wins. An input that
    /// matches no set yields [`Error::UnsupportedAlgorithm`].
    ///
    /// **Plaintext only** — encrypted (PBES2 `EncryptedPrivateKeyInfo`) KEM keys
    /// are not handled here; decrypt them via the per-set
    /// `from_pkcs8_der_encrypted` constructor with a known parameter set.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        if let Ok(k) = MlKem512DecapsKey::from_pkcs8_der(der) {
            Ok(AnyDecapsulationKey::MlKem512(k))
        } else if let Ok(k) = MlKem768DecapsKey::from_pkcs8_der(der) {
            Ok(AnyDecapsulationKey::MlKem768(k))
        } else if let Ok(k) = MlKem1024DecapsKey::from_pkcs8_der(der) {
            Ok(AnyDecapsulationKey::MlKem1024(k))
        } else {
            Err(Error::UnsupportedAlgorithm)
        }
    }

    /// Parses a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) ML-KEM decapsulation
    /// key. Plaintext only; see [`Self::from_pkcs8_der`].
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        Self::from_pkcs8_der(&pem_decode(pem, "PRIVATE KEY")?)
    }

    /// The ML-KEM parameter set of this key.
    pub fn algorithm(&self) -> crate::key::Algorithm {
        match self {
            AnyDecapsulationKey::MlKem512(_) => crate::key::Algorithm::MlKem512,
            AnyDecapsulationKey::MlKem768(_) => crate::key::Algorithm::MlKem768,
            AnyDecapsulationKey::MlKem1024(_) => crate::key::Algorithm::MlKem1024,
        }
    }
}

#[cfg(feature = "key")]
impl AnyDecapsulationKey {
    /// Converts this key into a boxed unified [`Decapsulator`](crate::key::Decapsulator)
    /// trait object, so a parsed-by-set KEM key can be decapsulated
    /// polymorphically without matching on the variant.
    pub fn into_dyn(self) -> alloc::boxed::Box<dyn crate::key::Decapsulator> {
        use alloc::boxed::Box;
        match self {
            AnyDecapsulationKey::MlKem512(k) => Box::new(k),
            AnyDecapsulationKey::MlKem768(k) => Box::new(k),
            AnyDecapsulationKey::MlKem1024(k) => Box::new(k),
        }
    }

    /// Borrows the matched variant as a [`Decapsulator`](crate::key::Decapsulator).
    fn inner(&self) -> &dyn crate::key::Decapsulator {
        match self {
            AnyDecapsulationKey::MlKem512(k) => k,
            AnyDecapsulationKey::MlKem768(k) => k,
            AnyDecapsulationKey::MlKem1024(k) => k,
        }
    }
}

/// `AnyDecapsulationKey` is itself a [`Decapsulator`](crate::key::Decapsulator):
/// it delegates to the matched variant, so a parsed-by-set KEM key is usable
/// both ways — `match` on it for the concrete parameter-set API, or decapsulate
/// directly without erasing the type.
#[cfg(feature = "key")]
impl crate::key::Decapsulator for AnyDecapsulationKey {
    fn decapsulate(&self, ct: &[u8]) -> Result<crate::key::Secret, crate::key::Error> {
        self.inner().decapsulate(ct)
    }
}

/// An ML-KEM (FIPS 203) encapsulation (public) key of any parameter set — the
/// KEM counterpart to [`AnyPublicKey`](super::AnyPublicKey), returned by
/// [`AnyEncapsulationKey::from_spki_der`].
///
/// `#[non_exhaustive]`: new parameter sets are added over time.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum AnyEncapsulationKey {
    /// An ML-KEM-512 encapsulation key.
    MlKem512(MlKem512EncapsKey),
    /// An ML-KEM-768 encapsulation key.
    MlKem768(MlKem768EncapsKey),
    /// An ML-KEM-1024 encapsulation key.
    MlKem1024(MlKem1024EncapsKey),
}

impl AnyEncapsulationKey {
    /// Parses a PKIX `SubjectPublicKeyInfo` DER by trying each ML-KEM parameter
    /// set in turn (512, then 768, then 1024); the first that parses and
    /// validates (FIPS 203 §7.2 encapsulation-key check) wins. An input that
    /// matches no set yields [`Error::UnsupportedAlgorithm`].
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        if let Ok(k) = MlKem512EncapsKey::from_spki_der(der) {
            Ok(AnyEncapsulationKey::MlKem512(k))
        } else if let Ok(k) = MlKem768EncapsKey::from_spki_der(der) {
            Ok(AnyEncapsulationKey::MlKem768(k))
        } else if let Ok(k) = MlKem1024EncapsKey::from_spki_der(der) {
            Ok(AnyEncapsulationKey::MlKem1024(k))
        } else {
            Err(Error::UnsupportedAlgorithm)
        }
    }

    /// Parses a PKIX PEM (`-----BEGIN PUBLIC KEY-----`) ML-KEM encapsulation key.
    /// See [`Self::from_spki_der`].
    pub fn from_spki_pem(pem: &str) -> Result<Self, Error> {
        Self::from_spki_der(&pem_decode(pem, "PUBLIC KEY")?)
    }

    /// The ML-KEM parameter set of this key.
    pub fn algorithm(&self) -> crate::key::Algorithm {
        match self {
            AnyEncapsulationKey::MlKem512(_) => crate::key::Algorithm::MlKem512,
            AnyEncapsulationKey::MlKem768(_) => crate::key::Algorithm::MlKem768,
            AnyEncapsulationKey::MlKem1024(_) => crate::key::Algorithm::MlKem1024,
        }
    }
}

#[cfg(feature = "key")]
impl AnyEncapsulationKey {
    /// Converts this key into a boxed unified [`Encapsulator`](crate::key::Encapsulator)
    /// trait object, so a parsed-by-set KEM key can encapsulate polymorphically
    /// without matching on the variant.
    pub fn into_dyn(self) -> alloc::boxed::Box<dyn crate::key::Encapsulator> {
        use alloc::boxed::Box;
        match self {
            AnyEncapsulationKey::MlKem512(k) => Box::new(k),
            AnyEncapsulationKey::MlKem768(k) => Box::new(k),
            AnyEncapsulationKey::MlKem1024(k) => Box::new(k),
        }
    }

    /// Borrows the matched variant as an [`Encapsulator`](crate::key::Encapsulator).
    fn inner(&self) -> &dyn crate::key::Encapsulator {
        match self {
            AnyEncapsulationKey::MlKem512(k) => k,
            AnyEncapsulationKey::MlKem768(k) => k,
            AnyEncapsulationKey::MlKem1024(k) => k,
        }
    }
}

/// `AnyEncapsulationKey` is itself an [`Encapsulator`](crate::key::Encapsulator):
/// it delegates to the matched variant.
#[cfg(feature = "key")]
impl crate::key::Encapsulator for AnyEncapsulationKey {
    fn encapsulate(
        &self,
        rng: &mut dyn crate::rng::CryptoRngCore,
    ) -> Result<(alloc::vec::Vec<u8>, crate::key::Secret), crate::key::Error> {
        self.inner().encapsulate(rng)
    }
}

/// The outer "either" enum over a PKCS#8 secret key: a signing/agreement facade
/// key ([`AnyPrivateKey`](super::AnyPrivateKey)) **or** a KEM decapsulation key
/// ([`AnyDecapsulationKey`]). Returned by [`AnyKey::from_pkcs8_der`].
///
/// [`AnyPrivateKey`](super::AnyPrivateKey) can still be used directly when you
/// don't expect a KEM key; this outer enum is for code that might receive
/// either.
///
/// `#[non_exhaustive]`: new key categories may be added over time.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum AnyKey {
    /// A signing or key-agreement private key.
    PrivateKey(super::AnyPrivateKey),
    /// An ML-KEM decapsulation key.
    DecapsulationKey(AnyDecapsulationKey),
}

impl AnyKey {
    /// Parses a PKCS#8 secret key from DER, accepting either a facade
    /// (signing/agreement) key or an ML-KEM decapsulation key.
    ///
    /// [`AnyPrivateKey::from_pkcs8_der`](super::AnyPrivateKey::from_pkcs8_der)
    /// is tried first (it dispatches on the `privateKeyAlgorithm` OID, honoring
    /// `opts` for encrypted keys). Only if that reports
    /// [`Error::UnsupportedAlgorithm`] — i.e. a well-formed PKCS#8 whose OID is
    /// none of the facade algorithms — does it fall back to the ML-KEM sets via
    /// [`AnyDecapsulationKey::from_pkcs8_der`]. Any other error (malformed
    /// input, missing/wrong password) propagates unchanged.
    pub fn from_pkcs8_der(der: &[u8], opts: super::Pkcs8ReadOptions) -> Result<Self, Error> {
        match super::AnyPrivateKey::from_pkcs8_der(der, opts) {
            Ok(k) => Ok(AnyKey::PrivateKey(k)),
            Err(Error::UnsupportedAlgorithm) => Ok(AnyKey::DecapsulationKey(
                AnyDecapsulationKey::from_pkcs8_der(der)?,
            )),
            Err(e) => Err(e),
        }
    }

    /// Parses a PKCS#8 secret key from PEM, accepting either a facade key or an
    /// ML-KEM decapsulation key. See [`Self::from_pkcs8_der`].
    pub fn from_pkcs8_pem(pem: &str, opts: super::Pkcs8ReadOptions) -> Result<Self, Error> {
        match super::AnyPrivateKey::from_pkcs8_pem(pem, opts) {
            Ok(k) => Ok(AnyKey::PrivateKey(k)),
            Err(Error::UnsupportedAlgorithm) => Ok(AnyKey::DecapsulationKey(
                AnyDecapsulationKey::from_pkcs8_pem(pem)?,
            )),
            Err(e) => Err(e),
        }
    }
}

/// The outer "either" enum over an SPKI public key: a verifying/agreement facade
/// key ([`AnyPublicKey`](super::AnyPublicKey)) **or** a KEM encapsulation key
/// ([`AnyEncapsulationKey`]). The public-key mirror of [`AnyKey`].
///
/// [`AnyPublicKey`](super::AnyPublicKey) can still be used directly when you
/// don't expect a KEM key; this outer enum is for code that might receive
/// either.
///
/// `#[non_exhaustive]`: new key categories may be added over time.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum AnyKeyPublic {
    /// A signing or key-agreement public key.
    PublicKey(super::AnyPublicKey),
    /// An ML-KEM encapsulation key.
    EncapsulationKey(AnyEncapsulationKey),
}

impl AnyKeyPublic {
    /// Parses a PKIX `SubjectPublicKeyInfo` DER, accepting either a facade
    /// public key or an ML-KEM encapsulation key.
    ///
    /// [`AnyPublicKey::from_spki_der`](super::AnyPublicKey::from_spki_der) is
    /// tried first; only on [`Error::UnsupportedAlgorithm`] does it fall back to
    /// the ML-KEM sets via [`AnyEncapsulationKey::from_spki_der`]. Any other
    /// error propagates unchanged.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        match super::AnyPublicKey::from_spki_der(der) {
            Ok(k) => Ok(AnyKeyPublic::PublicKey(k)),
            Err(Error::UnsupportedAlgorithm) => Ok(AnyKeyPublic::EncapsulationKey(
                AnyEncapsulationKey::from_spki_der(der)?,
            )),
            Err(e) => Err(e),
        }
    }

    /// Parses a PKIX PEM public key, accepting either a facade public key or an
    /// ML-KEM encapsulation key. See [`Self::from_spki_der`].
    pub fn from_spki_pem(pem: &str) -> Result<Self, Error> {
        Self::from_spki_der(&pem_decode(pem, "PUBLIC KEY")?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn rng(seed: &[u8]) -> HmacDrbg<Sha256> {
        HmacDrbg::<Sha256>::new(seed, b"nonce", &[])
    }

    #[test]
    fn any_decaps_dispatch_768() {
        let mut r = rng(b"anykey-768");
        let (dk, ek) = MlKem768DecapsKey::generate(&mut r);
        let pem = dk.to_pkcs8_pem();

        let parsed = AnyDecapsulationKey::from_pkcs8_pem(&pem).unwrap();
        assert!(matches!(parsed, AnyDecapsulationKey::MlKem768(_)));
        assert_eq!(parsed.algorithm(), crate::key::Algorithm::MlKem768);

        // A 768 key must NOT mis-parse as 512 or 1024.
        match parsed {
            AnyDecapsulationKey::MlKem768(_) => {}
            other => panic!("wrong set: {other:?}"),
        }

        // SPKI side.
        let spki = ek.to_spki_pem();
        let pub_parsed = AnyEncapsulationKey::from_spki_pem(&spki).unwrap();
        assert!(matches!(pub_parsed, AnyEncapsulationKey::MlKem768(_)));
    }

    #[cfg(feature = "key")]
    #[test]
    fn anykey_routes_kem_and_roundtrips_secret() {
        use crate::key::Encapsulator;

        let mut r = rng(b"anykey-route");
        let (dk, ek) = MlKem768DecapsKey::generate(&mut r);
        let pem = dk.to_pkcs8_pem();

        // Outer AnyKey routes a KEM key into the DecapsulationKey arm.
        let parsed = AnyKey::from_pkcs8_pem(&pem, super::super::Pkcs8ReadOptions::new()).unwrap();
        let decaps = match parsed {
            AnyKey::DecapsulationKey(d @ AnyDecapsulationKey::MlKem768(_)) => d,
            other => panic!("expected ML-KEM-768 decaps key, got {other:?}"),
        };

        // Encapsulate with the public key (via the unified Encapsulator trait,
        // which yields wire bytes), decapsulate via the boxed Decapsulator.
        let (ct, ss_a) = Encapsulator::encapsulate(&ek, &mut r).unwrap();
        let boxed = decaps.into_dyn();
        let ss_b = boxed.decapsulate(&ct).unwrap();
        assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    #[test]
    fn anykey_routes_ed25519_to_private_key() {
        use crate::ec::Ed25519PrivateKey;
        let mut r = rng(b"anykey-ed");
        let sk = Ed25519PrivateKey::generate(&mut r);
        let pem = sk.to_pkcs8_pem();

        let parsed = AnyKey::from_pkcs8_pem(&pem, super::super::Pkcs8ReadOptions::new()).unwrap();
        assert!(matches!(
            parsed,
            AnyKey::PrivateKey(super::super::AnyPrivateKey::Ed25519(_))
        ));
    }

    #[test]
    fn any_decaps_rejects_non_kem_pkcs8() {
        use crate::ec::Ed25519PrivateKey;
        let mut r = rng(b"anykey-notkem");
        let sk = Ed25519PrivateKey::generate(&mut r);
        let der = sk.to_pkcs8_der();
        assert!(matches!(
            AnyDecapsulationKey::from_pkcs8_der(&der),
            Err(Error::UnsupportedAlgorithm)
        ));
    }
}
