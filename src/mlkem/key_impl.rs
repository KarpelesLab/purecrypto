//! Unified [`key`](crate::key) trait impls for the ML-KEM key-encapsulation keys.
//!
//! ML-KEM is a KEM, not a signature or pairwise-agreement scheme, so the
//! encapsulation (public) keys implement [`Encapsulator`] and the decapsulation
//! (secret) keys implement [`Decapsulator`]. Both also wear the object-safe
//! facade ([`PublicKey`] / [`PrivateKey`]) for introspection and public-key
//! derivation; the facade's sign / decrypt / make_secret operations stay at
//! their defaulted [`Error::Unsupported`].

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::key::{Algorithm, Decapsulator, Encapsulator, Error, PrivateKey, PublicKey, Secret};
use crate::rng::CryptoRngCore;

use super::{
    MlKem512Ciphertext, MlKem512DecapsKey, MlKem512EncapsKey, MlKem768Ciphertext,
    MlKem768DecapsKey, MlKem768EncapsKey, MlKem1024Ciphertext, MlKem1024DecapsKey,
    MlKem1024EncapsKey,
};

/// Emits the unified-key impls for one ML-KEM parameter set.
macro_rules! ml_kem_key_impls {
    ($alg:ident, $dk:ident, $ek:ident, $ct:ident) => {
        impl Decapsulator for $dk {
            fn decapsulate(&self, ct: &[u8]) -> Result<Secret, Error> {
                // Parse the wire bytes into the fixed-width ciphertext type; a
                // wrong length is a decapsulation failure (caller fed us a bad
                // ciphertext).
                let bytes: [u8; <$ct>::BYTES] = ct.try_into().map_err(|_| Error::Decapsulation)?;
                let ct = <$ct>::from_bytes(bytes);
                let ss = self.decapsulate(&ct);
                Ok(Secret::from_bytes(ss.to_vec()))
            }
        }

        impl PrivateKey for $dk {
            fn algorithm(&self) -> Algorithm {
                Algorithm::$alg
            }
            fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
                Ok(Box::new(self.encapsulation_key()))
            }
        }

        impl Encapsulator for $ek {
            fn encapsulate(&self, rng: &mut dyn CryptoRngCore) -> Result<(Vec<u8>, Secret), Error> {
                let mut rng = rng;
                let (ct, ss) = self.encapsulate(&mut rng);
                Ok((ct.to_bytes().to_vec(), Secret::from_bytes(ss.to_vec())))
            }
        }

        impl PublicKey for $ek {
            fn algorithm(&self) -> Algorithm {
                Algorithm::$alg
            }
            fn as_any(&self) -> &dyn core::any::Any {
                self
            }
        }
    };
}

ml_kem_key_impls!(
    MlKem512,
    MlKem512DecapsKey,
    MlKem512EncapsKey,
    MlKem512Ciphertext
);
ml_kem_key_impls!(
    MlKem768,
    MlKem768DecapsKey,
    MlKem768EncapsKey,
    MlKem768Ciphertext
);
ml_kem_key_impls!(
    MlKem1024,
    MlKem1024DecapsKey,
    MlKem1024EncapsKey,
    MlKem1024Ciphertext
);
