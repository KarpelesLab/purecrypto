//! Elliptic-curve Diffie-Hellman over NIST P-256 (ECDHE for TLS).

use super::Error;
use super::ecdsa::EcdsaPublicKey;
use super::p256::{Fe, P256, random_scalar};
use crate::ct::ConstantTimeLess;
use crate::rng::{CryptoRng, RngCore};

/// An ephemeral ECDH private value (a scalar in `[1, n-1]`).
///
/// Generate a fresh one per handshake; the corresponding public key is sent to
/// the peer, and [`diffie_hellman`](EcdhPrivateKey::diffie_hellman) computes
/// the shared secret.
#[derive(Clone)]
pub struct EcdhPrivateKey {
    d: Fe,
}

impl Drop for EcdhPrivateKey {
    fn drop(&mut self) {
        // Best-effort wipe of the secret scalar with a `black_box` barrier so
        // the store is not elided (mirrors `secp256k1::Scalar` and the boxed
        // EC key types).
        self.d = Fe::ZERO;
        let _ = core::hint::black_box(&self.d);
    }
}

impl EcdhPrivateKey {
    /// Generates a fresh ephemeral key from `rng`. The RNG must be a
    /// cryptographically secure CSPRNG (see [`CryptoRng`]).
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        EcdhPrivateKey {
            d: random_scalar(rng),
        }
    }

    /// Creates an ECDH private value from a 32-byte big-endian scalar, checking
    /// it is in `[1, n-1]`. Use this for a *static* ECDH key (e.g. reusing an
    /// existing P-256 private scalar); generate ephemeral values with
    /// [`generate`](EcdhPrivateKey::generate).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let d = Fe::from_be_bytes(bytes);
        let n = P256::order();
        if !bool::from(d.is_zero()) && bool::from(d.ct_lt(&n)) {
            Ok(EcdhPrivateKey { d })
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// The public key `d * G` to send to the peer.
    pub fn public_key(&self) -> EcdsaPublicKey {
        let curve = P256::new();
        let (x, y) = curve
            .to_affine(&curve.mul_generator(&self.d))
            .expect("d in [1,n-1] so d*G is not the identity");
        EcdsaPublicKey::from_coordinates(x, y)
    }

    /// Computes the shared secret with `peer`'s public key: the big-endian
    /// 32-byte x-coordinate of `d * peer` (the SEC1 / RFC 5903 `Z` value).
    ///
    /// # Errors
    /// Returns [`Error::InvalidInput`] in the degenerate case where the product
    /// is the identity.
    pub fn diffie_hellman(&self, peer: &EcdsaPublicKey) -> Result<[u8; 32], Error> {
        let curve = P256::new();
        let (px, py) = peer.coordinates();
        let point = curve.lift_affine(&px, &py);
        let shared = curve.scalar_mul(&self.d, &point);
        let (x, _) = curve.to_affine(&shared).ok_or(Error::InvalidInput)?;
        let mut out = [0u8; 32];
        x.write_be_bytes(&mut out);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::super::p256::fe_from_hex;
    use super::*;
    use crate::ec::ecdsa::EcdsaPublicKey;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn be32(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        fe_from_hex(hex).write_be_bytes(&mut out);
        out
    }

    #[test]
    fn nist_kas_ecc_cdh_p256() {
        // NIST CAVP KAS-ECC-CDH, P-256, first vector.
        let secret = EcdhPrivateKey {
            d: fe_from_hex("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534"),
        };

        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&be32(
            "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
        ));
        sec1[33..65].copy_from_slice(&be32(
            "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
        ));
        let peer = EcdsaPublicKey::from_sec1(&sec1).unwrap();

        let z = secret.diffie_hellman(&peer).unwrap();
        assert_eq!(
            z,
            be32("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b")
        );
    }

    #[test]
    fn alice_bob_agree() {
        let mut rng = HmacDrbg::<Sha256>::new(b"ecdh-agree", b"nonce", &[]);
        let alice = EcdhPrivateKey::generate(&mut rng);
        let bob = EcdhPrivateKey::generate(&mut rng);

        let a_shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        let b_shared = bob.diffie_hellman(&alice.public_key()).unwrap();
        assert_eq!(a_shared, b_shared);
        assert_ne!(a_shared, [0u8; 32]);
    }
}
