//! ML-KEM-768 — the FIPS 203 module-lattice key-encapsulation mechanism
//! (the standardized form of Kyber).
//!
//! This is a `no_std`, allocation-free implementation: keys, ciphertexts and
//! all intermediate state are fixed-size arrays. Randomness is supplied through
//! the [`RngCore`](crate::rng::RngCore) trait; deterministic constructors
//! (`from_seeds`, `encapsulate_deterministic`) expose the FIPS 203 internal
//! functions for known-answer testing.
//!
//! Decapsulation never branches on secret data: the Fujisaki–Okamoto
//! re-encryption check and the implicit-rejection fallback both run in constant
//! time (see [`kem`]).

mod indcpa;
mod kem;
mod poly;

use crate::rng::RngCore;

/// Size in bytes of an ML-KEM-768 encapsulation (public) key.
pub const ENCAPS_KEY_BYTES: usize = kem::EK_BYTES;
/// Size in bytes of an ML-KEM-768 decapsulation (secret) key.
pub const DECAPS_KEY_BYTES: usize = kem::DK_BYTES;
/// Size in bytes of an ML-KEM-768 ciphertext.
pub const CIPHERTEXT_BYTES: usize = kem::CIPHERTEXT_BYTES;
/// Size in bytes of a shared secret.
pub const SHARED_SECRET_BYTES: usize = 32;

/// An ML-KEM-768 encapsulation (public) key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MlKem768EncapsKey([u8; ENCAPS_KEY_BYTES]);

/// An ML-KEM-768 decapsulation (secret) key.
#[derive(Clone)]
pub struct MlKem768DecapsKey([u8; DECAPS_KEY_BYTES]);

/// An ML-KEM-768 ciphertext.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MlKem768Ciphertext([u8; CIPHERTEXT_BYTES]);

impl MlKem768DecapsKey {
    /// Generates a fresh key pair from `rng` (32 bytes each of `d` and `z`).
    pub fn generate<R: RngCore>(rng: &mut R) -> (MlKem768DecapsKey, MlKem768EncapsKey) {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        rng.fill_bytes(&mut d);
        rng.fill_bytes(&mut z);
        Self::from_seeds(&d, &z)
    }

    /// Deterministically derives a key pair from the seeds `(d, z)`
    /// (ML-KEM.KeyGen_internal). Intended for testing.
    pub fn from_seeds(d: &[u8; 32], z: &[u8; 32]) -> (MlKem768DecapsKey, MlKem768EncapsKey) {
        let (ek, dk) = kem::keygen(d, z);
        (MlKem768DecapsKey(dk), MlKem768EncapsKey(ek))
    }

    /// The matching encapsulation key.
    pub fn encapsulation_key(&self) -> MlKem768EncapsKey {
        let mut ek = [0u8; ENCAPS_KEY_BYTES];
        ek.copy_from_slice(&self.0[indcpa::PKE_DK_BYTES..indcpa::PKE_DK_BYTES + ENCAPS_KEY_BYTES]);
        MlKem768EncapsKey(ek)
    }

    /// Decapsulates `ct`, returning the 32-byte shared secret. On an invalid
    /// ciphertext this returns a pseudo-random value (implicit rejection), not
    /// an error — the difference is unobservable to the sender.
    pub fn decapsulate(&self, ct: &MlKem768Ciphertext) -> [u8; SHARED_SECRET_BYTES] {
        kem::decaps(&self.0, &ct.0)
    }

    /// Restores a decapsulation key from its byte encoding.
    pub fn from_bytes(bytes: [u8; DECAPS_KEY_BYTES]) -> Self {
        MlKem768DecapsKey(bytes)
    }

    /// The byte encoding.
    pub fn to_bytes(&self) -> [u8; DECAPS_KEY_BYTES] {
        self.0
    }
}

impl MlKem768EncapsKey {
    /// Encapsulates to a fresh shared secret, returning `(ciphertext, secret)`.
    pub fn encapsulate<R: RngCore>(
        &self,
        rng: &mut R,
    ) -> (MlKem768Ciphertext, [u8; SHARED_SECRET_BYTES]) {
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        self.encapsulate_deterministic(&m)
    }

    /// Encapsulates with an explicit message `m` (ML-KEM.Encaps_internal).
    /// Intended for testing.
    pub fn encapsulate_deterministic(
        &self,
        m: &[u8; 32],
    ) -> (MlKem768Ciphertext, [u8; SHARED_SECRET_BYTES]) {
        let (ct, ss) = kem::encaps(&self.0, m);
        (MlKem768Ciphertext(ct), ss)
    }

    /// Restores an encapsulation key from its byte encoding.
    pub fn from_bytes(bytes: [u8; ENCAPS_KEY_BYTES]) -> Self {
        MlKem768EncapsKey(bytes)
    }

    /// The byte encoding.
    pub fn to_bytes(&self) -> [u8; ENCAPS_KEY_BYTES] {
        self.0
    }
}

impl MlKem768Ciphertext {
    /// Restores a ciphertext from its byte encoding.
    pub fn from_bytes(bytes: [u8; CIPHERTEXT_BYTES]) -> Self {
        MlKem768Ciphertext(bytes)
    }

    /// The byte encoding.
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    #[test]
    fn sizes_match_fips203() {
        assert_eq!(ENCAPS_KEY_BYTES, 1184);
        assert_eq!(DECAPS_KEY_BYTES, 2400);
        assert_eq!(CIPHERTEXT_BYTES, 1088);
    }

    #[test]
    fn encaps_decaps_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"mlkem", b"nonce", &[]);
        let (dk, ek) = MlKem768DecapsKey::generate(&mut rng);
        let (ct, ss_a) = ek.encapsulate(&mut rng);
        let ss_b = dk.decapsulate(&ct);
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn openssl_interop_keygen_and_decaps() {
        // Cross-validated against OpenSSL 3.5's FIPS 203 ML-KEM-768 using the
        // seed d = z = 0³²: the encapsulation key matches byte-for-byte, and
        // decapsulating OpenSSL's ciphertext recovers OpenSSL's shared secret.
        // (Decaps re-encrypts internally, so this also pins K-PKE.Encrypt; and a
        // separate check confirmed OpenSSL decaps of our encaps agrees.)
        use crate::test_util::{from_hex, from_hex_vec};
        let (dk, ek) = MlKem768DecapsKey::from_seeds(&[0u8; 32], &[0u8; 32]);

        let e = ek.to_bytes();
        assert_eq!(e[..16], from_hex::<16>("254a797885c63b1440aa389c65340ef3"));
        assert_eq!(
            e[e.len() - 32..],
            from_hex::<32>("6d3ae406763c50457d1481402aafc7e23f43f9d1d7c0af7060ac1daa9ecb0e67")
        );

        let ct_bytes = from_hex_vec(include_str!("../../testdata/mlkem768_openssl_ct.hex"));
        let mut ct = [0u8; CIPHERTEXT_BYTES];
        ct.copy_from_slice(&ct_bytes);
        let ss = dk.decapsulate(&MlKem768Ciphertext::from_bytes(ct));
        assert_eq!(
            ss,
            from_hex::<32>("2b59302b878ffc5eae9e4f5d4ddc8a73cea97ef10af90d7945b331d288683066")
        );
    }

    #[test]
    fn implicit_rejection_on_tampered_ciphertext() {
        let mut rng = HmacDrbg::<Sha256>::new(b"mlkem-reject", b"nonce", &[]);
        let (dk, ek) = MlKem768DecapsKey::generate(&mut rng);
        let (ct, ss) = ek.encapsulate(&mut rng);

        let mut bad = ct.to_bytes();
        bad[0] ^= 0x01;
        let rejected = dk.decapsulate(&MlKem768Ciphertext::from_bytes(bad));
        // A corrupted ciphertext yields a (deterministic) pseudo-random secret,
        // not the real one.
        assert_ne!(rejected, ss);
        // ...and the same corrupted ciphertext always maps to the same secret.
        assert_eq!(rejected, dk.decapsulate(&MlKem768Ciphertext::from_bytes(bad)));
    }
}
