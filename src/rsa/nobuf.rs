//! Allocator-free PKCS#1 v1.5, PSS and OAEP over the const-generic keys.
//!
//! These are the buffer-passing counterparts of the `Vec`-returning methods in
//! [`pkcs1`](super::pkcs1) and [`pss`](super::pss), and they share the single
//! constant-time implementation in [`emsa`](super::emsa) — nothing here
//! re-implements padding logic.
//!
//! The scratch each scheme needs is exactly `k = LIMBS * 8` octets, which is
//! known at compile time, so it lives on the stack as [`KeyScratch`]: `[u8;
//! LIMBS * 8]` cannot be written on stable, but `[[u8; 8]; LIMBS]` is the same
//! size and `as_flattened_mut` views it as `&mut [u8]` with no `unsafe`.
//!
//! Output length: signatures and ciphertexts are always exactly `k` octets, so
//! those methods take a `k`-octet `out` and return `()`. Decryption recovers a
//! variable-length plaintext, so it returns the number of octets written.

use super::keys::KeyScratch;
use super::{Error, Pkcs1Digest, RsaPrivateKey, RsaPublicKey};
use crate::hash::Digest;
use crate::rng::{CryptoRng, RngCore};

impl<const LIMBS: usize> RsaPrivateKey<LIMBS> {
    /// Signs `msg` with PKCS#1 v1.5 into `out`, which must be exactly
    /// `LIMBS * 8` octets. Allocation-free counterpart of
    /// [`sign_pkcs1v15`](Self::sign_pkcs1v15).
    pub fn sign_pkcs1v15_into<D: Pkcs1Digest>(
        &self,
        msg: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        super::emsa::sign_pkcs1v15::<D, _>(self, msg, out)
    }

    /// Signs `msg` with RSA-PSS into `out` (exactly `LIMBS * 8` octets), using a
    /// salt of `D`'s output length. Allocation-free counterpart of
    /// [`sign_pss`](Self::sign_pss).
    pub fn sign_pss_into<D: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<(), Error> {
        super::emsa::sign_pss::<D, _, R>(self, msg, rng, out)
    }

    /// Signs `msg` with RSA-PSS into `out` using an explicit salt length.
    pub fn sign_pss_with_salt_len_into<D: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        salt_len: usize,
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<(), Error> {
        super::emsa::sign_pss_with_salt_len::<D, _, R>(self, msg, salt_len, rng, out)
    }

    /// Decrypts a PKCS#1 v1.5 ciphertext into `out`, returning the plaintext
    /// length. `out` must be at least `LIMBS * 8 - 11` octets to be sure of
    /// holding any valid plaintext.
    ///
    /// Carries the same padding-oracle caveat as
    /// [`decrypt_pkcs1v15`](Self::decrypt_pkcs1v15): the returned length is
    /// observable. Prefer [`Self::decrypt_pkcs1v15_session_into`] where the
    /// plaintext length is known in advance.
    pub fn decrypt_pkcs1v15_into(&self, ct: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let mut scratch = KeyScratch::<LIMBS>::ZEROED;
        super::emsa::decrypt_pkcs1v15(self, ct, scratch.as_flattened_mut(), out)
    }

    /// Constant-time PKCS#1 v1.5 decryption with implicit rejection, writing
    /// exactly `out.len()` octets: on padding failure `out` receives a
    /// key-bound synthetic plaintext instead of an error, so success and
    /// failure are indistinguishable to the caller.
    pub fn decrypt_pkcs1v15_session_into(&self, ct: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let mut scratch = KeyScratch::<LIMBS>::ZEROED;
        super::emsa::decrypt_pkcs1v15_session(self, ct, scratch.as_flattened_mut(), out)
    }

    /// Decrypts an RSAES-OAEP ciphertext into `out`, returning the plaintext
    /// length.
    pub fn decrypt_oaep_into<D: Digest>(
        &self,
        ct: &[u8],
        label: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut scratch = KeyScratch::<LIMBS>::ZEROED;
        super::emsa::decrypt_oaep::<D, _>(self, ct, label, scratch.as_flattened_mut(), out)
    }
}

impl<const LIMBS: usize> RsaPublicKey<LIMBS> {
    /// Verifies a PKCS#1 v1.5 signature over `msg`.
    ///
    /// Needs no caller buffer and no allocator: both `k`-octet scratch buffers
    /// are stack-allocated here, so this has the same signature as the
    /// `alloc` build's [`verify_pkcs1v15`](Self::verify_pkcs1v15) — that method
    /// is simply this one under a different name when `alloc` is on.
    pub fn verify_pkcs1v15_noalloc<D: Pkcs1Digest>(
        &self,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), Error> {
        let (mut em, mut expected) = (KeyScratch::<LIMBS>::ZEROED, KeyScratch::<LIMBS>::ZEROED);
        super::emsa::verify_pkcs1v15::<D, _>(
            self,
            msg,
            sig,
            em.as_flattened_mut(),
            expected.as_flattened_mut(),
        )
    }

    /// Verifies an RSA-PSS signature over `msg`, requiring a salt of `D`'s
    /// output length. Stack-allocated scratch, no allocator.
    pub fn verify_pss_noalloc<D: Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let (mut em, mut db) = (KeyScratch::<LIMBS>::ZEROED, KeyScratch::<LIMBS>::ZEROED);
        super::emsa::verify_pss::<D, _>(
            self,
            msg,
            sig,
            em.as_flattened_mut(),
            db.as_flattened_mut(),
        )
    }

    /// Verifies an RSA-PSS signature requiring the salt to be exactly
    /// `salt_len` octets. Stack-allocated scratch, no allocator.
    pub fn verify_pss_with_salt_len_noalloc<D: Digest>(
        &self,
        msg: &[u8],
        sig: &[u8],
        salt_len: usize,
    ) -> Result<(), Error> {
        let (mut em, mut db) = (KeyScratch::<LIMBS>::ZEROED, KeyScratch::<LIMBS>::ZEROED);
        super::emsa::verify_pss_with_salt_len::<D, _>(
            self,
            msg,
            sig,
            salt_len,
            em.as_flattened_mut(),
            db.as_flattened_mut(),
        )
    }

    /// Verifies an RSA-PSS signature, recovering the salt length from the
    /// encoded message.
    pub fn verify_pss_any_salt_noalloc<D: Digest>(
        &self,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), Error> {
        let (mut em, mut db) = (KeyScratch::<LIMBS>::ZEROED, KeyScratch::<LIMBS>::ZEROED);
        super::emsa::verify_pss_any_salt::<D, _>(
            self,
            msg,
            sig,
            em.as_flattened_mut(),
            db.as_flattened_mut(),
        )
    }

    /// Encrypts `msg` with PKCS#1 v1.5 into `out` (exactly `LIMBS * 8` octets).
    ///
    /// `rng` must be a CSPRNG — the random padding is part of the security
    /// argument.
    pub fn encrypt_pkcs1v15_into<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<(), Error> {
        super::emsa::encrypt_pkcs1v15(self, msg, rng, out)
    }

    /// Encrypts `msg` with RSAES-OAEP into `out` (exactly `LIMBS * 8` octets).
    pub fn encrypt_oaep_into<D: Digest, R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        label: &[u8],
        rng: &mut R,
        out: &mut [u8],
    ) -> Result<(), Error> {
        super::emsa::encrypt_oaep::<D, _, _>(self, msg, label, rng, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::Uint;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    /// A 1024-bit key: quick to generate, yet large enough for PSS and OAEP
    /// with SHA-256, which need `2 * 32 + 2` octets of headroom.
    fn key() -> RsaPrivateKey<16> {
        let mut rng = HmacDrbg::<Sha256>::new(b"rsa-nobuf-tests", b"nonce", &[]);
        RsaPrivateKey::<16>::generate(Uint::from_u64(65537), &mut rng, 16)
    }

    #[test]
    fn pkcs1v15_sign_verify_roundtrip_no_alloc() {
        let sk = key();
        let pk = sk.public_key();
        let mut sig = [0u8; 128];
        sk.sign_pkcs1v15_into::<Sha256>(b"embedded", &mut sig)
            .unwrap();
        pk.verify_pkcs1v15_noalloc::<Sha256>(b"embedded", &sig)
            .unwrap();
        assert!(
            pk.verify_pkcs1v15_noalloc::<Sha256>(b"other", &sig)
                .is_err(),
            "signature must not verify over a different message"
        );
    }

    #[test]
    fn pss_sign_verify_roundtrip_no_alloc() {
        let sk = key();
        let pk = sk.public_key();
        let mut rng = HmacDrbg::<Sha256>::new(b"pss-salt", b"nonce", &[]);
        let mut sig = [0u8; 128];
        sk.sign_pss_into::<Sha256, _>(b"embedded", &mut rng, &mut sig)
            .unwrap();
        pk.verify_pss_noalloc::<Sha256>(b"embedded", &sig).unwrap();
        pk.verify_pss_any_salt_noalloc::<Sha256>(b"embedded", &sig)
            .unwrap();
        assert!(pk.verify_pss_noalloc::<Sha256>(b"other", &sig).is_err());
    }

    #[test]
    fn pkcs1v15_encrypt_decrypt_roundtrip_no_alloc() {
        let sk = key();
        let pk = sk.public_key();
        let mut rng = HmacDrbg::<Sha256>::new(b"v15-pad", b"nonce", &[]);
        let mut ct = [0u8; 128];
        pk.encrypt_pkcs1v15_into(b"secret", &mut rng, &mut ct)
            .unwrap();
        let mut pt = [0u8; 128];
        let n = sk.decrypt_pkcs1v15_into(&ct, &mut pt).unwrap();
        assert_eq!(&pt[..n], b"secret");
    }

    #[test]
    fn oaep_encrypt_decrypt_roundtrip_no_alloc() {
        let sk = key();
        let pk = sk.public_key();
        let mut rng = HmacDrbg::<Sha256>::new(b"oaep-seed", b"nonce", &[]);
        let mut ct = [0u8; 128];
        pk.encrypt_oaep_into::<Sha256, _>(b"secret", b"label", &mut rng, &mut ct)
            .unwrap();
        let mut pt = [0u8; 128];
        let n = sk
            .decrypt_oaep_into::<Sha256>(&ct, b"label", &mut pt)
            .unwrap();
        assert_eq!(&pt[..n], b"secret");
        // A different label must not decrypt.
        assert!(
            sk.decrypt_oaep_into::<Sha256>(&ct, b"other", &mut pt)
                .is_err()
        );
    }

    /// RFC 8017 §7.2.2 step 1: a ciphertext representative outside `[0, n)`
    /// must be reported, not silently reduced mod `n` (release) or tripped
    /// over in `MontModulus::to_mont`'s debug assertion (debug builds).
    /// `0xff…ff` is `2^1024 − 1`, above every 1024-bit modulus.
    #[test]
    fn out_of_range_ciphertext_is_rejected() {
        // A key imported without primes: blinding is disabled, so the raw op
        // is a bare `modulus.pow(c, d)` and `c >= n` reaches `to_mont`
        // directly. `d` need not be the real exponent — the point is that the
        // range check fires before any modular arithmetic runs.
        let real = key();
        let sk = RsaPrivateKey::<16>::from_components(
            *real.public_key().modulus(),
            Uint::from_u64(65537),
            Uint::from_u64(3),
        );
        let ct = [0xffu8; 128];
        let mut pt = [0u8; 128];

        assert!(sk.decrypt_pkcs1v15_into(&ct, &mut pt).is_err());
        assert!(
            sk.decrypt_oaep_into::<Sha256>(&ct, b"label", &mut pt)
                .is_err()
        );

        // The session variant must preserve implicit rejection: an
        // out-of-range ciphertext looks exactly like bad padding, so it
        // returns the synthetic plaintext rather than an error.
        let mut out = [0u8; 48];
        sk.decrypt_pkcs1v15_session_into(&ct, &mut out).unwrap();
        assert!(out.iter().any(|&b| b != 0));
        let mut again = [0u8; 48];
        sk.decrypt_pkcs1v15_session_into(&ct, &mut again).unwrap();
        assert_eq!(out, again, "synthetic plaintext must be deterministic");

        // An in-range ciphertext still decrypts on a fully-formed key.
        let mut rng = HmacDrbg::<Sha256>::new(b"oor-inrange", b"nonce", &[]);
        let mut good = [0u8; 128];
        real.public_key()
            .encrypt_pkcs1v15_into(b"secret", &mut rng, &mut good)
            .unwrap();
        let n = real.decrypt_pkcs1v15_into(&good, &mut pt).unwrap();
        assert_eq!(&pt[..n], b"secret");

        // And a blinded (generated) key rejects the out-of-range ciphertext
        // just the same.
        assert!(real.decrypt_pkcs1v15_into(&ct, &mut pt).is_err());
        assert!(
            real.decrypt_oaep_into::<Sha256>(&ct, b"label", &mut pt)
                .is_err()
        );
    }

    #[test]
    fn implicit_rejection_fills_the_whole_buffer() {
        let sk = key();
        // Garbage ciphertext: the session variant must still return Ok and fill
        // `out` with the key-bound synthetic plaintext rather than erroring.
        let ct = [0x42u8; 128];
        let mut out = [0u8; 48];
        sk.decrypt_pkcs1v15_session_into(&ct, &mut out).unwrap();
        assert!(out.iter().any(|&b| b != 0), "fallback must be filled");
        // Deterministic for a given key and ciphertext.
        let mut again = [0u8; 48];
        sk.decrypt_pkcs1v15_session_into(&ct, &mut again).unwrap();
        assert_eq!(out, again);
    }

    /// The buffer-passing API and the allocating API must agree exactly — they
    /// share one implementation, and this pins that they stay wired to it.
    #[cfg(feature = "alloc")]
    #[test]
    fn into_api_matches_allocating_api() {
        let sk = key();
        let pk = sk.public_key();

        let mut sig = [0u8; 128];
        sk.sign_pkcs1v15_into::<Sha256>(b"agree", &mut sig).unwrap();
        // PKCS#1 v1.5 signing is deterministic, so the bytes must be identical.
        assert_eq!(
            sig.as_slice(),
            sk.sign_pkcs1v15::<Sha256>(b"agree").unwrap()
        );

        // PSS is randomized, so cross-verify instead of comparing bytes.
        pk.verify_pkcs1v15::<Sha256>(b"agree", &sig).unwrap();
        let mut rng = HmacDrbg::<Sha256>::new(b"x", b"n", &[]);
        let mut pss = [0u8; 128];
        sk.sign_pss_into::<Sha256, _>(b"agree", &mut rng, &mut pss)
            .unwrap();
        pk.verify_pss::<Sha256>(b"agree", &pss).unwrap();
    }
}
