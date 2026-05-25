//! RSA-PSS signatures (RFC 8017 §8.1, EMSA-PSS with MGF1).
//!
//! The salt length equals the digest length (the common profile, used by
//! TLS 1.3). Gated on `alloc`.

use alloc::vec;
use alloc::vec::Vec;

use super::{Error, RsaPrivateKey, RsaPublicKey};
use crate::bignum::Uint;
use crate::hash::Digest;
use crate::rng::RngCore;

/// MGF1 mask generation function (RFC 8017 B.2.1) using hash `D`.
fn mgf1<D: Digest>(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(mask_len);
    let mut counter: u32 = 0;
    while mask.len() < mask_len {
        let mut h = D::new();
        h.update(seed);
        h.update(&counter.to_be_bytes());
        mask.extend_from_slice(h.finalize().as_ref());
        counter += 1;
    }
    mask.truncate(mask_len);
    mask
}

/// EMSA-PSS encoding of `msg` into an `em_bits`-bit encoded message.
fn emsa_pss_encode<D: Digest, R: RngCore>(
    msg: &[u8],
    em_bits: usize,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let h_len = D::OUTPUT_LEN;
    let s_len = h_len;
    let em_len = em_bits.div_ceil(8);
    if em_len < h_len + s_len + 2 {
        return Err(Error::MessageTooLong);
    }

    let m_hash = D::digest(msg);
    let mut salt = vec![0u8; s_len];
    rng.fill_bytes(&mut salt);

    // H = Hash(0x00*8 || mHash || salt)
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(m_hash.as_ref());
    m_prime.extend_from_slice(&salt);
    let h = D::digest(&m_prime);

    // DB = PS(0x00) || 0x01 || salt
    let db_len = em_len - h_len - 1;
    let mut db = vec![0u8; db_len];
    db[db_len - s_len - 1] = 0x01;
    db[db_len - s_len..].copy_from_slice(&salt);

    let db_mask = mgf1::<D>(h.as_ref(), db_len);
    for (b, m) in db.iter_mut().zip(db_mask.iter()) {
        *b ^= *m;
    }
    // Clear the leftmost (8*em_len - em_bits) bits of DB.
    let clear = 8 * em_len - em_bits;
    if clear > 0 {
        db[0] &= 0xff >> clear;
    }

    let mut em = db;
    em.extend_from_slice(h.as_ref());
    em.push(0xbc);
    Ok(em)
}

/// EMSA-PSS verification of `em` (an `em_bits`-bit encoded message) against
/// `msg`.
fn emsa_pss_verify<D: Digest>(msg: &[u8], em: &[u8], em_bits: usize) -> Result<(), Error> {
    let h_len = D::OUTPUT_LEN;
    let s_len = h_len;
    let em_len = em.len();
    if em_len < h_len + s_len + 2 || em[em_len - 1] != 0xbc {
        return Err(Error::Verification);
    }

    let db_len = em_len - h_len - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..db_len + h_len];

    let clear = 8 * em_len - em_bits;
    if clear > 0 && masked_db[0] & (0xffu8 << (8 - clear)) != 0 {
        return Err(Error::Verification);
    }

    let db_mask = mgf1::<D>(h, db_len);
    let mut db = vec![0u8; db_len];
    for i in 0..db_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }
    if clear > 0 {
        db[0] &= 0xff >> clear;
    }

    // DB must be PS(0x00) || 0x01 || salt.
    let ps_len = db_len - s_len - 1;
    if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
        return Err(Error::Verification);
    }
    let salt = &db[ps_len + 1..];

    let m_hash = D::digest(msg);
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(m_hash.as_ref());
    m_prime.extend_from_slice(salt);
    let h_prime = D::digest(&m_prime);

    if h_prime.as_ref() == h {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

impl<const LIMBS: usize> RsaPrivateKey<LIMBS> {
    /// Signs `msg` with RSA-PSS, hashing with `D` and a salt of `D`'s output
    /// length.
    pub fn sign_pss<D: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let k = LIMBS * 8;
        let em_bits = self.modulus().bit_len() - 1;
        let em = emsa_pss_encode::<D, R>(msg, em_bits, rng)?;
        let m = Uint::<LIMBS>::from_be_bytes(&em);
        let s = self.raw(&m);
        let mut out = vec![0u8; k];
        s.write_be_bytes(&mut out);
        Ok(out)
    }
}

impl<const LIMBS: usize> RsaPublicKey<LIMBS> {
    /// Verifies an RSA-PSS signature over `msg`, hashing with `D`.
    pub fn verify_pss<D: Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let k = LIMBS * 8;
        if sig.len() != k {
            return Err(Error::InvalidLength);
        }
        let s = Uint::<LIMBS>::from_be_bytes(sig);
        let m = self.raw(&s);

        let em_bits = self.modulus().bit_len() - 1;
        let em_len = em_bits.div_ceil(8);
        let mut full = vec![0u8; k];
        m.write_be_bytes(&mut full);
        // I2OSP(m, em_len): the rightmost em_len bytes.
        emsa_pss_verify::<D>(msg, &full[k - em_len..], em_bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::test_util::rsa_test_key_a;

    #[test]
    fn sign_verify_roundtrip() {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-pss", b"nonce", &[]);

        let sig = key.sign_pss::<Sha256, _>(b"pss message", &mut r).unwrap();
        pk.verify_pss::<Sha256>(b"pss message", &sig).unwrap();

        // Wrong message fails.
        assert_eq!(
            pk.verify_pss::<Sha256>(b"other", &sig),
            Err(Error::Verification)
        );
        // Tampered signature fails.
        let mut bad = sig.clone();
        bad[20] ^= 1;
        assert_eq!(
            pk.verify_pss::<Sha256>(b"pss message", &bad),
            Err(Error::Verification)
        );
    }

    #[test]
    fn pss_is_randomized() {
        // Two signatures over the same message differ (random salt).
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-pss-rand", b"nonce", &[]);
        let a = key.sign_pss::<Sha256, _>(b"m", &mut r).unwrap();
        let b = key.sign_pss::<Sha256, _>(b"m", &mut r).unwrap();
        assert_ne!(a, b);
        pk.verify_pss::<Sha256>(b"m", &a).unwrap();
        pk.verify_pss::<Sha256>(b"m", &b).unwrap();
    }
}
