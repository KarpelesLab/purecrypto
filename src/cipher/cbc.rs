//! Cipher Block Chaining (CBC) mode.
//!
//! `C_j = E(P_j ⊕ C_{j-1})` with `C_{-1} = IV`. CBC operates on whole blocks
//! only; callers must pad the plaintext (e.g. PKCS#7) so its length is a
//! multiple of 16. It provides confidentiality only — it is unauthenticated.
//! A (key, IV) pair must never be reused, and the IV must be unpredictable.

use super::{BlockCipher, InvalidLength};

/// CBC-mode wrapper around a block cipher.
#[derive(Clone)]
pub struct Cbc<C: BlockCipher> {
    cipher: C,
    /// Chaining value: the previous ciphertext block (IV initially).
    chain: [u8; 16],
}

impl<C: BlockCipher> Cbc<C> {
    /// Creates a CBC context from `cipher` and a 16-byte IV.
    #[inline]
    pub fn new(cipher: C, iv: &[u8; 16]) -> Self {
        Cbc { cipher, chain: *iv }
    }

    /// Encrypts `data` in place. May be called repeatedly to continue the
    /// chain, but every call's length must be a multiple of 16 bytes.
    ///
    /// # Errors
    /// Returns [`InvalidLength`] (without modifying `data`) if the length is
    /// not a whole number of blocks.
    pub fn encrypt(&mut self, data: &mut [u8]) -> Result<(), InvalidLength> {
        if !data.len().is_multiple_of(16) {
            return Err(InvalidLength);
        }
        for chunk in data.chunks_exact_mut(16) {
            for (b, c) in chunk.iter_mut().zip(self.chain.iter()) {
                *b ^= *c;
            }
            let block: &mut [u8; 16] = chunk.try_into().unwrap();
            self.cipher.encrypt_block(block);
            self.chain = *block;
        }
        Ok(())
    }

    /// Decrypts `data` in place. May be called repeatedly to continue the
    /// chain, but every call's length must be a multiple of 16 bytes.
    ///
    /// # Errors
    /// Returns [`InvalidLength`] (without modifying `data`) if the length is
    /// not a whole number of blocks.
    pub fn decrypt(&mut self, data: &mut [u8]) -> Result<(), InvalidLength> {
        if !data.len().is_multiple_of(16) {
            return Err(InvalidLength);
        }
        for chunk in data.chunks_exact_mut(16) {
            let saved = <[u8; 16]>::try_from(&chunk[..]).unwrap();
            let block: &mut [u8; 16] = chunk.try_into().unwrap();
            self.cipher.decrypt_block(block);
            for (b, c) in block.iter_mut().zip(self.chain.iter()) {
                *b ^= *c;
            }
            self.chain = saved;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::Aes128;
    use crate::test_util::from_hex;

    const PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172a\
                             ae2d8a571e03ac9c9eb76fac45af8e51\
                             30c81c46a35ce411e5fbc1191a0a52ef\
                             f69f2445df4f9b17ad2b417be66c3710";
    const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const IV: &str = "000102030405060708090a0b0c0d0e0f";
    // NIST SP 800-38A F.2.1 (CBC-AES128).
    const CIPHERTEXT: &str = "7649abac8119b246cee98e9b12e9197d\
                              5086cb9b507219ee95db113a917678b2\
                              73bed6b8e3c1743b7116e69e22229516\
                              3ff1caa1681fac09120eca307586e1a7";

    #[test]
    fn cbc_aes128() {
        let key = from_hex::<16>(KEY);
        let iv = from_hex::<16>(IV);
        let mut buf = from_hex::<64>(PLAINTEXT);

        Cbc::new(Aes128::new(&key), &iv).encrypt(&mut buf).unwrap();
        assert_eq!(buf, from_hex::<64>(CIPHERTEXT));

        Cbc::new(Aes128::new(&key), &iv).decrypt(&mut buf).unwrap();
        assert_eq!(buf, from_hex::<64>(PLAINTEXT));
    }

    #[test]
    fn rejects_partial_block() {
        let key = from_hex::<16>(KEY);
        let iv = from_hex::<16>(IV);
        let mut buf = [0u8; 20];
        assert_eq!(
            Cbc::new(Aes128::new(&key), &iv).encrypt(&mut buf),
            Err(InvalidLength)
        );
    }
}
