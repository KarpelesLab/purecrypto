//! Output Feedback (OFB) mode — a stream cipher built from a [`BlockCipher`].
//!
//! The keystream is `E(IV) ‖ E(E(IV)) ‖ …`: each block is the encryption of
//! the previous keystream block. Like CTR it is a synchronous stream cipher,
//! so encryption and decryption are the same XOR operation, and a (key, IV)
//! pair must never be reused.

use super::BlockCipher;

/// OFB-mode stream wrapper around a block cipher.
#[derive(Clone)]
pub struct Ofb<C: BlockCipher> {
    cipher: C,
    /// Current keystream block, fed back into the cipher to produce the next.
    block: [u8; 16],
    /// Bytes of `block` already consumed (`16` ⇒ a fresh block is needed).
    pos: usize,
}

impl<C: BlockCipher> Ofb<C> {
    /// Creates an OFB stream from `cipher` and a 16-byte IV.
    #[inline]
    pub fn new(cipher: C, iv: &[u8; 16]) -> Self {
        Ofb {
            cipher,
            block: *iv,
            pos: 16, // force generation on first use
        }
    }

    #[inline]
    fn refill(&mut self) {
        self.cipher.encrypt_block(&mut self.block);
        self.pos = 0;
    }

    /// XORs the keystream into `data` in place, encrypting or decrypting it.
    ///
    /// May be called repeatedly; the keystream continues seamlessly across
    /// calls regardless of chunk boundaries.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.pos == 16 {
                self.refill();
            }
            *byte ^= self.block[self.pos];
            self.pos += 1;
        }
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

    #[test]
    fn ofb_aes128() {
        // NIST SP 800-38A F.4.1.
        let key = from_hex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = from_hex::<16>("000102030405060708090a0b0c0d0e0f");
        let mut buf = from_hex::<64>(PLAINTEXT);
        let expected = from_hex::<64>(
            "3b3fd92eb72dad20333449f8e83cfb4a\
             7789508d16918f03f53c52dac54ed825\
             9740051e9c5fecf64344f7a82260edcc\
             304c6528f659c77866a510d9c1d6ae5e",
        );

        Ofb::new(Aes128::new(&key), &iv).apply_keystream(&mut buf);
        assert_eq!(buf, expected);

        // OFB is its own inverse.
        Ofb::new(Aes128::new(&key), &iv).apply_keystream(&mut buf);
        assert_eq!(buf, from_hex::<64>(PLAINTEXT));
    }
}
