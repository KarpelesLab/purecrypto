//! Cipher Feedback (CFB) mode, full-block variant (CFB-128).
//!
//! Each keystream block is `E` of the previous ciphertext block (the IV for
//! the first), and the ciphertext is fed back into the cipher. Encryption and
//! decryption differ (the feedback is always the ciphertext), so they are
//! separate methods. A (key, IV) pair must never be reused.

use super::BlockCipher;

/// CFB-128 mode wrapper around a block cipher.
#[derive(Clone)]
pub struct Cfb<C: BlockCipher> {
    cipher: C,
    /// Feedback block: the previous ciphertext block (IV initially), built up
    /// byte-by-byte as output is produced.
    feedback: [u8; 16],
    /// Current keystream block, `E(feedback)` from the start of this block.
    keystream: [u8; 16],
    /// Bytes of the current block already processed.
    pos: usize,
}

impl<C: BlockCipher> Cfb<C> {
    /// Creates a CFB stream from `cipher` and a 16-byte IV.
    #[inline]
    pub fn new(cipher: C, iv: &[u8; 16]) -> Self {
        Cfb {
            cipher,
            feedback: *iv,
            keystream: [0u8; 16],
            pos: 16, // force generation on first use
        }
    }

    /// Recomputes the keystream from the (just-completed) feedback block.
    #[inline]
    fn refill(&mut self) {
        self.keystream = self.feedback;
        self.cipher.encrypt_block(&mut self.keystream);
        self.pos = 0;
    }

    /// Encrypts `data` in place. May be called repeatedly across chunk
    /// boundaries.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.pos == 16 {
                self.refill();
            }
            let c = *byte ^ self.keystream[self.pos];
            self.feedback[self.pos] = c; // ciphertext feeds the next block
            *byte = c;
            self.pos += 1;
        }
    }

    /// Decrypts `data` in place. May be called repeatedly across chunk
    /// boundaries.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.pos == 16 {
                self.refill();
            }
            let c = *byte;
            self.feedback[self.pos] = c; // ciphertext feeds the next block
            *byte = c ^ self.keystream[self.pos];
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
    const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const IV: &str = "000102030405060708090a0b0c0d0e0f";
    // NIST SP 800-38A F.3.13 (CFB128-AES128).
    const CIPHERTEXT: &str = "3b3fd92eb72dad20333449f8e83cfb4a\
                              c8a64537a0b3a93fcde3cdad9f1ce58b\
                              26751f67a3cbb140b1808cf187a4f4df\
                              c04b05357c5d1c0eeac4c66f9ff7f2e6";

    #[test]
    fn cfb_aes128_encrypt() {
        let key = from_hex::<16>(KEY);
        let iv = from_hex::<16>(IV);
        let mut buf = from_hex::<64>(PLAINTEXT);
        Cfb::new(Aes128::new(&key), &iv).encrypt(&mut buf);
        assert_eq!(buf, from_hex::<64>(CIPHERTEXT));
    }

    #[test]
    fn cfb_aes128_decrypt() {
        let key = from_hex::<16>(KEY);
        let iv = from_hex::<16>(IV);
        let mut buf = from_hex::<64>(CIPHERTEXT);
        Cfb::new(Aes128::new(&key), &iv).decrypt(&mut buf);
        assert_eq!(buf, from_hex::<64>(PLAINTEXT));
    }

    #[test]
    fn streaming_matches_oneshot() {
        let key = from_hex::<16>(KEY);
        let iv = from_hex::<16>(IV);
        let plaintext = from_hex::<64>(PLAINTEXT);

        let mut chunked = plaintext;
        let mut cfb = Cfb::new(Aes128::new(&key), &iv);
        let mut start = 0;
        for len in [5usize, 11, 16, 1, 31] {
            cfb.encrypt(&mut chunked[start..start + len]);
            start += len;
        }
        assert_eq!(chunked, from_hex::<64>(CIPHERTEXT));
    }
}
