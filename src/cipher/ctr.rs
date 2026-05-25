//! Counter (CTR) mode — turns a [`BlockCipher`] into a stream cipher.
//!
//! The keystream is `E(C₀) ‖ E(C₁) ‖ …` where the counter block is incremented
//! as a big-endian 128-bit integer between blocks. Encryption and decryption
//! are the same operation (XOR with the keystream), so a single
//! [`apply_keystream`](Ctr::apply_keystream) serves both.
//!
//! CTR provides confidentiality only — it is unauthenticated and malleable.
//! For integrity, use an AEAD such as AES-GCM. A given (key, counter) prefix
//! must never be reused.

use super::BlockCipher;

/// CTR-mode stream wrapper around a block cipher.
#[derive(Clone)]
pub struct Ctr<C: BlockCipher> {
    cipher: C,
    counter: [u8; 16],
    keystream: [u8; 16],
    /// Bytes of `keystream` already consumed (`16` ⇒ a fresh block is needed).
    pos: usize,
}

impl<C: BlockCipher> Ctr<C> {
    /// Creates a CTR stream from `cipher` and an initial 16-byte counter block
    /// (nonce ‖ counter).
    #[inline]
    pub fn new(cipher: C, iv: &[u8; 16]) -> Self {
        Ctr {
            cipher,
            counter: *iv,
            keystream: [0u8; 16],
            pos: 16, // force generation on first use
        }
    }

    /// Generates the next keystream block and advances the counter.
    #[inline]
    fn refill(&mut self) {
        self.keystream = self.counter;
        self.cipher.encrypt_block(&mut self.keystream);
        increment(&mut self.counter);
        self.pos = 0;
    }

    /// XORs the keystream into `data` in place, encrypting or decrypting it.
    ///
    /// May be called repeatedly; the keystream continues seamlessly across
    /// calls regardless of how the data is chunked.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.pos == 16 {
                self.refill();
            }
            *byte ^= self.keystream[self.pos];
            self.pos += 1;
        }
    }
}

/// Increments a 16-byte big-endian counter in place, wrapping at 2¹²⁸.
#[inline]
fn increment(counter: &mut [u8; 16]) {
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{Aes128, Aes256};
    use crate::test_util::from_hex;

    // NIST SP 800-38A F.5.1 / F.5.5 CTR-AES vectors. The 64-byte message is the
    // standard four-block plaintext; the counter starts at f0f1..ff.
    const PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172a\
                             ae2d8a571e03ac9c9eb76fac45af8e51\
                             30c81c46a35ce411e5fbc1191a0a52ef\
                             f69f2445df4f9b17ad2b417be66c3710";
    const IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    #[test]
    fn ctr_aes128() {
        let key = from_hex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = from_hex::<16>(IV);
        let mut buf = from_hex::<64>(PLAINTEXT);
        let expected = from_hex::<64>(
            "874d6191b620e3261bef6864990db6ce\
             9806f66b7970fdff8617187bb9fffdff\
             5ae4df3edbd5d35e5b4f09020db03eab\
             1e031dda2fbe03d1792170a0f3009cee",
        );

        Ctr::new(Aes128::new(&key), &iv).apply_keystream(&mut buf);
        assert_eq!(buf, expected);

        // CTR is its own inverse.
        Ctr::new(Aes128::new(&key), &iv).apply_keystream(&mut buf);
        assert_eq!(buf, from_hex::<64>(PLAINTEXT));
    }

    #[test]
    fn ctr_aes256() {
        let key = from_hex::<32>(
            "603deb1015ca71be2b73aef0857d7781\
             1f352c073b6108d72d9810a30914dff4",
        );
        let iv = from_hex::<16>(IV);
        let mut buf = from_hex::<64>(PLAINTEXT);
        let expected = from_hex::<64>(
            "601ec313775789a5b7a7f504bbf3d228\
             f443e3ca4d62b59aca84e990cacaf5c5\
             2b0930daa23de94ce87017ba2d84988d\
             dfc9c58db67aada613c2dd08457941a6",
        );

        Ctr::new(Aes256::new(&key), &iv).apply_keystream(&mut buf);
        assert_eq!(buf, expected);
    }

    #[test]
    fn streaming_matches_oneshot() {
        let key = from_hex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = from_hex::<16>(IV);
        let plaintext = from_hex::<64>(PLAINTEXT);

        let mut oneshot = plaintext;
        Ctr::new(Aes128::new(&key), &iv).apply_keystream(&mut oneshot);

        // Encrypt in irregular chunks that straddle block boundaries.
        let mut chunked = plaintext;
        let mut ctr = Ctr::new(Aes128::new(&key), &iv);
        let mut start = 0;
        for len in [1usize, 14, 1, 30, 18] {
            ctr.apply_keystream(&mut chunked[start..start + len]);
            start += len;
        }
        assert_eq!(chunked, oneshot);
    }

    #[test]
    fn counter_carry() {
        let mut c = from_hex::<16>("000000000000000000000000000000ff");
        increment(&mut c);
        assert_eq!(c, from_hex::<16>("00000000000000000000000000000100"));

        let mut all_ones = [0xffu8; 16];
        increment(&mut all_ones);
        assert_eq!(all_ones, [0u8; 16]);
    }
}
