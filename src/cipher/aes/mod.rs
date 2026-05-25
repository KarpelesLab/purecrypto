//! AES (FIPS-197) block cipher, constant-time.
//!
//! Supports 128-, 192- and 256-bit keys. The state is held as 16 bytes in
//! column-major order (`state[4*col + row]`), matching FIPS-197. All
//! transforms are branchless and table-free, so encryption time does not
//! depend on key or data values.

mod gf;

use super::BlockCipher;
use gf::{gf_mul, inv_sub_byte, sub_byte};

/// XORs a 16-byte round key into the state.
#[inline]
fn add_round_key(state: &mut [u8; 16], rk: &[u8]) {
    for (s, k) in state.iter_mut().zip(rk.iter()) {
        *s ^= *k;
    }
}

#[inline]
fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = sub_byte(*b);
    }
}

#[inline]
fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = inv_sub_byte(*b);
    }
}

/// Cyclically shifts row `r` left by `r` bytes (column-major layout).
#[inline]
fn shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    // Row 1: <<< 1
    s[1] = t[5];
    s[5] = t[9];
    s[9] = t[13];
    s[13] = t[1];
    // Row 2: <<< 2
    s[2] = t[10];
    s[6] = t[14];
    s[10] = t[2];
    s[14] = t[6];
    // Row 3: <<< 3
    s[3] = t[15];
    s[7] = t[3];
    s[11] = t[7];
    s[15] = t[11];
}

/// Inverse of [`shift_rows`]: cyclically shifts row `r` right by `r` bytes.
#[inline]
fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    // Row 1: >>> 1
    s[1] = t[13];
    s[5] = t[1];
    s[9] = t[5];
    s[13] = t[9];
    // Row 2: >>> 2
    s[2] = t[10];
    s[6] = t[14];
    s[10] = t[2];
    s[14] = t[6];
    // Row 3: >>> 3
    s[3] = t[7];
    s[7] = t[11];
    s[11] = t[15];
    s[15] = t[3];
}

#[inline]
fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        s[i + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        s[i + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        s[i + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

#[inline]
fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
        s[i + 1] = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
        s[i + 2] = gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
        s[i + 3] = gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);
    }
}

/// Expands `key` (`nk` 32-bit words) into `out`, the round-key bytes for `nr`
/// rounds (`16 * (nr + 1)` bytes). The control flow depends only on the public
/// key length, not on key contents.
fn key_expansion(key: &[u8], nk: usize, nr: usize, out: &mut [u8]) {
    let total_words = 4 * (nr + 1);
    out[..key.len()].copy_from_slice(key);

    let mut rcon = 1u8;
    for i in nk..total_words {
        let prev = i - 1;
        let mut t = [
            out[prev * 4],
            out[prev * 4 + 1],
            out[prev * 4 + 2],
            out[prev * 4 + 3],
        ];

        if i % nk == 0 {
            // RotWord, then SubWord, then XOR the round constant.
            t = [t[1], t[2], t[3], t[0]];
            for b in t.iter_mut() {
                *b = sub_byte(*b);
            }
            t[0] ^= rcon;
            rcon = gf_mul(rcon, 2);
        } else if nk > 6 && i % nk == 4 {
            // AES-256 applies an extra SubWord a quarter of the way in.
            for b in t.iter_mut() {
                *b = sub_byte(*b);
            }
        }

        let base = i * 4;
        let src = (i - nk) * 4;
        for j in 0..4 {
            out[base + j] = out[src + j] ^ t[j];
        }
    }
}

/// Encrypts one block using the expanded round keys.
fn encrypt(rk: &[u8], nr: usize, block: &mut [u8; 16]) {
    add_round_key(block, &rk[0..16]);
    for round in 1..nr {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, &rk[round * 16..round * 16 + 16]);
    }
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, &rk[nr * 16..nr * 16 + 16]);
}

/// Decrypts one block using the expanded round keys (FIPS-197 inverse cipher).
fn decrypt(rk: &[u8], nr: usize, block: &mut [u8; 16]) {
    add_round_key(block, &rk[nr * 16..nr * 16 + 16]);
    for round in (1..nr).rev() {
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, &rk[round * 16..round * 16 + 16]);
        inv_mix_columns(block);
    }
    inv_shift_rows(block);
    inv_sub_bytes(block);
    add_round_key(block, &rk[0..16]);
}

/// Defines an AES variant with a given key size, key-word count, round count,
/// and round-key buffer length.
macro_rules! aes_variant {
    ($(#[$meta:meta])* $name:ident, $key_bytes:literal, $nk:literal, $nr:literal, $rk_len:literal) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            rk: [u8; $rk_len],
        }

        impl $name {
            /// Creates a cipher instance from the given key, expanding the key
            /// schedule.
            pub fn new(key: &[u8; $key_bytes]) -> Self {
                let mut rk = [0u8; $rk_len];
                key_expansion(key, $nk, $nr, &mut rk);
                $name { rk }
            }
        }

        impl BlockCipher for $name {
            const BLOCK_SIZE: usize = 16;
            const KEY_SIZE: usize = $key_bytes;

            #[inline]
            fn encrypt_block(&self, block: &mut [u8; 16]) {
                encrypt(&self.rk, $nr, block);
            }

            #[inline]
            fn decrypt_block(&self, block: &mut [u8; 16]) {
                decrypt(&self.rk, $nr, block);
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // Best-effort wipe of the expanded key material.
                for b in self.rk.iter_mut() {
                    *b = 0;
                }
                core::hint::black_box(&self.rk);
            }
        }
    };
}

aes_variant!(
    /// AES with a 128-bit key (10 rounds).
    Aes128, 16, 4, 10, 176
);
aes_variant!(
    /// AES with a 192-bit key (12 rounds).
    Aes192, 24, 6, 12, 208
);
aes_variant!(
    /// AES with a 256-bit key (14 rounds).
    Aes256, 32, 8, 14, 240
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    #[test]
    fn fips197_aes128() {
        let key = from_hex::<16>("000102030405060708090a0b0c0d0e0f");
        let cipher = Aes128::new(&key);
        let mut block = from_hex::<16>("00112233445566778899aabbccddeeff");
        cipher.encrypt_block(&mut block);
        assert_eq!(
            block,
            from_hex::<16>("69c4e0d86a7b0430d8cdb78070b4c55a")
        );
        cipher.decrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn fips197_aes192() {
        let key = from_hex::<24>("000102030405060708090a0b0c0d0e0f1011121314151617");
        let cipher = Aes192::new(&key);
        let mut block = from_hex::<16>("00112233445566778899aabbccddeeff");
        cipher.encrypt_block(&mut block);
        assert_eq!(
            block,
            from_hex::<16>("dda97ca4864cdfe06eaf70a0ec0d7191")
        );
        cipher.decrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn fips197_aes256() {
        let key =
            from_hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let cipher = Aes256::new(&key);
        let mut block = from_hex::<16>("00112233445566778899aabbccddeeff");
        cipher.encrypt_block(&mut block);
        assert_eq!(
            block,
            from_hex::<16>("8ea2b7ca516745bfeafc49904b496089")
        );
        cipher.decrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn roundtrip_all_byte_values() {
        let key = from_hex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let cipher = Aes128::new(&key);
        for v in 0u16..=255 {
            let original = [v as u8; 16];
            let mut block = original;
            cipher.encrypt_block(&mut block);
            assert_ne!(block, original, "ciphertext should differ from plaintext");
            cipher.decrypt_block(&mut block);
            assert_eq!(block, original);
        }
    }
}
