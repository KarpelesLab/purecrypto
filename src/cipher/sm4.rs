//! SM4 — the Chinese national block cipher (GB/T 32907-2016, RFC 8998 §2).
//!
//! SM4 is a 128-bit-block, 128-bit-key Feistel-like cipher with 32 rounds. Each
//! round applies the composite transform `T = L ∘ τ`, where `τ` is a
//! parallel S-box substitution on four bytes and `L` is a fixed GF(2)-linear
//! diffusion `L(B) = B ⊕ (B<<<2) ⊕ (B<<<10) ⊕ (B<<<18) ⊕ (B<<<24)`. The key
//! schedule uses the same S-box with a different linear map `L'` plus the system
//! parameter `FK` and the round constants `CK`.
//!
//! It implements [`BlockCipher`], so it composes with the crate's CBC, CTR and
//! GCM modes exactly like AES. Round keys are wiped on drop.
//!
//! Note that the S-box here is a table lookup, so — unlike the table-free AES
//! core in this crate — SM4 is **not** hardened against cache-timing attacks.

use super::BlockCipher;

/// The SM4 S-box (GB/T 32907 §6.2).
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

/// System parameter `FK` (GB/T 32907 §7.3.2).
const FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

/// Fixed round-key parameters `CK` (GB/T 32907 §7.3.2).
#[rustfmt::skip]
const CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

/// Nonlinear transform `τ`: applies the S-box to each of the four bytes.
#[inline]
fn tau(x: u32) -> u32 {
    let b = x.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

/// Round linear transform `L(B) = B ⊕ (B<<<2) ⊕ (B<<<10) ⊕ (B<<<18) ⊕ (B<<<24)`.
#[inline]
fn l_round(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

/// Key-schedule linear transform `L'(B) = B ⊕ (B<<<13) ⊕ (B<<<23)`.
#[inline]
fn l_key(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

/// Round composite `T = L ∘ τ`.
#[inline]
fn t_round(x: u32) -> u32 {
    l_round(tau(x))
}

/// Key-schedule composite `T' = L' ∘ τ`.
#[inline]
fn t_key(x: u32) -> u32 {
    l_key(tau(x))
}

/// SM4 block cipher (GB/T 32907 / RFC 8998).
#[derive(Clone)]
pub struct Sm4 {
    /// The 32 round keys.
    rk: [u32; 32],
}

impl Sm4 {
    /// Creates an SM4 cipher from a 128-bit key, expanding the round keys
    /// (GB/T 32907 §7.3).
    pub fn new(key: &[u8; 16]) -> Self {
        let mut k = [0u32; 4];
        for (i, w) in k.iter_mut().enumerate() {
            *w = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
                ^ FK[i];
        }
        let mut rk = [0u32; 32];
        for i in 0..32 {
            let t = k[1] ^ k[2] ^ k[3] ^ CK[i];
            let next = k[0] ^ t_key(t);
            rk[i] = next;
            k[0] = k[1];
            k[1] = k[2];
            k[2] = k[3];
            k[3] = next;
        }
        Sm4 { rk }
    }

    /// Runs the 32-round network with the given (possibly reversed) round-key
    /// order, transforming `block` in place.
    #[inline]
    fn crypt(&self, block: &mut [u8; 16], reverse: bool) {
        let mut x = [0u32; 4];
        for (i, w) in x.iter_mut().enumerate() {
            *w = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for round in 0..32 {
            let rk = if reverse {
                self.rk[31 - round]
            } else {
                self.rk[round]
            };
            let t = x[1] ^ x[2] ^ x[3] ^ rk;
            let next = x[0] ^ t_round(t);
            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = next;
        }
        // Reverse-order output transform R: (Y0,Y1,Y2,Y3) = (X35,X34,X33,X32).
        let out = [x[3], x[2], x[1], x[0]];
        for (i, w) in out.iter().enumerate() {
            block[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
    }
}

impl BlockCipher for Sm4 {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 16;

    #[inline]
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.crypt(block, false);
    }

    #[inline]
    fn decrypt_block(&self, block: &mut [u8; 16]) {
        // Decryption is the same network with the round keys reversed.
        self.crypt(block, true);
    }
}

impl Drop for Sm4 {
    fn drop(&mut self) {
        // Best-effort wipe of the round keys, mirroring the AES round-key drop.
        self.rk = [0u32; 32];
        let _ = core::hint::black_box(&self.rk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // GB/T 32907 Appendix A.1 / RFC 8998 Appendix A.1: single-block KAT.
    #[test]
    fn gbt32907_example() {
        let key = from_hex::<16>("0123456789abcdeffedcba9876543210");
        let cipher = Sm4::new(&key);
        let mut block = from_hex::<16>("0123456789abcdeffedcba9876543210");
        cipher.encrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("681edf34d206965e86b3e94f536e4246"));
        cipher.decrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("0123456789abcdeffedcba9876543210"));
    }

    // GB/T 32907 Appendix A.2: encrypt the example block 1,000,000 times.
    #[test]
    fn gbt32907_million_iterations() {
        let key = from_hex::<16>("0123456789abcdeffedcba9876543210");
        let cipher = Sm4::new(&key);
        let mut block = from_hex::<16>("0123456789abcdeffedcba9876543210");
        for _ in 0..1_000_000 {
            cipher.encrypt_block(&mut block);
        }
        assert_eq!(block, from_hex::<16>("595298c7c6fd271f0402f804c33d3f66"));
    }

    // Round-trip over all single-byte fill patterns.
    #[test]
    fn roundtrip_all_byte_values() {
        let key = from_hex::<16>("0123456789abcdeffedcba9876543210");
        let cipher = Sm4::new(&key);
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
