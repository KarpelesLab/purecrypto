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
//! Like the table-free AES core in this crate, the S-box is **computed**
//! rather than looked up: `S(x) = A(inv(A(x)))`, where `A` is a fixed affine
//! transform and `inv` is inversion in GF(2⁸) modulo `x⁸+x⁷+x⁶+x⁵+x⁴+x²+1`
//! (`0x1f5`). That field is isomorphic to the AES field, so the inversion is
//! carried out by the bitsliced AES circuit ([`super::sbox_bitsliced`]) with
//! the isomorphism and `A` folded into the affine maps around it. Every
//! operation is branchless with no secret-dependent memory access, so SM4 is
//! hardened against cache-timing attacks. The circuit substitutes 32 bytes
//! at once, so [`BlockCipher::encrypt_blocks`] runs eight blocks in lockstep
//! to fill it; a single block still pays for one pass per round.

use super::BlockCipher;
use super::sbox_bitsliced::{Affine, PlaneAffine, sbox_custom};
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

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

// --- The S-box as an affine conjugate of the AES S-box ---------------------
//
// `S = post ∘ S_aes ∘ pre` with `pre = φ ∘ A` and `post = A ∘ φ⁻¹ ∘ A_aes⁻¹`,
// where `φ` is the field isomorphism sending the SM4 generator to the root
// `0x23` of `0x1f5` in the AES field. Recovered numerically from the GB/T
// 32907 table; `affine_constants_match_derivation` recomputes them.

const SBOX_PRE: PlaneAffine = PlaneAffine::uniform(Affine {
    rows: [0x4c, 0x28, 0x7d, 0xb9, 0x1a, 0x22, 0x50, 0x5d],
    c: 0x3e,
});
const SBOX_POST: PlaneAffine = PlaneAffine::uniform(Affine {
    rows: [0x48, 0x0e, 0x4c, 0x47, 0x65, 0x1d, 0xba, 0xd3],
    c: 0x6c,
});

/// Nonlinear transform `τ` on every byte of `NW` words (two 32-bit values
/// per word), without table lookups.
#[inline]
fn tau<const NW: usize>(w: &mut [u64; NW]) {
    sbox_custom(w, &SBOX_PRE, &SBOX_POST);
}

/// `τ` on one 32-bit word (key schedule and the single-block path).
#[inline]
fn tau1(x: u32) -> u32 {
    let mut w = [u64::from(x)];
    tau(&mut w);
    w[0] as u32
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

/// Key-schedule composite `T' = L' ∘ τ`.
#[inline]
fn t_key(x: u32) -> u32 {
    l_key(tau1(x))
}

/// SM4 block cipher (GB/T 32907 / RFC 8998).
#[derive(Clone)]
pub struct Sm4 {
    /// The 32 round keys.
    rk: [u32; 32],
}

#[inline]
fn load(block: &[u8; 16]) -> [u32; 4] {
    core::array::from_fn(|i| {
        u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().expect("4 bytes"))
    })
}

/// Stores the reverse-order output transform `R`: `(Y0..Y3) = (X35..X32)`.
#[inline]
fn store(x: &[u32; 4], block: &mut [u8; 16]) {
    for (i, w) in x.iter().rev().enumerate() {
        block[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
    }
}

impl Sm4 {
    /// Creates an SM4 cipher from a 128-bit key, expanding the round keys
    /// (GB/T 32907 §7.3).
    pub fn new(key: &[u8; 16]) -> Self {
        let mut k = load(key);
        for (w, fk) in k.iter_mut().zip(FK) {
            *w ^= fk;
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
        // `k` is the running key state, seeded directly from the 128-bit key
        // (MK ^ FK) — recovering it recovers the key. `rk` itself lives in the
        // cipher, whose `Drop` zeroizes it.
        k.zeroize();
        Sm4 { rk }
    }

    /// Round key `round` in encryption or (public) reversed order.
    #[inline]
    fn key(&self, round: usize, reverse: bool) -> u32 {
        if reverse {
            self.rk[31 - round]
        } else {
            self.rk[round]
        }
    }

    /// Runs the 32-round network on one block.
    #[inline]
    fn crypt1(&self, block: &mut [u8; 16], reverse: bool) {
        let mut x = load(block);
        for round in 0..32 {
            let t = x[1] ^ x[2] ^ x[3] ^ self.key(round, reverse);
            let next = x[0] ^ l_round(tau1(t));
            x = [x[1], x[2], x[3], next];
        }
        store(&x, block);
        x.zeroize();
    }

    /// Runs the 32-round network on eight independent blocks in lockstep, so
    /// each round's `τ` fills the 32 lanes of the bitsliced circuit.
    fn crypt8(&self, blocks: &mut [[u8; 16]; 8], reverse: bool) {
        let mut x: [[u32; 4]; 8] = core::array::from_fn(|b| load(&blocks[b]));
        let mut w = [0u64; 4];
        for round in 0..32 {
            let rk = self.key(round, reverse);
            for (k, pair) in x.chunks_exact(2).enumerate() {
                let t0 = pair[0][1] ^ pair[0][2] ^ pair[0][3] ^ rk;
                let t1 = pair[1][1] ^ pair[1][2] ^ pair[1][3] ^ rk;
                w[k] = u64::from(t0) | (u64::from(t1) << 32);
            }
            tau(&mut w);
            for (b, xb) in x.iter_mut().enumerate() {
                let t = (w[b / 2] >> (32 * (b % 2))) as u32;
                let next = xb[0] ^ l_round(t);
                *xb = [xb[1], xb[2], xb[3], next];
            }
        }
        for (b, xb) in x.iter().enumerate() {
            store(xb, &mut blocks[b]);
        }
        x.zeroize();
        w.zeroize();
    }

    /// Processes whole blocks eight at a time; a short tail of two to seven
    /// blocks is padded to a batch (the padding lanes are discarded), a
    /// single trailing block takes the one-block path.
    fn crypt_blocks(&self, blocks: &mut [u8], reverse: bool) {
        let mut batches = blocks.chunks_exact_mut(128);
        let mut batch = [[0u8; 16]; 8];
        for chunk in &mut batches {
            for (b, src) in batch.iter_mut().zip(chunk.chunks_exact(16)) {
                b.copy_from_slice(src);
            }
            self.crypt8(&mut batch, reverse);
            for (b, dst) in batch.iter().zip(chunk.chunks_exact_mut(16)) {
                dst.copy_from_slice(b);
            }
        }
        let rest = batches.into_remainder();
        if rest.len() == 16 {
            self.crypt1(rest.try_into().expect("16 bytes"), reverse);
        } else if !rest.is_empty() {
            for (b, src) in batch.iter_mut().zip(rest.chunks_exact(16)) {
                b.copy_from_slice(src);
            }
            self.crypt8(&mut batch, reverse);
            for (b, dst) in batch.iter().zip(rest.chunks_exact_mut(16)) {
                dst.copy_from_slice(b);
            }
        }
        batch.zeroize();
    }
}

impl BlockCipher for Sm4 {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 16;

    #[inline]
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.crypt1(block, false);
    }

    #[inline]
    fn decrypt_block(&self, block: &mut [u8; 16]) {
        // Decryption is the same network with the round keys reversed.
        self.crypt1(block, true);
    }

    fn encrypt_blocks(&self, blocks: &mut [u8]) {
        assert!(
            blocks.len().is_multiple_of(16),
            "encrypt_blocks needs whole blocks"
        );
        self.crypt_blocks(blocks, false);
    }

    fn decrypt_blocks(&self, blocks: &mut [u8]) {
        assert!(
            blocks.len().is_multiple_of(16),
            "decrypt_blocks needs whole blocks"
        );
        self.crypt_blocks(blocks, true);
    }
}

impl Drop for Sm4 {
    fn drop(&mut self) {
        // Best-effort wipe of the round keys through `Zeroize` (volatile
        // stores plus a compiler fence), mirroring the AES round-key drop.
        self.rk.zeroize();
    }
}

impl ZeroizeOnDrop for Sm4 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::sbox_bitsliced::{derive, field_iso};
    use crate::test_util::from_hex;

    /// The SM4 S-box table (GB/T 32907 §6.2), kept here purely as the
    /// reference the computed constant-time S-box is checked against.
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

    // The computed constant-time S-box must agree with the GB/T 32907 table
    // for every input, in every lane, at every batch width.
    #[test]
    fn sbox_matches_reference_table() {
        for x in 0u32..=255 {
            // All four lanes carry the same byte …
            let same = tau1(u32::from_be_bytes([x as u8; 4]));
            assert_eq!(
                same.to_be_bytes(),
                [SBOX[x as usize]; 4],
                "S-box mismatch for {x:#04x}"
            );
            // … and lanes carrying distinct bytes stay independent.
            let b = [
                x as u8,
                (x as u8).wrapping_add(1),
                !(x as u8),
                (x as u8).rotate_left(3),
            ];
            let mixed = tau1(u32::from_be_bytes(b)).to_be_bytes();
            for i in 0..4 {
                assert_eq!(mixed[i], SBOX[b[i] as usize], "lane {i} for {x:#04x}");
            }
            // The full-width batch, every lane distinct.
            let mut w: [u64; 4] = core::array::from_fn(|k| {
                u64::from_le_bytes(core::array::from_fn(|j| x as u8 ^ (8 * k + j) as u8))
            });
            let orig = w;
            tau(&mut w);
            for (word, o) in w.iter().zip(orig.iter()) {
                for (y, i) in word.to_le_bytes().iter().zip(o.to_le_bytes()) {
                    assert_eq!(*y, SBOX[i as usize]);
                }
            }
        }
    }

    /// The hard-coded `(pre, post)` pair is what the GB/T table gives under
    /// `S = A ∘ inv₀ₓ₁f₅ ∘ A` with the field isomorphism into the AES field.
    #[test]
    fn affine_constants_match_derivation() {
        let phi = field_iso(0x1f5);
        let a = |x: u8| {
            x ^ x.rotate_left(1) ^ x.rotate_left(3) ^ x.rotate_left(6) ^ x.rotate_left(7) ^ 0xd3
        };
        let (pre, post) = derive(&SBOX, |x| phi.apply(a(x)));
        assert_eq!(PlaneAffine::uniform(pre), SBOX_PRE);
        assert_eq!(PlaneAffine::uniform(post), SBOX_POST);
    }

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

    /// The eight-block batch (and the padded short tail) must equal
    /// block-at-a-time processing for every block count up to two batches.
    #[test]
    fn batched_matches_single() {
        let cipher = Sm4::new(&[0x5au8; 16]);
        for nblocks in 1..=17 {
            let mut buf = alloc::vec![0u8; 16 * nblocks];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(197).wrapping_add(nblocks as u8);
            }
            let mut single = buf.clone();
            for blk in single.chunks_exact_mut(16) {
                cipher.encrypt_block(blk.try_into().unwrap());
            }
            let mut batched = buf.clone();
            cipher.encrypt_blocks(&mut batched);
            assert_eq!(batched, single, "{nblocks} blocks");
            cipher.decrypt_blocks(&mut batched);
            assert_eq!(batched, buf, "{nblocks} blocks");
        }
    }
}
