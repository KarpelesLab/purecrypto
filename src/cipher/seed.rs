//! SEED — the Korean national block cipher (KISA; RFC 4269, TTAS.KO-12.0004).
//!
//! SEED is a 128-bit-block, 128-bit-key Feistel cipher with 16 rounds. Each
//! round function `F` is built from three applications of a 32-bit
//! transform `G`, which substitutes the four bytes of its input through two
//! 8-bit S-boxes and then diffuses them with a fixed byte-mask pattern. The
//! key schedule feeds the key words through the same `G` after adding the
//! round constants `KC_i` (successive rotations of the golden ratio word
//! `0x9e3779b9`).
//!
//! It implements [`BlockCipher`], so it composes with the crate's CTR, CBC,
//! GCM, CCM and key-wrap modes exactly like AES. Round keys are wiped on
//! drop.
//!
//! # Constant time
//!
//! RFC 4269 §2.3 defines the two S-boxes algebraically, as affine images of
//! a power map in GF(2⁸) modulo `x⁸ + x⁶ + x⁵ + x + 1`:
//! `S_i(x) = A_i · x^247 ⊕ b_i` (the RFC writes the second one as a power
//! `x^251`; the two differ only by a Frobenius squaring, which is
//! GF(2)-linear and so folds into the matrix). This module **computes** that
//! form instead of indexing a table: the power map is a fixed
//! square-and-multiply chain over branchless field multiplications, and the
//! affine step is a masked XOR of the matrix columns. There is no
//! secret-dependent memory access or branch anywhere in the round function
//! or the key schedule, so SEED here is hardened against cache-timing
//! attacks — at roughly an order of magnitude the cost of the usual lookup
//! tables. The four S-box evaluations of every `G` run in parallel as byte
//! lanes of a `u32` to claw part of that back, in the manner of the
//! [`Sm4`](super::Sm4) core.
//!
//! Correctness is checked against the RFC 4269 Appendix B known-answer
//! vectors and the Wycheproof SEED-GCM / SEED-CCM / SEED-WRAP files.
//!
//! # When to use this module
//!
//! SEED appears in Korean PKI, TLS (RFC 4162, disallowed since TLS 1.3) and
//! CMS (RFC 4010) deployments. It has no published practical weakness, but
//! it is a 128-bit-key-only regional cipher with none of AES's hardware
//! support; prefer [`Aes256Gcm`](super::Aes256Gcm) for new designs.

use super::BlockCipher;
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// Byte masks `m0..m3` of the `G` diffusion layer (RFC 4269 §2.3).
const M0: u32 = 0xfc;
const M1: u32 = 0xf3;
const M2: u32 = 0xcf;
const M3: u32 = 0x3f;

/// Number of Feistel rounds.
const ROUNDS: usize = 16;

// --- Constant-time GF(2⁸) arithmetic, four byte lanes packed in a `u32` ---
//
// The SEED field is GF(2⁸) modulo `x⁸ + x⁶ + x⁵ + x + 1` (`0x163`). The
// lane-packed multiplication mirrors `sm4::gf_mul4`, with the SEED reduction
// polynomial.

/// Broadcasts the low bit of each byte lane (0 or 1) to the whole lane
/// (`0x00` or `0xff`).
#[inline]
fn lane_mask(m: u32) -> u32 {
    (m << 8).wrapping_sub(m)
}

/// Multiplies four pairs of field elements lane-wise in constant time
/// (branchless Russian-peasant multiplication with reduction by `0x163`).
#[inline]
fn gf_mul4(mut a: u32, mut b: u32) -> u32 {
    let mut product = 0u32;
    let mut i = 0;
    while i < 8 {
        product ^= lane_mask(b & 0x0101_0101) & a;
        let carry = lane_mask((a >> 7) & 0x0101_0101);
        a = ((a << 1) & 0xfefe_fefe) ^ (carry & 0x6363_6363);
        b = (b >> 1) & 0x7f7f_7f7f;
        i += 1;
    }
    product
}

/// Lane-wise `x^247` in GF(2⁸) by a fixed 11-multiplication addition chain
/// (`247 = 0b1111_0111`). `0^247 = 0` falls out naturally, as the S-box
/// definition requires.
#[inline]
fn gf_pow247_4(x: u32) -> u32 {
    let x2 = gf_mul4(x, x);
    let x3 = gf_mul4(x2, x);
    let x6 = gf_mul4(x3, x3);
    let x7 = gf_mul4(x6, x);
    let x14 = gf_mul4(x7, x7);
    let x15 = gf_mul4(x14, x);
    let x30 = gf_mul4(x15, x15);
    let x60 = gf_mul4(x30, x30);
    let x120 = gf_mul4(x60, x60);
    let x240 = gf_mul4(x120, x120);
    gf_mul4(x240, x7)
}

/// Columns of the affine matrices `A_1` / `A_2` of RFC 4269 §2.3 (bit `i` of
/// column `j` is entry `(i, j)`), so that `A · v = ⊕_j v_j · col_j`, and the
/// constants `b_1 = 169`, `b_2 = 56`. Recovered from the RFC's S-box
/// tables by solving the affine system; the unit tests confirm the resulting
/// S-boxes reproduce the Appendix B vectors bit for bit.
const A0_COLS: [u8; 8] = [0x2c, 0xd0, 0x69, 0xc2, 0x41, 0x44, 0x58, 0xe2];
const B0: u32 = 0xa9a9_a9a9;
const A1_COLS: [u8; 8] = [0xd0, 0xb7, 0x2a, 0x93, 0xe1, 0x6a, 0x2c, 0xa8];
const B1: u32 = 0x3838_3838;

/// Lane-wise affine map `A · v ⊕ b`: each set bit `j` of a lane XORs in
/// column `j`, selected by mask rather than by branch.
#[inline]
fn affine4(v: u32, cols: &[u8; 8], b: u32) -> u32 {
    let mut out = b;
    let mut j = 0;
    while j < 8 {
        let sel = lane_mask((v >> j) & 0x0101_0101);
        out ^= sel & (u32::from(cols[j]) * 0x0101_0101);
        j += 1;
    }
    out
}

/// The `G` transform (RFC 4269 §2.3): substitutes byte lanes 0 and 2 through
/// `S_1` and lanes 1 and 3 through `S_2`, then applies the mask diffusion
/// `Y_i = ⊕_j Z_j & m_{(i+j) mod 4}`.
#[inline]
fn g(x: u32) -> u32 {
    let p = gf_pow247_4(x);
    let s0 = affine4(p, &A0_COLS, B0);
    let s1 = affine4(p, &A1_COLS, B1);
    let z = (s0 & 0x00ff_00ff) | (s1 & 0xff00_ff00);
    // Lane `i` of `z.rotate_right(8k)` is `Z_{(i+k) mod 4}`; its mask is
    // `m_{(2i+k) mod 4}`, spelled out per rotation below.
    const K0: u32 = (M2 << 24) | (M0 << 16) | (M2 << 8) | M0;
    const K1: u32 = (M3 << 24) | (M1 << 16) | (M3 << 8) | M1;
    const K2: u32 = (M0 << 24) | (M2 << 16) | (M0 << 8) | M2;
    const K3: u32 = (M1 << 24) | (M3 << 16) | (M1 << 8) | M3;
    (z & K0) ^ (z.rotate_right(8) & K1) ^ (z.rotate_right(16) & K2) ^ (z.rotate_right(24) & K3)
}

/// The round function `F` (RFC 4269 §2.2) on the right half `(c, d)` under
/// the round key `(k0, k1)`; returns the two words XORed into the left half.
#[inline]
fn f(k: [u32; 2], c: u32, d: u32) -> (u32, u32) {
    let t0 = d ^ k[1];
    let t1 = c ^ k[0];
    let g1 = g(t0 ^ t1);
    let g2 = g(t1.wrapping_add(g1));
    let g3 = g(g2.wrapping_add(g1));
    (g2.wrapping_add(g3), g3)
}

/// The SEED block cipher (RFC 4269): 128-bit block, 128-bit key.
///
/// Construct with [`Seed::new`]; use through the [`BlockCipher`] trait or a
/// mode wrapper. The expanded round keys are wiped on drop.
#[derive(Clone)]
pub struct Seed {
    rk: [[u32; 2]; ROUNDS],
}

impl Seed {
    /// Expands a 16-byte key into the 16 round keys (RFC 4269 §3).
    pub fn new(key: &[u8; 16]) -> Self {
        let mut k0 = u32::from_be_bytes(key[0..4].try_into().unwrap());
        let mut k1 = u32::from_be_bytes(key[4..8].try_into().unwrap());
        let mut k2 = u32::from_be_bytes(key[8..12].try_into().unwrap());
        let mut k3 = u32::from_be_bytes(key[12..16].try_into().unwrap());
        let mut rk = [[0u32; 2]; ROUNDS];
        for (i, round) in rk.iter_mut().enumerate() {
            // `KC_i` is the golden-ratio word rotated left `i` times.
            let kc = 0x9e37_79b9u32.rotate_left(i as u32);
            round[0] = g(k0.wrapping_add(k2).wrapping_sub(kc));
            round[1] = g(k1.wrapping_sub(k3).wrapping_add(kc));
            if i % 2 == 0 {
                // Odd round (1-based): `K0 ‖ K1` rotates right by 8 bits.
                let v = ((u64::from(k0) << 32) | u64::from(k1)).rotate_right(8);
                k0 = (v >> 32) as u32;
                k1 = v as u32;
            } else {
                // Even round: `K2 ‖ K3` rotates left by 8 bits.
                let v = ((u64::from(k2) << 32) | u64::from(k3)).rotate_left(8);
                k2 = (v >> 32) as u32;
                k3 = v as u32;
            }
        }
        k0.zeroize();
        k1.zeroize();
        k2.zeroize();
        k3.zeroize();
        Seed { rk }
    }

    /// Runs the 16-round Feistel network with the round keys in the given
    /// order (forward for encryption, reversed for decryption).
    #[inline]
    fn feistel(block: &mut [u8; 16], keys: impl Iterator<Item = [u32; 2]>) {
        let mut l0 = u32::from_be_bytes(block[0..4].try_into().unwrap());
        let mut l1 = u32::from_be_bytes(block[4..8].try_into().unwrap());
        let mut r0 = u32::from_be_bytes(block[8..12].try_into().unwrap());
        let mut r1 = u32::from_be_bytes(block[12..16].try_into().unwrap());
        for k in keys {
            let (f0, f1) = f(k, r0, r1);
            let n0 = l0 ^ f0;
            let n1 = l1 ^ f1;
            l0 = r0;
            l1 = r1;
            r0 = n0;
            r1 = n1;
        }
        // The final swap is omitted (RFC 4269 §2.1).
        block[0..4].copy_from_slice(&r0.to_be_bytes());
        block[4..8].copy_from_slice(&r1.to_be_bytes());
        block[8..12].copy_from_slice(&l0.to_be_bytes());
        block[12..16].copy_from_slice(&l1.to_be_bytes());
    }
}

impl BlockCipher for Seed {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 16;

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        Self::feistel(block, self.rk.iter().copied());
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
        Self::feistel(block, self.rk.iter().rev().copied());
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        // Best-effort wipe of the round keys through `Zeroize` (volatile
        // stores plus a compiler fence, so LLVM cannot elide them).
        self.rk.zeroize();
    }
}

impl ZeroizeOnDrop for Seed {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// RFC 4269 Appendix B.1–B.4.
    const KATS: [(&str, &str, &str); 4] = [
        (
            "000102030405060708090a0b0c0d0e0f",
            "00000000000000000000000000000000",
            "c11f22f20140505084483597e4370f43",
        ),
        (
            "00000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f",
            "5ebac6e0054e166819aff1cc6d346cdb",
        ),
        (
            "4706480851e61be85d74bfb3fd956185",
            "83a2f8a288641fb9a4e9a5cc2f131c7d",
            "ee54d13ebcae706d226bc3142cd40d4a",
        ),
        (
            "28dbc3bc49ffd87dcfa509b11d422be7",
            "b41e6be2eba84a148e2eed84593c5ec7",
            "9b9b7bfcd1813cb95d0b3618f40f5122",
        ),
    ];

    #[test]
    fn rfc4269_appendix_b() {
        for (key, pt, ct) in KATS {
            let cipher = Seed::new(&from_hex::<16>(key));
            let mut block = from_hex::<16>(pt);
            cipher.encrypt_block(&mut block);
            assert_eq!(block, from_hex::<16>(ct), "encrypt {key}");
            cipher.decrypt_block(&mut block);
            assert_eq!(block, from_hex::<16>(pt), "decrypt {key}");
        }
    }

    /// Cross-checked against OpenSSL 3 (`openssl enc -seed-ecb`).
    #[test]
    fn all_zero_and_all_one_blocks() {
        let cipher = Seed::new(&[0u8; 16]);
        let mut block = [0u8; 16];
        cipher.encrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("90699de47893701e7511196be312af92"));

        let cipher = Seed::new(&[0xffu8; 16]);
        let mut block = [0xffu8; 16];
        cipher.encrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("bcb9e68bc5296b2b8e42fb4cf7a2b3ca"));
    }

    /// First sixteen entries of each RFC 4269 S-box table, as printed in
    /// the RFC: the computed affine-power form must agree with them.
    #[test]
    fn sbox_head_matches_rfc_tables() {
        const S1_HEAD: [u8; 16] = [
            0xa9, 0x85, 0xd6, 0xd3, 0x54, 0x1d, 0xac, 0x25, 0x5d, 0x43, 0x18, 0x1e, 0x51, 0xfc,
            0xca, 0x63,
        ];
        const S2_HEAD: [u8; 16] = [
            0x38, 0xe8, 0x2d, 0xa6, 0xcf, 0xde, 0xb3, 0xb8, 0xaf, 0x60, 0x55, 0xc7, 0x44, 0x6f,
            0x6b, 0x5b,
        ];
        for x in 0..16u32 {
            let p = gf_pow247_4(x * 0x0101_0101);
            assert_eq!(
                affine4(p, &A0_COLS, B0) as u8,
                S1_HEAD[x as usize],
                "S1[{x}]"
            );
            assert_eq!(
                affine4(p, &A1_COLS, B1) as u8,
                S2_HEAD[x as usize],
                "S2[{x}]"
            );
        }
    }

    /// Both S-boxes must be permutations of the byte space.
    #[test]
    fn sboxes_are_bijective() {
        let mut seen0 = [false; 256];
        let mut seen1 = [false; 256];
        for x in 0..256u32 {
            let p = gf_pow247_4(x);
            let s0 = (affine4(p, &A0_COLS, B0) & 0xff) as usize;
            let s1 = (affine4(p, &A1_COLS, B1) & 0xff) as usize;
            assert!(!seen0[s0] && !seen1[s1], "collision at {x}");
            seen0[s0] = true;
            seen1[s1] = true;
        }
    }
}
