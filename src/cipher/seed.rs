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
//! GF(2)-linear and so folds into the matrix). Since `x²⁴⁷ = (x⁻¹)⁸`, each
//! S-box is the field inverse followed by three Frobenius squarings and the
//! affine `A_i` — all linear — and that field is isomorphic to the AES
//! field. This module therefore **computes** both S-boxes with the
//! bitsliced AES circuit ([`super::sbox_bitsliced`]), the isomorphism and
//! the linear layers folded into the affine maps around it, instead of
//! indexing a table. There is no secret-dependent memory access or branch
//! anywhere in the round function or the key schedule, so SEED here is
//! hardened against cache-timing attacks. The circuit substitutes 32 bytes
//! at once, so [`BlockCipher::encrypt_blocks`] runs eight blocks in lockstep
//! to fill it.
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
use super::sbox_bitsliced::{Affine, PlaneAffine, sbox_custom};
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// Byte masks `m0..m3` of the `G` diffusion layer (RFC 4269 §2.3).
const M0: u32 = 0xfc;
const M1: u32 = 0xf3;
const M2: u32 = 0xcf;
const M3: u32 = 0x3f;

/// Number of Feistel rounds.
const ROUNDS: usize = 16;

// --- The S-boxes as affine conjugates of the AES S-box ----------------------
//
// `S_i = post_i ∘ S_aes ∘ pre` with `pre = φ`, the isomorphism sending the
// SEED generator to the root `0x19` of `0x163` in the AES field, and
// `post_i = A_i ∘ Frob³ ∘ φ⁻¹ ∘ A_aes⁻¹ (⊕ b_i)`. Recovered numerically from
// the RFC 4269 definition; `affine_constants_match_derivation` recomputes
// them.

const PRE: Affine = Affine {
    rows: [0x0b, 0xcc, 0xb0, 0x2e, 0x16, 0x18, 0x3c, 0x70],
    c: 0x00,
};
const POST_S1: Affine = Affine {
    rows: [0x74, 0xd4, 0x53, 0xf5, 0x5d, 0x6b, 0x71, 0xca],
    c: 0xe7,
};
const POST_S2: Affine = Affine {
    rows: [0x0a, 0xf2, 0x5d, 0x7b, 0xc8, 0x78, 0x4e, 0x08],
    c: 0x2b,
};

/// Lane `l` of a word holds byte `l % 4` of a 32-bit value: even lanes go
/// through `S_1`, odd lanes through `S_2`.
const fn parity() -> [u8; 32] {
    let mut p = [0u8; 32];
    let mut l = 0;
    while l < 32 {
        p[l] = (l % 2) as u8;
        l += 1;
    }
    p
}
const SBOX_PRE: PlaneAffine = PlaneAffine::uniform(PRE);
const SBOX_POST: PlaneAffine = PlaneAffine::per_lane(&[POST_S1, POST_S2], &parity());

/// The `G` transform (RFC 4269 §2.3) on `2·NW` 32-bit values packed two per
/// word: substitutes byte lanes 0 and 2 through `S_1` and lanes 1 and 3
/// through `S_2`, then applies the mask diffusion
/// `Y_i = ⊕_j Z_j & m_{(i+j) mod 4}`.
#[inline]
fn g<const NW: usize>(w: &mut [u64; NW]) {
    sbox_custom(w, &SBOX_PRE, &SBOX_POST);
    // Lane `i` of `z.rotate_right(8k)` is `Z_{(i+k) mod 4}`; its mask is
    // `m_{(2i+k) mod 4}`, spelled out per rotation below.
    const K0: u32 = (M2 << 24) | (M0 << 16) | (M2 << 8) | M0;
    const K1: u32 = (M3 << 24) | (M1 << 16) | (M3 << 8) | M1;
    const K2: u32 = (M0 << 24) | (M2 << 16) | (M0 << 8) | M2;
    const K3: u32 = (M1 << 24) | (M3 << 16) | (M1 << 8) | M3;
    let diffuse = |z: u32| {
        (z & K0) ^ (z.rotate_right(8) & K1) ^ (z.rotate_right(16) & K2) ^ (z.rotate_right(24) & K3)
    };
    for x in w.iter_mut() {
        let lo = diffuse(*x as u32);
        let hi = diffuse((*x >> 32) as u32);
        *x = u64::from(lo) | (u64::from(hi) << 32);
    }
}

/// `G` on one 32-bit value (key schedule and the single-block path).
#[inline]
fn g1(x: u32) -> u32 {
    let mut w = [u64::from(x)];
    g(&mut w);
    w[0] as u32
}

/// `G` on eight 32-bit values (the eight-block batch).
#[inline]
fn g8(x: [u32; 8]) -> [u32; 8] {
    let mut w: [u64; 4] =
        core::array::from_fn(|k| u64::from(x[2 * k]) | (u64::from(x[2 * k + 1]) << 32));
    g(&mut w);
    core::array::from_fn(|b| (w[b / 2] >> (32 * (b % 2))) as u32)
}

/// The round function `F` (RFC 4269 §2.2) on the right half `(c, d)` under
/// the round key `(k0, k1)`; returns the two words XORed into the left half.
#[inline]
fn f(k: [u32; 2], c: u32, d: u32) -> (u32, u32) {
    let t0 = d ^ k[1];
    let t1 = c ^ k[0];
    let g1_ = g1(t0 ^ t1);
    let g2 = g1(t1.wrapping_add(g1_));
    let g3 = g1(g2.wrapping_add(g1_));
    (g2.wrapping_add(g3), g3)
}

/// `F` on the right halves of eight blocks in lockstep.
#[inline]
fn f8(k: [u32; 2], c: &[u32; 8], d: &[u32; 8]) -> ([u32; 8], [u32; 8]) {
    let t1: [u32; 8] = core::array::from_fn(|b| c[b] ^ k[0]);
    let ga = g8(core::array::from_fn(|b| d[b] ^ k[1] ^ t1[b]));
    let gb = g8(core::array::from_fn(|b| t1[b].wrapping_add(ga[b])));
    let gc = g8(core::array::from_fn(|b| gb[b].wrapping_add(ga[b])));
    (core::array::from_fn(|b| gb[b].wrapping_add(gc[b])), gc)
}

/// The SEED block cipher (RFC 4269): 128-bit block, 128-bit key.
///
/// Construct with [`Seed::new`]; use through the [`BlockCipher`] trait or a
/// mode wrapper. The expanded round keys are wiped on drop.
#[derive(Clone)]
pub struct Seed {
    rk: [[u32; 2]; ROUNDS],
}

#[inline]
fn load(block: &[u8; 16]) -> [u32; 4] {
    core::array::from_fn(|i| {
        u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().expect("4 bytes"))
    })
}

#[inline]
fn store(x: &[u32; 4], block: &mut [u8; 16]) {
    for (i, w) in x.iter().enumerate() {
        block[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
    }
}

impl Seed {
    /// Expands a 16-byte key into the 16 round keys (RFC 4269 §3).
    pub fn new(key: &[u8; 16]) -> Self {
        let [mut k0, mut k1, mut k2, mut k3] = load(key);
        let mut rk = [[0u32; 2]; ROUNDS];
        for (i, round) in rk.iter_mut().enumerate() {
            // `KC_i` is the golden-ratio word rotated left `i` times.
            let kc = 0x9e37_79b9u32.rotate_left(i as u32);
            round[0] = g1(k0.wrapping_add(k2).wrapping_sub(kc));
            round[1] = g1(k1.wrapping_sub(k3).wrapping_add(kc));
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

    /// Round key `round` in encryption or (public) reversed order.
    #[inline]
    fn key(&self, round: usize, reverse: bool) -> [u32; 2] {
        if reverse {
            self.rk[ROUNDS - 1 - round]
        } else {
            self.rk[round]
        }
    }

    /// Runs the 16-round Feistel network on one block.
    #[inline]
    fn crypt1(&self, block: &mut [u8; 16], reverse: bool) {
        let [mut l0, mut l1, mut r0, mut r1] = load(block);
        for round in 0..ROUNDS {
            let (f0, f1) = f(self.key(round, reverse), r0, r1);
            let n0 = l0 ^ f0;
            let n1 = l1 ^ f1;
            l0 = r0;
            l1 = r1;
            r0 = n0;
            r1 = n1;
        }
        // The final swap is omitted (RFC 4269 §2.1).
        store(&[r0, r1, l0, l1], block);
    }

    /// Runs the Feistel network on eight independent blocks in lockstep, so
    /// each `G` fills the 32 lanes of the bitsliced circuit.
    fn crypt8(&self, blocks: &mut [[u8; 16]; 8], reverse: bool) {
        let x: [[u32; 4]; 8] = core::array::from_fn(|b| load(&blocks[b]));
        let mut l0: [u32; 8] = core::array::from_fn(|b| x[b][0]);
        let mut l1: [u32; 8] = core::array::from_fn(|b| x[b][1]);
        let mut r0: [u32; 8] = core::array::from_fn(|b| x[b][2]);
        let mut r1: [u32; 8] = core::array::from_fn(|b| x[b][3]);
        for round in 0..ROUNDS {
            let (f0, f1) = f8(self.key(round, reverse), &r0, &r1);
            for b in 0..8 {
                let n0 = l0[b] ^ f0[b];
                let n1 = l1[b] ^ f1[b];
                l0[b] = r0[b];
                l1[b] = r1[b];
                r0[b] = n0;
                r1[b] = n1;
            }
        }
        for (b, blk) in blocks.iter_mut().enumerate() {
            store(&[r0[b], r1[b], l0[b], l1[b]], blk);
        }
        for v in [&mut l0, &mut l1, &mut r0, &mut r1] {
            v.zeroize();
        }
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

impl BlockCipher for Seed {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 16;

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.crypt1(block, false);
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
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
    use crate::cipher::aes::gf::gf_mul;
    use crate::cipher::sbox_bitsliced::{derive, field_iso};
    use crate::test_util::from_hex;

    /// Reference S-boxes straight from the RFC 4269 §2.3 definition:
    /// `S_i(x) = A_i · x^247 ⊕ b_i` over GF(2⁸)/`0x163`, with the matrices
    /// given by columns (recovered from the RFC's tables; the first sixteen
    /// entries of each are checked against the RFC's printed table below).
    fn reference_sboxes() -> ([u8; 256], [u8; 256]) {
        const A0_COLS: [u8; 8] = [0x2c, 0xd0, 0x69, 0xc2, 0x41, 0x44, 0x58, 0xe2];
        const A1_COLS: [u8; 8] = [0xd0, 0xb7, 0x2a, 0x93, 0xe1, 0x6a, 0x2c, 0xa8];
        fn mul163(mut a: u8, mut b: u8) -> u8 {
            let mut p = 0u8;
            for _ in 0..8 {
                if b & 1 == 1 {
                    p ^= a;
                }
                let hi = a & 0x80;
                a <<= 1;
                if hi != 0 {
                    a ^= 0x63;
                }
                b >>= 1;
            }
            p
        }
        let affine = |cols: &[u8; 8], b: u8, v: u8| {
            (0..8).fold(b, |acc, j| {
                if (v >> j) & 1 == 1 {
                    acc ^ cols[j]
                } else {
                    acc
                }
            })
        };
        let mut s1 = [0u8; 256];
        let mut s2 = [0u8; 256];
        for x in 0..=255u8 {
            // x^247 by square-and-multiply.
            let mut p = 1u8;
            let mut base = x;
            let mut e = 247u32;
            while e > 0 {
                if e & 1 == 1 {
                    p = mul163(p, base);
                }
                base = mul163(base, base);
                e >>= 1;
            }
            s1[x as usize] = affine(&A0_COLS, 0xa9, p);
            s2[x as usize] = affine(&A1_COLS, 0x38, p);
        }
        (s1, s2)
    }

    /// Evaluates the S-box of lane `lane` (`S_1` for even lanes, `S_2` for
    /// odd) on one byte through the bitsliced substitution `G` uses.
    fn sbox_via_g(lane: usize, x: u8) -> u8 {
        let mut w = [u64::from(x) << (8 * lane)];
        sbox_custom(&mut w, &SBOX_PRE, &SBOX_POST);
        (w[0] >> (8 * lane)) as u8
    }

    /// First sixteen entries of each RFC 4269 S-box table, as printed in
    /// the RFC: the reference form and the bitsliced form must agree with
    /// them, and the two must agree everywhere.
    #[test]
    fn sboxes_match_rfc_tables() {
        const S1_HEAD: [u8; 16] = [
            0xa9, 0x85, 0xd6, 0xd3, 0x54, 0x1d, 0xac, 0x25, 0x5d, 0x43, 0x18, 0x1e, 0x51, 0xfc,
            0xca, 0x63,
        ];
        const S2_HEAD: [u8; 16] = [
            0x38, 0xe8, 0x2d, 0xa6, 0xcf, 0xde, 0xb3, 0xb8, 0xaf, 0x60, 0x55, 0xc7, 0x44, 0x6f,
            0x6b, 0x5b,
        ];
        let (s1, s2) = reference_sboxes();
        assert_eq!(&s1[..16], &S1_HEAD);
        assert_eq!(&s2[..16], &S2_HEAD);
        for x in 0..=255u8 {
            for lane in [0, 2] {
                assert_eq!(
                    sbox_via_g(lane, x),
                    s1[x as usize],
                    "S1 lane {lane} at {x:#04x}"
                );
            }
            for lane in [1, 3] {
                assert_eq!(
                    sbox_via_g(lane, x),
                    s2[x as usize],
                    "S2 lane {lane} at {x:#04x}"
                );
            }
        }
    }

    /// The hard-coded `(pre, post)` pairs are what the RFC definition gives
    /// under `x^247 = (x^-1)^8` with the field isomorphism into the AES
    /// field; `gf_mul` is only used to confirm the isomorphism's root.
    #[test]
    fn affine_constants_match_derivation() {
        let phi = field_iso(0x163);
        // φ(x) is a root of 0x163 in the AES field: φ(α)⁸ ⊕ φ(α)⁶ ⊕ φ(α)⁵ ⊕
        // φ(α) ⊕ 1 = 0, with φ(α) = φ(0x02).
        let beta = phi.apply(0x02);
        let pow = |e: u32| (0..e).fold(1u8, |acc, _| gf_mul(acc, beta));
        assert_eq!(pow(8) ^ pow(6) ^ pow(5) ^ pow(1) ^ 1, 0);
        let (s1, s2) = reference_sboxes();
        let (pre1, post1) = derive(&s1, |x| phi.apply(x));
        let (pre2, post2) = derive(&s2, |x| phi.apply(x));
        assert_eq!(pre1, PRE);
        assert_eq!(pre2, PRE);
        assert_eq!(post1, POST_S1);
        assert_eq!(post2, POST_S2);
    }

    /// Both S-boxes must be permutations of the byte space.
    #[test]
    fn sboxes_are_bijective() {
        let mut seen0 = [false; 256];
        let mut seen1 = [false; 256];
        for x in 0..=255u8 {
            let s0 = sbox_via_g(0, x) as usize;
            let s1 = sbox_via_g(1, x) as usize;
            assert!(!seen0[s0] && !seen1[s1], "collision at {x}");
            seen0[s0] = true;
            seen1[s1] = true;
        }
    }

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

    /// The eight-block batch (and the padded short tail) must equal
    /// block-at-a-time processing for every block count up to two batches.
    #[test]
    fn batched_matches_single() {
        let cipher = Seed::new(&[0x5au8; 16]);
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
