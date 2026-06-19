//! Camellia (RFC 3713) block cipher, constant-time.
//!
//! Camellia is a 128-bit-block Feistel cipher with 128-, 192- and 256-bit
//! keys (18 rounds for 128-bit keys, 24 for the larger keys), with the
//! key-dependent `FL`/`FL⁻¹` linear layers inserted every six rounds. It
//! implements [`BlockCipher`], so it composes with the crate's CBC, CTR and
//! GCM modes exactly like AES. Subkeys are wiped on drop.
//!
//! Like the table-free AES core in this crate, the four Camellia S-boxes are
//! **computed** rather than looked up, so there are no secret-dependent memory
//! accesses and hence no cache-timing leak. The base S-box `SBOX1` is affine-
//! equivalent to the AES S-box:
//!
//! ```text
//! SBOX1(x) = Lb · AesSbox( La · x ⊕ 1 ) ⊕ 1
//! ```
//!
//! where `La` and `Lb` are fixed 8×8 GF(2) matrices and `AesSbox` is the
//! crate's table-free AES S-box (`affine ∘ inv` over GF(2⁸) with reduction
//! polynomial `0x11b`, reused from [`super::aes::gf`]). The equivalence was
//! recovered numerically and is verified against the RFC 3713 SBOX1 table for
//! every input in the unit tests. `SBOX2/3/4` are the RFC's bit rotations of
//! `SBOX1`. Every operation is branchless with no data-dependent indexing.

use super::BlockCipher;
use super::aes::gf::sub_byte;

// --- S-boxes, computed table-free via the AES S-box ------------------------

/// Applies an 8×8 GF(2) matrix (rows MSB-first) to `x`, MSB-first output.
#[inline]
fn bit_matrix(rows: &[u8; 8], x: u8) -> u8 {
    let mut out = 0u8;
    let mut bit = 0;
    while bit < 8 {
        let parity = (rows[bit] & x).count_ones() & 1;
        out |= (parity as u8) << (7 - bit);
        bit += 1;
    }
    out
}

/// Pre-affine matrix `La` (rows MSB-first), recovered from the affine
/// equivalence `SBOX1 = Lb · AesSbox(La·x ⊕ 1) ⊕ 1`.
const LA: [u8; 8] = [147, 55, 187, 58, 21, 15, 197, 43];
/// Post-affine matrix `Lb` (rows MSB-first).
const LB: [u8; 8] = [178, 17, 44, 193, 2, 238, 39, 204];

/// Camellia `SBOX1`, computed without a lookup table.
#[inline]
fn sbox1(x: u8) -> u8 {
    bit_matrix(&LB, sub_byte(bit_matrix(&LA, x) ^ 0x01)) ^ 0x01
}

/// Camellia `SBOX2(x) = SBOX1(x) <<< 1`.
#[inline]
fn sbox2(x: u8) -> u8 {
    sbox1(x).rotate_left(1)
}

/// Camellia `SBOX3(x) = SBOX1(x) >>> 1`.
#[inline]
fn sbox3(x: u8) -> u8 {
    sbox1(x).rotate_right(1)
}

/// Camellia `SBOX4(x) = SBOX1(x <<< 1)`.
#[inline]
fn sbox4(x: u8) -> u8 {
    sbox1(x.rotate_left(1))
}

// --- F, FL and FL⁻¹ functions (RFC 3713 §2.3) ------------------------------

/// The Feistel round function `F(x, k)` (RFC 3713 §2.3).
#[inline]
fn f(x: u64, k: u64) -> u64 {
    let v = x ^ k;
    let t = v.to_be_bytes();
    let t1 = sbox1(t[0]);
    let t2 = sbox2(t[1]);
    let t3 = sbox3(t[2]);
    let t4 = sbox4(t[3]);
    let t5 = sbox2(t[4]);
    let t6 = sbox3(t[5]);
    let t7 = sbox4(t[6]);
    let t8 = sbox1(t[7]);

    let y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
    let y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
    let y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
    let y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
    let y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
    let y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
    let y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
    let y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;
    u64::from_be_bytes([y1, y2, y3, y4, y5, y6, y7, y8])
}

/// The `FL` linear layer (RFC 3713 §2.3).
#[inline]
fn fl(x: u64, k: u64) -> u64 {
    let x1 = (x >> 32) as u32;
    let mut x2 = x as u32;
    let k1 = (k >> 32) as u32;
    let k2 = k as u32;
    x2 ^= (x1 & k1).rotate_left(1);
    let x1 = x1 ^ (x2 | k2);
    ((x1 as u64) << 32) | (x2 as u64)
}

/// The inverse layer `FL⁻¹` (RFC 3713 §2.3).
#[inline]
fn fl_inv(y: u64, k: u64) -> u64 {
    let mut y1 = (y >> 32) as u32;
    let y2 = y as u32;
    let k1 = (k >> 32) as u32;
    let k2 = k as u32;
    y1 ^= y2 | k2;
    let y2 = y2 ^ (y1 & k1).rotate_left(1);
    ((y1 as u64) << 32) | (y2 as u64)
}

// --- Key schedule (RFC 3713 §2.4) ------------------------------------------

/// Sigma constants (RFC 3713 §2.4).
const SIGMA: [u64; 6] = [
    0xA09E667F3BCC908B,
    0xB67AE8584CAA73B2,
    0xC6EF372FE94F82BE,
    0x54FF53A5F1D36F1C,
    0x10E527FADE682D1D,
    0xB05688C2B3E6C1FD,
];

/// Rotates a 128-bit value (hi, lo) left by `n` bits and returns the upper
/// 64 bits.
#[inline]
fn rotl_hi(hi: u64, lo: u64, n: u32) -> u64 {
    (u128::from(hi) << 64 | u128::from(lo))
        .rotate_left(n)
        .wrapping_shr(64) as u64
}

/// Rotates a 128-bit value (hi, lo) left by `n` bits and returns the lower
/// 64 bits.
#[inline]
fn rotl_lo(hi: u64, lo: u64, n: u32) -> u64 {
    (u128::from(hi) << 64 | u128::from(lo)).rotate_left(n) as u64
}

/// Computes `KA` and `KB` from `KL` and `KR` (RFC 3713 §2.4).
fn ka_kb(kl: (u64, u64), kr: (u64, u64)) -> ((u64, u64), (u64, u64)) {
    let mut d1 = kl.0 ^ kr.0;
    let mut d2 = kl.1 ^ kr.1;
    d2 ^= f(d1, SIGMA[0]);
    d1 ^= f(d2, SIGMA[1]);
    d1 ^= kl.0;
    d2 ^= kl.1;
    d2 ^= f(d1, SIGMA[2]);
    d1 ^= f(d2, SIGMA[3]);
    let ka = (d1, d2);

    let mut e1 = ka.0 ^ kr.0;
    let mut e2 = ka.1 ^ kr.1;
    e2 ^= f(e1, SIGMA[4]);
    e1 ^= f(e2, SIGMA[5]);
    let kb = (e1, e2);

    (ka, kb)
}

/// An assembled Camellia cipher: the whitening keys, the round keys `k`, and
/// the `FL`/`FL⁻¹` keys `ke`, all in encryption order. Decryption swaps the
/// schedule order, so it is built once per direction at construction.
#[derive(Clone)]
struct Schedule {
    kw: [u64; 4],
    /// Round keys: 18 for 128-bit keys, 24 otherwise.
    k: [u64; 24],
    /// `FL`/`FL⁻¹` keys: 4 for 128-bit keys, 6 otherwise.
    ke: [u64; 6],
    /// Number of rounds (18 or 24).
    rounds: usize,
}

impl Schedule {
    /// Builds the encryption schedule for a 128-bit key.
    fn new128(kl: (u64, u64)) -> Self {
        let kr = (0u64, 0u64);
        let (ka, _kb) = ka_kb(kl, kr);
        let kw = [
            rotl_hi(kl.0, kl.1, 0),
            rotl_lo(kl.0, kl.1, 0),
            rotl_hi(ka.0, ka.1, 111),
            rotl_lo(ka.0, ka.1, 111),
        ];
        let k = [
            rotl_hi(ka.0, ka.1, 0),   // k1
            rotl_lo(ka.0, ka.1, 0),   // k2
            rotl_hi(kl.0, kl.1, 15),  // k3
            rotl_lo(kl.0, kl.1, 15),  // k4
            rotl_hi(ka.0, ka.1, 15),  // k5
            rotl_lo(ka.0, ka.1, 15),  // k6
            rotl_hi(kl.0, kl.1, 45),  // k7
            rotl_lo(kl.0, kl.1, 45),  // k8
            rotl_hi(ka.0, ka.1, 45),  // k9
            rotl_lo(kl.0, kl.1, 60),  // k10
            rotl_hi(ka.0, ka.1, 60),  // k11
            rotl_lo(ka.0, ka.1, 60),  // k12
            rotl_hi(kl.0, kl.1, 94),  // k13
            rotl_lo(kl.0, kl.1, 94),  // k14
            rotl_hi(ka.0, ka.1, 94),  // k15
            rotl_lo(ka.0, ka.1, 94),  // k16
            rotl_hi(kl.0, kl.1, 111), // k17
            rotl_lo(kl.0, kl.1, 111), // k18
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let ke = [
            rotl_hi(ka.0, ka.1, 30), // ke1
            rotl_lo(ka.0, ka.1, 30), // ke2
            rotl_hi(kl.0, kl.1, 77), // ke3
            rotl_lo(kl.0, kl.1, 77), // ke4
            0,
            0,
        ];
        Schedule {
            kw,
            k,
            ke,
            rounds: 18,
        }
    }

    /// Builds the encryption schedule for a 192- or 256-bit key.
    fn new256(kl: (u64, u64), kr: (u64, u64)) -> Self {
        let (ka, kb) = ka_kb(kl, kr);
        let kw = [
            rotl_hi(kl.0, kl.1, 0),
            rotl_lo(kl.0, kl.1, 0),
            rotl_hi(kb.0, kb.1, 111),
            rotl_lo(kb.0, kb.1, 111),
        ];
        let k = [
            rotl_hi(kb.0, kb.1, 0),   // k1
            rotl_lo(kb.0, kb.1, 0),   // k2
            rotl_hi(kr.0, kr.1, 15),  // k3
            rotl_lo(kr.0, kr.1, 15),  // k4
            rotl_hi(ka.0, ka.1, 15),  // k5
            rotl_lo(ka.0, ka.1, 15),  // k6
            rotl_hi(kb.0, kb.1, 30),  // k7
            rotl_lo(kb.0, kb.1, 30),  // k8
            rotl_hi(kl.0, kl.1, 45),  // k9
            rotl_lo(kl.0, kl.1, 45),  // k10
            rotl_hi(ka.0, ka.1, 45),  // k11
            rotl_lo(ka.0, ka.1, 45),  // k12
            rotl_hi(kr.0, kr.1, 60),  // k13
            rotl_lo(kr.0, kr.1, 60),  // k14
            rotl_hi(kb.0, kb.1, 60),  // k15
            rotl_lo(kb.0, kb.1, 60),  // k16
            rotl_hi(kl.0, kl.1, 77),  // k17
            rotl_lo(kl.0, kl.1, 77),  // k18
            rotl_hi(kr.0, kr.1, 94),  // k19
            rotl_lo(kr.0, kr.1, 94),  // k20
            rotl_hi(ka.0, ka.1, 94),  // k21
            rotl_lo(ka.0, ka.1, 94),  // k22
            rotl_hi(kl.0, kl.1, 111), // k23
            rotl_lo(kl.0, kl.1, 111), // k24
        ];
        let ke = [
            rotl_hi(kr.0, kr.1, 30), // ke1
            rotl_lo(kr.0, kr.1, 30), // ke2
            rotl_hi(kl.0, kl.1, 60), // ke3
            rotl_lo(kl.0, kl.1, 60), // ke4
            rotl_hi(ka.0, ka.1, 77), // ke5
            rotl_lo(ka.0, ka.1, 77), // ke6
        ];
        Schedule {
            kw,
            k,
            ke,
            rounds: 24,
        }
    }

    /// Builds the decryption schedule by reversing the encryption schedule
    /// (RFC 3713 §2.2): swap `kw1↔kw3`, `kw2↔kw4`, reverse the round keys, and
    /// reverse-and-pair the `ke` keys.
    fn invert(&self) -> Self {
        let r = self.rounds;
        let kw = [self.kw[2], self.kw[3], self.kw[0], self.kw[1]];
        let mut k = [0u64; 24];
        for (i, dst) in k.iter_mut().enumerate().take(r) {
            *dst = self.k[r - 1 - i];
        }
        // ke layers: encryption uses (ke1,ke2),(ke3,ke4),[ (ke5,ke6) ]; for
        // decryption they are applied in reverse group order with the pair
        // halves preserved.
        let ne = if r == 18 { 4 } else { 6 };
        let mut ke = [0u64; 6];
        for (i, dst) in ke.iter_mut().enumerate().take(ne) {
            *dst = self.ke[ne - 1 - i];
        }
        Schedule {
            kw,
            k,
            ke,
            rounds: r,
        }
    }

    /// Runs the Feistel network on a 128-bit block split as `(d1, d2)`.
    #[inline]
    fn crypt(&self, mut d1: u64, mut d2: u64) -> (u64, u64) {
        d1 ^= self.kw[0];
        d2 ^= self.kw[1];

        let groups = self.rounds / 6; // 3 or 4
        let mut round = 0;
        for g in 0..groups {
            // Six Feistel rounds.
            for _ in 0..6 {
                d2 ^= f(d1, self.k[round]);
                round += 1;
                core::mem::swap(&mut d1, &mut d2);
            }
            // After each group except the last, an FL / FL⁻¹ layer.
            if g != groups - 1 {
                d1 = fl(d1, self.ke[2 * g]);
                d2 = fl_inv(d2, self.ke[2 * g + 1]);
            }
        }
        // The last swap above is undone by the final-output swap convention:
        // after the loop d1/d2 are already in the post-swap order, so apply
        // post-whitening with the halves exchanged (RFC 3713 §2.2).
        d2 ^= self.kw[2];
        d1 ^= self.kw[3];
        (d2, d1)
    }
}

macro_rules! camellia_variant {
    ($(#[$meta:meta])* $name:ident, $key_bytes:expr, $build:expr) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            enc: Schedule,
            dec: Schedule,
        }

        impl $name {
            /// Creates the cipher from its key, expanding the subkeys.
            pub fn new(key: &[u8; $key_bytes]) -> Self {
                let build: fn(&[u8; $key_bytes]) -> Schedule = $build;
                let enc = build(key);
                let dec = enc.invert();
                $name { enc, dec }
            }
        }

        impl BlockCipher for $name {
            const BLOCK_SIZE: usize = 16;
            const KEY_SIZE: usize = $key_bytes;

            #[inline]
            fn encrypt_block(&self, block: &mut [u8; 16]) {
                let d1 = u64::from_be_bytes(block[..8].try_into().unwrap());
                let d2 = u64::from_be_bytes(block[8..].try_into().unwrap());
                let (c1, c2) = self.enc.crypt(d1, d2);
                block[..8].copy_from_slice(&c1.to_be_bytes());
                block[8..].copy_from_slice(&c2.to_be_bytes());
            }

            #[inline]
            fn decrypt_block(&self, block: &mut [u8; 16]) {
                let d1 = u64::from_be_bytes(block[..8].try_into().unwrap());
                let d2 = u64::from_be_bytes(block[8..].try_into().unwrap());
                let (c1, c2) = self.dec.crypt(d1, d2);
                block[..8].copy_from_slice(&c1.to_be_bytes());
                block[8..].copy_from_slice(&c2.to_be_bytes());
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                for s in [&mut self.enc, &mut self.dec] {
                    s.kw = [0u64; 4];
                    s.k = [0u64; 24];
                    s.ke = [0u64; 6];
                }
                core::hint::black_box(&self.enc.k);
                core::hint::black_box(&self.dec.k);
            }
        }
    };
}

camellia_variant!(
    /// Camellia with a 128-bit key (18 rounds).
    Camellia128,
    16,
    |key: &[u8; 16]| {
        let kl = (
            u64::from_be_bytes(key[..8].try_into().unwrap()),
            u64::from_be_bytes(key[8..16].try_into().unwrap()),
        );
        Schedule::new128(kl)
    }
);

camellia_variant!(
    /// Camellia with a 192-bit key (24 rounds).
    Camellia192,
    24,
    |key: &[u8; 24]| {
        let kl = (
            u64::from_be_bytes(key[..8].try_into().unwrap()),
            u64::from_be_bytes(key[8..16].try_into().unwrap()),
        );
        // KR = KR_high(64) || ~KR_high, with KR_high = key[16..24].
        let krh = u64::from_be_bytes(key[16..24].try_into().unwrap());
        let kr = (krh, !krh);
        Schedule::new256(kl, kr)
    }
);

camellia_variant!(
    /// Camellia with a 256-bit key (24 rounds).
    Camellia256,
    32,
    |key: &[u8; 32]| {
        let kl = (
            u64::from_be_bytes(key[..8].try_into().unwrap()),
            u64::from_be_bytes(key[8..16].try_into().unwrap()),
        );
        let kr = (
            u64::from_be_bytes(key[16..24].try_into().unwrap()),
            u64::from_be_bytes(key[24..32].try_into().unwrap()),
        );
        Schedule::new256(kl, kr)
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// RFC 3713 SBOX1 reference table.
    #[rustfmt::skip]
    const SBOX1_REF: [u8; 256] = [
        112,130, 44,236,179, 39,192,229,228,133, 87, 53,234, 12,174, 65,
         35,239,107,147, 69, 25,165, 33,237, 14, 79, 78, 29,101,146,189,
        134,184,175,143,124,235, 31,206, 62, 48,220, 95, 94,197, 11, 26,
        166,225, 57,202,213, 71, 93, 61,217,  1, 90,214, 81, 86,108, 77,
        139, 13,154,102,251,204,176, 45,116, 18, 43, 32,240,177,132,153,
        223, 76,203,194, 52,126,118,  5,109,183,169, 49,209, 23,  4,215,
         20, 88, 58, 97,222, 27, 17, 28, 50, 15,156, 22, 83, 24,242, 34,
        254, 68,207,178,195,181,122,145, 36,  8,232,168, 96,252,105, 80,
        170,208,160,125,161,137, 98,151, 84, 91, 30,149,224,255,100,210,
         16,196,  0, 72,163,247,117,219,138,  3,230,218,  9, 63,221,148,
        135, 92,131,  2,205, 74,144, 51,115,103,246,243,157,127,191,226,
         82,155,216, 38,200, 55,198, 59,129,150,111, 75, 19,190, 99, 46,
        233,121,167,140,159,110,188,142, 41,245,249,182, 47,253,180, 89,
        120,152,  6,106,231, 70,113,186,212, 37,171, 66,136,162,141,250,
        114,  7,185, 85,248,238,172, 10, 54, 73, 42,104, 60, 56,241,164,
         64, 40,211,123,187,201, 67,193, 21,227,173,244,119,199,128,158,
    ];

    #[test]
    fn sbox1_matches_reference_table() {
        for x in 0u16..=255 {
            assert_eq!(sbox1(x as u8), SBOX1_REF[x as usize], "SBOX1 at {x:#04x}");
        }
    }

    #[test]
    fn fl_round_trips() {
        for seed in 0u64..256 {
            let x = seed
                .wrapping_mul(0x9e3779b97f4a7c15)
                .rotate_left((seed % 63) as u32);
            let k = x ^ 0xdead_beef_cafe_babe;
            assert_eq!(fl_inv(fl(x, k), k), x);
        }
    }

    // RFC 3713 Appendix: 128-bit key test vector.
    #[test]
    fn rfc3713_camellia128() {
        let key = from_hex::<16>("0123456789abcdeffedcba9876543210");
        let pt = from_hex::<16>("0123456789abcdeffedcba9876543210");
        let ct = from_hex::<16>("67673138549669730857065648eabe43");
        let cipher = Camellia128::new(&key);
        let mut b = pt;
        cipher.encrypt_block(&mut b);
        assert_eq!(b, ct, "encrypt");
        cipher.decrypt_block(&mut b);
        assert_eq!(b, pt, "decrypt");
    }

    // RFC 3713 Appendix: 192-bit key test vector.
    #[test]
    fn rfc3713_camellia192() {
        let key = from_hex::<24>("0123456789abcdeffedcba98765432100011223344556677");
        let pt = from_hex::<16>("0123456789abcdeffedcba9876543210");
        let ct = from_hex::<16>("b4993401b3e996f84ee5cee7d79b09b9");
        let cipher = Camellia192::new(&key);
        let mut b = pt;
        cipher.encrypt_block(&mut b);
        assert_eq!(b, ct, "encrypt");
        cipher.decrypt_block(&mut b);
        assert_eq!(b, pt, "decrypt");
    }

    // RFC 3713 Appendix: 256-bit key test vector.
    #[test]
    fn rfc3713_camellia256() {
        let key =
            from_hex::<32>("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
        let pt = from_hex::<16>("0123456789abcdeffedcba9876543210");
        let ct = from_hex::<16>("9acc237dff16d76c20ef7c919e3a7509");
        let cipher = Camellia256::new(&key);
        let mut b = pt;
        cipher.encrypt_block(&mut b);
        assert_eq!(b, ct, "encrypt");
        cipher.decrypt_block(&mut b);
        assert_eq!(b, pt, "decrypt");
    }

    #[test]
    fn roundtrip_random_blocks() {
        let key = from_hex::<16>("0f0e0d0c0b0a09080706050403020100");
        let cipher = Camellia128::new(&key);
        let mut state = 0x0123_4567_89ab_cdefu64;
        for _ in 0..512 {
            let mut b = [0u8; 16];
            for chunk in b.chunks_mut(8) {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            let orig = b;
            cipher.encrypt_block(&mut b);
            assert_ne!(b, orig);
            cipher.decrypt_block(&mut b);
            assert_eq!(b, orig);
        }
    }
}
