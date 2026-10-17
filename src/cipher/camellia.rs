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
//! where `La` and `Lb` are fixed 8×8 GF(2) matrices, and `SBOX2/3/4` are the
//! RFC's bit rotations of `SBOX1` (which fold into the affine maps). The
//! eight S-box applications of the round function `F` therefore run as one
//! pass of the bitsliced AES circuit ([`super::sbox_bitsliced`]) with the
//! per-position maps applied on the bit-planes — and the circuit has room
//! for four blocks' worth, so [`BlockCipher::encrypt_blocks`] runs four
//! blocks in lockstep. The equivalence was recovered numerically and is
//! verified against the RFC 3713 SBOX1 table for every input in the unit
//! tests. Every operation is branchless with no data-dependent indexing.

use super::BlockCipher;
use super::sbox_bitsliced::{Affine, PlaneAffine, sbox_custom};
use crate::zeroize::Zeroize;

// --- S-boxes as (pre, post) affine conjugates of the AES S-box -------------
//
// `SBOXn = post_n ∘ S_aes ∘ pre_n`, with `post` applied to the raw AES S-box
// output. `SBOX2 = SBOX1 <<< 1` and `SBOX3 = SBOX1 >>> 1` rotate the post
// map, `SBOX4(x) = SBOX1(x <<< 1)` rotates the pre map. Recovered from the
// RFC 3713 table; `affine_constants_match_derivation` recomputes them.

/// `La · x ⊕ 1` (SBOX1, SBOX2, SBOX3).
const PRE_S123: Affine = Affine {
    rows: [0x2b, 0xc5, 0x0f, 0x15, 0x3a, 0xbb, 0x37, 0x93],
    c: 0x01,
};
/// `La · (x <<< 1) ⊕ 1` (SBOX4).
const PRE_S4: Affine = Affine {
    rows: [0x95, 0xe2, 0x87, 0x8a, 0x1d, 0xdd, 0x9b, 0xc9],
    c: 0x01,
};
/// `Lb · A_aes⁻¹(y) ⊕ 1` (SBOX1, SBOX4).
const POST_S14: Affine = Affine {
    rows: [0xcc, 0x27, 0xee, 0x02, 0xc1, 0x2c, 0x11, 0xb2],
    c: 0x01,
};
/// SBOX2: the SBOX1 map rotated left one bit.
const POST_S2: Affine = Affine {
    rows: [0xb2, 0xcc, 0x27, 0xee, 0x02, 0xc1, 0x2c, 0x11],
    c: 0x02,
};
/// SBOX3: the SBOX1 map rotated right one bit.
const POST_S3: Affine = Affine {
    rows: [0x27, 0xee, 0x02, 0xc1, 0x2c, 0x11, 0xb2, 0xcc],
    c: 0x80,
};

/// `F` substitutes the big-endian bytes of its 64-bit input through
/// `(s1, s2, s3, s4, s2, s3, s4, s1)`; lane `l` of a word is little-endian
/// byte `l % 8`, i.e. big-endian position `7 - l % 8`.
const F_PATTERN: [u8; 32] = {
    // Index into [s1, s2, s3, s4] by lane.
    let by_lane = [0u8, 3, 2, 1, 3, 2, 1, 0];
    let mut p = [0u8; 32];
    let mut l = 0;
    while l < 32 {
        p[l] = by_lane[l % 8];
        l += 1;
    }
    p
};
const F_PRE: PlaneAffine =
    PlaneAffine::per_lane(&[PRE_S123, PRE_S123, PRE_S123, PRE_S4], &F_PATTERN);
const F_POST: PlaneAffine =
    PlaneAffine::per_lane(&[POST_S14, POST_S2, POST_S3, POST_S14], &F_PATTERN);

// --- F, FL and FL⁻¹ functions (RFC 3713 §2.3) ------------------------------

/// The linear `P` layer of `F` on the substituted bytes `t1..t8` (big-endian).
#[inline]
fn p_layer(v: u64) -> u64 {
    let [t1, t2, t3, t4, t5, t6, t7, t8] = v.to_be_bytes();
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

/// The Feistel round function `F(x, k)` (RFC 3713 §2.3) on `N` blocks' left
/// halves at once (`N` = 1 or 4).
#[inline]
fn f<const N: usize>(x: &[u64; N], k: u64) -> [u64; N] {
    let mut w: [u64; N] = core::array::from_fn(|i| x[i] ^ k);
    sbox_custom(&mut w, &F_PRE, &F_POST);
    for v in w.iter_mut() {
        *v = p_layer(*v);
    }
    w
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

/// `F` on a single value (key schedule).
#[inline]
fn f1(x: u64, k: u64) -> u64 {
    f::<1>(&[x], k)[0]
}

/// Computes `KA` and `KB` from `KL` and `KR` (RFC 3713 §2.4).
fn ka_kb(kl: (u64, u64), kr: (u64, u64)) -> ((u64, u64), (u64, u64)) {
    let mut d1 = kl.0 ^ kr.0;
    let mut d2 = kl.1 ^ kr.1;
    d2 ^= f1(d1, SIGMA[0]);
    d1 ^= f1(d2, SIGMA[1]);
    d1 ^= kl.0;
    d2 ^= kl.1;
    d2 ^= f1(d1, SIGMA[2]);
    d1 ^= f1(d2, SIGMA[3]);
    let ka = (d1, d2);

    let mut e1 = ka.0 ^ kr.0;
    let mut e2 = ka.1 ^ kr.1;
    e2 ^= f1(e1, SIGMA[4]);
    e1 ^= f1(e2, SIGMA[5]);
    let kb = (e1, e2);

    // The Feistel temporaries hold KA and KB, from which the whole schedule
    // (and, with KL, the key) follows; don't leave them in the frame.
    for v in [&mut d1, &mut d2, &mut e1, &mut e2] {
        v.zeroize();
    }

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
    fn new128(mut kl: (u64, u64)) -> Self {
        let kr = (0u64, 0u64);
        let (mut ka, _kb) = ka_kb(kl, kr);
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
        let sched = Schedule {
            kw,
            k,
            ke,
            rounds: 18,
        };
        // KA is key-equivalent and KL *is* the key; the schedule now owns
        // everything needed.
        for v in [&mut ka.0, &mut ka.1, &mut kl.0, &mut kl.1] {
            v.zeroize();
        }
        sched
    }

    /// Builds the encryption schedule for a 192- or 256-bit key.
    fn new256(mut kl: (u64, u64), mut kr: (u64, u64)) -> Self {
        let (mut ka, mut kb) = ka_kb(kl, kr);
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
        let sched = Schedule {
            kw,
            k,
            ke,
            rounds: 24,
        };
        // KA/KB are key-equivalent and KL‖KR *is* the key; the schedule now
        // owns everything needed.
        for v in [
            &mut ka.0, &mut ka.1, &mut kb.0, &mut kb.1, &mut kl.0, &mut kl.1, &mut kr.0, &mut kr.1,
        ] {
            v.zeroize();
        }
        sched
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

    /// Runs the Feistel network on `N` independent blocks in lockstep, each
    /// split as `(d1, d2)`; `N` = 4 fills the bitsliced substitution.
    #[inline]
    fn crypt<const N: usize>(&self, d1: &mut [u64; N], d2: &mut [u64; N]) {
        for (a, b) in d1.iter_mut().zip(d2.iter_mut()) {
            *a ^= self.kw[0];
            *b ^= self.kw[1];
        }

        let groups = self.rounds / 6; // 3 or 4
        let mut round = 0;
        for g in 0..groups {
            // Six Feistel rounds.
            for _ in 0..6 {
                let fx = f(d1, self.k[round]);
                for (b, fv) in d2.iter_mut().zip(fx.iter()) {
                    *b ^= fv;
                }
                round += 1;
                core::mem::swap(d1, d2);
            }
            // After each group except the last, an FL / FL⁻¹ layer.
            if g != groups - 1 {
                for (a, b) in d1.iter_mut().zip(d2.iter_mut()) {
                    *a = fl(*a, self.ke[2 * g]);
                    *b = fl_inv(*b, self.ke[2 * g + 1]);
                }
            }
        }
        // The last swap above is undone by the final-output swap convention:
        // after the loop d1/d2 are already in the post-swap order, so apply
        // post-whitening with the halves exchanged (RFC 3713 §2.2).
        for (a, b) in d1.iter_mut().zip(d2.iter_mut()) {
            *b ^= self.kw[2];
            *a ^= self.kw[3];
        }
        core::mem::swap(d1, d2);
    }

    /// One block.
    #[inline]
    fn crypt_block(&self, block: &mut [u8; 16]) {
        let mut d1 = [u64::from_be_bytes(block[..8].try_into().expect("8 bytes"))];
        let mut d2 = [u64::from_be_bytes(block[8..].try_into().expect("8 bytes"))];
        self.crypt(&mut d1, &mut d2);
        block[..8].copy_from_slice(&d1[0].to_be_bytes());
        block[8..].copy_from_slice(&d2[0].to_be_bytes());
    }

    /// Whole blocks, four at a time; a tail of two or three blocks is padded
    /// to a batch (the padding lanes are discarded), a single trailing block
    /// takes the one-block path.
    fn crypt_blocks(&self, blocks: &mut [u8]) {
        let mut d1 = [0u64; 4];
        let mut d2 = [0u64; 4];
        let mut batches = blocks.chunks_exact_mut(64);
        for chunk in &mut batches {
            for (i, blk) in chunk.chunks_exact(16).enumerate() {
                d1[i] = u64::from_be_bytes(blk[..8].try_into().expect("8 bytes"));
                d2[i] = u64::from_be_bytes(blk[8..].try_into().expect("8 bytes"));
            }
            self.crypt(&mut d1, &mut d2);
            for (i, blk) in chunk.chunks_exact_mut(16).enumerate() {
                blk[..8].copy_from_slice(&d1[i].to_be_bytes());
                blk[8..].copy_from_slice(&d2[i].to_be_bytes());
            }
        }
        let rest = batches.into_remainder();
        if rest.len() == 16 {
            self.crypt_block(rest.try_into().expect("16 bytes"));
        } else if !rest.is_empty() {
            for (i, blk) in rest.chunks_exact(16).enumerate() {
                d1[i] = u64::from_be_bytes(blk[..8].try_into().expect("8 bytes"));
                d2[i] = u64::from_be_bytes(blk[8..].try_into().expect("8 bytes"));
            }
            self.crypt(&mut d1, &mut d2);
            for (i, blk) in rest.chunks_exact_mut(16).enumerate() {
                blk[..8].copy_from_slice(&d1[i].to_be_bytes());
                blk[8..].copy_from_slice(&d2[i].to_be_bytes());
            }
        }
        d1.zeroize();
        d2.zeroize();
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
                self.enc.crypt_block(block);
            }

            #[inline]
            fn decrypt_block(&self, block: &mut [u8; 16]) {
                self.dec.crypt_block(block);
            }

            fn encrypt_blocks(&self, blocks: &mut [u8]) {
                assert!(
                    blocks.len().is_multiple_of(16),
                    "encrypt_blocks needs whole blocks"
                );
                self.enc.crypt_blocks(blocks);
            }

            fn decrypt_blocks(&self, blocks: &mut [u8]) {
                assert!(
                    blocks.len().is_multiple_of(16),
                    "decrypt_blocks needs whole blocks"
                );
                self.dec.crypt_blocks(blocks);
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // Volatile stores plus a compiler fence, via `Zeroize`.
                for s in [&mut self.enc, &mut self.dec] {
                    s.kw.zeroize();
                    s.k.zeroize();
                    s.ke.zeroize();
                }
            }
        }

        impl crate::zeroize::ZeroizeOnDrop for $name {}
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
    use crate::cipher::sbox_bitsliced::derive;
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

    /// `La` of the affine equivalence `SBOX1 = Lb · AesSbox(La·x ⊕ 1) ⊕ 1`
    /// (rows MSB-first), for the derivation check.
    const LA: [u8; 8] = [147, 55, 187, 58, 21, 15, 197, 43];

    fn bit_matrix(rows: &[u8; 8], x: u8) -> u8 {
        let mut out = 0u8;
        for (bit, row) in rows.iter().enumerate() {
            out |= (((row & x).count_ones() & 1) as u8) << (7 - bit);
        }
        out
    }

    /// Evaluates the S-box of big-endian byte position `pos` of `F`'s input
    /// (`s1, s2, s3, s4, s2, s3, s4, s1`) on one byte, in every block lane.
    fn sbox_at(pos: usize, x: u8) -> u8 {
        let mut w = [u64::from(x) << (8 * (7 - pos)); 4];
        sbox_custom(&mut w, &F_PRE, &F_POST);
        let y = (w[0] >> (8 * (7 - pos))) as u8;
        for v in &w[1..] {
            assert_eq!((v >> (8 * (7 - pos))) as u8, y);
        }
        y
    }

    #[test]
    fn sbox1_matches_reference_table() {
        for x in 0u16..=255 {
            let x = x as u8;
            let s1 = SBOX1_REF[x as usize];
            assert_eq!(sbox_at(0, x), s1, "SBOX1 at {x:#04x}");
            assert_eq!(sbox_at(7, x), s1, "SBOX1 (last) at {x:#04x}");
            assert_eq!(sbox_at(1, x), s1.rotate_left(1), "SBOX2 at {x:#04x}");
            assert_eq!(sbox_at(4, x), s1.rotate_left(1), "SBOX2 at {x:#04x}");
            assert_eq!(sbox_at(2, x), s1.rotate_right(1), "SBOX3 at {x:#04x}");
            assert_eq!(sbox_at(5, x), s1.rotate_right(1), "SBOX3 at {x:#04x}");
            let s4 = SBOX1_REF[x.rotate_left(1) as usize];
            assert_eq!(sbox_at(3, x), s4, "SBOX4 at {x:#04x}");
            assert_eq!(sbox_at(6, x), s4, "SBOX4 at {x:#04x}");
        }
    }

    /// The hard-coded `(pre, post)` pairs are what the RFC 3713 table gives
    /// under the documented affine equivalence and the rotations.
    #[test]
    fn affine_constants_match_derivation() {
        let pre = |x: u8| bit_matrix(&LA, x) ^ 1;
        assert_eq!(derive(&SBOX1_REF, pre), (PRE_S123, POST_S14));
        let s2: [u8; 256] = core::array::from_fn(|i| SBOX1_REF[i].rotate_left(1));
        assert_eq!(derive(&s2, pre), (PRE_S123, POST_S2));
        let s3: [u8; 256] = core::array::from_fn(|i| SBOX1_REF[i].rotate_right(1));
        assert_eq!(derive(&s3, pre), (PRE_S123, POST_S3));
        let s4: [u8; 256] = core::array::from_fn(|i| SBOX1_REF[(i as u8).rotate_left(1) as usize]);
        assert_eq!(derive(&s4, |x| pre(x.rotate_left(1))), (PRE_S4, POST_S14));
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

    /// The four-block batch (and the padded short tail) must equal
    /// block-at-a-time processing for every block count up to two batches.
    #[cfg(feature = "alloc")]
    #[test]
    fn batched_matches_single() {
        let cipher = Camellia256::new(&[0x5au8; 32]);
        for nblocks in 1..=9 {
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
