//! ARIA (RFC 5794) block cipher, constant-time.
//!
//! ARIA is a 128-bit-block, involutional SPN cipher with 128-, 192- and
//! 256-bit keys (12, 14 and 16 rounds respectively). Each round applies a
//! key XOR, a byte-wise substitution layer (odd rounds use `SL1`, even rounds
//! `SL2`), and a 16×16 binary diffusion matrix `A` that is an involution. The
//! same round structure serves both encryption and decryption; only the
//! round-key order and an extra `A` applied to the interior decryption keys
//! differ.
//!
//! It implements [`BlockCipher`], so it composes with the crate's CBC, CTR
//! and GCM modes exactly like AES. Round keys are wiped on drop.
//!
//! Like the table-free AES core in this crate, the four ARIA S-boxes are
//! **computed** rather than looked up, so there are no secret-dependent
//! memory accesses and hence no cache-timing leak:
//!
//! * `S1` is the AES S-box: `affine_aes(inv(x))`, reusing [`super::aes::gf`].
//! * `S2(x) = B · inv(x) ⊕ 0xe2`, a different GF(2)-affine map of the same
//!   GF(2⁸) inverse (reduction polynomial `0x11b`).
//! * `SS1 = S1⁻¹` and `SS2 = S2⁻¹` are the corresponding inverse affines
//!   followed by the (self-inverse) field inversion.
//!
//! Every operation is branchless with no data-dependent indexing.

use super::BlockCipher;
use super::aes::gf::{gf_inv, inv_sub_byte, sub_byte};

// --- S-boxes, computed table-free from the GF(2⁸) inverse -------------------

/// ARIA `S1` — identical to the AES S-box.
#[inline]
fn s1(x: u8) -> u8 {
    sub_byte(x)
}

/// ARIA `SS1 = S1⁻¹` — the inverse AES S-box.
#[inline]
fn ss1(x: u8) -> u8 {
    inv_sub_byte(x)
}

/// Applies an 8×8 GF(2) matrix (rows MSB-first) to `y`, MSB-first output.
#[inline]
fn bit_matrix(rows: &[u8; 8], y: u8) -> u8 {
    let mut out = 0u8;
    let mut bit = 0;
    while bit < 8 {
        let parity = (rows[bit] & y).count_ones() & 1;
        out |= (parity as u8) << (7 - bit);
        bit += 1;
    }
    out
}

/// ARIA `S2(x) = B · inv(x) ⊕ 0xe2`.
///
/// `B` is the fixed 8×8 GF(2) matrix from RFC 5794 §2.4.2; applied as a
/// per-output-bit parity over the bits of the field inverse `inv(x)`, so there
/// is no table lookup. Validated against the standard S2 table in the tests.
#[inline]
fn s2(x: u8) -> u8 {
    const B: [u8; 8] = [
        0b0110_1111,
        0b1100_0110,
        0b0111_0011,
        0b1100_0010,
        0b1100_0011,
        0b1011_0111,
        0b1111_1100,
        0b1110_1010,
    ];
    bit_matrix(&B, gf_inv(x)) ^ 0xe2
}

/// ARIA `SS2 = S2⁻¹`: undo the affine `B·y ⊕ 0xe2`, then invert in GF(2⁸).
#[inline]
fn ss2(x: u8) -> u8 {
    const BINV: [u8; 8] = [
        0b1100_1001,
        0b1011_1101,
        0b1101_0110,
        0b0011_0111,
        0b1100_0111,
        0b0101_0000,
        0b0110_0100,
        0b0001_1000,
    ];
    gf_inv(bit_matrix(&BINV, x ^ 0xe2))
}

// --- Diffusion layer A (RFC 5794 §2.4.3) ------------------------------------

/// The involutional diffusion `A` on a 16-byte state. Each output byte is a
/// XOR of seven input bytes per the RFC 5794 §2.4.3 matrix. `A` is its own
/// inverse, so the same routine serves encryption and decryption.
#[inline]
fn a_layer(x: &[u8; 16]) -> [u8; 16] {
    let mut y = [0u8; 16];
    y[0] = x[3] ^ x[4] ^ x[6] ^ x[8] ^ x[9] ^ x[13] ^ x[14];
    y[1] = x[2] ^ x[5] ^ x[7] ^ x[8] ^ x[9] ^ x[12] ^ x[15];
    y[2] = x[1] ^ x[4] ^ x[6] ^ x[10] ^ x[11] ^ x[12] ^ x[15];
    y[3] = x[0] ^ x[5] ^ x[7] ^ x[10] ^ x[11] ^ x[13] ^ x[14];
    y[4] = x[0] ^ x[2] ^ x[5] ^ x[8] ^ x[11] ^ x[14] ^ x[15];
    y[5] = x[1] ^ x[3] ^ x[4] ^ x[9] ^ x[10] ^ x[14] ^ x[15];
    y[6] = x[0] ^ x[2] ^ x[7] ^ x[9] ^ x[10] ^ x[12] ^ x[13];
    y[7] = x[1] ^ x[3] ^ x[6] ^ x[8] ^ x[11] ^ x[12] ^ x[13];
    y[8] = x[0] ^ x[1] ^ x[4] ^ x[7] ^ x[10] ^ x[13] ^ x[15];
    y[9] = x[0] ^ x[1] ^ x[5] ^ x[6] ^ x[11] ^ x[12] ^ x[14];
    y[10] = x[2] ^ x[3] ^ x[5] ^ x[6] ^ x[8] ^ x[13] ^ x[15];
    y[11] = x[2] ^ x[3] ^ x[4] ^ x[7] ^ x[9] ^ x[12] ^ x[14];
    y[12] = x[1] ^ x[2] ^ x[6] ^ x[7] ^ x[9] ^ x[11] ^ x[12];
    y[13] = x[0] ^ x[3] ^ x[6] ^ x[7] ^ x[8] ^ x[10] ^ x[13];
    y[14] = x[0] ^ x[3] ^ x[4] ^ x[5] ^ x[9] ^ x[11] ^ x[14];
    y[15] = x[1] ^ x[2] ^ x[4] ^ x[5] ^ x[8] ^ x[10] ^ x[15];
    y
}

/// Odd-round substitution layer `SL1`: `(S1, S2, SS1, SS2)` repeated.
#[inline]
fn sl1(x: &mut [u8; 16]) {
    let mut i = 0;
    while i < 16 {
        x[i] = s1(x[i]);
        x[i + 1] = s2(x[i + 1]);
        x[i + 2] = ss1(x[i + 2]);
        x[i + 3] = ss2(x[i + 3]);
        i += 4;
    }
}

/// Even-round substitution layer `SL2`: `(SS1, SS2, S1, S2)` repeated.
#[inline]
fn sl2(x: &mut [u8; 16]) {
    let mut i = 0;
    while i < 16 {
        x[i] = ss1(x[i]);
        x[i + 1] = ss2(x[i + 1]);
        x[i + 2] = s1(x[i + 2]);
        x[i + 3] = s2(x[i + 3]);
        i += 4;
    }
}

#[inline]
fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        o[i] = a[i] ^ b[i];
        i += 1;
    }
    o
}

/// Odd round function `FO(D, RK) = A(SL1(D ⊕ RK))`.
#[inline]
fn fo(d: &[u8; 16], rk: &[u8; 16]) -> [u8; 16] {
    let mut t = xor_block(d, rk);
    sl1(&mut t);
    a_layer(&t)
}

/// Even round function `FE(D, RK) = A(SL2(D ⊕ RK))`.
#[inline]
fn fe(d: &[u8; 16], rk: &[u8; 16]) -> [u8; 16] {
    let mut t = xor_block(d, rk);
    sl2(&mut t);
    a_layer(&t)
}

// --- Key schedule (RFC 5794 §2.5) -------------------------------------------

/// Constant values `C1, C2, C3` from the fractional part of 1/π
/// (RFC 5794 §2.5.1).
const C1: [u8; 16] = [
    0x51, 0x7c, 0xc1, 0xb7, 0x27, 0x22, 0x0a, 0x94, 0xfe, 0x13, 0xab, 0xe8, 0xfa, 0x9a, 0x6e, 0xe0,
];
const C2: [u8; 16] = [
    0x6d, 0xb1, 0x4a, 0xcc, 0x9e, 0x21, 0xc8, 0x20, 0xff, 0x28, 0xb1, 0xd5, 0xef, 0x5d, 0xe2, 0xb0,
];
const C3: [u8; 16] = [
    0xdb, 0x92, 0x37, 0x1d, 0x21, 0x26, 0xe9, 0x70, 0x03, 0x24, 0x97, 0x75, 0x04, 0xe8, 0xc9, 0x0e,
];

/// Rotates a 128-bit value right by `n` bits, big-endian.
#[inline]
fn rotr128(x: &[u8; 16], n: u32) -> [u8; 16] {
    u128::from_be_bytes(*x).rotate_right(n).to_be_bytes()
}

/// Number of rounds for the given key length in bytes.
#[inline]
const fn rounds_for(key_bytes: usize) -> usize {
    match key_bytes {
        16 => 12,
        24 => 14,
        _ => 16, // 32-byte key
    }
}

/// Expands the encryption and decryption round keys for `master` (the key
/// zero-padded to 32 bytes, `KL || KR`) of length `key_bytes`.
fn expand(master: &[u8; 32], key_bytes: usize) -> ([[u8; 16]; 17], [[u8; 16]; 17], usize) {
    let nr = rounds_for(key_bytes);

    let mut kl = [0u8; 16];
    let mut kr = [0u8; 16];
    kl.copy_from_slice(&master[..16]);
    kr.copy_from_slice(&master[16..]);

    // (CK1, CK2, CK3) by key length (RFC 5794 §2.5.1).
    let (ck1, ck2, ck3) = match key_bytes {
        16 => (C1, C2, C3),
        24 => (C2, C3, C1),
        _ => (C3, C1, C2),
    };

    // Four 128-bit words W0..W3 (RFC 5794 §2.5.1).
    let w0 = kl;
    let w1 = xor_block(&fo(&w0, &ck1), &kr);
    let w2 = xor_block(&fe(&w1, &ck2), &w0);
    let w3 = xor_block(&fo(&w2, &ck3), &w1);
    let w = [w0, w1, w2, w3];

    // 17 encryption round keys (we always fill 17 slots; only nr+1 are used).
    // ek(i+1) = W(i mod 4) ⊕ rotr( W((i+1) mod 4), r_i ) per RFC 5794 §2.5.2.
    // The RFC writes the last three groups as left rotations 61, 31, 19, which
    // equal right rotations 67, 97, 109 — used here so a single rotr suffices.
    let rots = [19u32, 31, 67, 97, 109];
    let mut ek = [[0u8; 16]; 17];
    let mut i = 0;
    while i <= nr {
        let a = w[i % 4];
        let r = rots[i / 4];
        let b = rotr128(&w[(i + 1) % 4], r);
        ek[i] = xor_block(&a, &b);
        i += 1;
    }

    // Decryption round keys (RFC 5794 §2.5.3): reverse the encryption keys and
    // apply A to the interior ones.
    let mut dk = [[0u8; 16]; 17];
    dk[0] = ek[nr];
    let mut j = 1;
    while j < nr {
        dk[j] = a_layer(&ek[nr - j]);
        j += 1;
    }
    dk[nr] = ek[0];

    (ek, dk, nr)
}

/// The ARIA round structure, parameterised by round-key set.
#[inline]
fn crypt(state: &mut [u8; 16], rk: &[[u8; 16]; 17], nr: usize) {
    let mut p = *state;
    // Rounds 1 .. nr-1 alternate FO (odd) / FE (even); round nr is special.
    let mut round = 0;
    while round < nr - 1 {
        p = if round % 2 == 0 {
            fo(&p, &rk[round])
        } else {
            fe(&p, &rk[round])
        };
        round += 1;
    }
    // Final round (the (nr)-th): substitution-only, no diffusion, then the
    // last whitening key. Round index nr-1 is odd-numbered (1-based round nr
    // is even), so the final substitution uses SL2.
    let mut t = xor_block(&p, &rk[nr - 1]);
    sl2(&mut t);
    *state = xor_block(&t, &rk[nr]);
}

macro_rules! aria_variant {
    ($(#[$meta:meta])* $name:ident, $key_bytes:expr) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            ek: [[u8; 16]; 17],
            dk: [[u8; 16]; 17],
            nr: usize,
        }

        impl $name {
            /// Creates the cipher from its key, expanding the round keys.
            pub fn new(key: &[u8; $key_bytes]) -> Self {
                let mut master = [0u8; 32];
                master[..$key_bytes].copy_from_slice(key);
                let (ek, dk, nr) = expand(&master, $key_bytes);
                $name { ek, dk, nr }
            }
        }

        impl BlockCipher for $name {
            const BLOCK_SIZE: usize = 16;
            const KEY_SIZE: usize = $key_bytes;

            #[inline]
            fn encrypt_block(&self, block: &mut [u8; 16]) {
                crypt(block, &self.ek, self.nr);
            }

            #[inline]
            fn decrypt_block(&self, block: &mut [u8; 16]) {
                crypt(block, &self.dk, self.nr);
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                for w in self.ek.iter_mut().chain(self.dk.iter_mut()) {
                    *w = [0u8; 16];
                }
                core::hint::black_box(&self.ek);
                core::hint::black_box(&self.dk);
            }
        }
    };
}

aria_variant!(
    /// ARIA with a 128-bit key (12 rounds).
    Aria128,
    16
);
aria_variant!(
    /// ARIA with a 192-bit key (14 rounds).
    Aria192,
    24
);
aria_variant!(
    /// ARIA with a 256-bit key (16 rounds).
    Aria256,
    32
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// Reference ARIA S1 table (RFC 5794 §2.4.2 / AES S-box).
    #[rustfmt::skip]
    const S1_REF: [u8; 256] = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ];

    /// Reference ARIA S2 table (RFC 5794 §2.4.2).
    #[rustfmt::skip]
    const S2_REF: [u8; 256] = [
        0xe2,0x4e,0x54,0xfc,0x94,0xc2,0x4a,0xcc,0x62,0x0d,0x6a,0x46,0x3c,0x4d,0x8b,0xd1,
        0x5e,0xfa,0x64,0xcb,0xb4,0x97,0xbe,0x2b,0xbc,0x77,0x2e,0x03,0xd3,0x19,0x59,0xc1,
        0x1d,0x06,0x41,0x6b,0x55,0xf0,0x99,0x69,0xea,0x9c,0x18,0xae,0x63,0xdf,0xe7,0xbb,
        0x00,0x73,0x66,0xfb,0x96,0x4c,0x85,0xe4,0x3a,0x09,0x45,0xaa,0x0f,0xee,0x10,0xeb,
        0x2d,0x7f,0xf4,0x29,0xac,0xcf,0xad,0x91,0x8d,0x78,0xc8,0x95,0xf9,0x2f,0xce,0xcd,
        0x08,0x7a,0x88,0x38,0x5c,0x83,0x2a,0x28,0x47,0xdb,0xb8,0xc7,0x93,0xa4,0x12,0x53,
        0xff,0x87,0x0e,0x31,0x36,0x21,0x58,0x48,0x01,0x8e,0x37,0x74,0x32,0xca,0xe9,0xb1,
        0xb7,0xab,0x0c,0xd7,0xc4,0x56,0x42,0x26,0x07,0x98,0x60,0xd9,0xb6,0xb9,0x11,0x40,
        0xec,0x20,0x8c,0xbd,0xa0,0xc9,0x84,0x04,0x49,0x23,0xf1,0x4f,0x50,0x1f,0x13,0xdc,
        0xd8,0xc0,0x9e,0x57,0xe3,0xc3,0x7b,0x65,0x3b,0x02,0x8f,0x3e,0xe8,0x25,0x92,0xe5,
        0x15,0xdd,0xfd,0x17,0xa9,0xbf,0xd4,0x9a,0x7e,0xc5,0x39,0x67,0xfe,0x76,0x9d,0x43,
        0xa7,0xe1,0xd0,0xf5,0x68,0xf2,0x1b,0x34,0x70,0x05,0xa3,0x8a,0xd5,0x79,0x86,0xa8,
        0x30,0xc6,0x51,0x4b,0x1e,0xa6,0x27,0xf6,0x35,0xd2,0x6e,0x24,0x16,0x82,0x5f,0xda,
        0xe6,0x75,0xa2,0xef,0x2c,0xb2,0x1c,0x9f,0x5d,0x6f,0x80,0x0a,0x72,0x44,0x9b,0x6c,
        0x90,0x0b,0x5b,0x33,0x7d,0x5a,0x52,0xf3,0x61,0xa1,0xf7,0xb0,0xd6,0x3f,0x7c,0x6d,
        0xed,0x14,0xe0,0xa5,0x3d,0x22,0xb3,0xf8,0x89,0xde,0x71,0x1a,0xaf,0xba,0xb5,0x81,
    ];

    #[test]
    fn sboxes_match_reference_tables() {
        for x in 0u16..=255 {
            let x = x as u8;
            assert_eq!(s1(x), S1_REF[x as usize], "S1 at {x:#04x}");
            assert_eq!(s2(x), S2_REF[x as usize], "S2 at {x:#04x}");
            // Inverses really invert.
            assert_eq!(ss1(s1(x)), x, "SS1 at {x:#04x}");
            assert_eq!(ss2(s2(x)), x, "SS2 at {x:#04x}");
        }
    }

    #[test]
    fn a_layer_is_involution() {
        for seed in 0u16..=255 {
            let mut b = [0u8; 16];
            for (i, v) in b.iter_mut().enumerate() {
                *v = (seed as u8).wrapping_add(i as u8).wrapping_mul(31);
            }
            assert_eq!(a_layer(&a_layer(&b)), b);
        }
    }

    // RFC 5794 Appendix A.1: 128-bit key.
    #[test]
    fn rfc5794_aria128() {
        let key = from_hex::<16>("000102030405060708090a0b0c0d0e0f");
        let pt = from_hex::<16>("00112233445566778899aabbccddeeff");
        let ct = from_hex::<16>("d718fbd6ab644c739da95f3be6451778");
        let cipher = Aria128::new(&key);
        let mut b = pt;
        cipher.encrypt_block(&mut b);
        assert_eq!(b, ct, "encrypt");
        cipher.decrypt_block(&mut b);
        assert_eq!(b, pt, "decrypt");
    }

    // RFC 5794 Appendix A.2: 192-bit key.
    #[test]
    fn rfc5794_aria192() {
        let key = from_hex::<24>("000102030405060708090a0b0c0d0e0f1011121314151617");
        let pt = from_hex::<16>("00112233445566778899aabbccddeeff");
        let ct = from_hex::<16>("26449c1805dbe7aa25a468ce263a9e79");
        let cipher = Aria192::new(&key);
        let mut b = pt;
        cipher.encrypt_block(&mut b);
        assert_eq!(b, ct, "encrypt");
        cipher.decrypt_block(&mut b);
        assert_eq!(b, pt, "decrypt");
    }

    // RFC 5794 Appendix A.3: 256-bit key.
    #[test]
    fn rfc5794_aria256() {
        let key =
            from_hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = from_hex::<16>("00112233445566778899aabbccddeeff");
        let ct = from_hex::<16>("f92bd7c79fb72e2f2b8f80c1972d24fc");
        let cipher = Aria256::new(&key);
        let mut b = pt;
        cipher.encrypt_block(&mut b);
        assert_eq!(b, ct, "encrypt");
        cipher.decrypt_block(&mut b);
        assert_eq!(b, pt, "decrypt");
    }

    #[test]
    fn roundtrip_random_blocks() {
        let key = from_hex::<16>("0f0e0d0c0b0a09080706050403020100");
        let cipher = Aria128::new(&key);
        let mut state = 0x1234_5678_9abc_def0u64;
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
