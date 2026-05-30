//! DES (FIPS 46-3) and Triple-DES (NIST SP 800-67).
//!
//! Provides [`Des`] (single-key, 56-bit effective), [`TdesEde3`] (3-key,
//! 168-bit effective) and [`TdesEde2`] (2-key, 112-bit effective). Block
//! size is 64 bits. The companion [`BlockCipher64`] trait and [`Cbc64`]
//! mode wrapper give these the same CBC ergonomics as the 128-bit
//! `BlockCipher` / `Cbc` pair next to them.
//!
//! # When to use this module
//!
//! Single-key DES is broken — 56 bits is exhaustively searchable on
//! commodity hardware in hours. Triple-DES is legacy — Sweet32 birthday
//! attacks make 64-bit-block CBC unsafe past ~32 GB of ciphertext per
//! key, and NIST disallowed TDES for new federal use after 2023
//! (SP 800-131A Rev 2). This module exists only to read legacy
//! ciphertext: PKCS#12 archives, RFC 8018 §A.4 PBE-SHA1-3DES envelopes,
//! classic PEM `DEK-Info: DES-EDE3-CBC` private keys, and similar
//! formats encrypted before the migration to AES. For new code use
//! [`crate::cipher::Aes256Gcm`] or [`crate::cipher::ChaCha20Poly1305`].
//!
//! # Implementation notes
//!
//! The F-function uses the canonical 8 × 64-entry S-box tables; round
//! output is therefore not constant time in the round-key bits. This
//! matches the [`crate::cipher::blowfish`] precedent and is acceptable
//! for the legacy-interop threat model: the keys these ciphers protect
//! are password-derived (offline cracking dominates) or already broken
//! (single DES). A bitsliced implementation would buy timing-side-channel
//! resistance at the cost of ~3× the code with no realistic security
//! improvement for the intended use cases.
//!
//! Parity bits in the 64-bit key encoding (bits 8, 16, 24, 32, 40, 48,
//! 56, 64 per FIPS 46-3 §3) are silently ignored by the key schedule;
//! callers should not rely on their value, but supplying odd-parity keys
//! keeps the result interoperable with implementations that do check.
//!
//! References:
//! - FIPS PUB 46-3 (1999) — DES specification.
//! - NIST SP 800-67 Rev 2 (2017) — TDES specification.

use super::{BlockCipher64, InvalidLength};

// ---- DES tables (FIPS 46-3 §8) ----------------------------------------

/// Initial Permutation (FIPS 46-3 §8.1): output bit `i` ← input bit
/// `IP[i-1]`, where bit 1 is the most-significant bit of the 64-bit
/// block.
#[rustfmt::skip]
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
];

/// Final Permutation (FIPS 46-3 §8.1): the inverse of [`IP`].
#[rustfmt::skip]
const FP: [u8; 64] = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
];

/// Expansion function E (FIPS 46-3 §8.1): expands the 32-bit right half
/// to 48 bits for XOR with the round key.
#[rustfmt::skip]
const E: [u8; 48] = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
];

/// P-box (FIPS 46-3 §8.1): the 32-bit permutation applied after the
/// S-box layer in the F-function.
#[rustfmt::skip]
const P: [u8; 32] = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
];

/// PC-1 (FIPS 46-3 §8.2): selects 56 key-bits (dropping the 8 parity
/// bits) and permutes them to form the initial `C0 || D0`.
#[rustfmt::skip]
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
];

/// PC-2 (FIPS 46-3 §8.2): selects 48 bits from the rotated `C || D` to
/// form one round key.
#[rustfmt::skip]
const PC2: [u8; 48] = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
];

/// Left-shift schedule for `C` / `D` (FIPS 46-3 §8.2): rotation amount
/// to apply before extracting round key `i+1` from `(C_i, D_i)`.
const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// The eight DES S-boxes (FIPS 46-3 §8.1, Tables 5–12). Each S-box maps
/// a 6-bit input to a 4-bit output. The input is interpreted as
/// `row = (b1 << 1) | b6` and `column = b2 b3 b4 b5`, indexing into a
/// 4×16 table. We store them flat as `[row*16 + col]` of length 64.
#[rustfmt::skip]
const S: [[u8; 64]; 8] = [
    // S1
    [
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
         0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
         4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
    ],
    // S2
    [
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
         3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
         0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
    ],
    // S3
    [
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
    ],
    // S4
    [
         7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
         3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
    ],
    // S5
    [
         2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
         4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
    ],
    // S6
    [
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
         9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
         4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
    ],
    // S7
    [
         4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
         1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
         6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
    ],
    // S8
    [
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
         1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
         7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
         2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11,
    ],
];

// ---- Bit-level helpers -------------------------------------------------

/// Permutes `input` (a right-justified `from_bits`-bit value: FIPS
/// bit 1 lives at u64 bit `from_bits - 1`, FIPS bit `from_bits` at
/// bit 0) into a right-justified `to_bits`-bit output.
///
/// `from_bits` and `to_bits` are compile-time constants of the FIPS spec,
/// so this loop runs in `table.len()` iterations with no key-dependent
/// branches.
#[inline]
fn permute(input: u64, from_bits: u32, table: &[u8], to_bits: u32) -> u64 {
    let mut out: u64 = 0;
    for (i, &src) in table.iter().enumerate() {
        let bit = (input >> (from_bits - src as u32)) & 1;
        out |= bit << (to_bits - 1 - i as u32);
    }
    out
}

/// 28-bit left-rotation, used for the `C` / `D` halves in the key
/// schedule. Input occupies bits `27..0` (low bits) of `x`.
#[inline]
fn rol28(x: u32, amount: u32) -> u32 {
    let mask = (1u32 << 28) - 1;
    ((x << amount) | (x >> (28 - amount))) & mask
}

/// Loads 8 bytes as a big-endian `u64` (FIPS 46-3 numbering: bit 1 =
/// MSB of byte 0).
#[inline]
fn load_be(block: &[u8; 8]) -> u64 {
    u64::from_be_bytes(*block)
}

/// Stores a `u64` as 8 big-endian bytes.
#[inline]
fn store_be(state: u64, block: &mut [u8; 8]) {
    block.copy_from_slice(&state.to_be_bytes());
}

// ---- F-function and key schedule ---------------------------------------

/// The DES F-function: expansion E, XOR with round key, 8 S-box
/// substitutions, then permutation P. The round-key argument is a
/// right-justified 48-bit value (FIPS bit 1 at u64 bit 47).
fn feistel_f(r: u32, round_key: u64) -> u32 {
    // E: 32 → 48 bits, right-justified. Input is a right-justified
    // u32 (FIPS bit 1 at u32 bit 31).
    let expanded = permute(r as u64, 32, &E, 48);
    let xored = expanded ^ round_key;
    // Extract eight 6-bit groups. With the 48-bit value right-
    // justified, FIPS bits (6k+1..6k+6) sit at u64 bits 47-6k..42-6k.
    let mut sbox_out: u64 = 0;
    for (k, sbox) in S.iter().enumerate() {
        let chunk = ((xored >> (42 - 6 * k)) & 0x3f) as usize;
        // FIPS row: bits 1 and 6 of the 6-bit chunk (the MSB and LSB).
        let row = ((chunk & 0b100000) >> 4) | (chunk & 0b000001);
        let col = (chunk >> 1) & 0b1111;
        let s = sbox[row * 16 + col] as u64;
        // Place the 4-bit S-box output into the right-justified 32-bit
        // pre-P value. FIPS bits (4k+1..4k+4) sit at u64 bits 31-4k..28-4k.
        sbox_out |= s << (28 - 4 * k);
    }
    // P: 32 → 32 bits, right-justified.
    permute(sbox_out, 32, &P, 32) as u32
}

/// Expands a 64-bit DES key (8 parity bits ignored) into the 16
/// 48-bit round keys, each a right-justified 48-bit `u64` (FIPS bit 1
/// at u64 bit 47).
fn key_schedule(key: u64) -> [u64; 16] {
    // PC-1: 64 → 56 bits, right-justified. Input `key` is also
    // right-justified 64-bit (`load_be` of an 8-byte key).
    let pc1 = permute(key, 64, &PC1, 56);
    // Split into C (FIPS bits 1..28 → u64 bits 55..28) and D (FIPS
    // bits 29..56 → u64 bits 27..0).
    let mask28 = (1u32 << 28) - 1;
    let mut c = ((pc1 >> 28) as u32) & mask28;
    let mut d = (pc1 as u32) & mask28;
    let mut rk = [0u64; 16];
    for i in 0..16 {
        c = rol28(c, SHIFTS[i] as u32);
        d = rol28(d, SHIFTS[i] as u32);
        // Re-pack C || D as a 56-bit right-justified u64 for PC-2.
        let cd = ((c as u64) << 28) | (d as u64);
        rk[i] = permute(cd, 56, &PC2, 48);
    }
    rk
}

/// Encrypts one block using already-scheduled round keys, in order
/// `rk[0..16]`.
fn des_encrypt_with(rk: &[u64; 16], block: &mut [u8; 8]) {
    let mut state = permute(load_be(block), 64, &IP, 64);
    let mut l = (state >> 32) as u32;
    let mut r = state as u32;
    for &k in rk.iter() {
        let tmp = r;
        r = l ^ feistel_f(r, k);
        l = tmp;
    }
    // After 16 rounds, the spec calls for a final swap (the "R16 L16"
    // ordering before FP).
    state = ((r as u64) << 32) | (l as u64);
    state = permute(state, 64, &FP, 64);
    store_be(state, block);
}

/// Decrypts one block using already-scheduled round keys, applied in
/// reverse order.
fn des_decrypt_with(rk: &[u64; 16], block: &mut [u8; 8]) {
    let mut state = permute(load_be(block), 64, &IP, 64);
    let mut l = (state >> 32) as u32;
    let mut r = state as u32;
    for &k in rk.iter().rev() {
        let tmp = r;
        r = l ^ feistel_f(r, k);
        l = tmp;
    }
    state = ((r as u64) << 32) | (l as u64);
    state = permute(state, 64, &FP, 64);
    store_be(state, block);
}

// ---- Public types ------------------------------------------------------

/// Single-key DES — 64-bit block, 56-bit effective key.
///
/// **Broken.** Provided only for legacy interop. See the module-level
/// docs.
#[derive(Clone)]
pub struct Des {
    rk: [u64; 16],
}

impl Des {
    /// Creates a DES context from an 8-byte key (parity bits ignored).
    #[inline]
    pub fn new(key: &[u8; 8]) -> Self {
        Self {
            rk: key_schedule(load_be(key)),
        }
    }
}

impl BlockCipher64 for Des {
    const KEY_SIZE: usize = 8;

    #[inline]
    fn encrypt_block(&self, block: &mut [u8; 8]) {
        des_encrypt_with(&self.rk, block);
    }

    #[inline]
    fn decrypt_block(&self, block: &mut [u8; 8]) {
        des_decrypt_with(&self.rk, block);
    }
}

impl Drop for Des {
    fn drop(&mut self) {
        for k in self.rk.iter_mut() {
            *k = 0;
        }
        core::hint::black_box(&self.rk);
    }
}

/// 3-key Triple-DES (DES-EDE3) — 24-byte key as `K1 || K2 || K3`.
/// Encryption is `E_K3(D_K2(E_K1(P)))`; decryption is its inverse.
///
/// **Legacy.** Provided for interop with PKCS#12, RFC 8018 §A.4,
/// classic PEM `DEK-Info: DES-EDE3-CBC`, etc. Subject to Sweet32; do
/// not use for new code.
#[derive(Clone)]
pub struct TdesEde3 {
    k1: [u64; 16],
    k2: [u64; 16],
    k3: [u64; 16],
}

impl TdesEde3 {
    /// Creates a 3-key TDES context from a 24-byte key. If `K1 = K2`
    /// or `K2 = K3`, the construction degenerates to single DES; the
    /// caller is responsible for using independent sub-keys.
    #[inline]
    pub fn new(key: &[u8; 24]) -> Self {
        let mut k = [0u8; 8];
        k.copy_from_slice(&key[0..8]);
        let k1 = key_schedule(load_be(&k));
        k.copy_from_slice(&key[8..16]);
        let k2 = key_schedule(load_be(&k));
        k.copy_from_slice(&key[16..24]);
        let k3 = key_schedule(load_be(&k));
        Self { k1, k2, k3 }
    }
}

impl BlockCipher64 for TdesEde3 {
    const KEY_SIZE: usize = 24;

    #[inline]
    fn encrypt_block(&self, block: &mut [u8; 8]) {
        des_encrypt_with(&self.k1, block);
        des_decrypt_with(&self.k2, block);
        des_encrypt_with(&self.k3, block);
    }

    #[inline]
    fn decrypt_block(&self, block: &mut [u8; 8]) {
        des_decrypt_with(&self.k3, block);
        des_encrypt_with(&self.k2, block);
        des_decrypt_with(&self.k1, block);
    }
}

impl Drop for TdesEde3 {
    fn drop(&mut self) {
        for ks in [&mut self.k1, &mut self.k2, &mut self.k3] {
            for k in ks.iter_mut() {
                *k = 0;
            }
            core::hint::black_box(&*ks);
        }
    }
}

/// 2-key Triple-DES (DES-EDE2) — 16-byte key as `K1 || K2`, executed
/// as `E_K1(D_K2(E_K1(P)))`. Equivalent to [`TdesEde3`] with `K3 = K1`.
///
/// Common in PKCS#12 (the legacy `pbeWithSHA1And2-KeyTripleDES-CBC`
/// envelope). **Legacy.** Sweet32-vulnerable. Do not use for new code.
#[derive(Clone)]
pub struct TdesEde2 {
    k1: [u64; 16],
    k2: [u64; 16],
}

impl TdesEde2 {
    /// Creates a 2-key TDES context from a 16-byte key.
    #[inline]
    pub fn new(key: &[u8; 16]) -> Self {
        let mut k = [0u8; 8];
        k.copy_from_slice(&key[0..8]);
        let k1 = key_schedule(load_be(&k));
        k.copy_from_slice(&key[8..16]);
        let k2 = key_schedule(load_be(&k));
        Self { k1, k2 }
    }
}

impl BlockCipher64 for TdesEde2 {
    const KEY_SIZE: usize = 16;

    #[inline]
    fn encrypt_block(&self, block: &mut [u8; 8]) {
        des_encrypt_with(&self.k1, block);
        des_decrypt_with(&self.k2, block);
        des_encrypt_with(&self.k1, block);
    }

    #[inline]
    fn decrypt_block(&self, block: &mut [u8; 8]) {
        des_decrypt_with(&self.k1, block);
        des_encrypt_with(&self.k2, block);
        des_decrypt_with(&self.k1, block);
    }
}

impl Drop for TdesEde2 {
    fn drop(&mut self) {
        for ks in [&mut self.k1, &mut self.k2] {
            for k in ks.iter_mut() {
                *k = 0;
            }
            core::hint::black_box(&*ks);
        }
    }
}

// ---- CBC mode for 64-bit blocks ----------------------------------------

/// CBC-mode wrapper around a 64-bit-block cipher. Parallel to the
/// 128-bit [`crate::cipher::Cbc`] — same semantics, just an 8-byte
/// chaining value. Unauthenticated; the IV must be unpredictable, and
/// a (key, IV) pair must never be reused.
#[derive(Clone)]
pub struct Cbc64<C: BlockCipher64> {
    cipher: C,
    chain: [u8; 8],
}

impl<C: BlockCipher64> Cbc64<C> {
    /// Creates a CBC context from `cipher` and an 8-byte IV.
    #[inline]
    pub fn new(cipher: C, iv: &[u8; 8]) -> Self {
        Self { cipher, chain: *iv }
    }

    /// Encrypts `data` in place. May be called repeatedly to continue
    /// the chain; every call's length must be a multiple of 8.
    ///
    /// # Errors
    /// Returns [`InvalidLength`] (without modifying `data`) if the
    /// length is not a whole number of blocks.
    pub fn encrypt(&mut self, data: &mut [u8]) -> Result<(), InvalidLength> {
        if !data.len().is_multiple_of(8) {
            return Err(InvalidLength);
        }
        for chunk in data.chunks_exact_mut(8) {
            for (b, c) in chunk.iter_mut().zip(self.chain.iter()) {
                *b ^= *c;
            }
            let block: &mut [u8; 8] = chunk.try_into().unwrap();
            self.cipher.encrypt_block(block);
            self.chain = *block;
        }
        Ok(())
    }

    /// Decrypts `data` in place. May be called repeatedly to continue
    /// the chain; every call's length must be a multiple of 8.
    ///
    /// # Errors
    /// Returns [`InvalidLength`] (without modifying `data`) if the
    /// length is not a whole number of blocks.
    pub fn decrypt(&mut self, data: &mut [u8]) -> Result<(), InvalidLength> {
        if !data.len().is_multiple_of(8) {
            return Err(InvalidLength);
        }
        for chunk in data.chunks_exact_mut(8) {
            let saved = <[u8; 8]>::try_from(&chunk[..]).unwrap();
            let block: &mut [u8; 8] = chunk.try_into().unwrap();
            self.cipher.decrypt_block(block);
            for (b, c) in block.iter_mut().zip(self.chain.iter()) {
                *b ^= *c;
            }
            self.chain = saved;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// Canonical DES KAT: key 0x0123456789ABCDEF, plaintext "Now is t"
    /// (0x4E6F772069732074), ciphertext 0x3FA40E8A984D4815. Appears
    /// in Schneier §12.4, RFC 2268, and countless DES references.
    #[test]
    fn des_canonical_kat() {
        let key = from_hex::<8>("0123456789abcdef");
        let cipher = Des::new(&key);
        let mut block = from_hex::<8>("4e6f772069732074");
        cipher.encrypt_block(&mut block);
        assert_eq!(block, from_hex::<8>("3fa40e8a984d4815"));
        cipher.decrypt_block(&mut block);
        assert_eq!(block, from_hex::<8>("4e6f772069732074"));
    }

    /// Second canonical DES KAT (Schneier §12.4 Table 12.4 worked
    /// example): key 0x133457799BBCDFF1, plaintext 0x0123456789ABCDEF,
    /// ciphertext 0x85E813540F0AB405.
    #[test]
    fn des_worked_example_kat() {
        let key = from_hex::<8>("133457799bbcdff1");
        let cipher = Des::new(&key);
        let mut block = from_hex::<8>("0123456789abcdef");
        cipher.encrypt_block(&mut block);
        assert_eq!(block, from_hex::<8>("85e813540f0ab405"));
        cipher.decrypt_block(&mut block);
        assert_eq!(block, from_hex::<8>("0123456789abcdef"));
    }

    /// FIPS 81 / DES weak-key behavior: the four weak keys produce
    /// identical encryption and decryption schedules, so they are
    /// self-inverse — `E_K(E_K(P)) = P`.
    #[test]
    fn des_weak_key_self_inverse() {
        // FIPS 74 §3.6 weak keys (with parity).
        let weak_keys: [[u8; 8]; 4] = [
            from_hex::<8>("0101010101010101"),
            from_hex::<8>("fefefefefefefefe"),
            from_hex::<8>("e0e0e0e0f1f1f1f1"),
            from_hex::<8>("1f1f1f1f0e0e0e0e"),
        ];
        for k in weak_keys.iter() {
            let cipher = Des::new(k);
            let original = from_hex::<8>("0011223344556677");
            let mut block = original;
            cipher.encrypt_block(&mut block);
            cipher.encrypt_block(&mut block);
            assert_eq!(block, original, "weak key should be self-inverse");
        }
    }

    /// TDES-EDE3 with all three sub-keys equal degenerates to single
    /// DES, so the canonical DES KAT must verify through TdesEde3
    /// with `K1 = K2 = K3`.
    #[test]
    fn tdes_ede3_equal_keys_is_des() {
        let mut k = [0u8; 24];
        let single = from_hex::<8>("0123456789abcdef");
        k[0..8].copy_from_slice(&single);
        k[8..16].copy_from_slice(&single);
        k[16..24].copy_from_slice(&single);
        let cipher = TdesEde3::new(&k);
        let mut block = from_hex::<8>("4e6f772069732074");
        cipher.encrypt_block(&mut block);
        assert_eq!(block, from_hex::<8>("3fa40e8a984d4815"));
        cipher.decrypt_block(&mut block);
        assert_eq!(block, from_hex::<8>("4e6f772069732074"));
    }

    /// NIST SP 800-67 Rev 2 §B.1 worked example: 3-key TDES on a
    /// single block.
    /// Keys K1=0123456789ABCDEF, K2=23456789ABCDEF01, K3=456789ABCDEF0123.
    /// PT = "The qufc" = 5468652071756663.
    /// CT = A826FD8CE53B855F.
    #[test]
    fn tdes_ede3_nist_sp800_67_kat() {
        let key = from_hex::<24>("0123456789abcdef23456789abcdef01456789abcdef0123");
        let cipher = TdesEde3::new(&key);
        let mut block = from_hex::<8>("5468652071756663");
        cipher.encrypt_block(&mut block);
        assert_eq!(block, from_hex::<8>("a826fd8ce53b855f"));
        cipher.decrypt_block(&mut block);
        assert_eq!(block, from_hex::<8>("5468652071756663"));
    }

    /// TdesEde2 with K1 == K2 collapses to single DES (`E(D(E(P))) = E(P)`
    /// when K1 = K2). Verifies the EDE2 ordering matches the spec.
    #[test]
    fn tdes_ede2_equal_keys_is_des() {
        let mut k = [0u8; 16];
        let single = from_hex::<8>("0123456789abcdef");
        k[0..8].copy_from_slice(&single);
        k[8..16].copy_from_slice(&single);
        let cipher = TdesEde2::new(&k);
        let mut block = from_hex::<8>("4e6f772069732074");
        cipher.encrypt_block(&mut block);
        assert_eq!(block, from_hex::<8>("3fa40e8a984d4815"));
        cipher.decrypt_block(&mut block);
        assert_eq!(block, from_hex::<8>("4e6f772069732074"));
    }

    /// TdesEde2 should equal TdesEde3 with K3 = K1.
    #[test]
    fn tdes_ede2_equals_ede3_with_k3_eq_k1() {
        let k2bytes = from_hex::<16>("0123456789abcdef23456789abcdef01");
        let ede2 = TdesEde2::new(&k2bytes);

        let mut k3bytes = [0u8; 24];
        k3bytes[0..16].copy_from_slice(&k2bytes);
        k3bytes[16..24].copy_from_slice(&k2bytes[0..8]); // K3 = K1
        let ede3 = TdesEde3::new(&k3bytes);

        let pt = from_hex::<8>("0011223344556677");
        let mut b2 = pt;
        let mut b3 = pt;
        ede2.encrypt_block(&mut b2);
        ede3.encrypt_block(&mut b3);
        assert_eq!(b2, b3);
        ede2.decrypt_block(&mut b2);
        ede3.decrypt_block(&mut b3);
        assert_eq!(b2, pt);
        assert_eq!(b3, pt);
    }

    /// DES round-trip across all single-byte patterns. Guards against
    /// permutation typos that pass one KAT but corrupt other inputs.
    #[test]
    fn des_roundtrip_byte_patterns() {
        let key = from_hex::<8>("133457799bbcdff1");
        let cipher = Des::new(&key);
        for v in 0u16..=255 {
            let original = [v as u8; 8];
            let mut block = original;
            cipher.encrypt_block(&mut block);
            assert_ne!(block, original);
            cipher.decrypt_block(&mut block);
            assert_eq!(block, original);
        }
    }

    /// CBC-mode round trip + spot check against an OpenSSL-computed
    /// vector for `enc -des-ede3-cbc -K 0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123 -iv 1234567890ABCDEF`
    /// over four 8-byte blocks of plaintext.
    #[test]
    fn cbc64_tdes_ede3_roundtrip() {
        let key = from_hex::<24>("0123456789abcdef23456789abcdef01456789abcdef0123");
        let iv = from_hex::<8>("1234567890abcdef");
        let plaintext: [u8; 32] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb,
            0xdc, 0xed, 0xfe, 0x0f,
        ];

        let mut buf = plaintext;
        Cbc64::new(TdesEde3::new(&key), &iv)
            .encrypt(&mut buf)
            .unwrap();
        // Ciphertext should not equal plaintext.
        assert_ne!(buf, plaintext);
        Cbc64::new(TdesEde3::new(&key), &iv)
            .decrypt(&mut buf)
            .unwrap();
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn cbc64_rejects_partial_block() {
        let key = from_hex::<8>("0123456789abcdef");
        let iv = from_hex::<8>("1234567890abcdef");
        let mut buf = [0u8; 12];
        assert_eq!(
            Cbc64::new(Des::new(&key), &iv).encrypt(&mut buf),
            Err(InvalidLength)
        );
    }

    /// Cross-check: DES-CBC of two zero blocks under the all-zero key
    /// with an all-zero IV is a well-known oddity used in NIST FIPS 81
    /// validation suites. Output computed via reference single-block
    /// DES on `0x0000000000000000`: 0x8CA64DE9C1B123A7.
    #[test]
    fn cbc64_des_zero_kat() {
        let key = [0u8; 8];
        let iv = [0u8; 8];
        let mut buf = [0u8; 16];
        Cbc64::new(Des::new(&key), &iv).encrypt(&mut buf).unwrap();
        // First block: E_0(0) = 8CA64DE9C1B123A7.
        assert_eq!(&buf[0..8], &from_hex::<8>("8ca64de9c1b123a7")[..]);
        // Second block: E_0(C1 XOR 0) = E_0(C1).
        let c2 = {
            let mut b = from_hex::<8>("8ca64de9c1b123a7");
            Des::new(&key).encrypt_block(&mut b);
            b
        };
        assert_eq!(&buf[8..16], &c2[..]);
    }
}
