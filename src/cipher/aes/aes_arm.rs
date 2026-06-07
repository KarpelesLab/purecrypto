//! ARMv8 AES hardware backend (aarch64).
//!
//! Uses the `aes` (FEAT_AES) Crypto Extension via `core::arch::aarch64`
//! intrinsics. The AESE/AESD instructions are data-independent (constant-time)
//! in hardware, preserving the crate's constant-time guarantee.
//!
//! Every entry point is `#[target_feature(enable = "aes")]` (NEON is baseline on
//! aarch64) and therefore `unsafe`: callers in [`super`] invoke them only after
//! a runtime `is_aarch64_feature_detected!("aes")` check. The round keys are
//! read straight from the software-expanded FIPS-197 `rk` byte array.
//!
//! `vaeseq_u8(x, k)` computes `ShiftRows(SubBytes(x XOR k))` and `vaesmcq_u8`
//! the MixColumns, so each AESE folds one AddRoundKey with the *next* round's
//! byte/row transform — hence the off-by-one key indexing below, which matches
//! the canonical OpenSSL `aesv8` sequences. Decryption uses AESD/AESIMC over the
//! forward schedule taken in reverse (equivalent inverse cipher).
#![allow(unsafe_code)]
// Compute-only NEON intrinsics are safe to call inside a `#[target_feature]` fn
// (target_feature_11), so the uniform body-level `unsafe` is redundant in the
// pointer-free helpers; keep it for consistency and silence the style lint.
#![allow(unused_unsafe)]

use core::arch::aarch64::*;

/// Loads round key `i` (the 16 bytes at `rk[i*16..]`).
#[inline]
#[target_feature(enable = "aes")]
unsafe fn rk(rk: &[u8], i: usize) -> uint8x16_t {
    unsafe { vld1q_u8(rk.as_ptr().add(i * 16)) }
}

#[inline]
#[target_feature(enable = "aes")]
unsafe fn enc_core(ks: &[uint8x16_t], nr: usize, mut s: uint8x16_t) -> uint8x16_t {
    unsafe {
        for &k in ks.iter().take(nr - 1) {
            s = vaesmcq_u8(vaeseq_u8(s, k));
        }
        s = vaeseq_u8(s, ks[nr - 1]);
        veorq_u8(s, ks[nr])
    }
}

#[inline]
#[target_feature(enable = "aes")]
unsafe fn dec_core(ks: &[uint8x16_t], nr: usize, mut s: uint8x16_t) -> uint8x16_t {
    unsafe {
        // Equivalent inverse cipher with the forward key schedule (canonical
        // OpenSSL aesv8 decrypt): the first AESD uses the raw last round key,
        // the middle round keys are InvMixColumns-transformed (vaesimcq) before
        // AESD, and the state is InvMixColumns'd between rounds. AESD(x,k) =
        // InvSubBytes(InvShiftRows(x XOR k)).
        s = vaesdq_u8(s, ks[nr]);
        for round in (1..nr).rev() {
            s = vaesimcq_u8(s);
            s = vaesdq_u8(s, vaesimcq_u8(ks[round]));
        }
        veorq_u8(s, ks[0])
    }
}

/// Preloads the round-key schedule into a fixed array (≤ 15 keys for AES-256).
#[inline]
#[target_feature(enable = "aes")]
unsafe fn load_schedule(round_keys: &[u8], nr: usize) -> [uint8x16_t; 15] {
    unsafe {
        let mut ks = [vdupq_n_u8(0); 15];
        for (i, k) in ks.iter_mut().enumerate().take(nr + 1) {
            *k = rk(round_keys, i);
        }
        ks
    }
}

/// Single forward block.
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt_block(round_keys: &[u8], nr: usize, block: &mut [u8; 16]) {
    unsafe {
        let ks = load_schedule(round_keys, nr);
        let s = enc_core(&ks, nr, vld1q_u8(block.as_ptr()));
        vst1q_u8(block.as_mut_ptr(), s);
    }
}

/// Single inverse block.
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt_block(round_keys: &[u8], nr: usize, block: &mut [u8; 16]) {
    unsafe {
        let ks = load_schedule(round_keys, nr);
        let s = dec_core(&ks, nr, vld1q_u8(block.as_ptr()));
        vst1q_u8(block.as_mut_ptr(), s);
    }
}

/// Forward permutation over independent 16-byte blocks, pipelining 4 at a time.
/// `blocks.len()` must be a multiple of 16.
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt_blocks(round_keys: &[u8], nr: usize, blocks: &mut [u8]) {
    unsafe {
        let ks = load_schedule(round_keys, nr);
        let mut wide = blocks.chunks_exact_mut(16 * 4);
        for c in &mut wide {
            let mut b = [vdupq_n_u8(0); 4];
            for (j, bj) in b.iter_mut().enumerate() {
                *bj = enc_core(&ks, nr, vld1q_u8(c.as_ptr().add(j * 16)));
            }
            for (j, &bj) in b.iter().enumerate() {
                vst1q_u8(c.as_mut_ptr().add(j * 16), bj);
            }
        }
        for block in wide.into_remainder().chunks_exact_mut(16) {
            let s = enc_core(&ks, nr, vld1q_u8(block.as_ptr()));
            vst1q_u8(block.as_mut_ptr(), s);
        }
    }
}

/// Inverse permutation over independent 16-byte blocks, pipelining 4 at a time.
/// `blocks.len()` must be a multiple of 16.
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt_blocks(round_keys: &[u8], nr: usize, blocks: &mut [u8]) {
    unsafe {
        let ks = load_schedule(round_keys, nr);
        let mut wide = blocks.chunks_exact_mut(16 * 4);
        for c in &mut wide {
            let mut b = [vdupq_n_u8(0); 4];
            for (j, bj) in b.iter_mut().enumerate() {
                *bj = dec_core(&ks, nr, vld1q_u8(c.as_ptr().add(j * 16)));
            }
            for (j, &bj) in b.iter().enumerate() {
                vst1q_u8(c.as_mut_ptr().add(j * 16), bj);
            }
        }
        for block in wide.into_remainder().chunks_exact_mut(16) {
            let s = dec_core(&ks, nr, vld1q_u8(block.as_ptr()));
            vst1q_u8(block.as_mut_ptr(), s);
        }
    }
}
