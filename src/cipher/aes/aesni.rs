//! AES-NI hardware backend (x86_64).
//!
//! Uses the `aes` instruction-set extension via `core::arch::x86_64` intrinsics.
//! These instructions are data-independent (constant-time) in hardware, so this
//! backend preserves the crate's constant-time guarantee while running ~50×
//! faster than the table-free software S-box.
//!
//! Every entry point is `#[target_feature(enable = "aes,sse2")]` and therefore
//! `unsafe`: callers in [`super`] invoke them only after a runtime
//! `is_x86_feature_detected!("aes")` check. AES-NI consumes the standard
//! FIPS-197 round-key schedule directly, so the round keys are read straight
//! from the software-expanded `rk` byte array; decryption derives the
//! equivalent-inverse-cipher round keys on the fly with `aesimc`.
#![allow(unsafe_code)]

use core::arch::x86_64::*;

/// Loads round key `i` (the 16 bytes at `rk[i*16..]`) into a 128-bit register.
#[inline]
#[target_feature(enable = "sse2")]
unsafe fn rk(rk: &[u8], i: usize) -> __m128i {
    unsafe { _mm_loadu_si128(rk.as_ptr().add(i * 16) as *const __m128i) }
}

/// Single forward block via AES-NI.
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn encrypt_block(round_keys: &[u8], nr: usize, block: &mut [u8; 16]) {
    unsafe {
        let mut s = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        s = _mm_xor_si128(s, rk(round_keys, 0));
        for r in 1..nr {
            s = _mm_aesenc_si128(s, rk(round_keys, r));
        }
        s = _mm_aesenclast_si128(s, rk(round_keys, nr));
        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, s);
    }
}

/// Single inverse block via AES-NI (equivalent inverse cipher).
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn decrypt_block(round_keys: &[u8], nr: usize, block: &mut [u8; 16]) {
    unsafe {
        let mut s = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        s = _mm_xor_si128(s, rk(round_keys, nr));
        for r in (1..nr).rev() {
            s = _mm_aesdec_si128(s, _mm_aesimc_si128(rk(round_keys, r)));
        }
        s = _mm_aesdeclast_si128(s, rk(round_keys, 0));
        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, s);
    }
}

/// Forward permutation over independent 16-byte blocks, pipelining 8 at a time
/// so the AESENC latency is hidden. `blocks.len()` must be a multiple of 16.
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn encrypt_blocks(round_keys: &[u8], nr: usize, blocks: &mut [u8]) {
    unsafe {
        // Preload the schedule once (≤ 15 round keys for AES-256).
        let mut ks = [_mm_setzero_si128(); 15];
        for (i, k) in ks.iter_mut().enumerate().take(nr + 1) {
            *k = rk(round_keys, i);
        }

        let mut wide = blocks.chunks_exact_mut(16 * 8);
        for c in &mut wide {
            let mut b = [_mm_setzero_si128(); 8];
            for (j, bj) in b.iter_mut().enumerate() {
                *bj = _mm_loadu_si128(c.as_ptr().add(j * 16) as *const __m128i);
            }
            for bj in b.iter_mut() {
                *bj = _mm_xor_si128(*bj, ks[0]);
            }
            for &k in ks.iter().take(nr).skip(1) {
                for bj in b.iter_mut() {
                    *bj = _mm_aesenc_si128(*bj, k);
                }
            }
            for bj in b.iter_mut() {
                *bj = _mm_aesenclast_si128(*bj, ks[nr]);
            }
            for (j, &bj) in b.iter().enumerate() {
                _mm_storeu_si128(c.as_mut_ptr().add(j * 16) as *mut __m128i, bj);
            }
        }

        for block in wide.into_remainder().chunks_exact_mut(16) {
            let mut s = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            s = _mm_xor_si128(s, ks[0]);
            for &k in ks.iter().take(nr).skip(1) {
                s = _mm_aesenc_si128(s, k);
            }
            s = _mm_aesenclast_si128(s, ks[nr]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, s);
        }
    }
}

/// Inverse permutation over independent 16-byte blocks, pipelining 8 at a time.
/// `blocks.len()` must be a multiple of 16.
#[target_feature(enable = "aes,sse2")]
pub(super) unsafe fn decrypt_blocks(round_keys: &[u8], nr: usize, blocks: &mut [u8]) {
    unsafe {
        // Equivalent-inverse-cipher schedule: rk[0], imc(rk[1..nr]), rk[nr].
        let mut ks = [_mm_setzero_si128(); 15];
        ks[0] = rk(round_keys, 0);
        ks[nr] = rk(round_keys, nr);
        for (i, k) in ks.iter_mut().enumerate().take(nr).skip(1) {
            *k = _mm_aesimc_si128(rk(round_keys, i));
        }

        let mut wide = blocks.chunks_exact_mut(16 * 8);
        for c in &mut wide {
            let mut b = [_mm_setzero_si128(); 8];
            for (j, bj) in b.iter_mut().enumerate() {
                *bj = _mm_loadu_si128(c.as_ptr().add(j * 16) as *const __m128i);
            }
            for bj in b.iter_mut() {
                *bj = _mm_xor_si128(*bj, ks[nr]);
            }
            for r in (1..nr).rev() {
                for bj in b.iter_mut() {
                    *bj = _mm_aesdec_si128(*bj, ks[r]);
                }
            }
            for bj in b.iter_mut() {
                *bj = _mm_aesdeclast_si128(*bj, ks[0]);
            }
            for (j, &bj) in b.iter().enumerate() {
                _mm_storeu_si128(c.as_mut_ptr().add(j * 16) as *mut __m128i, bj);
            }
        }

        for block in wide.into_remainder().chunks_exact_mut(16) {
            let mut s = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            s = _mm_xor_si128(s, ks[nr]);
            for r in (1..nr).rev() {
                s = _mm_aesdec_si128(s, ks[r]);
            }
            s = _mm_aesdeclast_si128(s, ks[0]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, s);
        }
    }
}
