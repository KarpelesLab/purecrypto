//! AVX2 SIMD backend for BLAKE3 — 8-way parallel chunk compression.
//!
//! BLAKE3 hashes its input as independent 1024-byte chunks whose chaining
//! values form a binary tree. Those chunks are mutually independent, so the
//! bulk of a large hash parallelises perfectly: this backend compresses **8
//! chunks at once** across the eight 32-bit lanes of an AVX2 `__m256i`,
//! producing eight chunk chaining values per call. The per-lane arithmetic is
//! byte-for-byte the scalar [`super::blake3`] compression (same `g`, same round
//! schedule, same message permutation), just executed 8-wide; this is pinned by
//! a differential test against the scalar [`super::blake3::ChunkState`].
//!
//! Only the all-full-chunk fast path is vectorised here (every block is 64
//! bytes, `block_len = 64`, `CHUNK_START` on block 0 and `CHUNK_END` on block
//! 15). Partial chunks, parent nodes and the XOF stay on the scalar path. x86_64
//! only; the `super::blake3` dispatch falls back to scalar when AVX2 is absent
//! or on other architectures.
#![allow(unsafe_code)]

use super::blake3::{CHUNK_END, CHUNK_LEN, CHUNK_START, IV, MSG_PERMUTATION};

/// Number of chunks processed per call (AVX2 lane count).
pub(super) const DEGREE: usize = 8;

/// Whether the AVX2 BLAKE3 backend is available on this CPU.
#[cfg(target_arch = "x86_64")]
pub(super) fn supported() -> bool {
    std::is_x86_feature_detected!("avx2")
}

/// Compresses `DEGREE` consecutive full 1024-byte chunks in parallel.
///
/// `input` must be exactly `DEGREE * CHUNK_LEN` bytes; chunk `k` uses counter
/// `counter_base + k`. Returns the eight chunk chaining values (each the first
/// eight words of the chunk's final compression).
#[cfg(target_arch = "x86_64")]
pub(super) fn hash_chunks8(
    input: &[u8],
    key: &[u32; 8],
    counter_base: u64,
    flags: u32,
) -> [[u32; 8]; 8] {
    debug_assert_eq!(input.len(), DEGREE * CHUNK_LEN);
    // SAFETY: `supported()` (checked by the caller) confirmed AVX2.
    unsafe { avx2::hash_chunks8(input, key, counter_base, flags) }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::*;
    use core::arch::x86_64::*;

    const BLOCK_LEN: u32 = 64;

    // The intrinsics need the shift amount as a compile-time immediate, so the
    // four BLAKE3 rotations (16/12/8/7) are specialised rather than parametric.
    #[inline(always)]
    unsafe fn rotr16(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<16>(x), _mm256_slli_epi32::<16>(x)) }
    }
    #[inline(always)]
    unsafe fn rotr12(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<12>(x), _mm256_slli_epi32::<20>(x)) }
    }
    #[inline(always)]
    unsafe fn rotr8(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<8>(x), _mm256_slli_epi32::<24>(x)) }
    }
    #[inline(always)]
    unsafe fn rotr7(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<7>(x), _mm256_slli_epi32::<25>(x)) }
    }

    #[inline(always)]
    unsafe fn add(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_add_epi32(a, b) }
    }

    #[inline(always)]
    unsafe fn xor(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_xor_si256(a, b) }
    }

    /// The 8-wide BLAKE3 `g` mixing function (lanes are independent chunks).
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    unsafe fn g(
        v: &mut [__m256i; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        mx: __m256i,
        my: __m256i,
    ) {
        unsafe {
            v[a] = add(add(v[a], v[b]), mx);
            v[d] = rotr16(xor(v[d], v[a]));
            v[c] = add(v[c], v[d]);
            v[b] = rotr12(xor(v[b], v[c]));
            v[a] = add(add(v[a], v[b]), my);
            v[d] = rotr8(xor(v[d], v[a]));
            v[c] = add(v[c], v[d]);
            v[b] = rotr7(xor(v[b], v[c]));
        }
    }

    #[inline(always)]
    unsafe fn round(v: &mut [__m256i; 16], m: &[__m256i; 16]) {
        unsafe {
            // Columns.
            g(v, 0, 4, 8, 12, m[0], m[1]);
            g(v, 1, 5, 9, 13, m[2], m[3]);
            g(v, 2, 6, 10, 14, m[4], m[5]);
            g(v, 3, 7, 11, 15, m[6], m[7]);
            // Diagonals.
            g(v, 0, 5, 10, 15, m[8], m[9]);
            g(v, 1, 6, 11, 12, m[10], m[11]);
            g(v, 2, 7, 8, 13, m[12], m[13]);
            g(v, 3, 4, 9, 14, m[14], m[15]);
        }
    }

    // In-place 8x8 transpose of eight `__m256i` (each holding 8 `u32`), shared
    // with the multi-buffer SHA-256 kernel.
    use crate::hash::simd_x86::transpose8_epi32 as transpose8;

    /// Loads block `b` of all 8 chunks and transposes into 16 message vectors,
    /// where `m[j]` holds word `j` of that block across the 8 lanes.
    #[inline(always)]
    unsafe fn load_msg(input: &[u8], b: usize) -> [__m256i; 16] {
        unsafe {
            let mut lo = [_mm256_setzero_si256(); 8];
            let mut hi = [_mm256_setzero_si256(); 8];
            for (lane, (l, h)) in lo.iter_mut().zip(hi.iter_mut()).enumerate() {
                let p = input.as_ptr().add(lane * CHUNK_LEN + b * 64);
                // BLAKE3 words are little-endian, so the raw bytes are the words.
                *l = _mm256_loadu_si256(p as *const __m256i); // words 0..=7
                *h = _mm256_loadu_si256(p.add(32) as *const __m256i); // words 8..=15
            }
            transpose8(&mut lo);
            transpose8(&mut hi);
            let mut m = [_mm256_setzero_si256(); 16];
            m[..8].copy_from_slice(&lo);
            m[8..].copy_from_slice(&hi);
            m
        }
    }

    /// Reorders the 16 message vectors per `MSG_PERMUTATION` between rounds.
    #[inline(always)]
    unsafe fn permute(m: &[__m256i; 16]) -> [__m256i; 16] {
        let mut out = [unsafe { _mm256_setzero_si256() }; 16];
        for (i, &p) in MSG_PERMUTATION.iter().enumerate() {
            out[i] = m[p];
        }
        out
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn hash_chunks8(
        input: &[u8],
        key: &[u32; 8],
        counter_base: u64,
        flags: u32,
    ) -> [[u32; 8]; 8] {
        unsafe {
            // Per-lane counters: chunk k uses counter_base + k.
            let mut clo = [0u32; 8];
            let mut chi = [0u32; 8];
            for (k, (lo, hi)) in clo.iter_mut().zip(chi.iter_mut()).enumerate() {
                let c = counter_base.wrapping_add(k as u64);
                *lo = c as u32;
                *hi = (c >> 32) as u32;
            }
            let counter_lo = _mm256_loadu_si256(clo.as_ptr() as *const __m256i);
            let counter_hi = _mm256_loadu_si256(chi.as_ptr() as *const __m256i);
            let block_len = _mm256_set1_epi32(BLOCK_LEN as i32);

            // Chaining values, one broadcast key word per state lane.
            let mut h = [_mm256_setzero_si256(); 8];
            for (hi, &kw) in h.iter_mut().zip(key.iter()) {
                *hi = _mm256_set1_epi32(kw as i32);
            }

            for b in 0..16usize {
                let block_flags = {
                    let mut f = flags;
                    if b == 0 {
                        f |= CHUNK_START;
                    }
                    if b == 15 {
                        f |= CHUNK_END;
                    }
                    _mm256_set1_epi32(f as i32)
                };

                let msg = load_msg(input, b);

                let mut v = [
                    h[0],
                    h[1],
                    h[2],
                    h[3],
                    h[4],
                    h[5],
                    h[6],
                    h[7],
                    _mm256_set1_epi32(IV[0] as i32),
                    _mm256_set1_epi32(IV[1] as i32),
                    _mm256_set1_epi32(IV[2] as i32),
                    _mm256_set1_epi32(IV[3] as i32),
                    counter_lo,
                    counter_hi,
                    block_len,
                    block_flags,
                ];

                let mut m = msg;
                for r in 0..7 {
                    round(&mut v, &m);
                    if r < 6 {
                        m = permute(&m);
                    }
                }

                // Chunk chaining value = first 8 words: state[i] ^ state[i + 8].
                for i in 0..8 {
                    h[i] = xor(v[i], v[i + 8]);
                }
            }

            // Transpose the 8 CV word-vectors back to per-lane CVs.
            transpose8(&mut h);
            let mut out = [[0u32; 8]; 8];
            for (lane, hi) in h.iter().enumerate() {
                _mm256_storeu_si256(out[lane].as_mut_ptr() as *mut __m256i, *hi);
            }
            out
        }
    }
}
