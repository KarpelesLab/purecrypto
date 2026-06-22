//! Shared x86_64 AVX2 helpers for the wide hash backends.
//!
//! Both the multi-buffer SHA-256 kernel ([`super::sha256_mb`]) and the 8-way
//! BLAKE3 kernel ([`super::blake3_simd`]) load eight independent lanes as the
//! rows of an 8×8 matrix of 32-bit words and need the same transpose to move
//! between lane-major and word-major layouts. Keep that one intrinsic
//! sequence here rather than copied in both kernels.
#![allow(unsafe_code)]

use core::arch::x86_64::*;

/// Transposes an 8×8 matrix of 32-bit lanes held in eight `__m256i` rows: on
/// return `rows[i]` holds what was column `i` (i.e. `rows_out[i][j] ==
/// rows_in[j][i]`).
///
/// # Safety
/// Requires AVX2. The `#[target_feature]` makes the intrinsics legal here, but
/// the caller must only reach this on a CPU where AVX2 is actually present
/// (the kernels gate on a runtime `is_x86_feature_detected!("avx2")` check).
#[target_feature(enable = "avx2")]
#[inline]
pub(crate) unsafe fn transpose8_epi32(rows: &mut [__m256i; 8]) {
    // The intrinsics are safe to call directly within this `#[target_feature]`
    // function (no inner `unsafe` block needed); the `unsafe fn` contract is
    // only the AVX2-availability precondition the caller must uphold.
    let t0 = _mm256_unpacklo_epi32(rows[0], rows[1]);
    let t1 = _mm256_unpackhi_epi32(rows[0], rows[1]);
    let t2 = _mm256_unpacklo_epi32(rows[2], rows[3]);
    let t3 = _mm256_unpackhi_epi32(rows[2], rows[3]);
    let t4 = _mm256_unpacklo_epi32(rows[4], rows[5]);
    let t5 = _mm256_unpackhi_epi32(rows[4], rows[5]);
    let t6 = _mm256_unpacklo_epi32(rows[6], rows[7]);
    let t7 = _mm256_unpackhi_epi32(rows[6], rows[7]);

    let s0 = _mm256_unpacklo_epi64(t0, t2);
    let s1 = _mm256_unpackhi_epi64(t0, t2);
    let s2 = _mm256_unpacklo_epi64(t1, t3);
    let s3 = _mm256_unpackhi_epi64(t1, t3);
    let s4 = _mm256_unpacklo_epi64(t4, t6);
    let s5 = _mm256_unpackhi_epi64(t4, t6);
    let s6 = _mm256_unpacklo_epi64(t5, t7);
    let s7 = _mm256_unpackhi_epi64(t5, t7);

    rows[0] = _mm256_permute2x128_si256(s0, s4, 0x20);
    rows[1] = _mm256_permute2x128_si256(s1, s5, 0x20);
    rows[2] = _mm256_permute2x128_si256(s2, s6, 0x20);
    rows[3] = _mm256_permute2x128_si256(s3, s7, 0x20);
    rows[4] = _mm256_permute2x128_si256(s0, s4, 0x31);
    rows[5] = _mm256_permute2x128_si256(s1, s5, 0x31);
    rows[6] = _mm256_permute2x128_si256(s2, s6, 0x31);
    rows[7] = _mm256_permute2x128_si256(s3, s7, 0x31);
}
