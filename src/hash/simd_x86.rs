//! Shared x86_64 SIMD helpers for the wide hash backends.
//!
//! Both the multi-buffer SHA-256 kernel ([`super::sha256_mb`]) and the 8-way
//! BLAKE3 kernel ([`super::blake3_simd`]) load eight independent lanes as the
//! rows of an 8×8 matrix of 32-bit words and need the same transpose to move
//! between lane-major and word-major layouts. Keep that one intrinsic
//! sequence here rather than copied in both kernels.
//!
//! [`transpose16_epi32`] is the AVX-512 counterpart, used by the 16-way BLAKE3
//! kernel.
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

/// Transposes a 16×16 matrix of 32-bit lanes held in sixteen `__m512i` rows:
/// on return `rows[i]` holds what was column `i` (`rows_out[i][j] ==
/// rows_in[j][i]`).
///
/// Three stages, mirroring the AVX2 8×8 above: interleave 32-bit lanes of
/// adjacent row pairs, then 64-bit lanes, which leaves four independent 4×4
/// transposes inside the four 128-bit lanes; two rounds of `vshufi32x4` then
/// permute those 128-bit lanes into place.
///
/// # Safety
/// Requires AVX-512F. The `#[target_feature]` makes the intrinsics legal here,
/// but the caller must only reach this where AVX-512F is actually present
/// (the kernels gate on a runtime `is_x86_feature_detected!("avx512f")` check).
#[target_feature(enable = "avx512f")]
#[inline]
pub(crate) unsafe fn transpose16_epi32(rows: &mut [__m512i; 16]) {
    // Stage 1: interleave 32-bit lanes within each adjacent row pair.
    let mut lo = [_mm512_setzero_si512(); 8];
    let mut hi = [_mm512_setzero_si512(); 8];
    for k in 0..8 {
        lo[k] = _mm512_unpacklo_epi32(rows[2 * k], rows[2 * k + 1]);
        hi[k] = _mm512_unpackhi_epi32(rows[2 * k], rows[2 * k + 1]);
    }
    // Stage 2: interleave 64-bit lanes, pairing the pairs. Each 128-bit lane
    // now holds a completed 4×4 transpose of one four-row group.
    let mut q = [_mm512_setzero_si512(); 16];
    for k in 0..4 {
        q[4 * k] = _mm512_unpacklo_epi64(lo[2 * k], lo[2 * k + 1]);
        q[4 * k + 1] = _mm512_unpackhi_epi64(lo[2 * k], lo[2 * k + 1]);
        q[4 * k + 2] = _mm512_unpacklo_epi64(hi[2 * k], hi[2 * k + 1]);
        q[4 * k + 3] = _mm512_unpackhi_epi64(hi[2 * k], hi[2 * k + 1]);
    }
    // Stage 3: gather the 128-bit lanes across groups. `0x88` takes lanes 0/2
    // of each operand, `0xdd` lanes 1/3.
    let mut s = [[_mm512_setzero_si512(); 4]; 4];
    for k in 0..4 {
        s[0][k] = _mm512_shuffle_i32x4(q[k], q[4 + k], 0x88);
        s[1][k] = _mm512_shuffle_i32x4(q[k], q[4 + k], 0xdd);
        s[2][k] = _mm512_shuffle_i32x4(q[8 + k], q[12 + k], 0x88);
        s[3][k] = _mm512_shuffle_i32x4(q[8 + k], q[12 + k], 0xdd);
    }
    for k in 0..4 {
        rows[k] = _mm512_shuffle_i32x4(s[0][k], s[2][k], 0x88);
        rows[4 + k] = _mm512_shuffle_i32x4(s[1][k], s[3][k], 0x88);
        rows[8 + k] = _mm512_shuffle_i32x4(s[0][k], s[2][k], 0xdd);
        rows[12 + k] = _mm512_shuffle_i32x4(s[1][k], s[3][k], 0xdd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `transpose16_epi32` must be an exact matrix transpose.
    #[test]
    fn transpose16_is_a_transpose() {
        if !std::is_x86_feature_detected!("avx512f") {
            std::eprintln!("transpose16: SKIPPED (no AVX-512F)");
            return;
        }
        let mut src = [[0u32; 16]; 16];
        for (i, row) in src.iter_mut().enumerate() {
            for (j, v) in row.iter_mut().enumerate() {
                *v = (i * 16 + j) as u32;
            }
        }
        // SAFETY: AVX-512F confirmed just above.
        unsafe {
            let mut rows: [__m512i; 16] =
                core::array::from_fn(|i| _mm512_loadu_si512(src[i].as_ptr() as *const _));
            transpose16_epi32(&mut rows);
            let mut got = [[0u32; 16]; 16];
            for (i, g) in got.iter_mut().enumerate() {
                _mm512_storeu_si512(g.as_mut_ptr() as *mut _, rows[i]);
            }
            for i in 0..16 {
                for j in 0..16 {
                    assert_eq!(got[i][j], src[j][i], "({i},{j})");
                }
            }
        }
    }
}
