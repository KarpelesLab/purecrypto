//! Hardware GHASH — GF(2¹²⁸) multiply in the GCM bit convention via the
//! carryless-multiply instructions (PCLMULQDQ on x86_64, PMULL on aarch64).
//!
//! Exposes a [`gf_mul`] that returns the *same* value as the constant-time
//! software multiply in `super::gcm`, so it drops into the GHASH loop unchanged.
//! These instructions are data-independent (constant-time), so the GCM hash
//! subkey is not exposed through timing. Correctness is pinned by a differential
//! test against the software reference (see the `gcm` tests).
//!
//! This module is compiled only on `std` + (`x86_64` | `aarch64`), gated at the
//! `mod` declaration in `super`.
#![allow(unsafe_code)]
#![allow(unused_unsafe)]

#[cfg(target_arch = "aarch64")]
pub(super) use arm::gf_mul;
#[cfg(target_arch = "x86_64")]
pub(super) use x86::gf_mul;

/// Whether a hardware GHASH backend is available on this CPU.
#[cfg(target_arch = "x86_64")]
pub(super) fn supported() -> bool {
    std::is_x86_feature_detected!("pclmulqdq")
        && std::is_x86_feature_detected!("sse2")
        && std::is_x86_feature_detected!("ssse3")
}

#[cfg(target_arch = "aarch64")]
pub(super) fn supported() -> bool {
    // FEAT_PMULL (the 64→128 polynomial multiply) is reported under "aes".
    std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("neon")
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use core::arch::x86_64::*;

    /// Byte-reverses a 128-bit value. GCM blocks are big-endian; the reflected
    /// GHASH reduction works on the byte-swapped representation.
    #[inline]
    #[target_feature(enable = "sse2,ssse3")]
    unsafe fn bswap(v: __m128i) -> __m128i {
        unsafe {
            let mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            _mm_shuffle_epi8(v, mask)
        }
    }

    /// Carryless 128×128 → reduced 128-bit GCM product on the internal
    /// byte-swapped representation — the reflected `gfmul` from Intel's
    /// carry-less-multiply white paper (Figure 5 + the two-phase reduction).
    #[inline]
    #[target_feature(enable = "pclmulqdq,sse2")]
    unsafe fn gfmul(a: __m128i, b: __m128i) -> __m128i {
        unsafe {
            let t3 = _mm_clmulepi64_si128(a, b, 0x00);
            let t6 = _mm_clmulepi64_si128(a, b, 0x11);
            let t4 = _mm_clmulepi64_si128(a, b, 0x10);
            let t5 = _mm_clmulepi64_si128(a, b, 0x01);
            let t4 = _mm_xor_si128(t4, t5);
            let t5 = _mm_slli_si128(t4, 8);
            let t4 = _mm_srli_si128(t4, 8);
            let mut t3 = _mm_xor_si128(t3, t5);
            let mut t6 = _mm_xor_si128(t6, t4);

            // First phase: <<1 across the 256-bit product (reflected rep).
            let t7 = _mm_srli_epi32(t3, 31);
            let t8 = _mm_srli_epi32(t6, 31);
            t3 = _mm_slli_epi32(t3, 1);
            t6 = _mm_slli_epi32(t6, 1);
            let t9 = _mm_srli_si128(t7, 12);
            let t8 = _mm_slli_si128(t8, 4);
            let t7 = _mm_slli_si128(t7, 4);
            t3 = _mm_or_si128(t3, t7);
            t6 = _mm_or_si128(t6, t8);
            t6 = _mm_or_si128(t6, t9);

            // Second phase: reduce modulo x¹²⁸ + x⁷ + x² + x + 1.
            let t7 = _mm_slli_epi32(t3, 31);
            let t8 = _mm_slli_epi32(t3, 30);
            let t9 = _mm_slli_epi32(t3, 25);
            let t7 = _mm_xor_si128(t7, t8);
            let t7 = _mm_xor_si128(t7, t9);
            let t8 = _mm_srli_si128(t7, 4);
            let t7 = _mm_slli_si128(t7, 12);
            t3 = _mm_xor_si128(t3, t7);
            let t2 = _mm_srli_epi32(t3, 1);
            let t4 = _mm_srli_epi32(t3, 2);
            let t5 = _mm_srli_epi32(t3, 7);
            let t2 = _mm_xor_si128(t2, t4);
            let t2 = _mm_xor_si128(t2, t5);
            let t2 = _mm_xor_si128(t2, t8);
            t3 = _mm_xor_si128(t3, t2);
            _mm_xor_si128(t6, t3)
        }
    }

    /// GCM-convention GF(2¹²⁸) product matching `super::super::gcm::gf_mul`.
    #[target_feature(enable = "pclmulqdq,sse2,ssse3")]
    pub(in super::super) unsafe fn gf_mul(x: u128, y: u128) -> u128 {
        unsafe {
            let a = bswap(_mm_loadu_si128(x.to_be_bytes().as_ptr() as *const __m128i));
            let b = bswap(_mm_loadu_si128(y.to_be_bytes().as_ptr() as *const __m128i));
            let p = bswap(gfmul(a, b));
            let mut out = [0u8; 16];
            _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, p);
            u128::from_be_bytes(out)
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use core::arch::aarch64::*;

    // Byte/lane-shift helpers mirroring the x86 `_mm_*_si128` / `_mm_*_epi32`
    // ops used in the reflected GHASH reduction. `_mm_slli_si128(v, n)` (shift
    // left n bytes) == `vextq_u8(zero, v, 16 - n)`; `_mm_srli_si128(v, n)` ==
    // `vextq_u8(v, zero, n)`.
    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn clmul(a: uint8x16_t, b: uint8x16_t, imm: u32) -> uint8x16_t {
        unsafe {
            let au = vreinterpretq_u64_u8(a);
            let bu = vreinterpretq_u64_u8(b);
            let ax = if imm & 0x01 != 0 {
                vgetq_lane_u64(au, 1)
            } else {
                vgetq_lane_u64(au, 0)
            };
            let bx = if imm & 0x10 != 0 {
                vgetq_lane_u64(bu, 1)
            } else {
                vgetq_lane_u64(bu, 0)
            };
            vreinterpretq_u8_p128(vmull_p64(ax, bx))
        }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn slli32(v: uint8x16_t, n: i32) -> uint8x16_t {
        unsafe { vreinterpretq_u8_u32(vshlq_u32(vreinterpretq_u32_u8(v), vdupq_n_s32(n))) }
    }
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn srli32(v: uint8x16_t, n: i32) -> uint8x16_t {
        unsafe { vreinterpretq_u8_u32(vshlq_u32(vreinterpretq_u32_u8(v), vdupq_n_s32(-n))) }
    }

    /// Carryless 128×128 → reduced 128-bit GCM product, a 1:1 NEON port of the
    /// x86 reflected `gfmul` above (operating on the byte-swapped rep).
    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn gfmul(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
        unsafe {
            let zero = vdupq_n_u8(0);
            let t3 = clmul(a, b, 0x00);
            let t6 = clmul(a, b, 0x11);
            let t4 = clmul(a, b, 0x10);
            let t5 = clmul(a, b, 0x01);
            let t4 = veorq_u8(t4, t5);
            let t5 = vextq_u8(zero, t4, 8); // slli_si128(t4, 8)
            let t4 = vextq_u8(t4, zero, 8); // srli_si128(t4, 8)
            let mut t3 = veorq_u8(t3, t5);
            let mut t6 = veorq_u8(t6, t4);

            // First phase: <<1 across the 256-bit product.
            let t7 = srli32(t3, 31);
            let t8 = srli32(t6, 31);
            t3 = slli32(t3, 1);
            t6 = slli32(t6, 1);
            let t9 = vextq_u8(t7, zero, 12); // srli_si128(t7, 12)
            let t8 = vextq_u8(zero, t8, 12); // slli_si128(t8, 4)
            let t7 = vextq_u8(zero, t7, 12); // slli_si128(t7, 4)
            t3 = vorrq_u8(t3, t7);
            t6 = vorrq_u8(t6, t8);
            t6 = vorrq_u8(t6, t9);

            // Second phase: reduce modulo x¹²⁸ + x⁷ + x² + x + 1.
            let t7 = slli32(t3, 31);
            let t8 = slli32(t3, 30);
            let t9 = slli32(t3, 25);
            let t7 = veorq_u8(t7, t8);
            let t7 = veorq_u8(t7, t9);
            let t8 = vextq_u8(t7, zero, 4); // srli_si128(t7, 4)
            let t7 = vextq_u8(zero, t7, 4); // slli_si128(t7, 12)
            t3 = veorq_u8(t3, t7);
            let t2 = srli32(t3, 1);
            let t4 = srli32(t3, 2);
            let t5 = srli32(t3, 7);
            let t2 = veorq_u8(t2, t4);
            let t2 = veorq_u8(t2, t5);
            let t2 = veorq_u8(t2, t8);
            t3 = veorq_u8(t3, t2);
            veorq_u8(t6, t3)
        }
    }

    /// GCM-convention GF(2¹²⁸) product matching `super::super::gcm::gf_mul`.
    /// `vld1q_u8(x.to_le_bytes())` yields the byte-swapped representation
    /// directly (the x86 path achieves the same with an explicit `bswap`).
    #[target_feature(enable = "aes,neon")]
    pub(in super::super) unsafe fn gf_mul(x: u128, y: u128) -> u128 {
        unsafe {
            let a = vld1q_u8(x.to_le_bytes().as_ptr());
            let b = vld1q_u8(y.to_le_bytes().as_ptr());
            let p = gfmul(a, b);
            let mut out = [0u8; 16];
            vst1q_u8(out.as_mut_ptr(), p);
            u128::from_le_bytes(out)
        }
    }
}
