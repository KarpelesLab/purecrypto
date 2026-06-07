//! Hardware GHASH — GF(2¹²⁸) multiply in the GCM bit convention via the x86_64
//! carryless-multiply instruction (PCLMULQDQ).
//!
//! Exposes a [`gf_mul`] that returns the *same* value as the constant-time
//! software multiply in `super::gcm`, so it drops into the GHASH loop unchanged.
//! PCLMULQDQ is data-independent (constant-time), so the GCM hash subkey is not
//! exposed through timing. Correctness is pinned by a differential test against
//! the software reference (see the `gcm` tests).
//!
//! aarch64 PMULL GHASH is a deliberate follow-up: it requires bit-order-exact
//! reduction code that cannot be validated on the x86 development host, so until
//! it can be exercised on real ARM hardware the aarch64 build keeps the
//! constant-time software GHASH (its AES is still hardware-accelerated, which is
//! the dominant GCM cost).
//!
//! This module is compiled only on `std` + `x86_64` (gated at the `mod`
//! declaration in `super`).
#![allow(unsafe_code)]
#![allow(unused_unsafe)]

pub(super) use x86::gf_mul;

/// Whether the PCLMULQDQ GHASH backend is available on this CPU.
pub(super) fn supported() -> bool {
    std::is_x86_feature_detected!("pclmulqdq")
        && std::is_x86_feature_detected!("sse2")
        && std::is_x86_feature_detected!("ssse3")
}

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
