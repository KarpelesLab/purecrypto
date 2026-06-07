//! Hardware SHA-256 — the x86_64 SHA-NI extension via `core::arch::x86_64`.
//!
//! Produces identical state to the software `compress256_soft`, so it drops into
//! the compression dispatch unchanged; pinned by a differential test. The SHA
//! instructions are data-independent (constant-time). `std`-gated for runtime
//! feature detection; this module is compiled only on `std` + `x86_64` (gated at
//! the `mod` declaration in `super`).
//!
//! aarch64 `sha2` and SHA-512 hardware are a deliberate follow-up: their
//! intrinsic sequences need validation on real ARM hardware, which the x86
//! development host cannot provide, so those keep the (already fast) software
//! path for now.
#![allow(unsafe_code)]
#![allow(unused_unsafe)]

/// Whether the SHA-NI extension (and the SSE helpers it needs) is available.
pub(super) fn sha256_supported() -> bool {
    std::is_x86_feature_detected!("sha")
        && std::is_x86_feature_detected!("sse2")
        && std::is_x86_feature_detected!("ssse3")
        && std::is_x86_feature_detected!("sse4.1")
}

/// SHA-256 compression of one 64-byte block using SHA-NI.
pub(super) fn compress256(h: &mut [u32; 8], block: &[u8; 64]) {
    // SAFETY: only called after `sha256_supported()` confirmed the features the
    // target_feature function below requires.
    unsafe { x86::compress256(h, block) }
}

mod x86 {
    use crate::hash::sha256::K256;
    use core::arch::x86_64::*;

    /// SHA-NI single-block compression. Structured as a 16-group loop driven by
    /// `g % 4` so the message-schedule rotation is computed, not transcribed —
    /// the standard `sha256rnds2` / `sha256msg1` / `sha256msg2` sequence.
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub(super) unsafe fn compress256(state: &mut [u32; 8], block: &[u8; 64]) {
        unsafe {
            // Per-32-bit-word byte-reverse mask (block words are big-endian).
            let mask = _mm_set_epi64x(
                0x0c0d_0e0f_0809_0a0bu64 as i64,
                0x0405_0607_0001_0203u64 as i64,
            );

            // Load and rearrange the state into the SHA-NI ABEF / CDGH layout.
            let tmp0 = _mm_loadu_si128(state.as_ptr() as *const __m128i); // a b c d
            let s1_0 = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i); // e f g h
            let tmp = _mm_shuffle_epi32(tmp0, 0xB1); // c d a b
            let s1 = _mm_shuffle_epi32(s1_0, 0x1B); // h g f e
            let mut state0 = _mm_alignr_epi8(tmp, s1, 8); // ABEF
            let mut state1 = _mm_blend_epi16(s1, tmp, 0xF0); // CDGH
            let abef_save = state0;
            let cdgh_save = state1;

            // Load the four message vectors (16 bytes each), byte-reversed.
            let mut m = [
                _mm_shuffle_epi8(_mm_loadu_si128(block.as_ptr() as *const __m128i), mask),
                _mm_shuffle_epi8(
                    _mm_loadu_si128(block.as_ptr().add(16) as *const __m128i),
                    mask,
                ),
                _mm_shuffle_epi8(
                    _mm_loadu_si128(block.as_ptr().add(32) as *const __m128i),
                    mask,
                ),
                _mm_shuffle_epi8(
                    _mm_loadu_si128(block.as_ptr().add(48) as *const __m128i),
                    mask,
                ),
            ];

            let kptr = K256.as_ptr();
            for g in 0..16usize {
                let i = g % 4;
                // Round constants K[4g..4g+4] line up with the message lanes.
                let mut msg =
                    _mm_add_epi32(m[i], _mm_loadu_si128(kptr.add(4 * g) as *const __m128i));
                state1 = _mm_sha256rnds2_epu32(state1, state0, msg);

                // Message schedule (sha256msg2 half): groups 3..=14.
                if (3..=14).contains(&g) {
                    let tmp = _mm_alignr_epi8(m[i], m[(i + 3) % 4], 4);
                    m[(i + 1) % 4] = _mm_add_epi32(m[(i + 1) % 4], tmp);
                    m[(i + 1) % 4] = _mm_sha256msg2_epu32(m[(i + 1) % 4], m[i]);
                }

                msg = _mm_shuffle_epi32(msg, 0x0E);
                state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

                // Message schedule (sha256msg1 half): groups 1..=12.
                if (1..=12).contains(&g) {
                    m[(i + 3) % 4] = _mm_sha256msg1_epu32(m[(i + 3) % 4], m[i]);
                }
            }

            state0 = _mm_add_epi32(state0, abef_save);
            state1 = _mm_add_epi32(state1, cdgh_save);

            // Un-shuffle ABEF / CDGH back to a..h and store.
            let tmp = _mm_shuffle_epi32(state0, 0x1B); // FEBA
            let s1 = _mm_shuffle_epi32(state1, 0xB1); // DCHG
            let out0 = _mm_blend_epi16(tmp, s1, 0xF0); // DCBA
            let out1 = _mm_alignr_epi8(s1, tmp, 8); // HGFE
            _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, out0);
            _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, out1);
        }
    }
}
