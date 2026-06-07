//! Hardware SHA-2 — SHA-256 via the x86_64 SHA-NI extension or the aarch64
//! `sha2` extension, and SHA-512 via the aarch64 `sha512` extension (there is no
//! broadly-available x86 SHA-512 instruction, so x86 keeps the software path).
//!
//! Each path produces identical state to the `*_soft` software compression, so
//! it drops into the dispatch unchanged; pinned by differential tests. The SHA
//! instructions are data-independent (constant-time). Compiled only on `std` +
//! (`x86_64` | `aarch64`), gated at the `mod` declaration in `super`.
#![allow(unsafe_code)]
#![allow(unused_unsafe)]

/// Whether a hardware SHA-256 backend is available.
#[cfg(target_arch = "x86_64")]
pub(super) fn sha256_supported() -> bool {
    std::is_x86_feature_detected!("sha")
        && std::is_x86_feature_detected!("sse2")
        && std::is_x86_feature_detected!("ssse3")
        && std::is_x86_feature_detected!("sse4.1")
}
#[cfg(target_arch = "aarch64")]
pub(super) fn sha256_supported() -> bool {
    std::arch::is_aarch64_feature_detected!("sha2")
}

/// SHA-256 compression of one 64-byte block, dispatched to the active backend.
pub(super) fn compress256(h: &mut [u32; 8], block: &[u8; 64]) {
    // SAFETY: only called after `sha256_supported()` confirmed the features.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        x86::compress256(h, block)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        arm::compress256(h, block)
    }
}

/// Whether a hardware SHA-512 backend is available (aarch64 `sha512` only; x86
/// has no SHA-512 instruction, so this is defined only on aarch64 where the
/// SHA-512 dispatch references it).
#[cfg(target_arch = "aarch64")]
pub(super) fn sha512_supported() -> bool {
    // The SHA512 instructions are reported under the FEAT_SHA512 / "sha3" gate.
    std::arch::is_aarch64_feature_detected!("sha3")
}

/// SHA-512 compression of one 128-byte block (aarch64 hardware only; never
/// called on x86, where [`sha512_supported`] is `false`).
#[cfg(target_arch = "aarch64")]
pub(super) fn compress512(h: &mut [u64; 8], block: &[u8; 128]) {
    // SAFETY: only called after `sha512_supported()` confirmed FEAT_SHA512.
    unsafe { arm::compress512(h, block) }
}

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "aarch64")]
mod arm {
    use crate::hash::sha256::K256;
    use crate::hash::sha512::K512;
    use core::arch::aarch64::*;

    /// SHA-256 compression of one 64-byte block using the ARMv8 `sha2`
    /// extension. State is `abcd`/`efgh`; messages are byte-reversed per 32-bit
    /// word. A 16-group loop keyed on `g % 4` evolves the schedule with
    /// `sha256su0`/`sha256su1` (the round key uses the pre-update message words).
    #[target_feature(enable = "sha2")]
    pub(super) unsafe fn compress256(state: &mut [u32; 8], block: &[u8; 64]) {
        unsafe {
            let mut abcd = vld1q_u32(state.as_ptr());
            let mut efgh = vld1q_u32(state.as_ptr().add(4));
            let abcd0 = abcd;
            let efgh0 = efgh;
            let mut m = [
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr()))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(16)))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(32)))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(48)))),
            ];
            for g in 0..16usize {
                let i = g % 4;
                let wk = vaddq_u32(m[i], vld1q_u32(K256.as_ptr().add(4 * g)));
                if g < 12 {
                    m[i] = vsha256su1q_u32(
                        vsha256su0q_u32(m[i], m[(i + 1) % 4]),
                        m[(i + 2) % 4],
                        m[(i + 3) % 4],
                    );
                }
                let tmp = abcd;
                abcd = vsha256hq_u32(abcd, efgh, wk);
                efgh = vsha256h2q_u32(efgh, tmp, wk);
            }
            vst1q_u32(state.as_mut_ptr(), vaddq_u32(abcd, abcd0));
            vst1q_u32(state.as_mut_ptr().add(4), vaddq_u32(efgh, efgh0));
        }
    }

    /// SHA-512 compression of one 128-byte block using the ARMv8 `sha512`
    /// extension. Ported from RustCrypto's `sha2` aarch64 backend (MIT/Apache):
    /// state held as `ab`/`cd`/`ef`/`gh` (`uint64x2_t`), 8 byte-reversed message
    /// vectors, the first 16 rounds unrolled then 64 more in groups of 16 with
    /// `sha512su0`/`sha512su1` scheduling.
    #[target_feature(enable = "sha3")]
    pub(super) unsafe fn compress512(state: &mut [u64; 8], block: &[u8; 128]) {
        unsafe {
            let mut ab = vld1q_u64(state.as_ptr());
            let mut cd = vld1q_u64(state.as_ptr().add(2));
            let mut ef = vld1q_u64(state.as_ptr().add(4));
            let mut gh = vld1q_u64(state.as_ptr().add(6));
            let (ab0, cd0, ef0, gh0) = (ab, cd, ef, gh);

            let ld = |o: usize| vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block.as_ptr().add(o))));
            let mut s0 = ld(0);
            let mut s1 = ld(16);
            let mut s2 = ld(32);
            let mut s3 = ld(48);
            let mut s4 = ld(64);
            let mut s5 = ld(80);
            let mut s6 = ld(96);
            let mut s7 = ld(112);
            let k = |i: usize| vld1q_u64(K512.as_ptr().add(i));

            let mut isum = vaddq_u64(s0, k(0));
            let mut sum = vaddq_u64(vextq_u64(isum, isum, 1), gh);
            let mut it = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
            gh = vsha512h2q_u64(it, cd, ab);
            cd = vaddq_u64(cd, it);
            isum = vaddq_u64(s1, k(2));
            sum = vaddq_u64(vextq_u64(isum, isum, 1), ef);
            it = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
            ef = vsha512h2q_u64(it, ab, gh);
            ab = vaddq_u64(ab, it);
            isum = vaddq_u64(s2, k(4));
            sum = vaddq_u64(vextq_u64(isum, isum, 1), cd);
            it = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
            cd = vsha512h2q_u64(it, gh, ef);
            gh = vaddq_u64(gh, it);
            isum = vaddq_u64(s3, k(6));
            sum = vaddq_u64(vextq_u64(isum, isum, 1), ab);
            it = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
            ab = vsha512h2q_u64(it, ef, cd);
            ef = vaddq_u64(ef, it);
            isum = vaddq_u64(s4, k(8));
            sum = vaddq_u64(vextq_u64(isum, isum, 1), gh);
            it = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
            gh = vsha512h2q_u64(it, cd, ab);
            cd = vaddq_u64(cd, it);
            isum = vaddq_u64(s5, k(10));
            sum = vaddq_u64(vextq_u64(isum, isum, 1), ef);
            it = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
            ef = vsha512h2q_u64(it, ab, gh);
            ab = vaddq_u64(ab, it);
            isum = vaddq_u64(s6, k(12));
            sum = vaddq_u64(vextq_u64(isum, isum, 1), cd);
            it = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
            cd = vsha512h2q_u64(it, gh, ef);
            gh = vaddq_u64(gh, it);
            isum = vaddq_u64(s7, k(14));
            sum = vaddq_u64(vextq_u64(isum, isum, 1), ab);
            it = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
            ab = vsha512h2q_u64(it, ef, cd);
            ef = vaddq_u64(ef, it);

            let mut t = 16usize;
            while t < 80 {
                s0 = vsha512su1q_u64(vsha512su0q_u64(s0, s1), s7, vextq_u64(s4, s5, 1));
                isum = vaddq_u64(s0, k(t));
                sum = vaddq_u64(vextq_u64(isum, isum, 1), gh);
                it = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
                gh = vsha512h2q_u64(it, cd, ab);
                cd = vaddq_u64(cd, it);
                s1 = vsha512su1q_u64(vsha512su0q_u64(s1, s2), s0, vextq_u64(s5, s6, 1));
                isum = vaddq_u64(s1, k(t + 2));
                sum = vaddq_u64(vextq_u64(isum, isum, 1), ef);
                it = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
                ef = vsha512h2q_u64(it, ab, gh);
                ab = vaddq_u64(ab, it);
                s2 = vsha512su1q_u64(vsha512su0q_u64(s2, s3), s1, vextq_u64(s6, s7, 1));
                isum = vaddq_u64(s2, k(t + 4));
                sum = vaddq_u64(vextq_u64(isum, isum, 1), cd);
                it = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
                cd = vsha512h2q_u64(it, gh, ef);
                gh = vaddq_u64(gh, it);
                s3 = vsha512su1q_u64(vsha512su0q_u64(s3, s4), s2, vextq_u64(s7, s0, 1));
                isum = vaddq_u64(s3, k(t + 6));
                sum = vaddq_u64(vextq_u64(isum, isum, 1), ab);
                it = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
                ab = vsha512h2q_u64(it, ef, cd);
                ef = vaddq_u64(ef, it);
                s4 = vsha512su1q_u64(vsha512su0q_u64(s4, s5), s3, vextq_u64(s0, s1, 1));
                isum = vaddq_u64(s4, k(t + 8));
                sum = vaddq_u64(vextq_u64(isum, isum, 1), gh);
                it = vsha512hq_u64(sum, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1));
                gh = vsha512h2q_u64(it, cd, ab);
                cd = vaddq_u64(cd, it);
                s5 = vsha512su1q_u64(vsha512su0q_u64(s5, s6), s4, vextq_u64(s1, s2, 1));
                isum = vaddq_u64(s5, k(t + 10));
                sum = vaddq_u64(vextq_u64(isum, isum, 1), ef);
                it = vsha512hq_u64(sum, vextq_u64(cd, ef, 1), vextq_u64(ab, cd, 1));
                ef = vsha512h2q_u64(it, ab, gh);
                ab = vaddq_u64(ab, it);
                s6 = vsha512su1q_u64(vsha512su0q_u64(s6, s7), s5, vextq_u64(s2, s3, 1));
                isum = vaddq_u64(s6, k(t + 12));
                sum = vaddq_u64(vextq_u64(isum, isum, 1), cd);
                it = vsha512hq_u64(sum, vextq_u64(ab, cd, 1), vextq_u64(gh, ab, 1));
                cd = vsha512h2q_u64(it, gh, ef);
                gh = vaddq_u64(gh, it);
                s7 = vsha512su1q_u64(vsha512su0q_u64(s7, s0), s6, vextq_u64(s3, s4, 1));
                isum = vaddq_u64(s7, k(t + 14));
                sum = vaddq_u64(vextq_u64(isum, isum, 1), ab);
                it = vsha512hq_u64(sum, vextq_u64(gh, ab, 1), vextq_u64(ef, gh, 1));
                ab = vsha512h2q_u64(it, ef, cd);
                ef = vaddq_u64(ef, it);
                t += 16;
            }

            vst1q_u64(state.as_mut_ptr(), vaddq_u64(ab, ab0));
            vst1q_u64(state.as_mut_ptr().add(2), vaddq_u64(cd, cd0));
            vst1q_u64(state.as_mut_ptr().add(4), vaddq_u64(ef, ef0));
            vst1q_u64(state.as_mut_ptr().add(6), vaddq_u64(gh, gh0));
        }
    }
}
