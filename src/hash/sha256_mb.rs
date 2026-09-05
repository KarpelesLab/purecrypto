//! Multi-buffer SHA-256 — eight or sixteen independent message streams
//! compressed in parallel across the 32-bit lanes of an AVX2 `__m256i` or an
//! AVX-512 `__m512i`.
//!
//! Unlike a single SHA-256 stream (whose round chain and SHA-NI kernel are
//! inherently serial), hashing *independent* messages has no cross-lane data
//! dependency, so both the round function and the message schedule vectorise
//! perfectly 8-wide. This is the right primitive for the hash-based signatures
//! (LMS/XMSS/SLH-DSA), whose WOTS+ chains and Merkle trees evaluate enormous
//! numbers of independent SHA-256 compressions — there a multi-buffer kernel
//! beats calling the serial SHA-NI kernel eight times.
//!
//! The kernel exposes [`compress8`] and its 16-lane AVX-512 counterpart
//! [`compress16`], which apply one
//! 64-byte-block compression to that many independent `(state, block)` pairs. The
//! per-lane arithmetic is byte-for-byte the scalar [`super::sha256`] compression
//! (same `Σ`/`σ`/`Ch`/`Maj`, same constants), executed 8-wide; this is pinned by
//! a differential test against the scalar path. Callers (e.g. the WOTS+ batcher)
//! assemble the padded blocks and manage the lane states. x86_64 + AVX2 only.
#![allow(unsafe_code)]

/// Lanes processed in parallel (AVX2 32-bit lane count).
pub(crate) const LANES: usize = 8;

/// Lanes processed in parallel by the AVX-512 kernel.
pub(crate) const LANES16: usize = 16;

/// Whether the 16-lane multi-buffer SHA-256 backend is available.
///
/// Needs AVX-512BW as well as F: the big-endian word load uses `vpshufb` on a
/// zmm register, which is a BW instruction.
#[cfg(target_arch = "x86_64")]
pub(crate) fn supported16() -> bool {
    std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512bw")
}

/// Applies one SHA-256 block compression to each of the sixteen
/// `(state, block)` lanes in parallel. Same contract as [`compress8`].
#[cfg(target_arch = "x86_64")]
pub(crate) fn compress16(states: &mut [[u32; 8]; LANES16], blocks: &[[u8; 64]; LANES16]) {
    // SAFETY: `supported16()` (checked by the caller) confirmed AVX-512F+BW.
    unsafe { avx512::compress16(states, blocks) }
}

/// Whether the multi-buffer SHA-256 backend is available on this CPU.
#[cfg(target_arch = "x86_64")]
pub(crate) fn supported() -> bool {
    std::is_x86_feature_detected!("avx2")
}

/// Applies one SHA-256 block compression to each of the eight `(state, block)`
/// lanes in parallel: `states[l]` is folded with `blocks[l]` for every lane `l`.
#[cfg(target_arch = "x86_64")]
pub(crate) fn compress8(states: &mut [[u32; 8]; LANES], blocks: &[[u8; 64]; LANES]) {
    // SAFETY: `supported()` (checked by the caller) confirmed AVX2.
    unsafe { avx2::compress8(states, blocks) }
}

#[cfg(target_arch = "x86_64")]
mod avx512 {
    use crate::hash::sha256::K256;
    use crate::hash::simd_x86::transpose16_epi32 as transpose16;
    use core::arch::x86_64::*;

    /// Rotate-right each 32-bit lane — one `vprord`.
    #[inline(always)]
    unsafe fn ror<const R: i32>(x: __m512i) -> __m512i {
        unsafe { _mm512_ror_epi32::<R>(x) }
    }
    #[inline(always)]
    unsafe fn add(a: __m512i, b: __m512i) -> __m512i {
        unsafe { _mm512_add_epi32(a, b) }
    }
    /// `a ^ b ^ c` in one `vpternlogd` (the Σ/σ shape).
    #[inline(always)]
    unsafe fn xor3(a: __m512i, b: __m512i, c: __m512i) -> __m512i {
        unsafe { _mm512_ternarylogic_epi32::<0x96>(a, b, c) }
    }
    /// `Ch(e, f, g) = (e & f) ^ (!e & g)` in one `vpternlogd`.
    #[inline(always)]
    unsafe fn ch(e: __m512i, f: __m512i, g: __m512i) -> __m512i {
        unsafe { _mm512_ternarylogic_epi32::<0xCA>(e, f, g) }
    }
    /// `Maj(a, b, c) = (a & b) ^ (a & c) ^ (b & c)` in one `vpternlogd`.
    #[inline(always)]
    unsafe fn maj(a: __m512i, b: __m512i, c: __m512i) -> __m512i {
        unsafe { _mm512_ternarylogic_epi32::<0xE8>(a, b, c) }
    }

    /// Sixteen-lane multi-buffer SHA-256.
    ///
    /// Beyond the doubled lane count, AVX-512 shortens the round itself: `vprord`
    /// rotates in one instruction, and `vpternlogd` evaluates each of `Ch`, `Maj`
    /// and the three-way Σ/σ XORs in one, where AVX2 needs 3, 5 and 2
    /// respectively. The per-lane result is identical to the scalar compression;
    /// a differential test pins that.
    #[target_feature(enable = "avx512f,avx512bw")]
    pub(crate) unsafe fn compress16(states: &mut [[u32; 8]; 16], blocks: &[[u8; 64]; 16]) {
        unsafe {
            // Lane states are 8 words each; load into the low half of a row and
            // transpose the (padded) 16x16 matrix, so rows 0..8 come out as the
            // word-major vectors and rows 8..16 are the zero padding.
            let mut h = [_mm512_setzero_si512(); 16];
            for (lane, hrow) in h.iter_mut().enumerate() {
                *hrow = _mm512_maskz_loadu_epi32(0x00ff, states[lane].as_ptr() as *const i32);
            }
            transpose16(&mut h);
            let h0 = h;

            // Per-128-bit-lane byte-reverse mask, replicated across all four
            // lanes: SHA-256 words are big-endian.
            let bswap = _mm512_set_epi8(
                12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, //
                12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, //
                12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, //
                12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
            );

            // A 64-byte SHA-256 block is exactly one `__m512i`, so this is one
            // load per lane and a single transpose (AVX2 needs two halves).
            let mut w = [_mm512_setzero_si512(); 64];
            let mut rows = [_mm512_setzero_si512(); 16];
            for (lane, row) in rows.iter_mut().enumerate() {
                let p = blocks[lane].as_ptr();
                *row = _mm512_shuffle_epi8(_mm512_loadu_si512(p as *const _), bswap);
            }
            transpose16(&mut rows);
            w[..16].copy_from_slice(&rows);

            // Message schedule (per-lane independent -> trivially 16-wide).
            for t in 16..64 {
                let s0 = xor3(
                    ror::<7>(w[t - 15]),
                    ror::<18>(w[t - 15]),
                    _mm512_srli_epi32::<3>(w[t - 15]),
                );
                let s1 = xor3(
                    ror::<17>(w[t - 2]),
                    ror::<19>(w[t - 2]),
                    _mm512_srli_epi32::<10>(w[t - 2]),
                );
                w[t] = add(add(w[t - 16], s0), add(w[t - 7], s1));
            }

            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] =
                [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];

            for (t, wt) in w.iter().enumerate() {
                let s1 = xor3(ror::<6>(e), ror::<11>(e), ror::<25>(e));
                let kt = _mm512_set1_epi32(K256[t] as i32);
                let t1 = add(add(add(hh, s1), add(ch(e, f, g), kt)), *wt);
                let s0 = xor3(ror::<2>(a), ror::<13>(a), ror::<22>(a));
                let t2 = add(s0, maj(a, b, c));
                hh = g;
                g = f;
                f = e;
                e = add(d, t1);
                d = c;
                c = b;
                b = a;
                a = add(t1, t2);
            }

            let mut out = [_mm512_setzero_si512(); 16];
            out[0] = add(a, h0[0]);
            out[1] = add(b, h0[1]);
            out[2] = add(c, h0[2]);
            out[3] = add(d, h0[3]);
            out[4] = add(e, h0[4]);
            out[5] = add(f, h0[5]);
            out[6] = add(g, h0[6]);
            out[7] = add(hh, h0[7]);
            // Transpose word-major results back to per-lane states; rows 8..16
            // are the zero padding and are masked off on store.
            transpose16(&mut out);
            for (lane, orow) in out.iter().enumerate() {
                _mm512_mask_storeu_epi32(states[lane].as_mut_ptr() as *mut i32, 0x00ff, *orow);
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use crate::hash::sha256::K256;
    use core::arch::x86_64::*;

    #[inline(always)]
    unsafe fn ror<const R: i32, const L: i32>(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<R>(x), _mm256_slli_epi32::<L>(x)) }
    }
    #[inline(always)]
    unsafe fn add(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_add_epi32(a, b) }
    }
    #[inline(always)]
    unsafe fn xor(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_xor_si256(a, b) }
    }

    // In-place 8x8 transpose of eight `__m256i` (each holding 8 `u32`), shared
    // with the BLAKE3 8-way kernel.
    use crate::hash::simd_x86::transpose8_epi32 as transpose8;

    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn compress8(states: &mut [[u32; 8]; 8], blocks: &[[u8; 64]; 8]) {
        unsafe {
            // Load the 8 lane states (row = lane) and transpose to word-major
            // vectors `h[word] = [state0[word], …, state7[word]]`.
            let mut h = [_mm256_setzero_si256(); 8];
            for (lane, hrow) in h.iter_mut().enumerate() {
                *hrow = _mm256_loadu_si256(states[lane].as_ptr() as *const __m256i);
            }
            transpose8(&mut h);
            let h0 = h;

            // Per-128-bit-lane byte-reverse mask: each big-endian 32-bit word is
            // byte-swapped on load before the transpose.
            let bswap = _mm256_set_epi8(
                12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, // high 128
                12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, // low 128
            );

            // Load and transpose the 8 message blocks into 16 word-vectors.
            let mut lo = [_mm256_setzero_si256(); 8];
            let mut hi = [_mm256_setzero_si256(); 8];
            for lane in 0..8 {
                let p = blocks[lane].as_ptr();
                lo[lane] = _mm256_shuffle_epi8(_mm256_loadu_si256(p as *const __m256i), bswap);
                hi[lane] =
                    _mm256_shuffle_epi8(_mm256_loadu_si256(p.add(32) as *const __m256i), bswap);
            }
            transpose8(&mut lo);
            transpose8(&mut hi);
            let mut w = [_mm256_setzero_si256(); 64];
            w[..8].copy_from_slice(&lo);
            w[8..16].copy_from_slice(&hi);

            // Message schedule (per-lane independent → trivially 8-wide).
            for t in 16..64 {
                let s0 = xor(
                    xor(ror::<7, 25>(w[t - 15]), ror::<18, 14>(w[t - 15])),
                    _mm256_srli_epi32::<3>(w[t - 15]),
                );
                let s1 = xor(
                    xor(ror::<17, 15>(w[t - 2]), ror::<19, 13>(w[t - 2])),
                    _mm256_srli_epi32::<10>(w[t - 2]),
                );
                w[t] = add(add(w[t - 16], s0), add(w[t - 7], s1));
            }

            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] =
                [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];

            for t in 0..64 {
                let s1 = xor(xor(ror::<6, 26>(e), ror::<11, 21>(e)), ror::<25, 7>(e));
                let ch = xor(_mm256_and_si256(e, f), _mm256_andnot_si256(e, g));
                let kt = _mm256_set1_epi32(K256[t] as i32);
                let t1 = add(add(add(hh, s1), add(ch, kt)), w[t]);
                let s0 = xor(xor(ror::<2, 30>(a), ror::<13, 19>(a)), ror::<22, 10>(a));
                let maj = xor(
                    xor(_mm256_and_si256(a, b), _mm256_and_si256(a, c)),
                    _mm256_and_si256(b, c),
                );
                let t2 = add(s0, maj);
                hh = g;
                g = f;
                f = e;
                e = add(d, t1);
                d = c;
                c = b;
                b = a;
                a = add(t1, t2);
            }

            let mut out = [
                add(a, h0[0]),
                add(b, h0[1]),
                add(c, h0[2]),
                add(d, h0[3]),
                add(e, h0[4]),
                add(f, h0[5]),
                add(g, h0[6]),
                add(hh, h0[7]),
            ];
            // Transpose word-major results back to per-lane states and store.
            transpose8(&mut out);
            for (lane, orow) in out.iter().enumerate() {
                _mm256_storeu_si256(states[lane].as_mut_ptr() as *mut __m256i, *orow);
            }
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use crate::hash::sha256::compress256_soft as soft;

    /// Both wide kernels must reproduce the scalar compression exactly, for
    /// every lane. Each is driven directly (there is no dispatcher here, but
    /// keeping them separate means an AVX-512 host still covers the 8-lane
    /// kernel that non-AVX-512 CPUs will actually run).
    #[test]
    fn compress8_matches_scalar() {
        std::eprintln!(
            "sha256_mb: avx2={} avx512={}",
            if supported() { "RUNNING" } else { "SKIPPED" },
            if supported16() { "RUNNING" } else { "SKIPPED" },
        );
        if !supported() {
            return;
        }
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..200 {
            // Random independent states and blocks per lane.
            let mut states = [[0u32; 8]; LANES];
            let mut blocks = [[0u8; 64]; LANES];
            for lane in 0..LANES {
                for w in states[lane].iter_mut() {
                    *w = next() as u32;
                }
                for byte in blocks[lane].iter_mut() {
                    *byte = (next() >> 17) as u8;
                }
            }
            let mut want = states;
            for lane in 0..LANES {
                soft(&mut want[lane], &blocks[lane]);
            }
            compress8(&mut states, &blocks);
            assert_eq!(states, want);
        }
    }

    #[test]
    fn compress16_matches_scalar() {
        if !supported16() {
            std::eprintln!("sha256_mb compress16: SKIPPED (no AVX-512F on this CPU)");
            return;
        }
        let mut s = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..200 {
            let mut states = [[0u32; 8]; LANES16];
            let mut blocks = [[0u8; 64]; LANES16];
            for lane in 0..LANES16 {
                for w in states[lane].iter_mut() {
                    *w = next() as u32;
                }
                for byte in blocks[lane].iter_mut() {
                    *byte = (next() >> 17) as u8;
                }
            }
            let mut want = states;
            for lane in 0..LANES16 {
                soft(&mut want[lane], &blocks[lane]);
            }
            compress16(&mut states, &blocks);
            assert_eq!(states, want);
        }
    }
}
