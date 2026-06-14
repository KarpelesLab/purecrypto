//! Multi-buffer SHA-256 — eight independent message streams compressed in
//! parallel across the eight 32-bit lanes of an AVX2 `__m256i`.
//!
//! Unlike a single SHA-256 stream (whose round chain and SHA-NI kernel are
//! inherently serial), hashing *independent* messages has no cross-lane data
//! dependency, so both the round function and the message schedule vectorise
//! perfectly 8-wide. This is the right primitive for the hash-based signatures
//! (LMS/XMSS/SLH-DSA), whose WOTS+ chains and Merkle trees evaluate enormous
//! numbers of independent SHA-256 compressions — there a multi-buffer kernel
//! beats calling the serial SHA-NI kernel eight times.
//!
//! The kernel exposes a single primitive, [`compress8`], which applies one
//! 64-byte-block compression to eight independent `(state, block)` pairs. The
//! per-lane arithmetic is byte-for-byte the scalar [`super::sha256`] compression
//! (same `Σ`/`σ`/`Ch`/`Maj`, same constants), executed 8-wide; this is pinned by
//! a differential test against the scalar path. Callers (e.g. the WOTS+ batcher)
//! assemble the padded blocks and manage the lane states. x86_64 + AVX2 only.
#![allow(unsafe_code)]

/// Lanes processed in parallel (AVX2 32-bit lane count).
pub(crate) const LANES: usize = 8;

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

    /// In-place 8x8 transpose of eight `__m256i` (each holding 8 `u32`). On entry
    /// `rows[r]` is the r-th row; on exit `rows[c]` is the c-th column.
    #[inline(always)]
    unsafe fn transpose8(rows: &mut [__m256i; 8]) {
        unsafe {
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
    }

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

    #[test]
    fn compress8_matches_scalar() {
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
}
