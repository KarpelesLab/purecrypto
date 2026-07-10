//! Multi-buffer SHA-512 — four independent message streams compressed in
//! parallel across the four 64-bit lanes of an AVX2 `__m256i`.
//!
//! The 64-bit sibling of [`super::sha256_mb`]: a single SHA-512 stream is
//! inherently serial, but hashing *independent* messages has no cross-lane
//! data dependency, so the round function and message schedule vectorise
//! perfectly 4-wide. The consumer is SLH-DSA's SHA-2 n=24/32 parameter sets,
//! whose tweakable hash `H` (FORS/Merkle node merges) is SHA-512 — batches of
//! independent sibling merges beat four serial compressions.
//!
//! The kernel exposes a single primitive, [`compress4`], which applies one
//! 128-byte-block compression to four independent `(state, block)` pairs. The
//! per-lane arithmetic is byte-for-byte the scalar [`super::sha512`]
//! compression (same `Σ`/`σ`/`Ch`/`Maj`, same constants), executed 4-wide;
//! this is pinned by a differential test against the scalar path. Callers
//! assemble the padded blocks and manage the lane states. x86_64 + AVX2 only.
#![allow(unsafe_code)]

/// Lanes processed in parallel (AVX2 64-bit lane count).
pub(crate) const LANES: usize = 4;

/// Whether the multi-buffer SHA-512 backend is available on this CPU.
#[cfg(target_arch = "x86_64")]
pub(crate) fn supported() -> bool {
    std::is_x86_feature_detected!("avx2")
}

/// Applies one SHA-512 block compression to each of the four `(state, block)`
/// lanes in parallel: `states[l]` is folded with `blocks[l]` for every lane `l`.
#[cfg(target_arch = "x86_64")]
pub(crate) fn compress4(states: &mut [[u64; 8]; LANES], blocks: &[[u8; 128]; LANES]) {
    // SAFETY: `supported()` (checked by the caller) confirmed AVX2.
    unsafe { avx2::compress4(states, blocks) }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use crate::hash::sha512::K512;
    use core::arch::x86_64::*;

    #[inline(always)]
    unsafe fn ror<const R: i32, const L: i32>(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi64::<R>(x), _mm256_slli_epi64::<L>(x)) }
    }
    #[inline(always)]
    unsafe fn add(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_add_epi64(a, b) }
    }
    #[inline(always)]
    unsafe fn xor(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_xor_si256(a, b) }
    }

    /// In-place 4x4 transpose of four `__m256i` viewed as `u64` lanes.
    #[inline(always)]
    unsafe fn transpose4(v: &mut [__m256i; 4]) {
        unsafe {
            let t0 = _mm256_unpacklo_epi64(v[0], v[1]); // [a0 b0 a2 b2]
            let t1 = _mm256_unpackhi_epi64(v[0], v[1]); // [a1 b1 a3 b3]
            let t2 = _mm256_unpacklo_epi64(v[2], v[3]); // [c0 d0 c2 d2]
            let t3 = _mm256_unpackhi_epi64(v[2], v[3]); // [c1 d1 c3 d3]
            v[0] = _mm256_permute2x128_si256::<0x20>(t0, t2); // [a0 b0 c0 d0]
            v[1] = _mm256_permute2x128_si256::<0x20>(t1, t3); // [a1 b1 c1 d1]
            v[2] = _mm256_permute2x128_si256::<0x31>(t0, t2); // [a2 b2 c2 d2]
            v[3] = _mm256_permute2x128_si256::<0x31>(t1, t3); // [a3 b3 c3 d3]
        }
    }

    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn compress4(states: &mut [[u64; 8]; 4], blocks: &[[u8; 128]; 4]) {
        unsafe {
            // Load the 4 lane states (row = lane, two vectors per lane) and
            // transpose to word-major vectors
            // `h[word] = [state0[word], …, state3[word]]`.
            let mut lo = [_mm256_setzero_si256(); 4];
            let mut hi = [_mm256_setzero_si256(); 4];
            for lane in 0..4 {
                let p = states[lane].as_ptr();
                lo[lane] = _mm256_loadu_si256(p as *const __m256i);
                hi[lane] = _mm256_loadu_si256(p.add(4) as *const __m256i);
            }
            transpose4(&mut lo);
            transpose4(&mut hi);
            let mut h = [_mm256_setzero_si256(); 8];
            h[..4].copy_from_slice(&lo);
            h[4..].copy_from_slice(&hi);
            let h0 = h;

            // Per-128-bit-lane byte-reverse mask: each big-endian 64-bit word
            // is byte-swapped on load before the transpose.
            let bswap = _mm256_set_epi8(
                8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, // high 128
                8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, // low 128
            );

            // Load and transpose the 4 message blocks into 16 word-vectors,
            // one 32-byte quarter (4 words) at a time.
            let mut w = [_mm256_setzero_si256(); 80];
            for q in 0..4 {
                let mut quad = [_mm256_setzero_si256(); 4];
                for (lane, row) in quad.iter_mut().enumerate() {
                    let p = blocks[lane].as_ptr().add(32 * q);
                    *row = _mm256_shuffle_epi8(_mm256_loadu_si256(p as *const __m256i), bswap);
                }
                transpose4(&mut quad);
                w[4 * q..4 * q + 4].copy_from_slice(&quad);
            }

            // Message schedule (per-lane independent → trivially 4-wide).
            for t in 16..80 {
                let s0 = xor(
                    xor(ror::<1, 63>(w[t - 15]), ror::<8, 56>(w[t - 15])),
                    _mm256_srli_epi64::<7>(w[t - 15]),
                );
                let s1 = xor(
                    xor(ror::<19, 45>(w[t - 2]), ror::<61, 3>(w[t - 2])),
                    _mm256_srli_epi64::<6>(w[t - 2]),
                );
                w[t] = add(add(w[t - 16], s0), add(w[t - 7], s1));
            }

            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] =
                [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];

            for t in 0..80 {
                let s1 = xor(xor(ror::<14, 50>(e), ror::<18, 46>(e)), ror::<41, 23>(e));
                let ch = xor(_mm256_and_si256(e, f), _mm256_andnot_si256(e, g));
                let kt = _mm256_set1_epi64x(K512[t] as i64);
                let t1 = add(add(add(hh, s1), add(ch, kt)), w[t]);
                let s0 = xor(xor(ror::<28, 36>(a), ror::<34, 30>(a)), ror::<39, 25>(a));
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

            let mut out_lo = [add(a, h0[0]), add(b, h0[1]), add(c, h0[2]), add(d, h0[3])];
            let mut out_hi = [add(e, h0[4]), add(f, h0[5]), add(g, h0[6]), add(hh, h0[7])];
            // Transpose word-major results back to per-lane states and store.
            transpose4(&mut out_lo);
            transpose4(&mut out_hi);
            for lane in 0..4 {
                let p = states[lane].as_mut_ptr();
                _mm256_storeu_si256(p as *mut __m256i, out_lo[lane]);
                _mm256_storeu_si256(p.add(4) as *mut __m256i, out_hi[lane]);
            }
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use crate::hash::sha512::compress512_soft as soft;

    #[test]
    fn compress4_matches_scalar() {
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
            // Random independent states per lane, folded over three
            // consecutive random blocks (multi-block chaining).
            let mut states = [[0u64; 8]; LANES];
            for lane in states.iter_mut() {
                for w in lane.iter_mut() {
                    *w = next();
                }
            }
            let mut want = states;
            for _block in 0..3 {
                let mut blocks = [[0u8; 128]; LANES];
                for lane in blocks.iter_mut() {
                    for byte in lane.iter_mut() {
                        *byte = (next() >> 23) as u8;
                    }
                }
                for lane in 0..LANES {
                    soft(&mut want[lane], &blocks[lane]);
                }
                compress4(&mut states, &blocks);
            }
            assert_eq!(states, want);
        }
    }
}
