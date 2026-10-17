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
//! assemble the padded blocks and manage the lane states.
//!
//! On aarch64 the FEAT_SHA512 instructions are serial per stream, but two
//! independent streams pipeline in the SHA unit, so [`compress2`]
//! interleaves two copies of the straight-line `sha_hw` kernel; callers pick
//! the width from [`supported`] / [`supported2`].
#![allow(unsafe_code)]
#![allow(unused_unsafe)]
// Each architecture has only its own kernel's callers; the other width's
// names are kept so callers can be written once against both.
#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

/// Lanes processed in parallel (AVX2 64-bit lane count).
pub(crate) const LANES: usize = 4;

/// Lanes processed in parallel by the aarch64 two-stream kernel.
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) const LANES2: usize = 2;

/// Whether the two-stream aarch64 SHA-512 backend is available (FEAT_SHA512,
/// reported under the `sha3` gate; `false` elsewhere).
#[cfg(target_arch = "aarch64")]
pub(crate) fn supported2() -> bool {
    !crate::ct::force_portable() && std::arch::is_aarch64_feature_detected!("sha3")
}
#[cfg(not(target_arch = "aarch64"))]
#[allow(dead_code)]
pub(crate) fn supported2() -> bool {
    false
}

/// Applies one SHA-512 block compression to each of the two `(state, block)`
/// lanes, interleaved on the aarch64 SHA-512 instructions. Same contract as
/// [`compress4`].
///
/// Callers are expected to have checked [`supported2`]; this re-checks the
/// (cached) CPU feature flag and panics rather than executing the kernel on
/// a CPU without FEAT_SHA512, so it is safe to call unconditionally.
#[cfg(target_arch = "aarch64")]
pub(crate) fn compress2(states: &mut [[u64; 8]; LANES2], blocks: &[[u8; 128]; LANES2]) {
    assert!(
        supported2(),
        "sha512_mb::compress2 called on a CPU without FEAT_SHA512; check supported2() first"
    );
    // SAFETY: `supported2()` just confirmed FEAT_SHA512 on this CPU, and the
    // kernel has no other preconditions (the array types fix the lengths).
    unsafe { arm::compress2(states, blocks) }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use crate::hash::sha512::K512;
    use core::arch::aarch64::*;

    /// Two independent SHA-512 block compressions interleaved two rounds at a
    /// time. Per stream this is the `sha_hw` kernel: state as `ab/cd/ef/gh`
    /// pairs, each `step` two rounds with the pair names rotated
    /// `(x0, x1, x2, x3) -> (x3, x0, x1, x2)`, schedule words `s_i` evolved
    /// with `sha512su0`/`sha512su1` from round 16 on.
    #[target_feature(enable = "sha3")]
    pub(super) unsafe fn compress2(states: &mut [[u64; 8]; 2], blocks: &[[u8; 128]; 2]) {
        unsafe {
            let (p0, p1) = (states[0].as_ptr(), states[1].as_ptr());
            let mut ab0 = vld1q_u64(p0);
            let mut cd0 = vld1q_u64(p0.add(2));
            let mut ef0 = vld1q_u64(p0.add(4));
            let mut gh0 = vld1q_u64(p0.add(6));
            let mut ab1 = vld1q_u64(p1);
            let mut cd1 = vld1q_u64(p1.add(2));
            let mut ef1 = vld1q_u64(p1.add(4));
            let mut gh1 = vld1q_u64(p1.add(6));
            let save0 = (ab0, cd0, ef0, gh0);
            let save1 = (ab1, cd1, ef1, gh1);

            let ld = |p: *const u8, o: usize| vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(p.add(o))));
            let (b0, b1) = (blocks[0].as_ptr(), blocks[1].as_ptr());
            let mut s0 = ld(b0, 0);
            let mut s1 = ld(b0, 16);
            let mut s2 = ld(b0, 32);
            let mut s3 = ld(b0, 48);
            let mut s4 = ld(b0, 64);
            let mut s5 = ld(b0, 80);
            let mut s6 = ld(b0, 96);
            let mut s7 = ld(b0, 112);
            let mut t0 = ld(b1, 0);
            let mut t1 = ld(b1, 16);
            let mut t2 = ld(b1, 32);
            let mut t3 = ld(b1, 48);
            let mut t4 = ld(b1, 64);
            let mut t5 = ld(b1, 80);
            let mut t6 = ld(b1, 96);
            let mut t7 = ld(b1, 112);

            // Two rounds of both streams with message words `$sa` / `$sb` and
            // constants `K[t], K[t + 1]`.
            macro_rules! step {
                ($x0:ident, $x1:ident, $x2:ident, $x3:ident,
                 $y0:ident, $y1:ident, $y2:ident, $y3:ident,
                 $sa:ident, $sb:ident, $t:expr) => {{
                    let k = vld1q_u64(K512.as_ptr().add($t));
                    let isa = vaddq_u64($sa, k);
                    let isb = vaddq_u64($sb, k);
                    let suma = vaddq_u64(vextq_u64(isa, isa, 1), $x3);
                    let sumb = vaddq_u64(vextq_u64(isb, isb, 1), $y3);
                    let ita = vsha512hq_u64(suma, vextq_u64($x2, $x3, 1), vextq_u64($x1, $x2, 1));
                    let itb = vsha512hq_u64(sumb, vextq_u64($y2, $y3, 1), vextq_u64($y1, $y2, 1));
                    $x3 = vsha512h2q_u64(ita, $x1, $x0);
                    $y3 = vsha512h2q_u64(itb, $y1, $y0);
                    $x1 = vaddq_u64($x1, ita);
                    $y1 = vaddq_u64($y1, itb);
                }};
            }
            // Schedule `s_i = su1(su0(s_i, s_{i+1}), s_{i+7}, ext(s_{i+4}, s_{i+5}))`
            // for both streams.
            macro_rules! sch {
                ($si:ident, $si1:ident, $si4:ident, $si5:ident, $si7:ident,
                 $ti:ident, $ti1:ident, $ti4:ident, $ti5:ident, $ti7:ident) => {
                    $si =
                        vsha512su1q_u64(vsha512su0q_u64($si, $si1), $si7, vextq_u64($si4, $si5, 1));
                    $ti =
                        vsha512su1q_u64(vsha512su0q_u64($ti, $ti1), $ti7, vextq_u64($ti4, $ti5, 1));
                };
            }
            // Rounds 0..16: the loaded message words.
            step!(ab0, cd0, ef0, gh0, ab1, cd1, ef1, gh1, s0, t0, 0);
            step!(gh0, ab0, cd0, ef0, gh1, ab1, cd1, ef1, s1, t1, 2);
            step!(ef0, gh0, ab0, cd0, ef1, gh1, ab1, cd1, s2, t2, 4);
            step!(cd0, ef0, gh0, ab0, cd1, ef1, gh1, ab1, s3, t3, 6);
            step!(ab0, cd0, ef0, gh0, ab1, cd1, ef1, gh1, s4, t4, 8);
            step!(gh0, ab0, cd0, ef0, gh1, ab1, cd1, ef1, s5, t5, 10);
            step!(ef0, gh0, ab0, cd0, ef1, gh1, ab1, cd1, s6, t6, 12);
            step!(cd0, ef0, gh0, ab0, cd1, ef1, gh1, ab1, s7, t7, 14);
            // Rounds 16..80: schedule each word just before it is consumed.
            macro_rules! block16 {
                ($t:expr) => {
                    sch!(s0, s1, s4, s5, s7, t0, t1, t4, t5, t7);
                    step!(ab0, cd0, ef0, gh0, ab1, cd1, ef1, gh1, s0, t0, $t);
                    sch!(s1, s2, s5, s6, s0, t1, t2, t5, t6, t0);
                    step!(gh0, ab0, cd0, ef0, gh1, ab1, cd1, ef1, s1, t1, $t + 2);
                    sch!(s2, s3, s6, s7, s1, t2, t3, t6, t7, t1);
                    step!(ef0, gh0, ab0, cd0, ef1, gh1, ab1, cd1, s2, t2, $t + 4);
                    sch!(s3, s4, s7, s0, s2, t3, t4, t7, t0, t2);
                    step!(cd0, ef0, gh0, ab0, cd1, ef1, gh1, ab1, s3, t3, $t + 6);
                    sch!(s4, s5, s0, s1, s3, t4, t5, t0, t1, t3);
                    step!(ab0, cd0, ef0, gh0, ab1, cd1, ef1, gh1, s4, t4, $t + 8);
                    sch!(s5, s6, s1, s2, s4, t5, t6, t1, t2, t4);
                    step!(gh0, ab0, cd0, ef0, gh1, ab1, cd1, ef1, s5, t5, $t + 10);
                    sch!(s6, s7, s2, s3, s5, t6, t7, t2, t3, t5);
                    step!(ef0, gh0, ab0, cd0, ef1, gh1, ab1, cd1, s6, t6, $t + 12);
                    sch!(s7, s0, s3, s4, s6, t7, t0, t3, t4, t6);
                    step!(cd0, ef0, gh0, ab0, cd1, ef1, gh1, ab1, s7, t7, $t + 14);
                };
            }
            block16!(16);
            block16!(32);
            block16!(48);
            block16!(64);

            let q0 = states[0].as_mut_ptr();
            let q1 = states[1].as_mut_ptr();
            vst1q_u64(q0, vaddq_u64(ab0, save0.0));
            vst1q_u64(q0.add(2), vaddq_u64(cd0, save0.1));
            vst1q_u64(q0.add(4), vaddq_u64(ef0, save0.2));
            vst1q_u64(q0.add(6), vaddq_u64(gh0, save0.3));
            vst1q_u64(q1, vaddq_u64(ab1, save1.0));
            vst1q_u64(q1.add(2), vaddq_u64(cd1, save1.1));
            vst1q_u64(q1.add(4), vaddq_u64(ef1, save1.2));
            vst1q_u64(q1.add(6), vaddq_u64(gh1, save1.3));
        }
    }
}

/// Whether the multi-buffer SHA-512 backend is available on this CPU.
#[cfg(target_arch = "x86_64")]
pub(crate) fn supported() -> bool {
    !crate::ct::force_portable() && std::is_x86_feature_detected!("avx2")
}

/// Applies one SHA-512 block compression to each of the four `(state, block)`
/// lanes in parallel: `states[l]` is folded with `blocks[l]` for every lane `l`.
///
/// Callers are expected to have checked [`supported`]; this re-checks the
/// (cached) CPU feature flag and panics rather than executing the kernel on
/// a CPU without AVX2, so the function is safe to call unconditionally.
#[cfg(target_arch = "x86_64")]
pub(crate) fn compress4(states: &mut [[u64; 8]; LANES], blocks: &[[u8; 128]; LANES]) {
    assert!(
        supported(),
        "sha512_mb::compress4 called on a CPU without AVX2; check supported() first"
    );
    // SAFETY: `supported()` just confirmed AVX2 on this CPU, and the kernel
    // has no other preconditions (the array types fix the lengths).
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

#[cfg(all(test, target_arch = "aarch64"))]
mod tests_arm {
    use super::*;
    use crate::hash::sha512::compress512_soft as soft;

    /// The interleaved two-stream kernel must reproduce the scalar
    /// compression exactly in both lanes, over random states and blocks and
    /// across chained blocks.
    #[test]
    fn compress2_matches_scalar() {
        std::eprintln!(
            "sha512_mb compress2: {}",
            if supported2() { "RUNNING" } else { "SKIPPED" }
        );
        if !supported2() {
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
            let mut states = [[0u64; 8]; LANES2];
            for lane in states.iter_mut() {
                for w in lane.iter_mut() {
                    *w = next();
                }
            }
            let mut want = states;
            for _block in 0..3 {
                let mut blocks = [[0u8; 128]; LANES2];
                for lane in blocks.iter_mut() {
                    for byte in lane.iter_mut() {
                        *byte = (next() >> 23) as u8;
                    }
                }
                for lane in 0..LANES2 {
                    soft(&mut want[lane], &blocks[lane]);
                }
                compress2(&mut states, &blocks);
            }
            assert_eq!(states, want);
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
            std::eprintln!("sha512_mb compress4: SKIPPED (no AVX2 on this CPU)");
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
