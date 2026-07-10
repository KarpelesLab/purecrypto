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
pub(super) use arm::{gf_mul, ghash_blocks};
#[cfg(target_arch = "x86_64")]
pub(super) use x86::{ctr_ghash_fused, gf_mul, ghash_blocks};

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

    /// Carryless 128×128 multiply on the byte-swapped representation, returning
    /// the UNREDUCED 256-bit product as `(lo, hi)` (Intel white-paper Figure 5).
    /// Separated from the reduction so several products can be XOR-accumulated
    /// and reduced once — the aggregated-reduction trick (the reduction is
    /// XOR-linear, so `reduce(Σ pᵢ) = Σ reduce(pᵢ)`).
    ///
    /// Uses Karatsuba: 3 PCLMULQDQ instead of the 4 of the schoolbook form —
    /// the two cross terms `a₀b₁ ⊕ a₁b₀` are recovered from one multiply as
    /// `(a₀⊕a₁)(b₀⊕b₁) ⊕ a₀b₀ ⊕ a₁b₁` (carryless, so additions are XOR).
    #[inline]
    #[target_feature(enable = "pclmulqdq,sse2")]
    unsafe fn clmul_halves(a: __m128i, b: __m128i) -> (__m128i, __m128i) {
        unsafe {
            let t3 = _mm_clmulepi64_si128(a, b, 0x00); // a₀·b₀
            let t6 = _mm_clmulepi64_si128(a, b, 0x11); // a₁·b₁
            let ax = _mm_xor_si128(a, _mm_srli_si128(a, 8)); // low 64 = a₀⊕a₁
            let bx = _mm_xor_si128(b, _mm_srli_si128(b, 8)); // low 64 = b₀⊕b₁
            let mid = _mm_clmulepi64_si128(ax, bx, 0x00);
            let mid = _mm_xor_si128(mid, _mm_xor_si128(t3, t6)); // a₀b₁ ⊕ a₁b₀
            let t5 = _mm_slli_si128(mid, 8);
            let t4 = _mm_srli_si128(mid, 8);
            (_mm_xor_si128(t3, t5), _mm_xor_si128(t6, t4))
        }
    }

    /// Two-phase reduction modulo x¹²⁸ + x⁷ + x² + x + 1 of an unreduced
    /// 256-bit product `(lo, hi)` into a 128-bit field element.
    #[inline]
    #[target_feature(enable = "pclmulqdq,sse2")]
    unsafe fn reduce(lo: __m128i, hi: __m128i) -> __m128i {
        unsafe {
            let mut t3 = lo;
            let mut t6 = hi;
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

    /// Carryless 128×128 → reduced 128-bit GCM product (multiply then reduce).
    #[inline]
    #[target_feature(enable = "pclmulqdq,sse2")]
    unsafe fn gfmul(a: __m128i, b: __m128i) -> __m128i {
        unsafe {
            let (lo, hi) = clmul_halves(a, b);
            reduce(lo, hi)
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

    /// Loads the eight precomputed hash-subkey powers (`hpow[i] = H^{i+1}`,
    /// computed once at GCM construction) into registers in the reflected
    /// representation. A `u128`'s little-endian bytes ARE the byte-swapped
    /// big-endian block, so no shuffle is needed.
    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn load_hpow(hpow: &[u128; 8]) -> [__m128i; 8] {
        unsafe {
            let mut h = [_mm_setzero_si128(); 8];
            for (hv, hp) in h.iter_mut().zip(hpow.iter()) {
                let b = hp.to_le_bytes();
                *hv = _mm_loadu_si128(b.as_ptr() as *const __m128i);
            }
            h
        }
    }

    /// Folds the eight 16-byte blocks at `p` into `acc` with one reduction:
    /// `acc ← (acc ⊕ b₀)·H⁸ ⊕ b₁·H⁷ ⊕ … ⊕ b₇·H` (aggregated reduction).
    #[inline]
    #[target_feature(enable = "pclmulqdq,sse2,ssse3")]
    unsafe fn ghash_group8(acc: __m128i, h: &[__m128i; 8], p: *const u8) -> __m128i {
        unsafe {
            let load = |q: *const u8| bswap(_mm_loadu_si128(q as *const __m128i));
            let d0 = _mm_xor_si128(acc, load(p));
            let (mut lo, mut hi) = clmul_halves(d0, h[7]);
            for j in 1..8 {
                let (l, hh) = clmul_halves(load(p.add(j * 16)), h[7 - j]);
                lo = _mm_xor_si128(lo, l);
                hi = _mm_xor_si128(hi, hh);
            }
            reduce(lo, hi)
        }
    }

    /// Aggregated GHASH: folds whole 16-byte `blocks` (length a multiple of 16)
    /// into the accumulator `x`, eight blocks per reduction using the
    /// precomputed powers `hpow[i] = H^{i+1}`.
    ///
    /// `x ← (x ⊕ b₀)·H⁸ ⊕ b₁·H⁷ ⊕ … ⊕ b₇·H` per group, accumulating the eight
    /// unreduced products and reducing once; a `≥ 4`-block remainder folds as
    /// one four-block group and the final `< 4`-block tail folds serially.
    /// Returns the same value as repeated `gf_mul(x ⊕ bᵢ, h)`.
    #[target_feature(enable = "pclmulqdq,sse2,ssse3")]
    pub(in super::super) unsafe fn ghash_blocks(x: u128, hpow: &[u128; 8], blocks: &[u8]) -> u128 {
        unsafe {
            let load = |p: *const u8| bswap(_mm_loadu_si128(p as *const __m128i));
            let h = load_hpow(hpow);

            let xb = x.to_le_bytes();
            let mut acc = _mm_loadu_si128(xb.as_ptr() as *const __m128i);
            let mut chunks = blocks.chunks_exact(128);
            for c in &mut chunks {
                acc = ghash_group8(acc, &h, c.as_ptr());
            }
            let mut rest = chunks.remainder();
            if rest.len() >= 64 {
                let p = rest.as_ptr();
                let d0 = _mm_xor_si128(acc, load(p));
                let (mut lo, mut hi) = clmul_halves(d0, h[3]);
                for j in 1..4 {
                    let (l, hh) = clmul_halves(load(p.add(j * 16)), h[3 - j]);
                    lo = _mm_xor_si128(lo, l);
                    hi = _mm_xor_si128(hi, hh);
                }
                acc = reduce(lo, hi);
                rest = &rest[64..];
            }
            for c in rest.chunks_exact(16) {
                acc = gfmul(_mm_xor_si128(acc, load(c.as_ptr())), h[0]);
            }

            let p = bswap(acc);
            let mut out = [0u8; 16];
            _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, p);
            u128::from_be_bytes(out)
        }
    }

    /// Stitched AES-CTR ⊕ GHASH bulk loop — GCM "function stitching".
    ///
    /// Per 128-byte group the eight AESENC dependency chains and the
    /// PCLMULQDQ aggregation of the neighbouring group are issued in the same
    /// loop body, so the out-of-order core overlaps the AES units and the
    /// carryless multiplier instead of running two separate passes over the
    /// buffer.
    ///
    /// CTR-encrypts (⇔ decrypts) `buf` in place with AES under `round_keys`
    /// (`nr` rounds), starting from counter block `ctr` (GCM `inc32`
    /// semantics), while folding the *ciphertext* blocks into the GHASH
    /// accumulator `acc` using the precomputed powers `hpow[i] = H^{i+1}`.
    /// Encryption hashes each group's output with a one-group lag (the
    /// ciphertext exists only after the XOR); decryption hashes its input
    /// group directly. `buf.len()` must be a multiple of 128. Returns the
    /// updated accumulator.
    ///
    /// Constant-time: AESENC and PCLMULQDQ are data-independent, and the only
    /// branches here depend on the public buffer length and direction flag.
    #[target_feature(enable = "aes,pclmulqdq,sse2,ssse3")]
    pub(in super::super) unsafe fn ctr_ghash_fused(
        round_keys: &[u8],
        nr: usize,
        ctr: u128,
        hpow: &[u128; 8],
        acc: u128,
        buf: &mut [u8],
        encrypt: bool,
    ) -> u128 {
        debug_assert_eq!(buf.len() % 128, 0);
        unsafe {
            // Preload the schedule once (≤ 15 round keys for AES-256).
            let mut ks = [_mm_setzero_si128(); 15];
            for (i, k) in ks.iter_mut().enumerate().take(nr + 1) {
                *k = _mm_loadu_si128(round_keys.as_ptr().add(i * 16) as *const __m128i);
            }
            let h = load_hpow(hpow);
            let ab = acc.to_le_bytes();
            let mut acc = _mm_loadu_si128(ab.as_ptr() as *const __m128i);

            // Block `i`'s counter is independent of block `i-1`'s: GCM `inc32`
            // advances only the rightmost 32 bits, so counter `i` is
            // `hi ‖ (lo + i mod 2³²)` — no serial dependency chain.
            let ctr_hi = ctr & !0xffff_ffffu128;
            let ctr_lo = ctr as u32;
            let mut blk: u32 = 0;

            let n = buf.len();
            let base = buf.as_mut_ptr();
            let mut off = 0;
            while off < n {
                // Eight counter blocks through the AES rounds, 8-wide.
                let mut b = [_mm_setzero_si128(); 8];
                for bj in b.iter_mut() {
                    let cb = (ctr_hi | ctr_lo.wrapping_add(blk) as u128).to_be_bytes();
                    *bj = _mm_xor_si128(_mm_loadu_si128(cb.as_ptr() as *const __m128i), ks[0]);
                    blk = blk.wrapping_add(1);
                }
                for &k in ks.iter().take(nr).skip(1) {
                    for bj in b.iter_mut() {
                        *bj = _mm_aesenc_si128(*bj, k);
                    }
                }
                for bj in b.iter_mut() {
                    *bj = _mm_aesenclast_si128(*bj, ks[nr]);
                }
                // GHASH the neighbouring ciphertext group: the previous output
                // group when encrypting, the current input group when
                // decrypting (before the XOR below overwrites it).
                if encrypt {
                    if off >= 128 {
                        acc = ghash_group8(acc, &h, base.add(off - 128));
                    }
                } else {
                    acc = ghash_group8(acc, &h, base.add(off));
                }
                // XOR the keystream into the data.
                for (j, bj) in b.iter().enumerate() {
                    let q = base.add(off + j * 16);
                    let d = _mm_loadu_si128(q as *const __m128i);
                    _mm_storeu_si128(q as *mut __m128i, _mm_xor_si128(d, *bj));
                }
                off += 128;
            }
            // Flush the lag: the last output group is still unhashed.
            if encrypt && n != 0 {
                acc = ghash_group8(acc, &h, base.add(n - 128));
            }

            let p = bswap(acc);
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

    /// Carryless 128×128 multiply (byte-swapped rep), returning the UNREDUCED
    /// 256-bit product `(lo, hi)`. Split from the reduction for aggregation.
    ///
    /// Uses Karatsuba: 3 PMULL instead of the 4 of the schoolbook form — the
    /// two cross terms `a₀b₁ ⊕ a₁b₀` are recovered from one multiply as
    /// `(a₀⊕a₁)(b₀⊕b₁) ⊕ a₀b₀ ⊕ a₁b₁` (carryless, so additions are XOR).
    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn clmul_halves(a: uint8x16_t, b: uint8x16_t) -> (uint8x16_t, uint8x16_t) {
        unsafe {
            let zero = vdupq_n_u8(0);
            let t3 = clmul(a, b, 0x00); // a₀·b₀
            let t6 = clmul(a, b, 0x11); // a₁·b₁
            let ax = veorq_u8(a, vextq_u8(a, zero, 8)); // low 64 = a₀⊕a₁
            let bx = veorq_u8(b, vextq_u8(b, zero, 8)); // low 64 = b₀⊕b₁
            let mid = clmul(ax, bx, 0x00);
            let mid = veorq_u8(mid, veorq_u8(t3, t6)); // a₀b₁ ⊕ a₁b₀
            let t5 = vextq_u8(zero, mid, 8); // slli_si128(mid, 8)
            let t4 = vextq_u8(mid, zero, 8); // srli_si128(mid, 8)
            (veorq_u8(t3, t5), veorq_u8(t6, t4))
        }
    }

    /// Two-phase reduction of an unreduced 256-bit product `(lo, hi)`.
    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn reduce(lo: uint8x16_t, hi: uint8x16_t) -> uint8x16_t {
        unsafe {
            let zero = vdupq_n_u8(0);
            let mut t3 = lo;
            let mut t6 = hi;
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

    /// Carryless 128×128 → reduced 128-bit GCM product (multiply then reduce).
    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn gfmul(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
        unsafe {
            let (lo, hi) = clmul_halves(a, b);
            reduce(lo, hi)
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

    /// Aggregated GHASH (four blocks per reduction), the NEON analogue of the
    /// x86 [`ghash_blocks`]. `blocks.len()` must be a multiple of 16. Returns the
    /// same value as repeated `gf_mul(x ⊕ bᵢ, h)`.
    /// Loads a 16-byte GCM block into the byte-swapped ("reflected")
    /// representation `gfmul` expects. A `u128` reaches that form for free via
    /// `to_le_bytes` (its little-endian bytes are the big-endian block
    /// reversed); a raw block must be reversed explicitly, the NEON equivalent
    /// of the x86 path's `bswap`.
    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn load_rev(p: *const u8) -> uint8x16_t {
        unsafe {
            let v = vrev64q_u8(vld1q_u8(p));
            vextq_u8(v, v, 8)
        }
    }

    /// Folds the eight 16-byte blocks at `p` into `acc` with one reduction:
    /// `acc ← (acc ⊕ b₀)·H⁸ ⊕ b₁·H⁷ ⊕ … ⊕ b₇·H` (aggregated reduction).
    #[inline]
    #[target_feature(enable = "aes,neon")]
    unsafe fn ghash_group8(acc: uint8x16_t, h: &[uint8x16_t; 8], p: *const u8) -> uint8x16_t {
        unsafe {
            let d0 = veorq_u8(acc, load_rev(p));
            let (mut lo, mut hi) = clmul_halves(d0, h[7]);
            for j in 1..8 {
                let (l, hh) = clmul_halves(load_rev(p.add(j * 16)), h[7 - j]);
                lo = veorq_u8(lo, l);
                hi = veorq_u8(hi, hh);
            }
            reduce(lo, hi)
        }
    }

    /// Aggregated GHASH, the NEON analogue of the x86 [`ghash_blocks`]: folds
    /// whole 16-byte `blocks` (length a multiple of 16) into `x`, eight blocks
    /// per reduction using the precomputed powers `hpow[i] = H^{i+1}`; a
    /// `≥ 4`-block remainder folds as one four-block group and the final
    /// `< 4`-block tail folds serially. Returns the same value as repeated
    /// `gf_mul(x ⊕ bᵢ, h)`.
    #[target_feature(enable = "aes,neon")]
    pub(in super::super) unsafe fn ghash_blocks(x: u128, hpow: &[u128; 8], blocks: &[u8]) -> u128 {
        unsafe {
            // `x` and the powers are `u128`, so their little-endian bytes
            // already are the reflected representation; the message blocks are
            // reversed by `load_rev`.
            let mut h = [vdupq_n_u8(0); 8];
            for (hv, hp) in h.iter_mut().zip(hpow.iter()) {
                let b = hp.to_le_bytes();
                *hv = vld1q_u8(b.as_ptr());
            }

            let xb = x.to_le_bytes();
            let mut acc = vld1q_u8(xb.as_ptr());
            let mut chunks = blocks.chunks_exact(128);
            for c in &mut chunks {
                acc = ghash_group8(acc, &h, c.as_ptr());
            }
            let mut rest = chunks.remainder();
            if rest.len() >= 64 {
                let p = rest.as_ptr();
                let d0 = veorq_u8(acc, load_rev(p));
                let (mut lo, mut hi) = clmul_halves(d0, h[3]);
                for j in 1..4 {
                    let (l, hh) = clmul_halves(load_rev(p.add(j * 16)), h[3 - j]);
                    lo = veorq_u8(lo, l);
                    hi = veorq_u8(hi, hh);
                }
                acc = reduce(lo, hi);
                rest = &rest[64..];
            }
            for c in rest.chunks_exact(16) {
                acc = gfmul(veorq_u8(acc, load_rev(c.as_ptr())), h[0]);
            }

            let mut out = [0u8; 16];
            vst1q_u8(out.as_mut_ptr(), acc);
            u128::from_le_bytes(out)
        }
    }
}
