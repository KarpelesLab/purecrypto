//! AVX-512 IFMA backend for the X25519 Montgomery ladder: the four ladder
//! coordinates `(x₂, z₂, x₃, z₃)` live one per 64-bit lane of `__m256i`
//! vectors, so every ladder level is a single 4-way field multiplication.
//!
//! # Representation
//!
//! [`F4`] holds four GF(2²⁵⁵−19) elements in the same radix-2⁵¹ five-limb
//! form as the scalar [`Fe`], limb `i` of all four lanes in vector `i`. The
//! multiplier is `vpmadd52luq` / `vpmadd52huq`, which multiply the low 52 bits
//! of each operand, so **every multiplier input must have limbs `< 2^52`**.
//! The multiply's own output satisfies that (limbs `< 2^51 + 2^15`), and
//! every sum or difference goes through [`carry`] (one parallel carry round)
//! before it is multiplied.
//!
//! For a 104-bit product `a_i·b_j` at weight `2^(51(i+j))`, the low half
//! (`madd52lo`) lands at that weight and the high half (`madd52hi`, bits
//! 52..103) at `2^(51(i+j)+52) = 2·2^(51(i+j+1))`, hence the doubled high
//! accumulators below; columns 5..9 fold back with `×19`.
//!
//! # Ladder step (Hisil–Egrice–Wong-style 4-way schedule, three levels)
//!
//! ```text
//! v   = [x2, z2, x3, z3]                    (conditional swap folded into
//! ABCD = [x2+z2, x2−z2, x3+z3, x3−z3]        a secret-indexed lane permute)
//! U   = [A, B, C, D] · [A, B, B, A]  = [AA, BB, CB, DA]
//! W   = [·, E, S, D'] · [·, a24, S, D'] = [·, a24·E, S², D'²]
//!         (E = AA − BB, S = DA + CB, D' = CB − DA)
//! v'  = [AA, E, S², D'²] · [BB, AA + a24·E, 1, x1]
//! ```
//!
//! # Constant time
//!
//! No branches or memory accesses depend on the scalar. The per-step swap
//! is an arithmetic mask (behind the same [`mask_from_bit`] barrier as the
//! scalar ladder) that selects the permutation index vector of
//! `vpermq`, whose timing does not depend on the indices.

// Plain indexed loops on purpose: `core::array::from_fn` / iterator
// closures are not compiled with the caller's target features, so the
// intrinsics inside them were emitted out of line (a 12x slowdown).
#![allow(clippy::needless_range_loop)]

use super::field::{Fe, mask_from_bit};
use core::arch::x86_64::*;

/// Four field elements, limb `i` of every lane in `self.0[i]`.
#[derive(Clone, Copy)]
struct F4([__m256i; 5]);

const M51: i64 = (1i64 << 51) - 1;

/// `2·p` per limb (the bias added before a lane-wise subtraction).
const TWO_P0: i64 = 0xfffffffffffda;
const TWO_P: i64 = 0xffffffffffffe;

/// Whether the IFMA ladder may run.
pub(crate) fn supported() -> bool {
    !crate::ct::force_portable() && crate::cpu::avx512ifma() && crate::cpu::avx512vl()
}

/// `x·19` lane-wise (`x + 2x + 16x`); inputs `< 2^59`.
#[inline(always)]
unsafe fn times19(x: __m256i) -> __m256i {
    unsafe {
        _mm256_add_epi64(
            _mm256_add_epi64(x, _mm256_slli_epi64::<1>(x)),
            _mm256_slli_epi64::<4>(x),
        )
    }
}

/// One parallel carry round with the `2^255 ≡ 19` fold. Inputs with limbs
/// `< 2^60` leave with limbs `< 2^51 + 19·2^9 < 2^52` (valid multiplier
/// inputs); inputs `< 2^54` (lazy sums/differences) with limbs
/// `< 2^51 + 19·2^3`.
#[inline(always)]
unsafe fn carry(r: [__m256i; 5]) -> F4 {
    unsafe {
        let m = _mm256_set1_epi64x(M51);
        let c0 = _mm256_srli_epi64::<51>(r[0]);
        let c1 = _mm256_srli_epi64::<51>(r[1]);
        let c2 = _mm256_srli_epi64::<51>(r[2]);
        let c3 = _mm256_srli_epi64::<51>(r[3]);
        let c4 = _mm256_srli_epi64::<51>(r[4]);
        F4([
            _mm256_add_epi64(_mm256_and_si256(r[0], m), times19(c4)),
            _mm256_add_epi64(_mm256_and_si256(r[1], m), c0),
            _mm256_add_epi64(_mm256_and_si256(r[2], m), c1),
            _mm256_add_epi64(_mm256_and_si256(r[3], m), c2),
            _mm256_add_epi64(_mm256_and_si256(r[4], m), c3),
        ])
    }
}

/// Lane-wise `a·b`. Both inputs must have limbs `< 2^52`; the output has
/// limbs `< 2^51 + 2^15`.
///
/// Bounds: each low/high accumulator sums at most 5 values `< 2^52`
/// (`< 2^54.4`); a column `l_k + 2·h_{k−1}` is `< 2^56`; the folded column
/// `z_k + 19·z_{k+5}` is `< 2^60.4`, which [`carry`] accepts.
#[inline(always)]
unsafe fn mul(a: &F4, b: &F4) -> F4 {
    unsafe {
        let a = &a.0;
        let b = &b.0;
        let zero = _mm256_setzero_si256();
        let mut l = [zero; 9];
        let mut h = [zero; 9];
        for i in 0..5 {
            for j in 0..5 {
                l[i + j] = _mm256_madd52lo_epu64(l[i + j], a[i], b[j]);
                h[i + j] = _mm256_madd52hi_epu64(h[i + j], a[i], b[j]);
            }
        }
        // Column k (weight 2^(51k)): l_k + 2·h_{k−1}.
        let mut col = [zero; 10];
        col[0] = l[0];
        for k in 1..9 {
            col[k] = _mm256_add_epi64(l[k], _mm256_add_epi64(h[k - 1], h[k - 1]));
        }
        col[9] = _mm256_add_epi64(h[8], h[8]);
        let mut r = [zero; 5];
        for k in 0..5 {
            r[k] = _mm256_add_epi64(col[k], times19(col[k + 5]));
        }
        carry(r)
    }
}

#[inline(always)]
unsafe fn add(a: &F4, b: &F4) -> [__m256i; 5] {
    let mut r = a.0;
    for i in 0..5 {
        r[i] = unsafe { _mm256_add_epi64(a.0[i], b.0[i]) };
    }
    r
}

/// `a + 2p − b` lane-wise, unreduced; `b` limbs must be `≤ 2^52 − 38`.
#[inline(always)]
unsafe fn sub(a: &F4, b: &F4) -> [__m256i; 5] {
    unsafe {
        let mut r = a.0;
        for i in 0..5 {
            let bias = _mm256_set1_epi64x(if i == 0 { TWO_P0 } else { TWO_P });
            r[i] = _mm256_sub_epi64(_mm256_add_epi64(a.0[i], bias), b.0[i]);
        }
        r
    }
}

/// Per-lane choice: the 32-bit elements of `b` where `IMM` has bits set
/// (see the `LANE*` immediates), `a` elsewhere.
#[inline(always)]
unsafe fn blend<const IMM: i32>(a: &[__m256i; 5], b: &[__m256i; 5]) -> [__m256i; 5] {
    let mut r = *a;
    for i in 0..5 {
        r[i] = unsafe { _mm256_blend_epi32::<IMM>(a[i], b[i]) };
    }
    r
}

/// 32-bit blend immediates selecting whole 64-bit lanes.
const LANE1: i32 = 0b0000_1100;
const LANE01: i32 = 0b0000_1111;
const LANE2: i32 = 0b0011_0000;
const LANE13: i32 = 0b1100_1100;
const LANE23: i32 = 0b1111_0000;

#[inline(always)]
unsafe fn permute<const IMM: i32>(a: &F4) -> F4 {
    let mut r = a.0;
    for i in 0..5 {
        r[i] = unsafe { _mm256_permute4x64_epi64::<IMM>(a.0[i]) };
    }
    F4(r)
}

#[inline(always)]
unsafe fn permute_var(idx: __m256i, a: &F4) -> F4 {
    let mut r = a.0;
    for i in 0..5 {
        r[i] = unsafe { _mm256_permutexvar_epi64(idx, a.0[i]) };
    }
    F4(r)
}

#[inline(always)]
unsafe fn splat_lanes(v: [&Fe; 4]) -> F4 {
    unsafe {
        let mut r = [_mm256_setzero_si256(); 5];
        for (i, limb) in r.iter_mut().enumerate() {
            *limb = _mm256_setr_epi64x(
                v[0].0[i] as i64,
                v[1].0[i] as i64,
                v[2].0[i] as i64,
                v[3].0[i] as i64,
            );
        }
        F4(r)
    }
}

/// The Montgomery ladder over bits 254..0 of the clamped scalar `k` from
/// the u-coordinate `x1` (limbs `< 2^51`), returning `(x₂, z₂)` — the same
/// projective result as the scalar ladder in `x25519`. The caller wipes `k`.
pub(crate) fn ladder(k: &[u8; 32], x1: &Fe) -> (Fe, Fe) {
    // SAFETY: the caller checked `supported()` (AVX-512 IFMA + VL).
    unsafe { ladder_ifma(k, x1) }
}

#[target_feature(enable = "avx512f,avx512vl,avx512ifma")]
unsafe fn ladder_ifma(k: &[u8; 32], x1: &Fe) -> (Fe, Fe) {
    unsafe {
        let a24 = Fe([121665, 0, 0, 0, 0]);
        let mut v = splat_lanes([&Fe::ONE, &Fe::ZERO, x1, &Fe::ONE]);
        // Lanes 2, 3 of the last multiplier operand: [1, x1].
        let one_x1 = splat_lanes([&Fe::ZERO, &Fe::ZERO, &Fe::ONE, x1]).0;
        let a24v = splat_lanes([&a24, &a24, &Fe::ZERO, &Fe::ZERO]).0;
        // Index vectors selecting [x2, x2, x3, x3] and [z2, z2, z3, z3];
        // XOR-ing every index with 2 swaps the (x2, z2) and (x3, z3) pairs.
        let idx_p = _mm256_setr_epi64x(0, 0, 2, 2);
        let idx_q = _mm256_setr_epi64x(1, 1, 3, 3);

        let mut swap = 0u8;
        let mut t = 255;
        while t > 0 {
            t -= 1;
            let kt = (k[t / 8] >> (t % 8)) & 1;
            swap ^= kt;
            let s = _mm256_set1_epi64x((mask_from_bit(swap as u64) & 2) as i64);
            swap = kt;

            let p = permute_var(_mm256_xor_si256(idx_p, s), &v);
            let q = permute_var(_mm256_xor_si256(idx_q, s), &v);
            // [A, B, C, D] = [x2+z2, x2−z2, x3+z3, x3−z3].
            let abcd = carry(blend::<LANE13>(&add(&p, &q), &sub(&p, &q)));
            // U = [AA, BB, CB, DA].
            let u = mul(&abcd, &permute::<0b00_01_01_00>(&abcd));
            let usw = permute::<0b10_11_00_01>(&u); // [BB, AA, DA, CB]
            let sum = add(&u, &usw); // lane 2: S = CB + DA
            // lane 1: E = AA − BB; lane 3: CB − DA = −D' (only squared).
            let dif = sub(&usw, &u);
            // L2 = [·, E, S, −D'].
            let l2 = carry(blend::<LANE2>(&dif, &sum));
            let r2 = F4(blend::<LANE01>(&l2.0, &a24v));
            // W = [·, a24·E, S², D'²].
            let w = mul(&l2, &r2);
            // v' = [AA, E, S², D'²] · [BB, AA + a24·E, 1, x1].
            let l3 = F4(blend::<LANE23>(&blend::<LANE1>(&u.0, &l2.0), &w.0));
            let r3 = carry(blend::<LANE23>(
                &blend::<LANE1>(&usw.0, &add(&usw, &w)),
                &one_x1,
            ));
            v = mul(&l3, &r3);
        }
        let s = _mm256_set1_epi64x((mask_from_bit(swap as u64) & 2) as i64);
        // Lanes 0, 1 after the final conditional swap.
        let fin = permute_var(_mm256_xor_si256(_mm256_setr_epi64x(0, 1, 2, 3), s), &v);
        let mut lanes = [[0u64; 4]; 5];
        for (i, out) in lanes.iter_mut().enumerate() {
            _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, fin.0[i]);
        }
        let x2 = Fe([
            lanes[0][0],
            lanes[1][0],
            lanes[2][0],
            lanes[3][0],
            lanes[4][0],
        ]);
        let z2 = Fe([
            lanes[0][1],
            lanes[1][1],
            lanes[2][1],
            lanes[3][1],
            lanes[4][1],
        ]);
        // Best-effort wipe of the ladder state left in memory.
        crate::zeroize::Zeroize::zeroize(&mut lanes);
        (x2, z2)
    }
}
