//! NEON backend for BLAKE3 — four independent 1024-byte chunks compressed in
//! parallel across the four 32-bit lanes of a `uint32x4_t`.
//!
//! The aarch64 sibling of [`super::blake3_simd`]: chunks are mutually
//! independent, so the 16 block compressions of four chunks run lane-wise
//! with no cross-lane data flow. The per-lane arithmetic is byte-for-byte the
//! scalar [`super::blake3`] compression (same `g`, same round schedule, same
//! message permutation), executed 4-wide; pinned by a differential test
//! against the scalar `ChunkState`. The rotations use the idioms that make
//! BLAKE3's `g` cheap on NEON: `rotr 16` is a 16-bit lane reverse
//! (`rev32.8h`), `rotr 8` a byte-table lookup (`tbl`), and `rotr 12` / `rotr 7`
//! a shift-left plus shift-right-insert pair (`shl` + `sri`).
//!
//! Only the all-full-chunk fast path is vectorised (every block is 64 bytes,
//! `CHUNK_START` on block 0 and `CHUNK_END` on block 15). Partial chunks,
//! parent nodes and the XOF stay on the scalar path. NEON is baseline on
//! aarch64, so [`supported`] only honours the constant-time harness's
//! force-portable switch.
#![allow(unsafe_code)]
#![allow(unused_unsafe)]

use super::blake3::{CHUNK_END, CHUNK_LEN, CHUNK_START, IV, MSG_PERMUTATION};
use core::arch::aarch64::*;

/// Number of chunks processed per call (NEON 32-bit lane count).
pub(super) const DEGREE: usize = 4;

/// Whether the NEON BLAKE3 backend is to be used on this CPU.
pub(super) fn supported() -> bool {
    !crate::ct::force_portable()
}

/// Compresses `DEGREE` consecutive full 1024-byte chunks in parallel.
///
/// `input` is exactly `DEGREE * CHUNK_LEN` bytes; chunk `k` uses counter
/// `counter_base + k`. Returns the four chunk chaining values (each the first
/// eight words of the chunk's final compression).
pub(super) fn hash_chunks4(
    input: &[u8; DEGREE * CHUNK_LEN],
    key: &[u32; 8],
    counter_base: u64,
    flags: u32,
) -> [[u32; 8]; DEGREE] {
    // SAFETY: NEON is a baseline aarch64 feature, and the array type pins the
    // length the kernel reads, so no load can run off the end of `input`.
    unsafe { neon::hash_chunks4(input, key, counter_base, flags) }
}

mod neon {
    use super::*;

    const BLOCK_LEN: u32 = 64;

    #[inline(always)]
    unsafe fn rotr16(x: uint32x4_t) -> uint32x4_t {
        unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x))) }
    }
    #[inline(always)]
    unsafe fn rotr12(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<12>(vshlq_n_u32::<20>(x), x) }
    }
    /// `rotr 8` as a byte permutation (`tbl` with the per-word `1 2 3 0` index
    /// vector).
    #[inline(always)]
    unsafe fn rotr8(x: uint32x4_t, tbl: uint8x16_t) -> uint32x4_t {
        unsafe { vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), tbl)) }
    }
    #[inline(always)]
    unsafe fn rotr7(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<7>(vshlq_n_u32::<25>(x), x) }
    }
    #[inline(always)]
    unsafe fn add(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        unsafe { vaddq_u32(a, b) }
    }
    #[inline(always)]
    unsafe fn xor(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
        unsafe { veorq_u32(a, b) }
    }

    /// The 4-wide BLAKE3 `g` mixing function (lanes are independent chunks).
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    unsafe fn g(
        v: &mut [uint32x4_t; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        mx: uint32x4_t,
        my: uint32x4_t,
        tbl: uint8x16_t,
    ) {
        unsafe {
            v[a] = add(add(v[a], v[b]), mx);
            v[d] = rotr16(xor(v[d], v[a]));
            v[c] = add(v[c], v[d]);
            v[b] = rotr12(xor(v[b], v[c]));
            v[a] = add(add(v[a], v[b]), my);
            v[d] = rotr8(xor(v[d], v[a]), tbl);
            v[c] = add(v[c], v[d]);
            v[b] = rotr7(xor(v[b], v[c]));
        }
    }

    #[inline(always)]
    unsafe fn round(v: &mut [uint32x4_t; 16], m: &[uint32x4_t; 16], tbl: uint8x16_t) {
        unsafe {
            g(v, 0, 4, 8, 12, m[0], m[1], tbl);
            g(v, 1, 5, 9, 13, m[2], m[3], tbl);
            g(v, 2, 6, 10, 14, m[4], m[5], tbl);
            g(v, 3, 7, 11, 15, m[6], m[7], tbl);
            g(v, 0, 5, 10, 15, m[8], m[9], tbl);
            g(v, 1, 6, 11, 12, m[10], m[11], tbl);
            g(v, 2, 7, 8, 13, m[12], m[13], tbl);
            g(v, 3, 4, 9, 14, m[14], m[15], tbl);
        }
    }

    /// In-place 4x4 transpose of four vectors of `u32` lanes.
    #[inline(always)]
    unsafe fn transpose4(v: &mut [uint32x4_t; 4]) {
        unsafe {
            let t0 = vtrn1q_u32(v[0], v[1]); // a0 b0 a2 b2
            let t1 = vtrn2q_u32(v[0], v[1]); // a1 b1 a3 b3
            let t2 = vtrn1q_u32(v[2], v[3]); // c0 d0 c2 d2
            let t3 = vtrn2q_u32(v[2], v[3]); // c1 d1 c3 d3
            let (t0, t1, t2, t3) = (
                vreinterpretq_u64_u32(t0),
                vreinterpretq_u64_u32(t1),
                vreinterpretq_u64_u32(t2),
                vreinterpretq_u64_u32(t3),
            );
            v[0] = vreinterpretq_u32_u64(vtrn1q_u64(t0, t2)); // a0 b0 c0 d0
            v[1] = vreinterpretq_u32_u64(vtrn1q_u64(t1, t3)); // a1 b1 c1 d1
            v[2] = vreinterpretq_u32_u64(vtrn2q_u64(t0, t2)); // a2 b2 c2 d2
            v[3] = vreinterpretq_u32_u64(vtrn2q_u64(t1, t3)); // a3 b3 c3 d3
        }
    }

    /// Loads block `b` of all four chunks and transposes into 16 message
    /// vectors, where `m[j]` holds word `j` of that block across the lanes.
    #[inline(always)]
    unsafe fn load_msg(input: &[u8], b: usize) -> [uint32x4_t; 16] {
        unsafe {
            let mut m = [vdupq_n_u32(0); 16];
            for q in 0..4 {
                let mut quad = [vdupq_n_u32(0); 4];
                for (lane, row) in quad.iter_mut().enumerate() {
                    // BLAKE3 words are little-endian, so the raw bytes are the
                    // words.
                    let p = input.as_ptr().add(lane * CHUNK_LEN + b * 64 + q * 16);
                    *row = vreinterpretq_u32_u8(vld1q_u8(p));
                }
                transpose4(&mut quad);
                m[4 * q..4 * q + 4].copy_from_slice(&quad);
            }
            m
        }
    }

    /// Reorders the 16 message vectors per `MSG_PERMUTATION` between rounds.
    #[inline(always)]
    unsafe fn permute(m: &[uint32x4_t; 16]) -> [uint32x4_t; 16] {
        let mut out = [unsafe { vdupq_n_u32(0) }; 16];
        for (i, &p) in MSG_PERMUTATION.iter().enumerate() {
            out[i] = m[p];
        }
        out
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn hash_chunks4(
        input: &[u8],
        key: &[u32; 8],
        counter_base: u64,
        flags: u32,
    ) -> [[u32; 8]; DEGREE] {
        unsafe {
            let tbl_bytes: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];
            let tbl = vld1q_u8(tbl_bytes.as_ptr());

            // Per-lane counters: chunk k uses counter_base + k.
            let mut clo = [0u32; DEGREE];
            let mut chi = [0u32; DEGREE];
            for (k, (lo, hi)) in clo.iter_mut().zip(chi.iter_mut()).enumerate() {
                let c = counter_base.wrapping_add(k as u64);
                *lo = c as u32;
                *hi = (c >> 32) as u32;
            }
            let counter_lo = vld1q_u32(clo.as_ptr());
            let counter_hi = vld1q_u32(chi.as_ptr());
            let block_len = vdupq_n_u32(BLOCK_LEN);

            // Chaining values, one broadcast key word per state lane.
            let mut h = [vdupq_n_u32(0); 8];
            for (hi, &kw) in h.iter_mut().zip(key.iter()) {
                *hi = vdupq_n_u32(kw);
            }

            for b in 0..16usize {
                let block_flags = {
                    let mut f = flags;
                    if b == 0 {
                        f |= CHUNK_START;
                    }
                    if b == 15 {
                        f |= CHUNK_END;
                    }
                    vdupq_n_u32(f)
                };

                let msg = load_msg(input, b);

                let mut v = [
                    h[0],
                    h[1],
                    h[2],
                    h[3],
                    h[4],
                    h[5],
                    h[6],
                    h[7],
                    vdupq_n_u32(IV[0]),
                    vdupq_n_u32(IV[1]),
                    vdupq_n_u32(IV[2]),
                    vdupq_n_u32(IV[3]),
                    counter_lo,
                    counter_hi,
                    block_len,
                    block_flags,
                ];

                let mut m = msg;
                for r in 0..7 {
                    round(&mut v, &m, tbl);
                    if r < 6 {
                        m = permute(&m);
                    }
                }

                // Chunk chaining value = first 8 words: state[i] ^ state[i + 8].
                for i in 0..8 {
                    h[i] = xor(v[i], v[i + 8]);
                }
            }

            // Transpose the 8 CV word-vectors back to per-lane CVs, two 4x4
            // quarters at a time.
            let mut lo = [h[0], h[1], h[2], h[3]];
            let mut hi = [h[4], h[5], h[6], h[7]];
            transpose4(&mut lo);
            transpose4(&mut hi);
            let mut out = [[0u32; 8]; DEGREE];
            for (lane, o) in out.iter_mut().enumerate() {
                vst1q_u32(o.as_mut_ptr(), lo[lane]);
                vst1q_u32(o.as_mut_ptr().add(4), hi[lane]);
            }
            out
        }
    }
}
