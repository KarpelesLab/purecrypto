//! NEON backend for BLAKE3 — four independent 1024-byte chunks compressed in
//! parallel across the four 32-bit lanes of a `uint32x4_t`.
//!
//! The aarch64 sibling of [`super::blake3_simd`]: chunks are mutually
//! independent, so the 16 block compressions of four chunks run lane-wise
//! with no cross-lane data flow. The per-lane arithmetic is byte-for-byte the
//! scalar [`super::blake3`] compression (same `g`, same round schedule),
//! executed 4-wide; pinned by a differential test
//! against the scalar `ChunkState`. The rotations use the idioms that make
//! BLAKE3's `g` cheap on NEON: `rotr 16` is a 16-bit lane reverse
//! (`rev32.8h`), `rotr 8` a byte-table lookup (`tbl`), and `rotr 12` / `rotr 7`
//! a shift-left plus shift-right-insert pair (`shl` + `sri`).
//!
//! The same kernel also compresses up to four parent nodes of one tree level
//! at once, and a call may fill fewer lanes than four (the unused lanes
//! recompute the last real input and are dropped). Only full chunks are
//! vectorised (every block is 64 bytes, `CHUNK_START` on block 0 and
//! `CHUNK_END` on block 15); partial chunks and the XOF stay on the scalar
//! path. NEON is baseline on aarch64, so [`supported`] only honours the
//! constant-time harness's force-portable switch.
#![allow(unsafe_code)]
#![allow(unused_unsafe)]

use super::blake3::{CHUNK_END, CHUNK_LEN, CHUNK_START, IV, MSG_SCHEDULE, PARENT};
use core::arch::aarch64::*;

/// Number of chunks processed per call (NEON 32-bit lane count).
pub(super) const DEGREE: usize = 4;

/// Whether the NEON BLAKE3 backend is to be used on this CPU.
pub(super) fn supported() -> bool {
    !crate::ct::force_portable()
}

/// Compresses `out.len()` (1..=4) consecutive full 1024-byte chunks in
/// parallel.
///
/// `input` is exactly `out.len() * CHUNK_LEN` bytes; chunk `k` uses counter
/// `counter_base + k`, and `out[k]` receives its chaining value.
pub(super) fn hash_chunks4(
    input: &[u8],
    key: &[u32; 8],
    counter_base: u64,
    flags: u32,
    out: &mut [[u32; 8]],
) {
    assert!((1..=DEGREE).contains(&out.len()) && input.len() == out.len() * CHUNK_LEN);
    // SAFETY: NEON is a baseline aarch64 feature, and the assert above pins
    // `input` to the `out.len()` chunks the kernel reads.
    unsafe { neon::hash_many::<true>(input.as_ptr(), key, counter_base, flags, out) }
}

/// Compresses `out.len()` (1..=4) parent nodes in parallel: `out[k]` is the
/// parent of `cvs[2k]` and `cvs[2k + 1]`.
pub(super) fn hash_parents4(cvs: &[[u32; 8]], key: &[u32; 8], flags: u32, out: &mut [[u32; 8]]) {
    assert!((1..=DEGREE).contains(&out.len()) && cvs.len() == 2 * out.len());
    // SAFETY: as in `hash_chunks4`; `cvs` is `out.len()` 64-byte parent
    // blocks, laid out as the kernel reads them (see `hash_many`).
    unsafe { neon::hash_many::<false>(cvs.as_ptr().cast(), key, 0, flags | PARENT, out) }
}

/// Writes `out.len() / 64` (1..=4) consecutive extended-output blocks of a
/// root node in parallel: block `k` is the compression of `block` under `cv`
/// at counter `counter + k`, all 16 words, little-endian. `flags` must
/// already carry `ROOT`.
pub(super) fn xof4(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
    out: &mut [u8],
) {
    assert!(out.len().is_multiple_of(64) && (1..=DEGREE).contains(&(out.len() / 64)));
    // SAFETY: NEON is a baseline aarch64 feature, and the assert above sizes
    // `out` to the blocks the kernel writes.
    unsafe { neon::xof_many(cv, block, counter, block_len, flags, out) }
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
    unsafe fn round<const R: usize>(
        v: &mut [uint32x4_t; 16],
        m: &[uint32x4_t; 16],
        tbl: uint8x16_t,
    ) {
        let s = &MSG_SCHEDULE[R];
        unsafe {
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]], tbl);
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]], tbl);
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]], tbl);
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]], tbl);
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]], tbl);
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]], tbl);
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]], tbl);
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]], tbl);
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

    /// Loads the 64-byte block at offset `off` of each lane's input and
    /// transposes into 16 message vectors, where `m[j]` holds word `j` of that
    /// block across the lanes.
    #[inline(always)]
    unsafe fn load_msg(lanes: &[*const u8; DEGREE], off: usize) -> [uint32x4_t; 16] {
        unsafe {
            let mut m = [vdupq_n_u32(0); 16];
            for q in 0..4 {
                let mut quad = [vdupq_n_u32(0); 4];
                for (row, p) in quad.iter_mut().zip(lanes) {
                    // BLAKE3 words are little-endian, so the raw bytes are the
                    // words.
                    let p = p.add(off + q * 16);
                    *row = vreinterpretq_u32_u8(vld1q_u8(p));
                }
                transpose4(&mut quad);
                m[4 * q..4 * q + 4].copy_from_slice(&quad);
            }
            m
        }
    }

    /// Compresses `out.len()` (1..=4) inputs, one per lane. With `CHUNKS`
    /// each input is a full chunk (16 blocks, 1024-byte stride, counter
    /// `counter_base + lane`, `CHUNK_START`/`CHUNK_END` on its first/last
    /// block); without, each is one 64-byte parent block (counter 0, `flags`
    /// already carrying `PARENT`). Lanes past `out.len()` recompute the last
    /// input and are discarded.
    ///
    /// Message words are read as little-endian bytes, which on the
    /// little-endian targets this module is built for is also how a
    /// `[[u32; 8]]` sits in memory: a run of chaining values is read in place
    /// as its parent blocks, left‖right pair after pair.
    ///
    /// # Safety
    /// `input` must be valid for `out.len()` inputs.
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn hash_many<const CHUNKS: bool>(
        input: *const u8,
        key: &[u32; 8],
        counter_base: u64,
        flags: u32,
        out: &mut [[u32; 8]],
    ) {
        unsafe {
            let n = out.len();
            let (blocks, stride) = if CHUNKS { (16, CHUNK_LEN) } else { (1, 64) };
            let lanes: [*const u8; DEGREE] =
                core::array::from_fn(|lane| input.add(lane.min(n - 1) * stride));

            let tbl_bytes: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];
            let tbl = vld1q_u8(tbl_bytes.as_ptr());

            // Per-lane counters: chunk k uses counter_base + k; parents use 0.
            let mut clo = [0u32; DEGREE];
            let mut chi = [0u32; DEGREE];
            if CHUNKS {
                for (k, (lo, hi)) in clo.iter_mut().zip(chi.iter_mut()).enumerate() {
                    let c = counter_base.wrapping_add(k as u64);
                    *lo = c as u32;
                    *hi = (c >> 32) as u32;
                }
            }
            let counter_lo = vld1q_u32(clo.as_ptr());
            let counter_hi = vld1q_u32(chi.as_ptr());
            let block_len = vdupq_n_u32(BLOCK_LEN);

            // Chaining values, one broadcast key word per state lane.
            let mut h = [vdupq_n_u32(0); 8];
            for (hi, &kw) in h.iter_mut().zip(key.iter()) {
                *hi = vdupq_n_u32(kw);
            }

            for b in 0..blocks {
                let block_flags = {
                    let mut f = flags;
                    if CHUNKS && b == 0 {
                        f |= CHUNK_START;
                    }
                    if CHUNKS && b == 15 {
                        f |= CHUNK_END;
                    }
                    vdupq_n_u32(f)
                };

                let msg = load_msg(&lanes, b * 64);

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

                // All seven rounds unrolled, each reading the message words
                // in its own order, so no vectors move between rounds.
                round::<0>(&mut v, &msg, tbl);
                round::<1>(&mut v, &msg, tbl);
                round::<2>(&mut v, &msg, tbl);
                round::<3>(&mut v, &msg, tbl);
                round::<4>(&mut v, &msg, tbl);
                round::<5>(&mut v, &msg, tbl);
                round::<6>(&mut v, &msg, tbl);

                // Chaining value = first 8 words: state[i] ^ state[i + 8].
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
            for ((o, l), h) in out.iter_mut().zip(lo).zip(hi) {
                vst1q_u32(o.as_mut_ptr(), l);
                vst1q_u32(o.as_mut_ptr().add(4), h);
            }
        }
    }

    /// One compression of a root node per lane, at counters `counter`,
    /// `counter + 1`, …: lane `k` writes the full 16-word output block `k` to
    /// `out[64 * k..]`. The message is the same in every lane, so it is a
    /// broadcast rather than a transpose. Lanes past `out.len() / 64` are
    /// computed and dropped.
    ///
    /// # Safety
    /// `out.len()` is a multiple of 64, at most 4 blocks.
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn xof_many(
        cv: &[u32; 8],
        block: &[u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
        out: &mut [u8],
    ) {
        unsafe {
            let tbl_bytes: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];
            let tbl = vld1q_u8(tbl_bytes.as_ptr());
            let mut clo = [0u32; DEGREE];
            let mut chi = [0u32; DEGREE];
            for (k, (lo, hi)) in clo.iter_mut().zip(chi.iter_mut()).enumerate() {
                let c = counter.wrapping_add(k as u64);
                *lo = c as u32;
                *hi = (c >> 32) as u32;
            }
            let m: [uint32x4_t; 16] = core::array::from_fn(|j| vdupq_n_u32(block[j]));
            let h: [uint32x4_t; 8] = core::array::from_fn(|i| vdupq_n_u32(cv[i]));
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
                vld1q_u32(clo.as_ptr()),
                vld1q_u32(chi.as_ptr()),
                vdupq_n_u32(block_len),
                vdupq_n_u32(flags),
            ];
            round::<0>(&mut v, &m, tbl);
            round::<1>(&mut v, &m, tbl);
            round::<2>(&mut v, &m, tbl);
            round::<3>(&mut v, &m, tbl);
            round::<4>(&mut v, &m, tbl);
            round::<5>(&mut v, &m, tbl);
            round::<6>(&mut v, &m, tbl);
            // Output words: state[i] ^ state[i + 8], then state[i + 8] ^ cv[i].
            // Each group of four word-vectors transposes to one 16-byte
            // quarter of every lane's block.
            let mut rows = [vdupq_n_u32(0); 16];
            for i in 0..8 {
                rows[i] = xor(v[i], v[i + 8]);
                rows[i + 8] = xor(v[i + 8], h[i]);
            }
            for q in 0..4 {
                let mut quad = [
                    rows[4 * q],
                    rows[4 * q + 1],
                    rows[4 * q + 2],
                    rows[4 * q + 3],
                ];
                transpose4(&mut quad);
                for (o, row) in out.chunks_exact_mut(64).zip(quad) {
                    vst1q_u8(o.as_mut_ptr().add(16 * q), vreinterpretq_u8_u32(row));
                }
            }
        }
    }
}
