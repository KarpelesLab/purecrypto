//! SIMD backends for BLAKE3 — 8-way (AVX2) and 16-way (AVX-512) parallel
//! compression of chunks and parent nodes.
//!
//! BLAKE3 hashes its input as independent 1024-byte chunks whose chaining
//! values form a binary tree. Those chunks are mutually independent, so the
//! bulk of a large hash parallelises perfectly: these kernels compress up to
//! 8 (AVX2) or 16 (AVX-512) chunks at once, one per 32-bit lane, producing one
//! chunk chaining value per lane. The parent nodes of one tree level are just
//! as independent, so the same kernels also compress up to 8 or 16 parent
//! blocks (a left‖right pair of chaining values each) at once. The per-lane
//! arithmetic is byte-for-byte the scalar [`super::blake3`] compression (same
//! `g`, same round schedule, same message schedule), just executed
//! lane-wide; this is pinned by differential tests against the scalar
//! `ChunkState` and parent compression.
//!
//! A call may fill fewer lanes than the vector width: the unused lanes
//! recompute the last real input and their results are dropped, so a short
//! batch costs one full-width pass instead of falling back to scalar.
//!
//! Only full chunks are vectorised (every block is 64 bytes, `CHUNK_START` on
//! block 0 and `CHUNK_END` on block 15). Partial chunks and the XOF stay on the
//! scalar path. x86_64 only; the `super::blake3` dispatch falls back to scalar
//! when AVX2 is absent or on other architectures.
#![allow(unsafe_code)]

use super::blake3::{CHUNK_END, CHUNK_LEN, CHUNK_START, IV, MSG_SCHEDULE, PARENT};

/// Lanes per call of the AVX2 kernels.
pub(super) const DEGREE: usize = 8;

/// Lanes per call of the AVX-512 kernels.
pub(super) const DEGREE16: usize = 16;

/// Whether the AVX-512 BLAKE3 backend is available on this CPU.
#[cfg(target_arch = "x86_64")]
pub(super) fn supported16() -> bool {
    !crate::ct::force_portable() && crate::cpu::avx512f()
}

/// Whether the AVX2 BLAKE3 backend is available on this CPU.
#[cfg(target_arch = "x86_64")]
pub(super) fn supported() -> bool {
    !crate::ct::force_portable() && crate::cpu::avx2()
}

/// Compresses `out.len()` (1..=16) consecutive full 1024-byte chunks in
/// parallel with AVX-512.
///
/// `input` is exactly `out.len() * CHUNK_LEN` bytes; chunk `k` uses counter
/// `counter_base + k`, and `out[k]` receives its chaining value.
///
/// Callers are expected to have checked [`supported16`]; this re-checks the
/// (cached) CPU feature flag and panics rather than executing the kernel on a
/// CPU without AVX-512F, so the function is safe to call unconditionally.
#[cfg(target_arch = "x86_64")]
pub(super) fn hash_chunks16(
    input: &[u8],
    key: &[u32; 8],
    counter_base: u64,
    flags: u32,
    out: &mut [[u32; 8]],
) {
    assert!(
        supported16(),
        "blake3 hash_chunks16 called on a CPU without AVX-512F; check supported16() first"
    );
    assert!((1..=DEGREE16).contains(&out.len()) && input.len() == out.len() * CHUNK_LEN);
    // SAFETY: `supported16()` just confirmed AVX-512F on this CPU, and the
    // assert above pins `input` to the `out.len()` chunks the kernel reads.
    unsafe { avx512::hash_many::<true>(input.as_ptr(), key, counter_base, flags, out) }
}

/// Compresses `out.len()` (1..=16) parent nodes in parallel with AVX-512:
/// `out[k]` is the parent of `cvs[2k]` and `cvs[2k + 1]`.
///
/// Same CPU-feature contract as [`hash_chunks16`].
#[cfg(target_arch = "x86_64")]
pub(super) fn hash_parents16(cvs: &[[u32; 8]], key: &[u32; 8], flags: u32, out: &mut [[u32; 8]]) {
    assert!(
        supported16(),
        "blake3 hash_parents16 called on a CPU without AVX-512F; check supported16() first"
    );
    assert!((1..=DEGREE16).contains(&out.len()) && cvs.len() == 2 * out.len());
    // SAFETY: as in `hash_chunks16`; `cvs` is `out.len()` 64-byte parent
    // blocks, laid out as the kernel reads them (see `hash_many`).
    unsafe { avx512::hash_many::<false>(cvs.as_ptr().cast(), key, 0, flags | PARENT, out) }
}

/// Compresses `out.len()` (1..=8) consecutive full 1024-byte chunks in
/// parallel with AVX2. Same contract as [`hash_chunks16`], eight lanes wide.
///
/// Callers are expected to have checked [`supported`]; this re-checks the
/// (cached) CPU feature flag and panics rather than executing the kernel on a
/// CPU without AVX2, so the function is safe to call unconditionally.
#[cfg(target_arch = "x86_64")]
pub(super) fn hash_chunks8(
    input: &[u8],
    key: &[u32; 8],
    counter_base: u64,
    flags: u32,
    out: &mut [[u32; 8]],
) {
    assert!(
        supported(),
        "blake3 hash_chunks8 called on a CPU without AVX2; check supported() first"
    );
    assert!((1..=DEGREE).contains(&out.len()) && input.len() == out.len() * CHUNK_LEN);
    // SAFETY: `supported()` just confirmed AVX2 on this CPU, and the assert
    // above pins `input` to the `out.len()` chunks the kernel reads.
    unsafe { avx2::hash_many::<true>(input.as_ptr(), key, counter_base, flags, out) }
}

/// Compresses `out.len()` (1..=8) parent nodes in parallel with AVX2. Same
/// contract as [`hash_parents16`], eight lanes wide.
#[cfg(target_arch = "x86_64")]
pub(super) fn hash_parents8(cvs: &[[u32; 8]], key: &[u32; 8], flags: u32, out: &mut [[u32; 8]]) {
    assert!(
        supported(),
        "blake3 hash_parents8 called on a CPU without AVX2; check supported() first"
    );
    assert!((1..=DEGREE).contains(&out.len()) && cvs.len() == 2 * out.len());
    // SAFETY: as in `hash_chunks8`; `cvs` is `out.len()` 64-byte parent
    // blocks, laid out as the kernel reads them (see `hash_many`).
    unsafe { avx2::hash_many::<false>(cvs.as_ptr().cast(), key, 0, flags | PARENT, out) }
}

#[cfg(target_arch = "x86_64")]
mod avx512 {
    use super::*;
    use core::arch::x86_64::*;

    const BLOCK_LEN: u32 = 64;

    // AVX-512 rotates a lane in one instruction (`vprord`), where the AVX2
    // kernel below needs a shift/shift/or trio per rotation. BLAKE3's `g` is
    // four rotations and four adds, so this lands on the critical path.
    #[inline(always)]
    unsafe fn rotr<const N: i32>(x: __m512i) -> __m512i {
        unsafe { _mm512_ror_epi32::<N>(x) }
    }
    #[inline(always)]
    unsafe fn add(a: __m512i, b: __m512i) -> __m512i {
        unsafe { _mm512_add_epi32(a, b) }
    }
    #[inline(always)]
    unsafe fn xor(a: __m512i, b: __m512i) -> __m512i {
        unsafe { _mm512_xor_si512(a, b) }
    }

    /// The 16-wide BLAKE3 `g` mixing function (lanes are independent inputs).
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    unsafe fn g(
        v: &mut [__m512i; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        mx: __m512i,
        my: __m512i,
    ) {
        unsafe {
            v[a] = add(add(v[a], v[b]), mx);
            v[d] = rotr::<16>(xor(v[d], v[a]));
            v[c] = add(v[c], v[d]);
            v[b] = rotr::<12>(xor(v[b], v[c]));
            v[a] = add(add(v[a], v[b]), my);
            v[d] = rotr::<8>(xor(v[d], v[a]));
            v[c] = add(v[c], v[d]);
            v[b] = rotr::<7>(xor(v[b], v[c]));
        }
    }

    #[inline(always)]
    unsafe fn round<const R: usize>(v: &mut [__m512i; 16], m: &[__m512i; 16]) {
        let s = &MSG_SCHEDULE[R];
        unsafe {
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
    }

    use crate::hash::simd_x86::transpose16_epi32 as transpose16;

    /// Loads the 64-byte block at offset `off` of each lane's input and
    /// transposes into 16 message vectors, where `m[j]` holds word `j` of that
    /// block across the 16 lanes.
    ///
    /// A 64-byte BLAKE3 block is exactly one `__m512i`, so unlike the AVX2 path
    /// this is one load per lane and a single transpose rather than two halves.
    #[inline(always)]
    unsafe fn load_msg(lanes: &[*const u8; 16], off: usize) -> [__m512i; 16] {
        unsafe {
            let mut m = [_mm512_setzero_si512(); 16];
            for (mi, p) in m.iter_mut().zip(lanes) {
                // BLAKE3 words are little-endian, so the raw bytes are the words.
                *mi = _mm512_loadu_si512(p.add(off) as *const _);
            }
            transpose16(&mut m);
            m
        }
    }

    /// Compresses `out.len()` (1..=16) inputs, one per lane. With `CHUNKS`
    /// each input is a full chunk (16 blocks, 1024-byte stride, counter
    /// `counter_base + lane`, `CHUNK_START`/`CHUNK_END` on its first/last
    /// block); without, each is one 64-byte parent block (counter 0, `flags`
    /// already carrying `PARENT`). Lanes past `out.len()` recompute the last
    /// input and are discarded.
    ///
    /// Message words are read as little-endian bytes, which on x86 is also
    /// how a `[[u32; 8]]` sits in memory: a run of chaining values is read in
    /// place as its parent blocks, left‖right pair after pair.
    ///
    /// # Safety
    /// Requires AVX-512F, and `input` must be valid for `out.len()` inputs.
    #[target_feature(enable = "avx512f")]
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
            let lanes: [*const u8; 16] =
                core::array::from_fn(|lane| input.add(lane.min(n - 1) * stride));

            // Per-lane counters: chunk k uses counter_base + k; parents use 0.
            let mut clo = [0u32; 16];
            let mut chi = [0u32; 16];
            if CHUNKS {
                for (k, (lo, hi)) in clo.iter_mut().zip(chi.iter_mut()).enumerate() {
                    let c = counter_base.wrapping_add(k as u64);
                    *lo = c as u32;
                    *hi = (c >> 32) as u32;
                }
            }
            let counter_lo = _mm512_loadu_si512(clo.as_ptr() as *const _);
            let counter_hi = _mm512_loadu_si512(chi.as_ptr() as *const _);
            let block_len = _mm512_set1_epi32(BLOCK_LEN as i32);

            // Chaining values, one broadcast key word per state lane.
            let mut h = [_mm512_setzero_si512(); 8];
            for (hi, &kw) in h.iter_mut().zip(key.iter()) {
                *hi = _mm512_set1_epi32(kw as i32);
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
                    _mm512_set1_epi32(f as i32)
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
                    _mm512_set1_epi32(IV[0] as i32),
                    _mm512_set1_epi32(IV[1] as i32),
                    _mm512_set1_epi32(IV[2] as i32),
                    _mm512_set1_epi32(IV[3] as i32),
                    counter_lo,
                    counter_hi,
                    block_len,
                    block_flags,
                ];

                // All seven rounds unrolled, each reading the message words
                // in its own order, so no vectors move between rounds.
                round::<0>(&mut v, &msg);
                round::<1>(&mut v, &msg);
                round::<2>(&mut v, &msg);
                round::<3>(&mut v, &msg);
                round::<4>(&mut v, &msg);
                round::<5>(&mut v, &msg);
                round::<6>(&mut v, &msg);

                // Chaining value = first 8 words: state[i] ^ state[i + 8].
                for i in 0..8 {
                    h[i] = xor(v[i], v[i + 8]);
                }
            }

            // Transpose the 8 CV word-vectors back to per-lane CVs. The
            // transpose is square, so rows 8..16 are padded with zeros and the
            // CV is the first 8 words of each output row.
            let mut rows = [_mm512_setzero_si512(); 16];
            rows[..8].copy_from_slice(&h);
            transpose16(&mut rows);
            for (o, row) in out.iter_mut().zip(rows.iter()) {
                _mm256_storeu_si256(o.as_mut_ptr() as *mut _, _mm512_castsi512_si256(*row));
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::*;
    use core::arch::x86_64::*;

    const BLOCK_LEN: u32 = 64;

    // The intrinsics need the shift amount as a compile-time immediate, so the
    // four BLAKE3 rotations (16/12/8/7) are specialised rather than parametric.
    #[inline(always)]
    unsafe fn rotr16(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<16>(x), _mm256_slli_epi32::<16>(x)) }
    }
    #[inline(always)]
    unsafe fn rotr12(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<12>(x), _mm256_slli_epi32::<20>(x)) }
    }
    #[inline(always)]
    unsafe fn rotr8(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<8>(x), _mm256_slli_epi32::<24>(x)) }
    }
    #[inline(always)]
    unsafe fn rotr7(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<7>(x), _mm256_slli_epi32::<25>(x)) }
    }

    #[inline(always)]
    unsafe fn add(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_add_epi32(a, b) }
    }

    #[inline(always)]
    unsafe fn xor(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_xor_si256(a, b) }
    }

    /// The 8-wide BLAKE3 `g` mixing function (lanes are independent inputs).
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    unsafe fn g(
        v: &mut [__m256i; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        mx: __m256i,
        my: __m256i,
    ) {
        unsafe {
            v[a] = add(add(v[a], v[b]), mx);
            v[d] = rotr16(xor(v[d], v[a]));
            v[c] = add(v[c], v[d]);
            v[b] = rotr12(xor(v[b], v[c]));
            v[a] = add(add(v[a], v[b]), my);
            v[d] = rotr8(xor(v[d], v[a]));
            v[c] = add(v[c], v[d]);
            v[b] = rotr7(xor(v[b], v[c]));
        }
    }

    #[inline(always)]
    unsafe fn round<const R: usize>(v: &mut [__m256i; 16], m: &[__m256i; 16]) {
        let s = &MSG_SCHEDULE[R];
        unsafe {
            // Columns.
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            // Diagonals.
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
    }

    // In-place 8x8 transpose of eight `__m256i` (each holding 8 `u32`), shared
    // with the multi-buffer SHA-256 kernel.
    use crate::hash::simd_x86::transpose8_epi32 as transpose8;

    /// Loads the 64-byte block at offset `off` of each lane's input and
    /// transposes into 16 message vectors, where `m[j]` holds word `j` of that
    /// block across the 8 lanes.
    #[inline(always)]
    unsafe fn load_msg(lanes: &[*const u8; 8], off: usize) -> [__m256i; 16] {
        unsafe {
            let mut lo = [_mm256_setzero_si256(); 8];
            let mut hi = [_mm256_setzero_si256(); 8];
            for ((l, h), p) in lo.iter_mut().zip(hi.iter_mut()).zip(lanes) {
                let p = p.add(off);
                // BLAKE3 words are little-endian, so the raw bytes are the words.
                *l = _mm256_loadu_si256(p as *const __m256i); // words 0..=7
                *h = _mm256_loadu_si256(p.add(32) as *const __m256i); // words 8..=15
            }
            transpose8(&mut lo);
            transpose8(&mut hi);
            let mut m = [_mm256_setzero_si256(); 16];
            m[..8].copy_from_slice(&lo);
            m[8..].copy_from_slice(&hi);
            m
        }
    }

    /// The 8-lane counterpart of `avx512::hash_many`, same contract.
    ///
    /// # Safety
    /// Requires AVX2, and `input` must be valid for `out.len()` inputs.
    #[target_feature(enable = "avx2")]
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
            let lanes: [*const u8; 8] =
                core::array::from_fn(|lane| input.add(lane.min(n - 1) * stride));

            // Per-lane counters: chunk k uses counter_base + k; parents use 0.
            let mut clo = [0u32; 8];
            let mut chi = [0u32; 8];
            if CHUNKS {
                for (k, (lo, hi)) in clo.iter_mut().zip(chi.iter_mut()).enumerate() {
                    let c = counter_base.wrapping_add(k as u64);
                    *lo = c as u32;
                    *hi = (c >> 32) as u32;
                }
            }
            let counter_lo = _mm256_loadu_si256(clo.as_ptr() as *const __m256i);
            let counter_hi = _mm256_loadu_si256(chi.as_ptr() as *const __m256i);
            let block_len = _mm256_set1_epi32(BLOCK_LEN as i32);

            // Chaining values, one broadcast key word per state lane.
            let mut h = [_mm256_setzero_si256(); 8];
            for (hi, &kw) in h.iter_mut().zip(key.iter()) {
                *hi = _mm256_set1_epi32(kw as i32);
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
                    _mm256_set1_epi32(f as i32)
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
                    _mm256_set1_epi32(IV[0] as i32),
                    _mm256_set1_epi32(IV[1] as i32),
                    _mm256_set1_epi32(IV[2] as i32),
                    _mm256_set1_epi32(IV[3] as i32),
                    counter_lo,
                    counter_hi,
                    block_len,
                    block_flags,
                ];

                // All seven rounds unrolled, each reading the message words
                // in its own order, so no vectors move between rounds.
                round::<0>(&mut v, &msg);
                round::<1>(&mut v, &msg);
                round::<2>(&mut v, &msg);
                round::<3>(&mut v, &msg);
                round::<4>(&mut v, &msg);
                round::<5>(&mut v, &msg);
                round::<6>(&mut v, &msg);

                // Chaining value = first 8 words: state[i] ^ state[i + 8].
                for i in 0..8 {
                    h[i] = xor(v[i], v[i + 8]);
                }
            }

            // Transpose the 8 CV word-vectors back to per-lane CVs.
            transpose8(&mut h);
            for (o, row) in out.iter_mut().zip(h.iter()) {
                _mm256_storeu_si256(o.as_mut_ptr() as *mut __m256i, *row);
            }
        }
    }
}
