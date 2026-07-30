//! Hardware SHA — SHA-256 via the x86_64 SHA-NI extension or the aarch64 `sha2`
//! extension, SHA-512 via the aarch64 `sha512` extension (there is no
//! broadly-available x86 SHA-512 instruction, so x86 keeps the software path),
//! and SHA-1 via the SHA-1 instructions of those same two extensions (SHA-NI's
//! `sha1rnds4` family on x86_64, `sha1c`/`sha1p`/`sha1m` on aarch64).
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
    compress256_blocks(h, block);
}

/// SHA-256 compression of `data` (a whole number of 64-byte blocks), dispatched
/// to the active backend. The backend loads the hash state into registers once
/// and keeps it there across every block, so a single multi-block call avoids
/// the per-block state spill/reload and dispatch overhead that repeated
/// [`compress256`] calls incur — a measurable throughput win on bulk input.
pub(super) fn compress256_blocks(h: &mut [u32; 8], data: &[u8]) {
    debug_assert!(data.len().is_multiple_of(64));
    if data.is_empty() {
        return;
    }
    // SAFETY: only called after `sha256_supported()` confirmed the features.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        x86::compress256_blocks(h, data)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        arm::compress256_blocks(h, data)
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

/// Whether a hardware SHA-1 backend is available.
///
/// Both extensions bundle SHA-1 with SHA-256 — x86_64 SHA-NI defines the
/// `sha1rnds4` family under the same `sha` CPUID bit as `sha256rnds2`, and Rust's
/// aarch64 `sha2` feature covers FEAT_SHA1 as well as FEAT_SHA256 — so this is
/// the same predicate as [`sha256_supported`], spelled out separately because the
/// SHA-1 dispatch is a different call site.
#[cfg(target_arch = "x86_64")]
pub(super) fn sha1_supported() -> bool {
    std::is_x86_feature_detected!("sha")
        && std::is_x86_feature_detected!("sse2")
        && std::is_x86_feature_detected!("ssse3")
        && std::is_x86_feature_detected!("sse4.1")
}
#[cfg(target_arch = "aarch64")]
pub(super) fn sha1_supported() -> bool {
    std::arch::is_aarch64_feature_detected!("sha2")
}

/// SHA-1 compression of one 64-byte block, dispatched to the active backend.
pub(super) fn compress_sha1(h: &mut [u32; 5], block: &[u8; 64]) {
    compress_sha1_blocks(h, block);
}

/// SHA-1 compression of `data` (a whole number of 64-byte blocks), dispatched to
/// the active backend. As with [`compress256_blocks`], the backend loads the hash
/// state into registers once and keeps it there across every block, so a single
/// multi-block call avoids the per-block state spill/reload and dispatch overhead
/// of repeated [`compress_sha1`] calls.
pub(super) fn compress_sha1_blocks(h: &mut [u32; 5], data: &[u8]) {
    debug_assert!(data.len().is_multiple_of(64));
    if data.is_empty() {
        return;
    }
    // SAFETY: only called after `sha1_supported()` confirmed the features.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        x86::compress_sha1_blocks(h, data)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        arm::compress_sha1_blocks(h, data)
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use crate::hash::sha256::K256;
    use core::arch::x86_64::*;

    /// SHA-NI multi-block compression. The state is loaded into the ABEF / CDGH
    /// register layout once and kept there across every 64-byte block (only the
    /// per-block Davies–Meyer feed-forward touches it), so an N-block call pays
    /// the state load/store exactly once instead of N times. Each block runs the
    /// standard 16-group `sha256rnds2` / `sha256msg1` / `sha256msg2` sequence,
    /// with the schedule rotation computed from `g % 4`.
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub(super) unsafe fn compress256_blocks(state: &mut [u32; 8], data: &[u8]) {
        unsafe {
            // Per-32-bit-word byte-reverse mask (block words are big-endian).
            let mask = _mm_set_epi64x(
                0x0c0d_0e0f_0809_0a0bu64 as i64,
                0x0405_0607_0001_0203u64 as i64,
            );

            // Load and rearrange the state into the SHA-NI ABEF / CDGH layout
            // once; it stays resident in `state0` / `state1` across all blocks.
            let tmp0 = _mm_loadu_si128(state.as_ptr() as *const __m128i); // a b c d
            let s1_0 = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i); // e f g h
            let tmp = _mm_shuffle_epi32(tmp0, 0xB1); // c d a b
            let s1 = _mm_shuffle_epi32(s1_0, 0x1B); // h g f e
            let mut state0 = _mm_alignr_epi8(tmp, s1, 8); // ABEF
            let mut state1 = _mm_blend_epi16(s1, tmp, 0xF0); // CDGH

            let kptr = K256.as_ptr();
            let base = data.as_ptr();
            let nblocks = data.len() / 64;
            for blk in 0..nblocks {
                let bptr = base.add(blk * 64);
                let abef_save = state0;
                let cdgh_save = state1;

                // Load the four message vectors (16 bytes each), byte-reversed.
                let mut m = [
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr as *const __m128i), mask),
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr.add(16) as *const __m128i), mask),
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr.add(32) as *const __m128i), mask),
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr.add(48) as *const __m128i), mask),
                ];

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
            }

            // Un-shuffle ABEF / CDGH back to a..h and store once.
            let tmp = _mm_shuffle_epi32(state0, 0x1B); // FEBA
            let s1 = _mm_shuffle_epi32(state1, 0xB1); // DCHG
            let out0 = _mm_blend_epi16(tmp, s1, 0xF0); // DCBA
            let out1 = _mm_alignr_epi8(s1, tmp, 8); // HGFE
            _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, out0);
            _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, out1);
        }
    }

    /// One SHA-NI group of four SHA-1 rounds (`g` = 0..20, `IMM` = `g / 5`
    /// selects the round function / constant group baked into `sha1rnds4`).
    ///
    /// `abcd` holds state words a..d in reverse lane order; `ecar` carries the
    /// `e` term — it is the pre-round `abcd` of the previous group, from which
    /// `sha1nexte` recovers `rotl30(a)` and adds the round's message words. The
    /// first group instead adds the message to the incoming `e` (lane 3), which
    /// is already un-rotated.
    ///
    /// The message schedule advances in three independent steps whose write
    /// targets are distinct (`m[i+3]`, `m[i+2]`, `m[i+1]`), all reading only
    /// `m[i]`: `sha1msg1` feeds groups `g + 3`, the XOR groups `g + 2`, and
    /// `sha1msg2` finishes the words consumed by group `g + 1`. Their ranges stop
    /// once the words for group 19 (round 79) are complete.
    // Not `inline(always)`: that is rejected on `#[target_feature]` functions
    // (rust#145574). The hint suffices — the caller enables the same features, so
    // LLVM inlines and unrolls these into the block loop.
    #[inline]
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    unsafe fn sha1_group<const IMM: i32>(
        g: usize,
        abcd: &mut __m128i,
        ecar: &mut __m128i,
        m: &mut [__m128i; 4],
    ) {
        unsafe {
            let i = g % 4;
            let e = if g == 0 {
                _mm_add_epi32(*ecar, m[0])
            } else {
                _mm_sha1nexte_epu32(*ecar, m[i])
            };
            *ecar = *abcd;
            *abcd = _mm_sha1rnds4_epu32::<IMM>(*abcd, e);
            if (1..=16).contains(&g) {
                m[(i + 3) % 4] = _mm_sha1msg1_epu32(m[(i + 3) % 4], m[i]);
            }
            if (2..=17).contains(&g) {
                m[(i + 2) % 4] = _mm_xor_si128(m[(i + 2) % 4], m[i]);
            }
            if (3..=18).contains(&g) {
                m[(i + 1) % 4] = _mm_sha1msg2_epu32(m[(i + 1) % 4], m[i]);
            }
        }
    }

    /// SHA-NI SHA-1 multi-block compression. The state is loaded into the
    /// reverse-lane `abcd` vector plus the lane-3 `e` term once and kept there
    /// across every 64-byte block (only the per-block feed-forward touches it), so
    /// an N-block call pays the state load/store exactly once instead of N times.
    /// Each block runs 20 groups of four rounds via [`sha1_group`], one const-`IMM`
    /// quarter at a time.
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub(super) unsafe fn compress_sha1_blocks(state: &mut [u32; 5], data: &[u8]) {
        unsafe {
            // Whole-vector byte reverse: SHA-1 message words are big-endian and
            // the instructions want them in reverse lane order.
            let mask = _mm_set_epi64x(
                0x0001_0203_0405_0607u64 as i64,
                0x0809_0a0b_0c0d_0e0fu64 as i64,
            );

            // Load the state once; it stays resident across all blocks. `abcd` is
            // d c b a (reverse lane order), `e` sits in lane 3 un-rotated.
            let mut abcd =
                _mm_shuffle_epi32(_mm_loadu_si128(state.as_ptr() as *const __m128i), 0x1B);
            let mut e = _mm_set_epi32(state[4] as i32, 0, 0, 0);

            let base = data.as_ptr();
            let nblocks = data.len() / 64;
            for blk in 0..nblocks {
                let bptr = base.add(blk * 64);
                let abcd_save = abcd;
                let e_save = e;

                // Load the four message vectors (16 bytes each), byte-reversed.
                let mut m = [
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr as *const __m128i), mask),
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr.add(16) as *const __m128i), mask),
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr.add(32) as *const __m128i), mask),
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr.add(48) as *const __m128i), mask),
                ];

                // `e` enters as the carry for group 0 and leaves as the carry of
                // group 19 (the pre-round `abcd`), which the feed-forward below
                // turns back into the next block's lane-3 `e`.
                for g in 0..5 {
                    sha1_group::<0>(g, &mut abcd, &mut e, &mut m);
                }
                for g in 5..10 {
                    sha1_group::<1>(g, &mut abcd, &mut e, &mut m);
                }
                for g in 10..15 {
                    sha1_group::<2>(g, &mut abcd, &mut e, &mut m);
                }
                for g in 15..20 {
                    sha1_group::<3>(g, &mut abcd, &mut e, &mut m);
                }

                // Davies-Meyer feed-forward: `sha1nexte` supplies the rotate the
                // final carry still owes, then adds the saved `e`.
                e = _mm_sha1nexte_epu32(e, e_save);
                abcd = _mm_add_epi32(abcd, abcd_save);
            }

            // Un-reverse the lanes and store a..d, then extract `e` from lane 3.
            _mm_storeu_si128(
                state.as_mut_ptr() as *mut __m128i,
                _mm_shuffle_epi32(abcd, 0x1B),
            );
            state[4] = _mm_extract_epi32::<3>(e) as u32;
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use crate::hash::sha1::K1;
    use crate::hash::sha256::K256;
    use crate::hash::sha512::K512;
    use core::arch::aarch64::*;

    /// SHA-256 multi-block compression using the ARMv8 `sha2` extension. State
    /// (`abcd`/`efgh`) is loaded once and kept in registers across every block;
    /// messages are byte-reversed per 32-bit word. Each block runs a 16-group
    /// loop keyed on `g % 4`, evolving the schedule with `sha256su0`/`sha256su1`
    /// (the round key uses the pre-update message words).
    #[target_feature(enable = "sha2")]
    pub(super) unsafe fn compress256_blocks(state: &mut [u32; 8], data: &[u8]) {
        unsafe {
            let mut abcd = vld1q_u32(state.as_ptr());
            let mut efgh = vld1q_u32(state.as_ptr().add(4));
            let base = data.as_ptr();
            let nblocks = data.len() / 64;
            for blk in 0..nblocks {
                let bptr = base.add(blk * 64);
                let abcd0 = abcd;
                let efgh0 = efgh;
                let mut m = [
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr.add(16)))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr.add(32)))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr.add(48)))),
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
                abcd = vaddq_u32(abcd, abcd0);
                efgh = vaddq_u32(efgh, efgh0);
            }
            vst1q_u32(state.as_mut_ptr(), abcd);
            vst1q_u32(state.as_mut_ptr().add(4), efgh);
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

    /// SHA-1 multi-block compression using the ARMv8 `sha2` extension (its
    /// FEAT_SHA1 half). State (`abcd` vector + scalar `e`) is loaded once and kept
    /// in registers across every block; messages are byte-reversed per 32-bit
    /// word. Each block runs 20 groups of four rounds keyed on `g % 4`, evolving
    /// the schedule with `sha1su0`/`sha1su1` (the round key uses the pre-update
    /// message words) and picking `sha1c`/`sha1p`/`sha1m` per 20-round stage.
    #[target_feature(enable = "sha2")]
    pub(super) unsafe fn compress_sha1_blocks(state: &mut [u32; 5], data: &[u8]) {
        unsafe {
            let mut abcd = vld1q_u32(state.as_ptr());
            let mut e = state[4];
            let base = data.as_ptr();
            let nblocks = data.len() / 64;
            for blk in 0..nblocks {
                let bptr = base.add(blk * 64);
                let abcd0 = abcd;
                let e0 = e;
                let mut m = [
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr.add(16)))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr.add(32)))),
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr.add(48)))),
                ];
                for g in 0..20usize {
                    let i = g % 4;
                    let wk = vaddq_u32(m[i], vdupq_n_u32(K1[g / 5]));
                    // `sha1su0` starts the words for group `g + 4`, `sha1su1`
                    // finishes those for group `g + 3`; both stop once the words
                    // for group 19 (round 79) exist.
                    if g < 16 {
                        m[i] = vsha1su0q_u32(m[i], m[(i + 1) % 4], m[(i + 2) % 4]);
                    }
                    if (1..=16).contains(&g) {
                        m[(i + 3) % 4] = vsha1su1q_u32(m[(i + 3) % 4], m[(i + 2) % 4]);
                    }
                    // `sha1h` rotates the pre-round `a` into the next group's `e`.
                    let e_next = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
                    abcd = match g / 5 {
                        0 => vsha1cq_u32(abcd, e, wk),
                        2 => vsha1mq_u32(abcd, e, wk),
                        _ => vsha1pq_u32(abcd, e, wk),
                    };
                    e = e_next;
                }
                abcd = vaddq_u32(abcd, abcd0);
                e = e.wrapping_add(e0);
            }
            vst1q_u32(state.as_mut_ptr(), abcd);
            state[4] = e;
        }
    }
}
