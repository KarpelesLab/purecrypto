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
    !crate::ct::force_portable()
        && std::is_x86_feature_detected!("sha")
        && std::is_x86_feature_detected!("sse2")
        && std::is_x86_feature_detected!("ssse3")
        && std::is_x86_feature_detected!("sse4.1")
}
#[cfg(target_arch = "aarch64")]
pub(super) fn sha256_supported() -> bool {
    !crate::ct::force_portable() && std::arch::is_aarch64_feature_detected!("sha2")
}

/// SHA-256 compression of one 64-byte block, dispatched to the active backend.
///
/// # Safety
/// The caller must have checked [`sha256_supported`]; this executes the SHA
/// extension instructions unconditionally, and they fault with SIGILL on a CPU
/// without them.
pub(super) unsafe fn compress256(h: &mut [u32; 8], block: &[u8; 64]) {
    // SAFETY: the caller's obligation is exactly this function's.
    unsafe { compress256_blocks(h, block) }
}

/// SHA-256 compression of `data` (a whole number of 64-byte blocks), dispatched
/// to the active backend. The backend loads the hash state into registers once
/// and keeps it there across every block, so a single multi-block call avoids
/// the per-block state spill/reload and dispatch overhead that repeated
/// [`compress256`] calls incur — a measurable throughput win on bulk input.
///
/// # Safety
/// The caller must have checked [`sha256_supported`] (see [`compress256`]).
pub(super) unsafe fn compress256_blocks(h: &mut [u32; 8], data: &[u8]) {
    debug_assert!(data.len().is_multiple_of(64));
    debug_assert!(sha256_supported(), "hardware SHA-256 backend not available");
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
    !crate::ct::force_portable() && std::arch::is_aarch64_feature_detected!("sha3")
}

/// SHA-512 compression of one 128-byte block (aarch64 hardware only; never
/// called on x86, where [`sha512_supported`] is `false`).
///
/// # Safety
/// The caller must have checked [`sha512_supported`]; FEAT_SHA512 instructions
/// fault with SIGILL on a CPU without the extension.
#[cfg(target_arch = "aarch64")]
pub(super) unsafe fn compress512(h: &mut [u64; 8], block: &[u8; 128]) {
    debug_assert!(sha512_supported(), "hardware SHA-512 backend not available");
    // SAFETY: the caller guarantees FEAT_SHA512 is present.
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
    !crate::ct::force_portable()
        && std::is_x86_feature_detected!("sha")
        && std::is_x86_feature_detected!("sse2")
        && std::is_x86_feature_detected!("ssse3")
        && std::is_x86_feature_detected!("sse4.1")
}
#[cfg(target_arch = "aarch64")]
pub(super) fn sha1_supported() -> bool {
    !crate::ct::force_portable() && std::arch::is_aarch64_feature_detected!("sha2")
}

/// SHA-1 compression of one 64-byte block, dispatched to the active backend.
///
/// # Safety
/// The caller must have checked [`sha1_supported`]; this executes the SHA
/// extension instructions unconditionally.
pub(super) unsafe fn compress_sha1(h: &mut [u32; 5], block: &[u8; 64]) {
    // SAFETY: the caller's obligation is exactly this function's.
    unsafe { compress_sha1_blocks(h, block) }
}

/// SHA-1 compression of `data` (a whole number of 64-byte blocks), dispatched to
/// the active backend. As with [`compress256_blocks`], the backend loads the hash
/// state into registers once and keeps it there across every block, so a single
/// multi-block call avoids the per-block state spill/reload and dispatch overhead
/// of repeated [`compress_sha1`] calls.
///
/// # Safety
/// The caller must have checked [`sha1_supported`] (see [`compress_sha1`]).
pub(super) unsafe fn compress_sha1_blocks(h: &mut [u32; 5], data: &[u8]) {
    debug_assert!(data.len().is_multiple_of(64));
    debug_assert!(sha1_supported(), "hardware SHA-1 backend not available");
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
    /// standard 16-group `sha256rnds2` / `sha256msg1` / `sha256msg2` sequence as
    /// straight-line code: the four message vectors are named registers rotated
    /// through the macro arguments, so nothing in the schedule goes through a
    /// stack-resident array or a `g % 4` index.
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
                let mut m0 = _mm_shuffle_epi8(_mm_loadu_si128(bptr as *const __m128i), mask);
                let mut m1 =
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr.add(16) as *const __m128i), mask);
                let mut m2 =
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr.add(32) as *const __m128i), mask);
                let mut m3 =
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr.add(48) as *const __m128i), mask);

                // Four rounds under `K[k..k + 4]` with message vector `$mi`
                // (round constants line up with the message lanes). Returns the
                // low-half round key for the second `rnds2`.
                macro_rules! rnds4 {
                    ($mi:ident, $k:expr) => {{
                        let msg =
                            _mm_add_epi32($mi, _mm_loadu_si128(kptr.add($k) as *const __m128i));
                        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
                        msg
                    }};
                }
                // The `sha256msg2` half of the schedule, between the two
                // `rnds2`s: finishes the words of the next group (`$mi1`).
                macro_rules! msg2 {
                    ($mi:ident, $mi1:ident, $mi3:ident) => {{
                        let tmp = _mm_alignr_epi8($mi, $mi3, 4);
                        $mi1 = _mm_add_epi32($mi1, tmp);
                        $mi1 = _mm_sha256msg2_epu32($mi1, $mi);
                    }};
                }
                macro_rules! rnds4_hi {
                    ($msg:ident) => {{
                        let msg = _mm_shuffle_epi32($msg, 0x0E);
                        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
                    }};
                }
                // The `sha256msg1` half: starts the words three groups ahead
                // (`$mi3`).
                macro_rules! msg1 {
                    ($mi:ident, $mi3:ident) => {
                        $mi3 = _mm_sha256msg1_epu32($mi3, $mi);
                    };
                }
                // Group `g` uses `m[g % 4]`; `msg2` runs for groups 3..=14 and
                // `msg1` for groups 1..=12, exactly as the loop form did.
                let t = rnds4!(m0, 0);
                rnds4_hi!(t);
                let t = rnds4!(m1, 4);
                rnds4_hi!(t);
                msg1!(m1, m0);
                let t = rnds4!(m2, 8);
                rnds4_hi!(t);
                msg1!(m2, m1);
                let t = rnds4!(m3, 12);
                msg2!(m3, m0, m2);
                rnds4_hi!(t);
                msg1!(m3, m2);
                let t = rnds4!(m0, 16);
                msg2!(m0, m1, m3);
                rnds4_hi!(t);
                msg1!(m0, m3);
                let t = rnds4!(m1, 20);
                msg2!(m1, m2, m0);
                rnds4_hi!(t);
                msg1!(m1, m0);
                let t = rnds4!(m2, 24);
                msg2!(m2, m3, m1);
                rnds4_hi!(t);
                msg1!(m2, m1);
                let t = rnds4!(m3, 28);
                msg2!(m3, m0, m2);
                rnds4_hi!(t);
                msg1!(m3, m2);
                let t = rnds4!(m0, 32);
                msg2!(m0, m1, m3);
                rnds4_hi!(t);
                msg1!(m0, m3);
                let t = rnds4!(m1, 36);
                msg2!(m1, m2, m0);
                rnds4_hi!(t);
                msg1!(m1, m0);
                let t = rnds4!(m2, 40);
                msg2!(m2, m3, m1);
                rnds4_hi!(t);
                msg1!(m2, m1);
                let t = rnds4!(m3, 44);
                msg2!(m3, m0, m2);
                rnds4_hi!(t);
                msg1!(m3, m2);
                let t = rnds4!(m0, 48);
                msg2!(m0, m1, m3);
                rnds4_hi!(t);
                msg1!(m0, m3);
                let t = rnds4!(m1, 52);
                msg2!(m1, m2, m0);
                rnds4_hi!(t);
                let t = rnds4!(m2, 56);
                msg2!(m2, m3, m1);
                rnds4_hi!(t);
                let t = rnds4!(m3, 60);
                rnds4_hi!(t);

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

    /// SHA-NI SHA-1 multi-block compression. The state is loaded into the
    /// reverse-lane `abcd` vector plus the lane-3 `e` term once and kept there
    /// across every 64-byte block (only the per-block feed-forward touches it), so
    /// an N-block call pays the state load/store exactly once instead of N times.
    /// Each block is 20 straight-line groups of four rounds; the four message
    /// vectors are named registers rotated through the macro arguments, so the
    /// schedule never goes through a stack array or a `g % 4` index.
    ///
    /// Per group, `e` carries the `e` term — it is the pre-round `abcd` of the
    /// previous group, from which `sha1nexte` recovers `rotl30(a)` and adds the
    /// round's message words. The first group instead adds the message to the
    /// incoming `e` (lane 3), which is already un-rotated. The message schedule
    /// advances in three independent steps whose write targets are distinct
    /// (`m[i+3]`, `m[i+2]`, `m[i+1]`), all reading only `m[i]`: `sha1msg1` feeds
    /// groups `g + 3`, the XOR groups `g + 2`, and `sha1msg2` finishes the words
    /// consumed by group `g + 1`. They run for groups 1..=16, 2..=17 and 3..=18
    /// respectively, stopping once the words for group 19 (round 79) exist.
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
                let mut m0 = _mm_shuffle_epi8(_mm_loadu_si128(bptr as *const __m128i), mask);
                let mut m1 =
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr.add(16) as *const __m128i), mask);
                let mut m2 =
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr.add(32) as *const __m128i), mask);
                let mut m3 =
                    _mm_shuffle_epi8(_mm_loadu_si128(bptr.add(48) as *const __m128i), mask);

                // The four rounds themselves (`$imm` = `g / 5` selects the
                // round function / constant baked into `sha1rnds4`).
                macro_rules! rnds {
                    ($imm:literal, $mi:ident) => {{
                        let en = _mm_sha1nexte_epu32(e, $mi);
                        e = abcd;
                        abcd = _mm_sha1rnds4_epu32::<$imm>(abcd, en);
                    }};
                }
                macro_rules! msg1 {
                    ($mi:ident, $mi3:ident) => {
                        $mi3 = _mm_sha1msg1_epu32($mi3, $mi);
                    };
                }
                macro_rules! xor {
                    ($mi:ident, $mi2:ident) => {
                        $mi2 = _mm_xor_si128($mi2, $mi);
                    };
                }
                macro_rules! msg2 {
                    ($mi:ident, $mi1:ident) => {
                        $mi1 = _mm_sha1msg2_epu32($mi1, $mi);
                    };
                }
                // Group 0: the incoming `e` is already un-rotated.
                let en = _mm_add_epi32(e, m0);
                e = abcd;
                abcd = _mm_sha1rnds4_epu32::<0>(abcd, en);
                // Group g uses m[g % 4]: m0 m1 m2 m3 m0 ...
                rnds!(0, m1);
                msg1!(m1, m0);
                rnds!(0, m2);
                msg1!(m2, m1);
                xor!(m2, m0);
                rnds!(0, m3);
                msg1!(m3, m2);
                xor!(m3, m1);
                msg2!(m3, m0);
                rnds!(0, m0);
                msg1!(m0, m3);
                xor!(m0, m2);
                msg2!(m0, m1);
                rnds!(1, m1);
                msg1!(m1, m0);
                xor!(m1, m3);
                msg2!(m1, m2);
                rnds!(1, m2);
                msg1!(m2, m1);
                xor!(m2, m0);
                msg2!(m2, m3);
                rnds!(1, m3);
                msg1!(m3, m2);
                xor!(m3, m1);
                msg2!(m3, m0);
                rnds!(1, m0);
                msg1!(m0, m3);
                xor!(m0, m2);
                msg2!(m0, m1);
                rnds!(1, m1);
                msg1!(m1, m0);
                xor!(m1, m3);
                msg2!(m1, m2);
                rnds!(2, m2);
                msg1!(m2, m1);
                xor!(m2, m0);
                msg2!(m2, m3);
                rnds!(2, m3);
                msg1!(m3, m2);
                xor!(m3, m1);
                msg2!(m3, m0);
                rnds!(2, m0);
                msg1!(m0, m3);
                xor!(m0, m2);
                msg2!(m0, m1);
                rnds!(2, m1);
                msg1!(m1, m0);
                xor!(m1, m3);
                msg2!(m1, m2);
                rnds!(2, m2);
                msg1!(m2, m1);
                xor!(m2, m0);
                msg2!(m2, m3);
                rnds!(3, m3);
                msg1!(m3, m2);
                xor!(m3, m1);
                msg2!(m3, m0);
                rnds!(3, m0);
                msg1!(m0, m3);
                xor!(m0, m2);
                msg2!(m0, m1);
                rnds!(3, m1);
                xor!(m1, m3);
                msg2!(m1, m2);
                rnds!(3, m2);
                msg2!(m2, m3);
                rnds!(3, m3);

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
    /// messages are byte-reversed per 32-bit word. Each block is 16 straight-line
    /// groups of four rounds, evolving the schedule with `sha256su0`/`sha256su1`
    /// (the round key uses the pre-update message words); the four message
    /// vectors are named registers rotated through the macro arguments rather
    /// than a `g % 4`-indexed array.
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
                let mut m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr)));
                let mut m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr.add(16))));
                let mut m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr.add(32))));
                let mut m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr.add(48))));
                // Four rounds under `K[k..k + 4]` with message vector `$mi`.
                macro_rules! r4 {
                    ($mi:ident, $k:expr) => {{
                        let wk = vaddq_u32($mi, vld1q_u32(K256.as_ptr().add($k)));
                        let tmp = abcd;
                        abcd = vsha256hq_u32(abcd, efgh, wk);
                        efgh = vsha256h2q_u32(efgh, tmp, wk);
                    }};
                }
                // Schedule: `$a` becomes the words four groups ahead (runs for
                // groups 0..12; the words for groups 12..16 then all exist).
                macro_rules! sch {
                    ($a:ident, $b:ident, $c:ident, $d:ident) => {
                        $a = vsha256su1q_u32(vsha256su0q_u32($a, $b), $c, $d);
                    };
                }
                r4!(m0, 0);
                sch!(m0, m1, m2, m3);
                r4!(m1, 4);
                sch!(m1, m2, m3, m0);
                r4!(m2, 8);
                sch!(m2, m3, m0, m1);
                r4!(m3, 12);
                sch!(m3, m0, m1, m2);
                r4!(m0, 16);
                sch!(m0, m1, m2, m3);
                r4!(m1, 20);
                sch!(m1, m2, m3, m0);
                r4!(m2, 24);
                sch!(m2, m3, m0, m1);
                r4!(m3, 28);
                sch!(m3, m0, m1, m2);
                r4!(m0, 32);
                sch!(m0, m1, m2, m3);
                r4!(m1, 36);
                sch!(m1, m2, m3, m0);
                r4!(m2, 40);
                sch!(m2, m3, m0, m1);
                r4!(m3, 44);
                sch!(m3, m0, m1, m2);
                r4!(m0, 48);
                r4!(m1, 52);
                r4!(m2, 56);
                r4!(m3, 60);
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
    /// word. Each block is 20 straight-line groups of four rounds, evolving the
    /// schedule with `sha1su0`/`sha1su1` (the round key uses the pre-update
    /// message words) and picking `sha1c`/`sha1p`/`sha1m` per 20-round stage.
    /// The four message vectors are named registers rotated through the macro
    /// arguments and the stage constants are splat once per block, so nothing
    /// in the round goes through a stack array, a `g % 4` index or a `match`
    /// (the loop form cost ~2x: 45 ns/block vs 23 ns).
    #[target_feature(enable = "sha2")]
    pub(super) unsafe fn compress_sha1_blocks(state: &mut [u32; 5], data: &[u8]) {
        unsafe {
            let mut abcd = vld1q_u32(state.as_ptr());
            let mut e = state[4];
            let k0 = vdupq_n_u32(K1[0]);
            let k1 = vdupq_n_u32(K1[1]);
            let k2 = vdupq_n_u32(K1[2]);
            let k3 = vdupq_n_u32(K1[3]);
            let base = data.as_ptr();
            let nblocks = data.len() / 64;
            for blk in 0..nblocks {
                let bptr = base.add(blk * 64);
                let abcd0 = abcd;
                let e0 = e;
                let mut m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr)));
                let mut m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr.add(16))));
                let mut m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr.add(32))));
                let mut m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bptr.add(48))));
                // Four rounds with round key `$wk` and stage function `$op`;
                // `sha1h` rotates the pre-round `a` into the next group's `e`.
                macro_rules! rnd {
                    ($op:ident, $wk:ident) => {{
                        let e_next = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
                        abcd = $op(abcd, e, $wk);
                        e = e_next;
                    }};
                }
                // Group `g` with message vector `$mi` (= `m[g % 4]`); `$mi1`..
                // `$mi3` are the following vectors in rotation. `sha1su0` starts
                // the words for group `g + 4` (groups 0..16), `sha1su1` finishes
                // those for group `g + 3` (groups 1..=16); both stop once the
                // words for group 19 (round 79) exist, which the three tiers
                // below spell out.
                macro_rules! grp {
                    // Group 0: `sha1su0` only.
                    (su0 $op:ident, $k:ident, $mi:ident, $mi1:ident, $mi2:ident) => {{
                        let wk = vaddq_u32($mi, $k);
                        $mi = vsha1su0q_u32($mi, $mi1, $mi2);
                        rnd!($op, wk);
                    }};
                    // Group 16: `sha1su1` only.
                    (su1 $op:ident, $k:ident, $mi:ident, $mi2:ident, $mi3:ident) => {{
                        let wk = vaddq_u32($mi, $k);
                        $mi3 = vsha1su1q_u32($mi3, $mi2);
                        rnd!($op, wk);
                    }};
                    // Groups 17..=19: no schedule left.
                    (last $op:ident, $k:ident, $mi:ident) => {{
                        let wk = vaddq_u32($mi, $k);
                        rnd!($op, wk);
                    }};
                    // Groups 1..=15: both schedule steps.
                    ($op:ident, $k:ident, $mi:ident, $mi1:ident, $mi2:ident, $mi3:ident) => {{
                        let wk = vaddq_u32($mi, $k);
                        $mi = vsha1su0q_u32($mi, $mi1, $mi2);
                        $mi3 = vsha1su1q_u32($mi3, $mi2);
                        rnd!($op, wk);
                    }};
                }
                grp!(su0 vsha1cq_u32, k0, m0, m1, m2); // g0
                grp!(vsha1cq_u32, k0, m1, m2, m3, m0); // g1
                grp!(vsha1cq_u32, k0, m2, m3, m0, m1); // g2
                grp!(vsha1cq_u32, k0, m3, m0, m1, m2); // g3
                grp!(vsha1cq_u32, k0, m0, m1, m2, m3); // g4
                grp!(vsha1pq_u32, k1, m1, m2, m3, m0); // g5
                grp!(vsha1pq_u32, k1, m2, m3, m0, m1); // g6
                grp!(vsha1pq_u32, k1, m3, m0, m1, m2); // g7
                grp!(vsha1pq_u32, k1, m0, m1, m2, m3); // g8
                grp!(vsha1pq_u32, k1, m1, m2, m3, m0); // g9
                grp!(vsha1mq_u32, k2, m2, m3, m0, m1); // g10
                grp!(vsha1mq_u32, k2, m3, m0, m1, m2); // g11
                grp!(vsha1mq_u32, k2, m0, m1, m2, m3); // g12
                grp!(vsha1mq_u32, k2, m1, m2, m3, m0); // g13
                grp!(vsha1mq_u32, k2, m2, m3, m0, m1); // g14
                grp!(vsha1pq_u32, k3, m3, m0, m1, m2); // g15
                grp!(su1 vsha1pq_u32, k3, m0, m2, m3); // g16
                grp!(last vsha1pq_u32, k3, m1); // g17
                grp!(last vsha1pq_u32, k3, m2); // g18
                grp!(last vsha1pq_u32, k3, m3); // g19
                abcd = vaddq_u32(abcd, abcd0);
                e = e.wrapping_add(e0);
            }
            vst1q_u32(state.as_mut_ptr(), abcd);
            state[4] = e;
        }
    }
}
