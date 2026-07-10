//! 4-way Keccak-p[1600] — four independent 1600-bit states permuted in
//! parallel across the four 64-bit lanes of AVX2 `__m256i` registers.
//!
//! Independent sponges have no cross-state data dependency, so every step of
//! the round function vectorises perfectly 4-wide (χ's `!a & b` maps to the
//! native `vpandn`, so no lane complementing is needed here). This is the
//! right primitive for the FIPS 203/204/205 expansion hot paths, which
//! squeeze many independent SHAKE streams from a common public seed: ML-KEM's
//! matrix `Â` (K² streams), ML-DSA's matrix expansion (K·L streams), and the
//! CBD noise PRF (one stream per nonce).
//!
//! The kernel exposes [`keccak_p_x4`] over an interleaved `[u64; 100]` state
//! (lane `i` of stream `l` at index `4·i + l`, so each register loads
//! contiguously), plus [`KeccakX4`], a four-stream one-shot sponge for
//! short (single-block) inputs with block-at-a-time squeezing. Per-stream
//! output is byte-identical to the scalar [`super::keccak::Keccak`] sponge —
//! pinned by a differential test against four scalar `keccak_p` runs. The
//! kernel is branch-free in the state (bitwise/rotate only); x86_64 + AVX2
//! only, callers check [`supported`] and fall back to the scalar path.
#![allow(unsafe_code)]

/// Streams processed in parallel (AVX2 64-bit lane count).
pub(crate) const LANES: usize = 4;

/// The maximum rate handled by [`KeccakX4`] (SHAKE128's 168 bytes).
pub(crate) const MAX_RATE: usize = 168;

/// Whether the 4-way Keccak backend is available on this CPU.
pub(crate) fn supported() -> bool {
    std::is_x86_feature_detected!("avx2")
}

/// Keccak-p[1600, `rounds`] applied to four interleaved states: lane `i` of
/// stream `l` lives at `state[4 * i + l]`.
///
/// Callers must have checked [`supported`].
pub(crate) fn keccak_p_x4(state: &mut [u64; 100], rounds: usize) {
    // SAFETY: `supported()` (checked by the caller) confirmed AVX2.
    unsafe { avx2::keccak_p_x4(state, rounds) }
}

mod avx2 {
    use crate::hash::keccak::RC;
    use core::arch::x86_64::*;

    /// Rotate-left each 64-bit lane by `N` (with `M = 64 - N`).
    #[inline(always)]
    unsafe fn rotl<const N: i32, const M: i32>(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_slli_epi64::<N>(x), _mm256_srli_epi64::<M>(x)) }
    }
    #[inline(always)]
    unsafe fn xor(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_xor_si256(a, b) }
    }
    /// `!a & b` (the χ nonlinearity), one `vpandn`.
    #[inline(always)]
    unsafe fn andnot(a: __m256i, b: __m256i) -> __m256i {
        unsafe { _mm256_andnot_si256(a, b) }
    }

    /// One Keccak-p round, 4-wide. Same θ/ρπ/χ/ι data flow as the scalar
    /// round in [`crate::hash::keccak`], but with the standard (plain) χ
    /// since `vpandn` computes `!a & b` in one instruction.
    #[inline(always)]
    unsafe fn round(v: &mut [__m256i; 25], rc: __m256i) {
        unsafe {
            let c0 = xor(xor(xor(xor(v[0], v[5]), v[10]), v[15]), v[20]);
            let c1 = xor(xor(xor(xor(v[1], v[6]), v[11]), v[16]), v[21]);
            let c2 = xor(xor(xor(xor(v[2], v[7]), v[12]), v[17]), v[22]);
            let c3 = xor(xor(xor(xor(v[3], v[8]), v[13]), v[18]), v[23]);
            let c4 = xor(xor(xor(xor(v[4], v[9]), v[14]), v[19]), v[24]);
            let d0 = xor(c4, rotl::<1, 63>(c1));
            let d1 = xor(c0, rotl::<1, 63>(c2));
            let d2 = xor(c1, rotl::<1, 63>(c3));
            let d3 = xor(c2, rotl::<1, 63>(c4));
            let d4 = xor(c3, rotl::<1, 63>(c0));
            let b0 = xor(v[0], d0);
            let b1 = rotl::<44, 20>(xor(v[6], d1));
            let b2 = rotl::<43, 21>(xor(v[12], d2));
            let b3 = rotl::<21, 43>(xor(v[18], d3));
            let b4 = rotl::<14, 50>(xor(v[24], d4));
            let b5 = rotl::<28, 36>(xor(v[3], d3));
            let b6 = rotl::<20, 44>(xor(v[9], d4));
            let b7 = rotl::<3, 61>(xor(v[10], d0));
            let b8 = rotl::<45, 19>(xor(v[16], d1));
            let b9 = rotl::<61, 3>(xor(v[22], d2));
            let b10 = rotl::<1, 63>(xor(v[1], d1));
            let b11 = rotl::<6, 58>(xor(v[7], d2));
            let b12 = rotl::<25, 39>(xor(v[13], d3));
            let b13 = rotl::<8, 56>(xor(v[19], d4));
            let b14 = rotl::<18, 46>(xor(v[20], d0));
            let b15 = rotl::<27, 37>(xor(v[4], d4));
            let b16 = rotl::<36, 28>(xor(v[5], d0));
            let b17 = rotl::<10, 54>(xor(v[11], d1));
            let b18 = rotl::<15, 49>(xor(v[17], d2));
            let b19 = rotl::<56, 8>(xor(v[23], d3));
            let b20 = rotl::<62, 2>(xor(v[2], d2));
            let b21 = rotl::<55, 9>(xor(v[8], d3));
            let b22 = rotl::<39, 25>(xor(v[14], d4));
            let b23 = rotl::<41, 23>(xor(v[15], d0));
            let b24 = rotl::<2, 62>(xor(v[21], d1));
            v[0] = xor(xor(b0, andnot(b1, b2)), rc);
            v[1] = xor(b1, andnot(b2, b3));
            v[2] = xor(b2, andnot(b3, b4));
            v[3] = xor(b3, andnot(b4, b0));
            v[4] = xor(b4, andnot(b0, b1));
            v[5] = xor(b5, andnot(b6, b7));
            v[6] = xor(b6, andnot(b7, b8));
            v[7] = xor(b7, andnot(b8, b9));
            v[8] = xor(b8, andnot(b9, b5));
            v[9] = xor(b9, andnot(b5, b6));
            v[10] = xor(b10, andnot(b11, b12));
            v[11] = xor(b11, andnot(b12, b13));
            v[12] = xor(b12, andnot(b13, b14));
            v[13] = xor(b13, andnot(b14, b10));
            v[14] = xor(b14, andnot(b10, b11));
            v[15] = xor(b15, andnot(b16, b17));
            v[16] = xor(b16, andnot(b17, b18));
            v[17] = xor(b17, andnot(b18, b19));
            v[18] = xor(b18, andnot(b19, b15));
            v[19] = xor(b19, andnot(b15, b16));
            v[20] = xor(b20, andnot(b21, b22));
            v[21] = xor(b21, andnot(b22, b23));
            v[22] = xor(b22, andnot(b23, b24));
            v[23] = xor(b23, andnot(b24, b20));
            v[24] = xor(b24, andnot(b20, b21));
        }
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn keccak_p_x4(state: &mut [u64; 100], rounds: usize) {
        unsafe {
            let p = state.as_mut_ptr();
            let mut v = [_mm256_setzero_si256(); 25];
            for (i, vi) in v.iter_mut().enumerate() {
                *vi = _mm256_loadu_si256(p.add(4 * i) as *const __m256i);
            }
            for &rc in RC[24 - rounds..].iter() {
                round(&mut v, _mm256_set1_epi64x(rc as i64));
            }
            for (i, vi) in v.iter().enumerate() {
                _mm256_storeu_si256(p.add(4 * i) as *mut __m256i, *vi);
            }
        }
    }
}

/// Four parallel one-shot Keccak sponges over short (single-block) inputs,
/// squeezed a rate block at a time — the shape of the FIPS 203/204 expansion
/// XOFs (`SHAKE(seed ‖ indices)` squeezed until rejection sampling finishes).
pub(crate) struct KeccakX4 {
    /// Interleaved states: lane `i` of stream `l` at `4 * i + l`.
    state: [u64; 100],
    rate: usize,
    /// Whether the state still holds the first, not-yet-extracted block
    /// (produced by the absorb permutation).
    fresh: bool,
}

impl KeccakX4 {
    /// Absorbs `msgs[l]` into stream `l` with domain-separation byte `pad`.
    /// Each message must be shorter than `rate` (a single padded block).
    ///
    /// Callers must have checked [`supported`].
    pub(crate) fn new(rate: usize, msgs: [&[u8]; LANES], pad: u8) -> Self {
        debug_assert!(rate <= MAX_RATE && rate.is_multiple_of(8));
        let mut state = [0u64; 100];
        let mut block = [0u8; MAX_RATE];
        for (l, msg) in msgs.iter().enumerate() {
            debug_assert!(msg.len() < rate);
            block[..rate].fill(0);
            block[..msg.len()].copy_from_slice(msg);
            block[msg.len()] ^= pad;
            block[rate - 1] ^= 0x80;
            for (i, chunk) in block[..rate].chunks_exact(8).enumerate() {
                state[4 * i + l] = u64::from_le_bytes(chunk.try_into().unwrap());
            }
        }
        keccak_p_x4(&mut state, 24);
        KeccakX4 {
            state,
            rate,
            fresh: true,
        }
    }

    /// Squeezes the next `rate` bytes of every stream into
    /// `out[l][..rate]`.
    pub(crate) fn squeeze_blocks(&mut self, out: &mut [[u8; MAX_RATE]; LANES]) {
        if self.fresh {
            self.fresh = false;
        } else {
            keccak_p_x4(&mut self.state, 24);
        }
        for (l, lane_out) in out.iter_mut().enumerate() {
            for (i, chunk) in lane_out[..self.rate].chunks_exact_mut(8).enumerate() {
                chunk.copy_from_slice(&self.state[4 * i + l].to_le_bytes());
            }
        }
    }

    /// Best-effort wipe of the four sponge states (for secret-seeded streams
    /// such as the CBD noise PRF).
    pub(crate) fn zeroize(&mut self) {
        super::zeroize::zero_words(&mut self.state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::keccak::keccak_p;

    /// A tiny xorshift for reproducible pseudo-random test states.
    fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    /// The 4-way kernel must match four independent scalar permutations,
    /// for both supported round counts, over random states.
    #[test]
    fn keccak_p_x4_matches_scalar() {
        if !supported() {
            return;
        }
        let mut seed = 0x1234_5678_9abc_def0u64;
        for trial in 0..50 {
            let rounds = if trial % 2 == 0 { 24 } else { 12 };
            let mut scalar = [[0u64; 25]; LANES];
            let mut interleaved = [0u64; 100];
            for (l, st) in scalar.iter_mut().enumerate() {
                for (i, w) in st.iter_mut().enumerate() {
                    *w = xorshift(&mut seed);
                    interleaved[4 * i + l] = *w;
                }
            }
            keccak_p_x4(&mut interleaved, rounds);
            for (l, st) in scalar.iter_mut().enumerate() {
                keccak_p(st, rounds);
                for (i, w) in st.iter().enumerate() {
                    assert_eq!(
                        interleaved[4 * i + l],
                        *w,
                        "trial {trial} rounds {rounds}: lane {i} stream {l}"
                    );
                }
            }
        }
    }

    /// `KeccakX4` streams must be byte-identical to four scalar SHAKE
    /// sponges over the same messages.
    #[test]
    fn keccak_x4_sponge_matches_scalar_shake() {
        if !supported() {
            return;
        }
        for &(rate, pad) in &[(168usize, 0x1Fu8), (136, 0x1F)] {
            let msgs_buf: [[u8; 34]; LANES] =
                core::array::from_fn(|l| core::array::from_fn(|i| (l * 37 + i) as u8));
            let msgs: [&[u8]; LANES] = core::array::from_fn(|l| &msgs_buf[l][..]);
            let mut x4 = KeccakX4::new(rate, msgs, pad);
            let mut blocks = [[0u8; MAX_RATE]; LANES];
            let mut scalars: [crate::hash::keccak::Keccak; LANES] = core::array::from_fn(|l| {
                let mut k = crate::hash::keccak::Keccak::new(rate);
                k.update(&msgs_buf[l]);
                k.finalize(pad);
                k
            });
            for block_idx in 0..5 {
                x4.squeeze_blocks(&mut blocks);
                for (l, k) in scalars.iter_mut().enumerate() {
                    let mut expect = [0u8; MAX_RATE];
                    k.squeeze(&mut expect[..rate]);
                    assert_eq!(
                        &blocks[l][..rate],
                        &expect[..rate],
                        "rate {rate} stream {l} block {block_idx}"
                    );
                }
            }
        }
    }
}
