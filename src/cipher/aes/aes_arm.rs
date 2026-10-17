//! ARMv8 AES hardware backend (aarch64).
//!
//! Uses the `aes` (FEAT_AES) Crypto Extension via `core::arch::aarch64`
//! intrinsics. The AESE/AESD instructions are data-independent (constant-time)
//! in hardware, preserving the crate's constant-time guarantee.
//!
//! Every entry point is `#[target_feature(enable = "aes")]` (NEON is baseline on
//! aarch64) and therefore `unsafe`: callers in [`super`] invoke them only after
//! a runtime `is_aarch64_feature_detected!("aes")` check. The round keys are
//! read straight from the software-expanded FIPS-197 `rk` byte array, one
//! `vld1q` per round key per group of blocks — never copied into a stack
//! array, so there is no schedule spill to wipe and no memcpy prologue.
//!
//! The round count is a const generic (`NR` ∈ {10, 12, 14}): each `Aes*`
//! variant monomorphises its own kernels, so the round loops unroll fully and
//! the key offsets are immediates. The batch kernels are *round-major* over
//! eight independent blocks (all eight through round `r`, then round `r+1`):
//! the AESE→AESMC chains of the eight blocks interleave in the pipeline, hiding
//! the ~3-cycle latency of each pair.
//!
//! `vaeseq_u8(x, k)` computes `ShiftRows(SubBytes(x XOR k))` and `vaesmcq_u8`
//! the MixColumns, so each AESE folds one AddRoundKey with the *next* round's
//! byte/row transform — hence the off-by-one key indexing below, which matches
//! the canonical OpenSSL `aesv8` sequences. Decryption uses AESD/AESIMC over the
//! forward schedule taken in reverse (equivalent inverse cipher); the
//! InvMixColumns of the middle round keys is applied on the fly, once per key
//! per group, so no transformed schedule ever exists in memory.
#![allow(unsafe_code)]
// Compute-only NEON intrinsics are safe to call inside a `#[target_feature]` fn
// (target_feature_11), so the uniform body-level `unsafe` is redundant in the
// pointer-free helpers; keep it for consistency and silence the style lint.
#![allow(unused_unsafe)]

use core::arch::aarch64::*;

/// Loads round key `i` (the 16 bytes at `rk[i*16..]`).
#[inline]
#[target_feature(enable = "aes")]
unsafe fn rk(rk: &[u8], i: usize) -> uint8x16_t {
    debug_assert!(rk.len() >= 16 * (i + 1));
    unsafe { vld1q_u8(rk.as_ptr().add(i * 16)) }
}

/// Forward cipher over `N` independent blocks held in registers, round-major:
/// every block goes through round `r` before any goes through `r + 1`, so
/// the `N` AESE→AESMC chains overlap. `NR` is the round count; the schedule
/// holds `NR + 1` keys.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn enc_n<const NR: usize, const N: usize>(round_keys: &[u8], b: &mut [uint8x16_t; N]) {
    unsafe {
        for r in 0..NR - 1 {
            let k = rk(round_keys, r);
            for bj in b.iter_mut() {
                *bj = vaesmcq_u8(vaeseq_u8(*bj, k));
            }
        }
        let k = rk(round_keys, NR - 1);
        let last = rk(round_keys, NR);
        for bj in b.iter_mut() {
            *bj = veorq_u8(vaeseq_u8(*bj, k), last);
        }
    }
}

/// Inverse cipher over `N` independent blocks (equivalent inverse cipher with
/// the forward schedule, the canonical OpenSSL aesv8 decrypt): the first AESD
/// uses the raw last round key, each middle key is InvMixColumns-transformed
/// (`vaesimcq`, once per key per group of `N` blocks, off the blocks'
/// dependency chain) before its AESD, and the state is InvMixColumns'd between
/// rounds. `AESD(x,k) = InvSubBytes(InvShiftRows(x XOR k))`.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn dec_n<const NR: usize, const N: usize>(round_keys: &[u8], b: &mut [uint8x16_t; N]) {
    unsafe {
        let k = rk(round_keys, NR);
        for bj in b.iter_mut() {
            *bj = vaesdq_u8(*bj, k);
        }
        for r in (1..NR).rev() {
            let k = vaesimcq_u8(rk(round_keys, r));
            for bj in b.iter_mut() {
                *bj = vaesdq_u8(vaesimcq_u8(*bj), k);
            }
        }
        let k = rk(round_keys, 0);
        for bj in b.iter_mut() {
            *bj = veorq_u8(*bj, k);
        }
    }
}

/// Loads `N` consecutive blocks from `p`.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn load_n<const N: usize>(p: *const u8) -> [uint8x16_t; N] {
    unsafe {
        let mut b = [vdupq_n_u8(0); N];
        for (j, bj) in b.iter_mut().enumerate() {
            *bj = vld1q_u8(p.add(j * 16));
        }
        b
    }
}

/// Stores `N` consecutive blocks to `p`.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn store_n<const N: usize>(p: *mut u8, b: &[uint8x16_t; N]) {
    unsafe {
        for (j, bj) in b.iter().enumerate() {
            vst1q_u8(p.add(j * 16), *bj);
        }
    }
}

/// Best-effort wipe of a block group before the frame is released: a
/// **volatile** zero store per lane followed by a compiler fence, the same
/// contract as [`crate::zeroize::Zeroize`] (which cannot be used directly:
/// `uint8x16_t` is a vendor vector type, not a `DefaultIsZeroes` scalar).
/// The eight pipelined blocks normally live in registers, but if the
/// allocator spills any, the slot would otherwise keep the last group's
/// output (raw keystream when the caller is a CTR mode) on the stack.
#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn wipe(v: &mut [uint8x16_t]) {
    for x in v.iter_mut() {
        // SAFETY: `x` is a live `&mut uint8x16_t`, hence non-null, properly
        // aligned and exclusively held; a volatile store of a zero vector
        // through it is what `*x = vdupq_n_u8(0)` does, minus the optimizer's
        // licence to treat it as a dead store.
        unsafe { core::ptr::write_volatile(x, vdupq_n_u8(0)) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// One bare AES round (AESENC semantics): `MixColumns(ShiftRows(SubBytes(state)))
/// ⊕ rk`. `vaeseq_u8(x, 0)` gives `ShiftRows(SubBytes(x))` (AddRoundKey with a
/// zero key is a no-op), `vaesmcq_u8` the MixColumns, then XOR the round key.
#[target_feature(enable = "aes")]
pub(super) unsafe fn aes_round(state: [u8; 16], rk: [u8; 16]) -> [u8; 16] {
    unsafe {
        let s = vld1q_u8(state.as_ptr());
        let k = vld1q_u8(rk.as_ptr());
        let r = veorq_u8(vaesmcq_u8(vaeseq_u8(s, vdupq_n_u8(0))), k);
        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), r);
        out
    }
}

/// SubWord for the key schedule. With the word broadcast to all four columns,
/// ShiftRows only moves bytes between identical columns, so lane 0 of
/// `AESE(dup(w), 0)` is exactly `SubBytes(w)`.
#[target_feature(enable = "aes")]
pub(super) unsafe fn sub_word(w: [u8; 4]) -> [u8; 4] {
    unsafe {
        let v = vreinterpretq_u8_u32(vdupq_n_u32(u32::from_le_bytes(w)));
        let s = vaeseq_u8(v, vdupq_n_u8(0));
        vgetq_lane_u32::<0>(vreinterpretq_u32_u8(s)).to_le_bytes()
    }
}

/// Single forward block. The state stays in registers and the round keys are
/// read from the schedule, so nothing secret touches this frame.
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt_block<const NR: usize>(round_keys: &[u8], block: &mut [u8; 16]) {
    unsafe {
        let mut b = [vld1q_u8(block.as_ptr())];
        enc_n::<NR, 1>(round_keys, &mut b);
        vst1q_u8(block.as_mut_ptr(), b[0]);
    }
}

/// Single inverse block.
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt_block<const NR: usize>(round_keys: &[u8], block: &mut [u8; 16]) {
    unsafe {
        let mut b = [vld1q_u8(block.as_ptr())];
        dec_n::<NR, 1>(round_keys, &mut b);
        vst1q_u8(block.as_mut_ptr(), b[0]);
    }
}

/// Forward permutation over independent 16-byte blocks, eight at a time
/// round-major, then a four-block group and single blocks for the remainder.
/// `blocks.len()` must be a multiple of 16.
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt_blocks<const NR: usize>(round_keys: &[u8], blocks: &mut [u8]) {
    unsafe {
        let mut wide = blocks.chunks_exact_mut(16 * 8);
        // Hoisted so the wipe below covers the last group's outputs (raw
        // keystream when the caller is a CTR mode).
        let mut b = [vdupq_n_u8(0); 8];
        for c in &mut wide {
            b = load_n::<8>(c.as_ptr());
            enc_n::<NR, 8>(round_keys, &mut b);
            store_n::<8>(c.as_mut_ptr(), &b);
        }
        let mut rest = wide.into_remainder();
        if rest.len() >= 64 {
            let mut q = load_n::<4>(rest.as_ptr());
            enc_n::<NR, 4>(round_keys, &mut q);
            store_n::<4>(rest.as_mut_ptr(), &q);
            b[..4].copy_from_slice(&q);
            rest = &mut rest[64..];
        }
        for block in rest.chunks_exact_mut(16) {
            let mut s = [vld1q_u8(block.as_ptr())];
            enc_n::<NR, 1>(round_keys, &mut s);
            vst1q_u8(block.as_mut_ptr(), s[0]);
            b[0] = s[0];
        }
        wipe(&mut b);
    }
}

/// Inverse permutation over independent 16-byte blocks, eight at a time
/// round-major. `blocks.len()` must be a multiple of 16.
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt_blocks<const NR: usize>(round_keys: &[u8], blocks: &mut [u8]) {
    unsafe {
        let mut wide = blocks.chunks_exact_mut(16 * 8);
        let mut b = [vdupq_n_u8(0); 8];
        for c in &mut wide {
            b = load_n::<8>(c.as_ptr());
            dec_n::<NR, 8>(round_keys, &mut b);
            store_n::<8>(c.as_mut_ptr(), &b);
        }
        let mut rest = wide.into_remainder();
        if rest.len() >= 64 {
            let mut q = load_n::<4>(rest.as_ptr());
            dec_n::<NR, 4>(round_keys, &mut q);
            store_n::<4>(rest.as_mut_ptr(), &q);
            b[..4].copy_from_slice(&q);
            rest = &mut rest[64..];
        }
        for block in rest.chunks_exact_mut(16) {
            let mut s = [vld1q_u8(block.as_ptr())];
            dec_n::<NR, 1>(round_keys, &mut s);
            vst1q_u8(block.as_mut_ptr(), s[0]);
            b[0] = s[0];
        }
        wipe(&mut b);
    }
}
