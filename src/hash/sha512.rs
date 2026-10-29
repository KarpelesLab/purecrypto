//! SHA-384, SHA-512, SHA-512/224 and SHA-512/256 (FIPS 180-4), built on a
//! shared 64-bit SHA-2 core.

use super::Digest;

/// SHA-512 initial hash value.
pub(crate) const H512: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// SHA-384 initial hash value.
const H384: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

/// SHA-512/224 initial hash value.
const H512_224: [u64; 8] = [
    0x8c3d_37c8_1954_4da2,
    0x73e1_9966_89dc_d4d6,
    0x1dfa_b7ae_32ff_9c82,
    0x679d_d514_582f_9fcf,
    0x0f6d_2b69_7bd4_4da8,
    0x77e3_6f73_04c4_8942,
    0x3f9d_85a8_6a1d_36c8,
    0x1112_e6ad_91d6_92a1,
];

/// SHA-512/256 initial hash value.
const H512_256: [u64; 8] = [
    0x2231_2194_fc2b_f72c,
    0x9f55_5fa3_c84c_64c2,
    0x2393_b86b_6f53_b151,
    0x9638_7719_5940_eabd,
    0x9628_3ee2_a88e_ffe3,
    0xbe5e_1e25_5386_3992,
    0x2b01_99fc_2c85_b8aa,
    0x0eb7_2ddc_81c5_2ca2,
];

/// SHA-512 round constants (first 64 bits of the fractional parts of the cube
/// roots of the first 80 primes).
pub(crate) const K512: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

/// Streaming state shared by all SHA-512 variants (they differ only in IV and
/// output truncation).
#[derive(Clone)]
struct State512 {
    h: [u64; 8],
    /// Partial input not yet compressed (`block_len` valid bytes).
    block: [u8; 128],
    block_len: usize,
    /// Total message length in bytes (a 128-bit counter).
    msg_len: u128,
}

impl State512 {
    #[inline]
    fn new(iv: [u64; 8]) -> Self {
        State512 {
            h: iv,
            block: [0u8; 128],
            block_len: 0,
            msg_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.msg_len = self.msg_len.wrapping_add(data.len() as u128);

        if self.block_len > 0 {
            let take = (128 - self.block_len).min(data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
            if self.block_len == 128 {
                compress512(&mut self.h, &self.block);
                self.block_len = 0;
            }
        }

        // Whole blocks straight from the input, in one call.
        let bulk = data.len() & !127;
        if bulk > 0 {
            compress512_blocks(&mut self.h, &data[..bulk]);
            data = &data[bulk..];
        }

        if !data.is_empty() {
            self.block[..data.len()].copy_from_slice(data);
            self.block_len = data.len();
        }
    }

    /// Writes the chaining words, the 128-bit byte count and the partial
    /// block (see [`super::state`]).
    fn export_into(&self, w: &mut super::state::Writer<'_>) {
        w.u64s(&self.h);
        w.u128(self.msg_len);
        w.buffer(&self.block, self.block_len);
    }

    /// Loads what [`Self::export_into`] wrote; `self` is unchanged on error.
    fn import_from(&mut self, r: &mut super::state::Reader<'_>) -> Result<(), super::StateError> {
        let h = r.u64s::<8>();
        let msg_len = r.u128();
        let mut block = [0u8; 128];
        let block_len = r.buffer(&mut block, 127)?;
        if msg_len % 128 != block_len as u128 {
            return Err(super::StateError::Inconsistent);
        }
        *self = State512 {
            h,
            block,
            block_len,
            msg_len,
        };
        Ok(())
    }

    /// Best-effort wipe of the state words and partial block.
    fn zeroize(&mut self) {
        super::zeroize::zero_words(&mut self.h);
        super::zeroize::zero_bytes(&mut self.block);
        self.block_len = 0;
        self.msg_len = 0;
    }

    /// [`Digest::hmac_iterate`] for an `N`-byte digest: requires both states
    /// to sit right after their single pad block.
    fn hmac_iterate<const N: usize>(
        &self,
        outer: &Self,
        u: &mut [u8; N],
        acc: &mut [u8; N],
        rounds: u32,
    ) -> bool {
        if self.block_len != 0
            || outer.block_len != 0
            || self.msg_len != 128
            || outer.msg_len != 128
        {
            return false;
        }
        let len = ((128 + N as u128) * 8).to_be_bytes();
        super::hmac::hmac_iterate_with(
            (&self.h, &outer.h),
            &len,
            u,
            acc,
            rounds,
            compress512,
            |h, out| {
                // Truncated variants keep a partial last word (SHA-512/224).
                for (o, w) in out.chunks_mut(8).zip(h.iter()) {
                    o.copy_from_slice(&w.to_be_bytes()[..o.len()]);
                }
            },
        );
        true
    }

    /// [`Digest::hmac_short`] for an `N`-byte digest: the inner state must
    /// hold exactly its pad block plus whatever short message is buffered,
    /// the outer state exactly its pad block.
    fn hmac_short<const N: usize>(&self, outer: &Self, parts: &[&[u8]]) -> Option<[u8; N]> {
        if self.msg_len != 128 + self.block_len as u128
            || outer.block_len != 0
            || outer.msg_len != 128
        {
            return None;
        }
        super::hmac::hmac_short_with::<_, 128, N>(
            (&self.h, &outer.h),
            &self.block[..self.block_len],
            parts,
            111,
            compress512,
            |h, out| {
                // Truncated variants keep a partial last word (SHA-512/224).
                for (o, w) in out.chunks_mut(8).zip(h.iter()) {
                    o.copy_from_slice(&w.to_be_bytes()[..o.len()]);
                }
            },
            // The 128-bit length field's high half is always zero here.
            |bits, block| block[112..].copy_from_slice(&(bits as u128).to_be_bytes()),
        )
    }

    /// Applies SHA-2 padding and returns the final state words.
    fn finalize(mut self) -> [u64; 8] {
        // 128-bit big-endian bit length occupies the last 16 bytes.
        let bit_len = self.msg_len.wrapping_mul(8);

        let mut i = self.block_len;
        self.block[i] = 0x80;
        i += 1;

        if i > 112 {
            while i < 128 {
                self.block[i] = 0;
                i += 1;
            }
            compress512(&mut self.h, &self.block);
            i = 0;
        }
        while i < 112 {
            self.block[i] = 0;
            i += 1;
        }
        self.block[112..128].copy_from_slice(&bit_len.to_be_bytes());
        compress512(&mut self.h, &self.block);

        // `self` is consumed here and has no `Drop`; the partial block still
        // holds the tail of the message (possibly key material when used
        // under HMAC/KDFs), so wipe it and the state words before returning.
        let out = self.h;
        self.zeroize();
        out
    }
}

/// `u64` right-rotation as an explicit shift-or rather than
/// [`u64::rotate_right`]. In debug builds `rotate_right` lowers to a real
/// (non-inlined) `core::intrinsics::rotate_right` call; the shift-or inlines,
/// and release codegen is identical (a `ror`, or BMI2 `rorx` inside the
/// `bmi2`-enabled x86_64 kernel). (See the SHA-256 `rotr` for the profile.)
// Intentionally NOT `x.rotate_right(n)` — see the SHA-256 `rotr`.
#[inline(always)]
#[allow(clippy::manual_rotate)]
const fn rotr(x: u64, n: u32) -> u64 {
    (x >> n) | (x << (64 - n))
}

/// One SHA-512 round on named state variables, with `$wk = K[t] + W[t]`
/// already summed. Instead of shifting all eight words, the caller rotates the
/// variable names (see [`rounds8`]): only `$d` (the next `e`) and `$h` (the
/// next `a`) are written. `Maj(a,b,c) = ((a ^ b) & (b ^ c)) ^ b`: this
/// round's `a ^ b` is the next round's `b ^ c`, which LLVM reuses.
///
/// This is the form with the fewest operations, used by the portable path;
/// [`round_x86`] trades two more for a shorter dependency chain.
macro_rules! round_portable {
    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $wk:expr) => {
        let ch = ($e & $f) ^ (!$e & $g);
        let s1 = rotr($e, 14) ^ rotr($e, 18) ^ rotr($e, 41);
        let t1 = $h.wrapping_add($wk).wrapping_add(ch).wrapping_add(s1);
        $d = $d.wrapping_add(t1);
        let maj = (($a ^ $b) & ($b ^ $c)) ^ $b;
        $h = t1.wrapping_add((rotr($a, 28) ^ rotr($a, 34) ^ rotr($a, 39)).wrapping_add(maj));
    };
}

/// [`round_portable`] with the sums arranged for a short dependency chain
/// through `e`, for the wide out-of-order x86_64 cores the BMI2 kernels run
/// on: `new_e = (d + h + K + W) + Ch(e,f,g) + Σ1(e)`, with `d + h + K + W`
/// ready before `e` is. `new_a = T1 + Σ0(a) + Maj(a,b,c)` reuses `new_e`
/// (`T1` is `new_e - d`) and splits `Maj(a,b,c) = (a & (b ^ c)) + (b & c)`
/// (the two terms are bitwise disjoint), leaving only `a & (b ^ c)` and
/// `Σ0(a)` on the path through `a`. (LLVM reassociates the sums as it sees
/// fit; pinning this exact order with an empty `asm!` barrier measured slower
/// with the AVX-512VL kernel.)
#[cfg(target_arch = "x86_64")]
macro_rules! round_x86 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $wk:expr) => {
        let hk = $h.wrapping_add($wk);
        let ch = (($f ^ $g) & $e) ^ $g;
        let s1 = rotr($e, 14) ^ rotr($e, 18) ^ rotr($e, 41);
        let x = ($b & $c).wrapping_sub($d);
        $d = $d.wrapping_add(hk).wrapping_add(ch).wrapping_add(s1);
        $h = $d
            .wrapping_add(x)
            .wrapping_add($a & ($b ^ $c))
            .wrapping_add(rotr($a, 28) ^ rotr($a, 34) ^ rotr($a, 39));
    };
}

/// Eight `$round!`s — rounds `$t .. $t + 8`, one full rotation of the
/// variable names, so the variables hold `a..h` again afterwards. `$wk(t)`
/// yields `K + W` for round `t`.
macro_rules! rounds8 {
    ($round:ident, [$a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident],
     $wk:expr, $t:expr) => {
        $round!($a, $b, $c, $d, $e, $f, $g, $h, $wk($t + 0));
        $round!($h, $a, $b, $c, $d, $e, $f, $g, $wk($t + 1));
        $round!($g, $h, $a, $b, $c, $d, $e, $f, $wk($t + 2));
        $round!($f, $g, $h, $a, $b, $c, $d, $e, $wk($t + 3));
        $round!($e, $f, $g, $h, $a, $b, $c, $d, $wk($t + 4));
        $round!($d, $e, $f, $g, $h, $a, $b, $c, $wk($t + 5));
        $round!($c, $d, $e, $f, $g, $h, $a, $b, $wk($t + 6));
        $round!($b, $c, $d, $e, $f, $g, $h, $a, $wk($t + 7));
    };
}

/// SHA-512 compression function: folds a 128-byte block into the state.
///
/// Dispatches like [`compress512_blocks`]; every backend produces identical
/// state and is constant-time.
#[inline]
pub(crate) fn compress512(h: &mut [u64; 8], block: &[u8; 128]) {
    compress512_blocks(h, block);
}

/// SHA-512 compression of `data`, a whole number of 128-byte blocks.
///
/// Dispatches to the aarch64 `sha512` hardware extension when available; on
/// x86_64 (which has no broadly-available SHA-512 instruction) to the
/// AVX-512VL or AVX2 kernel with BMI2 rounds when available; else the
/// portable software path. Taking all blocks at once keeps the state in
/// registers across blocks and lets the x86_64 kernels schedule two blocks
/// per pass.
#[inline]
#[cfg_attr(
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", any(feature = "std", target_feature = "sha2"))
    ),
    allow(unsafe_code)
)]
pub(crate) fn compress512_blocks(h: &mut [u64; 8], data: &[u8]) {
    debug_assert!(data.len().is_multiple_of(128));
    #[cfg(all(target_arch = "aarch64", any(feature = "std", target_feature = "sha2")))]
    if super::sha_hw::sha512_supported() {
        for block in data.chunks_exact(128) {
            // SAFETY: guarded by the `sha512_supported()` feature check.
            unsafe { super::sha_hw::compress512(h, block.try_into().unwrap()) };
        }
        return;
    }
    #[cfg(target_arch = "x86_64")]
    match x86_backend() {
        // SAFETY: `x86_backend()` checked AVX2, AVX-512F/VL, BMI1 and BMI2.
        X86Backend::Avx512 => return unsafe { x86::compress_blocks_avx512(h, data) },
        // SAFETY: `x86_backend()` checked AVX2, BMI1 and BMI2.
        X86Backend::Avx2 => return unsafe { x86::compress_blocks_avx2(h, data) },
        X86Backend::Portable => {}
    }
    compress512_soft_blocks(h, data);
}

/// The x86_64 SHA-512 backends, best first.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum X86Backend {
    Avx512,
    Avx2,
    Portable,
}

/// The best x86_64 backend this CPU runs (the portable one when the
/// constant-time harness forces it).
#[cfg(target_arch = "x86_64")]
#[inline]
fn x86_backend() -> X86Backend {
    use crate::cpu;
    if crate::ct::force_portable() || !(cpu::avx2() && cpu::bmi1() && cpu::bmi2()) {
        X86Backend::Portable
    } else if cpu::avx512vl() {
        X86Backend::Avx512
    } else {
        X86Backend::Avx2
    }
}

/// Portable software SHA-512 compression of one block (the constant-time
/// fallback).
#[inline]
// Used by the multi-buffer kernels (SLH-DSA) and the tests.
#[allow(dead_code)]
pub(crate) fn compress512_soft(h: &mut [u64; 8], block: &[u8; 128]) {
    compress512_soft_blocks(h, block);
}

/// Portable software SHA-512 compression of whole 128-byte blocks: fully
/// unrolled rounds on rotating variable names, with the message schedule kept
/// in a 16-word ring computed just ahead of its use.
pub(crate) fn compress512_soft_blocks(state: &mut [u64; 8], data: &[u8]) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for block in data.chunks_exact(128) {
        let mut w = [0u64; 16];
        for (word, chunk) in w.iter_mut().zip(block.chunks_exact(8)) {
            *word = u64::from_be_bytes(chunk.try_into().unwrap());
        }
        let (a0, b0, c0, d0, e0, f0, g0, h0) = (a, b, c, d, e, f, g, h);

        let kw = |t: usize| K512[t].wrapping_add(w[t]);
        rounds8!(round_portable, [a, b, c, d, e, f, g, h], kw, 0);
        rounds8!(round_portable, [a, b, c, d, e, f, g, h], kw, 8);
        for t in (16..80).step_by(16) {
            // Replaces `w[j]` (= W[t + j - 16]) with W[t + j] and returns
            // K[t + j] + W[t + j].
            let mut next = |j: usize| {
                let w15 = w[(j + 1) % 16];
                let w2 = w[(j + 14) % 16];
                let s0 = rotr(w15, 1) ^ rotr(w15, 8) ^ (w15 >> 7);
                let s1 = rotr(w2, 19) ^ rotr(w2, 61) ^ (w2 >> 6);
                w[j] = w[j]
                    .wrapping_add(s0)
                    .wrapping_add(w[(j + 9) % 16])
                    .wrapping_add(s1);
                K512[t + j].wrapping_add(w[j])
            };
            rounds8!(round_portable, [a, b, c, d, e, f, g, h], next, 0);
            rounds8!(round_portable, [a, b, c, d, e, f, g, h], next, 8);
        }

        a = a.wrapping_add(a0);
        b = b.wrapping_add(b0);
        c = c.wrapping_add(c0);
        d = d.wrapping_add(d0);
        e = e.wrapping_add(e0);
        f = f.wrapping_add(f0);
        g = g.wrapping_add(g0);
        h = h.wrapping_add(h0);
    }
    *state = [a, b, c, d, e, f, g, h];
}

/// x86_64 SHA-512: vectorised message schedule, BMI2 (`rorx`) scalar rounds.
///
/// Blocks go two at a time (the layout of OpenSSL's
/// `sha512_block_data_order_avx2`): each `__m256i` holds two consecutive
/// schedule words of the first block in its low 128-bit lane and the same two
/// words of the second block in the high lane, so one vector step extends both
/// schedules by two words (`σ1` needs `W[t-2]`, which is never one of the two
/// words being computed). `K + W` for both blocks goes to a stack buffer. The
/// first block's scalar rounds run interleaved with the vector schedule (which
/// they do not depend on, so the two overlap in the out-of-order core); the
/// second block's rounds then just read the buffer. An odd last block is
/// loaded into both lanes and only its first-lane rounds are run.
///
/// Two builds of the same kernel: AVX2 (`σ` rotations as shift pairs) and
/// AVX-512VL (`vprorq` rotations and a three-way `vpternlogq` XOR, still on
/// 256-bit vectors). The shorter schedule is worth about 18% on Zen 5.
///
/// No data-dependent branches or memory indices: constant-time like the
/// portable path, which it matches word for word (pinned by tests).
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod x86 {
    use super::{K512, rotr};
    use core::arch::x86_64::*;

    /// The `K + W` buffer: 40 vectors, 32-byte aligned.
    #[repr(C, align(32))]
    struct Wk([u64; 160]);

    /// Index into the `K + W` buffer of round `t` of block `blk` (0 or 1):
    /// vector `t / 2`, lane `blk`, word `t % 2`.
    #[inline(always)]
    const fn idx(t: usize, blk: usize) -> usize {
        (t / 2) * 4 + blk * 2 + (t & 1)
    }

    /// `(K[t], K[t + 1])` in both 128-bit lanes.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn k2(t: usize) -> __m256i {
        let k: &[u64; 2] = K512[t..t + 2].try_into().unwrap();
        // SAFETY: `k` is 16 readable bytes (the load is unaligned).
        _mm256_broadcastsi128_si256(unsafe { _mm_loadu_si128(k.as_ptr().cast()) })
    }

    /// 64-bit right rotation in each lane (AVX2 has no `vprorq`).
    #[inline]
    #[target_feature(enable = "avx2")]
    fn ror<const R: i32, const L: i32>(x: __m256i) -> __m256i {
        _mm256_or_si256(_mm256_srli_epi64::<R>(x), _mm256_slli_epi64::<L>(x))
    }

    /// The next two schedule words of both blocks, from the window
    /// `x0 = (W[t], W[t+1])`, …, `x7 = (W[t+14], W[t+15])`:
    /// `W[t+16+j] = σ1(W[t+14+j]) + W[t+9+j] + σ0(W[t+1+j]) + W[t+j]`.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn schedule_avx2(x0: __m256i, x1: __m256i, x4: __m256i, x5: __m256i, x7: __m256i) -> __m256i {
        // Rotate each 64-bit word right by one byte.
        let rot8 = _mm256_setr_epi8(
            1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8, 1, 2, 3, 4, 5, 6, 7, 0, 9, 10,
            11, 12, 13, 14, 15, 8,
        );
        // (W[t+1], W[t+2]) and (W[t+9], W[t+10]); `vpalignr` works within
        // each 128-bit lane, i.e. within each block.
        let w1 = _mm256_alignr_epi8::<8>(x1, x0);
        let w9 = _mm256_alignr_epi8::<8>(x5, x4);
        // σ0(x) = ror1 ^ ror8 ^ shr7; the byte rotation is one shuffle.
        let s0 = _mm256_xor_si256(
            _mm256_xor_si256(ror::<1, 63>(w1), _mm256_shuffle_epi8(w1, rot8)),
            _mm256_srli_epi64::<7>(w1),
        );
        // σ1(x) = ror19 ^ ror61 ^ shr6.
        let s1 = _mm256_xor_si256(
            _mm256_xor_si256(ror::<19, 45>(x7), ror::<61, 3>(x7)),
            _mm256_srli_epi64::<6>(x7),
        );
        _mm256_add_epi64(_mm256_add_epi64(x0, w9), _mm256_add_epi64(s0, s1))
    }

    /// [`schedule_avx2`] with AVX-512VL rotations and three-way XORs.
    #[inline]
    #[target_feature(enable = "avx2,avx512f,avx512vl")]
    fn schedule_avx512(x0: __m256i, x1: __m256i, x4: __m256i, x5: __m256i, x7: __m256i) -> __m256i {
        let w1 = _mm256_alignr_epi8::<8>(x1, x0);
        let w9 = _mm256_alignr_epi8::<8>(x5, x4);
        // 0x96: a ^ b ^ c.
        let s0 = _mm256_ternarylogic_epi64::<0x96>(
            _mm256_ror_epi64::<1>(w1),
            _mm256_ror_epi64::<8>(w1),
            _mm256_srli_epi64::<7>(w1),
        );
        let s1 = _mm256_ternarylogic_epi64::<0x96>(
            _mm256_ror_epi64::<19>(x7),
            _mm256_ror_epi64::<61>(x7),
            _mm256_srli_epi64::<6>(x7),
        );
        _mm256_add_epi64(_mm256_add_epi64(x0, w9), _mm256_add_epi64(s0, s1))
    }

    /// Defines one build of the kernel: `$name` compresses `data` (a whole
    /// number of 128-byte blocks) into `state`, with `$features` enabled and
    /// `$schedule` extending the message schedule.
    macro_rules! kernel {
        ($(#[$doc:meta])* $name:ident, $features:literal, $schedule:ident) => {
            $(#[$doc])*
            #[target_feature(enable = $features)]
            pub(super) unsafe fn $name(state: &mut [u64; 8], data: &[u8]) {
                debug_assert!(data.len().is_multiple_of(128));
                // Byte-reverse each 64-bit word (big-endian load).
                let bswap = _mm256_setr_epi8(
                    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
                    15, 14, 13, 12, 11, 10, 9, 8,
                );
                // K + W for rounds 0..80 of both blocks, laid out as `idx` says.
                let mut wk = Wk([0; 160]);
                // Every buffer access goes through this one pointer.
                let wkw: *mut u64 = wk.0.as_mut_ptr();
                let wkp = wkw.cast::<__m256i>();
                // `K + W` of round `t < 80` of the first and second block.
                // SAFETY: `idx(t, blk) < 160` for every `t < 80`, `blk < 2`.
                let rd0 = |t: usize| unsafe { *wkw.add(idx(t, 0)) };
                // SAFETY: as above.
                let rd1 = |t: usize| unsafe { *wkw.add(idx(t, 1)) };
                let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

                let mut rest = data;
                while !rest.is_empty() {
                    let two = rest.len() >= 256;
                    let (first, second) = rest.split_at(128);
                    let p = first.as_ptr();
                    let q = if two { second.as_ptr() } else { p };
                    rest = if two { &second[128..] } else { second };

                    let mut x = [_mm256_setzero_si256(); 8];
                    for (i, xi) in x.iter_mut().enumerate() {
                        // SAFETY: `16 * i + 16 <= 128` stays within each block
                        // (`q` is the second block only when there is one).
                        let v = unsafe {
                            _mm256_inserti128_si256::<1>(
                                _mm256_castsi128_si256(_mm_loadu_si128(p.add(16 * i).cast())),
                                _mm_loadu_si128(q.add(16 * i).cast()),
                            )
                        };
                        *xi = _mm256_shuffle_epi8(v, bswap);
                        // SAFETY: vector `i < 40` of the 160-word buffer.
                        unsafe {
                            _mm256_storeu_si256(wkp.add(i), _mm256_add_epi64(*xi, k2(2 * i)))
                        };
                    }

                    let (a0, b0, c0, d0, e0, f0, g0, h0) = (a, b, c, d, e, f, g, h);
                    // Rounds 0..64 of the first block; meanwhile extend the
                    // schedule by 16 words per 16 rounds (vectors 8..40).
                    for r in (0..64).step_by(16) {
                        macro_rules! step {
                            ($i:literal) => {{
                                let v = r / 2 + $i + 8;
                                x[$i] = $schedule(
                                    x[$i],
                                    x[($i + 1) % 8],
                                    x[($i + 4) % 8],
                                    x[($i + 5) % 8],
                                    x[($i + 7) % 8],
                                );
                                // SAFETY: `v < 40`, and `2 * v + 2 <= 80`.
                                unsafe {
                                    _mm256_storeu_si256(
                                        wkp.add(v),
                                        _mm256_add_epi64(x[$i], k2(2 * v)),
                                    )
                                };
                            }};
                        }
                        step!(0);
                        step!(1);
                        step!(2);
                        step!(3);
                        rounds8!(round_x86, [a, b, c, d, e, f, g, h], rd0, r);
                        step!(4);
                        step!(5);
                        step!(6);
                        step!(7);
                        rounds8!(round_x86, [a, b, c, d, e, f, g, h], rd0, r + 8);
                    }
                    rounds8!(round_x86, [a, b, c, d, e, f, g, h], rd0, 64);
                    rounds8!(round_x86, [a, b, c, d, e, f, g, h], rd0, 72);
                    a = a.wrapping_add(a0);
                    b = b.wrapping_add(b0);
                    c = c.wrapping_add(c0);
                    d = d.wrapping_add(d0);
                    e = e.wrapping_add(e0);
                    f = f.wrapping_add(f0);
                    g = g.wrapping_add(g0);
                    h = h.wrapping_add(h0);

                    if two {
                        let (a0, b0, c0, d0, e0, f0, g0, h0) = (a, b, c, d, e, f, g, h);
                        for r in (0..80).step_by(8) {
                            rounds8!(round_x86, [a, b, c, d, e, f, g, h], rd1, r);
                        }
                        a = a.wrapping_add(a0);
                        b = b.wrapping_add(b0);
                        c = c.wrapping_add(c0);
                        d = d.wrapping_add(d0);
                        e = e.wrapping_add(e0);
                        f = f.wrapping_add(f0);
                        g = g.wrapping_add(g0);
                        h = h.wrapping_add(h0);
                    }
                }
                *state = [a, b, c, d, e, f, g, h];
                // The buffer holds message-derived words (key material under
                // HMAC): wipe it, a vector at a time (a word-wise volatile
                // wipe costs a fifth of a one-block hash).
                for i in 0..40 {
                    // SAFETY: vector `i < 40` of the buffer, which `Wk`
                    // aligns to 32 bytes.
                    unsafe { core::ptr::write_volatile(wkp.add(i), _mm256_setzero_si256()) };
                }
            }
        };
    }

    kernel!(
        /// AVX2 build of the kernel.
        ///
        /// # Safety
        /// The CPU must support AVX2, BMI1 and BMI2.
        compress_blocks_avx2,
        "avx2,bmi1,bmi2",
        schedule_avx2
    );
    kernel!(
        /// AVX-512VL build of the kernel.
        ///
        /// # Safety
        /// The CPU must support AVX2, AVX-512F, AVX-512VL, BMI1 and BMI2.
        compress_blocks_avx512,
        "avx2,avx512f,avx512vl,bmi1,bmi2",
        schedule_avx512
    );
}

/// Serializes the leftmost `N` bytes of the state words (big-endian),
/// including a partial trailing word when `N` is not a multiple of 8 (needed
/// for SHA-512/224).
#[inline]
fn truncate_words<const N: usize>(h: &[u64; 8]) -> [u8; N] {
    let mut out = [0u8; N];
    let full = N / 8;
    for i in 0..full {
        out[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_be_bytes());
    }
    let rem = N % 8;
    if rem > 0 {
        let be = h[full].to_be_bytes();
        out[full * 8..full * 8 + rem].copy_from_slice(&be[..rem]);
    }
    out
}

/// Serialized [`State512`]: header, eight words, `u128` count, `u8` + 128-byte
/// buffer.
const STATE512_LEN: usize = 2 + 64 + 16 + 1 + 128;

/// Generates a SHA-512-variant type with the given IV and output length.
macro_rules! sha512_variant {
    ($(#[$meta:meta])* $name:ident, $iv:expr, $out:literal, $fn_name:ident, $fn_doc:literal, $tag:ident) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            state: State512,
        }

        impl Digest for $name {
            type Output = [u8; $out];
            type Block = [u8; 128];
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = 128;

            #[inline]
            fn new() -> Self {
                $name {
                    state: State512::new($iv),
                }
            }

            #[inline]
            fn zeroed_block() -> [u8; 128] {
                [0u8; 128]
            }

            #[inline]
            fn zeroed_output() -> [u8; $out] {
                [0u8; $out]
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.state.update(data);
            }

            #[inline]
            fn hmac_iterate(
                inner: &Self,
                outer: &Self,
                u: &mut [u8; $out],
                acc: &mut [u8; $out],
                rounds: u32,
            ) -> bool {
                inner.state.hmac_iterate(&outer.state, u, acc, rounds)
            }
            #[inline]
            fn hmac_short(inner: &Self, outer: &Self, parts: &[&[u8]]) -> Option<[u8; $out]> {
                inner.state.hmac_short(&outer.state, parts)
            }

            #[inline]
            fn finalize(self) -> [u8; $out] {
                truncate_words(&self.state.finalize())
            }

            #[inline]
            fn zeroize(&mut self) {
                self.state.zeroize();
            }
        }

        #[doc = $fn_doc]
        #[inline]
        pub fn $fn_name(data: &[u8]) -> [u8; $out] {
            $name::digest(data)
        }

        super::state::impl_exportable_state!(
            $name,
            super::state::tag::$tag,
            STATE512_LEN,
            |s| s.state,
            $name::new()
        );
    };
}

sha512_variant!(
    /// The SHA-512 hash function.
    Sha512, H512, 64, sha512, "Computes the SHA-512 digest of `data`.", SHA512
);
sha512_variant!(
    /// The SHA-384 hash function (SHA-512 with a different IV, truncated to 384 bits).
    Sha384, H384, 48, sha384, "Computes the SHA-384 digest of `data`.", SHA384
);
sha512_variant!(
    /// The SHA-512/256 hash function.
    Sha512_256, H512_256, 32, sha512_256, "Computes the SHA-512/256 digest of `data`.", SHA512_256
);
sha512_variant!(
    /// The SHA-512/224 hash function.
    Sha512_224, H512_224, 28, sha512_224, "Computes the SHA-512/224 digest of `data`.", SHA512_224
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// Reference digest that bypasses every dispatched backend: the padding
    /// done by hand and each block through the portable
    /// [`compress512_soft_blocks`] — the portable path, forced.
    #[cfg(feature = "alloc")]
    fn software_digest(iv: [u64; 8], data: &[u8], out_len: usize) -> alloc::vec::Vec<u8> {
        let mut h = iv;
        let mut buf = data.to_vec();
        let bitlen = (buf.len() as u128) * 8;
        buf.push(0x80);
        while buf.len() % 128 != 112 {
            buf.push(0);
        }
        buf.extend_from_slice(&bitlen.to_be_bytes());
        for chunk in buf.chunks_exact(128) {
            compress512_soft_blocks(&mut h, chunk);
        }
        let mut out = alloc::vec::Vec::new();
        for w in h {
            out.extend_from_slice(&w.to_be_bytes());
        }
        out.truncate(out_len);
        out
    }

    /// Deterministic test bytes.
    #[cfg(feature = "alloc")]
    fn test_bytes(len: usize, seed: u64) -> alloc::vec::Vec<u8> {
        let mut s = seed | 1;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            })
            .collect()
    }

    /// One-shot and streamed digests of `data` through the dispatched path
    /// (whatever this CPU selects) must equal the portable reference, for all
    /// four variants. Streaming uses odd chunk sizes so that blocks straddle
    /// `update` calls and the bulk path sees both even and odd block counts.
    #[cfg(feature = "alloc")]
    fn check_all_variants(data: &[u8]) {
        fn streamed<D: Digest>(data: &[u8], chunks: &[usize]) -> alloc::vec::Vec<u8> {
            let mut d = D::new();
            let mut rest = data;
            let mut i = 0;
            while !rest.is_empty() {
                let n = chunks[i % chunks.len()].min(rest.len());
                d.update(&rest[..n]);
                rest = &rest[n..];
                i += 1;
            }
            d.finalize().as_ref().to_vec()
        }
        fn one<D: Digest>(iv: [u64; 8], data: &[u8]) {
            let want = software_digest(iv, data, D::OUTPUT_LEN);
            assert_eq!(
                D::digest(data).as_ref(),
                &want[..],
                "one-shot, len {}",
                data.len()
            );
            for chunks in [
                &[1usize][..],
                &[7, 129, 3],
                &[127, 255, 1, 384],
                &[1000, 13],
            ] {
                assert_eq!(
                    streamed::<D>(data, chunks),
                    want,
                    "streamed {chunks:?}, len {}",
                    data.len()
                );
            }
        }
        one::<Sha512>(H512, data);
        one::<Sha384>(H384, data);
        one::<Sha512_256>(H512_256, data);
        one::<Sha512_224>(H512_224, data);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dispatched_matches_portable_short_lengths() {
        let data = test_bytes(600, 0x5eed);
        for len in 0..=600 {
            check_all_variants(&data[..len]);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dispatched_matches_portable_large() {
        for len in [4096 + 17, 65_536, 100_003, (1 << 20) + 128 * 3 + 5] {
            check_all_variants(&test_bytes(len, 0xbeef ^ len as u64));
        }
    }

    /// Each x86_64 kernel (not just the one this CPU dispatches to) must equal
    /// the portable compression for random states and 1–7 blocks, which
    /// covers the paired and the odd-last-block paths.
    #[cfg(target_arch = "x86_64")]
    #[test]
    #[allow(unsafe_code)] // calls the `unsafe` kernels directly
    fn x86_kernels_match_portable() {
        use crate::cpu;
        type Kernel = unsafe fn(&mut [u64; 8], &[u8]);
        let kernels: [(&str, bool, Kernel); 2] = [
            (
                "avx2",
                cpu::avx2() && cpu::bmi1() && cpu::bmi2(),
                x86::compress_blocks_avx2,
            ),
            (
                "avx512",
                cpu::avx2() && cpu::avx512vl() && cpu::bmi1() && cpu::bmi2(),
                x86::compress_blocks_avx512,
            ),
        ];
        let mut s = 0x0123_4567_89ab_cdefu64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let mut data = [0u8; 7 * 128];
        for (name, supported, kernel) in kernels {
            if !supported {
                #[cfg(feature = "std")]
                std::eprintln!("sha512 {name}: SKIPPED (CPU lacks the features)");
                continue;
            }
            for round in 0..200 {
                let mut iv = [0u64; 8];
                iv.iter_mut().for_each(|w| *w = next());
                data.iter_mut().for_each(|b| *b = next() as u8);
                let blocks = 1 + round % 7;
                let mut want = iv;
                compress512_soft_blocks(&mut want, &data[..blocks * 128]);
                let mut got = iv;
                // SAFETY: the features were checked above.
                unsafe { kernel(&mut got, &data[..blocks * 128]) };
                assert_eq!(got, want, "sha512 {name}, {blocks} blocks");
            }
        }
    }

    /// The aarch64 `sha512` hardware compression must equal the software path
    /// for every block. Runs only where the extension exists.
    #[cfg(all(feature = "std", target_arch = "aarch64"))]
    #[test]
    #[allow(unsafe_code)] // calls the `unsafe` hardware backend directly
    fn sha512_hardware_matches_software() {
        // See the note in `sha1.rs`: report skip-vs-run so a green suite is not
        // mistaken for evidence that the hardware kernel ran. On x86 this is the
        // SHA512-extension path, which no CPU here can reach yet.
        if !super::super::sha_hw::sha512_supported() {
            std::eprintln!("hw-sha512: SKIPPED (no hardware SHA-512 on this CPU)");
            return;
        }
        std::eprintln!("hw-sha512: RUNNING against hardware backend");
        let mut s = 0x0123_4567_89ab_cdefu64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..1000 {
            let mut hw = H512;
            for (j, v) in hw.iter_mut().enumerate() {
                if j % 2 == 0 {
                    *v = next();
                }
            }
            let sw = hw;
            let mut block = [0u8; 128];
            for b in block.iter_mut() {
                *b = (next() >> 24) as u8;
            }
            let mut a = sw;
            let mut b = hw;
            compress512_soft(&mut a, &block);
            // SAFETY: the `sha512_supported()` check above returned early.
            unsafe { super::super::sha_hw::compress512(&mut b, &block) };
            assert_eq!(a, b, "sha512 HW/soft mismatch");
        }
        // Dispatched digest must equal a pure-software digest of the same data.
        let data: alloc::vec::Vec<u8> = (0..900u32).map(|i| (i * 5) as u8).collect();
        assert_eq!(sha512(&data).to_vec(), software_digest(H512, &data, 64));
    }

    #[test]
    fn sha512_vectors() {
        assert_eq!(
            sha512(b""),
            from_hex::<64>(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            )
        );
        assert_eq!(
            sha512(b"abc"),
            from_hex::<64>(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }

    #[test]
    fn sha512_one_million_a() {
        let mut h = Sha512::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            h.finalize(),
            from_hex::<64>(
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
                 de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
            )
        );
    }

    #[test]
    fn sha384_vectors() {
        assert_eq!(
            sha384(b""),
            from_hex::<48>(
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
                 274edebfe76f65fbd51ad2f14898b95b"
            )
        );
        assert_eq!(
            sha384(b"abc"),
            from_hex::<48>(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                 8086072ba1e7cc2358baeca134c825a7"
            )
        );
    }

    #[test]
    fn sha512_256_vectors() {
        assert_eq!(
            sha512_256(b""),
            from_hex::<32>("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a")
        );
        assert_eq!(
            sha512_256(b"abc"),
            from_hex::<32>("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23")
        );
    }

    #[test]
    fn sha512_224_vectors() {
        assert_eq!(
            sha512_224(b""),
            from_hex::<28>("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4")
        );
        assert_eq!(
            sha512_224(b"abc"),
            from_hex::<28>("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa")
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        // ~1.5 blocks, exercising the 112-byte length-field boundary handling.
        let big = [0xa5u8; 250];
        let oneshot = sha512(&big);
        let mut h = Sha512::new();
        h.update(&big[..1]);
        h.update(&big[1..111]);
        h.update(&big[111..200]);
        h.update(&big[200..]);
        assert_eq!(h.finalize(), oneshot);
    }
}
