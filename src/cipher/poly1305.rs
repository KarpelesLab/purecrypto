//! The Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! Poly1305 evaluates a polynomial in the secret evaluation point `r` modulo
//! the prime `2¹³⁰ − 5`, then adds the secret pad `s` modulo `2¹²⁸`. The
//! 130-bit arithmetic here is carried in five 26-bit limbs (the "donna" layout),
//! which keeps every step within 64-bit products and uses a branchless final
//! reduction — there are no secret-dependent branches or table lookups.
//!
//! The (`r`, `s`) key is **single-use**: authenticating two messages under the
//! same Poly1305 key reveals `r` and breaks the MAC. In ChaCha20-Poly1305 a
//! fresh key is derived per record from the cipher keystream.

/// Reads four bytes as a little-endian `u32`.
#[inline]
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// A Poly1305 authenticator state.
///
/// Implements [`Drop`] to wipe the clamped `r`, the precomputed `5·r`, the
/// accumulator `h`, the additive pad `s`, and the input-side buffer when the
/// state goes out of scope — these are all derived from the secret one-time
/// key.
#[derive(Clone)]
pub struct Poly1305 {
    /// Clamped evaluation point `r`, in five 26-bit limbs.
    r: [u32; 5],
    /// Precomputed `5·r[1..=4]` for the modular reduction.
    s: [u32; 4],
    /// Accumulator `h`, in five 26-bit limbs.
    h: [u32; 5],
    /// The final additive pad `s`, as four 32-bit words.
    pad: [u32; 4],
    /// Bytes held back until a full 16-byte block (or finalization).
    buffer: [u8; 16],
    leftover: usize,
}

impl Poly1305 {
    /// Creates a Poly1305 state from a 32-byte one-time key (`r ‖ s`).
    pub fn new(key: &[u8; 32]) -> Self {
        // Clamp r (RFC 8439 §2.5): clear the high 4 bits of each r byte group
        // and the low 2 bits of the upper three words.
        let r0 = le32(&key[0..4]) & 0x03ff_ffff;
        let r1 = (le32(&key[3..7]) >> 2) & 0x03ff_ff03;
        let r2 = (le32(&key[6..10]) >> 4) & 0x03ff_c0ff;
        let r3 = (le32(&key[9..13]) >> 6) & 0x03f0_3fff;
        let r4 = (le32(&key[12..16]) >> 8) & 0x000f_ffff;
        Poly1305 {
            r: [r0, r1, r2, r3, r4],
            s: [r1 * 5, r2 * 5, r3 * 5, r4 * 5],
            h: [0; 5],
            pad: [
                le32(&key[16..20]),
                le32(&key[20..24]),
                le32(&key[24..28]),
                le32(&key[28..32]),
            ],
            buffer: [0; 16],
            leftover: 0,
        }
    }

    /// Absorbs one 16-byte block. `hibit` is `1 << 24` (the implicit 2¹²⁸ bit)
    /// for a full block, or `0` for the padded final block.
    fn block(&mut self, m: &[u8; 16], hibit: u32) {
        let t0 = le32(&m[0..4]);
        let t1 = le32(&m[4..8]);
        let t2 = le32(&m[8..12]);
        let t3 = le32(&m[12..16]);

        // h += m
        let h0 = (self.h[0] + (t0 & 0x03ff_ffff)) as u64;
        let h1 = (self.h[1] + (((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff)) as u64;
        let h2 = (self.h[2] + (((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff)) as u64;
        let h3 = (self.h[3] + (((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff)) as u64;
        let h4 = (self.h[4] + ((t3 >> 8) | hibit)) as u64;

        let [r0, r1, r2, r3, r4] = self.r.map(u64::from);
        let [s1, s2, s3, s4] = self.s.map(u64::from);

        // h *= r mod 2¹³⁰−5 (schoolbook with the 5·r wrap-around terms)
        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        // Partial carry propagation back into 26-bit limbs.
        let mut c = d0 >> 26;
        let nh0 = (d0 as u32) & 0x03ff_ffff;
        let d1 = d1 + c;
        c = d1 >> 26;
        let nh1 = (d1 as u32) & 0x03ff_ffff;
        let d2 = d2 + c;
        c = d2 >> 26;
        let nh2 = (d2 as u32) & 0x03ff_ffff;
        let d3 = d3 + c;
        c = d3 >> 26;
        let nh3 = (d3 as u32) & 0x03ff_ffff;
        let d4 = d4 + c;
        c = d4 >> 26;
        let nh4 = (d4 as u32) & 0x03ff_ffff;
        let nh0 = nh0 as u64 + c * 5;
        let carry = (nh0 >> 26) as u32;
        self.h = [(nh0 as u32) & 0x03ff_ffff, nh1 + carry, nh2, nh3, nh4];
    }

    /// Absorbs `data` into the authenticator.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.leftover > 0 {
            let want = 16 - self.leftover;
            let take = want.min(data.len());
            self.buffer[self.leftover..self.leftover + take].copy_from_slice(&data[..take]);
            self.leftover += take;
            data = &data[take..];
            if self.leftover < 16 {
                return;
            }
            let block = self.buffer;
            self.block(&block, 1 << 24);
            self.leftover = 0;
        }

        // On x86_64 with AVX2, evaluate eight blocks per step with
        // precomputed powers r¹..r⁸ (parallel Horner). Only worth it once the
        // message is long enough to amortize the power setup; the tail
        // (< 128 bytes of full blocks plus any partial block) falls through
        // to the scalar path. Control flow depends only on the public message
        // length.
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        if data.len() >= simd::MIN_LEN && simd::supported() {
            let vec_len = data.len() & !127;
            simd::blocks(self, &data[..vec_len]);
            data = &data[vec_len..];
        }

        let mut chunks = data.chunks_exact(16);
        for chunk in &mut chunks {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            self.block(&block, 1 << 24);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.buffer[..rem.len()].copy_from_slice(rem);
            self.leftover = rem.len();
        }
    }

    /// Finalizes and returns the 16-byte authentication tag.
    pub fn finish(mut self) -> [u8; 16] {
        if self.leftover > 0 {
            let mut block = [0u8; 16];
            block[..self.leftover].copy_from_slice(&self.buffer[..self.leftover]);
            block[self.leftover] = 1;
            self.block(&block, 0);
        }

        // Fully carry h.
        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
        let mut c = h1 >> 26;
        h1 &= 0x03ff_ffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x03ff_ffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x03ff_ffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x03ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;

        // Compute h − p; if it does not borrow, h ≥ p and we keep the result.
        let mut g0 = h0 + 5;
        c = g0 >> 26;
        g0 &= 0x03ff_ffff;
        let mut g1 = h1 + c;
        c = g1 >> 26;
        g1 &= 0x03ff_ffff;
        let mut g2 = h2 + c;
        c = g2 >> 26;
        g2 &= 0x03ff_ffff;
        let mut g3 = h3 + c;
        c = g3 >> 26;
        g3 &= 0x03ff_ffff;
        let g4 = (h4 + c).wrapping_sub(1 << 26);

        // mask = 0 when h < p (g4 borrowed, high bit set), else all-ones.
        let mask = (g4 >> 31).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let g4 = g4 & mask;
        let nmask = !mask;
        h0 = (h0 & nmask) | g0;
        h1 = (h1 & nmask) | g1;
        h2 = (h2 & nmask) | g2;
        h3 = (h3 & nmask) | g3;
        h4 = (h4 & nmask) | g4;

        // Repack the 26-bit limbs into four 32-bit words (mod 2¹²⁸).
        let h0 = h0 | (h1 << 26);
        let h1 = (h1 >> 6) | (h2 << 20);
        let h2 = (h2 >> 12) | (h3 << 14);
        let h3 = (h3 >> 18) | (h4 << 8);

        // tag = (h + pad) mod 2¹²⁸.
        let mut f = h0 as u64 + self.pad[0] as u64;
        let m0 = f as u32;
        f = h1 as u64 + self.pad[1] as u64 + (f >> 32);
        let m1 = f as u32;
        f = h2 as u64 + self.pad[2] as u64 + (f >> 32);
        let m2 = f as u32;
        f = h3 as u64 + self.pad[3] as u64 + (f >> 32);
        let m3 = f as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&m0.to_le_bytes());
        tag[4..8].copy_from_slice(&m1.to_le_bytes());
        tag[8..12].copy_from_slice(&m2.to_le_bytes());
        tag[12..16].copy_from_slice(&m3.to_le_bytes());
        tag
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        // Best-effort secret wipe: zero every field that's derived from the
        // one-time key, then apply the standard `black_box` optimisation
        // barrier so LLVM doesn't elide the writes as a dead store.
        self.r = [0; 5];
        self.s = [0; 4];
        self.h = [0; 5];
        self.pad = [0; 4];
        self.buffer = [0u8; 16];
        self.leftover = 0;
        let _ = core::hint::black_box(&self.r);
        let _ = core::hint::black_box(&self.s);
        let _ = core::hint::black_box(&self.h);
        let _ = core::hint::black_box(&self.pad);
        let _ = core::hint::black_box(&self.buffer);
    }
}

/// AVX2 multi-block Poly1305 polynomial evaluation (x86_64),
/// poly1305-donna-AVX2 / Goll–Gueron style. Four consecutive 16-byte blocks
/// are held limb-sliced in `__m256i` vectors (one 26-bit limb per 64-bit
/// lane, so `vpmuludq` produces the full 64-bit partial products); two such
/// stripes advance in lockstep by the parallel-Horner identity
/// `h = (h + m) · r⁸` — the second, independent accumulator hides the latency
/// of the serial carry chain — with a final lane-wise multiply by
/// `[r⁸ … r¹]` and a horizontal fold. Carries stay lazy exactly as in the
/// scalar path. All arithmetic is multiply/add/shift/mask — no
/// secret-dependent branches or lookups — and the result is pinned to the
/// scalar path by a differential test over every length in `0..=1024` plus
/// large and chunked-streaming cases.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod simd {
    use super::Poly1305;
    use core::arch::x86_64::*;

    /// Below this many bytes the scalar path wins (power precomputation and
    /// vector setup cost more than they save).
    pub(super) const MIN_LEN: usize = 256;

    const MASK26: u64 = 0x03ff_ffff;

    pub(super) fn supported() -> bool {
        std::is_x86_feature_detected!("avx2")
    }

    /// Absorbs `data` (a non-empty multiple of 128 bytes) into `st.h`.
    pub(super) fn blocks(st: &mut Poly1305, data: &[u8]) {
        debug_assert!(!data.is_empty() && data.len().is_multiple_of(128));
        // SAFETY: `supported()` (checked by the caller) confirmed AVX2.
        unsafe { blocks_avx2(st, data) }
    }

    /// Scalar `a·b mod 2¹³⁰−5` on 5×26-bit limbs (same schoolbook + partial
    /// carry as `Poly1305::block`), used to precompute the powers of `r`.
    /// Output limbs are below `2²⁶ + 2⁹`.
    fn mul_mod(a: &[u32; 5], b: &[u32; 5]) -> [u32; 5] {
        let [a0, a1, a2, a3, a4] = a.map(u64::from);
        let [b0, b1, b2, b3, b4] = b.map(u64::from);
        let (s1, s2, s3, s4) = (b1 * 5, b2 * 5, b3 * 5, b4 * 5);

        let d0 = a0 * b0 + a1 * s4 + a2 * s3 + a3 * s2 + a4 * s1;
        let d1 = a0 * b1 + a1 * b0 + a2 * s4 + a3 * s3 + a4 * s2;
        let d2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * s4 + a4 * s3;
        let d3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * s4;
        let d4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        let mut c = d0 >> 26;
        let h0 = (d0 as u32) & 0x03ff_ffff;
        let d1 = d1 + c;
        c = d1 >> 26;
        let h1 = (d1 as u32) & 0x03ff_ffff;
        let d2 = d2 + c;
        c = d2 >> 26;
        let h2 = (d2 as u32) & 0x03ff_ffff;
        let d3 = d3 + c;
        c = d3 >> 26;
        let h3 = (d3 as u32) & 0x03ff_ffff;
        let d4 = d4 + c;
        c = d4 >> 26;
        let h4 = (d4 as u32) & 0x03ff_ffff;
        let h0 = h0 as u64 + c * 5;
        let carry = (h0 >> 26) as u32;
        [(h0 as u32) & 0x03ff_ffff, h1 + carry, h2, h3, h4]
    }

    /// Loads four consecutive 16-byte blocks limb-sliced: element `i` of the
    /// result holds limb `i` of blocks 0..4 in its four 64-bit lanes, with the
    /// implicit 2¹²⁸ bit set on limb 4 (all blocks here are full blocks).
    #[inline(always)]
    unsafe fn load4(m: &[u8]) -> [__m256i; 5] {
        unsafe {
            let lo = _mm256_loadu_si256(m.as_ptr().cast()); // blocks 0,1
            let hi = _mm256_loadu_si256(m.as_ptr().add(32).cast()); // blocks 2,3
            let a = _mm256_permute2x128_si256::<0x20>(lo, hi); // [block0 | block2]
            let b = _mm256_permute2x128_si256::<0x31>(lo, hi); // [block1 | block3]
            // Even/odd 32-bit words of each block, still block-interleaved:
            // e = [b0w0 b1w0 b0w1 b1w1 | b2w0 b3w0 b2w1 b3w1] (as 8×u32).
            let e = _mm256_unpacklo_epi32(a, b);
            let o = _mm256_unpackhi_epi32(a, b);
            // wN = 32-bit word N of blocks 0..4, zero-extended to u64 lanes.
            let pick = |v: __m256i, idx: i32| {
                let packed = match idx {
                    0 => _mm256_permute4x64_epi64::<0b1000>(v),
                    _ => _mm256_permute4x64_epi64::<0b1101>(v),
                };
                _mm256_cvtepu32_epi64(_mm256_castsi256_si128(packed))
            };
            let w0 = pick(e, 0);
            let w1 = pick(e, 1);
            let w2 = pick(o, 0);
            let w3 = pick(o, 1);

            let mask = _mm256_set1_epi64x(MASK26 as i64);
            let or = _mm256_or_si256;
            [
                _mm256_and_si256(w0, mask),
                _mm256_and_si256(
                    or(_mm256_srli_epi64::<26>(w0), _mm256_slli_epi64::<6>(w1)),
                    mask,
                ),
                _mm256_and_si256(
                    or(_mm256_srli_epi64::<20>(w1), _mm256_slli_epi64::<12>(w2)),
                    mask,
                ),
                _mm256_and_si256(
                    or(_mm256_srli_epi64::<14>(w2), _mm256_slli_epi64::<18>(w3)),
                    mask,
                ),
                or(_mm256_srli_epi64::<8>(w3), _mm256_set1_epi64x(1 << 24)),
            ]
        }
    }

    /// Lane-wise `h·r mod 2¹³⁰−5` with the same lazy carry structure as the
    /// scalar path. `r` holds one multiplier per lane (< 2²⁶ + 2⁹ per limb),
    /// `s` its wrap-around limbs `5·r[1..=4]`; `h` limbs may reach 2²⁸.
    /// Output limbs are below `2²⁶ + 2⁹`.
    #[inline(always)]
    unsafe fn mul_carry(h: &[__m256i; 5], r: &[__m256i; 5], s: &[__m256i; 4]) -> [__m256i; 5] {
        unsafe {
            let mul = |a, b| _mm256_mul_epu32(a, b);
            let add = |a, b| _mm256_add_epi64(a, b);

            // Schoolbook with the 5·r wrap-around terms; every product is at
            // most 2²⁸·2²⁹ = 2⁵⁷ and each column sums five of them, well
            // inside the 64-bit lanes.
            let d0 = add(
                add(mul(h[0], r[0]), mul(h[1], s[3])),
                add(mul(h[2], s[2]), add(mul(h[3], s[1]), mul(h[4], s[0]))),
            );
            let d1 = add(
                add(mul(h[0], r[1]), mul(h[1], r[0])),
                add(mul(h[2], s[3]), add(mul(h[3], s[2]), mul(h[4], s[1]))),
            );
            let d2 = add(
                add(mul(h[0], r[2]), mul(h[1], r[1])),
                add(mul(h[2], r[0]), add(mul(h[3], s[3]), mul(h[4], s[2]))),
            );
            let d3 = add(
                add(mul(h[0], r[3]), mul(h[1], r[2])),
                add(mul(h[2], r[1]), add(mul(h[3], r[0]), mul(h[4], s[3]))),
            );
            let d4 = add(
                add(mul(h[0], r[4]), mul(h[1], r[3])),
                add(mul(h[2], r[2]), add(mul(h[3], r[1]), mul(h[4], r[0]))),
            );

            // Partial carry propagation back into (lazy) 26-bit limbs.
            let mask = _mm256_set1_epi64x(MASK26 as i64);
            let mut c = _mm256_srli_epi64::<26>(d0);
            let h0 = _mm256_and_si256(d0, mask);
            let d1 = add(d1, c);
            c = _mm256_srli_epi64::<26>(d1);
            let h1 = _mm256_and_si256(d1, mask);
            let d2 = add(d2, c);
            c = _mm256_srli_epi64::<26>(d2);
            let h2 = _mm256_and_si256(d2, mask);
            let d3 = add(d3, c);
            c = _mm256_srli_epi64::<26>(d3);
            let h3 = _mm256_and_si256(d3, mask);
            let d4 = add(d4, c);
            c = _mm256_srli_epi64::<26>(d4);
            let h4 = _mm256_and_si256(d4, mask);
            // h0 += c·5, then one more carry into h1.
            let h0 = add(h0, add(c, _mm256_slli_epi64::<2>(c)));
            c = _mm256_srli_epi64::<26>(h0);
            let h0 = _mm256_and_si256(h0, mask);
            let h1 = add(h1, c);
            [h0, h1, h2, h3, h4]
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn blocks_avx2(st: &mut Poly1305, data: &[u8]) {
        unsafe {
            // Powers of the evaluation point: r¹..r⁸.
            let r1 = st.r;
            let r2 = mul_mod(&r1, &r1);
            let r3 = mul_mod(&r2, &r1);
            let r4 = mul_mod(&r2, &r2);
            let r5 = mul_mod(&r4, &r1);
            let r6 = mul_mod(&r4, &r2);
            let r7 = mul_mod(&r4, &r3);
            let r8 = mul_mod(&r4, &r4);

            let times5 = |v| _mm256_add_epi64(v, _mm256_slli_epi64::<2>(v));

            // r⁸ broadcast to every lane, for the striped Horner loop.
            let rr: [__m256i; 5] = core::array::from_fn(|j| _mm256_set1_epi64x(r8[j] as i64));
            let ss: [__m256i; 4] = core::array::from_fn(|j| times5(rr[j + 1]));

            // Two independent accumulators, blocks 0..4 and 4..8 of each
            // 128-byte stripe; h_in joins lane 0 of the first (the stream of
            // the oldest block, whose exponent is the highest).
            let mut ha = load4(data);
            let mut hb = load4(&data[64..128]);
            for (a, &hin) in ha.iter_mut().zip(st.h.iter()) {
                *a = _mm256_add_epi64(*a, _mm256_setr_epi64x(hin as i64, 0, 0, 0));
            }

            // h = (h · r⁸) + next stripe, for each remaining stripe. The two
            // chains have no data dependency until the fold.
            let mut off = 128;
            while off < data.len() {
                ha = mul_carry(&ha, &rr, &ss);
                hb = mul_carry(&hb, &rr, &ss);
                let ma = load4(&data[off..off + 64]);
                let mb = load4(&data[off + 64..off + 128]);
                for (i, a) in ha.iter_mut().enumerate() {
                    *a = _mm256_add_epi64(*a, ma[i]);
                    hb[i] = _mm256_add_epi64(hb[i], mb[i]);
                }
                off += 128;
            }

            // Fold: lane k of the first accumulator still owes a factor
            // r⁸⁻ᵏ, lane k of the second r⁴⁻ᵏ; then sum all eight lanes.
            let rpa: [__m256i; 5] = core::array::from_fn(|j| {
                _mm256_setr_epi64x(r8[j] as i64, r7[j] as i64, r6[j] as i64, r5[j] as i64)
            });
            let spa: [__m256i; 4] = core::array::from_fn(|j| times5(rpa[j + 1]));
            let rpb: [__m256i; 5] = core::array::from_fn(|j| {
                _mm256_setr_epi64x(r4[j] as i64, r3[j] as i64, r2[j] as i64, r1[j] as i64)
            });
            let spb: [__m256i; 4] = core::array::from_fn(|j| times5(rpb[j + 1]));
            let ha = mul_carry(&ha, &rpa, &spa);
            let hb = mul_carry(&hb, &rpb, &spb);

            let mut sum = [0u64; 5];
            for i in 0..5 {
                let mut lanes = [0u64; 4];
                // Limb-wise pair sum first: lanes stay below 2²⁷ + 2¹⁰.
                let h = _mm256_add_epi64(ha[i], hb[i]);
                _mm256_storeu_si256(lanes.as_mut_ptr().cast(), h);
                // Four lanes below 2²⁷ + 2¹⁰ each: the sum stays under 2²⁹.
                sum[i] = lanes[0] + lanes[1] + lanes[2] + lanes[3];
                // Best-effort wipe of the spilled secret lanes.
                lanes = [0; 4];
                let _ = core::hint::black_box(&lanes);
            }

            // Carry back into the scalar accumulator's lazy 26-bit form.
            let mut c = sum[0] >> 26;
            let h0 = (sum[0] as u32) & 0x03ff_ffff;
            sum[1] += c;
            c = sum[1] >> 26;
            let h1 = (sum[1] as u32) & 0x03ff_ffff;
            sum[2] += c;
            c = sum[2] >> 26;
            let h2 = (sum[2] as u32) & 0x03ff_ffff;
            sum[3] += c;
            c = sum[3] >> 26;
            let h3 = (sum[3] as u32) & 0x03ff_ffff;
            sum[4] += c;
            c = sum[4] >> 26;
            let h4 = (sum[4] as u32) & 0x03ff_ffff;
            let h0 = h0 as u64 + c * 5;
            let carry = (h0 >> 26) as u32;
            st.h = [(h0 as u32) & 0x03ff_ffff, h1 + carry, h2, h3, h4];
            let _ = core::hint::black_box(&sum);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    #[test]
    fn rfc8439_tag() {
        // RFC 8439 §2.5.2.
        let key =
            from_hex::<32>("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let msg = b"Cryptographic Forum Research Group";
        let mut p = Poly1305::new(&key);
        p.update(msg);
        assert_eq!(
            p.finish(),
            from_hex::<16>("a8061dc1305136c6c22b8baf0c0127a9")
        );
    }

    /// The AVX2 4-way path must produce the exact scalar tag for every
    /// length (byte-by-byte sweep across the dispatch threshold), for large
    /// messages, and under chunked streaming that straddles the leftover
    /// buffer, the vector stripes, and the scalar tail.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn simd_matches_scalar() {
        use alloc::vec::Vec;
        if !super::simd::supported() {
            return;
        }

        // Small deterministic PRNG for keys and data (not security relevant).
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut fill = |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = next() as u8;
            }
        };

        // Scalar oracle: feeding in sub-threshold chunks never dispatches to
        // the SIMD path (`update` only vectorizes runs of >= MIN_LEN bytes).
        let scalar_tag = |key: &[u8; 32], data: &[u8]| -> [u8; 16] {
            let mut p = Poly1305::new(key);
            for chunk in data.chunks(48) {
                p.update(chunk);
            }
            p.finish()
        };

        let mut data = Vec::new();
        for len in (0usize..=1024).chain([4096, 65536, 65536 + 17, 100_003]) {
            let mut key = [0u8; 32];
            fill(&mut key);
            data.resize(len, 0);
            fill(&mut data);

            let expected = scalar_tag(&key, &data);

            // One-shot (SIMD-dispatched for len >= MIN_LEN).
            let mut p = Poly1305::new(&key);
            p.update(&data);
            assert_eq!(p.finish(), expected, "one-shot len={len}");

            // Odd-sized chunks large enough to keep hitting the SIMD path,
            // preceded by a tiny chunk so the leftover buffer engages first.
            let mut p = Poly1305::new(&key);
            let mut rest = &data[..];
            for chunk_len in [5usize, 301, 4096 + 63, 257] {
                let take = chunk_len.min(rest.len());
                p.update(&rest[..take]);
                rest = &rest[take..];
            }
            p.update(rest);
            assert_eq!(p.finish(), expected, "chunked len={len}");
        }
    }

    #[test]
    fn streaming_matches_one_shot() {
        let key =
            from_hex::<32>("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let msg = b"Cryptographic Forum Research Group";
        let mut split = Poly1305::new(&key);
        split.update(&msg[..7]);
        split.update(&msg[7..16]);
        split.update(&msg[16..]);
        assert_eq!(
            split.finish(),
            from_hex::<16>("a8061dc1305136c6c22b8baf0c0127a9")
        );
    }
}
