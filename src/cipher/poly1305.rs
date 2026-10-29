//! The Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! Poly1305 evaluates a polynomial in the secret evaluation point `r` modulo
//! the prime `2¹³⁰ − 5`, then adds the secret pad `s` modulo `2¹²⁸`. The
//! 130-bit arithmetic is carried in the "donna" limb layouts: three 44-bit
//! limbs with `u128` products on 64-bit targets (two interleaved Horner
//! stripes hide the carry-chain latency on long inputs), five 26-bit limbs
//! with `u64` products on 32-bit targets. Both use a branchless final
//! reduction — there are no secret-dependent branches or table lookups.
//! On x86_64, long runs of blocks go through a vector kernel instead: AVX-512
//! IFMA (32 blocks per step, in the same radix 2⁴⁴) or AVX2 (eight blocks per
//! step, radix 2²⁶), each evaluating the polynomial with precomputed powers
//! of `r`.
//!
//! The (`r`, `s`) key is **single-use**: authenticating two messages under the
//! same Poly1305 key reveals `r` and breaks the MAC. In ChaCha20-Poly1305 a
//! fresh key is derived per record from the cipher keystream.

use crate::zeroize::Zeroize;

/// A Poly1305 authenticator state.
///
/// Implements [`Drop`] to wipe the clamped `r` and its precomputed multiples,
/// the accumulator `h`, the additive pad `s`, and the input-side buffer when
/// the state goes out of scope — these are all derived from the secret
/// one-time key.
#[derive(Clone)]
pub struct Poly1305 {
    /// The polynomial state: `r`, its reduction multiples and `h`.
    st: imp::State,
    /// The final additive pad `s`.
    pad: u128,
    /// Bytes held back until a full 16-byte block (or finalization).
    buffer: [u8; 16],
    leftover: usize,
}

impl Poly1305 {
    /// Creates a Poly1305 state from a 32-byte one-time key (`r ‖ s`).
    pub fn new(key: &[u8; 32]) -> Self {
        let (r, s) = key.split_at(16);
        Poly1305 {
            st: imp::State::new(r.try_into().expect("16-byte r")),
            pad: u128::from_le_bytes(s.try_into().expect("16-byte s")),
            buffer: [0; 16],
            leftover: 0,
        }
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
            self.st.block(&block, true);
            self.leftover = 0;
        }

        // On x86_64, evaluate many blocks per step with precomputed powers
        // of r (parallel Horner): 32 per step with AVX-512 IFMA, eight with
        // AVX2. Only worth it once the message is long enough to amortize
        // the vector setup; the tail (< 128 bytes of full blocks plus any
        // partial block) falls through to the scalar paths. Control flow
        // depends only on the public message length.
        #[cfg(target_arch = "x86_64")]
        if data.len() >= ifma::MIN_LEN && ifma::supported() {
            let vec_len = data.len() & !127;
            ifma::blocks(&mut self.st, &data[..vec_len]);
            data = &data[vec_len..];
        } else if data.len() >= simd::MIN_LEN && simd::supported() {
            let vec_len = data.len() & !127;
            simd::blocks(self, &data[..vec_len]);
            data = &data[vec_len..];
        }

        // 64-bit targets: interleaved Horner stripes — four (`h = (h + m)·r⁴`)
        // over runs of at least 512 bytes, where the `r³`/`r⁴` setup and
        // the fold amortise, two (`r²`) over runs of at least four blocks;
        // the odd blocks, if any, and anything shorter go through the
        // single-stripe step.
        #[cfg(target_pointer_width = "64")]
        {
            let quad_len = data.len() & !63;
            if quad_len >= 512 {
                self.st.blocks4(&data[..quad_len]);
                data = &data[quad_len..];
            }
            let pair_len = data.len() & !31;
            if pair_len >= 64 {
                self.st.blocks2(&data[..pair_len]);
                data = &data[pair_len..];
            }
        }

        let mut chunks = data.chunks_exact(16);
        for chunk in &mut chunks {
            let block: &[u8; 16] = chunk.try_into().expect("16-byte chunk");
            self.st.block(block, true);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.buffer[..rem.len()].copy_from_slice(rem);
            self.leftover = rem.len();
        }
    }

    /// Whether ChaCha20-Poly1305's stitched loop can run: AVX-512 IFMA (and
    /// so AVX-512F) is available and the state is block-aligned. Public
    /// facts only.
    #[cfg(target_arch = "x86_64")]
    pub(super) fn stitch_ready(&self) -> bool {
        self.leftover == 0 && ifma::supported()
    }

    /// Starts ChaCha20-Poly1305's stitched loop (see [`ifma::Stitch`]).
    /// Only valid once [`stitch_ready`](Self::stitch_ready) said so.
    #[cfg(target_arch = "x86_64")]
    pub(super) fn stitch(&mut self) -> ifma::Stitch<'_> {
        debug_assert!(self.stitch_ready());
        ifma::Stitch::new(&mut self.st)
    }

    /// Finalizes and returns the 16-byte authentication tag.
    pub fn finish(mut self) -> [u8; 16] {
        if self.leftover > 0 {
            let mut block = [0u8; 16];
            block[..self.leftover].copy_from_slice(&self.buffer[..self.leftover]);
            block[self.leftover] = 1;
            self.st.block(&block, false);
        }
        // tag = (h mod p + pad) mod 2¹²⁸.
        let h = self.st.reduce();
        h.wrapping_add(self.pad).to_le_bytes()
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        // Wipe every field derived from the one-time key. ChaCha20-Poly1305
        // builds and drops a fresh `Poly1305` per record, so this is on the
        // per-record path: with the word-at-a-time volatile wipe it costs
        // nothing measurable (an earlier per-limb version cost ~7% on a 1 KiB
        // record, which is why this used to be a plain store plus a
        // `black_box` barrier).
        self.st.wipe();
        self.pad.zeroize();
        self.buffer.zeroize();
        self.leftover.zeroize();
    }
}

/// Radix-2⁴⁴ polynomial state (poly1305-donna-64): `r` and `h` in three
/// limbs of 44, 44 and 42 bits, partial products as `u128`. Limbs are kept
/// lazily reduced — a multiplication leaves `h0 < 2⁴⁴`, `h1 ≤ 2⁴⁴`,
/// `h2 < 2⁴²`, and adding a message block or a second stripe stays under
/// 2⁴⁶ — which every product sum (`< 3 · 2⁴⁶ · 2⁴⁹`) fits comfortably.
#[cfg(target_pointer_width = "64")]
mod imp {
    use crate::zeroize::Zeroize;

    const M44: u64 = 0x0fff_ffff_ffff;
    const M42: u64 = 0x03ff_ffff_ffff;

    #[derive(Clone)]
    pub(super) struct State {
        /// Clamped evaluation point `r`.
        r: [u64; 3],
        /// `20·r[1]`, `20·r[2]`: the wrap-around multiples (`5 · 4`, since
        /// limb 2 is only 42 bits wide).
        s: [u64; 2],
        /// `r² mod p` and its multiples, for the two-stripe loop.
        r2: [u64; 3],
        s2: [u64; 2],
        /// Accumulator `h`.
        h: [u64; 3],
    }

    /// `h · r mod 2¹³⁰−5` with the lazy carry chain.
    #[inline(always)]
    fn mul(h: [u64; 3], r: [u64; 3], s: [u64; 2]) -> [u64; 3] {
        let [h0, h1, h2] = h.map(u128::from);
        let [r0, r1, r2] = r.map(u128::from);
        let [s1, s2] = s.map(u128::from);
        let d0 = h0 * r0 + h1 * s2 + h2 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0;
        let c = (d0 >> 44) as u64;
        let mut h0 = (d0 as u64) & M44;
        d1 += u128::from(c);
        let c = (d1 >> 44) as u64;
        let mut h1 = (d1 as u64) & M44;
        d2 += u128::from(c);
        let c = (d2 >> 42) as u64;
        let h2 = (d2 as u64) & M42;
        h0 += c * 5;
        let c = h0 >> 44;
        h0 &= M44;
        h1 += c;
        [h0, h1, h2]
    }

    /// Splits a 16-byte block into limbs, with the implicit 2¹²⁸ bit when
    /// `full`, and adds it into `h`. `full` is derived from the public
    /// message length, so the branch-free form is for uniformity only.
    #[inline(always)]
    fn add_block(h: &mut [u64; 3], m: &[u8; 16], full: bool) {
        let t0 = u64::from_le_bytes(m[..8].try_into().expect("8 bytes"));
        let t1 = u64::from_le_bytes(m[8..].try_into().expect("8 bytes"));
        h[0] += t0 & M44;
        h[1] += ((t0 >> 44) | (t1 << 20)) & M44;
        h[2] += ((t1 >> 24) & M42) | (u64::from(full) << 40);
    }

    impl State {
        pub(super) fn new(key: &[u8; 16]) -> Self {
            // Clamp r (RFC 8439 §2.5): clear the high 4 bits of each r byte
            // group and the low 2 bits of the upper three words.
            let t0 =
                u64::from_le_bytes(key[..8].try_into().expect("8 bytes")) & 0x0fff_fffc_0fff_ffff;
            let t1 =
                u64::from_le_bytes(key[8..].try_into().expect("8 bytes")) & 0x0fff_fffc_0fff_fffc;
            let r = [t0 & M44, ((t0 >> 44) | (t1 << 20)) & M44, (t1 >> 24) & M42];
            let s = [r[1] * 20, r[2] * 20];
            let r2 = mul(r, r, s);
            let s2 = [r2[1] * 20, r2[2] * 20];
            State {
                r,
                s,
                r2,
                s2,
                h: [0; 3],
            }
        }

        /// Absorbs one block: `h = (h + m) · r`.
        #[inline]
        pub(super) fn block(&mut self, m: &[u8; 16], full: bool) {
            add_block(&mut self.h, m, full);
            self.h = mul(self.h, self.r, self.s);
        }

        /// Absorbs `data` (a non-empty multiple of 64 bytes) with four
        /// interleaved Horner stripes, each advancing by `r⁴` per 64-byte
        /// group with no data dependency between them. After the last group
        /// the stripes are folded as `ha·r⁴ + hb·r³ + hc·r² + hd·r` (four
        /// independent multiplications), which is exactly the serial Horner
        /// value. `r³` and `r⁴` are derived here (two multiplications per
        /// call) rather than in `new`, so short messages do not pay for
        /// them.
        #[inline]
        pub(super) fn blocks4(&mut self, data: &[u8]) {
            debug_assert!(!data.is_empty() && data.len().is_multiple_of(64));
            let mut r3 = mul(self.r2, self.r, self.s);
            let mut s3 = [r3[1] * 20, r3[2] * 20];
            let mut r4 = mul(self.r2, self.r2, self.s2);
            let mut s4 = [r4[1] * 20, r4[2] * 20];
            let mut ha = self.h;
            let mut hb = [0u64; 3];
            let mut hc = [0u64; 3];
            let mut hd = [0u64; 3];
            let mut quads = data.chunks_exact(64);
            let last = quads.next_back().expect("at least one group");
            for q in quads {
                add_block(&mut ha, q[..16].try_into().expect("16 bytes"), true);
                add_block(&mut hb, q[16..32].try_into().expect("16 bytes"), true);
                add_block(&mut hc, q[32..48].try_into().expect("16 bytes"), true);
                add_block(&mut hd, q[48..].try_into().expect("16 bytes"), true);
                ha = mul(ha, r4, s4);
                hb = mul(hb, r4, s4);
                hc = mul(hc, r4, s4);
                hd = mul(hd, r4, s4);
            }
            add_block(&mut ha, last[..16].try_into().expect("16 bytes"), true);
            add_block(&mut hb, last[16..32].try_into().expect("16 bytes"), true);
            add_block(&mut hc, last[32..48].try_into().expect("16 bytes"), true);
            add_block(&mut hd, last[48..].try_into().expect("16 bytes"), true);
            ha = mul(ha, r4, s4);
            hb = mul(hb, r3, s3);
            hc = mul(hc, self.r2, self.s2);
            hd = mul(hd, self.r, self.s);
            self.h = [
                ha[0] + hb[0] + hc[0] + hd[0],
                ha[1] + hb[1] + hc[1] + hd[1],
                ha[2] + hb[2] + hc[2] + hd[2],
            ];
            // `r³`/`r⁴` are key-derived and the stripes are accumulator
            // state; this runs once per `update`, so the plain-store barrier
            // suffices.
            r3 = [0; 3];
            s3 = [0; 2];
            r4 = [0; 3];
            s4 = [0; 2];
            ha = [0; 3];
            hb = [0; 3];
            hc = [0; 3];
            hd = [0; 3];
            let _ = core::hint::black_box(&r3);
            let _ = core::hint::black_box(&s3);
            let _ = core::hint::black_box(&r4);
            let _ = core::hint::black_box(&s4);
            let _ = core::hint::black_box(&ha);
            let _ = core::hint::black_box(&hb);
            let _ = core::hint::black_box(&hc);
            let _ = core::hint::black_box(&hd);
        }

        /// Absorbs `data` (a non-empty multiple of 32 bytes) with two
        /// interleaved Horner stripes: the odd blocks advance one
        /// accumulator by `r²` per pair, the even blocks the other, and the
        /// two chains have no data dependency until the final fold. The last
        /// pair multiplies the even stripe by `r` instead, so that
        /// `ha + hb` is exactly the serial Horner value.
        #[inline]
        pub(super) fn blocks2(&mut self, data: &[u8]) {
            debug_assert!(!data.is_empty() && data.len().is_multiple_of(32));
            let mut ha = self.h;
            let mut hb = [0u64; 3];
            let mut pairs = data.chunks_exact(32);
            let last = pairs.next_back().expect("at least one pair");
            for pair in pairs {
                add_block(&mut ha, pair[..16].try_into().expect("16 bytes"), true);
                add_block(&mut hb, pair[16..].try_into().expect("16 bytes"), true);
                ha = mul(ha, self.r2, self.s2);
                hb = mul(hb, self.r2, self.s2);
            }
            add_block(&mut ha, last[..16].try_into().expect("16 bytes"), true);
            add_block(&mut hb, last[16..].try_into().expect("16 bytes"), true);
            ha = mul(ha, self.r2, self.s2);
            hb = mul(hb, self.r, self.s);
            self.h = [ha[0] + hb[0], ha[1] + hb[1], ha[2] + hb[2]];
            // Stripe scratch is key-derived accumulator state; this runs once
            // per `update`, so the plain-store barrier suffices.
            ha = [0; 3];
            hb = [0; 3];
            let _ = core::hint::black_box(&ha);
            let _ = core::hint::black_box(&hb);
        }

        /// Fully carries the lazy limbs (input limbs up to 2⁴⁶) so that
        /// `h0, h1 < 2⁴⁴`, `h2 < 2⁴²`, i.e. `h < 2¹³⁰`.
        #[inline(always)]
        fn carry(&self) -> [u64; 3] {
            let [mut h0, mut h1, mut h2] = self.h;
            for _ in 0..2 {
                let c = h1 >> 44;
                h1 &= M44;
                h2 += c;
                let c = h2 >> 42;
                h2 &= M42;
                h0 += c * 5;
                let c = h0 >> 44;
                h0 &= M44;
                h1 += c;
            }
            [h0, h1, h2]
        }

        /// `h mod p`, fully reduced, as a 128-bit value (mod 2¹²⁸).
        pub(super) fn reduce(&self) -> u128 {
            let [mut h0, mut h1, mut h2] = self.carry();

            // Compute g = h + 5 − 2¹³⁰; if it does not borrow, h ≥ p and g is
            // the reduced value.
            let mut g0 = h0 + 5;
            let c = g0 >> 44;
            g0 &= M44;
            let mut g1 = h1 + c;
            let c = g1 >> 44;
            g1 &= M44;
            let g2 = (h2 + c).wrapping_sub(1 << 42);

            // mask = 0 when h < p (g2 borrowed, high bit set), else all-ones.
            // `black_box` keeps the optimizer from turning the masked
            // selects into a branch on the secret comparison result.
            let mask = core::hint::black_box((g2 >> 63).wrapping_sub(1));
            let nmask = !mask;
            h0 = (h0 & nmask) | (g0 & mask);
            h1 = (h1 & nmask) | (g1 & mask);
            h2 = (h2 & nmask) | (g2 & mask);

            // Repack the limbs into 128 bits.
            let lo = h0 | (h1 << 44);
            let hi = (h1 >> 20) | (h2 << 24);
            u128::from(lo) | (u128::from(hi) << 64)
        }

        pub(super) fn wipe(&mut self) {
            self.r.zeroize();
            self.s.zeroize();
            self.r2.zeroize();
            self.s2.zeroize();
            self.h.zeroize();
        }

        /// `[r, r², r⁴, r⁸, r¹⁶, r³²]` (lazily reduced limbs), the IFMA
        /// kernel's seeds for its lane power vectors. The caller wipes the
        /// result.
        #[cfg(target_arch = "x86_64")]
        pub(super) fn r_pows(&self) -> [[u64; 3]; 6] {
            let mut p = [self.r, self.r2, [0; 3], [0; 3], [0; 3], [0; 3]];
            for k in 2..6 {
                let sq = p[k - 1];
                p[k] = mul(sq, sq, [sq[1] * 20, sq[2] * 20]);
            }
            p
        }

        /// The raw (lazily reduced) radix-2⁴⁴ accumulator.
        #[cfg(target_arch = "x86_64")]
        pub(super) fn h44(&self) -> [u64; 3] {
            self.h
        }

        /// Loads `h` from radix-2⁴⁴ limbs of up to 2⁶⁰ each, carrying them
        /// back under the lazy bounds the scalar steps assume.
        #[cfg(target_arch = "x86_64")]
        pub(super) fn set_h44(&mut self, l: [u64; 3]) {
            let [mut h0, mut h1, mut h2] = l;
            let c = h0 >> 44;
            h0 &= M44;
            h1 += c;
            let c = h1 >> 44;
            h1 &= M44;
            h2 += c;
            let c = h2 >> 42;
            h2 &= M42;
            h0 += c * 5;
            let c = h0 >> 44;
            h0 &= M44;
            h1 += c;
            self.h = [h0, h1, h2];
        }

        /// `r` as five 26-bit limbs, for the AVX2 kernel's power table.
        #[cfg(target_arch = "x86_64")]
        pub(super) fn r26(&self) -> [u32; 5] {
            let r = u128::from(self.r[0])
                | (u128::from(self.r[1]) << 44)
                | (u128::from(self.r[2]) << 88);
            core::array::from_fn(|i| ((r >> (26 * i)) as u32) & 0x03ff_ffff)
        }

        /// `h` as five lazily reduced 26-bit limbs (each below 2²⁷).
        #[cfg(target_arch = "x86_64")]
        pub(super) fn h26(&self) -> [u32; 5] {
            let [h0, h1, h2] = self.carry();
            [
                (h0 & 0x03ff_ffff) as u32,
                ((h0 >> 26) + ((h1 & 0xff) << 18)) as u32,
                ((h1 >> 8) & 0x03ff_ffff) as u32,
                ((h1 >> 34) + ((h2 & 0xffff) << 10)) as u32,
                (h2 >> 16) as u32,
            ]
        }

        /// Loads `h` from five lazily reduced 26-bit limbs (each below 2²⁸).
        #[cfg(target_arch = "x86_64")]
        pub(super) fn set_h26(&mut self, l: [u32; 5]) {
            let l = l.map(u64::from);
            // Sum (not OR) the correctly weighted pieces, so lazily reduced
            // input limbs carry naturally.
            self.h = [
                l[0] + ((l[1] & 0x3ffff) << 26),
                (l[1] >> 18) + (l[2] << 8) + ((l[3] & 0x3ff) << 34),
                (l[3] >> 10) + (l[4] << 16),
            ];
        }
    }
}

/// Radix-2²⁶ polynomial state (poly1305-donna-32): `r` and `h` in five
/// 26-bit limbs, partial products as `u64`, for targets without a fast
/// 64×64→128 multiply.
#[cfg(not(target_pointer_width = "64"))]
mod imp {
    use crate::zeroize::Zeroize;

    /// Reads four bytes as a little-endian `u32`.
    #[inline]
    fn le32(b: &[u8]) -> u32 {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    #[derive(Clone)]
    pub(super) struct State {
        /// Clamped evaluation point `r`, in five 26-bit limbs.
        r: [u32; 5],
        /// Precomputed `5·r[1..=4]` for the modular reduction.
        s: [u32; 4],
        /// Accumulator `h`, in five 26-bit limbs.
        h: [u32; 5],
    }

    impl State {
        pub(super) fn new(key: &[u8; 16]) -> Self {
            // Clamp r (RFC 8439 §2.5): clear the high 4 bits of each r byte
            // group and the low 2 bits of the upper three words.
            let r0 = le32(&key[0..4]) & 0x03ff_ffff;
            let r1 = (le32(&key[3..7]) >> 2) & 0x03ff_ff03;
            let r2 = (le32(&key[6..10]) >> 4) & 0x03ff_c0ff;
            let r3 = (le32(&key[9..13]) >> 6) & 0x03f0_3fff;
            let r4 = (le32(&key[12..16]) >> 8) & 0x000f_ffff;
            State {
                r: [r0, r1, r2, r3, r4],
                s: [r1 * 5, r2 * 5, r3 * 5, r4 * 5],
                h: [0; 5],
            }
        }

        /// Absorbs one block: `h = (h + m) · r`. `full` sets the implicit
        /// 2¹²⁸ bit (it is derived from the public message length).
        pub(super) fn block(&mut self, m: &[u8; 16], full: bool) {
            let hibit = u32::from(full) << 24;
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

        /// `h mod p`, fully reduced, as a 128-bit value (mod 2¹²⁸).
        pub(super) fn reduce(&self) -> u128 {
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

            // Compute h − p; if it does not borrow, h ≥ p and we keep the
            // result.
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
            // `black_box` keeps the optimizer from turning the masked selects
            // below into a branch on the secret comparison result.
            let mask = core::hint::black_box((g4 >> 31).wrapping_sub(1));
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
            let w0 = h0 | (h1 << 26);
            let w1 = (h1 >> 6) | (h2 << 20);
            let w2 = (h2 >> 12) | (h3 << 14);
            let w3 = (h3 >> 18) | (h4 << 8);
            u128::from(w0)
                | (u128::from(w1) << 32)
                | (u128::from(w2) << 64)
                | (u128::from(w3) << 96)
        }

        pub(super) fn wipe(&mut self) {
            self.r.zeroize();
            self.s.zeroize();
            self.h.zeroize();
        }
    }
}

/// AVX-512 IFMA multi-block Poly1305 (x86_64), in the scalar path's own
/// radix 2⁴⁴: eight consecutive 16-byte blocks sit one per 64-bit lane of a
/// `__m512i` per limb, and `vpmadd52luq`/`vpmadd52huq` produce the low and
/// high 52 bits of each 44×49-bit partial product directly — three limbs
/// instead of AVX2's five, so a block costs far fewer multiplies. Four such
/// 8-lane accumulators take the 128-byte groups round-robin and each
/// advances by `r³²` (`h = h·r³² + m`, parallel Horner), so four carry
/// chains overlap (measured on Zen 5: 0.131 → 0.117 cycles/byte going from
/// two chains to four); a final lane-wise multiply by the matching powers
/// and a horizontal sum fold them back into the scalar accumulator, with no
/// limb conversion.
///
/// Bounds: inputs to the multiplier stay below 2⁴⁶ (`h`) and 2⁴⁹ (`20·r`),
/// inside IFMA's 52-bit operand width; each column's low halves sum below
/// 2⁵⁵ and the carry chain is the scalar one. Multiply/add/shift/mask only —
/// no secret-dependent branches or lookups. The lane power vectors are built
/// per call from `r, r², r⁴, r⁸, r¹⁶, r³²` with six vector multiplies (no
/// table to store, copy or wipe in the state).
///
/// Pinned to the scalar path by a differential test over every length in
/// `0..=1100`, large messages, extreme limbs and odd-sized streaming chunks.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub(super) mod ifma {
    use super::imp;
    use crate::zeroize::Zeroize;
    use core::arch::x86_64::*;

    /// Below this many bytes the scalar path wins: the power vectors and the
    /// fold cost more than they save (measured on Zen 5: ~1.8 vs 1.5 cycles
    /// per byte at 256 bytes, 1.2 vs 1.4 at 384).
    pub(super) const MIN_LEN: usize = 384;

    /// Accumulators advancing in lockstep (each over every fourth group).
    const CHAINS: usize = 4;

    const M44: i64 = 0x0fff_ffff_ffff;
    const M42: i64 = 0x03ff_ffff_ffff;

    pub(super) fn supported() -> bool {
        !crate::ct::force_portable() && crate::cpu::avx512ifma()
    }

    /// Absorbs `data` (a non-empty multiple of 128 bytes) into `st`.
    pub(super) fn blocks(st: &mut imp::State, data: &[u8]) {
        debug_assert!(!data.is_empty() && data.len().is_multiple_of(128));
        // SAFETY: `supported()` (checked by the caller) confirmed AVX-512F
        // and AVX-512 IFMA.
        unsafe { blocks_ifma(st, data) }
    }

    /// Lane mask of the lanes whose fold exponent `e = 8 − j` (for the block
    /// `j` that [`load8`] places in the lane) has bit `bit` set in `e − 1`.
    const fn exp_mask(bit: u32) -> __mmask8 {
        let mut m = 0;
        let mut lane = 0;
        while lane < 8 {
            let j = lane / 2 + 4 * (lane % 2);
            if ((7 - j) >> bit) & 1 == 1 {
                m |= 1 << lane;
            }
            lane += 1;
        }
        m
    }

    /// `20·r` per lane (the wrap-around multiples of limbs 1 and 2).
    #[inline(always)]
    unsafe fn times20(r: __m512i) -> __m512i {
        unsafe { _mm512_add_epi64(_mm512_slli_epi64::<4>(r), _mm512_slli_epi64::<2>(r)) }
    }

    /// Eight consecutive full blocks as radix-2⁴⁴ limbs with the 2¹²⁸ bit.
    /// Lane `2k` holds block `k`, lane `2k + 1` block `4 + k`.
    #[inline(always)]
    unsafe fn load8(p: *const u8) -> [__m512i; 3] {
        unsafe {
            let a = _mm512_loadu_si512(p.cast());
            let b = _mm512_loadu_si512(p.add(64).cast());
            let t0 = _mm512_unpacklo_epi64(a, b);
            let t1 = _mm512_unpackhi_epi64(a, b);
            let m44 = _mm512_set1_epi64(M44);
            [
                _mm512_and_si512(t0, m44),
                _mm512_and_si512(
                    _mm512_or_si512(_mm512_srli_epi64::<44>(t0), _mm512_slli_epi64::<20>(t1)),
                    m44,
                ),
                _mm512_or_si512(_mm512_srli_epi64::<24>(t1), _mm512_set1_epi64(1 << 40)),
            ]
        }
    }

    /// Lane-wise `h·r + m mod 2¹³⁰−5` with the scalar path's carry chain.
    /// `s = [20·r₁, 20·r₂]`. Output limbs: `h₀ < 2⁴⁴`, `h₁ < 2⁴⁴ + 2¹⁴`,
    /// `h₂ < 2⁴²`.
    #[inline(always)]
    unsafe fn mul_add(
        h: &[__m512i; 3],
        r: &[__m512i; 3],
        s: &[__m512i; 2],
        m: &[__m512i; 3],
    ) -> [__m512i; 3] {
        unsafe {
            let z = _mm512_setzero_si512();
            let lo = |acc, a, b| _mm512_madd52lo_epu64(acc, a, b);
            let hi = |acc, a, b| _mm512_madd52hi_epu64(acc, a, b);
            // Column k: d_k = Σ h_i·r_j over i + j ≡ k, split into the low
            // 52 bits (`l`, weight 2^(44k)) and the rest (`u`, weight
            // 2^(44k + 52)). Ordered h₂, h₀, h₁: the carry chain below
            // finishes `h₂` first and `h₁` last, so the next step's
            // multiplies can start early (measured: 0.141 → 0.131
            // cycles/byte with two chains).
            let l0 = lo(lo(lo(m[0], h[2], s[0]), h[0], r[0]), h[1], s[1]);
            let l1 = lo(lo(lo(m[1], h[2], s[1]), h[0], r[1]), h[1], r[0]);
            let l2 = lo(lo(lo(m[2], h[2], r[0]), h[0], r[2]), h[1], r[1]);
            let u0 = hi(hi(hi(z, h[2], s[0]), h[0], r[0]), h[1], s[1]);
            let u1 = hi(hi(hi(z, h[2], s[1]), h[0], r[1]), h[1], r[0]);
            let u2 = hi(hi(hi(z, h[2], r[0]), h[0], r[2]), h[1], r[1]);

            let m44 = _mm512_set1_epi64(M44);
            let m42 = _mm512_set1_epi64(M42);
            let add = |a, b| _mm512_add_epi64(a, b);
            // 2⁵² = 2⁴⁴·2⁸ moves `u_k` one limb up; past limb 2 the weight
            // is 2¹³⁰·2¹⁰ ≡ 5·2¹⁰.
            let l1 = add(
                l1,
                add(_mm512_srli_epi64::<44>(l0), _mm512_slli_epi64::<8>(u0)),
            );
            let h0 = _mm512_and_si512(l0, m44);
            let l2 = add(
                l2,
                add(_mm512_srli_epi64::<44>(l1), _mm512_slli_epi64::<8>(u1)),
            );
            let h1 = _mm512_and_si512(l1, m44);
            let c = add(_mm512_srli_epi64::<42>(l2), _mm512_slli_epi64::<10>(u2));
            let h2 = _mm512_and_si512(l2, m42);
            let h0 = add(h0, add(c, _mm512_slli_epi64::<2>(c)));
            let h1 = add(h1, _mm512_srli_epi64::<44>(h0));
            let h0 = _mm512_and_si512(h0, m44);
            [h0, h1, h2]
        }
    }

    /// The per-call constants: the fold powers and the stride.
    struct Pow {
        /// `pw[k]` = `r^(8k + 8 − j)` per lane: what a chain owes when its
        /// final group is `k` groups before the message's last one.
        pw: [[__m512i; 3]; CHAINS],
        /// `r^(8·CHAINS)` = `r³²` in every lane and its `20·r` multiples.
        step: [__m512i; 3],
        step_s: [__m512i; 2],
    }

    #[inline(always)]
    unsafe fn bcast(x: &[u64; 3]) -> [__m512i; 3] {
        unsafe { core::array::from_fn(|l| _mm512_set1_epi64(x[l] as i64)) }
    }

    #[inline(always)]
    unsafe fn mults(r: &[__m512i; 3]) -> [__m512i; 2] {
        unsafe { [times20(r[1]), times20(r[2])] }
    }

    /// Builds the lane power vectors. Lane `L` holds block `j(L)` of a group
    /// and, in the chain holding the final group, owes `r^(8 − j)`:
    /// `r · Π r^(2^i)` over the set bits `i` of `7 − j`.
    #[inline(always)]
    unsafe fn setup(st: &imp::State) -> Pow {
        unsafe {
            let z = [_mm512_setzero_si512(); 3];
            let mut rp = st.r_pows();
            let one = [
                _mm512_set1_epi64(1),
                _mm512_setzero_si512(),
                _mm512_setzero_si512(),
            ];
            let pick = |mask: __mmask8, x: &[u64; 3]| -> [__m512i; 3] {
                let b = bcast(x);
                core::array::from_fn(|l| _mm512_mask_blend_epi64(mask, one[l], b[l]))
            };
            let x0 = pick(exp_mask(0), &rp[0]);
            let x1 = pick(exp_mask(1), &rp[1]);
            let x2 = pick(exp_mask(2), &rp[2]);
            let r1 = bcast(&rp[0]);
            let x01 = mul_add(&x0, &x1, &mults(&x1), &z);
            let x2r = mul_add(&x2, &r1, &mults(&r1), &z);
            let lo_pow = mul_add(&x01, &x2r, &mults(&x2r), &z);
            let r8 = bcast(&rp[3]);
            let r16 = bcast(&rp[4]);
            let p1 = mul_add(&lo_pow, &r8, &mults(&r8), &z);
            let p2 = mul_add(&lo_pow, &r16, &mults(&r16), &z);
            let p3 = mul_add(&p1, &r16, &mults(&r16), &z);
            let step = bcast(&rp[5]);
            let step_s = mults(&step);
            rp.zeroize();
            Pow {
                pw: [lo_pow, p1, p2, p3],
                step,
                step_s,
            }
        }
    }

    /// Starts the chains on the first `CHAINS` groups at `p` (fewer if
    /// `groups` is smaller; missing chains stay zero), with the running `h`
    /// joining lane 0 of chain 0 (block 0, the oldest).
    #[inline(always)]
    unsafe fn start(st: &imp::State, p: *const u8, groups: usize) -> [[__m512i; 3]; CHAINS] {
        unsafe {
            let mut acc = [[_mm512_setzero_si512(); 3]; CHAINS];
            for (c, x) in acc.iter_mut().enumerate() {
                if c < groups {
                    *x = load8(p.add(128 * c));
                }
            }
            let h = st.h44();
            for (x, &hl) in acc[0].iter_mut().zip(h.iter()) {
                *x = _mm512_add_epi64(*x, _mm512_set_epi64(0, 0, 0, 0, 0, 0, 0, hl as i64));
            }
            acc
        }
    }

    /// Advances chains `0..n` by one group each from `p` (chain `c` takes
    /// the group at `p + 128c`).
    #[inline(always)]
    unsafe fn step(acc: &mut [[__m512i; 3]; CHAINS], pow: &Pow, p: *const u8, n: usize) {
        unsafe {
            for (c, x) in acc.iter_mut().enumerate().take(n) {
                *x = mul_add(x, &pow.step, &pow.step_s, &load8(p.add(128 * c)));
            }
        }
    }

    /// Folds the chains after `groups` groups in total back into `st.h`:
    /// chain `c`'s last group is `(groups − 1 − c) mod CHAINS` groups before
    /// the final one (a chain with no groups is zero and its power is
    /// irrelevant), then every lane of every chain is summed — at most 32
    /// limbs below 2⁴⁴ + 2¹⁴, far from overflow.
    #[inline(always)]
    unsafe fn fold(st: &mut imp::State, pow: &Pow, acc: &[[__m512i; 3]; CHAINS], groups: usize) {
        unsafe {
            let z = [_mm512_setzero_si512(); 3];
            let mut tot = z;
            for (c, x) in acc.iter().enumerate() {
                let k = (groups + CHAINS - 1 - c) % CHAINS;
                let f = mul_add(x, &pow.pw[k], &mults(&pow.pw[k]), &z);
                for (t, v) in tot.iter_mut().zip(f.iter()) {
                    *t = _mm512_add_epi64(*t, *v);
                }
            }
            let sum: [u64; 3] = core::array::from_fn(|l| _mm512_reduce_add_epi64(tot[l]) as u64);
            st.set_h44(sum);
        }
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    unsafe fn blocks_ifma(st: &mut imp::State, data: &[u8]) {
        unsafe {
            let groups = data.len() / 128;
            let p = data.as_ptr();
            let pow = setup(st);
            let mut acc = start(st, p, groups);
            let mut g = CHAINS;
            while g + CHAINS <= groups {
                step(&mut acc, &pow, p.add(128 * g), CHAINS);
                g += CHAINS;
            }
            step(
                &mut acc,
                &pow,
                p.add(128 * g.min(groups)),
                groups.saturating_sub(g),
            );
            fold(st, &pow, &acc, groups);
        }
    }

    /// ChaCha20-Poly1305's stitched-loop handle: absorbs 128-byte groups
    /// one at a time (so the cipher can call it between its rounds) into
    /// the same four chains as [`blocks_ifma`], and folds them back into
    /// the state when finished. Its methods are `#[inline(always)]` and
    /// must only be called from code compiled with AVX-512F and AVX-512
    /// IFMA enabled, which [`Poly1305::stitch`](super::Poly1305) having
    /// returned it guarantees the CPU supports.
    pub(in crate::cipher) struct Stitch<'a> {
        st: &'a mut imp::State,
        pow: Option<Pow>,
        acc: [[__m512i; 3]; CHAINS],
        groups: usize,
    }

    impl<'a> Stitch<'a> {
        pub(super) fn new(st: &'a mut imp::State) -> Self {
            Stitch {
                st,
                pow: None,
                // SAFETY: `__m512i` is plain integer data, for which all-zero
                // bytes are a valid value.
                acc: unsafe { core::mem::zeroed() },
                groups: 0,
            }
        }

        /// Absorbs the 128 bytes at `p` as the next group.
        ///
        /// # Safety
        /// `p` must be valid for 128 bytes of reads; the caller must be
        /// compiled with AVX-512F and AVX-512 IFMA.
        #[inline(always)]
        pub(in crate::cipher) unsafe fn absorb(&mut self, p: *const u8) {
            unsafe {
                let g = self.groups;
                let c = g % CHAINS;
                if g < CHAINS {
                    if g == 0 {
                        self.pow = Some(setup(self.st));
                        self.acc = start(self.st, p, 1);
                    } else {
                        self.acc[c] = load8(p);
                    }
                } else {
                    let pow = self.pow.as_ref().expect("set up on the first group");
                    self.acc[c] = mul_add(&self.acc[c], &pow.step, &pow.step_s, &load8(p));
                }
                self.groups = g + 1;
            }
        }

        /// Folds the chains back into the Poly1305 state.
        ///
        /// # Safety
        /// The caller must be compiled with AVX-512F and AVX-512 IFMA.
        #[inline(always)]
        pub(in crate::cipher) unsafe fn finish(self) {
            unsafe {
                if let Some(pow) = &self.pow {
                    fold(self.st, pow, &self.acc, self.groups);
                }
            }
        }
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
/// large and chunked-streaming cases. The scalar state is radix 2⁴⁴ on this
/// target; `r` and `h` are converted to and from 26-bit limbs at the
/// kernel boundary.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod simd {
    use super::Poly1305;
    use core::arch::x86_64::*;

    /// Below this many bytes the scalar path wins (power precomputation and
    /// vector setup cost more than they save).
    pub(super) const MIN_LEN: usize = 256;

    const MASK26: u64 = 0x03ff_ffff;

    pub(super) fn supported() -> bool {
        !crate::ct::force_portable() && crate::cpu::avx2()
    }

    /// Absorbs `data` (a non-empty multiple of 128 bytes) into `st.h`.
    pub(super) fn blocks(st: &mut Poly1305, data: &[u8]) {
        debug_assert!(!data.is_empty() && data.len().is_multiple_of(128));
        // SAFETY: `supported()` (checked by the caller) confirmed AVX2.
        unsafe { blocks_avx2(st, data) }
    }

    /// Scalar `a·b mod 2¹³⁰−5` on 5×26-bit limbs (schoolbook + partial
    /// carry), used to precompute the powers of `r`. Output limbs are below
    /// `2²⁶ + 2⁹`.
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
            // Powers of the evaluation point: r¹..r⁸. Every one of these is
            // key-derived (r is half the Poly1305 one-time key), so they are
            // wiped at the end of the function alongside `sum`/`lanes`.
            let mut r1 = st.st.r26();
            let mut r2 = mul_mod(&r1, &r1);
            let mut r3 = mul_mod(&r2, &r1);
            let mut r4 = mul_mod(&r2, &r2);
            let mut r5 = mul_mod(&r4, &r1);
            let mut r6 = mul_mod(&r4, &r2);
            let mut r7 = mul_mod(&r4, &r3);
            let mut r8 = mul_mod(&r4, &r4);

            let times5 = |v| _mm256_add_epi64(v, _mm256_slli_epi64::<2>(v));

            // r⁸ broadcast to every lane, for the striped Horner loop.
            let rr: [__m256i; 5] = core::array::from_fn(|j| _mm256_set1_epi64x(r8[j] as i64));
            let ss: [__m256i; 4] = core::array::from_fn(|j| times5(rr[j + 1]));

            // Two independent accumulators, blocks 0..4 and 4..8 of each
            // 128-byte stripe; h_in joins lane 0 of the first (the stream of
            // the oldest block, whose exponent is the highest).
            let mut ha = load4(data);
            let mut hb = load4(&data[64..128]);
            let mut h_in = st.st.h26();
            for (a, &hin) in ha.iter_mut().zip(h_in.iter()) {
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

            // Carry back into lazy 26-bit limbs, then into the scalar state.
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
            st.st
                .set_h26([(h0 as u32) & 0x03ff_ffff, h1 + carry, h2, h3, h4]);
            // `sum` and `h_in` are accumulator state. This kernel runs once
            // per `update` of >= MIN_LEN bytes, so its scratch keeps the
            // cheap vector store plus `black_box` rather than per-limb
            // volatile stores (which would be a visible share of a 256-byte
            // update).
            sum = [0; 5];
            h_in = [0; 5];
            let _ = core::hint::black_box(&sum);
            let _ = core::hint::black_box(&h_in);

            // Best-effort wipe of the key-derived powers.
            for p in [
                &mut r1, &mut r2, &mut r3, &mut r4, &mut r5, &mut r6, &mut r7, &mut r8,
            ] {
                *p = [0u32; 5];
                let _ = core::hint::black_box(&*p);
            }
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

    /// Small deterministic PRNG for keys and data (not security relevant).
    #[cfg(feature = "alloc")]
    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    /// Independent reference: schoolbook Poly1305 over the crate's
    /// `Uint`-free arithmetic — `u128` limbs are not enough for 2¹³⁰, so
    /// this evaluates with a tiny 192-bit (three `u64`) big integer. Slow,
    /// but unrelated to any limb layout above.
    #[cfg(feature = "alloc")]
    fn reference_tag(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
        // 192-bit helpers: value = [lo, mid, hi], little-endian limbs.
        type W = [u64; 3];
        fn add(a: W, b: W) -> W {
            let (l, c0) = a[0].overflowing_add(b[0]);
            let (m, c1a) = a[1].overflowing_add(b[1]);
            let (m, c1b) = m.overflowing_add(u64::from(c0));
            let h = a[2]
                .wrapping_add(b[2])
                .wrapping_add(u64::from(c1a))
                .wrapping_add(u64::from(c1b));
            [l, m, h]
        }
        fn sub(a: W, b: W) -> W {
            let (l, b0) = a[0].overflowing_sub(b[0]);
            let (m, b1a) = a[1].overflowing_sub(b[1]);
            let (m, b1b) = m.overflowing_sub(u64::from(b0));
            let h = a[2]
                .wrapping_sub(b[2])
                .wrapping_sub(u64::from(b1a))
                .wrapping_sub(u64::from(b1b));
            [l, m, h]
        }
        fn ge(a: W, b: W) -> bool {
            a.iter().rev().cmp(b.iter().rev()) != core::cmp::Ordering::Less
        }
        fn shl1(a: W) -> W {
            [
                a[0] << 1,
                (a[1] << 1) | (a[0] >> 63),
                (a[2] << 1) | (a[1] >> 63),
            ]
        }
        // p = 2¹³⁰ − 5.
        let p: W = [u64::MAX - 4, u64::MAX, 3];
        // a · b mod p by double-and-add, both inputs below p.
        let mulmod = |a: W, b: W| -> W {
            let mut acc: W = [0; 3];
            for i in (0..130).rev() {
                acc = shl1(acc);
                if ge(acc, p) {
                    acc = sub(acc, p);
                }
                if (b[i / 64] >> (i % 64)) & 1 == 1 {
                    acc = add(acc, a);
                    if ge(acc, p) {
                        acc = sub(acc, p);
                    }
                }
            }
            acc
        };
        let r = u128::from_le_bytes(key[..16].try_into().unwrap())
            & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;
        let r: W = [r as u64, (r >> 64) as u64, 0];
        let mut h: W = [0; 3];
        for chunk in msg.chunks(16) {
            let mut block = [0u8; 17];
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()] = 1;
            let lo = u128::from_le_bytes(block[..16].try_into().unwrap());
            let m: W = [lo as u64, (lo >> 64) as u64, u64::from(block[16])];
            h = add(h, m);
            if ge(h, p) {
                h = sub(h, p);
            }
            h = mulmod(h, r);
        }
        let h = u128::from(h[0]) | (u128::from(h[1]) << 64);
        let s = u128::from_le_bytes(key[16..].try_into().unwrap());
        h.wrapping_add(s).to_le_bytes()
    }

    /// Every length in `0..=1024`, one-shot and under chunked streaming that
    /// straddles the leftover buffer, the two-stripe / vector paths and the
    /// single-block tail, must match the independent big-integer reference.
    /// This pins the radix-2⁴⁴ stripe folds and whichever vector kernel the
    /// dispatcher picks alike.
    #[cfg(feature = "alloc")]
    #[test]
    fn all_lengths_match_reference() {
        use alloc::vec::Vec;
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut data = Vec::new();
        for len in (0usize..=1024).chain([1500, 4096 + 17]) {
            let mut key = [0u8; 32];
            for b in key.iter_mut() {
                *b = xorshift(&mut state) as u8;
            }
            data.resize(len, 0);
            for b in data.iter_mut() {
                *b = xorshift(&mut state) as u8;
            }
            let expected = reference_tag(&key, &data);

            let mut p = Poly1305::new(&key);
            p.update(&data);
            assert_eq!(p.finish(), expected, "one-shot len={len}");

            // Odd-sized chunks, preceded by a tiny one so the leftover
            // buffer engages first; 48-byte chunks keep every run under the
            // two-stripe threshold on some calls and over it on others.
            let mut p = Poly1305::new(&key);
            let mut rest = &data[..];
            for chunk_len in [5usize, 301, 48, 48, 257] {
                let take = chunk_len.min(rest.len());
                p.update(&rest[..take]);
                rest = &rest[take..];
            }
            p.update(rest);
            assert_eq!(p.finish(), expected, "chunked len={len}");
        }
    }

    /// Each x86_64 vector tier, driven directly (so an IFMA host still tests
    /// the AVX2 kernel, which the dispatcher would never pick there), must
    /// produce the exact scalar tag for every length in `0..=1100`, for
    /// large messages and for extreme limbs, with the kernel entered both
    /// from a zero and from a non-zero accumulator. Then the dispatcher
    /// itself, under one-shot and odd-sized streaming updates that straddle
    /// the leftover buffer, the vector thresholds and the scalar tail.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn simd_matches_scalar() {
        use alloc::vec::Vec;
        let ifma = super::ifma::supported();
        let avx2 = super::simd::supported();
        for (name, on) in [("avx512-ifma 4x8-way", ifma), ("avx2 2x4-way", avx2)] {
            if on {
                std::eprintln!("poly1305: RUNNING {name} kernel vs scalar");
            } else {
                std::eprintln!("poly1305: SKIPPED {name} kernel (not supported here)");
            }
        }

        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut fill = |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                *b = xorshift(&mut state) as u8;
            }
        };

        // Scalar oracle: updates of under 128 bytes never reach a vector
        // kernel (every vector path needs at least one 128-byte group).
        let scalar_tag = |key: &[u8; 32], data: &[u8]| -> [u8; 16] {
            let mut p = Poly1305::new(key);
            for chunk in data.chunks(48) {
                p.update(chunk);
            }
            p.finish()
        };
        // `pre` bytes (a multiple of 16) through the scalar path, then the
        // largest multiple of 128 bytes through the chosen kernel, then the
        // rest through the scalar path again.
        let forced = |key: &[u8; 32], data: &[u8], pre: usize, tier: u8| -> [u8; 16] {
            let mut p = Poly1305::new(key);
            let pre = pre.min(data.len() & !15);
            p.update(&data[..pre]);
            let rest = &data[pre..];
            let vec_len = rest.len() & !127;
            if vec_len > 0 {
                match tier {
                    0 => super::ifma::blocks(&mut p.st, &rest[..vec_len]),
                    _ => super::simd::blocks(&mut p, &rest[..vec_len]),
                }
            }
            for chunk in rest[vec_len..].chunks(48) {
                p.update(chunk);
            }
            p.finish()
        };

        // Extreme limbs: the largest clamped `r` with all-ones data keeps
        // every lazy carry at its bound.
        for len in [384usize, 512, 1024 + 15, 4096 + 128, 65536] {
            let key = [0xffu8; 32];
            let data = std::vec![0xffu8; len];
            let expected = scalar_tag(&key, &data);
            assert_eq!(expected, reference_tag(&key, &data), "oracle len={len}");
            for pre in [0usize, 16] {
                if ifma {
                    assert_eq!(forced(&key, &data, pre, 0), expected, "ifma ff len={len}");
                }
                if avx2 {
                    assert_eq!(forced(&key, &data, pre, 1), expected, "avx2 ff len={len}");
                }
            }
        }

        let mut data = Vec::new();
        for len in (0usize..=1100).chain([2048 + 5, 4096, 16384 + 13, 65536 + 17, 100_003]) {
            let mut key = [0u8; 32];
            fill(&mut key);
            data.resize(len, 0);
            fill(&mut data);

            let expected = scalar_tag(&key, &data);

            for pre in [0usize, 16, 48] {
                if ifma {
                    assert_eq!(
                        forced(&key, &data, pre, 0),
                        expected,
                        "ifma len={len} pre={pre}"
                    );
                }
                if avx2 {
                    assert_eq!(
                        forced(&key, &data, pre, 1),
                        expected,
                        "avx2 len={len} pre={pre}"
                    );
                }
            }

            // One-shot through the dispatcher.
            let mut p = Poly1305::new(&key);
            p.update(&data);
            assert_eq!(p.finish(), expected, "one-shot len={len}");

            // Odd-sized chunks large enough to keep hitting the vector
            // paths, preceded by a tiny chunk so the leftover buffer engages
            // first.
            let mut p = Poly1305::new(&key);
            let mut rest = &data[..];
            for chunk_len in [5usize, 301, 4096 + 63, 257] {
                let take = chunk_len.min(rest.len());
                p.update(&rest[..take]);
                rest = &rest[take..];
            }
            p.update(rest);
            assert_eq!(p.finish(), expected, "chunked len={len}");

            // A cycle of odd chunk sizes either side of every threshold
            // (16-byte blocks, 128-byte groups, the 384-byte IFMA minimum).
            let mut p = Poly1305::new(&key);
            let mut rest = &data[..];
            for chunk_len in [1usize, 15, 17, 127, 129, 383, 385, 3, 1023].iter().cycle() {
                if rest.is_empty() {
                    break;
                }
                let take = (*chunk_len).min(rest.len());
                p.update(&rest[..take]);
                rest = &rest[take..];
            }
            assert_eq!(p.finish(), expected, "odd-chunked len={len}");
        }
    }

    /// RFC 8439 Appendix A.3 edge-case vectors. The §2.5.2 example above
    /// never reaches the interesting part of `finish`: these are the
    /// published probes for a partially reduced accumulator that is still
    /// above `p`, for the `+ s` addition overflowing 2¹²⁸, for a carry out of
    /// an all-ones limb, and for a polynomial result landing exactly on
    /// `2¹³⁰ − 5` / `2¹³⁰ − 6` (the constant-time `h − p` select).
    #[test]
    fn rfc8439_a3_edge_cases() {
        fn tag(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
            let mut p = Poly1305::new(key);
            p.update(msg);
            p.finish()
        }
        let r2 = from_hex::<16>("02000000000000000000000000000000");
        let r1 = from_hex::<16>("01000000000000000000000000000000");
        let ones = [0xffu8; 16];
        let mut key = [0u8; 32];

        // Test Vector #1: all-zero key and message → all-zero tag.
        assert_eq!(tag(&key, &[0u8; 64]), [0u8; 16]);

        // #5: r = 2, s = 0, one all-ones block. h = 2·(2¹²⁹ − 1) mod p = 3.
        key[..16].copy_from_slice(&r2);
        key[16..].fill(0);
        assert_eq!(
            tag(&key, &ones),
            from_hex::<16>("03000000000000000000000000000000")
        );

        // #6: r = 2, s = 2¹²⁸ − 1, message block 2: the `+ s` step overflows
        // 2¹²⁸ and must wrap.
        key[16..].copy_from_slice(&ones);
        assert_eq!(
            tag(&key, &r2),
            from_hex::<16>("03000000000000000000000000000000")
        );

        // #7: r = 1, s = 0, three blocks: an all-ones data limb with a carry
        // arriving from the limb below.
        key[..16].copy_from_slice(&r1);
        key[16..].fill(0);
        let msg7 = from_hex::<48>(
            "ffffffffffffffffffffffffffffffff\
             f0ffffffffffffffffffffffffffffff\
             11000000000000000000000000000000",
        );
        assert_eq!(
            tag(&key, &msg7),
            from_hex::<16>("05000000000000000000000000000000")
        );

        // #8: r = 1, s = 0: the polynomial result is exactly 2¹³⁰ − 5, which
        // must reduce to zero.
        let msg8 = from_hex::<48>(
            "ffffffffffffffffffffffffffffffff\
             fbfefefefefefefefefefefefefefefe\
             01010101010101010101010101010101",
        );
        assert_eq!(tag(&key, &msg8), [0u8; 16]);

        // #9: r = 2, s = 0: the polynomial result is exactly 2¹³⁰ − 6, one
        // below p, so the `h − p` candidate must be rejected.
        key[..16].copy_from_slice(&r2);
        assert_eq!(
            tag(&key, &from_hex::<16>("fdffffffffffffffffffffffffffffff")),
            from_hex::<16>("faffffffffffffffffffffffffffffff")
        );
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
