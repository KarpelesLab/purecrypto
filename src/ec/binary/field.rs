//! GF(2^m) polynomial-basis arithmetic for every binary-curve field
//! (113 ≤ m ≤ 571, trinomial or pentanomial reduction polynomial).
//!
//! An element is a polynomial over GF(2) of degree < m, stored as
//! little-endian `u64` limbs ([`Fe`]); a [`Field`] carries the public
//! parameters (m, the number of limbs in use and the middle exponents of the
//! reduction polynomial), so one code path serves every field: each loop
//! runs over the limbs in use. Every operation is branch-free in the element
//! data: multiplication is a schoolbook product of 64×64 carry-less
//! multiplications — the PMULL / PCLMULQDQ instruction where the CPU has it,
//! otherwise a bit-sliced integer-multiply emulation (no lookup tables
//! indexed by secret data) — squaring spreads bits with masks, reduction
//! folds words with shifts by public constants, and inversion is
//! Itoh–Tsujii with an addition chain fixed by the (public) field degree.

use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::zeroize::Zeroize;

/// Limbs of the widest field (571 bits → 9 × 64).
pub(super) const MAX_LIMBS: usize = 9;

/// Little-endian limb array wide enough for every supported field.
pub(super) type Limbs = [u64; MAX_LIMBS];

/// A field element (polynomial of degree < m, little-endian limbs).
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Fe(pub(super) Limbs);

impl Fe {
    /// The additive identity.
    pub(super) const ZERO: Fe = Fe([0; MAX_LIMBS]);
    /// The multiplicative identity.
    pub(super) const ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// Builds an element from a big-endian hex constant (at most
    /// `16 * MAX_LIMBS` digits; callers pass curve constants only).
    pub(super) const fn from_hex(hex: &str) -> Fe {
        Fe(limbs_from_hex(hex))
    }

    /// `self + other` (bitwise XOR).
    #[inline]
    pub(super) fn add(&self, other: &Fe) -> Fe {
        let mut out = *self;
        let mut i = 0;
        while i < MAX_LIMBS {
            out.0[i] ^= other.0[i];
            i += 1;
        }
        out
    }

    /// Whether the element is zero, in constant time.
    #[inline]
    pub(super) fn is_zero(&self) -> Choice {
        self.0.ct_eq(&[0; MAX_LIMBS])
    }

    /// The constant term (the "rightmost bit" of SEC 1 §2.3.4).
    #[inline]
    pub(super) fn lsb(&self) -> Choice {
        Choice::from((self.0[0] & 1) as u8)
    }
}

impl ConstantTimeEq for Fe {
    #[inline]
    fn ct_eq(&self, other: &Fe) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Fe {
    #[inline]
    fn conditional_select(a: &Fe, b: &Fe, choice: Choice) -> Fe {
        Fe(<Limbs>::conditional_select(&a.0, &b.0, choice))
    }
}

impl Zeroize for Fe {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Parses a big-endian hex constant into little-endian limbs. Only used on
/// hard-coded curve constants, so a malformed digit decodes as zero.
pub(super) const fn limbs_from_hex(hex: &str) -> Limbs {
    const fn nibble(c: u8) -> u64 {
        match c {
            b'0'..=b'9' => (c - b'0') as u64,
            b'a'..=b'f' => (c - b'a' + 10) as u64,
            b'A'..=b'F' => (c - b'A' + 10) as u64,
            _ => 0,
        }
    }
    let h = hex.as_bytes();
    assert!(h.len() <= 16 * MAX_LIMBS, "hex constant too wide");
    let mut out = [0u64; MAX_LIMBS];
    let mut i = 0;
    // Digit `h[len - 1 - i]` is nibble `i` of the little-endian value.
    while i < h.len() {
        let v = nibble(h[h.len() - 1 - i]);
        out[i / 16] |= v << (4 * (i % 16));
        i += 1;
    }
    out
}

/// The low 64 bits of the carry-less product `x · y` over GF(2)[X], from
/// integer multiplications (BearSSL's `bmul64`): each operand is split
/// into four words holding every fourth bit, so that in each of the sixteen
/// integer products a column receives at most 16 partial products — few
/// enough that carries never reach the bit of the next column kept by the
/// final masks (the one 16-term column overflows past bit 63, which is
/// discarded). Constant time wherever the integer multiplier is, which the
/// rest of the crate's field arithmetic already assumes.
#[inline]
fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = 0x2222_2222_2222_2222;
    const M2: u64 = 0x4444_4444_4444_4444;
    const M3: u64 = 0x8888_8888_8888_8888;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let z0 = x0.wrapping_mul(y0) ^ x1.wrapping_mul(y3) ^ x2.wrapping_mul(y2) ^ x3.wrapping_mul(y1);
    let z1 = x0.wrapping_mul(y1) ^ x1.wrapping_mul(y0) ^ x2.wrapping_mul(y3) ^ x3.wrapping_mul(y2);
    let z2 = x0.wrapping_mul(y2) ^ x1.wrapping_mul(y1) ^ x2.wrapping_mul(y0) ^ x3.wrapping_mul(y3);
    let z3 = x0.wrapping_mul(y3) ^ x1.wrapping_mul(y2) ^ x2.wrapping_mul(y1) ^ x3.wrapping_mul(y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// Software 64×64 → 128 carry-less multiplication `(lo, hi)`, constant
/// time: the low word from [`bmul64`], the high word from the same product
/// on the bit-reversed operands (`clmul(rev x, rev y)` is the degree-126
/// product reversed, so its low word, reversed and shifted down one bit, is
/// the top word of `x · y`).
#[inline]
fn clmul64_soft(a: u64, b: u64) -> (u64, u64) {
    let lo = bmul64(a, b);
    let hi = bmul64(a.reverse_bits(), b.reverse_bits()).reverse_bits() >> 1;
    (lo, hi)
}

/// The carry-less multiply instructions (PMULL on aarch64, PCLMULQDQ on
/// x86_64), when the build can detect them. The detection honours the
/// constant-time harness's `force_portable` switch, so the software kernel
/// is exercised under memcheck too.
#[cfg(all(
    feature = "cipher",
    feature = "std",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod hw {
    #![allow(unsafe_code)]
    use super::{Fe, MAX_LIMBS};
    use crate::cipher::clmul;

    #[inline]
    pub(super) fn supported() -> bool {
        clmul::supported()
    }

    /// XORs the unreduced product of the low `l` limbs of `a` and `b` into
    /// `c`. The caller has checked [`supported`].
    #[cfg_attr(target_arch = "aarch64", target_feature(enable = "aes,neon"))]
    #[cfg_attr(target_arch = "x86_64", target_feature(enable = "pclmulqdq,sse2"))]
    pub(super) unsafe fn mul_into(l: usize, a: &Fe, b: &Fe, c: &mut [u64; 2 * MAX_LIMBS]) {
        for i in 0..l {
            for j in 0..l {
                // SAFETY: the caller established the target feature.
                let p = unsafe { clmul::clmul64(a.0[i], b.0[j]) };
                c[i + j] ^= p as u64;
                c[i + j + 1] ^= (p >> 64) as u64;
            }
        }
    }
}

/// Interleaves a zero bit after every bit of `x` (the squaring map on one
/// 32-bit half-word).
#[inline]
fn spread(x: u32) -> u64 {
    let mut x = x as u64;
    x = (x | (x << 16)) & 0x0000_FFFF_0000_FFFF;
    x = (x | (x << 8)) & 0x00FF_00FF_00FF_00FF;
    x = (x | (x << 4)) & 0x0F0F_0F0F_0F0F_0F0F;
    x = (x | (x << 2)) & 0x3333_3333_3333_3333;
    x = (x | (x << 1)) & 0x5555_5555_5555_5555;
    x
}

/// The public parameters of one GF(2^m): the degree, the limbs in use and
/// the middle exponents of the reduction polynomial `x^m + Σ x^e + 1`.
#[derive(Clone, Copy, Debug)]
pub(super) struct Field {
    /// Extension degree `m` (even for five X9.62 fields).
    pub(super) m: usize,
    /// Limbs actually used (`ceil(m / 64)`); the rest stay zero.
    pub(super) limbs: usize,
    /// Middle exponents of the reduction polynomial (excluding `m` and 0).
    pub(super) mid: &'static [usize],
}

impl Field {
    /// The field `GF(2)[x] / (x^m + Σ_{e ∈ mid} x^e + 1)` (a trinomial or
    /// pentanomial basis). The reduction in [`reduce`](Self::reduce) folds
    /// one 64-bit word at a time, which needs every middle exponent below
    /// `m − 63` and `m` not a multiple of 64 — true of every SEC 2 / X9.62 /
    /// WTLS polynomial, and checked at compile time for each constant.
    pub(super) const fn new(m: usize, mid: &'static [usize]) -> Field {
        assert!(!m.is_multiple_of(64) && m <= 64 * MAX_LIMBS);
        let mut i = 0;
        while i < mid.len() {
            assert!(mid[i] > 0 && mid[i] + 63 < m);
            i += 1;
        }
        Field {
            m,
            limbs: m.div_ceil(64),
            mid,
        }
    }
}

impl Field {
    /// Bytes of the fixed-width big-endian encoding (`ceil(m / 8)`).
    #[inline]
    pub(super) const fn byte_len(&self) -> usize {
        self.m.div_ceil(8)
    }

    /// Bits of the ladder / scalar width (`64 * limbs`).
    #[inline]
    pub(super) const fn bit_width(&self) -> usize {
        64 * self.limbs
    }

    /// XORs `t · x^p` into the polynomial `c` (`p` is a public constant).
    #[inline]
    fn xor_shifted(c: &mut [u64; 2 * MAX_LIMBS], t: u64, p: usize) {
        let (w, s) = (p / 64, p % 64);
        c[w] ^= t << s;
        if s != 0 {
            c[w + 1] ^= t >> (64 - s);
        }
    }

    /// Reduces a product of degree < 2m modulo the field polynomial.
    ///
    /// Words above the one holding bit `m` are folded down one at a time
    /// (`x^{64 i} ≡ x^{64 i − m} · (1 + Σ x^e)`), then the bits at and above
    /// `m` in that top word are folded once more. Every shift amount is a
    /// function of the public parameters only.
    fn reduce(&self, c: &mut [u64; 2 * MAX_LIMBS]) -> Fe {
        let top = self.m / 64;
        let mut i = 2 * self.limbs;
        while i > top + 1 {
            i -= 1;
            let t = c[i];
            c[i] = 0;
            let base = 64 * i - self.m;
            Self::xor_shifted(c, t, base);
            for &e in self.mid {
                Self::xor_shifted(c, t, base + e);
            }
        }
        // Bits `m ..` of the top word, i.e. `x^m · t ≡ (1 + Σ x^e) · t`.
        let s = self.m % 64;
        let t = c[top] >> s;
        c[top] &= (1u64 << s) - 1;
        Self::xor_shifted(c, t, 0);
        for &e in self.mid {
            Self::xor_shifted(c, t, e);
        }
        let mut out = Fe::ZERO;
        out.0[..self.limbs].copy_from_slice(&c[..self.limbs]);
        out
    }

    /// `a · b`.
    pub(super) fn mul(&self, a: &Fe, b: &Fe) -> Fe {
        let mut c = [0u64; 2 * MAX_LIMBS];
        #[cfg(all(
            feature = "cipher",
            feature = "std",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if hw::supported() {
            // SAFETY: `hw::supported` detected the carry-less multiply
            // instructions on this CPU.
            #[allow(unsafe_code)]
            unsafe {
                hw::mul_into(self.limbs, a, b, &mut c)
            };
            return self.reduce(&mut c);
        }
        self.mul_soft_into(a, b, &mut c);
        self.reduce(&mut c)
    }

    /// The unreduced schoolbook product on the software carry-less
    /// multiply, XORed into `c`.
    fn mul_soft_into(&self, a: &Fe, b: &Fe, c: &mut [u64; 2 * MAX_LIMBS]) {
        let l = self.limbs;
        for i in 0..l {
            for j in 0..l {
                let (lo, hi) = clmul64_soft(a.0[i], b.0[j]);
                c[i + j] ^= lo;
                c[i + j + 1] ^= hi;
            }
        }
    }

    /// `a²` (the Frobenius map: bit spreading plus one reduction).
    pub(super) fn sqr(&self, a: &Fe) -> Fe {
        let mut c = [0u64; 2 * MAX_LIMBS];
        for i in 0..self.limbs {
            c[2 * i] = spread(a.0[i] as u32);
            c[2 * i + 1] = spread((a.0[i] >> 32) as u32);
        }
        self.reduce(&mut c)
    }

    /// `a^(2^k)`: `k` squarings.
    fn sqr_n(&self, a: &Fe, k: usize) -> Fe {
        let mut r = *a;
        for _ in 0..k {
            r = self.sqr(&r);
        }
        r
    }

    /// `a⁻¹` by Itoh–Tsujii (`a^(2^m − 2)`), with `0 ↦ 0`.
    ///
    /// `a^(2^(m−1) − 1)` is built with the binary addition chain of the
    /// public exponent `m − 1`: from `β_k = a^(2^k − 1)`, `β_{2k} = β_k^(2^k) ·
    /// β_k` and `β_{k+1} = β_k² · a`. That is `m − 1` squarings and
    /// `⌊log₂(m − 1)⌋ + popcount(m − 1) − 1` multiplications (11 for m = 283
    /// and 409, 13 for m = 571); a final squaring gives `a^(2^m − 2)`.
    pub(super) fn inv(&self, a: &Fe) -> Fe {
        let e = self.m - 1;
        let bits = usize::BITS - e.leading_zeros();
        let mut r = *a; // a^(2^k − 1)
        let mut k = 1usize;
        for i in (0..bits - 1).rev() {
            r = self.mul(&self.sqr_n(&r, k), &r);
            k *= 2;
            if (e >> i) & 1 == 1 {
                r = self.mul(&self.sqr(&r), a);
                k += 1;
            }
        }
        debug_assert_eq!(k, e);
        self.sqr(&r)
    }

    /// The absolute trace `Tr(a) = Σ_{i<m} a^(2^i) ∈ {0, 1}`.
    pub(super) fn trace(&self, a: &Fe) -> Choice {
        let mut acc = *a;
        let mut t = *a;
        for _ in 1..self.m {
            t = self.sqr(&t);
            acc = acc.add(&t);
        }
        debug_assert!(bool::from(acc.ct_eq(&Fe::ZERO) | acc.ct_eq(&Fe::ONE)));
        acc.lsb()
    }

    /// The half-trace `H(a) = Σ_{i ≤ (m−1)/2} a^(2^(2i))` (m odd), which
    /// solves `z² + z = a` whenever `Tr(a) = 0`.
    fn half_trace(&self, a: &Fe) -> Fe {
        let mut acc = *a;
        let mut t = *a;
        for _ in 0..(self.m - 1) / 2 {
            t = self.sqr(&self.sqr(&t));
            acc = acc.add(&t);
        }
        acc
    }

    /// The first monomial `x^i` of trace 1 — a public constant of the
    /// field, which the even-degree quadratic solver needs. (`Tr(1) = m mod
    /// 2`, so for odd `m` this is `1`; an even-degree field always has
    /// some `x^i` of trace 1, as the trace is a nonzero linear form.)
    fn trace_one_monomial(&self) -> Fe {
        for i in 0..self.m {
            let mut t = Fe::ZERO;
            t.0[i / 64] = 1 << (i % 64);
            // Public: a function of the field polynomial alone.
            if bool::from(self.trace(&t)) {
                return t;
            }
        }
        unreachable!("the trace form is nonzero")
    }

    /// Solves `z² + z = c` in constant time: the value is a root and the flag
    /// is `Tr(c) = 0`, i.e. whether a root exists (`z + 1` is the other).
    ///
    /// Odd `m`: the half-trace `H(c)`. Even `m` (the X9.62 c2pnb176/208/272/
    /// 304/368 fields): IEEE 1363 A.4.7 with a fixed `τ` of trace 1 —
    /// `z ← z² + w²·τ`, `w ← w² + c`, `m − 1` times from `z = 0`, `w = c`
    /// — whose result is a root whenever one exists.
    pub(super) fn solve_quadratic(&self, c: &Fe) -> (Fe, Choice) {
        let ok = !self.trace(c);
        if self.m % 2 == 1 {
            return (self.half_trace(c), ok);
        }
        let tau = self.trace_one_monomial();
        let mut z = Fe::ZERO;
        let mut w = *c;
        for _ in 1..self.m {
            let w2 = self.sqr(&w);
            z = self.sqr(&z).add(&self.mul(&w2, &tau));
            w = w2.add(c);
        }
        (z, ok)
    }

    /// `√a = a^(2^(m−1))` (squaring is a bijection in characteristic 2).
    pub(super) fn sqrt(&self, a: &Fe) -> Fe {
        self.sqr_n(a, self.m - 1)
    }

    /// Decodes a fixed-width big-endian element; `None` when the length is
    /// wrong or the value has bits at or above `m`.
    pub(super) fn decode_be(&self, bytes: &[u8]) -> Option<Fe> {
        if bytes.len() != self.byte_len() {
            return None;
        }
        let mut out = Fe::ZERO;
        for (i, &b) in bytes.iter().rev().enumerate() {
            out.0[i / 8] |= (b as u64) << (8 * (i % 8));
        }
        // Everything at or above bit m must be clear: the top used limb
        // above `m % 64`, and the unused limbs (the length check already
        // bounds those, but keep the test uniform).
        let s = self.m % 64;
        let mut high = out.0[self.m / 64] >> s;
        for &l in &out.0[self.limbs..] {
            high |= l;
        }
        (high == 0).then_some(out)
    }

    /// Writes the fixed-width big-endian encoding into `out`
    /// (`out.len() == byte_len()`).
    pub(super) fn encode_be(&self, a: &Fe, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.byte_len());
        for (i, b) in out.iter_mut().rev().enumerate() {
            *b = (a.0[i / 8] >> (8 * (i % 8))) as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every distinct field of the supported curves.
    const FIELDS: [Field; 19] = [
        Field::new(113, &[9]),
        Field::new(131, &[2, 3, 8]),
        Field::new(163, &[3, 6, 7]),
        Field::new(163, &[1, 2, 8]),
        Field::new(176, &[1, 2, 43]),
        Field::new(191, &[9]),
        Field::new(193, &[15]),
        Field::new(208, &[1, 2, 83]),
        Field::new(233, &[74]),
        Field::new(239, &[36]),
        Field::new(239, &[158]),
        Field::new(272, &[1, 3, 56]),
        Field::new(283, &[5, 7, 12]),
        Field::new(304, &[1, 2, 11]),
        Field::new(359, &[68]),
        Field::new(368, &[1, 2, 85]),
        Field::new(409, &[87]),
        Field::new(431, &[120]),
        Field::new(571, &[2, 5, 10]),
    ];

    /// A deterministic pseudo-random element (xorshift), reduced to `m` bits.
    fn sample(f: &Field, seed: &mut u64) -> Fe {
        let mut out = Fe::ZERO;
        for l in out.0[..f.limbs].iter_mut() {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *l = *seed;
        }
        let s = f.m % 64;
        out.0[f.m / 64] &= (1u64 << s) - 1;
        out
    }

    /// Reference multiplication: shift-and-add with bit-level reduction.
    fn mul_ref(f: &Field, a: &Fe, b: &Fe) -> Fe {
        let mut acc = [0u64; 2 * MAX_LIMBS];
        for i in 0..64 * f.limbs {
            if (b.0[i / 64] >> (i % 64)) & 1 == 1 {
                for j in 0..f.limbs {
                    let (w, s) = ((i + 64 * j) / 64, i % 64);
                    acc[w] ^= a.0[j] << s;
                    if s != 0 {
                        acc[w + 1] ^= a.0[j] >> (64 - s);
                    }
                }
            }
        }
        // Reduce bit by bit from the top.
        for bit in (f.m..2 * f.m).rev() {
            if (acc[bit / 64] >> (bit % 64)) & 1 == 1 {
                acc[bit / 64] ^= 1 << (bit % 64);
                let base = bit - f.m;
                for e in core::iter::once(&0).chain(f.mid) {
                    let p = base + e;
                    acc[p / 64] ^= 1 << (p % 64);
                }
            }
        }
        let mut out = Fe::ZERO;
        out.0[..f.limbs].copy_from_slice(&acc[..f.limbs]);
        out
    }

    /// The bit-sliced software carry-less multiply against a bit-serial
    /// reference, on structured and random operands (both words).
    #[test]
    fn clmul64_soft_matches_bit_serial() {
        fn reference(a: u64, b: u64) -> (u64, u64) {
            let mut r = 0u128;
            for i in 0..64 {
                if (b >> i) & 1 == 1 {
                    r ^= (a as u128) << i;
                }
            }
            (r as u64, (r >> 64) as u64)
        }
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut cases = alloc::vec![
            (0, 0),
            (1, 1),
            (u64::MAX, u64::MAX),
            (u64::MAX, 1 << 63),
            (0x8000_0000_0000_0001, 0xffff_ffff_ffff_ffff),
            (0x1111_1111_1111_1111, 0x1111_1111_1111_1111),
            (0xffff_ffff_0000_0000, 0x0000_0000_ffff_ffff),
        ];
        for _ in 0..2000 {
            cases.push((next(), next()));
        }
        for (a, b) in cases {
            assert_eq!(clmul64_soft(a, b), reference(a, b), "{a:#x} * {b:#x}");
        }
    }

    /// The software product path agrees with whatever `mul` dispatches to
    /// (the hardware instruction where detected).
    #[test]
    fn mul_soft_matches_dispatch() {
        let mut seed = 0x6A09_E667_F3BC_C908u64;
        for f in &FIELDS {
            for _ in 0..16 {
                let a = sample(f, &mut seed);
                let b = sample(f, &mut seed);
                let mut c = [0u64; 2 * MAX_LIMBS];
                f.mul_soft_into(&a, &b, &mut c);
                assert_eq!(f.reduce(&mut c).0, f.mul(&a, &b).0, "m={}", f.m);
            }
        }
    }

    #[test]
    fn mul_matches_reference_and_square() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for f in &FIELDS {
            for _ in 0..8 {
                let a = sample(f, &mut seed);
                let b = sample(f, &mut seed);
                let ab = f.mul(&a, &b);
                assert_eq!(ab.0, mul_ref(f, &a, &b).0, "mul m={}", f.m);
                assert_eq!(ab.0, f.mul(&b, &a).0, "commutativity m={}", f.m);
                assert_eq!(f.sqr(&a).0, f.mul(&a, &a).0, "square m={}", f.m);
                assert_eq!(f.mul(&a, &Fe::ONE).0, a.0);
                // The result must be fully reduced.
                assert!(f.decode_be(&be(f, &ab)).is_some());
            }
        }
    }

    fn be(f: &Field, a: &Fe) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec![0u8; f.byte_len()];
        f.encode_be(a, &mut v);
        v
    }

    #[test]
    fn inverse_and_sqrt() {
        let mut seed = 0xD1B5_4A32_D192_ED03u64;
        for f in &FIELDS {
            for _ in 0..3 {
                let a = sample(f, &mut seed);
                let inv = f.inv(&a);
                assert_eq!(f.mul(&a, &inv).0, Fe::ONE.0, "a·a⁻¹ m={}", f.m);
                let r = f.sqrt(&a);
                assert_eq!(f.sqr(&r).0, a.0, "sqrt m={}", f.m);
            }
            assert_eq!(f.inv(&Fe::ZERO).0, Fe::ZERO.0);
            assert_eq!(f.inv(&Fe::ONE).0, Fe::ONE.0);
        }
    }

    #[test]
    fn trace_and_half_trace() {
        let mut seed = 0x1234_5678_9ABC_DEF1u64;
        for f in &FIELDS {
            // Tr(1) = m mod 2.
            assert_eq!(bool::from(f.trace(&Fe::ONE)), f.m % 2 == 1);
            assert!(!bool::from(f.trace(&Fe::ZERO)));
            let mut solved = 0;
            for _ in 0..24 {
                let c = sample(f, &mut seed);
                let (z, ok) = f.solve_quadratic(&c);
                let has = bool::from(ok);
                // H(c) is a root exactly when Tr(c) = 0.
                assert_eq!(f.sqr(&z).add(&z).ct_eq(&c).unwrap_u8() == 1, has);
                if has {
                    solved += 1;
                    assert_eq!(f.sqr(&z).add(&z).0, c.0);
                    // z + 1 is the other root and has the opposite LSB.
                    let z1 = z.add(&Fe::ONE);
                    assert_eq!(f.sqr(&z1).add(&z1).0, c.0);
                    assert_ne!(bool::from(z.lsb()), bool::from(z1.lsb()));
                }
            }
            assert!(solved > 0);
        }
    }

    #[test]
    fn byte_round_trip_and_range() {
        for f in &FIELDS {
            let mut seed = 0x5555_AAAA_5555_AAAAu64;
            let a = sample(f, &mut seed);
            let v = be(f, &a);
            assert_eq!(v.len(), f.byte_len());
            assert_eq!(f.decode_be(&v).unwrap().0, a.0);
            // 2^m (bit m set) is out of range — unless m is a multiple of
            // 8, where the encoding has no room for it; one byte short is
            // rejected.
            let top = f.byte_len() * 8 - f.m;
            if top != 0 {
                let mut big = alloc::vec![0u8; f.byte_len()];
                big[0] = 1 << (8 - top);
                assert!(f.decode_be(&big).is_none());
            }
            assert!(f.decode_be(&v[1..]).is_none());
        }
    }

    #[test]
    fn hex_constant_parsing() {
        assert_eq!(limbs_from_hex("1")[0], 1);
        let l = limbs_from_hex("0123456789abcdef0011223344556677");
        assert_eq!(l[0], 0x0011_2233_4455_6677);
        assert_eq!(l[1], 0x0123_4567_89ab_cdef);
        assert_eq!(l[2], 0);
    }
}
