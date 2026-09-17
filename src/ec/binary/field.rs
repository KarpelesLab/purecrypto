//! GF(2^m) polynomial-basis arithmetic for m ∈ {283, 409, 571}.
//!
//! An element is a polynomial over GF(2) of degree < m, stored as
//! little-endian `u64` limbs ([`Fe`]); a [`Field`] carries the public
//! parameters (m, the number of limbs in use and the middle exponents of the
//! SEC 2 reduction polynomial). Every operation is branch-free in the element
//! data: multiplication is a schoolbook product of bit-serial, mask-driven
//! 64×64 carry-less multiplications (no lookup tables indexed by secret
//! data), squaring spreads bits with masks, reduction folds words with
//! shifts by public constants, and inversion is Itoh–Tsujii with an addition
//! chain fixed by the (public) field degree.

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

/// Bit-serial 64×64 → 128 carry-less multiplication. Each of the 64 steps
/// masks `a << i` with the (all-ones or all-zeros) mask derived from bit `i`
/// of `b`; shift amounts are loop constants, so the running time does not
/// depend on either operand.
#[inline]
fn clmul64(a: u64, b: u64) -> (u64, u64) {
    let a = a as u128;
    let mut r = 0u128;
    let mut i = 0;
    while i < 64 {
        let mask = core::hint::black_box((((b >> i) & 1) as u128).wrapping_neg());
        r ^= (a << i) & mask;
        i += 1;
    }
    (r as u64, (r >> 64) as u64)
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
    /// Extension degree `m` (odd for every SEC 2 binary curve).
    pub(super) m: usize,
    /// Limbs actually used (`ceil(m / 64)`); the rest stay zero.
    pub(super) limbs: usize,
    /// Middle exponents of the reduction polynomial (excluding `m` and 0).
    pub(super) mid: &'static [usize],
}

/// GF(2^283) with `x^283 + x^12 + x^7 + x^5 + 1`.
pub(super) const F283: Field = Field {
    m: 283,
    limbs: 5,
    mid: &[5, 7, 12],
};

/// GF(2^409) with `x^409 + x^87 + 1`.
pub(super) const F409: Field = Field {
    m: 409,
    limbs: 7,
    mid: &[87],
};

/// GF(2^571) with `x^571 + x^10 + x^5 + x^2 + 1`.
pub(super) const F571: Field = Field {
    m: 571,
    limbs: 9,
    mid: &[2, 5, 10],
};

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
        let l = self.limbs;
        let mut c = [0u64; 2 * MAX_LIMBS];
        for i in 0..l {
            for j in 0..l {
                let (lo, hi) = clmul64(a.0[i], b.0[j]);
                c[i + j] ^= lo;
                c[i + j + 1] ^= hi;
            }
        }
        self.reduce(&mut c)
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
    pub(super) fn half_trace(&self, a: &Fe) -> Fe {
        let mut acc = *a;
        let mut t = *a;
        for _ in 0..(self.m - 1) / 2 {
            t = self.sqr(&self.sqr(&t));
            acc = acc.add(&t);
        }
        acc
    }

    /// Solves `z² + z = c` in constant time: the value is `H(c)` and the flag
    /// is `Tr(c) = 0`, i.e. whether a solution exists (`z + 1` is the other).
    pub(super) fn solve_quadratic(&self, c: &Fe) -> (Fe, Choice) {
        (self.half_trace(c), !self.trace(c))
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

    const FIELDS: [Field; 3] = [F283, F409, F571];

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
            // Tr(1) = m mod 2 = 1 for every odd m.
            assert!(bool::from(f.trace(&Fe::ONE)));
            assert!(!bool::from(f.trace(&Fe::ZERO)));
            let mut solved = 0;
            for _ in 0..6 {
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
            // 2^m (bit m set) is out of range; one byte short is rejected.
            let mut big = alloc::vec![0u8; f.byte_len()];
            let top = f.byte_len() * 8 - f.m;
            big[0] = 1 << (8 - top);
            assert!(f.decode_be(&big).is_none());
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
