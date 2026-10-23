//! Projective short-Weierstrass arithmetic shared by `G1` (over `Fp`) and
//! `G2` (over `Fp2`), plus the EIP-196/197 and gnark-crypto encodings.
//!
//! Both curves are `y² = x³ + b` (`a = 0`). `E(Fp)` has prime order `r` and
//! the twist `E'(Fp2)` has order `r·(2p − r)` with `2p − r` odd, so neither
//! has a point of order two and the Renes–Costello–Batina **complete**
//! formulas for `j = 0` curves (Algorithms 7 and 9 of
//! <https://eprint.iacr.org/2015/1060>) are correct for every input pair —
//! identity, doubling and inverses included — without a single branch, on
//! the whole curve and not just the prime-order subgroup (cofactor clearing
//! in hash-to-curve runs on arbitrary twist points). `tools/bn254/consts.py`
//! checks both group orders.
//!
//! Scalar multiplication by a secret splits the scalar along the curve's
//! endomorphism (GLV on `G1`, four-dimensional GLS on `G2`) by a
//! fixed-point Babai round-off ([`babai_decompose`]) and runs simultaneous
//! fixed windows with every table entry fetched by a masked pass over the
//! whole table. The sub-scalars are signed; their signs are applied by
//! masked point negation. Neither the schedule nor the memory access
//! pattern depends on the scalar.

use super::Error;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crate::pairing_common::mont;
use crate::zeroize::Zeroize;

/// The field operations the curve code needs, implemented by `Fp` and `Fp2`.
pub(crate) trait CurveField:
    Copy + Default + ConditionallySelectable + ConstantTimeEq + Zeroize + core::fmt::Debug
{
    /// Additive identity.
    const ZERO: Self;
    /// Multiplicative identity.
    const ONE: Self;
    /// The curve coefficient `b`.
    const B: Self;
    /// Byte length of one encoded coordinate.
    const ENCODED_LEN: usize;
    /// `3·b·self`.
    fn mul_by_b3(&self) -> Self;
    /// `self |= mask & other` limb by limb — the masked-gather primitive
    /// (`mask` is all-ones or all-zeros).
    fn or_masked(&mut self, other: &Self, mask: u64);

    fn add(&self, rhs: &Self) -> Self;
    fn sub(&self, rhs: &Self) -> Self;
    fn mul(&self, rhs: &Self) -> Self;
    fn square(&self) -> Self;
    fn neg(&self) -> Self;
    fn is_zero(&self) -> Choice;
    fn invert(&self) -> CtOption<Self>;
    fn sqrt(&self) -> CtOption<Self>;
    /// The gnark-crypto "y is the larger of ±y" flag.
    fn lexicographically_largest(&self) -> Choice;
    /// Writes the canonical big-endian encoding (`ENCODED_LEN` bytes).
    fn write_be(&self, out: &mut [u8]);
    /// Reads the canonical big-endian encoding (`ENCODED_LEN` bytes), none
    /// when a coordinate is `>= p`.
    fn read_be(bytes: &[u8]) -> CtOption<Self>;
}

/// A point `(X : Y : Z)` with `x = X/Z`, `y = Y/Z`; `Z = 0` is the identity.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Projective<F> {
    pub(crate) x: F,
    pub(crate) y: F,
    pub(crate) z: F,
}

/// gnark-crypto compressed-point flags (top two bits of the first byte):
/// `10` compressed with the smaller `y`, `11` with the larger, `01` the
/// identity. `00` is gnark's uncompressed marker and is rejected by the
/// fixed-length compressed decoders.
const FLAG_MASK: u8 = 0xc0;
const FLAG_SMALLEST: u8 = 0x80;
const FLAG_LARGEST: u8 = 0xc0;
const FLAG_INFINITY: u8 = 0x40;

impl<F: CurveField> Projective<F> {
    /// The identity `(0 : 1 : 0)`.
    pub(crate) const IDENTITY: Self = Projective {
        x: F::ZERO,
        y: F::ONE,
        z: F::ZERO,
    };

    /// Lifts affine coordinates (no validation).
    #[inline]
    pub(crate) fn from_affine(x: F, y: F) -> Self {
        Projective { x, y, z: F::ONE }
    }

    /// Constant-time identity test.
    #[inline]
    pub(crate) fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Whether `Y²Z = X³ + bZ³` holds (true for the identity).
    pub(crate) fn is_on_curve(&self) -> Choice {
        let lhs = self.y.square().mul(&self.z);
        let z2 = self.z.square();
        let rhs = self
            .x
            .square()
            .mul(&self.x)
            .add(&F::B.mul(&z2).mul(&self.z));
        // (0 : 0 : 0) satisfies the equation but is not a point.
        lhs.ct_eq(&rhs) & !(self.z.is_zero() & self.y.is_zero())
    }

    /// Affine coordinates `(x, y)` and an "is infinity" flag (the coordinates
    /// are zero for the identity). One field inversion.
    pub(crate) fn to_affine(self) -> (F, F, Choice) {
        let inv = self.z.invert();
        let inf = inv.is_none();
        let zi = inv.unwrap_or(F::ZERO);
        (self.x.mul(&zi), self.y.mul(&zi), inf)
    }

    /// `-P`.
    #[inline]
    pub(crate) fn neg(&self) -> Self {
        Projective {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// `P + Q` (Renes–Costello–Batina Algorithm 7, complete for `a = 0`).
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let (x2, y2, z2) = (&rhs.x, &rhs.y, &rhs.z);
        let t0 = x1.mul(x2);
        let t1 = y1.mul(y2);
        let t2 = z1.mul(z2);
        let t3 = x1.add(y1);
        let t4 = x2.add(y2);
        let t3 = t3.mul(&t4);
        let t4 = t0.add(&t1);
        let t3 = t3.sub(&t4);
        let t4 = y1.add(z1);
        let x3 = y2.add(z2);
        let t4 = t4.mul(&x3);
        let x3 = t1.add(&t2);
        let t4 = t4.sub(&x3);
        let x3 = x1.add(z1);
        let y3 = x2.add(z2);
        let x3 = x3.mul(&y3);
        let y3 = t0.add(&t2);
        let y3 = x3.sub(&y3);
        let x3 = t0.add(&t0);
        let t0 = x3.add(&t0);
        let t2 = t2.mul_by_b3();
        let z3 = t1.add(&t2);
        let t1 = t1.sub(&t2);
        let y3 = y3.mul_by_b3();
        let x3 = t4.mul(&y3);
        let t2 = t3.mul(&t1);
        let x3 = t2.sub(&x3);
        let y3 = y3.mul(&t0);
        let t1 = t1.mul(&z3);
        let y3 = t1.add(&y3);
        let t0 = t0.mul(&t3);
        let z3 = z3.mul(&t4);
        let z3 = z3.add(&t0);
        Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `P - Q`.
    #[inline]
    pub(crate) fn sub(&self, rhs: &Self) -> Self {
        self.add(&rhs.neg())
    }

    /// `2P` (Renes–Costello–Batina Algorithm 9, complete for `a = 0`).
    pub(crate) fn double(&self) -> Self {
        let (x, y, z) = (&self.x, &self.y, &self.z);
        let t0 = y.square();
        let z3 = t0.add(&t0);
        let z3 = z3.add(&z3);
        let z3 = z3.add(&z3);
        let t1 = y.mul(z);
        let t2 = z.square();
        let t2 = t2.mul_by_b3();
        let x3 = t2.mul(&z3);
        let y3 = t0.add(&t2);
        let z3 = t1.mul(&z3);
        let t1 = t2.add(&t2);
        let t2 = t1.add(&t2);
        let t0 = t0.sub(&t2);
        let y3 = t0.mul(&y3);
        let y3 = x3.add(&y3);
        let t1 = x.mul(y);
        let x3 = t0.mul(&t1);
        let x3 = x3.add(&x3);
        Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Constant-time equality of the represented points (cross-multiplied
    /// coordinates; handles every projective representative of the identity).
    pub(crate) fn ct_eq(&self, other: &Self) -> Choice {
        let x1z2 = self.x.mul(&other.z);
        let x2z1 = other.x.mul(&self.z);
        let y1z2 = self.y.mul(&other.z);
        let y2z1 = other.y.mul(&self.z);
        x1z2.ct_eq(&x2z1) & y1z2.ct_eq(&y2z1)
    }

    /// Constant-time selection (`a` when `choice` is true).
    #[inline]
    pub(crate) fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Projective {
            x: F::conditional_select(&a.x, &b.x, choice),
            y: F::conditional_select(&a.y, &b.y, choice),
            z: F::conditional_select(&a.z, &b.z, choice),
        }
    }

    /// Fetches `table[digit]` by one masked pass over every entry: one
    /// opaque mask per entry, applied with `|`/`&` across all limbs.
    #[inline]
    fn gather(table: &[Self; 16], digit: u64) -> Self {
        let mut entry = Projective {
            x: F::ZERO,
            y: F::ZERO,
            z: F::ZERO,
        };
        for (i, t) in table.iter().enumerate() {
            let x = (i as u64) ^ digit;
            // All ones iff x == 0 (i.e. i == digit).
            let mask = mont::mask_from_bit(((x | x.wrapping_neg()) >> 63) ^ 1);
            entry.x.or_masked(&t.x, mask);
            entry.y.or_masked(&t.y, mask);
            entry.z.or_masked(&t.z, mask);
        }
        entry
    }

    /// `k·P` for a little-endian limb scalar, constant time in `k`: fixed
    /// 4-bit windows over every bit of `k` (four doublings and one complete
    /// addition each), each digit's entry fetched from the 16-entry table by
    /// a masked pass over all entries. The plain ladder the
    /// endomorphism-split multiplications are tested against; valid on any
    /// point, subgroup or not.
    #[cfg(test)]
    pub(crate) fn mul_limbs(&self, k: &[u64; 4]) -> Self {
        let mut table = [Self::IDENTITY; 16];
        for i in 1..16 {
            table[i] = table[i - 1].add(self);
        }
        let mut acc = Self::IDENTITY;
        for w in (0..64).rev() {
            acc = acc.double().double().double().double();
            let mut digit = (k[w / 16] >> (4 * (w % 16))) & 0xf;
            let mut entry = Self::gather(&table, digit);
            acc = acc.add(&entry);
            // The selected entry and the digit that picked it are the scalar
            // window in the clear; wipe them rather than leave them in the
            // frame.
            entry.zeroize();
            digit.zeroize();
        }
        for t in table.iter_mut() {
            t.zeroize();
        }
        acc
    }

    /// `-P` when `negate` is true, `P` otherwise (masked selection).
    #[inline]
    pub(crate) fn conditional_neg(&self, negate: Choice) -> Self {
        Self::conditional_select(&self.neg(), self, negate)
    }

    /// `Σ dᵢ·Pᵢ` for four 64-bit digits, constant time in the digits:
    /// simultaneous 1-bit windows over the 16 subset sums of the points,
    /// 64 doublings and 64 masked-gather additions.
    pub(crate) fn mul_4x64(points: &[Self; 4], digits: &[u64; 4]) -> Self {
        let mut table = [Self::IDENTITY; 16];
        for (i, p) in points.iter().enumerate() {
            let bit = 1 << i;
            table[bit] = *p;
            for j in 1..bit {
                table[bit + j] = table[j].add(p);
            }
        }
        let mut acc = Self::IDENTITY;
        for bit in (0..64).rev() {
            acc = acc.double();
            let mut digit = 0u64;
            for (i, d) in digits.iter().enumerate() {
                digit |= ((d >> bit) & 1) << i;
            }
            let mut entry = Self::gather(&table, digit);
            acc = acc.add(&entry);
            entry.zeroize();
            digit.zeroize();
        }
        for t in table.iter_mut() {
            t.zeroize();
        }
        acc
    }

    /// `d₀·P₀ + d₁·P₁` for two 128-bit digits, constant time in the
    /// digits: simultaneous 2-bit windows over the 16 combinations
    /// `a·P₀ + b·P₁` (`a, b < 4`), 128 doublings and 64 masked-gather
    /// additions.
    pub(crate) fn mul_2x128(points: &[Self; 2], digits: &[u128; 2]) -> Self {
        let mut table = [Self::IDENTITY; 16];
        table[1] = points[0];
        table[2] = points[0].double();
        table[3] = table[2].add(&points[0]);
        table[4] = points[1];
        table[8] = points[1].double();
        table[12] = table[8].add(&points[1]);
        for b in [4usize, 8, 12] {
            for a in 1..4 {
                table[a + b] = table[a].add(&table[b]);
            }
        }
        let mut acc = Self::IDENTITY;
        for w in (0..64).rev() {
            acc = acc.double().double();
            let shift = 2 * w;
            let mut digit = (((digits[0] >> shift) & 3) | ((digits[1] >> shift) & 3) << 2) as u64;
            let mut entry = Self::gather(&table, digit);
            acc = acc.add(&entry);
            entry.zeroize();
            digit.zeroize();
        }
        for t in table.iter_mut() {
            t.zeroize();
        }
        acc
    }

    /// `e·P` for a **public** 64-bit constant (double-and-add over its
    /// bits): no data-dependent control flow beyond the constant itself, and
    /// the formulas are complete.
    pub(crate) fn mul_by_public_u64(&self, e: u64) -> Self {
        let mut acc = Self::IDENTITY;
        for bit in (0..64).rev() {
            acc = acc.double();
            if (e >> bit) & 1 == 1 {
                acc = acc.add(self);
            }
        }
        acc
    }

    /// Wipes the coordinates.
    pub(crate) fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }

    // ---------------------------------------------------------------------
    // Encodings.

    /// Writes the gnark-crypto compressed encoding (`ENCODED_LEN` bytes):
    /// the big-endian x-coordinate with `10`/`11` in the top two bits for
    /// the smaller/larger `y`; the identity is `01` over zeros. (`p < 2^254`
    /// leaves the two top bits of every coordinate free.)
    pub(crate) fn write_compressed(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), F::ENCODED_LEN);
        let (x, y, inf) = self.to_affine();
        // Zero coordinates for the identity (to_affine already yields them).
        x.write_be(out);
        let largest = y.lexicographically_largest();
        let flag = u8::conditional_select(&FLAG_LARGEST, &FLAG_SMALLEST, largest);
        out[0] |= u8::conditional_select(&FLAG_INFINITY, &flag, inf);
    }

    /// Writes the uncompressed encoding (`2·ENCODED_LEN` bytes): `x || y`
    /// big-endian, all zeros for the identity — the EIP-196/197 format,
    /// which is also gnark-crypto's raw encoding.
    pub(crate) fn write_uncompressed(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), 2 * F::ENCODED_LEN);
        let (x, y, _) = self.to_affine();
        let n = F::ENCODED_LEN;
        x.write_be(&mut out[..n]);
        y.write_be(&mut out[n..]);
    }

    /// Parses a compressed encoding **without** a subgroup check. The point
    /// is guaranteed to be on the curve (or the identity) on success.
    ///
    /// Errors: [`Error::InvalidLength`]; [`Error::InvalidFlags`] for the
    /// `00` marker or an identity encoding with a nonzero payload;
    /// [`Error::InvalidEncoding`] for a non-canonical `x`;
    /// [`Error::NotOnCurve`] when `x³ + b` is not a square.
    pub(crate) fn read_compressed(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != F::ENCODED_LEN {
            return Err(Error::InvalidLength);
        }
        let flags = bytes[0] & FLAG_MASK;
        let mut buf = [0u8; 64];
        let buf = &mut buf[..F::ENCODED_LEN];
        buf.copy_from_slice(bytes);
        buf[0] &= !FLAG_MASK;
        match flags {
            FLAG_INFINITY => {
                if buf.iter().any(|&b| b != 0) {
                    return Err(Error::InvalidFlags);
                }
                return Ok(Self::IDENTITY);
            }
            FLAG_SMALLEST | FLAG_LARGEST => {}
            _ => return Err(Error::InvalidFlags),
        }
        let x = F::read_be(buf)
            .into_option()
            .ok_or(Error::InvalidEncoding)?;
        // y² = x³ + b; y ≠ 0 (no 2-torsion), so ±y are distinct.
        let rhs = x.square().mul(&x).add(&F::B);
        let y = rhs.sqrt().into_option().ok_or(Error::NotOnCurve)?;
        let want_largest = Choice::from((flags == FLAG_LARGEST) as u8);
        let flip = y.lexicographically_largest() ^ want_largest;
        let y = F::conditional_select(&y.neg(), &y, flip);
        Ok(Self::from_affine(x, y))
    }

    /// Parses an uncompressed (EIP-196/197) encoding **without** a subgroup
    /// check; checks canonicity and the curve equation. All zeros is the
    /// identity (it is not a curve point, as `b ≠ 0`).
    pub(crate) fn read_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 2 * F::ENCODED_LEN {
            return Err(Error::InvalidLength);
        }
        if bytes.iter().all(|&b| b == 0) {
            return Ok(Self::IDENTITY);
        }
        let n = F::ENCODED_LEN;
        let x = F::read_be(&bytes[..n])
            .into_option()
            .ok_or(Error::InvalidEncoding)?;
        let y = F::read_be(&bytes[n..])
            .into_option()
            .ok_or(Error::InvalidEncoding)?;
        let p = Self::from_affine(x, y);
        if !bool::from(p.is_on_curve()) {
            return Err(Error::NotOnCurve);
        }
        Ok(p)
    }
}

/// The Babai round-off shift `M`: `cⱼ = ⌊(k·gⱼ + 2^(M−1)) / 2^M⌋`.
const BABAI_SHIFT: usize = 320;

/// Splits a scalar `k < r` along a reduced lattice basis of the
/// endomorphism's kernel lattice (`D = 2` for GLV on `G1`, `D = 4` for GLS
/// on `G2`): returns `s = (k, 0, …) − Σⱼ cⱼ·bⱼ`, each `sᵢ` as a
/// two's-complement 256-bit value, with `cⱼ` Babai's rounding of
/// `k·αⱼ/r` computed from the fixed-point constants `gⱼ ≈ 2^320·|αⱼ|/r`
/// (signs `neg`). Then `k ≡ Σ sᵢλⁱ (mod r)` and `|sᵢ|` is below the bound
/// `tools/bn254/consts.py` proves (`2^127` for GLV, `2^64` for GLS).
///
/// Constant time in `k`, and straight-line: every basis entry is multiplied
/// (a zero entry contributes zero), both the sum and the difference are
/// computed, and the public sign picks one by mask. Branching on the public
/// basis is harmless in principle, but on 32-bit Arm LLVM kept that loop's
/// control state in a stack slot it also used for secret products and
/// memcheck flagged the branch; with no control flow left to optimise,
/// nothing can end up mixed with the scalar.
#[inline(always)]
pub(crate) fn babai_decompose<const D: usize>(
    k: &[u64; 4],
    basis: &[[i128; D]; D],
    g: &[[u64; 4]; D],
    neg: &[bool; D],
) -> [[u64; 4]; D] {
    // |cⱼ| < 2^192: the top three limbs of k·gⱼ + 2^319.
    let mut c = [[0u64; 4]; D];
    for (cj, gj) in c.iter_mut().zip(g.iter()) {
        let mut t = mul_wide(k, gj);
        let mut carry = 1u64 << 63;
        for limb in t.iter_mut().skip(BABAI_SHIFT / 64 - 1) {
            let (v, cy) = mont::adc(*limb, carry, 0);
            *limb = v;
            carry = cy;
        }
        *cj = [t[5], t[6], t[7], 0];
        t.zeroize();
    }
    let mut s = [[0u64; 4]; D];
    s[0] = *k;
    for j in 0..D {
        for i in 0..D {
            let b = basis[j][i];
            let mut prod = mul_lo_u128(&c[j], b.unsigned_abs());
            // sᵢ −= (±|cⱼ|)·bⱼᵢ; the product's sign is public.
            let mut diff = wrapping_sub(&s[i], &prod);
            let mut sum = wrapping_add(&s[i], &prod);
            let take_diff = Choice::from(((b < 0) == neg[j]) as u8);
            s[i] = mont::select(&diff, &sum, take_diff);
            prod.zeroize();
            diff.zeroize();
            sum.zeroize();
        }
    }
    for cj in c.iter_mut() {
        cj.zeroize();
    }
    s
}

/// The sign and magnitude of a two's-complement 256-bit value, branch-free.
pub(crate) fn sign_magnitude(s: &[u64; 4]) -> (Choice, [u64; 4]) {
    let bit = s[3] >> 63;
    let mask = mont::mask_from_bit(bit);
    let mut out = [0u64; 4];
    let mut carry = bit;
    for (o, l) in out.iter_mut().zip(s.iter()) {
        let (v, c) = mont::adc(l ^ mask, carry, 0);
        *o = v;
        carry = c;
    }
    (Choice::from(bit as u8), out)
}

/// The full 512-bit product `a·b` (schoolbook, fixed schedule).
#[inline(always)]
fn mul_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let (v, c) = mont::mac(t[i + j], a[i], b[j], carry);
            t[i + j] = v;
            carry = c;
        }
        t[i + 4] = carry;
    }
    t
}

/// `a·b mod 2^256` for a 128-bit `b`.
#[inline(always)]
fn mul_lo_u128(a: &[u64; 4], b: u128) -> [u64; 4] {
    let b = [b as u64, (b >> 64) as u64];
    let mut t = [0u64; 4];
    for i in 0..4 {
        let mut carry = 0u64;
        for (j, bj) in b.iter().enumerate() {
            if i + j < 4 {
                let (v, c) = mont::mac(t[i + j], a[i], *bj, carry);
                t[i + j] = v;
                carry = c;
            }
        }
        if i + 2 < 4 {
            t[i + 2] = carry;
        }
    }
    t
}

#[inline(always)]
fn wrapping_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (v, c) = mont::adc(a[i], b[i], carry);
        out[i] = v;
        carry = c;
    }
    out
}

#[inline(always)]
fn wrapping_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (v, bo) = mont::sbb(a[i], b[i], borrow);
        out[i] = v;
        borrow = bo;
    }
    out
}

impl CurveField for super::fp::Fp {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;
    const B: Self = super::constants::B1;
    const ENCODED_LEN: usize = 32;

    #[inline]
    fn add(&self, rhs: &Self) -> Self {
        Self::add(self, rhs)
    }
    #[inline]
    fn sub(&self, rhs: &Self) -> Self {
        Self::sub(self, rhs)
    }
    #[inline]
    fn mul(&self, rhs: &Self) -> Self {
        Self::mul(self, rhs)
    }
    #[inline]
    fn square(&self) -> Self {
        Self::square(self)
    }
    #[inline]
    fn neg(&self) -> Self {
        Self::neg(self)
    }
    #[inline]
    fn is_zero(&self) -> Choice {
        Self::is_zero(self)
    }
    #[inline]
    fn invert(&self) -> CtOption<Self> {
        Self::invert(self)
    }
    #[inline]
    fn sqrt(&self) -> CtOption<Self> {
        Self::sqrt(self)
    }
    #[inline]
    fn mul_by_b3(&self) -> Self {
        // 9·x = 8x + x.
        self.double().double().double().add(self)
    }
    #[inline]
    fn or_masked(&mut self, other: &Self, mask: u64) {
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a |= mask & b;
        }
    }
    #[inline]
    fn lexicographically_largest(&self) -> Choice {
        Self::lexicographically_largest(self)
    }
    fn write_be(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_bytes());
    }
    fn read_be(bytes: &[u8]) -> CtOption<Self> {
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        Self::from_bytes(&b)
    }
}

impl CurveField for super::fp2::Fp2 {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;
    const B: Self = super::constants::B2;
    const ENCODED_LEN: usize = 64;

    #[inline]
    fn add(&self, rhs: &Self) -> Self {
        Self::add(self, rhs)
    }
    #[inline]
    fn sub(&self, rhs: &Self) -> Self {
        Self::sub(self, rhs)
    }
    #[inline]
    fn mul(&self, rhs: &Self) -> Self {
        Self::mul(self, rhs)
    }
    #[inline]
    fn square(&self) -> Self {
        Self::square(self)
    }
    #[inline]
    fn neg(&self) -> Self {
        Self::neg(self)
    }
    #[inline]
    fn is_zero(&self) -> Choice {
        Self::is_zero(self)
    }
    #[inline]
    fn invert(&self) -> CtOption<Self> {
        Self::invert(self)
    }
    #[inline]
    fn sqrt(&self) -> CtOption<Self> {
        Self::sqrt(self)
    }
    #[inline]
    fn mul_by_b3(&self) -> Self {
        // 3b' = 9/(9 + u) has no small form; one Fp2 multiplication.
        self.mul(&super::constants::B2_3)
    }
    #[inline]
    fn or_masked(&mut self, other: &Self, mask: u64) {
        CurveField::or_masked(&mut self.c0, &other.c0, mask);
        CurveField::or_masked(&mut self.c1, &other.c1, mask);
    }
    #[inline]
    fn lexicographically_largest(&self) -> Choice {
        Self::lexicographically_largest(self)
    }
    /// EIP-197 / gnark order: `c1` (the `u` coefficient) first, then `c0`.
    fn write_be(&self, out: &mut [u8]) {
        out[..32].copy_from_slice(&self.c1.to_bytes());
        out[32..].copy_from_slice(&self.c0.to_bytes());
    }
    fn read_be(bytes: &[u8]) -> CtOption<Self> {
        let mut b1 = [0u8; 32];
        let mut b0 = [0u8; 32];
        b1.copy_from_slice(&bytes[..32]);
        b0.copy_from_slice(&bytes[32..]);
        super::fp::Fp::from_bytes(&b1)
            .and_then(|c1| super::fp::Fp::from_bytes(&b0).map(|c0| Self::new(c0, c1)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::constants::{
        BABAI_EDGE_SCALARS, GLS_BASIS, GLS_G, GLS_NEG, GLV_BASIS, GLV_G, GLV_NEG, X,
    };
    use super::super::fr::Fr;
    use super::*;

    fn fr_i128(v: i128) -> Fr {
        let m = v.unsigned_abs();
        let f = Fr::from_u64((m >> 64) as u64) * Fr::from_u64(1 << 32) * Fr::from_u64(1 << 32)
            + Fr::from_u64(m as u64);
        if v < 0 { -f } else { f }
    }

    fn fr_signed(s: &[u64; 4]) -> (Fr, [u64; 4]) {
        let (neg, mag) = sign_magnitude(s);
        let mut be = [0u8; 32];
        mont::to_be_bytes(&mag, &mut be);
        let f = Fr::from_bytes(&be).expect("small magnitude");
        (if bool::from(neg) { -f } else { f }, mag)
    }

    fn fr_of(k: &[u64; 4]) -> Fr {
        let mut be = [0u8; 32];
        mont::to_be_bytes(k, &mut be);
        Fr::from_bytes(&be).expect("canonical")
    }

    /// Every split recombines to `k` and respects the proven bounds.
    #[test]
    fn babai_splits_recombine_within_bounds() {
        let lambda = -fr_i128(GLV_BASIS[0][0]) * fr_i128(GLV_BASIS[0][1]).invert().unwrap();
        let x = Fr::from_u64(X);
        let mu = Fr::from_u64(6) * x * x;
        for b in GLV_BASIS.iter() {
            assert_eq!(fr_i128(b[0]) + fr_i128(b[1]) * lambda, Fr::ZERO);
        }
        for b in GLS_BASIS.iter() {
            let mut acc = Fr::ZERO;
            let mut pw = Fr::ONE;
            for e in b {
                acc += fr_i128(*e) * pw;
                pw *= mu;
            }
            assert_eq!(acc, Fr::ZERO);
        }
        for k in BABAI_EDGE_SCALARS.iter() {
            let s = babai_decompose(k, &GLV_BASIS, &GLV_G, &GLV_NEG);
            let (s0, m0) = fr_signed(&s[0]);
            let (s1, m1) = fr_signed(&s[1]);
            assert_eq!(s0 + s1 * lambda, fr_of(k), "k = {k:x?}");
            for m in [m0, m1] {
                assert!(
                    m[2] == 0 && m[3] == 0 && m[1] >> 63 == 0,
                    "GLV bound, k = {k:x?}"
                );
            }
            let s = babai_decompose(k, &GLS_BASIS, &GLS_G, &GLS_NEG);
            let mut acc = Fr::ZERO;
            let mut pw = Fr::ONE;
            for si in s.iter() {
                let (f, m) = fr_signed(si);
                assert!(m[1] == 0 && m[2] == 0 && m[3] == 0, "GLS bound, k = {k:x?}");
                acc += f * pw;
                pw *= mu;
            }
            assert_eq!(acc, fr_of(k), "k = {k:x?}");
        }
    }

    #[test]
    fn limb_helpers_edges() {
        assert_eq!(sign_magnitude(&[0; 4]).1, [0; 4]);
        assert!(!bool::from(sign_magnitude(&[0; 4]).0));
        let (n, m) = sign_magnitude(&[u64::MAX; 4]);
        assert!(bool::from(n) && m == [1, 0, 0, 0]);
        let (n, m) = sign_magnitude(&[0, 0, 0, 1 << 63]);
        assert!(bool::from(n) && m == [0, 0, 0, 1 << 63]);
        let (n, m) = sign_magnitude(&[5, 0, 0, 0]);
        assert!(!bool::from(n) && m == [5, 0, 0, 0]);
        assert_eq!(
            wrapping_sub(&[3, 0, 0, 0], &[5, 0, 0, 0]),
            [u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX]
        );
        assert_eq!(wrapping_add(&[u64::MAX; 4], &[1, 0, 0, 0]), [0; 4]);
        assert_eq!(
            mul_lo_u128(&[u64::MAX; 4], 2),
            [u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX]
        );
        assert_eq!(
            mul_lo_u128(&[1, 2, 3, 4], (7u128 << 64) | 5),
            [5, 17, 29, 41]
        );
        let w = mul_wide(&[u64::MAX; 4], &[u64::MAX; 4]);
        // (2^256 − 1)² = 2^512 − 2^257 + 1.
        assert_eq!(w, [1, 0, 0, 0, u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX]);
    }
}
