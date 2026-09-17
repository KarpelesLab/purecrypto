//! Projective short-Weierstrass arithmetic shared by `G1` (over `Fp`) and
//! `G2` (over `Fp2`), plus the ZCash point serialization.
//!
//! Both BLS12-381 groups are `y² = x³ + b` (`a = 0`) and both `E(Fp)` and
//! `E'(Fp2)` have odd order, so the Renes–Costello–Batina **complete**
//! formulas for `j = 0` curves (Algorithms 7 and 9 of
//! <https://eprint.iacr.org/2015/1060>) are correct for every input pair —
//! identity, doubling and inverse included — without a single branch. Scalar
//! multiplication by a secret is a fixed 4-bit window with a masked table
//! lookup, so neither the schedule nor the memory access pattern depends on
//! the scalar.

use super::Error;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
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
    /// `3·b`.
    const B3: Self;
    /// Byte length of one encoded coordinate.
    const ENCODED_LEN: usize;

    fn add(&self, rhs: &Self) -> Self;
    fn sub(&self, rhs: &Self) -> Self;
    fn mul(&self, rhs: &Self) -> Self;
    fn square(&self) -> Self;
    fn neg(&self) -> Self;
    fn is_zero(&self) -> Choice;
    fn invert(&self) -> CtOption<Self>;
    fn sqrt(&self) -> CtOption<Self>;
    /// The ZCash "y is the larger of ±y" flag.
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

/// Flag bits of the ZCash encoding (top three bits of the first byte).
const FLAG_COMPRESSED: u8 = 0x80;
const FLAG_INFINITY: u8 = 0x40;
const FLAG_SORT: u8 = 0x20;

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
        lhs.ct_eq(&rhs)
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
        let t2 = F::B3.mul(&t2);
        let z3 = t1.add(&t2);
        let t1 = t1.sub(&t2);
        let y3 = F::B3.mul(&y3);
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
        let t2 = F::B3.mul(&t2);
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

    /// `k·P` for a little-endian limb scalar, constant time in `k`: fixed
    /// 4-bit windows over every bit of `k`, each digit fetched from a
    /// 16-entry table by masked selection over all entries.
    pub(crate) fn mul_limbs(&self, k: &[u64]) -> Self {
        let mut table = [Self::IDENTITY; 16];
        for i in 1..16 {
            table[i] = table[i - 1].add(self);
        }
        let mut acc = Self::IDENTITY;
        let windows = k.len() * 16;
        for w in (0..windows).rev() {
            acc = acc.double().double().double().double();
            let digit = (k[w / 16] >> (4 * (w % 16))) & 0xf;
            let mut entry = Self::IDENTITY;
            for (i, t) in table.iter().enumerate() {
                let take = (i as u64).ct_eq(&digit);
                entry = Self::conditional_select(t, &entry, take);
            }
            acc = acc.add(&entry);
        }
        for t in table.iter_mut() {
            t.zeroize();
        }
        acc
    }

    /// `|x|·P` for the BLS parameter `|x| = 0xd201000000010000` (Hamming
    /// weight 6): double-and-add over the public constant's bits — no
    /// secret-dependent control flow, and the formulas are complete.
    pub(crate) fn mul_by_x_abs(&self) -> Self {
        const X_ABS: u64 = 0xd201000000010000;
        let mut acc = Self::IDENTITY;
        for bit in (0..64).rev() {
            acc = acc.double();
            if (X_ABS >> bit) & 1 == 1 {
                acc = acc.add(self);
            }
        }
        acc
    }

    /// `x·P` for the (negative) BLS parameter `x`.
    #[inline]
    pub(crate) fn mul_by_x(&self) -> Self {
        self.mul_by_x_abs().neg()
    }

    /// Wipes the coordinates.
    pub(crate) fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }

    // ---------------------------------------------------------------------
    // ZCash serialization (https://github.com/zkcrypto/bls12_381, "Serialization").

    /// Writes the compressed encoding (`ENCODED_LEN` bytes): the
    /// x-coordinate with the compression flag set, plus the sort flag when
    /// `y` is the larger root; the identity is the compression + infinity
    /// flags over zeros.
    pub(crate) fn write_compressed(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), F::ENCODED_LEN);
        let (x, y, inf) = self.to_affine();
        // Zero coordinates for the identity (to_affine already yields them).
        x.write_be(out);
        let sort = y.lexicographically_largest() & !inf;
        out[0] |= FLAG_COMPRESSED
            | u8::conditional_select(&FLAG_INFINITY, &0, inf)
            | u8::conditional_select(&FLAG_SORT, &0, sort);
    }

    /// Writes the uncompressed encoding (`2·ENCODED_LEN` bytes): `x || y`
    /// with only the infinity flag ever set.
    pub(crate) fn write_uncompressed(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), 2 * F::ENCODED_LEN);
        let (x, y, inf) = self.to_affine();
        let n = F::ENCODED_LEN;
        x.write_be(&mut out[..n]);
        y.write_be(&mut out[n..]);
        out[0] |= u8::conditional_select(&FLAG_INFINITY, &0, inf);
    }

    /// Parses a compressed encoding **without** a subgroup check. The point
    /// is guaranteed to be on the curve (or the identity) on success.
    ///
    /// Errors: [`Error::InvalidLength`]; [`Error::InvalidFlags`] when the
    /// compression bit is clear, or the infinity bit is set together with
    /// the sort bit or a nonzero payload; [`Error::InvalidEncoding`] for a
    /// non-canonical `x`; [`Error::NotOnCurve`] when `x³ + b` is not a
    /// square.
    pub(crate) fn read_compressed(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != F::ENCODED_LEN {
            return Err(Error::InvalidLength);
        }
        let flags = bytes[0];
        if flags & FLAG_COMPRESSED == 0 {
            return Err(Error::InvalidFlags);
        }
        let infinity = flags & FLAG_INFINITY != 0;
        let sort = flags & FLAG_SORT != 0;
        let mut buf = [0u8; 96];
        let buf = &mut buf[..F::ENCODED_LEN];
        buf.copy_from_slice(bytes);
        buf[0] &= 0x1f;
        if infinity {
            // The sort flag and any payload bit contradict "infinity".
            if sort || buf.iter().any(|&b| b != 0) {
                return Err(Error::InvalidFlags);
            }
            return Ok(Self::IDENTITY);
        }
        let x = F::read_be(buf)
            .into_option()
            .ok_or(Error::InvalidEncoding)?;
        // y² = x³ + b
        let rhs = x.square().mul(&x).add(&F::B);
        let y = rhs.sqrt().into_option().ok_or(Error::NotOnCurve)?;
        let flip = y.lexicographically_largest() ^ Choice::from(sort as u8);
        let y = F::conditional_select(&y.neg(), &y, flip);
        Ok(Self::from_affine(x, y))
    }

    /// Parses an uncompressed encoding **without** a subgroup check; checks
    /// the curve equation.
    pub(crate) fn read_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 2 * F::ENCODED_LEN {
            return Err(Error::InvalidLength);
        }
        let flags = bytes[0];
        if flags & FLAG_COMPRESSED != 0 || flags & FLAG_SORT != 0 {
            return Err(Error::InvalidFlags);
        }
        let infinity = flags & FLAG_INFINITY != 0;
        let n = F::ENCODED_LEN;
        let mut buf = [0u8; 192];
        let buf = &mut buf[..2 * n];
        buf.copy_from_slice(bytes);
        buf[0] &= 0x1f;
        if infinity {
            if buf.iter().any(|&b| b != 0) {
                return Err(Error::InvalidFlags);
            }
            return Ok(Self::IDENTITY);
        }
        let x = F::read_be(&buf[..n])
            .into_option()
            .ok_or(Error::InvalidEncoding)?;
        let y = F::read_be(&buf[n..])
            .into_option()
            .ok_or(Error::InvalidEncoding)?;
        let p = Self::from_affine(x, y);
        if !bool::from(p.is_on_curve()) {
            return Err(Error::NotOnCurve);
        }
        Ok(p)
    }
}

impl CurveField for super::fp::Fp {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;
    const B: Self = super::constants::B1;
    const B3: Self = super::constants::B1_3;
    const ENCODED_LEN: usize = 48;

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
    fn lexicographically_largest(&self) -> Choice {
        Self::lexicographically_largest(self)
    }
    fn write_be(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_bytes());
    }
    fn read_be(bytes: &[u8]) -> CtOption<Self> {
        let mut b = [0u8; 48];
        b.copy_from_slice(bytes);
        Self::from_bytes(&b)
    }
}

impl CurveField for super::fp2::Fp2 {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;
    const B: Self = super::constants::B2;
    const B3: Self = super::constants::B2_3;
    const ENCODED_LEN: usize = 96;

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
    fn lexicographically_largest(&self) -> Choice {
        Self::lexicographically_largest(self)
    }
    /// ZCash order: `c1` first, then `c0`.
    fn write_be(&self, out: &mut [u8]) {
        out[..48].copy_from_slice(&self.c1.to_bytes());
        out[48..].copy_from_slice(&self.c0.to_bytes());
    }
    fn read_be(bytes: &[u8]) -> CtOption<Self> {
        let mut b1 = [0u8; 48];
        let mut b0 = [0u8; 48];
        b1.copy_from_slice(&bytes[..48]);
        b0.copy_from_slice(&bytes[48..]);
        super::fp::Fp::from_bytes(&b1)
            .and_then(|c1| super::fp::Fp::from_bytes(&b0).map(|c0| Self::new(c0, c1)))
    }
}
