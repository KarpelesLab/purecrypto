//! The BLS12-377 base field `Fp`, `p = 0x01ae3a46…8508c00000000001` (377 bits).
//!
//! Elements are six little-endian `u64` limbs in Montgomery form
//! (`a·2^384 mod p`), always canonical (`< p`). Every operation runs a fixed
//! schedule: the limb routines in [`mont`](super::mont) never branch on
//! values, inversion is a Fermat exponentiation with a public exponent, and
//! the square root is the fixed-schedule RFC 9380 `sqrt_ratio`
//! (`p - 1` has 2-adicity 46, so the `p ≡ 3 (mod 4)` shortcut does not
//! apply). The only variable-time paths are the `Option`/`bool` conversions
//! at the API boundary, which are meant for public data (decoding).

use super::constants::{
    FP_INV, FP_MODULUS, FP_P_MINUS_1_DIV_2, FP_P_MINUS_2, FP_R, FP_R2, FP_R3, FP_SR_C1, FP_SR_C3,
    FP_SR_C6, FP_SR_C7,
};
use super::mont;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// An element of the BLS12-377 base field `GF(p)`.
///
/// Equality (`==`) and the [`ConstantTimeEq`] / [`ConditionallySelectable`]
/// impls are constant time. The value is stored in Montgomery form; use
/// [`to_bytes`](Fp::to_bytes) / [`from_bytes`](Fp::from_bytes) for the
/// 48-byte big-endian canonical encoding.
#[derive(Clone, Copy)]
pub struct Fp(pub(crate) [u64; 6]);

impl Fp {
    /// The additive identity.
    pub const ZERO: Fp = Fp([0; 6]);
    /// The multiplicative identity.
    pub const ONE: Fp = Fp(FP_R);

    /// Constant-time zero test.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        Choice::from((mont::is_nonzero_bit(&self.0) ^ 1) as u8)
    }

    /// `self + rhs`.
    #[inline]
    pub fn add(&self, rhs: &Fp) -> Fp {
        Fp(mont::add(&self.0, &rhs.0, &FP_MODULUS))
    }

    /// `self - rhs`.
    #[inline]
    pub fn sub(&self, rhs: &Fp) -> Fp {
        Fp(mont::sub(&self.0, &rhs.0, &FP_MODULUS))
    }

    /// `-self`.
    #[inline]
    pub fn neg(&self) -> Fp {
        Fp(mont::neg(&self.0, &FP_MODULUS))
    }

    /// `2·self`.
    #[inline]
    pub fn double(&self) -> Fp {
        self.add(self)
    }

    /// `self · rhs`.
    #[inline]
    pub fn mul(&self, rhs: &Fp) -> Fp {
        Fp(mont::mul(&self.0, &rhs.0, &FP_MODULUS, FP_INV))
    }

    /// `self²`.
    #[inline]
    pub fn square(&self) -> Fp {
        Fp(mont::square(&self.0, &FP_MODULUS, FP_INV))
    }

    /// `Σᵢ aᵢ·bᵢ` with one Montgomery reduction for the whole sum (see
    /// [`mont::sum_of_products`]); `p < 2^377` allows far more terms than
    /// the tower ever uses, the bound below is just a sanity cap.
    #[inline]
    pub(crate) fn sum_of_products<const M: usize>(a: &[Fp; M], b: &[Fp; M]) -> Fp {
        const { assert!(M <= 9) };
        let mut al = [[0u64; 6]; M];
        let mut bl = [[0u64; 6]; M];
        let mut i = 0;
        while i < M {
            al[i] = a[i].0;
            bl[i] = b[i].0;
            i += 1;
        }
        Fp(mont::sum_of_products(&al, &bl, &FP_MODULUS, FP_INV))
    }

    /// `5·self` by additions.
    #[inline]
    pub(crate) fn mul_by_5(&self) -> Fp {
        self.double().double().add(self)
    }

    /// `self^e` for a little-endian limb exponent. Fixed square-and-multiply
    /// schedule over every bit of `e`: the running time depends only on the
    /// exponent's limb count, so it is constant time in `self` whenever the
    /// exponent is public (every use in this crate).
    #[inline]
    pub fn pow(&self, e: &[u64]) -> Fp {
        Fp(mont::pow(&self.0, e, &FP_R, &FP_MODULUS, FP_INV))
    }

    /// `self^e` for a **public** exponent (fixed 4-bit window, see
    /// [`mont::pow_public_exp`]): constant time in `self`, not in `e`.
    #[inline]
    pub(crate) fn pow_public_exp(&self, e: &[u64]) -> Fp {
        mont::pow_public_exp(self, e, &Fp::ONE, Fp::mul, Fp::square)
    }

    /// Multiplicative inverse, `None` for zero (Fermat: `self^(p-2)`).
    #[inline]
    pub fn invert(&self) -> CtOption<Fp> {
        CtOption::new(self.pow_public_exp(&FP_P_MINUS_2), !self.is_zero())
    }

    /// `(is_square(u/v), √(u/v) or √(Z·u/v))` — RFC 9380 `sqrt_ratio` with
    /// the G1 SSWU constant `Z = 5` (see [`super::curve::sqrt_ratio`]).
    #[inline]
    pub(crate) fn sqrt_ratio(u: &Fp, v: &Fp) -> (Choice, Fp) {
        super::curve::sqrt_ratio(u, v, FP_SR_C1, &FP_SR_C3, &FP_SR_C6, &FP_SR_C7)
    }

    /// A square root, `None` when `self` is a non-residue. Computed by the
    /// fixed-schedule `sqrt_ratio(self, 1)` and verified by squaring, so
    /// the presence flag is exact.
    #[inline]
    pub fn sqrt(&self) -> CtOption<Fp> {
        let (_, cand) = Fp::sqrt_ratio(self, &Fp::ONE);
        CtOption::new(cand, cand.square().ct_eq(self))
    }

    /// The canonical integer representative as little-endian limbs (leaves
    /// Montgomery form by multiplying by 1).
    #[inline]
    pub(crate) fn to_canonical(self) -> [u64; 6] {
        let one = [1u64, 0, 0, 0, 0, 0];
        mont::mul(&self.0, &one, &FP_MODULUS, FP_INV)
    }

    /// Builds an element from canonical limbs (`< p`), entering Montgomery
    /// form.
    #[inline]
    pub(crate) fn from_canonical(limbs: &[u64; 6]) -> Fp {
        Fp(mont::mul(limbs, &FP_R2, &FP_MODULUS, FP_INV))
    }

    /// The canonical 48-byte big-endian encoding.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        mont::to_be_bytes(&self.to_canonical(), &mut out);
        out
    }

    /// The canonical 48-byte little-endian encoding (arkworks' layout).
    #[inline]
    pub fn to_bytes_le(&self) -> [u8; 48] {
        let mut out = self.to_bytes();
        out.reverse();
        out
    }

    /// Decodes a 48-byte big-endian integer, `None` unless it is canonical
    /// (`< p`). The returned element is meaningful only when the flag is set
    /// (a non-canonical input yields an unspecified but harmless value).
    #[inline]
    pub fn from_bytes(bytes: &[u8; 48]) -> CtOption<Fp> {
        let limbs = mont::from_be_bytes::<6>(bytes);
        let ok = Choice::from(mont::lt_bit(&limbs, &FP_MODULUS) as u8);
        CtOption::new(Fp::from_canonical(&limbs), ok)
    }

    /// Decodes a 48-byte little-endian integer, `None` unless canonical.
    #[inline]
    pub fn from_bytes_le(bytes: &[u8; 48]) -> CtOption<Fp> {
        let mut be = *bytes;
        be.reverse();
        Fp::from_bytes(&be)
    }

    /// Reduces a 64-byte big-endian integer modulo `p` (RFC 9380
    /// `hash_to_field` with `L = 64`).
    pub(crate) fn from_bytes_wide(bytes: &[u8; 64]) -> Fp {
        // value = hi·2^384 + lo with hi the top 16 bytes.
        let lo = mont::from_be_bytes::<6>(&bytes[16..]);
        let mut hi = [0u64; 6];
        let hi2 = mont::from_be_bytes::<2>(&bytes[..16]);
        hi[0] = hi2[0];
        hi[1] = hi2[1];
        // `lo` may exceed p (it is below 2^384): the Montgomery product of
        // a value below 2^384 with one below p still ends below 2p, which
        // the final conditional subtraction handles.
        let lo_m = mont::mul(&lo, &FP_R2, &FP_MODULUS, FP_INV);
        let hi_m = mont::mul(&hi, &FP_R3, &FP_MODULUS, FP_INV);
        Fp(mont::add(&lo_m, &hi_m, &FP_MODULUS))
    }

    /// True when the canonical representative is greater than `(p-1)/2`,
    /// i.e. `self > -self` — the sort flag of compressed points.
    #[inline]
    pub(crate) fn lexicographically_largest(&self) -> Choice {
        // self > (p-1)/2  <=>  !(self < (p-1)/2 + 1).
        let c = self.to_canonical();
        let mut t = FP_P_MINUS_1_DIV_2;
        t[0] += 1;
        Choice::from((mont::lt_bit(&c, &t) ^ 1) as u8)
    }

    /// Parity of the canonical representative (RFC 9380 `sgn0` for `GF(p)`).
    #[inline]
    pub(crate) fn is_odd(&self) -> Choice {
        Choice::from((self.to_canonical()[0] & 1) as u8)
    }
}

impl Default for Fp {
    fn default() -> Self {
        Fp::ZERO
    }
}

impl core::fmt::Debug for Fp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("0x")?;
        for b in self.to_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl ConstantTimeEq for Fp {
    #[inline]
    fn ct_eq(&self, other: &Fp) -> Choice {
        mont::ct_eq(&self.0, &other.0)
    }
}

impl ConditionallySelectable for Fp {
    #[inline]
    fn conditional_select(a: &Fp, b: &Fp, choice: Choice) -> Fp {
        Fp(mont::select(&a.0, &b.0, choice))
    }
}

impl PartialEq for Fp {
    #[inline]
    fn eq(&self, other: &Fp) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Fp {}

impl Zeroize for Fp {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Implements the `core::ops` traits for owned and borrowed operands in
/// terms of the inherent `&self`/`&rhs` methods.
macro_rules! impl_field_ops {
    ($t:ty) => {
        impl<'b> Add<&'b $t> for &$t {
            type Output = $t;
            #[inline]
            fn add(self, rhs: &'b $t) -> $t {
                <$t>::add(self, rhs)
            }
        }
        impl<'b> Sub<&'b $t> for &$t {
            type Output = $t;
            #[inline]
            fn sub(self, rhs: &'b $t) -> $t {
                <$t>::sub(self, rhs)
            }
        }
        impl<'b> Mul<&'b $t> for &$t {
            type Output = $t;
            #[inline]
            fn mul(self, rhs: &'b $t) -> $t {
                <$t>::mul(self, rhs)
            }
        }
        impl Add<$t> for $t {
            type Output = $t;
            #[inline]
            fn add(self, rhs: $t) -> $t {
                <$t>::add(&self, &rhs)
            }
        }
        impl Sub<$t> for $t {
            type Output = $t;
            #[inline]
            fn sub(self, rhs: $t) -> $t {
                <$t>::sub(&self, &rhs)
            }
        }
        impl Mul<$t> for $t {
            type Output = $t;
            #[inline]
            fn mul(self, rhs: $t) -> $t {
                <$t>::mul(&self, &rhs)
            }
        }
        impl<'b> Add<&'b $t> for $t {
            type Output = $t;
            #[inline]
            fn add(self, rhs: &'b $t) -> $t {
                <$t>::add(&self, rhs)
            }
        }
        impl<'b> Sub<&'b $t> for $t {
            type Output = $t;
            #[inline]
            fn sub(self, rhs: &'b $t) -> $t {
                <$t>::sub(&self, rhs)
            }
        }
        impl<'b> Mul<&'b $t> for $t {
            type Output = $t;
            #[inline]
            fn mul(self, rhs: &'b $t) -> $t {
                <$t>::mul(&self, rhs)
            }
        }
        impl Neg for $t {
            type Output = $t;
            #[inline]
            fn neg(self) -> $t {
                <$t>::neg(&self)
            }
        }
        impl Neg for &$t {
            type Output = $t;
            #[inline]
            fn neg(self) -> $t {
                <$t>::neg(self)
            }
        }
        impl AddAssign<$t> for $t {
            #[inline]
            fn add_assign(&mut self, rhs: $t) {
                *self = <$t>::add(self, &rhs);
            }
        }
        impl SubAssign<$t> for $t {
            #[inline]
            fn sub_assign(&mut self, rhs: $t) {
                *self = <$t>::sub(self, &rhs);
            }
        }
        impl MulAssign<$t> for $t {
            #[inline]
            fn mul_assign(&mut self, rhs: $t) {
                *self = <$t>::mul(self, &rhs);
            }
        }
        impl<'b> AddAssign<&'b $t> for $t {
            #[inline]
            fn add_assign(&mut self, rhs: &'b $t) {
                *self = <$t>::add(self, rhs);
            }
        }
        impl<'b> SubAssign<&'b $t> for $t {
            #[inline]
            fn sub_assign(&mut self, rhs: &'b $t) {
                *self = <$t>::sub(self, rhs);
            }
        }
        impl<'b> MulAssign<&'b $t> for $t {
            #[inline]
            fn mul_assign(&mut self, rhs: &'b $t) {
                *self = <$t>::mul(self, rhs);
            }
        }
    };
}
pub(crate) use impl_field_ops;

impl_field_ops!(Fp);

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> [u8; 48] {
        let mut out = [0u8; 48];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    const P_HEX: &str = "01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001";

    fn sample(i: u64) -> Fp {
        let mut w = [0u8; 64];
        for (k, c) in w.chunks_mut(8).enumerate() {
            let v = (i + 1)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .rotate_left(k as u32 * 7)
                ^ (k as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            c.copy_from_slice(&v.to_be_bytes());
        }
        Fp::from_bytes_wide(&w)
    }

    #[test]
    fn canonical_decoding() {
        assert!(bool::from(Fp::from_bytes(&hex(P_HEX)).is_none()));
        let mut pm1 = hex(P_HEX);
        pm1[47] -= 1;
        let a = Fp::from_bytes(&pm1).unwrap();
        assert_eq!(a.to_bytes(), pm1);
        assert_eq!(a, -Fp::ONE);
        assert!(bool::from(Fp::from_bytes(&[0xff; 48]).is_none()));
        assert_eq!(Fp::from_bytes(&[0; 48]).unwrap(), Fp::ZERO);
        let mut one = [0u8; 48];
        one[47] = 1;
        assert_eq!(Fp::from_bytes(&one).unwrap(), Fp::ONE);
        assert_eq!(Fp::ONE.to_bytes(), one);
        let mut le = one;
        le.reverse();
        assert_eq!(Fp::ONE.to_bytes_le(), le);
        assert_eq!(Fp::from_bytes_le(&le).unwrap(), Fp::ONE);
        let mut p_le = hex(P_HEX);
        p_le.reverse();
        assert!(bool::from(Fp::from_bytes_le(&p_le).is_none()));
    }

    #[test]
    fn ring_axioms_inverse_and_sqrt() {
        for i in 0..40 {
            let x = sample(i);
            let y = sample(i + 100);
            assert_eq!(x * y, y * x);
            assert_eq!(Fp::sum_of_products(&[x], &[y]), x * y);
            assert_eq!(Fp::sum_of_products(&[x, -y, x], &[y, x, x]), x.square());
            let m1 = -Fp::ONE;
            assert_eq!(
                Fp::sum_of_products(&[m1; 9], &[m1; 9]),
                Fp::from_canonical(&[9, 0, 0, 0, 0, 0])
            );
            assert_eq!((x + y) * (x - y), x.square() - y.square());
            assert_eq!(x * x.invert().unwrap(), Fp::ONE);
            assert_eq!(x.mul_by_5(), x * Fp::from_canonical(&[5, 0, 0, 0, 0, 0]));
            let s = x.square();
            let r = s.sqrt().unwrap();
            assert!(r == x || r == -x);
            // Exactly one of x and 5x is a square (5 is a non-residue).
            let sq = bool::from(x.sqrt().is_some());
            let sq5 = bool::from(x.mul_by_5().sqrt().is_some());
            assert!(sq ^ sq5);
            // sqrt_ratio: u/v square -> root; else root of Z·u/v.
            let (qr, w) = Fp::sqrt_ratio(&x, &y);
            if bool::from(qr) {
                assert_eq!(w.square() * y, x);
            } else {
                assert_eq!(w.square() * y, x.mul_by_5());
            }
        }
        assert!(bool::from(Fp::ZERO.invert().is_none()));
        assert_eq!(Fp::ZERO.sqrt().unwrap(), Fp::ZERO);
        assert_eq!(-Fp::ZERO, Fp::ZERO);
        // -1 is a square (p ≡ 1 mod 4); 5 and 22 are not.
        assert!(bool::from((-Fp::ONE).sqrt().is_some()));
        assert!(bool::from(
            Fp::from_canonical(&[5, 0, 0, 0, 0, 0]).sqrt().is_none()
        ));
        assert!(bool::from(
            Fp::from_canonical(&[22, 0, 0, 0, 0, 0]).sqrt().is_none()
        ));
    }

    #[test]
    fn wide_reduction_and_sign() {
        let mut wide = [0u8; 64];
        wide[15] = 1;
        wide[63] = 1;
        // 2^384 mod p is R (the Montgomery one as a plain integer).
        let v = Fp::from_bytes_wide(&wide);
        assert_eq!(v, Fp::from_canonical(&FP_R) + Fp::ONE);
        // All-ones: (2^512 - 1) mod p, checked via 2^512 = (2^384)·2^128.
        let all = Fp::from_bytes_wide(&[0xff; 64]);
        let two128 = Fp::from_canonical(&[0, 0, 1, 0, 0, 0]);
        assert_eq!(all, Fp::from_canonical(&FP_R) * two128 - Fp::ONE);
        assert!(bool::from((-Fp::ONE).lexicographically_largest()));
        assert!(!bool::from(Fp::ONE.lexicographically_largest()));
        assert!(!bool::from(Fp::ZERO.lexicographically_largest()));
        assert!(bool::from(Fp::ONE.is_odd()));
        assert!(!bool::from(Fp::ONE.double().is_odd()));
        assert!(!bool::from((-Fp::ONE).is_odd()));
    }
}
