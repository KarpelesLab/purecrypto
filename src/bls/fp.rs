//! The BLS12-381 base field `Fp`, `p = 0x1a0111ea…ffffaaab` (381 bits).
//!
//! Elements are six little-endian `u64` limbs in Montgomery form
//! (`a·2^384 mod p`), always canonical (`< p`). Every operation runs a fixed
//! schedule: the limb routines in [`mont`](super::mont) never branch on
//! values, inversion and square roots are Fermat exponentiations with a
//! public exponent, and the few conditional selections go through
//! [`Choice`]-driven masks. The only variable-time paths are the
//! `Option`/`bool` conversions at the API boundary, which are meant for
//! public data (decoding a serialized point).

use super::mont;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use crate::zeroize::Zeroize;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// The modulus `p`.
pub(crate) const MODULUS: [u64; 6] = [
    0xb9feffffffffaaab,
    0x1eabfffeb153ffff,
    0x6730d2a0f6b0f624,
    0x64774b84f38512bf,
    0x4b1ba7b6434bacd7,
    0x1a0111ea397fe69a,
];
/// `-p^(-1) mod 2^64`.
const INV: u64 = 0x89f3fffcfffcfffd;
/// `R = 2^384 mod p` (the Montgomery form of one).
const R: [u64; 6] = [
    0x760900000002fffd,
    0xebf4000bc40c0002,
    0x5f48985753c758ba,
    0x77ce585370525745,
    0x5c071a97a256ec6d,
    0x15f65ec3fa80e493,
];
/// `R^2 mod p`.
const R2: [u64; 6] = [
    0xf4df1f341c341746,
    0x0a76e6a609d104f1,
    0x8de5476c4c95b6d5,
    0x67eb88a9939d83c0,
    0x9a793e85b519952d,
    0x11988fe592cae3aa,
];
/// `R^3 mod p`.
const R3: [u64; 6] = [
    0xed48ac6bd94ca1e0,
    0x315f831e03a7adf8,
    0x9a53352a615e29dd,
    0x34c04e5e921e1761,
    0x2512d43565724728,
    0x0aa6346091755d4d,
];
/// `p - 2` (Fermat inversion exponent).
const P_MINUS_2: [u64; 6] = [
    0xb9feffffffffaaa9,
    0x1eabfffeb153ffff,
    0x6730d2a0f6b0f624,
    0x64774b84f38512bf,
    0x4b1ba7b6434bacd7,
    0x1a0111ea397fe69a,
];
/// `(p + 1) / 4` (square-root exponent; `p ≡ 3 mod 4`).
const P_PLUS_1_DIV_4: [u64; 6] = [
    0xee7fbfffffffeaab,
    0x07aaffffac54ffff,
    0xd9cc34a83dac3d89,
    0xd91dd2e13ce144af,
    0x92c6e9ed90d2eb35,
    0x0680447a8e5ff9a6,
];
/// `(p - 1) / 2` as canonical limbs (lexicographic sign threshold).
const P_MINUS_1_DIV_2: [u64; 6] = [
    0xdcff7fffffffd555,
    0x0f55ffff58a9ffff,
    0xb39869507b587b12,
    0xb23ba5c279c2895f,
    0x258dd3db21a5d66b,
    0x0d0088f51cbff34d,
];
/// `(p - 3) / 4` (the `sqrt_ratio_3mod4` exponent of RFC 9380 F.2.1.2).
pub(crate) const P_MINUS_3_DIV_4: [u64; 6] = [
    0xee7fbfffffffeaaa,
    0x07aaffffac54ffff,
    0xd9cc34a83dac3d89,
    0xd91dd2e13ce144af,
    0x92c6e9ed90d2eb35,
    0x0680447a8e5ff9a6,
];

/// An element of the BLS12-381 base field `GF(p)`.
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
    pub const ONE: Fp = Fp(R);

    /// Constant-time zero test.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        Choice::from((mont::is_nonzero_bit(&self.0) ^ 1) as u8)
    }

    /// `self + rhs`.
    #[inline]
    pub fn add(&self, rhs: &Fp) -> Fp {
        Fp(mont::add(&self.0, &rhs.0, &MODULUS))
    }

    /// `self - rhs`.
    #[inline]
    pub fn sub(&self, rhs: &Fp) -> Fp {
        Fp(mont::sub(&self.0, &rhs.0, &MODULUS))
    }

    /// `-self`.
    #[inline]
    pub fn neg(&self) -> Fp {
        Fp(mont::neg(&self.0, &MODULUS))
    }

    /// `2·self`.
    #[inline]
    pub fn double(&self) -> Fp {
        self.add(self)
    }

    /// `self · rhs`.
    #[inline]
    pub fn mul(&self, rhs: &Fp) -> Fp {
        Fp(mont::mul(&self.0, &rhs.0, &MODULUS, INV))
    }

    /// `self²`.
    #[inline]
    pub fn square(&self) -> Fp {
        Fp(mont::square(&self.0, &MODULUS, INV))
    }

    /// `self^e` for a little-endian limb exponent. Fixed square-and-multiply
    /// schedule over every bit of `e`: the running time depends only on the
    /// exponent's limb count, so it is constant time in `self` whenever the
    /// exponent is public (every use in this crate).
    #[inline]
    pub fn pow(&self, e: &[u64]) -> Fp {
        Fp(mont::pow(&self.0, e, &R, &MODULUS, INV))
    }

    /// Multiplicative inverse, `None` for zero (Fermat: `self^(p-2)`).
    #[inline]
    pub fn invert(&self) -> CtOption<Fp> {
        CtOption::new(self.pow(&P_MINUS_2), !self.is_zero())
    }

    /// A square root, `None` when `self` is a non-residue. With
    /// `p ≡ 3 (mod 4)` the candidate is `self^((p+1)/4)`; it is verified by
    /// squaring, so the presence flag is exact.
    #[inline]
    pub fn sqrt(&self) -> CtOption<Fp> {
        let cand = self.pow(&P_PLUS_1_DIV_4);
        CtOption::new(cand, cand.square().ct_eq(self))
    }

    /// The canonical integer representative as little-endian limbs (leaves
    /// Montgomery form by multiplying by 1).
    #[inline]
    pub(crate) fn to_canonical(self) -> [u64; 6] {
        let one = [1u64, 0, 0, 0, 0, 0];
        mont::mul(&self.0, &one, &MODULUS, INV)
    }

    /// Builds an element from canonical limbs (`< p`), entering Montgomery
    /// form.
    #[inline]
    pub(crate) fn from_canonical(limbs: &[u64; 6]) -> Fp {
        Fp(mont::mul(limbs, &R2, &MODULUS, INV))
    }

    /// The canonical 48-byte big-endian encoding.
    #[inline]
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        mont::to_be_bytes(&self.to_canonical(), &mut out);
        out
    }

    /// Decodes a 48-byte big-endian integer, `None` unless it is canonical
    /// (`< p`). The returned element is meaningful only when the flag is set
    /// (a non-canonical input yields an unspecified but harmless value).
    #[inline]
    pub fn from_bytes(bytes: &[u8; 48]) -> CtOption<Fp> {
        let limbs = mont::from_be_bytes::<6>(bytes);
        let ok = Choice::from(mont::lt_bit(&limbs, &MODULUS) as u8);
        CtOption::new(Fp::from_canonical(&limbs), ok)
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
        // mont(lo, R2) = lo·R (Montgomery form of lo);
        // mont(hi, R3) = hi·2^768 = (hi·2^384)·R.
        let lo_m = mont::mul(&lo, &R2, &MODULUS, INV);
        let hi_m = mont::mul(&hi, &R3, &MODULUS, INV);
        Fp(mont::add(&lo_m, &hi_m, &MODULUS))
    }

    /// True when the canonical representative is greater than `(p-1)/2`,
    /// i.e. `self > -self` — the ZCash "sort" flag for compressed points.
    #[inline]
    pub(crate) fn lexicographically_largest(&self) -> Choice {
        // self > (p-1)/2  <=>  !(self <= (p-1)/2)  <=>  !(self < (p-1)/2 + 1).
        let c = self.to_canonical();
        let mut t = P_MINUS_1_DIV_2;
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
        let s = s.as_bytes();
        for (i, o) in out.iter_mut().enumerate() {
            let hi = (s[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (s[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            *o = (hi << 4) | lo;
        }
        out
    }

    const P_HEX: &str = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

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
    }

    #[test]
    fn ring_axioms_and_inverse() {
        let mut x = Fp::from_bytes(&hex(
            "00f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        ))
        .unwrap();
        let y = Fp::from_bytes(&hex(
            "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
        ))
        .unwrap();
        for _ in 0..50 {
            assert_eq!(x * y, y * x);
            assert_eq!((x + y) * (x - y), x.square() - y.square());
            assert_eq!(x * x.invert().unwrap(), Fp::ONE);
            assert_eq!(x + (-x), Fp::ZERO);
            assert_eq!(x.double(), x + x);
            let s = x.square();
            let r = s.sqrt().unwrap();
            assert!(r == x || r == -x);
            x = x * y + Fp::ONE;
        }
        assert!(bool::from(Fp::ZERO.invert().is_none()));
        assert_eq!(-Fp::ZERO, Fp::ZERO);
    }

    #[test]
    fn wide_reduction_and_sign() {
        // 2^384 + 1 reduced: bytes = 00..01 (hi) || 00..01 (lo).
        let mut wide = [0u8; 64];
        wide[15] = 1;
        wide[63] = 1;
        // 2^384 mod p is R (the Montgomery one as a plain integer).
        let v = Fp::from_bytes_wide(&wide);
        let r_plus_1 = Fp::from_canonical(&R) + Fp::ONE;
        assert_eq!(v, r_plus_1);
        assert!(bool::from((-Fp::ONE).lexicographically_largest()));
        assert!(!bool::from(Fp::ONE.lexicographically_largest()));
        assert!(!bool::from(Fp::ZERO.lexicographically_largest()));
        assert!(bool::from(Fp::ONE.is_odd()));
        assert!(!bool::from(Fp::ONE.double().is_odd()));
        // -1 = p - 1 is even.
        assert!(!bool::from((-Fp::ONE).is_odd()));
        // 11 is a non-residue in Fp (it is the SSWU Z for G1).
        assert!(bool::from(
            Fp::from_canonical(&[11, 0, 0, 0, 0, 0]).sqrt().is_none()
        ));
        // -1 is a non-residue (p ≡ 3 mod 4).
        assert!(bool::from((-Fp::ONE).sqrt().is_none()));
    }
}
