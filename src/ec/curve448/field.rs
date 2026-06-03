//! The edwards448 base field GF(2⁴⁴⁸−2²²⁴−1) and curve constants.
//!
//! This is the shared field backend consumed by the Ed448 signing path
//! ([`crate::ec::ed448`]). All arithmetic is the constant-time [`MontModulus`]
//! over seven 64-bit limbs; field elements are held in Montgomery form
//! throughout.
//!
//! The prime is `p = 2⁴⁴⁸ − 2²²⁴ − 1`, and `p ≡ 3 (mod 4)`, so square roots are
//! the single exponentiation `√w = w^((p+1)/4)` (no `√−1` correction is needed,
//! unlike the `p ≡ 5 (mod 8)` edwards25519 field).

use crate::bignum::{MontModulus, Uint};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A field element, seven 64-bit limbs (448 bits).
pub(crate) type Fe = Uint<7>;

/// `p = 2⁴⁴⁸ − 2²²⁴ − 1` (big-endian hex, 112 nibbles).
const P_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
/// The edwards448 curve constant `d = −39081 mod p` (big-endian hex).
const D_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
ffffffffffffffffffffffffffffffffffffffffffffffffffff6756";
/// The group order `L = 2⁴⁴⁶ − 138...885` (big-endian hex, RFC 8032 §5.2).
const L_HEX: &str = "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff\
7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3";

/// The standard edwards448 base point `B`, as its 57-byte RFC 8032 §5.2
/// encoding (the canonical generator; `x` is even, so the sign bit is 0).
pub(crate) const BASE_ENC: [u8; 57] = {
    let mut b = [0u8; 57];
    // y (56 bytes, little-endian), then octet[56] sign bit = (Bx & 1) = 0.
    let yle: [u8; 56] = [
        0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98, 0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd,
        0xfd, 0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a, 0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c,
        0x78, 0x87, 0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b, 0x62, 0xc7, 0xc9, 0x56, 0x37,
        0x20, 0x76, 0x88, 0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
    ];
    let mut i = 0;
    while i < 56 {
        b[i] = yle[i];
        i += 1;
    }
    b
};

/// Parses 112 big-endian hex characters into a field element.
fn fe_from_be_hex(hex: &str) -> Fe {
    let h = hex.as_bytes();
    let mut bytes = [0u8; 56];
    let mut i = 0;
    while i < 56 {
        let hi = (h[2 * i] as char).to_digit(16).unwrap() as u8;
        let lo = (h[2 * i + 1] as char).to_digit(16).unwrap() as u8;
        bytes[i] = (hi << 4) | lo;
        i += 1;
    }
    Fe::from_be_bytes(&bytes)
}

/// Modular exponentiation in Montgomery form (`base` and the result are in
/// Montgomery domain). The exponent is public, so the fixed 448-step schedule
/// leaks nothing secret.
fn fe_pow(fp: &MontModulus<7>, one: &Fe, base: Fe, exp: &Fe) -> Fe {
    let mut r = *one;
    let limbs = exp.as_limbs();
    let mut i = 448;
    while i > 0 {
        i -= 1;
        r = fp.mont_mul(&r, &r);
        let bit = ((limbs[i / 64] >> (i % 64)) & 1) as u8;
        let prod = fp.mont_mul(&r, &base);
        // conditional_select(a, b, c) returns a when c is set (this crate's
        // convention): pick `prod` when the exponent bit is 1.
        r = Fe::conditional_select(&prod, &r, Choice::from(bit));
    }
    r
}

/// The edwards448 field together with the curve constants, all in Montgomery
/// form (except the integer constants `p`, `L`).
pub(crate) struct Field {
    fp: MontModulus<7>,
    /// `1` in Montgomery form.
    pub(crate) one: Fe,
    /// `d = −39081` in Montgomery form (the single Edwards constant; the
    /// `a = +1` formulas do not need `2d`).
    pub(crate) d: Fe,
    /// `p − 2` (the Fermat inversion exponent).
    p_minus_2: Fe,
    /// `(p − 3) / 4` (the square-root candidate exponent for `p ≡ 3 (mod 4)`).
    p_minus_3_div_4: Fe,
    /// The prime `p`.
    pub(crate) p: Fe,
    /// The group order `L`.
    pub(crate) l: Fe,
    /// `L` zero-extended to fifteen limbs, for reducing the 114-byte (912-bit)
    /// SHAKE256 outputs used as Ed448 nonces/challenges.
    pub(crate) l15: Uint<15>,
}

impl Field {
    pub(crate) fn new() -> Self {
        let p = fe_from_be_hex(P_HEX);
        let fp = MontModulus::new(p);
        let one = fp.to_mont(&Fe::ONE);
        let d = fp.to_mont(&fe_from_be_hex(D_HEX));
        let p_minus_2 = p.wrapping_sub(&Fe::from_u64(2));
        // (p − 3) / 4
        let p_minus_3_div_4 = p.wrapping_sub(&Fe::from_u64(3)).shr1().shr1();
        let l = fe_from_be_hex(L_HEX);
        let ll = l.as_limbs();
        let l15 = Uint::<15>::from_limbs([
            ll[0], ll[1], ll[2], ll[3], ll[4], ll[5], ll[6], 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        Field {
            fp,
            one,
            d,
            p_minus_2,
            p_minus_3_div_4,
            p,
            l,
            l15,
        }
    }

    #[inline]
    pub(crate) fn mul(&self, a: Fe, b: Fe) -> Fe {
        self.fp.mont_mul(&a, &b)
    }
    #[inline]
    pub(crate) fn sq(&self, a: Fe) -> Fe {
        self.fp.mont_mul(&a, &a)
    }
    #[inline]
    pub(crate) fn add(&self, a: Fe, b: Fe) -> Fe {
        self.fp.add_mod(&a, &b)
    }
    #[inline]
    pub(crate) fn sub(&self, a: Fe, b: Fe) -> Fe {
        self.fp.sub_mod(&a, &b)
    }
    #[inline]
    pub(crate) fn neg(&self, a: Fe) -> Fe {
        self.fp.sub_mod(&Fe::ZERO, &a)
    }
    #[inline]
    pub(crate) fn inv(&self, a: Fe) -> Fe {
        fe_pow(&self.fp, &self.one, a, &self.p_minus_2)
    }

    /// Converts a plain residue `< p` into Montgomery form.
    #[inline]
    pub(crate) fn to_mont(&self, x: &Fe) -> Fe {
        self.fp.to_mont(x)
    }

    /// Converts a Montgomery-form element back to a plain residue.
    #[inline]
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn from_mont(&self, x: &Fe) -> Fe {
        self.fp.from_mont(x)
    }

    /// Constant-time equality of two Montgomery-form elements.
    #[inline]
    pub(crate) fn ct_eq(&self, a: Fe, b: Fe) -> Choice {
        a.ct_eq(&b)
    }

    /// Raises a Montgomery-form element to a (public) exponent given as a plain
    /// integer `Fe`.
    #[inline]
    pub(crate) fn pow(&self, base: Fe, exp: &Fe) -> Fe {
        fe_pow(&self.fp, &self.one, base, exp)
    }

    /// Square root of the ratio `u / v` for the `p ≡ 3 (mod 4)` field.
    ///
    /// Returns `(is_square, r)` where, when `v ≠ 0` and `u/v` is a quadratic
    /// residue, `is_square` is true and `r` is a square root of `u/v` (one of
    /// the two; the caller imposes the sign). When `u/v` is a non-residue, or
    /// `v = 0`, `is_square` is false and `r` is unspecified.
    ///
    /// Uses the standard `p ≡ 3 (mod 4)` identity
    /// `r = u·v·(u·v³)^((p−3)/4)`, which satisfies `v·r² = u` exactly when
    /// `u/v` is a square. Constant time in `u`, `v`.
    pub(crate) fn sqrt_ratio(&self, u: Fe, v: Fe) -> (Choice, Fe) {
        let v2 = self.sq(v);
        let v3 = self.mul(v2, v);
        let uv3 = self.mul(u, v3);
        let pw = self.pow(uv3, &self.p_minus_3_div_4);
        let r = self.mul(self.mul(u, v), pw);

        // Validate: v·r² must equal u for a genuine root.
        let check = self.mul(v, self.sq(r));
        let is_square = self.ct_eq(check, u);
        (is_square, r)
    }
}
