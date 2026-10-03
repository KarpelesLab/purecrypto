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

use super::point::Point;
use crate::bignum::{MontModulus, Uint};
#[cfg(test)]
use crate::ct::ConditionallySelectable;
use crate::ct::{Choice, ConstantTimeEq};

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

/// The affine coordinates of the standard edwards448 base point `B`
/// (RFC 8032 §5.2, big-endian hex).
const BX_HEX: &str = "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324\
a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e";
const BY_HEX: &str = "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e\
05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14";

/// The standard edwards448 base point `B`, as its 57-byte RFC 8032 §5.2
/// encoding (the canonical generator; `x` is even, so the sign bit is 0).
/// The library uses the precomputed [`Field::base`] point; this encoding is
/// what the tests decompress to check it.
#[cfg(test)]
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
const fn fe_from_be_hex(hex: &str) -> Fe {
    crate::ec::uint_from_be_hex(hex)
}

/// Generic square-and-multiply exponentiation in Montgomery form, the
/// reference the fixed addition chains are checked against.
#[cfg(test)]
fn fe_pow(fp: &MontModulus<7>, one: &Fe, base: Fe, exp: &Fe) -> Fe {
    let mut r = *one;
    let limbs = exp.as_limbs();
    let mut i = 448;
    while i > 0 {
        i -= 1;
        r = fp.mont_sqr(&r);
        let bit = ((limbs[i / 64] >> (i % 64)) & 1) as u8;
        let prod = fp.mont_mul(&r, &base);
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
    /// The prime `p`.
    pub(crate) p: Fe,
    /// The group order `L`.
    pub(crate) l: Fe,
    /// The base point `B` in extended coordinates (Montgomery form, `Z = 1`),
    /// so `[k]B` needs no per-call decompression (a 446-bit exponentiation).
    pub(crate) base_point: Point,
}

/// The field context, built once at compile time: the `R² mod p` setup,
/// the Montgomery conversions of `1` and `d` and the hex decoding all run in
/// `const` evaluation instead of on every operation.
static FIELD: Field = Field::build();

impl Field {
    /// The shared, compile-time-built field context.
    #[inline]
    pub(crate) fn new() -> &'static Self {
        &FIELD
    }

    const fn build() -> Self {
        let p = fe_from_be_hex(P_HEX);
        let fp = MontModulus::new(p);
        let one = fp.to_mont(&Fe::ONE);
        let d = fp.to_mont(&fe_from_be_hex(D_HEX));
        let l = fe_from_be_hex(L_HEX);
        let bx = fp.to_mont(&fe_from_be_hex(BX_HEX));
        let by = fp.to_mont(&fe_from_be_hex(BY_HEX));
        let base_point = Point {
            x: bx,
            y: by,
            z: one,
            t: fp.mont_mul(&bx, &by),
        };
        Field {
            fp,
            one,
            d,
            p,
            l,
            base_point,
        }
    }

    #[inline]
    pub(crate) fn mul(&self, a: Fe, b: Fe) -> Fe {
        self.fp.mont_mul(&a, &b)
    }
    #[inline]
    pub(crate) fn sq(&self, a: Fe) -> Fe {
        self.fp.mont_sqr(&a)
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
    /// `a` squared `n` times.
    #[inline]
    fn sqn(&self, a: Fe, n: u32) -> Fe {
        let mut r = a;
        for _ in 0..n {
            r = self.sq(r);
        }
        r
    }

    /// `a^((p−3)/4)` by a fixed addition chain (451 squarings, 12
    /// multiplications), the shared core of inversion and square roots.
    ///
    /// `(p−3)/4 = 2⁴⁴⁶ − 2²²² − 1 = (2²²³ − 1)·2²²³ + (2²²² − 1)`, so with
    /// `eₖ = a^(2ᵏ−1)` the result is `e₂₂₃^(2²²³) · e₂₂₂`, and the `eₖ` are
    /// built by `e_{j+k} = e_j^(2ᵏ) · eₖ`. The exponent is public and the
    /// schedule fixed, so this is constant time in `a` — and roughly half the
    /// work of the bit-at-a-time ladder (448 squarings plus 448 masked
    /// multiplications).
    fn pow_p3_4(&self, a: Fe) -> Fe {
        let e1 = a;
        let e2 = self.mul(self.sq(e1), e1);
        let e3 = self.mul(self.sq(e2), e1);
        let e6 = self.mul(self.sqn(e3, 3), e3);
        let e12 = self.mul(self.sqn(e6, 6), e6);
        let e24 = self.mul(self.sqn(e12, 12), e12);
        let e30 = self.mul(self.sqn(e24, 6), e6);
        let e48 = self.mul(self.sqn(e24, 24), e24);
        let e96 = self.mul(self.sqn(e48, 48), e48);
        let e192 = self.mul(self.sqn(e96, 96), e96);
        let e222 = self.mul(self.sqn(e192, 30), e30);
        let e223 = self.mul(self.sq(e222), e1);
        self.mul(self.sqn(e223, 223), e222)
    }

    /// `a⁻¹ = a^(p−2)` (Fermat; `0` maps to `0`). `p − 2 = 4·(p−3)/4 + 1`,
    /// so this is [`Self::pow_p3_4`] plus two squarings and a multiply.
    #[inline]
    pub(crate) fn inv(&self, a: Fe) -> Fe {
        self.mul(self.sqn(self.pow_p3_4(a), 2), a)
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
        let pw = self.pow_p3_4(uv3);
        let r = self.mul(self.mul(u, v), pw);

        // Validate: v·r² must equal u for a genuine root.
        let check = self.mul(v, self.sq(r));
        let is_square = self.ct_eq(check, u);
        (is_square, r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic splitmix64 stream for the differential sweeps.
    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// The addition chains agree with the generic ladder on the exponents
    /// they replace (`p − 2` and `(p − 3) / 4`), over edge values and a
    /// random sweep.
    #[test]
    fn addition_chains_match_generic_pow() {
        let f = Field::new();
        let p_minus_2 = f.p.wrapping_sub(&Fe::from_u64(2));
        let p_minus_3_div_4 = f.p.wrapping_sub(&Fe::from_u64(3)).shr1().shr1();
        let edges = [
            Fe::ZERO,
            Fe::ONE,
            Fe::from_u64(2),
            f.p.wrapping_sub(&Fe::ONE),
            f.p.wrapping_sub(&Fe::from_u64(2)),
            f.d,
        ];
        let mut st = 0x448;
        let random = core::iter::repeat_with(|| {
            let mut l = [0u64; 7];
            for x in l.iter_mut() {
                *x = splitmix(&mut st);
            }
            Fe::from_limbs(l).reduce(&f.p)
        })
        .take(64);
        for x in edges.into_iter().chain(random) {
            let xm = f.to_mont(&x);
            assert_eq!(
                f.inv(xm),
                fe_pow(&f.fp, &f.one, xm, &p_minus_2),
                "inv mismatch"
            );
            assert_eq!(
                f.pow_p3_4(xm),
                fe_pow(&f.fp, &f.one, xm, &p_minus_3_div_4),
                "pow_p3_4 mismatch"
            );
            if !bool::from(x.ct_eq(&Fe::ZERO)) {
                assert_eq!(f.mul(f.inv(xm), xm), f.one);
            }
        }
    }
}
