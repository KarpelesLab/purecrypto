//! The edwards25519 base field GF(2²⁵⁵−19) and curve constants.
//!
//! This is the shared field backend consumed by the audited Ed25519 signing
//! path ([`crate::ec::ed25519`]), the [`crate::ec::edwards25519::hazmat`]
//! exposure, and the [`crate::ec::ristretto255`] group. All arithmetic is the
//! constant-time [`MontModulus`] over four 64-bit limbs; field elements are
//! held in Montgomery form throughout.

use crate::bignum::{MontModulus, Uint};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};

/// A field element, four 64-bit limbs (256 bits).
pub(crate) type Fe = Uint<4>;

/// `p = 2²⁵⁵ − 19` (big-endian hex).
const P_HEX: &str = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
/// The curve constant `d = −121665/121666 mod p` (big-endian hex).
const D_HEX: &str = "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3";
/// The group order `L = 2²⁵² + 27742317777372353535851937790883648493`.
const L_HEX: &str = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

/// The standard base point `B`, as its 32-byte RFC 8032 encoding (`y = 4/5`,
/// with an even `x`).
// Library-path base multiplications go through the precomputed comb table;
// only the ristretto255 group API (and tests) still decompress `B` itself, so
// gate to match [`Field::base`] and avoid dead_code on the default build.
#[cfg(any(test, feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub(crate) const BASE_ENC: [u8; 32] = {
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    b
};

/// Parses 64 big-endian hex characters into a field element.
fn fe_from_be_hex(hex: &str) -> Fe {
    crate::ec::uint_from_be_hex(hex)
}

/// Modular exponentiation in Montgomery form (`base` and the result are in
/// Montgomery domain). The exponent is public, so the fixed 256-step schedule
/// leaks nothing secret.
fn fe_pow(fp: &MontModulus<4>, one: &Fe, base: Fe, exp: &Fe) -> Fe {
    let mut r = *one;
    let limbs = exp.as_limbs();
    let mut i = 256;
    while i > 0 {
        i -= 1;
        r = fp.mont_sqr(&r);
        let bit = ((limbs[i / 64] >> (i % 64)) & 1) as u8;
        let prod = fp.mont_mul(&r, &base);
        // conditional_select(a, b, c) returns a when c is set (this crate's
        // convention): pick `prod` when the exponent bit is 1.
        r = Fe::conditional_select(&prod, &r, Choice::from(bit));
    }
    r
}

/// The edwards25519 field together with the curve constants, all in Montgomery
/// form (except the integer constants `p`, `L`).
pub(crate) struct Field {
    fp: MontModulus<4>,
    /// `1` in Montgomery form.
    pub(crate) one: Fe,
    /// `d` in Montgomery form.
    pub(crate) d: Fe,
    /// `2·d` in Montgomery form (for the addition formula).
    pub(crate) d2: Fe,
    /// `√−1 mod p` in Montgomery form (for point decompression).
    pub(crate) sqrtm1: Fe,
    /// `p − 2` (the Fermat inversion exponent).
    p_minus_2: Fe,
    /// `(p − 5) / 8` (the candidate-root exponent).
    p_minus_5_div_8: Fe,
    /// The prime `p`.
    pub(crate) p: Fe,
    /// The group order `L`.
    pub(crate) l: Fe,
    /// `L` zero-extended to eight limbs, for reducing 512-bit scalars.
    pub(crate) l8: Uint<8>,
}

impl Field {
    pub(crate) fn new() -> Self {
        let p = fe_from_be_hex(P_HEX);
        let fp = MontModulus::new(p);
        let one = fp.to_mont(&Fe::ONE);
        let d = fp.to_mont(&fe_from_be_hex(D_HEX));
        let d2 = fp.add_mod(&d, &d);
        let p_minus_2 = p.wrapping_sub(&Fe::from_u64(2));
        let p_minus_5_div_8 = p.wrapping_sub(&Fe::from_u64(5)).shr1().shr1().shr1();
        let p_minus_1_div_4 = p.wrapping_sub(&Fe::ONE).shr1().shr1();
        // √−1 = 2^((p−1)/4) mod p.
        let two = fp.to_mont(&Fe::from_u64(2));
        let sqrtm1 = fe_pow(&fp, &one, two, &p_minus_1_div_4);
        let l = fe_from_be_hex(L_HEX);
        let ll = l.as_limbs();
        let l8 = Uint::<8>::from_limbs([ll[0], ll[1], ll[2], ll[3], 0, 0, 0, 0]);
        Field {
            fp,
            one,
            d,
            d2,
            sqrtm1,
            p_minus_2,
            p_minus_5_div_8,
            p,
            l,
            l8,
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

    /// Tests (constant-time) whether the Montgomery-form element is zero.
    // Only the ristretto255 encode/decode path calls this; the always-on
    // Ed25519 signing path does not, so gate it to avoid a dead-code warning on
    // the default build.
    #[cfg(feature = "ristretto255")]
    #[inline]
    pub(crate) fn is_zero(&self, a: Fe) -> Choice {
        self.fp.from_mont(&a).ct_eq(&Fe::ZERO)
    }

    /// Tests (constant-time) whether the canonical residue of the element is
    /// odd (its least-significant bit). Used as the "sign" bit in encodings.
    #[inline]
    pub(crate) fn is_negative(&self, a: Fe) -> Choice {
        Choice::from(self.fp.from_mont(&a).is_odd().unwrap_u8())
    }

    /// Constant-time equality of two Montgomery-form elements.
    #[inline]
    pub(crate) fn ct_eq(&self, a: Fe, b: Fe) -> Choice {
        a.ct_eq(&b)
    }

    /// Conditionally negates `a` (in place semantics by return) when `c` is set.
    #[inline]
    pub(crate) fn conditional_negate(&self, a: Fe, c: Choice) -> Fe {
        Fe::conditional_select(&self.neg(a), &a, c)
    }

    /// Raises a Montgomery-form element to a (public) exponent given as a plain
    /// integer `Fe`.
    #[inline]
    pub(crate) fn pow(&self, base: Fe, exp: &Fe) -> Fe {
        fe_pow(&self.fp, &self.one, base, exp)
    }

    /// The named RFC 9496 §3.1.3 "square root of `u/v`" routine.
    ///
    /// Given Montgomery-form `u`, `v`, computes a candidate
    /// `r = (u/v)^((p+3)/8)` (as `u·v³·(u·v⁷)^((p−5)/8)`) and corrects it by
    /// `√−1` when needed. Returns `(was_square, r)` exactly per the RFC:
    ///
    /// - if `v` is nonzero and `u/v` is square, `was_square` is true and
    ///   `r = +√(u/v)` (the non-negative root);
    /// - if `v` is nonzero and `u/v` is not square, `was_square` is false and
    ///   `r = +√(i·u/v)` with `i = √−1` (the non-negative root);
    /// - if `u = 0`, `was_square` is true and `r = 0`;
    /// - if `v = 0` (and `u ≠ 0`), `was_square` is false and `r = 0`.
    ///
    /// The returned `r` is always non-negative (even least-significant bit).
    /// ristretto255 (encode/decode/one-way map) relies on these exact
    /// semantics; Ed25519 point decompression also calls it and re-imposes its
    /// own sign bit afterwards, so the normalization here is harmless there.
    pub(crate) fn sqrt_ratio_i(&self, u: Fe, v: Fe) -> (Choice, Fe) {
        // candidate r = u·v³·(u·v⁷)^((p−5)/8)
        let v3 = self.mul(self.sq(v), v);
        let v7 = self.mul(self.sq(v3), v);
        let pw = self.pow(self.mul(u, v7), &self.p_minus_5_div_8);
        let r = self.mul(self.mul(u, v3), pw);

        // check = v·r²; compare against ±u and ±i·u.
        let check = self.mul(v, self.sq(r));
        let neg_u = self.neg(u);
        let i_u = self.mul(self.sqrtm1, u);
        let neg_i_u = self.neg(i_u);

        let correct_sign = self.ct_eq(check, u);
        let flipped_sign = self.ct_eq(check, neg_u);
        let flipped_sign_i = self.ct_eq(check, neg_i_u);

        // r·√−1 is used in the non-square (or i-flipped) branch.
        let r_prime = self.mul(self.sqrtm1, r);
        let use_r_prime = flipped_sign | flipped_sign_i;
        let r = Fe::conditional_select(&r_prime, &r, use_r_prime);

        // Normalize to the non-negative root.
        let r = self.abs(r);

        let was_square = correct_sign | flipped_sign;
        (was_square, r)
    }

    /// The non-negative representative `|a|`: negates `a` iff its canonical
    /// residue is odd. Constant-time. (RFC 9496 `CT_ABS`.)
    #[inline]
    pub(crate) fn abs(&self, a: Fe) -> Fe {
        self.conditional_negate(a, self.is_negative(a))
    }
}
