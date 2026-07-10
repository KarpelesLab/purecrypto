//! The edwards25519 base field GF(2²⁵⁵−19) and curve constants.
//!
//! This is the shared field backend consumed by the audited Ed25519 signing
//! path ([`crate::ec::ed25519`]), the [`crate::ec::edwards25519::hazmat`]
//! exposure, the [`crate::ec::ristretto255`] group, and X25519.
//!
//! Field elements use the classic unsaturated **5×51-bit limb**
//! representation (as in curve25519-donna / dalek's `FieldElement51`): an
//! element is `Σ limbs[i]·2^(51·i)` with each limb held in a `u64`.
//! Multiplication and squaring expand into `u128` partial products with the
//! `2^255 ≡ 19 (mod p)` folding, followed by a fixed carry chain; reduction is
//! lazy (values are kept merely *bounded*, not canonical, until
//! [`Fe::to_bytes`] performs the full canonical reduction). Everything is
//! branch-free and table-free, so the arithmetic is constant-time by
//! construction.
//!
//! # Bounds discipline
//!
//! Every `Fe` produced by this module has limbs `< 2^51 + 2^13` (the output
//! of [`Fe::weak_reduce`] or of the multiply carry chain). All operations
//! accept limbs up to `2^54`, so sums of a few reduced elements are always
//! safe inputs; to keep the invariant trivial to audit, `add`/`sub`/`neg`
//! re-reduce their results before returning.

use crate::bignum::Uint;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};

/// The saturated 4×u64 integer type used for order-`L` scalars and for
/// byte-level canonicity checks (`< p`, `< L`) on wire encodings.
pub(crate) type ScalarInt = Uint<4>;

/// 51-bit limb mask.
const M51: u64 = (1u64 << 51) - 1;

/// `16·p` spread as five per-limb constants (`16·(2^51−19)` then
/// `16·(2^51−1)`), added before a limbwise subtraction so intermediate limbs
/// never underflow (the standard donna trick).
const SIXTEEN_P: [u64; 5] = [
    0x7ffffffffffed0,
    0x7ffffffffffff0,
    0x7ffffffffffff0,
    0x7ffffffffffff0,
    0x7ffffffffffff0,
];

/// A field element of GF(2²⁵⁵−19) in unsaturated 5×51-bit limb form.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe(pub(crate) [u64; 5]);

/// `p = 2²⁵⁵ − 19` as a saturated integer (for canonicity checks).
pub(crate) const P_INT: ScalarInt = ScalarInt::from_limbs([
    0xffffffffffffffed,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x7fffffffffffffff,
]);

/// The group order `L = 2²⁵² + 27742317777372353535851937790883648493`.
pub(crate) const L_INT: ScalarInt = ScalarInt::from_limbs([
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
]);

/// The standard base point `B`, as its 32-byte RFC 8032 encoding (`y = 4/5`,
/// with an even `x`).
// Library-path base multiplications go through the precomputed comb table;
// only the ristretto255 group API (and tests) still decompress `B` itself, so
// gate to match usage and avoid dead_code on the default build.
#[cfg(any(test, feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub(crate) const BASE_ENC: [u8; 32] = {
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    b
};

#[inline(always)]
fn m(a: u64, b: u64) -> u128 {
    (a as u128) * (b as u128)
}

impl Fe {
    /// The additive identity `0`.
    pub(crate) const ZERO: Fe = Fe([0; 5]);
    /// The multiplicative identity `1`.
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0]);
    /// The curve constant `d = −121665/121666 mod p`. Verified by
    /// `tests::curve_constants_recompute`.
    pub(crate) const D: Fe = Fe([
        0x34dca135978a3,
        0x1a8283b156ebd,
        0x5e7a26001c029,
        0x739c663a03cbb,
        0x52036cee2b6ff,
    ]);
    /// `2·d mod p` (for the HWCD addition formula). Verified by
    /// `tests::curve_constants_recompute`.
    pub(crate) const D2: Fe = Fe([
        0x69b9426b2f159,
        0x35050762add7a,
        0x3cf44c0038052,
        0x6738cc7407977,
        0x2406d9dc56dff,
    ]);
    /// `√−1 = 2^((p−1)/4) mod p` (for point decompression / sqrt_ratio).
    /// Verified by `tests::curve_constants_recompute`.
    pub(crate) const SQRT_M1: Fe = Fe([
        0x61b274a0ea0b0,
        0x0d5a5fc8f189d,
        0x7ef5e9cbd0c60,
        0x78595a6804c9e,
        0x2b8324804fc1d,
    ]);

    /// A small integer as a field element.
    #[cfg(test)]
    pub(crate) const fn from_u64(v: u64) -> Fe {
        Fe([v & M51, v >> 51, 0, 0, 0])
    }

    /// One pass of carry propagation with the `2^255 ≡ 19` fold. Accepts any
    /// limbs `< 2^63`; the result's limbs are `< 2^51 + 2^13·19`.
    #[inline(always)]
    fn weak_reduce(mut l: [u64; 5]) -> Fe {
        let c0 = l[0] >> 51;
        let c1 = l[1] >> 51;
        let c2 = l[2] >> 51;
        let c3 = l[3] >> 51;
        let c4 = l[4] >> 51;
        l[0] &= M51;
        l[1] &= M51;
        l[2] &= M51;
        l[3] &= M51;
        l[4] &= M51;
        l[0] += c4 * 19;
        l[1] += c0;
        l[2] += c1;
        l[3] += c2;
        l[4] += c3;
        Fe(l)
    }

    /// Parses a 32-byte little-endian encoding. The top bit (bit 255) is
    /// ignored, so the value is `< 2^255`; it is **not** required to be a
    /// canonical residue `< p` (the lazy representation is closed over
    /// non-canonical inputs, and [`Self::to_bytes`] canonicalizes on the way
    /// out). Callers that must reject non-canonical encodings check the raw
    /// bytes against [`P_INT`] first.
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Fe {
        #[inline(always)]
        fn load8(b: &[u8]) -> u64 {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b[..8]);
            u64::from_le_bytes(a)
        }
        Fe([
            load8(&bytes[0..]) & M51,
            (load8(&bytes[6..]) >> 3) & M51,
            (load8(&bytes[12..]) >> 6) & M51,
            (load8(&bytes[19..]) >> 1) & M51,
            (load8(&bytes[24..]) >> 12) & M51,
        ])
    }

    /// The canonical 32-byte little-endian encoding: performs the full
    /// reduction to the unique residue in `[0, p)`. Constant-time.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        // First bring all limbs under 2^52.
        let mut l = Fe::weak_reduce(self.0).0;

        // Compute q = ⌊value / p⌋ ∈ {0, 1} branch-free: q = 1 exactly when
        // value + 19 ≥ 2^255, i.e. when adding 19 carries all the way out of
        // limb 4.
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;

        // value − q·p = value + 19·q − q·2^255 (the 2^255 subtraction is the
        // final mask).
        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= M51;
        l[2] += l[1] >> 51;
        l[1] &= M51;
        l[3] += l[2] >> 51;
        l[2] &= M51;
        l[4] += l[3] >> 51;
        l[3] &= M51;
        l[4] &= M51;

        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&(l[0] | (l[1] << 51)).to_le_bytes());
        out[8..16].copy_from_slice(&((l[1] >> 13) | (l[2] << 38)).to_le_bytes());
        out[16..24].copy_from_slice(&((l[2] >> 26) | (l[3] << 25)).to_le_bytes());
        out[24..32].copy_from_slice(&((l[3] >> 39) | (l[4] << 12)).to_le_bytes());
        out
    }

    /// `self + rhs`, reduced.
    #[inline]
    pub(crate) fn add(&self, rhs: &Fe) -> Fe {
        let a = &self.0;
        let b = &rhs.0;
        Fe::weak_reduce([
            a[0] + b[0],
            a[1] + b[1],
            a[2] + b[2],
            a[3] + b[3],
            a[4] + b[4],
        ])
    }

    /// `self − rhs`, reduced. Adds `16·p` first so no limb underflows.
    #[inline]
    pub(crate) fn sub(&self, rhs: &Fe) -> Fe {
        let a = &self.0;
        let b = &rhs.0;
        Fe::weak_reduce([
            (a[0] + SIXTEEN_P[0]) - b[0],
            (a[1] + SIXTEEN_P[1]) - b[1],
            (a[2] + SIXTEEN_P[2]) - b[2],
            (a[3] + SIXTEEN_P[3]) - b[3],
            (a[4] + SIXTEEN_P[4]) - b[4],
        ])
    }

    /// `−self`, reduced.
    #[inline]
    pub(crate) fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    /// `self · rhs`: 25 `u128` partial products with ×19 folding and a fixed
    /// carry chain. Inputs may have limbs up to `2^54`; output limbs are
    /// `< 2^51 + 2^13`.
    pub(crate) fn mul(&self, rhs: &Fe) -> Fe {
        let a = &self.0;
        let b = &rhs.0;

        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;

        let c0 = m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19);
        let c1 = m(a[0], b[1]) + m(a[1], b[0]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19);
        let c2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[4], b3_19) + m(a[3], b4_19);
        let c3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4_19);
        let c4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);

        Fe::carry_chain(c0, c1, c2, c3, c4)
    }

    /// `self²`: 15 `u128` partial products (squaring symmetry) with ×19
    /// folding. Same bounds as [`Self::mul`].
    pub(crate) fn sq(&self) -> Fe {
        let a = &self.0;
        let a3_19 = a[3] * 19;
        let a4_19 = a[4] * 19;

        let c0 = m(a[0], a[0]) + ((m(a[1], a4_19) + m(a[2], a3_19)) << 1);
        let c1 = m(a[3], a3_19) + ((m(a[0], a[1]) + m(a[2], a4_19)) << 1);
        let c2 = m(a[1], a[1]) + ((m(a[0], a[2]) + m(a[4], a3_19)) << 1);
        let c3 = m(a[4], a4_19) + ((m(a[0], a[3]) + m(a[1], a[2])) << 1);
        let c4 = m(a[2], a[2]) + ((m(a[0], a[4]) + m(a[1], a[3])) << 1);

        Fe::carry_chain(c0, c1, c2, c3, c4)
    }

    /// The shared post-product carry chain: propagates 51-bit carries once,
    /// folds the limb-4 carry back into limb 0 via ×19, and does one final
    /// 0→1 carry, leaving all limbs `< 2^51 + 2^13`.
    #[inline(always)]
    fn carry_chain(c0: u128, mut c1: u128, mut c2: u128, mut c3: u128, mut c4: u128) -> Fe {
        let mut out = [0u64; 5];
        c1 += (c0 >> 51) as u64 as u128;
        out[0] = (c0 as u64) & M51;
        c2 += (c1 >> 51) as u64 as u128;
        out[1] = (c1 as u64) & M51;
        c3 += (c2 >> 51) as u64 as u128;
        out[2] = (c2 as u64) & M51;
        c4 += (c3 >> 51) as u64 as u128;
        out[3] = (c3 as u64) & M51;
        let carry = (c4 >> 51) as u64;
        out[4] = (c4 as u64) & M51;
        out[0] += carry * 19;
        out[1] += out[0] >> 51;
        out[0] &= M51;
        Fe(out)
    }

    /// `self^(2^k)`: `k` back-to-back squarings.
    #[inline]
    pub(crate) fn sqn(&self, k: u32) -> Fe {
        let mut r = self.sq();
        for _ in 1..k {
            r = r.sq();
        }
        r
    }

    /// The shared prefix of the two public-exponent chains: returns
    /// `(self^(2^250 − 1), self^11)` (the classic curve25519-donna /
    /// Bernstein addition chain).
    fn pow22501(&self) -> (Fe, Fe) {
        let z2 = self.sq(); // 2
        let z9 = z2.sqn(2).mul(self); // 9
        let z11 = z9.mul(&z2); // 11
        let z2_5_0 = z11.sq().mul(&z9); // 2^5 − 1
        let z2_10_0 = z2_5_0.sqn(5).mul(&z2_5_0); // 2^10 − 1
        let z2_20_0 = z2_10_0.sqn(10).mul(&z2_10_0); // 2^20 − 1
        let z2_40_0 = z2_20_0.sqn(20).mul(&z2_20_0); // 2^40 − 1
        let z2_50_0 = z2_40_0.sqn(10).mul(&z2_10_0); // 2^50 − 1
        let z2_100_0 = z2_50_0.sqn(50).mul(&z2_50_0); // 2^100 − 1
        let z2_200_0 = z2_100_0.sqn(100).mul(&z2_100_0); // 2^200 − 1
        let z2_250_0 = z2_200_0.sqn(50).mul(&z2_50_0); // 2^250 − 1
        (z2_250_0, z11)
    }

    /// The multiplicative inverse `self^(p−2) = self^(2^255 − 21)` via the
    /// standard 254-squaring / 11-multiply addition chain — constant-time by
    /// construction (fixed operation schedule, no exponent scanning). The
    /// "inverse" of `0` is `0`.
    pub(crate) fn invert(&self) -> Fe {
        let (z2_250_0, z11) = self.pow22501();
        z2_250_0.sqn(5).mul(&z11) // 2^255 − 21
    }

    /// `self^((p−5)/8) = self^(2^252 − 3)`, the candidate-root exponent used
    /// by `sqrt_ratio_i`. Same fixed addition chain discipline as
    /// [`Self::invert`].
    pub(crate) fn pow_p58(&self) -> Fe {
        let (z2_250_0, _) = self.pow22501();
        z2_250_0.sqn(2).mul(self) // 2^252 − 3
    }

    /// Constant-time equality (compares canonical encodings).
    #[inline]
    pub(crate) fn ct_eq_fe(&self, other: &Fe) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }

    /// Constant-time zero test (on the canonical residue).
    #[inline]
    pub(crate) fn is_zero(&self) -> Choice {
        self.to_bytes().ct_eq(&[0u8; 32])
    }

    /// Whether the canonical residue is odd (its least-significant bit) —
    /// the "sign" bit in encodings. Constant-time.
    #[inline]
    pub(crate) fn is_negative(&self) -> Choice {
        Choice::from(self.to_bytes()[0] & 1)
    }
}

impl ConditionallySelectable for Fe {
    #[inline]
    fn conditional_select(a: &Fe, b: &Fe, choice: Choice) -> Fe {
        Fe(<[u64; 5]>::conditional_select(&a.0, &b.0, choice))
    }
}

impl ConstantTimeEq for Fe {
    #[inline]
    fn ct_eq(&self, other: &Fe) -> Choice {
        self.ct_eq_fe(other)
    }
}

/// The edwards25519 field context: curve constants (compile-time literals,
/// verified by an always-on test) plus the order-`L` integers for the scalar
/// side. Constructing it is trivial — no field ops are performed.
pub(crate) struct Field {
    /// `1`.
    pub(crate) one: Fe,
    /// The curve constant `d`.
    pub(crate) d: Fe,
    /// `2·d` (for the addition formula).
    pub(crate) d2: Fe,
    /// `√−1 mod p` (for point decompression).
    pub(crate) sqrtm1: Fe,
    /// The prime `p`, as a saturated integer for encoding canonicity checks.
    pub(crate) p: ScalarInt,
    /// The group order `L`.
    pub(crate) l: ScalarInt,
    /// `L` zero-extended to eight limbs, for reducing 512-bit scalars.
    pub(crate) l8: Uint<8>,
}

impl Field {
    pub(crate) fn new() -> Self {
        let ll = L_INT.as_limbs();
        Field {
            one: Fe::ONE,
            d: Fe::D,
            d2: Fe::D2,
            sqrtm1: Fe::SQRT_M1,
            p: P_INT,
            l: L_INT,
            l8: Uint::<8>::from_limbs([ll[0], ll[1], ll[2], ll[3], 0, 0, 0, 0]),
        }
    }

    #[inline]
    pub(crate) fn mul(&self, a: Fe, b: Fe) -> Fe {
        a.mul(&b)
    }
    #[inline]
    pub(crate) fn sq(&self, a: Fe) -> Fe {
        a.sq()
    }
    #[inline]
    pub(crate) fn add(&self, a: Fe, b: Fe) -> Fe {
        a.add(&b)
    }
    #[inline]
    pub(crate) fn sub(&self, a: Fe, b: Fe) -> Fe {
        a.sub(&b)
    }
    #[inline]
    pub(crate) fn neg(&self, a: Fe) -> Fe {
        a.neg()
    }
    #[inline]
    pub(crate) fn inv(&self, a: Fe) -> Fe {
        a.invert()
    }

    /// Tests (constant-time) whether the canonical residue of the element is
    /// odd (its least-significant bit). Used as the "sign" bit in encodings.
    #[inline]
    pub(crate) fn is_negative(&self, a: Fe) -> Choice {
        a.is_negative()
    }

    /// Constant-time equality of two field elements (as residues).
    #[inline]
    pub(crate) fn ct_eq(&self, a: Fe, b: Fe) -> Choice {
        a.ct_eq_fe(&b)
    }

    /// Conditionally negates `a` (in place semantics by return) when `c` is set.
    #[inline]
    pub(crate) fn conditional_negate(&self, a: Fe, c: Choice) -> Fe {
        Fe::conditional_select(&a.neg(), &a, c)
    }

    /// The named RFC 9496 §3.1.3 "square root of `u/v`" routine.
    ///
    /// Computes a candidate `r = (u/v)^((p+3)/8)` (as `u·v³·(u·v⁷)^((p−5)/8)`)
    /// and corrects it by `√−1` when needed. Returns `(was_square, r)` exactly
    /// per the RFC:
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
        let pw = self.mul(u, v7).pow_p58();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::MontModulus;
    use crate::hash::Sha256;
    use crate::rng::{HmacDrbg, RngCore};

    /// The generic saturated Montgomery field used as the differential
    /// oracle: an entirely independent code path (`bignum::MontModulus`)
    /// operating on the same byte-level values.
    struct Oracle {
        fp: MontModulus<4>,
    }

    impl Oracle {
        fn new() -> Self {
            Oracle {
                fp: MontModulus::new(P_INT),
            }
        }
        /// Loads (and reduces) a little-endian 32-byte value into Montgomery
        /// form. The top bit is masked to mirror `Fe::from_bytes`.
        fn load(&self, b: &[u8; 32]) -> ScalarInt {
            let mut bb = *b;
            bb[31] &= 0x7f;
            self.fp
                .to_mont(&ScalarInt::from_le_bytes(&bb).reduce(self.fp.modulus()))
        }
        fn out(&self, v: &ScalarInt) -> [u8; 32] {
            let mut o = [0u8; 32];
            self.fp.from_mont(v).write_le_bytes(&mut o);
            o
        }
        fn pow(&self, base: &ScalarInt, exp: &ScalarInt) -> ScalarInt {
            let mut r = self.fp.to_mont(&ScalarInt::ONE);
            let limbs = exp.as_limbs();
            let mut i = 256;
            while i > 0 {
                i -= 1;
                r = self.fp.mont_sqr(&r);
                if (limbs[i / 64] >> (i % 64)) & 1 == 1 {
                    r = self.fp.mont_mul(&r, base);
                }
            }
            r
        }
    }

    /// Mirrors `Fe::from_bytes` masking so both sides see the same value.
    fn fe(b: &[u8; 32]) -> Fe {
        Fe::from_bytes(b)
    }

    fn edge_values() -> alloc::vec::Vec<[u8; 32]> {
        let mut vals = alloc::vec::Vec::new();
        let mut push_int = |v: ScalarInt| {
            let mut b = [0u8; 32];
            v.write_le_bytes(&mut b);
            vals.push(b);
        };
        let p = P_INT;
        push_int(ScalarInt::ZERO);
        push_int(ScalarInt::ONE);
        push_int(ScalarInt::from_u64(2));
        push_int(ScalarInt::from_u64(19));
        push_int(p.wrapping_sub(&ScalarInt::ONE)); // p − 1
        push_int(p.wrapping_sub(&ScalarInt::from_u64(2))); // p − 2
        push_int(p); // non-canonical: p
        push_int(p.wrapping_add(&ScalarInt::ONE)); // non-canonical: p + 1
        push_int(p.wrapping_add(&ScalarInt::from_u64(18))); // non-canonical: p + 18
        vals.push([0xff; 32]); // 2^255 − 1 after masking (= p + 18)
        vals
    }

    #[test]
    fn curve_constants_recompute() {
        // d = −121665/121666 mod p, d2 = 2d, sqrtm1 = 2^((p−1)/4) — recompute
        // all three with the new arithmetic itself plus the independent
        // Montgomery oracle, so the compile-time literals are verified, not
        // trusted.
        let o = Oracle::new();
        let n121665 = ScalarInt::from_u64(121665);
        let n121666 = ScalarInt::from_u64(121666);
        let p_minus_2 = P_INT.wrapping_sub(&ScalarInt::from_u64(2));
        let inv121666 = o.pow(&o.fp.to_mont(&n121666), &p_minus_2);
        let d = o.fp.sub_mod(
            &ScalarInt::ZERO,
            &o.fp.mont_mul(&o.fp.to_mont(&n121665), &inv121666),
        );
        assert_eq!(o.out(&d), Fe::D.to_bytes(), "D literal mismatch");
        let d2 = o.fp.add_mod(&d, &d);
        assert_eq!(o.out(&d2), Fe::D2.to_bytes(), "D2 literal mismatch");
        // sqrtm1² == −1, and sqrtm1 matches 2^((p−1)/4).
        let p_minus_1_div_4 = P_INT.wrapping_sub(&ScalarInt::ONE).shr1().shr1();
        let s = o.pow(&o.fp.to_mont(&ScalarInt::from_u64(2)), &p_minus_1_div_4);
        assert_eq!(
            o.out(&s),
            Fe::SQRT_M1.to_bytes(),
            "SQRT_M1 literal mismatch"
        );
        let neg1 = Fe::ONE.neg();
        assert!(
            bool::from(Fe::SQRT_M1.sq().ct_eq_fe(&neg1)),
            "sqrtm1² != −1"
        );
        // The saturated integer constants match their defining values.
        assert_eq!(
            P_INT,
            crate::ec::uint_from_be_hex::<4>(
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
            )
        );
        assert_eq!(
            L_INT,
            crate::ec::uint_from_be_hex::<4>(
                "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"
            )
        );
    }

    #[test]
    fn differential_vs_montgomery_oracle() {
        let o = Oracle::new();
        let mut rng = HmacDrbg::<Sha256>::new(b"fe51-differential", b"nonce", &[]);

        let mut values = edge_values();
        for _ in 0..64 {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            values.push(b);
        }

        for a_bytes in &values {
            let a = fe(a_bytes);
            let am = o.load(a_bytes);

            // Unary ops: neg, sq, invert (addition chain vs generic Fermat
            // ladder — pins task-3 semantics), to_bytes canonicalization.
            assert_eq!(
                a.neg().to_bytes(),
                o.out(&o.fp.sub_mod(&ScalarInt::ZERO, &am)),
                "neg mismatch"
            );
            assert_eq!(a.sq().to_bytes(), o.out(&o.fp.mont_sqr(&am)), "sq mismatch");
            let p_minus_2 = P_INT.wrapping_sub(&ScalarInt::from_u64(2));
            assert_eq!(
                a.invert().to_bytes(),
                o.out(&o.pow(&am, &p_minus_2)),
                "invert (addition chain) != generic Fermat pow"
            );
            let p_58 = P_INT
                .wrapping_sub(&ScalarInt::from_u64(5))
                .shr1()
                .shr1()
                .shr1();
            assert_eq!(
                a.pow_p58().to_bytes(),
                o.out(&o.pow(&am, &p_58)),
                "pow_p58 (addition chain) != generic pow"
            );
            // Round-trip canonicalization.
            assert_eq!(fe(&a.to_bytes()).to_bytes(), a.to_bytes());

            for b_bytes in &values {
                let b = fe(b_bytes);
                let bm = o.load(b_bytes);
                assert_eq!(
                    a.mul(&b).to_bytes(),
                    o.out(&o.fp.mont_mul(&am, &bm)),
                    "mul mismatch"
                );
                assert_eq!(
                    a.add(&b).to_bytes(),
                    o.out(&o.fp.add_mod(&am, &bm)),
                    "add mismatch"
                );
                assert_eq!(
                    a.sub(&b).to_bytes(),
                    o.out(&o.fp.sub_mod(&am, &bm)),
                    "sub mismatch"
                );
            }
        }
    }

    #[test]
    fn sqrt_ratio_i_semantics() {
        // Spot-check the four RFC 9496 cases plus random squares/non-squares
        // against first principles (v·r² ∈ {u, i·u}).
        let f = Field::new();
        let mut rng = HmacDrbg::<Sha256>::new(b"fe51-sqrt-ratio", b"nonce", &[]);

        // u = 0 → (true, 0).
        let (ok, r) = f.sqrt_ratio_i(Fe::ZERO, Fe::from_u64(3));
        assert!(bool::from(ok));
        assert!(bool::from(r.is_zero()));
        // v = 0, u ≠ 0 → (false, 0).
        let (ok, r) = f.sqrt_ratio_i(Fe::from_u64(3), Fe::ZERO);
        assert!(!bool::from(ok));
        assert!(bool::from(r.is_zero()));

        for _ in 0..32 {
            let mut ub = [0u8; 32];
            let mut vb = [0u8; 32];
            rng.fill_bytes(&mut ub);
            rng.fill_bytes(&mut vb);
            let u = fe(&ub);
            let v = fe(&vb);
            let (was_square, r) = f.sqrt_ratio_i(u, v);
            // r is the non-negative root.
            assert!(!bool::from(r.is_negative()));
            let vr2 = f.mul(v, r.sq());
            if bool::from(was_square) {
                assert!(bool::from(f.ct_eq(vr2, u)), "v·r² != u for square case");
            } else {
                let iu = f.mul(f.sqrtm1, u);
                assert!(
                    bool::from(f.ct_eq(vr2, iu)),
                    "v·r² != i·u for non-square case"
                );
            }
        }
    }
}
