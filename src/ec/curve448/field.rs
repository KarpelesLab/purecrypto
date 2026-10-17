//! The edwards448 / Curve448 base field GF(2⁴⁴⁸−2²²⁴−1) and curve constants.
//!
//! This is the shared field backend consumed by the Ed448 signing path
//! ([`crate::ec::ed448`]) and the X448 ladder ([`crate::ec::x448`]).
//!
//! Field elements use an unsaturated **8×56-bit limb** representation (the
//! "Goldilocks" layout of Hamburg's libdecaf): an element is
//! `Σ limbs[i]·2^(56·i)` with each limb held in a `u64`. The prime is a
//! Solinas prime, `p = 2⁴⁴⁸ − 2²²⁴ − 1`, so `2⁴⁴⁸ ≡ 2²²⁴ + 1 (mod p)` and a
//! carry out of the top limb folds back into limbs 0 and 4 with two
//! additions — no Montgomery reduction, no multiplication by a constant.
//! Multiplication splits each operand at 2²²⁴ (the "golden ratio" `φ = 2²²⁴`,
//! `φ² = φ + 1 (mod p)`) and uses one level of Karatsuba, so a product costs
//! three 4×4-limb schoolbook products (48 `u128` partial products) instead of
//! 64, and a squaring three 4-limb squarings (30 partial products). Reduction
//! is lazy: values are kept merely *bounded*, not canonical, until
//! [`Fe::to_bytes`] performs the full canonical reduction. Everything is
//! branch-free and table-free, so the arithmetic is constant-time by
//! construction.
//!
//! `p ≡ 3 (mod 4)`, so square roots are the single exponentiation
//! `√w = w^((p+1)/4)` (no `√−1` correction is needed, unlike the
//! `p ≡ 5 (mod 8)` edwards25519 field).
//!
//! # Bounds discipline
//!
//! Every `Fe` produced by this module is **reduced**: its limbs are
//! `< 2^56 + 2^8` (the output of [`Fe::weak_reduce`] or of the multiply
//! carry chains). [`Fe::mul`] and [`Fe::sq`] accept limbs up to `2^57`, and
//! `add`/`sub`/`neg`/`mul_small` accept any reduced input; to keep the
//! invariant trivial to audit, every operation re-reduces its result before
//! returning, so a reduced value is all a caller ever holds.

#[cfg(any(test, not(feature = "ed448-table")))]
use super::point::Point;
use crate::bignum::Uint;
use crate::ct::{Choice, ConstantTimeEq};

/// The saturated 7×u64 integer type used for order-`L` scalars and for
/// byte-level canonicity checks (`< p`, `< L`) on wire encodings.
pub(crate) type ScalarInt = Uint<7>;

/// 56-bit limb mask.
const M56: u64 = (1u64 << 56) - 1;

/// `4·p` spread as eight per-limb constants (`p` is `2^56 − 1` in every limb
/// except limb 4, which is `2^56 − 2`), added before a limbwise subtraction so
/// intermediate limbs never underflow.
const FOUR_P: [u64; 8] = [
    4 * M56,
    4 * M56,
    4 * M56,
    4 * M56,
    4 * (M56 - 1),
    4 * M56,
    4 * M56,
    4 * M56,
];

/// A field element of GF(2⁴⁴⁸−2²²⁴−1) in unsaturated 8×56-bit limb form.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe(pub(crate) [u64; 8]);

/// `p = 2⁴⁴⁸ − 2²²⁴ − 1` as a saturated integer (for canonicity checks).
pub(crate) const P_INT: ScalarInt = crate::ec::uint_from_be_hex(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);

/// The group order `L = 2⁴⁴⁶ − 138...885` (RFC 8032 §5.2).
pub(crate) const L_INT: ScalarInt = crate::ec::uint_from_be_hex(
    "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff\
7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
);

/// The affine coordinates of the standard edwards448 base point `B`
/// (RFC 8032 §5.2, big-endian hex) and `T = X·Y`. The `T` literal is checked
/// against the product by `point::tests::const_base_matches_decoded_encoding`.
// With the fixed-base table the library takes `B` from the table; the
// literals then only back the tests.
#[cfg(any(test, not(feature = "ed448-table")))]
const BX_HEX: &str = "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324\
a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e";
#[cfg(any(test, not(feature = "ed448-table")))]
const BY_HEX: &str = "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e\
05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14";
#[cfg(any(test, not(feature = "ed448-table")))]
const BT_HEX: &str = "c75eb58aee221c6ccec39d2d508d91c9c5056a183f8451d260d71667\
e2356d58f179de90b5b27da1f78fa07d85662d1deb06624e82af95f3";

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

/// Parses 112 big-endian hex characters (a canonical residue) into limbs at
/// compile time. Each limb is exactly 14 nibbles, so no nibble straddles a
/// limb boundary.
#[cfg(any(test, not(feature = "ed448-table")))]
const fn fe_from_be_hex(hex: &str) -> Fe {
    let h = hex.as_bytes();
    assert!(h.len() == 112, "field constant must be 112 hex digits");
    let mut l = [0u64; 8];
    let mut n = 0;
    while n < 112 {
        let c = h[111 - n];
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex digit in field constant"),
        } as u64;
        l[n / 14] |= v << (4 * (n % 14));
        n += 1;
    }
    Fe(l)
}

#[inline(always)]
fn m(a: u64, b: u64) -> u128 {
    (a as u128) * (b as u128)
}

/// The seven columns of the 4×4-limb schoolbook product `a·b`.
#[inline(always)]
fn mul4(a: &[u64; 4], b: &[u64; 4]) -> [u128; 7] {
    [
        m(a[0], b[0]),
        m(a[0], b[1]) + m(a[1], b[0]),
        m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]),
        m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]),
        m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]),
        m(a[2], b[3]) + m(a[3], b[2]),
        m(a[3], b[3]),
    ]
}

/// The seven columns of the 4-limb square `a²` (10 partial products instead
/// of 16, by symmetry). Limbs must be `< 2^63` so the doubled limbs fit.
#[inline(always)]
fn sq4(a: &[u64; 4]) -> [u128; 7] {
    let a0_2 = a[0] << 1;
    let a1_2 = a[1] << 1;
    let a2_2 = a[2] << 1;
    [
        m(a[0], a[0]),
        m(a0_2, a[1]),
        m(a0_2, a[2]) + m(a[1], a[1]),
        m(a0_2, a[3]) + m(a1_2, a[2]),
        m(a1_2, a[3]) + m(a[2], a[2]),
        m(a2_2, a[3]),
        m(a[3], a[3]),
    ]
}

/// Expands a secret-derived `0`/`1` limb into an all-ones / all-zeros mask
/// without a branch: `wrapping_neg`, behind a `black_box` barrier so LLVM
/// cannot turn the mask back into a conditional jump. This is the single
/// opaque operation of every constant-time selection in the curve448
/// backend; the mask is then applied across all limbs with plain `&`/`^`.
#[inline]
pub(crate) fn mask_from_bit(bit: u64) -> u64 {
    core::hint::black_box(bit.wrapping_neg())
}

/// An all-ones mask iff `a == b`, else all-zeros; branch-free with one
/// barrier (via [`mask_from_bit`]).
#[inline]
pub(crate) fn eq_mask(a: u64, b: u64) -> u64 {
    let x = a ^ b;
    // The top bit of `x | −x` is 1 iff `x != 0`.
    let differ = (x | x.wrapping_neg()) >> 63;
    mask_from_bit(differ ^ 1)
}

impl Fe {
    /// The additive identity `0`.
    pub(crate) const ZERO: Fe = Fe([0; 8]);
    /// The multiplicative identity `1`.
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0]);
    /// The edwards448 curve constant `d = −39081 mod p` (the single Edwards
    /// constant; the `a = +1` formulas do not need `2d`). Verified by
    /// `tests::curve_constants_recompute`.
    pub(crate) const D: Fe = Fe([M56 - 39081, M56, M56, M56, M56 - 1, M56, M56, M56]);
    /// `−d = 39081`, the small positive constant the point formulas multiply
    /// by instead of `d` (a [`Fe::mul_small`] rather than a full multiply).
    pub(crate) const NEG_D_SMALL: u32 = 39081;

    /// A small integer as a field element.
    #[cfg(test)]
    pub(crate) const fn from_u64(v: u64) -> Fe {
        Fe([v & M56, v >> 56, 0, 0, 0, 0, 0, 0])
    }

    /// One parallel pass of carry propagation with the `2⁴⁴⁸ ≡ 2²²⁴ + 1`
    /// fold: every limb keeps its low 56 bits and takes the carry of the limb
    /// below, the top carry landing in limbs 0 and 4. Accepts any limbs
    /// `< 2^63`; the result's limbs are `< 2^56 + 2^8`.
    #[inline(always)]
    fn weak_reduce(l: [u64; 8]) -> Fe {
        let c7 = l[7] >> 56;
        Fe([
            (l[0] & M56) + c7,
            (l[1] & M56) + (l[0] >> 56),
            (l[2] & M56) + (l[1] >> 56),
            (l[3] & M56) + (l[2] >> 56),
            (l[4] & M56) + (l[3] >> 56) + c7,
            (l[5] & M56) + (l[4] >> 56),
            (l[6] & M56) + (l[5] >> 56),
            (l[7] & M56) + (l[6] >> 56),
        ])
    }

    /// Parses a 56-byte little-endian encoding, seven bytes per limb. The
    /// value is **not** required to be a canonical residue `< p` (the lazy
    /// representation is closed over non-canonical inputs, and
    /// [`Self::to_bytes`] canonicalizes on the way out). Callers that must
    /// reject non-canonical encodings check the raw bytes against [`P_INT`]
    /// first.
    pub(crate) fn from_bytes(bytes: &[u8; 56]) -> Fe {
        let mut l = [0u64; 8];
        for (i, limb) in l.iter_mut().enumerate() {
            let mut t = [0u8; 8];
            t[..7].copy_from_slice(&bytes[7 * i..7 * i + 7]);
            *limb = u64::from_le_bytes(t);
        }
        Fe(l)
    }

    /// The canonical 56-byte little-endian encoding: performs the full
    /// reduction to the unique residue in `[0, p)`. Constant-time.
    pub(crate) fn to_bytes(self) -> [u8; 56] {
        // Bring every limb under 2^56 + 2^8; the value is then < 2^448 + 2^401
        // < 2p, so a single conditional subtraction of p canonicalizes it.
        let mut l = Fe::weak_reduce(self.0).0;

        // q = ⌊value / p⌋ ∈ {0, 1} branch-free: q = 1 exactly when
        // value + 2^224 + 1 ≥ 2^448, i.e. when adding 1 at limb 0 and 1 at
        // limb 4 carries all the way out of limb 7.
        let mut c = (l[0] + 1) >> 56;
        c = (l[1] + c) >> 56;
        c = (l[2] + c) >> 56;
        c = (l[3] + c) >> 56;
        c = (l[4] + 1 + c) >> 56;
        c = (l[5] + c) >> 56;
        c = (l[6] + c) >> 56;
        let q = (l[7] + c) >> 56;

        // value − q·p = value + q·(2^224 + 1) − q·2^448: add q at limbs 0
        // and 4, propagate, and drop the carry out of limb 7 (which is
        // exactly q by construction).
        l[0] += q;
        l[4] += q;
        l[1] += l[0] >> 56;
        l[0] &= M56;
        l[2] += l[1] >> 56;
        l[1] &= M56;
        l[3] += l[2] >> 56;
        l[2] &= M56;
        l[4] += l[3] >> 56;
        l[3] &= M56;
        l[5] += l[4] >> 56;
        l[4] &= M56;
        l[6] += l[5] >> 56;
        l[5] &= M56;
        l[7] += l[6] >> 56;
        l[6] &= M56;
        l[7] &= M56;

        let mut out = [0u8; 56];
        for (i, limb) in l.iter().enumerate() {
            out[7 * i..7 * i + 7].copy_from_slice(&limb.to_le_bytes()[..7]);
        }
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
            a[5] + b[5],
            a[6] + b[6],
            a[7] + b[7],
        ])
    }

    /// `self − rhs`, reduced. Adds `4·p` first so no limb underflows.
    #[inline]
    pub(crate) fn sub(&self, rhs: &Fe) -> Fe {
        let a = &self.0;
        let b = &rhs.0;
        Fe::weak_reduce([
            (a[0] + FOUR_P[0]) - b[0],
            (a[1] + FOUR_P[1]) - b[1],
            (a[2] + FOUR_P[2]) - b[2],
            (a[3] + FOUR_P[3]) - b[3],
            (a[4] + FOUR_P[4]) - b[4],
            (a[5] + FOUR_P[5]) - b[5],
            (a[6] + FOUR_P[6]) - b[6],
            (a[7] + FOUR_P[7]) - b[7],
        ])
    }

    /// `−self`, reduced.
    #[inline]
    pub(crate) fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    /// `self · rhs` by golden-ratio Karatsuba: with `a = a₀ + a₁·φ`,
    /// `b = b₀ + b₁·φ` (four limbs each) and `φ² ≡ φ + 1`,
    ///
    /// `a·b ≡ (a₀b₀ + a₁b₁) + ((a₀+a₁)(b₀+b₁) − a₀b₀)·φ (mod p)`,
    ///
    /// three 4×4 products whose columns the shared [`Self::fold`] combines.
    /// Inputs may have limbs up to `2^57`; output limbs are `< 2^56 + 2^8`.
    pub(crate) fn mul(&self, rhs: &Fe) -> Fe {
        let a = &self.0;
        let b = &rhs.0;
        let a0 = [a[0], a[1], a[2], a[3]];
        let a1 = [a[4], a[5], a[6], a[7]];
        let b0 = [b[0], b[1], b[2], b[3]];
        let b1 = [b[4], b[5], b[6], b[7]];
        let aa = [a[0] + a[4], a[1] + a[5], a[2] + a[6], a[3] + a[7]];
        let bb = [b[0] + b[4], b[1] + b[5], b[2] + b[6], b[3] + b[7]];
        Fe::fold(&mul4(&a0, &b0), &mul4(&a1, &b1), &mul4(&aa, &bb))
    }

    /// `self²`: the same split as [`Self::mul`] with three 4-limb squarings
    /// (30 partial products instead of 48). Same bounds as [`Self::mul`].
    pub(crate) fn sq(&self) -> Fe {
        let a = &self.0;
        let a0 = [a[0], a[1], a[2], a[3]];
        let a1 = [a[4], a[5], a[6], a[7]];
        let aa = [a[0] + a[4], a[1] + a[5], a[2] + a[6], a[3] + a[7]];
        Fe::fold(&sq4(&a0), &sq4(&a1), &sq4(&aa))
    }

    /// Combines the three half-products of [`Self::mul`] / [`Self::sq`]
    /// (`p00 = a₀b₀`, `p11 = a₁b₁`, `paa = (a₀+a₁)(b₀+b₁)`, seven columns
    /// each) into eight reduced limbs.
    ///
    /// Writing `Xₖ` for column `k` of a half-product (`k ≥ 7` is empty), the
    /// unreduced product has low columns `p00ₖ + p11ₖ` (`k < 4`) and `φ`
    /// columns `paaₖ − p00ₖ` (`k < 8`); the `φ` columns at `k ≥ 4` sit at
    /// `φ² = φ + 1`, i.e. land in both halves. Hence for `i in 0..4`:
    ///
    /// `lo[i] = p00ᵢ + p11ᵢ + paaᵢ₊₄ − p00ᵢ₊₄`,
    /// `hi[i] = paaᵢ + paaᵢ₊₄ − p00ᵢ + p11ᵢ₊₄`
    ///
    /// (every subtraction is of a column by a column-wise larger one, so the
    /// `u128` arithmetic never underflows). Two independent carry chains run
    /// over `lo` and `hi`; the carry out of `lo` is position 4 and the carry
    /// out of `hi` is position 8 ≡ positions 0 and 4, each absorbed by one
    /// more limb carry.
    #[inline(always)]
    fn fold(p00: &[u128; 7], p11: &[u128; 7], paa: &[u128; 7]) -> Fe {
        let lo0 = p00[0] + p11[0] + (paa[4] - p00[4]);
        let lo1 = p00[1] + p11[1] + (paa[5] - p00[5]);
        let lo2 = p00[2] + p11[2] + (paa[6] - p00[6]);
        let lo3 = p00[3] + p11[3];
        let hi0 = (paa[0] - p00[0]) + paa[4] + p11[4];
        let hi1 = (paa[1] - p00[1]) + paa[5] + p11[5];
        let hi2 = (paa[2] - p00[2]) + paa[6] + p11[6];
        let hi3 = paa[3] - p00[3];

        let mut out = [0u64; 8];
        let mut c = lo0;
        out[0] = (c as u64) & M56;
        c = (c >> 56) + lo1;
        out[1] = (c as u64) & M56;
        c = (c >> 56) + lo2;
        out[2] = (c as u64) & M56;
        c = (c >> 56) + lo3;
        out[3] = (c as u64) & M56;
        let c4 = (c >> 56) as u64;

        let mut d = hi0;
        out[4] = (d as u64) & M56;
        d = (d >> 56) + hi1;
        out[5] = (d as u64) & M56;
        d = (d >> 56) + hi2;
        out[6] = (d as u64) & M56;
        d = (d >> 56) + hi3;
        out[7] = (d as u64) & M56;
        let c8 = (d >> 56) as u64;

        out[4] += c4 + c8;
        out[0] += c8;
        out[5] += out[4] >> 56;
        out[4] &= M56;
        out[1] += out[0] >> 56;
        out[0] &= M56;
        Fe(out)
    }

    /// `self · k` for a small public constant `k` (the curve constants
    /// `−d = 39081` and `a24 = 39081`): eight limb-by-word products and one
    /// fold, in place of a full multiplication. Output reduced.
    #[inline]
    pub(crate) fn mul_small(&self, k: u32) -> Fe {
        let k = k as u128;
        let mut out = [0u64; 8];
        let mut c: u128 = 0;
        for (o, &a) in out.iter_mut().zip(self.0.iter()) {
            c += (a as u128) * k;
            *o = (c as u64) & M56;
            c >>= 56;
        }
        let c = c as u64;
        out[0] += c;
        out[4] += c;
        out[1] += out[0] >> 56;
        out[0] &= M56;
        out[5] += out[4] >> 56;
        out[4] &= M56;
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

    /// `self^((p−3)/4)` by a fixed addition chain (451 squarings, 12
    /// multiplications), the shared core of inversion and square roots.
    ///
    /// `(p−3)/4 = 2⁴⁴⁶ − 2²²² − 1 = (2²²³ − 1)·2²²³ + (2²²² − 1)`, so with
    /// `eₖ = a^(2ᵏ−1)` the result is `e₂₂₃^(2²²³) · e₂₂₂`, and the `eₖ` are
    /// built by `e_{j+k} = e_j^(2ᵏ) · eₖ`. The exponent is public and the
    /// schedule fixed, so this is constant time in `self`.
    pub(crate) fn pow_p3_4(&self) -> Fe {
        let e1 = *self;
        let e2 = e1.sq().mul(&e1);
        let e3 = e2.sq().mul(&e1);
        let e6 = e3.sqn(3).mul(&e3);
        let e12 = e6.sqn(6).mul(&e6);
        let e24 = e12.sqn(12).mul(&e12);
        let e30 = e24.sqn(6).mul(&e6);
        let e48 = e24.sqn(24).mul(&e24);
        let e96 = e48.sqn(48).mul(&e48);
        let e192 = e96.sqn(96).mul(&e96);
        let e222 = e192.sqn(30).mul(&e30);
        let e223 = e222.sq().mul(&e1);
        e223.sqn(223).mul(&e222)
    }

    /// The multiplicative inverse `self^(p−2)` (Fermat; the "inverse" of `0`
    /// is `0`). `p − 2 = 4·(p−3)/4 + 1`, so this is [`Self::pow_p3_4`] plus
    /// two squarings and a multiply — constant-time by construction.
    pub(crate) fn invert(&self) -> Fe {
        self.pow_p3_4().sqn(2).mul(self)
    }

    /// Constant-time equality (compares canonical encodings).
    #[inline]
    pub(crate) fn ct_eq_fe(&self, other: &Fe) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }

    /// Constant-time zero test (on the canonical residue).
    #[inline]
    pub(crate) fn is_zero(&self) -> Choice {
        self.to_bytes().ct_eq(&[0u8; 56])
    }

    /// Whether the canonical residue is odd (its least-significant bit) —
    /// the "sign" bit in encodings. Constant-time.
    #[inline]
    pub(crate) fn is_negative(&self) -> Choice {
        Choice::from(self.to_bytes()[0] & 1)
    }

    /// `a` when `mask` is all-ones, `b` when it is all-zeros, limb by limb.
    /// The mask comes from [`mask_from_bit`] / [`eq_mask`] (one barrier per
    /// selection, shared by every limb of every coordinate it decides).
    #[inline(always)]
    pub(crate) fn select(a: &Fe, b: &Fe, mask: u64) -> Fe {
        let mut out = [0u64; 8];
        for ((o, &x), &y) in out.iter_mut().zip(a.0.iter()).zip(b.0.iter()) {
            *o = y ^ (mask & (x ^ y));
        }
        Fe(out)
    }

    /// Swaps `a` and `b` when `mask` is all-ones, leaves them when it is
    /// all-zeros.
    #[inline(always)]
    pub(crate) fn cswap(a: &mut Fe, b: &mut Fe, mask: u64) {
        for (x, y) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let t = mask & (*x ^ *y);
            *x ^= t;
            *y ^= t;
        }
    }
}

impl ConstantTimeEq for Fe {
    #[inline]
    fn ct_eq(&self, other: &Fe) -> Choice {
        self.ct_eq_fe(other)
    }
}

impl crate::zeroize::Zeroize for Fe {
    /// Wipes the limbs: ladder and point intermediates are as secret as the
    /// scalar that produced them.
    #[inline]
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// The edwards448 field context: the curve constants (compile-time literals,
/// verified by always-on tests) plus the order-`L` integers for the scalar
/// side. Constructing it is trivial — no field ops are performed.
pub(crate) struct Field {
    /// `1`.
    pub(crate) one: Fe,
    /// The curve constant `d = −39081`.
    pub(crate) d: Fe,
    /// The prime `p`, as a saturated integer for encoding canonicity checks.
    pub(crate) p: ScalarInt,
    /// The group order `L`.
    pub(crate) l: ScalarInt,
    /// The base point `B` in extended coordinates (`Z = 1`, `T = X·Y`), so
    /// `[k]B` needs no per-call decompression. With the fixed-base table
    /// (feature `ed448-table`) library paths never touch the point itself;
    /// only the table-free ladders and the tests do.
    #[cfg(any(test, not(feature = "ed448-table")))]
    pub(crate) base_point: Point,
}

/// The field context, built at compile time.
static FIELD: Field = Field {
    one: Fe::ONE,
    d: Fe::D,
    p: P_INT,
    l: L_INT,
    #[cfg(any(test, not(feature = "ed448-table")))]
    base_point: Point {
        x: fe_from_be_hex(BX_HEX),
        y: fe_from_be_hex(BY_HEX),
        z: Fe::ONE,
        t: fe_from_be_hex(BT_HEX),
    },
};

impl Field {
    /// The shared, compile-time-built field context.
    #[inline]
    pub(crate) fn new() -> &'static Self {
        &FIELD
    }

    /// The base point `B` as a stored affine `(x, y, t = x·y)` triple, the
    /// same value as the first entry of the fixed-base table.
    #[cfg(test)]
    pub(crate) fn base_affine(&self) -> (Fe, Fe, Fe) {
        (
            fe_from_be_hex(BX_HEX),
            fe_from_be_hex(BY_HEX),
            fe_from_be_hex(BT_HEX),
        )
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
    pub(crate) fn mul_small(&self, a: Fe, k: u32) -> Fe {
        a.mul_small(k)
    }
    /// `a⁻¹` (Fermat; `0` maps to `0`), constant time.
    #[inline]
    pub(crate) fn inv(&self, a: Fe) -> Fe {
        a.invert()
    }
    /// Constant-time equality of two elements.
    #[inline]
    pub(crate) fn ct_eq(&self, a: Fe, b: Fe) -> Choice {
        a.ct_eq_fe(&b)
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
        let pw = uv3.pow_p3_4();
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
    use crate::bignum::MontModulus;
    use crate::hash::Sha256;
    use crate::rng::{HmacDrbg, RngCore};
    use crate::zeroize::Zeroize;

    /// `Fe`'s `Zeroize` must clear every unsaturated limb: ladder and point
    /// intermediates are wiped through it.
    #[test]
    fn fe_zeroize_clears_limbs() {
        let mut x = Fe::from_u64(0x1234_5678_9abc_def0);
        x = x.mul(&x);
        assert!(x.0.iter().any(|&l| l != 0));
        x.zeroize();
        assert_eq!(x.0, [0u64; 8]);
    }

    /// The generic saturated Montgomery field used as the differential
    /// oracle: an entirely independent code path (`bignum::MontModulus`, the
    /// backend this module replaced) operating on the same byte-level values.
    struct Oracle {
        fp: MontModulus<7>,
    }

    impl Oracle {
        fn new() -> Self {
            Oracle {
                fp: MontModulus::new(P_INT),
            }
        }
        /// Loads (and reduces) a little-endian 56-byte value into Montgomery
        /// form.
        fn load(&self, b: &[u8; 56]) -> ScalarInt {
            self.fp
                .to_mont(&ScalarInt::from_le_bytes(b).reduce(self.fp.modulus()))
        }
        fn out(&self, v: &ScalarInt) -> [u8; 56] {
            let mut o = [0u8; 56];
            self.fp.from_mont(v).write_le_bytes(&mut o);
            o
        }
        fn pow(&self, base: &ScalarInt, exp: &ScalarInt) -> ScalarInt {
            let mut r = self.fp.to_mont(&ScalarInt::ONE);
            let limbs = exp.as_limbs();
            let mut i = 448;
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

    fn int_bytes(v: &ScalarInt) -> [u8; 56] {
        let mut out = [0u8; 56];
        v.write_le_bytes(&mut out);
        out
    }

    /// Canonical and non-canonical edge residues: 0, 1, 2, −d, p−1, p−2, p,
    /// p+1, 2²²⁴, 2²²⁴+1, p−39081 (= d), 2⁴⁴⁸−1 (the largest encodable
    /// value), and the limb patterns that stress the Karatsuba fold.
    fn edge_values() -> [[u8; 56]; 15] {
        let p = P_INT;
        let two224 = ScalarInt::from_limbs([0, 0, 0, 1 << 32, 0, 0, 0]);
        let ints = [
            ScalarInt::ZERO,
            ScalarInt::ONE,
            ScalarInt::from_u64(2),
            ScalarInt::from_u64(39081),
            p.wrapping_sub(&ScalarInt::ONE),
            p.wrapping_sub(&ScalarInt::from_u64(2)),
            p,
            p.wrapping_add(&ScalarInt::ONE),
            two224,
            two224.wrapping_add(&ScalarInt::ONE),
            p.wrapping_sub(&ScalarInt::from_u64(39081)),
            // Low half all-ones, high half zero, and the reverse.
            ScalarInt::from_limbs([u64::MAX, u64::MAX, u64::MAX, u32::MAX as u64, 0, 0, 0]),
            ScalarInt::from_limbs([0, 0, 0, !(u32::MAX as u64), u64::MAX, u64::MAX, u64::MAX]),
        ];
        let mut vals = [[0u8; 56]; 15];
        for (slot, v) in vals.iter_mut().zip(ints.iter()) {
            *slot = int_bytes(v);
        }
        vals[13] = [0xff; 56]; // 2⁴⁴⁸ − 1 = p + 2²²⁴
        vals[14] = [0x55; 56];
        vals
    }

    #[test]
    fn curve_constants_recompute() {
        let o = Oracle::new();
        // d = −39081 mod p.
        let d = o.fp.sub_mod(
            &ScalarInt::ZERO,
            &o.fp.to_mont(&ScalarInt::from_u64(Fe::NEG_D_SMALL as u64)),
        );
        assert_eq!(o.out(&d), Fe::D.to_bytes(), "D literal mismatch");
        assert_eq!(Fe::D.to_bytes(), Field::new().d.to_bytes());
        // The saturated integer constants match their defining values, and
        // p − 1 canonicalizes to the lazy field's `0 − 1`.
        let mut p_bytes = [0xffu8; 56];
        p_bytes[28] = 0xfe;
        assert_eq!(int_bytes(&P_INT), p_bytes);
        let mut p_minus_1 = p_bytes;
        p_minus_1[0] = 0xfe;
        assert_eq!(Fe::ZERO.sub(&Fe::ONE).to_bytes(), p_minus_1);
        assert_eq!(
            L_INT,
            crate::ec::uint_from_be_hex::<7>(
                "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff\
7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"
            )
        );
        // The base point literals: T = X·Y and the point is on the curve
        // (x² + y² = 1 + d·x²·y²).
        let (x, y, t) = Field::new().base_affine();
        assert!(bool::from(x.mul(&y).ct_eq_fe(&t)), "BT literal != BX·BY");
        let lhs = x.sq().add(&y.sq());
        let rhs = Fe::ONE.add(&Fe::D.mul(&x.sq()).mul(&y.sq()));
        assert!(bool::from(lhs.ct_eq_fe(&rhs)), "base point not on curve");
    }

    #[test]
    fn differential_vs_montgomery_oracle() {
        let o = Oracle::new();
        let mut rng = HmacDrbg::<Sha256>::new(b"fe448-differential", b"nonce", &[]);

        let edges = edge_values();
        let mut values = [[0u8; 56]; 63];
        values[..edges.len()].copy_from_slice(&edges);
        for slot in values[edges.len()..].iter_mut() {
            rng.fill_bytes(slot);
        }

        let p_minus_2 = P_INT.wrapping_sub(&ScalarInt::from_u64(2));
        let p_minus_3_div_4 = P_INT.wrapping_sub(&ScalarInt::from_u64(3)).shr1().shr1();

        for a_bytes in &values {
            let a = Fe::from_bytes(a_bytes);
            let am = o.load(a_bytes);

            // Unary ops: canonicalization, neg, sq, the small-constant
            // multiplies, invert and pow_p3_4 (addition chains vs the generic
            // Fermat ladder), parity.
            assert_eq!(a.to_bytes(), o.out(&am), "to_bytes canonicalization");
            assert_eq!(Fe::from_bytes(&a.to_bytes()).to_bytes(), a.to_bytes());
            assert_eq!(
                a.neg().to_bytes(),
                o.out(&o.fp.sub_mod(&ScalarInt::ZERO, &am)),
                "neg mismatch"
            );
            assert_eq!(a.sq().to_bytes(), o.out(&o.fp.mont_sqr(&am)), "sq mismatch");
            for k in [0u32, 1, 2, 39081, 156326, u32::MAX] {
                let km = o.fp.to_mont(&ScalarInt::from_u64(k as u64));
                assert_eq!(
                    a.mul_small(k).to_bytes(),
                    o.out(&o.fp.mont_mul(&am, &km)),
                    "mul_small({k}) mismatch"
                );
            }
            assert_eq!(
                a.invert().to_bytes(),
                o.out(&o.pow(&am, &p_minus_2)),
                "invert (addition chain) != generic Fermat pow"
            );
            assert_eq!(
                a.pow_p3_4().to_bytes(),
                o.out(&o.pow(&am, &p_minus_3_div_4)),
                "pow_p3_4 (addition chain) != generic pow"
            );
            assert_eq!(
                a.is_negative().unwrap_u8(),
                o.out(&am)[0] & 1,
                "is_negative mismatch"
            );
            assert_eq!(
                bool::from(a.is_zero()),
                o.out(&am) == [0u8; 56],
                "is_zero mismatch"
            );
            // Chained lazy inputs: (a + a + a + a)² and (a − 2a)·a feed
            // unreduced-looking sums straight into the multiplier.
            let a4 = a.add(&a).add(&a).add(&a);
            let a4m =
                o.fp.add_mod(&o.fp.add_mod(&am, &am), &o.fp.add_mod(&am, &am));
            assert_eq!(a4.sq().to_bytes(), o.out(&o.fp.mont_sqr(&a4m)));
            let am2 = o.fp.sub_mod(&am, &o.fp.add_mod(&am, &am));
            assert_eq!(
                a.sub(&a.add(&a)).mul(&a).to_bytes(),
                o.out(&o.fp.mont_mul(&am2, &am))
            );

            for b_bytes in &values {
                let b = Fe::from_bytes(b_bytes);
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
                assert_eq!(
                    bool::from(a.ct_eq_fe(&b)),
                    o.out(&am) == o.out(&bm),
                    "ct_eq mismatch"
                );
            }
        }
    }

    /// The masked selection helpers: `select` picks `a` under an all-ones
    /// mask and `b` under zero, `cswap` swaps exactly under all-ones, and
    /// `eq_mask` is all-ones iff its arguments are equal.
    #[test]
    fn select_and_swap_semantics() {
        let a = Fe::from_bytes(&[0x37; 56]);
        let b = Fe::from_bytes(&[0xc9; 56]);
        let on = mask_from_bit(1);
        let off = mask_from_bit(0);
        assert_eq!(on, u64::MAX);
        assert_eq!(off, 0);
        assert_eq!(Fe::select(&a, &b, on).0, a.0);
        assert_eq!(Fe::select(&a, &b, off).0, b.0);
        let (mut x, mut y) = (a, b);
        Fe::cswap(&mut x, &mut y, off);
        assert_eq!((x.0, y.0), (a.0, b.0));
        Fe::cswap(&mut x, &mut y, on);
        assert_eq!((x.0, y.0), (b.0, a.0));
        for i in 0..20u64 {
            for j in 0..20u64 {
                assert_eq!(eq_mask(i, j), if i == j { u64::MAX } else { 0 });
            }
        }
        assert_eq!(eq_mask(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(eq_mask(1 << 63, 0), 0);
    }

    /// `sqrt_ratio` semantics: squares yield a verified root, non-squares and
    /// `v = 0` report failure, `u = 0` succeeds with root 0.
    #[test]
    fn sqrt_ratio_semantics() {
        let f = Field::new();
        let mut rng = HmacDrbg::<Sha256>::new(b"fe448-sqrt-ratio", b"nonce", &[]);
        let (ok, r) = f.sqrt_ratio(Fe::ZERO, Fe::from_u64(3));
        assert!(bool::from(ok));
        assert!(bool::from(r.is_zero()));
        let (ok, _) = f.sqrt_ratio(Fe::from_u64(3), Fe::ZERO);
        assert!(!bool::from(ok));
        let mut squares = 0;
        for _ in 0..32 {
            let mut ub = [0u8; 56];
            let mut vb = [0u8; 56];
            rng.fill_bytes(&mut ub);
            rng.fill_bytes(&mut vb);
            let u = Fe::from_bytes(&ub);
            let v = Fe::from_bytes(&vb);
            let (was_square, r) = f.sqrt_ratio(u, v);
            if bool::from(was_square) {
                squares += 1;
                assert!(bool::from(f.ct_eq(f.mul(v, r.sq()), u)));
            }
            // u·v is a square iff u/v is: the squared ratio must succeed.
            let (ok, r2) = f.sqrt_ratio(f.mul(u, u), f.mul(v, v));
            assert!(bool::from(ok));
            assert!(bool::from(
                f.ct_eq(f.mul(f.mul(v, v), r2.sq()), f.mul(u, u))
            ));
        }
        assert!(squares > 4 && squares < 28, "implausible residue split");
    }
}
