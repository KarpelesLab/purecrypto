//! Arithmetic modulo the edwards25519 group order
//! `L = 2²⁵² + 27742317777372353535851937790883648493`.
//!
//! These are the low-level scalar helpers shared by Ed25519 and the public
//! `Scalar` newtype in [`crate::ec::edwards25519::hazmat`] /
//! [`crate::ec::ristretto255`]. Reduction rides on the constant-time
//! [`Uint`](crate::bignum::Uint) long division.

use crate::bignum::Uint;
// `Choice` / `ConditionallySelectable` are only used by the order-`L` scalar
// helpers below, which are gated to the optional hazmat/ristretto consumers;
// gate the import with the same cfg so the Ed25519-only build has no unused
// import.
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
use crate::ct::{Choice, ConditionallySelectable};

use super::field::ScalarInt;

/// Joins low/high 256-bit halves into a 512-bit integer.
fn join(lo: &ScalarInt, hi: &ScalarInt) -> Uint<8> {
    let a = lo.as_limbs();
    let b = hi.as_limbs();
    Uint::from_limbs([a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]])
}

/// Zero-extends a 256-bit integer to 512 bits.
fn widen(a: &ScalarInt) -> Uint<8> {
    let l = a.as_limbs();
    Uint::from_limbs([l[0], l[1], l[2], l[3], 0, 0, 0, 0])
}

/// Truncates a 512-bit integer to its low 256 bits.
fn narrow(a: &Uint<8>) -> ScalarInt {
    let l = a.as_limbs();
    Uint::from_limbs([l[0], l[1], l[2], l[3]])
}

/// Reduces a 64-byte little-endian integer modulo `L`.
pub(crate) fn scalar_reduce_wide(bytes: &[u8; 64], l8: &Uint<8>) -> ScalarInt {
    narrow(&Uint::<8>::from_le_bytes(bytes).reduce(l8))
}

/// Computes `(r + k·a) mod L`.
pub(crate) fn scalar_muladd(
    r: &ScalarInt,
    k: &ScalarInt,
    a: &ScalarInt,
    l8: &Uint<8>,
) -> ScalarInt {
    let (lo, hi) = k.mul_wide(a);
    let (sum, _) = join(&lo, &hi).adc(&widen(r), 0);
    narrow(&sum.reduce(l8))
}

/// Computes `(a · b) mod L` for `a, b < L`.
// The order-`L` field arithmetic below (mul/add/sub/negate/invert) is exercised
// only by the optional `edwards25519::hazmat` group API (which also backs
// `ristretto255`); the RFC 8032 Ed25519 path uses `scalar_reduce_wide` /
// `scalar_muladd` instead. Gate to silence dead-code warnings on the default
// (Ed25519-only) build. `scalar_mul` additionally feeds `scalar_invert`, which
// shares the same gate, so the internal call vanishes together with the export.
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub(crate) fn scalar_mul(a: &ScalarInt, b: &ScalarInt, l8: &Uint<8>) -> ScalarInt {
    let (lo, hi) = a.mul_wide(b);
    narrow(&join(&lo, &hi).reduce(l8))
}

/// Computes `(a + b) mod L` for `a, b < L`.
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub(crate) fn scalar_add(a: &ScalarInt, b: &ScalarInt, l: &ScalarInt) -> ScalarInt {
    // a, b < L < 2²⁵³, so the sum fits in 256 bits with no carry out; one
    // conditional subtraction of L canonicalises it.
    let (sum, _) = a.adc(b, 0);
    let (reduced, borrow) = sum.sbb(l, 0);
    ScalarInt::conditional_select(&reduced, &sum, Choice::from((borrow ^ 1) as u8))
}

/// Computes `(a − b) mod L` for `a, b < L`.
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub(crate) fn scalar_sub(a: &ScalarInt, b: &ScalarInt, l: &ScalarInt) -> ScalarInt {
    let (diff, borrow) = a.sbb(b, 0);
    let (wrapped, _) = diff.adc(l, 0);
    ScalarInt::conditional_select(&wrapped, &diff, Choice::from(borrow as u8))
}

/// Computes `(−a) mod L` for `a < L`.
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub(crate) fn scalar_negate(a: &ScalarInt, l: &ScalarInt) -> ScalarInt {
    scalar_sub(&ScalarInt::ZERO, a, l)
}

/// Computes the modular inverse `a⁻¹ mod L` for `a < L` via ScalarIntrmat's little
/// theorem (`a^(L−2) mod L`), constant time in the value of `a`. `L` is prime,
/// so this is well-defined for every nonzero `a`; the inverse of `0` is `0`.
#[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
pub(crate) fn scalar_invert(a: &ScalarInt, l: &ScalarInt, l8: &Uint<8>) -> ScalarInt {
    // exponent = L − 2
    let exp = l.wrapping_sub(&ScalarInt::from_u64(2));
    let mut r = ScalarInt::ONE;
    let limbs = exp.as_limbs();
    let mut i = 256;
    while i > 0 {
        i -= 1;
        r = scalar_mul(&r, &r, l8);
        let bit = ((limbs[i / 64] >> (i % 64)) & 1) as u8;
        let prod = scalar_mul(&r, a, l8);
        r = ScalarInt::conditional_select(&prod, &r, Choice::from(bit));
    }
    r
}

/// Clamps the lower half of the seed hash into the secret scalar (RFC 8032).
pub(crate) fn clamp(b: &mut [u8; 32]) {
    b[0] &= 248;
    b[31] &= 127;
    b[31] |= 64;
}
