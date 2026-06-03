//! Arithmetic modulo the edwards448 group order
//! `L = 2⁴⁴⁶ − 13818066809895115352007386748515426880336692474882178609894547503885`.
//!
//! These are the low-level scalar helpers used by Ed448. Reduction rides on the
//! constant-time [`Uint`](crate::bignum::Uint) long division. The Ed448 nonce
//! and challenge are SHAKE256 outputs of 114 bytes (912 bits), so the wide
//! integers here are fifteen limbs (960 bits) to hold them without truncation.

use crate::bignum::Uint;

use super::field::Fe;

/// Truncates a 15-limb integer to its low seven limbs (448 bits).
fn narrow(a: &Uint<15>) -> Fe {
    let l = a.as_limbs();
    Uint::from_limbs([l[0], l[1], l[2], l[3], l[4], l[5], l[6]])
}

/// Zero-extends a seven-limb integer to fifteen limbs.
fn widen(a: &Fe) -> Uint<15> {
    let l = a.as_limbs();
    Uint::from_limbs([
        l[0], l[1], l[2], l[3], l[4], l[5], l[6], 0, 0, 0, 0, 0, 0, 0, 0,
    ])
}

/// Reduces a 114-byte little-endian integer modulo `L`.
pub(crate) fn scalar_reduce_wide(bytes: &[u8; 114], l15: &Uint<15>) -> Fe {
    // 114 bytes fit in fifteen 64-bit limbs (120 bytes); the top six bytes are
    // zero-padded by `from_le_bytes`.
    narrow(&Uint::<15>::from_le_bytes(bytes).reduce(l15))
}

/// Computes `(r + k·a) mod L` for `r, k, a < L`.
pub(crate) fn scalar_muladd(r: &Fe, k: &Fe, a: &Fe, l15: &Uint<15>) -> Fe {
    // k·a is the full 14-limb product; widen both operands to 15 limbs so the
    // sum with r cannot carry out of the representation.
    let (lo, hi) = k.mul_wide(a); // each seven limbs
    let lo = lo.as_limbs();
    let hi = hi.as_limbs();
    let prod = Uint::<15>::from_limbs([
        lo[0], lo[1], lo[2], lo[3], lo[4], lo[5], lo[6], hi[0], hi[1], hi[2], hi[3], hi[4], hi[5],
        hi[6], 0,
    ]);
    let (sum, _) = prod.adc(&widen(r), 0);
    narrow(&sum.reduce(l15))
}

/// Prunes the lower 57 bytes of the seed hash into the secret scalar
/// (RFC 8032 §5.2.5): clear the bottom two bits, set bit 447, clear the top
/// byte. The result `s` is read little-endian from `b[0..57]`.
pub(crate) fn prune(b: &mut [u8; 57]) {
    b[0] &= 0xFC;
    b[55] |= 0x80;
    b[56] = 0;
}
