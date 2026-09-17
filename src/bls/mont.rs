//! Fixed-limb Montgomery arithmetic shared by the 381-bit base field
//! ([`Fp`](super::Fp), six limbs) and the 255-bit scalar field
//! ([`Fr`](super::Fr), four limbs).
//!
//! Every routine here runs a fixed schedule in the element values: loop
//! bounds are the limb count, carries propagate unconditionally, and the
//! final canonicalisation is a masked conditional subtraction. Nothing
//! branches on limb contents, so the field layers built on top inherit
//! constant-time behaviour for free.

use crate::ct::Choice;

/// `a + b·c + carry` as `(low, high)`.
#[inline(always)]
pub(crate) const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// `a + b + carry` as `(sum, carry)`.
#[inline(always)]
pub(crate) const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// `a - b - borrow` as `(difference, borrow)` with `borrow ∈ {0, 1}`.
#[inline(always)]
pub(crate) const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (t as u64, ((t >> 64) as u64) & 1)
}

/// All-ones when `bit == 1`, all-zeros when `bit == 0`.
#[inline(always)]
const fn mask_from_bit(bit: u64) -> u64 {
    0u64.wrapping_sub(bit & 1)
}

/// Reduces `hi·2^(64N) + r` (with `hi ∈ {0, 1}` and the whole value `< 2m`)
/// into `[0, m)` by one masked conditional subtraction of `m`.
#[inline]
pub(crate) fn reduce_once<const N: usize>(r: [u64; N], hi: u64, m: &[u64; N]) -> [u64; N] {
    let mut d = [0u64; N];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < N {
        let (v, b) = sbb(r[i], m[i], borrow);
        d[i] = v;
        borrow = b;
        i += 1;
    }
    // The value is >= m iff there was a high bit or no final borrow.
    let mask = mask_from_bit(hi | (borrow ^ 1));
    let mut out = [0u64; N];
    let mut i = 0;
    while i < N {
        out[i] = (r[i] & !mask) | (d[i] & mask);
        i += 1;
    }
    out
}

/// `(a + b) mod m` for `a, b < m`.
#[inline]
pub(crate) fn add<const N: usize>(a: &[u64; N], b: &[u64; N], m: &[u64; N]) -> [u64; N] {
    let mut r = [0u64; N];
    let mut carry = 0u64;
    let mut i = 0;
    while i < N {
        let (v, c) = adc(a[i], b[i], carry);
        r[i] = v;
        carry = c;
        i += 1;
    }
    reduce_once(r, carry, m)
}

/// `(a - b) mod m` for `a, b < m`.
#[inline]
pub(crate) fn sub<const N: usize>(a: &[u64; N], b: &[u64; N], m: &[u64; N]) -> [u64; N] {
    let mut r = [0u64; N];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < N {
        let (v, bo) = sbb(a[i], b[i], borrow);
        r[i] = v;
        borrow = bo;
        i += 1;
    }
    // Add `m` back when the subtraction underflowed.
    let mask = mask_from_bit(borrow);
    let mut carry = 0u64;
    let mut i = 0;
    while i < N {
        let (v, c) = adc(r[i], m[i] & mask, carry);
        r[i] = v;
        carry = c;
        i += 1;
    }
    r
}

/// `(-a) mod m` for `a < m`; zero maps to zero.
#[inline]
pub(crate) fn neg<const N: usize>(a: &[u64; N], m: &[u64; N]) -> [u64; N] {
    let mut r = [0u64; N];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < N {
        let (v, bo) = sbb(m[i], a[i], borrow);
        r[i] = v;
        borrow = bo;
        i += 1;
    }
    // `m - 0 = m` must fold back to zero: mask by "a != 0".
    let nz = mask_from_bit(is_nonzero_bit(a));
    let mut i = 0;
    while i < N {
        r[i] &= nz;
        i += 1;
    }
    r
}

/// `1` when any limb is nonzero, else `0` (branch-free).
#[inline]
pub(crate) fn is_nonzero_bit<const N: usize>(a: &[u64; N]) -> u64 {
    let mut acc = 0u64;
    let mut i = 0;
    while i < N {
        acc |= a[i];
        i += 1;
    }
    (acc | acc.wrapping_neg()) >> 63
}

/// Constant-time equality of two limb arrays.
#[inline]
pub(crate) fn ct_eq<const N: usize>(a: &[u64; N], b: &[u64; N]) -> Choice {
    let mut acc = 0u64;
    let mut i = 0;
    while i < N {
        acc |= a[i] ^ b[i];
        i += 1;
    }
    Choice::from(core::hint::black_box(
        (((acc | acc.wrapping_neg()) >> 63) ^ 1) as u8,
    ))
}

/// Constant-time select: `a` when `choice` is true, else `b`.
#[inline]
pub(crate) fn select<const N: usize>(a: &[u64; N], b: &[u64; N], choice: Choice) -> [u64; N] {
    let mask = core::hint::black_box((choice.unwrap_u8() as u64).wrapping_neg());
    let mut out = [0u64; N];
    let mut i = 0;
    while i < N {
        out[i] = b[i] ^ (mask & (a[i] ^ b[i]));
        i += 1;
    }
    out
}

/// `1` when `a < m` as integers (branch-free), else `0`.
#[inline]
pub(crate) fn lt_bit<const N: usize>(a: &[u64; N], m: &[u64; N]) -> u64 {
    let mut borrow = 0u64;
    let mut i = 0;
    while i < N {
        let (_, b) = sbb(a[i], m[i], borrow);
        borrow = b;
        i += 1;
    }
    borrow
}

/// Montgomery product `a·b·2^(-64N) mod m` for `a, b < m`, with
/// `inv = -m^(-1) mod 2^64`. Schoolbook product followed by word-by-word
/// Montgomery reduction (CIOS); the result is canonical.
#[inline]
pub(crate) fn mul<const N: usize>(a: &[u64; N], b: &[u64; N], m: &[u64; N], inv: u64) -> [u64; N] {
    const { assert!(N <= 6) };
    // Full 2N-limb product (plus one spare limb for the reduction carry).
    let mut t = [0u64; 13];
    let mut i = 0;
    while i < N {
        let mut carry = 0u64;
        let mut j = 0;
        while j < N {
            let (v, c) = mac(t[i + j], a[i], b[j], carry);
            t[i + j] = v;
            carry = c;
            j += 1;
        }
        t[i + N] = carry;
        i += 1;
    }
    mont_reduce::<N>(&mut t, m, inv)
}

/// Montgomery squaring, `a·a·2^(-64N) mod m`.
#[inline]
pub(crate) fn square<const N: usize>(a: &[u64; N], m: &[u64; N], inv: u64) -> [u64; N] {
    mul(a, a, m, inv)
}

/// Reduces the `2N`-limb value in `t[..2N]` (with `t[2N]` a spare limb that
/// must be zero on entry) to `t·2^(-64N) mod m`.
#[inline]
fn mont_reduce<const N: usize>(t: &mut [u64; 13], m: &[u64; N], inv: u64) -> [u64; N] {
    let mut i = 0;
    while i < N {
        let k = t[i].wrapping_mul(inv);
        let mut carry = 0u64;
        let mut j = 0;
        while j < N {
            let (v, c) = mac(t[i + j], k, m[j], carry);
            t[i + j] = v;
            carry = c;
            j += 1;
        }
        // Propagate the carry through the remaining upper limbs.
        let mut idx = i + N;
        while idx <= 2 * N {
            let (v, c) = adc(t[idx], 0, carry);
            t[idx] = v;
            carry = c;
            idx += 1;
        }
        i += 1;
    }
    let mut r = [0u64; N];
    let mut i = 0;
    while i < N {
        r[i] = t[N + i];
        i += 1;
    }
    reduce_once(r, t[2 * N], m)
}

/// Fixed-schedule exponentiation `base^e` (square-and-multiply over every
/// bit of `e`, most significant limb last in the array). The schedule
/// depends only on the exponent's bit *length*, so with a public exponent —
/// the only way it is used here — the running time is independent of the
/// base.
#[inline]
pub(crate) fn pow<const N: usize>(
    base: &[u64; N],
    e: &[u64],
    one: &[u64; N],
    m: &[u64; N],
    inv: u64,
) -> [u64; N] {
    let mut acc = *one;
    let mut i = e.len();
    while i > 0 {
        i -= 1;
        let mut bit = 64;
        while bit > 0 {
            bit -= 1;
            acc = square(&acc, m, inv);
            let prod = mul(&acc, base, m, inv);
            let take = Choice::from(((e[i] >> bit) & 1) as u8);
            acc = select(&prod, &acc, take);
        }
    }
    acc
}

/// Loads a big-endian byte string of exactly `8N` bytes as limbs.
#[inline]
pub(crate) fn from_be_bytes<const N: usize>(bytes: &[u8]) -> [u64; N] {
    debug_assert_eq!(bytes.len(), 8 * N);
    let mut out = [0u64; N];
    let mut i = 0;
    while i < N {
        let off = 8 * (N - 1 - i);
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[off..off + 8]);
        out[i] = u64::from_be_bytes(w);
        i += 1;
    }
    out
}

/// Writes limbs as a big-endian byte string of exactly `8N` bytes.
#[inline]
pub(crate) fn to_be_bytes<const N: usize>(limbs: &[u64; N], out: &mut [u8]) {
    debug_assert_eq!(out.len(), 8 * N);
    let mut i = 0;
    while i < N {
        let off = 8 * (N - 1 - i);
        out[off..off + 8].copy_from_slice(&limbs[i].to_be_bytes());
        i += 1;
    }
}
