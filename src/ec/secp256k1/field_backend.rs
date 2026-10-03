//! Base-field backend for the const-generic secp256k1 implementation.
//!
//! The point arithmetic in [`super::group`] is generic over a [`FieldBackend`]
//! so the base field `GF(p)` with `p = 2²⁵⁶ − 2³² − 977` can be implemented
//! several ways behind one interface. Two backends exist:
//!
//! - [`Secp256k1Field`] — the native pseudo-Mersenne backend the public API is
//!   wired to (via the `Backend` alias in [`super`]): schoolbook 4×4 limb
//!   multiplication followed by a reduction specialised to `2²⁵⁶ ≡ c (mod p)`
//!   with `c = 2³² + 977`, all branch-free and mask-driven.
//! - [`GenericMont`] — wraps the crate's generic 4-limb [`MontModulus`] CIOS
//!   arithmetic, exactly the numeric core P-256 uses. It is the reference
//!   oracle: the differential tests at the bottom of this file check the
//!   native backend against it operation by operation, and it remains a
//!   `pub(crate)` fallback that slots in by changing that one alias.
//!
//! Field elements are carried as plain (non-Montgomery) residues `< p`, stored
//! as a [`Uint<4>`]; this is the representation the SEC1 codec serialises.

// `from_bytes_be(&self, ..)` is parameterised by the backend instance (it is a
// method, not a free constructor), so the `from_*`-takes-no-self heuristic does
// not apply to this trait.
#![allow(clippy::wrong_self_convention)]

use crate::bignum::safegcd::SafegcdModulus;
use crate::bignum::{MontModulus, Uint};
use crate::ct::{Choice, ConstantTimeEq, ConstantTimeLess};

/// A 256-bit base-field element, four little-endian 64-bit limbs.
pub(crate) type Fe = Uint<4>;

/// A constant-time optional field element: the value is always materialised,
/// and `is_some` indicates whether it is meaningful. Used by fallible field
/// operations (square root, canonical decode) so the caller can branch only at
/// the public boundary, where presence is no longer secret.
#[derive(Clone, Copy)]
pub(crate) struct CtOption {
    value: Fe,
    is_some: Choice,
}

impl CtOption {
    /// Creates an option carrying `value`, present iff `is_some` is true.
    #[inline]
    pub(crate) fn new(value: Fe, is_some: Choice) -> Self {
        CtOption { value, is_some }
    }
    /// Converts to a plain [`Option`] at the public boundary, where presence is
    /// no longer secret. **Not** constant time in the presence flag.
    #[inline]
    pub(crate) fn into_option(self) -> Option<Fe> {
        if bool::from(self.is_some) {
            Some(self.value)
        } else {
            None
        }
    }
}

/// The secp256k1 base-field prime `p = 2²⁵⁶ − 2³² − 977`, big-endian hex.
pub(crate) const P_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

/// Decodes a 64-character big-endian hex string into an [`Fe`].
pub(crate) const fn fe_from_hex(hex: &str) -> Fe {
    super::super::uint_from_be_hex(hex)
}

/// Returns the prime `p` as a [`Fe`].
#[inline]
pub(crate) const fn p() -> Fe {
    fe_from_hex(P_HEX)
}

/// The square-root exponent `(p + 1) / 4` for the `p ≡ 3 (mod 4)` root formula.
#[cfg_attr(not(test), allow(dead_code))]
fn sqrt_exponent() -> Fe {
    // (p + 1) / 4. Computed directly from p to avoid a second hard-coded constant.
    let p_plus_1 = p().wrapping_add(&Fe::ONE);
    p_plus_1.shr1().shr1()
}

/// The Fermat-inverse exponent `p - 2`, computed directly from `p`.
#[cfg(test)]
fn p_minus_2() -> Fe {
    p().wrapping_sub(&Fe::from_u64(2))
}

/// Constant-time arithmetic over the secp256k1 base field `GF(p)`.
///
/// All methods operate on plain residues in `[0, p)` and are constant time in
/// the element values (no secret-dependent branches or table indexing).
pub(crate) trait FieldBackend {
    /// The additive identity `0`.
    fn zero(&self) -> Fe;
    /// The multiplicative identity `1`.
    fn one(&self) -> Fe;
    /// Returns `(a + b) mod p`.
    fn add(&self, a: &Fe, b: &Fe) -> Fe;
    /// Returns `(a - b) mod p`.
    fn sub(&self, a: &Fe, b: &Fe) -> Fe;
    /// Returns `(a * b) mod p`.
    fn mul(&self, a: &Fe, b: &Fe) -> Fe;
    /// Returns `a^2 mod p`.
    #[inline]
    fn square(&self, a: &Fe) -> Fe {
        self.mul(a, a)
    }
    /// Returns `(a * k) mod p` for a small constant `k` (the curve's
    /// `b3 = 21`).
    #[inline]
    fn mul_small(&self, a: &Fe, k: u32) -> Fe {
        self.mul(a, &Fe::from_u64(u64::from(k)))
    }
    /// Returns `(-a) mod p`.
    fn negate(&self, a: &Fe) -> Fe;
    /// Returns the modular inverse `a^-1 mod p` (constant time). The
    /// inverse of `0` is `0`.
    fn invert(&self, a: &Fe) -> Fe;
    /// Returns a square root of `a` if one exists. When `a` is a non-residue
    /// the [`CtOption`] is empty; the contained value is then unspecified.
    fn sqrt(&self, a: &Fe) -> CtOption;
    /// Decodes a 32-byte big-endian field element, rejecting any encoding `>= p`.
    fn from_bytes_be(&self, bytes: &[u8; 32]) -> CtOption;
    /// Serialises an element as 32 big-endian bytes.
    fn to_bytes_be(&self, a: &Fe) -> [u8; 32];
}

/// Base-field backend over the crate's generic 4-limb Montgomery arithmetic.
///
/// Reuses exactly the [`MontModulus`] core that P-256 uses. The modulus context
/// is built once when the backend is constructed.
///
/// Now that the public API is wired to [`Secp256k1Field`], this backend is no
/// longer on the runtime path; it is retained as the differential-test oracle
/// (see `backend_tests`) and a `pub(crate)` fallback, so it is only constructed
/// from `#[cfg(test)]` code — hence the `not(test)` dead-code allowance.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct GenericMont {
    fp: MontModulus<4>,
}

impl GenericMont {
    /// Builds the backend (computes the Montgomery constants once).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new() -> Self {
        GenericMont {
            fp: MontModulus::new(p()),
        }
    }
}

impl FieldBackend for GenericMont {
    #[inline]
    fn zero(&self) -> Fe {
        Fe::ZERO
    }
    #[inline]
    fn one(&self) -> Fe {
        Fe::ONE
    }
    #[inline]
    fn add(&self, a: &Fe, b: &Fe) -> Fe {
        self.fp.add_mod(a, b)
    }
    #[inline]
    fn sub(&self, a: &Fe, b: &Fe) -> Fe {
        self.fp.sub_mod(a, b)
    }
    #[inline]
    fn mul(&self, a: &Fe, b: &Fe) -> Fe {
        self.fp.mul_mod(a, b)
    }
    #[inline]
    fn negate(&self, a: &Fe) -> Fe {
        self.fp.sub_mod(&Fe::ZERO, a)
    }
    fn invert(&self, a: &Fe) -> Fe {
        // Fermat: a^(p-2) mod p, via the constant-time Montgomery ladder.
        let p_minus_2 = p().wrapping_sub(&Fe::from_u64(2));
        self.fp.pow(a, &p_minus_2)
    }
    fn sqrt(&self, a: &Fe) -> CtOption {
        // p ≡ 3 (mod 4) ⇒ candidate root a^((p+1)/4); valid iff its square == a.
        let cand = self.fp.pow(a, &sqrt_exponent());
        let ok = self.mul(&cand, &cand).ct_eq(a);
        CtOption::new(cand, ok)
    }
    fn from_bytes_be(&self, bytes: &[u8; 32]) -> CtOption {
        let v = Fe::from_be_bytes(bytes);
        let in_range = v.ct_lt(&p());
        CtOption::new(v, in_range)
    }
    fn to_bytes_be(&self, a: &Fe) -> [u8; 32] {
        let mut out = [0u8; 32];
        a.write_be_bytes(&mut out);
        out
    }
}

// =====================================================================
// Native pseudo-Mersenne backend
// =====================================================================

/// The folding constant `c = 2³² + 977 = 0x1_0000_03D1` (33 bits).
///
/// secp256k1's prime is `p = 2²⁵⁶ − c`, so the reduction identity is
/// `2²⁵⁶ ≡ c (mod p)`: any overflow past 256 bits is folded back by
/// multiplying it by `c` and adding it in.
const C: u128 = 0x1_0000_03D1;

/// The prime `p` as little-endian 64-bit limbs (`p = 2²⁵⁶ − 2³² − 977`).
const P_LIMBS: [u64; 4] = [
    0xFFFF_FFFE_FFFF_FC2F,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// Native secp256k1 base-field backend using a pseudo-Mersenne reduction
/// specialised to `p = 2²⁵⁶ − 2³² − 977`.
///
/// Internally elements are four little-endian `u64` limbs in canonical
/// `[0, p)` form — the exact in-memory layout of [`Fe`], so the trait-boundary
/// conversions are pure reinterpretations. Multiplication uses a schoolbook
/// 256×256→512 product folded back through `2²⁵⁶ ≡ c`; the carry is folded a
/// fixed number of times (no data-dependent loop counts), then one mask-based
/// conditional subtraction of `p` restores canonical form. All
/// operations are constant time in the element values; only the public prime
/// and (public) Fermat / square-root exponents drive any branching.
pub(crate) struct Secp256k1Field;

impl Secp256k1Field {
    /// Builds the native backend (stateless).
    #[inline]
    pub(crate) fn new() -> Self {
        Secp256k1Field
    }
}

/// Adds `carry * C` into the four limbs `r`, returning the new limbs and the
/// 0/1 carry that propagated out of the most significant limb.
///
/// `carry` is bounded by `2³⁴` on the first fold (`< 2⁶⁷` after multiplying by
/// `C`); subsequent folds pass a 0/1 carry, so `carry * C < 2³³`. Either way the
/// carry out is small and shrinks to a single bit after the first fold.
#[inline]
fn fold_carry(mut r: [u64; 4], carry: u64) -> ([u64; 4], u64) {
    let mut acc: u128 = (r[0] as u128) + (carry as u128) * C;
    r[0] = acc as u64;
    acc >>= 64;
    let mut i = 1;
    while i < 4 {
        acc += r[i] as u128;
        r[i] = acc as u64;
        acc >>= 64;
        i += 1;
    }
    (r, acc as u64)
}

/// Expands a secret-derived `0`/`1` limb into an all-ones / all-zeros mask
/// without a branch: `wrapping_neg`, behind a `black_box` barrier so LLVM
/// cannot turn the mask back into a conditional jump. Takes the bit as a
/// limb rather than a `bool` so no comparison exists for the compiler to
/// re-materialise as a jump.
#[inline]
fn mask_from_bit(bit: u64) -> u64 {
    core::hint::black_box(bit.wrapping_neg())
}

/// Selects `a` when `mask == 0` and `b` when `mask == 0xFFFF…FF`, per limb.
#[inline]
fn select(a: &[u64; 4], b: &[u64; 4], mask: u64) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        out[i] = (a[i] & !mask) | (b[i] & mask);
        i += 1;
    }
    out
}

/// Canonicalises `hi·2²⁵⁶ + r` into `[0, p)`, given that the value is `< 2p`
/// (`hi <= 1`).
///
/// One masked correction suffices: the value is `>= p` iff adding
/// `c = 2²⁵⁶ − p` carries past `2²⁵⁶` (or `hi` is already set), and in that
/// case the low 256 bits of `r + c` are exactly `value − p`. (With `hi = 1`
/// the value is `< 2p`, so `r + c < p` and the addition itself cannot carry.)
/// The add runs unconditionally and the result is picked by a mask, so there
/// is no secret-dependent branch.
#[inline]
fn canonicalize(r: [u64; 4], hi: u64) -> [u64; 4] {
    let (w, carry) = fold_carry(r, 1);
    select(&r, &w, mask_from_bit(hi | carry))
}

/// Folds a 512-bit product (eight little-endian limbs) down to canonical
/// `[0, p)` using `2²⁵⁶ ≡ c`.
#[inline]
fn reduce512(t: [u64; 8]) -> [u64; 4] {
    // r = lo + hi*c, computed limb-by-limb with a u128 running accumulator.
    // Each hi[i]*C < 2⁹⁷ fits in u128; the carry-out d after four limbs is
    // bounded by 2³⁴.
    let mut r = [0u64; 4];
    let mut carry: u128 = 0;
    let mut i = 0;
    while i < 4 {
        let acc = (t[i] as u128) + carry + (t[i + 4] as u128) * C;
        r[i] = acc as u64;
        carry = acc >> 64;
        i += 1;
    }
    let d = carry as u64; // < 2³⁴

    // Fold d·c (< 2⁶⁷) back in; it can carry out at most one bit, c1. When
    // it does, the wrapped low part is < d·c < 2⁶⁷, so folding c1·c (< 2³⁴)
    // a second time cannot carry again: two folds always leave a value
    // < 2²⁵⁶ < 2p, which `canonicalize` finishes. The schedule is fixed.
    let (r, c1) = fold_carry(r, d);
    let (r, c2) = fold_carry(r, c1);
    debug_assert_eq!(c2, 0);
    canonicalize(r, c2)
}

/// Schoolbook 256×256→512 multiply of two little-endian 4-limb operands.
#[inline]
fn mul_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut t = [0u64; 8];
    let mut i = 0;
    while i < 4 {
        let mut carry: u128 = 0;
        let mut j = 0;
        while j < 4 {
            let acc = (t[i + j] as u128) + (a[i] as u128) * (b[j] as u128) + carry;
            t[i + j] = acc as u64;
            carry = acc >> 64;
            j += 1;
        }
        t[i + 4] = carry as u64;
        i += 1;
    }
    t
}

/// 256-bit → 512-bit squaring: the six distinct cross products `aᵢ·aⱼ`
/// (`i < j`) are summed once and doubled by a one-bit shift, then the four
/// diagonal squares are added — 10 limb products instead of `mul_wide`'s 16.
#[inline]
fn square_wide(a: &[u64; 4]) -> [u64; 8] {
    // Cross products into t[1..7].
    let mut t = [0u64; 8];
    let mut i = 0;
    while i < 3 {
        let mut carry: u128 = 0;
        let mut j = i + 1;
        while j < 4 {
            let acc = (t[i + j] as u128) + (a[i] as u128) * (a[j] as u128) + carry;
            t[i + j] = acc as u64;
            carry = acc >> 64;
            j += 1;
        }
        t[i + 4] = carry as u64;
        i += 1;
    }
    // Double: the cross sum is < 2⁵¹¹, so the shift loses nothing.
    let mut k = 7;
    while k > 0 {
        t[k] = (t[k] << 1) | (t[k - 1] >> 63);
        k -= 1;
    }
    t[0] <<= 1;
    // Add the diagonal squares aᵢ² at t[2i..2i+2].
    let mut carry: u128 = 0;
    let mut i = 0;
    while i < 4 {
        let sq = (a[i] as u128) * (a[i] as u128);
        let lo = (t[2 * i] as u128) + (sq as u64 as u128) + carry;
        t[2 * i] = lo as u64;
        let hi = (t[2 * i + 1] as u128) + (sq >> 64) + (lo >> 64);
        t[2 * i + 1] = hi as u64;
        carry = hi >> 64;
        i += 1;
    }
    t
}

impl Secp256k1Field {
    /// Field multiplication on raw limbs.
    #[inline]
    fn mul_limbs(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        reduce512(mul_wide(a, b))
    }
}

impl FieldBackend for Secp256k1Field {
    #[inline]
    fn zero(&self) -> Fe {
        Fe::ZERO
    }
    #[inline]
    fn one(&self) -> Fe {
        Fe::ONE
    }
    #[inline]
    fn add(&self, a: &Fe, b: &Fe) -> Fe {
        let a = a.as_limbs();
        let b = b.as_limbs();
        let mut r = [0u64; 4];
        let mut carry: u128 = 0;
        let mut i = 0;
        while i < 4 {
            let acc = (a[i] as u128) + (b[i] as u128) + carry;
            r[i] = acc as u64;
            carry = acc >> 64;
            i += 1;
        }
        // Sum < 2p, so one masked −p restores [0, p).
        Fe::from_limbs(canonicalize(r, carry as u64))
    }
    #[inline]
    fn sub(&self, a: &Fe, b: &Fe) -> Fe {
        let a = a.as_limbs();
        let b = b.as_limbs();
        let mut r = [0u64; 4];
        let mut borrow: u128 = 0;
        let mut i = 0;
        while i < 4 {
            let tmp = (a[i] as u128).wrapping_sub(b[i] as u128 + borrow);
            r[i] = tmp as u64;
            borrow = (tmp >> 64) & 1;
            i += 1;
        }
        // On underflow, add p back (constant-time, mask-driven).
        let mask = mask_from_bit(borrow as u64);
        let mut out = [0u64; 4];
        let mut carry: u128 = 0;
        let mut j = 0;
        while j < 4 {
            let acc = (r[j] as u128) + ((P_LIMBS[j] & mask) as u128) + carry;
            out[j] = acc as u64;
            carry = acc >> 64;
            j += 1;
        }
        Fe::from_limbs(out)
    }
    #[inline]
    fn mul(&self, a: &Fe, b: &Fe) -> Fe {
        Fe::from_limbs(Self::mul_limbs(a.as_limbs(), b.as_limbs()))
    }
    #[inline]
    fn square(&self, a: &Fe) -> Fe {
        Fe::from_limbs(reduce512(square_wide(a.as_limbs())))
    }
    #[inline]
    fn mul_small(&self, a: &Fe, k: u32) -> Fe {
        // a·k < 2²⁸⁸: four limb products leave a carry h < 2³². Folding h·c
        // (< 2⁶⁵) carries at most one bit, after which the wrapped value is
        // < 2⁶⁵ and folding that bit cannot carry again — the same argument
        // as `reduce512`, from a much smaller excess.
        let a = a.as_limbs();
        let mut r = [0u64; 4];
        let mut carry: u128 = 0;
        let mut i = 0;
        while i < 4 {
            let acc = (a[i] as u128) * (k as u128) + carry;
            r[i] = acc as u64;
            carry = acc >> 64;
            i += 1;
        }
        let (r, c1) = fold_carry(r, carry as u64);
        let (r, c2) = fold_carry(r, c1);
        debug_assert_eq!(c2, 0);
        Fe::from_limbs(canonicalize(r, c2))
    }
    #[inline]
    fn negate(&self, a: &Fe) -> Fe {
        let a = a.as_limbs();
        // p - a, then select 0 when a == 0 (since p - 0 == p is non-canonical).
        let mut r = [0u64; 4];
        let mut borrow: u128 = 0;
        let mut i = 0;
        while i < 4 {
            let tmp = (P_LIMBS[i] as u128).wrapping_sub(a[i] as u128 + borrow);
            r[i] = tmp as u64;
            borrow = (tmp >> 64) & 1;
            i += 1;
        }
        let acc = a[0] | a[1] | a[2] | a[3];
        // Top bit of `acc | -acc` is 1 iff `acc != 0`; invert for "is zero".
        let zero_mask = mask_from_bit(((acc | acc.wrapping_neg()) >> 63) ^ 1);
        let out = select(&r, &[0u64; 4], zero_mask);
        Fe::from_limbs(out)
    }
    fn invert(&self, a: &Fe) -> Fe {
        // Bernstein–Yang safegcd (a fixed 590-divstep schedule): constant
        // time, and ~2.7× faster than the Fermat chain (`invert_chain`).
        // Elements are canonical (< p), as the inversion requires.
        SAFEGCD_P.invert(a)
    }
    fn sqrt(&self, a: &Fe) -> CtOption {
        // p ≡ 3 (mod 4) ⇒ candidate root a^((p+1)/4); valid iff its square == a.
        let cand = self.sqrt_candidate(a);
        let ok = self.square(&cand).ct_eq(a);
        CtOption::new(cand, ok)
    }
    fn from_bytes_be(&self, bytes: &[u8; 32]) -> CtOption {
        let v = Fe::from_be_bytes(bytes);
        let in_range = v.ct_lt(&p());
        CtOption::new(v, in_range)
    }
    fn to_bytes_be(&self, a: &Fe) -> [u8; 32] {
        let mut out = [0u8; 32];
        a.write_be_bytes(&mut out);
        out
    }
}

/// The safegcd inversion context for `p`, built at compile time.
const SAFEGCD_P: SafegcdModulus = SafegcdModulus::new(&p());

impl Secp256k1Field {
    /// Fermat inversion `a^(p-2)`, with p − 2 = [1]²²³ 0 [1]²² 0000 101101
    /// in binary (libsecp256k1's chain): 255 squarings and 15
    /// multiplications. The previous [`invert`](FieldBackend::invert), kept
    /// as its differential oracle.
    #[cfg(test)]
    fn invert_chain(&self, a: &Fe) -> Fe {
        let (x2, t) = self.pow_chain_prefix(a);
        let t = self.mul(&self.sqn(&t, 5), a);
        let t = self.mul(&self.sqn(&t, 3), &x2);
        self.mul(&self.sqn(&t, 2), a)
    }

    /// The principal square-root candidate `a^((p+1)/4)`, whether or not `a`
    /// is a residue (for a non-residue its square is `−a`).
    ///
    /// (p + 1)/4 = [1]²²³ 0 [1]²² 0000 11 00 in binary: the inverse's chain
    /// prefix, then 6 + 2 more squarings and one multiplication.
    pub(crate) fn sqrt_candidate(&self, a: &Fe) -> Fe {
        let (x2, t) = self.pow_chain_prefix(a);
        let t = self.mul(&self.sqn(&t, 6), &x2);
        self.sqn(&t, 2)
    }

    /// `a^(2^n)`: `n` successive squarings.
    #[inline]
    fn sqn(&self, a: &Fe, n: u32) -> Fe {
        let mut r = *a;
        for _ in 0..n {
            r = self.square(&r);
        }
        r
    }

    /// The shared head of the fixed inversion / square-root addition chains
    /// (libsecp256k1's `secp256k1_fe_inv` / `_sqrt`). Writing `xk` for
    /// `a^(2^k − 1)` (k one bits), returns `(x2, x223·2²³ · x22)`, the second
    /// being `a` raised to `[1]²²³ 0 [1]²²`, the top 246 bits both exponents
    /// share.
    ///
    /// The chain is a fixed sequence of squarings and multiplications set by
    /// the public modulus alone, so it is constant time in `a` without any
    /// per-bit select.
    fn pow_chain_prefix(&self, a: &Fe) -> (Fe, Fe) {
        let x2 = self.mul(&self.square(a), a);
        let x3 = self.mul(&self.square(&x2), a);
        let x6 = self.mul(&self.sqn(&x3, 3), &x3);
        let x9 = self.mul(&self.sqn(&x6, 3), &x3);
        let x11 = self.mul(&self.sqn(&x9, 2), &x2);
        let x22 = self.mul(&self.sqn(&x11, 11), &x11);
        let x44 = self.mul(&self.sqn(&x22, 22), &x22);
        let x88 = self.mul(&self.sqn(&x44, 44), &x44);
        let x176 = self.mul(&self.sqn(&x88, 88), &x88);
        let x220 = self.mul(&self.sqn(&x176, 44), &x44);
        let x223 = self.mul(&self.sqn(&x220, 3), &x3);
        let t = self.mul(&self.sqn(&x223, 23), &x22);
        (x2, t)
    }

    /// Generic exponentiation, kept as the test oracle for the fixed
    /// addition chains above.
    ///
    /// Constant-time modular exponentiation by a **public** exponent, via
    /// square-and-always-multiply (Montgomery-ladder-style: the multiply runs
    /// every bit and the result is selected by the public exponent bit, so the
    /// secret base never drives a branch).
    #[cfg(test)]
    fn pow(&self, base: &Fe, exp: &Fe) -> Fe {
        let exp = exp.as_limbs();
        let mut acc = Fe::ONE;
        let mut i = 4;
        while i > 0 {
            i -= 1;
            let limb = exp[i];
            let mut bit = 64;
            while bit > 0 {
                bit -= 1;
                acc = self.square(&acc);
                let prod = self.mul(&acc, base);
                // The exponent is public, so a branch here would leak
                // nothing; the mask select is used anyway because LLVM
                // lowered the branch to `bt`+`jcc`, whose stale flag state
                // memcheck (tests/ct_valgrind.rs) conflates with the
                // secret base.
                let take = mask_from_bit((limb >> bit) & 1);
                acc = Fe::from_limbs(select(acc.as_limbs(), prod.as_limbs(), take));
            }
        }
        acc
    }
}

#[cfg(test)]
mod backend_tests {
    //! Differential tests: the native [`Secp256k1Field`] backend must agree
    //! byte-for-byte with the generic Montgomery oracle [`GenericMont`] on
    //! every field operation, across edge cases and a large deterministic
    //! pseudo-random batch.

    use super::*;

    /// Deterministic SplitMix64 PRNG seeded from a literal — reproducible, no
    /// system randomness, so a failure always reprints the same offending case.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    /// A pseudo-random 256-bit value reduced into `[0, p)` via the oracle.
    fn rand_fe(rng: &mut SplitMix64) -> Fe {
        let limbs = [
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
        ];
        Fe::from_limbs(limbs).reduce(&p())
    }

    /// Canonical 32-byte big-endian encoding, independent of which backend
    /// produced `a` (both return canonical `[0, p)` residues).
    fn bytes(a: &Fe) -> [u8; 32] {
        let mut out = [0u8; 32];
        a.write_be_bytes(&mut out);
        out
    }

    /// Field elements at and around the dangerous boundaries, all in `[0, p)`.
    fn edge_cases() -> [Fe; 12] {
        let prime = p();
        let p_minus_1 = prime.wrapping_sub(&Fe::ONE);
        let p_minus_2 = prime.wrapping_sub(&Fe::from_u64(2));
        // 2²⁵⁶ − 1 reduced mod p (== c − 1, the largest near-2²⁵⁶ pattern).
        let all_ones = Fe::from_limbs([u64::MAX; 4]).reduce(&prime);
        // A value just below p (p - 1) in the low-limb band.
        let near_low = Fe::from_limbs([0xFFFF_FFFE_FFFF_FC2E, !0, !0, !0]);
        let mid = Fe::from_limbs([0, 0, 0, 0x8000_0000_0000_0000]);
        [
            Fe::ZERO,
            Fe::ONE,
            Fe::from_u64(2),
            Fe::from_u64(7),
            p_minus_1,
            p_minus_2,
            all_ones,
            near_low,
            mid,
            Fe::from_u64(0xFFFF_FFFF),
            Fe::from_limbs([C as u64, 0, 0, 0]),
            Fe::from_limbs([(C as u64) - 1, 0, 0, 0]),
        ]
    }

    fn check_pair(g: &GenericMont, n: &Secp256k1Field, a: &Fe, b: &Fe) {
        // `mul_small` against a full multiplication, with `k` taken from the
        // low 32 bits of `b` (so the edge cases reach k = 0 and 2³² − 1).
        let k = b.as_limbs()[0] as u32;
        assert_eq!(
            bytes(&g.mul(a, &Fe::from_u64(u64::from(k)))),
            bytes(&n.mul_small(a, k)),
            "mul_small mismatch: a={:x?} k={k}",
            a.as_limbs()
        );
        assert_eq!(
            bytes(&g.add(a, b)),
            bytes(&n.add(a, b)),
            "add mismatch: a={:x?} b={:x?}",
            a.as_limbs(),
            b.as_limbs()
        );
        assert_eq!(
            bytes(&g.sub(a, b)),
            bytes(&n.sub(a, b)),
            "sub mismatch: a={:x?} b={:x?}",
            a.as_limbs(),
            b.as_limbs()
        );
        assert_eq!(
            bytes(&g.mul(a, b)),
            bytes(&n.mul(a, b)),
            "mul mismatch: a={:x?} b={:x?}",
            a.as_limbs(),
            b.as_limbs()
        );
    }

    fn check_unary(g: &GenericMont, n: &Secp256k1Field, a: &Fe) {
        assert_eq!(
            bytes(&g.square(a)),
            bytes(&n.square(a)),
            "square mismatch: a={:x?}",
            a.as_limbs()
        );
        assert_eq!(
            bytes(&g.negate(a)),
            bytes(&n.negate(a)),
            "negate mismatch: a={:x?}",
            a.as_limbs()
        );
        assert_eq!(
            bytes(&g.invert(a)),
            bytes(&n.invert(a)),
            "invert mismatch: a={:x?}",
            a.as_limbs()
        );
        assert_eq!(
            bytes(&n.invert_chain(a)),
            bytes(&n.invert(a)),
            "invert vs chain mismatch: a={:x?}",
            a.as_limbs()
        );
        // sqrt: value and presence flag must both match the oracle.
        let gs = g.sqrt(a);
        let ns = n.sqrt(a);
        assert_eq!(
            bool::from(gs.is_some),
            bool::from(ns.is_some),
            "sqrt is_square mismatch: a={:x?}",
            a.as_limbs()
        );
        if bool::from(gs.is_some) {
            // Both roots square back to a; compare the canonical root bytes.
            assert_eq!(
                bytes(&gs.value),
                bytes(&ns.value),
                "sqrt root mismatch: a={:x?}",
                a.as_limbs()
            );
        }
    }

    #[test]
    fn native_matches_generic_edge_cases() {
        let g = GenericMont::new();
        let n = Secp256k1Field::new();
        let cases = edge_cases();
        for a in &cases {
            check_unary(&g, &n, a);
            for b in &cases {
                check_pair(&g, &n, a, b);
            }
        }
    }

    #[test]
    fn native_matches_generic_random_batch() {
        let g = GenericMont::new();
        let n = Secp256k1Field::new();
        let mut rng = SplitMix64(0x0123_4567_89AB_CDEF);
        // 100k random operands; each iteration exercises every binary op.
        for _ in 0..100_000 {
            let a = rand_fe(&mut rng);
            let b = rand_fe(&mut rng);
            check_pair(&g, &n, &a, &b);
        }
    }

    #[test]
    fn native_matches_generic_random_unary() {
        let g = GenericMont::new();
        let n = Secp256k1Field::new();
        let mut rng = SplitMix64(0xDEAD_BEEF_CAFE_F00D);
        // Unary ops (square/negate/invert/sqrt) are the expensive ones; run a
        // smaller but still large batch, with ~50% sqrt non-residues by chance.
        for _ in 0..20_000 {
            let a = rand_fe(&mut rng);
            check_unary(&g, &n, &a);
        }
    }

    /// The fixed inversion / square-root chains against the generic
    /// square-and-multiply `pow` they replaced, on the edge values and a
    /// random sweep (the raw chain output is compared even for non-residues).
    #[test]
    fn addition_chains_match_generic_pow() {
        let n = Secp256k1Field::new();
        let check = |a: &Fe| {
            assert_eq!(
                bytes(&n.invert_chain(a)),
                bytes(&n.pow(a, &p_minus_2())),
                "invert chain: a={:x?}",
                a.as_limbs()
            );
            assert_eq!(
                bytes(&n.sqrt(a).value),
                bytes(&n.pow(a, &sqrt_exponent())),
                "sqrt chain: a={:x?}",
                a.as_limbs()
            );
        };
        for a in &edge_cases() {
            check(a);
        }
        let mut rng = SplitMix64(0x5EC9_256B_1C4A_17F0);
        for _ in 0..2_000 {
            check(&rand_fe(&mut rng));
        }
    }

    #[test]
    fn native_sqrt_roundtrips_squares() {
        // Every square has a root; the native backend must recover one whose
        // square is the input, and agree with the oracle on the canonical root.
        let g = GenericMont::new();
        let n = Secp256k1Field::new();
        let mut rng = SplitMix64(0xA5A5_5A5A_F0F0_0F0F);
        for _ in 0..5_000 {
            let a = rand_fe(&mut rng);
            let sq = n.square(&a);
            let r = n.sqrt(&sq);
            assert!(
                bool::from(r.is_some),
                "square has no root: a={:x?}",
                a.as_limbs()
            );
            assert_eq!(
                bytes(&n.square(&r.value)),
                bytes(&sq),
                "native sqrt does not round-trip: a={:x?}",
                a.as_limbs()
            );
            // Oracle agreement on the canonical root.
            let gr = g.sqrt(&sq);
            assert_eq!(bytes(&gr.value), bytes(&r.value));
        }
    }
}
