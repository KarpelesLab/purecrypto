//! Runtime-sized unsigned big integers (heap-backed).
//!
//! [`BoxedUint`] stores its limbs in a [`Vec`], so its width is chosen at
//! runtime rather than in the type. This is used where a value's size is only
//! known at parse time — most importantly RSA public keys read from a
//! certificate, whose modulus size varies. The fixed-size [`Uint`](super::Uint)
//! remains the choice when the width is known at compile time.

use super::mul::mac;
use super::uint::{LIMB_BITS, Limb, adc, sbb};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use alloc::vec;
use alloc::vec::Vec;

// `ConditionallySelectable` (used for the limb-wise select) requires `Copy`,
// which `Limb` satisfies; `BoxedUint` itself selects via an inherent method.

/// `a + b + carry` over equal-length limb slices, returning `(sum, carry_out)`.
fn adc_limbs(a: &[Limb], b: &[Limb], carry_in: Limb) -> (Vec<Limb>, Limb) {
    let mut out = vec![0 as Limb; a.len()];
    let mut c = carry_in;
    for i in 0..a.len() {
        let (s, co) = adc(a[i], b[i], c);
        out[i] = s;
        c = co;
    }
    (out, c)
}

/// `a - b - borrow` over equal-length limb slices, returning `(diff, borrow_out)`.
fn sbb_limbs(a: &[Limb], b: &[Limb], borrow_in: Limb) -> (Vec<Limb>, Limb) {
    let mut out = vec![0 as Limb; a.len()];
    let mut bo = borrow_in;
    for i in 0..a.len() {
        let (d, b) = sbb(a[i], b[i], bo);
        out[i] = d;
        bo = b;
    }
    (out, bo)
}

/// Selects `a` if `choice` is true, else `b`, limb-by-limb (constant time).
fn select_limbs(a: &[Limb], b: &[Limb], choice: Choice) -> Vec<Limb> {
    (0..a.len())
        .map(|i| Limb::conditional_select(&a[i], &b[i], choice))
        .collect()
}

/// An unsigned integer of runtime-chosen width, stored as little-endian 64-bit
/// limbs (limb 0 is least significant).
#[derive(Clone, Debug)]
pub struct BoxedUint {
    pub(super) limbs: Vec<Limb>,
}

impl BoxedUint {
    /// The value zero, occupying `limbs` limbs.
    pub fn zero(limbs: usize) -> Self {
        BoxedUint {
            limbs: vec![0; limbs.max(1)],
        }
    }

    /// Creates a `BoxedUint` from a single 64-bit value.
    pub fn from_u64(v: u64) -> Self {
        BoxedUint { limbs: vec![v] }
    }

    /// Builds a value directly from little-endian limbs.
    pub fn from_limbs(limbs: Vec<Limb>) -> Self {
        BoxedUint {
            limbs: if limbs.is_empty() { vec![0] } else { limbs },
        }
    }

    /// Interprets `bytes` as a big-endian integer.
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let nlimbs = bytes.len().div_ceil(8).max(1);
        let mut limbs = vec![0 as Limb; nlimbs];
        let mut end = bytes.len();
        let mut i = 0;
        while end > 0 {
            let start = end.saturating_sub(8);
            let mut buf = [0u8; 8];
            let slice = &bytes[start..end];
            buf[8 - slice.len()..].copy_from_slice(slice);
            limbs[i] = Limb::from_be_bytes(buf);
            i += 1;
            end = start;
        }
        BoxedUint { limbs }
    }

    /// Serializes this integer big-endian into a `len`-byte vector. The value
    /// must fit; otherwise this would silently drop the high bytes.
    ///
    /// # Panics
    /// Panics if `self` has any significant byte beyond position `len`
    /// (i.e. the encoded value would not round-trip via [`Self::from_be_bytes`]).
    pub fn to_be_bytes(&self, len: usize) -> Vec<u8> {
        // Refuse to silently truncate: every limb byte at position >= len
        // must be zero. Equivalently, `bit_len <= len * 8`. The check runs
        // in O(limbs) and is unconditional on input size (no secret-dependent
        // branch), matching the rest of this module's panic style for
        // misuse (see `from_be_bytes` width assertion in `Uint`).
        for (i, &limb) in self.limbs.iter().enumerate() {
            let le = limb.to_le_bytes();
            for (b, &byte) in le.iter().enumerate() {
                let pos = i * 8 + b;
                assert!(
                    pos < len || byte == 0,
                    "BoxedUint::to_be_bytes: value does not fit in {len} bytes"
                );
            }
        }
        let mut out = vec![0u8; len];
        for (i, &limb) in self.limbs.iter().enumerate() {
            let le = limb.to_le_bytes();
            for (b, &byte) in le.iter().enumerate() {
                let pos = i * 8 + b; // byte significance from the right
                if pos < len {
                    out[len - 1 - pos] = byte;
                }
            }
        }
        out
    }

    /// The number of limbs in the current representation.
    #[inline]
    pub fn limbs(&self) -> usize {
        self.limbs.len()
    }

    /// The limbs (little-endian).
    #[inline]
    pub fn as_limbs(&self) -> &[Limb] {
        &self.limbs
    }

    /// Best-effort wipe of the limb storage, for use in `Drop` impls that
    /// hold secret material (e.g. RSA private exponents and prime factors).
    /// Mirrors the `core::hint::black_box` pattern used by [`Aes128`] /
    /// [`Poly1305`] and the in-crate [`hash::zeroize`] helpers so LLVM does
    /// not elide the writes as a dead store.
    #[inline]
    pub(crate) fn zeroize(&mut self) {
        for limb in self.limbs.iter_mut() {
            *limb = 0;
        }
        let _ = core::hint::black_box(&self.limbs);
    }

    /// The bit length (most-significant set bit + 1); zero for zero.
    pub fn bit_len(&self) -> usize {
        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] != 0 {
                return i * LIMB_BITS + (LIMB_BITS - self.limbs[i].leading_zeros() as usize);
            }
        }
        0
    }

    /// Whether the value is odd.
    #[inline]
    pub fn is_odd(&self) -> bool {
        self.limbs.first().is_some_and(|l| l & 1 == 1)
    }

    /// Whether the value is zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    /// The number of significant (non-leading-zero) limbs, at least one.
    pub(super) fn significant_limbs(&self) -> usize {
        let mut n = self.limbs.len();
        while n > 1 && self.limbs[n - 1] == 0 {
            n -= 1;
        }
        n
    }

    /// Returns the limbs padded or truncated to exactly `n` limbs.
    pub(super) fn limbs_resized(&self, n: usize) -> Vec<Limb> {
        let mut v = vec![0 as Limb; n];
        let copy = self.limbs.len().min(n);
        v[..copy].copy_from_slice(&self.limbs[..copy]);
        v
    }

    /// Wrapping subtraction `self - other` (the result is sized to the wider
    /// operand; an underflow wraps modulo `2^(64·limbs)`).
    pub fn sub(&self, other: &BoxedUint) -> BoxedUint {
        let n = self.limbs.len().max(other.limbs.len());
        let (diff, _borrow) = sbb_limbs(&self.limbs_resized(n), &other.limbs_resized(n), 0);
        BoxedUint::from_limbs(diff)
    }

    /// Returns `self >> shift` (logical right shift by `shift` bits).
    pub fn shr_bits(&self, shift: usize) -> BoxedUint {
        let limb_shift = shift / LIMB_BITS;
        let bit_shift = shift % LIMB_BITS;
        let n = self.limbs.len();
        let mut out = vec![0 as Limb; n];
        for (i, slot) in out.iter_mut().enumerate() {
            let src = i + limb_shift;
            if src < n {
                let mut val = self.limbs[src] >> bit_shift;
                if bit_shift > 0 && src + 1 < n {
                    val |= self.limbs[src + 1] << (LIMB_BITS - bit_shift);
                }
                *slot = val;
            }
        }
        BoxedUint::from_limbs(out)
    }

    /// Reduces `self` modulo `modulus` via constant-time bitwise long division.
    /// The schedule depends only on the bit widths, not the values. `modulus`
    /// must be nonzero.
    ///
    /// # Panics
    /// Panics if `modulus` is zero. (Long division by zero would silently
    /// produce a meaningless result — every iteration "subtracts" because
    /// the borrow never fires — so the precondition is checked rather than
    /// returning garbage.)
    pub fn reduce(&self, modulus: &BoxedUint) -> BoxedUint {
        assert!(
            !modulus.is_zero(),
            "BoxedUint::reduce: modulus must be nonzero"
        );
        let m = modulus.significant_limbs();
        let n = modulus.limbs_resized(m);
        let mut r = vec![0 as Limb; m];
        for i in (0..self.limbs.len()).rev() {
            let mut bit = LIMB_BITS;
            while bit > 0 {
                bit -= 1;
                // shifted = (r << 1) | next bit of self
                let (mut shifted, carry) = adc_limbs(&r, &r, 0);
                shifted[0] |= (self.limbs[i] >> bit) & 1;
                // Subtract the modulus when shifted overflowed or shifted >= n.
                let (diff, borrow) = sbb_limbs(&shifted, &n, 0);
                let ge = Choice::from((carry | (borrow ^ 1)) as u8);
                r = select_limbs(&diff, &shifted, ge);
            }
        }
        BoxedUint::from_limbs(r)
    }

    /// Wrapping addition `self + other`, widened by one limb so no carry is
    /// lost.
    pub fn add(&self, other: &BoxedUint) -> BoxedUint {
        let n = self.limbs.len().max(other.limbs.len());
        let (mut sum, carry) = adc_limbs(&self.limbs_resized(n), &other.limbs_resized(n), 0);
        sum.push(carry);
        BoxedUint::from_limbs(sum)
    }

    /// Widening multiply `self * other` (schoolbook).
    pub fn mul(&self, other: &BoxedUint) -> BoxedUint {
        let a = &self.limbs;
        let b = &other.limbs;
        let mut out = vec![0 as Limb; a.len() + b.len()];
        for (i, &ai) in a.iter().enumerate() {
            let mut carry: Limb = 0;
            for (j, &bj) in b.iter().enumerate() {
                let (s, c) = mac(out[i + j], ai, bj, carry);
                out[i + j] = s;
                carry = c;
            }
            out[i + b.len()] = out[i + b.len()].wrapping_add(carry);
        }
        BoxedUint::from_limbs(out)
    }

    /// Whether `self < other` (not constant time).
    pub fn lt(&self, other: &BoxedUint) -> bool {
        let n = self.limbs.len().max(other.limbs.len());
        let (_, borrow) = sbb_limbs(&self.limbs_resized(n), &other.limbs_resized(n), 0);
        borrow == 1
    }

    /// Returns `(quotient, remainder)` for `self / divisor`, via bitwise long
    /// division. The schedule depends only on the bit widths; `divisor` must be
    /// nonzero.
    ///
    /// # Panics
    /// Panics if `divisor` is zero. (See [`BoxedUint::reduce`] for why this
    /// is checked rather than returning a meaningless result.)
    pub fn divrem(&self, divisor: &BoxedUint) -> (BoxedUint, BoxedUint) {
        assert!(
            !divisor.is_zero(),
            "BoxedUint::divrem: divisor must be nonzero"
        );
        let m = divisor.significant_limbs();
        let d = divisor.limbs_resized(m);
        let mut q = vec![0 as Limb; self.limbs.len()];
        let mut r = vec![0 as Limb; m];
        for i in (0..self.limbs.len()).rev() {
            let mut bit = LIMB_BITS;
            while bit > 0 {
                bit -= 1;
                // r = (r << 1) | next bit of self
                let (mut shifted, carry) = adc_limbs(&r, &r, 0);
                shifted[0] |= (self.limbs[i] >> bit) & 1;
                let (diff, borrow) = sbb_limbs(&shifted, &d, 0);
                let ge = Choice::from((carry | (borrow ^ 1)) as u8);
                r = select_limbs(&diff, &shifted, ge);
                // q = (q << 1) | quotient bit
                let (mut q_shifted, _) = adc_limbs(&q, &q, 0);
                q_shifted[0] |= ge.unwrap_u8() as Limb;
                q = q_shifted;
            }
        }
        (BoxedUint::from_limbs(q), BoxedUint::from_limbs(r))
    }

    /// Constant-time select: returns `a` if `choice` is true, else `b` (operands
    /// resized to the wider limb count). [`BoxedUint`] cannot implement
    /// [`ConditionallySelectable`](crate::ct::ConditionallySelectable) because
    /// that trait requires `Copy`, so this is an inherent method.
    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let n = a.limbs.len().max(b.limbs.len());
        BoxedUint::from_limbs(select_limbs(
            &a.limbs_resized(n),
            &b.limbs_resized(n),
            choice,
        ))
    }
}

impl ConstantTimeEq for BoxedUint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let n = self.limbs.len().max(other.limbs.len());
        self.limbs_resized(n)[..].ct_eq(&other.limbs_resized(n)[..])
    }
}

impl PartialEq for BoxedUint {
    fn eq(&self, other: &Self) -> bool {
        let n = self.limbs.len().max(other.limbs.len());
        (0..n).all(|i| {
            self.limbs.get(i).copied().unwrap_or(0) == other.limbs.get(i).copied().unwrap_or(0)
        })
    }
}

impl Eq for BoxedUint {}

// Best-effort zeroize on drop: every BoxedUint may carry secret material
// (RSA `d`/`p`/`q`, ECDSA/ECDH scalars, blinding intermediates, …) and the
// limb Vec is returned to the allocator otherwise unchanged. Overwrite the
// limbs and route the read through `core::hint::black_box` so LLVM cannot
// eliminate the writes as dead stores (same pattern as ML-DSA/ML-KEM in
// `src/mldsa/mod.rs` and `src/mlkem/mod.rs`, avoiding a `zeroize` dep).
impl Drop for BoxedUint {
    fn drop(&mut self) {
        for l in self.limbs.iter_mut() {
            *l = 0;
        }
        let _ = core::hint::black_box(&self.limbs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_roundtrip_and_properties() {
        let bytes = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10];
        let u = BoxedUint::from_be_bytes(&bytes);
        assert_eq!(u.to_be_bytes(9), bytes);
        // Zero-extends on a longer buffer.
        let mut padded = [0u8; 16];
        padded[7..].copy_from_slice(&bytes);
        assert_eq!(u.to_be_bytes(16), padded);

        assert_eq!(BoxedUint::from_u64(0).bit_len(), 0);
        assert_eq!(BoxedUint::from_u64(1).bit_len(), 1);
        assert_eq!(BoxedUint::from_u64(0xff).bit_len(), 8);
        assert!(BoxedUint::from_u64(3).is_odd());
        assert!(!BoxedUint::from_u64(4).is_odd());
        assert!(BoxedUint::zero(4).is_zero());
    }

    #[test]
    fn equality_ignores_leading_zero_limbs() {
        let a = BoxedUint::from_limbs(vec![5]);
        let b = BoxedUint::from_limbs(vec![5, 0, 0]);
        assert_eq!(a, b);
        assert_ne!(a, BoxedUint::from_limbs(vec![6]));
    }

    #[test]
    fn reduce_matches_u128() {
        // A wide value reduced modulo a smaller modulus.
        let value = BoxedUint::from_be_bytes(&0x1234_5678_9abc_def0u64.to_be_bytes());
        let modulus = BoxedUint::from_u64(1_000_003);
        let got = value.reduce(&modulus);
        let expected = (0x1234_5678_9abc_def0u128 % 1_000_003) as u64;
        assert_eq!(got, BoxedUint::from_u64(expected));

        // Reducing a value already smaller than the modulus is the identity.
        assert_eq!(
            BoxedUint::from_u64(7).reduce(&modulus),
            BoxedUint::from_u64(7)
        );
    }

    #[test]
    fn reduce_wide_then_mod_is_consistent() {
        // (2^128 - 1) mod 97, computed against u128.
        let mut bytes = [0xffu8; 16];
        bytes[0] = 0xff;
        let value = BoxedUint::from_be_bytes(&bytes);
        let got = value.reduce(&BoxedUint::from_u64(97));
        assert_eq!(got, BoxedUint::from_u64(((u128::MAX) % 97) as u64));
    }

    #[test]
    fn sub_wraps_and_subtracts() {
        assert_eq!(
            BoxedUint::from_u64(10).sub(&BoxedUint::from_u64(3)),
            BoxedUint::from_u64(7)
        );
        // Used to form modulus-2 for Fermat inversion.
        let p = BoxedUint::from_u64(0xffff_fffe_ffff_fc2f); // secp256k1 low limb-ish
        assert_eq!(
            p.sub(&BoxedUint::from_u64(2)).as_limbs()[0],
            0xffff_fffe_ffff_fc2d
        );
    }

    #[test]
    fn conditional_select_and_ct_eq() {
        let a = BoxedUint::from_u64(0xAAAA);
        let b = BoxedUint::from_u64(0xBBBB);
        assert_eq!(BoxedUint::conditional_select(&a, &b, Choice::from(1)), a);
        assert_eq!(BoxedUint::conditional_select(&a, &b, Choice::from(0)), b);

        assert!(bool::from(a.ct_eq(&BoxedUint::from_limbs(vec![0xAAAA, 0]))));
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    #[should_panic(expected = "modulus must be nonzero")]
    fn reduce_zero_modulus_panics() {
        // A zero divisor used to silently produce a meaningless result;
        // now it must panic so the caller cannot consume garbage data.
        let _ = BoxedUint::from_u64(5).reduce(&BoxedUint::zero(2));
    }

    #[test]
    #[should_panic(expected = "divisor must be nonzero")]
    fn divrem_zero_divisor_panics() {
        let _ = BoxedUint::from_u64(5).divrem(&BoxedUint::zero(1));
    }

    #[test]
    #[should_panic(expected = "does not fit in 2 bytes")]
    fn to_be_bytes_truncation_panics() {
        // 0x1_0000 = 65536 needs 3 bytes; encoding into 2 must reject.
        let _ = BoxedUint::from_u64(0x1_0000).to_be_bytes(2);
    }

    #[test]
    fn to_be_bytes_exact_fit_succeeds() {
        // The boundary case: the value uses exactly the supplied byte count.
        assert_eq!(BoxedUint::from_u64(0xff).to_be_bytes(1), vec![0xff]);
        // Larger buffers still zero-pad.
        assert_eq!(
            BoxedUint::from_u64(0xff).to_be_bytes(4),
            vec![0, 0, 0, 0xff]
        );
        // High zero limbs do not trigger the truncation panic.
        let u = BoxedUint::from_limbs(vec![0x42, 0, 0]);
        assert_eq!(u.to_be_bytes(1), vec![0x42]);
    }
}
