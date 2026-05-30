//! Base-field backend for the const-generic secp256k1 implementation.
//!
//! The point arithmetic in [`super::group`] is generic over a [`FieldBackend`]
//! so the base field `GF(p)` with `p = 2²⁵⁶ − 2³² − 977` can be implemented
//! several ways behind one interface. This phase ships a single backend:
//!
//! - [`GenericMont`] — wraps the crate's generic 4-limb [`MontModulus`] CIOS
//!   arithmetic. It reuses exactly the numeric core P-256 uses, so it is
//!   trivially trustworthy, and the public API is wired to it.
//!
//! A native pseudo-Mersenne reduction specialised to secp256k1's prime is the
//! natural next backend (it would slot in behind this same trait by changing
//! one type alias in [`super`]); it is deliberately deferred so this exposure
//! lands on the audited generic core first.
//!
//! Field elements are carried as plain (non-Montgomery) residues `< p`, stored
//! as a [`Uint<4>`]; this is the representation the SEC1 codec serialises.

// `from_bytes_be(&self, ..)` is parameterised by the backend instance (it is a
// method, not a free constructor), so the `from_*`-takes-no-self heuristic does
// not apply to this trait.
#![allow(clippy::wrong_self_convention)]

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
pub(crate) fn fe_from_hex(hex: &str) -> Fe {
    let h = hex.as_bytes();
    assert!(h.len() == 64, "field hex must be 64 chars");
    let mut bytes = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        bytes[i] = (hex_nibble(h[2 * i]) << 4) | hex_nibble(h[2 * i + 1]);
        i += 1;
    }
    Fe::from_be_bytes(&bytes)
}

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Returns the prime `p` as a [`Fe`].
#[inline]
pub(crate) fn p() -> Fe {
    fe_from_hex(P_HEX)
}

/// The square-root exponent `(p + 1) / 4` for the `p ≡ 3 (mod 4)` root formula.
fn sqrt_exponent() -> Fe {
    // (p + 1) / 4. Computed directly from p to avoid a second hard-coded constant.
    let p_plus_1 = p().wrapping_add(&Fe::ONE);
    p_plus_1.shr1().shr1()
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
    /// Returns `(-a) mod p`.
    fn negate(&self, a: &Fe) -> Fe;
    /// Returns the modular inverse `a^-1 mod p` (constant time, Fermat). The
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
pub(crate) struct GenericMont {
    fp: MontModulus<4>,
}

impl GenericMont {
    /// Builds the backend (computes the Montgomery constants once).
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
