//! Opt-in: enable the `bls12-377` feature (off by default). Allocator-free.
//!
//! The pairing-friendly curve BLS12-377 (Bowe, Chiesa, Green, Miers, Mishra
//! and Wu, "Zexe", <https://eprint.iacr.org/2018/962>), the curve of
//! Zexe/Aleo-style systems and of the EIP-2539 precompile: its field tower
//! `Fp ⊂ Fp2 ⊂ Fp6 ⊂ Fp12` (`u² = -5`, `v³ = u`, `w² = v`), the groups
//! [`G1`] (`y² = x³ + 1` over `Fp`) and [`G2`] (the D-type twist
//! `y² = x³ + 1/u` over `Fp2`), the optimal ate [`pairing`] into [`Gt`],
//! [`multi_pairing`] / [`pairing_check`], and RFC 9380-style
//! [hashing to both groups](hash_to_g1).
//! On top, [`min_pk`] and [`min_sig`] provide BLS signatures
//! (`draft-irtf-cfrg-bls-signature-05`, all three schemes and aggregation)
//! with public keys in `G1` or in `G2` respectively — under documented,
//! non-standard ciphersuite IDs, since the draft defines none for
//! BLS12-377.
//!
//! # Interoperability
//!
//! Everything is byte-compatible with gnark-crypto: point encodings
//! ([`G1::to_compressed`] and friends, the ZCash flag layout), `GT` values
//! and their encoding ([`Gt::to_bytes`]; the pairing is the cube of the
//! reduced optimal ate pairing, as gnark-crypto and arkworks both compute),
//! and [`hash_to_g1`] / [`hash_to_g2`] / [`encode_to_g1`] /
//! [`encode_to_g2`]. The arkworks `CanonicalSerialize` encodings are
//! available as `*_ark` methods. Interop was established black-box,
//! against the public APIs of gnark-crypto v0.21 and arkworks 0.5 (see
//! `tools/pairing-interop/bls12-377/`). arkworks' G1 hash-to-curve does
//! **not** agree with gnark-crypto's (its G2 one does); this module follows
//! gnark-crypto.
//!
//! # Security level
//!
//! BLS12-377 targets roughly 123–125-bit security: the 253-bit `r` gives
//! ~126 bits against Pollard rho, and the special/extended tower number
//! field sieve against `GF(p¹²)` (4524 bits) brings the discrete-log
//! estimate of the target group to about the same level. That is slightly
//! below the 128-bit class; prefer it where its ecosystem demands it.
//!
//! # Example
//!
//! ```
//! use purecrypto::bls12_377::{Fr, G1, G2, hash_to_g2, pairing_check};
//!
//! // A BLS-style check e(pk, H(m)) = e(G1, sig) with sk·G1 = pk.
//! let sk = Fr::from_bytes_wide(&[7u8; 64]);
//! let pk = G1::generator() * sk;
//! let h = hash_to_g2(b"message", b"EXAMPLE-BLS12377G2_XMD:SHA-256_SSWU_RO_");
//! let sig = h * sk;
//! let neg_g1 = -G1::generator();
//! assert!(pairing_check(&[(&pk, &h), (&neg_g1, &sig)]));
//!
//! // Encodings round-trip with full validation.
//! let bytes = pk.to_compressed();
//! assert_eq!(G1::from_compressed(&bytes).unwrap(), pk);
//! assert_eq!(G2::from_compressed(&sig.to_compressed()).unwrap(), sig);
//! ```
//!
//! # Constant time
//!
//! Everything that touches a secret — scalar multiplication ([`G1::mul`],
//! [`G2::mul`]), [`Gt::pow`], [`Fr`] arithmetic and the hash-to-curve maps
//! — runs in constant time: fixed-schedule Montgomery limb code with masked
//! conditional subtractions, Fermat inversion and fixed-schedule square
//! roots (RFC 9380 `sqrt_ratio`; `p - 1` has 2-adicity 46), branch-free
//! group laws, and endomorphism-split fixed-window scalar multiplication
//! with masked table gathers. Decoding and pairing process public data and
//! use the same primitives, though their early-exit error paths are not
//! timing-neutral (nor do they need to be).
//!
//! # The even G1 cofactor
//!
//! Unlike BLS12-381, the curve `E(Fp)` has rational points of order 2, and
//! the usual "complete" addition formulas degenerate on pairs whose
//! difference has order 2. Inside `G1` that cannot happen, but it can for
//! the attacker-chosen points a decoder must reject: left unhandled, the
//! degenerate output `(0 : 0 : 0)` would compare equal to anything and let
//! a point such as `(-1, 0)` pass the subgroup check. The subgroup check
//! and the hash-to-curve pipeline therefore use an addition law with a
//! masked fallback that is correct on every input (see the `curve` module
//! documentation). Every `G1` value is in the prime-order subgroup.

mod constants;
mod curve;
mod fp;
mod fp12;
mod fp2;
mod fp6;
mod fr;
mod g1;
mod g2;
mod hash_to_curve;
pub mod min_pk;
pub mod min_sig;
mod pairing;
#[cfg(test)]
mod vectors;
use crate::pairing_common::mont;

pub use fp::Fp;
pub use fp2::Fp2;
pub use fp6::Fp6;
pub use fp12::Fp12;
pub use fr::Fr;
pub use g1::G1;
pub use g2::G2;
pub use hash_to_curve::{encode_to_g1, encode_to_g2, expand_message_xmd, hash_to_g1, hash_to_g2};
pub use pairing::{Gt, multi_pairing, pairing, pairing_check};

/// Errors from BLS12-377 decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An encoding has the wrong length.
    InvalidLength,
    /// The flag bits of an encoded point are inconsistent (compression flag
    /// wrong for the form, infinity together with a sign flag or a nonzero
    /// payload, a sign flag that does not match `y`, ...).
    InvalidFlags,
    /// A coordinate is not a canonical field element.
    InvalidEncoding,
    /// The decoded coordinates do not satisfy the curve equation.
    NotOnCurve,
    /// The element is on the curve (or in `Fp12*`) but outside the
    /// prime-order subgroup.
    NotInSubgroup,
    /// The identity point where the BLS signature scheme forbids it (public
    /// keys, aggregate public keys).
    IdentityPoint,
    /// A BLS secret key is zero or not a canonical scalar.
    InvalidScalar,
    /// BLS `KeyGen` was given fewer than 32 bytes of input keying material.
    InsufficientKeyMaterial,
    /// A BLS signature (or proof of possession) did not verify.
    InvalidSignature,
    /// A BLS aggregate operation was given no inputs.
    EmptyAggregate,
    /// The numbers of public keys and messages differ.
    LengthMismatch,
    /// The Basic scheme requires all messages of an aggregate to be distinct.
    DuplicateMessage,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "BLS12-377 encoding has the wrong length",
            Error::InvalidFlags => "BLS12-377 encoding has inconsistent flag bits",
            Error::InvalidEncoding => "BLS12-377 encoding is not canonical",
            Error::NotOnCurve => "BLS12-377 point is not on the curve",
            Error::NotInSubgroup => "BLS12-377 element is not in the prime-order subgroup",
            Error::IdentityPoint => "BLS12-377 identity point where it is forbidden",
            Error::InvalidScalar => "BLS secret key is zero or not canonical",
            Error::InsufficientKeyMaterial => "BLS KeyGen needs at least 32 bytes of IKM",
            Error::InvalidSignature => "BLS signature verification failed",
            Error::EmptyAggregate => "BLS aggregate over zero inputs",
            Error::LengthMismatch => "BLS public key and message counts differ",
            Error::DuplicateMessage => "BLS Basic scheme requires distinct messages",
        })
    }
}

impl core::error::Error for Error {}

/// Implements the operator and comparison traits of a group wrapper
/// (`G1` / `G2`) in terms of its inherent methods.
macro_rules! ops_for_group {
    ($t:ident) => {
        impl Default for $t {
            fn default() -> Self {
                Self::IDENTITY
            }
        }
        impl ConstantTimeEq for $t {
            #[inline]
            fn ct_eq(&self, other: &Self) -> Choice {
                self.0.ct_eq(&other.0)
            }
        }
        impl ConditionallySelectable for $t {
            #[inline]
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                $t(Projective::conditional_select(&a.0, &b.0, choice))
            }
        }
        impl PartialEq for $t {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).into()
            }
        }
        impl Eq for $t {}
        impl Add<$t> for $t {
            type Output = $t;
            #[inline]
            fn add(self, rhs: $t) -> $t {
                $t::add(&self, &rhs)
            }
        }
        impl<'b> Add<&'b $t> for &$t {
            type Output = $t;
            #[inline]
            fn add(self, rhs: &'b $t) -> $t {
                $t::add(self, rhs)
            }
        }
        impl Sub<$t> for $t {
            type Output = $t;
            #[inline]
            fn sub(self, rhs: $t) -> $t {
                $t::sub(&self, &rhs)
            }
        }
        impl<'b> Sub<&'b $t> for &$t {
            type Output = $t;
            #[inline]
            fn sub(self, rhs: &'b $t) -> $t {
                $t::sub(self, rhs)
            }
        }
        impl AddAssign<$t> for $t {
            #[inline]
            fn add_assign(&mut self, rhs: $t) {
                *self = $t::add(self, &rhs);
            }
        }
        impl SubAssign<$t> for $t {
            #[inline]
            fn sub_assign(&mut self, rhs: $t) {
                *self = $t::sub(self, &rhs);
            }
        }
        impl Neg for $t {
            type Output = $t;
            #[inline]
            fn neg(self) -> $t {
                $t::neg(&self)
            }
        }
        impl Neg for &$t {
            type Output = $t;
            #[inline]
            fn neg(self) -> $t {
                $t::neg(self)
            }
        }
        impl<'b> Mul<&'b Fr> for &$t {
            type Output = $t;
            #[inline]
            fn mul(self, k: &'b Fr) -> $t {
                $t::mul(self, k)
            }
        }
        impl Mul<Fr> for $t {
            type Output = $t;
            #[inline]
            fn mul(self, k: Fr) -> $t {
                $t::mul(&self, &k)
            }
        }
        impl<'b> Mul<&'b Fr> for $t {
            type Output = $t;
            #[inline]
            fn mul(self, k: &'b Fr) -> $t {
                $t::mul(&self, k)
            }
        }
    };
}
pub(crate) use ops_for_group;
