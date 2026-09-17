//! BLS12-381 and the BLS signature scheme.
//!
//! This module implements the pairing-friendly curve BLS12-381 from the
//! ground up — the field tower `Fp ⊂ Fp2 ⊂ Fp6 ⊂ Fp12`, the groups
//! [`G1`] and [`G2`] with the ZCash serialization, the optimal ate
//! [`pairing`] into [`Gt`], the RFC 9380 hash-to-curve suites
//! `BLS12381G1_XMD:SHA-256_SSWU_RO_` and `BLS12381G2_XMD:SHA-256_SSWU_RO_` —
//! and, on top, the BLS signature scheme of
//! `draft-irtf-cfrg-bls-signature-05` in its **minimal-pubkey-size**
//! instantiation (public keys in `G1`, 48 bytes; signatures in `G2`, 96
//! bytes), i.e. the variant used by Ethereum 2.0. All three schemes of the
//! draft are provided ([`Scheme::Basic`], [`Scheme::MessageAugmentation`],
//! [`Scheme::ProofOfPossession`]) together with aggregation.
//!
//! # Example
//!
//! ```
//! use purecrypto::bls::{SecretKey, Scheme, Signature, aggregate_verify};
//!
//! let sk1 = SecretKey::generate(b"an IKM of at least thirty-two bytes!", b"").unwrap();
//! let sk2 = SecretKey::generate(b"another IKM of at least 32 bytes long", b"").unwrap();
//! let (pk1, pk2) = (sk1.public_key(), sk2.public_key());
//!
//! let sig1 = sk1.sign(Scheme::Basic, b"message one");
//! pk1.verify(Scheme::Basic, b"message one", &sig1).unwrap();
//! assert!(pk1.verify(Scheme::Basic, b"message two", &sig1).is_err());
//!
//! // Basic-scheme aggregation needs distinct messages.
//! let sig2 = sk2.sign(Scheme::Basic, b"message two");
//! let agg = Signature::aggregate(&[sig1, sig2]).unwrap();
//! aggregate_verify(Scheme::Basic, &[pk1, pk2], &[b"message one", b"message two"], &agg).unwrap();
//! ```
//!
//! # Constant time
//!
//! Everything that touches a secret key — [`SecretKey::generate`],
//! [`SecretKey::sign`] and the scalar multiplications behind them — runs in
//! constant time: the field arithmetic is fixed-schedule limb code with
//! masked conditional subtractions, the group law uses complete
//! (branch-free) formulas, and scalar multiplication is a fixed-window
//! ladder with masked table lookups. Verification, decoding and hashing to
//! the curve process public data and use the same branch-free primitives,
//! though their early-exit error paths are not timing-neutral (nor do they
//! need to be).

mod constants;
mod curve;
#[cfg(test)]
mod eth_vectors;
mod fp;
mod fp12;
mod fp2;
mod fp6;
mod fr;
mod g1;
mod g2;
mod hash_to_curve;
mod mont;
mod pairing;
mod signature;

pub use fp::Fp;
pub use fp2::Fp2;
pub use fp6::Fp6;
pub use fp12::Fp12;
pub use fr::Fr;
pub use g1::G1;
pub use g2::G2;
pub use hash_to_curve::{expand_message_xmd, hash_to_g1, hash_to_g2};
pub use pairing::{Gt, multi_pairing, pairing};
pub use signature::{
    DST_AUG, DST_BASIC, DST_POP, DST_POP_PROOF, ProofOfPossession, PublicKey, Scheme, SecretKey,
    Signature, aggregate_verify, fast_aggregate_verify,
};

/// Errors from BLS12-381 decoding and BLS signature operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An encoded point, key or signature has the wrong length.
    InvalidLength,
    /// The ZCash flag bits of an encoded point are inconsistent (compression
    /// flag clear on a compressed encoding, sort flag with infinity, ...).
    InvalidFlags,
    /// A coordinate is not a canonical field element, or an identity
    /// encoding carries nonzero payload bits.
    InvalidEncoding,
    /// The decoded coordinates do not satisfy the curve equation.
    NotOnCurve,
    /// The point is on the curve but outside the prime-order subgroup.
    NotInSubgroup,
    /// The identity point where the protocol forbids it (public keys,
    /// aggregate inputs).
    IdentityPoint,
    /// A secret key is zero or not a canonical scalar.
    InvalidScalar,
    /// `KeyGen` was given fewer than 32 bytes of input keying material.
    InsufficientKeyMaterial,
    /// The signature (or proof of possession) did not verify.
    InvalidSignature,
    /// An aggregate operation was given no inputs.
    EmptyAggregate,
    /// The numbers of public keys and messages differ.
    LengthMismatch,
    /// The Basic scheme requires all messages of an aggregate to be distinct.
    DuplicateMessage,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "BLS12-381 encoding has the wrong length",
            Error::InvalidFlags => "BLS12-381 encoding has inconsistent flag bits",
            Error::InvalidEncoding => "BLS12-381 encoding is not canonical",
            Error::NotOnCurve => "BLS12-381 point is not on the curve",
            Error::NotInSubgroup => "BLS12-381 point is not in the prime-order subgroup",
            Error::IdentityPoint => "BLS12-381 identity point where it is forbidden",
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
