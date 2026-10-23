//! Opt-in: enable the `bn254` feature (off by default). Allocator-free.
//!
//! BN254 (also called `alt_bn128` or BN256): the Barreto–Naehrig
//! pairing-friendly curve of Ethereum's `ecAdd` / `ecMul` / `ecPairing`
//! precompiles (EIP-196, EIP-197) and of most deployed zk-SNARK tooling.
//!
//! The module implements the field tower `Fp ⊂ Fp2 ⊂ Fp6 ⊂ Fp12`, the scalar
//! field [`Fr`], the groups [`G1`] (`y² = x³ + 3` over `Fp`) and [`G2`] (on
//! the D-type sextic twist over `Fp2`), the optimal ate [`pairing`] into
//! [`Gt`] with [`multi_pairing`] / [`pairing_check`] for products of
//! pairings, the raw EIP-197 precompile ([`pairing_check_eip197`]), and
//! RFC 9380 hash-to-curve with the Shallue–van de Woestijne map
//! ([`hash_to_g1`], [`hash_to_g2`] and the non-uniform `encode_to_*`).
//!
//! Interoperability is byte-exact with gnark-crypto (and, for pairing
//! values, arkworks): the uncompressed point encodings are the EIP-196/197
//! ones (also gnark's raw encoding), the compressed ones and the [`Gt`]
//! encoding are gnark's, the pairing value is the one both libraries return
//! (`e(P, Q)^(2x(6x² + 3x + 1))` of the reduced Tate-style ate pairing; see
//! [`pairing`]), and hash-to-curve matches gnark's `HashToG1` / `HashToG2`.
//! The test vectors were produced by driving those libraries as black-box
//! oracles (`tools/pairing-interop/bn254/`).
//!
//! # Security level
//!
//! **BN254 offers roughly 100 bits of security, not 128.** Its 254-bit
//! prime was chosen before the extended tower number field sieve (Kim and
//! Barbulescu, 2016) made discrete logarithms in `GF(p¹²)` cheaper than
//! once believed. It is provided for interoperability with Ethereum and
//! existing zk-SNARK systems; new designs should prefer BLS12-381
//! (the `bls` feature).
//!
//! # Example
//!
//! ```
//! use purecrypto::bn254::{Fr, G1, G2, pairing, pairing_check};
//!
//! let a = Fr::from_u64(1234);
//! let b = Fr::from_u64(5678);
//! let (p, q) = (G1::generator(), G2::generator());
//!
//! // Bilinearity: e(a·P, b·Q) = e(P, Q)^(a·b).
//! assert_eq!(pairing(&p.mul(&a), &q.mul(&b)), pairing(&p, &q).pow(&(a * b)));
//!
//! // The EIP-197 check: e(a·P, Q) · e(−P, a·Q) = 1.
//! let (ap, aq, np) = (p.mul(&a), q.mul(&a), -p);
//! assert!(pairing_check(&[(&ap, &q), (&np, &aq)]));
//!
//! // Points round-trip through the EIP-196/197 encodings, fully validated.
//! let bytes = q.mul(&b).to_uncompressed();
//! assert_eq!(G2::from_uncompressed(&bytes).unwrap(), q.mul(&b));
//! ```
//!
//! # Constant time
//!
//! Everything that can touch a secret runs in constant time: the field
//! arithmetic is fixed-schedule limb code with masked conditional
//! subtractions; inversion is Fermat exponentiation and square roots are
//! fixed exponentiations; the group law uses complete (branch-free)
//! formulas, exception-free on the whole of both curves since neither has
//! a point of order two; [`G1::mul`], [`G2::mul`] and [`Gt::pow`] run fixed
//! 4-bit windows over every scalar bit with masked table gathers; and the
//! SVDW map is the straight-line form with masked selections. Decoding and
//! the pairing process public data and use the same branch-free
//! primitives, though their early-exit error paths are not timing-neutral
//! (nor do they need to be). Every decoder enforces canonical coordinates,
//! the curve equation and — for `G2` and `Gt` — subgroup membership, so a
//! value of these types is always a genuine group element.

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
mod pairing;
#[cfg(test)]
mod vectors;

pub use fp::Fp;
pub use fp2::Fp2;
pub use fp6::Fp6;
pub use fp12::Fp12;
pub use fr::Fr;
pub use g1::G1;
pub use g2::G2;
pub use hash_to_curve::{encode_to_g1, encode_to_g2, expand_message_xmd, hash_to_g1, hash_to_g2};
pub use pairing::{Gt, multi_pairing, pairing, pairing_check, pairing_check_eip197};

/// Errors from BN254 decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An encoded point or `Gt` element has the wrong length.
    InvalidLength,
    /// The flag bits of a compressed point are invalid (the uncompressed
    /// `00` marker, or an identity encoding with a nonzero payload).
    InvalidFlags,
    /// A coordinate is not a canonical field element (`>= p`, or flag bits
    /// set in an uncompressed encoding).
    InvalidEncoding,
    /// The decoded coordinates do not satisfy the curve equation.
    NotOnCurve,
    /// The point (or `Gt` element) is outside the prime-order subgroup.
    NotInSubgroup,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "BN254 encoding has the wrong length",
            Error::InvalidFlags => "BN254 compressed encoding has invalid flag bits",
            Error::InvalidEncoding => "BN254 encoding is not canonical",
            Error::NotOnCurve => "BN254 point is not on the curve",
            Error::NotInSubgroup => "BN254 element is not in the prime-order subgroup",
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
