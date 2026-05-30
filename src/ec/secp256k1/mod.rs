//! secp256k1 scalar / point arithmetic and SEC1 codec (`hazmat`).
//!
//! A stack-allocated const-generic implementation of the secp256k1 curve
//! `y² = x³ + 7` over `GF(p)` with `p = 2²⁵⁶ − 2³² − 977`, exposing the
//! low-level group operations that threshold-ECDSA libraries (e.g. `dkls-tss`)
//! need: scalar field arithmetic mod the group order `n`, projective/affine
//! point arithmetic, a constant-time scalar-multiplication ladder, and a
//! **compressed** SEC1 point codec with `y`-recovery.
//!
//! # Hazmat
//!
//! This is a low-level "hazardous materials" API. **There is no semver
//! stability guarantee** for anything in this module, and it is gated behind
//! the non-default `hazmat-secp256k1` feature. Misuse — feeding it non-reduced
//! scalars, ignoring the on-curve / identity checks, comparing secret points
//! with non-constant-time code, etc. — can silently break security. The caller
//! owns correctness and constant-time discipline. Prefer the high-level
//! [`ecdsa`](crate::ec::ecdsa) / [`boxed`](crate::ec::boxed) paths unless you
//! are building a protocol that genuinely needs raw group arithmetic.
//!
//! ## Backend
//!
//! The point formulas are generic over a
//! [`FieldBackend`](field_backend::FieldBackend); the public API is wired to
//! the native pseudo-Mersenne backend
//! ([`Secp256k1Field`](field_backend::Secp256k1Field)), a reduction specialised
//! to secp256k1's prime (`2²⁵⁶ ≡ c (mod p)`). It is validated byte-for-byte
//! against the generic Montgomery reference
//! ([`GenericMont`](field_backend::GenericMont), the same audited
//! `MontModulus<4>` core P-256 uses) by the differential tests in
//! `field_backend`; `GenericMont` remains as that oracle and a fallback.

mod field_backend;
mod group;

use crate::bignum::MontModulus;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use crate::ec::Error;

use field_backend::{Fe, FieldBackend, Secp256k1Field, fe_from_hex};
use group::Point;

// --- curve constants (big-endian hex) ---

/// Generator x-coordinate.
const GX_HEX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// Generator y-coordinate.
const GY_HEX: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
/// Group order `n`.
const N_HEX: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

/// The base field backend the public API is wired to: the native
/// pseudo-Mersenne [`Secp256k1Field`](field_backend::Secp256k1Field) backend.
///
/// This native reduction is active and validated byte-for-byte against the
/// generic Montgomery reference [`GenericMont`](field_backend::GenericMont) by
/// the differential tests in `field_backend`. `GenericMont` is retained as that
/// oracle and a `pub(crate)` fallback.
type Backend = Secp256k1Field;

/// Constructs the active field backend.
#[inline]
fn field() -> Backend {
    Secp256k1Field::new()
}

// =====================================================================
// Scalar (mod n)
// =====================================================================

/// A scalar in the secp256k1 group field `Z/nZ`, where `n` is the (prime)
/// group order.
///
/// # Hazmat
///
/// Holds secret key material in some uses; it implements [`Drop`] to wipe its
/// bytes. Arithmetic is constant time, but the caller is responsible for not
/// leaking the value through other channels.
#[derive(Clone)]
pub struct Scalar(Fe);

impl Scalar {
    /// The additive identity `0`.
    pub const ZERO: Scalar = Scalar(Fe::ZERO);
    /// The multiplicative identity `1`.
    pub const ONE: Scalar = Scalar(Fe::ONE);

    /// Builds the scalar-field modulus context (order `n`).
    #[inline]
    fn modulus() -> MontModulus<4> {
        MontModulus::new(fe_from_hex(N_HEX))
    }

    /// The group order `n` as a [`Fe`].
    #[inline]
    fn order() -> Fe {
        fe_from_hex(N_HEX)
    }

    /// Decodes a canonical 32-byte big-endian scalar, rejecting any value
    /// `>= n` (including `n` itself).
    ///
    /// # Errors
    /// Returns [`Error::InvalidInput`] if the encoded value is not `< n`.
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Result<Scalar, Error> {
        let v = Fe::from_be_bytes(bytes);
        if bool::from(v.ct_lt(&Self::order())) {
            Ok(Scalar(v))
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// Reduces a 32-byte big-endian value modulo `n` (no range check).
    ///
    /// Intended for hash-to-scalar, where the input is a uniform hash output
    /// that should be folded into `[0, n)` rather than rejected.
    pub fn from_bytes_be_reduce(bytes: &[u8; 32]) -> Scalar {
        let v = Fe::from_be_bytes(bytes);
        Scalar(v.reduce(&Self::order()))
    }

    /// Returns the 32-byte big-endian encoding of this scalar.
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.write_be_bytes(&mut out);
        out
    }

    /// Returns `(self + rhs) mod n`.
    pub fn add(&self, rhs: &Scalar) -> Scalar {
        Scalar(Self::modulus().add_mod(&self.0, &rhs.0))
    }

    /// Returns `(self - rhs) mod n`.
    pub fn sub(&self, rhs: &Scalar) -> Scalar {
        Scalar(Self::modulus().sub_mod(&self.0, &rhs.0))
    }

    /// Returns `(self * rhs) mod n`.
    pub fn mul(&self, rhs: &Scalar) -> Scalar {
        Scalar(Self::modulus().mul_mod(&self.0, &rhs.0))
    }

    /// Returns `(-self) mod n`.
    pub fn negate(&self) -> Scalar {
        Scalar(Self::modulus().sub_mod(&Fe::ZERO, &self.0))
    }

    /// Returns the modular inverse `self^-1 mod n` (constant-time Fermat), or
    /// `0` when `self` is `0`.
    pub fn invert(&self) -> Scalar {
        // n is prime, so a^(n-2) is the inverse.
        let n_minus_2 = Self::order().wrapping_sub(&Fe::from_u64(2));
        Scalar(Self::modulus().pow(&self.0, &n_minus_2))
    }

    /// Returns a [`Choice`] that is true iff this scalar is `0`.
    pub fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    /// Returns a [`Choice`] that is true iff `self == other` (constant time).
    pub fn ct_eq(&self, other: &Scalar) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        // Best-effort wipe of the secret limbs with a black_box barrier so the
        // stores are not elided (mirrors the crate's no-foreign-code pattern).
        self.0 = Fe::ZERO;
        let _ = core::hint::black_box(&self.0);
    }
}

// =====================================================================
// Points
// =====================================================================

/// A secp256k1 point in projective coordinates.
///
/// The identity (point at infinity) is representable; use
/// [`is_identity`](ProjectivePoint::is_identity) to test for it.
#[derive(Clone, Copy)]
pub struct ProjectivePoint(Point);

/// A secp256k1 point in affine coordinates `(x, y)`, guaranteed on-curve and
/// not the identity (the identity has no affine representation).
#[derive(Clone, Copy)]
pub struct AffinePoint {
    x: Fe,
    y: Fe,
}

impl ProjectivePoint {
    /// The identity element (point at infinity).
    pub fn identity() -> ProjectivePoint {
        ProjectivePoint(Point::identity(&field()))
    }

    /// The generator (base point) `G`.
    pub fn generator() -> ProjectivePoint {
        let f = field();
        ProjectivePoint(Point::from_affine(
            &f,
            &fe_from_hex(GX_HEX),
            &fe_from_hex(GY_HEX),
        ))
    }

    /// Returns a [`Choice`] that is true iff this is the identity.
    pub fn is_identity(&self) -> Choice {
        self.0.is_identity()
    }

    /// Returns `self + rhs` (complete addition; correct for all inputs).
    pub fn add(&self, rhs: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint(Point::add(&field(), &self.0, &rhs.0))
    }

    /// Returns `2·self`.
    pub fn double(&self) -> ProjectivePoint {
        ProjectivePoint(Point::double(&field(), &self.0))
    }

    /// Returns `-self`.
    pub fn negate(&self) -> ProjectivePoint {
        ProjectivePoint(Point::negate(&field(), &self.0))
    }

    /// Returns `scalar · self` via a constant-time double-and-add ladder.
    pub fn mul(&self, scalar: &Scalar) -> ProjectivePoint {
        ProjectivePoint(Point::mul(&field(), scalar.0.as_limbs(), &self.0))
    }

    /// Returns `scalar · G` (scalar times the generator).
    pub fn mul_generator(scalar: &Scalar) -> ProjectivePoint {
        Self::generator().mul(scalar)
    }

    /// Constant-time point equality (different projective representatives of the
    /// same affine point compare equal).
    pub fn ct_eq(&self, other: &ProjectivePoint) -> Choice {
        self.0.ct_eq(&field(), &other.0)
    }

    /// Converts to affine coordinates, or `None` if this is the identity.
    pub fn to_affine(&self) -> Option<AffinePoint> {
        self.0
            .to_affine(&field())
            .map(|(x, y)| AffinePoint { x, y })
    }
}

impl ConditionallySelectable for ProjectivePoint {
    #[inline]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ProjectivePoint(Point::conditional_select(&a.0, &b.0, choice))
    }
}

impl AffinePoint {
    /// The generator (base point) `G`.
    pub fn generator() -> AffinePoint {
        AffinePoint {
            x: fe_from_hex(GX_HEX),
            y: fe_from_hex(GY_HEX),
        }
    }

    /// Lifts this affine point into projective coordinates.
    pub fn to_projective(&self) -> ProjectivePoint {
        ProjectivePoint(Point::from_affine(&field(), &self.x, &self.y))
    }

    /// The big-endian x-coordinate.
    pub fn x_bytes(&self) -> [u8; 32] {
        field().to_bytes_be(&self.x)
    }

    /// The big-endian y-coordinate.
    pub fn y_bytes(&self) -> [u8; 32] {
        field().to_bytes_be(&self.y)
    }

    /// Tests whether `(x, y)` satisfies `y² = x³ + 7 (mod p)`.
    fn is_on_curve(f: &Backend, x: &Fe, y: &Fe) -> Choice {
        let y2 = f.square(y);
        let x3 = f.mul(&f.square(x), x);
        let rhs = f.add(&x3, &Fe::from_u64(7));
        y2.ct_eq(&rhs)
    }

    // --- SEC1 codec ---

    /// Encodes as a 33-byte compressed SEC1 point: `0x02`/`0x03 || X`, where the
    /// tag byte's low bit is the parity (oddness) of `Y`.
    pub fn to_sec1_compressed(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        let x = self.x_bytes();
        let y = self.y_bytes();
        let y_odd = y[31] & 1;
        out[0] = 0x02 | y_odd;
        out[1..].copy_from_slice(&x);
        out
    }

    /// Encodes as a 65-byte uncompressed SEC1 point: `0x04 || X || Y`.
    pub fn to_sec1_uncompressed(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x_bytes());
        out[33..].copy_from_slice(&self.y_bytes());
        out
    }

    /// Decodes a SEC1 point, accepting both the 33-byte compressed form
    /// (`0x02`/`0x03`) and the 65-byte uncompressed form (`0x04`).
    ///
    /// Validates: correct length and tag, `X < p` (and `Y < p` for the
    /// uncompressed form), the point lies on the curve, and the point is not
    /// the identity. Compressed decoding recovers `Y` via the field square
    /// root and selects the root of the requested parity.
    ///
    /// # Errors
    /// Returns [`Error::Malformed`] for a bad length or tag, and
    /// [`Error::InvalidInput`] for an out-of-range coordinate, an off-curve
    /// point, or an identity / no-root encoding.
    pub fn from_sec1(bytes: &[u8]) -> Result<AffinePoint, Error> {
        let f = field();
        match bytes.first().copied() {
            Some(tag @ (0x02 | 0x03)) => {
                if bytes.len() != 33 {
                    return Err(Error::Malformed);
                }
                let mut xb = [0u8; 32];
                xb.copy_from_slice(&bytes[1..33]);
                let x = f
                    .from_bytes_be(&xb)
                    .into_option()
                    .ok_or(Error::InvalidInput)?;
                // y² = x³ + 7.
                let x3 = f.mul(&f.square(&x), &x);
                let rhs = f.add(&x3, &Fe::from_u64(7));
                let y = f.sqrt(&rhs).into_option().ok_or(Error::InvalidInput)?;
                // Pick the root with the requested parity.
                let y_bytes = f.to_bytes_be(&y);
                let want_odd = tag & 1;
                let have_odd = y_bytes[31] & 1;
                let y = if have_odd == want_odd {
                    y
                } else {
                    f.negate(&y)
                };
                let pt = AffinePoint { x, y };
                // y == 0 would make both parities identical; reject (no such
                // point exists on secp256k1, but the guard is cheap).
                if bool::from(pt.x.is_zero() & pt.y.is_zero()) {
                    return Err(Error::InvalidInput);
                }
                Ok(pt)
            }
            Some(0x04) => {
                if bytes.len() != 65 {
                    return Err(Error::Malformed);
                }
                let mut xb = [0u8; 32];
                let mut yb = [0u8; 32];
                xb.copy_from_slice(&bytes[1..33]);
                yb.copy_from_slice(&bytes[33..65]);
                let x = f
                    .from_bytes_be(&xb)
                    .into_option()
                    .ok_or(Error::InvalidInput)?;
                let y = f
                    .from_bytes_be(&yb)
                    .into_option()
                    .ok_or(Error::InvalidInput)?;
                if !bool::from(Self::is_on_curve(&f, &x, &y)) {
                    return Err(Error::InvalidInput);
                }
                if bool::from(x.is_zero() & y.is_zero()) {
                    return Err(Error::InvalidInput);
                }
                Ok(AffinePoint { x, y })
            }
            _ => Err(Error::Malformed),
        }
    }
}

#[cfg(test)]
mod tests;
