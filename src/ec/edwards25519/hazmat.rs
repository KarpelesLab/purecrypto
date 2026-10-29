//! Low-level edwards25519 group and order-`L` scalar arithmetic.
//!
//! # Hazmat
//!
//! **This module carries no semver-stability guarantee.** Its API may change
//! in any release. It exposes the raw group operations underneath the audited
//! RFC 8032 [`Ed25519`](crate::ec::ed25519) signing path, so the caller — not
//! purecrypto — owns protocol correctness, domain separation, cofactor
//! handling, and constant-time discipline at the call sites. Use the
//! high-level [`ed25519`](crate::ec::ed25519) API unless you are implementing a
//! lower-level construction (threshold signatures, VSS, FROST, …) that
//! genuinely needs group access.
//!
//! The arithmetic itself is constant-time (it is the same constant-time
//! `curve25519` backend the signing path uses):
//! scalar multiplication is a fixed-schedule double-and-add, field/scalar ops
//! are branch-free. Variable-time helpers, where offered, are suffixed
//! `_vartime` and documented as such.
//!
//! ## Types
//!
//! - [`Scalar`] — an integer modulo the group order
//!   `L = 2²⁵² + 27742317777372353535851937790883648493`. This is **the shared
//!   scalar type**, also re-exported by [`crate::ec::ristretto255`].
//! - [`EdwardsPoint`] — a point on edwards25519 in the full group (cofactor 8),
//!   with RFC 8032 32-byte compression, affine / extended coordinate access,
//!   and the Montgomery (X25519) `u` map.
//! - [`FieldElement`] — an element of the base field `GF(p)`,
//!   `p = 2²⁵⁵ − 19`, with the minimal arithmetic needed to work with those
//!   coordinates.
//!
//! ## Variable-time operations
//!
//! [`EdwardsPoint::double_scalar_mul_base_vartime`] (`[a]A + [b]B`, the
//! verification combination) branches on and indexes tables by its scalars.
//! It must only see **public** inputs.
#![cfg_attr(
    not(feature = "ristretto255"),
    doc = "",
    doc = "[`crate::ec::ristretto255`]: crate"
)]

use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use crate::ec::curve25519::field::{Fe, Field, ScalarInt};
use crate::ec::curve25519::point::Point;
use crate::ec::curve25519::scalar::{
    scalar_add, scalar_invert, scalar_mul, scalar_negate, scalar_reduce_wide, scalar_sub,
};

/// An integer modulo the edwards25519 group order
/// `L = 2²⁵² + 27742317777372353535851937790883648493`.
///
/// Stored as a canonical residue in `[0, L)`. This is the shared scalar field
/// for both edwards25519 and [`crate::ec::ristretto255`]. The value is wiped on
/// drop with the crate's volatile [`zeroize`](crate::zeroize) stores.
///
/// Because the value is zeroized on drop, `Scalar` is [`Clone`] but not
/// `Copy`; pass it by reference or clone it explicitly.
#[cfg_attr(
    not(feature = "ristretto255"),
    doc = "",
    doc = "[`crate::ec::ristretto255`]: crate"
)]
#[derive(Clone)]
pub struct Scalar(pub(crate) ScalarInt);

impl crate::zeroize::Zeroize for Scalar {
    /// Wipes the secret limbs with volatile stores the optimizer may not
    /// elide (a plain assignment plus a `black_box` read is only a hint).
    #[inline]
    fn zeroize(&mut self) {
        crate::zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl crate::zeroize::ZeroizeOnDrop for Scalar {}

impl Drop for Scalar {
    fn drop(&mut self) {
        crate::zeroize::Zeroize::zeroize(self);
    }
}

impl Scalar {
    /// The additive identity `0`.
    pub const ZERO: Scalar = Scalar(ScalarInt::ZERO);
    /// The multiplicative identity `1`.
    pub const ONE: Scalar = Scalar(ScalarInt::ONE);

    /// Decodes a 32-byte little-endian scalar, returning `None` if it is not
    /// canonical (i.e. `>= L`).
    pub fn from_bytes_canonical(bytes: &[u8; 32]) -> Option<Scalar> {
        let f = Field::new();
        let v = ScalarInt::from_le_bytes(bytes);
        if bool::from(v.ct_lt(&f.l)) {
            Some(Scalar(v))
        } else {
            None
        }
    }

    /// Reduces a 64-byte little-endian integer modulo `L` (the wide
    /// reduction used for hash-to-scalar, RFC 8032 / FROST).
    pub fn from_bytes_mod_order(bytes: &[u8; 64]) -> Scalar {
        Scalar(scalar_reduce_wide(bytes))
    }

    /// The 32-byte little-endian canonical encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.write_le_bytes(&mut out);
        out
    }

    /// `self + rhs (mod L)`.
    pub fn add(&self, rhs: &Scalar) -> Scalar {
        let f = Field::new();
        Scalar(scalar_add(&self.0, &rhs.0, &f.l))
    }

    /// `self - rhs (mod L)`.
    pub fn sub(&self, rhs: &Scalar) -> Scalar {
        let f = Field::new();
        Scalar(scalar_sub(&self.0, &rhs.0, &f.l))
    }

    /// `self * rhs (mod L)`.
    pub fn mul(&self, rhs: &Scalar) -> Scalar {
        Scalar(scalar_mul(&self.0, &rhs.0))
    }

    /// `-self (mod L)`.
    pub fn negate(&self) -> Scalar {
        let f = Field::new();
        Scalar(scalar_negate(&self.0, &f.l))
    }

    /// The multiplicative inverse `self⁻¹ (mod L)`, constant-time (a fixed
    /// safegcd divstep schedule). The inverse of `0` is `0`.
    pub fn invert(&self) -> Scalar {
        let f = Field::new();
        Scalar(scalar_invert(&self.0, &f.l))
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Scalar) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Scalar) -> bool {
        bool::from(self.ct_eq(other))
    }
}
impl Eq for Scalar {}

impl core::fmt::Debug for Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Do not leak the value; scalars may be secret.
        f.write_str("Scalar(…)")
    }
}

/// An element of the edwards25519 / curve25519 base field `GF(p)`,
/// `p = 2²⁵⁵ − 19`.
///
/// Internally an unsaturated 5×51-bit limb representation that is not
/// necessarily fully reduced; every observable output
/// ([`to_bytes`](Self::to_bytes), equality, [`is_negative`](Self::is_negative))
/// goes through the canonical residue in `[0, p)`. All operations are
/// constant-time (inversion is a fixed safegcd schedule, square roots a fixed
/// exponentiation chain).
///
/// The type is `Copy` and is **not** wiped on drop; when a field element is
/// secret (e.g. an X25519 `u` coordinate derived from a private key), wipe it
/// explicitly with [`Zeroize`](crate::zeroize::Zeroize).
#[derive(Clone, Copy)]
pub struct FieldElement(pub(crate) Fe);

impl FieldElement {
    /// The additive identity `0`.
    pub const ZERO: FieldElement = FieldElement(Fe::ZERO);
    /// The multiplicative identity `1`.
    pub const ONE: FieldElement = FieldElement(Fe::ONE);
    /// The edwards25519 curve constant `d = −121665/121666`.
    pub const EDWARDS_D: FieldElement = FieldElement(Fe::D);
    /// A square root of `−1` (`2^((p−1)/4)`, the value RFC 8032 and RFC 9496
    /// use).
    pub const SQRT_M1: FieldElement = FieldElement(Fe::SQRT_M1);

    /// Decodes 32 little-endian bytes, **ignoring the top bit** (bit 255) and
    /// accepting non-canonical values in `[p, 2²⁵⁵)`, which are reduced
    /// modulo `p`. This matches libsodium / ref10's `fe25519_frombytes` and
    /// RFC 7748's handling of X25519 `u` coordinates.
    pub fn from_bytes(bytes: &[u8; 32]) -> FieldElement {
        FieldElement(Fe::from_bytes(bytes))
    }

    /// Decodes 32 little-endian bytes, returning `None` unless they are the
    /// canonical encoding of a residue (`< p`, top bit clear). Only whether
    /// the input was canonical is revealed.
    pub fn from_bytes_canonical(bytes: &[u8; 32]) -> Option<FieldElement> {
        let v = ScalarInt::from_le_bytes(bytes);
        if bool::from(v.ct_lt(&Field::new().p)) {
            Some(FieldElement(Fe::from_bytes(bytes)))
        } else {
            None
        }
    }

    /// The canonical 32-byte little-endian encoding of the residue in
    /// `[0, p)` (top bit always clear).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// `self + rhs`.
    pub fn add(&self, rhs: &FieldElement) -> FieldElement {
        FieldElement(self.0.add(&rhs.0))
    }

    /// `self − rhs`.
    pub fn sub(&self, rhs: &FieldElement) -> FieldElement {
        FieldElement(self.0.sub(&rhs.0))
    }

    /// `−self`.
    pub fn negate(&self) -> FieldElement {
        FieldElement(self.0.neg())
    }

    /// `self · rhs`.
    pub fn mul(&self, rhs: &FieldElement) -> FieldElement {
        FieldElement(self.0.mul(&rhs.0))
    }

    /// `self²`.
    pub fn square(&self) -> FieldElement {
        FieldElement(self.0.sq())
    }

    /// The multiplicative inverse `self⁻¹`; the inverse of `0` is `0`.
    pub fn invert(&self) -> FieldElement {
        FieldElement(self.0.invert())
    }

    /// RFC 9496 §4.2 `SQRT_RATIO_M1(u, v)`: returns `(was_square, r)` where
    ///
    /// - if `v ≠ 0` and `u/v` is a square, `was_square` is true and
    ///   `r = +√(u/v)`;
    /// - if `v ≠ 0` and `u/v` is not a square, `was_square` is false and
    ///   `r = +√(√−1 · u/v)`;
    /// - if `u = 0`, `was_square` is true and `r = 0`;
    /// - if `v = 0` and `u ≠ 0`, `was_square` is false and `r = 0`.
    ///
    /// `r` is always the non-negative root (even canonical encoding).
    pub fn sqrt_ratio_i(u: &FieldElement, v: &FieldElement) -> (Choice, FieldElement) {
        let (was_square, r) = Field::new().sqrt_ratio_i(u.0, v.0);
        (was_square, FieldElement(r))
    }

    /// Whether the canonical residue is odd — the "sign" (negative) bit of
    /// RFC 8032 / RFC 9496 encodings.
    pub fn is_negative(&self) -> Choice {
        self.0.is_negative()
    }

    /// Whether the element is `0`.
    pub fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    /// Constant-time equality (of the residues).
    pub fn ct_eq(&self, other: &FieldElement) -> Choice {
        self.0.ct_eq_fe(&other.0)
    }

    /// `a` if `choice` is set, otherwise `b`, constant-time.
    pub fn conditional_select(a: &FieldElement, b: &FieldElement, choice: Choice) -> FieldElement {
        FieldElement(Fe::conditional_select(&a.0, &b.0, choice))
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &FieldElement) -> bool {
        bool::from(self.ct_eq(other))
    }
}
impl Eq for FieldElement {}

impl core::fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Field elements may be secret; do not print the value.
        f.write_str("FieldElement(…)")
    }
}

impl crate::zeroize::Zeroize for FieldElement {
    /// Wipes the limbs with volatile stores.
    fn zeroize(&mut self) {
        crate::zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// A point on the edwards25519 curve (the full group, cofactor 8).
///
/// Compression / decompression follow RFC 8032 §5.1.2–5.1.3 (32 bytes, sign
/// bit in the top bit of the last byte).
#[derive(Clone, Copy)]
pub struct EdwardsPoint(pub(crate) Point);

impl core::fmt::Debug for EdwardsPoint {
    /// Prints the canonical RFC 8032 encoding rather than the raw projective
    /// `(X:Y:Z:T)` coordinates: those differ between representatives of the
    /// same point (so are misleading in a diff) and, for a point derived from
    /// a secret, can leak more than the public encoding does.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EdwardsPoint(")?;
        for b in self.compress() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

impl EdwardsPoint {
    /// The edwards25519 basepoint `B` (RFC 8032).
    pub fn generator() -> EdwardsPoint {
        EdwardsPoint(Field::new().base())
    }

    /// The neutral element (identity) of the group.
    pub fn identity() -> EdwardsPoint {
        EdwardsPoint(Field::new().identity())
    }

    /// `self + rhs`.
    pub fn add(&self, rhs: &EdwardsPoint) -> EdwardsPoint {
        EdwardsPoint(Field::new().point_add(&self.0, &rhs.0))
    }

    /// `self - rhs`.
    pub fn sub(&self, rhs: &EdwardsPoint) -> EdwardsPoint {
        let f = Field::new();
        EdwardsPoint(f.point_add(&self.0, &f.point_negate(&rhs.0)))
    }

    /// `[2]self`.
    pub fn double(&self) -> EdwardsPoint {
        EdwardsPoint(Field::new().point_double(&self.0))
    }

    /// `-self`.
    pub fn negate(&self) -> EdwardsPoint {
        EdwardsPoint(Field::new().point_negate(&self.0))
    }

    /// `[scalar]·self`, constant-time.
    pub fn mul(&self, scalar: &Scalar) -> EdwardsPoint {
        let f = Field::new();
        let mut bytes = scalar_bytes(&scalar.0);
        let out = EdwardsPoint(f.scalar_mult(&bytes, &self.0));
        wipe_scalar_bytes(&mut bytes);
        out
    }

    /// `[scalar]·B` (scalar times the basepoint), constant-time (precomputed
    /// fixed-base comb with the `ed25519-table` feature, a windowed ladder
    /// without it).
    pub fn mul_base(scalar: &Scalar) -> EdwardsPoint {
        let f = Field::new();
        let mut bytes = scalar_bytes(&scalar.0);
        let out = EdwardsPoint(f.mul_base(&bytes));
        wipe_scalar_bytes(&mut bytes);
        out
    }

    /// `[8]self` — multiply by the curve cofactor.
    pub fn mul_by_cofactor(&self) -> EdwardsPoint {
        let f = Field::new();
        EdwardsPoint(f.point_double(&f.point_double(&f.point_double(&self.0))))
    }

    /// Constant-time point equality (compares the projective representatives by
    /// cross-multiplication, so different `(X:Y:Z:T)` for the same point are
    /// equal).
    pub fn ct_eq(&self, other: &EdwardsPoint) -> Choice {
        Field::new().point_ct_eq(&self.0, &other.0)
    }

    /// RFC 8032 32-byte compression.
    pub fn compress(&self) -> [u8; 32] {
        Field::new().encode(&self.0)
    }

    /// RFC 8032 32-byte decompression. Returns `None` if the bytes do not
    /// encode a curve point (non-canonical `y`, or no valid `x`).
    pub fn decompress(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
        Field::new().decode(bytes).map(EdwardsPoint)
    }

    /// The affine coordinates `(x, y) = (X/Z, Y/Z)` of this point, each as a
    /// 32-byte little-endian canonical encoding of a field residue in `[0, p)`,
    /// where `p = 2²⁵⁵ − 19`.
    ///
    /// Unlike [`compress`](Self::compress) (which keeps only `y` plus the sign
    /// bit of `x`), this exposes the full, un-folded `x` and `y`. The single
    /// field inversion needed to de-projectivize is shared between the two
    /// coordinates; prefer this over calling [`x_bytes`](Self::x_bytes) and
    /// [`y_bytes`](Self::y_bytes) separately when you need both.
    pub fn to_affine(&self) -> ([u8; 32], [u8; 32]) {
        Field::new().to_affine_bytes(&self.0)
    }

    /// The affine `x` coordinate, as a 32-byte little-endian canonical encoding
    /// in `[0, p)`. See [`to_affine`](Self::to_affine).
    pub fn x_bytes(&self) -> [u8; 32] {
        self.to_affine().0
    }

    /// The affine `y` coordinate, as a 32-byte little-endian canonical encoding
    /// in `[0, p)`. See [`to_affine`](Self::to_affine).
    pub fn y_bytes(&self) -> [u8; 32] {
        self.to_affine().1
    }

    /// The affine coordinates `(x, y)` as [`FieldElement`]s. See
    /// [`to_affine`](Self::to_affine) for the byte form.
    pub fn to_affine_coordinates(&self) -> (FieldElement, FieldElement) {
        let f = Field::new();
        let zinv = f.inv(self.0.z);
        (
            FieldElement(f.mul(self.0.x, zinv)),
            FieldElement(f.mul(self.0.y, zinv)),
        )
    }

    /// The extended twisted-Edwards coordinates `[X, Y, Z, T]` of this
    /// representative, with `x = X/Z`, `y = Y/Z` and `X·Y = Z·T`.
    ///
    /// These are **not unique**: a point has many representatives (any common
    /// nonzero scale factor), and which one you get depends on how the point
    /// was computed. Compare points with [`ct_eq`](Self::ct_eq) or through
    /// [`to_affine`](Self::to_affine), never by these coordinates. For a point
    /// derived from a secret, the representative can reveal more about the
    /// computation than the canonical encoding does.
    pub fn to_extended(&self) -> [FieldElement; 4] {
        [
            FieldElement(self.0.x),
            FieldElement(self.0.y),
            FieldElement(self.0.z),
            FieldElement(self.0.t),
        ]
    }

    /// [`to_extended`](Self::to_extended) as canonical 32-byte little-endian
    /// encodings `[X, Y, Z, T]` (each residue in `[0, p)`).
    pub fn to_extended_bytes(&self) -> [[u8; 32]; 4] {
        self.to_extended().map(|c| c.to_bytes())
    }

    /// Builds a point from affine coordinates, returning `None` unless
    /// `−x² + y² = 1 + d·x²·y²`. The check is constant-time; only its outcome
    /// is revealed.
    pub fn from_affine(x: &FieldElement, y: &FieldElement) -> Option<EdwardsPoint> {
        let f = Field::new();
        let xx = f.sq(x.0);
        let yy = f.sq(y.0);
        let lhs = f.sub(yy, xx);
        let rhs = f.add(f.one, f.mul(f.d, f.mul(xx, yy)));
        if bool::from(f.ct_eq(lhs, rhs)) {
            Some(EdwardsPoint(Point {
                x: x.0,
                y: y.0,
                z: f.one,
                t: f.mul(x.0, y.0),
            }))
        } else {
            None
        }
    }

    /// Builds a point from extended coordinates `[X, Y, Z, T]`, returning
    /// `None` unless `Z ≠ 0`, `X·Y = Z·T`, and the projective curve equation
    /// `(Y² − X²)·Z² = Z⁴ + d·X²·Y²` holds. The checks are constant-time; only
    /// their combined outcome is revealed.
    pub fn from_extended(coords: &[FieldElement; 4]) -> Option<EdwardsPoint> {
        let f = Field::new();
        let [x, y, z, t] = [coords[0].0, coords[1].0, coords[2].0, coords[3].0];
        let xx = f.sq(x);
        let yy = f.sq(y);
        let zz = f.sq(z);
        let on_curve = f.ct_eq(
            f.mul(f.sub(yy, xx), zz),
            f.add(f.sq(zz), f.mul(f.d, f.mul(xx, yy))),
        );
        let segre = f.ct_eq(f.mul(x, y), f.mul(z, t));
        let z_ok = !z.is_zero();
        if bool::from(on_curve & segre & z_ok) {
            Some(EdwardsPoint(Point { x, y, z, t }))
        } else {
            None
        }
    }

    /// The Montgomery `u`-coordinate of the birationally equivalent
    /// curve25519 point, `u = (1 + y)/(1 − y)`, as the canonical 32-byte
    /// encoding X25519 uses (RFC 7748 §4.1). Constant-time.
    ///
    /// No validation is performed: the identity (`y = 1`) maps to `u = 0`,
    /// and small- or mixed-order points map to the corresponding torsioned
    /// Montgomery points. For libsodium's validated
    /// `crypto_sign_ed25519_pk_to_curve25519`, use
    /// [`Ed25519PublicKey::to_x25519`](crate::ec::ed25519::Ed25519PublicKey::to_x25519).
    pub fn to_montgomery(&self) -> [u8; 32] {
        Field::new().to_montgomery_u(&self.0)
    }

    /// **Variable-time** `[a]·A + [b]·B`, with `B` the basepoint — the
    /// Ed25519 verification combination, an interleaved (Straus) wNAF ladder
    /// sharing one run of doublings (width 8 against a static basepoint table
    /// with the `ed25519-table` feature).
    ///
    /// # Warning: public inputs only
    ///
    /// The branch pattern and table indices depend on both scalars, and the
    /// table contents on `A`. Never pass a secret scalar or a secret point.
    pub fn double_scalar_mul_base_vartime(
        a: &Scalar,
        point_a: &EdwardsPoint,
        b: &Scalar,
    ) -> EdwardsPoint {
        EdwardsPoint(Field::new().double_scalar_mult_base_vartime(
            &a.to_bytes(),
            &point_a.0,
            &b.to_bytes(),
        ))
    }

    /// Whether `self` is a point of small order (in the 8-torsion subgroup):
    /// `[8]self == identity`. Constant-time.
    pub fn is_small_order(&self) -> Choice {
        let f = Field::new();
        let eightp = self.mul_by_cofactor();
        f.point_ct_eq(&eightp.0, &f.identity())
    }

    /// Whether `self` is torsion-free (in the prime-order subgroup):
    /// `[L]self == identity`. Constant-time in the point (the scalar `L` is a
    /// public constant).
    pub fn is_torsion_free(&self) -> Choice {
        let f = Field::new();
        let lp = f.scalar_mult(&scalar_bytes(&f.l), &self.0);
        f.point_ct_eq(&lp, &f.identity())
    }
}

impl PartialEq for EdwardsPoint {
    fn eq(&self, other: &EdwardsPoint) -> bool {
        bool::from(self.ct_eq(other))
    }
}
impl Eq for EdwardsPoint {}

/// Little-endian 32-byte view of a residue `< L`, for the scalar ladder.
fn scalar_bytes(v: &ScalarInt) -> [u8; 32] {
    let mut b = [0u8; 32];
    v.write_le_bytes(&mut b);
    b
}

/// Best-effort wipe of a scalar's plaintext byte copy through
/// [`crate::zeroize::Zeroize`] (the volatile stores `Scalar::drop` uses). The
/// scalar fed to `mul`/`mul_base` is usually a private key or nonce.
#[inline]
fn wipe_scalar_bytes(b: &mut [u8; 32]) {
    crate::zeroize::Zeroize::zeroize(b);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curve25519::field::Field;
    use crate::zeroize::Zeroize as _;

    /// The scalar's `Zeroize` (and hence its `Drop`) must leave every limb
    /// zero — the limbs are the private key in `ec::ristretto255` and the
    /// hazmat exposures.
    #[test]
    fn zeroize_clears_limbs() {
        let mut s = Scalar::from_bytes_mod_order(&[0xAB; 64]);
        assert!(s.0.as_limbs().iter().any(|&l| l != 0));
        s.zeroize();
        assert!(s.0.as_limbs().iter().all(|&l| l == 0));
    }

    // Reference [s]B straight off the backend, mirroring how Ed25519's
    // `public_key` computes A = [a]B, so we cross-check mul_base against it.
    fn backend_mul_base(s: &Scalar) -> [u8; 32] {
        let f = Field::new();
        let mut bytes = [0u8; 32];
        s.0.write_le_bytes(&mut bytes);
        f.encode(&f.scalar_mult(&bytes, &f.base()))
    }

    #[test]
    fn mul_base_matches_backend() {
        for seed in [1u64, 2, 7, 0xdead_beef, 0x1234_5678_9abc_def0] {
            let s = Scalar::from_bytes_mod_order(&{
                let mut b = [0u8; 64];
                b[..8].copy_from_slice(&seed.to_le_bytes());
                b
            });
            let viapoint = EdwardsPoint::mul_base(&s).compress();
            assert_eq!(
                viapoint,
                backend_mul_base(&s),
                "mul_base != [s]B (seed {seed})"
            );
        }
    }

    #[test]
    fn generator_is_basepoint_and_mul_base_one() {
        let g = EdwardsPoint::generator();
        let one = Scalar::ONE;
        assert_eq!(EdwardsPoint::mul_base(&one), g);
    }

    #[test]
    fn add_double_consistency() {
        let g = EdwardsPoint::generator();
        let g2 = g.add(&g);
        assert_eq!(g2, g.double());
        // [2]B via scalar must match.
        let two = Scalar::ONE.add(&Scalar::ONE);
        assert_eq!(EdwardsPoint::mul_base(&two), g2);
        // [3]B = [2]B + B.
        let g3 = g2.add(&g);
        let three = two.add(&Scalar::ONE);
        assert_eq!(EdwardsPoint::mul_base(&three), g3);
    }

    /// `Debug` shows the canonical encoding, not projective coordinates: two
    /// representatives of the same point print identically, and the output is
    /// exactly the hex of `compress()`.
    #[test]
    fn debug_prints_canonical_encoding() {
        use core::fmt::Write;

        /// A fixed-size `fmt::Write` sink, so the test needs no allocator.
        struct Sink {
            buf: [u8; 96],
            len: usize,
        }
        impl Write for Sink {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let b = s.as_bytes();
                self.buf[self.len..self.len + b.len()].copy_from_slice(b);
                self.len += b.len();
                Ok(())
            }
        }
        fn render(args: core::fmt::Arguments<'_>) -> ([u8; 96], usize) {
            let mut s = Sink {
                buf: [0u8; 96],
                len: 0,
            };
            s.write_fmt(args).unwrap();
            (s.buf, s.len)
        }

        let g = EdwardsPoint::generator();
        let two = Scalar::ONE.add(&Scalar::ONE);
        // [2]B via doubling and via the ladder have different (X:Y:Z:T).
        let a = g.double();
        let b = g.mul(&two);
        assert_eq!(a, b);
        let (da, la) = render(format_args!("{a:?}"));
        let (db, lb) = render(format_args!("{b:?}"));
        assert_eq!(&da[..la], &db[..lb]);

        let mut want = Sink {
            buf: [0u8; 96],
            len: 0,
        };
        want.write_str("EdwardsPoint(").unwrap();
        for byte in a.compress() {
            write!(want, "{byte:02x}").unwrap();
        }
        want.write_str(")").unwrap();
        assert_eq!(&da[..la], &want.buf[..want.len]);
    }

    #[test]
    fn known_multiples_via_mul() {
        // [k]B computed by mul on the generator equals mul_base(k).
        let g = EdwardsPoint::generator();
        for k in 1u64..16 {
            let s = Scalar::from_bytes_mod_order(&{
                let mut b = [0u8; 64];
                b[..8].copy_from_slice(&k.to_le_bytes());
                b
            });
            assert_eq!(g.mul(&s), EdwardsPoint::mul_base(&s), "[{k}]B mismatch");
        }
    }

    #[test]
    fn compress_decompress_roundtrip() {
        for k in 1u64..10 {
            let s = Scalar::from_bytes_mod_order(&{
                let mut b = [0u8; 64];
                b[..8].copy_from_slice(&k.to_le_bytes());
                b
            });
            let p = EdwardsPoint::mul_base(&s);
            let enc = p.compress();
            let dec = EdwardsPoint::decompress(&enc).expect("roundtrip decode");
            assert_eq!(dec, p);
            assert_eq!(dec.compress(), enc);
        }
    }

    #[test]
    fn affine_coords_match_compression() {
        // `compress()` keeps `y` plus the sign bit of `x`, so it is the
        // well-tested oracle for the affine accessors: rebuilding the
        // compressed encoding from (x_bytes, y_bytes) must reproduce it.
        for k in 1u64..12 {
            let s = Scalar::from_bytes_mod_order(&{
                let mut b = [0u8; 64];
                b[..8].copy_from_slice(&k.to_le_bytes());
                b
            });
            let p = EdwardsPoint::mul_base(&s);
            let (x, y) = p.to_affine();
            // x_bytes/y_bytes agree with the combined accessor.
            assert_eq!(p.x_bytes(), x);
            assert_eq!(p.y_bytes(), y);
            // y is canonical (high bit unused) and x's parity is the sign bit.
            assert_eq!(y[31] & 0x80, 0, "[{k}]B: y must be < 2^255");
            let mut rebuilt = y;
            rebuilt[31] |= (x[0] & 1) << 7;
            assert_eq!(rebuilt, p.compress(), "[{k}]B affine vs compress");
            // Decompressing the rebuilt encoding returns the same point.
            assert_eq!(EdwardsPoint::decompress(&rebuilt).unwrap(), p);
        }
    }

    #[test]
    fn affine_identity() {
        // Identity is affine (0, 1): x all-zero, y == 1.
        let (x, y) = EdwardsPoint::identity().to_affine();
        assert_eq!(x, [0u8; 32]);
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(y, one);
    }

    #[test]
    fn negate_and_sub() {
        let g = EdwardsPoint::generator();
        let two = Scalar::ONE.add(&Scalar::ONE);
        let g2 = EdwardsPoint::mul_base(&two);
        // [2]B - B == B.
        assert_eq!(g2.sub(&g), g);
        // B + (-B) == identity.
        assert_eq!(g.add(&g.negate()), EdwardsPoint::identity());
    }

    #[test]
    fn scalar_arithmetic_identities() {
        let a = Scalar::from_bytes_mod_order(&{
            let mut b = [0u8; 64];
            b[..8].copy_from_slice(&0x0123_4567u64.to_le_bytes());
            b
        });
        let b = Scalar::from_bytes_mod_order(&{
            let mut bb = [0u8; 64];
            bb[..8].copy_from_slice(&0x89ab_cdefu64.to_le_bytes());
            bb
        });
        // a + 0 == a, a * 1 == a.
        assert_eq!(a.add(&Scalar::ZERO), a);
        assert_eq!(a.mul(&Scalar::ONE), a);
        // a - a == 0, a + (-a) == 0.
        assert_eq!(a.sub(&a), Scalar::ZERO);
        assert_eq!(a.add(&a.negate()), Scalar::ZERO);
        // a * a^-1 == 1 (a != 0).
        assert_eq!(a.mul(&a.invert()), Scalar::ONE);
        // distributivity: (a+b)*a == a*a + b*a.
        assert_eq!(a.add(&b).mul(&a), a.mul(&a).add(&b.mul(&a)));
    }

    #[test]
    fn canonical_rejects_l_and_above() {
        let f = Field::new();
        // L itself is non-canonical.
        let mut lbytes = [0u8; 32];
        f.l.write_le_bytes(&mut lbytes);
        assert!(Scalar::from_bytes_canonical(&lbytes).is_none());
        // L - 1 is canonical.
        let lm1 = f.l.wrapping_sub(&ScalarInt::from_u64(1));
        let mut lm1b = [0u8; 32];
        lm1.write_le_bytes(&mut lm1b);
        assert!(Scalar::from_bytes_canonical(&lm1b).is_some());
        // to_bytes round-trips a canonical scalar.
        let s = Scalar::from_bytes_canonical(&lm1b).unwrap();
        assert_eq!(s.to_bytes(), lm1b);
    }

    #[test]
    fn torsion_and_small_order() {
        let g = EdwardsPoint::generator();
        // The basepoint is in the prime-order subgroup and not small-order.
        assert!(bool::from(g.is_torsion_free()));
        assert!(!bool::from(g.is_small_order()));
        // The identity is small-order.
        assert!(bool::from(EdwardsPoint::identity().is_small_order()));
    }

    fn scalar_u64(k: u64) -> Scalar {
        let mut b = [0u8; 64];
        b[..8].copy_from_slice(&k.to_le_bytes());
        Scalar::from_bytes_mod_order(&b)
    }

    fn fe_u64(k: u64) -> FieldElement {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&k.to_le_bytes());
        FieldElement::from_bytes(&b)
    }

    #[test]
    fn field_element_arithmetic() {
        let two = fe_u64(2);
        let three = fe_u64(3);
        assert_eq!(two.add(&three), fe_u64(5));
        assert_eq!(two.sub(&three), FieldElement::ONE.negate());
        assert_eq!(two.mul(&three), fe_u64(6));
        assert_eq!(three.square(), fe_u64(9));
        assert_eq!(three.mul(&three.invert()), FieldElement::ONE);
        assert_eq!(FieldElement::ZERO.invert(), FieldElement::ZERO);
        assert!(bool::from(FieldElement::ZERO.is_zero()));
        assert!(bool::from(FieldElement::ONE.is_negative()));
        assert!(!bool::from(two.is_negative()));
        // SQRT_M1² = −1; d·121666 = −121665.
        assert_eq!(FieldElement::SQRT_M1.square(), FieldElement::ONE.negate());
        assert_eq!(
            FieldElement::EDWARDS_D.mul(&fe_u64(121666)),
            fe_u64(121665).negate()
        );
        // sqrt_ratio_i: 4/1 → 2 (square), 2/1 → non-square, 0/v → 0.
        let (sq, r) = FieldElement::sqrt_ratio_i(&fe_u64(4), &FieldElement::ONE);
        assert!(bool::from(sq));
        assert_eq!(r, two);
        let (sq, r) = FieldElement::sqrt_ratio_i(&two, &FieldElement::ONE);
        assert!(!bool::from(sq));
        // r² = √−1 · 2.
        assert_eq!(r.square(), FieldElement::SQRT_M1.mul(&two));
        let (sq, r) = FieldElement::sqrt_ratio_i(&FieldElement::ZERO, &three);
        assert!(bool::from(sq));
        assert_eq!(r, FieldElement::ZERO);
        assert_eq!(
            FieldElement::conditional_select(&two, &three, Choice::from(1)),
            two
        );
        assert_eq!(
            FieldElement::conditional_select(&two, &three, Choice::from(0)),
            three
        );
    }

    #[test]
    fn field_element_encodings() {
        // p + 1 (non-canonical) decodes leniently to 1, canonical decode
        // refuses it; the top bit is ignored by the lenient decoder.
        let mut p1 = [0xffu8; 32];
        p1[0] = 0xee;
        p1[31] = 0x7f;
        assert_eq!(FieldElement::from_bytes(&p1), FieldElement::ONE);
        assert_eq!(FieldElement::from_bytes(&p1).to_bytes(), {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        });
        assert!(FieldElement::from_bytes_canonical(&p1).is_none());
        let mut top = [0u8; 32];
        top[0] = 7;
        top[31] = 0x80;
        assert_eq!(FieldElement::from_bytes(&top), fe_u64(7));
        assert!(FieldElement::from_bytes_canonical(&top).is_none());
        // p − 1 is canonical and equals −1.
        let mut pm1 = [0xffu8; 32];
        pm1[0] = 0xec;
        pm1[31] = 0x7f;
        let m1 = FieldElement::from_bytes_canonical(&pm1).unwrap();
        assert_eq!(m1, FieldElement::ONE.negate());
        assert_eq!(m1.to_bytes(), pm1);
    }

    #[test]
    fn coordinates_roundtrip() {
        for k in [1u64, 2, 5, 77, 0xdead_beef] {
            // A non-trivial projective representative (from the ladder).
            let p = EdwardsPoint::generator().mul(&scalar_u64(k));
            let [x, y, z, t] = p.to_extended();
            assert_eq!(x.mul(&y), z.mul(&t), "[{k}]B Segre relation");
            let (ax, ay) = p.to_affine_coordinates();
            let zinv = z.invert();
            assert_eq!(ax, x.mul(&zinv));
            assert_eq!(ay, y.mul(&zinv));
            assert_eq!((ax.to_bytes(), ay.to_bytes()), p.to_affine());
            assert_eq!(
                p.to_extended_bytes(),
                [x.to_bytes(), y.to_bytes(), z.to_bytes(), t.to_bytes()]
            );
            assert_eq!(EdwardsPoint::from_affine(&ax, &ay).unwrap(), p);
            assert_eq!(EdwardsPoint::from_extended(&[x, y, z, t]).unwrap(), p);
            // Off-curve / malformed inputs are refused.
            assert!(EdwardsPoint::from_affine(&ax, &ay.add(&FieldElement::ONE)).is_none());
            assert!(EdwardsPoint::from_extended(&[x, y, z, t.add(&FieldElement::ONE)]).is_none());
            assert!(
                EdwardsPoint::from_extended(&[
                    FieldElement::ZERO,
                    FieldElement::ZERO,
                    FieldElement::ZERO,
                    FieldElement::ZERO
                ])
                .is_none()
            );
        }
        // Identity (0, 1).
        assert_eq!(
            EdwardsPoint::from_affine(&FieldElement::ZERO, &FieldElement::ONE).unwrap(),
            EdwardsPoint::identity()
        );
    }

    #[test]
    fn montgomery_map_matches_x25519() {
        // B ↦ u = 9.
        let mut nine = [0u8; 32];
        nine[0] = 9;
        assert_eq!(EdwardsPoint::generator().to_montgomery(), nine);
        assert_eq!(EdwardsPoint::identity().to_montgomery(), [0u8; 32]);
        // [c]B ↦ X25519(c, 9) for clamped c ([c]B = [c mod L]B).
        for seed in [1u8, 0x42, 0xa5, 0xff] {
            let mut c = [seed; 32];
            c[0] &= 248;
            c[31] &= 127;
            c[31] |= 64;
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&c);
            let p = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(&wide));
            assert_eq!(p.to_montgomery(), crate::ec::x25519::x25519(&c, &nine));
        }
    }

    #[test]
    fn double_scalar_mul_base_vartime_matches_ct() {
        let a_pt = EdwardsPoint::mul_base(&scalar_u64(0x1234_5678));
        let cases = [
            (Scalar::ZERO, Scalar::ZERO),
            (Scalar::ONE, Scalar::ZERO),
            (Scalar::ZERO, Scalar::ONE),
            (scalar_u64(7), scalar_u64(11)),
            (
                Scalar::from_bytes_mod_order(&[0xab; 64]),
                Scalar::from_bytes_mod_order(&[0x5c; 64]),
            ),
            (Scalar::ONE.negate(), Scalar::ONE.negate()),
        ];
        for (a, b) in cases.iter() {
            let want = a_pt.mul(a).add(&EdwardsPoint::mul_base(b));
            assert_eq!(
                EdwardsPoint::double_scalar_mul_base_vartime(a, &a_pt, b),
                want
            );
        }
    }
}
