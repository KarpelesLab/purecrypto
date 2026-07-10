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
//!   with RFC 8032 32-byte compression.

use crate::ct::{Choice, ConstantTimeEq, ConstantTimeLess};
use crate::ec::curve25519::field::{Field, ScalarInt};
use crate::ec::curve25519::point::Point;
use crate::ec::curve25519::scalar::{
    scalar_add, scalar_invert, scalar_mul, scalar_negate, scalar_reduce_wide, scalar_sub,
};

/// An integer modulo the edwards25519 group order
/// `L = 2²⁵² + 27742317777372353535851937790883648493`.
///
/// Stored as a canonical residue in `[0, L)`. This is the shared scalar field
/// for both edwards25519 and [`crate::ec::ristretto255`]. The value is wiped on
/// drop with the crate's `black_box`-guarded best-effort pattern.
///
/// Because the value is zeroized on drop, `Scalar` is [`Clone`] but not
/// `Copy`; pass it by reference or clone it explicitly.
#[derive(Clone)]
pub struct Scalar(pub(crate) ScalarInt);

impl Drop for Scalar {
    fn drop(&mut self) {
        // Best-effort wipe; the black_box barrier keeps LLVM from eliding it.
        self.0 = ScalarInt::ZERO;
        let _ = core::hint::black_box(&self.0);
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
        let f = Field::new();
        Scalar(scalar_reduce_wide(bytes, &f.l8))
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
        let f = Field::new();
        Scalar(scalar_mul(&self.0, &rhs.0, &f.l8))
    }

    /// `-self (mod L)`.
    pub fn negate(&self) -> Scalar {
        let f = Field::new();
        Scalar(scalar_negate(&self.0, &f.l))
    }

    /// The multiplicative inverse `self⁻¹ (mod L)`, constant-time via Fermat
    /// (`self^(L-2)`). The inverse of `0` is `0`.
    pub fn invert(&self) -> Scalar {
        let f = Field::new();
        Scalar(scalar_invert(&self.0, &f.l, &f.l8))
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

/// A point on the edwards25519 curve (the full group, cofactor 8).
///
/// Compression / decompression follow RFC 8032 §5.1.2–5.1.3 (32 bytes, sign
/// bit in the top bit of the last byte).
#[derive(Clone, Copy, Debug)]
pub struct EdwardsPoint(pub(crate) Point);

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
        let bytes = scalar_bytes(&scalar.0);
        EdwardsPoint(f.scalar_mult(&bytes, &self.0))
    }

    /// `[scalar]·B` (scalar times the basepoint), constant-time (precomputed
    /// fixed-base comb).
    pub fn mul_base(scalar: &Scalar) -> EdwardsPoint {
        let f = Field::new();
        let bytes = scalar_bytes(&scalar.0);
        EdwardsPoint(f.mul_base(&bytes))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curve25519::field::Field;

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
}
