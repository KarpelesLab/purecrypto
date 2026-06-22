//! ristretto255: a prime-order group built on edwards25519 (RFC 9496).
//!
//! ristretto255 quotients the edwards25519 group by its cofactor-8 torsion,
//! yielding a clean prime-order group with canonical 32-byte encodings and no
//! cofactor pitfalls. It is the natural group for higher-level protocols such
//! as FROST, OPAQUE, and VOPRFs. This is a **stable** public module (RFC 9496
//! is a stable specification) — unlike the `hazmat-*` exposures it carries the
//! usual stability expectations.
//!
//! The implementation is built on the in-house, constant-time `curve25519`
//! backend (the same field/point arithmetic behind
//! [`ed25519`](crate::ec::ed25519)) plus the named
//! `sqrt_ratio_i` routine. Group elements are [`RistrettoPoint`]; their
//! canonical wire form is [`CompressedRistretto`]. The scalar field is the
//! shared [`Scalar`] (integers modulo the group order `L`), re-exported from
//! [`edwards25519::hazmat`](crate::ec::edwards25519::hazmat).
//!
//! # Constant-time
//!
//! Encoding, decoding, equality, and scalar multiplication are constant-time
//! with respect to secret inputs (point coordinates and scalars). Decoding
//! rejects non-canonical and invalid encodings per RFC 9496 §4.3.1; the
//! reject/accept decision is a public function of the (public) encoded bytes.

use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use crate::ec::curve25519::field::{Fe, Field};
use crate::ec::curve25519::point::Point;

#[doc(inline)]
pub use crate::ec::edwards25519::hazmat::Scalar;

/// `(1 − d²) mod p`, in Montgomery form (RFC 9496 `ONE_MINUS_D_SQ`).
const ONE_MINUS_D_SQ_HEX: &str = "029072a8b2b3e0d79994abddbe70dfe42c81a138cd5e350fe27c09c1945fc176";
/// `(d − 1)² mod p`, in Montgomery form (RFC 9496 `D_MINUS_ONE_SQ`).
const D_MINUS_ONE_SQ_HEX: &str = "5968b37af66c22414cdcd32f529b4eebd29e4a2cb01e199931ad5aaa44ed4d20";
/// `√(a·d − 1) mod p` with `a = −1` (RFC 9496 `SQRT_AD_MINUS_ONE`).
const SQRT_AD_MINUS_ONE_HEX: &str =
    "376931bf2b8348ac0f3cfcc931f5d1fdaf9d8e0c1b7854bd7e97f6a0497b2e1b";
/// `1/√(a − d) mod p` with `a = −1` (RFC 9496 `INVSQRT_A_MINUS_D`).
const INVSQRT_A_MINUS_D_HEX: &str =
    "786c8905cfaffca216c27b91fe01d8409d2f16175a4172be99c8fdaa805d40ea";

/// Parses 64 big-endian hex chars into a plain residue `Fe`.
fn fe_from_be_hex(hex: &str) -> Fe {
    super::uint_from_be_hex(hex)
}

/// The ristretto255-specific field constants, in Montgomery form, alongside the
/// shared [`Field`] backend.
struct R255 {
    f: Field,
    one_minus_d_sq: Fe,
    d_minus_one_sq: Fe,
    sqrt_ad_minus_one: Fe,
    invsqrt_a_minus_d: Fe,
}

impl R255 {
    fn new() -> Self {
        let f = Field::new();
        let one_minus_d_sq = f.to_mont(&fe_from_be_hex(ONE_MINUS_D_SQ_HEX));
        let d_minus_one_sq = f.to_mont(&fe_from_be_hex(D_MINUS_ONE_SQ_HEX));
        let sqrt_ad_minus_one = f.to_mont(&fe_from_be_hex(SQRT_AD_MINUS_ONE_HEX));
        let invsqrt_a_minus_d = f.to_mont(&fe_from_be_hex(INVSQRT_A_MINUS_D_HEX));
        R255 {
            f,
            one_minus_d_sq,
            d_minus_one_sq,
            sqrt_ad_minus_one,
            invsqrt_a_minus_d,
        }
    }
}

/// A point in the ristretto255 prime-order group.
///
/// Internally an edwards25519 point; equality is the ristretto equivalence
/// (RFC 9496 §4.3.3), **not** a raw coordinate comparison, so two
/// representatives of the same ristretto element compare equal.
#[derive(Clone, Copy, Debug)]
pub struct RistrettoPoint(Point);

/// The canonical 32-byte encoding of a [`RistrettoPoint`] (RFC 9496 §4.3.1).
#[derive(Clone, Copy, Debug)]
pub struct CompressedRistretto([u8; 32]);

impl RistrettoPoint {
    /// The identity element.
    pub fn identity() -> RistrettoPoint {
        RistrettoPoint(Field::new().identity())
    }

    /// The ristretto255 generator (the image of the edwards25519 basepoint).
    pub fn basepoint() -> RistrettoPoint {
        RistrettoPoint(Field::new().base())
    }

    /// Group addition.
    pub fn add(&self, rhs: &RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint(Field::new().point_add(&self.0, &rhs.0))
    }

    /// Group subtraction.
    pub fn sub(&self, rhs: &RistrettoPoint) -> RistrettoPoint {
        let f = Field::new();
        RistrettoPoint(f.point_add(&self.0, &f.point_negate(&rhs.0)))
    }

    /// Negation.
    pub fn negate(&self) -> RistrettoPoint {
        RistrettoPoint(Field::new().point_negate(&self.0))
    }

    /// Scalar multiplication `[scalar]·self`, constant-time.
    pub fn mul(&self, scalar: &Scalar) -> RistrettoPoint {
        let f = Field::new();
        let bytes = scalar.to_bytes();
        RistrettoPoint(f.scalar_mult(&bytes, &self.0))
    }

    /// Scalar multiplication of the generator `[scalar]·B`, constant-time.
    pub fn mul_base(scalar: &Scalar) -> RistrettoPoint {
        let f = Field::new();
        let bytes = scalar.to_bytes();
        RistrettoPoint(f.scalar_mult(&bytes, &f.base()))
    }

    /// Constant-time ristretto equality (RFC 9496 §4.3.3): two points `P`, `Q`
    /// are equal iff `X₁·Y₂ == Y₁·X₂` or `Y₁·Y₂ == X₁·X₂` (the cofactor
    /// quotient), comparing in the extended representation.
    pub fn ct_eq(&self, other: &RistrettoPoint) -> Choice {
        let f = Field::new();
        let p = &self.0;
        let q = &other.0;
        // X1*Y2 == Y1*X2  OR  Y1*Y2 == X1*X2
        let a = f.ct_eq(f.mul(p.x, q.y), f.mul(p.y, q.x));
        let b = f.ct_eq(f.mul(p.y, q.y), f.mul(p.x, q.x));
        a | b
    }

    /// Encodes to the canonical 32-byte ristretto wire form (RFC 9496 §4.3.2).
    pub fn compress(&self) -> CompressedRistretto {
        let r = R255::new();
        let f = &r.f;
        let p = &self.0;

        // u1 = (Z + Y) * (Z - Y); u2 = X * Y
        let u1 = f.mul(f.add(p.z, p.y), f.sub(p.z, p.y));
        let u2 = f.mul(p.x, p.y);

        // invsqrt = 1/sqrt(u1 * u2^2)
        let (_ok, invsqrt) = f.sqrt_ratio_i(f.one, f.mul(u1, f.sq(u2)));

        let den1 = f.mul(invsqrt, u1);
        let den2 = f.mul(invsqrt, u2);
        let z_inv = f.mul(f.mul(den1, den2), p.t);

        // Conditional rotation: if (T * z_inv) is negative, rotate.
        let ix = f.mul(p.x, f.sqrtm1);
        let iy = f.mul(p.y, f.sqrtm1);
        let enchanted_denominator = f.mul(den1, r.invsqrt_a_minus_d);

        let rotate = f.is_negative(f.mul(p.t, z_inv));

        let x = Fe::conditional_select(&iy, &p.x, rotate);
        let mut y = Fe::conditional_select(&ix, &p.y, rotate);
        let den_inv = Fe::conditional_select(&enchanted_denominator, &den2, rotate);

        // If x * z_inv is negative, negate y.
        let y_is_neg = f.is_negative(f.mul(x, z_inv));
        y = f.conditional_negate(y, y_is_neg);

        // s = |den_inv * (z - y)|
        let s = f.abs(f.mul(den_inv, f.sub(p.z, y)));

        let mut out = [0u8; 32];
        f.from_mont(&s).write_le_bytes(&mut out);
        CompressedRistretto(out)
    }

    /// The one-way map / hash-to-group (RFC 9496 §4.3.4): maps 64 uniformly
    /// random bytes to a group element. Used to build hash-to-ristretto255 from
    /// a 512-bit hash (e.g. SHA-512).
    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> RistrettoPoint {
        let mut lo = [0u8; 32];
        let mut hi = [0u8; 32];
        lo.copy_from_slice(&bytes[..32]);
        hi.copy_from_slice(&bytes[32..]);
        // Mask the high bit of each half (interpret as a field element < 2^255).
        lo[31] &= 0x7f;
        hi[31] &= 0x7f;
        let p1 = map(&lo);
        let p2 = map(&hi);
        RistrettoPoint(Field::new().point_add(&p1, &p2))
    }
}

impl PartialEq for RistrettoPoint {
    fn eq(&self, other: &RistrettoPoint) -> bool {
        bool::from(self.ct_eq(other))
    }
}
impl Eq for RistrettoPoint {}

impl CompressedRistretto {
    /// The 32-byte encoding (by value).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// The 32-byte encoding (by reference).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes without validation. Validity is checked by
    /// [`decompress`](Self::decompress).
    pub fn from_slice(bytes: &[u8; 32]) -> CompressedRistretto {
        CompressedRistretto(*bytes)
    }

    /// Decodes to a [`RistrettoPoint`], or `None` if the bytes are not a valid
    /// canonical ristretto encoding (RFC 9496 §4.3.1).
    pub fn decompress(&self) -> Option<RistrettoPoint> {
        let r = R255::new();
        let f = &r.f;
        let s_bytes = self.0;

        // Field-element canonicity: s must be a canonical, non-negative residue.
        let s_plain = Fe::from_le_bytes(&s_bytes);
        // The full 256-bit little-endian integer must already be reduced
        // (`s < p`) — constant-time, mirroring how edwards25519 point decoding
        // rejects a non-canonical `y`. This rejects encodings like `s + p` or
        // `2p − s` that would otherwise alias an existing element
        // (RFC 9496 §4.3.1 step 1).
        if !bool::from(s_plain.ct_lt(&f.p)) {
            return None;
        }
        // s must be non-negative (even). `s_plain < p` was just enforced, so
        // this is the low bit of the canonical residue.
        if s_plain.is_odd().unwrap_u8() == 1 {
            return None;
        }

        let s = f.to_mont(&s_plain);
        let ss = f.sq(s);
        let u1 = f.sub(f.one, ss); // 1 - s^2
        let u2 = f.add(f.one, ss); // 1 + s^2
        let u2_sqr = f.sq(u2);

        // v = -(d * u1^2) - u2^2
        let neg_d_u1_sq = f.neg(f.mul(f.d, f.sq(u1)));
        let v = f.sub(neg_d_u1_sq, u2_sqr);

        // invsqrt = 1/sqrt(v * u2^2); was_square required.
        let (was_square, invsqrt) = f.sqrt_ratio_i(f.one, f.mul(v, u2_sqr));

        let den_x = f.mul(invsqrt, u2);
        let den_y = f.mul(f.mul(invsqrt, den_x), v);

        let x = f.abs(f.mul(f.add(s, s), den_x));
        let y = f.mul(u1, den_y);
        let t = f.mul(x, y);

        // Reject: not a square, or t negative, or y == 0.
        let ok =
            bool::from(was_square) && !bool::from(f.is_negative(t)) && !bool::from(f.is_zero(y));
        if !ok {
            return None;
        }

        Some(RistrettoPoint(Point { x, y, z: f.one, t }))
    }
}

impl ConstantTimeEq for CompressedRistretto {
    fn ct_eq(&self, other: &CompressedRistretto) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for CompressedRistretto {
    fn eq(&self, other: &CompressedRistretto) -> bool {
        bool::from(self.ct_eq(other))
    }
}
impl Eq for CompressedRistretto {}

/// The ristretto255 Elligator map on a single field element `t < 2^255`
/// (RFC 9496 §4.3.4 `MAP`), returning an edwards25519 point.
fn map(t_bytes: &[u8; 32]) -> Point {
    let r255 = R255::new();
    let f = &r255.f;
    let t = f.to_mont(&Fe::from_le_bytes(t_bytes));

    // r = SQRT_M1 * t^2
    let rr = f.mul(f.sqrtm1, f.sq(t));
    // u = (r + 1) * ONE_MINUS_D_SQ
    let u = f.mul(f.add(rr, f.one), r255.one_minus_d_sq);
    // v = (-1 - r*d) * (r + d)
    let neg_one = f.neg(f.one);
    let v = f.mul(f.sub(neg_one, f.mul(rr, f.d)), f.add(rr, f.d));

    let (was_square, s) = f.sqrt_ratio_i(u, v);
    // s_prime = -|s * t|
    let s_prime = f.neg(f.abs(f.mul(s, t)));
    let s = Fe::conditional_select(&s, &s_prime, was_square);
    // c = was_square ? -1 : r
    let c = Fe::conditional_select(&neg_one, &rr, was_square);

    // N = c * (r - 1) * D_MINUS_ONE_SQ - v
    let n = f.sub(f.mul(f.mul(c, f.sub(rr, f.one)), r255.d_minus_one_sq), v);

    let ss = f.sq(s);
    let w0 = f.add(f.mul(s, v), f.mul(s, v)); // 2*s*v
    let w1 = f.mul(n, r255.sqrt_ad_minus_one);
    let w2 = f.sub(f.one, ss); // 1 - s^2
    let w3 = f.add(f.one, ss); // 1 + s^2

    Point {
        x: f.mul(w0, w3),
        y: f.mul(w2, w1),
        z: f.mul(w1, w3),
        t: f.mul(w0, w2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Digest, Sha512};
    use crate::test_util::from_hex;

    /// RFC 9496 Appendix A.1 — encodings of `[0]B .. [15]B`.
    const MULTIPLES: [&str; 16] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
        "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
        "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
        "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
        "f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403",
        "44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
        "903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c",
        "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
        "20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f",
        "bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
        "e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460",
        "aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
        "46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e",
        "e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
    ];

    /// RFC 9496 Appendix A.2/A.3 — encodings that MUST be rejected.
    const INVALID: [&str; 29] = [
        // Non-canonical field encodings.
        "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // Negative field elements.
        "0100000000000000000000000000000000000000000000000000000000000000",
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20",
        "c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562",
        "c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78",
        "47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24",
        "f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72",
        "87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309",
        // Non-square x^2.
        "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
        "4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
        "de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b",
        "bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042",
        "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
        "f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22",
        "8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731",
        "2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b",
        // Negative x*y.
        "3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e",
        "a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220",
        "d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e",
        "8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32",
        "32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b",
        "227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165",
        "5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e",
        "445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b",
        // s = -1, which causes y = 0.
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    /// RFC 9496 Appendix A.4 — hash-to-group labels and expected encodings.
    const HASH_LABELS: [&str; 7] = [
        "Ristretto is traditionally a short shot of espresso coffee",
        "made with the normal amount of ground coffee but extracted with",
        "about half the amount of water in the same amount of time",
        "by using a finer grind.",
        "This produces a concentrated shot of coffee per volume.",
        "Just pulling a normal shot short will produce a weaker shot",
        "and is not a Ristretto as some believe.",
    ];
    const HASH_EXPECTED: [&str; 7] = [
        "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46",
        "f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b",
        "006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826",
        "f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a",
        "ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179",
        "e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628",
        "80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065",
    ];

    #[test]
    fn basepoint_multiples_encode() {
        // [k]B compresses to the RFC vector, and decodes back.
        let mut p = RistrettoPoint::identity();
        let b = RistrettoPoint::basepoint();
        for (k, hexv) in MULTIPLES.iter().enumerate() {
            let want = from_hex::<32>(hexv);
            assert_eq!(p.compress().to_bytes(), want, "[{k}]B encode mismatch");
            let dec = CompressedRistretto::from_slice(&want)
                .decompress()
                .unwrap_or_else(|| panic!("[{k}]B decode failed"));
            assert_eq!(dec, p, "[{k}]B decode != point");
            p = p.add(&b);
        }
    }

    #[test]
    fn mul_base_matches_repeated_add() {
        let b = RistrettoPoint::basepoint();
        for k in 0u64..16 {
            let s = scalar_small(k);
            let viamul = RistrettoPoint::mul_base(&s);
            // repeated addition
            let mut acc = RistrettoPoint::identity();
            for _ in 0..k {
                acc = acc.add(&b);
            }
            assert_eq!(viamul, acc, "[{k}]B mul_base mismatch");
            assert_eq!(b.mul(&s), acc, "[{k}]B point mul mismatch");
        }
    }

    #[test]
    fn invalid_encodings_rejected() {
        for hexv in INVALID.iter() {
            let bytes = from_hex::<32>(hexv);
            assert!(
                CompressedRistretto::from_slice(&bytes)
                    .decompress()
                    .is_none(),
                "should reject {hexv}"
            );
        }
    }

    /// Non-canonical aliasing encodings must be rejected (RFC 9496 §4.3.1).
    ///
    /// For a point with even canonical `s0`, the 256-bit value `2p − s0` is
    /// also even (so it passes the sign check on the raw low bit) and is
    /// congruent to `−s0`, which decodes to the SAME point as `s0` since the
    /// decoding only uses `s²`. Without the `s < p` canonicity check this
    /// gives every group element a second wire encoding.
    #[test]
    fn noncanonical_two_p_minus_s_rejected() {
        // 2p = 2^256 − 38, little-endian.
        let mut two_p = [0xffu8; 32];
        two_p[0] = 0xda;
        for (k, hexv) in MULTIPLES.iter().enumerate() {
            let s0 = from_hex::<32>(hexv);
            // Canonical ristretto encodings are non-negative, i.e. even.
            assert_eq!(s0[0] & 1, 0, "[{k}]B encoding should be even");
            // enc = 2p − s0, little-endian schoolbook subtraction.
            let mut enc = [0u8; 32];
            let mut borrow = 0i16;
            for i in 0..32 {
                let d = two_p[i] as i16 - s0[i] as i16 - borrow;
                enc[i] = (d & 0xff) as u8;
                borrow = i16::from(d < 0);
            }
            assert_eq!(borrow, 0, "2p > s0, no final borrow");
            assert_eq!(enc[0] & 1, 0, "2p − s0 is even");
            assert!(
                CompressedRistretto::from_slice(&enc).decompress().is_none(),
                "non-canonical 2p − s encoding of [{k}]B must be rejected"
            );
        }
    }

    #[test]
    fn hash_to_group_vectors() {
        for (label, expected) in HASH_LABELS.iter().zip(HASH_EXPECTED.iter()) {
            let h = Sha512::digest(label.as_bytes());
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&h);
            let p = RistrettoPoint::from_uniform_bytes(&wide);
            assert_eq!(
                p.compress().to_bytes(),
                from_hex::<32>(expected),
                "hash-to-group mismatch for {label:?}"
            );
        }
    }

    #[test]
    fn equality_is_ristretto_not_coordinate() {
        // P and P are equal; P and [2]P are not.
        let b = RistrettoPoint::basepoint();
        let b2 = b.add(&b);
        assert_eq!(b, b);
        assert_ne!(b, b2);
        // identity round-trips and equals itself.
        let id = RistrettoPoint::identity();
        assert_eq!(id, id);
        assert_ne!(id, b);
        // The all-zero encoding is the identity.
        let zero = CompressedRistretto::from_slice(&[0u8; 32])
            .decompress()
            .unwrap();
        assert_eq!(zero, id);
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let b = RistrettoPoint::basepoint();
        let mut p = b;
        for _ in 0..20 {
            let enc = p.compress();
            let dec = enc.decompress().expect("roundtrip");
            assert_eq!(dec, p);
            assert_eq!(dec.compress().to_bytes(), enc.to_bytes());
            p = p.add(&b);
        }
    }

    #[test]
    fn group_law_with_scalars() {
        let b = RistrettoPoint::basepoint();
        let a = scalar_small(7);
        let c = scalar_small(11);
        // [a]B + [c]B == [a+c]B
        let lhs = RistrettoPoint::mul_base(&a).add(&RistrettoPoint::mul_base(&c));
        let rhs = RistrettoPoint::mul_base(&a.add(&c));
        assert_eq!(lhs, rhs);
        // [a]([c]B) == [a*c]B
        let lhs2 = b.mul(&c).mul(&a);
        let rhs2 = RistrettoPoint::mul_base(&a.mul(&c));
        assert_eq!(lhs2, rhs2);
        // P - P == identity
        assert_eq!(b.sub(&b), RistrettoPoint::identity());
    }

    fn scalar_small(k: u64) -> Scalar {
        let mut b = [0u8; 64];
        b[..8].copy_from_slice(&k.to_le_bytes());
        Scalar::from_bytes_mod_order(&b)
    }
}
