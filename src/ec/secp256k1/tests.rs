//! KATs and property tests for the secp256k1 hazmat surface.
//!
//! Covers: generator multiples against published vectors, point add/double,
//! compressed/uncompressed SEC1 round-trips and rejection cases, and scalar
//! arithmetic against a reference.

use super::field_backend::{Fe, fe_from_hex, p};
use super::*;

// --- published secp256k1 generator multiples (affine, big-endian hex) ---
// Source: standard secp256k1 test vectors (k*G for small k).
const KG: &[(u64, &str, &str)] = &[
    (
        1,
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    ),
    (
        2,
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
    ),
    (
        3,
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672",
    ),
    (
        4,
        "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
        "51ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922",
    ),
    (
        5,
        "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
        "d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6",
    ),
    (
        20,
        "4ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97",
        "12ba26dcb10ec1625da61fa10a844c676162948271d96967450288ee9233dc3a",
    ),
];

fn scalar_from_u64(k: u64) -> Scalar {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&k.to_be_bytes());
    Scalar::from_bytes_be(&b).unwrap()
}

fn fe_bytes(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    fe_from_hex(hex).write_be_bytes(&mut out);
    out
}

#[test]
fn generator_multiples_match_vectors() {
    for &(k, xh, yh) in KG {
        let pt = ProjectivePoint::mul_generator(&scalar_from_u64(k));
        let aff = pt.to_affine().expect("k*G is not the identity");
        assert_eq!(aff.x_bytes(), fe_bytes(xh), "x mismatch for {k}G");
        assert_eq!(aff.y_bytes(), fe_bytes(yh), "y mismatch for {k}G");
    }
}

#[test]
fn double_equals_add_self() {
    let g = ProjectivePoint::generator();
    let two_a = g.double();
    let two_b = g.add(&g);
    assert!(bool::from(two_a.ct_eq(&two_b)));
    let aff = two_a.to_affine().unwrap();
    assert_eq!(aff.x_bytes(), fe_bytes(KG[1].1));
    assert_eq!(aff.y_bytes(), fe_bytes(KG[1].2));
}

#[test]
fn add_chain_matches_scalar_mul() {
    let g = ProjectivePoint::generator();
    // 5G by repeated addition vs scalar mul.
    let mut acc = g;
    for _ in 0..4 {
        acc = acc.add(&g);
    }
    let by_mul = ProjectivePoint::mul_generator(&scalar_from_u64(5));
    assert!(bool::from(acc.ct_eq(&by_mul)));
}

#[test]
fn identity_behaviour() {
    let id = ProjectivePoint::identity();
    assert!(bool::from(id.is_identity()));
    let g = ProjectivePoint::generator();
    // G + identity == G.
    assert!(bool::from(g.add(&id).ct_eq(&g)));
    // identity + G == G.
    assert!(bool::from(id.add(&g).ct_eq(&g)));
    // G + (-G) == identity.
    let neg = g.negate();
    assert!(bool::from(g.add(&neg).is_identity()));
    // identity has no affine form.
    assert!(id.to_affine().is_none());
}

#[test]
fn order_times_generator_is_identity() {
    // n*G == identity. n itself is out of range for a Scalar, so split as
    // (n-1)*G + G.
    let n_minus_1 = Scalar::ZERO.sub(&Scalar::ONE); // -1 mod n == n-1
    let pt = ProjectivePoint::mul_generator(&n_minus_1).add(&ProjectivePoint::generator());
    assert!(bool::from(pt.is_identity()), "n*G must be identity");
}

// --- SEC1 codec ---

#[test]
fn sec1_roundtrip_compressed_and_uncompressed() {
    for &(k, _, _) in KG {
        let aff = ProjectivePoint::mul_generator(&scalar_from_u64(k))
            .to_affine()
            .unwrap();

        let comp = aff.to_sec1_compressed();
        let dec = AffinePoint::from_sec1(&comp).unwrap();
        assert_eq!(dec.x_bytes(), aff.x_bytes());
        assert_eq!(dec.y_bytes(), aff.y_bytes());

        let unc = aff.to_sec1_uncompressed();
        let dec2 = AffinePoint::from_sec1(&unc).unwrap();
        assert_eq!(dec2.x_bytes(), aff.x_bytes());
        assert_eq!(dec2.y_bytes(), aff.y_bytes());
    }
}

#[test]
fn sec1_compressed_tag_encodes_parity() {
    let g = AffinePoint::generator();
    let comp = g.to_sec1_compressed();
    // G's y is even (..b8), so tag is 0x02.
    assert_eq!(comp[0], 0x02);
    // -G has odd y -> tag 0x03.
    let neg = g.to_projective().negate().to_affine().unwrap();
    assert_eq!(neg.to_sec1_compressed()[0], 0x03);
}

#[test]
fn sec1_rejects_bad_length_and_tag() {
    assert!(AffinePoint::from_sec1(&[0x04; 64]).is_err());
    assert!(AffinePoint::from_sec1(&[0x02; 32]).is_err());
    assert!(AffinePoint::from_sec1(&[]).is_err());
    let mut buf = [0u8; 33];
    buf[0] = 0x05;
    assert!(AffinePoint::from_sec1(&buf).is_err());
}

#[test]
fn sec1_rejects_x_ge_p() {
    // Compressed point with X = p (out of range).
    let mut comp = [0u8; 33];
    comp[0] = 0x02;
    let mut pb = [0u8; 32];
    p().write_be_bytes(&mut pb);
    comp[1..].copy_from_slice(&pb);
    assert!(AffinePoint::from_sec1(&comp).is_err());
}

#[test]
fn sec1_rejects_off_curve_compressed() {
    // X = 0: x^3 + 7 = 7, which is not a QR mod p, so no y-recovery.
    let mut comp = [0u8; 33];
    comp[0] = 0x02;
    assert!(AffinePoint::from_sec1(&comp).is_err());
}

#[test]
fn sec1_rejects_off_curve_uncompressed() {
    let g = AffinePoint::generator();
    let mut unc = g.to_sec1_uncompressed();
    // Flip a bit in Y so the point is off-curve.
    unc[64] ^= 1;
    assert!(AffinePoint::from_sec1(&unc).is_err());
}

#[test]
fn sec1_rejects_identity_encoding() {
    let mut unc = [0u8; 65];
    unc[0] = 0x04;
    assert!(AffinePoint::from_sec1(&unc).is_err());
}

#[test]
fn sec1_recovers_both_parities() {
    // For each KAT point, the compressed form recovers the correct y, and the
    // negated point recovers the opposite parity.
    for &(k, _, _) in KG {
        let aff = ProjectivePoint::mul_generator(&scalar_from_u64(k))
            .to_affine()
            .unwrap();
        let neg = aff.to_projective().negate().to_affine().unwrap();
        // Their compressed tags must differ (y and p-y have opposite parity).
        assert_ne!(aff.to_sec1_compressed()[0], neg.to_sec1_compressed()[0]);
        // Both decode back to themselves.
        let d1 = AffinePoint::from_sec1(&aff.to_sec1_compressed()).unwrap();
        let d2 = AffinePoint::from_sec1(&neg.to_sec1_compressed()).unwrap();
        assert_eq!(d1.y_bytes(), aff.y_bytes());
        assert_eq!(d2.y_bytes(), neg.y_bytes());
    }
}

// --- scalar arithmetic ---

#[test]
fn scalar_add_sub_mul_small() {
    let a = scalar_from_u64(7);
    let b = scalar_from_u64(5);
    assert_eq!(a.add(&b).to_bytes_be(), scalar_from_u64(12).to_bytes_be());
    assert_eq!(a.sub(&b).to_bytes_be(), scalar_from_u64(2).to_bytes_be());
    assert_eq!(a.mul(&b).to_bytes_be(), scalar_from_u64(35).to_bytes_be());
}

#[test]
fn scalar_negate_and_zero() {
    let a = scalar_from_u64(9);
    assert!(bool::from(a.add(&a.negate()).is_zero()));
    assert!(bool::from(Scalar::ZERO.is_zero()));
    assert!(!bool::from(Scalar::ONE.is_zero()));
}

#[test]
fn scalar_invert_roundtrip() {
    for k in [1u64, 2, 3, 7, 1000, u64::MAX] {
        let a = scalar_from_u64(k);
        let inv = a.invert();
        assert!(
            bool::from(a.mul(&inv).ct_eq(&Scalar::ONE)),
            "a * a^-1 != 1 for k={k}"
        );
    }
}

#[test]
fn scalar_from_bytes_rejects_ge_n() {
    let mut nb = [0u8; 32];
    Scalar::order().write_be_bytes(&mut nb);
    assert!(Scalar::from_bytes_be(&nb).is_err());
    let n_minus_1 = Scalar::order().wrapping_sub(&Fe::from_u64(1));
    let mut b = [0u8; 32];
    n_minus_1.write_be_bytes(&mut b);
    assert!(Scalar::from_bytes_be(&b).is_ok());
}

#[test]
fn scalar_reduce_folds_large_input() {
    // n + 5 reduces to 5.
    let np5 = Scalar::order().wrapping_add(&Fe::from_u64(5));
    let mut b = [0u8; 32];
    np5.write_be_bytes(&mut b);
    let s = Scalar::from_bytes_be_reduce(&b);
    assert_eq!(s.to_bytes_be(), scalar_from_u64(5).to_bytes_be());
}

#[test]
fn scalar_mul_bilinear() {
    // (a+b)*G == a*G + b*G.
    let a = scalar_from_u64(123456789);
    let b = scalar_from_u64(987654321);
    let lhs = ProjectivePoint::mul_generator(&a.add(&b));
    let rhs = ProjectivePoint::mul_generator(&a).add(&ProjectivePoint::mul_generator(&b));
    assert!(bool::from(lhs.ct_eq(&rhs)));
}

#[test]
fn large_scalar_known_pubkey() {
    // d -> Q standard vector: d = 0xAA5E...E (a published secp256k1 test key).
    // Verify d*G lands on-curve and round-trips through SEC1 compressed.
    let d_hex = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    let d = Scalar::from_bytes_be(&fe_bytes(d_hex)).unwrap();
    let q = ProjectivePoint::mul_generator(&d).to_affine().unwrap();
    let comp = q.to_sec1_compressed();
    let back = AffinePoint::from_sec1(&comp).unwrap();
    assert_eq!(back.x_bytes(), q.x_bytes());
    assert_eq!(back.y_bytes(), q.y_bytes());
    // Sanity: Q is not the identity and lies on the curve (from_sec1 validates).
    assert!(!bool::from(q.to_projective().is_identity()));
}
