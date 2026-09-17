//! RFC 9380 hashing to BLS12-381: the suites `BLS12381G1_XMD:SHA-256_SSWU_RO_`
//! and `BLS12381G2_XMD:SHA-256_SSWU_RO_`.
//!
//! Pipeline (§3): `expand_message_xmd` with SHA-256 → `hash_to_field` with
//! `L = 64` (two elements) → the Simplified SWU map onto the isogenous curve
//! `E'` (§6.6.3, straight-line form of Appendix F.2) → the 11-isogeny (G1,
//! Appendix E.2) or 3-isogeny (G2, Appendix E.3) back to `E` → point
//! addition → cofactor clearing (`1 - x` for G1; the Budroni–Pintore
//! endomorphism formula of Appendix G.3 for G2).
//!
//! Every step is branch-free in the message-derived values: the maps use
//! masked selections (`CMOV`) and fixed exponentiations, the isogenies are
//! evaluated projectively (no inversion, the rare `x_den = 0` case selects
//! the identity by mask), and the group law is complete.

use super::constants::{
    ISO1_A, ISO1_B, ISO1_K_1, ISO1_K_2, ISO1_K_3, ISO1_K_4, ISO2_A, ISO2_B, ISO2_K_1, ISO2_K_2,
    ISO2_K_3, ISO2_K_4, SQRT_MINUS_Z1, SQRT_RATIO_C3, SQRT_RATIO_C6, SQRT_RATIO_C7, Z1, Z2,
};
use super::curve::{CurveField, Projective};
use super::fp::{Fp, P_MINUS_3_DIV_4};
use super::fp2::Fp2;
use super::g1::G1;
use super::g2::G2;
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::hash::{Digest, Sha256};

/// RFC 9380 `CMOV(a, b, c)`: `b` when `c` is true, else `a`.
#[inline]
fn cmov<T: ConditionallySelectable>(a: &T, b: &T, c: Choice) -> T {
    T::conditional_select(b, a, c)
}

/// `expand_message_xmd` (RFC 9380 §5.3.1) with SHA-256, writing
/// `out.len()` uniform bytes.
///
/// A DST longer than 255 bytes is replaced by
/// `SHA-256("H2C-OVERSIZE-DST-" || DST)` as §5.3.3 prescribes.
///
/// # Panics
///
/// If `out.len()` exceeds `255 · 32` bytes (the `ell ≤ 255` bound) or
/// `65535`, or is zero.
pub fn expand_message_xmd(msg: &[u8], dst: &[u8], out: &mut [u8]) {
    const B_IN_BYTES: usize = 32;
    const S_IN_BYTES: usize = 64;
    let len_in_bytes = out.len();
    assert!(
        len_in_bytes > 0 && len_in_bytes <= 65535,
        "expand_message_xmd: bad output length"
    );
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    assert!(ell <= 255, "expand_message_xmd: output too long");

    // DST' = DST || I2OSP(len(DST), 1), hashing oversized tags first.
    let hashed_dst: [u8; 32];
    let dst: &[u8] = if dst.len() > 255 {
        let mut h = Sha256::new();
        h.update(b"H2C-OVERSIZE-DST-");
        h.update(dst);
        hashed_dst = h.finalize();
        &hashed_dst
    } else {
        dst
    };
    let dst_len = [dst.len() as u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || 0x00 || DST')
    let mut h = Sha256::new();
    h.update(&[0u8; S_IN_BYTES]);
    h.update(msg);
    h.update(&(len_in_bytes as u16).to_be_bytes());
    h.update(&[0u8]);
    h.update(dst);
    h.update(&dst_len);
    let b0 = h.finalize();

    // b_1 = H(b_0 || 0x01 || DST'); b_i = H(strxor(b_0, b_{i-1}) || i || DST').
    let mut prev = [0u8; B_IN_BYTES];
    for i in 1..=ell {
        let mut h = Sha256::new();
        if i == 1 {
            h.update(&b0);
        } else {
            let mut x = [0u8; B_IN_BYTES];
            for (k, xk) in x.iter_mut().enumerate() {
                *xk = b0[k] ^ prev[k];
            }
            h.update(&x);
        }
        h.update(&[i as u8]);
        h.update(dst);
        h.update(&dst_len);
        prev = h.finalize();
        let off = (i - 1) * B_IN_BYTES;
        let n = core::cmp::min(B_IN_BYTES, len_in_bytes - off);
        out[off..off + n].copy_from_slice(&prev[..n]);
    }
}

/// `hash_to_field` into `Fp` with `count = 2`, `L = 64`.
fn hash_to_field_fp(msg: &[u8], dst: &[u8]) -> [Fp; 2] {
    let mut buf = [0u8; 128];
    expand_message_xmd(msg, dst, &mut buf);
    let mut e0 = [0u8; 64];
    let mut e1 = [0u8; 64];
    e0.copy_from_slice(&buf[..64]);
    e1.copy_from_slice(&buf[64..]);
    [Fp::from_bytes_wide(&e0), Fp::from_bytes_wide(&e1)]
}

/// `hash_to_field` into `Fp2` with `count = 2`, `L = 64` (`m = 2`, so 256
/// bytes of expanded output: `u_i = e_{i,0} + e_{i,1}·u`).
fn hash_to_field_fp2(msg: &[u8], dst: &[u8]) -> [Fp2; 2] {
    let mut buf = [0u8; 256];
    expand_message_xmd(msg, dst, &mut buf);
    let elem = |off: usize| {
        let mut e = [0u8; 64];
        e.copy_from_slice(&buf[off..off + 64]);
        Fp::from_bytes_wide(&e)
    };
    [Fp2::new(elem(0), elem(64)), Fp2::new(elem(128), elem(192))]
}

/// `sqrt_ratio_3mod4` (RFC 9380 F.2.1.2) for `Fp` with `Z = 11`:
/// `(true, sqrt(u/v))` when `u/v` is square, else `(false, sqrt(Z·u/v))`.
fn sqrt_ratio_fp(u: &Fp, v: &Fp) -> (Choice, Fp) {
    let tv1 = v.square();
    let tv2 = u.mul(v);
    let tv1 = tv1.mul(&tv2);
    let y1 = tv1.pow(&P_MINUS_3_DIV_4);
    let y1 = y1.mul(&tv2);
    let y2 = y1.mul(&SQRT_MINUS_Z1);
    let tv3 = y1.square();
    let tv3 = tv3.mul(v);
    let is_qr = tv3.ct_eq(u);
    let y = cmov(&y2, &y1, is_qr);
    (is_qr, y)
}

/// `sqrt_ratio` (RFC 9380 F.2.1.1) for `Fp2` with `Z = -(2 + u)`, where
/// `q - 1 = 2³·c2` (`c1 = 3`, `c4 = 7`, `c5 = 4`).
fn sqrt_ratio_fp2(u: &Fp2, v: &Fp2) -> (Choice, Fp2) {
    let mut tv1 = SQRT_RATIO_C6;
    // tv2 = v^7
    let v2 = v.square();
    let v4 = v2.square();
    let mut tv2 = v4.mul(&v2).mul(v);
    let mut tv3 = tv2.square().mul(v);
    let mut tv5 = u.mul(&tv3);
    tv5 = tv5.pow(&SQRT_RATIO_C3);
    tv5 = tv5.mul(&tv2);
    tv2 = tv5.mul(v);
    tv3 = tv5.mul(u);
    let mut tv4 = tv3.mul(&tv2);
    // tv5 = tv4^c5 = tv4^4
    tv5 = tv4.square().square();
    let is_qr = tv5.ct_eq(&Fp2::ONE);
    tv2 = tv3.mul(&SQRT_RATIO_C7);
    tv5 = tv4.mul(&tv1);
    tv3 = cmov(&tv2, &tv3, is_qr);
    tv4 = cmov(&tv5, &tv4, is_qr);
    // for i in (c1, c1-1, ..., 2) = (3, 2): tv5 = tv4^(2^(i-2))
    for i in [3usize, 2] {
        tv5 = if i == 3 { tv4.square() } else { tv4 };
        let e1 = tv5.ct_eq(&Fp2::ONE);
        tv2 = tv3.mul(&tv1);
        tv1 = tv1.square();
        tv5 = tv4.mul(&tv1);
        tv3 = cmov(&tv2, &tv3, e1);
        tv4 = cmov(&tv5, &tv4, e1);
    }
    (is_qr, tv3)
}

/// The Simplified SWU map (RFC 9380 F.2) onto `E': y² = x³ + A'x + B'`,
/// generic over the field; returns affine coordinates on `E'`.
fn map_to_curve_sswu<F, S>(
    u: &F,
    a: &F,
    b: &F,
    z: &F,
    sgn0: fn(&F) -> Choice,
    sqrt_ratio: S,
) -> (F, F)
where
    F: CurveField,
    S: Fn(&F, &F) -> (Choice, F),
{
    let tv1 = u.square();
    let tv1 = z.mul(&tv1);
    let tv2 = tv1.square();
    let tv2 = tv2.add(&tv1);
    let tv3 = tv2.add(&F::ONE);
    let tv3 = b.mul(&tv3);
    let tv4 = cmov(z, &tv2.neg(), !tv2.is_zero());
    let tv4 = a.mul(&tv4);
    let tv2 = tv3.square();
    let tv6 = tv4.square();
    let tv5 = a.mul(&tv6);
    let tv2 = tv2.add(&tv5);
    let tv2 = tv2.mul(&tv3);
    let tv6 = tv6.mul(&tv4);
    let tv5 = b.mul(&tv6);
    let tv2 = tv2.add(&tv5);
    let x = tv1.mul(&tv3);
    let (is_gx1_square, y1) = sqrt_ratio(&tv2, &tv6);
    let y = tv1.mul(u);
    let y = y.mul(&y1);
    let x = cmov(&x, &tv3, is_gx1_square);
    let y = cmov(&y, &y1, is_gx1_square);
    let e1 = sgn0(u).ct_eq(&sgn0(&y));
    let y = cmov(&y.neg(), &y, e1);
    // tv4 = A·Z or -A·tv2 is never zero, so the inverse always exists.
    let x = x.mul(&tv4.invert().unwrap_or(F::ZERO));
    (x, y)
}

/// Horner evaluation of `Σ coeffs[i]·x^i`.
fn poly<F: CurveField>(coeffs: &[F], x: &F) -> F {
    let mut acc = F::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc.mul(x).add(c);
    }
    acc
}

/// Evaluates an isogeny `(x_num/x_den, y·y_num/y_den)` projectively as
/// `(x_num·y_den : y·y_num·x_den : x_den·y_den)`, selecting the identity
/// when a denominator vanishes.
fn iso_map<F: CurveField>(
    x: &F,
    y: &F,
    kx_num: &[F],
    kx_den: &[F],
    ky_num: &[F],
    ky_den: &[F],
) -> Projective<F> {
    let xn = poly(kx_num, x);
    let xd = poly(kx_den, x);
    let yn = poly(ky_num, x);
    let yd = poly(ky_den, x);
    let z = xd.mul(&yd);
    let p = Projective {
        x: xn.mul(&yd),
        y: y.mul(&yn).mul(&xd),
        z,
    };
    Projective::conditional_select(&Projective::IDENTITY, &p, z.is_zero())
}

/// `map_to_curve` for G1: SSWU onto the 11-isogenous curve, then the isogeny.
fn map_to_curve_g1(u: &Fp) -> Projective<Fp> {
    let (x, y) = map_to_curve_sswu(u, &ISO1_A, &ISO1_B, &Z1, Fp::is_odd, sqrt_ratio_fp);
    iso_map(&x, &y, &ISO1_K_1, &ISO1_K_2, &ISO1_K_3, &ISO1_K_4)
}

/// `map_to_curve` for G2: SSWU onto the 3-isogenous curve, then the isogeny.
fn map_to_curve_g2(u: &Fp2) -> Projective<Fp2> {
    let (x, y) = map_to_curve_sswu(u, &ISO2_A, &ISO2_B, &Z2, Fp2::sgn0, sqrt_ratio_fp2);
    iso_map(&x, &y, &ISO2_K_1, &ISO2_K_2, &ISO2_K_3, &ISO2_K_4)
}

/// `hash_to_curve` for the suite `BLS12381G1_XMD:SHA-256_SSWU_RO_`
/// (RFC 9380 §8.8.1) with the given domain separation tag.
pub fn hash_to_g1(msg: &[u8], dst: &[u8]) -> G1 {
    let [u0, u1] = hash_to_field_fp(msg, dst);
    let q0 = map_to_curve_g1(&u0);
    let q1 = map_to_curve_g1(&u1);
    G1(q0.add(&q1)).clear_cofactor()
}

/// `hash_to_curve` for the suite `BLS12381G2_XMD:SHA-256_SSWU_RO_`
/// (RFC 9380 §8.8.2) with the given domain separation tag.
pub fn hash_to_g2(msg: &[u8], dst: &[u8]) -> G2 {
    let [u0, u1] = hash_to_field_fp2(msg, dst);
    let q0 = map_to_curve_g2(&u0);
    let q1 = map_to_curve_g2(&u1);
    G2(q0.add(&q1)).clear_cofactor()
}

impl G1 {
    /// Hashes a message to `G1` (RFC 9380 `BLS12381G1_XMD:SHA-256_SSWU_RO_`).
    pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> G1 {
        hash_to_g1(msg, dst)
    }
}

impl G2 {
    /// Hashes a message to `G2` (RFC 9380 `BLS12381G2_XMD:SHA-256_SSWU_RO_`).
    pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> G2 {
        hash_to_g2(msg, dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn fp(s: &str) -> Fp {
        let mut b = [0u8; 48];
        b.copy_from_slice(&unhex(s));
        Fp::from_bytes(&b).unwrap()
    }

    fn fp2(c0: &str, c1: &str) -> Fp2 {
        Fp2::new(fp(c0), fp(c1))
    }

    /// The RFC's long messages: `q128_` + 128 × `q`, `a512_` + 512 × `a`.
    fn long_msg(prefix: &str, c: u8, n: usize) -> Vec<u8> {
        let mut v = prefix.as_bytes().to_vec();
        v.extend(core::iter::repeat_n(c, n));
        v
    }

    #[test]
    fn expand_message_xmd_rfc_k1_k2() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let mut out = [0u8; 32];
        expand_message_xmd(b"", dst, &mut out);
        assert_eq!(
            out.to_vec(),
            unhex("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235")
        );
        expand_message_xmd(b"abc", dst, &mut out);
        assert_eq!(
            out.to_vec(),
            unhex("d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615")
        );
        expand_message_xmd(b"abcdef0123456789", dst, &mut out);
        assert_eq!(
            out.to_vec(),
            unhex("eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1")
        );
        // K.2: a 5-byte-over-255 DST is pre-hashed.
        let mut long = b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-".to_vec();
        long.extend(core::iter::repeat_n(b'1', 256 - long.len()));
        assert_eq!(long.len(), 256);
        expand_message_xmd(b"", &long, &mut out);
        assert_eq!(
            out.to_vec(),
            unhex("e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3")
        );
    }

    #[test]
    fn rfc_j10_1_g2_vectors() {
        // Appendix J.10.1, BLS12381G2_XMD:SHA-256_SSWU_RO_.
        let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        // Intermediate values for msg = "abc": u[0], u[1], Q0, Q1.
        let [u0, u1] = hash_to_field_fp2(b"abc", dst);
        assert_eq!(
            u0,
            fp2(
                "15f7c0aa8f6b296ab5ff9c2c7581ade64f4ee6f1bf18f55179ff44a2cf355fa53dd2a2158c5ecb17d7c52f63e7195771",
                "01c8067bf4c0ba709aa8b9abc3d1cef589a4758e09ef53732d670fd8739a7274e111ba2fcaa71b3d33df2a3a0c8529dd"
            )
        );
        assert_eq!(
            u1,
            fp2(
                "187111d5e088b6b9acfdfad078c4dacf72dcd17ca17c82be35e79f8c372a693f60a033b461d81b025864a0ad051a06e4",
                "08b852331c96ed983e497ebc6dee9b75e373d923b729194af8e72a051ea586f3538a6ebb1e80881a082fa2b24df9f566"
            )
        );
        let q0 = G2(map_to_curve_g2(&u0)).to_affine().unwrap();
        assert_eq!(
            q0.0,
            fp2(
                "12b2e525281b5f4d2276954e84ac4f42cf4e13b6ac4228624e17760faf94ce5706d53f0ca1952f1c5ef75239aeed55ad",
                "05d8a724db78e570e34100c0bc4a5fa84ad5839359b40398151f37cff5a51de945c563463c9efbdda569850ee5a53e77"
            )
        );
        assert_eq!(
            q0.1,
            fp2(
                "02eacdc556d0bdb5d18d22f23dcb086dd106cad713777c7e6407943edbe0b3d1efe391eedf11e977fac55f9b94f2489c",
                "04bbe48bfd5814648d0b9e30f0717b34015d45a861425fabc1ee06fdfce36384ae2c808185e693ae97dcde118f34de41"
            )
        );
        let q1 = G2(map_to_curve_g2(&u1)).to_affine().unwrap();
        assert_eq!(
            q1.0,
            fp2(
                "19f18cc5ec0c2f055e47c802acc3b0e40c337256a208001dde14b25afced146f37ea3d3ce16834c78175b3ed61f3c537",
                "15b0dadc256a258b4c68ea43605dffa6d312eef215c19e6474b3e101d33b661dfee43b51abbf96fee68fc6043ac56a58"
            )
        );
        let q128 = long_msg("q128_", b'q', 128);
        let a512 = long_msg("a512_", b'a', 512);
        let cases: [(&[u8], [&str; 4]); 5] = [
            (
                b"",
                [
                    "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
                    "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d",
                    "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92",
                    "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6",
                ],
            ),
            (
                b"abc",
                [
                    "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
                    "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8",
                    "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48",
                    "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16",
                ],
            ),
            (
                b"abcdef0123456789",
                [
                    "121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0",
                    "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c",
                    "05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8",
                    "0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be",
                ],
            ),
            (
                &q128,
                [
                    "19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da",
                    "0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91",
                    "14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192",
                    "09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662",
                ],
            ),
            (
                &a512,
                [
                    "01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534",
                    "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569",
                    "0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e",
                    "03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52",
                ],
            ),
        ];
        for (msg, [px0, px1, py0, py1]) in cases {
            let p = hash_to_g2(msg, dst);
            assert!(bool::from(p.is_torsion_free()));
            let (x, y) = p.to_affine().unwrap();
            assert_eq!(x, fp2(px0, px1), "msg {:?}", core::str::from_utf8(msg));
            assert_eq!(y, fp2(py0, py1));
        }
    }

    #[test]
    fn rfc_j9_1_g1_vectors() {
        // Appendix J.9.1, BLS12381G1_XMD:SHA-256_SSWU_RO_.
        let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
        let [u0, u1] = hash_to_field_fp(b"abc", dst);
        assert_eq!(
            u0,
            fp(
                "0d921c33f2bad966478a03ca35d05719bdf92d347557ea166e5bba579eea9b83e9afa5c088573c2281410369fbd32951"
            )
        );
        assert_eq!(
            u1,
            fp(
                "003574a00b109ada2f26a37a91f9d1e740dffd8d69ec0c35e1e9f4652c7dba61123e9dd2e76c655d956e2b3462611139"
            )
        );
        let q0 = G1(map_to_curve_g1(&u0)).to_affine().unwrap();
        assert_eq!(
            q0.0,
            fp(
                "125435adce8e1cbd1c803e7123f45392dc6e326d292499c2c45c5865985fd74fe8f042ecdeeec5ecac80680d04317d80"
            )
        );
        assert_eq!(
            q0.1,
            fp(
                "0e8828948c989126595ee30e4f7c931cbd6f4570735624fd25aef2fa41d3f79cfb4b4ee7b7e55a8ce013af2a5ba20bf2"
            )
        );
        let q128 = long_msg("q128_", b'q', 128);
        let a512 = long_msg("a512_", b'a', 512);
        let cases: [(&[u8], [&str; 2]); 5] = [
            (
                b"",
                [
                    "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
                    "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
                ],
            ),
            (
                b"abc",
                [
                    "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
                    "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d",
                ],
            ),
            (
                b"abcdef0123456789",
                [
                    "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
                    "03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709",
                ],
            ),
            (
                &q128,
                [
                    "15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488",
                    "1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38",
                ],
            ),
            (
                &a512,
                [
                    "082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe",
                    "05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8",
                ],
            ),
        ];
        for (msg, [px, py]) in cases {
            let p = hash_to_g1(msg, dst);
            assert!(bool::from(p.is_torsion_free()));
            let (x, y) = p.to_affine().unwrap();
            assert_eq!(x, fp(px), "msg {:?}", core::str::from_utf8(msg));
            assert_eq!(y, fp(py));
        }
    }
}
