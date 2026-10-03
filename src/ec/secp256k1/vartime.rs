//! **Variable-time** multi-scalar multiplication for secp256k1 verification.
//!
//! # Warning — public inputs only
//!
//! Everything in this module branches on, and indexes tables by, the scalar
//! digits. It is only sound when every scalar and point is public, which is
//! exactly the verification setting (ECDSA / BIP340 verify, public-key
//! recovery, the zkp proof verifiers): signature, message digest, public keys
//! and proof transcripts are all published. Signing, key generation, ECDH and
//! every prover must keep using the constant-time [`Point::mul`] ladder.
//!
//! Strategy: every scalar is first split with the GLV endomorphism
//! `λ·(x, y) = (β·x, y)` into two halves of at most 128 bits,
//! `k ≡ k₁ + k₂·λ (mod n)`, so a term `k·P` becomes `k₁·P + k₂·λP`, where
//! `λP` costs three field multiplications per table entry. The half-size
//! terms are then interleaved by Straus' method over width-5 wNAF digits:
//! each gets the eight odd multiples `[1]P, [3]P, …, [15]P`, one shared run
//! of ~128 doublings serves them all, and a term costs an addition only at
//! its nonzero digits (on average one in six). For `a·G + b·Q` that is ~128
//! doublings and ~86 additions, against ~512 doublings and ~158 additions for
//! two constant-time 4-bit-window ladders. No static table is used.

use super::Scalar;
use super::field_backend::{Fe, FieldBackend, fe_from_hex};
use super::group::Point;
use crate::ct::ConstantTimeLess;

/// `β`, a primitive cube root of unity mod `p`: `(x, y) ↦ (β·x, y)` is the
/// endomorphism acting as multiplication by [`LAMBDA`].
const BETA: Fe = fe_from_hex("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");

/// `λ`, the matching cube root of unity mod `n`.
const LAMBDA: Fe = fe_from_hex("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");

/// `−b₁ mod n` and `−b₂ mod n` for the short lattice basis
/// `(a₁, b₁) = (0x3086…eb15, −0xe443…e4c3)`, `(a₂, b₂) = (0x1_14ca…4cfd8, a₁)`
/// of `{(x, y) : x + y·λ ≡ 0 (mod n)}` (the libsecp256k1 constants).
const MINUS_B1: Fe =
    fe_from_hex("00000000000000000000000000000000e4437ed6010e88286f547fa90abfe4c3");
const MINUS_B2: Fe =
    fe_from_hex("fffffffffffffffffffffffffffffffe8a280ac50774346dd765cda83db1562c");

/// `round(2³⁸⁴·b₂ / n)` and `round(2³⁸⁴·(−b₁) / n)`: `round(k·gᵢ / 2³⁸⁴)`
/// approximates the Babai rounding coefficients of `k` in that basis.
const G1: Fe = fe_from_hex("3086d221a7d46bcde86c90e49284eb153daa8a1471e8ca7fe893209a45dbb031");
const G2: Fe = fe_from_hex("e4437ed6010e88286f547fa90abfe4c4221208ac9df506c61571b4ae8ac47f71");

/// `round(k·g / 2³⁸⁴)` for 256-bit `k` and `g`.
fn mul_shift_384(k: &Fe, g: &Fe) -> Fe {
    let (k, g) = (k.as_limbs(), g.as_limbs());
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let acc = t[i + j] as u128 + (k[i] as u128) * (g[j] as u128) + carry;
            t[i + j] = acc as u64;
            carry = acc >> 64;
        }
        t[i + 4] = carry as u64;
    }
    // Bits 384.. plus the rounding bit 383 (no overflow: the quotient is
    // < 2¹²⁸ since g < 2²⁵⁶ and k < 2²⁵⁶).
    let round = t[5] >> 63;
    let (lo, c) = t[6].overflowing_add(round);
    Fe::from_limbs([lo, t[7] + c as u64, 0, 0])
}

/// `n/2`, the threshold above which a residue is treated as negative.
fn half_order() -> Fe {
    Scalar::ORDER.shr1()
}

/// GLV split of `k < n`: returns `(k₁, k₂)` as `(magnitude, is_negative)`
/// pairs with `k ≡ ±|k₁| ± |k₂|·λ (mod n)` and both magnitudes `< 2¹²⁸`.
/// **Variable time** (public scalars only).
fn split_lambda(k: &Fe) -> [(Fe, bool); 2] {
    let m = &Scalar::MODULUS;
    let c1 = mul_shift_384(k, &G1);
    let c2 = mul_shift_384(k, &G2);
    let k2 = m.add_mod(&m.mul_mod(&c1, &MINUS_B1), &m.mul_mod(&c2, &MINUS_B2));
    let k1 = m.sub_mod(k, &m.mul_mod(&k2, &LAMBDA));
    let half = half_order();
    [k1, k2].map(|v| {
        if bool::from(half.ct_lt(&v)) {
            (Scalar::ORDER.wrapping_sub(&v), true)
        } else {
            (v, false)
        }
    })
}

/// Most terms any caller combines at once (`a·P + b·Q`).
const MAX_TERMS: usize = 2;

/// The wNAF window width: digits are odd and in `[−15, 15]`.
const WINDOW: u32 = 5;

/// Number of odd multiples per table: `[1]P, [3]P, …, [2^(WINDOW−1) − 1]P`.
const TABLE_LEN: usize = 1 << (WINDOW - 2);

/// Digit positions of a 256-bit scalar's wNAF (the top carry can spill into
/// position 256).
const NAF_LEN: usize = 257;

/// `count <= WINDOW` bits of `k` starting at bit `pos` (bits past 255 read as
/// zero).
#[inline]
fn bits(k: &[u64; 4], pos: usize, count: u32) -> u32 {
    let limb = pos / 64;
    let shift = pos % 64;
    let mut v = k[limb] >> shift;
    if shift + count as usize > 64 && limb + 1 < 4 {
        v |= k[limb + 1] << (64 - shift);
    }
    (v as u32) & ((1u32 << count) - 1)
}

/// Width-5 wNAF recoding of `k` (libsecp256k1's `ecmult_wnaf`): every nonzero
/// digit is odd with `|d| <= 15`, and any two nonzero digits are at least five
/// positions apart. Returns the number of digit positions in use (one past the
/// highest nonzero digit; `0` for `k = 0`). **Variable time** in `k`.
fn wnaf(k: &[u64; 4], naf: &mut [i8; NAF_LEN]) -> usize {
    let mut carry = 0u32;
    let mut bit = 0usize;
    let mut len = 0usize;
    while bit < 256 {
        // A digit starts only where the (carry-adjusted) bit is set, which
        // makes `word` below odd.
        if bits(k, bit, 1) == carry {
            bit += 1;
            continue;
        }
        let now = WINDOW.min((256 - bit) as u32);
        let mut word = bits(k, bit, now) as i32 + carry as i32;
        carry = ((word >> (WINDOW - 1)) & 1) as u32;
        word -= (carry as i32) << WINDOW;
        naf[bit] = word as i8;
        len = bit + 1;
        bit += now as usize;
    }
    if carry != 0 {
        naf[256] = 1;
        len = NAF_LEN;
    }
    len
}

/// The odd multiples `[1]P, [3]P, …, [15]P`.
fn odd_multiples<F: FieldBackend>(f: &F, p: &Point) -> [Point; TABLE_LEN] {
    let two_p = Point::double(f, p);
    let mut table = [*p; TABLE_LEN];
    for i in 1..TABLE_LEN {
        table[i] = Point::add(f, &table[i - 1], &two_p);
    }
    table
}

/// **Variable-time** `Σ kᵢ·Pᵢ` over `N <= 2` public terms (scalars reduced
/// mod `n`), by a GLV split of each scalar and Straus' method over width-5
/// wNAF digits.
pub(crate) fn multi_mul<F: FieldBackend, const N: usize>(
    f: &F,
    terms: [(&Scalar, &Point); N],
) -> Point {
    const { assert!(N <= MAX_TERMS) };
    let mut nafs = [[0i8; NAF_LEN]; 2 * MAX_TERMS];
    let mut tables = [[Point::identity(f); TABLE_LEN]; 2 * MAX_TERMS];
    let mut top = 0;
    let beta = BETA;
    for (t, (k, p)) in terms.iter().enumerate() {
        let [(k1, neg1), (k2, neg2)] = split_lambda(&k.0);
        let len1 = wnaf(k1.as_limbs(), &mut nafs[2 * t]);
        let len2 = wnaf(k2.as_limbs(), &mut nafs[2 * t + 1]);
        if len1.max(len2) == 0 {
            continue;
        }
        top = top.max(len1).max(len2);
        let base = if neg1 { Point::negate(f, p) } else { **p };
        let odd = odd_multiples(f, &base);
        // λ·(X : Y : Z) = (β·X : Y : Z); flipping the sign of k₂ relative to
        // k₁ is a negation of Y.
        let mut odd_lambda = odd;
        for e in &mut odd_lambda {
            e.x = f.mul(&e.x, &beta);
            if neg1 != neg2 {
                e.y = f.negate(&e.y);
            }
        }
        tables[2 * t] = odd;
        tables[2 * t + 1] = odd_lambda;
    }

    let mut acc = Point::identity(f);
    for i in (0..top).rev() {
        // Doubling the identity is a no-op; skip it until the first digit.
        if i + 1 < top {
            acc = Point::double(f, &acc);
        }
        for t in 0..2 * N {
            let d = nafs[t][i];
            if d > 0 {
                acc = Point::add(f, &acc, &tables[t][(d as usize) / 2]);
            } else if d < 0 {
                let neg = Point::negate(f, &tables[t][((-d) as usize) / 2]);
                acc = Point::add(f, &acc, &neg);
            }
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::secp256k1::Scalar;
    use crate::ec::secp256k1::field_backend::Secp256k1Field;

    struct SplitMix64(u64);
    impl SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn limbs(&mut self) -> [u64; 4] {
            [
                self.next_u64(),
                self.next_u64(),
                self.next_u64(),
                self.next_u64(),
            ]
        }
    }

    /// The recoding reconstructs `k` exactly, with the wNAF shape.
    #[test]
    fn wnaf_reconstructs_scalar() {
        let mut rng = SplitMix64(0x77AF_0005);
        let mut cases = [[0u64; 4]; 2_006];
        cases[1] = [1, 0, 0, 0];
        cases[2] = [u64::MAX; 4];
        cases[3] = [31, 0, 0, 0];
        cases[4] = [0, 0, 0, 1 << 63];
        cases[5] = [u64::MAX, 0, u64::MAX, 0];
        for c in &mut cases[6..] {
            *c = rng.limbs();
        }
        for k in &cases {
            let mut naf = [0i8; NAF_LEN];
            let len = wnaf(k, &mut naf);
            // Σ dᵢ·2ⁱ, in 320-bit two's complement over five limbs.
            let mut acc = [0u64; 5];
            let mut last: Option<usize> = None;
            for (i, &d) in naf.iter().enumerate() {
                if d == 0 {
                    continue;
                }
                assert!(d % 2 != 0 && d.abs() <= 15, "bad digit {d}");
                if let Some(l) = last {
                    assert!(i - l >= WINDOW as usize, "digits too close");
                }
                last = Some(i);
                assert!(i < len);
                // Add sign(d)·|d|·2^i.
                let mut term = [0u64; 5];
                let mag = (d.unsigned_abs() as u128) << (i % 64);
                term[i / 64] = mag as u64;
                if i / 64 + 1 < 5 {
                    term[i / 64 + 1] = (mag >> 64) as u64;
                }
                if d < 0 {
                    let mut borrow = 0u128;
                    for j in 0..5 {
                        let t = (acc[j] as u128).wrapping_sub(term[j] as u128 + borrow);
                        acc[j] = t as u64;
                        borrow = (t >> 64) & 1;
                    }
                } else {
                    let mut carry = 0u128;
                    for j in 0..5 {
                        let t = acc[j] as u128 + term[j] as u128 + carry;
                        acc[j] = t as u64;
                        carry = t >> 64;
                    }
                }
            }
            assert_eq!(acc, [k[0], k[1], k[2], k[3], 0], "k={k:x?}");
            assert_eq!(len, last.map_or(0, |l| l + 1));
        }
    }

    /// A pseudo-random scalar mod `n`.
    fn rand_scalar(rng: &mut SplitMix64) -> Scalar {
        let mut b = [0u8; 32];
        Fe::from_limbs(rng.limbs()).write_be_bytes(&mut b);
        Scalar::from_bytes_be_reduce(&b)
    }

    /// Scalars at the split's boundaries: 0, 1, n − 1, n/2, n/2 + 1, λ, 2¹²⁸.
    fn edge_scalars() -> [Scalar; 7] {
        let n = Scalar::ORDER;
        let s = |v: Fe| Scalar(v);
        [
            Scalar::ZERO,
            Scalar::ONE,
            s(n.wrapping_sub(&Fe::ONE)),
            s(half_order()),
            s(half_order().wrapping_add(&Fe::ONE)),
            s(LAMBDA),
            s(Fe::from_limbs([0, 0, 1, 0])),
        ]
    }

    /// `k ≡ ±k₁ ± k₂·λ (mod n)` with both halves below 2¹²⁸.
    #[test]
    fn split_lambda_recombines() {
        let m = &Scalar::MODULUS;
        let mut rng = SplitMix64(0x61F0_0003);
        let check = |k: &Scalar| {
            let [(k1, n1), (k2, n2)] = split_lambda(&k.0);
            assert!(
                k1.as_limbs()[2] == 0 && k1.as_limbs()[3] == 0,
                "k1 wide: {k1:x?}"
            );
            assert!(
                k2.as_limbs()[2] == 0 && k2.as_limbs()[3] == 0,
                "k2 wide: {k2:x?}"
            );
            let signed = |v: Fe, neg: bool| if neg { m.sub_mod(&Fe::ZERO, &v) } else { v };
            let back = m.add_mod(&signed(k1, n1), &m.mul_mod(&signed(k2, n2), &LAMBDA));
            assert_eq!(back.as_limbs(), k.0.as_limbs());
        };
        for k in &edge_scalars() {
            check(k);
        }
        for _ in 0..20_000 {
            check(&rand_scalar(&mut rng));
        }
    }

    /// The endomorphism constants agree: `λ·G = (β·Gx, Gy)`.
    #[test]
    fn lambda_acts_as_beta() {
        let f = Secp256k1Field::new();
        let g = crate::ec::secp256k1::ProjectivePoint::generator().0;
        let lg = Point::mul(&f, LAMBDA.as_limbs(), &g);
        let bg = Point {
            x: f.mul(&g.x, &BETA),
            y: g.y,
            z: g.z,
        };
        assert!(bool::from(lg.ct_eq(&f, &bg)));
    }

    /// `multi_mul` agrees with the constant-time ladder on random terms and on
    /// the degenerate ones (zero scalars, the identity, `P == Q`, `Q == −P`).
    #[test]
    fn multi_mul_matches_ladder() {
        let f = Secp256k1Field::new();
        let g = crate::ec::secp256k1::ProjectivePoint::generator().0;
        let mut rng = SplitMix64(0x5EC9_0002);
        let mut pts = [g; 10];
        pts[1] = Point::identity(&f);
        pts[2] = Point::negate(&f, &g);
        for p in &mut pts[3..] {
            *p = Point::mul(&f, rand_scalar(&mut rng).0.as_limbs(), &g);
        }
        let edges = edge_scalars();
        let mut scalars = [
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
        ];
        for (i, k) in scalars.iter_mut().enumerate() {
            *k = if i < edges.len() {
                edges[i].clone()
            } else {
                rand_scalar(&mut rng)
            };
        }
        let ladder = |k: &Scalar, p: &Point| Point::mul(&f, k.0.as_limbs(), p);
        for (i, a) in scalars.iter().enumerate() {
            let b = &scalars[(i * 7 + 3) % scalars.len()];
            for p in &pts {
                for q in [&pts[(i + 2) % pts.len()], p] {
                    let want = Point::add(&f, &ladder(a, p), &ladder(b, q));
                    let got = multi_mul(&f, [(a, p), (b, q)]);
                    assert!(bool::from(got.ct_eq(&f, &want)), "i={i}");
                    let one = multi_mul(&f, [(a, p)]);
                    assert!(bool::from(one.ct_eq(&f, &ladder(a, p))));
                }
            }
        }
        // a·G + (n − a)·G is the identity.
        let a = rand_scalar(&mut rng);
        let got = multi_mul(&f, [(&a, &g), (&a.negate(), &g)]);
        assert!(bool::from(got.is_identity()));
    }
}
