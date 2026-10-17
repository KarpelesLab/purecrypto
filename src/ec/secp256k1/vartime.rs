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
//! terms are then interleaved by Straus' method over wNAF digits: one shared
//! run of ~128 doublings serves them all, and a term costs an addition only
//! at its nonzero digits. A runtime term gets the eight odd multiples
//! `[1]P, [3]P, …, [15]P` (width 5, one addition per ~6 digits); with the
//! `secp256k1-table` feature the generator term instead reads the 128
//! precomputed affine odd multiples `[1]G … [255]G` and their `λ`-images
//! ([`super::gtable_vartime`], width 8, one *mixed* addition per ~9 digits
//! and no table to build). For `a·G + b·Q` that is ~128 doublings and ~70
//! additions, against ~512 doublings and ~158 additions for two
//! constant-time 4-bit-window ladders.

use super::Scalar;
use super::field_backend::{Fe, FieldBackend};
use super::glv::{BETA, split_residues};
use super::group::Point;
use crate::ct::ConstantTimeLess;

/// `n/2`, the threshold above which a residue is treated as negative.
fn half_order() -> Fe {
    Scalar::ORDER.shr1()
}

/// GLV split of `k < n`: returns `(k₁, k₂)` as `(magnitude, is_negative)`
/// pairs with `k ≡ ±|k₁| ± |k₂|·λ (mod n)` and both magnitudes `< 2¹²⁸`.
/// **Variable time** (public scalars only): the sign normalisation of the
/// constant-time [`split_residues`] branches.
fn split_lambda(k: &Fe) -> [(Fe, bool); 2] {
    let (k1, k2) = split_residues(k);
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

/// The wNAF window width of a term with a runtime table: digits are odd and
/// in `[−15, 15]`.
const WINDOW: u32 = 5;

/// Number of odd multiples per runtime table: `[1]P, [3]P, …, [15]P`.
const TABLE_LEN: usize = 1 << (WINDOW - 2);

/// The wNAF window width of the generator term over the static tables:
/// digits are odd and in `[−255, 255]`.
#[cfg(feature = "secp256k1-table")]
const GEN_WINDOW: u32 = 8;

/// Digit positions of a 256-bit scalar's wNAF (the top carry can spill into
/// position 256).
const NAF_LEN: usize = 257;

/// `count <= 8` bits of `k` starting at bit `pos` (bits past 255 read as
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

/// Width-`W` wNAF recoding of `k` (libsecp256k1's `ecmult_wnaf`): every
/// nonzero digit is odd with `|d| < 2^(W−1)`, and any two nonzero digits are
/// at least `W` positions apart. Returns the number of digit positions in
/// use (one past the highest nonzero digit; `0` for `k = 0`). **Variable
/// time** in `k`.
fn wnaf<const W: u32>(k: &[u64; 4], naf: &mut [i16; NAF_LEN]) -> usize {
    const { assert!(W >= 2 && W <= 8) };
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
        let now = W.min((256 - bit) as u32);
        let mut word = bits(k, bit, now) as i32 + carry as i32;
        carry = ((word >> (W - 1)) & 1) as u32;
        word -= (carry as i32) << W;
        naf[bit] = word as i16;
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

/// The runtime tables of a term `k·P`: the odd multiples of `±P` and of
/// `±λP` (`λ·(X : Y : Z) = (β·X : Y : Z)`; flipping the sign of `k₂`
/// relative to `k₁` is a negation of `Y`), with the signs of the split
/// halves folded in. Returns the digit counts of the two halves.
fn term_tables<F: FieldBackend>(
    f: &F,
    k: &Scalar,
    p: &Point,
    nafs: &mut [[i16; NAF_LEN]; 2],
    tables: &mut [[Point; TABLE_LEN]; 2],
) -> usize {
    let [(k1, neg1), (k2, neg2)] = split_lambda(&k.0);
    let len1 = wnaf::<WINDOW>(k1.as_limbs(), &mut nafs[0]);
    let len2 = wnaf::<WINDOW>(k2.as_limbs(), &mut nafs[1]);
    if len1.max(len2) == 0 {
        return 0;
    }
    let base = if neg1 { Point::negate(f, p) } else { *p };
    let odd = odd_multiples(f, &base);
    let mut odd_lambda = odd;
    for e in &mut odd_lambda {
        e.x = f.mul(&e.x, &BETA);
        if neg1 != neg2 {
            e.y = f.negate(&e.y);
        }
    }
    tables[0] = odd;
    tables[1] = odd_lambda;
    len1.max(len2)
}

/// `acc + d·P` for the wNAF digit `d` over the odd-multiple table of `P`
/// (`table[i] = [2i + 1]P`); a zero digit is a no-op.
#[inline]
fn add_digit<F: FieldBackend>(f: &F, acc: &Point, table: &[Point; TABLE_LEN], d: i16) -> Point {
    if d > 0 {
        Point::add(f, acc, &table[(d as usize) / 2])
    } else if d < 0 {
        let neg = Point::negate(f, &table[(d.unsigned_abs() as usize) / 2]);
        Point::add(f, acc, &neg)
    } else {
        *acc
    }
}

/// **Variable-time** `Σ kᵢ·Pᵢ` over `N <= 2` public terms (scalars reduced
/// mod `n`), by a GLV split of each scalar and Straus' method over width-5
/// wNAF digits.
pub(crate) fn multi_mul<F: FieldBackend, const N: usize>(
    f: &F,
    terms: [(&Scalar, &Point); N],
) -> Point {
    const { assert!(N <= MAX_TERMS) };
    let mut nafs = [[[0i16; NAF_LEN]; 2]; MAX_TERMS];
    let mut tables = [[[Point::identity(f); TABLE_LEN]; 2]; MAX_TERMS];
    let mut top = 0;
    for (t, (k, p)) in terms.iter().enumerate() {
        top = top.max(term_tables(f, k, p, &mut nafs[t], &mut tables[t]));
    }

    let mut acc = Point::identity(f);
    for i in (0..top).rev() {
        // Doubling the identity is a no-op; skip it until the first digit.
        if i + 1 < top {
            acc = Point::double(f, &acc);
        }
        for t in 0..N {
            acc = add_digit(f, &acc, &tables[t][0], nafs[t][0][i]);
            acc = add_digit(f, &acc, &tables[t][1], nafs[t][1][i]);
        }
    }
    acc
}

/// **Variable-time** `a·G + b·Q` for public `a`, `b`, `Q`: the generator
/// term over the static width-8 tables of odd multiples of `G` and `λG`
/// (affine entries, complete mixed additions, nothing to precompute), the
/// `Q` term over runtime width-5 tables, both interleaved in one doubling
/// chain.
#[cfg(feature = "secp256k1-table")]
pub(crate) fn generator_double<F: FieldBackend>(f: &F, a: &Scalar, b: &Scalar, q: &Point) -> Point {
    use super::comb::affine_entry;
    use super::gtable_vartime::{SECP256K1_G_ODD_TABLE, SECP256K1_LAMBDA_G_ODD_TABLE};

    let [(a1, neg_a1), (a2, neg_a2)] = split_lambda(&a.0);
    let mut naf_a = [[0i16; NAF_LEN]; 2];
    let len_a1 = wnaf::<GEN_WINDOW>(a1.as_limbs(), &mut naf_a[0]);
    let len_a2 = wnaf::<GEN_WINDOW>(a2.as_limbs(), &mut naf_a[1]);
    let neg_a = [neg_a1, neg_a2];
    let gen_tables = [&SECP256K1_G_ODD_TABLE, &SECP256K1_LAMBDA_G_ODD_TABLE];

    let mut naf_b = [[0i16; NAF_LEN]; 2];
    let mut tables_b = [[Point::identity(f); TABLE_LEN]; 2];
    let len_b = term_tables(f, b, q, &mut naf_b, &mut tables_b);

    let top = len_a1.max(len_a2).max(len_b);
    let mut acc = Point::identity(f);
    for i in (0..top).rev() {
        if i + 1 < top {
            acc = Point::double(f, &acc);
        }
        for t in 0..2 {
            let d = naf_a[t][i];
            if d != 0 {
                let (x, y) = affine_entry(&gen_tables[t][(d.unsigned_abs() as usize) / 2]);
                let y = if (d < 0) != neg_a[t] { f.negate(&y) } else { y };
                acc = Point::add_mixed(f, &acc, &x, &y);
            }
        }
        acc = add_digit(f, &acc, &tables_b[0], naf_b[0][i]);
        acc = add_digit(f, &acc, &tables_b[1], naf_b[1][i]);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::secp256k1::Scalar;
    use crate::ec::secp256k1::field_backend::Secp256k1Field;
    use crate::ec::secp256k1::glv::LAMBDA;

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

    /// Σ dᵢ·2ⁱ of a wNAF, in 320-bit two's complement over five limbs, with
    /// the digit-shape assertions for window `w`.
    fn naf_value(naf: &[i16; NAF_LEN], len: usize, w: u32) -> [u64; 5] {
        let mut acc = [0u64; 5];
        let mut last: Option<usize> = None;
        for (i, &d) in naf.iter().enumerate() {
            if d == 0 {
                continue;
            }
            assert!(
                d % 2 != 0 && d.unsigned_abs() < (1 << (w - 1)),
                "bad digit {d}"
            );
            if let Some(l) = last {
                assert!(i - l >= w as usize, "digits too close");
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
        assert_eq!(len, last.map_or(0, |l| l + 1));
        acc
    }

    /// The recoding reconstructs `k` exactly, with the wNAF shape, at both
    /// window widths.
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
            let mut naf = [0i16; NAF_LEN];
            let len = wnaf::<5>(k, &mut naf);
            assert_eq!(
                naf_value(&naf, len, 5),
                [k[0], k[1], k[2], k[3], 0],
                "k={k:x?}"
            );
            let mut naf = [0i16; NAF_LEN];
            let len = wnaf::<8>(k, &mut naf);
            assert_eq!(
                naf_value(&naf, len, 8),
                [k[0], k[1], k[2], k[3], 0],
                "k={k:x?}"
            );
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

    /// `multi_mul` (and, with the table, `generator_double`) agree with the
    /// reference ladder on random terms and on the degenerate ones (zero
    /// scalars, the identity, `P == Q`, `Q == −P`).
    #[test]
    fn multi_mul_matches_ladder() {
        let f = Secp256k1Field::new();
        let g = crate::ec::secp256k1::ProjectivePoint::generator().0;
        let mut rng = SplitMix64(0x5EC9_0002);
        let mut pts = [g; 10];
        pts[1] = Point::identity(&f);
        pts[2] = Point::negate(&f, &g);
        for p in &mut pts[3..] {
            *p = Point::mul_reference(&f, rand_scalar(&mut rng).0.as_limbs(), &g);
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
        let ladder = |k: &Scalar, p: &Point| Point::mul_reference(&f, k.0.as_limbs(), p);
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
                #[cfg(feature = "secp256k1-table")]
                {
                    let want = Point::add(&f, &ladder(a, &g), &ladder(b, p));
                    let got = generator_double(&f, a, b, p);
                    assert!(bool::from(got.ct_eq(&f, &want)), "generator i={i}");
                }
            }
        }
        // a·G + (n − a)·G is the identity.
        let a = rand_scalar(&mut rng);
        let got = multi_mul(&f, [(&a, &g), (&a.negate(), &g)]);
        assert!(bool::from(got.is_identity()));
        #[cfg(feature = "secp256k1-table")]
        {
            let got = generator_double(&f, &a, &a.negate(), &g);
            assert!(bool::from(got.is_identity()));
        }
    }
}
