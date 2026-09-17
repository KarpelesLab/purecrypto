//! The six SEC 2 binary curves `y² + xy = x³ + a·x² + b` over GF(2^m), with
//! a constant-time López–Dahab Montgomery ladder and the SEC 1 §2.3.3 /
//! §2.3.4 point encodings.

use super::field::{F283, F409, F571, Fe, Field, Limbs, MAX_LIMBS};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};

/// One curve's public parameters.
#[derive(Clone, Copy, Debug)]
pub(super) struct Curve {
    /// The underlying field.
    pub(super) field: Field,
    /// `a` (0 for the Koblitz `k1` curves, 1 for the random `r1` curves).
    pub(super) a: Fe,
    /// `b` (1 for the Koblitz curves).
    pub(super) b: Fe,
    /// Generator x-coordinate.
    pub(super) gx: Fe,
    /// Generator y-coordinate.
    pub(super) gy: Fe,
    /// Prime order `n` of the generator, little-endian limbs.
    pub(super) n: Limbs,
    /// `bit_len(n)`; scalars encode in `ceil(n_bits / 8)` bytes.
    pub(super) n_bits: usize,
    /// Cofactor `h`.
    pub(super) h: u64,
    /// The SEC 2 named-curve OID arcs.
    pub(super) oid: &'static [u64],
    /// The SEC 2 name.
    pub(super) name: &'static str,
}

/// An affine point, with the identity carried as a constant-time flag
/// (`x`/`y` are then unspecified and must not be observed).
#[derive(Clone, Copy, Debug)]
pub(super) struct Point {
    pub(super) x: Fe,
    pub(super) y: Fe,
    pub(super) inf: Choice,
}

impl ConditionallySelectable for Point {
    fn conditional_select(a: &Point, b: &Point, choice: Choice) -> Point {
        Point {
            x: Fe::conditional_select(&a.x, &b.x, choice),
            y: Fe::conditional_select(&a.y, &b.y, choice),
            inf: Choice::conditional_select(&a.inf, &b.inf, choice),
        }
    }
}

const ONE: Fe = Fe::ONE;

pub(super) const SECT283K1: Curve = Curve {
    field: F283,
    a: Fe::ZERO,
    b: ONE,
    gx: Fe::from_hex("0503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836"),
    gy: Fe::from_hex("01ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259"),
    n: super::field::limbs_from_hex(
        "01ffffffffffffffffffffffffffffffffffe9ae2ed07577265dff7f94451e061e163c61",
    ),
    n_bits: 281,
    h: 4,
    oid: &[1, 3, 132, 0, 16],
    name: "sect283k1",
};

pub(super) const SECT283R1: Curve = Curve {
    field: F283,
    a: ONE,
    b: Fe::from_hex("027b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5"),
    gx: Fe::from_hex("05f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053"),
    gy: Fe::from_hex("03676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4"),
    n: super::field::limbs_from_hex(
        "03ffffffffffffffffffffffffffffffffffef90399660fc938a90165b042a7cefadb307",
    ),
    n_bits: 282,
    h: 2,
    oid: &[1, 3, 132, 0, 17],
    name: "sect283r1",
};

pub(super) const SECT409K1: Curve = Curve {
    field: F409,
    a: Fe::ZERO,
    b: ONE,
    gx: Fe::from_hex(
        "0060f05f658f49c1ad3ab1890f7184210efd0987e307c84c27accfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746",
    ),
    gy: Fe::from_hex(
        "01e369050b7c4e42acba1dacbf04299c3460782f918ea427e6325165e9ea10e3da5f6c42e9c55215aa9ca27a5863ec48d8e0286b",
    ),
    n: super::field::limbs_from_hex(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffe5f83b2d4ea20400ec4557d5ed3e3e7ca5b4b5c83b8e01e5fcf",
    ),
    n_bits: 407,
    h: 4,
    oid: &[1, 3, 132, 0, 36],
    name: "sect409k1",
};

pub(super) const SECT409R1: Curve = Curve {
    field: F409,
    a: ONE,
    b: Fe::from_hex(
        "21a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f",
    ),
    gx: Fe::from_hex(
        "015d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7",
    ),
    gy: Fe::from_hex(
        "0061b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706",
    ),
    n: super::field::limbs_from_hex(
        "010000000000000000000000000000000000000000000000000001e2aad6a612f33307be5fa47c3c9e052f838164cd37d9a21173",
    ),
    n_bits: 409,
    h: 2,
    oid: &[1, 3, 132, 0, 37],
    name: "sect409r1",
};

pub(super) const SECT571K1: Curve = Curve {
    field: F571,
    a: Fe::ZERO,
    b: ONE,
    gx: Fe::from_hex(
        "026eb7a859923fbc82189631f8103fe4ac9ca2970012d5d46024804801841ca44370958493b205e647da304db4ceb08cbbd1ba39494776fb988b47174dca88c7e2945283a01c8972",
    ),
    gy: Fe::from_hex(
        "0349dc807f4fbf374f4aeade3bca95314dd58cec9f307a54ffc61efc006d8a2c9d4979c0ac44aea74fbebbb9f772aedcb620b01a7ba7af1b320430c8591984f601cd4c143ef1c7a3",
    ),
    n: super::field::limbs_from_hex(
        "020000000000000000000000000000000000000000000000000000000000000000000000131850e1f19a63e4b391a8db917f4138b630d84be5d639381e91deb45cfe778f637c1001",
    ),
    n_bits: 570,
    h: 4,
    oid: &[1, 3, 132, 0, 38],
    name: "sect571k1",
};

pub(super) const SECT571R1: Curve = Curve {
    field: F571,
    a: ONE,
    b: Fe::from_hex(
        "02f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a",
    ),
    gx: Fe::from_hex(
        "0303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19",
    ),
    gy: Fe::from_hex(
        "037bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b",
    ),
    n: super::field::limbs_from_hex(
        "03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe661ce18ff55987308059b186823851ec7dd9ca1161de93d5174d66e8382e9bb2fe84e47",
    ),
    n_bits: 570,
    h: 2,
    oid: &[1, 3, 132, 0, 39],
    name: "sect571r1",
};

/// `a < b` on little-endian limbs, in constant time (a borrow chain).
pub(super) fn limbs_lt(a: &Limbs, b: &Limbs) -> Choice {
    let mut borrow = 0u128;
    for i in 0..MAX_LIMBS {
        let d = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow);
        borrow = (d >> 127) & 1;
    }
    Choice::from(borrow as u8)
}

/// Whether every limb is zero, in constant time.
pub(super) fn limbs_is_zero(a: &Limbs) -> Choice {
    a.ct_eq(&[0; MAX_LIMBS])
}

impl Curve {
    /// Bytes of a scalar (`ceil(bit_len(n) / 8)`).
    #[inline]
    pub(super) const fn scalar_len(&self) -> usize {
        self.n_bits.div_ceil(8)
    }

    /// The generator.
    pub(super) fn generator(&self) -> Point {
        Point {
            x: self.gx,
            y: self.gy,
            inf: Choice::from(0),
        }
    }

    /// Whether `(x, y)` satisfies `y² + xy = x³ + a·x² + b`.
    pub(super) fn is_on_curve(&self, x: &Fe, y: &Fe) -> Choice {
        let f = &self.field;
        let x2 = f.sqr(x);
        let lhs = f.sqr(y).add(&f.mul(x, y));
        let rhs = f.mul(&x2, x).add(&f.mul(&self.a, &x2)).add(&self.b);
        lhs.ct_eq(&rhs)
    }

    /// Montgomery doubling in López–Dahab x-only coordinates:
    /// `(X : Z) ↦ (X⁴ + b·Z⁴ : X²·Z²)`.
    #[inline]
    fn mdouble(&self, x: &Fe, z: &Fe) -> (Fe, Fe) {
        let f = &self.field;
        let x2 = f.sqr(x);
        let z2 = f.sqr(z);
        let x4 = f.sqr(&x2);
        let bz4 = f.mul(&self.b, &f.sqr(&z2));
        (x4.add(&bz4), f.mul(&x2, &z2))
    }

    /// Montgomery differential addition: given `x(P₁)`, `x(P₂)` and
    /// `x = x(P₂ − P₁)`, returns `x(P₁ + P₂)` as
    /// `(x·(T₁ + T₂)² + T₁·T₂ : (T₁ + T₂)²)` with `T₁ = X₁Z₂`, `T₂ = X₂Z₁`.
    #[inline]
    fn madd(&self, x1: &Fe, z1: &Fe, x2: &Fe, z2: &Fe, x: &Fe) -> (Fe, Fe) {
        let f = &self.field;
        let t1 = f.mul(x1, z2);
        let t2 = f.mul(x2, z1);
        let z = f.sqr(&t1.add(&t2));
        let xo = f.mul(x, &z).add(&f.mul(&t1, &t2));
        (xo, z)
    }

    /// `k · p` by the López–Dahab Montgomery ladder over the full
    /// `64 · limbs` bit width of `k` (little-endian limbs), with
    /// constant-time swaps driven by consecutive bit differences.
    ///
    /// The ladder starts from `(∞, P)` so every bit — leading zeros included —
    /// runs the same doubling and differential addition. The x-only formulas
    /// carry infinity as `(X : 0)` with `X ≠ 0` and never produce `(0 : 0)`
    /// for a finite `p` on the curve, whatever its order (so the same routine
    /// performs the `n·Q = ∞` subgroup check). The y-coordinate is recovered
    /// from the final pair `(kP, (k+1)P)`; the two cases where that formula
    /// degenerates — `(k+1)P = ∞` (then `kP = −P`) and `x(P) = 0` (an
    /// order-2 point, `kP ∈ {P, ∞}`) — are patched by constant-time selects,
    /// and `kP = ∞` sets the flag.
    pub(super) fn mul(&self, k: &Limbs, p: &Point) -> Point {
        let f = &self.field;
        let x = p.x;
        let y = p.y;
        // R0 = ∞, R1 = P.
        let (mut x1, mut z1) = (Fe::ONE, Fe::ZERO);
        let (mut x2, mut z2) = (x, Fe::ONE);
        let mut prev = Choice::from(0);
        for i in (0..f.bit_width()).rev() {
            let bit = Choice::from(((k[i / 64] >> (i % 64)) & 1) as u8);
            let swap = bit ^ prev;
            Fe::conditional_swap(&mut x1, &mut x2, swap);
            Fe::conditional_swap(&mut z1, &mut z2, swap);
            prev = bit;
            // R1 = R0 + R1, R0 = 2·R0 (in the orientation selected by `bit`).
            let (ax, az) = self.madd(&x1, &z1, &x2, &z2, &x);
            let (dx, dz) = self.mdouble(&x1, &z1);
            x1 = dx;
            z1 = dz;
            x2 = ax;
            z2 = az;
        }
        Fe::conditional_swap(&mut x1, &mut x2, prev);
        Fe::conditional_swap(&mut z1, &mut z2, prev);

        // (x1 : z1) = kP, (x2 : z2) = (k+1)P. Recover y (López–Dahab Mxy):
        // y_k = (x + x_k)·[(X₁ + xZ₁)(X₂ + xZ₂) + (x² + y)Z₁Z₂] / (xZ₁Z₂) + y.
        let z1_zero = z1.is_zero();
        let z2_zero = z2.is_zero();
        let x_zero = x.is_zero();
        let xk = f.mul(&x1, &f.inv(&z1));
        let t1 = x1.add(&f.mul(&x, &z1));
        let t2 = x2.add(&f.mul(&x, &z2));
        let z1z2 = f.mul(&z1, &z2);
        let num = f.mul(&t1, &t2).add(&f.mul(&f.sqr(&x).add(&y), &z1z2));
        let den = f.inv(&f.mul(&x, &z1z2));
        let yk = f.mul(&x.add(&xk), &f.mul(&num, &den)).add(&y);
        // (k+1)P = ∞ ⇒ kP = −P = (x, x + y); x = 0 and kP ≠ ∞ ⇒ kP = P.
        let yk = Fe::conditional_select(&x.add(&y), &yk, z2_zero);
        let yk = Fe::conditional_select(&y, &yk, x_zero);
        let xk = Fe::conditional_select(&x, &xk, z2_zero | x_zero);
        Point {
            x: xk,
            y: yk,
            inf: z1_zero | p.inf,
        }
    }

    /// Whether `n · p = ∞` (the prime-order subgroup check).
    pub(super) fn in_subgroup(&self, p: &Point) -> Choice {
        self.mul(&self.n, p).inf
    }

    /// Bytes of the SEC 1 encoding: `1 + len` compressed, `1 + 2·len`
    /// uncompressed.
    pub(super) fn encoded_len(&self, compressed: bool) -> usize {
        let len = self.field.byte_len();
        if compressed { 1 + len } else { 1 + 2 * len }
    }

    /// SEC 1 §2.3.3 encoding of a finite point. The compressed form carries
    /// `ỹ = 0` when `x = 0`, otherwise the constant term of `y · x⁻¹`.
    pub(super) fn encode(&self, p: &Point, compressed: bool, out: &mut [u8]) {
        let f = &self.field;
        let len = f.byte_len();
        debug_assert_eq!(out.len(), self.encoded_len(compressed));
        f.encode_be(&p.x, &mut out[1..1 + len]);
        if compressed {
            // `inv(0) = 0`, so x = 0 yields ỹ = 0 without a branch.
            let ybit = f.mul(&p.y, &f.inv(&p.x)).lsb();
            out[0] = 0x02 | ybit.unwrap_u8();
        } else {
            out[0] = 0x04;
            f.encode_be(&p.y, &mut out[1 + len..]);
        }
    }

    /// SEC 1 §2.3.4 decoding: accepts `04 || x || y` and `02/03 || x`,
    /// verifies the field-element ranges and the curve equation, and refuses
    /// the single-byte identity. The subgroup check is the caller's.
    pub(super) fn decode(&self, bytes: &[u8]) -> Result<Point, super::Error> {
        let f = &self.field;
        let len = f.byte_len();
        let (&tag, rest) = bytes.split_first().ok_or(super::Error::Malformed)?;
        match tag {
            0x04 if rest.len() == 2 * len => {
                let x = f.decode_be(&rest[..len]);
                let y = f.decode_be(&rest[len..]);
                let (Some(x), Some(y)) = (x, y) else {
                    return Err(super::Error::Malformed);
                };
                if bool::from(self.is_on_curve(&x, &y)) {
                    Ok(Point {
                        x,
                        y,
                        inf: Choice::from(0),
                    })
                } else {
                    Err(super::Error::InvalidInput)
                }
            }
            0x02 | 0x03 if rest.len() == len => {
                let x = f.decode_be(rest).ok_or(super::Error::Malformed)?;
                let ybit = Choice::from(tag & 1);
                // x ≠ 0: β = x + a + b·x⁻², z² + z = β, pick the root with
                // the requested constant term, y = x·z.
                let xinv = f.inv(&x);
                let beta = x.add(&self.a).add(&f.mul(&self.b, &f.sqr(&xinv)));
                let (z, ok) = f.solve_quadratic(&beta);
                let flip = z.lsb() ^ ybit;
                let z = Fe::conditional_select(&z.add(&Fe::ONE), &z, flip);
                let y = f.mul(&x, &z);
                // x = 0: y = √b, and only ỹ = 0 is a valid encoding.
                let x_zero = x.is_zero();
                let y = Fe::conditional_select(&f.sqrt(&self.b), &y, x_zero);
                let ok = Choice::conditional_select(&!ybit, &ok, x_zero);
                if bool::from(ok) {
                    Ok(Point {
                        x,
                        y,
                        inf: Choice::from(0),
                    })
                } else {
                    Err(super::Error::InvalidInput)
                }
            }
            _ => Err(super::Error::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    pub(super) const CURVES: [&Curve; 6] = [
        &SECT283K1, &SECT283R1, &SECT409K1, &SECT409R1, &SECT571K1, &SECT571R1,
    ];

    fn scalar(v: u64) -> Limbs {
        let mut k = [0u64; MAX_LIMBS];
        k[0] = v;
        k
    }

    #[test]
    fn parameters_are_consistent() {
        for c in CURVES {
            let g = c.generator();
            assert!(bool::from(c.is_on_curve(&g.x, &g.y)), "{} G", c.name);
            // n has the documented bit length and is odd.
            let top = c.n[(c.n_bits - 1) / 64] >> ((c.n_bits - 1) % 64);
            assert_eq!(top, 1, "{} n_bits", c.name);
            assert_eq!(c.n[0] & 1, 1);
            for &l in &c.n[c.n_bits.div_ceil(64)..] {
                assert_eq!(l, 0);
            }
            assert_eq!(c.oid[..4], [1, 3, 132, 0]);
        }
    }

    #[test]
    fn generator_order_and_cofactor() {
        for c in CURVES {
            let g = c.generator();
            let ng = c.mul(&c.n, &g);
            assert!(bool::from(ng.inf), "{} n·G = ∞", c.name);
            assert!(bool::from(c.in_subgroup(&g)));
            // h·∞ = ∞, and (n − 1)·G = −G = (x, x + y).
            assert!(bool::from(c.mul(&scalar(c.h), &ng).inf));
            let mut n1 = c.n;
            n1[0] -= 1;
            let neg = c.mul(&n1, &g);
            assert!(!bool::from(neg.inf));
            assert_eq!(neg.x.0, g.x.0, "{} (n-1)G.x", c.name);
            assert_eq!(neg.y.0, g.x.add(&g.y).0, "{} (n-1)G.y", c.name);
        }
    }

    #[test]
    fn small_multiples_agree_with_affine_addition() {
        // 2G by the affine doubling formula, 3G = 2G + G by affine addition;
        // both must match the ladder, which also validates y recovery.
        for c in CURVES {
            let f = &c.field;
            let g = c.generator();
            let one = c.mul(&scalar(1), &g);
            assert_eq!((one.x.0, one.y.0), (g.x.0, g.y.0), "{} 1·G", c.name);
            // λ = x + y/x; x₂ = λ² + λ + a; y₂ = x² + (λ + 1)·x₂.
            let lam = g.x.add(&f.mul(&g.y, &f.inv(&g.x)));
            let x2 = f.sqr(&lam).add(&lam).add(&c.a);
            let y2 = f.sqr(&g.x).add(&f.mul(&lam.add(&Fe::ONE), &x2));
            let two = c.mul(&scalar(2), &g);
            assert!(!bool::from(two.inf));
            assert_eq!((two.x.0, two.y.0), (x2.0, y2.0), "{} 2·G", c.name);
            // λ = (y₁ + y₂)/(x₁ + x₂); x₃ = λ² + λ + x₁ + x₂ + a;
            // y₃ = λ(x₁ + x₃) + x₃ + y₁.
            let lam = f.mul(&g.y.add(&y2), &f.inv(&g.x.add(&x2)));
            let x3 = f.sqr(&lam).add(&lam).add(&g.x).add(&x2).add(&c.a);
            let y3 = f.mul(&lam, &g.x.add(&x3)).add(&x3).add(&g.y);
            let three = c.mul(&scalar(3), &g);
            assert_eq!((three.x.0, three.y.0), (x3.0, y3.0), "{} 3·G", c.name);
            assert!(bool::from(c.is_on_curve(&x3, &y3)));
        }
    }

    #[test]
    fn point_encoding_round_trips() {
        for c in CURVES {
            for k in [1u64, 2, 3, 7] {
                let p = c.mul(&scalar(k), &c.generator());
                for compressed in [false, true] {
                    let mut enc = vec![0u8; c.encoded_len(compressed)];
                    c.encode(&p, compressed, &mut enc);
                    let q = c.decode(&enc).unwrap();
                    assert_eq!((q.x.0, q.y.0), (p.x.0, p.y.0), "{} {k}G", c.name);
                    // The other compressed root is a different point: −P.
                    if compressed {
                        enc[0] ^= 1;
                        let neg = c.decode(&enc).unwrap();
                        assert_eq!(neg.y.0, p.x.add(&p.y).0);
                    }
                }
            }
            // The order-2 point (0, √b) compresses with ỹ = 0 only.
            let f = &c.field;
            let mut enc = vec![0u8; c.encoded_len(true)];
            enc[0] = 0x02;
            let p = c.decode(&enc).unwrap();
            assert_eq!(p.y.0, f.sqrt(&c.b).0);
            assert!(bool::from(c.is_on_curve(&p.x, &p.y)));
            assert!(!bool::from(c.in_subgroup(&p)));
            assert!(bool::from(c.mul(&scalar(2), &p).inf));
            enc[0] = 0x03;
            assert!(c.decode(&enc).is_err());
            let mut enc2 = vec![0u8; c.encoded_len(true)];
            c.encode(&p, true, &mut enc2);
            assert_eq!(enc2[0], 0x02);
        }
    }

    #[test]
    fn decode_rejects_bad_input() {
        let c = &SECT283K1;
        let g = c.generator();
        let mut enc = vec![0u8; c.encoded_len(false)];
        c.encode(&g, false, &mut enc);
        assert!(c.decode(&enc[..enc.len() - 1]).is_err());
        assert!(c.decode(&[0x00]).is_err());
        assert!(c.decode(&[]).is_err());
        let mut hybrid = enc.clone();
        hybrid[0] = 0x06;
        assert!(c.decode(&hybrid).is_err());
        let mut off = enc.clone();
        off[enc.len() - 1] ^= 1;
        assert_eq!(
            c.decode(&off).err(),
            Some(super::super::Error::InvalidInput)
        );
        let mut big = enc.clone();
        big[1] |= 0x80; // bit ≥ m in x
        assert_eq!(c.decode(&big).err(), Some(super::super::Error::Malformed));
    }

    #[test]
    fn scalar_comparison() {
        let a = scalar(5);
        let b = scalar(6);
        assert!(bool::from(limbs_lt(&a, &b)));
        assert!(!bool::from(limbs_lt(&b, &a)));
        assert!(!bool::from(limbs_lt(&a, &a)));
        let mut hi = scalar(0);
        hi[3] = 1;
        assert!(bool::from(limbs_lt(&b, &hi)));
        assert!(!bool::from(limbs_lt(&hi, &b)));
        assert!(bool::from(limbs_is_zero(&scalar(0))));
        assert!(!bool::from(limbs_is_zero(&a)));
    }
}
