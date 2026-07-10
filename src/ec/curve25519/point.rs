//! Edwards25519 curve points in extended homogeneous coordinates.
//!
//! Twisted Edwards curve `−x² + y² = 1 + d·x²·y²` (`a = −1`) over
//! GF(2²⁵⁵−19), in extended coordinates `(X:Y:Z:T)` with the complete
//! Hisil–Wong–Carter–Dawson 2008 addition formulas. Scalar multiplication is a
//! constant-time fixed 4-bit window ladder; base-point multiplication uses a
//! precomputed comb table ([`super::base_table`]) with no doublings. This is
//! the shared point backend behind Ed25519, the edwards25519 hazmat surface,
//! and ristretto255.

use super::base_table::ED25519_BASE_TABLE;
use super::field::{Fe, Field};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};

/// A curve point in extended homogeneous coordinates `(X:Y:Z:T)`, all in
/// Montgomery form.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Point {
    pub(crate) x: Fe,
    pub(crate) y: Fe,
    pub(crate) z: Fe,
    pub(crate) t: Fe,
}

impl Field {
    /// The base point `B`, decompressed from its standard encoding.
    // Library-path base multiplications go through [`Self::mul_base`] and its
    // precomputed comb table; only the ristretto255 group API (and tests)
    // still need the point itself. Gate to avoid dead_code on the default
    // (Ed25519-only) build, like `point_negate` below.
    #[cfg(any(test, feature = "hazmat-edwards25519", feature = "ristretto255"))]
    pub(crate) fn base(&self) -> Point {
        self.decode(&super::field::BASE_ENC)
            .expect("valid base point")
    }

    /// Decompresses a 32-byte point encoding (RFC 8032 §5.1.3), or `None` if the
    /// bytes do not encode a curve point.
    pub(crate) fn decode(&self, enc: &[u8; 32]) -> Option<Point> {
        let sign = (enc[31] >> 7) & 1;
        let mut yb = *enc;
        yb[31] &= 0x7f;
        let yval = Fe::from_le_bytes(&yb);
        if !bool::from(yval.ct_lt(&self.p)) {
            return None;
        }
        let y = self.to_mont(&yval);

        // x² = (y² − 1) / (d·y² + 1) = u / v.
        let yy = self.sq(y);
        let u = self.sub(yy, self.one);
        let v = self.add(self.mul(self.d, yy), self.one);

        // x = sqrt(u/v) via the shared sqrt-ratio routine. `was_square` is
        // false exactly when neither v·x² == u nor v·x² == −u, i.e. the point
        // is not on the curve.
        let (was_square, mut x) = self.sqrt_ratio_i(u, v);
        if !bool::from(was_square) {
            return None;
        }

        let xplain = self.from_mont(&x);
        if bool::from(xplain.ct_eq(&Fe::ZERO)) && sign == 1 {
            return None;
        }
        if xplain.is_odd().unwrap_u8() != sign {
            x = self.neg(x);
        }

        let t = self.mul(x, y);
        Some(Point {
            x,
            y,
            z: self.one,
            t,
        })
    }

    /// Compresses a point to its 32-byte encoding.
    pub(crate) fn encode(&self, p: &Point) -> [u8; 32] {
        let zinv = self.inv(p.z);
        let x = self.from_mont(&self.mul(p.x, zinv));
        let y = self.from_mont(&self.mul(p.y, zinv));
        let mut out = [0u8; 32];
        y.write_le_bytes(&mut out);
        out[31] |= x.is_odd().unwrap_u8() << 7;
        out
    }

    /// The affine coordinates `(x, y) = (X/Z, Y/Z)` of `p`, each written as a
    /// 32-byte little-endian canonical encoding of a residue in `[0, p)`.
    ///
    /// Unlike [`encode`](Self::encode) this returns the full `x` coordinate
    /// rather than folding its sign into a bit of `y`. Group points always have
    /// an invertible `Z`, so the inversion is well defined (the identity is
    /// `(0:1:1:0)`, giving affine `(0, 1)`).
    // Used by the edwards25519::hazmat affine-coordinate accessors; gate to the
    // same features as that surface to avoid a dead-code warning on the default
    // (Ed25519-only) build.
    #[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
    pub(crate) fn to_affine_bytes(&self, p: &Point) -> ([u8; 32], [u8; 32]) {
        let zinv = self.inv(p.z);
        let x = self.from_mont(&self.mul(p.x, zinv));
        let y = self.from_mont(&self.mul(p.y, zinv));
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        x.write_le_bytes(&mut xb);
        y.write_le_bytes(&mut yb);
        (xb, yb)
    }

    /// The neutral element `(0:1:1:0)`.
    pub(crate) fn identity(&self) -> Point {
        Point {
            x: Fe::ZERO,
            y: self.one,
            z: self.one,
            t: Fe::ZERO,
        }
    }

    /// Point addition (add-2008-hwcd-3), complete for `a = −1` since `d` is a
    /// non-square on edwards25519.
    pub(crate) fn point_add(&self, p: &Point, q: &Point) -> Point {
        let aa = self.mul(self.sub(p.y, p.x), self.sub(q.y, q.x));
        let bb = self.mul(self.add(p.y, p.x), self.add(q.y, q.x));
        let cc = self.mul(self.mul(p.t, self.d2), q.t);
        let dd = self.mul(self.add(p.z, p.z), q.z);
        let e = self.sub(bb, aa);
        let ff = self.sub(dd, cc);
        let g = self.add(dd, cc);
        let h = self.add(bb, aa);
        Point {
            x: self.mul(e, ff),
            y: self.mul(g, h),
            t: self.mul(e, h),
            z: self.mul(ff, g),
        }
    }

    /// Point doubling (dbl-2008-hwcd) for `a = −1`.
    pub(crate) fn point_double(&self, p: &Point) -> Point {
        let a = self.sq(p.x);
        let b = self.sq(p.y);
        let zz = self.sq(p.z);
        let c = self.add(zz, zz);
        let d = self.neg(a);
        let e = self.sub(self.sub(self.sq(self.add(p.x, p.y)), a), b);
        let g = self.add(d, b);
        let ff = self.sub(g, c);
        let h = self.sub(d, b);
        Point {
            x: self.mul(e, ff),
            y: self.mul(g, h),
            t: self.mul(e, h),
            z: self.mul(ff, g),
        }
    }

    /// Negates a point: `−(X:Y:Z:T) = (−X:Y:Z:−T)`.
    // Used only by the optional edwards25519::hazmat and ristretto255 group
    // APIs; the RFC 8032 Ed25519 path negates via scalars, not points. Gate to
    // silence a dead-code warning on the default (Ed25519-only) build.
    #[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
    pub(crate) fn point_negate(&self, p: &Point) -> Point {
        Point {
            x: self.neg(p.x),
            y: p.y,
            z: p.z,
            t: self.neg(p.t),
        }
    }

    /// Constant-time `[scalar]·p` over the 256-bit little-endian scalar, via
    /// a fixed 4-bit window: 4 doublings and one *unconditional* addition per
    /// nibble, with the window value fetched by a masked scan of all 16 table
    /// entries (no secret-indexed memory access). A zero nibble adds the
    /// identity — a no-op with the same operation sequence, since the HWCD
    /// formulas are complete — so the schedule depends only on the (public)
    /// scalar width, exactly like the previous bit-at-a-time ladder. The
    /// scalar bytes are treated as secret.
    pub(crate) fn scalar_mult(&self, scalar: &[u8; 32], p: &Point) -> Point {
        // table[j] = [j]P; table[0] is the identity.
        let mut table = [self.identity(); 16];
        table[1] = *p;
        for i in 2..16 {
            table[i] = self.point_add(&table[i - 1], p);
        }

        let mut acc = self.identity();
        let mut i = 64;
        while i > 0 {
            i -= 1;
            acc = self.point_double(&acc);
            acc = self.point_double(&acc);
            acc = self.point_double(&acc);
            acc = self.point_double(&acc);

            let byte = scalar[i / 2];
            let digit = (if i % 2 == 1 { byte >> 4 } else { byte & 0xf }) as usize;
            // Constant-time gather of table[digit].
            let mut sel = table[0];
            for (j, entry) in table.iter().enumerate() {
                sel = point_select(&sel, entry, Choice::from((j == digit) as u8));
            }
            acc = self.point_add(&acc, &sel);
        }
        acc
    }

    /// Constant-time fixed-base multiplication `[scalar]·B` via the
    /// precomputed comb table [`ED25519_BASE_TABLE`]:
    /// `[k]B = Σᵢ [dᵢ · 16^i]B` over the 64 base-16 digits `dᵢ` of the
    /// little-endian scalar, so there are **no doublings** — just 64
    /// unconditional additions, each operand fetched by a masked scan of that
    /// window's 15 stored points (no secret-indexed memory access, same
    /// gather discipline as [`Self::scalar_mult`]). A zero digit adds the
    /// identity, a uniform no-op under the complete HWCD formulas, so the
    /// schedule depends only on the (public) scalar width. The scalar bytes
    /// are treated as secret.
    pub(crate) fn mul_base(&self, scalar: &[u8; 32]) -> Point {
        let id = self.identity();
        let mut acc = id;
        for (i, window) in ED25519_BASE_TABLE.iter().enumerate() {
            // Digit i = nibble i of the little-endian scalar bytes.
            let byte = scalar[i / 2];
            let digit = (if i % 2 == 1 { byte >> 4 } else { byte & 0xf }) as usize;
            // Constant-time gather: scan all 15 entries, keep entry j when
            // j + 1 == digit; a zero digit keeps the identity. Every stored
            // entry is affine, so Z = 1 — which also matches the identity
            // representation (0:1:1:0).
            let mut sel = id;
            for (j, entry) in window.iter().enumerate() {
                let cand = Point {
                    x: Fe::from_limbs([entry[0], entry[1], entry[2], entry[3]]),
                    y: Fe::from_limbs([entry[4], entry[5], entry[6], entry[7]]),
                    z: self.one,
                    t: Fe::from_limbs([entry[8], entry[9], entry[10], entry[11]]),
                };
                sel = point_select(&sel, &cand, Choice::from((j + 1 == digit) as u8));
            }
            acc = self.point_add(&acc, &sel);
        }
        acc
    }

    /// Constant-time equality of two points, comparing the affine
    /// representatives via cross-multiplication (so distinct projective
    /// representatives of the same point compare equal): `X₁·Z₂ == X₂·Z₁` and
    /// `Y₁·Z₂ == Y₂·Z₁`.
    // Used only by the edwards25519::hazmat group API (point equality /
    // identity / order checks); gate to silence a dead-code warning on the
    // default build.
    #[cfg(any(feature = "hazmat-edwards25519", feature = "ristretto255"))]
    pub(crate) fn point_ct_eq(&self, p: &Point, q: &Point) -> Choice {
        let x1z2 = self.mul(p.x, q.z);
        let x2z1 = self.mul(q.x, p.z);
        let y1z2 = self.mul(p.y, q.z);
        let y2z1 = self.mul(q.y, p.z);
        self.ct_eq(x1z2, x2z1) & self.ct_eq(y1z2, y2z1)
    }
}

/// Constant-time point selection: `b` if `c` is set, else `a`. (This crate's
/// `conditional_select(x, y, c)` returns `x` when `c` is set, so the chosen
/// value goes first.)
pub(crate) fn point_select(a: &Point, b: &Point, c: Choice) -> Point {
    Point {
        x: Fe::conditional_select(&b.x, &a.x, c),
        y: Fe::conditional_select(&b.y, &a.y, c),
        z: Fe::conditional_select(&b.z, &a.z, c),
        t: Fe::conditional_select(&b.t, &a.t, c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Re-derives every entry of the embedded fixed-base table from the
    /// group law and cross-checks the constants, so `ED25519_BASE_TABLE` is
    /// verified on every test run rather than trusted. The check is
    /// inversion-free: the stored affine `(x, y, t)` matches the computed
    /// extended `(X : Y : Z : T)` iff `x·Z == X`, `y·Z == Y` and `t·Z == T`.
    #[test]
    fn base_table_matches_computed() {
        let f = Field::new();
        let mut base = f.base();
        for window in ED25519_BASE_TABLE.iter() {
            let mut acc = base;
            for (j, entry) in window.iter().enumerate() {
                if j > 0 {
                    acc = f.point_add(&acc, &base);
                }
                let ex = Fe::from_limbs([entry[0], entry[1], entry[2], entry[3]]);
                let ey = Fe::from_limbs([entry[4], entry[5], entry[6], entry[7]]);
                let et = Fe::from_limbs([entry[8], entry[9], entry[10], entry[11]]);
                assert!(bool::from(f.ct_eq(f.mul(ex, acc.z), acc.x)), "x mismatch");
                assert!(bool::from(f.ct_eq(f.mul(ey, acc.z), acc.y)), "y mismatch");
                assert!(bool::from(f.ct_eq(f.mul(et, acc.z), acc.t)), "t mismatch");
            }
            base = f.point_double(&f.point_double(&f.point_double(&f.point_double(&base))));
        }
    }

    /// Differential test: the fixed-base comb agrees with the generic
    /// windowed ladder for edge scalars (0, 1, 2, L−1, L, L+1, 2²⁵⁵-ish,
    /// all-ones) and a batch of random ones.
    #[test]
    fn mul_base_matches_generic_scalar_mult() {
        use crate::hash::Sha256;
        use crate::rng::{HmacDrbg, RngCore};
        let f = Field::new();
        let b = f.base();

        let check = |s: &[u8; 32]| {
            assert_eq!(
                f.encode(&f.mul_base(s)),
                f.encode(&f.scalar_mult(s, &b)),
                "comb/ladder mismatch"
            );
        };

        let fe_bytes = |v: &Fe| {
            let mut out = [0u8; 32];
            v.write_le_bytes(&mut out);
            out
        };
        let mut edges = [[0u8; 32]; 8];
        edges[1][0] = 1;
        edges[2][0] = 2;
        edges[3] = fe_bytes(&f.l.wrapping_sub(&Fe::ONE));
        edges[4] = fe_bytes(&f.l);
        edges[5] = fe_bytes(&f.l.wrapping_add(&Fe::ONE));
        edges[6][31] = 0x80;
        edges[7] = [0xff; 32];
        for s in &edges {
            check(s);
        }

        let mut rng = HmacDrbg::<Sha256>::new(b"ed25519-comb-differential", b"nonce", &[]);
        for _ in 0..32 {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            check(&s);
        }
    }

    /// Regenerates the fixed-base table source
    /// (`src/ec/curve25519/base_table.rs`). Run with:
    /// `cargo test --release gen_ed25519_base_table -- --ignored --nocapture`
    /// and paste the emitted `static` between the file's header comment and
    /// EOF. The non-ignored `base_table_matches_computed` test keeps the
    /// pasted constants honest on every test run.
    #[test]
    #[ignore = "table generator; emits Rust source on stdout"]
    #[cfg(feature = "std")]
    fn gen_ed25519_base_table() {
        use std::{print, println};
        let f = Field::new();
        // base = [16^i]B for the current window i.
        let mut base = f.base();
        println!("pub(crate) static ED25519_BASE_TABLE: [[[u64; 12]; 15]; 64] = [");
        for _ in 0..64 {
            println!("    [");
            let mut acc = base;
            for j in 1..=15u32 {
                if j > 1 {
                    acc = f.point_add(&acc, &base);
                }
                // Affine (x, y, t = x·y), all in Montgomery form.
                let zinv = f.inv(acc.z);
                let x = f.mul(acc.x, zinv);
                let y = f.mul(acc.y, zinv);
                let t = f.mul(x, y);
                print!("        [");
                for l in x.as_limbs() {
                    print!("0x{l:016x}, ");
                }
                for l in y.as_limbs() {
                    print!("0x{l:016x}, ");
                }
                for l in t.as_limbs() {
                    print!("0x{l:016x}, ");
                }
                println!("],");
            }
            println!("    ],");
            base = f.point_double(&f.point_double(&f.point_double(&f.point_double(&base))));
        }
        println!("];");
    }
}
