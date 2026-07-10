//! Edwards25519 curve points in extended homogeneous coordinates.
//!
//! Twisted Edwards curve `−x² + y² = 1 + d·x²·y²` (`a = −1`) over
//! GF(2²⁵⁵−19), in extended coordinates `(X:Y:Z:T)` with the complete
//! Hisil–Wong–Carter–Dawson 2008 addition formulas. Scalar multiplication is a
//! constant-time fixed 4-bit window ladder; base-point multiplication uses a
//! precomputed comb table ([`super::base_table`]) with no doublings. This is
//! the shared point backend behind Ed25519, the edwards25519 hazmat surface,
//! and ristretto255.
//!
//! Two clearly-marked `_vartime` entry points exist for **public-input**
//! workloads (Ed25519 signature verification): they take data-dependent
//! branches and perform table lookups indexed by the scalar, so they must
//! never see secret scalars or secret points.

use super::base_table::ED25519_BASE_TABLE;
use super::field::{Fe, Field, ScalarInt};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeLess};

/// A curve point in extended homogeneous coordinates `(X:Y:Z:T)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Point {
    pub(crate) x: Fe,
    pub(crate) y: Fe,
    pub(crate) z: Fe,
    pub(crate) t: Fe,
}

/// Lifts a stored affine table entry (`x‖y‖t`, 5 little-endian 51-bit limbs
/// each, canonical residues) to extended coordinates with `Z = 1`.
#[inline]
fn table_point(entry: &[u64; 15], one: Fe) -> Point {
    Point {
        x: Fe([entry[0], entry[1], entry[2], entry[3], entry[4]]),
        y: Fe([entry[5], entry[6], entry[7], entry[8], entry[9]]),
        z: one,
        t: Fe([entry[10], entry[11], entry[12], entry[13], entry[14]]),
    }
}

impl Field {
    /// The base point `B`, decompressed from its standard encoding.
    // Library-path base multiplications go through [`Self::mul_base`] and its
    // precomputed comb table; only the ristretto255 group API (and tests)
    // still need the point itself. Gate to avoid dead_code on the default
    // (Ed25519-only) build.
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
        let yval = ScalarInt::from_le_bytes(&yb);
        if !bool::from(yval.ct_lt(&self.p)) {
            return None;
        }
        let y = Fe::from_bytes(&yb);

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

        if bool::from(x.is_zero()) && sign == 1 {
            return None;
        }
        if x.is_negative().unwrap_u8() != sign {
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
        let x = self.mul(p.x, zinv);
        let y = self.mul(p.y, zinv);
        let mut out = y.to_bytes();
        out[31] |= x.is_negative().unwrap_u8() << 7;
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
        let x = self.mul(p.x, zinv);
        let y = self.mul(p.y, zinv);
        (x.to_bytes(), y.to_bytes())
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
    // Ed25519 verification moved to the vartime path (its inputs are public),
    // so on the default build this constant-time generic multiplication only
    // backs the test-side differential oracles; the hazmat/ristretto group
    // APIs (secret scalars) are its library users. Gate accordingly to keep
    // the default build free of dead code.
    #[cfg(any(test, feature = "hazmat-edwards25519", feature = "ristretto255"))]
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
                let cand = table_point(entry, self.one);
                sel = point_select(&sel, &cand, Choice::from((j + 1 == digit) as u8));
            }
            acc = self.point_add(&acc, &sel);
        }
        acc
    }

    /// **Variable-time** fixed-base multiplication `[scalar]·B` over the same
    /// comb table as [`Self::mul_base`], but indexing each window entry
    /// directly and skipping zero digits.
    ///
    /// # Warning: public inputs only
    ///
    /// The lookup index and the skip pattern leak the scalar through timing
    /// and memory access. This must ONLY ever be called with **public**
    /// scalars (e.g. the signature scalar `S` during Ed25519 verification) —
    /// never with signing nonces or secret keys.
    pub(crate) fn mul_base_vartime(&self, scalar: &[u8; 32]) -> Point {
        let mut acc = self.identity();
        for (i, window) in ED25519_BASE_TABLE.iter().enumerate() {
            let byte = scalar[i / 2];
            let digit = (if i % 2 == 1 { byte >> 4 } else { byte & 0xf }) as usize;
            if digit != 0 {
                let cand = table_point(&window[digit - 1], self.one);
                acc = self.point_add(&acc, &cand);
            }
        }
        acc
    }

    /// **Variable-time** `[scalar]·p` via a width-5 wNAF ladder: ~254
    /// doublings plus one addition per nonzero digit (≈ 1 in 6), against a
    /// table of the 8 odd multiples `[1]P..[15]P`.
    ///
    /// # Warning: public inputs only
    ///
    /// Both the branch pattern and the table indices leak the scalar. This
    /// must ONLY ever be called with **public** scalars and points (e.g. the
    /// challenge scalar `k` and public key `A` during Ed25519 verification).
    pub(crate) fn scalar_mult_vartime(&self, scalar: &[u8; 32], p: &Point) -> Point {
        // Odd multiples: odd[i] = [2i+1]P.
        let p2 = self.point_double(p);
        let mut odd = [*p; 8];
        for i in 1..8 {
            odd[i] = self.point_add(&odd[i - 1], &p2);
        }

        let naf = wnaf5(scalar);
        // Find the highest nonzero digit (vartime by design).
        let mut top = None;
        for i in (0..naf.len()).rev() {
            if naf[i] != 0 {
                top = Some(i);
                break;
            }
        }
        let Some(top) = top else {
            return self.identity();
        };

        let mut acc = self.identity();
        for i in (0..=top).rev() {
            acc = self.point_double(&acc);
            let d = naf[i];
            if d > 0 {
                acc = self.point_add(&acc, &odd[(d as usize) / 2]);
            } else if d < 0 {
                acc = self.point_add(&acc, &self.point_negate(&odd[(-d as usize) / 2]));
            }
        }
        acc
    }

    /// Constant-time equality of two points, comparing the affine
    /// representatives via cross-multiplication (so distinct projective
    /// representatives of the same point compare equal): `X₁·Z₂ == X₂·Z₁` and
    /// `Y₁·Z₂ == Y₂·Z₁`. Inversion-free.
    pub(crate) fn point_ct_eq(&self, p: &Point, q: &Point) -> Choice {
        let x1z2 = self.mul(p.x, q.z);
        let x2z1 = self.mul(q.x, p.z);
        let y1z2 = self.mul(p.y, q.z);
        let y2z1 = self.mul(q.y, p.z);
        self.ct_eq(x1z2, x2z1) & self.ct_eq(y1z2, y2z1)
    }
}

/// Width-5 non-adjacent form of a 256-bit little-endian scalar: digits in
/// `{0, ±1, ±3, …, ±15}` with at least 4 zeros between nonzero digits. The
/// extra trailing positions absorb the recoding carry of scalars close to
/// `2^256`, so any 256-bit integer is represented exactly.
/// **Variable-time**; only for public scalars.
fn wnaf5(scalar: &[u8; 32]) -> [i8; 261] {
    let mut naf = [0i8; 261];

    // Five u64 limbs so the window read below may index one limb past the
    // scalar's 256 bits.
    let mut x = [0u64; 5];
    for (i, limb) in x.iter_mut().take(4).enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&scalar[i * 8..i * 8 + 8]);
        *limb = u64::from_le_bytes(b);
    }

    let width = 1u64 << 5;
    let window_mask = width - 1;

    let mut pos = 0;
    let mut carry = 0u64;
    while pos < 256 {
        let idx = pos / 64;
        let bit = pos % 64;
        let bit_buf = if bit < 64 - 5 {
            x[idx] >> bit
        } else {
            (x[idx] >> bit) | (x[idx + 1] << (64 - bit))
        };
        let window = carry + (bit_buf & window_mask);
        if window & 1 == 0 {
            pos += 1;
            continue;
        }
        if window < width / 2 {
            carry = 0;
            naf[pos] = window as i8;
        } else {
            carry = 1;
            naf[pos] = (window as i8).wrapping_sub(width as i8);
        }
        pos += 5;
    }
    // A carry surviving past bit 255 stands for `+2^pos`; record it (pos is
    // at most 260, and the digit is always +1).
    if carry != 0 {
        naf[pos] = 1;
    }
    naf
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
                let e = table_point(entry, f.one);
                assert!(bool::from(f.ct_eq(f.mul(e.x, acc.z), acc.x)), "x mismatch");
                assert!(bool::from(f.ct_eq(f.mul(e.y, acc.z), acc.y)), "y mismatch");
                assert!(bool::from(f.ct_eq(f.mul(e.t, acc.z), acc.t)), "t mismatch");
            }
            base = f.point_double(&f.point_double(&f.point_double(&f.point_double(&base))));
        }
    }

    /// Differential test: the fixed-base comb agrees with the generic
    /// windowed ladder for edge scalars (0, 1, 2, L−1, L, L+1, 2²⁵⁵-ish,
    /// all-ones) and a batch of random ones — and the two vartime paths agree
    /// with their constant-time counterparts on every one of them.
    #[test]
    fn mul_base_matches_generic_scalar_mult() {
        use crate::hash::Sha256;
        use crate::rng::{HmacDrbg, RngCore};
        let f = Field::new();
        let b = f.base();

        let check = |s: &[u8; 32]| {
            let comb = f.encode(&f.mul_base(s));
            assert_eq!(
                comb,
                f.encode(&f.scalar_mult(s, &b)),
                "comb/ladder mismatch"
            );
            assert_eq!(
                comb,
                f.encode(&f.mul_base_vartime(s)),
                "vartime comb mismatch"
            );
            assert_eq!(
                comb,
                f.encode(&f.scalar_mult_vartime(s, &b)),
                "vartime wNAF mismatch"
            );
        };

        let int_bytes = |v: &ScalarInt| {
            let mut out = [0u8; 32];
            v.write_le_bytes(&mut out);
            out
        };
        let mut edges = [[0u8; 32]; 8];
        edges[1][0] = 1;
        edges[2][0] = 2;
        edges[3] = int_bytes(&f.l.wrapping_sub(&ScalarInt::ONE));
        edges[4] = int_bytes(&f.l);
        edges[5] = int_bytes(&f.l.wrapping_add(&ScalarInt::ONE));
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
        println!("pub(crate) static ED25519_BASE_TABLE: [[[u64; 15]; 15]; 64] = [");
        for _ in 0..64 {
            println!("    [");
            let mut acc = base;
            for j in 1..=15u32 {
                if j > 1 {
                    acc = f.point_add(&acc, &base);
                }
                // Affine (x, y, t = x·y), canonical plain residues, printed
                // as 51-bit limbs (fully reduced via the to/from bytes
                // round-trip).
                let zinv = f.inv(acc.z);
                let x = Fe::from_bytes(&f.mul(acc.x, zinv).to_bytes());
                let y = Fe::from_bytes(&f.mul(acc.y, zinv).to_bytes());
                let t = Fe::from_bytes(&f.mul(x, y).to_bytes());
                print!("        [");
                for l in x.0.iter().chain(y.0.iter()).chain(t.0.iter()) {
                    print!("0x{l:013x}, ");
                }
                println!("],");
            }
            println!("    ],");
            base = f.point_double(&f.point_double(&f.point_double(&f.point_double(&base))));
        }
        println!("];");
    }
}
