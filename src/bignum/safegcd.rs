//! Constant-time modular inversion modulo a public odd modulus of up to
//! nine 64-bit limbs by Bernstein–Yang "safegcd" divsteps ("Fast
//! constant-time gcd computation and modular inversion", TCHES 2019), in the
//! form of libsecp256k1's `modinv64` (Pieter Wuille's
//! `doc/safegcd_implementation.md`).
//!
//! Numbers are held as signed 62-bit limbs (`Σ vᵢ·2⁶²ⁱ`), `⌊64·LIMBS/62⌋ + 1`
//! of them (five for 256 bits). Each round runs 59 divsteps on the low 64
//! bits of `f`, `g` alone, collecting them into a 2×2 transition matrix
//! scaled by 2⁶², then applies that matrix to the full-width `(f, g)`
//! (dividing by 2⁶², exact) and to the Bézout coefficients `(d, e)` (made
//! exactly divisible by adding a multiple of the modulus chosen through
//! `m⁻¹ mod 2⁶²`).
//!
//! **Iteration bound.** This is the "half-delta" divstep (δ starts at ½,
//! tracked as `ζ = −(δ + ½)`), for which `⌊(45907·b + 26313) / 19929⌋`
//! divsteps reach `g = 0` for every `0 ≤ g < f < 2ᵇ` with `f` odd — the
//! bound established by the computer-verified convex-hull analysis of
//! sipa/safegcd-bounds, which libsecp256k1 relies on (after Bernstein–Yang
//! §11, whose closed-form theorem for the original δ = 1 divstep gives the
//! weaker ⌊(49·b + 57)/17⌋). For `b = 256` the exact computation gives
//! **590 divsteps, ten rounds** (the closed form, 591, is one step looser);
//! above 256 bits the closed form is used with one extra round of margin:
//! 384 bits need 885 (16 rounds), 448 bits 1033 (19), 521 bits 1201 (22).
//! The round count is derived from the modulus's bit length at construction
//! and is a public constant of the modulus; a debug assertion checks
//! `g = 0` at the end, and the tests hunt for 256-bit inputs with long
//! divstep chains (the longest found are ~535 steps).
//!
//! **Constant time.** Every round does the same work. Inside a divstep the
//! two data-dependent conditions (`δ > 0`, `g` odd) become all-ones/all-zero
//! masks that pass through an optimisation barrier (`barrier::opaque`), so
//! LLVM cannot re-materialise them as jumps; no memory index depends on the
//! input. The only branches are on the modulus limbs, which are public. The
//! 64×64→128 products are a multiply-instruction pair on 64-bit targets; on
//! 32-bit ones LLVM expands them inline into 32×32 multiplies (no
//! `__multi3` call on thumbv7em) — the same exposure as the crate's other
//! `u128` arithmetic.

use super::Uint;
use barrier::opaque;

/// The optimisation barrier behind every mask, as in `falcon::fpr`.
///
/// On x86-64 and AArch64 an empty `asm!` block names the value as a
/// read/write register operand: no instruction is emitted, but the optimizer
/// must treat the result as unknown, so it cannot prove a mask is a
/// comparison result and turn the masked arithmetic into a branch. Elsewhere
/// it falls back to [`core::hint::black_box`], which does the same through a
/// memory round-trip — on the serial divstep chain that round-trip nearly
/// doubles the inversion time (2.2 µs against 1.2 µs on AArch64), hence the
/// fast path. The `unsafe` opt-in is scoped to this module, per the crate's
/// `unsafe_code = "deny"` policy.
mod barrier {
    #![allow(unsafe_code)]

    /// Returns `x` as a value the optimizer knows nothing about.
    #[inline(always)]
    pub(super) fn opaque(x: u64) -> u64 {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let mut v = x;
            // SAFETY: the template is a comment only; it executes nothing,
            // names `v` as its sole (register) operand, and touches no memory.
            unsafe {
                core::arch::asm!(
                    "/* {0} */",
                    inout(reg) v,
                    options(pure, nomem, nostack, preserves_flags)
                );
            }
            v
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            core::hint::black_box(x)
        }
    }
}

/// The low-62-bit mask.
const M62: u64 = u64::MAX >> 2;

/// Divsteps per round (the matrix is collected over 59 steps so its entries
/// fit `2⁶²`-scaled `i64`s).
const DIVSTEPS_PER_ROUND: usize = 59;

/// The widest modulus supported, in 64-bit limbs (P-521 in nine limbs).
const MAX_LIMBS: usize = 9;

/// Signed-62 limbs covering `MAX_LIMBS` 64-bit limbs: `⌊64·9/62⌋ + 1`. The
/// arrays are sized for the maximum; every loop runs to the width in use
/// (`N62`, a constant per `LIMBS`), so the 256-bit path only pays the
/// larger stack frame.
const S: usize = 10;

/// The divstep bound for inputs below `2^bits` (see the module docs): the
/// exact, computer-verified 590 up to 256 bits (the closed form gives 591
/// there), the closed form `⌊(45907·bits + 26313) / 19929⌋` above.
const fn divstep_bound(bits: usize) -> usize {
    if bits <= 256 {
        590
    } else {
        (45907 * bits + 26313) / 19929
    }
}

/// 59-divstep rounds for a `bits`-bit modulus: the bound rounded up to
/// whole rounds, plus one round of margin above 256 bits, where the bound
/// is the closed form rather than the exact convex-hull computation.
const fn rounds_for(bits: usize) -> usize {
    let rounds = divstep_bound(bits).div_ceil(DIVSTEPS_PER_ROUND);
    if bits <= 256 { rounds } else { rounds + 1 }
}

/// A 2×2 divstep transition matrix `[[u, v], [q, r]]`, scaled by 2⁶².
/// Entries lie in `[−2⁶², 2⁶²]` and `|u| + |v|, |q| + |r| ≤ 2⁶²`.
struct Trans {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// A public odd modulus `m < 2^(64·LIMBS)`, `LIMBS ≤ 9`, prepared for
/// [`invert`](Self::invert). The default width is the 256-bit curves'.
pub(crate) struct SafegcdModulus<const LIMBS: usize = 4> {
    /// `m` in signed-62 form (limbs `N62..` unused).
    m: [i64; S],
    /// `m⁻¹ mod 2⁶²`.
    m_inv62: u64,
    /// 59-divstep rounds covering the proven bound for `m`'s bit length.
    rounds: usize,
}

/// Splits `LIMBS` 64-bit limbs into `n62` 62-bit ones (all non-negative).
const fn to_signed62<const LIMBS: usize>(a: &[u64; LIMBS], n62: usize) -> [i64; S] {
    let mut out = [0i64; S];
    let mut i = 0;
    while i < n62 {
        let bit = 62 * i;
        let (w, sh) = (bit / 64, bit % 64);
        let mut v = if w < LIMBS { a[w] >> sh } else { 0 };
        // With `sh ≤ 2` the 62 bits lie within one word.
        if sh > 2 && w + 1 < LIMBS {
            v |= a[w + 1] << (64 - sh);
        }
        out[i] = (v & M62) as i64;
        i += 1;
    }
    out
}

/// Joins normalised 62-bit limbs (`vᵢ ∈ [0, 2⁶²)`, the value below
/// `2^(64·LIMBS)`).
fn from_signed62<const LIMBS: usize>(v: &[i64; S], n62: usize) -> [u64; LIMBS] {
    let mut out = [0u64; LIMBS];
    for (i, &x) in v.iter().enumerate().take(n62) {
        let x = x as u64;
        let bit = 62 * i;
        let (w, sh) = (bit / 64, bit % 64);
        if w < LIMBS {
            out[w] |= x << sh;
        }
        if sh > 2 && w + 1 < LIMBS {
            out[w + 1] |= x >> (64 - sh);
        }
    }
    out
}

impl<const LIMBS: usize> SafegcdModulus<LIMBS> {
    /// Signed-62 limbs in use: `62·N62 > 64·LIMBS`, leaving at least 30
    /// bits of headroom in the top limb for the sign and the `(−2m, m)`
    /// range of the Bézout coefficients.
    const N62: usize = 64 * LIMBS / 62 + 1;

    /// Prepares an odd modulus (compile-time constructible).
    ///
    /// The round count is `⌈bound / 59⌉` for the divstep bound of the
    /// modulus's bit length (a public quantity of a public modulus).
    pub(crate) const fn new(m: &Uint<LIMBS>) -> Self {
        assert!(
            LIMBS >= 1 && LIMBS <= MAX_LIMBS,
            "safegcd supports moduli of 1 to 9 limbs"
        );
        let l = m.as_limbs();
        assert!(l[0] & 1 == 1, "safegcd modulus must be odd");
        // Newton's iteration x ← x·(2 − m·x) doubles the correct low bits;
        // x = m is right mod 8 for any odd m, so five steps give 96 ≥ 62.
        let mut x = l[0];
        let mut i = 0;
        while i < 5 {
            x = x.wrapping_mul(2u64.wrapping_sub(l[0].wrapping_mul(x)));
            i += 1;
        }
        let mut top = LIMBS;
        while top > 1 && l[top - 1] == 0 {
            top -= 1;
        }
        let bits = 64 * top - l[top - 1].leading_zeros() as usize;
        SafegcdModulus {
            m: to_signed62(l, Self::N62),
            m_inv62: x & M62,
            rounds: rounds_for(bits),
        }
    }

    /// `a⁻¹ mod m` in `[0, m)`, constant time in `a`; requires `a < m` and
    /// `m` prime (or at least `gcd(a, m) = 1`), and maps `0` to `0`.
    pub(crate) fn invert(&self, a: &Uint<LIMBS>) -> Uint<LIMBS> {
        let n = Self::N62;
        let mut d = [0i64; S];
        let mut e = [0i64; S];
        e[0] = 1;
        let mut f = self.m;
        let mut g = to_signed62(a.as_limbs(), n);
        let mut zeta: i64 = -1; // ζ = −(δ + ½), δ = ½.
        for _ in 0..self.rounds {
            let (z, t) = divsteps_59(zeta, f[0] as u64, g[0] as u64);
            zeta = z;
            self.update_de(&mut d, &mut e, &t);
            update_fg(&mut f, &mut g, &t, n);
        }
        // g = 0, f = ±gcd = ±1 and d = ±a⁻¹ (for a = 0: f = m, d = 0).
        debug_assert!(g == [0; S], "safegcd: g did not reach 0 within the bound");
        self.normalize(&mut d, f[n - 1]);
        Uint::from_limbs(from_signed62(&d, n))
    }

    /// `(d, e) ← (t·(d, e) + m·(md, me)) / 2⁶²`, with `md`, `me` chosen to
    /// make the division exact and to keep `d`, `e` in `(−2m, m)`.
    #[inline(always)]
    fn update_de(&self, d: &mut [i64; S], e: &mut [i64; S], t: &Trans) {
        let n = Self::N62;
        let m = &self.m;
        let (u, v, q, r) = (t.u as i128, t.v as i128, t.q as i128, t.r as i128);
        // Start (md, me) at [u, q] if d < 0 plus [v, r] if e < 0: this, with
        // the correction below, keeps the outputs in range.
        let sd = opaque((d[n - 1] >> 63) as u64) as i64;
        let se = opaque((e[n - 1] >> 63) as u64) as i64;
        let mut md = (t.u & sd).wrapping_add(t.v & se);
        let mut me = (t.q & sd).wrapping_add(t.r & se);
        let mut cd = u * d[0] as i128 + v * e[0] as i128;
        let mut ce = q * d[0] as i128 + r * e[0] as i128;
        // Correct md, me so the low 62 bits of cd + m·md vanish.
        md = md.wrapping_sub(
            (self.m_inv62.wrapping_mul(cd as u64).wrapping_add(md as u64) & M62) as i64,
        );
        me = me.wrapping_sub(
            (self.m_inv62.wrapping_mul(ce as u64).wrapping_add(me as u64) & M62) as i64,
        );
        cd += m[0] as i128 * md as i128;
        ce += m[0] as i128 * me as i128;
        debug_assert!(cd as u64 & M62 == 0 && ce as u64 & M62 == 0);
        cd >>= 62;
        ce >>= 62;
        for i in 1..n {
            cd += u * d[i] as i128 + v * e[i] as i128;
            ce += q * d[i] as i128 + r * e[i] as i128;
            // Always multiply, even by a zero modulus limb: a "skip zero
            // limbs" branch on the public modulus was folded by LLVM on
            // 32-bit ARM into a branch on secret-derived halves (flagged by
            // the Valgrind armv7 run), and the saved multiplies are noise.
            cd += m[i] as i128 * md as i128;
            ce += m[i] as i128 * me as i128;
            d[i - 1] = (cd as u64 & M62) as i64;
            e[i - 1] = (ce as u64 & M62) as i64;
            cd >>= 62;
            ce >>= 62;
        }
        d[n - 1] = cd as i64;
        e[n - 1] = ce as i64;
    }

    /// Brings `d ∈ (−2m, m)` to `sign(f)·d mod m ∈ [0, m)` with masked adds.
    #[inline(always)]
    fn normalize(&self, d: &mut [i64; S], f_top: i64) {
        let n = Self::N62;
        let m = &self.m;
        // Add m if negative: (−2m, m) → (−m, m).
        let add = opaque((d[n - 1] >> 63) as u64) as i64;
        for i in 0..n {
            d[i] += m[i] & add;
        }
        // Negate if f = −1.
        let neg = opaque((f_top >> 63) as u64) as i64;
        for x in d.iter_mut().take(n) {
            *x = (*x ^ neg).wrapping_sub(neg);
        }
        carry62(d, n);
        // Add m again if still negative: (−m, m) → [0, m).
        let add = opaque((d[n - 1] >> 63) as u64) as i64;
        for i in 0..n {
            d[i] += m[i] & add;
        }
        carry62(d, n);
    }
}

/// Propagates carries so limbs `0..n−1` lie in `[0, 2⁶²)` (signed arithmetic
/// shifts move each limb's excess, negative or not, upward).
#[inline(always)]
fn carry62(d: &mut [i64; S], n: usize) {
    for i in 0..n - 1 {
        d[i + 1] += d[i] >> 62;
        d[i] &= M62 as i64;
    }
}

/// 59 half-delta divsteps on the low 64 bits of `f` (odd) and `g`, returning
/// the new `ζ` and the transition matrix scaled by 2⁶² (the identity starts
/// at 2³ so the 59 doublings land on 2⁶²). All arithmetic is mod 2⁶⁴; the
/// matrix entries stay within `[−2⁶², 2⁶²]` so the final casts are exact.
#[inline(always)]
fn divsteps_59(mut zeta: i64, f0: u64, g0: u64) -> (i64, Trans) {
    let (mut u, mut v, mut q, mut r) = (8u64, 0u64, 0u64, 8u64);
    let (mut f, mut g) = (f0, g0);
    for _ in 3..62 {
        debug_assert!(f & 1 == 1);
        // c1: δ > 0 (ζ < 0); c2: g odd.
        let c1 = opaque((zeta >> 63) as u64);
        let c2 = opaque((g & 1).wrapping_neg());
        // If g is odd, add (−1)^c1 · (f, u, v) to (g, q, r).
        let x = (f ^ c1).wrapping_sub(c1);
        let y = (u ^ c1).wrapping_sub(c1);
        let z = (v ^ c1).wrapping_sub(c1);
        g = g.wrapping_add(x & c2);
        q = q.wrapping_add(y & c2);
        r = r.wrapping_add(z & c2);
        // If both, swap in the old g: f += (g − f), i.e. f ← g, and
        // δ ← 1 − δ (ζ ← −ζ − 2); otherwise δ ← δ + 1 (ζ ← ζ − 1).
        let c = c1 & c2;
        zeta = (zeta ^ c as i64).wrapping_sub(1);
        f = f.wrapping_add(g & c);
        u = u.wrapping_add(q & c);
        v = v.wrapping_add(r & c);
        // g ← g / 2 (exact: g is now even); scale (u, v) instead of halving
        // (q, r).
        g >>= 1;
        u <<= 1;
        v <<= 1;
    }
    let t = Trans {
        u: u as i64,
        v: v as i64,
        q: q as i64,
        r: r as i64,
    };
    (zeta, t)
}

/// `(f, g) ← t·(f, g) / 2⁶²` (exact by construction of `t`), over `n` limbs.
#[inline(always)]
fn update_fg(f: &mut [i64; S], g: &mut [i64; S], t: &Trans, n: usize) {
    let (u, v, q, r) = (t.u as i128, t.v as i128, t.q as i128, t.r as i128);
    let mut cf = u * f[0] as i128 + v * g[0] as i128;
    let mut cg = q * f[0] as i128 + r * g[0] as i128;
    debug_assert!(cf as u64 & M62 == 0 && cg as u64 & M62 == 0);
    cf >>= 62;
    cg >>= 62;
    for i in 1..n {
        cf += u * f[i] as i128 + v * g[i] as i128;
        cg += q * f[i] as i128 + r * g[i] as i128;
        f[i - 1] = (cf as u64 & M62) as i64;
        g[i - 1] = (cg as u64 & M62) as i64;
        cf >>= 62;
        cg >>= 62;
    }
    f[n - 1] = cf as i64;
    g[n - 1] = cg as i64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::MontModulus;

    const MODULI: [(&str, &str); 4] = [
        (
            "secp256k1 p",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        ),
        (
            "secp256k1 n",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        ),
        (
            "P-256 p",
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ),
        (
            "P-256 n",
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        ),
    ];

    fn hex(s: &str) -> Uint<4> {
        crate::ec::uint_from_be_hex(s)
    }

    struct SplitMix64(u64);
    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, m: &Uint<4>) -> Uint<4> {
            // Uniform-enough draws, plus sparse / run-heavy shapes.
            let mut l = [self.next(), self.next(), self.next(), self.next()];
            match self.next() % 4 {
                0 => l = l.map(|x| x & self.next() & self.next()),
                1 => l = l.map(|x| x | self.next() | self.next()),
                _ => {}
            }
            Uint::from_limbs(l).reduce(m)
        }
    }

    /// Full-precision half-delta divstep count until `g = 0` (320-bit two's
    /// complement), the quantity the 590 bound is about.
    fn divstep_count(m: &Uint<4>, a: &Uint<4>) -> u32 {
        fn add(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
            let mut out = [0; 5];
            let mut c = 0u64;
            for i in 0..5 {
                let (s1, o1) = a[i].overflowing_add(b[i]);
                let (s2, o2) = s1.overflowing_add(c);
                out[i] = s2;
                c = (o1 | o2) as u64;
            }
            out
        }
        fn neg(a: &[u64; 5]) -> [u64; 5] {
            add(&a.map(|x| !x), &[1, 0, 0, 0, 0])
        }
        fn sar1(a: &[u64; 5]) -> [u64; 5] {
            let mut out = [0; 5];
            for i in 0..4 {
                out[i] = a[i] >> 1 | a[i + 1] << 63;
            }
            out[4] = ((a[4] as i64) >> 1) as u64;
            out
        }
        let wide = |x: &Uint<4>| {
            let l = x.as_limbs();
            [l[0], l[1], l[2], l[3], 0]
        };
        let (mut f, mut g) = (wide(m), wide(a));
        let mut delta2: i64 = 1; // 2δ
        let mut n = 0;
        while g != [0; 5] {
            if delta2 > 0 && g[0] & 1 == 1 {
                (f, g) = (g, sar1(&add(&g, &neg(&f))));
                delta2 = 2 - delta2;
            } else if g[0] & 1 == 1 {
                g = sar1(&add(&g, &f));
                delta2 += 2;
            } else {
                g = sar1(&g);
                delta2 += 2;
            }
            n += 1;
        }
        n
    }

    fn check(name: &str, sg: &SafegcdModulus, mm: &MontModulus<4>, a: &Uint<4>) {
        let got = sg.invert(a);
        let want = mm.inv_prime(a);
        assert_eq!(
            got.as_limbs(),
            want.as_limbs(),
            "{name}: a={:x?}",
            a.as_limbs()
        );
    }

    #[test]
    fn modinfo_constants() {
        for (name, h) in MODULI {
            let m = hex(h);
            let sg = SafegcdModulus::new(&m);
            assert_eq!(from_signed62(&sg.m, 5), *m.as_limbs(), "{name}");
            assert_eq!(sg.m_inv62.wrapping_mul(m.as_limbs()[0]) & M62, 1, "{name}");
            assert_eq!(sg.rounds, 10, "{name}: 590 divsteps = 10 rounds");
            assert_eq!(SafegcdModulus::<4>::N62, 5);
        }
        assert_eq!(divstep_bound(256), 590);
        assert_eq!((45907 * 256 + 26313) / 19929, 591);
        assert_eq!(divstep_bound(384), 885);
        assert_eq!(divstep_bound(448), 1033);
        assert_eq!(divstep_bound(521), 1201);
        assert_eq!(rounds_for(255), 10);
        assert_eq!(rounds_for(384), 16);
        assert_eq!(rounds_for(448), 19);
        assert_eq!(rounds_for(521), 22);
    }

    #[cfg(feature = "alloc")]
    fn hex_wide<const L: usize>(s: &str) -> Uint<L> {
        let bytes: alloc::vec::Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect();
        Uint::from_be_bytes(&bytes)
    }

    /// Wider moduli: the P-384 and P-521 field primes and group orders,
    /// against Fermat, on edges, powers of two and random residues; the
    /// signed-62 conversions round-trip; the round counts match the bound.
    #[cfg(feature = "alloc")]
    fn wide_matches_fermat<const L: usize>(
        name: &str,
        h: &str,
        rounds: usize,
        rng: &mut SplitMix64,
    ) {
        let m = hex_wide::<L>(h);
        let sg = SafegcdModulus::<L>::new(&m);
        assert_eq!(sg.rounds, rounds, "{name}");
        let n = SafegcdModulus::<L>::N62;
        assert_eq!(
            from_signed62::<L>(&to_signed62(m.as_limbs(), n), n),
            *m.as_limbs()
        );
        let mm = MontModulus::new(m);
        let one = Uint::ONE;
        let m1 = m.wrapping_sub(&one);
        let chk = |a: &Uint<L>| {
            let got = sg.invert(a);
            let want = mm.inv_prime(a);
            assert_eq!(
                got.as_limbs(),
                want.as_limbs(),
                "{name}: a={:x?}",
                a.as_limbs()
            );
        };
        assert_eq!(sg.invert(&Uint::ZERO), Uint::ZERO, "{name}: 0");
        for a in [one, Uint::from_u64(2), Uint::from_u64(3), m1, m1.shr1()] {
            chk(&a);
        }
        for k in (0..64 * L).step_by(7) {
            let mut l = [0u64; L];
            l[k / 64] = 1 << (k % 64);
            let p2 = Uint::from_limbs(l);
            for x in [p2, p2.wrapping_sub(&one), m.wrapping_sub(&p2)] {
                chk(&x.reduce(&m));
            }
        }
        for _ in 0..300 {
            let mut l = [0u64; L];
            for w in l.iter_mut() {
                *w = rng.next();
            }
            chk(&Uint::from_limbs(l).reduce(&m));
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn matches_fermat_384_and_521() {
        let mut rng = SplitMix64(0x5a3e_9cd1_0384_0521);
        wide_matches_fermat::<6>(
            "P-384 p",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
            16,
            &mut rng,
        );
        wide_matches_fermat::<6>(
            "P-384 n",
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            16,
            &mut rng,
        );
        wide_matches_fermat::<9>(
            "P-521 p",
            "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            22,
            &mut rng,
        );
        wide_matches_fermat::<9>(
            "P-521 n",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
            22,
            &mut rng,
        );
        // A 7-limb odd prime (2^448 − 2^224 − 1, curve448's field).
        wide_matches_fermat::<7>(
            "curve448 p",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            19,
            &mut rng,
        );
    }

    #[test]
    fn matches_fermat_on_edges_and_random() {
        let mut rng = SplitMix64(0x5afe_9cd0);
        for (name, h) in MODULI {
            let m = hex(h);
            let sg = SafegcdModulus::new(&m);
            let mm = MontModulus::new(m);
            assert_eq!(sg.invert(&Uint::ZERO).as_limbs(), &[0; 4], "{name}: 0");
            let one = Uint::ONE;
            let m1 = m.wrapping_sub(&one);
            let chk = |a: &Uint<4>| {
                if !bool::from(a.is_zero()) {
                    assert!(divstep_count(&m, a) <= 590, "{name}");
                }
                check(name, &sg, &mm, a);
            };
            for a in [
                one,
                Uint::from_u64(2),
                Uint::from_u64(3),
                m1,
                m.wrapping_sub(&Uint::from_u64(2)),
                m1.shr1(),
                m1.shr1().wrapping_add(&one),
                Uint::from_limbs([u64::MAX; 4]).reduce(&m),
            ] {
                chk(&a);
            }
            for k in 0..256 {
                // 2^k, 2^k − 1, 2^k + 1, m − 2^k (all reduced below m).
                let mut l = [0u64; 4];
                l[k / 64] = 1 << (k % 64);
                let p2 = Uint::from_limbs(l);
                for x in [
                    p2,
                    p2.wrapping_sub(&one),
                    p2.wrapping_add(&one),
                    m.wrapping_sub(&p2),
                ] {
                    chk(&x.reduce(&m));
                }
                // Alternating runs of k + 1 ones / zeros.
                let mut l = [0u64; 4];
                for b in 0..256 {
                    if (b / (k + 1)) % 2 == 0 {
                        l[b / 64] |= 1 << (b % 64);
                    }
                }
                chk(&Uint::from_limbs(l).reduce(&m));
            }
            for _ in 0..20_000 {
                let a = rng.below(&m);
                check(name, &sg, &mm, &a);
            }
        }
    }

    /// Hill-climbs toward inputs with long divstep chains (the regime the
    /// fixed 590 count must cover) and checks they still invert correctly.
    #[test]
    fn long_divstep_chains() {
        let mut rng = SplitMix64(0xd157_7e95);
        for (name, h) in MODULI {
            let m = hex(h);
            let sg = SafegcdModulus::new(&m);
            let mm = MontModulus::new(m);
            for _ in 0..8 {
                let mut a = rng.below(&m);
                let mut best = divstep_count(&m, &a);
                for _ in 0..400 {
                    let mut l = *a.as_limbs();
                    for _ in 0..(1 + rng.next() % 3) {
                        let b = (rng.next() % 256) as usize;
                        l[b / 64] ^= 1 << (b % 64);
                    }
                    let c = Uint::from_limbs(l).reduce(&m);
                    if bool::from(c.is_zero()) {
                        continue;
                    }
                    let n = divstep_count(&m, &c);
                    if n >= best {
                        (a, best) = (c, n);
                    }
                }
                assert!(best <= 590, "{name}: {best} divsteps");
                check(name, &sg, &mm, &a);
            }
        }
    }
}
