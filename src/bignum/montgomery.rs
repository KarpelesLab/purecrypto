//! Constant-time modular arithmetic in Montgomery form.
//!
//! For an odd modulus `N` of `LIMBS` limbs and `R = 2^(64*LIMBS)`, a value `x`
//! is represented in *Montgomery form* as `xR mod N`. The product of two
//! Montgomery-form values is computed with [`MontModulus::mont_mul`], which
//! yields `abR^-1 mod N` — i.e. the Montgomery form of `ab mod N` — using the
//! CIOS algorithm with no data-dependent branches.

use super::Uint;
use super::mul::mac;
use super::uint::{Limb, adc, sbb};

/// Computes `n^-1 mod 2^64` for odd `n` via Newton's iteration (each step
/// doubles the number of correct low bits; six steps cover 64 bits). Shared
/// with [`super::boxed_montgomery`].
pub(crate) const fn inv_mod_2_64(n: u64) -> u64 {
    let mut x = 1u64; // correct mod 2 (n is odd)
    let mut i = 0;
    while i < 6 {
        x = x.wrapping_mul(2u64.wrapping_sub(n.wrapping_mul(x)));
        i += 1;
    }
    x
}

/// Returns `a` when `bit == 1`, `b` when `bit == 0`, without branching on
/// `bit`. A `const` counterpart of
/// [`ConditionallySelectable::conditional_select`]
/// with the same `black_box`-masked limb select, so that [`add_mod`],
/// [`sub_mod`], [`MontModulus::new`] and [`MontModulus::mont_mul`] can run at
/// compile time while staying
/// constant time when called at runtime on secret moduli (RSA primes).
#[inline]
const fn select<const LIMBS: usize>(a: &Uint<LIMBS>, b: &Uint<LIMBS>, bit: Limb) -> Uint<LIMBS> {
    // All-ones when bit is 1, all-zeros when 0.
    let mask = core::hint::black_box(bit.wrapping_neg());
    let a = a.as_limbs();
    let b = b.as_limbs();
    let mut limbs = [0 as Limb; LIMBS];
    let mut i = 0;
    while i < LIMBS {
        limbs[i] = b[i] ^ (mask & (a[i] ^ b[i]));
        i += 1;
    }
    Uint::from_limbs(limbs)
}

/// Conditional final subtraction shared by the Montgomery kernels: the
/// `(l + 1)`-limb value `(t, ts)` is `< 2n`; `out ← t − n` when it is `≥ n`,
/// else `out ← t`. One opaque mask for the whole select — `black_box` on the
/// comparison verdict, then plain `&`/`^` across the limbs — so there is
/// neither a branch nor a per-limb barrier.
///
/// `out` may alias `t`'s source only through the caller's buffers (the
/// borrow checker forbids literal aliasing); it is written limb by limb
/// after `t[j]` is read, so an `out == t` buffer would also be correct.
#[inline(always)]
pub(crate) const fn mont_final_sub(n: &[Limb], t: &[Limb], ts: Limb, out: &mut [Limb]) {
    let l = n.len();
    let mut bo: Limb = 0;
    let mut j = 0;
    while j < l {
        let (d, b) = sbb(t[j], n[j], bo);
        out[j] = d;
        bo = b;
        j += 1;
    }
    let (_, borrow) = sbb(ts, 0, bo);
    // All-ones when (t, ts) >= n (no borrow): keep the difference.
    let mask = core::hint::black_box((borrow ^ 1).wrapping_neg());
    let mut j = 0;
    while j < l {
        out[j] = t[j] ^ (mask & (out[j] ^ t[j]));
        j += 1;
    }
}

/// CIOS Montgomery multiplication kernel over limb slices: `out ← a·b·R⁻¹
/// mod n` for `R = 2^(64·l)`, `l = n.len()`, `n` odd with `n' = −n⁻¹ mod
/// 2^64`, and `a, b < n` (one operand may be any value `< R`; the result is
/// then `< 2n` before the final subtraction, which still brings it below
/// `n` — [`super::BoxedMontModulus::reduce`] relies on this). `t` is `l`
/// limbs of scratch; `out` receives `l` limbs. Wider slices are cut to `l`
/// up front so the bounds checks hoist out of the loops.
///
/// Each CIOS row is *merged*: the `a·b[i]` accumulation and the `m·n`
/// reduction run in one pass with two independent carry chains, so the
/// row-`i` accumulator is read and written once instead of twice. Rows are
/// then taken two at a time — row `i + 1` consumes row `i`'s output one
/// limb behind, so the pair streams through `t` in a single pass with four
/// carry chains in flight — and an odd `l` finishes with one single-row
/// step. Every loop bound is a function of `l` alone; the only conditional
/// is the odd-`l` tail, a public width.
///
/// `const` so that [`MontModulus::new`] can run at compile time; at runtime
/// the same code is constant time in `a`, `b` and `n`.
#[inline(always)]
pub(crate) const fn mont_mul_kernel(
    n: &[Limb],
    np: Limb,
    a: &[Limb],
    b: &[Limb],
    t: &mut [Limb],
    out: &mut [Limb],
) {
    let l = n.len();
    let (a, _) = a.split_at(l);
    let (b, _) = b.split_at(l);
    let (t, _) = t.split_at_mut(l);
    let mut j = 0;
    while j < l {
        t[j] = 0;
        j += 1;
    }
    // `t` is the accumulator's low `l` limbs; `ts` its limb `l` (at most 1:
    // the accumulator stays below `a + n < 2n` after every row).
    let mut ts: Limb = 0;
    let mut i = 0;
    while i + 1 < l {
        let b0 = b[i];
        let b1 = b[i + 1];
        // Row i, column 0: decides m0; the low limb cancels.
        let (s0, mut c1) = mac(t[0], a[0], b0, 0);
        let m0 = s0.wrapping_mul(np);
        let (_, mut c2) = mac(s0, m0, n[0], 0);
        // Row i, column 1 -> row-i output limb 0, which row i + 1 consumes
        // at once (its column 0, deciding m1).
        let (s, cc1) = mac(t[1], a[1], b0, c1);
        c1 = cc1;
        let (tp0, cc2) = mac(s, m0, n[1], c2);
        c2 = cc2;
        let (u0, mut d1) = mac(tp0, a[0], b1, 0);
        let m1 = u0.wrapping_mul(np);
        let (_, mut d2) = mac(u0, m1, n[0], 0);
        // Column j of row i is column j − 1 of row i + 1, whose result is
        // limb j − 2 of the pair's output.
        let mut j = 2;
        while j < l {
            let (s, cc1) = mac(t[j], a[j], b0, c1);
            c1 = cc1;
            let (tpj1, cc2) = mac(s, m0, n[j], c2);
            c2 = cc2;
            let (u, dd1) = mac(tpj1, a[j - 1], b1, d1);
            d1 = dd1;
            let (u2, dd2) = mac(u, m1, n[j - 1], d2);
            d2 = dd2;
            t[j - 2] = u2;
            j += 1;
        }
        // Row i's top: limb l − 1 of its output is ts + c1 + c2, limb l the
        // carry out of that sum.
        let s = ts as u128 + c1 as u128 + c2 as u128;
        let tpl1 = s as Limb;
        let tpl = (s >> 64) as Limb;
        let (u, dd1) = mac(tpl1, a[l - 1], b1, d1);
        d1 = dd1;
        let (u2, dd2) = mac(u, m1, n[l - 1], d2);
        d2 = dd2;
        t[l - 2] = u2;
        let s = tpl as u128 + d1 as u128 + d2 as u128;
        t[l - 1] = s as Limb;
        ts = (s >> 64) as Limb;
        i += 2;
    }
    if i < l {
        // Odd width: one merged single row for b[l − 1].
        let bi = b[i];
        let (s0, mut c1) = mac(t[0], a[0], bi, 0);
        let m = s0.wrapping_mul(np);
        let (_, mut c2) = mac(s0, m, n[0], 0);
        let mut j = 1;
        while j < l {
            let (s, cc1) = mac(t[j], a[j], bi, c1);
            c1 = cc1;
            let (s2, cc2) = mac(s, m, n[j], c2);
            c2 = cc2;
            t[j - 1] = s2;
            j += 1;
        }
        let s = ts as u128 + c1 as u128 + c2 as u128;
        t[l - 1] = s as Limb;
        ts = (s >> 64) as Limb;
    }
    mont_final_sub(n, t, ts, out);
}

/// Montgomery squaring kernel over limb slices: `out ← a²·R⁻¹ mod n`,
/// bit-identical to [`mont_mul_kernel`]`(a, a)`, for `a < n`. `p` is
/// `2·l` limbs of scratch holding the full square; `out` receives `l` limbs.
///
/// The square is formed with the usual optimisation — each off-diagonal
/// product `a[i]·a[j]` (`i < j`) once, the triangle doubled by a shift,
/// then the diagonal `a[i]²` added — and the triangle itself takes two rows
/// per pass (row `i + 1` trailing row `i` by one column). The Montgomery
/// reduction is a separate SOS pass over the `2·l`-limb product, also two
/// rows per pass: `m_{i+1}` is decided from row `i`'s updated limb `i + 1`,
/// then both `m·n` rows stream through the product together. Odd `l` ends
/// each phase with a single-row step.
///
/// Constant time: every loop bound and every conditional is a function of
/// `l` and the loop indices (public widths); the doubling is an
/// unconditional shift across the whole product, and the final subtraction
/// is the shared one-mask select.
#[inline(always)]
pub(crate) fn mont_sqr_kernel(n: &[Limb], np: Limb, a: &[Limb], p: &mut [Limb], out: &mut [Limb]) {
    let l = n.len();
    let a = &a[..l];
    let p = &mut p[..2 * l];
    p.fill(0);

    // Off-diagonal triangle, rows i and i + 1 together. Row i writes columns
    // 2i+1 ..= i+l−1 and drops its carry into i+l; row i + 1 writes columns
    // 2i+3 ..= i+l and its carry into i+l+1. From column 2i+3 on both rows
    // contribute, so the merged loop pipelines row i one column ahead.
    let mut i = 0;
    while i + 1 < l {
        let ai = a[i];
        let ai1 = a[i + 1];
        let (s, mut c0) = mac(p[2 * i + 1], ai, ai1, 0);
        p[2 * i + 1] = s;
        let mut c1: Limb = 0;
        if i + 2 < l {
            let (s, cc0) = mac(p[2 * i + 2], ai, a[i + 2], c0);
            c0 = cc0;
            p[2 * i + 2] = s;
        }
        for j in (i + 3)..l {
            let (s, cc0) = mac(p[i + j], ai, a[j], c0);
            c0 = cc0;
            let (s2, cc1) = mac(s, ai1, a[j - 1], c1);
            c1 = cc1;
            p[i + j] = s2;
        }
        if i + 3 <= l {
            // Row i + 1's last product lands on row i's carry column.
            let (s2, cc1) = mac(c0, ai1, a[l - 1], c1);
            p[i + l] = s2;
            p[i + l + 1] = cc1;
        } else {
            p[i + l] = c0;
        }
        i += 2;
    }
    // (An odd l leaves row l − 1, which has no off-diagonal products.)

    // Double the triangle: 2S <= a² < 2^(128·l), so the shift cannot carry
    // out of the 2l-limb product.
    let mut carry: Limb = 0;
    for w in p.iter_mut() {
        let next = *w >> 63;
        *w = (*w << 1) | carry;
        carry = next;
    }

    // Add the diagonal a[i]² at (2i, 2i+1); the odd position's carry-out is
    // the next even position's carry-in. The total is a², so the last carry
    // out is zero.
    let mut carry: Limb = 0;
    for i in 0..l {
        let (s, c) = mac(p[2 * i], a[i], a[i], carry);
        p[2 * i] = s;
        let (s, c2) = adc(p[2 * i + 1], c, 0);
        p[2 * i + 1] = s;
        carry = c2;
    }

    // SOS reduction, two rows per pass. `hi` is the carry riding above the
    // top limb a pass touched (position i + l + 2 for a pair, i + l + 1 for
    // the odd tail), which is exactly where the next pass's top add lands.
    let mut hi: Limb = 0;
    let mut i = 0;
    while i + 1 < l {
        let m0 = p[i].wrapping_mul(np);
        let (_, mut c0) = mac(p[i], m0, n[0], 0);
        // Row i, column i + 1: its result decides m1.
        let (s, cc) = mac(p[i + 1], m0, n[1], c0);
        c0 = cc;
        let m1 = s.wrapping_mul(np);
        let (_, mut c1) = mac(s, m1, n[0], 0);
        for j in 2..l {
            let (s, cc) = mac(p[i + j], m0, n[j], c0);
            c0 = cc;
            let (s2, cc1) = mac(s, m1, n[j - 1], c1);
            c1 = cc1;
            p[i + j] = s2;
        }
        // Column i + l: row i's carry (plus the riding carry) and row
        // i + 1's last product; column i + l + 1: the two carries out.
        let s = p[i + l] as u128 + c0 as u128 + hi as u128;
        let (s2, cc1) = mac(s as Limb, m1, n[l - 1], c1);
        p[i + l] = s2;
        let s3 = p[i + l + 1] as u128 + cc1 as u128 + (s >> 64);
        p[i + l + 1] = s3 as Limb;
        hi = (s3 >> 64) as Limb;
        i += 2;
    }
    if i < l {
        // Odd width: one single row.
        let m = p[i].wrapping_mul(np);
        let mut carry: Limb = 0;
        for j in 0..l {
            let (s, c) = mac(p[i + j], m, n[j], carry);
            p[i + j] = s;
            carry = c;
        }
        let (s, c) = adc(p[i + l], carry, hi);
        p[i + l] = s;
        hi = c;
    }

    // The result is the (l+1)-limb value (p[l..2l], hi) < 2n.
    mont_final_sub(n, &p[l..], hi, out);
}

/// Returns `(a + b) mod n`, assuming `a, b < n`.
const fn add_mod<const LIMBS: usize>(
    n: &Uint<LIMBS>,
    a: &Uint<LIMBS>,
    b: &Uint<LIMBS>,
) -> Uint<LIMBS> {
    let (sum, carry) = a.adc(b, 0);
    let (diff, borrow) = sum.sbb(n, 0);
    // Subtract n when the sum overflowed (carry) or sum >= n (no borrow).
    let subtract = carry | (borrow ^ 1);
    select(&diff, &sum, subtract)
}

/// Returns `(a - b) mod n`, assuming `a, b < n`.
const fn sub_mod<const LIMBS: usize>(
    n: &Uint<LIMBS>,
    a: &Uint<LIMBS>,
    b: &Uint<LIMBS>,
) -> Uint<LIMBS> {
    let (diff, borrow) = a.sbb(b, 0);
    let (wrapped, _) = diff.adc(n, 0);
    // If a < b (borrow), the true result wrapped negative; add n back.
    select(&wrapped, &diff, borrow)
}

/// Parameters for modular arithmetic with a fixed odd modulus.
///
/// The arithmetic runs at the modulus's *significant* width `s ≤ LIMBS`
/// (its non-leading-zero limbs): a half-width prime held in a full-width
/// type — an RSA CRT factor in the key's `Uint<LIMBS>` — costs a quarter of
/// the full-width multiply. `R = 2^(64·s)` accordingly, so Montgomery-form
/// values are only meaningful within one context; the plain-residue API
/// (`pow`, `mul_mod`, `to_mont` ∘ `from_mont`) is unaffected. The width is
/// public by convention (see [`new`](Self::new)).
#[derive(Clone, Debug)]
pub struct MontModulus<const LIMBS: usize> {
    modulus: Uint<LIMBS>,
    /// `-N^-1 mod 2^64`.
    n_prime: Limb,
    /// `R^2 mod N`, used to convert into Montgomery form.
    r2: Uint<LIMBS>,
    /// Significant limbs of the modulus: the width every kernel runs at.
    limbs: usize,
}

impl<const LIMBS: usize> MontModulus<LIMBS> {
    /// Builds modular parameters for an odd `modulus`.
    ///
    /// # Panics
    /// Panics if `modulus` is even (Montgomery reduction requires an odd
    /// modulus). In a `const` context that panic is a compile error.
    ///
    /// Costs `s + 1` modular doublings plus six Montgomery multiplications
    /// at the modulus's significant width `s` (plus one doubling per bit the
    /// top limb is short of full) — cheap, but a fixed modulus should still
    /// be built once, ideally as a `const`.
    ///
    /// The significant width and bit length of the modulus steer the
    /// construction. They are public by convention — an RSA prime's size is
    /// fixed by the key size, a Miller-Rabin candidate's by the generator —
    /// the same "widths are public" rule `BoxedUint::significant_limbs`
    /// follows. This `const fn` cannot declassify its scan for the taint
    /// harness; a modulus whose *limbs* are classified secret goes through
    /// `new_secret`, which does.
    pub const fn new(modulus: Uint<LIMBS>) -> Self {
        let n = modulus.as_limbs();
        assert!(n[0] & 1 == 1, "Montgomery modulus must be odd");
        let mut s = LIMBS;
        while s > 1 && n[s - 1] == 0 {
            s -= 1;
        }
        let bits = 64 * s - n[s - 1].leading_zeros() as usize;
        Self::with_shape(modulus, s, bits)
    }

    /// [`new`](Self::new) for a modulus held in classified (taint-tracked)
    /// limbs: the width scan's verdicts — public by convention — are
    /// declassified so the constant-time harness does not see the loop
    /// bounds as secret-derived. Same result as `new`.
    #[cfg(any(test, feature = "rsa"))]
    pub(crate) fn new_secret(modulus: Uint<LIMBS>) -> Self {
        let n = modulus.as_limbs();
        // A prime's parity is public; declassify the bit the assert reads.
        assert!(
            crate::ct::declassify_value(n[0] & 1) == 1,
            "Montgomery modulus must be odd"
        );
        let mut s = LIMBS;
        while s > 1 && crate::ct::declassify_value(n[s - 1] == 0) {
            s -= 1;
        }
        let bits = 64 * s - crate::ct::declassify_value(n[s - 1].leading_zeros()) as usize;
        Self::with_shape(modulus, s, bits)
    }

    /// The construction proper, for a modulus of `s` significant limbs and
    /// `bits` bits (both public).
    ///
    /// `R² mod N`, `R = 2^(64·s)`, without the `2·64·s` doublings of the
    /// textbook loop. With `M(x) = x·R mod N`, a modular doubling maps
    /// `M(2^e)` to `M(2^(e+1))` and a Montgomery squaring maps it to
    /// `M(2^(2e))`; the target is `R² = M(2^(64·s))`. Starting from
    /// `2^(bits−1)` — below `N`, which has that bit set — `64·s − bits + 1 + s`
    /// doublings reach `M(2^s)`, and six squarings (`64 = 2^6`) then reach
    /// `M(2^(64·s))`. Six is about where the squaring count stops paying
    /// for the doublings it replaces (a doubling is ~3 limb operations, a
    /// squaring ~s² multiplies), and `s + 1` doublings for a full-width
    /// modulus is a fraction of one squaring.
    ///
    /// Constant time in the modulus value: every loop bound is a function of
    /// `s` and `bits`, the arithmetic is the masked add/select and the
    /// Montgomery kernel. (`mont_mul` rather than `mont_sqr` so this stays
    /// `const`.)
    const fn with_shape(modulus: Uint<LIMBS>, s: usize, bits: usize) -> Self {
        // Oddness is asserted by the two constructors (`new` directly,
        // `new_secret` on a declassified bit) so this shared body never
        // branches on the modulus value.
        let n_prime = inv_mod_2_64(modulus.as_limbs()[0]).wrapping_neg();
        let mut m = MontModulus {
            modulus,
            n_prime,
            r2: Uint::ZERO,
            limbs: s,
        };
        let mut start = [0 as Limb; LIMBS];
        start[(bits - 1) / 64] = 1 << ((bits - 1) % 64);
        let mut x = Uint::from_limbs(start);
        let mut i = 0;
        while i < 64 * s - bits + 1 + s {
            x = add_mod(&modulus, &x, &x);
            i += 1;
        }
        let mut i = 0;
        while i < 6 {
            x = m.mont_mul(&x, &x);
            i += 1;
        }
        m.r2 = x;
        m
    }

    /// The significant width of the modulus in limbs — the width every
    /// operation of this context runs at (public by convention).
    #[inline]
    pub fn limbs(&self) -> usize {
        self.limbs
    }

    /// `R² mod N` (for `reduce`).
    #[inline]
    pub(crate) fn r2(&self) -> &Uint<LIMBS> {
        &self.r2
    }

    /// The modulus `N`.
    #[inline]
    pub fn modulus(&self) -> &Uint<LIMBS> {
        &self.modulus
    }

    /// Montgomery multiplication: given `a, b` in Montgomery form, returns
    /// `a*b*R^-1 mod N` (the Montgomery form of the product). CIOS with
    /// merged, two-rows-per-pass inner loops (`mont_mul_kernel`), constant
    /// time.
    pub const fn mont_mul(&self, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
        let mut t = [0 as Limb; LIMBS];
        let mut out = [0 as Limb; LIMBS];
        // At the significant width: operands below the modulus have zero
        // limbs above it, and so does the result.
        let (n, _) = self.modulus.as_limbs().split_at(self.limbs);
        mont_mul_kernel(
            n,
            self.n_prime,
            a.as_limbs(),
            b.as_limbs(),
            &mut t,
            &mut out,
        );
        Uint::from_limbs(out)
    }

    /// Montgomery squaring: given `a` in Montgomery form, returns
    /// `a²·R^-1 mod N` — exactly [`mont_mul`](Self::mont_mul)`(a, a)`, but
    /// with each off-diagonal product computed once (`mont_sqr_kernel`:
    /// roughly half the multiplies of the general product), constant time.
    ///
    /// The `2·LIMBS`-limb square lives in a `[[Limb; 2]; LIMBS]` viewed as
    /// one flat slice (`2 * LIMBS` is not expressible as an array length on
    /// stable), so the kernel indexes a single contiguous buffer — no
    /// `lo`/`hi` split branching on every column.
    pub fn mont_sqr(&self, a: &Uint<LIMBS>) -> Uint<LIMBS> {
        let mut p = [[0 as Limb; 2]; LIMBS];
        let mut out = [0 as Limb; LIMBS];
        mont_sqr_kernel(
            &self.modulus.as_limbs()[..self.limbs],
            self.n_prime,
            a.as_limbs(),
            p.as_flattened_mut(),
            &mut out,
        );
        Uint::from_limbs(out)
    }

    /// Converts `x` (a plain residue `< N`) into Montgomery form `xR mod N`.
    ///
    /// `x` is required to be a plain residue strictly below the modulus; a
    /// debug-only assertion documents and checks that precondition (it also
    /// guards [`pow`](Self::pow), which routes its `base` through here).
    /// Release behavior is unchanged.
    #[inline]
    pub const fn to_mont(&self, x: &Uint<LIMBS>) -> Uint<LIMBS> {
        // x < N iff x − N borrows (a `const`-usable comparison).
        debug_assert!(
            x.sbb(&self.modulus, 0).1 == 1,
            "to_mont precondition violated: base must be < N"
        );
        self.mont_mul(x, &self.r2)
    }

    /// Converts `x` out of Montgomery form, returning the plain residue.
    #[inline]
    pub const fn from_mont(&self, x: &Uint<LIMBS>) -> Uint<LIMBS> {
        self.mont_mul(x, &Uint::ONE)
    }

    /// Returns `(a + b) mod N` for plain residues `a, b < N`.
    #[inline]
    pub const fn add_mod(&self, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
        add_mod(&self.modulus, a, b)
    }

    /// Returns `(a - b) mod N` for plain residues `a, b < N`.
    #[inline]
    pub const fn sub_mod(&self, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
        sub_mod(&self.modulus, a, b)
    }

    /// Returns `(a * b) mod N` for plain residues `a, b < N`.
    pub fn mul_mod(&self, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
        // mont_mul(a, b) = ab·R^-1; multiplying by R^2 (·R^-1) restores ab.
        let t = self.mont_mul(a, b);
        self.mont_mul(&t, &self.r2)
    }
}

// The modulus is secret whenever it is an RSA prime factor (the fixed-width
// CRT path builds one context per prime), so a key can wipe its contexts.
impl<const LIMBS: usize> crate::zeroize::Zeroize for MontModulus<LIMBS> {
    fn zeroize(&mut self) {
        self.modulus.zeroize();
        self.r2.zeroize();
        self.n_prime.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct::{ConstantTimeEq, ConstantTimeGreater};

    // --- independent reference modular arithmetic (comparison-based) ---

    fn ge<const L: usize>(a: &Uint<L>, n: &Uint<L>) -> bool {
        bool::from(a.ct_gt(n)) || bool::from(a.ct_eq(n))
    }

    fn addmod_ref<const L: usize>(a: &Uint<L>, b: &Uint<L>, n: &Uint<L>) -> Uint<L> {
        let (s, carry) = a.adc(b, 0);
        if carry == 1 || ge(&s, n) {
            s.wrapping_sub(n)
        } else {
            s
        }
    }

    fn mulmod_ref<const L: usize>(a: &Uint<L>, b: &Uint<L>, n: &Uint<L>) -> Uint<L> {
        // Double-and-add; assumes a, b < n.
        let mut res = Uint::ZERO;
        for li in (0..L).rev() {
            let limb = b.as_limbs()[li];
            for bit in (0..64).rev() {
                res = addmod_ref(&res, &res, n);
                if (limb >> bit) & 1 == 1 {
                    res = addmod_ref(&res, a, n);
                }
            }
        }
        res
    }

    #[test]
    fn mulmod_matches_u128_for_64bit() {
        let n_vals: [u64; 3] = [0xFFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0001, 97];
        let vals: [u64; 5] = [0, 1, 2, 0x1234_5678_9abc_def1, 0xfedc_ba98_7654_3211];
        for &nv in &n_vals {
            let m = MontModulus::new(Uint::<1>::from_u64(nv));
            for &av in &vals {
                for &bv in &vals {
                    let a = Uint::<1>::from_u64(av % nv);
                    let b = Uint::<1>::from_u64(bv % nv);
                    let got = m.mul_mod(&a, &b).as_limbs()[0];
                    let expected = ((av % nv) as u128 * (bv % nv) as u128 % nv as u128) as u64;
                    assert_eq!(got, expected, "n={nv} a={av} b={bv}");
                }
            }
        }
    }

    #[test]
    fn mulmod_matches_reference_128bit() {
        // Odd 128-bit moduli with values spanning both limbs.
        let moduli = [
            Uint::<2>::from_limbs([0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF]),
            Uint::<2>::from_limbs([0x1234_5678_9abc_def1, 0x0fed_cba9_8765_4321]),
            Uint::<2>::from_limbs([3, 0]),
        ];
        let vals = [
            Uint::<2>::from_limbs([0xdead_beef_cafe_babe, 0x0123_4567_89ab_cdef]),
            Uint::<2>::from_limbs([0, 1]),
            Uint::<2>::from_limbs([1, 0]),
            Uint::<2>::from_limbs([0xFFFF_FFFF_FFFF_FFFE, 0x7FFF_FFFF_FFFF_FFFE]),
        ];
        for n in &moduli {
            let m = MontModulus::new(*n);
            for a0 in &vals {
                // reduce a, b below n
                let a = reduce(a0, n);
                for b0 in &vals {
                    let b = reduce(b0, n);
                    assert_eq!(m.mul_mod(&a, &b), mulmod_ref(&a, &b, n));
                    assert_eq!(m.add_mod(&a, &b), addmod_ref(&a, &b, n));
                    // Montgomery roundtrip.
                    assert_eq!(m.from_mont(&m.to_mont(&a)), a);
                }
            }
        }
    }

    /// Reduces `x mod n` via binary long division (test moduli have their top
    /// bit clear, so `r * 2` never overflows the width).
    fn reduce<const L: usize>(x: &Uint<L>, n: &Uint<L>) -> Uint<L> {
        let mut r = Uint::ZERO;
        for li in (0..L).rev() {
            let limb = x.as_limbs()[li];
            for bit in (0..64).rev() {
                let b = (limb >> bit) & 1;
                r = r.wrapping_add(&r).wrapping_add(&Uint::from_u64(b)); // (r << 1) | b
                if ge(&r, n) {
                    r = r.wrapping_sub(n);
                }
            }
        }
        r
    }

    /// SplitMix64 — deterministic test-only RNG.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Differential: `mont_sqr(a)` must be bit-identical to `mont_mul(a, a)`
    /// for random odd moduli and residues, plus the edge values 0, 1, n-1,
    /// and all-limbs-set (reduced).
    fn sqr_matches_mul_width<const L: usize>(rng: &mut u64) {
        for _ in 0..4 {
            let mut n_limbs = [0 as Limb; L];
            for l in n_limbs.iter_mut() {
                *l = splitmix64(rng);
            }
            n_limbs[0] |= 1; // odd
            n_limbs[L - 1] &= !(1 << 63); // top bit clear so `reduce` works
            n_limbs[L - 1] |= 1 << 62; // ...but still (64L-1)-bit wide
            let n = Uint::<L>::from_limbs(n_limbs);
            let m = MontModulus::new(n);

            let mut values = [Uint::<L>::ZERO; 10];
            values[1] = Uint::ONE;
            values[2] = n.wrapping_sub(&Uint::ONE);
            values[3] = reduce(&Uint::from_limbs([Limb::MAX; L]), &n);
            for k in 0..6 {
                let mut v = [0 as Limb; L];
                for (j, l) in v.iter_mut().enumerate() {
                    // Include top-heavy values (low limbs zero).
                    *l = if k >= 4 && j < L / 2 {
                        0
                    } else {
                        splitmix64(rng)
                    };
                }
                values[4 + k] = reduce(&Uint::from_limbs(v), &n);
            }
            for a in &values {
                assert_eq!(m.mont_sqr(a), m.mont_mul(a, a), "L={L} a={a:?}");
            }
        }
    }

    #[test]
    fn mont_sqr_matches_mont_mul() {
        let mut rng: u64 = 0xD1F5_ACE5_0FBE_EF01;
        sqr_matches_mul_width::<1>(&mut rng);
        sqr_matches_mul_width::<2>(&mut rng);
        sqr_matches_mul_width::<3>(&mut rng);
        sqr_matches_mul_width::<4>(&mut rng);
        sqr_matches_mul_width::<7>(&mut rng);
        sqr_matches_mul_width::<8>(&mut rng);
        sqr_matches_mul_width::<16>(&mut rng);
    }

    /// The textbook `R²` loop `new` replaced: `2·64·s` doublings of 1, for
    /// `R = 2^(64·s)` at the modulus's significant width `s`.
    fn r2_by_doubling<const L: usize>(n: &Uint<L>) -> Uint<L> {
        let s = n
            .as_limbs()
            .iter()
            .rposition(|&l| l != 0)
            .map_or(1, |i| i + 1);
        let mut r2 = Uint::ONE;
        for _ in 0..2 * 64 * s {
            r2 = add_mod(n, &r2, &r2);
        }
        r2
    }

    /// `new_secret` is `new` with the width scan declassified: same result.
    #[test]
    fn new_secret_matches_new() {
        let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
        for top in [1usize, 2, 5, 8] {
            let mut v = [0 as Limb; 8];
            for l in v.iter_mut().take(top) {
                *l = splitmix64(&mut rng);
            }
            v[0] |= 1;
            let n = Uint::<8>::from_limbs(v);
            let a = MontModulus::new(n);
            let b = MontModulus::new_secret(n);
            assert_eq!(a.r2, b.r2);
            assert_eq!(a.limbs, b.limbs);
            assert_eq!(a.limbs, top);
        }
    }

    fn r2_matches_width<const L: usize>(rng: &mut u64) {
        for k in 0..8 {
            let mut v = [0 as Limb; L];
            for l in v.iter_mut() {
                *l = splitmix64(rng);
            }
            // Full-width, short (leading zero limbs, as a half-width RSA
            // prime in a full-width type), and a single-limb top.
            let top = if k < 3 { L } else { 1 + (k % L) };
            for l in v.iter_mut().skip(top) {
                *l = 0;
            }
            if k == 1 {
                v[top - 1] = 1;
            }
            v[0] |= 1;
            if v[0] == 1 && top == 1 {
                v[0] = 3;
            }
            let n = Uint::<L>::from_limbs(v);
            assert_eq!(MontModulus::new(n).r2, r2_by_doubling(&n), "L={L} n={n:?}");
        }
    }

    #[test]
    fn r2_matches_doubling_oracle() {
        let mut rng: u64 = 0x5151_7E57_0DD5_EED5;
        for v in [3u64, 5, 97, 0xFFFF_FFFF_FFFF_FFC5, u64::MAX] {
            let n = Uint::<1>::from_u64(v);
            assert_eq!(MontModulus::new(n).r2, r2_by_doubling(&n));
            let n = Uint::<3>::from_u64(v);
            assert_eq!(MontModulus::new(n).r2, r2_by_doubling(&n));
        }
        r2_matches_width::<1>(&mut rng);
        r2_matches_width::<2>(&mut rng);
        r2_matches_width::<3>(&mut rng);
        r2_matches_width::<4>(&mut rng);
        r2_matches_width::<5>(&mut rng);
        r2_matches_width::<7>(&mut rng);
        r2_matches_width::<8>(&mut rng);
        r2_matches_width::<16>(&mut rng);
        r2_matches_width::<17>(&mut rng);
        r2_matches_width::<32>(&mut rng);
        r2_matches_width::<48>(&mut rng);
    }

    #[test]
    fn sub_mod_wraps() {
        let n = Uint::<2>::from_limbs([101, 0]);
        let m = MontModulus::new(n);
        let a = Uint::<2>::from_u64(3);
        let b = Uint::<2>::from_u64(10);
        // 3 - 10 mod 101 = 94
        assert_eq!(m.sub_mod(&a, &b), Uint::<2>::from_u64(94));
    }
}
